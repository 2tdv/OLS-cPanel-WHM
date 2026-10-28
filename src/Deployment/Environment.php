<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cpanel\Discovery\PlatformInspector;
use OlsCpanel\Infrastructure\Filesystem\ObservationReader;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Infrastructure\Process\ProbeRunner;

/**
 * Everything the deployment operations touch, injectable for tests: the command runner (every external
 * command), the state directory (plans, backups, profile, lock), the compile, the configuration activator,
 * the platform report, the root check and the clock.
 */
final class Environment
{
    public const STATE = '/var/lib/ols-cpanel';
    /** Families of docs/installation.md; the release notes list the exact tested rows. */
    /** AlmaLinux only in this release (built and tested there); Rocky Linux and CloudLinux follow later. */
    public const OS_FAMILIES = ['almalinux'];
    /** Release 9 only: built and tested there; release 8 follows in a later release. */
    public const OS_MAJORS = ['9'];
    /**
     * How long apache-return and uninstall wait for the deployment lock: a running reconcile pass holds it
     * shared and is drained, not interrupted (the bound of recover.sh's own wait).
     */
    public const DRAIN_SECONDS = 900;
    /** The reconciler service's group (build/product/ols-cpanel.sysusers): may open the deployment lock to share it. */
    public const LOCK_GROUP = 'olscpanel';

    public readonly Host $host;
    /** cPanel's EasyApache 4 profile directory (the recommended profile goes to custom/ below it). */
    public readonly string $ea4Root;
    public readonly Compilation $compilation;
    /** @var \Closure():array<string,mixed> */
    private \Closure $platform;
    /** @var \Closure():int */
    private \Closure $clock;

    /**
     * @param \Closure():array<string,mixed>|null $platform PlatformInspector report (with "runtime")
     * @param \Closure(float):void|null $sleep
     * @param \Closure():int|null $clock unix time
     */
    public function __construct(public readonly CommandRunner $runner, public readonly string $state = self::STATE,
                                ?Compilation $compilation = null, public readonly ?ConfigurationActivator $activator = null,
                                public readonly bool $root = true, ?\Closure $platform = null, ?\Closure $sleep = null,
                                ?\Closure $clock = null, public readonly string $hookEntry = Hooks::ENTRY,
                                public readonly string $pluginSource = Plugins::SOURCE,
                                public readonly string $phpRoot = '/opt/cpanel', ?string $ea4Root = null,
                                public readonly string $unitDir = '/etc/systemd/system')
    {
        // Test isolation: only the production state directory means the real EasyApache 4 profile directory.
        $this->ea4Root = $ea4Root ?? ($state === self::STATE ? Ea4Profile::ROOT : $state . '/ea4-profiles');
        $this->host = new Host($runner, $sleep);
        $this->compilation = $compilation ?? new BuilderCompilation($runner);
        $this->platform = $platform ?? self::observePlatform(...);
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * The root CLI on the server. The configuration activator (the reconciler's forced pass) is wired here
     * once that component is present; without it a cutover refuses before changing anything.
     */
    public function plugins(): Plugins
    {
        return new Plugins($this->host, $this->state, $this->pluginSource);
    }

    public static function production(?ConfigurationActivator $activator = null): self
    {
        return new self(new LocalCommandRunner(), self::STATE, null, $activator,
            function_exists('posix_geteuid') && posix_geteuid() === 0);
    }

    public function ea4Profile(): Ea4Profile
    {
        return new Ea4Profile($this->ea4Root, $this->state === self::STATE ? '/etc/os-release' : $this->state . '/os-release');
    }

    public function profilePath(): string
    {
        return $this->state . '/profile.json';
    }

    /** The operator's HTTP/3 input (FV-04); absent means enabled. */
    public function http3Path(): string
    {
        return $this->state . '/http3.json';
    }

    public function plansDir(): string
    {
        return $this->state . '/plans';
    }

    public function backupsDir(): string
    {
        return $this->state . '/backups';
    }

    public function now(): int
    {
        return ($this->clock)();
    }

    public function hooks(): Hooks
    {
        return new Hooks($this->host, $this->hookEntry);
    }

    /** A new identifier: <prefix><UTC YYYYmmddHHMMSS>-<6 hex>. */
    public function newId(string $prefix): string
    {
        return $prefix . gmdate('YmdHis', $this->now()) . '-' . bin2hex(random_bytes(3));
    }

    public function requireRoot(): void
    {
        if (!$this->root) {
            throw DeploymentError::refused('this command must run as root');
        }
    }

    /**
     * Platform rules of `doctor`: complete observations, a supported OS family and major version, x86_64.
     * Certification (the G0 gates) is reported separately, never assumed.
     * @return array{supported:bool, problems:list<string>, certification_blockers:list<string>}
     */
    public function platform(): array
    {
        $report = ($this->platform)();
        $problems = [];
        if (($report['observation_complete'] ?? false) !== true) {
            $problems[] = 'incomplete platform observation';
        }
        $os = $report['platform']['os']['value'] ?? null;
        $family = is_array($os) ? strtolower((string) ($os['ID'] ?? '')) : '';
        $major = is_array($os) ? explode('.', (string) ($os['VERSION_ID'] ?? ''))[0] : '';
        if (!in_array($family, self::OS_FAMILIES, true) || !in_array($major, self::OS_MAJORS, true)) {
            $problems[] = "unsupported operating system $family $major";
        }
        if (($report['runtime']['architecture'] ?? null) !== 'x86_64') {
            $problems[] = 'unsupported architecture ' . var_export($report['runtime']['architecture'] ?? null, true);
        }
        if (!is_string($report['platform']['cpanel']['value'] ?? null)) {
            $problems[] = 'cPanel version not observed';
        }
        $blockers = array_values(array_filter(is_array($report['blockers'] ?? null) ? $report['blockers'] : [], 'is_string'));
        return ['supported' => $problems === [], 'problems' => $problems, 'certification_blockers' => $blockers];
    }

    public function deploymentLockPath(): string
    {
        return $this->state . '/deployment.lock';
    }

    /**
     * Exclusive deployment lock (prepare, cutover, return, hooks, uninstall; recover.sh takes the same lock and
     * every reconcile pass holds it shared, docs/product-interfaces.md "Locks, deadlines and recovery"). Busy (75)
     * when still held after $waitSeconds (polled once a second). The file is root:olscpanel 0640: only the
     * reconciler service may open it besides root, so no other local user can hold it and delay a recovery.
     * @return resource
     */
    public function lock(int $waitSeconds = 0)
    {
        if (!is_dir($this->state)) {
            throw DeploymentError::refused("{$this->state} does not exist; run install --prepare first");
        }
        $path = $this->deploymentLockPath();
        $handle = @fopen($path, 'c');
        if ($handle === false) {
            throw DeploymentError::refused('cannot open the deployment lock');
        }
        if (!@chmod($path, 0640)) {
            fclose($handle);
            throw DeploymentError::refused("cannot restrict the deployment lock $path");
        }
        if ($this->root) {
            @chgrp($path, self::LOCK_GROUP);  // fails until systemd-sysusers created the group; root-only until then
        }
        for ($waited = 0; !flock($handle, LOCK_EX | LOCK_NB); ++$waited) {
            if ($waited >= $waitSeconds) {
                fclose($handle);
                throw new DeploymentError('another deployment operation or a reconcile pass holds the deployment lock',
                    Application::EXIT_BUSY);
            }
            $this->host->sleep(1);
        }
        return $handle;
    }

    /** Writes a root-only file atomically (temporary file, fsync, rename). */
    public static function writeFile(string $path, string $text, int $mode): void
    {
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $handle = @fopen($tmp, 'x');
        if ($handle === false) {
            throw DeploymentError::refused("cannot write $tmp");
        }
        try {
            if (!chmod($tmp, $mode) || fwrite($handle, $text) !== strlen($text) || !fflush($handle) || !fsync($handle)) {
                throw DeploymentError::refused("cannot write $tmp");
            }
        } finally {
            fclose($handle);
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw DeploymentError::refused("cannot install $path");
        }
    }

    public static function ensureDir(string $path, int $mode): void
    {
        if (!is_dir($path) && !@mkdir($path, $mode, true) && !is_dir($path)) {
            throw DeploymentError::refused("cannot create $path");
        }
        if (is_link($path) || !chmod($path, $mode)) {
            throw DeploymentError::refused("unsafe or unwritable directory $path");
        }
    }

    public static function json(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @return array<string,mixed> */
    private static function observePlatform(): array
    {
        $reader = new ObservationReader();
        $runner = new ProbeRunner();
        $observations = [];
        foreach (array_keys(ObservationReader::PATHS) as $source) {
            $observations[$source] = $reader->read($source);
        }
        foreach (array_keys(ProbeRunner::COMMANDS) as $source) {
            $observations[$source] = $runner->run($source);
        }
        return (new PlatformInspector())->inspect($observations, ['architecture' => php_uname('m')]);
    }
}
