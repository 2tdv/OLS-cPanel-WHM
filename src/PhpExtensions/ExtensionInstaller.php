<?php
declare(strict_types=1);

namespace OlsCpanel\PhpExtensions;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Events\HookEntry;
use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * Keeps the PHP `redis` extension working in every installed EA4 PHP version (docs/product-interfaces.md, "PHP
 * extensions"). Root only; every command goes through the CommandRunner as a fixed argv, and the only file ever
 * written below /opt/cpanel is the INI file `zz-ols-cpanel-redis.ini` of a version.
 *
 * For one version, in this order, until the extension loads:
 *  1. a redis that already loads (EA4 package, PECL, the operator's own INI) is never touched;
 *  2. the prebuilt build of the ols-cpanel-php-redis package, when its PHP API number and build id equal those of
 *     the installed PHP (`php -n -i`; stable within a minor series, so EA4 patch updates keep it valid);
 *  3. an earlier local build of this server with the same ABI;
 *  4. a new local build: the pinned, checksum-verified phpredis tarball of the package is compiled against the
 *     version's EA4 development package (installed with dnf from the repositories of the server when missing)
 *     in a private directory, and installed to /var/lib/ols-cpanel/php-ext/redis/<version>/redis.so.
 * Each candidate is activated by writing the INI atomically and proven with `php -m` and a class check; a
 * candidate that does not load is removed again. A failed build is recorded (state.json, the log, the report) and
 * retried after a back-off by the watcher; an operator command retries at once.
 *
 * Only PHP 7.4 and newer is supported (the packaged phpredis 6.3.0 requires it): an older version is reported as
 * `unsupported` ("unsupported for the object cache") and is never built for or activated; that is not a failure of
 * the pass, it is a permanent, visible fact about the version.
 *
 * The compile runs unprivileged (RV-31 item 16): extraction, phpize, configure and make are each a transient
 * systemd service with a dynamic user, a private state directory, a read-only file system, no network, no
 * capabilities and memory, task and time limits. Root only installs build dependencies with dnf (before) and copies
 * the finished redis.so into the local index, verifies its SHA-256 and loads it (after); the build directory is
 * removed afterwards, and leftovers of an interrupted build are pruned before the next one. Without systemd-run
 * the build is refused: there is no fallback that compiles as root.
 */
final class ExtensionInstaller
{
    public const INI = 'zz-ols-cpanel-redis.ini';
    public const MARKER = '; Managed by ols-cpanel (php-ext). Remove with: ols-cpanel php-ext remove';
    public const PHP_ROOT = '/opt/cpanel';
    public const STATE_ROOT = '/var/lib/ols-cpanel/php-ext';
    /** The PHP environment applier's units (Php\PhpEnvironment): one service for lsphp, OPcache and this extension. */
    public const WATCHER = 'ols-cpanel-php.path';
    public const TIMER = 'ols-cpanel-php.timer';
    public const SERVICE = 'ols-cpanel-php.service';
    public const RETRY_SECONDS = 900;
    public const DNF = '/usr/bin/dnf';
    /** The oldest PHP the packaged phpredis supports. */
    public const MIN_PHP = '7.4';
    public const SYSTEMD_RUN = '/usr/bin/systemd-run';
    /** Where a transient service with DynamicUser and StateDirectory= keeps its (private, 0700) state directory. */
    public const BUILD_ROOT = '/var/lib/private';
    public const BUILD_PREFIX = 'ols-cpanel-ext-build-';
    public const BUILD_MEMORY = '2G';
    public const BUILD_TASKS = 256;
    public const TOOLS = ['/usr/bin/gcc' => 'gcc', '/usr/bin/make' => 'make', '/usr/bin/autoconf' => 'autoconf'];
    private const ENV = '/usr/bin/env';
    private const TAR = '/usr/bin/tar';
    private const RM = '/usr/bin/rm';
    private const SYSTEMCTL = '/usr/bin/systemctl';
    private const LOG_LIMIT = 1048576;

    /** @var \Closure():int */
    private \Closure $clock;

    /**
     * @param \Closure(string,string):void|null $changed called with (version, revision) when the workers of a version
     *        must restart (redis activated, replaced or removed), BEFORE the change is recorded as done; it may throw
     */
    public function __construct(private readonly CommandRunner $runner, private readonly string $bundleRoot = ExtensionBundle::ROOT,
                                private readonly string $phpRoot = self::PHP_ROOT, private readonly string $stateRoot = self::STATE_ROOT,
                                ?\Closure $clock = null, private readonly string $buildRoot = self::BUILD_ROOT,
                                private readonly ?\Closure $changed = null, private readonly string $systemdRun = self::SYSTEMD_RUN)
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** PHP 7.4 or newer, by the EA4 name (ea-php74 is 7.4). */
    public static function supported(string $php): bool
    {
        $digits = substr($php, 6);
        return strlen($digits) >= 2 && version_compare(substr($digits, 0, -1) . '.' . substr($digits, -1), self::MIN_PHP, '>=');
    }

    private static function unsupportedMessage(string $php): string
    {
        return "unsupported for the object cache: the packaged phpredis needs PHP " . self::MIN_PHP . " or newer and $php is older";
    }

    // --- Public operations ------------------------------------------------------------------------------------

    /** Installed EA4 PHP versions (a PHP CLI binary exists). @return list<string> */
    public function versions(): array
    {
        $found = [];
        foreach (is_dir($this->phpRoot) ? (scandir($this->phpRoot) ?: []) : [] as $name) {
            if (preg_match(ExtensionBundle::EA_PHP, $name) === 1 && is_file($this->binary($name))) {
                $found[] = $name;
            }
        }
        sort($found, SORT_STRING);
        return $found;
    }

    /**
     * Read-only report. `needs_sync` is true when the watcher has work to do now (wanted, and some version neither
     * loads redis nor waits out a back-off).
     * @return array<string,mixed>
     */
    public function status(): array
    {
        $state = ExtensionState::load($this->statePath());
        $prebuilt = ExtensionBundle::load($this->bundleRoot);
        $local = ExtensionBundle::load($this->localRoot());
        $rows = [];
        $needs = false;
        foreach ($this->versions() as $php) {
            $row = ['php' => $php, 'ini' => $this->ownIni($php) === true, 'loaded' => $this->loaded($php)];
            $failure = $state->failures[$php] ?? null;
            if ($row['loaded']) {
                $row['status'] = $row['ini'] ? 'active' : 'already_loaded';
                $row['replaced'] = $row['ini'] && $this->replaced($php, $state);
            } elseif (!self::supported($php)) {
                $row['status'] = 'unsupported';
                $row['candidate'] = 'unsupported';
                $row['message'] = self::unsupportedMessage($php);
            } else {
                $abi = $this->abi($php);
                $row['php_version'] = $abi['version'] ?? null;
                $row['status'] = $row['ini'] ? 'broken' : 'inactive';
                $row['candidate'] = $abi === null ? 'php_unusable' : ($this->usable($prebuilt, $php, $abi) ? 'prebuilt'
                    : ($this->usable($local, $php, $abi) ? 'local_build' : ($prebuilt?->sourcePath() !== null ? 'build_needed' : 'none')));
                $needs = $needs || ($state->wanted && ($failure === null || $this->clock->__invoke() - $failure['at'] >= self::RETRY_SECONDS));
            }
            if ($failure !== null) {
                $row['last_failure'] = $failure + ['retry_at' => $failure['at'] + self::RETRY_SECONDS];
            }
            $rows[] = $row;
        }
        $watcher = $this->run('watcher-enabled', [self::SYSTEMCTL, 'is-enabled', '--quiet', self::WATCHER])['exit_code'] === 0;
        $timer = $this->run('timer-enabled', [self::SYSTEMCTL, 'is-enabled', '--quiet', self::TIMER])['exit_code'] === 0;
        // Wanted but the units that retry it are off: the work is due (the pass enables them again).
        $needs = $needs || ($state->wanted && !($watcher && $timer));
        return ['result' => 'status', 'extension' => 'redis', 'wanted' => $state->wanted, 'needs_sync' => $needs,
            'watcher' => $watcher, 'timer' => $timer,
            'prebuilt' => $prebuilt === null ? null : ['version' => $prebuilt->extensionVersion, 'php' => array_keys($prebuilt->versions)],
            'local_builds' => $local === null ? [] : array_keys($local->versions), 'versions' => $rows];
    }

    /**
     * Operator install: wanted, the watcher enabled, every version (or one) brought to a loading extension now,
     * ignoring the back-off. @return array<string,mixed>
     */
    public function install(?string $only = null): array
    {
        return $this->locked(function () use ($only): array {
            $versions = $this->selected($only);
            $state = ExtensionState::load($this->statePath());
            if (!$state->wanted) {
                $state->wanted = true;
                $state->save($this->statePath());
            }
            $watcher = $this->ensureWatcher();
            return self::units($watcher, $this->pass($versions, true));
        });
    }

    /** The watcher's pass: nothing unless wanted; failures back off. @return array<string,mixed> */
    public function sync(): array
    {
        return $this->locked(function (): array {
            if (!ExtensionState::load($this->statePath())->wanted) {
                return ['result' => 'idle', 'versions' => [], 'changed' => [], 'note' => 'the extension is not wanted (php-ext install)'];
            }
            return $this->pass($this->versions(), false);
        });
    }

    /** Object cache path: one version (or several) of an account, now; marks the extension wanted. @return array<string,mixed> */
    public function ensure(array $versions): array
    {
        return $this->locked(function () use ($versions): array {
            $state = ExtensionState::load($this->statePath());
            if (!$state->wanted) {
                $state->wanted = true;
                $state->save($this->statePath());
            }
            $watcher = $this->ensureWatcher();
            $known = $this->versions();
            $present = array_values(array_intersect($versions, $known));
            return self::units($watcher, $this->pass($present, true))
                + ($present === $versions ? [] : ['not_installed' => array_values(array_diff($versions, $known))]);
        });
    }

    /**
     * The report with the state of the units that retry the work: when they cannot be enabled the pass is a failure
     * (nothing would retry it), reported as such.
     * @param array<string,mixed> $report
     * @return array<string,mixed>
     */
    private static function units(bool $enabled, array $report): array
    {
        if (!$enabled) {
            $report['result'] = 'failed';
            $report['watcher_error'] = 'the path watcher or the timer of the PHP environment pass could not be enabled';
        }
        return ['watcher' => $enabled] + $report;
    }

    /** Marks the extension wanted and enables the watcher; changes nothing else. */
    public function want(): void
    {
        $this->locked(function (): null {
            $state = ExtensionState::load($this->statePath());
            if (!$state->wanted) {
                $state->wanted = true;
                $state->save($this->statePath());
            }
            $this->ensureWatcher();
            return null;
        });
    }

    /** Deletes only our INI files and clears "wanted" (the applier then leaves redis alone). @return array<string,mixed> */
    public function remove(): array
    {
        return $this->locked(function (): array {
            $state = ExtensionState::load($this->statePath());
            if ($state->wanted) {
                $state->wanted = false;
                $state->save($this->statePath());
            }
            // The units stay: the same service keeps lsphp and OPcache complete. Every version that loses its extension
            // owes its accounts a restart; that is recorded before the file is deleted.
            return ['result' => 'removed'] + $this->removeInis(true);
        });
    }

    /** Versions that carry our INI file (read-only). @return list<string> */
    public function ownInis(): array
    {
        $found = [];
        foreach (is_dir($this->phpRoot) ? (scandir($this->phpRoot) ?: []) : [] as $name) {
            if (preg_match(ExtensionBundle::EA_PHP, $name) === 1 && $this->ownIni($name) === true) {
                $found[] = $name;
            }
        }
        return $found;
    }

    /** Removes our INI files without touching state or units (uninstall). @return array{versions:list<array<string,mixed>>} */
    public function removeInis(bool $markRestart = false): array
    {
        $rows = [];
        $changed = [];
        foreach (is_dir($this->phpRoot) ? (scandir($this->phpRoot) ?: []) : [] as $name) {
            if (preg_match(ExtensionBundle::EA_PHP, $name) !== 1) {
                continue;
            }
            $own = $this->ownIni($name);
            if ($own === null) {
                continue;
            }
            if ($own === false) {
                $rows[] = ['php' => $name, 'status' => 'foreign', 'note' => self::INI . ' is not ours and was left alone'];
            } elseif ($this->noteRemoval($name, $markRestart) && @unlink($this->ini($name))) {
                $rows[] = ['php' => $name, 'status' => 'removed'];
                $changed[] = $name;
                $this->forgetArtifact($name);
            } else {
                $rows[] = ['php' => $name, 'status' => 'failed', 'note' => 'cannot remove ' . $this->ini($name)];
            }
        }
        return ['versions' => $rows] + ($markRestart ? ['changed' => $changed] : []);
    }

    /** Marks the restart owed for a removal (before the file goes). false: it could not be recorded, so the file stays. */
    private function noteRemoval(string $php, bool $mark): bool
    {
        if (!$mark || $this->changed === null) {
            return true;
        }
        try {
            ($this->changed)($php, 'redis:removed');
            return true;
        } catch (\Throwable $error) {
            $this->log("$php: cannot record the restart owed for the removal: " . $error->getMessage());
            return false;
        }
    }

    // --- One pass over versions --------------------------------------------------------------------------------

    /**
     * @param list<string> $versions
     * @return array<string,mixed>
     */
    private function pass(array $versions, bool $force): array
    {
        $rows = [];
        $changed = [];
        $failed = false;
        foreach ($versions as $php) {
            $row = $this->one($php, $force);
            $rows[] = $row;
            if ($row['changed']) {
                $changed[] = $php;
            }
            $failed = $failed || in_array($row['status'], ['failed', 'backoff', 'no_source', 'php_unusable'], true);
        }
        $failed = $failed || count(array_filter($rows, static fn(array $r): bool => ($r['status'] ?? '') === 'failed')) > 0;
        return ['result' => $failed ? 'failed' : ($changed === [] ? 'unchanged' : 'activated'), 'versions' => $rows, 'changed' => $changed];
    }

    /** @return array<string,mixed> */
    private function one(string $php, bool $force): array
    {
        return $this->attempt($php, $force) + ['changed' => false];
    }

    /** @return array<string,mixed> */
    private function attempt(string $php, bool $force): array
    {
        $row = ['php' => $php];
        $ours = $this->ownIni($php);
        if ($ours === false) {
            return $row + ['status' => 'failed', 'message' => $this->ini($php) . ' exists and is not managed by ols-cpanel; not touched'];
        }
        if ($this->loaded($php)) {
            if ($ours === true) {
                $replaced = $this->replacement($php);
                if ($replaced !== null) {
                    return $this->withChange($row + ['status' => 'replaced', 'changed' => true, 'source' => 'ini', 'sha256' => $replaced], $php, $replaced);
                }
            }
            return $row + ['status' => $ours === true ? 'active' : 'already_loaded', 'source' => $ours === true ? 'ini' : 'external'];
        }
        if (!self::supported($php)) {
            return $row + ['status' => 'unsupported', 'message' => self::unsupportedMessage($php)];
        }
        $abi = $this->abi($php);
        if ($abi === null) {
            return $row + ['status' => 'php_unusable', 'message' => "$php did not report its build (php -n -i failed)"];
        }
        $row += ['php_version' => $abi['version'], 'php_api' => $abi['api'], 'build_id' => $abi['build_id']];
        $prebuilt = ExtensionBundle::load($this->bundleRoot);
        $local = ExtensionBundle::load($this->localRoot());
        $problems = [];
        foreach (['prebuilt' => $prebuilt, 'local_build' => $local] as $source => $bundle) {
            if (!$this->usable($bundle, $php, $abi)) {
                continue;
            }
            $entry = $bundle->entry($php);
            $done = $this->activate($php, $entry['so']);
            if ($done === null) {
                $this->clearFailure($php);
                $this->log("$php: activated the $source build ({$entry['sha256']})");
                return $this->withChange($row + ['status' => 'activated', 'changed' => true, 'source' => $source, 'sha256' => $entry['sha256']], $php, $entry['sha256']);
            }
            $problems[] = "$source build: $done";
        }
        if ($prebuilt === null || $prebuilt->sourcePath() === null) {
            return $row + ['status' => 'no_source', 'message' => 'no prebuilt build matches and the phpredis source is not installed'
                . ' (is ols-cpanel-php-redis installed?)'];
        }
        $failure = ExtensionState::load($this->statePath())->failures[$php] ?? null;
        if (!$force && $failure !== null && ($this->clock)() - $failure['at'] < self::RETRY_SECONDS) {
            return $row + ['status' => 'backoff', 'message' => $failure['error'], 'retry_at' => $failure['at'] + self::RETRY_SECONDS,
                'attempts' => $failure['attempts']];
        }
        try {
            $entry = $this->build($php, $prebuilt, $abi);
            $done = $this->activate($php, $entry['so']);
            if ($done !== null) {
                throw new Refused("the new build does not load: $done");
            }
        } catch (Refused $error) {
            $message = implode('; ', [...$problems, $error->getMessage()]);
            $attempts = $this->recordFailure($php, $message);
            $this->log("$php: FAILED (attempt $attempts): $message");
            return $row + ['status' => 'failed', 'message' => $message, 'attempts' => $attempts];
        }
        $this->clearFailure($php);
        $this->log("$php: built phpredis {$prebuilt->extensionVersion} locally and activated it ({$entry['sha256']})");
        return $this->withChange($row + ['status' => 'activated', 'changed' => true, 'source' => 'local_build_new', 'sha256' => $entry['sha256']], $php, $entry['sha256']);
    }

    // --- Artifact tracking (what the running workers were last told to load) -----------------------------------------------

    /** sha256 of the file our INI of the version loads; null when it cannot be read. */
    private function artifactSha(string $php): ?string
    {
        $text = (string) @file_get_contents($this->ini($php));
        if (preg_match('/^extension=(\/[^\n]+)$/m', $text, $m) !== 1 || !is_file($m[1]) || is_link($m[1])) {
            return null;
        }
        $sha = @hash_file('sha256', $m[1]);
        return $sha === false ? null : $sha;
    }

    /** The new sha256 when the artifact our INI loads is not the one registered for the version; null otherwise (a first sight registers silently). */
    private function replacement(string $php): ?string
    {
        $sha = $this->artifactSha($php);
        if ($sha === null) {
            return null;
        }
        $state = ExtensionState::load($this->statePath());
        $known = $state->artifacts[$php] ?? null;
        if ($known === null) {
            $state->artifacts[$php] = $sha;
            $state->save($this->statePath());
            return null;
        }
        return $known === $sha ? null : $sha;
    }

    /** Read-only: whether status should show the loaded artifact as replaced. */
    private function replaced(string $php, ExtensionState $state): bool
    {
        $sha = $this->artifactSha($php);
        $known = $state->artifacts[$php] ?? null;
        return $sha !== null && $known !== null && $known !== $sha;
    }

    /**
     * The version's workers owe a restart for this artifact: recorded through the `changed` callback first, then the artifact is
     * registered. When the callback fails the artifact stays unregistered, so the next pass finds it again.
     * @return array<string,mixed>|null a failure row to merge (status failed), or null
     */
    private function recordChange(string $php, string $sha): ?array
    {
        try {
            if ($this->changed !== null) {
                ($this->changed)($php, "redis:$sha");
            }
        } catch (\Throwable $error) {
            $state = ExtensionState::load($this->statePath());
            $state->artifacts[$php] = 'unregistered';  // never equals a real sha256: the next pass re-detects it
            $state->save($this->statePath());
            return ['status' => 'failed', 'message' => 'the restart owed to the accounts could not be recorded: ' . substr($error->getMessage(), 0, 200)];
        }
        $state = ExtensionState::load($this->statePath());
        $state->artifacts[$php] = $sha;
        $state->save($this->statePath());
        return null;
    }

    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private function withChange(array $row, string $php, string $sha): array
    {
        return array_merge($row, $this->recordChange($php, $sha) ?? []);
    }

    private function forgetArtifact(string $php): void
    {
        $state = ExtensionState::load($this->statePath());
        if (isset($state->artifacts[$php])) {
            unset($state->artifacts[$php]);
            $state->save($this->statePath());
        }
    }

    // --- The layers --------------------------------------------------------------------------------------------

    /** @param array{version:string, api:string, build_id:string} $abi */
    private function usable(?ExtensionBundle $bundle, string $php, array $abi): bool
    {
        $entry = $bundle?->entry($php);
        return $entry !== null && $entry['php_api'] === $abi['api'] && $entry['build_id'] === $abi['build_id'];
    }

    /**
     * Writes our INI for $so and proves it loads; on failure removes the INI again.
     * @return string|null null on success, the reason otherwise
     */
    private function activate(string $php, string $so): ?string
    {
        $entry = null;
        foreach ([ExtensionBundle::load($this->bundleRoot), ExtensionBundle::load($this->localRoot())] as $bundle) {
            if ($bundle !== null && ($bundle->entry($php)['so'] ?? null) === $so) {
                $entry = $bundle->entry($php);
            }
        }
        if ($entry === null || !is_file($so) || is_link($so) || @filesize($so) !== $entry['size'] || hash_file('sha256', $so) !== $entry['sha256']) {
            return "$so is missing or does not match its recorded SHA-256";
        }
        $dir = dirname($this->ini($php));
        if (!is_dir($dir)) {
            return "$dir does not exist";
        }
        try {
            HookEntry::writeDurable($this->ini($php), self::MARKER . "\nextension=$so\n", 0644);
        } catch (\RuntimeException $error) {
            return $error->getMessage();
        }
        $problem = $this->verify($php);
        if ($problem !== null) {
            @unlink($this->ini($php));
        }
        return $problem;
    }

    /** `php -m` lists redis and the Redis class exists. @return string|null the reason it does not */
    private function verify(string $php): ?string
    {
        $modules = $this->run('modules', [$this->binary($php), '-m']);
        if ($modules['exit_code'] !== 0 || !in_array('redis', self::lines($modules['stdout']), true)) {
            return 'php -m does not list redis' . self::detail($modules);
        }
        $class = $this->run('class-check', [$this->binary($php), '-r', 'var_dump(class_exists("Redis"));']);
        if ($class['exit_code'] !== 0 || trim($class['stdout']) !== 'bool(true)') {
            return 'the Redis class is not available' . self::detail($class);
        }
        return null;
    }

    private function loaded(string $php): bool
    {
        $modules = $this->run('modules', [$this->binary($php), '-m']);
        return $modules['exit_code'] === 0 && in_array('redis', self::lines($modules['stdout']), true);
    }

    /**
     * Compiles the packaged phpredis source against $php and installs the result into the local index.
     * @param array{version:string, api:string, build_id:string} $abi
     * @return array{so:string, sha256:string, size:int, php_api:string, build_id:string, built_with:string}
     * @throws Refused
     */
    private function build(string $php, ExtensionBundle $prebuilt, array $abi): array
    {
        $tarball = $prebuilt->sourcePath();
        if ($tarball === null || !is_file($tarball) || is_link($tarball) || hash_file('sha256', $tarball) !== $prebuilt->source['sha256']) {
            throw new Refused('the packaged phpredis source is missing or does not match its recorded SHA-256');
        }
        $bin = dirname($this->binary($php));
        $missing = [];
        foreach (self::TOOLS as $path => $package) {
            if (!is_executable($path)) {
                $missing[] = $package;
            }
        }
        if (!is_file("$bin/phpize") || !is_file("$bin/php-config") || $missing !== []) {
            $install = $this->run('dnf-install', [self::DNF, '-y', '--setopt=install_weak_deps=False', 'install', "$php-php-devel", ...$missing], 1800);
            if ($install['exit_code'] !== 0 || !is_file("$bin/phpize") || !is_file("$bin/php-config")) {
                throw new Refused("dnf could not install $php-php-devel" . ($missing === [] ? '' : ' and ' . implode(', ', $missing)) . self::detail($install));
            }
        }
        if (!is_file($this->systemdRun) || ((int) @fileperms($this->systemdRun) & 0111) === 0) {  // by mode, so it holds on any mount
            throw new Refused($this->systemdRun . ' is missing: the extension is never compiled with root authority; install systemd or the prebuilt package');
        }
        $this->pruneBuilds();
        $unit = self::BUILD_PREFIX . bin2hex(random_bytes(6));
        $inside = "/var/lib/$unit";                      // the private state directory as the build service sees it
        $outside = "{$this->buildRoot}/$unit";           // the same directory as root sees it (created by systemd for the service)
        $src = "$inside/redis-{$prebuilt->extensionVersion}";
        try {
            $steps = [
                ['untar', [self::TAR, '-xzf', $tarball, '-C', $inside, '--no-same-owner', '--no-same-permissions'], 300],
                ['phpize', [self::ENV, '-C', $src, "$bin/phpize"], 300],
                ['configure', [self::ENV, '-C', $src, 'CFLAGS=-O2', './configure', "--with-php-config=$bin/php-config",
                    '--disable-redis-igbinary', '--disable-redis-msgpack', '--disable-redis-lzf', '--disable-redis-zstd', '--disable-redis-lz4'], 600],
                ['make', [self::ENV, '-C', $src, '/usr/bin/make', '-j2'], 1800],
            ];
            foreach ($steps as [$name, $argv, $timeout]) {
                $done = $this->run("build-$name", self::sandboxed($unit, $argv, $timeout, $this->systemdRun), $timeout + 60);
                if ($done['exit_code'] !== 0) {
                    throw new Refused("build step $name failed" . self::detail($done));
                }
            }
            // From here on root only copies and verifies; nothing the build produced is executed as root except by the load check.
            $built = "$outside/redis-{$prebuilt->extensionVersion}/modules/redis.so";
            $real = realpath($built);
            if ($real === false || is_link($built) || !is_file($real) || !str_starts_with($real, (string) realpath($outside) . '/')) {
                throw new Refused('the build produced no redis.so');
            }
            $size = (int) @filesize($real);
            if ($size < 1 || $size > 64 * 1024 * 1024) {
                throw new Refused('the build produced a redis.so of an implausible size');
            }
            $dir = "{$this->localRoot()}/$php";
            if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new Refused("cannot create $dir");
            }
            $target = "$dir/redis.so";
            $temporary = "$target.tmp-" . bin2hex(random_bytes(8));
            if (!@copy($real, $temporary) || !@chmod($temporary, 0755)) {
                @unlink($temporary);
                throw new Refused("cannot install $target");
            }
            $sha = (string) hash_file('sha256', $temporary);
            if (!hash_equals((string) hash_file('sha256', $real), $sha) || (int) filesize($temporary) !== $size || !@rename($temporary, $target)) {
                @unlink($temporary);
                throw new Refused("the copy of the build does not match the build; $target was not installed");
            }
            $entry = ['so' => $target, 'sha256' => $sha, 'size' => $size,
                'php_api' => $abi['api'], 'build_id' => $abi['build_id'], 'built_with' => $abi['version']];
            ($this->localIndex($prebuilt->extensionVersion)->with($php, $entry))->save();
            return $entry;
        } finally {
            $this->run('build-stop', [self::SYSTEMCTL, 'stop', "$unit.service"]);
            $this->run('build-cleanup', [self::RM, '-rf', '--', $outside, dirname($this->buildRoot) . "/$unit"]);
        }
    }

    /**
     * One build step as a transient, sandboxed service: a dynamic unprivileged user whose only writable place is its own
     * state directory, a read-only system, a private /tmp, no network, no capabilities, memory, task and time limits.
     * @param list<string> $argv
     * @return list<string>
     */
    public static function sandboxed(string $unit, array $argv, int $timeout, string $systemdRun = self::SYSTEMD_RUN): array
    {
        $properties = ['DynamicUser=yes', "StateDirectory=$unit", 'StateDirectoryMode=0700', "WorkingDirectory=/var/lib/$unit",
            "Environment=HOME=/var/lib/$unit", 'UMask=0077', 'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
            'PrivateNetwork=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'RestrictAddressFamilies=AF_UNIX', 'RestrictSUIDSGID=yes',
            'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'LockPersonality=yes',
            'MemoryMax=' . self::BUILD_MEMORY, 'MemorySwapMax=0', 'TasksMax=' . self::BUILD_TASKS, 'LimitNOFILE=4096', "RuntimeMaxSec=$timeout"];
        $command = [$systemdRun, '--quiet', '--wait', '--pipe', '--collect', "--unit=$unit"];
        foreach ($properties as $property) {
            array_push($command, '-p', $property);
        }
        return [...$command, '--', ...$argv];
    }

    /** Removes what an interrupted build left (the installer lock guarantees no build is running). */
    private function pruneBuilds(): void
    {
        foreach (is_dir($this->buildRoot) ? (scandir($this->buildRoot) ?: []) : [] as $name) {
            if (preg_match('/^' . preg_quote(self::BUILD_PREFIX, '/') . '[0-9a-f]{12}$/D', $name) === 1) {
                $this->run('build-prune', [self::RM, '-rf', '--', "{$this->buildRoot}/$name", dirname($this->buildRoot) . "/$name"]);
            }
        }
    }

    private function localIndex(string $version): ExtensionBundle
    {
        $local = ExtensionBundle::load($this->localRoot());
        return $local !== null && $local->extensionVersion === $version ? $local : ExtensionBundle::create($this->localRoot(), $version);
    }

    // --- Facts ------------------------------------------------------------------------------------------------

    /** @return array{version:string, api:string, build_id:string}|null from `php -n -i` */
    private function abi(string $php): ?array
    {
        $done = $this->run('abi', [$this->binary($php), '-n', '-i']);
        $fields = [];
        foreach (explode("\n", $done['stdout']) as $line) {
            if (preg_match('/^(PHP Version|PHP API|PHP Extension Build) => (.+)$/D', rtrim($line), $match) && !isset($fields[$match[1]])) {
                $fields[$match[1]] = trim($match[2]);
            }
        }
        if ($done['exit_code'] !== 0 || !isset($fields['PHP Version'], $fields['PHP API'], $fields['PHP Extension Build'])
            || preg_match('/^[0-9]{8}$/D', $fields['PHP API']) !== 1 || preg_match('/^API[0-9]{8},(NTS|ZTS)(,debug)?$/D', $fields['PHP Extension Build']) !== 1
            || preg_match('/^[0-9A-Za-z.+_-]{1,40}$/D', $fields['PHP Version']) !== 1) {
            return null;
        }
        return ['version' => $fields['PHP Version'], 'api' => $fields['PHP API'], 'build_id' => $fields['PHP Extension Build']];
    }

    /** true: our INI exists; false: a file of that name exists and is not ours; null: none. */
    private function ownIni(string $php): ?bool
    {
        $path = $this->ini($php);
        if (!is_file($path) || is_link($path)) {
            return is_link($path) ? false : null;
        }
        return str_starts_with((string) @file_get_contents($path), self::MARKER . "\n");
    }

    private function ensureWatcher(): bool
    {
        $all = true;
        foreach ([self::WATCHER, self::TIMER] as $unit) {
            if ($this->run('watcher-enabled', [self::SYSTEMCTL, 'is-enabled', '--quiet', $unit])['exit_code'] === 0) {
                continue;
            }
            $all = $this->run('watcher-enable', [self::SYSTEMCTL, 'enable', '--now', $unit])['exit_code'] === 0 && $all;
        }
        return $all;
    }

    /** @return list<string> */
    private function selected(?string $only): array
    {
        if ($only === null) {
            return $this->versions();
        }
        if (preg_match(ExtensionBundle::EA_PHP, $only) !== 1 || !in_array($only, $this->versions(), true)) {
            throw new Refused("$only is not an installed EA4 PHP version");
        }
        return [$only];
    }

    private function recordFailure(string $php, string $message): int
    {
        $state = ExtensionState::load($this->statePath());
        $attempts = ($state->failures[$php]['attempts'] ?? 0) + 1;
        $state->failures[$php] = ['at' => ($this->clock)(), 'attempts' => $attempts, 'error' => substr($message, 0, 600)];
        $state->save($this->statePath());
        return $attempts;
    }

    private function clearFailure(string $php): void
    {
        $state = ExtensionState::load($this->statePath());
        if (isset($state->failures[$php])) {
            unset($state->failures[$php]);
            $state->save($this->statePath());
        }
    }

    private function log(string $line): void
    {
        $path = "{$this->stateRoot}/php-ext.log";
        if (!is_dir($this->stateRoot)) {
            return;
        }
        if (is_file($path) && (int) @filesize($path) > self::LOG_LIMIT) {
            @rename($path, "$path.1");
        }
        @file_put_contents($path, gmdate('c', ($this->clock)()) . " $line\n", FILE_APPEND);
        fwrite(STDERR, "php-ext: $line\n");
    }

    // --- Paths and plumbing --------------------------------------------------------------------------------------

    private function binary(string $php): string
    {
        return "{$this->phpRoot}/$php/root/usr/bin/php";
    }

    private function ini(string $php): string
    {
        return "{$this->phpRoot}/$php/root/etc/php.d/" . self::INI;
    }

    private function localRoot(): string
    {
        return "{$this->stateRoot}/redis";
    }

    private function statePath(): string
    {
        return "{$this->stateRoot}/state.json";
    }

    /** @return list<string> */
    private static function lines(string $text): array
    {
        return array_map(static fn(string $l): string => strtolower(trim($l)), explode("\n", $text));
    }

    /** @param array{stdout:string, stderr?:string} $done */
    private static function detail(array $done): string
    {
        $text = substr(preg_replace('/[^\x20-\x7e]+/', ' ', trim(($done['stderr'] ?? '') !== '' ? $done['stderr'] : $done['stdout'])) ?? '', -240);
        return $text === '' ? '' : ": $text";
    }

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    private function run(string $name, array $argv, int $timeout = 60): array
    {
        return $this->runner->run('phpext-' . $name, $argv, $timeout);
    }

    /** @template T @param \Closure():T $work @return T */
    private function locked(\Closure $work): mixed
    {
        if (!is_dir($this->stateRoot) && !@mkdir($this->stateRoot, 0755, true) && !is_dir($this->stateRoot)) {
            throw new Refused("cannot create {$this->stateRoot}");
        }
        $lock = @fopen("{$this->stateRoot}/lock", 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new Refused('cannot take the php-ext lock');
        }
        try {
            return $work();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
