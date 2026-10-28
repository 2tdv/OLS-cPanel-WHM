<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\PhpRestart;

/**
 * OPcache for the EA4 PHP versions (FV-03). The extension is the EA4 package ea-phpXX-php-opcache (cPanel's EA4
 * repository is configured on every cPanel server; its default php.ini already carries opcache.enable=1 and
 * opcache.validate_permission=1). Installing it and tuning it takes effect only after the account's lsphp
 * processes restart (a graceful OLS reload keeps detached lsphp processes), so a change always ends with
 * PhpRestart for the accounts on that version.
 *
 * Root only. Every external command is a fixed argv through the Environment's runner (dnf, rpm, the version's
 * own php, systemctl); the version is validated against /opt/cpanel/ea-phpNN directories that exist.
 * The shared-hosting tuning is one drop-in, /opt/cpanel/ea-phpXX/root/etc/php.d/zz-ols-cpanel-opcache.ini: it
 * is not owned by an RPM, so EA4 updates leave it alone, and its name sorts after every package's own file.
 *
 * Since FV-10 the service behind the timer runs Php\PhpEnvironment (`php env sync`), which calls convergeVersion() per version
 * together with lsphp and redis; `php opcache reconcile` remains as the OPcache-only pass.
 *
 * reconcile() is level-triggered and idempotent: for every installed version that does not run the wanted
 * configuration it does what install() does, and nothing otherwise. The root timer ols-cpanel-php.timer
 * runs it, so a PHP version installed or rebuilt later (EA4 updates, MultiPHP) is converged without a manual
 * step. `install --prepare --no-opcache` records the operator's opt-out; an explicit `php opcache install`
 * removes it.
 */
final class OpcacheManager
{
    public const OPT = '/opt/cpanel';
    public const USERDATADOMAINS = '/etc/userdatadomains';
    public const VERSION = '/^ea-php[0-9]{2,3}$/D';
    public const INI = 'zz-ols-cpanel-opcache.ini';
    /** First line of the INI the product writes; the only proof that a file of that name is its own. */
    public const MARKER = '; Managed by ols-cpanel (php opcache install, rewritten by php opcache reconcile): OPcache for shared hosting.';
    public const TIMER = 'ols-cpanel-php.timer';
    /** Fires the service after every package transaction (watches rpm's lock file). */
    public const WATCHER = 'ols-cpanel-php.path';
    public const SERVICE = 'ols-cpanel-php.service';
    /** The units that run the PHP environment pass; enabled whenever any automatic PHP management is active. */
    public const UNITS = [self::WATCHER, self::TIMER];
    public const DNF = '/usr/bin/dnf';
    public const RPM = '/usr/bin/rpm';
    public const SYSTEMCTL = '/usr/bin/systemctl';
    /** Settings the tuning sets, and shown by status. */
    public const KEYS = ['enable', 'validate_root', 'validate_permission', 'memory_consumption', 'max_accelerated_files', 'revalidate_freq'];
    public const MAX_FILES = 20000;
    public const REVALIDATE = 2;
    private const DNF_TIMEOUT = 1800;

    private ?PhpRestartLedger $ledger = null;

    public function __construct(private readonly Environment $env, private readonly string $optRoot = self::OPT,
                                private readonly string $userdata = self::USERDATADOMAINS, private readonly ?string $statePath = null,
                                ?PhpRestartLedger $ledger = null)
    {
        $this->ledger = $ledger;
    }

    /** The owed worker restarts (kept in the PHP environment state; see PhpRestartLedger). */
    public function ledger(): PhpRestartLedger
    {
        return $this->ledger ??= PhpRestartLedger::forEnvironment($this->env, fn(string $version): ?array => $this->accountsOrNull($version));
    }

    public function statePath(): string
    {
        return $this->statePath ?? $this->env->state . '/php-opcache.json';
    }

    /**
     * OPcache memory per version, in MB (opcache.memory_consumption). The segment belongs to one account's lsphp
     * family (the parent creates it, its children share it), so the total is bounded by what each account
     * actually caches: the pages are demand-allocated, a setting is a ceiling and not a reservation. A full cache
     * restarts itself and loses the benefit, so the ceiling must cover a large WordPress or WooCommerce site
     * (40-80 MB of compiled scripts on PHP 8, a little less on 7, less again on 5.x): 128 for PHP 8 and later,
     * 96 for 7.x, 64 for 5.x. The same count of files (20000) fits all three.
     */
    public static function memoryMb(string $version): int
    {
        $digits = substr($version, 6);
        $major = (int) substr($digits, 0, -1);
        return $major >= 8 ? 128 : ($major === 7 ? 96 : 64);
    }

    /** @return array<string,string> setting => wanted value */
    public static function wanted(string $version): array
    {
        // enable=1 is managed and verified: a disabled OPcache (an admin's php.ini, a profile) is never "tuned". enable_cli is
        // not touched (it only concerns the CLI).
        return ['enable' => '1', 'validate_root' => '1', 'validate_permission' => '1', 'memory_consumption' => (string) self::memoryMb($version),
            'max_accelerated_files' => (string) self::MAX_FILES, 'revalidate_freq' => (string) self::REVALIDATE];
    }

    public static function iniText(string $version): string
    {
        $lines = [self::MARKER,
            '; enable=1 keeps OPcache on; validate_root and validate_permission keep one account from reading another account\'s cached scripts.'];
        foreach (self::wanted($version) as $key => $value) {
            $lines[] = "opcache.$key=$value";
        }
        return implode("\n", $lines) . "\n";
    }

    public function iniPath(string $version): string
    {
        return "{$this->optRoot}/$version/root/etc/php.d/" . self::INI;
    }

    /**
     * Uninstall: the versions whose php.d holds this product's OPcache INI, found by directory name and by the first line of the
     * file (a link or a file of that name that is not ours is never counted). The OPcache packages are left installed.
     * @return list<string>
     */
    public function ownInis(): array
    {
        $found = [];
        foreach (@scandir($this->optRoot) ?: [] as $name) {
            if (preg_match(self::VERSION, $name) === 1 && $this->ownIni($this->iniPath($name))) {
                $found[] = $name;
            }
        }
        return $found;
    }

    /**
     * Uninstall: removes the INI of every version that carries ours (see ownInis) and nothing else.
     * @return list<array{php:string, status:string}> status: removed or failed
     */
    public function removeInis(): array
    {
        $rows = [];
        foreach ($this->ownInis() as $version) {
            $rows[] = ['php' => $version, 'status' => @unlink($this->iniPath($version)) ? 'removed' : 'failed'];
        }
        return $rows;
    }

    private function ownIni(string $path): bool
    {
        return !is_link($path) && is_file($path) && str_starts_with((string) @file_get_contents($path, false, null, 0, 4096), self::MARKER . "\n");
    }

    public static function package(string $version): string
    {
        return "$version-php-opcache";
    }

    /** The installed EA4 PHP versions with an lsphp or php binary, oldest first. @return list<string> */
    public function versions(): array
    {
        $found = [];
        foreach (@scandir($this->optRoot) ?: [] as $name) {
            if (preg_match(self::VERSION, $name) === 1 && (is_file("{$this->optRoot}/$name/root/usr/bin/lsphp")
                    || is_file("{$this->optRoot}/$name/root/usr/bin/php"))) {
                $found[] = $name;
            }
        }
        usort($found, static fn(string $a, string $b): int => (int) substr($a, 6) <=> (int) substr($b, 6));
        return $found;
    }

    public static function dotted(string $version): string
    {
        $digits = substr($version, 6);
        return substr($digits, 0, -1) . '.' . substr($digits, -1);
    }

    /** @return array<string,mixed> */
    public function status(?string $only = null): array
    {
        $this->env->requireRoot();
        $present = $this->versions();
        if ($only !== null && !in_array($only, $present, true)) {
            throw new Refused("$only is not an installed EA4 PHP version");
        }
        $versions = [];
        foreach ($only !== null ? [$only] : $present as $version) {
            $versions[] = $this->versionStatus($version);
        }
        $state = $this->state();
        return ['result' => 'status', 'auto' => $state['auto'], 'timer' => $this->timerEnabled(), 'watcher' => $this->unitEnabled(self::WATCHER),
            'versions' => $versions];
    }

    /** @return array<string,mixed> */
    public function versionStatus(string $version): array
    {
        $observed = $this->observe($version);
        $wanted = self::wanted($version);
        $matches = $observed['loaded'];
        foreach ($wanted as $key => $value) {
            $matches = $matches && self::same($observed['settings'][$key] ?? null, $value);
        }
        // Every key is always present (null: not reported, e.g. the extension is not loaded), so the settings are a
        // JSON object in every case and a reader never meets a missing field.
        $settings = [];
        foreach (self::KEYS as $key) {
            $settings[$key] = $observed['settings'][$key] ?? null;
        }
        return ['version' => $version, 'php' => self::dotted($version), 'package' => self::package($version),
            'package_installed' => $this->packageInstalled($version), 'loaded' => $observed['loaded'],
            'settings' => $settings, 'wanted' => $wanted, 'tuned' => $matches,
            'ini_file' => is_file($this->iniPath($version)), 'accounts' => count($this->accountsOf($version))];
    }

    /**
     * Installs and tunes one version or all of them, then restarts lsphp of the accounts on the versions that changed.
     * An explicit install lifts the operator's opt-out of the automatic management.
     * @return array<string,mixed>
     */
    public function install(?string $version, bool $all): array
    {
        $this->env->requireRoot();
        $present = $this->versions();
        if ($all === ($version !== null)) {
            throw new Refused('name one --version=ea-phpNN or --all');
        }
        if ($version !== null && !in_array($version, $present, true)) {
            throw new Refused("$version is not an installed EA4 PHP version");
        }
        $this->setAuto(true);
        $rows = [];
        foreach ($version !== null ? [$version] : $present as $name) {
            $rows[] = $this->converge($name);
        }
        $result = $this->summary('installed', $rows);
        // Automatic management is on, so the units that keep it converged must run (a manual install used to leave them off).
        $result['timer'] = $this->ensureTimer();
        return $result;
    }

    /** One version, converged now (package, tuning drop-in, verification, restart of its accounts). @return array<string,mixed> */
    public function convergeVersion(string $version): array
    {
        $this->env->requireRoot();
        return $this->converge($version);
    }

    /** @return bool whether automatic OPcache management is on (not opted out) */
    public function auto(): bool
    {
        return $this->state()['auto'];
    }

    /**
     * Converges every installed version that does not run the wanted configuration (the root timer's pass).
     * @return array<string,mixed>
     */
    public function reconcile(): array
    {
        $this->env->requireRoot();
        if (!$this->state()['auto']) {
            return ['result' => 'disabled', 'note' => 'automatic OPcache management was turned off (install --prepare --no-opcache); '
                . 'php opcache install turns it on again', 'versions' => [], 'changed' => 0, 'failed' => 0];
        }
        $rows = [];
        foreach ($this->versions() as $name) {
            $rows[] = $this->converge($name);
        }
        return $this->summary('reconciled', $rows);
    }

    /** The automatic step of `install --prepare`: records the opt-out, or installs everywhere and enables the timer. @return array<string,mixed> */
    public function prepare(bool $optOut): array
    {
        $this->env->requireRoot();
        if ($optOut) {
            $this->setAuto(false);
            return ['result' => 'disabled', 'note' => 'OPcache management was skipped (--no-opcache)'];
        }
        return $this->install(null, true);
    }

    /** Enables the path watcher and the timer of the PHP environment pass (idempotent). @return bool every unit is enabled */
    public function ensureTimer(): bool
    {
        $all = true;
        foreach (self::UNITS as $unit) {
            if ($this->unitEnabled($unit)) {
                continue;
            }
            $all = $this->env->host->run('opcache-unit-enable', [self::SYSTEMCTL, 'enable', '--now', $unit])['exit_code'] === 0 && $all;
        }
        return $all;
    }

    private function timerEnabled(): bool
    {
        return $this->unitEnabled(self::TIMER);
    }

    private function unitEnabled(string $unit): bool
    {
        return $this->env->host->run('opcache-unit-enabled', [self::SYSTEMCTL, 'is-enabled', '--quiet', $unit])['exit_code'] === 0;
    }

    /**
     * @param list<array<string,mixed>> $rows
     * @return array<string,mixed>
     */
    private function summary(string $result, array $rows): array
    {
        $failed = count(array_filter($rows, static fn(array $r): bool => $r['result'] === 'failed'));
        $changed = count(array_filter($rows, static fn(array $r): bool => in_array($r['result'], ['installed', 'tuned'], true)));
        return ['result' => $failed > 0 ? 'failed' : $result, 'changed' => $changed, 'failed' => $failed, 'versions' => $rows];
    }

    /**
     * One version: package, tuning drop-in, verification, restart. A version that already reports the wanted
     * settings is left alone (no write, no restart).
     * @return array<string,mixed>
     */
    private function converge(string $version): array
    {
        $row = ['version' => $version, 'result' => 'unchanged', 'package_installed_now' => false, 'ini_written' => false,
            'verified' => false, 'restarted' => [], 'error' => null];
        $before = $this->versionStatus($version);
        if ($before['tuned']) {
            $row['verified'] = true;
            if ($this->ledger()->pending() !== []) {
                $this->settle($row, $version);  // an earlier restart that did not complete is retried here too
            }
            return $row;
        }
        try {
            if (!$before['loaded']) {
                $done = $this->env->host->run('opcache-dnf', [self::DNF, '-y', 'install', self::package($version)], self::DNF_TIMEOUT);
                if ($done['exit_code'] !== 0) {
                    throw new Refused('dnf could not install ' . self::package($version) . ': '
                        . trim(substr(preg_replace('/[^\x20-\x7e\n]/', '?', (string) ($done['stderr'] ?? '') ?: $done['stdout']) ?? '', -300)));
                }
                // A package that is installed but not reporting the extension (a transient php failure) is not a new install.
                $row['package_installed_now'] = !$before['package_installed'];
            }
            $path = $this->iniPath($version);
            $text = self::iniText($version);
            if (!is_dir(dirname($path))) {
                throw new Refused('no ' . dirname($path));
            }
            if (is_link($path) || @file_get_contents($path) !== $text) {
                Environment::writeFile($path, $text, 0644);
                $row['ini_written'] = true;
            }
            if ($row['package_installed_now'] || $row['ini_written']) {
                // Every account on the version is owed a restart; recorded durably before verification and before the first attempt.
                $this->ledger()->mark($version, 'opcache:' . hash('sha256', $text) . ($row['package_installed_now'] ? ':package' : ''));
            }
            $after = $this->versionStatus($version);
            if (!$after['tuned']) {
                throw new Refused($version . ' does not report the wanted OPcache settings after the installation: '
                    . ($after['loaded'] ? 'check ' . $path . ' and other ini files that set opcache' : 'the extension is not loaded'));
            }
            $row['verified'] = true;
            if ($row['package_installed_now'] || $row['ini_written']) {
                $row['result'] = $row['package_installed_now'] ? 'installed' : 'tuned';
            }
            $this->settle($row, $version);
        } catch (Refused | DeploymentError $error) {
            $row['result'] = 'failed';
            $row['error'] = $error->getMessage();
        }
        return $row;
    }

    /**
     * Retries the owed lsphp restarts of the version. Restarts that still fail keep the row failed (the PHP
     * environment applier then reports it and retries on its schedule).
     * @param array<string,mixed> $row
     */
    private function settle(array &$row, string $version): void
    {
        try {
            $report = $this->ledger()->settle($version);
        } catch (Refused | DeploymentError $error) {
            $row['result'] = 'failed';
            $row['error'] = 'lsphp restart pending: ' . $error->getMessage();
            return;
        }
        foreach ($report['restarted'] as $done) {
            $row['restarted'][] = ['account' => $done['account'], 'result' => $done['result']];
        }
        if ($report['pending'] !== [] || $report['unresolved'] !== []) {
            $row['result'] = 'failed';
            $row['error'] = PhpRestartLedger::describe($report) . ($report['errors'] === [] ? '' : ': ' . implode('; ', array_slice($report['errors'], 0, 3)));
        }
    }

    /** Accounts with a domain on the version, or null when the cPanel domain list cannot be read. @return list<string>|null */
    public function accountsOrNull(string $version): ?array
    {
        return @is_readable($this->userdata) && @file_get_contents($this->userdata, false, null, 0, 1) !== false ? $this->accountsOf($version) : null;
    }

    /** @return list<string> */
    public function accountsOf(string $version): array
    {
        $text = @file_get_contents($this->userdata, false, null, 0, 16 * 1024 * 1024);
        $users = [];
        foreach (explode("\n", $text === false ? '' : $text) as $line) {
            $split = explode(': ', $line, 2);
            $fields = explode('==', $split[1] ?? '');
            if (count($fields) >= 10 && $fields[9] === $version && preg_match(PhpRestart::ACCOUNT, $fields[0]) === 1) {
                $users[$fields[0]] = true;
            }
        }
        $names = array_keys($users);
        sort($names, SORT_STRING);
        return $names;
    }

    private function packageInstalled(string $version): bool
    {
        return $this->env->host->run('opcache-package', [self::RPM, '-q', self::package($version)])['exit_code'] === 0;
    }

    /**
     * What the version's own php reports (php -i): whether OPcache is loaded and the local value of the settings.
     * @return array{loaded:bool, settings:array<string,string>}
     */
    private function observe(string $version): array
    {
        $root = "{$this->optRoot}/$version/root/usr/bin";
        $php = is_file("$root/php") ? "$root/php" : "$root/lsphp";
        $record = $this->env->host->run('opcache-php-info', [$php, '-i'], 60);
        $settings = [];
        if ($record['exit_code'] === 0 && preg_match_all('/^opcache\.([a-z_]+) => (.*?) => /m', $record['stdout'], $matches, PREG_SET_ORDER) > 0) {
            foreach ($matches as $m) {
                if (in_array($m[1], self::KEYS, true)) {
                    $settings[$m[1]] = trim($m[2]);
                }
            }
        }
        // The directives are listed only while the extension is loaded.
        return ['loaded' => isset($settings['memory_consumption']), 'settings' => $settings];
    }

    /** "On"/"1" and "Off"/"0" compare as booleans, numbers as numbers. */
    private static function same(?string $shown, string $wanted): bool
    {
        if ($shown === null) {
            return false;
        }
        $norm = static fn(string $v): string => match (strtolower(trim($v))) {
            'on', 'yes', 'true' => '1',
            'off', 'no', 'false' => '0',
            default => strtolower(trim($v)),
        };
        return $norm($shown) === $norm($wanted);
    }

    /** @return array{auto:bool} */
    public function state(): array
    {
        $text = is_file($this->statePath()) && !is_link($this->statePath()) ? @file_get_contents($this->statePath(), false, null, 0, 4096) : false;
        $data = $text === false ? null : json_decode($text, true);
        return ['auto' => !is_array($data) || ($data['auto'] ?? true) !== false];
    }

    private function setAuto(bool $auto): void
    {
        if ($this->state()['auto'] === $auto && is_file($this->statePath())) {
            return;
        }
        Environment::ensureDir(dirname($this->statePath()), 0755);
        Environment::writeFile($this->statePath(), json_encode(['auto' => $auto], JSON_THROW_ON_ERROR) . "\n", 0644);
    }
}
