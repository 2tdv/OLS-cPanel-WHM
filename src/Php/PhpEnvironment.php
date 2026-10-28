<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Ea4Profile;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Events\HookEntry;
use OlsCpanel\PhpExtensions\ExtensionService;

/**
 * The PHP environment applier (FV-10): the one root pass that keeps every installed EasyApache 4 PHP version
 * complete for OLS, whatever EasyApache, MultiPHP or a profile does to the packages. For each version:
 *
 *  1. `ea-phpXX-php-litespeed` (lsphp, the binary every OLS vhost runs PHP through) is installed and executes;
 *  2. OPcache is installed and tuned (OpcacheManager, unless the operator opted out of OPcache management);
 *  3. the redis extension loads (ExtensionInstaller: prebuilt, earlier build or an on-server build), once the
 *     product wants it (set by `install --prepare` and the object cache).
 *
 * Missing packages are installed with `dnf -y install` through the CommandRunner (cPanel's EA4 repository is
 * configured on every cPanel server); lsphp of the accounts on a version that changed is restarted by the
 * steps themselves (PhpRestart), never for another version. Level-triggered and idempotent: a pass over complete
 * versions only reads. The pass runs as ols-cpanel-php.service, started by ols-cpanel-php.path after every
 * package transaction (rpm's lock file), by ols-cpanel-php.timer (the fallback) and by `php env repair` (the
 * WHM button). It also keeps the recommended EA4 profile file present (Ea4Profile).
 *
 * State, one file (`<state>/php-env.json`): per version `complete`, `repairing` or `failed` with the reason, the
 * attempt count and the time of the next automatic retry (back-off 1, 5, 15, 30 minutes, then every 30 minutes),
 * so a failure is always reported (WHM, `php env status`, the journal) and never silently dropped. `repair`
 * ignores the back-off. Root only.
 *
 * The same file holds the restart ledger (key `restarts`, Php\PhpRestartLedger): every change to a version (OPcache
 * tuning, redis installed, replaced or removed) marks ALL accounts on that version as owed an lsphp restart, per
 * revision, and every pass retries what is still owed (also for versions waiting out a back-off); an entry is
 * cleared only after its restart succeeded. A version whose restarts are still owed is reported failed.
 *
 * Every pass also ends the lsphp of accounts whose running processes carry an old extProcessor environment (a new
 * product release changed an `env` line; detached lsphp keeps the old one), see LsphpEnvironmentCheck; reported as
 * `lsphp_environment`, never fatal, and nothing is restarted for an account that already matches.
 *
 * The timer and path units that run this pass are enabled by every pass; when they cannot be enabled the pass fails
 * and says so. PHP older than 7.4 has no redis support (phpredis 6.3.0): such a version shows `unsupported` for redis
 * and is not a failure.
 */
final class PhpEnvironment
{
    public const FILE = 'php-env.json';
    public const LOCK = 'php-env.lock';
    public const DNF = '/usr/bin/dnf';
    public const DNF_TIMEOUT = 1800;
    /** Seconds until the next automatic retry after the 1st, 2nd, 3rd and later failed attempts. */
    public const BACKOFF = [60, 300, 900, 1800];
    /** A "repairing" record older than this is an interrupted pass, shown as failed. */
    public const STALE_SECONDS = 7200;
    private const MAX_ERROR = 400;

    private PhpRestartLedger $ledger;

    public function __construct(private readonly Environment $env, private readonly OpcacheManager $opcache,
                                private readonly ExtensionService $redis, private readonly ?Ea4Profile $profile = null,
                                private readonly ?string $phpRoot = null, ?PhpRestartLedger $ledger = null)
    {
        $this->ledger = $ledger ?? $opcache->ledger();
    }

    /** The directory of the EA4 PHP versions (/opt/cpanel). */
    private function root(): string
    {
        return $this->phpRoot ?? $this->env->phpRoot;
    }

    /** The server wiring: the production environment, OPcache manager, redis layer and recommended profile. */
    public static function production(?Environment $env = null): self
    {
        $env ??= Environment::production();
        return new self($env, new OpcacheManager($env), \OlsCpanel\PhpExtensions\ExtensionSync::production($env), $env->ea4Profile());
    }

    public function statePath(): string
    {
        return $this->env->state . '/' . self::FILE;
    }

    public function lsphpPath(string $version): string
    {
        return "{$this->root()}/$version/root/usr/bin/lsphp";
    }

    /** lsphp is a file with an execute bit (the check the compiler's guard makes, without running it; by mode, so it holds on any mount). */
    public static function lsphpPresent(string $phpRoot, string $version): bool
    {
        $path = "$phpRoot/$version/root/usr/bin/lsphp";
        return is_file($path) && ((int) @fileperms($path) & 0111) !== 0;
    }

    // --- Operations ----------------------------------------------------------------------------------------------

    /**
     * The automatic pass: versions in back-off are left for their retry time. @return array<string,mixed>
     */
    public function sync(): array
    {
        $this->env->requireRoot();
        return $this->locked(fn(): array => $this->pass(false));
    }

    /** The WHM button: every version now, back-off ignored. @return array<string,mixed> */
    public function repair(): array
    {
        $this->env->requireRoot();
        return $this->locked(fn(): array => $this->pass(true));
    }

    /**
     * `install --prepare`: the product now wants the redis extension everywhere, the units run, the recommended
     * profile exists, and every version is brought complete. @return array<string,mixed>
     */
    public function prepare(): array
    {
        $this->env->requireRoot();
        $this->redis->want();
        return $this->locked(fn(): array => $this->pass(true));
    }

    /**
     * Read only (state file and cheap checks): what WHM and `php env status` show.
     * @return array<string,mixed>
     */
    public function status(): array
    {
        $state = $this->load();
        $now = $this->env->now();
        $rows = [];
        foreach ($this->opcache->versions() as $version) {
            $known = $state['versions'][$version] ?? null;
            $live = self::lsphpPresent($this->root(), $version);
            if ($known === null) {
                $row = $this->row($version, 'pending', $now) + ['error' => null];
            } else {
                $row = $known;
                if ($row['status'] === 'repairing' && $now - ($row['since'] ?? $row['checked_at']) > self::STALE_SECONDS) {
                    $row['status'] = 'failed';
                    $row['error'] = 'an earlier pass was interrupted; the next pass repairs it';
                } elseif ($row['status'] === 'complete' && !$live) {
                    $row['status'] = 'repairing';
                    $row['error'] = 'lsphp is missing again (a package change); the next pass reinstalls it';
                }
            }
            $row['lsphp'] = $live;
            $rows[] = $row;
        }
        return ['result' => 'status', 'checked_at' => $state['checked_at'], 'opcache_auto' => $this->opcache->auto(),
            'units' => ['watcher' => $this->unit(OpcacheManager::WATCHER), 'timer' => $this->unit(OpcacheManager::TIMER)],
            'profile' => ['file' => $this->profile?->path(), 'present' => $this->profile?->present() ?? false,
                'error' => $state['profile_error']],
            'restarts' => $this->restartsOwed(),
            'versions' => $rows];
    }

    // --- The pass -------------------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private function pass(bool $force): array
    {
        $state = $this->load();
        $now = $this->env->now();
        $units = $this->opcache->ensureTimer();
        $profile = $this->ensureProfile($state);
        try {
            $redis = $this->redis->status();
        } catch (Refused $error) {
            $redis = ['wanted' => false, 'versions' => [], 'error' => $error->getMessage()];
        }
        $redisWanted = ($redis['wanted'] ?? false) === true;
        $loaded = [];
        $replaced = [];
        $unsupported = [];
        foreach ($redis['versions'] ?? [] as $row) {
            $loaded[$row['php']] = ($row['loaded'] ?? false) === true;
            $replaced[$row['php']] = ($row['replaced'] ?? false) === true;
            $unsupported[$row['php']] = ($row['status'] ?? '') === 'unsupported';
        }
        $auto = $this->opcache->auto();
        $rows = [];
        $needRedis = [];
        $failure = [];
        foreach ($this->opcache->versions() as $version) {
            $prev = $state['versions'][$version] ?? null;
            if (!$force && $prev !== null && $prev['status'] === 'failed' && ($prev['retry_at'] ?? 0) > $now) {
                $rows[$version] = ['changed' => false, 'restarted' => [], 'waiting' => true] + $prev;
                continue;
            }
            $row = $this->row($version, 'complete', $now);
            $row['changed'] = false;
            $row['prev_attempts'] = $prev !== null && $prev['status'] === 'failed' ? (int) ($prev['attempts'] ?? 0) : 0;
            $row['lsphp'] = self::lsphpPresent($this->root(), $version);
            $redisDue = $redisWanted && !($unsupported[$version] ?? false) && (($loaded[$version] ?? false) === false || ($replaced[$version] ?? false));
            $work = !$row['lsphp'] || ($auto && !$this->opcache->versionStatus($version)['tuned']) || $redisDue;
            if ($work) {
                $state['versions'][$version] = $this->row($version, 'repairing', $now)
                    + ['since' => $now, 'error' => null, 'attempts' => $row['prev_attempts']];
                $this->save($state);
            }
            $errors = [];
            $row['restarted'] = [];
            if (!$row['lsphp']) {
                $problem = $this->installLsphp($version);
                $row['lsphp'] = $problem === null;
                $row['changed'] = $row['lsphp'];
                if ($problem !== null) {
                    $errors[] = $problem;
                }
            }
            if ($auto) {
                $done = $this->opcache->convergeVersion($version);
                $row['opcache'] = $done['result'] === 'failed' ? 'failed' : ($done['result'] === 'unchanged' ? 'ok' : 'repaired');
                $row['changed'] = $row['changed'] || $row['opcache'] === 'repaired';
                foreach ($done['restarted'] ?? [] as $restart) {
                    $row['restarted'][] = $restart['account'];
                }
                if ($done['result'] === 'failed') {
                    $errors[] = 'OPcache: ' . ($done['error'] ?? 'failed');
                }
            } else {
                $row['opcache'] = 'off';
            }
            $row['redis'] = !$redisWanted ? 'not_wanted' : (($unsupported[$version] ?? false) ? 'unsupported' : ($redisDue ? 'pending' : 'active'));
            if ($row['redis'] === 'pending') {
                $needRedis[] = $version;
            }
            $row['errors'] = $errors;
            $rows[$version] = $row;
        }
        if ($needRedis !== []) {
            $this->redisStep($needRedis, $rows);
        }
        $restarts = $this->settleRestarts($rows);
        $report = $this->finish($state, $rows, $now, $units, $profile, $force, $restarts);
        $report['lsphp_environment'] = $this->lsphpEnvironment();
        return $report;
    }

    /**
     * Restarts the lsphp of accounts whose running processes still carry an old extProcessor environment (a detached
     * lsphp keeps it across OLS reloads); a failure is reported and never fatal to the pass.
     * @return array{checked:int, restarted:list<string>, errors:list<string>}
     */
    private function lsphpEnvironment(): array
    {
        try {
            return (new LsphpEnvironmentCheck($this->env))->run();
        } catch (\Throwable $error) {
            return ['checked' => 0, 'restarted' => [], 'errors' => [substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200)]];
        }
    }

    /**
     * @param list<string> $versions
     * @param array<string,array<string,mixed>> $rows
     */
    private function redisStep(array $versions, array &$rows): void
    {
        try {
            $report = $this->redis->ensureVersions($versions);
        } catch (Refused | DeploymentError $error) {
            foreach ($versions as $version) {
                $rows[$version]['redis'] = 'failed';
                $rows[$version]['errors'][] = 'redis: ' . $error->getMessage();
            }
            return;
        }
        $accounts = array_keys($report['restart'] ?? []);
        foreach ($report['versions'] ?? [] as $result) {
            $version = $result['php'] ?? null;
            if (!is_string($version) || !isset($rows[$version])) {
                continue;
            }
            if (($result['status'] ?? '') === 'unsupported') {
                $rows[$version]['redis'] = 'unsupported';
            } elseif (in_array($result['status'] ?? '', ['active', 'already_loaded', 'activated', 'replaced'], true)) {
                $rows[$version]['redis'] = in_array($result['status'] ?? '', ['activated', 'replaced'], true) ? 'repaired' : 'active';
                $rows[$version]['changed'] = $rows[$version]['changed'] || $rows[$version]['redis'] === 'repaired';
                if ($rows[$version]['redis'] === 'repaired') {
                    $rows[$version]['restarted'] = array_values(array_unique([...$rows[$version]['restarted'], ...$accounts]));
                }
            } else {
                $rows[$version]['redis'] = 'failed';
                $rows[$version]['errors'][] = 'redis: ' . ($result['message'] ?? $result['status'] ?? 'failed');
            }
        }
    }

    /**
     * Records the outcome of every version (failure: attempts, next retry) and returns the report.
     * @param array<string,mixed> $state
     * @param array<string,array<string,mixed>> $rows
     * @param array<string,mixed> $restarts
     * @return array<string,mixed>
     */
    private function finish(array $state, array $rows, int $now, bool $units, ?array $profile, bool $force, array $restarts): array
    {
        $versions = [];
        $failed = false;
        $changed = false;
        foreach ($rows as $version => $row) {
            if (($row['waiting'] ?? false) === true) {
                $failed = true;
                $versions[] = $row;
                continue;
            }
            $errors = $row['errors'] ?? [];
            $prevAttempts = (int) $row['prev_attempts'];
            unset($row['errors'], $row['prev_attempts']);
            if ($errors === []) {
                $record = $row + ['error' => null, 'attempts' => 0, 'retry_at' => null];
            } else {
                $attempts = $prevAttempts + 1;
                $record = ['status' => 'failed', 'error' => substr(preg_replace('/[^\x20-\x7e]/', '?', implode('; ', $errors)) ?? '', 0, self::MAX_ERROR),
                    'attempts' => $attempts, 'retry_at' => $now + self::BACKOFF[min($attempts, count(self::BACKOFF)) - 1]] + $row;
                $failed = true;
            }
            $changed = $changed || ($record['changed'] ?? false) === true;
            $state['versions'][$version] = array_diff_key($record, ['changed' => 0, 'restarted' => 0]);
            $versions[] = $record;
        }
        foreach (array_keys($state['versions']) as $name) {
            if (!isset($rows[$name])) {
                unset($state['versions'][$name]);  // the version is gone (removed in EasyApache)
            }
        }
        $state['checked_at'] = $now;
        $this->save($state);
        // A version whose restarts are owed is a failure even while it waits out a back-off; so are units that cannot be enabled.
        $failed = $failed || $restarts['pending'] !== [] || $restarts['unresolved'] !== [] || $restarts['error'] !== null || !$units;
        return ['result' => $failed ? 'failed' : ($changed ? 'repaired' : 'unchanged'), 'forced' => $force, 'units' => $units,
            'units_error' => $units ? null : 'the path watcher or the timer of this pass could not be enabled, so nothing would retry it',
            'profile' => $profile, 'restarts' => $restarts, 'versions' => $versions];
    }

    /**
     * Retries every owed lsphp restart (all versions, whatever their back-off) and puts what is still owed on the
     * version rows as an error, so the version is failed and retried with its back-off.
     * @param array<string,array<string,mixed>> $rows
     * @return array{pending:array<string,list<string>>, unresolved:list<string>, errors:list<string>, error:?string}
     */
    private function settleRestarts(array &$rows): array
    {
        try {
            $report = $this->ledger->settle();
        } catch (Refused | DeploymentError $error) {
            return ['pending' => [], 'unresolved' => [], 'errors' => [], 'error' => 'restart ledger: ' . $error->getMessage()];
        }
        foreach ($report['restarted'] as $done) {
            if ($done['result'] === 'restarted' && isset($rows[$done['version']]) && ($rows[$done['version']]['waiting'] ?? false) !== true) {
                $rows[$done['version']]['restarted'] = array_values(array_unique([...($rows[$done['version']]['restarted'] ?? []), $done['account']]));
            }
        }
        foreach ([...array_keys($report['pending']), ...$report['unresolved']] as $version) {
            if (isset($rows[$version]) && ($rows[$version]['waiting'] ?? false) !== true) {
                $rows[$version]['errors'][] = PhpRestartLedger::describe(['pending' => array_intersect_key($report['pending'], [$version => 1]),
                    'unresolved' => array_values(array_intersect($report['unresolved'], [$version]))])
                    . ($report['errors'] === [] ? '' : ': ' . implode('; ', array_slice($report['errors'], 0, 2)));
            }
        }
        return ['pending' => $report['pending'], 'unresolved' => $report['unresolved'], 'errors' => $report['errors'], 'error' => null];
    }

    /** @return list<array{version:string, accounts:list<string>, unresolved:bool, since:int}> restarts still owed (read only) */
    private function restartsOwed(): array
    {
        $owed = [];
        foreach ($this->ledger->pending() as $version => $entry) {
            $owed[] = ['version' => $version, 'accounts' => array_keys($entry['accounts']), 'unresolved' => $entry['unresolved'], 'since' => $entry['since']];
        }
        return $owed;
    }

    // --- Steps ----------------------------------------------------------------------------------------------------

    /** @return string|null the reason when lsphp is still not usable */
    private function installLsphp(string $version): ?string
    {
        $package = "$version-php-litespeed";
        $done = $this->env->runner->run('phpenv-dnf-litespeed', [self::DNF, '-y', 'install', $package], self::DNF_TIMEOUT);
        if ($done['exit_code'] !== 0) {
            return "dnf could not install $package: "
                . trim(substr(preg_replace('/[^\x20-\x7e\n]/', '?', (string) ($done['stderr'] ?? '') ?: $done['stdout']) ?? '', -240));
        }
        if (!self::lsphpPresent($this->root(), $version)) {
            return "$package is installed but {$this->lsphpPath($version)} is missing or not executable";
        }
        $run = $this->env->runner->run('phpenv-lsphp-version', [$this->lsphpPath($version), '-v'], 30);
        if ($run['exit_code'] !== 0 || !str_starts_with(ltrim($run['stdout']), 'PHP ')) {
            return "{$this->lsphpPath($version)} does not run (lsphp -v failed)";
        }
        return null;
    }

    /**
     * The recommended profile file; a failure is recorded, never fatal.
     * @param array<string,mixed> $state
     * @return array<string,mixed>|null
     */
    private function ensureProfile(array &$state): ?array
    {
        if ($this->profile === null) {
            return null;
        }
        try {
            $state['profile_error'] = null;
            return $this->profile->write();
        } catch (DeploymentError $error) {
            $state['profile_error'] = substr($error->getMessage(), 0, 200);
            return ['result' => 'failed', 'error' => $state['profile_error']];
        }
    }

    // --- State ------------------------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private function row(string $version, string $status, int $now): array
    {
        return ['version' => $version, 'php' => OpcacheManager::dotted($version), 'status' => $status, 'checked_at' => $now];
    }

    /** @return array{checked_at:?int, profile_error:?string, versions:array<string,array<string,mixed>>} a malformed file is treated as empty and rewritten */
    private function load(): array
    {
        $empty = ['checked_at' => null, 'profile_error' => null, 'versions' => []];
        $path = $this->statePath();
        if (!is_file($path) || is_link($path)) {
            return $empty;
        }
        $data = json_decode((string) @file_get_contents($path, false, null, 0, 1 << 20), true, 8);
        if (!is_array($data) || ($data['schema_version'] ?? null) !== 1 || !is_array($data['versions'] ?? null)) {
            return $empty;
        }
        $versions = [];
        foreach ($data['versions'] as $name => $row) {
            if (is_string($name) && preg_match(OpcacheManager::VERSION, $name) === 1 && is_array($row)
                && in_array($row['status'] ?? null, ['complete', 'repairing', 'failed'], true) && is_int($row['checked_at'] ?? null)) {
                $versions[$name] = $row;
            }
        }
        return ['checked_at' => is_int($data['checked_at'] ?? null) ? $data['checked_at'] : null,
            'profile_error' => is_string($data['profile_error'] ?? null) ? $data['profile_error'] : null, 'versions' => $versions];
    }

    /** @param array<string,mixed> $state */
    private function save(array $state): void
    {
        ksort($state['versions'], SORT_STRING);
        try {
            HookEntry::writeDurable($this->statePath(), json_encode(['schema_version' => 1, 'checked_at' => $state['checked_at'],
                'profile_error' => $state['profile_error'], 'versions' => (object) $state['versions'],
                PhpRestartLedger::KEY => $this->ledger->encoded()],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n", 0644);
        } catch (\RuntimeException $error) {
            throw new Refused('cannot write ' . $this->statePath() . ': ' . $error->getMessage());
        }
    }

    private function unit(string $unit): bool
    {
        return $this->env->runner->run('phpenv-unit', [OpcacheManager::SYSTEMCTL, 'is-enabled', '--quiet', $unit], 20)['exit_code'] === 0;
    }

    /** @template T @param \Closure():T $work @return T */
    private function locked(\Closure $work): mixed
    {
        if (!is_dir($this->env->state) && !@mkdir($this->env->state, 0755, true) && !is_dir($this->env->state)) {
            throw new Refused("cannot create {$this->env->state}");
        }
        $lock = @fopen($this->env->state . '/' . self::LOCK, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new Refused('cannot take the PHP environment lock');
        }
        try {
            return $work();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
