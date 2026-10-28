<?php
declare(strict_types=1);

namespace OlsCpanel\ObjectCache;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Cpanel\Discovery\AccountVhosts;
use OlsCpanel\Cpanel\Discovery\HomePath;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\PhpExtensions\ExtensionInstaller;
use OlsCpanel\PhpExtensions\ExtensionService;

/**
 * Per-account object cache (FV-09; docs/product-interfaces.md, "Object cache"). Runs as root (the CLI, and the
 * oneshot unit ols-cpanel-objcache.service): every external command goes through the CommandRunner as a fixed
 * argv array, account names and paths are validated first, and everything that touches an account's home runs
 * as that account (runuser), so root never follows a path the account controls.
 *
 * Desired state is the state file (accounts enabled explicitly, cPanel packages enabled by the operator) minus
 * what cPanel says: an account that is suspended runs no instance, one that no longer exists loses its
 * instance and files. reconcile() is level-triggered and idempotent; enable() and disable() apply one
 * account immediately with the same code.
 */
final class ObjectCacheManager
{
    public const STATE = '/var/lib/ols-cpanel/objcache.json';
    public const CONF_ROOT = '/var/lib/ols-cpanel/objcache';
    public const LOCK = '/var/lib/ols-cpanel/objcache.lock';
    public const UNIT_DIR = '/etc/systemd/system';
    public const TIMER = 'ols-cpanel-objcache.timer';
    public const SERVICE = 'ols-cpanel-objcache.service';
    public const SYSTEMCTL = '/usr/bin/systemctl';
    public const RUNUSER = '/usr/sbin/runuser';
    public const GETENT = '/usr/bin/getent';
    public const WP = '/usr/local/bin/wp';
    public const WHMAPI = '/usr/local/cpanel/bin/whmapi1';
    public const CPANEL_USERS = '/var/cpanel/users';
    public const CPANEL_SUSPENDED = '/var/cpanel/suspended';
    public const MIN_UID = 500;
    public const PHP = '/^ea-php[0-9]{2,3}$/D';
    private const TEST = '/usr/bin/test';
    private const INSTALL = '/usr/bin/install';
    private const RM = '/usr/bin/rm';
    private const GREP = '/usr/bin/grep';
    private const LS = '/usr/bin/ls';
    private const TIMEOUT = 60;
    private const CAT = '/usr/bin/cat';
    private const FIND = '/usr/bin/find';
    public const USERDATADOMAINS = '/etc/userdatadomains';
    /** A site is looked at again after this many seconds. The look reads two small files as the account (LiteSpeed Cache's
     * object cache drop-in and its runtime configuration); wp-cli, which boots all of WordPress, runs only when a site must be
     * configured or the files cannot tell (lab finding 2026-10-28: about 9 s of CPU per wp-cli check on a WooCommerce site). */
    public const RECHECK_OK = 900;
    /** A site with an error is tried again after this many seconds, doubled for every failed attempt up to RECHECK_MAX. */
    public const RECHECK_ERROR = 300;
    /** Longest wait between wp-cli attempts on a site (error backoff, and a site whose LiteSpeed Cache plugin is inactive). */
    public const RECHECK_MAX = 86400;
    /** The drop-in LiteSpeed Cache installs for its object cache, and the runtime configuration it reads. */
    private const DROPIN = 'wp-content/object-cache.php';
    private const RUNTIME_CONF = ['wp-content/.litespeed_conf.php', 'wp-content/.litespeed_conf.dat'];
    /** Names in wp-content whose presence changes when LiteSpeed Cache is activated or its object cache switched. */
    private const MARKERS = ['wp-content/plugins/litespeed-cache', 'wp-content/advanced-cache.php', 'wp-content/object-cache.php',
        'wp-content/.litespeed_conf.php', 'wp-content/.litespeed_conf.dat'];
    /** All wp-cli calls for one site together. */
    public const SITE_BUDGET = 150;
    /** All site checks of one reconcile pass together (the unit's limit is 300 s). */
    public const PASS_BUDGET = 200;
    public const MAX_SITES = 25;

    public function __construct(private readonly CommandRunner $runner, private readonly string $statePath = self::STATE,
                                private readonly string $confRoot = self::CONF_ROOT, private readonly string $unitDir = self::UNIT_DIR,
                                private readonly ?string $lockPath = self::LOCK, private readonly ?ExtensionService $extensions = null,
                                private readonly ?\Closure $clock = null)
    {
    }

    // --- Operator operations ------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    public function enable(string $user, ?string $memory): array
    {
        return $this->locked(function () use ($user, $memory): array {
            $mb = $memory === null ? null : ValkeyConfig::parseMemory($memory);
            if ($memory !== null && $mb === null) {
                throw new Refused('memory must be a whole number of MB from ' . ValkeyConfig::MIN_MEMORY_MB . ' to ' . ValkeyConfig::MAX_MEMORY_MB);
            }
            $account = $this->account($user);
            $state = ObjectCacheState::load($this->statePath);
            $mb ??= $state->accounts[$user]['memory_mb'] ?? $this->planMemory($state, $user) ?? $state->defaultMemory;
            $state->accounts[$user] = ['enabled' => true, 'memory_mb' => $mb];
            $state->save($this->statePath);  // the wish survives a failed start; reconcile retries it
            $suspended = $this->suspendedNow($user);  // throws when unknown: an instance is never started blind
            $this->apply($user, $account['home'], $mb, $suspended, $this->instanceState($user));
            $timer = $this->ensureTimer();
            $extension = $this->extensionFor($user);
            // WordPress sites with LiteSpeed Cache are set up now, without waiting for the next pass; never fails the enable.
            $sites = $this->wordPressNow($state, $user, $account['home'], $suspended);
            return ['result' => 'enabled', 'account' => $user, 'memory_mb' => $mb, 'socket' => ValkeyConfig::socket($account['home']),
                'suspended' => $suspended, 'active' => !$suspended, 'timer' => $timer, 'wordpress' => $sites]
                + ($extension === null ? [] : ['php_extension' => $extension]);
        });
    }

    /** @return array<string,mixed> */
    public function disable(string $user): array
    {
        return $this->locked(function () use ($user): array {
            if (!ValkeyConfig::validUser($user)) {
                throw new Refused('invalid account name');
            }
            $state = ObjectCacheState::load($this->statePath);
            $known = isset($state->accounts[$user]);
            $plan = $this->planOf($user);
            if ($plan !== null && isset($state->packages[$plan])) {
                $state->accounts[$user] = ['enabled' => false, 'memory_mb' => $state->accounts[$user]['memory_mb'] ?? $state->packages[$plan]['memory_mb']];
            } else {
                unset($state->accounts[$user]);
            }
            $home = $this->homeIfAny($user);
            // Sites the product set up stop using the socket before it goes away; a failure stays recorded and is retried by the pass.
            $off = $this->turnOffWordPress($state, $user, $home);
            $state->save($this->statePath);
            $this->cleanup($user, $home);
            $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
            return ['result' => $known ? 'disabled' : 'unchanged', 'account' => $user] + ($off === [] ? [] : ['wordpress' => $off]);
        });
    }

    /** @return array<string,mixed> */
    public function flush(string $user): array
    {
        $account = $this->account($user);
        $state = ObjectCacheState::load($this->statePath);
        if ($state->memoryFor($user, $this->planOf($user)) === null) {
            throw new Refused("the object cache is not enabled for $user");
        }
        if (!$this->isActive($user)) {
            throw new Refused("the object cache instance of $user is not running");
        }
        $done = $this->cli($user, $account['home'], ['FLUSHALL']);
        if ($done['exit_code'] !== 0 || trim($done['stdout']) !== 'OK') {
            throw new Refused('flush failed: ' . self::tail($done));
        }
        return ['result' => 'flushed', 'account' => $user];
    }

    /** @return array<string,mixed> */
    public function status(?string $user): array
    {
        $state = ObjectCacheState::load($this->statePath);
        $running = $this->running();
        $engine = ['binary' => ValkeyConfig::SERVER,
            'present' => $this->run('engine-present', [self::TEST, '-x', ValkeyConfig::SERVER])['exit_code'] === 0];
        $extension = $this->extensions === null ? [] : ['php_extension' => $this->extensionStatus()];
        if ($user === null) {
            $accounts = [];
            $names = array_unique([...array_keys($state->accounts), ...array_keys($running), ...$this->configured()]);
            sort($names, SORT_STRING);
            $homes = $this->passwd();
            foreach ($names as $name) {
                $entry = $state->accounts[$name] ?? null;
                $home = $homes[$name]['home'] ?? null;
                $accounts[] = ['account' => $name, 'enabled' => $entry === null ? null : $entry['enabled'],
                    'memory_mb' => $entry['memory_mb'] ?? null, 'state' => $running[$name] ?? 'inactive']
                    + $this->connection($name, $home) + ['wordpress' => self::siteRows($state, $name)];
            }
            return ['result' => 'status', 'engine' => $engine, 'defaults' => ['memory_mb' => $state->defaultMemory],
                'packages' => $state->packages, 'accounts' => $accounts] + $extension;
        }
        $account = $this->account($user);
        $plan = $this->planOf($user);
        $memory = $state->memoryFor($user, $plan);
        $record = ['result' => 'status', 'engine' => $engine, 'account' => $user, 'package' => $plan, 'enabled' => $memory !== null,
            'memory_mb' => $memory, 'suspended' => $this->suspendedNow($user), 'state' => $running[$user] ?? 'inactive',
            'socket' => ValkeyConfig::socket($account['home'])] + $this->connection($user, $account['home'])
            + ['wordpress' => self::siteRows($state, $user)] + $extension;
        if (($running[$user] ?? '') === 'active') {
            $record['usage'] = self::usage($this->cli($user, $account['home'], ['INFO']));
        }
        return $record;
    }

    /** Sets the memory a package's accounts get (or removes the package from the object cache). @return array<string,mixed> */
    public function package(string $name, ?string $memory, bool $remove): array
    {
        return $this->locked(function () use ($name, $memory, $remove): array {
            if (!preg_match(ObjectCacheState::PACKAGE, $name)) {
                throw new Refused('invalid package name');
            }
            $state = ObjectCacheState::load($this->statePath);
            if ($remove) {
                unset($state->packages[$name]);
            } else {
                $mb = $memory === null ? $state->defaultMemory : ValkeyConfig::parseMemory($memory);
                if ($mb === null) {
                    throw new Refused('memory must be a whole number of MB from ' . ValkeyConfig::MIN_MEMORY_MB . ' to ' . ValkeyConfig::MAX_MEMORY_MB);
                }
                $state->packages[$name] = ['memory_mb' => $mb];
            }
            $state->save($this->statePath);
            // Applied now without waiting for the next timer period; never blocks this command.
            $timer = $this->ensureTimer();
            $this->run('objcache-trigger', [self::SYSTEMCTL, 'start', '--no-block', self::SERVICE]);
            return ['result' => $remove ? 'package_removed' : 'package_enabled', 'package' => $name,
                'memory_mb' => $state->packages[$name]['memory_mb'] ?? null, 'timer' => $timer];
        });
    }

    /**
     * Uninstall: switches LiteSpeed Cache's object cache off again, as the site owner through wp-cli (the argv of the applier), on
     * every installation the state says the product switched on, but only while the site's object-host is still the product's
     * socket (the runtime files first, wp-cli when they cannot tell). A site whose administrator changed the host, the plugin or
     * the drop-in is never touched. Best effort: a site that cannot be reverted is a row with its reason, never an exception.
     * $dryRun only reads (wp-cli is not run).
     * @return list<array{account:string, path:string, result:string, reason:string}> result: reverted, would_revert, unchanged, error
     */
    public function revertWordPress(bool $dryRun): array
    {
        try {
            $state = ObjectCacheState::load($this->statePath);
            return $this->locked(function () use ($state, $dryRun): array {
                $rows = [];
                foreach ($state->wordpress as $user => $paths) {
                    $home = $this->homeIfAny((string) $user);
                    foreach ($paths as $path => $site) {
                        if (!$site['product_set']) {
                            continue;
                        }
                        $row = ['account' => (string) $user, 'path' => (string) $path];
                        if ($home === null || !self::safeDirectory((string) $path, (string) $user, $home)) {
                            $rows[] = $row + ['result' => 'unchanged', 'reason' => 'the account or the directory is gone'];
                            continue;
                        }
                        try {
                            [$result, $reason] = $this->revertSite((string) $user, $home, (string) $path, $site, $dryRun);
                        } catch (\Throwable $error) {
                            [$result, $reason] = ['error', self::message($error)];
                        }
                        $rows[] = $row + ['result' => $result, 'reason' => $reason];
                    }
                }
                return $rows;
            });
        } catch (Refused $error) {
            return [['account' => '*', 'path' => $this->statePath, 'result' => 'error', 'reason' => self::message($error)]];
        }
    }

    /**
     * @param array{state:string, product_set:bool, checked:int, php:?string, error:?string} $site
     * @return array{0:string, 1:string} result and reason
     */
    private function revertSite(string $user, string $home, string $path, array $site, bool $dryRun): array
    {
        $socket = ValkeyConfig::socket($home);
        $previous = $site['previous_socket'] ?? null;
        $quick = $this->quickState($user, $path, $socket, $previous);
        if ($quick !== null && $quick[0] !== 'automatic') {
            return ['unchanged', $quick[0] === 'owner' ? 'the object cache is not the product\'s' : 'LiteSpeed Cache is not installed'];
        }
        if ($dryRun) {
            return ['would_revert', $quick === null ? 'the settings are read with wp-cli when it runs' : 'the object cache uses the product socket'];
        }
        $binary = '/opt/cpanel/' . ($site['php'] ?? $this->discoverPhp($user)) . '/root/usr/bin/php';
        $limit = $this->now() + self::SITE_BUDGET;
        $wp = fn(array $arguments): array => $this->asUser($user, self::wpArgv($home, $binary, $path, $arguments),
            max(1, min(self::TIMEOUT, $limit - $this->now())));
        $active = $wp(['plugin', 'is-active', 'litespeed-cache']);
        if ($active['exit_code'] !== 0) {
            if ($active['exit_code'] !== 1 || str_contains($active['stderr'] ?? '', 'Error')) {
                throw new Refused('wp plugin is-active failed: ' . self::tail($active));
            }
            return ['unchanged', 'LiteSpeed Cache is not active'];
        }
        if ($quick === null) {
            $get = function (string $option) use ($wp): string {
                $done = $wp(['litespeed-option', 'get', $option]);
                if ($done['exit_code'] !== 0) {
                    throw new Refused("wp litespeed-option get $option failed: " . self::tail($done));
                }
                return trim($done['stdout']);
            };
            $on = self::flag($get('object'));
            if ($on === null) {
                throw new Refused('LiteSpeed Cache answered something unexpected for the object cache setting');
            }
            if (!$on) {
                return ['unchanged', 'the object cache is already off'];
            }
            $host = $get('object-host');
            if ($host !== $socket && $host !== $previous) {
                return ['unchanged', 'the object cache is not the product\'s'];
            }
        }
        $set = $wp(['litespeed-option', 'set', 'object', 'false']);
        if ($set['exit_code'] !== 0) {
            throw new Refused('wp litespeed-option set object failed: ' . self::tail($set));
        }
        return ['reverted', 'the object cache of LiteSpeed Cache is off'];
    }

    /**
     * Uninstall: removes the per-account systemd drop-in directories of the instances (ols-cpanel-objcache@<account>.service.d holding
     * the product's 50-account.conf only; a link, a directory with another file or another name is never touched), then one daemon-reload.
     * @return list<array{path:string, result:string, reason?:string}> result: removed, would_remove, kept, error
     */
    public function removeDropIns(bool $dryRun): array
    {
        $rows = [];
        $removed = false;
        foreach (is_dir($this->unitDir) ? (scandir($this->unitDir) ?: []) : [] as $name) {
            if (preg_match('/^' . preg_quote(ValkeyConfig::UNIT_PREFIX, '/') . '(.+)\.service\.d$/D', $name, $match) !== 1
                || !ValkeyConfig::validUser($match[1])) {
                continue;
            }
            $dir = "{$this->unitDir}/$name";
            if (is_link($dir) || !is_dir($dir)) {
                $rows[] = ['path' => $dir, 'result' => 'kept', 'reason' => 'not a plain directory'];
                continue;
            }
            if (array_diff(scandir($dir) ?: [], ['.', '..', '50-account.conf']) !== []) {
                $rows[] = ['path' => $dir, 'result' => 'kept', 'reason' => 'holds files the product did not write'];
                continue;
            }
            $file = "$dir/50-account.conf";
            if ($dryRun) {
                $rows[] = ['path' => $dir, 'result' => 'would_remove'];
            } elseif (((is_file($file) || is_link($file)) && !@unlink($file)) || !@rmdir($dir)) {
                $rows[] = ['path' => $dir, 'result' => 'error', 'reason' => "cannot remove $dir"];
            } else {
                $rows[] = ['path' => $dir, 'result' => 'removed'];
                $removed = true;
            }
        }
        if ($removed) {
            $reload = $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
            if ($reload['exit_code'] !== 0) {
                $rows[] = ['path' => 'systemctl daemon-reload', 'result' => 'error', 'reason' => self::tail($reload)];
            }
        }
        return $rows;
    }

    /**
     * LiteSpeed Cache's object cache for a WordPress installation of the account, through wp-cli as the account:
     * method Redis, host the account's socket, port 0.
     * @return array<string,mixed>
     */
    public function configureWordPress(string $user, string $path, ?string $php): array
    {
        $account = $this->account($user);
        $state = ObjectCacheState::load($this->statePath);
        if ($state->memoryFor($user, $this->planOf($user)) === null) {
            throw new Refused("the object cache is not enabled for $user; enable it first");
        }
        $parts = explode('/', $path);
        if (!preg_match('~^/[A-Za-z0-9_./-]+$~D', $path) || in_array('.', $parts, true) || in_array('..', $parts, true)
            || str_contains($path, '//') || str_ends_with($path, '/') || HomePath::homeOf($path, $user) !== $account['home']) {
            throw new Refused("the WordPress path must be a directory inside {$account['home']}");
        }
        if ($php !== null && !preg_match(self::PHP, $php)) {
            throw new Refused('--php must look like ea-php83');
        }
        $php ??= $this->discoverPhp($user);
        $binary = "/opt/cpanel/$php/root/usr/bin/php";
        if ($this->asUser($user, [self::TEST, '-x', $binary])['exit_code'] !== 0) {
            throw new Refused("$binary is not available");
        }
        if ($this->asUser($user, [self::TEST, '-f', "$path/wp-config.php"])['exit_code'] !== 0) {
            throw new Refused("no WordPress installation (wp-config.php) at $path");
        }
        if ($this->asUser($user, [$binary, '-r', 'exit(extension_loaded("redis") ? 0 : 3);'])['exit_code'] !== 0) {
            if ($this->extensions === null) {
                throw new Refused("the redis extension is not loaded in $php; run: ols-cpanel php-ext install");
            }
            $report = $this->extensions->ensureForAccount($user, [$php]);
            $row = $report['versions'][0] ?? ['status' => 'unknown'];
            if ($this->asUser($user, [$binary, '-r', 'exit(extension_loaded("redis") ? 0 : 3);'])['exit_code'] !== 0) {
                throw new Refused("the redis extension is not loaded in $php and could not be activated ({$row['status']}"
                    . (isset($row['message']) ? ': ' . self::message(new \RuntimeException((string) $row['message'])) : '') . ')');
            }
        }
        $socket = ValkeyConfig::socket($account['home']);
        $commands = [['plugin', 'is-active', 'litespeed-cache'],
            ['litespeed-option', 'set', 'object-kind', '1'], ['litespeed-option', 'set', 'object-host', $socket],
            ['litespeed-option', 'set', 'object-port', '0'], ['litespeed-option', 'set', 'object', 'true']];
        foreach ($commands as $arguments) {
            $done = $this->asUser($user, self::wpArgv($account['home'], $binary, $path, $arguments), 120);
            if ($done['exit_code'] !== 0) {
                throw new Refused('wp ' . $arguments[0] . ' ' . $arguments[1] . ($arguments[1] === 'is-active'
                    ? ': LiteSpeed Cache is not active in that installation' : ' failed: ' . self::tail($done)));
            }
        }
        return ['result' => 'configured', 'account' => $user, 'path' => $path, 'php' => $php, 'method' => 'redis', 'host' => $socket, 'port' => 0];
    }

    /** The wp-cli argv (fixed shape; tests/objcache.php) @return list<string> */
    public static function wpArgv(string $home, string $php, string $path, array $arguments): array
    {
        return ['/usr/bin/env', "HOME=$home", 'WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1', 'WP_CLI_CACHE_DIR=' . ValkeyConfig::socketDir($home) . '/wp-cli-cache',
            $php, '-d', 'memory_limit=512M', self::WP, "--path=$path", '--skip-themes', ...$arguments];
    }

    /**
     * Converges the instances with the desired state. Idempotent; the per-account errors are collected and do not
     * stop the pass.
     * @return array<string,mixed>
     */
    public function reconcile(): array
    {
        return $this->locked(function (): array {
            $state = ObjectCacheState::load($this->statePath);
            $plans = $this->plans();  // every existing cPanel account with its package (empty only when authoritative)
            $suspended = $this->suspendedSet();  // null: the suspension markers cannot be read; nothing is started then
            $running = $this->running();
            $homes = $this->passwd();
            $pending = [];
            $errors = $this->migrateRenames($state, $plans, $homes, $pending);
            \OlsCpanel\Php\PhpLimits::reconcileAccounts(dirname($this->statePath) . '/php-limits.json', [...array_keys($plans), ...array_keys($pending)]);
            $configured = $this->configured();
            $actions = [];
            $desired = [];
            $dirty = false;
            foreach (array_unique([...array_keys($state->accounts), ...array_keys($plans)]) as $user) {
                if (!ValkeyConfig::validUser($user)) {
                    continue;
                }
                if (!isset($plans[$user])) {
                    if (isset($pending[$user])) {
                        continue;  // its rename migration failed: nothing of it is dropped before the job succeeds
                    }
                    // Removed from cPanel: cleaned below, and its explicit entry dropped.
                    if (isset($state->accounts[$user])) {
                        unset($state->accounts[$user]);
                        $dirty = true;
                    }
                    continue;
                }
                $mb = $state->memoryFor($user, $plans[$user]);
                if ($mb !== null) {
                    $desired[$user] = $mb;
                }
            }
            $deadline = $this->now() + self::PASS_BUDGET;
            $reload = false;
            foreach (array_unique([...$configured, ...array_keys($running)]) as $user) {
                if (isset($desired[$user]) || isset($pending[$user]) && !isset($plans[$user]) || !ValkeyConfig::validUser($user)) {
                    continue;
                }
                try {
                    $this->cleanup($user, $homes[$user]['home'] ?? null);
                    $reload = true;
                    $actions[] = ['account' => $user, 'action' => isset($plans[$user]) ? 'removed (disabled)' : 'removed (account gone)'];
                } catch (\Throwable $error) {
                    $errors[] = ['account' => $user, 'error' => self::message($error)];
                }
            }
            foreach ($desired as $user => $mb) {
                try {
                    $home = $homes[$user]['home'] ?? null;
                    if ($home === null || ($homes[$user]['uid'] ?? 0) < self::MIN_UID || HomePath::homeOf($home, $user) !== $home
                        || strlen(ValkeyConfig::socket($home)) > ValkeyConfig::MAX_SOCKET_PATH) {
                        throw new Refused('the account has no usable home directory');
                    }
                    if ($suspended === null) {
                        // Fail closed: with the suspension state unknown an instance is neither started nor restarted,
                        // and a running one is left as it is until the markers can be read again.
                        throw new Refused('the suspension state of the account cannot be read; the instance was neither started nor changed');
                    }
                    $done = $this->apply($user, $home, $mb, isset($suspended[$user]), $running[$user] ?? 'inactive');
                    foreach ($done as $action) {
                        $actions[] = ['account' => $user, 'action' => $action];
                    }
                    if (!isset($suspended[$user])) {
                        // The instance is up: WordPress sites are found and set up. Site errors are recorded, never errors of the pass.
                        $dirty = $this->syncWordPress($state, $user, $home, false, $deadline) || $dirty;
                    }
                } catch (\Throwable $error) {
                    $errors[] = ['account' => $user, 'error' => self::message($error)];
                }
            }
            // Sites the product set up whose account no longer has a running cache (disabled, suspended or gone).
            foreach (array_keys($state->wordpress) as $user) {
                if (isset($pending[$user]) && !isset($plans[$user])) {
                    continue;
                }
                $wanted = isset($desired[$user]);
                if ($wanted && ($suspended === null || !isset($suspended[$user]))) {
                    continue;
                }
                $home = isset($plans[$user]) ? ($homes[$user]['home'] ?? null) : null;
                $before = $state->wordpress[$user];
                $this->turnOffWordPress($state, $user, $home !== null && ($homes[$user]['uid'] ?? 0) >= self::MIN_UID
                    && HomePath::homeOf($home, $user) === $home ? $home : null);
                $dirty = $dirty || ($state->wordpress[$user] ?? []) !== $before;
            }
            if ($reload) {
                $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
            }
            if ($dirty) {
                $state->save($this->statePath);
            }
            foreach ($this->removeAccountLeftovers(array_keys($plans), $homes)['errors'] as $message) {
                $errors[] = ['account' => '(removal)', 'error' => $message];
            }
            if (!$this->ensureTimer()) {
                // Nothing would retry a failure without the timer: reported, and tried again by every pass that does run.
                $errors[] = ['account' => '(timer)', 'error' => 'the object cache timer ' . self::TIMER . ' could not be enabled'];
            }
            $extension = null;
            if ($this->extensions !== null && $desired !== []) {
                $extension = $this->watchExtension($actions, $errors);
            }
            return ['result' => $errors === [] ? 'reconciled' : 'errors', 'actions' => $actions, 'errors' => $errors]
                + ($extension === null ? [] : ['php_extension' => $extension]);
        });
    }

    /**
     * Requests and OLS error logs left behind by removed accounts and vhosts (AccountRemoval).
     * @param list<string> $accounts
     * @return array{archived:int, logs_removed:int, errors:list<string>}
     */
    private function removeAccountLeftovers(array $accounts, array $homes): array
    {
        $base = dirname($this->statePath);
        $table = $this->run('userdatadomains', [self::CAT, self::USERDATADOMAINS]);
        $removal = new AccountRemoval("$base/requests", "$base/requests-archive",
            $this->statePath === self::STATE ? \OlsCpanel\Deployment\BuilderCompilation::ERROR_LOG_DIR : "$base/vhost-logs");
        $text = $table['exit_code'] === 0 ? $table['stdout'] : null;
        $result = $removal->run($accounts, $text, function (string $user) use ($homes): ?string {
            if (!ValkeyConfig::validUser($user)) {
                return null;
            }
            $done = $this->run('startdate', [self::GREP, '-m1', '--', '^STARTDATE=', self::CPANEL_USERS . "/$user"]);
            if ($done['exit_code'] === 0 && preg_match('/^STARTDATE=([0-9]+)$/m', $done['stdout'], $match) === 1) {
                return 'start:' . $match[1];
            }
            $home = $homes[$user]['home'] ?? null;
            $stat = is_string($home) && is_dir($home) && !is_link($home) ? @stat($home) : false;
            return $stat === false ? null : 'home:' . $stat['uid'] . ':' . $stat['ino'];
        });
        try {
            (new DomainOwners("$base/domain-owners.json"))->update($accounts, $text);
        } catch (\Throwable $error) {
            $result['errors'][] = 'domain owners: ' . substr($error->getMessage(), 0, 200);
        }
        return $result;
    }

    /**
     * Durable rename jobs are independent of the OLS event spool, so activation cannot consume a failed migration.
     * Jobs are applied in the order they were recorded (their names sort chronologically) and each one is isolated: a
     * failing job stays queued and is reported, and neither the other jobs nor the other accounts of the pass are
     * affected. A rename whose destination is renamed again by a later job moves on to that final name (A to B, B to C
     * ends at C); A to B followed by B to A changes nothing and only completes both jobs.
     * Sources of jobs that failed are returned in $pending: their state and instance are left alone until the job succeeds.
     * @param array<string,true> $pending
     * @return list<array{account:string,error:string}>
     */
    private function migrateRenames(ObjectCacheState $state, array $plans, array $homes, array &$pending): array
    {
        $directory = dirname($this->statePath) . '/account-renames';
        $paths = glob($directory . '/*.json') ?: [];
        sort($paths, SORT_STRING);
        $errors = [];
        $jobs = [];
        foreach ($paths as $path) {
            $job = json_decode((string) file_get_contents($path), true, 8);
            $old = $job['olduser'] ?? null;
            $new = $job['newuser'] ?? null;
            if (!is_string($old) || !is_string($new) || !ValkeyConfig::validUser($old)
                || !ValkeyConfig::validUser($new) || $old === $new) {
                $errors[] = ['account' => '(rename)', 'error' => 'invalid account rename job ' . basename($path)];
                continue;
            }
            $jobs[] = ['path' => $path, 'old' => $old, 'new' => $new];
        }
        foreach ($jobs as $index => $job) {
            $old = $job['old'];
            try {
                $new = $job['new'];
                for ($later = $index + 1; $later < count($jobs); $later++) {
                    if ($jobs[$later]['old'] === $new) {
                        $new = $jobs[$later]['new'];
                    }
                }
                if ($new === $old) {
                    // The account was renamed away and back: nothing moved.
                    if (!unlink($job['path'])) {
                        throw new Refused('cannot complete account rename job');
                    }
                    continue;
                }
                if (isset($plans[$old])) {
                    throw new Refused('account rename source still exists; migration deferred');
                }
                if (isset($plans[$new])) {
                    $this->moveRenamed($state, $plans, $homes, $old, $new);
                }
                // If both names disappeared, ordinary orphan cleanup removes the source's remaining state.
                if (!unlink($job['path'])) {
                    throw new Refused('cannot complete account rename job');
                }
            } catch (\Throwable $error) {
                $errors[] = ['account' => $old, 'error' => self::message($error)];
                $pending[$old] = true;
            }
        }
        return $errors;
    }

    private function moveRenamed(ObjectCacheState $state, array $plans, array $homes, string $old, string $new): void
    {
        $home = $homes[$new]['home'] ?? null;
        if ($home === null || ($homes[$new]['uid'] ?? 0) < self::MIN_UID || HomePath::homeOf($home, $new) !== $home) {
            throw new Refused('account rename destination has no usable home');
        }
        // Stop the old instance before the new one can bind the moved socket. A failure keeps the job and files.
        if (is_dir("{$this->confRoot}/$old") || $this->instanceState($old) !== 'inactive') {
            $this->cleanup($old, null);
        }
        if (isset($state->accounts[$old])) {
            $state->accounts[$new] ??= $state->accounts[$old];
            unset($state->accounts[$old]);
        }
        foreach ($state->wordpress[$old] ?? [] as $site => $record) {
            $oldHome = HomePath::homeOf($site, $old);
            if ($oldHome === null) {
                continue;
            }
            $target = $home . substr($site, strlen($oldHome));
            $record['checked'] = 0;
            if ($record['product_set']) {
                $record['previous_socket'] ??= ValkeyConfig::socket($oldHome);
            }
            $state->wordpress[$new][$target] ??= $record;
        }
        unset($state->wordpress[$old]);
        $state->save($this->statePath);
        \OlsCpanel\Php\PhpLimits::reconcileAccounts(dirname($this->statePath) . '/php-limits.json', array_keys($plans), $old, $new);
        $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
    }

    // --- WordPress sites with LiteSpeed Cache (automatic) -------------------------------------------------------

    /**
     * The connection values every application needs: the socket as host, port 0, no password (the socket's mode is
     * the access control). Empty when the account's home is unknown.
     * @return array<string,mixed>
     */
    private function connection(string $user, ?string $home): array
    {
        if ($home === null || HomePath::homeOf($home, $user) !== $home) {
            return [];
        }
        return ['socket' => ValkeyConfig::socket($home), 'connection' => ['host' => ValkeyConfig::socket($home), 'port' => 0, 'password' => null]];
    }

    /** @return list<array<string,mixed>> the recorded WordPress sites of an account, by path */
    private static function siteRows(ObjectCacheState $state, string $user): array
    {
        $rows = [];
        foreach ($state->wordpress[$user] ?? [] as $path => $row) {
            $rows[] = ['path' => $path, 'state' => $row['state'], 'configured_by_product' => $row['product_set'],
                'checked_at' => $row['checked'], 'php' => $row['php'], 'error' => $row['error']];
        }
        return $rows;
    }

    private function now(): int
    {
        return $this->clock === null ? time() : (int) ($this->clock)();
    }

    /**
     * What `enable` does for WordPress: sets the sites up (or, for a suspended account, off) at once. Never throws.
     * @return list<array<string,mixed>>
     */
    private function wordPressNow(ObjectCacheState $state, string $user, string $home, bool $suspended): array
    {
        try {
            $changed = $suspended ? $this->turnOffWordPress($state, $user, $home) !== []
                : $this->syncWordPress($state, $user, $home, true, $this->now() + self::PASS_BUDGET);
            if ($changed || $suspended) {
                $state->save($this->statePath);
            }
        } catch (\Throwable) {
            // The next pass tries again.
        }
        return self::siteRows($state, $user);
    }

    /**
     * Finds the account's WordPress installations and sets LiteSpeed Cache's object cache where that is the product's to
     * do: off, or already on this account's socket. A different object cache host is the site owner's choice and is left
     * alone. Results (or the error) are recorded per site in $state->wordpress; nothing is thrown for a site. A site that was
     * looked at recently is not looked at again unless $force.
     * @return bool whether the recorded state changed
     */
    private function syncWordPress(ObjectCacheState $state, string $user, string $home, bool $force, int $deadline): bool
    {
        try {
            $found = $this->findWordPress($user, $home);
        } catch (\Throwable) {
            return false;  // the records stay as they are; the next pass looks again
        }
        $records = $state->wordpress[$user] ?? [];
        $next = [];
        foreach ($found as $path => $hint) {
            $old = $records[$path] ?? null;
            $now = $this->now();
            $due = $force || $old === null || $now < $old['checked'] || $now - $old['checked'] >= self::recheckAfter($old);
            if (!$due || $now >= $deadline) {
                if ($old !== null) {
                    $next[$path] = $old;
                }
                continue;
            }
            $next[$path] = $this->checkSite($user, $home, $path, $hint, $old);
        }
        if ($next === $records) {
            return false;
        }
        if ($next === []) {
            unset($state->wordpress[$user]);
        } else {
            $state->wordpress[$user] = $next;
        }
        return true;
    }

    /**
     * The WordPress installations of an account: the document roots of its domains (/etc/userdatadomains), each searched
     * as the account for wp-config.php in the document root and one directory below it (find -P: no link is followed).
     * @return array<string,?string> install directory => the PHP version of the domain that serves it
     */
    private function findWordPress(string $user, string $home): array
    {
        $table = $this->run('userdatadomains', [self::CAT, self::USERDATADOMAINS]);
        if ($table['exit_code'] !== 0) {
            throw new Refused('cannot read ' . self::USERDATADOMAINS);
        }
        try {
            $rows = (new AccountVhosts())->parseUserdataDomains($table['stdout']);
        } catch (\InvalidArgumentException $error) {
            throw new Refused(self::message($error));
        }
        $roots = [];
        foreach ($rows as $row) {
            if ($row['user'] === $user && self::safeDirectory($row['docroot'], $user, $home) && !isset($roots[$row['docroot']])) {
                $roots[$row['docroot']] = preg_match(self::PHP, $row['php']) === 1 ? $row['php'] : null;
            }
        }
        $found = [];
        foreach ($roots as $root => $php) {
            $listed = $this->asUser($user, [self::FIND, '-P', $root, '-mindepth', '1', '-maxdepth', '2', '-name', 'wp-config.php', '-type', 'f'], 30);
            foreach (explode("\n", $listed['stdout']) as $line) {
                $dir = dirname($line);
                if ($line === '' || basename($line) !== 'wp-config.php' || !self::safeDirectory($dir, $user, $home)
                    || ($dir !== $root && dirname($dir) !== $root) || isset($found[$dir])) {
                    continue;
                }
                $found[$dir] = $php;
            }
        }
        ksort($found, SORT_STRING);
        return array_slice($found, 0, self::MAX_SITES, true);
    }

    /** A plain absolute directory path inside the account's own home (no dot components, no trailing slash). */
    private static function safeDirectory(string $path, string $user, string $home): bool
    {
        $parts = explode('/', $path);
        return preg_match('~^/[A-Za-z0-9_./-]+$~D', $path) === 1 && !in_array('.', $parts, true) && !in_array('..', $parts, true)
            && !str_contains($path, '//') && !str_ends_with($path, '/') && HomePath::homeOf($path, $user) === $home;
    }

    /**
     * One site, as the account through wp-cli: is LiteSpeed Cache active, is its object cache off or already ours, then
     * the same settings as `objcache configure-wordpress`. A site error is recorded, not thrown.
     * @param array{state:string, product_set:bool, checked:int, php:?string, error:?string}|null $old
     * @return array{state:string, product_set:bool, checked:int, php:?string, error:?string}
     */
    private function checkSite(string $user, string $home, string $path, ?string $hint, ?array $old): array
    {
        $php = $hint ?? $old['php'] ?? null;
        $previous = ($old['product_set'] ?? false) ? ($old['previous_socket'] ?? null) : null;
        $fingerprint = null;
        try {
            // The cheap look: two small files and a few names, as the account. Most passes end here.
            $fingerprint = $this->fingerprint($user, $path);
            $quick = $this->quickState($user, $path, ValkeyConfig::socket($home), $previous);
            if ($quick !== null) {
                return ['state' => $quick[0], 'product_set' => $quick[0] === 'automatic' ? ($old['product_set'] ?? true) : false,
                    'checked' => $this->now(), 'php' => $php, 'error' => null, 'fingerprint' => $fingerprint];
            }
            // An inactive plugin is asked again (wp-cli) only when the markers changed or after RECHECK_MAX.
            if (($old['state'] ?? null) === 'inactive' && ($old['fingerprint'] ?? null) === $fingerprint
                && $this->now() - $old['checked'] < self::RECHECK_MAX) {
                return $old;
            }
            $php ??= $this->discoverPhp($user);
            [$status, $set] = $this->configureSite($user, $home, $path, $php, $previous);
            return ['state' => $status, 'product_set' => $set, 'checked' => $this->now(), 'php' => $php, 'error' => null,
                'fingerprint' => $this->fingerprint($user, $path)];
        } catch (\Throwable $error) {
            return ['state' => 'error', 'product_set' => $old['product_set'] ?? false, 'checked' => $this->now(), 'php' => $php,
                'error' => self::message($error), 'attempts' => ($old['state'] ?? null) === 'error' ? ($old['attempts'] ?? 0) + 1 : 1]
                + (isset($old['previous_socket']) ? ['previous_socket' => $old['previous_socket']] : [])
                + ($fingerprint !== null ? ['fingerprint' => $fingerprint] : []);
        }
    }

    /** Seconds until a site record is due again: errors back off exponentially, an inactive plugin waits for RECHECK_MAX. */
    private static function recheckAfter(array $old): int
    {
        return match ($old['state']) {
            'error' => min(self::RECHECK_MAX, self::RECHECK_ERROR * (2 ** min(10, max(0, ($old['attempts'] ?? 1) - 1)))),
            default => self::RECHECK_OK,
        };
    }

    /** Which of the MARKERS exist (as the account, without following links): changes when the plugin is activated. */
    private function fingerprint(string $user, string $path): string
    {
        $present = [];
        foreach (self::MARKERS as $name) {
            if ($this->asUser($user, [self::TEST, '-e', "$path/$name"], 10)['exit_code'] === 0) {
                $present[] = $name;
            }
        }
        return implode(',', $present);
    }

    /**
     * The site's object cache from LiteSpeed Cache's own files, without running PHP: its drop-in loads the runtime
     * configuration file, which holds the object cache settings it uses. 'automatic' when they point to this account's
     * socket, 'owner' when another object cache drop-in or another server is in use, 'inactive' when the plugin is not
     * installed; null when the files cannot tell (then wp-cli decides).
     * @return array{0:string}|null
     */
    private function quickState(string $user, string $path, string $socket, ?string $previousSocket): ?array
    {
        if ($this->asUser($user, [self::TEST, '-d', "$path/wp-content/plugins/litespeed-cache"], 10)['exit_code'] !== 0) {
            $dropin = $this->asUser($user, ['/usr/bin/head', '-c', '4096', '--', "$path/" . self::DROPIN], 10);
            // Another object cache drop-in is the site owner's choice; without LiteSpeed Cache there is nothing to configure.
            return [$dropin['exit_code'] === 0 && $dropin['stdout'] !== '' && !str_contains($dropin['stdout'], 'litespeedtech.com')
                ? 'owner' : 'inactive'];
        }
        $dropin = $this->asUser($user, ['/usr/bin/head', '-c', '4096', '--', "$path/" . self::DROPIN], 10);
        if ($dropin['exit_code'] !== 0 || $dropin['stdout'] === '') {
            return null;  // no drop-in: the object cache is off (or the plugin inactive); wp-cli decides
        }
        if (!str_contains($dropin['stdout'], 'litespeedtech.com')) {
            return ['owner'];  // another plugin's object cache
        }
        foreach (self::RUNTIME_CONF as $name) {
            $conf = $this->asUser($user, ['/usr/bin/head', '-c', '65536', '--', "$path/$name"], 10);
            if ($conf['exit_code'] !== 0 || $conf['stdout'] === '') {
                continue;
            }
            $json = substr($conf['stdout'], (int) strpos($conf['stdout'], '{'));
            $settings = json_decode($json, true);
            if (!is_array($settings)) {
                return null;
            }
            $host = $settings['object-host'] ?? null;
            if (!is_string($host)) {
                return null;
            }
            if ($host !== $socket && $host !== $previousSocket) {
                return ['owner'];
            }
            // object-kind true is Redis in LiteSpeed Cache; port 0 for a Unix socket.
            return $host === $socket && ($settings['object-kind'] ?? null) === true && (int) ($settings['object-port'] ?? -1) === 0
                ? ['automatic'] : null;
        }
        return null;
    }

    /** @return array{0:string, 1:bool} state and whether the product's settings are in place */
    private function configureSite(string $user, string $home, string $path, string $php, ?string $previousSocket = null): array
    {
        $binary = "/opt/cpanel/$php/root/usr/bin/php";
        if ($this->asUser($user, [self::TEST, '-x', $binary])['exit_code'] !== 0) {
            throw new Refused("$binary is not available");
        }
        $limit = $this->now() + self::SITE_BUDGET;
        $wp = function (array $arguments) use ($user, $home, $binary, $path, $limit): array {
            $left = $limit - $this->now();
            if ($left <= 0) {
                throw new Refused('wp-cli took too long for this site; tried again later');
            }
            return $this->asUser($user, self::wpArgv($home, $binary, $path, $arguments), min(self::TIMEOUT, $left));
        };
        $active = $wp(['plugin', 'is-active', 'litespeed-cache']);
        if ($active['exit_code'] !== 0) {
            if ($active['exit_code'] !== 1 || str_contains($active['stderr'] ?? '', 'Error')) {
                throw new Refused('wp plugin is-active failed: ' . self::tail($active));
            }
            return ['inactive', false];
        }
        $get = function (string $option) use ($wp): string {
            $done = $wp(['litespeed-option', 'get', $option]);
            if ($done['exit_code'] !== 0) {
                throw new Refused("wp litespeed-option get $option failed: " . self::tail($done));
            }
            return trim($done['stdout']);
        };
        $socket = ValkeyConfig::socket($home);
        $on = self::flag($get('object'));
        if ($on === null) {
            throw new Refused('LiteSpeed Cache answered something unexpected for the object cache setting');
        }
        if ($on) {
            $host = $get('object-host');
            if ($host !== $socket && $host !== $previousSocket) {
                return ['owner', false];  // the site owner's own object cache: never overridden
            }
            if ($host === $socket && $get('object-kind') === '1' && $get('object-port') === '0') {
                return ['automatic', true];  // already ours: nothing to do
            }
        }
        if ($this->asUser($user, [$binary, '-r', 'exit(extension_loaded("redis") ? 0 : 3);'])['exit_code'] !== 0) {
            throw new Refused("the redis extension is not loaded in $php yet; the PHP environment pass installs it, then this is retried");
        }
        foreach ([['object-kind', '1'], ['object-host', $socket], ['object-port', '0'], ['object', 'true']] as [$option, $value]) {
            $done = $wp(['litespeed-option', 'set', $option, $value]);
            if ($done['exit_code'] !== 0) {
                throw new Refused("wp litespeed-option set $option failed: " . self::tail($done));
            }
        }
        return ['automatic', true];
    }

    private static function flag(string $text): ?bool
    {
        $value = strtolower(trim($text));
        return in_array($value, ['true', '1', 'on', 'yes'], true) ? true : (in_array($value, ['false', '0', 'off', 'no', ''], true) ? false : null);
    }

    /**
     * Switches LiteSpeed Cache's object cache off on the sites where the product switched it on (the socket is going
     * away or is not served now), and forgets the others. A site that cannot be switched off keeps its record and is
     * tried again by the next pass. $home null: the account or its home is gone, nothing can be done and nothing is kept.
     * @return list<array<string,mixed>> what happened per site that needed an action
     */
    private function turnOffWordPress(ObjectCacheState $state, string $user, ?string $home): array
    {
        $done = [];
        foreach ($state->wordpress[$user] ?? [] as $path => $row) {
            if (!$row['product_set'] || $home === null || !self::safeDirectory($path, $user, $home)) {
                unset($state->wordpress[$user][$path]);
                continue;
            }
            try {
                $php = $row['php'] ?? $this->discoverPhp($user);
                $binary = "/opt/cpanel/$php/root/usr/bin/php";
                $result = 'off';
                if ($this->asUser($user, [self::TEST, '-f', "$path/wp-config.php"])['exit_code'] !== 0) {
                    $result = 'gone';  // the installation was removed
                } else {
                    $limit = $this->now() + self::SITE_BUDGET;
                    $wp = fn(array $arguments): array => $this->asUser($user, self::wpArgv($home, $binary, $path, $arguments),
                        max(1, min(self::TIMEOUT, $limit - $this->now())));
                    $active = $wp(['plugin', 'is-active', 'litespeed-cache']);
                    if ($active['exit_code'] === 0) {
                        $set = $wp(['litespeed-option', 'set', 'object', 'false']);
                        if ($set['exit_code'] !== 0) {
                            throw new Refused('wp litespeed-option set object failed: ' . self::tail($set));
                        }
                    } elseif ($active['exit_code'] !== 1 || str_contains($active['stderr'] ?? '', 'Error')) {
                        throw new Refused('wp plugin is-active failed: ' . self::tail($active));
                    }
                }
                unset($state->wordpress[$user][$path]);
                $done[] = ['path' => $path, 'result' => $result];
            } catch (\Throwable $error) {
                $state->wordpress[$user][$path]['state'] = 'error';
                $state->wordpress[$user][$path]['error'] = self::message($error);
                $state->wordpress[$user][$path]['checked'] = $this->now();
                $done[] = ['path' => $path, 'result' => 'error', 'error' => self::message($error)];
            }
        }
        if (($state->wordpress[$user] ?? null) === []) {
            unset($state->wordpress[$user]);
        }
        return $done;
    }

    // --- Instances --------------------------------------------------------------------------------------------

    /**
     * Makes one account's instance match: files, socket directory, running state. Returns what it did.
     * @return list<string>
     */
    private function apply(string $user, string $home, int $mb, bool $suspended, string $state): array
    {
        $actions = [];
        $active = $state === 'active';
        if ($suspended) {
            // The stop comes before any file is written: a filesystem failure must not keep a suspended account's cache alive.
            if (!in_array($state, ['inactive', 'failed'], true)) {
                $stopped = $this->run('stop', [self::SYSTEMCTL, 'stop', ValkeyConfig::unit($user)]);
                if ($stopped['exit_code'] !== 0 || $this->isActive($user)) {
                    throw new Refused("the object cache instance of the suspended account $user could not be stopped: " . self::tail($stopped));
                }
                $actions[] = 'stopped (suspended)';
            }
            $changed = $this->writeFiles($user, $home, $mb);
            if ($changed['dropin']) {
                $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
            }
            return $actions;
        }
        $changed = $this->writeFiles($user, $home, $mb);
        if ($changed['dropin']) {
            $this->run('daemon-reload', [self::SYSTEMCTL, 'daemon-reload']);
        }
        if ($changed['conf'] || $changed['dropin'] || !$active) {
            $this->socketDir($user, $home);
            if (!$active) {
                $this->run('reset-failed', [self::SYSTEMCTL, 'reset-failed', ValkeyConfig::unit($user)]);
            }
            $started = $this->run('start', [self::SYSTEMCTL, 'restart', ValkeyConfig::unit($user)]);
            if ($started['exit_code'] !== 0) {
                throw new Refused("the object cache instance of $user did not start: " . self::tail($started));
            }
            $actions[] = $active ? 'restarted (configuration changed)' : 'started';
        }
        return $actions;
    }

    /** @return array{conf:bool, dropin:bool} what was written */
    private function writeFiles(string $user, string $home, int $mb): array
    {
        $directory = "{$this->confRoot}/$user";
        $dropins = "{$this->unitDir}/" . ValkeyConfig::UNIT_PREFIX . "$user.service.d";
        $files = [[$directory, 'valkey.conf', ValkeyConfig::render($user, $home, $mb)],
            [$dropins, '50-account.conf', ValkeyConfig::dropIn($home, $mb)]];
        $changed = [];
        foreach ($files as [$dir, $name, $text]) {
            if ((!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) || !@chmod($dir, 0755)) {
                throw new Refused("cannot create $dir");
            }
            $current = @file_get_contents("$dir/$name");
            $changed[] = $current !== $text;
            if ($current !== $text) {
                \OlsCpanel\Events\HookEntry::writeDurable("$dir/$name", $text, 0644);
            }
        }
        return ['conf' => $changed[0], 'dropin' => $changed[1]];
    }

    /** The account's socket directory (0700, owned by the account), created as the account. */
    private function socketDir(string $user, string $home): void
    {
        $dir = ValkeyConfig::socketDir($home);
        if ($this->asUser($user, [self::TEST, '-L', $dir])['exit_code'] === 0) {
            throw new Refused("$dir is a symbolic link; remove it");
        }
        $made = $this->asUser($user, [self::INSTALL, '-d', '-m', '0700', $dir]);
        if ($made['exit_code'] !== 0) {
            throw new Refused("cannot create $dir as $user: " . self::tail($made));
        }
    }

    /** Stops the instance and removes its configuration, drop-in and socket directory (as the account). */
    private function cleanup(string $user, ?string $home): void
    {
        $stopped = $this->run('stop', [self::SYSTEMCTL, 'stop', ValkeyConfig::unit($user)]);
        if ($stopped['exit_code'] !== 0 || $this->isActive($user)) {
            throw new Refused("the object cache instance of $user could not be stopped: " . self::tail($stopped));
        }
        $this->run('reset-failed', [self::SYSTEMCTL, 'reset-failed', ValkeyConfig::unit($user)]);
        if ($home !== null && HomePath::homeOf($home, $user) === $home) {
            $removed = $this->asUser($user, [self::RM, '-rf', '--', ValkeyConfig::socketDir($home)]);
            if ($removed['exit_code'] !== 0) {
                throw new Refused('cannot remove ' . ValkeyConfig::socketDir($home) . ': ' . self::tail($removed));
            }
        }
        $dropins = "{$this->unitDir}/" . ValkeyConfig::UNIT_PREFIX . "$user.service.d";
        foreach (["$dropins/50-account.conf" => $dropins, "{$this->confRoot}/$user/valkey.conf" => "{$this->confRoot}/$user"] as $file => $dir) {
            if (is_file($file) && !@unlink($file)) {
                throw new Refused("cannot remove $file");
            }
            if (is_dir($dir) && !@rmdir($dir)) {
                throw new Refused("cannot remove $dir");
            }
        }
    }

    // --- cPanel and system facts, all through the runner -------------------------------------------------------

    /** @return array{user:string, uid:int, home:string} */
    private function account(string $user): array
    {
        if (!ValkeyConfig::validUser($user)) {
            throw new Refused('invalid account name');
        }
        if ($this->run('cpanel-account', [self::TEST, '-e', self::CPANEL_USERS . "/$user"])['exit_code'] !== 0) {
            throw new Refused("$user is not a cPanel account");
        }
        $entry = $this->passwd($user)[$user] ?? null;
        if ($entry === null || $entry['uid'] < self::MIN_UID) {
            throw new Refused("$user is not a regular account");
        }
        if (HomePath::homeOf($entry['home'], $user) !== $entry['home'] || strlen(ValkeyConfig::socket($entry['home'])) > ValkeyConfig::MAX_SOCKET_PATH) {
            throw new Refused("the home directory of $user is not /<home mount>/$user");
        }
        return ['user' => $user, 'uid' => $entry['uid'], 'home' => $entry['home']];
    }

    private function homeIfAny(string $user): ?string
    {
        $entry = $this->passwd($user)[$user] ?? null;
        return $entry !== null && $entry['uid'] >= self::MIN_UID && HomePath::homeOf($entry['home'], $user) === $entry['home'] ? $entry['home'] : null;
    }

    /** @return array<string,array{uid:int, home:string}> */
    private function passwd(?string $user = null): array
    {
        $done = $this->run('passwd', [self::GETENT, 'passwd', ...($user === null ? [] : [$user])]);
        $found = [];
        foreach (explode("\n", $done['stdout']) as $line) {
            $fields = explode(':', $line);
            if (count($fields) >= 7 && ctype_digit($fields[2]) && $fields[0] !== '') {
                $found[$fields[0]] = ['uid' => (int) $fields[2], 'home' => $fields[5]];
            }
        }
        return $found;
    }

    private function planOf(string $user): ?string
    {
        if (!ValkeyConfig::validUser($user)) {
            return null;
        }
        $done = $this->run('plan', [self::GREP, '-m1', '--', '^PLAN=', self::CPANEL_USERS . "/$user"]);
        return $done['exit_code'] === 0 && str_starts_with($done['stdout'], 'PLAN=') ? rtrim(substr($done['stdout'], 5), "\n") : null;
    }

    private function planMemory(ObjectCacheState $state, string $user): ?int
    {
        $plan = $this->planOf($user);
        return $plan !== null ? ($state->packages[$plan]['memory_mb'] ?? null) : null;
    }

    /**
     * Every existing cPanel account => its package. An empty array is returned only for an authoritative "zero
     * accounts": grep found no PLAN line (exit 1, no error) and the account directory itself is readable. An
     * unreadable directory or a failed command throws, so "nothing found" is never read as "every account was removed".
     * @return array<string,string>
     */
    private function plans(): array
    {
        $done = $this->run('plans', [self::GREP, '-rH', '-m1', '--', '^PLAN=', self::CPANEL_USERS]);
        $plans = [];
        foreach (explode("\n", $done['stdout']) as $line) {
            if (preg_match('~^' . preg_quote(self::CPANEL_USERS, '~') . '/([a-z0-9][a-z0-9_.-]*):PLAN=(.*)$~D', $line, $match)) {
                $plans[$match[1]] = $match[2];
            }
        }
        if ($plans !== [] && $done['exit_code'] === 0) {
            return $plans;
        }
        if ($plans === [] && $done['exit_code'] === 1 && trim($done['stdout']) === ''
            && $this->run('users-dir', [self::TEST, '-d', self::CPANEL_USERS])['exit_code'] === 0
            && $this->run('users-dir-list', [self::LS, '-1', '--', self::CPANEL_USERS])['exit_code'] === 0) {
            return [];  // authoritative: the directory is readable and holds no account
        }
        throw new Refused('cannot read the cPanel account list; nothing was changed');
    }

    /** @throws Refused when the marker cannot be told (anything but test's exit 0 and 1): an unknown state is never "not suspended" */
    private function suspendedNow(string $user): bool
    {
        $done = $this->run('suspended', [self::TEST, '-e', self::CPANEL_SUSPENDED . "/$user"]);
        if ($done['exit_code'] !== 0 && $done['exit_code'] !== 1) {
            throw new Refused("cannot tell whether $user is suspended: " . self::tail($done));
        }
        return $done['exit_code'] === 0;
    }

    /**
     * The suspended accounts, or null when the marker directory cannot be listed (callers then start nothing). A
     * directory that does not exist is an authoritative empty set; one that exists but cannot be listed is not.
     * @return array<string,true>|null
     */
    private function suspendedSet(): ?array
    {
        $done = $this->run('suspended-list', [self::LS, '-1', '--', self::CPANEL_SUSPENDED]);
        if ($done['exit_code'] !== 0) {
            $exists = $this->run('suspended-dir', [self::TEST, '-e', self::CPANEL_SUSPENDED]);
            return $exists['exit_code'] === 1 ? [] : null;
        }
        $set = [];
        foreach (explode("\n", $done['stdout']) as $name) {
            if ($name !== '') {
                $set[$name] = true;
            }
        }
        return $set;
    }

    /** The instance's state as far as apply() distinguishes it: active or inactive. */
    private function instanceState(string $user): string
    {
        return $this->isActive($user) ? 'active' : 'inactive';
    }

    private function isActive(string $user): bool
    {
        return $this->run('is-active', [self::SYSTEMCTL, 'is-active', '--quiet', ValkeyConfig::unit($user)])['exit_code'] === 0;
    }

    /** @return array<string,string> account => systemd active state of its instance (including failed ones) */
    private function running(): array
    {
        $done = $this->run('list-units', [self::SYSTEMCTL, 'list-units', '--all', '--plain', '--no-legend', '--no-pager',
            ValkeyConfig::UNIT_PREFIX . '*.service']);
        $units = [];
        foreach (explode("\n", $done['stdout']) as $line) {
            if (preg_match('/^' . preg_quote(ValkeyConfig::UNIT_PREFIX, '/') . '(\S+)\.service\s+\S+\s+(\S+)/', $line, $match)) {
                $units[$match[1]] = $match[2];
            }
        }
        return $units;
    }

    /** @return list<string> accounts with a configuration directory */
    private function configured(): array
    {
        $found = [];
        foreach (is_dir($this->confRoot) ? (scandir($this->confRoot) ?: []) : [] as $name) {
            if (ValkeyConfig::validUser($name) && is_dir("{$this->confRoot}/$name")) {
                $found[] = $name;
            }
        }
        return $found;
    }

    private function discoverPhp(string $user): string
    {
        $done = $this->run('php-versions', [self::WHMAPI, '--output=json', 'php_get_vhost_versions']);
        $data = json_decode($done['stdout'], true, 16);
        foreach ($done['exit_code'] === 0 && is_array($data) ? ($data['data']['versions'] ?? []) : [] as $row) {
            if (is_array($row) && ($row['account'] ?? null) === $user && !empty($row['main_domain'])
                && is_string($row['version'] ?? null) && preg_match(self::PHP, $row['version'])) {
                return $row['version'];
            }
        }
        throw new Refused("cannot determine the PHP version of $user's main domain; pass --php=ea-phpNN");
    }

    private function ensureTimer(): bool
    {
        if ($this->run('timer-enabled', [self::SYSTEMCTL, 'is-enabled', '--quiet', self::TIMER])['exit_code'] === 0) {
            return true;
        }
        return $this->run('timer-enable', [self::SYSTEMCTL, 'enable', '--now', self::TIMER])['exit_code'] === 0;
    }

    /**
     * The valkey-cli call as the account against its own socket.
     * @param list<string> $arguments
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    private function cli(string $user, string $home, array $arguments): array
    {
        return $this->asUser($user, [ValkeyConfig::CLI, '-s', ValkeyConfig::socket($home), ...$arguments], 30);
    }

    /** @return array<string,mixed> the fields of INFO the status shows */
    public static function usage(array $info): array
    {
        $fields = [];
        foreach (explode("\n", $info['stdout']) as $line) {
            if (preg_match('/^([a-z0-9_]+):(.*)$/', rtrim($line), $match)) {
                $fields[$match[1]] = $match[2];
            }
        }
        $number = static fn(string $key): ?int => isset($fields[$key]) && ctype_digit($fields[$key]) ? (int) $fields[$key] : null;
        $hits = $number('keyspace_hits');
        $misses = $number('keyspace_misses');
        $keys = 0;
        foreach ($fields as $key => $value) {
            if (preg_match('/^db[0-9]+$/', $key) && preg_match('/keys=([0-9]+)/', $value, $m)) {
                $keys += (int) $m[1];
            }
        }
        return ['used_memory' => $number('used_memory'), 'maxmemory' => $number('maxmemory'), 'keys' => $keys,
            'evicted_keys' => $number('evicted_keys'), 'keyspace_hits' => $hits, 'keyspace_misses' => $misses,
            'hit_rate' => $hits !== null && $misses !== null && $hits + $misses > 0 ? round($hits / ($hits + $misses), 4) : null,
            'connected_clients' => $number('connected_clients'), 'uptime_seconds' => $number('uptime_in_seconds')];
    }

    // --- PHP redis extension --------------------------------------------------------------------------------------

    /**
     * The extension for the account's PHP versions, never fatal for the enable itself: the instance is up either way
     * and the outcome (and any failure) is part of the result.
     * @return array<string,mixed>|null
     */
    private function extensionFor(string $user): ?array
    {
        if ($this->extensions === null) {
            return null;
        }
        try {
            $versions = $this->accountPhpVersions($user);
            if ($versions === []) {
                return ['result' => 'skipped', 'note' => "cannot determine the PHP versions of $user; run: ols-cpanel php-ext install"];
            }
            return $this->extensions->ensureForAccount($user, $versions);
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'error' => self::message($error)];
        }
    }

    /** @return array<string,mixed> */
    private function extensionStatus(): array
    {
        try {
            return $this->extensions->status();
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'error' => self::message($error)];
        }
    }

    /**
     * The reconcile pass's part: object cache in use means the extension is wanted; the work itself (dnf, compiler)
     * does not fit this unit's sandbox, so it is started in the unrestricted watcher service, without waiting.
     * Failures that are still unresolved are errors of this pass, so the unit shows failed and the status says why.
     * @param list<array<string,mixed>> $actions
     * @param list<array<string,mixed>> $errors
     * @return array<string,mixed>
     */
    private function watchExtension(array &$actions, array &$errors): array
    {
        try {
            $status = $this->extensions->status();
            // Wanted but the units that retry the work are off (an administrator disabled them): enable them again now.
            $unitsOff = array_key_exists('watcher', $status) && ($status['watcher'] !== true || ($status['timer'] ?? true) !== true);
            if (($status['wanted'] ?? false) !== true || $unitsOff) {
                $this->extensions->want();
                $status['needs_sync'] = true;
            }
            if (($status['needs_sync'] ?? false) === true) {
                $this->run('php-ext-trigger', [self::SYSTEMCTL, 'start', '--no-block', ExtensionInstaller::SERVICE]);
                $actions[] = ['account' => '(php-ext)', 'action' => 'started a PHP extension pass'];
            }
            foreach ($status['versions'] ?? [] as $row) {
                if (!in_array($row['status'] ?? '', ['active', 'already_loaded'], true) && isset($row['last_failure'])) {
                    $errors[] = ['account' => '(php-ext)', 'error' => "redis extension in {$row['php']}: " . self::message(new \RuntimeException($row['last_failure']['error']))];
                }
            }
            return $status;
        } catch (\Throwable $error) {
            $errors[] = ['account' => '(php-ext)', 'error' => self::message($error)];
            return ['result' => 'failed'];
        }
    }

    /** @return list<string> distinct EA4 PHP versions of the account's vhosts */
    private function accountPhpVersions(string $user): array
    {
        $done = $this->run('php-versions', [self::WHMAPI, '--output=json', 'php_get_vhost_versions']);
        $data = json_decode($done['stdout'], true, 16);
        $found = [];
        foreach ($done['exit_code'] === 0 && is_array($data) ? ($data['data']['versions'] ?? []) : [] as $row) {
            if (is_array($row) && ($row['account'] ?? null) === $user && is_string($row['version'] ?? null) && preg_match(self::PHP, $row['version'])) {
                $found[$row['version']] = true;
            }
        }
        $versions = array_keys($found);
        sort($versions, SORT_STRING);
        return $versions;
    }

    // --- Plumbing --------------------------------------------------------------------------------------------

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    private function run(string $name, array $argv, int $timeout = self::TIMEOUT): array
    {
        return $this->runner->run('objcache-' . $name, $argv, $timeout);
    }

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    private function asUser(string $user, array $argv, int $timeout = self::TIMEOUT): array
    {
        return $this->run('as-user', [self::RUNUSER, '-u', $user, '--', ...$argv], $timeout);
    }

    /** @template T @param \Closure():T $work @return T */
    private function locked(\Closure $work): mixed
    {
        if ($this->lockPath === null) {
            return $work();
        }
        $lock = @fopen($this->lockPath, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new Refused("cannot take the object cache lock {$this->lockPath}");
        }
        try {
            return $work();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** @param array{stdout:string, stderr?:string} $done */
    private static function tail(array $done): string
    {
        return substr(preg_replace('/[^\x20-\x7e]/', '?', trim(($done['stderr'] ?? '') !== '' ? $done['stderr'] : $done['stdout'])) ?? '', -200);
    }

    private static function message(\Throwable $error): string
    {
        return substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 300);
    }
}
