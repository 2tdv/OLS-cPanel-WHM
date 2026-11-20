<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Ols\Compiler\CachePolicy;
use OlsCpanel\Ols\Generation\LocalEngine;

/**
 * The cPanel hook entry (port of ols_events.hook), run as root by cPanel with the event as JSON on stdin.
 * It records the event durably in the spool (one file per event, written to a temporary name, synced,
 * renamed, directory synced) for the reconciler. For security events (suspension, account or domain
 * removal) it first raises the restriction epoch through the activator (`restrict <reason>`), before
 * cPanel's operation is acknowledged, so no rollback can serve the old rights. It always answers exactly
 * "1": anything else (even "1\n") is a failure message to cPanel, and the event pipeline must never fail
 * the cPanel operation; problems go to stderr and the periodic reconciliation catches up.
 *
 * When the epoch cannot be raised (restrict fails or times out) the restriction is not lost (review RV-29,
 * finding 5): before "1" is printed it is written as a durable restriction intent, one file per restriction
 * in STATE/restrictions/ (root 0700; file root 0600, written to a temporary name, synced, renamed, directory
 * synced; name `<nanoseconds>-<32 hex>.json` like the spool), the JSON object
 * `{"event": <cPanel event>, "reason": <the restrict reason, at most 200 characters>, "time": <Unix seconds>,
 * "user": <user or null>}`. The broker's enforcement thread and every reconcile pass fold intents into the
 * epoch (Engine::foldRestrictions) before deciding anything, and enforcement counts an intent as a restriction
 * no generation has applied. The restriction is attempted before the spool directory is even created, and the
 * event is still spooled (without "epoch") so the reconciler applies the change as soon as it can.
 *
 * RV-65 (a suspension applied one to three minutes late): cPanel's own tools keep the password database in caches under /etc
 * (passwd.cache, shadow.nouids.cache), valid only when written in a later second than /etc/passwd and /etc/shadow. Suspension,
 * unsuspension, creation and removal change those files, so the next whmapi1 listaccts or php_get_vhost_versions rebuilds the
 * cache, and inside the broker's sandbox (/etc read-only) that rebuild fails: every compile was refused ("API command listaccts
 * failed", "API semantic failure in php_get_vhost_versions") until some unconfined cPanel process happened to rebuild the
 * caches. So, for the account events, the hook (root, outside any sandbox, after cPanel changed the files: stage "post") waits
 * for the next second and runs the compile's two cPanel reads itself before the event is spooled ($refreshCpanelCaches): the
 * reconciler's first pass finds the caches current. Then, for a suspension or a removal, the account's page cache stores are
 * purged ($purge): from the hook on, no page of the account is served from the cache (the new generation disables its cache).
 * Finally, for a restricting event, when the reconciler service runs, the hook waits (at most $applyWait seconds) until the
 * reconciler has consumed the spooled event, that is until a configuration that includes it is active: when cPanel's
 * operation returns, OLS already serves the restriction. A timeout only ends the wait; the restriction deadline still holds.
 */
final class HookEntry
{
    /** Events after which serving the previous configuration would keep rights cPanel just removed. */
    public const RESTRICTING = ['Accounts::suspendacct', 'Accounts::Remove', 'Api2::SubDomain::delsubdomain',
        'Api2::AddonDomain::deladdondomain', 'Api2::Park::unpark', 'UAPI::SubDomain::delete_subdomain'];
    public const SPOOL = LocalEngine::STATE . '/events';
    public const INTENTS = LocalEngine::STATE . '/' . LocalEngine::RESTRICTIONS;
    /** Events after which the object cache instances must be reconciled (suspend stops, unsuspend starts, removal cleans up). */
    public const OBJCACHE_EVENTS = ['Accounts::suspendacct', 'Accounts::unsuspendacct', 'Accounts::Remove', 'Accounts::change_package',
        'Accounts::Create', 'Accounts::Modify', 'Restore', 'Transfers::Session'];
    public const TRUST_EVENTS = ['Accounts::SiteIP::set', 'Accounts::Modify', 'Restore', 'Transfers::Session'];
    public const TRUST_SERVICE = 'ols-cpanel-hybrid-trust.service';
    public const OBJCACHE_SERVICE = 'ols-cpanel-objcache.service';
    /** Events after which cPanel has changed /etc/passwd or /etc/shadow (shell, password lock, account added or removed): RV-65. */
    public const ACCOUNT_EVENTS = ['Accounts::Create', 'Accounts::Remove', 'Accounts::suspendacct', 'Accounts::unsuspendacct',
        'Accounts::Modify', 'Accounts::change_package', 'Restore', 'Transfers::Session'];
    /** cPanel's single password change hook (Cpanel::ChangePasswd, reached by WHM passwd and UAPI Users::change_password): cache refresh only. */
    public const PASSWORD_EVENT = ['Passwd', 'ChangePasswd'];
    /**
     * cPanel's shell change (Whostmgr::Accounts::Shell::set_shell, /usr/local/cpanel/Whostmgr/Accounts/Shell.pm lines 79 and 110; also
     * reached by the package change's shell step and the transfer restore): rewrites /etc/passwd, nothing the configuration depends on.
     */
    public const SHELL_EVENT = ['Whostmgr', 'Accounts::set_shell'];
    /** Events that only refresh cPanel's password caches: nothing is spooled, no restriction, no wait. */
    public const REFRESH_ONLY_EVENTS = [self::PASSWORD_EVENT, self::SHELL_EVENT];
    /** The compile's cPanel reads that rebuild cPanel's password caches under /etc (BuilderCompilation, ServerConfigurationBuilder). */
    public const CPANEL_CACHE_READS = [
        ['/usr/local/cpanel/bin/whmapi1', '--output=json', 'listaccts'],
        ['/usr/local/cpanel/bin/whmapi1', '--output=json', 'php_get_vhost_versions'],
    ];
    /** Events whose account's page cache stores the hook purges at once (RV-65). */
    public const PURGE_EVENTS = ['Accounts::suspendacct', 'Accounts::Remove'];
    /** The longest wait of the hook for the reconciler to apply a restricting event (RV-65). */
    public const APPLY_WAIT = 45;
    public const RECONCILER_SERVICE = 'ols-cpanel-reconciler.service';
    /** restrict waits for the activation lock, which an activation holds for its bounded duration. */
    private const RESTRICT_TIMEOUT = 300;
    private const CPANEL_READ_TIMEOUT = 60;
    /** cPanel's caches are valid when written in a later second than passwd and shadow: the hook waits that long at most. */
    private const CACHE_SETTLE = 2.0;
    private const POLL = 0.2;

    private CommandRunner $runner;
    /** @var \Closure():float */
    private \Closure $clock;
    /** @var \Closure(float):void */
    private \Closure $sleep;

    /**
     * @param bool $refreshCpanelCaches run CPANEL_CACHE_READS after an account event, before spooling it (production: true)
     * @param (\Closure(string):array<string,mixed>)|null $purge purges every page cache store of an account (CacheManager::purge)
     * @param int $applyWait seconds a restricting event waits for the reconciler to consume it (0: no wait)
     * @param string $etc where passwd and shadow are
     * @param (\Closure():float)|null $clock seconds
     * @param (\Closure(float):void)|null $sleep
     */
    public function __construct(private readonly string $spool = self::SPOOL, ?CommandRunner $runner = null,
                                private readonly string $activator = LocalEngine::ACTIVATOR,
                                private readonly string $intents = self::INTENTS, private readonly ?string $objcacheState = null,
                                private readonly bool $refreshCpanelCaches = false, private readonly ?\Closure $purge = null,
                                private readonly int $applyWait = 0, private readonly string $etc = '/etc',
                                ?\Closure $clock = null, ?\Closure $sleep = null)
    {
        $this->runner = $runner ?? new LocalCommandRunner(LocalCommandRunner::MAX_OUTPUT, true);
        $this->clock = $clock ?? static fn(): float => microtime(true);
        $this->sleep = $sleep ?? static function (float $seconds): void {
            usleep((int) round($seconds * 1e6));
        };
    }

    /**
     * @param resource $stdout receives exactly "1"
     * @param resource $stderr
     */
    public function handle(string $input, $stdout, $stderr): void
    {
        try {
            $this->record($input, $stderr);
        } catch (\Throwable $error) {
            fwrite($stderr, 'ols-cpanel event hook: ' . Reconciler::describe($error) . "\n");
        } finally {
            fwrite($stdout, '1');
        }
    }

    /** @param resource $stderr */
    private function record(string $input, $stderr): void
    {
        $payload = $input === '' ? [] : json_decode($input, true, 64);
        $context = is_array($payload) && !array_is_list($payload) ? ($payload['context'] ?? null) : null;
        if (!is_array($context) || $context === [] || array_is_list($context)) {
            return;  // registry maintenance runs the script without an event
        }
        $data = is_array($payload['data'] ?? null) ? $payload['data'] : [];
        $event = ['category' => $context['category'] ?? null, 'event' => $context['event'] ?? null,
            'stage' => $context['stage'] ?? null, 'time' => microtime(true),
            'user' => self::first($context['user'] ?? null, $data['user'] ?? null, $data['username'] ?? null)];
        // A password change (WHM passwd, UAPI Users::change_password, the cPanel interface) changes /etc/shadow, a shell change
        // /etc/passwd, and neither changes anything the configuration depends on: only cPanel's caches are refreshed. Nothing of
        // the payload (a password change's holds the password) is kept.
        if (in_array([$event['category'], $event['event']], self::REFRESH_ONLY_EVENTS, true)) {
            if ($this->refreshCpanelCaches) {
                $this->refreshCaches($stderr);
            }
            return;
        }
        if (in_array($event['event'], self::RESTRICTING, true)) {
            $reason = substr($event['event'] . ' ' . self::text($event['user']), 0, 200);
            try {
                $raised = $this->runner->run('restrict', [$this->activator, 'restrict', $reason], self::RESTRICT_TIMEOUT);
                $epoch = $raised['exit_code'] === 0 ? (json_decode(trim($raised['stdout']), true, 8)['epoch'] ?? null) : null;
                if (!is_int($epoch)) {
                    throw new \RuntimeException('activator restrict failed: ' . substr(trim($raised['stderr'] ?? ''), -200));
                }
                $event['epoch'] = $epoch;
            } catch (\Throwable $error) {
                fwrite($stderr, 'ols-cpanel event hook: restriction epoch not raised: ' . Reconciler::describe($error) . "\n");
                try {
                    $intent = $this->recordIntent($event, $reason);
                    fwrite($stderr, "ols-cpanel event hook: restriction kept as the durable intent $intent\n");
                } catch (\Throwable $failure) {
                    fwrite($stderr, 'ols-cpanel event hook: restriction intent not recorded: ' . Reconciler::describe($failure) . "\n");
                }
            }
        }
        // Preserve only the verified identity fields, never the rest of a hook payload (which may contain secrets).
        if ($event['category'] === 'Whostmgr' && $event['event'] === 'Accounts::Modify'
            && is_string($data['user'] ?? null) && is_string($data['newuser'] ?? null)
            && $data['user'] !== $data['newuser']
            && \OlsCpanel\ObjectCache\ValkeyConfig::validUser($data['user'])
            && \OlsCpanel\ObjectCache\ValkeyConfig::validUser($data['newuser'])) {
            $event['olduser'] = $data['user'];
            $event['newuser'] = $data['newuser'];
            if ($this->objcacheState !== null) {
                $directory = dirname($this->objcacheState) . '/account-renames';
                if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
                    throw new \RuntimeException('cannot create account rename queue');
                }
                self::writeDurable($directory . '/' . self::newName(), json_encode(
                    ['olduser' => $data['user'], 'newuser' => $data['newuser']], JSON_THROW_ON_ERROR), 0600);
            }
        }
        // RV-65: before the reconciler can see the event, so its first pass reads current cPanel caches.
        if ($this->refreshCpanelCaches && in_array($event['event'], self::ACCOUNT_EVENTS, true)) {
            $this->refreshCaches($stderr);
        }
        // Triggers are independent of spool availability; timers retry any failed start.
        $this->triggerService($event['event'], self::TRUST_EVENTS, self::TRUST_SERVICE, $stderr);
        $this->triggerObjectCache($event['event'], $stderr);
        if (!is_dir($this->spool) && !@mkdir($this->spool, 0700, true)) {
            throw new \RuntimeException("cannot create {$this->spool}");
        }
        ksort($event, SORT_STRING);
        $name = self::newName();
        self::writeDurable("{$this->spool}/$name", json_encode($event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
        // The account is data.user for these WHM events (context.user is the operator, e.g. root).
        if ($this->purge !== null && in_array($event['event'], self::PURGE_EVENTS, true)) {
            $this->purgeAccount($data['user'] ?? null, $stderr);
        }
        if ($this->applyWait > 0 && in_array($event['event'], self::RESTRICTING, true)) {
            $this->waitApplied($name, $stderr);
        }
    }

    /**
     * Rebuilds cPanel's password caches as root outside any sandbox (RV-65; see the class comment): waits until the clock is past
     * the second of the last passwd or shadow change (a cache written in that same second counts as stale), then runs the
     * compile's cPanel reads. Never throws; a failure only leaves the rebuild to the next unconfined cPanel process.
     * @param resource $stderr
     */
    private function refreshCaches($stderr): void
    {
        clearstatcache();
        $latest = max((int) @filemtime("{$this->etc}/passwd"), (int) @filemtime("{$this->etc}/shadow"));
        $deadline = ($this->clock)() + self::CACHE_SETTLE;
        while (floor(($this->clock)()) <= $latest && ($this->clock)() < $deadline) {
            ($this->sleep)(min(self::POLL, max(0.01, $latest + 1 - ($this->clock)())));
        }
        foreach (self::CPANEL_CACHE_READS as $argv) {
            try {
                $read = $this->runner->run('cpanel-cache-refresh', $argv, self::CPANEL_READ_TIMEOUT);
                if ($read['exit_code'] !== 0) {
                    fwrite($stderr, "ols-cpanel event hook: {$argv[2]} failed (exit {$read['exit_code']}); cPanel's caches are rebuilt later\n");
                }
            } catch (\Throwable $error) {
                fwrite($stderr, "ols-cpanel event hook: {$argv[2]}: " . Reconciler::describe($error) . "\n");
            }
        }
    }

    /**
     * Empties every page cache store of a suspended or removed account (RV-65). Never throws.
     * @param resource $stderr
     */
    private function purgeAccount(mixed $account, $stderr): void
    {
        if (!is_string($account) || preg_match(CachePolicy::USER, $account) !== 1) {
            fwrite($stderr, "ols-cpanel event hook: no valid account in the event; no page cache purged\n");
            return;
        }
        try {
            $purged = ($this->purge)($account);
            if (($purged['result'] ?? null) !== 'purged') {
                fwrite($stderr, "ols-cpanel event hook: page cache of $account: " . substr((string) ($purged['error'] ?? 'not purged'), 0, 300) . "\n");
            }
        } catch (\Throwable $error) {
            fwrite($stderr, "ols-cpanel event hook: page cache of $account not purged: " . Reconciler::describe($error) . "\n");
        }
    }

    /**
     * Waits until the reconciler has consumed the spooled restricting event (moved out of the spool once a configuration that
     * includes it is active), at most $applyWait seconds, and only while the reconciler service runs. Never throws.
     * @param resource $stderr
     */
    private function waitApplied(string $name, $stderr): void
    {
        try {
            $active = $this->runner->run('reconciler-active', ['/usr/bin/systemctl', 'is-active', '--quiet', self::RECONCILER_SERVICE], 20);
        } catch (\Throwable) {
            return;
        }
        if ($active['exit_code'] !== 0) {
            return;  // nothing would consume it now; the restriction deadline applies
        }
        $deadline = ($this->clock)() + $this->applyWait;
        while (true) {
            clearstatcache();
            if (!file_exists("{$this->spool}/$name")) {
                return;
            }
            if (($this->clock)() >= $deadline) {
                fwrite($stderr, "ols-cpanel event hook: the event is not applied after {$this->applyWait} s; the reconciler applies it"
                    . " (restriction deadline enforcement meanwhile)\n");
                return;
            }
            ($this->sleep)(self::POLL);
        }
    }

    /**
     * For account lifecycle events, asks systemd to run the reconciliation now, without waiting for it (the
     * oneshot unit applies suspension, unsuspension and removal; a failure here only delays that to the timer's
     * next period). Never throws: the hook always answers "1".
     * @param resource $stderr
     */
    private function triggerObjectCache(mixed $event, $stderr): void
    {
        if ($this->objcacheState === null || !in_array($event, self::OBJCACHE_EVENTS, true)) {
            return;
        }
        $this->triggerService($event, self::OBJCACHE_EVENTS, self::OBJCACHE_SERVICE, $stderr);
    }

    /** @param list<string> $events @param resource $stderr */
    private function triggerService(mixed $event, array $events, string $service, $stderr): void
    {
        if (!in_array($event, $events, true)) {
            return;
        }
        try {
            $started = $this->runner->run($service === self::TRUST_SERVICE ? 'hybrid-trust-trigger' : 'objcache-trigger',
                ['/usr/bin/systemctl', 'start', '--no-block', $service], 20);
            if ($started['exit_code'] !== 0) {
                fwrite($stderr, "ols-cpanel event hook: $service not started; the timer applies it\n");
            }
        } catch (\Throwable $error) {
            fwrite($stderr, 'ols-cpanel event hook: service trigger: ' . Reconciler::describe($error) . "\n");
        }
    }

    /**
     * The durable restriction intent (see the class comment); returns its file name.
     * @param array<string,mixed> $event
     */
    private function recordIntent(array $event, string $reason): string
    {
        if (!is_dir($this->intents) && !@mkdir($this->intents, 0700, true)) {
            throw new \RuntimeException("cannot create {$this->intents}");
        }
        $intent = ['event' => is_string($event['event']) ? $event['event'] : null, 'reason' => $reason, 'time' => $event['time'],
            'user' => is_string($event['user']) && $event['user'] !== '' ? $event['user'] : null];
        $name = self::newName();
        self::writeDurable("{$this->intents}/$name", json_encode($intent, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR), 0600);
        return $name;
    }

    /** <nanoseconds>-<random>.json like the lab (time.time_ns()): names sort in arrival order. */
    private static function newName(): string
    {
        [$fraction, $seconds] = explode(' ', microtime());
        return $seconds . substr($fraction, 2, 6) . '000-' . bin2hex(random_bytes(16)) . '.json';
    }

    /** @param int|null $mode the file's mode, set before anything is written (null: the umask's default) */
    public static function writeDurable(string $path, string $text, ?int $mode = null): void
    {
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(16));
        $handle = @fopen($tmp, 'x');
        if ($handle === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        if ($mode !== null && !chmod($tmp, $mode)) {
            fclose($handle);
            @unlink($tmp);
            throw new \RuntimeException("cannot set the mode of $tmp");
        }
        try {
            if (fwrite($handle, $text) !== strlen($text) || !fflush($handle) || !fsync($handle)) {
                throw new \RuntimeException("cannot write $tmp");
            }
        } finally {
            fclose($handle);
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot install $path");
        }
        $directory = @fopen(dirname($path), 'r');
        if ($directory !== false) {
            fsync($directory);
            fclose($directory);
        }
    }

    /** Python's `a or b or c`: the first truthy value, else the last. */
    private static function first(mixed ...$values): mixed
    {
        foreach ($values as $value) {
            if (!in_array($value, [null, false, 0, 0.0, '', []], true)) {
                return $value;
            }
        }
        return $values[count($values) - 1];
    }

    private static function text(mixed $value): string
    {
        return match (true) {
            $value === null => 'None',
            is_scalar($value) => (string) $value,
            default => json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE) ?: '?',
        };
    }
}
