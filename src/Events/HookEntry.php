<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
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
    /** restrict waits for the activation lock, which an activation holds for its bounded duration. */
    private const RESTRICT_TIMEOUT = 300;

    private CommandRunner $runner;

    public function __construct(private readonly string $spool = self::SPOOL, ?CommandRunner $runner = null,
                                private readonly string $activator = LocalEngine::ACTIVATOR,
                                private readonly string $intents = self::INTENTS, private readonly ?string $objcacheState = null)
    {
        $this->runner = $runner ?? new LocalCommandRunner(LocalCommandRunner::MAX_OUTPUT, true);
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
        // Triggers are independent of spool availability; timers retry any failed start.
        $this->triggerService($event['event'], self::TRUST_EVENTS, self::TRUST_SERVICE, $stderr);
        $this->triggerObjectCache($event['event'], $stderr);
        if (!is_dir($this->spool) && !@mkdir($this->spool, 0700, true)) {
            throw new \RuntimeException("cannot create {$this->spool}");
        }
        ksort($event, SORT_STRING);
        self::writeDurable("{$this->spool}/" . self::newName(), json_encode($event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
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
