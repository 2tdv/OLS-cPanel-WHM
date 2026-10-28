<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

/**
 * Notifications (FV-07), run every five minutes by ols-cpanel-notify.timer as `ols-cpanel notify run` (root). It reads the
 * product's own state and result files and sends what is new, through the local mail system (/usr/sbin/sendmail -t -oi: cPanel
 * servers run Exim) and/or one https webhook (POST JSON, 5 s, no redirects):
 *   job              jobs/<id>/job.json of a switch (ols.cutover), return (ols.apache_return) or recovery (ols.rollback)
 *   held             active/summary.json: sites newly appearing in held_vhosts or hybrid_vhosts
 *   php_env          php-env.json: a PHP version newly failed
 *   upgrade          ols-cpanel-upgrade.service in the failed state
 *   cache_emergency  cache-clean.json: the last cleanup ran in emergency mode
 *   disk             the filesystems of the state directory and of the page cache below 5% free
 *   objcache         objcache.json: a WordPress site check newly in error
 *   schedule         schedule.json: a scheduled job that was missed or could not start
 * Bounds: the same event key at most once per six hours (DEDUPE_SECONDS; job, cache and upgrade events are one-shot for a week),
 * at most MAX_PER_DAY messages in any 24 hours, a failed delivery is retried on the next pass up to three times. Delivery is
 * tracked per channel: a message the e-mail took while the webhook failed counts against the daily allowance at once, and only
 * the webhook is tried again (`delivered`, `attempts` per key and channel). Events not subscribed to and events already sent are
 * set aside before the pass's bound of MAX_EVENTS, which takes the events of every kind in turn. State of what
 * was sent lives in `<state>/notify-ledger.json` (root 0600); the settings in notify.json (NotifySettings). A condition that
 * exists when notifications are first enabled is recorded, not announced. Nothing the notification contains comes from a
 * customer: names of sites and accounts, job results and counts only; the webhook URL appears nowhere in a message or a log.
 */
final class Notifier
{
    public const LEDGER = 'notify-ledger.json';
    public const LOCK = 'notify.lock';
    public const DEDUPE_SECONDS = 6 * 3600;
    public const ONCE_SECONDS = 8 * 86400;
    public const MAX_PER_DAY = 20;
    public const MAX_ATTEMPTS = 3;
    public const MAX_EVENTS = 100;
    public const RECENT = 20;
    public const SENDMAIL = '/usr/sbin/sendmail';
    public const DISK_FREE_PERCENT = 5;
    public const JOB_ACTIONS = ['ols.cutover' => 'Switch to OpenLiteSpeed', 'ols.apache_return' => 'Return to Apache', 'ols.rollback' => 'Configuration rollback'];
    private const MAX_NAMES = 8;

    /** @var \Closure():int */
    private \Closure $clock;
    /** @var \Closure(list<string>,string,string):?string */
    private \Closure $mailer;
    /** @var \Closure(string,array<string,mixed>):?string */
    private \Closure $webhook;
    /** @var \Closure(string):array{0:int,1:int} total and free bytes */
    private \Closure $disk;
    /** @var \Closure(list<string>):array{exit_code:int,stdout:string} */
    private \Closure $system;

    /**
     * @param (\Closure():int)|null $clock
     * @param (\Closure(list<string>,string,string):?string)|null $mailer recipients, subject, body: null on success, else the reason
     * @param (\Closure(string,array<string,mixed>):?string)|null $webhook url, payload: null on success, else the reason
     * @param (\Closure(string):array{0:int,1:int})|null $disk
     * @param (\Closure(list<string>):array{exit_code:int,stdout:string})|null $system
     */
    public function __construct(private readonly string $state, private readonly string $cacheRoot = '/var/lib/ols-cpanel/cache',
                                ?\Closure $clock = null, ?\Closure $mailer = null, ?\Closure $webhook = null, ?\Closure $disk = null,
                                ?\Closure $system = null, private readonly string $host = '')
    {
        $this->clock = $clock ?? static fn(): int => time();
        $this->mailer = $mailer ?? self::sendmail(...);
        $this->webhook = $webhook ?? self::post(...);
        $this->disk = $disk ?? static fn(string $p): array => [(int) (@disk_total_space($p) ?: 0), (int) (@disk_free_space($p) ?: 0)];
        $this->system = $system ?? static function (array $argv): array {
            $runner = new \OlsCpanel\Infrastructure\Process\LocalCommandRunner(1 << 16);
            return $runner->run('notify-system', $argv, 20);
        };
    }

    /** The settings and what was sent, for the WHM form. @return array<string,mixed> */
    public function status(): array
    {
        $now = ($this->clock)();
        $ledger = $this->ledger();
        $recent = array_values(array_filter($ledger['times'], static fn($t): bool => is_int($t) && $t > $now - 86400));
        return ['settings' => NotifySettings::load($this->state)->view(),
            'limits' => ['per_day' => self::MAX_PER_DAY, 'dedupe_hours' => self::DEDUPE_SECONDS / 3600],
            'sent_last_24h' => count($recent), 'last_run' => $ledger['last_run'], 'last_sent' => $ledger['last_sent'],
            'last_error' => $ledger['last_error'], 'recent' => $ledger['recent']];
    }

    /** One pass. @return array<string,mixed> */
    public function run(): array
    {
        $lock = @fopen($this->state . '/' . self::LOCK, 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['result' => 'busy'];
        }
        try {
            return $this->pass();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
            @chmod($this->state . '/' . self::LOCK, 0600);
        }
    }

    /** @return array<string,mixed> */
    private function pass(): array
    {
        $now = ($this->clock)();
        $settings = NotifySettings::load($this->state);
        if (!$settings->enabled()) {
            return ['result' => 'disabled', 'sent' => 0];
        }
        $ledger = $this->ledger();
        $ledger['last_run'] = $now;
        $times = array_values(array_filter($ledger['times'], static fn($t): bool => is_int($t) && $t > $now - 86400));
        $counts = ['sent' => 0, 'duplicate' => 0, 'deferred' => 0, 'failed' => 0];
        // Events not subscribed to, no-ops and those already sent are settled first, so they never take a place of the bound below
        // (a hundred consumed job events once hid every disk, upgrade, held and schedule alert).
        $fresh = [];
        foreach ($this->collect($settings, $ledger, $now) as $event) {
            if (($event['noop'] ?? false) === true || !$settings->wants($event['kind'])) {
                $this->commit($ledger, $event);
                continue;
            }
            $window = ($event['once'] ?? false) ? self::ONCE_SECONDS : self::DEDUPE_SECONDS;
            if (isset($ledger['sent'][$event['key']]) && $ledger['sent'][$event['key']] > $now - $window) {
                // A one-shot event that is still detected (a finished job stays on disk) is not worth a count.
                $counts['duplicate'] += ($event['once'] ?? false) ? 0 : 1;
                $this->commit($ledger, $event);
                continue;
            }
            $fresh[] = $event;
        }
        foreach (self::fair($fresh, self::MAX_EVENTS) as $event) {
            $key = $event['key'];
            $delivered = $ledger['delivered'][$key] ?? [];
            // A message already delivered on one channel was counted then; only a new message waits for the daily allowance.
            if ($delivered === [] && count($times) >= self::MAX_PER_DAY) {
                $counts['deferred']++;
                continue;
            }
            $results = $this->channels($settings, $event, $now, $delivered);
            $ok = array_keys(array_filter($results, static fn(?string $e): bool => $e === null));
            $errors = array_filter($results, static fn(?string $e): bool => $e !== null);
            if ($ok !== [] && $delivered === []) {
                $times[] = $now;
                $ledger['last_sent'] = $now;
            }
            $delivered = array_values(array_unique([...$delivered, ...$ok]));
            if ($errors === []) {
                $ledger['sent'][$key] = $now;
                unset($ledger['delivered'][$key], $ledger['attempts'][$key]);
                foreach (array_keys($results) as $channel) {
                    unset($ledger['attempts']["$key#$channel"]);
                }
                $this->remember($ledger, $event, $now, true);
                $this->commit($ledger, $event);
                $counts['sent']++;
                continue;
            }
            // Only the channels that failed are tried again on the next passes, each at most MAX_ATTEMPTS times.
            $ledger['last_error'] = ['time' => $now, 'message' => StateFile::clean(implode('; ', array_map(static fn($c, $e): string => "$c: $e",
                array_keys($errors), $errors)), 200)];
            $counts['failed']++;
            $exhausted = true;
            foreach (array_keys($errors) as $channel) {
                $attempts = ($ledger['attempts']["$key#$channel"] ?? 0) + 1;
                $ledger['attempts']["$key#$channel"] = $attempts;
                $exhausted = $exhausted && $attempts >= self::MAX_ATTEMPTS;
            }
            if ($delivered !== []) {
                $ledger['delivered'][$key] = $delivered;
            }
            if ($exhausted) {
                // Given up: the failure is recorded and the event is consumed (the WHM view shows the last error).
                $ledger['sent'][$key] = $now;
                unset($ledger['delivered'][$key]);
                foreach (array_keys($errors) as $channel) {
                    unset($ledger['attempts']["$key#$channel"]);
                }
                $this->remember($ledger, $event, $now, false);
                $this->commit($ledger, $event);
            }
        }
        $ledger['times'] = $times;
        $this->prune($ledger, $now);
        $this->saveLedger($ledger);
        return ['result' => 'ok'] + $counts;
    }

    /**
     * Sends a test message to every configured channel now (not counted against the daily limit, not deduplicated).
     * @return array<string,mixed>
     */
    public function test(): array
    {
        $settings = NotifySettings::load($this->state);
        if (!$settings->enabled()) {
            return ['result' => 'not-configured', 'channels' => []];
        }
        $now = ($this->clock)();
        $event = ['key' => 'test', 'kind' => 'test', 'severity' => 'info', 'title' => 'Test notification',
            'detail' => 'This is a test message from OLS-cPanel. Notifications are working.'];
        $channels = [];
        foreach ($this->channels($settings, $event, $now) as $name => $error) {
            $channels[] = ['channel' => $name, 'ok' => $error === null, 'error' => $error === null ? null : StateFile::clean($error, 200)];
        }
        $ok = array_filter($channels, static fn(array $c): bool => !$c['ok']) === [];
        return ['result' => $ok ? 'sent' : 'failed', 'channels' => $channels];
    }

    /**
     * Sends $event to every configured channel except those in $skip (already delivered on an earlier pass).
     * @param array<string,mixed> $event @param list<string> $skip @return array<string,?string> channel => error
     */
    private function channels(NotifySettings $settings, array $event, int $now, array $skip = []): array
    {
        $out = [];
        if ($settings->emails !== [] && !in_array('email', $skip, true)) {
            $out['email'] = ($this->mailer)($settings->emails, $this->subject($event), $this->body($event, $now));
        }
        if ($settings->webhook !== null && !in_array('webhook', $skip, true)) {
            $out['webhook'] = ($this->webhook)($settings->webhook, $this->payload($event, $now));
        }
        return $out;
    }

    /**
     * At most $max events, taken in turn from each kind (the first of every kind, then the second...), so that one source with
     * many events (a hundred finished jobs) cannot crowd out the others. @param list<array<string,mixed>> $events
     * @return list<array<string,mixed>>
     */
    private static function fair(array $events, int $max): array
    {
        $byKind = [];
        foreach ($events as $event) {
            $byKind[$event['kind']][] = $event;
        }
        $out = [];
        for ($i = 0; $byKind !== [] && count($out) < $max; $i++) {
            foreach ($byKind as $kind => $list) {
                if (!isset($list[$i])) {
                    unset($byKind[$kind]);
                } elseif (count($out) < $max) {
                    $out[] = $list[$i];
                }
            }
        }
        return $out;
    }

    /** @param array<string,mixed> $event */
    private function subject(array $event): string
    {
        return '[OLS-cPanel] ' . StateFile::clean($event['title'], 120);
    }

    /** @param array<string,mixed> $event */
    private function body(array $event, int $now): string
    {
        return implode("\n", ['OLS-cPanel notification', '', 'Event:    ' . StateFile::clean($event['title']),
            'Severity: ' . StateFile::clean($event['severity'], 20), 'Server:   ' . $this->hostname(),
            'Time:     ' . gmdate('Y-m-d H:i:s', $now) . ' UTC', '', StateFile::clean($event['detail'], 600), '',
            'Open WHM > OLS-cPanel for details. You receive this because notifications are enabled in OLS-cPanel for WHM.', '']);
    }

    /** @param array<string,mixed> $event @return array<string,mixed> */
    private function payload(array $event, int $now): array
    {
        return ['product' => 'ols-cpanel', 'server' => $this->hostname(), 'event' => $event['kind'], 'key' => $event['key'],
            'severity' => $event['severity'], 'title' => StateFile::clean($event['title']), 'detail' => StateFile::clean($event['detail'], 600),
            'time' => gmdate('c', $now)];
    }

    private function hostname(): string
    {
        return StateFile::clean($this->host !== '' ? $this->host : (string) gethostname(), 100);
    }

    // --- Event sources --------------------------------------------------------------------------------------------

    /**
     * @param array<string,mixed> $ledger
     * @return list<array<string,mixed>> events: key, kind, severity, title, detail, once?, observe? (kind => current items)
     */
    private function collect(NotifySettings $settings, array $ledger, int $now): array
    {
        $events = [];
        $watched = fn(string $kind): bool => $settings->wants($kind);
        // First enable of a watched kind: record what exists, announce nothing.
        $newly = function (string $kind, array $items) use (&$ledger): array {
            $items = array_values(array_unique(array_map('strval', $items)));
            sort($items, SORT_STRING);
            $known = $ledger['observed'][$kind] ?? null;
            return [$items, $known === null ? [] : array_values(array_diff($items, $known))];
        };
        // 1. jobs (not read at all when job notifications are off)
        foreach ($watched('job') ? array_slice(glob($this->state . '/jobs/j*/job.json') ?: [], -200) : [] as $file) {
            $job = StateFile::read($file);
            $action = $job['action'] ?? null;
            $finished = $job['finished'] ?? null;
            if (!is_array($job) || !is_string($action) || !isset(self::JOB_ACTIONS[$action]) || !in_array($job['state'] ?? null, ['done', 'failed'], true)
                || !is_int($finished) || $finished < $settings->enabledSince || $finished < $now - 7 * 86400
                || preg_match('/^j[0-9]{10}-[0-9a-f]{8}$/D', (string) ($job['job'] ?? '')) !== 1) {
                continue;
            }
            $failed = $job['state'] === 'failed';
            $reason = $failed ? ' Reason: ' . StateFile::clean($job['reason'] ?? ('exit code ' . StateFile::clean($job['exit_code'] ?? '?', 10)), 300) : '';
            $events[] = ['key' => 'job:' . $job['job'], 'kind' => 'job', 'once' => true, 'severity' => $failed ? 'error' : 'info',
                'title' => self::JOB_ACTIONS[$action] . ($failed ? ' failed' : ' finished'),
                'detail' => self::JOB_ACTIONS[$action] . ($failed ? ' failed.' : ' finished successfully.') . $reason . ' Job ' . $job['job'] . '.'];
        }
        // 2. held and hybrid-fallback sites of the active configuration
        $summary = StateFile::read($this->state . '/active/summary.json');
        if ($summary !== null) {
            $held = array_keys(is_array($summary['held_vhosts'] ?? null) ? $summary['held_vhosts'] : []);
            $hybrid = is_array($summary['hybrid_vhosts'] ?? null) ? $summary['hybrid_vhosts'] : [];
            [$all, $new] = $newly('held', array_filter([...$held, ...$hybrid], 'is_string'));
            if ($watched('held') && $new !== []) {
                $events[] = ['key' => 'held:' . substr(sha1(implode(',', $new)), 0, 16), 'kind' => 'held', 'severity' => 'warning', 'observe' => ['held' => $all],
                    'title' => count($new) . ' site(s) held back or served by Apache',
                    'detail' => 'The reconciler is holding or leaving on Apache: ' . $this->names($new) . '. See Compatibility in WHM for the reasons.'];
            } else {
                $events[] = ['key' => 'noop:held', 'kind' => 'held', 'noop' => true, 'observe' => ['held' => $all]];
            }
        }
        // 3. PHP environment failures
        $php = StateFile::read($this->state . '/php-env.json');
        if ($php !== null) {
            $failed = [];
            foreach (is_array($php['versions'] ?? null) ? $php['versions'] : [] as $version => $row) {
                if (is_array($row) && ($row['status'] ?? null) === 'failed' && preg_match('/^ea-php[0-9]{2,3}$/D', (string) $version) === 1) {
                    $failed[] = (string) $version;
                }
            }
            [$all, $new] = $newly('php_env', $failed);
            $events[] = $new !== [] ? ['key' => 'php_env:' . substr(sha1(implode(',', $new)), 0, 16), 'kind' => 'php_env', 'severity' => 'error',
                'observe' => ['php_env' => $all], 'title' => 'PHP environment check failed',
                'detail' => 'The PHP environment could not be completed for: ' . implode(', ', $new) . '. The automatic repair retries; see PHP in WHM.']
                : ['key' => 'noop:php_env', 'kind' => 'php_env', 'noop' => true, 'observe' => ['php_env' => $all]];
        }
        // 4. a failed upgrade unit
        if ($watched('upgrade')) {
            $unit = 'ols-cpanel-upgrade.service';
            $failed = ($this->system)(['/usr/bin/systemctl', 'is-failed', '--quiet', $unit])['exit_code'] === 0;
            if ($failed) {
                $when = StateFile::clean(trim(($this->system)(['/usr/bin/systemctl', 'show', '--property=ExecMainExitTimestamp', '--value', $unit])['stdout']), 60);
                $events[] = ['key' => 'upgrade:' . substr(sha1($when), 0, 16), 'kind' => 'upgrade', 'once' => true, 'severity' => 'error',
                    'title' => 'Upgrade failed', 'detail' => 'The automatic upgrade after a package update failed' . ($when !== '' ? " (last run: $when)" : '')
                    . '. The previous configuration keeps serving. See the journal of ' . $unit . '.'];
            }
        }
        // 5. cache emergency trim
        $clean = StateFile::read($this->state . '/cache-clean.json');
        if (is_array($clean) && ($clean['emergency'] ?? false) === true && is_int($clean['last_run'] ?? null) && $clean['last_run'] >= $now - 7 * 86400
            && $clean['last_run'] >= $settings->enabledSince) {
            $events[] = ['key' => 'cache:' . $clean['last_run'], 'kind' => 'cache_emergency', 'once' => true, 'severity' => 'warning',
                'title' => 'Page cache trimmed in an emergency',
                'detail' => 'The disk holding the page cache was nearly full, so the automatic cleanup halved the cache limits and removed pages.'];
        }
        // 6. disks
        $seen = [];
        foreach (['state' => $this->state, 'cache' => $this->cacheRoot] as $label => $path) {
            if (!is_dir($path)) {
                continue;
            }
            [$total, $free] = ($this->disk)($path);
            if ($total <= 0 || isset($seen["$total/$free"])) {
                continue;
            }
            $seen["$total/$free"] = true;
            if ($free * 100 < $total * self::DISK_FREE_PERCENT) {
                $events[] = ['key' => 'disk:' . $label, 'kind' => 'disk', 'severity' => 'error', 'title' => 'Disk nearly full',
                    'detail' => sprintf('The disk holding the %s has %.1f%% free space (%d MiB).', $label === 'state' ? 'product state' : 'page cache',
                        $free * 100 / $total, intdiv($free, 1 << 20))];
            }
        }
        // 7. object cache site checks
        $obj = StateFile::read($this->state . '/objcache.json');
        if ($obj !== null) {
            $bad = [];
            foreach (is_array($obj['wordpress'] ?? null) ? $obj['wordpress'] : [] as $user => $paths) {
                foreach (is_array($paths) ? $paths : [] as $dir => $row) {
                    if (is_array($row) && ($row['state'] ?? null) === 'error') {
                        $bad[] = (string) $user;
                    }
                }
            }
            [$all, $new] = $newly('objcache', array_unique($bad));
            $events[] = $new !== [] ? ['key' => 'objcache:' . substr(sha1(implode(',', $new)), 0, 16), 'kind' => 'objcache', 'severity' => 'warning',
                'observe' => ['objcache' => $all], 'title' => 'Object cache site check failed',
                'detail' => 'The object cache check reported an error for the accounts: ' . $this->names($new) . '.']
                : ['key' => 'noop:objcache', 'kind' => 'objcache', 'noop' => true, 'observe' => ['objcache' => $all]];
        }
        // 8. scheduled jobs that did not run
        $schedule = StateFile::read($this->state . '/' . Schedule::FILE);
        foreach (is_array($schedule['entries'] ?? null) ? $schedule['entries'] : [] as $entry) {
            if (is_array($entry) && in_array($entry['state'] ?? null, ['missed', 'refused'], true) && is_int($entry['updated'] ?? null)
                && $entry['updated'] >= $now - 7 * 86400 && $entry['updated'] >= $settings->enabledSince && is_string($entry['id'] ?? null)) {
                $events[] = ['key' => 'schedule:' . StateFile::clean($entry['id'], 40), 'kind' => 'schedule', 'once' => true, 'severity' => 'error',
                    'title' => 'Scheduled job ' . ($entry['state'] === 'missed' ? 'missed' : 'refused'),
                    'detail' => 'A scheduled ' . StateFile::clean($entry['action'] ?? '', 30) . ' did not run: ' . StateFile::clean($entry['note'] ?? '', 200)];
            }
        }
        return $events; // bounded by pass() after the settled events are set aside, fairly across kinds
    }

    /** @param list<string> $names */
    private function names(array $names): string
    {
        $shown = array_map(static fn(string $n): string => StateFile::clean($n, 80), array_slice($names, 0, self::MAX_NAMES));
        return implode(', ', $shown) . (count($names) > self::MAX_NAMES ? ' and ' . (count($names) - self::MAX_NAMES) . ' more' : '');
    }

    // --- Ledger ---------------------------------------------------------------------------------------------------

    /** @param array<string,mixed> $ledger @param array<string,mixed> $event */
    private function commit(array &$ledger, array $event): void
    {
        foreach ($event['observe'] ?? [] as $kind => $items) {
            $ledger['observed'][$kind] = $items;
        }
    }

    /** @param array<string,mixed> $ledger @param array<string,mixed> $event */
    private function remember(array &$ledger, array $event, int $now, bool $ok): void
    {
        array_unshift($ledger['recent'], ['time' => $now, 'kind' => $event['kind'], 'title' => StateFile::clean($event['title'], 120), 'ok' => $ok]);
        $ledger['recent'] = array_slice($ledger['recent'], 0, self::RECENT);
    }

    /** @param array<string,mixed> $ledger */
    private function prune(array &$ledger, int $now): void
    {
        $ledger['sent'] = array_filter($ledger['sent'], static fn($t): bool => is_int($t) && $t > $now - self::ONCE_SECONDS);
        $ledger['attempts'] = array_slice($ledger['attempts'], -200, null, true);
        $ledger['delivered'] = array_slice($ledger['delivered'], -200, null, true);
        foreach (array_keys($ledger['observed']) as $kind) {
            $ledger['observed'][$kind] = array_slice($ledger['observed'][$kind], 0, 2000);
        }
    }

    /** @return array{sent:array<string,int>,attempts:array<string,int>,delivered:array<string,list<string>>,times:list<int>,observed:array<string,list<string>>,recent:list<array<string,mixed>>,last_run:?int,last_sent:?int,last_error:?array<string,mixed>} */
    private function ledger(): array
    {
        $data = StateFile::read($this->state . '/' . self::LEDGER) ?? [];
        $map = static fn($v): array => is_array($v) ? $v : [];
        $observed = [];
        foreach ($map($data['observed'] ?? null) as $kind => $items) {
            if (is_string($kind) && is_array($items)) {
                $observed[$kind] = array_values(array_filter($items, 'is_string'));
            }
        }
        $error = $data['last_error'] ?? null;
        $delivered = [];
        foreach ($map($data['delivered'] ?? null) as $key => $channels) {
            if (is_string($key) && is_array($channels)) {
                $delivered[$key] = array_values(array_intersect($channels, ['email', 'webhook']));
            }
        }
        return ['sent' => array_filter($map($data['sent'] ?? null), 'is_int'), 'attempts' => array_filter($map($data['attempts'] ?? null), 'is_int'),
            'delivered' => $delivered,
            'times' => array_values(array_filter($map($data['times'] ?? null), 'is_int')), 'observed' => $observed,
            'recent' => array_values(array_filter($map($data['recent'] ?? null), 'is_array')),
            'last_run' => is_int($data['last_run'] ?? null) ? $data['last_run'] : null, 'last_sent' => is_int($data['last_sent'] ?? null) ? $data['last_sent'] : null,
            'last_error' => is_array($error) ? $error : null];
    }

    /** @param array<string,mixed> $ledger */
    private function saveLedger(array $ledger): void
    {
        StateFile::write($this->state . '/' . self::LEDGER, $ledger);
    }

    // --- Delivery -------------------------------------------------------------------------------------------------

    /**
     * The local MTA: `sendmail -t -oi` with the message on stdin (recipients are taken from the headers, which hold only addresses
     * that passed NotifySettings::validEmail). @param list<string> $to
     */
    public static function sendmail(array $to, string $subject, string $body): ?string
    {
        foreach ($to as $address) {
            if (!NotifySettings::validEmail($address)) {
                return 'invalid recipient';
            }
        }
        $subject = StateFile::clean($subject, 160);
        $message = 'To: ' . implode(', ', $to) . "\nSubject: $subject\nAuto-Submitted: auto-generated\nMIME-Version: 1.0\n"
            . "Content-Type: text/plain; charset=us-ascii\n\n" . str_replace("\r", '', $body);
        if (!is_executable(self::SENDMAIL)) {
            return 'no local mail system (' . self::SENDMAIL . ' is missing)';
        }
        $process = @proc_open([self::SENDMAIL, '-t', '-oi'], [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes, '/',
            ['PATH' => '/usr/sbin:/usr/bin:/bin', 'LANG' => 'C']);
        if (!is_resource($process)) {
            return 'the mail system could not be started';
        }
        fwrite($pipes[0], $message);
        fclose($pipes[0]);
        stream_set_blocking($pipes[2], false);
        $deadline = time() + 30;
        $error = '';
        while (true) {
            $status = proc_get_status($process);
            $error .= (string) fread($pipes[2], 4096);
            if (!$status['running']) {
                $code = $status['exitcode'];
                break;
            }
            if (time() > $deadline) {
                proc_terminate($process, 9);
                $code = -1;
                $error = 'timed out';
                break;
            }
            usleep(20000);
        }
        fclose($pipes[2]);
        proc_close($process);
        return $code === 0 ? null : 'the mail system refused the message: ' . StateFile::clean($error === '' ? "exit $code" : $error, 120);
    }

    /**
     * POST JSON to an https URL: 5 s, certificate verified, redirects not followed. The reason never contains the URL.
     * @param array<string,mixed> $payload
     */
    public static function post(string $url, array $payload): ?string
    {
        if (!NotifySettings::validWebhook($url)) {
            return 'invalid webhook';
        }
        $context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\nUser-Agent: ols-cpanel-notify\r\n",
            'content' => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), 'timeout' => 5.0, 'follow_location' => 0,
            'max_redirects' => 0, 'ignore_errors' => true], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $response = @file_get_contents($url, false, $context, 0, 4096);
        $line = $http_response_header[0] ?? '';
        if ($response === false && $line === '') {
            return 'the webhook did not answer';
        }
        if (preg_match('~^HTTP/\S+ (2[0-9]{2})~', (string) $line) === 1) {
            return null;
        }
        return 'the webhook answered ' . (preg_match('~^HTTP/\S+ ([0-9]{3})~', (string) $line, $m) === 1 ? $m[1] : 'with an error');
    }
}
