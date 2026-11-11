<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Events\HookEntry;

/**
 * Demand-based PHP children per account (RV-53), automatic and without any operator input.
 *
 * Every lsphp group used to get PHP_LSAPI_CHILDREN=5 (PhpLimits::BUILTIN) whatever the account does, while OpenLiteSpeed's
 * stderr log filled with "Reached max children process limit: 5 ... busy: 6" for the busy ones and the server had CPU and
 * memory to spare. This class counts those lines per account and keeps a small state file, /var/lib/ols-cpanel/php-demand.json
 * (root 0644, written atomically), that PhpLimits reads at compile time as an input (so the compile stays deterministic and
 * the Reconciler's InputDigest covers it): the file records, per account, the last time the limit was reached and the
 * current raised value.
 *
 * The scan is run by `php env sync` (ols-cpanel-php.service, root, every 5 minutes) and reads the stderr log from where
 * the previous scan stopped (inode and offset in the file; a rotated or truncated log starts again at 0; at most MAX_READ
 * bytes per scan). A line names its account either by the extprocessor ("<user>-php") or by "[UID:<n>]" (the LSAPI
 * library's own prefix), resolved through the passwd database; a line that names nobody is counted as unattributed and
 * changes nothing.
 *
 * Algorithm (STEPS 5 -> 8 -> 12, never above 12):
 *  - a line whose logged limit is at least the account's current value is a "hit at the limit"; lines logged by an lsphp
 *    that still runs with an older, lower limit only keep the account marked as busy (a graceful reload keeps detached
 *    lsphp processes), so one raise never triggers the next;
 *  - RAISE_HITS hit(s) at the limit move the account one step up, the busiest account first, while the extra children of
 *    all accounts (60 MB each, EXTRA_MB) stay within 25% of MemTotal (BUDGET_PERCENT); an account that does not fit is
 *    marked "budget" and keeps its value;
 *  - after DECAY_SECONDS (7 days) without any hit an account steps one step down, and again after every further 7 days,
 *    until it is back at the built-in value and its entry is dropped.
 * Lines older than DECAY_SECONDS are ignored, and an account's last hit is the time written in its log line.
 *
 * Precedence: an operator's explicit value in php-limits.json (an account's own, or "defaults") always wins over the
 * automatic one (PhpLimits). Without the file, or with an unreadable one, nothing changes from the built-in limits.
 */
final class PhpDemand
{
    public const PATH = '/var/lib/ols-cpanel/php-demand.json';
    public const LOG = '/usr/local/lsws/logs/stderr.log';
    public const MEMINFO = '/proc/meminfo';
    /** Children per step; the first is the built-in value, the last the ceiling. */
    public const STEPS = [5, 8, 12];
    public const EXTRA_MB = 60;
    public const BUDGET_PERCENT = 25;
    /** The first wait raises (RV-62: with three, a morning burst waited five minutes at 3 s per page before the raise). */
    public const RAISE_HITS = 1;
    public const DECAY_SECONDS = 604800;
    public const MAX_READ = 8388608;
    private const ACCOUNT = '/^[a-z][a-z0-9_-]{0,31}$/D';
    private const LINE = '/^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)?.*Reached max children process limit: (\d+)/';

    /**
     * @param array<string,array{children:int, hits:int, waits:int, last_hit:int, raised_at:int, decayed_at:int, budget:bool}> $accounts
     * @param array{inode:int, offset:int}|null $log where the previous scan stopped
     */
    private function __construct(private array $accounts = [], private ?array $log = null, private int $updated = 0)
    {
    }

    public static function empty(): self
    {
        return new self();
    }

    /**
     * The state at $path. Lenient by design: the compile must never fail because of this file, so an absent, foreign
     * (not root's, or writable by others), oversized or malformed file is "no automatic limits", and an entry with an
     * impossible value is dropped.
     */
    public static function load(string $path = self::PATH): self
    {
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || ($stat['mode'] & 0022) !== 0 || $stat['size'] > PhpLimits::MAX_BYTES * 4) {
            return new self();
        }
        $euid = function_exists('posix_geteuid') ? posix_geteuid() : 0;
        if (!in_array($stat['uid'], [0, $euid], true)) {
            return new self();
        }
        $text = @file_get_contents($path);
        $data = is_string($text) ? json_decode($text, true, 6) : null;
        if (!is_array($data) || ($data['version'] ?? null) !== 1 || !is_array($data['accounts'] ?? null)) {
            return new self();
        }
        $accounts = [];
        foreach ($data['accounts'] as $user => $row) {
            if (!is_string($user) || preg_match(self::ACCOUNT, $user) !== 1 || !is_array($row) || !in_array($row['children'] ?? null, self::STEPS, true)) {
                continue;
            }
            $number = static fn(string $key): int => is_int($row[$key] ?? null) && $row[$key] >= 0 ? $row[$key] : 0;
            $accounts[$user] = ['children' => $row['children'], 'hits' => $number('hits'), 'waits' => $number('waits'), 'last_hit' => $number('last_hit'),
                'raised_at' => $number('raised_at'), 'decayed_at' => $number('decayed_at'), 'budget' => ($row['budget'] ?? false) === true];
        }
        $log = $data['log'] ?? null;
        $log = is_array($log) && is_int($log['inode'] ?? null) && is_int($log['offset'] ?? null) && $log['offset'] >= 0
            ? ['inode' => $log['inode'], 'offset' => $log['offset']] : null;
        return new self($accounts, $log, is_int($data['updated'] ?? null) ? $data['updated'] : 0);
    }

    /**
     * The automatic children per account that differ from the built-in value: what PhpLimits applies.
     * @return array<string,int>
     */
    public function children(): array
    {
        $out = [];
        foreach ($this->accounts as $user => $row) {
            if ($row['children'] > self::STEPS[0]) {
                $out[$user] = $row['children'];
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /**
     * Per account for `php status` and the WHM view: the value, why, and when.
     * @return array<string,array<string,mixed>>
     */
    public function describe(): array
    {
        $out = [];
        $accounts = $this->accounts;
        ksort($accounts, SORT_STRING);
        foreach ($accounts as $user => $row) {
            if ($row['children'] === self::STEPS[0] && $row['waits'] === 0) {
                continue;
            }
            $reason = $row['children'] > self::STEPS[0]
                ? "OpenLiteSpeed reported the limit reached {$row['waits']} times; raised from " . $this->before($row['children']) . ' to ' . $row['children']
                    . ' children and lowered again one step after ' . intdiv(self::DECAY_SECONDS, 86400) . ' days without a report'
                : "OpenLiteSpeed reported the limit reached {$row['waits']} times; not enough yet to raise it";
            if ($row['budget']) {
                $reason .= '; the next step does not fit the memory budget of ' . self::BUDGET_PERCENT . '% of the server memory';
            }
            $out[$user] = ['children' => $row['children'], 'reason' => $reason, 'waits' => $row['waits'], 'last_hit' => $row['last_hit'] ?: null,
                'raised_at' => $row['raised_at'] ?: null, 'budget_limited' => $row['budget']];
        }
        return $out;
    }

    /**
     * Counts the new "Reached max children" lines of the stderr log, applies them (raise and decay) and writes the state.
     * Never throws for a missing or unreadable log (the result says so); a state that cannot be written is reported too.
     * @param (\Closure(int):?string)|null $account passwd lookup: uid => account name (default posix_getpwuid)
     * @return array<string,mixed> what the scan did, for the `php env sync` output
     */
    public static function scan(string $statePath = self::PATH, string $logPath = self::LOG, string $meminfo = self::MEMINFO,
                                ?int $now = null, ?\Closure $account = null): array
    {
        $now ??= time();
        $account ??= static function (int $uid): ?string {
            $entry = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
            return is_array($entry) ? $entry['name'] : null;
        };
        $lock = @fopen($statePath . '.lock', 'c');
        if ($lock === false) {
            return ['result' => 'unavailable', 'error' => 'cannot open ' . $statePath . '.lock'];
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            return ['result' => 'busy'];
        }
        try {
            $state = self::load($statePath);
            $reports = [];
            $report = ['result' => 'scanned', 'lines' => 0, 'unattributed' => 0];
            $state->log = self::read($state->log, $logPath, $now, $account, $reports, $report);
            $report += $state->apply($reports, $now, self::memoryBytes($meminfo));
            $state->updated = $now;
            try {
                HookEntry::writeDurable($statePath, $state->json(), 0644);
            } catch (\Throwable $error) {
                $report['result'] = 'not_written';
                $report['error'] = substr($error->getMessage(), 0, 200);
            }
            return $report;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * The pure step: the reports of one scan (account, the limit the reporting lsphp ran with, the time of the line) into
     * raises, the budget and decay.
     * @param list<array{user:string, limit:int, time:int}> $reports
     * @return array{raised:list<string>, decayed:list<string>, budget_limited:list<string>, extra_mb:int, budget_mb:int}
     */
    public function apply(array $reports, int $now, int $memTotalBytes): array
    {
        foreach ($reports as $report) {
            $user = $report['user'];
            $row = $this->accounts[$user] ?? ['children' => self::STEPS[0], 'hits' => 0, 'waits' => 0, 'last_hit' => 0, 'raised_at' => 0,
                'decayed_at' => 0, 'budget' => false];
            ++$row['waits'];
            // A hit at the limit: the lsphp ran with the account's current value or more (an older, lower limit only marks it busy).
            $row['hits'] += $report['limit'] >= $row['children'] ? 1 : 0;
            $row['last_hit'] = max($row['last_hit'], $report['time']);
            $this->accounts[$user] = $row;
        }
        $decayed = [];
        foreach ($this->accounts as $user => $row) {
            if ($now - max($row['last_hit'], $row['raised_at'], $row['decayed_at']) < self::DECAY_SECONDS) {
                continue;
            }
            if ($row['children'] > self::STEPS[0]) {
                $this->accounts[$user]['children'] = self::STEPS[array_search($row['children'], self::STEPS, true) - 1];
                $this->accounts[$user]['decayed_at'] = $now;
                $this->accounts[$user]['hits'] = 0;
                $this->accounts[$user]['budget'] = false;
                $decayed[] = $user;
            } else {
                unset($this->accounts[$user]);  // idle at the built-in value: nothing to remember
            }
        }
        $budget = intdiv($memTotalBytes * self::BUDGET_PERCENT, 100);
        $candidates = array_filter($this->accounts, static fn(array $row): bool => $row['hits'] >= self::RAISE_HITS && $row['children'] < self::STEPS[count(self::STEPS) - 1]);
        uksort($candidates, fn(string $a, string $b): int => [$this->accounts[$b]['hits'], $a] <=> [$this->accounts[$a]['hits'], $b]);
        $raised = $limited = [];
        foreach (array_keys($candidates) as $user) {
            $row = $this->accounts[$user];
            $next = self::STEPS[array_search($row['children'], self::STEPS, true) + 1];
            if (($this->extraBytes() + ($next - $row['children']) * self::EXTRA_MB * 1048576) <= $budget) {
                $this->accounts[$user]['children'] = $next;
                $this->accounts[$user]['hits'] = 0;
                $this->accounts[$user]['raised_at'] = $now;
                $this->accounts[$user]['budget'] = false;
                $raised[] = $user;
            } else {
                $this->accounts[$user]['budget'] = true;
                $limited[] = $user;
            }
        }
        ksort($this->accounts, SORT_STRING);
        return ['raised' => $raised, 'decayed' => $decayed, 'budget_limited' => $limited, 'extra_mb' => intdiv($this->extraBytes(), 1048576),
            'budget_mb' => intdiv($budget, 1048576)];
    }

    /** @return int the memory the automatic extra children of every account may use, in bytes */
    private function extraBytes(): int
    {
        $extra = 0;
        foreach ($this->accounts as $row) {
            $extra += ($row['children'] - self::STEPS[0]) * self::EXTRA_MB * 1048576;
        }
        return $extra;
    }

    private function before(int $children): int
    {
        return self::STEPS[array_search($children, self::STEPS, true) - 1] ?? self::STEPS[0];
    }

    private function json(): string
    {
        return json_encode(['version' => 1, 'updated' => $this->updated, 'log' => $this->log, 'accounts' => (object) $this->accounts],
            JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
    }

    /**
     * @param array{inode:int, offset:int}|null $from
     * @param list<array{user:string, limit:int, time:int}> $reports
     * @param array<string,mixed> $report
     * @return array{inode:int, offset:int}|null the position after the last complete line read
     */
    private static function read(?array $from, string $logPath, int $now, \Closure $account, array &$reports, array &$report): ?array
    {
        $stat = @stat($logPath);
        if ($stat === false) {
            $report['log'] = 'absent';
            return $from;
        }
        $offset = $from !== null && $from['inode'] === $stat['ino'] && $from['offset'] <= $stat['size'] ? $from['offset'] : 0;
        $handle = @fopen($logPath, 'rb');
        if ($handle === false || fseek($handle, $offset) !== 0) {
            $report['log'] = 'unreadable';
            return $from;
        }
        $text = (string) stream_get_contents($handle, self::MAX_READ);
        fclose($handle);
        $end = strrpos($text, "\n");
        $text = $end === false ? '' : substr($text, 0, $end + 1);
        $position = ['inode' => $stat['ino'], 'offset' => $offset + strlen($text)];
        foreach (explode("\n", $text) as $line) {
            if (!str_contains($line, 'Reached max children process limit') || preg_match(self::LINE, $line, $m) !== 1) {
                continue;
            }
            ++$report['lines'];
            $time = $m[1] !== '' ? (int) strtotime($m[1]) : $now;
            if ($time < $now - self::DECAY_SECONDS) {
                continue;
            }
            $user = null;
            if (preg_match('/\b([a-z][a-z0-9_-]{0,31})-php\b/', $line, $name) === 1) {
                $user = $name[1];
            } elseif (preg_match('/\[UID:(\d+)\]/', $line, $uid) === 1) {
                $user = $account((int) $uid[1]);
            }
            if ($user === null || preg_match(self::ACCOUNT, $user) !== 1 || in_array($user, ['root', 'nobody'], true)) {
                ++$report['unattributed'];
                continue;
            }
            $reports[] = ['user' => $user, 'limit' => (int) $m[2], 'time' => $time];
        }
        $report['read_bytes'] = strlen($text);
        $report['accounts'] = count(array_unique(array_column($reports, 'user')));
        return $position;
    }

    private static function memoryBytes(string $meminfo): int
    {
        $text = @file_get_contents($meminfo);
        return is_string($text) && preg_match('/^MemTotal:\s+(\d+)\s+kB/m', $text, $m) === 1 ? (int) $m[1] * 1024 : 0;
    }
}
