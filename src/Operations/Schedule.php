<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Cli\Refused;

/**
 * Maintenance windows (FV-07): the existing switch (ols.cutover) and return (ols.apache_return) jobs scheduled for a time window.
 * `<state>/schedule.json` (root 0600) holds the entries; `ols-cpanel schedule run`, started every minute by
 * ols-cpanel-schedule.timer (root), starts a due entry through the broker's own capability flow (cap.issue then cap.execute on the
 * admin socket), so the broker's checks, digests and audit records are the ones of a click in the Switch center:
 *  - ols.cutover: the entry stores the approved plan id and the plan digest the operator saw. At the time the broker compares it with
 *    the plan file; a plan that changed is refused (STALE) and the entry is marked refused, never run on a different plan.
 *  - ols.apache_return: the return takes the server's status digest, which changes with every account change, so it is read at the
 *    time; the return only runs while the server is switched (cut over) and is otherwise marked refused.
 * An entry that could not start within its window (the server was off, another job kept running) is marked missed and is never run
 * later. A busy broker is retried every minute inside the window. States: scheduled, running, done, failed, missed, refused, cancelled.
 * Every read-modify-write of schedule.json (add, cancel, each step of a pass) holds `schedule.lock` (flock, waiting at most
 * LOCK_WAIT_MS), so a cancel or an add is never overwritten by a pass that read the file earlier, and two adds never lose one.
 * The broker calls of a pass take seconds and run outside that lock: before them the pass claims the entry under the lock (state
 * running, `claimed`, note "starting") and saves it, so a cancel arriving meanwhile is refused as already started instead of being
 * silently undone; afterwards the pass re-reads the file and changes only the entry it claimed. Passes never overlap
 * (`schedule-run.lock`, not waited for). An entry still claimed when a pass starts belongs to a pass that died after its claim:
 * whether the broker started the job is unknown, so it is marked failed with a note to check the job list, never started twice.
 */
final class Schedule
{
    public const FILE = 'schedule.json';
    public const ACTIONS = ['ols.cutover' => 'plan', 'ols.apache_return' => 'server'];
    public const MIN_WINDOW = 15;
    public const MAX_WINDOW = 720;
    public const DEFAULT_WINDOW = 60;
    public const MAX_AHEAD = 90 * 86400;
    public const MAX_PENDING = 10;
    public const MAX_ENTRIES = 100;
    public const KEEP_SECONDS = 30 * 86400;
    public const LOCK = 'schedule.lock';
    public const RUN_LOCK = 'schedule-run.lock';
    public const LOCK_WAIT_MS = 5000;

    /** @var \Closure():int */
    private \Closure $clock;
    /** @var \Closure(string,?array<string,mixed>):array<string,mixed> */
    private \Closure $broker;

    /**
     * @param (\Closure():int)|null $clock
     * @param (\Closure(string,?array<string,mixed>):array<string,mixed>)|null $broker a call on the broker's admin socket
     */
    public function __construct(private readonly string $state, ?\Closure $clock = null, ?\Closure $broker = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
        $this->broker = $broker ?? static fn(string $op, ?array $args): array => (new \OlsCpanel\Broker\BrokerClient(
            \OlsCpanel\Broker\BrokerClient::ADMIN_SOCKET, 30.0))->call($op, $args);
    }

    /** @return list<array<string,mixed>> the entries, soonest first */
    public function entries(): array
    {
        $data = StateFile::read($this->state . '/' . self::FILE) ?? [];
        $entries = [];
        foreach (is_array($data['entries'] ?? null) ? $data['entries'] : [] as $row) {
            if (is_array($row) && is_string($row['id'] ?? null) && isset(self::ACTIONS[$row['action'] ?? '']) && is_int($row['at'] ?? null)
                && is_string($row['state'] ?? null)) {
                $entries[] = $row;
            }
        }
        usort($entries, static fn(array $a, array $b): int => $a['at'] <=> $b['at']);
        return $entries;
    }

    /** @return array<string,mixed> */
    public function view(): array
    {
        return ['now' => ($this->clock)(), 'entries' => array_map(static fn(array $e): array => array_intersect_key($e,
            array_flip(['id', 'action', 'scope', 'at', 'window_minutes', 'state', 'created', 'updated', 'job', 'note'])), $this->entries()),
            'limits' => ['window_minutes' => [self::MIN_WINDOW, self::MAX_WINDOW], 'default_window' => self::DEFAULT_WINDOW,
                'max_pending' => self::MAX_PENDING, 'max_days_ahead' => intdiv(self::MAX_AHEAD, 86400)]];
    }

    /** @param list<array<string,mixed>> $entries */
    private function save(array $entries): void
    {
        $now = ($this->clock)();
        $entries = array_values(array_filter($entries, static fn(array $e): bool => in_array($e['state'], ['scheduled', 'running'], true)
            || ($e['updated'] ?? $e['at']) > $now - self::KEEP_SECONDS));
        usort($entries, static fn(array $a, array $b): int => $a['at'] <=> $b['at']);
        StateFile::write($this->state . '/' . self::FILE, ['entries' => array_slice($entries, -self::MAX_ENTRIES)]);
    }

    /**
     * Adds an entry. The plan or status digest must be the one the operator saw (the broker checked it before calling this).
     * @return array<string,mixed> the new entry
     */
    public function add(string $action, string $scope, string $digest, int $at, int $window): array
    {
        $now = ($this->clock)();
        if (!isset(self::ACTIONS[$action])) {
            throw new Refused('only a switch to OpenLiteSpeed or a return to Apache can be scheduled');
        }
        $plan = self::ACTIONS[$action] === 'plan';
        if ($plan ? ($scope === 'server' || preg_match('/^[0-9A-Za-z_][0-9A-Za-z_-]{0,63}$/D', $scope) !== 1) : $scope !== 'server') {
            throw new Refused($plan ? 'a switch is scheduled for an approved plan id' : 'a return takes the scope "server"');
        }
        if (preg_match('/^[0-9a-f]{64}$/D', $digest) !== 1) {
            throw new Refused('invalid digest');
        }
        if ($at < $now + 60 || $at > $now + self::MAX_AHEAD) {
            throw new Refused('the start time must be between one minute and ' . intdiv(self::MAX_AHEAD, 86400) . ' days from now');
        }
        if ($window < self::MIN_WINDOW || $window > self::MAX_WINDOW) {
            throw new Refused('the window must be ' . self::MIN_WINDOW . ' to ' . self::MAX_WINDOW . ' minutes');
        }
        return $this->locked(fn(): array => $this->append($action, $scope, $digest, $at, $window, $now));
    }

    /** The read-modify-write of add(), under the lock. @return array<string,mixed> */
    private function append(string $action, string $scope, string $digest, int $at, int $window, int $now): array
    {
        $entries = $this->entries();
        if (count(array_filter($entries, static fn(array $e): bool => $e['state'] === 'scheduled')) >= self::MAX_PENDING) {
            throw new Refused('at most ' . self::MAX_PENDING . ' scheduled jobs; cancel one first');
        }
        foreach ($entries as $e) {
            if ($e['state'] === 'scheduled' && $e['action'] === $action && $e['scope'] === $scope && abs($e['at'] - $at) < 60) {
                throw new Refused('the same job is already scheduled for that time');
            }
        }
        $entry = ['id' => 's' . gmdate('YmdHis', $now) . '-' . bin2hex(random_bytes(3)), 'action' => $action, 'scope' => $scope, 'digest' => $digest,
            'at' => $at, 'window_minutes' => $window, 'state' => 'scheduled', 'created' => $now, 'updated' => $now, 'job' => null, 'note' => null];
        $entries[] = $entry;
        $this->save($entries);
        return $entry;
    }

    public function cancel(string $id): void
    {
        $this->locked(function () use ($id): void {
            $entries = $this->entries();
            foreach ($entries as $i => $e) {
                if ($e['id'] === $id) {
                    if ($e['state'] === 'running') {
                        throw new Refused('the job has already started and can no longer be cancelled');
                    }
                    if ($e['state'] !== 'scheduled') {
                        throw new Refused('only a scheduled job that has not started can be cancelled');
                    }
                    $entries[$i]['state'] = 'cancelled';
                    $entries[$i]['updated'] = ($this->clock)();
                    $entries[$i]['note'] = 'cancelled by the operator';
                    $this->save($entries);
                    return;
                }
            }
            throw new Refused('no such scheduled job');
        });
    }

    /** One pass of the timer. @return array<string,mixed> */
    public function run(): array
    {
        $lock = @fopen($this->state . '/' . self::RUN_LOCK, 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['result' => 'busy', 'started' => 0];
        }
        try {
            return $this->pass();
        } catch (Refused) {
            return ['result' => 'busy', 'started' => 0]; // schedule.lock was not free in time: the next minute tries again
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
            @chmod($this->state . '/' . self::RUN_LOCK, 0600);
        }
    }

    /**
     * Runs $fn holding schedule.lock, waiting at most LOCK_WAIT_MS for it (a pass holds it only between its broker calls).
     * @template T @param \Closure():T $fn @return T
     */
    private function locked(\Closure $fn): mixed
    {
        $path = $this->state . '/' . self::LOCK;
        $lock = @fopen($path, 'c');
        if ($lock === false) {
            throw new \RuntimeException('cannot open ' . self::LOCK);
        }
        @chmod($path, 0600);
        try {
            $deadline = microtime(true) + self::LOCK_WAIT_MS / 1000;
            while (!flock($lock, LOCK_EX | LOCK_NB)) {
                if (microtime(true) >= $deadline) {
                    throw new Refused('the schedule is being changed right now; try again in a moment');
                }
                usleep(20000);
            }
            try {
                return $fn();
            } finally {
                flock($lock, LOCK_UN);
            }
        } finally {
            fclose($lock);
        }
    }

    /**
     * Under the lock: $change applied to the entry $id as it is now, and saved (a pass's step after broker calls that ran unlocked).
     * @param \Closure(array<string,mixed>):?array<string,mixed> $change the changed entry, or null to leave it as it is
     */
    private function update(string $id, \Closure $change): void
    {
        $this->locked(function () use ($id, $change): void {
            $entries = $this->entries();
            foreach ($entries as $i => $e) {
                if ($e['id'] === $id) {
                    $next = $change($e);
                    if ($next !== null) {
                        $entries[$i] = $next;
                        $this->save($entries);
                    }
                    return;
                }
            }
        });
    }

    /** @return array<string,mixed> */
    private function pass(): array
    {
        $now = ($this->clock)();
        $set = static fn(array $e, string $state, ?string $note, ?string $job = null): array => array_merge($e,
            ['state' => $state, 'note' => $note, 'updated' => $now, 'claimed' => false], $job !== null ? ['job' => $job] : []);
        // Under the lock and without the broker: windows that ended, and claims left by a pass that died after claiming.
        $this->locked(function () use ($now, $set): void {
            $entries = $this->entries();
            $changed = false;
            foreach ($entries as $i => $e) {
                if ($e['state'] === 'running' && ($e['claimed'] ?? false) === true) {
                    $entries[$i] = $set($e, 'failed', 'the scheduler stopped while starting the job; check the job list before scheduling it again');
                    $changed = true;
                } elseif ($e['state'] === 'scheduled' && $e['at'] <= $now && $now > $e['at'] + ($e['window_minutes'] ?? self::DEFAULT_WINDOW) * 60) {
                    $entries[$i] = $set($e, 'missed', 'the window ended before the job could start');
                    $changed = true;
                }
            }
            if ($changed) {
                $this->save($entries);
            }
        });
        // Started jobs: their state is asked for unlocked and written only while the entry still follows that job.
        foreach ($this->entries() as $e) {
            if ($e['state'] !== 'running' || ($e['claimed'] ?? false) === true || !is_string($e['job'] ?? null)) {
                continue;
            }
            $reply = ($this->broker)('job.status', ['job' => $e['job']]);
            $state = $reply['result']['state'] ?? null;
            $next = null;
            if (($reply['ok'] ?? false) && $state === 'done') {
                $next = ['done', 'the job finished'];
            } elseif (($reply['ok'] ?? false) && $state === 'failed') {
                $next = ['failed', 'the job failed: ' . StateFile::clean($reply['result']['reason'] ?? 'see the job', 160)];
            } elseif (!($reply['ok'] ?? false) && ($reply['error']['code'] ?? '') === 'NOT_FOUND') {
                $next = ['failed', 'the job record is gone'];
            }
            if ($next !== null) {
                $job = $e['job'];
                $this->update($e['id'], static fn(array $cur): ?array => $cur['state'] === 'running' && ($cur['job'] ?? null) === $job
                    ? $set($cur, $next[0], $next[1]) : null);
            }
        }
        // Due entries, one job at a time: each is claimed under the lock before its broker calls, then settled under the lock.
        $started = 0;
        $tried = [];
        while (($claimed = $this->claim($now, $tried)) !== null) {
            $tried[$claimed['id']] = true;
            [$state, $note, $job, $busy] = $this->start($claimed);
            $this->update($claimed['id'], static fn(array $cur): ?array => $cur['state'] !== 'running' || ($cur['claimed'] ?? false) !== true ? null
                : ($state === 'scheduled' ? array_merge($cur, ['state' => 'scheduled', 'note' => $note, 'claimed' => false]) : $set($cur, $state, $note, $job)));
            if ($state === 'running') {
                $started++;
                break; // one job at a time
            }
            if ($busy) {
                break; // the broker runs another job: the next minute tries again inside the window
            }
        }
        return ['result' => 'ok', 'started' => $started];
    }

    /**
     * Under the lock: the first due entry not yet tried in this pass, marked running and claimed and saved before the broker is
     * called, so that a cancel cannot take it from under the start. @param array<string,true> $tried @return array<string,mixed>|null
     */
    private function claim(int $now, array $tried): ?array
    {
        return $this->locked(function () use ($now, $tried): ?array {
            $entries = $this->entries();
            foreach ($entries as $i => $e) {
                if ($e['state'] === 'scheduled' && $e['at'] <= $now && !isset($tried[$e['id']])
                    && $now <= $e['at'] + ($e['window_minutes'] ?? self::DEFAULT_WINDOW) * 60) {
                    $entries[$i] = array_merge($e, ['state' => 'running', 'claimed' => true, 'note' => 'starting', 'updated' => $now]);
                    $this->save($entries);
                    return $entries[$i];
                }
            }
            return null;
        });
    }

    /**
     * The broker calls that start a claimed entry (unlocked). @param array<string,mixed> $e
     * @return array{0:string,1:?string,2:?string,3:bool} the new state (scheduled again when the broker is busy or not answering),
     *         the note, the job id and whether the broker was busy with another job
     */
    private function start(array $e): array
    {
        $retry = 'the service did not answer; trying again inside the window';
        $digest = $e['digest'];
        if (self::ACTIONS[$e['action']] === 'server') {
            $status = ($this->broker)('server.status', null);
            if (!($status['ok'] ?? false) || !is_string($status['result']['digest'] ?? null)) {
                return ['scheduled', $retry, null, false];
            }
            if (($status['result']['cut_over'] ?? null) !== true) {
                return ['refused', 'the server is not switched to OpenLiteSpeed, so there is nothing to return', null, false];
            }
            $digest = $status['result']['digest'];
        }
        $capability = ['principal' => 'root', 'action' => $e['action'], 'scope' => $e['scope'], 'digest' => $digest];
        $issued = ($this->broker)('cap.issue', $capability);
        $token = $issued['result']['token'] ?? null;
        if (!($issued['ok'] ?? false) || !is_string($token)) {
            return ['refused', 'the broker refused the job: ' . StateFile::clean($issued['error']['message'] ?? 'no answer', 160), null, false];
        }
        $done = ($this->broker)('cap.execute', ['token' => $token, 'action' => $e['action'], 'scope' => $e['scope'], 'digest' => $digest]);
        if ($done['ok'] ?? false) {
            $job = $done['result']['job'] ?? null;
            return ['running', 'started', is_string($job) ? $job : null, false];
        }
        $code = $done['error']['code'] ?? '';
        if ($code === 'BUSY') {
            return ['scheduled', 'another job is running; trying again inside the window', null, true];
        }
        if ($code === 'BROKER_UNAVAILABLE') {
            return ['scheduled', $retry, null, false];
        }
        return ['refused', $code === 'STALE' ? 'the plan changed after it was approved; plan and schedule again'
            : 'the broker refused the job: ' . StateFile::clean($done['error']['message'] ?? $code, 160), null, false];
    }
}
