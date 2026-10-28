<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * `php restart (--all | --account=U)`: ends the lsphp processes (process name `lsphp`) of one account or of every
 * account so OLS starts new ones that read the current PHP extensions and INI files. A graceful OLS reload keeps
 * detached lsphp processes, so this is what a PHP package or INI change needs.
 *
 * The original cohort is captured first: every matching pid together with its start time (field 22 of
 * /proc/<pid>/stat, in clock ticks since boot). Only that cohort is signalled and waited for: SIGTERM, then
 * SIGKILL for the members still alive after a few seconds. A member counts as the same process only while its
 * pid still has the recorded start time (a reused pid is a different process); a zombie counts as gone. The
 * replacement processes OLS starts while this runs are never touched, so the restart reports success when
 * the original cohort is gone, however busy the account is. A named account must be a known system account
 * with a cPanel-range uid (never root or another system user).
 */
final class PhpRestart
{
    public const PROCESS = 'lsphp';
    public const MIN_UID = 500;
    public const ACCOUNT = '/^[a-z][a-z0-9_-]{0,31}$/D';
    private const PGREP = '/usr/bin/pgrep';
    private const CAT = '/usr/bin/cat';
    private const KILL = '/usr/bin/kill';

    public function __construct(private Environment $env)
    {
    }

    /** @return array<string,mixed> */
    public function run(?string $account): array
    {
        $this->env->requireRoot();
        $host = $this->env->host;
        $filter = [];
        if ($account !== null) {
            if (preg_match(self::ACCOUNT, $account) !== 1) {
                throw DeploymentError::refused('invalid account name');
            }
            $uid = $host->run('account-uid', ['/usr/bin/id', '-u', $account]);
            $number = trim($uid['stdout']);
            if ($uid['exit_code'] !== 0 || preg_match('/^\d{1,10}$/D', $number) !== 1 || (int) $number < self::MIN_UID) {
                throw DeploymentError::refused("unknown account $account");
            }
            $filter = ['-u', $account];
        }
        $cohort = $this->capture($filter);
        $found = count($cohort);
        $left = 0;
        if ($found > 0) {
            $this->signal('TERM', $cohort);
            $host->waitFor(fn(): bool => $this->alive($cohort, 'lsphp-after-term') === [], 5, 1.0);
            $survivors = $this->alive($cohort, 'lsphp-left');
            $left = count($survivors);
            if ($left > 0) {
                $this->signal('KILL', $survivors);
                $host->waitFor(fn(): bool => $this->alive($survivors, 'lsphp-after-kill') === [], 3, 1.0);
            }
        }
        $remaining = $found > 0 ? count($this->alive($cohort, 'lsphp-remaining')) : 0;
        return ['result' => $remaining === 0 ? 'restarted' : 'failed', 'scope' => $account === null ? 'all' : 'account',
            'account' => $account, 'process' => self::PROCESS, 'found' => $found, 'killed' => max(0, $found - $remaining),
            'killed_with_sigkill' => $left, 'remaining' => $remaining,
            'note' => 'Only the processes present when the restart began were ended; OLS starts new lsphp processes on the next PHP request.'];
    }

    /**
     * @param list<string> $filter
     * @return array<int,string> pid => start time of the processes present now
     */
    private function capture(array $filter): array
    {
        $record = $this->env->host->run('lsphp-before', [self::PGREP, ...$filter, '-x', self::PROCESS]);
        // pgrep exits 1 when nothing matches; anything above is its own failure.
        if ($record['exit_code'] > 1) {
            throw DeploymentError::step('lsphp-before', 'pgrep failed (exit ' . $record['exit_code'] . ') ' . Host::tail($record['stderr'] ?? ''));
        }
        $cohort = [];
        foreach ($record['exit_code'] === 0 ? explode("\n", trim($record['stdout'])) : [] as $line) {
            if (preg_match('/^\d{1,9}$/D', trim($line)) !== 1) {
                throw DeploymentError::step('lsphp-before', 'unexpected pgrep output');
            }
            $start = $this->startTime((int) trim($line), 'lsphp-start');
            if ($start !== null) {
                $cohort[(int) trim($line)] = $start;
            }
        }
        return $cohort;
    }

    /** Start time (field 22 of /proc/PID/stat) of a live, non-zombie process; null when it is gone or a zombie. */
    private function startTime(int $pid, string $name): ?string
    {
        $record = $this->env->host->run($name, [self::CAT, "/proc/$pid/stat"]);
        if ($record['exit_code'] !== 0) {
            return null;
        }
        $close = strrpos($record['stdout'], ')');  // the command name may hold spaces and parentheses
        if ($close === false) {
            return null;
        }
        $fields = explode(' ', trim(substr($record['stdout'], $close + 1)));
        // $fields[0] is field 3 (state), so field 22 is index 19.
        if (!isset($fields[19]) || preg_match('/^\d+$/D', $fields[19]) !== 1 || $fields[0] === 'Z' || $fields[0] === 'X') {
            return null;
        }
        return $fields[19];
    }

    /**
     * @param array<int,string> $cohort
     * @return array<int,string> the members that are still the same live process
     */
    private function alive(array $cohort, string $name): array
    {
        $alive = [];
        foreach ($cohort as $pid => $start) {
            if ($this->startTime($pid, $name) === $start) {
                $alive[$pid] = $start;
            }
        }
        return $alive;
    }

    /** @param array<int,string> $cohort */
    private function signal(string $signal, array $cohort): void
    {
        foreach ($cohort as $pid => $start) {
            // Re-checked right before the signal: a pid that now has another start time is not ours to end.
            if ($this->startTime($pid, 'lsphp-recheck') === $start) {
                $this->env->host->run('lsphp-' . strtolower($signal), [self::KILL, "-$signal", '--', (string) $pid]);
            }
        }
    }
}
