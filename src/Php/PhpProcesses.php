<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * Live view of the lsphp processes per account and runaway detection (FV-03). One fixed `ps` argv, parsed
 * strictly; nothing here signals a process. An account's lsphp family is one parent (started by OLS) and its
 * LSAPI children (parent pid = an lsphp pid).
 *
 * A process is a runaway when it is a child or parent that has existed at least `min_age_seconds` and its
 * cumulative CPU time is at least `cpu_seconds` (reason "cpu") or its resident memory is at least `rss_mb`
 * (reason "rss"). A command run has no memory of earlier samples, so "for longer than N seconds" is the
 * process age, which is what makes a long-lived worker that keeps burning CPU or holding memory stand out
 * from a fresh one handling a heavy request. Thresholds come from PhpLimits (runaway).
 */
final class PhpProcesses
{
    public const PS = '/usr/bin/ps';
    public const PROCESS = 'lsphp';
    public const ACCOUNT = '/^[a-z][a-z0-9_-]{0,31}$/D';
    /** Fixed argv (no header: every column is empty-named with "="). */
    public const ARGV = [self::PS, '-eo', 'pid=,ppid=,user:32=,etimes=,cputimes=,rss=,pcpu=,stat=,comm='];
    private const ROW = '/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+(?:\.\d+)?)\s+(\S+)\s+(.+?)\s*$/D';

    public function __construct(private readonly CommandRunner $runner, private readonly ?PhpLimits $limits = null,
                                private readonly \Closure|null $clock = null)
    {
    }

    /** @return array<string,mixed> */
    public function report(?string $account = null): array
    {
        if ($account !== null && preg_match(self::ACCOUNT, $account) !== 1) {
            throw new Refused('invalid account name');
        }
        $thresholds = ($this->limits ?? new PhpLimits())->runaway();
        $record = $this->runner->run('ps-lsphp', self::ARGV, 20);
        if ($record['exit_code'] !== 0) {
            throw new Refused('ps failed (exit ' . $record['exit_code'] . ')');
        }
        $rows = [];
        foreach (explode("\n", $record['stdout']) as $line) {
            if (trim($line) === '') {
                continue;
            }
            if (preg_match(self::ROW, $line, $m) !== 1) {
                throw new Refused('unexpected ps output');
            }
            if ($m[9] !== self::PROCESS) {
                continue;
            }
            $rows[(int) $m[1]] = ['pid' => (int) $m[1], 'ppid' => (int) $m[2], 'user' => $m[3], 'elapsed_seconds' => (int) $m[4],
                'cpu_seconds' => (int) $m[5], 'rss_kb' => (int) $m[6], 'cpu_percent' => (float) $m[7], 'state' => $m[8]];
        }
        $byUser = [];
        foreach ($rows as $row) {
            $row['role'] = isset($rows[$row['ppid']]) ? 'child' : 'parent';
            $row['children'] = 0;
            $byUser[$row['user']][$row['pid']] = $row;
        }
        ksort($byUser, SORT_STRING);
        $accounts = [];
        $totals = ['accounts' => 0, 'processes' => 0, 'children' => 0, 'rss_kb' => 0, 'runaway' => 0];
        foreach ($byUser as $user => $family) {
            if ($account !== null && $user !== $account) {
                continue;
            }
            foreach ($family as $pid => $row) {
                if ($row['role'] === 'child' && isset($family[$row['ppid']])) {
                    ++$family[$row['ppid']]['children'];
                }
            }
            ksort($family);
            $out = ['account' => $user, 'parents' => 0, 'children' => 0, 'rss_kb' => 0, 'cpu_percent' => 0.0, 'runaway' => 0, 'processes' => []];
            foreach ($family as $row) {
                $reasons = [];
                if ($row['elapsed_seconds'] >= $thresholds['min_age_seconds']) {
                    if ($row['cpu_seconds'] >= $thresholds['cpu_seconds']) {
                        $reasons[] = 'cpu';
                    }
                    if ($row['rss_kb'] >= $thresholds['rss_mb'] * 1024) {
                        $reasons[] = 'rss';
                    }
                }
                unset($row['user']);
                $row['runaway'] = $reasons;
                $out['processes'][] = $row;
                ++$out[$row['role'] === 'child' ? 'children' : 'parents'];
                $out['rss_kb'] += $row['rss_kb'];
                $out['cpu_percent'] += $row['cpu_percent'];
                $out['runaway'] += $reasons === [] ? 0 : 1;
            }
            $out['cpu_percent'] = round($out['cpu_percent'], 1);
            $accounts[] = $out;
            $totals['accounts']++;
            $totals['processes'] += $out['parents'] + $out['children'];
            $totals['children'] += $out['children'];
            $totals['rss_kb'] += $out['rss_kb'];
            $totals['runaway'] += $out['runaway'];
        }
        return ['result' => 'processes', 'observed_at' => $this->clock === null ? time() : ($this->clock)(), 'account' => $account,
            'process' => self::PROCESS, 'thresholds' => $thresholds, 'totals' => $totals, 'accounts' => $accounts];
    }
}
