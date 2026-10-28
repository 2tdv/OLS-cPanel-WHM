<?php
declare(strict_types=1);

/**
 * The lsphp part of a scripted fake host: `pgrep -u U -x lsphp`, `cat /proc/PID/stat` and `kill -SIG -- PID`, over a
 * table of pids per account. The start time of a pid is $starts[$pid] (default 1000 + pid), which is what a real
 * /proc/PID/stat reports in field 22.
 */
final class LsphpFake
{
    /**
     * @param array<string,list<int>> $lsphp account => pids
     * @param array<int,int> $starts pid => start time
     * @param list<string> $argv
     * @param \Closure(int,string):(bool|null)|null $onSignal called for a delivered signal (pid, TERM or KILL); true: the signal had no effect
     * @param array<int,string> $states pid => process state letter (default S)
     * @param array<int,string|null> $environs pid => /proc/PID/environ content (null: unreadable)
     * @return array{exit_code:int, stdout:string, stderr:string}|null null for a command that is not ours
     */
    public static function handle(array &$lsphp, array &$starts, bool $stubborn, array $argv, ?\Closure $onSignal = null, array $states = [], array $environs = []): ?array
    {
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1): array => ['exit_code' => $code, 'stdout' => '', 'stderr' => ''];
        $args = array_slice($argv, 1);
        switch ($argv[0]) {
            case '/usr/bin/pgrep':
                $user = in_array('-u', $args, true) ? $args[array_search('-u', $args, true) + 1] : null;
                $pids = [];
                foreach ($lsphp as $u => $list) {
                    if ($user === null || $user === $u) {
                        array_push($pids, ...$list);
                    }
                }
                return $pids === [] ? $no(1) : $ok(implode("\n", $pids) . "\n");
            case '/usr/bin/cat':
                if (preg_match('~^/proc/(\d+)/environ$~D', $args[0], $m) === 1) {
                    return isset($environs[(int) $m[1]]) ? $ok($environs[(int) $m[1]]) : $no(1);
                }
                if (preg_match('~^/proc/(\d+)/stat$~D', $args[0], $m) !== 1) {
                    return null;
                }
                $pid = (int) $m[1];
                foreach ($lsphp as $list) {
                    if (in_array($pid, $list, true)) {
                        $start = $starts[$pid] ?? 1000 + $pid;
                        return $ok("$pid (lsphp) " . ($states[$pid] ?? 'S') . " 1 $pid $pid 0 -1 " . implode(' ', array_fill(0, 9, '0')) . " 20 0 1 0 $start 0 0\n");
                    }
                }
                return $no(1);
            case '/usr/bin/kill':
                $signal = ltrim($args[0], '-');
                $pid = (int) $args[2];
                $ignored = $onSignal !== null && $onSignal($pid, $signal) === true;
                if ($ignored || ($stubborn && $signal === 'TERM')) {
                    return $ok();
                }
                foreach ($lsphp as $u => $list) {
                    $lsphp[$u] = array_values(array_diff($list, [$pid]));
                }
                return $ok();
        }
        return null;
    }
}
