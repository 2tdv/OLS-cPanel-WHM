<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\Process;

/**
 * Runs a command directly as the calling user (the root CLI, LocalEngine): the argv array goes to proc_open,
 * so no shell ever parses it; the environment is exactly the broker's (docs/product-interfaces.md,
 * engine.run), stdin is /dev/null and the working directory is "/". Both output pipes are drained together
 * with stream_select, so a command filling stderr cannot block on a full pipe while we wait for stdout.
 * Output is decoded like the broker decodes it (text()), so a compile gives the same result either way.
 * Output above the limit is refused (killed, CommandFailed OUTPUT_TOO_LARGE), never truncated.
 *
 * Every command runs in its own session and process group (review RV-29, finding 13), like the broker's
 * runner: it is started through util-linux setsid(1), which (the child of proc_open is never a group leader)
 * calls setsid() and executes the command in place, so the process proc_open reports leads the group. At the
 * time limit or above the output limit the whole group is killed (SIGKILL to -pgid): a shell script, a cPanel
 * script or runuser's child cannot keep changing the host after the caller reported the failure.
 *
 * Deployment steps get exit code 124 at the time limit (like timeout(1)) and 127 when the command cannot
 * start; in strict mode (the engine, where a failed read must never look like an answer) both are
 * CommandFailed with the broker's codes TIMEOUT and SPAWN_FAILED instead. A start failure is recognized
 * without taking a program's own exit 127 for one (finding 17): the executable must be an executable regular
 * file before anything starts, and setsid's own report of a failed exec (exit 126 or 127, nothing on stdout,
 * stderr exactly "setsid: failed to execute <program>: <reason>") is a start failure too.
 */
final class LocalCommandRunner implements CommandRunner
{
    public const ENVIRONMENT = ['PATH' => '/usr/bin:/bin:/usr/sbin', 'LANG' => 'C', 'LC_ALL' => 'C'];
    public const MAX_OUTPUT = 16 * 1024 * 1024;
    /** util-linux setsid(1): runs the command as the leader of a new session and process group. */
    public const SETSID = '/usr/bin/setsid';
    private const KILL = '/usr/bin/kill';

    public function __construct(private readonly int $maxOutput = self::MAX_OUTPUT, private readonly bool $strict = false,
                                private readonly string $setsid = self::SETSID)
    {
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        if ($argv === [] || !array_is_list($argv) || !str_starts_with((string) $argv[0], '/')) {
            throw new \InvalidArgumentException("$name: the command must start with an absolute executable");
        }
        foreach ($argv as $arg) {
            if (!is_string($arg) || str_contains($arg, "\0")) {
                throw new \InvalidArgumentException("$name: arguments must be strings without NUL bytes");
            }
        }
        $process = self::startable($argv[0]) && self::startable($this->setsid)
            ? @proc_open([$this->setsid, ...$argv], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes, '/', self::ENVIRONMENT)
            : false;
        if (!is_resource($process)) {
            return $this->spawnFailed($name, $argv[0]);
        }
        // The group id is the leader's pid. While any member lives the kernel never reuses it, so killing -pid
        // reaches only this command's processes even after the leader itself has ended.
        $started = proc_get_status($process);
        $group = (int) $started['pid'];
        $output = [1 => '', 2 => ''];
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        foreach ($open as $pipe) {
            stream_set_blocking($pipe, false);
        }
        $deadline = hrtime(true) + max(1, $timeout) * 1_000_000_000;
        $failure = $code = null;
        // A command that has already ended was reaped by that first status call: keep its status now.
        $exit = $started['running'] ? null : ($started['signaled'] ? -$started['termsig'] : $started['exitcode']);
        try {
            while ($open !== []) {
                $left = $deadline - hrtime(true);
                if ($left <= 0) {
                    [$code, $failure] = [CommandFailed::TIMEOUT, "$name: timed out after {$timeout}s"];
                    break;
                }
                $read = array_values($open);
                $write = $except = null;
                $ready = @stream_select($read, $write, $except, intdiv($left, 1_000_000_000), intdiv($left % 1_000_000_000, 1000));
                if ($ready === false) {
                    [$code, $failure] = [CommandFailed::SPAWN_FAILED, "$name: waiting for output failed"];
                    break;
                }
                foreach ($open as $fd => $pipe) {
                    if (!in_array($pipe, $read, true)) {
                        continue;
                    }
                    $chunk = fread($pipe, 65536);
                    if ($chunk === false || ($chunk === '' && feof($pipe))) {
                        unset($open[$fd]);
                        continue;
                    }
                    $output[$fd] .= $chunk;
                }
                if (strlen($output[1]) + strlen($output[2]) > $this->maxOutput) {
                    [$code, $failure] = [CommandFailed::OUTPUT_TOO_LARGE, "$name: output above {$this->maxOutput} bytes refused"];
                    break;
                }
            }
            if ($failure === null && $exit === null) {
                // Both pipes are closed; the process exits now (or has already).
                while (true) {
                    $status = proc_get_status($process);
                    if (!$status['running']) {
                        $exit = $status['signaled'] ? -$status['termsig'] : $status['exitcode'];
                        break;
                    }
                    if (hrtime(true) > $deadline) {
                        [$code, $failure] = [CommandFailed::TIMEOUT, "$name: timed out after {$timeout}s"];
                        break;
                    }
                    usleep(2000);
                }
            }
            if ($failure !== null) {
                self::killGroup($group);
                proc_terminate($process, 9);
            }
        } finally {
            fclose($pipes[1]);
            fclose($pipes[2]);
            $closed = proc_close($process);
        }
        if ($code === CommandFailed::TIMEOUT && !$this->strict) {
            return ['exit_code' => 124, 'stdout' => self::text($output[1]), 'stderr' => self::text($output[2] . "\n$name: killed after {$timeout}s")];
        }
        if ($failure !== null) {
            throw new CommandFailed((string) $code, $failure);
        }
        $exit = $exit !== null && $exit !== -1 ? $exit : $closed;
        if (in_array($exit, [126, 127], true) && $output[1] === ''
            && preg_match('/^setsid: failed to execute ' . preg_quote($argv[0], '/') . ': [^\n]*\n$/D', $output[2]) === 1) {
            return $this->spawnFailed($name, $argv[0], rtrim($output[2]));
        }
        return ['exit_code' => $exit, 'stdout' => self::text($output[1]), 'stderr' => self::text($output[2])];
    }

    /**
     * The command could not be started: exit 127 for deployment steps, SPAWN_FAILED in strict mode.
     * @return array{exit_code:int, stdout:string, stderr:string}
     */
    private function spawnFailed(string $name, string $program, string $detail = ''): array
    {
        $message = "$name: cannot start $program" . ($detail !== '' ? ' (' . self::text($detail) . ')' : '');
        if (!$this->strict) {
            return ['exit_code' => 127, 'stdout' => '', 'stderr' => $message];
        }
        throw new CommandFailed(CommandFailed::SPAWN_FAILED, $message);
    }

    private static function startable(string $program): bool
    {
        return is_file($program) && is_executable($program);
    }

    /**
     * SIGKILL to the command's whole process group (the group id is the leader's pid, which is not reaped yet,
     * so it cannot have been reused). posix_kill when the posix extension is present, otherwise kill(1).
     */
    private static function killGroup(int $group): void
    {
        if ($group <= 1) {
            return;
        }
        if (function_exists('posix_kill')) {
            posix_kill(-$group, 9);
            return;
        }
        $kill = @proc_open([self::KILL, '-KILL', '--', '-' . $group], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'],
            2 => ['file', '/dev/null', 'w']], $ignored, '/', self::ENVIRONMENT);
        if (is_resource($kill)) {
            proc_close($kill);
        }
    }

    /**
     * Output as text exactly like the broker decodes it (Rust String::from_utf8_lossy, Python
     * errors="replace"): valid UTF-8 unchanged, otherwise each maximal invalid subsequence becomes one U+FFFD.
     * Without mbstring: PCRE checks validity, the rest is the UTF-8 well-formedness table.
     */
    public static function text(string $bytes): string
    {
        if (preg_match('//u', $bytes) === 1) {
            return $bytes;
        }
        $out = '';
        $length = strlen($bytes);
        for ($i = 0; $i < $length;) {
            $byte = ord($bytes[$i]);
            if ($byte < 0x80) {
                $out .= $bytes[$i++];
                continue;
            }
            // Continuation count and the allowed range of the second byte (Unicode table 3-7).
            [$need, $low, $high] = match (true) {
                $byte >= 0xC2 && $byte <= 0xDF => [1, 0x80, 0xBF],
                $byte === 0xE0 => [2, 0xA0, 0xBF],
                $byte === 0xED => [2, 0x80, 0x9F],
                $byte >= 0xE1 && $byte <= 0xEF => [2, 0x80, 0xBF],
                $byte === 0xF0 => [3, 0x90, 0xBF],
                $byte >= 0xF1 && $byte <= 0xF3 => [3, 0x80, 0xBF],
                $byte === 0xF4 => [3, 0x80, 0x8F],
                default => [0, 0, 0],
            };
            $next = $i + 1;
            $seen = 0;
            while ($seen < $need && $next < $length) {
                $continuation = ord($bytes[$next]);
                if ($continuation < ($seen === 0 ? $low : 0x80) || $continuation > ($seen === 0 ? $high : 0xBF)) {
                    break;
                }
                ++$next;
                ++$seen;
            }
            $out .= $need > 0 && $seen === $need ? substr($bytes, $i, $need + 1) : "\u{FFFD}";
            $i = $next;
        }
        return $out;
    }
}
