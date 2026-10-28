<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\Process;

/** Fixed read-only commands. No user-supplied executable, argument or environment. */
final class ProbeRunner
{
    public const COMMANDS = [
        'packages' => ['/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'],
        'apache' => ['/usr/bin/systemctl', 'show', 'httpd.service',
            '--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath'],
    ];

    public function run(string $id): array
    {
        if (!isset(self::COMMANDS[$id])) {
            throw new \InvalidArgumentException('Unknown probe');
        }
        $command = self::COMMANDS[$id];
        $base = ['source' => $id, 'observed_at' => gmdate('c'), 'value' => null, 'exit_code' => null];
        if (!is_executable($command[0])) {
            return $base + ['status' => 'unavailable'];
        }
        $process = @proc_open($command, [
            0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $pipes, '/', ['PATH' => '/usr/bin:/bin', 'LANG' => 'C', 'LC_ALL' => 'C']);
        if (!is_resource($process)) {
            return $base + ['status' => 'unavailable'];
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $size = 0;
        $deadline = hrtime(true) + 10_000_000_000;
        $status = 'observed';
        $exit = null;
        try {
            while (true) {
                $chunk = stream_get_contents($pipes[1], 65536);
                $error = stream_get_contents($pipes[2], 65536);
                $out .= $chunk === false ? '' : $chunk;
                $size += strlen($chunk === false ? '' : $chunk) + strlen($error === false ? '' : $error);
                if ($size > 1048576 || hrtime(true) > $deadline) {
                    $status = $size > 1048576 ? 'output_limit' : 'timeout';
                    proc_terminate($process, 9);
                    break;
                }
                $state = proc_get_status($process);
                if (!$state['running'] && feof($pipes[1]) && feof($pipes[2])) {
                    $exit = $state['exitcode'];
                    break;
                }
                usleep(10000);
            }
        } finally {
            fclose($pipes[1]);
            fclose($pipes[2]);
            $closed = proc_close($process);
        }
        $exit = $exit !== null && $exit >= 0 ? $exit : $closed;
        $base['exit_code'] = $exit;
        if ($status === 'observed' && $exit !== 0) {
            $status = 'error';
        }
        $base['value'] = $status === 'observed' ? $out : null;
        return $base + ['status' => $status];
    }
}
