<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\Process;

/**
 * Runs one fixed, read-only command for discovery and compilation. In production the broker
 * implements it (privileged reads; tenant files are read as the tenant through runuser, exactly as
 * the argv says); tests replay recorded calls. Callers build every argv themselves and never pass
 * user-supplied executables or environment.
 */
interface CommandRunner
{
    /**
     * @param string $name step label for evidence and logs (several calls may share one)
     * @param list<string> $argv absolute executable followed by its arguments, never run through a shell
     * @param int $timeout seconds before the command is killed
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    public function run(string $name, array $argv, int $timeout): array;
}
