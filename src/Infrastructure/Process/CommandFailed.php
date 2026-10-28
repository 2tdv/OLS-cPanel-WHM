<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\Process;

/**
 * A command that produced no usable result, with the broker's error code (engine.run): SPAWN_FAILED (it could
 * not be started), TIMEOUT (killed at its time limit) or OUTPUT_TOO_LARGE (refused, never truncated). A
 * non-zero exit status is a result, not this.
 */
final class CommandFailed extends \RuntimeException
{
    public const SPAWN_FAILED = 'SPAWN_FAILED';
    public const TIMEOUT = 'TIMEOUT';
    public const OUTPUT_TOO_LARGE = 'OUTPUT_TOO_LARGE';

    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}
