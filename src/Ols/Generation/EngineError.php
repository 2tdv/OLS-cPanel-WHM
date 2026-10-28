<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Generation;

/** The engine could not perform an operation (broker error code, activator failure); the message is bounded. */
final class EngineError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct(substr(preg_replace('/[^\x20-\x7e]/', '?', $message) ?? '', 0, 500));
    }
}
