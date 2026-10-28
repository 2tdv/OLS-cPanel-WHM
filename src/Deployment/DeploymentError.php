<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Cli\Application;

/**
 * A deployment operation stopped with a reported reason. The exit code is the documented one
 * (docs/product-interfaces.md): refused or failed (1), unsupported platform (2), busy (75).
 */
final class DeploymentError extends \RuntimeException
{
    /** @param array<string,mixed> $details */
    public function __construct(string $message, public readonly int $exitCode = Application::EXIT_REFUSED,
                                public readonly array $details = [], public readonly string $step = '')
    {
        parent::__construct($message);
    }

    /** @param array<string,mixed> $details */
    public static function refused(string $message, array $details = []): self
    {
        return new self($message, Application::EXIT_REFUSED, $details);
    }

    /** A step that changes or checks the host failed. */
    public static function step(string $step, string $message, array $details = []): self
    {
        return new self("$step: $message", Application::EXIT_REFUSED, $details, $step);
    }
}
