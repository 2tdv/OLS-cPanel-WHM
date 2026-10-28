<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/** Wrong command-line usage: exit 64, nothing on stdout. */
final class UsageError extends \RuntimeException
{
}
