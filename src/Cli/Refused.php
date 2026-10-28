<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/** The command may not run for this caller or in this state: exit 1 with the reason. */
final class Refused extends \RuntimeException
{
}
