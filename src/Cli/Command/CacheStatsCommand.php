<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;

/** `cache stats [--account=U] [--domain=D]`: entries and bytes per LSCache store (root). */
final class CacheStatsCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'stats'];
    }

    public function summary(): string
    {
        return 'LSCache entries and bytes per store, optionally for one account or domain (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], ['account', 'domain']);
        $this->context->root();
        try {
            $out->result($this->context->cache()->stats($args->value('account'), $args->value('domain')));
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        return Application::EXIT_OK;
    }
}
