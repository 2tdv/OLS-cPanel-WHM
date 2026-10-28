<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;

/** Every generation with its epoch, validation verdict and whether it is active or was committed (root). */
final class GenerationListCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['generation', 'list'];
    }

    public function summary(): string
    {
        return 'Generations, oldest first (root)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $this->context->root();
        $store = $this->context->store();
        $out->result(['active' => $store->pointer(), 'generations' => $store->list()]);
        return Application::EXIT_OK;
    }
}
