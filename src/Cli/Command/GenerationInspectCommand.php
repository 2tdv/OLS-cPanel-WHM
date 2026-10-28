<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Cli\UsageError;

/** One generation: epoch, source digest, health targets, hybrid vhosts, validation and transactions (root). */
final class GenerationInspectCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['generation', 'inspect'];
    }

    public function summary(): string
    {
        return 'One generation in detail: generation inspect <id> (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $id = (new Arguments($argv, [], [], 1))->positional(0);
        if ($id === null) {
            throw new UsageError('generation inspect <id>');
        }
        $this->context->root();
        $view = $this->context->store()->inspect($id);
        if ($view === null) {
            throw new Refused('no such generation: ' . substr($id, 0, 128));
        }
        $out->result($view);
        return Application::EXIT_OK;
    }
}
