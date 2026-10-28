<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Operations\UpdateCheck;

/**
 * `update check [--refresh]` (FV-07, root): installed versus available versions of the product packages and the rpm signature
 * state of the installed ones. Read-only; the update itself is done by dnf and cPanel's update schedule. See Operations\UpdateCheck.
 */
final class UpdateCheckCommand implements Command
{
    /** @param (\Closure():UpdateCheck)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly ?\Closure $factory = null, private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['update', 'check'];
    }

    public function summary(): string
    {
        return 'Show installed and available product versions and the package signature state: [--refresh] (root, read-only)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['refresh'], []);
        $this->context->root();
        $check = $this->factory !== null ? ($this->factory)()
            : new UpdateCheck(new \OlsCpanel\Deployment\Host(new LocalCommandRunner(1 << 20)), $this->state);
        $out->result(['command' => 'update check'] + $check->report($args->flag('refresh')));
        return Application::EXIT_OK;
    }
}
