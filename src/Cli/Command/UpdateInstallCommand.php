<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Host;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Operations\ReleaseUpdate;

/**
 * `update install --version=<v> | --latest` (root): installs a newer release from its GitHub release after verifying install.sh
 * against the release key shipped in the product package (Operations\ReleaseUpdate). The WHM "Update now" button runs it as the job
 * `ols.update` with --latest. The report always carries `code` (0 updated, 1 failed or refused), so a broker that restarted while
 * the job ran (the product's own upgrade restarts it) can still record the outcome from the report.
 */
final class UpdateInstallCommand implements Command
{
    /** @param (\Closure(Output):ReleaseUpdate)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly ?\Closure $factory = null, private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['update', 'install'];
    }

    public function summary(): string
    {
        return 'Install a newer signed release from GitHub: --version=<v> | --latest (root; verified before anything runs)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['latest'], ['version']);
        if ($args->flag('latest') === ($args->value('version') !== null)) {
            throw new UsageError('give exactly one of --version=<v> and --latest');
        }
        $this->context->root();
        $update = $this->factory !== null ? ($this->factory)($out)
            : new ReleaseUpdate(new Host(new LocalCommandRunner()), $this->state, progress: static fn(string $line) => $out->error($line));
        $result = $update->install($args->value('version'));
        $out->result(['command' => 'update install'] + $result);
        return $result['code'] === 0 ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
