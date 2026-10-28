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
use OlsCpanel\Operations\SupportBundle;

/**
 * `support bundle [--no-anonymize]` and `support list` (FV-07, root): the redacted diagnostics archive (kept in
 * /var/lib/ols-cpanel/support/, downloadable from the WHM Support view) and the bundles that exist. See Operations\SupportBundle.
 */
final class SupportBundleCommand implements Command
{
    /** @param (\Closure():SupportBundle)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly ?\Closure $factory = null,
                                private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['support', $this->action];
    }

    public function summary(): string
    {
        return ($this->action === 'bundle' ? 'Make a redacted diagnostics archive: [--no-anonymize]' : 'List the diagnostics archives') . ' (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, $this->action === 'bundle' ? ['no-anonymize'] : [], []);
        $this->context->root();
        $bundle = $this->factory !== null ? ($this->factory)() : new SupportBundle(new LocalCommandRunner(16 << 20), $this->state);
        $result = $this->action === 'bundle' ? ['created' => $bundle->create(!$args->flag('no-anonymize'))] : [];
        $out->result(['command' => 'support ' . $this->action] + $result + ['bundles' => $bundle->bundles(), 'limit_bytes' => SupportBundle::MAX_BYTES]);
        return Application::EXIT_OK;
    }
}
