<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Php\PhpLimits;
use OlsCpanel\Php\PhpProcesses;

/** `php processes [--account=U]`: the lsphp processes per account with runaway detection (root, read only). */
final class PhpProcessesCommand extends DeploymentCommand
{
    /** @param string $limitsPath */
    public function __construct(?\Closure $environment = null, private readonly string $limitsPath = PhpLimits::PATH)
    {
        parent::__construct($environment);
    }

    public function words(): array
    {
        return ['php', 'processes'];
    }

    public function summary(): string
    {
        return 'lsphp processes per account (pid, children, CPU, RSS, age, state) with runaway detection [--account=U] (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], ['account']);
        try {
            $env = $this->environment();
            $env->requireRoot();
            [$limits, $problem] = PhpLimits::loadLenient($this->limitsPath);
            $report = (new PhpProcesses($env->runner, $limits))->report($args->value('account'));
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'php processes');
        }
        $out->result(['command' => 'php processes'] + $report + ['limits_error' => $problem]);
        return 0;
    }
}
