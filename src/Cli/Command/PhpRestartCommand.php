<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\PhpRestart;

/** `php restart (--all | --account=U)`: end the lsphp processes so they restart with new extensions and INI (root). */
final class PhpRestartCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['php', 'restart'];
    }

    public function summary(): string
    {
        return 'End lsphp processes of --all or --account=U so they restart with new PHP extensions/INI (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['all'], ['account']);
        if ($args->flag('all') === ($args->value('account') !== null)) {
            throw new UsageError('php restart takes exactly one of --all or --account=U');
        }
        try {
            $outcome = (new PhpRestart($this->environment()))->run($args->value('account'));
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'php restart');
        }
        $out->result(['command' => 'php restart'] + $outcome);
        return $outcome['result'] === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
