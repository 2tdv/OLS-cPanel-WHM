<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Uninstall;

/** `uninstall [--dry-run] [--keep-packages]`. */
final class UninstallCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['uninstall'];
    }

    public function summary(): string
    {
        return 'Return to Apache if needed, remove hooks, units, state, OPcache INI and the object cache setting, then the packages (backups kept); --dry-run shows the actions, --keep-packages keeps the packages';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['dry-run', 'keep-packages'], []);
        try {
            $outcome = (new Uninstall($this->environment()))->run($args->flag('dry-run'), $args->flag('keep-packages'));
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'uninstall');
        }
        $out->result(['command' => 'uninstall'] + $outcome);
        return $outcome['result'] === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
