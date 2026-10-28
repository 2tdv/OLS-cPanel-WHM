<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Upgrade;

/** `upgrade`: verify the installed packages and restart the broker and the reconciler (root). */
final class UpgradeCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['upgrade'];
    }

    public function summary(): string
    {
        return 'After a package upgrade: verify the packages, restart the broker and reconciler (root)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        try {
            $outcome = (new Upgrade($this->environment()))->run();
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'upgrade');
        }
        $out->result(['command' => 'upgrade'] + $outcome);
        return $outcome['result'] === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
