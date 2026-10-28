<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\ApacheReturn;
use OlsCpanel\Deployment\DeploymentError;

/** `apache-return --prepare | --execute [--yes]`. */
final class ApacheReturnCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['apache-return'];
    }

    public function summary(): string
    {
        return "Return to Apache with the latest backup's recover.sh (--prepare | --execute [--yes])";
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['prepare', 'execute', 'yes'], []);
        if ($args->flag('prepare') === $args->flag('execute') || ($args->flag('prepare') && $args->flag('yes'))) {
            throw new UsageError('apache-return --prepare | apache-return --execute [--yes]');
        }
        $return = new ApacheReturn($this->environment());
        try {
            if ($args->flag('prepare')) {
                $summary = $return->prepare();
                $out->result(['command' => 'apache-return --prepare'] + $summary);
                return $summary['intact'] ? Application::EXIT_OK : Application::EXIT_REFUSED;
            }
            $yes = $args->flag('yes');
            $outcome = $return->execute(fn(array $summary): bool => $this->approve($out, $yes, $summary['backup'],
                ["Return to Apache with backup {$summary['backup']} (plan {$summary['plan']}):",
                    ...array_map(static fn(string $a): string => "  - $a", $summary['actions'])], 'the return to Apache'));
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'apache-return');
        }
        $out->result(['command' => 'apache-return --execute'] + $outcome);
        return ApacheReturn::exitCode($outcome);
    }
}
