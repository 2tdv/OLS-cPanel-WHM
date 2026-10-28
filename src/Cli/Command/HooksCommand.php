<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\DeploymentError;

/** `hooks install | verify | remove`: the product's cPanel hook registrations (manage_hooks). */
final class HooksCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['hooks'];
    }

    public function summary(): string
    {
        return 'cPanel hook registrations of the product (install | verify | remove)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], [], 1);
        $action = $args->positional(0);
        if (!in_array($action, ['install', 'verify', 'remove'], true)) {
            throw new UsageError('hooks install | hooks verify | hooks remove');
        }
        $env = $this->environment();
        try {
            $env->requireRoot();
            if ($action === 'verify') {
                $result = $env->hooks()->verify();
                $out->result(['command' => 'hooks verify', 'result' => $result['ok'] ? 'match' : 'mismatch'] + $result);
                return $result['ok'] ? Application::EXIT_OK : Application::EXIT_REFUSED;
            }
            $lock = $env->lock();
            try {
                $result = $action === 'install' ? $env->hooks()->install() : $env->hooks()->remove();
            } finally {
                fclose($lock);
            }
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, "hooks $action");
        }
        $out->result(['command' => "hooks $action", 'result' => $action === 'install' ? 'installed' : 'removed'] + $result);
        return Application::EXIT_OK;
    }
}
