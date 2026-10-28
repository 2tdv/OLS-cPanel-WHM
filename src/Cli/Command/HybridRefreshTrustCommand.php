<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\HybridHost;

/**
 * `hybrid refresh-trust`: keeps Apache's trusted proxy list (the mod_remoteip include of the hybrid profile) equal to the
 * host's local addresses (root; run by ols-cpanel-hybrid-trust.service). A no-op without the hybrid profile.
 */
final class HybridRefreshTrustCommand extends DeploymentCommand
{
    public function words(): array
    {
        return ['hybrid', 'refresh-trust'];
    }

    public function summary(): string
    {
        return 'Trust every local address in the hybrid mod_remoteip include and reload Apache when it changed (root)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $env = $this->environment();
        try {
            $env->requireRoot();
            $lock = $env->lock(120);
            try {
                $outcome = (new HybridHost($env->host))->refreshTrust($env->state . '/staging');
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'hybrid refresh-trust');
        }
        $out->result(['command' => 'hybrid refresh-trust'] + $outcome);
        return $outcome['result'] === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
