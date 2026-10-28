<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Upgrade;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Php\PhpEnvironment;

/**
 * `php env status | sync | repair` (root; docs/product-interfaces.md, "PHP environment"): the applier that keeps
 * every installed EA4 PHP version complete for OLS (lsphp, OPcache, redis). `sync` is what ols-cpanel-php.service
 * runs (after package transactions and periodically, back-off respected); `repair` is the WHM button
 * (`ols.php_env_repair`, back-off ignored). One instance per action, so the dispatcher's longest-match rule selects it.
 */
final class PhpEnvCommand extends DeploymentCommand
{
    public const ACTIONS = [
        'status' => 'PHP environment per EA4 PHP version: complete, repairing or failed with the reason (root, read only)',
        'sync' => 'Make every installed EA4 PHP version complete now: lsphp, OPcache, redis; failed versions wait for their retry time (root; the service runs it)',
        'repair' => 'Like sync, but retry failed versions at once (root; the WHM button)',
    ];

    /** @param \Closure(Environment):PhpEnvironment|null $applier */
    public function __construct(private readonly string $action, ?\Closure $environment = null, private readonly ?\Closure $applier = null)
    {
        parent::__construct($environment);
    }

    public function words(): array
    {
        return ['php', 'env', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action];
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $command = "php env {$this->action}";
        try {
            $env = $this->environment();
            $env->requireRoot();
            // After a package transaction that changed the product, apply it (ols-cpanel-upgrade.service runs `upgrade`):
            // nobody has to run it. Never fails this pass.
            if ($this->action === 'sync') {
                try {
                    if (Upgrade::pending($env)) {
                        $env->host->run('upgrade-trigger', ['/usr/bin/systemctl', 'start', '--no-block', Upgrade::SERVICE]);
                    }
                } catch (\Throwable) {
                    // The next pass tries again.
                }
            }
            $applier = $this->applier !== null ? ($this->applier)($env) : PhpEnvironment::production($env);
            $result = match ($this->action) {
                'status' => $applier->status(),
                'sync' => $applier->sync(),
                'repair' => $applier->repair(),
            };
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, $command);
        }
        $out->result(['command' => $command] + $result);
        return ($result['result'] ?? '') === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
