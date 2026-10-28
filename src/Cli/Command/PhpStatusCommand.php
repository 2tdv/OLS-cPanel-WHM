<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Php\OpcacheManager;
use OlsCpanel\Php\PhpLimits;
use OlsCpanel\Php\PhpEnvironment;
use OlsCpanel\Php\PhpProcesses;
use OlsCpanel\PhpExtensions\ExtensionSync;

/**
 * `php status [--account=U]`: what the WHM and cPanel PHP views show, in one answer: OPcache per EA4 PHP version,
 * the lsphp processes (per account without their rows, unless one account is named) and the limits in
 * force (root, read only). The broker's `php.status` and `tenant.php` run it.
 */
final class PhpStatusCommand extends DeploymentCommand
{
    public function __construct(?\Closure $environment = null, private readonly string $limitsPath = PhpLimits::PATH,
                                private readonly string $optRoot = OpcacheManager::OPT, private readonly string $userdata = OpcacheManager::USERDATADOMAINS)
    {
        parent::__construct($environment);
    }

    public function words(): array
    {
        return ['php', 'status'];
    }

    public function summary(): string
    {
        return 'PHP manager state: OPcache per version, lsphp processes, limits [--account=U] (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], ['account']);
        $account = $args->value('account');
        try {
            $env = $this->environment();
            $env->requireRoot();
            [$limits, $problem] = PhpLimits::loadLenient($this->limitsPath);
            $processes = (new PhpProcesses($env->runner, $limits))->report($account);
            if ($account === null) {
                $processes['accounts'] = array_map(static function (array $a): array {
                    unset($a['processes']);
                    return $a;
                }, $processes['accounts']);
            }
            $manager = new OpcacheManager($env, $this->optRoot, $this->userdata);
            $opcache = $manager->status();
            // FV-10: the PHP environment applier's per-version state (complete, repairing, failed with the reason).
            $environment = (new PhpEnvironment($env, $manager, ExtensionSync::production($env), $env->ea4Profile(), $this->optRoot))->status();
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'php status');
        }
        $limitReport = $limits->describe() + ['file' => PhpLimits::PATH, 'error' => $problem];
        if ($account !== null) {
            $limitReport['account'] = $limits->forAccount($account);
        }
        $out->result(['command' => 'php status', 'result' => 'status', 'observed_at' => time(), 'account' => $account,
            'opcache' => $opcache, 'environment' => $environment, 'processes' => $processes, 'limits' => $limitReport]);
        return 0;
    }
}
