<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Php\OpcacheManager;

/**
 * `php opcache status | install (--version=ea-phpNN | --all) | reconcile` (root; docs/product-interfaces.md, "PHP
 * manager"). One instance per action, so the dispatcher's longest-match rule selects it.
 */
final class PhpOpcacheCommand extends DeploymentCommand
{
    public const ACTIONS = [
        'status' => 'OPcache per installed EA4 PHP version, or one (--version=ea-phpNN): package, loaded, key settings (root)',
        'install' => 'Install and tune OPcache (--version=ea-phpNN | --all), then restart the lsphp of the accounts on it (root)',
        'reconcile' => 'Converge OPcache on every installed EA4 PHP version that is not as wanted (root; the timer runs it)',
    ];

    /** @param \Closure():\OlsCpanel\Deployment\Environment|null $environment */
    public function __construct(private readonly string $action, ?\Closure $environment = null, private readonly string $optRoot = OpcacheManager::OPT,
                                private readonly string $userdata = OpcacheManager::USERDATADOMAINS)
    {
        parent::__construct($environment);
    }

    public function words(): array
    {
        return ['php', 'opcache', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action];
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, $this->action === 'install' ? ['all'] : [], in_array($this->action, ['install', 'status'], true) ? ['version'] : []);
        $version = $args->value('version');
        if ($this->action === 'install' && $args->flag('all') === ($version !== null)) {
            throw new UsageError('php opcache install takes exactly one of --version=ea-phpNN or --all');
        }
        $command = "php opcache {$this->action}";
        try {
            $manager = new OpcacheManager($this->environment(), $this->optRoot, $this->userdata);
            $result = match ($this->action) {
                'status' => $manager->status($version),
                'install' => $manager->install($version, $args->flag('all')),
                'reconcile' => $manager->reconcile(),
            };
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, $command);
        }
        $out->result(['command' => $command] + $result);
        return ($result['result'] ?? '') === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
