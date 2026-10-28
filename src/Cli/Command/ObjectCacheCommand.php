<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\ObjectCache\ObjectCacheManager;

/**
 * `ols-cpanel objcache <action>` (root): status, enable, disable, flush, configure-wordpress, package, auto and reconcile
 * (docs/product-interfaces.md, "Object cache"). One instance per action, so the dispatcher's longest-match rule
 * selects it.
 */
final class ObjectCacheCommand implements Command
{
    public const ACTIONS = [
        'status' => 'Object cache state of all accounts, or of one (--account=U: usage and hit rate)',
        'enable' => 'Enable the object cache of an account (--account=U [--memory=MB])',
        'disable' => 'Turn the object cache of an account off and remove its instance; it stays off (packages and the automatic mode) until enable (--account=U)',
        'flush' => 'Flush the object cache of an account (--account=U)',
        'configure-wordpress' => 'Set LiteSpeed Cache object cache for one WordPress by hand (support; enable and the timer do this automatically) (--account=U --path=DIR [--php=ea-phpNN])',
        'package' => 'Memory for the accounts of a cPanel package, 0 or --off switches it off for them (--name=P (--memory=MB | --off | --remove))',
        'auto' => 'Automatic object cache for every account with WordPress and LiteSpeed Cache (--on | --off; off removes only automatic ones)',
        'reconcile' => 'Apply the object cache desired state now (suspension, removal, packages, WordPress sites)',
    ];

    /** @param \Closure():ObjectCacheManager $manager */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly \Closure $manager)
    {
    }

    public function words(): array
    {
        return ['objcache', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action];
    }

    public function run(array $argv, Output $out): int
    {
        $valued = match ($this->action) {
            'status', 'disable', 'flush' => ['account'],
            'enable' => ['account', 'memory'],
            'configure-wordpress' => ['account', 'path', 'php'],
            'package' => ['name', 'memory'],
            default => [],
        };
        $flags = match ($this->action) {
            'package' => ['remove', 'off'],
            'auto' => ['on', 'off'],
            default => [],
        };
        $args = new Arguments($argv, $flags, $valued);
        $this->context->root();
        $account = $args->value('account');
        if ($account === null && in_array($this->action, ['enable', 'disable', 'flush', 'configure-wordpress'], true)) {
            throw new UsageError("objcache {$this->action} --account=U" . ($this->action === 'enable' ? ' [--memory=MB]'
                : ($this->action === 'configure-wordpress' ? ' --path=DIR [--php=ea-phpNN]' : '')));
        }
        $manager = ($this->manager)();
        $result = match ($this->action) {
            'status' => $manager->status($account),
            'enable' => $manager->enable((string) $account, $args->value('memory')),
            'disable' => $manager->disable((string) $account),
            'flush' => $manager->flush((string) $account),
            'configure-wordpress' => $manager->configureWordPress((string) $account,
                $args->value('path') ?? throw new UsageError('objcache configure-wordpress --account=U --path=DIR [--php=ea-phpNN]'),
                $args->value('php')),
            'package' => $this->package($manager, $args),
            'auto' => $args->flag('on') !== $args->flag('off') ? $manager->automatic($args->flag('on'))
                : throw new UsageError('objcache auto (--on | --off)'),
            'reconcile' => $manager->reconcile(),
        };
        $out->result($result);
        return ($result['result'] ?? '') === 'errors' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }

    /** @return array<string,mixed> */
    private function package(ObjectCacheManager $manager, Arguments $args): array
    {
        $name = $args->value('name');
        if ($name === null || (int) $args->flag('remove') + (int) $args->flag('off') + (int) ($args->value('memory') !== null) > 1) {
            throw new UsageError('objcache package --name=P (--memory=MB | --off | --remove)');
        }
        return $manager->package($name, $args->value('memory'), $args->flag('remove'), $args->flag('off'));
    }
}
