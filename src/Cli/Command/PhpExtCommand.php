<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\PhpExtensions\ExtensionService;

/**
 * `ols-cpanel php-ext <action>` (root): status, install [--php=ea-phpNN], remove and sync (the watcher's pass,
 * run as part of ols-cpanel-php.service by `php env sync`). One instance per action, so the dispatcher's longest-match rule selects it.
 */
final class PhpExtCommand implements Command
{
    public const ACTIONS = [
        'status' => 'PHP redis extension state per EA4 PHP version (prebuilt, local build, last failure)',
        'install' => 'Make the redis extension load in every EA4 PHP version, or one (--php=ea-phpNN); enables the PHP environment units',
        'remove' => 'Remove the INI files this product wrote and stop keeping redis active (the PHP environment service keeps running for lsphp and OPcache)',
        'sync' => 'Re-verify every EA4 PHP version now (what the watcher runs)',
    ];

    /** @param \Closure():ExtensionService $service */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly \Closure $service)
    {
    }

    public function words(): array
    {
        return ['php-ext', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action];
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], $this->action === 'install' ? ['php'] : []);
        $this->context->root();
        $service = ($this->service)();
        $result = match ($this->action) {
            'status' => $service->status(),
            'install' => $service->install($args->value('php')),
            'remove' => $service->remove(),
            'sync' => $service->sync(),
        };
        $out->result($result);
        return ($result['result'] ?? '') === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
