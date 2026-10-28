<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Events\PacedEngine;
use OlsCpanel\Events\Reconciler;

/**
 * Reconcile once (exit 0 when the active generation is current: "unchanged" or "committed"; 1 when the
 * new generation was invalid, refused or rolled back, the events then stay pending), or run the service
 * loop (`--watch`, one JSON line per pass and per enforcement action; it never returns on its own).
 */
final class SyncCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['sync'];
    }

    public function summary(): string
    {
        return 'Reconcile once (--force: activate even when unchanged) or --watch [--interval=N]';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['watch', 'force'], ['interval']);
        $interval = $args->value('interval');
        if ($interval !== null && (!$args->flag('watch') || !preg_match('/^[1-9][0-9]{0,4}$/D', $interval))) {
            throw new UsageError('sync --watch --interval=N (N seconds, 1 to 99999)');
        }
        if ($args->flag('watch') && $args->flag('force')) {
            throw new UsageError('sync --force is a single pass; the service loop never forces');
        }
        $engine = $this->context->engine();
        if ($args->flag('watch')) {
            $emit = static function (array $record) use ($out): void {
                $out->line($record);
            };
            $this->context->reconciler(new PacedEngine($engine, \Closure::fromCallable($emit)))
                ->watch($interval === null ? Reconciler::DEFAULT_INTERVAL : (int) $interval, \Closure::fromCallable($emit));
            return Application::EXIT_OK;
        }
        $result = $this->context->reconciler($engine)->reconcile($args->flag('force'));
        $out->result($result);
        return in_array($result['action'] ?? null, ['unchanged', 'committed'], true) ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
