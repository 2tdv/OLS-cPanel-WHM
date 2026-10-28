<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Operations\Schedule;

/**
 * `schedule list|add|cancel|run` (FV-07, root): maintenance windows for the switch and return jobs. `run` is the pass of
 * ols-cpanel-schedule.timer (every minute). `add` is what the broker calls after it checked that the plan or status digest is
 * the one the operator saw: --action=ols.cutover|ols.apache_return --scope=<plan id>|server --digest=<sha256> --at=<unix time>
 * [--window=<minutes>]. See Operations\Schedule.
 */
final class ScheduleCommand implements Command
{
    public const ACTIONS = ['list' => 'List the scheduled jobs', 'add' => 'Schedule a switch or return: --action= --scope= --digest= --at= [--window=]',
        'cancel' => 'Cancel a scheduled job: --id=', 'run' => 'Start the scheduled jobs that are due (runs every minute by itself)'];

    /** @param (\Closure():Schedule)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly ?\Closure $factory = null,
                                private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['schedule', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action] . ' (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $valued = match ($this->action) {
            'add' => ['action', 'scope', 'digest', 'at', 'window'],
            'cancel' => ['id'],
            default => [],
        };
        $args = new Arguments($argv, [], $valued);
        $this->context->root();
        $schedule = $this->factory !== null ? ($this->factory)() : new Schedule($this->state);
        $result = [];
        switch ($this->action) {
            case 'add':
                foreach (['action', 'scope', 'digest', 'at'] as $required) {
                    if ($args->value($required) === null) {
                        throw new UsageError("--$required is required");
                    }
                }
                foreach (['at', 'window'] as $number) {
                    if ($args->value($number) !== null && preg_match('/^[0-9]{1,10}$/D', (string) $args->value($number)) !== 1) {
                        throw new UsageError("--$number takes a whole number");
                    }
                }
                $result = ['added' => self::visible($schedule->add((string) $args->value('action'), (string) $args->value('scope'), (string) $args->value('digest'),
                    (int) $args->value('at'), (int) ($args->value('window') ?? Schedule::DEFAULT_WINDOW)))] + $schedule->view();
                break;
            case 'cancel':
                if ($args->value('id') === null || preg_match('/^s[0-9]{14}-[0-9a-f]{6}$/D', (string) $args->value('id')) !== 1) {
                    throw new UsageError('--id takes a scheduled job id');
                }
                $schedule->cancel((string) $args->value('id'));
                $result = ['cancelled' => $args->value('id')] + $schedule->view();
                break;
            case 'run':
                $result = $schedule->run();
                break;
            default:
                $result = $schedule->view();
        }
        $out->result(['command' => 'schedule ' . $this->action] + $result);
        return Application::EXIT_OK;
    }

    /** @param array<string,mixed> $entry @return array<string,mixed> */
    private static function visible(array $entry): array
    {
        return array_diff_key($entry, ['digest' => 0]);
    }
}
