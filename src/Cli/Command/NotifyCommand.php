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
use OlsCpanel\Operations\Notifier;
use OlsCpanel\Operations\NotifySettings;

/**
 * `notify show|set|test|run` (FV-07, root): the notification settings and sender. `run` is the five-minute pass of
 * ols-cpanel-notify.timer; `set` is what the WHM Notifications form calls (--emails=a@x,b@y|none, --webhook=<https url>|none,
 * --events=job,held,...; an option that is left out keeps the stored value); `test` sends a test message to the configured channels.
 */
final class NotifyCommand implements Command
{
    public const ACTIONS = ['show' => 'Show the notification settings and what was sent', 'set' => 'Set --emails=a@x,b@y|none --webhook=https://...|none --events=a,b',
        'test' => 'Send a test notification to the configured channels', 'run' => 'Send the notifications that are new (runs every five minutes by itself)'];

    /** @param (\Closure():Notifier)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly ?\Closure $factory = null,
                                private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['notify', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action] . ' (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], $this->action === 'set' ? ['emails', 'webhook', 'events'] : []);
        $this->context->root();
        $notifier = $this->factory !== null ? ($this->factory)() : new Notifier($this->state);
        if ($this->action === 'set') {
            $current = NotifySettings::load($this->state);
            $emails = $args->value('emails');
            $webhook = $args->value('webhook');
            $events = $args->value('events');
            try {
                NotifySettings::save($this->state,
                    $emails === null ? $current->emails : ($emails === 'none' ? [] : explode(',', $emails)),
                    $webhook === null ? null : ($webhook === 'none' ? '' : $webhook),
                    $events === null ? null : ($events === 'none' ? [] : explode(',', $events)), time());
            } catch (\OlsCpanel\Cli\Refused $error) {
                throw new UsageError($error->getMessage());
            }
        }
        $result = match ($this->action) {
            'test' => $notifier->test(),
            'run' => $notifier->run(),
            default => $notifier->status(),
        };
        if ($this->action === 'set') {
            $result = ['changed' => true] + $notifier->status();
        }
        $out->result(['command' => 'notify ' . $this->action] + $result);
        return ($result['result'] ?? 'ok') === 'failed' ? Application::EXIT_REFUSED : Application::EXIT_OK;
    }
}
