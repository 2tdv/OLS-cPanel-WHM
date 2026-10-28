<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The timers of the operations features (FV-07): the notification pass every five minutes and the maintenance-window pass every
 * minute. Enabled by `install --prepare` and by `upgrade` (so hosts prepared before they existed get them with the next package
 * update). Idempotent; a failure never stops the caller (the result is returned and the next upgrade or prepare tries again).
 */
final class OperationsTimers
{
    public const TIMERS = ['ols-cpanel-notify.timer', 'ols-cpanel-schedule.timer'];

    /** @return array<string,bool> timer => enabled and started */
    public static function ensure(Host $host): array
    {
        $result = [];
        foreach (self::TIMERS as $timer) {
            $result[$timer] = $host->run("ops-timer-enable-$timer", [Host::SYSTEMCTL, 'enable', '--now', $timer])['exit_code'] === 0;
        }
        return $result;
    }
}
