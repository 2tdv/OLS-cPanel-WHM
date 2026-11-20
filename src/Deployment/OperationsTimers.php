<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The timers of the operations features (FV-07): the notification pass every five minutes and the maintenance-window pass every
 * minute; the WordPress login guard's watcher (RV-64, a service, on by default) and the tenant .htaccess watch (CMP-02, a service). Enabled by `install --prepare` and by `upgrade` (so hosts prepared before they existed get them with the next package
 * update). Idempotent; a failure never stops the caller (the result is returned and the next upgrade or prepare tries again).
 */
final class OperationsTimers
{
    public const TIMERS = ['ols-cpanel-notify.timer', 'ols-cpanel-schedule.timer', 'ols-cpanel-login-guard.service',
        'ols-cpanel-htaccess-watch.service'];

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
