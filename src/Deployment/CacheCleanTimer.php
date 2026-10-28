<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The hourly LSCache cleanup (FV-01, ols-cpanel-cache-clean.timer): enabled by `install --prepare` and by `upgrade`, so hosts that
 * were prepared before the cleanup existed get it with the next package update. Idempotent; a failure never stops the caller (the
 * result is returned and the next upgrade or prepare tries again).
 */
final class CacheCleanTimer
{
    public const TIMER = 'ols-cpanel-cache-clean.timer';

    /** @return bool the timer is enabled and started */
    public static function ensure(Host $host): bool
    {
        if ($host->run('cache-clean-timer-enabled', [Host::SYSTEMCTL, 'is-enabled', '--quiet', self::TIMER])['exit_code'] === 0
            && $host->unitActive(self::TIMER, 'cache-clean-timer-active')) {
            return true;
        }
        return $host->run('cache-clean-timer-enable', [Host::SYSTEMCTL, 'enable', '--now', self::TIMER])['exit_code'] === 0;
    }
}
