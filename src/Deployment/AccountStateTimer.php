<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/** The root account-state fallback runs even when no account currently uses object cache. */
final class AccountStateTimer
{
    public const TIMER = 'ols-cpanel-objcache.timer';

    /** Best effort at prepare and upgrade; the account pass also keeps its timer enabled. */
    public static function ensure(Host $host): bool
    {
        return $host->run('account-state-timer-enable', [Host::SYSTEMCTL, 'enable', '--now', self::TIMER])['exit_code'] === 0;
    }
}
