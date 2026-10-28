<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * `upgrade`: applies a package upgrade (`dnf upgrade ols-cpanel ols-cpanel-openlitespeed`). Nobody has to run it: the PHP
 * environment pass, which runs after every package transaction, starts ols-cpanel-upgrade.service when the installed versions
 * differ from the ones recorded by the last upgrade (pending()). The long-running product services (the broker and the
 * reconciler) keep the code they started with, so this verifies the installed payload (`rpm -V`, as the cutover does), runs and
 * checks `systemctl daemon-reload` (the package has no scriptlets, so changed unit files must be loaded before the restarts) and
 * restarts each of them that is enabled or active, broker first (the reconciler requires it), then checks that each is active
 * again. The serving state is never touched (the active generation stays); when the running OLS main process still executes a
 * replaced binary, OLS is reloaded gracefully (its ExecReload starts the new binary and drains the old one, no connection is
 * dropped). A package that is missing or does not verify refuses before any restart. The installed versions are recorded
 * only when the hook registration and every timer succeeded as well (`incomplete` lists what did not), so a failure leaves the
 * upgrade pending and it is retried by the next package transaction or by the 15-minute PHP environment timer.
 */
final class Upgrade
{
    public const PACKAGES = [CutoverPlan::PRODUCT_PACKAGE, CutoverPlan::OLS_PACKAGE];
    /** Restart order: the reconciler requires the broker. */
    public const UNITS = [CutoverPlan::BROKER_UNIT, Cutover::RECONCILER];
    /** The unit that runs this command after a package transaction. */
    public const SERVICE = 'ols-cpanel-upgrade.service';
    /** Installed versions applied by the last successful upgrade (root 0600 JSON in the state directory). */
    public const RECORD = 'upgrade.json';
    public const OLS_UNIT = 'ols-cpanel.service';
    public const OLS_PIDFILE = '/run/ols-cpanel/lshttpd/lshttpd.pid';

    public function __construct(private Environment $env)
    {
    }

    /**
     * The installed product package versions, package => version-release.arch; a package that is not installed is absent.
     * @return array<string,string>
     */
    public static function installed(Host $host): array
    {
        $versions = [];
        foreach (self::PACKAGES as $package) {
            $query = $host->run("package-$package", ['/usr/bin/rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', $package]);
            $version = trim($query['stdout']);
            if ($query['exit_code'] === 0 && preg_match('/^[A-Za-z0-9._+~^-]+$/D', $version) === 1) {
                $versions[$package] = $version;
            }
        }
        return $versions;
    }

    /**
     * Whether a package transaction changed the product since the last upgrade on a prepared host (the broker is enabled):
     * the installed versions differ from the record, or there is no record yet.
     */
    public static function pending(Environment $env): bool
    {
        $host = $env->host;
        if (trim($host->run('enabled-broker', [Host::SYSTEMCTL, 'is-enabled', CutoverPlan::BROKER_UNIT])['stdout']) !== 'enabled') {
            return false;
        }
        $installed = self::installed($host);
        if (count($installed) !== count(self::PACKAGES)) {
            return false;
        }
        $text = @file_get_contents($env->state . '/' . self::RECORD);
        $record = is_string($text) ? json_decode($text, true) : null;
        return !is_array($record) || ($record['packages'] ?? null) !== $installed;
    }

    /** @return array<string,mixed> */
    public function run(): array
    {
        $this->env->requireRoot();
        $host = $this->env->host;
        $packages = [];
        foreach (self::PACKAGES as $package) {
            $query = $host->run("package-$package", ['/usr/bin/rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', $package]);
            $version = trim($query['stdout']);
            if ($query['exit_code'] !== 0 || preg_match('/^[A-Za-z0-9._+~^-]+$/D', $version) !== 1) {
                throw DeploymentError::refused("$package is not installed", ['packages' => $packages]);
            }
            // Contents only: OLS itself sets the owner and mode of its runtime directories (cachedata, cgid, tmp,
            // autoupdate) when it starts, so owner, group, mode and time differences are expected, not tampering.
            $verify = $host->run("verify-$package", ['/usr/bin/rpm', '-V', '--nouser', '--nogroup', '--nomode', '--nomtime', $package]);
            $packages[] = ['package' => $package, 'version' => $version, 'verified' => $verify['exit_code'] === 0];
            if ($verify['exit_code'] !== 0) {
                throw DeploymentError::refused("the installed $package files differ from the package: " . Host::tail($verify['stdout'])
                    . ' (nothing was restarted)', ['packages' => $packages]);
            }
        }
        // RV-31 item 13: the RPM has no scriptlets, so changed unit files (hardening, writable paths, ExecStart) are loaded
        // here, after the payload verified and before anything is enabled or restarted; a failure stops the upgrade.
        $reload = $host->run('daemon-reload', [Host::SYSTEMCTL, 'daemon-reload']);
        if ($reload['exit_code'] !== 0) {
            throw DeploymentError::step('daemon-reload', 'systemctl daemon-reload failed: ' . Host::tail(($reload['stderr'] ?? '') . $reload['stdout'])
                . ' (nothing was restarted)', ['packages' => $packages]);
        }
        // The plugin copies cPanel serves must match the installed engine (a stale copy misreports the site).
        $plugins = $this->env->plugins()->deploy();
        // FV-10: the recommended EA4 profile follows cPanel's own default profile and the packages EasyApache offers now.
        try {
            $profile = $this->env->ea4Profile()->write();
        } catch (DeploymentError $error) {
            $profile = ['result' => 'failed', 'error' => $error->getMessage()];
        }
        // The PHP environment units (merged from the earlier php-ext watcher and the OPcache timer): enabled from here on,
        // the old watcher of earlier builds retired. Best effort; the service pass reports what it cannot do.
        $host->run('legacy-watcher', [Host::SYSTEMCTL, 'disable', '--now', 'ols-cpanel-php-ext.path']);
        // `disable --now` fails without stopping once the unit file is gone (lab: still "not-found active"), so stop it apart.
        $host->run('legacy-watcher-stop', [Host::SYSTEMCTL, 'stop', 'ols-cpanel-php-ext.path']);
        $phpUnits = (new \OlsCpanel\Php\OpcacheManager($this->env))->ensureTimer();
        // Timers that `install --prepare` enables, enabled here too on a host prepared by an earlier build (the hybrid trust
        // refresh does nothing without the hybrid profile). Best effort, like the PHP units.
        $prepared = trim($host->run('enabled-broker', [Host::SYSTEMCTL, 'is-enabled', CutoverPlan::BROKER_UNIT])['stdout']) === 'enabled';
        $trust = $prepared && $host->run('hybrid-trust-enable', [Host::SYSTEMCTL, 'enable', '--now', 'ols-cpanel-hybrid-trust.timer'])['exit_code'] === 0;
        // FV-01: the hourly LSCache cleanup, also on hosts prepared before it existed.
        $cacheClean = CacheCleanTimer::ensure($host);
        $accountState = AccountStateTimer::ensure($host);
        // FV-07: the notification and maintenance-window timers, also on hosts prepared before they existed.
        $operationsTimers = $prepared ? OperationsTimers::ensure($host) : [];
        // Hook events added by this release (registered at cutover) are registered here too, so a host cut over by an earlier
        // build gets them. Only where the product's hooks are in use; best effort, reported.
        try {
            $hooks = $this->env->hooks();
            $hookResult = $hooks->registered() === [] ? 'not-installed' : (($hooks->install()['added'] ?? 0) > 0 ? 'updated' : 'current');
        } catch (\Throwable $error) {
            $hookResult = 'failed: ' . $error->getMessage();
        }
        $units = [];
        $failed = false;
        foreach (self::UNITS as $unit) {
            $active = $host->unitActive($unit, "active-$unit");
            $enabled = trim($host->run("enabled-$unit", [Host::SYSTEMCTL, 'is-enabled', $unit])['stdout']) === 'enabled';
            if (!$active && !$enabled) {
                $units[] = ['unit' => $unit, 'enabled' => false, 'was_active' => false, 'action' => 'skipped', 'active' => false];
                continue;
            }
            $record = $host->run("restart-$unit", [Host::SYSTEMCTL, 'restart', $unit]);
            $now = $record['exit_code'] === 0 && $host->waitFor(static fn(): bool => $host->unitActive($unit, "reactive-$unit"), 10, 1.0);
            $failed = $failed || !$now;
            $units[] = ['unit' => $unit, 'enabled' => $enabled, 'was_active' => $active, 'action' => 'restarted', 'active' => $now];
        }
        $ols = $this->reloadStaleOls();
        $failed = $failed || $ols === 'failed';
        // The versions are recorded only when everything this pass sets up succeeded: otherwise the upgrade stays pending and the
        // next package transaction pass, or the PHP environment timer (`php env sync`, every 15 minutes, which starts this service
        // while pending() is true), runs it again.
        $incomplete = array_keys(array_filter([
            'hooks' => str_starts_with($hookResult, 'failed'),
            'php_environment_units' => !$phpUnits,
            'hybrid_trust_timer' => $prepared && !$trust,
            'cache_clean_timer' => !$cacheClean,
            'account_state_timer' => !$accountState,
            'operations_timers' => in_array(false, $operationsTimers, true),
        ]));
        $failed = $failed || $incomplete !== [];
        if (!$failed) {
            $this->record(array_combine(array_column($packages, 'package'), array_column($packages, 'version')));
        }
        return ['result' => $failed ? 'failed' : 'upgraded', 'incomplete' => $incomplete, 'ols' => $ols, 'packages' => $packages, 'plugins' => $plugins, 'ea4_profile' => $profile, 'php_environment_units' => $phpUnits, 'hybrid_trust_timer' => $trust, 'cache_clean_timer' => $cacheClean, 'account_state_timer' => $accountState, 'operations_timers' => $operationsTimers, 'hooks' => $hookResult, 'units' => $units,
            'note' => 'The active generation was not touched.'];
    }

    /**
     * Reloads OLS gracefully when its running main process executes a binary the package has replaced (the kernel marks the
     * executable link " (deleted)"). @return string 'not-running', 'current', 'reloaded' or 'failed'
     */
    private function reloadStaleOls(): string
    {
        $host = $this->env->host;
        if (!$host->unitActive(self::OLS_UNIT, 'active-ols')) {
            return 'not-running';
        }
        $pid = trim($host->run('ols-pid', ['/usr/bin/cat', '--', self::OLS_PIDFILE])['stdout']);
        if (preg_match('/^[1-9]\d*$/D', $pid) !== 1) {
            return 'current';
        }
        $exe = trim($host->run('ols-exe', ['/usr/bin/readlink', "/proc/$pid/exe"])['stdout']);
        if (!str_ends_with($exe, ' (deleted)')) {
            return 'current';
        }
        $record = $host->run('reload-ols', [Host::SYSTEMCTL, 'reload', self::OLS_UNIT], 180);
        $active = $record['exit_code'] === 0 && $host->waitFor(fn(): bool => $host->unitActive(self::OLS_UNIT, 'reactive-ols'), 30, 1.0);
        return $active ? 'reloaded' : 'failed';
    }

    /** @param array<string,string> $packages */
    private function record(array $packages): void
    {
        $path = $this->env->state . '/' . self::RECORD;
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        if (@file_put_contents($tmp, json_encode(['packages' => $packages, 'upgraded_at' => time()], JSON_PRETTY_PRINT) . "\n") === false
            || !@chmod($tmp, 0600) || !@rename($tmp, $path)) {
            @unlink($tmp);
        }
    }
}
