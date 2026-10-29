<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\ObjectCache\ObjectCacheManager;
use OlsCpanel\Php\OpcacheManager;
use OlsCpanel\PhpExtensions\ExtensionInstaller;

/**
 * `uninstall [--dry-run] [--keep-packages] [--keep-backups]`: the return to Apache when cut over, hook registrations
 * removed, product units disabled and stopped, and the state directory removed (backups/, the record of every cutover and
 * its recovery script, only with --keep-backups). The server is left as it was before the product: LiteSpeed Cache's object cache is switched off again on the
 * WordPress sites where the product switched it on (only while the site still uses the product's socket), the product's OPcache INI
 * files and per-account systemd drop-ins are removed, and after a fully successful cleanup the product packages are removed by a
 * transient unit outside this process (dnf; `--keep-packages` leaves them), which then removes what the packages leave
 * behind: OpenLiteSpeed's runtime files in /usr/local/lsws, the state directory, the olscpanel system user and the valkey
 * user of a Valkey that dnf removed with them (PURGE). Nothing of the product stays (an owner's test on a second server,
 * 2026-10-29, found those leftovers). Kept: the OPcache packages and everything the product did not install. A dry run only reads.
 *
 * Review RV-29: nothing is removed unless Apache is verified serving (enabled, monitored and running, the only
 * owner of 80/443, answering) under the deployment lock, whatever profile.json says: a recovery interrupted
 * after it removed the profile still leads to the return to Apache first, and without a backup to return with
 * uninstall refuses. A product unit that does not stop aborts the cleanup.
 */
final class Uninstall
{
    // The object cache applier (FV-09) first, so no instance is started again while the others stop.
    // ols-cpanel-php-ext.* are the units of earlier builds (merged into the PHP environment units); stopped if still present.
    public const UNITS = ['ols-cpanel-php-ext.path', 'ols-cpanel-php-ext.service', 'ols-cpanel-objcache.timer', 'ols-cpanel-objcache.service',
        'ols-cpanel-cache-clean.timer', 'ols-cpanel-cache-clean.service', 'ols-cpanel-notify.timer', 'ols-cpanel-notify.service',
        'ols-cpanel-schedule.timer', 'ols-cpanel-schedule.service',
        'ols-cpanel-php.path', 'ols-cpanel-php.timer', 'ols-cpanel-php.service', 'ols-cpanel-upgrade.service', 'ols-cpanel-hybrid-trust.timer',
        'ols-cpanel-hybrid-trust.service', HybridHost::FIREWALL_UNIT, Cutover::RECONCILER, 'ols-cpanel.service',
        'ols-cpanel-logs.service', CutoverPlan::BROKER_UNIT];
    /** Every per-account object cache instance (FV-09), stopped by pattern. */
    public const OBJCACHE_INSTANCES = 'ols-cpanel-objcache@*.service';
    /** Units of earlier builds (merged into the PHP environment units); their unit files may already be gone. */
    public const LEGACY_UNITS = ['ols-cpanel-php-ext.path', 'ols-cpanel-php-ext.service'];
    /** The product packages, removed together (the spec has no scriptlets, so the removal never calls back into uninstall). */
    public const PACKAGES = ['ols-cpanel', 'ols-cpanel-openlitespeed', 'ols-cpanel-php-redis'];
    /** The transient unit that runs dnf outside this process (which lives in a package being removed). */
    public const REMOVE_UNIT = 'ols-cpanel-remove-packages';
    public const RPM = '/usr/bin/rpm';
    public const SYSTEMD_RUN = '/usr/bin/systemd-run';
    public const DNF = '/usr/bin/dnf';
    /**
     * Run by the transient unit: `sh -c PURGE sh <state dir> <packages...>`. After dnf, only what no package owns any more:
     * /usr/local/lsws when no package owns it and no other LiteSpeed is there (bin/), the state directory's lock (and the
     * directory when nothing else is in it), the olscpanel user and group, and the valkey user and group when Valkey is no
     * longer installed (dnf removes it with the product when the product brought it) and runs nothing.
     */
    public const PURGE = 'state=$1; shift; /usr/bin/dnf -y remove "$@" || exit 1; '
        . 'if ! /usr/bin/rpm -q ols-cpanel-openlitespeed >/dev/null 2>&1 && ! /usr/bin/rpm -qf /usr/local/lsws >/dev/null 2>&1 '
        . '&& [ ! -e /usr/local/lsws/bin ]; then /usr/bin/rm -rf -- /usr/local/lsws; fi; '
        . '/usr/bin/rm -f -- "$state/deployment.lock"; /usr/bin/rmdir -- "$state" 2>/dev/null; '
        . 'for u in olscpanel valkey; do '
        . 'if [ "$u" = valkey ] && /usr/bin/rpm -q valkey >/dev/null 2>&1; then continue; fi; '
        . 'if [ "$u" = olscpanel ] && /usr/bin/rpm -q ols-cpanel >/dev/null 2>&1; then continue; fi; '
        . 'if /usr/bin/getent passwd "$u" >/dev/null && ! /usr/bin/pgrep -u "$u" >/dev/null; then /usr/sbin/userdel "$u"; fi; '
        . 'if /usr/bin/getent group "$u" >/dev/null; then /usr/sbin/groupdel "$u" 2>/dev/null; fi; '
        . 'done; exit 0';

    public function __construct(private Environment $env)
    {
    }

    /** @return array<string,mixed> actions done (or, with $dryRun, that would be done) */
    public function run(bool $dryRun, bool $keepPackages = false, bool $keepBackups = false): array
    {
        $this->env->requireRoot();
        if (!is_dir($this->env->state)) {
            $actions = [];
            $next = $this->packages($dryRun, $keepPackages, $actions);
            return ['result' => $dryRun ? 'dry_run' : 'uninstalled', 'actions' => $actions, 'kept' => [], 'next' => $next];
        }
        $lock = $dryRun ? null : $this->env->lock(Environment::DRAIN_SECONDS);
        try {
            return $this->locked($dryRun, $keepPackages, $keepBackups);
        } finally {
            if ($lock !== null) {
                fclose($lock);
            }
        }
    }

    /** @return array<string,mixed> */
    private function locked(bool $dryRun, bool $keepPackages, bool $keepBackups): array
    {
        $actions = [];
        $return = new ApacheReturn($this->env);
        $cutOver = file_exists($this->env->profilePath());
        if ($cutOver || !$this->env->host->apacheServes()) {
            if ((new Backup($this->env))->latest() === null) {
                throw DeploymentError::refused('Apache is not verified serving 80/443 and there is no cutover backup to return with; '
                    . 'nothing was removed');
            }
            $summary = $return->prepare();
            if (!$summary['intact']) {
                throw DeploymentError::refused(($cutOver ? 'cut over' : 'Apache is not verified serving 80/443')
                    . ", but backup {$summary['backup']} is not intact: {$summary['problem']}");
            }
            if ($dryRun) {
                $actions[] = ['action' => 'apache-return', 'backup' => $summary['backup'], 'steps' => $summary['actions']];
            } else {
                $outcome = $return->executeLocked($summary);
                $actions[] = ['action' => 'apache-return'] + $outcome;
                if ($outcome['result'] === 'failed') {
                    return ['result' => 'failed', 'actions' => $actions,
                        'error' => 'the return to Apache did not verify; nothing else was removed'];
                }
            }
        }
        if (!$dryRun && !$this->env->host->apacheServes()) {
            return ['result' => 'failed', 'actions' => $actions,
                'error' => 'Apache is not verified serving 80/443; nothing was removed'];
        }
        $hooks = $this->env->hooks();
        $registered = count($hooks->registered());
        if ($registered > 0) {
            $actions[] = $dryRun ? ['action' => 'remove hook registrations', 'count' => $registered]
                : ['action' => 'remove hook registrations'] + $hooks->remove();
        }
        $actions[] = $dryRun ? ['action' => 'unregister and remove the WHM and cPanel plugins']
            : ['action' => 'unregister and remove the WHM and cPanel plugins', 'done' => $this->env->plugins()->remove()];
        foreach (self::UNITS as $unit) {
            if ($dryRun) {
                $actions[] = ['action' => "disable and stop $unit"];
                continue;
            }
            $record = $this->env->host->run('disable-unit', [Host::SYSTEMCTL, 'disable', '--now', $unit]);
            $stopped = $this->env->host->unitStopped($unit, 'unit-stopped');
            $ok = $record['exit_code'] === 0 && $stopped;
            if (!$ok && $stopped && in_array($unit, self::LEGACY_UNITS, true)) {
                // A unit of an earlier build whose file is gone: `disable` fails and leaves its enable link behind
                // (lab 2026-10-28). It is stopped; its links are removed, which is all that is left of it.
                foreach (['paths.target.wants', 'multi-user.target.wants', 'timers.target.wants'] as $wants) {
                    $this->env->host->run('legacy-unit-link', ['/usr/bin/rm', '-f', '--', "{$this->env->unitDir}/$wants/$unit"]);
                }
                $ok = true;
            }
            $actions[] = ['action' => "disable and stop $unit", 'ok' => $ok, 'stopped' => $stopped];
            if (!$stopped) {
                return ['result' => 'failed', 'actions' => $actions,
                    'error' => "$unit did not stop; the state directory was not removed"];
            }
        }
        // The sites' object cache goes off while the applier is stopped and before the instances (and their sockets) go away.
        $objcache = new ObjectCacheManager($this->env->runner, statePath: $this->env->state . '/objcache.json',
            confRoot: $this->env->state . '/objcache', unitDir: $this->env->unitDir, lockPath: $dryRun ? null : $this->env->state . '/objcache.lock');
        foreach ($objcache->revertWordPress($dryRun) as $site) {
            if ($site['result'] === 'unchanged') {
                continue;
            }
            $actions[] = ['action' => ($dryRun ? 'turn off' : 'turned off') . " the object cache of LiteSpeed Cache in {$site['account']}:{$site['path']}",
                'result' => $site['result'], 'reason' => $site['reason']] + ($site['result'] === 'error' ? ['ok' => false] : []);
        }
        if ($dryRun) {
            $actions[] = ['action' => 'stop every object cache instance'];
        } else {
            $record = $this->env->host->run('objcache-stop', [Host::SYSTEMCTL, 'stop', self::OBJCACHE_INSTANCES]);
            $actions[] = ['action' => 'stop every object cache instance', 'ok' => $record['exit_code'] === 0];
            if ($record['exit_code'] !== 0) {
                return ['result' => 'failed', 'actions' => $actions,
                    'error' => 'object cache instances did not stop; the state directory was not removed'];
            }
            // Their slice stays active (empty) until a reboot otherwise.
            $this->env->host->run('objcache-slice-stop', [Host::SYSTEMCTL, 'stop', 'system-ols\\x2dcpanel\\x2dobjcache.slice']);
        }
        // The per-account systemd drop-ins of the instances (only the product's own file in a directory of its name).
        foreach ($objcache->removeDropIns($dryRun) as $dropIn) {
            $actions[] = ['action' => ($dryRun ? 'remove' : ($dropIn['result'] === 'removed' ? 'removed' : 'did not remove')) . ' the systemd drop-in ' . $dropIn['path']]
                + (isset($dropIn['reason']) ? ['reason' => $dropIn['reason']] : []) + ($dropIn['result'] === 'error' ? ['ok' => false] : []);
        }
        // Each account's ~/.ols-objcache (the socket directory, recreated by the wp-cli runs of the revert above), as the account.
        foreach ($objcache->removeSocketDirs($dryRun) as $dir) {
            $actions[] = ['action' => ($dryRun ? 'remove' : ($dir['result'] === 'removed' ? 'removed' : 'did not remove')) . ' ' . $dir['path']]
                + (isset($dir['reason']) ? ['reason' => $dir['reason']] : []) + ($dir['result'] === 'error' ? ['ok' => false] : []);
        }
        // The PHP redis extension: only the INI files this product wrote below /opt/cpanel (never another file).
        $extensions = new ExtensionInstaller($this->env->runner, phpRoot: $this->env->phpRoot, stateRoot: $this->env->state . '/php-ext');
        $inis = $dryRun ? $extensions->ownInis() : array_column($extensions->removeInis()['versions'], 'php');
        if ($inis !== []) {
            $actions[] = ['action' => ($dryRun ? 'remove' : 'removed') . ' the PHP redis extension INI of ' . implode(', ', $inis)];
        }
        // The OPcache tuning INI (only a file that carries the product's first line; the OPcache packages stay installed).
        $opcache = new OpcacheManager($this->env, optRoot: $this->env->phpRoot);
        if ($dryRun) {
            if (($own = $opcache->ownInis()) !== []) {
                $actions[] = ['action' => 'remove the OPcache INI of ' . implode(', ', $own)];
            }
        } else {
            foreach ($opcache->removeInis() as $row) {
                $actions[] = ['action' => ($row['status'] === 'removed' ? 'removed' : 'did not remove') . ' the OPcache INI of ' . $row['php']]
                    + ($row['status'] === 'removed' ? [] : ['ok' => false]);
            }
        }
        // FV-10: the recommended EA4 profile (only the file of that name, only when it is ours).
        $profile = $this->env->ea4Profile();
        if ($dryRun ? $profile->present() : $profile->remove()['result'] === 'removed') {
            $actions[] = ['action' => ($dryRun ? 'remove' : 'removed') . ' the recommended EA4 profile ' . $profile->path()];
        }
        $remove = [];
        foreach (scandir($this->env->state) ?: [] as $name) {
            // The lock is held until the end; the package removal's PURGE removes it with the directory.
            if (!in_array($name, ['.', '..', 'deployment.lock', ...($keepBackups ? ['backups'] : [])], true)) {
                $remove[] = $this->env->state . "/$name";
            }
        }
        sort($remove, SORT_STRING);
        foreach ($remove as $path) {
            if (!$dryRun) {
                self::delete($path);
            }
            $actions[] = ['action' => "remove $path"];
        }
        if (!$dryRun) {
            // recover.sh's lock file under /run (it would otherwise stay until a reboot).
            $this->env->host->run('recover-lock-remove', ['/usr/bin/rm', '-f', '--', RecoveryScript::LOCK]);
            // The release key the installer imported into the rpm database (gpg-pubkey-<last 8 hex of the fingerprint>).
            $fingerprint = @file_get_contents(\OlsCpanel\Operations\ReleaseChannel::FINGERPRINT);
            if (is_string($fingerprint) && preg_match('/^[0-9A-F]{40}$/D', trim($fingerprint)) === 1) {
                $this->env->host->run('release-key-remove', ['/usr/bin/rpm', '-e', '--allmatches', 'gpg-pubkey-' . strtolower(substr(trim($fingerprint), -8))]);
            }
            // The preparation report the installer keeps for support.
            $this->env->host->run('prepare-report-remove', ['/usr/bin/rm', '-f', '--', '/root/ols-cpanel-prepare.json']);
        }
        $next = $this->packages($dryRun, $keepPackages, $actions);
        return ['result' => $dryRun ? 'dry_run' : 'uninstalled', 'actions' => $actions, 'kept' => $keepBackups ? [$this->env->backupsDir()] : [],
            'next' => $next];
    }

    /**
     * Starts the removal of the installed product packages in a transient unit (this process runs from one of them), unless
     * $keep. Only reached after every earlier step succeeded. A dry run only lists it.
     * @param list<array<string,mixed>> $actions
     * @return string the "next" text of the result
     */
    private function packages(bool $dryRun, bool $keep, array &$actions): string
    {
        $installed = array_values(array_filter(self::PACKAGES,
            fn(string $package): bool => $this->env->host->run('package-installed', [self::RPM, '-q', $package])['exit_code'] === 0));
        $manual = 'remove the packages: dnf remove ' . implode(' ', $installed !== [] ? $installed : self::PACKAGES);
        if ($installed === []) {
            return 'no product package is installed';
        }
        if ($keep) {
            return $manual . ' (kept because of --keep-packages)';
        }
        $argv = [self::SYSTEMD_RUN, '--unit=' . self::REMOVE_UNIT, '--no-block', '--collect', '/bin/sh', '-c', self::PURGE, 'sh',
            $this->env->state, ...$installed];
        if ($dryRun) {
            $actions[] = ['action' => 'remove the packages ' . implode(', ', $installed) . ' (dnf, in the unit ' . self::REMOVE_UNIT . ')'];
            $actions[] = ['action' => 'then remove what they leave: OpenLiteSpeed runtime files in /usr/local/lsws, ' . $this->env->state
                . ', the olscpanel user, and the valkey user if Valkey was removed with them'];
            return 'the packages would be removed; --keep-packages leaves them';
        }
        $record = $this->env->host->run('remove-packages', $argv, 60);
        $started = $record['exit_code'] === 0;
        $actions[] = ['action' => 'remove the packages ' . implode(', ', $installed) . ' (dnf, in the unit ' . self::REMOVE_UNIT . ')', 'ok' => $started];
        return $started ? 'the packages are being removed in the background (journalctl -u ' . self::REMOVE_UNIT . ')'
            : "dnf could not be started: $manual";
    }

    /** Removes a path below the state directory without following symlinks. */
    private static function delete(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            if (!unlink($path)) {
                throw DeploymentError::refused("cannot remove $path");
            }
            return;
        }
        if (is_dir($path)) {
            foreach (scandir($path) ?: [] as $name) {
                if ($name !== '.' && $name !== '..') {
                    self::delete("$path/$name");
                }
            }
            if (!rmdir($path)) {
                throw DeploymentError::refused("cannot remove $path");
            }
        }
    }
}
