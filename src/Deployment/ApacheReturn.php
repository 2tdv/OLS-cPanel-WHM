<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Cli\Application;

/**
 * `apache-return --prepare | --execute`: the latest backup's recover.sh (the file the recovery timer would run)
 * returns the host to Apache; the product then removes its hook registrations and verifies the result.
 *
 * Review RV-29: the backup and the deployment state are chosen and validated under the deployment lock (taken
 * after the approval, waiting up to Environment::DRAIN_SECONDS for a running reconcile pass to finish), and must
 * still be what was approved; recover.sh runs under that lock (OLS_CPANEL_DEPLOYMENT_LOCK=held). The recovery
 * timer is disarmed only once Apache is verified serving; a failed recovery keeps it, or arms it again.
 */
final class ApacheReturn
{
    public function __construct(private Environment $env)
    {
    }

    /**
     * What --execute would do, and whether the backup is intact (recover.sh sha256 as recorded in the manifest).
     * @return array<string,mixed>
     */
    public function prepare(): array
    {
        $this->env->requireRoot();
        $backup = (new Backup($this->env))->latest();
        if ($backup === null) {
            throw DeploymentError::refused('no cutover backup found in ' . $this->env->backupsDir());
        }
        $actions = ['stop ' . Cutover::RECONCILER];
        $actions[] = 'run ' . $backup['dir'] . '/recover.sh: stop and disable ' . implode(', ', RecoveryScript::PRODUCT_UNITS)
            . ', remove ' . RecoveryScript::PRODUCT_PROFILE;
        if (($backup['hybrid'] ?? false) === true) {
            $tweaks = [];
            foreach ((array) ($backup['tweaks'] ?? []) as $key => $value) {
                $tweaks[] = "$key=$value";
            }
            $actions[] = 'remove ' . HybridHost::REMOTEIP_CONF . ', restore ' . implode(', ', $tweaks)
                . ', rebuild the Apache configuration';
        }
        $firewall = $backup['http3']['firewall'] ?? null;
        if (is_array($firewall) && ($firewall['action'] ?? null) === 'add') {
            $actions[] = 'undo the UDP 443 change in ' . $firewall['type'] . ' (' . $firewall['detail'] . '): '
                . ($firewall['type'] === 'csf' ? 'csf.conf restored byte for byte while it is unchanged since the cutover, csf restarted'
                    : '443/udp removed from zone ' . ($firewall['zone'] ?? '?') . ' where the product added it (runtime and/or permanent), no firewalld reload');
        }
        $actions[] = 'enable, monitor and restart Apache; retry until Apache owns 80/443'
            . (($backup['hybrid'] ?? false) === true ? ', then delete nftables table inet ' . HybridHost::NFT_TABLE : '');
        $actions[] = "resynchronise cPanel's FileProtect";
        $actions[] = 'remove the cPanel hook registrations of ' . $this->env->hookEntry;
        $actions[] = 'verify the result';
        return ['backup' => $backup['id'], 'plan' => $backup['plan'] ?? null, 'created' => $backup['created'] ?? null,
            'intact' => $backup['intact'], 'problem' => $backup['problem'], 'recover_sh_sha256' => $backup['recover_sh_sha256'] ?? null,
            'cut_over' => file_exists($this->env->profilePath()),
            'hybrid' => $backup['hybrid'] ?? null, 'actions' => $actions];
    }

    /**
     * @param \Closure(array<string,mixed>):bool $approve shown the prepared summary
     * @return array<string,mixed> outcome ("result": returned | nothing_to_do | failed)
     */
    public function execute(\Closure $approve): array
    {
        $shown = $this->intact();
        if ($this->nothingToDo($shown)) {
            return self::nothing($shown);
        }
        if (!$approve($shown)) {
            throw DeploymentError::refused('return to Apache not approved; nothing was changed');
        }
        $lock = $this->env->lock(Environment::DRAIN_SECONDS);
        try {
            $summary = $this->intact();
            if ($this->nothingToDo($summary)) {
                return self::nothing($summary);
            }
            if ($summary['backup'] !== $shown['backup'] || $summary['recover_sh_sha256'] !== $shown['recover_sh_sha256']) {
                throw DeploymentError::refused("the latest backup is now {$summary['backup']}, not the approved {$shown['backup']}; "
                    . 'nothing was changed; run apache-return again');
            }
            return $this->executeLocked($summary);
        } finally {
            fclose($lock);
        }
    }

    /**
     * The summary of the latest backup, refused unless it is intact.
     * @return array<string,mixed>
     */
    public function intact(): array
    {
        $summary = $this->prepare();
        if (!$summary['intact']) {
            throw DeploymentError::refused("backup {$summary['backup']} is not intact: {$summary['problem']}");
        }
        return $summary;
    }

    /** Not cut over and Apache verified serving. */
    public function nothingToDo(array $summary): bool
    {
        return !$summary['cut_over'] && $this->env->host->apacheServes();
    }

    /** @return array<string,mixed> */
    private static function nothing(array $summary): array
    {
        return ['result' => 'nothing_to_do', 'backup' => $summary['backup'], 'reason' => 'not cut over and Apache serves 80/443'];
    }

    /**
     * The return under the already held deployment lock, with a summary chosen under it (execute, uninstall).
     * @return array<string,mixed>
     */
    public function executeLocked(array $summary): array
    {
        $host = $this->env->host;
        $backup = (new Backup($this->env))->load($summary['backup']);
        if (!$backup['intact'] || $backup['recover_sh_sha256'] !== $summary['recover_sh_sha256']) {
            throw DeploymentError::refused("backup {$summary['backup']} changed or is not intact: " . ($backup['problem'] ?? 'recover.sh differs'));
        }
        $script = $backup['dir'] . '/recover.sh';
        $unit = Backup::unit($backup['id']);
        $host->run('stop-reconciler', [Host::SYSTEMCTL, 'stop', Cutover::RECONCILER]);
        $run = $host->run('recovery-run', RecoveryScript::heldArgv($script), Cutover::RECOVERY_TIMEOUT);
        $hooks = null;
        try {
            $hooks = $this->env->hooks()->remove();
        } catch (DeploymentError $error) {
            $hooks = ['ok' => false, 'error' => $error->getMessage()];
        }
        $checks = $this->verify($backup);
        $served = $run['exit_code'] === 0 && $checks['apache_enabled_monitored_running'] && $checks['apache_owns_80_443']
            && $checks['apache_answers'];
        if ($served) {
            // Only verified Apache service ends the fallback (review RV-29 finding 7).
            $host->run('disarm-recovery', [Host::SYSTEMCTL, 'stop', "$unit.timer", "$unit.service"]);
            $recovery = ['timer_disarmed' => !$host->unitActive("$unit.timer", 'recovery-disarmed')
                && !$host->unitActive("$unit.service", 'recovery-idle')];
        } else {
            $recovery = ['timer_disarmed' => false, 'timer_armed' => $host->keepRecoveryArmed($unit, $script, Cutover::RETRY_DELAY)];
        }
        $ok = $served && !in_array(false, $checks, true) && $recovery['timer_disarmed'];
        return ['result' => $ok ? 'returned' : 'failed', 'backup' => $backup['id'],
            'recovery' => ['exit_code' => $run['exit_code'], 'output' => Host::tail($run['stdout'] . ' ' . ($run['stderr'] ?? ''))] + $recovery,
            'hooks' => $hooks, 'checks' => $checks, 'http3_firewall_restored' => $this->http3Restored($backup),
            'failed_checks' => array_keys(array_filter($checks, static fn(bool $v): bool => !$v)),
            'ownership_changed' => $this->ownershipChanges($backup)];
    }

    /**
     * Whether the UDP 443 change of the cutover (FV-04) is gone again; true when none was made. Information only:
     * recover.sh leaves a csf.conf the administrator edited since the cutover alone.
     */
    private function http3Restored(array $backup): bool
    {
        $record = $backup['http3']['firewall'] ?? null;
        if (!is_array($record)) {
            return true;
        }
        try {
            return (new Http3Firewall($this->env->host))->restored($record);
        } catch (DeploymentError) {
            return false;
        }
    }

    /**
     * The checks of a completed return: check => holds.
     * @return array<string,bool>
     */
    public function verify(array $backup): array
    {
        $host = $this->env->host;
        try {
            $status = $host->apacheStatus();
        } catch (DeploymentError) {
            $status = [];
        }
        $answer = trim($host->run('apache-answers', ['/usr/bin/curl', '--noproxy', '*', '-s', '-o', '/dev/null', '-m', '10',
            '-w', '%{http_code}', 'http://127.0.0.1/'], 30)['stdout']);
        $checks = ['apache_enabled_monitored_running' => $status === ['enabled' => true, 'monitored' => true, 'running' => true],
            'apache_owns_80_443' => $host->ownedBy([80, 443], ['httpd']),
            'apache_answers' => preg_match('/^[1-4]\d\d$/D', $answer) === 1,
            'ols_stopped' => !$host->unitActive('ols-cpanel.service', 'ols-stopped'),
            'reconciler_stopped' => !$host->unitActive(Cutover::RECONCILER, 'reconciler-stopped'),
            'profile_absent' => !file_exists($this->env->profilePath())];
        try {
            $checks['hooks_absent'] = $this->env->hooks()->registered() === [];
        } catch (DeploymentError) {
            $checks['hooks_absent'] = false;
        }
        if (($backup['hybrid'] ?? false) === true) {
            $checks += (new HybridHost($host))->verifyRemoved((array) ($backup['tweaks'] ?? []),
                $backup['hybrid_ports'] ?? RecoveryScript::BACKEND_PORTS);
        }
        return $checks;
    }

    /**
     * Docroots whose owner, group or mode differ from the backup's record (information only: FileProtect owns
     * them, and cPanel's own unsuspendacct leaves group "nobody" behind, lab finding LOG-049).
     * @return array<string,string>
     */
    private function ownershipChanges(array $backup): array
    {
        $changed = [];
        foreach ((array) ($backup['docroot_ownership'] ?? []) as $docroot => $before) {
            $stat = $this->env->host->run('docroot-ownership', ['/usr/bin/stat', '-c', '%U:%G:%a', '--', (string) $docroot]);
            $now = $stat['exit_code'] === 0 ? trim($stat['stdout']) : 'absent';
            if ($now !== $before) {
                $changed[(string) $docroot] = "$before -> $now";
            }
        }
        return $changed;
    }

    public static function exitCode(array $outcome): int
    {
        return in_array($outcome['result'] ?? null, ['returned', 'nothing_to_do'], true) ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
