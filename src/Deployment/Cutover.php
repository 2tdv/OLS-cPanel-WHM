<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Cli\Application;

/**
 * `install --cutover --plan=<id>`: moves 80/443 from Apache to OLS, or returns everything to Apache.
 *
 * Order (each step checked; any failure after the timer is armed runs recover.sh synchronously):
 *  1. plan loaded, approval, lock (the deployment lock, exclusive for the whole transaction: no reconcile pass
 *     and no recover.sh runs beside it), the plan read again and required unchanged since the approval,
 *     preflight again (no profile, OLS stopped, Apache the healthy owner of 80/443, suEXEC when the plan has
 *     hybrid vhosts), recompile with the plan's profile: a different full compile digest (configuration and
 *     every referenced certificate, key and password file, CutoverPlan::digest) refuses the stale plan;
 *     Apache's answer for every vhost recorded (HTTP and HTTPS); the digest checked once more immediately
 *     before the first host change.
 *  2. Backup and recover.sh (Backup), then the recovery timer armed (systemd-run --on-active=45min): from here
 *     on the host returns to Apache even if this process dies.
 *  3. Hooks registered: an event between this compile and the activation is spooled and raises the epoch.
 *  4. Hybrid host changes (HybridHost::apply), or Apache disabled and unmonitored; wait until Apache released
 *     80/443.
 *  5. profile.json written, then ConfigurationActivator::activate() (the reconciler's forced pass) with the
 *     plan's digest: the activator refuses a compile that differs from the approved plan (review RV-29).
 *     The activator is deliberately run with OLS stopped, and OLS is not started before it: the activator's
 *     reload step starts ols-cpanel.service when it is not running (ols_generation.reload), inside the
 *     activation transaction (intent, switched, reloaded with the start's exit code, marker and per-vhost
 *     health, committed), exactly as the lab's first `reconcile --force` did. Starting OLS first would either
 *     fail (first cutover: no active generation, so no main configuration) or serve the previous generation
 *     outside any journal transaction (a cutover after a return to Apache). Committed is required.
 *  6. `systemctl start ols-cpanel.service ols-cpanel-logs.service` (idempotent after the activation; asserts
 *     both units), OLS the only owner of 80/443, cPanel's FileProtect resynchronised while OLS runs (cPanel
 *     then gives docroots the group "nobody"), every vhost answering through OLS with the status Apache gave.
 *  7. Units enabled for boot (OLS, log shipper) and the reconciler enabled and started (its passes wait for
 *     the deployment lock); the outcome written durably to cutover.json; only then the timer disarmed and a
 *     recovery service the timer may have started (necessarily still waiting for the deployment lock) stopped,
 *     both verified inactive. A failure of the record or of the disarm is a failed cutover and runs recover.sh.
 * recover.sh runs under the held lock with OLS_CPANEL_DEPLOYMENT_LOCK=held; the timer is disarmed after it
 * only once Apache is verified serving, and armed again if a failed recovery left it inactive.
 */
final class Cutover
{
    public const UNITS = ['ols-cpanel.service', 'ols-cpanel-logs.service'];
    public const RECONCILER = 'ols-cpanel-reconciler.service';
    public const RECOVERY_DELAY = '45min';
    public const RECOVERY_TIMEOUT = 3600;
    /** Delay of a recovery timer armed again after a failed recovery. */
    public const RETRY_DELAY = '10min';

    /** @var list<array{step:string, ok:bool, detail?:mixed}> */
    private array $steps = [];
    /** @var list<string> things the administrator should know that do not fail the cutover (HTTP/3 firewall) */
    private array $warnings = [];

    public function __construct(private Environment $env)
    {
    }

    /**
     * @param \Closure(array<string,mixed>):bool $approve shown the plan; false refuses without any change
     * @return array<string,mixed> the outcome ("result": cut_over | failed); refusals throw DeploymentError
     */
    public function run(string $planId, \Closure $approve): array
    {
        $this->env->requireRoot();
        $planner = new CutoverPlan($this->env);
        $shown = $planner->load($planId);
        if ($this->env->activator === null) {
            throw DeploymentError::refused('the configuration activator is not available in this installation');
        }
        if (!$approve($shown)) {
            throw DeploymentError::refused('cutover not approved; nothing was changed');
        }
        $lock = $this->env->lock();
        try {
            // Everything is chosen and validated again under the lock (review RV-29 finding 14).
            $plan = $planner->load($planId);
            if ($plan !== $shown) {
                throw DeploymentError::refused("plan $planId changed after it was shown for approval; nothing was changed");
            }
            return $this->locked($planner, $plan);
        } finally {
            fclose($lock);
        }
    }

    /** @return array<string,mixed> */
    private function locked(CutoverPlan $planner, array $plan): array
    {
        $checks = [];
        $planner->preflight($checks);
        $ports = $plan['profile']['hybrid_ports'];
        if ($ports !== null) {
            $planner->requireSuexec($checks);
        }
        $this->record('preflight', true, array_column($checks, 'name'));
        $compiled = $this->current($planner, $plan, 'plan-current');
        $baseline = $this->answers($compiled['plan'], 'apache');
        $silent = array_keys(array_filter($baseline, static fn(string $code): bool => $code === '000'));
        if ($silent !== []) {
            throw DeploymentError::refused('Apache does not answer for ' . implode(', ', $silent));
        }
        $this->record('apache-baseline', true, count($baseline) . ' requests');
        // Immediately before the first host change: the inputs are still the approved ones (review RV-29 finding 10).
        $compiled = $this->current($planner, $plan, 'plan-recheck');

        $id = $this->env->newId('c');
        $manifest = (new Backup($this->env))->create($id, $plan, $compiled['plan']);
        $this->record('backup', true, $manifest['dir']);
        $script = $manifest['dir'] . '/recover.sh';
        $unit = Backup::unit($id);
        $this->env->host->must('arm-recovery', ['/usr/bin/systemd-run', "--unit=$unit", '--on-active=' . self::RECOVERY_DELAY,
            '--timer-property=AccuracySec=1s', '/bin/sh', $script]);
        $this->record('recovery-armed', true, $unit);
        $record = $manifest['dir'] . '/cutover.json';
        try {
            $this->change($plan, $compiled, $baseline, $manifest);
            // The final record is part of the guarded transaction, and the fallback goes only once it is durable
            // (review RV-29 finding 15).
            $outcome = ['result' => 'cut_over', 'plan' => $plan['id'], 'backup' => $id, 'profile' => $plan['profile'],
                'hybrid_vhosts' => array_column($plan['hybrid_vhosts'], 'vhost'), 'steps' => $this->steps]
                + ($this->warnings === [] ? [] : ['warnings' => $this->warnings]);
            try {
                Environment::writeFile($record, Environment::json($outcome), 0600);
            } catch (DeploymentError $error) {
                throw DeploymentError::step('record', $error->getMessage());
            }
            $this->record('recorded', true, $record);
            $this->disarm($unit);
        } catch (\Throwable $error) {
            // Anything (a failed step, an unwritable profile or record, an internal error) returns the host to Apache.
            $message = $error instanceof DeploymentError ? $error->getMessage()
                : (new \ReflectionClass($error))->getShortName() . ': ' . Host::tail($error->getMessage());
            $this->record($error instanceof DeploymentError && $error->step !== '' ? $error->step : 'cutover', false, $message);
            $recovery = $this->recover($script, $unit);
            $outcome = ['result' => 'failed', 'plan' => $plan['id'], 'backup' => $id, 'error' => $message,
                'recovery' => $recovery, 'steps' => $this->steps];
            try {
                Environment::writeFile($record, Environment::json($outcome), 0600);
            } catch (\Throwable $unwritable) {
                $outcome['record_error'] = Host::tail($unwritable->getMessage());
            }
            return $outcome;
        }
        $outcome['steps'] = $this->steps;
        if ($this->warnings !== []) {
            $outcome['warnings'] = $this->warnings;
        }
        try {
            Environment::writeFile($record, Environment::json($outcome), 0600);  // completes the durable record
        } catch (\Throwable $unwritable) {
            $outcome['record_warning'] = 'cutover.json lacks the disarm step: ' . Host::tail($unwritable->getMessage());
        }
        return $outcome;
    }

    /**
     * A fresh compile with the plan's profile, refused unless its full digest (configuration and referenced
     * files) and its hybrid vhosts are the plan's.
     * @return array<string,mixed>
     */
    private function current(CutoverPlan $planner, array $plan, string $step): array
    {
        $compiled = $planner->compile($plan['profile']['hybrid_ports']);
        if (!hash_equals($plan['compile_sha256'], CutoverPlan::digest($compiled, $planner->referencedFiles($compiled)))) {
            throw DeploymentError::refused("the cPanel state or a certificate, key or password file it references changed since plan "
                . "{$plan['id']} was prepared; run install --prepare again");
        }
        $hybridNow = array_column(CutoverPlan::hybridVhosts($compiled), 'vhost');
        if ($hybridNow !== array_column($plan['hybrid_vhosts'], 'vhost')) {
            throw DeploymentError::refused('the hybrid vhosts changed; run install --prepare again');
        }
        $this->record($step, true);
        return $compiled;
    }

    /**
     * Ends the fallback of a completed cutover: the timer stopped, and a recovery service it started stopped too
     * (it cannot have changed anything: it waits for the deployment lock this cutover holds); both verified.
     */
    private function disarm(string $unit): void
    {
        $host = $this->env->host;
        $host->run('disarm-recovery', [Host::SYSTEMCTL, 'stop', "$unit.timer", "$unit.service"]);
        if ($host->unitActive("$unit.timer", 'recovery-disarmed')) {
            throw DeploymentError::step('disarm-recovery', "$unit.timer is still active");
        }
        if ($host->unitActive("$unit.service", 'recovery-idle')) {
            throw DeploymentError::step('disarm-recovery', "the recovery service $unit.service is still active");
        }
        $this->record('recovery-disarmed', true);
    }

    /** Steps 3 to 7 up to the record; throws DeploymentError on the first failure. */
    private function change(array $plan, array $compiled, array $baseline, array $manifest): void
    {
        $host = $this->env->host;
        $ports = $plan['profile']['hybrid_ports'];
        $this->record('hooks', true, $this->env->hooks()->install());
        if ($ports !== null) {
            (new HybridHost($host, $this->env->state))->apply(HybridHost::proxies($compiled['plan']), $ports, $manifest['dir'] . '/staged');
            // The table is in memory only: the boot unit loads the persisted ruleset before the network and Apache start.
            $host->must('hybrid-firewall-enable', [Host::SYSTEMCTL, 'enable', HybridHost::FIREWALL_UNIT]);
            $this->record('hybrid-host', true, "Apache on {$ports[0]}/{$ports[1]}");
        } else {
            $host->api('disable-httpd', 'configureservice', ['service=httpd', 'enabled=0', 'monitored=0']);
            $this->record('apache-disabled', true);
        }
        if (!$host->waitFor(fn(): bool => $host->free([80, 443], 'apache-released'), 30, 2)) {
            throw DeploymentError::step('apache-released', 'ports 80/443 are still in use');
        }
        $this->record('apache-released', true);
        $profile = new Profile(true, $ports);
        $profile->save($this->env->profilePath());
        $this->record('profile', true, json_decode($profile->toJson(), true));
        try {
            $activation = $this->env->activator->activate($plan['compile_sha256']);
        } catch (\Throwable $error) {
            throw DeploymentError::step('activate', get_class($error) . ': ' . Host::tail($error->getMessage()));
        }
        if (($activation['action'] ?? null) !== 'committed') {
            throw DeploymentError::step('activate', 'activation not committed: ' . Host::tail(json_encode($activation) ?: ''));
        }
        if (array_key_exists('hybrid_vhosts', $activation) && $activation['hybrid_vhosts'] != array_column($plan['hybrid_vhosts'], 'vhost')) {
            throw DeploymentError::step('activate', 'the activated generation has other hybrid vhosts than the plan');
        }
        $this->record('activate', true, $activation['generation'] ?? null);
        $host->must('start-ols', [Host::SYSTEMCTL, 'start', ...self::UNITS]);
        foreach (self::UNITS as $unit) {
            if (!$host->unitActive($unit, 'ols-active')) {
                throw DeploymentError::step('start-ols', "$unit is not active");
            }
        }
        if (!$host->waitFor(fn(): bool => $host->ownedBy([80, 443], Host::OLS_PROCESSES, 'ols-listeners'), 10, 2)) {
            throw DeploymentError::step('ols-listeners', 'OLS is not the only owner of 80/443');
        }
        $this->record('ols-serving', true);
        $this->http3Firewall($manifest);
        $host->must('enablefileprotect', ['/usr/local/cpanel/scripts/enablefileprotect'], 300);
        $this->record('fileprotect', true);
        $different = [];
        $healthy = $host->waitFor(function () use ($compiled, $baseline, &$different): bool {
            $now = $this->answers($compiled['plan'], 'ols');
            $different = array_filter($now, static fn(string $code, string $key): bool => $code !== $baseline[$key],
                ARRAY_FILTER_USE_BOTH);
            return $different === [];
        }, 20, 3);
        if (!$healthy) {
            $detail = [];
            foreach ($different as $key => $code) {
                $detail[] = "$key: Apache {$baseline[$key]}, OLS $code";
            }
            throw DeploymentError::step('vhost-health', implode('; ', array_slice($detail, 0, 20)));
        }
        $this->record('vhost-health', true, count($baseline) . ' requests equal to Apache');
        $host->must('enable-units', [Host::SYSTEMCTL, 'enable', ...self::UNITS]);
        $host->must('enable-reconciler', [Host::SYSTEMCTL, 'enable', '--now', self::RECONCILER]);
        $this->record('units-enabled', true);
    }

    /**
     * HTTP/3 (FV-04): UDP 443 opened in the host firewall as the backup recorded it. HTTP/3 is an addition, so a
     * failure here never fails the cutover: the partial change is undone, the step is recorded as failed and the
     * administrator is told (clients fall back to TCP when the advertised UDP port does not answer).
     * @param array<string,mixed> $manifest
     */
    private function http3Firewall(array $manifest): void
    {
        $http3 = $manifest['http3'] ?? ['enabled' => false, 'firewall' => null];
        $record = $http3['firewall'] ?? null;
        if ($http3['enabled'] !== true || !is_array($record)) {
            $this->record('http3', true, 'disabled by ' . $this->env->http3Path() . '; no firewall change');
            return;
        }
        foreach ($record['warnings'] ?? [] as $warning) {
            $this->warnings[] = (string) $warning;
        }
        if (($record['action'] ?? null) !== 'add') {
            $this->record('http3-firewall', true, "{$record['type']}: {$record['detail']}");
            return;
        }
        $firewall = new Http3Firewall($this->env->host);
        try {
            $firewall->apply($record, $manifest['dir'] . '/staged');
            $this->record('http3-firewall', true, "{$record['type']}: {$record['detail']}");
        } catch (DeploymentError $error) {
            $undo = $firewall->undo($record, $manifest['dir']);
            $this->record('http3-firewall', false, $error->getMessage() . (($undo['restored'] ?? false) ? '; undone' : '; NOT undone'));
            $this->warnings[] = 'UDP 443 could not be opened in ' . $record['type'] . ' (' . $error->getMessage()
                . '): HTTP/3 is advertised but may be unreachable; open UDP 443 yourself or set {"enabled": false} in '
                . $this->env->http3Path() . ' and reconcile';
        }
    }

    /**
     * Status code per "<scheme>://<vhost>/" for every cPanel vhost (hybrid ones answer through their HTTP and
     * their TLS vhost), requested at the vhost's address on the public ports.
     * @param array<string,array<string,mixed>> $vhosts
     * @return array<string,string>
     */
    private function answers(array $vhosts, string $label): array
    {
        $out = [];
        ksort($vhosts, SORT_STRING);
        foreach ($vhosts as $name => $vhost) {
            $ip = is_string($vhost['ip'] ?? null) && $vhost['ip'] !== '' ? $vhost['ip'] : '127.0.0.1';
            foreach (['http', 'https'] as $scheme) {
                $out["$scheme://$name/"] = $this->env->host->httpStatus($scheme, (string) $name, $ip, "$label-$scheme");
            }
        }
        return $out;
    }

    /**
     * Runs recover.sh now (the same file the timer would run) under the held deployment lock, disarms the timer
     * only once Apache is verified serving (otherwise keeps or re-arms it) and removes the hook registrations
     * (the script cannot: it does not depend on the product).
     * @return array<string,mixed>
     */
    private function recover(string $script, string $unit): array
    {
        $host = $this->env->host;
        $run = $host->run('recovery-run', RecoveryScript::heldArgv($script), self::RECOVERY_TIMEOUT);
        $out = ['exit_code' => $run['exit_code'], 'output' => Host::tail($run['stdout'] . ' ' . ($run['stderr'] ?? ''))];
        $served = $run['exit_code'] === 0 && $host->apacheServes();
        if ($served) {
            $host->run('disarm-recovery', [Host::SYSTEMCTL, 'stop', "$unit.timer", "$unit.service"]);
            $out['timer_disarmed'] = !$host->unitActive("$unit.timer", 'recovery-disarmed')
                && !$host->unitActive("$unit.service", 'recovery-idle');
        } else {
            $out['timer_disarmed'] = false;  // the timer retries the recovery
            $out['timer_armed'] = $host->keepRecoveryArmed($unit, $script, self::RETRY_DELAY);
        }
        try {
            $out['hooks'] = $this->env->hooks()->remove();
        } catch (DeploymentError $error) {
            $out['hooks'] = ['ok' => false, 'error' => $error->getMessage()];
        }
        $out['recovered'] = $served;
        return $out;
    }

    private function record(string $step, bool $ok, mixed $detail = null): void
    {
        $this->steps[] = $detail === null ? ['step' => $step, 'ok' => $ok] : ['step' => $step, 'ok' => $ok, 'detail' => $detail];
    }

    /** Exit code of an outcome. */
    public static function exitCode(array $outcome): int
    {
        return ($outcome['result'] ?? null) === 'cut_over' ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
