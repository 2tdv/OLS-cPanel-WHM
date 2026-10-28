<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\Cutover;
use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\PhpExtensions\ExtensionInstaller;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Php\OpcacheManager;

/** `install --prepare [--native] [--no-opcache]` and `install --cutover --plan=<id> [--yes]`. */
final class InstallCommand extends DeploymentCommand
{
    /**
     * @param \Closure():Environment|null $environment
     * @param \Closure(Environment):OpcacheManager|null $opcache the PHP OPcache step of --prepare (FV-03); null skips it
     * @param resource|null $input
     * @param \Closure():bool|null $tty
     */
    public function __construct(?\Closure $environment = null, $input = null, ?\Closure $tty = null, private readonly ?\Closure $opcache = null,
                                private readonly ?\Closure $phpEnvironment = null)
    {
        parent::__construct($environment, $input, $tty);
    }

    public function words(): array
    {
        return ['install'];
    }

    public function summary(): string
    {
        return 'Prepare (--prepare [--native] [--no-opcache]; hybrid is the default) or cut over to OLS (--cutover --plan=ID [--yes])';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['prepare', 'cutover', 'hybrid', 'native', 'yes', 'no-opcache'], ['plan']);
        $prepare = $args->flag('prepare');
        $cutover = $args->flag('cutover');
        if ($prepare === $cutover || ($prepare && ($args->value('plan') !== null || $args->flag('yes')))
            || ($cutover && ($args->value('plan') === null || $args->flag('hybrid') || $args->flag('native') || $args->flag('no-opcache')))
            || ($args->flag('hybrid') && $args->flag('native'))) {
            throw new UsageError('install --prepare [--native] [--no-opcache] | install --cutover --plan=ID [--yes]');
        }
        return $prepare ? $this->prepare($args->flag('native'), $args->flag('no-opcache'), $out) : $this->cutover((string) $args->value('plan'), $args->flag('yes'), $out);
    }

    private function prepare(bool $native, bool $noOpcache, Output $out): int
    {
        try {
            $env = $this->environment();
            $plan = (new CutoverPlan($env))->prepare($native);
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'install --prepare');
        }
        // FV-03: OPcache on every installed EA4 PHP version unless the operator opts out. A failure here never undoes
        // the plan (Apache keeps serving); it is reported, and the php timer retries.
        $opcache = null;
        if ($this->opcache !== null) {
            try {
                $opcache = ($this->opcache)($env)->prepare($noOpcache);
            } catch (DeploymentError | \OlsCpanel\Cli\Refused $error) {
                $opcache = ['result' => 'failed', 'error' => $error->getMessage()];
            }
        }
        // FV-10: every installed EA4 PHP version complete for OLS (lsphp, OPcache, redis), the recommended EA4 profile file, and the
        // units that keep it so. Reported, never fatal: the pass retries by itself.
        $environment = null;
        if ($this->phpEnvironment !== null) {
            try {
                $environment = ($this->phpEnvironment)($env)->prepare();
            } catch (DeploymentError | \OlsCpanel\Cli\Refused $error) {
                $environment = ['result' => 'failed', 'error' => $error->getMessage()];
            }
        }
        $out->result(['command' => 'install --prepare', 'result' => 'prepared', 'plan' => $plan['id'], 'opcache' => $opcache,
            'php_environment' => $environment, 'php_extensions' => $this->extensions(),
            'vhost_count' => $plan['vhost_count'], 'hybrid_vhosts' => $plan['hybrid_vhosts'], 'profile' => $plan['profile'],
            'host_changes' => $plan['host_changes'], 'http3' => $plan['http3'], 'setup' => $plan['setup'],
            'next' => "ols-cpanel install --cutover --plan={$plan['id']}"]);
        return Application::EXIT_OK;
    }

    /**
     * Availability of the PHP redis extension per EA4 PHP version (read only; never fails the preparation).
     * @return array<string,mixed>
     */
    private function extensions(): array
    {
        try {
            $env = $this->environment();
            $status = (new ExtensionInstaller($env->runner, phpRoot: $env->phpRoot, stateRoot: $env->state . '/php-ext'))->status();
            return ['prebuilt' => $status['prebuilt'], 'versions' => array_map(static fn(array $row): array => [
                'php' => $row['php'], 'status' => $row['status'], 'candidate' => $row['candidate'] ?? null], $status['versions']),
                'note' => 'kept active automatically by the PHP environment service'];
        } catch (\Throwable $error) {
            return ['result' => 'unknown', 'error' => substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200)];
        }
    }

    private function cutover(string $planId, bool $yes, Output $out): int
    {
        $approve = function (array $plan) use ($out, $yes): bool {
            $hybrid = array_map(static fn(array $h): string => "    {$h['vhost']}: " . implode('; ', $h['reasons']), $plan['hybrid_vhosts']);
            return $this->approve($out, $yes, $plan['id'], [
                "Cutover plan {$plan['id']} (prepared {$plan['created']})",
                "  vhosts: {$plan['vhost_count']}, OLS package: {$plan['ols_package']}",
                '  host changes: ' . implode('; ', $plan['host_changes']),
                '  HTTP/3: ' . (($plan['http3']['enabled'] ?? false) !== true ? 'disabled by ' . ($plan['http3']['input'] ?? 'the operator input')
                    : 'enabled, firewall ' . ($plan['http3']['firewall']['type'] ?? '?') . ': ' . ($plan['http3']['firewall']['detail'] ?? '')),
                '  ' . ($plan['profile']['hybrid_ports'] === null
                    ? 'native profile (--native): an untranslatable change refuses the compile for safety'
                    : 'Apache stays in standby behind OpenLiteSpeed for sites that need it (ports '
                    . implode('/', $plan['profile']['hybrid_ports']) . ', closed to the outside)'),
                '  sites served by Apache automatically today: ' . ($hybrid === [] ? 'none' : "\n" . implode("\n", $hybrid)),
                '  a backup and recover.sh are written first; a recovery timer returns the host to Apache in 45 minutes '
                . 'unless the cutover completes; any failed check returns it at once',
            ], 'the cutover');
        };
        try {
            $outcome = (new Cutover($this->environment()))->run($planId, $approve);
        } catch (DeploymentError $error) {
            return $this->refused($out, $error, 'install --cutover');
        }
        if ($out->json()) {
            $out->result(['command' => 'install --cutover'] + $outcome);
        } else {
            $this->readable($out, $outcome);
        }
        return Cutover::exitCode($outcome);
    }

    /** Readable words for the cutover steps on a terminal (JSON keeps the step names). */
    private const STEP_TEXT = [
        'preflight' => 'Pre-checks passed', 'plan-current' => 'The approved plan is still current',
        'apache-baseline' => 'Recorded how every site answers under Apache', 'plan-recheck' => 'Plan checked again',
        'backup' => 'Backup and recovery script written', 'recovery-armed' => 'Safety timer armed (returns to Apache if anything goes wrong)',
        'hooks' => 'cPanel hooks registered', 'hybrid-host' => 'Apache moved to standby behind OpenLiteSpeed',
        'apache-released' => 'Apache released ports 80 and 443', 'profile' => 'Serving profile recorded',
        'activate' => 'OpenLiteSpeed configuration activated', 'ols-serving' => 'OpenLiteSpeed is serving ports 80 and 443',
        'http3-firewall' => 'HTTP/3 checked', 'fileprotect' => 'cPanel FileProtect kept',
        'vhost-health' => 'Every site answers as it did under Apache', 'units-enabled' => 'Services enabled for every boot',
        'recorded' => 'Result recorded', 'recovery-disarmed' => 'Safety timer disarmed',
    ];

    /** @param array<string,mixed> $outcome */
    private function readable(Output $out, array $outcome): void
    {
        foreach (is_array($outcome['steps'] ?? null) ? $outcome['steps'] : [] as $step) {
            $name = (string) ($step['step'] ?? '');
            $text = self::STEP_TEXT[$name] ?? $name;
            $out->error(($step['ok'] ?? false) === true ? "    ✓ $text" : "    ✗ $text: " . (is_string($step['detail'] ?? null) ? $step['detail'] : ''));
        }
        $result = (string) ($outcome['result'] ?? '');
        if ($result === 'cut_over') {
            $out->error('');
            $out->error('Done: OpenLiteSpeed is serving your sites. Apache stays in standby for any site that needs it.');
            $out->error('Backup: ' . (string) ($outcome['backup'] ?? ''));
        } else {
            $out->error('');
            $out->error("Not switched ($result): " . (string) ($outcome['error'] ?? '') . ' Apache is serving your sites.');
        }
    }
}
