<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Cli\Application;
use OlsCpanel\Events\SourceDigest;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Compiler\CpanelSurface;
use OlsCpanel\Ols\Compiler\ServerCompiler;

/**
 * `install --prepare`: preflight, a full compile with production listeners (lint included, nothing staged),
 * the plan file plans/<id>.json (root 0600) and the prepared state (state directories, the engine user, the
 * broker). Apache keeps serving; nothing a cutover changes is touched. Also loads and checks plans.
 */
final class CutoverPlan
{
    public const ID = '/^p\d{14}-[0-9a-f]{6}$/D';
    public const OLS_PACKAGE = 'ols-cpanel-openlitespeed';
    public const PRODUCT_PACKAGE = 'ols-cpanel';
    public const OLS_UNIT = 'ols-cpanel.service';
    public const SYSUSERS = '/usr/lib/sysusers.d/ols-cpanel.conf';
    public const BROKER_UNIT = 'ols-cpanel-broker.service';

    public function __construct(private Environment $env)
    {
    }

    public const SCHEMA_VERSION = 2;

    /**
     * The full compile digest a plan is bound to (review RV-29 findings 9 and 10): sha256 over the compiled
     * configuration (server and every vhost) and the sha256 of every certificate, key and password file it
     * references (Events\SourceDigest::referencedFiles, the reconciler's own safe readers; null when unreadable) and of every
     * ModSecurity rule and data file the compile read (FV-02, summary.waf.inputs).
     * A plan is stale when it changes; the cutover's activation refuses a compile with another digest.
     * @param array<string,?string> $files path => sha256
     */
    public static function digest(array $compiled, array $files): string
    {
        $vhconf = $compiled['vhconf'];
        ksort($vhconf, SORT_STRING);
        ksort($files, SORT_STRING);
        return hash('sha256', json_encode(['config' => $compiled['config'], 'vhconf' => $vhconf, 'files' => (object) $files],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /**
     * The referenced-file digests of a compile, read with the deployment's command runner (root: the same
     * commands as the engine allowlist, tenant files only as the tenant).
     * @return array<string,?string>
     */
    public function referencedFiles(array $compiled): array
    {
        return SourceDigest::referencedFiles($compiled, $this->env->runner);
    }

    /**
     * Runs the preparation; returns the written plan.
     * @return array<string,mixed>
     */
    public function prepare(bool $native = false): array
    {
        $this->env->requireRoot();
        $platform = $this->env->platform();
        if (!$platform['supported']) {
            throw new DeploymentError('unsupported platform: ' . implode('; ', $platform['problems']), Application::EXIT_AUDIT_ONLY,
                ['problems' => $platform['problems']]);
        }
        Environment::ensureDir($this->env->state, 0755);
        $lock = $this->env->lock();
        try {
            $checks = [['name' => 'root', 'ok' => true], ['name' => 'platform', 'ok' => true,
                'detail' => 'certification blockers: ' . (implode(', ', $platform['certification_blockers']) ?: 'none')]];
            $olsVersion = $this->preflight($checks);
            [$compiled, $hybridVhosts] = $this->compileProfile($native);
            $checks[] = ['name' => 'compile', 'ok' => true, 'detail' => count($compiled['plan']) . ' vhosts, lint passed'];
            // HR-D14: the hybrid profile is the default; only --native plans without Apache's standby.
            $ports = $native ? null : CpanelSurface::HYBRID_PORTS;
            if ($ports !== null) {
                $this->requireSuexec($checks);
            }
            $http3 = $this->http3();
            $id = $this->env->newId('p');
            $vhosts = array_map('strval', array_keys($compiled['plan']));
            sort($vhosts, SORT_STRING);
            $files = $this->referencedFiles($compiled);
            $plan = ['schema_version' => self::SCHEMA_VERSION, 'id' => $id, 'created' => gmdate('c', $this->env->now()),
                'profile' => ['production' => true, 'hybrid_ports' => $ports], 'hybrid_vhosts' => $hybridVhosts,
                'vhost_count' => count($vhosts), 'vhosts' => $vhosts, 'ols_package' => self::OLS_PACKAGE . '-' . $olsVersion,
                'compile_sha256' => self::digest($compiled, $files), 'referenced_files' => (object) $files,
                'host_changes' => [...($ports === null
                    ? ['Apache disabled and unmonitored (whmapi1 configureservice), OLS on 80/443']
                    : ["Apache stays in standby behind OpenLiteSpeed for sites that need it: moved to {$ports[0]}/{$ports[1]} "
                        . '(apache_port/apache_ssl_port tweaks, closed to the outside), ' . HybridHost::REMOTEIP_CONF
                        . ', nftables table inet ' . HybridHost::NFT_TABLE . ', OLS on 80/443']),
                    ...(($http3['firewall']['action'] ?? null) === 'add'
                        ? ['HTTP/3: ' . $http3['firewall']['type'] . ': ' . $http3['firewall']['detail']] : [])],
                'http3' => $http3,
                'backups_needed' => Backup::FILES, 'certification_blockers' => $platform['certification_blockers'],
                'checks' => $checks,
                // The compile summary the plugins show before cutover (the broker reads it from the latest plan).
                'summary' => $compiled['summary'] ?? null];
            Environment::ensureDir($this->env->plansDir(), 0700);
            Environment::writeFile($this->env->plansDir() . "/$id.json", Environment::json($plan), 0600);
            $plan['setup'] = $this->setup();
            return $plan;
        } finally {
            fclose($lock);
        }
    }

    /**
     * HTTP/3 (FV-04) as the cutover would do it: enabled by the operator input and what the host firewall needs for
     * UDP 443 (read-only inspection; csf.conf's text is never part of the plan).
     * @return array<string,mixed>
     */
    private function http3(): array
    {
        try {
            $enabled = Http3Input::load($this->env->http3Path());
        } catch (\OlsCpanel\Ols\Compiler\CompilationRefused $refused) {
            throw DeploymentError::refused($refused->getMessage());
        }
        if (!$enabled) {
            return ['enabled' => false, 'input' => $this->env->http3Path(), 'firewall' => null];
        }
        $firewall = (new Http3Firewall($this->env->host))->inspect();
        unset($firewall['new_text']);
        return ['enabled' => true, 'input' => $this->env->http3Path(), 'firewall' => $firewall];
    }

    /**
     * The checks shared with cutover: no profile, OLS package installed (product payload intact) and stopped,
     * Apache the healthy owner of 80/443. Returns the OLS package version.
     * @param list<array<string,mixed>> $checks appended to
     */
    public function preflight(array &$checks): string
    {
        try {
            $profile = Profile::load($this->env->profilePath());
        } catch (\RuntimeException $error) {
            throw DeploymentError::refused($error->getMessage());
        }
        if ($profile !== null) {
            throw DeploymentError::refused('already cut over (' . $this->env->profilePath() . ' exists); use apache-return first');
        }
        $checks[] = ['name' => 'no-profile', 'ok' => true];
        $rpm = $this->env->host->run('ols-package', ['/usr/bin/rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', self::OLS_PACKAGE]);
        $version = trim($rpm['stdout']);
        if ($rpm['exit_code'] !== 0 || !preg_match('/^[A-Za-z0-9._+~^-]+$/D', $version)) {
            throw DeploymentError::refused(self::OLS_PACKAGE . ' is not installed');
        }
        $checks[] = ['name' => 'ols-package', 'ok' => true, 'detail' => $version];
        $verify = $this->env->host->run('product-payload', ['/usr/bin/rpm', '-V', self::PRODUCT_PACKAGE]);
        if ($verify['exit_code'] !== 0) {
            throw DeploymentError::refused('the installed ' . self::PRODUCT_PACKAGE . ' files differ from the package: '
                . Host::tail($verify['stdout']));
        }
        $checks[] = ['name' => 'product-payload', 'ok' => true];
        // ea-nginx serves 80/443 itself with Apache behind it; OLS cannot take those ports beside it (the product
        // package conflicts with it, so this only catches an installation forced past the package manager).
        if ($this->env->host->run('no-ea-nginx', ['/usr/bin/rpm', '-q', 'ea-nginx'])['exit_code'] === 0) {
            throw DeploymentError::refused('ea-nginx is installed: it serves ports 80/443 itself. Remove it in '
                . 'EasyApache 4 (or keep nginx and do not install OLS-cPanel) before preparing a cutover');
        }
        $checks[] = ['name' => 'no-ea-nginx', 'ok' => true];
        if ($this->env->host->unitActive(self::OLS_UNIT, 'ols-stopped')) {
            throw DeploymentError::refused(self::OLS_UNIT . ' is running; it must stay stopped until cutover');
        }
        $checks[] = ['name' => 'ols-stopped', 'ok' => true];
        $status = $this->env->host->apacheStatus();
        if ($status !== ['enabled' => true, 'monitored' => true, 'running' => true]) {
            throw DeploymentError::refused('Apache is not enabled, monitored and running: ' . json_encode($status));
        }
        if (!$this->env->host->ownedBy([80, 443], ['httpd'])) {
            throw DeploymentError::refused('Apache is not the only owner of ports 80 and 443');
        }
        $checks[] = ['name' => 'apache-owner', 'ok' => true];
        return $version;
    }

    /** @param list<array<string,mixed>> $checks */
    public function requireSuexec(array &$checks): void
    {
        if (!(new HybridHost($this->env->host, $this->env->state))->suexec()) {
            throw DeploymentError::refused("hybrid vhosts need Apache to run each account's CGI as that account (suexec_module, "
                . 'ruid2_module or mpm_itk_module; without one CGI runs as OLS\'s user, which may reach the backend ports)');
        }
        $checks[] = ['name' => 'apache-suexec', 'ok' => true];
    }

    /**
     * The compile for the requested profile. Default (HR-D14): the hybrid profile, so blocked vhosts are planned
     * on Apache and none refuses; with $native any blocker refuses, listing every blocked vhost.
     * @return array{0:array<string,mixed>, 1:list<array{vhost:string, reasons:list<string>}>}
     */
    public function compileProfile(bool $native): array
    {
        if (!$native) {
            $compiled = $this->compile(CpanelSurface::HYBRID_PORTS);
            return [$compiled, self::hybridVhosts($compiled)];
        }
        try {
            return [$this->compile(null), []];
        } catch (DeploymentError $refused) {
            if (($refused->details['vhosts'] ?? []) === []) {
                throw $refused;
            }
            // List every blocked vhost, not only the first the native compile stopped at.
            try {
                $blocked = self::hybridVhosts($this->compile(CpanelSurface::HYBRID_PORTS));
            } catch (DeploymentError) {
                $blocked = [];
            }
            $blocked = $blocked !== [] ? $blocked
                : array_map(static fn(string $v): array => ['vhost' => $v, 'reasons' => [$refused->getMessage()]], $refused->details['vhosts']);
            throw DeploymentError::refused('vhosts that must stay on Apache (the default hybrid profile keeps them on Apache behind OLS; --native refuses): '
                . implode(', ', array_column($blocked, 'vhost')), ['blockers' => $blocked]);
        }
    }

    /**
     * @param array{0:int,1:int}|null $ports
     * @return array<string,mixed>
     */
    public function compile(?array $ports): array
    {
        try {
            return $this->env->compilation->compile($ports);
        } catch (CompilationRefused $error) {
            throw DeploymentError::refused('compile refused: ' . $error->getMessage(), ['vhosts' => $error->vhosts()]);
        }
    }

    /** @return list<array{vhost:string, reasons:list<string>}> */
    public static function hybridVhosts(array $compiled): array
    {
        $out = [];
        foreach ($compiled['summary']['hybrid_vhosts'] ?? [] as $name) {
            $reasons = array_values(array_map('strval', [...($compiled['summary']['htaccess_blockers'][$name] ?? []),
                ...($compiled['summary']['hybrid_reasons'][$name] ?? [])]));
            $handler = $compiled['plan'][$name]['php_handler'] ?? null;
            if (!in_array($handler, ServerCompiler::PHP_HANDLERS, true)) {
                $reasons[] = 'unsupported PHP handler ' . var_export($handler, true);
            }
            $out[] = ['vhost' => (string) $name, 'reasons' => $reasons];
        }
        return $out;
    }

    /** @return array<string,mixed> a validated plan */
    public function load(string $id): array
    {
        if (!preg_match(self::ID, $id)) {
            throw DeploymentError::refused("invalid plan id $id");
        }
        $path = $this->env->plansDir() . "/$id.json";
        $text = is_link($path) ? false : @file_get_contents($path, false, null, 0, 4194305);
        if ($text === false) {
            throw DeploymentError::refused("no plan $id (run install --prepare)");
        }
        $plan = json_decode($text, true, 32);
        $ports = $plan['profile']['hybrid_ports'] ?? null;
        if (is_array($plan) && ($plan['id'] ?? null) === $id && ($plan['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw DeploymentError::refused("plan $id was prepared by an earlier version; run install --prepare again");
        }
        if (!is_array($plan) || ($plan['id'] ?? null) !== $id
            || ($plan['profile']['production'] ?? null) !== true || !is_string($plan['compile_sha256'] ?? null)
            || !is_array($plan['hybrid_vhosts'] ?? null) || ($ports !== null && $ports !== CpanelSurface::HYBRID_PORTS)
            || ($ports === null && $plan['hybrid_vhosts'] !== [])) {
            throw DeploymentError::refused("plan $id is malformed");
        }
        return $plan;
    }

    /**
     * Prepared state (build/product units): state directories, the engine user (systemd-sysusers) and the
     * broker. Idempotent; uninstall reverses the broker and removes the state except backups/.
     * @return list<string>
     */
    /** The listeners' neutral default certificate, relative to the state directory (GenerationTree points the listeners at it). */
    public const DEFAULT_KEY = 'tls/default.key';
    /** OLS's fixed main configuration (ols-cpanel.service ConditionPathExists). */
    public const MAIN_CONFIG = '/usr/local/lsws/conf/httpd_config.conf';
    public const DEFAULT_CERT = 'tls/default.crt';

    private function setup(): array
    {
        foreach (['plans' => 0700, 'backups' => 0700, 'events' => 0700, 'events/done' => 0700, 'staging' => 0700,
                     'tls' => 0700, 'cache' => 0711] as $dir => $mode) {
            Environment::ensureDir($this->env->state . "/$dir", $mode);
        }
        // cache/ (FV-01): OLS creates each vhost store below it as nobody:nobody 2770; the root must exist first.
        // The listeners' default certificate stays neutral (plan section 12): a self-signed one of the
        // product's own, never a tenant's; tenants answer with their own certificates through SNI.
        $key = $this->env->state . '/' . self::DEFAULT_KEY;
        $cert = $this->env->state . '/' . self::DEFAULT_CERT;
        if (!is_file($key) || !is_file($cert)) {
            $this->env->host->must('default-certificate', ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-days', '3650', '-subj', '/CN=ols-cpanel-default', '-keyout', $key, '-out', $cert]);
        }
        // OLS reads a fixed main configuration: a stable link to the active generation (the activator only
        // switches state/active). It dangles until the first activation, so the unit's condition keeps OLS down.
        // Per-vhost error logs (BuilderCompilation's error log directory): written by the OLS workers (nobody),
        // like the server's own error.log next to it.
        $this->env->host->must('vhost-log-dir', ['/usr/bin/install', '-d', '-m', '0750', '-o', 'nobody', '-g', 'nobody',
            '/usr/local/lsws/logs/vhosts']);
        $this->env->host->must('adopt-main-config', ['/usr/bin/ln', '-sfn', $this->env->state . '/active/httpd_config.conf',
            self::MAIN_CONFIG]);
        $this->env->host->must('sysusers', ['/usr/bin/systemd-sysusers', self::SYSUSERS]);
        $this->env->host->must('broker-enable', [Host::SYSTEMCTL, 'enable', '--now', self::BROKER_UNIT]);
        // Hybrid trust refresh (HR-D14): the command does nothing unless the hybrid profile is in effect.
        $this->env->host->must('hybrid-trust-enable', [Host::SYSTEMCTL, 'enable', '--now', 'ols-cpanel-hybrid-trust.timer']);
        // FV-01: the hourly cleanup of expired and oversized LSCache entries (best effort: the next upgrade tries again).
        $cleanup = CacheCleanTimer::ensure($this->env->host);
        $accountState = AccountStateTimer::ensure($this->env->host);
        // FV-07: the notification and maintenance-window timers (best effort: the next upgrade tries again).
        $operations = OperationsTimers::ensure($this->env->host);
        $plugins = $this->env->plugins()->deploy();
        return ['state directories', 'default listener certificate', 'main configuration linked to the active generation', 'engine user (systemd-sysusers)',
            self::BROKER_UNIT . ' enabled and started', AccountStateTimer::TIMER . ($accountState ? ' enabled' : ' could not be enabled (upgrade retries)'), CacheCleanTimer::TIMER . ($cleanup ? ' enabled' : ' could not be enabled (upgrade retries)'),
            ...array_map(static fn(string $timer, bool $ok): string => $timer . ($ok ? ' enabled' : ' could not be enabled (upgrade retries)'), array_keys($operations), $operations), ...$plugins];
    }
}
