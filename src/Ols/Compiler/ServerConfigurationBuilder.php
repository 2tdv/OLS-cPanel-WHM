<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

use OlsCpanel\Cpanel\Discovery\AccountVhosts;
use OlsCpanel\Cpanel\Discovery\HomePath;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\Validation\ConfigLint;
use OlsCpanel\Php\Ini\FpmPoolTranslator;
use OlsCpanel\Php\PhpLimits;

/**
 * Compiles the complete production OLS configuration (server httpd_config.conf and one vhconf.conf per
 * OLS vhost) from cPanel's own state, read through a CommandRunner. Port of the lab-proven
 * compile_lab(step, summary, production=True) in build/vm-qualification/tenant_isolation_probe.py: it
 * issues the same command argv lists and produces byte-identical output (tests/compile_replay.php
 * replays the calls recorded on the lab server).
 *
 * Inputs: /etc/userdatadomains and the per-vhost userdata (OLS-19), the PHP handler per vhost from
 * whmapi1 (HR-D05), cPanel's suspension markers, the cPanel-generated PHP-FPM pools and the target PHP's
 * E_* constants, every .htaccess under each docroot and above it read as the tenant (OLS-16, HR-D07),
 * the installed certificates, cPanel's generated httpd.conf (per-address defaults and proxy-subdomains
 * endpoints), the bound IPv6 addresses and the global alias directories present on the host.
 *
 * Fails closed (CompilationRefused): malformed userdata, a failed or unexpected API answer, an
 * unsupported PHP handler, any .htaccess that cannot be listed, read or translated completely (a
 * symlinked .htaccess included) and lint errors. Nothing is guessed and nothing is changed on the host.
 * The lab-only check that Apache serves PHP as the tenant (a request to the live site) is not part of
 * compilation: it never changes the output.
 */
final class ServerConfigurationBuilder
{
    /** cPanel's installed certificate per vhost: one PEM with key, certificate and chain. */
    public const TLS_DIR = '/var/cpanel/ssl/apache_tls';
    /** PHP code printing the target PHP's E_* constants as JSON; no pool expression is ever executed. */
    public const CONSTANTS_CODE = 'echo json_encode(array_filter(get_defined_constants(true)["Core"], '
        . 'fn($k) => str_starts_with($k, "E_"), ARRAY_FILTER_USE_KEY));';
    /** Why a vhost is held (HR-D14); shown by the plugins as handled automatically. */
    public const HELD_DSO_REASON = 'PHP handler dso on a site that needs Apache';
    private const TIMEOUT = 120;
    private const USER = '/^[a-z0-9][a-z0-9_.-]*$/D';
    private const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';
    /** A PHP version is one path component under /opt/cpanel (ea-php83, alt-php74, ...). */
    private const PHP_VERSION = '/^[a-z][a-z0-9-]*$/D';
    private const RUNUSER = '/usr/sbin/runuser';
    /** cPanel's technical domains (temporary domains): the host test of its vhost template (RV-44). */
    private const TECHNICAL_DOMAIN = '/^(?:(?:.*\.)?cpanel\.site)$/Di';
    private const TECHNICAL_DOMAIN_HEADER = 'Header set X-Robots-Tag "noindex, nofollow"';
    private const VHOST_FIELDS = ['user', 'type', 'docroot', 'aliases', 'php', 'php_handler', 'pool', 'service_domains'];

    private CommandRunner $runner;
    /** @var array<string,string> cPanel user => main domain */
    private array $tenants;
    private string $serverTemplate;
    private string $errorLogDir;
    private AccountVhosts $model;
    /** @var array{0:int,1:int}|null Apache's backend ports when the hybrid profile (HR-D08) is enabled */
    private ?array $hybridPorts;
    private CpanelSurface $surface;
    private ServerCompiler $compiler;
    private HtaccessTranslator $htaccess;
    private FpmPoolTranslator $fpm;
    private CachePolicy $cache;
    private ConfigLint $lint;
    /** @var array<string,bool> directory => present, for one compilation */
    private array $directories = [];
    /** Product security input (FV-02); null compiles without the WAF and security part and reads none of its inputs. */
    private mixed $security;
    private SecurityTranslator $securityTranslator;
    /** @var array<string,string> cPanel vhost => userdata text, for one compilation */
    private array $userdata = [];
    /** @var array<string,array<string,mixed>>|null whmapi1 php_get_vhost_versions rows by vhost, read once per compilation */
    private ?array $vhostVersions = null;

    /**
     * @param array<string,string> $tenants cPanel user => main domain of the accounts OLS serves
     * @param string $serverTemplate server policy template text (ownership_httpd_config.conf)
     * @param string $errorLogDir directory of the per-vhost OLS error logs
     * @param (\Closure(string):?string)|null $previousVhost the native vhost configuration of the active generation (LsphpGuard::previous), for a held vhost
     */
    public function __construct(CommandRunner $runner, array $tenants, string $serverTemplate, string $errorLogDir,
                                ?AccountVhosts $model = null, ?CpanelSurface $surface = null, ?ServerCompiler $compiler = null,
                                ?HtaccessTranslator $htaccess = null, ?FpmPoolTranslator $fpm = null, ?ConfigLint $lint = null,
                                ?array $hybridPorts = null, mixed $security = null, ?SecurityTranslator $securityTranslator = null,
                                private readonly ?PhpLimits $phpLimits = null, private bool $http3 = true,
                                private readonly ?\Closure $previousVhost = null)
    {
        if ($hybridPorts !== null && (count($hybridPorts) !== 2 || array_filter($hybridPorts,
                static fn(mixed $p): bool => !is_int($p) || $p < 1 || $p > 65535 || in_array($p, [80, 443], true)) !== [])) {
            throw new \InvalidArgumentException('hybrid ports must be two backend ports other than 80 and 443');
        }
        $this->hybridPorts = $hybridPorts === null ? null : array_values($hybridPorts);
        foreach ($tenants as $user => $domain) {
            if (!preg_match(self::USER, (string) $user) || !preg_match(self::DOMAIN, $domain)) {
                throw new \InvalidArgumentException("invalid account $user => $domain");
            }
        }
        if (!preg_match('/^\/[A-Za-z0-9._\/-]*$/D', $errorLogDir)) {
            throw new \InvalidArgumentException('unsafe error log directory');
        }
        $this->runner = $runner;
        $this->tenants = $tenants;
        $this->serverTemplate = $serverTemplate;
        $this->errorLogDir = $errorLogDir;
        $this->model = $model ?? new AccountVhosts();
        $this->surface = $surface ?? new CpanelSurface();
        $this->fpm = $fpm ?? new FpmPoolTranslator();
        $this->compiler = $compiler ?? new ServerCompiler($this->surface, $this->fpm);
        $this->htaccess = $htaccess ?? new HtaccessTranslator();
        $this->lint = $lint ?? new ConfigLint();
        $this->cache = new CachePolicy();
        $this->security = $security;
        $this->securityTranslator = $securityTranslator ?? new SecurityTranslator();
    }

    /**
     * Discover every cPanel vhost of the accounts and compile the production configuration.
     * @return array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>, summary:array<string,mixed>}
     * @throws CompilationRefused
     */
    public function compile(): array
    {
        $this->directories = [];
        $this->userdata = [];
        $this->vhostVersions = null;
        try {
            return $this->compileChecked();
        } catch (\InvalidArgumentException | \JsonException $error) {
            throw new CompilationRefused($error->getMessage(), [], $error);
        }
    }

    /** @return array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>, summary:array<string,mixed>} */
    private function compileChecked(): array
    {
        $summary = [];
        $plan = $this->plan();
        $this->phpHandlers($plan);
        $summary['vhosts'] = [];
        foreach ($plan as $name => $v) {
            $summary['vhosts'][$name] = array_combine(self::VHOST_FIELDS,
                array_map(static fn(string $key): mixed => $v[$key], self::VHOST_FIELDS));
        }
        $versions = [];
        foreach ($this->tenants as $user => $domain) {
            if (!isset($plan[$domain])) {
                throw new CompilationRefused("main domain $domain is not a cPanel vhost", [$domain]);
            }
            $versions[(string) $user] = $plan[$domain]['php'];
        }
        // Suspended accounts (cPanel's marker file) get cPanel's suspended-page redirect.
        $suspended = [];
        foreach (array_keys($this->tenants) as $user) {
            $user = (string) $user;
            if ($this->run("suspended-$user", ['/usr/bin/test', '-e', "/var/cpanel/suspended/$user"])['exit_code'] === 0) {
                $suspended[] = $user;
            }
        }
        foreach ($plan as $name => $v) {
            $plan[$name]['suspended'] = in_array($v['user'], $suspended, true);
        }
        sort($suspended, SORT_STRING);
        $summary['suspended_accounts'] = $suspended;
        // The cPanel-generated FPM pool is the effective per-vhost PHP policy Apache applies; an addon
        // vhost's pool is named after the addon domain. Without FPM there is no pool (empty policy).
        $pools = [];
        $poolUnreadable = [];
        foreach ($plan as $name => $v) {
            $read = $this->run("fpm-pool-$name", ['/usr/bin/cat', "/opt/cpanel/{$v['php']}/root/etc/php-fpm.d/{$v['pool']}.conf"]);
            if ($read['exit_code'] !== 0 && $v['php_handler'] === 'fpm') {
                // HR-D14: with the hybrid profile only this vhost moves to Apache, which applies the pool itself.
                if ($this->hybridPorts === null) {
                    throw new CompilationRefused("PHP-FPM pool of $name is unreadable (domain must stay on Apache)", [$name]);
                }
                $plan[$name]['mode'] = 'apache';
                $poolUnreadable[] = (string) $name;
            }
            $pools[$name] = $read['stdout'];
        }
        $summary['php_versions'] = $versions;
        // E_* values come from the exact target PHP; no expression is ever executed.
        $constants = [];
        foreach ($plan as $v) {
            if (!array_key_exists($v['php'], $constants)) {
                $version = $v['php'];
                $value = json_decode($this->run("constants-$version", ["/opt/cpanel/$version/root/usr/bin/php", '-n', '-r',
                    self::CONSTANTS_CODE])['stdout'], true, 8, JSON_THROW_ON_ERROR);
                if ($value !== null && !is_array($value)) {
                    throw new CompilationRefused("unexpected E_* constants from $version");
                }
                $constants[$version] = $value;
            }
        }
        $summary['php_overrides'] = [];
        foreach ($plan as $name => $v) {
            $summary['php_overrides'][$name] = $this->fpm->translate($pools[$name], $constants[$v['php']]);
        }
        [$access, $rootHeaders, $summary['htaccess_blockers']] = $this->htaccessAccess($plan);
        // Blockers are enforced (review F-03): a vhost whose .htaccess cannot be translated completely is
        // never served by OLS: Apache keeps it in the hybrid profile (HR-D08), otherwise compilation stops.
        $blocked = array_filter($summary['htaccess_blockers'], static fn(array $b): bool => $b !== []);
        if ($blocked !== [] && $this->hybridPorts === null) {
            $names = array_map('strval', array_keys($blocked));
            throw new CompilationRefused('untranslatable .htaccess in ' . implode(', ', $names) . ' (domain must stay on Apache): '
                . substr(json_encode($blocked, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), 0, 400), $names);
        }
        foreach (array_keys($blocked) as $name) {
            $plan[$name]['mode'] = 'apache';
        }
        $hybrid = array_map('strval', array_keys(array_filter($plan, static fn(array $v): bool => $v['mode'] === 'apache')));
        sort($hybrid, SORT_STRING);
        $summary['hybrid_vhosts'] = $hybrid;
        if ($poolUnreadable !== []) {
            sort($poolUnreadable, SORT_STRING);
            $summary['hybrid_reasons'] = array_fill_keys($poolUnreadable, ['PHP-FPM pool unreadable']);
        }
        // Apache's mod_php (handler "dso") runs tenant code as "nobody", the identity OLS uses to reach Apache's
        // backend ports; such a tenant could bypass OLS and forge the trusted client address (review RV-28).
        // HR-D14: only that vhost is held, never the whole compilation. It keeps the native configuration of the
        // active generation (the same rule as LsphpGuard); without one it stays served by Apache as it was before
        // the product (never left out: the site must keep answering). The hold ends by itself once the handler
        // changes (the vhost is then compiled normally).
        $shared = array_values(array_filter($hybrid, static fn(string $n): bool => $plan[$n]['php_handler'] === 'dso'));
        $held = [];
        $heldText = [];
        foreach ($shared as $name) {
            $previous = $this->previousVhost !== null ? ($this->previousVhost)($name) : null;
            $held[$name] = [self::HELD_DSO_REASON, $previous !== null ? 'keeps the configuration of the active generation'
                : 'served by Apache as before (no earlier OpenLiteSpeed configuration)'];
            if ($previous !== null) {
                $plan[$name]['mode'] = 'native';
                $heldText[$name] = $previous;
                unset($summary['php_overrides'][$name], $summary['htaccess_blockers'][$name]);
            }
        }
        if ($held !== []) {
            ksort($held, SORT_STRING);
            $summary['held_vhosts'] = $held;
            $hybrid = array_values(array_diff($hybrid, array_keys($heldText)));
            $summary['hybrid_vhosts'] = $hybrid;
        }
        $tls = [];
        foreach (array_keys($plan) as $name) {
            $combined = self::TLS_DIR . "/$name/combined";
            $tls[$name] = $this->run("tls-present-$name", ['/usr/bin/test', '-f', $combined])['exit_code'] === 0 ? $combined : null;
        }
        $summary['tls_sources'] = $tls;
        // Read like the lab compiler; production listeners do not depend on the host name.
        $this->run('hostname', ['/usr/bin/hostname', '-f']);
        // Per-address defaults and proxy-subdomains endpoints from cPanel's generated Apache
        // configuration, and the bound IPv6 addresses.
        $httpdConf = $this->required('apache-conf', ['/usr/bin/cat', '/etc/apache2/conf/httpd.conf']);
        $defaults = $this->model->apacheDefaults($httpdConf);
        $ipv6 = $this->model->boundIpv6($this->required('ipv6-addresses', ['/usr/sbin/ip', '-6', '-o', 'addr', 'show', 'scope', 'global']));
        $proxyEndpoints = $this->model->apacheProxyEndpoints($httpdConf);
        // With the hybrid profile cPanel binds every Apache vhost to the backend ports (apache_port/apache_ssl_port); the
        // endpoints OLS takes over are the public ones. Without this the compile after the cutover moved Apache differed
        // from the approved plan (lab 2026-10-28: a fresh install's cutover refused and returned to Apache) and lost the
        // per-address defaults and proxy-subdomains maps in the steady state.
        if ($this->hybridPorts !== null) {
            $ports = [$this->hybridPorts[0] => '80', $this->hybridPorts[1] => '443'];
            $public = static fn(string $endpoint): string => preg_replace_callback('/\|([0-9]+)$/D',
                static fn(array $m): string => '|' . ($ports[(int) $m[1]] ?? $m[1]), $endpoint) ?? $endpoint;
            $mapped = [];
            foreach ($defaults as $endpoint => $name) {
                $mapped[$public((string) $endpoint)] ??= $name;  // the first vhost on an endpoint stays its default
            }
            $defaults = $mapped;
            // The mapping keeps the order (81 before 444 as 80 before 443).
            $proxyEndpoints = array_values(array_unique(array_map($public, $proxyEndpoints)));
        }
        $summary['ipv6_addresses'] = $ipv6;
        $summary['apache_defaults'] = $defaults;
        $summary['apache_proxy_endpoints'] = $proxyEndpoints;
        $config = $this->compiler->serverConfig($this->serverTemplate, $plan, $ipv6, $defaults, $proxyEndpoints, $this->hybridPorts,
            $this->http3);
        // Alias directories absent on this host (and a vhost's deleted cgi-bin) get no context.
        $missing = [];
        foreach ($plan as $name => $v) {
            $missing[$name] = $this->missingAliases(['/cgi-bin/' => $v['docroot'] . '/cgi-bin/']);
        }
        $summary['missing_alias_dirs'] = $missing;
        $vhconf = [];
        foreach ($plan as $name => $v) {
            $vhconf[$name] = isset($heldText[$name]) ? $heldText[$name] : ($v['mode'] === 'apache'
                ? $this->surface->apacheVhost($v['docroot'], (string) $name, (string) $v['ip'], $tls[$name], $this->errorLogDir,
                    $this->hybridPorts ?? CpanelSurface::HYBRID_PORTS)
                : $this->compiler->vhostConfig($v, $pools[$name], $constants[$v['php']], $access[$name], $tls[$name],
                    $this->errorLogDir, $missing[$name], $rootHeaders[$name], $v['suspended'],
                    $this->phpLimits?->forAccount((string) $v['user'])));
        }
        foreach ($plan as $name => $v) {
            if ($v['mode'] === 'apache') {
                $vhconf[$this->surface->hybridTlsName((string) $name)] = $this->surface->apacheVhost($v['docroot'], (string) $name,
                    (string) $v['ip'], $tls[$name], $this->errorLogDir, $this->hybridPorts ?? CpanelSurface::HYBRID_PORTS, true);
                // LSCache (FV-01): both pass-through vhosts of a hybrid domain never use the cache.
                foreach ([(string) $name, $this->surface->hybridTlsName((string) $name)] as $passThrough) {
                    $vhconf[$passThrough] .= $this->cache->disabledBlock();
                }
            }
            if ($v['service_domains'] !== []) {
                $vhconf[$this->surface->serviceVhostName($name)] = $this->surface->serviceVhost($v['docroot'], $v['service_domains'],
                    $tls[$name]);
            }
        }
        // The service certificate cPanel's Apache currently uses (it moves to mycpanel.pem once installed).
        $cert = CpanelSurface::SERVICE_CERTS[count(CpanelSurface::SERVICE_CERTS) - 1];
        foreach (CpanelSurface::SERVICE_CERTS as $candidate) {
            if ($candidate === $cert || $this->run('service-cert', ['/usr/bin/test', '-f', $candidate])['exit_code'] === 0) {
                $cert = $candidate;
                break;
            }
        }
        $summary['service_cert'] = $cert;
        $summary['cache'] = $this->cache->summary($plan, $suspended);
        $vhconf[CpanelSurface::PROXY_VHOST] = $this->surface->proxyVhost($cert);
        $vhconf[CpanelSurface::DEFAULT_VHOST] = $this->surface->defaultVhost($cert,
            $this->missingAliases(['/cgi-bin/' => CpanelSurface::PROXY_DOCROOT . 'cgi-bin/']));
        if ($this->security !== null) {
            [$config, $vhconf, $summary] = $this->secure($plan, $config, $vhconf, $summary);
        }
        if ($this->phpLimits !== null && $this->phpLimits->overrides()) {
            // FV-03: only present with an operator input, so summaries without one are unchanged.
            $summary['php_limits'] = [];
            foreach ($this->phpLimits->accountsWithOverrides() as $user) {
                $summary['php_limits'][$user] = $this->phpLimits->forAccount($user);
            }
        }
        $errors = $this->lint->lint($config);
        foreach ($vhconf as $text) {
            array_push($errors, ...$this->lint->lint($text, false));
        }
        if ($errors !== []) {
            throw new CompilationRefused('Generated configuration fails lint: ' . implode('; ', $errors));
        }
        return ['config' => $config, 'vhconf' => $vhconf, 'plan' => $plan, 'summary' => $summary];
    }

    /**
     * Every cPanel vhost of each account (main, subdomains, addon vhosts; parked domains are aliases)
     * from /etc/userdatadomains and the per-vhost userdata (OLS-19).
     * @return array<string,array<string,mixed>>
     */
    private function plan(): array
    {
        $rows = $this->model->parseUserdataDomains($this->required('userdatadomains', ['/usr/bin/cat', '/etc/userdatadomains']));
        $plan = [];
        foreach (array_keys($this->tenants) as $user) {
            $user = (string) $user;
            $userdata = [];
            foreach ($rows as $domain => $row) {
                $domain = (string) $domain;
                if ($row['user'] !== $user || !in_array($row['type'], ['main', 'sub'], true)) {
                    continue;
                }
                // Validated before it names a file (the model refuses such a vhost anyway).
                if (!preg_match(self::DOMAIN, $domain)) {
                    throw new CompilationRefused("invalid domain '$domain' for $user", [$domain]);
                }
                $userdata[$domain] = $this->required("userdata-$domain", ['/usr/bin/cat', "/var/cpanel/userdata/$user/$domain"]);
                $this->userdata[$domain] = $userdata[$domain];
            }
            foreach ($this->model->accountVhosts($user, $rows, $userdata) as $v) {
                if ($v['php'] === '' || $v['php'] === 'inherit') {
                    // No version of its own: a new account until cPanel writes one into its userdata (about two minutes
                    // later, lab 2026-10-28), or "inherit". Apache serves it with the version cPanel resolves (the system
                    // default), so OLS takes the same answer from cPanel instead of refusing the whole compilation.
                    $resolved = $this->vhostVersions()[$v['pool']]['version'] ?? $this->vhostVersions()[$v['name']]['version'] ?? '';
                    $v['php'] = is_string($resolved) ? $resolved : '';
                }
                if (!preg_match(self::PHP_VERSION, $v['php'])) {
                    throw new CompilationRefused("invalid PHP version '{$v['php']}' for {$v['name']}", [$v['name']]);
                }
                // cPanel's "Force HTTPS Redirect" (Domains): Apache's plain-HTTP vhost answers 301 to https.
                $v['ssl_redirect'] = preg_match('/^ssl_redirect:\s*[\'"]?1[\'"]?\s*$/m', $userdata[$v['name']] ?? '') === 1;
                $plan[$v['name']] = $v + ['user' => $user];
            }
        }
        return $plan;
    }

    /**
     * FV-02, kept apart from the other compilation steps: cPanel's ModSecurity (SecurityTranslator), per-domain
     * disables and the product security input. Any blocker refuses the compilation (the current state is kept).
     * @param array<string,array<string,mixed>> $plan
     * @param array<string,string> $vhconf
     * @param array<string,mixed> $summary
     * @return array{0:string, 1:array<string,string>, 2:array<string,mixed>}
     */
    private function secure(array $plan, string $config, array $vhconf, array $summary): array
    {
        $secured = $this->securityTranslator->compileSecurity(
            fn(string $name, array $argv): array => $this->run($name, $argv), $plan, $this->userdata, $this->security,
            array_map('strval', array_keys($vhconf)), CpanelSurface::PROXY_VHOST,
            fn(string $name): string => $this->surface->serviceVhostName($name),
            fn(string $name): string => $this->surface->hybridTlsName($name));
        $config = $this->securityTranslator->applyServer($config, $secured);
        foreach ($secured['vhosts'] as $name => $block) {
            $vhconf[$name] .= $block;
        }
        return [$config, $vhconf, $summary + $secured['summary']];
    }

    /**
     * PHP handler per vhost (HR-D05): PHP-FPM where cPanel enabled it, otherwise the version's handler.
     * @param array<string,array<string,mixed>> $plan
     */
    private function phpHandlers(array &$plan): void
    {
        $fpm = [];
        foreach ($this->vhostVersions() as $vhost => $row) {
            $fpm[$vhost] = self::truthy($row['php_fpm'] ?? null);
        }
        $handlers = [];
        foreach ($this->apiList('php-handlers', 'php_get_handlers', 'version_handlers') as $row) {
            if (!array_key_exists('version', $row) || !is_scalar($row['version']) || !array_key_exists('current_handler', $row)) {
                throw new CompilationRefused('php_get_handlers row without a version or handler');
            }
            $handlers[(string) $row['version']] = $row['current_handler'];
        }
        foreach ($plan as $name => $v) {
            // cPanel reports an addon domain's vhost under the addon name (its FPM pool name), not the subdomain.
            $handler = ($fpm[$v['pool']] ?? $fpm[$name] ?? false) ? 'fpm' : ($handlers[$v['php']] ?? 'unknown');
            $plan[$name]['mode'] = 'native';
            if (!is_string($handler) || !in_array($handler, ServerCompiler::PHP_HANDLERS, true)) {
                if ($this->hybridPorts === null) {
                    throw new CompilationRefused('unsupported PHP handler ' . var_export($handler, true)
                        . " for $name (domain must stay on Apache)", [$name]);
                }
                $plan[$name]['mode'] = 'apache';  // hybrid profile: Apache keeps serving this vhost
            }
            $plan[$name]['php_handler'] = $handler;
        }
    }

    /**
     * Access control from every .htaccess under each docroot (OLS-16), read with the tenant's own
     * privileges. Apache (AllowOverride All on "/") also applies .htaccess files in every directory above
     * the docroot, so their text leads the docroot's own; unknown directives are blockers.
     * @param array<string,array<string,mixed>> $plan
     * @return array{0:array<string,string>, 1:array<string,list<string>>, 2:array<string,list<string>>}
     */
    private function htaccessAccess(array $plan): array
    {
        $access = $rootHeaders = $blockers = [];
        // RV-46: Apache's loaded modules decide every <IfModule>; unknown (the command failed): only the modules
        // EasyApache 4 always loads are assumed, as before.
        $listed = $this->run('httpd-modules', ['/usr/sbin/httpd', '-M']);
        $modules = null;
        if ($listed['exit_code'] === 0 && preg_match_all('/^\s*([A-Za-z0-9_]+_module)\s+\((?:static|shared)\)\s*$/m', $listed['stdout'], $found)) {
            $modules = $found[1];
        }
        foreach ($plan as $name => $v) {
            $user = $v['user'];
            $docroot = $v['docroot'];
            // Fail closed (review F-03): a directory the tenant cannot list or a file it cannot read is a
            // blocker, never an empty .htaccess; NUL-separated names keep paths with spaces intact.
            $listing = $this->run("htaccess-list-$name", [self::RUNUSER, '-u', $user, '--', '/usr/bin/find', '-H', $docroot,
                '-name', '.htaccess', '(', '-type', 'f', '-o', '-type', 'l', ')', '-printf', '%y%p\\0']);
            $files = $readBlockers = [];
            if ($listing['exit_code'] !== 0) {
                $readBlockers[] = '/: .htaccess scan incomplete (' . substr(trim($listing['stderr'] ?? ''), -160) . ')';
            }
            foreach (explode("\0", $listing['stdout']) as $entry) {
                if ($entry === '') {
                    continue;
                }
                $kind = substr($entry, 0, 1);
                $path = substr($entry, 1);
                $tail = substr($path, strlen($docroot));
                $slash = strrpos($tail, '/');
                $rel = trim($slash === false ? $tail : substr($tail, 0, $slash), '/');
                $where = '/' . ($rel !== '' ? "$rel/" : '');
                if ($kind !== 'f') {
                    // OLS never reads .htaccess itself, so a symlinked one would silently lose its
                    // restrictions; never follow it.
                    $readBlockers[] = "$where: .htaccess is a symlink";
                    continue;
                }
                $read = $this->run("htaccess-read-$name", [self::RUNUSER, '-u', $user, '--', '/usr/bin/cat', $path]);
                if ($read['exit_code'] !== 0) {
                    $readBlockers[] = "$where: .htaccess unreadable";
                    continue;
                }
                $files[$rel] = $read['stdout'];
            }
            $inherited = [];
            foreach ($this->model->ancestors($docroot) as $directory) {
                // The account's home and everything below it, on any /home* mount, is read as the account (by
                // whole path components: "/home/olscpa" is not inside user "olsc"); only "/" and the mount are root's.
                $parts = explode('/', trim($directory, '/'));
                $inHome = count($parts) >= 2 && HomePath::isMount($parts[0]) && $parts[1] === $user;
                $asUser = $inHome ? [self::RUNUSER, '-u', $user, '--'] : [];
                $read = $this->run("htaccess-ancestor-$name", [...$asUser, '/usr/bin/cat', rtrim($directory, '/') . '/.htaccess']);
                if ($read['exit_code'] === 0) {
                    $inherited[] = $read['stdout'];
                }
            }
            if ($inherited !== []) {
                $files[''] = implode("\n", [...$inherited, $files[''] ?? '']);
            }
            // RV-44: cPanel marks every response of a technical domain (its temporary *.cpanel.site names) "noindex".
            $names = [(string) $name, ...array_map('strval', $v['aliases'] ?? [])];
            $technical = array_filter($names, static fn(string $n): bool => preg_match(self::TECHNICAL_DOMAIN, $n) === 1);
            $vhostHeaders = count($technical) === count($names) ? [self::TECHNICAL_DOMAIN_HEADER] : [];
            [$realms, $contexts, $translated] = $this->htaccess->translate($files, $docroot, $modules, $vhostHeaders);
            $access[$name] = implode('', [...$realms, ...$contexts]);
            $rootHeaders[$name] = $this->htaccess->rootHeaderNames($contexts);
            $blockers[$name] = [...$readBlockers, ...$translated];
        }
        return [$access, $rootHeaders, $blockers];
    }

    /**
     * Alias URIs (cPanel's global Alias/ScriptAlias set, with $overrides) whose directory is absent.
     * @param array<string,string> $overrides
     * @return list<string>
     */
    private function missingAliases(array $overrides): array
    {
        $missing = [];
        foreach (array_merge(CpanelSurface::STATIC_ALIASES, CpanelSurface::CGI_ALIASES, $overrides) as $uri => $path) {
            $this->directories[$path] ??= $this->run('alias-dir', ['/usr/bin/test', '-d', $path])['exit_code'] === 0;
            if (!$this->directories[$path]) {
                $missing[] = (string) $uri;
            }
        }
        return $missing;
    }

    /**
     * cPanel's PHP answer per vhost (whmapi1 php_get_vhost_versions: resolved version, PHP-FPM), read once per compilation.
     * @return array<string,array<string,mixed>>
     */
    private function vhostVersions(): array
    {
        if ($this->vhostVersions === null) {
            $rows = [];
            foreach ($this->apiList('php-vhost-versions', 'php_get_vhost_versions', 'versions') as $row) {
                if (!array_key_exists('vhost', $row) || !is_scalar($row['vhost'])) {
                    throw new CompilationRefused('php_get_vhost_versions row without a vhost');
                }
                $rows[(string) $row['vhost']] = $row;
            }
            $this->vhostVersions = $rows;
        }
        return $this->vhostVersions;
    }

    /**
     * The list `$key` under "data" of a successful whmapi1 call.
     * @return list<array<string,mixed>>
     */
    private function apiList(string $name, string $command, string $key): array
    {
        $record = $this->run($name, ['/usr/local/cpanel/bin/whmapi1', '--output=json', $command]);
        if ($record['exit_code'] !== 0) {
            throw new CompilationRefused("API command $command failed");
        }
        $data = json_decode($record['stdout'], true, 64, JSON_THROW_ON_ERROR);
        $metadata = is_array($data) ? ($data['metadata'] ?? []) : null;
        if (!is_array($metadata) || !in_array($metadata['result'] ?? null, [1, 1.0, true], true)
            || ($metadata['command'] ?? null) !== $command) {
            throw new CompilationRefused("API semantic failure in $command");
        }
        $list = $data['data'][$key] ?? null;
        if (!is_array($list) || !array_is_list($list)) {
            throw new CompilationRefused("API answer of $command lacks data.$key");
        }
        foreach ($list as $row) {
            if (!is_array($row) || ($row !== [] && array_is_list($row))) {
                throw new CompilationRefused("API answer of $command has a malformed row");
            }
        }
        return $list;
    }

    /** stdout of a command that must succeed: cPanel state that cannot be read is never taken as empty. */
    private function required(string $name, array $argv): string
    {
        $record = $this->run($name, $argv);
        if ($record['exit_code'] !== 0) {
            throw new CompilationRefused('unable to read ' . $argv[count($argv) - 1] . " ($name)");
        }
        return $record['stdout'];
    }

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    private function run(string $name, array $argv): array
    {
        return $this->runner->run($name, $argv, self::TIMEOUT);
    }

    /** Python truthiness of a decoded JSON value ("0" is true, 0 and empty values are false). */
    private static function truthy(mixed $value): bool
    {
        return !in_array($value, [null, false, 0, 0.0, '', []], true);
    }
}
