<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

use OlsCpanel\Cpanel\Discovery\HomePath;
use OlsCpanel\Php\Ini\FpmPoolTranslator;
use OlsCpanel\Php\PhpLimits;

/**
 * Server and tenant vhost configuration for production ports (plan sections 12 and 17).
 * Output is kept byte-identical to the lab-proven server_config(production=True) and vhost_config()
 * in build/vm-qualification/tenant_isolation_probe.py (checked by tests/compiler_equivalence.py).
 *
 * Listeners mirror Apache's "Listen 0.0.0.0:port" + "Listen [::]:port": one listener per bound IPv6
 * address, and one IPv4 "*" listener while every account vhost shares one IPv4 address (userdata "ip").
 * Linux refuses a specific listener beside a wildcard one on the same port, so with several account
 * IPv4 addresses each gets its own listener with only its vhosts (and their service vhosts), plus one on
 * 127.0.0.1 for Apache's hostname and proxy-subdomains vhosts there. Apache picks vhosts by local
 * address and answers an unknown name with the first vhost on that address and port, so every listener
 * maps that default as "*" (read from cPanel's httpd.conf). Over IPv6 only vhosts with a cPanel IPv6
 * address answer; their service vhosts on HTTPS. On every specific-address listener unclaimed service
 * names are proxied only where cPanel binds its proxy-subdomains vhosts (read from httpd.conf).
 * Recompile when addresses change.
 */
final class ServerCompiler
{
    /** OLS runtime state (OLS patch 0009). */
    public const RUNTIME_DIR = '/run/ols-cpanel/lshttpd';
    private const TEMPLATE_CUT = 'extProcessor ea-php83 {';
    /** HTTP/3 (FV-04): the template line the opt-out turns off, as in tenant_isolation_probe.QUIC_ON. */
    private const QUIC_ON = "    quicEnable           1\n";
    private const QUIC_OFF = "    quicEnable           0\n";
    private const LISTENER_TLS ="    keyFile              \$SERVER_ROOT/conf/cert/lab.key\n"
        . "    certFile             \$SERVER_ROOT/conf/cert/lab.crt\n";

    private CpanelSurface $surface;
    private FpmPoolTranslator $fpm;
    private CachePolicy $cache;

    public function __construct(?CpanelSurface $surface = null, ?FpmPoolTranslator $fpm = null, ?CachePolicy $cache = null)
    {
        $this->surface = $surface ?? new CpanelSurface();
        $this->fpm = $fpm ?? new FpmPoolTranslator();
        $this->cache = $cache ?? new CachePolicy();
    }

    /** OLS vhost answering for Apache's default ServerName on an address. */
    public function defaultVhostFor(string $serverName, array $plan): string
    {
        if (isset($plan[$serverName])) {
            return $serverName;
        }
        if (str_starts_with($serverName, 'proxy-subdomains-vhost')) {
            return CpanelSurface::PROXY_VHOST;
        }
        return CpanelSurface::DEFAULT_VHOST;
    }

    /**
     * @param array<string,array<string,mixed>> $plan vhost name => account vhost model (with "user")
     * @param list<string> $ipv6 bound IPv6 addresses (canonical form)
     * @param array<string,string> $apacheDefaults "address|port" (port "" = any) => first ServerName
     * @param list<string> $proxyEndpoints "address|port" where cPanel binds a proxy-subdomains vhost
     * @param array{0:int,1:int}|null $hybridPorts Apache's backend ports when the hybrid profile is enabled
     * @param bool $http3 QUIC on the HTTPS listeners (FV-04); false is the operator opt-out (quicEnable 0, enableQuic 0)
     */
    public function serverConfig(string $base, array $plan, array $ipv6, array $apacheDefaults, array $proxyEndpoints = [],
                                 ?array $hybridPorts = null, bool $http3 = true): string
    {
        $head = substr($base, 0, (int) strpos($base, self::TEMPLATE_CUT));
        if (!str_contains($head, self::QUIC_ON)) {
            throw new \InvalidArgumentException('the server template has no quicEnable 1 line');
        }
        if (!$http3) {
            $head = str_replace(self::QUIC_ON, self::QUIC_OFF, $head);
        }
        $quic = '    enableQuic           ' . ($http3 ? '1' : '0') . "\n";
        // LSCache (FV-01): the cache module off at server level; tenant vhosts enable it in their own block.
        $parts = [$head, $this->cache->serverBlock()];
        foreach ($plan as $name => $v) {
            // vhRoot: the account's home on its /home<suffix> mount (HomePath).
            $home = HomePath::homeOf((string) ($v['docroot'] ?? ''), (string) $v['user']) ?? "/home/{$v['user']}";
            foreach (array_unique([(string) $name, $this->vhostFor((string) $name, $v, 443)]) as $vhost) {
                $parts[] = "virtualHost $vhost {\n    vhRoot               $home/\n"
                    . "    configFile           conf/vhosts/$vhost/vhconf.conf\n    allowSymbolLink      2\n"
                    . "    enableScript         1\n    restrained           1\n    setUIDMode           2\n}\n";
            }
            if ($v['service_domains'] !== []) {
                $parts[] = $this->surface->serviceServerBlock((string) $name, $v['user'], $home);
            }
        }
        $parts[] = $this->surface->proxyServerBlock();
        $parts[] = $this->surface->defaultServerBlock();
        $parts[] = $this->surface->processors();
        $hybrid = [];
        foreach ($plan as $name => $v) {
            if (($v['mode'] ?? 'native') === 'apache') {
                $hybrid[] = [(string) $name, (string) $v['ip']];
            }
        }
        if ($hybrid !== []) {
            $parts[] = $this->surface->apacheBackends($hybrid, $hybridPorts ?? CpanelSurface::HYBRID_PORTS);
        }
        $allMaps = function (int $port) use ($plan): string {
            $maps = [];
            foreach ($plan as $name => $v) {
                $maps[] = $this->map($this->vhostFor((string) $name, $v, $port), [$name, ...$v['aliases']]);
            }
            foreach ($plan as $name => $v) {
                if ($v['service_domains'] !== []) {
                    $maps[] = $this->map($this->surface->serviceVhostName((string) $name), $this->serviceHosts($v));
                }
            }
            $maps[] = $this->map(CpanelSurface::PROXY_VHOST, $this->surface->proxyHosts());
            return implode("\n", $maps);
        };
        $proxy = fn(string $address, int $port): array => in_array("$address|$port", $proxyEndpoints, true)
            ? [$this->map(CpanelSurface::PROXY_VHOST, $this->surface->proxyHosts())] : [];
        $ipv4 = [];
        foreach ($plan as $v) {
            if (($v['ip'] ?? '') !== '' && !in_array($v['ip'], $ipv4, true)) {
                $ipv4[] = $v['ip'];
            }
        }
        sort($ipv4, SORT_STRING);
        $listeners = [];
        if (count($ipv4) <= 1) {
            $listeners[] = ['', '*', $ipv4[0] ?? '', [80 => $allMaps(80), 443 => $allMaps(443)]];
        } else {
            $addresses = $ipv4;
            if (!in_array('127.0.0.1', $ipv4, true)) {
                $addresses['lo'] = '127.0.0.1';
            }
            foreach ($addresses as $number => $address) {
                $bound = static fn(array $v): bool => ($v['ip'] ?? '') === $address;
                $listenerMaps = [];
                foreach ([80, 443] as $port) {
                    [$own, $services] = $this->addressMaps($plan, $bound, $port);
                    $listenerMaps[$port] = implode("\n", [...$own, ...$services, ...$proxy($address, $port)]);
                }
                $listeners[] = ["4-$number", $address, $address, $listenerMaps];
            }
        }
        foreach (array_values($ipv6) as $number => $address) {
            $bound = static fn(array $v): bool => in_array($address, $v['ipv6'] ?? [], true);
            [$own80] = $this->addressMaps($plan, $bound, 80);
            [$own443, $services] = $this->addressMaps($plan, $bound, 443);
            $listeners[] = ["6-$number", "[$address]", $address, [80 => implode("\n", [...$own80, ...$proxy($address, 80)]),
                443 => implode("\n", [...$own443, ...$services, ...$proxy($address, 443)])]];
        }
        foreach ($listeners as [$suffix, $address, $key, $listenerMaps]) {
            foreach ([['http', 80, ''], ['https', 443, '1']] as [$kind, $port, $secure]) {
                $default = $this->defaultVhostFor(
                    $apacheDefaults["$key|$port"] ?? $apacheDefaults["*|$port"] ?? $apacheDefaults['*|'] ?? '', $plan);
                $wildcard = '    map                  '
                    . (isset($plan[$default]) ? $this->vhostFor($default, $plan[$default], $port) : $default) . ' *';
                $body = implode("\n", array_filter([$listenerMaps[$port], $wildcard], static fn(string $x): bool => $x !== ''));
                $parts[] = "listener $kind$suffix {\n    address              $address:$port\n    secure               "
                    . ($secure !== '' ? $secure : '0') . "\n" . ($secure !== '' ? self::LISTENER_TLS . $quic : '') . "$body\n}\n";
            }
        }
        return implode('', $parts);
    }

    /**
     * One tenant vhost (vhconf.conf).
     * @param array<string,mixed> $v account vhost model (with "user" and "name")
     * @param array<string,int>|null $constants
     * @param list<string> $missing
     * @param list<string> $unsetHeaders
     * @param array{children:int, max_conns:int, mem_soft:int, mem_hard:int, proc_soft:int, proc_hard:int}|null $limits
     *        the account's PHP limits (PhpLimits::forAccount, memory in bytes); null is PhpLimits::BUILTIN
     */
    public function vhostConfig(array $v, string $pool, ?array $constants, string $access, ?string $tls,
                                string $errorLogDir, array $missing = [], array $unsetHeaders = [],
                                bool $suspended = false, ?array $limits = null): string
    {
        $limits ??= PhpLimits::BUILTIN;
        $user = $v['user'];
        $name = $v['name'];
        $handlers = implode("\n", array_map(static fn(string $s): string => "    add                  lsapi:$user-php $s",
            $this->fpm->suffixes($pool)));
        return "docRoot                  {$v['docroot']}/\nvhDomain                 $name\n"
            . "errorlog $errorLogDir/$name-error.log {\n    useServer            0\n    logLevel             INFO\n}\n"
            . "index {\n    useServer            0\n    indexFiles           index.html, index.php\n"
            . "    # Mirrors the lab Apache, which lists directories unless \"Options -Indexes\" applies.\n"
            . "    autoIndex            1\n}\n"
            . "extProcessor $user-php {\n    type                 lsapi\n    address              uds:/" . self::RUNTIME_DIR . "/$name-php.sock\n"
            . "    maxConns             {$limits['max_conns']}\n    env                  PHP_LSAPI_CHILDREN={$limits['children']}\n    env                  LSPHP_ENABLE_USER_INI=on\n"
            // An idle worker leaves after 10 s, as cPanel's PHP-FPM default (pm.process_idle_timeout); LSAPI keeps one for
            // 300 s otherwise (lab 2026-10-28: a 116 MiB WordPress worker held for five minutes). The parent keeps OPcache,
            // so a new worker is a cheap fork.
            . "    env                  LSAPI_MAX_IDLE=10\n"
            . $this->phpEnvironment($v) . "    initTimeout          60\n    retryTimeout         0\n    persistConn          1\n    respBuffer           0\n"
            . "    autoStart            2\n    path                 /opt/cpanel/{$v['php']}/root/usr/bin/lsphp\n"
            . "    extUser              $user\n    extGroup             $user\n    backlog              50\n"
            . "    instances            1\n    memSoftLimit         {$limits['mem_soft']}\n    memHardLimit         {$limits['mem_hard']}\n"
            . "    procSoftLimit        {$limits['proc_soft']}\n    procHardLimit        {$limits['proc_hard']}\n}\n"
            . "scripthandler {\n$handlers\n}\n"
            . "rewrite {\n    enable               1\n    autoLoadHtaccess     0\n    rules                <<<END_rules\n"
            . ($suspended ? $this->surface->suspensionRules($missing) : '') . $this->cache->vhostRules($v, $suspended)
            . $this->surface->rewriteRules([], true, (bool) ($v['ssl_redirect'] ?? false)) . "END_rules\n}\n"
            . $this->surface->contexts($missing, $unsetHeaders) . $this->surface->accessLogs($name) . "\n"
            . $this->fpm->overrideBlock($this->fpm->translate($pool, $constants)) . $access
            . ($tls !== null ? "vhssl {\n    keyFile              $tls\n    certFile             $tls\n    certChain            1\n}\n" : '')
            . $this->cache->vhostBlock($v, $suspended);
    }

    /** PHP handlers the product reproduces (HR-D05); any other handler keeps the domain on Apache. */
    public const PHP_HANDLERS = ['fpm', 'cgi', 'fcgi', 'suphp'];

    /**
     * Extra LSAPI environment reproducing the Apache PHP handler's INI loading. suPHP (as configured by
     * cPanel) loads the docroot php.ini as the main file, then scans the global php.ini, php.d and the
     * docroot. lsphp ignores scan directories when PHPRC is set, so the same files are scanned in the
     * same order after the global php.ini: identical effective values, only php_ini_loaded_file() names
     * the global file. FPM, CGI and fcgid need nothing extra.
     * @param array<string,mixed> $v
     */
    public function phpEnvironment(array $v): string
    {
        if (($v['php_handler'] ?? 'fpm') !== 'suphp') {
            return '';
        }
        $etc = "/opt/cpanel/{$v['php']}/root/etc";
        return "    env                  PHP_INI_SCAN_DIR=$etc:$etc/php.d:{$v['docroot']}\n";
    }

    /**
     * The OLS vhost answering for a cPanel vhost on a port: hybrid vhosts have one per scheme.
     * @param array<string,mixed> $v
     */
    public function vhostFor(string $name, array $v, int $port): string
    {
        return $port === 443 && ($v['mode'] ?? 'native') === 'apache' ? $this->surface->hybridTlsName($name) : $name;
    }

    /** @param list<string> $hosts */
    private function map(string $vhost, array $hosts): string
    {
        return "    map                  $vhost " . implode(', ', $hosts);
    }

    /**
     * Vhost and service vhost maps of the vhosts bound to one address.
     * @param array<string,array<string,mixed>> $plan
     * @param callable(array<string,mixed>):bool $bound
     * @return array{0:list<string>,1:list<string>}
     */
    private function addressMaps(array $plan, callable $bound, int $port): array
    {
        $own = $services = [];
        foreach ($plan as $name => $v) {
            if ($bound($v)) {
                $own[] = $this->map($this->vhostFor((string) $name, $v, $port), [$name, ...$v['aliases']]);
                if ($v['service_domains'] !== []) {
                    $services[] = $this->map($this->surface->serviceVhostName((string) $name), $this->serviceHosts($v));
                }
            }
        }
        return [$own, $services];
    }

    /** @param array<string,mixed> $v @return list<string> */
    private function serviceHosts(array $v): array
    {
        $hosts = [];
        foreach ($v['service_domains'] as $domain) {
            array_push($hosts, ...$this->surface->hostAliases($domain));
        }
        return $hosts;
    }
}
