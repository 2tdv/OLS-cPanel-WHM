<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * cPanel's global web surface for OLS tenant vhosts (G0-E, OLS-17): DCV exemption, global deny
 * files, service-subdomain proxies to cpsrvd (WebSocket upgrades as ws://), ActiveSync over HTTPS,
 * cgi-sys script paths, global Alias/ScriptAlias directories, the tenant's /cgi-bin/ and the
 * /cpanelwebcall/ proxy. Output is byte-identical
 * to build/vm-qualification/cpanel_surface.py (tests/compiler_equivalence.py).
 */
final class CpanelSurface
{
    public const DCV = '^/\.well-known/(acme-challenge/[0-9a-zA-Z_-]+|cpanel-dcv/[0-9a-zA-Z_-]+|'
        . 'pki-validation/[A-F0-9]{32}\.txt(\ Sectigo\ DCV)?|pki-validation/(\ Ballot169)?)$';
    public const DENY_FILES = '(^|/)(\.ht(access|passwds?)|\.user\.ini|php\.ini|error_log)$';
    /** Subdomain => cpsrvd port, from the cPanel proxy-subdomain vhost. */
    public const SERVICES = ['cpanel' => 2082, 'webmail' => 2095, 'webdisk' => 2077, 'cpcalendars' => 2079,
        'cpcontacts' => 2079];
    /** Service subdomains Apache maps to a cgi-sys script instead of a cpsrvd port. */
    public const SCRIPT_HOSTS = ['autoconfig' => '/cgi-sys/autoconfig.cgi', 'autodiscover' => '/cgi-sys/autodiscover.cgi'];
    /** Service subdomains whose WebSocket upgrades Apache proxies to cpsrvd (ws://). */
    public const WEBSOCKET_SERVICES = ['cpanel' => 2082, 'webmail' => 2095];
    /** Apache proxies /Microsoft-Server-ActiveSync* to this port on the SSL vhost only. */
    public const ACTIVESYNC_PORT = 2090;
    public const MAILMAN = '/usr/local/cpanel/3rdparty/mailman';
    /** Global Alias URI => directory (static; a missing directory is a 404 like Apache's). */
    public const STATIC_ALIASES = ['/bandwidth/' => '/usr/local/bandmin/htdocs/', '/img-sys/' => '/usr/local/cpanel/img-sys/',
        '/java-sys/' => '/usr/local/cpanel/java-sys/', '/mailman/archives/' => self::MAILMAN . '/archives/public/',
        '/pipermail/' => self::MAILMAN . '/archives/public/', '/sys_cpanel/' => '/usr/local/cpanel/sys_cpanel/'];
    /** ScriptAlias URI => directory (the tenant's own /cgi-bin/ is under its docroot). */
    public const CGI_ALIASES = ['/cgi-bin/' => '$DOC_ROOT/cgi-bin/', '/cgi-sys/' => '/usr/local/cpanel/cgi-sys/',
        '/mailman/' => self::MAILMAN . '/cgi-bin/'];
    /** Global ScriptAliasMatch paths => cgi-sys script, executed through the /cgi-sys/ CGI context. */
    public const GLOBAL_SCRIPTS = [
        ['^/?(controlpanel|cpanel|kpanel)/?$', '/cgi-sys/redirect.cgi'],
        ['^/?(securecontrolpanel|securecpanel)/?$', '/cgi-sys/sredirect.cgi'],
        ['^/?securewhm/?$', '/cgi-sys/swhmredirect.cgi'],
        ['^/?webmail(/.*)?$', '/cgi-sys/wredirect.cgi'],
        ['^/?whm/?$', '/cgi-sys/whmredirect.cgi'],
        ['^/[Aa]utodiscover/[Aa]utodiscover\.xml', '/cgi-sys/autodiscover.cgi'],
    ];

    /**
     * Apache's catch-all proxy-subdomains vhosts take any name starting with a service label that no
     * tenant claims (whm.<domain>, cpanel.<unknown>); OLS exact names win over these wildcards.
     */
    public const PROXY_VHOST = 'cpanel-proxy';
    public const PROXY_SERVICES = ['cpanel' => 2082, 'webmail' => 2095, 'whm' => 2086, 'webdisk' => 2077,
        'cpcontacts' => 2079, 'cpcalendars' => 2079];
    public const PROXY_WEBSOCKET = ['cpanel' => 2082, 'webmail' => 2095, 'whm' => 2086];
    public const PROXY_DOCROOT = '/var/www/html/';
    /**
     * cPanel's service certificate, in the order its Apache template uses them: the installed (e.g.
     * AutoSSL) certificate replaces the self-signed one; cPanel can switch at any time.
     */
    public const SERVICE_CERTS = ['/var/cpanel/ssl/cpanel/mycpanel.pem', '/var/cpanel/ssl/cpanel/cpanel.pem'];
    public const PROXY_CERT = '/var/cpanel/ssl/cpanel/cpanel.pem';
    /** DCV files of the domain behind the requested name; run by a regex CGI context (OLS never rewrites acme-challenge URLs). */
    public const DCV_HELPER = '/usr/local/cpanel/cgi-priv/get_local.cgi';

    /**
     * cPanel's global DCV exclusion ("Satisfy Any" + "Allow from all") also covers the alias directories,
     * which Apache never protects with a docroot realm; OLS contexts inherit the "/" realm unless they
     * pass accessControl with "satisfy any" (OLS patch 0006).
     */
    public const EXEMPT = "  accessControl  {\n    allow                 ALL\n  }\n  satisfy                 any\n";
    /** Alias contexts never inherit the tenant's translated "/" rewrite rules (RV-19). */
    public const NO_TENANT_REWRITE = "  rewrite  {\n    enable                0\n  }\n";

    public const DOMLOGS = '/etc/apache2/logs/domlogs';
    public const LOG_DIR = '/run/ols-cpanel/logs';
    /**
     * Apache's combinedvhost format with %v replaced by the literal domain (OLS-18). Apache's bytesvhost
     * writes %I and %O as two records; OLS has no line break in formats, so one record carries their sum
     * (%S). cpanellogd sums the records.
     */
    public const ACCESS_FORMAT = '%s:%%p %%a %%l %%u %%t "%%r" %%>s %%b "%%{Referer}i" "%%{User-Agent}i"';
    public const BYTES_FORMAT = '%s %%{%%s}t %%S .';

    /** Two vhost access logs written to the root log shipper's FIFOs (OLS workers run as nobody). */
    public function accessLogs(string $domain): string
    {
        $out = '';
        foreach (['access' => self::ACCESS_FORMAT, 'bytes' => self::BYTES_FORMAT] as $name => $format) {
            $out .= 'accesslog ' . self::LOG_DIR . "/$name.fifo {\n    useServer            0\n    rollingSize          0\n"
                . '    logFormat            ' . sprintf($format, $domain) . "\n}\n";
        }
        return $out;
    }

    /** Server-level proxy backends, one per cpsrvd port. */
    public function processors(): string
    {
        $ports = array_unique([...array_values(self::SERVICES), ...array_values(self::PROXY_SERVICES), self::ACTIVESYNC_PORT]);
        sort($ports);
        $out = '';
        foreach ($ports as $port) {
            $out .= "extProcessor cpsrvd$port {\n    type                 proxy\n    address              127.0.0.1:$port\n"
                . "    maxConns             20\n    initTimeout          60\n    retryTimeout         0\n"
                . "    respBuffer           0\n}\n";
        }
        return $out;
    }

    /** @return list<string> */
    public function hostAliases(string $domain): array
    {
        return array_map(static fn(string $name): string => "$name.$domain",
            [...array_keys(self::SERVICES), ...array_keys(self::SCRIPT_HOSTS)]);
    }

    /**
     * Vhost-level rules evaluated before the tenant's .htaccess rules. $domains are the vhost's
     * service domains (its main or addon domains; none for a plain subdomain).
     * @param list<string> $domains
     */
    public function rewriteRules(array $domains, bool $activeSync = true, bool $sslRedirect = false): string
    {
        $lines = ['RewriteCond %{REQUEST_URI} ' . self::DCV, 'RewriteRule ^ - [L]'];
        if ($sslRedirect) {
            // cPanel's Force HTTPS Redirect, as its Apache template writes it right after the DCV exemption: plain HTTP
            // (unless a proxy in front says https) gets 301 to the same host and path; the query string is kept.
            array_push($lines, 'RewriteCond %{HTTP:X-Forwarded-Proto} !https', 'RewriteCond %{HTTPS} !^on$',
                'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]');
        }
        // Like Apache: upgrades go to cpsrvd's WebSocket endpoint; other service rules skip upgrades.
        foreach ($domains as $domain) {
            $escaped = str_replace('.', '\.', $domain);
            foreach (self::WEBSOCKET_SERVICES as $name => $port) {
                $lines[] = 'RewriteCond %{HTTP:Upgrade} websocket [NC]';
                $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.$escaped(:[0-9]+)?$ [NC]";
                $lines[] = "RewriteRule ^/?(.*)$ ws://127.0.0.1:$port/\$1 [P,L]";
            }
        }
        foreach ($domains as $domain) {
            $escaped = str_replace('.', '\.', $domain);
            foreach (self::SERVICES as $name => $port) {
                $lines[] = 'RewriteCond %{HTTP:Upgrade} !websocket [NC]';
                $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.$escaped(:[0-9]+)?$ [NC]";
                $lines[] = "RewriteRule ^/?(.*)$ http://cpsrvd$port/\$1 [P,L]";
            }
            foreach (self::SCRIPT_HOSTS as $name => $script) {
                $lines[] = 'RewriteCond %{HTTP:Upgrade} !websocket [NC]';
                $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.$escaped(:[0-9]+)?$ [NC]";
                $lines[] = "RewriteRule ^ $script [L]";
            }
        }
        // Apache's ActiveSync proxy drops the path suffix and only exists on the account SSL vhosts.
        if ($activeSync) {
            $lines[] = 'RewriteCond %{HTTPS} on';
            $lines[] = 'RewriteRule ^/?Microsoft-Server-ActiveSync http://cpsrvd' . self::ACTIVESYNC_PORT
                . '/Microsoft-Server-ActiveSync/ [P,L]';
        }
        foreach (self::GLOBAL_SCRIPTS as [$pattern, $script]) {
            $lines[] = "RewriteRule $pattern $script [L]";
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * DCV first so it wins over the deny context and tenant restrictions. $missing lists alias URIs
     * whose directory does not exist on the host: OLS rejects such contexts with [ERROR], while the
     * request falls through to a 404 as under Apache. OLS contexts inherit the "/" context's header
     * operations; Apache applies the docroot .htaccess only inside the docroot, so the alias contexts
     * unset every header the tenant's root context sets ($unsetHeaders).
     * @param list<string> $missing
     * @param list<string> $unsetHeaders
     */
    public function contexts(array $missing = [], array $unsetHeaders = []): string
    {
        $unset = implode('', array_map(static fn(string $name): string => "Header unset $name\n", $unsetHeaders));
        $out = 'context exp:' . self::DCV . " {\n  allowBrowse             1\n" . self::EXEMPT . "}\n"
            . 'context exp:' . self::DENY_FILES . " {\n  allowBrowse             0\n}\n";
        foreach (self::STATIC_ALIASES as $uri => $location) {
            if (in_array($uri, $missing, true)) {
                continue;
            }
            // mailman.conf: archives are user content, never sniffed into an executable type.
            $ops = $unset . (str_starts_with($location, self::MAILMAN) ? "Header set X-Content-Type-Options nosniff\n" : '');
            $headers = $ops !== '' ? "  extraHeaders            <<<END_extraHeaders\n{$ops}END_extraHeaders\n" : '';
            $out .= "context $uri {\n  location                $location\n  allowBrowse             1\n" . self::EXEMPT . self::NO_TENANT_REWRITE . "$headers}\n";
        }
        foreach (self::CGI_ALIASES as $uri => $location) {
            if (in_array($uri, $missing, true)) {
                continue;
            }
            // Mailman's CGI wrappers are setuid/setgid mailman; OLS otherwise refuses them with 403.
            $setuid = str_starts_with($location, self::MAILMAN) ? "  allowSetUID             1\n" : '';
            $headers = $unset !== '' ? "  extraHeaders            <<<END_extraHeaders\n{$unset}END_extraHeaders\n" : '';
            $out .= "context $uri {\n  type                    cgi\n  location                $location\n"
                . "  allowBrowse             1\n$setuid" . self::EXEMPT . self::NO_TENANT_REWRITE . "$headers}\n";
        }
        $headers = $unset !== '' ? "  extraHeaders            <<<END_extraHeaders\n{$unset}END_extraHeaders\n" : '';
        return $out . "context /cpanelwebcall/ {\n  type                    proxy\n  handler                 cpsrvd2082\n"
            . "  addDefaultCharset       off\n" . self::EXEMPT . self::NO_TENANT_REWRITE . "$headers}\n";
    }

    /** @return list<string> */
    public const SUSPENDED_PAGE = '/cgi-sys/suspendedpage.cgi';

    /**
     * cPanel suspends an account's websites with RedirectMatch inside <Directory /home/<user>> and
     * AllowOverride none (account_suspensions.conf): every request that maps into the account's home is
     * redirected (302) to the suspended page; cPanel's aliases outside the home directory, /cgi-sys/, the
     * proxied /cpanelwebcall/ and the global /cpanel-style script URLs are not. Vhost-level rules ahead of
     * the DCV exemption, which Apache's redirect also overrides. $missing is the list given to contexts():
     * an alias without a context maps into the docroot, so only emitted aliases are exempt, and the global
     * script URLs only while /cgi-sys/ (which runs them) has a context.
     * @param list<string> $missing
     */
    public function suspensionRules(array $missing): string
    {
        $outside = array_values(array_filter(array_keys(self::STATIC_ALIASES),
            static fn(string $uri): bool => !in_array($uri, $missing, true)));
        foreach (self::CGI_ALIASES as $uri => $dir) {
            if (!str_starts_with($dir, '$DOC_ROOT') && !in_array($uri, $missing, true)) {
                $outside[] = $uri;
            }
        }
        $outside[] = '/cpanelwebcall/';
        $outside = array_values(array_unique($outside));
        sort($outside, SORT_STRING);
        $prefixes = implode('|', array_map(static fn(string $u): string => str_replace('.', '\\.', trim($u, '/')) . '/', $outside));
        $scripts = [];
        foreach (self::GLOBAL_SCRIPTS as [$pattern]) {
            if (str_starts_with($pattern, '^/?')) {
                $scripts[] = rtrim(substr($pattern, 3), '$');
            }
        }
        $globalScripts = in_array('/cgi-sys/', $missing, true) ? ''
            : 'RewriteCond %{REQUEST_URI} !^/(' . implode('|', $scripts) . ")\$\n"
            . "RewriteCond %{REQUEST_URI} !^/[Aa]utodiscover/[Aa]utodiscover\\.xml\n";
        return "RewriteCond %{REQUEST_URI} !^/($prefixes)\n" . $globalScripts
            . 'RewriteRule ^ ' . self::SUSPENDED_PAGE . " [R=302,L]\n";
    }

    public function proxyHosts(): array
    {
        return array_map(static fn(string $name): string => "$name.*",
            [...array_keys(self::PROXY_SERVICES), ...array_keys(self::SCRIPT_HOSTS)]);
    }

    /** Runs CGI as the server user (nobody), like Apache's proxy vhost without suexec. */
    public function proxyServerBlock(): string
    {
        return 'virtualHost ' . self::PROXY_VHOST . " {\n    vhRoot               " . self::PROXY_DOCROOT . "\n"
            . '    configFile           $SERVER_ROOT/conf/vhosts/' . self::PROXY_VHOST . "/vhconf.conf\n    allowSymbolLink      0\n"
            . "    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n";
    }

    public function proxyRules(): string
    {
        // Plain-HTTP DCV stops rewriting so the DCV context answers (acme-challenge never reaches here).
        $lines = ['RewriteCond %{HTTPS} !on', 'RewriteCond %{REQUEST_URI} ' . self::DCV, 'RewriteRule ^ - [L]'];
        foreach (self::PROXY_WEBSOCKET as $name => $port) {
            $lines[] = 'RewriteCond %{HTTP:Upgrade} websocket [NC]';
            $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.";
            $lines[] = "RewriteRule ^/?(.*)$ ws://127.0.0.1:$port/\$1 [P,L]";
        }
        foreach (self::PROXY_SERVICES as $name => $port) {
            if (isset(self::PROXY_WEBSOCKET[$name])) {
                $lines[] = 'RewriteCond %{HTTP:Upgrade} !websocket [NC]';
            }
            $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.";
            $lines[] = "RewriteRule ^/?(.*)$ http://cpsrvd$port/\$1 [P,L]";
        }
        foreach (self::SCRIPT_HOSTS as $name => $script) {
            $lines[] = "RewriteCond %{HTTP_HOST} ^$name\\.";
            $lines[] = "RewriteRule ^ $script [L]";
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * Apache's server default vhost (<VirtualHost *>, DocumentRoot /var/www/html): answers every name no
     * other vhost claims on an address (e.g. all names over IPv6 when no account has an IPv6 address)
     * with cPanel's global aliases and redirect scripts, nothing proxied, cPanel's service certificate.
     */
    public const DEFAULT_VHOST = 'server-default';

    public function defaultServerBlock(): string
    {
        return 'virtualHost ' . self::DEFAULT_VHOST . " {\n    vhRoot               " . self::PROXY_DOCROOT . "\n"
            . '    configFile           $SERVER_ROOT/conf/vhosts/' . self::DEFAULT_VHOST . "/vhconf.conf\n    allowSymbolLink      0\n"
            . "    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n";
    }

    /** @param list<string> $missing */
    public function defaultVhost(string $cert = self::PROXY_CERT, array $missing = []): string
    {
        return 'docRoot                  ' . self::PROXY_DOCROOT . "\nrewrite {\n    enable               1\n    autoLoadHtaccess     0\n"
            . "    rules                <<<END_rules\n" . $this->rewriteRules([], false) . "END_rules\n}\n"
            . $this->contexts($missing)
            . "vhssl {\n    keyFile              $cert\n    certFile             $cert\n    certChain            1\n}\n";
    }

    public function proxyVhost(string $cert = self::PROXY_CERT): string
    {
        return 'docRoot                  ' . self::PROXY_DOCROOT . "\nrewrite {\n    enable               1\n    autoLoadHtaccess     0\n"
            . "    rules                <<<END_rules\n" . $this->proxyRules() . "END_rules\n}\n"
            . 'context exp:' . self::DCV . " {\n  type                    cgi\n  location                " . self::DCV_HELPER . "\n"
            . "  allowBrowse             1\n}\n"
            . "context /cgi-sys/ {\n  type                    cgi\n  location                /usr/local/cpanel/cgi-sys/\n"
            . "  allowBrowse             1\n}\n"
            . "vhssl {\n    keyFile              $cert\n    certFile             $cert\n    certChain            1\n}\n";
    }

    /**
     * Service names of a tenant vhost get their own OLS vhost: the tenant's certificate and docroot (for
     * DCV) but none of the tenant's .htaccess settings, which OLS would otherwise apply to proxied
     * cpsrvd traffic through the "/" context (Apache proxies these names before any directory walk).
     */
    public function serviceVhostName(string $name): string
    {
        return "svc.$name";
    }

    /** @param string|null $home the account's home directory (default /home/<user>) */
    public function serviceServerBlock(string $name, string $user, ?string $home = null): string
    {
        $vhost = $this->serviceVhostName($name);
        $root = $home ?? "/home/$user";
        return "virtualHost $vhost {\n    vhRoot               $root/\n"
            . "    configFile           \$SERVER_ROOT/conf/vhosts/$vhost/vhconf.conf\n"
            . "    allowSymbolLink      2\n    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n";
    }

    /** @param list<string> $domains */
    public function serviceVhost(string $docroot, array $domains, ?string $tls = null): string
    {
        return 'docRoot                  ' . rtrim($docroot, '/') . "/\nrewrite {\n    enable               1\n    autoLoadHtaccess     0\n"
            . "    rules                <<<END_rules\n" . $this->rewriteRules($domains) . "END_rules\n}\n"
            . 'context exp:' . self::DCV . " {\n  allowBrowse             1\n}\n"
            . "context /cgi-sys/ {\n  type                    cgi\n  location                /usr/local/cpanel/cgi-sys/\n"
            . "  allowBrowse             1\n}\n"
            . ($tls !== null ? "vhssl {\n    keyFile              $tls\n    certFile             $tls\n    certChain            1\n}\n" : '');
    }

    /** Apache's backend ports in the hybrid profile (cPanel's apache_port / apache_ssl_port, as with ea-nginx). */
    public const HYBRID_PORTS = [81, 444];

    public function apacheBackendName(string $vhost, bool $tls): string
    {
        return 'apache-' . ($tls ? 'https' : 'http') . "-$vhost";
    }

    /**
     * The OLS vhost serving a hybrid domain on the HTTPS listeners: OLS skips rewrite rules for ACME paths
     * (contexts cannot test the scheme), so each scheme gets its own vhost and ACME context (review RV-28).
     */
    public function hybridTlsName(string $name): string
    {
        return "tls.$name";
    }

    /**
     * Server-level proxy backends, one pair per hybrid vhost: a TLS backend connection carries the SNI of
     * the vhost that opened it, so pools are never shared between vhosts (review RV-27).
     * @param list<array{0:string,1:string}> $vhosts (vhost name, IPv4 address)
     * @param array{0:int,1:int} $ports
     */
    public function apacheBackends(array $vhosts, array $ports = self::HYBRID_PORTS): string
    {
        usort($vhosts, static fn(array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]]);
        $out = '';
        foreach ($vhosts as [$name, $ip]) {
            foreach ([[false, $ports[0]], [true, $ports[1]]] as [$tls, $port]) {
                $out .= 'extProcessor ' . $this->apacheBackendName($name, $tls) . " {\n    type                 proxy\n"
                    . '    address              ' . ($tls ? 'https://' : '') . self::ipv4($ip) . ":$port\n    maxConns             100\n"
                    . "    initTimeout          60\n    retryTimeout         0\n    respBuffer           0\n}\n";
            }
        }
        return $out;
    }

    /**
     * A hybrid vhost for one scheme ($secure: the HTTPS listeners' vhost, hybridTlsName). OLS terminates TLS
     * with the domain's certificate and passes everything to Apache on the backend port of the same scheme,
     * which applies the account's own configuration (including cPanel's suspension). WebSocket upgrades are
     * tunnelled with the original, still encoded request path (the rewritten path is decoded; review RV-28)
     * and SNI (OLS patch 0010); ACME challenges, which OLS never rewrites, reach Apache through a proxy
     * context. Requests are logged by Apache only (client address from X-OLS-Client-IP, OLS patch 0010).
     * @param array{0:int,1:int} $ports
     */
    public function apacheVhost(string $docroot, string $name, string $ip, ?string $tls, string $errorLogDir,
                                array $ports = self::HYBRID_PORTS, bool $secure = false): string
    {
        $vhost = $secure ? $this->hybridTlsName($name) : $name;
        $backend = $this->apacheBackendName($name, $secure);
        $rules = "RewriteCond %{HTTP:Upgrade} websocket [NC]\nRewriteCond %{ORG_REQ_URI} ^(/.*)$\n"
            . 'RewriteRule ^ ' . ($secure ? 'wss' : 'ws') . '://' . self::ipv4($ip) . ':' . ($secure ? $ports[1] : $ports[0]) . "%1 [P,L]\n"
            . "RewriteRule ^/?(.*)$ http://$backend/\$1 [P,L]\n";
        return 'docRoot                  ' . rtrim($docroot, '/') . "/\nvhDomain                 $name\n"
            . "errorlog $errorLogDir/$vhost-error.log {\n    useServer            0\n    logLevel             INFO\n}\n"
            . "rewrite {\n    enable               1\n    autoLoadHtaccess     0\n    rules                <<<END_rules\n"
            . $rules . "END_rules\n}\n"
            . "context exp:^/\\.well-known/acme-challenge/ {\n  type                    proxy\n"
            . "  handler                 $backend\n  addDefaultCharset       off\n}\n"
            . ($secure && $tls !== null ? "vhssl {\n    keyFile              $tls\n    certFile             $tls\n    certChain            1\n}\n" : '');
    }

    /**
     * cPanel's userdata "ip" is always IPv4 (IPv6 is separate); OLS's string-address WebSocket connector
     * resolves IPv4 only (review RV-28), so anything else is refused rather than emitted.
     */
    private static function ipv4(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new \InvalidArgumentException("hybrid backend address must be IPv4: $ip");
        }
        return $ip;
    }
}
