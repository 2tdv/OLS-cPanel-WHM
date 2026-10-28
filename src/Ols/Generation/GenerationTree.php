<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Generation;

use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Ols\Compiler\CpanelSurface;

/**
 * A compiled production configuration (ServerConfigurationBuilder::compile()) as one self-contained
 * generation: the engine.apply arguments. Port of generation_tree(..., production=True) in
 * build/vm-qualification/ols_generation_probe.py, byte-identical (tests/generation_tree.py):
 *
 * - every vhost configFile points into GEN_ROOT/<generation>/vhosts/, so the tree never depends on the
 *   server root;
 * - the listener certificate (ServerCompiler's LISTENER_TLS, `$SERVER_ROOT/conf/cert/lab.key` and `lab.crt`,
 *   full-string replacements) is the product's LISTENER_KEY / LISTENER_CERT: the default certificate in the
 *   state directory that `install --prepare` creates, read by OLS when it starts (it answers names that
 *   have no vhost certificate);
 * - the marker vhost and its loopback listener (127.0.0.1:8097) serve the generation id to the activator;
 * - each vhost gets the health rule ahead of its own rules, a static health context and health/<vhost>/id;
 * - summary.json: the compile summary the plugins show (docs/product-interfaces.md, plugin data), with
 *   "compiled_at"; product-only (the lab tree has no summary), never part of the source digest.
 *
 * Health targets: the activator checks plain HTTP on port 80 of the first listener that maps the vhost,
 * preferring its own address. Account vhosts and their service vhosts are checked on their own IPv4
 * address with their own host name (a server with several addresses has no account vhost on 127.0.0.1),
 * and their health context then also admits that address (the source of a local connection to it). The
 * cPanel proxy and server default vhosts are checked on 127.0.0.1 (the wildcard listener, or cPanel's
 * loopback proxy binding), else on the first address that maps them, with a host that only they claim
 * (`cpanel.ols-health.invalid`, or an unclaimed name for a listener default). A vhost that no port-80
 * listener maps (a hybrid domain's HTTPS vhost `tls.<domain>`, a default answering only on 443) is checked
 * over TLS on port 443 the same way (review RV-29, finding 12): `https://<IPv4>:443/.ols-cpanel-generation/id`,
 * the host as SNI and Host header, the certificate not verified (the activator proves which generation
 * answers, not who the server is); OLS answers the health path locally in every vhost, a hybrid one
 * included (the health rule precedes its proxy rule). Only a vhost no IPv4 listener on 80 or 443 maps
 * gets no target and is listed in "unprobed" (covered by OLS's configuration test during validation).
 */
final class GenerationTree
{
    public const GEN_ROOT = '/var/lib/ols-cpanel/generations';
    /** The listener default certificate `install --prepare` creates (Deployment\CutoverPlan::DEFAULT_KEY / DEFAULT_CERT). */
    public const LISTENER_KEY = LocalEngine::STATE . '/' . CutoverPlan::DEFAULT_KEY;
    public const LISTENER_CERT = LocalEngine::STATE . '/' . CutoverPlan::DEFAULT_CERT;
    public const LISTENER_TLS = ['$SERVER_ROOT/conf/cert/lab.key' => self::LISTENER_KEY, '$SERVER_ROOT/conf/cert/lab.crt' => self::LISTENER_CERT];
    public const MARKER_VHOST = 'olscp-gen';
    public const MARKER_PORT = 8097;
    public const HEALTH_URI = '/.ols-cpanel-generation/';
    /** Ahead of every vhost rule (service proxies, tenant rules): the health path is never rewritten. */
    public const HEALTH_RULE = "RewriteRule ^/\\.ols-cpanel-generation/ - [L]\n";
    /** A name no vhost claims: requests carrying it reach a listener's default ("*") vhost. */
    public const HEALTH_MISS = 'ols-health.invalid';
    public const ID = '/^r[0-9]{14}-[0-9a-f]{6}$/D';
    /** The builder's domain grammar: at least two dot-separated labels (ServerConfigurationBuilder::DOMAIN). */
    public const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';
    /** Product vhosts without a domain name (the marker vhost is added here, never compiled). */
    public const FIXED_VHOSTS = [CpanelSurface::PROXY_VHOST, CpanelSurface::DEFAULT_VHOST, self::MARKER_VHOST];
    /**
     * Health URLs the activator may request: plain HTTP to loopback on any port or to an IPv4 address on port
     * 80, or HTTPS to an IPv4 address on port 443 (SNI and Host = the target's host, certificate not verified).
     */
    public const HEALTH_URL = '#^(https?)://((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])):'
        . '([1-9][0-9]{0,4})/\.ols-cpanel-generation/[A-Za-z0-9_-][A-Za-z0-9._-]*$#D';

    /** Summary fields the plugins read; per vhost only these model fields. */
    // cache (FV-01), waf and security (FV-02): read by the plugins and by `ols-cpanel waf status`.
    public const SUMMARY_FIELDS = ['hybrid_vhosts', 'htaccess_blockers', 'tls_sources', 'suspended_accounts', 'missing_alias_dirs',
        'cache', 'waf', 'security'];
    public const SUMMARY_VHOST_FIELDS = ['user', 'type', 'docroot', 'aliases', 'php', 'php_handler'];

    private CpanelSurface $surface;
    /** @var \Closure():int */
    private \Closure $clock;

    /** @param (\Closure():int)|null $clock Unix time of "compiled_at" */
    public function __construct(private readonly string $genRoot = self::GEN_ROOT, ?CpanelSurface $surface = null, ?\Closure $clock = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
        if (!preg_match('#^(/[A-Za-z0-9._-]+)+$#D', $genRoot)) {
            throw new \InvalidArgumentException('unsafe generation root');
        }
        $this->surface = $surface ?? new CpanelSurface();
    }

    /** A new generation id: r<YYYYmmddHHMMSS>-<6 hex> (UTC). */
    public static function newId(?int $time = null): string
    {
        return 'r' . gmdate('YmdHis', $time ?? time()) . '-' . bin2hex(random_bytes(3));
    }

    /**
     * The engine.apply arguments for a compiled configuration, plus "unprobed" (vhosts without a health
     * target, with the reason) for the caller's report.
     * @param array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>} $compiled
     * @return array{generation:string, files:array<string,string>, health:list<array{vhost:string,host:string,url:string}>, epoch:int, source_sha256:string, unprobed:list<array{vhost:string,reason:string}>}
     */
    public function arguments(array $compiled, string $generation, int $epoch, string $sourceSha256): array
    {
        if (!preg_match(self::ID, $generation) || $epoch < 0 || !preg_match('/^[0-9a-f]{64}$/D', $sourceSha256)) {
            throw new \InvalidArgumentException('invalid generation id, epoch or source digest');
        }
        return ['generation' => $generation, ...$this->build($compiled, $generation), 'epoch' => $epoch, 'source_sha256' => $sourceSha256];
    }

    /**
     * @param array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>} $compiled
     * @return array{files:array<string,string>, health:list<array{vhost:string,host:string,url:string}>, unprobed:list<array{vhost:string,reason:string}>}
     */
    public function build(array $compiled, string $generation): array
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $generation)) {
            throw new \InvalidArgumentException('invalid generation id');
        }
        $base = "{$this->genRoot}/$generation";
        $config = (string) preg_replace('/(configFile\s+)(\$SERVER_ROOT\/)?conf\/vhosts\//', '${1}' . $base . '/vhosts/', $compiled['config']);
        $config = strtr($config, self::LISTENER_TLS);
        if (str_contains($config, '$SERVER_ROOT/conf/cert/')) {
            throw new \InvalidArgumentException('unexpected listener certificate reference');
        }
        $listeners = [80 => self::httpListeners($config), 443 => self::httpListeners($config, 443)];
        $config .= 'virtualHost ' . self::MARKER_VHOST . " {\n    vhRoot               $base/marker/\n"
            . "    configFile           $base/vhosts/" . self::MARKER_VHOST . "/vhconf.conf\n    allowSymbolLink      0\n"
            . "    enableScript         0\n    restrained           1\n    setUIDMode           0\n}\n"
            . "listener generation {\n    address              127.0.0.1:" . self::MARKER_PORT . "\n    secure               0\n"
            . '    map                  ' . self::MARKER_VHOST . " *\n}\n";
        $files = ['httpd_config.conf' => $config, 'summary.json' => $this->summaryJson($compiled['summary'] ?? [])];
        $health = $unprobed = [];
        foreach ($compiled['vhconf'] as $name => $text) {
            $name = (string) $name;
            if (!self::validVhost($name) || $name === self::MARKER_VHOST) {
                throw new \InvalidArgumentException("invalid vhost name $name");
            }
            $target = $this->target($name, $compiled['plan'], $listeners);
            $address = $target === null ? '127.0.0.1' : self::targetAddress($target['url']);
            $allow = $address === '127.0.0.1' ? '127.0.0.1' : "127.0.0.1, $address";
            $files["vhosts/$name/vhconf.conf"] = str_replace("<<<END_rules\n", "<<<END_rules\n" . self::HEALTH_RULE, $text)
                . $this->healthContext($base, $name, $allow);
            $files["health/$name/id"] = "$generation $name\n";
            if ($target !== null) {
                $health[] = $target;
            } else {
                $unprobed[] = ['vhost' => $name, 'reason' => 'no IPv4 listener on port 80 or 443 maps it (validated by the configuration test only)'];
            }
        }
        $files['vhosts/' . self::MARKER_VHOST . '/vhconf.conf'] = "docRoot                  $base/marker/\n";
        $files['marker/generation'] = "$generation\n";
        return ['files' => $files, 'health' => $health, 'unprobed' => $unprobed];
    }

    /** An OLS vhost name engine.apply accepts: a domain, a fixed product vhost or svc.<domain> (tls.<domain> is a domain). */
    public static function validVhost(string $name): bool
    {
        return strlen($name) <= 253 && (preg_match(self::DOMAIN, $name) === 1 || in_array($name, self::FIXED_VHOSTS, true)
            || (str_starts_with($name, 'svc.') && preg_match(self::DOMAIN, substr($name, 4)) === 1));
    }

    public static function validHealthUrl(string $url): bool
    {
        return preg_match(self::HEALTH_URL, $url, $m) === 1 && (int) $m[3] <= 65535
            && ($m[1] === 'https' ? $m[3] === '443' : $m[2] === '127.0.0.1' || $m[3] === '80');
    }

    /** The IPv4 address a health URL connects to (the source address of that local connection). */
    public static function targetAddress(string $url): string
    {
        $authority = explode('/', $url)[2];
        return substr($authority, 0, (int) strrpos($authority, ':'));
    }

    /**
     * The plugins' view of a compile: the summary fields, each vhost's model fields and "compiled_at" (UTC,
     * ISO 8601); pretty JSON with keys sorted at every level.
     * @param array<string,mixed> $summary ServerConfigurationBuilder's compile summary
     */
    public function summaryJson(array $summary): string
    {
        $out = ['compiled_at' => gmdate('Y-m-d\TH:i:s\Z', ($this->clock)())];
        foreach (self::SUMMARY_FIELDS as $field) {
            $out[$field] = $summary[$field] ?? null;
        }
        $out['vhosts'] = [];
        foreach ($summary['vhosts'] ?? [] as $name => $vhost) {
            $out['vhosts'][(string) $name] = array_intersect_key((array) $vhost, array_flip(self::SUMMARY_VHOST_FIELDS));
        }
        return json_encode(self::sorted($out), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_THROW_ON_ERROR) . "\n";
    }

    private static function sorted(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        $value = array_map([self::class, 'sorted'], $value);
        if (!array_is_list($value)) {
            ksort($value, SORT_STRING);
        }
        return $value;
    }

    /**
     * health.json as the lab writes it (Python `json.dumps(targets, indent=1)`), byte for byte.
     * @param list<array<string,string>> $targets
     */
    public static function healthJson(array $targets): string
    {
        if ($targets === []) {
            return '[]';
        }
        $items = [];
        foreach ($targets as $target) {
            $fields = [];
            foreach ($target as $key => $value) {
                $fields[] = '  ' . json_encode((string) $key, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . ': '
                    . json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            }
            $items[] = " {\n" . implode(",\n", $fields) . "\n }";
        }
        return "[\n" . implode(",\n", $items) . "\n]";
    }

    /**
     * IPv4 listeners on a port (80: plain HTTP, 443: HTTPS), in configuration order.
     * @return list<array{0:string, 1:list<array{0:string, 1:list<string>}>}> (address or "*", [(vhost, hosts)])
     */
    public static function httpListeners(string $config, int $port = 80): array
    {
        preg_match_all('/^listener \S+ \{\n((?:[^\n]*\n)*?)\}\n/m', $config, $blocks);
        $out = [];
        foreach ($blocks[1] as $body) {
            if (!preg_match('/^\s*address\s+(\S+)\s*$/m', $body, $address) || str_starts_with($address[1], '[')
                || !str_ends_with($address[1], ":$port")) {
                continue;
            }
            preg_match_all('/^\s*map\s+(\S+)\s+(.+?)\s*$/m', $body, $maps, PREG_SET_ORDER);
            $out[] = [substr($address[1], 0, -strlen(":$port")), array_map(static fn(array $m): array => [$m[1], array_map('trim', explode(',', $m[2]))], $maps)];
        }
        return $out;
    }

    /**
     * Port 80 first; only a vhost no port-80 listener maps is checked over TLS on 443.
     * @param array<string,array<string,mixed>> $plan
     * @param array<int,list<array{0:string, 1:list<array{0:string, 1:list<string>}>}>> $listeners port => listeners
     * @return array{vhost:string,host:string,url:string}|null
     */
    private function target(string $name, array $plan, array $listeners): ?array
    {
        $owner = isset($plan[$name]) ? $name : null;
        foreach (array_keys($plan) as $candidate) {
            if ($owner === null && in_array($name, [$this->surface->serviceVhostName((string) $candidate),
                    $this->surface->hybridTlsName((string) $candidate)], true)) {
                $owner = (string) $candidate;
            }
        }
        $own = $owner !== null && ($plan[$owner]['ip'] ?? '') !== '' ? (string) $plan[$owner]['ip'] : '127.0.0.1';
        foreach ([80 => 'http', 443 => 'https'] as $port => $scheme) {
            $best = $this->best($name, $own, $listeners[$port] ?? []);
            if ($best !== null) {
                return ['vhost' => $name, 'host' => $best[1], 'url' => "$scheme://{$best[0]}:$port" . self::HEALTH_URI . 'id'];
            }
        }
        return null;
    }

    /**
     * The listener address (own address first, then the wildcard as the own address, then any other) and host.
     * @param list<array{0:string, 1:list<array{0:string, 1:list<string>}>}> $listeners
     * @return array{0:string, 1:string}|null
     */
    private function best(string $name, string $own, array $listeners): ?array
    {
        $best = null;
        foreach ($listeners as [$address, $maps]) {
            $hosts = null;
            foreach ($maps as [$vhost, $list]) {
                if ($vhost === $name) {
                    $hosts = $list;
                    break;
                }
            }
            if ($hosts === null) {
                continue;
            }
            $rank = $address === $own ? 0 : ($address === '*' ? 1 : 2);
            if ($best === null || $rank < $best[0]) {
                $best = [$rank, $address === '*' ? $own : $address, str_replace('*', self::HEALTH_MISS, $hosts[0])];
            }
        }
        return $best === null ? null : [$best[1], $best[2]];
    }

    /**
     * Static context answering "<generation> <vhost>" (health_context of the lab): "satisfy any" keeps a
     * tenant realm on "/" from hiding it; rewriting is off because OLS applies docroot .htaccess rules even
     * to contexts outside the docroot (RV-19).
     */
    private function healthContext(string $base, string $name, string $allow): string
    {
        return 'context ' . self::HEALTH_URI . " {\n    location             $base/health/$name/\n    allowBrowse          1\n"
            . "    accessControl  {\n        allow                $allow\n        deny                 ALL\n    }\n"
            . "    satisfy              any\n    rewrite  {\n        enable               0\n    }\n}\n";
    }
}
