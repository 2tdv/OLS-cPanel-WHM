<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * WAF and security part of a compilation (feature vertical FV-02, plan sections 20.1, 20.2 and 21.6). Port of
 * build/vm-qualification/modsec_translate.py (translate_cpanel, policy, compile_security, apply_server); output
 * and summaries are identical (tests/compiler_equivalence.py, tests/compile_replay_security.py).
 *
 * cPanel's ModSecurity 2 state (EA4's modsec2.conf, the administrator's modsec2.user.conf, WHM's generated
 * modsec2.cpanel.conf with vendor includes and disabled rules, every included vendor file and its data files,
 * the per-domain userdata key secruleengineoff) becomes one server `module mod_security` block loading the same
 * files in the same order and one vhost block per exception. Requests Apache proxies to cpsrvd (service and
 * proxy vhosts) and hybrid vhosts (Apache applies its own ModSecurity) run with the engine off, as under Apache.
 * Anything OLS's libmodsecurity 3 cannot reproduce stops the compilation (fail closed).
 *
 * The optional product security input adds server per-client limits (`perClientConnLimit`), IP allow (OLS
 * trusted clients: exempt from per-client limits and bans, never from the WAF) and block lists (server
 * `accessControl`), accepted weaker differences, and operator exceptions (FV-06): rule ids removed for one vhost,
 * or its engine off, each with a reason and an optional expiry.
 */
final class SecurityTranslator
{
    public const MODULE_CONF = '/etc/apache2/conf.modules.d/800-mod_security2.conf';
    public const MODSEC2_CONF = '/etc/apache2/conf.d/modsec2.conf';
    public const USER_CONF = '/etc/apache2/conf.d/modsec/modsec2.user.conf';
    public const CPANEL_CONF = '/etc/apache2/conf.d/modsec/modsec2.cpanel.conf';
    /** The product's audit log (root 0600, opened by OLS when it loads the rules). */
    public const AUDIT_LOG = '/usr/local/lsws/logs/modsec_audit.log';
    /** No request or response bodies in the audit log (plan section 20.2: audit data redaction). */
    public const AUDIT_PARTS = 'ABFHZ';
    /** Weakening differences an operator may accept by code. */
    public const WEAKER_CODES = ['oversized-request-body', 'oversized-response-body'];
    private const MAX_INLINE = 8000;
    private const MAX_FILES = 200;
    private const SAFE_VALUE = '/^[A-Za-z0-9._\/:-]*$/D';
    private const SECTIONS = ['security2_module' => 1, 'ruid2_module' => 2, 'mpm_itk_module' => 2];
    private const DROPPED = [1 => ['secauditlog', 'secdebuglog', 'secdebugloglevel'], 2 => ['secauditlogstoragedir', 'secauditlogtype']];
    private const POLICY_KEYS = ['exceptions', 'per_client', 'ip_allow', 'ip_block', 'accept_differences', 'evaluated_at'];
    private const PER_CLIENT = [['staticReqPerSec', 0, 1000000], ['dynReqPerSec', 0, 1000000], ['outBandwidth', 0, 2147483647],
        ['inBandwidth', 0, 2147483647], ['softLimit', 1, 1000000], ['hardLimit', 1, 1000000], ['gracePeriod', 1, 3600],
        ['banPeriod', 1, 31536000]];
    private const EXCEPTION_KEYS = ['vhost', 'rule_ids', 'engine', 'reason', 'approver', 'expires'];
    private const MAX_LIST = 1000;
    private const PRINTABLE = '/^[\x20-\x7e]+$/D';
    private const LIMIT_TIME = 4611686018427387904;
    private const ACCESS_BLOCK = '/^accessControl \{\n((?:    [^\n]*\n)*)\}\n/m';
    private const PROXIED = 'requests proxied to cpsrvd (cPanel turns the rule engine off for them)';

    private static function refuse(string $message): never
    {
        throw new \InvalidArgumentException($message);
    }

    /** @return array{key:string, value:string, default:?int} */
    private static function inline(string $value): array
    {
        if (str_contains($value, '`') || str_contains($value, "\n") || str_contains($value, "\r") || str_ends_with($value, '\\')
            || strlen($value) > self::MAX_INLINE) {
            self::refuse('a ModSecurity directive cannot be passed to OLS as one module parameter');
        }
        return ['key' => 'modsecurity_rules', 'value' => "`$value`", 'default' => null];
    }

    /**
     * cPanel's ModSecurity state through $read(name, argv) => {exit_code, stdout}.
     * @return array<string,mixed> ["state" => "absent"] or the translation with its checker
     */
    public function translateCpanel(callable $read): array
    {
        $present = [];
        foreach ([self::MODSEC2_CONF, self::MODULE_CONF] as $path) {
            $present[] = $read('modsec-present', ['/usr/bin/test', '-e', $path])['exit_code'] === 0;
        }
        if (!in_array(true, $present, true)) {
            return ['state' => 'absent'];
        }
        if (in_array(false, $present, true)) {
            self::refuse('ModSecurity is half installed (modsec2.conf and the Apache module must both be present or both absent)');
        }
        $checker = new ModSecurityRules();
        $entries = $inputs = $includes = $disabled = $ruleFiles = [];
        $fetch = static function (string $name, string $path) use ($read, &$inputs): string {
            $record = $read($name, ['/usr/bin/cat', $path]);
            if ($record['exit_code'] !== 0) {
                self::refuse("unable to read $path");
            }
            $inputs[] = ['path' => $path, 'sha256' => hash('sha256', $record['stdout'])];
            return $record['stdout'];
        };
        // EA4's wrapper: only the known directives, inside <IfModule security2_module>.
        $stack = [];
        foreach (ModSecurityRules::logicalLines($fetch('modsec-conf', self::MODSEC2_CONF)) as [$number, $line]) {
            $where = self::MODSEC2_CONF . ":$number";
            if ($line === null) {
                $checker->block($where, 'comment line ends with a line continuation');
                continue;
            }
            if (preg_match('/^<IfModule[ \t]+([A-Za-z0-9_.]+)[ \t]*>$/iD', $line, $opened)) {
                if ((self::SECTIONS[$opened[1]] ?? null) !== count($stack) + 1) {
                    $checker->block($where, "unexpected section {$opened[1]}");
                }
                $stack[] = $opened[1];
                continue;
            }
            if (preg_match('/^<\/IfModule[ \t]*>$/iD', $line)) {
                if ($stack === []) {
                    $checker->block($where, 'unbalanced section');
                } else {
                    array_pop($stack);
                }
                continue;
            }
            $args = ModSecurityRules::splitArgs($line) ?: [''];
            $name = strtolower($args[0]);
            $depth = count($stack);
            if ($depth === 0) {
                $checker->block($where, 'directive outside <IfModule security2_module>');
            } elseif ($depth > 2) {
                $checker->block($where, 'unexpected section depth');
            } elseif (in_array($name, self::DROPPED[$depth], true)) {
                $checker->differ('product-audit-log', $where, "{$args[0]} is replaced by the product audit log settings");
            } elseif ($depth !== 1) {
                $checker->block($where, "unexpected directive {$args[0]}");
            } elseif ($name === 'include' && count($args) === 2) {
                $includes[] = $args[1];
            } elseif ($name === 'secdefaultaction' && count($args) === 2 && !str_contains($args[1], '"')) {
                $index = $checker->defaultAction($where, $args[1], true);
                if ($index !== null) {
                    $entries[] = ['default' => $index] + self::inline("SecDefaultAction \"{$args[1]}\"");
                }
            } elseif ($name === 'secrequestbodylimitaction' && count($args) === 2
                && in_array(strtolower($args[1]), ModSecurityRules::VALUES[$name], true)) {
                $entries[] = self::inline("SecRequestBodyLimitAction {$args[1]}");
            } else {
                $checker->block($where, "unexpected directive {$args[0]}");
            }
        }
        if ($stack !== []) {
            $checker->block(self::MODSEC2_CONF, 'unbalanced section');
        }
        if ($includes !== [self::USER_CONF, self::CPANEL_CONF]) {
            $checker->block(self::MODSEC2_CONF, 'must include exactly modsec2.user.conf, then modsec2.cpanel.conf');
        }
        $load = static function (string $path, string $text) use ($checker, &$entries, &$ruleFiles): void {
            $lines = ModSecurityRules::logicalLines($text);
            foreach ($lines as [, $line]) {
                if ($line !== null) {
                    $checker->trackEngine($line);
                }
            }
            $checker->checkFile($path, $text, substr($path, 0, (int) strrpos($path, '/')));
            if ($lines !== []) {
                $ruleFiles[] = $path;
                $entries[] = ['key' => 'modsecurity_rules_file', 'value' => $path, 'default' => null];
            }
        };
        $load(self::USER_CONF, $fetch('modsec-user', self::USER_CONF));
        // WHM's generated file (template modsec2.cpanel.conf.tmpl): settings, includes, disabled rules.
        foreach (ModSecurityRules::logicalLines($fetch('modsec-cpanel', self::CPANEL_CONF)) as [$number, $line]) {
            $where = self::CPANEL_CONF . ":$number";
            $line ??= '';
            if (preg_match('/^(Sec[A-Za-z0-9]+) "([^"]*)"$/D', $line, $setting)) {
                [, $name, $value] = $setting;
                if (!preg_match(self::SAFE_VALUE, $value)) {
                    $checker->block($where, "$name has an unsupported value");
                    continue;
                }
                $blockers = count($checker->blockers);
                $checker->directive($where, "$name $value");
                if (count($checker->blockers) === $blockers
                    && in_array(strtolower($name), [...ModSecurityRules::PASS, ...ModSecurityRules::OFF_ONLY], true)) {
                    $checker->trackEngine("$name $value");
                    $entries[] = self::inline("$name $value");
                }
            } elseif (preg_match('/^Include "([^"]+)"$/D', $line, $include)) {
                $path = $include[1];
                if (!preg_match(ModSecurityRules::VENDOR_FILE, $path)) {
                    $checker->block($where, "included file $path is outside the vendor configurations");
                } elseif (count($ruleFiles) >= self::MAX_FILES) {
                    $checker->block($where, 'too many rule files for one OLS module block');
                } else {
                    $load($path, $fetch('modsec-rules', $path));
                }
            } elseif (preg_match('/^SecRuleRemoveById ([0-9]{1,10})$/D', $line, $removal)) {
                $checker->directive($where, $line);
                $disabled[] = (int) $removal[1];
                $entries[] = self::inline($line);
            } else {
                $checker->block($where, "unexpected line in WHM's generated configuration");
            }
        }
        foreach ($checker->dataFiles as $path) {
            $fetch('modsec-data', $path);
        }
        $checker->finish();
        if ($checker->engine === null) {
            array_unshift($entries, self::inline('SecRuleEngine Off'));  // ModSecurity 2's default
        }
        foreach (['SecAuditLog ' . self::AUDIT_LOG, 'SecAuditLogType Serial', 'SecAuditLogParts ' . self::AUDIT_PARTS,
                     'SecAuditLogFileMode 0600'] as $directive) {
            $entries[] = self::inline($directive);
        }
        $entries = array_values(array_filter($entries, static fn(array $e): bool
            => $e['default'] === null || $checker->defaults[$e['default']]['emit']));
        return ['state' => 'translated', 'entries' => $entries, 'checker' => $checker, 'inputs' => $inputs,
            'rule_files' => $ruleFiles, 'disabled_rules' => $disabled, 'engine' => $checker->engine ?? 'Off'];
    }

    /** cPanel's per-domain disable: the userdata key secruleengineoff of the vhost ("1" off; absent, "" or "0" on). */
    public function userdataEngineOff(string $text, string $name): bool
    {
        $values = [];
        foreach (explode("\n", $text) as $raw) {
            $line = str_ends_with($raw, "\r") ? substr($raw, 0, -1) : $raw;
            if (str_starts_with($line, 'secruleengineoff:')) {
                $values[] = trim(trim(substr($line, strlen('secruleengineoff:')), " \t"), "'\"");
            }
        }
        if ($values === []) {
            return false;
        }
        if (count($values) > 1 || !in_array($values[0], ['', '0', '1'], true)) {
            self::refuse("unreadable secruleengineoff in the userdata of $name");
        }
        return $values[0] === '1';
    }

    private static function isInt(mixed $value, int $minimum, int $maximum): bool
    {
        return is_int($value) && $minimum <= $value && $value <= $maximum;
    }

    private static function isDict(mixed $value): bool
    {
        return is_array($value) && ($value === [] || !array_is_list($value));
    }

    /** Normalized IP or network for an OLS access list (a single address without its prefix length). */
    private static function network(mixed $entry, bool $trusted): string
    {
        if (!is_string($entry) || !preg_match('/^[0-9A-Fa-f:.]{2,45}(\/([0-9]|[1-9][0-9]{1,2}))?$/D', $entry)
            || (str_contains($entry, ':') && str_contains($entry, '.'))) {
            self::refuse('invalid address in the security input');
        }
        [$address, $length] = array_pad(explode('/', $entry, 2), 2, null);
        $packed = @inet_pton($address);
        $bits = $packed === false ? 0 : strlen($packed) * 8;
        $prefix = $length === null ? $bits : (int) $length;
        if ($packed === false || $prefix > $bits || !self::hostBitsZero($packed, $prefix)) {
            self::refuse("invalid address $entry");
        }
        if ($prefix === 0) {
            self::refuse("$entry covers every client");
        }
        [$loopback, $loopbackPrefix] = $bits === 32 ? [inet_pton('127.0.0.0'), 8] : [inet_pton('::1'), 128];
        if (!$trusted && self::samePrefix($packed, $loopback, min($prefix, $loopbackPrefix))) {
            self::refuse("$entry would block the server's own loopback clients");
        }
        return $prefix === $bits ? (string) inet_ntop($packed) : inet_ntop($packed) . "/$prefix";
    }

    /** Whether the binary addresses $a and $b agree on their first $count bits. */
    private static function samePrefix(string $a, string $b, int $count): bool
    {
        for ($bit = 0; $bit < $count; ++$bit) {
            $mask = 0x80 >> ($bit % 8);
            if ((ord($a[intdiv($bit, 8)]) & $mask) !== (ord($b[intdiv($bit, 8)]) & $mask)) {
                return false;
            }
        }
        return true;
    }

    /** Whether every bit of the binary address from bit $prefix on is zero (no host part). */
    private static function hostBitsZero(string $packed, int $prefix): bool
    {
        for ($bit = $prefix; $bit < strlen($packed) * 8; ++$bit) {
            if ((ord($packed[intdiv($bit, 8)]) & (0x80 >> ($bit % 8))) !== 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validated product security input. Throws \InvalidArgumentException.
     * @param array<string,array<string,mixed>> $plan
     * @return array<string,mixed>
     */
    public function policy(mixed $security, array $plan): array
    {
        if (!self::isDict($security) || array_diff(array_map('strval', array_keys($security)), self::POLICY_KEYS) !== []) {
            self::refuse('unknown security input keys');
        }
        $now = $security['evaluated_at'] ?? null;
        if ($now !== null && !self::isInt($now, 0, self::LIMIT_TIME)) {
            self::refuse('invalid evaluated_at');
        }
        $out = ['per_client' => null, 'ip_allow' => [], 'ip_block' => [], 'accept_differences' => [], 'exceptions' => [], 'expired' => []];
        $limits = $security['per_client'] ?? null;
        if ($limits !== null) {
            $known = array_column(self::PER_CLIENT, 0);
            if (!self::isDict($limits) || $limits === [] || array_diff(array_map('strval', array_keys($limits)), $known) !== []) {
                self::refuse('invalid per_client limits');
            }
            foreach (self::PER_CLIENT as [$key, $minimum, $maximum]) {
                if (array_key_exists($key, $limits) && !self::isInt($limits[$key], $minimum, $maximum)) {
                    self::refuse("invalid per_client $key");
                }
            }
            if (isset($limits['softLimit'], $limits['hardLimit']) && $limits['softLimit'] > $limits['hardLimit']) {
                self::refuse('per_client softLimit exceeds hardLimit');
            }
            $out['per_client'] = [];
            foreach ($known as $key) {
                if (array_key_exists($key, $limits)) {
                    $out['per_client'][$key] = $limits[$key];
                }
            }
        }
        foreach (['ip_allow' => true, 'ip_block' => false] as $key => $trusted) {
            $entries = array_key_exists($key, $security) ? $security[$key] : [];
            if (!is_array($entries) || !array_is_list($entries) || count($entries) > self::MAX_LIST) {
                self::refuse("invalid $key");
            }
            foreach ($entries as $entry) {
                $value = self::network($entry, $trusted);
                if (in_array($value, $out[$key], true)) {
                    self::refuse("$key lists $value twice");
                }
                $out[$key][] = $value;
            }
        }
        foreach ($out['ip_allow'] as $value) {
            if (in_array($value, $out['ip_block'], true)) {
                self::refuse("$value is both allowed and blocked");
            }
        }
        $accept = array_key_exists('accept_differences', $security) ? $security['accept_differences'] : [];
        if (!is_array($accept) || !array_is_list($accept)
            || array_filter($accept, static fn(mixed $c): bool => !in_array($c, self::WEAKER_CODES, true)) !== []
            || count(array_unique($accept)) !== count($accept)) {
            self::refuse('invalid accept_differences');
        }
        sort($accept, SORT_STRING);
        $out['accept_differences'] = $accept;
        $exceptions = array_key_exists('exceptions', $security) ? $security['exceptions'] : [];
        if (!is_array($exceptions) || !array_is_list($exceptions) || count($exceptions) > self::MAX_LIST) {
            self::refuse('invalid exceptions');
        }
        foreach ($exceptions as $item) {
            if (!self::isDict($item) || array_diff(array_map('strval', array_keys($item)), self::EXCEPTION_KEYS) !== []
                || !is_string($item['vhost'] ?? null)) {
                self::refuse('invalid exception');
            }
            $vhost = $item['vhost'];
            if (!array_key_exists($vhost, $plan)) {
                self::refuse("exception for $vhost, which is not a cPanel vhost");
            }
            if (($plan[$vhost]['mode'] ?? null) === 'apache') {
                self::refuse("exception for $vhost, which Apache serves (hybrid)");
            }
            $reason = $item['reason'] ?? null;
            if (!is_string($reason) || !preg_match(self::PRINTABLE, $reason) || strlen($reason) > 200) {
                self::refuse("exception for $vhost needs a reason");
            }
            if (array_key_exists('approver', $item) && (!is_string($item['approver']) || !preg_match(self::PRINTABLE, $item['approver'])
                    || strlen($item['approver']) > 100)) {
                self::refuse("invalid approver for $vhost");
            }
            if (array_key_exists('engine', $item) === array_key_exists('rule_ids', $item)) {
                self::refuse("exception for $vhost needs exactly one of engine and rule_ids");
            }
            if (array_key_exists('engine', $item) && $item['engine'] !== 'off') {
                self::refuse("invalid engine for $vhost");
            }
            $ids = array_key_exists('rule_ids', $item) ? $item['rule_ids'] : [];
            if (!is_array($ids) || !array_is_list($ids) || (array_key_exists('rule_ids', $item) && (count($ids) < 1 || count($ids) > 100))
                || array_filter($ids, static fn(mixed $i): bool => !self::isInt($i, 1, 9999999999)) !== []) {
                self::refuse("invalid rule_ids for $vhost");
            }
            if (array_key_exists('expires', $item)) {
                if (!self::isInt($item['expires'], 0, self::LIMIT_TIME) || $now === null) {
                    self::refuse("exception for $vhost expires without evaluated_at");
                }
                if ($item['expires'] <= $now) {
                    $out['expired'][] = ['vhost' => $vhost, 'reason' => $reason];
                    continue;
                }
            }
            $ids = array_values(array_unique($ids));
            sort($ids);
            $out['exceptions'][] = ['vhost' => $vhost, 'source' => 'operator', 'engine' => $item['engine'] ?? null,
                'rule_ids' => $ids, 'reason' => $reason];
        }
        return $out;
    }

    /** @param list<int> $ruleIds */
    public function vhostBlock(bool $engineOff, array $ruleIds): string
    {
        if ($engineOff) {
            return "module mod_security {\n    modsecurity          off\n}\n";
        }
        if ($ruleIds !== []) {
            return "module mod_security {\n    modsecurity_rules    `SecRuleRemoveById " . implode(' ', $ruleIds) . "`\n}\n";
        }
        return '';
    }

    /** @param list<array{key:string, value:string}> $entries */
    public function serverBlock(array $entries): string
    {
        $out = "module mod_security {\n    ls_enabled           1\n    modsecurity          on\n";
        foreach ($entries as $entry) {
            $out .= sprintf("    %-20s %s\n", $entry['key'], $entry['value']);
        }
        return $out . "}\n";
    }

    /**
     * The WAF and security part of a compilation.
     * @param callable(string, list<string>): array{exit_code:int, stdout:string} $read
     * @param array<string,array<string,mixed>> $plan cPanel vhost name => model (with "mode" and "service_domains")
     * @param array<string,string> $userdata cPanel vhost name => userdata text
     * @param list<string> $vhosts every OLS vhost of the compilation
     * @param callable(string): string $serviceName
     * @param callable(string): string $hybridName
     * @return array<string,mixed> {server, per_client, ip_allow, ip_block, vhosts, summary}
     */
    public function compileSecurity(callable $read, array $plan, array $userdata, mixed $security, array $vhosts, string $proxyVhost,
                                    callable $serviceName, callable $hybridName): array
    {
        $rules = $this->policy($security, $plan);
        $waf = $this->translateCpanel($read);
        $exceptions = [];
        if ($waf['state'] === 'translated') {
            $checker = $waf['checker'];
            $blockers = $checker->blockers;
            $refused = [];
            foreach ($checker->differences as $index => $difference) {
                $accepted = $difference['weaker'] && in_array($difference['code'], $rules['accept_differences'], true);
                $checker->differences[$index]['accepted'] = $accepted;
                if ($difference['weaker'] && !$accepted) {
                    $refused[] = "{$difference['where']}: {$difference['detail']} (code {$difference['code']} not accepted)";
                }
            }
            $blockers = [...$blockers, ...$refused];
            if ($blockers !== []) {
                self::refuse('ModSecurity configuration cannot be reproduced on OLS: ' . substr(implode('; ', $blockers), 0, 600));
            }
            $off = static fn(string $vhost, string $source, string $reason): array
                => ['vhost' => $vhost, 'source' => $source, 'engine' => 'off', 'rule_ids' => [], 'reason' => $reason];
            foreach ($plan as $name => $v) {
                $name = (string) $name;
                if (($v['mode'] ?? null) === 'apache') {
                    foreach ([$name, $hybridName($name)] as $vhost) {
                        $exceptions[] = $off($vhost, 'product', 'Apache serves this vhost and applies its own ModSecurity');
                    }
                    continue;
                }
                if ($this->userdataEngineOff($userdata[$name] ?? '', $name)) {
                    $exceptions[] = $off($name, 'cpanel', 'ModSecurity disabled for the domain in cPanel');
                }
                if (($v['service_domains'] ?? []) !== []) {
                    $exceptions[] = $off($serviceName($name), 'product', self::PROXIED);
                }
            }
            $exceptions[] = $off($proxyVhost, 'product', self::PROXIED);
            $exceptions = [...$exceptions, ...$rules['exceptions']];
        } elseif ($rules['exceptions'] !== []) {
            self::refuse('ModSecurity exceptions without ModSecurity');
        }
        usort($exceptions, static function (array $a, array $b): int {
            foreach ([['vhost'], ['source'], ['engine'], ['rule_ids']] as [$key]) {
                $left = $key === 'rule_ids' ? implode(',', $a[$key]) : (string) ($a[$key] ?? '');
                $right = $key === 'rule_ids' ? implode(',', $b[$key]) : (string) ($b[$key] ?? '');
                if ($left !== $right) {
                    return strcmp($left, $right);
                }
            }
            return 0;
        });
        $unknown = array_values(array_diff(array_unique(array_column($exceptions, 'vhost')), $vhosts));
        sort($unknown, SORT_STRING);
        if ($unknown !== []) {
            self::refuse("exception for an OLS vhost the compilation does not have: {$unknown[0]}");
        }
        $blocks = [];
        foreach ($vhosts as $vhost) {
            $engineOff = false;
            $ids = [];
            foreach ($exceptions as $exception) {
                if ($exception['vhost'] === $vhost) {
                    $engineOff = $engineOff || $exception['engine'] === 'off';
                    array_push($ids, ...$exception['rule_ids']);
                }
            }
            $ids = array_values(array_unique($ids));
            sort($ids);
            $block = $this->vhostBlock($engineOff, $ids);
            if ($block !== '') {
                $blocks[$vhost] = $block;
            }
        }
        $perClient = '';
        if ($rules['per_client'] !== null) {
            $perClient = "perClientConnLimit {\n";
            foreach ($rules['per_client'] as $key => $value) {
                $perClient .= sprintf("    %-20s %d\n", $key, $value);
            }
            $perClient .= "}\n";
        }
        if ($waf['state'] === 'absent') {
            $summaryWaf = ['state' => 'absent'];
            $server = '';
        } else {
            $summaryWaf = ['state' => 'translated', 'engine' => $waf['engine'], 'audit_log' => self::AUDIT_LOG, 'inputs' => $waf['inputs'],
                'rule_files' => $waf['rule_files'], 'data_files' => $waf['checker']->dataFiles, 'rules' => count($waf['checker']->rules),
                'disabled_rules' => $waf['disabled_rules'], 'differences' => $waf['checker']->differences, 'exceptions' => $exceptions];
            $server = $this->serverBlock($waf['entries']);
        }
        return ['server' => $server, 'per_client' => $perClient, 'ip_allow' => $rules['ip_allow'], 'ip_block' => $rules['ip_block'],
            'vhosts' => $blocks, 'summary' => ['waf' => $summaryWaf, 'security' => ['per_client' => $rules['per_client'],
                'ip_allow' => $rules['ip_allow'], 'ip_block' => $rules['ip_block'], 'accept_differences' => $rules['accept_differences'],
                'expired_exceptions' => $rules['expired']]]];
    }

    /**
     * The server configuration with the security part: IP lists merged into the server accessControl (trusted
     * clients get OLS's "T" suffix; a blocked entry leaves the allow list), perClientConnLimit after it, the
     * module block at the end.
     * @param array<string,mixed> $compiled the result of compileSecurity
     */
    public function applyServer(string $config, array $compiled): string
    {
        $count = preg_match_all(self::ACCESS_BLOCK, $config, $found);
        if ($count !== 1 || str_contains($config, 'perClientConnLimit') || str_contains($config, 'module mod_security')) {
            self::refuse('server template must hold exactly one accessControl block and no security settings');
        }
        $values = ['allow' => null, 'deny' => null];
        foreach (array_slice(explode("\n", $found[1][0]), 0, -1) as $line) {
            [$key, $value] = array_pad(explode(' ', trim($line, ' '), 2), 2, '');
            if (!array_key_exists($key, $values) || $values[$key] !== null) {
                self::refuse('unexpected accessControl line in the server template');
            }
            $values[$key] = array_values(array_filter(explode(', ', trim($value, ' ')), static fn(string $v): bool => $v !== ''));
        }
        $allow = array_values(array_filter($values['allow'] ?? [], static fn(string $v): bool => !in_array($v, $compiled['ip_block'], true)));
        foreach ($compiled['ip_allow'] as $entry) {
            $position = array_search($entry, $allow, true);
            if ($position !== false) {
                $allow[$position] = $entry . 'T';
            } else {
                $allow[] = $entry . 'T';
            }
        }
        $deny = [...($values['deny'] ?? []), ...$compiled['ip_block']];
        if ($allow === []) {
            self::refuse('the blocked addresses leave no client allowed');
        }
        $block = "accessControl {\n    allow                " . implode(', ', $allow) . "\n"
            . ($deny !== [] ? '    deny                 ' . implode(', ', $deny) . "\n" : '') . "}\n";
        preg_match(self::ACCESS_BLOCK, $config, $match, PREG_OFFSET_CAPTURE);
        $start = $match[0][1];
        return substr($config, 0, $start) . $block . $compiled['per_client'] . substr($config, $start + strlen($match[0][0]))
            . $compiled['server'];
    }
}
