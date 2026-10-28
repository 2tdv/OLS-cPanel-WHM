<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * UDP 443 for HTTP/3 (FV-04). QUIC is the UDP twin of OLS's HTTPS listeners, so a host firewall that drops UDP 443
 * makes the advertised HTTP/3 unreachable. The product opens the port the way the host's firewall expects and records
 * exactly what it changed, so recover.sh and apache-return undo it:
 *
 *  - csf (/usr/sbin/csf and /etc/csf/csf.conf, not disabled by /etc/csf/csf.disable): 443 is appended to UDP_IN and
 *    UDP6_IN (only the quoted value of the line changes; a list that already covers 443 is left alone), csf restarts
 *    (csf -r). The original csf.conf is copied into the backup and restored byte for byte.
 *  - firewalld (`firewall-cmd --state` is "running"): the default zone is resolved once at inspection and recorded; every
 *    command names it (`--zone=`). The runtime and the permanent state are tracked separately (RV-31 items 3-5): the
 *    runtime port is added with `--zone=Z --add-port=443/udp` only when it is not open at runtime, the permanent one with
 *    `--permanent --zone=Z --add-port=443/udp` only when it is not in the permanent configuration, and the record says
 *    which of the two the product added. Undo removes exactly those, in the recorded zone. There is never a global
 *    `--reload` (it would discard the administrator's runtime-only rules); a host that binds its public interface to
 *    another zone opens it itself.
 *  - nftables and anything else: nothing is changed (the product cannot know an administrator's tables); a ruleset
 *    with an input hook of policy drop and no UDP 443 rule yields a warning.
 *
 * The decisions (csfPlan, nftInputDrop) are byte-identical to build/vm-qualification/http3.py (tests/http3.py). Every
 * command is a fixed argv through the host's command runner.
 */
final class Http3Firewall
{
    public const CSF = '/usr/sbin/csf';
    public const CSF_CONF = '/etc/csf/csf.conf';
    public const CSF_DISABLE = '/etc/csf/csf.disable';
    public const FIREWALL_CMD = '/usr/bin/firewall-cmd';
    public const CSF_KEYS = ['UDP_IN', 'UDP6_IN'];
    private const PORT = '443/udp';
    /** A firewalld zone name as the recovery script and the commands take it. */
    public const ZONE = '/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/D';

    public function __construct(private Host $host)
    {
    }

    /** A csf port list ("20,21,3000:4000") contains the port, alone or inside a range. */
    public static function portListCovers(string $value, int $port = 443): bool
    {
        foreach (explode(',', $value) as $token) {
            $token = trim($token, " \t\r\n");
            if ($token === (string) $port) {
                return true;
            }
            $parts = explode(':', $token, 2);
            if (count($parts) === 2 && preg_match('/^[0-9]+$/D', $parts[0]) && preg_match('/^[0-9]+$/D', $parts[1])
                && (int) $parts[0] <= $port && $port <= (int) $parts[1]) {
                return true;
            }
        }
        return false;
    }

    /**
     * What csf.conf needs for UDP 443 (http3.csf_plan): UDP_IN must exist exactly once or nothing is planned;
     * UDP6_IN is changed when present exactly once; a key that covers 443 is left alone.
     * @return array{supported:bool, keys:array<string,array{value:string, open:bool}>, changed:bool, text:string}
     */
    public static function csfPlan(string $text): array
    {
        $keys = [];
        $out = $text;
        foreach (self::CSF_KEYS as $key) {
            if (preg_match_all(self::csfPattern($key), $text, $found, PREG_SET_ORDER) === 1) {
                $keys[$key] = ['value' => $found[0][2], 'open' => self::portListCovers($found[0][2])];
            }
        }
        $supported = isset($keys['UDP_IN']);
        $changed = false;
        if ($supported) {
            foreach ($keys as $key => $state) {
                if ($state['open']) {
                    continue;
                }
                $value = $state['value'];
                $new = $value === '' || str_ends_with($value, ',') ? $value . '443' : $value . ',443';
                $out = (string) preg_replace_callback(self::csfPattern($key),
                    static fn(array $m): string => $m[1] . $new . $m[3], $out, 1);
                $changed = true;
            }
        }
        return ['supported' => $supported, 'keys' => $keys, 'changed' => $changed, 'text' => $out];
    }

    private static function csfPattern(string $key): string
    {
        return '/^(' . $key . '\s*=\s*")([^"\n]*)("[^\n]*)$/m';
    }

    /**
     * An nftables input hook with policy drop, and whether any rule already mentions UDP port 443.
     * @return array{input_policy_drop:bool, udp_443_mentioned:bool}
     */
    public static function nftInputDrop(string $ruleset): array
    {
        return ['input_policy_drop' => preg_match('/hook input priority [^;]*; policy drop;/', $ruleset) === 1,
            'udp_443_mentioned' => preg_match('/udp dport (\{[^}]*\b443\b[^}]*\}|443\b)/', $ruleset) === 1];
    }

    /**
     * Read-only inspection: the firewall type, what the cutover would change and why. Keys: type (csf, firewalld,
     * nftables, none), action ("add": the product opens UDP 443; "none": nothing to change), detail, warnings and, for
     * csf, conf, before_sha256, after_sha256, keys and the changed text under "new_text" (never stored).
     * @return array<string,mixed>
     */
    public function inspect(): array
    {
        if ($this->exists(self::CSF, 'csf-present') && $this->exists(self::CSF_CONF, 'csf-conf-present')
            && !$this->exists(self::CSF_DISABLE, 'csf-disabled')) {
            try {
                return $this->inspectCsf();
            } catch (DeploymentError $error) {
                // An unusual csf.conf never blocks a cutover: HTTP/3 only needs the port reachable.
                return ['type' => 'csf', 'action' => 'none', 'detail' => 'csf.conf cannot be used: ' . $error->getMessage(),
                    'warnings' => ['csf.conf cannot be inspected: open UDP 443 in csf yourself or set {"enabled": false} in '
                        . Http3Input::PATH]];
            }
        }
        $state = $this->host->run('firewalld-state', [self::FIREWALL_CMD, '--state']);
        if ($state['exit_code'] === 0 && trim($state['stdout']) === 'running') {
            return $this->inspectFirewalld();
        }
        $rules = $this->host->run('nft-ruleset', [HybridHost::NFT, 'list', 'ruleset']);
        $others = [];
        if ($rules['exit_code'] === 0) {
            preg_match_all('/^table (\S+) (\S+)/m', $rules['stdout'], $tables, PREG_SET_ORDER);
            $others = array_filter($tables, static fn(array $t): bool => $t[2] !== HybridHost::NFT_TABLE);
        }
        if ($others === []) {
            return ['type' => 'none', 'action' => 'none', 'warnings' => [], 'detail' => 'no host firewall detected'];
        }
        $drop = self::nftInputDrop($rules['stdout']);
        $warnings = $drop['input_policy_drop'] && !$drop['udp_443_mentioned']
            ? ['an nftables input hook drops by default and no rule mentions UDP 443: allow UDP 443 for HTTP/3 or set '
                . '{"enabled": false} in ' . Http3Input::PATH] : [];
        return ['type' => 'nftables', 'action' => 'none', 'warnings' => $warnings,
            'detail' => 'nftables rules are an administrator\'s; the product changes none'];
    }

    /**
     * firewalld: the default zone (resolved once, recorded) and, per state, whether 443/udp is open. query-port answers
     * 0 (yes) or 1 (no); any other answer is an inspection failure and plans nothing (never "open" by guesswork).
     * @return array<string,mixed>
     */
    private function inspectFirewalld(): array
    {
        $unknown = static fn(string $why): array => ['type' => 'firewalld', 'action' => 'none', 'detail' => "firewalld cannot be inspected: $why",
            'warnings' => ["firewalld cannot be inspected ($why): open UDP 443 yourself or set {\"enabled\": false} in " . Http3Input::PATH]];
        $zone = $this->host->run('firewalld-zone', [self::FIREWALL_CMD, '--get-default-zone']);
        $name = trim($zone['stdout']);
        if ($zone['exit_code'] !== 0 || preg_match(self::ZONE, $name) !== 1) {
            return $unknown('the default zone is not known');
        }
        $runtime = $this->host->run('firewalld-query-runtime', [self::FIREWALL_CMD, '--zone=' . $name, '--query-port=' . self::PORT])['exit_code'];
        $permanent = $this->host->run('firewalld-query-permanent', [self::FIREWALL_CMD, '--permanent', '--zone=' . $name, '--query-port=' . self::PORT])['exit_code'];
        if (!in_array($runtime, [0, 1], true) || !in_array($permanent, [0, 1], true)) {
            return $unknown("the state of 443/udp in zone $name is not readable");
        }
        $add = [];
        $add[] = $runtime === 1 ? 'runtime' : null;
        $add[] = $permanent === 1 ? 'permanent' : null;
        $add = array_values(array_filter($add));
        return ['type' => 'firewalld', 'zone' => $name, 'runtime_open' => $runtime === 0, 'permanent_open' => $permanent === 0,
            'add_runtime' => $runtime === 1, 'add_permanent' => $permanent === 1, 'action' => $add === [] ? 'none' : 'add', 'warnings' => [],
            'detail' => $add === [] ? "UDP 443 is open in zone $name (runtime and permanent)"
                : 'add 443/udp to zone ' . $name . ' (' . implode(' and ', $add) . '; no reload)'];
    }

    /** @return array<string,mixed> */
    private function inspectCsf(): array
    {
        $state = $this->host->systemFileState(self::CSF_CONF, 'csf-conf-state');
        if ($state === null) {
            throw DeploymentError::step('csf-conf-state', self::CSF_CONF . ' vanished');
        }
        $text = $this->host->must('csf-conf-read', ['/usr/bin/cat', '--', self::CSF_CONF]);
        $before = substr($state, -64);
        if (hash('sha256', $text) !== $before) {
            throw DeploymentError::step('csf-conf-read', self::CSF_CONF . ' changed while it was read');
        }
        $plan = self::csfPlan($text);
        $base = ['type' => 'csf', 'conf' => self::CSF_CONF, 'before_sha256' => $before, 'keys' => $plan['keys']];
        if (!$plan['supported']) {
            return $base + ['action' => 'none', 'after_sha256' => $before, 'new_text' => null,
                'detail' => 'UDP_IN is not exactly once in csf.conf: the product changes nothing',
                'warnings' => ['csf.conf has no single UDP_IN line: open UDP 443 in csf yourself or set {"enabled": false} in '
                    . Http3Input::PATH]];
        }
        if (!$plan['changed']) {
            return $base + ['action' => 'none', 'after_sha256' => $before, 'new_text' => null, 'warnings' => [],
                'detail' => 'UDP 443 is allowed in csf already'];
        }
        $keys = array_keys(array_filter($plan['keys'], static fn(array $k): bool => !$k['open']));
        return $base + ['action' => 'add', 'after_sha256' => hash('sha256', $plan['text']), 'new_text' => $plan['text'], 'warnings' => [],
            'detail' => 'append 443 to ' . implode(' and ', $keys) . ' in csf.conf and restart csf'];
    }

    /**
     * The record for the backup manifest and recover.sh: what inspect() found, with the csf.conf copy taken into
     * "<backup>/firewall/csf.conf" (byte-exact, verified) when the product will change it.
     * @param array<string,mixed> $inspected
     * @return array<string,mixed>
     */
    public function capture(string $backupDir, array $inspected): array
    {
        $record = $inspected;
        unset($record['new_text']);
        if ($inspected['type'] === 'csf' && $inspected['action'] === 'add') {
            Environment::ensureDir("$backupDir/" . RecoveryScript::FIREWALL_DIR, 0700);
            $copy = "$backupDir/" . RecoveryScript::FIREWALL_DIR . '/csf.conf';
            $this->host->must('csf-conf-copy', ['/usr/bin/cp', '-P', '-p', '--', self::CSF_CONF, $copy]);
            if (!is_file($copy) || hash_file('sha256', $copy) !== $inspected['before_sha256']) {
                throw DeploymentError::step('csf-conf-copy', 'the copy of ' . self::CSF_CONF . ' differs from the original');
            }
            $record['backup'] = RecoveryScript::FIREWALL_DIR . '/csf.conf';
        }
        return $record;
    }

    /**
     * The firewall argument of RecoveryScript::render for a recorded change; null when nothing is changed.
     * @param array<string,mixed>|null $record
     * @return array{type:string, before_sha256?:string, after_sha256?:string, zone?:string, runtime?:bool, permanent?:bool}|null
     */
    public static function recovery(?array $record): ?array
    {
        if ($record === null || ($record['action'] ?? null) !== 'add') {
            return null;
        }
        return $record['type'] === 'csf' ? ['type' => 'csf', 'before_sha256' => $record['before_sha256'], 'after_sha256' => $record['after_sha256']]
            : ['type' => 'firewalld', 'zone' => $record['zone'], 'runtime' => $record['add_runtime'], 'permanent' => $record['add_permanent']];
    }

    /**
     * Opens UDP 443 as recorded. csf.conf must still be what was captured (any difference refuses: nothing is guessed).
     * @param array<string,mixed> $record
     * @param string $stageDir root-only directory for the staged csf.conf
     */
    public function apply(array $record, string $stageDir): void
    {
        if (($record['action'] ?? null) !== 'add') {
            return;
        }
        if ($record['type'] === 'firewalld') {
            $zone = $this->zone($record);
            if ($record['add_runtime'] ?? false) {
                $this->host->must('firewalld-add-port', [self::FIREWALL_CMD, '--zone=' . $zone, '--add-port=' . self::PORT]);
                if (!$this->firewalldOpen($zone, false)) {
                    throw DeploymentError::step('firewalld-open', "UDP 443 is not open at runtime in zone $zone");
                }
            }
            if ($record['add_permanent'] ?? false) {
                $this->host->must('firewalld-add-port-permanent', [self::FIREWALL_CMD, '--permanent', '--zone=' . $zone, '--add-port=' . self::PORT]);
                if (!$this->firewalldOpen($zone, true)) {
                    throw DeploymentError::step('firewalld-open-permanent', "UDP 443 is not in the permanent configuration of zone $zone");
                }
            }
            return;
        }
        $now = $this->inspectCsf();
        if ($now['before_sha256'] !== $record['before_sha256'] || ($now['new_text'] ?? null) === null
            || $now['after_sha256'] !== $record['after_sha256']) {
            throw DeploymentError::step('csf-conf-changed', self::CSF_CONF . ' changed since the backup was taken');
        }
        if (!is_dir($stageDir) && !mkdir($stageDir, 0700, true)) {
            throw DeploymentError::step('stage', "cannot create $stageDir");
        }
        $staged = "$stageDir/csf.conf";
        if (file_put_contents($staged, $now['new_text']) !== strlen($now['new_text']) || !chmod($staged, 0600)) {
            throw DeploymentError::step('stage', "cannot write $staged");
        }
        // cp onto the existing file keeps its owner and mode.
        $this->host->must('csf-conf-write', ['/usr/bin/cp', '--', $staged, self::CSF_CONF]);
        if (substr((string) $this->host->systemFileState(self::CSF_CONF, 'csf-conf-after'), -64) !== $record['after_sha256']) {
            throw DeploymentError::step('csf-conf-write', 'the installed csf.conf differs from the staged text');
        }
        $this->host->must('csf-restart', [self::CSF, '-r'], 300);
    }

    /**
     * Undoes a recorded change now (the failure path of a cutover; recover.sh does the same without the product):
     * csf.conf goes back byte for byte while it still is what the cutover wrote, then csf restarts; firewalld's
     * permanent port is removed and the configuration reloaded. Never throws; returns what happened.
     * @param array<string,mixed> $record
     * @return array<string,mixed>
     */
    public function undo(array $record, string $backupDir): array
    {
        if (($record['action'] ?? null) !== 'add') {
            return ['changed' => false];
        }
        try {
            if ($record['type'] === 'firewalld') {
                // Exactly what the product added, in the recorded zone, no reload.
                $zone = $this->zone($record);
                if ($record['add_runtime'] ?? false) {
                    $this->host->run('firewalld-remove-port', [self::FIREWALL_CMD, '--zone=' . $zone, '--remove-port=' . self::PORT]);
                }
                if ($record['add_permanent'] ?? false) {
                    $this->host->run('firewalld-remove-port-permanent', [self::FIREWALL_CMD, '--permanent', '--zone=' . $zone, '--remove-port=' . self::PORT]);
                }
                return ['changed' => true, 'restored' => $this->firewalldGone($record)];
            }
            // The file and the firewall are separate facts: the restored file is only "undone" once csf has been restarted
            // on it. The original file already in place (an earlier attempt restored it, the restart failed) is retried.
            $state = $this->host->systemFileState(self::CSF_CONF, 'csf-conf-state');
            $sum = $state === null ? null : substr($state, -64);
            if ($sum === $record['after_sha256']) {
                $this->host->must('csf-conf-restore', ['/usr/bin/cp', '--', "$backupDir/{$record['backup']}", self::CSF_CONF]);
                $sum = substr((string) $this->host->systemFileState(self::CSF_CONF, 'csf-conf-state'), -64);
            }
            $applied = false;
            if ($sum === $record['before_sha256']) {
                $applied = $this->host->run('csf-restart-undo', [self::CSF, '-r'], 300)['exit_code'] === 0;
            }
            return ['changed' => true, 'restored' => $sum === $record['before_sha256'] && $applied, 'file_restored' => $sum === $record['before_sha256'],
                'firewall_applied' => $applied];
        } catch (DeploymentError $error) {
            return ['changed' => true, 'restored' => false, 'error' => $error->getMessage()];
        }
    }

    /**
     * Whether a recorded change is gone again (information after apache-return: a csf.conf the administrator edited
     * since is left alone by recover.sh and reported as not restored).
     * @param array<string,mixed> $record
     */
    public function restored(array $record): bool
    {
        if (($record['action'] ?? null) !== 'add') {
            return true;
        }
        if ($record['type'] === 'firewalld') {
            return $this->firewalldGone($record);
        }
        $state = $this->host->systemFileState(self::CSF_CONF, 'csf-conf-state');
        return $state !== null && substr($state, -64) === $record['before_sha256'];
    }

    /** Whether each port state the product added is gone again (an exit other than "no" counts as not gone). */
    private function firewalldGone(array $record): bool
    {
        $zone = $this->zone($record);
        $gone = true;
        if ($record['add_runtime'] ?? false) {
            $gone = $this->host->run('firewalld-query-runtime', [self::FIREWALL_CMD, '--zone=' . $zone, '--query-port=' . self::PORT])['exit_code'] === 1 && $gone;
        }
        if ($record['add_permanent'] ?? false) {
            $gone = $this->host->run('firewalld-query-permanent', [self::FIREWALL_CMD, '--permanent', '--zone=' . $zone, '--query-port=' . self::PORT])['exit_code'] === 1 && $gone;
        }
        return $gone;
    }

    private function firewalldOpen(string $zone, bool $permanent): bool
    {
        $argv = $permanent ? [self::FIREWALL_CMD, '--permanent', '--zone=' . $zone, '--query-port=' . self::PORT]
            : [self::FIREWALL_CMD, '--zone=' . $zone, '--query-port=' . self::PORT];
        return $this->host->run($permanent ? 'firewalld-query-permanent' : 'firewalld-query-runtime', $argv)['exit_code'] === 0;
    }

    /** @param array<string,mixed> $record */
    private function zone(array $record): string
    {
        $zone = (string) ($record['zone'] ?? '');
        if (preg_match(self::ZONE, $zone) !== 1) {
            throw DeploymentError::step('firewalld-zone', 'the recorded firewalld zone is invalid');
        }
        return $zone;
    }

    private function exists(string $path, string $name): bool
    {
        return $this->host->run($name, ['/usr/bin/test', '-e', $path])['exit_code'] === 0;
    }
}
