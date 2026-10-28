<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The hybrid profile's host changes (HR-D08; build/vm-qualification/hybrid_lab.py and the hybrid steps of
 * ols_production_probe.py): Apache moves to cPanel's backend ports through the apache_port/apache_ssl_port
 * tweaks, trusts only X-OLS-Client-IP from OLS's local addresses (mod_remoteip include), and an nftables table
 * admits the backend ports only over loopback and only from root and OLS's user. Texts are byte-identical to
 * the lab functions (tests/deployment_texts.py). Every step is checked; removal keeps the firewall until
 * Apache owns 80/443 again (review RV-28). nftables rules live in memory only, so the same ruleset is persisted
 * (state/hybrid.nft, root 0600) and loaded at every boot by ols-cpanel-hybrid-firewall.service before the network
 * and Apache start; the trust pass puts the table back when it is missing (RV-40).
 */
final class HybridHost
{
    public const NFT_TABLE = 'ols_cpanel_hybrid';
    public const REMOTEIP_CONF = '/etc/apache2/conf.d/ols-cpanel-remoteip.conf';
    /** OLS worker processes (httpd_config.conf "user"). */
    public const OLS_USER = 'nobody';
    public const HTTPD_CONF = '/etc/apache2/conf/httpd.conf';
    public const HTTPD = '/usr/sbin/httpd';
    public const NFT = '/usr/sbin/nft';
    /** The persisted ruleset in the state directory (the boot unit's ConditionPathExists and ExecStart name the same path). */
    public const FIREWALL_FILE = 'hybrid.nft';
    public const FIREWALL_UNIT = 'ols-cpanel-hybrid-firewall.service';
    public const IP = '/usr/sbin/ip';
    public const RELOAD = '/usr/local/cpanel/scripts/restartsrv_httpd';

    public function __construct(private Host $host, private string $state = Environment::STATE)
    {
    }

    /**
     * The ruleset as `nft -f` input that can be loaded any number of times: the table is declared (a no-op when it
     * exists), deleted and defined again, so a second load never fails with "File exists" and never duplicates rules.
     */
    public static function persistedRuleset(array $ports): string
    {
        return 'table inet ' . self::NFT_TABLE . " {}\ndelete table inet " . self::NFT_TABLE . "\n" . self::nftRuleset($ports);
    }

    public function firewallPath(): string
    {
        return $this->state . '/' . self::FIREWALL_FILE;
    }

    /** Writes the persisted ruleset atomically (temporary file in the same directory, root-only, then rename). */
    private function persist(array $ports): void
    {
        $path = $this->firewallPath();
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $text = self::persistedRuleset($ports);
        if (!is_dir($this->state) || @file_put_contents($tmp, $text) !== strlen($text) || !@chmod($tmp, 0600) || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw DeploymentError::step('nft-persist', "cannot write $path");
        }
    }

    private function firewallPresent(): bool
    {
        return $this->host->run('nft-present', [self::NFT, 'list', 'table', 'inet', self::NFT_TABLE])['exit_code'] === 0;
    }

    /**
     * Makes the firewall table exist while the hybrid profile is in effect: 'present' when it does, 'restored' when it was
     * missing (after a reboot of an earlier build, or an operator's `nft flush ruleset`) and is loaded again from the persisted
     * file, which is written first from the profile's ports when it is absent. 'failed' (with the reason) when it cannot be.
     * @return array{0:string,1:?string} state and error
     */
    public function ensureFirewall(): array
    {
        if ($this->firewallPresent()) {
            return ['present', null];
        }
        try {
            if (!is_file($this->firewallPath())) {
                $profile = Profile::load($this->state . '/profile.json');
                if ($profile === null || $profile->hybridPorts === null) {
                    return ['failed', 'the hybrid ports are unknown (no profile with hybrid ports)'];
                }
                $this->persist($profile->hybridPorts);
            }
            $this->host->must('nft-restore', [self::NFT, '-f', $this->firewallPath()]);
            $this->host->must('nft-present', [self::NFT, 'list', 'table', 'inet', self::NFT_TABLE]);
        } catch (DeploymentError | \RuntimeException $error) {
            return ['failed', $error->getMessage()];
        }
        return ['restored', null];
    }

    /**
     * Writes the persisted ruleset when it is missing on a host whose hybrid profile is in effect (the upgrade pass: a host
     * prepared by an earlier build has none). @return bool whether the file exists afterwards
     */
    public function ensurePersisted(): bool
    {
        if (is_file($this->firewallPath())) {
            return true;
        }
        try {
            $profile = Profile::load($this->state . '/profile.json');
            if ($profile === null || $profile->hybridPorts === null) {
                return false;
            }
            $this->persist($profile->hybridPorts);
        } catch (DeploymentError | \RuntimeException) {
            return false;
        }
        return true;
    }

    /** 'present', 'missing' or 'not-hybrid' (no include, so the hybrid profile is not in effect). */
    public function firewallState(): string
    {
        if ($this->host->run('remoteip-current', ['/usr/bin/cat', '--', self::REMOTEIP_CONF])['exit_code'] !== 0) {
            return 'not-hybrid';
        }
        return $this->firewallPresent() ? 'present' : 'missing';
    }

    /** The hybrid firewall table: the backend ports only over loopback, and only from root and OLS's user. */
    public static function nftRuleset(array $ports): string
    {
        $list = implode(', ', array_map('strval', $ports));
        return 'table inet ' . self::NFT_TABLE . " {\n"
            . "    chain input {\n        type filter hook input priority -10; policy accept;\n"
            . "        tcp dport { $list } iifname != \"lo\" drop\n    }\n"
            . "    chain output {\n        type filter hook output priority -10; policy accept;\n"
            . "        tcp dport { $list } fib daddr type local meta skuid != { 0, " . self::OLS_USER . " } reject with tcp reset\n"
            . "    }\n}\n";
    }

    /** The mod_remoteip include: Apache trusts only X-OLS-Client-IP, and only from OLS's local addresses. */
    public static function remoteipConf(array $proxies): string
    {
        return "# OLS-cPanel hybrid profile: requests reach Apache through OpenLiteSpeed on this server, which sends\n"
            . "# the client address in X-OLS-Client-IP. The backend ports admit only local connections from OLS.\n"
            . "<IfModule remoteip_module>\n    RemoteIPHeader X-OLS-Client-IP\n"
            . '    RemoteIPInternalProxy ' . implode(' ', $proxies) . "\n</IfModule>\n";
    }

    /**
     * The local addresses OLS connects to Apache from: loopback plus every vhost address of the compiled plan
     * (IPv4 and the accounts' IPv6 addresses), as the lab experiment derived them.
     * @param array<string,array<string,mixed>> $plan
     * @return list<string>
     */
    public static function proxies(array $plan): array
    {
        $local = [];
        foreach ($plan as $vhost) {
            if (is_string($vhost['ip'] ?? null) && $vhost['ip'] !== '') {
                $local[$vhost['ip']] = true;
            }
            foreach (is_array($vhost['ipv6'] ?? null) ? $vhost['ipv6'] : [] as $address) {
                $local[(string) $address] = true;
            }
        }
        $addresses = array_map('strval', array_keys($local));
        sort($addresses, SORT_STRING);
        return ['127.0.0.1', '::1', ...$addresses];
    }

    /**
     * Every local address of the host from `ip -o addr show`: IPv4 of any scope and global IPv6 (link-local and
     * invalid values dropped), as loopback first and the rest sorted and deduplicated. OLS connects to Apache
     * from whichever of these the vhost's address is, so all of them are trusted (the nftables table admits the
     * backend ports only over loopback and only from root and OLS's user).
     * @return list<string>
     */
    public static function localAddresses(string $ipOutput): array
    {
        $found = [];
        foreach (preg_split('/\R/', $ipOutput) ?: [] as $line) {
            if (preg_match('#\binet (\S+?)(?:/\d+)?(?:\s|$)#', $line, $m) === 1 && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $found[$m[1]] = true;
            } elseif (preg_match('#\binet6 (\S+?)(?:/\d+)?\s.*\bscope global\b#', $line, $m) === 1
                && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $found[strtolower($m[1])] = true;
            }
        }
        unset($found['127.0.0.1'], $found['::1']);
        $addresses = array_map('strval', array_keys($found));
        sort($addresses, SORT_STRING);
        return ['127.0.0.1', '::1', ...$addresses];
    }

    /**
     * The addresses of the RemoteIPInternalProxy line of an installed include (world-readable).
     * @return list<string>
     */
    public static function trustedIn(string $conf): array
    {
        return preg_match('/^\s*RemoteIPInternalProxy\s+(.+?)\s*$/m', $conf, $m) === 1 ? (preg_split('/\s+/', $m[1]) ?: []) : [];
    }

    /**
     * Keeps the include's trusted list equal to the host's local addresses (HR-D14: a new server IP or an account
     * moved to a new IP must not make Apache see the proxy instead of the client). Nothing happens unless the
     * include exists (the hybrid profile is in effect); a changed list is installed atomically, checked with
     * Apache's configuration test (the previous text is put back when it fails) and Apache reloaded gracefully.
     * @return array{result:string, trusted?:list<string>, error?:string}
     */
    public function refreshTrust(string $stageDir): array
    {
        $current = $this->host->run('remoteip-current', ['/usr/bin/cat', '--', self::REMOTEIP_CONF]);
        if ($current['exit_code'] !== 0) {
            return ['result' => 'not-hybrid'];
        }
        // The backend ports are open to the world without the table, so it is checked first and whatever else fails.
        [$firewall, $firewallError] = $this->ensureFirewall();
        $outcome = $this->refreshInclude($stageDir, $current);
        $outcome['firewall'] = $firewall;
        if ($firewall === 'failed') {
            $outcome['result'] = 'failed';
            $outcome['error'] = trim('the firewall table is missing and could not be restored (' . $firewallError . ') ' . ($outcome['error'] ?? ''));
        }
        return $outcome;
    }

    /**
     * @param array{exit_code:int,stdout:string} $current the include as read
     * @return array{result:string, trusted?:list<string>, error?:string}
     */
    private function refreshInclude(string $stageDir, array $current): array
    {
        $trusted = self::localAddresses($this->host->must('local-addresses', [self::IP, '-o', 'addr', 'show']));
        $conf = self::remoteipConf($trusted);
        if ($current['stdout'] === $conf) {
            return ['result' => 'unchanged', 'trusted' => $trusted];
        }
        $this->install($stageDir, $conf);
        $test = $this->host->run('httpd-configtest', [self::HTTPD, '-t'], 60);
        if ($test['exit_code'] !== 0) {
            $this->install($stageDir, $current['stdout']);
            return ['result' => 'failed', 'error' => 'Apache rejected the new include (' . Host::tail($test['stderr'] ?? '')
                . '); the previous one was restored'];
        }
        $this->host->must('reload-httpd', [self::RELOAD, '--graceful'], 180);
        return ['result' => 'updated', 'trusted' => $trusted];
    }

    private function install(string $stageDir, string $conf): void
    {
        $staged = $this->stage($stageDir, 'remoteip.conf', $conf);
        $this->host->must('remoteip-conf', ['/usr/bin/install', '-m', '0644', '-o', 'root', '-g', 'root', $staged, self::REMOTEIP_CONF]);
        $sum = substr(trim($this->host->run('remoteip-digest', ['/usr/bin/sha256sum', '--', self::REMOTEIP_CONF])['stdout']), 0, 64);
        if ($sum !== hash('sha256', $conf)) {
            throw DeploymentError::step('remoteip-conf', 'the installed include differs from the staged text');
        }
    }

    /** @return array<string,string> captured apache_port / apache_ssl_port (validated like the recovery script) */
    public function captureTweaks(): array
    {
        $values = [];
        foreach (RecoveryScript::TWEAK_KEYS as $key) {
            $value = $this->host->getTweak($key);
            if (!preg_match(RecoveryScript::TWEAK_VALUE, $value)) {
                throw DeploymentError::step("tweak-get-$key", "unexpected value $key=" . var_export($value, true));
            }
            $values[$key] = $value;
        }
        return $values;
    }

    /** @return list<string> host objects the product would create that already exist (never overwritten) */
    public function collisions(): array
    {
        $found = [];
        if ($this->host->run('nft-absent', [self::NFT, 'list', 'table', 'inet', self::NFT_TABLE])['exit_code'] === 0) {
            $found[] = 'nftables table inet ' . self::NFT_TABLE;
        }
        if ($this->host->run('remoteip-absent', ['/usr/bin/test', '-e', self::REMOTEIP_CONF])['exit_code'] === 0
            || $this->host->run('remoteip-absent-link', ['/usr/bin/test', '-L', self::REMOTEIP_CONF])['exit_code'] === 0) {
            $found[] = self::REMOTEIP_CONF;
        }
        return $found;
    }

    /**
     * Apache runs each account's CGI as that account (required with hybrid vhosts: otherwise tenant CGI runs as OLS's user):
     * suEXEC, or mod_ruid2 or MPM ITK, the alternatives cPanel itself configures per vhost (`RUidGid`, `AssignUserID`;
     * lab 2026-10-28: a server with mod_ruid2 and no suEXEC was refused the preparation).
     */
    public function suexec(): bool
    {
        $record = $this->host->run('httpd-modules', [self::HTTPD, '-M']);
        return $record['exit_code'] === 0 && preg_match('/^\s*(?:suexec_module|ruid2_module|mpm_itk_module)\b/m', $record['stdout']) === 1;
    }

    /**
     * Applies the changes in the lab-proven order, each checked: include, firewall, tweaks, cPanel's rebuilt
     * httpd.conf listening on the backend ports, an explicit Apache restart (cPanel does not restart Apache
     * after an apache_ssl_port change), Apache listening on the backend ports.
     * @param list<string> $proxies
     * @param array{0:int,1:int} $ports
     * @param string $stageDir root-only directory for the staged texts
     */
    public function apply(array $proxies, array $ports, string $stageDir): void
    {
        $conf = self::remoteipConf($proxies);
        $this->install($stageDir, $conf);
        // The same idempotent text that boot loads: persisted first, then loaded from the persisted file.
        $this->persist($ports);
        $this->host->must('nft-hybrid', [self::NFT, '-f', $this->firewallPath()]);
        $this->host->must('nft-present', [self::NFT, 'list', 'table', 'inet', self::NFT_TABLE]);
        foreach (['apache_port' => $ports[0], 'apache_ssl_port' => $ports[1]] as $key => $port) {
            $this->host->api("tweak-set-$key", 'set_tweaksetting', ["key=$key", "value=0.0.0.0:$port"]);
            if ($this->host->getTweak($key) !== "0.0.0.0:$port") {
                throw DeploymentError::step("tweak-set-$key", "cPanel did not keep $key=0.0.0.0:$port");
            }
        }
        $listening = fn(): bool => array_filter($ports, fn(int $port): bool => !preg_match('/^[1-9]\d*$/D', trim($this->host->run(
            'httpd-conf-listen', ['/usr/bin/grep', '-c', '-F', "Listen 0.0.0.0:$port", self::HTTPD_CONF])['stdout']))) === [];
        if (!$this->host->waitFor($listening, 30, 2)) {
            throw DeploymentError::step('httpd-conf-listen', 'cPanel did not rebuild httpd.conf with the backend ports');
        }
        $this->host->must('restart-httpd', ['/usr/local/cpanel/scripts/restartsrv_httpd'], 180);
        if (!$this->host->waitFor(fn(): bool => $this->host->ownedBy($ports, ['httpd'], 'backend-listeners'), 30, 1)) {
            throw DeploymentError::step('backend-listeners', 'Apache does not listen on the backend ports');
        }
    }

    /**
     * Removes the changes (the recovery script's hybrid part, each step checked): include, captured tweaks,
     * rebuilt configuration, Apache restarted on 80/443, and only then the firewall table.
     * @param array<string,string> $originals
     */
    public function remove(array $originals): void
    {
        $this->host->must('remoteip-remove', ['/usr/bin/rm', '-f', '--', self::REMOTEIP_CONF]);
        ksort($originals, SORT_STRING);
        foreach ($originals as $key => $value) {
            $this->host->api("tweak-restore-$key", 'set_tweaksetting', ["key=$key", "value=$value"]);
        }
        $this->host->must('rebuild-httpd-conf', ['/usr/local/cpanel/scripts/rebuildhttpdconf'], 180);
        $this->host->must('restart-httpd', ['/usr/local/cpanel/scripts/restartsrv_httpd'], 180);
        if (!$this->host->waitFor(fn(): bool => $this->host->ownedBy([80, 443], ['httpd']), 30, 2)) {
            throw DeploymentError::step('listeners', 'Apache does not own 80/443 again; the firewall table stays');
        }
        // The persisted file goes with the table, or the next boot would close the ports of an Apache that owns 80/443 again.
        if (file_exists($this->firewallPath()) && !@unlink($this->firewallPath())) {
            throw DeploymentError::step('nft-unpersist', 'cannot delete ' . $this->firewallPath());
        }
        if ($this->firewallPresent()) {
            $this->host->must('nft-delete', [self::NFT, 'delete', 'table', 'inet', self::NFT_TABLE]);
        }
    }

    /**
     * What the hybrid changes left behind after a return to Apache: check name => holds.
     * @param array<string,string> $originals
     * @param array{0:int,1:int} $ports
     * @return array<string,bool>
     */
    public function verifyRemoved(array $originals, array $ports): array
    {
        $originalPorts = array_map(static fn(string $v): string => substr($v, (int) strrpos($v, ':') + 1), array_values($originals));
        $closed = array_values(array_filter($ports, static fn(int $p): bool => !in_array((string) $p, $originalPorts, true)));
        $checks = ['backend_ports_closed' => $closed === [] || $this->host->free($closed, 'backend-listeners'),
            'nft_table_absent' => $this->host->run('nft-absent', [self::NFT, 'list', 'table', 'inet', self::NFT_TABLE])['exit_code'] !== 0,
            'remoteip_include_absent' => $this->host->run('remoteip-absent', ['/usr/bin/test', '-e', self::REMOTEIP_CONF])['exit_code'] !== 0];
        $equal = true;
        foreach ($originals as $key => $value) {
            try {
                $equal = $equal && $this->host->getTweak($key) === $value;
            } catch (DeploymentError) {
                $equal = false;
            }
        }
        $checks['tweaks_restored'] = $equal;
        return $checks;
    }

    private function stage(string $dir, string $name, string $text): string
    {
        if (!is_dir($dir) && !mkdir($dir, 0700, true)) {
            throw DeploymentError::step('stage', "cannot create $dir");
        }
        $path = "$dir/$name";
        if (file_put_contents($path, $text) !== strlen($text) || !chmod($path, 0600)) {
            throw DeploymentError::step('stage', "cannot write $path");
        }
        return $path;
    }
}
