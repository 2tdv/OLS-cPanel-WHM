<?php
declare(strict_types=1);

namespace OlsCpanel\Cpanel\Discovery;

/**
 * cPanel account vhosts for OLS (OLS-19), read the way cPanel lays them out: "main" and "sub"
 * domains in /etc/userdatadomains are vhosts, "parked" domains are aliases of their parent, an
 * "addon" domain is served by its own subdomain vhost (and names that vhost's PHP-FPM pool); the
 * per-vhost userdata file is authoritative for names, document root, IP and PHP version.
 * Output is kept identical to the lab-proven build/vm-qualification/cpanel_vhosts.py
 * (tests/compiler_equivalence.py).
 */
final class AccountVhosts
{
    private const FIELDS = ['servername', 'serveralias', 'documentroot', 'ip', 'phpversion'];
    private const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';
    private const SAFE_PATH = '/^\/[A-Za-z0-9._\/@+-]*$/D';
    private const VHOST_OPEN = '/^\s*<VirtualHost\s+([^>]+)>/i';
    private const SERVER_NAME = '/^\s*ServerName\s+(\S+)/i';
    private const SERVER_ALIAS = '/^\s*ServerAlias\s+(.+)$/iD';

    /** @return array<string,array<string,string>> domain => user, owner, type, parent, docroot, http, https, php */
    public function parseUserdataDomains(string $text): array
    {
        $rows = [];
        foreach (preg_split('/\R/', $text) as $line) {
            if (trim($line) === '') {
                continue;
            }
            [$domain, $rest] = array_pad(explode(': ', $line, 2), 2, '');
            $fields = explode('==', $rest);
            if (count($fields) < 10) {
                throw new \InvalidArgumentException("unexpected userdatadomains line for $domain");
            }
            [$user, $owner, $kind, $parent, $docroot, $http, $https] = $fields;
            $rows[$domain] = ['user' => $user, 'owner' => $owner, 'type' => $kind, 'parent' => $parent,
                'docroot' => $docroot, 'http' => $http, 'https' => $https, 'php' => $fields[9]];
        }
        return $rows;
    }

    /** @return array<string,string> the scalar vhost fields of a userdata YAML file */
    public function userdataFields(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) as $line) {
            $parts = explode(': ', $line, 2);
            if (count($parts) === 2 && in_array($parts[0], self::FIELDS, true)) {
                $out[$parts[0]] = trim(trim($parts[1]), "'\"");
            }
        }
        return $out;
    }

    /**
     * Vhost specs for one account; every name and path is validated and a malformed or foreign
     * entry is an error, never a guess.
     * @param array<string,array<string,string>> $rows
     * @param array<string,string> $userdata vhost name => userdata file text
     * @return list<array<string,mixed>>
     */
    /**
     * IPv6 addresses cPanel assigned to the vhost: the keys of the userdata "ipv6:" mapping ("ipv6: ~"
     * or no block means none). Anything that is not an IPv6 address is an error.
     * @return list<string>
     */
    public function userdataIpv6(string $text): array
    {
        $addresses = [];
        $inside = false;
        foreach (preg_split('/\R/', $text) as $line) {
            if (!str_starts_with($line, ' ')) {
                $inside = trim(explode('#', $line)[0]) === 'ipv6:';
                continue;
            }
            if ($inside && str_starts_with($line, '  ') && !str_starts_with($line, '   ') && str_ends_with(rtrim($line), ':')) {
                $key = trim(substr(trim($line), 0, -1), "'\"");
                $packed = @inet_pton($key);
                if ($packed === false || strlen($packed) !== 16) {
                    throw new \InvalidArgumentException("invalid IPv6 address in userdata: $key");
                }
                $addresses[] = (string) inet_ntop($packed);
            }
        }
        return $addresses;
    }

    public function accountVhosts(string $user, array $rows, array $userdata): array
    {
        ksort($rows, SORT_STRING);
        $vhosts = [];
        foreach ($rows as $name => $row) {
            $name = (string) $name;
            if ($row['user'] !== $user || !in_array($row['type'], ['main', 'sub'], true)) {
                continue;
            }
            if (!isset($userdata[$name])) {
                throw new \InvalidArgumentException("no userdata for $name");
            }
            $fields = $this->userdataFields($userdata[$name]);
            if (($fields['servername'] ?? null) !== $name) {
                throw new \InvalidArgumentException("userdata servername mismatch for $name");
            }
            $aliases = preg_split('/\s+/', $fields['serveralias'] ?? '', -1, PREG_SPLIT_NO_EMPTY);
            $addons = $this->children($rows, 'addon', $name, $user);
            $parked = $this->children($rows, 'parked', $name, $user);
            foreach ([$name, ...$aliases, ...$addons, ...$parked] as $domain) {
                if (!preg_match(self::DOMAIN, $domain)) {
                    throw new \InvalidArgumentException("invalid domain '$domain' for $name");
                }
            }
            $docroot = $fields['documentroot'] ?? '';
            // In the account's own home on a /home<suffix> mount (HomePath, the product's one home policy).
            if (!preg_match(self::SAFE_PATH, $docroot) || HomePath::homeOf($docroot, $user) === null) {
                throw new \InvalidArgumentException("unsafe document root for $name: '$docroot'");
            }
            if (count($addons) > 1) {
                throw new \InvalidArgumentException("more than one addon domain on $name");
            }
            $vhosts[] = ['name' => $name, 'type' => $row['type'], 'docroot' => $docroot, 'aliases' => $aliases,
                'ip' => $fields['ip'] ?? '', 'ipv6' => $this->userdataIpv6($userdata[$name]), 'php' => ($fields['phpversion'] ?? '') !== '' ? $fields['phpversion'] : $row['php'],
                'pool' => $addons[0] ?? $name,
                'service_domains' => [...($row['type'] === 'main' ? [$name] : []), ...$addons],
                'addons' => $addons, 'parked' => $parked];
        }
        if (count(array_filter($vhosts, static fn(array $v): bool => $v['type'] === 'main')) !== 1) {
            throw new \InvalidArgumentException("expected exactly one main vhost for $user");
        }
        return $vhosts;
    }

    /**
     * Every directory above the document root, outermost first: cPanel's httpd.conf has
     * AllowOverride All on "/", so Apache applies a .htaccess in any of them to the vhost.
     * @return list<string>
     */
    public function ancestors(string $docroot): array
    {
        $parts = array_slice(explode('/', rtrim($docroot, '/')), 1, -1);
        $out = [];
        for ($i = 0; $i <= count($parts); $i++) {
            $out[] = $i === 0 ? '/' : '/' . implode('/', array_slice($parts, 0, $i));
        }
        return $out;
    }

    /**
     * Default vhost per address: {"address|port" => ServerName} of the first <VirtualHost> on each address
     * and port of cPanel's generated httpd.conf (Apache answers every unknown name on that address with
     * it). "*" entries are recorded as "*|port", and a token without a port as "address|" (any port).
     * Read only; never modified.
     * @return array<string,string>
     */
    public function apacheDefaults(string $httpdConf): array
    {
        $defaults = [];
        $pending = null;
        foreach ($this->lines($httpdConf) as $line) {
            if (preg_match(self::VHOST_OPEN, $line, $opened)) {
                $pending = $this->endpoints($opened[1]);
                continue;
            }
            if ($pending !== null && preg_match(self::SERVER_NAME, $line, $named)) {
                foreach ($pending as $endpoint) {
                    $defaults[$endpoint] ??= strtolower($named[1]);
                }
                $pending = null;
            }
        }
        return $defaults;
    }

    /**
     * "address|port" endpoints where cPanel binds a proxy-subdomains vhost (ServerAlias cpanel.*): there
     * every unclaimed service name is proxied to cpsrvd. Sorted by address, then port.
     * @return list<string>
     */
    public function apacheProxyEndpoints(string $httpdConf): array
    {
        $endpoints = [];
        $pending = null;
        foreach ($this->lines($httpdConf) as $line) {
            if (preg_match(self::VHOST_OPEN, $line, $opened)) {
                $pending = $this->endpoints($opened[1]);
                continue;
            }
            if ($pending !== null && preg_match(self::SERVER_ALIAS, $line, $alias)
                && in_array('cpanel.*', preg_split('/\s+/', $alias[1], -1, PREG_SPLIT_NO_EMPTY), true)) {
                foreach ($pending as $endpoint) {
                    $endpoints[$endpoint] = true;
                }
            }
            if (str_starts_with(strtolower(trim($line)), '</virtualhost')) {
                $pending = null;
            }
        }
        $sorted = array_map('strval', array_keys($endpoints));
        usort($sorted, static function (string $a, string $b): int {
            [$addressA, $portA] = explode('|', $a);
            [$addressB, $portB] = explode('|', $b);
            return strcmp($addressA, $addressB) ?: (int) $portA <=> (int) $portB;
        });
        return $sorted;
    }

    /**
     * Global IPv6 addresses from `ip -6 -o addr show scope global`, canonical, after ::1 (where
     * Apache's "Listen [::]" also answers).
     * @return list<string>
     */
    public function boundIpv6(string $ipOutput): array
    {
        $found = ['::1'];
        foreach ($this->lines($ipOutput) as $line) {
            $parts = preg_split('/\s+/', $line, -1, PREG_SPLIT_NO_EMPTY);
            $index = array_search('inet6', $parts, true);
            if ($index === false) {
                continue;
            }
            if (!isset($parts[$index + 1])) {
                throw new \InvalidArgumentException('inet6 without an address in ip output');
            }
            $address = $this->canonicalIpv6(explode('/', $parts[$index + 1])[0]);
            if (!in_array($address, $found, true)) {
                $found[] = $address;
            }
        }
        return $found;
    }

    /**
     * "address|port" of each <VirtualHost> token; "*" or "*:443" are wildcards (empty port = any).
     * @return list<string>
     */
    private function endpoints(string $tokens): array
    {
        $out = [];
        foreach (preg_split('/\s+/', $tokens, -1, PREG_SPLIT_NO_EMPTY) as $token) {
            if (str_starts_with($token, '[')) {
                [$address, $port] = array_pad(explode(']:', substr($token, 1), 2), 2, '');
                $out[] = $this->canonicalIpv6($address) . '|' . $this->port($port, $token);
                continue;
            }
            $colon = strrpos($token, ':');
            $port = $colon === false ? '' : substr($token, $colon + 1);
            $out[] = ($colon === false ? $token : substr($token, 0, $colon)) . '|'
                . ($port === '' ? '' : $this->port($port, $token));
        }
        return $out;
    }

    /** A port number as Python's int() reads it (optional sign, "_" digit separators). */
    private function port(string $port, string $token): string
    {
        if (!preg_match('/^[+-]?\d+(?:_\d+)*$/D', $port)) {
            throw new \InvalidArgumentException("invalid VirtualHost address $token");
        }
        return (string) (int) str_replace('_', '', $port);
    }

    private function canonicalIpv6(string $address): string
    {
        $packed = @inet_pton($address);
        if ($packed === false || strlen($packed) !== 16) {
            throw new \InvalidArgumentException("invalid IPv6 address: $address");
        }
        return (string) inet_ntop($packed);
    }

    /**
     * Lines as Python's str.splitlines() yields them from UTF-8 text; a UTF-8 continuation byte is
     * never taken for a line break.
     * @return list<string>
     */
    private function lines(string $text): array
    {
        $lines = preg_split('/\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e]|\xc2\x85|\xe2\x80[\xa8\xa9]/', $text);
        if ($lines !== [] && end($lines) === '') {
            array_pop($lines);
        }
        return $lines;
    }

    /**
     * @param array<string,array<string,string>> $rows
     * @return list<string>
     */
    private function children(array $rows, string $type, string $parent, string $user): array
    {
        $out = [];
        foreach ($rows as $domain => $row) {
            if ($row['type'] === $type && $row['parent'] === $parent && $row['user'] === $user) {
                $out[] = (string) $domain;
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }
}
