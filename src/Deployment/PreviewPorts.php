<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * Port selection of the preview (CMP-03): high loopback ports that nothing listens on. The listening table is read
 * once (ss) and the inner script checks the chosen ports again right before OpenLiteSpeed starts.
 */
final class PreviewPorts
{
    /** Below the kernel's ephemeral range (32768 and up), so an outgoing connection never holds one of them. */
    public const FIRST = 20000;
    public const LAST = 29999;
    /** Never chosen, whatever the table says: the public ports, the hybrid Apache pair, the marker port, cPanel's and OLS's own. */
    public const RESERVED = [80, 443, 81, 444, 8080, 8443, 8097, 7080, 2082, 2083, 2086, 2087, 2095, 2096];

    /**
     * The TCP ports in `ss -H -ltn` output (every local address, IPv4, IPv6 and wildcard alike).
     * @return list<int>
     */
    public static function listening(string $ssText): array
    {
        $ports = [];
        foreach (explode("\n", $ssText) as $line) {
            $fields = preg_split('/\s+/', trim($line)) ?: [];
            if (count($fields) < 4) {
                continue;
            }
            $colon = strrpos($fields[3], ':');
            $port = $colon === false ? '' : substr($fields[3], $colon + 1);
            if (preg_match('/^\d{1,5}$/D', $port) === 1) {
                $ports[(int) $port] = true;
            }
        }
        $out = array_keys($ports);
        sort($out);
        return $out;
    }

    /**
     * $count distinct free ports, scanned from a random start inside FIRST..LAST (wrapping once), skipping the listening
     * ones and the reserved ones. Refuses when the range does not hold enough.
     * @param list<int> $busy ports that are in use
     * @param \Closure(int,int):int|null $random random_int-compatible, injectable for tests
     * @return list<int>
     */
    public static function pick(int $count, array $busy, ?\Closure $random = null): array
    {
        if ($count < 1 || $count > 64) {
            throw new \InvalidArgumentException('invalid port count');
        }
        $taken = array_fill_keys([...$busy, ...self::RESERVED], true);
        $size = self::LAST - self::FIRST + 1;
        $start = ($random ?? random_int(...))(0, $size - 1);
        $chosen = [];
        for ($i = 0; $i < $size && count($chosen) < $count; ++$i) {
            $port = self::FIRST + (($start + $i) % $size);
            if (!isset($taken[$port])) {
                $chosen[] = $port;
            }
        }
        if (count($chosen) < $count) {
            throw DeploymentError::refused("no $count free ports in " . self::FIRST . '-' . self::LAST . ' for the preview');
        }
        return $chosen;
    }

    /** True for an address a preview may bind: IPv4 loopback with a port outside the reserved and privileged ones. */
    public static function bindable(string $address): bool
    {
        if (preg_match('/^127\.0\.0\.1:([1-9]\d{0,4})$/D', $address, $m) !== 1) {
            return false;
        }
        $port = (int) $m[1];
        return $port >= 1024 && $port <= 65535 && !in_array($port, self::RESERVED, true);
    }
}
