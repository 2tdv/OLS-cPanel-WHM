<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The preview's main configuration (CMP-03): the compiled one with every listener moved to a loopback port. Nothing
 * else of the compile changes, so the vhosts, rewrite rules, PHP handlers and TLS are exactly what the cutover would
 * activate. Anything this class cannot account for is refused: the preview never binds a non-loopback address.
 */
final class PreviewConfig
{
    private const BLOCK = '/^listener[ \t]+(\S+)[ \t]*\{\n(.*?)^\}[ \t]*$\n?/ms';
    private const ADDRESS = '/^[ \t]*address[ \t]+(\S+)[ \t]*$/m';
    /** Never added below this gid: root and the static system groups (accounts start at 500 on old servers, 1000 on EL9). */
    public const MIN_ACCOUNT_GID = 500;

    /**
     * The configuration with loopback listeners. IPv6 listeners are dropped (an IPv6-only site is reported as unprobed);
     * each IPv4 listener (wildcard or one address) gets the next port of $ports; QUIC is left off (nothing binds UDP).
     * @param list<int> $ports ports to use, in order; at least as many as the listeners that stay
     * @return array{config:string, listeners:list<array{name:string, address:string, port:int, new:int}>}
     */
    public static function rewrite(string $config, array $ports): array
    {
        if (preg_match_all('/^[ \t]*listener\b/m', $config) !== preg_match_all(self::BLOCK, $config)) {
            throw DeploymentError::refused('the preview cannot read every listener of the compiled configuration');
        }
        $listeners = [];
        $next = 0;
        $out = preg_replace_callback(self::BLOCK, static function (array $m) use (&$listeners, &$next, $ports): string {
            if (preg_match_all(self::ADDRESS, $m[2], $a) !== 1) {
                throw DeploymentError::refused("listener {$m[1]} has no single address");
            }
            $address = $a[1][0];
            if (str_starts_with($address, '[')) {
                return '';  // IPv6
            }
            if (preg_match('/^(\*|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/D', $address, $parts) !== 1) {
                throw DeploymentError::refused("listener {$m[1]} has an address the preview does not understand: "
                    . substr(preg_replace('/[^\x20-\x7e]+/', ' ', $address) ?? '', 0, 60));
            }
            if (!isset($ports[$next])) {
                throw DeploymentError::refused('not enough preview ports for the listeners');
            }
            $new = $ports[$next++];
            $listeners[] = ['name' => $m[1], 'address' => $parts[1], 'port' => (int) $parts[2], 'new' => $new];
            $body = (string) preg_replace(self::ADDRESS, "    address              127.0.0.1:$new", $m[2], 1);
            $body = (string) preg_replace('/^[ \t]*enableQuic\b.*\n/m', '', $body);
            return "listener {$m[1]} {\n$body}\n";
        }, $config);
        if ($out === null) {
            throw DeploymentError::refused('the preview could not rewrite the listeners');
        }
        self::assertLoopback($out);
        return ['config' => $out, 'listeners' => $listeners];
    }

    /**
     * Refuses a configuration with a listener that is not `127.0.0.1:<unreserved high port>`, with one that cannot be
     * read, and one without any listener. Run on the final text, so a change to rewrite() cannot weaken it.
     */
    public static function assertLoopback(string $config): void
    {
        $declared = preg_match_all('/^[ \t]*listener\b/m', $config);
        if ($declared < 1) {
            throw DeploymentError::refused('the preview configuration has no listener');
        }
        if (preg_match_all(self::BLOCK, $config, $blocks, PREG_SET_ORDER) !== $declared) {
            throw DeploymentError::refused('the preview could not check every listener');
        }
        foreach ($blocks as $block) {
            if (preg_match_all(self::ADDRESS, $block[2], $a) !== 1 || !PreviewPorts::bindable($a[1][0])) {
                throw DeploymentError::refused('the preview refuses a listener that is not on 127.0.0.1 with a free high port: '
                    . substr(preg_replace('/[^\x20-\x7e]+/', ' ', implode(' ', $a[1] ?? [])) ?? '', 0, 80));
            }
        }
    }

    /**
     * The port of the listener that answers a vhost's address on $port (80 or 443): the listener bound to that very
     * address, else the wildcard one.
     * @param list<array{name:string, address:string, port:int, new:int}> $listeners
     */
    public static function portFor(array $listeners, string $ip, int $port): ?int
    {
        foreach ([$ip, '*'] as $address) {
            foreach ($listeners as $listener) {
                if ($listener['address'] === $address && $listener['port'] === $port) {
                    return $listener['new'];
                }
            }
        }
        return null;
    }

    /**
     * Directories the private mount namespace covers with a tmpfs, so a request never reaches a live log, the log
     * shipper's FIFOs or the page cache: every directory an access or error log of the configuration names, and the
     * cache root. "m:<dir>" mounts a tmpfs (an existing directory, or the nearest existing ancestor of a missing one),
     * "d:<dir>" creates the rest. Port of the stage validator's log_dirs (broker/src/activator/validate.rs).
     * @param list<string> $texts the main configuration and every vhost configuration
     * @return list<string>
     */
    public static function mounts(array $texts, string $cacheRoot): array
    {
        $dirs = [$cacheRoot];
        foreach ($texts as $text) {
            if (preg_match_all('/^[ \t]*(?:accesslog|errorlog)[ \t]+(\/\S+)/mi', $text, $m)) {
                foreach ($m[1] as $path) {
                    if (!str_contains($path, '$')) {
                        $dirs[] = dirname($path);
                    }
                }
            }
        }
        $dirs = array_values(array_unique($dirs));
        sort($dirs, SORT_STRING);
        $mounts = $creates = [];
        foreach ($dirs as $dir) {
            if (str_starts_with($dir, '/run/')) {
                $creates[] = $dir;  // /run is a private tmpfs already
                continue;
            }
            if (str_starts_with($dir, '/tmp') || str_starts_with($dir, '/dev/shm') || !str_starts_with($dir, '/')) {
                continue;
            }
            $anchor = $dir;
            while ($anchor !== '/' && !is_dir($anchor)) {
                $anchor = dirname($anchor);
            }
            if (self::protectedPath($anchor)) {
                continue;  // nothing safe to mount over; the server reports the missing directory in its own log
            }
            if ($anchor !== $dir) {
                $creates[] = $dir;
            }
            $mounts[] = $anchor;
        }
        $mounts = array_values(array_unique($mounts));
        sort($mounts, SORT_STRING);
        $outer = array_values(array_filter($mounts, static function (string $m) use ($mounts): bool {
            foreach ($mounts as $other) {
                if ($other !== $m && str_starts_with($m, rtrim($other, '/') . '/')) {
                    return false;  // a mount over an ancestor hides this one
                }
            }
            return true;
        }));
        $creates = array_values(array_unique($creates));
        sort($creates, SORT_STRING);
        return [...array_map(static fn(string $d): string => "m:$d", $outer), ...array_map(static fn(string $d): string => "d:$d", $creates)];
    }

    /** The user the server's workers run as (the main configuration's `user`), or null when it names none usable. */
    public static function webUser(string $config): ?string
    {
        return preg_match('/^user[ \t]+([a-z_][a-z0-9_.-]{0,31})[ \t]*$/m', $config, $m) === 1 ? $m[1] : null;
    }

    /**
     * The groups the web server user joins inside the preview namespace (a private /etc/group): each account's own
     * primary group, which is what lets the workers into a public_html that cPanel FileProtect left user:user 0750 while
     * Apache (mod_ruid2) serves. After the cutover, enablefileprotect makes it user:nobody 0750 instead; the preview
     * changes no file and gives the access in its namespace only. Only a group named like its account and with that
     * account's primary gid qualifies; root's group (gid 0) and every system group are never added.
     * @param list<string> $users the probed vhosts' account users
     * @return list<string>
     */
    public static function accountGroups(array $users, string $passwd, string $group): array
    {
        $gids = [];
        foreach (explode("\n", $passwd) as $line) {
            $f = explode(':', $line);
            if (count($f) >= 4 && preg_match('/^\d+$/D', $f[3])) {
                $gids[$f[0]] = (int) $f[3];
            }
        }
        $names = [];
        foreach (explode("\n", $group) as $line) {
            $f = explode(':', $line);
            if (count($f) >= 3 && preg_match('/^\d+$/D', $f[2])) {
                $names[$f[0]] = (int) $f[2];
            }
        }
        $out = [];
        foreach (array_unique($users) as $user) {
            if (!preg_match('/^[a-z][a-z0-9_-]{0,31}$/D', $user) || in_array($user, ['root', 'nobody', 'wheel', 'adm', 'mail', 'apache', 'cpanel'], true)) {
                continue;
            }
            $gid = $gids[$user] ?? null;
            if ($gid !== null && $gid >= self::MIN_ACCOUNT_GID && ($names[$user] ?? null) === $gid) {
                $out[] = $user;
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }

    /** Directories that stay as they are in the namespace too: the system and the product's own state. */
    private static function protectedPath(string $path): bool
    {
        return in_array($path, ['/', '/var', '/var/lib', '/var/lib/ols-cpanel', '/usr', '/usr/local', '/etc', '/home', '/opt', '/var/log', '/boot'], true);
    }
}
