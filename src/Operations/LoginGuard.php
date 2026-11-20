<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Ols\Compiler\CpanelSurface;

/**
 * WordPress login guard (RV-64, CMP-04; docs/product-interfaces.md "Login guard"). On 2026-11-12 one address sent about 250
 * `POST /xmlrpc.php` a minute to each of four WordPress sites; every request ran PHP (about 46 ms of CPU) and the server stayed
 * at 100% for an hour. OpenLiteSpeed has no per-client request limit scoped to a path (its dynReqPerSec is server-wide and counts
 * every file of a hybrid page, RV-60), so the guard is a watcher of the access logs the product already writes (cPanel's domlogs,
 * filled by splitlogs from OLS and by Apache for hybrid sites):
 *
 * - it counts `POST .../wp-login.php` and `POST .../xmlrpc.php` per site and client address over a sliding minute (the log's own
 *   time stamps); more than LIMITS in WINDOW seconds blocks that address for that site;
 * - a block is a line `<domain>/<address> 1` in the rewrite map every tenant vhost declares (CpanelSurface::GUARD_FILE). The vhost
 *   rule answers the listed client 403 for those two paths only, before PHP; OLS re-reads the changed map within a second, so no
 *   compile and no reload happen during an attack;
 * - blocks expire (BLOCK seconds, doubled for each repeat within a day, at most MAX_BLOCK); the watcher removes them from the map;
 * - never blocked: loopback, the server's own addresses, Jetpack's (Automattic) published ranges, and the operator's `allow` list.
 *
 * A site owner's own login is one or two POSTs; a mobile app or Jetpack a few xmlrpc calls a minute; the soak harness logs in a
 * few times per session. All stay far below the limits. On by default (zero-touch); `login-guard set --enabled=no` and the WHM
 * switch turn it off, which empties the map at once. Settings `<state>/login-guard.json`, state `<state>/login-guard-state.json`
 * (root 0600).
 */
final class LoginGuard
{
    public const SETTINGS = 'login-guard.json';
    public const STATE = 'login-guard-state.json';
    public const DOMLOGS = '/etc/apache2/logs/domlogs';
    public const WINDOW = 60;
    /** POSTs per site, client and WINDOW above which the client is blocked. */
    public const LIMITS = ['xmlrpc' => 30, 'wp-login' => 20];
    public const BLOCK = 900;
    public const MAX_BLOCK = 86400;
    /** A repeat within this time after a block ended doubles the next block. */
    public const MEMORY = 86400;
    public const MAX_BLOCKS = 2000;
    public const MAX_ALLOW = 50;
    public const HISTORY = 50;
    /** The most new log bytes read from one file per pass (a backlog beyond it is skipped). */
    public const MAX_READ = 16 << 20;
    public const INTERVAL = 5;
    /** Jetpack's published addresses (jetpack.com/support/how-to-add-jetpack-ips-allowlist), Automattic's 192.0.64.0/18. */
    public const JETPACK = ['122.248.245.244/32', '54.217.201.243/32', '54.232.116.4/32', '192.0.64.0/18', '195.234.108.0/22'];
    public const LOOPBACK = ['127.0.0.0/8', '::1/128'];
    private const LINE = '~^(\S+) \S+ \S+ \[([^\]]{10,40})\] "POST (\S+)[^"]*" (\d{3}) ~';

    /** @var array<string,array{inode:int,offset:int}> */
    private array $files = [];
    /** @var array<string,list<int>> "<domain>/<address>|<endpoint>" => recent POST times */
    private array $recent = [];
    /** @var array<string,mixed> */
    private array $state;
    private bool $dirty = false;
    /** @var list<string> */
    private array $own;

    /**
     * @param list<string>|null $own the server's own addresses (null: read from /proc)
     */
    public function __construct(private readonly string $stateDir = \OlsCpanel\Deployment\Environment::STATE,
                                private readonly string $domlogs = self::DOMLOGS, private readonly string $mapFile = CpanelSurface::GUARD_FILE,
                                ?array $own = null, private readonly string $group = 'nobody')
    {
        $this->own = $own ?? self::localAddresses();
        $this->reload();
    }

    /** The state as saved (by this watcher or by `login-guard unblock`, another process). */
    private function reload(): void
    {
        $state = StateFile::read($this->stateDir . '/' . self::STATE) ?? [];
        $this->state = ['blocks' => array_filter(is_array($state['blocks'] ?? null) ? $state['blocks'] : [], 'is_array'),
            'strikes' => array_filter(is_array($state['strikes'] ?? null) ? $state['strikes'] : [], 'is_array'),
            'history' => array_values(array_filter(is_array($state['history'] ?? null) ? $state['history'] : [], 'is_array')),
            'seen' => is_array($state['seen'] ?? null) ? $state['seen'] : ['since' => 0, 'posts' => 0, 'refused' => 0],
            'checked_at' => (int) ($state['checked_at'] ?? 0)];
    }

    /** Runs $work under the state lock, on the state as saved (another process may have changed it). */
    private function locked(\Closure $work): mixed
    {
        $lock = @fopen($this->stateDir . '/login-guard.lock', 'c');
        if ($lock !== false) {
            @chmod($this->stateDir . '/login-guard.lock', 0600);
            flock($lock, LOCK_EX);
        }
        try {
            // Everything this watcher changed was saved by its last commit, so the file is the whole state.
            $this->reload();
            return $work();
        } finally {
            if ($lock !== false) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    /** @return array{enabled:bool, allow:list<string>, changed_at:int} */
    public static function settings(string $stateDir): array
    {
        $data = StateFile::read($stateDir . '/' . self::SETTINGS) ?? [];
        $allow = array_values(array_filter(is_array($data['allow'] ?? null) ? $data['allow'] : [],
            static fn($c): bool => is_string($c) && self::validCidr($c)));
        return ['enabled' => ($data['enabled'] ?? true) !== false, 'allow' => array_slice($allow, 0, self::MAX_ALLOW),
            'changed_at' => (int) ($data['changed_at'] ?? 0)];
    }

    /**
     * @param list<string>|null $allow null keeps the stored list
     * @throws Refused for an invalid allow entry
     */
    public static function saveSettings(string $stateDir, ?bool $enabled, ?array $allow, int $now): array
    {
        $current = self::settings($stateDir);
        if ($allow !== null) {
            $allow = array_values(array_unique(array_map('trim', $allow)));
            foreach ($allow as $cidr) {
                if (!self::validCidr($cidr)) {
                    throw new Refused('not an address or address range: ' . StateFile::clean($cidr, 60));
                }
            }
            if (count($allow) > self::MAX_ALLOW) {
                throw new Refused('at most ' . self::MAX_ALLOW . ' allowed addresses');
            }
        }
        $new = ['enabled' => $enabled ?? $current['enabled'], 'allow' => $allow ?? $current['allow'], 'changed_at' => $now];
        StateFile::write($stateDir . '/' . self::SETTINGS, $new);
        return $new;
    }

    /** An IPv4 or IPv6 address, optionally with a prefix length. */
    public static function validCidr(string $cidr): bool
    {
        [$address, $bits] = str_contains($cidr, '/') ? explode('/', $cidr, 2) : [$cidr, null];
        $packed = @inet_pton($address);
        if ($packed === false || ($bits !== null && preg_match('/^[0-9]{1,3}$/D', $bits) !== 1)) {
            return false;
        }
        return $bits === null || (int) $bits <= strlen($packed) * 8;
    }

    /** Whether $address lies in $cidr (both families; a different family never matches). */
    public static function inCidr(string $address, string $cidr): bool
    {
        [$network, $bits] = str_contains($cidr, '/') ? explode('/', $cidr, 2) : [$cidr, null];
        $a = @inet_pton($address);
        $n = @inet_pton($network);
        if ($a === false || $n === false || strlen($a) !== strlen($n)) {
            return false;
        }
        $bits = $bits === null ? strlen($a) * 8 : (int) $bits;
        $bytes = intdiv($bits, 8);
        if (substr($a, 0, $bytes) !== substr($n, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;
        return (ord($a[$bytes]) & $mask) === (ord($n[$bytes]) & $mask);
    }

    /** @param list<string> $allow */
    public function allowed(string $address, array $allow): bool
    {
        if (in_array($address, $this->own, true)) {
            return true;
        }
        foreach ([...self::LOOPBACK, ...self::JETPACK, ...$allow] as $cidr) {
            if (self::inCidr($address, $cidr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * One access log line of $domain (cPanel's combined format: address, identity, user, [time], "request", status, ...). Only
     * POSTs to wp-login.php or xmlrpc.php in the current window count.
     * @param list<string> $allow
     */
    public function observe(string $domain, string $line, int $now, array $allow = []): void
    {
        // POSTs only (an encoded path such as xmlrp%63.php is decoded below, so no cheaper filter on the name).
        if (!str_contains($line, '"POST ') || preg_match(self::LINE, $line, $m) !== 1) {
            return;
        }
        $path = strtolower(rawurldecode(explode('?', $m[3], 2)[0]));
        if (preg_match('~(?:^|/)(wp-login|xmlrpc)\.php(?:/|$)~', $path, $endpoint) !== 1 || filter_var($m[1], FILTER_VALIDATE_IP) === false) {
            return;
        }
        $time = \DateTimeImmutable::createFromFormat('d/M/Y:H:i:s O', $m[2]);
        $at = $time === false ? $now : $time->getTimestamp();
        if ($at <= $now - self::WINDOW || $at > $now + self::WINDOW) {
            return;
        }
        $key = $domain . '/' . $m[1];
        $this->state['seen']['posts'] = (int) ($this->state['seen']['posts'] ?? 0) + 1;
        $this->dirty = true;
        if (isset($this->state['blocks'][$key])) {
            if ($m[4] === '403') {
                $this->state['blocks'][$key]['refused'] = (int) ($this->state['blocks'][$key]['refused'] ?? 0) + 1;
                $this->state['seen']['refused'] = (int) ($this->state['seen']['refused'] ?? 0) + 1;
            }
            return;
        }
        if ($this->allowed($m[1], $allow)) {
            return;
        }
        $name = $key . '|' . $endpoint[1];
        $times = array_values(array_filter($this->recent[$name] ?? [], static fn(int $t): bool => $t > $now - self::WINDOW));
        $times[] = $at;
        $limit = self::LIMITS[$endpoint[1]];
        $this->recent[$name] = array_slice($times, -($limit + 1));
        if (count($times) > $limit && count($this->state['blocks']) < self::MAX_BLOCKS) {
            $this->block($domain, $m[1], $endpoint[1] . '.php', count($times), $now);
            unset($this->recent[$name]);
        }
    }

    private function block(string $domain, string $address, string $endpoint, int $requests, int $now): void
    {
        $key = "$domain/$address";
        $strike = $this->state['strikes'][$key] ?? null;
        $count = is_array($strike) && (int) ($strike['last'] ?? 0) > $now - self::MEMORY ? (int) ($strike['count'] ?? 0) + 1 : 1;
        $duration = min(self::MAX_BLOCK, self::BLOCK * (2 ** min(10, $count - 1)));
        $this->state['strikes'][$key] = ['count' => $count, 'last' => $now + $duration];
        $this->state['blocks'][$key] = ['domain' => $domain, 'address' => $address, 'endpoint' => $endpoint, 'since' => $now,
            'until' => $now + $duration, 'strike' => $count, 'requests' => $requests, 'refused' => 0];
        $this->dirty = true;
    }

    /** New lines of every site's access logs since the last pass (the first pass starts at each file's end). */
    public function scan(int $now, array $allow = []): int
    {
        $lines = 0;
        $names = @scandir($this->domlogs);
        foreach (is_array($names) ? $names : [] as $name) {
            // "<domain>" and "<domain>-ssl_log"; the -bytes_log and -ftp_log files have an underscore elsewhere and never match.
            if (preg_match('/^([a-z0-9][a-z0-9.-]{0,252})(-ssl_log)?$/D', $name, $m) !== 1) {
                continue;
            }
            $path = $this->domlogs . '/' . $name;
            $stat = is_link($path) ? false : @stat($path);
            if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
                continue;
            }
            $known = $this->files[$name] ?? null;
            if ($known === null) {
                $this->files[$name] = ['inode' => $stat['ino'], 'offset' => $stat['size']];
                continue;
            }
            $offset = $known['inode'] === $stat['ino'] && $known['offset'] <= $stat['size'] ? $known['offset'] : 0;
            $offset = max($offset, $stat['size'] - self::MAX_READ);
            $this->files[$name] = ['inode' => $stat['ino'], 'offset' => $offset];
            if ($offset >= $stat['size']) {
                continue;
            }
            $handle = @fopen($path, 'rb');
            if ($handle === false) {
                continue;
            }
            fseek($handle, $offset);
            $text = (string) stream_get_contents($handle, $stat['size'] - $offset);
            fclose($handle);
            // Only whole lines; a line still being written is read on the next pass.
            $end = strrpos($text, "\n");
            if ($end === false) {
                continue;
            }
            $this->files[$name]['offset'] = $offset + $end + 1;
            foreach (explode("\n", substr($text, 0, $end)) as $line) {
                ++$lines;
                $this->observe($m[1], $line, $now, $allow);
            }
        }
        $this->files = array_intersect_key($this->files, array_flip(is_array($names) ? $names : []));
        return $lines;
    }

    /** Expire blocks, write the map when it changed, save the state when it changed (or once a minute). */
    public function commit(int $now, bool $enabled): void
    {
        foreach ($this->state['blocks'] as $key => $block) {
            if (!$enabled || (int) ($block['until'] ?? 0) <= $now) {
                $this->state['history'][] = $block + ['ended' => $now, 'reason' => $enabled ? 'expired' : 'guard_off'];
                unset($this->state['blocks'][$key]);
                $this->dirty = true;
            }
        }
        $this->state['history'] = array_slice($this->state['history'], -self::HISTORY);
        foreach ($this->state['strikes'] as $key => $strike) {
            if ((int) ($strike['last'] ?? 0) <= $now - self::MEMORY) {
                unset($this->state['strikes'][$key]);
            }
        }
        foreach ($this->recent as $name => $times) {
            if (max($times) <= $now - self::WINDOW) {
                unset($this->recent[$name]);
            }
        }
        $this->writeMap($now);
        if ($this->dirty || $this->state['checked_at'] <= $now - 60) {
            $this->state['checked_at'] = $now;
            if ((int) ($this->state['seen']['since'] ?? 0) === 0) {
                $this->state['seen']['since'] = $now;
            }
            StateFile::write($this->stateDir . '/' . self::STATE, $this->state);
            $this->dirty = false;
        }
    }

    /** The map: one line per active block, written atomically with a strictly newer mtime (OLS compares whole seconds). */
    private function writeMap(int $now): void
    {
        $lines = array_keys($this->state['blocks']);
        sort($lines, SORT_STRING);
        $text = "# OLS-cPanel login guard (RV-64): written by `ols-cpanel login-guard run`; do not edit.\n"
            . implode('', array_map(static fn(string $key): string => "$key 1\n", $lines));
        clearstatcache(true, $this->mapFile);
        $current = is_file($this->mapFile) && !is_link($this->mapFile) ? @file_get_contents($this->mapFile) : null;
        if ($current === $text) {
            return;
        }
        $dir = dirname($this->mapFile);
        // /run/ols-cpanel exists while OLS is the product's server (ols-cpanel-logs.service); before that nothing reads a map.
        if (!is_dir(dirname($dir))) {
            return;
        }
        if (!is_dir($dir) && !@mkdir($dir, 0750)) {
            throw new \RuntimeException('cannot create ' . $dir);
        }
        @chmod($dir, 0750);
        @chgrp($dir, $this->group);
        $tmp = $this->mapFile . '.tmp-' . bin2hex(random_bytes(6));
        if (@file_put_contents($tmp, $text) !== strlen($text)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . basename($this->mapFile));
        }
        @chmod($tmp, 0640);
        @chgrp($tmp, $this->group);
        $previous = @filemtime($this->mapFile);
        @touch($tmp, max($now, time(), $previous === false ? 0 : $previous + 1));
        if (!@rename($tmp, $this->mapFile)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . basename($this->mapFile));
        }
    }

    /** One pass: settings, new log lines, expiry, map. */
    public function pass(int $now): array
    {
        return $this->locked(function () use ($now): array {
            $settings = self::settings($this->stateDir);
            $lines = $settings['enabled'] ? $this->scan($now, $settings['allow']) : 0;
            $this->commit($now, $settings['enabled']);
            return ['enabled' => $settings['enabled'], 'lines' => $lines, 'blocked' => count($this->state['blocks'])];
        });
    }

    /** Remove the blocks of $address (on every site, or only $domain); also forgets its repeats. */
    public function unblock(string $address, ?string $domain, int $now): int
    {
        return $this->locked(function () use ($address, $domain, $now): int {
            $removed = 0;
            foreach ($this->state['blocks'] as $key => $block) {
                if (($block['address'] ?? null) === $address && ($domain === null || ($block['domain'] ?? null) === $domain)) {
                    $this->state['history'][] = $block + ['ended' => $now, 'reason' => 'unblocked'];
                    unset($this->state['blocks'][$key], $this->state['strikes'][$key]);
                    ++$removed;
                }
            }
            $this->dirty = true;
            $this->commit($now, self::settings($this->stateDir)['enabled']);
            return $removed;
        });
    }

    /** `pass` every INTERVAL seconds until stopped (ols-cpanel-login-guard.service); a failed pass is retried on the next. */
    public function watch(?int $passes = null, int $interval = self::INTERVAL): void
    {
        for ($i = 0; $passes === null || $i < $passes; ++$i) {
            try {
                $this->pass(time());
            } catch (\Exception $error) {
                fwrite(STDERR, 'login guard: ' . StateFile::clean($error->getMessage()) . "\n");
            }
            if ($passes === null || $i + 1 < $passes) {
                sleep($interval);
            }
        }
    }

    /** The view of `login-guard status` and the WHM page. */
    public function status(int $now): array
    {
        $settings = self::settings($this->stateDir);
        $blocks = array_values(array_filter($this->state['blocks'], static fn($b): bool => is_array($b) && (int) ($b['until'] ?? 0) > $now));
        usort($blocks, static fn(array $a, array $b): int => [$b['since'] ?? 0, $a['domain'] ?? ''] <=> [$a['since'] ?? 0, $b['domain'] ?? '']);
        return ['enabled' => $settings['enabled'], 'allow' => $settings['allow'], 'limits' => self::LIMITS, 'window_seconds' => self::WINDOW,
            'block_seconds' => self::BLOCK, 'max_block_seconds' => self::MAX_BLOCK, 'checked_at' => $this->state['checked_at'] ?: null,
            'watching' => $this->state['checked_at'] > $now - 3 * 60, 'map' => $this->mapFile,
            'seen' => $this->state['seen'], 'blocked' => $blocks, 'recent' => array_reverse($this->state['history'])];
    }

    /** The host's own IPv4 (/proc/net/fib_trie, local routes) and IPv6 (/proc/net/if_inet6) addresses. */
    public static function localAddresses(string $proc = '/proc/net'): array
    {
        $own = [];
        $trie = @file($proc . '/fib_trie', FILE_IGNORE_NEW_LINES);
        $last = null;
        foreach (is_array($trie) ? $trie : [] as $line) {
            if (preg_match('/\|-- ([0-9.]+)$/', $line, $m) === 1) {
                $last = $m[1];
            } elseif ($last !== null && str_contains($line, '/32 host LOCAL')) {
                $own[$last] = true;
            }
        }
        $inet6 = @file($proc . '/if_inet6', FILE_IGNORE_NEW_LINES);
        foreach (is_array($inet6) ? $inet6 : [] as $line) {
            if (preg_match('/^([0-9a-f]{32}) /', $line, $m) === 1) {
                $packed = hex2bin($m[1]);
                $text = $packed === false ? false : inet_ntop($packed);
                if (is_string($text)) {
                    $own[$text] = true;
                }
            }
        }
        return array_map('strval', array_keys($own));
    }
}
