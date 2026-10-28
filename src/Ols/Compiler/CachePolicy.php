<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * LSCache policy for the OLS 1.9.3 cache module (feature vertical FV-01, plan §20.3 and §21.6): server level
 * module off with the product's parameters, one store per native tenant vhost in the root-owned cache tree
 * (lookups only where the cache is enabled: not suspended, plan field "cache" not false), the hybrid
 * pass-through vhosts disabled, and PURGE/REFRESH refused on enabled vhosts. Output is byte-identical to
 * build/vm-qualification/lscache.py (checked by tests/compiler_equivalence.py); the source citations for
 * every choice are in that module's docstring.
 */
final class CachePolicy
{
    public const CACHE_ROOT = '/var/lib/ols-cpanel/cache';
    /** The server-level store; vhost stores always contain "@", so no vhost store can take this name. */
    public const SERVER_STORE = 'server';
    /** Server and vhost parameters in emission order (OLS cache.cpp paramArray names). */
    public const PARAMS = [
        ['checkPublicCache', '1'], ['checkPrivateCache', '1'], ['enableCache', '0'], ['enablePrivateCache', '0'],
        ['qsCache', '1'], ['reqCookieCache', '1'], ['respCookieCache', '1'], ['ignoreReqCacheCtrl', '1'],
        ['ignoreRespCacheCtrl', '0'], ['expireInSeconds', '3600'], ['privateExpireInSeconds', '3600'],
        ['maxStaleAge', '200'], ['maxCacheObjSize', '10000000'],
    ];
    /** Cleanup margin (seconds) past the longest lifetime this policy gives an entry: applications may set a longer one themselves. */
    public const CLEAN_MARGIN = 86400;
    /** Floor of the expiry age: applications may set longer lifetimes than the server default (LiteSpeed Cache for WordPress
     * defaults to one week), so entries are never removed as expired before eight days; the size caps bound growth meanwhile. */
    public const MIN_ENTRY_AGE = 691200;
    public const USER = '/^[a-z0-9][a-z0-9_.-]*$/D';
    public const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';
    private const NAME_MAX = 255;

    /**
     * Age in seconds (by modification time) after which an entry file is certainly expired: the longest default lifetime of this
     * policy (public or private) plus the stale window (maxStaleAge, a stale ".S" copy) plus CLEAN_MARGIN, at least MIN_ENTRY_AGE. Read from PARAMS, so the
     * cleanup follows the emitted configuration.
     */
    public static function maxEntryAge(): int
    {
        $values = [];
        foreach (self::PARAMS as [$key, $value]) {
            $values[$key] = (int) $value;
        }
        return max(self::MIN_ENTRY_AGE, max($values['expireInSeconds'], $values['privateExpireInSeconds']) + $values['maxStaleAge'] + self::CLEAN_MARGIN);
    }

    public function serverBlock(string $root = self::CACHE_ROOT): string
    {
        return $this->block(false, "$root/" . self::SERVER_STORE);
    }

    /**
     * A native vhost serves from its cache unless its account is suspended or the per-vhost "cache" plan
     * field (configuration overrides, FV-06) is anything but true; absent means on.
     * @param array<string,mixed> $v
     */
    public function enabled(array $v, bool $suspended = false): bool
    {
        return ($v['cache'] ?? true) === true && !$suspended;
    }

    /** @param array<string,mixed> $v account vhost model with "user" and "name" */
    public function vhostBlock(array $v, bool $suspended = false, string $root = self::CACHE_ROOT): string
    {
        return $this->block($this->enabled($v, $suspended), $this->storagePath((string) $v['user'], (string) $v['name'], $root));
    }

    /** A vhost that never uses the cache (the hybrid pass-through vhosts <domain> and tls.<domain>). */
    public function disabledBlock(): string
    {
        return "module cache {\n" . $this->line('ls_enabled', '0') . "}\n";
    }

    /**
     * Vhost-level rewrite rules of an enabled vhost: PURGE/REFRESH are refused before the cache module could
     * honour them from a local address without authentication.
     * @param array<string,mixed> $v
     */
    public function vhostRules(array $v, bool $suspended = false): string
    {
        return $this->enabled($v, $suspended)
            ? "RewriteCond %{REQUEST_METHOD} ^(PURGE|REFRESH)\$ [NC]\nRewriteRule ^ - [F]\n" : '';
    }

    /**
     * Per account vhost: whether OLS serves it from cache and its store (null for hybrid vhosts).
     * @param array<string,array<string,mixed>> $plan
     * @param list<string> $suspendedUsers
     * @return array<string,array{enabled:bool, storage:?string}>
     */
    public function summary(array $plan, array $suspendedUsers, string $root = self::CACHE_ROOT): array
    {
        $out = [];
        foreach ($plan as $name => $v) {
            $native = ($v['mode'] ?? 'native') !== 'apache';
            $out[(string) $name] = [
                'enabled' => $native && $this->enabled($v, in_array($v['user'], $suspendedUsers, true)),
                'storage' => $native ? $this->storagePath((string) $v['user'], (string) $name, $root) : null,
            ];
        }
        return $out;
    }

    /** "<user>@<vhost>", or "<user>@h-<sha256 of vhost>" when that would exceed one path component. */
    public function storeName(string $user, string $vhost): string
    {
        if (!preg_match(self::USER, $user) || !preg_match(self::DOMAIN, $vhost)) {
            throw new \InvalidArgumentException("invalid cache store owner '$user' or vhost '$vhost'");
        }
        $name = "$user@$vhost";
        if (strlen($name) > self::NAME_MAX) {
            $name = "$user@h-" . hash('sha256', $vhost);
        }
        if (strlen($name) > self::NAME_MAX) {
            throw new \InvalidArgumentException("cache store name for '$user' is too long");
        }
        return $name;
    }

    public function storagePath(string $user, string $vhost, string $root = self::CACHE_ROOT): string
    {
        return "$root/" . $this->storeName($user, $vhost);
    }

    private function block(bool $enabled, string $storage): string
    {
        $params = '';
        foreach (self::PARAMS as [$key, $value]) {
            $params .= $this->line($key, $value);
        }
        return "module cache {\n" . $this->line('ls_enabled', $enabled ? '1' : '0') . $params
            . $this->line('storagePath', $storage) . "}\n";
    }

    private function line(string $key, string $value): string
    {
        return '    ' . str_pad($key, 20) . " $value\n";
    }
}
