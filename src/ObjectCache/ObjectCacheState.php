<?php
declare(strict_types=1);

namespace OlsCpanel\ObjectCache;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Events\HookEntry;

/**
 * /var/lib/ols-cpanel/objcache.json (root 0644, no secrets), written atomically (temporary file, fsync, rename):
 *
 *   {"schema_version": 1, "defaults": {"memory_mb": 64},
 *    "packages": {"<cPanel package>": {"memory_mb": 128}},
 *    "accounts": {"<account>": {"enabled": true, "memory_mb": 64}}}
 *
 * The optional top-level "wordpress" key records, per account, the WordPress installations the product looked at
 * ("<account>": {"<install directory>": {"state", "product_set", "checked", "php", "error"}}); "product_set" is true
 * only where the product itself switched LiteSpeed Cache's object cache on, so only those are switched off again.
 * An absent file is the empty state. A malformed file is refused (never silently replaced): the operator
 * fixes or removes it. An account entry with "enabled": false is the administrator's durable "off" for that account: it
 * opts the account out of its package and out of the automatic mode until `objcache enable` replaces it.
 *
 * Automatic mode (on unless the top-level "automatic" is false, the only value of it ever written): an account with a
 * WordPress site that has LiteSpeed Cache gets its own instance without anyone enabling it. Its entry carries "origin":
 * "automatic" (an entry without "origin" was set by the administrator), and only such entries are ever removed again by
 * the pass: when the account's last WordPress with LiteSpeed Cache is gone, when its package is switched off or when the
 * automatic mode is turned off. A package with "memory_mb": 0 is switched off for its accounts (no package instance and
 * no automatic one). The optional "discovery" key ("<account>": <unix time>) records when the pass last looked for
 * WordPress with LiteSpeed Cache in an account without an object cache, so that each such account is looked at only once
 * per ObjectCacheManager::DISCOVERY_INTERVAL.
 */
final class ObjectCacheState
{
    public const SITE_STATES = ['automatic', 'owner', 'inactive', 'error'];
    public const PACKAGE = '/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/D';
    /** The origin of an account entry the automatic mode created (and may remove again). */
    public const AUTOMATIC = 'automatic';

    /**
     * @param array<string,array{memory_mb:int}> $packages memory_mb 0: the package is switched off
     * @param array<string,array{enabled:bool, memory_mb:int, origin?:string}> $accounts
     * @param array<string,array<string,array{state:string, product_set:bool, checked:int, php:?string, error:?string}>> $wordpress
     * @param array<string,int> $discovery account => when the pass last looked for WordPress with LiteSpeed Cache in it
     */
    public function __construct(public int $defaultMemory = ValkeyConfig::DEFAULT_MEMORY_MB, public array $packages = [],
                                public array $accounts = [], public array $wordpress = [], public bool $automatic = true,
                                public array $discovery = [])
    {
    }

    public static function load(string $path): self
    {
        if (!file_exists($path)) {
            return new self();
        }
        $text = @file_get_contents($path);
        $data = is_string($text) ? json_decode($text, true, 8) : null;
        if (!is_array($data) || ($data['schema_version'] ?? null) !== 1 || !is_array($data['defaults'] ?? null)
            || !is_array($data['packages'] ?? null) || !is_array($data['accounts'] ?? null)) {
            throw new Refused("$path is malformed; fix or remove it");
        }
        $default = $data['defaults']['memory_mb'] ?? null;
        if (!is_int($default) || ValkeyConfig::parseMemory((string) $default) === null) {
            throw new Refused("$path: defaults.memory_mb is invalid");
        }
        $state = new self($default);
        foreach ($data['packages'] as $name => $entry) {
            $mb = is_array($entry) ? ($entry['memory_mb'] ?? null) : null;
            if (!is_string($name) || !preg_match(self::PACKAGE, $name) || !is_int($mb) || ($mb !== 0 && ValkeyConfig::parseMemory((string) $mb) === null)) {
                throw new Refused("$path: invalid package entry");
            }
            $state->packages[$name] = ['memory_mb' => $mb];
        }
        foreach ($data['accounts'] as $user => $entry) {
            $mb = is_array($entry) ? ($entry['memory_mb'] ?? null) : null;
            $origin = is_array($entry) ? ($entry['origin'] ?? null) : null;
            if (!is_string($user) || !ValkeyConfig::validUser($user) || !is_bool($entry['enabled'] ?? null)
                || !is_int($mb) || ValkeyConfig::parseMemory((string) $mb) === null || !($origin === null || $origin === self::AUTOMATIC)) {
                throw new Refused("$path: invalid account entry");
            }
            $state->accounts[(string) $user] = ['enabled' => $entry['enabled'], 'memory_mb' => $mb] + ($origin === null ? [] : ['origin' => $origin]);
        }
        $automatic = $data['automatic'] ?? true;
        $discovery = $data['discovery'] ?? [];
        if (!is_bool($automatic) || !is_array($discovery)) {
            throw new Refused("$path: invalid automatic mode entry");
        }
        $state->automatic = $automatic;
        foreach ($discovery as $user => $checked) {
            if (!is_string($user) || !ValkeyConfig::validUser($user) || !is_int($checked) || $checked < 0) {
                throw new Refused("$path: invalid discovery entry");
            }
            $state->discovery[$user] = $checked;
        }
        $sites = $data['wordpress'] ?? [];
        if (!is_array($sites)) {
            throw new Refused("$path: invalid wordpress entry");
        }
        foreach ($sites as $user => $paths) {
            if (!is_string($user) || !ValkeyConfig::validUser($user) || !is_array($paths)) {
                throw new Refused("$path: invalid wordpress entry");
            }
            foreach ($paths as $dir => $row) {
                if (!is_string($dir) || !is_array($row) || !in_array($row['state'] ?? null, self::SITE_STATES, true)
                    || !is_bool($row['product_set'] ?? null) || !is_int($row['checked'] ?? null)
                    || !(($row['php'] ?? null) === null || is_string($row['php'])) || !(($row['error'] ?? null) === null || is_string($row['error']))) {
                    throw new Refused("$path: invalid wordpress entry");
                }
                $state->wordpress[$user][$dir] = ['state' => $row['state'], 'product_set' => $row['product_set'], 'checked' => $row['checked'],
                    'php' => $row['php'] ?? null, 'error' => $row['error'] ?? null]
                    + (is_string($row['previous_socket'] ?? null) ? ['previous_socket' => $row['previous_socket']] : [])
                    + (is_int($row['attempts'] ?? null) && $row['attempts'] >= 0 ? ['attempts' => $row['attempts']] : [])
                    + (is_string($row['fingerprint'] ?? null) ? ['fingerprint' => $row['fingerprint']] : []);
            }
        }
        return $state;
    }

    public function save(string $path): void
    {
        ksort($this->packages, SORT_STRING);
        ksort($this->accounts, SORT_STRING);
        $document = ['schema_version' => 1, 'defaults' => ['memory_mb' => $this->defaultMemory],
            'packages' => (object) $this->packages, 'accounts' => (object) $this->accounts];
        if (!$this->automatic) {
            $document['automatic'] = false;  // only the administrator's "off" is written; absent means on
        }
        if ($this->discovery !== []) {
            ksort($this->discovery, SORT_STRING);
            $document['discovery'] = $this->discovery;
        }
        $sites = [];
        foreach ($this->wordpress as $user => $paths) {
            if ($paths !== []) {
                ksort($paths, SORT_STRING);
                $sites[$user] = $paths;
            }
        }
        if ($sites !== []) {
            ksort($sites, SORT_STRING);
            $document['wordpress'] = $sites;
        }
        $text = json_encode($document,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        HookEntry::writeDurable($path, $text, 0644);
    }

    /**
     * What the state asks for an account: its memory limit, or null when no instance is wanted.
     * @param string|null $package the account's cPanel package, when known
     */
    public function memoryFor(string $user, ?string $package): ?int
    {
        $entry = $this->accounts[$user] ?? null;
        if ($entry !== null) {
            return $entry['enabled'] ? $entry['memory_mb'] : null;
        }
        return $this->packageMemory($package) ?: null;  // 0: the package is switched off
    }

    /** The package's memory: null when the package has no object cache setting, 0 when it is switched off. */
    public function packageMemory(?string $package): ?int
    {
        return $package !== null ? ($this->packages[$package]['memory_mb'] ?? null) : null;
    }

    /**
     * Who decided the account's object cache: "automatic" (the automatic mode), "administrator" (enabled for the account),
     * "package" (its package has memory), "disabled" (the administrator turned it off for the account), "package_off" (its
     * package is switched off), or null (nothing decided: while the automatic mode is on, the account gets its cache once
     * it has WordPress with LiteSpeed Cache).
     */
    public function origin(string $user, ?string $package): ?string
    {
        $entry = $this->accounts[$user] ?? null;
        if ($entry !== null) {
            return !$entry['enabled'] ? 'disabled' : (($entry['origin'] ?? null) === self::AUTOMATIC ? 'automatic' : 'administrator');
        }
        $mb = $this->packageMemory($package);
        return $mb === null ? null : ($mb === 0 ? 'package_off' : 'package');
    }
}
