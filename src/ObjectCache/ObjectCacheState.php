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
 * fixes or removes it. An account entry with "enabled": false opts an account out of its package.
 */
final class ObjectCacheState
{
    public const SITE_STATES = ['automatic', 'owner', 'inactive', 'error'];
    public const PACKAGE = '/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/D';

    /**
     * @param array<string,array{memory_mb:int}> $packages
     * @param array<string,array{enabled:bool, memory_mb:int}> $accounts
     */
    /**
     * @param array<string,array<string,array{state:string, product_set:bool, checked:int, php:?string, error:?string}>> $wordpress
     */
    public function __construct(public int $defaultMemory = ValkeyConfig::DEFAULT_MEMORY_MB, public array $packages = [],
                                public array $accounts = [], public array $wordpress = [])
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
            if (!is_string($name) || !preg_match(self::PACKAGE, $name) || !is_int($mb) || ValkeyConfig::parseMemory((string) $mb) === null) {
                throw new Refused("$path: invalid package entry");
            }
            $state->packages[$name] = ['memory_mb' => $mb];
        }
        foreach ($data['accounts'] as $user => $entry) {
            $mb = is_array($entry) ? ($entry['memory_mb'] ?? null) : null;
            if (!is_string($user) || !ValkeyConfig::validUser($user) || !is_bool($entry['enabled'] ?? null)
                || !is_int($mb) || ValkeyConfig::parseMemory((string) $mb) === null) {
                throw new Refused("$path: invalid account entry");
            }
            $state->accounts[(string) $user] = ['enabled' => $entry['enabled'], 'memory_mb' => $mb];
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
        return $package !== null && isset($this->packages[$package]) ? $this->packages[$package]['memory_mb'] : null;
    }
}
