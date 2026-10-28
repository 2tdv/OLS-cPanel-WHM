<?php
declare(strict_types=1);

namespace OlsCpanel\PhpExtensions;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Events\HookEntry;

/**
 * An index of redis.so builds: `<root>/index.json` maps an EA4 PHP version to its `redis.so`, the SHA-256 of that
 * file and the PHP API number and extension build id it was compiled for. Two instances exist on a server: the
 * prebuilt builds of the ols-cpanel-php-redis package (written by build/php-ext/package.py; it also names the
 * pinned phpredis source tarball shipped in the package) and the local builds the installer compiled itself
 * (same schema, no source). A missing index means there is none; a malformed one is refused, never guessed at.
 */
final class ExtensionBundle
{
    public const ROOT = '/usr/local/ols-cpanel/php-ext/redis';
    public const EA_PHP = '/^ea-php[0-9]{2,3}$/D';

    /**
     * @param array<string,array{so:string, sha256:string, size:int, php_api:string, build_id:string, built_with:string}> $versions
     * @param array{file:string, sha256:string}|null $source phpredis source tarball (path relative to the root)
     */
    private function __construct(public readonly string $root, public readonly string $extensionVersion,
                                 public readonly array $versions, public readonly ?array $source)
    {
    }

    /** @param array<string,array{so:string, sha256:string, size:int, php_api:string, build_id:string, built_with:string}> $versions */
    public static function create(string $root, string $extensionVersion, array $versions = [], ?array $source = null): self
    {
        return new self($root, $extensionVersion, $versions, $source);
    }

    /** The index below $root, or null when there is none. @throws Refused when it is malformed */
    public static function load(string $root = self::ROOT): ?self
    {
        $path = "$root/index.json";
        if (!is_file($path)) {
            return null;
        }
        $text = @file_get_contents($path);
        $data = is_string($text) ? json_decode($text, true, 16) : null;
        if (!is_array($data) || ($data['schema_version'] ?? null) !== 1 || ($data['extension'] ?? null) !== 'redis'
            || !is_string($data['extension_version'] ?? null) || preg_match('/^[0-9]+(\.[0-9]+){1,3}$/D', $data['extension_version']) !== 1
            || !is_array($data['versions'] ?? null)) {
            throw new Refused("$path is malformed");
        }
        $source = null;
        if (isset($data['source'])) {
            $file = $data['source']['file'] ?? null;
            if (!is_array($data['source']) || $file !== 'src/phpredis-' . $data['extension_version'] . '.tgz'
                || !is_string($data['source']['sha256'] ?? null) || preg_match('/^[0-9a-f]{64}$/D', $data['source']['sha256']) !== 1) {
                throw new Refused("$path has a malformed source entry");
            }
            $source = ['file' => $file, 'sha256' => $data['source']['sha256']];
        }
        $versions = [];
        foreach ($data['versions'] as $name => $entry) {
            if (!is_string($name) || preg_match(self::EA_PHP, $name) !== 1 || !is_array($entry)
                || ($entry['so'] ?? null) !== "$root/$name/redis.so"
                || !is_string($entry['sha256'] ?? null) || preg_match('/^[0-9a-f]{64}$/D', $entry['sha256']) !== 1
                || !is_int($entry['size'] ?? null) || $entry['size'] < 1
                || !is_string($entry['php_api'] ?? null) || preg_match('/^[0-9]{8}$/D', $entry['php_api']) !== 1
                || !is_string($entry['build_id'] ?? null) || preg_match('/^API[0-9]{8},(NTS|ZTS)(,debug)?$/D', $entry['build_id']) !== 1
                || substr($entry['build_id'], 3, 8) !== $entry['php_api']
                || !is_string($entry['built_with'] ?? null) || preg_match('/^[0-9A-Za-z.+_-]{1,40}$/D', $entry['built_with']) !== 1) {
                throw new Refused("$path has a malformed entry for " . (is_string($name) ? substr($name, 0, 20) : 'a version'));
            }
            $versions[$name] = ['so' => $entry['so'], 'sha256' => $entry['sha256'], 'size' => $entry['size'],
                'php_api' => $entry['php_api'], 'build_id' => $entry['build_id'], 'built_with' => $entry['built_with']];
        }
        return new self($root, $data['extension_version'], $versions, $source);
    }

    /** @return array{so:string, sha256:string, size:int, php_api:string, build_id:string, built_with:string}|null */
    public function entry(string $php): ?array
    {
        return $this->versions[$php] ?? null;
    }

    /** Absolute path of the source tarball, or null. */
    public function sourcePath(): ?string
    {
        return $this->source === null ? null : "{$this->root}/{$this->source['file']}";
    }

    /** @param array{so:string, sha256:string, size:int, php_api:string, build_id:string, built_with:string} $entry */
    public function with(string $php, array $entry): self
    {
        return new self($this->root, $this->extensionVersion, [$php => $entry] + $this->versions, $this->source);
    }

    public function save(): void
    {
        if (!is_dir($this->root) && !@mkdir($this->root, 0755, true) && !is_dir($this->root)) {
            throw new Refused("cannot create {$this->root}");
        }
        $versions = $this->versions;
        ksort($versions, SORT_STRING);
        $data = ['schema_version' => 1, 'extension' => 'redis', 'extension_version' => $this->extensionVersion,
            'versions' => $versions] + ($this->source === null ? [] : ['source' => $this->source]);
        ksort($data, SORT_STRING);
        try {
            HookEntry::writeDurable("{$this->root}/index.json", json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", 0644);
        } catch (\RuntimeException $error) {
            throw new Refused($error->getMessage());
        }
    }
}
