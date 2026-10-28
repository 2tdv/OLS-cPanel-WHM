<?php
declare(strict_types=1);

namespace OlsCpanel\PhpExtensions;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Events\HookEntry;

/**
 * `/var/lib/ols-cpanel/php-ext/state.json`: whether the operator wants the extension kept active (set by
 * `php-ext install` and by the object cache commands, cleared by `php-ext remove`; the watcher does nothing
 * while it is false) and, per EA4 PHP version, the last failed activation with its time, attempt count and
 * reason so a failure is reported until it is fixed and retried with a back-off.
 */
final class ExtensionState
{
    /**
     * @param array<string,array{at:int, attempts:int, error:string}> $failures
     * @param array<string,string> $artifacts per version: the SHA-256 of the redis.so whose restart obligation was recorded ("unregistered" while it could not be)
     */
    public function __construct(public bool $wanted = false, public array $failures = [], public array $artifacts = [])
    {
    }

    /** @throws Refused when the file exists but is malformed (never replaced) */
    public static function load(string $path): self
    {
        if (!is_file($path)) {
            return new self();
        }
        $data = json_decode((string) @file_get_contents($path), true, 8);
        if (!is_array($data) || ($data['schema_version'] ?? null) !== 1 || !is_bool($data['wanted'] ?? null) || !is_array($data['failures'] ?? null)) {
            throw new Refused("$path is malformed; fix or remove it");
        }
        $failures = [];
        foreach ($data['failures'] as $php => $failure) {
            if (!is_string($php) || preg_match(ExtensionBundle::EA_PHP, $php) !== 1 || !is_array($failure)
                || !is_int($failure['at'] ?? null) || !is_int($failure['attempts'] ?? null) || !is_string($failure['error'] ?? null)) {
                throw new Refused("$path has a malformed failure entry");
            }
            $failures[$php] = ['at' => $failure['at'], 'attempts' => $failure['attempts'], 'error' => $failure['error']];
        }
        $artifacts = [];
        foreach (is_array($data['artifacts'] ?? null) ? $data['artifacts'] : [] as $php => $sha) {
            if (is_string($php) && preg_match(ExtensionBundle::EA_PHP, $php) === 1 && is_string($sha) && preg_match('/^([0-9a-f]{64}|unregistered)$/D', $sha) === 1) {
                $artifacts[$php] = $sha;
            }
        }
        return new self($data['wanted'], $failures, $artifacts);
    }

    public function save(string $path): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new Refused("cannot create $dir");
        }
        ksort($this->failures, SORT_STRING);
        ksort($this->artifacts, SORT_STRING);
        try {
            HookEntry::writeDurable($path, json_encode(['schema_version' => 1, 'wanted' => $this->wanted, 'failures' => (object) $this->failures,
                'artifacts' => (object) $this->artifacts],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", 0644);
        } catch (\RuntimeException $error) {
            throw new Refused($error->getMessage());
        }
    }
}
