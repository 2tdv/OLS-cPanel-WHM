<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Cache;

/**
 * Size limits of the automatic LSCache cleanup (FV-01): `<state>/cache-limits.json`, an optional root-owned operator input
 * {"per_site_mb": int, "server_percent": int, "server_max_gb": int}. Missing keys keep their default; anything else that is not
 * valid (unreadable, not an object, unknown key, not an integer, outside the bounds) is a problem: the defaults are used and the
 * problem is reported, never a crash, so a damaged file can neither stop the cleanup nor remove the protection.
 *
 * per_site_mb: most one site's store may hold. The server-wide cap is server_percent of the filesystem that holds the cache, at
 * most server_max_gb.
 */
final class CacheLimits
{
    public const FILE = 'cache-limits.json';
    public const DEFAULTS = ['per_site_mb' => 512, 'server_percent' => 10, 'server_max_gb' => 20];
    /** Inclusive bounds per key. */
    public const BOUNDS = ['per_site_mb' => [16, 102400], 'server_percent' => [1, 50], 'server_max_gb' => [1, 2048]];
    private const MAX_SIZE = 4096;

    public function __construct(private readonly string $state)
    {
    }

    /** @return array{limits:array<string,int>, problem:?string, from_file:bool} */
    public function load(): array
    {
        $path = $this->path();
        $info = @lstat($path);
        if ($info === false) {
            return ['limits' => self::DEFAULTS, 'problem' => null, 'from_file' => false];
        }
        if (($info['mode'] & 0170000) !== 0100000 || $info['size'] > self::MAX_SIZE) {
            return $this->bad('is not a regular file of at most ' . self::MAX_SIZE . ' bytes');
        }
        $text = @file_get_contents($path);
        if (!is_string($text)) {
            return $this->bad('cannot be read');
        }
        try {
            $data = json_decode($text, false, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->bad('is not valid JSON');
        }
        if (!$data instanceof \stdClass) {
            return $this->bad('must be a JSON object');
        }
        $checked = self::validate((array) $data);
        return is_string($checked) ? $this->bad($checked) : ['limits' => $checked, 'problem' => null, 'from_file' => true];
    }

    /** @return string|array<string,int> the complete limits (defaults for missing keys) or the reason the input is refused */
    public static function validate(mixed $data): string|array
    {
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            return 'must be a JSON object';
        }
        $out = self::DEFAULTS;
        foreach ($data as $key => $value) {
            if (!is_string($key) || !isset(self::BOUNDS[$key])) {
                return 'has an unknown setting ' . (is_string($key) ? "\"$key\"" : '(not a name)');
            }
            if (!is_int($value)) {
                return "$key must be a whole number";
            }
            [$min, $max] = self::BOUNDS[$key];
            if ($value < $min || $value > $max) {
                return "$key must be between $min and $max";
            }
            $out[$key] = $value;
        }
        return $out;
    }

    /**
     * Writes the limits atomically (root 0600). Only the keys given change; the others keep their current value.
     * @param array<string,mixed> $change
     * @return array<string,int> the limits now in force
     * @throws \InvalidArgumentException a value outside the bounds
     */
    public function save(array $change): array
    {
        $checked = self::validate($change);
        if (is_string($checked)) {
            throw new \InvalidArgumentException("cache limits: $checked");
        }
        $merged = array_merge($this->load()['limits'], array_intersect_key($checked, $change));
        if (!is_dir($this->state)) {
            throw new \InvalidArgumentException("{$this->state} is not a directory");
        }
        $path = $this->path();
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
        $handle = @fopen($tmp, 'xb');
        if ($handle === false) {
            throw new \RuntimeException('cannot write the cache limits');
        }
        @chmod($tmp, 0600);
        $ok = fwrite($handle, json_encode($merged, JSON_THROW_ON_ERROR) . "\n") !== false;
        $ok = fclose($handle) && $ok;
        if (!$ok || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write the cache limits');
        }
        return $merged;
    }

    private function path(): string
    {
        return $this->state . '/' . self::FILE;
    }

    /** @return array{limits:array<string,int>, problem:string, from_file:bool} */
    private function bad(string $reason): array
    {
        return ['limits' => self::DEFAULTS, 'problem' => $this->path() . " $reason: the defaults are in force", 'from_file' => false];
    }
}
