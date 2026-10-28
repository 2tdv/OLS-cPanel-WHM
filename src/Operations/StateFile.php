<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

/**
 * Root-only JSON state files of the operations features (notify.json, schedule.json, the ledgers): bounded reads that never follow
 * a link at the last component, atomic writes (temporary file, fsync, rename) with mode 0600.
 */
final class StateFile
{
    public const MAX_BYTES = 1 << 20;

    /** @return array<string,mixed>|null the object, or null when the file is absent, not a regular file, too large or not a JSON object */
    public static function read(string $path): ?array
    {
        if (is_link($path) || !is_file($path) || (int) @filesize($path) > self::MAX_BYTES) {
            return null;
        }
        $text = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        $data = is_string($text) ? json_decode($text, true, 16) : null;
        return is_array($data) && ($data === [] || !array_is_list($data)) ? $data : null;
    }

    /** @param array<string,mixed> $data */
    public static function write(string $path, array $data): void
    {
        if (is_link($path)) {
            throw new \RuntimeException('refusing to write through a link');
        }
        $text = json_encode($data === [] ? new \stdClass() : $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $handle = @fopen($tmp, 'xb');
        if ($handle === false) {
            throw new \RuntimeException('cannot write ' . basename($path));
        }
        @chmod($tmp, 0600);
        $ok = fwrite($handle, $text) === strlen($text) && fflush($handle) && (!function_exists('fsync') || fsync($handle));
        fclose($handle);
        if (!$ok || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . basename($path));
        }
    }

    /** Printable ASCII only and bounded: nothing a log line or a message header could be forged with. */
    public static function clean(mixed $value, int $max = 200): string
    {
        return substr(preg_replace('/[^\x20-\x7e]/', '?', is_scalar($value) ? (string) $value : '') ?? '', 0, $max);
    }
}
