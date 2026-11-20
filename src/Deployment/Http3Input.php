<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Ols\Compiler\CompilationRefused;

/**
 * The operator input for HTTP/3 (FV-04), /var/lib/ols-cpanel/http3.json (root, not writable by others):
 * `{"enabled": false}` turns HTTP/3 off (no QUIC listener, no Alt-Svc, no firewall change), for a server whose
 * UDP/443 is not reachable. Absent, or an object without "enabled", means enabled. Anything unreadable, oversized,
 * not a JSON object, with another key or a non-boolean value is refused, never ignored. CMP-07: the optional
 * `"off": ["example.com"]` lists domains whose vhost no longer advertises HTTP/3 (Alt-Svc); lower-case host names, at
 * most MAX_OFF, no duplicates (a stale name of a removed domain is harmless at compile time: it matches no vhost).
 * Port of build/vm-qualification/http3.py parse_settings and load_settings.
 */
final class Http3Input
{
    public const PATH = '/var/lib/ols-cpanel/http3.json';
    public const MAX_BYTES = 16384;
    /** CMP-07: at most this many domains in "off". */
    public const MAX_OFF = 256;
    private const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';

    /** @throws CompilationRefused */
    public static function load(string $path = self::PATH): bool
    {
        return self::settings($path)['enabled'];
    }

    /**
     * @return array{enabled:bool, off:list<string>}
     * @throws CompilationRefused
     */
    public static function settings(string $path = self::PATH): array
    {
        if (!file_exists($path) && !is_link($path)) {
            return ['enabled' => true, 'off' => []];
        }
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
            throw new CompilationRefused("http3 input $path is not a regular file");
        }
        $euid = function_exists('posix_geteuid') ? posix_geteuid() : 0;
        if (($stat['mode'] & 0022) !== 0 || !in_array($stat['uid'], [0, $euid], true)) {
            throw new CompilationRefused("http3 input $path must be owned by root and writable by no one else");
        }
        $text = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($text === false || strlen($text) > self::MAX_BYTES) {
            throw new CompilationRefused("http3 input $path is unreadable or larger than " . self::MAX_BYTES . ' bytes');
        }
        try {
            return self::parseSettings($text);
        } catch (\InvalidArgumentException $error) {
            throw new CompilationRefused($error->getMessage() . " ($path)", [], $error);
        }
    }

    /** @throws \InvalidArgumentException */
    public static function parse(string $text): bool
    {
        return self::parseSettings($text)['enabled'];
    }

    /**
     * @return array{enabled:bool, off:list<string>}
     * @throws \InvalidArgumentException
     */
    public static function parseSettings(string $text): array
    {
        try {
            $data = json_decode($text, false, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new \InvalidArgumentException('http3 input is not valid JSON: ' . $error->getMessage());
        }
        if (!$data instanceof \stdClass) {
            throw new \InvalidArgumentException('http3 input must be a JSON object');
        }
        $data = (array) $data;
        $unknown = array_diff(array_map('strval', array_keys($data)), ['enabled', 'off']);
        if ($unknown !== []) {
            sort($unknown, SORT_STRING);
            throw new \InvalidArgumentException('http3 input has unknown keys: ' . implode(', ', $unknown));
        }
        $enabled = array_key_exists('enabled', $data) ? $data['enabled'] : true;
        if (!is_bool($enabled)) {
            throw new \InvalidArgumentException('http3 input "enabled" must be true or false');
        }
        $off = array_key_exists('off', $data) ? $data['off'] : [];
        if (!is_array($off) || count($off) > self::MAX_OFF) {
            throw new \InvalidArgumentException('http3 input "off" must be a list of at most ' . self::MAX_OFF . ' domain names');
        }
        foreach ($off as $domain) {
            if (!is_string($domain) || strlen($domain) > 253 || preg_match(self::DOMAIN, $domain) !== 1) {
                throw new \InvalidArgumentException('http3 input "off" has an entry that is not a lower-case domain name');
            }
        }
        if (count(array_unique($off)) !== count($off)) {
            throw new \InvalidArgumentException('http3 input "off" lists a domain twice');
        }
        sort($off, SORT_STRING);
        return ['enabled' => $enabled, 'off' => $off];
    }

    /**
     * Writes the input (CMP-07: the per-domain switch of `ols-cpanel http3 on|off`), atomically (temporary file, rename), root
     * 0644, under an exclusive lock beside it, and returns the settings now in force. `$off` lists domains to add to the
     * off list, `$on` domains to remove from it (a name already in the wanted state changes nothing); a malformed current
     * file is never overwritten.
     * @param list<string> $off
     * @param list<string> $on
     * @return array{enabled:bool, off:list<string>, changed:bool}
     * @throws CompilationRefused
     */
    public static function change(array $off, array $on, string $path = self::PATH): array
    {
        $lock = @fopen($path . '.lock', 'cb');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new CompilationRefused("cannot lock the http3 input $path");
        }
        try {
            $current = self::settings($path);
            $list = array_values(array_diff(array_unique([...$current['off'], ...$off]), $on));
            sort($list, SORT_STRING);
            $changed = $list !== $current['off'];
            if ($changed) {
                $data = ($current['enabled'] ? [] : ['enabled' => false]) + ($list === [] ? [] : ['off' => $list]);
                $text = ($data === [] ? '{}' : json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)) . "\n";
                // Held to the reader's own rules before it is written (the list bound, the names).
                try {
                    self::parseSettings($text);
                } catch (\InvalidArgumentException $error) {
                    throw new CompilationRefused($error->getMessage(), [], $error);
                }
                if (strlen($text) > self::MAX_BYTES) {
                    throw new CompilationRefused('the http3 input would be larger than ' . self::MAX_BYTES . ' bytes');
                }
                $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
                $handle = @fopen($tmp, 'xb');
                if ($handle === false) {
                    throw new CompilationRefused("cannot write the http3 input $path");
                }
                @chmod($tmp, 0644);
                $ok = fwrite($handle, $text) === strlen($text);
                $ok = fclose($handle) && $ok;
                if (!$ok || !@rename($tmp, $path)) {
                    @unlink($tmp);
                    throw new CompilationRefused("cannot write the http3 input $path");
                }
            }
            return ['enabled' => $current['enabled'], 'off' => $list, 'changed' => $changed];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
