<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Ols\Compiler\CompilationRefused;

/**
 * The operator input for HTTP/3 (FV-04), /var/lib/ols-cpanel/http3.json (root, not writable by others):
 * `{"enabled": false}` turns HTTP/3 off (no QUIC listener, no Alt-Svc, no firewall change), for a server whose
 * UDP/443 is not reachable. Absent, or an object without "enabled", means enabled. Anything unreadable, oversized,
 * not a JSON object, with another key or a non-boolean value is refused, never ignored. Port of
 * build/vm-qualification/http3.py parse_input and load_input.
 */
final class Http3Input
{
    public const PATH = '/var/lib/ols-cpanel/http3.json';
    public const MAX_BYTES = 4096;

    /** @throws CompilationRefused */
    public static function load(string $path = self::PATH): bool
    {
        if (!file_exists($path) && !is_link($path)) {
            return true;
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
            return self::parse($text);
        } catch (\InvalidArgumentException $error) {
            throw new CompilationRefused($error->getMessage() . " ($path)", [], $error);
        }
    }

    /** @throws \InvalidArgumentException */
    public static function parse(string $text): bool
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
        $unknown = array_diff(array_map('strval', array_keys($data)), ['enabled']);
        if ($unknown !== []) {
            sort($unknown, SORT_STRING);
            throw new \InvalidArgumentException('http3 input has unknown keys: ' . implode(', ', $unknown));
        }
        $enabled = array_key_exists('enabled', $data) ? $data['enabled'] : true;
        if (!is_bool($enabled)) {
            throw new \InvalidArgumentException('http3 input "enabled" must be true or false');
        }
        return $enabled;
    }
}
