<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\Filesystem;

/** Development-only reader of fixed, root-owned platform metadata; not a broker API. */
final class ObservationReader
{
    public const PATHS = [
        'os' => '/etc/os-release',
        'cpanel' => '/usr/local/cpanel/version',
        'monitor' => '/etc/chkserv.d/chkservd.conf',
    ];

    public function read(string $source): array
    {
        if (!isset(self::PATHS[$source])) {
            throw new \InvalidArgumentException('Unknown observation source');
        }
        $path = self::PATHS[$source];
        $base = ['source' => $path, 'observed_at' => gmdate('c'), 'value' => null];
        // /etc/os-release may be a distribution-owned symlink. No tenant paths are accepted.
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return $base + ['status' => 'unavailable'];
        }
        try {
            $before = fstat($handle);
            if ($before === false || ($before['mode'] & 0170000) !== 0100000
                || $before['uid'] !== 0 || ($before['mode'] & 0022) !== 0
                || $before['size'] > 65536) {
                return $base + ['status' => 'unsafe_source'];
            }
            $data = stream_get_contents($handle, 65537);
            $after = fstat($handle);
            clearstatcache(true, $path);
            $current = @stat($path);
            if ($data === false || strlen($data) > 65536) {
                return $base + ['status' => 'unavailable'];
            }
            foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $key) {
                if ($after === false || $current === false || $before[$key] !== $after[$key]
                    || $before[$key] !== $current[$key]) {
                    return $base + ['status' => 'changed'];
                }
            }
            // A second read detects same-size writes within coarse timestamp resolution.
            rewind($handle);
            if (stream_get_contents($handle, 65537) !== $data) {
                return $base + ['status' => 'changed'];
            }
            $base['value'] = $data;
            return $base + ['status' => 'observed', 'sha256' => hash('sha256', $data)];
        } finally {
            fclose($handle);
        }
    }
}
