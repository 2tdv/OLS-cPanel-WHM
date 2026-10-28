<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The deployment profile (/var/lib/ols-cpanel/profile.json), written at cutover and removed on the
 * return to Apache: production listeners, and Apache's backend ports when the hybrid profile is on.
 * Absent means not cut over; anything malformed is refused (port of ols_events.load_profile).
 */
final class Profile
{
    public const PATH = '/var/lib/ols-cpanel/profile.json';

    /** @param array{0:int,1:int}|null $hybridPorts */
    public function __construct(public readonly bool $production, public readonly ?array $hybridPorts)
    {
        if ($hybridPorts !== null && !self::validPorts($hybridPorts)) {
            throw new \InvalidArgumentException('hybrid ports must be two backend ports other than 80 and 443');
        }
    }

    /** The profile on disk, or null when the server is not cut over. */
    public static function load(string $path = self::PATH): ?self
    {
        if (!file_exists($path)) {
            return null;
        }
        $text = @file_get_contents($path, false, null, 0, 4097);
        if ($text === false || strlen($text) > 4096) {
            throw new \RuntimeException("unreadable deployment profile $path");
        }
        try {
            $data = json_decode($text, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \RuntimeException("malformed deployment profile $path");
        }
        if (!is_array($data) || array_is_list($data) || array_keys($data) != ['production', 'hybrid_ports']
            && array_keys($data) != ['hybrid_ports', 'production'] || !is_bool($data['production'])
            || !($data['hybrid_ports'] === null || is_array($data['hybrid_ports']) && self::validPorts($data['hybrid_ports']))) {
            throw new \RuntimeException("malformed deployment profile $path");
        }
        return new self($data['production'], $data['hybrid_ports'] === null ? null : array_values($data['hybrid_ports']));
    }

    public function toJson(): string
    {
        return json_encode(['production' => $this->production, 'hybrid_ports' => $this->hybridPorts], JSON_THROW_ON_ERROR) . "\n";
    }

    /** Written atomically (temporary file, fsync, rename), root-owned 0644. */
    public function save(string $path = self::PATH): void
    {
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $handle = fopen($tmp, 'x');
        if ($handle === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        try {
            if (fwrite($handle, $this->toJson()) === false || !fflush($handle) || !fsync($handle)) {
                throw new \RuntimeException("cannot write $tmp");
            }
        } finally {
            fclose($handle);
        }
        if (!chmod($tmp, 0644) || !rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot install $path");
        }
    }

    /** @param array<mixed> $ports */
    private static function validPorts(array $ports): bool
    {
        return array_is_list($ports) && count($ports) === 2 && $ports[0] !== $ports[1] && array_filter($ports,
            static fn(mixed $p): bool => !is_int($p) || $p < 1 || $p > 65535 || in_array($p, [80, 443], true)) === [];
    }
}
