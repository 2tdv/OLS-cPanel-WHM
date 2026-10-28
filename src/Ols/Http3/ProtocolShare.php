<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Http3;

/**
 * The protocol share per vhost (FV-04): HTTP/1.x, HTTP/2 and HTTP/3 requests among the last lines of a vhost's access
 * logs. The product's access log format (CpanelSurface::ACCESS_FORMAT) puts the request line in quotes, and OLS ends
 * it in HTTP/1.0, HTTP/1.1, HTTP/2 or HTTP/3 (its AccessLog fixHttpVer). The logs read are cPanel's domlogs the log
 * shipper fills: "<domain>" (HTTP) and "<domain>-ssl_log" (HTTPS); HTTP/3 only ever appears in the second. Reading is
 * bounded (the last `count` lines, at most `maxBytes` from the end of each file, lines over LINE_MAX are not parsed)
 * and never follows a symlink. Port of build/vm-qualification/http3.py (tests/http3.py compares them).
 */
final class ProtocolShare
{
    public const DOMLOGS = '/etc/apache2/logs/domlogs';
    public const DOMAIN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/D';
    public const LINES = 2000;
    public const MAX_BYTES = 4194304;
    public const LINE_MAX = 8192;
    public const CLASSES = ['h1', 'h2', 'h3', 'other', 'unparsed'];
    /** Optional "<domain>:<port> " prefix (before cPanel's splitlogs), then `%a %l %u [%t] "%r" %>s `. */
    private const LINE = '/^(?:\S+:\d+ )?\S+ \S+ \S+ \[[^\]]+\] "([^"\\\\]*(?:\\\\.[^"\\\\]*)*)" \d{3} /';

    /** h1 (HTTP/1.0 and 1.1), h2, h3, other (another or no version in the request line) or unparsed. */
    public static function classify(string $line): string
    {
        if (strlen($line) > self::LINE_MAX || preg_match(self::LINE, $line, $match) !== 1) {
            return 'unparsed';
        }
        $words = explode(' ', $match[1]);
        $version = count($words) >= 2 ? $words[count($words) - 1] : '';
        return match ($version) {
            'HTTP/1.1', 'HTTP/1.0' => 'h1',
            'HTTP/2' => 'h2',
            'HTTP/3' => 'h3',
            default => 'other',
        };
    }

    /**
     * The last `$count` complete lines of a regular file, reading at most `$maxBytes` from its end; [] when absent
     * or not a regular file (never through a symlink).
     * @return list<string>
     */
    public static function tailLines(string $path, int $count = self::LINES, int $maxBytes = self::MAX_BYTES): array
    {
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
            return [];
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return [];
        }
        try {
            $size = (int) $stat['size'];
            $start = max(0, $size - $maxBytes);
            if (fseek($handle, $start) !== 0) {
                return [];
            }
            $data = '';
            while (strlen($data) < $size - $start) {
                $chunk = fread($handle, min(1 << 20, $size - $start - strlen($data)));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $data .= $chunk;
            }
        } finally {
            fclose($handle);
        }
        $lines = explode("\n", $data);
        if ($start > 0) {
            array_shift($lines);  // the first line may be cut
        }
        if ($lines !== [] && $lines[count($lines) - 1] === '') {
            array_pop($lines);
        }
        return array_slice($lines, -$count);
    }

    /** part/total in basis points, rounded half up, in integers. */
    public static function basisPoints(int $part, int $total): int
    {
        return $total === 0 ? 0 : intdiv($part * 20000 + $total, 2 * $total);
    }

    /**
     * The protocol share of one vhost from the last lines of its plain and its -ssl_log domlog.
     * @return array<string,mixed>
     */
    public static function vhost(string $logDir, string $domain, int $count = self::LINES, int $maxBytes = self::MAX_BYTES): array
    {
        if (!preg_match(self::DOMAIN, $domain)) {
            throw new \InvalidArgumentException("invalid domain '$domain'");
        }
        $counts = array_fill_keys(self::CLASSES, 0);
        $sources = [];
        foreach (['', '-ssl_log'] as $suffix) {
            $lines = self::tailLines("$logDir/$domain$suffix", $count, $maxBytes);
            if ($lines !== []) {
                $sources[] = $domain . $suffix;
            }
            foreach ($lines as $line) {
                ++$counts[self::classify($line)];
            }
        }
        $parsed = $counts['h1'] + $counts['h2'] + $counts['h3'] + $counts['other'];
        return ['vhost' => $domain, 'lines' => $parsed + $counts['unparsed']] + $counts + ['sources' => $sources,
            'share_bp' => ['h1' => self::basisPoints($counts['h1'], $parsed), 'h2' => self::basisPoints($counts['h2'], $parsed),
                'h3' => self::basisPoints($counts['h3'], $parsed)]];
    }

    /**
     * The share of each domain, sorted by name.
     * @param list<string> $domains
     * @return list<array<string,mixed>>
     */
    public static function shares(string $logDir, array $domains, int $count = self::LINES, int $maxBytes = self::MAX_BYTES): array
    {
        $domains = array_values(array_unique($domains));
        sort($domains, SORT_STRING);
        return array_map(static fn(string $domain): array => self::vhost($logDir, $domain, $count, $maxBytes), $domains);
    }
}
