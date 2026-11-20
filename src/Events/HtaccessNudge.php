<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

/**
 * The token of the tenant .htaccess watch (CMP-02): `ols-cpanel-htaccess-watch.service` (root, `ols-cpanel-broker
 * --htaccess-watch`) writes a new token to PATH about a second after a tenant .htaccess was created, written, renamed,
 * deleted or chmod-ed (debounced), and once when it starts. The service loop (Reconciler::watch) reads it every second and
 * runs a pass when it changed; the pass still decides by the input digest whether to compile (RV-48). The token says
 * nothing about which account or file changed. Absent, unreadable or malformed: null, and the loop keeps its periodic
 * passes only (the watch is unavailable or not installed).
 */
final class HtaccessNudge
{
    public const PATH = '/run/ols-cpanel-watch/htaccess.nudge';
    private const TOKEN = '/^[0-9]{1,40}-[0-9]{1,20} [0-9]{1,20}$/D';

    /** @return \Closure():?string the token reader for $path */
    public static function reader(string $path = self::PATH): \Closure
    {
        return static fn(): ?string => self::token($path);
    }

    public static function token(string $path = self::PATH): ?string
    {
        $text = @file_get_contents($path, false, null, 0, 128);
        if (!is_string($text)) {
            return null;
        }
        $text = rtrim($text, "\n");
        return preg_match(self::TOKEN, $text) === 1 ? $text : null;
    }
}
