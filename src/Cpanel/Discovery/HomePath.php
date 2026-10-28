<?php
declare(strict_types=1);

namespace OlsCpanel\Cpanel\Discovery;

/**
 * The product's one home-directory policy (review RV-29, finding 11), shared by account discovery, the
 * compiler (vhRoot, which ancestors are read as the tenant), the source digest (which password files are
 * digested) and, by the same written rule, the broker's engine.run allowlist (docs/product-interfaces.md):
 *
 *     an account's home is /<mount>/<user>, where <mount> is "home" followed by [A-Za-z0-9_-]* (one path
 *     component directly below "/": /home, /home2, /home3, /home_ssd, /home-b) and <user> is the account.
 *
 * cPanel places homes under HOMEDIR (default /home) and on every mount point matching HOMEMATCH (default
 * "home": /home2, /home3, ... are created that way, the most free space wins). cPanel's matching is broader
 * (a mount such as /newhome, /usr/home or a HOMEDIR of /data also qualifies); the product supports the
 * /home<suffix> mounts only and refuses any other location (an "unsafe document root"), so it never guesses
 * which directories above a home are root's. A dot is not part of the suffix (/home.old stays refused).
 * Byte-equivalent to HOME_MOUNT and account_home in build/vm-qualification/cpanel_vhosts.py.
 */
final class HomePath
{
    /** One path component: the home mount (anchored use: '/^' . MOUNT . '$/D'). */
    public const MOUNT = 'home[A-Za-z0-9_-]*';

    /** Whether $component (no slashes) names a home mount. */
    public static function isMount(string $component): bool
    {
        return preg_match('/^' . self::MOUNT . '$/D', $component) === 1;
    }

    /**
     * The home directory of $user that $path lies in (whole path components; $path itself may be the home),
     * or null: "/home2/olscpa/public_html" for olscpa gives "/home2/olscpa"; "/home/olscpab" is not olscpa's.
     */
    public static function homeOf(string $path, string $user): ?string
    {
        $parts = explode('/', $path, 4);
        if (count($parts) < 3 || $parts[0] !== '' || !self::isMount($parts[1]) || $parts[2] !== $user || $user === '') {
            return null;
        }
        return "/{$parts[1]}/$user";
    }
}
