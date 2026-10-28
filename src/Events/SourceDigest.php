<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Cpanel\Discovery\HomePath;
use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * The source digest of a compiled configuration (ols_events.reconcile): sha256 of the canonical JSON of
 * {config, vhconf, epoch, files}, where files maps every certificate, key and password file the
 * configuration names to its sha256 (null when unreadable). OLS reads those files only when it loads the
 * configuration, so a renewed certificate or a changed password file needs an activation although the
 * compiled text is unchanged (RV-21). Canonical JSON is Python's `json.dumps(..., sort_keys=True)`, so the
 * digest equals the lab reconciler's for the same input.
 *
 * The files are digested through the engine, never read here (the reconciler may not read them), with the
 * engine.run allowlist's digest commands: `/usr/bin/sha256sum <path>` as root for certificates and keys under
 * /var/cpanel/ssl/, and `/usr/sbin/runuser -u <user> -- /usr/bin/sha256sum <path>` as the tenant for password
 * files under /home<suffix>/<user>/.htpasswds/ (HomePath). Any other path (or one that is not a normalized absolute path)
 * records null without running anything: fail-safe, since a later digest differs and forces a recompile.
 */
final class SourceDigest
{
    /**
     * Certificates and keys by extension or under /var/cpanel/ssl/; password files whatever their name
     * (review RV-29, finding 11): any `location` under a home's .htpasswds/ on any /home<suffix> mount
     * (HomePath), and the `location` of every realm userDB the .htaccess translator emits (AuthUserFile).
     */
    public const REFERENCED = '/^\s*(?:keyFile|certFile|location)\s+(\/\S+\.(?:pem|crt|key|combined)|\/var\/cpanel\/ssl\/\S+)\s*$|'
        . '^\s*location\s+(\/' . HomePath::MOUNT . '\/[^\/\s]+\/\.htpasswds\/\S+)\s*$|'
        . '^\s*userDB\s*\{\s*location\s+(\/\S+)\s*$/m';
    private const TIMEOUT = 30;
    private const USER = '[a-z0-9][a-z0-9_-]{0,31}';

    /**
     * @param array{config:string, vhconf:array<string,string>} $compiled
     * @param array<string,?string> $files
     */
    public static function source(array $compiled, int $epoch, array $files): string
    {
        return hash('sha256', '{"config": ' . self::string($compiled['config']) . ', "epoch": ' . $epoch
            . ', "files": ' . self::object($files) . ', "vhconf": ' . self::object($compiled['vhconf']) . '}');
    }

    /**
     * Paths of the files the configuration names (referenced_files of the lab), sorted.
     * @param array{config:string, vhconf:array<string,string>} $compiled
     * @return list<string>
     */
    public static function referencedPaths(array $compiled): array
    {
        $paths = [];
        foreach ([$compiled['config'], ...array_values($compiled['vhconf'])] as $text) {
            preg_match_all(self::REFERENCED, $text, $matches, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL);
            foreach ($matches as $match) {
                $paths[$match[1] ?? $match[2] ?? $match[3]] = true;
            }
        }
        $paths = array_map('strval', array_keys($paths));
        sort($paths, SORT_STRING);
        return $paths;
    }

    /**
     * @param array{config:string, vhconf:array<string,string>} $compiled
     * @return array<string,?string> path => sha256 (null when it cannot be read); the ModSecurity files of the
     *         summary are included with the digest of the text the compile read
     */
    public static function referencedFiles(array $compiled, CommandRunner $engine): array
    {
        $out = [];
        foreach (self::referencedPaths($compiled) as $path) {
            $out[$path] = self::digest($path, $engine);
        }
        // Every ModSecurity input the compile read (FV-02: modsec2.conf, rule files, data files), with the digest the
        // compile took of the text it read, so a vendor rule update changes the source digest and the plan digest.
        foreach (self::wafInputs($compiled) as $path => $sha256) {
            $out[$path] = $sha256;
        }
        return $out;
    }

    /**
     * @param array<string,mixed> $compiled
     * @return array<string,string> path => sha256 of the files in summary.waf.inputs
     */
    public static function wafInputs(array $compiled): array
    {
        $out = [];
        $inputs = $compiled['summary']['waf']['inputs'] ?? [];
        foreach (is_array($inputs) ? $inputs : [] as $input) {
            if (is_array($input) && is_string($input['path'] ?? null) && is_string($input['sha256'] ?? null)) {
                $out[$input['path']] = $input['sha256'];
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    public static function digest(string $path, CommandRunner $engine): ?string
    {
        if (!self::normalized($path)) {
            return null;
        }
        if (str_starts_with($path, '/var/cpanel/ssl/')) {
            $argv = ['/usr/bin/sha256sum', $path];
        } elseif (preg_match('#^/' . HomePath::MOUNT . '/(' . self::USER . ')/\.htpasswds/#D', $path, $m) && !in_array($m[1], ['root', 'nobody'], true)) {
            $argv = ['/usr/sbin/runuser', '-u', $m[1], '--', '/usr/bin/sha256sum', $path];
        } else {
            return null;
        }
        $read = $engine->run('referenced-digest', $argv, self::TIMEOUT);
        return $read['exit_code'] === 0 && preg_match('/^\\\\?([0-9a-f]{64}) /', $read['stdout'], $hex) ? $hex[1] : null;
    }

    private static function normalized(string $path): bool
    {
        return str_starts_with($path, '/') && !str_contains($path, '//') && !str_contains($path, "\0")
            && array_filter(explode('/', substr($path, 1)), static fn(string $part): bool => in_array($part, ['', '.', '..'], true)) === [];
    }

    /** @param array<string,mixed> $map a JSON object with sorted keys */
    private static function object(array $map): string
    {
        ksort($map, SORT_STRING);
        $items = [];
        foreach ($map as $key => $value) {
            $items[] = self::string((string) $key) . ': ' . ($value === null ? 'null' : self::string((string) $value));
        }
        return '{' . implode(', ', $items) . '}';
    }

    /** A JSON string as Python writes it (ASCII only, "/" unescaped). */
    private static function string(string $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
