<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The recommended EasyApache 4 profile (FV-10): `/etc/cpanel/ea4/profiles/custom/ols-cpanel-recommended.json`, the
 * directory cPanel reads for site-specific profiles, so EasyApache 4's own interface lists it and provisions it
 * (the product never installs a profile itself). Written by `install --prepare`, refreshed by `upgrade` and the
 * PHP environment pass, removed by `uninstall`.
 *
 * Generation, not a fixed list: the packages come from cPanel's own "cPanel Default" profile on the server
 * (`profiles/cpanel/default.json`: the Apache 2.4 base modules and the default PHP extension set), so the profile
 * follows what cPanel recommends. For every PHP version of PHP_VERSIONS that EasyApache offers it carries that
 * extension set plus `-php-litespeed` (lsphp, which OLS runs) and `-php-opcache` (a version whose opcache is part
 * of PHP itself, PHP 8.5, has no such package). Packages the server's EasyApache repository does not offer
 * (read from `profiles/pkg-manifest.json` for the server's OS) are left out. No ea-nginx. Without the cPanel
 * default profile the built-in lists below are used. The schema is cPanel's own (name, desc, version, tags, pkgs).
 */
final class Ea4Profile
{
    public const ROOT = '/etc/cpanel/ea4/profiles';
    public const FILE = 'ols-cpanel-recommended.json';
    public const NAME = 'OLS-cPanel (OpenLiteSpeed) Recommended';
    public const VERSION = 1.0;
    /** PHP versions the profile covers, as EasyApache numbers them; those the repository lacks are skipped. */
    public const PHP_VERSIONS = ['81', '82', '83', '84', '85'];
    /** Packages that never belong in the profile (the product replaces what they do, or they conflict with it). */
    public const EXCLUDED = ['ea-nginx'];
    /** First version whose OPcache is part of PHP itself (no separate package). */
    public const OPCACHE_BUILT_IN_FROM = 85;
    /** Apache 2.4 base of "cPanel Default" (EA4 repository, cPanel 11.138), used without the server's profile. */
    public const BASE = ['ea-apache24', 'ea-apr', 'ea-apr-util', 'ea-apache24-mod_mpm_prefork', 'ea-apache24-mod_ruid2', 'ea-apache24-mod_ssl',
        'ea-apache24-mod_deflate', 'ea-apache24-mod_expires', 'ea-apache24-mod_headers', 'ea-apache24-mod_proxy', 'ea-apache24-mod_proxy_fcgi',
        'ea-apache24-mod_cgi', 'ea-apache24-mod_unique_id', 'ea-apache24-mod_security2'];
    /** The default PHP extension set of "cPanel Default", as package suffixes after `ea-phpNN`. */
    public const EXTENSIONS = ['-php-bcmath', '-php-calendar', '-php-curl', '-php-ftp', '-php-gd', '-php-iconv', '-php-imap', '-php-mbstring',
        '-php-mysqlnd', '-php-pdo', '-php-posix', '-php-sockets', '-php-xml', '-runtime', '-php-fpm', '-php-zip'];

    public function __construct(private readonly string $root = self::ROOT, private readonly string $osRelease = '/etc/os-release')
    {
    }

    public function path(): string
    {
        return "{$this->root}/custom/" . self::FILE;
    }

    /**
     * The profile for the given inputs (pure).
     * @param array<string,mixed>|null $default cPanel's "cPanel Default" profile (decoded), or null for the built-in lists
     * @param list<string>|null $available every package the EasyApache repository offers for this OS, or null (no filtering)
     * @return array{name:string, desc:string, version:float, tags:list<string>, pkgs:list<string>}
     */
    public static function build(?array $default, ?array $available): array
    {
        $listed = is_array($default['pkgs'] ?? null) ? array_values(array_filter($default['pkgs'], 'is_string')) : [];
        $base = [];
        $extensions = [];
        foreach ($listed as $package) {
            if (preg_match('/^ea-php[0-9]{2,3}(.*)$/D', $package, $match) === 1) {
                if ($match[1] !== '') {
                    $extensions[$match[1]] = true;  // the set is taken from every version cPanel lists; the same for all of them
                }
            } elseif (!in_array($package, self::EXCLUDED, true)) {
                $base[] = $package;
            }
        }
        $base = $base === [] ? self::BASE : $base;
        $suffixes = $extensions === [] ? self::EXTENSIONS : array_keys($extensions);
        $offered = $available === null ? null : array_flip($available);
        $has = static fn(string $package): bool => $offered === null || isset($offered[$package]);
        $pkgs = array_values(array_filter(array_unique($base), $has));
        $tags = ['Apache 2.4'];
        foreach (self::PHP_VERSIONS as $digits) {
            $php = "ea-php$digits";
            // The version exists in the repository (the metapackage); without a manifest every version is assumed.
            if (!$has($php)) {
                continue;
            }
            $wanted = [$php];
            foreach ($suffixes as $suffix) {
                $wanted[] = $php . $suffix;
            }
            $wanted[] = "$php-php-litespeed";
            if ((int) $digits < self::OPCACHE_BUILT_IN_FROM || ($offered !== null && isset($offered["$php-php-opcache"]))) {
                $wanted[] = "$php-php-opcache";
            }
            foreach ($wanted as $package) {
                if ($has($package) && !in_array($package, self::EXCLUDED, true)) {
                    $pkgs[] = $package;
                }
            }
            $tags[] = 'PHP ' . substr($digits, 0, -1) . '.' . substr($digits, -1);
        }
        $tags[] = 'OpenLiteSpeed';
        return ['name' => self::NAME,
            'desc' => 'Apache 2.4 and the PHP versions cPanel offers, each with the default cPanel extensions plus LiteSpeed PHP (lsphp) and OPcache, '
                . 'as the OLS-cPanel product needs them to serve every site with OpenLiteSpeed. Provisioning it keeps OLS-cPanel complete; '
                . 'it contains no NGINX.',
            'version' => self::VERSION, 'tags' => $tags, 'pkgs' => array_values(array_unique($pkgs))];
    }

    /**
     * Generates the profile from this server and writes it when it differs (atomic, 0644, directory 0755).
     * @return array{result:string, path:string, packages:int, php:list<string>}
     * @throws DeploymentError when the file cannot be written
     */
    public function write(): array
    {
        $os = [];
        foreach (explode("\n", (string) @file_get_contents($this->osRelease, false, null, 0, 65536)) as $line) {
            if (preg_match('/^(ID|VERSION_ID)="?([A-Za-z0-9._-]*)"?$/D', rtrim($line), $match) === 1) {
                $os[$match[1]] = $match[2];
            }
        }
        $profile = self::build($this->readJson("{$this->root}/cpanel/default.json"),
            self::available($this->readJson("{$this->root}/pkg-manifest.json"), $os['ID'] ?? '', $os['VERSION_ID'] ?? ''));
        $text = Environment::json($profile);
        $path = $this->path();
        $php = array_values(array_filter($profile['tags'], static fn(string $t): bool => str_starts_with($t, 'PHP ')));
        $report = ['path' => $path, 'packages' => count($profile['pkgs']), 'php' => $php];
        if (!is_link($path) && @file_get_contents($path) === $text) {
            return ['result' => 'unchanged'] + $report;
        }
        if (is_link($path)) {
            @unlink($path);
        }
        Environment::ensureDir(dirname($path), 0755);
        Environment::writeFile($path, $text, 0644);
        return ['result' => 'written'] + $report;
    }

    /** Removes the profile; only the file of this name, only when it is ours. @return array{result:string, path:string} */
    public function remove(): array
    {
        $path = $this->path();
        if (!is_file($path) && !is_link($path)) {
            return ['result' => 'absent', 'path' => $path];
        }
        $own = is_file($path) && !is_link($path) && (json_decode((string) @file_get_contents($path), true, 8)['name'] ?? null) === self::NAME;
        if (!$own && !is_link($path)) {
            return ['result' => 'foreign', 'path' => $path];
        }
        return ['result' => @unlink($path) ? 'removed' : 'failed', 'path' => $path];
    }

    public function present(): bool
    {
        return is_file($this->path()) && !is_link($this->path());
    }

    /**
     * The packages EasyApache offers for an OS, from `pkg-manifest.json` (sections EA4, by the names cPanel uses
     * for its OS builds: `CentOS_9` is also AlmaLinux, Rocky and CloudLinux 9); null when it cannot tell.
     * @param array<string,mixed>|null $manifest
     * @return list<string>|null
     */
    public static function available(?array $manifest, string $osId, string $osVersion): ?array
    {
        $sections = is_array($manifest['EA4'] ?? null) ? $manifest['EA4'] : null;
        $major = explode('.', $osVersion)[0];
        if ($sections === null || preg_match('/^[0-9]{1,2}$/D', $major) !== 1) {
            return null;
        }
        $keys = in_array(strtolower($osId), ['almalinux', 'rocky', 'cloudlinux', 'centos', 'rhel'], true)
            ? ["CentOS_$major", ucfirst(strtolower($osId)) . "_$major", "Almalinux_$major"] : [];
        foreach ($keys as $key) {
            if (is_array($sections[$key] ?? null)) {
                return array_values(array_filter($sections[$key], 'is_string'));
            }
        }
        return null;
    }

    /** @return array<string,mixed>|null */
    private function readJson(string $path): ?array
    {
        if (!is_file($path) || is_link($path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($path, false, null, 0, 16 * 1024 * 1024), true, 16);
        return is_array($data) ? $data : null;
    }
}
