<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Cpanel\Discovery\HomePath;
use OlsCpanel\Deployment\BuilderCompilation;
use OlsCpanel\Deployment\Http3Input;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Deployment\SecurityInput;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Php\PhpDemand;
use OlsCpanel\Php\PhpLimits;

/**
 * The cheap digest of everything a compile reads (RV-48), taken before the compile so that a pass whose inputs did not
 * change can skip it: a compile costs about 5 s of CPU with 25 accounts even when its result is "unchanged", while the
 * digest below is metadata only (type, inode, size, mtime and ctime of each file; one `find` per document root, no file
 * is read) plus a few small product files.
 *
 * What it covers, and the compile input it stands for:
 *  - the deployment profile (hybrid ports) and the restriction epoch;
 *  - the product inputs: the server template, security.json, php-limits.json, http3.json (type, owner, size, mtime and a
 *    hash of the text) and the automatic PHP limits of php-demand.json (the effective values, not the file, which
 *    its scanner rewrites every pass: PhpDemand);
 *  - cPanel's state: /etc/userdatadomains and /etc/trueuserdomains (accounts, main domains, document roots),
 *    /var/cpanel/users, every file of /var/cpanel/userdata (vhosts, aliases, PHP versions, handlers, php-fpm.yaml),
 *    /var/cpanel/suspended, the certificates under /var/cpanel/ssl/apache_tls, /etc/cpanel/ea4/php.conf (the PHP
 *    handlers), Apache's httpd.conf and conf.modules.d (the loaded modules decide every <IfModule>) and cPanel's
 *    ModSecurity files (modsec2.conf, modsec/, modsec_vendor_configs/);
 *  - the EasyApache PHP trees: every php-fpm.d pool, the PHP binary the E_* constants come from and lsphp;
 *  - the tenants' .htaccess files: path, type, inode, size, mtime and ctime of every .htaccess below each document root
 *    of every account, and of the ancestors of a document root inside the home (read as the tenant, like the compile);
 *    ctime catches a chmod that makes a file unreadable and readable again without changing its mtime (the Drupal Twig
 *    rebuild of RV-48: the Reconciler also compiles the pass after one that met an unreadable file);
 *  - the bound global IPv6 addresses (`ip -6 -o addr show scope global`).
 *
 * Not covered, and left to the forced compile every Reconciler::FULL_COMPILE_SECONDS: the root-owned .htaccess files above
 * the homes ("/", "/home"), the existence of the global alias directories (cgi-bin and the like), the content of a
 * tenant .htaccess that changed without touching its mtime and ctime (impossible without root), and the files a
 * configuration references (certificates keys and password files are digested after the compile as before: SourceDigest).
 *
 * Fail safe: anything that cannot be listed, parsed or stat'ed makes the digest unavailable (InputsUnsure) and the caller
 * compiles. The only tolerated failure is a root that does not exist ("No such file or directory": ModSecurity is
 * optional); its absence is part of the digest, so it appearing changes it.
 */
final class InputDigest
{
    private const TIMEOUT = 60;
    private const FIND = '/usr/bin/find';
    private const RUNUSER = '/usr/sbin/runuser';
    private const STAT = '%y %i %s %T@ %C@ %p\\0';
    /** Fixed argv of the engine.run allowlist rule find-stat-cpanel. */
    public const CPANEL_ROOTS = ['/etc/userdatadomains', '/etc/trueuserdomains', '/var/cpanel/users', '/var/cpanel/userdata',
        '/var/cpanel/suspended', '/var/cpanel/ssl/apache_tls', '/etc/cpanel/ea4/php.conf', '/etc/apache2/conf/httpd.conf',
        '/etc/apache2/conf.modules.d', '/etc/apache2/conf.d/modsec2.conf', '/etc/apache2/conf.d/modsec', '/etc/apache2/conf.d/modsec_vendor_configs'];
    private const USER = '/^[a-z0-9][a-z0-9_-]{0,31}$/D';

    /**
     * @param list<string> $productFiles product input files by path (default: what BuilderCompilation reads)
     * @param string|null $demandPath the automatic PHP limits (default: beside the limits file)
     */
    public function __construct(private readonly CommandRunner $engine, private readonly array $productFiles = [],
                                private readonly ?string $demandPath = null)
    {
    }

    /** @return list<string> */
    public static function defaultProductFiles(): array
    {
        return [BuilderCompilation::TEMPLATE, SecurityInput::PATH, PhpLimits::PATH, Http3Input::PATH];
    }

    /**
     * @throws InputsUnsure when the inputs cannot be digested completely
     */
    public function digest(Profile $profile, int $epoch): string
    {
        $parts = ['profile' => [$profile->production, $profile->hybridPorts], 'epoch' => $epoch];
        $files = $this->productFiles === [] ? self::defaultProductFiles() : $this->productFiles;
        foreach ($files as $path) {
            $parts['product'][$path] = self::fileState($path);
        }
        $parts['demand'] = PhpDemand::load($this->demandPath ?? PhpDemand::PATH)->children();
        $parts['cpanel'] = $this->listing('input-cpanel', [self::FIND, '-L', ...self::CPANEL_ROOTS, '-printf', self::STAT], true);
        $parts['php'] = $this->listing('input-php', [self::FIND, '-L', '/opt/cpanel', '-maxdepth', '5', '(', '-path',
            '/opt/cpanel/*/root/etc/php-fpm.d/*', '-o', '-path', '/opt/cpanel/*/root/usr/bin/*php', ')', '-printf', self::STAT], false);
        $parts['ipv6'] = hash('sha256', $this->run('input-ipv6', ['/usr/sbin/ip', '-6', '-o', 'addr', 'show', 'scope', 'global'])['stdout']);
        $domains = $this->run('input-userdatadomains', ['/usr/bin/cat', '/etc/userdatadomains']);
        $parts['userdatadomains'] = hash('sha256', $domains['stdout']);
        foreach (self::documentRoots($domains['stdout']) as $user => $roots) {
            foreach ($roots as $root) {
                $parts['htaccess'][$user][$root] = $this->listing("input-htaccess-$user", [self::RUNUSER, '-u', $user, '--', self::FIND,
                    '-H', $root, '-name', '.htaccess', '(', '-type', 'f', '-o', '-type', 'l', ')', '-printf', self::STAT], false);
            }
            foreach (self::ancestors($user, $roots) as $directory) {
                $parts['ancestors'][$user][$directory] = $this->listing("input-ancestor-$user", [self::RUNUSER, '-u', $user, '--', self::FIND,
                    '-L', $directory, '-maxdepth', '1', '-name', '.htaccess', '-printf', self::STAT], false);
            }
        }
        return hash('sha256', json_encode($parts, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /**
     * Distinct document roots per account from /etc/userdatadomains (field 5 of every row), each inside the account's own
     * home; any other row is unsafe for a digest (the compile refuses or reads it elsewhere).
     * @return array<string,list<string>>
     * @throws InputsUnsure
     */
    public static function documentRoots(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text, -1, PREG_SPLIT_NO_EMPTY) as $line) {
            $fields = explode('==', explode(': ', $line, 2)[1] ?? '');
            if (count($fields) < 10) {
                throw new InputsUnsure('unexpected /etc/userdatadomains line');
            }
            [$user, , , , $docroot] = $fields;
            $root = rtrim($docroot, '/');
            if (preg_match(self::USER, $user) !== 1 || in_array($user, ['root', 'nobody'], true) || HomePath::homeOf($root, $user) === null
                || preg_match('/^\/[A-Za-z0-9._\/@+-]+$/D', $root) !== 1 || str_contains($root, '//') || preg_match('#/\.\.?(/|$)#', $root) === 1) {
                throw new InputsUnsure("document root '$docroot' of account '$user' is not inside its home");
            }
            $out[$user][$root] = true;
        }
        ksort($out, SORT_STRING);
        return array_map(static function (array $roots): array {
            $roots = array_map('strval', array_keys($roots));
            sort($roots, SORT_STRING);
            return $roots;
        }, $out);
    }

    /**
     * The directories above a document root that lie inside the home (the home itself included), outermost first, without
     * those below another document root of the account (its own listing covers them).
     * @param list<string> $roots
     * @return list<string>
     */
    public static function ancestors(string $user, array $roots): array
    {
        $out = [];
        foreach ($roots as $root) {
            $home = HomePath::homeOf($root, $user);
            for ($directory = dirname($root); $home !== null && strlen($directory) >= strlen($home); $directory = dirname($directory)) {
                $covered = false;
                foreach ($roots as $other) {
                    $covered = $covered || $directory === $other || str_starts_with($directory, $other . '/');
                }
                if (!$covered) {
                    $out[$directory] = true;
                }
            }
        }
        $out = array_map('strval', array_keys($out));
        sort($out, SORT_STRING);
        return $out;
    }

    /**
     * The sorted metadata records of one `find` (NUL-terminated lines; sorted because the order of a directory is not stable).
     * @param list<string> $argv
     * @return list<string>
     */
    private function listing(string $name, array $argv, bool $roots): array
    {
        $read = $this->run($name, $argv, true);
        $stderr = trim((string) ($read['stderr'] ?? ''));
        if ($read['exit_code'] !== 0) {
            $lines = $stderr === '' ? [] : preg_split('/\R/', $stderr);
            // A root that is absent (ModSecurity not installed, a php-fpm.d that does not exist) is a fact, not a failure.
            $missing = $roots && $read['exit_code'] === 1 && $lines !== []
                && array_filter($lines, static fn(string $l): bool => !str_ends_with($l, ': No such file or directory')) === [];
            if (!$missing) {
                throw new InputsUnsure("$name failed (exit {$read['exit_code']}): " . substr($stderr, -160));
            }
        }
        $records = explode("\0", $read['stdout']);
        $records = array_values(array_filter($records, static fn(string $r): bool => $r !== ''));
        sort($records, SORT_STRING);
        return $records;
    }

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     * @throws InputsUnsure
     */
    private function run(string $name, array $argv, bool $tolerant = false): array
    {
        try {
            $read = $this->engine->run($name, $argv, self::TIMEOUT);
        } catch (\Throwable $error) {
            throw new InputsUnsure("$name: " . Reconciler::describe($error), 0, $error);
        }
        if (!$tolerant && $read['exit_code'] !== 0) {
            throw new InputsUnsure("$name failed (exit {$read['exit_code']})");
        }
        return $read;
    }

    /** One product input: absent, or "type:owner:size:mtime:sha256" (a link or an unreadable file is "unreadable": never a guess). */
    private static function fileState(string $path): string
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);
        if ($stat === false) {
            return file_exists($path) || is_link($path) ? 'unreadable' : 'absent';
        }
        $text = ($stat['mode'] & 0170000) === 0100000 ? @file_get_contents($path) : false;
        return $text === false ? 'unreadable:' . $stat['mode'] : sprintf('%o:%d:%d:%d:%s', $stat['mode'], $stat['uid'], $stat['size'], $stat['mtime'],
            hash('sha256', $text));
    }
}
