<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Deployment\Host;

/**
 * The product's release channel: the GitHub releases of the project repository (tag = product version). A release carries
 * install.sh with its detached signature, one signed manifest per platform row and the packages (build/release/release.py);
 * there is no package repository, so `dnf check-update` never sees a new release. This class is the one place that names
 * the repository and its URLs (build/release/release.py's DEFAULT_BASE is the same download base; tests/operations.php
 * checks that), asks GitHub for the latest release and compares versions.
 *
 * Network access is curl with HTTPS only (redirects too: release downloads are redirected to GitHub's object storage, which
 * --proto-redir =https allows and nothing else), TLS 1.2 or newer, short timeouts and a bounded size. Nothing a reply says is
 * trusted beyond its shape: the tag must be a plain dotted version, and every file a release provides is verified against
 * the release key shipped in the product package (ReleaseUpdate) before anything runs.
 */
final class ReleaseChannel
{
    public const REPOSITORY = '2tdv/OLS-cPanel-WHM';
    public const API_LATEST = 'https://api.github.com/repos/' . self::REPOSITORY . '/releases/latest';
    public const DOWNLOAD_BASE = 'https://github.com/' . self::REPOSITORY . '/releases/download';
    public const RELEASE_PAGE = 'https://github.com/' . self::REPOSITORY . '/releases/tag';
    /** The release public key and its primary key fingerprint, shipped in the product package (build/product/package.py). */
    public const KEY = '/usr/local/ols-cpanel/share/release-key.asc';
    public const FINGERPRINT = '/usr/local/ols-cpanel/share/release-key.fingerprint';
    /** Written by install.sh after a verified install or upgrade (root 0600, in the state directory): which release is installed. */
    public const RECORD = 'installed-release.json';
    public const CURL = '/usr/bin/curl';
    public const RPM = '/usr/bin/rpm';
    public const PRODUCT_PACKAGE = 'ols-cpanel';
    /** The tag grammar of a release (the same as install.sh's RELEASE_VERSION and release.py's VERSION). */
    public const VERSION = '/^[0-9]+(?:\.[0-9]+)*$/D';
    public const API_MAX_BYTES = 1 << 20;

    /**
     * curl with the channel's transport rules; $extra goes before the URL.
     * @param list<string> $extra
     * @return list<string>
     */
    public static function curl(string $url, array $extra, int $maxBytes, int $maxSeconds): array
    {
        return [self::CURL, '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--fail', '--silent', '--show-error',
            '--location', '--max-redirs', '5', '--connect-timeout', '10', '--max-time', (string) $maxSeconds,
            '--max-filesize', (string) $maxBytes, '--user-agent', 'ols-cpanel-update', ...$extra, $url];
    }

    /**
     * The latest published release (drafts and pre-releases are never "latest" on GitHub).
     * @return array{version:string,url:string}
     * @throws \RuntimeException with a short printable reason when GitHub cannot be asked or the reply is not a release
     */
    public static function latest(Host $host): array
    {
        try {
            $reply = $host->run('release-latest', self::curl(self::API_LATEST, ['--header', 'Accept: application/vnd.github+json'],
                self::API_MAX_BYTES, 20), 30);
        } catch (\Throwable $error) {
            // A runner refusal (an answer above its output limit, a start failure) is an unreachable channel, not a crash.
            throw new \RuntimeException('GitHub could not be asked for the latest release: ' . StateFile::clean($error->getMessage(), 160));
        }
        if ($reply['exit_code'] !== 0) {
            throw new \RuntimeException('GitHub could not be asked for the latest release: '
                . StateFile::clean(Host::tail(($reply['stderr'] ?? '') . $reply['stdout']), 200));
        }
        if (strlen($reply['stdout']) > self::API_MAX_BYTES) {
            throw new \RuntimeException('the GitHub reply is larger than expected');
        }
        $data = json_decode($reply['stdout'], true, 32);
        if (!is_array($data) || array_is_list($data)) {
            throw new \RuntimeException('the GitHub reply is not a release');
        }
        $tag = $data['tag_name'] ?? null;
        if (!is_string($tag) || strlen($tag) > 64 || preg_match(self::VERSION, $tag) !== 1) {
            throw new \RuntimeException('the latest release has no valid version tag');
        }
        if (($data['draft'] ?? false) !== false || ($data['prerelease'] ?? false) !== false) {
            throw new \RuntimeException('the latest release is a draft or a pre-release');
        }
        // The page link is built from the tag, never taken from the reply.
        return ['version' => $tag, 'url' => self::RELEASE_PAGE . '/' . $tag];
    }

    /** The installed ols-cpanel package version (rpm VERSION, without release), or null when it cannot be read. */
    public static function installedVersion(Host $host): ?string
    {
        $query = $host->run('release-installed', [self::RPM, '-q', '--qf', '%{VERSION}', self::PRODUCT_PACKAGE]);
        $version = trim($query['stdout']);
        return $query['exit_code'] === 0 && strlen($version) <= 64 && preg_match(self::VERSION, $version) === 1 ? $version : null;
    }

    /**
     * rpm's version order (rpmvercmp) for the tag grammar: numeric segments compared as numbers (no integer overflow: leading
     * zeros dropped, then length, then digits), and when every common segment is equal the version with more segments is newer
     * ("1.0.1" > "1.0"; rpm also orders "1.0.0" after "1.0"). -1, 0 or 1.
     */
    public static function compare(string $a, string $b): int
    {
        if (preg_match(self::VERSION, $a) !== 1 || preg_match(self::VERSION, $b) !== 1) {
            throw new \InvalidArgumentException('not a release version');
        }
        $left = explode('.', $a);
        $right = explode('.', $b);
        for ($i = 0; $i < min(count($left), count($right)); ++$i) {
            $x = ltrim($left[$i], '0');
            $y = ltrim($right[$i], '0');
            $order = strlen($x) <=> strlen($y) ?: strcmp($x, $y) <=> 0;
            if ($order !== 0) {
                return $order;
            }
        }
        return count($left) <=> count($right);
    }

    /**
     * The verified-release record install.sh wrote, when it is well-formed: {version, platform, manifest_sha256, packages
     * (name-version-release.arch of every verified package), installed_at}.
     * @return array{version:string,platform:string,manifest_sha256:string,packages:list<string>,installed_at:int}|null
     */
    public static function record(string $state): ?array
    {
        $record = StateFile::read($state . '/' . self::RECORD);
        $packages = $record['packages'] ?? null;
        if (!is_array($record) || !is_string($record['version'] ?? null) || preg_match(self::VERSION, $record['version']) !== 1
            || !is_string($record['manifest_sha256'] ?? null) || preg_match('/^[0-9a-f]{64}$/D', $record['manifest_sha256']) !== 1
            || !is_string($record['platform'] ?? null) || preg_match('/^el[0-9]+\.x86_64$/D', $record['platform']) !== 1
            || !is_int($record['installed_at'] ?? null) || !is_array($packages) || !array_is_list($packages) || count($packages) > 8) {
            return null;
        }
        foreach ($packages as $package) {
            if (!is_string($package) || preg_match('/^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}$/D', $package) !== 1) {
                return null;
            }
        }
        return ['version' => $record['version'], 'platform' => $record['platform'], 'manifest_sha256' => $record['manifest_sha256'],
            'packages' => $packages, 'installed_at' => $record['installed_at']];
    }
}
