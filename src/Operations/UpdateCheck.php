<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Deployment\Host;
use OlsCpanel\Deployment\Upgrade;

/**
 * The update channel view (FV-07): the installed product version against the latest GitHub release of the project
 * (ReleaseChannel), and per installed package its rpm signature state and whether it is exactly a package of the release whose
 * signed manifest install.sh verified. Read-only: one HTTPS request to the GitHub releases API and `rpm -q` queries; nothing is
 * installed here (the WHM "Update now" button runs `update install` as a job, ReleaseUpdate). The product has no package
 * repository, so `dnf check-update` could never see a release and is not asked. The result is kept in `<state>/update-check.json`
 * for CACHE_SECONDS so that opening the page does not ask GitHub every time (unauthenticated API calls are rate limited per
 * address); a result with an error only for ERROR_CACHE_SECONDS, so an outage neither hides a release for long nor makes every
 * page view wait for the timeout. GitHub being unreachable never fails the view: it is reported as `error`.
 *
 * Signature state of an installed package, from its rpm header: `signed` (a key id is present and that key is imported into the rpm
 * database), `signed-key-missing` (signed, but the key is not imported on this server) or `unsigned` (no rpm signature). Independently,
 * `release_verified` says the installed build is exactly one of the packages listed in the signed release manifest that install.sh
 * verified before installing it (the record ReleaseChannel::RECORD it writes after a verified install or upgrade); a lab or local
 * build is neither.
 */
final class UpdateCheck
{
    public const FILE = 'update-check.json';
    public const CACHE_SECONDS = 900;
    public const ERROR_CACHE_SECONDS = 60;
    public const RPM = '/usr/bin/rpm';

    /** @var \Closure():int */
    private \Closure $clock;

    /** @param (\Closure():int)|null $clock */
    public function __construct(private readonly Host $host, private readonly string $state, ?\Closure $clock = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** @return array<string,mixed> */
    public function report(bool $refresh = false): array
    {
        $now = ($this->clock)();
        $cached = StateFile::read($this->state . '/' . self::FILE);
        if (!$refresh && is_array($cached) && is_int($cached['checked_at'] ?? null) && $cached['checked_at'] <= $now
            && $cached['checked_at'] > $now - (($cached['error'] ?? null) === null ? self::CACHE_SECONDS : self::ERROR_CACHE_SECONDS)) {
            return $cached + ['cached' => true];
        }
        $installed = Upgrade::installed($this->host);
        $current = ReleaseChannel::installedVersion($this->host);
        $latest = null;
        $error = null;
        try {
            $latest = ReleaseChannel::latest($this->host);
        } catch (\RuntimeException $failure) {
            $error = StateFile::clean($failure->getMessage(), 240);
        }
        if ($current === null && $error === null) {
            $error = 'the installed OLS-cPanel version could not be read';
        }
        $newer = $latest !== null && $current !== null && ReleaseChannel::compare($latest['version'], $current) > 0;
        $record = ReleaseChannel::record($this->state);
        $packages = [];
        foreach (Upgrade::PACKAGES as $package) {
            $version = $installed[$package] ?? null;
            $packages[] = ['package' => $package, 'installed' => $version,
                'signature' => $version !== null ? $this->signature($package) : null,
                'release_verified' => $version !== null && $record !== null && in_array("$package-$version", $record['packages'], true)];
        }
        $report = ['checked_at' => $now, 'error' => $error, 'repository' => ReleaseChannel::REPOSITORY, 'installed_version' => $current,
            'latest_release' => $latest, 'available_release' => $newer ? $latest : null, 'update_available' => $newer,
            'verified_release' => $record === null ? null : ['version' => $record['version'], 'platform' => $record['platform'],
                'manifest_sha256' => $record['manifest_sha256'], 'installed_at' => $record['installed_at']],
            'packages' => $packages, 'cpanel_version' => $this->cpanelVersion()];
        try {
            StateFile::write($this->state . '/' . self::FILE, $report);
        } catch (\RuntimeException) {
            // A cache that cannot be written only costs the next view a query.
        }
        return $report + ['cached' => false];
    }

    /** @return array{state:string,key_id:?string,detail:string} */
    private function signature(string $package): array
    {
        $query = $this->host->run("signature-$package", [self::RPM, '-q', '--qf', '%{RSAHEADER:pgpsig}|%{SIGPGP:pgpsig}', $package]);
        $text = trim($query['stdout']);
        if ($query['exit_code'] !== 0 || preg_match('/Key ID ([0-9a-f]{16})/i', $text, $m) !== 1) {
            return ['state' => 'unsigned', 'key_id' => null, 'detail' => 'No rpm signature.'];
        }
        $keyId = strtolower($m[1]);
        $known = $this->host->run("signature-key-$package", [self::RPM, '-q', 'gpg-pubkey-' . substr($keyId, 8)])['exit_code'] === 0;
        return ['state' => $known ? 'signed' : 'signed-key-missing', 'key_id' => $keyId,
            'detail' => $known ? 'Signed; the key is imported on this server.' : 'Signed, but the signing key is not imported on this server.'];
    }

    private function cpanelVersion(): ?string
    {
        $text = @file_get_contents('/usr/local/cpanel/version', false, null, 0, 64);
        return is_string($text) && preg_match('/^[0-9]+\.[0-9]+(?:\.[0-9]+)*$/D', trim($text)) === 1 ? trim($text) : null;
    }
}
