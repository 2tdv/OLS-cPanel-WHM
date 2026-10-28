<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Deployment\Host;
use OlsCpanel\Deployment\Upgrade;

/**
 * The update channel view (FV-07): installed versus available versions of the product packages and the rpm signature state of the
 * installed ones. Read-only: `dnf -q check-update` and `rpm -q` queries; nothing is installed. The update itself stays with dnf
 * and cPanel's own update schedule; the product applies it by itself afterwards (Upgrade::pending). The result is kept in
 * `<state>/update-check.json` for CACHE_SECONDS so that opening the page does not run the package manager every time.
 *
 * Signature state of an installed package, from its rpm header: `signed` (a key id is present and that key is imported into the rpm
 * database), `signed-key-missing` (signed, but the key is not imported on this server) or `unsigned` (no signature: a lab or local
 * build). A release manifest signature is not part of the product's channel; the rpm signature is the integrity statement.
 */
final class UpdateCheck
{
    public const FILE = 'update-check.json';
    public const CACHE_SECONDS = 900;
    public const DNF = '/usr/bin/dnf';
    public const RPM = '/usr/bin/rpm';
    private const VERSION = '/^[A-Za-z0-9._+~^-]+$/D';

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
        if (!$refresh && is_array($cached) && is_int($cached['checked_at'] ?? null) && $cached['checked_at'] > $now - self::CACHE_SECONDS
            && $cached['checked_at'] <= $now) {
            return $cached + ['cached' => true];
        }
        $installed = Upgrade::installed($this->host);
        $available = [];
        $error = null;
        $check = $this->host->run('update-check', [self::DNF, '-q', 'check-update', '--refresh', ...Upgrade::PACKAGES], 60);
        if ($check['exit_code'] === 100) {
            foreach (explode("\n", $check['stdout']) as $line) {
                if (preg_match('/^(ols-cpanel(?:-openlitespeed)?)\.([A-Za-z0-9_]+)\s+(\S+)\s+\S+/', $line, $m) === 1
                    && in_array($m[1], Upgrade::PACKAGES, true) && preg_match(self::VERSION, $m[3]) === 1) {
                    $available[$m[1]] = $m[3] . '.' . $m[2];
                }
            }
        } elseif ($check['exit_code'] !== 0) {
            $error = 'the package repositories could not be queried: ' . StateFile::clean(Host::tail(($check['stderr'] ?? '') . $check['stdout']), 200);
        }
        $packages = [];
        foreach (Upgrade::PACKAGES as $package) {
            $packages[] = ['package' => $package, 'installed' => $installed[$package] ?? null, 'available' => $available[$package] ?? null,
                'update_available' => isset($available[$package]), 'signature' => isset($installed[$package]) ? $this->signature($package) : null];
        }
        $report = ['checked_at' => $now, 'error' => $error, 'update_available' => $available !== [], 'packages' => $packages,
            'cpanel_version' => $this->cpanelVersion()];
        if ($error === null) {
            try {
                StateFile::write($this->state . '/' . self::FILE, $report);
            } catch (\RuntimeException) {
                // A cache that cannot be written only costs the next view a query.
            }
        }
        return $report + ['cached' => false];
    }

    /** @return array{state:string,key_id:?string,detail:string} */
    private function signature(string $package): array
    {
        $query = $this->host->run("signature-$package", [self::RPM, '-q', '--qf', '%{RSAHEADER:pgpsig}|%{SIGPGP:pgpsig}', $package]);
        $text = trim($query['stdout']);
        if ($query['exit_code'] !== 0 || preg_match('/Key ID ([0-9a-f]{16})/i', $text, $m) !== 1) {
            return ['state' => 'unsigned', 'key_id' => null, 'detail' => 'No rpm signature (lab or local build).'];
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
