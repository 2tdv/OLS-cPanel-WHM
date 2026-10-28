<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Deployment\Host;

/**
 * `update install` (the WHM "Update now" button, job `ols.update`): installs a newer release of the product from its GitHub
 * release, verified before anything runs. Steps, all through the Host's CommandRunner (argv arrays, no shell):
 *
 *   1. the version: the one given, or the latest release (ReleaseChannel::latest); refused unless it is newer than the installed
 *      ols-cpanel version (rpm order), so the button can never reinstall or downgrade;
 *   2. the release key SHIPPED IN THE INSTALLED PRODUCT PACKAGE (ReleaseChannel::KEY, with its pinned fingerprint file): never a
 *      key from the network, so a compromised release page cannot introduce its own key;
 *   3. install.sh and install.sh.asc of exactly that tag, over HTTPS (ReleaseChannel::curl), into a private 0700 directory under
 *      /var/tmp (the job's unit has a private /tmp; /var/tmp keeps the files off tmpfs);
 *   4. the detached signature, verified by gpg in an isolated home inside that directory holding only the shipped key: the key
 *      must import as exactly the pinned primary fingerprint, and gpg must report VALIDSIG with that fingerprint (a good
 *      signature by any other key, or a changed install.sh, is refused); the signed installer must also name this release
 *      (RELEASE_VERSION), so the signed installer of another release cannot be served under this tag;
 *   5. `sh install.sh` with stdin /dev/null: on a server with an older build the installer verifies the release manifest and
 *      every package against its own embedded key, upgrades the packages with dnf (never a downgrade) and exits; the product
 *      then applies its own upgrade (Upgrade, ols-cpanel-upgrade.service started after the package transaction), which
 *      restarts the broker. The job runs as a transient systemd unit (broker/src/panel/jobs.rs), so that restart does not end
 *      it, and the outcome is in this command's own report (`code`), which the restarted broker reads.
 *
 * The private directory is removed on every path. The cached update check is dropped afterwards, so the Updates view shows the
 * new installed version on its next load. Nothing here changes the server before step 5; refusals before it exit 1 with the reason.
 */
final class ReleaseUpdate
{
    public const TEMP_BASE = '/var/tmp';
    public const GPG = '/usr/bin/gpg';
    public const SH = '/usr/bin/sh';
    public const INSTALLER_MAX_BYTES = 1 << 20;
    /** Below the job's own limit (one hour), so the command reports a stuck installer itself. */
    public const INSTALLER_TIMEOUT = 3300;
    public const OUTPUT_LINES = 40;

    /** @var \Closure(string):void */
    private \Closure $progress;

    /** @param (\Closure(string):void)|null $progress one line per step (the job log) */
    public function __construct(private readonly Host $host, private readonly string $state, private readonly string $key = ReleaseChannel::KEY,
                                private readonly string $fingerprint = ReleaseChannel::FINGERPRINT,
                                private readonly string $tempBase = self::TEMP_BASE, ?\Closure $progress = null)
    {
        $this->progress = $progress ?? static function (string $line): void {
        };
    }

    /**
     * @param string|null $version the release to install; null: the latest release
     * @return array<string,mixed> result "updated" (code 0) or "failed" (code 1, the installer's exit status and output tail)
     */
    public function install(?string $version): array
    {
        if ($version === null) {
            try {
                $version = ReleaseChannel::latest($this->host)['version'];
            } catch (\RuntimeException $error) {
                throw new Refused($error->getMessage() . '; nothing was changed');
            }
        }
        if (strlen($version) > 64 || preg_match(ReleaseChannel::VERSION, $version) !== 1) {
            throw new Refused('the release version must be a dotted number such as 0.2.3');
        }
        $current = ReleaseChannel::installedVersion($this->host);
        if ($current === null) {
            throw new Refused('the installed OLS-cPanel version could not be read; nothing was changed');
        }
        if (ReleaseChannel::compare($version, $current) <= 0) {
            throw new Refused("release $version is not newer than the installed version $current; nothing was changed");
        }
        $fingerprint = $this->shippedFingerprint();
        ($this->progress)("updating OLS-cPanel $current to release $version");
        $dir = $this->privateDirectory();
        try {
            $installer = "$dir/install.sh";
            ($this->progress)('downloading install.sh and its signature');
            $this->download("install.sh", $version, $installer);
            $this->download("install.sh.asc", $version, "$installer.asc");
            $this->verify($dir, $installer, $fingerprint, $version);
            ($this->progress)("install.sh of release $version verified (key $fingerprint)");
            ($this->progress)('running the verified installer (packages are verified against the signed release manifest, then upgraded)');
            $run = $this->host->run('update-installer', [self::SH, $installer], self::INSTALLER_TIMEOUT);
        } finally {
            self::remove($dir);
            @unlink($this->state . '/' . UpdateCheck::FILE);
        }
        $lines = preg_split('/\R/', rtrim(($run['stderr'] ?? '') . "\n" . $run['stdout'])) ?: [];
        $tail = array_map(static fn(string $line): string => StateFile::clean($line, 300),
            array_slice(array_values(array_filter($lines, static fn(string $line): bool => trim($line) !== '')), -self::OUTPUT_LINES));
        $ok = $run['exit_code'] === 0;
        ($this->progress)($ok ? "release $version installed; the product applies the upgrade by itself" : "the installer failed (exit {$run['exit_code']})");
        return ['result' => $ok ? 'updated' : 'failed', 'code' => $ok ? 0 : 1, 'previous_version' => $current, 'version' => $version,
            'installer_exit_code' => $run['exit_code'], 'output_tail' => $tail,
            'next' => $ok ? 'The product applies the upgrade by itself within a minute; sites keep being served.'
                : 'Nothing was changed if verification failed; otherwise re-run the update. See the output tail.'];
    }

    /** The pinned fingerprint shipped with the key; the key file itself is checked when gpg imports it. */
    private function shippedFingerprint(): string
    {
        $text = is_file($this->fingerprint) && !is_link($this->fingerprint) ? @file_get_contents($this->fingerprint, false, null, 0, 256) : false;
        $fingerprint = is_string($text) ? trim($text) : '';
        if (preg_match('/^[0-9A-F]{40}$/D', $fingerprint) !== 1) {
            throw new Refused('the release key fingerprint shipped with the product is missing or malformed; nothing was changed');
        }
        $key = is_file($this->key) && !is_link($this->key) ? @file_get_contents($this->key, false, null, 0, 65536) : false;
        if (!is_string($key) || !str_starts_with($key, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n")) {
            throw new Refused('the release key shipped with the product is missing; nothing was changed');
        }
        return $fingerprint;
    }

    private function privateDirectory(): string
    {
        $old = umask(0077);
        try {
            $dir = $this->tempBase . '/ols-cpanel-update.' . bin2hex(random_bytes(6));
            if (!@mkdir($dir, 0700) || !@mkdir("$dir/gnupg", 0700)) {
                throw new Refused('a private working directory could not be created; nothing was changed');
            }
        } finally {
            umask($old);
        }
        return $dir;
    }

    private function download(string $name, string $version, string $target): void
    {
        $url = ReleaseChannel::DOWNLOAD_BASE . "/$version/$name";
        $reply = $this->host->run("update-download-$name", ReleaseChannel::curl($url, ['--retry', '2', '--output', $target],
            self::INSTALLER_MAX_BYTES, 120), 150);
        clearstatcache(true, $target);
        if ($reply['exit_code'] !== 0 || !is_file($target) || is_link($target) || (int) filesize($target) > self::INSTALLER_MAX_BYTES) {
            throw new Refused("$name of release $version could not be downloaded: "
                . StateFile::clean(Host::tail(($reply['stderr'] ?? '') . $reply['stdout']), 200) . '; nothing was changed');
        }
    }

    private function verify(string $dir, string $installer, string $fingerprint, string $version): void
    {
        $gpg = [self::GPG, '--homedir', "$dir/gnupg", '--batch', '--no-tty', '--no-autostart'];
        $import = $this->host->run('update-key-import', [...$gpg, '--quiet', '--import', $this->key], 60);
        $listing = $this->host->run('update-key-list', [...$gpg, '--with-colons', '--fingerprint'], 60);
        $primary = null;
        $previous = '';
        foreach (explode("\n", $listing['stdout']) as $line) {
            $fields = explode(':', $line);
            if ($fields[0] === 'fpr' && $previous === 'pub' && $primary === null) {
                $primary = $fields[9] ?? null;
            }
            $previous = $fields[0];
        }
        if ($import['exit_code'] !== 0 || $listing['exit_code'] !== 0 || $primary !== $fingerprint) {
            throw new Refused('the release key shipped with the product does not match its fingerprint; nothing was changed');
        }
        $check = $this->host->run('update-verify', [...$gpg, '--status-fd', '1', '--verify', "$installer.asc", $installer], 60);
        $valid = false;
        foreach (explode("\n", $check['stdout']) as $line) {
            $fields = preg_split('/\s+/', trim($line)) ?: [];
            // VALIDSIG <signing key fpr> ... <primary key fpr>: the primary key must be the pinned one.
            $valid = $valid || (($fields[0] ?? '') === '[GNUPG:]' && ($fields[1] ?? '') === 'VALIDSIG' && end($fields) === $fingerprint);
        }
        if ($check['exit_code'] !== 0 || !$valid) {
            throw new Refused("install.sh of release $version is not signed by the release key $fingerprint; nothing was changed");
        }
        $text = (string) @file_get_contents($installer, false, null, 0, self::INSTALLER_MAX_BYTES);
        if (substr_count($text, "\nRELEASE_VERSION=\"$version\"\n") !== 1) {
            throw new Refused("the signed install.sh is not the installer of release $version; nothing was changed");
        }
    }

    /** Removes the private directory (never following a link). */
    private static function remove(string $path): void
    {
        if (is_dir($path) && !is_link($path)) {
            foreach (scandir($path) ?: [] as $name) {
                if ($name !== '.' && $name !== '..') {
                    self::remove("$path/$name");
                }
            }
            @rmdir($path);
        } elseif (file_exists($path) || is_link($path)) {
            @unlink($path);
        }
    }
}
