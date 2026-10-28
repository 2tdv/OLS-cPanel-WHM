# Installing OLS-cPanel

OLS-cPanel replaces Apache with OpenLiteSpeed (OLS) as the web server of an existing cPanel/WHM server,
while cPanel stays the source of truth for accounts, domains, PHP versions and certificates. This guide
explains how a release is installed, what each stage changes, and how to stop, go back to Apache or remove
the product.

> **Use the command from the release notes.** The command below is shown as a template: `RELEASE_BASE_URL`,
> `RELEASE_VERSION` and `INSTALLER_SHA256` are the values that the release notes of each release (and the README)
> fill in. Do not run the template as it is, and do not use a command from any other source.

## What gets installed

| Package | Contents |
|---|---|
| `ols-cpanel-openlitespeed` | OpenLiteSpeed built from a pinned upstream version with the product patches, and its service units. |
| `ols-cpanel-php-redis` | The PHP `redis` extension (phpredis, pinned) prebuilt for the EA4 PHP versions, and its checksum-pinned source for any other EA4 PHP version. The PHP environment service activates it itself. |
| `ols-cpanel` | The configuration engine and the `ols-cpanel` command (run with cPanel's own PHP), the privileged broker, the reconciler service, and the WHM and cPanel plugins. Installed under `/usr/local/ols-cpanel`. |

All packages only place files. Installing them does not start or enable any service, create accounts,
register plugins or hooks, or open ports. Those steps happen later, inside the guided workflow, where each
one is recorded so it can be undone.

## Before you start

You need:

- **A supported server**: AlmaLinux 9 on x86_64 (Rocky Linux, CloudLinux and release 8 follow in later releases), with a
  licensed and working cPanel/WHM. The release notes list the exact operating system and cPanel versions
  that each release was tested on; only those rows are supported. This product does not install or license
  cPanel.
- **Root access**: log in as root, or use `sudo` from an account allowed to run commands as root.
- **Console access** to the server (for example your provider's web console), independent of SSH and of the
  web server, in case you need to recover.
- **A current backup** of the server, kept somewhere other than the server itself. The installer backs up
  the cPanel and Apache configuration it changes, but that is not a backup of your sites, mail or databases.
- **These tools** (present on a standard cPanel server): `curl`, `gpg`, `sha256sum`, `mktemp`, `dnf`.
- **HTTPS access** from the server to the release location and to your operating system's package
  repositories (for ordinary dependencies such as `libaio`).
- **A maintenance window** for the final switch. Until then your sites keep running on Apache.

### Where the trust comes from

Each release publishes two values in its release notes, through a channel separate from the download
location:

1. the SHA-256 digest of `install.sh` (`INSTALLER_SHA256` below), and
2. the fingerprint of the release signing key.

The command checks the installer against the digest before running it. The installer contains the release
public key and checks the signed release manifest with it; every package is then checked against the digest
in that signed manifest. If you received the digest from the same place as the download, it does not prove
anything: compare it with the release notes.

The release signing key of this project has the fingerprint

    118D FA42 F66A 585D 176C  0B51 48E2 6833 CB82 EAD1

(RSA 4096, valid until 2029-10-27). Its public key is in the repository as
`build/release/ols-cpanel-release-key.asc`. A release signed by any other key is refused by the installer.

The installer is also signed (`install.sh.asc`). Each release's notes give a stricter variant of the command below
that fetches the release key from keys.openpgp.org by this fingerprint and verifies the installer's signature before
running it, so it does not depend on the digest shown on the release page.

## The one command

Run this on the server, with the placeholders replaced by the values from the release notes:

```sh
d=$(mktemp -d) && curl --proto '=https' --tlsv1.2 -fsSL -o "$d/install.sh" "RELEASE_BASE_URL/RELEASE_VERSION/install.sh" && echo "INSTALLER_SHA256  $d/install.sh" | sha256sum -c - && sh "$d/install.sh"; rm -rf "$d"
```

From a non-root account with `sudo`, replace `sh "$d/install.sh"` with `sudo sh "$d/install.sh"`.

What it does: creates a private temporary directory, downloads the installer for exactly this release into
it (never a "latest" link), stops if the installer does not match the published digest, otherwise runs it,
and finally deletes the directory. Nothing downloaded is piped into a shell.

To only prepare (no switch from Apache in this session), add `--prepare-only`:
`sh "$d/install.sh" --prepare-only`. Run `sh "$d/install.sh" --help` to see all options.

## What happens, stage by stage

The installer prints each stage. Stages 1 to 3 change nothing on the server.

1. **Checks.** Root access; operating system, version and architecture; cPanel present and reporting its
   version; cPanel's PHP 8.4 runtime present; required tools present. An unsupported system is refused.
2. **Download.** The signed release manifest for your platform (for example `el9.x86_64`), its signature
   and the two packages are downloaded over HTTPS only into a private temporary directory under
   `/var/tmp`, readable only by root.
3. **Verification.** The manifest signature is checked against the release key built into the installer,
   using a separate, temporary keyring (your system keyrings are not used or changed). The manifest must
   name this release and this platform. Every package must match its SHA-256 digest from the manifest. If
   anything does not match, the installer stops and the server is unchanged.
4. **Package installation.** The verified packages are installed with `dnf`. If a different build of either
   package is already installed, the installer stops: upgrades use a separate workflow. Running the same
   command again after an interruption is safe; it installs the same packages again or finds them already
   installed.
5. **Preparation** (`/usr/local/ols-cpanel/bin/ols-cpanel install --prepare`; hybrid profile by default: Apache stays in standby behind OpenLiteSpeed on ports 81/444, closed to the outside, and serves automatically only the sites whose `.htaccess` or PHP handler OpenLiteSpeed cannot reproduce exactly; add `--native` to opt out, in which case an untranslatable change refuses the compile for safety). A read-only preflight report of the server; a backup of
   the cPanel and Apache configuration the product will touch; the first OLS configuration generated from
   cPanel's data and validated; the broker and the WHM and cPanel plugins set up. OLS is installed but
   does not take over any public port.
   **Apache keeps serving your sites.**
6. **Cutover** (`/usr/local/ols-cpanel/bin/ols-cpanel install --cutover`). Only when you run the installer in an interactive terminal
   without `--prepare-only`. The command shows what will change: which sites move to OLS, which (if any)
   stay on Apache behind OLS, which services are affected and how to recover. **Nothing is switched until
   you approve this plan.** After approval, OLS takes over ports 80 and 443 and every site is checked; if
   the checks fail, the server is returned to Apache automatically.

If the installer is not attached to a terminal, or you used `--prepare-only`, it stops after stage 5 and
prints the cutover command to run when you are ready.

The temporary directory is removed when the installer exits, whether it succeeded, failed or was
interrupted.

### Exit status

| Code | Meaning |
|---|---|
| 0 | Finished (prepared, or cut over after your approval) |
| 64 | Unknown option |
| 65 | Verification failed (signature, release, platform or package digest); nothing was changed |
| 69 | Unsupported system, or an installer that was not prepared for a release |
| 70 | A download, package installation, preparation or cutover step failed |
| 77 | Not run as root |

A verification failure is never a reason to bypass the checks. Report it, and do not install packages from
that location.

## Cancelling

- **During stages 1 to 3**: press Ctrl+C. Nothing was changed; the temporary files are removed.
- **During stage 4**: `dnf` either completes or rolls back its own transaction. Run the same command again
  to finish; the installed packages do not start anything by themselves.
- **During or after stage 5**: Apache is still serving. Leave the preparation in place, or remove it with
  `/usr/local/ols-cpanel/bin/ols-cpanel uninstall --dry-run` (shows what would be removed) followed by `/usr/local/ols-cpanel/bin/ols-cpanel uninstall`.
- **At the cutover approval**: decline. Apache keeps serving and nothing is switched.

## Upgrading

Run the one command of the newer release (from its release notes), exactly as for the installation. The installer
verifies the new release the same way (signed manifest, package digests); when an older build is installed it
upgrades the packages, never downgrades a newer one, and changes nothing else. It does not ask for a cutover again.

After the package transaction the product applies the upgrade by itself within a minute: it restarts its own
services, refreshes the WHM and cPanel plugins, reloads OpenLiteSpeed gracefully when its binary changed, and
restarts only the PHP processes whose settings changed. Your sites keep being served; nothing else is needed.
The WHM plugin's Updates view shows the installed and available versions.

To apply an upgrade by hand (support only): `/usr/local/ols-cpanel/bin/ols-cpanel upgrade`.

## Going back to Apache

After a cutover, you can return to Apache at any time:

```sh
/usr/local/ols-cpanel/bin/ols-cpanel apache-return --prepare
/usr/local/ols-cpanel/bin/ols-cpanel apache-return --execute --plan=<plan id shown by the previous command>
```

The first command checks that Apache can be rebuilt from cPanel's current configuration (not from an old
copy taken on the day of installation) and shows a plan. The second stops OLS, gives ports 80 and 443 back to
Apache, removes the product's Apache port changes, include file and firewall rule if they were used, and
checks every site. The product stays installed and can be activated again.

## Uninstalling

```sh
/usr/local/ols-cpanel/bin/ols-cpanel uninstall --dry-run
/usr/local/ols-cpanel/bin/ols-cpanel uninstall
```

Uninstall first returns the server to Apache if OLS is still serving, and verifies that Apache serves
80/443. Only then does it remove what the product added, so the server is left as it was before:

- the cPanel hooks, the WHM and cPanel plugins, and every product service and timer (stopped and disabled);
- LiteSpeed Cache's object cache in WordPress sites: where the product switched it on, it is switched off
  again as the site owner (`wp litespeed-option set object false`), and only while the site's object cache
  host is still the product's socket (`/home/<user>/.ols-objcache/valkey.sock`). A site whose owner or
  administrator changed the host, or that uses another object cache plugin, is never touched. A site that
  cannot be switched off is listed in the result (account, path, reason); it never stops the uninstall;
- the per-account object cache instances, their systemd drop-ins
  (`/etc/systemd/system/ols-cpanel-objcache@<account>.service.d/50-account.conf`, followed by one
  `systemctl daemon-reload`), and the product's state directory `/var/lib/ols-cpanel` (plans, generations,
  object cache and PHP environment records) except `backups/`;
- the INI files the product wrote: `zz-ols-cpanel-opcache.ini` and the PHP redis extension INI in
  `/opt/cpanel/ea-php*/root/etc/php.d/`. Only a file that carries the product's own first line is removed;
  another file of that name, a link, or any other INI stays. The `ea-php*-php-opcache` packages stay installed;
- the recommended EasyApache profile file the product added;
- the three product packages (`ols-cpanel`, `ols-cpanel-openlitespeed`, `ols-cpanel-php-redis`, the ones that
  are installed), as the last step and only after everything above succeeded. The removal runs in the
  transient unit `ols-cpanel-remove-packages` (`dnf -y remove ...`), outside the uninstall process, which runs
  from one of those packages. Follow it with `journalctl -u ols-cpanel-remove-packages`. The packages have no
  scriptlets, so their removal never calls uninstall again. `--keep-packages` skips this step and prints the
  `dnf remove` command instead.

What is kept: `/var/lib/ols-cpanel/backups/` (every cutover backup and its recovery script), the logs
(including `/usr/local/lsws/logs`), the `olscpanel` system user and group, the OPcache packages, and
everything the product did not create. It never removes your sites' files, cPanel's certificates, packages
the product did not install, or changes made by an administrator. It can be run again if it is interrupted.

`uninstall --dry-run` lists every action above, including the sites it would switch off and the package
removal, and changes nothing. For WordPress sites whose settings cannot be read from files without running
PHP, the dry run lists the site and the real run checks it with wp-cli before changing anything.

Do not remove the packages with `dnf remove` while OLS is serving: that would remove the web server without
giving the ports back to Apache. Use `/usr/local/ols-cpanel/bin/ols-cpanel uninstall`.

## Getting help

- `/usr/local/ols-cpanel/bin/ols-cpanel doctor --read-only --format=json` produces a read-only report of the server that you can
  attach to a support request.
- Recovery instructions that work even if the WHM interface is unavailable are part of each release.
