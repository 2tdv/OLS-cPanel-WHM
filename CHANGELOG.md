# Changelog

## 0.2.8

- Installer: an Enter pressed while the preparation runs no longer cancels the approval; keys typed before the question
  are ignored, and an empty answer asks again.

## 0.2.7

- Installer: when an earlier installation stopped before the switch (for example a refused preparation), running the
  install command of a newer release continues with the preparation and the switch instead of stopping after the
  packages.

## 0.2.6

- ModSecurity: servers using cPanel's OWASP Core Rule Set (WHM, ModSecurity Vendors) can now be switched; the rule set
  runs on OpenLiteSpeed and blocks the same attacks as under Apache. Its commented examples and its optional
  country rule (which needs a geolocation database that is not configured) no longer stop the preparation.

## 0.2.5

- Security: the firewall that closes Apache's standby ports (behind OpenLiteSpeed) is restored at every boot, before
  Apache and OpenLiteSpeed start, and checked every 15 minutes; it was lost after a reboot. Updating repairs existing
  installations by itself.

## 0.2.4

- Installer: running the install command again for the release that is already installed and serving says so and
  changes nothing.
- Object cache: right after an installation, WordPress sites are connected within about a minute (they waited five).

## 0.2.3

- Updates from WHM: the Updates page finds a new release on GitHub, and **Update now** installs it after verifying
  it with the project's signing key; sites keep being served and the product applies the update by itself.
- Release packages are signed (rpm signatures), and the installer adds the project key to the system.
- Uninstalling also removes the project key and the installer's report.

## 0.2.2

- Object cache works out of the box: every account with WordPress and LiteSpeed Cache automatically gets its own
  private object cache (Valkey), and the plugin's default settings are switched to it by themselves. WHM shows which
  accounts use it and can turn the automatic mode off; an administrator's decision for an account always wins.
- Uninstalling leaves nothing behind.
- Guide: what to enter in LiteSpeed Cache by hand, for anyone who prefers to (docs/object-cache.md).

## 0.2.1

- Fix: on a fresh installation the cPanel plugin was disabled for every account (cPanel's plugin registration files
  were created readable by root only). Installing 0.2.1 over 0.2.0 repairs it.
- Fix: a WordPress site with the current Akismet plugin was moved to Apache (an "@" in a file name of its
  `.htaccess` was not understood); it is served by OpenLiteSpeed and its page cache works.
- Fix: the object cache engine (Valkey) is installed with the product, so turning on an account's object cache in
  WHM works without anything else.
- Installer: clear stage headings, a short summary instead of a long report, and approval by typing "yes".

## 0.2.0 — first release

- OpenLiteSpeed for cPanel & WHM on AlmaLinux 9 (x86_64): planned switch from Apache with per-site checks and
  automatic return to Apache; sites OpenLiteSpeed cannot reproduce stay on Apache behind it.
- Automatic application of cPanel changes (accounts, domains, certificates, PHP versions, suspensions) and of
  product upgrades.
- LSCache page cache, HTTP/3, OPcache, per-account object cache (Valkey) with automatic WordPress configuration,
  ModSecurity rules.
- WHM plugin and cPanel plugin (WCAG 2.1 AA checked).
- Signed one-command installer.
