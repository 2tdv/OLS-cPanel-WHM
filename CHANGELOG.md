# Changelog

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
