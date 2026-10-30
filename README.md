<div align="center">

# OLS-cPanel-WHM

**OpenLiteSpeed for cPanel & WHM — faster sites, lower server load, one command to install.**

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-AlmaLinux%209%20%7C%20cPanel%20%26%20WHM-orange)
![Release](https://img.shields.io/badge/release-0.2.11-brightgreen)

**[Website and screenshots](https://2tdv.github.io/OLS-cPanel-WHM/)** · [Install](https://2tdv.github.io/OLS-cPanel-WHM/install.html) · [FAQ](https://2tdv.github.io/OLS-cPanel-WHM/faq.html)

</div>

OLS-cPanel-WHM replaces Apache with [OpenLiteSpeed](https://openlitespeed.org) on a cPanel/WHM server and keeps
everything cPanel manages working: accounts, domains, SSL/AutoSSL, PHP versions, `.htaccess`, suspensions, logs and
bandwidth. Administrators get a WHM plugin, every hosting account gets a cPanel plugin.

## Features

- **Fast by default** — LiteSpeed page cache (LSCache), HTTP/3, OPcache on every PHP version, per-account object
  cache (Valkey) configured into WordPress automatically.
- **Safe switch** — the switch from Apache is planned, checked site by site and undone automatically if anything
  fails. Sites OpenLiteSpeed cannot reproduce exactly stay on Apache behind it.
- **Zero touch** — cPanel changes (new accounts, domains, certificates, PHP versions) apply by themselves;
  upgrades apply themselves; the PHP environment repairs itself.
- **WHM plugin** — dashboard, switch center, accounts, page cache, PHP, security (ModSecurity), HTTP/3, activity
  log, notifications, maintenance windows, updates, support bundle.
- **cPanel plugin** — page cache with one-click purge, PHP, object cache, logs, speed check, traffic history,
  `.htaccess` advisor, requests to the host.
- **Secure** — a small privileged broker, accounts isolated from each other, signed releases.

## Requirements

- AlmaLinux 9 (x86_64) with a licensed, working cPanel & WHM
- Root access

## Install

Run as root on the server:

```sh
d=$(mktemp -d) && curl --proto '=https' --tlsv1.2 -fsSL -o "$d/install.sh" "https://github.com/2tdv/OLS-cPanel-WHM/releases/download/0.2.11/install.sh" && echo "2b483993890bbf98045ab869e453bdf7e7d39fa13ab5fbbe37d57501125eef3c  $d/install.sh" | sha256sum -c - && sh "$d/install.sh"; rm -rf "$d"
```

The installer verifies the signed release before it changes anything, installs the packages and prepares the
server while Apache keeps serving your sites. It then shows the switch plan and waits for your approval — or switch
later from **WHM → Plugins → OLS-cPanel → Switch center**.

<details>
<summary>Stricter: verify the installer's signature first</summary>

```sh
d=$(mktemp -d) && mkdir -m 700 "$d/g" && export GNUPGHOME="$d/g" && curl --proto '=https' --tlsv1.2 -fsSL -o "$d/install.sh" "https://github.com/2tdv/OLS-cPanel-WHM/releases/download/0.2.11/install.sh" && curl --proto '=https' --tlsv1.2 -fsSL -o "$d/install.sh.asc" "https://github.com/2tdv/OLS-cPanel-WHM/releases/download/0.2.11/install.sh.asc" && gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 118DFA42F66A585D176C0B5148E26833CB82EAD1 && gpg --verify "$d/install.sh.asc" "$d/install.sh" && sh "$d/install.sh"; unset GNUPGHOME; rm -rf "$d"
```

Release signing key: `118DFA42F66A585D176C0B5148E26833CB82EAD1` ([public key](build/release/ols-cpanel-release-key.asc)).
</details>

## Upgrade and removal

- **Upgrade:** run the install command of the newer [release](https://github.com/2tdv/OLS-cPanel-WHM/releases).
  The product applies the upgrade by itself.
- **Remove:** `/usr/local/ols-cpanel/bin/ols-cpanel uninstall` returns the server to Apache and removes the
  product (backups and logs are kept).

## Documentation

| | |
|---|---|
| [Installation guide](docs/installation.md) | What the installer does, stage by stage; going back to Apache |
| [Object cache](docs/object-cache.md) | Valkey per account, WordPress and other applications |
| [Architecture](docs/product-architecture.md) | How the pieces fit together |
| [Interfaces](docs/product-interfaces.md) | Broker operations, gateways and command line (for developers) |
| [Releasing](docs/releasing.md) | How signed releases are built |

## Building from source

Builds run in pinned containers with rootless `podman`; see [docs/releasing.md](docs/releasing.md).
The full test suite: `python3 build/check/run.py`.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[GNU General Public License v3](LICENSE). OpenLiteSpeed is GPLv3; the PHP redis extension package is under the PHP
License 3.01.
