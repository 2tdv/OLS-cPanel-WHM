# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub's
**[Report a vulnerability](https://github.com/2tdv/OLS-cPanel-WHM/security/advisories/new)** form, with the affected
component, the version, steps to reproduce and the impact. You will get an answer as soon as possible, and a fix is
released before any details are published.

Problems found in OpenLiteSpeed or cPanel themselves are reported to those vendors privately first.

## Supported versions

Only the latest release receives security fixes.

## Design summary

- **Privileged broker:** the only privileged component the plugins reach. The administrator socket is root-only;
  the account socket identifies the caller from the kernel (`SO_PEERCRED`), never from the request. Fixed operations,
  no shell, bounded requests.
- **WHM plugin:** root only. **cPanel plugin:** runs as the account and can only see that account's own sites.
- **Account isolation:** PHP runs as the account user with the account's own group; one account cannot read
  another's files.
- **Signed releases:** the installer verifies the release signature and every package digest before installing.
