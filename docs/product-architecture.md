# Product architecture (release 1)

How the proven lab mechanisms become the installable product. Plan references: §5 (architecture and
privileges), §14–17 (events, hooks, generations), §18 (installation and cutover), §19 (return and
uninstall), §21 (WHM and cPanel plugins), §26 (CLI). Owner decisions: complete scope including the hybrid
profile (HR-D08), PHP engine plus a small Rust privileged component (plan §5.1), public source release.

The lab tools in `build/vm-qualification/` remain the reference implementation. Every product component
that replaces one is checked against it: byte-for-byte for configuration output (recorded real inputs in
`tests/Fixtures/lab-snapshot/`), and by running the same lab experiments against the product commands.

## Packages

| Package | Contents |
|---|---|
| `ols-cpanel-openlitespeed` | OLS 1.9.3 with the product patches (0001–0009), `ols-cpanel.service`, `ols-cpanel-logs.service`, reload helper, epoch start guard. No install scripts. |
| `ols-cpanel-php-redis` | phpredis (pinned) prebuilt for each EA4 PHP version with an index of PHP API numbers and build ids, plus its checksum-pinned source for building other versions on the server (`build/php-ext/`). No install scripts; `ols-cpanel php-ext` activates it. |
| `ols-cpanel` | PHP engine (`/usr/local/ols-cpanel/lib`, CLI `/usr/local/ols-cpanel/bin/ols-cpanel`, run with cPanel's own PHP), Rust `ols-cpanel-broker` and `ols-cpanel-activator`, the reconciler unit, the cPanel hook entry point, WHM and cPanel plugins with their built interface, the installer. Install scripts only place files; nothing is activated by the package manager. |

Release artifacts are signed; the one-command installer verifies them before running anything (§18.2.1).

## Processes and privileges (§5.2)

| Process | Runs as | Does |
|---|---|---|
| `ols-cpanel-broker` | root | The only privileged entry point: peer-credential checks, fixed operations, cPanel input reads from a fixed list (the engine's `CommandRunner`), tenant-identity reads of `.htaccess`, generation staging and activation through `ols-cpanel-activator`, service control, port changes for the hybrid profile, firewall rules. |
| `ols-cpanel-activator` | root, invoked by the broker | Generations, validation records, activation journal, restriction epoch, recovery and enforcement (port of `ols_generation.py` and `ols_stage_validate.py`). |
| `ols-cpanel-reconciler` | dedicated unprivileged user | Event spool consumer and periodic pass (port of `ols_events.py`): compiles through the engine, asks the broker to stage, validate and activate; a separate enforcement loop asks the activator to enforce the restriction deadline. |
| cPanel hook entry | root (cPanel) | Records events durably; raises the restriction epoch for security events; always answers `1`. |
| WHM gateway / cPanel plugin | root CGI / account user | Read views and, for root, approved jobs submitted to the broker with single-use capabilities. |

## Configuration engine

`ServerConfigurationBuilder` (PHP) reproduces the lab compiler: cPanel inventory (userdatadomains, userdata
including IPv6, suspension markers, PHP versions and handlers, FPM pools, `.htaccess` read as the tenant,
certificates, alias directories, Apache's per-address defaults and proxy bindings from `httpd.conf`, bound
IPv6 addresses) → server configuration (`ServerCompiler`) and one vhost configuration per cPanel vhost
(`vhostConfig`, or the hybrid pass-through vhost). Blockers decide the profile: none → native; any → hybrid
vhost when the hybrid profile is enabled, otherwise the installation refuses cutover.

## Generations and activation

Unchanged from the proven lab design (§17, `docs/g0g-generations.md`): immutable generations, validation
record bound to the tree and OLS binary, per-vhost health paths, journal with sequence numbers, restriction
epoch with high-water mark, rollback only to validated current generations, deadline enforcement (HR-D11,
300 s) independent of compilation, start guard in the unit.

## Installation and cutover (§18)

1. `ols-cpanel install --prepare`: preflight (`doctor`), backup of the cPanel/Apache state the product will
   touch, package payload verification, OLS installed but not started, first generation compiled and
   validated. Apache keeps serving.
2. Shadow test: OLS on loopback test listeners; the isolation/parity comparisons of the lab experiments run
   against Apache (`tenant_isolation_probe` logic) and must pass; the report lists hybrid vhosts.
3. `ols-cpanel install --cutover --plan=<id>`: native profile → Apache disabled and unmonitored, OLS takes
   80/443; hybrid profile → Apache moved to 81/444 through `apache_port`/`apache_ssl_port`, `mod_remoteip`
   include, firewall rule restricting 81/444 to local addresses, Apache restarted, OLS takes 80/443. Health
   verification of every vhost; automatic return on failure.
4. Steady state: hooks + reconciler; the WHM "Restart Apache" action is blocked with an explanation while OLS
   owns the ports (HR-D01).

## Return to Apache and uninstall (§19)

`ols-cpanel apache-return`: OLS stopped, Apache restored to 80/443 (ports, monitoring, include and firewall
rule removed), FileProtect resynchronised, health verified. `uninstall` additionally removes hooks, units,
plugins and packages, keeping cPanel's own configuration as it was before installation.

## Command-line interface (release 1 subset of §26)

`doctor`, `compatibility scan`, `plan create|show`, `install --prepare|--cutover`, `sync --all [--dry-run]`,
`config validate|diff`, `generation list|inspect`, `rollback`, `apache-return --prepare|--execute`, `hooks
verify`, `recover`, `status`, `uninstall [--dry-run]`. JSON output, documented exit codes, transaction IDs.

## State on disk

`/var/lib/ols-cpanel/`: `generations/`, `active` (symlink), `journal/`, `validations/`, `epoch.json`,
`epoch.high`, `events/` (spool), `plans/`, `backups/`. Root-owned; the reconciler has write access only to
its spool consumption through the broker.
