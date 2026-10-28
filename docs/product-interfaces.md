# Product interfaces (release 1)

The contracts between the product components of `docs/product-architecture.md`. Each component is built
and tested against this document; a change here comes first.

## Users, paths and units

| Item | Value |
|---|---|
| Engine user | `olscpanel` (system user, no shell, no home; `build/product/ols-cpanel.sysusers`) |
| Product root | `/usr/local/ols-cpanel` (`bin/ols-cpanel`, `lib/`, `libexec/ols-cpanel-broker`, `libexec/ols-cpanel-activator`) |
| State | `/var/lib/ols-cpanel` (root 0755; contents below) |
| Broker sockets | `/run/ols-cpanel-broker/admin.sock` (root), `tenant.sock` (any local user), `engine.sock` (root and `olscpanel`) |
| Units | `ols-cpanel.service` (OLS), `ols-cpanel-logs.service`, `ols-cpanel-broker.service` (root), `ols-cpanel-reconciler.service` (`olscpanel`, runs `ols-cpanel sync --watch`), the object cache units of "Object cache", `ols-cpanel-php.path`, `.service` and `.timer` ("PHP environment": lsphp, OPcache and the redis extension for every EA4 PHP version, root) |

State directory:

| Path | Owner | Content |
|---|---|---|
| `profile.json` | root 0644 | Deployment profile, written at cutover: `{"production": true, "hybrid_ports": [81, 444] \| null}`. Absent = not cut over. Malformed = every compile refuses. |
| `generations/`, `active`, `journal/`, `validations/`, `epoch.json`, `epoch.high`, `activation.lock` | root | Activator state (`ols-cpanel-activator`, formats of `ols_generation.py`). |
| `cache-purges.json` | root 0600 | LSCache purge ledger: `{<store name>: <unix time of its last purge>}`, written atomically by `cache purge` ("LSCache management" below). |
| `cache-limits.json` | root 0600 (operator input) | Optional limits of the automatic LSCache cleanup: `{"per_site_mb": 16..102400, "server_percent": 1..50, "server_max_gb": 1..2048}`, any key optional (defaults 512, 10, 20). Written by `cache limits --per-site-mb=.. ` (the WHM page cache view); a file that is not valid is not used (defaults apply) and the problem is reported, never a crash ("LSCache management", automatic cleanup). |
| `cache-clean.json` | root 0600 | Record of the last automatic cleanup: time, caps used, emergency flag, totals and files, bytes and failures removed per store; written atomically by `cache clean`. |
| `notify.json` | root 0600 | Notification settings (FV-07): `{"emails": [..], "webhook": "https://..." \| null, "events": [..], "enabled_since", "updated_at"}`. Written by the broker's `admin.notify_set` (the webhook URL may hold a secret and is never an argument, never shown again, never audited or logged). Absent or without a channel = notifications off. |
| `notify-ledger.json`, `notify.lock` | root 0600 | What `notify run` sent: key => time (de-duplication), the times of the last 24 hours (the daily limit), observed sets, the channels already delivered and the attempts per key and channel (only a failed channel is retried), the last ten messages and the last delivery error. |
| `schedule.json`, `schedule.lock`, `schedule-run.lock` | root 0600 | Maintenance windows (FV-07): `{"entries": [{id, action, scope, digest, at, window_minutes, state, claimed, created, updated, job, note}]}`. Every read-modify-write holds `schedule.lock` (5 s wait); a pass claims an entry (`claimed`) before its broker calls, so a cancel then is refused as already started; `schedule-run.lock` keeps passes from overlapping. |
| `update-check.json` | root 0600 | The last update check (15-minute cache). |
| `support/`, `support-salt` | root 0700, files 0600 | Support bundles `bundle-<10-digit time>-<8 hex>.tar.gz` (the last three are kept) and the per-server salt of the anonymizing placeholders. |
| `staging/` | root 0700 | Trees the broker writes for `engine.apply` before `activator stage`. |
| `events/`, `events/done/`, `events/quarantine/` | root 0700 | Hook spool (one JSON file per event). Read and consumed only through the broker; malformed entries are moved to `quarantine/`. |
| `restrictions/` | root 0700, files root 0600 | Durable restriction intents of the hook (format in "Locks, deadlines and recovery"). Folded into the restriction epoch by the broker and by every reconcile pass. |
| `plans/<id>.json` | root 0600 | Cutover plans from `install --prepare` (`schema_version` 2: `compile_sha256` covers the configuration and the sha256 of every referenced certificate, key and password file, listed in `referenced_files`). |
| `backups/<id>/` | root 0700 | Byte-exact copies of everything a cutover changes, `recover.sh`, `manifest.json`, `cutover.json` (outcome). |
| `tls/default.key`, `tls/default.crt` | root 0700 dir | The listeners' neutral self-signed default certificate, created by `install --prepare`. |
| `deployment.lock` | root:olscpanel 0640 | Exclusive for prepare, cutover, apache-return, hooks, uninstall and `recover.sh`; shared by every reconcile pass (lock order below). Only root and the reconciler's group may open it, so no other user can hold it. |

Identifiers: plans `p<YYYYmmddHHMMSS>-<6 hex>`, backups `c<YYYYmmddHHMMSS>-<6 hex>`, recovery unit
`ols-cpanel-recover-<backup id>`, generations `r<YYYYmmddHHMMSS>-<6 hex>`.

## Broker protocol

One JSON request per connection (newline-terminated, at most 64 KiB, 5 s to arrive), the existing
envelope `{"v": 1, "id": "<text>", "op": "<name>", "args": {...}}`, unknown fields rejected. Replies:
`{"v": 1, "id": ..., "ok": true, "result": ...}` or `{"v": 1, "id": ..., "ok": false, "error": {"code", "message"}}`.
Replies may be up to 32 MiB (compiler inputs). The caller identity is the peer UID (`SO_PEERCRED`).

### Engine socket (`engine.sock`, peer UID 0 or `olscpanel`)

| Operation | Arguments | Result |
|---|---|---|
| `engine.run` | `{"name": text, "argv": [text, ...]}` | `{"exit_code": int, "stdout": text, "stderr": text}`. Runs argv without a shell, `env` `PATH=/usr/bin:/bin:/usr/sbin LANG=C LC_ALL=C`, 120 s limit, output capped at 16 MiB (refused, not truncated, above it). argv must match the allowlist below exactly; anything else is `FORBIDDEN`. |
| `engine.apply` | `{"generation": "r<YYYYmmddHHMMSS>-<6 hex>", "files": {relative path: text}, "health": [{"vhost", "host", "url"}], "epoch": int, "source_sha256": hex64}` | Refuses an existing generation id; writes a new tree under `staging/`, then `activator stage`, `validate`, `activate`; returns `{"generation", "valid", "result", "reason"}` (the activator's words). Paths: `httpd_config.conf`, `vhosts/<vhost>/vhconf.conf`, `health/<vhost>/id`, `marker/generation` only; vhost names match the domain grammar; at most 64 MiB in total. The broker adds `health.json`, `EPOCH` and `SOURCE_SHA256` itself from the arguments. |
| `engine.status` | none | `activator status` output plus `{"source_sha256": <active generation's SOURCE_SHA256 or null>}`. |
| `engine.enforce` | `{"grace": int}` | `activator enforce --grace N` result. |
| `engine.health` | `{"seconds": int 0..60}` | `activator health --seconds N`: `{"generation": <active pointer or null>, "failing": [{"vhost", "got"}]}`, the vhost health of the active generation's `health.json` targets (checked by `sync` before keeping an unchanged generation). |
| `engine.recover` | `{"grace": int}` | `activator recover --grace N` result. |
| `engine.events` | none | `{"pending": [{"name", "event"}]}`: spool entries, oldest first (at most 1000). |
| `engine.events_done` | `{"names": [text]}` | Moves those spool entries to `done/`. Names must be spool file names. |
| `engine.events_quarantine` | `{"names": [text]}` (at most 1000) | Moves those spool entries, names as `engine.events` lists them (one directory entry of `events/` ending in `.json`, never a path, `.` or `..`; a symbolic link is moved as the link, never followed), to `events/quarantine/` (root 0700, created when absent; an existing name there is never replaced: the moved entry gets a `.<16 hex>` suffix). All names are checked before anything moves: a repeated or invalid name is `BAD_ARGS`, an absent one `NOT_FOUND`. Returns `{"quarantined": [names]}`. |
| `engine.restrictions_fold` | none | Folds every restriction intent of `restrictions/` into the epoch, oldest first (the order of spool names): `activator restrict <reason>` per intent, then the intent is removed (and the directory synced) only after `restrict` returned the raised epoch; a failed `restrict` stops the fold (`ACTIVATOR`) with that intent and the later ones kept. Returns `{"folded": [names], "epoch": <epoch after the last fold, or null when none>}`. The same function runs first in every round of the broker's enforcement thread. |

`engine.run` allowlist (every command the configuration builder runs; `<user>` is an account in
`/etc/userdatadomains` matching `[a-z0-9][a-z0-9_-]{0,31}`, never `root` or `nobody`; `<domain>` matches the
builder's domain grammar; `<version>` matches `[a-z][a-z0-9-]*`; `<path>` is absolute without empty, `.` or
`..` components (one trailing slash allowed) and is never resolved):

`/home*` is the product's one home policy (review RV-29, finding 11; PHP `Cpanel\Discovery\HomePath`, Python
`cpanel_vhosts.account_home`): a home mount is the single path component `home` followed by `[A-Za-z0-9_-]*`
directly below `/` (`/home`, `/home2`, `/home_ssd`, `/home-b`; not `/home.old`, `/newhome`, `/usr/home`, `/data`), and
an account's home is `/<mount>/<user>`. cPanel places homes under `HOMEDIR` and on mounts matching `HOMEMATCH`
(default `home`, which also admits mounts the product does not); account discovery refuses a document root outside
`/<mount>/<user>` ("unsafe document root"), the compiler's `vhRoot` is that home, and the allowlist below admits
exactly these mounts.

- `/usr/bin/cat <dir>/.htaccess` for `<dir>` = `/` or `/home*` (the root-owned directories above every home)
- `/usr/bin/cat /etc/userdatadomains`, `/usr/bin/cat /var/cpanel/userdata/<user>/<domain>`,
  `/usr/bin/cat /etc/apache2/conf/httpd.conf`, `/usr/bin/cat /opt/cpanel/<version>/root/etc/php-fpm.d/<domain>.conf`
- `/usr/local/cpanel/bin/whmapi1 --output=json <api>` for `listaccts`, `php_get_vhost_versions`, `php_get_handlers`
- `/usr/bin/test -e|-f|-d <path>` for `<path>` under `/var/cpanel/suspended/`, `/var/cpanel/ssl/`, `/home*/<user>/`,
  `/usr/local/cpanel/`, `/usr/local/bandmin/`, `/var/www/html/`
- `/usr/sbin/runuser -u <user> -- /usr/bin/cat <path>/.htaccess` and the `.htaccess` listing
  `/usr/sbin/runuser -u <user> -- /usr/bin/find -H <docroot> -name .htaccess ( -type f -o -type l ) -printf %y%p\0`,
  where the path lies in that user's home directory
- `/opt/cpanel/<version>/root/usr/bin/php -n -r <the builder's constant code, byte-identical>`
- `/usr/bin/hostname -f`, `/usr/sbin/ip -6 -o addr show scope global`
- `/usr/bin/systemctl start --no-block ols-cpanel-php.service` (exactly this argv; FV-10: the reconciler asks the root PHP
  environment service to run when a vhost's PHP version has no usable lsphp; at most once every two minutes, never fatal)
- `/usr/bin/systemctl start --no-block ols-cpanel-hybrid-trust.service` (exactly this argv; HR-D14: the reconciler asks the root
  hybrid trust service to run when a compiled vhost address is not in the installed `mod_remoteip` include; at most once every
  two minutes, never fatal)
- WAF and security inputs (FV-02; read only when the builder compiles with a security input):
  `/usr/bin/test -e /etc/apache2/conf.d/modsec2.conf`, `/usr/bin/test -e /etc/apache2/conf.modules.d/800-mod_security2.conf`,
  `/usr/bin/cat /etc/apache2/conf.d/modsec2.conf`, `/usr/bin/cat /etc/apache2/conf.d/modsec/modsec2.user.conf`,
  `/usr/bin/cat /etc/apache2/conf.d/modsec/modsec2.cpanel.conf`, and `/usr/bin/cat <vendor file>` where `<vendor file>` is
  `/etc/apache2/conf.d/modsec_vendor_configs/` followed by one or more `/`-separated components matching
  `[A-Za-z0-9_-][A-Za-z0-9_.-]*` (rule files end in `.conf`; data files referenced by `@pmFromFile`/`@ipMatchFromFile`
  may have any such name). Never resolved; no `.` or `..` components by the grammar.
- `/usr/bin/sha256sum <path>` for `<path>` under `/var/cpanel/ssl/`, and
  `/usr/sbin/runuser -u <user> -- /usr/bin/sha256sum <path>` for `<path>` under `/home*/<user>/.htpasswds/` (digests
  of the certificates, keys and password files a configuration references; the reconciler's source digest;
  tenant files only as the tenant)

Output that is not valid UTF-8 is decoded with each invalid sequence replaced by U+FFFD, by the broker and
by `LocalCommandRunner` alike, so a compile gives the same result through either path. Engine socket limits:
requests up to 64 MiB for `engine.apply` (64 KiB otherwise), 30 s to arrive, no per-UID rate limit (a compile
issues about 120 reads). Error codes: `FORBIDDEN`, `BAD_ARGS`, `TIMEOUT`, `OUTPUT_TOO_LARGE`, `SPAWN_FAILED`,
`EXISTS`, `NOT_FOUND`, `ACTIVATOR`, `TOO_LARGE`. `engine.events_done` returns `{"done": [names]}`; a malformed
spool entry is listed as `{"name", "error"}`; an invalid generation returns `result: "invalid"` with the
validator report as `reason`. Health URLs: `http://127.0.0.1:<port>/...`, `http://<IPv4>:80/...` or
`https://<IPv4>:443/...` (review RV-29, finding 12), the path `/.ols-cpanel-generation/<file>`, `<file>` one segment of
`[A-Za-z0-9._-]` not starting with a dot; `host` matches the domain grammar.

The broker keeps this list in one table with a test per entry; the PHP builder's test asserts that
every command of a recorded compile is accepted (`tests/Fixtures/lab-snapshot/compile-production.json`).

### Admin socket (`admin.sock`, root): jobs for WHM

Existing `server.status`, `inventory.accounts`, `cap.issue`, `cap.execute`. The capability actions
become product jobs; `cap.execute` starts `/usr/local/ols-cpanel/bin/ols-cpanel` with fixed argv and
returns `{"job": id}`; `job.status {"job": id}` returns `{"state": "running" | "done" | "failed", "exit_code", "output"}`
(the command's JSON output, at most 1 MiB). Jobs run one at a time.

| Action | Command |
|---|---|
| `ols.sync` | `ols-cpanel sync --format=json` |
| `ols.rollback` | `ols-cpanel rollback --format=json` |
| `ols.plan` | `ols-cpanel install --prepare --format=json` |
| `ols.cutover` | `ols-cpanel install --cutover --plan=<scope> --yes --format=json` (scope = plan id) |
| `ols.apache_return` | `ols-cpanel apache-return --execute --yes --format=json` |
| `ols.cache_purge` | `ols-cpanel cache purge (--all \| --account=<user> \| --domain=<domain>) --format=json`; scope `server` \| `account:<user>` \| `domain:<domain>` ("LSCache management") |
| `ols.php_restart` | `ols-cpanel php restart (--all \| --account=<user>) --format=json`; scope `server` \| `account:<user>` ("PHP manager") |
| `ols.opcache_install` | `ols-cpanel php opcache install (--all \| --version=ea-phpNN) --format=json`; scope `server` \| `version:ea-phpNN` ("PHP manager") |
| `ols.php_env_repair` | `ols-cpanel php env repair --format=json`; scope `server` ("PHP environment") |
| `ols.support_bundle` | `ols-cpanel support bundle --format=json`; scope `server` ("Operations", anonymized) |
| `ols.support_bundle_raw` | `ols-cpanel support bundle --no-anonymize --format=json`; scope `server` ("Operations", names and addresses kept) |

## Command-line interface (`ols-cpanel`, root unless noted)

Every command accepts `--format=json` (one JSON object on stdout) and otherwise prints text. Exit codes:
`0` success, `1` refused or failed with the reason reported, `2` audit-only or unsupported platform,
`64` usage, `70` internal error, `75` busy (another operation holds the lock). With `--format=json` every exit
prints exactly one JSON object on stdout (review RV-29, finding 17): the command's result, or for a usage error,
an internal error, a refusal or busy `{"result": "usage" | "internal" | "refused" | "busy", "code": <exit code>,
"error": <reason>}` (refusals add `"class"`, and `"engine_code"` for engine and broker error codes; deployment
commands add `"command"` and their details). `hook` is the one exception: it always prints exactly `1`.

| Command | Effect |
|---|---|
| `doctor [--read-only]` | Platform and readiness report (existing). |
| `status` | Server owner of 80/443, profile, active generation, pending events, epoch, hybrid vhosts. |
| `install --prepare` | Preflight (`doctor` rules), a full compile with `production: true` and the requested profile (configuration lint included, nothing staged), write `plans/<id>.json` (hybrid vhosts listed, ports, backups needed). Apache keeps serving. The hybrid profile is the default (HR-D14): the plan always carries `hybrid_ports` 81/444 (Apache in standby behind OLS, closed to the outside), needs Apache's `suexec_module`, and lists the vhosts that Apache serves today with their reasons (possibly none). Options: `--native` (explicit opt-out: no standby Apache; any untranslatable change then refuses the compile for safety); `--hybrid` is accepted as a no-op alias of the default; the two cannot be combined. Also (FV-10, reported under `php_environment`, never fatal): the PHP environment is made complete for every EA4 PHP version, the units that keep it so are enabled and the recommended EA4 profile is written. |
| `install --cutover --plan=<id> [--yes]` | Under the deployment lock: the plan read again and required unchanged since the approval, its full compile digest (configuration and referenced files) checked, and checked again immediately before the first host change; backups and `recover.sh`, recovery timer, hooks registered, hybrid changes (tweaks, `mod_remoteip` include, nftables table, Apache restarted on 81/444 and verified) in every default plan, with or without hybrid vhosts (only `--native` plans skip them), Apache off 80/443, `profile.json`, the activation of exactly the plan's digest (`ConfigurationActivator::activate(digest)` refuses any other compile), OLS started, health of every vhost, `cutover.json` written, then the timer disarmed and its recovery service verified stopped; any failure (the record and the disarm included) runs `recover.sh`. |
| `apache-return --prepare \| --execute [--yes]` | Runs the latest backup's `recover.sh` (OLS stopped, Apache restored and verified, profile removed), then the CLI removes the hook registrations (`recover.sh` does not depend on the product). `--execute` takes the deployment lock after the approval (waiting up to 900 s for a running reconcile pass), selects and validates the backup again under it and refuses one other than the approved; the recovery timer is disarmed only after Apache is verified serving, otherwise kept or armed again (10 min). |
| `sync [--watch] [--interval=N] [--force]` | Reconcile once (or as the service loop, with the 5 s enforcement thread). Runs as `olscpanel` through `engine.sock`, or as root directly. |
| `hook` | cPanel hook entry: reads the event on stdin, raises the restriction epoch for restricting events (or, when that fails, writes a durable restriction intent first), spools the event, always prints exactly `1`. |
| `hooks install \| verify \| remove` | Registers the product hook entry `/usr/local/ols-cpanel/libexec/ols-cpanel-hook` (a fixed wrapper running `ols-cpanel hook`; cPanel runs script hooks without arguments) on stage `post` for the events in `ols_events.RESTRICTING` and the account, domain, PHP, certificate and `.htaccess` change events (`Deployment\Hooks::EVENTS`), through `manage_hooks`. |
| `generation list \| inspect <id>`, `rollback`, `recover` | Activator views and operations. |
| `waf status`, `waf blocked [--limit=N]` | WAF state of the active generation with `security.json`'s exceptions, and the newest blocked requests (FV-02; formats under "WAF and security"). |
| `http3 status [--lines=N]` | HTTP/3 input, the UDP 443 firewall state (read-only inspection) and the HTTP/1.x, HTTP/2 and HTTP/3 share of each vhost of the active generation (FV-04, root; "HTTP/3"). |
| `objcache status [--account=U]`, `enable --account=U [--memory=MB]`, `disable --account=U`, `flush --account=U`, `configure-wordpress --account=U --path=DIR [--php=ea-phpNN]`, `package --name=P (--memory=MB \| --remove)`, `reconcile` | Per-account object cache (FV-09), root only; see "Object cache". |
| `php-ext status`, `install [--php=ea-phpNN]`, `remove`, `sync` | The PHP `redis` extension in every EA4 PHP version (root), see "PHP redis extension (object cache)". `remove` clears the wish to keep it active (the PHP environment service keeps running for lsphp and OPcache). |
| `hybrid refresh-trust` | Keeps the hybrid include `/etc/apache2/conf.d/ols-cpanel-remoteip.conf` trusting every local address of the host (root; HR-D14 follow-up). Result `{"command": "hybrid refresh-trust", "result": "not-hybrid" \| "unchanged" \| "updated" \| "failed", "trusted", "error"}`; `not-hybrid` (the include does not exist) changes nothing. The trusted list is loopback plus every address of `ip -o addr show` (IPv4, global IPv6; sorted, deduplicated), which is safe because the nftables table admits the backend ports only over loopback and only from root and OLS's user. A changed list is staged, installed 0644 root:root with a sha256 check, tested with `httpd -t` (on failure the previous include is put back and the exit code is 1) and Apache reloaded with `restartsrv_httpd --graceful`. Run by `ols-cpanel-hybrid-trust.service`, started by `ols-cpanel-hybrid-trust.timer` (boot plus 2 min, then every 15 minutes; enabled by `install --prepare`) and by the reconciler right after a pass whose compiled plan has an address the include does not list (the allowlisted `systemctl start --no-block`, at most once every two minutes). No operator action is ever needed after a new server IP or an account move to a new IP. |
| `php env status`, `php env sync`, `php env repair` | The PHP environment applier (root), see "PHP environment (EasyApache compatibility, FV-10)". `sync` is what `ols-cpanel-php.service` runs; `repair` (job `ols.php_env_repair`, the WHM button) ignores the back-off. |
| `notify show`, `notify set [--emails=a@x,b@y\|none] [--webhook=https://...\|none] [--events=a,b\|none]`, `notify test`, `notify run` | Notifications (FV-07, root; "Operations"). `run` is what `ols-cpanel-notify.timer` starts every five minutes; `set` is the command-line form of the WHM Notifications form (the WHM form is written by the broker so the webhook URL never appears in a process list). |
| `schedule list`, `schedule add --action=ols.cutover\|ols.apache_return --scope=<plan id>\|server --digest=<sha256> --at=<unix time> [--window=<minutes>]`, `schedule cancel --id=<id>`, `schedule run` | Maintenance windows (FV-07, root). `run` is what `ols-cpanel-schedule.timer` starts every minute. |
| `update check [--refresh]` | Installed versus available versions of the product packages and their rpm signature state (root, read-only; "Operations"). |
| `support bundle [--no-anonymize]`, `support list` | The redacted support bundle (root; "Operations"). |
| `cache stats [--account=U] [--domain=D]` | LSCache entries and bytes per store (root; "LSCache management"). |
| `cache purge (--all \| --account=U \| --domain=D)` | Deletes the entries of the selected stores and records the purge time of every store emptied completely (root); exit 1 with `result` `partial` or `failed` when a removal failed. `--account` may accompany `--domain` as an ownership check. |
| `cache clean` | The automatic LSCache cleanup (root; run hourly by `ols-cpanel-cache-clean.timer`, enabled by `install --prepare` and `upgrade`): removes expired entries, keeps every store under its cap and the server under its cap, trims harder on a nearly full disk, records the run in `cache-clean.json`; exit 1 (`result` `partial`) when a removal failed ("LSCache management"). |
| `cache limits [--per-site-mb=N] [--server-percent=N] [--server-max-gb=N]` | Shows the cleanup limits, the caps they give on this disk and the last cleanup (root); with options it saves the limits to `cache-limits.json` after checking the bounds (exit 1 outside them). |
| `cache clean-store --root=R --store=S --cutoff=T --cap=N --now=T` | Internal helper of `cache clean`, confined like `cache purge-store` (refuses to run as root). |
| `cache purge-store --root=R --store=S [--retire]` | Internal helper of `cache purge`: purges one store (retirement also empties obsolete index files) with the privileges of the process running it and refuses to run as root ("LSCache management", purge confinement). |
| `upgrade` | Applies `dnf upgrade ols-cpanel ols-cpanel-openlitespeed` (root). Nobody has to run it: `php env sync` (ols-cpanel-php.service, after every package transaction) starts `ols-cpanel-upgrade.service` when the installed versions differ from `upgrade.json` (the versions the last successful upgrade applied, root 0600 in the state directory) on a prepared host (broker enabled). `rpm -q` and `rpm -V` of both packages through the `CommandRunner` (a missing package, or files that differ from the package, refuse before anything is restarted), then one `systemctl daemon-reload` (the RPM has no scriptlets, so changed unit files are loaded here; a failing reload refuses the upgrade before any plugin deployment, enable or restart: RV-31 item 13), then `systemctl restart` of `ols-cpanel-broker.service` and `ols-cpanel-reconciler.service`, broker first, each only when it is enabled or active, and a check that each is active again (10 s). Result `{"command": "upgrade", "result": "upgraded" \| "failed", "packages": [{package, version, verified}], "units": [{unit, enabled, was_active, action: "restarted" \| "skipped", active}]}`; exit 1 when a unit does not come back. The active generation is never touched. When OLS runs and its main process executes a binary the package replaced (`/proc/<pid>/exe` ends in ` (deleted)`), `systemctl reload ols-cpanel.service` restarts it gracefully (no dropped connection) and the result's `ols` is `reloaded`; otherwise `current` or `not-running` (`failed` when OLS does not come back, exit 1). A successful run records the installed versions in `upgrade.json`. |
| `php restart (--all \| --account=U)` | Ends the `lsphp` processes so OLS starts new ones that read new PHP extensions and INI files (a graceful OLS reload keeps detached lsphp processes). The original cohort is captured first (`pgrep -x lsphp`, with `-u U` for one account, each pid with its start time, field 22 of `/proc/<pid>/stat`); only that cohort is signalled (`kill -TERM -- <pid>`, then `kill -KILL -- <pid>` after 5 s for the survivors, each pid re-checked against its start time right before the signal, so a reused pid is never touched) and waited for; replacement processes started meanwhile are never signalled and never make the restart fail, and a zombie counts as gone. An account must be a system account with uid 500 or above (never root or another system user). Result `{"command": "php restart", "result": "restarted" \| "failed", "scope", "account", "found", "killed", "killed_with_sigkill", "remaining"}`. |
| `php status [--account=U]` | What the PHP views show in one answer (root, read only): `opcache` (as `php opcache status`), `processes` (as `php processes`, per account without the process rows unless `--account` is given) and `limits`; see "PHP manager". |
| `php processes [--account=U]` | lsphp processes per account with runaway detection (root, read only); see "PHP manager". |
| `php opcache status [--version=ea-phpNN]`, `php opcache install (--version=ea-phpNN \| --all)`, `php opcache reconcile` | OPcache per EA4 PHP version (root); see "PHP manager". `install --prepare` also installs OPcache everywhere unless `--no-opcache` is given. |
| `uninstall [--dry-run] [--keep-packages]` | `apache-return` when cut over or when Apache is not verified serving (refused without a backup), then Apache verified serving before anything is removed; hooks removed, units stopped (a unit that does not stop aborts); LiteSpeed Cache's object cache turned off as the site owner on the sites the product set, only while their object host is still the product socket (a failure is an action with `ok: false`, never fatal); instances stopped; per-account systemd drop-ins removed with one `daemon-reload`; the product's OPcache and redis INI files removed (marker line only); state kept in `backups/` only; then, unless `--keep-packages`, `systemd-run --unit=ols-cpanel-remove-packages --no-block --collect /usr/bin/dnf -y remove <installed product packages>`. Kept: backups, logs, the `olscpanel` user, the OPcache packages. |

## Engine classes (PHP, `OlsCpanel\`)

- `Infrastructure\Process\CommandRunner` (existing interface): `LocalCommandRunner` (root; `proc_open`
  with an argv array, fixed environment, timeout; every command leads its own session and process group through
  `/usr/bin/setsid`, and the whole group is killed at the time limit or above the output limit; a start failure,
  recognized without taking a program's own exit 127 for one, is `SPAWN_FAILED` in strict mode) and
  `Broker\BrokerCommandRunner` (`engine.run`).
- `Ols\Compiler\ServerConfigurationBuilder` (existing; `hybridPorts` from the profile).
- `Ols\Generation\GenerationTree`: compiled configuration → `engine.apply` arguments (port of
  `ols_generation_probe.generation_tree` for production listeners: health requests go to the vhost's
  own IPv4 address on port 80 with its host name, since a multi-address server has no tenant vhost on
  `127.0.0.1`).
- Health targets: account and service vhosts on their own IPv4 address on port 80 with their own host name (the
  health context also admits that address); the proxy and default vhosts on 127.0.0.1 with
  `cpanel.ols-health.invalid` / `ols-health.invalid`; a vhost no port-80 listener maps (a hybrid domain's `tls.<domain>`)
  is checked over TLS on port 443 by the same rules (own address first): `https://<IPv4>:443/.ols-cpanel-generation/id`
  with the domain as `host` (review RV-29, finding 12; activator contract in "Locks, deadlines and recovery"). Only a
  vhost no IPv4 listener on 80 or 443 maps gets no target ("unprobed", validation only). The listener certificate is
  `tls/default.key` / `tls/default.crt` in the state directory.
- `Events\Reconciler`: port of `ols_events.reconcile` and `watch` (restriction intents folded first; source digest
  over configuration, vhosts, epoch and referenced certificate/key/password files; recover with grace when
  incoherent; unchanged and healthy → no activation; valid events marked done after a committed activation or an
  unchanged and healthy pass; malformed entries quarantined at once).
- `Events\HookEntry`: port of `ols_events.hook` (restriction intent when the epoch cannot be raised).
- `Ols\Generation\Engine` (interface, written): `BrokerEngine` and `LocalEngine`. `Deployment\ConfigurationActivator`
  (interface, written): the reconciler's forced pass, used by cutover after `profile.json` is written, under the
  cutover's exclusive deployment lock; `activate(?string $expectedDigest)` refuses (`ReconcileRefused`, nothing
  applied) a compile whose `CutoverPlan::digest` (configuration plus referenced-file digests) differs from the plan's.
- `Deployment\Profile` (written), `Deployment\CutoverPlan`, `Deployment\Cutover`, `Deployment\ApacheReturn`,
  `Deployment\RecoveryScript` (port of `hybrid_lab.recovery_script`), `Deployment\HybridHost`
  (tweaks, `mod_remoteip` include, nftables table; texts from `hybrid_lab`).
- `Cli\Application` with one class per command under `Cli\Command\`.

The lab tools stay the reference: shared texts (`remoteip_conf`, `nft_ruleset`, recovery script,
generation tree files) are checked byte-for-byte against the Python functions in tests.

## Account lifecycle hooks

Every registration uses stage `post`; `Deployment\Hooks::EVENTS` and `ols_events.EVENTS` are checked for exact equality.
The hook spools a reconcile event; the reconciler compiles the complete current cPanel inventory, so account names,
main domains and addresses replace their previous configuration automatically. A successful explicit empty account
array removes the final tenant's vhosts while keeping the cPanel proxy and default vhosts; missing API data still refuses.

| Category | Event | Additional automatic work |
|---|---|---|
| `Whostmgr` | `Accounts::Modify` | Queue username migration from `data.user` to `data.newuser` when they differ; start account-state and hybrid trust passes. Main-domain and IP changes use this same hook. |
| `Whostmgr` | `Accounts::SiteIP::set` | Start `ols-cpanel-hybrid-trust.service` with `systemctl start --no-block` so Apache trusts the new local address. |
| `PkgAcct` | `Restore` | Apply the restored account's object cache package after restoration finishes, and refresh hybrid trust. |
| `Whostmgr` | `Transfers::Session` | Reconcile after a Transfer Tool session and apply account state and hybrid trust, without needing an account identity in the session payload. |
| `Whostmgr` | `Accounts::Create`, `Accounts::Remove` | Apply package settings on creation; removal, including after transfer away, stops and removes the old instance and orphan state. Removal also raises the restriction epoch. |

A rename is durably recorded in `account-renames/<nanoseconds>-<random>.json` (root directory 0700, file 0600;
only `olduser` and `newuser`, no complete hook payload). The root `ols-cpanel-objcache.service` processes these jobs
under `objcache.lock` before pruning orphans. They are independent of the OLS event spool: a successful vhost activation
cannot acknowledge a failed migration. Failed jobs stay for the next pass; chained renames resolve to the final name.
The destination must exist in cPanel with a usable home and the source must be absent before migration proceeds.

Migration stops the old instance before removing its configuration and drop-in, moves explicit object cache settings
(including opt-outs), translates recorded WordPress paths to the new home, and moves per-account PHP limits while
preserving defaults and runaway thresholds. Existing destination overrides take precedence. The new Valkey instance
and its socket directory are created by the ordinary desired-state pass, as the new account. Cached objects are disposable;
no cache data is copied. WordPress records retain the previous product socket until it has been replaced successfully;
an unrelated site-owner connection remains untouched. Sites and disabled or suspended accounts follow the ordinary pass.

Page-cache stores are purged and recreated under the new `<user>@<vhost>` name rather than renamed: cached responses
and shared-memory indices must not cross account or domain identities. The hourly cache pass compares stores with the
active generation summary, empties obsolete stores (including index files) through the confined owner helper, then
removes only their empty top-level directories as root. A missing or malformed summary cannot authorize retirement.
Root never recursively deletes cache contents. This also removes stores after a main-domain change or account removal.

Prepare and upgrade enable the account-state timer even without object cache settings. Its 60-second passes prune
object cache and WordPress entries and PHP overrides for accounts absent from the authoritative cPanel inventory;
failed instance stops retain configuration so the next pass can retry. Hooks start the pass without waiting and still
answer exactly `1` on failure. No customer or operator CLI action is needed. Verified server-source paths and the
registry access limitation are recorded in [g0f-hooks.md](g0f-hooks.md).

## Object cache (FV-09)

A Valkey (Redis-compatible) instance per account, for WordPress and other PHP applications of that account.
Engine: Valkey 8.0.x from AlmaLinux 9 AppStream (`valkey`, `/usr/bin/valkey-server`, `/usr/bin/valkey-cli`;
EPEL is not needed). The binary names are the constants `ValkeyConfig::SERVER` and `CLI` and the unit template's
`ExecStart`; on a platform without the package the same configuration and unit run Redis 6/7 from AppStream
(`/usr/bin/redis-server`, `redis-cli`) after changing those three places. The package does not depend on
Valkey; `objcache status` reports `engine.present`.

**Where things live** (all per account `<u>`, home `<h>` = `/home<suffix>/<u>` as `Cpanel\Discovery\HomePath`):

| Path | Owner / mode | Content |
|---|---|---|
| `/var/lib/ols-cpanel/objcache.json` | root 0644 | Desired state (below), written atomically. |
| `/var/lib/ols-cpanel/objcache/<u>/valkey.conf` | root 0644, directory root 0755 | Generated configuration (text contract: `tests/objcache.php`). Root-owned so the account cannot raise its limit or re-enable a renamed command. No secrets. |
| `/etc/systemd/system/ols-cpanel-objcache@<u>.service.d/50-account.conf` | root 0644 | `ReadWritePaths=<h>/.ols-objcache` and `MemoryMax=<ceil(1.25 x memory_mb) + 32>M`. |
| `<h>/.ols-objcache/` | `<u>:<u>` 0700 | Socket directory (created and removed as the account, never by root). |
| `<h>/.ols-objcache/valkey.sock` | `<u>` 0600 | The only listener (`port 0`). |

**Why the socket is in the account's home.** lsphp runs as the account and, under CageFS (CloudLinux), sees the
account's own home inside the cage but not `/run` or `/var/lib`; a socket below the home is reachable by that
PHP with no CageFS mount configuration. The directory is 0700 owned by the account and the socket 0600, so no
other account (nor lsphp of another account, nor a CageFS cage of another account) can traverse or connect;
root can, as always. Everything running as the account (its PHP, cron, SSH) can use the cache; that is the
intended trust boundary. Root never follows account-controlled paths: the directory is created and removed with
`runuser -u <u> -- install -d -m 0700` / `rm -rf --`, and a symbolic link in its place is refused. A path longer
than 100 bytes (`sun_path`) is refused.

**Configuration** (`ValkeyConfig::render`): `port 0`, `unixsocket <h>/.ols-objcache/valkey.sock`,
`unixsocketperm 600`, `protected-mode yes`, `dir <h>/.ols-objcache`, `maxclients 256`, `timeout 300`,
`maxmemory <N>mb`, `maxmemory-policy allkeys-lru`, `save ""`, `appendonly no`, and `rename-command <C> ""` for
`CONFIG DEBUG MODULE REPLICAOF SLAVEOF FAILOVER SAVE BGSAVE BGREWRITEAOF SYNC PSYNC` (`FLUSHALL`/`FLUSHDB` stay: the
account's own flush). Memory limits are whole MB from 16 to 8192 (default 64).

**Unit** `ols-cpanel-objcache@<u>.service` (template `build/product/ols-cpanel-objcache@.service`, no `[Install]`):
`User=<u>` `Group=<u>`, `ConditionPathExists=` the configuration, `NoNewPrivileges`, empty capability sets,
`ProtectSystem=strict`, `ProtectHome=read-only` with the account's socket directory re-opened by the drop-in's
`ReadWritePaths`, `PrivateTmp`, `PrivateDevices`, kernel and cgroup protections, `RestrictAddressFamilies=AF_UNIX`,
`MemoryDenyWriteExecute`, `MemorySwapMax=0`, `MemoryMax` (drop-in), `TasksMax=64`, `CPUQuota=100%`,
`Restart=on-failure` with 5 starts per 300 s. The unit name's instance is the account name (validated against
`^[a-z0-9][a-z0-9_.-]{0,31}$`, not `root`, no `..`).

**State** `objcache.json`: `{"schema_version": 1, "defaults": {"memory_mb": 64}, "packages": {"<cPanel package>":
{"memory_mb": N}}, "accounts": {"<u>": {"enabled": true|false, "memory_mb": N, "origin": "automatic" (optional)}}}`. An account's
instance is wanted when its entry has `enabled: true`, or it has no entry and its cPanel package (`PLAN=` in
`/var/cpanel/users/<u>`) is listed with a memory above 0. `enabled: false` is the administrator's durable "off" (`objcache disable`):
it opts the account out of its package and out of the automatic mode until `objcache enable` replaces the entry. A package with
`"memory_mb": 0` is switched off for its accounts (no package instance, no automatic one). An entry with `"origin": "automatic"` was
created by the automatic mode (below); an entry without `origin` was set by the administrator, and the automatic mode never
changes it. The optional top-level `"automatic": false` turns the automatic mode off (absent: on; only `false` is ever written),
and the optional `"discovery": {"<u>": <unix time>}` records when the pass last looked for WordPress with LiteSpeed Cache in an
account without an object cache. The optional key `"wordpress": {"<u>": {"<install dir>": {"state":
"automatic"|"owner"|"inactive"|"error", "product_set": bool, "checked": <unix time>, "php": "ea-phpNN"|null, "error": text|null, "previous_socket": <old product socket, optional>}}}`
records the WordPress sites (see "WordPress sites with LiteSpeed Cache"); it is absent while nothing is recorded. Malformed
state is refused, never replaced.

**Automatic mode (on by default).** A customer who switches LiteSpeed Cache's object cache on with the plugin's defaults
(Redis, `localhost:6379`) got "Connection Test: Failed" while their account had no instance (lab finding on 0.2.1); the
automatic mode makes that work without the customer or the administrator doing anything, and never with one Redis shared by
all accounts. Every reconcile pass looks, as the account, for a WordPress installation with the LiteSpeed Cache plugin
directory (`wp-content/plugins/litespeed-cache`, through the same search as below: the domain table read once per pass, one
`find` per document root, one `test -d` per site; never wp-cli) in accounts that have no entry, no package setting and are not
suspended (nothing is looked at while the suspension state is unknown). Each such account is looked at at most every
`DISCOVERY_INTERVAL` (600 s), at most `DISCOVERY_PER_PASS` (20) accounts per pass (never looked at first, then the longest
unseen), inside the pass budget. A hit gets the entry `{"enabled": true, "memory_mb": <default>, "origin": "automatic"}` and is
then handled exactly like an enabled account: its instance is started and its WordPress sites are set up. An automatic entry is
removed (instance stopped and removed, the product's sites switched off first) when the account's last WordPress with LiteSpeed
Cache is gone (judged from the site records of the pass: an installation not looked at yet, or whose look failed, keeps it),
when its package gets a setting of its own (memory 0: off; memory above 0: the package takes it over) or when the mode is turned
off. `objcache enable` turns an automatic entry into the administrator's; `objcache disable` records the durable "off". A rename
migration replaces an automatic entry the new name got meanwhile with the old name's entry.

**Lifecycle and privilege.** The reconciler (`olscpanel`) has no authority over systemd units and the broker gets
no operation that manages instances (`admin.objcache` only reads and switches the automatic mode): `objcache reconcile` is a root, level-triggered, idempotent pass run by the oneshot unit
`ols-cpanel-objcache.service` (root; `ProtectSystem=full`), started by `ols-cpanel-objcache.timer` (60 s, and 60 s
after boot) and, without waiting (`systemctl start --no-block`), by the cPanel hook entry (root) after
`Accounts::suspendacct`, `unsuspendacct`, `Remove`, `change_package`, `Create`, `Modify`, `PkgAcct/Restore` and
`Transfers::Session`, including when `objcache.json` does not yet exist (a failure only
leaves it to the timer; the hook still prints `1`). One pass reads the cPanel account list (`grep -rH ^PLAN=
/var/cpanel/users`), the suspension markers (`/var/cpanel/suspended`), `getent passwd` and `systemctl list-units`, then
per account: wanted and not suspended, instance running with current files (written only on change; a changed file
restarts, a failed unit is `reset-failed` and restarted); wanted and suspended, stopped, files kept; not wanted or account gone, stopped,
drop-in and configuration removed, socket directory removed as the account while its home exists, the explicit
state entry of a gone account dropped. The units are installed by the package; prepare and upgrade enable the timer automatically
(`systemctl enable --now`), and enabled accounts also ensure that it runs. Passes and CLI mutations serialize on
`/var/lib/ols-cpanel/objcache.lock`.

**WordPress sites with LiteSpeed Cache (automatic; no CLI step for customers or operators).** After the instance of an
account is running (not suspended), `objcache enable` and every `objcache reconcile` pass find the account's WordPress
installations: the document roots of the account's own rows of `/etc/userdatadomains` (path validated against the home, as
for `configure-wordpress`), searched as the account with `find -P <docroot> -mindepth 1 -maxdepth 2 -name wp-config.php -type f`
(`wp-config.php` in the root and one directory below; no link is followed; at most 25 sites). Per site, first the cheap look,
as the account and without running PHP (wp-cli boots all of WordPress: about 9 s of CPU per call on a WooCommerce site, lab
2026-10-28): no `wp-content/plugins/litespeed-cache` directory is `inactive` (or `owner` when another object cache drop-in is
installed); LiteSpeed Cache's drop-in `wp-content/object-cache.php` (its `litespeedtech.com` header) with its runtime
configuration `wp-content/.litespeed_conf.php` (or `.dat`) pointing to this account's socket, `object-kind` true and port 0 is
`automatic`; another drop-in, or a configuration with another host, is `owner`. Only when the files cannot tell (no drop-in: the
object cache is off) does wp-cli run, with `--skip-themes`, as the account with the
wp-cli argv above and the PHP version of the serving domain: `plugin is-active litespeed-cache` (exit 1 without an error text:
state `inactive`; anything else is `error`), then `litespeed-option get object`. Object cache off, or on with `object-host` equal to
this account's socket: when `object-kind` is 1 and `object-port` is 0 nothing is written (`automatic`), otherwise
`object-kind 1`, `object-host <socket>`, `object-port 0`, `object true` are set (the redis extension must be loaded in that PHP;
if it is not, the site is an `error` until it is). LiteSpeed Cache's own defaults are nobody's choice and are treated like this
account's socket: `object-host` `localhost`, `127.0.0.1` or empty together with `object-port` `6379` or empty (in the runtime
configuration too, where the cheap look then leaves the decision to wp-cli). Object cache on with any other host or port (or
Memcached): `owner`, left untouched and never turned off by the product. `product_set` is true where the product's settings are in place. Timing: `enable` looks at once;
a pass looks at a site every 15 min (the cheap look), retries a site with an error after 5 min doubled per failed attempt
up to a day, asks wp-cli again about an `inactive` plugin only when the names LiteSpeed Cache creates in `wp-content` (plugin
directory, `advanced-cache.php`, drop-in, runtime configuration) changed or after a day, runs at `Nice=19`, `CPUWeight=10` and the
idle I/O class, spends at most 200 s per pass and 150 s per
site, and a site's error is recorded (not an error of the pass; `objcache status` shows it). When the cache is disabled
(`disable`, a package removed, an explicit opt-out), the account is suspended or removed, sites with `product_set` get `litespeed-option set
object false` (a removed installation or an inactive plugin is only forgotten); a failed turn-off stays recorded and the pass
retries it; sites of the owner are never changed. After the cache is enabled or unsuspended, discovery sets sites up again.
`ols-cpanel-objcache.service` therefore allows AF_INET and AF_INET6 (a WordPress database may be on TCP). `objcache status`:
per account `socket`, `connection` (`{"host": <socket path>, "port": 0, "password": null}`) and `wordpress` (`[{path, state,
configured_by_product, checked_at, php, error}]`); `objcache enable` returns `wordpress` too. The cPanel plugin reads the same
through `tenant.objcache` ("Tenant socket operations").

**Fails closed (RV-31).** *Suspension.* The marker directory listing is an observation that can fail: a failed listing
(the directory exists but `ls` fails) or a failed per-account marker test (`test -e` with any exit code other than 0 or 1)
is an error, never "nobody is suspended". With the suspension state unknown an instance is never started or restarted (each
wanted account is an error of the pass, a running instance is left as it is, `enable` refuses) while removals of accounts that
are no longer wanted continue; a missing marker directory is an authoritative empty set. For a suspended account the stop
comes BEFORE any configuration is written, its exit code is checked, and `systemctl is-active` must then report it stopped
(else an error and the next pass tries again), so a filesystem failure cannot keep a suspended account's cache alive.
*Account list.* An empty `PLAN=` result is read as "zero accounts" only when it is authoritative: `grep` exited 1 (no match,
no error) with empty output and `/var/cpanel/users` is a readable directory (`test -d`, `ls`); then, after the last account is
removed, every instance is stopped, its files and its explicit state entry are removed. An unreadable directory, a failed
`grep` (exit 2) or any other failure refuses the pass ("cannot read the cPanel account list; nothing was changed").
The pass also enables the object cache timer when it is off (a failure to do so is an error of the pass) and, when the PHP
extension is wanted, enables the units of the PHP environment pass again and starts a pass if an administrator switched them off.

**Commands** (root; `--format=json` result objects):
`objcache enable --account=U [--memory=MB]` validates the name, that `/var/cpanel/users/U` exists, the uid
(>= 500) and the home, records the state, writes the files, creates the socket directory as the account, starts
(`systemctl restart`, so a new limit applies) unless suspended, and enables the timer (an earlier "off" or an automatic entry
becomes the administrator's enable); `disable --account=U` stops, removes files and the socket directory and records the durable
"off" `{"enabled": false, "memory_mb": N}` for an existing cPanel account (packages and the automatic mode leave it off;
`unchanged` when it was off already);
`flush --account=U` runs `valkey-cli -s <socket> FLUSHALL` as the account; `status` lists accounts and engine
presence, `automatic` (the mode) and per account `origin` (`automatic`, `administrator`, `package`, `disabled`, `package_off`
or null: nothing decided), `status --account=U` adds package, `origin`, `automatic`, suspension, state and `usage` (`used_memory`,
`maxmemory`, `keys`, `evicted_keys`, `keyspace_hits`, `keyspace_misses`, `hit_rate`, `connected_clients`, `uptime_seconds`);
`package --name=P --memory=MB | --off | --remove` enables a package, switches it off (`--off` or `--memory=0`, result
`package_off`) or removes its setting; `auto --on | --off` turns the automatic mode on or off (result `automatic_on`,
`automatic_off` or `unchanged`; it starts a pass without waiting, and off removes only automatic accounts); `reconcile` (exit 1 with
`"result": "errors"` when an account failed). `configure-wordpress --account=U --path=DIR [--php=ea-phpNN]`
(kept for support and automation; the product does this for every site by itself, see above)
requires an enabled cache, `DIR` inside the account's own home (no `.`/`..` components, no trailing slash), a
`wp-config.php`, the PHP `redis` extension (activated automatically when missing, see "PHP redis extension"), and the PHP version of the account's main
domain (`whmapi1 php_get_vhost_versions`) unless `--php` is given. It runs, as the account, with the argv
`/usr/sbin/runuser -u U -- /usr/bin/env HOME=<h> WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1 WP_CLI_CACHE_DIR=<h>/.ols-objcache/wp-cli-cache
/opt/cpanel/ea-phpNN/root/usr/bin/php -d memory_limit=512M /usr/local/bin/wp --path=DIR`, followed by `plugin
is-active litespeed-cache`, then `litespeed-option set object-kind 1`, `object-host <socket>`, `object-port 0`,
`object true`.

## PHP redis extension (object cache)

The object cache needs the PHP `redis` extension in the PHP version of every account that uses it. cPanel has no
EA4 package for it (the only cPanel route is a PECL compile on the customer's server), so the product delivers it
itself, in three layers, with no manual step and no download on the customer's server. Code: `src/PhpExtensions/`;
build pipeline: `build/php-ext/` (modelled on `build/ols-source/`).

**Package `ols-cpanel-php-redis`** (required by `ols-cpanel`; files only, no scriptlets, nothing under `/opt/cpanel`):

| Path | Content |
|---|---|
| `/usr/local/ols-cpanel/php-ext/redis/<ea-phpNN>/redis.so` | phpredis (pinned release) compiled against that EA4 PHP's own development package, no igbinary/msgpack/lzf/zstd/lz4. |
| `/usr/local/ols-cpanel/php-ext/redis/index.json` | `{"schema_version": 1, "extension": "redis", "extension_version", "source": {"file": "src/phpredis-<ver>.tgz", "sha256"}, "versions": {"ea-phpNN": {"so", "sha256", "size", "php_api", "build_id", "built_with"}}}`. `php_api` is the PHP API number (for example `20230831`), `build_id` the zend extension build id (`API20230831,NTS`), as `php -n -i` prints them (`PHP API`, `PHP Extension Build`). |
| `/usr/local/ols-cpanel/php-ext/redis/src/phpredis-<ver>.tgz` | The pinned, checksum-verified phpredis source, so any other EA4 PHP version can be built on the server without a download. |

**Build** (`python3 build/php-ext/build.py`, then `package.py <build dir>`; rootless podman, nothing on the host):
the builder image is the digest-pinned image of the OLS package; cPanel's public EA4 repository definition
(`build/php-ext/EA4.repo`, a copy of `/etc/yum.repos.d/EA4.repo`; the vendor variable `os_name_prefix` is set to
`c`) and its signing key (fingerprint pinned in `source.json`) are used inside the container. The tarball
(`pecl.php.net`, sha256 in `source.json`) is downloaded inside the container and refused unless it matches. For
every version in `source.json` `php_versions` (currently `ea-php81` to `ea-php85`): `ea-phpNN-php-devel` and `-cli`
are installed, `phpize`, `configure --with-php-config=...`, `make -j 2`, `strip`; the result must load into that
PHP (`php -n -d extension=... -m`, `--ri redis` reports the pinned version) and the build id found in the `.so`
must equal the PHP's `PHP Extension Build`, else the build fails. EA4's `php-config` has no `--phpapi`; the API
number comes from `php -n -i`. Two independent builds produced byte-identical `.so` files, and the RPM is
deterministic for the same objects (payload with fixed owner and times, `SOURCE_DATE_EPOCH` clamping).
`release_inputs_sha256` in `build/php-ext/source.json` guards the release counter exactly as for the OLS package
(`tests/php_ext_build.py`).

**ABI stability.** PHP's API number and build id change with the PHP minor series (8.2 to 8.3), not with patch
releases: a prebuilt build keeps loading across ordinary EA4 updates of the same series (a 8.2.34 to 8.2.35
update keeps `API20220829,NTS`). The installer therefore compares the numbers instead of assuming; when they differ
(a different build flavour, a new series) the next layer applies.

**Activation** (`ExtensionInstaller`, root, every command through the `CommandRunner` with a fixed argv). For each
installed EA4 PHP (`/opt/cpanel/ea-phpNN/root/usr/bin/php` exists), in this order, until the extension loads:

1. `php -m` lists `redis` and the product's INI is absent: loaded by other means (EA4 package, PECL, the
   operator's own INI): never touched (`already_loaded`).
2. The prebuilt build, when its `php_api` and `build_id` equal those of `php -n -i`, its file matches the
   recorded SHA-256 and size.
3. An earlier local build of this server (`/var/lib/ols-cpanel/php-ext/redis/index.json`, same schema) with the same ABI.
4. A new local build: the packaged tarball is verified against `index.json`, `ea-phpNN-php-devel` (and `gcc`,
   `make`, `autoconf` when missing) installed with `/usr/bin/dnf -y install` from the server's own repositories
   (cPanel's EA4 repository is configured on every cPanel server) as root, then the compile runs UNPRIVILEGED (RV-31):
   extraction, `phpize`, `configure --with-php-config=... --disable-redis-*` and `make -j2` are each one transient
   systemd service (`systemd-run --quiet --wait --pipe --collect --unit=ols-cpanel-ext-build-<random>`, one name for the
   four steps) with `DynamicUser=yes`, a private `StateDirectory=` (0700, the only writable place), `ProtectSystem=strict`,
   `ProtectHome=yes`, `PrivateTmp`, `PrivateDevices`, `PrivateNetwork=yes`, `NoNewPrivileges`, an empty
   `CapabilityBoundingSet`, `RestrictAddressFamilies=AF_UNIX`, `MemoryMax=2G`, `MemorySwapMax=0`, `TasksMax=256`,
   `LimitNOFILE=4096` and `RuntimeMaxSec=` the step's timeout. Root then only copies the finished `redis.so` (a regular
   file inside that directory, not a link, at most 64 MB), verifies the SHA-256 of the copy, installs it to
   `/var/lib/ols-cpanel/php-ext/redis/<ea-phpNN>/redis.so`, records it in the local index, and loads it (the activation
   check below). The unit is stopped and the build directory removed afterwards, also on failure, and leftovers of an
   interrupted build (`ols-cpanel-ext-build-*` below `/var/lib/private`) are pruned before the next build. Without
   `/usr/bin/systemd-run` (or when a step's sandbox cannot start) the build fails with "never compiled with root authority":
   there is no fallback that compiles as root.

**PHP 7.4 and newer only.** The packaged phpredis 6.3.0 requires PHP 7.4, so an EA4 PHP older than 7.4 (`ea-php54` to
`ea-php73`) is never built for and never activated (`php-ext status`/`install` row `status: "unsupported"`, `message:
"unsupported for the object cache: ..."`; the PHP environment row shows `redis: "unsupported"`, the WHM view "Unsupported (needs PHP
7.4 or newer)"; `objcache enable` and `configure-wordpress` report it as the reason). It is a permanent, visible fact and not a
failure of the pass. A redis that already loads there by other means is left alone (`already_loaded`).

A candidate is activated by writing `/opt/cpanel/ea-phpNN/root/etc/php.d/zz-ols-cpanel-redis.ini` atomically
(`; Managed by ols-cpanel (php-ext)...` marker line, then `extension=<path of the .so>`, mode 0644: the only file
the product ever writes below `/opt/cpanel`) and proven with `php -m` (lists `redis`) and
`php -r 'var_dump(class_exists("Redis"));'`. A candidate that does not load is removed again and the next layer
is tried. A file of that name without the marker is never overwritten or removed. Removal deletes only INI files
with the marker.

**Worker restarts are owed, durably (RV-31).** Whenever a version gains its extension (`activated`), loads a different
`redis.so` than the one registered for it (`replaced`: the SHA-256 of the file our INI names differs from the one recorded in
`state.json` `artifacts`; for example a package update replaced the managed file in place) or loses it (`php-ext remove`),
EVERY account with a vhost on that version (`whmapi1 php_get_vhost_versions`) is marked in the restart ledger (see "PHP
environment") before the change is recorded as done (for a removal, before the INI is deleted; when the mark cannot be written
the removal is not carried out). `php-ext install`/`sync`/`remove` then try the owed restarts and report them under `restart`;
what fails is `restart_pending` and makes the result `failed`, and the PHP environment applier retries it on every pass. A failed
WHM call marks the version `unresolved` ("accounts not enumerable"), never "no accounts".

**Failures are loud and retried.** A version where every layer failed is `failed` (reason: the dnf or build step
and the tail of its output) and recorded in `/var/lib/ols-cpanel/php-ext/state.json` (`failures`: time, attempts,
reason) and `/var/lib/ols-cpanel/php-ext/php-ext.log`. The watcher retries after 15 minutes (`RETRY_SECONDS`, status
`backoff` meanwhile); `php-ext install` retries at once. `php-ext status`, `objcache status` (`php_extension`) and
the reconcile pass (an unresolved failure is an error of the pass, so `ols-cpanel-objcache.service` shows failed)
report it until it is fixed. The WHM plugin view of this state is not built yet.

**Watcher.** The unit pair is shared with the PHP environment applier ("PHP environment (EasyApache compatibility,
FV-10)"): `ols-cpanel-php.path` (`PathChanged=/var/lib/rpm/.rpm.lock`) starts `ols-cpanel-php.service`
(`ols-cpanel php env sync`, which runs this layer for the versions that need it) after every package transaction. rpm opens `.rpm.lock` for writing only while it holds
the transaction lock, so closing it marks the end of a transaction that installed, upgraded or removed packages
(measured on EL9, rpm 4.16: `rpm -qa` never touches it, while the `rpmdb.sqlite-wal`/`-shm` files change on plain
queries too; a glob below `/opt/cpanel` cannot be watched and would not see a new `ea-phpNN` directory). The
periodic object cache reconcile (60 s) covers anything the path unit misses: when the extension is wanted and some
version neither loads redis nor waits out a back-off (or the path and timer units are off), it starts the same service with
`--no-block` (the work, dnf and a compiler, does not fit the reconcile unit's sandbox). A pass re-verifies every installed version: loads,
nothing; missing or broken (ABI changed, INI lost, `.so` replaced), reinstall or rebuild automatically; a new PHP
version is enabled automatically. After a change, `php restart --account=U` runs for exactly the accounts that
have a vhost on a changed version (`whmapi1 php_get_vhost_versions`), because a running lsphp keeps the extensions
it started with. The pass is idle until the extension is wanted (`install --prepare`, `php-ext install`, `objcache
enable`, or an object cache in use at reconcile); `php-ext remove` clears that, removes our INI files and restarts the accounts of the versions that lost it (the shared
units keep running; `systemctl enable --now` of the path and timer units is done by the CLI, never by the package).

**Commands** (root): `php-ext status` (per version: `status` is `active`, `already_loaded`, `inactive` with a
`candidate` of `prebuilt`, `local_build`, `build_needed` or `none`, or `broken`; `needs_sync`, `watcher`,
`last_failure`, `replaced` for an artifact that differs from the registered one, and `unsupported`; `watcher` and `timer` are the
two units of the PHP environment pass), `php-ext install [--php=ea-phpNN]`, `php-ext remove`, `php-ext sync` (the watcher's pass; exit 1
when a version failed). `objcache enable` ensures the extension for every PHP version of the account's vhosts and
restarts the lsphp of every account on a version that changed (the enable itself never fails because of it; the outcome is
`php_extension` in the result); `objcache configure-wordpress` does the same for the chosen PHP when `redis` is
not loaded there and refuses only if it still is not. `install --prepare` reports the availability per version
(`php_extensions`, read only). `uninstall` removes our INI files (listed in the dry run).

Uninstall: removing the product with instances running leaves them running until `objcache disable` (open: the
`uninstall` command does not yet stop them).

## HTTP/3 (FV-04)

QUIC is the UDP twin of OLS's HTTPS listeners: the same address and port over UDP. Reference: `build/vm-qualification/http3.py`
(the PHP ports are byte-identical, `tests/http3.py`); the lab experiment is `build/vm-qualification/http3_probe.py`.

OLS 1.9.3 behaviour the product relies on (verified in the OLS source):

| Fact | Source |
|---|---|
| Server key `quicEnable` in the `tuning` block, default 1 (`QUIC_ENABLED_BY_DEFAULT`); 0 creates no QUIC engine and no UDP socket | `HttpServerImpl::initQuic` (`src/main/httpserver.cpp`), called from `configTuning` |
| Shared state key `quicShmDir` in `tuning` (`.quicshmdata` and `.quicshmmap` files, created `0640`); unset, OLS falls back to its shared-memory base directories, which still include `/dev/shm/ols` (RV-30) | `HttpServerImpl::initQuic`, `QuicShm::init`, `LsShm::open` |
| Listener key `enableQuic`, default 1, read on secure listeners only; it binds the UDP socket (`bindUdpPort`) and sets the listener's Alt-Svc string | `HttpServerImpl::configListener`, `enableQuicListener` |
| Vhost `vhssl` key `enableQuic`, default 1: Alt-Svc is added to responses of vhosts that have it, never behind a proxy | `HttpVHost` (`VH_QUIC_LISTENER`), `HttpSession::finalizeHeader` |
| Alt-Svc is `h3=":<udp port>"; ma=2592000` (one entry per h3 ALPN, newest first; the `quic=` entry only for gQUIC versions, which are off by default) | `QuicEngine::getAltSvcVerStr` |
| The certificate for a QUIC connection is chosen by SNI exactly as for TLS: the vhost mapped to the name on that listener (a `www.` name falls back to the bare name), else the listener's certificate | `QuicEngine::sniCb`, `VHostMapFindSslContext` |
| The access log request line ends in `HTTP/1.0`, `HTTP/1.1`, `HTTP/2` or `HTTP/3` | `AccessLog` `fixHttpVer` |

What the product writes. The server template (`ownership_httpd_config.conf`, shipped as `/usr/local/ols-cpanel/share/ols/httpd_config.conf`)
has `quicEnable 1` and `quicShmDir /run/ols-cpanel/shm/` (the directory `shmDefaultDir` already names; `ols-cpanel.service`
creates it `nobody:nobody 0750` before OLS starts, RV-30). The compiler adds `enableQuic 1` to every secure listener (the
production listeners and the lab's `tenantsTls` and `tenantsTlsExternal`); plain HTTP listeners carry no QUIC key. Per-vhost
certificates need nothing more: the vhost's own `vhssl` block serves TLS and QUIC alike. Alt-Svc is OLS's own header, added
by default; the product adds none.

Operator input `/var/lib/ols-cpanel/http3.json` (root, not writable by group or others, at most 4096 bytes): a JSON object whose only
key is `enabled` (boolean). Absent, `{}` and `{"enabled": true}` mean enabled. `{"enabled": false}` compiles `quicEnable 0` and
`enableQuic 0` (no UDP socket, no Alt-Svc) and the cutover touches no firewall: use it where UDP 443 is not reachable, so that
clients are not advertised HTTP/3 they cannot use. Anything else (another key, a non-boolean, invalid JSON, a symbolic link, a
writable file) refuses `install --prepare`, the cutover and every reconcile pass (fail closed). The file is read by every compile,
so a change takes effect at the next reconcile pass (the QUIC engine is configured at OLS start: `systemctl restart ols-cpanel`
for a running server) and, being part of the compiled configuration, makes an unapproved plan stale.

Firewall at cutover (`Deployment\Http3Firewall`, every command a fixed argv through the command runner). `install --prepare`
inspects it read-only and shows the change under `http3` in its result and in the approval text; the cutover repeats the
inspection when it takes the backup:

| Host firewall | Detected by | Change | Recorded and undone |
|---|---|---|---|
| csf | `/usr/sbin/csf` and `/etc/csf/csf.conf` present, `/etc/csf/csf.disable` absent | `443` appended to `UDP_IN` and to `UDP6_IN` (only the quoted value of the line changes; a list or range that covers 443 is left alone; `UDP_IN` must appear exactly once, else nothing is changed and a warning is given), then `csf -r` | The original `csf.conf` is copied (byte-exact, verified) to `backups/<id>/firewall/csf.conf`; the manifest records `http3.firewall` (type, keys, `before_sha256`, `after_sha256`). `recover.sh` restores the copy byte for byte while the file still has `after_sha256` (an administrator's later edit is never overwritten; `apache-return` reports `http3_firewall_restored: false`) and runs `csf -r` whenever the original file is in place and no restart has succeeded in this run: "file restored" and "firewall applied" are separate facts, so an attempt that restored the file but failed to restart csf retries the restart (`CSF_APPLIED`), and `healthy()` does not pass until it succeeded (RV-31 item 6). `undo()` reports `file_restored` and `firewall_applied` separately and retries the same way |
| firewalld | `firewall-cmd --state` prints `running` | The default zone is resolved once (`--get-default-zone`) and recorded; runtime and permanent state are separate facts, each queried with `--zone=` (exit 0 open, 1 not open, anything else: not inspectable, nothing planned and a warning). Only what is missing is added: `firewall-cmd --zone=Z --add-port=443/udp` for runtime, `firewall-cmd --permanent --zone=Z --add-port=443/udp` for the permanent configuration, each verified by a query. Never a global `--reload` (it would discard runtime-only administrative rules) | The record holds `zone`, `runtime_open`, `permanent_open`, `add_runtime`, `add_permanent`. `recover.sh` and `undo()` run `--remove-port` with the recorded `--zone=Z` for exactly the state(s) the product added (`--permanent` for the permanent one), never a reload; a default zone changed since the cutover does not redirect the undo; ports the administrator opened stay |
| nftables, none | any other table in `nft list ruleset`, or none | Nothing: an administrator's tables are never edited. An input hook with `policy drop` and no rule mentioning UDP 443 yields a warning | none |

The firewall step runs after OLS serves and never fails a cutover: a failure undoes the partial change, is recorded as a failed
`http3-firewall` step and appears in the outcome's `warnings`, which also carry the nftables and unusable-`csf.conf` advice. With
the opt-out nothing is inspected or changed. The firewall lines of `recover.sh` sit in `restore()` (retried with it); only the csf restart is also checked in
`healthy()` (a successful `csf -r` on the original file, unless the administrator has edited the file since), so recovery cannot
report success while the live firewall still carries the cutover's rules; a firewalld removal that fails is retried with `restore()`
and reported by `apache-return` as `http3_firewall_restored: false`, but never keeps Apache from coming back. Byte equivalence with the lab script:
`hybrid_lab.recovery_script(..., firewall=...)`, `tests/deployment_texts.py`. Enabling HTTP/3 after a cutover that was done with
the opt-out does not open the firewall: open UDP 443 yourself (`http3 status` shows what the product would change).

Protocol share. `ols-cpanel http3 status [--lines=N]` (root; N 1..20000, default 2000) prints
`{"active_generation", "enabled" (true, false, or null when the input is invalid), "input": {"path", "present", "error"?},
"firewall" (null with the opt-out, else the inspection without any file text: "type", "action", "detail", "warnings"),
"log_dir", "lines", "protocol_share": [...]}`. Each `protocol_share` row, for every vhost of the active generation, reads the
last `N` lines of `/etc/apache2/logs/domlogs/<vhost>` and `<vhost>-ssl_log` (the files the log shipper fills from the access
format `<domain>:%p %a %l %u %t "%r" %>s ...`; cPanel's `splitlogs` drops the `<domain>:<port> ` prefix, the parser accepts both):
`{"vhost", "lines" (parsed and unparsed), "h1" (HTTP/1.0 and 1.1), "h2", "h3", "other" (another or no version), "unparsed",
"sources": [files read], "share_bp": {"h1", "h2", "h3"}}`. The shares are integers in basis points (1/10000, rounded half up,
over the parsed lines; 0 when there are none), identical in PHP and Python. The read is bounded (at most 4 MiB from the end of
each file, lines over 8192 bytes are not parsed), never follows a symbolic link and reads only regular files; the domain must be
a valid lower-case host name. Classes: `Ols\Http3\ProtocolShare` (`classify`, `tailLines`, `vhost`, `shares`).

Lab experiment (`http3_probe.py`; not run by the checks): the lab's curl has no HTTP/3, so the client is the container image
`docker.io/ymuski/curl-http3` pinned by digest (`sha256:9eadfcaa...` for the index, `sha256:b9ba1d84...` for linux/amd64), run with
`podman run --network ns:/var/run/netns/olscpc --entrypoint curl`, pulled after the recovery timer is armed and removed again by
the recovery. Outcomes: QUIC UDP sockets owned by OLS on the TLS test listeners only, state under `/run/ols-cpanel/shm` and not
`/dev/shm`, Alt-Svc on HTTPS and not on HTTP, HTTP/3 equal to HTTP/2 (status, size, body digest, header subset) for a PHP page and
a 531 KB static file on three vhosts of two accounts, the vhost's own certificate over QUIC (equal to TCP, different per account),
the HTTP/3 and HTTP/2 lines in the right vhost's domlog and the share the parser computes, and the opt-out leaving no UDP socket,
no Alt-Svc and a failing HTTP/3 request with HTTP/2 intact.

## Hybrid profile constraints

- Default and automatic fallback (HR-D14). Every installation has the hybrid profile unless prepared with `--native`.
  The reconciler compiles with `profile.json`'s hybrid ports, so a blocker that belongs to one vhost never refuses the
  compile: an `.htaccess` the translator cannot reproduce (unknown directive, symlinked file, a file or directory the
  account's own user cannot read, an incomplete scan), an unsupported PHP handler, or an unreadable PHP-FPM pool moves
  THAT vhost alone to Apache (fail safe: Apache applies the account's real rules); the pass result reports
  `hybrid_vhosts` and `hybrid_reasons` (vhost to reasons). The next pass without the cause compiles the vhost natively
  again; no customer or operator action is needed. Remaining refusals are only what cannot be isolated per vhost:
  unreadable cPanel inputs (account list, userdata, httpd.conf, handler lists, template), a malformed product input
  (security, PHP limits, HTTP/3). A vhost with the `dso` PHP handler that would have to go to Apache (it would run
  tenant code as OLS's user) never refuses the compile either: that vhost alone is held, keeping the native configuration
  of the active generation (the same rule as the lsphp guard) or, without one, staying served by Apache exactly as before
  the product (the site keeps answering; the residual risk is the one the dso handler already carries on cPanel, plus that
  its PHP could forge `X-OLS-Client-IP` towards Apache's backend ports), and the
  pass result and the generation summary report `held_vhosts` (vhost to reasons, "PHP handler dso on a site that needs
  Apache"); the WHM interface shows it as handled automatically. The hold ends by itself on the first pass after the
  handler changes. Without hybrid ports (`--native`) every blocker refuses.
- Idle footprint of Apache in standby: the same worker processes as before the installation, but serving only the sites
  that need it, so its resident memory is the idle footprint of a stock cPanel Apache (tens of MB; the MPM and the
  request load drop with every site served by OLS). The product does not change cPanel's MPM tuning (WHM Apache
  Configuration remains the owner's); measuring the idle memory and the added local-hop latency in WHM is planned.

- A hybrid domain has two OLS vhosts: `<domain>` on the HTTP listeners and `tls.<domain>` on the HTTPS
  listeners (OLS skips rewrite rules for ACME paths, so the ACME proxy context must be per scheme). Health
  verification covers both (the TLS vhost through HTTPS or by its own documented check).
- Apache's backend ports admit only root and OLS's user (`nobody`). Tenant code must never run as that
  user on Apache: the compiler holds hybrid vhosts with the `dso` PHP handler (never served by Apache), and cutover with hybrid
  vhosts requires Apache's `suexec_module`.
- Tenant-owned files are read and written only as the tenant (never by root through tenant paths).

## Plugin data and actions (release 1)

Release 1 ships every view of plan §21.3/§21.4 (owner decision HR-D13). The views below rest on what the
product controls today; the feature verticals of plan §21.6 (FV-01..FV-08: LSCache, WAF and security, PHP
manager, HTTP/3, metrics history, configuration overrides, operations, account tools) add their own data and
actions to this section as they are built. No view shows placeholder or invented data.

### Plugin deployment (`Deployment\Plugins`; RV-31 item 14)

`install --prepare` and `upgrade` deploy the WHM tree (`/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel`, plus the icon
`.../addon_plugins/ols-cpanel.svg`) and the cPanel Jupiter tree (`/usr/local/cpanel/base/frontend/jupiter/ols_cpanel`) from the
package's `plugins/{whm,cpanel}`. A deployment replaces each tree as a complete unit and never touches a live tree before its
replacement is complete: (1) each package tree must hold `manifest.json` and its entry point (`index.cgi`, `index.live.php`);
(2) each replacement is staged next to its destination (`<dest>.ols-new`, the same filesystem), the WHM entry point made executable
and the staged tree validated (`test -f` of manifest and entry point), the icon staged likewise; (3) the switch is two `mv -T`
renames per path (the live path to `<dest>.ols-old`, the staged one in), so a request sees the old or the new tree and never a
mix; (4) `register_appconfig` and `install_plugin` run; (5) only then are the `.ols-old` copies removed. Any failure restores every
path that was switched (the old tree back in place, staging removed) and reports the failing step, so the working plugin
is never left missing or half installed; a run interrupted between the two renames is repaired at the start of the next one (a live
path that is missing while its `.ols-old` exists is moved back first). Stale `.ols-new`/`.ols-old` leftovers are cleared before staging.

### Data the engine publishes

Each generation tree carries `summary.json` (an `engine.apply` file path): the compile summary of
`ServerConfigurationBuilder` (vhosts with user/type/docroot/aliases/php/php_handler, `hybrid_vhosts`,
`htaccess_blockers` per vhost, `tls_sources`, `suspended_accounts`, `missing_alias_dirs`) plus
`"compiled_at"`. The broker reads the active generation's copy; with no active generation it reads the
latest plan (`plans/<id>.json`, which embeds the same summary). OLS real-time statistics come from the
`.rtreport*` files in `/run/ols-cpanel/status/` (the server `statDir`) (format of OLS 1.9.3; unknown lines are ignored, an unknown
format gives `status: "unavailable"`). Every value the interface shows carries `observed_at` and `source`.

WAF and security (FV-02, server side). A compile with a security input (builder argument `security`; schema:
`exceptions` [{`vhost`, `rule_ids` | `engine: "off"`, `reason`, optional `approver`, `expires`}], `per_client`
{`staticReqPerSec`, `dynReqPerSec`, `outBandwidth`, `inBandwidth`, `softLimit`, `hardLimit`, `gracePeriod`,
`banPeriod`}, `ip_allow`, `ip_block`, `accept_differences`, `evaluated_at`; unknown keys refused) adds to the summary
`waf` (`{"state": "absent"}` or `state: "translated"`, `engine`, `audit_log`, `inputs` [{path, sha256}], `rule_files`,
`data_files`, `rules`, `disabled_rules`, `differences` [{code, where, detail, weaker, accepted}], `exceptions`
[{vhost, source: "cpanel"|"operator"|"product", engine, rule_ids, reason}]) and `security` (`per_client`, `ip_allow`,
`ip_block`, `accept_differences`, `expired_exceptions`). Anything cPanel's ModSecurity holds that OLS's libmodsecurity 3
cannot reproduce refuses the compile (the current generation stays).

Production input: `/var/lib/ols-cpanel/security.json` (owned by root, mode 0644, at most 256 KiB; a file writable by
group or others, a symlink or a non-regular file is refused). It is one JSON object in the schema above (every key
optional); an absent file is `{}`. `Deployment\SecurityInput::load` validates it with the translator's own rules
(exception vhosts are checked against the real plan at compile time) and `Deployment\BuilderCompilation` passes it as
the builder's `security` argument for every compile: the reconciler (`sync`, the service loop) and `install --prepare` /
`--cutover` alike. An unreadable, oversized or invalid file refuses the compile with a message naming the file (fail
closed; the current generation stays). The WAF is active whenever cPanel's ModSecurity is present, with or without the
file. The reconciler's source digest and the plan's `compile_sha256` include the sha256 of every file in
`summary.waf.inputs` (modsec2.conf, rule files, data files), so a vendor rule update triggers a recompile and
validation, and makes an approved plan stale.

```json
{"exceptions": [{"vhost": "blog.example.com", "rule_ids": [941100], "reason": "editor posts markup", "approver": "root", "expires": 1893456000}],
 "per_client": {"hardLimit": 100}, "ip_allow": ["203.0.113.7"], "ip_block": ["198.51.100.0/24"],
 "accept_differences": [], "evaluated_at": 1790000000}
```

Commands (root, `--format=json` supported): `ols-cpanel waf status` reports the active generation's WAF from its
`summary.json` (`state`, `engine`, `vendors`, `rule_files` and `data_files` as `{path, sha256}`, `rules`,
`disabled_rules`, `differences`, `domain_disables` = the summary's per-vhost exceptions) and `security_json`
(`path`, `present`, the file's `exceptions`, `per_client`, `ip_allow`, `ip_block`, `accept_differences`, or `error`
when it is invalid). `ols-cpanel waf blocked [--limit=N]` (N 1..1000, default 50) parses the last 4 MiB of the audit
log with `ModSecurityAuditLog` and prints `{log, available, limit, records, skipped}`, records newest first. The blocked-request log is OLS's serial audit log
`/usr/local/lsws/logs/modsec_audit.log` (root 0600) read through `ModSecurityAuditLog::parse` (a bounded tail; records
`{time, client, vhost, uri, rule_id, message, action}`, printable ASCII, no headers other than Host).

### Admin socket operations (root; WHM gateway)

| Operation | Arguments | Result |
|---|---|---|
| `server.status` (existing) | none | plus `profile`, `active_generation`, `epoch`, `pending_events`, `hybrid_vhosts` (from `ols-cpanel status --format=json`, run by the broker, 30 s limit, cached 2 s) |
| `server.metrics` | none | `{"observed_at", "status": "ok"\|"unavailable"\|"stale", "server": {requests_per_second, connections, bytes_per_second, ...}, "vhosts": [{"vhost", "requests_per_second", ...}]}` |
| `admin.metrics` | `{"resolution": "hour"\|"day"\|"week", "vhost": domain}` (both optional; default the server, one hour) | The metrics history (FV-05, "Metrics history"): `{"observed_at", "source", "scope": "server"\|"vhost", "vhost", "resolution", "start", "step", "count", "samples", "interval", "channels": {<name>: [value \| null, ...]}, "vhosts": [names with a ring]}`, oldest first, `null` for a bucket without samples. `BAD_ARGS` for another resolution or a vhost that is not a domain name. |
| `inventory.accounts` (extended) | `{"query": text, "page": int, "size": 1..200}` (all optional) | server-side search and paging over domains: `{"total", "page", "size", "domains": [{user, domain, type, docroot, engine: "ols"\|"hybrid"\|"apache"\|"unknown", php_handler, tls: bool, suspended: bool}]}` |
| `compat.findings` | `{"query", "page", "size"}` | blockers and hybrid reasons per vhost with file and line where known, severity, explanation key |
| `plan.latest` | none | the latest plan or null |
| `generation.list` | none | `ols-cpanel generation list --format=json` |
| `doctor.report` | none | `ols-cpanel doctor --read-only --format=json` (cached 60 s) |
| `cache.stats` | `{"account": text, "domain": text}` (both optional) | `ols-cpanel cache stats [--account=..] [--domain=..] --format=json`, as `generation.list` gives its own: `{observed_at, source, exit_code, output}` with `output` the report of "LSCache management"; a refusal (unknown account or domain) is `REFUSED`. Synchronous, 30 s limit. |
| `admin.objcache` | none (read), or `{"automatic": true\|false}` (write) | `ols-cpanel objcache status --format=json` as `{observed_at, source, exit_code, output}` (every account with its `origin`, the `automatic` mode; "Object cache"). A write first runs `ols-cpanel objcache auto --on\|--off --format=json` (anything else is `BAD_ARGS`), is appended to the audit log (`event: objcache_automatic_set`, `args: ["--on"\|"--off"]`) and answers with the status after the change. Admin socket only. |
| `admin.cache_limits` | none (read), or any of `{"per_site_mb": 16..102400, "server_percent": 1..50, "server_max_gb": 1..2048}` (whole numbers, write) | `ols-cpanel cache limits [--per-site-mb=..] [--server-percent=..] [--server-max-gb=..] --format=json`, as `cache.stats` gives its report: `{observed_at, source, exit_code, output}` with `output` the report of "LSCache management" (automatic cleanup). A write validates the bounds before any command runs (`BAD_ARGS`; the engine checks them again, `REFUSED`) and is appended to the audit log (`event: cache_limits_set`). Admin socket only. |
| `admin.audit` | `{"query", "page", "size", "event", "result"}` (all optional; `event` lower-case letters and underscores, `result` `ok` or `failed`) | The broker's audit log, newest first ("Operations"): `{"observed_at", "source", "total", "page", "size", "records": [{"time", "event", "actor", "action", "scope", "job", "result": "ok"\|"failed", "detail"}], "events": [names present], "truncated", "window_bytes"}`. Reads the last 4 MiB of the log; digests are never shown. |
| `admin.notify` | none | `ols-cpanel notify show --format=json` as `{observed_at, source, exit_code, output}`: the settings (the webhook as `{"set", "host"}` only), the limits (20 per day, one per event key per 6 h), messages sent in the last 24 hours, the last delivery error and the last ten messages. |
| `admin.notify_set` | any of `{"emails": [up to 5 addresses], "webhook": "https://..." \| "", "events": [..]}` (left out = keeps the stored value; `""` removes the webhook) | Validates and writes `notify.json` itself (0600, atomic), audits `notify_settings_set` (counts only, never an address or URL), and returns the `notify show` report. `BAD_ARGS` for an invalid address, a webhook that is not https or has credentials, an unknown event. |
| `admin.notify_test` | none | `ols-cpanel notify test --format=json`: a test message to every configured channel now (38 s limit); audited. |
| `admin.schedule` | none | `ols-cpanel schedule list --format=json`: the scheduled jobs (never their digest). |
| `admin.schedule_add` | `{"action": "ols.cutover"\|"ols.apache_return", "scope": plan id \| "server", "digest", "at": unix time, "window": 15..720 minutes}` | Stores a maintenance window. The digest must be the plan's (switch) or the server status' (return) right now, as for `cap.issue` (`STALE`, `NOT_FOUND`); `ols.cutover` is stored with the approved plan id and digest. Audited (`schedule_add`). |
| `admin.schedule_cancel` | `{"id"}` | Cancels a job that is still `scheduled`; audited (`schedule_cancel`). |
| `admin.update` | `{"refresh": bool}` (optional) | `ols-cpanel update check [--refresh] --format=json`: installed and available versions, rpm signature state (15-minute cache; 38 s limit). |
| `admin.bundle` | none | The support bundles that exist, newest first: `{"bundles": [{name, size, created}], "limit_bytes", "keep"}`. A bundle is made by the job `ols.support_bundle` or `ols.support_bundle_raw`. |
| `php.status` | none | `ols-cpanel php status --format=json` as `{observed_at, source, exit_code, output}`: OPcache per version, the lsphp process summary per account and the limits in force ("PHP manager"). Synchronous, 30 s limit. |
| `admin.requests` | none | `{"observed_at", "open", "total", "requests": [{id, user, subject, text, created_at, status: "open"\|"done", done_at}]}`: the requests accounts sent to the administrator, newest first (at most 200) ("Account tools"). Admin socket only. |
| `admin.request_status` | `{"id", "status": "open"\|"done"}` | `{"request": {...}}`: marks one request; `BAD_ARGS` for a malformed id or status, `NOT_FOUND` for an unknown request. A settings change, not a job; audited (`event: request_status`). Admin socket only. |
| `job.list` | none | the last 50 jobs `{job, action, state, started, finished, exit_code}` |
| `job.status` | `{"job"}` | as above plus `output` (the command's JSON) and `log` (bounded progress lines) |

Mutations use the existing capability flow: the gateway receives a POST with the action, the scope (plan
id or `server`) and the digest of what the operator saw (the plan digest, or the status digest), issues a
capability as the cPanel principal and executes it in the same request; the broker starts the job and
returns `{"job"}`. Actions and commands are the table in "Admin socket: jobs for WHM" above, plus
`ols.plan_hybrid` (`install --prepare --hybrid`). One job at a time; a second gets `BUSY`.

Mount namespace of the preparation jobs (RV-31 item 7). The broker unit runs under `ProtectSystem=full` with a short
`ReadWritePaths`, but `install --prepare` deploys the WHM and cPanel plugins into `/usr/local/cpanel` and registers them with
cPanel's own tools, which write wherever cPanel keeps its plugin state. Widening the broker's writable paths for that would
loosen the sandbox of every other broker operation, so only `ols.plan` and `ols.plan_hybrid` run as a transient root unit
`ols-cpanel-job-<id>.service`, started through PID 1 with `systemd-run --wait --collect --pipe --quiet` (so it does not inherit the
broker's mount namespace; `--pipe` keeps stdout and stderr in the job's files and the client's exit status is the job's), with
`User=root`, `WorkingDirectory=/`, `UMask=0077` (the broker's), `NoNewPrivileges=yes`, `ProtectKernelTunables=yes`,
`ProtectControlGroups=yes`, `RestrictRealtime=yes`, `LockPersonality=yes`, `PrivateTmp=yes`, `KillMode=control-group`,
`RuntimeMaxSec` equal to the job time limit and the fixed environment. The monitor still watches the client's pid; when it must
end the job (time or output limit, or a restarted broker that finds it still running) it also runs `systemctl stop
ols-cpanel-job-<id>.service`. Every other action stays a plain child of the broker.

### As implemented by the broker (plugin backend)

`cap.execute` checks the capability's digest against the current state: for `ols.cutover` the SHA-256 of
`plans/<scope>.json` (as `plan.latest` reports it), otherwise `server.status`'s `digest` (SHA-256 of the sorted
JSON of `ols_active`, `apache_active`, `active_generation`, `cut_over`, `profile`, `epoch`, `hybrid_vhosts`); a
mismatch is `STALE`, a missing plan `NOT_FOUND`. Job ids are `j<unix seconds>-<8 hex>`; a job's `job.json`,
`output` and `log` are kept under `jobs/<id>/` (root 0700, the newest 200 kept) and each start and finish is
recorded in `broker-audit.log`. `server.metrics` reads the directory given by the broker's `--rtreport-dir=`
(default `/run/ols-cpanel/status/`); reports older than 30 s are `stale`. Engine `unknown` means no summary, or
a domain the summary does not contain. `install --prepare` embeds the compile summary in the plan
(`summary`); the broker also accepts older plans and derives the engine from `vhosts` and `hybrid_vhosts`.

### Tenant socket operations (any account; cPanel gateway)

| Operation | Result (only the caller's own domains, identity from SO_PEERCRED) |
|---|---|
| `tenant.status` (existing) | unchanged |
| `tenant.domains` (existing) | unchanged |
| `tenant.cache_stats` | `{"user", "observed_at", "source", "generation", "stores": [...], "totals"}`: the caller's own cache stores (rows of the report of "LSCache management", filtered to the caller's account); no arguments. An account without stores gets an empty list. |
| `tenant.cache_purge` | `{"domain": text}` (optional) in; out `{"user", "domain", "observed_at", "purged_at", "stores", "totals"}` (what was removed). Without `domain`, every store of the caller's account. Synchronous (30 s limit); at most one purge per account every 10 s (`RATE_LIMITED`). |
| `tenant.php` | `{"user", "observed_at", "source", "sites": [{domain, type, vhost, engine, php_version, php_handler}], "opcache": [{version, php, loaded, tuned}], "processes": {account, parents, children, rss_kb, cpu_percent, runaway, processes: [...]} \| null, "thresholds", "limits": {children, max_conns, mem_soft, mem_hard, proc_soft, proc_hard}}`: the caller's own PHP view (only the versions its sites use, only its own processes); no arguments. See "PHP manager". |
| `tenant.objcache` | `{"user", "observed_at", "source", "enabled", "origin", "automatic", "suspended", "state", "memory_mb", "connection": {"host": <socket path>, "port": 0, "password": null} \| absent, "wordpress": [{path, state, configured_by_product, checked_at, error}], "usage": {used_memory, maxmemory, keys, evicted_keys, hit_rate, connected_clients} \| null}`: the caller's own object cache (`objcache status --account=<caller>`, see "Object cache"); no arguments; nothing of other accounts or of the operator's configuration. |
| `tenant.metrics` | `{"resolution": "hour"\|"day"\|"week", "vhost": domain}` (both optional) | `{"user", "observed_at", "source", "vhost", "vhosts": [the caller's vhosts], "resolution", "start", "step", "count", "samples", "interval", "channels": {requests_per_second, cache_hits_per_second, static_hits_per_second, php_in_use}}`: the history of one of the caller's own vhosts (default the first by name). A vhost of another account is `NOT_FOUND`, the same as one that does not exist; server data is never returned. |
| `tenant.php_restart` | no arguments; out `{"user", "observed_at", "result", "found", "killed", "remaining"}`: ends the caller's own lsphp processes (`php restart --account=<caller>`). Needs a domain in `/etc/userdatadomains` (`NOT_FOUND`), at most one restart per account every 30 s (`RATE_LIMITED`), audited (`event: tenant_php_restart`). |
| `tenant.logs` | `{"domain", "kind": "access"\|"access_http"\|"error", "lines"?: 1..500 (default 200), "search"?: text (at most 100 characters), "download"?: bool}` | `{"user", "domain", "kind", "file", "observed_at", "exists", "lines": [...], "count", "window_truncated", "search", "download"}` (`text` and `bytes` instead of `lines` for a download): redacted lines of the caller's own domain logs ("Account tools"). `NOT_FOUND` for a domain that is not the caller's, `UNREADABLE` for a link or a non-regular file. |
| `tenant.php_errors` | `{"domain"}` | `{"user", "domain", "observed_at", "sources", "scanned_lines", "php_lines", "groups_total", "groups": [{level, message, count, first_seen, last_seen, sources}]}`: the PHP errors of the domain's vhost error log and docroot `error_log` grouped by message. |
| `tenant.perf` | `{"domain"}` | `{"user", "domain", "observed_at", "reachable", "status", "http_version", "server", "time_first_ms", "time_second_ms", "tls": {verified, verify_code}, "compression": {state: "on"\|"off"\|"not_html", encoding}, "cache": {state: "hit"\|"miss"\|"none", litespeed, cache_control, expires, etag, last_modified}, "http3": {advertised, alt_svc}, "cache_subsites": [{path, state: "hit"\|"miss"\|"none"\|"unreachable"}], "slow_urls": {available: false, reason}}` (`cache_subsites`: when the front page has no LSCache header, up to two WordPress folders directly under the document root, found as the account with `find`, are checked the same way): two HTTPS requests from the server to the domain's own address with its Host and SNI; at most one check per account every 15 s (`RATE_LIMITED`). An unreachable site is a result (`reachable: false`). |
| `tenant.request` | `{"subject": cache\|php\|htaccess\|ssl\|performance\|logs\|domains\|other, "text": 1..1000 characters}` | `{"user", "request": {id, user, subject, text, created_at, status, done_at}}`: a request to the administrator. One per account per 60 s and at most 10 open (`RATE_LIMITED`). |
| `tenant.requests` | none | `{"user", "observed_at", "subjects", "max_text", "requests": [...]}`: the caller's own requests, newest first. |
| `tenant.sites` | `[{domain, type, docroot, engine, php_version, php_handler, tls: {present, not_after}, suspended}]` from the active summary and the certificate files (expiry parsed by the broker), `observed_at` |

### Gateways

WHM `index.cgi` (root only, as today): `GET ?api=<name>` for the read operations (names: `status`, `metrics`,
`inventory`, `compat`, `plan`, `generations`, `doctor`, `jobs`, `job`, `cache`, `cache_limits`, `objcache`, `php`, `history`, `requests`, `audit`, `notify`, `schedule`, `update`, `bundle`), query arguments validated against the
operation's schema; `POST ?action=<name>` with a JSON body `{"scope", "digest"}` for mutations (cpsrvd's
session token in the URL is the CSRF boundary; the gateway also requires the header
`X-OLS-cPanel-Request: 1`). `?api=cache` takes the optional `account` (`^[a-z0-9][a-z0-9_-]{0,31}$`) and `domain` (a lower-case
domain name) and calls `cache.stats`; `POST ?action=ols.cache_purge` takes the scope `server`, `account:<user>` or
`domain:<domain>` (the same grammar) with the status digest, like every server-scoped action; `?api=cache_limits` takes no argument and calls `admin.cache_limits`, and `POST ?action=cache_limits` (header required, no digest: a settings change, not a job) takes a JSON object of at least one of `per_site_mb`, `server_percent`, `server_max_gb` as whole numbers inside their bounds and relays `admin.cache_limits`; `?api=objcache` takes no argument and calls `admin.objcache`, and `POST ?action=objcache_automatic` (header required, no digest) takes exactly `{"automatic": true|false}` and relays `admin.objcache`; `?api=php` takes no argument and calls `php.status`; the Operations reads ("Operations") `?api=audit` (`query`, `page`, `size`, `event`, `result`; `admin.audit`), `?api=notify`, `?api=schedule`, `?api=bundle` (no argument) and `?api=update` (optional `refresh=1`; `admin.update`), `POST ?action=notify_settings` / `notify_test` / `schedule_add` / `schedule_cancel` (header required, no digest, a strict JSON body per action as in the table above; they relay `admin.notify_set`, `admin.notify_test`, `admin.schedule_add`, `admin.schedule_cancel`), the jobs `ols.support_bundle` and `ols.support_bundle_raw` with scope `server`, and `GET ?download=bundle-<10 digits>-<8 hex>.tar.gz`, which serves that file of `/var/lib/ols-cpanel/support/` as an attachment (never through a link, at most 21 MiB; any other name is `BAD_QUERY`); `?api=history` takes the optional `resolution` (`hour`, `day`, `week`) and `vhost` (a lower-case domain name) and calls `admin.metrics`; `ols.php_restart` takes `server` or `account:<user>`, `ols.opcache_install` `server` or `version:ea-phpNN`, `ols.php_env_repair` `server`. cPanel `index.live.php`:
`GET ?api=sites|htaccess|status|cache|php|objcache|logs|php_errors|perf|requests|htaccess_backups|history` (`cache` calls `tenant.cache_stats`, `php` calls `tenant.php`, `objcache` calls `tenant.objcache`; none of these takes a query argument; `history` calls `tenant.metrics` and takes only the optional `resolution` and `vhost`, the broker refusing a vhost that is not the account's) and
`POST ?action=cache_purge` or `?action=php_restart` with the header `X-OLS-cPanel-Request: 1` and a JSON body `{}` or `{"domain": <domain>}` for the purge, `{}` for the restart (at most 1 KiB,
no other key), which calls `tenant.cache_purge` or `tenant.php_restart` on the tenant socket (40 s client timeout) and needs the account's feature
(`FEATURE_DISABLED` otherwise). Broker errors map to HTTP status as in the WHM gateway, plus `REFUSED` 422 and
`RATE_LIMITED` 429 (cPanel).

### Metrics history (FV-05)

The broker samples OpenLiteSpeed's real-time reports in a thread of its own (`panel/history.rs`; the broker runs as root all the time
and reads the report directory, `/etc/userdatadomains` and the state directory, so there is no extra unit or timer and nothing to
enable: it starts with the broker after every install and upgrade). Every 10 s, on the 10 s boundary, it takes the same aggregation
of `.rtreport*` that `server.metrics` returns (so a history value is a value OLS reported: plain and TLS bytes summed, processes
summed as WebAdmin does) and folds it into ring files under `/var/lib/ols-cpanel/metrics/` (directories root 0700, files root 0600):
`server.ring` and `vhosts/<vhost>.ring`. A report that is not `ok` (missing, stale, unknown format) leaves a gap, never a guess.

| Resolution | Bucket | Slots | Covers |
|---|---|---|---|
| `hour` | 10 s | 360 | 1 hour |
| `day` | 1 min | 1440 | 1 day |
| `week` | 10 min | 1008 | 1 week |

A ring is a fixed-size binary file: a 16-byte header (`OLSM`, version, channel count), then the three levels, each slot being
the bucket start (u32), the number of samples folded in (u32) and one f32 sum per channel. A sample goes to the slot
`(t / bucket) mod slots` of each level and a slot of an older bucket is overwritten, so a file never grows; a reader returns
sum / count (the mean of the samples in the bucket) and `null` for a bucket with none. f32 keeps counts exact up to 16.7 million
and within 1e-7 relative above. A file of another size or header is started again; links are never followed (`O_NOFOLLOW`).

Series: the server, 8 channels (`requests_per_second`, `requests_processing`, `connections`, `tls_connections`,
`bytes_in_per_second`, `bytes_out_per_second`, `cache_hits_per_second`, `php_in_use`; the names and values of `server.metrics`)
and each vhost, 4 channels (`requests_per_second`, `cache_hits_per_second`, `static_hits_per_second`, `php_in_use`).

Disk use is bounded: `server.ring` is 112,336 bytes and a vhost ring 67,408 bytes. An idle vhost has no ring until its first
non-zero sample, at most 1000 vhost rings exist (further vhosts are skipped until one is pruned), and rings not written for
8 days (longer than the week they hold: the vhost left the report) and any stray file in `vhosts/` are removed once an hour. The
whole directory therefore never exceeds 112,336 + 1000 x 67,408 = about 67.5 MB, whatever the traffic.

Reads: `admin.metrics` (the server or any vhost) and `tenant.metrics` (only a vhost listed for the caller's account in
`/etc/userdatadomains`: the vhost serving a main or sub domain, or the parent of an addon or parked domain; the account comes
from SO_PEERCRED). The WHM Overview shows the server charts with a vhost picker; the cPanel "Traffic history" view shows the
account's vhosts.

### Account tools (FV-08)

Operations of the cPanel plugin's "Account tools". Every one is scoped to the caller: the account is the SO_PEERCRED identity
in the broker (or, for the `.htaccess` rewrite, the account the LivePHP page runs as), never a request field, and a domain in a
request must be one of that account's own rows of `/etc/userdatadomains` (`NOT_FOUND` otherwise; unknown fields are `BAD_ARGS`).

Logs (`tenant.logs`). Access logs are cPanel's domlogs `/etc/apache2/logs/domlogs/<domain>-ssl_log` (`access`) and `<domain>`
(`access_http`), the error log is the OLS vhost's `/usr/local/lsws/logs/vhosts/<vhost>-error.log` (the vhost of an addon or parked
domain is its parent's, which must also be the caller's). Files are per domain or vhost, opened without following a link and only
when regular; at most the last 4 MiB are read (1 MiB for a download), a first line cut by the window is dropped, a line is cut at
2000 characters and control characters become `?`. The view returns the last N lines (at most 500). The search is a fixed string of
at most 100 characters matched against the redacted text, so it cannot be used to find a removed value. Redaction removes the value
of `name=value`, `name: value` and `"name": "value"` when the name contains `pass`, `pwd`, `token`, `key`, `secret`, `sess`, `auth`,
`cookie`, `credential` or `sig` (query strings included), the whole value of `Authorization`, `Proxy-Authorization`, `Cookie` and
`Set-Cookie`, and the token after `Bearer` or `Basic`; it is replaced by `[redacted]`. Live tail is the interface polling the last lines every
five seconds. The cPanel gateway also serves `GET ?api=logs_download` as a text attachment.

Ownership epoch. The reconcile pass keeps `/var/lib/ols-cpanel/domain-owners.json` (root 0600): per domain `{"owner", "since"}`, where `since`
(unix seconds) is when the current owner took the domain (a new domain or a changed owner sets it to now, an unchanged owner keeps it, a removed
domain is dropped; the first file of an install uses 0 for every domain). `tenant.logs` and `tenant.php_errors` answer `NOT_FOUND` when the domain is
not in that file with the caller as owner, and return only vhost and domain log lines whose own timestamp (Apache `[28/Oct/2026:04:16:04 +0000]`,
OLS `2026-10-28 04:30:39.432908`, PHP `[28-Oct-2026 04:30:39 UTC]`) is not before `since`; a line without a timestamp follows the line before it. A
domain moved between accounts therefore never shows the earlier owner's requests or PHP errors.

PHP error groups (`tenant.php_errors`). Lines of the vhost error log (read by the broker as above) and of `<docroot>/error_log` (the
account's own file, read as the account with `runuser -u <user> -- tail -c 4194304 -- <path>`, so a link in the home cannot lead root to
another file) that contain `PHP <Level>:` are grouped by level and message (digit runs of six or more become `N`; file and line stay); each group has a count and the first and last
timestamp as written in the log (the two files use different formats).

Performance checks (`tenant.perf`). `curl` with a fixed argv (`--resolve <domain>:443:<address>`, 8 s limit per request, 12 s for the
command), the address being the `ip:443` field cPanel lists for the domain. Compression is judged on the first response (`Content-Encoding` for an HTML page, with
`Accept-Encoding: gzip, br`), LSCache on `X-LiteSpeed-Cache` of the second, HTTP/3 on `Alt-Svc` containing `h3`, TLS on curl's certificate
verification result. Slow URLs: the access log format (`CpanelSurface::ACCESS_FORMAT`) has no request time field, so the result says plainly that
they cannot be listed. In hybrid mode the answer is whatever serves the address (the `server` header shows it).

`.htaccess` rewrite. The cPanel page (LivePHP, running as the account; root never writes into a home) reports per file a `digest` (SHA-256) and
`fixes` (the rules `HtaccessRewrite::proposal` would apply). The advisor has no replacement for unsupported directives; the cases it can rewrite
are `bom` (a UTF-8 byte order mark at the start) and `cr_line_endings` (lone CR line ends and no LF in the file). `POST ?action=htaccess_apply`
`{"path": "~/dir/.htaccess", "digest"}` refuses (HTTP status, code) a path that is not `~/[dirs/].htaccess` without `.` or `..` (400 `BAD_PATH`),
outside the account's own site document roots (403 `OUT_OF_SCOPE`), through a link in any component below the home (422 `LINK`), a missing file (404), over 256 KiB (422 `UNREADABLE`),
a digest other than the file's current one (409 `STALE`) and a file with nothing to rewrite (422 `NO_REWRITE`). It stores the original bytes as
`~/.ols-cpanel/htaccess-backups/<id>.bak` (folder 0700, files 0600, created under umask 077, never through a link; the newest 50 kept) with `<id>.json`, holds the
account's lock `~/.ols-cpanel/htaccess.lock` (another change in progress for 5 s: 409 `BUSY`), writes a temporary file next to the original with its permissions, checks the digest
again after it is complete and immediately before renaming it into place (the window left is the interval between that comparison and the rename, so the guarantee is "a changed file is
refused", not an absolute one; the original is always in the backup). PHP has no `openat`, so the directories below the home are pinned by device and inode during the walk and compared with
`lstat` before every read and before the rename, which narrows but cannot close a link race; the process runs as the account, so at most its own files are affected. `POST ?action=htaccess_undo` `{"id"}` (id `YYYYMMDDTHHMMSSZ-<8 hex>`)
restores the stored bytes exactly, and only when the file still has the digest apply wrote (409 `STALE` otherwise, so a later edit is never lost); a damaged
backup is 422 `CORRUPT`; each change can be undone once. `GET ?api=htaccess_backups` lists the account's changes.

Requests to the administrator. One JSON file per request in `/var/lib/ols-cpanel/requests` (root, directory 0700, files 0600, created without following a link), id
`r<unix seconds>-<8 hex>`, subjects from the fixed list above, text 1..1000 characters of plain text (rendered as text, never as HTML). The queue is bounded
(2000), an account has at most 10 open requests and sends one per 60 s. The WHM view lists them with status and the administrator marks them done or open
(`admin.request_status`); creation and status changes are audited.

Gateways. cPanel `index.live.php`: `GET ?api=logs|logs_download|php_errors|perf&domain=<domain>` (`logs` also `kind`, `lines`, `search`; any other argument is `BAD_QUERY`),
`GET ?api=requests`, `GET ?api=htaccess_backups`; `POST ?action=htaccess_apply|htaccess_undo|request` with the header `X-OLS-cPanel-Request: 1` (bodies of at most 1 KiB, 8 KiB for `request`).
WHM `index.cgi`: `GET ?api=requests` and `POST ?action=request_status` `{"id", "status"}` (header required, no digest).

### LSCache management (FV-01, plugin part)

Storage is `CacheStorage` (stores under `/var/lib/ols-cpanel/cache/<user>@<vhost>`, root-owned tree, links never followed, the
shared-memory index never touched). A domain is mapped to its vhost through the active generation's `summary.json`: the vhost
itself or one of its `aliases`; the store name comes from `CachePolicy::storeName` (hashed form for long names) and a vhost whose
`summary.cache` entry has no storage (hybrid pass-through) has no store. Without an active generation only account and server
scopes work (from the stores on disk). The CLI refuses (exit 1, `{"result": "refused", "error"}`) an invalid or unknown
account, an unknown domain, a domain of another account when `--account` is also given, and a domain without a store.

`cache stats` result: `{"scope": {"scope": "server" | "account" | "domain", "account", "domain"}, "observed_at",
"generation", "stores": [{"store", "account", "vhost", "domains", "enabled", "present", "public_entries",
"public_bytes", "private_entries", "private_bytes", "entries", "bytes", "last_purge"}], "totals": {"stores", "entries",
"bytes", "private_entries", "private_bytes"}}`. `domains` is the vhost followed by its aliases; `enabled` is the summary's
cache state (null for a store no active vhost names, which is listed as found on disk; false for the `server` store);
`last_purge` is the unix time recorded by the last `cache purge` that touched the store, or null. `cache purge` prints
`{"command": "cache purge", "result": "purged" | "partial" | "failed", "error", "scope", "purged_at", "generation", "stores", "totals"}`
where the counts are what was actually removed (RV-31 item 12): an entry counts once its unlink succeeded, an entry that vanished
meanwhile (ENOENT) is neither removed nor a failure, any other failed unlink or rmdir is counted in the store's `failed` (and in
`totals.failed`). `result` is `purged` only when no removal failed; `partial` when some failed but something was removed, `failed`
when nothing could be removed; both exit 1 with `error` naming the stores, and `purged_at` is null. The ledger
(`cache-purges.json`) and a store's `last_purge` are written only for a store emptied without a failed removal.

Purge confinement (RV-31 item 15). Root never traverses a tenant-influenced store to delete: statistics only read, and for a
purge `CacheStorage` takes each store directory's owner (the OLS server user, `nobody:nobody 2770`; a root-owned store is refused
and reported failed) and runs the internal command `cache purge-store --root=R --store=S` through `setpriv --reuid=U --regid=G
--clear-groups --no-new-privs --inh-caps=-all --bounding-set=-all` (a timeout of 900 s; anything but a complete JSON answer is a
failed store). The command refuses to run as root and validates the store name. Because the helper holds only that user's
rights, a directory swapped for a symlink by a compromised OLS worker can redirect deletions only to what that user could
already delete. PHP has no `openat`, which is why the confinement rather than descriptor-relative traversal is the boundary; the
Python reference (`lscache.py`, `dir_fd`/`O_NOFOLLOW`) gives the same results and failure counts (`tests/lscache.py`).

Automatic cleanup. OLS leaves an expired entry file on disk until the same URL is cached again, so the stores of sites with many
URLs (query strings, crawlers, variants) would grow without bound; the stores are owned by `nobody`, so no cPanel quota ever
limits them. `ols-cpanel-cache-clean.timer` (hourly, 10 min after boot, randomized delay) runs `ols-cpanel-cache-clean.service`
(root, `Nice=19`, `IOSchedulingClass=idle`, hardened) = `cache clean`, enabled by `install --prepare` and by `upgrade` on hosts
prepared earlier; nobody has to do anything and customers see nothing except the sentence in their page cache view that old
cached pages are removed automatically. Per store: (1) entry files (`<16 hex>`, the `.S` stale copy, an old `.tmp`) whose
modification time is older than `CachePolicy::maxEntryAge()` are removed, that is the longest lifetime the compiled policy gives
(`expireInSeconds`, `privateExpireInSeconds`, read from `CachePolicy::PARAMS`) plus `maxStaleAge` plus a margin of one day, and never
less than eight days (`MIN_ENTRY_AGE`: an application may set a longer lifetime itself, LiteSpeed Cache for WordPress one week); (2) a store over `per_site_mb` (default 512 MB) loses its oldest entries (by
modification time, then path) until it fits; then over all stores (3) the oldest entries of the whole server go until the total is
within `min(server_percent of the filesystem holding the cache, server_max_gb)` (default 10%, at most 20 GB; the cut-off time
is found from a read-only inventory in one-minute steps). When the filesystem has under 5% free space every cap is halved
(`emergency`). Never touched: links (never followed), `.cacheman.*` control files, any name that is not an entry or a hash
directory, and any entry modified in the last 60 s (OLS may be writing it); directories a cleanup emptied are removed. Like a
purge, root never deletes: `CacheStorage::trimStore` runs in the confined helper `cache clean-store` (setpriv as the store's
owner, no capabilities, `CacheStorage::confinedTrimHelper`) and Python `lscache.trim_store` is its reference twin with equal
results (`tests/lscache.py`). `cache clean` prints `{"command", "result": "cleaned" | "partial", "last_run", "emergency",
"over_server_cap", "limits", "limits_problem", "per_site_bytes", "server_bytes", "filesystem", "totals": {"stores", "files",
"bytes", "failed", "remaining_bytes"}, "stores": {<store>: {"files", "bytes", "failed", "remaining_files", "remaining_bytes"}}}`
and records it in `cache-clean.json`. `cache limits` prints `{"command", "changed", "observed_at", "limits", "defaults",
"bounds", "problem", "per_site_bytes", "server_bytes", "emergency", "filesystem": {"total_bytes", "free_bytes",
"free_percent"}, "max_entry_age", "last_clean", "stores"}`; `problem` names an invalid `cache-limits.json`, whose values are then
ignored (defaults in force).

Broker rules. `cache.stats` arguments are validated (`deny_unknown_fields`, account `^[a-z0-9][a-z0-9_-]{0,31}$`, domain
lower-case labels) and become fixed argv; `ols.cache_purge` is a job action whose scope is `server`, `account:<user>` or
`domain:<domain>` (anything else is `BAD_ARGS` at `cap.issue`), bound by `cap.execute` to the status digest, one job at a time
like every job. Tenant operations take the account only from SO_PEERCRED (root and unknown uids are `FORBIDDEN`). A
`tenant.cache_purge` domain must be one of the caller's own rows of `/etc/userdatadomains` (read by the broker; otherwise
`NOT_FOUND`, nothing runs); the broker passes that row's vhost (the parent's for an addon or parked domain) together with
`--account=<caller>`, so the command checks ownership a second time. The rate limit (one purge per account per 10 s) is
checked after validation and ownership, and each tenant purge is appended to the broker's audit log
(`event: tenant_cache_purge`). New broker error codes: `REFUSED` (the command refused, with its reason), `RATE_LIMITED`.

## Operations (FV-07)

WHM views Activity, Notifications, Maintenance windows, Updates and Support; every setting is a form with defaults and every
action a button, nothing needs the command line. Admin socket only; the tenant socket has none of it.

**Activity (`admin.audit`).** The audit log (`broker-audit.log`: every capability execution, job start and finish, cache limit
change, tenant purge and restart, enforcement action, and the Operations changes below) as a paged table: when, who (the principal,
the account, or `system`), what (event, action, scope, job), result and a bounded detail. Filters: free text, event, result.

**Notifications (`notify.json`, `ols-cpanel-notify.timer`).** Opt-in: until an address (up to five, sent through the local mail
system as `sendmail -t -oi`, which cPanel's Exim provides) or an https webhook (`POST` JSON, 5 s, certificate verified, redirects
not followed, no credentials in the URL) is set, nothing is sent. `ols-cpanel notify run` (root oneshot every five minutes) reads
the product's own state and sends what is new: a finished switch, return or recovery job (`jobs/<id>/job.json`, `ols.cutover`,
`ols.apache_return`, `ols.rollback`, finished after notifications were enabled); sites newly in `held_vhosts` or `hybrid_vhosts` of
the active summary; a PHP version newly `failed` in `php-env.json`; `ols-cpanel-upgrade.service` in the failed state; the last cache
cleanup in emergency mode (`cache-clean.json`); the state or cache disk below 5% free; a WordPress site check newly in error in
`objcache.json`; a scheduled job that was missed or refused. A condition that exists when notifications are first enabled is
recorded, not announced. Bounds: the same event key at most once per six hours (job, cache and upgrade events once per week), at
most 20 messages in any 24 hours (the rest is deferred, not lost), a failed delivery is retried on the next pass up to three
times and then recorded as the last error. The sent-ledger is `notify-ledger.json`. Messages contain names of sites and accounts,
job results and counts, never a customer's content; the webhook URL appears in no message, log, audit record or view (the views
show its host name). The "Send test" button is `admin.notify_test`.

**Maintenance windows (`schedule.json`, `ols-cpanel-schedule.timer`).** The switch (`ols.cutover`) and the return
(`ols.apache_return`) can be scheduled for a time and a window of 15 to 720 minutes (default 60), up to 90 days ahead, ten pending
at a time. `ols-cpanel schedule run` (root oneshot every minute) starts a due entry through the broker's own capability flow
(`cap.issue` then `cap.execute` on the admin socket), so the checks, digests, one-job-at-a-time rule and audit records are those of
a click in the Switch center. A switch is stored with the approved plan id and the plan digest the operator saw; if the plan file
changed by the time it runs, the broker answers `STALE` and the entry is marked `refused` and never run. A return takes the status
digest at the time it runs (it changes with every account change) and only runs while the server is switched, otherwise it is
`refused`. A busy broker is retried every minute inside the window; a window that passed is `missed` and never run later. States:
`scheduled`, `running`, `done`, `failed`, `missed`, `refused`, `cancelled`. Cancel is a button.

**Updates (`admin.update`).** Installed and available versions of `ols-cpanel` and `ols-cpanel-openlitespeed` from
`dnf -q check-update --refresh` (read-only; nothing is installed), the rpm signature state of each installed package (`signed`, with
the key id, when that key is imported into the rpm database; `signed-key-missing`; or `unsigned`, shown neutrally for a lab or local
build) and, beside it, whether this server's operating system and cPanel version are in the supported list (the same rule as the
Overview's platform line). The update itself stays with dnf and cPanel's own update schedule; the product applies it by itself
afterwards (`Upgrade::pending`, `ols-cpanel-upgrade.service`).

**Support bundle (`ols.support_bundle`, `ols.support_bundle_raw`, `admin.bundle`, `GET ?download=`).** A job of the capability flow
that writes `/var/lib/ols-cpanel/support/bundle-<time>-<hex>.tar.gz` (root 0600, at most 20 MB, the last three kept): package
versions and platform facts, the `status`, `doctor` and `generation list` reports, a reduced summary of the active generation (types,
PHP versions, held and hybrid sites, counts of `.htaccess` blockers; no document roots, no `.htaccess` text, no TLS paths), the
product's own configuration and result files (notification settings reduced to on or off, schedule without digests), the last audit
records, the last 600 journal lines of the product's units and the tail of the OpenLiteSpeed error log. Never included: private keys,
certificates, the broker's secret, anything under a document root, access logs. Redaction (`Operations\Redactor`) always removes PEM
blocks, passwords, tokens, API keys, authorization and cookie values, URL credentials and the path and query of full URLs, long
token-like strings and e-mail addresses; with "anonymize" (the default) IP addresses, domain names and account names become stable
placeholders (`ip-<hex>`, `domain-<hex>.invalid`, `acct-<hex>`, an HMAC under a per-server salt, so they read the same in every file
and bundle of one server and cannot be matched across servers). `manifest.json` lists the files with sizes, hashes and redaction counts.

The timers `ols-cpanel-notify.timer` and `ols-cpanel-schedule.timer` are enabled by `install --prepare` and by `upgrade`
(`Deployment\OperationsTimers`), removed by `uninstall`, and never started by the package.

## PHP manager (FV-03)

**Limits input.** The optional file `/var/lib/ols-cpanel/php-limits.json` (root, 0644, a regular file nobody else can write; read
by the compiler, also in the reconciler) sets typed per-account limits for the lsphp pool of every vhost of the account:
`{"defaults": {...}, "accounts": {"<user>": {...}}, "runaway": {"cpu_seconds", "rss_mb", "min_age_seconds"}}`. Limit fields, all
optional: `children` (`PHP_LSAPI_CHILDREN`, 1-256, default 5), `max_conns` (OLS `maxConns`, 1-1024, never below `children`, equal
to `children` unless set), `mem_soft_mb` / `mem_hard_mb` (`memSoftLimit` / `memHardLimit`; 0 = unlimited, the default, otherwise
64-2047 MB, hard not below soft), `proc_soft` / `proc_hard` (`procSoftLimit` / `procHardLimit`, 1-65535, defaults 400 and 500,
soft not below `children`, hard not below soft). Precedence: built-in values, `defaults`, the account's entry. Unknown keys,
wrong types and out-of-range values refuse the compile (a broken file never reaches a configuration; read-only views fall back to
the built-in set and report the reason). Without the file or an entry the compiler output is byte-identical to the built-in
values (`tests/compiler_equivalence.py`; the lab reference `tenant_isolation_probe.vhost_config` takes the same `limits`). A change
takes effect at the next compile (`ols-cpanel sync`, or the reconciler's next pass) and, for running pools, the next PHP restart.
The compile summary lists the accounts with an entry under `php_limits`. Runaway thresholds default to 900 CPU seconds, 1024 MB and a
minimum age of 120 s.

**`php processes [--account=U]`** (root, read only; `ps -eo pid=,ppid=,user:32=,etimes=,cputimes=,rss=,pcpu=,stat=,comm=`, rows
named exactly `lsphp`). Result `{"command", "result": "processes", "observed_at", "account", "process": "lsphp", "thresholds",
"totals": {accounts, processes, children, rss_kb, runaway}, "accounts": [{account, parents, children, rss_kb, cpu_percent, runaway,
processes: [{pid, ppid, role: "parent" | "child", children, cpu_percent, cpu_seconds, rss_kb, elapsed_seconds, state, runaway:
[] | ["cpu"] | ["rss"] | ["cpu", "rss"]}]}], "limits_error"}`. A parent is an lsphp process whose parent is not an lsphp process (OLS
started it); its children are the LSAPI workers. A process is a runaway when it is at least `min_age_seconds` old and its cumulative
CPU time is at least `cpu_seconds` (`cpu`) or its resident memory at least `rss_mb` (`rss`); a command has no memory of earlier
samples, so "for longer than N seconds" is the process age. The command never signals a process.

**OPcache** (root). Per installed EA4 PHP version (`/opt/cpanel/ea-phpNN` with `root/usr/bin/lsphp` or `php`):

- `php opcache status`: `{"result": "status", "auto", "timer", "versions": [{version, php, package, package_installed, loaded,
  settings, wanted, tuned, ini_file, accounts}]}`. `settings` is what `php -i` of that version reports for `enable`,
  `validate_root`, `validate_permission`, `memory_consumption`, `max_accelerated_files` and `revalidate_freq` (empty while the
  extension is not loaded); `tuned` is true when it is loaded and every wanted setting matches, `enable` included (OPcache loaded but disabled is not tuned and
  is repaired and verified like any other drift; `enable_cli` is never touched); `accounts` counts the accounts with
  a domain on the version (`/etc/userdatadomains`).
- `php opcache install (--version=ea-phpNN | --all)`: for each version that is not loaded and tuned: `dnf -y install ea-phpNN-php-opcache`
  when the extension is not loaded, the tuning drop-in `/opt/cpanel/ea-phpNN/root/etc/php.d/zz-ols-cpanel-opcache.ini`
  (`opcache.enable=1`, `opcache.validate_root=1`, `opcache.validate_permission=1`, `opcache.max_accelerated_files=20000`,
  `opcache.memory_consumption=` 128 for PHP 8 and later, 96 for 7.x, 64 for 5.x, `opcache.revalidate_freq=2`; not owned by an RPM,
  so EA4 updates leave it, and sorted after every package's own file), verification with `php -i`, then `PhpRestart` for every account
  with a domain on that version, through the restart ledger (a failed restart stays owed and fails the row; a graceful OLS reload does not load the extension; lab: an uncached WordPress page 1.17 s to
  0.60 s after the restart). A version that already reports the wanted settings is left alone (no write, no restart). Result
  `{"result": "installed" | "failed", "changed", "failed", "versions": [{version, result: "installed" | "tuned" | "unchanged" |
  "failed", package_installed_now, ini_written, verified, restarted: [{account, result}], error}]}`, exit 1 when any version failed. An
  explicit install turns the automatic management on.
- `php opcache reconcile`: the same convergence for every installed version that is not as wanted (`{"result": "reconciled" |
  "failed" | "disabled", ...}`); `disabled` while the operator opted out. Run by `ols-cpanel-php.timer` (15 min, root oneshot
  `ols-cpanel-php.service`), so a PHP version installed or rebuilt by EasyApache or MultiPHP, or an update that changed what PHP
  reports, is converged without a manual step (since FV-10 the service runs `php env sync`, which includes this step). `install
  --prepare` installs OPcache everywhere, enables the timer and the package-transaction watcher and reports the result under
  `opcache` (a failure there never undoes the plan); `install --prepare --no-opcache` records the opt-out in
  `/var/lib/ols-cpanel/php-opcache.json` (`{"auto": false}`) and skips only the OPcache step. An explicit `php opcache install`
  also enables the timer and the watcher (it used to leave them off). `uninstall` stops them and removes the OPcache INI the product wrote (the OPcache
  packages stay installed).
- Output shape, per version row (the WHM view and `php status` read exactly this): `loaded` (boolean) and `settings`, always an
  object with every one of the six keys (`null` where PHP does not report it, for instance while the extension is not loaded;
  never missing or an empty list). `php opcache status --version=ea-phpNN` returns the same document with that one row (an
  uninstalled version is refused), and `status` also reports `watcher` next to `timer`.

**Sizing.** The OPcache segment belongs to one account's lsphp family (the parent creates it, its LSAPI children share it), and its pages
are allocated on demand, so the setting is a ceiling per account and not a reservation: the memory used is what each account actually
caches. A full cache restarts itself and loses its benefit, so the ceiling must hold a large WordPress or WooCommerce site (40-80 MB of
compiled scripts on PHP 8, less on 7 and 5); `max_accelerated_files=20000` suits all of them (PHP rounds it up to a prime).
`validate_root` and `validate_permission` keep an account from reading another account's cached scripts; `revalidate_freq=2` keeps
edits visible within two seconds.

**`php status [--account=U]`** (root, read only) is `{"command", "result": "status", "observed_at", "account", "opcache", "environment",
"processes", "limits": {builtin, overrides, accounts, runaway, file, error[, account]}}` (`environment` is `php env status`) (memory limits in bytes); the broker's `php.status` and
`tenant.php` run it. Broker rules: `php.status` takes no arguments; `ols.php_restart` scopes are `server` and `account:<user>`,
`ols.opcache_install` scopes `server` and `version:ea-phpNN` (anything else is `BAD_ARGS` at `cap.issue`), `ols.php_env_repair` the scope
`server` only, all bound to the status digest like every server-scoped job. Tenant operations take the account only from SO_PEERCRED; `tenant.php` keeps only the caller's sites,
the OPcache state of the versions they use and the caller's own process family; `tenant.php_restart` is rate limited and audited.

## PHP environment (EasyApache compatibility, FV-10)

Product rule: nobody ever needs the command line or EasyApache knowledge for OLS to keep working. Every PHP request of every OLS
vhost runs through the EA4 package `ea-phpXX-php-litespeed` (`/opt/cpanel/ea-phpXX/root/usr/bin/lsphp`), so each installed EA4 PHP
version must always have it, plus OPcache and (for the object cache) the redis extension, whatever EasyApache, MultiPHP, an EA4
profile or a cPanel update does to the packages. One root service does this; the pieces (OPcache, the redis layer) are the existing
ones, called from it.

**One applier, one service.** `ols-cpanel-php.service` (root oneshot, `ols-cpanel php env sync`) is started by three triggers:
`ols-cpanel-php.path` (`PathChanged=/var/lib/rpm/.rpm.lock`: after every package transaction, including EA4 profile provisioning,
a new PHP version and a profile that removed packages; see "PHP redis extension" for why that file), `ols-cpanel-php.timer` (boot
plus 180 s, then every 15 minutes: the fallback and the retry clock) and the reconciler (the allowlisted `systemctl start --no-block
ols-cpanel-php.service`, below). The OPcache timer and the redis watcher of earlier builds are merged into this one pair of units
because they answered the same event with the same privileges: two services racing on `dnf` and on the same restarts, with two
back-off clocks and no single place to report from, was the alternative. `ols-cpanel-php-ext.*` units of earlier builds are retired
by `upgrade` and `uninstall`.

**A pass** (`Php\PhpEnvironment`, under `php-env.lock`) first makes sure the path and timer units are enabled (so any automatic
PHP management keeps them on; `php opcache install` enables them too), writes the recommended EA4 profile file when it differs,
and then, for every installed EA4 PHP version (a `/opt/cpanel/ea-phpNN` directory with `php` or `lsphp`):

1. lsphp: a file with an execute bit. Missing: `dnf -y install ea-phpNN-php-litespeed` through the `CommandRunner`
   (cPanel's EA4 repository is configured on every cPanel server), then `lsphp -v` must run.
2. OPcache (unless the operator opted out with `--no-opcache`): `OpcacheManager::convergeVersion` (package, tuning drop-in,
   verification, restart of the accounts on that version). PHP 8.5 has no `php-opcache` package (OPcache is part of PHP); it counts as
   installed when `php -i` reports it.
3. redis, once the product wants it (`install --prepare`, the object cache, `php-ext install`): `ExtensionInstaller` (prebuilt,
   earlier local build or a build on the server), restarting the accounts on a version that changed.

Nothing runs for a version that is complete. PHP is restarted only for the accounts with a domain on a version that changed (all of them).

**lsphp environment (LOG-072, RV-36).** OLS runs each account's lsphp detached (`autoStart 2`), so a running lsphp parent keeps the
`env` lines it was started with when a product release changes them (release 37 added `LSAPI_MAX_IDLE=10`; lab 2026-10-28: the old
parent kept a 116 MiB worker five minutes). After the versions, every pass (`sync`, `repair`, `prepare`) runs `Php\LsphpEnvironmentCheck`:
for each account in the active generation's tenant vhosts it takes the `env` lines of `extProcessor <user>-php` for the names the product
sets (`PHP_LSAPI_CHILDREN`, `LSAPI_MAX_IDLE`, `LSPHP_ENABLE_USER_INI`, `PHP_INI_SCAN_DIR`; a name is compared only when every vhost of
the account agrees on it) and compares them with `/proc/<pid>/environ` of the account's lsphp processes (cPanel-range uid only; an
unreadable environ is skipped, at most 500 are read per pass). An account with a missing or different value is restarted once with
the `php restart --account` code; accounts that match are not touched. The pass result carries `lsphp_environment`
(`checked`, `restarted`, `errors`); a failure is reported there and never fails the pass. Nobody runs `php restart` by hand.

**Owed restarts (RV-31).** A running lsphp keeps what it loaded, so any change to a version (OPcache installed or retuned, redis
installed, replaced or removed) makes the workers of every account on that version stale. The change is recorded durably in the
state file under `restarts` BEFORE any restart is attempted, and cleared per account only after `php restart --account` succeeded:
`"restarts": {"ea-phpNN": {"revision", "since", "unresolved", "accounts": {"<account>": "<revision>"}}}`. `revision` names the
artifact or configuration the workers must run (`opcache:<sha256 of the drop-in>[:package]`, `redis:<sha256 of redis.so>`,
`redis:removed`); marking again supersedes it for every account. When the accounts of a version cannot be listed
(`/etc/userdatadomains` unreadable, WHM failing) the entry is `unresolved` and the listing is retried by every pass. An account
with no domain on the version any more, or that no longer exists, is dropped. Every pass settles the ledger for ALL versions
(including those waiting out a back-off), a restart that still fails puts `lsphp restart pending (ea-phpNN: <accounts>)` in the
version's `error` (so it is `failed` and retried, and the pass exits 1), and `php env status` lists what is owed under `restarts`
(`[{version, accounts, unresolved, since}]`). One successful `php restart --account` settles every mark the account had.

**Units.** A pass whose path or timer unit cannot be enabled is a failure (`units: false`, `units_error`, exit 1): nothing would retry
it. The redis column shows `unsupported` for an EA4 PHP older than 7.4 (not a failure; see "PHP redis extension").

**State** is one file, `/var/lib/ols-cpanel/php-env.json` (root 0644, `schema_version` 1): `{"checked_at", "profile_error",
"versions": {"ea-phpNN": {version, php, status: "complete" | "repairing" | "failed", checked_at, lsphp, opcache: "ok" | "repaired" |
"failed" | "off", redis: "active" | "repaired" | "failed" | "pending" | "not_wanted", error, attempts, retry_at}}}`. A version is
`repairing` from the moment its first change starts until the pass ends (a record older than two hours is shown as `failed`:
an interrupted pass); a failure records every failing step in `error` (at most 400 characters), counts `attempts` and sets
`retry_at` (back-off 1, 5, 15 and then 30 minutes). `sync` leaves a failed version until its `retry_at`; `repair` ignores it.
Failures are never silent: `php env status`, `php status` (`environment`), the WHM PHP view, the exit code of the pass (1 when any
version is failed, so the unit shows failed) and the journal report them. A damaged state file is treated as empty and rewritten.

**Commands.** `php env status` (read only): `{"command", "result": "status", "checked_at", "opcache_auto", "units": {watcher,
timer}, "profile": {file, present, error}, "versions": [<state row> + "lsphp" (checked now); "pending" before the first pass]}`.
`php env sync` and `php env repair`: `{"command", "result": "unchanged" | "repaired" | "failed", "forced", "units", "profile":
{result: "written" | "unchanged" | "failed", path, packages, php}, "versions": [row + changed, restarted: [accounts], waiting]}`
(`waiting` marks a failed version skipped until its retry time); exit 1 when `failed`.

**Reconciler safety.** After compiling, the reconciler (`Php\LsphpGuard`) checks every natively served vhost's PHP version for a
usable lsphp. A vhost without one keeps its configuration from the ACTIVE generation (read from `active/vhosts/<vhost>/vhconf.conf`;
the tree's health rule and context are removed first because the tree adds them again), so the site answers exactly as before
until the version is complete; the pass result lists them as `php_kept` (`{vhost, php, action: "kept_previous"}`). A vhost with
no usable earlier configuration (new, or its earlier PHP is gone too) refuses the compilation (`CompilationRefused` naming the
vhost, nothing is activated; the pass retries). Either way the guard asks the applier to run through the engine's allowlisted
`systemctl start --no-block ols-cpanel-php.service` (at most once per two minutes), and the next pass after the applier
completes the version compiles it normally. Hybrid vhosts served by Apache are not checked. The cutover's forced pass uses the
same guard.

**Recommended EA4 profile.** `/etc/cpanel/ea4/profiles/custom/ols-cpanel-recommended.json` (root 0644; the directory EasyApache 4
reads for site profiles), `{"name": "OLS-cPanel (OpenLiteSpeed) Recommended", "desc", "version", "tags", "pkgs"}`: cPanel's own schema.
`install --prepare`, `upgrade` and every applier pass write it (only when its content differs); `uninstall` removes it (only a file
of that name that carries our profile name). It is generated by `Deployment\Ea4Profile` from `profiles/cpanel/default.json`
("cPanel Default"): its non-PHP packages (the Apache 2.4 base modules, with `ea-nginx` always excluded) and its per-PHP extension
set are kept; for PHP 8.1 to 8.5, each version that the EasyApache repository offers (from `profiles/pkg-manifest.json`, section
`EA4`, `CentOS_<major>` for EL, the same list EasyApache uses) gets that extension set plus `-php-litespeed` and `-php-opcache`
(not for 8.5, where OPcache is built in); packages the repository does not offer for this OS are left out. Without the default
profile or the manifest, built-in lists (the lists of cPanel 11.138) are used. The product never provisions it: EasyApache 4's
own interface (and `ea_install_profile`) does, and the applier then makes any missing piece complete. `ea-nginx` conflicts with the
product package, so the NGINX profile is refused by the package manager.

**WHM.** The PHP view's "EasyApache compatibility" section lists every version with its state (complete, being repaired, failed with
the reason and the next automatic attempt), the three steps, the time of the last check, a "Repair now" button (job
`ols.php_env_repair`, scope `server`, bound to the status digest like the other PHP jobs) and where the recommended profile is provisioned
(EasyApache 4, "Customize your profile").

## Locks, deadlines and recovery (review RV-29)

Lock order (outer first; never acquired in the other direction):

1. `/var/lib/ols-cpanel/deployment.lock`: exclusive for prepare, cutover, apache-return, hooks, uninstall and
   for `recover.sh`; shared for every reconcile pass (`sync`, root or through the broker). `recover.sh` takes it
   with `flock -w 900` unless it runs synchronously under a holder, which exports `OLS_CPANEL_DEPLOYMENT_LOCK=held`.
   Cutover, prepare and hooks report busy at once; apache-return and uninstall wait up to 900 s (a running pass is
   drained, never interrupted). A reconcile pass is busy (exit 75) while the lock is held exclusively; the cutover's
   own forced pass runs under the cutover's exclusive hold and takes only the reconcile lock.
2. `/var/lib/ols-cpanel/reconcile.lock`: one reconcile pass at a time.
3. `/var/lib/ols-cpanel/activation.lock`: the activator's own (stage, validate, activate, rollback, recover,
   enforce).

Deadlines: every activator transaction has a total deadline (health checks share the remaining budget;
every subprocess, including `systemctl`, is bounded). HR-D11 enforcement runs in the broker (root, its own
thread, every 5 s), independent of the reconciler: when the earliest restriction the served generation lacks
is older than 300 s it stops OLS, waiting for the activation lock at most until that deadline and stopping
without it after (the activator detects the stopped server and fails closed). A restriction the hook could not
record in the epoch is kept as a durable intent file in `/var/lib/ols-cpanel/restrictions/` and folded into
the epoch by the broker's enforcement thread before any other decision; an intent counts as unapplied by
every generation.

Restriction intents (review RV-29, finding 5). When `activator restrict` fails, times out (300 s) or returns no epoch,
`ols-cpanel hook` writes the intent before it prints `1`, whether or not the spool directory exists:

- Directory `restrictions/` (root 0700, created by the hook when absent). One file per restriction, root 0600, named
  `<nanoseconds since the epoch>-<32 lowercase hex>.json` (the spool name grammar `^[0-9]{1,24}-[0-9a-f]{32}\.json$`);
  written to `<name>.tmp-<32 hex>` (mode set before any byte is written), synced, renamed, directory synced.
  Readers ignore every other name (temporary files included).
- Content: one JSON object with exactly the keys `event` (the cPanel event, e.g. `"Accounts::suspendacct"`, or
  null), `reason` (the text the hook passed to `restrict`: `<event> <user>`, at most 200 bytes), `time` (Unix
  seconds, a number: when the hook ran) and `user` (text or null), at most 64 KiB.
- Folding (`engine.restrictions_fold`, the broker's enforcement thread before each round, every reconcile pass
  before it reads the epoch, `ols_events.fold_restrictions`): oldest name first (shorter names first, then
  byte order), `activator restrict <reason>` with `reason` reduced to printable ASCII (each other byte `?`, at most
  200 bytes); an intent that is unreadable, a symbolic link, larger than 64 KiB, not a JSON object or without a
  non-empty text `reason` still raises the epoch, with the reason `restriction intent <name> (malformed)`. The file
  is removed only after `restrict` returned the raised epoch (durable: `epoch.high` and `epoch.json` written with
  fsync); a crash in between folds it twice, which only raises the epoch once more.
- Enforcement before folding: an unfolded intent is a restriction no generation has applied, from its `time`
  (the file's modification time when `time` is unusable); the folded restriction's epoch history time is the fold
  time, at most one enforcement round later.

HTTPS health targets (review RV-29, finding 12). A health target is `{"vhost", "host", "url"}`; `url` is
`http://127.0.0.1:<port>/.ols-cpanel-generation/<file>`, `http://<IPv4>:80/.ols-cpanel-generation/<file>` or
`https://<IPv4>:443/.ols-cpanel-generation/<file>`. For `https` the activator connects to that address and port, sends
`host` as the TLS SNI name and as the `Host` header, does not verify the certificate (the check proves which
generation answers on the local server, not the server's identity) and follows no redirect; like plain HTTP, the
vhost answers the health path itself (its health rule precedes every proxy rule) and only a 200 response whose
body, trimmed, is `<generation> <vhost>` passes; anything else is reported as `got` (`error: HTTP <status>`,
`error: <exception>`). Each target attempt is bounded (2 s) and counts against the transaction's total deadline.
Reference: `ols_generation.health_body`.

Events are consumed (`events_done`) only once a configuration that includes them is active: after a
committed activation, or after a pass that found the active generation already equal to the compiled state
and healthy. Malformed spool entries are moved to `events/quarantine/` by `engine.events_quarantine`
(names as listed by `engine.events`), never left to block consumption: every pass quarantines the malformed
entries it lists at once, whatever its outcome, and marks done only valid entries (a failed quarantine is
reported as `quarantine_error` and retried by the next pass).

Recovery timers stay armed until Apache's ownership and service are verified; `apache-return` and
`uninstall` never remove the fallback after a failed recovery, and destructive cleanup requires verified
Apache service regardless of `profile.json`.
