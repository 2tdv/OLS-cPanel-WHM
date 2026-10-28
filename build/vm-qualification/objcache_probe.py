#!/usr/bin/python3
"""FV-09 lab experiment (object cache, plan §21.6): the product's per-account Valkey instances are enabled for the
lab tenants with `ols-cpanel objcache`, and WordPress with LiteSpeed Cache (pinned artifacts shared with
lscache_probe.py) is configured to use tenant A's instance through wp-cli. Apache keeps serving; no OLS is needed.

Declared outcomes (expected_outcomes): the engine is Valkey and its files have the documented owners and modes
(configuration root 0644, socket directory 0700 and socket 0600 owned by the account); each instance runs as its
account, hardened, without any TCP listener; tenant A's PHP (CLI and the web handler through Apache) stores and
reads through its own socket; tenant A cannot connect to tenant B's socket nor B to A's, and neither sees the
other's keys; CONFIG, DEBUG, MODULE and REPLICAOF are refused; filling an instance beyond its maxmemory evicts keys
without restarts or OOM kills and with the unit's MemoryCurrent below its MemoryMax; nothing is persisted; the
flush empties only its own instance; suspending tenant A stops its instance (configuration kept) and unsuspending
starts it, tenant B's never changing; deleting an account removes its instance, unit drop-in, configuration and
state entry; disable removes everything of the account; LiteSpeed Cache's object cache works with the instance
(`configure-wordpress`, a value stored by one wp-cli process read by another, hits counted by the instance); and
removal restores the tenants' files, database list, packages and the host exactly.

Changes, all undone by one recovery script armed in an independent systemd timer before the first change and run
on the normal return path: the product packages and what they install, the `valkey` and EA PHP redis packages (only
when absent before), per-account units, drop-ins, configuration, socket directories and the state under
/var/lib/ols-cpanel (absent before), the WordPress directory, lab pages and database of tenant A, a suspension of
tenant A, and a temporary cPanel account (created and deleted by the experiment itself). Refuses to run when any
product state exists. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lscache_probe as lsp
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
A, B = tf.TENANTS["olscpa"], tf.TENANTS["olscpb"]
USER_A, USER_B = "olscpa", "olscpb"
TEMP_USER, TEMP_DOMAIN = "olscpobj", "olscp-obj.test"
# Artifacts and their digests are the ones of the LSCache experiment (recorded once, shared).
PINS = lsp.PINS
pins_ready = lsp.pins_ready
WP_DIR = "/home/olscpa/public_html/olscp-oc-wp"
DB = "olscpa_olscpoc"
WP_ADMIN = "olscpadmin"
PAGE = "olscp-objcache.php"
PAGE_PATH = "/home/olscpa/public_html/" + PAGE
CLI = "/usr/local/ols-cpanel/bin/ols-cpanel"
STATE = "/var/lib/ols-cpanel"
UNITS = "/etc/systemd/system"
WHMAPI = "/usr/local/cpanel/bin/whmapi1"
UAPI = "/usr/local/cpanel/bin/uapi"
RECOVERY_ROOT = "/var/lib/ols-cpanel-lab-recovery"
LOCK = "/run/ols-cpanel-recover.lock"
SOCKET = lambda user: f"/home/{user}/.ols-objcache/valkey.sock"
UNIT = lambda user: f"ols-cpanel-objcache@{user}.service"
FILL_MB = 16  # tenant B's limit; the fill writes about four times that
RESIDUE = ["/usr/local/ols-cpanel", STATE, "/usr/lib/systemd/system/ols-cpanel-objcache@.service"]
PRODUCT_PACKAGES = ["ols-cpanel", "ols-cpanel-openlitespeed"]
# PHP run as the tenant (EA PHP CLI with the redis extension). The socket paths are substituted, never shell-quoted.
PHP_ROUNDTRIP = ('$r = new Redis(); $r->connect(%(sock)s); $r->set("olscp-k", %(val)s); '
                 'echo json_encode(["get" => $r->get("olscp-k"), "ping" => (bool) $r->ping()]);')
PHP_CROSS = ('try { $r = new Redis(); $ok = @$r->connect(%(sock)s); $v = $ok ? $r->get("olscp-k") : null; '
             'echo json_encode(["connected" => (bool) $ok, "value" => $v]); } '
             'catch (Throwable $e) { echo json_encode(["connected" => false, "value" => null, "error" => $e->getMessage()]); }')
PHP_DISABLED = ('$r = new Redis(); $r->connect(%(sock)s); $out = []; '
                'foreach ([["CONFIG","GET","maxmemory"],["DEBUG","SLEEP","0"],["MODULE","LIST"],["REPLICAOF","NO","ONE"]] as $c) '
                '{ try { $x = $r->rawCommand(...$c); $out[$c[0]] = is_string($x) ? "ok:".$x : "ok"; } '
                'catch (Throwable $e) { $out[$c[0]] = "error:".$e->getMessage(); } } echo json_encode($out);')
PHP_FILL = ('$r = new Redis(); $r->connect(%(sock)s); $v = str_repeat("x", 262144); $n = %(count)s; '
            'for ($i = 0; $i < $n; $i++) { $r->set("fill-$i", $v); } echo json_encode(["written" => $n]);')
PHP_WEB = ("<?php header('Content-Type: application/json'); $r = new Redis(); $ok = $r->connect('" + SOCKET(USER_A) + "'); "
           "$r->set('olscp-web', 'web-ok'); echo json_encode(['connected' => $ok, 'get' => $r->get('olscp-web'), "
           "'owner' => posix_getpwuid(posix_geteuid())['name']]), \"\\n\";\n")
WP_SET = 'wp_cache_set("olscp_probe", "v1", "olscp", 300); echo "set";'
WP_GET = 'echo wp_cache_get("olscp_probe", "olscp");'
WP_EXT = 'echo json_encode(["ext" => wp_using_ext_object_cache()]);'


def php_code(template, **values):
    """PHP source with %(name)s replaced by a PHP string literal (json) or an integer: never concatenated unescaped."""
    return template % {k: (str(v) if isinstance(v, int) else json.dumps(v)) for k, v in values.items()}


def parse_info(text):
    """The INFO fields of valkey-cli output: {name: value}, plus keys= of every db."""
    fields = {}
    for line in text.replace("\r", "").splitlines():
        match = re.match(r"^([a-z0-9_]+):(.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2)
    fields["keys"] = str(sum(int(m) for k, v in fields.items() if re.fullmatch(r"db\d+", k)
                             for m in re.findall(r"keys=(\d+)", v)))
    return fields


def number(fields, key):
    value = fields.get(key, "")
    return int(value) if value.isdigit() else None


def show(text):
    """`systemctl show` output as {Property: value}."""
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def as_json(record):
    try:
        return json.loads(record["stdout"]) if record["exit_code"] == 0 else {}
    except ValueError:
        return {}


def expected_outcomes(summary):
    """Pass/fail per declared outcome of a completed run (review RV-06)."""
    obs = summary.get("observations") or {}
    get = lambda key: obs.get(key) or {}
    enable_a, enable_b = get("enable_a"), get("enable_b")
    modes = get("modes")
    fill = get("fill")
    unit_b = get("unit_b")
    wp = get("wp")
    suspended, unsuspended = get("suspended"), get("unsuspended")
    removal = get("account_removal")
    disabled = get("disable_b")
    info_before, info_after = fill.get("before", {}), fill.get("after", {})
    cases = {
        "engine-is-valkey": "valkey" in (summary.get("engine_version") or "").lower(),
        "enable-results": enable_a.get("result") == "enabled" and enable_b.get("result") == "enabled"
                          and enable_a.get("memory_mb") == 64 and enable_b.get("memory_mb") == FILL_MB
                          and enable_a.get("socket") == SOCKET(USER_A) and obs.get("timer_enabled") is True,
        "files-owners-and-modes": modes == {"conf_a": "root root 644", "dir_a": "olscpa olscpa 700", "sock_a": "olscpa olscpa 600",
                                            "conf_b": "root root 644", "dir_b": "olscpb olscpb 700", "sock_b": "olscpb olscpb 600",
                                            "confdir_a": "root root 755"},
        "instances-run-as-accounts": get("process_users") == {USER_A: USER_A, USER_B: USER_B},
        "unit-hardening": get("unit_a").get("NoNewPrivileges") == "yes" and get("unit_a").get("ProtectSystem") == "strict"
                          and get("unit_a").get("PrivateTmp") == "yes" and get("unit_a").get("User") == USER_A
                          and get("unit_a").get("MemoryMax") == str(112 * 1024 * 1024)
                          and get("unit_a").get("RestrictAddressFamilies", "").split() == ["AF_UNIX"],
        "no-tcp-listener": summary.get("tcp_listeners") == [],
        "own-php-cli-roundtrip": get("cli_a").get("get") == "v-a" and get("cli_a").get("ping") is True
                                 and get("cli_b").get("get") == "v-b",
        "own-php-web-roundtrip": get("web_a").get("connected") is True and get("web_a").get("get") == "web-ok"
                                 and get("web_a").get("owner") == USER_A,
        "no-cross-account-connect": get("a_to_b").get("connected") is False and get("b_to_a").get("connected") is False
                                    and get("a_to_b").get("value") is None and get("b_to_a").get("value") is None,
        "dangerous-commands-refused": bool(get("disabled_cmds")) and all(str(v).startswith("error:") for v in get("disabled_cmds").values())
                                      and len(get("disabled_cmds")) == 4,
        "maxmemory-evicts": number(info_after, "evicted_keys") is not None and number(info_after, "evicted_keys") > 0
                            and number(info_after, "used_memory") is not None
                            and number(info_after, "used_memory") <= number(info_after, "maxmemory") * 1.2
                            and number(info_after, "maxmemory") == FILL_MB * 1024 * 1024
                            and fill.get("written", 0) * 262144 > 3 * FILL_MB * 1024 * 1024,
        "no-oom-no-restart": unit_b.get("NRestarts") == "0" and unit_b.get("ActiveState") == "active" and unit_b.get("Result") == "success"
                             and summary.get("oom_log") == []
                             and number(unit_b, "MemoryCurrent") is not None
                             and number(unit_b, "MemoryCurrent") < number(unit_b, "MemoryMax"),
        "nothing-persisted": summary.get("socket_dir_b_listing") == ["valkey.sock"],
        "flush-own-only": get("flush").get("result") == "flushed" and get("flush").get("keys_a_after") == 0
                          and (get("flush").get("keys_b_after") or 0) > 0,
        "suspend-stops-only-that-instance": suspended.get("a_state") != "active" and suspended.get("b_state") == "active"
                                            and suspended.get("conf_kept") is True and not suspended.get("socket_a_listening"),
        "unsuspend-starts": unsuspended.get("a_state") == "active" and unsuspended.get("b_state") == "active"
                            and unsuspended.get("socket_a_listening") is True,
        "account-removal-cleans-up": removal.get("enabled") == "enabled" and removal.get("state_before") == "active"
                                     and removal.get("state_after") != "active" and removal.get("conf_dir_exists") is False
                                     and removal.get("dropin_exists") is False and removal.get("in_state") is False,
        "disable-removes-everything": disabled.get("result") == "disabled" and disabled.get("state") != "active"
                                      and disabled.get("conf_dir_exists") is False and disabled.get("dropin_exists") is False
                                      and disabled.get("socket_dir_exists") is False and disabled.get("in_state") is False
                                      and disabled.get("a_still_active") is True,
        "wordpress-configured": wp.get("configure", {}).get("result") == "configured" and wp.get("configure", {}).get("host") == SOCKET(USER_A)
                                and wp.get("configure", {}).get("port") == 0 and wp.get("object_kind") == "1"
                                and wp.get("object_host") == SOCKET(USER_A),
        "wordpress-object-cache-hits": wp.get("ext") is True and wp.get("persisted_value") == "v1"
                                       and (wp.get("hits_after") or 0) > (wp.get("hits_before") or 0),
        "no-errors-in-journal": summary.get("journal_errors") == [],
        "tenant-files-restored": bool(summary.get("files_before")) and summary.get("files_after") == summary.get("files_before"),
        "database-removed": summary.get("databases_after") == summary.get("databases_before") is not None,
        "host-restored": bool(summary.get("restored")) and all(summary["restored"].values()),
    }
    return cases


def recovery_script(backup, packages):
    """POSIX shell run as root: undoes every change of the experiment and verifies it. Fixed paths only (it never
    imports the development checkout); tenant paths are handled as the tenant. `packages` are the ones the
    experiment installed (absent before)."""
    q = shlex.quote
    as_a = "timeout 60 runuser -u olscpa --"
    users = (USER_A, USER_B, TEMP_USER)
    lines = ["#!/bin/sh", "# OLS-cPanel object cache lab recovery: every experiment change undone.", f"B={q(backup)}",
             "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "T='timeout 120'", f"exec 9>{LOCK}",
             "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }",
             "restore() {",
             "    $T systemctl disable --now ols-cpanel-objcache.timer 2>/dev/null",
             "    $T systemctl stop ols-cpanel-objcache.service 2>/dev/null",
             *[f"    $T systemctl stop {UNIT(u)} 2>/dev/null" for u in users],
             f"    if [ -e /var/cpanel/suspended/olscpa ]; then $T {WHMAPI} --output=json unsuspendacct user=olscpa >/dev/null; fi",
             f"    if [ -e /var/cpanel/users/{TEMP_USER} ]; then $T {WHMAPI} --output=json removeacct username={TEMP_USER} >/dev/null; fi",
             "    for p in " + " ".join(PRODUCT_PACKAGES) + "; do if rpm -q $p >/dev/null 2>&1; then $T rpm -e $p; fi; done"]
    if packages:
        lines.append("    $T dnf -y -q remove " + " ".join(q(p) for p in packages) + " >/dev/null 2>&1")
    lines += [f"    rm -rf {UNITS}/ols-cpanel-objcache@*.service.d {UNITS}/timers.target.wants/ols-cpanel-objcache.timer {STATE}",
              "    $T systemctl daemon-reload", f"    $T systemctl reset-failed {' '.join(UNIT(u) for u in users)} 2>/dev/null",
              f"    timeout 60 runuser -u olscpa -- rm -rf -- /home/olscpa/.ols-objcache {q(WP_DIR)}",
              "    timeout 60 runuser -u olscpb -- rm -rf -- /home/olscpb/.ols-objcache",
              f"    timeout 60 runuser -u olscpa -- rm -f -- {q(PAGE_PATH)}",
              f"    $T {UAPI} --user=olscpa --output=json Mysql delete_database name={DB} >/dev/null",
              f"    $T {UAPI} --user=olscpa --output=json Mysql delete_user name={DB} >/dev/null", "    return 0", "}",
              "verified() {", f"    test ! -e {STATE} || return 1", "    test ! -e /var/cpanel/suspended/olscpa || return 1",
              f"    test ! -e /var/cpanel/users/{TEMP_USER} || return 1",
              "    for p in " + " ".join(PRODUCT_PACKAGES + list(packages)) + "; do if rpm -q $p >/dev/null 2>&1; then return 1; fi; done",
              f"    ls {UNITS}/ols-cpanel-objcache* >/dev/null 2>&1 && return 1",
              "    ls /usr/lib/systemd/system/ols-cpanel-objcache* >/dev/null 2>&1 && return 1",
              f"    {as_a} test ! -e /home/olscpa/.ols-objcache || return 1", f"    {as_a} test ! -e {q(WP_DIR)} || return 1",
              "    timeout 60 runuser -u olscpb -- test ! -e /home/olscpb/.ols-objcache || return 1",
              f"    {as_a} test ! -e {q(PAGE_PATH)} || return 1",
              f"    $T {UAPI} --user=olscpa --output=json Mysql list_databases | grep -qF {q(chr(34) + DB + chr(34))} && return 1",
              "    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
              "    case \"$code\" in [1-4]??) return 0;; esac", "    return 1", "}",
              "for attempt in 1 2 3 4 5; do", "    restore", "    if verified; then echo recovered; exit 0; fi", "    sleep 15", "done",
              "echo 'recovery incomplete' >&2", "exit 1", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, action="append", type=pathlib.Path,
                        help="the ols-cpanel product RPM and the ols-cpanel-openlitespeed RPM it requires (repeat)")
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Installs packages, WordPress and a temporary account and suspends tenant A; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    missing = pins_ready()
    if missing:
        parser.error("record the SHA-256 of the pinned artifacts first (lscache_probe.PINS): " + ", ".join(missing))
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("objcache-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "objcache-experiment", "started_at": probe.now(), "result": "not_run",
                   "recovery_unit": recovery_unit, "pins": PINS, "observations": {}}
        obs = summary["observations"]
        index = 0

        def step(name, command, limit=120):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
            return record

        def stage_file(name, content):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            return str(path)

        def ols(*argv, limit=180):
            record = step("ols-" + "-".join(a for a in argv[:2] if not a.startswith("-")), [CLI, *argv, "--format=json"], limit)
            return {"exit_code": record["exit_code"], **as_json(record)}

        def as_user(user, command, name="as-user", limit=120):
            return step(name, ["/usr/sbin/runuser", "-u", user, "--", *command], limit)

        def php(user, code, name):
            record = as_user(user, [php_bin, "-r", code], name)
            try:
                return json.loads(record["stdout"]) if record["exit_code"] == 0 else {"exit_code": record["exit_code"],
                                                                                    "stderr": record["stderr"][-300:]}
            except ValueError:
                return {"exit_code": record["exit_code"], "stdout": record["stdout"][-300:]}

        def wp(name, *argv, limit=300):
            return as_user(USER_A, ["/usr/bin/env", f"HOME=/home/{USER_A}", "WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
                                    f"WP_CLI_CACHE_DIR={WP_DIR}/.wp-cli-cache", php_bin, "-d", "memory_limit=512M", artifacts["wp-cli"],
                                    "--path=" + WP_DIR, *argv], "wp-" + name, limit)

        def info(user):
            record = as_user(user, ["/usr/bin/valkey-cli", "-s", SOCKET(user), "INFO"], "info-" + user, 60)
            return parse_info(record["stdout"]) if record["exit_code"] == 0 else {}

        def unit_state(user):
            return step("is-active-" + user, ["/usr/bin/systemctl", "is-active", UNIT(user)])["stdout"].strip()

        def exists(path):
            return step("exists", ["/usr/bin/test", "-e", path])["exit_code"] == 0

        def exists_as(user, path):
            return as_user(user, ["/usr/bin/test", "-e", path], "exists-as")["exit_code"] == 0

        def in_state(user):
            record = step("state", ["/usr/bin/cat", STATE + "/objcache.json"])
            try:
                return user in json.loads(record["stdout"]).get("accounts", {})
            except ValueError:
                return False

        def listening(user):
            record = step("ss-unix", ["/usr/sbin/ss", "-H", "-lxn"])
            return SOCKET(user) in record["stdout"]

        def tenant_files():
            out = {}
            for user in tf.TENANTS:
                base = f"/home/{user}/public_html"
                listing = as_user(user, ["/usr/bin/find", base, "-xdev", "-printf", "%y %m %U %G %P\\n"], "files-" + user, 300)
                digests = as_user(user, ["/usr/bin/find", base, "-xdev", "-type", "f", "-exec", "/usr/bin/sha256sum", "{}", "+"],
                                  "digests-" + user, 600)
                if listing["exit_code"] or digests["exit_code"]:
                    raise ValueError("cannot list the files of " + user)
                out[user] = sorted(listing["stdout"].splitlines()) + sorted(digests["stdout"].splitlines())
            return out

        def databases():
            data = json.loads(step("databases", [UAPI, "--user=olscpa", "--output=json", "Mysql", "list_databases"])["stdout"] or "{}")
            rows = (data.get("result") or {}).get("data")
            return None if rows is None else sorted(r.get("database", "") for r in rows)

        def uapi(name, *argv):
            record = step(name, [UAPI, "--user=olscpa", "--output=json", *argv])
            try:
                ok = json.loads(record["stdout"])["result"]["status"] == 1
            except (ValueError, KeyError, TypeError):
                ok = False
            if not ok:
                raise ValueError(f"UAPI {' '.join(argv[:2])} failed")

        def settle(command, wanted, tries=20):
            """Polls a state the hook would have applied (the reconciliation unit runs synchronously: oneshot)."""
            for _ in range(tries):
                if command() == wanted:
                    return True
                time.sleep(1)
            return False

        def reconcile_now():
            return step("reconcile-unit", ["/usr/bin/systemctl", "start", "ols-cpanel-objcache.service"], 300)

        armed = installed = False
        recovery_script_path = None
        artifacts, packages, php_bin = {}, [], None
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            present = [p for p in [*RESIDUE, UNITS + "/ols-cpanel-objcache.timer"] if exists(p)]
            if present:
                raise ValueError("Product state present: " + ", ".join(present))
            if exists("/var/cpanel/suspended/olscpa") or exists(f"/var/cpanel/users/{TEMP_USER}"):
                raise ValueError("Tenant A is suspended or the temporary account exists")
            if exists_as(USER_A, PAGE_PATH) or exists_as(USER_A, WP_DIR):
                raise ValueError("Refusing to overwrite a lab path of tenant A")
            summary["databases_before"] = databases()
            if summary["databases_before"] is None or DB in summary["databases_before"]:
                raise ValueError("Tenant A's database list is unreadable or already holds " + DB)
            versions = as_json(step("php-versions", [WHMAPI, "--output=json", "php_get_vhost_versions"]))
            main = [r["version"] for r in versions.get("data", {}).get("versions", [])
                    if r.get("account") == USER_A and r.get("main_domain")]
            if not main or not re.fullmatch(r"ea-php\d{2,3}", main[0]):
                raise ValueError("Cannot determine tenant A's PHP version")
            php_version = main[0]
            php_bin = f"/opt/cpanel/{php_version}/root/usr/bin/php"
            for name, pin in PINS.items():
                target = run / pathlib.Path(pin["url"]).name
                fetched = subprocess.run(["/usr/bin/curl", "-fsSL", "--max-time", "300", "-o", str(target), pin["url"]],
                                         capture_output=True, text=True, check=False)
                digest = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
                summary.setdefault("artifacts", {})[name] = {"exit_code": fetched.returncode, "sha256": digest}
                if digest != pin["sha256"]:
                    raise ValueError(f"{name} {pin['version']} does not match its pinned SHA-256")
                os.chmod(target, 0o644)
                artifacts[name] = str(target)
            summary["files_before"] = tenant_files()
            # Packages the experiment needs and does not find: installed by it, removed again by the recovery.
            for package in ("valkey", f"{php_version}-php-redis"):
                if step("rpm-before", ["/usr/bin/rpm", "-q", package])["exit_code"] != 0:
                    packages.append(package)
            summary["installed_packages"] = packages
            backup = f"{RECOVERY_ROOT}/{run_id}"
            if step("recovery-dir", ["/usr/bin/install", "-d", "-m", "0700", backup])["exit_code"]:
                raise ValueError("Could not create the recovery directory")
            script = backup + "/recover.sh"
            if step("recovery-script", ["/usr/bin/install", "-m", "0700", stage_file("recover.sh", recovery_script(backup, packages)),
                                        script])["exit_code"]:
                raise ValueError("Could not install the recovery script")
            if step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=60min",
                                     "--timer-property=AccuracySec=1s", "/bin/sh", script])["exit_code"]:
                raise ValueError("Could not arm the recovery timer")
            recovery_script_path, armed = script, True
            installed = True
            if packages and step("dnf-install", ["/usr/bin/dnf", "-y", "-q", "install", *packages], 900)["exit_code"]:
                raise ValueError("Installing " + " ".join(packages) + " failed")
            if step("rpm-install", ["/usr/bin/rpm", "-i", *[str(p.resolve()) for p in args.rpm]], 300)["exit_code"]:
                raise ValueError("Product RPM install failed")
            summary["engine_version"] = step("engine-version", ["/usr/bin/valkey-server", "--version"])["stdout"].strip()
            # WordPress and LiteSpeed Cache as tenant A (wp-cli only: Apache keeps serving, nothing else is needed).
            if step("wp-dir", ["/usr/sbin/runuser", "-u", USER_A, "--", "/usr/bin/mkdir", "-m", "0755", WP_DIR])["exit_code"]:
                raise ValueError("Could not create " + WP_DIR)
            if as_user(USER_A, ["/usr/bin/tar", "-xzf", artifacts["wordpress"], "-C", WP_DIR, "--strip-components=1", "--no-same-owner"],
                       "wp-extract", 300)["exit_code"]:
                raise ValueError("Could not extract WordPress")
            password = secrets.token_urlsafe(24) + "Aa1"
            uapi("db-create", "Mysql", "create_database", "name=" + DB)
            uapi("db-user", "Mysql", "create_user", "name=" + DB, "password=" + password)
            uapi("db-grant", "Mysql", "set_privileges_on_database", "user=" + DB, "database=" + DB, "privileges=ALL PRIVILEGES")
            admin_password = secrets.token_urlsafe(18)
            site = f"http://{A}/olscp-oc-wp"
            for name, argv in (("config", ["config", "create", "--dbname=" + DB, "--dbuser=" + DB, "--dbpass=" + password,
                                           "--dbhost=localhost", "--skip-check"]),
                               ("install", ["core", "install", "--url=" + site, "--title=OLS-cPanel object cache lab",
                                            "--admin_user=" + WP_ADMIN, "--admin_password=" + admin_password,
                                            "--admin_email=lab@" + A, "--skip-email"]),
                               ("plugin", ["plugin", "install", artifacts["litespeed-cache"], "--activate"])):
                if wp(name, *argv)["exit_code"]:
                    raise ValueError(f"wp {name} failed")
            if step("page", ["/usr/bin/install", "-m", "0644", "-o", USER_A, "-g", USER_A, stage_file(PAGE, PHP_WEB), PAGE_PATH])["exit_code"]:
                raise ValueError("Could not place " + PAGE_PATH)
            # Enable: tenant A with the default memory, tenant B with the small limit the fill test uses.
            obs["enable_a"] = ols("objcache", "enable", "--account=" + USER_A, "--memory=64")
            obs["enable_b"] = ols("objcache", "enable", "--account=" + USER_B, "--memory=%d" % FILL_MB)
            obs["timer_enabled"] = step("timer-enabled", ["/usr/bin/systemctl", "is-enabled", "ols-cpanel-objcache.timer"])["stdout"].strip() == "enabled"
            stat = lambda path, name: step("stat-" + name, ["/usr/bin/stat", "-c", "%U %G %a", path])["stdout"].strip()
            obs["modes"] = {"conf_a": stat(f"{STATE}/objcache/{USER_A}/valkey.conf", "conf-a"), "confdir_a": stat(f"{STATE}/objcache/{USER_A}", "confdir-a"),
                            "dir_a": stat(f"/home/{USER_A}/.ols-objcache", "dir-a"), "sock_a": stat(SOCKET(USER_A), "sock-a"),
                            "conf_b": stat(f"{STATE}/objcache/{USER_B}/valkey.conf", "conf-b"),
                            "dir_b": stat(f"/home/{USER_B}/.ols-objcache", "dir-b"), "sock_b": stat(SOCKET(USER_B), "sock-b")}
            obs["process_users"] = {u: step("ps-" + u, ["/usr/bin/ps", "-o", "user=", "-p",
                                    step("mainpid-" + u, ["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", UNIT(u)])["stdout"].strip() or "0"]
                                            )["stdout"].strip() for u in (USER_A, USER_B)}
            obs["unit_a"] = show(step("show-a", ["/usr/bin/systemctl", "show", UNIT(USER_A), "-p", "User", "-p", "NoNewPrivileges", "-p", "ProtectSystem",
                                                  "-p", "PrivateTmp", "-p", "MemoryMax", "-p", "RestrictAddressFamilies"])["stdout"])
            ss = step("ss-tcp", ["/usr/sbin/ss", "-H", "-ltnp"])["stdout"]
            summary["tcp_listeners"] = [line for line in ss.splitlines() if "valkey" in line]
            # Own PHP: CLI, and the web handler through Apache.
            obs["cli_a"] = php(USER_A, php_code(PHP_ROUNDTRIP, sock=SOCKET(USER_A), val="v-a"), "cli-a")
            obs["cli_b"] = php(USER_B, php_code(PHP_ROUNDTRIP, sock=SOCKET(USER_B), val="v-b"), "cli-b")
            web = step("web-a", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "30", "--resolve", f"{A}:80:127.0.0.1", f"http://{A}/{PAGE}"], 60)
            try:
                obs["web_a"] = json.loads(web["stdout"])
            except ValueError:
                obs["web_a"] = {"error": web["stdout"][-200:]}
            # Isolation and refused commands.
            obs["a_to_b"] = php(USER_A, php_code(PHP_CROSS, sock=SOCKET(USER_B)), "a-to-b")
            obs["b_to_a"] = php(USER_B, php_code(PHP_CROSS, sock=SOCKET(USER_A)), "b-to-a")
            obs["disabled_cmds"] = php(USER_A, php_code(PHP_DISABLED, sock=SOCKET(USER_A)), "disabled")
            # Memory limit: about four times tenant B's maxmemory, written in 256 KiB values.
            obs["fill"] = {"before": info(USER_B)}
            obs["fill"].update(php(USER_B, php_code(PHP_FILL, sock=SOCKET(USER_B), count=FILL_MB * 4 * 4), "fill"))
            obs["fill"]["after"] = info(USER_B)
            obs["unit_b"] = show(step("show-b", ["/usr/bin/systemctl", "show", UNIT(USER_B), "-p", "NRestarts", "-p", "ActiveState", "-p", "Result",
                                                  "-p", "MemoryCurrent", "-p", "MemoryMax"])["stdout"])
            log = step("journal-b", ["/usr/bin/journalctl", "-u", UNIT(USER_B), "-u", UNIT(USER_A), "--no-pager", "-o", "cat"])["stdout"]
            summary["oom_log"] = [l for l in log.splitlines() if re.search(r"oom|out of memory|Killed|signal", l, re.I)][:20]
            listing = as_user(USER_B, ["/usr/bin/ls", "-A", f"/home/{USER_B}/.ols-objcache"], "listing-b")["stdout"].split()
            summary["socket_dir_b_listing"] = sorted(listing)
            # WordPress with LiteSpeed Cache through the product command.
            obs["wp"] = {"configure": ols("objcache", "configure-wordpress", "--account=" + USER_A, "--path=" + WP_DIR)}
            for key in ("object-kind", "object-host"):
                obs["wp"][key.replace("-", "_")] = wp("get-" + key, "litespeed-option", "get", key)["stdout"].strip()
            before = info(USER_A)
            obs["wp"]["ext"] = None
            try:
                obs["wp"]["ext"] = json.loads(wp("ext", "eval", WP_EXT)["stdout"]).get("ext")
            except ValueError:
                pass
            wp("set", "eval", WP_SET)
            obs["wp"]["persisted_value"] = wp("get", "eval", WP_GET)["stdout"].strip()
            for _ in range(5):
                wp("option", "option", "get", "blogname")
            after = info(USER_A)
            obs["wp"]["hits_before"], obs["wp"]["hits_after"] = number(before, "keyspace_hits"), number(after, "keyspace_hits")
            obs["wp"]["dropin"] = exists_as(USER_A, WP_DIR + "/wp-content/object-cache.php")
            # Flush: tenant A's only.
            obs["flush"] = ols("objcache", "flush", "--account=" + USER_A)
            obs["flush"]["keys_a_after"] = number(info(USER_A), "keys")
            obs["flush"]["keys_b_after"] = number(info(USER_B), "keys")
            # Suspension and unsuspension: cPanel's marker, then the reconciliation the hook triggers.
            probe.api(step("suspendacct", [WHMAPI, "--output=json", "suspendacct", "user=olscpa", "reason=lab"], 600), "suspendacct")
            reconcile_now()
            obs["suspended"] = {"a_state": unit_state(USER_A), "b_state": unit_state(USER_B), "socket_a_listening": listening(USER_A),
                                "conf_kept": exists(f"{STATE}/objcache/{USER_A}/valkey.conf")}
            probe.api(step("unsuspendacct", [WHMAPI, "--output=json", "unsuspendacct", "user=olscpa"], 600), "unsuspendacct")
            reconcile_now()
            settle(lambda: unit_state(USER_A), "active")
            obs["unsuspended"] = {"a_state": unit_state(USER_A), "b_state": unit_state(USER_B), "socket_a_listening": listening(USER_A)}
            # Account deletion: a temporary account is enabled, then removed through cPanel.
            probe.api(step("temp-create", [WHMAPI, "--output=json", "createacct", "username=" + TEMP_USER, "domain=" + TEMP_DOMAIN,
                                           "password=" + secrets.token_urlsafe(18) + "Aa1!", "contactemail=", "hasshell=0"], 600), "createacct")
            temp = ols("objcache", "enable", "--account=" + TEMP_USER, "--memory=16")
            obs["account_removal"] = {"enabled": temp.get("result"), "state_before": unit_state(TEMP_USER)}
            probe.api(step("temp-remove", [WHMAPI, "--output=json", "removeacct", "username=" + TEMP_USER], 600), "removeacct")
            reconcile_now()
            settle(lambda: unit_state(TEMP_USER), "inactive")
            obs["account_removal"].update({"state_after": unit_state(TEMP_USER), "conf_dir_exists": exists(f"{STATE}/objcache/{TEMP_USER}"),
                                           "dropin_exists": exists(f"{UNITS}/{UNIT(TEMP_USER)}.d"), "in_state": in_state(TEMP_USER)})
            # Disable removes everything of tenant B and nothing of tenant A.
            disabled = ols("objcache", "disable", "--account=" + USER_B)
            obs["disable_b"] = {"result": disabled.get("result"), "state": unit_state(USER_B),
                                "conf_dir_exists": exists(f"{STATE}/objcache/{USER_B}"), "dropin_exists": exists(f"{UNITS}/{UNIT(USER_B)}.d"),
                                "socket_dir_exists": exists_as(USER_B, f"/home/{USER_B}/.ols-objcache"), "in_state": in_state(USER_B),
                                "a_still_active": unit_state(USER_A) == "active"}
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                log = step("journal-all", ["/usr/bin/journalctl", "-u", "ols-cpanel-objcache*", "--no-pager", "-o", "cat", "-p", "err"])["stdout"]
                summary["journal_errors"] = [l for l in log.splitlines() if l.strip()][:40]
            if armed:
                record = step("recovery-run", ["/bin/sh", recovery_script_path], 900)
                summary["recovery_run"] = {"exit_code": record["exit_code"], "stdout": record["stdout"][-500:], "stderr": record["stderr"][-500:]}
            restored = {"recovery_script": not armed or (summary.get("recovery_run") or {}).get("exit_code") == 0,
                        "residue": all(step("final-residue", ["/usr/bin/test", "-e", p])["exit_code"] != 0 for p in [STATE, "/usr/local/ols-cpanel"]),
                        "packages_absent": all(step("rpm-final", ["/usr/bin/rpm", "-q", p])["exit_code"] != 0 for p in [*PRODUCT_PACKAGES, *packages]),
                        "not_suspended": step("suspended-final", ["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa"])["exit_code"] != 0,
                        "temp_account_absent": step("temp-final", ["/usr/bin/test", "-e", f"/var/cpanel/users/{TEMP_USER}"])["exit_code"] != 0,
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200"}
            if summary.get("files_before"):
                summary["files_after"] = tenant_files()
                summary["databases_after"] = databases()
            summary["restored"] = restored
            if armed and all(restored.values()):
                stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])["exit_code"] == 0
                states = step("recovery-unit-state", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer", recovery_unit + ".service"])["stdout"].split()
                restored["recovery_disarmed"] = stopped and all(s not in ("active", "activating") for s in states)
            if summary["result"] == "observed":
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": restored,
                              "failed_cases": [k for k, v in (summary.get("cases") or {}).items() if not v["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
