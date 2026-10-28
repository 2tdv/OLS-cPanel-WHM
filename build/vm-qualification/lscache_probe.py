#!/usr/bin/python3
"""FV-01 lab experiment (LSCache, plan §20.3 and §21.6): WordPress and LiteSpeed Cache for WordPress (pinned,
checksum-verified) are installed into tenant A as the tenant, and the compiled configuration for the lab
tenants is served by the product OLS build on the loopback test listeners (Apache keeps 80/443).

Declared outcomes (expected_outcomes): a public page is stored (miss) and then served from cache (hit);
logged-in requests are never answered from the public cache; the plugin's own purge, an application purge
header and the administrator's purge (lscache.py purge, the product primitive) each empty the cache; the
PURGE method is refused; vhosts and accounts never share entries (same path on tenant A, its subdomain vhost
and tenant B) and their stores are separate and unreadable by tenants; a suspended account's site is never
served from cache; a hybrid vhost (tenant B kept on Apache, both <domain> and tls.<domain>) is never cached;
the translated .htaccess carries the plugin's LiteSpeed section; and removal restores the tenants' files,
database list and the host exactly.

Changes, all undone by one recovery script armed in an independent systemd timer before the first change and
run on the normal return path: the OLS package and its files, the cache tree under /var/lib/ols-cpanel (absent
before), the client network namespace, the WordPress directory and lab pages (as the tenants), tenant A's
database and database user (cPanel UAPI), a suspension of tenant A, and a marker prepended to tenant B's
.htaccess (restored byte for byte as the tenant). Refuses to run when the plugin preview or any product state
is installed. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import html
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
import cpanel_surface
import lscache
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso

ROOT = pathlib.Path(__file__).resolve().parents[2]
LSWS = owner.LSWS
A, B = tf.TENANTS["olscpa"], tf.TENANTS["olscpb"]
SUB = tf.SUBDOMAIN  # tenant A's second vhost (docroot public_html/blog)
PORT, TLS_PORT = iso.PORT, iso.TLS_PORT
# Pinned artifacts. The SHA-256 of each must be recorded from an independent download before the first run;
# the experiment refuses to run with any digest missing and stops on any mismatch.
PINS = {
    "wordpress": {"version": "6.8.2", "url": "https://wordpress.org/wordpress-6.8.2.tar.gz",
                  "sha256": "d85a72e392bfe866816b3c2ebc6a44699072aa50cc3a620f1c4ed2f13b645e2b"},
    "litespeed-cache": {"version": "7.2", "url": "https://downloads.wordpress.org/plugin/litespeed-cache.7.2.zip",
                        "sha256": "5953f5b99dd6edeccf139275334c8dfdb49a52c95d25e1f53a95e453bc802c73"},
    "wp-cli": {"version": "2.12.0", "url": "https://github.com/wp-cli/wp-cli/releases/download/v2.12.0/wp-cli-2.12.0.phar",
               "sha256": "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"},
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
WP_DIR = "/home/olscpa/public_html/olscp-wp"
WP_PATH = "/olscp-wp/"
DB = "olscpa_olscpwp"
WP_ADMIN = "olscpadmin"
# Lab pages: the application instructs public caching; the body names the serving account, host and a nonce.
PAGE = "olscp-cache.php"
PAGE_PHP = ("<?php header('X-LiteSpeed-Cache-Control: public,max-age=300'); header('Content-Type: application/json');\n"
            "echo json_encode(['owner' => posix_getpwuid(posix_geteuid())['name'], 'host' => $_SERVER['HTTP_HOST'] ?? null,\n"
            "                  'nonce' => bin2hex(random_bytes(8))]), \"\\n\";\n")
PURGE_PAGE = "olscp-cache-purge.php"
PURGE_PHP = "<?php header('X-LiteSpeed-Purge: *'); header('Content-Type: text/plain'); echo \"purged\\n\";\n"
PAGES = {A: ("olscpa", "/home/olscpa/public_html"), SUB: ("olscpa", "/home/olscpa/public_html/blog"),
         B: ("olscpb", "/home/olscpb/public_html")}
B_HTACCESS = "/home/olscpb/public_html/.htaccess"
# Prepended to tenant B's .htaccess: SetEnvIf is not translated, so B becomes a hybrid vhost (HR-D08).
HYBRID_MARKER = "SetEnvIf Request_URI \".\" OLS_LAB_HYBRID=apache\n# OLS-cPanel lab hybrid marker end\n"
# On the test listeners the hybrid vhosts reach Apache on its own ports.
HYBRID_PORTS = (80, 443)
STATE = "/var/lib/ols-cpanel"
RECOVERY_ROOT = "/var/lib/ols-cpanel-lab-recovery"
LOCK = "/run/ols-cpanel-recover.lock"
WHMAPI = "/usr/local/cpanel/bin/whmapi1"
UAPI = "/usr/local/cpanel/bin/uapi"
# Anything the plugin preview (plugin_preview.sh) or a product installation leaves behind.
PREVIEW = ["/usr/local/ols-cpanel", "/etc/systemd/system/ols-cpanel-broker.service",
           "/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel", "/usr/local/cpanel/base/frontend/jupiter/ols_cpanel", STATE]
WP_ENV = ["HOME=/home/olscpa", f"WP_CLI_CACHE_DIR={WP_DIR}/.wp-cli-cache", "WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
          # The plugin detects the server from these variables, which OLS gives every PHP request.
          "LSWS_EDITION=Openlitespeed 1.9.3", "X-LSCACHE=on"]

def pins_ready(pins=PINS):
    """Names of artifacts whose digest is not recorded."""
    return sorted(name for name, pin in pins.items() if not SHA256.match(pin.get("sha256") or ""))

def response(stdout):
    """{status, cache, location, body} from `curl -i` output (the last header block wins after 1xx)."""
    head, body = stdout, ""
    while True:
        head, sep, rest = head.partition("\r\n\r\n")
        if not sep or not re.match(r"^HTTP/\S+ 1\d\d", head):
            body = rest
            break
        head = rest
    lines = head.split("\r\n")
    status = lines[0].split()[1] if lines and len(lines[0].split()) > 1 else ""
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers.setdefault(key.strip().lower(), value.strip())
    return {"status": status, "cache": headers.get("x-litespeed-cache"), "location": headers.get("location"),
            "body": body[:4000]}

def page_data(entry):
    try:
        return json.loads(entry["body"]) if entry and entry.get("status") == "200" else {}
    except ValueError:
        return {}

def expected_outcomes(summary):
    """Pass/fail per declared outcome of a completed run (review RV-06)."""
    obs = summary.get("observations") or {}
    get = lambda key: obs.get(key) or {}
    seq = lambda key: obs.get(key) or []
    front = seq("front")
    a_page, sub_page, b_page = seq("page_a"), seq("page_sub"), seq("page_b")
    logged = seq("logged_in")
    stores = summary.get("stats_before_purge") or {}
    store = lambda host, user: stores.get(lscache.store_name(user, host), {})
    stored = lambda s: (s.get("public_entries") or 0) + (s.get("private_entries") or 0) > 0
    admin = get("admin_purge")
    hybrid = seq("hybrid")
    suspended = seq("suspended")
    cases = {
        "htaccess-translated": "<IfModule LiteSpeed>" in (summary.get("lscwp_htaccess") or "")
                               and summary.get("htaccess_blockers", {}).get(A) == [],
        "public-page-miss-then-hit": len(front) == 2 and front[0]["cache"] == "miss" and front[1]["cache"] == "hit",
        "lab-page-miss-then-hit": len(a_page) == 2 and a_page[0]["cache"] == "miss" and a_page[1]["cache"] == "hit"
                                  and page_data(a_page[0]) == page_data(a_page[1]) != {},
        "logged-in-not-from-public-cache": len(logged) == 2 and all(r["status"] == "200" and r["cache"] != "hit"
                                                                    and "wpadminbar" in r["body"] for r in logged)
                                           and get("anonymous_after_login").get("cache") == "hit"
                                           and "wpadminbar" not in get("anonymous_after_login").get("body", "x wpadminbar"),
        "no-cross-vhost-hit": len(sub_page) == 2 and sub_page[0]["cache"] == "miss" and page_data(sub_page[0]).get("host") == SUB
                              and page_data(sub_page[0]).get("nonce") != page_data(a_page[0] if a_page else {}).get("nonce"),
        "no-cross-account-hit": len(b_page) == 2 and b_page[0]["cache"] == "miss" and page_data(b_page[0]).get("owner") == "olscpb",
        "separate-stores": all(stored(store(h, u)) for h, u in ((A, "olscpa"), (SUB, "olscpa"), (B, "olscpb"))),
        "stores-unreadable-by-tenants": bool(summary.get("tenant_reads")) and all(code != 0 for code in summary["tenant_reads"].values())
                                        and summary.get("store_mode") == "nobody nobody 2770",
        "purge-method-refused": get("purge_method").get("status") == "403" and get("after_purge_method").get("cache") == "hit",
        "plugin-purge": bool(summary.get("plugin_purge_link")) and get("after_plugin_purge").get("cache") == "miss",
        "application-purge-scoped-to-vhost": get("before_app_purge").get("cache") == "hit"
                                             and get("after_app_purge").get("cache") == "miss"
                                             and get("other_account_after_app_purge").get("cache") == "hit",
        "admin-purge": stored(admin.get("removed", {}).get(lscache.store_name("olscpa", A), {}))
                       and not stored(admin.get("after", {}).get(lscache.store_name("olscpa", A), {"public_entries": 1}))
                       and get("after_admin_purge").get("cache") == "miss",
        "suspended-not-served-from-cache": len(suspended) >= 2 and all(r["status"] == "302" and r["cache"] is None
                                                                       and cpanel_surface.SUSPENDED_PAGE in (r["location"] or "")
                                                                       for r in suspended)
                                           and (summary.get("cache_while_suspended") or {}).get(A, {}).get("enabled") is False,
        "unsuspended-served-again": get("unsuspended").get("status") == "200",
        "hybrid-never-cached": len(hybrid) == 4 and all(r["status"] == "200" and r["cache"] is None for r in hybrid)
                               and len({page_data(r).get("nonce") for r in hybrid}) == 4
                               and all(page_data(r).get("owner") == "olscpb" for r in hybrid)
                               and summary.get("hybrid_vhosts") == [B],
        "no-ols-errors": summary.get("ols_log_errors") == [],
        "tenant-files-restored": bool(summary.get("files_before")) and summary.get("files_after") == summary.get("files_before"),
        "database-removed": summary.get("databases_after") == summary.get("databases_before") is not None,
        "host-restored": bool(summary.get("restored")) and all(summary["restored"].values()),
    }
    return cases

def recovery_script(backup, b_sha256, b_saved):
    """POSIX shell run as root: undoes every change of the experiment and verifies it. Fixed paths only (it
    never imports the development checkout); tenant paths are handled as the tenant."""
    q = shlex.quote
    as_a, as_b = "timeout 60 runuser -u olscpa --", "timeout 60 runuser -u olscpb --"
    pages = [f"{d}/{p}" for host, (_, d) in PAGES.items() for p in (PAGE, PURGE_PAGE) if host == A or p == PAGE]
    lines = ["#!/bin/sh", "# OLS-cPanel LSCache lab recovery: every experiment change undone.", f"B={q(backup)}",
             "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "T='timeout 120'", f"exec 9>{LOCK}",
             "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }",
             "restore() {", "    $T systemctl stop ols-cpanel.service ols-cpanel-logs.service 2>/dev/null",
             "    if rpm -q ols-cpanel-openlitespeed >/dev/null 2>&1; then $T rpm -e ols-cpanel-openlitespeed; fi",
             f"    rm -rf {LSWS} {owner.WEB} /run/ols-cpanel/lshttpd /dev/shm/ols /tmp/lshttpd {STATE}",
             "    $T systemctl daemon-reload",
             f"    if [ -e /var/cpanel/suspended/olscpa ]; then $T {WHMAPI} --output=json unsuspendacct user=olscpa >/dev/null; fi"]
    if b_saved:
        lines.append(f"    {as_b} sh -c 'cat > \"$1\"' sh {q(B_HTACCESS)} < \"$B/htaccess-b\"")
    lines += [f"    {as_a} rm -rf -- {q(WP_DIR)}"]
    for path in pages:
        user = "olscpb" if path.startswith("/home/olscpb/") else "olscpa"
        lines.append(f"    timeout 60 runuser -u {user} -- rm -f -- {q(path)}")
    lines += [f"    $T {UAPI} --user=olscpa --output=json Mysql delete_database name={DB} >/dev/null",
              f"    $T {UAPI} --user=olscpa --output=json Mysql delete_user name={DB} >/dev/null",
              f"    ip netns delete {iso.NETNS} 2>/dev/null; ip link delete {iso.HOST_IF} 2>/dev/null", "    return 0", "}",
              "verified() {", f"    for p in {LSWS} {owner.WEB} {STATE}; do test ! -e \"$p\" || return 1; done",
              "    test ! -e /var/cpanel/suspended/olscpa || return 1", f"    {as_a} test ! -e {q(WP_DIR)} || return 1"]
    for path in pages:
        user = "olscpb" if path.startswith("/home/olscpb/") else "olscpa"
        lines.append(f"    timeout 60 runuser -u {user} -- test ! -e {q(path)} || return 1")
    if b_saved:
        lines.append(f"    [ \"$({as_b} sh -c 'sha256sum < \"$1\"' sh {q(B_HTACCESS)} | cut -d' ' -f1)\" = {q(b_sha256)} ] || return 1")
    lines += [f"    $T {UAPI} --user=olscpa --output=json Mysql list_databases | grep -qF {q(chr(34) + DB + chr(34))} && return 1",
              "    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
              "    case \"$code\" in [1-4]??) return 0;; esac", "    return 1", "}",
              "for attempt in 1 2 3 4 5; do", "    restore", "    if verified; then echo recovered; exit 0; fi", "    sleep 15", "done",
              "echo 'recovery incomplete' >&2", "exit 1", ""]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Installs WordPress into the lab tenants and suspends tenant A; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    missing = pins_ready()
    if missing:
        parser.error("record the SHA-256 of the pinned artifacts first (PINS): " + ", ".join(missing))
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("lscache-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "lscache-experiment", "started_at": probe.now(), "result": "not_run",
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

        def request(label, host, path, port=PORT, scheme="http", method=None, jar=None, data=None, extra=()):
            command = ["/usr/bin/curl", "--noproxy", "*", "-sk", "--http1.1", "--max-time", "30", "-i",
                       *(["-X", method] if method else []), *(["-b", jar, "-c", jar] if jar else []),
                       *(["--data", data] if data is not None else []), *extra,
                       "--resolve", f"{host}:{port}:127.0.0.1", f"{scheme}://{host}:{port}{path}"]
            return response(step(label, command, 60)["stdout"])

        def twice(label, host, path, **kw):
            return [request(f"{label}-{n}", host, path, **kw) for n in (1, 2)]

        def tenant_files():
            out = {}
            for user in tf.TENANTS:
                base = f"/home/{user}/public_html"
                listing = step("files-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", base, "-xdev",
                                                 "-printf", "%y %m %U %G %P\\n"], 300)
                digests = step("digests-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", base, "-xdev", "-type",
                                                   "f", "-exec", "/usr/bin/sha256sum", "{}", "+"], 600)
                if listing["exit_code"] or digests["exit_code"]:
                    raise ValueError("cannot list the files of " + user)
                out[user] = sorted(listing["stdout"].splitlines()) + sorted(digests["stdout"].splitlines())
            out["wp_cli_home"] = step("wp-cli-home", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/test", "-e",
                                                      "/home/olscpa/.wp-cli"])["exit_code"] != 0
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

        def wp(name, *argv, limit=300):
            php = f"/opt/cpanel/{compiled_plan[A]['php']}/root/usr/bin/php"
            return step("wp-" + name, ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/env", *WP_ENV, php, artifacts["wp-cli"],
                                        "--path=" + WP_DIR, *argv], limit)

        def compile_and_load(label, hybrid=False):
            compiled = iso.compile_lab(step, summary, hybrid_ports=HYBRID_PORTS if hybrid else None)
            iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])
            if step("reload-" + label, ["/usr/bin/systemctl", "reload", owner.UNIT], 120)["exit_code"]:
                raise ValueError("OLS reload failed")
            time.sleep(4)
            return compiled

        def stats(account=None, vhost=None, purge=False):
            command = ["/usr/bin/python3", "-I", str(pathlib.Path(__file__).resolve().parent / "lscache.py"),
                       "purge" if purge else "stats", lscache.CACHE_ROOT, *([account] if account else []), *([vhost] if vhost else [])]
            record = step("cache-purge" if purge else "cache-stats", command)
            return json.loads(record["stdout"]) if record["exit_code"] == 0 else {"error": record["stderr"][-300:]}

        installed = armed = netns = False
        recovery_script_path = None
        artifacts, compiled_plan = {}, {}
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            present = [p for p in [LSWS, owner.WEB, *PREVIEW] if step("residue", ["/usr/bin/test", "-e", p])["exit_code"] == 0]
            if present:
                raise ValueError("OLS, plugin preview or product state present: " + ", ".join(present))
            if step("suspended-before", ["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa"])["exit_code"] == 0:
                raise ValueError("Tenant A is suspended")
            for who, directory in PAGES.values():
                for name in (PAGE, PURGE_PAGE):
                    if step("collision", ["/usr/sbin/runuser", "-u", who, "--", "/usr/bin/test", "-e", f"{directory}/{name}"])["exit_code"] == 0:
                        raise ValueError(f"Refusing to overwrite {directory}/{name}")
            if step("wp-collision", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/test", "-e", WP_DIR])["exit_code"] == 0:
                raise ValueError("Refusing to overwrite " + WP_DIR)
            summary["databases_before"] = databases()
            if summary["databases_before"] is None or DB in summary["databases_before"]:
                raise ValueError("Tenant A's database list is unreadable or already holds " + DB)
            # Pinned artifacts, downloaded as the development user and verified before any change.
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
            b_read = step("b-htaccess", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/cat", B_HTACCESS])
            if b_read["exit_code"] or step("b-htaccess-link", ["/usr/bin/test", "-L", B_HTACCESS])["exit_code"] == 0:
                raise ValueError("Tenant B's .htaccess must be a readable regular file")
            b_sha256 = hashlib.sha256(b_read["stdout"].encode()).hexdigest()
            # Recovery before the first change (RV-27).
            backup = f"{RECOVERY_ROOT}/{run_id}"
            if step("recovery-dir", ["/usr/bin/install", "-d", "-m", "0700", backup])["exit_code"]:
                raise ValueError("Could not create the recovery directory")
            if step("backup-b", ["/usr/bin/sh", "-c", '/usr/sbin/runuser -u olscpb -- /usr/bin/cat -- "$1" > "$2"', "sh",
                                 B_HTACCESS, backup + "/htaccess-b"])["exit_code"]:
                raise ValueError("Could not back up tenant B's .htaccess")
            script = backup + "/recover.sh"
            if step("recovery-script", ["/usr/bin/install", "-m", "0700", stage_file("recover.sh", recovery_script(backup, b_sha256, True)),
                                        script])["exit_code"]:
                raise ValueError("Could not install the recovery script")
            if step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=60min",
                                     "--timer-property=AccuracySec=1s", "/bin/sh", script])["exit_code"]:
                raise ValueError("Could not arm the recovery timer")
            recovery_script_path, armed = script, True
            netns = True
            iso.netns_up(step)
            # The cache root the compiler names: root-owned, traversable by the OLS workers only (lscache.ensure_root).
            for path, mode in ((STATE, "0755"), (lscache.CACHE_ROOT, "0711")):
                if step("cache-root", ["/usr/bin/install", "-d", "-m", mode, "-o", "root", "-g", "root", path])["exit_code"]:
                    raise ValueError("Could not create " + path)
            # WordPress and the plugin, installed as tenant A from the verified artifacts.
            if step("wp-dir", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/mkdir", "-m", "0755", WP_DIR])["exit_code"]:
                raise ValueError("Could not create " + WP_DIR)
            if step("wp-extract", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/tar", "-xzf", artifacts["wordpress"], "-C", WP_DIR,
                                   "--strip-components=1", "--no-same-owner"], 300)["exit_code"]:
                raise ValueError("Could not extract WordPress")
            password = secrets.token_urlsafe(24) + "Aa1"
            uapi("db-create", "Mysql", "create_database", "name=" + DB)
            uapi("db-user", "Mysql", "create_user", "name=" + DB, "password=" + password)
            uapi("db-grant", "Mysql", "set_privileges_on_database", "user=" + DB, "database=" + DB, "privileges=ALL PRIVILEGES")
            for user, (who, directory) in PAGES.items():
                for name, text in ((PAGE, PAGE_PHP), (PURGE_PAGE, PURGE_PHP)):
                    if name == PURGE_PAGE and user != A:
                        continue
                    if step("page", ["/usr/bin/install", "-m", "0644", "-o", who, "-g", who, stage_file(name, text),
                                     f"{directory}/{name}"])["exit_code"]:
                        raise ValueError(f"Could not place {directory}/{name}")
            # Discovery first: the PHP version wp-cli runs with is the vhost's own.
            compiled = iso.compile_lab(step, summary)
            compiled_plan.update(compiled["plan"])
            admin_password = secrets.token_urlsafe(18)
            site = f"http://{A}:{PORT}{WP_PATH.rstrip('/')}"
            for name, argv in (("config", ["config", "create", "--dbname=" + DB, "--dbuser=" + DB, "--dbpass=" + password,
                                           "--dbhost=localhost", "--skip-check"]),
                               ("install", ["core", "install", "--url=" + site, "--title=OLS-cPanel LSCache lab",
                                            "--admin_user=" + WP_ADMIN, "--admin_password=" + admin_password,
                                            "--admin_email=lab@" + A, "--skip-email"]),
                               ("plugin", ["plugin", "install", artifacts["litespeed-cache"], "--activate"])):
                record = wp(name, *argv)
                summary.setdefault("wp", {})[name] = {"exit_code": record["exit_code"], "stderr": record["stderr"][-400:]}
                if record["exit_code"]:
                    raise ValueError(f"wp {name} failed")
            # Plugin settings saved once through the CLI so it (re)writes its .htaccess section (best effort).
            summary["wp"]["cache-on"] = wp("cache-on", "litespeed-option", "set", "cache", "true")["exit_code"]
            summary["wp"]["permalinks"] = wp("permalinks", "rewrite", "structure", "/%postname%/", "--hard")["exit_code"]
            summary["lscwp_htaccess"] = step("wp-htaccess", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat",
                                                             WP_DIR + "/.htaccess"])["stdout"]
            # Recompile so the plugin's section is translated, then serve.
            compiled = iso.compile_lab(step, summary)
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])
            if step("recovery-timer-armed", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer"])["stdout"].strip() != "active":
                raise ValueError("The recovery timer is no longer armed")
            if step("start", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(4)
            summary["cache_initial"] = summary.get("cache")
            # Public caching, vhost and account separation.
            obs["front"] = twice("front", A, WP_PATH)
            obs["page_a"] = twice("page-a", A, "/" + PAGE)
            obs["page_sub"] = twice("page-sub", SUB, "/" + PAGE)
            obs["page_b"] = twice("page-b", B, "/" + PAGE)
            summary["stats_before_purge"] = stats()
            store = f"{lscache.CACHE_ROOT}/{lscache.store_name('olscpa', A)}"
            summary["store_mode"] = step("store-mode", ["/usr/bin/stat", "-c", "%U %G %a", store])["stdout"].strip()
            summary["tenant_reads"] = {user: step("tenant-read-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/ls", store])["exit_code"]
                                       for user in tf.TENANTS}
            # The PURGE method is refused before the cache module could honour it from 127.0.0.1.
            obs["purge_method"] = request("purge-method", A, "/" + PAGE, method="PURGE")
            obs["after_purge_method"] = request("after-purge-method", A, "/" + PAGE)
            # Logged in: never the public entry.
            jar = str(run / "cookies.txt")
            obs["login"] = request("login", A, WP_PATH + "wp-login.php", jar=jar,
                                   data=f"log={WP_ADMIN}&pwd={admin_password}&wp-submit=Log+In&testcookie=1",
                                   extra=["-b", "wordpress_test_cookie=WP%20Cookie%20check"])
            obs["logged_in"] = twice("logged-in", A, WP_PATH, jar=jar)
            obs["anonymous_after_login"] = request("anonymous-after-login", A, WP_PATH)
            # The plugin's own purge: the admin bar "purge all" action as the logged-in administrator.
            full = step("wp-admin", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "30", "-b", jar,
                                     "--resolve", f"{A}:{PORT}:127.0.0.1", f"http://{A}:{PORT}{WP_PATH}wp-admin/"])["stdout"]
            links = [html.unescape(m) for m in re.findall(r'href="([^"]*LSCWP_CTRL=[^"]*)"', full) if "purge_all" in html.unescape(m)]
            summary["plugin_purge_links"] = links[:5]
            summary["plugin_purge_link"] = bool(links)
            if links:
                target = re.sub(r"^https?://[^/]+", "", links[0])
                obs["plugin_purge"] = request("plugin-purge", A, target, jar=jar)
            obs["after_plugin_purge"] = request("after-plugin-purge", A, WP_PATH)
            request("refill-front", A, WP_PATH)
            # An application purge header acts on its own vhost only.
            request("refill-a", A, "/" + PAGE)
            obs["before_app_purge"] = request("before-app-purge", A, "/" + PAGE)
            obs["app_purge"] = request("app-purge", A, "/" + PURGE_PAGE)
            obs["after_app_purge"] = request("after-app-purge", A, "/" + PAGE)
            obs["other_account_after_app_purge"] = request("b-after-app-purge", B, "/" + PAGE)
            # The administrator's purge (product primitive) of tenant A's main vhost.
            request("refill-front-2", A, WP_PATH)
            request("refill-front-3", A, WP_PATH)
            removed = stats("olscpa", A, purge=True)
            obs["admin_purge"] = {"removed": removed, "after": stats("olscpa", A)}
            obs["after_admin_purge"] = request("after-admin-purge", A, WP_PATH)
            # Suspension: cPanel's marker makes the compiler redirect and turn lookups off.
            request("refill-a-2", A, "/" + PAGE)
            request("refill-a-3", A, "/" + PAGE)
            probe.api(step("suspendacct", [WHMAPI, "--output=json", "suspendacct", "user=olscpa", "reason=lab"], 600), "suspendacct")
            compile_and_load("suspended")
            summary["cache_while_suspended"] = summary.get("cache")
            obs["suspended"] = [request("suspended-page", A, "/" + PAGE), request("suspended-front", A, WP_PATH),
                                request("suspended-page-2", A, "/" + PAGE)]
            probe.api(step("unsuspendacct", [WHMAPI, "--output=json", "unsuspendacct", "user=olscpa"], 600), "unsuspendacct")
            compile_and_load("unsuspended")
            obs["unsuspended"] = request("unsuspended-page", A, "/" + PAGE)
            # Hybrid: tenant B stays on Apache behind OLS; its pass-through vhosts never use the cache.
            if step("hybrid-htaccess", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/sh", "-c",
                    'tmp=$(mktemp "$2.XXXXXX") && { printf "%s" "$1"; cat "$2"; } > "$tmp" && cat "$tmp" > "$2"; '
                    'rc=$?; rm -f "$tmp"; exit $rc', "sh", HYBRID_MARKER, B_HTACCESS])["exit_code"]:
                raise ValueError("Could not mark tenant B's .htaccess")
            compile_and_load("hybrid", hybrid=True)
            obs["hybrid"] = (twice("hybrid-http", B, "/" + PAGE)
                             + twice("hybrid-https", B, "/" + PAGE, port=TLS_PORT, scheme="https"))
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                step("stop-ols", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                log = step("ols-error-log", ["/usr/bin/tail", "-c", "200000", LSWS + "/logs/error.log"])["stdout"]
                summary["ols_log_errors"] = [l[27:] for l in log.splitlines() if "[ERROR]" in l][:40]
                summary["ols_cache_log"] = [l[27:] for l in log.splitlines() if "CACHE" in l][:40]
            if armed:
                record = step("recovery-run", ["/bin/sh", recovery_script_path], 900)
                summary["recovery_run"] = {"exit_code": record["exit_code"], "stdout": record["stdout"][-500:],
                                           "stderr": record["stderr"][-500:]}
            elif netns:
                iso.netns_down(step)
            restored = {"recovery_script": not armed or (summary.get("recovery_run") or {}).get("exit_code") == 0,
                        "residue": all(step("final-residue", ["/usr/bin/test", "-e", p])["exit_code"] != 0
                                       for p in [LSWS, owner.WEB, STATE]),
                        "package_absent": step("rpm-final", ["/usr/bin/rpm", "-q", "ols-cpanel-openlitespeed"])["exit_code"] != 0,
                        "not_suspended": step("suspended-final", ["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa"])["exit_code"] != 0,
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200"}
            if summary.get("files_before"):
                summary["files_after"] = tenant_files()
                summary["databases_after"] = databases()
            summary["restored"] = restored
            if armed and all(restored.values()):
                stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])["exit_code"] == 0
                states = step("recovery-unit-state", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer",
                                                       recovery_unit + ".service"])["stdout"].split()
                restored["recovery_disarmed"] = stopped and all(s not in ("active", "activating") for s in states)
            if summary["result"] == "observed":
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": restored,
                              "failed_cases": [k for k, v in (summary.get("cases") or {}).items() if not v["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
