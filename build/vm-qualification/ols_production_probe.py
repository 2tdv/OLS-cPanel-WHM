#!/usr/bin/python3
"""Production-port experiment (G0-E, OLS-17/18/19): the complete compiled configuration for the lab
tenants (every cPanel vhost, service vhosts, the catch-all proxy vhost, log shipper) served by OLS on
the real *:80/*:443 listeners. Apache's answers are recorded first from the simulated external
client, an independent recovery timer is armed, 80/443 move to OLS through cPanel's configureservice
API, the same requests are repeated against OLS, and everything returns to Apache.
Covers what test listeners cannot: per-port log routing (":443" -> -ssl_log) and DCV through
get_local.cgi, which fetches from SERVER_ADDR:80. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpanel_surface
import ols_config_lint
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso
import hybrid_lab

ROOT = pathlib.Path(__file__).resolve().parents[2]
LSWS = owner.LSWS
TOKEN = "/.well-known/acme-challenge/" + tf.DCV_TOKEN
A, B = tf.TENANTS["olscpa"], tf.TENANTS["olscpb"]
# (scheme, host, path, mode): mode "status" compares only the status (front-server error pages).
CASES = [("http", A, "/static.txt", ""), ("http", "www." + A, "/static.txt", ""), ("http", A, "/private/", ""),
         ("http", A, "/denied/", ""), ("http", A, "/.env", ""), ("http", A, "/missing-page", ""),
         ("http", B, "/hello-world/", ""), ("http", B, "/old-page", ""), ("http", tf.SUBDOMAIN, "/whoami.php", ""),
         ("http", tf.ADDON, "/whoami.php", ""), ("http", tf.PARKED, "/static.txt", ""), ("http", tf.SECURE, "/static.txt", ""),
         ("http", tf.SECURE, TOKEN, ""), ("http", A, TOKEN, ""), ("http", "cpanel." + A, "/", ""), ("http", "whm." + A, "/", ""),
         ("http", "whm." + A, TOKEN, ""), ("http", "cpanel.nowhere.example", TOKEN, ""), ("http", A, "/img-sys/csf.svg", ""),
         ("http", A, "/cpanel", ""), ("http", "autoconfig." + tf.ADDON, "/", ""), ("http", A, "/mailman/listinfo", ""),
         ("http", A, "/cgi-bin/whoami.cgi", ""),
         ("https", A, "/static.txt", ""), ("https", "cpanel." + A, "/", ""), ("https", "webmail." + tf.ADDON, "/", ""),
         ("https", "whm." + A, "/", ""), ("https", "cpanel.nowhere.example", "/", ""), ("https", tf.SECURE, TOKEN, ""),
         ("https", tf.ADDON, "/whoami.php", ""), ("https", A, "/Microsoft-Server-ActiveSync", "status"),
         ("https", B, "/hello-world/", ""), ("https", "autodiscover." + A, "/", ""),
         # Unknown names: Apache answers with the first vhost on the address (name-based default).
         ("http", "nowhere.example", "/static.txt", ""), ("https", "nowhere.example", "/static.txt", "")]
TLS_NAMES = [A, "www." + A, "cpanel." + A, tf.ADDON, "cpanel." + tf.ADDON, tf.SUBDOMAIN, "whm." + A, "cpanel.nowhere.example"]
HYBRID_PORTS = (81, 444)
# Prepended to tenant B's .htaccess: SetEnvIf is not translated, so B becomes a hybrid vhost; the WebSocket
# rule sends upgrades through Apache's own ws:// proxy to the lab echo backend.
HYBRID_MARKER = ("SetEnvIf Request_URI \".\" OLS_LAB_HYBRID=apache\nRewriteEngine On\n" + iso.WS_ECHO_RULES
                 + "# OLS-cPanel lab hybrid marker end\n")
HYBRID_PAGE = "olscp-hybrid.php"
# SERVER_SOFTWARE names the server that ran PHP ("Apache" or "LiteSpeed"); suexec drops custom variables.
HYBRID_PHP = ("<?php header('Content-Type: application/json'); echo json_encode(['server' => $_SERVER['SERVER_SOFTWARE'] ?? null, "
              "'remote' => $_SERVER['REMOTE_ADDR'] ?? null, 'https' => $_SERVER['HTTPS'] ?? null, "
              "'host' => $_SERVER['HTTP_HOST'] ?? null, 'query' => $_SERVER['QUERY_STRING'] ?? null, "
              "'user' => posix_getpwuid(posix_geteuid())['name']]), \"\\n\";\n")
HYBRID_QUERY = "?q=olscp"
HYBRID_FILES = {"htaccess": "/home/olscpb/public_html/.htaccess", "page": "/home/olscpb/public_html/" + HYBRID_PAGE,
                "acme": "/home/olscpb/public_html/.well-known/acme-challenge/" + HYBRID_PAGE}
HYBRID_DIRS = ["/home/olscpb/public_html/.well-known", "/home/olscpb/public_html/.well-known/acme-challenge"]
SPOOF = ["-H", "X-OLS-Client-IP: 203.0.113.9", "-H", "X-Forwarded-For: 203.0.113.9"]
RECOVERY_ROOT = "/var/lib/ols-cpanel-lab-recovery"
OLS_NAMES = ["litespeed", "openlitespeed", "lshttpd"]
# Authenticated WebSocket upgrades through cpanel.<domain> (owner-approved lab session for olscpa).
WS_SESSION = pathlib.Path(__file__).resolve().parent / "cpanel_ws_session.py"
WS_PATHS = ["/websocket/Shell?rows=24&cols=80", "/websocket/MysqlDump?dbname=none"]

def expected_outcomes(summary):
    """Pass/fail per declared expectation; a dedicated-IPv6 comparison is required only when the lab
    has an account with an IPv6 address."""
    equal = lambda section: bool(summary.get(section)) and all(v["match"] for v in summary[section].values())
    true_all = lambda section: bool(summary.get(section)) and all(summary[section].values())
    cases = {
        "ipv4-requests-equal": equal("comparison"),
        "ipv6-requests-equal": equal("comparison_v6"),
        "ipv4-certificates-equal": true_all("tls_match"),
        "ipv6-certificates-equal": true_all("tls_match_v6"),
        "websocket-sessions-equal": true_all("ws_session_match"),
        "log-routing": (summary.get("log_routing") or {}).get("ok") is True,
        "no-ols-errors": summary.get("ols_log_errors") == [],
        "host-restored": true_all("restored"),
        "php-survives-reload": bool((summary.get("reload") or {}).get("after"))
                               and all(v is True for v in summary["reload"]["after"].values()),
    }
    if summary.get("dedicated_ipv6"):
        cases["dedicated-ipv6-requests-equal"] = equal("comparison_v6_dedicated")
    if summary.get("hybrid_ols") is not None:
        def page(side, scheme):
            try:
                return json.loads(summary[side][scheme]["content"] or "{}") if summary[side][scheme]["status"] == "200" else {}
            except (ValueError, KeyError, TypeError):
                return {}
        pages = ("http", "https", "http-spoofed", "https-spoofed", "acme", "acme-https")
        cases["hybrid-vhost-listed"] = bool(summary.get("hybrid_vhosts"))
        cases["hybrid-served-by-apache"] = all(str(page("hybrid_ols", k).get("server", "")).startswith("Apache") for k in pages)
        cases["hybrid-equal-to-apache"] = all(page("hybrid_ols", k) and page("hybrid_ols", k) == page("hybrid_apache", k)
                                              for k in pages)
        cases["hybrid-client-address-not-forgeable"] = all(page("hybrid_ols", k).get("remote") == iso.CLIENT_IP
                                                           for k in ("http-spoofed", "https-spoofed"))
        cases["hybrid-https-state"] = (page("hybrid_ols", "https").get("https") == "on"
                                       and page("hybrid_ols", "http").get("https") is None)
        def ws(side, scheme):
            return (summary.get(side) or {}).get(scheme + "-websocket") or {}
        def seen(report):
            # Apache's proxy appends the client to the X-Forwarded-For OLS sent (a normal proxy chain); the
            # other headers the backend saw must be identical.
            return {k: v for k, v in (report.get("backend_saw") or {}).items() if k != "x-forwarded-for"} or None
        cases["hybrid-websocket-through-apache"] = all(
            ws("hybrid_ols", k).get("status") == "101" and ws("hybrid_ols", k).get("accept_ok") and ws("hybrid_ols", k).get("echo_ok")
            and seen(ws("hybrid_ols", k)) == seen(ws("hybrid_apache", k))
            and str((ws("hybrid_ols", k).get("backend_saw") or {}).get("x-forwarded-for")).endswith(iso.CLIENT_IP)
            for k in ("http", "https"))
        access = summary.get("hybrid_backend_access") or {}
        cases["hybrid-backend-ports-closed"] = (access.get("external") not in (None, 0) and access.get("tenant") not in (None, 0)
                                                and access.get("root") == "200")
        cases["hybrid-log-routing"] = (summary.get("hybrid_log_routing") or {}).get("ok") is True
    autossl = summary.get("autossl")
    if autossl is not None:
        new_cert = bool(autossl.get("file_after")) and autossl.get("file_after") != autossl.get("file_before")
        cases["autossl-issued-through-ols"] = autossl.get("dcv_ok") is True and new_cert
        cases["ols-serves-new-certificate-after-reload"] = new_cert and autossl.get("served_after_reload") == autossl.get("file_after")
    return cases

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    parser.add_argument("--hybrid", action="store_true",
                        help="hybrid profile: tenant B gets an untranslatable .htaccess directive and stays on Apache, "
                             "which moves to ports 81/444 behind OLS (HR-D08)")
    parser.add_argument("--autossl", action="store_true",
                        help="also reissue tenant B's certificate through cPanel AutoSSL while OLS serves (uses a CA order)")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("This experiment moves 80/443 to OLS for the lab tenants; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("ols-production-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "ols-production-port-experiment", "started_at": probe.now(),
                   "result": "not_run", "recovery_unit": recovery_unit, "passes": {}}
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

        def web(label):
            return step(label + "-web-listeners", ["/usr/sbin/ss", "-H", "-ltnp", owner.WEB_PORTS])["stdout"]

        def apache_status(label):
            row = json.loads(step(label + "-httpd-status", probe.COMMANDS["api_status"])["stdout"])["data"]["service"][0]
            return {k: row.get(k) for k in ("enabled", "monitored", "running")}

        def ownership():
            paths = [p for u in tf.TENANTS for p in ("/home/" + u, "/home/" + u + "/public_html")]
            return step("ownership", ["/usr/bin/stat", "-c", "%n %U %G %a", *paths])["stdout"]

        def request(label, scheme, host, path, mode, address, extra=()):
            port = 443 if scheme == "https" else 80
            record = step(label, ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/curl", "--noproxy", "*", "-ks",
                                  "--http1.1", "--max-time", "20", *extra, "-w", "\n%{http_code} %{redirect_url}",
                                  "--resolve", f"{host}:{port}:{address}", f"{scheme}://{host}{path}"])
            body, _, tail = record["stdout"].rpartition("\n")
            status, _, location = tail.partition(" ")
            title = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
            content = ("" if mode == "status" else body.strip()[:4000] if mode == "full" else title.group(1).strip()[:80] if title
                       else body.strip()[:120] if status == "200" else "")
            return {"status": status, "location": location, "content": content}

        def observe_all(label, address):
            return {f"{s}://{h}{p}": request(f"{label}-{s}", s, h, p, m, address) for s, h, p, m in CASES}

        def observe_v6(label):
            """The same requests from the external client over IPv6 (HR-D06)."""
            return observe_all(label + "-v6", f"[{iso.HOST_IP6}]")

        def ws_sessions(label, address):
            out = {}
            for path in WS_PATHS:
                # From the external client: OLS sends X-Forwarded-For only for non-local peers on plain
                # proxying but always on WebSocket proxying, and cpsrvd binds sessions to the client IP.
                result = step(f"ws-session-{label}", ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/python3", "-I",
                                                      str(WS_SESSION), address, "443", "cpanel." + A, path], 120)
                try:
                    out[path] = json.loads(result["stdout"])
                except ValueError:
                    out[path] = {"error": result["stderr"][-300:]}
            probe.durable_json(run / f"ws-session-{label}.json", out)
            return out

        def fingerprints(label, address):
            out = {}
            for name in TLS_NAMES:
                record = step(f"{label}-tls", ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/sh", "-c",
                              'openssl s_client -connect "$1" -servername "$2" </dev/null 2>/dev/null | '
                              'openssl x509 -noout -fingerprint -sha256 2>/dev/null', "sh", f"{address}:443", name])
                out[name] = record["stdout"].strip()
            return out

        def file_fingerprints():
            out = step("tls-files", ["/usr/bin/sh", "-c", 'for f in "$1"/*/combined "$@"; do [ -f "$f" ] && openssl x509 '
                                     '-in "$f" -noout -fingerprint -sha256 2>/dev/null; done', "sh", iso.TLS_DIR,
                                     *cpanel_surface.SERVICE_CERTS])["stdout"]
            return {line.split("=")[-1] for line in out.splitlines() if "=" in line}

        def served_fingerprint(name, address):
            return step("served-fp", ["/usr/bin/sh", "-c", 'openssl s_client -connect "$1" -servername "$2" </dev/null 2>/dev/null'
                                      ' | openssl x509 -noout -fingerprint -sha256 2>/dev/null', "sh", f"{address}:443", name])["stdout"].strip()

        def file_fingerprint(name):
            return step("file-fp", ["/usr/bin/sh", "-c", 'openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null', "sh",
                                    f"{iso.TLS_DIR}/{name}/combined"])["stdout"].strip()

        def autossl_through_ols(address):
            """G0-E: cPanel AutoSSL issues tenant B's certificate while OLS owns 80/443 (the CA validates through
            OLS), and OLS serves the newly installed certificate (before and after a graceful reload)."""
            name, user = B, "olscpb"
            out = {"served_before": served_fingerprint(name, address), "file_before": file_fingerprint(name)}
            logs_before = set(step("autossl-logs", ["/usr/bin/ls", "/var/cpanel/logs/autossl"])["stdout"].split())
            out["delete_exit"] = step("delete-ssl", ["/usr/local/cpanel/bin/uapi", "--user=" + user, "--output=json", "SSL",
                                                     "delete_ssl", "domain=" + name])["exit_code"]
            out["file_after_delete"] = file_fingerprint(name)
            step("autossl-check", ["/usr/local/cpanel/bin/autossl_check", "--user=" + user], 600)
            log_text = ""
            for _ in range(60):
                new = sorted(set(step("autossl-logs", ["/usr/bin/ls", "/var/cpanel/logs/autossl"])["stdout"].split()) - logs_before)
                if new:
                    log_text = step("autossl-log", ["/usr/bin/cat", f"/var/cpanel/logs/autossl/{new[-1]}/txt"])["stdout"]
                    if "has completed" in log_text:
                        break
                time.sleep(5)
            out["log"] = [l.split("]", 1)[-1].strip() for l in log_text.splitlines()
                          if any(k in l for k in ("DCV OK", "Impediment", "Installing", "will request", "error"))][:30]
            out["dcv_ok"] = f"Local HTTP DCV OK: {name}" in log_text
            out["file_after"] = file_fingerprint(name)
            out["served_without_reload"] = served_fingerprint(name, address)
            step("reload-ols", ["/usr/bin/systemctl", "reload", owner.UNIT], 120)
            time.sleep(3)
            out["served_after_reload"] = served_fingerprint(name, address)
            return out

        def php_after_reload(address):
            """Graceful reload while serving: each tenant's PHP must still answer as the tenant (detached
            LSAPI processes and their PID files survive a reload)."""
            out = {"before": {}, "after": {}}
            for label in ("before", "after"):
                if label == "after":
                    out["runtime_before"] = step("runtime-before-reload", ["/usr/bin/sh", "-c", 'stat -c "%n %U %G %a %F" "$1" "$1"/*',
                                                                           "sh", iso.RUNTIME_DIR])["stdout"].splitlines()
                    out["reload_exit"] = step("reload", ["/usr/bin/systemctl", "reload", owner.UNIT], 120)["exit_code"]
                    time.sleep(3)
                for user, domain in tf.TENANTS.items():
                    body = request(f"php-{label}-{user}", "http", domain, "/probe.php", "", address)
                    out[label][user] = f'"user":"{user}"' in body["content"] if body["status"] == "200" else body["status"]
            out["runtime"] = step("runtime-after-reload", ["/usr/bin/sh", "-c", 'stat -c "%n %U %G %a" "$1"/*', "sh",
                                                           iso.RUNTIME_DIR])["stdout"].splitlines()
            out["processes"] = [l for l in step("ps-after-reload", ["/usr/bin/ps", "-eo", "pid,ppid,user,etimes,args"])["stdout"]
                                .splitlines() if "lshttpd" in l or "lsphp" in l or "lscgid" in l]
            out["error_log"] = step("ols-log-after-reload", ["/usr/bin/tail", "-n", "60", LSWS + "/logs/error.log"])["stdout"].splitlines()
            return out

        def file_states(paths):
            """Owner, mode and content digest of each path ("absent" when missing)."""
            out = step("file-states", ["/usr/bin/sh", "-c", 'for f; do if [ -e "$f" ]; then printf "%s %s\\n" '
                                       '"$(stat -c "%U:%G:%a" "$f")" "$(sha256sum < "$f" | cut -d" " -f1)"; '
                                       'else echo absent; fi; done', "sh", *paths])["stdout"].splitlines()
            return dict(zip(paths, out))

        def hybrid_observe(label, address):
            """Tenant B's diagnostic page (with forged client-address headers too), the same page under the
            ACME path, and a WebSocket session through Apache's own ws:// proxy to the lab echo backend."""
            out = {}
            for s_ in ("http", "https"):
                out[s_] = request(f"{label}-page-{s_}", s_, B, "/" + HYBRID_PAGE + HYBRID_QUERY, "full", address)
                out[s_ + "-spoofed"] = request(f"{label}-spoof-{s_}", s_, B, "/" + HYBRID_PAGE + HYBRID_QUERY, "full",
                                               address, SPOOF)
                record = step(f"{label}-ws-{s_}", ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/python3", "-I",
                              str(iso.WS_ECHO), "client", "--connect", f"{address}:{443 if s_ == 'https' else 80}",
                              "--host", B, "--path", "/olscp-ws-echo/socket?probe=1", "--nonce", run_id,
                              *(["--tls"] if s_ == "https" else [])], 60)
                try:
                    out[s_ + "-websocket"] = json.loads(record["stdout"])
                except ValueError:
                    out[s_ + "-websocket"] = {"error": record["stderr"][-300:]}
            for s_, key in (("http", "acme"), ("https", "acme-https")):
                out[key] = request(f"{label}-{key}", s_, B, "/.well-known/acme-challenge/" + HYBRID_PAGE + HYBRID_QUERY,
                                   "full", address)
            return out

        installed = armed = cut_over = netns = False
        original = None
        recovery_script = echo = None
        tweaks, tenant_files = {}, {}
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if apache_status("before") != {"enabled": 1, "monitored": 1, "running": 1} or not owner.owned_by(web("before"), ["httpd"]):
                raise ValueError("Apache is not the healthy owner of 80/443")
            if step("residue", ["/usr/bin/ls", "-d", LSWS, owner.WEB])["stdout"].strip():
                raise ValueError("OLS residue present")
            original = ownership()
            # Recovery before the first change (review RV-27): byte-exact backups of everything the experiment
            # changes, one recovery script, armed in a timer and also run on the normal return path.
            backup = f"{RECOVERY_ROOT}/{run_id}"
            created_dirs = []
            if args.hybrid:
                for key in ("apache_port", "apache_ssl_port"):
                    tweaks[key] = probe.api(step("tweak-get-" + key, ["/usr/local/cpanel/bin/whmapi1", "--output=json",
                                            "get_tweaksetting", "key=" + key]), "get_tweaksetting")["data"]["tweaksetting"]["value"]
                if step("nft-absent", ["/usr/sbin/nft", "list", "table", "inet", hybrid_lab.NFT_TABLE])["exit_code"] == 0:
                    raise ValueError("The hybrid firewall table already exists")
                for path in (hybrid_lab.REMOTEIP_CONF, HYBRID_FILES["page"], HYBRID_FILES["acme"]):
                    if step("collision", ["/usr/bin/test", "-e", path])["exit_code"] == 0:
                        raise ValueError("Refusing to overwrite " + path)
                for path in HYBRID_FILES.values():
                    tenant_files[path] = step("exists", ["/usr/bin/test", "-e", path])["exit_code"] == 0
                if not tenant_files[HYBRID_FILES["htaccess"]]:
                    raise ValueError("Tenant B has no .htaccess to extend")
                created_dirs = [d for d in HYBRID_DIRS if step("dir-exists", ["/usr/bin/test", "-d", d])["exit_code"] != 0]
                summary["hybrid_before"] = {"tweaks": tweaks, "files": file_states(sorted(tenant_files)),
                                            "created_dirs": created_dirs}
            if step("recovery-dir", ["/usr/bin/install", "-d", "-m", "0700", backup + "/files"])["exit_code"]:
                raise ValueError("Could not create the recovery directory")
            # Tenant files are read as the tenant (a planted symlink gives no root read) into the root-only backup.
            for number, (path, existed) in enumerate(sorted(tenant_files.items())):
                if not existed:
                    continue
                if step("backup-symlink", ["/usr/bin/test", "-L", path])["exit_code"] == 0:
                    raise ValueError("Refusing a symlinked tenant file " + path)
                if step("backup-file", ["/usr/bin/sh", "-c", '/usr/sbin/runuser -u "$1" -- /usr/bin/cat -- "$2" > "$3"', "sh",
                                        "olscpb", path, f"{backup}/files/{number}"])["exit_code"]:
                    raise ValueError("Could not back up " + path)
            expected = {path: state.split()[1] for path, state in (summary.get("hybrid_before") or {}).get("files", {}).items()
                        if state != "absent"}
            script = backup + "/recover.sh"
            if step("recovery-script", ["/usr/bin/install", "-m", "0700", stage_file("recover.sh", hybrid_lab.recovery_script(
                    backup, tweaks, tenant_files, created_dirs, args.hybrid, "olscpb", expected)), script])["exit_code"]:
                raise ValueError("Could not install the recovery script")
            if step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=45min",
                                     "--timer-property=AccuracySec=1s", "/bin/sh", script])["exit_code"]:
                raise ValueError("Could not arm the recovery timer")
            recovery_script, armed = script, True
            # The client namespace first: its IPv6 link address must exist when listeners are compiled.
            netns = True
            iso.netns_up(step)
            if args.hybrid:
                # As the tenant, in place (owner, mode and inode kept); the backup restores the exact bytes.
                if step("hybrid-htaccess", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/sh", "-c",
                        'tmp=$(mktemp "$2.XXXXXX") && { printf "%s" "$1"; cat "$2"; } > "$tmp" && cat "$tmp" > "$2"; '
                        'rc=$?; rm -f "$tmp"; exit $rc', "sh", HYBRID_MARKER, HYBRID_FILES["htaccess"]])["exit_code"]:
                    raise ValueError("Could not mark tenant B's .htaccess")
                for directory in created_dirs:
                    step("hybrid-dir", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/install", "-d", "-m", "0755", directory])
                for key in ("page", "acme"):
                    if step("hybrid-" + key, ["/usr/bin/install", "-m", "0644", "-o", "olscpb", "-g", "olscpb",
                                              stage_file(HYBRID_PAGE, HYBRID_PHP), HYBRID_FILES[key]])["exit_code"]:
                        raise ValueError("Could not place the diagnostic page")
            compiled = iso.compile_lab(step, summary, production=True, hybrid_ports=HYBRID_PORTS if args.hybrid else None)
            address = compiled["local_ips"]["olscpa"]
            summary["listen_address"] = address
            # An account with a dedicated IPv6 address (WHM IPv6 range), if the lab has one.
            dedicated = next((v["ipv6"][0] for v in compiled["plan"].values() if v.get("ipv6")), None)
            summary["dedicated_ipv6"] = dedicated
            summary["apache"] = observe_all("apache", address)
            if args.hybrid:
                echo = subprocess.Popen([sys.executable, "-I", str(iso.WS_ECHO), "server", "--port", str(iso.WS_ECHO_PORT)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1)
                summary["hybrid_apache"] = hybrid_observe("hybrid-apache", address)
            # Precondition (RV-15): cPanel reloads Apache asynchronously after certificate changes; the
            # baseline is only meaningful once Apache serves the certificate files on disk.
            for _ in range(24):
                summary["apache_tls"] = fingerprints("apache", address)
                if all(not v or v.split("=")[-1] in file_fingerprints() for v in summary["apache_tls"].values()):
                    break
                time.sleep(5)
            else:
                raise ValueError("Apache does not serve the certificates on disk (pending cPanel reload)")
            summary["apache_v6"] = observe_v6("apache")
            if dedicated:
                summary["apache_v6d"] = observe_all("apache-v6d", f"[{dedicated}]")
            summary["apache_tls_v6"] = fingerprints("apache-v6", f"[{iso.HOST_IP6}]")
            summary["apache_ws_session"] = ws_sessions("apache", address)

            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])
            if os.environ.get("OLS_LAB_UNIT_DROPIN"):  # lab diagnosis only: unit override for one run
                summary["unit_dropin"] = os.environ["OLS_LAB_UNIT_DROPIN"]
                step("dropin-dir", ["/usr/bin/install", "-d", "-m", "0755", "/etc/systemd/system/ols-cpanel.service.d"])
                step("dropin", ["/usr/bin/install", "-m", "0644", stage_file("lab.conf", os.environ["OLS_LAB_UNIT_DROPIN"]),
                                "/etc/systemd/system/ols-cpanel.service.d/lab.conf"])
                step("daemon-reload-dropin", ["/usr/bin/systemctl", "daemon-reload"])
            # Fence (RV-28): if the emergency timer already fired, its recovery owns the host; stop here.
            if step("recovery-timer-armed", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer"])["stdout"].strip() != "active":
                raise ValueError("The recovery timer is no longer armed")
            cut_over = True
            if args.hybrid:
                # Apache keeps serving on cPanel's backend ports (as with ea-nginx); OLS proxies the hybrid vhosts.
                # It trusts only X-OLS-Client-IP from the local addresses OLS connects from, and the firewall
                # admits only root and OLS's user to the backend ports, over loopback.
                local = sorted({v["ip"] for v in compiled["plan"].values() if v.get("ip")}
                               | {a for v in compiled["plan"].values() for a in v.get("ipv6") or []})
                if step("remoteip-conf", ["/usr/bin/install", "-m", "0644", stage_file("remoteip.conf",
                        hybrid_lab.remoteip_conf(["127.0.0.1", "::1", *local])), hybrid_lab.REMOTEIP_CONF])["exit_code"]:
                    raise ValueError("Could not install the remoteip include")
                if step("nft-hybrid", ["/usr/sbin/nft", "-f", stage_file("hybrid.nft",
                        hybrid_lab.nft_ruleset(HYBRID_PORTS))])["exit_code"]:
                    raise ValueError("Could not install the backend port firewall")
                for key, port in (("apache_port", HYBRID_PORTS[0]), ("apache_ssl_port", HYBRID_PORTS[1])):
                    probe.api(step("tweak-" + key, ["/usr/local/cpanel/bin/whmapi1", "--output=json", "set_tweaksetting",
                                                    "key=" + key, f"value=0.0.0.0:{port}"]), "set_tweaksetting")
                # cPanel does not restart Apache after apache_ssl_port changes (lab finding): restart explicitly.
                for _ in range(30):
                    conf = step("httpd-conf-listen", ["/usr/bin/grep", "-c", f"Listen 0.0.0.0:{HYBRID_PORTS[1]}",
                                                      "/etc/apache2/conf/httpd.conf"])["stdout"].strip()
                    if conf not in ("", "0"):
                        break
                    time.sleep(2)
                step("restart-httpd-hybrid", ["/usr/local/cpanel/scripts/restartsrv_httpd"], 120)
            else:
                probe.api(step("disable-httpd", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "configureservice",
                                                 "service=httpd", "enabled=0", "monitored=0"]), "configureservice")
            time.sleep(3)
            if owner.owners(web("apache-disabled")):
                raise ValueError("Apache did not release 80/443")
            if step("start-ols", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(3)
            if not owner.owned_by(web("ols-active"), OLS_NAMES):
                raise ValueError("OLS does not own 80/443")
            # cPanel's own FileProtect sync while OLS runs (docroots become user:nobody 0750).
            summary["enablefileprotect_running_exit"] = step("enablefileprotect-running",
                                                             ["/usr/local/cpanel/scripts/enablefileprotect"], 300)["exit_code"]
            ready = False
            for _ in range(20):
                if request("ols-ready", "http", A, "/static.txt", "", address)["status"] == "200":
                    ready = True
                    break
                time.sleep(3)
            if not ready:
                raise ValueError("OLS does not serve the tenant on port 80")
            # Log routing: splitlogs sends ":443" lines to -ssl_log (checked after the shipper flushes).
            marker = "olscp-prod-" + uuid.uuid4().hex
            summary["log_marker"] = marker
            for scheme in ("http", "https"):
                request("log-" + scheme, scheme, A, "/static.txt", "", address, ["-A", marker])
            summary["ols"] = observe_all("ols", address)
            if args.hybrid:
                summary["hybrid_ols"] = hybrid_observe("hybrid-ols", address)
                # Apache's backend ports: closed to the external client and to tenant processes, open to root.
                backend = f"http://{address}:{HYBRID_PORTS[0]}/{HYBRID_PAGE}"
                summary["hybrid_backend_access"] = {
                    "external": step("backend-external", ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/curl", "-s",
                                     "-o", "/dev/null", "--max-time", "5", "-H", "Host: " + B, backend])["exit_code"],
                    "tenant": step("backend-tenant", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/curl", "-s", "-o",
                                   "/dev/null", "--max-time", "5", "-H", "Host: " + B, backend])["exit_code"],
                    "root": step("backend-root", ["/usr/bin/curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time",
                                 "5", "-H", "Host: " + B, backend])["stdout"]}
                # Accounting: Apache logs the hybrid requests in B's domlogs, HTTPS (backend port 444) in -ssl_log.
                # splitlogs writes them when Apache's piped log closes, so they are read after the recovery.
                summary["hybrid_log_marker"] = hybrid_marker = "olscp-hybrid-" + uuid.uuid4().hex
                for s_ in ("http", "https"):
                    request("hybrid-log-" + s_, s_, B, "/" + HYBRID_PAGE, "status", address, ["-A", hybrid_marker])
            summary["ols_tls"] = fingerprints("ols", address)
            summary["ols_v6"] = observe_v6("ols")
            if dedicated:
                summary["ols_v6d"] = observe_all("ols-v6d", f"[{dedicated}]")
            summary["ols_tls_v6"] = fingerprints("ols-v6", f"[{iso.HOST_IP6}]")
            summary["ols_ws_session"] = ws_sessions("ols", address)
            if args.autossl:
                summary["autossl"] = autossl_through_ols(address)
            summary["reload"] = php_after_reload(address)
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
                if summary.get("log_marker"):
                    found = {}
                    for name in ("", "-ssl_log"):
                        lines = step("domlog" + name, ["/usr/bin/grep", "-h", summary["log_marker"],
                                     f"{cpanel_surface.DOMLOGS}/{A}{name}"])["stdout"].splitlines()
                        found[name or "plain"] = lines
                    summary["log_routing"] = {"lines": found,
                                              "ok": len(found["plain"]) == 1 and len(found["-ssl_log"]) == 1
                                              and all('"GET /static.txt HTTP/1.1" 200' in l for v in found.values() for l in v)}
            if echo is not None:
                echo.terminate()
                echo.wait(10)
            if armed:
                # The same script the timer would run: it restores everything and verifies Apache serves again.
                record = step("recovery-run", ["/bin/sh", recovery_script], 900)
                summary["recovery_run"] = {"exit_code": record["exit_code"], "stdout": record["stdout"][-500:],
                                           "stderr": record["stderr"][-500:]}
            if summary.get("hybrid_log_marker"):
                for _ in range(20):
                    found = {name or "plain": step("hybrid-domlog" + name, ["/usr/bin/grep", "-h", summary["hybrid_log_marker"],
                             f"{cpanel_surface.DOMLOGS}/{B}{name}"])["stdout"].splitlines() for name in ("", "-ssl_log")}
                    if found["plain"] and found["-ssl_log"]:
                        break
                    time.sleep(3)
                summary["hybrid_log_routing"] = {"lines": found, "ok": len(found["plain"]) == 1 and len(found["-ssl_log"]) == 1
                                                 and all(l.startswith(iso.CLIENT_IP + " ") and f"GET /{HYBRID_PAGE} HTTP/1.1\" 200" in l
                                                         for v in found.values() for l in v)}
            if installed:
                summary["package_erased"] = owner.erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, owner.WEB, "/tmp/lshttpd", "/run/ols-cpanel/lshttpd", "/dev/shm/ols",
                                      "/etc/systemd/system/ols-cpanel.service.d"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
            if netns:
                iso.netns_down(step)
            restored = {"apache": apache_status("final") == {"enabled": 1, "monitored": 1, "running": 1},
                        "listeners": owner.owned_by(web("final"), ["httpd"]),
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200",
                        "ownership": original is None or ownership() == original,
                        "package_absent": summary.get("package_erased", True),
                        "residue": not step("final-residue", ["/usr/bin/ls", "-d", LSWS, owner.WEB])["stdout"].strip(),
                        "recovery_script": not armed or (summary.get("recovery_run") or {}).get("exit_code") == 0}
            if args.hybrid and summary.get("hybrid_before"):
                restored["tweaks"] = all(probe.api(step("tweak-final-" + k, ["/usr/local/cpanel/bin/whmapi1", "--output=json",
                                         "get_tweaksetting", "key=" + k]), "get_tweaksetting")["data"]["tweaksetting"]["value"] == v
                                         for k, v in tweaks.items())
                restored["tenant_files"] = file_states(sorted(tenant_files)) == summary["hybrid_before"]["files"]
                restored["created_dirs_removed"] = all(step("dir-gone", ["/usr/bin/test", "-e", d])["exit_code"] != 0
                                                       for d in summary["hybrid_before"]["created_dirs"])
                restored["remoteip_absent"] = step("remoteip-gone", ["/usr/bin/test", "-e", hybrid_lab.REMOTEIP_CONF])["exit_code"] != 0
                restored["firewall_absent"] = step("nft-gone", ["/usr/sbin/nft", "list", "table", "inet",
                                                                hybrid_lab.NFT_TABLE])["exit_code"] != 0
                restored["backend_ports_closed"] = not step("backend-listeners", ["/usr/sbin/ss", "-H", "-ltn",
                                                            f"( sport = :{HYBRID_PORTS[0]} or sport = :{HYBRID_PORTS[1]} )"])["stdout"].strip()
            summary["restored"] = restored
            if armed and all(restored.values()):
                stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])["exit_code"] == 0
                states = step("recovery-unit-state", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer",
                                                       recovery_unit + ".service"])["stdout"].split()
                summary["recovery_disarmed"] = stopped and all(state != "active" and state != "activating" for state in states)
                restored["recovery_disarmed"] = summary["recovery_disarmed"]
            if summary.get("ols"):
                summary["comparison"] = {k: {"apache": summary["apache"][k], "ols": v, "match": summary["apache"][k] == v}
                                         for k, v in summary["ols"].items()}
                summary["tls_match"] = {k: summary["apache_tls"][k] == v and bool(v) for k, v in summary["ols_tls"].items()}
                # IPv6 (HR-D06): the same requests and certificates over IPv6 from the external client.
                summary["comparison_v6"] = {k: {"apache": summary["apache_v6"][k], "ols": v, "match": summary["apache_v6"][k] == v}
                                            for k, v in summary.get("ols_v6", {}).items()}
                summary["comparison_v6_dedicated"] = {k: {"apache": summary["apache_v6d"][k], "ols": v,
                                                          "match": summary["apache_v6d"][k] == v}
                                                      for k, v in summary.get("ols_v6d", {}).items()}
                summary["tls_match_v6"] = {k: summary["apache_tls_v6"][k] == v and bool(v)
                                           for k, v in summary.get("ols_tls_v6", {}).items()}
                # Frame lengths vary with the shell prompt; status and opcode must match.
                strip = lambda r: {k: v for k, v in r.items() if k != "first_frame_length"}
                summary["ws_session_match"] = {k: strip(summary["apache_ws_session"][k]) == strip(v)
                                               for k, v in (summary.get("ols_ws_session") or {}).items()}
            if summary["result"] == "observed":
                # Declared expectations (review RV-06): every comparison equal, the host restored.
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": restored,
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
