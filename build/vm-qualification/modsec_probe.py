#!/usr/bin/python3
"""FV-02 lab experiment (WAF and security): cPanel's ModSecurity with the OWASP Core Rule Set vendor, served by
Apache and by the product OLS build on the test listeners (Apache keeps 80/443), compared request by request.

1. Enables cPanel's OWASP vendor through the WHM API (installing EA4's ea-modsec2-rules-owasp-crs package only
   when no OWASP vendor is installed) unless it already is; every cPanel file the experiment can change is
   copied first and restored byte for byte at the end (an independent timer restores them if this process dies).
2. Compiles the lab tenants with the product security input (compile_lab(..., security=...)), installs the OLS
   build, and sends the same corpus of malicious and benign requests to Apache (account address :80) and to OLS
   (external test listener, from the simulated external client).
3. Per-domain disable: cPanel's own ModSecurity::disable_domains for tenant B, recompile, the corpus again.
4. Per-client limits and IP lists: throttling, hard-limit ban, trusted client exemption, block list, each
   compiled from the security input and observed from the external client (OLS exempts local clients).
5. Reads OLS's audit log through the product parser (modsec_translate.parse_audit_log).
Declared outcomes in expected_outcomes(); documented differences in KNOWN_DIFFERENCES. NOT a certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import modsec_translate as mt
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso

ROOT = pathlib.Path(__file__).resolve().parents[2]
WHMAPI = "/usr/local/cpanel/bin/whmapi1"
UAPI = "/usr/local/cpanel/bin/uapi"
OWASP_PACKAGE = "ea-modsec2-rules-owasp-crs"
DATASTORE = "/var/cpanel/modsec_cpanel_conf_datastore"
# Every cPanel file the experiment may change, restored byte for byte (absent files are removed again).
GUARDED = [DATASTORE, mt.CPANEL_CONF, mt.CPANEL_CONF + ".PREVIOUS", mt.USER_CONF,
           f"/var/cpanel/userdata/olscpb/{tf.TENANTS['olscpb']}", f"/var/cpanel/userdata/olscpb/{tf.TENANTS['olscpb']}_SSL",
           "/var/cpanel/userdata/olscpb/cache"]
HTTPD_CONF = "/etc/apache2/conf/httpd.conf"
# The lab plugin preview (plugin_preview.sh) must not be installed: it owns /usr/local/ols-cpanel and a broker.
PREVIEW = ["/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel", "/usr/local/cpanel/base/frontend/jupiter/ols_cpanel",
           "/usr/local/ols-cpanel"]
# (name, method, path, extra curl arguments, Apache baseline verdict). Paranoia level 1 of the Core Rule Set.
CORPUS = [
    ("xss-query", "GET", "/static.txt?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", [], "block"),
    ("sqli-query", "GET", "/static.txt?id=1%27%20OR%20%271%27%3D%271", [], "block"),
    ("path-traversal", "GET", "/static.txt?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", [], "block"),
    ("unix-command", "GET", "/static.txt?cmd=%3Bcat%20%2Fetc%2Fpasswd", [], "block"),
    ("php-injection", "GET", "/static.txt?x=%3C%3Fphp%20system(%27id%27)%3B%20%3F%3E", [], "block"),
    ("scanner-agent", "GET", "/static.txt", ["-A", "Nikto/2.1.6"], "block"),
    ("sqli-form", "POST", "/static.txt", ["--data", "user=admin%27--&pass=x"], "block"),
    ("benign-static", "GET", "/static.txt", [], "allow"),
    ("benign-query", "GET", "/static.txt?page=2&sort=asc", [], "allow"),
    ("benign-form", "POST", "/static.txt", ["--data", "name=alice&comment=hello+world"], "allow"),
    ("benign-browser", "GET", "/static.txt", ["-A", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"], "allow"),
]
DISABLED_PROBE = ("xss-query", "GET", CORPUS[0][2], [], "block")
LIMITS = {"staticReqPerSec": 5, "softLimit": 4, "hardLimit": 6, "gracePeriod": 2, "banPeriod": 20}
THROTTLE_REQUESTS = 20
# Documented differences (request name -> reason); any other difference fails its case, and a listed one may
# never turn an Apache block into an OLS allow.
KNOWN_DIFFERENCES = {}

def verdict(status):
    return "block" if status in ("403", "406") else "allow" if status and status[0] in "2345" else "error"

def expected_outcomes(summary):
    """Pass/fail per declared guarantee of a completed run."""
    corpus = summary.get("corpus") or {}
    disabled = summary.get("domain_disable") or {}
    limits = summary.get("limits") or {}
    audit = summary.get("audit") or {}
    cases = {
        "apache-baseline": bool(corpus) and all(e["apache"]["verdict"] == e["expected"] for e in corpus.values()),
        "same-verdicts-as-apache": bool(corpus) and all(
            e["apache"]["status"] == e["ols"]["status"] or (name in KNOWN_DIFFERENCES and e["ols"]["verdict"] == "block")
            for name, e in corpus.items()),
        "audit-records-parsed": bool(audit.get("blocked")) and audit.get("missing") == [],
        "per-domain-disable-honoured": bool(disabled) and disabled.get("b", {}).get("apache") == "allow"
                                       and disabled.get("b", {}).get("ols") == "allow" and disabled.get("a", {}).get("apache") == "block"
                                       and disabled.get("a", {}).get("ols") == "block",
        "rate-limit-throttles": (limits.get("throttled_seconds") or 0) >= (THROTTLE_REQUESTS / LIMITS["staticReqPerSec"]) - 1.5
                                and limits.get("throttled_ok") == THROTTLE_REQUESTS,
        "hard-limit-bans": limits.get("over_hard_limit") == "000" and limits.get("after_ban") == "200",
        "trusted-client-exempt": (limits.get("trusted_seconds") is not None and limits["trusted_seconds"] < 2.0
                                  and limits.get("trusted_ok") == THROTTLE_REQUESTS),
        "block-list-refuses": limits.get("blocked_external") == "000" and limits.get("blocked_loopback") == "200",
        "no-ols-errors": summary.get("ols_log_errors") == [],
        "host-restored": summary.get("restored") is True and summary.get("removed") is True,
    }
    return cases

def recovery_script(run, installed_package):
    """Independent recovery: restore every guarded file from the run's copies, remove the package the
    experiment installed, rebuild Apache's configuration and remove OLS."""
    lines = ["#!/bin/sh", "/usr/bin/systemctl stop ols-cpanel.service ols-cpanel-logs.service"]
    for index, path in enumerate(GUARDED):
        copy = f"{run}/backup/{index}"
        lines.append(f'if [ -e "{copy}" ]; then /usr/bin/cp -p "{copy}" "{path}"; else /usr/bin/rm -f "{path}"; fi')
    if installed_package:
        lines.append(f"/usr/bin/dnf -y remove {OWASP_PACKAGE}")
    lines += ["/usr/local/cpanel/scripts/updateuserdatacache --force", "/usr/local/cpanel/scripts/rebuildhttpdconf",
              "/usr/local/cpanel/scripts/restartsrv_httpd", "/usr/bin/rpm -e ols-cpanel-openlitespeed",
              f"/usr/bin/rm -rf {owner.LSWS} {owner.WEB}"]
    return "\n".join(lines) + "\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Changes cPanel's ModSecurity vendors and tenant B's settings; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    run_id = uuid.uuid4().hex
    run = local / ("modsec-" + run_id)
    run.mkdir(mode=0o700, parents=True)
    os.chmod(run, 0o711)
    recovery_unit = "ols-cpanel-modsec-recover-" + run_id
    summary = {"schema_version": 1, "kind": "modsec-experiment", "started_at": probe.now(), "result": "not_run", "argv": sys.argv}
    index = 0

    def step(name, command, limit=300):
        nonlocal index
        index += 1
        record = owner.invoke(command, limit)
        probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
        return record

    def stage_file(name, content):
        path = run / f"{index:03d}-{name}"
        path.write_text(content)
        os.chmod(path, 0o644)
        return str(path)

    def digests():
        out = {}
        for path in [*GUARDED, HTTPD_CONF]:
            record = step("digest", ["/usr/bin/sha256sum", path])
            out[path] = record["stdout"].split(" ")[0] if record["exit_code"] == 0 else None
        return out

    def vendors():
        return probe.api(step("vendors", [WHMAPI, "--output=json", "modsec_get_vendors"]), "modsec_get_vendors")["data"]["vendors"]

    def owasp(found):
        return next((v for v in found if "OWASP" in str(v.get("vendor_id", "")).upper()), None)

    def request(target, host, name, method, path, extra):
        """(status, seconds) of one request: Apache from the host, OLS from the external client namespace."""
        address, port, netns = target
        command = ["/usr/bin/curl", "--noproxy", "*", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "20",
                   "-X", method, *extra, "--resolve", f"{host}:{port}:{address}", f"http://{host}:{port}{path}"]
        if netns:
            command = ["/usr/sbin/ip", "netns", "exec", iso.NETNS, *command]
        status, _, seconds = step("request-" + name, command)["stdout"].strip().partition(" ")
        return status, float(seconds or 0)

    def ols_compile(label, security):
        nonlocal compiled
        part = {}
        compiled = iso.compile_lab(step, part, security=security)
        summary.setdefault("compiles", {})[label] = {"waf": part.get("waf"), "security": part.get("security")}
        iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])

    def restart():
        if step("restart-ols", ["/usr/bin/systemctl", "restart", owner.UNIT])["exit_code"]:
            raise ValueError("OLS restart failed")
        time.sleep(3)

    def wait_apache(domain, address):
        for _ in range(30):
            if request((address, 80, False), domain, "apache-ready", "GET", "/static.txt", [])[0] == "200":
                return
            time.sleep(2)
        raise ValueError("Apache does not serve the lab tenant after the change")

    compiled = None
    armed = installed = enabled_vendor = installed_package = netns = disabled_domain = False
    before = None
    try:
        with (local / "service-probe.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if step("residue", ["/usr/bin/ls", "-d", owner.LSWS])["stdout"].strip():
                raise ValueError("OLS residue present")
            if step("preview", ["/usr/bin/ls", "-d", *PREVIEW])["stdout"].strip():
                raise ValueError("The lab plugin preview is installed; remove it (plugin_preview.sh uninstall) first")
            before = digests()
            summary["before"] = before
            step("backup-dir", ["/usr/bin/install", "-d", "-m", "0700", str(run / "backup")])
            for number, path in enumerate(GUARDED):
                if before[path] is not None:
                    step("backup", ["/usr/bin/cp", "-p", path, str(run / "backup" / str(number))])
            found = vendors()
            vendor = owasp(found)
            summary["vendor_before"] = vendor
            installed_package = vendor is None
            armed = step("arm-recovery", ["/usr/bin/systemd-run", f"--unit={recovery_unit}", "--on-active=60min", "/bin/sh",
                                          stage_file("recover.sh", recovery_script(run, installed_package))])["exit_code"] == 0
            if not armed:
                raise ValueError("Unable to arm the independent recovery timer")
            if installed_package:
                if step("install-owasp", ["/usr/bin/dnf", "-y", "install", OWASP_PACKAGE], 1200)["exit_code"]:
                    raise ValueError("Installing the OWASP vendor package failed")
                vendor = owasp(vendors())
                if vendor is None:
                    raise ValueError("No OWASP vendor after installing its package")
            vendor_id = vendor["vendor_id"]
            if not vendor.get("enabled"):
                enabled_vendor = True
                probe.api(step("enable-vendor", [WHMAPI, "--output=json", "modsec_enable_vendor", f"vendor_id={vendor_id}"]),
                          "modsec_enable_vendor")
            probe.api(step("enable-configs", [WHMAPI, "--output=json", "modsec_enable_vendor_configs", f"vendor_id={vendor_id}"]),
                      "modsec_enable_vendor_configs")
            step("restart-httpd", ["/usr/local/cpanel/scripts/restartsrv_httpd"], 300)
            summary["vendor_after"] = owasp(vendors())
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            ols_compile("waf", {})
            ips = compiled["local_ips"]
            for user, domain in tf.TENANTS.items():
                wait_apache(domain, ips[user])
            netns = True
            iso.netns_up(step)
            if step("start", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(3)
            domain = tf.TENANTS["olscpa"]
            apache, ols = (ips["olscpa"], 80, False), (iso.HOST_IP, iso.PORT, True)
            corpus = {}
            for name, method, path, extra, expected in CORPUS:
                seen = {}
                for label, target in (("apache", apache), ("ols", ols)):
                    status, _ = request(target, domain, f"{label}-{name}", method, path, extra)
                    seen[label] = {"status": status, "verdict": verdict(status)}
                corpus[name] = dict(seen, expected=expected, path=path)
            summary["corpus"] = corpus
            # Blocked-request log: every request OLS blocked has a parsed record with its URI and a rule id.
            tail = step("audit-log", ["/usr/bin/tail", "-c", "1000000", mt.AUDIT_LOG])["stdout"]
            parsed = mt.parse_audit_log(tail, 1000)
            blocked = [e["path"] for e in corpus.values() if e["ols"]["verdict"] == "block"]
            records = [r for r in parsed["records"] if r["action"] == "deny" and r["rule_id"] is not None]
            summary["audit"] = {"blocked": blocked, "records": parsed["records"][-50:], "skipped": parsed["skipped"],
                                "missing": [p for p in blocked if not any(r["uri"] == p for r in records)]}
            # Per-domain disable through cPanel's own API, then the same request on both servers and both tenants.
            disabled_domain = True
            step("disable-domain", [UAPI, "--user=olscpb", "--output=json", "ModSecurity", "disable_domains",
                                    f"domains={tf.TENANTS['olscpb']}"], 600)
            wait_apache(tf.TENANTS["olscpb"], ips["olscpb"])
            ols_compile("domain-disabled", {})
            restart()
            disabled = {}
            for key, user in (("a", "olscpa"), ("b", "olscpb")):
                host = tf.TENANTS[user]
                _, method, path, extra, _ = DISABLED_PROBE
                disabled[key] = {label: verdict(request(target, host, f"disabled-{label}-{key}", method, path, extra)[0])
                                 for label, target in (("apache", (ips[user], 80, False)), ("ols", ols))}
            summary["domain_disable"] = disabled
            step("enable-domain", [UAPI, "--user=olscpb", "--output=json", "ModSecurity", "enable_domains",
                                   f"domains={tf.TENANTS['olscpb']}"], 600)
            disabled_domain = False
            limits = {}
            # Throttling: requests over one connection to a static file at staticReqPerSec.
            def burst(label):
                urls = [f"http://{domain}:{iso.PORT}/static.txt"] * THROTTLE_REQUESTS
                started = time.monotonic()
                out = step(label, ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/curl", "--noproxy", "*", "-s",
                                   "-o", "/dev/null", "-w", "%{http_code}\\n", "--max-time", "60",
                                   "--resolve", f"{domain}:{iso.PORT}:{iso.HOST_IP}", *urls], 120)["stdout"].split()
                return time.monotonic() - started, out.count("200")
            ols_compile("limits", {"per_client": LIMITS})
            restart()
            limits["throttled_seconds"], limits["throttled_ok"] = burst("throttle")
            # Hard limit: hold more idle connections than hardLimit, then one request (closed, client banned),
            # and again after banPeriod.
            hold = step("hold-connections", ["/usr/sbin/ip", "netns", "exec", iso.NETNS, "/usr/bin/python3", "-I", "-c",
                        "import socket,subprocess,sys,time\nsocks=[]\nfor _ in range(int(sys.argv[3])):\n"
                        " s=socket.create_connection((sys.argv[1],int(sys.argv[2])),5); socks.append(s)\ntime.sleep(4)\n"
                        "r=subprocess.run(['/usr/bin/curl','-s','-o','/dev/null','-w','%{http_code}','--max-time','10','--resolve',"
                        "sys.argv[4]+':'+sys.argv[2]+':'+sys.argv[1],'http://'+sys.argv[4]+':'+sys.argv[2]+'/static.txt'],"
                        "capture_output=True,text=True)\nprint(r.stdout)",
                        iso.HOST_IP, str(iso.PORT), str(LIMITS["hardLimit"] + 4), domain], 60)
            limits["over_hard_limit"] = hold["stdout"].strip()
            time.sleep(LIMITS["banPeriod"] + 5)
            limits["after_ban"] = request(ols, domain, "after-ban", "GET", "/static.txt", [])[0]
            ols_compile("trusted", {"per_client": LIMITS, "ip_allow": [iso.CLIENT_IP]})
            restart()
            limits["trusted_seconds"], limits["trusted_ok"] = burst("trusted")
            ols_compile("blocked", {"ip_block": [iso.CLIENT_IP]})
            restart()
            limits["blocked_external"] = request(ols, domain, "blocked-external", "GET", "/static.txt", [])[0]
            limits["blocked_loopback"] = request(("127.0.0.1", iso.PORT, False), domain, "blocked-loopback", "GET",
                                                 "/static.txt", [])[0]
            summary["limits"] = limits
            summary["result"] = "observed"
    except Exception as exc:
        summary["result"] = "fail"
        summary["error_type"] = type(exc).__name__
        summary["error"] = str(exc)[:500]
    finally:
        if disabled_domain:
            step("enable-domain", [UAPI, "--user=olscpb", "--output=json", "ModSecurity", "enable_domains",
                                   f"domains={tf.TENANTS['olscpb']}"], 600)
        if netns:
            iso.netns_down(step)
        if installed:
            step("stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
            log = step("ols-error-log", ["/usr/bin/tail", "-c", "200000", owner.LSWS + "/logs/error.log"])["stdout"]
            # A rule file libmodsecurity refuses is only logged (setSecRule ... failed): it is an error here.
            summary["ols_log_errors"] = [l[27:] for l in log.splitlines() if "[ERROR]" in l or "setSecRule" in l and "failed" in l][:50]
            summary["package_erased"] = owner.erase_package(step)
            step("remove-files", ["/usr/bin/rm", "-rf", owner.LSWS, owner.WEB, "/run/ols-cpanel/lshttpd", "/dev/shm/ols"])
            step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
        if enabled_vendor and not installed_package and summary.get("vendor_before"):
            step("disable-vendor", [WHMAPI, "--output=json", "modsec_disable_vendor",
                                    f"vendor_id={summary['vendor_before']['vendor_id']}"])
        if installed_package and armed:
            step("remove-owasp", ["/usr/bin/dnf", "-y", "remove", OWASP_PACKAGE], 1200)
        if before is not None:
            # Exact restoration: every guarded file back to its copied bytes (or absent again), then cPanel rebuilds.
            for number, path in enumerate(GUARDED):
                if before[path] is None:
                    step("restore-absent", ["/usr/bin/rm", "-f", path])
                else:
                    step("restore", ["/usr/bin/cp", "-p", str(run / "backup" / str(number)), path])
            step("userdata-cache", ["/usr/local/cpanel/scripts/updateuserdatacache", "--force"], 600)
            step("rebuild-httpd", ["/usr/local/cpanel/scripts/rebuildhttpdconf"], 600)
            step("restart-httpd-final", ["/usr/local/cpanel/scripts/restartsrv_httpd"], 300)
            after = digests()
            summary["after"] = after
            summary["restored"] = after == before
        summary["removed"] = not step("final-residue", ["/usr/bin/ls", "-d", owner.LSWS])["stdout"].strip() \
            and summary.get("package_erased", True)
        if armed and summary.get("restored") and summary["removed"]:
            step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])
            summary["recovery_disarmed"] = True
        failed = []
        if summary["result"] == "observed":
            cases = expected_outcomes(summary)
            summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
            summary["known_differences"] = KNOWN_DIFFERENCES
            failed = [name for name, ok in cases.items() if not ok]
            summary["result"] = "fail" if failed else "pass"
        summary["finished_at"] = probe.now()
        summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()}
        probe.durable_json(run / "manifest.json", summary)
        print(json.dumps({"path": str(run), "result": summary["result"], "failed_cases": failed, "restored": summary.get("restored"),
                          "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
