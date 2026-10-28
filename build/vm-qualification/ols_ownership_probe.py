#!/usr/bin/python3
"""Empty-lab G0-A ownership experiment (ADR-018 A1-A4, A7): install the product OLS package,
validate the candidate in a staged namespace, hand 80/443 from Apache to OLS through the
documented configureservice API, add a custom chkservd monitor, exercise native httpd
callers and an EA4 transaction, then return to Apache and remove everything.
An independent systemd timer restores Apache if this process dies. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_lab_cycle as cycle
import service_probe as probe

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES = pathlib.Path(__file__).resolve().parent / "ols-lab"
LSWS = "/usr/local/lsws"
WEB = "/var/lib/ols-cpanel-lab"
UNIT = "ols-cpanel.service"
# Product log shipper; ols-cpanel.service requires it (OLS-18), so cleanup stops both.
LOGS_UNIT = "ols-cpanel-logs.service"
MONITOR = "/etc/chkserv.d/olscpanel"
CHKSERV_CONF = "/etc/chkserv.d/chkservd.conf"
HEALTH = "olscpanel-health.txt"
MONITOR_LINE = ("service[olscpanel]=80,GET /" + HEALTH + " HTTP/1.0\\r\\nHost: localhost,HTTP/1..,"
                "/usr/bin/systemctl restart " + UNIT + "\n")
WEB_PORTS = ("( sport = :80 or sport = :443 )")
# chkservd restarts on the 3rd consecutive socket failure; checks run every 300 s here and the
# first one after a chkservd restart came about 8 minutes later (LOG-011).
CHKSERVD_WAIT = 4 * 300 + 120
EA4_PACKAGE = "ea-apache24-mod_expires"
# Fixed recovery code: it must not import the development checkout.
RECOVERY = ("systemctl stop ols-cpanel.service; "
            "sed -i '/^olscpanel:/d' /etc/chkserv.d/chkservd.conf; rm -f /etc/chkserv.d/olscpanel; "
            "/usr/local/cpanel/bin/whmapi1 configureservice service=httpd enabled=1 monitored=1; "
            "/usr/local/cpanel/scripts/restartsrv_httpd; /usr/local/cpanel/scripts/restartsrv_chkservd")

def invoke(command, limit=90):
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", str(limit) + "s", *command]
    started = probe.now()
    result = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=limit + 15,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin", "LANG": "C", "LC_ALL": "C"}, check=False)
    return {"started_at": started, "finished_at": probe.now(), "exit_code": result.returncode,
            "stdout": result.stdout[-1048576:].decode("utf-8", "replace"),
            "stderr": result.stderr[-1048576:].decode("utf-8", "replace")}

def erase_package(step, name="ols-cpanel-openlitespeed", *options):
    """rpm -e, retried while another transaction (cPanel maintenance) holds the RPM lock.
    Returns True only when the package is no longer in the RPM database."""
    for attempt in range(24):
        if step("rpm-query", ["/usr/bin/rpm", "-q", name])["exit_code"] != 0:
            return True
        step("rpm-erase", ["/usr/bin/rpm", "-e", *options, name])
        if step("rpm-query", ["/usr/bin/rpm", "-q", name])["exit_code"] != 0:
            return True
        time.sleep(5)
    return False

def owners(ss_text):
    """Map each web listener to the process names holding it."""
    result = {}
    for line in ss_text.splitlines():
        fields = line.split()
        if len(fields) >= 6:
            names = sorted(set(part.split('"')[1] for part in fields[5].split("((")[-1].split("),(")
                               if part.count('"') >= 2))
            result.setdefault(fields[3], set()).update(names)
    return {key: sorted(value) for key, value in result.items()}

def owned_by(ss_text, names):
    table = owners(ss_text)
    return bool(table) and all(set(v) <= set(names) for v in table.values())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path, help="product ols-cpanel-openlitespeed RPM")
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("This experiment stops Apache and moves 80/443 to OLS; --lab-empty-host is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("ols-owner-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "ols-ownership-experiment", "started_at": probe.now(),
                   "g0_a": "unproven", "result": "not_run", "checks": {}, "observations": {},
                   "recovery_unit": recovery_unit, "rpm_sha256": None}
        index = 0

        def step(name, command, limit=90):
            nonlocal index
            index += 1
            record = invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def check(name, condition, detail=None):
            summary["checks"][name] = {"pass": bool(condition), "detail": detail}
            if not condition:
                raise ValueError("Check failed: " + name)

        def observe(name, value):
            summary["observations"][name] = value
            return value

        def stage_file(name, content):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            return str(path)

        def web(label):
            return step(label + "-web-listeners", ["/usr/sbin/ss", "-H", "-ltnp", WEB_PORTS])["stdout"]

        def http(label, url):
            return step(label, ["/usr/bin/curl", "--noproxy", "*", "-ks", "--max-time", "5", url])["stdout"].strip()

        def apache_status(label):
            data = json.loads(step(label + "-httpd-status", probe.COMMANDS["api_status"])["stdout"])
            row = data["data"]["service"][0]
            return {k: row.get(k) for k in ("enabled", "monitored", "running")}

        def ols_running():
            return any(p["args"].startswith("openlitespeed (lshttpd - main)") for p in
                       cycle.ols_processes(step("ols-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"]))

        installed = armed = cut_over = monitor_added = False
        chkserv_before = None
        try:
            digest = invoke(["/usr/bin/sha256sum", str(args.rpm.resolve())])["stdout"].split()[0]
            summary["rpm_sha256"] = digest
            # Apache may still be restarting after a previous run's restoration.
            for _ in range(12):
                if invoke(probe.COMMANDS["http"])["stdout"] == "200":
                    break
                time.sleep(5)
            initial = {key: step("before-" + key, probe.COMMANDS[key])
                       for key in ("accounts_api", "account_entries", "version", "http")}
            accounts = probe.api(initial["accounts_api"], "listaccts").get("data", {})
            if (not isinstance(accounts, dict) or accounts.get("acct", []) != []
                    or initial["account_entries"]["stdout"] != "" or initial["http"]["stdout"] != "200"
                    or initial["version"]["stdout"].strip() != "11.138.0.18"):
                raise ValueError("Not the qualified empty lab baseline")
            check("apache-baseline", apache_status("before") == {"enabled": 1, "monitored": 1, "running": 1}
                  and owned_by(web("before"), ["httpd"]))
            if step("before-residue", ["/usr/bin/ls", "-d", LSWS, WEB, MONITOR])["stdout"].strip():
                raise ValueError("OLS residue present before experiment")
            chkserv_before = step("before-chkserv-hash", ["/usr/bin/sha256sum", CHKSERV_CONF])["stdout"]
            rpm_before = sorted(step("before-rpm", ["/usr/bin/rpm", "-qa"])["stdout"].split())

            installed = True
            check("product-rpm-install", step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"] == 0)
            check("no-listener-after-install", owned_by(web("installed"), ["httpd"]) and not ols_running())
            check("unit-installed-disabled", step("unit-enabled", ["/usr/bin/systemctl", "is-enabled", UNIT])
                  ["stdout"].strip() == "disabled")

            nonce = uuid.uuid4().hex
            for target, source, mode in [(LSWS + "/conf/httpd_config.conf", TEMPLATES / "ownership_httpd_config.conf", "0600")]:
                step("place-config", ["/usr/bin/install", "-m", mode, str(source), target])
            step("vhost-dir", ["/usr/bin/install", "-d", "-m", "0750", LSWS + "/conf/vhosts/owner", LSWS + "/conf/cert"])
            step("place-vhconf", ["/usr/bin/install", "-m", "0600", str(TEMPLATES / "ownership_vhconf.conf"),
                                  LSWS + "/conf/vhosts/owner/vhconf.conf"])
            step("web-dirs", ["/usr/bin/install", "-d", "-m", "0755", WEB, WEB + "/html", WEB + "/logs"])
            step("place-index", ["/usr/bin/install", "-m", "0644", stage_file("index.html", "ols-owner " + nonce + "\n"),
                                 WEB + "/html/index.html"])
            step("place-health", ["/usr/bin/install", "-m", "0644", stage_file(HEALTH, "ok\n"), WEB + "/html/" + HEALTH])
            check("lab-cert", step("lab-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                                                "-days", "2", "-subj", "/CN=ols-cpanel-lab",
                                                "-keyout", LSWS + "/conf/cert/lab.key",
                                                "-out", LSWS + "/conf/cert/lab.crt"])["exit_code"] == 0)

            # G0-B: the staged candidate must pass, and deliberately broken candidates must fail,
            # without touching the live tree.
            with tempfile.TemporaryDirectory(dir=run) as temp:
                os.chmod(temp, 0o755)
                good = pathlib.Path(temp, "good")
                (good / "vhosts/owner").mkdir(parents=True)
                (good / "httpd_config.conf").write_text((TEMPLATES / "ownership_httpd_config.conf").read_text())
                (good / "vhosts/owner/vhconf.conf").write_text((TEMPLATES / "ownership_vhconf.conf").read_text())
                (good / "cert").mkdir()
                for name in ("lab.key", "lab.crt"):
                    # Owned by the development user so the staging tree can be prepared and cleaned.
                    step("copy-cert-" + name, ["/usr/bin/install", "-m", "0644", "-o", str(os.getuid()),
                                               "-g", str(os.getgid()), LSWS + "/conf/cert/" + name,
                                               str(good / "cert" / name)])
                (good / "admin_config.conf").write_text((TEMPLATES / "admin_config.conf").read_text())
                validator = [sys.executable, "-I", str(pathlib.Path(__file__).resolve().parent / "ols_stage_validate.py")]
                for root, dirs, files in os.walk(temp):
                    for name in dirs:
                        os.chmod(os.path.join(root, name), 0o755)
                    for name in files:
                        os.chmod(os.path.join(root, name), 0o644)
                result = step("stage-valid", [*validator, str(good)])
                observe("stage_valid", json.loads(result["stdout"] or "{}"))
                check("staged-valid-candidate-passes", result["exit_code"] == 0)
                broken_cases = {"unterminated-block": "virtualHost broken {\n  vhRoot /nonexistent/\n",
                                "unknown-directive": "thisIsNotADirective 1\n",
                                "bad-listener": "listener bad {\n  address not-an-address\n  secure 0\n}\n"}
                outcomes = {}
                for case, fragment in broken_cases.items():
                    bad = pathlib.Path(temp, case)
                    (bad / "vhosts/owner").mkdir(parents=True)
                    (bad / "httpd_config.conf").write_text((good / "httpd_config.conf").read_text() + fragment)
                    (bad / "vhosts/owner/vhconf.conf").write_text((good / "vhosts/owner/vhconf.conf").read_text())
                    for path in [bad, bad / "vhosts", bad / "vhosts/owner"]:
                        os.chmod(path, 0o755)
                    for path in bad.rglob("*.conf"):
                        os.chmod(path, 0o644)
                    record = step("stage-" + case, [*validator, str(bad)])
                    outcomes[case] = {"exit_code": record["exit_code"],
                                      "report": json.loads(record["stdout"] or "{}")}
                observe("stage_broken", outcomes)
                check("staged-broken-candidates-fail", all(v["exit_code"] != 0 for v in outcomes.values()), outcomes)

            # A1: cut over through the documented API, with independent recovery armed first.
            timer = step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=60min",
                                          "--timer-property=AccuracySec=1s", "/bin/sh", "-c", RECOVERY])
            check("recovery-armed", timer["exit_code"] == 0)
            armed = True
            cut_over = True
            check("disable-apache", probe.api(step("disable-httpd", ["/usr/local/cpanel/bin/whmapi1", "--output=json",
                  "configureservice", "service=httpd", "enabled=0", "monitored=0"]), "configureservice") is not None)
            time.sleep(3)
            check("apache-released-ports", not owners(web("apache-disabled")))
            observe("chkservd_httpd_after_disable", [l for l in step("chkservd-conf-after-disable",
                    ["/usr/bin/grep", "-E", "^(httpd|olscpanel):", CHKSERV_CONF])["stdout"].splitlines()])
            check("start-ols", step("start-ols", ["/usr/bin/systemctl", "start", UNIT])["exit_code"] == 0)
            time.sleep(3)
            check("ols-owns-web-ports", owned_by(web("ols-active"), ["litespeed", "openlitespeed", "lshttpd"])
                  and len(owners(web("ols-active-2"))) >= 2)
            public = step("public-ip", ["/usr/bin/hostname", "-I"])["stdout"].split()[0]
            check("http-nonce", http("http-local", "http://127.0.0.1/") == "ols-owner " + nonce)
            check("https-nonce", http("https-local", "https://127.0.0.1/") == "ols-owner " + nonce)
            check("public-http-nonce", http("http-public", "http://" + public + "/") == "ols-owner " + nonce)
            observe("ipv6_http", http("http-ipv6", "http://[::1]/"))
            observe("outbound_artifacts", {name: step("outbound-" + name.replace("/", "-"),
                    ["/usr/bin/test", "-e", LSWS + "/" + name])["exit_code"] == 0 for name in cycle.OUTBOUND_ARTIFACTS})

            # A2: custom chkservd monitor restarts OLS after an orderly stop systemd will not undo.
            monitor_added = True
            step("monitor-file", ["/usr/bin/install", "-m", "0644", stage_file("olscpanel.monitor", MONITOR_LINE), MONITOR])
            step("monitor-enable", ["/usr/bin/sh", "-c", "grep -q '^olscpanel:' " + CHKSERV_CONF
                                    + " || echo olscpanel:1 >> " + CHKSERV_CONF])
            check("chkservd-restart", step("restart-chkservd", ["/usr/local/cpanel/scripts/restartsrv_chkservd"],
                                           120)["exit_code"] == 0)
            time.sleep(10)
            step("stop-ols-for-monitor", ["/usr/bin/systemctl", "stop", UNIT])
            stopped_at = time.monotonic()
            check("ols-stopped", not ols_running())
            recovered_after = None
            while time.monotonic() - stopped_at < CHKSERVD_WAIT:
                time.sleep(20)
                if ols_running() and http("monitor-poll", "http://127.0.0.1/" + HEALTH) == "ok":
                    recovered_after = round(time.monotonic() - stopped_at)
                    break
            observe("chkservd_recovery_seconds", recovered_after)
            step("chkservd-log", ["/usr/bin/tail", "-n", "60", "/var/log/chkservd.log"])
            check("chkservd-restarted-ols", recovered_after is not None)
            check("apache-still-disabled-after-monitor", apache_status("after-monitor")["enabled"] == 0
                  and owned_by(web("after-monitor"), ["litespeed", "openlitespeed", "lshttpd"]))

            # A3: native httpd callers while OLS owns the ports.
            observe("native_restart_exit", step("native-restart", ["/usr/local/cpanel/scripts/restartsrv_httpd",
                                                                   "--restart"], 120)["exit_code"])
            whm = step("whm-restart", probe.ACTIONS["whm-restart"], 120)
            observe("whm_restart_result", json.loads(whm["stdout"]).get("metadata", {}).get("result"))
            time.sleep(3)
            check("native-callers-did-not-start-apache", owned_by(web("after-native"), ["litespeed", "openlitespeed", "lshttpd"])
                  and http("http-after-native", "http://127.0.0.1/") == "ols-owner " + nonce)

            # A4: rebuildhttpdconf and an EA4 transaction (its hook runs restartsrv_httpd --stop/start).
            observe("rebuildhttpdconf_exit", step("rebuildhttpdconf", ["/usr/local/cpanel/scripts/rebuildhttpdconf"],
                                                  300)["exit_code"])
            observe("ea4_reinstall_exit", step("ea4-reinstall", ["/usr/bin/dnf", "-y", "-q", "reinstall", EA4_PACKAGE],
                                               600)["exit_code"])
            time.sleep(5)
            check("ea4-and-rebuild-kept-ols", owned_by(web("after-ea4"), ["litespeed", "openlitespeed", "lshttpd"])
                  and ols_running() and http("http-after-ea4", "http://127.0.0.1/") == "ols-owner " + nonce)
            check("apache-disabled-after-ea4", apache_status("after-ea4")["enabled"] == 0)
            summary["result"] = "pass_pending_restore"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            # A7: return to Apache and remove every product artifact.
            if monitor_added:
                step("restore-monitor-conf", ["/usr/bin/sed", "-i", "/^olscpanel:/d", CHKSERV_CONF])
                step("remove-monitor", ["/usr/bin/rm", "-f", MONITOR])
                step("restore-chkservd", ["/usr/local/cpanel/scripts/restartsrv_chkservd"], 120)
            if installed:
                step("stop-ols-final", ["/usr/bin/systemctl", "stop", UNIT, LOGS_UNIT])
                log = step("ols-error-log", ["/usr/bin/tail", "-c", "900000", LSWS + "/logs/error.log"])["stdout"]
                observe("trusted_acl_lines", [l[27:] for l in log.splitlines()
                                              if "trusted" in l.lower() or "QUIC.cloud" in l][:10])
            if cut_over:
                step("enable-httpd", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "configureservice",
                                      "service=httpd", "enabled=1", "monitored=1"])
                step("start-httpd", ["/usr/local/cpanel/scripts/restartsrv_httpd"], 120)
                time.sleep(3)
            if installed:
                summary["package_erased"] = erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, WEB, "/tmp/lshttpd", "/run/ols-cpanel/lshttpd", "/dev/shm/ols"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
            restored = {"apache": apache_status("final") == {"enabled": 1, "monitored": 1, "running": 1},
                        "listeners": owned_by(web("final"), ["httpd"]),
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200",
                        "chkservd_conf": chkserv_before is None
                        or step("final-chkserv-hash", ["/usr/bin/sha256sum", CHKSERV_CONF])["stdout"] == chkserv_before,
                        "package_absent": summary.get("package_erased", True),
                        "residue": not step("final-residue", ["/usr/bin/ls", "-d", LSWS, WEB, MONITOR])["stdout"].strip()}
            if installed:
                restored["rpm_set"] = sorted(step("final-rpm", ["/usr/bin/rpm", "-qa"])["stdout"].split()) == rpm_before
            summary["restored"] = restored
            if armed and all(restored.values()):
                step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])
                summary["recovery_disarmed"] = True
            if summary["result"] == "pass_pending_restore":
                summary["result"] = "pass" if all(restored.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": summary["restored"],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
