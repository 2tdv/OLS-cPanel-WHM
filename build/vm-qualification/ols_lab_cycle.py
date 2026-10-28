#!/usr/bin/python3
"""Empty-lab NEXT-03 cycle: install pinned OLS without vendor scriptlets, serve on loopback,
exercise stop/fault paths, remove, and prove the host returned to its prior state.
NOT an installer, adapter or G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import service_probe as probe

def owner_erase(step, name, *options):
    # Imported lazily: ols_ownership_probe imports this module.
    import ols_ownership_probe
    return ols_ownership_probe.erase_package(step, name, *options)

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES = pathlib.Path(__file__).resolve().parent / "ols-lab"
PINNED_SHA256 = "a76c241e654b2684c91c5b5c6eb1ffd084fa55bf907240bf822aee5fd920ee61"
LSWS = "/usr/local/lsws"
WEB = "/var/lib/ols-cpanel-lab"
UNIT = "ols-cpanel-lab.service"
UNIT_PATH = "/etc/systemd/system/" + UNIT
EXPECTED_NEW_LISTENER = "tcp 127.0.0.1:8088"
APACHE_FILES = ["/etc/apache2/conf/httpd.conf", "/usr/local/cpanel/scripts/restartsrv_httpd",
                "/etc/chkserv.d/chkservd.conf"]
OUTBOUND_WAIT = 75
OUTBOUND_ARTIFACTS = ["admin/conf/quic-cloud-ips", "tmp/download-quic-cloud-ips", "tmp/download-quic-cloud-ips.tmp",
                      "autoupdate/release", "autoupdate/releasecb"]
BROKEN_FRAGMENT = "virtualHost unterminated {\n  vhRoot /nonexistent/\nthisIsNotADirective 1\n"

def listener_set(text):
    rows = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            rows.add(fields[0] + " " + fields[4])
    return rows

def new_listeners(before, after):
    return sorted(after - before), sorted(before - after)

def ols_processes(ps_text):
    rows = []
    for line in ps_text.splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and (fields[3].startswith("openlitespeed") or fields[3].startswith("lsphp")):
            rows.append({"pid": int(fields[0]), "ppid": int(fields[1]), "user": fields[2], "args": fields[3]})
    return rows

def php_probe(body):
    data = json.loads(body)
    return (data.get("sapi") == "litespeed" and re.fullmatch(r"8\.3\.\d+", str(data.get("version"))) is not None
            and data.get("user") == "nobody" and data.get("ini") == "/opt/cpanel/ea-php83/root/etc/php.ini")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("This experiment installs and removes OLS; --lab-empty-host is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("ols-lab-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)  # root must read staged files; contents stay private by mode.
        summary = {"schema_version": 1, "kind": "ols-lab-cycle", "started_at": probe.now(),
                   "artifact_sha256": PINNED_SHA256, "g0": "unproven", "result": "not_run",
                   "installed": False, "removed": False, "checks": {}}
        index = 0

        def step(name, command):
            nonlocal index
            index += 1
            record = probe.invoke(command)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def check(name, condition, detail=None):
            summary["checks"][name] = {"pass": bool(condition), "detail": detail}
            if not condition:
                raise ValueError("Check failed: " + name)

        def stage(name, content):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            return str(path)

        def state(label):
            return {
                "rpm": sorted(step(label + "-rpm", ["/usr/bin/rpm", "-qa", "--qf", "%{NEVRA}\n"])["stdout"].split()),
                "units": sorted(step(label + "-units", ["/usr/bin/ls", "/etc/systemd/system",
                                                        "/usr/lib/systemd/system"])["stdout"].split()),
                "passwd": sorted(l.split(":")[0] for l in step(label + "-passwd", ["/usr/bin/getent", "passwd"])
                                 ["stdout"].splitlines()),
                "group": sorted(step(label + "-group", ["/usr/bin/getent", "group"])["stdout"].splitlines()),
                "listeners": listener_set(step(label + "-listeners", ["/usr/sbin/ss", "-H", "-ltnu"])["stdout"]),
                "apache_hashes": step(label + "-hashes", ["/usr/bin/sha256sum", *APACHE_FILES])["stdout"],
                "paths": step(label + "-paths", ["/usr/bin/ls", "-d", LSWS, WEB, "/tmp/lshttpd", "/dev/shm/ols",
                                                 UNIT_PATH])["stdout"].split(),
            }

        installed = False
        try:
            if probe.invoke(["/usr/bin/sha256sum", str(args.rpm.resolve())])["stdout"].split()[:1] != [PINNED_SHA256]:
                raise ValueError("Artifact digest mismatch")
            initial = {key: step("before-" + key, probe.COMMANDS[key])
                       for key in ("accounts_api", "account_entries", "version", "api_status", "http")}
            accounts = probe.api(initial["accounts_api"], "listaccts").get("data", {})
            if (not isinstance(accounts, dict) or accounts.get("acct", []) != []
                    or initial["account_entries"]["stdout"] != ""
                    or initial["version"]["stdout"].strip() != "11.138.0.18"
                    or initial["http"]["stdout"] != "200"):
                raise ValueError("Not the qualified empty lab baseline")
            before = state("before")
            if before["paths"] or step("before-rpmq", ["/usr/bin/rpm", "-q", "openlitespeed"])["exit_code"] == 0:
                raise ValueError("OLS residue present before install")
            summary["dnf_check_before"] = step("before-dnf-check", ["/usr/bin/dnf", "-q", "-C", "check"])["exit_code"]

            installed = True  # Clean up even if rpm fails after partially writing files.
            install = step("install", ["/usr/bin/rpm", "-i", "--nodeps", "--noscripts", "--notriggers",
                                       str(args.rpm.resolve())])
            check("rpm-install", install["exit_code"] == 0, install["stderr"][-400:])
            summary["installed"] = True
            idle = state("installed-idle")
            check("no-listener-after-install", idle["listeners"] == before["listeners"])
            check("no-process-after-install",
                  not ols_processes(step("installed-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"]))
            check("no-unit-after-install", idle["units"] == before["units"])

            for name, target, mode in [("httpd_config.conf", LSWS + "/conf/httpd_config.conf", "0600"),
                                       ("admin_config.conf", LSWS + "/admin/conf/admin_config.conf", "0600")]:
                step("place-" + name, ["/usr/bin/install", "-m", mode, "-o", "root", "-g", "root",
                                       str(TEMPLATES / name), target])
            step("vhost-dir", ["/usr/bin/install", "-d", "-m", "0750", LSWS + "/conf/vhosts/lab"])
            step("place-vhconf", ["/usr/bin/install", "-m", "0600", str(TEMPLATES / "vhconf.conf"),
                                  LSWS + "/conf/vhosts/lab/vhconf.conf"])
            step("web-dirs", ["/usr/bin/install", "-d", "-m", "0755", WEB, WEB + "/html", WEB + "/logs"])
            nonce = uuid.uuid4().hex
            step("place-index", ["/usr/bin/install", "-m", "0644", stage("index.html", "ols-lab-static " + nonce + "\n"),
                                 WEB + "/html/index.html"])
            step("place-probe", ["/usr/bin/install", "-m", "0644", str(TEMPLATES / "probe.php"),
                                 WEB + "/html/probe.php"])
            step("place-unit", ["/usr/bin/install", "-m", "0644", str(TEMPLATES / UNIT), UNIT_PATH])
            step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])

            # G0-B input: does the native test flag reject a broken live configuration?
            conf = LSWS + "/conf/httpd_config.conf"
            good = step("conf-hash", ["/usr/bin/sha256sum", conf])["stdout"]
            summary["native_test_valid_exit"] = step("native-test-valid", [LSWS + "/bin/openlitespeed", "-t"])["exit_code"]
            step("break-config", ["/usr/bin/sh", "-c", 'cat "$1" >> "$2"', "sh",
                                  stage("broken.fragment", BROKEN_FRAGMENT), conf])
            summary["native_test_broken_exit"] = step("native-test-broken", [LSWS + "/bin/openlitespeed", "-t"])["exit_code"]
            step("restore-config", ["/usr/bin/install", "-m", "0600", str(TEMPLATES / "httpd_config.conf"), conf])
            check("config-restored", step("conf-hash-after", ["/usr/bin/sha256sum", conf])["stdout"] == good)
            summary["native_test_detects_errors"] = summary["native_test_broken_exit"] != 0

            check("unit-not-enabled", step("unit-enabled", ["/usr/bin/systemctl", "is-enabled", UNIT])
                  ["stdout"].strip() == "static")
            check("start", step("start", ["/usr/bin/systemctl", "start", UNIT])["exit_code"] == 0)
            started = time.monotonic()
            time.sleep(3)
            running = state("running")
            added, removed = new_listeners(before["listeners"], running["listeners"])
            check("only-loopback-listener", added == [EXPECTED_NEW_LISTENER] and not removed, added)
            static = step("http-static", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "5",
                                          "http://127.0.0.1:8088/"])
            check("static-nonce", static["stdout"].strip() == "ols-lab-static " + nonce)
            php = step("http-php", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "20",
                                    "http://127.0.0.1:8088/probe.php"])
            check("ea4-lsapi-php", php_probe(php["stdout"]), php["stdout"][:300])
            public = step("public-ip", ["/usr/bin/hostname", "-I"])["stdout"].split()[0]
            exposed = step("public-8088", ["/usr/bin/curl", "--noproxy", "*", "-s", "-o", "/dev/null", "--max-time", "3",
                                           "-w", "%{http_code}", "http://" + public + ":8088/"])
            check("public-ip-refused", exposed["stdout"] == "000")
            check("apache-unchanged", running["apache_hashes"] == before["apache_hashes"]
                  and step("apache-http", probe.COMMANDS["http"])["stdout"] == "200")
            processes = ols_processes(step("running-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"])
            summary["processes"] = processes
            check("workers-unprivileged", all(p["user"] == "nobody" for p in processes
                                              if "lshttpd - #" in p["args"] or p["args"].startswith("lsphp")))
            # Let the first 60-second server timer fire, then record hard-coded outbound fetch artifacts.
            time.sleep(max(0.0, started + OUTBOUND_WAIT - time.monotonic()))
            summary["outbound_artifacts"] = {name: step("outbound-" + name.replace("/", "-"),
                                                        ["/usr/bin/test", "-e", LSWS + "/" + name])["exit_code"] == 0
                                             for name in OUTBOUND_ARTIFACTS}

            worker = next(p["pid"] for p in processes if p["args"].endswith("(lshttpd - #01)"))
            step("kill-worker", ["/usr/bin/kill", "-9", str(worker)])
            time.sleep(3)
            respawned = ols_processes(step("after-worker-kill-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"])
            check("worker-respawned", any(p["args"].endswith("(lshttpd - #01)") and p["pid"] != worker for p in respawned)
                  and step("after-worker-kill-http", probe.COMMANDS["http"][:-1] + ["http://127.0.0.1:8088/"])
                  ["stdout"] == "200")

            main_pid = step("main-pid", ["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", UNIT])["stdout"].strip()
            step("kill-main", ["/usr/bin/kill", "-9", main_pid])
            time.sleep(4)
            summary["after_main_kill_unit"] = step("after-main-kill-active", ["/usr/bin/systemctl", "is-active", UNIT])["stdout"].strip()
            check("no-orphans-after-main-kill",
                  not ols_processes(step("after-main-kill-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"])
                  and state("after-main-kill")["listeners"] == before["listeners"])
            step("reset-failed", ["/usr/bin/systemctl", "reset-failed", UNIT])
            check("restart", step("restart", ["/usr/bin/systemctl", "start", UNIT])["exit_code"] == 0)
            time.sleep(2)
            check("php-after-restart", php_probe(step("http-php-2", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time",
                                                                      "20", "http://127.0.0.1:8088/probe.php"])["stdout"]))
            summary["dnf_check_installed"] = step("installed-dnf-check", ["/usr/bin/dnf", "-q", "-C", "check"])["exit_code"]
            check("stop", step("stop", ["/usr/bin/systemctl", "stop", UNIT])["exit_code"] == 0)
            time.sleep(2)
            check("stop-result-success", step("stop-result", ["/usr/bin/systemctl", "show", "-p", "Result", "--value", UNIT])
                  ["stdout"].strip() == "success")
            check("no-process-after-stop",
                  not ols_processes(step("stopped-ps", ["/usr/bin/ps", "-eo", "pid,ppid,user,args"])["stdout"]))
            summary["result"] = "pass_pending_cleanup"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                step("cleanup-stop", ["/usr/bin/systemctl", "stop", UNIT])
                log = step("server-error-log", ["/usr/bin/tail", "-c", "900000", LSWS + "/logs/error.log"])["stdout"]
                summary["trusted_acl_log_lines"] = [line[27:] for line in log.splitlines()
                                                    if "trusted" in line.lower() or "QUIC.cloud" in line][:20]
                owner_erase(step, "openlitespeed", "--noscripts", "--nodeps")
                step("cleanup-files", ["/usr/bin/rm", "-rf", LSWS, WEB, "/tmp/lshttpd", "/dev/shm/ols", UNIT_PATH])
                step("cleanup-reload", ["/usr/bin/systemctl", "daemon-reload"])
                step("cleanup-reset", ["/usr/bin/systemctl", "reset-failed", UNIT])
                after = state("after-removal")
                same = {key: after[key] == before[key] for key in before}
                summary["post_removal_identical"] = same
                summary["dnf_check_after"] = step("after-dnf-check", ["/usr/bin/dnf", "-q", "-C", "check"])["exit_code"]
                summary["removed"] = all(same.values()) and summary["dnf_check_after"] == summary["dnf_check_before"]
                if summary["result"] == "pass_pending_cleanup":
                    summary["result"] = "pass" if summary["removed"] else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "removed": summary["removed"],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
