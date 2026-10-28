#!/usr/bin/python3
"""Empty-lab G0-D parity experiment: serve the same probe from Apache's default docroot through
Apache (EA4 CGI) and through the product OLS build (EA4 LSAPI, loopback only), compare the
effective PHP environments, then remove OLS. Apache keeps ports 80/443 throughout."""
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
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "php-parity"))
import compare
import ols_ownership_probe as owner
import service_probe as probe

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent / "php-parity"
LSWS = owner.LSWS
WEB = owner.WEB
DOCROOT = "/var/www/html"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path, help="product ols-cpanel-openlitespeed RPM")
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("This experiment installs OLS and writes a probe into the Apache docroot; --lab-empty-host is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("php-parity-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "php-parity-experiment", "started_at": probe.now(),
                   "g0_d": "unproven", "result": "not_run"}
        index = 0

        def step(name, command, limit=90):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        installed = False
        script = "olscp-parity-" + uuid.uuid4().hex + ".php"
        try:
            initial = {key: step("before-" + key, probe.COMMANDS[key])
                       for key in ("accounts_api", "account_entries", "version", "http")}
            accounts = probe.api(initial["accounts_api"], "listaccts").get("data", {})
            if (not isinstance(accounts, dict) or accounts.get("acct", []) != []
                    or initial["account_entries"]["stdout"] != "" or initial["http"]["stdout"] != "200"):
                raise ValueError("Not the qualified empty lab baseline")
            if step("before-residue", ["/usr/bin/ls", "-d", LSWS, WEB])["stdout"].strip():
                raise ValueError("OLS residue present before experiment")
            rpm_before = sorted(step("before-rpm", ["/usr/bin/rpm", "-qa"])["stdout"].split())
            summary["rpm_sha256"] = owner.invoke(["/usr/bin/sha256sum", str(args.rpm.resolve())])["stdout"].split()[0]
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            step("place-config", ["/usr/bin/install", "-m", "0600", str(HERE / "httpd_config.conf"),
                                  LSWS + "/conf/httpd_config.conf"])
            step("vhost-dir", ["/usr/bin/install", "-d", "-m", "0750", LSWS + "/conf/vhosts/parity"])
            step("place-vhconf", ["/usr/bin/install", "-m", "0600", str(HERE / "vhconf.conf"),
                                  LSWS + "/conf/vhosts/parity/vhconf.conf"])
            step("log-dir", ["/usr/bin/install", "-d", "-m", "0755", WEB, WEB + "/logs"])
            if step("start", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(3)
            step("place-probe", ["/usr/bin/install", "-m", "0644", str(HERE / "probe.php"), DOCROOT + "/" + script])
            results = {}
            for name, url in (("apache", "http://127.0.0.1/"), ("ols", "http://127.0.0.1:8088/")):
                record = step("fetch-" + name, ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "20",
                                                "-H", "Host: localhost", url + script + "?parity=1"])
                results[name] = json.loads(record["stdout"])
            report = compare.compare(results["apache"], results["ols"], test_binding={"SERVER_PORT": "8088"})
            summary["reference"] = {k: results["apache"][k] for k in ("sapi", "version", "user", "ini_loaded")}
            summary["candidate"] = {k: results["ols"][k] for k in ("sapi", "version", "user", "ini_loaded")}
            summary["equivalent"] = report["equivalent"]
            summary["unexpected_differences"] = [d for d in report["differences"] if not d["expected"]]
            summary["expected_differences"] = [d["field"] for d in report["differences"] if d["expected"]]
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            step("remove-probe", ["/usr/bin/rm", "-f", DOCROOT + "/" + script])
            if installed:
                step("stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                summary["package_erased"] = owner.erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, WEB, "/tmp/lshttpd", "/dev/shm/ols"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
                summary["removed"] = (summary["package_erased"] and not step("final-residue", ["/usr/bin/ls", "-d", LSWS, WEB, DOCROOT + "/" + script])
                                      ["stdout"].strip()
                                      and sorted(step("final-rpm", ["/usr/bin/rpm", "-qa"])["stdout"].split()) == rpm_before
                                      and step("final-http", probe.COMMANDS["http"])["stdout"] == "200")
                if summary["result"] == "observed" and not summary["removed"]:
                    summary["result"] = "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "equivalent": summary.get("equivalent"),
                              "unexpected": len(summary.get("unexpected_differences", [])), "error": summary.get("error")}))
    return 0 if summary["result"] == "observed" else 1

if __name__ == "__main__":
    sys.exit(main())
