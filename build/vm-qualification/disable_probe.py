#!/usr/bin/python3
"""Reversible, empty-lab test of cPanel's disabled-httpd control paths."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import uuid

import service_probe as probe

ROOT = probe.ROOT
CONFIGURE = ["/usr/local/cpanel/bin/whmapi1", "--output=json", "configureservice", "service=httpd"]
ENABLE = CONFIGURE + ["enabled=1", "monitored=1"]
DISABLE = CONFIGURE + ["enabled=0", "monitored=0"]
RESTART = ["/usr/local/cpanel/scripts/restartsrv_httpd", "--restart"]
# Fixed recovery payload, embedded in the transient root-owned systemd unit.
# It does not import code from the user-writable checkout.
RECOVERY = (
    "import subprocess; "
    "subprocess.run(" + repr(ENABLE) + ",timeout=60,check=False); "
    "subprocess.run(" + repr(RESTART) + ",timeout=60,check=False)"
)

def disabled_observation(status, listeners, processes):
    data = probe.api(status, "servicestatus")
    rows = data.get("data", {}).get("service", [])
    if len(rows) != 1 or rows[0].get("name") != "httpd":
        raise ValueError("Ambiguous service state")
    row = rows[0]
    for key in ("installed", "enabled", "monitored"):
        if type(row.get(key)) is not int or row[key] not in (0, 1):
            raise ValueError("Unknown service field")
    if "running" in row and (type(row["running"]) is not int or row["running"] not in (0, 1)):
        raise ValueError("Unknown running field")
    if processes["exit_code"] not in (0, 1):
        raise ValueError("Missing process observation")
    process_text = processes["stdout"].strip()
    if ((processes["exit_code"] == 1 and process_text != "")
        or (processes["exit_code"] == 0 and (not process_text
            or any(not line.isdigit() for line in process_text.splitlines())))):
        raise ValueError("Malformed process observation")
    absent = processes["exit_code"] == 1
    if listeners["exit_code"] != 0:
        raise ValueError("Missing listener observation")
    return {
        "enabled": bool(row["enabled"]), "monitored": bool(row["monitored"]),
        "running": bool(row["running"]) if "running" in row else None,
        "httpd_processes_absent": absent, "public_ports_empty": listeners["stdout"].strip() == "",
        "disabled_and_stopped": row["enabled"] == 0 and row["monitored"] == 0
            and row.get("running", 0) == 0 and absent and listeners["stdout"].strip() == "",
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("This experiment stops Apache temporarily; --lab-empty-host is required")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("disable-" + run_id)
        run.mkdir(mode=0o700)
        unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "disabled-apache-experiment",
                   "started_at": probe.now(), "g0_a": "unproven", "ols_adapter_tested": False,
                   "recovery_unit": unit, "result": "not_run", "recovery_verified": False}
        spec = importlib.util.spec_from_file_location("snapshot", ROOT / "build/package/snapshot.py")
        snapshot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(snapshot)
        source = snapshot.archive()
        (run / "source.tar.gz").write_bytes(source)
        summary["source_sha256"] = hashlib.sha256(source).hexdigest()
        index = 0
        armed = False
        mutated = False

        def step(name, command):
            nonlocal index
            index += 1
            # Each command finishes well before the five-minute recovery timer.
            record = probe.invoke(["/usr/bin/timeout", "--kill-after=2s", "20s", *command])
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def observe(label):
            status = step(label + "-status", probe.COMMANDS["api_status"])
            ports = step(label + "-ports", probe.COMMANDS["listeners"])
            processes = step(label + "-processes", ["/usr/bin/pgrep", "-x", "httpd"])
            return disabled_observation(status, ports, processes)

        try:
            initial = {key: step("before-" + key, probe.COMMANDS[key])
                       for key in ("accounts_api", "account_entries", "version")}
            accounts = probe.api(initial["accounts_api"], "listaccts").get("data", {})
            if (not isinstance(accounts, dict) or accounts.get("acct", []) != []
                or any(r["exit_code"] != 0 for r in initial.values())
                or initial["account_entries"]["stdout"] != ""
                or initial["version"]["stdout"].strip() != "11.138.0.18"):
                raise ValueError("Not the qualified empty lab baseline")
            for key, command in probe.COMMANDS.items():
                if key not in initial:
                    initial[key] = step("before-" + key, command)
            summary["platform"] = probe.validate_baseline(initial)
            timer = step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + unit,
                "--on-active=5min", "--timer-property=AccuracySec=1s",
                "/usr/bin/python3", "-c", RECOVERY])
            if timer["exit_code"] != 0:
                raise ValueError("Unable to arm independent recovery")
            armed = True
            if step("check-timer", ["/usr/bin/systemctl", "is-active", unit + ".timer"])["exit_code"] != 0:
                raise ValueError("Recovery timer not active")
            if snapshot.archive() != source:
                raise ValueError("Source drift")
            probe.durable_json(run / "intent.json", {
                "operation": "disable-httpd-and-test-native-callers",
                "created_at": probe.now(), "restore": {"enabled": 1, "monitored": 1, "running": 1},
                "recovery_unit": unit, "independent_recovery_delay_seconds": 300})
            mutated = True  # Restore even if the disable call times out after changing state.
            probe.api(step("disable", DISABLE), "configureservice")
            summary["after_disable"] = observe("disabled")
            if not summary["after_disable"]["disabled_and_stopped"]:
                raise ValueError("Disable did not release listeners")
            summary["native_restart_exit"] = step("native-restart", RESTART)["exit_code"]
            summary["after_native_restart"] = observe("after-native")
            whm = step("whm-restart", probe.ACTIONS["whm-restart"])
            summary["whm_restart_exit"] = whm["exit_code"]
            metadata = json.loads(whm["stdout"]).get("metadata", {})
            if metadata.get("command") != "restartservice" or type(metadata.get("result")) is not int:
                raise ValueError("Missing WHM semantic result")
            summary["whm_restart_api_result"] = metadata["result"]
            summary["after_whm_restart"] = observe("after-whm")
            summary["result"] = "observed"
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
        finally:
            try:
                if mutated:
                    probe.api(step("restore-enable", ENABLE), "configureservice")
                    if step("restore-restart", RESTART)["exit_code"] != 0:
                        raise ValueError("Restore restart failed")
                    after = {key: step("after-" + key, cmd) for key, cmd in probe.COMMANDS.items()}
                    probe.validate_baseline(after)
                    if initial["hashes"]["stdout"] != after["hashes"]["stdout"]:
                        raise ValueError("Vendor/configuration drift")
                    summary["recovery_verified"] = True
                if armed and (not mutated or summary["recovery_verified"]):
                    stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", unit + ".timer"])
                    summary["recovery_timer_disarmed"] = stopped["exit_code"] == 0
                    if stopped["exit_code"] != 0:
                        raise ValueError("Timer cleanup failed")
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                summary["result"] = "recovery_required"
                summary["recovery_error_type"] = type(exc).__name__
                # Leave the independent timer armed when normal recovery was not verified.
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()
            }
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"],
                              "recovery_verified": summary["recovery_verified"], "g0_a": "unproven"}))
        return 0 if summary["result"] == "observed" and summary["recovery_verified"] else 1

if __name__ == "__main__":
    sys.exit(main())
