#!/usr/bin/python3
"""Empty-lab Apache control-path experiment; NOT an OLS adapter or G0 certificate."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMMANDS = {
    "api_status": ["/usr/local/cpanel/bin/whmapi1", "--output=json", "servicestatus", "service=httpd"],
    "accounts_api": ["/usr/local/cpanel/bin/whmapi1", "--output=json", "listaccts"],
    "account_entries": ["/usr/bin/find", "/var/cpanel/users", "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n"],
    "native_status": ["/usr/local/cpanel/scripts/restartsrv_httpd", "--status"],
    "listeners": ["/usr/sbin/ss", "-H", "-ltnp", "( sport = :80 or sport = :443 )"],
    "syntax": ["/usr/sbin/httpd", "-t"],
    "hashes": ["/usr/bin/sha256sum", "/usr/local/cpanel/Cpanel/ServiceManager/Services/Httpd.pm",
               "/usr/local/cpanel/scripts/restartsrv_httpd", "/etc/apache2/conf/httpd.conf"],
    "version": ["/usr/bin/cat", "/usr/local/cpanel/version"],
    "http": ["/usr/bin/curl", "--noproxy", "*", "--max-time", "5", "--silent", "--show-error",
             "--head", "--output", "/dev/null", "--write-out", "%{http_code}", "http://127.0.0.1/"],
}
ACTIONS = {
    "native-graceful": ["/usr/local/cpanel/scripts/restartsrv_httpd", "--graceful"],
    "whm-restart": ["/usr/local/cpanel/bin/whmapi1", "--output=json", "restartservice", "service=httpd"],
}
now = lambda: datetime.now(timezone.utc).isoformat()

def invoke(command):
    # timeout runs with the target's privileges, so descendants can be terminated too.
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", "90s", *command]
    started = now()
    # Spool to private files rather than retaining unbounded pipe output in RAM.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                                timeout=105, check=False)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(1048577), err.read(1048577)
    if len(stdout) > 1048576 or len(stderr) > 1048576:
        raise ValueError("Probe output limit exceeded")
    return {"started_at": started, "finished_at": now(), "exit_code": result.returncode,
            "stdout": stdout.decode("utf-8", errors="strict"),
            "stderr": stderr.decode("utf-8", errors="strict")}

def api(record, command):
    if record["exit_code"] != 0:
        raise ValueError("API command failed")
    data = json.loads(record["stdout"])
    metadata = data.get("metadata", {})
    if metadata.get("result") != 1 or metadata.get("command") != command:
        raise ValueError("API semantic failure")
    return data

def validate_baseline(records):
    if any(record["exit_code"] != 0 for record in records.values()):
        raise ValueError("Incomplete baseline")
    accounts = api(records["accounts_api"], "listaccts")
    # This observed cPanel release omits data on a successful zero-account result.
    # Never infer empty from that alone: require an independently empty user directory.
    data = accounts.get("data", {})
    if not isinstance(data, dict) or data.get("acct", []) != [] or records["account_entries"]["stdout"] != "":
        raise ValueError("Host is not an empty lab")
    status = api(records["api_status"], "servicestatus")
    services = status.get("data", {}).get("service", [])
    if len(services) != 1 or services[0].get("name") != "httpd":
        raise ValueError("Missing unique Apache status")
    if any(services[0].get(key) != 1 for key in ("running", "enabled", "monitored", "installed")):
        raise ValueError("Apache is not fully healthy/enabled/monitored")
    ports = set()
    for line in records["listeners"]["stdout"].splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise ValueError("Malformed listener")
        port = fields[3].rsplit(":", 1)[-1]
        owners = re.findall(r'\("([^"]+)",pid=([0-9]+),fd=[0-9]+\)', line)
        if port not in ("80", "443") or not owners or any(name != "httpd" for name, _ in owners):
            raise ValueError("Unknown or competing public listener owner")
        ports.add(port)
    if ports != {"80", "443"}:
        raise ValueError("Both public ports must be owned by Apache")
    if records["http"]["stdout"] != "200":
        raise ValueError("Local default HTTP response is not the expected 200")
    version = records["version"]["stdout"].strip()
    if not re.fullmatch(r"11\.138\.0\.18", version):
        raise ValueError("This lab contract is only observed on cPanel 11.138.0.18")
    lines = records["hashes"]["stdout"].splitlines()
    expected = COMMANDS["hashes"][1:]
    if len(lines) != len(expected):
        raise ValueError("Missing integrity observations")
    for line, path in zip(lines, expected):
        if not re.fullmatch(r"[0-9a-f]{64}  " + re.escape(path), line):
            raise ValueError("Invalid integrity observation")
    return {"cpanel": version, "ports": sorted(ports), "service": "httpd", "empty_lab": True}

def verdict(before, action, after, action_name):
    validate_baseline(before)
    validate_baseline(after)
    if action["exit_code"] != 0:
        raise ValueError("Restart failed")
    if action_name == "whm-restart":
        api(action, "restartservice")
    if before["hashes"]["stdout"] != after["hashes"]["stdout"]:
        raise ValueError("Vendor/configuration hash changed")
    if before["version"]["stdout"] != after["version"]["stdout"]:
        raise ValueError("cPanel version changed during probe")
    return "pass"

def durable_json(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["observe", *ACTIONS], default="observe")
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if args.action != "observe" and not args.lab_empty_host:
        parser.error("Restart experiments require --lab-empty-host on an authorized empty lab")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(parents=True, exist_ok=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("service-" + str(uuid.uuid4()))
        run.mkdir(mode=0o700)
        spec = importlib.util.spec_from_file_location("snapshot", ROOT / "build/package/snapshot.py")
        snapshot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(snapshot)
        source = snapshot.archive()
        (run / "source.tar.gz").write_bytes(source)
        manifest = {"schema_version": 1, "kind": "native-apache-control-experiment",
                    "source_sha256": hashlib.sha256(source).hexdigest(), "started_at": now(),
                    "action": args.action, "g0_a": "unproven", "ols_adapter_tested": False,
                    "reviewer": None, "result": "not_run"}
        try:
            # Check emptiness first, before the HTTP probe can hit an application.
            before = {key: invoke(COMMANDS[key]) for key in ("accounts_api", "account_entries", "version")}
            account_data = api(before["accounts_api"], "listaccts").get("data", {})
            if (any(r["exit_code"] != 0 for r in before.values())
                    or before["version"]["stdout"].strip() != "11.138.0.18"
                    or not isinstance(account_data, dict)
                    or account_data.get("acct", []) != [] or before["account_entries"]["stdout"]):
                raise ValueError("Refusing experiment on nonempty or ambiguous host")
            for key, command in COMMANDS.items():
                if key not in before:
                    before[key] = invoke(command)
            durable_json(run / "before.json", before)
            manifest["platform"] = validate_baseline(before)
            if snapshot.archive() != source:
                raise ValueError("Source changed before experiment")
            if args.action == "observe":
                manifest["result"] = "observed"
            else:
                durable_json(run / "intent.json", {"action": args.action, "created_at": now(),
                             "expected": "healthy Apache and unchanged vendor/configuration hashes"})
                action = invoke(ACTIONS[args.action])
                durable_json(run / "action.json", action)
                after = {key: invoke(command) for key, command in COMMANDS.items()}
                durable_json(run / "after.json", after)
                manifest["result"] = verdict(before, action, after, args.action)
                if snapshot.archive() != source:
                    raise ValueError("Source changed during experiment")
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            manifest["result"] = "fail"
            manifest["error_type"] = type(exc).__name__
            # No arbitrary command output or tenant data in terminal errors.
        finally:
            manifest["finished_at"] = now()
            manifest["file_sha256"] = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(run.iterdir()) if path.is_file()
            }
            durable_json(run / "manifest.json", manifest)
            print(json.dumps({"path": str(run), "result": manifest["result"], "g0_a": "unproven"}))
        return 0 if manifest["result"] in ("pass", "observed") else 1

if __name__ == "__main__":
    sys.exit(main())
