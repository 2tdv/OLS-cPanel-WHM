#!/usr/bin/python3
"""Synthetic negative contracts; these do not establish cPanel/OLS compatibility."""
import copy
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("service_probe", ROOT / "build/vm-qualification/service_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

def record(text):
    return {"exit_code": 0, "stdout": text, "stderr": ""}
def api(command, data=None):
    value = {"metadata": {"result": 1, "command": command}}
    if data is not None:
        value["data"] = data
    return record(json.dumps(value))
base = {
    "accounts_api": api("listaccts"),
    "account_entries": record(""),
    "api_status": api("servicestatus", {"service": [{
        "name": "httpd", "running": 1, "enabled": 1, "installed": 1, "monitored": 1}]}),
    "native_status": record("running"),
    "syntax": record("Syntax OK"),
    "listeners": record('LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=123,fd=3))\n'
                        'LISTEN 0 511 [::]:443 [::]:* users:(("httpd",pid=123,fd=4))\n'),
    "hashes": record("".join("a" * 64 + "  " + path + "\n" for path in probe.COMMANDS["hashes"][1:])),
    "version": record("11.138.0.18\n"),
    "http": record("200"),
}
assert probe.validate_baseline(base)["empty_lab"]
assert probe.verdict(base, record(""), base, "native-graceful") == "pass"
assert probe.verdict(base, api("restartservice"), base, "whm-restart") == "pass"
cases = [
    ("account_entries", record("customer\n")),
    ("accounts_api", api("listaccts", {"acct": [{"user": "customer"}]})),
    ("accounts_api", record('{"metadata":{"result":0,"command":"listaccts"}}')),
    ("api_status", api("servicestatus", {"service": []})),
    ("listeners", record('LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("lshttpd",pid=123,fd=3))')),
    ("listeners", record("")),
    ("http", record("503")),
    ("version", record("11.140.0.1")),
    ("hashes", record("")),
    ("syntax", {"exit_code": 1, "stdout": "", "stderr": "invalid"}),
]
for key, value in cases:
    bad = copy.deepcopy(base)
    bad[key] = value
    try:
        probe.validate_baseline(bad)
        raise AssertionError("Accepted invalid baseline: " + key)
    except ValueError:
        pass
changed = copy.deepcopy(base)
changed["hashes"]["stdout"] = changed["hashes"]["stdout"].replace("a" * 64, "b" * 64)
for action, after, kind in [
    (record(""), changed, "native-graceful"),
    ({"exit_code": 1, "stdout": "", "stderr": ""}, base, "native-graceful"),
    (record('{"metadata":{"result":0,"command":"restartservice"}}'), base, "whm-restart"),
]:
    try:
        probe.verdict(base, action, after, kind)
        raise AssertionError("Accepted failed action or integrity drift")
    except ValueError:
        pass
print("16 native service-probe contract checks passed (synthetic).")

# Ensure omission of explicit lab acknowledgement fails before any privileged action.
import subprocess
import sys
import hashlib
import tempfile
for action in probe.ACTIONS:
    refused = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/service_probe.py"),
                              "--action", action], capture_output=True, text=True)
    assert refused.returncode == 2
spec = importlib.util.spec_from_file_location("verify_service", ROOT / "build/vm-qualification/verify_service.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
with tempfile.TemporaryDirectory(prefix="ols-service-evidence-") as directory:
    root = pathlib.Path(directory)
    values = {"before.json": base, "after.json": base, "action.json": record(""),
              "intent.json": {"action": "native-graceful"}}
    for name, value in values.items():
        (root / name).write_text(json.dumps(value))
    (root / "source.tar.gz").write_bytes(b"synthetic source fixture, not qualification")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
    manifest = {"kind": "native-apache-control-experiment", "g0_a": "unproven",
                "ols_adapter_tested": False, "action": "native-graceful", "result": "pass",
                "source_sha256": hashes["source.tar.gz"], "file_sha256": hashes}
    (root / "manifest.json").write_text(json.dumps(manifest))
    verifier.verify(root)
    for field, value in [("g0_a", "passed"), ("ols_adapter_tested", True),
                         ("source_sha256", "0"*64), ("result", "observed")]:
        changed = copy.deepcopy(manifest)
        changed[field] = value
        (root / "manifest.json").write_text(json.dumps(changed))
        try:
            verifier.verify(root)
            raise AssertionError("False evidence accepted: " + field)
        except ValueError:
            pass
    (root / "manifest.json").write_text(json.dumps(manifest))
    for name in hashes:
        original = (root / name).read_bytes()
        (root / name).write_bytes(original + b"tampered")
        try:
            verifier.verify(root)
            raise AssertionError("Tampering accepted: " + name)
        except ValueError:
            pass
        (root / name).write_bytes(original)
print("Lab acknowledgement and service-evidence tamper/refusal checks passed.")
