#!/usr/bin/python3
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import disable_probe as probe

def status(**overrides):
    row = {"name": "httpd", "installed": 1, "enabled": 0, "monitored": 0, "running": 0}
    row.update(overrides)
    return {"exit_code": 0, "stdout": json.dumps({
        "metadata": {"command": "servicestatus", "result": 1}, "data": {"service": [row]}})}
ports = {"exit_code": 0, "stdout": ""}
absent = {"exit_code": 1, "stdout": ""}
assert probe.disabled_observation(status(), ports, absent)["disabled_and_stopped"]
for changed in (status(enabled=1), status(monitored=1), status(running=1)):
    assert not probe.disabled_observation(changed, ports, absent)["disabled_and_stopped"]
assert not probe.disabled_observation(status(), {"exit_code": 0, "stdout": "listener"}, absent)["disabled_and_stopped"]
for changed, sockets in [(status(running=None), ports), (status(enabled="0"), ports),
                         (status(), {"exit_code": 1, "stdout": ""})]:
    try:
        probe.disabled_observation(changed, sockets, absent)
        raise AssertionError("Unknown state accepted")
    except ValueError:
        pass
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/disable_probe.py")],
                        capture_output=True, text=True)
assert result.returncode == 2
assert "restartsrv_httpd" in probe.RECOVERY and "configureservice" in probe.RECOVERY
print("Disabled-service semantics and explicit-lab guard checks passed.")

missing = status()
payload = json.loads(missing["stdout"])
del payload["data"]["service"][0]["running"]
missing["stdout"] = json.dumps(payload)
observed = probe.disabled_observation(missing, ports, absent)
assert observed["running"] is None and observed["disabled_and_stopped"]
assert not probe.disabled_observation(missing, ports, {"exit_code": 0, "stdout": "123\n"})["disabled_and_stopped"]
try:
    probe.disabled_observation(missing, ports, {"exit_code": 2, "stdout": ""})
    raise AssertionError("Failed process observation accepted")
except ValueError:
    pass
print("Omitted running field requires independent process and listener evidence.")
