#!/usr/bin/python3
"""Recompute the limited disabled-Apache experiment from local transcripts."""
import hashlib
import json
import pathlib
import re
import sys

import disable_probe as disabled
import service_probe as native

def verify(directory):
    root = pathlib.Path(directory)
    manifest = json.loads((root / "manifest.json").read_text())
    if (manifest["kind"] != "disabled-apache-experiment" or manifest["result"] != "observed"
        or manifest["g0_a"] != "unproven" or manifest["ols_adapter_tested"] is not False
        or manifest["recovery_verified"] is not True or manifest["recovery_timer_disarmed"] is not True):
        raise ValueError("Not a completed, restored native experiment")
    hashes = manifest["file_sha256"]
    if not {"source.tar.gz", "intent.json"}.issubset(hashes):
        raise ValueError("Missing source or intent")
    for name, digest in hashes.items():
        if name not in ("source.tar.gz", "intent.json") and not re.fullmatch(r"[0-9]{2}-[a-z_\-]+\.json", name):
            raise ValueError("Unexpected evidence path")
        path = root / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Evidence digest mismatch")
    if hashes["source.tar.gz"] != manifest["source_sha256"]:
        raise ValueError("Source digest mismatch")
    def record(label):
        matches = [name for name in hashes if re.fullmatch(r"[0-9]{2}-" + re.escape(label) + r"\.json", name)]
        if len(matches) != 1:
            raise ValueError("Missing or duplicated required record")
        return json.loads((root / matches[0]).read_text())
    before = {key: record("before-" + key) for key in native.COMMANDS}
    after = {key: record("after-" + key) for key in native.COMMANDS}
    native.validate_baseline(before)
    native.validate_baseline(after)
    if before["hashes"]["stdout"] != after["hashes"]["stdout"]:
        raise ValueError("Vendor/configuration changed")
    intent = json.loads((root / "intent.json").read_text())
    if (intent["restore"] != {"enabled": 1, "monitored": 1, "running": 1}
        or intent["recovery_unit"] != manifest["recovery_unit"]):
        raise ValueError("Recovery intent mismatch")
    for label in ("arm-recovery", "check-timer", "restore-restart", "disarm-recovery"):
        if record(label)["exit_code"] != 0:
            raise ValueError("Failed recovery step")
    native.api(record("disable"), "configureservice")
    native.api(record("restore-enable"), "configureservice")
    for label, field in (("disabled", "after_disable"), ("after-native", "after_native_restart"),
                         ("after-whm", "after_whm_restart")):
        result = disabled.disabled_observation(record(label + "-status"),
            record(label + "-ports"), record(label + "-processes"))
        if result != manifest[field]:
            raise ValueError("Observed state differs from summary")
    if manifest["native_restart_exit"] != record("native-restart")["exit_code"]:
        raise ValueError("Native exit mismatch")
    whm = record("whm-restart")
    data = json.loads(whm["stdout"])
    if (data["metadata"]["command"] != "restartservice"
        or manifest["whm_restart_exit"] != whm["exit_code"]
        or manifest["whm_restart_api_result"] != data["metadata"]["result"]):
        raise ValueError("WHM result mismatch")
    return manifest

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: verify_disable.py EVIDENCE_DIRECTORY")
    try:
        verify(sys.argv[1])
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise SystemExit("Evidence rejected: " + str(exc))
    print("Disable experiment and recovery verified; G0-A remains unproven.")
