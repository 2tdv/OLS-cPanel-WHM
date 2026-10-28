#!/usr/bin/python3
"""Verify local native-Apache experiment integrity and semantics, never G0 certification."""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("service_probe", ROOT / "build/vm-qualification/service_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

def verify(directory):
    directory = pathlib.Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    action = manifest["action"]
    if manifest["kind"] != "native-apache-control-experiment" or manifest["g0_a"] != "unproven":
        raise ValueError("Wrong evidence type or invalid G0 claim")
    if manifest["ols_adapter_tested"] is not False:
        raise ValueError("Native baseline cannot establish an OLS adapter")
    if action not in ("observe", *probe.ACTIONS):
        raise ValueError("Unknown experiment action")
    required = {"source.tar.gz", "before.json"}
    if action != "observe":
        required.update({"intent.json", "action.json", "after.json"})
    if set(manifest["file_sha256"]) != required:
        raise ValueError("Missing or unexpected evidence files")
    for name, digest in manifest["file_sha256"].items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Evidence integrity mismatch")
    if manifest["source_sha256"] != manifest["file_sha256"]["source.tar.gz"]:
        raise ValueError("Source digest mismatch")
    before = json.loads((directory / "before.json").read_text())
    probe.validate_baseline(before)
    if action == "observe":
        if manifest["result"] != "observed":
            raise ValueError("Wrong observation result")
    else:
        intent = json.loads((directory / "intent.json").read_text())
        if intent["action"] != action:
            raise ValueError("Intent/action mismatch")
        result = probe.verdict(before, json.loads((directory / "action.json").read_text()),
                               json.loads((directory / "after.json").read_text()), action)
        if manifest["result"] != result:
            raise ValueError("Manifest/result mismatch")
    return manifest

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: verify_service.py EVIDENCE_DIRECTORY")
    try:
        verify(sys.argv[1])
    except (KeyError, OSError, ValueError, TypeError) as exc:
        raise SystemExit("Evidence rejected: " + str(exc))
    print("Native Apache experiment verified; OLS integration and G0-A remain unproven.")
