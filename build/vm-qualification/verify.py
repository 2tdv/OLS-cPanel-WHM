#!/usr/bin/python3
"""Validate baseline evidence integrity. Never certifies a platform."""
import hashlib
import json
import pathlib
import sys

def verify(path):
    path = pathlib.Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    report_data = (path / "doctor.json").read_bytes()
    source_data = (path / "source.tar.gz").read_bytes()
    if manifest["kind"] != "platform-observation" or manifest["gates_passed"] != []:
        raise ValueError("Baseline cannot certify gates")
    if hashlib.sha256(report_data).hexdigest() != manifest["report_sha256"]:
        raise ValueError("Report digest mismatch")
    if hashlib.sha256(source_data).hexdigest() != manifest["source_sha256"]:
        raise ValueError("Source digest mismatch")
    report = json.loads(report_data)
    if report["synthetic"] or report["mode"] != "audit-only":
        raise ValueError("Not a live audit observation")
    if report["compatibility"]["production_activation_allowed"] or report["compatibility"]["supported"]:
        raise ValueError("Invalid certification claim")
    if manifest["actual"]["exit_code"] != 2:
        raise ValueError("Unexpected doctor exit")
    if manifest["actual"]["observation_complete"] != report["observation_complete"]:
        raise ValueError("Completeness mismatch")
    return manifest

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: verify.py EVIDENCE_DIRECTORY")
    try:
        verify(sys.argv[1])
    except (KeyError, OSError, ValueError) as exc:
        raise SystemExit("Evidence rejected: " + str(exc))
    print("Baseline integrity verified; G0 gates remain unproven.")
