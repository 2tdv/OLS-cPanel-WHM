#!/usr/bin/python3
import hashlib
import importlib.util
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
snapshot = module("snapshot", "build/package/snapshot.py")
verifier = module("verifier", "build/vm-qualification/verify.py")
first = snapshot.archive()
assert first == snapshot.archive(), "Source archives must be deterministic"
assert all(not name.startswith(("evidence/", ".git/")) for name, _ in snapshot.entries())
with tempfile.TemporaryDirectory(prefix="ols-evidence-test-") as directory:
    root = pathlib.Path(directory)
    data = json.dumps({"synthetic": False, "mode": "audit-only", "observation_complete": True,
        "compatibility": {"production_activation_allowed": False, "supported": False}}).encode()
    manifest = {"kind": "platform-observation", "gates_passed": [],
        "report_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": hashlib.sha256(first).hexdigest(),
        "actual": {"exit_code": 2, "observation_complete": True}}
    (root / "source.tar.gz").write_bytes(first)
    (root / "doctor.json").write_bytes(data)
    (root / "manifest.json").write_text(json.dumps(manifest))
    verifier.verify(root)
    for file in ("doctor.json", "source.tar.gz", "manifest.json"):
        original = (root / file).read_bytes()
        (root / file).write_bytes(original + b"tampered")
        try:
            verifier.verify(root)
            raise AssertionError("Tampering accepted: " + file)
        except (ValueError, KeyError):
            pass
        (root / file).write_bytes(original)
    manifest["gates_passed"] = ["G0-A"]
    (root / "manifest.json").write_text(json.dumps(manifest))
    try:
        verifier.verify(root)
        raise AssertionError("Fabricated gate accepted")
    except ValueError:
        pass
print("Archive reproducibility and evidence tamper/refusal checks passed.")
