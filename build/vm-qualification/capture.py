#!/usr/bin/python3
"""Capture a private platform baseline. No service or host configuration changes."""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("snapshot", ROOT / "build/package/snapshot.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
os.umask(0o077)
now = lambda: datetime.now(timezone.utc).isoformat()
started = now()
source = snapshot.archive()
result = subprocess.run(
    ["/usr/local/cpanel/3rdparty/php/84/bin/php", "-n", str(ROOT / "bin/ols-cpanel"),
     "doctor", "--read-only", "--format=json"],
    capture_output=True, text=True, timeout=45, check=False)
if result.returncode != 2:
    raise SystemExit("Doctor failed; no evidence accepted")
report = json.loads(result.stdout)
if report["synthetic"] or report["compatibility"]["production_activation_allowed"]:
    raise SystemExit("Invalid audit report")
if snapshot.archive() != source:
    raise SystemExit("Source changed during capture; retry")
run = ROOT / "evidence/local" / str(uuid.uuid4())
run.mkdir(parents=True, mode=0o700)
(run / "doctor.json").write_text(result.stdout)
(run / "source.tar.gz").write_bytes(source)
manifest = {
    "schema_version": 1, "kind": "platform-observation", "started_at": started, "finished_at": now(),
    "source_sha256": hashlib.sha256(source).hexdigest(),
    "report_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
    "expected": "read-only baseline; unsupported platform; no certification",
    "actual": {"exit_code": result.returncode, "observation_complete": report["observation_complete"]},
    "reviewer": None, "gates_passed": [], "scope": "platform-baseline-only",
}
(run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(run)
