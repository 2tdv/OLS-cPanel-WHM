#!/usr/bin/python3
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/review"))
import show_evidence as se

with tempfile.TemporaryDirectory() as temp:
    se.EVIDENCE = pathlib.Path(temp)
    run = se.EVIDENCE / "plugins-test"
    run.mkdir()
    (run / "001-step.json").write_text("{}")
    manifest = {"kind": "plugin-experiment", "result": "observed", "cases": {"a": {"pass": True}, "b": {"pass": False}},
                "surface": {"x": {"match": True, "baseline_ok": True}, "y": {"match": False, "baseline_ok": True, "lab_limited": "lab-port80"}},
                "passes": {"native": {"valid": True, "leaks": ["olscpa:php-read-other-static"]}},
                "file_sha256": {"001-step.json": hashlib.sha256(b"{}").hexdigest()}}
    (run / "manifest.json").write_text(json.dumps(manifest))
    import io, contextlib
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        se.summary("plugins-test", True)
    text = out.getvalue()
    assert "Cases: 1 of 2 passed" in text and "[FAIL] b" in text
    assert "surface: 1 of 2 equal to Apache" in text and "[DIFF] y (lab limitation)" in text
    assert "leaks=['olscpa:php-read-other-static']" in text and "File hashes: 1 of 1 match" in text
    (run / "001-step.json").write_text('{"tampered": 1}')
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        se.summary("plugins-test", True)
    assert "MISMATCH: ['001-step.json']" in out.getvalue()
print("Evidence summary helper checks passed.")
