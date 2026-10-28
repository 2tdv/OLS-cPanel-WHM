#!/usr/bin/python3
"""Plain summary of one lab evidence run for human reviewers (read-only).

Usage:
  python3 build/review/show_evidence.py                   list all runs, newest first
  python3 build/review/show_evidence.py <run-id>          summary of one run
  python3 build/review/show_evidence.py <run-id> --check  also re-check every file hash
<run-id> is a directory name under evidence/local (e.g. plugins-2ac71aa5e9dc4e2a8ddb22173f074277).
Nothing on the server is changed."""
import hashlib
import json
import pathlib
import sys

EVIDENCE = pathlib.Path(__file__).resolve().parents[2] / "evidence/local"

def short(value, limit=160):
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + " …"

def list_runs():
    runs = sorted((p for p in EVIDENCE.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
    print(f"{'run-id':58} {'result':12} started")
    for run in runs:
        manifest = run / "manifest.json"
        data = json.loads(manifest.read_text()) if manifest.is_file() else {}
        print(f"{run.name:58} {str(data.get('result', '(no manifest)')):12} {data.get('started_at', '')}")

def summary(run_id, check):
    run = EVIDENCE / run_id
    manifest = run / "manifest.json"
    if not manifest.is_file():
        sys.exit(f"no manifest.json in {run}")
    data = json.loads(manifest.read_text())
    print(f"Run:      {run_id}")
    print(f"Kind:     {data.get('kind')}")
    print(f"Result:   {data.get('result')}   (\"observed\" = finished without error; read the cases below)")
    print(f"Started:  {data.get('started_at')}   Finished: {data.get('finished_at')}")
    if data.get("error"):
        print(f"ERROR:    {data['error']}")
    cases = data.get("cases")
    if isinstance(cases, dict) and cases:
        passed = sum(1 for c in cases.values() if c.get("pass"))
        print(f"\nCases: {passed} of {len(cases)} passed")
        for name, case in cases.items():
            print(f"  [{'PASS' if case.get('pass') else 'FAIL'}] {name}")
    for section in ("surface", "surface_tls", "multi_domain", "comparison", "comparison_v6", "comparison_v6_dedicated", "access_control", "rewrite", "compat"):
        block = data.get(section)
        if isinstance(block, dict) and block:
            good = [k for k, v in block.items() if isinstance(v, dict) and v.get("match") is not False
                    and v.get("baseline_ok", True) is not False]
            bad = [k for k in block if k not in good]
            print(f"\n{section}: {len(good)} of {len(block)} equal to Apache")
            for key in bad:
                note = " (lab limitation)" if block[key].get("lab_limited") else ""
                print(f"  [DIFF] {key}{note}")
    passes = data.get("passes")
    if isinstance(passes, dict):
        for name, value in passes.items():
            if isinstance(value, dict) and "leaks" in value:
                print(f"\nisolation pass {name}: valid={value.get('valid')} leaks={value.get('leaks')}")
    for key in ("restored", "removed", "hooks_restored", "accounts_after", "bandwidth", "log_routing",
                "websocket_proxy", "fifo_tenant_write", "tls_match", "tls_match_v6", "ws_session_match"):
        if key in data:
            print(f"{key}: {short(data[key])}")
    if check:
        hashes = data.get("file_sha256") or {}
        bad = [name for name, digest in hashes.items()
               if not (run / name).is_file() or hashlib.sha256((run / name).read_bytes()).hexdigest() != digest]
        print(f"\nFile hashes: {len(hashes) - len(bad)} of {len(hashes)} match" + (f"; MISMATCH: {bad}" if bad else ""))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        list_runs()
    else:
        summary(sys.argv[1], "--check" in sys.argv[2:])
