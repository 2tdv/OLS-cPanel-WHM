#!/usr/bin/python3 -I
"""Lab-only cPanel hook observer (G0-F). Installed root-owned by cpanel_hook_probe.py and registered
for candidate events; cPanel passes {"hook", "context", "data"} as JSON on stdin.
Records which event fired, its stage, the effective user and the data key names, plus the values
of identity fields (user, domains, PHP version) only; secrets are never written. Answers "1"
(continue), or "0" for a pre-stage event whose data names the lab block marker, so the probe can
measure which events can veto an operation. Success is exactly "1" without a newline: cPanel parses
"1\n" into an empty but defined message, and scripts/suspendacct treats any message as a failure."""
import json
import os
import re
import sys
import time

LOG = "/var/log/ols-cpanel-lab-hooks.jsonl"
BLOCK_MARKER = "olscp-block"
SECRET = re.compile(r"pass|pw|key|cert|crt|token|secret|hash|cookie|session", re.I)
IDENTITY = re.compile(r"^(user|username|owner|domain|newdomain|rootdomain|subdomain|sub|vhost|servername|"
                      r"version|dir|dirname|homedir|docroot|documentroot|package|plan|reason|vhosts)$", re.I)

def identity(data):
    out = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if SECRET.search(str(key)):
                continue
            if IDENTITY.match(str(key)) and isinstance(value, (str, int, list)):
                out[key] = value if not isinstance(value, list) else [v for v in value if isinstance(v, (str, int))][:10]
    return out

def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    context = payload.get("context") or {}
    if not context:
        return  # registry maintenance (e.g. manage_hooks del) runs the script without an event
    data = payload.get("data")
    args = data.get("args") if isinstance(data, dict) and isinstance(data.get("args"), dict) else None
    record = {"time": time.time(), "category": context.get("category"), "event": context.get("event"),
              "stage": context.get("stage"), "euid": os.geteuid(), "context_user": context.get("user"),
              "context_blocking": context.get("blocking"), "escalateprivs": context.get("escalateprivs"),
              "data_type": type(data).__name__,
              "data_keys": sorted(str(k) for k in data)[:60] if isinstance(data, dict) else None,
              "identity": identity(data), "args_identity": identity(args) if args else None}
    try:
        fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    except OSError as exc:
        record["log_error"] = str(exc)
        sys.stderr.write("ols-cpanel lab observer could not log: " + str(exc) + "\n")
    blocked = str(context.get("stage", "")).startswith("pre") and BLOCK_MARKER in json.dumps(data, default=str)
    sys.stdout.write("0 blocked by the OLS-cPanel lab observer\n" if blocked else "1")

if __name__ == "__main__":
    main()
