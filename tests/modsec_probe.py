#!/usr/bin/python3
"""Offline checks of the FV-02 lab experiment (build/vm-qualification/modsec_probe.py): guards, corpus,
declared outcomes on synthetic summaries, the recovery script, and that it compiles through the product
security input. The experiment itself only runs on the lab server."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
sys.path.insert(0, str(TOOLS))
import modsec_probe as mp
import modsec_translate as mt

# Guards: --lab-tenants is required (argparse exits 2 before anything runs).
result = subprocess.run([sys.executable, str(TOOLS / "modsec_probe.py"), "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr, result.stderr
source = (TOOLS / "modsec_probe.py").read_text()
for required in ("service-probe.lock", "fcntl.LOCK_EX | fcntl.LOCK_NB", "systemd-run", "--on-active=60min", "plugin preview",
                 "durable_json", "manifest.json", "disarm-recovery", "security=security", "parse_audit_log"):
    assert required in source, required
assert set(mp.PREVIEW) == {"/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel", "/usr/local/cpanel/base/frontend/jupiter/ols_cpanel",
                           "/usr/local/ols-cpanel"}
# Every cPanel file the experiment can change is guarded and restored.
for path in (mp.DATASTORE, mt.CPANEL_CONF, mt.USER_CONF, "/var/cpanel/userdata/olscpb/olstest2.example.test"):
    assert path in mp.GUARDED, path
script = mp.recovery_script("/run/x", True)
assert script.startswith("#!/bin/sh\n") and script.count("/run/x/backup/") == 2 * len(mp.GUARDED) and "dnf -y remove" in script
assert "rebuildhttpdconf" in script and "restartsrv_httpd" in script and "dnf" not in mp.recovery_script("/run/x", False)
# Corpus: malicious and benign requests, unique names, Apache baselines declared.
names = [c[0] for c in mp.CORPUS]
assert len(names) == len(set(names)) and {c[4] for c in mp.CORPUS} == {"block", "allow"}
assert sum(c[4] == "block" for c in mp.CORPUS) >= 5 and sum(c[4] == "allow" for c in mp.CORPUS) >= 3
assert [mp.verdict(s) for s in ("403", "406", "200", "404", "000", "")] == ["block", "block", "allow", "allow", "error", "error"]

def passing():
    corpus = {c[0]: {"apache": {"status": "403" if c[4] == "block" else "200", "verdict": c[4]},
                     "ols": {"status": "403" if c[4] == "block" else "200", "verdict": c[4]}, "expected": c[4], "path": c[2]}
              for c in mp.CORPUS}
    return {"corpus": corpus, "domain_disable": {"a": {"apache": "block", "ols": "block"}, "b": {"apache": "allow", "ols": "allow"}},
            "audit": {"blocked": [c[2] for c in mp.CORPUS if c[4] == "block"], "missing": []},
            "limits": {"throttled_seconds": 3.4, "throttled_ok": 20, "over_hard_limit": "000", "after_ban": "200",
                       "trusted_seconds": 0.2, "trusted_ok": 20, "blocked_external": "000", "blocked_loopback": "200"},
            "ols_log_errors": [], "restored": True, "removed": True}

assert all(mp.expected_outcomes(passing()).values()), mp.expected_outcomes(passing())
failures = {
    "same-verdicts-as-apache": lambda s: s["corpus"]["xss-query"]["ols"].update(status="200", verdict="allow"),
    "apache-baseline": lambda s: [s["corpus"]["sqli-query"][k].update(status="200", verdict="allow") for k in ("apache", "ols")],
    "audit-records-parsed": lambda s: s["audit"].update(missing=["/static.txt"]),
    "per-domain-disable-honoured": lambda s: s["domain_disable"]["b"].update(ols="block"),
    "rate-limit-throttles": lambda s: s["limits"].update(throttled_seconds=0.3),
    "hard-limit-bans": lambda s: s["limits"].update(over_hard_limit="200"),
    "trusted-client-exempt": lambda s: s["limits"].update(trusted_seconds=3.5),
    "block-list-refuses": lambda s: s["limits"].update(blocked_loopback="000"),
    "no-ols-errors": lambda s: s.update(ols_log_errors=["[Module:mod_security]setSecRule(type 2) x failed"]),
    "host-restored": lambda s: s.update(restored=False),
}
for case, mutate in failures.items():
    summary = passing()
    mutate(summary)
    outcome = mp.expected_outcomes(summary)
    assert not outcome[case] and all(v for k, v in outcome.items() if k != case), (case, outcome)
assert not any(mp.expected_outcomes({}).values()), "an empty run proves nothing"
# A listed difference may never turn an Apache block into an OLS allow.
mp.KNOWN_DIFFERENCES["xss-query"] = "test"
summary = passing()
summary["corpus"]["xss-query"]["ols"].update(status="406", verdict="block")
assert mp.expected_outcomes(summary)["same-verdicts-as-apache"]
summary["corpus"]["xss-query"]["ols"].update(status="200", verdict="allow")
assert not mp.expected_outcomes(summary)["same-verdicts-as-apache"]
mp.KNOWN_DIFFERENCES.clear()
print("ModSecurity experiment constants, guards, declared outcomes and recovery checks passed.")
