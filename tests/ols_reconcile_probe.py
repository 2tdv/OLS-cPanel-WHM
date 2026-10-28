#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
sys.path.insert(0, str(TOOLS))
import ols_reconcile_probe as rp

events = {e for _, e, _ in rp.HOOKS}
assert {"Accounts::suspendacct", "Accounts::unsuspendacct", "UAPI::SSL::install_ssl", "AutoSSL::installssl",
        "Api2::SubDomain::delsubdomain"} <= events
good = {"scenarios": {"suspend": {"seconds_from_action": 20, "ols_seconds": 15, "comparison": {"/x": {"match": True}}},
                      "unsuspend": {"seconds_from_action": 30}, "install_ssl": {"seconds_from_action": 40, "ols_seconds": 30},
                      "add_subdomain": {"seconds_from_action": 50, "ols_seconds": 40},
                      "delete_subdomain": {"seconds_from_action": 50, "ols_seconds": 40},
                      "htaccess_edit": {"seconds_from_action": 90, "ols_seconds": 80}},
        "restored": {"removed": True}}
assert all(rp.expected_outcomes(good).values()), rp.expected_outcomes(good)
slow = {**good, "scenarios": {**good["scenarios"], "suspend": {**good["scenarios"]["suspend"], "seconds_from_action": 301}}}
assert not rp.expected_outcomes(slow)["suspension-within-300s"]
missing = {**good, "scenarios": {**good["scenarios"], "install_ssl": {"seconds_from_action": 360, "ols_seconds": None}}}
assert not rp.expected_outcomes(missing)["certificate-install-served"]
result = subprocess.run([sys.executable, str(TOOLS / "ols_reconcile_probe.py"), "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("Event reconcile experiment outcomes and guard checks passed.")
