#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_ownership_probe as owner

apache = """LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=68590,fd=3),("httpd",pid=67229,fd=3))
LISTEN 0 511 [::]:443 [::]:* users:(("httpd",pid=68590,fd=6))"""
ols = """LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("litespeed",pid=6232,fd=15),("litespeed",pid=6225,fd=15))
LISTEN 0 511 *:443 *:* users:(("litespeed",pid=6231,fd=14))"""
mixed = ols + '\nLISTEN 0 511 [::]:80 [::]:* users:(("httpd",pid=1,fd=4))'
assert owner.owners(apache) == {"0.0.0.0:80": ["httpd"], "[::]:443": ["httpd"]}
assert owner.owned_by(apache, ["httpd"]) and not owner.owned_by(apache, ["litespeed"])
assert owner.owned_by(ols, ["litespeed", "openlitespeed", "lshttpd"])
assert not owner.owned_by(mixed, ["litespeed"]) and not owner.owned_by("", ["httpd"])
assert owner.MONITOR_LINE.startswith("service[olscpanel]=80,GET /olscpanel-health.txt HTTP/1.0\\r\\n")
assert "httpd" not in owner.MONITOR_LINE.split(",")[-1] and owner.MONITOR_LINE.endswith(owner.UNIT + "\n")
assert "enabled=1 monitored=1" in owner.RECOVERY and "restartsrv_httpd" in owner.RECOVERY
config = (owner.TEMPLATES / "ownership_httpd_config.conf").read_text()
for needle in ("autoDetectCdn                    0", "enableUpdateCheck                0", "CGIRLimit",
               "disableWebAdmin                  1", "enableScript         0"):
    assert needle in config, needle
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/ols_ownership_probe.py"), "--rpm", "/x"],
                        capture_output=True, text=True)
assert result.returncode == 2 and "--lab-empty-host" in result.stderr
print("OLS ownership listener-owner parsing, monitor, recovery and guard checks passed.")
