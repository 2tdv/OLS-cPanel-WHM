#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_reboot_probe as rb

observed_text = """boot_id=new-boot
ols_active=active
ols_enabled=enabled
httpd_active=inactive
chkservd_httpd=httpd:0
chkservd_olscpanel=olscpanel:1
http_body=ols-owner abc
https_body=ols-owner abc
nonce=abc
listeners<<
LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("litespeed",pid=1,fd=3))
LISTEN 0 511 *:443 *:* users:(("litespeed",pid=1,fd=4))
>>
"""
obs = rb.parse_observed(observed_text)
assert obs["boot_id"] == "new-boot" and len(obs["listeners"]) == 2
assert all(rb.evaluate(obs, "old-boot").values())
assert not rb.evaluate(obs, "new-boot")["rebooted"]
for key, value, check in [("httpd_active", "active", "apache_stayed_down"), ("ols_enabled", "disabled", "ols_started_at_boot"),
                          ("http_body", "", "served_after_boot"), ("chkservd_olscpanel", "", "monitor_present")]:
    assert not rb.evaluate(dict(obs, **{key: value}), "old-boot")[check], key
mixed = dict(obs, listeners=obs["listeners"] + ['LISTEN 0 511 [::]:80 [::]:* users:(("httpd",pid=2,fd=4))'])
assert not rb.evaluate(mixed, "old-boot")["ols_owns_ports"]
assert "enabled=1 monitored=1" in rb.RESTORE and "rpm -e ols-cpanel-openlitespeed" in rb.RESTORE
assert "ConditionPathExists=!" in rb.FALLBACK_SERVICE and "OnBootSec=15min" in rb.FALLBACK_TIMER
assert rb.VERIFY.rstrip().endswith('echo done >"$S/verified"') and '/bin/sh "$S/restore.sh"' in rb.VERIFY
for argv in (["--arm"], ["--arm", "--lab-empty-host"], ["--collect"]):
    result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/ols_reboot_probe.py"), *argv],
                            capture_output=True, text=True)
    assert result.returncode == 2, argv
print("OLS reboot experiment parsing, evaluation, recovery and guard checks passed.")
