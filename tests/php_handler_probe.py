#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
sys.path.insert(0, str(TOOLS))
import php_handler_probe as hp

# The swap brings in exactly the modules that conflict with mod_ruid2 and restores mod_ruid2 itself.
assert hp.RUID2 == "ea-apache24-mod_ruid2" and set(hp.SWAP_IN) == {"ea-apache24-mod_suexec", "ea-apache24-mod_suphp",
                                                                  "ea-apache24-mod_fcgid"}
assert hp.HANDLERS == ("suphp", "fcgi") and hp.RUID2 in hp.RECOVERY and "handler=cgi" in hp.RECOVERY
assert hp.VERSION == "ea-php82" and "olscpb" in hp.tf.CGI_TENANTS
result = subprocess.run([sys.executable, str(TOOLS / "php_handler_probe.py"), "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("PHP handler experiment constants and guard checks passed.")
