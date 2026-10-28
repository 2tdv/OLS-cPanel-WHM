#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_lab_cycle as cycle

ss = """tcp   LISTEN 0 511 0.0.0.0:80 0.0.0.0:*
tcp   LISTEN 0 511 127.0.0.1:8088 0.0.0.0:*
tcp   LISTEN 0 511 127.0.0.1:8088 0.0.0.0:*
udp   UNCONN 0 0   127.0.0.1:323 0.0.0.0:*"""
after = cycle.listener_set(ss)
assert after == {"tcp 0.0.0.0:80", "tcp 127.0.0.1:8088", "udp 127.0.0.1:323"}
before = {"tcp 0.0.0.0:80", "udp 127.0.0.1:323"}
assert cycle.new_listeners(before, after) == (["tcp 127.0.0.1:8088"], [])
assert cycle.new_listeners(before, after | {"tcp 0.0.0.0:7080"})[0] != [cycle.EXPECTED_NEW_LISTENER]
assert cycle.new_listeners(before | {"tcp 0.0.0.0:443"}, after)[1] == ["tcp 0.0.0.0:443"]

ps = """    PID    PPID USER     COMMAND
   6225       1 root     openlitespeed (lshttpd - main)
   6229    6225 nobody   openlitespeed (lshttpd - #01)
   6672    6665 nobody   lsphp
   7000       1 root     /bin/bash -c pgrep openlitespeed"""
rows = cycle.ols_processes(ps)
assert [r["pid"] for r in rows] == [6225, 6229, 6672] and rows[1]["user"] == "nobody"

good = {"sapi": "litespeed", "version": "8.3.36", "user": "nobody",
        "ini": "/opt/cpanel/ea-php83/root/etc/php.ini"}
assert cycle.php_probe(json.dumps(good))
for key, value in [("sapi", "cgi-fcgi"), ("version", "8.2.1"), ("user", "root"),
                   ("ini", "/usr/local/lsws/lsphp83/etc/php.ini")]:
    assert not cycle.php_probe(json.dumps(dict(good, **{key: value})))
try:
    cycle.php_probe("<html>503</html>")
    raise AssertionError("Non-JSON PHP response accepted")
except ValueError:
    pass

for name in ["httpd_config.conf", "admin_config.conf"]:
    text = (cycle.TEMPLATES / name).read_text()
    addresses = [line.split()[1] for line in text.splitlines() if line.strip().startswith("address")
                 and not line.split()[1].startswith("uds://")]
    assert addresses and all(a.startswith("127.0.0.1:") for a in addresses), (name, addresses)
config = (cycle.TEMPLATES / "httpd_config.conf").read_text()
assert "disableWebAdmin                  1" in config and "CGIRLimit" in config and "quicEnable           0" in config
unit = (cycle.TEMPLATES / cycle.UNIT).read_text()
assert "[Install]" not in unit and "SuccessExitStatus=255" in unit

script = str(ROOT / "build/vm-qualification/ols_lab_cycle.py")
result = subprocess.run([sys.executable, script, "--rpm", "/nonexistent"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-empty-host" in result.stderr
print("OLS lab-cycle listener, process, PHP-probe, template and guard checks passed.")
