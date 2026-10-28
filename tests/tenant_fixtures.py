#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import tenant_fixtures as tf

assert tf.leaked("symlink-other-static", "static olscpb abc\n", "olscpb")
assert tf.leaked("symlink-other-secret", "secret olscpb abc\n", "olscpb")
assert not tf.leaked("symlink-other-static", "<html>403 Forbidden</html>", "olscpb")
assert not tf.leaked("own-static", "static olscpa abc\n", "olscpb")
assert tf.leaked("php-read-other-secret", json.dumps({"readable": True}), "olscpb")
assert not tf.leaked("php-read-other-secret", json.dumps({"readable": False}), "olscpb")
assert not tf.leaked("php-read-other-static", "<html>500</html>", "olscpb")
items = tf.fixture_commands("olscpa", "olscpb", "n0nce")
writes = {i[1]: i for i in items if i[0] == "write"}
assert writes["/home/olscpa/secret.txt"][3] == "0600" and "n0nce" in writes["/home/olscpa/secret.txt"][2]
assert "$other = 'olscpb';" in writes["/home/olscpa/public_html/read.php"][2]
links = {i[1]: i[2] for i in items if i[0] == "symlink"}
assert links["/home/olscpa/public_html/link-other-secret.txt"] == "/home/olscpb/secret.txt"
# Only reserved .test names or the owner's lab subdomains (DNS pointed at the lab server by the owner).
assert set(tf.TENANTS) == {"olscpa", "olscpb"} and all(d.endswith((".test", ".example.test")) for d in tf.TENANTS.values())
ok = {u + ":own-static": {"status": "200", "body": "static " + u + " n"} for u in tf.TENANTS}
ok.update({u + ":own-php": {"status": "200", "body": json.dumps({"user": u, "sapi": "cgi-fcgi"})} for u in tf.TENANTS})
assert tf.valid_observation(ok)
bad = dict(ok); bad["olscpa:own-static"] = {"status": "404", "body": "<html>"}
assert not tf.valid_observation(bad)
bad = dict(ok); bad["olscpb:own-php"] = {"status": "200", "body": "<?php echo 1;"}
assert not tf.valid_observation(bad)
ops = tf.scenario_operations()
assert ops[0][0] == "whmapi" and [o[0] for o in ops].index("append") > [o[0] for o in ops].index("uapi")
assert any(o[0] == "append" and o[2].endswith("olscpb/public_html/.htaccess") and "RewriteRule . /index.php" in o[3] for o in ops)
assert any(o[0] == "write" and o[2].endswith("uploads/.htaccess") and "Deny from all" in o[3] for o in ops)
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/tenant_fixtures.py"), "--create"],
                        capture_output=True, text=True)
assert result.returncode == 2 and "--lab-empty-host" in result.stderr
print("Tenant fixture leak classification, fixture layout and guard checks passed.")
