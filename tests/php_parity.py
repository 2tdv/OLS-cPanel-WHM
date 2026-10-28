#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification/php-parity"))
import compare

base = {"sapi": "cgi-fcgi", "version": "8.2.35", "user": "nobody", "extensions": ["Core", "date"],
        "ini": {"memory_limit": "128M", "cgi.fix_pathinfo": "1"}, "server": {"DOCUMENT_ROOT": "/var/www/html",
        "GATEWAY_INTERFACE": "CGI/1.1"}}
same = dict(base, sapi="litespeed", ini={"memory_limit": "128M"}, server={"DOCUMENT_ROOT": "/var/www/html"})
report = compare.compare(base, same)
assert report["equivalent"]
assert {d["field"] for d in report["differences"]} == {"sapi", "ini.cgi.fix_pathinfo", "server.GATEWAY_INTERFACE"}
for changed in (dict(same, user="root"), dict(same, ini={"memory_limit": "256M"}),
                dict(same, extensions=["Core"]), dict(same, server={"DOCUMENT_ROOT": "/tmp"}),
                dict(same, version="8.3.36")):
    assert not compare.compare(base, changed)["equivalent"], changed
sapi_ext = dict(base, extensions=["Core", "cgi-fcgi", "date"])
assert compare.compare(sapi_ext, dict(same, extensions=["Core", "date", "litespeed"]))["equivalent"]
port = dict(base, server={"DOCUMENT_ROOT": "/var/www/html", "SERVER_PORT": "80"})
moved = dict(same, server={"DOCUMENT_ROOT": "/var/www/html", "SERVER_PORT": "8088"})
assert compare.compare(port, moved, test_binding={"SERVER_PORT": "8088"})["equivalent"]
assert not compare.compare(port, moved)["equivalent"]
assert not compare.compare(port, dict(moved, server={"DOCUMENT_ROOT": "/var/www/html", "SERVER_PORT": "81"}),
                           test_binding={"SERVER_PORT": "8088"})["equivalent"]
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/php_parity_probe.py"), "--rpm", "/x"],
                        capture_output=True, text=True)
assert result.returncode == 2 and "--lab-empty-host" in result.stderr
config = (ROOT / "build/vm-qualification/php-parity/httpd_config.conf").read_text()
assert "127.0.0.1:8088" in config and "*:80" not in config and "ea-php83" not in config
print("PHP parity comparator classification and guard checks passed.")

# suPHP reports a "." scan directory as "./name"; those are the same files under the script's cwd.
_ref = {"cwd": "/home/u/public_html", "ini_loaded": "/home/u/public_html/php.ini",
        "ini_scanned": ["/opt/cpanel/ea-php82/root/etc/php.ini", "./.user.ini", "./php.ini"], "ini": {}, "server": {}}
_cand = dict(_ref, ini_scanned=["/opt/cpanel/ea-php82/root/etc/php.ini", "/home/u/public_html/.user.ini",
                                "/home/u/public_html/php.ini"])
assert compare.compare(_ref, _cand)["equivalent"]
assert not compare.compare(_ref, dict(_cand, ini_loaded="/opt/cpanel/ea-php82/root/etc/php.ini"))["equivalent"]
print("Relative scan-directory paths are normalized.")
assert compare.compare(_ref, dict(_cand, ini_loaded="/opt/cpanel/ea-php82/root/etc/php.ini"), expected_fields=("ini_loaded",))["equivalent"]
