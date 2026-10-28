#!/usr/bin/python3
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
gateway = (ROOT / "plugins/whm/index.cgi").read_text()
# Identity only from cpsrvd's REMOTE_USER; root only; the contract's API names and job actions, nothing else.
assert "getenv('REMOTE_USER')" in gateway and "const ALLOWED_PRINCIPALS = ['root'];" in gateway
code = "\n".join(line for line in gateway.splitlines() if not line.lstrip().startswith("//"))
# Request input: the method, the action header, the body length and php://input; never cookies or other headers.
assert not re.search(r"HTTP_(?!X_OLS_CPANEL_REQUEST)|\$_COOKIE|\$_POST|\$_REQUEST|\$_SERVER\['(?!REQUEST_METHOD|HTTP_X_OLS_CPANEL_REQUEST|CONTENT_LENGTH)", code)
assert "($_SERVER['HTTP_X_OLS_CPANEL_REQUEST'] ?? null) !== '1'" in gateway and "BODY_LIMIT = 4096" in gateway
contract = (ROOT / "docs/product-interfaces.md").read_text()
names = re.search(r"GET \?api=<name>` for the read operations \(names: ([^)]*)\)", contract.replace("\n", " ")).group(1)
api = dict(re.findall(r"'(\w+)' => \['([a-z_.]+)', \[", gateway.split("const API = [", 1)[1].split("];", 1)[0]))
assert sorted(api) == sorted(re.findall(r"`(\w+)`", names)), (api, names)
actions = re.findall(r"'(ols\.[a-z_]+)' => '(server|plan|cache|php_restart|opcache)'", gateway)
jobs = (ROOT / "broker/src/panel/jobs.rs").read_text()
assert sorted(a for a, _ in actions) == sorted(re.findall(r'Action \{ name: "(ols\.[a-z_]+)"', jobs)), actions
assert [a for a, s in actions if s == "plan"] == ["ols.cutover"]
assert "'cap.issue'" in gateway and "'cap.execute'" in gateway and "$principal" in gateway.split("'cap.issue'", 1)[0]
assert "catch (Throwable)" in gateway and "Cache-Control: no-store" in gateway and "X-Content-Type-Options: nosniff" in gateway
page = (ROOT / "plugins/cpanel/index.live.php").read_text()
# No account, domain or path from the request; the feature decision is the data field, failing closed.
# FV-08 account tools take a domain, log kind, line count and search text (validated here; the broker serves only the
# caller's own domains). Never an account, a user or a path.
assert set(re.findall(r"\$_GET\[.(\w+).\]", page)) == {"api", "action", "domain", "kind", "lines", "search"} and "$_POST" not in page and "$_REQUEST" not in page
assert "(int) ($answer['data'] ?? 0) === 1" in page and "posix_geteuid()" in page
assert "'tenant.cache_purge'" in page and "($_SERVER['HTTP_X_OLS_CPANEL_REQUEST'] ?? null) !== '1'" in page
assert "$name === 'sites'" in page and "'tenant.sites'" in page and "Cache-Control: no-store" in page
assert "FilesystemIterator::SKIP_DOTS" in page and "isLink()" in page and "SCAN_FILE_LIMIT" in page and "SCAN_ENTRY_LIMIT" in page and "SCAN_SECONDS" in page
install = json.loads((ROOT / "plugins/cpanel/install.json").read_text())
link = next(i for i in install if i["type"] == "link")
assert link["featuremanager"] is True and link["feature"] == "ols_cpanel" and link["uri"] == "ols_cpanel/index.live.php"
conf = (ROOT / "plugins/whm/ols-cpanel.conf").read_text()
assert "acls=all" in conf and "service=whostmgr" in conf and "user=root" in conf
assert (ROOT / "ui/package-lock.json").is_file() and "node@sha256:" in (ROOT / "build/ui/build.sh").read_text()
probe = (TOOLS / "plugin_probe.py").read_text()
assert 'UMASK_022 = ["/usr/bin/sh", "-c", \'umask 022 && exec "$@"\', "sh"]' in probe
result = subprocess.run([sys.executable, str(TOOLS / "plugin_probe.py"), "--broker", "/x", "--ui", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("WHM gateway, cPanel plugin, registration and probe guard checks passed.")
