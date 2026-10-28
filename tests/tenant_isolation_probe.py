#!/usr/bin/python3
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_config_lint as lint
import tenant_isolation_probe as iso

config = iso.server_config((iso.TEMPLATES / "ownership_httpd_config.conf").read_text())
assert lint.lint(config) == []
assert "127.0.0.1:8088" in config and "*:80" not in config and "*:443" not in config
# Tenants run as their docroot owner; their service vhosts and the catch-all cPanel proxy vhost run CGI
# as the server user, like Apache's proxy vhosts.
assert config.count("setUIDMode           2") == 2 and config.count("restrained           1") == 5
assert config.count("setUIDMode           0") == 3 and "map                  cpanel-proxy cpanel.*, webmail.*, whm.*" in config
A = iso.tf.TENANTS["olscpa"]
assert f"map                  svc.{A} cpanel.{A}, webmail.{A}" in config
assert lint.lint(iso.cpanel_surface.proxy_vhost(), False) == []
assert "allow                127.0.0.1" in config and "allow                ALL" not in config
for user, domain in iso.tf.TENANTS.items():
    spec = dict(iso.default_plan()[domain], php="ea-php83")
    vh = iso.vhost_config(spec, "php_admin_value[disable_functions] = exec,system\nsecurity.limit_extensions = .php .phtml\n", {})
    assert "php_admin_value disable_functions exec,system" in vh and "LSPHP_ENABLE_USER_INI=on" in vh
    assert f"lsapi:{user}-php phtml" in vh
    assert "/opt/cpanel/ea-php83/root/usr/bin/lsphp" in vh and f"lsapi:{user}-php php" in vh
    assert lint.lint(vh, False) == [] and f"extUser              {user}" in vh and "autoStart            2" in vh
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/tenant_isolation_probe.py"), "--rpm", "/x"],
                        capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
# Suspension (review): only alias contexts the vhost actually has are exempt from the suspended page; a
# missing alias directory has no context, so its URI maps into the docroot and must be redirected.
import inspect
import re
spec = dict(iso.default_plan()[A], php="ea-php83")
vh = iso.vhost_config(spec, "", {}, missing=["/bandwidth/"], suspended=True)
exempt = re.search(r"RewriteCond %\{REQUEST_URI\} !(\^/\([^\n]*\))\n", vh).group(1)
assert "context /bandwidth/" not in vh and "context /img-sys/" in vh and lint.lint(vh, False) == []
assert not re.match(exempt, "/bandwidth/x.html") and re.match(exempt, "/img-sys/x.png"), exempt
assert re.match(re.search(r"!(\^/\([^\n]*\))\n", iso.cpanel_surface.suspension_rules([])).group(1), "/bandwidth/x.html")
assert "suspendedpage" not in iso.vhost_config(spec, "", {}, missing=["/bandwidth/"])
# .htaccess discovery (review): symlinked .htaccess files are listed (never silently skipped) and refused.
listing = iso.htaccess_listing("olscpa", "/home/olscpa/public_html")
assert listing[:5] == ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/find"] and "/home/olscpa/public_html" in listing
assert " ".join(listing).endswith("-name .htaccess ( -type f -o -type l ) -printf %y%p\\0"), listing
assert "-print0" not in listing and "-H" in listing
source = inspect.getsource(iso.compile_lab)
assert "htaccess_listing(user, docroot)" in source and ".htaccess is a symlink" in source and 'kind != "f"' in source
print("Tenant isolation config generation and guard checks passed.")

# PHP handlers (HR-D05): only suPHP changes the LSAPI environment.
_v = {"php": "ea-php82", "docroot": "/home/u/public_html"}
assert iso.php_environment(dict(_v, php_handler="fpm")) == "" and iso.php_environment(dict(_v, php_handler="cgi")) == ""
env = iso.php_environment(dict(_v, php_handler="suphp"))
assert "PHPRC" not in env  # lsphp ignores scan directories when PHPRC is set
assert "PHP_INI_SCAN_DIR=/opt/cpanel/ea-php82/root/etc:/opt/cpanel/ea-php82/root/etc/php.d:/home/u/public_html" in env
assert set(iso.PHP_HANDLERS) == {"fpm", "cgi", "fcgi", "suphp"}
print("PHP handler environment checks passed.")

# Declared outcomes (RV-06): a completed run passes only when every guarantee holds; known differences are
# explicit with a reason, and a lab-limited entry is accepted only when listed.
same = lambda s: {"apache": {"status": s}, "ols": {"status": s}, "match": True, "baseline_ok": True}
differ = lambda a, o: {"apache": {"status": a}, "ols": {"status": o}, "match": False, "baseline_ok": True}
good = {"passes": {"current_permissions": {"valid": False, "leaks": []}, "native_fileprotect": {"valid": True, "leaks": []}},
        "lsphp_primary_group_only": True, "socket_cross_refused": True,
        "fifo_tenant_write": {"access": "PermissionError", "bytes": "PermissionError"},
        "php_parity": {u: {"equivalent": True} for u in iso.tf.TENANTS},
        "access_control": {"private-anonymous": same("401")}, "rewrite": {"/old-page": same("301")},
        "compat": {"/static.txt": same("200"), "/legacy/": differ("403", "403"), "/listing/": differ("200", "200"),
                   "/noindex/": differ("403", "404")},
        "multi_domain": {iso.tf.SECURE + "/static.txt": same("401"), iso.tf.SECURE + iso.DCV_PATH: differ("200", "200")},
        "surface": {"cpanel./": same("301"), "whm." + iso.DCV_PATH: dict(differ("200", "404"), lab_limited="lab-port80")},
        "surface_tls": {"cpanel./": same("200")},
        "tls": {"<no-sni>": {"apache": "a", "ols": "a", "match": True}, "unknown.invalid": {"apache": "t", "ols": "n", "match": False}},
        "tls_default_is_not_tenant": True, "https_content": {u: {"apache": "x", "ols": "x", "match": True} for u in iso.tf.TENANTS},
        "websocket_proxy": {"ok": True}, "htaccess_blockers": {d: [] for d in iso.tf.TENANTS.values()},
        "log_accounting": {"combined_format": True, "bytes_log_grew": True}, "bandwidth": {"ok": True}, "ols_log_errors": [],
        "enablefileprotect_running_exit": 0, "enablefileprotect_stopped_exit": 0, "return_matches_original": True,
        "ownership_restored": True, "removed": True}
cases = iso.expected_outcomes(good)
assert all(cases.values()), [k for k, v in cases.items() if not v]
assert {"php-parity-" + u for u in iso.tf.TENANTS} <= set(cases) and "acl-traverse-valid-no-leaks" not in cases
assert all(reason.strip() for reason in iso.KNOWN_DIFFERENCES.values())

def fails(change, *expected):
    """Exactly the expected cases fail after the change."""
    broken = sorted(k for k, v in iso.expected_outcomes(dict(good, **change)).items() if not v)
    assert broken == sorted(expected), (expected, broken)

fails({"passes": dict(good["passes"], native_fileprotect={"valid": True, "leaks": ["olscpa:x"]})},
      "native-fileprotect-valid-no-leaks", "no-leaks-in-any-pass")
fails({"passes": dict(good["passes"], native_fileprotect={"valid": False, "leaks": []})}, "native-fileprotect-valid-no-leaks")
fails({"passes": dict(good["passes"], current_permissions={"valid": False, "leaks": ["olscpb:x"]})}, "no-leaks-in-any-pass")
fails({"php_parity": dict(good["php_parity"], olscpb={"equivalent": False})}, "php-parity-olscpb")
fails({"php_parity": {"olscpa": {"equivalent": True}}}, "php-parity-olscpb")
fails({"compat": dict(good["compat"], **{"/uploads/shell.php": differ("403", "403")})}, "compat-equal-except-known")
fails({"rewrite": {"/old-page": differ("301", "200")}}, "rewrite-equal")
fails({"access_control": {}}, "access-control-equal")
# lab_limited alone is no excuse: only listed entries may differ.
fails({"surface": dict(good["surface"], **{"webdisk./": dict(differ("302", "404"), lab_limited="lab-port80")})},
      "surface-equal-except-known")
fails({"multi_domain": dict(good["multi_domain"], **{iso.tf.SECURE + "/missing": dict(same("401"), baseline_ok=False)})},
      "multi-domain-equal-except-known")
# A listed difference that turns an Apache refusal into a success is never accepted.
fails({"compat": dict(good["compat"], **{"/noindex/": differ("403", "200")})}, "compat-equal-except-known")
fails({"tls": dict(good["tls"], **{"<no-sni>": {"apache": "a", "ols": "b", "match": False}})}, "tls-certificates-equal-except-known")
fails({"fifo_tenant_write": {"access": "opened", "bytes": "PermissionError"}}, "fifo-tenant-write-refused")
fails({"socket_cross_refused": False}, "cross-tenant-sockets-refused")
fails({"lsphp_primary_group_only": False}, "php-primary-group-only")
fails({"bandwidth": {"ok": False}}, "bandwidth-counted")
fails({"log_accounting": {"combined_format": True, "bytes_log_grew": False}}, "log-accounting")
fails({"ols_log_errors": ["[ERROR] x"]}, "no-ols-errors")
fails({"ownership_restored": False}, "host-restored")
fails({"removed": False}, "host-restored")
fails({"return_matches_original": False}, "fileprotect-return-path")
fails({"htaccess_blockers": {iso.tf.TENANTS["olscpa"]: ["/: RewriteMap"]}}, "no-htaccess-blockers")
fails({"passes": dict(good["passes"], acl_traverse={"valid": True, "leaks": ["x"]})}, "acl-traverse-valid-no-leaks",
      "no-leaks-in-any-pass")
print("Tenant isolation declared outcomes checks passed.")
