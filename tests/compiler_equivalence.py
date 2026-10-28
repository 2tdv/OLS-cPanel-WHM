#!/usr/bin/python3
"""The PHP product translators must produce exactly what the lab-proven Python tools produce."""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import fpm_translate as fpm
import cpanel_surface as cs
import htaccess_translate as ht
import ols_config_lint as lint
import tenant_fixtures as tf

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
PPD = ("\n#----------------------------------------------------------------cp:ppd\n# Section managed by cPanel: "
       "Password Protected Directories     -cp:ppd\n#----------------------------------------------------------------cp:ppd\n"
       "AuthType Basic\nAuthName \"Private Zone!\"\nAuthUserFile \"/home/u/.htpasswds/public_html/p/passwd\"\n"
       "Require valid-user\n#----------------------------------------------------------------cp:ppd\n"
       "# End section managed by cPanel: Password Protected Directories -cp:ppd\n"
       "#----------------------------------------------------------------cp:ppd")
fixture_files = {}
for op in tf.scenario_operations():
    if op[0] in ("write", "append") and op[2].endswith(".htaccess") and op[2].startswith("/home/olscpa/public_html"):
        rel = op[2][len("/home/olscpa/public_html"):].rsplit("/", 1)[0].strip("/")
        fixture_files[rel] = fixture_files.get(rel, "") + op[3]
HTACCESS = [
    {"files": fixture_files, "docroot": "/home/olscpa/public_html"},
    {"files": {"": tf.WORDPRESS}, "docroot": "/home/olscpb/public_html"},
    {"files": {"p": PPD, "": '<Files "*.lo?">\nDeny from all\n</Files>\n<FilesMatch "^wp-config\\.php$">\nRequire all denied\n</FilesMatch>\n'},
     "docroot": "/home/u/public_html/"},
    {"files": {"a.b+c": "Order Allow,Deny\nDeny from all\n", "x": "Options +Indexes -MultiViews +FollowSymLinks\n"},
     "docroot": "/home/u/public_html"},
    {"files": {"": "Options +ExecCGI\nRedirect 301 /a /b\nHeader always set X-A \"1\"\nHeader unset Server\n"
                   "ErrorDocument 403 /e.html\n<Files x>\nAllow from all\n</Files>\n<FilesMatch a/b>\nDeny from all\n</FilesMatch>\n",
               "sub": "ErrorDocument 404 /x.html\nOrder deny,allow\nDeny from all\nAllow from 1.2.3.4\n",
               "bad dir": "Require all denied\n", "q": "Require all granted\nSetEnv X 'y'\n"},
     "docroot": "/home/u/public_html"},
    {"files": {"z": PPD.replace("Require valid-user", "Require user bob")}, "docroot": "/home/u/public_html"},
    # Ancestor .htaccess text merged ahead of the docroot's own: the later ErrorDocument wins.
    {"files": {"": "ErrorDocument 404 /a.html\nHeader set X-A 1\nErrorDocument 403 /f.html\nErrorDocument 404 /b.html\n"},
     "docroot": "/home/olscpa/public_html/blog"},
    # Conditional headers are blockers (OLS ignores env=); an unconditional one still translates.
    {"files": {"": 'Header set X-A "1" env=HTTPS\nHeader always set X-B 2 early\nHeader set X-C "a" expr=%{HTTPS}\nHeader set X-D 3\n'},
     "docroot": "/home/u/public_html"},
    # Rewrite translation (HR-D07): own rules per directory, Inherit, Engine Off, and every blocker kind.
    {"files": {"": tf.WORDPRESS, "app": "RewriteEngine On\nRewriteOptions Inherit\nRewriteBase /app/\nRewriteRule ^go$ t.txt [L]\n",
               "off": "RewriteEngine Off\nRewriteRule ^x$ y [L]\n", "keep": "Options -Indexes\n"},
     "docroot": "/home/olscpb/public_html"},
    {"files": {"": "RewriteEngine On\nRewriteRule ^(.*)$ http://127.0.0.1:2082/$1 [P]\n",
               "a": "RewriteEngine On\nRewriteRule ^x$ http://example.com/ [proxy,L]\n",
               "b": "RewriteEngine On\nRewriteRule ^ws$ ws://localhost:1/ [L]\n",
               "c": "RewriteEngine On\nRewriteRule ^x$ /y [L]\nEND_rules\n",
               "d": "RewriteRule ^x$ /y [L]\n", "e": "RewriteEngine On\nRewriteOptions MergeBase\n",
               "f": "RewriteEngine On\nRewriteBase /a b/\n"},
     "docroot": "/home/u/public_html"},
    # Internal backends through rewrites: one attack per directory, each must be refused identically.
    {"files": {f"r{i}": "RewriteEngine On\n" + rule + "\n" for i, rule in enumerate([
        "RewriteRule\t^ http://cpsrvd2082/ [P,L]", "RewriteRule ^ http://cpsrvd2082/ [P, L]", "RewriteRule ^ /x [L,\tP]",
        "RewriteRule ^ /x [L p]", "RewriteRule ^(.*)$ /$1 [p]", "RewriteRule ^ /x [PROXY]", "RewriteRule ^ http://cpsrvd2082/ [L]",
        "RewriteRule ^ HTTPS://CPSRVD2083:2083/x", "RewriteRule ^ http://lsphp/x [L]", "RewriteRule ^ http://u@cpsrvd2082/ [L]",
        "RewriteRule ^ http://[::1]:2082/", "RewriteRule ^ unix:/run/x.sock|http://a.b/", "RewriteRule ^ /x [H=cpsrvd2082]",
        "RewriteRule ^ \"http://cpsrvd2082/\"", "RewriteRule ^ /x [L] [P]", "RewriteRule ^ [P]", "RewriteRule ^a\\ b /x [L]",
        "RewriteRule ^ /x \\", "RewriteRule ^ |/bin/x [L]", "RewriteCond |x y", "RewriteRule ^ /x\x01 [L]",
        "RewriteMap m prg:/bin/x", "RewriteRule-x ^ /y", "RewriteEngine\tYes", "RewriteCond\t%{HTTP_HOST} ^x [P]",
        "RewriteRule ^ /x'y [L]"])},
     "docroot": "/home/u/public_html"},
    # Tabs and blanks inside a harmless flag list translate verbatim.
    {"files": {"": "RewriteEngine\tOn\nRewriteCond\t%{REQUEST_FILENAME}\t!-f\nRewriteRule\t.\t/index.php\t[L, NC]\n",
               "s": "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301, L]\n",
               "w": "RewriteEngine On\nRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\nRewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n"},
     "docroot": "/home/u/public_html"},
]
# LiteSpeed Cache sections (FV-01): the shape LiteSpeed Cache for WordPress writes with every optional marker
# (tests/Fixtures/lscwp-htaccess.txt) ahead of WordPress's own rules, and every refusal kind.
LSCWP = (ROOT / "tests/Fixtures/lscwp-htaccess.txt").read_text()
HTACCESS += [
    {"files": {"": LSCWP + tf.WORDPRESS, "sub": "<IfModule litespeed>\nCacheLookup public on\n</IfModule>\n"},
     "docroot": "/home/olscpb/public_html"},
    {"files": {f"l{i}": text for i, text in enumerate([
        "<IfModule LiteSpeed>\nCacheLookup off\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteRule .* - [E=Cache-Control:esi=on]\n</IfModule>\n",
        "RewriteEngine On\nRewriteRule .* - [E=Cache-Control:max-age=60]\n",
        "RewriteEngine On\nRewriteRule .* - [env='cache-vary:x']\n",
        "CacheLookup on\n", "CacheKeyModify -qs:x\n", "<IfModule LiteSpeed>\nSetEnv noabort 1\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteRule .? \"http://cpsrvd2082/\" [E=\"Cache-Vary:x\"]\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteRule .? - [E=\"Cache-Vary:x\",P]\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteRule .? - [E=\"Cache-Vary:%{HTTP_HOST}\"]\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nCacheKeyModify -qs:%{x}\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteCond \"%{HTTP_HOST} x\nRewriteRule ^ - [L]\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteCond %{HTTP_HOST} a\\ b [P]\nRewriteRule ^ - [L]\n</IfModule>\n",
        "<IfModule LiteSpeed>\nRewriteEngine on\nRewriteRule ^ http://cpsrvd2082/ [L]\n</IfModule>\n",
        "<IfModule LiteSpeed>\n<IfModule mod_headers.c>\nHeader set X 1\n</IfModule>\n</IfModule>\n"])},
     "docroot": "/home/u/public_html"},
]
# WordPress plugin corpus (tests/Fixtures/wp-plugins-htaccess): every file is translated on its own and its
# expected outcome (translated, or a blocker with the reason) is recorded in expected.json.
PLUGIN_DIR = ROOT / "tests/Fixtures/wp-plugins-htaccess"
PLUGIN_EXPECTED = json.loads((PLUGIN_DIR / "expected.json").read_text())
PLUGIN_CASES = []
for fixture in sorted(PLUGIN_DIR.rglob("*.htaccess")):
    parts = fixture.relative_to(PLUGIN_DIR).parts
    PLUGIN_CASES.append(("/".join(parts), {"files": {"/".join(parts[1:-1]) if parts[-1] == ".htaccess" else "": fixture.read_text()},
                                           "docroot": "/home/u/public_html"}))
assert sorted(n for n, _ in PLUGIN_CASES) == sorted(PLUGIN_EXPECTED), "every fixture needs an expected outcome"
PLUGIN_BASE = len(HTACCESS)
HTACCESS += [case for _, case in PLUGIN_CASES]
# Module sections, expiry directives and the "deny the directory, allow listed files" pattern: accepted and refused forms.
AKISMET = (PLUGIN_DIR / "akismet/wp-content/plugins/akismet/.htaccess").read_text()
GRANT = '<FilesMatch "^(a|b)\\.js$">\nRequire all granted\n</FilesMatch>\n'
EDGE_BASE = len(HTACCESS)
EDGE = [
    {"files": {"wp/wp-content/plugins/akismet": AKISMET}, "docroot": "/home/u/public_html"},
    {"files": {"x": "Require all denied\n" + GRANT + '<Files "c.txt">\nRequire all granted\n</Files>\n<Files "*.png">\nRequire all granted\n</Files>\n'},
     "docroot": "/home/u/public_html"},
    {"files": {f"g{i}": text for i, text in enumerate([
        GRANT, "Require all granted\n" + GRANT, "Require all denied\nRequire all denied\n" + GRANT,
        "Order deny,allow\nDeny from all\n" + GRANT, "Require all denied\n" + GRANT + '<Files x>\nRequire all denied\n</Files>\n',
        "Require all denied\nRewriteEngine On\nRewriteRule ^a$ /b [L]\n" + GRANT,
        'Require all denied\n<FilesMatch "^a)|(b$">\nRequire all granted\n</FilesMatch>\n',
        'Require all denied\n<FilesMatch "^(a)\\1$">\nRequire all granted\n</FilesMatch>\n',
        'Require all denied\n<FilesMatch "*\\.js">\nRequire all granted\n</FilesMatch>\n',
        'Require all denied\n<FilesMatch "^(?:a)$">\nRequire all granted\n</FilesMatch>\n',
        'Require all denied\n<Files "a[bc]">\nRequire all granted\n</Files>\n',
        'Require all denied\n<FilesMatch "^a\\">\nRequire all granted\n</FilesMatch>\n',
        'Require all denied\n<Files a>\nRequire all granted\nRequire all denied\n</Files>\n',
        'Require all denied\n<Files a>\n<IfModule !mod_authz_core.c>\nRequire all granted\n</IfModule>\n</Files>\n'])},
     "docroot": "/home/u/public_html"},
    {"files": {"": "<IfModule mod_authz_core.c>\n<Files a.txt>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n</Files>\n</IfModule>\n"
                   "<IfModule !mod_authz_core.c>\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\nOptions +ExecCGI\n</IfModule>\n",
               "u": "<IfModule mod_authz_core.c>\nRequire all denied\n", "v": "</IfModule>\nRequire all denied\n",
               "w": "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n</IfModule>\n",
               "x": "<IfModule  !MOD_AUTHZ_CORE.C >\nRequire all denied\n</IfModule>\n<IfModule mod_authz_host.c>\nRequire all denied\n</IfModule>\n"},
     "docroot": "/home/u/public_html"},
    # mod_expires: short and long syntax, ExpiresActive off, later duplicates win, every refusal kind.
    {"files": {"": "<IfModule mod_expires.c>\nExpiresActive On\nExpiresDefault \"access plus 1 month 2 days\"\nExpiresByType image/jpeg A604800\n"
                   "ExpiresByType Text/CSS \"modification plus 1 week\"\nExpiresByType image/jpeg M0100\nExpiresByType image/svg+xml now plus 5 minutes\n</IfModule>\n",
               "off": "ExpiresActive off\n", "d": "<IfModule !mod_expires.c>\nExpiresActive On\n</IfModule>\n"},
     "docroot": "/home/u/public_html"},
    {"files": {f"e{i}": text for i, text in enumerate([
        "ExpiresActive maybe\n", "ExpiresDefault 3600\n", "ExpiresByType image/* A60\n", "ExpiresByType image/png\n", "ExpiresByType image/png access plus\n",
        "ExpiresByType image/png access plus 1 fortnight\n", "ExpiresByType image/png A99999999999\n", "ExpiresByType image/png access plus 99999999 years\n",
        "ExpiresByType image/png now\n", "ExpiresDefault \"A60\n", "ExpiresByType image/png A60 A70\n", "ExpiresActive On Off\n",
        "<Files a>\nExpiresActive On\n</Files>\n", "<FilesMatch x>\nExpiresDefault A5\n</FilesMatch>\n",
        "".join(f"ExpiresByType image/t{n} A31557600\n" for n in range(200))])},
     "docroot": "/home/u/public_html"},
    # mod_headers wrapper: unwrapped; "always" is kept out of the output; env=/expr=/early stay blockers; nested in LiteSpeed it stays refused.
    {"files": {"": "<IfModule mod_headers.c>\nHeader always set X-A \"1\"\nHeader set X-B 2\nHeader unset X-C\nHeader append X-D x\n</IfModule>\n"
                   "<IfModule !mod_headers.c>\nHeader set X-E 5\n</IfModule>\n",
               "c": "<IfModule mod_headers.c>\nHeader set X-A 1 env=HTTPS\n</IfModule>\n",
               "d": "<IfModule mod_headers.c>\n<Files a>\nHeader set X 1\n</Files>\n</IfModule>\n",
               "e": "<IfModule LiteSpeed>\n<IfModule mod_expires.c>\nExpiresActive On\n</IfModule>\n</IfModule>\n"},
     "docroot": "/home/u/public_html"},
]
HTACCESS += EDGE
C = {"E_ALL": 32767, "E_NOTICE": 8, "E_STRICT": 2048, "E_DEPRECATED": 8192, "E_WARNING": 2}
FPM = [
    {"pool": "[x]\nphp_admin_flag[allow_url_fopen] = on\nphp_admin_value[disable_functions] = exec,system\n"
             "php_admin_value[doc_root] = \"/home/u/public_html\"\nphp_value[error_reporting] = E_ALL & ~E_NOTICE\n"
             "php_admin_value[short_open_tag] = on\nphp_value[x] = Off\nphp_value[y] = \"on\"\nphp_flag[d] = OFF\n"
             "; php_admin_value[c] = 1\nsecurity.limit_extensions = .phtml .php .php8\n", "constants": C},
    {"pool": "php_value[error_reporting] = (E_WARNING | E_NOTICE) ^ E_ALL\n", "constants": C},
    {"pool": "php_value[error_reporting] = E_ALL; system('id')\n", "constants": C},
    {"pool": "php_flag[x] = maybe\n", "constants": C},
    {"pool": "php_value[error_reporting] = E_ALL\n", "constants": None},
    {"pool": "php_admin_value[x] = a}b\n", "constants": C},
    {"pool": "", "constants": C},
]
TEMPLATE = (ROOT / "build/vm-qualification/ols-lab/ownership_httpd_config.conf").read_text()
LINT = [{"text": TEMPLATE, "policy": True},
        {"text": TEMPLATE + "virtualHost broken {\n  vhRoot /x/\n", "policy": True},
        {"text": TEMPLATE + "}\nlistener bad {\n  address not-an-address\n}\nlistener t {\n  address 127.0.0.1:8443\n  secure 1\n}\n", "policy": True},
        {"text": TEMPLATE.replace("autoDetectCdn                    0\n", "").replace("CGIRLimit {", "CGIRLimitX {"), "policy": True},
        {"text": "rewrite {\n  rules <<<END\nRewriteRule ^a#b$ /c [L]\nEND\n}\n# comment\n", "policy": False},
        {"text": "a b\nc {\n d e\n}\n", "policy": True}]
ADDRESS = ["*:80", "[ANY]:443", "127.0.0.1:8088", "[::1]:80", "192.0.2.10:443", "", "80", "*:", "*:0", "*:65536",
           "host:80", "[::1:80", "1.2.3.4:abc", "::1:80", "[2001:db8::1]:8443", "256.1.1.1:80"]
python = {"htaccess": [list(ht.translate(c["files"], c["docroot"])) for c in HTACCESS], "fpm": []}
for case in FPM:
    try:
        entries = fpm.translate(case["pool"], case["constants"])
        python["fpm"].append({"entries": [list(e) for e in entries], "block": fpm.override_block(entries),
                              "suffixes": fpm.suffixes(case["pool"])})
    except ValueError:
        python["fpm"].append("error")
python["lint"] = [lint.lint(c["text"], c["policy"]) for c in LINT]
python["address"] = [lint.valid_address(a) for a in ADDRESS]
SURFACE = ["olscp-a.test", "example.co.uk", "xn--bcher-kva.example"]
# Service domains per vhost: a main vhost, a subdomain vhost (none), an addon vhost.
SURFACE_SERVICE = [["olscp-a.test"], [], ["olscp-c.test", "xn--bcher-kva.example"]]
SURFACE_MISSING = [[], ["/bandwidth/", "/java-sys/", "/cgi-sys/"], ["/mailman/", "/mailman/archives/", "/pipermail/"]]
SURFACE_UNSET = [[], ["X-Frame-Options", "Vary"], ["Content-Security-Policy"]]
python["surface"] = [[cs.processors(), cs.host_aliases(d), cs.rewrite_rules(s), cs.contexts(m, u), cs.access_logs(d),
                      cs.service_vhost_name(d), cs.service_server_block(d, "u"), cs.service_vhost("/home/u/public_html/x", s or [d],
                                                                                                  "/c/" + d if u else None),
                      cs.suspension_rules(m)]
                     for d, m, s, u in zip(SURFACE, SURFACE_MISSING, SURFACE_SERVICE, SURFACE_UNSET)]
python["root_headers"] = [ht.root_header_names(r[1]) for r in python["htaccess"]]
import cpanel_vhosts as cv
SAMPLE = json.loads((ROOT / "tests/Fixtures/cpanel_vhosts.json").read_text())
VHOSTS = [{"user": "olscpa", "rows": SAMPLE["rows"], "userdata": SAMPLE["userdata"]},
          {"user": "olscpb", "rows": SAMPLE["rows"], "userdata": {"olscp-b.test": "documentroot: /home/olscpb/public_html\nservername: olscp-b.test\nserveralias: www.olscp-b.test\n"}},
          {"user": "olscpa", "rows": SAMPLE["rows"], "userdata": dict(SAMPLE["userdata"], **{"blog.olscp-a.test": "servername: x\n"})},
          {"user": "olscpa", "rows": SAMPLE["rows"], "userdata": {}},
          {"user": "olscpa", "rows": "bad line\n", "userdata": {}}]
python["vhosts"] = []
for case in VHOSTS:
    try:
        rows = cv.parse_userdatadomains(case["rows"])
        found = cv.account_vhosts(case["user"], rows, case["userdata"])
        python["vhosts"].append([rows, found, [cv.ancestors(v) for v in found]])
    except ValueError:
        python["vhosts"].append("error")
# cPanel's generated httpd.conf (per-address defaults, proxy-subdomains endpoints) and `ip -6` output:
# the lab server's own, then edge cases (wildcards, IPv6 spelling, Python int() ports, refusals).
LAB_CALLS = json.loads((ROOT / "tests/Fixtures/lab-snapshot/compile-production.json").read_text())["calls"]
HTTPD = [next(c["stdout"] for c in LAB_CALLS if c["name"] == "apache-conf"),
         "<VirtualHost 192.0.2.1:80 [2001:DB8:0:0::1]:443 *>\n  ServerAlias www.x cpanel.*\nServerName Host.Example\n"
         "</VirtualHost>\n<virtualhost *:443 >\nservername second\n  </VIRTUALHOST>\n<VirtualHost 192.0.2.1:80>\nServerName later\n",
         "<VirtualHost 10.0.0.1:+80 10.0.0.2:8_0 10.0.0.3: 10.0.0.4>\r\nServerAlias  cpanel.*\r\nServerName a\r\n</VirtualHost>\r\n"
         "ServerName stray\nServerAlias cpanel.*\n",
         "<VirtualHost [::1]>\nServerName x\n", "<VirtualHost 1.2.3.4:http>\n", ""]
IP_OUTPUT = [next(c["stdout"] for c in LAB_CALLS if c["name"] == "ipv6-addresses"),
             "2: eth0    inet6 2001:DB8::0:1/64 scope global\n3: x inet6 2001:db8::1/128\n4: y inet6 ::1/128\n", "",
             "1: lo inet6\n", "1: lo inet6 not-an-address/64\n"]
python["apache"] = []
for text in HTTPD:
    try:
        endpoint = lambda e: f"{e[0]}|{'' if e[1] is None else e[1]}"
        python["apache"].append([{endpoint(k): v for k, v in cv.apache_defaults(text).items()},
                                 [endpoint(e) for e in cv.apache_proxy_endpoints(text)]])
    except ValueError:
        python["apache"].append("error")
python["ipv6"] = []
for text in IP_OUTPUT:
    try:
        python["ipv6"].append(cv.bound_ipv6(text))
    except (ValueError, IndexError):
        python["ipv6"].append("error")
python["proxy"] = [cs.proxy_hosts(), cs.proxy_server_block(), cs.proxy_vhost(), cs.proxy_vhost(cs.SERVICE_CERTS[0]),
                   cs.default_server_block(), cs.default_vhost(), cs.default_vhost(cs.SERVICE_CERTS[0], ["/mailman/", "/pipermail/"])]
# Server and tenant vhost configuration for production ports (ServerCompiler).
import tenant_isolation_probe as iso
base_plan = {v["name"]: dict(v, user="olscpa") for v in cv.account_vhosts(
    "olscpa", cv.parse_userdatadomains(SAMPLE["rows"]), SAMPLE["userdata"])}
v6_plan = {n: dict(v, ipv6=["2001:db8::10"] if n == "olscp-a.test" else []) for n, v in base_plan.items()}
DEFAULTS = {("172.16.0.4", 80): "host.example", ("172.16.0.4", 443): "olscp-a.test", ("2001:db8::10", 80): "blog.olscp-a.test",
            ("*", None): "host.example", ("*", 443): "host.example", ("127.0.0.1", 80): "proxy-subdomains-vhost.localhost"}
SERVERS = [{"plan": base_plan, "ipv6": [], "defaults": {}}, {"plan": base_plan, "ipv6": ["::1"], "defaults": DEFAULTS},
           {"plan": v6_plan, "ipv6": ["::1", "2001:db8::10"], "defaults": DEFAULTS},
           {"plan": v6_plan, "ipv6": ["2001:db8::10"], "defaults": DEFAULTS, "proxy": [("2001:db8::10", 80), ("2001:db8::10", 443)]}]
# Two accounts on two dedicated IPv4 addresses: one listener per address with only its vhosts, plus 127.0.0.1.
# Account B lives on a second home mount (/home2): its vhRoot is that home (review RV-29, finding 11).
B_USERDATA = "documentroot: /home2/olscpb/public_html\nip: 172.16.0.5\nservername: olscp-b.test\nserveralias: www.olscp-b.test\n"
two_ip_plan = dict(base_plan, **{v["name"]: dict(v, user="olscpb") for v in cv.account_vhosts(
    "olscpb", cv.parse_userdatadomains(SAMPLE["rows"]), {"olscp-b.test": B_USERDATA})})
two_ip_v6_plan = {n: dict(v, ipv6=["2001:db8::10"] if n == "olscp-a.test" else []) for n, v in two_ip_plan.items()}
TWO_IP_DEFAULTS = {("172.16.0.4", 80): "olscp-a.test", ("172.16.0.4", 443): "blog.olscp-a.test", ("172.16.0.5", 80): "olscp-b.test",
                   ("127.0.0.1", 80): "proxy-subdomains-vhost.localhost", ("*", 443): "host.example", ("*", None): "host.example"}
TWO_IP_PROXY = [("172.16.0.4", 80), ("172.16.0.4", 443), ("172.16.0.5", 443), ("127.0.0.1", 80), ("127.0.0.1", 443)]
SERVERS += [{"plan": two_ip_plan, "ipv6": [], "defaults": TWO_IP_DEFAULTS, "proxy": TWO_IP_PROXY},
            {"plan": two_ip_v6_plan, "ipv6": ["::1", "2001:db8::10"], "defaults": TWO_IP_DEFAULTS,
             "proxy": TWO_IP_PROXY + [("2001:db8::10", 443)]},
            {"plan": two_ip_plan, "ipv6": [], "defaults": {}}]
# HTTP/3 opt-out (FV-04): quicEnable 0 at server level and enableQuic 0 on every HTTPS listener.
SERVERS += [dict(SERVERS[1], http3=False), dict(SERVERS[5], http3=False)]
python["servers"] = [iso.server_config(TEMPLATE, "h", c["plan"], True, c["ipv6"], c["defaults"], c.get("proxy", []),
                                       http3=c.get("http3", True)) for c in SERVERS]
assert "    quicEnable           1\n" in python["servers"][1] and "    quicEnable           0\n" in python["servers"][-2]
assert python["servers"][1].count("    enableQuic           1\n") == python["servers"][1].count("    secure               1\n") > 0
assert python["servers"][-2].count("    enableQuic           0\n") == python["servers"][-2].count("    secure               1\n") > 0
assert python["servers"][-2] == python["servers"][1].replace("quicEnable           1", "quicEnable           0").replace(
    "enableQuic           1", "enableQuic           0")
assert "virtualHost olscp-b.test {\n    vhRoot               /home2/olscpb/\n" in python["servers"][-1]
assert "virtualHost svc.olscp-b.test {\n    vhRoot               /home2/olscpb/\n" in python["servers"][-1]
POOL = FPM[0]["pool"]
VHCONF = [{"v": dict(v, name=n, php_handler=("fpm", "suphp", "cgi")[i % 3]), "pool": POOL if i == 0 else "", "constants": C if i == 0 else None,
           "access": "realm r {\n}\n" if i == 1 else "", "tls": f"/c/{n}" if i != 2 else None,
           "missing": ["/mailman/"] if i == 2 else ["/bandwidth/"] if i == 1 else [], "unset": ["X-Frame-Options"] if i == 0 else [], "suspended": i == 1}
          for i, (n, v) in enumerate(base_plan.items())]
# The per-vhost cache switch of the configuration overrides (FV-06): off keeps the store, drops lookups.
VHCONF.append(dict(VHCONF[0], v=dict(VHCONF[0]["v"], cache=False)))
# Per-account PHP limits (FV-03): an override set, a partly default one and memory limits; absent is the built-in set.
VHCONF.append(dict(VHCONF[0], limits={"children": 12, "max_conns": 16, "mem_soft": 536870912, "mem_hard": 1073741824,
                                      "proc_soft": 600, "proc_hard": 800}))
VHCONF.append(dict(VHCONF[1], limits={"children": 5, "max_conns": 5, "mem_soft": 0, "mem_hard": 2146435072,
                                      "proc_soft": 400, "proc_hard": 500}))
python["vhconf"] = [iso.vhost_config(c["v"], c["pool"], c["constants"], c["access"], c["tls"], "", c["missing"], c["unset"],
                                     "/var/log/ols-cpanel", c["suspended"], c.get("limits")) for c in VHCONF]
assert python["vhconf"][-2] != python["vhconf"][0] and "maxConns             16\n    env                  PHP_LSAPI_CHILDREN=12\n" in python["vhconf"][-2]
assert "memHardLimit         2146435072\n" in python["vhconf"][-1] and "procSoftLimit        400\n" in python["vhconf"][-1]
# Absent limits are the built-in numbers, byte for byte.
assert "maxConns             5\n    env                  PHP_LSAPI_CHILDREN=5\n" in python["vhconf"][0] and "memSoftLimit         0\n" in python["vhconf"][0]
# LSCache policy (FV-01): blocks, rules and summary for every switch state, store names and their refusals.
import lscache
LONG_VHOST = ("a" * 60 + ".") * 4 + "test"
CACHE = [{"v": dict(v, name=n), "suspended": False} for n, v in base_plan.items()]
CACHE += [{"v": dict(CACHE[0]["v"], cache=False), "suspended": False}, {"v": dict(CACHE[0]["v"], cache="yes"), "suspended": False},
          {"v": dict(CACHE[0]["v"], cache=True), "suspended": True}, {"v": {"name": LONG_VHOST, "user": "olscpa"}, "suspended": False}]
CACHE_PLAN = {n: dict(v, mode="apache" if i == 1 else "native", cache=i != 2) for i, (n, v) in enumerate(two_ip_plan.items())}
STORES = [["olscpa", "olscp-a.test"], ["olscp.b-1_x", LONG_VHOST], ["a" * 200, LONG_VHOST], ["Root", "x.test"],
          ["olscpa", "localhost"], ["olscpa", "../x.test"], ["", "x.test"], ["olscpa", "x.test/y"]]
python["cache"] = [[lscache.vhost_block(c["v"], c["suspended"]), lscache.vhost_rules(c["v"], c["suspended"]),
                    lscache.cache_enabled(c["v"], c["suspended"])] for c in CACHE]
python["cache"].append([lscache.server_block(), lscache.disabled_block(), lscache.summary(CACHE_PLAN, ["olscpb"]),
                        lscache.server_block("/srv/c")])
python["stores"] = []
for user, vhost in STORES:
    try:
        python["stores"].append(lscache.storage_path(user, vhost))
    except ValueError:
        python["stores"].append("error")
assert python["stores"][0] == "/var/lib/ols-cpanel/cache/olscpa@olscp-a.test" and "@h-" in python["stores"][1]
assert python["stores"][2:] == ["error"] * 6, python["stores"]
with tempfile.NamedTemporaryFile("w", suffix=".json") as corpus:
    json.dump({"cache": CACHE, "cache_plan": CACHE_PLAN, "stores": STORES, "htaccess": HTACCESS, "fpm": FPM, "lint": LINT, "address": ADDRESS, "surface": SURFACE, "surface_missing": SURFACE_MISSING,
               "surface_service": SURFACE_SERVICE, "surface_unset": SURFACE_UNSET,
               "vhosts": VHOSTS, "template": TEMPLATE, "vhconf": VHCONF, "httpd": HTTPD, "ip_output": IP_OUTPUT,
               "servers": [dict(c, defaults={f"{a}|{p if p is not None else ''}": n for (a, p), n in c["defaults"].items()},
                                proxy=[f"{a}|{p}" for a, p in c.get("proxy", [])]) for c in SERVERS]}, corpus)
    corpus.flush()
    result = subprocess.run([PHP, "-n", str(ROOT / "tests/compiler_corpus.php"), corpus.name],
                            capture_output=True, text=True, check=True)
php = json.loads(result.stdout)
for section in ("htaccess", "fpm", "lint", "address", "surface", "proxy", "root_headers", "vhosts", "servers", "vhconf", "apache", "ipv6", "cache", "stores"):
    for index, (left, right) in enumerate(zip(python[section], php[section])):
        assert left == right, (section, index, left, right)
    assert len(python[section]) == len(php[section])
assert python["htaccess"][4][2], "blocker corpus must produce blockers"
# WordPress plugin corpus: recorded outcomes.
for offset, (name, case) in enumerate(PLUGIN_CASES):
    _, blocks_, blockers_ = python["htaccess"][PLUGIN_BASE + offset]
    expected = PLUGIN_EXPECTED[name]
    if expected["outcome"] == "translated":
        assert blockers_ == [], (name, blockers_)
    else:
        assert any(expected["blocker"] in b for b in blockers_), (name, expected["blocker"], blockers_)
        assert not re.search(r"RemoveHandler|auto_prepend", "".join(blocks_)), name
# Akismet: one lookahead context, the plain directory denial is not emitted, and the regex keeps Apache's meaning.
_, ak_blocks, ak_blockers = python["htaccess"][EDGE_BASE]
assert ak_blockers == [] and len(ak_blocks) == 1 and ak_blocks[0].startswith("context exp:^/wp/wp\\-content/plugins/akismet/(?!")
assert "allowBrowse             0" in ak_blocks[0] and "context /wp/" not in ak_blocks[0]
ak_regex = ak_blocks[0].split()[1][4:]
base = "/wp/wp-content/plugins/akismet/"
for path, denied in [("", True), ("form.js", False), ("_inc/akismet-frontend.js", False), ("a/b/akismet-admin-rtl.css", False),
                     ("inter.css", False), ("class.akismet.php", True), ("form.js/x.php", True), ("x.php/form.js", True),
                     ("xform.js", True), ("form.jsx", True), ("sub/", True), ("akismet.js.php", True), ("v1.2/form.js", True),
                     ("form.js/", True)]:
    assert (re.match(ak_regex, base + path) is not None) == denied, (path, ak_regex)
assert not re.match(ak_regex, "/wp/wp-content/plugins/other/class.php"), "only the akismet directory"
# Granted blocks without a lone directory-level denial, mixed rules and unsupported patterns are blockers of their own directory.
_, mixed_blocks, mixed_blockers = python["htaccess"][EDGE_BASE + 1]
assert mixed_blockers == [] and len(mixed_blocks) == 1 and mixed_blocks[0].count("(?:") >= 3, python["htaccess"][EDGE_BASE + 1]
assert "context /x/" not in "".join(mixed_blocks)
grant_files = EDGE[2]["files"]
assert {b.split(":")[0] for b in python["htaccess"][EDGE_BASE + 2][2]} == {f"/{d}/" for d in grant_files}, python["htaccess"][EDGE_BASE + 2][2]
assert not re.search(r"\(\?!", "".join(python["htaccess"][EDGE_BASE + 2][1])), "no refused allow-list reaches the output"
# Module sections: nested keep/drop, unbalanced sections and other modules stay blockers.
_, mod_blocks, mod_blockers = python["htaccess"][EDGE_BASE + 3]
assert {b.split(":")[0] for b in mod_blockers} == {"/u/", "/v/", "/w/", "/x/"}, mod_blockers
assert any(b.startswith("/: ") for b in mod_blockers) is False and "context exp:^/(.*/)?a\\.txt$" in "".join(mod_blocks)
assert "ExecCGI" not in "".join(mod_blockers), "the body of a false section is never evaluated"
# Expiry translation: normalised values, later duplicates win, ExpiresActive off, and every refusal kind.
_, exp_blocks, exp_blockers = python["htaccess"][EDGE_BASE + 4]
assert exp_blockers == [], exp_blockers
exp_text = "".join(exp_blocks)
assert ("  enableExpires           1\n  expiresDefault          A2764800\n"
        "  expiresByType           text/css=M604800,image/jpeg=M100,image/svg+xml=A300\n") in exp_text, exp_text
assert "context /off/ {\n  location                /home/u/public_html/off/\n  enableExpires           0\n}" in exp_text and "/d/" not in exp_text
assert {b.split(":")[0] for b in python["htaccess"][EDGE_BASE + 5][2]} == {f"/{d}/" for d in EDGE[5]["files"]}, python["htaccess"][EDGE_BASE + 5][2]
assert not re.search(r"expires", "".join(python["htaccess"][EDGE_BASE + 5][1])), "no refused expiry reaches the output"
# mod_headers wrapper: unwrapped, "always" dropped, the negated form ignored; conditional and nested forms stay refused.
_, hdr_blocks, hdr_blockers = python["htaccess"][EDGE_BASE + 6]
assert {b.split(":")[0] for b in hdr_blockers} == {"/c/", "/d/", "/e/"}, hdr_blockers
assert ("  extraHeaders            <<<END_extraHeaders\nHeader set X-A \"1\"\nHeader set X-B 2\nHeader unset X-C\nHeader append X-D x\nEND_extraHeaders") in "".join(hdr_blocks)
assert "X-E" not in "".join(hdr_blocks)
# LiteSpeed Cache sections: the complete plugin shape translates ahead of WordPress's rules (CacheLookup dropped),
# a lookup-only section emits nothing, and every refusal kind is a blocker of its own directory.
lscwp_realms, lscwp_blocks, lscwp_blockers = python["htaccess"][12]
assert lscwp_blockers == [] and len(lscwp_blocks) == 1 and "CacheLookup" not in lscwp_blocks[0], python["htaccess"][12]
assert lscwp_blocks[0].index("[E=Cache-Control:no-autoflush]") < lscwp_blocks[0].index("RewriteRule . /index.php [L]")
assert "CacheKeyModify -qs:utm*\n" in lscwp_blocks[0] and 'RewriteRule .? - [E="Cache-Vary:,wp-postpass_abc"]' in lscwp_blocks[0]
assert {b.split(":")[0] for b in python["htaccess"][13][2]} == {f"/{d}/" for d in HTACCESS[13]["files"]}, python["htaccess"][13][2]
assert not re.search(r"Rewrite|Cache", "".join(python["htaccess"][13][1])), "no refused LiteSpeed rule reaches the output"
# Cache blocks: one store per vhost, lookups only where enabled, the PURGE refusal only there.
blocks = [c[0] for c in python["cache"][:3]]
assert len({re.search(r"storagePath +(\S+)", b).group(1) for b in blocks}) == 3
assert [c[2] for c in python["cache"]][:-1] == [True, True, True, False, False, False, True]
assert all(("ls_enabled           1" in c[0]) == c[2] == bool(c[1]) for c in python["cache"][:-1])
assert "ls_enabled           0" in python["cache"][-1][0] and "storagePath          /var/lib/ols-cpanel/cache/server\n" in python["cache"][-1][0]
for text in python["vhconf"][:3] + python["servers"]:
    assert lint.lint(text, text in python["servers"]) == []
assert "ls_enabled           0" in python["vhconf"][1] and "PURGE" not in python["vhconf"][1], "suspended: lookups off"
assert "ls_enabled           0" in python["vhconf"][3] and "PURGE" not in python["vhconf"][3], "cache override off"
assert all(s.count("module cache {") == 1 for s in python["servers"])
attacks = HTACCESS[10]["files"]
assert {b.split(":")[0] for b in python["htaccess"][10][2]} == {f"/{d}/" for d in attacks}, "every rewrite attack is a blocker"
assert "Rewrite" not in "".join(python["htaccess"][10][1]), "no refused rewrite line reaches the output"
assert python["htaccess"][11][2] == [] and len(python["htaccess"][11][1]) == 3, "harmless blanks in rewrite lines translate"
# A suspended vhost exempts only alias contexts it actually has (a missing alias maps into the docroot).
assert "bandwidth/" not in python["surface"][1][-1] and "img-sys/" in python["surface"][1][-1]
assert "bandwidth/" in python["surface"][0][-1] and "utodiscover" in python["surface"][0][-1] and "cpanel|kpanel" in python["surface"][0][-1]
# Without a /cgi-sys/ context the global script URLs would map into the docroot too.
assert "utodiscover" not in python["surface"][1][-1] and "cpanel|kpanel" not in python["surface"][1][-1]
suspended_vhconf = python["vhconf"][1]
assert "suspendedpage.cgi" in suspended_vhconf and "|bandwidth/|" not in suspended_vhconf and "context /bandwidth/" not in suspended_vhconf
assert [v == "error" for v in python["vhosts"]] == [False, False, True, True, True], "vhost corpus must cover refusals"
assert [v == "error" for v in python["apache"]] == [False, False, False, True, True, False], "httpd.conf corpus must cover refusals"
assert [v == "error" for v in python["ipv6"]] == [False, False, False, True, True], "ip corpus must cover refusals"
assert python["apache"][0][0] and python["apache"][0][1] and len(python["ipv6"][0]) > 1, "the lab httpd.conf has defaults and endpoints"
assert len(python["vhosts"][0][1]) == 3 and python["vhosts"][0][1][2]["pool"] == "olscp-c.test"

def listeners(config):
    """listener name -> (address, [(vhost, [hosts]), ...]) of a compiled server configuration."""
    found = {}
    for name, body in re.findall(r"^listener (\S+) \{\n(.*?)^\}\n", config, re.M | re.S):
        address = re.search(r"^    address +(\S+)$", body, re.M).group(1)
        found[name] = (address, [(m[0], m[1].split(", ")) for m in re.findall(r"^    map +(\S+) (.+)$", body, re.M)])
    return found

# One shared IPv4 address keeps the single "*" listener holding every vhost.
for config in python["servers"][:4]:
    assert lint.lint(config) == [] and "listener http {\n    address              *:80\n" in config and "http4-" not in config
# Several account IPv4 addresses: no wildcard IPv4 listener, and each address answers only for its own vhosts.
A_HOSTS = {h for n, v in two_ip_plan.items() if v["user"] == "olscpa" for h in [n, *v["aliases"]]}
B_HOSTS = {"olscp-b.test", "www.olscp-b.test"}
SVC = cs.service_vhost_name
A_SVC = {SVC(n) for n, v in two_ip_plan.items() if v["user"] == "olscpa" and v["service_domains"]}
B_SVC = {SVC("olscp-b.test")}
for index in (4, 5, 6):
    config, case = python["servers"][index], SERVERS[index]
    found = listeners(config)
    assert lint.lint(config) == [] and "*:80" not in config and "*:443" not in config, index
    v4 = [n for n in found if not n.startswith(("http6-", "https6-"))]
    assert v4 == ["http4-0", "https4-0", "http4-1", "https4-1", "http4-lo", "https4-lo"], v4
    expect = {"4-0": ("172.16.0.4", A_HOSTS, B_HOSTS, A_SVC, B_SVC), "4-1": ("172.16.0.5", B_HOSTS, A_HOSTS, B_SVC, A_SVC)}
    for suffix, (address, mine, others, my_service, other_service) in expect.items():
        for kind, port in (("http", 80), ("https", 443)):
            listen, maps = found[kind + suffix]
            hosts = {h for vhost, names in maps if vhost not in A_SVC | B_SVC | {cs.PROXY_VHOST}
                     for h in names if h != "*"}
            mapped = {vhost for vhost, _ in maps}
            assert listen == f"{address}:{port}" and hosts == mine and not hosts & others, (index, kind + suffix, hosts)
            assert my_service <= mapped and not other_service & mapped, (index, kind + suffix)
            assert (cs.PROXY_VHOST in mapped) == ((address, port) in case.get("proxy", [])), (index, kind + suffix)
    # Loopback: Apache's hostname and proxy-subdomains vhosts only, no account names.
    for kind, port in (("http", 80), ("https", 443)):
        listen, maps = found[kind + "4-lo"]
        mapped = {vhost for vhost, _ in maps}
        assert listen == f"127.0.0.1:{port}" and not mapped & set(two_ip_plan), (index, kind)
        assert (cs.PROXY_VHOST in mapped) == (("127.0.0.1", port) in case.get("proxy", [])), (index, kind)
    # The "*" default of each listener follows the Apache default of its own address.
    defaults = {n: next(v for v, names in m if names == ["*"]) for n, (_, m) in found.items()}
    if case["defaults"]:
        assert {n: defaults[n] for n in v4} == {"http4-0": "olscp-a.test", "https4-0": "blog.olscp-a.test", "http4-1": "olscp-b.test",
                                               "https4-1": cs.DEFAULT_VHOST, "http4-lo": cs.PROXY_VHOST,
                                               "https4-lo": cs.DEFAULT_VHOST}, defaults
    else:
        assert set(defaults.values()) == {cs.DEFAULT_VHOST}, defaults
# IPv6 listeners are unchanged by the IPv4 split.
assert "listener http6-1 {\n    address              [2001:db8::10]:80\n" in python["servers"][5]
assert [v for v, _ in listeners(python["servers"][5])["https6-1"][1]] == ["olscp-a.test", SVC("olscp-a.test"), cs.PROXY_VHOST,
                                                                         cs.DEFAULT_VHOST]
print("PHP compiler modules are byte-equivalent to the lab-proven translators "
      f"({len(VHOSTS)} account models, {len(HTACCESS)} .htaccess sets, {len(FPM)} FPM pools, {len(LINT)} configs, {len(ADDRESS)} addresses, {len(SURFACE)} surface domains, "
      f"{len(SERVERS)} server configurations, {len(VHCONF)} vhost configurations).")
