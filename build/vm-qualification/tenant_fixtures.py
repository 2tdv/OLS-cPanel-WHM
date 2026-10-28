#!/usr/bin/python3
"""NEXT-08 / G0-C fixtures: create or remove two synthetic cPanel tenants with cross-tenant
attack fixtures (symlinks and PHP reads into the other tenant), then record which requests
the current web server allows. Only the fixed lab account names are ever touched."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import secrets
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Live lab runs need real names whose DNS points at the lab server, so the sites can be opened in a browser
# and cPanel AutoSSL can issue real certificates: set OLS_LAB_TENANT_DOMAINS="<domain of olscpa>,<domain of
# olscpb>" (for example olstest1.<your domain>,olstest2.<your domain>). The built-in names are reserved
# example names that exist only for the offline tests; no live probe can succeed with them. All fixture
# content is synthetic.
_DOMAINS = os.environ.get("OLS_LAB_TENANT_DOMAINS", "olstest1.example.test,olstest2.example.test").split(",")
if len(_DOMAINS) != 2 or not all(d.strip() for d in _DOMAINS):
    raise SystemExit("OLS_LAB_TENANT_DOMAINS must be two comma-separated domains")
TENANTS = {"olscpa": _DOMAINS[0].strip(), "olscpb": _DOMAINS[1].strip()}
# Extra cPanel domains on tenant A (OLS-19): a subdomain, an addon domain (served by its own
# subdomain vhost) and a parked alias. Lab names only; cPanel must be told to accept unregistered
# domains while they are created.
SUBDOMAIN, ADDON, ADDON_LABEL, PARKED = "blog." + TENANTS["olscpa"], "olscp-c.test", "olscpc", "olscp-alias.test"
EXTRA_DOCROOTS = {SUBDOMAIN: "/home/olscpa/public_html/blog", ADDON: "/home/olscpa/public_html/olscp-c.test"}
# A subdomain whose whole docroot is password-protected and sets a strict header: Apache applies both
# only inside that docroot (not to /img-sys, /cgi-sys scripts, DCV exemptions or proxied services).
SECURE, SECURE_ROOT = "secure." + TENANTS["olscpa"], "/home/olscpa/public_html/secure"
# A dedicated IPv6 address for tenant A (owner decision HR-D06): a unique-local range registered in WHM;
# cPanel binds the address on the main interface and adds it to the account's Apache vhosts.
IPV6_RANGE_NAME, IPV6_RANGE = "olscplab", "fd00:6c73:6371::/64"
# PHP handlers (owner decision HR-D05): tenant A on PHP-FPM, tenant B on the CGI handler; each sets one
# directive through cPanel's MultiPHP INI editor (FPM pool vs php.ini/.user.ini in the docroot).
MEMORY_LIMITS = {"olscpa": "321M", "olscpb": "222M"}
CGI_TENANTS = {"olscpb"}
WHOAMI_PHP = """<?php
echo json_encode(['user' => posix_getpwuid(posix_geteuid())['name'], 'doc_root' => ini_get('doc_root'),
                  'error_log' => ini_get('error_log')]), "\\n";
"""
# Requests issued against each tenant's host name; "other" is the opposite tenant.
CASES = {
    "own-static": "/static.txt",
    "own-php": "/probe.php",
    "symlink-other-static": "/link-other-static.txt",
    "symlink-other-secret": "/link-other-secret.txt",
    "php-read-other-static": "/read.php?target=static",
    "php-read-other-secret": "/read.php?target=secret",
}
READ_PHP = """<?php
$other = '{other}';
$paths = ['static' => "/home/$other/public_html/static.txt", 'secret' => "/home/$other/secret.txt"];
$path = $paths[$_GET['target'] ?? ''] ?? null;
$data = $path === null ? false : @file_get_contents($path);
echo json_encode(['target' => $path, 'readable' => $data !== false,
                  'user' => posix_getpwuid(posix_geteuid())['name'], 'gid' => posix_getegid(),
                  'groups' => posix_getgroups()]), "\\n";
"""

def primary_group_only(lines):
    """True when every PHP process (lines of `pid Uid: r e s f Gid: r e s f Groups: ...`) runs with
    the primary group of its user in all four gid slots and no group outside that user's own."""
    import grp
    import pwd
    if not lines:
        return False
    for line in lines:
        fields = line.split()
        try:
            uid = int(fields[fields.index("Uid:") + 1])
            gids = [int(x) for x in fields[fields.index("Gid:") + 1:fields.index("Gid:") + 5]]
            groups = [int(x) for x in fields[fields.index("Groups:") + 1:]]
        except (ValueError, IndexError):
            return False
        user = pwd.getpwuid(uid)
        allowed = {user.pw_gid} | {g.gr_gid for g in grp.getgrall() if user.pw_name in g.gr_mem}
        if any(g != user.pw_gid for g in gids) or any(g not in allowed for g in groups):
            return False
    return True

def fixture_commands(user, other, nonce):
    home = "/home/" + user
    web = home + "/public_html"
    files = {web + "/static.txt": "static " + user + " " + nonce + "\n",
             home + "/secret.txt": "secret " + user + " " + nonce + "\n",
             web + "/read.php": READ_PHP.replace("{other}", other),
             web + "/probe.php": "<?php echo json_encode(['user' => posix_getpwuid(posix_geteuid())['name'],"
                                 " 'sapi' => PHP_SAPI]), \"\\n\";\n"}
    commands = []
    for path, content in files.items():
        mode = "0600" if path.endswith("secret.txt") else "0644"
        commands.append(("write", path, content, mode))
    commands.append(("symlink", web + "/link-other-static.txt", "/home/" + other + "/public_html/static.txt"))
    commands.append(("symlink", web + "/link-other-secret.txt", "/home/" + other + "/secret.txt"))
    return commands

# Fixture credential for the synthetic Directory Privacy user (lab only; also used by the probes).
PRIVACY_USER, PRIVACY_PASSWORD = "alice", "Lab-Only-Passw0rd-1"
DCV_TOKEN = "olscpLabToken_0123456789abcdef"
WORDPRESS = """
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^old-page/?$ /new-page/ [R=301,L]
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""
FRONT_CONTROLLER = """<?php
header('Content-Type: application/json');
echo json_encode(['front' => 'index.php', 'uri' => $_SERVER['REQUEST_URI'] ?? null, 'query' => $_SERVER['QUERY_STRING'] ?? null]), "\\n";
"""

CGI_WHOAMI = """#!/bin/sh
printf 'Content-Type: text/plain\\r\\n\\r\\ncgi %s\\n' "$(/usr/bin/id -un)"
"""

def scenario_operations():
    """Ordered G0-C/G0-D/OLS-16 scenario fixtures. API calls first: cPanel rewrites .htaccess."""
    a, b = "/home/olscpa/public_html", "/home/olscpb/public_html"
    return [
        ("whmapi", ["php_set_vhost_versions", "version=ea-php83", "vhost=" + TENANTS["olscpa"]]),
        ("uapi", "olscpa", ["LangPHP", "php_ini_set_user_basic_directives", "type=vhost", "vhost=" + TENANTS["olscpa"],
                            "directive-1=memory_limit:" + MEMORY_LIMITS["olscpa"]]),
        ("mkdir", "olscpa", [a + "/private", a + "/denied", a + "/uploads", a + "/legacy", a + "/listing", a + "/noindex",
                             a + "/cgi-bin"]),
        # Tenant ScriptAlias /cgi-bin/: Apache runs it through suexec as the tenant.
        ("script", "olscpa", a + "/cgi-bin/whoami.cgi", CGI_WHOAMI),
        ("write", "olscpa", a + "/private/index.html", "secret-private-olscpa\n"),
        ("uapi", "olscpa", ["DirectoryPrivacy", "configure_directory_protection", "dir=" + a + "/private",
                            "authname=Private", "enabled=1"]),
        ("uapi", "olscpa", ["DirectoryPrivacy", "add_user", "dir=" + a + "/private", "user=" + PRIVACY_USER,
                            "password=" + PRIVACY_PASSWORD]),
        ("write", "olscpa", a + "/denied/index.html", "secret-denied-olscpa\n"),
        ("write", "olscpa", a + "/denied/.htaccess", "Require all denied\n"),
        ("write", "olscpa", a + "/.env", "APP_KEY=env-secret-olscpa\n"),
        ("write", "olscpa", a + "/uploads/shell.php", '<?php echo "uploaded-php-executed";\n'),
        ("write", "olscpa", a + "/uploads/pic.txt", "img\n"),
        ("write", "olscpa", a + "/uploads/.htaccess", "<Files *.php>\nDeny from all\n</Files>\n"),
        ("write", "olscpa", a + "/legacy/index.html", "legacy\n"),
        ("write", "olscpa", a + "/legacy/.htaccess", "Order deny,allow\nDeny from all\n"),
        ("write", "olscpa", a + "/listing/a.txt", "a\n"),
        ("write", "olscpa", a + "/noindex/b.txt", "b\n"),
        ("write", "olscpa", a + "/noindex/.htaccess", "Options -Indexes\n"),
        ("write", "olscpa", a + "/404.html", "custom-404-page\n"),
        ("append", "olscpa", a + "/.htaccess", '\n<Files ".env">\n    Require all denied\n</Files>\n'
                                               '\nErrorDocument 404 /404.html\nHeader set X-Frame-Options "SAMEORIGIN"\n'),
        ("write", "olscpa", a + "/error_log", "[22-Oct-2026] PHP Warning: secret path /home/olscpa/x\n"),
        ("mkdir", "olscpa", [a + "/.well-known", a + "/.well-known/acme-challenge"]),
        ("write", "olscpa", a + "/.well-known/acme-challenge/" + DCV_TOKEN, "dcv-" + DCV_TOKEN + "\n"),
        ("write", "olscpb", b + "/index.php", FRONT_CONTROLLER),
        ("whmapi", ["php_set_vhost_versions", "version=ea-php82", "vhost=" + TENANTS["olscpb"], "php_fpm=0"]),
        ("uapi", "olscpb", ["LangPHP", "php_ini_set_user_basic_directives", "type=vhost", "vhost=" + TENANTS["olscpb"],
                            "directive-1=memory_limit:" + MEMORY_LIMITS["olscpb"]]),
        ("append", "olscpb", b + "/.htaccess", WORDPRESS),
        # Per-directory rewrite semantics (HR-D07 translation must match Apache): a subdirectory whose
        # .htaccess has no rewrite directives, and one with its own rules under the WordPress root.
        ("mkdir", "olscpb", [b + "/sub-noindex", b + "/app"]),
        ("write", "olscpb", b + "/sub-noindex/real.txt", "real-sub\n"),
        ("write", "olscpb", b + "/sub-noindex/.htaccess", "Options -Indexes\n"),
        ("write", "olscpb", b + "/app/target.txt", "app-target\n"),
        ("write", "olscpb", b + "/app/.htaccess", "RewriteEngine On\nRewriteRule ^go$ target.txt [L]\n"),
        ("uapi", "olscpa", ["SubDomain", "addsubdomain", "domain=blog", "rootdomain=" + TENANTS["olscpa"], "dir=public_html/blog"]),
        ("cpapi2", "olscpa", ["AddonDomain", "addaddondomain", "newdomain=" + ADDON, "subdomain=" + ADDON_LABEL,
                              "dir=public_html/" + ADDON]),
        ("cpapi2", "olscpa", ["Park", "park", "domain=" + PARKED]),
        *[op for name, root in EXTRA_DOCROOTS.items() for op in (
            ("write", "olscpa", root + "/static.txt", "static " + name + "\n"),
            ("write", "olscpa", root + "/whoami.php", WHOAMI_PHP))],
        ("uapi", "olscpa", ["SubDomain", "addsubdomain", "domain=secure", "rootdomain=" + TENANTS["olscpa"], "dir=public_html/secure"]),
        ("write", "olscpa", SECURE_ROOT + "/static.txt", "static " + SECURE + "\n"),
        ("mkdir", "olscpa", [SECURE_ROOT + "/.well-known", SECURE_ROOT + "/.well-known/acme-challenge"]),
        ("write", "olscpa", SECURE_ROOT + "/.well-known/acme-challenge/" + DCV_TOKEN, "dcv-" + DCV_TOKEN + "\n"),
        ("uapi", "olscpa", ["DirectoryPrivacy", "configure_directory_protection", "dir=" + SECURE_ROOT,
                            "authname=Secure", "enabled=1"]),
        ("uapi", "olscpa", ["DirectoryPrivacy", "add_user", "dir=" + SECURE_ROOT, "user=" + PRIVACY_USER,
                            "password=" + PRIVACY_PASSWORD]),
        ("append", "olscpa", SECURE_ROOT + "/.htaccess", '\nHeader set X-Frame-Options "DENY"\n'),
        ("whmapi", ["ipv6_range_add", "name=" + IPV6_RANGE_NAME, "range=" + IPV6_RANGE, "enabled=1"]),
        ("whmapi", ["ipv6_enable_account", "user=olscpa", "range=" + IPV6_RANGE_NAME]),
    ]

def leaked(case, body, other):
    """True when a request against one tenant returned the other tenant's content."""
    if case.startswith("php-read"):
        try:
            return bool(json.loads(body).get("readable"))
        except ValueError:
            return False
    if "other" in case:
        return ("static " + other) in body or ("secret " + other) in body
    return False

def valid_observation(results):
    for user in TENANTS:
        static = results.get(user + ":own-static", {})
        php = results.get(user + ":own-php", {})
        if static.get("status") != "200" or ("static " + user) not in static.get("body", ""):
            return False
        try:
            if php.get("status") != "200" or json.loads(php.get("body", "")).get("user") is None:
                return False
        except ValueError:
            return False
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--observe", action="store_true")
    mode.add_argument("--remove", action="store_true")
    parser.add_argument("--lab-empty-host", action="store_true")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--address", help="connect here instead of each account's IP (e.g. a test listener)")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("Tenant fixtures change accounts on the lab; --lab-empty-host is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = "create" if args.create else "observe" if args.observe else "remove"
        run = local / ("tenants-" + action + "-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)  # tenants read staged fixture files through runuser; names are unguessable
        summary = {"schema_version": 1, "kind": "tenant-fixtures", "action": action,
                   "started_at": probe.now(), "result": "not_run"}
        index = 0

        def step(name, command, limit=300):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def fpm_pools():
            """PHP-FPM tenant -> (ea-php version, pool socket) from cPanel's generated FPM pool files."""
            pools = {}
            for user, domain in TENANTS.items():
                if user in CGI_TENANTS:
                    continue
                found = step("fpm-pool", ["/usr/bin/sh", "-c", 'ls /opt/cpanel/ea-php*/root/etc/php-fpm.d/"$1".conf',
                                          "sh", domain])["stdout"].split()
                if len(found) != 1:
                    raise ValueError(f"Expected one PHP-FPM pool for {domain}, found {found}")
                listen = step("fpm-listen", ["/usr/bin/grep", "-m1", "^listen =", found[0]])["stdout"]
                pools[user] = (found[0].split("/")[3], listen.split("=", 1)[1].strip())
            return pools

        def fpm_versions():
            return [version for version, _ in fpm_pools().values()]

        def fpm_sockets():
            return {user: socket for user, (_, socket) in fpm_pools().items()}

        def account_rows():
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            return {a["user"]: a for a in data.get("acct", [])}

        def accounts():
            return sorted(account_rows())

        try:
            present = accounts()
            if args.create:
                if present:
                    raise ValueError("Accounts already exist: " + ",".join(present))
                nonce = uuid.uuid4().hex
                for user, domain in TENANTS.items():
                    # The password is random, never stored, and only visible to the API call.
                    created = step("createacct-" + user, ["/usr/local/cpanel/bin/whmapi1", "--output=json", "createacct",
                                   "username=" + user, "domain=" + domain, "password=" + secrets.token_urlsafe(24),
                                   "contactemail=", "hasshell=0", "maxaddon=2", "maxpark=2"])
                    probe.api(created, "createacct")
                for user in TENANTS:
                    other = next(u for u in TENANTS if u != user)
                    for item in fixture_commands(user, other, nonce):
                        if item[0] == "write":
                            _, path, content, mode = item
                            staged = run / (hashlib.sha256(path.encode()).hexdigest()[:16])
                            staged.write_text(content)
                            os.chmod(staged, 0o644)
                            step("write", ["/usr/bin/install", "-m", mode, "-o", user, "-g", user, str(staged), path])
                        else:
                            _, path, target = item
                            step("symlink", ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/ln", "-sfn", target, path])
                # Addon and parked lab domains are unregistered: allow them only while the fixtures run.
                tweak_key = "key=allowunregistereddomains"
                original_tweak = probe.api(step("tweak-read", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "get_tweaksetting",
                                                               tweak_key]), "get_tweaksetting")["data"]["tweaksetting"]["value"]
                probe.api(step("tweak-allow", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "set_tweaksetting", tweak_key,
                                               "value=1"]), "set_tweaksetting")
                try:
                    for operation in scenario_operations():
                        kind = operation[0]
                        if kind == "whmapi":
                            probe.api(step("whmapi", ["/usr/local/cpanel/bin/whmapi1", "--output=json", *operation[1]]),
                                      operation[1][0])
                        elif kind == "cpapi2":
                            record = step("cpapi2", ["/usr/local/cpanel/bin/cpapi2", "--user=" + operation[1], "--output=json",
                                                     *operation[2]])
                            data = json.loads(record["stdout"])["cpanelresult"].get("data") or [{}]
                            if not data[0].get("result"):
                                raise ValueError("cPanel API 2 call failed: " + " ".join(operation[2][:2]) + ": "
                                                 + str(data[0].get("reason", ""))[:200])
                        elif kind == "uapi":
                            record = step("uapi", ["/usr/local/cpanel/bin/uapi", "--user=" + operation[1], "--output=json",
                                                   *operation[2]])
                            if json.loads(record["stdout"])["result"]["status"] != 1:
                                raise ValueError("UAPI call failed: " + " ".join(operation[2][:2]))
                        elif kind == "mkdir":
                            step("mkdir", ["/usr/bin/install", "-d", "-m", "0755", "-o", operation[1], "-g", operation[1],
                                           *operation[2]])
                        else:
                            _, user, path, content = operation
                            staged = run / hashlib.sha256((kind + path).encode()).hexdigest()[:16]
                            staged.write_text(content)
                            os.chmod(staged, 0o644)
                            if kind in ("write", "script"):
                                mode = "0755" if kind == "script" else "0644"
                                record = step(kind, ["/usr/bin/install", "-m", mode, "-o", user, "-g", user, str(staged), path])
                            else:
                                # As the tenant, with the content as an argument: root never writes through
                                # tenant-controlled paths, and the tenant cannot read the operator's home.
                                record = step("append", ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/sh", "-c",
                                                         'printf "%s" "$1" >> "$2"', "sh", content, path])
                            if record["exit_code"] != 0:
                                raise ValueError(f"{kind} failed for {path}: {record['stderr'][-200:]}")
                finally:
                    probe.api(step("tweak-restore", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "set_tweaksetting",
                                                     tweak_key, f"value={original_tweak}"]), "set_tweaksetting")
                # cPanel rebuilds httpd.conf and restarts Apache asynchronously after createacct; until then
                # the tenant vhost does not exist and observations would be meaningless.
                # cPanel quirk: after removeacct + createacct with the same name, an FPM reload keeps the
                # old pool socket owned by the previous uid, so Apache gets 503 until a full restart.
                # restartsrv_apache_php_fpm and cPanel's own reloads keep the inherited socket, so only a
                # full systemd restart recreates it; then each pool socket must belong to its tenant.
                # cPanel writes the FPM pools of new vhosts asynchronously (default_accounts_to_fpm).
                for attempt in range(36):
                    try:
                        fpm_pools()
                        break
                    except ValueError:
                        if attempt == 35:
                            raise
                        time.sleep(5)
                units = [f"{v}-php-fpm" for v in sorted(set(fpm_versions()))]
                if step("restart-fpm", ["/usr/bin/systemctl", "restart", *units], 300)["exit_code"]:
                    raise ValueError("PHP-FPM restart failed")
                for user, socket in fpm_sockets().items():
                    owner_name = step("fpm-socket-owner", ["/usr/bin/stat", "-c", "%U", socket])["stdout"].strip()
                    if owner_name != user:
                        raise ValueError(f"PHP-FPM socket {socket} belongs to {owner_name!r}, not {user}")
                rows = account_rows()
                ready = {}
                for _ in range(40):
                    for user, domain in TENANTS.items():
                        body = step("ready-" + user, ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "5",
                                    "--resolve", f"{domain}:80:{rows[user]['ip']}", f"http://{domain}/probe.php"])["stdout"]
                        ready[user] = f'"user":"{user}"' in body
                    for user, domain in TENANTS.items():
                        # cPanel installs each new vhost's self-signed certificate asynchronously.
                        ready["tls-" + domain] = step("ready-tls-" + domain, ["/usr/bin/test", "-f",
                                                      f"/var/cpanel/ssl/apache_tls/{domain}/combined"])["exit_code"] == 0
                    for name in EXTRA_DOCROOTS:
                        body = step("ready-" + name, ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "5",
                                    "--resolve", f"{name}:80:{rows['olscpa']['ip']}", f"http://{name}/static.txt"])["stdout"]
                        ready[name] = body == "static " + name + "\n"
                    if all(ready.values()):
                        break
                    time.sleep(5)
                if not all(ready.values()):
                    raise ValueError(f"Apache did not serve the new tenants: {ready}")
                (run / "nonce").write_text(nonce + "\n")
                summary["nonce_file"] = str(run / "nonce")
                summary["accounts"] = accounts()
                summary["result"] = "created" if summary["accounts"] == sorted(TENANTS) else "fail"
            elif args.observe:
                if present != sorted(TENANTS):
                    raise ValueError("Expected exactly the lab tenants, found: " + ",".join(present))
                perms = step("permissions", ["/usr/bin/stat", "-c", "%n %U:%G %a",
                                             *[p for u in TENANTS for p in ("/home/" + u, "/home/" + u + "/public_html")]])
                summary["permissions"] = perms["stdout"].splitlines()
                rows = account_rows()
                nonce = None
                results = {}
                for user, domain in TENANTS.items():
                    # cPanel binds account vhosts to the account IP, not loopback.
                    address = args.address or rows[user]["ip"]
                    for case, path in CASES.items():
                        record = step("get-" + user + "-" + case, ["/usr/bin/curl", "--noproxy", "*", "-s",
                                      "--max-time", "15", "-o", "/dev/stdout", "-w", "\n%{http_code}",
                                      "--resolve", f"{domain}:{args.port}:{address}",
                                      f"http://{domain}:{args.port}{path}"])
                        body, _, status = record["stdout"].rpartition("\n")
                        other = next(u for u in TENANTS if u != user)
                        results[user + ":" + case] = {"status": status, "leaked": leaked(case, body, other),
                                                      "body": body[:200]}
                summary["requests"] = results
                summary["cross_tenant_leaks"] = sorted(k for k, v in results.items() if v["leaked"])
                # Without working own-tenant responses an empty leak list proves nothing.
                summary["observation_valid"] = valid_observation(results)
                summary["result"] = "observed" if summary["observation_valid"] else "fail"
                if not summary["observation_valid"]:
                    summary["error"] = "own-tenant static/PHP requests did not succeed; observation is not meaningful"
            else:
                for user in TENANTS:
                    if user in present:
                        probe.api(step("removeacct-" + user, ["/usr/local/cpanel/bin/whmapi1", "--output=json",
                                       "removeacct", "username=" + user]), "removeacct")
                # The lab IPv6 range (cPanel unbinds an account's address when the account is removed).
                ranges = probe.api(step("ipv6-ranges", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "ipv6_range_list"]),
                                   "ipv6_range_list")["data"].get("range") or []
                if any(r.get("name") == IPV6_RANGE_NAME for r in ranges):
                    probe.api(step("ipv6-range-remove", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "ipv6_range_remove",
                                                         "name=" + IPV6_RANGE_NAME]), "ipv6_range_remove")
                summary["accounts"] = accounts()
                summary["result"] = "removed" if not summary["accounts"] else "fail"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        summary["finished_at"] = probe.now()
        probe.durable_json(run / "manifest.json", summary)
        print(json.dumps({"path": str(run), "result": summary["result"],
                          "leaks": summary.get("cross_tenant_leaks"), "error": summary.get("error")}))
    return 0 if summary["result"] in ("created", "observed", "removed") else 1

if __name__ == "__main__":
    sys.exit(main())
