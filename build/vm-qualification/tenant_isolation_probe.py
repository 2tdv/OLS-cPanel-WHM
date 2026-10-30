#!/usr/bin/python3
"""G0-C lab experiment: serve the two lab tenants through the product OLS build on a loopback
test listener (Apache keeps 80/443), run the cross-tenant fixture requests with the current
permissions, then after cPanel's own enablefileprotect runs while OLS is running (cPanel treats a
running /usr/local/lsws/bin/lswsctrl as a nobody-run web server and syncs docroots to
user:nobody 0750), then stops OLS and runs enablefileprotect again to prove the return path.
A traverse-only ACL is kept as a fallback mode (--acl). NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpanel_surface
import cpanel_vhosts
import fpm_translate
import htaccess_translate
import lscache
import modsec_translate
import ols_config_lint

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "php-parity"))
import compare
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES = pathlib.Path(__file__).resolve().parent / "ols-lab"
LSWS = owner.LSWS
PORT = 8088
TLS_PORT = 8443
TLS_DIR = "/var/cpanel/ssl/apache_tls"
# Names Apache serves from each tenant vhost (ServerName + ServerAlias of the :80 vhost).
ALIASES = ("", "www.", "mail.")
# Simulated external client: a network namespace behind a veth pair, so servers see a non-local
# peer. OLS (like Apache) only adds X-Forwarded-For for non-local peers, and cpsrvd only redirects
# proxied service-subdomain requests to HTTPS when it receives it.
NETNS, HOST_IF, NS_IF, HOST_IP, CLIENT_IP = "olscpc", "olscph", "olscpc0", "10.250.0.1", "10.250.0.2"
# IPv6 for the same simulated external client (owner decision HR-D06): a unique-local /64 on the link.
HOST_IP6, CLIENT_IP6 = "fd00:6c73:6370::1", "fd00:6c73:6370::2"
DEFAULT_PHP = "ea-php82"
# Access-control fixtures on tenant A (created through cPanel's DirectoryPrivacy API and .htaccess):
# (path, credentials or None) -> status Apache returned in the baseline.
# Legacy/compat .htaccess fixtures on tenant A: compared on status, X-Frame-Options and body.
# The second value is the Apache baseline the fixture must produce; otherwise equality is vacuous.
COMPAT = {"/uploads/shell.php": "403", "/uploads/pic.txt": "200", "/legacy/": "403", "/listing/": "200",
          "/noindex/": "403", "/missing-page": "404", "/static.txt": "200"}
# cPanel global web surface (G0-E, OLS-17) on tenant A: (host prefix, path, expected Apache status).
SURFACE = [("cpanel.", "/", "301"), ("webmail.", "/", "301"), ("webdisk.", "/", "302"), ("cpcalendars.", "/", "302"),
           ("cpcontacts.", "/", "302"), ("autoconfig.", "/", "200"), ("autodiscover.", "/", "302"),
           ("", "/cpanel", "301|200"), ("", "/whm", "301|200"), ("", "/webmail", "301|200"), ("", "/controlpanel", "301|200"),
           ("", "/securecpanel", "301|200"), ("", "/.htaccess", "403"), ("", "/.user.ini", "403"), ("", "/php.ini", "403"),
           ("", "/error_log", "403"), ("", "/.well-known/acme-challenge/" + tf.DCV_TOKEN, "200"),
           ("cpanel.", "/.well-known/acme-challenge/" + tf.DCV_TOKEN, "200"),
           # Global Alias/ScriptAlias directories, the tenant's /cgi-bin/ (suexec user) and /cpanelwebcall/.
           ("", "/img-sys/csf.svg", "200"), ("", "/img-sys/", "200"), ("", "/sys_cpanel/", "200"),
           ("", "/pipermail/", "200"), ("", "/mailman/archives/", "200"), ("", "/mailman/listinfo", "200"),
           ("", "/mailman/listinfo/nolist", "404"), ("", "/bandwidth/", "404", "status"), ("", "/java-sys/", "404", "status"),
           ("", "/cpanelwebcall/x", "400"), ("", "/cgi-bin/whoami.cgi", "200"), ("", "/Microsoft-Server-ActiveSync", "404"),
           # Unauthenticated upgrades reach cpsrvd's own answer (no session: redirect/login page).
           ("cpanel.", "/", "301", "ws"), ("webmail.", "/", "301", "ws"),
           # Catch-all proxy vhost ("=" is a literal host): names no tenant claims, DCV through get_local.cgi.
           ("whm.", "/", "301"), ("=cpanel.nowhere.example", "/", "301"), ("=webmail.nowhere.example", "/", "301"),
           # get_local.cgi fetches the file from SERVER_ADDR:80, which only OLS owns in production.
           ("whm.", "/.well-known/acme-challenge/" + tf.DCV_TOKEN, "200", "lab-port80"),
           ("=cpanel.nowhere.example", "/.well-known/acme-challenge/" + tf.DCV_TOKEN, "400"),
           ("=autoconfig.nowhere.example", "/", "200"), ("=autodiscover.nowhere.example", "/", "302"),
           ("=webdisk.nowhere.example", "/", "302"), ("whm.", "/", "301", "ws")]
# The same surface over HTTPS (Apache :443 vs the OLS external TLS listener). Status-only cases are
# answered by the front server itself (proxy error pages differ in markup).
SURFACE_TLS = [("cpanel.", "/", "200"), ("webmail.", "/", "200"), ("webdisk.", "/", "401"), ("cpcalendars.", "/", "401"),
               ("autoconfig.", "/", "200"), ("autodiscover.", "/", "400"), ("", "/Microsoft-Server-ActiveSync", "503", "status"),
               ("cpanel.", "/Microsoft-Server-ActiveSync", "404"), ("", "/cgi-bin/whoami.cgi", "200"),
               ("cpanel.", "/", "200", "ws"), ("webmail.", "/", "200", "ws"),
               ("whm.", "/", "200"), ("=cpanel.nowhere.example", "/", "200"), ("=webmail.nowhere.example", "/", "200"),
               ("=autoconfig.nowhere.example", "/", "200"),
               ("=autodiscover.nowhere.example", "/", "400"), ("=webdisk.nowhere.example", "/", "401"),
               ("whm.", "/", "200", "ws"), ("=cpanel.nowhere.example", "/", "200", "ws")]
WS_HEADERS = ["-H", "Connection: Upgrade", "-H", "Upgrade: websocket", "-H", "Sec-WebSocket-Version: 13",
              "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="]
# Lab-only WebSocket backend proving OLS's ws:// [P] proxy end to end (101, frames both ways).
WS_ECHO = pathlib.Path(__file__).resolve().parent / "ws_echo.py"
WS_ECHO_PORT = 18099
WS_ECHO_RULES = f"""RewriteCond %{{HTTP:Upgrade}} websocket [NC]
RewriteRule ^/?olscp-ws-echo/(.*)$ ws://127.0.0.1:{WS_ECHO_PORT}/$1 [P,L]
"""
# Multi-domain account (OLS-19): every name of tenant A's subdomain, addon and parked domains. Status
# is always compared; body and X-Frame-Options on 200 (OLS also sets Header values on error pages).
MULTI_HOSTS = [tf.SUBDOMAIN, "www." + tf.SUBDOMAIN, tf.ADDON, "www." + tf.ADDON, "mail." + tf.ADDON,
               f"{tf.ADDON_LABEL}.{tf.TENANTS['olscpa']}", tf.PARKED, "www." + tf.PARKED]
MULTI_PATHS = {"/static.txt": "200", "/whoami.php": "200", "/missing": "404", "/.env": "403"}
MULTI_SERVICE = [("cpanel." + tf.ADDON, "/", "301"), ("autoconfig." + tf.ADDON, "/", "200"),
                 ("cpanel." + tf.PARKED, "/", "301"), ("cpanel." + tf.SUBDOMAIN, "/", "301")]
# A docroot's realm and headers stop at the docroot under Apache: DCV stays reachable (cPanel's global
# "Satisfy Any" exclusion) and alias directories carry neither the realm nor the tenant's headers.
MULTI_SCOPE = [(tf.SECURE, "/static.txt", "401"), (tf.SECURE, "/missing", "401"),
               (tf.SECURE, "/.well-known/acme-challenge/" + tf.DCV_TOKEN, "200"), (tf.SECURE, "/img-sys/csf.svg", "200"),
               (tf.SECURE, "/cpanel", "301|200"), (tf.TENANTS["olscpa"], "/secure/static.txt", "401"),
               (tf.TENANTS["olscpa"], "/img-sys/csf.svg", "200"), (tf.TENANTS["olscpa"], "/mailman/listinfo", "200"),
               # WordPress rules live in the "/" context; aliases outside the docroot must not inherit them (RV-19).
               (tf.TENANTS["olscpb"], "/img-sys/csf.svg", "200"), (tf.TENANTS["olscpb"], "/mailman/listinfo", "200"),
               (tf.TENANTS["olscpb"], "/cgi-sys/defaultwebpage.cgi", "200"), (tf.TENANTS["olscpb"], "/cpanel", "301|200")]
# Rewrite fixtures on tenant B (WordPress-style .htaccess): compared on status, redirect and body.
REWRITE = {"/hello-world/": "200", "/2026/10/post/?p=5": "200", "/old-page": "301", "/static.txt": "200", "/index.php": "200",
           # Subdirectories: one without rewrite directives, one with its own rules (Apache decides).
           "/sub-noindex/real.txt": "200", "/sub-noindex/missing": "200|404", "/app/go": "200", "/app/missing": "200|404"}
APACHE_BODY = {"/hello-world/": '"front":"index.php"', "/app/go": "app-target", "/missing-page": "custom-404-page",
               "/static.txt": "static olscp"}
PROTECTION = {"private-anonymous": ("/private/", None), "private-authenticated": ("/private/", "alice:Lab-Only-Passw0rd-1"),
              "denied-dir": ("/denied/", None), "denied-dotenv": ("/.env", None)}
PROTECTION_BASELINE = {"private-anonymous": "401", "private-authenticated": "200", "denied-dir": "403", "denied-dotenv": "403"}
PARITY = pathlib.Path(__file__).resolve().parent / "php-parity"
LAB_RULES = {tf.TENANTS["olscpa"]: WS_ECHO_RULES}
RUNTIME_DIR = os.environ.get("OLS_LAB_RUNTIME_DIR", "/run/ols-cpanel/lshttpd")  # OLS DEFAULT_TMP_DIR (patch 0009); override only to test older builds
# Bandwidth accounting: a sparse file only OLS serves, fetched often enough to exceed all Apache
# traffic the probe itself causes, so cpanellogd growth of at least this much is OLS's.
BANDWIDTH_FILE, BANDWIDTH_BYTES, BANDWIDTH_FETCHES = "olscp-bandwidth.bin", 16 * 1024 * 1024, 2
BANDWIDTH_DB = "/var/cpanel/bandwidth/olscpa.sqlite"
# Documented deviations from Apache (review RV-06), "section:key" -> reason. Any other difference fails
# its case; an entry marked lab_limited is accepted only when it is listed here.
DCV_PATH = "/.well-known/acme-challenge/" + tf.DCV_TOKEN
KNOWN_DIFFERENCES = {
    "compat:/legacy/": "OLS also sends the context's Header set values (X-Frame-Options) on the 403 error response",
    "compat:/listing/": "the OLS directory-listing page carries no context headers (no X-Frame-Options)",
    "compat:/noindex/": "Options -Indexes gives the custom 404 on OLS where Apache answers 403; no listing is exposed",
    f"multi_domain:{tf.SECURE}{DCV_PATH}": "the DCV exemption under a protected docroot lacks the docroot's X-Frame-Options",
    f"surface:whm.{DCV_PATH}": "lab-port80: get_local.cgi fetches SERVER_ADDR:80, which is Apache in the lab (production probe covers it)",
    "tls:unknown.invalid": "the listener default certificate stays neutral (plan §12); Apache presents the first tenant vhost's",
}

def section_equal(summary, section):
    """Every entry of a comparison section equals Apache on a valid Apache baseline, except the known
    differences; even a listed difference must never turn an Apache refusal into a success on OLS."""
    entries = summary.get(section)
    if not isinstance(entries, dict) or not entries:
        return False
    for key, entry in entries.items():
        if entry.get("baseline_ok") is False:
            return False
        if entry.get("match") is True:
            continue
        apache, ols = entry.get("apache"), entry.get("ols")
        opened = (isinstance(apache, dict) and isinstance(ols, dict) and not str(apache.get("status")).startswith("2")
                  and str(ols.get("status")).startswith("2"))
        if f"{section}:{key}" not in KNOWN_DIFFERENCES or opened:
            return False
    return True

def expected_outcomes(summary):
    """Pass/fail per declared guarantee of a completed run (review RV-06)."""
    passes = summary.get("passes") or {}
    native = passes.get("native_fileprotect") or {}
    fifo = summary.get("fifo_tenant_write") or {}
    blockers = summary.get("htaccess_blockers") or {}
    logs = summary.get("log_accounting") or {}
    cases = {
        "native-fileprotect-valid-no-leaks": native.get("valid") is True and native.get("leaks") == [],
        # Before FileProtect the worker may be refused (403), but no pass may ever leak.
        "no-leaks-in-any-pass": bool(passes) and all(p.get("leaks") == [] for p in passes.values()),
        "php-primary-group-only": summary.get("lsphp_primary_group_only") is True,
        "cross-tenant-sockets-refused": summary.get("socket_cross_refused") is True,
        "fifo-tenant-write-refused": bool(fifo) and all(v == "PermissionError" for v in fifo.values()),
    }
    for user in tf.TENANTS:
        cases["php-parity-" + user] = ((summary.get("php_parity") or {}).get(user) or {}).get("equivalent") is True
    cases.update({
        "access-control-equal": section_equal(summary, "access_control"),
        "rewrite-equal": section_equal(summary, "rewrite"),
        "compat-equal-except-known": section_equal(summary, "compat"),
        "multi-domain-equal-except-known": section_equal(summary, "multi_domain"),
        "surface-equal-except-known": section_equal(summary, "surface"),
        "surface-tls-equal": section_equal(summary, "surface_tls"),
        "tls-certificates-equal-except-known": section_equal(summary, "tls"),
        "tls-default-not-tenant": summary.get("tls_default_is_not_tenant") is True,
        "https-content-equal": section_equal(summary, "https_content"),
        "websocket-proxy": (summary.get("websocket_proxy") or {}).get("ok") is True,
        "no-htaccess-blockers": bool(blockers) and not any(blockers.values()),
        "log-accounting": logs.get("combined_format") is True and logs.get("bytes_log_grew") is True,
        "bandwidth-counted": (summary.get("bandwidth") or {}).get("ok") is True,
        "no-ols-errors": summary.get("ols_log_errors") == [],
        "fileprotect-return-path": summary.get("enablefileprotect_running_exit") == 0
                                   and summary.get("enablefileprotect_stopped_exit") == 0
                                   and summary.get("return_matches_original") is True,
        "host-restored": summary.get("ownership_restored") is True and summary.get("removed") is True,
    })
    if "acl_traverse" in passes:
        cases["acl-traverse-valid-no-leaks"] = passes["acl_traverse"].get("valid") is True and passes["acl_traverse"].get("leaks") == []
    return cases

def default_plan():
    """One main vhost per lab tenant, as created by tenant_fixtures before any extra domains."""
    return {d: {"name": d, "user": u, "type": "main", "docroot": f"/home/{u}/public_html", "aliases": ["mail." + d, "www." + d],
                "php": DEFAULT_PHP, "pool": d, "service_domains": [d], "addons": [], "parked": []}
            for u, d in tf.TENANTS.items()}

def default_vhost_for(servername, plan, hostname):
    """OLS vhost answering for Apache's default ServerName on an address."""
    if servername in plan:
        return servername
    if servername.startswith("proxy-subdomains-vhost"):
        return cpanel_surface.PROXY_VHOST
    return cpanel_surface.DEFAULT_VHOST  # the server hostname vhost and anything else

QUIC_ON = "    quicEnable           1\n"
QUIC_OFF = "    quicEnable           0\n"

def server_config(base, hostname="localhost", plan=None, production=False, ipv6=(), apache_defaults=None, proxy_endpoints=(),
                  hybrid_ports=None, http3=True):
    """Product server policy from the ownership template, one OLS vhost per cPanel vhost, and either
    test listeners (Apache keeps 80/443) or, for the production-port experiment, *:80 and *:443."""
    plan = plan or default_plan()
    head = base[:base.index("extProcessor ea-php83 {")]
    # HTTP/3 (FV-04): the template enables QUIC; an operator opt-out turns it off at server level and on every
    # HTTPS listener (no Alt-Svc is advertised, no UDP socket is bound). A template without the key is refused.
    if QUIC_ON not in head:
        raise ValueError("the server template has no quicEnable 1 line")
    if not http3:
        head = head.replace(QUIC_ON, QUIC_OFF)
    quic = f"    enableQuic           {1 if http3 else 0}\n"
    if not production:
        head = head.replace("accessControl {\n    allow                ALL\n}\n",
                        f"accessControl {{\n    allow                127.0.0.1, {CLIENT_IP}\n    deny                 ALL\n}}\n")
    # LSCache (FV-01): the cache module off at server level; tenant vhosts enable it in their own block.
    parts = [head, lscache.server_block()]
    def vh(name, port):
        """The OLS vhost answering for a cPanel vhost on a port: hybrid vhosts have one per scheme."""
        return cpanel_surface.hybrid_tls_name(name) if port == 443 and plan[name].get("mode") == "apache" else name
    for name, v in plan.items():
        # vhRoot: the account's home on its /home<suffix> mount (cpanel_vhosts.account_home).
        home = cpanel_vhosts.account_home(v.get("docroot", ""), v["user"]) or f"/home/{v['user']}"
        for vhost in dict.fromkeys((name, vh(name, 443))):
            parts.append(f"""virtualHost {vhost} {{
    vhRoot               {home}/
    configFile           conf/vhosts/{vhost}/vhconf.conf
    allowSymbolLink      2
    enableScript         1
    restrained           1
    setUIDMode           2
}}
""")
        if v["service_domains"]:
            parts.append(cpanel_surface.service_server_block(name, v["user"], home))
    parts.append(cpanel_surface.proxy_server_block())
    if production:
        parts.append(cpanel_surface.default_server_block())
    parts.append(cpanel_surface.processors())
    hybrid = [(name, v["ip"]) for name, v in plan.items() if v.get("mode") == "apache"]
    if hybrid:
        parts.append(cpanel_surface.apache_backends(hybrid, hybrid_ports or (81, 444)))
    def all_maps(port):
        return "\n".join([f"    map                  {vh(name, port)} " + ", ".join([name, *v["aliases"]]) for name, v in plan.items()]
                      + [f"    map                  {cpanel_surface.service_vhost_name(name)} "
                         + ", ".join(h for d in v["service_domains"] for h in cpanel_surface.host_aliases(d))
                         for name, v in plan.items() if v["service_domains"]]
                      + [f"    map                  {cpanel_surface.PROXY_VHOST} " + ", ".join(cpanel_surface.proxy_hosts())])
    if production:
        # The listener default certificate stays neutral (plan §12); tenants answer with their own.
        # Like Apache's "Listen 0.0.0.0:port" + "Listen [::]:port" (RV-10, HR-D06). Apache picks vhosts by
        # local address: an unknown name gets the first vhost on that address and port. OLS selects only
        # by listener, and Linux refuses a specific listener beside a wildcard one on the same port, so
        # IPv6 gets one listener per bound address with that address's vhosts. IPv4 keeps one "*" listener
        # while every account vhost shares one IPv4 address (userdata "ip"); with several, each account
        # address gets its own listener with its own vhosts, and 127.0.0.1 (Apache's hostname and
        # proxy-subdomains vhosts) keeps its own. Recompile when cPanel adds or removes an address.
        defaults = apache_defaults or {}
        def wildcard(address, port):
            servername = defaults.get((address, port)) or defaults.get(("*", port)) or defaults.get(("*", None)) or ""
            default = default_vhost_for(servername, plan, hostname)
            return f"    map                  {vh(default, port) if default in plan else default} *"
        def own(mine, port):
            return [f"    map                  {vh(name, port)} " + ", ".join([name, *v["aliases"]]) for name, v in mine]
        def services(mine):
            return [f"    map                  {cpanel_surface.service_vhost_name(name)} "
                    + ", ".join(h for d in v["service_domains"] for h in cpanel_surface.host_aliases(d))
                    for name, v in mine if v["service_domains"]]
        def proxy(address, port):
            # Unclaimed service names are proxied only where cPanel binds its proxy-subdomains vhosts.
            return ([f"    map                  {cpanel_surface.PROXY_VHOST} " + ", ".join(cpanel_surface.proxy_hosts())]
                    if (address, port) in proxy_endpoints else [])
        ipv4 = sorted({v["ip"] for v in plan.values() if v.get("ip")})
        if len(ipv4) <= 1:
            listeners = [("", "*", ipv4[0] if ipv4 else "", {port: all_maps(port) for port in (80, 443)})]
        else:
            listeners = []
            loopback = [] if "127.0.0.1" in ipv4 else [("lo", "127.0.0.1")]
            for number, address in [*enumerate(ipv4), *loopback]:
                mine = [(name, v) for name, v in plan.items() if v.get("ip") == address]
                listeners.append((f"4-{number}", address, address,
                                  {port: "\n".join(own(mine, port) + services(mine) + proxy(address, port)) for port in (80, 443)}))
        for number, address in enumerate(ipv6):
            mine = [(name, v) for name, v in plan.items() if address in v.get("ipv6", [])]
            # Service names: the account SSL vhosts carry them on every address (HTTPS).
            listeners.append((f"6-{number}", f"[{address}]", address, {80: "\n".join(own(mine, 80) + proxy(address, 80)),
                                                                      443: "\n".join(own(mine, 443) + services(mine) + proxy(address, 443))}))
        for suffix, address, key, listener_maps in listeners:
            for kind, port, secure in (("http", 80, ""), ("https", 443, "1")):
                body = "\n".join(x for x in (listener_maps[port], wildcard(key, port)) if x)
                tls = ("    keyFile              $SERVER_ROOT/conf/cert/lab.key\n    certFile             $SERVER_ROOT/conf/cert/lab.crt\n"
                       + quic if secure else "")
                parts.append(f"listener {kind}{suffix} {{\n    address              {address}:{port}\n    secure               "
                             f"{secure or '0'}\n{tls}{body}\n}}\n")
        return "".join(parts)
    parts.append(f"listener tenants {{\n    address              127.0.0.1:{PORT}\n    secure               0\n{all_maps(80)}\n}}\n")
    parts.append(f"listener tenantsExternal {{\n    address              {HOST_IP}:{PORT}\n    secure               0\n{all_maps(80)}\n}}\n")
    # The listener default certificate is the lab's own, never a tenant certificate (plan §12).
    parts.append(f"listener tenantsTls {{\n    address              127.0.0.1:{TLS_PORT}\n    secure               1\n"
                 f"    keyFile              $SERVER_ROOT/conf/cert/lab.key\n    certFile             $SERVER_ROOT/conf/cert/lab.crt\n"
                 f"{quic}{all_maps(443)}\n}}\n")
    parts.append(f"listener tenantsTlsExternal {{\n    address              {HOST_IP}:{TLS_PORT}\n    secure               1\n"
                 f"    keyFile              $SERVER_ROOT/conf/cert/lab.key\n    certFile             $SERVER_ROOT/conf/cert/lab.crt\n"
                 f"{quic}{all_maps(443)}\n}}\n")
    return "".join(parts)

PHP_HANDLERS = ("fpm", "cgi", "fcgi", "suphp")

def php_environment(v):
    """Extra LSAPI environment reproducing the Apache PHP handler's INI loading (HR-D05). suPHP (as
    configured by cPanel) loads the docroot php.ini as the main file, then scans the global php.ini,
    php.d and the docroot (.user.ini, php.ini). lsphp ignores scan directories when PHPRC is set, so the
    same files are scanned in the same order after the global php.ini: identical effective values, only
    php_ini_loaded_file() names the global file. FPM, CGI and fcgid need nothing extra."""
    if v.get("php_handler", "fpm") != "suphp":
        return ""
    etc = f"/opt/cpanel/{v['php']}/root/etc"
    return f"    env                  PHP_INI_SCAN_DIR={etc}:{etc}/php.d:{v['docroot']}\n"

def vhost_config(v, pool="", constants=None, access="", tls=None, lab_rules="", missing=(), unset_headers=(),
                 error_log_dir="/var/lib/ols-cpanel-lab/logs", suspended=False, limits=None):
    # limits: the account's PHP limits (children, max_conns, mem_soft and mem_hard in bytes, proc_soft, proc_hard);
    # None is the built-in set the lab always used.
    limits = limits or {"children": 5, "max_conns": 5, "mem_soft": 0, "mem_hard": 0, "proc_soft": 400, "proc_hard": 500}
    user, name = v["user"], v["name"]
    handlers = "\n".join(f"    add                  lsapi:{user}-php {s}" for s in fpm_translate.suffixes(pool))
    return f"""docRoot                  {v["docroot"]}/
vhDomain                 {name}
errorlog {error_log_dir}/{name}-error.log {{
    useServer            0
    logLevel             INFO
}}
index {{
    useServer            0
    indexFiles           index.html, index.php
    # Mirrors the lab Apache, which lists directories unless "Options -Indexes" applies.
    autoIndex            1
}}
extProcessor {user}-php {{
    type                 lsapi
    address              uds:/{RUNTIME_DIR}/{name}-php.sock
    maxConns             {limits["max_conns"]}
    env                  PHP_LSAPI_CHILDREN={limits["children"]}
    env                  LSPHP_ENABLE_USER_INI=on
    env                  LSAPI_MAX_IDLE=10
{php_environment(v)}    initTimeout          60
    retryTimeout         0
    persistConn          1
    respBuffer           0
    autoStart            2
    path                 /opt/cpanel/{v["php"]}/root/usr/bin/lsphp
    extUser              {user}
    extGroup             {user}
    backlog              50
    instances            1
    memSoftLimit         {limits["mem_soft"]}
    memHardLimit         {limits["mem_hard"]}
    procSoftLimit        {limits["proc_soft"]}
    procHardLimit        {limits["proc_hard"]}
}}
scripthandler {{
{handlers}
}}
rewrite {{
    enable               1
    autoLoadHtaccess     0
    rules                <<<END_rules
{cpanel_surface.suspension_rules(missing) if suspended else ""}{lscache.vhost_rules(v, suspended)}{lab_rules}{cpanel_surface.rewrite_rules([])}END_rules
}}
{cpanel_surface.contexts(missing, unset_headers)}{cpanel_surface.access_logs(name)}
""" + fpm_translate.override_block(fpm_translate.translate(pool, constants)) + access + (
        f"vhssl {{\n    keyFile              {tls}\n    certFile             {tls}\n    certChain            1\n}}\n" if tls else "") + (
        lscache.vhost_block(v, suspended))

def htaccess_listing(user, docroot):
    """The tenant's own listing of every .htaccess under its docroot (the docroot itself followed, as OLS
    serves it): regular files and symlinks alike, each NUL-terminated and prefixed with its type
    letter ("f" or "l") so that a symlinked .htaccess becomes a blocker instead of being skipped."""
    return ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", "-H", docroot, "-name", ".htaccess",
            "(", "-type", "f", "-o", "-type", "l", ")", "-printf", "%y%p\\0"]

def compile_lab(step, summary, production=False, hybrid_ports=None, security=None, http3=True):
    """Discover every cPanel vhost of the lab tenants and compile the OLS configuration (shared
    by the test-listener probe and the production-port probe). Raises on any refusal or lint error.
    `security`: the product security input (FV-02, modsec_translate.policy); None compiles without the WAF
    and security part and reads none of its inputs. `http3`: QUIC on the HTTPS listeners (FV-04, the operator
    input /var/lib/ols-cpanel/http3.json; absent means enabled)."""
    # Every cPanel vhost of each account (main, subdomains, addon vhosts; parked domains are
    # aliases) from /etc/userdatadomains and the per-vhost userdata (OLS-19).
    rows = cpanel_vhosts.parse_userdatadomains(step("userdatadomains", ["/usr/bin/cat", "/etc/userdatadomains"])["stdout"])
    plan, userdata_texts = {}, {}
    for user in tf.TENANTS:
        names = [d for d, r in rows.items() if r["user"] == user and r["type"] in ("main", "sub")]
        bad = [n for n in names if not cpanel_vhosts.DOMAIN.match(n)]
        if bad:  # validate before the name becomes part of a path read as root
            raise ValueError(f"invalid vhost names for {user}: {bad[:5]}")
        userdata = {n: step("userdata-" + n, ["/usr/bin/cat", f"/var/cpanel/userdata/{user}/{n}"])["stdout"] for n in names}
        userdata_texts.update(userdata)
        for v in cpanel_vhosts.account_vhosts(user, rows, userdata):
            plan[v["name"]] = dict(v, user=user)
    # PHP handler per vhost (HR-D05): PHP-FPM where cPanel enabled it, otherwise the version's handler.
    fpm = {row["vhost"]: bool(row.get("php_fpm")) for row in probe.api(step("php-vhost-versions", [
        "/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_vhost_versions"]), "php_get_vhost_versions")["data"]["versions"]}
    version_handlers = {row["version"]: row["current_handler"] for row in probe.api(step("php-handlers", [
        "/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_handlers"]), "php_get_handlers")["data"]["version_handlers"]}
    for name, v in plan.items():
        # cPanel reports an addon domain's vhost under the addon name (its FPM pool name), not the subdomain.
        v["php_handler"] = "fpm" if fpm.get(v["pool"], fpm.get(name)) else version_handlers.get(v["php"], "unknown")
        v["mode"] = "native"
        if v["php_handler"] not in PHP_HANDLERS:
            if not hybrid_ports:
                raise ValueError(f"unsupported PHP handler {v['php_handler']!r} for {name} (domain must stay on Apache)")
            v["mode"] = "apache"
    summary["vhosts"] = {n: {k: v[k] for k in ("user", "type", "docroot", "aliases", "php", "php_handler", "pool", "service_domains")}
                         for n, v in plan.items()}
    # userdata holds the local (bindable) address; listaccts reports the public NAT address.
    local_ips = {plan[d]["user"]: plan[d]["ip"] for d in tf.TENANTS.values()}
    bad_php = sorted({v["php"] for v in plan.values() if not re.fullmatch(r"[a-z][a-z0-9-]*", v["php"] or "")})
    if bad_php:  # the version becomes part of paths and of a binary run as root
        raise ValueError(f"invalid PHP versions: {bad_php}")
    versions = {u: plan[d]["php"] for u, d in tf.TENANTS.items()}
    # Suspended accounts (cPanel's marker file) get cPanel's suspended-page redirect.
    suspended = {u for u in tf.TENANTS if step("suspended-" + u, ["/usr/bin/test", "-e", f"/var/cpanel/suspended/{u}"])["exit_code"] == 0}
    for v in plan.values():
        v["suspended"] = v["user"] in suspended
    summary["suspended_accounts"] = sorted(suspended)
    # Apache must already run each tenant's PHP as the tenant; otherwise every PHP comparison is
    # vacuous (e.g. a stale FPM socket left by a previous account incarnation gives 503).
    for user, domain in tf.TENANTS.items():
        if user in suspended:
            continue
        served = step("apache-php-" + user, ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "15",
                                             "--resolve", f"{domain}:80:{local_ips[user]}", f"http://{domain}/probe.php"])
        if f'"user":"{user}"' not in served["stdout"]:
            raise ValueError(f"Apache does not serve PHP as {user}; fix the baseline first")
    # The cPanel-generated FPM pool is the effective per-vhost PHP policy Apache applies; an
    # addon vhost's pool is named after the addon domain.
    pools = {}
    pool_unreadable = []
    for n, v in plan.items():
        read = step("fpm-pool-" + n, ["/usr/bin/cat", f"/opt/cpanel/{v['php']}/root/etc/php-fpm.d/{v['pool']}.conf"])
        if read["exit_code"] != 0 and v["php_handler"] == "fpm":
            # Without the pool its php_admin_* limits (e.g. disable_functions) would silently disappear. HR-D14:
            # with the hybrid profile only this vhost moves to Apache, which applies the pool itself.
            if not hybrid_ports:
                raise ValueError(f"PHP-FPM pool of {n} is unreadable")
            plan[n]["mode"] = "apache"
            pool_unreadable.append(n)
        pools[n] = read["stdout"] if read["exit_code"] == 0 else ""
    summary["php_versions"] = versions
    # E_* values come from the exact target PHP; no expression is ever executed.
    constants = {}
    for version in {v["php"] for v in plan.values()}:
        code = 'echo json_encode(array_filter(get_defined_constants(true)["Core"], fn($k) => str_starts_with($k, "E_"), ARRAY_FILTER_USE_KEY));'
        constants[version] = json.loads(step("constants-" + version, [f"/opt/cpanel/{version}/root/usr/bin/php", "-n", "-r", code])["stdout"])
    summary["php_overrides"] = {n: fpm_translate.translate(pools[n], constants[v["php"]]) for n, v in plan.items()}
    # Access control from every .htaccess under the docroot (OLS-16), read with the tenant's own
    # privileges. Apache (AllowOverride All on "/") also applies .htaccess files in every
    # directory above the docroot, so their text leads the docroot's own; unknown directives
    # are blockers.
    access, root_headers, summary["htaccess_blockers"] = {}, {}, {}
    # RV-46: Apache's loaded modules decide every <IfModule>; unknown (the command failed): only the modules
    # EasyApache 4 always loads are assumed, as before.
    listed = step("httpd-modules", ["/usr/sbin/httpd", "-M"])
    modules = None
    if listed["exit_code"] == 0:
        modules = re.findall(r"^\s*([A-Za-z0-9_]+_module)\s+\((?:static|shared)\)\s*$", listed["stdout"], re.M) or None
    for name, v in plan.items():
        user, docroot = v["user"], v["docroot"]
        # Fail closed (review F-03): a directory the tenant cannot list or a file it cannot read is a
        # blocker, never an empty .htaccess; NUL-separated names keep paths with spaces intact.
        listing = step("htaccess-list-" + name, htaccess_listing(user, docroot))
        found = [p for p in listing["stdout"].split("\0") if p]
        files, read_blockers = {}, []
        if listing["exit_code"] != 0:
            read_blockers.append(f"/: .htaccess scan incomplete ({listing['stderr'].strip()[-160:]})")
        for entry in found:
            kind, path = entry[:1], entry[1:]
            rel = path[len(docroot):].rsplit("/", 1)[0].strip("/")
            if kind != "f":
                # OLS no longer reads .htaccess itself, so a symlinked one would silently lose its
                # restrictions; never follow it.
                read_blockers.append(f"/{rel + '/' if rel else ''}: .htaccess is a symlink")
                continue
            read = step("htaccess-read-" + name, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/cat", path])
            if read["exit_code"] != 0:
                read_blockers.append(f"/{rel + '/' if rel else ''}: .htaccess unreadable")
                continue
            files[rel] = read["stdout"]
        inherited = []
        for directory in cpanel_vhosts.ancestors(v):
            # The account's home and everything below it, on any /home* mount, is read as the account (by
            # whole path components: "/home/olscpa" is not inside user "olsc"); only "/" and the mount are root's.
            parts = directory.strip("/").split("/")
            in_home = len(parts) >= 2 and cpanel_vhosts.HOME_MOUNT.fullmatch(parts[0]) is not None and parts[1] == user
            as_user = ["/usr/sbin/runuser", "-u", user, "--"] if in_home else []
            read = step("htaccess-ancestor-" + name, [*as_user, "/usr/bin/cat", directory.rstrip("/") + "/.htaccess"])
            if read["exit_code"] == 0:
                inherited.append(read["stdout"])
        if inherited:
            files[""] = "\n".join([*inherited, files.get("", "")])
        # RV-44: cPanel marks every response of a technical domain (its temporary *.cpanel.site names) "noindex".
        names = [name, *v.get("aliases", [])]
        technical = all(re.fullmatch(r"(?:(?:.*\.)?cpanel\.site)", n, re.I) for n in names)
        realms, contexts, blockers = htaccess_translate.translate(files, docroot, modules,
                                                                  ['Header set X-Robots-Tag "noindex, nofollow"'] if technical else None)
        access[name] = "".join(realms + contexts)
        root_headers[name] = htaccess_translate.root_header_names(contexts)
        summary["htaccess_blockers"][name] = read_blockers + blockers
    # Blockers are enforced (review F-03): a vhost whose .htaccess cannot be translated completely is never
    # served by OLS. Until the hybrid profile (HR-D08) can keep that domain on Apache, compilation stops.
    blocked = {n: b for n, b in summary["htaccess_blockers"].items() if b}
    if blocked and not hybrid_ports:
        raise ValueError("untranslatable .htaccess (domain must stay on Apache): " + json.dumps(blocked)[:400])
    for name in blocked:
        plan[name]["mode"] = "apache"  # hybrid profile (HR-D08): Apache keeps serving this vhost
    summary["hybrid_vhosts"] = sorted(n for n, v in plan.items() if v["mode"] == "apache")
    if pool_unreadable:
        summary["hybrid_reasons"] = {n: ["PHP-FPM pool unreadable"] for n in sorted(pool_unreadable)}
    # Apache's mod_php (handler "dso") runs tenant code as "nobody", the identity OLS uses to reach Apache's
    # backend ports; such a tenant could bypass OLS and forge the trusted client address (review RV-28).
    # HR-D14: only that vhost is held (no earlier generation in the lab: it stays served by Apache as before).
    shared = sorted(n for n in summary["hybrid_vhosts"] if plan[n]["php_handler"] == "dso")
    if shared:
        summary["held_vhosts"] = {n: ["PHP handler dso on a site that needs Apache",
                                      "served by Apache as before (no earlier OpenLiteSpeed configuration)"] for n in shared}
    # cPanel's installed certificate per vhost: one PEM with key and certificate (and chain).
    tls = {}
    for name in plan:
        combined = f"{TLS_DIR}/{name}/combined"
        tls[name] = combined if step("tls-present-" + name, ["/usr/bin/test", "-f", combined])["exit_code"] == 0 else None
    summary["tls_sources"] = tls
    hostname = step("hostname", ["/usr/bin/hostname", "-f"])["stdout"].strip()
    ipv6, defaults = (), None
    if production:
        # Per-address defaults from cPanel's generated Apache configuration, and the bound IPv6 addresses.
        def required(name, command):
            read = step(name, command)
            if read["exit_code"] != 0:
                raise ValueError(f"cannot read {' '.join(command[1:])}: listener defaults would be guessed")
            return read["stdout"]
        httpd_conf = required("apache-conf", ["/usr/bin/cat", "/etc/apache2/conf/httpd.conf"])
        defaults = cpanel_vhosts.apache_defaults(httpd_conf)
        ipv6 = cpanel_vhosts.bound_ipv6(required("ipv6-addresses", ["/usr/sbin/ip", "-6", "-o", "addr", "show", "scope", "global"]))
        proxy_endpoints = cpanel_vhosts.apache_proxy_endpoints(httpd_conf)
        summary["ipv6_addresses"], summary["apache_defaults"] = ipv6, {f"{a}:{p}": n for (a, p), n in defaults.items()}
        summary["apache_proxy_endpoints"] = [f"{a}:{p}" for a, p in proxy_endpoints]
    else:
        proxy_endpoints = []
    config = server_config((TEMPLATES / "ownership_httpd_config.conf").read_text(), hostname, plan, production, ipv6, defaults,
                           proxy_endpoints, hybrid_ports=hybrid_ports, http3=http3)
    # Alias directories absent on this host (and a vhost's deleted cgi-bin) get no context.
    missing = {}
    for name, v in plan.items():
        dirs = {**cpanel_surface.STATIC_ALIASES, **cpanel_surface.CGI_ALIASES, "/cgi-bin/": v["docroot"] + "/cgi-bin/"}
        missing[name] = [uri for uri, path in dirs.items()
                         if step("alias-dir", ["/usr/bin/test", "-d", path])["exit_code"] != 0]
    summary["missing_alias_dirs"] = missing
    vhconf = {n: (cpanel_surface.apache_vhost(v["docroot"], n, v["ip"], tls[n], "/var/lib/ols-cpanel-lab/logs",
                                              hybrid_ports or (81, 444))
                  if v.get("mode") == "apache" else
                  vhost_config(v, pools[n], constants[v["php"]], access[n], tls[n], "" if production else LAB_RULES.get(n, ""),
                               missing[n], root_headers[n], suspended=v["suspended"])) for n, v in plan.items()}
    for n, v in plan.items():
        if v.get("mode") == "apache":
            vhconf[cpanel_surface.hybrid_tls_name(n)] = cpanel_surface.apache_vhost(
                v["docroot"], n, v["ip"], tls[n], "/var/lib/ols-cpanel-lab/logs", hybrid_ports or (81, 444), secure=True)
            # LSCache (FV-01): both pass-through vhosts of a hybrid domain never use the cache.
            for name in (n, cpanel_surface.hybrid_tls_name(n)):
                vhconf[name] += lscache.disabled_block()
        if v["service_domains"]:
            vhconf[cpanel_surface.service_vhost_name(n)] = cpanel_surface.service_vhost(v["docroot"], v["service_domains"], tls[n])
    # The service certificate cPanel's Apache currently uses (it moves to mycpanel.pem once installed).
    cert = next(c for c in cpanel_surface.SERVICE_CERTS
                if c == cpanel_surface.SERVICE_CERTS[-1] or step("service-cert", ["/usr/bin/test", "-f", c])["exit_code"] == 0)
    summary["service_cert"] = cert
    summary["cache"] = lscache.summary(plan, suspended)
    vhconf[cpanel_surface.PROXY_VHOST] = cpanel_surface.proxy_vhost(cert)
    if production:
        default_missing = [uri for uri, path in {**cpanel_surface.STATIC_ALIASES, **cpanel_surface.CGI_ALIASES}.items()
                           if step("alias-dir", ["/usr/bin/test", "-d",
                                                 path.replace("$DOC_ROOT/", cpanel_surface.PROXY_DOCROOT)])["exit_code"] != 0]
        vhconf[cpanel_surface.DEFAULT_VHOST] = cpanel_surface.default_vhost(cert, default_missing)
    if security is not None:
        # FV-02 (kept apart from the other compiler steps): cPanel's ModSecurity, per-domain disables and the
        # product security input; any blocker refuses the compilation (the current state is kept).
        secured = modsec_translate.compile_security(step, plan, userdata_texts, security, list(vhconf), cpanel_surface.PROXY_VHOST,
                                                    cpanel_surface.service_vhost_name, cpanel_surface.hybrid_tls_name)
        config = modsec_translate.apply_server(config, secured)
        for name, block in secured["vhosts"].items():
            vhconf[name] += block
        summary.update(secured["summary"])
    lint = ols_config_lint.lint(config) + [e for c in vhconf.values() for e in ols_config_lint.lint(c, False)]
    if lint:
        raise ValueError("Generated configuration fails lint: " + "; ".join(lint))
    return {"plan": plan, "local_ips": local_ips, "versions": versions, "config": config, "vhconf": vhconf,
            "missing": missing}

def place_configs(step, stage_file, config, vhconf):
    """Install the compiled configuration and the neutral lab default certificate."""
    step("place-config", ["/usr/bin/install", "-m", "0600", stage_file("httpd_config.conf", config),
                          LSWS + "/conf/httpd_config.conf"])
    for user in vhconf:
        step("vhost-dir-" + user, ["/usr/bin/install", "-d", "-m", "0750", LSWS + "/conf/vhosts/" + user])
        step("vhconf-" + user, ["/usr/bin/install", "-m", "0600", stage_file(user + ".vhconf", vhconf[user]),
                                LSWS + "/conf/vhosts/" + user + "/vhconf.conf"])
    step("log-dir", ["/usr/bin/install", "-d", "-m", "0755", owner.WEB, owner.WEB + "/logs"])
    step("cert-dir", ["/usr/bin/install", "-d", "-m", "0750", LSWS + "/conf/cert"])
    step("lab-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                      "-subj", "/CN=ols-cpanel-lab-default", "-keyout", LSWS + "/conf/cert/lab.key",
                      "-out", LSWS + "/conf/cert/lab.crt"])

def netns_up(step):
    """The simulated external client (see NETNS)."""
    for command in (["/usr/sbin/ip", "netns", "add", NETNS],
                    ["/usr/sbin/ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF],
                    ["/usr/sbin/ip", "link", "set", NS_IF, "netns", NETNS],
                    ["/usr/sbin/ip", "addr", "add", HOST_IP + "/30", "dev", HOST_IF],
                    ["/usr/sbin/ip", "link", "set", HOST_IF, "up"],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "addr", "add", CLIENT_IP + "/30", "dev", NS_IF],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "link", "set", NS_IF, "up"],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "link", "set", "lo", "up"],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "route", "add", "default", "via", HOST_IP],
                    ["/usr/sbin/ip", "-6", "addr", "add", HOST_IP6 + "/64", "dev", HOST_IF, "nodad"],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "-6", "addr", "add", CLIENT_IP6 + "/64", "dev", NS_IF, "nodad"],
                    ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/sbin/ip", "-6", "route", "add", "default", "via", HOST_IP6]):
        if step("netns", command)["exit_code"]:
            raise ValueError("Unable to build the external-client namespace: " + " ".join(command[1:4]))

def netns_down(step):
    step("netns-delete", ["/usr/sbin/ip", "netns", "delete", NETNS])
    step("veth-delete", ["/usr/sbin/ip", "link", "delete", HOST_IF])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    parser.add_argument("--acl", action="store_true", help="test the traverse-only ACL fallback instead")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Requires exactly the lab tenants from tenant_fixtures.py; pass --lab-tenants")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("tenant-isolation-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "tenant-isolation-experiment", "started_at": probe.now(),
                   "g0_c": "unproven", "result": "not_run", "passes": {}}
        index = 0

        def step(name, command, limit=120):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def stage_file(name, content):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            return str(path)

        def ownership():
            paths = [p for u in tf.TENANTS for p in ("/home/" + u, "/home/" + u + "/public_html")]
            return (step("ownership", ["/usr/bin/stat", "-c", "%n %U %G %a", *paths])["stdout"]
                    + step("acls", ["/usr/bin/getfacl", "-p", *paths])["stdout"])

        def observe(label):
            results = {}
            for user, domain in tf.TENANTS.items():
                other = next(u for u in tf.TENANTS if u != user)
                for case, path in tf.CASES.items():
                    record = step(f"{label}-{user}-{case}", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "20",
                                  "-w", "\n%{http_code}", "--resolve", f"{domain}:{PORT}:127.0.0.1",
                                  f"http://{domain}:{PORT}{path}"])
                    body, _, status = record["stdout"].rpartition("\n")
                    results[user + ":" + case] = {"status": status, "leaked": tf.leaked(case, body, other),
                                                  "body": body[:160]}
            return {"valid": tf.valid_observation(results),
                    "leaks": sorted(k for k, v in results.items() if v["leaked"]), "requests": results}

        installed = changed = netns = False
        parity_files = []
        original = None
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if step("residue", ["/usr/bin/ls", "-d", LSWS])["stdout"].strip():
                raise ValueError("OLS residue present")
            original = ownership()
            summary["original_ownership"] = original.splitlines()
            compiled = compile_lab(step, summary)
            plan, local_ips, versions = compiled["plan"], compiled["local_ips"], compiled["versions"]
            config, vhconf = compiled["config"], compiled["vhconf"]
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            place_configs(step, stage_file, config, vhconf)
            netns = True
            netns_up(step)
            if step("start", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(3)
            summary["passes"]["current_permissions"] = observe("current")
            changed = True
            if args.acl:
                for user in tf.TENANTS:
                    step("acl-" + user, ["/usr/bin/setfacl", "-m", "u:nobody:x", "/home/" + user + "/public_html"])
                summary["passes"]["acl_traverse"] = observe("acl")
            # cPanel-native path: FileProtect sync while the LiteSpeed control script reports running.
            summary["lswsctrl_status"] = step("lswsctrl-status", [LSWS + "/bin/lswsctrl", "status"])["stdout"].strip()
            summary["enablefileprotect_running_exit"] = step("enablefileprotect-running",
                                                             ["/usr/local/cpanel/scripts/enablefileprotect"], 300)["exit_code"]
            summary["native_ownership"] = ownership().splitlines()
            # RV-17: OLS derives a vhost's suEXEC identity when it loads the configuration. Restart it so
            # every PHP process starts from the FileProtect ownership (group nobody on public_html);
            # before patch 0008 the PHP processes then ran with gid nobody and read other tenants' files.
            if step("restart-after-fileprotect", ["/usr/bin/systemctl", "restart", owner.UNIT])["exit_code"]:
                raise ValueError("OLS restart after FileProtect failed")
            time.sleep(3)
            summary["passes"]["native_fileprotect"] = observe("native")
            # Identity of every PHP process while the isolation pass runs (real/effective/saved/fs ids, groups).
            identities = step("lsphp-identity", ["/usr/bin/sh", "-c", "for p in $(/usr/bin/pgrep -x lsphp); do "
                              "printf '%s ' $p; /usr/bin/grep -E '^(Uid|Gid|Groups):' /proc/$p/status | /usr/bin/tr -s '\\t\\n' '  '; echo; done"])
            summary["lsphp_identities"] = identities["stdout"].splitlines()
            summary["lsphp_primary_group_only"] = tf.primary_group_only(summary["lsphp_identities"])
            # RV-04: OLS runtime state and each tenant's LSAPI socket. A tenant that can connect to another
            # tenant's socket can ask that PHP process to run a script with the other tenant's identity.
            summary["runtime_modes"] = step("runtime-modes", ["/usr/bin/sh", "-c", 'stat -c "%n %U %G %a %F" "$1" "$1"/*',
                                                              "sh", RUNTIME_DIR])["stdout"].splitlines()
            summary["socket_cross_connect"] = {}
            sockets = [line.split()[0] for line in summary["runtime_modes"] if line.endswith(" socket")]
            for path in sockets:
                vhost = path.rsplit("/", 1)[1][:-len("-php.sock")]
                owner_user = summary["vhosts"].get(vhost, {}).get("user")
                for user in tf.TENANTS:
                    if user == owner_user:
                        continue
                    attempt = step("cross-socket-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/python3", "-I", "-c",
                                   "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1]); print('connected')\n"
                                   "except OSError as e:\n print(type(e).__name__)", path])
                    summary["socket_cross_connect"][f"{user}->{vhost}"] = attempt["stdout"].strip()
            summary["socket_cross_refused"] = bool(sockets) and all(v == "PermissionError"
                                                                    for v in summary["socket_cross_connect"].values())
            # G0-D per tenant: the same full probe through Apache (account IP :80) and OLS (test listener).
            rows = probe.api(step("listaccts-ip", probe.COMMANDS["accounts_api"]), "listaccts")["data"]["acct"]
            summary["listaccts_ips"] = {row["user"]: row["ip"] for row in rows}
            ips = local_ips
            parity = {}
            for user, domain in tf.TENANTS.items():
                target = f"/home/{user}/public_html/olscp-parity.php"
                parity_files.append(target)
                step("place-parity-" + user, ["/usr/bin/install", "-m", "0644", "-o", user, "-g", user,
                                              str(PARITY / "probe.php"), target])
                fetched = {}
                for name, port, address in (("apache", 80, ips[user]), ("ols", PORT, "127.0.0.1")):
                    record = step(f"parity-{name}-{user}", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "20",
                                  "--resolve", f"{domain}:{port}:{address}", f"http://{domain}:{port}/olscp-parity.php"])
                    fetched[name] = json.loads(record["stdout"])
                # suPHP: the same INI files in the same effective order, but lsphp names the global php.ini as
                # the loaded file (see php_environment); every value must still be identical.
                suphp = plan[domain].get("php_handler") == "suphp"
                report = compare.compare(fetched["apache"], fetched["ols"], test_binding={
                    "SERVER_PORT": str(PORT), "HTTP_HOST": f"{domain}:{PORT}", "REMOTE_ADDR": "127.0.0.1"},
                    expected_fields=("ini_loaded",) if suphp else ())
                # The cPanel MultiPHP INI directive of each tenant (fixtures) must be in effect on both sides,
                # otherwise equality could come from both ignoring it (HR-D05: FPM pool vs CGI .user.ini).
                expected_memory = tf.MEMORY_LIMITS.get(user)
                parity[user] = {"equivalent": report["equivalent"] and all(
                                    f["ini"].get("memory_limit") == expected_memory for f in fetched.values()),
                                "handler": fetched["apache"]["sapi"],
                                "memory_limit": {k: f["ini"].get("memory_limit") for k, f in fetched.items()},
                                "reference": {k: fetched["apache"][k] for k in ("sapi", "version", "user", "ini_loaded", "ini_scanned")},
                                "candidate": {k: fetched["ols"][k] for k in ("sapi", "version", "user", "ini_loaded", "ini_scanned")},
                                "unexpected": [d for d in report["differences"] if not d["expected"]]}
            summary["php_parity"] = parity
            # G0-C/G0-E access control: identical status codes under Apache and OLS, or a finding.
            protection = {}
            domain = tf.TENANTS["olscpa"]
            for case, (path, credentials) in PROTECTION.items():
                statuses = {}
                for name, port, address in (("apache", 80, ips["olscpa"]), ("ols", PORT, "127.0.0.1")):
                    command = ["/usr/bin/curl", "--noproxy", "*", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                               "--max-time", "15", "--resolve", f"{domain}:{port}:{address}", f"http://{domain}:{port}{path}"]
                    if credentials:
                        command[1:1] = ["-u", credentials]
                    statuses[name] = step(f"protect-{name}-{case}", command)["stdout"]
                protection[case] = dict(statuses, match=statuses["apache"] == statuses["ols"],
                                        baseline_ok=statuses["apache"] == PROTECTION_BASELINE[case])
            summary["access_control"] = protection
            rewrite, domain = {}, tf.TENANTS["olscpb"]
            for path in REWRITE:
                seen = {}
                for name, port, address in (("apache", 80, ips["olscpb"]), ("ols", PORT, "127.0.0.1")):
                    record = step(f"rewrite-{name}", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "15",
                                  "-w", "\n%{http_code} %{redirect_url}", "--resolve", f"{domain}:{port}:{address}",
                                  f"http://{domain}:{port}{path}"])
                    body, _, tail = record["stdout"].rpartition("\n")
                    status, _, location = tail.partition(" ")
                    # Normalize the test listener port so only real differences remain.
                    location = location.replace(f":{PORT}/", "/")
                    seen[name] = {"status": status, "location": location,
                                  "body": body[:200] if status == "200" else ""}
                rewrite[path] = dict(seen, match=seen["apache"] == seen["ols"],
                                     baseline_ok=seen["apache"]["status"] in REWRITE[path].split("|")
                                     and APACHE_BODY.get(path, "") in seen["apache"]["body"])
            summary["rewrite"] = rewrite
            compat, domain = {}, tf.TENANTS["olscpa"]
            for path in COMPAT:
                seen = {}
                for name, port, address in (("apache", 80, ips["olscpa"]), ("ols", PORT, "127.0.0.1")):
                    record = step(f"compat-{name}", ["/usr/bin/curl", "--noproxy", "*", "-s", "-D", "-", "--max-time", "15",
                                  "-w", "\n%{http_code}", "--resolve", f"{domain}:{port}:{address}",
                                  f"http://{domain}:{port}{path}"])
                    raw, _, status = record["stdout"].rpartition("\n")
                    head, _, body = raw.partition("\r\n\r\n")
                    xfo = [l.split(":", 1)[1].strip() for l in head.splitlines() if l.lower().startswith("x-frame-options:")]
                    listing = "<a href" in body.lower() and ("a.txt" in body or "b.txt" in body)
                    seen[name] = {"status": status, "x_frame_options": xfo[0] if xfo else None,
                                  "body": ("<listing>" if listing else body[:80]) if status in ("200", "404") else ""}
                compat[path] = dict(seen, match=seen["apache"] == seen["ols"],
                                    baseline_ok=seen["apache"]["status"] == COMPAT[path]
                                    and APACHE_BODY.get(path, "") in seen["apache"]["body"])
            summary["compat"] = compat
            def surface_compare(cases, tls):
                seen_cases = {}
                scheme = "https" if tls else "http"
                for prefix, path, expected, *mode in cases:
                    mode = mode[0] if mode else ""
                    host = prefix[1:] if prefix.startswith("=") else prefix + tf.TENANTS["olscpa"]
                    seen = {}
                    targets = (("apache", 443 if tls else 80, ips["olscpa"]), ("ols", TLS_PORT if tls else PORT, HOST_IP))
                    for name, port, address in targets:
                        # Host without the test port, as on the real listeners (cpsrvd only issues its HTTPS
                        # redirect for a port-less forwarded host).
                        record = step(f"surface-{scheme}-{name}", ["/usr/sbin/ip", "netns", "exec", NETNS,
                                      "/usr/bin/curl", "--noproxy", "*", "-ks", "--http1.1", "--max-time", "20",
                                      "-H", "Host: " + host, *(WS_HEADERS if mode == "ws" else []),
                                      "-w", "\n%{http_code} %{redirect_url}", "--resolve", f"{host}:{port}:{address}",
                                      f"{scheme}://{host}:{port}{path}"])
                        body, _, tail = record["stdout"].rpartition("\n")
                        status, _, location = tail.partition(" ")
                        title = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
                        seen[name] = {"status": status, "location": re.sub(f":({PORT}|{TLS_PORT})/", "/", location),
                                      "title": "" if mode == "status" else title.group(1).strip()[:80] if title
                                      else body.strip()[:60] if status == "200" else ""}
                    key = ("ws " if mode == "ws" else "") + prefix + path
                    seen_cases[key] = dict(seen, match=seen["apache"] == seen["ols"], baseline_ok=seen["apache"]["status"] in expected.split("|"),
                                           **({"lab_limited": mode} if mode.startswith("lab-") else {}))
                return seen_cases
            surface = surface_compare(SURFACE, False)
            multi = {}
            cases = [(h, p, e) for h in MULTI_HOSTS for p, e in MULTI_PATHS.items()
                     if not (h.endswith(tf.PARKED) and p == "/whoami.php")] + MULTI_SERVICE + MULTI_SCOPE
            for host, path, expected in cases:
                seen = {}
                for name, port, address in (("apache", 80, ips["olscpa"]), ("ols", PORT, HOST_IP)):
                    record = step(f"multi-{name}", ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/bin/curl", "--noproxy", "*",
                                  "-s", "-D", "-", "--max-time", "20", "-H", "Host: " + host, "-w", "\n%{http_code} %{redirect_url}",
                                  "--resolve", f"{host}:{port}:{address}", f"http://{host}:{port}{path}"])
                    raw, _, tail = record["stdout"].rpartition("\n")
                    status, _, location = tail.partition(" ")
                    head, _, body = raw.partition("\r\n\r\n")
                    xfo = [l.split(":", 1)[1].strip() for l in head.splitlines() if l.lower().startswith("x-frame-options:")]
                    seen[name] = {"status": status, "location": re.sub(f":{PORT}/", "/", location),
                                  "x_frame_options": (xfo[0] if xfo else None) if status == "200" else "",
                                  "body": body[:200] if status == "200" else ""}
                multi[host + path] = dict(seen, match=seen["apache"] == seen["ols"], baseline_ok=seen["apache"]["status"] in expected.split("|"))
            summary["multi_domain"] = multi
            summary["surface_tls"] = surface_tls = surface_compare(SURFACE_TLS, True)
            # OLS's ws:// proxy end to end against the lab echo backend, over both test listeners.
            echo = subprocess.Popen([sys.executable, "-I", str(WS_ECHO), "server", "--port", str(WS_ECHO_PORT)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(1)
                ws_nonce = uuid.uuid4().hex
                reports = {}
                for label, port, extra in (("http", PORT, []), ("https", TLS_PORT, ["--tls"])):
                    record = step(f"ws-echo-{label}", ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/bin/python3", "-I",
                                  str(WS_ECHO), "client", "--connect", f"{HOST_IP}:{port}", "--host", tf.TENANTS["olscpa"],
                                  "--path", "/olscp-ws-echo/socket?probe=1", "--nonce", ws_nonce, *extra], 60)
                    try:
                        reports[label] = json.loads(record["stdout"])
                    except ValueError:
                        reports[label] = {"error": record["stderr"][-300:]}
                summary["websocket_proxy"] = dict(reports, ok=all(
                    r.get("status") == "101" and r.get("accept_ok") and r.get("echo_ok")
                    and (r.get("backend_saw") or {}).get("request_line") == "GET /socket?probe=1 HTTP/1.1"
                    for r in reports.values()))
            finally:
                echo.terminate()
                echo.wait(10)
            summary["surface"] = surface
            def bandwidth_total():
                out = step("bandwidth-db", ["/usr/bin/sqlite3", "-readonly", BANDWIDTH_DB,
                                            "select coalesce(sum(bytes),0) from bandwidth_5min"])["stdout"].strip()
                return int(out) if out.isdigit() else None
            bw_file = f"/home/olscpa/public_html/{BANDWIDTH_FILE}"
            parity_files.append(bw_file)
            # The probe's umask 077 reaches the tenant through sudo; a web file needs 0644.
            if step("bandwidth-file", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sh", "-c",
                                       'umask 022 && /usr/bin/truncate -s "$1" "$2"', "sh", str(BANDWIDTH_BYTES), bw_file])["exit_code"]:
                raise ValueError("Could not create the bandwidth test file as the tenant")
            summary["bandwidth"] = {"before": bandwidth_total(), "served": 0}
            for _ in range(BANDWIDTH_FETCHES):
                got = step("bandwidth-fetch", ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/bin/curl", "--noproxy", "*", "-s",
                                               "-o", "/dev/null", "-w", "%{size_download}", "--max-time", "60", "--resolve",
                                               f"{tf.TENANTS['olscpa']}:{PORT}:{HOST_IP}",
                                               f"http://{tf.TENANTS['olscpa']}:{PORT}/{BANDWIDTH_FILE}"])["stdout"].strip()
                summary["bandwidth"]["served"] += int(got) if got.isdigit() else 0
            # Log accounting (G0-E): OLS requests must land in cPanel's domlogs through splitlogs.
            marker = "olscp-log-" + uuid.uuid4().hex
            domain = tf.TENANTS["olscpa"]
            logs_before = {name: step("domlog-size", ["/usr/bin/stat", "-c", "%s", f"{cpanel_surface.DOMLOGS}/{domain}{name}"])["stdout"].strip()
                           for name in ("", "-bytes_log")}
            requests = [["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/bin/curl", "--noproxy", "*", "-s", "-o", "/dev/null",
                         "-A", marker, "--resolve", f"{domain}:{PORT}:{HOST_IP}", f"http://{domain}:{PORT}/static.txt"],
                        ["/usr/bin/curl", "--noproxy", "*", "-ks", "-o", "/dev/null", "-A", marker,
                         "--resolve", f"{domain}:{TLS_PORT}:127.0.0.1", f"https://{domain}:{TLS_PORT}/static.txt"]]
            summary["log_request_epoch"] = int(time.time())
            for command in requests:
                step("log-request", command)
            lines, grew = [], False
            for _ in range(30):  # splitlogs writes shortly after the FIFO delivers
                lines = step("domlog-read", ["/usr/bin/grep", "-h", marker, f"{cpanel_surface.DOMLOGS}/{domain}"])["stdout"].splitlines()
                grew = step("bytes-size", ["/usr/bin/stat", "-c", "%s", f"{cpanel_surface.DOMLOGS}/{domain}-bytes_log"])["stdout"].strip() != logs_before["-bytes_log"]
                if len(lines) >= 2:
                    break
                time.sleep(1)
            summary["log_accounting"] = {
                "marker": marker,
                "marker_lines": lines,
                "combined_format": len(lines) == 2 and all(re.fullmatch(
                    r'\S+ - - \[[^]]+\] "GET /static\.txt HTTP/[12](\.[01])?" 200 \d+ "-" "' + marker + '"', l) for l in lines),
                "bytes_log_grew": grew,
                "ssl_split_note": "lab TLS listener is :8443, so HTTPS lines go to the plain domlog; :443 routing verified on splitlogs directly"}
            # Review F-01: a tenant must not be able to write into the log FIFOs (forged records for other
            # domains, inflated bandwidth). Non-blocking open so a refused write never hangs the probe.
            fifo_writes = {}
            for name in ("access", "bytes"):
                record = step("fifo-tenant-write", ["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/python3", "-I", "-c",
                              "import os,sys\ntry:\n os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)\n print('opened')\n"
                              "except OSError as e:\n print(type(e).__name__)", f"{cpanel_surface.LOG_DIR}/{name}.fifo"])
                fifo_writes[name] = record["stdout"].strip()
            summary["fifo_tenant_write"] = fifo_writes
            summary["fifo_modes"] = step("fifo-modes", ["/usr/bin/stat", "-c", "%n %U %G %a", f"{cpanel_surface.LOG_DIR}/access.fifo",
                                                        f"{cpanel_surface.LOG_DIR}/bytes.fifo"])["stdout"].splitlines()
            broken = sorted(k for k, v in [*surface.items(), *surface_tls.items(), *multi.items()] if not v["baseline_ok"])
            if broken:
                raise ValueError("Apache surface baseline does not match the fixtures: " + ", ".join(broken))
            # TLS/SNI: certificate presented for each name, Apache (account IP :443) vs OLS (test listener).
            def fingerprint(address, port, name):
                sni = ["-servername", name] if name else ["-noservername"]
                record = step("tls-" + (name or "nosni"), ["/usr/bin/sh", "-c",
                              'openssl s_client -connect "$1" "$2" "$3" </dev/null 2>/dev/null | '
                              'openssl x509 -noout -fingerprint -sha256 -subject 2>/dev/null', "sh",
                              f"{address}:{port}", *sni])
                return record["stdout"].strip().replace("\n", " | ")
            tls_seen = {}
            names = ([p + d for d in tf.TENANTS.values() for p in ("", "www.", "cpanel.")]
                     + ["whm." + tf.TENANTS["olscpa"], "cpanel.nowhere.example", "unknown.invalid", ""])
            for name in names:
                apache = fingerprint(ips["olscpa"], 443, name)
                ols = fingerprint("127.0.0.1", TLS_PORT, name)
                tls_seen[name or "<no-sni>"] = {"apache": apache, "ols": ols, "match": apache == ols}
            summary["tls"] = tls_seen
            tenant_prints = {v["apache"] for k, v in tls_seen.items() if k.split(".", 1)[-1] in tf.TENANTS.values()
                             or k in tf.TENANTS.values()}
            summary["tls_default_is_not_tenant"] = all(tls_seen[k]["ols"] not in tenant_prints
                                                       for k in ("unknown.invalid", "<no-sni>"))
            body = {}
            for user, domain in tf.TENANTS.items():
                seen = {}
                for name, port, address in (("apache", 443, ips[user]), ("ols", TLS_PORT, "127.0.0.1")):
                    seen[name] = step(f"https-{name}-{user}", ["/usr/bin/curl", "--noproxy", "*", "-ks", "--max-time", "15",
                                      "--resolve", f"{domain}:{port}:{address}", f"https://{domain}:{port}/static.txt"])["stdout"]
                body[user] = dict(seen, match=seen["apache"] == seen["ols"] and seen["apache"].startswith("static " + user))
            summary["https_content"] = body
            broken = sorted(k for section in (protection, rewrite, compat) for k, v in section.items() if not v["baseline_ok"])
            summary["fixture_baseline_failures"] = broken
            if broken:
                raise ValueError("Apache baseline does not match the fixtures; comparisons would be vacuous: " + ", ".join(broken))
            # Return path: with OLS stopped, cPanel must restore its Apache (ruid2) ownership itself.
            step("stop-before-return", ["/usr/bin/systemctl", "stop", owner.UNIT])
            summary["enablefileprotect_stopped_exit"] = step("enablefileprotect-stopped",
                                                             ["/usr/local/cpanel/scripts/enablefileprotect"], 300)["exit_code"]
            summary["return_ownership"] = ownership().splitlines()
            summary["return_matches_original"] = ownership() == original
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                # The packaged log shipper (OLS-18) flushes splitlogs' buffered records when it stops.
                step("logship-stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                if summary.get("log_accounting") is not None:
                    # splitlogs buffers byte records; they are complete once the shipper has stopped.
                    tail = step("bytes-tail", ["/usr/bin/tail", "-n", "50", f"{cpanel_surface.DOMLOGS}/{tf.TENANTS['olscpa']}-bytes_log"])["stdout"]
                    records = [l.split() for l in tail.splitlines() if len(l.split()) == 3 and l.split()[0].isdigit()]
                    summary["log_accounting"]["byte_records_for_requests"] = [r for r in records
                                                                              if int(r[0]) >= summary["log_request_epoch"]]
                    summary["log_accounting"]["bytes_log_grew"] = len(summary["log_accounting"]["byte_records_for_requests"]) >= 2
                    # Access lines are buffered by splitlogs as well; re-read them after the flush.
                    marker = summary["log_accounting"]["marker"]
                    lines = step("domlog-final", ["/usr/bin/grep", "-h", marker, f"{cpanel_surface.DOMLOGS}/{tf.TENANTS['olscpa']}"])["stdout"].splitlines()
                    summary["log_accounting"]["marker_lines"] = lines
                    summary["log_accounting"]["combined_format"] = len(lines) == 2 and all(re.fullmatch(
                        r'\S+ - - \[[^]]+\] "GET /static\.txt HTTP/[12](\.[01])?" 200 \d+ "-" "' + marker + '"', l) for l in lines)
                if summary.get("bandwidth", {}).get("before") is not None:
                    # cPanel's own log processing (cpanellogd) turns the flushed byte records into bandwidth.
                    step("runweblogs", ["/usr/local/cpanel/scripts/runweblogs", "olscpa"], 900)
                    bandwidth = summary["bandwidth"]
                    bandwidth["after"] = bandwidth_total()
                    bandwidth["counted"] = None if bandwidth["after"] is None else bandwidth["after"] - bandwidth["before"]
                    bandwidth["ok"] = (bandwidth["served"] == BANDWIDTH_BYTES * BANDWIDTH_FETCHES
                                       and (bandwidth["counted"] or 0) >= bandwidth["served"])
            if netns:
                netns_down(step)
            for target in parity_files:
                step("remove-parity", ["/usr/bin/rm", "-f", target])
            if changed and original and ownership() != original:
                # Exact restore of owner, group, mode and ACLs from the getfacl snapshot.
                acl_text = original[original.index("# file:"):]
                step("restore-acls", ["/usr/bin/setfacl", "--restore=" + stage_file("original.acl", acl_text)])
            if installed:
                step("stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                log = step("ols-error-log", ["/usr/bin/tail", "-c", "200000", LSWS + "/logs/error.log"])["stdout"]
                summary["ols_log_errors"] = [l[27:] for l in log.splitlines() if "[ERROR]" in l][:50]
                summary["ols_log_warnings"] = [l[27:] for l in log.splitlines() if "denied" in l.lower()][:40]
                summary["package_erased"] = owner.erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, owner.WEB, "/tmp/lshttpd", "/run/ols-cpanel/lshttpd", "/dev/shm/ols"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
            summary["ownership_restored"] = original is None or ownership() == original
            summary["removed"] = (not step("final-residue", ["/usr/bin/ls", "-d", LSWS])["stdout"].strip()
                                  and summary.get("package_erased", True))
            failed = []
            if summary["result"] == "observed":
                # Declared expectations (review RV-06): isolation holds, every comparison equals Apache except
                # the listed known differences, and the host is restored.
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["known_differences"] = KNOWN_DIFFERENCES
                failed = [name for name, ok in cases.items() if not ok]
                summary["result"] = "fail" if failed else "pass"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"],
                              "passes": {k: {"valid": v["valid"], "leaks": v["leaks"]} for k, v in summary["passes"].items()},
                              "restored": summary["ownership_restored"], "failed_cases": failed, "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
