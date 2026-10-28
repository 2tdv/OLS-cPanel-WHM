#!/usr/bin/python3
"""cPanel's global web surface for OLS tenant vhosts (G0-E, OLS-17). Mirrors what the
cPanel-generated httpd.conf gives every domain:
- DCV paths (AutoSSL/Sectigo) stay reachable from the docroot even on service subdomains and
  under tenant access restrictions;
- the global deny for .htaccess/.htpasswd(s)/.user.ini/php.ini/error_log;
- service subdomains proxied to cpsrvd (cpanel, webmail, webdisk, cpcalendars, cpcontacts), and
  autoconfig/autodiscover mapped to their cgi-sys scripts; WebSocket upgrades on cpanel./webmail.
  proxied to cpsrvd as ws:// (terminal, MySQL dump streams); ActiveSync over HTTPS to port 2090;
- the global Alias directories (img-sys, sys_cpanel, Mailman archives, ...), ScriptAlias /mailman,
  the tenant's ScriptAlias /cgi-bin/ and the global /cpanelwebcall/ proxy;
- global paths /cpanel, /whm, /webmail, ..., autodiscover.xml and /cgi-sys/, executed as CGI from
  /usr/local/cpanel/cgi-sys like Apache's ScriptAlias(Match) (cpsrvd does not run them unauthenticated).
Proxied requests reach cpsrvd from the OLS worker (user nobody); cpsrvd honors X-Forwarded-For/Host
only from that user, exactly as for Apache."""

DCV = (r"^/\.well-known/(acme-challenge/[0-9a-zA-Z_-]+|cpanel-dcv/[0-9a-zA-Z_-]+|"
       r"pki-validation/[A-F0-9]{32}\.txt(\ Sectigo\ DCV)?|pki-validation/(\ Ballot169)?)$")
DENY_FILES = r"(^|/)(\.ht(access|passwds?)|\.user\.ini|php\.ini|error_log)$"
# Subdomain -> cpsrvd port, from the cPanel proxy-subdomain vhost.
SERVICES = {"cpanel": 2082, "webmail": 2095, "webdisk": 2077, "cpcalendars": 2079, "cpcontacts": 2079}
# Service subdomains Apache maps to a cgi-sys script instead of a cpsrvd port.
SCRIPT_HOSTS = {"autoconfig": "/cgi-sys/autoconfig.cgi", "autodiscover": "/cgi-sys/autodiscover.cgi"}
# Service subdomains whose WebSocket upgrades Apache proxies to cpsrvd (ws://).
WEBSOCKET_SERVICES = {"cpanel": 2082, "webmail": 2095}
# Apache proxies /Microsoft-Server-ActiveSync* to this port on the SSL vhost only.
ACTIVESYNC_PORT = 2090
# Global Alias URI -> directory (served as static files; a missing directory is a 404 like Apache's).
MAILMAN = "/usr/local/cpanel/3rdparty/mailman"
STATIC_ALIASES = {"/bandwidth/": "/usr/local/bandmin/htdocs/", "/img-sys/": "/usr/local/cpanel/img-sys/",
                  "/java-sys/": "/usr/local/cpanel/java-sys/", "/mailman/archives/": MAILMAN + "/archives/public/",
                  "/pipermail/": MAILMAN + "/archives/public/", "/sys_cpanel/": "/usr/local/cpanel/sys_cpanel/"}
# Global ScriptAlias URI -> directory (the tenant's own /cgi-bin/ is per vhost under its docroot).
CGI_ALIASES = {"/cgi-bin/": "$DOC_ROOT/cgi-bin/", "/cgi-sys/": "/usr/local/cpanel/cgi-sys/",
               "/mailman/": MAILMAN + "/cgi-bin/"}
# Global ScriptAliasMatch paths -> cgi-sys script, executed through the /cgi-sys/ CGI context.
GLOBAL_SCRIPTS = [(r"^/?(controlpanel|cpanel|kpanel)/?$", "/cgi-sys/redirect.cgi"),
                  (r"^/?(securecontrolpanel|securecpanel)/?$", "/cgi-sys/sredirect.cgi"),
                  (r"^/?securewhm/?$", "/cgi-sys/swhmredirect.cgi"),
                  (r"^/?webmail(/.*)?$", "/cgi-sys/wredirect.cgi"),
                  (r"^/?whm/?$", "/cgi-sys/whmredirect.cgi"),
                  (r"^/[Aa]utodiscover/[Aa]utodiscover\.xml", "/cgi-sys/autodiscover.cgi")]

def processors():
    """Server-level proxy backends, one per cpsrvd port."""
    return "".join(f"extProcessor cpsrvd{port} {{\n    type                 proxy\n    address              127.0.0.1:{port}\n"
                   f"    maxConns             20\n    initTimeout          60\n    retryTimeout         0\n"
                   f"    respBuffer           0\n}}\n" for port in sorted({*SERVICES.values(), *PROXY_SERVICES.values(), ACTIVESYNC_PORT}))

def host_aliases(domain):
    return [f"{name}.{domain}" for name in [*SERVICES, *SCRIPT_HOSTS]]

def rewrite_rules(domains, activesync=True):
    """Vhost-level rules evaluated before the tenant's .htaccess rules. `domains` are the vhost's
    service domains (its main or addon domains; none for a plain subdomain)."""
    lines = [f"RewriteCond %{{REQUEST_URI}} {DCV}", "RewriteRule ^ - [L]"]
    # Like Apache: upgrades go to cpsrvd's WebSocket endpoint; other service rules skip upgrades.
    for domain in domains:
        escaped = domain.replace(".", r"\.")
        for name, port in WEBSOCKET_SERVICES.items():
            lines += ["RewriteCond %{HTTP:Upgrade} websocket [NC]",
                      f"RewriteCond %{{HTTP_HOST}} ^{name}\\.{escaped}(:[0-9]+)?$ [NC]",
                      f"RewriteRule ^/?(.*)$ ws://127.0.0.1:{port}/$1 [P,L]"]
    for domain in domains:
        escaped = domain.replace(".", r"\.")
        for name, port in SERVICES.items():
            lines += ["RewriteCond %{HTTP:Upgrade} !websocket [NC]",
                      f"RewriteCond %{{HTTP_HOST}} ^{name}\\.{escaped}(:[0-9]+)?$ [NC]",
                      f"RewriteRule ^/?(.*)$ http://cpsrvd{port}/$1 [P,L]"]
        for name, script in SCRIPT_HOSTS.items():
            lines += ["RewriteCond %{HTTP:Upgrade} !websocket [NC]",
                      f"RewriteCond %{{HTTP_HOST}} ^{name}\\.{escaped}(:[0-9]+)?$ [NC]",
                      f"RewriteRule ^ {script} [L]"]
    # Apache's ActiveSync proxy drops the path suffix and only exists on the account SSL vhosts.
    if activesync:
        lines += ["RewriteCond %{HTTPS} on",
                  f"RewriteRule ^/?Microsoft-Server-ActiveSync http://cpsrvd{ACTIVESYNC_PORT}/Microsoft-Server-ActiveSync/ [P,L]"]
    for pattern, script in GLOBAL_SCRIPTS:
        lines.append(f"RewriteRule {pattern} {script} [L]")
    return "\n".join(lines) + "\n"

SUSPENDED_PAGE = "/cgi-sys/suspendedpage.cgi"

def suspension_rules(missing):
    """cPanel suspends an account's websites with RedirectMatch inside <Directory /home/<user>> and
    AllowOverride none (account_suspensions.conf): every request that maps into the account's home is
    redirected (302) to the suspended page; cPanel's aliases outside the home directory, /cgi-sys/, the
    proxied /cpanelwebcall/ and the global /cpanel-style script URLs are not. Vhost-level rules ahead of
    the DCV exemption, which Apache's redirect also overrides. `missing` is the list given to contexts():
    an alias without a context maps into the docroot, so only emitted aliases are exempt, and the global
    script URLs only while /cgi-sys/ (which runs them) has a context."""
    outside = sorted({*(u for u in STATIC_ALIASES if u not in missing),
                      *(u for u, d in CGI_ALIASES.items() if not d.startswith("$DOC_ROOT") and u not in missing),
                      "/cpanelwebcall/"})
    prefixes = "|".join(u.strip("/").replace(".", "\\.") + "/" for u in outside)
    scripts = "|".join(pattern[3:].rstrip("$") for pattern, _ in GLOBAL_SCRIPTS if pattern.startswith("^/?"))
    global_scripts = "" if "/cgi-sys/" in missing else (
        f"RewriteCond %{{REQUEST_URI}} !^/({scripts})$\n"
        f"RewriteCond %{{REQUEST_URI}} !^/[Aa]utodiscover/[Aa]utodiscover\\.xml\n")
    return (f"RewriteCond %{{REQUEST_URI}} !^/({prefixes})\n{global_scripts}"
            f"RewriteRule ^ {SUSPENDED_PAGE} [R=302,L]\n")

# cPanel's global DCV exclusion ("Satisfy Any" + "Allow from all") also covers the alias directories,
# which Apache never protects with a docroot realm; OLS contexts inherit the "/" realm unless they
# pass accessControl with "satisfy any" (OLS patch 0006).
EXEMPT = "  accessControl  {\n    allow                 ALL\n  }\n  satisfy                 any\n"
# Alias directories live outside the docroot, so Apache never applies the tenant's .htaccess rules there;
# OLS contexts inherit the "/" context's translated rules (e.g. WordPress "!-f -> /index.php") unless
# rewriting is off in the alias context itself (RV-19).
NO_TENANT_REWRITE = "  rewrite  {\n    enable                0\n  }\n"

def contexts(missing=(), unset_headers=()):
    """DCV first so it wins over the deny context and tenant restrictions. `missing` lists alias URIs
    whose directory does not exist on the host: OLS rejects such contexts with [ERROR], while the
    request falls through to a 404 as under Apache. OLS contexts inherit the "/" context's header
    operations; Apache applies the docroot .htaccess only inside the docroot, so the alias contexts
    unset every header the tenant's root context sets (`unset_headers`)."""
    unset = "".join(f"Header unset {name}\n" for name in unset_headers)
    out = (f"context exp:{DCV} {{\n  allowBrowse             1\n{EXEMPT}}}\n"
           f"context exp:{DENY_FILES} {{\n  allowBrowse             0\n}}\n")
    for uri, location in STATIC_ALIASES.items():
        if uri in missing:
            continue
        # mailman.conf: archives are user content, never sniffed into an executable type.
        ops = unset + ("Header set X-Content-Type-Options nosniff\n" if location.startswith(MAILMAN) else "")
        headers = f"  extraHeaders            <<<END_extraHeaders\n{ops}END_extraHeaders\n" if ops else ""
        out += f"context {uri} {{\n  location                {location}\n  allowBrowse             1\n{EXEMPT}{NO_TENANT_REWRITE}{headers}}}\n"
    for uri, location in CGI_ALIASES.items():
        if uri in missing:
            continue
        # Mailman's CGI wrappers are setuid/setgid mailman; OLS otherwise refuses them with 403.
        setuid = "  allowSetUID             1\n" if location.startswith(MAILMAN) else ""
        headers = f"  extraHeaders            <<<END_extraHeaders\n{unset}END_extraHeaders\n" if unset else ""
        out += (f"context {uri} {{\n  type                    cgi\n  location                {location}\n"
                f"  allowBrowse             1\n{setuid}{EXEMPT}{NO_TENANT_REWRITE}{headers}}}\n")
    headers = f"  extraHeaders            <<<END_extraHeaders\n{unset}END_extraHeaders\n" if unset else ""
    return (out + "context /cpanelwebcall/ {\n  type                    proxy\n  handler                 cpsrvd2082\n"
            f"  addDefaultCharset       off\n{EXEMPT}{NO_TENANT_REWRITE}{headers}}}\n")

DOMLOGS = "/etc/apache2/logs/domlogs"
LOG_DIR = "/run/ols-cpanel/logs"
# Apache's "combinedvhost" format with %v replaced by the literal domain (OLS vhost names are not
# domains); splitlogs routes ":443" to -ssl_log. Apache's "bytesvhost" writes %I and %O as two records;
# OLS formats have no line break, so one record carries their sum (%S). cpanellogd sums the records.
ACCESS_FORMAT = '{domain}:%p %a %l %u %t "%r" %>s %b "%{{Referer}}i" "%{{User-Agent}}i"'
BYTES_FORMAT = "{domain} %{{%s}}t %S ."

def access_logs(domain):
    """Two vhost access logs written to the root log shipper's FIFOs (OLS workers run as nobody
    and OLS piped loggers also run as nobody, so they cannot write cPanel's domlogs themselves)."""
    return (f"accesslog {LOG_DIR}/access.fifo {{\n    useServer            0\n    rollingSize          0\n"
            f"    logFormat            {ACCESS_FORMAT.format(domain=domain)}\n}}\n"
            f"accesslog {LOG_DIR}/bytes.fifo {{\n    useServer            0\n    rollingSize          0\n"
            f"    logFormat            {BYTES_FORMAT.format(domain=domain)}\n}}\n")

# Apache's catch-all proxy-subdomains vhosts (:80, and the hostname :443 vhost with cPanel's own
# certificate) take any name starting with a service label that no tenant claims, e.g. whm.<domain>
# or cpanel.<unknown>. OLS exact names win over wildcards, so tenant service names stay on the tenant.
PROXY_VHOST = "cpanel-proxy"
PROXY_SERVICES = {"cpanel": 2082, "webmail": 2095, "whm": 2086, "webdisk": 2077, "cpcontacts": 2079, "cpcalendars": 2079}
PROXY_WEBSOCKET = {"cpanel": 2082, "webmail": 2095, "whm": 2086}
PROXY_DOCROOT = "/var/www/html/"
# cPanel's service certificate, in the order its Apache template uses them: the installed
# (e.g. AutoSSL) certificate replaces the self-signed one; cPanel can switch at any time.
SERVICE_CERTS = ("/var/cpanel/ssl/cpanel/mycpanel.pem", "/var/cpanel/ssl/cpanel/cpanel.pem")
PROXY_CERT = SERVICE_CERTS[-1]
# Serves DCV files of the domain behind the requested name. OLS never rewrites acme-challenge URLs
# (SKIP_REWRITE), so a regex CGI context runs it; Apache only does this on plain HTTP.
DCV_HELPER = "/usr/local/cpanel/cgi-priv/get_local.cgi"

def proxy_hosts():
    return [f"{name}.*" for name in [*PROXY_SERVICES, *SCRIPT_HOSTS]]

def proxy_server_block():
    """Runs CGI as the server user (nobody), like Apache's proxy vhost without suexec."""
    return (f"virtualHost {PROXY_VHOST} {{\n    vhRoot               {PROXY_DOCROOT}\n"
            f"    configFile           $SERVER_ROOT/conf/vhosts/{PROXY_VHOST}/vhconf.conf\n    allowSymbolLink      0\n"
            "    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n")

def proxy_rules():
    # Plain-HTTP DCV stops rewriting so the DCV context answers (acme-challenge never reaches here).
    lines = ["RewriteCond %{HTTPS} !on", f"RewriteCond %{{REQUEST_URI}} {DCV}", "RewriteRule ^ - [L]"]
    for name, port in PROXY_WEBSOCKET.items():
        lines += ["RewriteCond %{HTTP:Upgrade} websocket [NC]", f"RewriteCond %{{HTTP_HOST}} ^{name}\\.",
                  f"RewriteRule ^/?(.*)$ ws://127.0.0.1:{port}/$1 [P,L]"]
    for name, port in PROXY_SERVICES.items():
        if name in PROXY_WEBSOCKET:
            lines.append("RewriteCond %{HTTP:Upgrade} !websocket [NC]")
        lines += [f"RewriteCond %{{HTTP_HOST}} ^{name}\\.", f"RewriteRule ^/?(.*)$ http://cpsrvd{port}/$1 [P,L]"]
    for name, script in SCRIPT_HOSTS.items():
        lines += [f"RewriteCond %{{HTTP_HOST}} ^{name}\\.", f"RewriteRule ^ {script} [L]"]
    return "\n".join(lines) + "\n"

def proxy_vhost(cert=PROXY_CERT):
    return (f"docRoot                  {PROXY_DOCROOT}\nrewrite {{\n    enable               1\n    autoLoadHtaccess     0\n"
            f"    rules                <<<END_rules\n{proxy_rules()}END_rules\n}}\n"
            f"context exp:{DCV} {{\n  type                    cgi\n  location                {DCV_HELPER}\n"
            "  allowBrowse             1\n}\n"
            "context /cgi-sys/ {\n  type                    cgi\n  location                /usr/local/cpanel/cgi-sys/\n"
            "  allowBrowse             1\n}\n"
            f"vhssl {{\n    keyFile              {cert}\n    certFile             {cert}\n    certChain            1\n}}\n")

# Hybrid profile (owner decision HR-D08, plan section 3): a vhost whose .htaccess or PHP handler OLS cannot
# reproduce stays on Apache. OLS keeps the public listeners and the domain's certificate and passes every
# request through to Apache on its backend ports (cPanel's apache_port/apache_ssl_port, as with ea-nginx),
# preserving Host (and SNI for HTTPS), so Apache applies the account's own configuration unchanged.
def apache_backend_name(vhost, tls):
    return f"apache-{'https' if tls else 'http'}-{vhost}"

def hybrid_tls_name(name):
    """The OLS vhost serving a hybrid domain on the HTTPS listeners: OLS skips rewrite rules for ACME paths
    (contexts cannot test the scheme), so each scheme gets its own vhost and ACME context (review RV-28)."""
    return "tls." + name

def _ipv4(ip):
    # cPanel's userdata "ip" is always IPv4 (IPv6 is separate); OLS's string-address WebSocket connector
    # resolves IPv4 only (review RV-28), so anything else is refused rather than emitted.
    if not ip or ":" in ip:
        raise ValueError(f"hybrid backend address must be IPv4: {ip!r}")
    return ip

def apache_backends(vhosts, ports):
    """Server-level proxy backends, one pair per hybrid vhost: a TLS backend connection carries the SNI of the
    vhost that opened it, so pools are never shared between vhosts (review RV-27)."""
    out = ""
    for name, ip in sorted(vhosts):
        for tls, port in ((False, ports[0]), (True, ports[1])):
            out += (f"extProcessor {apache_backend_name(name, tls)} {{\n    type                 proxy\n"
                    f"    address              {'https://' if tls else ''}{_ipv4(ip)}:{port}\n    maxConns             100\n"
                    f"    initTimeout          60\n    retryTimeout         0\n    respBuffer           0\n}}\n")
    return out

def apache_vhost(docroot, name, ip, tls_file, error_log_dir, ports=(81, 444), secure=False):
    """A hybrid vhost for one scheme (`secure`: the HTTPS listeners' vhost, hybrid_tls_name). OLS terminates TLS
    with the domain's certificate and passes everything to Apache on the backend port of the same scheme, which
    applies the account's own configuration (including cPanel's suspension). WebSocket upgrades are tunnelled
    with the original, still encoded request path (the rewritten path is decoded; review RV-28) and SNI (OLS
    patch 0010); ACME challenges, which OLS never rewrites, reach Apache through a proxy context. Requests are
    logged by Apache only (client address from X-OLS-Client-IP, OLS patch 0010)."""
    vhost, backend = (hybrid_tls_name(name) if secure else name), apache_backend_name(name, secure)
    rules = ("RewriteCond %{HTTP:Upgrade} websocket [NC]\nRewriteCond %{ORG_REQ_URI} ^(/.*)$\n"
             f"RewriteRule ^ {'wss' if secure else 'ws'}://{_ipv4(ip)}:{ports[1] if secure else ports[0]}%1 [P,L]\n"
             f"RewriteRule ^/?(.*)$ http://{backend}/$1 [P,L]\n")
    return (f"docRoot                  {docroot.rstrip('/')}/\nvhDomain                 {name}\n"
            f"errorlog {error_log_dir}/{vhost}-error.log {{\n    useServer            0\n    logLevel             INFO\n}}\n"
            f"rewrite {{\n    enable               1\n    autoLoadHtaccess     0\n    rules                <<<END_rules\n"
            f"{rules}END_rules\n}}\n"
            f"context exp:^/\\.well-known/acme-challenge/ {{\n  type                    proxy\n"
            f"  handler                 {backend}\n  addDefaultCharset       off\n}}\n"
            + (f"vhssl {{\n    keyFile              {tls_file}\n    certFile             {tls_file}\n    certChain            1\n}}\n"
               if secure and tls_file else ""))

# Apache's server default vhost (<VirtualHost *>, the hostname, DocumentRoot /var/www/html) answers every
# name no other vhost claims on an address, e.g. all names over IPv6 when no account has an IPv6 address:
# cPanel's global aliases and redirect scripts, nothing proxied, cPanel's service certificate.
DEFAULT_VHOST = "server-default"

def default_server_block():
    return (f"virtualHost {DEFAULT_VHOST} {{\n    vhRoot               {PROXY_DOCROOT}\n"
            f"    configFile           $SERVER_ROOT/conf/vhosts/{DEFAULT_VHOST}/vhconf.conf\n    allowSymbolLink      0\n"
            "    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n")

def default_vhost(cert=PROXY_CERT, missing=()):
    return (f"docRoot                  {PROXY_DOCROOT}\nrewrite {{\n    enable               1\n    autoLoadHtaccess     0\n"
            f"    rules                <<<END_rules\n{rewrite_rules([], activesync=False)}END_rules\n}}\n"
            + contexts(missing)
            + f"vhssl {{\n    keyFile              {cert}\n    certFile             {cert}\n    certChain            1\n}}\n")

# Service names of a tenant vhost (cpanel.<domain>, webmail.<domain>, ...) get their own OLS vhost:
# the tenant's certificate and docroot (for DCV) but none of the tenant's .htaccess settings, which
# OLS would otherwise apply to proxied cpsrvd traffic through the "/" context (Apache proxies these
# names before any directory walk).
def service_vhost_name(name):
    return "svc." + name

def service_server_block(name, user, home=None):
    """`home`: the account's home directory (default /home/<user>)."""
    return (f"virtualHost {service_vhost_name(name)} {{\n    vhRoot               {home or '/home/' + user}/\n"
            f"    configFile           $SERVER_ROOT/conf/vhosts/{service_vhost_name(name)}/vhconf.conf\n"
            "    allowSymbolLink      2\n    enableScript         1\n    restrained           1\n    setUIDMode           0\n}\n")

def service_vhost(docroot, domains, tls=None):
    return (f"docRoot                  {docroot.rstrip('/')}/\nrewrite {{\n    enable               1\n    autoLoadHtaccess     0\n"
            f"    rules                <<<END_rules\n{rewrite_rules(domains)}END_rules\n}}\n"
            f"context exp:{DCV} {{\n  allowBrowse             1\n}}\n"
            "context /cgi-sys/ {\n  type                    cgi\n  location                /usr/local/cpanel/cgi-sys/\n"
            "  allowBrowse             1\n}\n"
            + (f"vhssl {{\n    keyFile              {tls}\n    certFile             {tls}\n    certChain            1\n}}\n" if tls else ""))

