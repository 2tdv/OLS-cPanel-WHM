#!/usr/bin/python3
"""cPanel account vhosts for OLS (OLS-19), read the way cPanel itself lays them out:
- /etc/userdatadomains lists every domain with its type: "main" and "sub" domains are vhosts;
  "parked" domains are aliases of the main vhost; an "addon" domain is served by its own
  subdomain vhost (parent = that subdomain);
- /var/cpanel/userdata/<user>/<vhost> holds the authoritative ServerName, ServerAlias,
  DocumentRoot, IP and PHP version of each vhost;
- the PHP-FPM pool of a vhost is named after its addon domain when it has one (cPanel names the
  pool and its php-fpm.yaml after the addon), otherwise after the vhost;
- cpanel./webmail./... service names belong to the main domain and to every addon domain, on the
  vhost serving it; subdomains and parked domains get them from the catch-all proxy vhost."""
import ipaddress
import re

FIELDS = ("servername", "serveralias", "documentroot", "ip", "phpversion")
DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/@+-]*$")
# The product's one home policy (review RV-29, finding 11; PHP Cpanel\Discovery\HomePath, the broker's
# engine.run allowlist): an account's home is /<mount>/<user> with <mount> = "home" + [A-Za-z0-9_-]*, one
# component below "/" (/home, /home2, /home_ssd). cPanel's HOMEMATCH also admits other mounts (/newhome,
# /usr/home) and HOMEDIR may be anywhere; those are refused, never guessed.
HOME_MOUNT = re.compile(r"home[A-Za-z0-9_-]*")  # fullmatch: no trailing newline

def account_home(path, user):
    """The home of `user` that `path` lies in (whole components; the home itself included), or None."""
    parts = path.split("/", 3)
    if len(parts) < 3 or parts[0] != "" or not HOME_MOUNT.fullmatch(parts[1]) or parts[2] != user or not user:
        return None
    return f"/{parts[1]}/{user}"

def parse_userdatadomains(text):
    """domain -> {user, owner, type, parent, docroot, http, https, php} from /etc/userdatadomains."""
    rows = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        domain, _, rest = line.partition(": ")
        fields = rest.split("==")
        if len(fields) < 10:
            raise ValueError(f"unexpected userdatadomains line for {domain!r}")
        user, owner, kind, parent, docroot, http, https = fields[:7]
        rows[domain] = {"user": user, "owner": owner, "type": kind, "parent": parent, "docroot": docroot,
                        "http": http, "https": https, "php": fields[9]}
    return rows

def userdata_fields(text):
    """The scalar vhost fields from a userdata YAML file (single-line "key: value" entries)."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition(": ")
        if sep and key in FIELDS:
            out[key] = value.strip().strip("'\"")
    return out

def userdata_ipv6(text):
    """IPv6 addresses cPanel assigned to the vhost: the keys of the userdata "ipv6:" mapping
    ("ipv6: ~" or no block means none). Anything that is not an IPv6 address is an error."""
    addresses, inside = [], False
    for line in text.splitlines():
        if not line.startswith(" "):
            inside = line.split("#")[0].strip() == "ipv6:"
            continue
        if inside and line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            key = line.strip()[:-1].strip("'\"")
            addresses.append(str(ipaddress.IPv6Address(key)))
    return addresses

VHOST_OPEN = re.compile(r"^\s*<VirtualHost\s+([^>]+)>", re.I)
SERVER_NAME = re.compile(r"^\s*ServerName\s+(\S+)", re.I)

def _endpoint(token):
    """("address", port) of one <VirtualHost> token; "*" or "*:443" are wildcards (port None = any)."""
    if token.startswith("["):
        address, _, port = token[1:].partition("]:")
        return str(ipaddress.IPv6Address(address)), int(port)
    address, _, port = token.rpartition(":") if ":" in token else (token, "", "")
    return address, int(port) if port else None

SERVER_ALIAS = re.compile(r"^\s*ServerAlias\s+(.+)$", re.I)

def apache_proxy_endpoints(httpd_conf):
    """(address, port) endpoints where cPanel binds a proxy-subdomains vhost (ServerAlias cpanel.*):
    there every unclaimed service name is proxied to cpsrvd."""
    endpoints, pending = set(), None
    for line in httpd_conf.splitlines():
        opened = VHOST_OPEN.match(line)
        if opened:
            pending = [_endpoint(t) for t in opened.group(1).split()]
            continue
        alias = SERVER_ALIAS.match(line)
        if alias and pending is not None and "cpanel.*" in alias.group(1).split():
            endpoints.update(pending)
        if line.strip().lower().startswith("</virtualhost"):
            pending = None
    return sorted(endpoints, key=lambda e: (e[0], e[1] or 0))

def apache_defaults(httpd_conf):
    """{(address, port): ServerName} of the first <VirtualHost> on each address and port: Apache answers
    every unknown name on that address with it (name-based default). "*" entries are recorded as
    ("*", port-or-None). Read from cPanel's generated httpd.conf; never modified."""
    defaults, pending = {}, None
    for line in httpd_conf.splitlines():
        opened = VHOST_OPEN.match(line)
        if opened:
            pending = [_endpoint(t) for t in opened.group(1).split()]
            continue
        named = SERVER_NAME.match(line)
        if named and pending is not None:
            for endpoint in pending:
                defaults.setdefault(endpoint, named.group(1).lower())
            pending = None
    return defaults

def bound_ipv6(ip_output):
    """Global IPv6 addresses from `ip -6 -o addr show scope global` (plus ::1, where Apache's
    "Listen [::]" also answers)."""
    found = ["::1"]
    for line in ip_output.splitlines():
        parts = line.split()
        if "inet6" in parts:
            address = str(ipaddress.IPv6Address(parts[parts.index("inet6") + 1].split("/")[0]))
            if address not in found:
                found.append(address)
    return found

def account_vhosts(user, rows, userdata):
    """Vhost specs for one account. `userdata` maps a vhost name to its userdata file text.
    Every name and path is validated: a malformed or foreign entry is an error, never a guess."""
    vhosts = []
    for name, row in sorted(rows.items()):
        if row["user"] != user or row["type"] not in ("main", "sub"):
            continue
        if name not in userdata:
            raise ValueError(f"no userdata for {name}")
        fields = userdata_fields(userdata[name])
        if fields.get("servername") != name:
            raise ValueError(f"userdata servername mismatch for {name}")
        aliases = fields.get("serveralias", "").split()
        addons = sorted(d for d, r in rows.items() if r["type"] == "addon" and r["parent"] == name and r["user"] == user)
        parked = sorted(d for d, r in rows.items() if r["type"] == "parked" and r["parent"] == name and r["user"] == user)
        for domain in [name, *aliases, *addons, *parked]:
            if not DOMAIN.match(domain):
                raise ValueError(f"invalid domain {domain!r} for {name}")
        docroot = fields.get("documentroot", "")
        if not SAFE_PATH.match(docroot) or account_home(docroot, user) is None:
            raise ValueError(f"unsafe document root for {name}: {docroot!r}")
        if len(addons) > 1:
            raise ValueError(f"more than one addon domain on {name}: {addons}")
        vhosts.append({"name": name, "type": row["type"], "docroot": docroot, "aliases": aliases,
                       "ip": fields.get("ip", ""), "ipv6": userdata_ipv6(userdata[name]),
                       "php": fields.get("phpversion") or row["php"],
                       "pool": addons[0] if addons else name,
                       "service_domains": ([name] if row["type"] == "main" else []) + addons,
                       "addons": addons, "parked": parked})
    if [v["type"] for v in vhosts].count("main") != 1:
        raise ValueError(f"expected exactly one main vhost for {user}")
    return vhosts

def nested_in(vhost, vhosts):
    """Other vhosts whose document root lies inside this one's (their .htaccess files and
    directories belong to them, not to this vhost's URL space)."""
    root = vhost["docroot"].rstrip("/") + "/"
    return [v for v in vhosts if v is not vhost and v["docroot"].startswith(root)]

def ancestors(vhost):
    """Every directory above the document root, outermost first. cPanel's httpd.conf has
    AllowOverride All on "/", so Apache applies a .htaccess in any of them (including the account
    home) to this vhost: AllowOverride works on the filesystem path, not the URL."""
    parts = vhost["docroot"].rstrip("/").split("/")[1:-1]
    return ["/" + "/".join(parts[:i]) if i else "/" for i in range(len(parts) + 1)]
