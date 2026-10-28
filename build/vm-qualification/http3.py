"""HTTP/3 (FV-04) reference: the operator input, the firewall decisions for UDP 443 and the protocol share of the
access logs. The PHP port (src/Deployment/Http3Input.php, Http3Firewall.php, src/Ols/Http3/ProtocolShare.php) is
byte-identical for the same inputs (tests/http3.py).

OLS 1.9.3 facts these functions rely on (verified in the OLS source, see docs/product-interfaces.md "HTTP/3"):
QUIC is the UDP twin of the HTTPS listener: the same address and port, over UDP. The server level key is
`quicEnable` (tuning block, default 1) and the listener key `enableQuic` (default 1, secure listeners only).
The access log request line (%r) ends in HTTP/1.0, HTTP/1.1, HTTP/2 or HTTP/3 (AccessLog fixHttpVer)."""
import json
import os
import re
import stat

INPUT_PATH = "/var/lib/ols-cpanel/http3.json"
MAX_INPUT_BYTES = 4096

def parse_input(text):
    """True when HTTP/3 is enabled. The input is a JSON object whose only key is "enabled" (a boolean); an
    object without it means enabled. Anything else is refused, never ignored (a broken file must not silently
    leave HTTP/3 advertised on a server that cannot serve it)."""
    try:
        data = json.loads(text)
    except ValueError as error:
        raise ValueError(f"http3 input is not valid JSON: {error}")
    if not isinstance(data, dict):
        raise ValueError("http3 input must be a JSON object")
    unknown = sorted(set(data) - {"enabled"})
    if unknown:
        raise ValueError("http3 input has unknown keys: " + ", ".join(unknown))
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError('http3 input "enabled" must be true or false')
    return enabled

def load_input(path=INPUT_PATH):
    """The operator input: absent means enabled. The file must be a regular root-owned file that no one else
    can write, at most MAX_INPUT_BYTES."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"http3 input {path} is not a regular file")
    if info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid()):
        raise ValueError(f"http3 input {path} must be owned by root and writable by no one else")
    with open(path, "rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"http3 input {path} is larger than {MAX_INPUT_BYTES} bytes")
    return parse_input(raw.decode("utf-8", "replace"))

# --- Firewall decisions (the deployment layer executes them through its command runner) ---

CSF = "/usr/sbin/csf"
CSF_CONF = "/etc/csf/csf.conf"
CSF_DISABLE = "/etc/csf/csf.disable"
CSF_KEYS = ("UDP_IN", "UDP6_IN")
_CSF_LINE = {key: re.compile(r"^(" + key + r"\s*=\s*\")([^\"\n]*)(\"[^\n]*)$", re.M | re.A) for key in CSF_KEYS}

def port_list_covers(value, port=443):
    """A csf port list ("20,21,3000:4000") contains the port, alone or inside a range."""
    for token in value.split(","):
        token = token.strip(" \t\r\n")
        if token == str(port):
            return True
        low, sep, high = token.partition(":")
        if sep and re.fullmatch(r"[0-9]+", low) and re.fullmatch(r"[0-9]+", high) and int(low) <= port <= int(high):
            return True
    return False

def csf_plan(text):
    """What csf.conf needs for UDP 443: {"supported", "keys": {key: {"value", "open"}}, "changed", "text"}.
    UDP_IN must exist exactly once or nothing is planned (supported false); UDP6_IN is changed when present
    exactly once. A key that already covers 443 is left alone. Only the quoted value of a line changes."""
    keys, out = {}, text
    for key in CSF_KEYS:
        found = _CSF_LINE[key].findall(text)
        if len(found) == 1:
            keys[key] = {"value": found[0][1], "open": port_list_covers(found[0][1])}
    supported = "UDP_IN" in keys
    changed = False
    if supported:
        for key, state in keys.items():
            if state["open"]:
                continue
            value = state["value"]
            new = value + "443" if value == "" or value.endswith(",") else value + ",443"
            out = _CSF_LINE[key].sub(lambda m: m.group(1) + new + m.group(3), out, count=1)
            changed = True
    return {"supported": supported, "keys": keys, "changed": changed, "text": out}

def nft_input_drop(ruleset):
    """An nftables input hook with policy drop, and whether any rule already mentions UDP port 443."""
    drop = re.search(r"hook input priority [^;]*; policy drop;", ruleset, re.A) is not None
    mentioned = re.search(r"udp dport (\{[^}]*\b443\b[^}]*\}|443\b)", ruleset, re.A) is not None
    return {"input_policy_drop": drop, "udp_443_mentioned": mentioned}

# --- Protocol share of the access logs ---

DOMLOGS = "/etc/apache2/logs/domlogs"
DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
SHARE_LINES = 2000
SHARE_MAX_BYTES = 4 * 1024 * 1024
LINE_MAX = 8192
CLASSES = ("h1", "h2", "h3", "other", "unparsed")
# Optional "<domain>:<port> " prefix (before cPanel's splitlogs), then "%a %l %u [%t] "%r" %>s ".
_LINE = re.compile(r'^(?:\S+:\d+ )?\S+ \S+ \S+ \[[^\]]+\] "([^"\\]*(?:\\.[^"\\]*)*)" \d{3} ', re.A)

def classify(line):
    """h1 (HTTP/1.0 and 1.1), h2, h3, other (another or no version in the request line) or unparsed."""
    if len(line) > LINE_MAX:
        return "unparsed"
    match = _LINE.match(line)
    if match is None:
        return "unparsed"
    words = match.group(1).split(" ")
    version = words[-1] if len(words) >= 2 else ""
    if version in ("HTTP/1.1", "HTTP/1.0"):
        return "h1"
    if version == "HTTP/2":
        return "h2"
    if version == "HTTP/3":
        return "h3"
    return "other"

def tail_lines(path, count=SHARE_LINES, max_bytes=SHARE_MAX_BYTES):
    """The last `count` complete lines of a file, reading at most `max_bytes` from its end; [] when absent.
    Only regular files are read (never through a symlink)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return []
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return []
        start = max(0, info.st_size - max_bytes)
        os.lseek(fd, start, os.SEEK_SET)
        data = b""
        while len(data) < info.st_size - start:
            chunk = os.read(fd, min(1 << 20, info.st_size - start - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # the first line may be cut
    if lines and lines[-1] == b"":
        lines.pop()
    return [line.decode("latin-1") for line in lines[-count:]]

def basis_points(part, total):
    """part/total in basis points, rounded half up, in integers (identical in every language)."""
    return 0 if total == 0 else (part * 20000 + total) // (2 * total)

def vhost_share(logdir, domain, count=SHARE_LINES, max_bytes=SHARE_MAX_BYTES):
    """The protocol share of one vhost from the last `count` lines of its plain and its -ssl_log domlog."""
    if not DOMAIN.match(domain):
        raise ValueError(f"invalid domain {domain!r}")
    counts = {name: 0 for name in CLASSES}
    sources = []
    for suffix in ("", "-ssl_log"):
        lines = tail_lines(f"{logdir}/{domain}{suffix}", count, max_bytes)
        if lines:
            sources.append(domain + suffix)
        for line in lines:
            counts[classify(line)] += 1
    parsed = counts["h1"] + counts["h2"] + counts["h3"] + counts["other"]
    return {"vhost": domain, "lines": parsed + counts["unparsed"], **counts, "sources": sources,
            "share_bp": {name: basis_points(counts[name], parsed) for name in ("h1", "h2", "h3")}}

def shares(logdir, domains, count=SHARE_LINES, max_bytes=SHARE_MAX_BYTES):
    """vhost_share for each domain, sorted by name."""
    return [vhost_share(logdir, domain, count, max_bytes) for domain in sorted(set(domains))]

# --- Observations of the lab experiment ---

def udp_listeners(ss_text):
    """Local address -> sorted process names from `ss -H -lunp`. With -u, ss prints a leading Netid column
    ("udp"), so the local address is the fifth field then and the fourth without it."""
    result = {}
    for line in ss_text.splitlines():
        fields = line.split()
        shift = 1 if fields and fields[0] in ("udp", "tcp") else 0
        if len(fields) < 5 + shift:
            continue
        names = re.findall(r'\("([^"]+)"', " ".join(fields[5 + shift:]))
        result.setdefault(fields[3 + shift], set()).update(names)
    return {key: sorted(value) for key, value in sorted(result.items())}

def main(argv):
    """`share <logdir> <domain>... [--lines=N]`: the protocol share of each domain as JSON (the lab experiment runs
    it as root over the domlogs)."""
    lines, rest = SHARE_LINES, []
    for arg in argv:
        if arg.startswith("--lines="):
            lines = int(arg[len("--lines="):])
        else:
            rest.append(arg)
    if len(rest) < 3 or rest[0] != "share":
        raise SystemExit("usage: http3.py share <logdir> <domain>... [--lines=N]")
    print(json.dumps(shares(rest[1], rest[2:], lines), sort_keys=True))

if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
