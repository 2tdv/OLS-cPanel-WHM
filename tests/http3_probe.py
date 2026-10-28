#!/usr/bin/python3
"""Offline checks of the FV-04 lab experiment (build/vm-qualification/http3_probe.py): guards, the pinned client image,
curl output parsing, the recovery script and every declared outcome against good and broken observations."""
import copy
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import http3
import http3_probe as hp

PROBE = str(ROOT / "build/vm-qualification/http3_probe.py")
result = subprocess.run([sys.executable, PROBE, "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
# The client image is pinned by digest (never a tag) and both digests are recorded.
assert hp.pins_ready() == [] and hp.IMAGE_REF == hp.IMAGE["repository"] + "@" + hp.IMAGE["digest"] and "@sha256:" in hp.IMAGE_REF
assert hp.pins_ready({"digest": "sha256:" + "a" * 64, "amd64_digest": "latest"}) == ["amd64_digest"] and hp.pins_ready({}) == ["amd64_digest", "digest"]
assert hp.IMAGE["repository"].startswith("docker.io/") and ":" not in hp.IMAGE["repository"].split("/")[-1]
# Anything the plugin preview or a product installation leaves behind is refused as residue, /run state included.
assert {"/usr/local/ols-cpanel", "/var/lib/ols-cpanel", "/run/ols-cpanel"} <= set(hp.PREVIEW)
assert hp.SHM_DIR == "/run/ols-cpanel/shm" and "/dev/shm" not in hp.SHM_DIR

h2_out = {"exit_code": 0, "stdout": "owner=olscpa host=a\n\nCURLMETA 200 2 19\n",
          "stderr": "HTTP/2 200 \r\ncontent-type: text/plain\r\nx-olscp-lab: olscpa\r\nalt-svc: h3=\":8443\"; ma=2592000\r\nserver: LiteSpeed\r\n"
                    "date: x\r\n\r\n"}
h3_out = dict(h2_out, stderr=h2_out["stderr"].replace("HTTP/2", "HTTP/3"), stdout=h2_out["stdout"].replace("200 2 19", "200 3 19"))
parsed = hp.parse_curl(h2_out)
assert parsed["status"] == "200" and parsed["version"] == "2" and parsed["size"] == 19 and parsed["alt_svc"] == 'h3=":8443"; ma=2592000'
assert parsed["headers"] == {"content-type": "text/plain", "x-olscp-lab": "olscpa"}, parsed  # only the compared subset
assert parsed["body_sha256"] == hp.hashlib.sha256(b"owner=olscpa host=a\n").hexdigest()
assert hp.parse_curl(h3_out)["version"] == "3" and hp.parse_curl(h3_out)["body_sha256"] == parsed["body_sha256"]
interim = dict(h2_out, stderr="HTTP/1.1 100 Continue\r\n\r\n" + h2_out["stderr"])
assert hp.parse_curl(interim)["alt_svc"] == parsed["alt_svc"]
failed = hp.parse_curl({"exit_code": 7, "stdout": "", "stderr": "curl: (7) Failed to connect"})
assert failed["status"] == "" and failed["body_sha256"] is None and failed["exit_code"] == 7 and failed["alt_svc"] is None
cert = hp.parse_certificate("* Server certificate:\n*  subject: CN=olstest1.example.test\n*  start date: Oct  1 00:00:00 2026 GMT\n"
                            "*  expire date: Dec 30 00:00:00 2026 GMT\n*  issuer: C=US; O=Example; CN=CA\n*  SSL certificate verify result: x\n")
assert cert == {"subject": "CN=olstest1.example.test", "start_date": "Oct  1 00:00:00 2026 GMT", "expire_date": "Dec 30 00:00:00 2026 GMT",
                "issuer": "C=US; O=Example; CN=CA"}, cert
assert hp.parse_certificate("") == {}

# ss output of the QUIC sockets.
ss = ('udp   UNCONN 0      0       10.250.0.1:8443      0.0.0.0:*    users:(("litespeed",pid=12,fd=9),("litespeed",pid=13,fd=9))\n'
      'udp   UNCONN 0      0        127.0.0.1:8443      0.0.0.0:*    users:(("litespeed",pid=12,fd=10))\n'
      'udp   UNCONN 0      0          0.0.0.0:68        0.0.0.0:*    users:(("dhclient",pid=5,fd=6))\n')
assert http3.udp_listeners(ss) == {"0.0.0.0:68": ["dhclient"], "10.250.0.1:8443": ["litespeed"], "127.0.0.1:8443": ["litespeed"]}
assert http3.udp_listeners('UNCONN 0 0 [::]:5353 [::]:* users:(("avahi",pid=1,fd=1))\n') == {"[::]:5353": ["avahi"]}
assert http3.udp_listeners("") == {}

script = hp.recovery_script("/var/lib/ols-cpanel-lab-recovery/1", True)
assert subprocess.run(["/bin/sh", "-n"], input=script, text=True).returncode == 0
assert "vm-qualification" not in script and "flock -w 900" in script and "exit 1" in script
for needle in ("rpm -e ols-cpanel-openlitespeed", "rm -rf /usr/local/lsws", "/run/ols-cpanel /dev/shm/ols /tmp/lshttpd /var/lib/ols-cpanel\n",
               "podman rmi --force docker.io/ymuski/curl-http3@sha256:", "ip netns delete olscpc", "podman image exists",
               "runuser -u olscpa -- rm -f -- /home/olscpa/public_html/olscp-h3.php", "runuser -u olscpb -- rm -f -- /home/olscpb/public_html/olscp-h3.txt",
               "runuser -u olscpa -- rm -f -- /home/olscpa/public_html/blog/olscp-h3.php"):
    assert needle in script, needle
# Tenant files are removed as their owner; the image is only removed when the run pulled it.
assert "\n    rm -rf -- /home" not in script and "rmi" not in hp.recovery_script("/b", False) and "image exists" not in hp.recovery_script("/b", False)

def entry(status="200", version="2", sha="a" * 64, size=19, headers=None, alt='h3=":8443"; ma=2592000', exit_code=0):
    return {"exit_code": exit_code, "status": status, "version": version, "size": size, "body_sha256": sha,
            "headers": headers if headers is not None else {"content-type": "text/plain"}, "alt_svc": alt}

def pair(host, kind, **change):
    sha = ("b" if kind == "static" else "a") * 63 + host[0]
    size = 531000 if kind == "static" else 19
    h2, h3 = entry(sha=sha, size=size), entry(version="3", sha=sha, size=size)
    h2.update(change.get("h2", {}))
    h3.update(change.get("h3", {}))
    return {"vhost": host, "kind": kind, "h2": h2, "h3": h3}

A, B, SUB = hp.A, hp.B, hp.SUB
def lines(host):
    rows = []
    for kind in ("php", "static"):
        for via, proto in (("h2", "HTTP/2"), ("h3", "HTTP/3")):
            line = f'203.0.113.5 - - [27/Oct/2026:12:00:00 +0000] "GET /olscp-h3.{"php" if kind == "php" else "txt"}?via={via}&run=abc HTTP/{proto[-1]}" 200 19 "-" "curl"'
            rows.append({"file": host + "-ssl_log", "via": via, "line": line})
    return rows
def share(host, h3=2):
    return {"vhost": host, "h3": h3, "h2": 2, "share_bp": {"h1": 0, "h2": 5000, "h3": 5000}}
cert = lambda name: {"subject": f"CN={name}", "issuer": "CN=CA", "start_date": "a", "expire_date": "b"}
good = {
    "image_verified": True, "ols_log_errors": [], "files_before": {"olscpa": ["f"]}, "files_after": {"olscpa": ["f"]},
    "restored": {"residue": True, "http": True},
    "observations": {
        "client": {"features": "Features: alt-svc HTTP2 HTTP3 HTTPS-proxy"},
        "udp_on": {"tls": [f"127.0.0.1:{hp.TLS_PORT}", f"{hp.HOST_IP}:{hp.TLS_PORT}"], "other": [], "owned_by_ols": True},
        "shm": {"run_files": ["/run/ols-cpanel/shm/.quicshmdata.lsshm"], "dev_shm_files": []},
        "plain_http": entry(alt=None),
        "pairs": [pair(h, k) for h in (A, SUB, B) for k in ("php", "static")],
        "certificates": {A: {"h2": cert("a"), "h3": cert("a")}, SUB: {"h2": cert("sub"), "h3": cert("sub")},
                         B: {"h2": cert("b"), "h3": cert("b")}},
        "log_lines": {h: lines(h) for h in (A, SUB, B)},
        "share": [share(h) for h in (A, SUB, B)],
        "opt_out": {"udp_tls": [], "h3_exit": 28, "alt_svc": None, "h2_status": "200", "h2_version": "2"}}}
cases = hp.expected_outcomes(good)
assert set(cases) >= {"quic-udp-on-tls-listeners", "http3-equals-http2", "per-vhost-certificate-over-quic", "opt-out-no-quic",
                      "http3-lines-in-right-vhost-log", "alt-svc-on-https", "quic-state-under-run"}
assert all(cases.values()), [k for k, v in cases.items() if not v]

def broken(change, name):
    case = copy.deepcopy(good)
    change(case)
    failing = [k for k, v in hp.expected_outcomes(case).items() if not v]
    return name in failing

o = lambda c: c["observations"]
for name, change in [
        ("client-supports-http3", lambda c: o(c)["client"].__setitem__("features", "Features: HTTP2")),
        ("client-supports-http3", lambda c: c.__setitem__("image_verified", False)),
        ("quic-udp-on-tls-listeners", lambda c: o(c)["udp_on"].__setitem__("tls", [f"127.0.0.1:{hp.TLS_PORT}"])),
        ("quic-udp-on-tls-listeners", lambda c: o(c)["udp_on"].__setitem__("other", ["127.0.0.1:8088"])),
        ("quic-udp-on-tls-listeners", lambda c: o(c)["udp_on"].__setitem__("owned_by_ols", False)),
        ("quic-state-under-run", lambda c: o(c)["shm"].__setitem__("run_files", [])),
        ("quic-state-under-run", lambda c: o(c)["shm"].__setitem__("dev_shm_files", ["/dev/shm/ols/.quicshmdata.lsshm"])),
        ("alt-svc-on-https", lambda c: o(c)["pairs"][0]["h2"].__setitem__("alt_svc", None)),
        ("alt-svc-on-https", lambda c: o(c)["pairs"][1]["h3"].__setitem__("alt_svc", 'h3=":9999"')),
        ("no-alt-svc-on-http", lambda c: o(c)["plain_http"].__setitem__("alt_svc", 'h3=":8443"')),
        ("http3-equals-http2", lambda c: o(c)["pairs"][0]["h3"].__setitem__("status", "404")),
        ("http3-equals-http2", lambda c: o(c)["pairs"][1]["h3"].__setitem__("body_sha256", "c" * 64)),
        ("http3-equals-http2", lambda c: o(c)["pairs"][2]["h3"].__setitem__("version", "2")),       # not really HTTP/3
        ("http3-equals-http2", lambda c: o(c)["pairs"][3]["h2"].__setitem__("version", "1.1")),
        ("http3-equals-http2", lambda c: o(c)["pairs"][0]["h3"].__setitem__("headers", {"content-type": "text/html"})),
        ("http3-equals-http2", lambda c: o(c)["pairs"].pop()),
        ("http3-equals-http2", lambda c: o(c)["pairs"][0]["h3"].__setitem__("size", 5)),
        ("static-file-served-in-full", lambda c: o(c)["pairs"][1]["h3"].__setitem__("size", 100)),
        ("per-vhost-certificate-over-quic", lambda c: o(c)["certificates"][A].__setitem__("h3", cert("default"))),
        ("per-vhost-certificate-over-quic", lambda c: o(c)["certificates"][B].__setitem__("h3", cert("a")) or o(c)["certificates"][B].__setitem__("h2", cert("a"))),
        ("per-vhost-certificate-over-quic", lambda c: o(c)["certificates"][SUB].__setitem__("h3", {})),
        ("http3-lines-in-right-vhost-log", lambda c: o(c)["log_lines"][A].pop()),
        ("http3-lines-in-right-vhost-log", lambda c: o(c)["log_lines"][B].append(o(c)["log_lines"][A][0])),
        ("http3-lines-in-right-vhost-log", lambda c: o(c)["log_lines"][A][1].__setitem__("line", o(c)["log_lines"][A][1]["line"].replace("HTTP/3", "HTTP/2"))),
        ("http3-lines-in-right-vhost-log", lambda c: o(c)["log_lines"][B][0].__setitem__("file", A)),
        ("protocol-share", lambda c: o(c)["share"][0].__setitem__("h3", 0)),
        ("protocol-share", lambda c: o(c)["share"][1]["share_bp"].__setitem__("h2", 0)),
        ("protocol-share", lambda c: o(c)["share"].pop()),
        ("opt-out-no-quic", lambda c: o(c)["opt_out"].__setitem__("udp_tls", [f"127.0.0.1:{hp.TLS_PORT}"])),
        ("opt-out-no-quic", lambda c: o(c)["opt_out"].__setitem__("h3_exit", 0)),
        ("opt-out-no-quic", lambda c: o(c)["opt_out"].__setitem__("alt_svc", 'h3=":8443"')),
        ("opt-out-no-quic", lambda c: o(c)["opt_out"].__setitem__("h2_status", "503")),
        ("no-ols-errors", lambda c: c.__setitem__("ols_log_errors", ["[ERROR] quic"])),
        ("tenant-files-restored", lambda c: c.__setitem__("files_after", {"olscpa": []})),
        ("host-restored", lambda c: c["restored"].__setitem__("residue", False))]:
    assert broken(change, name), name
print("HTTP/3 experiment guards, pinned image, curl parsing, recovery script and declared outcomes checks passed.")
