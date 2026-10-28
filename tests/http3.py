#!/usr/bin/python3
"""HTTP/3 (FV-04): the lab reference (build/vm-qualification/http3.py) and the PHP port (Http3Input, Http3Firewall,
ProtocolShare) agree on a corpus (operator input, csf.conf plans, nftables rulesets, access log lines and files),
and the reference's own invariants hold: the template and the compiled configuration (QUIC on the HTTPS listeners,
state under /run, never /dev/shm or /tmp), the opt-out, the log format and the share arithmetic."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import cpanel_surface
import http3
import tenant_isolation_probe as iso

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"

INPUTS = ["", "{}", '{"enabled": true}', '{"enabled": false}', '{"enabled": 0}', '{"enabled": "false"}', '{"enabled": null}',
          '{"enabled": false, "other": 1}', '{"other": 1}', "[]", "[false]", "true", "null", '"off"', "{bad", '{"enabled": false,}',
          ' \n{"enabled":false}\n', '{"enabled": false, "enabled": true}', '{"0": 1}']
EXPECTED_INPUT = {"{}": True, '{"enabled": true}': True, '{"enabled": false}': False, ' \n{"enabled":false}\n': False,
                  '{"enabled": false, "enabled": true}': True}

CSF = [
    '# csf\nTESTING = "0"\nTCP_IN = "20,21,22,80,443"\nUDP_IN = "20,21,53"\nUDP6_IN = "20,21,53"\nUDP_OUT = "20,113,123"\n',
    'UDP_IN = "20,21,53,443"\nUDP6_IN = "20,21,53"\n',
    'UDP_IN = "3000:4000,53"\nUDP6_IN = "400:500"\n',
    'UDP_IN = "500:600"\nUDP6_IN = ""\n',
    'UDP_IN = "20,"\n',
    'UDP_IN="53" # note\nUDP6_IN =   "53"   \n',
    '#UDP_IN = "53"\nTCP_IN = "80"\n',
    'UDP_IN = "1"\nUDP_IN = "2"\n',
    'UDP_IN = "1"\nUDP6_IN = "1"\nUDP6_IN = "2"\n',
    "UDP_IN = '53'\n",
    'UDP_IN = "53"',
    'UDP_IN = "53"\r\nUDP6_IN = "53"\r\n',
    '  UDP_IN = "53"\n',
    "",
    'UDP_IN\n= "53"\n',
    'XUDP_IN = "53"\nUDP_IN_X = "1"\nUDP_IN = "7"\n',
    'UDP_IN = "1:65535"\nUDP6_IN = "443:443"\n',
    'UDP_IN = "0443,443x,44:3"\n',
]
PORTS = ["", "443", "20,443", "20, 443", "400:500", "444:500", "1:", ":443", "a:b", "443:443", "1:65535", "-1:500", "4_43", "0443"]
NFT = [
    "table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n  tcp dport 22 accept\n }\n}\n",
    "table inet filter {\n chain input {\n  type filter hook input priority filter; policy accept;\n }\n}\n",
    "chain input {\n type filter hook input priority 0; policy drop;\n udp dport 443 accept\n}\n",
    "chain input {\n type filter hook input priority 0; policy drop;\n udp dport { 80, 443 } accept\n}\n",
    "chain input {\n type filter hook input priority 0; policy drop;\n udp dport 4430 accept\n tcp dport 443 accept\n}\n",
    "table ip x {\n chain forward {\n  type filter hook forward priority 0; policy drop;\n }\n}\n",
    "",
]
H = '203.0.113.5 - - [27/Oct/2026:12:00:00 +0000] "{r}" {s} 123 "-" "curl/8.5.0"'
LINES = [
    H.format(r="GET / HTTP/1.1", s=200), H.format(r="GET / HTTP/1.0", s=200), H.format(r="GET /a HTTP/2", s=200),
    H.format(r="GET /a?x=1 HTTP/3", s=404), H.format(r="HEAD /h3 HTTP/3", s=200), H.format(r="POST /p HTTP/1.1", s=500),
    "example.test:443 " + H.format(r="GET /b HTTP/3", s=200), "example.test:80 " + H.format(r="GET /b HTTP/1.1", s=301),
    '2001:db8::1 - - [27/Oct/2026:12:00:00 +0000] "GET /v6 HTTP/2" 200 5 "-" "-"',
    'example.test:443 2001:db8::1 - - [27/Oct/2026:12:00:00 +0000] "GET /v6 HTTP/3" 200 5 "-" "-"',
    H.format(r="GET /q\\\"x HTTP/3", s=200), H.format(r="-", s=400), H.format(r="\\x16\\x03\\x01", s=400), H.format(r="GET /old", s=200),
    H.format(r="GET / HTTP/0.9", s=200), H.format(r="GET / HTTP/1.1 HTTP/3", s=200), H.format(r="", s=400), H.format(r="GET / HTTP/3.0", s=200),
    H.format(r="GET / HTTP/1.1", s="20"), "garbage", "", "203.0.113.5 - - 27/Oct/2026 \"GET / HTTP/3\" 200 1", H.format(r="GET / HTTP/3", s=200) + "\r",
    H.format(r="GET /" + "a" * 9000 + " HTTP/3", s=200), 'u:443 ' + 'x' * 5 + ' - - [t] "GET / HTTP/2" 200 ',
    H.format(r="GET / http/3", s=200), H.format(r="GET /x\\\\ HTTP/2", s=200), H.format(r="GET / HTTP/2 ", s=200),
]
EXPECTED_CLASS = {LINES[0]: "h1", LINES[1]: "h1", LINES[2]: "h2", LINES[3]: "h3", LINES[6]: "h3", LINES[7]: "h1", LINES[8]: "h2",
                  LINES[9]: "h3", LINES[10]: "h3", LINES[11]: "other", LINES[13]: "other", LINES[14]: "other", LINES[15]: "h3",
                  LINES[17]: "other", "garbage": "unparsed", "": "unparsed"}
BASIS = [(0, 0), (0, 5), (1, 3), (2, 3), (1, 2), (1, 8), (7, 8), (5, 5), (1, 1000000), (333, 1000), (1, 20000), (1, 40000)]

# --- reference invariants (Python only) ---
for text in INPUTS:
    try:
        got = http3.parse_input(text)
    except ValueError:
        got = "error"
    if text in EXPECTED_INPUT:
        assert got is EXPECTED_INPUT[text], (text, got)
    else:
        assert got == "error", (text, got)
for line, want in EXPECTED_CLASS.items():
    assert http3.classify(line) == want, (line, want, http3.classify(line))
assert http3.classify(LINES[21]) == "unparsed" and http3.classify(LINES[22]) == "h3"
assert http3.classify(LINES[23]) == "unparsed"  # longer than LINE_MAX
assert http3.basis_points(1, 3) == 3333 and http3.basis_points(2, 3) == 6667 and http3.basis_points(1, 8) == 1250
assert http3.basis_points(1, 40000) == 0 and http3.basis_points(1, 20000) == 1 and http3.basis_points(0, 0) == 0
plan = http3.csf_plan(CSF[0])
assert plan["supported"] and plan["changed"] and plan["text"] == CSF[0].replace('UDP_IN = "20,21,53"', 'UDP_IN = "20,21,53,443"').replace(
    'UDP6_IN = "20,21,53"', 'UDP6_IN = "20,21,53,443"')
assert not http3.csf_plan(CSF[1])["keys"]["UDP_IN"]["value"] == "" and http3.csf_plan(CSF[1])["text"].count("443") == 2
assert not http3.csf_plan(CSF[6])["supported"] and not http3.csf_plan(CSF[7])["supported"] and http3.csf_plan(CSF[6])["text"] == CSF[6]

# The access log format the product writes carries the request line the parser reads (CpanelSurface.ACCESS_FORMAT);
# OLS ends it in HTTP/1.0, 1.1, 2 or 3 (AccessLog fixHttpVer).
assert '"%r"' in cpanel_surface.ACCESS_FORMAT and cpanel_surface.ACCESS_FORMAT.startswith("{domain}:%p %a %l %u %t ")

# The template and the compiled configuration: QUIC on, state under /run/ols-cpanel, never a world-writable directory.
template = (ROOT / "build/vm-qualification/ols-lab/ownership_httpd_config.conf").read_text()
tuning = template[template.index("tuning {"):template.index("}", template.index("tuning {"))]
assert "    quicEnable           1\n" in tuning and "    quicShmDir           /run/ols-cpanel/shm/\n" in tuning
assert "/dev/shm" not in tuning.replace("# ", "#") or all("quic" not in l for l in tuning.splitlines() if "/dev/shm" in l)
assert not any(("/tmp" in l or "/dev/shm" in l) for l in tuning.splitlines() if l.strip().startswith("quic"))
plan_ = {"x.test": {"user": "u", "docroot": "/home/u/public_html", "aliases": [], "service_domains": [], "ip": "192.0.2.1", "name": "x.test"}}
for production in (True, False):
    on = iso.server_config(template, plan=plan_, production=production)
    off = iso.server_config(template, plan=plan_, production=production, http3=False)
    secure = on.count("    secure               1\n")
    assert secure >= 1 and on.count("    enableQuic           1\n") == secure and "    quicEnable           1\n" in on
    assert off.count("    enableQuic           0\n") == secure and "    quicEnable           0\n" in off and "quicEnable           1" not in off
    assert off == on.replace("quicEnable           1", "quicEnable           0").replace("enableQuic           1", "enableQuic           0")
    # Plain-HTTP listeners carry no QUIC key (OLS reads enableQuic on secure listeners only).
    for block in on.split("\nlistener ")[1:]:
        assert ("enableQuic" in block) == ("secure               1" in block), block
try:
    iso.server_config(template.replace("    quicEnable           1\n", "    quicEnable           0\n"), plan=plan_)
    raise AssertionError("a template without quicEnable 1 must be refused")
except ValueError:
    pass

# --- Python/PHP corpus ---
with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    log = tmp / "logs"
    log.mkdir()
    def write(name, lines, newline_end=True):
        (log / name).write_bytes(("\n".join(lines) + ("\n" if newline_end else "")).encode("latin-1"))
    sample = [l for l in LINES if l and l != "garbage"]
    write("example.test", [H.format(r=f"GET /{n} HTTP/1.1", s=200) for n in range(30)])
    write("example.test-ssl_log", [H.format(r=f"GET /{n} HTTP/{'3' if n % 3 == 0 else '2'}", s=200) for n in range(60)])
    write("mixed.test", sample)
    write("mixed.test-ssl_log", sample * 3, newline_end=False)
    write("only-ssl.test-ssl_log", [H.format(r="GET / HTTP/3", s=200)] * 5)
    write("empty.test", [])
    (log / "link.test").symlink_to(log / "example.test")
    (log / "dir.test").mkdir()
    (log / "big.test-ssl_log").write_bytes(b"x" * 100 + b"\n" + ("\n".join(H.format(r=f"GET /{n} HTTP/3", s=200) for n in range(400)) + "\n").encode())
    tails = [{"path": str(log / name), "count": c, "max_bytes": m} for name in
             ("example.test", "mixed.test-ssl_log", "big.test-ssl_log", "empty.test", "link.test", "dir.test", "missing.test")
             for c, m in ((10, 4 << 20), (2000, 4 << 20), (5, 300), (1, 1), (0, 100), (100000, 100000))]
    shares = [{"dir": str(log), "domains": d, "count": c, "max_bytes": m} for d in
              (["example.test"], ["mixed.test", "example.test", "mixed.test"], ["only-ssl.test", "empty.test", "link.test", "dir.test", "missing.test"],
               ["big.test"], ["bad_domain"], ["../x.test"], ["Example.test"], ["a.test", "-b.test"])
              for c, m in ((2000, 4 << 20), (7, 4 << 20), (50, 400))]
    corpus = {"input": INPUTS, "csf": CSF, "ports": PORTS, "nft": NFT, "lines": LINES, "tail": tails, "share": shares, "basis": BASIS}

    def reference():
        out = {"input": [], "csf": [http3.csf_plan(t) for t in CSF], "ports": [http3.port_list_covers(v) for v in PORTS],
               "nft": [http3.nft_input_drop(t) for t in NFT], "classify": [http3.classify(l) for l in LINES],
               "tail": [http3.tail_lines(c["path"], c["count"], c["max_bytes"]) for c in tails], "share": [],
               "basis": [http3.basis_points(p, t) for p, t in BASIS]}
        for text in INPUTS:
            try:
                out["input"].append(http3.parse_input(text))
            except ValueError:
                out["input"].append("error")
        for case in shares:
            try:
                out["share"].append(http3.shares(case["dir"], case["domains"], case["count"], case["max_bytes"]))
            except ValueError:
                out["share"].append("error")
        return out

    python = json.loads(json.dumps(reference()))
    result = subprocess.run([PHP, "-n", str(ROOT / "tests/http3.php")], input=json.dumps(corpus), capture_output=True, text=True, check=True)
    php = json.loads(result.stdout)
    for section in python:
        assert len(python[section]) == len(php[section]), section
        for index, (left, right) in enumerate(zip(python[section], php[section])):
            assert left == right, (section, index, left, right)
    # Bounds and refusals of the reference itself.
    share = http3.vhost_share(str(log), "example.test")
    assert share["h1"] == 30 and share["h3"] == 20 and share["h2"] == 40 and share["lines"] == 90 and share["share_bp"] == {
        "h1": 3333, "h2": 4444, "h3": 2222} and share["sources"] == ["example.test", "example.test-ssl_log"], share
    assert http3.vhost_share(str(log), "example.test", count=7)["lines"] == 14
    assert http3.vhost_share(str(log), "link.test")["lines"] == 0, "a symlinked log is never read"
    assert http3.vhost_share(str(log), "dir.test")["lines"] == 0 and http3.vhost_share(str(log), "missing.test")["sources"] == []
    big = http3.vhost_share(str(log), "big.test", count=2000, max_bytes=1 << 20)
    assert big["h3"] == 400 and big["unparsed"] == 1, big  # the 100-byte junk line is the first complete line
    small = http3.vhost_share(str(log), "big.test", count=2000, max_bytes=300)
    assert 0 < small["lines"] < 10, small  # bounded by bytes: the first, cut line is dropped
    assert [s["vhost"] for s in http3.shares(str(log), ["mixed.test", "example.test", "mixed.test"])] == ["example.test", "mixed.test"]
    for bad in ("bad_domain", "../x.test", "Example.test", "a.test/b", ""):
        try:
            http3.vhost_share(str(log), bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    # Reading never follows a symlink and refuses a FIFO without blocking.
    fifo = tmp / "fifo"
    os.mkfifo(fifo)
    assert http3.tail_lines(str(fifo)) == []
print(f"HTTP/3: {len(INPUTS)} inputs, {len(CSF)} csf.conf, {len(NFT)} nftables, {len(LINES)} log lines, {len(tails)} tails and "
      f"{len(shares)} share runs identical in Python and PHP; template, opt-out and log format checks passed.")
