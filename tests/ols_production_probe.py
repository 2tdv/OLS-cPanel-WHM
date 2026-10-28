#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import cpanel_vhosts as cv
import ols_config_lint as lint
import ols_production_probe as prod
import tenant_isolation_probe as iso

sample = json.loads((ROOT / "tests/Fixtures/cpanel_vhosts.json").read_text())
plan = {v["name"]: dict(v, user="olscpa") for v in cv.account_vhosts(
    "olscpa", cv.parse_userdatadomains(sample["rows"]), sample["userdata"])}
config = iso.server_config((iso.TEMPLATES / "ownership_httpd_config.conf").read_text(), plan=plan, production=True)
assert lint.lint(config) == []
assert "address              *:80" in config and "address              *:443" in config
assert "8088" not in config and "8443" not in config and "allow                ALL" in config
# Every case targets a lab name, and recovery never imports the development checkout.
assert all(c[0] in ("http", "https") and c[1].endswith((".test", ".example", ".example.test")) for c in prod.CASES)
import hybrid_lab
tweaks = {"apache_port": "0.0.0.0:80", "apache_ssl_port": "0.0.0.0:443"}
for hybrid in (False, True):
    script = hybrid_lab.recovery_script("/var/lib/r/1", tweaks if hybrid else {}, {"/h/.htaccess": True, "/h/p.php": False}
                                        if hybrid else {}, ["/h/.w"] if hybrid else [], hybrid, "olscpb", {"/h/.htaccess": "ab" * 32})
    assert subprocess.run(["/bin/sh", "-n"], input=script, text=True).returncode == 0
    assert "enablefileprotect" in script and "vm-qualification" not in script and "exit 1" in script and "flock -w" in script
    assert ("value=0.0.0.0:443" in script and "runuser -u olscpb -- sh -c 'cat > \"$1\"' sh /h/.htaccess < \"$B/files/0\"" in script
            and "rm -f -- /h/p.php" in script and "rmdir -- /h/.w" in script and "nft delete table" in script
            and "ab" * 32 in script) is hybrid
    if hybrid:
        # The firewall goes only after Apache is healthy again (RV-28).
        assert script.index("if healthy; then") < script.index("nft delete table")
for bad in ({"apache_port": "0.0.0.0:80'; rm -rf /"}, {"other": "0.0.0.0:80"}):
    try:
        hybrid_lab.recovery_script("/b", bad, {}, [], True)
        raise AssertionError(bad)
    except ValueError:
        pass
rules = hybrid_lab.nft_ruleset((81, 444))
assert 'iifname != "lo" drop' in rules and "meta skuid != { 0, nobody }" in rules and "fib daddr type local" in rules
conf = hybrid_lab.remoteip_conf(["127.0.0.1", "::1"])
assert "RemoteIPHeader X-OLS-Client-IP" in conf and "X-Forwarded-For" not in conf
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/ols_production_probe.py"), "--rpm", "/x"],
                        capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("Production-port experiment configuration and guard checks passed.")

# Declared outcomes (RV-06): every comparison must be equal and the host restored.
good = {"comparison": {"a": {"match": True}}, "comparison_v6": {"a": {"match": True}}, "tls_match": {"x": True},
        "tls_match_v6": {"x": True}, "ws_session_match": {"w": True}, "log_routing": {"ok": True}, "ols_log_errors": [],
        "restored": {"apache": True}, "reload": {"after": {"olscpa": True, "olscpb": True}}}
assert all(prod.expected_outcomes(good).values()) and "dedicated-ipv6-requests-equal" not in prod.expected_outcomes(good)
assert not prod.expected_outcomes(dict(good, dedicated_ipv6="2001:db8::1"))["dedicated-ipv6-requests-equal"]
for key, bad in (("comparison_v6", {"a": {"match": False}}), ("comparison", {}), ("restored", {"apache": False}),
                 ("ols_log_errors", ["[ERROR] x"])):
    assert not all(prod.expected_outcomes(dict(good, **{key: bad})).values()), key
page = lambda **k: {"status": "200", "content": json.dumps(dict({"server": "Apache", "remote": iso.CLIENT_IP, "https": None,
                                                                 "user": "olscpb", "host": "b", "query": "q=olscp"}, **k))}
side = lambda: {"http": page(), "https": page(https="on"), "http-spoofed": page(), "https-spoofed": page(https="on"),
                "acme": page(), "acme-https": page(https="on"), **{k + "-websocket": {"status": "101", "accept_ok": True, "echo_ok": True, "backend_saw":
                {"request_line": "GET /socket?probe=1 HTTP/1.1", "host": "b", "x-forwarded-for": iso.CLIENT_IP}} for k in ("http", "https")}}
hybrid = dict(good, hybrid_vhosts=["b"], hybrid_apache=side(), hybrid_ols=side(),
              hybrid_backend_access={"external": 28, "tenant": 7, "root": "200"}, hybrid_log_routing={"ok": True})
hybrid["hybrid_ols"]["https-websocket"]["backend_saw"]["x-forwarded-for"] = f"{iso.CLIENT_IP}, {iso.CLIENT_IP}"
assert all(prod.expected_outcomes(hybrid).values()) and len(prod.expected_outcomes(hybrid)) == len(prod.expected_outcomes(good)) + 8
def broken(change):
    case = json.loads(json.dumps(hybrid))
    change(case)
    return not all(prod.expected_outcomes(case).values())
assert broken(lambda c: c["hybrid_ols"].update({"https-spoofed": page(https="on", remote="203.0.113.9")}))
assert broken(lambda c: c["hybrid_ols"].update({"acme": page(server="LiteSpeed")}))
assert broken(lambda c: c["hybrid_ols"].update({"acme-https": page()}))
assert broken(lambda c: c["hybrid_ols"]["http-websocket"].update(echo_ok=False))
assert broken(lambda c: c["hybrid_ols"]["http-websocket"]["backend_saw"].update(host="a"))
assert broken(lambda c: c["hybrid_backend_access"].update(tenant=0))
assert broken(lambda c: c["hybrid_backend_access"].update(root="000"))
assert broken(lambda c: c.update(hybrid_log_routing={"ok": False}))
assert broken(lambda c: c["hybrid_ols"].update({"http": page(https="on")}))
print("Production-port declared outcomes checks passed.")
