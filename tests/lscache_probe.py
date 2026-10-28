#!/usr/bin/python3
"""Offline checks of the FV-01 lab experiment (build/vm-qualification/lscache_probe.py): guards, response
parsing, the recovery script and every declared outcome against good and broken observations."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import lscache
import lscache_probe as lp

PROBE = str(ROOT / "build/vm-qualification/lscache_probe.py")
result = subprocess.run([sys.executable, PROBE, "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
# Every artifact digest is recorded (an unrecorded one refuses the run before anything else happens).
assert lp.pins_ready() == []
assert lp.pins_ready({"x": {"sha256": "a" * 64}}) == [] and lp.pins_ready({"x": {"sha256": "A" * 64}}) == ["x"]
assert all(pin["url"].startswith("https://") and pin["version"] in pin["url"] for pin in lp.PINS.values())
# The plugin preview and every product state path are refused as residue.
assert {"/usr/local/ols-cpanel", "/var/lib/ols-cpanel"} <= set(lp.PREVIEW) and lscache.CACHE_ROOT.startswith(lp.STATE + "/")

raw = ("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-LiteSpeed-Cache: hit\r\nContent-Type: application/json\r\n\r\n"
       '{"owner": "olscpa", "host": "a", "nonce": "1"}\n')
parsed = lp.response(raw)
assert parsed["status"] == "200" and parsed["cache"] == "hit" and lp.page_data(parsed)["owner"] == "olscpa"
redirect = lp.response("HTTP/1.1 302 Found\r\nLocation: /cgi-sys/suspendedpage.cgi\r\n\r\n")
assert redirect["status"] == "302" and redirect["cache"] is None and redirect["location"] == "/cgi-sys/suspendedpage.cgi"
assert lp.response("")["status"] == "" and lp.page_data({"status": "500", "body": "{}"}) == {}

script = lp.recovery_script("/var/lib/ols-cpanel-lab-recovery/1", "ab" * 32, True)
assert subprocess.run(["/bin/sh", "-n"], input=script, text=True).returncode == 0
assert "vm-qualification" not in script and "flock -w 900" in script and "exit 1" in script
for needle in ("rpm -e ols-cpanel-openlitespeed", "rm -rf /usr/local/lsws", "/tmp/lshttpd /var/lib/ols-cpanel\n", "unsuspendacct user=olscpa",
               "Mysql delete_database name=olscpa_olscpwp", "Mysql delete_user name=olscpa_olscpwp", "runuser -u olscpa -- rm -rf -- "
               + lp.WP_DIR, "runuser -u olscpb -- sh -c 'cat > \"$1\"' sh /home/olscpb/public_html/.htaccess", "ab" * 32,
               "ip netns delete"):
    assert needle in script, needle
# Tenant files are removed as their owner; root never deletes through a tenant path.
assert "rm -f -- /home/olscpb/public_html/olscp-cache.php" in script and "\n    rm -rf -- /home" not in script
assert "olscp-cache-purge.php" not in script.split("olscpb")[-1]

def entry(status="200", cache=None, body=None, location=None):
    return {"status": status, "cache": cache, "location": location, "body": json.dumps(body) if isinstance(body, dict) else body or ""}

A, B, SUB = lp.A, lp.B, lp.SUB
page = lambda owner, host, nonce, cache: entry(cache=cache, body={"owner": owner, "host": host, "nonce": nonce})
counts = {"public_entries": 2, "public_bytes": 10, "private_entries": 0, "private_bytes": 0, "present": True}
empty = dict(counts, public_entries=0, public_bytes=0)
store = lambda user, host: lscache.store_name(user, host)
good = {
    "lscwp_htaccess": "<IfModule LiteSpeed>\nCacheLookup on\n</IfModule>\n", "htaccess_blockers": {A: [], B: ["x"]},
    "stats_before_purge": {store("olscpa", A): counts, store("olscpa", SUB): counts, store("olscpb", B): counts},
    "tenant_reads": {"olscpa": 2, "olscpb": 2}, "store_mode": "nobody nobody 2770", "plugin_purge_link": True,
    "cache_while_suspended": {A: {"enabled": False, "storage": "/x"}}, "hybrid_vhosts": [B], "ols_log_errors": [],
    "files_before": {"olscpa": ["f 644 olscpa olscpa x"]}, "files_after": {"olscpa": ["f 644 olscpa olscpa x"]},
    "databases_before": ["olscpa_x"], "databases_after": ["olscpa_x"], "restored": {"residue": True, "http": True},
    "observations": {
        "front": [entry(cache="miss", body="<html>"), entry(cache="hit", body="<html>")],
        "page_a": [page("olscpa", A, "1", "miss"), page("olscpa", A, "1", "hit")],
        "page_sub": [page("olscpa", SUB, "2", "miss"), page("olscpa", SUB, "2", "hit")],
        "page_b": [page("olscpb", B, "3", "miss"), page("olscpb", B, "3", "hit")],
        "purge_method": entry("403"), "after_purge_method": entry(cache="hit"),
        "logged_in": [entry(body='<div id="wpadminbar">'), entry(body='<div id="wpadminbar">')],
        "anonymous_after_login": entry(cache="hit", body="<html>"),
        "after_plugin_purge": entry(cache="miss"), "before_app_purge": entry(cache="hit"), "after_app_purge": entry(cache="miss"),
        "other_account_after_app_purge": entry(cache="hit"),
        "admin_purge": {"removed": {store("olscpa", A): counts}, "after": {store("olscpa", A): empty}},
        "after_admin_purge": entry(cache="miss"),
        "suspended": [entry("302", location="http://x/cgi-sys/suspendedpage.cgi")] * 3, "unsuspended": entry(),
        "hybrid": [page("olscpb", B, str(n), None) for n in range(4)]}}
cases = lp.expected_outcomes(good)
assert all(cases.values()), [k for k, v in cases.items() if not v]

def broken(change):
    case = json.loads(json.dumps(good))
    change(case)
    return not all(lp.expected_outcomes(case).values())

o = lambda c: c["observations"]
for change in [
        lambda c: o(c)["front"].__setitem__(1, entry(cache="miss")),                          # never served from cache
        lambda c: o(c)["logged_in"].__setitem__(0, entry(cache="hit", body="wpadminbar")),     # logged in from public cache
        lambda c: o(c)["logged_in"].__setitem__(1, entry(body="<html>")),                     # the anonymous page to a user
        lambda c: o(c)["page_sub"].__setitem__(0, page("olscpa", SUB, "1", "hit")),            # cross-vhost hit
        lambda c: o(c)["page_sub"].__setitem__(0, page("olscpa", A, "9", "miss")),             # another vhost's body
        lambda c: o(c)["page_b"].__setitem__(0, page("olscpa", A, "1", "miss")),               # cross-account body
        lambda c: o(c).__setitem__("purge_method", entry("200")),
        lambda c: o(c).__setitem__("after_plugin_purge", entry(cache="hit")),
        lambda c: c.__setitem__("plugin_purge_link", False),
        lambda c: o(c).__setitem__("other_account_after_app_purge", entry(cache="miss")),      # purge crossed vhosts
        lambda c: o(c)["admin_purge"]["after"].__setitem__(store("olscpa", A), counts),
        lambda c: o(c)["suspended"].__setitem__(1, entry("302", cache="hit", location="/cgi-sys/suspendedpage.cgi")),
        lambda c: o(c)["suspended"].__setitem__(0, entry("200")),
        lambda c: c.__setitem__("cache_while_suspended", {A: {"enabled": True}}),
        lambda c: o(c)["hybrid"].__setitem__(1, page("olscpb", B, "0", None)),                 # same nonce: cached copy
        lambda c: o(c)["hybrid"].__setitem__(2, page("olscpb", B, "7", "hit")),
        lambda c: c.__setitem__("hybrid_vhosts", []),
        lambda c: c["tenant_reads"].__setitem__("olscpb", 0),
        lambda c: c.__setitem__("store_mode", "nobody nobody 2777"),
        lambda c: c["stats_before_purge"].pop(store("olscpb", B)),
        lambda c: c.__setitem__("files_after", {"olscpa": []}),
        lambda c: c.__setitem__("databases_after", ["olscpa_x", "olscpa_olscpwp"]),
        lambda c: c.__setitem__("databases_before", None),
        lambda c: c["restored"].__setitem__("residue", False),
        lambda c: c.__setitem__("ols_log_errors", ["[ERROR] x"]),
        lambda c: c.__setitem__("lscwp_htaccess", ""),
        lambda c: c["htaccess_blockers"].__setitem__(A, ["/: unsupported directive"])]:
    assert broken(change)
print("LSCache experiment guards, parsing, recovery script and declared outcomes checks passed.")
