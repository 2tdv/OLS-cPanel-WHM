#!/usr/bin/python3
"""Python/PHP byte equivalence of the deployment texts: the recovery script (lab and product variants), the
hybrid nftables ruleset and mod_remoteip include (hybrid_lab.py is the reference; src/Deployment ports them),
and the product hook list against the lab's event lists (ols_events.RESTRICTING, ols_reconcile_probe.HOOKS)."""
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import hybrid_lab
import ols_events
import ols_reconcile_probe

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
TWEAKS = {"apache_port": "0.0.0.0:80", "apache_ssl_port": "0.0.0.0:443"}

def recovery(backup, originals, tenant_files, created_dirs, hybrid, tenant_user=None, expected=None, product=False,
             backend_ports=(81, 444), firewall=None):
    return {"backup": backup, "originals": originals, "tenant_files": tenant_files, "created_dirs": created_dirs,
            "hybrid": hybrid, "tenant_user": tenant_user, "expected": expected or {}, "product": product,
            "backend_ports": list(backend_ports), "firewall": firewall}

CSF1 = {"type": "csf", "before_sha256": "cd" * 32, "after_sha256": "ab" * 32}
FWD = {"type": "firewalld", "zone": "public", "runtime": True, "permanent": True}

RECOVERY = [
    recovery("/var/lib/r/1", {}, {}, [], False),
    recovery("/var/lib/r/1", TWEAKS, {"/h/.htaccess": True, "/h/p.php": False}, ["/h/.w", "/h/.w/a"], True, "olscpb",
             {"/h/.htaccess": "ab" * 32}),
    recovery("/b x/it's", {"apache_ssl_port": "[2001:db8::1]:443", "apache_port": "10.0.0.1:80"},
             {"/home/u/public_html/a b/.htaccess": True, "/home/u/z": True}, ["/home/u/d"], True, "u-1", {"/home/u/z": "cd" * 32}),
    recovery("/b", {"apache_port": "0.0.0.0:81"}, {}, [], True),
    recovery("/var/lib/ols-cpanel/backups/c20261022120000-abcdef", {}, {}, [], False, product=True),
    recovery("/var/lib/ols-cpanel/backups/c20261022120000-abcdef", TWEAKS, {}, [], True, product=True),
    recovery("/var/lib/ols-cpanel/backups/c1", TWEAKS, {}, [], True, product=True, backend_ports=(8081, 8444)),
    # HTTP/3 firewall undo (FV-04): csf (digests of the original and of the changed csf.conf) and firewalld (zone and the
    # runtime / permanent states the product added; RV-31), native and hybrid.
    recovery("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True, firewall=CSF1),
    recovery("/var/lib/ols-cpanel/backups/c1", TWEAKS, {}, [], True, product=True, firewall={"type": "csf", "before_sha256": "1e" * 32, "after_sha256": "0f" * 32}),
    recovery("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True, firewall=FWD),
    recovery("/var/lib/ols-cpanel/backups/c1", TWEAKS, {}, [], True, product=True, firewall=FWD),
    recovery("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True, firewall={"type": "firewalld", "zone": "dmz", "runtime": True, "permanent": False}),
    recovery("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True, firewall={"type": "firewalld", "zone": "my-zone.1", "runtime": False, "permanent": True}),
    recovery("/var/lib/ols-cpanel/backups/c 1", {}, {}, [], False, product=True, firewall=CSF1),
    # Refusals: a csf recovery without a valid digest, a firewalld one without zone or states, an unknown firewall.
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "csf", "before_sha256": "ab" * 32, "after_sha256": "xyz"}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "csf", "after_sha256": "ab" * 32}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "csf"}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "firewalld"}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "firewalld", "zone": "public"}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "firewalld", "zone": "pub lic; rm", "runtime": True, "permanent": True}),
    recovery("/b", {}, {}, [], False, product=True, firewall={"type": "pf"}),
    # Refusals: injected or unknown tweak values, tenant files without a user, tenant files in the product script.
    recovery("/b", {"apache_port": "0.0.0.0:80'; rm -rf /"}, {}, [], True),
    recovery("/b", {"other": "0.0.0.0:80"}, {}, [], True),
    recovery("/b", TWEAKS, {"/h/x": True}, [], True),
    recovery("/b", TWEAKS, {"/h/x": True}, [], True, "u", product=True),
]
cases = ([{"fn": "recovery_script", "args": a} for a in RECOVERY]
         + [{"fn": "nft_ruleset", "args": {"ports": p}} for p in ([81, 444], [8081, 8444])]
         + [{"fn": "remoteip_conf", "args": {"proxies": p}} for p in (["127.0.0.1", "::1"],
                                                                       ["127.0.0.1", "::1", "10.0.0.5", "fd00:6c73:6371::"])]
         + [{"fn": "hooks", "args": {}}])
result = subprocess.run([PHP, "-n", str(ROOT / "tests/deployment_texts.php")], input=json.dumps(cases),
                        capture_output=True, text=True, check=True)
php = json.loads(result.stdout)
assert len(php) == len(cases)
compared = 0
for case, got in zip(cases, php):
    a = case["args"]
    if case["fn"] == "hooks":
        continue
    try:
        if case["fn"] == "recovery_script":
            want = hybrid_lab.recovery_script(a["backup"], a["originals"], a["tenant_files"], a["created_dirs"], a["hybrid"],
                                              a["tenant_user"], a["expected"], product=a["product"],
                                              backend_ports=tuple(a["backend_ports"]), firewall=a["firewall"])
            assert subprocess.run(["/bin/sh", "-n"], input=want, text=True).returncode == 0
        elif case["fn"] == "nft_ruleset":
            want = hybrid_lab.nft_ruleset(tuple(a["ports"]))
        else:
            want = hybrid_lab.remoteip_conf(a["proxies"])
    except ValueError:
        assert "error" in got, f"PHP accepted what the reference refuses: {case}"
        compared += 1
        continue
    assert got.get("text") == want, f"text differs for {case}:\n--- python\n{want}\n--- php\n{got}"
    compared += 1

# The product script: lock, profile removed and verified, every product unit stopped and disabled, the firewall
# removed only once Apache is healthy again, no tenant file handling, no dependency on the product.
product = hybrid_lab.recovery_script("/var/lib/ols-cpanel/backups/c1", TWEAKS, {}, [], True, product=True)
assert "flock -w 900" in product and "rm -f /var/lib/ols-cpanel/profile.json" in product
assert "test ! -e /var/lib/ols-cpanel/profile.json || return 1" in product
assert f"systemctl stop {' '.join(hybrid_lab.PRODUCT_UNITS)}" in product
assert 'systemctl disable "$u"' in product and "runuser" not in product and "ols-cpanel hook" not in product
assert product.index("if healthy; then") < product.index("nft delete table")
assert "/usr/local/ols-cpanel" not in product
# The firewall lines (FV-04) sit in restore() (retried with it), never in healthy(): a firewall that cannot be
# restored must not keep Apache from coming back; the script without a firewall change has none of them.
csf = hybrid_lab.recovery_script("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True,
                                 firewall={"type": "csf", "before_sha256": "cd" * 32, "after_sha256": "ab" * 32})
assert csf.index("csf.conf") < csf.index("healthy() {") and "csf" not in product and "firewall-cmd" not in product
assert 'cat "$B/firewall/csf.conf" > /etc/csf/csf.conf' in csf and "= " + "ab" * 32 + " ]" in csf
# RV-31 item 6: the csf restart is retried while the original file is in place, and healthy() waits for it.
assert "CSF_APPLIED=1" in csf and csf.index("CSF_APPLIED=1") < csf.index("healthy() {") and '"${CSF_APPLIED:-}" = 1' in csf[csf.index("healthy() {"):]
# RV-31 items 3-5: firewalld removes exactly the recorded states in the recorded zone and never reloads.
fwd = hybrid_lab.recovery_script("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True,
                                 firewall={"type": "firewalld", "zone": "dmz", "runtime": True, "permanent": False})
assert "firewall-cmd --zone=dmz --remove-port=443/udp" in fwd and "--permanent" not in fwd and "--reload" not in fwd
fwd = hybrid_lab.recovery_script("/var/lib/ols-cpanel/backups/c1", {}, {}, [], False, product=True,
                                 firewall={"type": "firewalld", "zone": "dmz", "runtime": False, "permanent": True})
assert "firewall-cmd --permanent --zone=dmz --remove-port=443/udp" in fwd and "--reload" not in fwd
assert fwd.count("firewall-cmd") == 1


def csf_scenario(initial, csf_exit, repeats=1):
    """Runs the csf restore lines and health lines of the script in a real shell against a temp csf.conf and a fake csf;
    returns (conf text, csf runs, healthy exit)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        original, changed = "UDP_IN = \"20\"\n", "UDP_IN = \"20,443\"\n"
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        (tmp / "firewall").mkdir()
        (tmp / "firewall/csf.conf").write_text(original)
        conf = tmp / "csf.conf"
        conf.write_text({"changed": changed, "original": original, "edited": "# edited\n"}[initial])
        fake = tmp / "csf"
        fake.write_text(f"#!/bin/sh\necho run >> {tmp}/runs\nexit {csf_exit}\n")
        fake.chmod(0o755)
        arg = {"type": "csf", "before_sha256": digest(original), "after_sha256": digest(changed)}
        restore = "\n".join(hybrid_lab.firewall_restore_lines(arg))
        health = "\n".join(hybrid_lab.firewall_health_lines(arg))
        restore = restore.replace(hybrid_lab.http3.CSF_CONF, str(conf)).replace(hybrid_lab.http3.CSF, "/bin/sh " + str(fake))
        health = health.replace(hybrid_lab.http3.CSF_CONF, str(conf))
        script = f"B={tmp}\nT=''\nrestore() {{\n{restore}\n}}\nhealthy() {{\n{health}\n    return 0\n}}\n" \
                 + "restore; healthy; echo $?\n" * repeats
        out = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=30)
        runs = (tmp / "runs").read_text().count("run") if (tmp / "runs").exists() else 0
        return conf.read_text(), runs, out.stdout.split()


original_text, changed_text = "UDP_IN = \"20\"\n", "UDP_IN = \"20,443\"\n"
# The file is restored but csf fails: not healthy (recovery does not report success), the file stays restored.
assert csf_scenario("changed", 1) == (original_text, 1, ["1"])
# The next attempt finds the original file in place and retries csf, which now succeeds: healthy, one more run.
assert csf_scenario("original", 0) == (original_text, 1, ["0"])
# Restored and restarted in one attempt; a second pass in the same run does not restart csf again.
assert csf_scenario("changed", 0, repeats=2) == (original_text, 1, ["0", "0"])
# An administrator's edit is neither touched nor fought: csf is not run and the script is healthy.
assert csf_scenario("edited", 1) == ("# edited\n", 0, ["0"])

# Lock order (review RV-29): the product script takes the deployment lock exclusively unless its caller holds it
# (OLS_CPANEL_DEPLOYMENT_LOCK=held); the lab script keeps its own lock. The script's own lock prologue runs here
# against a real lock file, with a concurrent holder (a reconcile pass sharing the lock) and without.
lab = hybrid_lab.recovery_script("/var/lib/r/1", TWEAKS, {}, [], True)
assert f"exec 9>{hybrid_lab.LOCK}" in lab and hybrid_lab.DEPLOYMENT_LOCK not in lab
assert f"exec 9>{hybrid_lab.DEPLOYMENT_LOCK}" in product and "flock -w 900 9" in product and hybrid_lab.LOCK not in product
assert product.index("flock -w 900 9") < product.index("restore() {")
lines = product.split("\n")
prologue = "\n".join(lines[:lines.index("fi") + 1])
with tempfile.TemporaryDirectory() as tmp:
    lock_path = os.path.join(tmp, "deployment.lock")
    script = (prologue.replace(hybrid_lab.DEPLOYMENT_LOCK, lock_path).replace("flock -w 900 9", "flock -w 1 9")
              + "\necho locked\n")
    def run(held=False):
        env = {"PATH": "/usr/bin:/bin"} | ({hybrid_lab.DEPLOYMENT_LOCK_HELD: "held"} if held else {})
        return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    free = run()
    assert free.returncode == 0 and free.stdout == "locked\n", free
    with open(lock_path, "a") as holder:
        fcntl.flock(holder, fcntl.LOCK_SH)
        busy = run()
        assert busy.returncode == 1 and busy.stdout == "" and "holds the deployment lock" in busy.stderr, busy
        fcntl.flock(holder, fcntl.LOCK_UN)
        fcntl.flock(holder, fcntl.LOCK_EX)
        assert run().returncode == 1
        under = run(held=True)
        assert under.returncode == 0 and under.stdout == "locked\n", under

hooks = json.loads(php[-1]["text"])
assert set(hooks["restricting"]) == ols_events.RESTRICTING
assert hooks["objcache_events"] == ols_events.OBJCACHE_EVENTS
assert hooks["trust_events"] == ols_events.TRUST_EVENTS
events = {(h["category"], h["event"]): h for h in hooks["events"]}
assert set(events) == set(ols_events.EVENTS)
assert len(events) == len(hooks["events"]), "duplicate hook registration"
assert {e for _, e in events} >= ols_events.RESTRICTING
for category, event, escalate in ols_reconcile_probe.HOOKS:
    assert (category, event) in events and events[(category, event)]["escalateprivs"] == ("1" if escalate else "0"), event
assert all(h["stage"] == "post" for h in events.values())
print(f"Deployment texts: {compared} Python/PHP cases identical; recovery lock prologue serialized with the deployment lock; "
      "hook list covers the lab's restricting and reconcile events.")
