#!/usr/bin/python3
"""Offline checks of the FV-09 lab experiment (build/vm-qualification/objcache_probe.py): guards, PHP snippet
quoting, INFO parsing, the recovery script and every declared outcome against good and broken observations."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import objcache_probe as op

PROBE = str(ROOT / "build/vm-qualification/objcache_probe.py")
result = subprocess.run([sys.executable, PROBE, "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
# The pins are shared with the LSCache experiment and recorded there (an unrecorded one refuses the run first).
assert op.pins_ready() == []
result = subprocess.run([sys.executable, PROBE, "--lab-tenants"], capture_output=True, text=True)
assert result.returncode == 2 and "--rpm" in result.stderr
assert op.PINS is op.lsp.PINS and op.pins_ready({"x": {"sha256": "a" * 64}}) == []

# PHP snippets: values become string literals, never code.
code = op.php_code(op.PHP_ROUNDTRIP, sock='/home/a/x"); system("id"); //', val="v")
assert '"/home/a/x\\"); system(\\"id\\"); //"' in code and "%(" not in code
assert op.php_code(op.PHP_FILL, sock="/s", count=64).count("$n = 64;") == 1
assert op.SOCKET("olscpa") == "/home/olscpa/.ols-objcache/valkey.sock" and op.UNIT("olscpa") == "ols-cpanel-objcache@olscpa.service"
fields = op.parse_info("# Memory\r\nused_memory:100\r\nmaxmemory:200\r\nevicted_keys:3\r\n# Keyspace\r\ndb0:keys=5,expires=0,avg_ttl=0\r\ndb1:keys=2,expires=0\r\n")
assert op.number(fields, "used_memory") == 100 and op.number(fields, "keys") == 7 and op.number(fields, "missing") is None
assert op.show("A=1\nB=x=y\nnoise\n") == {"A": "1", "B": "x=y"}

script = op.recovery_script("/var/lib/ols-cpanel-lab-recovery/1", ["valkey", "ea-php83-php-redis"])
assert subprocess.run(["/bin/sh", "-n"], input=script, text=True).returncode == 0
assert "vm-qualification" not in script and "flock -w 900" in script and "exit 1" in script
for needle in ("systemctl disable --now ols-cpanel-objcache.timer", "systemctl stop ols-cpanel-objcache@olscpa.service",
               "systemctl stop ols-cpanel-objcache@olscpobj.service", "unsuspendacct user=olscpa", "removeacct username=olscpobj",
               "rpm -e $p", "dnf -y -q remove valkey ea-php83-php-redis", "rm -rf /etc/systemd/system/ols-cpanel-objcache@*.service.d",
               "/var/lib/ols-cpanel\n", "runuser -u olscpa -- rm -rf -- /home/olscpa/.ols-objcache", "runuser -u olscpb -- rm -rf -- /home/olscpb/.ols-objcache",
               "Mysql delete_database name=olscpa_olscpoc", "Mysql delete_user name=olscpa_olscpoc"):
    assert needle in script, needle
# Packages the experiment did not install are never removed; home paths are only ever deleted as their owner.
assert "dnf" not in op.recovery_script("/b", [])
assert "\n    rm -rf -- /home" not in script and "rm -rf /home" not in script

mode = lambda user, text: f"{user} {user} {text}"
info_after = {"used_memory": "16000000", "maxmemory": str(op.FILL_MB * 1024 * 1024), "evicted_keys": "40", "keys": "30"}
good = {
    "engine_version": "Valkey server v=8.0.10 sha=00000000:0", "tcp_listeners": [], "oom_log": [], "journal_errors": [],
    "socket_dir_b_listing": ["valkey.sock"], "files_before": {"olscpa": ["f"]}, "files_after": {"olscpa": ["f"]},
    "databases_before": ["x"], "databases_after": ["x"], "restored": {"residue": True, "packages_absent": True},
    "observations": {
        "enable_a": {"result": "enabled", "memory_mb": 64, "socket": op.SOCKET("olscpa")},
        "enable_b": {"result": "enabled", "memory_mb": op.FILL_MB}, "timer_enabled": True,
        "modes": {"conf_a": "root root 644", "dir_a": mode("olscpa", "700"), "sock_a": mode("olscpa", "600"), "conf_b": "root root 644",
                  "dir_b": mode("olscpb", "700"), "sock_b": mode("olscpb", "600"), "confdir_a": "root root 755"},
        "process_users": {"olscpa": "olscpa", "olscpb": "olscpb"},
        "unit_a": {"User": "olscpa", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "PrivateTmp": "yes",
                   "MemoryMax": str(112 * 1024 * 1024), "RestrictAddressFamilies": "AF_UNIX"},
        "cli_a": {"get": "v-a", "ping": True}, "cli_b": {"get": "v-b", "ping": True},
        "web_a": {"connected": True, "get": "web-ok", "owner": "olscpa"},
        "a_to_b": {"connected": False, "value": None}, "b_to_a": {"connected": False, "value": None},
        "disabled_cmds": {"CONFIG": "error:unknown command", "DEBUG": "error:x", "MODULE": "error:x", "REPLICAOF": "error:x"},
        "fill": {"written": 256, "before": {}, "after": info_after},
        "unit_b": {"NRestarts": "0", "ActiveState": "active", "Result": "success", "MemoryCurrent": "30000000", "MemoryMax": str(52 * 1024 * 1024)},
        "wp": {"configure": {"result": "configured", "host": op.SOCKET("olscpa"), "port": 0}, "object_kind": "1",
               "object_host": op.SOCKET("olscpa"), "ext": True, "persisted_value": "v1", "hits_before": 1, "hits_after": 9},
        "flush": {"result": "flushed", "keys_a_after": 0, "keys_b_after": 12},
        "suspended": {"a_state": "inactive", "b_state": "active", "conf_kept": True, "socket_a_listening": False},
        "unsuspended": {"a_state": "active", "b_state": "active", "socket_a_listening": True},
        "account_removal": {"enabled": "enabled", "state_before": "active", "state_after": "inactive", "conf_dir_exists": False,
                            "dropin_exists": False, "in_state": False},
        "disable_b": {"result": "disabled", "state": "inactive", "conf_dir_exists": False, "dropin_exists": False,
                      "socket_dir_exists": False, "in_state": False, "a_still_active": True}}}
cases = op.expected_outcomes(good)
assert all(cases.values()), [k for k, v in cases.items() if not v]


def broken(change):
    case = json.loads(json.dumps(good))
    change(case)
    return not all(op.expected_outcomes(case).values())


o = lambda c: c["observations"]
for change in [
        lambda c: c.__setitem__("engine_version", "Redis server v=6.2"),
        lambda c: o(c)["modes"].__setitem__("dir_a", mode("olscpa", "755")),               # directory open to others
        lambda c: o(c)["modes"].__setitem__("sock_b", mode("olscpb", "666")),
        lambda c: o(c)["modes"].__setitem__("conf_a", mode("olscpa", "644")),              # configuration owned by the account
        lambda c: o(c)["process_users"].__setitem__("olscpa", "root"),
        lambda c: o(c)["unit_a"].__setitem__("RestrictAddressFamilies", "AF_UNIX AF_INET"),
        lambda c: o(c)["unit_a"].__setitem__("NoNewPrivileges", "no"),
        lambda c: c.__setitem__("tcp_listeners", ["LISTEN 127.0.0.1:6379 valkey"]),
        lambda c: o(c)["cli_a"].__setitem__("get", None),
        lambda c: o(c)["web_a"].__setitem__("owner", "nobody"),
        lambda c: o(c)["a_to_b"].__setitem__("connected", True),
        lambda c: o(c)["b_to_a"].__setitem__("value", "v-a"),
        lambda c: o(c)["disabled_cmds"].__setitem__("CONFIG", "ok:64"),
        lambda c: o(c)["fill"]["after"].__setitem__("evicted_keys", "0"),
        lambda c: o(c)["fill"]["after"].__setitem__("used_memory", str(40 * 1024 * 1024)),   # limit not enforced
        lambda c: o(c)["fill"].__setitem__("written", 2),                                    # not filled beyond the limit
        lambda c: o(c)["unit_b"].__setitem__("NRestarts", "1"),
        lambda c: o(c)["unit_b"].__setitem__("MemoryCurrent", str(60 * 1024 * 1024)),
        lambda c: c.__setitem__("oom_log", ["Killed process 1 (valkey-server)"]),
        lambda c: c.__setitem__("socket_dir_b_listing", ["valkey.sock", "dump.rdb"]),
        lambda c: o(c)["flush"].__setitem__("keys_b_after", 0),
        lambda c: o(c)["flush"].__setitem__("keys_a_after", 3),
        lambda c: o(c)["suspended"].__setitem__("a_state", "active"),
        lambda c: o(c)["suspended"].__setitem__("b_state", "inactive"),
        lambda c: o(c)["suspended"].__setitem__("conf_kept", False),
        lambda c: o(c)["unsuspended"].__setitem__("a_state", "inactive"),
        lambda c: o(c)["account_removal"].__setitem__("state_after", "active"),
        lambda c: o(c)["account_removal"].__setitem__("dropin_exists", True),
        lambda c: o(c)["account_removal"].__setitem__("in_state", True),
        lambda c: o(c)["disable_b"].__setitem__("socket_dir_exists", True),
        lambda c: o(c)["disable_b"].__setitem__("a_still_active", False),
        lambda c: o(c)["wp"].__setitem__("object_host", "127.0.0.1"),
        lambda c: o(c)["wp"]["configure"].__setitem__("port", 6379),
        lambda c: o(c)["wp"].__setitem__("persisted_value", ""),
        lambda c: o(c)["wp"].__setitem__("hits_after", 1),
        lambda c: o(c)["wp"].__setitem__("ext", False),
        lambda c: c.__setitem__("journal_errors", ["valkey: error"]),
        lambda c: c.__setitem__("files_after", {"olscpa": []}),
        lambda c: c.__setitem__("databases_after", ["x", "olscpa_olscpoc"]),
        lambda c: c["restored"].__setitem__("packages_absent", False)]:
    assert broken(change)
print("Object cache experiment guards, quoting, recovery script and declared outcomes checks passed.")
