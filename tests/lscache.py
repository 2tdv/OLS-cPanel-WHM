#!/usr/bin/python3
"""LSCache storage primitives (FV-01) on temporary trees: statistics and purge by vhost, account and server,
links never followed and nothing outside the hash directories touched; the PHP port (CacheStorage) gives the
same results and leaves the same tree (tests/lscache_storage.php)."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import lscache

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
UID = os.getuid()

def write(path, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)

def build(base):
    """A cache root as OLS lays it out, with a victim directory outside it and planted links."""
    victim = base / "victim"
    write(victim / "keep.txt", 7)
    root = base / "cache"
    root.mkdir(mode=0o711)
    os.chmod(root, 0o711)
    a = root / "olscpa@a.test"
    write(a / "0/1/2/0123456789abcdef", 100)
    write(a / "0/1/2/0123456789abcdef.tmp", 9)            # being written: not counted, removed by a purge
    write(a / "3/4/5/fedcba9876543210.S", 50)               # stale copy: counted
    write(a / "priv/a/b/c/aaaaaaaaaaaaaaaa", 30)
    write(a / ".cacheman.shm", 40960)                       # shared-memory index: never touched
    write(a / ".cacheman.lock", 0)
    write(a / "x/notes", 3)                                 # not a hash directory: never touched
    (a / "0/1/2/1111111111111111").symlink_to(victim / "keep.txt")
    (a / "7").symlink_to(victim)
    write(root / "olscpa@b.test/9/9/9/9999999999999999", 10)
    write(root / "olscpb@a.test/1/1/1/1111111111111111", 20)
    write(root / "server/2/2/2/2222222222222222", 5)
    write(root / "not-a-store/1/1/1/1111111111111111", 5)   # never selected
    return root, victim

def tree(base):
    out = {}
    for path in sorted(base.rglob("*")):
        rel = str(path.relative_to(base))
        out[rel] = "link" if path.is_symlink() else "dir" if path.is_dir() else path.stat().st_size
    return out

OPS = [["stats", None, None], ["stats", "olscpa", None], ["stats", "olscpa", "a.test"], ["stats", "olscpa", "c.test"],
       ["stats", "Bad", None], ["stats", None, "a.test"], ["stats", "olscpa", "../a.test"], ["purge", "olscpa", "a.test"],
       ["stats", None, None], ["purge", "olscpb", None], ["purge", None, None], ["stats", None, None]]

def python_run(root, ops, owner=UID):
    out = []
    for action, account, vhost in ops:
        try:
            out.append((lscache.purge if action == "purge" else lscache.stats)(str(root), account, vhost, owner=owner))
        except ValueError:
            out.append("error")
    return out

def php_run(root, ops, owner=UID):
    with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
        json.dump({"root": str(root), "owner": owner, "ops": ops}, handle)
        handle.flush()
        result = subprocess.run([PHP, "-n", str(ROOT / "tests/lscache_storage.php"), handle.name],
                                capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

with tempfile.TemporaryDirectory() as temp:
    left, right = pathlib.Path(temp, "py"), pathlib.Path(temp, "php")
    root_l, victim_l = build(left)
    root_r, _ = build(right)
    py, php = python_run(root_l, OPS), php_run(root_r, OPS)
    assert py == php, (py, php)
    assert tree(left) == tree(right), "the PHP port leaves the same tree"
    stats_all = py[0]
    assert sorted(stats_all) == ["olscpa@a.test", "olscpa@b.test", "olscpb@a.test", "server"], stats_all
    assert stats_all["olscpa@a.test"] == {"public_entries": 2, "public_bytes": 150, "private_entries": 1, "private_bytes": 30,
                                          "present": True}, stats_all
    assert sorted(py[1]) == ["olscpa@a.test", "olscpa@b.test"] and list(py[2]) == ["olscpa@a.test"]
    assert py[3] == {"olscpa@c.test": {"public_entries": 0, "public_bytes": 0, "private_entries": 0, "private_bytes": 0,
                                       "present": False}}
    assert py[4:7] == ["error"] * 3, py[4:7]
    assert py[7] == {"olscpa@a.test": dict(stats_all["olscpa@a.test"], failed=0)}, "a purge reports what it removed"
    after = py[8]
    assert after["olscpa@a.test"]["public_entries"] == 0 and after["olscpa@a.test"]["private_entries"] == 0
    assert after["olscpa@b.test"] == stats_all["olscpa@b.test"] and after["server"] == stats_all["server"], "other stores untouched"
    assert list(py[9]) == ["olscpb@a.test"] and all(v["public_entries"] == 0 for v in py[11].values())
    final = tree(left)
    a = "cache/olscpa@a.test/"
    assert final["victim/keep.txt"] == 7 and final["victim"] == "dir", "links are never followed"
    assert {a + ".cacheman.shm", a + ".cacheman.lock", a + "x/notes"} <= set(final), "index and unknown names stay"
    assert not any(k.startswith(tuple(a + d for d in ("0", "3", "7", "priv"))) for k in final), final
    assert "cache/not-a-store/1/1/1/1111111111111111" in final, "only stores are selected"
    # The root must be owned by the expected user and not group/other writable; a linked store is refused.
    os.chmod(root_l, 0o777)
    os.chmod(root_r, 0o777)
    assert python_run(root_l, OPS[:1]) == php_run(root_r, OPS[:1]) == ["error"]
    os.chmod(root_l, 0o711)
    os.chmod(root_r, 0o711)
    assert python_run(root_l, OPS[:1], UID + 1) == php_run(root_r, OPS[:1], UID + 1) == ["error"]
    for root, victim in ((root_l, victim_l), (root_r, right / "victim")):
        (root / "olscpc@x.test").symlink_to(victim)
    ops = [["purge", "olscpc", "x.test"], ["stats", "olscpc", None]]
    assert python_run(root_l, ops) == php_run(root_r, ops) == ["error", "error"]
    assert (victim_l / "keep.txt").exists()
    # ensure_root creates the root 0711 and refuses a writable one.
    fresh = pathlib.Path(temp, "fresh")
    lscache.ensure_root(str(fresh), UID)
    assert fresh.stat().st_mode & 0o777 == 0o711
    os.chmod(fresh, 0o733)
    try:
        lscache.ensure_root(str(fresh), UID)
        raise AssertionError("writable root accepted")
    except ValueError:
        pass

# RV-31 item 12: a purge counts only what it removed. A directory that cannot be written keeps its entries (EACCES), they are not
# counted as removed, "failed" says so, and PHP and Python agree; an entry that vanished meanwhile (ENOENT) is neither.
if os.geteuid() != 0:
    with tempfile.TemporaryDirectory() as temp:
        left, right = pathlib.Path(temp, "py"), pathlib.Path(temp, "php")
        for base in (left, right):
            root, _ = build(base)
            os.chmod(root / "olscpa@b.test/9/9/9", 0o500)
        ops = [["purge", "olscpa", "b.test"], ["purge", "olscpb", None]]
        py, php = python_run(left / "cache", ops), php_run(right / "cache", ops)
        assert py == php, (py, php)
        assert py[0]["olscpa@b.test"] == {"public_entries": 0, "public_bytes": 0, "private_entries": 0, "private_bytes": 0,
                                          "present": True, "failed": 1}, py[0]
        assert (left / "cache/olscpa@b.test/9/9/9/9999999999999999").exists() and (right / "cache/olscpa@b.test/9/9/9/9999999999999999").exists()
        assert py[1]["olscpb@a.test"]["failed"] == 0 and py[1]["olscpb@a.test"]["public_entries"] == 1
        for base in (left, right):
            os.chmod(base / "cache/olscpa@b.test/9/9/9", 0o700)
        again = python_run(left / "cache", ops[:1])[0]["olscpa@b.test"]
        assert again["failed"] == 0 and again["public_entries"] == 1 and not (left / "cache/olscpa@b.test/9").exists()
    with tempfile.TemporaryDirectory() as temp:
        root, _ = build(pathlib.Path(temp))
        real_unlink = os.unlink
        def racing_unlink(path, *args, **kwargs):
            if path == "0123456789abcdef":
                real_unlink(path, *args, **kwargs)  # somebody else removed it first
            return real_unlink(path, *args, **kwargs)
        lscache.os.unlink = racing_unlink
        try:
            raced = lscache.purge(str(root), "olscpa", "a.test", owner=UID)["olscpa@a.test"]
        finally:
            lscache.os.unlink = real_unlink
        # The raced entry (100 bytes) is not ours to count and not a failure; the others are counted.
        assert raced["failed"] == 0 and raced["public_entries"] == 1 and raced["public_bytes"] == 50, raced
# The cleanup primitive (automatic LSCache cleanup): Python trim_store and PHP CacheStorage::trimStore give the same results and leave
# the same tree on stores with expired, stale, temporary, young, private, linked and control files.
NOW = 1_800_000_000
EXPIRY = lscache.max_entry_age()

def age(path, seconds):
    os.utime(path, (NOW - seconds, NOW - seconds), follow_symlinks=False)

def build_clean(base):
    root, victim = build(base)
    # Every file gets an age: the entries of olscpa@a.test span expired, in-lifetime and young; b and the others are 1 hour old.
    a = root / "olscpa@a.test"
    ages = {"0/1/2/0123456789abcdef": EXPIRY + 5, "0/1/2/0123456789abcdef.tmp": EXPIRY + 5, "3/4/5/fedcba9876543210.S": 4000,
            "priv/a/b/c/aaaaaaaaaaaaaaaa": EXPIRY + 5, ".cacheman.shm": EXPIRY + 99, ".cacheman.lock": EXPIRY + 99, "x/notes": EXPIRY + 99}
    for rel, seconds in ages.items():
        age(a / rel, seconds)
    write(a / "5/5/5/5555555555555555", 200)
    age(a / "5/5/5/5555555555555555", 10)                   # young: never removed
    write(a / "6/6/6/6666666666666666", 300)
    age(a / "6/6/6/6666666666666666", 2000)
    age(a / "0/1/2/1111111111111111", EXPIRY + 5)           # a link: never followed, never removed
    age(root / "olscpa@b.test/9/9/9/9999999999999999", 3000)
    age(root / "olscpb@a.test/1/1/1/1111111111111111", 100)
    age(root / "server/2/2/2/2222222222222222", 90000)
    return root, victim

def python_trim(root, ops, owner=UID):
    out = []
    for _, store, (cutoff, cap, now) in ops:
        try:
            out.append(lscache.trim_store(str(root), store, cutoff, cap, now, owner))
        except ValueError:
            out.append("error")
    return out

TRIMS = [["trim", "olscpa@a.test", [NOW - EXPIRY, 10**12, NOW]],        # expiry only
         ["trim", "olscpa@a.test", [NOW - EXPIRY, 100, NOW]],            # then the cap: oldest first, the young entry stays
         ["trim", "olscpa@b.test", [NOW + 10**6, 0, NOW]],               # everything that is not young
         ["trim", "olscpb@a.test", [0, 10**12, NOW]],                    # nothing
         ["trim", "olscpa@missing.test", [0, 0, NOW]],
         ["trim", "../victim", [0, 0, NOW]], ["trim", "olscpa", [0, 0, NOW]], ["trim", "server", [NOW - 5000, 0, NOW]]]

with tempfile.TemporaryDirectory() as temp:
    left, right = pathlib.Path(temp, "py"), pathlib.Path(temp, "php")
    root_l, victim_l = build_clean(left)
    root_r, _ = build_clean(right)
    py, php = python_trim(root_l, TRIMS), php_run(root_r, TRIMS)
    assert py == php, (py, php)
    assert tree(left) == tree(right), "the PHP port leaves the same tree"
    assert py[0]["files"] == 3 and py[0]["bytes"] == 100 + 9 + 30, py[0]
    assert py[0]["remaining_files"] == 3 and py[0]["failed"] == 0 and py[4] == dict(files=0, bytes=0, failed=0, remaining_files=0, remaining_bytes=0, present=False)
    assert py[5] == py[6] == "error"
    final = tree(left)
    a = "cache/olscpa@a.test/"
    assert final["victim/keep.txt"] == 7 and (a + "0/1/2/1111111111111111") in final, "links are not followed or removed"
    assert {a + ".cacheman.shm", a + ".cacheman.lock", a + "x/notes", a + "5/5/5/5555555555555555"} <= set(final), "control files and young entries stay"
    assert (a + "priv") not in final and (a + "0/1/2/0123456789abcdef") not in final, "expired entries and emptied directories go"
    assert "cache/olscpa@b.test/9" not in final and "cache/server/2" not in final
    # PHP's policy gives the same expiry age as the Python reference.
    code = subprocess.run([PHP, "-n", "-r", "require '" + str(ROOT / "src/bootstrap.php") + "'; echo OlsCpanel\\Ols\\Compiler\\CachePolicy::maxEntryAge();"],
                          capture_output=True, text=True, check=True).stdout
    assert int(code) == EXPIRY, (code, EXPIRY)
# The command line used by the lab experiment.
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/lscache.py"), "drop", "/x"], capture_output=True, text=True)
assert result.returncode == 64
print("LSCache storage primitives: Python and PHP equal on stats, purge and the cleanup trim; links never followed.")
