#!/usr/bin/python3
"""The Rust activator (artifacts/broker/ols-cpanel-activator, built by build/broker/build.sh) must be
interchangeable with the lab tool build/vm-qualification/ols_generation.py on the same state directory:
same JSON on stdout, same exit codes, same on-disk records. Also: the Rust structural lint must report
exactly what ols_config_lint.py reports on the LINT/ADDRESS corpus of tests/compiler_equivalence.py
(the PHP port is held to the same corpus there).

Offline and unprivileged: nothing is built here; both implementations run against temporary state
directories with every service, process and HTTP check disabled (Python: patched functions; Rust:
--lab-root, which the binary refuses for root). Only flows that never reach a reload, a stop or the
marker are compared: status, restrict, stage, validate (as non-root the validator refuses at once),
refused activations, journal recovery without service actions, and error handling.
Skips with a clear message when the binary is absent. OLS_CPANEL_ACTIVATOR overrides its path."""
import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
BINARY = pathlib.Path(os.environ.get("OLS_CPANEL_ACTIVATOR") or ROOT / "artifacts/broker/ols-cpanel-activator")
sys.path.insert(0, str(TOOLS))
import ols_config_lint as lint

if not (BINARY.is_file() and os.access(BINARY, os.X_OK)):
    print(f"Activator parity checks SKIPPED: no compiled binary at {BINARY} (build it with build/broker/build.sh).")
    sys.exit(0)
if os.geteuid() == 0:
    print("Activator parity checks SKIPPED: run unprivileged (--lab-root is refused for root).")
    sys.exit(0)

RUNNER = r'''
import sys
sys.path.insert(0, sys.argv[1])
import ols_generation as a
state = sys.argv[2]
a.STATE = state
a.GEN_ROOT, a.JOURNAL, a.VALIDATIONS = state + "/generations", state + "/journal", state + "/validations"
a.EPOCH, a.EPOCH_HIGH = state + "/epoch.json", state + "/epoch.high"
a.ACTIVE, a.LOCK, a.BINARY = state + "/active", state + "/activation.lock", state + "/openlitespeed"
a.RESTRICTIONS = state + "/restrictions"
a.running = a.ols_running = lambda: False
a.served = lambda timeout=1.0: None
def refuse(*args, **kwargs):
    raise SystemExit("parity test: a service action was requested")
if sys.argv[3:4] == ["health"]:
    # health only reads: every request fails as with no server listening (Rust --lab-root: no HTTP at all).
    import urllib.error, urllib.request
    def unreachable(*args, **kwargs):
        raise urllib.error.URLError("parity test: no network")
    urllib.request.urlopen = unreachable
    def refused(self):
        raise ConnectionRefusedError(111, "parity test: no network")
    a._SniConnection.connect = refused  # HTTPS targets: refused like a closed port (Rust: no network at all)
    a.reload = a.stop_serving = a.wait_for = refuse
else:
    a.reload = a.stop_serving = a.wait_for = a.vhost_health = refuse
sys.argv = ["ols_generation.py"] + sys.argv[3:]
a.main()
'''


def python(state, *args):
    return subprocess.run([sys.executable, "-I", "-c", RUNNER, str(TOOLS), str(state), *args],
                          capture_output=True, text=True, timeout=60)


def rust(state, *args):
    return subprocess.run([str(BINARY), "--lab-root", str(state), *args], capture_output=True, text=True, timeout=60)


def same(label, py, rs, stderr=False):
    assert py.returncode == rs.returncode, (label, py.returncode, rs.returncode, py.stderr[-500:], rs.stderr[-500:])
    assert py.stdout == rs.stdout, (label, py.stdout, rs.stdout)
    if stderr:
        assert py.stderr == rs.stderr, (label, py.stderr, rs.stderr)
    return py


def both(states, *args, stderr=False):
    return same(" ".join(args), python(states[0], *args), rust(states[1], *args), stderr)


def fresh(temp, name):
    states = []
    for impl in ("py", "rs"):
        state = pathlib.Path(temp, name, impl)
        state.mkdir(parents=True)
        (state / "openlitespeed").write_bytes(b"binary-1")
        states.append(state)
    return states


def without(record, *keys):
    return {k: v for k, v in record.items() if k not in keys}


def tree(path):
    """Relative path -> (mode, contents or link target) for every entry below path."""
    found = {}
    for item in sorted(path.rglob("*")):
        rel = str(item.relative_to(path))
        if item.is_symlink():
            found[rel] = ("link", os.readlink(item))
        elif item.is_dir():
            found[rel] = (oct(item.stat().st_mode & 0o7777), None)
        else:
            found[rel] = (oct(item.stat().st_mode & 0o7777), item.read_bytes())
    return found


# 1. Lint parity on the corpus of tests/compiler_equivalence.py (evaluated from its source, not copied).
namespace = {"ROOT": ROOT}
for node in ast.parse((ROOT / "tests/compiler_equivalence.py").read_text()).body:
    if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in ("TEMPLATE", "LINT", "ADDRESS") for t in node.targets):
        exec(compile(ast.Module([node], []), "compiler_equivalence.py", "exec"), namespace)
LINT, ADDRESS = namespace["LINT"], namespace["ADDRESS"]
assert len(LINT) >= 6 and len(ADDRESS) >= 16
EXTRA = [  # whitespace, line breaks, quoting and control characters as Python sees them
    {"text": "disableWebAdmin\t1\nautoDetectCdn 0 \nenableUpdateCheck  0\nCGIRLimit{\n}\n", "policy": True},
    {"text": "\ufeffdisableWebAdmin 1\r\nautoDetectCdn 0\r\nenableUpdateCheck 0\rCGIRLimit {\r\n}\r\n", "policy": True},
    {"text": "autoDetectCdn it's\nautoDetectCdn \"x\"\nautoDetectCdn a'\"b\ndisableWebAdmin 1\x01\nenableUpdateCheck \u00ad\u00e9\U0001f600\n", "policy": True},
    {"text": "disableWebAdmin\u00a01\nlistener x {\n address\u20031.2.3.4:80\n}\nlistener  spaced   name {\n address [::1]:443\n secure 1\n keyFile /k\n}\n", "policy": True},
    {"text": "  # comment {\n}\na {\n b {\n", "policy": True},
    {"text": "disableWebAdmin 1\x1cautoDetectCdn 0\x0benableUpdateCheck 0\x85CGIRLimit {\u2028}\n", "policy": True},
    {"text": "listener a {\n address 01.2.3.4:80\n}\nlistener b {\n address [fe80::1%eth0]:80\n}\nlistener c {\n address [::ffff:1.2.3.4]:080\n}\n", "policy": False},
    {"text": "", "policy": True},
]
CASES = LINT + EXTRA + [{"text": f"listener l {{\n  address {a}\n}}\n", "policy": False} for a in ADDRESS]
with tempfile.TemporaryDirectory() as temp:
    for index, case in enumerate(CASES):
        path = pathlib.Path(temp, f"case{index}.conf")
        path.write_bytes(case["text"].encode())
        command = [str(BINARY), "lint", str(path)] + ([] if case["policy"] else ["--no-policy"])
        rs = subprocess.run(command, capture_output=True, text=True)
        expected = lint.lint(case["text"], case["policy"])
        assert rs.returncode == (0 if not expected else 1), (index, rs.returncode, rs.stderr)
        assert json.loads(rs.stdout) == {"valid": not expected, "errors": expected}, (index, rs.stdout, expected)
        if case["policy"]:  # byte-identical to the Python command line
            py = subprocess.run([sys.executable, "-I", str(TOOLS / "ols_config_lint.py"), str(path)], capture_output=True, text=True)
            same(f"lint case {index}", py, rs)
print(f"Rust lint parity passed ({len(LINT)} corpus configs, {len(ADDRESS)} addresses, {len(EXTRA)} extra texts).")

with tempfile.TemporaryDirectory() as temp:
    # 2. Status and the restriction epoch.
    states = fresh(temp, "epoch")
    both(states, "status")
    both(states, "restrict", "suspend", "alice")
    both(states, "restrict")
    both(states, "status")
    records = [json.loads((s / "epoch.json").read_text()) for s in states]
    for record in records:
        assert all(isinstance(h.pop("time"), float) for h in record["history"])
    assert records[0] == records[1] == {"epoch": 2, "history": [{"epoch": 1, "reason": "suspend alice"},
                                                                {"epoch": 2, "reason": "unspecified"}]}, records
    assert (states[0] / "epoch.high").read_text() == (states[1] / "epoch.high").read_text() == "2\n"
    assert tree(states[0] / "journal") == tree(states[1] / "journal") == {}
    for state in states:  # interchangeable: each implementation continues the other's record
        rust(state, "restrict", "x") if state == states[0] else python(state, "restrict", "x")
    both(states, "status")
    assert json.loads(rust(states[0], "status").stdout)["epoch"] == json.loads(python(states[1], "status").stdout)["epoch"] == 3

    # 3. A damaged epoch record fails closed in both: status shows no epoch, restrict refuses, nothing is reset.
    for text in ("{broken", '{"epoch": true}', '{"epoch": -1}'):
        states = fresh(temp, f"damaged{len(text)}")
        for state in states:
            (state / "epoch.json").write_text(text)
        both(states, "status")
        both(states, "recover")
        py, rs = python(states[0], "restrict", "x"), rust(states[1], "restrict", "x")
        assert py.returncode == rs.returncode == 1 and py.stdout == rs.stdout == "", (py, rs)
        assert all((s / "epoch.json").read_text() == text and not (s / "epoch.high").exists() for s in states)
    states = fresh(temp, "high")
    for state in states:
        (state / "epoch.high").write_text("1\n")
    both(states, "status")

    # 4. Staging, validation binding and refused activations.
    src = pathlib.Path(temp, "src")
    (src / "vhosts/site").mkdir(parents=True)
    (src / "marker").mkdir()
    (src / "httpd_config.conf").write_text("serverName lab\n")
    (src / "vhosts/site/vhconf.conf").write_text("docRoot /home/u/public_html/\n")
    (src / "marker/generation").write_text("g1\n")
    (src / "EPOCH").write_text("0\n")
    (src / "health.json").write_text(json.dumps([{"vhost": "site", "host": "site", "url": "http://127.0.0.1:1/h"}]))
    os.symlink("httpd_config.conf", src / "config-link")  # copied as a file (copytree follows links)
    before = tree(src)
    states = fresh(temp, "stage")
    both(states, "status")
    both(states, "activate", "g1")
    both(states, "stage", "g1", str(src))
    assert tree(src) == before, "the source is never touched"
    assert tree(states[0] / "generations") == tree(states[1] / "generations")
    both(states, "stage", "g1", str(src), stderr=True)  # immutable
    validations = []
    for state, run in zip(states, (python, rust)):
        result = run(state, "validate", "g1")
        assert result.returncode == 0, result.stderr
        validations.append(json.loads(result.stdout))
    keys = ("generation", "valid", "exit_code", "tree_sha256", "binary_sha256", "health_targets")
    assert [{k: v[k] for k in keys} for v in validations][0] == {k: validations[1][k] for k in keys}, validations
    assert validations[0]["valid"] is False and validations[0]["exit_code"] == 2  # unprivileged validator refuses
    stored = [json.loads((s / "validations/g1.json").read_text()) for s in states]
    assert set(stored[0]) == set(stored[1]) and without(stored[0], "validator_sha256", "time") == without(stored[1], "validator_sha256", "time")
    both(states, "activate", "g1")  # validation failed
    for state in states:  # a passing record bound to this tree and binary, then a newer restriction
        (state / "validations/g1.json").write_text(json.dumps(dict(stored[0], valid=True, exit_code=0)))
        python(state, "restrict", "suspend")
    both(states, "activate", "g1")
    assert json.loads(rust(states[1], "activate", "g1").stdout)["reason"] == "generation epoch 0 predates restriction epoch 1"
    (states[1] / "openlitespeed").write_bytes(b"binary-2")
    (states[0] / "openlitespeed").write_bytes(b"binary-2")
    both(states, "activate", "g1")  # OLS binary changed after validation
    assert tree(states[0] / "journal") == tree(states[1] / "journal") == {}
    # An unfolded restriction intent makes every generation stale, whatever its epoch (review RV-29, finding 3).
    intent = "1729600000000000001-0123456789abcdef0123456789abcdef.json"
    for state in states:
        (state / "openlitespeed").write_bytes(b"binary-1")
        (state / "restrictions").mkdir(mode=0o700)
        (state / "restrictions" / intent).write_text(json.dumps({"event": None, "reason": "x", "time": 1.0, "user": None}))
    out = json.loads(both(states, "activate", "g1").stdout)
    assert out == {"generation": "g1", "reason": f"restriction intent {intent} not yet folded into the epoch", "result": "refused"}, out
    both(states, "status")
    for state in states:
        (state / "restrictions" / intent).unlink()
    both(states, "activate", "g1")

    # 5. Journal recovery without service actions: superseded and aborted transactions, a pointer whose
    #    generation is not validated (left alone), ordering by seq whatever the file names.
    states = fresh(temp, "recover")
    journal = [("z1", 1, "g0", "committed"), ("a2", 2, "g1", "switched"), ("m3", 3, "g2", "committed"), ("b4", 4, "g3", "intent")]
    for state in states:
        (state / "journal").mkdir()
        (state / "generations/g2").mkdir(parents=True)
        (state / "generations/g2/EPOCH").write_text("0\n")
        os.symlink(str(state / "generations/g2"), state / "active")
        for tx, seq, gen, step in journal:
            (state / f"journal/{tx}.json").write_text(json.dumps({"id": tx, "seq": seq, "new": gen, "previous": None,
                                                                   "started": 100.0 - seq, "state": step, "history": [step]}))
    out = json.loads(both(states, "recover").stdout)
    assert out["actions"] == [{"tx": "a2", "action": "superseded"}, {"tx": "b4", "action": "aborted"}], out
    assert out["pointer"] == "g2" and out["committed"] == "g2" and out["served"] is None and not out["coherent"]
    for tx, *_ in journal:
        records = [json.loads((s / f"journal/{tx}.json").read_text()) for s in states]
        assert without(records[0], "updated") == without(records[1], "updated"), records
    both(states, "status")
    same("cross status", python(states[1], "status"), rust(states[0], "status"))

    # 6. Command-line errors.
    states = fresh(temp, "cli")
    for args in (["activate", "g1", "--crash-after", "bogus"],):
        both(states, *args, stderr=True)
    for args in (["bogus"], ["stage"], ["validate"], []):
        py, rs = python(states[0], *args), rust(states[1], *args)
        assert py.returncode == rs.returncode == 1 and py.stdout == rs.stdout == "", (args, py, rs)
    py = subprocess.run([sys.executable, "-I", str(TOOLS / "ols_stage_validate.py"), "/nonexistent"], capture_output=True, text=True)
    rs = subprocess.run([str(BINARY), "stage-validate", "/nonexistent"], capture_output=True, text=True)
    assert py.returncode == rs.returncode == 2 and "Run as root" in py.stderr and "Run as root" in rs.stderr
    rs = subprocess.run([str(BINARY), "--lab-root", states[1], "enforce", "--grace", "300"], capture_output=True, text=True)
    assert rs.returncode == 0 and json.loads(rs.stdout) == {"result": None}, rs
    rs = subprocess.run([str(BINARY), "--lab-root", states[1], "recover", "--grace", "300"], capture_output=True, text=True)
    assert rs.returncode == 0 and json.loads(rs.stdout)["actions"] == [], rs

    # 7. Health of the active generation: none, unreachable targets (one pass with --seconds 0), no targets.
    states = fresh(temp, "health")
    assert json.loads(both(states, "health").stdout) == {"failing": [], "generation": None}
    for state in states:
        (state / "generations/g1").mkdir(parents=True)
        (state / "generations/g1/health.json").write_text(json.dumps([{"vhost": "site", "host": "site", "url": "http://127.0.0.1:1/h"}]))
        os.symlink(str(state / "generations/g1"), state / "active")
    out = json.loads(both(states, "health", "--seconds", "0").stdout)
    assert out == {"failing": [{"got": "error: URLError", "vhost": "site"}], "generation": "g1"}, out
    # HTTPS targets (review RV-29, finding 12): TLS to the address with the host as SNI, refused here.
    for state in states:
        (state / "generations/g1/health.json").write_text(json.dumps([
            {"vhost": "site", "host": "site", "url": "http://127.0.0.1:1/h"},
            {"vhost": "tls.site.test", "host": "site.test", "url": "https://127.0.0.1:443/.ols-cpanel-generation/id"}]))
    out = json.loads(both(states, "health", "--seconds", "0").stdout)
    assert out["failing"] == [{"got": "error: URLError", "vhost": "site"},
                              {"got": "error: ConnectionRefusedError", "vhost": "tls.site.test"}], out
    for state in states:
        (state / "generations/g1/health.json").unlink()
    assert json.loads(both(states, "health", "--seconds", "1").stdout) == {"failing": [], "generation": "g1"}
    for args in (["health", "--seconds", "x"], ["health", "--seconds"]):
        py, rs = python(states[0], *args), rust(states[1], *args)
        assert py.returncode == rs.returncode == 1 and py.stdout == rs.stdout == "", (args, py, rs)
print("Rust activator parity passed (status, restrict, epoch fail-closed, stage, validate binding, refused "
      "activations, unfolded restriction intents, journal recovery, command-line errors, HTTP and HTTPS health).")
