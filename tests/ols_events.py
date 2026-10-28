#!/usr/bin/python3
import io
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_events as ev

# Security events raise the restriction epoch before the hook answers; others are only recorded.
assert {"Accounts::suspendacct", "Accounts::Remove", "Api2::SubDomain::delsubdomain"} <= ev.RESTRICTING
assert "Accounts::unsuspendacct" not in ev.RESTRICTING and "UAPI::SSL::install_ssl" not in ev.RESTRICTING
with tempfile.TemporaryDirectory() as temp:
    ev.SPOOL, ev.DONE = temp + "/events", temp + "/events/done"
    ev.activator.EPOCH, ev.activator.LOCK, ev.activator.EPOCH_HIGH = temp + "/epoch.json", temp + "/lock", temp + "/epoch.high"
    # Never the host's own state (a prepared lab server has root-only generations).
    ev.activator.GEN_ROOT, ev.activator.ACTIVE, ev.activator.RESTRICTIONS = temp + "/generations", temp + "/active", temp + "/restrictions"
    ev.RESTRICTIONS = temp + "/restrictions"
    out = io.StringIO()
    for event, user in (("UAPI::SSL::install_ssl", "olscpa"), ("Accounts::suspendacct", None)):
        sys.stdin = io.StringIO(json.dumps({"context": {"category": "x", "event": event, "stage": "post", "user": user},
                                            "data": {"user": "olscpb"}}))
        sys.stdout, saved = out, sys.stdout
        try:
            ev.hook()
        finally:
            sys.stdout = saved
    assert out.getvalue() == "11", out.getvalue()  # exactly "1" per call, no newline (cPanel parses it)
    records = [json.loads(pathlib.Path(ev.SPOOL, n).read_text()) for n in ev.pending()]
    assert [r["event"] for r in records] == ["UAPI::SSL::install_ssl", "Accounts::suspendacct"]
    assert records[0]["user"] == "olscpa" and records[1]["user"] == "olscpb"
    assert "epoch" not in records[0] and records[1]["epoch"] == 1 and ev.activator.current_epoch() == 1
    # Registry maintenance or malformed input: nothing recorded, still exactly "1" (review 2, item 11).
    for raw in ("{}", "not json", "[]", '{"context": "bad"}', ""):
        sys.stdin, sys.stdout, saved = io.StringIO(raw), io.StringIO(), sys.stdout
        try:
            ev.hook()
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        assert printed == "1", (raw, printed)
    assert len(ev.pending()) == 2
print("Event hook recording, restriction epoch and spool checks passed.")

# Deployment profile: absent means the lab test listeners; anything malformed stops reconciliation.
with tempfile.TemporaryDirectory() as temp:
    ev.PROFILE = temp + "/profile.json"
    assert ev.load_profile() == {"production": False, "hybrid_ports": None}
    good = {"production": True, "hybrid_ports": [81, 444]}
    pathlib.Path(ev.PROFILE).write_text(json.dumps(good))
    assert ev.load_profile() == {"production": True, "hybrid_ports": (81, 444)}
    pathlib.Path(ev.PROFILE).write_text(json.dumps(dict(good, hybrid_ports=None)))
    assert ev.load_profile()["hybrid_ports"] is None
    for bad in ([], dict(good, production="yes"), dict(good, hybrid_ports=[81]), dict(good, hybrid_ports=[80, 444]),
                dict(good, hybrid_ports=[81, True]), dict(good, hybrid_ports=[81, 70000]), dict(good, extra=1), {"production": True}):
        pathlib.Path(ev.PROFILE).write_text(json.dumps(bad))
        try:
            ev.load_profile()
            raise AssertionError(bad)
        except ValueError:
            pass
    pathlib.Path(ev.PROFILE).write_text("{")
    try:
        ev.load_profile()
        raise AssertionError("truncated profile accepted")
    except ValueError:
        pass
print("Deployment profile checks passed.")

# Restriction intents (review RV-29, finding 5): when the epoch cannot be raised the hook still answers exactly "1",
# but only after a durable root 0600 intent exists; folding raises the epoch first and removes the intent after.
import os
import stat
import subprocess
with tempfile.TemporaryDirectory() as temp:
    ev.SPOOL, ev.DONE, ev.RESTRICTIONS = temp + "/no-such/events", temp + "/no-such/events/done", temp + "/restrictions"
    ev.activator.EPOCH, ev.activator.LOCK, ev.activator.EPOCH_HIGH = temp + "/epoch.json", temp + "/lock", temp + "/epoch.high"
    real_restrict = ev.activator.restrict

    def failing(reason):
        raise TimeoutError("activation lock busy")

    ev.activator.restrict = failing
    pathlib.Path(temp, "no-such").write_text("a file where the spool directory should be")  # the spool cannot exist
    sys.stdin = io.StringIO(json.dumps({"context": {"event": "Accounts::Remove", "user": "root"}, "data": {"user": "olscpb"}}))
    sys.stdout, sys.stderr, saved = io.StringIO(), io.StringIO(), (sys.stdout, sys.stderr)
    try:
        ev.hook()
        printed, errors = sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdout, sys.stderr = saved
    assert printed == "1" and "restriction epoch not raised" in errors and "durable intent" in errors, errors
    [name] = os.listdir(ev.RESTRICTIONS)
    intent = json.loads(pathlib.Path(ev.RESTRICTIONS, name).read_text())
    assert ev.INTENT_NAME.fullmatch(name) and set(intent) == {"event", "reason", "time", "user"}
    assert intent["event"] == "Accounts::Remove" and intent["reason"] == "Accounts::Remove root" and intent["user"] == "root"
    assert stat.S_IMODE(os.stat(pathlib.Path(ev.RESTRICTIONS, name)).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(ev.RESTRICTIONS).st_mode) == 0o700
    pathlib.Path(ev.RESTRICTIONS, "1761134400000000000-" + "0" * 32 + ".json").write_text("{not json")  # oldest, malformed
    pathlib.Path(ev.RESTRICTIONS, "stray.json.tmp-x").write_text("{}")  # never an intent
    ev.activator.restrict = failing
    try:
        ev.fold_restrictions()
        raise AssertionError("an intent was folded without a raised epoch")
    except TimeoutError:
        pass
    assert len(os.listdir(ev.RESTRICTIONS)) == 3, "nothing removed while the epoch could not be raised"
    ev.activator.restrict = real_restrict
    assert ev.fold_restrictions() == ["1761134400000000000-" + "0" * 32 + ".json", name]
    history = json.loads(pathlib.Path(ev.activator.EPOCH).read_text())["history"]
    assert [h["reason"] for h in history] == ["restriction intent 1761134400000000000-" + "0" * 32 + ".json (malformed)",
                                             "Accounts::Remove root"] and ev.activator.current_epoch() == 2
    assert os.listdir(ev.RESTRICTIONS) == ["stray.json.tmp-x"] and ev.fold_restrictions() == []
print("Restriction intent recording and folding checks passed.")

# The PHP product reads the same intents the same way, and both extract the same referenced files (finding 11).
PHP = "/usr/local/cpanel/3rdparty/php/84/bin/php"
with tempfile.TemporaryDirectory() as temp:
    ev.RESTRICTIONS = temp
    names = [ev.record_intent({"event": "Accounts::suspendacct", "user": "olscpa", "time": 1.5}, "Accounts::suspendacct olscpa"),
             ev.record_intent({"event": None, "user": 7, "time": 2.0}, "None 7\x07é")]
    for bad, text in (("1-" + "a" * 32 + ".json", "[]"), ("2-" + "b" * 32 + ".json", '{"reason": ""}'),
                      ("3-" + "c" * 32 + ".json", "x" * 70000)):
        pathlib.Path(temp, bad).write_text(text)
        names.append(bad)
    os.symlink(temp + "/" + names[0], temp + "/4-" + "d" * 32 + ".json")
    names.append("4-" + "d" * 32 + ".json")
    python = [ev.intent_reason(f"{temp}/{n}", n) for n in names]
    config = ("realm ppd_1 {\n  userDB {\n    location              /home2/olscpa/.htpasswds/public_html/private/passwd\n  }\n}\n"
              "realm ppd_2 {\n  userDB {\n    location              /home_ssd/olscpb/.htpasswds/x/users.key\n  }\n}\n"
              "context /x/ {\n  location /home3/olscpc/.htpasswds/plain\n}\n"
              "vhssl {\n    keyFile              /var/cpanel/ssl/apache_tls/a.example/combined\n}\n"
              "context /y/ {\n  location /home2/olscpa/public_html/y/\n}\n")
    code = ('require $argv[1]; $names = json_decode($argv[3], true); $out = [];'
            ' foreach ($names as $n) { $out[] = OlsCpanel\\Ols\\Generation\\LocalEngine::intentReason($argv[2] . "/" . $n, $n); }'
            ' echo json_encode(["reasons" => $out, "paths" => OlsCpanel\\Events\\SourceDigest::referencedPaths('
            '["config" => $argv[4], "vhconf" => []])]);')
    php = subprocess.run([PHP, "-n", "-r", code, str(ROOT / "src/bootstrap.php"), temp, json.dumps(names), config],
                         capture_output=True, text=True, check=True)
    answer = json.loads(php.stdout)
    assert answer["reasons"] == python, (answer["reasons"], python)
    assert python[0] == "Accounts::suspendacct olscpa" and python[1] == "None 7???" and python[2].endswith("(malformed)")
    assert python[4].endswith("(malformed)") and python[5].endswith("(malformed)")
    paths = ev.referenced_paths({"config": config, "vhconf": {}})
    assert answer["paths"] == paths == ["/home2/olscpa/.htpasswds/public_html/private/passwd", "/home3/olscpc/.htpasswds/plain",
                                        "/home_ssd/olscpb/.htpasswds/x/users.key",
                                        "/var/cpanel/ssl/apache_tls/a.example/combined"], (answer["paths"], paths)
print("Restriction intent reasons and referenced password files are identical in the lab reference and the product.")
