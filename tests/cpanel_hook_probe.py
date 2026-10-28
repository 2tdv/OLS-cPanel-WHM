#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
sys.path.insert(0, str(TOOLS))
import cpanel_hook_probe as hp
import hook_observer as ob

with tempfile.TemporaryDirectory() as temp:
    ob.LOG = str(pathlib.Path(temp, "hooks.jsonl"))
    def run(payload):
        sys.stdin = __import__("io").StringIO(json.dumps(payload))
        out = __import__("io").StringIO()
        real, sys.stdout = sys.stdout, out
        try:
            ob.main()
        finally:
            sys.stdout = real
        return out.getvalue().strip(), json.loads(pathlib.Path(ob.LOG).read_text().splitlines()[-1])
    reply, record = run({"context": {"category": "Whostmgr", "event": "Accounts::Create", "stage": "pre"},
                         "data": {"user": "olscpz", "domain": "olscp-z.test", "pass": "S3cret!", "ssl_key": "-----BEGIN"}})
    assert reply == "1" and record["identity"] == {"user": "olscpz", "domain": "olscp-z.test"}
    assert "S3cret" not in json.dumps(record) and "BEGIN" not in json.dumps(record) and "pass" in record["data_keys"]
    reply, _ = run({"context": {"category": "Whostmgr", "event": "Accounts::Create", "stage": "pre"},
                    "data": {"domain": "olscp-block.test"}})
    assert reply.startswith("0 ")
    reply, _ = run({"context": {"category": "Whostmgr", "event": "Accounts::Create", "stage": "post"},
                    "data": {"domain": "olscp-block.test"}})
    assert reply == "1"  # only pre stages can veto
    reply, record = run({"context": {"category": "Cpanel", "event": "UAPI::SubDomain::addsubdomain", "stage": "pre"},
                         "data": {"args": {"domain": "one", "rootdomain": "olscp-z.test"}, "user": "olscpz"}})
    assert record["args_identity"] == {"domain": "one", "rootdomain": "olscp-z.test"}
    before = pathlib.Path(ob.LOG).read_text()
    sys.stdin = __import__("io").StringIO("")
    ob.main()
    assert pathlib.Path(ob.LOG).read_text() == before  # no context, no record
names = {(c, e) for c, e, *_ in hp.CANDIDATES}
assert set(hp.INVENTED) <= names and ("PkgAcct", "Restore") in names and hp.BLOCK_DOMAIN.startswith(ob.BLOCK_MARKER)
result = subprocess.run([sys.executable, str(TOOLS / "cpanel_hook_probe.py")], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("Hook observer redaction/veto and hook probe guard checks passed.")
