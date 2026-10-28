#!/usr/bin/python3
"""G0-H lab experiment, broker part: the prebuilt ols-cpanel-broker runs as a transient root service
and is exercised by the callers it must serve and the ones it must refuse: root on the admin socket,
each lab tenant and an unrelated local user on the tenant socket, forged account fields, unknown
fields and operations, path-like operations, oversized and malformed requests, and capability
misuse (replay, widened scope, changed request digest, tampered expiry, disallowed action), and the
review hardening: per-UID connection slots, a total request deadline, log-safe ids, a status cache
and a private audit log.
Removes everything afterwards. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT_SRC = pathlib.Path(__file__).resolve().parent / "broker_client.py"
RUN_DIR = "/run/ols-cpanel-broker-lab"
STATE = "/var/lib/ols-cpanel"
AUDIT = STATE + "/broker-audit.log"
UNIT = "ols-cpanel-broker-lab"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Runs a root service and connects as the lab tenants; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("broker-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "broker-experiment", "started_at": probe.now(), "result": "not_run",
                   "cases": {}}
        index = 0

        def step(name, command, limit=60):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
            return record

        client = run / "broker_client.py"
        shutil.copy2(CLIENT_SRC, client)
        os.chmod(client, 0o755)

        def call(label, user, sock, payload):
            prefix = [] if user == "root" else ["/usr/sbin/runuser", "-u", user, "--"]
            if user == "self":
                record = subprocess.run([sys.executable, "-I", str(client), f"{RUN_DIR}/{sock}.sock", payload],
                                              capture_output=True, text=True, timeout=30)
                out = {"exit_code": record.returncode, "stdout": record.stdout, "stderr": record.stderr}
                probe.durable_json(run / f"self-{label}.json", out)
            else:
                # Tenants cannot read the operator's home; root staged the client in the runtime directory.
                out = step(label, [*prefix, "/usr/bin/python3", "-I", f"{RUN_DIR}/client.py", f"{RUN_DIR}/{sock}.sock", payload])
            try:
                return json.loads(out["stdout"])
            except ValueError:
                return {"transport_error": (out["stderr"] or "")[-200:]}

        def req(op, args=None, **extra):
            body = {"v": 1, "id": uuid.uuid4().hex[:12], "op": op, **extra}
            if args is not None:
                body["args"] = args
            return json.dumps(body)

        def case(name, reply, expect):
            ok = expect(reply)
            summary["cases"][name] = {"pass": bool(ok), "reply": reply}
            return reply

        started = state_created = False
        try:
            digest = step("broker-sha256", ["/usr/bin/sha256sum", str(args.broker.resolve())])["stdout"].split()[0]
            summary["broker_sha256"] = digest
            if step("residue", ["/usr/bin/ls", "-d", RUN_DIR])["stdout"].strip():
                raise ValueError("broker lab residue present")
            state_created = step("state-exists", ["/usr/bin/test", "-d", STATE])["exit_code"] != 0
            step("state-dir", ["/usr/bin/install", "-d", "-m", "0755", STATE])
            started = True
            step("start", ["/usr/bin/systemd-run", f"--unit={UNIT}", f"--property=RuntimeDirectory={pathlib.Path(RUN_DIR).name}",
                           "--property=RuntimeDirectoryMode=0755", str(args.broker.resolve()), RUN_DIR])
            for _ in range(50):
                if step("socket-wait", ["/usr/bin/test", "-S", f"{RUN_DIR}/tenant.sock"])["exit_code"] == 0:
                    break
                time.sleep(0.1)
            step("client", ["/usr/bin/install", "-m", "0755", str(client), f"{RUN_DIR}/client.py"])
            summary["socket_modes"] = step("socket-modes", ["/usr/bin/stat", "-c", "%n %U %a", f"{RUN_DIR}/admin.sock",
                                                            f"{RUN_DIR}/tenant.sock"])["stdout"].splitlines()
            a, b = list(tf.TENANTS)
            ok = lambda r: r.get("ok") is True
            code = lambda c: (lambda r: r.get("ok") is False and r.get("error", {}).get("code") == c)
            # Admin socket.
            case("admin-from-unprivileged-user", call("admin-dev", "self", "admin", req("server.status")),
                 lambda r: "transport_error" in r or code("FORBIDDEN")(r))
            case("admin-status-root", call("admin-status", "root", "admin", req("server.status")), ok)
            inv = case("admin-inventory-root", call("admin-inventory", "root", "admin", req("inventory.accounts")),
                       lambda r: ok(r) and {d["user"] for d in r["result"]["domains"]} >= set(tf.TENANTS))
            # Tenant socket: identity comes only from the kernel.
            for user in (a, b):
                case(f"tenant-domains-{user}", call(f"tenant-{user}", user, "tenant", req("tenant.domains")),
                     lambda r, u=user: ok(r) and r["result"]["user"] == u and r["result"]["domains"]
                     and all(d["user"] == u for d in r["result"]["domains"]))
            case("tenant-forged-user-argument", call("forged-arg", a, "tenant", req("tenant.domains", {"user": b})),
                 code("BAD_ARGS"))
            case("tenant-forged-top-level-field", call("forged-field", a, "tenant", req("tenant.domains", user=b)),
                 code("BAD_REQUEST"))
            case("tenant-root-refused", call("tenant-root", "root", "tenant", req("tenant.domains")), code("FORBIDDEN"))
            case("tenant-unrelated-user", call("tenant-dev", "self", "tenant", req("tenant.domains")),
                 lambda r: ok(r) and r["result"]["domains"] == [])
            case("tenant-admin-op-refused", call("tenant-admin-op", a, "tenant", req("inventory.accounts")),
                 code("UNKNOWN_OPERATION"))
            case("tenant-capability-op-refused", call("tenant-cap", a, "tenant", req("cap.issue", {"principal": a,
                 "action": "lab.audit_marker", "scope": a, "digest": "0" * 64})), code("UNKNOWN_OPERATION"))
            for label, op in (("path", "../../etc/shadow"), ("shell", "server.status;id"), ("empty", "")):
                case(f"op-{label}", call(f"op-{label}", a, "tenant", req(op)), code("UNKNOWN_OPERATION"))
            case("oversized", call("oversized", a, "tenant", "@size:70000"), code("TOO_LARGE"))
            case("malformed-json", call("malformed", a, "tenant", '{"v":1,"id":"x","op":'), code("BAD_REQUEST"))
            case("wrong-version", call("version", a, "tenant", json.dumps({"v": 2, "id": "x", "op": "tenant.status"})),
                 code("PROTOCOL"))
            # Review hardening (human review 2026-10-22): slots, deadline, log safety, status cache.
            case("control-characters-in-id", call("ctl-id", a, "tenant", json.dumps({"v": 1, "id": "x\nFAKE uid=0", "op": "tenant.status"})),
                 code("BAD_REQUEST"))
            started_at = time.monotonic()
            case("trickle-hits-total-deadline", call("trickle", a, "tenant", "@trickle:12"), code("TIMEOUT"))
            summary["trickle_seconds"] = round(time.monotonic() - started_at, 1)
            first = call("status-1", a, "tenant", req("tenant.status"))
            second = call("status-2", b, "tenant", req("tenant.status"))
            case("status-cached", {"first": first, "second": second},
                 lambda r: ok(r["first"]) and ok(r["second"])
                 and r["first"]["result"]["observed_at"] == r["second"]["result"]["observed_at"])
            holder = subprocess.Popen(["sudo", "-n", "/usr/sbin/runuser", "-u", a, "--", "/usr/bin/python3", "-I",
                                       f"{RUN_DIR}/client.py", f"{RUN_DIR}/tenant.sock", "@idle:4:8"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # held slots expire at the 5 s request deadline; the three checks fit before it
            case("tenant-slot-cap", call("slot-cap", a, "tenant", req("tenant.status")), code("BUSY"))
            case("other-tenant-unaffected", call("slot-other", b, "tenant", req("tenant.status")), ok)
            case("admin-unaffected", call("slot-admin", "root", "admin", req("server.status")), ok)
            holder.wait(timeout=30)
            case("tenant-slots-released", call("slot-released", a, "tenant", req("tenant.status")), ok)
            # Capabilities (admin socket).
            body = hashlib.sha256(b'{"marker":"lab"}').hexdigest()
            issue = lambda **kw: call("cap-issue", "root", "admin", req("cap.issue", {"principal": "root",
                                      "action": "lab.audit_marker", "scope": "server", "digest": body, **kw}))
            execute = lambda token, **kw: call("cap-execute", "root", "admin", req("cap.execute", {"token": token,
                                               "action": "lab.audit_marker", "scope": "server", "digest": body, **kw}))
            token = case("cap-issue", issue(), ok)["result"]["token"]
            case("cap-execute", execute(token), ok)
            case("cap-replay", execute(token), code("CAPABILITY_REPLAYED"))
            token = issue()["result"]["token"]
            case("cap-widened-scope", execute(token, scope=a), code("CAPABILITY_INVALID"))
            case("cap-changed-request", execute(token, digest=hashlib.sha256(b"other").hexdigest()), code("CAPABILITY_INVALID"))
            principal, nonce, expires, mac = token.split(".")
            case("cap-tampered-expiry", execute(f"{principal}.{nonce}.{int(expires) + 86400}.{mac}"), code("CAPABILITY_INVALID"))
            case("cap-forged-principal", execute(f"{a}.{nonce}.{expires}.{mac}"), code("CAPABILITY_INVALID"))
            case("cap-disallowed-action", issue(action="server.restart"), code("BAD_ARGS"))
            case("cap-injected-principal", issue(principal="root;id"), code("BAD_ARGS"))
            case("cap-still-valid-after-tampering", execute(token), ok)
            summary["audit_records"] = len(step("audit", ["/usr/bin/cat", AUDIT])["stdout"].splitlines())
            case("audit-exactly-two", {"records": summary["audit_records"]}, lambda r: r["records"] == 2)
            summary["audit_mode"] = step("audit-mode", ["/usr/bin/stat", "-c", "%a %U", AUDIT])["stdout"].strip()
            case("audit-log-private", {"mode": summary["audit_mode"]}, lambda r: r["mode"] == "600 root")
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if started:
                step("journal", ["/usr/bin/journalctl", "-u", UNIT, "--no-pager", "-n", "200"])
                step("stop", ["/usr/bin/systemctl", "stop", UNIT])
            if state_created:
                step("state-remove", ["/usr/bin/rm", "-rf", STATE])
            else:
                step("audit-remove", ["/usr/bin/rm", "-f", AUDIT])
            summary["removed"] = not step("final-residue", ["/usr/bin/ls", "-d", RUN_DIR])["stdout"].strip()
            summary["passed"] = sum(c["pass"] for c in summary["cases"].values())
            summary["total"] = len(summary["cases"])
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "passed": summary["passed"],
                              "total": summary["total"], "removed": summary["removed"], "error": summary.get("error")}))
    return 0 if summary["result"] == "observed" and summary["passed"] == summary["total"] else 1

if __name__ == "__main__":
    sys.exit(main())
