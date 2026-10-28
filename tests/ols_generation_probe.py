#!/usr/bin/python3
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
sys.path.insert(0, str(TOOLS))
import ols_config_lint as lint
import ols_generation as activator
import ols_generation_probe as gp
import tenant_isolation_probe as iso

plan = iso.default_plan()
A, B = iso.tf.TENANTS["olscpa"], iso.tf.TENANTS["olscpb"]
compiled = {"config": iso.server_config((iso.TEMPLATES / "ownership_httpd_config.conf").read_text(), plan=plan),
            "vhconf": {n: f"docRoot {v['docroot']}/\nrewrite {{\n    rules                <<<END_rules\nRewriteRule ^ - [L]\nEND_rules\n}}\n"
                       for n, v in plan.items()}, "plan": plan, "missing": {n: [] for n in plan}}
with tempfile.TemporaryDirectory() as temp:
    gp.generation_tree(pathlib.Path(temp, "g"), "g7", compiled)
    config = pathlib.Path(temp, "g/httpd_config.conf").read_text()
    # Self-contained: no vhost or certificate reference resolves through the server root.
    assert "$SERVER_ROOT/conf/" not in config and "configFile           conf/" not in config
    assert f"{gp.GEN_ROOT}/g7/vhosts/{A}/vhconf.conf" in config and lint.lint(config) == []
    assert pathlib.Path(temp, "g/marker/generation").read_text() == "g7\n"
    gp.generation_tree(pathlib.Path(temp, "b"), "g8", compiled, smoke_ok=False, syntax_ok=False)
    broken = pathlib.Path(temp, "b").joinpath("httpd_config.conf").read_text()
    assert "virtualHost unterminated" in broken and "marker-missing" in pathlib.Path(temp, "b/vhosts/olscp-gen/vhconf.conf").read_text()
    # Every vhost: health context, the health rule ahead of its own rules, and a health.json target.
    import json as _json
    targets = _json.loads(pathlib.Path(temp, "g/health.json").read_text())
    assert {t["vhost"] for t in targets} == set(plan) and all(t["host"] == t["vhost"] for t in targets)
    vh = pathlib.Path(temp, f"g/vhosts/{A}/vhconf.conf").read_text()
    assert f"context {gp.HEALTH_URI}" in vh and "allow                127.0.0.1" in vh and "satisfy              any" in vh
    assert vh.index(gp.HEALTH_RULE) < vh.index("RewriteRule ^ - [L]")
    assert pathlib.Path(temp, f"g/health/{A}/id").read_text() == f"g7 {A}\n"
    gp.generation_tree(pathlib.Path(temp, "u"), "g9", compiled, broken_vhost=f"{A}")
    assert not pathlib.Path(temp, f"u/health/{A}/id").exists() and pathlib.Path(temp, f"u/health/{B}/id").exists()

# Activation is bound to a passing validation of exactly this tree and binary (RV-02).
with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    activator.GEN_ROOT, activator.VALIDATIONS = str(temp / "gens"), str(temp / "validations")
    activator.BINARY = str(temp / "openlitespeed")
    (temp / "validations").mkdir()
    pathlib.Path(activator.BINARY).write_bytes(b"binary-1")
    gp.generation_tree(temp / "gens/g1", "g1", compiled)
    assert activator.validation_problem("g1") == "not validated"
    record = {"generation": "g1", "valid": True, "tree_sha256": activator.tree_sha256("g1"),
              "binary_sha256": activator.file_sha256(activator.BINARY)}
    (temp / "validations/g1.json").write_text(_json.dumps(record))
    assert activator.validation_problem("g1") is None
    (temp / "validations/g1.json").write_text(_json.dumps(dict(record, valid=False)))
    assert activator.validation_problem("g1") == "validation failed"
    (temp / "validations/g1.json").write_text(_json.dumps(record))
    (temp / f"gens/g1/health/{A}/id").write_text("changed\n")
    assert activator.validation_problem("g1") == "generation changed after validation"
    (temp / f"gens/g1/health/{A}/id").write_text(f"g1 {A}\n")
    pathlib.Path(activator.BINARY).write_bytes(b"binary-2")
    assert activator.validation_problem("g1") == "OLS binary changed after validation"
    pathlib.Path(activator.BINARY).write_bytes(b"binary-1")
    (temp / "gens/g1/health.json").unlink()
    record["tree_sha256"] = activator.tree_sha256("g1")
    (temp / "validations/g1.json").write_text(_json.dumps(record))
    assert activator.validation_problem("g1") == "no vhost health targets"
# Restriction epoch (RV-05): suspended vhosts answer 403, removed ones disappear, EPOCH is recorded.
with tempfile.TemporaryDirectory() as temp:
    gp.generation_tree(pathlib.Path(temp, "e"), "e1", compiled, epoch=2, suspended=[f"{B}"], removed=[f"{A}"])
    tree = pathlib.Path(temp, "e")
    assert (tree / "EPOCH").read_text() == "2\n"
    config = (tree / "httpd_config.conf").read_text()
    assert f"virtualHost {A} {{" not in config and f"map                  {A}" not in config
    assert f"virtualHost {B} {{" in config and not (tree / f"vhosts/{A}").exists()
    b = (tree / f"vhosts/{B}/vhconf.conf").read_text()
    assert b.index(gp.HEALTH_RULE) < b.index("RewriteRule ^ /cgi-sys/suspendedpage.cgi [R=302,L]")
    assert {t["vhost"] for t in _json.loads((tree / "health.json").read_text())} == {f"{B}"}
with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    activator.GEN_ROOT, activator.EPOCH, activator.LOCK = str(temp / "gens"), str(temp / "epoch.json"), str(temp / "lock")
    activator.EPOCH_HIGH = str(temp / "epoch.high")
    (temp / "gens" / "old").mkdir(parents=True)
    (temp / "gens" / "old" / "EPOCH").write_text("0\n")
    assert activator.current_epoch() == 0 and not activator.stale("old")  # fresh installation
    assert activator.restrict("suspend x")["epoch"] == 1 and activator.current_epoch() == 1
    (temp / "gens" / "new").mkdir(parents=True)
    (temp / "gens" / "new" / "EPOCH").write_text("1\n")
    assert activator.stale("old") and not activator.stale("new")
    (temp / "gens/broken").mkdir()
    assert activator.stale("broken")  # unknown epoch is never treated as current
assert activator.CRASH_POINTS == ("intent", "switched", "reloaded")
assert "ExecReload=/usr/libexec/ols-cpanel/ols-cpanel-reload" in (ROOT / "build/ols-source/ols-cpanel.service").read_text()
result = subprocess.run([sys.executable, str(TOOLS / "ols_generation_probe.py"), "--rpm", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("Generation builder, activator constants and probe guard checks passed.")

# Review findings 8 and 11: superseded transactions and a damaged epoch record (fail closed).
with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    activator.GEN_ROOT, activator.EPOCH, activator.JOURNAL = str(temp / "gens"), str(temp / "epoch.json"), str(temp / "journal")
    activator.EPOCH_HIGH = str(temp / "epoch.high")
    activator.LOCK = str(temp / "lock")
    (temp / "journal").mkdir()
    for gen, epoch in (("g0", 0), ("g1", 1)):
        (temp / "gens" / gen).mkdir(parents=True)
        (temp / "gens" / gen / "EPOCH").write_text(f"{epoch}\n")
    try:
        activator.current_epoch()
        raise AssertionError("missing record with later generations must fail closed")
    except activator.EpochError:
        pass
    assert activator.stale("g1") and activator.stale("g0")  # nothing is current
    (temp / "epoch.json").write_text("{broken")
    try:
        activator.restrict("x")
        raise AssertionError("a damaged record must never be reset")
    except activator.EpochError:
        pass
    (temp / "epoch.json").write_text(_json.dumps({"epoch": 1, "history": []}))
    assert activator.current_epoch() == 1 and not activator.stale("g1") and activator.stale("g0")
    # Losing epoch.json after a restriction must not erase it (high-water mark), nor may a JSON true pass.
    (temp / "epoch.high").write_text("1\n")
    (temp / "epoch.json").unlink()
    (temp / "gens" / "g1" / "EPOCH").write_text("0\n")
    try:
        activator.current_epoch()
        raise AssertionError("missing record with a high-water mark must fail closed")
    except activator.EpochError:
        pass
    (temp / "epoch.json").write_text('{"epoch": true}')
    try:
        activator.current_epoch()
        raise AssertionError("a boolean epoch must be rejected")
    except activator.EpochError:
        pass
    (temp / "epoch.json").write_text(_json.dumps({"epoch": 0, "history": []}))
    try:
        activator.current_epoch()
        raise AssertionError("an epoch below its high-water mark must fail closed")
    except activator.EpochError:
        pass
    (temp / "gens" / "g1" / "EPOCH").write_text("1\n")
    (temp / "epoch.json").write_text(_json.dumps({"epoch": 1, "history": [
        {"epoch": 1, "time": 100.0}, {"epoch": 2, "time": 900.0}]}))
    # The grace deadline counts from the earliest restriction a generation lacks, not the latest.
    assert activator.first_unapplied_restriction(0) == 100.0 and activator.first_unapplied_restriction(1) == 900.0
    # An interrupted transaction followed by a later committed one is superseded, not rolled back.
    for seq, (gen, state) in enumerate((("g0", "committed"), ("g1", "switched"), ("g2", "committed")), 1):
        (temp / "journal" / f"t{seq}.json").write_text(_json.dumps({"id": f"t{seq}", "seq": seq, "new": gen,
                                                                     "previous": None, "state": state}))
    calls = []
    activator.pointer, activator.served = (lambda: "g2"), (lambda: "g2")
    activator.reload, activator.switch = (lambda: calls.append("reload")), (lambda g: calls.append(("switch", g)))
    actions = activator._recover_locked()
    assert actions == [{"tx": "t2", "action": "superseded"}] and not any(isinstance(c, tuple) for c in calls), (actions, calls)

# Health targets over TLS (review RV-29, finding 12): https://<IPv4>:<port>/..., the target host as SNI and as the
# Host header, the certificate not verified; plain HTTP unchanged. A local TLS server with a throwaway certificate.
import http.server as _http
import ssl as _ssl
import threading as _threading
with tempfile.TemporaryDirectory() as temp:
    key, cert = f"{temp}/k.pem", f"{temp}/c.pem"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "1", "-subj", "/CN=unrelated.invalid"], check=True, capture_output=True)
    seen = {}

    class Health(_http.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"], seen["path"] = self.headers.get("Host"), self.path
            body = b"g9 tls.a.example\n" if self.path == "/.ols-cpanel-generation/id" else b"no"
            self.send_response(200 if body != b"no" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.sni_callback = lambda sock, name, ctx: seen.__setitem__("sni", name)
    server = _http.HTTPServer(("127.0.0.1", 0), Health)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    _threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        target = {"vhost": "tls.a.example", "host": "a.example", "url": f"https://127.0.0.1:{port}/.ols-cpanel-generation/id"}
        assert activator.vhost_health("g9", [target], seconds=0) == []
        assert seen == {"sni": "a.example", "host": "a.example", "path": "/.ols-cpanel-generation/id"}, seen
        missing = dict(target, url=f"https://127.0.0.1:{port}/.ols-cpanel-generation/other")
        assert activator.vhost_health("g9", [missing], seconds=0) == [{"vhost": "tls.a.example", "got": "error: HTTP 404"}]
        plain = dict(target, url=f"http://127.0.0.1:{port}/.ols-cpanel-generation/id")
        assert activator.vhost_health("g9", [plain], seconds=0)[0]["got"].startswith("error: ")
    finally:
        server.shutdown()
print("Activator health over TLS (SNI and Host = target host, certificate unverified) checks passed.")
