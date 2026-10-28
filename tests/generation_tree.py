#!/usr/bin/python3
"""Production generation trees: the lab reference (ols_generation_probe.generation_tree(..., production=True)
on the lab compiler's output for recorded inputs) and the product (GenerationTree + LocalEngine::writeTree on
the product compiler's output for the same inputs, tests/generation_tree.php) must be byte-identical, file
by file and mode by mode (the product adds summary.json for the plugins), and give the same source digest
(ols_events.reconcile vs Events\\SourceDigest).
Scenarios: the recorded lab server (one IPv4 address: wildcard listeners), the same with tenant B on a
second address (per-address listeners and a loopback listener) and a hybrid vhost (HR-D08, its HTTPS vhost
checked over TLS on 443)."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_events as ev
import ols_generation_probe as gp
import tenant_isolation_probe as iso

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
FIXTURE = json.loads((ROOT / "tests/Fixtures/lab-snapshot/compile-production.json").read_text())
GEN, EPOCH = "r20261022120000-0a1b2c", 3
B = "olstest2.example.test"

def edited(argv, change):
    calls, hits = json.loads(json.dumps(FIXTURE["calls"])), 0
    for call in calls:
        if call["argv"] == argv:
            call["stdout"], hits = change(call["stdout"]), hits + 1
    assert hits, f"the fixture has no call {argv}"
    return calls

def compile_reference(calls, hybrid_ports):
    results, curl = {}, {}
    for call in calls:
        record = {"exit_code": call["exit_code"], "stdout": call["stdout"], "stderr": ""}
        results.setdefault(json.dumps(call["argv"]), record)
        if call["argv"][0] == "/usr/bin/curl":
            curl[call["argv"][-1]] = record

    def step(name, command, limit=300):
        # The lab-only Apache PHP check names the vhost address; an edited address keeps its recorded answer.
        return curl[command[-1]] if command[0] == "/usr/bin/curl" else results[json.dumps(command)]

    return iso.compile_lab(step, {}, production=True, hybrid_ports=hybrid_ports)

def digest(path):
    return hashlib.sha256(path.encode()).hexdigest()  # what the fake engine of the PHP side answers

SCENARIOS = {
    "recorded": (FIXTURE["calls"], None),
    "multi-address": (edited(["/usr/bin/cat", f"/var/cpanel/userdata/olscpb/{B}"],
                             lambda s: s.replace("ip: 172.16.0.4", "ip: 172.16.0.9")), None),
    "hybrid": (edited(["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/cat", "/home/olscpb/public_html/.htaccess"],
                      lambda s: 'SetEnvIf Request_URI "." X=1\n' + s), [81, 444]),
}
scenarios = {}
with tempfile.TemporaryDirectory() as temp:
    for label, (calls, ports) in SCENARIOS.items():
        compiled = compile_reference(calls, tuple(ports) if ports else None)
        files = {path: digest(path) for path in ev.referenced_paths(compiled)}
        source = hashlib.sha256(json.dumps({"config": compiled["config"], "vhconf": compiled["vhconf"], "epoch": EPOCH,
                                            "files": files}, sort_keys=True).encode()).hexdigest()
        tree = pathlib.Path(temp, label)
        gp.generation_tree(tree, GEN, compiled, epoch=EPOCH, production=True)
        (tree / ev.SOURCE).write_text(source + "\n")
        os.chmod(tree / ev.SOURCE, 0o644)
        targets = json.loads((tree / "health.json").read_text())
        scenarios[label] = {"calls": calls, "hybrid_ports": ports, "generation": GEN, "epoch": EPOCH, "source": source,
                            "files": {str(p.relative_to(tree)): p.read_text() for p in sorted(tree.rglob("*")) if p.is_file()},
                            "modes": {str(p.relative_to(tree)): p.stat().st_mode & 0o7777 for p in sorted(tree.rglob("*"))},
                            "targets": targets}
        hosts = {t["vhost"]: t for t in targets}
        if label == "recorded":
            # One address: wildcard listeners; account vhosts on their own address, the others on loopback.
            assert hosts[B]["url"] == "http://172.16.0.4:80/.ols-cpanel-generation/id" and hosts[B]["host"] == B
            assert hosts["cpanel-proxy"]["url"].startswith("http://127.0.0.1:80/")
            assert hosts["cpanel-proxy"]["host"] == "cpanel.ols-health.invalid"
            assert hosts["server-default"]["host"] == "ols-health.invalid" and hosts[f"svc.{B}"]["host"] == f"cpanel.{B}"
            assert set(hosts) == set(compiled["vhconf"]), "every vhost of the recorded server is probed"
            vh = (tree / f"vhosts/{B}/vhconf.conf").read_text()
            assert "allow                127.0.0.1, 172.16.0.4\n" in vh
            config = (tree / "httpd_config.conf").read_text()
            assert gp.LISTENER_TLS["$SERVER_ROOT/conf/cert/lab.key"] in config and "$SERVER_ROOT/conf/cert/" not in config
        if label == "multi-address":
            assert hosts[B]["url"] == "http://172.16.0.9:80/.ols-cpanel-generation/id"
            assert hosts["olstest1.example.test"]["url"] == "http://172.16.0.4:80/.ols-cpanel-generation/id"
            assert hosts["server-default"]["url"].startswith("http://127.0.0.1:80/")
        if label == "hybrid":
            # A hybrid domain's HTTPS vhost is mapped on 443 only: checked over TLS on its own address, the domain
            # as SNI and Host (review RV-29, finding 12); its health context admits that address.
            assert hosts["tls." + B] == {"vhost": "tls." + B, "host": B, "url": "https://172.16.0.4:443/.ols-cpanel-generation/id"}
            assert "allow                127.0.0.1, 172.16.0.4\n" in (tree / f"vhosts/tls.{B}/vhconf.conf").read_text()
            assert B in hosts and set(hosts) == set(compiled["vhconf"]), "every vhost of the hybrid server is probed"
    with tempfile.NamedTemporaryFile("w", suffix=".json", dir=temp, delete=False) as handle:
        json.dump(scenarios, handle)
    result = subprocess.run([PHP, "-n", str(ROOT / "tests/generation_tree.php"), handle.name], capture_output=True, text=True)
print(result.stdout.splitlines()[-1] if result.returncode == 0 and result.stdout else result.stdout[-3000:] + result.stderr[-3000:])
sys.exit(result.returncode)
