#!/usr/bin/python3
"""Hybrid profile (HR-D08) equivalence: the lab compiler (reference) compiles edited copies of the recorded
lab inputs with the hybrid profile enabled, and the product compiler must produce byte-identical output
for each (tests/compile_replay.php with a scenario file)."""
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import tenant_isolation_probe as iso

PHP = "/usr/local/cpanel/3rdparty/php/84/bin/php"
FIXTURE = json.loads((ROOT / "tests/Fixtures/lab-snapshot/compile-production.json").read_text())
B = "olstest2.example.test"

def read(user, path):
    return ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/cat", f"/home/{user}/public_html/{path}"]

def edited(argv, change):
    calls, hits = json.loads(json.dumps(FIXTURE["calls"])), 0
    for call in calls:
        if call["argv"] == argv:
            call["stdout"], hits = change(call["stdout"]), hits + 1
    assert hits, f"the fixture has no call {argv}"
    return calls

def handler(text, name="lsapi"):
    data = json.loads(text)
    for row in data["data"]["version_handlers"]:
        if row["version"] == "ea-php82":
            row["current_handler"] = name
    return json.dumps(data)

SCENARIOS = {
    "untranslatable-directive": edited(read("olscpb", ".htaccess"), lambda s: 'SetEnvIf Request_URI "." X=1\n' + s),
    "unsupported-php-handler": edited(["/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_handlers"], handler),
    "dso-held": edited(["/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_handlers"], lambda s: handler(s, "dso")),
    "nested-docroot": edited(read("olscpa", "secure/.htaccess"), lambda s: s + "Action x /cgi-bin/x\n"),
}

def failing(argv):
    calls, hits = json.loads(json.dumps(FIXTURE["calls"])), 0
    for call in calls:
        if call["argv"] == argv:
            call["exit_code"], call["stdout"], hits = 1, "", hits + 1
    assert hits, f"the fixture has no call {argv}"
    return calls

# HR-D14: one account's read failure moves only that vhost to Apache (fail safe), never refuses the whole server.
SCENARIOS["htaccess-unreadable"] = failing(read("olscpb", "sub-noindex/.htaccess"))
SCENARIOS["fpm-pool-unreadable"] = failing(["/usr/bin/cat", "/opt/cpanel/ea-php83/root/etc/php-fpm.d/blog.olstest1.example.test.conf"])

# LSCache (FV-01): tenant A's site carries the LiteSpeed Cache for WordPress section (native, translated) while
# tenant B is hybrid (its pass-through vhosts never use the cache).
LSCWP = (ROOT / "tests/Fixtures/lscwp-htaccess.txt").read_text()
SCENARIOS["lscache-plugin"] = edited(read("olscpb", ".htaccess"), lambda s: 'SetEnvIf Request_URI "." X=1\n' + s)
for call in SCENARIOS["lscache-plugin"]:
    if call["argv"] == read("olscpa", ".htaccess"):
        call["stdout"] = LSCWP + call["stdout"]

def compile_reference(calls):
    results = {}
    for call in calls:
        results.setdefault(json.dumps(call["argv"]), {"exit_code": call["exit_code"], "stdout": call["stdout"], "stderr": ""})

    def step(name, command, limit=300):
        return results[json.dumps(command)]

    summary = {}
    compiled = iso.compile_lab(step, summary, production=True, hybrid_ports=(81, 444))
    return {"production": True, "hybrid_ports": [81, 444], "calls": calls, "summary": summary,
            "compiled": {"config": compiled["config"], "vhconf": compiled["vhconf"]}}

scenarios = {label: compile_reference(calls) for label, calls in SCENARIOS.items()}
# mod_php runs tenant code as the OLS user: such a vhost is held (here: no earlier generation, so it stays served by
# Apache as before) and is never a reason to refuse the other sites (HR-D14, review RV-28).
held = scenarios["dso-held"]["summary"]
assert list(held["held_vhosts"]) == [B] and held["held_vhosts"][B][0] == "PHP handler dso on a site that needs Apache"
assert held["hybrid_vhosts"] == [B] and B in scenarios["dso-held"]["compiled"]["vhconf"]
assert "olstest1.example.test" in scenarios["dso-held"]["compiled"]["vhconf"]
assert scenarios["untranslatable-directive"]["summary"]["hybrid_vhosts"] == [B]
assert scenarios["unsupported-php-handler"]["summary"]["hybrid_vhosts"] == [B]
assert scenarios["htaccess-unreadable"]["summary"]["hybrid_vhosts"] == [B]
assert any("unreadable" in r for r in scenarios["htaccess-unreadable"]["summary"]["htaccess_blockers"][B])
assert scenarios["fpm-pool-unreadable"]["summary"]["hybrid_vhosts"] == ["blog.olstest1.example.test"]
assert scenarios["fpm-pool-unreadable"]["summary"]["hybrid_reasons"] == {"blog.olstest1.example.test": ["PHP-FPM pool unreadable"]}
assert scenarios["nested-docroot"]["summary"]["hybrid_vhosts"] == ["olstest1.example.test", "secure.olstest1.example.test"]
for scenario in scenarios.values():
    for name in scenario["summary"]["hybrid_vhosts"]:
        plain, secure = scenario["compiled"]["vhconf"][name], scenario["compiled"]["vhconf"]["tls." + name]
        for text, scheme in ((plain, "ws://"), (secure, "wss://")):
            assert "lsapi:" not in text and "[P,L]" in text and "acme-challenge" in text and scheme in text
        assert "vhssl" not in plain and "apache-https-" not in plain and "apache-http-" + name not in secure
        config = scenario["compiled"]["config"]
        assert f"virtualHost tls.{name} {{" in config and f"map                  tls.{name} {name}" in config
lscache = scenarios["lscache-plugin"]
A = "olstest1.example.test"
assert lscache["summary"]["hybrid_vhosts"] == [B] and lscache["summary"]["htaccess_blockers"][A] == []
assert "RewriteRule .* - [E=Cache-Control:no-autoflush]" in lscache["compiled"]["vhconf"][A]
assert "ls_enabled           1" in lscache["compiled"]["vhconf"][A] and lscache["summary"]["cache"][A]["enabled"] is True
for name in (B, "tls." + B):
    assert lscache["compiled"]["vhconf"][name].endswith("module cache {\n    ls_enabled           0\n}\n"), name
assert lscache["summary"]["cache"][B] == {"enabled": False, "storage": None}
with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
    json.dump(scenarios, handle)
    handle.flush()
    result = subprocess.run([PHP, "-n", str(ROOT / "tests/compile_replay.php"), handle.name], capture_output=True, text=True)
print(result.stdout.splitlines()[-1] if result.returncode == 0 else result.stdout[-2000:] + result.stderr[-2000:])
sys.exit(result.returncode)
