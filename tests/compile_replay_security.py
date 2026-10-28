#!/usr/bin/python3
"""FV-02 compile equivalence: the lab compiler (reference) compiles the recorded lab inputs plus cPanel ModSecurity
states (the lab's own files and the synthetic vendor set in tests/Fixtures/modsec/) with a product security input,
and the product ServerConfigurationBuilder must produce byte-identical output, or the same refusal
(tests/compile_replay.php with a scenario file). Recorded inputs are never edited on disk: new reads are answered
from the scenario's own files, edited userdata only in memory."""
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import cpanel_surface as cs
import modsec_translate as mt
import tenant_isolation_probe as iso

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
FIXTURE = json.loads((ROOT / "tests/Fixtures/lab-snapshot/compile-production.json").read_text())
FIX = ROOT / "tests/Fixtures/modsec"
A, B = "olstest1.example.test", "olstest2.example.test"
VENDOR = {mt.VENDOR_DIR + "OWASP3/" + str(p.relative_to(FIX / "OWASP3")): p.read_text()
          for p in sorted((FIX / "OWASP3").rglob("*")) if p.is_file()}

def files(cpanel="modsec2.cpanel.vendor.conf", user="", present=True, **extra):
    if not present:
        return {}
    out = {mt.MODSEC2_CONF: (FIX / "modsec2.conf").read_text(), mt.MODULE_CONF: "LoadModule",
           mt.USER_CONF: user, mt.CPANEL_CONF: (FIX / cpanel).read_text(), **VENDOR}
    out.update(extra)
    return out

def userdata(text):
    return text + "secruleengineoff: 1\n"

def edited_calls(changes):
    calls = json.loads(json.dumps(FIXTURE["calls"]))
    for argv, change in changes:
        hits = [c for c in calls if c["argv"] == argv]
        assert hits, f"the fixture has no call {argv}"
        for call in hits:
            call["stdout"] = change(call["stdout"])
    return calls

def handler(text):
    data = json.loads(text)
    for row in data["data"]["version_handlers"]:
        if row["version"] == "ea-php82":
            row["current_handler"] = "lsapi"
    return json.dumps(data)

SECURITY = {"per_client": {"staticReqPerSec": 40, "dynReqPerSec": 4, "softLimit": 30, "hardLimit": 60, "gracePeriod": 10,
                           "banPeriod": 120},
            "ip_allow": ["203.0.113.7"], "ip_block": ["198.51.100.0/24"],
            "exceptions": [{"vhost": "blog." + A, "rule_ids": [941100], "reason": "editor posts markup", "approver": "root"}]}
B_USERDATA = ["/usr/bin/cat", f"/var/cpanel/userdata/olscpb/{B}"]
HANDLERS = ["/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_handlers"]
SCENARIOS = {
    "lab-modsecurity": dict(files=files("modsec2.cpanel.lab.conf"), security={}),
    "absent": dict(files=files(present=False), security={"per_client": {"hardLimit": 100}}),
    "vendor": dict(files=files(), security=SECURITY, changes=[(B_USERDATA, userdata)]),
    "vendor-hybrid": dict(files=files(), security={}, changes=[(HANDLERS, handler)], hybrid_ports=[81, 444]),
    "refused-directive": dict(files=files(user="SecServerSignature Apache\n"), security={}),
    "refused-weaker": dict(files=files(user="SecRequestBodyAccess On\n"), security={}),
    "accepted-weaker": dict(files=files(user="SecRequestBodyAccess On\n"),
                            security={"accept_differences": ["oversized-request-body"]}),
    "refused-unreadable": dict(files=files(**{mt.CPANEL_CONF: False}), security={}),
    "refused-exception": dict(files=files(), security={"exceptions": [{"vhost": "nowhere.test", "engine": "off", "reason": "x"}]}),
}

def compile_reference(scenario):
    calls = edited_calls(scenario.get("changes", []))
    recorded = {json.dumps(c["argv"]): c for c in calls}
    used = []

    def step(name, command, limit=300):
        key = json.dumps(command)
        if key in recorded:
            call = recorded[key]
            return {"exit_code": call["exit_code"], "stdout": call["stdout"], "stderr": ""}
        path = command[-1]
        assert path.startswith("/etc/apache2/conf"), command  # only the WAF part may read anything new
        present = scenario["files"].get(path) is not None
        if command[0] == "/usr/bin/test":
            result = {"exit_code": 0 if present else 1, "stdout": ""}
        elif present and scenario["files"][path] is not False:
            result = {"exit_code": 0, "stdout": scenario["files"][path]}
        else:
            result = {"exit_code": 1, "stdout": ""}
        if key not in [json.dumps(u["argv"]) for u in used]:
            used.append({"name": name, "argv": command, **result})
        return dict(result, stderr="")

    summary = {}
    ports = tuple(scenario["hybrid_ports"]) if scenario.get("hybrid_ports") else None
    out = {"production": True, "hybrid_ports": scenario.get("hybrid_ports"), "security": scenario["security"]}
    try:
        compiled = iso.compile_lab(step, summary, production=True, hybrid_ports=ports, security=scenario["security"])
    except ValueError as error:
        return dict(out, calls=calls + used, refused=str(error), new_calls=used)
    return dict(out, calls=calls + used, summary=summary, compiled={"config": compiled["config"], "vhconf": compiled["vhconf"]},
                new_calls=used)

results = {label: compile_reference(s) for label, s in SCENARIOS.items()}
lab = results["lab-modsecurity"]
recorded = FIXTURE["compiled"]
# The lab's own state: the recorded configuration plus the server module block; the proxy and service vhosts run
# with the engine off (cPanel's <Proxy>/<ProxyMatch>), tenant vhosts unchanged.
assert lab["compiled"]["config"].startswith(recorded["config"]) and lab["compiled"]["config"].endswith("}\n")
assert "module mod_security {\n    ls_enabled           1\n" in lab["compiled"]["config"][len(recorded["config"]):]
off = mt.vhost_block(True, [])
for name, text in recorded["vhconf"].items():
    want = text + off if name == cs.PROXY_VHOST or name.startswith("svc.") else text
    assert lab["compiled"]["vhconf"][name] == want, name
assert [c["argv"] for c in lab["new_calls"]] == [["/usr/bin/test", "-e", mt.MODSEC2_CONF], ["/usr/bin/test", "-e", mt.MODULE_CONF],
                                                 ["/usr/bin/cat", mt.MODSEC2_CONF], ["/usr/bin/cat", mt.USER_CONF],
                                                 ["/usr/bin/cat", mt.CPANEL_CONF]]
absent = results["absent"]
assert absent["summary"]["waf"] == {"state": "absent"} and "module mod_security" not in absent["compiled"]["config"]
assert "perClientConnLimit {\n    hardLimit            100\n}\n" in absent["compiled"]["config"]
assert absent["compiled"]["vhconf"] == recorded["vhconf"]
vendor = results["vendor"]
assert vendor["compiled"]["vhconf"][B].endswith(off) and vendor["compiled"]["vhconf"][A] == recorded["vhconf"][A]
assert vendor["compiled"]["vhconf"]["blog." + A].endswith("`SecRuleRemoveById 941100`\n}\n")
assert "allow                ALL, 203.0.113.7T\n    deny                 198.51.100.0/24\n}\nperClientConnLimit {\n" in vendor["compiled"]["config"]
assert vendor["summary"]["waf"]["rules"] == 8 and len(vendor["summary"]["waf"]["rule_files"]) == 4
hybrid = results["vendor-hybrid"]
assert hybrid["summary"]["hybrid_vhosts"] == [B]
assert hybrid["compiled"]["vhconf"][B].endswith(off) and hybrid["compiled"]["vhconf"]["tls." + B].endswith(off)
for label, text in (("refused-directive", "SecServerSignature is refused"), ("refused-weaker", "oversized-request-body not accepted"),
                    ("refused-unreadable", "unable to read " + mt.CPANEL_CONF), ("refused-exception", "not a cPanel vhost")):
    assert text in results[label].get("refused", ""), (label, results[label].get("refused"))
assert "refused" not in results["accepted-weaker"]
for result in results.values():
    del result["new_calls"]
with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
    json.dump(results, handle)
    handle.flush()
    run = subprocess.run([PHP, "-n", str(ROOT / "tests/compile_replay.php"), handle.name], capture_output=True, text=True)
print(run.stdout.splitlines()[-1] if run.returncode == 0 else run.stdout[-3000:] + run.stderr[-3000:])
sys.exit(run.returncode)
