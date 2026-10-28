#!/usr/bin/python3
"""FV-02: the lab reference (build/vm-qualification/modsec_translate.py) checked on its own, then the PHP port
(ModSecurityRules, SecurityTranslator, ModSecurityAuditLog) checked against it byte for byte on the same corpus:
rule files, cPanel ModSecurity states, security inputs, server access lists and audit logs."""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import cpanel_surface as cs
import modsec_translate as mt

PHP = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php"
FIX = ROOT / "tests/Fixtures/modsec"
V = mt.VENDOR_DIR + "OWASP3/"
VENDOR = {V + str(p.relative_to(FIX / "OWASP3")): p.read_text() for p in sorted((FIX / "OWASP3").rglob("*")) if p.is_file()}
MODSEC2 = (FIX / "modsec2.conf").read_text()
LAB_CPANEL = (FIX / "modsec2.cpanel.lab.conf").read_text()
VENDOR_CPANEL = (FIX / "modsec2.cpanel.vendor.conf").read_text()
TEMPLATE = (ROOT / "build/vm-qualification/ols-lab/ownership_httpd_config.conf").read_text()

def state(user="", cpanel=VENDOR_CPANEL, modsec2=MODSEC2, vendor=None, module=True, **extra):
    files = {mt.MODSEC2_CONF: modsec2, mt.MODULE_CONF: "LoadModule" if module else None, mt.USER_CONF: user, mt.CPANEL_CONF: cpanel}
    files.update(VENDOR if vendor is None else vendor)
    files.update(extra.get("files", {}))
    return files

PLAN = {"a.test": {"mode": "native", "service_domains": ["a.test"]}, "blog.a.test": {"mode": "native", "service_domains": []},
        "b.test": {"mode": "native", "service_domains": ["b.test"]}, "h.test": {"mode": "apache", "service_domains": ["h.test"]}}
VHOSTS = ["a.test", "blog.a.test", "b.test", "h.test", "tls.h.test", "svc.a.test", "svc.b.test", "svc.h.test", cs.PROXY_VHOST,
          cs.DEFAULT_VHOST]
USERDATA = {"a.test": "servername: a.test\n", "blog.a.test": "secruleengineoff: 1\r\n", "b.test": "secruleengineoff: '0'\n",
            "h.test": "secruleengineoff: 1\n"}
SECURITY = {"per_client": {"staticReqPerSec": 50, "dynReqPerSec": 5, "outBandwidth": 0, "softLimit": 20, "hardLimit": 40,
                           "gracePeriod": 15, "banPeriod": 300},
            "ip_allow": ["203.0.113.5", "2001:DB8::/32"], "ip_block": ["198.51.100.0/24", "2001:db9::1"],
            "evaluated_at": 1800000000,
            "exceptions": [{"vhost": "a.test", "rule_ids": [942100, 941100, 942100], "reason": "search form", "approver": "admin"},
                           {"vhost": "b.test", "engine": "off", "reason": "migration window", "expires": 1900000000},
                           {"vhost": "b.test", "rule_ids": [1], "reason": "expired one", "expires": 1700000000}]}
USER_RULES = ('SecRule REQUEST_URI "@contains /blocked-by-user-conf" "id:1000001,phase:1,deny,status:403,log,'
              "msg:'Local rule'\"\n")
REQUEST_BODY = "SecRequestBodyAccess On\nSecRequestBodyLimit 13107200\n"
CASES = {
    "absent": dict(files=state(module=False, modsec2=None, cpanel=None, user=None),
                   security={k: v for k, v in SECURITY.items() if k != "exceptions"}),
    "absent-with-exceptions": dict(files=state(module=False, modsec2=None, cpanel=None, user=None),
                                   security={"exceptions": [{"vhost": "a.test", "engine": "off", "reason": "x"}]}),
    "half-installed": dict(files=state(module=False), security={}),
    "lab": dict(files=state(cpanel=LAB_CPANEL, vendor={}), security={}),
    "vendor": dict(files=state(), security=SECURITY),
    "vendor-user-rules": dict(files=state(user=USER_RULES), security={}),
    "weaker-refused": dict(files=state(user=REQUEST_BODY), security={}),
    "weaker-accepted": dict(files=state(user=REQUEST_BODY), security={"accept_differences": ["oversized-request-body"]}),
    # A phase-2 rule governed by cPanel's "deny,status:406" ahead of the vendor's "pass": libmodsecurity 3 would
    # apply both defaults to every phase-2 rule.
    "default-conflict": dict(files=state(user='SecRule ARGS "@rx x" "id:1000002,phase:2,block,log"\n'), security={}),
    "engine-default-off": dict(files=state(cpanel=LAB_CPANEL.replace('SecRuleEngine "On"\n', ""), vendor={}), security={}),
    "engine-detection": dict(files=state(user="SecRuleEngine DetectionOnly\n", cpanel=LAB_CPANEL, vendor={}), security={}),
    "unreadable-vendor": dict(files=state(files={V + "rules/REQUEST-949-BLOCKING-EVALUATION.conf": False}), security={}),
    "unreadable-user": dict(files=state(user=False), security={}),
    "missing-data": dict(files=state(files={V + "rules/scanners-user-agents.data": None}), security={}),
    "cpanel-unexpected": dict(files=state(cpanel=VENDOR_CPANEL + "SecRule ARGS x \"id:5\"\n"), security={}),
    "cpanel-foreign-include": dict(files=state(cpanel=VENDOR_CPANEL.replace(V + "crs-setup.conf", "/etc/passwd.conf")), security={}),
    "cpanel-guardian": dict(files=state(cpanel=VENDOR_CPANEL.replace('SecAuditEngine "RelevantOnly"', 'SecGuardianLog "|/bin/x"')),
                            security={}),
    "cpanel-unsafe-value": dict(files=state(cpanel=VENDOR_CPANEL.replace('"RelevantOnly"', '"Relevant Only"')), security={}),
    "cpanel-connengine-off": dict(files=state(cpanel=VENDOR_CPANEL.replace('SecAuditEngine "RelevantOnly"', 'SecConnEngine "Off"')),
                                  security={}),
    "modsec2-extra-include": dict(files=state(modsec2=MODSEC2.replace("    Include /etc/apache2/conf.d/modsec/modsec2.cpanel.conf\n", "")),
                                  security={}),
    "modsec2-unknown": dict(files=state(modsec2=MODSEC2.replace("SecDebugLogLevel 0", "SecServerSignature x")), security={}),
    "modsec2-outside": dict(files=state(modsec2="SecRuleEngine On\n" + MODSEC2), security={}),
    "userdata-bad": dict(files=state(), security={}, userdata=dict(USERDATA, **{"a.test": "secruleengineoff: maybe\n"})),
    "unknown-exception-vhost": dict(files=state(), security={"exceptions": [{"vhost": "zz.test", "engine": "off", "reason": "x"}]}),
    "hybrid-exception": dict(files=state(), security={"exceptions": [{"vhost": "h.test", "engine": "off", "reason": "x"}]}),
    "removal-before-rule": dict(files=state(user="SecRuleRemoveById 941100\n"), security={}),
    "removal-range-before-rule": dict(files=state(user="SecRuleRemoveById 941000-941999\n"), security={}),
    "tag-before-rule": dict(files=state(user="SecRuleRemoveByTag attack-xss\n"), security={}),
}
CHECKER = [
    [("/u.conf", "\n".join([
        "<LocationMatch x>", "SecServerSignature x", "SecRuleScript /x.lua", "SecConnEngine On", "SecConnEngine Off", "SecFoo bar",
        'SecRule NOPE "@rx x" "id:1"', 'SecRule ARGS "@fooBar x" "id:2"', 'SecRule ARGS "@inspectFile /x" "id:3"',
        'SecRule ARGS "@rx x" "id:4,pause:10"', 'SecRule ARGS "@rx x" "id:5,t:magic"', 'SecRule ARGS "@rx x" "id:6,ctl:debugLogLevel=9"',
        'SecRule ARGS "@rx x" "id:7,ctl:requestBodyProcessor=MULTIPART"', 'SecRule ARGS "@rx x" "phase:2,deny"',
        'SecRule ARGS "@rx x" "id:8"', 'SecRule ARGS "@rx x" "id:8"', 'SecRule ARGS "@rx x" "id:9,phase:9"',
        'SecDefaultAction "phase:2,deny,id:1"', 'SecDefaultAction "deny"', 'SecRuleRemoveByTag "attack-.*"',
        'SecRule ARGS "@pmFromFile ../x.data" "id:10"', 'SecRule ARGS "@rx x" "id:11', "# comment \\", "continued",
        'SecRule ARGS "@rx x" "id:12,sanitiseArg:password"', 'SecRule ARGS "@rx x" "id:13,exec:/x.lua"', "SecArgumentSeparator ab",
        "SecCookieFormat 1", "Include /x.conf", "SecRuleEngine Maybe", 'SecRule ARGS "@rx x" "id:14,chain"',
        'SecRule ARGS "@rx x" "id:15"', 'SecRule ARGS "@pmf http://x/y" "id:16"', "SecUploadKeepFiles RelevantOnly",
        "SecDataDir /tmp", "SecAuditLog /tmp/x", "SecRuleRemoveById 1-x 9-3", "SecRuleUpdateTargetById 8 !ARGS:x",
        "SecRuleUpdateActionById 8 \"pause:1\"", 'SecRule ARGS|"x" "@rx x" "id:17"', 'SecRule ARGS:/a|b "@rx x" "id:18"',
        "SecRuleRemoveByMsg x", 'SecAction "id:19,phase:1,pass,initcol:ip=%{remote_addr},deprecatevar:ip.x=1/10"',
        'SecRule ARGS "@rx x" "id:20,phase:2,pass,chain"']) + "\n")],
    [("/v/a.conf", 'SecDefaultAction "phase:2,log,pass"\nSecDefaultAction "phase:2,log,deny"\n'
                   'SecRule ARGS "@rx x" "id:1,phase:2,block"\nSecRule XML:/* "@rx x" "id:2,phase:response,block"\n'
                   "SecRule &TX:x|!REQUEST_COOKIES:/__utm|_ga/|REQUEST_HEADERS:'User-Agent' \"@eq 0\" \"id:3,phase:'1',pass,"
                   "tag:'a-b',tag:x\"\n"),
     ("/v/b.conf", "SecRuleRemoveByTag a\nSecRuleUpdateTargetByTag x ARGS:y\nSecRuleRemoveById 1 3\n"
                   'SecRule ARGS "@rx x" "id:4,phase:2,block,tag:a"\n')],
    [("/e.conf", "")],
]
POLICY_PLAN = {"a.test": {"mode": "native"}, "h.test": {"mode": "apache"}}
POLICY = [{}, None, [1], {"x": 1}, {"evaluated_at": -1}, {"evaluated_at": True}, {"per_client": {}}, {"per_client": None},
          {"per_client": {"dynReqPerSec": 1.5}}, {"per_client": {"gracePeriod": 3601}}, {"per_client": {"softLimit": 9, "hardLimit": 3}},
          {"per_client": {"banPeriod": 1, "staticReqPerSec": 0}}, {"per_client": {"nope": 1}},
          {"ip_allow": None}, {"ip_allow": ["1.2.3.4", "1.2.3.4"]}, {"ip_allow": ["010.0.0.1"]}, {"ip_allow": ["10.0.0.1/8"]},
          {"ip_allow": ["0.0.0.0/0"]}, {"ip_block": ["127.0.0.1"]}, {"ip_block": ["::1"]}, {"ip_block": ["120.0.0.0/4"]},
          {"ip_allow": ["127.0.0.1"]}, {"ip_allow": ["::ffff:1.2.3.4"]}, {"ip_allow": ["1.2.3.4/033"]}, {"ip_allow": ["1.2.3.4/33"]},
          {"ip_allow": ["2001:DB8:0:0:1::/80", "1:0:0:0:0:0:0:8", "fe80::/10", "10.1.2.3/32"]}, {"ip_allow": [5]},
          {"ip_allow": ["1.2.3.4"], "ip_block": ["1.2.3.4"]}, {"ip_block": ["1.2.3.4 "]}, {"ip_block": ["1.2.3.4\n"]},
          {"accept_differences": ["oversized-request-body", "oversized-request-body"]}, {"accept_differences": ["x"]},
          {"accept_differences": ["oversized-response-body", "oversized-request-body"]}, {"accept_differences": None},
          {"exceptions": None}, {"exceptions": [{}]}, {"exceptions": [{"vhost": "a.test", "engine": "off"}]},
          {"exceptions": [{"vhost": "a.test", "engine": "on", "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "engine": "off", "rule_ids": [1], "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [], "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [0], "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [True], "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [3, 1, 3], "reason": "r\n"}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [3, 1, 3], "reason": "r", "approver": ""}]},
          {"exceptions": [{"vhost": "a.test", "rule_ids": [3, 1, 3], "reason": "r", "expires": 5}]},
          {"evaluated_at": 10, "exceptions": [{"vhost": "a.test", "rule_ids": [3, 1, 3], "reason": "r", "expires": 5},
                                              {"vhost": "a.test", "engine": "off", "reason": "s", "expires": 11, "approver": "ops"}]},
          {"exceptions": [{"vhost": "h.test", "engine": "off", "reason": "r"}]}, {"exceptions": [{"vhost": "zz.test", "engine": "off", "reason": "r"}]},
          {"exceptions": [{"vhost": "a.test", "engine": "off", "reason": "r", "extra": 1}]}]
PRODUCTION_HEAD = TEMPLATE[:TEMPLATE.index("extProcessor ea-php83 {")]
LAB_HEAD = PRODUCTION_HEAD.replace("accessControl {\n    allow                ALL\n}\n",
                                   "accessControl {\n    allow                127.0.0.1, 10.250.0.2\n    deny                 ALL\n}\n")
def compiled(allow=(), block=(), per_client="", server=""):
    return {"ip_allow": list(allow), "ip_block": list(block), "per_client": per_client, "server": server}
APPLY = [{"config": PRODUCTION_HEAD, "compiled": compiled()},
         {"config": PRODUCTION_HEAD, "compiled": compiled(["203.0.113.5"], ["198.51.100.0/24"], "perClientConnLimit {\n}\n", "module x\n")},
         {"config": LAB_HEAD, "compiled": compiled(["10.250.0.2"], [])},
         {"config": LAB_HEAD, "compiled": compiled([], ["10.250.0.2"])},
         {"config": LAB_HEAD.replace("127.0.0.1, ", ""), "compiled": compiled([], ["10.250.0.2"])},
         {"config": "x\n", "compiled": compiled()},
         {"config": PRODUCTION_HEAD + PRODUCTION_HEAD, "compiled": compiled()},
         {"config": PRODUCTION_HEAD.replace("    allow                ALL\n", "    allow                ALL\n    allow                x\n"),
          "compiled": compiled()},
         {"config": PRODUCTION_HEAD.replace("    allow                ALL\n", "    trust                x\n"), "compiled": compiled()},
         {"config": PRODUCTION_HEAD + "perClientConnLimit {\n}\n", "compiled": compiled()}]
AUDIT_TEXT = (FIX / "audit-serial.log").read_bytes()
EDGE = (b"---abcdefgh---A--\n[01/Jan/1969:00:00:00 +0000] 1 10.0.0.1 1 10.0.0.2 80\n---abcdefgh---H--\n"
        b"ModSecurity: Warning. [id \"1\"] [msg \"old\"]\n---abcdefgh---Z--\n"
        b"---ijklmnop---A--\n[01/Jan/1970:00:30:00 +0100] 1 ::1.2.3.4 1 10.0.0.2 80\n---ijklmnop---H--\nModSecurity: Warning. [id \"2\"]\n"
        b"---ijklmnop---Z--\n---qrstuvwx---A--\n[29/Feb/2028:23:59:59 -2359] 1 2001:DB8:0::1 1 10.0.0.2 80\n---qrstuvwx---B--\n"
        b"GET /\xc3\xa9\xff" + b"x" * 20000 + b" HTTP/1.1\nHost: \xe2\x84\xaaelvin.example\n---qrstuvwx---H--\n"
        b"ModSecurity: Access denied with code 999 (phase 2). [id \"12345678901\"] [msg \"\xff\x01" + b"m" * 600 + b"\"]\n"
        b"---qrstuvwx---Z--\n---zzzzzzzz---A--\n[01/Jan/2026:00:00:00 +0000] 1 10.0.0.3 1 10.0.0.2 80\n---yyyyyyyy---Z--\n"
        b"---zzzzzzzz---Z--\n")
AUDIT = [{"text": AUDIT_TEXT, "limit": 200}, {"text": AUDIT_TEXT, "limit": 1}, {"text": AUDIT_TEXT, "limit": 0},
         {"text": EDGE, "limit": 50}, {"text": b"", "limit": 5}, {"text": AUDIT_TEXT * 3, "limit": 4}]
USERDATA_CASES = ["", "secruleengineoff: 1\n", "secruleengineoff: \"0\"\n", "secruleengineoff:\n", "secruleengineoff: 2\n",
                  "secruleengineoff: 1\nsecruleengineoff: 1\n", " secruleengineoff: 1\n", "secruleengineoff: 1\r\n"]

def python_results():
    out = {"checker": [], "states": [], "policy": [], "apply": [], "audit": [], "userdata": []}
    for files in CHECKER:
        checker = mt.RuleChecker()
        for path, text in files:
            checker.check_file(path, text, path.rsplit("/", 1)[0])
        checker.finish()
        out["checker"].append({"blockers": checker.blockers, "differences": checker.differences, "rules": checker.rules,
                               "data_files": checker.data_files,
                               "defaults": [[d["phase"], d["norm"], d["emit"]] for d in checker.defaults]})
    for case in CASES.values():
        calls = []

        def read(name, argv, files=case["files"]):
            calls.append([name, argv])
            path = argv[-1]
            present = files.get(path) is not None
            if argv[0] == "/usr/bin/test":
                return {"exit_code": 0 if present else 1, "stdout": ""}
            return {"exit_code": 0, "stdout": files[path]} if present and files[path] is not False else {"exit_code": 1, "stdout": ""}
        try:
            result = mt.compile_security(read, PLAN, case.get("userdata", USERDATA), case["security"], VHOSTS, cs.PROXY_VHOST,
                                         cs.service_vhost_name, cs.hybrid_tls_name)
            out["states"].append({k: result[k] for k in ("server", "per_client", "ip_allow", "ip_block", "vhosts", "summary")}
                                 | {"calls": calls, "applied": mt.apply_server(PRODUCTION_HEAD, result)})
        except ValueError as error:
            out["states"].append({"error": str(error), "calls": calls})
    for security in POLICY:
        try:
            out["policy"].append(mt.policy(security, POLICY_PLAN))
        except ValueError as error:
            out["policy"].append("error: " + str(error))
    for case in APPLY:
        try:
            out["apply"].append(mt.apply_server(case["config"], case["compiled"]))
        except ValueError as error:
            out["apply"].append("error: " + str(error))
    out["audit"] = [mt.parse_audit_log(case["text"], max(case["limit"], 1)) for case in AUDIT]
    for text in USERDATA_CASES:
        try:
            out["userdata"].append(mt.userdata_engine_off(text, "x.test"))
        except ValueError as error:
            out["userdata"].append("error: " + str(error))
    return out

python = python_results()
states = dict(zip(CASES, python["states"]))
def error(name):
    return states[name].get("error", "")

# The reference itself: what each case must do (independent of the port).
assert states["absent"]["summary"]["waf"] == {"state": "absent"} and states["absent"]["server"] == ""
assert states["absent"]["calls"] == [["modsec-present", ["/usr/bin/test", "-e", p]] for p in (mt.MODSEC2_CONF, mt.MODULE_CONF)]
assert "perClientConnLimit {\n    staticReqPerSec      50\n" in states["absent"]["applied"]
assert error("absent-with-exceptions") == "ModSecurity exceptions without ModSecurity"
assert error("half-installed").startswith("ModSecurity is half installed")
lab = states["lab"]
assert lab["server"] == ("module mod_security {\n    ls_enabled           1\n    modsecurity          on\n"
                         "    modsecurity_rules    `SecRequestBodyLimitAction ProcessPartial`\n"
                         "    modsecurity_rules    `SecAuditEngine RelevantOnly`\n    modsecurity_rules    `SecRuleEngine On`\n"
                         f"    modsecurity_rules    `SecAuditLog {mt.AUDIT_LOG}`\n    modsecurity_rules    `SecAuditLogType Serial`\n"
                         "    modsecurity_rules    `SecAuditLogParts ABFHZ`\n    modsecurity_rules    `SecAuditLogFileMode 0600`\n}\n"), lab["server"]
assert lab["summary"]["waf"]["rules"] == 0 and lab["summary"]["waf"]["rule_files"] == []
assert {d["code"] for d in lab["summary"]["waf"]["differences"]} == {"product-audit-log", "ignored-secdatadir", "superseded-default-action"}
vendor = states["vendor"]
assert vendor["server"].count("modsecurity_rules_file") == 4 and "SecDefaultAction" not in vendor["server"]
assert vendor["server"].index("crs-setup.conf") < vendor["server"].index("REQUEST-901") < vendor["server"].index("SecRuleRemoveById 941110")
assert vendor["vhosts"] == {"a.test": "module mod_security {\n    modsecurity_rules    `SecRuleRemoveById 941100 942100`\n}\n",
                            **{v: mt.vhost_block(True, []) for v in ("blog.a.test", "b.test", "h.test", "tls.h.test", "svc.a.test",
                                                                     "svc.b.test", cs.PROXY_VHOST)}}, vendor["vhosts"]
assert "svc.h.test" not in vendor["vhosts"] and cs.DEFAULT_VHOST not in vendor["vhosts"]
assert vendor["summary"]["security"]["expired_exceptions"] == [{"vhost": "b.test", "reason": "expired one"}]
assert vendor["summary"]["security"]["ip_allow"] == ["203.0.113.5", "2001:db8::/32"]
assert vendor["summary"]["waf"]["data_files"] == [V + "rules/scanners-user-agents.data"]
assert "    allow                ALL, 203.0.113.5T, 2001:db8::/32T\n    deny                 198.51.100.0/24, 2001:db9::1\n}\n" \
       "perClientConnLimit {\n" in vendor["applied"] and vendor["applied"].endswith(vendor["server"])
assert "modsecurity_rules_file " + mt.USER_CONF in states["vendor-user-rules"]["server"]
assert "oversized-request-body" in error("weaker-refused") and "not accepted" in error("weaker-refused")
accepted = [d for d in states["weaker-accepted"]["summary"]["waf"]["differences"] if d["weaker"]]
assert accepted and all(d["accepted"] for d in accepted)
assert "different default actions" in error("default-conflict")
assert "`SecRuleEngine Off`" in states["engine-default-off"]["server"].split("\n")[3]
assert states["engine-detection"]["summary"]["waf"]["engine"] == "On"  # cPanel's setting follows the user file
assert error("unreadable-vendor") == f"unable to read {V}rules/REQUEST-949-BLOCKING-EVALUATION.conf"
assert error("unreadable-user") == f"unable to read {mt.USER_CONF}"
assert error("missing-data") == f"unable to read {V}rules/scanners-user-agents.data"
for name, text in (("cpanel-unexpected", "unexpected line in WHM's generated configuration"),
                   ("cpanel-foreign-include", "outside the vendor configurations"), ("cpanel-guardian", "SecGuardianLog has an unsupported value"),
                   ("cpanel-unsafe-value", "SecAuditEngine has an unsupported value"),
                   ("modsec2-extra-include", "must include exactly"), ("modsec2-unknown", "unexpected directive SecServerSignature"),
                   ("modsec2-outside", "directive outside"), ("userdata-bad", "unreadable secruleengineoff"),
                   ("unknown-exception-vhost", "not a cPanel vhost"), ("hybrid-exception", "Apache serves (hybrid)"),
                   ("removal-before-rule", "modifies rule 941100, which is loaded later"),
                   ("removal-range-before-rule", "modifies rule 941100, which is loaded later"),
                   ("tag-before-rule", "modifies rule 941100, which is loaded later")):
    assert text in error(name), (name, error(name))
assert "SecConnEngine Off" in states["cpanel-connengine-off"]["server"]
blockers = python["checker"][0]["blockers"]
for text in ("Apache configuration sections", "SecServerSignature is refused", "SecRuleScript is not qualified",
             "SecConnEngine is supported by libmodsecurity 3 only with Off", "unknown directive SecFoo",
             "unknown or unreadable SecRule targets", "unknown operator @fooBar", "operator @inspectFile is not qualified",
             "action pause is refused", "unknown transformation", "ctl option is not supported",
             "request body processor is not supported", "rule without a numeric id", "rule id 8 is already defined",
             "unknown phase", "SecDefaultAction holds actions", "SecDefaultAction needs a phase", "matches tags by regular expression",
             "rule data file ../x.data is outside", "unterminated quote", "comment line ends with a line continuation",
             "action sanitisearg is refused", "action exec is refused", "SecArgumentSeparator must be a single character",
             "SecCookieFormat has an unsupported value", "Include is not qualified", "SecRuleEngine has an unsupported value",
             "a chained rule carries its own id", "rule data from a URL is not qualified", "SecUploadKeepFiles is supported",
             "SecRuleRemoveById has an unreadable rule id", "SecRuleRemoveById has an empty id range", "action pause is refused",
             "SecRuleRemoveByMsg is not qualified", "action deprecatevar is refused", "the last rule announces a chain"):
    assert any(text in b for b in blockers), text
assert "/u.conf:23: unknown directive continued" not in blockers  # a continued comment swallows its next line
assert python["checker"][0]["data_files"] == []
assert {d["code"] for d in python["checker"][0]["differences"]} == {"ignored-secdatadir", "product-audit-log", "persistent-collections"}
second = python["checker"][1]
assert any("SecDefaultAction for one phase twice in one file" in b for b in second["blockers"])
assert any("modifies rule 4, which is loaded later" in b for b in second["blockers"])
assert [r["id"] for r in second["rules"]] == [1, 2, 3, 4] and second["rules"][1]["phase"] == 4 and second["rules"][2]["tags"] == ["a-b", "x"]
assert {d["code"] for d in second["differences"]} == {"tag-match"}
assert python["checker"][2] == {"blockers": [], "differences": [], "rules": [], "data_files": [], "defaults": []}
policy = dict(zip(range(len(POLICY)), python["policy"]))
assert policy[0] == {"per_client": None, "ip_allow": [], "ip_block": [], "accept_differences": [], "exceptions": [], "expired": []}
assert policy[25]["ip_allow"] == ["2001:db8:0:0:1::/80", "1::8", "fe80::/10", "10.1.2.3"], policy[25]
assert policy[45]["exceptions"] == [{"vhost": "a.test", "source": "operator", "engine": "off", "rule_ids": [], "reason": "s"}]
assert policy[45]["expired"] == [{"vhost": "a.test", "reason": "r"}]
assert sum(1 for p in python["policy"] if isinstance(p, str)) == len(POLICY) - 7, [p for p in python["policy"] if not isinstance(p, str)]
assert python["apply"][3].count("10.250.0.2") == 1 and "allow                127.0.0.1\n    deny                 ALL, 10.250.0.2\n" in python["apply"][3]
assert "allow                127.0.0.1, 10.250.0.2T\n" in python["apply"][2]
assert python["apply"][4] == "error: the blocked addresses leave no client allowed"
assert [a.startswith("error:") for a in python["apply"]] == [False] * 4 + [True] * 6
audit = python["audit"]
assert [r["rule_id"] for r in audit[0]["records"]] == [949110, 913100, 1000001] and audit[0]["skipped"] == 4
assert audit[0]["records"][0] == {"time": "2026-10-27T10:35:09Z", "client": "10.250.0.2", "vhost": "olstest1.example.test",
                                  "uri": "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "rule_id": 949110,
                                  "message": "Inbound Anomaly Score Exceeded (Total Score: 5)", "action": "deny"}
assert "secret" not in json.dumps(audit) and "c2VjcmV0" not in json.dumps(audit)
assert audit[1]["records"] == audit[0]["records"][-1:] and len(audit[5]["records"]) == 4
edge = audit[3]["records"]
assert [r["time"] for r in edge] == ["2028-03-01T23:58:59Z"] and edge[0]["client"] == "2001:db8::1" and edge[0]["vhost"] is None
# The request line is cut at 16 KiB, so it has no URI; an 11-digit id is no rule id; the message is bounded.
assert edge[0]["rule_id"] is None and edge[0]["uri"] is None and len(edge[0]["message"]) == 512 and edge[0]["message"].startswith("??m")
assert audit[3]["skipped"] == 4 and audit[4] == {"records": [], "skipped": 0}
assert python["userdata"] == [False, True, False, False, "error: unreadable secruleengineoff in the userdata of x.test",
                              "error: unreadable secruleengineoff in the userdata of x.test", False, True]

# The PHP port on the same corpus.
corpus = {"checker": CHECKER, "states": [{"files": c["files"], "plan": PLAN, "userdata": c.get("userdata", USERDATA),
                                          "security": c["security"], "vhosts": VHOSTS, "template": PRODUCTION_HEAD} for c in CASES.values()],
          "policy": [{"security": s, "plan": POLICY_PLAN} for s in POLICY], "apply": APPLY,
          "audit": [{"text": base64.b64encode(c["text"]).decode(), "limit": max(c["limit"], 1)} for c in AUDIT],
          "userdata": USERDATA_CASES}
with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
    json.dump(corpus, handle)
    handle.flush()
    result = subprocess.run([PHP, "-n", str(ROOT / "tests/modsec_corpus.php"), handle.name], capture_output=True, text=True)
if result.returncode != 0:
    raise SystemExit(result.stdout[-3000:] + result.stderr[-3000:])
php = json.loads(result.stdout)
canonical = lambda value: json.loads(json.dumps(value, sort_keys=True))
for section, left in python.items():
    right = php[section]
    assert len(left) == len(right), section
    for index, (a, b) in enumerate(zip(left, right)):
        if section == "states":
            a = {k: (v if v != {} else []) for k, v in a.items()}
            b = {k: (v if v != {} else []) for k, v in b.items()}
        assert canonical(a) == canonical(b), (section, index, list(CASES)[index] if section == "states" else "", a, b)
print(f"FV-02 translators: lab reference checks and PHP byte-equivalence passed ({len(CHECKER)} rule-file sets, {len(CASES)} cPanel "
      f"ModSecurity states, {len(POLICY)} security inputs, {len(APPLY)} access lists, {len(AUDIT)} audit logs).")
