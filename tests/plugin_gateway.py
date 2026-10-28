#!/usr/bin/python3
"""Offline tests of the WHM gateway (plugins/whm/index.cgi) and the cPanel page's API (plugins/cpanel/index.live.php),
run as CGI requests under cPanel's php-cgi (the interpreter the shebang names). Each entry point runs from a
temporary copy whose lib/BrokerClient.php is a stub that records every call (socket, timeout, operation,
arguments) and answers from a fixture, and whose cPanel library is a stub with the feature switched on or off.
Nothing connects to a broker or to cPanel. Argument: the PHP CLI path of build/check/run.py; php-cgi is taken
from the same directory (the dynamic part is skipped when it is missing)."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PHP = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/local/cpanel/3rdparty/php/84/bin/php")
CGI = PHP.with_name("php-cgi")
DIGEST = "ab" * 32
PLAN = "p20261022120000-a1b2c3"
JOB = "j1761134400-0a1b2c3d"

STUB_CLIENT = r"""<?php
declare(strict_types=1);

namespace OlsCpanel\Broker;

/** Test stub: records the call, answers from the fixture (operation => reply). */
final class BrokerClient
{
    public const ADMIN_SOCKET = '/run/ols-cpanel-broker/admin.sock';
    public const TENANT_SOCKET = '/run/ols-cpanel-broker/tenant.sock';

    public function __construct(private readonly string $socket, private readonly float $timeout = 5.0)
    {
    }

    public function call(string $op, ?array $args = null): array
    {
        file_put_contents((string) getenv('FAKE_BROKER_LOG'), json_encode(['socket' => $this->socket, 'timeout' => $this->timeout,
            'op' => $op, 'args' => $args]) . "\n", FILE_APPEND);
        $replies = json_decode((string) file_get_contents((string) getenv('FAKE_BROKER_REPLIES')), true);
        return $replies[$op] ?? ['ok' => true, 'id' => 'x', 'result' => ['op' => $op]];
    }
}
"""

STUB_CPANEL = r"""<?php
/** Test stub of cPanel's LivePHP library: the feature decision comes from the environment. */
class CPANEL
{
    public function uapi(string $module, string $function, array $args = []): array
    {
        return ['cpanelresult' => ['result' => ['status' => 1, 'data' => getenv('FAKE_FEATURE') === 'on' ? 1 : null]]];
    }

    public function header(string $title): string
    {
        return '';
    }

    public function footer(): string
    {
        return '';
    }

    public function end(): void
    {
    }
}
"""

CPANEL_REQUIRE = "require_once '/usr/local/cpanel/php/cpanel.php';"


def tree(temp, name, entry, rewrite=None):
    root = pathlib.Path(temp, name)
    (root / "lib").mkdir(parents=True)
    text = (ROOT / entry).read_text()
    if rewrite:
        assert text.count(rewrite[0]) == 1, rewrite[0]
        text = text.replace(rewrite[0], rewrite[1])
    script = root / pathlib.Path(entry).name
    script.write_text(text)
    (root / "lib/BrokerClient.php").write_text(STUB_CLIENT)
    shutil.copy(ROOT / "src/Ui/AssetManifest.php", root / "lib/AssetManifest.php")
    shutil.copy(ROOT / "src/Ols/Compiler/HtaccessTranslator.php", root / "lib/HtaccessTranslator.php")
    shutil.copy(ROOT / "src/Ols/Compiler/HtaccessRewrite.php", root / "lib/HtaccessRewrite.php")
    shutil.copy(ROOT / "ui/src/shared/i18n.htaccess.en.json", root / "lib/i18n.htaccess.en.json")
    (root / "cpanel_stub.php").write_text(STUB_CPANEL)
    return script


class Gateway:
    def __init__(self, temp, script):
        self.temp = pathlib.Path(temp)
        self.script = script
        self.log = self.temp / f"{script.parent.name}.log"
        self.replies = self.temp / f"{script.parent.name}.replies.json"
        self.answer({})

    def answer(self, replies):
        self.replies.write_text(json.dumps(replies))

    def request(self, method="GET", query="", body=None, user="root", headers=None, feature="on"):
        """(status, headers, json body or text, broker calls)."""
        self.log.write_text("")
        data = (json.dumps(body) if isinstance(body, (dict, list)) else (body or "")).encode()
        env = {"GATEWAY_INTERFACE": "CGI/1.1", "REQUEST_METHOD": method, "QUERY_STRING": query, "REDIRECT_STATUS": "200",
               "SCRIPT_FILENAME": str(self.script), "SERVER_PROTOCOL": "HTTP/1.1", "FAKE_BROKER_LOG": str(self.log),
               "FAKE_BROKER_REPLIES": str(self.replies), "FAKE_FEATURE": feature, "PATH": "/usr/bin:/bin"}
        if user is not None:
            env["REMOTE_USER"] = user
        if method == "POST":
            env["CONTENT_LENGTH"] = str(len(data))
            env["CONTENT_TYPE"] = "application/json"
        env.update(headers or {})
        result = subprocess.run([str(CGI), "-n", "-d", "display_errors=stderr", str(self.script)], input=data, env=env,
                                capture_output=True, timeout=60)
        assert not result.stderr.strip(), result.stderr.decode()[-2000:]
        head, _, payload = result.stdout.decode().partition("\r\n\r\n")
        header = {}
        for line in head.split("\r\n"):
            key, _, value = line.partition(": ")
            header[key.lower()] = value
        status = int(header.get("status", "200").split()[0])
        try:
            payload = json.loads(payload)
        except ValueError:
            pass
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return status, header, payload, calls


def refused(response, status, code=None):
    got, header, body, calls = response
    assert got == status, (status, response)
    assert calls == [], ("no broker call expected", calls)
    if code:
        assert body["ok"] is False and body["error"]["code"] == code, body
    return body


# Exercise the real scanner with account-local fixture roots, including privacy boundaries.
if PHP.is_file():
    with tempfile.TemporaryDirectory() as scan_temp:
        scan = pathlib.Path(scan_temp)
        script = tree(scan, "scanner", "plugins/cpanel/index.live.php")
        page = script.read_text()
        functions = page[page.index("const SCAN_FILE_LIMIT"):page.index("$cpanel = new CPANEL();")]
        home = scan / "account"
        root = home / "public_html"
        nested = root / "shop"
        nested.mkdir(parents=True)
        (root / ".htaccess").write_text("RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n")
        (nested / ".htaccess").write_text("Header set X-Frame-Options DENY env=example\nphp_value memory_limit 128M\n")
        large = root / "large"
        large.mkdir()
        (large / ".htaccess").write_text("#" * 262145)
        foreign = scan / "other-account"
        foreign.mkdir()
        (foreign / ".htaccess").write_text("private_foreign_directive secret\n")
        (root / "linked").symlink_to(foreign, target_is_directory=True)
        (root / "linked-file").mkdir()
        (root / "linked-file/.htaccess").symlink_to(foreign / ".htaccess")
        domains = [{"type": "main", "docroot": str(root)}, {"type": "sub", "docroot": str(nested)},
                   {"type": "main", "docroot": str(foreign)}]
        runner = script.parent / "scan.php"
        runner.write_text("<?php\nrequire __DIR__ . '/lib/HtaccessTranslator.php';\nrequire __DIR__ . '/lib/HtaccessRewrite.php';\n"
                          "use OlsCpanel\\Ols\\Compiler\\HtaccessRewrite;\nuse OlsCpanel\\Ols\\Compiler\\HtaccessTranslator;\n" + functions +
                          "\necho json_encode(htaccess_report(json_decode($argv[1], true), $argv[2]));\n")
        result = subprocess.run([str(PHP), str(runner), json.dumps(domains), str(home)],
                                capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        assert report["roots"] == 2 and len(report["files"]) == 3, report
        by_path = {f["path"]: f for f in report["files"]}
        translated = by_path["~/public_html/.htaccess"]
        assert translated["outcome"] == "translated" and translated["reasons"] == [] and translated["blockers"] == []
        kept = by_path["~/public_html/shop/.htaccess"]
        assert kept["outcome"] == "kept_on_apache" and kept["docroot"] == "~/public_html/shop"
        catalog = json.loads((ROOT / "ui/src/shared/i18n.htaccess.en.json").read_text())
        assert [r["reason_key"] for r in kept["reasons"]] == ["conditional_header", "directive"], kept
        for file in report["files"]:
            assert len(file["reasons"]) == len(file["blockers"])
            for reason, blocker in zip(file["reasons"], file["blockers"]):
                assert reason["directive"] == blocker and reason["reason"] == catalog[reason["reason_key"]]
        assert by_path["~/public_html/large/.htaccess"]["outcome"] == "kept_on_apache"
        assert by_path["~/public_html/large/.htaccess"]["reasons"][0]["reason_key"] == "unreadable"
        assert "other-account" not in result.stdout and "secret" not in result.stdout and str(home) not in result.stdout
        print("Account-local .htaccess outcomes, reasons and scan privacy checks passed.")


if not CGI.is_file():
    print(f"Plugin gateway request tests SKIPPED: no php-cgi next to {PHP}.")
    sys.exit(0)

with tempfile.TemporaryDirectory() as temp:
    whm = Gateway(temp, tree(temp, "whm", "plugins/whm/index.cgi"))

    # Principal: only cpsrvd's REMOTE_USER, only root.
    refused(whm.request(query="api=status", user=None), 403, "FORBIDDEN")
    refused(whm.request(query="api=status", user="reseller"), 403, "FORBIDDEN")
    refused(whm.request(query="api=status", user="", headers={"HTTP_REMOTE_USER": "root"}), 403, "FORBIDDEN")

    # Reads: fixed names, schema-checked arguments, the admin socket, a timeout above the broker's 30 s.
    status, header, body, calls = whm.request(query="api=status")
    assert status == 200 and body["result"] == {"op": "server.status"}, body
    assert calls == [{"socket": "/run/ols-cpanel-broker/admin.sock", "timeout": 40.0, "op": "server.status", "args": None}], calls
    assert header["cache-control"] == "no-store" and header["x-content-type-options"] == "nosniff", header
    assert header["content-security-policy"] == "default-src 'none'; frame-ancestors 'self'", header
    assert header["content-type"].startswith("application/json"), header
    for api, op in [("metrics", "server.metrics"), ("plan", "plan.latest"), ("generations", "generation.list"),
                    ("doctor", "doctor.report"), ("jobs", "job.list"), ("inventory", "inventory.accounts"), ("compat", "compat.findings")]:
        _, _, _, calls = whm.request(query=f"api={api}")
        assert [(c["op"], c["args"]) for c in calls] == [(op, None)], (api, calls)
    _, _, _, calls = whm.request(query="api=inventory&query=Shop.a-1&page=2&size=200")
    assert calls[0]["args"] == {"query": "Shop.a-1", "page": 2, "size": 200}, calls
    _, _, _, calls = whm.request(query="api=compat&size=1")
    assert calls[0]["op"] == "compat.findings" and calls[0]["args"] == {"size": 1}, calls
    _, _, _, calls = whm.request(query=f"api=job&job={JOB}")
    assert calls[0]["op"] == "job.status" and calls[0]["args"] == {"job": JOB}, calls
    for query in ["api=inventory&size=201", "api=inventory&size=0", "api=inventory&size=07", "api=inventory&page=0",
                  "api=inventory&page=abc", "api=inventory&query=%3Cscript%3E", "api=inventory&query=a%20b",
                  "api=inventory&user=olscpb", "api=inventory&size[]=1", "api=status&page=1", "api=job",
                  "api=job&job=..%2Fx", f"api=job&job={JOB.upper()}", "api=metrics&x="]:
        body = refused(whm.request(query=query), 400, "BAD_QUERY")
        assert "script" not in json.dumps(body) and "olscpb" not in json.dumps(body), body
    body = refused(whm.request(query="api=..%2F..%2Fetc%2Fshadow"), 404, "UNKNOWN_API")
    assert "shadow" not in json.dumps(body)
    refused(whm.request(query="api[]=status"), 404, "UNKNOWN_API")
    # LSCache statistics: optional account and domain, schema-checked.
    _, _, _, calls = whm.request(query="api=cache")
    assert [(c["op"], c["args"]) for c in calls] == [("cache.stats", None)], calls
    _, _, _, calls = whm.request(query="api=cache&account=olscpa&domain=shop.a.test")
    assert calls[0]["op"] == "cache.stats" and calls[0]["args"] == {"account": "olscpa", "domain": "shop.a.test"}, calls
    for query in ["api=cache&account=Olscpa", "api=cache&account=-x", "api=cache&account=a%2Fb", "api=cache&domain=nodot",
                  "api=cache&domain=a..test", "api=cache&domain=A.test", "api=cache&domain=a.test%0A", "api=cache&query=x",
                  "api=cache&account[]=a", "api=cache&domain=-a.test"]:
        refused(whm.request(query=query), 400, "BAD_QUERY")
    # Metrics history: optional resolution and vhost, schema-checked.
    _, _, _, calls = whm.request(query="api=history")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.metrics", None)], calls
    _, _, _, calls = whm.request(query="api=history&resolution=day&vhost=shop.a.test")
    assert calls[0]["op"] == "admin.metrics" and calls[0]["args"] == {"resolution": "day", "vhost": "shop.a.test"}, calls
    for query in ["api=history&resolution=year", "api=history&resolution=Hour", "api=history&vhost=A.test", "api=history&vhost=nodot",
                  "api=history&vhost=a%2Fb.test", "api=history&account=x", "api=history&vhost[]=a.test"]:
        refused(whm.request(query=query), 400, "BAD_QUERY")
    # PHP manager: status takes no argument.
    _, _, _, calls = whm.request(query="api=php")
    assert [(c["op"], c["args"]) for c in calls] == [("php.status", None)], calls
    for query in ["api=php&account=olscpa", "api=php&version=ea-php83", "api=php&query=x"]:
        refused(whm.request(query=query), 400, "BAD_QUERY")
    # Broker errors keep their meaning.
    whm.answer({"job.status": {"ok": False, "error": {"code": "NOT_FOUND", "message": "no such job"}},
                "doctor.report": {"ok": False, "error": {"code": "TIMEOUT", "message": "x"}}})
    assert whm.request(query=f"api=job&job={JOB}")[0] == 404
    assert whm.request(query="api=doctor")[0] == 502
    whm.answer({})

    # Methods: reads never by POST, actions never by GET, nothing else.
    refused(whm.request(method="POST", query="api=status", headers={"HTTP_X_OLS_CPANEL_REQUEST": "1"}), 405, "METHOD")
    refused(whm.request(query="action=ols.sync"), 405, "METHOD")
    refused(whm.request(method="PUT", query="api=status"), 405, "METHOD")
    refused(whm.request(method="DELETE", query="action=ols.sync"), 405, "METHOD")

    # Actions: the header, a strict body, the scope each action takes; issue and execute in one request.
    post = lambda action, body, **kw: whm.request(method="POST", query=f"action={action}", body=body,
                                                  headers={"HTTP_X_OLS_CPANEL_REQUEST": "1", **kw.pop("headers", {})}, **kw)
    good = {"scope": "server", "digest": DIGEST}
    refused(whm.request(method="POST", query="action=ols.sync", body=good), 403, "REQUEST_HEADER")
    refused(whm.request(method="POST", query="action=ols.sync", body=good, headers={"HTTP_X_OLS_CPANEL_REQUEST": "true"}),
            403, "REQUEST_HEADER")
    refused(post("ols.restart", good), 404, "UNKNOWN_ACTION")
    refused(whm.request(method="POST", query="action=ols.sync&scope=server", body=good, headers={"HTTP_X_OLS_CPANEL_REQUEST": "1"}),
            405, "METHOD")
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {"token": "root.n.1.m", "expires": "1"}},
                "cap.execute": {"ok": True, "id": "x", "result": {"job": JOB}}})
    for action in ["ols.sync", "ols.rollback", "ols.plan", "ols.plan_hybrid", "ols.apache_return"]:
        status, _, body, calls = post(action, good)
        assert status == 202 and body["result"] == {"job": JOB}, (action, status, body)
        assert [c["op"] for c in calls] == ["cap.issue", "cap.execute"], calls
        assert calls[0]["args"] == {"principal": "root", "action": action, "scope": "server", "digest": DIGEST}, calls
        assert calls[1]["args"] == {"token": "root.n.1.m", "action": action, "scope": "server", "digest": DIGEST}, calls
        assert calls[0]["socket"].endswith("/admin.sock") and calls[0]["timeout"] == 40.0
    status, _, body, calls = post("ols.cutover", {"scope": PLAN, "digest": DIGEST})
    assert status == 202 and calls[1]["args"]["scope"] == PLAN, (status, body, calls)
    for scope in ["server", "account:olscpa", "domain:shop.a.test"]:
        status, _, body, calls = post("ols.cache_purge", {"scope": scope, "digest": DIGEST})
        assert status == 202 and body["result"] == {"job": JOB}, (scope, status, body)
        assert calls[0]["args"] == {"principal": "root", "action": "ols.cache_purge", "scope": scope, "digest": DIGEST}, calls
    for scope in [PLAN, "all", "account:", "account:Olscpa", "account:a b", "account:-x", "domain:", "domain:nodot", "domain:a..test",
                  "domain:a.test/x", "domain:A.test", "domain:a.test\n", "server ", "account:olscpa:x", "--all"]:
        refused(post("ols.cache_purge", {"scope": scope, "digest": DIGEST}), 400, "BAD_BODY")
    for action, scope in [("ols.php_restart", "server"), ("ols.php_restart", "account:olscpa"), ("ols.opcache_install", "server"),
                          ("ols.opcache_install", "version:ea-php83"), ("ols.opcache_install", "version:ea-php100"),
                          ("ols.php_env_repair", "server")]:
        status, _, body, calls = post(action, {"scope": scope, "digest": DIGEST})
        assert status == 202 and body["result"] == {"job": JOB}, (action, scope, status, body)
        assert calls[0]["args"] == {"principal": "root", "action": action, "scope": scope, "digest": DIGEST}, calls
    for action, scope in [("ols.php_restart", "version:ea-php83"), ("ols.php_restart", "domain:a.test"), ("ols.php_restart", "account:"),
                          ("ols.php_restart", "account:Olscpa"), ("ols.php_restart", PLAN), ("ols.opcache_install", "account:olscpa"),
                          ("ols.opcache_install", "version:ea-php8"), ("ols.opcache_install", "version:ea-php1000"),
                          ("ols.opcache_install", "version:alt-php81"), ("ols.opcache_install", "version:ea-php83 --all"),
                          ("ols.opcache_install", "version:ea-php83\n"), ("ols.opcache_install", "all"),
                          ("ols.php_env_repair", "version:ea-php83"), ("ols.php_env_repair", "account:olscpa"), ("ols.php_env_repair", "all"),
                          ("ols.php_env_repair", PLAN)]:
        refused(post(action, {"scope": scope, "digest": DIGEST}), 400, "BAD_BODY")
    refused(post("ols.sync", {"scope": "account:olscpa", "digest": DIGEST}), 400, "BAD_BODY")
    # The cleanup limits of the page cache: read with GET (no argument), changed with a strict body (no job, no digest).
    _, _, _, calls = whm.request(query="api=cache_limits")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.cache_limits", None)], calls
    refused(whm.request(query="api=cache_limits&per_site_mb=1024"), 400, "BAD_QUERY")
    limits = {"per_site_mb": 1024, "server_percent": 15, "server_max_gb": 40}
    status, _, body, calls = post("cache_limits", limits)
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.cache_limits", limits)], (status, body, calls)
    _, _, _, calls = post("cache_limits", {"server_max_gb": 2048})
    assert calls[0]["args"] == {"server_max_gb": 2048}, calls
    refused(whm.request(method="POST", query="action=cache_limits", body=limits), 403, "REQUEST_HEADER")
    for bad in [{}, [], [1], {"per_site_mb": 15}, {"per_site_mb": 102401}, {"server_percent": 0}, {"server_percent": 51}, {"server_max_gb": 0},
                {"server_max_gb": 2049}, {"per_site_mb": "512"}, {"per_site_mb": 512.5}, {"per_site_mb": True}, {"per_site_mb": None},
                {"x": 1}, {"per_site_mb": 600, "x": 1}, {"scope": "server", "digest": DIGEST}, "text"]:
        refused(post("cache_limits", bad), 400, "BAD_BODY")
    # The object cache: read with GET (no argument); the automatic mode switched with exactly {automatic: bool}.
    _, _, _, calls = whm.request(query="api=objcache")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.objcache", None)], calls
    refused(whm.request(query="api=objcache&account=olscpa"), 400, "BAD_QUERY")
    for value in [True, False]:
        status, _, body, calls = post("objcache_automatic", {"automatic": value})
        assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.objcache", {"automatic": value})], (status, body, calls)
    refused(whm.request(method="POST", query="action=objcache_automatic", body={"automatic": False}), 403, "REQUEST_HEADER")
    for bad in [{}, [], [True], {"automatic": "off"}, {"automatic": 0}, {"automatic": None}, {"automatic": True, "x": 1}, {"enabled": True},
                {"scope": "server", "digest": DIGEST}, "text"]:
        refused(post("objcache_automatic", bad), 400, "BAD_BODY")
    # Requests to the administrator: listed without arguments; a status change takes exactly {id, status}.
    _, _, _, calls = whm.request(query="api=requests")
    assert [(c["op"], c["args"], c["socket"].endswith("/admin.sock")) for c in calls] == [("admin.requests", None, True)], calls
    refused(whm.request(query="api=requests&user=olscpa"), 400, "BAD_QUERY")
    rid = "r1761134400-0a1b2c3d"
    status, _, body, calls = post("request_status", {"id": rid, "status": "done"})
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.request_status", {"id": rid, "status": "done"})], (status, calls)
    refused(whm.request(method="POST", query="action=request_status", body={"id": rid, "status": "done"}), 403, "REQUEST_HEADER")
    for bad in [{}, {"id": rid}, {"status": "done"}, {"id": "../x", "status": "done"}, {"id": rid, "status": "gone"}, {"id": rid, "status": "done", "x": 1},
                {"id": "r1761134400-0A1B2C3D", "status": "done"}, [rid], "text"]:
        refused(post("request_status", bad), 400, "BAD_BODY")
    # FV-07 operations. Reads: the activity log (paged, filtered), notification settings, schedule, update check, bundles.
    for api, op in [("notify", "admin.notify"), ("schedule", "admin.schedule"), ("bundle", "admin.bundle")]:
        _, _, _, calls = whm.request(query=f"api={api}")
        assert [(c["op"], c["args"]) for c in calls] == [(op, None)], calls
        refused(whm.request(query=f"api={api}&query=x"), 400, "BAD_QUERY")
    _, _, _, calls = whm.request(query="api=audit")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.audit", None)], calls
    _, _, _, calls = whm.request(query="api=audit&query=olscpa&page=2&size=50&event=job_finish&result=failed")
    assert calls[0]["op"] == "admin.audit" and calls[0]["args"] == {"query": "olscpa", "page": 2, "size": 50, "event": "job_finish", "result": "failed"}, calls
    for query in ["api=audit&event=Job", "api=audit&event=a-b", "api=audit&event=", "api=audit&result=maybe", "api=audit&size=201", "api=audit&page=0",
                  "api=audit&query=a%20b", "api=audit&account=x", "api=audit&event[]=a"]:
        refused(whm.request(query=query), 400, "BAD_QUERY")
    _, _, _, calls = whm.request(query="api=update")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.update", None)], calls
    _, _, _, calls = whm.request(query="api=update&refresh=1")
    assert [(c["op"], c["args"]) for c in calls] == [("admin.update", {"refresh": True})], calls
    for query in ["api=update&refresh=0", "api=update&refresh=true", "api=update&refresh=", "api=update&x=1"]:
        refused(whm.request(query=query), 400, "BAD_QUERY")
    # Support bundles are jobs of the capability flow (with and without anonymization).
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {"token": "root.n.1.m", "expires": "1"}},
                "cap.execute": {"ok": True, "id": "x", "result": {"job": JOB}}})
    for action in ["ols.support_bundle", "ols.support_bundle_raw"]:
        status, _, body, calls = post(action, good)
        assert status == 202 and calls[0]["args"] == {"principal": "root", "action": action, "scope": "server", "digest": DIGEST}, (action, status, calls)
        refused(post(action, {"scope": PLAN, "digest": DIGEST}), 400, "BAD_BODY")
    whm.answer({})
    # Settings and small operations: a strict body per action, the header, no digest, relayed to one broker operation.
    notify = {"emails": ["ops@example.test", "Second.Admin+x@mail.example.org"], "webhook": "https://hooks.example.com/services/T1/B2/xyz", "events": ["job", "disk"]}
    status, _, body, calls = post("notify_settings", notify)
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.notify_set", notify)] and calls[0]["timeout"] == 40.0, (status, body, calls)
    for good_body in [{"emails": []}, {"webhook": ""}, {"events": []}, {"emails": ["a@b.test"]}]:
        assert post("notify_settings", good_body)[0] == 200, good_body
    refused(whm.request(method="POST", query="action=notify_settings", body=notify), 403, "REQUEST_HEADER")
    for bad in [{}, [], [1], {"x": 1}, {"emails": "a@b.test"}, {"emails": ["a"]}, {"emails": ["a@b.test\nBcc: c@d.test"]}, {"emails": [1]},
                {"emails": [f"u{i}@b.test" for i in range(6)]}, {"webhook": "http://hooks.example.com/x"}, {"webhook": "https://u:p@hooks.example.com/x"},
                {"webhook": "https://hooks.example.com/x y"}, {"webhook": "https://" + "a" * 520}, {"webhook": None}, {"webhook": 5}, {"events": ["nonsense"]},
                {"events": "job"}, {"events": [1]}, {"emails": [], "other": 1}, {"scope": "server", "digest": DIGEST}]:
        refused(post("notify_settings", bad), 400, "BAD_BODY")
    status, _, body, calls = post("notify_test", {})
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.notify_test", None)], (status, calls)
    for bad in [{"x": 1}, {"emails": []}, "text"]:
        refused(post("notify_test", bad), 400, "BAD_BODY")
    window = {"action": "ols.cutover", "scope": PLAN, "digest": DIGEST, "at": 1900000000, "window": 90}
    status, _, body, calls = post("schedule_add", window)
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.schedule_add", window)], (status, calls)
    ret = {"action": "ols.apache_return", "scope": "server", "digest": DIGEST, "at": 1900000000}
    assert post("schedule_add", ret)[3][0]["args"] == ret
    for bad in [{}, {**window, "action": "ols.sync"}, {**window, "action": "ols.rollback", "scope": "server"}, {**window, "scope": "server"},
                {**ret, "scope": PLAN}, {**window, "scope": "../x"}, {**window, "digest": "ab"}, {**window, "at": "soon"}, {**window, "at": 0},
                {**window, "at": 1.5}, {**window, "at": 99999999999}, {**window, "window": 14}, {**window, "window": 721}, {**window, "window": "60"},
                {**window, "x": 1}, {k: v for k, v in window.items() if k != "at"}, {k: v for k, v in window.items() if k != "digest"}]:
        refused(post("schedule_add", bad), 400, "BAD_BODY")
    status, _, body, calls = post("schedule_cancel", {"id": "s20261028100000-0a1b2c"})
    assert status == 200 and [(c["op"], c["args"]) for c in calls] == [("admin.schedule_cancel", {"id": "s20261028100000-0a1b2c"})], (status, calls)
    for bad in [{}, {"id": "../x"}, {"id": "s20261028100000-0A1B2C"}, {"id": 1}, {"id": "s20261028100000-0a1b2c", "x": 1}]:
        refused(post("schedule_cancel", bad), 400, "BAD_BODY")
    # A stale plan or a broker refusal keeps its meaning.
    whm.answer({"admin.schedule_add": {"ok": False, "error": {"code": "STALE", "message": "changed"}}})
    assert post("schedule_add", window)[0] == 409
    whm.answer({"admin.schedule_add": {"ok": False, "error": {"code": "REFUSED", "message": "at most 10"}}})
    assert post("schedule_add", window)[0] == 422
    whm.answer({})
    # Bundle download: only the bundle name shape, from the bundle directory, never through a link, as an attachment.
    bundles = pathlib.Path(temp, "bundles")
    bundles.mkdir()
    dl = Gateway(temp, tree(temp, "whm_dl", "plugins/whm/index.cgi",
                            ("const BUNDLE_DIR = '/var/lib/ols-cpanel/support';", f"const BUNDLE_DIR = '{bundles}';")))
    name = "bundle-1800000000-0a1b2c3d.tar.gz"
    (bundles / name).write_bytes(b"fake-archive-bytes")
    status, header, raw, calls = dl.request(query=f"download={name}")
    assert status == 200 and header["content-type"] == "application/gzip" and header["content-disposition"] == f'attachment; filename="{name}"', (status, header)
    assert header["content-length"] == str(len(b"fake-archive-bytes")) and header["cache-control"] == "no-store" and calls == [], header
    (bundles / "bundle-1800000001-0a1b2c3d.tar.gz").symlink_to("/etc/passwd")
    refused(dl.request(query="download=bundle-1800000001-0a1b2c3d.tar.gz"), 404, "NOT_FOUND")
    refused(dl.request(query="download=bundle-1800000002-0a1b2c3d.tar.gz"), 404, "NOT_FOUND")
    for query in ["download=../bundle-1800000000-0a1b2c3d.tar.gz", "download=bundle-1800000000-0A1B2C3D.tar.gz", "download=/etc/passwd", "download=",
                  f"download={name}&x=1", "download[]=x", f"download={name}%0A", "download=bundle-1800000000-0a1b2c3d.tar"]:
        refused(dl.request(query=query), 400, "BAD_QUERY")
    refused(dl.request(query=f"download={name}", user="olscpa"), 403, "FORBIDDEN")
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {"token": "root.n.1.m", "expires": "1"}},
                "cap.execute": {"ok": False, "error": {"code": "REFUSED", "message": "x"}}})
    assert post("ols.cache_purge", good)[0] == 422
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {"token": "root.n.1.m", "expires": "1"}},
                "cap.execute": {"ok": True, "id": "x", "result": {"job": JOB}}})
    for action, body in [("ols.cutover", good), ("ols.cutover", {"scope": "-x", "digest": DIGEST}),
                         ("ols.cutover", {"scope": "../p", "digest": DIGEST}), ("ols.sync", {"scope": PLAN, "digest": DIGEST}),
                         ("ols.sync", {"scope": "server", "digest": DIGEST.upper()}), ("ols.sync", {"scope": "server", "digest": "ab"}),
                         ("ols.sync", {"scope": "server"}), ("ols.sync", {**good, "principal": "olscpa"}), ("ols.sync", [good]),
                         ("ols.sync", "not json"), ("ols.sync", ""), ("ols.sync", {"scope": 1, "digest": DIGEST}),
                         ("ols.sync", {"scope": "server", "digest": DIGEST, "x": {"y": {"z": 1}}})]:
        reply = refused(post(action, body), 400, "BAD_BODY")
        assert "olscpa" not in json.dumps(reply)
    refused(post("ols.sync", {"scope": "server", "digest": DIGEST, "pad": "x" * 5000}), 413, "BODY")
    # Broker refusals: STALE and BUSY are conflicts, a failed issue never executes.
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {"token": "root.n.1.m"}},
                "cap.execute": {"ok": False, "error": {"code": "BUSY", "message": "job j1 is still running"}}})
    status, _, body, calls = post("ols.sync", good)
    assert status == 409 and body["error"]["code"] == "BUSY" and len(calls) == 2, (status, body)
    whm.answer({"cap.issue": {"ok": False, "error": {"code": "BAD_ARGS", "message": "invalid principal, action, scope or digest"}}})
    status, _, body, calls = post("ols.sync", good)
    assert status == 400 and [c["op"] for c in calls] == ["cap.issue"], (status, calls)
    whm.answer({"cap.issue": {"ok": True, "id": "x", "result": {}}})
    status, _, body, calls = post("ols.sync", good)
    assert status == 502 and body["error"]["code"] == "BROKER_REPLY" and len(calls) == 1, (status, body)

    # cPanel page: tenant socket, no account or argument from the request, the feature decides.
    cpanel = Gateway(temp, tree(temp, "cpanel", "plugins/cpanel/index.live.php",
                                (CPANEL_REQUIRE, "require_once __DIR__ . '/cpanel_stub.php';")))
    for api, op in [("sites", "tenant.sites"), ("status", "tenant.status"), ("domains", "tenant.domains")]:
        status, header, body, calls = cpanel.request(query=f"api={api}&user=olscpb", user="olscpa")
        assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 5.0, "op": op, "args": None}], calls
        assert header["cache-control"] == "no-store" and "default-src 'none'" in header["content-security-policy"]
    refused(cpanel.request(query="api=sites", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")

    # LSCache: statistics take nothing from the request; a purge takes {domain?} with the header, and only then.
    status, header, body, calls = cpanel.request(query="api=cache&account=olscpb&domain=b.test", user="olscpa")
    assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 40.0, "op": "tenant.cache_stats",
                                         "args": None}], calls
    refused(cpanel.request(query="api=cache", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")
    # PHP: the view takes nothing from the request; the restart takes {} with the header, and only then.
    status, _, body, calls = cpanel.request(query="api=php&user=olscpb&account=olscpb", user="olscpa")
    assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 40.0, "op": "tenant.php", "args": None}], calls
    refused(cpanel.request(query="api=php", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")
    # Object cache: the view takes nothing from the request either.
    status, _, body, calls = cpanel.request(query="api=objcache&user=olscpb&account=olscpb", user="olscpa")
    assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 40.0, "op": "tenant.objcache", "args": None}], calls
    refused(cpanel.request(query="api=objcache", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")
    # Traffic history: only the optional resolution and vhost, validated; the broker enforces whose vhost it is.
    status, _, body, calls = cpanel.request(query="api=history", user="olscpa")
    assert status == 200 and calls[0]["op"] == "tenant.metrics" and calls[0]["args"] is None and calls[0]["socket"].endswith("tenant.sock"), calls
    _, _, _, calls = cpanel.request(query="api=history&resolution=week&vhost=a.test", user="olscpa")
    assert calls[0]["args"] == {"resolution": "week", "vhost": "a.test"}, calls
    for query in ["api=history&resolution=year", "api=history&vhost=A.test", "api=history&vhost=a%2Fb.test", "api=history&user=olscpb",
                  "api=history&account=olscpb", "api=history&vhost[]=a.test", "api=history&vhost=nodot"]:
        refused(cpanel.request(query=query, user="olscpa"), 400, "BAD_QUERY")
    refused(cpanel.request(query="api=history", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")
    # Account tools (FV-08): the domain and options are checked in the gateway; the broker serves only the caller's own domains.
    tenant = "/run/ols-cpanel-broker/tenant.sock"
    status, _, body, calls = cpanel.request(query="api=logs&domain=a.test&kind=error&lines=50&search=PHP+Warning&user=olscpb", user="olscpa")
    assert status == 400, status
    status, _, body, calls = cpanel.request(query="api=logs&domain=a.test&kind=error&lines=50&search=PHP+Warning", user="olscpa")
    assert status == 200 and calls == [{"socket": tenant, "timeout": 40.0, "op": "tenant.logs",
                                         "args": {"domain": "a.test", "kind": "error", "lines": 50, "search": "PHP Warning"}}], calls
    _, _, _, calls = cpanel.request(query="api=logs&domain=a.test", user="olscpa")
    assert calls[0]["args"] == {"domain": "a.test", "kind": "access"}, calls
    for query in ["api=logs", "api=logs&domain=nodot", "api=logs&domain=../b.test", "api=logs&domain=a.test&kind=other", "api=logs&domain=a.test&lines=501",
                  "api=logs&domain=a.test&lines=0", "api=logs&domain=a.test&lines=5x", "api=logs&domain=a.test&search=" + "x" * 101,
                  "api=logs&domain=a.test&search=a%0Ab", "api=logs&domain=a.test&account=olscpb", "api=perf&domain=a.test&kind=error",
                  "api=php_errors&domain=a.test&lines=5", "api=logs_download&domain=a.test&lines=5", "api=logs&domain[]=a.test"]:
        refused(cpanel.request(query=query, user="olscpa"), 400, "BAD_QUERY")
    refused(cpanel.request(query="api=logs&domain=a.test", user="olscpa", feature="off"), 403, "FEATURE_DISABLED")
    for api, op in [("php_errors", "tenant.php_errors"), ("perf", "tenant.perf")]:
        status, _, body, calls = cpanel.request(query=f"api={api}&domain=shop.a.test", user="olscpa")
        assert status == 200 and calls == [{"socket": tenant, "timeout": 40.0, "op": op, "args": {"domain": "shop.a.test"}}], calls
    cpanel.answer({"tenant.logs": {"ok": True, "id": "x", "result": {"file": "a.test-error.log", "text": "line one\n"}}})
    status, header, body, calls = cpanel.request(query="api=logs_download&domain=a.test&kind=error", user="olscpa")
    assert status == 200 and body == "line one\n" and header["content-type"].startswith("text/plain") and "attachment" in header["content-disposition"], (status, header, body)
    assert calls[0]["args"] == {"domain": "a.test", "kind": "error", "download": True}, calls
    cpanel.answer({"tenant.logs": {"ok": False, "error": {"code": "NOT_FOUND", "message": "x"}}})
    assert cpanel.request(query="api=logs&domain=b.test", user="olscpa")[0] == 404
    cpanel.answer({})
    _, _, _, calls = cpanel.request(query="api=requests", user="olscpa")
    assert calls == [{"socket": tenant, "timeout": 5.0, "op": "tenant.requests", "args": None}], calls
    mark_t = {"HTTP_X_OLS_CPANEL_REQUEST": "1"}
    ask = lambda body, **kw: cpanel.request(method="POST", query="action=request", body=body, user="olscpa", headers=kw.pop("headers", mark_t), **kw)
    status, _, body, calls = ask({"subject": "php", "text": "Please raise the memory limit \u00e9"})
    assert status == 200 and calls == [{"socket": tenant, "timeout": 5.0, "op": "tenant.request",
                                         "args": {"subject": "php", "text": "Please raise the memory limit \u00e9"}}], calls
    refused(cpanel.request(method="POST", query="action=request", body={"subject": "php", "text": "x"}, user="olscpa"), 403, "REQUEST_HEADER")
    for bad in [{}, {"subject": "php"}, {"subject": "php", "text": "x", "user": "olscpb"}, {"subject": 1, "text": "x"}, {"subject": "php", "text": ["x"]}, ["php", "x"]]:
        refused(ask(bad), 400, "BAD_BODY")
    refused(ask({"subject": "php", "text": "x" * 8200}), 413, "BODY")
    cpanel.answer({"tenant.request": {"ok": False, "error": {"code": "RATE_LIMITED", "message": "x"}}})
    assert ask({"subject": "php", "text": "x"})[0] == 429
    cpanel.answer({})
    # .htaccess apply and undo run in the page as the account; the shape is strict and the scope check comes before any file access.
    apply = lambda body, **kw: cpanel.request(method="POST", query="action=htaccess_apply", body=body, user="olscpa", headers=kw.pop("headers", mark_t), **kw)
    undo = lambda body, **kw: cpanel.request(method="POST", query="action=htaccess_undo", body=body, user="olscpa", headers=kw.pop("headers", mark_t), **kw)
    refused(cpanel.request(method="POST", query="action=htaccess_apply", body={"path": "~/public_html/.htaccess", "digest": DIGEST}, user="olscpa"), 403, "REQUEST_HEADER")
    for bad in [{}, {"path": "~/public_html/.htaccess"}, {"digest": DIGEST}, {"path": "/etc/passwd", "digest": DIGEST}, {"path": "~/../x/.htaccess", "digest": DIGEST},
                {"path": "~/a/./.htaccess", "digest": DIGEST}, {"path": "~/public_html/.htaccess", "digest": "ab"}, {"path": "~/.htaccess", "digest": DIGEST, "x": 1}]:
        refused(apply(bad), 400, "BAD_BODY")
    for bad in [{}, {"id": "../x"}, {"id": "20261028T120000Z-0000000g"}, {"id": "20261028T120000Z-00000000", "path": "~/.htaccess"}]:
        refused(undo(bad), 400, "BAD_BODY")
    cpanel.answer({"tenant.domains": {"ok": True, "id": "x", "result": {"user": "olscpa", "domains": [{"type": "main", "docroot": "/nonexistent-ols-test/public_html"}]}}})
    status, _, body, calls = apply({"path": "~/public_html/.htaccess", "digest": DIGEST})
    assert status == 403 and body["error"]["code"] == "OUT_OF_SCOPE" and [c["op"] for c in calls] == ["tenant.domains"], (status, body, calls)
    status, _, body, calls = undo({"id": "20261028T120000Z-00000000"})
    assert status == 404 and body["error"]["code"] == "NOT_FOUND", (status, body)
    cpanel.answer({})
    _, _, body, _ = cpanel.request(query="api=htaccess_backups", user="olscpa")
    assert isinstance(body["result"]["backups"], list)
    mark_php = {"HTTP_X_OLS_CPANEL_REQUEST": "1"}
    restart = lambda body, **kw: cpanel.request(method="POST", query="action=php_restart", body=body, user="olscpa", headers=kw.pop("headers", mark_php), **kw)
    status, _, body, calls = restart({})
    assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 40.0, "op": "tenant.php_restart", "args": None}], calls
    refused(cpanel.request(method="POST", query="action=php_restart", body={}, user="olscpa"), 403, "REQUEST_HEADER")
    refused(restart({}, feature="off"), 403, "FEATURE_DISABLED")
    refused(cpanel.request(method="POST", query="action=php_restart&user=olscpb", body={}, user="olscpa", headers=mark_php), 405, "METHOD")
    for bad in [{"domain": "a.test"}, {"account": "olscpb"}, {"user": "olscpb"}, [{}], "x", ""]:
        refused(restart(bad), 400, "BAD_BODY")
    for code, expected in [("RATE_LIMITED", 429), ("NOT_FOUND", 404), ("REFUSED", 422), ("FORBIDDEN", 403), ("TIMEOUT", 502)]:
        cpanel.answer({"tenant.php_restart": {"ok": False, "error": {"code": code, "message": "x"}}})
        assert restart({})[0] == expected, code
    cpanel.answer({})
    mark = {"HTTP_X_OLS_CPANEL_REQUEST": "1"}
    purge = lambda body, **kw: cpanel.request(method="POST", query="action=cache_purge", body=body, user="olscpa", headers=kw.pop("headers", mark), **kw)
    status, _, body, calls = purge({})
    assert status == 200 and calls == [{"socket": "/run/ols-cpanel-broker/tenant.sock", "timeout": 40.0, "op": "tenant.cache_purge",
                                         "args": None}], (status, calls)
    status, _, body, calls = purge({"domain": "shop.a.test"})
    assert status == 200 and calls[0]["op"] == "tenant.cache_purge" and calls[0]["args"] == {"domain": "shop.a.test"}, calls
    refused(cpanel.request(method="POST", query="action=cache_purge", body={}, user="olscpa"), 403, "REQUEST_HEADER")
    refused(purge({}, headers={"HTTP_X_OLS_CPANEL_REQUEST": "true"}), 403, "REQUEST_HEADER")
    refused(purge({}, feature="off"), 403, "FEATURE_DISABLED")
    refused(cpanel.request(method="POST", query="action=other", body={}, user="olscpa", headers=mark), 404, "UNKNOWN_ACTION")
    refused(cpanel.request(method="POST", query="action=cache_purge&user=olscpb", body={}, user="olscpa", headers=mark), 405, "METHOD")
    refused(cpanel.request(method="POST", query="", body={}, user="olscpa", headers=mark), 405, "METHOD")
    for bad in [{"domain": "../b.test"}, {"domain": "nodot"}, {"domain": "A.test"}, {"domain": 5}, {"domain": "a.test", "user": "olscpb"},
                {"user": "olscpb"}, {"account": "olscpb"}, {"scope": "server"}, [{"domain": "a.test"}], ["a.test"], "not json", "",
                {"domain": "a.test", "x": {"y": {"z": 1}}}]:
        reply = refused(purge(bad), 400, "BAD_BODY")
        assert "olscpb" not in json.dumps(reply)
    refused(purge({"domain": "a.test", "pad": "x" * 2000}), 413, "BODY")
    # Broker errors keep their meaning: another account's domain, the rate limit, a refusal.
    for code, expected in [("NOT_FOUND", 404), ("RATE_LIMITED", 429), ("REFUSED", 422), ("BAD_ARGS", 400), ("FORBIDDEN", 403), ("TIMEOUT", 502)]:
        cpanel.answer({"tenant.cache_purge": {"ok": False, "error": {"code": code, "message": "x"}}})
        assert purge({"domain": "a.test"})[0] == expected, code
    cpanel.answer({})
    body = refused(cpanel.request(query="api=..%2Fsites", user="olscpa"), 404, "UNKNOWN_API")
    assert "sites" not in json.dumps(body)

print("WHM gateway and cPanel page request checks passed (php-cgi, stub broker).")
