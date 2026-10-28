#!/usr/bin/python3
"""G0-G lab experiment (plan section 17): transactional generation activation on the test listeners
with the lab tenants' complete compiled configuration. Proves: immutable self-contained generations;
validation of exactly the staged tree; atomic pointer switch plus graceful reload under systemd with
no failed requests; rejection of an invalid candidate without touching the live state; automatic
rollback when the activated generation does not serve; recovery to a coherent state after the
activator is killed at each step; and that an OLS crash or restart comes back on the committed
generation. Apache keeps 80/443 throughout. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_config_lint
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso
import cpanel_surface

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = pathlib.Path(__file__).resolve().parent
ACTIVATOR = [sys.executable, "-I", str(TOOLS / "ols_generation.py")]
STATE, GEN_ROOT = "/var/lib/ols-cpanel", "/var/lib/ols-cpanel/generations"
LAB_CERT = STATE + "/lab-cert"
LSWS = owner.LSWS
MARKER_PORT = 8097
PROBE_URL = f"http://127.0.0.1:{iso.PORT}/static.txt"
HEALTH_URI = "/.ols-cpanel-generation/"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

NO_REDIRECT = urllib.request.build_opener(_NoRedirect)
# Ahead of every vhost rule (service proxies, tenant rules): the health path is never rewritten.
HEALTH_RULE = "RewriteRule ^/\\.ols-cpanel-generation/ - [L]\n"

def health_context(base, name, allow="127.0.0.1"):
    """Loopback-only static context answering "<generation> <vhost>" from the generation itself, so
    the activator can prove each vhost loaded from this generation (review RV-02). "satisfy any" keeps
    a tenant realm on "/" from hiding it; rewriting is off because OLS applies the docroot .htaccess
    rules (e.g. WordPress "!-f -> /index.php") even to contexts outside the docroot (RV-19). On production
    listeners the check connects to the vhost's own address, which is then also the source address."""
    return (f"context {HEALTH_URI} {{\n    location             {base}/health/{name}/\n    allowBrowse          1\n"
            f"    accessControl  {{\n        allow                {allow}\n        deny                 ALL\n    }}\n"
            "    satisfy              any\n    rewrite  {\n        enable               0\n    }\n}\n")

def health_host(name, compiled):
    """A Host header that the listener maps to this vhost."""
    plan = compiled["plan"]
    if name in plan:
        return name
    if name == cpanel_surface.PROXY_VHOST:
        return cpanel_surface.proxy_hosts()[0].replace("*", "ols-health.invalid")
    owner_name = next(n for n in plan if cpanel_surface.service_vhost_name(n) == name)
    return cpanel_surface.host_aliases(plan[owner_name]["service_domains"][0])[0]

def drop_vhost(config, name):
    """The server config without one vhost: its block and its listener map lines."""
    config = re.sub(rf"virtualHost {re.escape(name)} {{\n(?:[^\n]*\n)*?}}\n", "", config)
    return re.sub(rf"\n    map\s+{re.escape(name)} [^\n]*", "", config)

# Production listeners (profile.json written, OLS on 80/443): the listener certificate (the answer for names
# without a vhost certificate) is the product's default certificate, created by `install --prepare`
# (Deployment\CutoverPlan::DEFAULT_KEY / DEFAULT_CERT) and read by OLS at start.
LISTENER_TLS = {"$SERVER_ROOT/conf/cert/lab.key": STATE + "/tls/default.key",
                "$SERVER_ROOT/conf/cert/lab.crt": STATE + "/tls/default.crt"}
# A name no vhost claims: requests carrying it reach a listener's default ("*") vhost.
HEALTH_MISS = "ols-health.invalid"

def http_listeners(config, port=80):
    """The IPv4 listeners on a port (80: plain HTTP, 443: HTTPS) in configuration order:
    [(address, [(vhost, [host, ...])])]."""
    out = []
    for block in re.finditer(r"^listener \S+ \{\n((?:[^\n]*\n)*?)\}\n", config, re.M):
        address = re.search(r"^\s*address\s+(\S+)\s*$", block.group(1), re.M)
        if not address or address.group(1).startswith("[") or not address.group(1).endswith(f":{port}"):
            continue
        maps = [(m.group(1), [h.strip() for h in m.group(2).split(",")])
                for m in re.finditer(r"^\s*map\s+(\S+)\s+(.+?)\s*$", block.group(1), re.M)]
        out.append((address.group(1)[:-len(f":{port}")], maps))
    return out

def target_address(url):
    """The IPv4 address a health URL connects to (the source address of that local connection)."""
    return url.split("/")[2].rsplit(":", 1)[0]

def production_target(name, plan, listeners):
    """Where the activator checks a vhost on production listeners ({port: http_listeners(config, port)} for 80
    and 443), or None when no IPv4 listener on either port maps it. Account vhosts (and their service vhosts)
    are checked on their own IPv4 address: a server with several addresses has no account vhost on 127.0.0.1.
    The proxy and default vhosts are checked on 127.0.0.1 where a listener maps them there (the wildcard
    listener, or cPanel's loopback proxy binding), else on the first address that maps them. Plain HTTP on
    port 80 first; a vhost no port-80 listener maps (a hybrid domain's tls.<domain>) is checked over TLS on
    443 (review RV-29, finding 12): https://<IPv4>:443, the host as SNI and Host, certificate not verified."""
    owner_name = name if name in plan else next((n for n in plan if name in (cpanel_surface.service_vhost_name(n),
                                                                                cpanel_surface.hybrid_tls_name(n))), None)
    own = (plan[owner_name].get("ip") if owner_name else None) or "127.0.0.1"
    for port, scheme in ((80, "http"), (443, "https")):
        best = None
        for address, maps in listeners.get(port, []):
            hosts = next((h for v, h in maps if v == name), None)
            if hosts is None:
                continue
            rank = 0 if address == own else 1 if address == "*" else 2
            if best is None or rank < best[0]:
                best = (rank, own if address == "*" else address, hosts[0].replace("*", HEALTH_MISS))
        if best is not None:
            return {"vhost": name, "host": best[2], "url": f"{scheme}://{best[1]}:{port}{HEALTH_URI}id"}
    return None

def generation_tree(dest, gen, compiled, smoke_ok=True, syntax_ok=True, broken_vhost=None, epoch=0,
                    suspended=(), removed=(), production=False):
    """A self-contained generation: every server-root conf reference points into GEN_ROOT/<gen>/.
    Each compiled vhost gets a health context and a health.json target; `broken_vhost` names one whose
    health file is left out (a generation that validates but does not fully serve). `epoch` is the
    restriction epoch it was compiled against; `suspended` vhosts redirect to cPanel's suspended page as
    Apache does (except the health path),
    `removed` vhosts (and their service vhosts) are not configured at all. `production`: the compiled
    production listeners (OLS on 80/443): health targets from production_target, the listener certificate
    from LISTENER_TLS (the product's GenerationTree is byte-identical, tests/generation_tree.py)."""
    base = f"{GEN_ROOT}/{gen}"
    config = compiled["config"]
    gone = {n for v in removed for n in (v, cpanel_surface.service_vhost_name(v))}
    for name in gone:
        config = drop_vhost(config, name)
    config = re.sub(r"(configFile\s+)(\$SERVER_ROOT/)?conf/vhosts/", rf"\g<1>{base}/vhosts/", config)
    if production:
        for lab, product in LISTENER_TLS.items():
            config = config.replace(lab, product)
        if "$SERVER_ROOT/conf/cert/" in config:
            raise ValueError("unexpected listener certificate reference")
        listeners = {80: http_listeners(config), 443: http_listeners(config, 443)}
    config = config.replace("$SERVER_ROOT/conf/cert/", LAB_CERT + "/")
    marker_root = f"{base}/marker/" if smoke_ok else f"{base}/marker-missing/"
    config += (f"virtualHost olscp-gen {{\n    vhRoot               {base}/marker/\n"
               f"    configFile           {base}/vhosts/olscp-gen/vhconf.conf\n    allowSymbolLink      0\n"
               "    enableScript         0\n    restrained           1\n    setUIDMode           0\n}\n"
               f"listener generation {{\n    address              127.0.0.1:{MARKER_PORT}\n    secure               0\n"
               "    map                  olscp-gen *\n}\n")
    if not syntax_ok:
        config += "virtualHost unterminated {\n  vhRoot /nonexistent/\n"
    dest.mkdir(parents=True)
    (dest / "httpd_config.conf").write_text(config)
    targets = []
    for name, text in compiled["vhconf"].items():
        if name in gone:
            continue
        # Only the alias contexts this vhost actually has are exempt from the suspended page.
        suspend = cpanel_surface.suspension_rules(compiled["missing"][name]) if name in suspended else ""
        text = text.replace("<<<END_rules\n", "<<<END_rules\n" + HEALTH_RULE + suspend)
        if production:
            target = production_target(name, compiled["plan"], listeners)
            address = target_address(target["url"]) if target else "127.0.0.1"
            allow = "127.0.0.1" if address == "127.0.0.1" else f"127.0.0.1, {address}"
        else:
            target = {"vhost": name, "host": health_host(name, compiled), "url": f"http://127.0.0.1:{iso.PORT}{HEALTH_URI}id"}
            allow = "127.0.0.1"
        (dest / "vhosts" / name).mkdir(parents=True)
        (dest / "vhosts" / name / "vhconf.conf").write_text(text + health_context(base, name, allow))
        (dest / "health" / name).mkdir(parents=True)
        if name != broken_vhost:
            (dest / "health" / name / "id").write_text(f"{gen} {name}\n")
        if target:
            targets.append(target)
    (dest / "health.json").write_text(json.dumps(targets, indent=1))
    (dest / "EPOCH").write_text(f"{epoch}\n")
    (dest / "vhosts" / "olscp-gen").mkdir(parents=True)
    (dest / "vhosts" / "olscp-gen" / "vhconf.conf").write_text(f"docRoot                  {marker_root}\n")
    (dest / "marker").mkdir()
    (dest / "marker" / "generation").write_text(gen + "\n")
    for path in [dest, *dest.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)

def expected_outcomes(sc):
    """Declared expectations for every scenario (review RV-06): the run passes only if all hold."""
    g = lambda *keys: _dig(sc, keys)
    coherent = lambda *keys: g(*keys, "coherent") is True
    return {
        "first-activation-commits": g("first", "validate", "valid") is True and g("first", "activate", "result") == "committed"
                                    and g("first", "tenant_ok") is True,
        "reload-under-load-no-failures": g("reload_under_load", "activate", "result") == "committed"
                                         and g("reload_under_load", "requests_failed") == 0
                                         and g("reload_under_load", "systemd_active") is True,
        "plain-reloads-no-failures": g("plain_reloads", "failed") == 0 and coherent("plain_reloads", "status"),
        "php-survives-reloads": g("reload_under_load", "php_ok") is True and g("plain_reloads", "php_ok") is True,
        "invalid-candidate-rejected": g("invalid_rejected", "validate", "valid") is False
                                      and coherent("invalid_rejected", "status") and g("invalid_rejected", "tenant_ok") is True,
        "unvalidated-activation-refused": g("unvalidated_refused", "activate_without_validation", "reason") == "not validated"
                                          and g("unvalidated_refused", "validate", "valid") is False
                                          and g("unvalidated_refused", "activate_after_failed_validation", "reason") == "validation failed"
                                          and coherent("unvalidated_refused", "status") and g("unvalidated_refused", "tenant_ok") is True,
        "unhealthy-vhost-rolls-back": g("vhost_health_rollback", "validate", "valid") is True
                                      and g("vhost_health_rollback", "activate", "result") == "rolled_back"
                                      and any(f.get("vhost") == g("vhost_health_rollback", "broken_vhost")
                                              for f in g("vhost_health_rollback", "activate", "failing") or [])
                                      and coherent("vhost_health_rollback", "status")
                                      and g("vhost_health_rollback", "tenant_ok") is True,
        **{f"crash-after-{point}-recovers": coherent(f"crash_{point}", "recover") and g(f"crash_{point}", "tenant_ok") is True
           for point in ("intent", "switched", "reloaded")},
        "restriction-makes-active-incoherent": g("epoch", "status_after_restrict", "coherent") is False,
        "suspension-applied": g("epoch", "activate_e1", "result") == "committed" and g("epoch", "suspended_after_e1", "status") == 302,
        "stale-generation-refused": g("epoch", "stale_activation", "result") == "refused"
                                    and "predates" in (g("epoch", "stale_activation", "reason") or ""),
        "rollback-keeps-suspension": g("epoch", "activate_e2", "result") == "rolled_back"
                                     and g("epoch", "activate_e2", "generation") == "e1-suspended"
                                     and g("epoch", "suspended_after_rollback", "status") == 302,
        "removal-applied": g("epoch", "activate_e3", "result") == "committed"
                           and g("epoch", "removed_after_e3", "status") != 200,
        "stale-recovery-fails-closed": any(a.get("action") == "stopped_no_fresh_generation"
                                           for a in g("epoch", "recover_stale", "actions") or [])
                                       and g("epoch", "serving_after_stale_recover", "status") is None,
        "unit-refuses-stale-start": g("epoch", "start_on_stale_exit") not in (0, None)
                                    and g("epoch", "serving_after_stale_start", "status") is None,
        "current-generation-restores": g("epoch", "activate_e5", "result") == "committed" and coherent("epoch", "status_e5")
                                       and g("epoch", "suspended_after_e5", "status") == 302
                                       and g("epoch", "removed_after_e5", "status") != 200 and g("epoch", "tenant_ok") is True,
        "ols-killed-comes-back": coherent("ols_killed", "status") and g("ols_killed", "tenant_ok") is True,
        "ols-restart-comes-back": g("ols_restarted", "restart_exit") == 0 and coherent("ols_restarted", "status")
                                  and g("ols_restarted", "tenant_ok") is True,
    }

def _dig(value, keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Installs OLS for the lab tenants on test listeners; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("generations-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "generation-activation-experiment", "started_at": probe.now(),
                   "result": "not_run", "scenarios": {}}
        index = 0

        def step(name, command, limit=180):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
            return record

        def stage_file(name, content):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            return str(path)

        def gen_cmd(name, *words):
            record = step("gen-" + name, [*ACTIVATOR, *words], 240)
            try:
                return json.loads(record["stdout"].strip().splitlines()[-1])
            except (ValueError, IndexError):
                return {"exit_code": record["exit_code"], "stderr": record["stderr"][-400:]}

        def build(gen, **kw):
            tree = run / "trees" / gen
            generation_tree(tree, gen, compiled, **kw)
            os.chmod(run / "trees", 0o755)
            return gen_cmd("stage-" + gen, "stage", gen, str(tree))

        def tenant_request():
            try:
                req = urllib.request.Request(PROBE_URL, headers={"Host": tf.TENANTS["olscpa"]})
                # Generous timeout: a graceful restart queues new connections until the new workers
                # accept; that shows up as latency, not as a failure.
                with urllib.request.urlopen(req, timeout=15) as response:
                    body = response.read()
                    return None if response.status == 200 and body.startswith(b"static olscpa") else f"status {response.status}"
            except urllib.error.HTTPError as exc:
                return f"HTTP {exc.code}"
            except OSError as exc:
                return f"{type(exc).__name__}: {str(exc)[:80]}"

        def tenant_ok():
            return tenant_request() is None

        def php_ok():
            """Each tenant's PHP answers as the tenant (detached LSAPI processes survive reloads)."""
            for user, domain in tf.TENANTS.items():
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{iso.PORT}/probe.php", headers={"Host": domain})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        if f'"user":"{user}"' not in response.read().decode(errors="replace"):
                            return False
                except OSError:
                    return False
            return True

        def host_status(host):
            """Status, redirect target and start of the body for /static.txt on a vhost (redirects not followed)."""
            try:
                req = urllib.request.Request(PROBE_URL, headers={"Host": host})
                with NO_REDIRECT.open(req, timeout=15) as response:
                    return {"status": response.status, "body": response.read(60).decode(errors="replace")}
            except urllib.error.HTTPError as exc:
                return {"status": exc.code, "body": "", "location": exc.headers.get("Location", "")}
            except OSError as exc:
                return {"status": None, "body": type(exc).__name__}

        class Load(threading.Thread):
            """Continuous tenant requests while an activation runs: zero failures expected."""
            def __init__(self):
                super().__init__(daemon=True)
                self.stop, self.ok, self.failed, self.errors, self.latencies = threading.Event(), 0, 0, [], []
            def run(self):
                while not self.stop.is_set():
                    began = time.time()
                    error = tenant_request()
                    self.latencies.append((began, round(time.time() - began, 3), error))
                    if error is None:
                        self.ok += 1
                    else:
                        self.failed += 1
                        self.errors.append({"time": time.time(), "error": error})
                    time.sleep(0.02)

        def ownership():
            paths = [p for u in tf.TENANTS for p in ("/home/" + u, "/home/" + u + "/public_html")]
            return step("ownership", ["/usr/bin/stat", "-c", "%n %U %G %a", *paths])["stdout"]

        def wait_coherent(label, seconds=60):
            status = None
            for _ in range(seconds // 2):
                time.sleep(2)
                status = gen_cmd(label, "status")
                if status.get("coherent"):
                    break
            return status

        installed = netns = False
        original = None
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if step("residue", ["/usr/bin/ls", "-d", LSWS, STATE])["stdout"].strip():
                raise ValueError("OLS or generation residue present")
            original = ownership()
            compiled = iso.compile_lab(step, summary)
            # The compiled test listeners include the external-client address; OLS retries an
            # unbindable listener for seconds before starting workers, on every (re)start.
            netns = True
            iso.netns_up(step)
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            summary["unit_has_reload"] = "ExecReload=" in step("unit", ["/usr/bin/systemctl", "cat", owner.UNIT])["stdout"]
            # Adoption: OLS's fixed main config becomes a stable reference to the active generation.
            step("state-dirs", ["/usr/bin/install", "-d", "-m", "0755", STATE, GEN_ROOT, LAB_CERT, owner.WEB, owner.WEB + "/logs"])
            step("lab-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                              "-subj", "/CN=ols-cpanel-lab-default", "-keyout", LAB_CERT + "/lab.key", "-out", LAB_CERT + "/lab.crt"])
            step("adopt-main-config", ["/usr/bin/ln", "-sfn", STATE + "/active/httpd_config.conf", LSWS + "/conf/httpd_config.conf"])
            ols_iso_lint = ols_config_lint.lint(compiled["config"])
            if ols_iso_lint:
                raise ValueError("compiled configuration fails lint: " + "; ".join(ols_iso_lint))

            # 1. First activation (start) and a second one under load (graceful reload).
            sc = summary["scenarios"]
            sc["first"] = {"stage": build("g1"), "validate": gen_cmd("validate-g1", "validate", "g1")}
            sc["first"]["activate"] = gen_cmd("activate-g1", "activate", "g1")
            # cPanel's own FileProtect sync while OLS runs (docroots user:nobody 0750), as in production.
            sc["first"]["enablefileprotect_exit"] = step("enablefileprotect-running",
                                                         ["/usr/local/cpanel/scripts/enablefileprotect"], 300)["exit_code"]
            sc["first"]["tenant_ok"] = tenant_ok()
            build("g2")
            sc["reload_under_load"] = {"validate": gen_cmd("validate-g2", "validate", "g2")}
            load = Load(); load.start(); time.sleep(1)
            reload_started = time.time()
            sc["reload_under_load"]["activate"] = gen_cmd("activate-g2", "activate", "g2")
            time.sleep(1); load.stop.set(); load.join()
            sc["reload_under_load"]["php_ok"] = php_ok()
            sc["reload_under_load"].update(requests_ok=load.ok, requests_failed=load.failed,
                                           errors=[dict(e, after_reload_start=round(e["time"] - reload_started, 3))
                                                   for e in load.errors][:20],
                                           systemd_active=step("is-active", ["/usr/bin/systemctl", "is-active", owner.UNIT])
                                           ["stdout"].strip() == "active")
            # 1b. Plain graceful reloads (no configuration change) under load: request latency around each.
            load = Load(); load.start(); time.sleep(1)
            marks = []
            for _ in range(5):
                marks.append(time.time())
                step("plain-reload", ["/usr/bin/systemctl", "reload", owner.UNIT])
                time.sleep(4)
            load.stop.set(); load.join()
            windows = []
            for mark in marks:
                around = [(round(b - mark, 3), lat, err) for b, lat, err in load.latencies if mark - 0.5 <= b <= mark + 4]
                windows.append({"max_latency": max((lat for _, lat, _ in around), default=None),
                                "failed": sum(1 for _, _, err in around if err),
                                "slow": [x for x in around if x[1] > 0.5][:10]})
            kinds = {}
            for _, _, err in load.latencies:
                if err:
                    kinds[err] = kinds.get(err, 0) + 1
            sc["plain_reloads"] = {"requests": len(load.latencies), "failed": load.failed, "error_kinds": kinds, "php_ok": php_ok(),
                                   "windows": windows, "status": gen_cmd("status-after-reloads", "status"),
                                   "processes": step("ps-after-reloads", ["/usr/bin/ps", "-eo", "pid,ppid,user,etimes,args"])
                                   ["stdout"].count("openlitespeed (lshttpd"),
                                   "unit": step("unit-after-reloads", ["/usr/bin/systemctl", "status", "--no-pager", "-n", "25",
                                                                       owner.UNIT])["stdout"][-2500:]}
            # 2. Invalid candidate: rejected by validation, live state untouched.
            build("g3-invalid", syntax_ok=False)
            sc["invalid_rejected"] = {"validate": gen_cmd("validate-g3", "validate", "g3-invalid"),
                                      "status": gen_cmd("status-after-g3", "status"), "tenant_ok": tenant_ok()}
            # 2b. A generation that failed validation is never activated (RV-02), nor one never validated.
            build("g4-smoke-fails", smoke_ok=False)
            sc["unvalidated_refused"] = {"activate_without_validation": gen_cmd("activate-g4-unvalidated", "activate", "g4-smoke-fails"),
                                         "validate": gen_cmd("validate-g4", "validate", "g4-smoke-fails"),
                                         "activate_after_failed_validation": gen_cmd("activate-g4", "activate", "g4-smoke-fails"),
                                         "status": gen_cmd("status-after-g4", "status"), "tenant_ok": tenant_ok()}
            # 3. Validated, but one tenant vhost does not answer from the new generation: automatic rollback.
            broken = next(iter(compiled["plan"]))
            build("g4b-vhost-unhealthy", broken_vhost=broken)
            sc["vhost_health_rollback"] = {"broken_vhost": broken,
                                           "validate": gen_cmd("validate-g4b", "validate", "g4b-vhost-unhealthy"),
                                           "activate": gen_cmd("activate-g4b", "activate", "g4b-vhost-unhealthy"),
                                           "status": gen_cmd("status-after-g4b", "status"), "tenant_ok": tenant_ok()}
            # 4. Activator killed after each journal step, then recovery.
            for number, point in enumerate(("intent", "switched", "reloaded"), 5):
                gen = f"g{number}-crash-{point}"
                build(gen)
                gen_cmd("validate-" + gen, "validate", gen)
                killed = gen_cmd("activate-" + gen, "activate", gen, "--crash-after", point)
                sc["crash_" + point] = {"killed": killed, "before_recovery": gen_cmd("status-" + gen, "status"),
                                        "recover": gen_cmd("recover-" + gen, "recover"), "tenant_ok": tenant_ok()}
            # 4b. Restriction epoch (RV-05): a suspension, then a removal, never revived by rollback or recovery.
            suspended_host, removed_host = tf.TENANTS["olscpb"], tf.SUBDOMAIN
            ep = sc["epoch"] = {"restrict_suspend": gen_cmd("restrict-suspend", "restrict", "suspend", "olscpb")}
            ep["status_after_restrict"] = gen_cmd("status-after-restrict", "status")
            build("e1-suspended", epoch=1, suspended=[suspended_host])
            ep["validate_e1"] = gen_cmd("validate-e1", "validate", "e1-suspended")
            ep["activate_e1"] = gen_cmd("activate-e1", "activate", "e1-suspended")
            ep["suspended_after_e1"] = host_status(suspended_host)
            ep["stale_activation"] = gen_cmd("activate-stale-g2", "activate", "g2")
            build("e2-unhealthy", epoch=1, suspended=[suspended_host], broken_vhost=tf.TENANTS["olscpa"])
            gen_cmd("validate-e2", "validate", "e2-unhealthy")
            ep["activate_e2"] = gen_cmd("activate-e2", "activate", "e2-unhealthy")
            ep["suspended_after_rollback"] = host_status(suspended_host)
            ep["restrict_remove"] = gen_cmd("restrict-remove", "restrict", "remove", removed_host)
            build("e3-removed", epoch=2, suspended=[suspended_host], removed=[removed_host])
            gen_cmd("validate-e3", "validate", "e3-removed")
            ep["activate_e3"] = gen_cmd("activate-e3", "activate", "e3-removed")
            ep["removed_after_e3"] = host_status(removed_host)
            # Activation interrupted, then a newer restriction: nothing current exists, so recovery stops
            # serving instead of reviving stale rights; a generation compiled for the new epoch restores.
            build("e4-interrupted", epoch=2, suspended=[suspended_host], removed=[removed_host])
            gen_cmd("validate-e4", "validate", "e4-interrupted")
            ep["killed_e4"] = gen_cmd("activate-e4", "activate", "e4-interrupted", "--crash-after", "switched")
            ep["restrict_more"] = gen_cmd("restrict-more", "restrict", "suspend", "lab-third-account")
            ep["recover_stale"] = gen_cmd("recover-stale", "recover")
            ep["serving_after_stale_recover"] = host_status(tf.TENANTS["olscpa"])
            # The unit itself refuses to start on the stale generation (boot, manual start, crash restart).
            ep["start_on_stale_exit"] = step("start-on-stale", ["/usr/bin/systemctl", "start", owner.UNIT])["exit_code"]
            ep["serving_after_stale_start"] = host_status(tf.TENANTS["olscpa"])
            build("e5-current", epoch=3, suspended=[suspended_host], removed=[removed_host])
            gen_cmd("validate-e5", "validate", "e5-current")
            ep["activate_e5"] = gen_cmd("activate-e5", "activate", "e5-current")
            ep["status_e5"] = gen_cmd("status-e5", "status")
            ep["suspended_after_e5"] = host_status(suspended_host)
            ep["removed_after_e5"] = host_status(removed_host)
            ep["tenant_ok"] = tenant_ok()
            # 5. OLS itself dies (SIGKILL of the main process) and is restarted: committed generation again.
            pid = step("main-pid", ["/usr/bin/cat", "/run/ols-cpanel/lshttpd/lshttpd.pid"])["stdout"].strip()
            if pid.isdigit():
                step("kill-main", ["/usr/bin/kill", "-9", pid])
            sc["ols_killed"] = {"status": wait_coherent("status-after-kill"), "tenant_ok": tenant_ok()}
            restart = step("restart", ["/usr/bin/systemctl", "restart", owner.UNIT])
            sc["ols_restarted"] = {"restart_exit": restart["exit_code"], "status": wait_coherent("status-after-restart"),
                                   "tenant_ok": tenant_ok(),
                                   "unit": step("unit-status", ["/usr/bin/systemctl", "status", "--no-pager", "-n", "15",
                                                                owner.UNIT])["stdout"][-1500:]}
            summary["cases"] = {name: {"pass": bool(ok)} for name, ok in expected_outcomes(sc).items()}
            summary["result"] = "pass" if all(c["pass"] for c in summary["cases"].values()) else "fail"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                step("stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                summary["journal"] = step("journal", ["/usr/bin/sh", "-c", 'cat "$1"/journal/*.json', "sh", STATE])["stdout"][-20000:]
                summary["package_erased"] = owner.erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, owner.WEB, STATE, "/tmp/lshttpd", "/run/ols-cpanel/lshttpd", "/dev/shm/ols"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
                # Return path: with OLS gone, cPanel restores its Apache (ruid2) docroot ownership itself.
                step("enablefileprotect-return", ["/usr/local/cpanel/scripts/enablefileprotect"], 300)
                summary["ownership_restored"] = original is None or ownership() == original
            if netns:
                iso.netns_down(step)
            summary["removed"] = not step("final-residue", ["/usr/bin/ls", "-d", LSWS, STATE, "/run/ols-cpanel"])["stdout"].strip()
            summary["apache_http"] = step("final-http", probe.COMMANDS["http"])["stdout"] == "200"
            summary["finished_at"] = probe.now()
            if summary["result"] == "pass" and not (summary["removed"] and summary["apache_http"]
                                                    and summary.get("ownership_restored", True)):
                summary["result"] = "fail"  # a run that does not restore the host is not a pass
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "removed": summary["removed"],
                              "failed_cases": [n for n, c in summary.get("cases", {}).items() if not c["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
