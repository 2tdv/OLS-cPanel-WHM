#!/usr/bin/python3
"""G0-F lab experiment: which cPanel hook events really fire, at which stages, with which data and
privileges, and which pre-stage hooks can veto an operation. Registers the lab observer
(hook_observer.py) for a candidate list (cPanel's own metadata catalog, events other products
use on this host, and two invented names that must never fire), drives each lifecycle operation
through cPanel's APIs on a temporary lab account, attributes every observed event to the
operation that caused it, and removes everything again. NOT a G0 certificate."""
import argparse
import fcntl
import re
import hashlib
import json
import os
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
OBSERVER_SRC = pathlib.Path(__file__).resolve().parent / "hook_observer.py"
OBSERVER = "/usr/local/ols-cpanel-lab/hooks/observer"
LOG = "/var/log/ols-cpanel-lab-hooks.jsonl"
PERL = "/usr/local/cpanel/3rdparty/bin/perl"
WHMAPI, UAPI, CPAPI2 = "/usr/local/cpanel/bin/whmapi1", "/usr/local/cpanel/bin/uapi", "/usr/local/cpanel/bin/cpapi2"
USER, DOMAIN = "olscpz", "olscp-z.test"
BLOCK_USER, BLOCK_DOMAIN = "olscpblk", "olscp-block.test"
# Runs inside the probe's sudo context: create a cPanel session for the temporary account and call UAPI
# through cpsrvd as that user (the path a customer's browser takes). Prints only the UAPI result status.
SESSION_CALL = r"""
import http.client, json, ssl, subprocess, sys, urllib.parse
user, module, func, params = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
url = urllib.parse.urlsplit(json.loads(subprocess.run(["/usr/local/cpanel/bin/whmapi1", "--output=json",
      "create_user_session", "user=" + user, "service=cpaneld"], capture_output=True, text=True, check=True).stdout)["data"]["url"])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
conn = http.client.HTTPSConnection("127.0.0.1", 2083, context=ctx, timeout=60)
conn.request("GET", url.path + "?" + url.query); resp = conn.getresponse(); resp.read()
cookie = "; ".join(v.split(";", 1)[0] for k, v in resp.getheaders() if k.lower() == "set-cookie")
conn.request("GET", "/" + url.path.split("/")[1] + f"/execute/{module}/{func}?{params}", headers={"Cookie": cookie})
print(json.dumps({"status": json.loads(conn.getresponse().read()).get("status")}))
"""
INVENTED = [("Whostmgr", "Accounts::OlscpNeverFires"), ("Cpanel", "UAPI::OlscpNever::fires")]
# (category, event, stages, escalate, blocking)
CANDIDATES = [
    ("Whostmgr", "Accounts::Create", ("pre", "post"), False, True),
    ("Whostmgr", "Accounts::Remove", ("pre", "post"), False, False),
    ("Whostmgr", "Accounts::Modify", ("pre", "post"), False, False),
    ("Whostmgr", "Accounts::suspendacct", ("pre", "post"), False, False),
    ("Whostmgr", "Accounts::unsuspendacct", ("pre", "post"), False, False),
    ("Whostmgr", "Accounts::change_package", ("pre", "post"), False, False),
    ("Whostmgr", "Lang::PHP::set_vhost_versions", ("pre", "post"), False, False),
    ("Whostmgr", "SSL::installssl", ("pre", "post"), False, False),
    ("Whostmgr", "SSL::delssl", ("pre", "post"), False, False),
    ("Whostmgr", "AutoSSL::installssl", ("pre", "post"), False, False),
    ("PkgAcct", "Create", ("pre", "preFinalize", "postFinalize"), False, False),
    ("PkgAcct", "Restore", ("preExtract", "postExtract", "post"), False, False),
    ("Cpanel", "UAPI::SubDomain::addsubdomain", ("pre", "post"), True, True),
    ("Cpanel", "Api2::SubDomain::addsubdomain", ("pre", "post"), True, False),
    ("Cpanel", "Api2::SubDomain::delsubdomain", ("pre", "post"), True, False),
    ("Cpanel", "Api2::SubDomain::changedocroot", ("pre", "post"), True, False),
    ("Cpanel", "Api2::AddonDomain::addaddondomain", ("pre", "post"), True, False),
    ("Cpanel", "Api2::AddonDomain::deladdondomain", ("pre", "post"), True, False),
    ("Cpanel", "Api2::Park::park", ("pre", "post"), True, False),
    ("Cpanel", "Api2::Park::unpark", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::LangPHP::php_set_vhost_versions", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::LangPHP::php_ini_set_user_basic_directives", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::DirectoryPrivacy::configure_directory_protection", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::SSL::install_ssl", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::SSL::delete_ssl", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::Fileman::save_file_content", ("pre", "post"), True, False),
    ("Cpanel", "UAPI::Mime::add_redirect", ("pre", "post"), True, False),
] + [(c, e, ("pre", "post"), c == "Cpanel", False) for c, e in INVENTED]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-tenants", action="store_true")
    parser.add_argument("--autossl-user", choices=sorted(tf.TENANTS),
                        help="also reissue this real-domain lab account's certificate through AutoSSL (uses a CA order)")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Creates and removes temporary lab accounts and hooks; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("hooks-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "cpanel-hook-experiment", "started_at": probe.now(), "result": "not_run",
                   "operations": [], "registered": []}
        index = 0

        def step(name, command, limit=300):
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

        def log_lines():
            out = step("hook-log", ["/usr/bin/cat", LOG])["stdout"]
            return [json.loads(l) for l in out.splitlines() if l.strip()]

        def operation(name, command, limit=300, expect_ok=True):
            before = len(log_lines())
            record = step("op-" + name, command, limit)
            time.sleep(2)  # post hooks of asynchronous callers (e.g. Apache rebuild) settle
            events = log_lines()[before:]
            ok = record["exit_code"] == 0
            try:
                data = json.loads(record["stdout"])
                ok = ok and (data.get("metadata", {}).get("result") == 1 if "metadata" in data
                             else data.get("status") == 1 if "status" in data
                             else data.get("result", {}).get("status") == 1 if "result" in data
                             else bool((data.get("cpanelresult", {}).get("data") or [{}])[0].get("result")))
            except (ValueError, AttributeError, IndexError):
                pass
            summary["operations"].append({"operation": name, "succeeded": ok, "expected_success": expect_ok,
                                          "events": [{k: e.get(k) for k in ("category", "event", "stage", "euid",
                                                     "context_blocking", "escalateprivs", "data_keys", "identity",
                                                     "args_identity")} for e in events]})
            return ok

        tweak_key = "key=allowunregistereddomains"
        original_tweak = None
        hooks_added = observer_installed = False
        try:
            accounts = sorted(a["user"] for a in probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts")
                              .get("data", {}).get("acct", []))
            if USER in accounts or BLOCK_USER in accounts:
                raise ValueError("Temporary lab accounts already exist")
            if step("residue", ["/usr/bin/ls", "-d", OBSERVER, LOG])["stdout"].strip():
                raise ValueError("Observer residue present")
            summary["hooks_before"] = step("hooks-before", ["/usr/local/cpanel/bin/manage_hooks", "list"])["stdout"]
            observer_installed = True
            step("observer-dir", ["/usr/bin/install", "-d", "-m", "0755", os.path.dirname(OBSERVER)])
            step("observer", ["/usr/bin/install", "-m", "0755", "-o", "root", "-g", "root", str(OBSERVER_SRC), OBSERVER])
            step("observer-log", ["/usr/bin/install", "-m", "0600", "-o", "root", "-g", "root", "/dev/null", LOG])
            hooks_added = True
            for category, event, stages, escalate, blocking in CANDIDATES:
                for stage in stages:
                    # Cpanel::Hooks::Manage::add is the module behind manage_hooks; it also takes "blocking".
                    code = ('use Cpanel::Hooks::Manage; my ($ok, $msg) = Cpanel::Hooks::Manage::add('
                            'category => $ARGV[0], event => $ARGV[1], stage => $ARGV[2], exectype => "script", '
                            'hook => $ARGV[3], escalateprivs => $ARGV[4], blocking => $ARGV[5]); '
                            'print $ok ? "ok" : "fail $msg";')
                    record = step("hook-add", [PERL, "-I/usr/local/cpanel", "-e", code, category, event, stage, OBSERVER,
                                               "1" if escalate else "0", "1" if blocking and stage == "pre" else "0"])
                    summary["registered"].append({"category": category, "event": event, "stage": stage,
                                                  "added": record["stdout"].strip() == "ok"})
            original_tweak = probe.api(step("tweak-read", [WHMAPI, "--output=json", "get_tweaksetting", tweak_key]),
                                       "get_tweaksetting")["data"]["tweaksetting"]["value"]
            probe.api(step("tweak-allow", [WHMAPI, "--output=json", "set_tweaksetting", tweak_key, "value=1"]), "set_tweaksetting")
            secret = uuid.uuid4().hex + "Aa1!"
            operation("createacct", [WHMAPI, "--output=json", "createacct", "username=" + USER, "domain=" + DOMAIN,
                                     "password=" + secret, "contactemail=", "hasshell=0", "maxaddon=2", "maxpark=2"], 600)
            u = ["--user=" + USER, "--output=json"]
            operation("uapi-addsubdomain", [UAPI, *u, "SubDomain", "addsubdomain", "domain=one", "rootdomain=" + DOMAIN,
                                            "dir=public_html/one"])
            operation("api2-addsubdomain", [CPAPI2, *u, "SubDomain", "addsubdomain", "domain=two", "rootdomain=" + DOMAIN,
                                            "dir=public_html/two"])
            operation("api2-changedocroot", [CPAPI2, *u, "SubDomain", "changedocroot", "subdomain=two", "rootdomain=" + DOMAIN,
                                             "dir=public_html/two-moved"])
            operation("api2-addaddondomain", [CPAPI2, *u, "AddonDomain", "addaddondomain", "newdomain=olscp-y.test",
                                              "subdomain=olscpy", "dir=public_html/olscp-y.test"])
            operation("api2-park", [CPAPI2, *u, "Park", "park", "domain=olscp-x.test"])
            operation("uapi-php-vhost", [UAPI, *u, "LangPHP", "php_set_vhost_versions", "version=ea-php82", "vhost=" + DOMAIN])
            operation("whm-php-vhost", [WHMAPI, "--output=json", "php_set_vhost_versions", "version=ea-php83", "vhost=" + DOMAIN])
            operation("uapi-php-ini", [UAPI, *u, "LangPHP", "php_ini_set_user_basic_directives", "type=vhost", "vhost=" + DOMAIN,
                                       "directive-1=memory_limit:256M"])
            operation("uapi-directory-privacy", [UAPI, *u, "DirectoryPrivacy", "configure_directory_protection",
                                                 f"dir=/home/{USER}/public_html/one", "authname=Lab", "enabled=1"])
            operation("uapi-fileman-htaccess", [UAPI, *u, "Fileman", "save_file_content", f"dir=/home/{USER}/public_html",
                                                "file=.htaccess", "content=Header set X-Lab 1\n"])
            operation("uapi-mime-redirect", [UAPI, *u, "Mime", "add_redirect", "domain=" + DOMAIN, "src=/old",
                                             "redirect=https://" + DOMAIN + "/new", "type=permanent", "redirect_wildcard=0",
                                             "redirect_www=0"])
            # A self-signed certificate made for this lab domain only; never written to evidence.
            keyfile, crtfile = f"/root/.olscp-lab-{USER}.key", f"/root/.olscp-lab-{USER}.crt"
            step("lab-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                              "-subj", "/CN=" + DOMAIN, "-keyout", keyfile, "-out", crtfile])
            # cPanel's API CLIs take URI-encoded values; PEM text is encoded by root, never logged.
            enc = 'enc() { /usr/bin/python3 -I -c "import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read()))" "$1"; }; '
            operation("uapi-install-ssl", ["/usr/bin/sh", "-c", enc + 'exec "$1" --user="$2" --output=json SSL install_ssl '
                                           'domain="$3" cert="$(enc "$4")" key="$(enc "$5")"', "sh", UAPI, USER, DOMAIN,
                                           crtfile, keyfile])
            operation("uapi-delete-ssl", [UAPI, *u, "SSL", "delete_ssl", "domain=" + DOMAIN])
            operation("whm-installssl", ["/usr/bin/sh", "-c", enc + 'exec "$1" --output=json installssl domain="$2" '
                                         'crt="$(enc "$3")" key="$(enc "$4")"', "sh", WHMAPI, DOMAIN, crtfile, keyfile])
            step("lab-cert-remove", ["/usr/bin/rm", "-f", keyfile, crtfile])
            operation("suspendacct", [WHMAPI, "--output=json", "suspendacct", "user=" + USER, "reason=lab"])
            operation("unsuspendacct", [WHMAPI, "--output=json", "unsuspendacct", "user=" + USER])
            operation("modifyacct", [WHMAPI, "--output=json", "modifyacct", "user=" + USER, "MAXFTP=5"])
            operation("changepackage", [WHMAPI, "--output=json", "changepackage", "user=" + USER, "pkg=default"])
            # Through cpsrvd as the cPanel user (browser path): Cpanel hooks registered with escalateprivs
            # run through cPanel's adminbin; the observer records the effective uid.
            operation("session-uapi-addsubdomain", ["/usr/bin/python3", "-I", "-c", SESSION_CALL, USER, "SubDomain",
                                                    "addsubdomain", f"domain=three&rootdomain={DOMAIN}&dir=public_html/three"])
            operation("session-uapi-mime-redirect", ["/usr/bin/python3", "-I", "-c", SESSION_CALL, USER, "Mime", "add_redirect",
                                                     f"domain={DOMAIN}&src=/s&redirect=https://{DOMAIN}/t&type=permanent"
                                                     "&redirect_wildcard=0&redirect_www=0"])
            operation("uapi-addsubdomain-blocked", [UAPI, *u, "SubDomain", "addsubdomain", "domain=olscp-block",
                                                    "rootdomain=" + DOMAIN, "dir=public_html/blocked"], expect_ok=False)
            operation("api2-unpark", [CPAPI2, *u, "Park", "unpark", "domain=olscp-x.test"])
            operation("api2-deladdondomain", [CPAPI2, *u, "AddonDomain", "deladdondomain", "domain=olscp-y.test",
                                              "subdomain=olscpy_" + DOMAIN])
            operation("api2-delsubdomain", [CPAPI2, *u, "SubDomain", "delsubdomain", "domain=one." + DOMAIN])
            operation("pkgacct", ["/usr/local/cpanel/scripts/pkgacct", USER, "/home"], 900)
            operation("removeacct", [WHMAPI, "--output=json", "removeacct", "user=" + USER], 600)
            operation("restorepkg", ["/usr/local/cpanel/scripts/restorepkg", f"/home/cpmove-{USER}.tar.gz"], 900)
            operation("removeacct-restored", [WHMAPI, "--output=json", "removeacct", "user=" + USER], 600)
            step("archive-remove", ["/usr/bin/rm", "-f", f"/home/cpmove-{USER}.tar.gz"])
            # Veto: the observer answers "0" for pre-stage data naming the block marker.
            operation("createacct-blocked", [WHMAPI, "--output=json", "createacct", "username=" + BLOCK_USER,
                                             "domain=" + BLOCK_DOMAIN, "password=" + secret, "contactemail=", "hasshell=0"],
                      600, expect_ok=False)
            if args.autossl_user:
                # AutoSSL (RV-21): which events a real issuance fires, from which process, with which data.
                name = tf.TENANTS[args.autossl_user]
                operation("autossl-delete-ssl", [UAPI, "--user=" + args.autossl_user, "--output=json", "SSL", "delete_ssl",
                                                 "domain=" + name])
                before = len(log_lines())
                operation("autossl-check", ["/usr/local/cpanel/bin/autossl_check", "--user=" + args.autossl_user], 900)
                fired = []
                for _ in range(60):
                    fired = [e for e in log_lines()[before:] if e.get("event") == "AutoSSL::installssl"]
                    if any(e.get("stage") == "post" for e in fired):
                        break
                    time.sleep(5)
                summary["autossl"] = {"user": args.autossl_user, "domain": name,
                                      "events": [{k: e.get(k) for k in ("event", "stage", "euid", "data_keys", "identity")}
                                                 for e in fired],
                                      "installed": step("autossl-cert", ["/usr/bin/sh", "-c",
                                                        'openssl x509 -in "$1" -noout -issuer 2>/dev/null', "sh",
                                                        f"/var/cpanel/ssl/apache_tls/{name}/combined"])["stdout"].strip()}
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if hooks_added:
                # manage_hooks del removes one matching entry per call; delete per stage, then prune.
                for category, event, stages, escalate, blocking in CANDIDATES:
                    for stage in stages:
                        step("hook-del", ["/usr/local/cpanel/bin/manage_hooks", "del", "script", OBSERVER,
                                          "--category=" + category, "--event=" + event, "--stage=" + stage])
            for user in (USER, BLOCK_USER):
                listed = probe.api(step("listaccts-final", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {}).get("acct", [])
                if user in [a["user"] for a in listed]:
                    step("cleanup-removeacct", [WHMAPI, "--output=json", "removeacct", "user=" + user], 600)
            step("cleanup-archive", ["/usr/bin/rm", "-f", f"/home/cpmove-{USER}.tar.gz", f"/root/.olscp-lab-{USER}.key",
                                     f"/root/.olscp-lab-{USER}.crt"])
            if original_tweak is not None:
                step("tweak-restore", [WHMAPI, "--output=json", "set_tweaksetting", tweak_key, f"value={original_tweak}"])
            if observer_installed:
                summary["all_events"] = log_lines() if step("log-exists", ["/usr/bin/test", "-f", LOG])["exit_code"] == 0 else []
                step("observer-remove", ["/usr/bin/rm", "-rf", "/usr/local/ols-cpanel-lab", LOG])
                step("hooks-prune", ["/usr/local/cpanel/bin/manage_hooks", "prune"])
            hooks_after = step("hooks-after", ["/usr/local/cpanel/bin/manage_hooks", "list"])["stdout"]
            ids = lambda text: sorted(re.findall(r"id: ([0-9a-f-]{36})", text or ""))
            summary["hooks_restored"] = (summary.get("hooks_before") is not None and OBSERVER not in hooks_after
                                         and ids(hooks_after) == ids(summary["hooks_before"]))
            listed = probe.api(step("listaccts-end", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {}).get("acct", [])
            summary["accounts_after"] = sorted(a["user"] for a in listed)
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "hooks_restored": summary["hooks_restored"],
                              "accounts_after": summary["accounts_after"], "error": summary.get("error")}))
    return 0 if summary["result"] == "observed" else 1

if __name__ == "__main__":
    sys.exit(main())
