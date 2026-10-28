#!/usr/bin/python3
"""G0-F lab experiment (plan sections 14/15; RV-21, HR-D11, RV-03): cPanel hooks feed the event
pipeline (ols_events.py) and a reconciler service keeps OLS (test listeners, generation layout) equal
to cPanel's state. Measures, from the cPanel action until OLS shows it: account suspension and
unsuspension (compared path by path with Apache), a certificate install through UAPI, a new and a
deleted subdomain, and an .htaccess edit that no hook reports (periodic reconciliation). Removes
everything afterwards and restores the fixtures. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import ssl
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpanel_surface
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = pathlib.Path(__file__).resolve().parent
STATE, GEN_ROOT = "/var/lib/ols-cpanel", "/var/lib/ols-cpanel/generations"
LAB_CERT = STATE + "/lab-cert"
LSWS = owner.LSWS
HOOK_DIR = "/usr/local/ols-cpanel-lab/events"
HOOK = HOOK_DIR + "/hook"
UNIT = "ols-cpanel-reconciler-lab"
PERL = "/usr/local/cpanel/3rdparty/bin/perl"
WHMAPI, UAPI, CPAPI2 = "/usr/local/cpanel/bin/whmapi1", "/usr/local/cpanel/bin/uapi", "/usr/local/cpanel/bin/cpapi2"
INTERVAL = 60
# (category, event, escalate): the events whose effects this experiment exercises.
HOOKS = [("Whostmgr", "Accounts::suspendacct", False), ("Whostmgr", "Accounts::unsuspendacct", False),
         ("Whostmgr", "Accounts::Remove", False), ("Whostmgr", "SSL::installssl", False),
         ("Whostmgr", "AutoSSL::installssl", False), ("Cpanel", "UAPI::SSL::install_ssl", True),
         ("Cpanel", "UAPI::SSL::delete_ssl", True), ("Cpanel", "UAPI::SubDomain::addsubdomain", True),
         ("Cpanel", "Api2::SubDomain::addsubdomain", True), ("Cpanel", "Api2::SubDomain::delsubdomain", True)]
B, A = tf.TENANTS["olscpb"], tf.TENANTS["olscpa"]
SUSPEND_PATHS = ["/static.txt", "/img-sys/csf.svg", "/cpanel", "/cgi-sys/suspendedpage.cgi",
                 "/.well-known/pki-validation/0123456789ABCDEF0123456789ABCDEF.txt"]
NEW_SUB = "rec"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Registers hooks and changes the lab tenants temporarily; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("reconcile-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "event-reconcile-experiment", "started_at": probe.now(),
                   "result": "not_run", "argv": sys.argv, "scenarios": {}}
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

        def fetch(host, path, port=iso.PORT, scheme="http", address="127.0.0.1"):
            record = step("fetch", ["/usr/bin/curl", "--noproxy", "*", "-sk", "--max-time", "10", "-D", "-",
                                    "-w", "\n%{http_code} %{redirect_url}", "--resolve", f"{host}:{port}:{address}",
                                    f"{scheme}://{host}:{port}{path}"], 30)
            body, _, tail = record["stdout"].rpartition("\n")
            status, _, location = tail.partition(" ")
            return {"status": status, "location": location.replace(f":{port}/", "/"), "body": body}

        def wait_until(label, check, limit=360):
            began = time.time()
            while time.time() - began < limit:
                if check():
                    return round(time.time() - began, 1)
                time.sleep(1)
            return None

        def fingerprint(name, port=iso.TLS_PORT):
            return step("fp", ["/usr/bin/sh", "-c", 'openssl s_client -connect "$1" -servername "$2" </dev/null 2>/dev/null'
                                                     ' | openssl x509 -noout -fingerprint -sha256 2>/dev/null', "sh",
                                f"127.0.0.1:{port}", name], 30)["stdout"].strip()

        installed = netns = hooks_added = service = False
        original = original_htaccess = original_cert = None
        sub_created = suspended = False
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if step("residue", ["/usr/bin/ls", "-d", LSWS, STATE, HOOK_DIR])["stdout"].strip():
                raise ValueError("OLS, generation or hook residue present")
            userdata = step("userdata-b", ["/usr/bin/cat", f"/var/cpanel/userdata/olscpb/{B}"])["stdout"]
            apache_ip = next(l.split(":", 1)[1].strip() for l in userdata.splitlines() if l.startswith("ip:"))
            original = step("ownership", ["/usr/bin/stat", "-c", "%n %U %G %a", *[f"/home/{u}/public_html" for u in tf.TENANTS]])["stdout"]
            netns = True
            iso.netns_up(step)
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            step("state-dirs", ["/usr/bin/install", "-d", "-m", "0755", STATE, GEN_ROOT, LAB_CERT, owner.WEB, owner.WEB + "/logs"])
            step("lab-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                              "-subj", "/CN=ols-cpanel-lab-default", "-keyout", LAB_CERT + "/lab.key", "-out", LAB_CERT + "/lab.crt"])
            step("adopt-main-config", ["/usr/bin/ln", "-sfn", STATE + "/active/httpd_config.conf", LSWS + "/conf/httpd_config.conf"])
            # First generation (starts OLS), then cPanel's FileProtect as in production.
            first = step("reconcile-first", ["/usr/bin/python3", "-I", str(TOOLS / "ols_events.py"), "reconcile", "--force"], 900)
            summary["first_reconcile"] = first["stdout"].strip().splitlines()[-1:] or first["stderr"][-400:]
            step("enablefileprotect", ["/usr/local/cpanel/scripts/enablefileprotect"], 300)
            if fetch(A, "/static.txt")["status"] != "200":
                raise ValueError("OLS does not serve the first generation")
            # Hook dispatcher (root-owned copy) and the reconciler service.
            step("hook-dir", ["/usr/bin/install", "-d", "-m", "0755", HOOK_DIR])
            for name in ("ols_events.py", "ols_generation.py"):
                step("hook-file", ["/usr/bin/install", "-m", "0644", str(TOOLS / name), f"{HOOK_DIR}/{name}"])
            step("hook-wrapper", ["/usr/bin/install", "-m", "0755", stage_file(
                "hook", f"#!/bin/sh\nexec /usr/bin/python3 -I {HOOK_DIR}/ols_events.py hook\n"), HOOK])
            hooks_added = True
            code = ('use Cpanel::Hooks::Manage; my ($ok, $msg) = Cpanel::Hooks::Manage::add(category => $ARGV[0], '
                    'event => $ARGV[1], stage => "post", exectype => "script", hook => $ARGV[2], escalateprivs => $ARGV[3]); '
                    'print $ok ? "ok" : "fail $msg";')
            summary["hooks_registered"] = {}
            for category, event, escalate in HOOKS:
                record = step("hook-add", [PERL, "-I/usr/local/cpanel", "-e", code, category, event, HOOK, "1" if escalate else "0"])
                summary["hooks_registered"][event] = record["stdout"].strip() == "ok"
            service = True
            step("reconciler", ["/usr/bin/systemd-run", f"--unit={UNIT}", "/usr/bin/python3", "-I",
                                str(TOOLS / "ols_events.py"), "watch", "--interval", str(INTERVAL)])
            sc = summary["scenarios"]

            # a. Suspension: cPanel's suspended-page redirect on OLS, path by path equal to Apache.
            began = time.time()
            suspended = True
            probe.api(step("suspendacct", [WHMAPI, "--output=json", "suspendacct", "user=olscpb", "reason=lab"], 600), "suspendacct")
            sc["suspend"] = {"api_seconds": round(time.time() - began, 1)}
            sc["suspend"]["ols_seconds"] = wait_until("suspend", lambda: fetch(B, "/static.txt")["status"] == "302", 360)
            sc["suspend"]["seconds_from_action"] = round(time.time() - began, 1)
            wait_until("apache-suspend", lambda: fetch(B, "/static.txt", 80, address=apache_ip)["status"] == "302", 120)
            compare = {}
            for path in SUSPEND_PATHS:
                a, o = fetch(B, path, 80, address=apache_ip), fetch(B, path)
                compare[path] = {"apache": [a["status"], a["location"]], "ols": [o["status"], o["location"]],
                                 "match": [a["status"], a["location"]] == [o["status"], o["location"]]}
            sc["suspend"]["comparison"] = compare
            began = time.time()
            probe.api(step("unsuspendacct", [WHMAPI, "--output=json", "unsuspendacct", "user=olscpb"], 600), "unsuspendacct")
            suspended = False
            sc["unsuspend"] = {"seconds_from_action": None}
            served = wait_until("unsuspend", lambda: fetch(B, "/static.txt")["status"] == "200", 360)
            sc["unsuspend"]["seconds_from_action"] = None if served is None else round(time.time() - began, 1)

            # b. A certificate installed through cPanel's UAPI is served without a manual reload.
            # cPanel keeps a vhost's certificate under its ServerName: the addon is served by its subdomain vhost.
            combined = step("orig-cert", ["/usr/bin/cat", f"{iso.TLS_DIR}/{tf.ADDON_LABEL}.{A}/combined"])["stdout"]
            if "PRIVATE KEY" not in combined:
                raise ValueError("Cannot save the addon's current certificate for restoration")
            blocks = re.findall(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----\n?", combined, re.S)
            original_cert = {"key": next((b for b in blocks if "PRIVATE KEY" in b), ""),
                             "cert": next((b for b in blocks if "CERTIFICATE" in b), "")}
            keyfile, crtfile = f"{STATE}/lab-new.key", f"{STATE}/lab-new.crt"
            step("new-cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                              "-subj", "/CN=" + tf.ADDON, "-keyout", keyfile, "-out", crtfile])
            new_fp = step("new-fp", ["/usr/bin/openssl", "x509", "-in", crtfile, "-noout", "-fingerprint", "-sha256"])["stdout"].strip()
            enc = 'enc() { /usr/bin/python3 -I -c "import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read()))" "$1"; }; '
            began = time.time()
            step("uapi-install-ssl", ["/usr/bin/sh", "-c", enc + 'exec "$1" --user=olscpa --output=json SSL install_ssl '
                                      'domain="$2" cert="$(enc "$3")" key="$(enc "$4")"', "sh", UAPI, tf.ADDON, crtfile, keyfile], 600)
            sc["install_ssl"] = {"ols_seconds": wait_until("ssl", lambda: fingerprint(tf.ADDON) == new_fp, 360)}
            sc["install_ssl"]["seconds_from_action"] = round(time.time() - began, 1)
            step("new-cert-remove", ["/usr/bin/rm", "-f", keyfile, crtfile])

            # c. A new subdomain is served, a deleted one is not.
            sub, docroot = f"{NEW_SUB}.{A}", f"/home/olscpa/public_html/{NEW_SUB}"
            began = time.time()
            sub_created = True
            step("addsubdomain", [UAPI, "--user=olscpa", "--output=json", "SubDomain", "addsubdomain", "domain=" + NEW_SUB,
                                  "rootdomain=" + A, "dir=public_html/" + NEW_SUB], 600)
            step("sub-static", ["/usr/bin/install", "-m", "0644", "-o", "olscpa", "-g", "olscpa",
                                stage_file("sub.txt", "static " + sub + "\n"), docroot + "/static.txt"])
            sc["add_subdomain"] = {"ols_seconds": wait_until("addsub", lambda: fetch(sub, "/static.txt")["body"].strip().endswith("static " + sub), 360)}
            sc["add_subdomain"]["seconds_from_action"] = round(time.time() - began, 1)
            began = time.time()
            step("delsubdomain", [CPAPI2, "--user=olscpa", "--output=json", "SubDomain", "delsubdomain", "domain=" + sub], 600)
            sub_created = False
            sc["delete_subdomain"] = {"ols_seconds": wait_until("delsub", lambda: not fetch(sub, "/static.txt")["body"].strip().endswith("static " + sub), 360)}
            sc["delete_subdomain"]["seconds_from_action"] = round(time.time() - began, 1)
            step("sub-docroot-remove", ["/usr/bin/rm", "-rf", docroot])

            # d. An .htaccess edit with no hook reaches OLS through the periodic reconciliation (RV-03).
            ht = f"/home/olscpb/public_html/.htaccess"
            original_htaccess = step("htaccess-read", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/cat", ht])["stdout"]
            began = time.time()
            step("htaccess-edit", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/sh", "-c",
                                   'printf "%s" "$1" >> "$2"', "sh", "\nHeader set X-Ols-Lab reconcile\n", ht])
            sc["htaccess_edit"] = {"ols_seconds": wait_until("htaccess", lambda: "x-ols-lab: reconcile" in
                                                             fetch(B, "/static.txt")["body"].lower(), 360)}
            sc["htaccess_edit"]["seconds_from_action"] = round(time.time() - began, 1)
            summary["reconciler_log"] = step("reconciler-log", ["/usr/bin/journalctl", "-u", UNIT, "--no-pager", "-o", "cat"])["stdout"].splitlines()[-40:]
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if service:
                step("reconciler-stop", ["/usr/bin/systemctl", "stop", UNIT])
            if hooks_added:
                for category, event, escalate in HOOKS:
                    step("hook-del", ["/usr/local/cpanel/bin/manage_hooks", "del", "script", HOOK, "--category=" + category,
                                      "--event=" + event, "--stage=post"])
                step("hooks-prune", ["/usr/local/cpanel/bin/manage_hooks", "prune"])
                step("hook-dir-remove", ["/usr/bin/rm", "-rf", HOOK_DIR])
            summary["hooks_restored"] = HOOK not in step("hooks-final", ["/usr/local/cpanel/bin/manage_hooks", "list"])["stdout"]
            if suspended:
                step("unsuspend-final", [WHMAPI, "--output=json", "unsuspendacct", "user=olscpb"], 600)
            if sub_created:
                step("delsubdomain-final", [CPAPI2, "--user=olscpa", "--output=json", "SubDomain", "delsubdomain",
                                            "domain=" + f"{NEW_SUB}.{A}"], 600)
                step("sub-docroot-final", ["/usr/bin/rm", "-rf", f"/home/olscpa/public_html/{NEW_SUB}"])
            if original_htaccess is not None:
                step("htaccess-restore", ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/sh", "-c", 'printf "%s" "$1" > "$2"',
                                          "sh", original_htaccess, "/home/olscpb/public_html/.htaccess"])
            if original_cert and original_cert["key"] and original_cert["cert"]:
                kf, cf = stage_file("orig.key", original_cert["key"]), stage_file("orig.crt", original_cert["cert"])
                enc = 'enc() { /usr/bin/python3 -I -c "import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read()))" "$1"; }; '
                step("cert-restore", ["/usr/bin/sh", "-c", enc + 'exec "$1" --user=olscpa --output=json SSL install_ssl '
                                      'domain="$2" cert="$(enc "$3")" key="$(enc "$4")"', "sh", UAPI, tf.ADDON, cf, kf], 600)
                for path in (kf, cf):
                    pathlib.Path(path).unlink(missing_ok=True)
            if installed:
                step("stop", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                summary["package_erased"] = owner.erase_package(step)
                step("remove-files", ["/usr/bin/rm", "-rf", LSWS, owner.WEB, STATE, "/tmp/lshttpd", "/run/ols-cpanel/lshttpd", "/dev/shm/ols"])
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
                step("enablefileprotect-return", ["/usr/local/cpanel/scripts/enablefileprotect"], 300)
            if netns:
                iso.netns_down(step)
            restored_owner = step("ownership-final", ["/usr/bin/stat", "-c", "%n %U %G %a",
                                                      *[f"/home/{u}/public_html" for u in tf.TENANTS]])["stdout"]
            summary["restored"] = {"removed": not step("final-residue", ["/usr/bin/ls", "-d", LSWS, STATE, HOOK_DIR])["stdout"].strip(),
                                   "hooks": summary["hooks_restored"],
                                   "apache_http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200",
                                   "not_suspended": step("suspended-final", ["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpb"])["exit_code"] != 0,
                                   "ownership": original is None or restored_owner == original or "nobody" in (original or "")}
            if summary["result"] == "observed":
                cases = expected_outcomes(summary)
                summary["cases"] = {k: {"pass": bool(v)} for k, v in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": summary["restored"],
                              "failed_cases": [k for k, v in summary.get("cases", {}).items() if not v["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

def expected_outcomes(summary):
    sc = summary.get("scenarios", {})
    within = lambda key, limit: isinstance((sc.get(key) or {}).get("seconds_from_action"), (int, float)) \
        and (sc.get(key) or {}).get("ols_seconds", 0) is not None and sc[key]["seconds_from_action"] <= limit
    return {
        "suspension-within-300s": within("suspend", 300),
        "suspension-equal-to-apache": bool((sc.get("suspend") or {}).get("comparison"))
                                      and all(v["match"] for v in sc["suspend"]["comparison"].values()),
        "unsuspension-within-300s": (sc.get("unsuspend") or {}).get("seconds_from_action") is not None
                                    and sc["unsuspend"]["seconds_from_action"] <= 300,
        "certificate-install-served": within("install_ssl", 300),
        "new-subdomain-served": within("add_subdomain", 300),
        "deleted-subdomain-not-served": within("delete_subdomain", 300),
        "htaccess-edit-applied-periodically": within("htaccess_edit", INTERVAL * 3),
        "host-restored": all((summary.get("restored") or {}).values()),
    }

if __name__ == "__main__":
    sys.exit(main())
