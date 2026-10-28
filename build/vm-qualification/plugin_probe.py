#!/usr/bin/python3
"""G0-H lab experiment, interface part: install the broker, the WHM plugin (AppConfig, root CGI gateway)
and the cPanel plugin (install_plugin, LivePHP page, Feature Manager feature) with the prebuilt
interface, then use them through real cpsrvd sessions: root in WHM, no session, a reseller without
root ACLs, a local user running the gateway with a forged REMOTE_USER, both lab tenants in cPanel
(own data only, forged parameters ignored) and the feature disabled. Removes everything afterwards.
NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tarfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = pathlib.Path(__file__).resolve().parent
WHM_DIR = "/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel"
WHM_ICON = "/usr/local/cpanel/whostmgr/docroot/addon_plugins/ols-cpanel.svg"
CPANEL_DIR = "/usr/local/cpanel/base/frontend/jupiter/ols_cpanel"
BROKER_BIN = "/usr/local/ols-cpanel/bin/ols-cpanel-broker"
BROKER_UNIT = "ols-cpanel-broker-lab"
STATE = "/var/lib/ols-cpanel"
HELPER_DIR = "/usr/local/ols-cpanel/lab"
WHMAPI = "/usr/local/cpanel/bin/whmapi1"
RESELLER, RESELLER_DOMAIN = "olscpr", "olscp-r.test"
FEATURE = "ols_cpanel"

# cPanel's registration tools do not set their own file modes: under the probe's umask 077 (passed on
# by sudo) install_plugin wrote feature metadata the account cannot read, so the feature stayed off.
UMASK_022 = ["/usr/bin/sh", "-c", 'umask 022 && exec "$@"', "sh"]

def tree(dest, files, ui):
    dest.mkdir(parents=True)
    for target, source in files.items():
        (dest / target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest / target)
    shutil.copytree(ui / "assets", dest / "assets")
    shutil.copy2(ui / ".vite/manifest.json", dest / "manifest.json")
    for path in [dest, *dest.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() or path.suffix == ".cgi" else 0o644)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", required=True, type=pathlib.Path)
    parser.add_argument("--ui", required=True, type=pathlib.Path, help="built interface (artifacts/ui)")
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Installs WHM/cPanel plugins and a temporary reseller on the lab; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("plugins-" + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "plugin-experiment", "started_at": probe.now(), "result": "not_run",
                   "cases": {}}
        index = 0

        def step(name, command, limit=300):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
            return record

        def http(label, service, user, requests):
            record = step("http-" + label, ["/usr/bin/python3", "-I", f"{HELPER_DIR}/plugin_http_check.py", service, user,
                                            json.dumps(requests)], 180)
            try:
                return json.loads(record["stdout"])
            except ValueError:
                return {"error": record["stderr"][-300:]}

        def case(name, value, passed):
            summary["cases"][name] = {"pass": bool(passed), "observed": value}

        def results(report):
            return report.get("results") or [{}] * 10

        whm_tree, cpanel_tree = run / "whm", run / "cpanel"
        lib = {"lib/BrokerClient.php": ROOT / "src/Broker/BrokerClient.php", "lib/AssetManifest.php": ROOT / "src/Ui/AssetManifest.php"}
        tree(whm_tree, {"index.cgi": ROOT / "plugins/whm/index.cgi", **lib}, args.ui)
        tree(cpanel_tree, {"index.live.php": ROOT / "plugins/cpanel/index.live.php",
                           "lib/i18n.htaccess.en.json": ROOT / "ui/src/shared/i18n.htaccess.en.json",
                           "lib/HtaccessTranslator.php": ROOT / "src/Ols/Compiler/HtaccessTranslator.php",
                           "lib/HtaccessRewrite.php": ROOT / "src/Ols/Compiler/HtaccessRewrite.php", **lib}, args.ui)
        archive = run / "ols_cpanel_plugin.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in ("install.json", "ols_cpanel.svg", "ols_cpanel_group.svg", "ols_cpanel_cache.svg", "ols_cpanel_php.svg", "ols_cpanel_objcache.svg", "ols_cpanel_speed.svg", "ols_cpanel_logs.svg", "ols_cpanel_traffic.svg", "ols_cpanel_purge.svg"):
                tar.add(ROOT / "plugins/cpanel" / name, arcname=name)
        os.chmod(archive, 0o644)
        os.chmod(run / "whm", 0o755)
        os.chmod(run / "cpanel", 0o755)

        installed = {"broker": False, "whm": False, "cpanel": False, "reseller": False, "state": False}
        original_feature = None
        try:
            accounts = sorted(a["user"] for a in probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts")
                              .get("data", {}).get("acct", []))
            if accounts != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            if step("residue", ["/usr/bin/ls", "-d", WHM_DIR, CPANEL_DIR, BROKER_BIN, "/run/ols-cpanel-broker"])["stdout"].strip():
                raise ValueError("plugin residue present")
            # Broker.
            installed["broker"] = True
            installed["state"] = step("state-exists", ["/usr/bin/test", "-d", STATE])["exit_code"] != 0
            step("dirs", ["/usr/bin/install", "-d", "-m", "0755", os.path.dirname(BROKER_BIN), HELPER_DIR, STATE])
            step("broker-bin", ["/usr/bin/install", "-m", "0755", str(args.broker.resolve()), BROKER_BIN])
            step("helper", ["/usr/bin/install", "-m", "0755", str(TOOLS / "plugin_http_check.py"), HELPER_DIR + "/plugin_http_check.py"])
            step("broker-start", ["/usr/bin/systemd-run", f"--unit={BROKER_UNIT}", "--property=RuntimeDirectory=ols-cpanel-broker",
                                  "--property=RuntimeDirectoryMode=0755", BROKER_BIN, "/run/ols-cpanel-broker"])
            # WHM plugin through cPanel's AppConfig registration.
            installed["whm"] = True
            step("whm-files", ["/usr/bin/cp", "-a", str(whm_tree), WHM_DIR])
            step("whm-owner", ["/usr/bin/chown", "-R", "root:root", WHM_DIR])
            step("whm-icon", ["/usr/bin/install", "-m", "0644", str(ROOT / "plugins/whm/ols-cpanel.svg"), WHM_ICON])
            summary["register_appconfig"] = step("register", [*UMASK_022, "/usr/local/cpanel/bin/register_appconfig",
                                                              str(ROOT / "plugins/whm/ols-cpanel.conf")])["exit_code"]
            # cPanel plugin through install_plugin (sitemap entry + Feature Manager feature).
            installed["cpanel"] = True
            step("cpanel-files", ["/usr/bin/cp", "-a", str(cpanel_tree), CPANEL_DIR])
            step("cpanel-owner", ["/usr/bin/chown", "-R", "root:root", CPANEL_DIR])
            summary["install_plugin"] = step("install-plugin", [*UMASK_022, "/usr/local/cpanel/scripts/install_plugin", str(archive),
                                                                "--theme", "jupiter"])["exit_code"]
            features = probe.api(step("featurelist", [WHMAPI, "--output=json", "get_featurelist_data", "featurelist=default"]),
                                 "get_featurelist_data")["data"]["features"]
            original_feature = next((f["value"] for f in features if f["id"] == FEATURE), None)
            summary["feature_default_value"] = original_feature
            a, b = list(tf.TENANTS)
            # cPanel finishes plugin/AppConfig registration asynchronously (feature visibility, WHM chrome
            # cache); an installer must wait for both before declaring the interface ready.
            ready_after = None
            for second in range(0, 180, 3):
                feature_on = all(json.loads(step("feature-wait", ["/usr/local/cpanel/bin/uapi", "--user=" + u, "--output=json",
                                 "Features", "has_feature", "name=" + FEATURE])["stdout"])["result"]["data"] == 1 for u in (a, b))
                chrome = step("chrome-wait", ["/usr/bin/test", "-f", "/var/cpanel/caches/_generated_header_files/cache_keys.json"])["exit_code"] == 0
                if feature_on and chrome:
                    ready_after = second
                    break
                time.sleep(3)
            summary["registration_ready_after_s"] = ready_after

            # WHM as root through a real session.
            whm = http("whm-root", "whm", "root", [["GET", "/cgi/ols-cpanel/index.cgi"], ["GET", "/cgi/ols-cpanel/index.cgi?api=status"],
                                                   ["GET", "/cgi/ols-cpanel/index.cgi?api=inventory"],
                                                   ["GET", "/cgi/ols-cpanel/index.cgi?api=../../etc/shadow"],
                                                   ["POST", "/cgi/ols-cpanel/index.cgi?api=status"]])
            page, status, inventory, bogus, post = results(whm)[:5]
            asset = json.loads((whm_tree / "manifest.json").read_text())["src/whm/main.js"]["file"]
            case("whm-page-renders-app", {k: page.get(k) for k in ("status", "content_type")},
                 page.get("status") == 200 and page.get("has_app_div"))
            case("whm-api-status", status.get("json"), status.get("status") == 200 and status.get("json", {}).get("ok"))
            users = {d["user"] for d in inventory.get("json", {}).get("result", {}).get("domains", [])}
            case("whm-api-inventory", sorted(users), inventory.get("status") == 200 and set(tf.TENANTS) <= users)
            case("whm-api-unknown-refused", bogus.get("status"), bogus.get("status") == 404)
            case("whm-api-post-refused", post.get("status"), post.get("status") == 405)
            assets = http("whm-asset", "whm", "root", [["GET", "/cgi/ols-cpanel/" + asset]])
            first = results(assets)[0]
            case("whm-asset-served", {k: first.get(k) for k in ("status", "content_type")},
                 first.get("status") == 200 and "javascript" in (first.get("content_type") or ""))
            # No session at all.
            anon = http("whm-anon", "whm", "root", [["GET", "!/cgi/ols-cpanel/index.cgi?api=inventory"]])
            first = results(anon)[0]
            case("whm-no-session-refused", {k: first.get(k) for k in ("status",)},
                 first.get("status") != 200 or "inventory" not in json.dumps(first.get("json", {})) and "domains" not in json.dumps(first))
            # A reseller without root ACLs.
            installed["reseller"] = True
            secret = uuid.uuid4().hex + "Aa1!"
            probe.api(step("reseller-create", [*UMASK_022, WHMAPI, "--output=json", "createacct", "username=" + RESELLER,
                                               "domain=" + RESELLER_DOMAIN, "password=" + secret, "contactemail=",
                                               "hasshell=0", "reseller=1"], 600), "createacct")
            reseller = http("whm-reseller", "whm", RESELLER, [["GET", "/cgi/ols-cpanel/index.cgi?api=inventory"],
                                                              ["GET", "/cgi/ols-cpanel/index.cgi"]])
            api, page = results(reseller)[:2]
            leaked = tf.TENANTS["olscpa"] in json.dumps(api) + json.dumps(page)
            case("whm-reseller-refused", {"api": api.get("status"), "page": page.get("status"), "leaked": leaked},
                 not leaked and api.get("status") != 200)
            # A local user executing the gateway with a forged REMOTE_USER: never reaches the broker.
            forged = step("forged-remote-user", ["/usr/sbin/runuser", "-u", a, "--", "/usr/bin/env", "-i", "REMOTE_USER=root",
                                                 "GATEWAY_INTERFACE=CGI/1.1", "REQUEST_METHOD=GET", "QUERY_STRING=api=inventory",
                                                 "SCRIPT_FILENAME=" + WHM_DIR + "/index.cgi", "REDIRECT_STATUS=200",
                                                 "/usr/local/cpanel/3rdparty/bin/php-cgi", WHM_DIR + "/index.cgi"])
            case("whm-forged-remote-user-local", forged["stdout"][-300:],
                 tf.TENANTS["olscpb"] not in forged["stdout"] and "BROKER_UNAVAILABLE" in forged["stdout"])
            # Diagnostic: cPanel's own answer for the feature, outside any session.
            summary["feature_cli"] = {u: json.loads(step("feature-cli-" + u, ["/usr/local/cpanel/bin/uapi", "--user=" + u,
                                      "--output=json", "Features", "has_feature", "name=" + FEATURE])["stdout"])["result"]["data"]
                                      for u in (a, b)}
            summary["featurelist_line"] = step("featurelist-file", ["/usr/bin/grep", "-h", FEATURE, "/var/cpanel/features/default"])["stdout"]
            # cPanel plugin as each tenant.
            for user in (a, b):
                other = b if user == a else a
                report = http("cpanel-" + user, "cpanel", user, [["GET", "/frontend/jupiter/ols_cpanel/index.live.php"],
                              ["GET", "/frontend/jupiter/ols_cpanel/index.live.php?api=domains"],
                              ["GET", f"/frontend/jupiter/ols_cpanel/index.live.php?api=domains&user={other}"],
                              ["GET", "/frontend/jupiter/ols_cpanel/index.live.php?api=htaccess"],
                              ["GET", "/frontend/jupiter/ols_cpanel/index.live.php?api=status"]])
                page, mine, forged_param, htaccess, status = results(report)[:5]
                rows = mine.get("json", {}).get("result", {}).get("domains", [])
                case(f"cpanel-{user}-page", page.get("status"), page.get("status") == 200 and page.get("has_app_div"))
                case(f"cpanel-{user}-own-domains", [r["domain"] for r in rows], rows and all(r["user"] == user for r in rows))
                frows = forged_param.get("json", {}).get("result", {}).get("domains", [])
                case(f"cpanel-{user}-forged-user-ignored", [r["user"] for r in frows], frows and all(r["user"] == user for r in frows))
                files = htaccess.get("json", {}).get("result", {}).get("files", [])
                case(f"cpanel-{user}-htaccess", {"files": [f["path"] for f in files][:20],
                                                 "blockers": sum(len(f["blockers"]) for f in files)},
                     htaccess.get("status") == 200 and files and all(f["path"].startswith("~/") for f in files))
                case(f"cpanel-{user}-status", status.get("json"), status.get("json", {}).get("ok"))
            # Feature disabled in the account's feature list: menu gone and API refused.
            probe.api(step("feature-off", [*UMASK_022, WHMAPI, "--output=json", "update_featurelist", "featurelist=default", f"{FEATURE}=0"]),
                      "update_featurelist")
            off = http("cpanel-feature-off", "cpanel", a, [["GET", "/frontend/jupiter/ols_cpanel/index.live.php?api=domains"]])
            first = results(off)[0]
            case("cpanel-feature-disabled-refused", {"status": first.get("status"), "json": first.get("json")},
                 first.get("status") == 403 and tf.TENANTS["olscpa"] not in json.dumps(first))
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if original_feature is not None:
                step("feature-restore", [*UMASK_022, WHMAPI, "--output=json", "update_featurelist", "featurelist=default",
                                         f"{FEATURE}={original_feature}"])
            if installed["reseller"]:
                step("reseller-remove", [*UMASK_022, WHMAPI, "--output=json", "removeacct", "user=" + RESELLER], 600)
            if installed["cpanel"]:
                step("uninstall-plugin", [*UMASK_022, "/usr/local/cpanel/scripts/uninstall_plugin", str(archive), "--theme", "jupiter"])
                step("cpanel-remove", ["/usr/bin/rm", "-rf", CPANEL_DIR])
            if installed["whm"]:
                step("unregister", [*UMASK_022, "/usr/local/cpanel/bin/unregister_appconfig", "ols-cpanel"])
                step("whm-remove", ["/usr/bin/rm", "-rf", WHM_DIR, WHM_ICON])
            if installed["broker"]:
                step("broker-stop", ["/usr/bin/systemctl", "stop", BROKER_UNIT])
                step("broker-remove", ["/usr/bin/rm", "-rf", "/usr/local/ols-cpanel"])
                step("state-remove", ["/usr/bin/rm", "-rf", STATE] if installed["state"] else ["/usr/bin/rm", "-f", STATE + "/broker-audit.log"])
            summary["removed"] = not step("final-residue", ["/usr/bin/ls", "-d", WHM_DIR, CPANEL_DIR, "/usr/local/ols-cpanel",
                                                            "/run/ols-cpanel-broker", WHM_ICON])["stdout"].strip()
            listed = probe.api(step("listaccts-end", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {}).get("acct", [])
            summary["accounts_after"] = sorted(x["user"] for x in listed)
            summary["passed"] = sum(c["pass"] for c in summary["cases"].values())
            summary["total"] = len(summary["cases"])
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "passed": summary["passed"],
                              "total": summary["total"], "removed": summary["removed"],
                              "accounts_after": summary["accounts_after"], "error": summary.get("error")}))
    return 0 if summary["result"] == "observed" and summary["passed"] == summary["total"] else 1

if __name__ == "__main__":
    sys.exit(main())
