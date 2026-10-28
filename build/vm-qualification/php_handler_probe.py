#!/usr/bin/python3
"""G0-D lab experiment for the PHP handlers that cannot run beside mod_ruid2 (owner decision HR-D05):
temporarily replaces mod_ruid2 with mod_suexec + mod_suphp + mod_fcgid (EA4 package conflicts), runs the
complete tenant isolation experiment once per handler with tenant B's PHP version on that handler, keeps
each run's PHP parity result, then restores the exact original EA4 Apache package set and handlers.
An independent timer restores the packages if this process dies. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = pathlib.Path(__file__).resolve().parent
WHMAPI = "/usr/local/cpanel/bin/whmapi1"
SWAP_IN = ["ea-apache24-mod_suexec", "ea-apache24-mod_suphp", "ea-apache24-mod_fcgid"]
RUID2 = "ea-apache24-mod_ruid2"
HANDLERS = ("suphp", "fcgi")
VERSION = "ea-php82"  # tenant B's PHP version (fixtures put it on a handler, not PHP-FPM)
# Fixed recovery (no checkout needed): back to mod_ruid2, the CGI handler and a running Apache.
RECOVERY = (f"dnf -y --allowerasing install {RUID2}; "
            f"{WHMAPI} php_set_handler version={VERSION} handler=cgi; /usr/local/cpanel/scripts/restartsrv_httpd")

def apache_packages(step, label):
    out = step(label + "-packages", ["/usr/bin/rpm", "-qa", "--qf", "%{NAME}\\n", "ea-apache24*"])["stdout"]
    return sorted(set(out.split()))

def handlers(step, label):
    data = probe.api(step(label + "-handlers", [WHMAPI, "--output=json", "php_get_handlers"]), "php_get_handlers")["data"]
    return {v["version"]: v["current_handler"] for v in data["version_handlers"]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Replaces Apache modules and runs the isolation experiment; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    run_id = uuid.uuid4().hex
    run = local / ("php-handlers-" + run_id)
    run.mkdir(mode=0o700, parents=True)
    os.chmod(run, 0o711)
    recovery_unit = "ols-cpanel-handler-recover-" + run_id
    summary = {"schema_version": 1, "kind": "php-handler-experiment", "started_at": probe.now(), "result": "not_run",
               "argv": sys.argv, "handlers": {}, "cases": {}}
    index = 0

    def step(name, command, limit=900):
        nonlocal index
        index += 1
        record = owner.invoke(command, limit)
        probe.durable_json(run / (str(index).zfill(3) + "-" + name + ".json"), record)
        return record

    def apache_serves_tenant_php():
        domain = tf.TENANTS["olscpb"]
        userdata = step("userdata-b", ["/usr/bin/cat", f"/var/cpanel/userdata/olscpb/{domain}"])["stdout"]
        address = next((l.split(":", 1)[1].strip() for l in userdata.splitlines() if l.startswith("ip:")), "")
        for _ in range(30):
            body = step("tenant-php", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "10",
                                       "--resolve", f"{domain}:80:{address}", f"http://{domain}/probe.php"])["stdout"]
            if '"user":"olscpb"' in body:
                return True
            time.sleep(4)
        return False

    armed = swapped = False
    original_packages = original_handlers = None
    try:
        with (local / "service-probe.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # nothing else may run; released for the children
        original_packages = apache_packages(step, "before")
        original_handlers = handlers(step, "before")
        summary["original"] = {"packages": original_packages, "handlers": original_handlers}
        if RUID2 not in original_packages or any(p in original_packages for p in SWAP_IN):
            raise ValueError("Expected the mod_ruid2 lab profile without suexec/suphp/fcgid")
        if not apache_serves_tenant_php():
            raise ValueError("Apache does not serve tenant B's PHP as the tenant before the experiment")
        armed = step("arm-recovery", ["/usr/bin/systemd-run", f"--unit={recovery_unit}", "--on-active=45min",
                                      "/bin/sh", "-c", RECOVERY])["exit_code"] == 0
        if not armed:
            raise ValueError("Unable to arm the independent recovery timer")
        swapped = True
        swap = step("swap-in", ["/usr/bin/dnf", "-y", "--allowerasing", "install", *SWAP_IN], 1200)
        summary["swap_exit"] = swap["exit_code"]
        if swap["exit_code"]:
            raise ValueError("Module swap failed: " + swap["stderr"][-300:])
        summary["swapped_packages"] = apache_packages(step, "swapped")
        for handler in HANDLERS:
            probe.api(step("set-" + handler, [WHMAPI, "--output=json", "php_set_handler", f"version={VERSION}",
                                              f"handler={handler}"]), "php_set_handler")
            entry = summary["handlers"][handler] = {"current": handlers(step, handler)}
            entry["apache_tenant_php"] = apache_serves_tenant_php()
            child = subprocess.run([sys.executable, str(TOOLS / "tenant_isolation_probe.py"), "--rpm",
                                    str(args.rpm.resolve()), "--lab-tenants"], capture_output=True, text=True, timeout=3600)
            try:
                result = json.loads(child.stdout.strip().splitlines()[-1])
                manifest = json.loads((pathlib.Path(result["path"]) / "manifest.json").read_text())
            except (ValueError, IndexError, KeyError, OSError):
                entry["error"] = (child.stdout + child.stderr)[-600:]
                continue
            parity = manifest.get("php_parity", {}).get("olscpb", {})
            entry.update(run=pathlib.Path(result["path"]).name, child_result=result.get("result"),
                         child_error=result.get("error"), restored=result.get("restored"), parity=parity,
                         leaks=manifest.get("passes", {}).get("native_fileprotect", {}).get("leaks"))
            summary["cases"][f"{handler}-parity"] = {"pass": bool(parity.get("equivalent"))
                                                     and parity.get("handler", "").startswith("cgi")}
            summary["cases"][f"{handler}-no-leaks"] = {"pass": entry["leaks"] == []}
        summary["result"] = "pass" if summary["cases"] and all(c["pass"] for c in summary["cases"].values()) else "fail"
    except Exception as exc:
        summary["result"] = "fail"
        summary["error_type"] = type(exc).__name__
        summary["error"] = str(exc)[:500]
    finally:
        if swapped:
            step("swap-back", ["/usr/bin/dnf", "-y", "--allowerasing", "install", RUID2], 1200)
            for version, handler in (original_handlers or {}).items():
                step("restore-handler-" + version, [WHMAPI, "--output=json", "php_set_handler", f"version={version}",
                                                    f"handler={handler}"])
            step("restart-httpd", ["/usr/local/cpanel/scripts/restartsrv_httpd"], 300)
        restored = {"packages": original_packages is None or apache_packages(step, "after") == original_packages,
                    "handlers": original_handlers is None or handlers(step, "after") == original_handlers,
                    "tenant_php": apache_serves_tenant_php()}
        summary["restored"] = restored
        if armed and all(restored.values()):
            step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])
            summary["recovery_disarmed"] = True
        if summary["result"] == "pass" and not all(restored.values()):
            summary["result"] = "fail"
        summary["finished_at"] = probe.now()
        summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()}
        probe.durable_json(run / "manifest.json", summary)
        print(json.dumps({"path": str(run), "result": summary["result"], "restored": summary.get("restored"),
                          "cases": {k: v["pass"] for k, v in summary["cases"].items()}, "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
