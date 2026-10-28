#!/usr/bin/python3
"""FV-10 lab experiment (EasyApache 4 integration, plan section 21.6): with the product installed and OLS serving the lab
tenants, EasyApache 4 profiles are provisioned with cPanel's own tool (`/usr/local/bin/ea_install_profile --install`,
read from its usage text: `--install` resolves package conflicts and installs; without a flag it only resolves
conflicts) and the PHP environment applier (`ols-cpanel php env`, started by the rpm-lock path unit after every
transaction) must keep every EA4 PHP version complete: the recommended profile written by the product
(`/etc/cpanel/ea4/profiles/custom/ols-cpanel-recommended.json`), cPanel's "All PHP Options + OpCache" and
"cPanel Default + MPM ITK" (both remove or replace packages the product needs, or never carried them), and the NGINX
profile, which must be refused by the package conflict.

Declared outcomes (expected_outcomes): the product precondition holds (OLS serving 80/443, the PHP environment path and
timer units enabled, the recommended profile present); after each provisioning every lab vhost answers as before
(status and body of a static file; the PHP page runs through lsphp, sapi litespeed, as the tenant, with OPcache enabled
and the redis extension loaded) and answered at every sample while the applier was working; within the applier's deadline
(APPLIER_DEADLINE seconds after the transaction) `php env status` reports every installed EA4 PHP version complete, each
has an executable lsphp, OPcache loaded and redis loaded (`php -m`), and `ea-phpXX-php-litespeed` is installed; OLS logs
no errors (the journal of ols-cpanel.service and its error log) during the whole run; the NGINX profile fails with a
conflict, `ea-nginx` is not installed afterwards and the vhosts still answer; the original profile is provisioned again at
the end and the set of installed EA packages (name and version) equals the one recorded at the start, the temporary profile
files are gone and the recommended profile file is as before; lab pages are removed and the tenants' files are equal.

Changes, all undone by one recovery script armed in an independent systemd timer before the first change and run on the
normal return path: EA4 packages (by provisioning the recorded original profile again), a copy of the original profile in
the custom profile directory, and lab pages (as the tenants). Refuses to run unless the product serves (profile.json,
ols-cpanel.service active) and only the lab tenants exist. Run it only on the lab server. NOT a G0 certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shlex
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf

ROOT = pathlib.Path(__file__).resolve().parents[2]
A, B = tf.TENANTS["olscpa"], tf.TENANTS["olscpb"]
SUB = tf.SUBDOMAIN
PAGES = {A: ("olscpa", "/home/olscpa/public_html"), SUB: ("olscpa", "/home/olscpa/public_html/blog"), B: ("olscpb", "/home/olscpb/public_html")}
PHP_PAGE, STATIC_PAGE = "olscp-ea4.php", "olscp-ea4.txt"
PAGE_PHP = ("<?php header('Content-Type: application/json');\n"
            "$o = function_exists('opcache_get_status') ? @opcache_get_status(false) : false;\n"
            "echo json_encode(['sapi' => php_sapi_name(), 'user' => posix_getpwuid(posix_geteuid())['name'],\n"
            "  'opcache' => is_array($o) && ($o['opcache_enabled'] ?? false) === true, 'redis' => extension_loaded('redis')]), \"\\n\";\n")
STATIC_TEXT = "olscp ea4 static page\n"
CLI = "/usr/local/ols-cpanel/bin/ols-cpanel"
EA_INSTALL = "/usr/local/bin/ea_install_profile"
EA_CURRENT = "/usr/local/bin/ea_current_to_profile"
PROFILES = "/etc/cpanel/ea4/profiles"
CUSTOM = PROFILES + "/custom"
RECOMMENDED = CUSTOM + "/ols-cpanel-recommended.json"
ORIGINAL_NAME = "olscp-lab-original.json"
STATE = "/var/lib/ols-cpanel"
RECOVERY_ROOT = "/var/lib/ols-cpanel-lab-recovery"
LOCK = "/run/ols-cpanel-recover.lock"
OPT = "/opt/cpanel"
# What the applier is allowed after a transaction before the experiment calls it late: a dnf transaction of the profile
# itself can still be running when the tool returns, and a redis build of every version is the longest step.
APPLIER_DEADLINE = 1200
SAMPLE_SECONDS = 15
# (name, profile file, must be refused)
PHASES = [("recommended", RECOMMENDED, False), ("all-php-opcache", PROFILES + "/cpanel/allphp-opcache.json", False),
          ("mpm-itk", PROFILES + "/cpanel/mpm_itk.json", False), ("nginx", PROFILES + "/cpanel/default-nginx.json", True)]


def parse_page(text):
    """The lab PHP page's JSON, or {} when the answer is not that."""
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def answers_ok(row):
    """A vhost row ({static: {status, sha256}, php: {status, page}}) answers as the lab pages promise."""
    static, php = row.get("static") or {}, row.get("php") or {}
    page = php.get("page") or {}
    return (static.get("status") == "200" and static.get("sha256") == hashlib.sha256(STATIC_TEXT.encode()).hexdigest()
            and php.get("status") == "200" and page.get("sapi") == "litespeed" and page.get("opcache") is True and page.get("redis") is True
            and page.get("user") in ("olscpa", "olscpb"))


def versions_complete(env_status, probes):
    """Every installed EA4 PHP version complete in `php env status` and, probed on the server, with lsphp, OPcache, redis."""
    rows = (env_status or {}).get("versions") or []
    if not rows or any(r.get("status") != "complete" for r in rows):
        return False
    installed = {r.get("version") for r in rows}
    return (set(probes) == installed and all(p.get("lsphp") is True and p.get("opcache") is True and p.get("redis") is True
                                             and p.get("package") is True for p in probes.values()))


def parse_rpm_set(text):
    """`rpm -qa 'ea-*'` output as a sorted list of non-empty lines."""
    return sorted(line.strip() for line in text.splitlines() if line.strip())


def expected_outcomes(summary):
    """Pass/fail per declared outcome of a completed run (review RV-06)."""
    obs = summary.get("observations") or {}
    phases = obs.get("phases") or {}
    pre = obs.get("precondition") or {}
    baseline = obs.get("baseline") or {}
    refused = [p for p in PHASES if p[2]]
    served = [p for p in PHASES if not p[2]]
    cases = {
        "product-precondition": pre.get("serving") is True and pre.get("units") == {"ols-cpanel-php.path": True, "ols-cpanel-php.timer": True}
                                and pre.get("recommended_profile") is True,
        "baseline-answers": bool(baseline.get("vhosts")) and all(answers_ok(r) for r in baseline["vhosts"].values()),
        "baseline-complete": versions_complete(baseline.get("env"), baseline.get("probes") or {}),
    }
    for name, _, _ in served:
        ph = phases.get(name) or {}
        cases[f"{name}-provisioned"] = ph.get("exit_code") == 0
        cases[f"{name}-vhosts-answer"] = bool(ph.get("vhosts")) and all(answers_ok(r) for r in ph["vhosts"].values())
        cases[f"{name}-answered-throughout"] = ph.get("samples", 0) > 0 and ph.get("failed_samples") == []
        cases[f"{name}-complete-within-deadline"] = (ph.get("complete_after") is not None and ph["complete_after"] <= APPLIER_DEADLINE
                                                     and versions_complete(ph.get("env"), ph.get("probes") or {}))
    for name, _, _ in refused:
        ph = phases.get(name) or {}
        cases[f"{name}-refused"] = ph.get("exit_code") not in (None, 0) and ph.get("ea_nginx_installed") is False
        cases[f"{name}-vhosts-answer"] = bool(ph.get("vhosts")) and all(answers_ok(r) for r in ph["vhosts"].values())
        cases[f"{name}-product-intact"] = ph.get("product_installed") is True
    final = obs.get("final") or {}
    cases.update({
        "no-ols-errors": summary.get("ols_errors") == [],
        "original-profile-restored": bool(summary.get("ea_before")) and summary.get("ea_after") == summary.get("ea_before"),
        "recommended-profile-as-before": final.get("recommended_sha256") is not None and final.get("recommended_sha256") == obs.get("recommended_sha256_before"),
        "temporary-profiles-removed": final.get("custom_files") is not None and final.get("custom_files") == obs.get("custom_files_before"),
        "tenant-files-restored": bool(summary.get("files_before")) and summary.get("files_after") == summary.get("files_before"),
        "host-restored": bool(summary.get("restored")) and all(summary["restored"].values()),
    })
    return cases


def recovery_script(backup):
    """POSIX shell run as root: provisions the recorded original profile again, removes the experiment's files and verifies
    the EA package set against the recorded list. Fixed paths only (it never imports the development checkout)."""
    q = shlex.quote
    lines = ["#!/bin/sh", "# OLS-cPanel EA4 profile lab recovery: every experiment change undone.", f"B={q(backup)}",
             "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin", "T='timeout 3000'", f"exec 9>{LOCK}",
             "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }",
             "restore() {",
             f"    if ! rpm -qa 'ea-*' | sort | cmp -s - \"$B/ea-before.txt\"; then $T {EA_INSTALL} --install \"$B/original-profile.json\" >/dev/null 2>&1; fi"]
    for user, docroot in sorted({v for v in PAGES.values()}):
        lines.append(f"    timeout 60 runuser -u {user} -- rm -f -- {q(docroot + '/' + PHP_PAGE)} {q(docroot + '/' + STATIC_PAGE)}")
    lines += [f"    rm -f {q(CUSTOM + '/' + ORIGINAL_NAME)}", "    return 0", "}", "verified() {",
              "    rpm -qa 'ea-*' | sort | cmp -s - \"$B/ea-before.txt\" || return 1",
              f"    test ! -e {q(CUSTOM + '/' + ORIGINAL_NAME)} || return 1"]
    for user, docroot in sorted({v for v in PAGES.values()}):
        lines.append(f"    timeout 60 runuser -u {user} -- test ! -e {q(docroot + '/' + PHP_PAGE)} || return 1")
    lines += ["    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
              "    case \"$code\" in [1-4]??) return 0;; esac", "    return 1", "}",
              "for attempt in 1 2 3 4 5; do", "    restore", "    if verified; then echo recovered; exit 0; fi", "    sleep 30", "done",
              "echo 'recovery incomplete' >&2", "exit 1", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Provisions EasyApache 4 profiles (packages change); --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        run = local / ("ea4-profile-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "ea4-profile-experiment", "started_at": probe.now(), "result": "not_run",
                   "recovery_unit": recovery_unit, "applier_deadline_seconds": APPLIER_DEADLINE, "observations": {}}
        obs = summary["observations"]
        obs["phases"] = {}
        index = 0

        def step(name, command, limit=120):
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

        def exists(path):
            return step("exists", ["/usr/bin/test", "-e", path])["exit_code"] == 0

        def as_user(user, command, name="as-user", limit=120):
            return step(name, ["/usr/sbin/runuser", "-u", user, "--", *command], limit)

        def ea_packages():
            return parse_rpm_set(step("rpm-ea", ["/usr/bin/rpm", "-qa", "ea-*", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"])["stdout"])

        def fetch(host, path):
            record = step("curl", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "30", "--resolve", f"{host}:80:127.0.0.1",
                                   "-w", "\nCURLSTATUS %{http_code}", f"http://{host}{path}"], 60)
            body, _, status = record["stdout"].rpartition("\nCURLSTATUS ")
            return status.strip(), body

        def vhosts():
            rows = {}
            for host in PAGES:
                status, body = fetch(host, "/" + STATIC_PAGE)
                php_status, php_body = fetch(host, "/" + PHP_PAGE)
                rows[host] = {"static": {"status": status, "sha256": hashlib.sha256(body.encode()).hexdigest()},
                              "php": {"status": php_status, "page": parse_page(php_body)}}
            return rows

        def env_status():
            record = step("php-env-status", [CLI, "php", "env", "status", "--format=json"], 120)
            try:
                return json.loads(record["stdout"])
            except ValueError:
                return {}

        def installed_versions():
            names = step("opt", ["/usr/bin/ls", "-1", OPT])["stdout"].split()
            return sorted(n for n in names if re.fullmatch(r"ea-php\d{2,3}", n) and exists(f"{OPT}/{n}/root/usr/bin/php"))

        def probe_versions():
            out = {}
            for version in installed_versions():
                php = f"{OPT}/{version}/root/usr/bin/php"
                modules = step("php-m", [php, "-m"])["stdout"].lower().split()
                out[version] = {"lsphp": step("lsphp-x", ["/usr/bin/test", "-x", f"{OPT}/{version}/root/usr/bin/lsphp"])["exit_code"] == 0,
                                "opcache": "opcache" in modules,
                                "redis": "redis" in modules,
                                "package": step("rpm-ls", ["/usr/bin/rpm", "-q", f"{version}-php-litespeed"])["exit_code"] == 0}
            return out

        def tenant_files():
            out = {}
            for user in tf.TENANTS:
                base = f"/home/{user}/public_html"
                listing = as_user(user, ["/usr/bin/find", base, "-xdev", "-printf", "%y %m %U %G %P\\n"], "files-" + user, 300)
                digests = as_user(user, ["/usr/bin/find", base, "-xdev", "-type", "f", "-exec", "/usr/bin/sha256sum", "{}", "+"], "digests-" + user, 600)
                if listing["exit_code"] or digests["exit_code"]:
                    raise ValueError("cannot list the files of " + user)
                out[user] = sorted(listing["stdout"].splitlines()) + sorted(digests["stdout"].splitlines())
            return out

        def sha(path):
            record = step("sha", ["/usr/bin/sha256sum", path])
            return record["stdout"].split()[0] if record["exit_code"] == 0 and record["stdout"].split() else None

        def custom_files():
            return sorted(step("custom-ls", ["/usr/bin/ls", "-1", CUSTOM])["stdout"].split())

        armed = False
        recovery_script_path = None
        journal_since = "-1h"
        error_log = "/usr/local/lsws/logs/error.log"
        log_lines_before = 0
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            serving = (exists(STATE + "/profile.json") and step("ols-active", ["/usr/bin/systemctl", "is-active", "ols-cpanel.service"])["stdout"].strip() == "active")
            units = {u: step("unit-" + u, ["/usr/bin/systemctl", "is-enabled", u])["stdout"].strip() == "enabled"
                     for u in ("ols-cpanel-php.path", "ols-cpanel-php.timer")}
            obs["precondition"] = {"serving": serving, "units": units, "recommended_profile": exists(RECOMMENDED)}
            if not serving:
                raise ValueError("The product is not serving (profile.json and ols-cpanel.service are required)")
            for _, docroot in PAGES.values():
                for page in (PHP_PAGE, STATIC_PAGE):
                    if as_user(PAGES[A][0], ["/usr/bin/test", "-e", docroot + "/" + page], "lab-path")["exit_code"] == 0:
                        raise ValueError("Refusing to overwrite " + docroot + "/" + page)
            summary["files_before"] = tenant_files()
            summary["ea_before"] = ea_packages()
            obs["custom_files_before"] = custom_files()
            obs["recommended_sha256_before"] = sha(RECOMMENDED)
            backup = f"{RECOVERY_ROOT}/{run_id}"
            if step("recovery-dir", ["/usr/bin/install", "-d", "-m", "0700", backup])["exit_code"]:
                raise ValueError("Could not create the recovery directory")
            # The original profile: what is installed now, written by cPanel's own tool, copied away at once.
            if step("current-profile", [EA_CURRENT, "--output=" + CUSTOM + "/" + ORIGINAL_NAME], 300)["exit_code"]:
                raise ValueError("ea_current_to_profile failed")
            if step("keep-profile", ["/usr/bin/cp", "--", CUSTOM + "/" + ORIGINAL_NAME, backup + "/original-profile.json"])["exit_code"]:
                raise ValueError("Could not keep the original profile")
            if step("keep-list", ["/bin/sh", "-c", f"rpm -qa 'ea-*' --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' | sort > {shlex.quote(backup + '/ea-before.txt')}"])["exit_code"]:
                raise ValueError("Could not record the EA package list")
            script = backup + "/recover.sh"
            if step("recovery-script", ["/usr/bin/install", "-m", "0700", stage_file("recover.sh", recovery_script(backup)), script])["exit_code"]:
                raise ValueError("Could not install the recovery script")
            if step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=240min",
                                     "--timer-property=AccuracySec=1s", "/bin/sh", script])["exit_code"]:
                raise ValueError("Could not arm the recovery timer")
            recovery_script_path, armed = script, True
            for host, (user, docroot) in PAGES.items():
                for name, content in ((PHP_PAGE, PAGE_PHP), (STATIC_PAGE, STATIC_TEXT)):
                    if step("page", ["/usr/bin/install", "-m", "0644", "-o", user, "-g", user, stage_file(name, content), docroot + "/" + name])["exit_code"]:
                        raise ValueError("Could not place a lab page")
            obs["baseline"] = {"vhosts": vhosts(), "env": env_status(), "probes": probe_versions()}
            journal_since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            counted = step("error-log-lines", ["/usr/bin/wc", "-l", error_log])["stdout"].split()
            log_lines_before = int(counted[0]) if counted and counted[0].isdigit() else 0
            for name, profile, must_refuse in PHASES:
                ph = obs["phases"][name] = {"profile": profile}
                started = time.time()
                record = step("provision-" + name, [EA_INSTALL, "--install", profile], 3300)
                ph["exit_code"], ph["output_tail"] = record["exit_code"], (record["stdout"] + record["stderr"])[-400:]
                if must_refuse:
                    ph["ea_nginx_installed"] = step("rpm-nginx", ["/usr/bin/rpm", "-q", "ea-nginx"])["exit_code"] == 0
                    ph["product_installed"] = all(step("rpm-product", ["/usr/bin/rpm", "-q", p])["exit_code"] == 0
                                                  for p in ("ols-cpanel", "ols-cpanel-openlitespeed"))
                    ph["vhosts"] = vhosts()
                    continue
                # The applier's deadline counts from the end of the transaction; vhosts are sampled while it works.
                ph["samples"], ph["failed_samples"] = 0, []
                ended = time.time()
                ph["complete_after"] = None
                while time.time() - ended <= APPLIER_DEADLINE:
                    rows = vhosts()
                    ph["samples"] += 1
                    bad = [h for h, r in rows.items() if (r.get("static") or {}).get("status") != "200" or (r.get("php") or {}).get("status") not in ("200",)]
                    if bad:
                        ph["failed_samples"].append({"at": round(time.time() - started), "vhosts": bad})
                    env = env_status()
                    if versions_complete(env, probe_versions()):
                        ph["complete_after"] = round(time.time() - ended)
                        break
                    time.sleep(SAMPLE_SECONDS)
                ph["env"], ph["probes"], ph["vhosts"] = env_status(), probe_versions(), vhosts()
            obs["final"] = {}
            # Restore the original profile with the same tool, then let the applier finish.
            record = step("provision-original", [EA_INSTALL, "--install", backup + "/original-profile.json"], 3300)
            obs["final"]["restore_exit_code"] = record["exit_code"]
            step("env-repair", [CLI, "php", "env", "repair", "--format=json"], 3000)
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if armed:
                record = step("recovery-run", ["/bin/sh", recovery_script_path], 3600)
                summary["recovery_run"] = {"exit_code": record["exit_code"], "stdout": record["stdout"][-500:], "stderr": record["stderr"][-500:]}
            log = step("journal-ols", ["/usr/bin/journalctl", "-u", "ols-cpanel.service", "--since", journal_since,
                                       "--no-pager", "-o", "cat", "-p", "err"])["stdout"]
            tail = step("ols-error-log", ["/usr/bin/tail", "-n", f"+{log_lines_before + 1}", error_log])["stdout"]
            errors = "\n".join(l for l in tail.splitlines() if re.search(r"\[(ERROR|CRIT|ALERT|EMERG)\]", l))
            summary["ols_errors"] = [l for l in (log + "\n" + errors).splitlines() if l.strip()][:40]
            obs.setdefault("final", {})
            obs["final"]["recommended_sha256"] = sha(RECOMMENDED)
            obs["final"]["custom_files"] = custom_files()
            summary["ea_after"] = ea_packages()
            if summary.get("files_before"):
                summary["files_after"] = tenant_files()
            restored = {"recovery_script": not armed or (summary.get("recovery_run") or {}).get("exit_code") == 0,
                        "packages_equal": bool(summary.get("ea_before")) and summary["ea_after"] == summary["ea_before"],
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200",
                        "ols_active": step("final-ols", ["/usr/bin/systemctl", "is-active", "ols-cpanel.service"])["stdout"].strip() == "active"}
            summary["restored"] = restored
            if armed and all(restored.values()):
                stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])["exit_code"] == 0
                states = step("recovery-unit-state", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer", recovery_unit + ".service"])["stdout"].split()
                restored["recovery_disarmed"] = stopped and all(s not in ("active", "activating") for s in states)
            if summary["result"] == "observed":
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": restored,
                              "failed_cases": [k for k, v in (summary.get("cases") or {}).items() if not v["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
