#!/usr/bin/python3
"""G0-A A6 reboot experiment, in two phases because a reboot ends this session.

--arm: on the empty lab, install the product OLS package, hand 80/443 to it (Apache disabled
through configureservice), enable ols-cpanel.service at boot, add the custom chkservd monitor,
and install two persistent root units: a one-shot post-boot verifier that records the observed
state and then returns the host to Apache, and a fallback timer that restores Apache 15 minutes
after boot if the verifier did not finish. The operator then reboots.

--collect: after the reboot, copy the verifier's result into local evidence and check that the
host is back on Apache with no residue. NOT a G0 certificate."""
import argparse
import fcntl
import json
import os
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import service_probe as probe

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES = pathlib.Path(__file__).resolve().parent / "ols-lab"
STATE = "/var/lib/ols-cpanel-lab-reboot"
VERIFY_UNIT = "ols-cpanel-lab-postboot.service"
FALLBACK_UNIT = "ols-cpanel-lab-fallback"
UNIT_DIR = "/etc/systemd/system"

# Fixed root-owned scripts; they never import the development checkout.
VERIFY = r"""#!/bin/sh
# Post-boot verifier for the OLS-cPanel A6 experiment. Records, then returns to Apache.
S=/var/lib/ols-cpanel-lab-reboot
exec >"$S/verify.log" 2>&1
sleep 45
{
  echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
  echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
  echo "ols_active=$(systemctl is-active ols-cpanel.service)"
  echo "ols_enabled=$(systemctl is-enabled ols-cpanel.service)"
  echo "httpd_active=$(systemctl is-active httpd.service)"
  echo "chkservd_httpd=$(grep -E '^httpd:' /etc/chkserv.d/chkservd.conf)"
  echo "chkservd_olscpanel=$(grep -E '^olscpanel:' /etc/chkserv.d/chkservd.conf)"
  echo "http_body=$(curl --noproxy '*' -s --max-time 10 http://127.0.0.1/)"
  echo "https_body=$(curl --noproxy '*' -ks --max-time 10 https://127.0.0.1/)"
  echo "nonce=$(cat $S/nonce)"
  echo "cpanel_version=$(cat /usr/local/cpanel/version)"
  echo "monitor_file=$(cat /etc/chkserv.d/olscpanel 2>/dev/null | head -c 200)"
  echo "whm_httpd=$(/usr/local/cpanel/bin/whmapi1 servicestatus service=httpd | grep -E 'enabled|monitored|running' | tr -s ' ' | tr '\n' ' ')"
  echo "listeners<<"
  ss -H -ltnp '( sport = :80 or sport = :443 )'
  echo ">>"
} >"$S/observed.txt"
/bin/sh "$S/restore.sh"
echo done >"$S/verified"
"""
RESTORE = r"""#!/bin/sh
# Return to Apache and remove every experiment artifact except the evidence directory.
S=/var/lib/ols-cpanel-lab-reboot
systemctl disable --now ols-cpanel.service ols-cpanel-logs.service
sed -i '/^olscpanel:/d' /etc/chkserv.d/chkservd.conf
rm -f /etc/chkserv.d/olscpanel
/usr/local/cpanel/bin/whmapi1 configureservice service=httpd enabled=1 monitored=1
/usr/local/cpanel/scripts/restartsrv_httpd
/usr/local/cpanel/scripts/restartsrv_chkservd
for i in $(seq 1 24); do rpm -q ols-cpanel-openlitespeed >/dev/null || break; rpm -e ols-cpanel-openlitespeed && break; sleep 5; done
rm -rf /usr/local/lsws /var/lib/ols-cpanel-lab /tmp/lshttpd /dev/shm/ols
systemctl disable ols-cpanel-lab-postboot.service ols-cpanel-lab-fallback.timer
rm -f /etc/systemd/system/ols-cpanel-lab-postboot.service /etc/systemd/system/ols-cpanel-lab-fallback.service \
      /etc/systemd/system/ols-cpanel-lab-fallback.timer
systemctl daemon-reload
echo "restored $(date -u +%FT%TZ)" >"$S/restored"
"""
VERIFY_SERVICE = f"""[Unit]
Description=OLS-cPanel lab A6 post-boot verifier
After=network-online.target ols-cpanel.service tailwatchd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh {STATE}/verify.sh
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
"""
FALLBACK_SERVICE = f"""[Unit]
Description=OLS-cPanel lab A6 fallback restore
ConditionPathExists=!{STATE}/restored

[Service]
Type=oneshot
ExecStart=/bin/sh {STATE}/restore.sh
"""
FALLBACK_TIMER = """[Unit]
Description=OLS-cPanel lab A6 fallback restore timer

[Timer]
OnBootSec=15min
AccuracySec=1s

[Install]
WantedBy=timers.target
"""

def parse_observed(text):
    values, listeners, inside = {}, [], False
    for line in text.splitlines():
        if line == "listeners<<":
            inside = True
        elif line == ">>":
            inside = False
        elif inside:
            listeners.append(line)
        elif "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    values["listeners"] = listeners
    return values

def evaluate(observed, armed_boot_id):
    nonce_page = "ols-owner " + observed.get("nonce", "")
    return {
        "rebooted": bool(observed.get("boot_id")) and observed.get("boot_id") != armed_boot_id,
        "ols_started_at_boot": observed.get("ols_active") == "active" and observed.get("ols_enabled") == "enabled",
        "apache_stayed_down": observed.get("httpd_active") != "active" and observed.get("chkservd_httpd") == "httpd:0",
        "monitor_present": observed.get("chkservd_olscpanel") == "olscpanel:1",
        "served_after_boot": observed.get("http_body") == nonce_page and observed.get("https_body") == nonce_page,
        "ols_owns_ports": bool(observed.get("listeners")) and all('"litespeed"' in l and '"httpd"' not in l
                                                                   for l in observed["listeners"]),
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--arm", action="store_true")
    phase.add_argument("--collect", action="store_true")
    parser.add_argument("--rpm", type=pathlib.Path)
    parser.add_argument("--rehearsal", action="store_true",
                        help="with --collect: the verifier was run by hand without a reboot")
    parser.add_argument("--lab-empty-host", action="store_true")
    args = parser.parse_args()
    if not args.lab_empty_host:
        parser.error("Reboot experiments require --lab-empty-host")
    if args.arm and not args.rpm:
        parser.error("--arm needs --rpm")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    os.umask(0o077)
    local = ROOT / "evidence/local"
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = local / ("ols-reboot-" + ("arm-" if args.arm else "collect-") + uuid.uuid4().hex)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        summary = {"schema_version": 1, "kind": "ols-reboot-experiment", "phase": "arm" if args.arm else "collect",
                   "started_at": probe.now(), "g0_a": "unproven", "result": "not_run"}
        index = 0
        restore_placed = False

        def step(name, command, limit=120):
            nonlocal index
            index += 1
            record = owner.invoke(command, limit)
            probe.durable_json(run / (str(index).zfill(2) + "-" + name + ".json"), record)
            return record

        def place(name, content, target, mode="0644"):
            path = run / name
            path.write_text(content)
            os.chmod(path, 0o644)
            if step("place-" + name, ["/usr/bin/install", "-m", mode, "-o", "root", "-g", "root", str(path), target])["exit_code"]:
                raise ValueError("Unable to place " + target)

        try:
            if args.arm:
                initial = {key: step("before-" + key, probe.COMMANDS[key]) for key in ("accounts_api", "account_entries", "http")}
                accounts = probe.api(initial["accounts_api"], "listaccts").get("data", {})
                if (accounts.get("acct", []) if isinstance(accounts, dict) else ["?"]) or initial["account_entries"]["stdout"] \
                        or initial["http"]["stdout"] != "200":
                    raise ValueError("Not the qualified empty lab baseline")
                if step("residue", ["/usr/bin/ls", "-d", "/usr/local/lsws", STATE])["stdout"].strip():
                    raise ValueError("Residue present")
                summary["armed_cpanel_version"] = step("cpanel-version", ["/usr/bin/cat", "/usr/local/cpanel/version"])["stdout"].strip()
                summary["armed_boot_id"] = step("boot-id", ["/usr/bin/cat", "/proc/sys/kernel/random/boot_id"])["stdout"].strip()
                summary["rpm_sha256"] = owner.invoke(["/usr/bin/sha256sum", str(args.rpm.resolve())])["stdout"].split()[0]
                step("state-dir", ["/usr/bin/install", "-d", "-m", "0700", STATE])
                nonce = uuid.uuid4().hex
                place("nonce", nonce + "\n", STATE + "/nonce", "0600")
                place("verify.sh", VERIFY, STATE + "/verify.sh", "0700")
                place("restore.sh", RESTORE, STATE + "/restore.sh", "0700")
                restore_placed = True
                # Fallback first: from here on, any failure is recoverable at the next boot.
                place("fallback.service", FALLBACK_SERVICE, f"{UNIT_DIR}/{FALLBACK_UNIT}.service")
                place("fallback.timer", FALLBACK_TIMER, f"{UNIT_DIR}/{FALLBACK_UNIT}.timer")
                place("postboot.service", VERIFY_SERVICE, f"{UNIT_DIR}/{VERIFY_UNIT}")
                step("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
                if step("enable-lab-units", ["/usr/bin/systemctl", "enable", f"{FALLBACK_UNIT}.timer", VERIFY_UNIT])["exit_code"]:
                    raise ValueError("Unable to enable lab units")
                if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                    raise ValueError("Product RPM install failed")
                step("place-config", ["/usr/bin/install", "-m", "0600", str(TEMPLATES / "ownership_httpd_config.conf"),
                                      "/usr/local/lsws/conf/httpd_config.conf"])
                step("dirs", ["/usr/bin/install", "-d", "-m", "0750", "/usr/local/lsws/conf/vhosts/owner", "/usr/local/lsws/conf/cert"])
                step("vhconf", ["/usr/bin/install", "-m", "0600", str(TEMPLATES / "ownership_vhconf.conf"),
                                "/usr/local/lsws/conf/vhosts/owner/vhconf.conf"])
                step("web", ["/usr/bin/install", "-d", "-m", "0755", owner.WEB, owner.WEB + "/html", owner.WEB + "/logs"])
                place("index.html", "ols-owner " + nonce + "\n", owner.WEB + "/html/index.html")
                place("health", "ok\n", owner.WEB + "/html/" + owner.HEALTH)
                step("cert", ["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
                              "-subj", "/CN=ols-cpanel-lab", "-keyout", "/usr/local/lsws/conf/cert/lab.key",
                              "-out", "/usr/local/lsws/conf/cert/lab.crt"])
                probe.api(step("disable-httpd", ["/usr/local/cpanel/bin/whmapi1", "--output=json", "configureservice",
                                                 "service=httpd", "enabled=0", "monitored=0"]), "configureservice")
                time.sleep(3)
                if step("enable-ols", ["/usr/bin/systemctl", "enable", "--now", owner.UNIT])["exit_code"]:
                    raise ValueError("OLS start failed")
                place("monitor", owner.MONITOR_LINE, owner.MONITOR)
                step("monitor-enable", ["/usr/bin/sh", "-c", f"grep -q '^olscpanel:' {owner.CHKSERV_CONF} || echo olscpanel:1 >> {owner.CHKSERV_CONF}"])
                step("restart-chkservd", ["/usr/local/cpanel/scripts/restartsrv_chkservd"])
                time.sleep(3)
                served = step("pre-reboot-http", ["/usr/bin/curl", "--noproxy", "*", "-s", "--max-time", "5", "http://127.0.0.1/"])
                if served["stdout"].strip() != "ols-owner " + nonce:
                    raise ValueError("OLS is not serving before reboot")
                summary["result"] = "armed"
                summary["next"] = "sudo systemctl reboot; after reconnecting run --collect"
            else:
                if step("verified", ["/usr/bin/cat", STATE + "/verified"])["stdout"].strip() != "done":
                    raise ValueError("Post-boot verifier has not finished (or the host was not rebooted)")
                observed = parse_observed(step("observed", ["/usr/bin/cat", STATE + "/observed.txt"])["stdout"])
                armed = sorted(local.glob("ols-reboot-arm-*/manifest.json"), key=lambda p: p.stat().st_mtime)[-1]
                armed_summary = json.loads(armed.read_text())
                summary["armed_run"] = armed.parent.name
                summary["observed"] = observed
                summary["checks"] = evaluate(observed, armed_summary.get("armed_boot_id"))
                if args.rehearsal:
                    # Same boot by design; everything else must hold.
                    summary["checks"]["rebooted"] = observed.get("boot_id") == armed_summary.get("armed_boot_id")
                    summary["rehearsal"] = True
                summary["verify_log"] = step("verify-log", ["/usr/bin/cat", STATE + "/verify.log"])["stdout"][-2000:]
                summary["restored_marker"] = step("restored", ["/usr/bin/cat", STATE + "/restored"])["stdout"].strip()
                summary["final"] = {"http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200",
                                    "residue": not step("final-residue", ["/usr/bin/ls", "-d", "/usr/local/lsws", owner.MONITOR,
                                                                          f"{UNIT_DIR}/{VERIFY_UNIT}"])["stdout"].strip()}
                summary["result"] = "pass" if all(summary["checks"].values()) and all(summary["final"].values()) else "fail"
                if all(summary["final"].values()):
                    step("remove-state", ["/usr/bin/rm", "-rf", STATE])
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
            if args.arm and restore_placed:
                # Never leave a half-armed host: restore now instead of waiting for a reboot.
                step("restore-after-failure", ["/bin/sh", STATE + "/restore.sh"], 300)
        summary["finished_at"] = probe.now()
        probe.durable_json(run / "manifest.json", summary)
        print(json.dumps({"path": str(run), "result": summary["result"], "error": summary.get("error"),
                          "checks": summary.get("checks"), "next": summary.get("next")}))
    return 0 if summary["result"] in ("armed", "pass") else 1

if __name__ == "__main__":
    sys.exit(main())
