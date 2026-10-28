#!/usr/bin/python3
"""Offline checks of the FV-10 lab experiment (build/vm-qualification/ea4_profile_probe.py): guards, page parsing, the recovery
script and every declared outcome against good and broken observations."""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ea4_profile_probe as ep

PROBE = str(ROOT / "build/vm-qualification/ea4_profile_probe.py")
result = subprocess.run([sys.executable, PROBE], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr

assert ep.parse_page('{"sapi": "litespeed"}') == {"sapi": "litespeed"} and ep.parse_page("nope") == {} and ep.parse_page("[1]") == {}
assert ep.parse_rpm_set("b-1\n\n a-2 \n") == ["a-2", "b-1"]
# Every phase profile is a real cPanel profile or the one the product writes; the NGINX one is the only refusal.
assert [p[0] for p in ep.PHASES if p[2]] == ["nginx"] and ep.PHASES[0][1] == ep.RECOMMENDED
assert ep.RECOMMENDED == "/etc/cpanel/ea4/profiles/custom/ols-cpanel-recommended.json"

script = ep.recovery_script("/var/lib/ols-cpanel-lab-recovery/1")
assert subprocess.run(["/bin/sh", "-n"], input=script, text=True).returncode == 0
assert "vm-qualification" not in script and "flock -w 900" in script and "exit 1" in script
for needle in ("ea_install_profile --install \"$B/original-profile.json\"", "cmp -s - \"$B/ea-before.txt\"",
               "runuser -u olscpa -- rm -f -- /home/olscpa/public_html/olscp-ea4.php", "runuser -u olscpb -- rm -f --",
               "rm -f /etc/cpanel/ea4/profiles/custom/olscp-lab-original.json"):
    assert needle in script, needle
assert "rm -rf /home" not in script and "\n    rm -rf --" not in script

static_sha = hashlib.sha256(ep.STATIC_TEXT.encode()).hexdigest()
row = lambda: {"static": {"status": "200", "sha256": static_sha},
               "php": {"status": "200", "page": {"sapi": "litespeed", "user": "olscpa", "opcache": True, "redis": True}}}
hosts = lambda: {ep.A: row(), ep.SUB: row(), ep.B: {**row(), "php": {"status": "200", "page": {"sapi": "litespeed", "user": "olscpb", "opcache": True, "redis": True}}}}
env = lambda: {"versions": [{"version": "ea-php82", "status": "complete"}, {"version": "ea-php83", "status": "complete"}]}
probes = lambda: {v: {"lsphp": True, "opcache": True, "redis": True, "package": True} for v in ("ea-php82", "ea-php83")}
phase = lambda: {"exit_code": 0, "vhosts": hosts(), "samples": 4, "failed_samples": [], "complete_after": 90, "env": env(), "probes": probes()}
good = {
    "ols_errors": [], "ea_before": ["a-1", "b-2"], "ea_after": ["a-1", "b-2"], "files_before": {"olscpa": ["f"]}, "files_after": {"olscpa": ["f"]},
    "restored": {"recovery_script": True, "packages_equal": True, "http": True, "ols_active": True, "recovery_disarmed": True},
    "observations": {
        "precondition": {"serving": True, "units": {"ols-cpanel-php.path": True, "ols-cpanel-php.timer": True}, "recommended_profile": True},
        "baseline": {"vhosts": hosts(), "env": env(), "probes": probes()},
        "phases": {"recommended": phase(), "all-php-opcache": phase(), "mpm-itk": phase(),
                   "nginx": {"exit_code": 1, "ea_nginx_installed": False, "product_installed": True, "vhosts": hosts()}},
        "final": {"recommended_sha256": "x", "custom_files": ["ols-cpanel-recommended.json"]},
        "recommended_sha256_before": "x", "custom_files_before": ["ols-cpanel-recommended.json"],
    },
}
cases = ep.expected_outcomes(good)
assert cases and all(cases.values()), [k for k, v in cases.items() if not v]
assert {"recommended-provisioned", "all-php-opcache-complete-within-deadline", "mpm-itk-answered-throughout", "nginx-refused", "no-ols-errors",
        "original-profile-restored", "host-restored"} <= set(cases)


def broken(mutate, expect):
    summary = copy.deepcopy(good)
    mutate(summary)
    failed = [k for k, v in ep.expected_outcomes(summary).items() if not v]
    assert expect in failed, (expect, failed)


broken(lambda s: s["observations"]["precondition"].update(serving=False), "product-precondition")
broken(lambda s: s["observations"]["precondition"]["units"].update({"ols-cpanel-php.timer": False}), "product-precondition")
broken(lambda s: s["observations"]["phases"]["recommended"].update(exit_code=1), "recommended-provisioned")
broken(lambda s: s["observations"]["phases"]["mpm-itk"]["vhosts"][ep.B]["php"]["page"].update(sapi="apache2handler"), "mpm-itk-vhosts-answer")
broken(lambda s: s["observations"]["phases"]["mpm-itk"]["vhosts"][ep.A]["php"]["page"].update(redis=False), "mpm-itk-vhosts-answer")
broken(lambda s: s["observations"]["phases"]["all-php-opcache"]["vhosts"][ep.A]["static"].update(sha256="0" * 64), "all-php-opcache-vhosts-answer")
broken(lambda s: s["observations"]["phases"]["all-php-opcache"].update(failed_samples=[{"at": 5, "vhosts": [ep.A]}]), "all-php-opcache-answered-throughout")
broken(lambda s: s["observations"]["phases"]["recommended"].update(complete_after=ep.APPLIER_DEADLINE + 1), "recommended-complete-within-deadline")
broken(lambda s: s["observations"]["phases"]["recommended"].update(complete_after=None), "recommended-complete-within-deadline")
broken(lambda s: s["observations"]["phases"]["recommended"]["probes"]["ea-php83"].update(lsphp=False), "recommended-complete-within-deadline")
broken(lambda s: s["observations"]["phases"]["recommended"]["env"]["versions"][0].update(status="failed"), "recommended-complete-within-deadline")
broken(lambda s: s["observations"]["phases"]["nginx"].update(exit_code=0), "nginx-refused")
broken(lambda s: s["observations"]["phases"]["nginx"].update(ea_nginx_installed=True), "nginx-refused")
broken(lambda s: s["observations"]["phases"]["nginx"].update(product_installed=False), "nginx-product-intact")
broken(lambda s: s.update(ols_errors=["[ERROR] x"]), "no-ols-errors")
broken(lambda s: s.update(ea_after=["a-1"]), "original-profile-restored")
broken(lambda s: s["observations"]["final"].update(custom_files=["olscp-lab-original.json"]), "temporary-profiles-removed")
broken(lambda s: s["observations"]["final"].update(recommended_sha256="y"), "recommended-profile-as-before")
broken(lambda s: s.update(files_after={"olscpa": ["g"]}), "tenant-files-restored")
broken(lambda s: s["restored"].update(http=False), "host-restored")
assert not any(ep.expected_outcomes({}).values()), "an empty run passes nothing"
print("ea4_profile_probe: guards, recovery script and every declared outcome checked.")
