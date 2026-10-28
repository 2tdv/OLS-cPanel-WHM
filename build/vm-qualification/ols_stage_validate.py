#!/usr/bin/python3
"""G0-B candidate validation: test a staged OLS configuration tree with the installed binary
inside private mount and network namespaces, so live PID, socket, shm and listener state is
never touched. Not an activation step and not a G0 certificate."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_config_lint

BINARY = "/usr/local/lsws/bin/openlitespeed"
LIVE_ROOT = "/usr/local/lsws"
# Read-only support the binary resolves relative to the server root.
SHARED = ["modules", "share", "lsrecaptcha", "lsns"]
WRITABLE = ["logs", "tmp", "cachedata", "autoupdate", "cgid", "admin/tmp", "admin/logs", "admin/cgid"]
# Private /tmp and /dev/shm; DEFAULT_TMP_DIR must exist for the test log. Every directory holding a log
# the candidate names is replaced by a private tmpfs too: "-t" opens access and error logs for writing,
# which would touch live log files and block forever on the log shipper's FIFOs when nothing reads them.
INNER = ('set -e; mount -t tmpfs -o mode=1777 tmpfs /tmp; mount -t tmpfs -o mode=1777 tmpfs /dev/shm; '
         # OLS patch 0009 keeps its runtime state in /run/ols-cpanel/lshttpd (statistics and shared memory in status and shm, RV-30): a private /run hides the live one.
         'mount -t tmpfs -o mode=0755 tmpfs /run; mkdir -p /run/ols-cpanel/lshttpd /run/ols-cpanel/status /run/ols-cpanel/shm /run/ols-cpanel/logs /tmp/lshttpd; for d in "$@"; do case "$d" in m:*) mount -t tmpfs -o mode=0755 tmpfs "${d#m:}" ;; '
         'd:*) mkdir -p "${d#d:}" ;; esac; done; exec "$0" -t')
LOG_LINE = re.compile(r"^\s*(?:accesslog|errorlog)\s+(/\S+)", re.MULTILINE)

def log_dirs(candidate):
    """Namespace setup for every access/error log directory the candidate configures: "m:<dir>" mounts a
    private tmpfs, "d:<dir>" creates a directory inside one. A directory that does not exist yet (e.g.
    /run/ols-cpanel/logs before the first start) is created under a tmpfs mounted on its nearest
    existing ancestor, so nothing is ever created or opened on the live filesystem."""
    texts = [(candidate / "httpd_config.conf").read_text()]
    texts += [p.read_text() for p in sorted(candidate.glob("vhosts/*/vhconf.conf"))]
    dirs = {os.path.dirname(path) for text in texts for path in LOG_LINE.findall(text) if "$" not in path}
    mounts, creates = set(), set()
    for d in dirs:
        if d.startswith("/run/"):
            creates.add(d)  # /run is already a private tmpfs in the namespace
            continue
        if d.startswith(("/tmp", "/dev/shm")) or d == "/":
            continue
        anchor = d
        while not os.path.isdir(anchor):
            anchor = os.path.dirname(anchor)
        if anchor == "/" or anchor.startswith(("/tmp", "/dev/shm")):
            continue  # nothing safe to mount over; "-t" reports the missing directory
        mounts.add(anchor)
        if anchor != d:
            creates.add(d)
    # A mount over an ancestor hides any deeper mount point, so keep only the outermost mounts.
    mounts = {m for m in mounts if not any(m != o and m.startswith(o.rstrip("/") + "/") for o in mounts)}
    return [f"m:{m}" for m in sorted(mounts)] + [f"d:{d}" for d in sorted(creates)]
FAILURE = re.compile(r"\[ERROR\]|Not support \[|failed to |Can not |Cannot |is not accessible|configuration failed",
                     re.IGNORECASE)
# Fail closed (review F-02): OLS skips a broken vhost with only a warning and keeps serving the rest, so
# every [WARN] is a finding unless it is one of these reviewed, harmless messages.
BENIGN_WARN = re.compile(r"\[WARN\].* (?:Uid|Gid) of \S+ is \d+, smaller than minimum requirement \d+, use server [ug]id!$")

def verdict(exit_code, text):
    findings = [line.strip() for line in text.splitlines()
                if FAILURE.search(line) or ("[WARN]" in line and not BENIGN_WARN.search(line.strip()))]
    return {"exit_code": exit_code, "findings": findings[:50], "valid": exit_code == 0 and not findings}

def stage(candidate, root, live=LIVE_ROOT):
    for name in WRITABLE:
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copytree(candidate, root / "conf", dirs_exist_ok=False)
    admin = candidate / "admin_config.conf"
    (root / "admin/conf").mkdir(parents=True)
    if admin.is_file():
        shutil.copy2(admin, root / "admin/conf/admin_config.conf")
    for name in SHARED:
        if pathlib.Path(live, name).exists():
            os.symlink(pathlib.Path(live, name), root / name)
    if not (root / "conf/mime.properties").exists():
        shutil.copy2(pathlib.Path(live, "conf/mime.properties"), root / "conf/mime.properties")

def tree_digest(path):
    digest = hashlib.sha256()
    for item in sorted(pathlib.Path(path).rglob("*")):
        if item.is_file() and not item.is_symlink():
            digest.update(str(item).encode() + b"\0" + item.read_bytes())
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=pathlib.Path,
                        help="directory holding httpd_config.conf, vhosts/ and optional admin_config.conf")
    parser.add_argument("--binary", default=BINARY)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root (sudo): namespaces and tmpfs mounts are required")
    binary = pathlib.Path(args.binary).resolve()
    if binary.is_relative_to("/tmp") or binary.is_relative_to("/dev/shm"):
        parser.error("binary must not live under /tmp or /dev/shm: they are replaced by private tmpfs mounts")
    candidate = args.candidate.resolve()
    if not (candidate / "httpd_config.conf").is_file():
        parser.error("candidate must contain httpd_config.conf")
    # Structural/product-policy lint first: the binary test does not validate listeners.
    lint_errors = ols_config_lint.lint((candidate / "httpd_config.conf").read_text())
    for vhconf in sorted(candidate.glob("vhosts/*/vhconf.conf")):
        lint_errors += [f"{vhconf.parent.name}: {e}" for e in ols_config_lint.lint(vhconf.read_text(), False)]
    if lint_errors:
        print(json.dumps({"exit_code": None, "findings": lint_errors, "valid": False, "stage": "lint",
                          "live_conf_unchanged": True}, indent=2))
        return 1
    live_conf = pathlib.Path(LIVE_ROOT, "conf")
    before = tree_digest(live_conf) if live_conf.is_dir() else None
    with tempfile.TemporaryDirectory(prefix="ols-stage-", dir="/var/tmp") as temp:
        root = pathlib.Path(temp, "root")
        stage(candidate, root)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "LSWS_HOME": str(root)}
        result = subprocess.run(["/usr/bin/unshare", "--mount", "--net", "--propagation", "private",
                                 "/bin/sh", "-c", INNER, str(binary), *log_dirs(candidate)],
                                env=env, capture_output=True, text=True, timeout=60, check=False)
        log = root / "logs/error.log"
        text = result.stdout + result.stderr + (log.read_text(errors="replace") if log.is_file() else "")
    report = verdict(result.returncode, text)
    report["output_tail"] = text.splitlines()[-15:]
    report["live_conf_unchanged"] = before == (tree_digest(live_conf) if live_conf.is_dir() else None)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] and report["live_conf_unchanged"] else 1

if __name__ == "__main__":
    sys.exit(main())
