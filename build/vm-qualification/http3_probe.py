#!/usr/bin/python3
"""FV-04 lab experiment (HTTP/3, plan section 21.6): the compiled configuration for the lab tenants is served by the
product OLS build on the test listeners (Apache keeps 80/443; the TLS test listeners are 127.0.0.1 and the host side of
the client namespace on TLS_PORT, QUIC being the same address and port over UDP). The lab's own curl (7.76) has no
HTTP/3, so the HTTP/3 client is a pinned container image whose curl does (podman, the client network namespace joined
with --network ns:), pulled by digest before the first change and removed again by the recovery.

Declared outcomes (expected_outcomes): QUIC UDP sockets are owned by OLS on the TLS test listeners and on no other
port; its shared state lives under /run/ols-cpanel/shm, never /dev/shm; HTTPS responses advertise Alt-Svc for h3 on the
listener's port and plain HTTP does not; for a PHP page and a static file on three vhosts (two accounts) the HTTP/3
response equals the HTTP/2 response (status, size, body digest, a header subset) and is really HTTP/3; the certificate
served over QUIC is the vhost's own, equal to the one served over TCP, and differs between accounts (SNI is chosen
per vhost for QUIC as for TLS); the access logs (cPanel's domlogs) carry the HTTP/3 and HTTP/2 lines of each request in
the right vhost's log and nowhere else, classified by the product's parser (http3.py) with the share it computes; with the
operator opt-out ({"enabled": false} compiled: quicEnable 0, enableQuic 0) there is no UDP socket, no Alt-Svc, HTTP/3
fails and HTTP/2 still answers; OLS logs no errors; and removal restores the tenants' files and the host exactly.

Changes, all undone by one recovery script armed in an independent systemd timer before the first change and run on the
normal return path: the OLS package and its files, the client network namespace, the HTTP/3 client image (when it was
not present before), and lab pages (as the tenants). Refuses to run when the plugin preview or any product state is
installed. The lab firewall must admit UDP on the test port from the client namespace like the TCP the other experiments
use; a firewall that drops it fails the HTTP/3 outcomes (that is the finding, not a defect of the experiment). NOT a G0
certificate."""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpanel_surface
import http3
import ols_ownership_probe as owner
import service_probe as probe
import tenant_fixtures as tf
import tenant_isolation_probe as iso

ROOT = pathlib.Path(__file__).resolve().parents[2]
LSWS = owner.LSWS
A, B = tf.TENANTS["olscpa"], tf.TENANTS["olscpb"]
SUB = tf.SUBDOMAIN  # tenant A's second vhost (docroot public_html/blog)
PORT, TLS_PORT = iso.PORT, iso.TLS_PORT
HOST_IP, NETNS = iso.HOST_IP, iso.NETNS
# The HTTP/3 client: Alpine with a curl built against ngtcp2 and nghttp3 (Docker Hub, last pushed 2023-09-02). Pinned by
# the digest of the multi-platform index; the linux/amd64 manifest it resolves to is recorded too. The experiment
# refuses to run unless the pulled image carries one of the two digests and its curl reports the HTTP3 feature.
IMAGE = {"repository": "docker.io/ymuski/curl-http3",
         "digest": "sha256:9eadfcaa6e541ef61880795c3044f7a603dd62fe5be5a3b45b5e154025c783de",
         "amd64_digest": "sha256:b9ba1d8477b2a5985e8c290bbd19f071363bcb143283317298cee81ab01ee8a7"}
IMAGE_REF = IMAGE["repository"] + "@" + IMAGE["digest"]
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PODMAN = "/usr/bin/podman"
STATE = "/var/lib/ols-cpanel"
RUN_STATE = "/run/ols-cpanel"
SHM_DIR = RUN_STATE + "/shm"
RECOVERY_ROOT = "/var/lib/ols-cpanel-lab-recovery"
LOCK = "/run/ols-cpanel-recover.lock"
# Anything the plugin preview (plugin_preview.sh) or a product installation leaves behind.
PREVIEW = ["/usr/local/ols-cpanel", "/etc/systemd/system/ols-cpanel-broker.service",
           "/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel", "/usr/local/cpanel/base/frontend/jupiter/ols_cpanel", STATE, RUN_STATE]
# Lab pages: a deterministic PHP page (no nonce, no protocol: HTTP/2 and HTTP/3 must give identical bytes) and a static
# file larger than one QUIC flight.
PAGE, STATIC = "olscp-h3.php", "olscp-h3.txt"
PAGE_PHP = ("<?php header('Content-Type: text/plain'); header('X-Olscp-Lab: ' . posix_getpwuid(posix_geteuid())['name']);\n"
            "echo 'owner=' . posix_getpwuid(posix_geteuid())['name'] . ' host=' . ($_SERVER['HTTP_HOST'] ?? '') . \"\\n\";\n")
STATIC_TEXT = "".join(f"olscp-h3 static line {n:06d} " + "abcdefghij" * 3 + "\n" for n in range(9000))
PAGES = {A: ("olscpa", "/home/olscpa/public_html"), SUB: ("olscpa", "/home/olscpa/public_html/blog"),
         B: ("olscpb", "/home/olscpb/public_html")}
URLS = {"php": "/" + PAGE, "static": "/" + STATIC}
DOMLOGS = cpanel_surface.DOMLOGS
SUBSET = ("content-type", "content-length", "etag", "last-modified", "content-encoding", "accept-ranges", "x-olscp-lab")
META = "\nCURLMETA %{http_code} %{http_version} %{size_download}\n"

def parse_curl(record):
    """{status, version, size, body_sha256, headers, alt_svc, exit_code} from a curl run with `-D /dev/stderr -o /dev/stdout
    -w META`: the body then the metadata line on stdout, the headers (the last block after any 1xx) on stderr."""
    out = record.get("stdout") or ""
    body, sep, meta = out.rpartition("\nCURLMETA ")
    fields = meta.split() if sep else []
    if not sep:
        body = out
    blocks = [b for b in (record.get("stderr") or "").replace("\r\n", "\n").split("\n\n") if re.match(r"^\s*HTTP/\S+ \d{3}", b)]
    headers = {}
    if blocks:
        for line in blocks[-1].strip().split("\n")[1:]:
            key, _, value = line.partition(":")
            if _:
                headers.setdefault(key.strip().lower(), value.strip())
    return {"exit_code": record.get("exit_code"), "status": fields[0] if len(fields) >= 3 else "",
            "version": fields[1] if len(fields) >= 3 else "", "size": int(fields[2]) if len(fields) >= 3 and fields[2].isdigit() else None,
            "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest() if sep else None,
            "headers": {k: headers[k] for k in sorted(headers) if k in SUBSET}, "alt_svc": headers.get("alt-svc")}

CERT_LINE = re.compile(r"^\*\s+(subject|issuer|start date|expire date):\s*(.*?)\s*$", re.M)

def parse_certificate(stderr):
    """The server certificate curl -v prints: subject, issuer and validity dates (the last of each)."""
    found = {}
    for key, value in CERT_LINE.findall(stderr or ""):
        found[key.replace(" ", "_")] = value
    return found

def pins_ready(image=IMAGE):
    """Names of the pinned digests that are not recorded."""
    return sorted(k for k in ("digest", "amd64_digest") if not SHA256.match(image.get(k) or ""))

def comparable(h2, h3):
    """The two responses' comparable parts. The header subset is compared as sent; content-length only when both
    carry one (the framing of a dynamic body may differ by protocol, its bytes may not)."""
    shared = {"content-length"} if "content-length" in h2["headers"] and "content-length" in h3["headers"] else set()
    cut = lambda entry: (entry.get("status"), entry.get("size"), entry.get("body_sha256"),
                         tuple(sorted((k, v) for k, v in (entry.get("headers") or {}).items() if k != "content-length" or k in shared)))
    return cut(h2), cut(h3)

def expected_outcomes(summary):
    """Pass/fail per declared outcome of a completed run (review RV-06)."""
    obs = summary.get("observations") or {}
    get = lambda key: obs.get(key) or {}
    pairs = obs.get("pairs") or []
    udp = get("udp_on")
    off = get("opt_out")
    certs = get("certificates")
    logs = get("log_lines")
    share = {row["vhost"]: row for row in obs.get("share") or []}
    n_req = {}
    for pair in pairs:
        n_req[pair["vhost"]] = n_req.get(pair["vhost"], 0) + 1
    alt = lambda value: bool(value) and re.search(r'(^|,\s*)h3=":%d"' % TLS_PORT, value) is not None
    def tls_pairs_equal(pair):
        h2, h3 = pair["h2"], pair["h3"]
        return (h2["status"] == "200" and h3["status"] == "200" and h2["version"] == "2" and h3["version"] == "3"
                and comparable(h2, h3)[0] == comparable(h2, h3)[1] and h2["body_sha256"] is not None and h2["size"] and h2["size"] > 0)
    def lines_ok(host):
        rows = logs.get(host) or []
        want = n_req.get(host, 0)
        return (len(rows) == 2 * want and want > 0
                and all(http3.classify(r["line"]) == {"h2": "h2", "h3": "h3"}[r["via"]] for r in rows)
                and sum(1 for r in rows if r["via"] == "h3") == want and sum(1 for r in rows if r["via"] == "h2") == want
                and all(r["file"] in (host, host + "-ssl_log") for r in rows))
    hosts = sorted(PAGES)
    cases = {
        "client-supports-http3": "HTTP3" in (get("client").get("features") or "") and bool(summary.get("image_verified")),
        "quic-udp-on-tls-listeners": sorted(udp.get("tls") or []) == sorted([f"127.0.0.1:{TLS_PORT}", f"{HOST_IP}:{TLS_PORT}"])
                                     and udp.get("other") == [] and udp.get("owned_by_ols") is True,
        "quic-state-under-run": bool(get("shm").get("run_files")) and get("shm").get("dev_shm_files") == [],
        "alt-svc-on-https": bool(pairs) and all(alt(p["h2"]["alt_svc"]) and alt(p["h3"]["alt_svc"]) for p in pairs),
        "no-alt-svc-on-http": get("plain_http").get("status") == "200" and not get("plain_http").get("alt_svc"),
        "http3-equals-http2": len(pairs) == 2 * len(PAGES) and {(p["vhost"], p["kind"]) for p in pairs}
                              == {(h, k) for h in PAGES for k in URLS} and all(tls_pairs_equal(p) for p in pairs),
        "static-file-served-in-full": any(p["kind"] == "static" for p in pairs)
                                      and all((p["h3"]["size"] or 0) > 100000 for p in pairs if p["kind"] == "static"),
        "per-vhost-certificate-over-quic": all((certs.get(h) or {}).get("h3", {}).get("subject")
                                                and (certs[h]["h3"] == certs[h]["h2"]) for h in hosts)
                                           and (certs.get(A) or {}).get("h3", {}).get("subject") != (certs.get(B) or {}).get("h3", {}).get("subject"),
        "http3-lines-in-right-vhost-log": all(lines_ok(h) for h in hosts),
        "protocol-share": all((share.get(h) or {}).get("h3", 0) >= n_req.get(h, 0) > 0 and (share[h]["share_bp"]["h3"] > 0)
                              and (share[h]["share_bp"]["h2"] > 0) for h in hosts),
        "opt-out-no-quic": off.get("udp_tls") == [] and off.get("h3_exit") not in (None, 0) and not off.get("alt_svc")
                           and off.get("h2_status") == "200" and off.get("h2_version") == "2",
        "no-ols-errors": summary.get("ols_log_errors") == [],
        "tenant-files-restored": bool(summary.get("files_before")) and summary.get("files_after") == summary.get("files_before"),
        "host-restored": bool(summary.get("restored")) and all(summary["restored"].values()),
    }
    return cases

def recovery_script(backup, image_pulled):
    """POSIX shell run as root: undoes every change of the experiment and verifies it. Fixed paths only (it never
    imports the development checkout); tenant paths are handled as the tenant."""
    q = shlex.quote
    pages = [f"{d}/{p}" for _, (_, d) in PAGES.items() for p in (PAGE, STATIC)]
    user_of = lambda path: "olscpb" if path.startswith("/home/olscpb/") else "olscpa"
    lines = ["#!/bin/sh", "# OLS-cPanel HTTP/3 lab recovery: every experiment change undone.", f"B={q(backup)}",
             "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "T='timeout 120'", f"exec 9>{LOCK}",
             "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }",
             "restore() {", "    $T systemctl stop ols-cpanel.service ols-cpanel-logs.service 2>/dev/null",
             "    if rpm -q ols-cpanel-openlitespeed >/dev/null 2>&1; then $T rpm -e ols-cpanel-openlitespeed; fi",
             f"    rm -rf {LSWS} {owner.WEB} {RUN_STATE} /dev/shm/ols /tmp/lshttpd {STATE}", "    $T systemctl daemon-reload"]
    for path in pages:
        lines.append(f"    timeout 60 runuser -u {user_of(path)} -- rm -f -- {q(path)}")
    if image_pulled:
        lines.append(f"    $T {PODMAN} rmi --force {q(IMAGE_REF)} >/dev/null 2>&1")
    lines += [f"    ip netns delete {NETNS} 2>/dev/null; ip link delete {iso.HOST_IF} 2>/dev/null", "    return 0", "}",
              "verified() {", f"    for p in {LSWS} {owner.WEB} {STATE} {RUN_STATE}; do test ! -e \"$p\" || return 1; done"]
    for path in pages:
        lines.append(f"    timeout 60 runuser -u {user_of(path)} -- test ! -e {q(path)} || return 1")
    if image_pulled:
        lines.append(f"    {PODMAN} image exists {q(IMAGE_REF)} && return 1")
    lines += [f"    ip netns list | grep -qw {NETNS} && return 1",
              "    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
              "    case \"$code\" in [1-4]??) return 0;; esac", "    return 1", "}",
              "for attempt in 1 2 3 4 5; do", "    restore", "    if verified; then echo recovered; exit 0; fi", "    sleep 15", "done",
              "echo 'recovery incomplete' >&2", "exit 1", ""]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--lab-tenants", action="store_true")
    args = parser.parse_args()
    if not args.lab_tenants:
        parser.error("Places lab pages in the lab tenants and pulls a container image; --lab-tenants is required")
    if os.geteuid() == 0:
        parser.error("Run as the development user; privileged steps use sudo -n")
    missing = pins_ready()
    if missing:
        parser.error("record the image digests first (IMAGE): " + ", ".join(missing))
    os.umask(0o077)
    local = ROOT / "evidence/local"
    local.mkdir(exist_ok=True, parents=True)
    with (local / "service-probe.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        token = run_id[:12]
        run = local / ("http3-" + run_id)
        run.mkdir(mode=0o700)
        os.chmod(run, 0o711)
        recovery_unit = "ols-cpanel-lab-recover-" + run_id
        summary = {"schema_version": 1, "kind": "http3-experiment", "started_at": probe.now(), "result": "not_run",
                   "recovery_unit": recovery_unit, "image": IMAGE, "observations": {}}
        obs = summary["observations"]
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

        def in_namespace(command):
            return ["/usr/sbin/ip", "netns", "exec", NETNS, *command]

        def curl_args(host, path, port, scheme, version, extra=()):
            return ["--noproxy", "*", "-sk", "--max-time", "30", version, "-D", "/dev/stderr", "-o", "/dev/stdout", "-w", META, *extra,
                    "--resolve", f"{host}:{port}:{HOST_IP}", f"{scheme}://{host}:{port}{path}"]

        def over_h2(label, host, path, port=TLS_PORT, scheme="https", extra=()):
            version = "--http2" if scheme == "https" else "--http1.1"
            record = step(label, in_namespace(["/usr/bin/curl", *curl_args(host, path, port, scheme, version, extra)]), 60)
            return parse_curl(record)

        def over_h3(label, host, path, port=TLS_PORT, extra=()):
            record = step(label, [PODMAN, "run", "--rm", "--network", f"ns:/var/run/netns/{NETNS}", "--entrypoint", "curl", IMAGE_REF,
                                  *curl_args(host, path, port, "https", "--http3-only", extra)], 90)
            return parse_curl(record)

        def certificate(label, host, h3):
            args_ = ["--noproxy", "*", "-skv", "--max-time", "30", "--http3-only" if h3 else "--http2", "-o", "/dev/null",
                     "--resolve", f"{host}:{TLS_PORT}:{HOST_IP}", f"https://{host}:{TLS_PORT}/"]
            command = ([PODMAN, "run", "--rm", "--network", f"ns:/var/run/netns/{NETNS}", "--entrypoint", "curl", IMAGE_REF, *args_]
                       if h3 else in_namespace(["/usr/bin/curl", *args_]))
            return parse_certificate(step(label, command, 90)["stderr"])

        def tenant_files():
            out = {}
            for user in tf.TENANTS:
                base = f"/home/{user}/public_html"
                listing = step("files-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", base, "-xdev",
                                                 "-printf", "%y %m %U %G %P\\n"], 300)
                digests = step("digests-" + user, ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", base, "-xdev", "-type",
                                                   "f", "-exec", "/usr/bin/sha256sum", "{}", "+"], 600)
                if listing["exit_code"] or digests["exit_code"]:
                    raise ValueError("cannot list the files of " + user)
                out[user] = sorted(listing["stdout"].splitlines()) + sorted(digests["stdout"].splitlines())
            return out

        def udp_sockets():
            record = step("ss-udp", ["/usr/sbin/ss", "-H", "-lunp"])
            return http3.udp_listeners(record["stdout"]) if record["exit_code"] == 0 else None

        def load(label, http3_on):
            compiled = iso.compile_lab(step, summary, http3=http3_on)
            iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])
            return compiled

        def log_lines(host):
            """The request lines of this run in the vhost's domlogs (plain and -ssl_log), with their file and `via`."""
            rows = []
            for suffix in ("", "-ssl_log"):
                record = step("grep-" + host + suffix, ["/usr/bin/grep", "-s", "-h", "--", f"run={token}", f"{DOMLOGS}/{host}{suffix}"])
                for line in record["stdout"].splitlines():
                    via = re.search(r"via=(h2|h3)", line)
                    if via:
                        rows.append({"file": host + suffix, "via": via.group(1), "line": line})
            return rows

        installed = armed = netns = pulled = False
        recovery_script_path = None
        try:
            data = probe.api(step("listaccts", probe.COMMANDS["accounts_api"]), "listaccts").get("data", {})
            if sorted(a["user"] for a in data.get("acct", [])) != sorted(tf.TENANTS):
                raise ValueError("Expected exactly the lab tenants")
            present = [p for p in [LSWS, owner.WEB, *PREVIEW] if step("residue", ["/usr/bin/test", "-e", p])["exit_code"] == 0]
            if present:
                raise ValueError("OLS, plugin preview or product state present: " + ", ".join(present))
            if step("netns-residue", ["/usr/sbin/ip", "netns", "exec", NETNS, "/usr/bin/true"])["exit_code"] == 0:
                raise ValueError("The client network namespace exists already")
            for who, directory in PAGES.values():
                for name in (PAGE, STATIC):
                    if step("collision", ["/usr/sbin/runuser", "-u", who, "--", "/usr/bin/test", "-e", f"{directory}/{name}"])["exit_code"] == 0:
                        raise ValueError(f"Refusing to overwrite {directory}/{name}")
            if step("podman-present", ["/usr/bin/test", "-x", PODMAN])["exit_code"] != 0:
                raise ValueError("podman is required for the HTTP/3 client")
            existed = step("image-before", [PODMAN, "image", "exists", IMAGE_REF])["exit_code"] == 0
            summary["image_present_before"] = existed
            summary["files_before"] = tenant_files()
            # Recovery before the first change (RV-27).
            backup = f"{RECOVERY_ROOT}/{run_id}"
            if step("recovery-dir", ["/usr/bin/install", "-d", "-m", "0700", backup])["exit_code"]:
                raise ValueError("Could not create the recovery directory")
            script = backup + "/recover.sh"
            if step("recovery-script", ["/usr/bin/install", "-m", "0700", stage_file("recover.sh", recovery_script(backup, not existed)),
                                        script])["exit_code"]:
                raise ValueError("Could not install the recovery script")
            if step("arm-recovery", ["/usr/bin/systemd-run", "--unit=" + recovery_unit, "--on-active=60min",
                                     "--timer-property=AccuracySec=1s", "/bin/sh", script])["exit_code"]:
                raise ValueError("Could not arm the recovery timer")
            recovery_script_path, armed = script, True
            netns = True
            iso.netns_up(step)
            # The client image, by digest, before the product is touched.
            if not existed:
                pulled = True
                if step("image-pull", [PODMAN, "pull", "--quiet", IMAGE_REF], 900)["exit_code"]:
                    raise ValueError("Could not pull the HTTP/3 client image " + IMAGE_REF)
            identity = step("image-digest", [PODMAN, "image", "inspect", "--format", "{{.Digest}}", IMAGE_REF])["stdout"].strip()
            summary["image_digest_seen"] = identity
            summary["image_verified"] = identity in (IMAGE["digest"], IMAGE["amd64_digest"])
            version = step("client-version", [PODMAN, "run", "--rm", "--network", "none", "--entrypoint", "curl", IMAGE_REF, "--version"], 120)
            obs["client"] = {"exit_code": version["exit_code"], "version": version["stdout"].splitlines()[:1],
                             "features": " ".join(line for line in version["stdout"].splitlines() if line.startswith("Features:"))}
            if not summary["image_verified"] or "HTTP3" not in obs["client"]["features"]:
                raise ValueError("The HTTP/3 client image is not the pinned one or its curl has no HTTP3 feature")
            for user, (who, directory) in PAGES.items():
                for name, text in ((PAGE, PAGE_PHP), (STATIC, STATIC_TEXT)):
                    if step("page", ["/usr/bin/install", "-m", "0644", "-o", who, "-g", who, stage_file(name, text), f"{directory}/{name}"])["exit_code"]:
                        raise ValueError(f"Could not place {directory}/{name}")
            compiled = load("on", True)
            installed = True
            if step("install", ["/usr/bin/rpm", "-i", str(args.rpm.resolve())])["exit_code"]:
                raise ValueError("Product RPM install failed")
            iso.place_configs(step, stage_file, compiled["config"], compiled["vhconf"])
            if step("recovery-timer-armed", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer"])["stdout"].strip() != "active":
                raise ValueError("The recovery timer is no longer armed")
            if step("start", ["/usr/bin/systemctl", "start", owner.UNIT, owner.LOGS_UNIT])["exit_code"]:
                raise ValueError("OLS start failed")
            time.sleep(5)
            # QUIC sockets, state directories.
            sockets = udp_sockets() or {}
            tls = sorted(a for a in sockets if a.endswith(f":{TLS_PORT}"))
            obs["udp_on"] = {"tls": tls, "other": sorted(a for a in sockets if a not in tls and any(n in ("litespeed", "openlitespeed", "lshttpd")
                                                                                                   for n in sockets[a])),
                             "owned_by_ols": bool(tls) and all(set(sockets[a]) <= {"litespeed", "openlitespeed", "lshttpd"} for a in tls)}
            run_files = step("shm-run", ["/usr/bin/find", SHM_DIR, "-maxdepth", "1", "-name", ".quicshm*"])["stdout"].split()
            dev_files = step("shm-dev", ["/usr/bin/find", "/dev/shm", "-name", ".quicshm*"])["stdout"].split()
            obs["shm"] = {"run_files": run_files, "dev_shm_files": dev_files}
            # HTTP/2 and HTTP/3 for the same requests; every request carries the run token and its protocol for the log check.
            obs["plain_http"] = over_h2("plain-http", A, URLS["php"] + f"?via=plain&run={token}", port=PORT, scheme="http")
            obs["pairs"] = []
            for host in PAGES:
                for kind, path in URLS.items():
                    h2 = over_h2(f"h2-{kind}", host, f"{path}?via=h2&run={token}")
                    h3 = over_h3(f"h3-{kind}", host, f"{path}?via=h3&run={token}")
                    obs["pairs"].append({"vhost": host, "kind": kind, "h2": h2, "h3": h3})
            # The certificate each transport serves for the vhost's name.
            obs["certificates"] = {host: {"h2": certificate(f"cert-h2-{host}", host, False), "h3": certificate(f"cert-h3-{host}", host, True)}
                                   for host in PAGES}
            # Accounting: the product's domlogs. The log shipper writes them asynchronously; wait until every line is there.
            # Each vhost's log must hold exactly its own requests (one HTTP/2 and one HTTP/3 line per URL): a line in the
            # wrong vhost's log changes both counts.
            deadline = time.time() + 60
            while True:
                obs["log_lines"] = {host: log_lines(host) for host in PAGES}
                if all(len(obs["log_lines"][h]) >= 2 * len(URLS) for h in PAGES) or time.time() > deadline:
                    break
                time.sleep(5)
            share = step("share", ["/usr/bin/python3", "-I", str(pathlib.Path(__file__).resolve().parent / "http3.py"), "share", DOMLOGS,
                                   *PAGES, "--lines=5000"])
            obs["share"] = json.loads(share["stdout"]) if share["exit_code"] == 0 else []
            # The operator opt-out: compiled with quicEnable 0 and enableQuic 0, then restarted (QUIC is configured at start).
            load("off", False)
            if step("restart-off", ["/usr/bin/systemctl", "restart", owner.UNIT], 180)["exit_code"]:
                raise ValueError("OLS restart failed")
            time.sleep(5)
            sockets = udp_sockets() or {}
            h2_off = over_h2("off-h2", A, URLS["php"] + f"?via=h2&run={token}x")
            h3_off = step("off-h3", [PODMAN, "run", "--rm", "--network", f"ns:/var/run/netns/{NETNS}", "--entrypoint", "curl", IMAGE_REF,
                                     "--noproxy", "*", "-sk", "--max-time", "10", "--http3-only", "--resolve", f"{A}:{TLS_PORT}:{HOST_IP}",
                                     f"https://{A}:{TLS_PORT}{URLS['php']}"], 60)
            obs["opt_out"] = {"udp_tls": sorted(a for a in sockets if a.endswith(f":{TLS_PORT}")), "h3_exit": h3_off["exit_code"],
                              "alt_svc": h2_off["alt_svc"], "h2_status": h2_off["status"], "h2_version": h2_off["version"]}
            summary["result"] = "observed"
        except Exception as exc:
            summary["result"] = "fail"
            summary["error_type"] = type(exc).__name__
            summary["error"] = str(exc)[:500]
        finally:
            if installed:
                step("stop-ols", ["/usr/bin/systemctl", "stop", owner.UNIT, owner.LOGS_UNIT])
                log = step("ols-error-log", ["/usr/bin/tail", "-c", "200000", LSWS + "/logs/error.log"])["stdout"]
                summary["ols_log_errors"] = [l[27:] for l in log.splitlines() if "[ERROR]" in l][:40]
                summary["ols_quic_log"] = [l[27:] for l in log.splitlines() if "QUIC" in l.upper()][:40]
            if armed:
                record = step("recovery-run", ["/bin/sh", recovery_script_path], 900)
                summary["recovery_run"] = {"exit_code": record["exit_code"], "stdout": record["stdout"][-500:],
                                           "stderr": record["stderr"][-500:]}
            elif netns:
                iso.netns_down(step)
            restored = {"recovery_script": not armed or (summary.get("recovery_run") or {}).get("exit_code") == 0,
                        "residue": all(step("final-residue", ["/usr/bin/test", "-e", p])["exit_code"] != 0
                                       for p in [LSWS, owner.WEB, STATE, RUN_STATE]),
                        "package_absent": step("rpm-final", ["/usr/bin/rpm", "-q", "ols-cpanel-openlitespeed"])["exit_code"] != 0,
                        "image_removed": not pulled or step("image-final", [PODMAN, "image", "exists", IMAGE_REF])["exit_code"] != 0,
                        "http": step("final-http", probe.COMMANDS["http"])["stdout"] == "200"}
            if summary.get("files_before"):
                summary["files_after"] = tenant_files()
            summary["restored"] = restored
            if armed and all(restored.values()):
                stopped = step("disarm-recovery", ["/usr/bin/systemctl", "stop", recovery_unit + ".timer"])["exit_code"] == 0
                states = step("recovery-unit-state", ["/usr/bin/systemctl", "is-active", recovery_unit + ".timer",
                                                       recovery_unit + ".service"])["stdout"].split()
                restored["recovery_disarmed"] = stopped and all(s not in ("active", "activating") for s in states)
            if summary["result"] == "observed":
                cases = expected_outcomes(summary)
                summary["cases"] = {name: {"pass": bool(ok)} for name, ok in cases.items()}
                summary["result"] = "pass" if all(cases.values()) else "fail"
            summary["finished_at"] = probe.now()
            summary["file_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(run.iterdir()) if p.is_file()}
            probe.durable_json(run / "manifest.json", summary)
            print(json.dumps({"path": str(run), "result": summary["result"], "restored": restored,
                              "failed_cases": [k for k, v in (summary.get("cases") or {}).items() if not v["pass"]],
                              "error": summary.get("error")}))
    return 0 if summary["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
