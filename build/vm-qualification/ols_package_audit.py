#!/usr/bin/python3
"""Read-only audit of a downloaded OLS RPM; never installs it or touches the system rpmdb."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
QUERY = ("%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{BUILDTIME}\n%{LICENSE}\n"
         "%{DSAHEADER:pgpsig}\n%{RSAHEADER:pgpsig}\n")
# Scriptlet behavior the product adapter must own instead of the vendor package.
RISKS = [
    ("starts-service", r"systemctl\s+(re)?start\s+lsws|service\s+lsws\s+(re)?start|lswsctrl\s+start"),
    ("enables-boot-service", r"rc-inst\.sh|systemctl\s+enable|update-rc\.d|chkconfig\s+--add"),
    ("prints-admin-secret", r"echo\s+\"WebAdmin user/password is"),
    ("creates-system-user", r"useradd|groupadd"),
    ("generates-key-material", r"openssl\s+req"),
]
WEAK_ALGORITHMS = ("DSA/",)
now = lambda: datetime.now(timezone.utc).isoformat()

def run(argv, stdin=None):
    result = subprocess.run(argv, input=stdin, capture_output=True, env=ENV, timeout=300, check=False)
    return result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()

def parse_checksig(text):
    signatures, digests = [], {}
    for line in text.splitlines():
        line = line.strip()
        match = re.fullmatch(r"Header V(\d) (\S+) Signature, key ID ([0-9a-f]{8}): (OK|NOKEY|BAD|NOTTRUSTED)", line)
        if match:
            signatures.append({"version": int(match[1]), "algorithm": match[2],
                               "key_id": match[3], "result": match[4]})
            continue
        match = re.fullmatch(r"(.+ digest): (OK|BAD)", line)
        if match:
            digests[match[1]] = match[2]
    if not signatures and not digests:
        raise ValueError("Unrecognized checksig output")
    return {"signatures": signatures, "digests": digests,
            "verified": bool(signatures) and all(s["result"] == "OK" for s in signatures)
                        and bool(digests) and all(v == "OK" for v in digests.values()),
            "weak_algorithm": any(s["algorithm"].startswith(WEAK_ALGORITHMS) for s in signatures)}

def parse_listeners(text):
    listeners, current = [], None
    for line in text.splitlines():
        match = re.match(r"\s*listener\s+(\S+?)\s*\{", line)
        if match:
            current = {"name": match[1]}
            continue
        if current is not None:
            if line.strip() == "}":
                listeners.append(current)
                current = None
                continue
            match = re.match(r"\s*(address|secure)\s+(\S+)", line)
            if match:
                current[match[1]] = match[2]
    if current is not None:
        raise ValueError("Unterminated listener block")
    for item in listeners:
        address = item.get("address", "")
        item["wildcard"] = address.startswith("*:") or address.startswith("[::]:")
    return listeners

def classify_scriptlets(text):
    return sorted({name for name, pattern in RISKS if re.search(pattern, text)})

def verdict(signature, risks, listeners, lsphp_requires):
    reasons = []
    if not signature["verified"]:
        reasons.append("signature-not-verified")
    if signature["weak_algorithm"]:
        reasons.append("weak-signature-algorithm-requires-pinned-digest")
    reasons += ["scriptlet-" + risk for risk in risks if risk in ("starts-service", "enables-boot-service",
                                                                  "prints-admin-secret")]
    if any(item["wildcard"] for item in listeners):
        reasons.append("default-wildcard-listener")
    if lsphp_requires:
        reasons.append("hard-requires-vendor-lsphp")
    blocking = [r for r in reasons if r != "weak-signature-algorithm-requires-pinned-digest"]
    return {"vendor_install_allowed": not blocking, "reasons": reasons,
            "payload_candidate": signature["verified"]}

def audit(rpm, expected, keys):
    actual = sha256(rpm)
    if actual != expected:
        raise ValueError("Artifact digest mismatch")
    with tempfile.TemporaryDirectory() as temp:
        db = pathlib.Path(temp, "rpmdb")
        db.mkdir()
        code, _, err = run(["/usr/bin/rpm", "--dbpath", str(db), "--initdb"])
        if code:
            raise ValueError("Private rpmdb init failed: " + err.strip())
        for key in keys:
            code, _, err = run(["/usr/bin/rpm", "--dbpath", str(db), "--import", str(key)])
            if code:
                raise ValueError("Key import failed: " + err.strip())
        _, out, err = run(["/usr/bin/rpmkeys", "--dbpath", str(db), "--checksig", "-v", str(rpm)])
        signature = parse_checksig(out + err)
        code, out, _ = run(["/usr/bin/rpm", "--dbpath", str(db), "-qp", "--qf", QUERY, str(rpm)])
        fields = out.split("\n")
        if code or len(fields) < 8:
            raise ValueError("Header query failed")
        _, requires, _ = run(["/usr/bin/rpm", "--dbpath", str(db), "-qp", "--requires", str(rpm)])
        _, scripts, _ = run(["/usr/bin/rpm", "--dbpath", str(db), "-qp", "--scripts", str(rpm)])
        payload = pathlib.Path(temp, "payload")
        payload.mkdir()
        cpio = subprocess.run(["/usr/bin/rpm2cpio", str(rpm)], capture_output=True, env=ENV, timeout=300, check=True)
        subprocess.run(["/usr/bin/cpio", "-idm", "--quiet", "--no-absolute-filenames"], input=cpio.stdout,
                       cwd=payload, env=ENV, timeout=300, check=True, capture_output=True)
        lsws = payload / "usr/local/lsws"
        listeners = []
        for name in ("conf/httpd_config.conf", "admin/conf/admin_config.conf"):
            for item in parse_listeners((lsws / name).read_text()):
                listeners.append({"file": name, **item})
        binary_present = (lsws / "bin/openlitespeed").is_file()
        files ={name: sha256(lsws / name) for name in ("bin/openlitespeed", "admin/fcgi-bin/admin_php",
                 "admin/misc/lshttpd.service", "admin/misc/rc-inst.sh") if (lsws / name).is_file()}
        version_file = (lsws / "VERSION").read_text().strip()
    requires = sorted({line.strip() for line in requires.splitlines() if line.strip()})
    lsphp = [item for item in requires if item.startswith("lsphp")]
    risks = classify_scriptlets(scripts)
    return {"artifact": {"path_name": rpm.name, "sha256": actual, "name": fields[0], "version": fields[1],
                         "release": fields[2], "arch": fields[3], "build_time": int(fields[4]),
                         "license": fields[5], "dsa_header": fields[6], "rsa_header": fields[7],
                         "payload_version_file": version_file, "binary_present": binary_present},
            "trusted_keys": [{"path_name": pathlib.Path(k).name, "sha256": sha256(k)} for k in keys],
            "signature": signature, "requires": requires, "scriptlet_risks": risks,
            "default_listeners": listeners, "payload_sha256": files,
            "verdict": verdict(signature, risks, listeners, lsphp)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=pathlib.Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--key", required=True, action="append", type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        print("Run as the development user; this audit needs no privileges.", file=sys.stderr)
        return 64
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        print("--sha256 must be 64 lowercase hex characters", file=sys.stderr)
        return 64
    run_dir = ROOT / "evidence/local" / ("ols-package-" + uuid.uuid4().hex)
    manifest = {"schema_version": 1, "kind": "ols-package-audit", "started_at": now(),
                "system_rpmdb_modified": False, "installed": False, "g0": "unproven"}
    try:
        manifest.update(audit(args.rpm.resolve(), args.sha256, [k.resolve() for k in args.key]))
        manifest["result"] = "observed"
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        manifest["result"] = "fail"
        manifest["error"] = str(exc)
    manifest["finished_at"] = now()
    run_dir.mkdir(parents=True, mode=0o700)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(run_dir), "result": manifest["result"],
                      "verdict": manifest.get("verdict"), "error": manifest.get("error")}))
    return 0 if manifest["result"] == "observed" else 1

if __name__ == "__main__":
    sys.exit(main())
