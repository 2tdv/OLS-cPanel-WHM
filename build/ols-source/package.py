#!/usr/bin/python3
"""Assemble the product RPM from a passing build.py output; rpmbuild runs in the pinned builder image."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": os.environ.get("HOME", "/tmp")}
# Files whose content goes into the RPM besides the compiled tree (review RV-07: a changed input must
# never ship under an existing name-version-release).
RELEASE_INPUTS = ["ols-cpanel.service", "ols-cpanel-logs.service", "ols-cpanel-logship", "ols-cpanel-reload",
                  "ols-cpanel-epoch-check",
                  "ols-cpanel-openlitespeed.spec", "../vm-qualification/ols-lab/admin_config.conf"]
SERVERROOT = "usr/local/lsws"

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def withheld():
    """Patches held back from a public copy of the repository until their coordinated disclosure ends:
    patches/WITHHELD lists "<name> <sha256>" per line. The released packages contain them; the digest of a
    withheld patch is the recorded one, so the packaging-input digest stays the same in both copies."""
    path = HERE / "patches" / "WITHHELD"
    if not path.exists():
        return {}
    entries = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            name, digest = line.split()
            entries[name] = digest
    return entries

def patch_sha256(name):
    path = HERE / "patches" / name
    if not path.exists() and name in withheld():
        return withheld()[name]
    return sha256(path)

def release_inputs_sha256(source):
    """One digest over the pinned source, every patch and every packaged product file."""
    digest = hashlib.sha256()
    for key in ("commit", "lsquic_commit", "third_party_commit", "builder_image"):
        digest.update(f"{key}={source[key]}\n".encode())
    for name in source["patches"]:
        digest.update(f"patch {name} {patch_sha256(name)}\n".encode())
    for name in source["third_party_patches"]:
        digest.update(f"third-party {name} {sha256(HERE / 'third-party-patches' / name)}\n".encode())
    for name in RELEASE_INPUTS:
        digest.update(f"file {name} {sha256(HERE / name)}\n".encode())
    return digest.hexdigest()

def release(source):
    """RPM release from the product counter; refuses inputs that changed without a new counter."""
    if release_inputs_sha256(source) != source["release_inputs_sha256"]:
        raise SystemExit("Packaging inputs changed: bump product_release and record release_inputs_sha256 "
                         f"{release_inputs_sha256(source)} in source.json")
    return f"1.olscp{source['product_release']}"

def main():
    work = pathlib.Path(sys.argv[1]).resolve()
    manifest = json.loads((work / "manifest.json").read_text())
    if manifest["result"] != "pass":
        raise SystemExit("Build did not pass")
    current = json.loads((HERE / "source.json").read_text())
    if manifest["patch_sha256"] != {n: sha256(HERE / "patches" / n) for n in current["patches"]}:
        raise SystemExit("Build output does not match the current patch set; rebuild first")
    RELEASE = release(current)
    source = manifest["source"]
    dist, out = work / "openlitespeed/dist", work / "out/dist"
    # Fresh directory per run: rpmbuild leaves files owned by mapped container ids.
    pkg = work / ("package-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    root = pkg / "payload" / SERVERROOT
    for name in ["bin", "conf/vhosts", "logs", "tmp", "cachedata", "autoupdate", "cgid",
                 "admin/conf", "admin/tmp", "admin/logs", "admin/cgid"]:
        (root / name).mkdir(parents=True)
    shutil.copy2(out / "bin/openlitespeed", root / "bin/openlitespeed")
    shutil.copy2(dist / "bin/lswsctrl", root / "bin/lswsctrl")
    os.symlink("openlitespeed", root / "bin/lshttpd")
    os.symlink("lshttpd", root / "bin/litespeed")
    shutil.copytree(out / "modules", root / "modules")
    shutil.copytree(out / "lsns", root / "lsns")
    shutil.copytree(dist / "share", root / "share")
    shutil.copytree(dist / "lsrecaptcha", root / "lsrecaptcha")
    for name in ["GPL.txt", "VERSION"]:
        shutil.copy2(dist / name, root / name)
    shutil.copy2(dist / "conf/mime.properties", root / "conf/mime.properties")
    shutil.copy2(HERE.parent / "vm-qualification/ols-lab/admin_config.conf", root / "admin/conf/admin_config.conf")
    unit = pkg / "payload/usr/lib/systemd/system"
    unit.mkdir(parents=True)
    shutil.copy2(HERE / "ols-cpanel.service", unit / "ols-cpanel.service")
    shutil.copy2(HERE / "ols-cpanel-logs.service", unit / "ols-cpanel-logs.service")
    libexec = pkg / "payload/usr/libexec/ols-cpanel"
    libexec.mkdir(parents=True)
    shutil.copy2(HERE / "ols-cpanel-logship", libexec / "ols-cpanel-logship")
    shutil.copy2(HERE / "ols-cpanel-reload", libexec / "ols-cpanel-reload")
    shutil.copy2(HERE / "ols-cpanel-epoch-check", libexec / "ols-cpanel-epoch-check")
    version = (root / "VERSION").read_text().strip()
    with tarfile.open(pkg / "payload.tar", "w") as tar:
        tar.add(pkg / "payload", arcname="payload")
    shutil.copy2(HERE / "ols-cpanel-openlitespeed.spec", pkg / "ols-cpanel-openlitespeed.spec")
    script = ("set -eu; dnf -y -q install rpm-build >/dev/null; "
              "rpmbuild -bb --define '_topdir /pkg/rpmbuild' --define '_sourcedir /pkg' "
              f"--define 'ols_version {version}' --define 'ols_release {RELEASE}' "
              f"--define 'ols_commit {source['commit']}' /pkg/ols-cpanel-openlitespeed.spec")
    result = subprocess.run(["podman", "run", "--rm", "-v", f"{pkg}:/pkg", source["builder_image"],
                             "/bin/sh", "-c", script], env=ENV, stdin=subprocess.DEVNULL)
    rpms = sorted((pkg / "rpmbuild/RPMS").rglob("*.rpm")) if result.returncode == 0 else []
    record = {"result": "pass" if len(rpms) == 1 else "fail", "version": version, "release": RELEASE,
              "release_inputs_sha256": current["release_inputs_sha256"],
              "rpm": {p.name: sha256(p) for p in rpms}, "signed": False}
    (pkg / "package.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(pkg), **record}))
    return 0 if record["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
