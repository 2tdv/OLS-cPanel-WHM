#!/usr/bin/python3
"""Assemble the ols-cpanel-php-redis RPM from a passing build.py output; rpmbuild runs in the pinned builder image.

Usage: python3 build/php-ext/package.py <build directory printed by build.py>

The RPM is deterministic: payload paths are added in sorted order with fixed owner, mode and time
(source_date_epoch of source.json), and rpmbuild clamps its own timestamps to the same epoch.
"""
import hashlib
import importlib.util
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
PREFIX = "usr/local/ols-cpanel/php-ext/redis"
# Everything that decides the content of the RPM besides the compiled objects (review RV-07: a changed input must
# never ship under an existing name-version-release).
RELEASE_INPUTS = ["EA4.repo", "build-in-container.sh", "build.py", "ols-cpanel-php-redis.spec"]
SOURCE_KEYS = ["extension", "version", "url", "sha256", "builder_image", "ea4_repo_key_url", "ea4_repo_key_fingerprint",
               "ea4_repo_os_name_prefix", "php_versions", "configure_options", "source_date_epoch"]


def _load_build():
    spec = importlib.util.spec_from_file_location("php_ext_build", HERE / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release_inputs_sha256(source, here=HERE):
    """One digest over the pinned source description and every packaged or build-driving file."""
    digest = hashlib.sha256()
    for key in SOURCE_KEYS:
        digest.update(f"{key}={json.dumps(source[key], sort_keys=True)}\n".encode())
    for name in RELEASE_INPUTS:
        digest.update(f"file {name} {sha256(here / name)}\n".encode())
    return digest.hexdigest()


def release(source, here=HERE):
    """RPM release from the counter; refuses inputs that changed without a new counter."""
    current = release_inputs_sha256(source, here)
    if current != source["release_inputs_sha256"]:
        raise SystemExit("Packaging inputs changed: bump product_release and record release_inputs_sha256 "
                         f"{current} in source.json")
    return f"1.olscp{source['product_release']}"


def index_document(source, versions, prefix="/" + PREFIX):
    """The JSON index shipped next to the builds (read by src/PhpExtensions/ExtensionBundle.php)."""
    # The pinned source tarball ships inside the package: a version without a matching prebuilt build is compiled on
    # the server from it (src/PhpExtensions/ExtensionInstaller.php) without any download.
    return {"schema_version": 1, "extension": source["extension"], "extension_version": source["version"],
            "source": {"file": f"src/phpredis-{source['version']}.tgz", "sha256": source["sha256"]},
            "versions": {name: {"so": f"{prefix}/{name}/redis.so", "sha256": record["sha256"], "size": record["size"],
                                "php_api": record["php_api"], "build_id": record["build_id"],
                                "built_with": record["php_version"]}
                         for name, record in sorted(versions.items())}}


def stage(work, source, manifest, pkg):
    """Payload tree of the package under pkg/payload."""
    root = pkg / "payload" / PREFIX
    out = work / "out"
    for name, record in sorted(manifest["versions"].items()):
        so = out / name / "redis.so"
        if sha256(so) != record["sha256"]:
            raise SystemExit(f"{so} does not match the build manifest")
        (root / name).mkdir(parents=True)
        shutil.copyfile(so, root / name / "redis.so")
        os.chmod(root / name / "redis.so", 0o755)
    tarball = work / "src.tgz"
    if sha256(tarball) != source["sha256"]:
        raise SystemExit("the downloaded source does not match the pinned SHA-256")
    (root / "src").mkdir()
    shutil.copyfile(tarball, root / "src" / f"phpredis-{source['version']}.tgz")
    os.chmod(root / "src" / f"phpredis-{source['version']}.tgz", 0o644)
    shutil.copyfile(out / "LICENSE", root / "LICENSE")
    os.chmod(root / "LICENSE", 0o644)
    (root / "index.json").write_text(json.dumps(index_document(source, manifest["versions"]), indent=2, sort_keys=True) + "\n")
    os.chmod(root / "index.json", 0o644)
    for path in [pkg / "payload", *(pkg / "payload").rglob("*")]:
        if path.is_dir():
            os.chmod(path, 0o755)


def write_tar(pkg, epoch):
    """payload.tar with sorted entries and fixed owner and time."""
    def fixed(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = epoch
        return info
    with tarfile.open(pkg / "payload.tar", "w", format=tarfile.GNU_FORMAT) as tar:
        tar.add(pkg / "payload", arcname="payload", recursive=False, filter=fixed)
        for path in sorted((pkg / "payload").rglob("*")):
            tar.add(path, arcname="payload/" + path.relative_to(pkg / "payload").as_posix(), recursive=False, filter=fixed)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: package.py BUILD_DIRECTORY")
    work = pathlib.Path(sys.argv[1]).resolve()
    manifest = json.loads((work / "manifest.json").read_text())
    if manifest["result"] != "pass":
        raise SystemExit("Build did not pass")
    current = source = _load_build().load_source()
    if {k: manifest["source"][k] for k in SOURCE_KEYS} != {k: current[k] for k in SOURCE_KEYS} \
            or manifest["ea4_repo_sha256"] != sha256(HERE / "EA4.repo"):
        raise SystemExit("Build output does not match the current source.json; rebuild first")
    rel = release(current)
    pkg = work / ("package-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    pkg.mkdir()
    stage(work, source, manifest, pkg)
    write_tar(pkg, source["source_date_epoch"])
    shutil.copyfile(HERE / "ols-cpanel-php-redis.spec", pkg / "ols-cpanel-php-redis.spec")
    script = ("set -eu; dnf -y -q install rpm-build >/dev/null; "
              f"SOURCE_DATE_EPOCH={source['source_date_epoch']} rpmbuild -bb --define '_topdir /pkg/rpmbuild' "
              "--define '_sourcedir /pkg' --define 'source_date_epoch_from_changelog 0' "
              "--define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' "
              "--define '_buildhost olscp-builder' "
              f"--define 'ext_version {source['version']}' --define 'ext_release {rel}' /pkg/ols-cpanel-php-redis.spec")
    result = subprocess.run(["podman", "run", "--rm", "-v", f"{pkg}:/pkg", source["builder_image"],
                             "/bin/sh", "-c", script], env=ENV, stdin=subprocess.DEVNULL)
    rpms = sorted((pkg / "rpmbuild/RPMS").rglob("*.rpm")) if result.returncode == 0 else []
    record = {"result": "pass" if len(rpms) == 1 else "fail", "version": source["version"], "release": rel,
              "release_inputs_sha256": current["release_inputs_sha256"],
              "rpm": {p.name: {"sha256": sha256(p), "size": p.stat().st_size} for p in rpms}, "signed": False,
              "versions": {n: {k: r[k] for k in ("php_version", "php_api", "build_id", "sha256", "size")}
                           for n, r in manifest["versions"].items()}}
    (pkg / "package.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(pkg), **record}))
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
