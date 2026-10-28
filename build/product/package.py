#!/usr/bin/python3
"""Assemble the ols-cpanel payload from the repository and the built artifacts, then build the RPM in the
pinned builder image of build/ols-source (same image, same rules: rootless podman, nothing on the host).

Usage: python3 build/product/package.py [OUTPUT_DIR]      (default OUTPUT_DIR: artifacts/product)

Required artifacts (built beforehand, never fetched here):
  artifacts/ui/                         build/ui/build.sh      (assets/, .vite/manifest.json, SHA256SUMS)
  artifacts/broker/ols-cpanel-broker    build/broker/build.sh  (+ ols-cpanel-broker.sha256)
Optional: artifacts/broker/ols-cpanel-activator (+ .sha256), packaged when present.

Payload layout:
  /usr/local/ols-cpanel/bin/ols-cpanel           launcher: cPanel's PHP on libexec/ols-cpanel.php
  /usr/local/ols-cpanel/lib/                     the PHP engine (repository src/)
  /usr/local/ols-cpanel/libexec/                 ols-cpanel.php (repository bin/ols-cpanel), broker, activator
  /usr/local/ols-cpanel/share/ui/                the verified interface build, with its SHA256SUMS
  /usr/local/ols-cpanel/share/ols/               the OLS server policy template of the compiler
  /usr/local/ols-cpanel/share/release-key.asc    the release public key and its fingerprint (build/release/): the key
  /usr/local/ols-cpanel/share/release-key.fingerprint   `update install` verifies a new release's install.sh against
  /usr/local/ols-cpanel/libexec/ols-cpanel-hook  cPanel hook entry (runs `ols-cpanel hook`)
  /usr/local/ols-cpanel/plugins/{whm,cpanel}/    deployable plugin trees (entry point, lib/, assets/,
                                                 manifest.json, registration files); deployed by the CLI
  /usr/lib/systemd/system/ols-cpanel-{broker,reconciler}.service, ols-cpanel-objcache@.service (per-account
                                                 object cache template), ols-cpanel-objcache.{service,timer},
                                                 ols-cpanel-php.{path,service,timer} (PHP environment: lsphp, OPcache, redis),
                                                 ols-cpanel-hybrid-trust.{service,timer} (hybrid Apache trust of local addresses),
                                                 /usr/lib/sysusers.d/ols-cpanel.conf
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": os.environ.get("HOME", "/tmp")}
PREFIX = "usr/local/ols-cpanel"
SKIP = {"__pycache__", "node_modules", ".git"}
# Repository paths whose content goes into the RPM directly or through a built artifact (review RV-07: a
# changed input must never ship under an existing name-version-release). The artifacts themselves are
# checked against their checksum files and for staleness against these sources.
BROKER_SOURCES = ["broker/Cargo.toml", "broker/Cargo.lock", "broker/src", "build/broker/build.sh"]
UI_SOURCES = ["ui/package.json", "ui/package-lock.json", "ui/vite.config.js", "ui/src", "build/ui/build.sh"]
RELEASE_INPUTS = ["src", "bin/ols-cpanel", "plugins/whm", "plugins/cpanel", *BROKER_SOURCES, *UI_SOURCES,
                  "build/vm-qualification/ols-lab/ownership_httpd_config.conf", "build/product/ols-cpanel-hook",
                  "build/product/ols-cpanel.spec", "build/product/ols-cpanel.sh",
                  "build/product/ols-cpanel-broker.service", "build/product/ols-cpanel-reconciler.service",
                  "build/product/ols-cpanel-objcache@.service", "build/product/ols-cpanel-objcache.service",
                  "build/product/ols-cpanel-objcache.timer", "build/product/ols-cpanel-cache-clean.service",
                  "build/product/ols-cpanel-cache-clean.timer", "build/product/ols-cpanel-notify.service",
                  "build/product/ols-cpanel-notify.timer", "build/product/ols-cpanel-schedule.service",
                  "build/product/ols-cpanel-schedule.timer", "build/product/ols-cpanel-php.path",
                  "build/product/ols-cpanel-php.service",
                  "build/product/ols-cpanel-php.timer",
                  "build/product/ols-cpanel-hybrid-trust.service", "build/product/ols-cpanel-hybrid-trust.timer",
                  "build/product/ols-cpanel-upgrade.service",
                  "build/product/ols-cpanel.sysusers",
                  "build/release/ols-cpanel-release-key.asc", "build/release/ols-cpanel-release-key.fingerprint"]
UNITS = ["ols-cpanel-broker.service", "ols-cpanel-reconciler.service", "ols-cpanel-objcache@.service",
         "ols-cpanel-objcache.service", "ols-cpanel-objcache.timer", "ols-cpanel-cache-clean.service",
         "ols-cpanel-cache-clean.timer", "ols-cpanel-notify.service", "ols-cpanel-notify.timer",
         "ols-cpanel-schedule.service", "ols-cpanel-schedule.timer", "ols-cpanel-php.path", "ols-cpanel-php.service", "ols-cpanel-php.timer",
         "ols-cpanel-hybrid-trust.service", "ols-cpanel-hybrid-trust.timer",
         "ols-cpanel-upgrade.service"]
# The packaged CLI lives in libexec/ and finds the engine in lib/ instead of the checkout's src/.
CLI_BOOTSTRAP = "require dirname(__DIR__) . '/src/bootstrap.php';"
PACKAGED_BOOTSTRAP = "require dirname(__DIR__) . '/lib/bootstrap.php';"
PLUGIN_LIB = re.compile(r"^require __DIR__ \. '/lib/([A-Za-z0-9]+\.php)';$", re.M)


class PackagingError(SystemExit):
    pass


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files_under(root, name):
    """Regular files of a repository path (file or directory), sorted, without caches or dependencies."""
    path = root / name
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise PackagingError(f"Packaging input {name} is missing")
    found = []
    for item in sorted(path.rglob("*")):
        if SKIP.intersection(item.relative_to(root).parts) or item.suffix == ".pyc":
            continue
        if item.is_symlink():
            raise PackagingError(f"Symlinks are not allowed in packaging inputs: {item.relative_to(root)}")
        if item.is_file():
            found.append(item)
    return found


def builder_image(root=ROOT):
    """The same pinned image as the OLS package (build/ols-source/source.json)."""
    image = json.loads((root / "build/ols-source/source.json").read_text())["builder_image"]
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
        raise PackagingError("The builder image in build/ols-source/source.json is not pinned by digest")
    return image


def release_inputs_sha256(root=ROOT, activator=None):
    """One digest over the builder image and every packaged repository file."""
    if activator is None:
        activator = (root / "artifacts/broker/ols-cpanel-activator").is_file()
    digest = hashlib.sha256()
    digest.update(f"builder_image={builder_image(root)}\n".encode())
    # Adding (or dropping) the activator changes the package contents, so it needs a new release too.
    digest.update(f"activator={'yes' if activator else 'no'}\n".encode())
    for name in RELEASE_INPUTS:
        for path in files_under(root, name):
            digest.update(f"file {path.relative_to(root).as_posix()} {sha256(path)}\n".encode())
    return digest.hexdigest()


def release(product, root=ROOT, activator=None):
    """RPM release from the product counter; refuses inputs that changed without a new counter."""
    current = release_inputs_sha256(root, activator)
    if current != product["release_inputs_sha256"]:
        raise PackagingError("Packaging inputs changed: bump product_release and record release_inputs_sha256 "
                             f"{current} in build/product/product.json")
    return f"1.olscp{product['product_release']}"


def require_artifact(path, hint):
    if not path.is_file():
        raise PackagingError(f"Required artifact {path} is missing: run {hint} first")


def newest_source(root, names):
    return max(p.stat().st_mtime for name in names for p in files_under(root, name))


def check_broker_artifact(root, name):
    """Binary present, matching its .sha256 record, and not older than the broker sources."""
    binary, record = root / "artifacts/broker" / name, root / "artifacts/broker" / (name + ".sha256")
    require_artifact(binary, "build/broker/build.sh")
    require_artifact(record, "build/broker/build.sh")
    fields = record.read_text().split()
    if len(fields) != 2 or fields[1] != name or fields[0] != sha256(binary):
        raise PackagingError(f"{binary} does not match {record}; rebuild with build/broker/build.sh")
    if binary.stat().st_mtime < newest_source(root, BROKER_SOURCES):
        raise PackagingError(f"{binary} is older than the broker sources; rebuild with build/broker/build.sh")
    return fields[0]


def check_ui_artifact(root):
    """Every built file listed in SHA256SUMS with a matching digest, nothing unlisted, sources not newer."""
    ui = root / "artifacts/ui"
    sums = ui / "SHA256SUMS"
    require_artifact(sums, "build/ui/build.sh")
    require_artifact(ui / ".vite/manifest.json", "build/ui/build.sh")
    listed = {}
    for line in sums.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./([A-Za-z0-9._/-]+)", line)
        if not match or ".." in match.group(2).split("/"):
            raise PackagingError(f"Malformed line in {sums}: {line!r}")
        listed[match.group(2)] = match.group(1)
    present = {p.relative_to(ui).as_posix() for p in ui.rglob("*") if p.is_file() and p != sums}
    if set(listed) != present:
        raise PackagingError(f"{ui} does not match its SHA256SUMS (missing or unlisted files); rebuild the UI")
    for name, digest in listed.items():
        if sha256(ui / name) != digest:
            raise PackagingError(f"{ui / name} does not match SHA256SUMS; rebuild with build/ui/build.sh")
    if sums.stat().st_mtime < newest_source(root, UI_SOURCES):
        raise PackagingError(f"{ui} is older than the interface sources; rebuild with build/ui/build.sh")
    return sha256(sums)


def place(source, target, mode):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    os.chmod(target, mode)


def place_tree(source, target):
    for path in files_under(source, "."):
        relative = path.relative_to(source)
        place(path, target / relative, 0o755 if path.suffix == ".cgi" else 0o644)


def plugin_tree(root, name, entry, payload):
    """A deployable plugin directory: entry point and registration files, the engine classes the entry point
    requires (resolved by file name in src/, exactly one match each), and the interface build."""
    source, target = root / "plugins" / name, payload / PREFIX / "plugins" / name
    place_tree(source, target)
    if name == "cpanel":
        place(root / "ui/src/shared/i18n.htaccess.en.json", target / "lib/i18n.htaccess.en.json", 0o644)
    text = (source / entry).read_text()
    for library in PLUGIN_LIB.findall(text):
        matches = [p for p in files_under(root, "src") if p.name == library]
        if len(matches) != 1:
            raise PackagingError(f"plugins/{name}/{entry} requires lib/{library}: expected exactly one "
                                 f"src/**/{library}, found {len(matches)}")
        place(matches[0], target / "lib" / library, 0o644)
    place_tree(root / "artifacts/ui/assets", target / "assets")
    place(root / "artifacts/ui/.vite/manifest.json", target / "manifest.json", 0o644)


def assemble(payload, root=ROOT):
    """Build the payload tree under `payload`; returns the artifact digests recorded in package.json."""
    artifacts = {"ols-cpanel-broker": check_broker_artifact(root, "ols-cpanel-broker"),
                 "ui/SHA256SUMS": check_ui_artifact(root)}
    activator = (root / "artifacts/broker/ols-cpanel-activator").is_file()
    if activator:
        artifacts["ols-cpanel-activator"] = check_broker_artifact(root, "ols-cpanel-activator")
    prefix = payload / PREFIX
    place_tree(root / "src", prefix / "lib")
    cli = (root / "bin/ols-cpanel").read_text()
    if cli.count(CLI_BOOTSTRAP) != 1:
        raise PackagingError(f"bin/ols-cpanel must contain exactly one line {CLI_BOOTSTRAP!r} to be packaged")
    (prefix / "libexec").mkdir(parents=True)
    (prefix / "libexec/ols-cpanel.php").write_text(cli.replace(CLI_BOOTSTRAP, PACKAGED_BOOTSTRAP))
    os.chmod(prefix / "libexec/ols-cpanel.php", 0o644)
    place(root / "build/product/ols-cpanel.sh", prefix / "bin/ols-cpanel", 0o755)
    place(root / "build/product/ols-cpanel-hook", prefix / "libexec/ols-cpanel-hook", 0o755)
    # The OLS server policy template the compiler starts from (Deployment\BuilderCompilation::TEMPLATE).
    place(root / "build/vm-qualification/ols-lab/ownership_httpd_config.conf", prefix / "share/ols/httpd_config.conf", 0o644)
    # The release public key (Operations\ReleaseChannel::KEY/FINGERPRINT): updates from WHM trust only this key, never one
    # obtained from the network.
    place(root / "build/release/ols-cpanel-release-key.asc", prefix / "share/release-key.asc", 0o644)
    place(root / "build/release/ols-cpanel-release-key.fingerprint", prefix / "share/release-key.fingerprint", 0o644)
    place(root / "artifacts/broker/ols-cpanel-broker", prefix / "libexec/ols-cpanel-broker", 0o755)
    if activator:
        place(root / "artifacts/broker/ols-cpanel-activator", prefix / "libexec/ols-cpanel-activator", 0o755)
    ui = root / "artifacts/ui"
    place_tree(ui / "assets", prefix / "share/ui/assets")
    place(ui / ".vite/manifest.json", prefix / "share/ui/.vite/manifest.json", 0o644)
    place(ui / "SHA256SUMS", prefix / "share/ui/SHA256SUMS", 0o644)
    plugin_tree(root, "whm", "index.cgi", payload)
    plugin_tree(root, "cpanel", "index.live.php", payload)
    for unit in UNITS:
        place(root / "build/product" / unit, payload / "usr/lib/systemd/system" / unit, 0o644)
    place(root / "build/product/ols-cpanel.sysusers", payload / "usr/lib/sysusers.d/ols-cpanel.conf", 0o644)
    for path in [payload, *payload.rglob("*")]:
        if path.is_dir():
            os.chmod(path, 0o755)
    return artifacts, activator


def main(argv):
    if len(argv) > 2 or (len(argv) == 2 and argv[1].startswith("-")):
        raise SystemExit("Usage: package.py [OUTPUT_DIR]")
    out = pathlib.Path(argv[1]).resolve() if len(argv) == 2 else ROOT / "artifacts/product"
    product = json.loads((HERE / "product.json").read_text())
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", product["version"]):
        raise SystemExit("product.json version must be numeric (RPM Version)")
    activator = (ROOT / "artifacts/broker/ols-cpanel-activator").is_file()
    RELEASE = release(product, activator=activator)
    image = builder_image()
    # Fresh directory per run: rpmbuild leaves files owned by mapped container ids.
    pkg = out / ("package-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    pkg.mkdir(parents=True)
    artifacts, activator = assemble(pkg / "payload")
    with tarfile.open(pkg / "payload.tar", "w") as tar:
        tar.add(pkg / "payload", arcname="payload")
    shutil.copy2(HERE / "ols-cpanel.spec", pkg / "ols-cpanel.spec")
    script = ("set -eu; dnf -y -q install rpm-build >/dev/null; "
              "rpmbuild -bb --define '_topdir /pkg/rpmbuild' --define '_sourcedir /pkg' "
              f"--define 'product_version {product['version']}' --define 'product_release {RELEASE}' "
              f"--define 'with_activator {1 if activator else 0}' /pkg/ols-cpanel.spec")
    result = subprocess.run(["podman", "run", "--rm", "-v", f"{pkg}:/pkg", image, "/bin/sh", "-c", script],
                            env=ENV, stdin=subprocess.DEVNULL)
    rpms = sorted((pkg / "rpmbuild/RPMS").rglob("*.rpm")) if result.returncode == 0 else []
    record = {"result": "pass" if len(rpms) == 1 else "fail", "version": product["version"], "release": RELEASE,
              "release_inputs_sha256": product["release_inputs_sha256"], "builder_image": image,
              "artifacts": artifacts, "rpm": {p.name: sha256(p) for p in rpms}, "signed": False}
    (pkg / "package.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(pkg), **record}))
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
