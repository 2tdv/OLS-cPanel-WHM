#!/usr/bin/python3
"""Reproducible build of the phpredis extension for every pinned EA4 PHP version.

The compile runs inside the pinned builder image (the one of build/ols-source) in rootless podman with cPanel's
public EA4 repository definition mounted; nothing is installed on the host. The source tarball is downloaded
inside the container and refused unless it matches the SHA-256 pinned in source.json.

Usage: python3 build/php-ext/build.py        (writes artifacts/php-ext-build/<id>/ with manifest.json)
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": os.environ.get("HOME", "/tmp")}
VERSION = re.compile(r"[0-9]+(\.[0-9]+){1,3}")
EA_PHP = re.compile(r"ea-php[0-9]{2,3}")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_source():
    """source.json, validated: every value that reaches a shell has a closed grammar."""
    source = json.loads((HERE / "source.json").read_text())
    checks = {
        "extension": r"[a-z]+", "version": VERSION.pattern, "sha256": r"[0-9a-f]{64}",
        "url": r"https://[A-Za-z0-9._/-]+", "builder_image": r".+@sha256:[0-9a-f]{64}",
        "ea4_repo_key_url": r"https://[A-Za-z0-9._/-]+", "ea4_repo_key_fingerprint": r"[0-9A-F]{40}",
        "ea4_repo_os_name_prefix": r"[a-z]{1,8}"}
    for key, pattern in checks.items():
        if not isinstance(source.get(key), str) or not re.fullmatch(pattern, source[key]):
            raise SystemExit(f"source.json: {key} is missing or malformed")
    versions = source.get("php_versions")
    if not isinstance(versions, list) or not versions or versions != sorted(set(versions)) \
            or not all(isinstance(v, str) and EA_PHP.fullmatch(v) for v in versions):
        raise SystemExit("source.json: php_versions must be a sorted list of ea-phpNN names")
    options = source.get("configure_options")
    if not isinstance(options, list) or not all(isinstance(o, str) and re.fullmatch(r"--[a-z0-9-]+", o) for o in options):
        raise SystemExit("source.json: configure_options must be a list of --flag words")
    if not isinstance(source.get("source_date_epoch"), int):
        raise SystemExit("source.json: source_date_epoch must be an integer")
    return source


def environment_script(source):
    """The values the container script reads, written to a file it sources (validated grammar, so quoting is safe)."""
    values = {"EXT": source["extension"], "EXT_VERSION": source["version"], "SOURCE_URL": source["url"],
              "SOURCE_SHA256": source["sha256"], "EA4_KEY_URL": source["ea4_repo_key_url"],
              "EA4_KEY_FINGERPRINT": source["ea4_repo_key_fingerprint"],
              "EA4_OS_NAME_PREFIX": source["ea4_repo_os_name_prefix"], "PHP_VERSIONS": " ".join(source["php_versions"]),
              "CONFIGURE_OPTIONS": " ".join(source["configure_options"]),
              "SOURCE_DATE_EPOCH": str(source["source_date_epoch"])}
    return "".join(f"{key}='{value}'\n" for key, value in values.items())


def parse_versions(text, source):
    """versions.tsv written by the container script -> {ea-phpNN: {...}}; refuses anything unexpected."""
    found = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            raise SystemExit(f"malformed versions line: {line!r}")
        name, php_version, api, build_id, devel = fields
        if name in found or name not in source["php_versions"] or not VERSION.fullmatch(php_version) \
                or not re.fullmatch(r"[0-9]{8}", api) or not re.fullmatch(rf"API{api},(NTS|ZTS)(,debug)?", build_id):
            raise SystemExit(f"unexpected versions line: {line!r}")
        found[name] = {"php_version": php_version, "php_api": api, "build_id": build_id, "devel_package": devel}
    if sorted(found) != source["php_versions"]:
        raise SystemExit("the build did not cover every pinned PHP version")
    return found


def main():
    if os.geteuid() == 0:
        raise SystemExit("Run as the development user; the build uses rootless podman")
    source = load_source()
    work = ROOT / "artifacts/php-ext-build" / uuid.uuid4().hex
    (work / "out").mkdir(parents=True)
    started = datetime.now(timezone.utc).isoformat()
    (work / "env.sh").write_text(environment_script(source))
    for name in ("build-in-container.sh",):
        (work / name).write_bytes((HERE / name).read_bytes())
    result = subprocess.run(
        ["podman", "run", "--rm", "--network=slirp4netns", "-v", f"{work}:/build",
         "-v", f"{HERE / 'EA4.repo'}:/etc/yum.repos.d/EA4.repo:ro", source["builder_image"],
         "/bin/sh", "/build/build-in-container.sh"], env=ENV, stdin=subprocess.DEVNULL)
    out = work / "out"
    manifest = {"schema_version": 1, "kind": "php-ext-build", "started_at": started,
                "finished_at": datetime.now(timezone.utc).isoformat(), "source": source,
                "ea4_repo_sha256": sha256(HERE / "EA4.repo"), "container_exit": result.returncode, "result": "fail"}
    if result.returncode == 0:
        versions = parse_versions((out / "versions.tsv").read_text(), source)
        for name, record in versions.items():
            so = out / name / "redis.so"
            record["sha256"] = sha256(so)
            record["size"] = so.stat().st_size
        manifest["versions"] = versions
        manifest["license_sha256"] = sha256(out / "LICENSE")
        manifest["result"] = "pass"
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(work), "result": manifest["result"]}))
    return 0 if manifest["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
