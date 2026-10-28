#!/usr/bin/python3
"""Offline checks of the phpredis build pipeline (build/php-ext): pinned inputs, release guard, deterministic payload,
package layout, and the index the PHP installer reads. Builds nothing and changes nothing on the server."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HERE = ROOT / "build/php-ext"
PHP = "/usr/local/cpanel/3rdparty/php/84/bin/php"


def load(name):
    spec = importlib.util.spec_from_file_location("php_ext_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refuses(function, *args, contains):
    try:
        function(*args)
    except SystemExit as error:
        assert contains in str(error), (contains, str(error))
        return
    raise AssertionError(f"expected a refusal containing {contains!r}")


build, package = load("build"), load("package")
source = build.load_source()
ols = json.loads((ROOT / "build/ols-source/source.json").read_text())

# --- Pins -----------------------------------------------------------------------------------------------------------
assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) and source["url"].startswith("https://pecl.php.net/get/redis-" + source["version"])
assert re.fullmatch(r".+@sha256:[0-9a-f]{64}", source["builder_image"])
assert source["builder_image"] == ols["builder_image"], "one pinned builder image for every product package"
assert re.fullmatch(r"[0-9A-F]{40}", source["ea4_repo_key_fingerprint"])
assert source["php_versions"] == sorted(source["php_versions"]) and {"ea-php81", "ea-php82", "ea-php83", "ea-php84"} <= set(source["php_versions"])
assert all(o.startswith("--disable-redis-") for o in source["configure_options"]), "no optional compression or serializer library"
repo = (HERE / "EA4.repo").read_text()
assert "[EA4-$os_name_prefix$releasever]" in repo and "gpgcheck=1" in repo and "mirrorlist=http://httpupdate.cpanel.net/" in repo
script = (HERE / "build-in-container.sh").read_text()
# The checksum is verified before anything is extracted, the key fingerprint before anything is installed.
assert script.index("sha256sum --check") < script.index("tar -xzf /build/src.tgz") and script.index("EA4_KEY_FINGERPRINT\" ] ||") < script.index("dnf -y -q install")
assert "make -j 2" in script and "set -eu" in script and "phpize" in script and "--with-php-config" in script
assert 'php-config" --phpapi' not in script, "EA4 php-config has no --phpapi; the API number comes from php -i"
assert "SOURCE_DATE_EPOCH" in script and "-ffile-prefix-map" in script

# --- Pin validation -----------------------------------------------------------------------------------------------------
for key, bad in (("sha256", "xyz"), ("url", "http://pecl.php.net/x"), ("builder_image", "almalinux:9"),
                 ("php_versions", ["ea-php83", "ea-php81"]), ("php_versions", ["ea-php83; id"]),
                 ("configure_options", ["--with-x; id"]), ("version", "6.3.0'; id"), ("ea4_repo_key_fingerprint", "abc")):
    broken = copy.deepcopy(source)
    broken[key] = bad
    (tmp := pathlib.Path(tempfile.mkdtemp())).joinpath("source.json").write_text(json.dumps(broken))
    original = build.HERE
    build.HERE = tmp
    try:
        refuses(build.load_source, contains=key)
    finally:
        build.HERE = original
environment = build.environment_script(source)
assert "SOURCE_SHA256='" + source["sha256"] + "'" in environment and "PHP_VERSIONS='" + " ".join(source["php_versions"]) + "'" in environment
good = "\n".join(f"{v}\t8.3.1\t20230831\tAPI20230831,NTS\tdevel" for v in source["php_versions"])
assert sorted(build.parse_versions(good, source)) == source["php_versions"]
refuses(build.parse_versions, good.splitlines()[0], source, contains="every pinned PHP version")
refuses(build.parse_versions, good + "\nea-php99\t8\t20230831\tAPI20230831,NTS\td", source, contains="unexpected versions line")
refuses(build.parse_versions, good.replace("API20230831,NTS", "API20230832,NTS", 1), source, contains="unexpected versions line")

# --- Spec: files only ----------------------------------------------------------------------------------------------------
spec = (HERE / "ols-cpanel-php-redis.spec").read_text()
assert not re.search(r"^%(pre|post|preun|postun|pretrans|posttrans|trigger\w*)\b", spec, re.M), "no scriptlets"
code = "\n".join(line for line in spec.splitlines() if not line.startswith("#"))
assert "/opt/cpanel" not in code and "systemctl" not in code
assert "Name:           ols-cpanel-php-redis" in spec and "BuildArch:      x86_64" in spec and "AutoReqProv:    no" in spec
assert "%{prefix_dir}/src" in spec and "%{prefix_dir}/ea-php*" in spec and "_build_id_links none" in spec

# --- Release guard (RV-07) -----------------------------------------------------------------------------------------------------
assert package.release(source) == f"1.olscp{source['product_release']}", "recorded release_inputs_sha256 matches the inputs"
changed = dict(source, version="6.3.1")
refuses(package.release, changed, contains="bump product_release")
refuses(package.release, dict(source, release_inputs_sha256="0" * 64), contains="record release_inputs_sha256")

# --- Payload layout, determinism, index ---------------------------------------------------------------------------------------------
tarball = b"pinned source"
pinned = dict(source, sha256=hashlib.sha256(tarball).hexdigest())
with tempfile.TemporaryDirectory() as temp:
    work = pathlib.Path(temp) / "work"
    (work / "out").mkdir(parents=True)
    (work / "src.tgz").write_bytes(tarball)
    (work / "out/LICENSE").write_text("license")
    versions = {}
    for name in source["php_versions"]:
        (work / "out" / name).mkdir()
        data = ("so " + name).encode()
        (work / "out" / name / "redis.so").write_bytes(data)
        versions[name] = {"php_version": "8.3.1", "php_api": "20230831", "build_id": "API20230831,NTS",
                          "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    manifest = {"versions": versions}
    outputs = []
    for run in range(2):
        pkg = pathlib.Path(temp) / f"pkg{run}"
        pkg.mkdir()
        package.stage(work, pinned, manifest, pkg)
        package.write_tar(pkg, pinned["source_date_epoch"])
        outputs.append(hashlib.sha256((pkg / "payload.tar").read_bytes()).hexdigest())
    assert outputs[0] == outputs[1], "the payload tar is deterministic"
    payload = pathlib.Path(temp) / "pkg0/payload"
    files = sorted(p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file())
    prefix = "usr/local/ols-cpanel/php-ext/redis"
    assert files == sorted([f"{prefix}/index.json", f"{prefix}/LICENSE", f"{prefix}/src/phpredis-{source['version']}.tgz",
                            *[f"{prefix}/{n}/redis.so" for n in source["php_versions"]]]), files
    assert not [p for p in payload.rglob("*") if p.is_symlink()] and not any(f.startswith("opt/") for f in files), "nothing under /opt/cpanel"
    assert (payload / prefix / "ea-php83/redis.so").stat().st_mode & 0o777 == 0o755 and (payload / prefix / "index.json").stat().st_mode & 0o777 == 0o644
    with tarfile.open(pathlib.Path(temp) / "pkg0/payload.tar") as tar:
        assert all(m.uid == 0 and m.gid == 0 and m.mtime == pinned["source_date_epoch"] for m in tar.getmembers())
    index = json.loads((payload / prefix / "index.json").read_text())
    assert index["source"] == {"file": f"src/phpredis-{source['version']}.tgz", "sha256": pinned["sha256"]}
    assert index["versions"]["ea-php83"] == {"so": f"/{prefix}/ea-php83/redis.so", "sha256": versions["ea-php83"]["sha256"],
                                             "size": versions["ea-php83"]["size"], "php_api": "20230831",
                                             "build_id": "API20230831,NTS", "built_with": "8.3.1"}
    # A tampered object or source is refused when staging.
    (work / "out/ea-php83/redis.so").write_bytes(b"other")
    refuses(package.stage, work, pinned, manifest, pathlib.Path(temp) / "pkg9", contains="does not match the build manifest")
    (work / "out/ea-php83/redis.so").write_bytes(b"so ea-php83")
    (work / "src.tgz").write_bytes(b"tampered")
    refuses(package.stage, work, pinned, manifest, pathlib.Path(temp) / "pkg8", contains="pinned SHA-256")

    # The index of this package is what the PHP installer reads (same schema, absolute paths below the given root).
    if pathlib.Path(PHP).is_file():
        root = pathlib.Path(temp) / "installed"
        (root).mkdir()
        doc = package.index_document(pinned, versions, prefix=str(root))
        (root / "index.json").write_text(json.dumps(doc))
        probe = ("require $argv[1] . '/src/bootstrap.php'; $b = OlsCpanel\\PhpExtensions\\ExtensionBundle::load($argv[2]);"
                 "echo json_encode([$b->extensionVersion, array_keys($b->versions), $b->sourcePath(), $b->entry('ea-php83')['build_id']]);")
        result = subprocess.run([PHP, "-n", "-r", probe, "--", str(ROOT), str(root)], capture_output=True, text=True, check=True)
        assert json.loads(result.stdout) == [source["version"], source["php_versions"], f"{root}/src/phpredis-{source['version']}.tgz", "API20230831,NTS"], result.stdout

# --- The watcher is the PHP environment service (build/product/ols-cpanel-php.{path,service}; tests/product_package.py) ---------------
assert not (ROOT / "build/product/ols-cpanel-php-ext.path").exists() and not (ROOT / "build/product/ols-cpanel-php-ext.service").exists()
print("phpredis build pins, spec, release guard, deterministic payload, index checks passed.")
