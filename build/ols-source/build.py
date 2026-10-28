#!/usr/bin/python3
"""Reproducible product build of OLS from the pinned upstream tag plus reviewed patches.
Runs the compile inside the pinned builder image; never installs anything on the host."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import uuid
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": os.environ.get("HOME", "/tmp")}

def run(argv, cwd=None):
    subprocess.run(argv, cwd=cwd, env=ENV, check=True, stdin=subprocess.DEVNULL)

def output(argv, cwd=None):
    return subprocess.run(argv, cwd=cwd, env=ENV, check=True, capture_output=True, text=True).stdout.strip()

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def third_party_lock(tree):
    # Upstream third-party scripts clone some branches and download unchecksummed tarballs;
    # record exactly what was resolved so later builds can refuse drift.
    lock = {"git": {}, "archives": {}}
    for path in sorted(tree.joinpath("src").rglob(".git")):
        repo = path.parent
        if len(repo.relative_to(tree).parts) > 6:
            continue
        name = str(repo.relative_to(tree))
        lock["git"][name] = {"commit": output(["git", "-C", str(repo), "rev-parse", "HEAD"]),
                             "url": subprocess.run(["git", "-C", str(repo), "config", "--get", "remote.origin.url"],
                                                   env=ENV, capture_output=True, text=True).stdout.strip()}
    lock["unversioned_dirs"] = []
    for path in sorted(tree.joinpath("src").glob("*")):
        if path.is_file() and path.name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".zip")):
            lock["archives"][path.name] = sha256(path)
        elif path.is_dir() and not (path / ".git").exists():
            # Extracted from an archive that upstream scripts deleted; only the name/version is known.
            lock["unversioned_dirs"].append(path.name)
    return lock

def patch_change_sha256(path):
    """Digest of what a patch changes (from its first diff on): its mail header (author, date, subject) does not
    change the build output, so it does not invalidate the cache."""
    text = path.read_bytes()
    start = text.find(b"\ndiff --git ")
    return hashlib.sha256(text[start + 1:] if start >= 0 else text).hexdigest()

def third_party_cache(source):
    # Third-party output depends only on pinned inputs, so it is cached by them.
    key = hashlib.sha256(json.dumps([source["third_party_commit"], source["builder_image"]]
                                    + [patch_change_sha256(HERE / "third-party-patches" / n)
                                       for n in source["third_party_patches"]]).encode()).hexdigest()[:24]
    return ROOT / "artifacts/ols-third-party" / key

def third_party_complete(tree):
    return (tree / ".olscp-built").is_file() and all((tree / "lib" / name).is_file() for name in
                                                     ("libssl.a", "libcrypto.a", "libcurl.a", "libmodsecurity.a"))

def checkout(url, commit, target):
    run(["git", "init", "-q", str(target)])
    run(["git", "-C", str(target), "fetch", "-q", "--depth", "1", url, commit])
    run(["git", "-C", str(target), "checkout", "-q", "FETCH_HEAD"])
    if output(["git", "-C", str(target), "rev-parse", "HEAD"]) != commit:
        raise SystemExit("Pinned commit mismatch for " + url)

def main():
    if os.geteuid() == 0:
        raise SystemExit("Run as the development user; the build uses rootless podman")
    source = json.loads((HERE / "source.json").read_text())
    work = ROOT / "artifacts/ols-build" / uuid.uuid4().hex
    (work / "out").mkdir(parents=True)
    started = datetime.now(timezone.utc).isoformat()
    checkout(source["upstream"], source["commit"], work / "openlitespeed")
    if output(["cat", "LSQUICCOMMIT"], cwd=work / "openlitespeed") != source["lsquic_commit"]:
        raise SystemExit("Upstream lsquic pin changed")
    missing = [n for n in source["patches"] if not (HERE / "patches" / n).exists()]
    if missing:
        raise SystemExit("patches withheld until their coordinated disclosure ends (see patches/WITHHELD): "
                         + ", ".join(missing) + "; the released packages contain them")
    for name in source["patches"]:
        run(["git", "apply", "--check", str(HERE / "patches" / name)], cwd=work / "openlitespeed")
        run(["git", "apply", str(HERE / "patches" / name)], cwd=work / "openlitespeed")
    cache = third_party_cache(source)
    if third_party_complete(cache):
        run(["cp", "-a", str(cache), str(work / "third-party")])
    else:
        checkout(source["third_party"], source["third_party_commit"], work / "third-party")
        for name in source["third_party_patches"]:
            patch = str(HERE / "third-party-patches" / name)
            run(["git", "apply", "--check", patch], cwd=work / "third-party")
            run(["git", "apply", patch], cwd=work / "third-party")
    run(["cp", str(HERE / "build-in-container.sh"), str(work / "build-in-container.sh")])
    result = subprocess.run(["podman", "run", "--rm", "--network=slirp4netns", "-v", f"{work}:/build",
                             source["builder_image"], "/bin/sh", "/build/build-in-container.sh"],
                            env=ENV, stdin=subprocess.DEVNULL)
    binary = work / "out/dist/bin/openlitespeed"
    # Cache a complete third-party tree even when the server compile fails afterwards.
    if not cache.exists() and third_party_complete(work / "third-party"):
        cache.parent.mkdir(parents=True, exist_ok=True)
        run(["cp", "-a", str(work / "third-party"), str(cache)])
    manifest = {"schema_version": 1, "kind": "ols-product-build", "started_at": started,
                "finished_at": datetime.now(timezone.utc).isoformat(), "source": source,
                "patch_sha256": {n: sha256(HERE / "patches" / n) for n in source["patches"]},
                "third_party_patch_sha256": {n: sha256(HERE / "third-party-patches" / n)
                                             for n in source["third_party_patches"]},
                "third_party_cache": str(cache), "container_exit": result.returncode, "result": "pass" if result.returncode == 0 and binary.is_file() else "fail"}
    if result.returncode == 0:
        lock = third_party_lock(work / "third-party")
        (work / "third-party.lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        pinned = HERE / "third-party.lock.json"
        if pinned.is_file():
            expected = json.loads(pinned.read_text())
            manifest["third_party_lock_match"] = expected == lock
            if expected != lock:
                manifest["result"] = "fail"
                manifest["error"] = "third-party sources differ from build/ols-source/third-party.lock.json"
        else:
            manifest["third_party_lock_match"] = None
    if manifest["result"] == "pass":
        manifest["artifacts"] = {str(p.relative_to(work / "out")): sha256(p)
                                 for p in sorted((work / "out/dist").rglob("*")) if p.is_file()}
        manifest["version"] = (work / "out/version.txt").read_text().splitlines()[:1]
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"path": str(work), "result": manifest["result"]}))
    return 0 if manifest["result"] == "pass" else 1

if __name__ == "__main__":
    sys.exit(main())
