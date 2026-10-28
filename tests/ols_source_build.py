#!/usr/bin/python3
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HERE = ROOT / "build/ols-source"
sys.path.insert(0, str(HERE))
import build

source = json.loads((HERE / "source.json").read_text())
assert re.fullmatch(r"[0-9a-f]{40}", source["commit"]) and re.fullmatch(r"[0-9a-f]{40}", source["third_party_commit"])
assert re.fullmatch(r".+@sha256:[0-9a-f]{64}", source["builder_image"])
# A public copy may hold security patches back until their disclosure (patches/WITHHELD: "<name> <sha256>").
_withheld = {}
if (HERE / "patches/WITHHELD").exists():
    _withheld = dict(l.split() for l in (HERE / "patches/WITHHELD").read_text().splitlines() if l.strip() and not l.startswith("#"))
    assert all(re.fullmatch(r"[0-9a-f]{64}", d) and n in source["patches"] and not (HERE / "patches" / n).exists() for n, d in _withheld.items())
assert sorted([*(p.name for p in (HERE / "patches").glob("*.patch")), *_withheld]) == source["patches"]
assert sorted(p.name for p in (HERE / "third-party-patches").glob("*.patch")) == source["third_party_patches"]
for path in [*(HERE / "patches").glob("*.patch"), *(HERE / "third-party-patches").glob("*.patch")]:
    text = path.read_text()
    assert text.startswith("From ") and "\nSubject: [PATCH" in text, path.name
    assert not re.search(r"co-authored-by|generated with", text, re.I), path.name

spec = (HERE / "ols-cpanel-openlitespeed.spec").read_text()
assert not re.search(r"^%(pre|post|preun|postun|pretrans|posttrans|trigger\w*)\b", spec, re.M)
assert "lsphp" not in spec and "AutoReqProv:    no" in spec and "Conflicts:      openlitespeed" in spec
assert "httpd_config.conf" not in spec and "Example" not in spec
assert "/usr/libexec/ols-cpanel/ols-cpanel-logship" in spec and "ols-cpanel-logs.service" in spec
assert "/usr/libexec/ols-cpanel/ols-cpanel-reload" in spec
logs_unit = (HERE / "ols-cpanel-logs.service").read_text()
assert "mkfifo -m 0620" in logs_unit and "chown root:nobody" in logs_unit and "0622" not in logs_unit
assert "RuntimeDirectory=ols-cpanel ols-cpanel/logs" in logs_unit and "RuntimeDirectoryPreserve=restart" in logs_unit
reload_script = (HERE / "ols-cpanel-reload").read_text()
assert "kill -USR1" in reload_script and "lshttpd - #" in reload_script and 'wait_ready "new:$old"' in reload_script
assert "ExecReload=/usr/libexec/ols-cpanel/ols-cpanel-reload" in (HERE / "ols-cpanel.service").read_text()
logship = (HERE / "ols-cpanel-logship").read_text()
assert "mkfifo -m 0620" in logship and "chown root:nobody" in logship and "0622" not in logship and '<>"$DIR/access.fifo"' in logship and "--suffix=-bytes_log" in logship
unit = (HERE / "ols-cpanel.service").read_text()
assert "Requires=ols-cpanel-logs.service" in unit
assert "SuccessExitStatus=255" in unit and "ConditionPathExists=/usr/local/lsws/conf/httpd_config.conf" in unit

with tempfile.TemporaryDirectory() as temp:
    tree = pathlib.Path(temp)
    repo = tree / "src/libfoo"
    repo.mkdir(parents=True)
    env = {"PATH": "/usr/bin:/bin", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "HOME": temp}
    for argv in (["git", "init", "-q"], ["git", "commit", "-q", "--allow-empty", "-m", "x"],
                 ["git", "remote", "add", "origin", "https://example.invalid/libfoo.git"]):
        subprocess.run(argv, cwd=repo, env=env, check=True)
    (tree / "src/bar-1.0.tar.gz").write_bytes(b"archive")
    (tree / "src/notes.txt").write_text("ignored")
    lock = build.third_party_lock(tree)
    assert list(lock["git"]) == ["src/libfoo"] and lock["git"]["src/libfoo"]["url"].endswith("libfoo.git")
    assert re.fullmatch(r"[0-9a-f]{40}", lock["git"]["src/libfoo"]["commit"])
    assert lock["archives"] == {"bar-1.0.tar.gz": build.sha256(tree / "src/bar-1.0.tar.gz")}
print("OLS source pins, patch hygiene, package spec and third-party lock checks passed.")

# RV-07: the recorded packaging-input digest matches, so a changed input cannot reuse a release.
_spec = importlib.util.spec_from_file_location("ols_package", HERE / "package.py")
_package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_package)
assert _package.release(source) == f"1.olscp{source['product_release']}"
print("Product RPM release matches its recorded inputs.")
