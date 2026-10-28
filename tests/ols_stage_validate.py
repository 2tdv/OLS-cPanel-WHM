#!/usr/bin/python3
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_stage_validate as stage

assert stage.verdict(0, "[OK] Configuration test passed.\n")["valid"]
for code, text in [(1, "[OK]"), (0, "[ERROR] [PlainConf] parseline found more '}'"),
                   (0, "2026 [WARN] [PlainConf] Not support [thisisnotadirective 1] in file x:3"),
                   (0, "[ERROR] [config:server:listener] failed to start listener on address bad"),
                   (0, "Can not set address bogus to webAdmin!"),
                   (0, "[WARN] [1] Path for vhost root is not accessible: /var/lib/x/"),
                   (0, "[WARN] [139358] [config:server:vhosts:vhost:olscp-gen] configuration failed!"),
                   (0, "[WARN] [1] some new warning nobody reviewed")]:
    assert not stage.verdict(code, text)["valid"], text
assert stage.verdict(0, "[INFO] No lsadm account, keep configuration directory ownership.")["valid"]
assert stage.verdict(0, "2026 [WARN] [1] [config:server:vhosts:vhost:p] Uid of /var/www/html/ is 0, smaller than "
                        "minimum requirement 11, use server uid!")["valid"]

with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    live = temp / "live"
    for name in ["modules", "share", "conf"]:
        (live / name).mkdir(parents=True)
    (live / "conf/mime.properties").write_text("html = text/html\n")
    candidate = temp / "candidate"
    (candidate / "vhosts/lab").mkdir(parents=True)
    (candidate / "httpd_config.conf").write_text("serverName x\n")
    (candidate / "vhosts/lab/vhconf.conf").write_text("docRoot $VH_ROOT/html/\n")
    (candidate / "admin_config.conf").write_text("listener a {\n}\n")
    root = temp / "root"
    stage.stage(candidate, root, live)
    assert (root / "conf/httpd_config.conf").read_text() == "serverName x\n"
    assert (root / "conf/vhosts/lab/vhconf.conf").is_file()
    assert (root / "conf/mime.properties").is_file() and (root / "admin/conf/admin_config.conf").is_file()
    assert (root / "modules").is_symlink() and (root / "modules").resolve() == (live / "modules").resolve()
    assert not (root / "lsns").exists()
    assert all((root / name).is_dir() for name in stage.WRITABLE)
    digest = stage.tree_digest(live)
    (live / "conf/new").write_text("x")
    assert stage.tree_digest(live) != digest

result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/ols_stage_validate.py"), "/nonexistent"],
                        capture_output=True, text=True)
assert result.returncode == 2
print("OLS staged-validation verdict, staging layout and privilege guard checks passed.")

# Log directories named by the candidate are isolated (tmpfs) during "-t": never the live files/FIFOs.
import tempfile as _tempfile
with _tempfile.TemporaryDirectory(dir=ROOT) as _temp:  # /tmp is private in the namespace; use the writable checkout for a non-private path
    _cand, _logs = pathlib.Path(_temp, "cand"), pathlib.Path(_temp, "live-logs")
    (_cand / "vhosts/a").mkdir(parents=True)
    _logs.mkdir()
    (_cand / "httpd_config.conf").write_text(f"errorlog {_logs}/error.log {{\n}}\naccesslog $SERVER_ROOT/logs/x.log {{\n}}\n")
    (_cand / "vhosts/a/vhconf.conf").write_text(f"accesslog {_logs}/access.fifo {{\n}}\naccesslog /nonexistent/dir/x {{\n}}\n")
    assert stage.log_dirs(_cand) == [f"m:{_logs}"], stage.log_dirs(_cand)
    # Missing directory: tmpfs on the nearest existing ancestor, the directory created inside it.
    (_cand / "vhosts/a/vhconf.conf").write_text(f"accesslog {_logs}/run/ols/logs/access.fifo {{\n}}\n")
    assert stage.log_dirs(_cand) == [f"m:{_logs}", f"d:{_logs}/run/ols/logs"], stage.log_dirs(_cand)
assert 'm:*) mount -t tmpfs' in stage.INNER and 'd:*) mkdir -p' in stage.INNER
# Patch 0009 runtime state: /run is private in the namespace; log directories under it are only created.
assert "mount -t tmpfs -o mode=0755 tmpfs /run;" in stage.INNER and "/run/ols-cpanel/lshttpd" in stage.INNER
with _tempfile.TemporaryDirectory(dir=ROOT) as _temp:
    _cand = pathlib.Path(_temp, "cand")
    (_cand / "vhosts/a").mkdir(parents=True)
    (_cand / "httpd_config.conf").write_text("accesslog /run/ols-cpanel/logs/access.fifo {\n}\n")
    assert stage.log_dirs(_cand) == ["d:/run/ols-cpanel/logs"], stage.log_dirs(_cand)
print("Staged validation log isolation checks passed.")
