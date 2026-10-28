#!/usr/bin/python3
import pathlib
import subprocess
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/vm-qualification"
manifest = (ROOT / "broker/Cargo.toml").read_text()
deps = manifest.split("[dependencies]", 1)[1].split("\n[", 1)[0]
# Exact dependency pins and a committed lock file: the broker is part of the trusted computing base.
versions = re.findall(r'^\w+ = (?:"([^"]+)"|\{ version = "([^"]+)")', deps, re.M)
assert versions and all((a or b).startswith("=") for a, b in versions), versions
assert (ROOT / "broker/Cargo.lock").is_file()
source = (ROOT / "broker/src/main.rs").read_text()
panel = {path.name: path.read_text() for path in (ROOT / "broker/src/panel").glob("*.rs")}
for required in ("deny_unknown_fields", "SO_PEERCRED", "MAX_REQUEST", "CAPABILITY_REPLAYED", "0o600", "0o666",
                 "MAX_CONNECTIONS_PER_UID", "REQUEST_DEADLINE", "impl Drop for Slot", "log_safe", "STATUS_CACHE"):
    assert required in source, required
for forbidden in ("Command::new(\"/bin/sh\"", "Command::new(\"sh\"", "\"exec\"", "read_path", "write_file"):
    assert forbidden not in source, forbidden
    for name, text in panel.items():
        assert forbidden not in text.split("#[cfg(test)]", 1)[0], (name, forbidden)
# The audit log: appended, private, never through a link.
assert "panel::audit(&state.panel.config.audit_log" in source
assert ".mode(0o600)" in panel["mod.rs"] and "O_NOFOLLOW" in panel["mod.rs"]

# Plugin operations of the contract (docs/product-interfaces.md, "Plugin data and actions"): each on its
# own socket only; tenants never reach an admin operation.
contract = (ROOT / "docs/product-interfaces.md").read_text()
plugin = contract.split("## Plugin data and actions (release 1)", 1)[1]
admin_ops = re.findall(r"^\| `((?:server|inventory|compat|plan|generation|doctor|job|cache|php|admin)\.[a-z_]+)`", plugin, re.M)
tenant_ops = re.findall(r"^\| `(tenant\.[a-z_]+)`", plugin, re.M)
assert sorted(admin_ops) == sorted(["server.status", "server.metrics", "inventory.accounts", "compat.findings", "plan.latest",
                                    "generation.list", "doctor.report", "job.list", "job.status", "cache.stats", "admin.cache_limits",
                                    "admin.objcache", "php.status", "admin.metrics", "admin.requests", "admin.request_status",
                                    "admin.audit", "admin.notify", "admin.notify_set", "admin.notify_test",
                                    "admin.schedule", "admin.schedule_add", "admin.schedule_cancel", "admin.update", "admin.bundle"]), admin_ops
assert sorted(tenant_ops) == ["tenant.cache_purge", "tenant.cache_stats", "tenant.domains", "tenant.logs", "tenant.metrics", "tenant.objcache", "tenant.perf",
                            "tenant.php", "tenant.php_errors", "tenant.php_restart", "tenant.request", "tenant.requests", "tenant.sites", "tenant.status"], tenant_ops
for op in admin_ops + ["cap.issue", "cap.execute"]:
    assert f'(Socket::Admin, "{op}")' in source and f'(Socket::Tenant, "{op}")' not in source, op
for op in tenant_ops:
    assert f'(Socket::Tenant, "{op}")' in source and f'(Socket::Admin, "{op}")' not in source, op
assert "user_name(peer.uid).filter(|_| peer.uid != 0)" in source

# The job table equals the contract's action table (plus ols.plan_hybrid), argv fixed, scope checked.
jobs = panel["jobs.rs"]
table = dict(re.findall(r"^\| `(ols\.[a-z_]+)` \| `ols-cpanel ([^`]+)`", contract, re.M))
table["ols.plan_hybrid"] = "install --prepare --hybrid --format=json"
assert "`ols.plan_hybrid` (`install --prepare --hybrid`)" in contract
# The purge job's argv is completed from its scope (broker/src/panel/cache.rs purge_flag); the table row says so.
assert "scope `server` \\| `account:<user>` \\| `domain:<domain>`" in contract
table["ols.cache_purge"] = "cache purge"
# FV-03: the restart and install jobs' argv is completed from their scopes (broker/src/panel/php.rs restart_flag, opcache_flag).
assert "scope `server` \\| `account:<user>` (\"PHP manager\")" in contract and "scope `server` \\| `version:ea-phpNN` (\"PHP manager\")" in contract
table["ols.php_restart"] = "php restart"
table["ols.opcache_install"] = "php opcache install"
rust = {name: " ".join(re.findall(r'"([^"]*)"', args)) for name, args in
        re.findall(r'Action \{ name: "(ols\.[a-z_]+)", args: &\[([^\]]*)\]', jobs)}
assert rust.keys() == table.keys(), (rust.keys(), table.keys())
for name, command in table.items():
    assert rust[name] == command.replace("--plan=<scope>", "--plan="), (name, rust[name], command)
for required in (".env_clear()", ".envs(command::ENV)", "process_group(0)", "Stdio::null()", "MAX_OUTPUT: u64 = 1 << 20",
                 "mode(0o700)", "O_NOFOLLOW", "\"BUSY\"", "job_start", "job_finish", "fn recover(", "write_durable"):
    assert required in jobs, required
# Two process starts outside the tests: the job itself and (RV-31 item 7) `systemctl stop` of a job's transient unit; never a shell.
assert jobs.count("Command::new(") == 2 + jobs.split("#[cfg(test)]", 1)[1].count("Command::new(")
assert "Command::new(&launcher.systemctl)" in jobs and "unit: true" in jobs and "--unit=" in jobs
assert "sh -c" not in jobs.split("#[cfg(test)]", 1)[0]
assert '"STALE"' in source and "summary::plan_digest" in source and "panel::status_digest" in source
assert "valid_plan_id" in panel["summary.rs"] and "is_ascii_alphanumeric() || b == b'_' || b == b'-'" in panel["summary.rs"]
# Product commands: fixed argv, the engine runner (no shell, fixed environment), 30 s, cached as the contract says.
product = panel["product.rs"]
for required in ('&["status", "--format=json"]', '&["generation", "list", "--format=json"]',
                 '&["doctor", "--read-only", "--format=json"]', "TIMEOUT: Duration = Duration::from_secs(30)",
                 "STATUS_CACHE: Duration = Duration::from_secs(2)", "DOCTOR_CACHE: Duration = Duration::from_secs(60)", "command::run("):
    assert required in product, required
assert 'cli: PathBuf::from("/usr/local/ols-cpanel/bin/ols-cpanel")' in panel["mod.rs"]
# Metrics: the OLS 1.9.3 format, default directory, 30 s staleness; certificates parsed without a process.
metrics = panel["metrics.rs"]
for required in ('DEFAULT_DIR: &str = "/run/ols-cpanel/status"', "STALE_AFTER: u64 = 30", '"VERSION: LiteSpeed Web Server/"',
                 '"REQ_RATE "', '"EXTAPP "', '"BPS_IN:"', '"MAXCONN:"', '"EOF"', '"unavailable"', '"stale"'):
    assert required in metrics, required
# FV-05 history: fixed-size rings, no link followed, bounded count, no process started.
history = panel["history.rs"]
for required in ("O_NOFOLLOW", "MAX_VHOST_RINGS: usize = 1000", "PRUNE_AFTER", "mode(0o600)", "mode(0o700)", "fn tenant_history", "NOT_FOUND"):
    assert required in history, required
assert "Command" not in history
assert "Command" not in panel["certificate.rs"] and "fn not_after_der" in panel["certificate.rs"]

build = (ROOT / "build/broker/build.sh").read_text()
assert "rust@sha256:" in build and "x86_64-unknown-linux-musl" in build
result = subprocess.run([sys.executable, str(TOOLS / "broker_probe.py"), "--broker", "/x"], capture_output=True, text=True)
assert result.returncode == 2 and "--lab-tenants" in result.stderr
print("Broker pins, protocol guards, plugin operations, job table and probe guard checks passed.")
