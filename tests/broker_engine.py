#!/usr/bin/python3
"""Static checks of the broker's engine socket against docs/product-interfaces.md and the recorded compile
(no root, no Rust toolchain: the behaviour itself is covered by the Rust unit tests in broker/src/engine/)."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/src"
main = (BROKER / "main.rs").read_text()
engine = {path.name: path.read_text() for path in (BROKER / "engine").glob("*.rs")}
allowlist, command, apply, events, module = (engine[n] for n in ("allowlist.rs", "command.rs", "apply.rs", "events.rs", "mod.rs"))
contract = (ROOT / "docs/product-interfaces.md").read_text()

# Socket: its own slot pool, root or olscpanel peers, group socket only when the group exists.
for required in ('"{dir}/engine.sock"',"Socket::Engine", "MAX_ENGINE_CONNECTIONS", 'ENGINE_USER: &str = "olscpanel"',
                 "user_id(ENGINE_USER) != Some(peer.uid)", "group_id(ENGINE_USER)", "0o660", "0o600",
                 "MAX_APPLY_REQUEST: usize = 64 << 20", "MAX_REPLY: usize = 32 << 20", "ENGINE_DEADLINE: Duration = Duration::from_secs(30)",
                 'request.op != "engine.apply"', "OUTPUT_TOO_LARGE"):
    assert required in main, required
assert "MAX_REQUEST: usize = 64 * 1024" in main and "REQUEST_DEADLINE: Duration = Duration::from_secs(5)" in main
# Every engine operation of the contract is dispatched on the engine socket only.
operations = re.findall(r"^\| `(engine\.[a-z_]+)` \|", contract, re.M)
assert sorted(operations) == sorted(["engine.run", "engine.apply", "engine.status", "engine.enforce", "engine.health",
                                     "engine.recover", "engine.events", "engine.events_done", "engine.events_quarantine",
                                     "engine.restrictions_fold"]), operations
for op in operations:
    assert f'(Socket::Engine, "{op}")' in main, op
    assert f'(Socket::Admin, "{op}")' not in main and f'(Socket::Tenant, "{op}")' not in main, op

# Execution: no shell, the fixed environment, limits that refuse instead of truncating.
for source in engine.values():
    for forbidden in ('Command::new("/bin/sh"', 'Command::new("sh"', '.arg("-c")', '"/bin/bash"',"read_path", "write_file"):
        assert forbidden not in source, forbidden
for required in (".env_clear()", '("PATH", "/usr/bin:/bin:/usr/sbin"), ("LANG", "C"), ("LC_ALL", "C")',
                 "TIMEOUT: Duration = Duration::from_secs(120)", "MAX_OUTPUT: usize = 16 << 20", "process_group(0)",
                 "Stdio::null()", "killpg"):
    assert required in command, required
assert command.count("Command::new(") == 1

# The allowlist table: the PHP builder's constant code byte for byte, every recorded executable present,
# curl absent, and the Rust test that replays the recorded compile.
php = (ROOT / "src/Ols/Compiler/ServerConfigurationBuilder.php").read_text()
parts = re.search(r"public const CONSTANTS_CODE = ((?:'[^']*'\s*(?:\.\s*)?)+);", php).group(1)
constants = "".join(re.findall(r"'([^']*)'", parts))
assert f'r#"{constants}"#' in allowlist
table = allowlist.split("const CAT: Arg", 1)[1].split("\n];", 1)[0]
calls = json.loads((ROOT / "tests/Fixtures/lab-snapshot/compile-production.json").read_text())["calls"]
for call in calls:
    program = call["argv"][0]
    if program == "/usr/bin/curl":
        assert program not in table
        continue
    template = re.sub(r"/opt/cpanel/[a-z][a-z0-9-]*/", "/opt/cpanel/{version}/", program)
    assert f'"{template}"' in table or f'"{program}"' in table, program
    if program.endswith("/php"):
        assert call["argv"][1:] == ["-n", "-r", constants], call["argv"]
assert "fn recorded_compiles_are_accepted" in allowlist and "compile-production.json" in allowlist
for program in ("/usr/bin/cat", "/usr/local/cpanel/bin/whmapi1", "/usr/bin/test", "/usr/sbin/runuser", "/usr/bin/find",
                "/opt/cpanel/{version}/root/usr/bin/php", "/usr/bin/hostname", "/usr/sbin/ip", "/usr/bin/sha256sum"):
    assert program in allowlist, program
for api in ("listaccts", "php_get_vhost_versions", "php_get_handlers"):
    assert f'"{api}"' in allowlist and api in contract, api
assert len(re.findall(r"^\s*Rule \{", table, re.M)) == 19

# Apply: generation grammar, tree paths, health URL prefix, the files the broker adds itself.
for required in ('"httpd_config.conf"', '"marker/generation"', '"summary.json"', '["vhosts", vhost, "vhconf.conf"]', '["health", vhost, "id"]',
                 '"/.ols-cpanel-generation/"', '["cpanel-proxy", "server-default", "olscp-gen"]', 'strip_prefix("svc.")',
                 '"health.json"', '"EPOCH"', '"SOURCE_SHA256"', "create_new(true)", "O_NOFOLLOW", "remove_dir_all",
                 "MAX_FILES: usize = 64 << 20", "dumps_ordered_list", "activator.stage(", "activator.validate(", "activator.activate("):
    assert required in apply, required
assert 'OsString::from("stage-validate")' in module and "/usr/local/ols-cpanel/libexec/ols-cpanel-activator" in module
# engine.health: the activator's health command with the same 0..60 bound.
activator_cli = (BROKER / "activator/cli.rs").read_text()
assert '"health" => activator.health(seconds(args)?)' in activator_cli and "MAX_HEALTH_SECONDS: i64 = 60" in activator_cli
assert "crate::activator::cli::MAX_HEALTH_SECONDS" in module and "activator.health(seconds)" in module
assert "MAX_GRACE: i64 = 86400" in module and '"/etc/userdatadomains"' in module
for required in ("MAX_PENDING: usize = 1000", 'join("done")', "O_NOFOLLOW", '"quarantine"', "RENAME_NOREPLACE", "oldest_first"):
    assert required in events, required
# Review RV-29: intents folded (fold before enforcing), the enforcement thread of the broker, bounded activator waits.
restrictions = engine["restrictions.rs"]
for required in ("restrict_since(", "remove_file", "fsync_dir(", "(malformed)"):
    assert required in restrictions, required
for required in ("thread::spawn(move || enforcement(enforcement_state))", "enforcement_round()", "panel::audit("):
    assert required in main, required
for required in ("ENFORCE_GRACE: f64 = 300.0", "ENFORCE_PERIOD: f64 = 5.0", "enforce_ahead(ENFORCE_GRACE, ENFORCE_LEAD)"):
    assert required in module, required
generation = (BROKER / "activator/generation.rs").read_text()
runtime = (BROKER / "activator/runtime.rs").read_text()
for required in ("TRANSACTION_SECONDS: f64 = 120.0", "fn lock_within(", "stopped-without-lock", "DEADLINE_EXCEEDED"):
    assert required in generation, required
assert "Command::new" not in runtime and '"--insecure"' in runtime and '"--resolve"' in runtime and '"-L"' not in runtime.split("mod tests")[0]
assert '"https://"' in apply and 'port == "443"' in apply
assert "fn home_mount(" in allowlist and "b == b'_' || b == b'-'" in allowlist
print("Broker engine socket guard checks passed.")
