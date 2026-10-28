#!/usr/bin/python3
"""Portable development checks; never a compatibility certificate."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PHP = "/usr/local/cpanel/3rdparty/php/84/bin/php"
if len(sys.argv) == 2:
    PHP = sys.argv[1]
if not pathlib.Path(PHP).is_absolute():
    raise SystemExit("Pass an absolute PHP CLI path")
for path in sorted([*ROOT.glob("src/**/*.php"), *ROOT.glob("tests/**/*.php"), ROOT / "bin/ols-cpanel"]):
    subprocess.run([PHP, "-n", "-l", str(path)], check=True, stdout=subprocess.DEVNULL)
subprocess.run([PHP, "-n", str(ROOT / "tests/run.php")], check=True)
cli = [PHP, "-n", str(ROOT / "bin/ols-cpanel")]
result = subprocess.run(cli + ["doctor", "--read-only", "--format=json",
    "--fixture=" + str(ROOT / "tests/Fixtures/platform.json")], capture_output=True, text=True, check=False)
assert result.returncode == 2, result.stderr
report = json.loads(result.stdout)
assert report["synthetic"] and not report["compatibility"]["production_activation_allowed"]
for args in [["install", "--cutover"], ["doctor"], ["doctor", "--read-only", "--format=json", "--force"], ["--format=json"],
             ["no-such-command", "--format=json"]]:
    result = subprocess.run(cli + args, capture_output=True, text=True, check=False)
    # Text mode: nothing on stdout; --format=json: exactly one JSON object {result, code, error} (review RV-29, 17).
    assert result.returncode == 64, (args, result.returncode)
    if "--format=json" in args:
        failure = json.loads(result.stdout)
        assert failure["result"] == "usage" and failure["code"] == 64 and failure["error"], failure
    else:
        assert not result.stdout, args
for name in ["docs/development-baseline.yaml", "docs/requirements.yaml", "compatibility/matrix.yaml"]:
    # These generated tracking files use the JSON subset of YAML 1.2 (development copy only; not in the public copy).
    if (ROOT / name).exists():
        json.loads((ROOT / name).read_text())
print("PHP lint, unit and CLI refusal checks passed. G0 qualification: NOT RUN.")

subprocess.run([sys.executable, str(ROOT / "tests/evidence.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/service_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/disable_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_package_audit.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_lab_cycle.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_stage_validate.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_source_build.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/product_package.py")], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/release_tool.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_ownership_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/php_parity.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/tenant_fixtures.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_config_lint.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/tenant_isolation_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/fpm_translate.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/htaccess_translate.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_reboot_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/compiler_equivalence.py"), PHP], check=True)

# The product builder replays every command the lab compiler ran on the lab server (byte-identical output).
subprocess.run([PHP, "-n", str(ROOT / "tests/compile_replay.php")], check=True)

# Deployment layer (prepare, cutover, return, hooks, uninstall) against a scripted fake host, and the recovery
# script and hybrid texts byte-identical to the lab reference.
subprocess.run([PHP, "-n", str(ROOT / "tests/deployment.php")], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/deployment_texts.py"), PHP], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/compile_replay_hybrid.py")], check=True)

# HTTP/3 (FV-04): operator input, csf/nftables decisions and the protocol share parser in Python and PHP, the compiled QUIC
# configuration and its opt-out, and the lab experiment's offline checks. The firewall steps of the cutover and the
# recovery script are in tests/deployment.php and tests/deployment_texts.py; `http3 status` is in tests/engine.php.
subprocess.run([sys.executable, str(ROOT / "tests/http3.py"), PHP], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/http3_probe.py")], check=True)

# LSCache (FV-01): storage primitives (Python and PHP on temporary trees) and the lab experiment's offline checks.
subprocess.run([sys.executable, str(ROOT / "tests/lscache.py"), PHP], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/lscache_probe.py")], check=True)

# WAF and security (FV-02): translators (lab reference and PHP port byte-equivalent), whole compilations with
# cPanel ModSecurity states and security inputs, and the lab experiment's offline checks.
subprocess.run([sys.executable, str(ROOT / "tests/modsec_equivalence.py"), PHP], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/compile_replay_security.py"), PHP], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/modsec_probe.py")], check=True)

# Object cache (FV-09): configuration, enable/disable/flush/status, lifecycle, wp-cli argv, hook trigger (scripted fake
# host) and the lab experiment's offline checks.
subprocess.run([PHP, "-n", str(ROOT / "tests/objcache.php")], check=True, stdout=subprocess.DEVNULL)
# PHP redis extension for the object cache (prebuilt build, build from the packaged source, watcher, removal) against a
# scripted fake host, and the pins of its build pipeline (build/php-ext).
subprocess.run([PHP, "-n", str(ROOT / "tests/php_extensions.php")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run([sys.executable, str(ROOT / "tests/php_ext_build.py")], check=True)
subprocess.run([sys.executable, str(ROOT / "tests/objcache_probe.py")], check=True)

# Engine runtime: runner, local and broker engines, reconciler decisions, paced enforcement, hook, CLI exit codes.
subprocess.run([PHP, "-n", str(ROOT / "tests/engine.php")], check=True, stdout=subprocess.DEVNULL)
print("Engine runtime unit checks passed.")

# Production generation trees and source digests: the product equals the lab reference byte for byte.
# `cache stats|purge` (FV-01 plugin part), `upgrade` and `php restart` against temporary trees and a scripted host.
subprocess.run([PHP, "-n", str(ROOT / "tests/cache_upgrade.php")], check=True, stdout=subprocess.DEVNULL)
print("Cache, upgrade and PHP restart checks passed.")

# LSCache automatic cleanup (FV-01): expiry, per-site and server caps, emergency trim, link and control-file safety, young entries,
# the limits file, the confined helper chain and the CLI. The Python/PHP equality of the trim is in tests/lscache.py.
subprocess.run([PHP, "-n", str(ROOT / "tests/cache_clean.php")], check=True, stdout=subprocess.DEVNULL)
print("Cache cleanup checks passed.")

# PHP manager (FV-03): per-account limits input, process view and runaway detection, OPcache status, install and
# reconcile against temporary trees and a scripted host.
subprocess.run([PHP, "-n", str(ROOT / "tests/php_manager.php")], check=True, stdout=subprocess.DEVNULL)
print("PHP manager checks passed.")

# Operations (FV-07): notification settings, de-duplication, the daily limit and the sent-ledger; maintenance windows through a scripted
# broker; the update check; the support bundle's redaction with planted secrets; the root-only commands.
subprocess.run([PHP, "-n", str(ROOT / "tests/operations.php")], check=True, stdout=subprocess.DEVNULL)
print("Operations checks passed.")

# PHP environment (FV-10): the applier (lsphp, OPcache, redis per EA4 PHP version, state, back-off, units), the reconciler's
# lsphp guard and the recommended EA4 profile against temporary trees and a scripted host.
subprocess.run([PHP, "-n", str(ROOT / "tests/htaccess_rewrite.php")], check=True, stdout=subprocess.DEVNULL)
subprocess.run([PHP, "-n", str(ROOT / "tests/php_env.php")], check=True, stdout=subprocess.DEVNULL)
print("PHP environment checks passed.")
subprocess.run([sys.executable, str(ROOT / "tests/ea4_profile_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/generation_tree.py"), PHP], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ws_echo.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/cpanel_vhosts.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_production_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/cpanel_hook_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_generation_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/activator_parity.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/broker_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/broker_engine.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/plugin_probe.py")], check=True)

# WHM gateway and cPanel page API as CGI requests under php-cgi, with a stub broker client.
subprocess.run([sys.executable, str(ROOT / "tests/plugin_gateway.py"), PHP], check=True)

# WHM and cPanel interfaces against the gateway contract (the Node tests and builds: build/ui/test.sh).
subprocess.run([sys.executable, str(ROOT / "tests/ui_static.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/show_evidence.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/english_only.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/php_handler_probe.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_events.py")], check=True)

subprocess.run([sys.executable, str(ROOT / "tests/ols_reconcile_probe.py")], check=True)
