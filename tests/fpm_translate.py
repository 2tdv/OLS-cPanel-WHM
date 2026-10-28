#!/usr/bin/python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import fpm_translate as fpm

pool = """[olscp-a_test]
user = "olscpa"
php_admin_flag[allow_url_fopen] = on
php_admin_value[disable_functions] = exec,passthru,shell_exec,system
php_admin_value[doc_root] = "/home/olscpa/public_html"
php_admin_value[error_log] = /home/olscpa/logs/olscp-a_test.php.error.log
php_value[error_reporting] = E_ALL & ~E_NOTICE
; php_admin_value[commented] = x
security.limit_extensions = .phtml .php .php3 .php8
"""
C = {"E_ALL": 32767, "E_NOTICE": 8, "E_STRICT": 2048, "E_DEPRECATED": 8192, "E_WARNING": 2}
entries = fpm.translate(pool, C)
assert entries == [("php_admin_flag", "allow_url_fopen", "1"),
                   ("php_admin_value", "disable_functions", "exec,passthru,shell_exec,system"),
                   ("php_admin_value", "doc_root", "/home/olscpa/public_html"),
                   ("php_admin_value", "error_log", "/home/olscpa/logs/olscp-a_test.php.error.log"),
                   ("php_value", "error_reporting", "32759")]
block = fpm.override_block(entries)
assert block.startswith("phpIniOverride  {\n") and block.endswith("\n}\n") and block.count("\n") == 7
assert fpm.override_block([]) == ""
assert fpm.suffixes(pool) == ["phtml", "php", "php3", "php8"] and fpm.suffixes("") == ["php"]
try:
    fpm.translate("php_admin_value[x] = a}b")
    raise AssertionError("brace accepted")
except ValueError:
    pass
assert fpm.evaluate_constants("E_ALL & ~E_DEPRECATED & ~E_STRICT", C) == 22527
assert fpm.evaluate_constants("(E_WARNING | E_NOTICE)", C) == 10 and fpm.evaluate_constants("E_ALL ^ E_NOTICE", C) == 32759
assert fpm.evaluate_constants("~E_NOTICE & E_ALL", C) == 32759 and fpm.evaluate_constants("6135", C) == 6135
for bad in ["E_ALL; system('id')", "E_UNKNOWN", "(E_ALL", "E_ALL &", "phpinfo()"]:
    try:
        fpm.evaluate_constants(bad, C)
        raise AssertionError(bad)
    except ValueError:
        pass
assert fpm.translate("php_flag[display_errors] = Off\n") == [("php_flag", "display_errors", "0")]
for bad in ["php_flag[x] = maybe\n", "php_value[error_reporting] = E_ALL\n"]:
    try:
        fpm.translate(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
assert fpm.translate("php_admin_value[short_open_tag] = on\nphp_value[x] = Off\nphp_value[y] = \"on\"\n") == [
    ("php_admin_value", "short_open_tag", "1"), ("php_value", "x", ""), ("php_value", "y", "on")]
print("FPM pool to phpIniOverride translation checks passed.")
