#!/usr/bin/python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_config_lint as lint

good = (ROOT / "build/vm-qualification/ols-lab/ownership_httpd_config.conf").read_text()
assert lint.lint(good) == []
assert lint.lint((ROOT / "build/vm-qualification/php-parity/httpd_config.conf").read_text()) == []
cases = {
    "unclosed": good + "virtualHost broken {\n  vhRoot /x/\n",
    "extra-brace": good + "}\n",
    "bad-address": good + "listener bad {\n  address not-an-address\n  secure 0\n}\n",
    "bad-port": good + "listener bad {\n  address *:70000\n}\n",
    "secure-no-cert": good + "listener tls {\n  address 127.0.0.1:8443\n  secure 1\n}\n",
    "webadmin-on": good.replace("disableWebAdmin                  1", "disableWebAdmin                  0"),
    "cdn-trust-on": good.replace("autoDetectCdn                    0\n", ""),
    "no-cgirlimit": good.replace("CGIRLimit {", "CGIRLimitX {"),
}
for name, text in cases.items():
    assert lint.lint(text), name
for address in ["*:80", "[ANY]:443", "127.0.0.1:8088", "[::1]:80", "192.0.2.10:443"]:
    assert lint.valid_address(address), address
for address in ["", "80", "*:", "*:0", "host:80", "[::1:80", "1.2.3.4:abc"]:
    assert not lint.valid_address(address), address
assert lint.lint("rewrite {\n  rules <<<END\nRewriteRule ^a#b$ /c [L]\nEND\n}\n", False) == []
print("OLS config lint structure, listener and product-policy checks passed.")
