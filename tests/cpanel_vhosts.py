#!/usr/bin/python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import cpanel_vhosts as cv
import ols_config_lint as lint
import tenant_isolation_probe as iso

import json
SAMPLE = json.loads((ROOT / "tests/Fixtures/cpanel_vhosts.json").read_text())
ROWS, USERDATA = SAMPLE["rows"], SAMPLE["userdata"]
rows = cv.parse_userdatadomains(ROWS)
assert rows["olscp-c.test"] == {"user": "olscpa", "owner": "root", "type": "addon", "parent": "olscpc.olscp-a.test",
                                "docroot": "/home/olscpa/public_html/olscp-c.test", "http": "172.16.0.4:80",
                                "https": "172.16.0.4:443", "php": "ea-php83"}
vhosts = {v["name"]: v for v in cv.account_vhosts("olscpa", rows, USERDATA)}
assert sorted(vhosts) == ["blog.olscp-a.test", "olscp-a.test", "olscpc.olscp-a.test"]
assert vhosts["olscp-a.test"]["service_domains"] == ["olscp-a.test"] and vhosts["olscp-a.test"]["parked"] == ["olscp-alias.test"]
assert vhosts["blog.olscp-a.test"]["service_domains"] == [] and vhosts["blog.olscp-a.test"]["pool"] == "blog.olscp-a.test"
assert vhosts["olscpc.olscp-a.test"]["pool"] == "olscp-c.test" and vhosts["olscpc.olscp-a.test"]["service_domains"] == ["olscp-c.test"]
assert cv.ancestors(vhosts["blog.olscp-a.test"]) == ["/", "/home", "/home/olscpa", "/home/olscpa/public_html"]
assert cv.ancestors(vhosts["olscp-a.test"]) == ["/", "/home", "/home/olscpa"]
assert [v["name"] for v in cv.nested_in(vhosts["olscp-a.test"], list(vhosts.values()))] == ["blog.olscp-a.test", "olscpc.olscp-a.test"]

# Refusals: wrong servername, a document root outside the account, a foreign alias, two addons.
for broken, message in [(dict(USERDATA, **{"blog.olscp-a.test": USERDATA["blog.olscp-a.test"].replace("servername: blog", "servername: x")}), "servername"),
                        (dict(USERDATA, **{"blog.olscp-a.test": USERDATA["blog.olscp-a.test"].replace("/home/olscpa/public_html/blog", "/home/olscpb/public_html")}), "document root"),
                        (dict(USERDATA, **{"blog.olscp-a.test": USERDATA["blog.olscp-a.test"].replace("www.blog.olscp-a.test", "bad_name..test")}), "invalid domain")]:
    try:
        cv.account_vhosts("olscpa", rows, broken)
        raise AssertionError("accepted " + message)
    except ValueError as exc:
        assert message in str(exc), exc
two = cv.parse_userdatadomains(ROWS + "olscp-d.test: olscpa==root==addon==olscpc.olscp-a.test==/home/olscpa/public_html/olscp-c.test==172.16.0.4:80==172.16.0.4:443====0==ea-php83\n")
try:
    cv.account_vhosts("olscpa", two, USERDATA)
    raise AssertionError("accepted two addons on one vhost")
except ValueError as exc:
    assert "more than one addon" in str(exc)

# The probe's server configuration for this plan: service names only for main and addon domains.
plan = {n: dict(v, user="olscpa") for n, v in vhosts.items()}
config = iso.server_config((iso.TEMPLATES / "ownership_httpd_config.conf").read_text(), plan=plan)
assert lint.lint(config) == []
maps = {line.split()[1]: line.split(None, 2)[2] for line in config.splitlines() if line.strip().startswith("map ")}
# Service names live on a separate service vhost (tenant .htaccess settings never reach cpsrvd traffic).
assert "cpanel.olscp-c.test" in maps["svc.olscpc.olscp-a.test"] and "olscp-c.test" in maps["olscpc.olscp-a.test"]
assert "cpanel." not in maps["olscpc.olscp-a.test"] and "cpanel." not in maps["olscp-a.test"]
assert "svc.blog.olscp-a.test" not in maps and "olscp-alias.test" in maps["olscp-a.test"]
assert "cpanel.olscp-alias.test" not in maps["svc.olscp-a.test"]  # parked: served by the catch-all proxy vhost
vh = iso.vhost_config(plan["olscpc.olscp-a.test"], "security.limit_extensions = .php\n", {}, unset_headers=["X-Frame-Options"])
assert "docRoot                  /home/olscpa/public_html/olscp-c.test/" in vh and "cpanel\\.olscp-c\\.test" not in vh
assert vh.count("Header unset X-Frame-Options") == 10  # 6 static aliases, 3 CGI aliases, /cpanelwebcall/
svc = iso.cpanel_surface.service_vhost(plan["olscpc.olscp-a.test"]["docroot"], ["olscp-c.test"], "/c")
assert "cpanel\\.olscp-c\\.test" in svc and "autoLoadHtaccess     0" in svc and lint.lint(svc, False) == []
assert "domlogs" not in vh and "{olscpc.olscp-a.test}" not in vh and lint.lint(vh, False) == []
print("cPanel vhost model (userdatadomains, userdata, pools, ancestors, refusals) checks passed.")

# IPv6 addresses from userdata (HR-D06), identical in the PHP discovery module and in canonical form.
import json as _json
import subprocess as _subprocess
IPV6_CASES = ["ip: 1.2.3.4\nipv6:\n  2001:DB8:0:0::10:\n    dedicated: 1\n    prefix_len: 64\nphpversion: x\n",
              "ipv6: ~\n", "ip: 1.2.3.4\n", "ipv6:\n  '2001:db8::1':\n    dedicated: 0\n  2001:db8::2:\n    prefix_len: 64\n"]
python_v6 = [cv.userdata_ipv6(t) for t in IPV6_CASES]
assert python_v6 == [["2001:db8::10"], [], [], ["2001:db8::1", "2001:db8::2"]], python_v6
for bad in ["ipv6:\n  not-an-ip:\n", "ipv6:\n  1.2.3.4:\n"]:
    try:
        cv.userdata_ipv6(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
php = _subprocess.run(["/usr/local/cpanel/3rdparty/php/84/bin/php", "-n", "-r",
                       'require $argv[1]; $v = new OlsCpanel\\Cpanel\\Discovery\\AccountVhosts();'
                       ' echo json_encode(array_map([$v, "userdataIpv6"], json_decode($argv[2], true)));',
                       str(ROOT / "src/Cpanel/Discovery/AccountVhosts.php"), _json.dumps(IPV6_CASES)],
                      capture_output=True, text=True, check=True)
assert _json.loads(php.stdout) == python_v6, php.stdout
print("Userdata IPv6 parsing matches between the lab tool and the PHP module.")

# One home policy (review RV-29, finding 11): /home<[A-Za-z0-9_-]*>/<user>, whole path components, identical in the lab
# reference (cpanel_vhosts.account_home), the product (Cpanel\Discovery\HomePath) and the discovery of both.
HOME_CASES = [("/home/olscpa", "olscpa"), ("/home/olscpa/public_html", "olscpa"), ("/home2/olscpa/public_html/x", "olscpa"),
              ("/home_ssd/olscpa/", "olscpa"), ("/home-b/olscpa/a", "olscpa"), ("/HOME/olscpa", "olscpa"), ("/homeX9/olscpa", "olscpa"),
              ("/home.old/olscpa", "olscpa"), ("/data/olscpa/public_html", "olscpa"), ("/usr/home/olscpa", "olscpa"),
              ("/newhome/olscpa", "olscpa"), ("/home/olscpab/public_html", "olscpa"), ("/home/olscp/public_html", "olscpa"),
              ("/home2/olscpa\n", "olscpa"), ("/home2\n/olscpa", "olscpa"), ("home/olscpa", "olscpa"), ("/home", "olscpa"),
              ("/home/", ""), ("/home2/olscpa", "")]
python_homes = [cv.account_home(p, u) for p, u in HOME_CASES]
assert python_homes[:5] == ["/home/olscpa", "/home/olscpa", "/home2/olscpa", "/home_ssd/olscpa", "/home-b/olscpa"], python_homes
assert python_homes[6] == "/homeX9/olscpa" and python_homes[5] is None and all(h is None for h in python_homes[7:]), python_homes
moved = dict(USERDATA, **{n: t.replace("/home/olscpa/", "/home2/olscpa/") for n, t in USERDATA.items()})
assert {v["docroot"] for v in cv.account_vhosts("olscpa", rows, moved)} >= {"/home2/olscpa/public_html"}
DOCROOT_CASES = []
for mount, accepted in (("/home2/olscpa", True), ("/home_ssd/olscpa", True), ("/data/olscpa", False), ("/home.old/olscpa", False),
                        ("/home2/olscpb", False)):
    data = dict(USERDATA, **{n: t.replace("/home/olscpa", mount) for n, t in USERDATA.items()})
    DOCROOT_CASES.append(data)
    try:
        cv.account_vhosts("olscpa", rows, data)
        assert accepted, mount
    except ValueError as exc:
        assert not accepted and "unsafe document root" in str(exc), (mount, exc)
php = _subprocess.run(["/usr/local/cpanel/3rdparty/php/84/bin/php", "-n", "-r",
                       'require $argv[1]; $v = new OlsCpanel\\Cpanel\\Discovery\\AccountVhosts(); $out = ["homes" => [], "docroots" => []];'
                       ' foreach (json_decode($argv[2], true) as [$p, $u]) { $out["homes"][] = OlsCpanel\\Cpanel\\Discovery\\HomePath::homeOf($p, $u); }'
                       ' $rows = $v->parseUserdataDomains($argv[3]);'
                       ' foreach (json_decode($argv[4], true) as $data) { try { $out["docroots"][] = array_column($v->accountVhosts("olscpa", $rows, $data), "docroot"); }'
                       ' catch (InvalidArgumentException $e) { $out["docroots"][] = $e->getMessage(); } }'
                       ' echo json_encode($out);',
                       str(ROOT / "src/bootstrap.php"), _json.dumps(HOME_CASES), ROWS, _json.dumps(DOCROOT_CASES)],
                      capture_output=True, text=True, check=True)
answer = _json.loads(php.stdout)
assert answer["homes"] == python_homes, (answer["homes"], python_homes)
python_docroots = []
for data in DOCROOT_CASES:
    try:
        python_docroots.append([v["docroot"] for v in cv.account_vhosts("olscpa", rows, data)])
    except ValueError as exc:
        python_docroots.append(str(exc))
assert [a if isinstance(a, list) else a.replace("'", "") for a in answer["docroots"]] == \
       [p if isinstance(p, list) else p.replace("'", "") for p in python_docroots], (answer["docroots"], python_docroots)
print("Home path policy (/home<suffix>/<user>) identical in the lab reference and the PHP discovery module.")
