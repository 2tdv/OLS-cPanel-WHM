#!/usr/bin/python3
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import htaccess_translate as ht

PPD = """
#----------------------------------------------------------------cp:ppd
# Section managed by cPanel: Password Protected Directories     -cp:ppd
# - Do not edit this section of the htaccess file!              -cp:ppd
#----------------------------------------------------------------cp:ppd
AuthType Basic
AuthName "Private"
AuthUserFile "/home/olscpa/.htpasswds/public_html/private/passwd"
Require valid-user
#----------------------------------------------------------------cp:ppd
# End section managed by cPanel: Password Protected Directories -cp:ppd
#----------------------------------------------------------------cp:ppd"""
ROOT_HT = """# BEGIN cPanel-generated php ini directives, do not edit
<IfModule php8_module>
   php_value memory_limit 321M
</IfModule>
# END cPanel-generated php ini directives, do not edit

# php -- BEGIN cPanel-generated handler, do not edit
<IfModule mime_module>
  AddHandler application/x-httpd-ea-php83 .php .php8 .phtml
</IfModule>
# php -- END cPanel-generated handler, do not edit

<Files ".env">
    Require all denied
</Files>
"""
realms, contexts, blockers = ht.translate({"": ROOT_HT, "private": PPD, "denied": "Require all denied\n"},
                                          "/home/olscpa/public_html")
assert blockers == [], blockers
assert len(realms) == 1 and "location              /home/olscpa/.htpasswds/public_html/private/passwd" in realms[0]
text = "".join(contexts)
assert "context /private/ {" in text and "required                valid-user" in text and "authName                Private" in text
assert "context /denied/ {\n  location                /home/olscpa/public_html/denied/\n  allowBrowse             0" in text
dotenv = [c for c in contexts if c.startswith("context exp:")][0]
regex = dotenv.split()[1][4:]
for path, denied in [("/.env", True), ("/sub/.env", True), ("/x.env", False), ("/.envrc", False)]:
    assert bool(re.match(regex, path)) == denied, (path, regex)
fm = ht.translate({"": '<FilesMatch "\\.(ini|log)$">\nRequire all denied\n</FilesMatch>\n'}, "/d")[1][0].split()[1][4:]
assert re.match(fm, "/a/b/error.log") and not re.match(fm, "/a.log/x")
glob = ht.translate({"logs": '<Files "*.log">\nRequire all denied\n</Files>\n'}, "/d")[1][0].split()[1][4:]
assert re.match(glob, "/logs/a.log") and re.match(glob, "/logs/x/b.log") and not re.match(glob, "/logs/a.logx")
assert not re.match(glob, "/other/a.log")
wp = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n"
r, blocks, b = ht.translate({"": wp}, "/d")
assert r == [] and b == [] and len(blocks) == 1
assert "rewrite  {\n    enable                1\n    base                  /\n    rules                 <<<END_rules\n" in blocks[0]
assert "RewriteRule . /index.php [L]\nEND_rules\n  }" in blocks[0]
# Apache semantics: a subdirectory with its own rules gets its own context; one without keeps none.
r, blocks, b = ht.translate({"": wp, "app": "RewriteEngine On\nRewriteRule ^go$ t.txt [L]\n", "keep": "Options -Indexes\n"}, "/d")
joined = "".join(blocks)
assert b == [] and "context /app/ {" in joined and "RewriteRule ^go$ t.txt [L]" in joined
assert "rewrite" not in joined.split("context /keep/ {")[1]
assert "enable                0" in "".join(ht.translate({"o": "RewriteEngine Off\nRewriteRule ^x$ y\n"}, "/d")[1])
for bad in ["RewriteEngine On\nRewriteRule ^(.*)$ http://127.0.0.1:2082/$1 [P]\n", "RewriteEngine On\nRewriteRule ^x$ /y [L,Proxy]\n",
            "RewriteEngine On\nRewriteRule ^x$ wss://h/ [L]\n", "RewriteEngine On\nRewriteRule ^x$ /y\nEND_rules\n",
            "RewriteRule ^x$ /y\n", "RewriteEngine On\nRewriteOptions MergeBase\n", "RewriteEngine On\nRewriteBase /a b/\n"]:
    r, blocks, b = ht.translate({"": bad}, "/d")
    # Any blocker keeps the domain on Apache (HR-D08); a heredoc terminator never reaches the output.
    assert b and all(t.splitlines().count("END_rules") <= 1 for t in blocks), bad
# mod_headers is always loaded on cPanel's Apache: its wrapper is unwrapped; a module that may be absent is still refused.
assert ht.translate({"": "<IfModule mod_headers.c>\nHeader set X 1\n</IfModule>\n"}, "/d")[2] == []
assert ht.translate({"": "<IfModule mod_unique_id.c>\nHeader set X 1\n</IfModule>\n"}, "/d")[2]
# Internal backends (review): tabs between arguments, blanks inside the flag list, any flag case,
# the cpsrvdNNNN proxy backends and every other dotless extProcessor name, handler flags, quoting,
# continuations, "|" arguments, control characters and unknown Rewrite* directives are all blockers.
INTERNAL_RULES = ["RewriteRule\t^ http://cpsrvd2082/ [P,L]", "RewriteRule ^ http://cpsrvd2082/ [P, L]",
                  "RewriteRule ^ /x [L,\tP]", "RewriteRule ^ /x [L p]", "RewriteRule ^(.*)$ /$1 [p]", "RewriteRule ^ /x [PROXY]",
                  "RewriteRule ^ http://cpsrvd2082/ [L]", "RewriteRule ^ HTTPS://CPSRVD2083:2083/x", "RewriteRule ^ http://cpsrvd2082",
                  "RewriteRule ^ http://lsphp/x [L]", "RewriteRule ^ http://u@cpsrvd2082/ [L]", "RewriteRule ^ http://2130706433/",
                  "RewriteRule ^ http://[::1]:2082/", "RewriteRule ^ http://0.0.0.0:2082/", "RewriteRule ^ unix:/run/x.sock|http://a.b/",
                  "RewriteRule ^ /x [H=cpsrvd2082]", "RewriteRule ^ /x [handler=proxy:http://cpsrvd2082/]", "RewriteRule ^ \"http://cpsrvd2082/\"",
                  "RewriteRule ^ /x [L] [P]", "RewriteRule ^ /x L,P", "RewriteRule ^ [P]", "RewriteRule ^", "RewriteRule ^a\\ b /x [L]",
                  "RewriteRule ^ /x \\", "RewriteRule ^ |/bin/x [L]", "RewriteCond |x y", "RewriteCond %{HTTP_HOST} x [NC] y",
                  "RewriteRule ^ /x\x01 [L]", "RewriteRule ^ /x [L]\x7f", "RewriteMap m prg:/bin/x", "RewriteLock /tmp/x",
                  "RewriteEngine\tYes", "RewriteCond\t%{HTTP_HOST} ^x [P]", "RewriteRule-x ^ /y"]
for rule in INTERNAL_RULES:
    r, blocks, b = ht.translate({"": "RewriteEngine On\n" + rule + "\n"}, "/d")
    assert b and rule not in "".join(blocks), rule
assert ht.translate({"": "RewriteEngine On\nRewriteRule ^ /x\x01 [L]\n"}, "/d")[2] == ["/: rewrite line with control characters"]
assert ht.translate({"": "RewriteEngine On\nRewriteRule\t^ /x [L,\tP]\n"}, "/d")[2] == [
    "/: unsupported RewriteRule 'RewriteRule\\t^ /x [L,\\tP]'"]
# Tabs and blanks inside a harmless flag list still translate, and the rule is kept verbatim.
for good in ["RewriteEngine\tOn\nRewriteCond\t%{REQUEST_FILENAME}\t!-f\nRewriteRule\t.\t/index.php\t[L, NC]\n",
             "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301, L]\n",
             "RewriteEngine On\nRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\nRewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n",
             "RewriteEngine On\nRewriteRule ^old$ https://www.example.com/new [R=302,L]\n"]:
    r, blocks, b = ht.translate({"": good}, "/d")
    assert b == [] and len(blocks) == 1 and good.splitlines()[-1] + "\nEND_rules" in blocks[0], (good, b)
# The WordPress fixture still translates completely.
import tenant_fixtures as tf
r, blocks, b = ht.translate({"": tf.WORDPRESS}, "/home/olscpb/public_html")
assert b == [] and "RewriteRule . /index.php [L]\nEND_rules" in blocks[0], b
for bad, expect in [({"": "Options +ExecCGI\n"}, "unsupported Options"),
                    ({"": "Redirect 301 /a /b\n"}, "unsupported directive"),
                    ({"x": "Order deny,allow\nDeny from all\nAllow from 1.2.3.4\n"}, "unsupported directive"),
                    ({"sub": "ErrorDocument 404 /x.html\n"}, "unsupported directive"),
                    ({"": "<Files x>\nAllow from all\n</Files>\n"}, "unsupported body"),
                    ({"": PPD.replace("Require valid-user", "Require user bob")}, "Directory Privacy"),
                    ({"a b": "Require all denied\n"}, "unsafe path"),
                    ({"z": PPD.replace("/home/olscpa/.htpasswds/", "/home/olscpb/.htpasswds/")}, "Directory Privacy"),
                    ({"z": PPD.replace("/home/olscpa/.htpasswds/public_html/private/passwd", "/etc/shadow")}, "Directory Privacy"),
                    ({"z": PPD.replace(".htpasswds/public_html", ".htpasswds/../x")}, "Directory Privacy")]:
    assert any(expect in b for b in ht.translate(bad, "/home/olscpa/public_html")[2]), (bad, expect)
for body in ["Deny from all", "Order deny,allow\nDeny from all", "Order Allow,Deny\nDeny from all"]:
    r, blocks, b = ht.translate({"legacy": body + "\n"}, "/d")
    assert b == [] and "allowBrowse             0" in blocks[0], body
    r, blocks, b = ht.translate({"uploads": f"<Files *.php>\n{body}\n</Files>\n"}, "/d")
    assert b == [] and blocks[0].startswith("context exp:^/uploads/"), body
r, blocks, b = ht.translate({"": 'ErrorDocument 404 /404.html\nHeader set X-Frame-Options "SAMEORIGIN"\nHeader always unset X-Powered-By\n',
                             "noindex": "Options -Indexes +FollowSymLinks\n"}, "/d")
assert b == [], b
joined = "".join(blocks)
assert "errorPage 404 {\n  url                     /404.html" in joined
assert 'Header set X-Frame-Options "SAMEORIGIN"' in joined and "Header unset X-Powered-By" in joined
assert "context /noindex/ {" in joined and "autoIndex               0" in joined
assert joined.count("context / {") == 1
print("htaccess access-control translation and blocker checks passed.")
