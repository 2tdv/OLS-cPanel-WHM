# "PHP off" .htaccess corpus (CMP-09)

Every idiom a site uses to stop PHP from running in a folder (typically an upload folder: Elementor forms, Drupal's
files directory, WPForms, plugin caches), and the idioms that turn PHP on there. `tests/compiler_equivalence.py`
translates each file as `wp-content/uploads/.htaccess` of `/home/u/public_html`, once with the lab Apache's module list
(`tests/Fixtures/cms-htaccess/apache-modules.txt`, plus `extra_modules`) and once without a list, and checks that the
Python reference and the PHP product agree byte for byte and that the verdict is the one recorded in `expected.json`.

The rule is fail closed: a folder whose behaviour cannot be reproduced exactly keeps its site on Apache (a blocker).
A translated idiom must refuse under OLS everything Apache refuses, path info included (`/x.php/y` runs `x.php`).

`expected.json`, per file:

| Key | Meaning |
| --- | --- |
| `outcome` | `translated` or `blocker`, with the module list |
| `without_modules` | the same without a module list (`httpd -M` failed); a translation must then be identical |
| `blocker` | text the blocker contains |
| `denied` | request paths below the folder that OLS must refuse (403) |
| `allowed` | request paths no translated context refuses (PHP runs there under Apache too, or a static file) |
| `static_scripts` | request paths whose scripts OLS maps to a static type (Drupal's idiom) |
| `extra_modules` | modules added to the lab list (mod_php loaded) |

`build/soak/php_off_probe.py` uses the same file on the lab: harmless scripts in such folders must never run under OLS.
