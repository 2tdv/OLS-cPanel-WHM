# WordPress plugin .htaccess corpus

Real-world `.htaccess` files written by popular WordPress plugins, used by `tests/compiler_equivalence.py` to check that
the Python reference translator and the PHP translator agree byte for byte and that each file ends the way
`expected.json` says (translated, or refused with a named reason).

Layout: `<plugin>/<directory relative to the site's document root>/.htaccess`, or `<plugin>/root-<variant>.htaccess` for
a file in the document root. `expected.json` holds the outcome and reason of every file.

## Provenance

None of these files was downloaded; each is **reconstructed** from the plugin's published behaviour and from files seen
on a live server, as small, well-known texts. Versions are those current when the corpus was written; exact whitespace
and marker comments can differ between releases. Files marked "live" were observed on the lab server and copied verbatim.

| Plugin | Version basis | Origin |
| --- | --- | --- |
| Akismet | 5.x | live (WordPress default plugin) |
| LiteSpeed Cache | 7.9.x | live (`wp-content/litespeed/.htaccess` LSCACHE_STATIC_PROTECT_V3, `debug/.htaccess`); browser cache block and cache rules reconstructed |
| Wordfence | 7.x | reconstructed (`wflogs/.htaccess`; the firewall section of the root file in its LiteSpeed form `root-waf`, mod_php form `root-waf-mod-php` and PHP-FPM form `root-waf-fpm`, whose prepend is in `.user.ini`) |
| W3 Total Cache | 2.x | reconstructed (browser cache, page cache core, page cache directory) |
| WP Super Cache | 1.x | reconstructed (root rules, `wp-content/cache/.htaccess`) |
| WP Fastest Cache | 1.x | reconstructed (root rules) |
| All In One WP Security | 5.x | reconstructed (firewall section, spambot rule) |
| Solid Security (iThemes Security) | 8.x | reconstructed (system tweaks) |
| WooCommerce | 8.x | reconstructed (`woocommerce_uploads`, `wc-logs`) |
| UpdraftPlus | 1.x | reconstructed (backup directory) |
| Elementor | 3.x | reconstructed (uploads, forms) |
| WPForms | 1.x | reconstructed (uploads) |
| Contact Form 7 | 5.x | reconstructed (`wpcf7_uploads`) |
| Really Simple SSL | 7.x | reconstructed (https redirect, HSTS variant) |
| Redirection | 5.x | reconstructed (Apache redirect module next to WordPress's block) |
| Yoast SEO | 2x | ships no `.htaccess`; nothing to test |

## Translation rules these files exercise

- `<IfModule mod_authz_core.c>`, `mod_expires.c` and `mod_headers.c` (always loaded on cPanel EasyApache 4): body kept;
  the negated form (`<IfModule !mod_authz_core.c>`) is dropped. Not applied inside `<IfModule LiteSpeed>`.
- A lone directory-level `Require all denied` plus `<Files>`/`<FilesMatch>` blocks holding only `Require all granted`
  becomes one regex context with a negative lookahead: everything below the directory is denied except the allowed
  basenames. Earlier path segments of an allowed name must not contain a dot, so `x.php/allowed.js` (script with path
  info) stays denied. Any other use of `Require all granted` is a blocker.
- `ExpiresActive`, `ExpiresDefault`, `ExpiresByType` (short `A<s>`/`M<s>` or `access|now|modification plus <n> <unit>`)
  become `enableExpires`, `expiresDefault`, `expiresByType` of the directory's context. Differences: OLS adds
  `Cache-Control: public, max-age=N` (Apache only `max-age=N`) and applies it to static files, not to dynamic responses.
- `Header always set|unset|append|merge` is translated like `Header set`: OLS has one header table (applied whenever the
  context matches), no separate table for error responses.
- A denied `<Files>`/`<FilesMatch>` name also gets a context for the same name followed by path info (CMP-09): OLS
  matches regex contexts against the whole URI, so `x.php/y` would otherwise run a script Apache refuses.
- Wordfence's firewall (CMP-08): `php_value auto_prepend_file '<path>/wordfence-waf.php'` inside `<IfModule LiteSpeed>`
  of the document root becomes the root context's `phpIniOverride` when the path is a plain absolute path inside the
  account's home; the compile checks the file as the account (a readable regular file it owns) and keeps the site on
  Apache otherwise. Fixtures marked `"modules": "lab"` are translated with the lab Apache's module list.
