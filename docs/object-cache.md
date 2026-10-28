# Object cache for site owners

Every cPanel account can have its own private object cache (Valkey, compatible with Redis). It runs on a
Unix socket inside the account's home directory, so only that account's sites can reach it. No password is needed.

## Connection values

| Setting | Value |
|---|---|
| Type | Redis |
| Host | `/home/<cPanel user>/.ols-objcache/valkey.sock` (the account's home directory; an absolute path) |
| Port | `0` (a Unix socket has no port) |
| Password / username | empty |
| Database | `0` (any of `0` to `15` works) |

Example for the account `exampleuser`: Host `/home/exampleuser/.ols-objcache/valkey.sock`, Port `0`.
If the account's home directory is not under `/home` (for example `/home2`), use that directory instead.

## WordPress with LiteSpeed Cache: automatic

When the object cache is turned on for an account (by your hosting provider), the product finds the account's
WordPress installations by itself (in the folders of your domains, in the main folder and one folder below it,
for example `/wp`) and sets the LiteSpeed Cache plugin's object cache for them: method Redis, the Host and
Port above, object cache on. Nothing has to be typed in. The values shown in
LiteSpeed Cache > Cache > Object are the ones the product set; leave them as they are. The product looks again
every few minutes, so a WordPress site you add later is set up too, and a site whose LiteSpeed Cache plugin you
activate later as well.

- If you chose a different object cache host in LiteSpeed Cache yourself, the product does not change it. The
  cPanel page "Object cache" lists the site as "Configured by the site owner".
- If the object cache is switched off for your account, or the account is suspended, the product switches the
  LiteSpeed Cache object cache off again, but only on sites where it had switched it on, so WordPress does not
  keep trying a connection that is gone. It is set up again when the cache returns.
- The cPanel page "Object cache" shows the connection values (with a copy button) and, for each WordPress
  site, whether it is configured automatically, configured by the site owner, has no active LiteSpeed Cache
  plugin, or could not be set up yet (it is then tried again automatically).

## Other applications: enter the values once

The product does not change the settings of other applications. For them, enter the values above once, in the
application's own cache settings:

- **Joomla:** System > Global Configuration > System > Cache: Cache Handler "Redis", Redis Server Host the
  socket path, Port `0`. (The LiteSpeed Cache extension for Joomla handles page cache only.)
- **Drupal:** the `redis` module; in `settings.php` set the host to the socket path and the port to `0`.
- **Magento 2:** `app/etc/env.php`, cache and session backends `redis` with `server` the socket path and
  `port` `0`.
- **WordPress without LiteSpeed Cache** (for example the Redis Object Cache plugin): in `wp-config.php`
  `define('WP_REDIS_SCHEME', 'unix');` and `define('WP_REDIS_PATH', '/home/<cPanel user>/.ols-objcache/valkey.sock');`.
- **Any other LiteSpeed Cache plugin or application with Redis support:** the same Host (socket path) and Port `0`.

The PHP `redis` extension these need is installed and kept active by the product on every EA4 PHP version.

## Good to know

- The cache is limited in memory; the oldest entries are removed first when it is full. Nothing is lost that the
  site cannot rebuild.
- When the account is suspended the cache stops; it starts again when the account is unsuspended.
- When the account is removed the cache and its files are removed with it.
