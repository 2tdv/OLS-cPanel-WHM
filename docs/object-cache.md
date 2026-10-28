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

Every account with WordPress and LiteSpeed Cache gets its own private object cache automatically. Nobody has to
turn it on: the product looks through the accounts every few minutes (a few accounts at a time, so the server
is not loaded), and an account that has a WordPress installation with the LiteSpeed Cache plugin (in the folders of
your domains, in the main folder and one folder below it, for example `/wp`) gets its own cache. The product
then sets the LiteSpeed Cache plugin's object cache of those sites: method Redis, the Host and Port above, object
cache on. Nothing has to be typed in. If you already switched the object cache on in LiteSpeed Cache with its
defaults (Redis, host `localhost`, port `6379`, which shows "Connection Test: Failed" because there is no shared
Redis on the server), the product replaces those defaults with your own socket and the connection test passes.
The values shown in LiteSpeed Cache > Cache > Object are the ones the product set; leave them as they are. The
product looks again every few minutes, so a WordPress site you add later is set up too, and a site whose
LiteSpeed Cache plugin you activate later as well. If you remove your last WordPress with LiteSpeed Cache, the
cache that was started for it is removed again.

Your hosting provider can decide otherwise: turn the object cache off for your account, or for your hosting
package, or turn the automatic object cache off for the whole server. The cPanel page "Object cache" then says
that your hosting provider turned it off. The provider can also turn it on for your account without WordPress.

- If you chose a different object cache host in LiteSpeed Cache yourself (another server name, or another port),
  the product does not change it. The cPanel page "Object cache" lists the site as "Configured by the site owner".
- If the object cache is switched off for your account, or the account is suspended, the product switches the
  LiteSpeed Cache object cache off again, but only on sites where it had switched it on, so WordPress does not
  keep trying a connection that is gone. It is set up again when the cache returns.
- The cPanel page "Object cache" says when your cache is ready and configured for your WordPress sites, shows the
  connection values (with a copy button) and, for each WordPress
  site, whether it is configured automatically, configured by the site owner, has no active LiteSpeed Cache
  plugin, or could not be set up yet (it is then tried again automatically).

## Setting it by hand in LiteSpeed Cache (WordPress)

Only needed if you want to set it yourself; normally the product does it. First make sure the object cache is on
for your account: cPanel → Website performance → **Object cache** must say it is running (if it says it is off,
ask your hosting provider). Then, in WordPress: **LiteSpeed Cache → Cache → [6] Object**:

| Field in LiteSpeed Cache | Enter |
|---|---|
| Object Cache | **ON** |
| Method | **Redis** |
| Host | **`/home/<your cPanel user>/.ols-objcache/valkey.sock`** — the full path, not `localhost` |
| Port | **`0`** — not `6379` |
| Default Object Lifetime | leave as it is (360) |
| Username / Password | **empty** |
| Redis Database ID | **`0`** |
| Global Groups, Do Not Cache Groups | leave as they are |
| Persistent Connection | **ON** |
| Cache Wp-Admin | ON or OFF, as you like |

Press **Save Changes**. The Status box then shows *Redis Extension: Enabled* and *Connection Test: Passed*.

Why not `localhost` and `6379`: each account has its own private cache that only that account can reach, through
the socket file in its home directory. There is no shared cache on `localhost:6379` (it would let every account see
every other account's data), so the plugin's default values find nothing. The cPanel page "Object cache" shows
your exact Host value with a copy button.

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
