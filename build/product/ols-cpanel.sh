#!/bin/sh
# Installed as /usr/local/ols-cpanel/bin/ols-cpanel. Runs the product CLI with cPanel's own PHP (plan 5.1):
# no system PHP, no php.ini (-n), fixed paths only. The CLI itself is the repository's bin/ols-cpanel,
# installed as /usr/local/ols-cpanel/libexec/ols-cpanel.php with the engine in /usr/local/ols-cpanel/lib.
PHP=/usr/local/cpanel/3rdparty/php/84/bin/php
CLI=/usr/local/ols-cpanel/libexec/ols-cpanel.php
if [ ! -x "$PHP" ]; then
    echo "ols-cpanel: cPanel's PHP 8.4 runtime ($PHP) is missing; this cPanel build is not supported." >&2
    exit 70
fi
exec "$PHP" -n "$CLI" "$@"
