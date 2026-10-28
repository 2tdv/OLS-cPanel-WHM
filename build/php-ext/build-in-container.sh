#!/bin/sh
# Runs inside the pinned builder image (build.py mounts /build and the EA4 repository definition). Downloads the
# pinned phpredis tarball and refuses it unless its SHA-256 matches the pin, installs the EA4 development package
# of every pinned PHP version and compiles the extension against each one. Nothing here runs on a server.
set -eu
umask 022
. /build/env.sh
export LC_ALL=C SOURCE_DATE_EPOCH
OUT=/build/out
mkdir -p "$OUT" /build/src /build/work

# EA4 vendor variable the repository definition uses ($os_name_prefix$releasever -> c9).
echo "$EA4_OS_NAME_PREFIX" > /etc/dnf/vars/os_name_prefix

# The EA4 package signing key: fetched over HTTPS and refused unless its fingerprint is the pinned one.
curl --proto '=https' --tlsv1.2 -fsSL -o /build/ea4.key "$EA4_KEY_URL"
found=$(gpg --show-keys --with-colons /build/ea4.key | awk -F: '$1 == "fpr" {print $10; exit}')
[ "$found" = "$EA4_KEY_FINGERPRINT" ] || { echo "EA4 key fingerprint mismatch: $found" >&2; exit 1; }
rpm --import /build/ea4.key

dnf -y -q install gcc make autoconf automake libtool binutils tar gzip >/dev/null
packages=""
for v in $PHP_VERSIONS; do packages="$packages $v-php-devel $v-php-cli"; done
dnf -y -q install $packages >/dev/null

# The source: checksum verified before anything is extracted.
curl --proto '=https' --tlsv1.2 -fsSL -o /build/src.tgz "$SOURCE_URL"
echo "$SOURCE_SHA256  /build/src.tgz" | sha256sum --check --strict -
tar -xzf /build/src.tgz -C /build/src
SRC="/build/src/$EXT-$EXT_VERSION"
[ -f "$SRC/config.m4" ] || { echo "unexpected source layout" >&2; exit 1; }
cp "$SRC/LICENSE" "$OUT/LICENSE"

: > "$OUT/versions.tsv"
for v in $PHP_VERSIONS; do
    P="/opt/cpanel/$v/root/usr/bin"
    W="/build/work/$v"
    cp -a "$SRC" "$W"
    cd "$W"
    "$P/phpize" > "$OUT/$v.phpize.log" 2>&1
    # Fixed optimisation, no debug info and a fixed path prefix keep the object code independent of the build host.
    CFLAGS="-O2 -g0 -ffile-prefix-map=/build=." ./configure --with-php-config="$P/php-config" $CONFIGURE_OPTIONS \
        > "$OUT/$v.configure.log" 2>&1
    make -j 2 > "$OUT/$v.make.log" 2>&1
    strip --strip-unneeded modules/redis.so
    # It must load into the very PHP it was built against.
    modules=$("$P/php" -n -d extension="$W/modules/redis.so" -m 2> "$OUT/$v.load.err") \
        || { cat "$OUT/$v.load.err" >&2; echo "$v: php -m failed" >&2; exit 1; }
    printf '%s\n' "$modules" | grep -qx redis || { cat "$OUT/$v.load.err" >&2; echo "$v: redis.so does not load" >&2; exit 1; }
    loaded=$("$P/php" -n -d extension="$W/modules/redis.so" --ri redis | sed -n 's/^Redis Version => //p')
    [ "$loaded" = "$EXT_VERSION" ] || { echo "$v: loaded version '$loaded'" >&2; exit 1; }
    api=$("$P/php" -n -i | sed -n "s/^PHP API => //p")
    build_id=$(grep -a -o "API$api,[A-Z,]*" modules/redis.so | sort -u)
    [ "$(printf '%s\n' "$build_id" | wc -l)" = 1 ] || { echo "$v: no single build id in redis.so" >&2; exit 1; }
    target=$("$P/php" -n -i | sed -n 's/^PHP Extension Build => //p')
    [ "$target" = "$build_id" ] || { echo "$v: build id $build_id differs from PHP's $target" >&2; exit 1; }
    mkdir -p "$OUT/$v"
    cp modules/redis.so "$OUT/$v/redis.so"
    printf '%s\t%s\t%s\t%s\t%s\n' "$v" "$("$P/php-config" --version)" "$api" "$build_id" \
        "$(rpm -q --qf '%{NEVRA}' "$v-php-devel")" >> "$OUT/versions.tsv"
    cd /build
done
rpm -qa --qf '%{NEVRA}\n' | sort > "$OUT/builder-packages.txt"
