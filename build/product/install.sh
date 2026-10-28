#!/bin/sh
# OLS-cPanel one-command installer bootstrap (plan 18.2, 18.2.1 INST-01/02/03, 18.6).
#
# Trust boundary: this script trusts only the release public key embedded below and the release version
# pinned below. It is itself published with an independently distributed SHA-256 (release notes), and the
# documented command verifies that digest before running it; this script cannot authenticate its own
# execution after the fact. Everything it downloads is verified before use: the release manifest by its
# detached OpenPGP signature against the embedded key (isolated keyring), every artifact by the SHA-256
# listed in that signed manifest. Nothing on the server is changed before all verification has passed.
# Nothing downloaded is ever executed by a shell; the RPMs carry no install scripts.
#
# After the verified packages are installed, the guided workflow continues inside the product CLI:
# `ols-cpanel install --prepare` (preflight, backup, first generation; Apache keeps serving), then the
# cutover, which the CLI only performs after showing the plan and receiving the administrator's approval.
set -eu

# --- Release identity: filled in by the release owner when a signed release is published. -----------------
RELEASE_VERSION="RELEASE_VERSION"
RELEASE_BASE_URL="RELEASE_BASE_URL"
# Primary key fingerprint of the release signing key (40 hex characters, no spaces).
RELEASE_KEY_FINGERPRINT="RELEASE_KEY_FINGERPRINT"
# ------------------------------------------------------------------------------------------------------------

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077
CLI=/usr/local/ols-cpanel/bin/ols-cpanel
MANIFEST_FORMAT="ols-cpanel-release-manifest 1"
MAX_DOWNLOAD=1073741824
WORK=""

release_key() {
# BEGIN OLS-CPANEL RELEASE KEY
# The ASCII-armored OpenPGP public key of the release signing key, inserted at release time between the
# RELEASE_KEY_EOF lines. It must match RELEASE_KEY_FINGERPRINT above. Until then this is a placeholder and
# the installer refuses to run.
cat <<'RELEASE_KEY_EOF'
RELEASE KEY PLACEHOLDER: replace this line with the ASCII-armored release public key.
RELEASE_KEY_EOF
# END OLS-CPANEL RELEASE KEY
}

usage() {
    cat <<EOF
Usage: install.sh [--prepare-only] [--help]

Installs OLS-cPanel ${RELEASE_VERSION} on this cPanel/WHM server:
  1. checks root, the operating system (AlmaLinux 9, x86_64) and cPanel;
  2. downloads the signed release manifest and the packages over HTTPS into a private temporary directory;
  3. verifies the manifest signature with the release key embedded in this script and every package's
     SHA-256 from that manifest; nothing is changed on the server if any check fails;
  4. installs the verified packages with dnf (they only place files; no service is started);
  5. runs '${CLI} install --prepare' (preflight, backup, first configuration; Apache keeps serving);
  6. on an interactive terminal, continues to the cutover, which the CLI performs only after showing the
     plan and receiving your explicit approval. Declining leaves Apache serving.

Options:
  --prepare-only  stop after step 5 and print the command for the cutover
  --help          show this help

Exit status: 0 success, 64 usage error, 65 verification failure, 69 unsupported platform or
             unprepared installer, 70 other failure, 77 not run as root.
EOF
}

log() { printf 'ols-cpanel installer: %s\n' "$*" >&2; }
die() { code=$1; shift; log "ERROR: $*"; exit "$code"; }
# Stage headings: blue on a terminal, plain in a log, so the owner sees what is happening and why it takes time.
step() {
    if [ -t 2 ]; then printf '\n\033[1;34m==> %s\033[0m\n' "$*" >&2; else printf '\n==> %s\n' "$*" >&2; fi
}
done_ok() {
    if [ -t 2 ]; then printf '\033[1;32m    ✓ %s\033[0m\n' "$*" >&2; else printf '    ✓ %s\n' "$*" >&2; fi
}

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    case "$WORK" in
        /var/tmp/ols-cpanel-install.*)
            if [ -d "$WORK/gnupg" ] && [ -x /usr/bin/gpgconf ]; then
                GNUPGHOME="$WORK/gnupg" /usr/bin/gpgconf --kill all >/dev/null 2>&1 || :
            fi
            rm -rf -- "$WORK"
            ;;
    esac
    exit "$status"
}

# --- Arguments -----------------------------------------------------------------------------------------------
PREPARE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --prepare-only) PREPARE_ONLY=1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; die 64 "unknown argument: $arg" ;;
    esac
done

# --- Root and installer readiness ------------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || die 77 "run as root (for example: sudo sh install.sh)"
case "$RELEASE_VERSION$RELEASE_BASE_URL$RELEASE_KEY_FINGERPRINT" in
    *RELEASE_VERSION*|*RELEASE_BASE_URL*|*RELEASE_KEY_FINGERPRINT*)
        die 69 "this installer has not been prepared for a release (placeholders are not filled in)" ;;
esac
case "$RELEASE_BASE_URL" in
    https://*) ;;
    *) die 69 "the release base URL must use HTTPS" ;;
esac
printf '%s\n' "$RELEASE_VERSION" | grep -Eqx '[0-9]+(\.[0-9]+)*' || die 69 "malformed release version"
printf '%s\n' "$RELEASE_KEY_FINGERPRINT" | grep -Eqx '[0-9A-F]{40}' || die 69 "malformed release key fingerprint"
release_key | grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----$' \
    || die 69 "this installer has no release key (placeholder block not filled in)"

# --- Platform detection (read-only) ----------------------------------------------------------------------------
step "Checking this server (operating system, cPanel, required tools)"
# /etc/os-release is parsed, never sourced (plan 18.6: no editable state as shell code).
os_field() {
    sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d '"'"'"
}
[ -r /etc/os-release ] || die 69 "cannot read /etc/os-release"
OS_ID=$(os_field ID)
OS_MAJOR=$(os_field VERSION_ID | cut -d. -f1)
case "$OS_ID" in
    # This release is built and tested on AlmaLinux 9 only; Rocky Linux, CloudLinux and release 8 follow later.
    almalinux) ;;
    *) die 69 "unsupported operating system '$OS_ID' (this release supports AlmaLinux 9 only)" ;;
esac
case "$OS_MAJOR" in
    # This release is built and tested for release 9 only; release 8 follows in a later release.
    9) ;;
    *) die 69 "unsupported $OS_ID release '$OS_MAJOR' (this release supports 9 only)" ;;
esac
[ "$(uname -m)" = x86_64 ] || die 69 "unsupported architecture $(uname -m) (supported: x86_64)"
[ -x /usr/local/cpanel/cpanel ] || die 69 "cPanel/WHM is not installed (this product does not install cPanel)"
CPANEL_VERSION=$(/usr/local/cpanel/cpanel -V 2>/dev/null) || die 69 "cPanel did not report its version"
[ -n "$CPANEL_VERSION" ] || die 69 "cPanel did not report its version"
[ -x /usr/local/cpanel/3rdparty/php/84/bin/php ] || die 69 "cPanel's PHP 8.4 runtime is missing"
for tool in /usr/bin/curl /usr/bin/gpg /usr/bin/sha256sum /usr/bin/mktemp /usr/bin/dnf; do
    [ -x "$tool" ] || die 69 "required tool $tool is missing"
done
log "platform: $OS_ID $OS_MAJOR x86_64, cPanel $CPANEL_VERSION; release $RELEASE_VERSION"

# --- Private working directory, removed on every exit ----------------------------------------------------------
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
WORK=$(/usr/bin/mktemp -d /var/tmp/ols-cpanel-install.XXXXXXXXXX) || die 70 "cannot create a private directory"
chmod 0700 "$WORK"
mkdir -m 0700 "$WORK/gnupg" "$WORK/download"

fetch() {
    # HTTPS only (also for redirects), TLS 1.2 or newer, bounded size; the body goes to a private file.
    /usr/bin/curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --connect-timeout 20 --max-filesize "$MAX_DOWNLOAD" --output "$2" "$1" \
        || die 70 "download failed: $1"
}

# --- Download the version-pinned manifest and its detached signature -------------------------------------------
# One manifest per supported platform row: packages built for EL9 must never be installed on EL8.
PLATFORM="el$OS_MAJOR.x86_64"
RELEASE_URL="$RELEASE_BASE_URL/$RELEASE_VERSION"
MANIFEST_NAME="ols-cpanel-$RELEASE_VERSION.$PLATFORM.manifest"
MANIFEST="$WORK/download/$MANIFEST_NAME"
step "Downloading release $RELEASE_VERSION and checking its signature"
fetch "$RELEASE_URL/$MANIFEST_NAME" "$MANIFEST"
fetch "$RELEASE_URL/$MANIFEST_NAME.asc" "$MANIFEST.asc"

# --- Verify the manifest signature against the embedded key only -----------------------------------------------
GNUPGHOME="$WORK/gnupg"
export GNUPGHOME
release_key | /usr/bin/gpg --batch --no-tty --quiet --import >/dev/null 2>&1 \
    || die 65 "the embedded release key could not be imported"
IMPORTED=$(/usr/bin/gpg --batch --no-tty --with-colons --fingerprint 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
[ "$IMPORTED" = "$RELEASE_KEY_FINGERPRINT" ] || die 65 "the embedded release key does not match its fingerprint"
/usr/bin/gpg --batch --no-tty --status-file "$WORK/gpg-status" --verify "$MANIFEST.asc" "$MANIFEST" 2>/dev/null \
    || die 65 "the release manifest signature is not valid; nothing was changed"
# A good signature from the pinned primary key, not merely any key in the keyring.
awk -v fpr="$RELEASE_KEY_FINGERPRINT" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $NF == fpr {ok = 1} END {exit !ok}' \
    "$WORK/gpg-status" || die 65 "the release manifest is not signed by the release key; nothing was changed"
log "release manifest signature verified (key $RELEASE_KEY_FINGERPRINT)"

# --- Parse the signed manifest -----------------------------------------------------------------------------------
# Format (one item per line, nothing else allowed):
#   ols-cpanel-release-manifest 1
#   version <RELEASE_VERSION>
#   platform <el8|el9>.x86_64
#   artifact <sha256> <package file name>      (one line per package)
# The version and platform lines bind the signature to this release and this platform row, so a validly
# signed manifest of another release or row cannot be substituted.
[ "$(head -n 1 "$MANIFEST")" = "$MANIFEST_FORMAT" ] || die 65 "unknown release manifest format"
[ "$(grep -c '^version ' "$MANIFEST")" = 1 ] && grep -qx "version $RELEASE_VERSION" "$MANIFEST" \
    || die 65 "the signed manifest is not for release $RELEASE_VERSION"
[ "$(grep -c '^platform ' "$MANIFEST")" = 1 ] && grep -qx "platform $PLATFORM" "$MANIFEST" \
    || die 65 "the signed manifest is not for platform $PLATFORM"
if grep -Evx "$MANIFEST_FORMAT|version [0-9.]+|platform el[89]\.x86_64|artifact [0-9a-f]{64} [A-Za-z0-9][A-Za-z0-9._+-]*\.el$OS_MAJOR\.x86_64\.rpm" \
    "$MANIFEST" | grep -q .; then
    die 65 "the signed manifest contains unexpected lines"
fi
grep '^artifact ' "$MANIFEST" > "$WORK/artifact-lines" || die 65 "the signed manifest lists no packages"
awk '{print $3}' "$WORK/artifact-lines" > "$WORK/artifacts"
grep -Eqx "ols-cpanel-openlitespeed-[0-9][A-Za-z0-9._+-]*\.x86_64\.rpm" "$WORK/artifacts" \
    || die 65 "the signed manifest lists no ols-cpanel-openlitespeed package"
grep -Eqx "ols-cpanel-php-redis-[0-9][A-Za-z0-9._+-]*\.x86_64\.rpm" "$WORK/artifacts" \
    || die 65 "the signed manifest lists no ols-cpanel-php-redis package"
PRODUCT_RPM=$(grep -E "^ols-cpanel-$(printf '%s' "$RELEASE_VERSION" | sed 's/\./\\./g')-[A-Za-z0-9._+-]+\.x86_64\.rpm$" "$WORK/artifacts" || :)
[ -n "$PRODUCT_RPM" ] && [ "$(printf '%s\n' "$PRODUCT_RPM" | wc -l)" = 1 ] \
    || die 65 "the signed manifest must list exactly one ols-cpanel $RELEASE_VERSION package"
[ "$(sort -u "$WORK/artifacts" | wc -l)" = "$(wc -l < "$WORK/artifacts")" ] || die 65 "duplicate manifest entries"

# --- Download every artifact and verify its SHA-256 from the signed manifest --------------------------------------
step "Downloading the packages (OpenLiteSpeed, PHP redis extension, OLS-cPanel) and verifying each one"
mkdir -m 0700 "$WORK/verified"
while read -r _ digest name; do
    fetch "$RELEASE_URL/$name" "$WORK/download/$name"
    printf '%s  %s\n' "$digest" "$WORK/download/$name" | /usr/bin/sha256sum --check --quiet --strict - >/dev/null 2>&1 \
        || die 65 "$name does not match the signed manifest; nothing was changed"
    mv -- "$WORK/download/$name" "$WORK/verified/$name"
done < "$WORK/artifact-lines"
[ "$(ls "$WORK/verified" | wc -l)" = "$(wc -l < "$WORK/artifacts")" ] || die 65 "not every artifact was verified"
log "all $(wc -l < "$WORK/artifacts") packages verified against the signed manifest"

# --- From here on the server is changed; everything above was verification only. ---------------------------------
# The same build is installed again idempotently, which also completes an interrupted run (INST-05). An older
# installed build is upgraded to the verified one (the product then applies its own upgrade by itself after the
# package transaction); a newer installed build is never downgraded.
UPGRADE=0
EVR_FORMAT='%{EPOCHNUM}:%{VERSION}-%{RELEASE}'
for package in "$WORK"/verified/*.rpm; do
    name=$(/usr/bin/rpm -qp --queryformat '%{NAME}' "$package" 2>/dev/null) || die 65 "cannot read $package"
    wanted=$(/usr/bin/rpm -qp --queryformat '%{NEVRA}' "$package" 2>/dev/null) || die 65 "cannot read $package"
    if /usr/bin/rpm -q --quiet "$name"; then
        present=$(/usr/bin/rpm -q --queryformat '%{NEVRA}\n' "$name")
        [ "$present" = "$wanted" ] && continue
        present_evr=$(/usr/bin/rpm -q --queryformat "$EVR_FORMAT" "$name")
        wanted_evr=$(/usr/bin/rpm -qp --queryformat "$EVR_FORMAT" "$package" 2>/dev/null) || die 65 "cannot read $package"
        # Both come from rpm itself; checked before they reach rpm's version comparison.
        for evr in "$present_evr" "$wanted_evr"; do
            printf '%s\n' "$evr" | grep -Eqx '[0-9]+:[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+' || die 65 "unexpected package version $evr"
        done
        order=$(/usr/bin/rpm --eval "%{lua: print(rpm.vercmp('$present_evr', '$wanted_evr'))}")
        [ "$order" = "-1" ] || die 70 "$present is installed, which is not older than $wanted; nothing was changed"
        UPGRADE=1
    fi
done
step "Installing the packages: OpenLiteSpeed, the PHP redis extension, the Valkey object cache engine, OLS-cPanel"
log "installing the verified packages (files only; no service is started)"
/usr/bin/dnf --assumeyes --setopt=install_weak_deps=False install "$WORK"/verified/*.rpm \
    || die 70 "package installation failed; Apache is unaffected. Re-run the same command to retry"
[ -x "$CLI" ] || die 70 "$CLI is missing after installation"
done_ok "packages installed (nothing is started yet; Apache keeps serving)"

if [ "$UPGRADE" = 1 ]; then
    cat <<EOF

Upgraded to OLS-cPanel ${RELEASE_VERSION}. The product applies the upgrade by itself within a minute (services,
plugins, configuration); your sites keep being served. Nothing else is needed.
EOF
    exit 0
fi

step "Preparing the server: checks, backup, OpenLiteSpeed configuration, PHP (lsphp, OPcache, redis), WHM and cPanel plugins"
log "running: $CLI install --prepare (Apache keeps serving your sites meanwhile)"
PREPARED=$("$CLI" install --prepare --format=json) || {
    printf '%s\n' "$PREPARED"
    die 70 "preparation did not complete; Apache keeps serving. See the output above"
}
# The full report stays available for support; the screen gets a short summary.
printf '%s\n' "$PREPARED" > /root/ols-cpanel-prepare.json 2>/dev/null && chmod 0600 /root/ols-cpanel-prepare.json 2>/dev/null || :
# The plan id the cutover approves (grammar of Deployment\CutoverPlan).
PLAN=$(printf '%s\n' "$PREPARED" | sed -n 's/^ *"plan": "\(p[0-9]\{14\}-[0-9a-f]\{6\}\)",\{0,1\}$/\1/p' | head -n 1)
[ -n "$PLAN" ] || die 70 "the preparation did not report a plan id; Apache keeps serving"
SITES=$(printf '%s\n' "$PREPARED" | sed -n 's/^    "vhost_count": \([0-9]*\),\{0,1\}$/\1/p' | head -n 1)
done_ok "server prepared: ${SITES:-?} sites ready for OpenLiteSpeed (full report: /root/ols-cpanel-prepare.json)"

if [ "$PREPARE_ONLY" = 1 ] || [ ! -t 0 ] || [ ! -t 1 ]; then
    cat <<EOF

Preparation finished. Apache is still serving your sites; nothing has been switched.
Next step, when you are ready (the CLI shows the plan and asks for your approval before changing anything):
    $CLI install --cutover --plan=$PLAN
To discard the preparation and keep Apache only:
    $CLI uninstall --dry-run   (review), then $CLI uninstall
EOF
    exit 0
fi
step "Switching your sites from Apache to OpenLiteSpeed (you approve the plan first)"
"$CLI" install --cutover --plan="$PLAN" || die 70 "cutover not completed; see the output above for the serving state"
done_ok "OpenLiteSpeed is serving your sites. Manage it in WHM: Plugins -> OLS-cPanel."
