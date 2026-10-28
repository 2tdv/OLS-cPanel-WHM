#!/bin/sh
# Lab preview of the G0-H interfaces that stays installed until removed (the probes remove theirs).
# Usage (as the development user): build/vm-qualification/plugin_preview.sh install|uninstall
# Installs the prebuilt broker as ols-cpanel-broker.service, the WHM plugin (AppConfig, root only)
# and the cPanel plugin (install_plugin + Feature Manager feature). Read-only interfaces.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WHM_DIR=/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel
WHM_ICON=/usr/local/cpanel/whostmgr/docroot/addon_plugins/ols-cpanel.svg
CPANEL_DIR=/usr/local/cpanel/base/frontend/jupiter/ols_cpanel
BROKER_BIN=/usr/local/ols-cpanel/bin/ols-cpanel-broker
UNIT=/etc/systemd/system/ols-cpanel-broker.service
STAGE=$(mktemp -d /var/tmp/ols-cpanel-preview.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
chmod 0755 "$STAGE"
# cPanel's registration tools write files with the caller's umask (see plan RV-18).
umask 022
S="sudo -n"

archive() {
    tar -C "$ROOT/plugins/cpanel" -czf "$STAGE/plugin.tar.gz" install.json ols_cpanel.svg ols_cpanel_group.svg
}

case "${1:-}" in
install)
    for f in "$ROOT/artifacts/broker/ols-cpanel-broker" "$ROOT/artifacts/ui/.vite/manifest.json"; do
        [ -f "$f" ] || { echo "missing $f: run build/broker/build.sh and build/ui/build.sh" >&2; exit 1; }
    done
    for app in whm cpanel; do
        mkdir -p "$STAGE/$app/lib"
        cp "$ROOT/src/Broker/BrokerClient.php" "$ROOT/src/Ui/AssetManifest.php" "$STAGE/$app/lib/"
        cp -r "$ROOT/artifacts/ui/assets" "$STAGE/$app/assets"
        cp "$ROOT/artifacts/ui/.vite/manifest.json" "$STAGE/$app/manifest.json"
    done
    cp "$ROOT/plugins/whm/index.cgi" "$STAGE/whm/"
    cp "$ROOT/ui/src/shared/i18n.htaccess.en.json" "$STAGE/cpanel/lib/"
    cp "$ROOT/plugins/cpanel/index.live.php" "$STAGE/cpanel/"
    cp "$ROOT/src/Ols/Compiler/HtaccessTranslator.php" "$STAGE/cpanel/lib/"
    cp "$ROOT/src/Ols/Compiler/HtaccessRewrite.php" "$STAGE/cpanel/lib/"
    chmod -R a+rX "$STAGE"
    chmod 0755 "$STAGE/whm/index.cgi"
    archive
    cat > "$STAGE/unit" <<'EOF'
[Unit]
Description=OLS-cPanel privileged broker (lab preview)

[Service]
ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel-broker /run/ols-cpanel-broker
RuntimeDirectory=ols-cpanel-broker
RuntimeDirectoryMode=0755
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    $S install -d -m 0755 /usr/local/ols-cpanel/bin /var/lib/ols-cpanel
    $S install -m 0755 "$ROOT/artifacts/broker/ols-cpanel-broker" "$BROKER_BIN"
    $S install -m 0644 "$STAGE/unit" "$UNIT"
    $S systemctl daemon-reload
    $S systemctl enable --now ols-cpanel-broker.service
    $S rm -rf "$WHM_DIR" "$CPANEL_DIR"
    $S cp -r "$STAGE/whm" "$WHM_DIR"
    $S cp -r "$STAGE/cpanel" "$CPANEL_DIR"
    $S chown -R root:root "$WHM_DIR" "$CPANEL_DIR"
    $S install -m 0644 "$ROOT/plugins/whm/ols-cpanel.svg" "$WHM_ICON"
    $S sh -c 'umask 022 && exec "$@"' sh /usr/local/cpanel/bin/register_appconfig "$ROOT/plugins/whm/ols-cpanel.conf"
    $S sh -c 'umask 022 && exec "$@"' sh /usr/local/cpanel/scripts/install_plugin "$STAGE/plugin.tar.gz" --theme jupiter
    echo "installed"
    ;;
uninstall)
    archive
    $S sh -c 'umask 022 && exec "$@"' sh /usr/local/cpanel/scripts/uninstall_plugin "$STAGE/plugin.tar.gz" --theme jupiter || true
    $S sh -c 'umask 022 && exec "$@"' sh /usr/local/cpanel/bin/unregister_appconfig ols-cpanel || true
    $S rm -rf "$WHM_DIR" "$CPANEL_DIR" "$WHM_ICON"
    $S systemctl disable --now ols-cpanel-broker.service || true
    $S rm -f "$UNIT"
    $S systemctl daemon-reload
    $S rm -rf /usr/local/ols-cpanel /var/lib/ols-cpanel
    echo "removed"
    ;;
*)
    echo "usage: $0 install|uninstall" >&2
    exit 2
    ;;
esac
