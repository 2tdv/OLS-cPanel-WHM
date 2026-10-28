#!/bin/sh
# Builds the WHM and cPanel interfaces in the pinned Node image (nothing installed on the host).
# Usage: build/ui/build.sh   -> artifacts/ui/ (hashed assets + .vite/manifest.json)
set -eu
# Release builds never run in fixture mode (ui/vite.config.js refuses it as well).
[ -z "${OLS_UI_FIXTURES:-}" ] || { echo "OLS_UI_FIXTURES is set: fixture mode is for development only" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=docker.io/library/node@sha256:1b01570a09b39510be11b6d8ac43258d60c68846f26dba191843da614adb226b
mkdir -p "$ROOT/artifacts/ui" "$ROOT/artifacts/npm-cache"
INSTALL="npm ci --no-audit --no-fund"
[ -f "$ROOT/ui/package-lock.json" ] || INSTALL="npm install --no-audit --no-fund"
podman run --rm -v "$ROOT/ui:/src:Z" -v "$ROOT/artifacts/ui:/out:Z" -v "$ROOT/artifacts/npm-cache:/npm:Z" \
    -e npm_config_cache=/npm -e OLS_UI_OUT=/out -w /src "$IMAGE" \
    sh -c "$INSTALL && npm run build && node tests/check_dist.mjs /out"
rm -rf "$ROOT/ui/node_modules"
( cd "$ROOT/artifacts/ui" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS )
