#!/bin/sh
# Browser and accessibility check of both interfaces: a fixture build (offline, pinned Node image) is loaded by
# a headless Chromium in the pinned Playwright image, with axe-core (WCAG 2.1 A/AA) on every route and fixture
# scenario, plus console, reflow (320/1280 px), keyboard and dialog checks (ui/tests/browser/check.mjs).
# Needs the network once per run (pulls the Playwright image, installs two pinned npm packages); it is NOT part of
# build/check/run.py. Output only in the scratch dirs below; nothing is installed on the host.
# Usage: build/ui/browser-check.sh [--quick]    (exit 1 on any violation)
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NODE=docker.io/library/node@sha256:1b01570a09b39510be11b6d8ac43258d60c68846f26dba191843da614adb226b
PLAYWRIGHT=mcr.microsoft.com/playwright:v1.49.1-jammy
[ -d "$ROOT/artifacts/npm-cache" ] || { echo "no npm cache: run build/ui/build.sh once" >&2; exit 1; }
mkdir -p "$ROOT/artifacts/browser-npm-cache"
podman run --rm --network=none -v "$ROOT/ui:/work/ui:Z" -v "$ROOT/artifacts/npm-cache:/npm:Z" \
    -e npm_config_cache=/npm -w /work/ui "$NODE" sh -c '
set -eu
npm ci --no-audit --no-fund --offline --loglevel=error
OLS_UI_FIXTURES=1 npx vite build --mode fixtures --logLevel warn'
rm -rf "$ROOT/ui/node_modules"
status=0
podman run --rm --ipc=host -v "$ROOT/ui:/work/ui:Z" -v "$ROOT/artifacts/browser-npm-cache:/npm:Z" \
    -e npm_config_cache=/npm -w /work/ui/tests/browser "$PLAYWRIGHT" sh -c '
set -eu
npm ci --no-audit --no-fund --loglevel=error
node check.mjs /work/ui/dist-fixtures '"$*" || status=$?
rm -rf "$ROOT/ui/tests/browser/node_modules" "$ROOT/ui/dist-fixtures"
exit $status
