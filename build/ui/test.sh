#!/bin/sh
# Interface tests in the pinned Node image, offline (packages only from the lockfile and the npm cache
# that build/ui/build.sh filled): unit and component tests, a production build checked for fixture code,
# and the refusals of the fixture flag. Nothing is installed on the host; the build output is discarded.
# Usage: build/ui/test.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=docker.io/library/node@sha256:1b01570a09b39510be11b6d8ac43258d60c68846f26dba191843da614adb226b
[ -d "$ROOT/artifacts/npm-cache" ] || { echo "no npm cache: run build/ui/build.sh once" >&2; exit 1; }
podman run --rm --network=none -v "$ROOT/ui:/work/ui:Z" -v "$ROOT/artifacts/npm-cache:/npm:Z" \
    -e npm_config_cache=/npm -w /work/ui "$IMAGE" sh -c '
set -eu
npm ci --no-audit --no-fund --offline --loglevel=error
node tests/run.mjs
OLS_UI_OUT=/tmp/prod npx vite build --logLevel warn
node tests/check_dist.mjs /tmp/prod
refuse() { if "$@" >/tmp/refused.log 2>&1; then echo "not refused: $*" >&2; exit 1; fi; }
refuse env OLS_UI_FIXTURES=1 OLS_UI_OUT=/tmp/a npx vite build
refuse env OLS_UI_OUT=/tmp/b npx vite build --mode fixtures
refuse env OLS_UI_FIXTURES=1 OLS_UI_OUT=/tmp/c npx vite build --mode fixtures
echo "Production build refuses the fixture flag in every combination."
OLS_UI_FIXTURES=1 npx vite build --mode fixtures --logLevel warn
if node tests/check_dist.mjs dist-fixtures >/dev/null 2>&1; then echo "fixture build not detected" >&2; exit 1; fi
echo "Fixture build works and is detected by the artifact check."
rm -rf dist-fixtures'
rm -rf "$ROOT/ui/node_modules" "$ROOT/ui/dist-fixtures"
