#!/bin/sh
# Builds the broker and the generation activator as static (musl) binaries in the pinned Rust image;
# nothing is installed on the host.
# Usage: build/broker/build.sh   -> artifacts/broker/ols-cpanel-broker and ols-cpanel-activator (+ .sha256)
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=docker.io/library/rust@sha256:abf205baef81d968704753c839f7ea895b2317977e3e7528d207d52927f6ad90
OUT="$ROOT/artifacts/broker"
mkdir -p "$OUT" "$ROOT/artifacts/cargo-home"
LOCKED=--locked
[ -f "$ROOT/broker/Cargo.lock" ] || LOCKED=
podman run --rm --network=slirp4netns -v "$ROOT/broker:/src:Z" -v "$ROOT/artifacts/cargo-home:/cargo:Z" \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/cargo/target -w /src "$IMAGE" \
    sh -c "rustup target add x86_64-unknown-linux-musl >/dev/null && cargo build --release -j 2 $LOCKED --target x86_64-unknown-linux-musl"
for BIN in ols-cpanel-broker ols-cpanel-activator; do
    cp "$ROOT/artifacts/cargo-home/target/x86_64-unknown-linux-musl/release/$BIN" "$OUT/$BIN"
    ( cd "$OUT" && sha256sum "$BIN" > "$BIN.sha256" )
    cat "$OUT/$BIN.sha256"
done
