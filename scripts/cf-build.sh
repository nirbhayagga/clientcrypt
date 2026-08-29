#!/usr/bin/env sh
# Build for hosts whose build image has Node but no Rust (Cloudflare Workers
# Builds): install a minimal rustup toolchain with the wasm32 target, then run
# the normal build. No-op on machines that already have cargo.
set -eu
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --target wasm32-unknown-unknown
  . "$HOME/.cargo/env"
fi
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
npm run build
