#!/usr/bin/env bash
#
# Build the worker binaries + checksums into deploy/artifacts/, which the
# production Caddy serves at https://<hub>/dist/. Run this before bringing up
# the prod stack (or whenever the worker changes) so the install one-liner is
# self-contained (no GitHub release required).
#
#   ./build-artifacts.sh [VERSION]
#
# Builds worker-rs (Rust) for linux/amd64 + linux/arm64, statically linked
# (musl), cross-compiled with cargo-zigbuild (requires: rustup,
# `pip install ziglang`, `cargo install cargo-zigbuild`).
#
set -euo pipefail

VERSION="v1.4.0"
for arg in "$@"; do
  case "$arg" in
    --*) echo "unknown flag: $arg" >&2; exit 2 ;;
    *) VERSION="$arg" ;;
  esac
done

here="$(cd "$(dirname "$0")" && pwd)"
out="${here}/artifacts"
rust_dir="$(cd "${here}/../worker-rs" 2>/dev/null && pwd || true)"

build_rust() {
  [ -n "$rust_dir" ] || { echo "worker-rs/ not found" >&2; exit 1; }
  echo "==> building worker-rs ${VERSION} (musl static: linux/amd64, linux/arm64)"
  export PATH="${HOME}/.cargo/bin:${PATH}"
  command -v cargo >/dev/null || { echo "cargo not found (install rustup)" >&2; exit 1; }
  command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild not found (cargo install cargo-zigbuild)" >&2; exit 1; }

  mkdir -p "$out"
  for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    case "$target" in
      x86_64-*) arch=amd64 ;;
      aarch64-*) arch=arm64 ;;
    esac
    ( cd "$rust_dir" && \
      HUGINN_WORKER_VERSION="$VERSION" cargo zigbuild --release --locked --target "$target" )
    cp "${rust_dir}/target/${target}/release/huginn-worker" "${out}/huginn-worker-linux-${arch}"
    chmod 0755 "${out}/huginn-worker-linux-${arch}"
  done
}

build_rust

( cd "$out" && sha256sum huginn-worker-linux-* > checksums.txt )

echo "==> artifacts in ${out}:"
ls -1 "$out"
cat "$out/checksums.txt"
