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
  for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu; do
    case "$target" in
      x86_64-unknown-linux-*) os=linux; arch=amd64 ;;
      aarch64-unknown-linux-*) os=linux; arch=arm64 ;;
      x86_64-pc-windows-*)   os=windows; arch=amd64 ;;
    esac
    if [ "$os" = "windows" ]; then
      # mingw-w64 linker (not zig) for the Windows target
      ( cd "$rust_dir" && \
        HUGINN_WORKER_VERSION="$VERSION" cargo build --release --locked --target "$target" )
      cp "${rust_dir}/target/${target}/release/huginn-worker.exe" "${out}/huginn-worker-windows-${arch}.exe"
      chmod 0755 "${out}/huginn-worker-windows-${arch}.exe"
    else
      ( cd "$rust_dir" && \
        HUGINN_WORKER_VERSION="$VERSION" cargo zigbuild --release --locked --target "$target" )
      cp "${rust_dir}/target/${target}/release/huginn-worker" "${out}/huginn-worker-${os}-${arch}"
      chmod 0755 "${out}/huginn-worker-${os}-${arch}"
    fi
  done
}

build_rust

# The manifest covers EVERY asset this script publishes — the Windows binary
# included. A glob limited to the Linux assets produced a checksums.txt that
# the Windows installer could not match against, and the install failed with
# "no checksum entry" on a file that had been downloaded correctly.
( cd "$out" && sha256sum huginn-worker-* > checksums.txt )

echo "==> artifacts in ${out}:"
ls -1 "$out"
cat "$out/checksums.txt"
