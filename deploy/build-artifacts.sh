#!/usr/bin/env bash
#
# Build the worker binaries + checksums into deploy/artifacts/, which the
# production Caddy serves at https://<hub>/dist/. Run this before bringing up the
# prod stack (or whenever the worker changes) so the install one-liner is
# self-contained (no GitHub release required).
#
#   ./build-artifacts.sh [VERSION]
#
set -euo pipefail

VERSION="${1:-v0.1.0}"
here="$(cd "$(dirname "$0")" && pwd)"
worker_dir="$(cd "${here}/../worker" && pwd)"
out="${here}/artifacts"

echo "==> building worker ${VERSION} (linux/amd64, linux/arm64)"
( cd "${worker_dir}" && make release VERSION="${VERSION}" )

mkdir -p "${out}"
cp "${worker_dir}"/dist/huginn-worker-linux-* "${out}/"
( cd "${out}" && sha256sum huginn-worker-linux-* > checksums.txt )

echo "==> artifacts in ${out}:"
ls -1 "${out}"
