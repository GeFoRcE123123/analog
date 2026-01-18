#!/usr/bin/env bash
set -euo pipefail

# Fetch frontend JS libs locally to avoid flaky CDN/provider issues.
# Places files into: static/vendor/
#
# Usage (on backend VM / inside container where app files live):
#   bash scripts/frontend/fetch_graph3d_libs.sh
#
# Then restart the backend service/container so static files are served.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR_DIR="${ROOT_DIR}/static/vendor"

mkdir -p "${VENDOR_DIR}"

THREE_URL="https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.min.js"
FG_URL="https://cdn.jsdelivr.net/npm/3d-force-graph@1.73.3/dist/3d-force-graph.min.js"

echo "[fetch_graph3d_libs] Root: ${ROOT_DIR}"
echo "[fetch_graph3d_libs] Vendor dir: ${VENDOR_DIR}"

echo "[fetch_graph3d_libs] Downloading three.min.js ..."
curl -fsSL "${THREE_URL}" -o "${VENDOR_DIR}/three.min.js"

echo "[fetch_graph3d_libs] Downloading 3d-force-graph.min.js ..."
curl -fsSL "${FG_URL}" -o "${VENDOR_DIR}/3d-force-graph.min.js"

echo "[fetch_graph3d_libs] Done:"
ls -lh "${VENDOR_DIR}/three.min.js" "${VENDOR_DIR}/3d-force-graph.min.js"


