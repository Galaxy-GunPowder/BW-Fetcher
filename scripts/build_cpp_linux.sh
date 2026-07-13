#!/usr/bin/env bash
# C++ BW-Fetcher — Linux build.
# Output: builds/BW-Fetcher_linux_YYYYMMDD_HHMMSS_Release/BW-Fetcher-linux64
#
# Usage:
#   ./scripts/build_cpp_linux.sh
#   ./scripts/build_cpp_linux.sh Debug
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-Release}"
STAMP="$(date +%Y%m%d_%H%M%S)"
BUILD_DIR="$REPO_ROOT/builds/BW-Fetcher_linux_${STAMP}_${CONFIG}"

mkdir -p "$BUILD_DIR"
echo "==> Platform:  Linux (C++)"
echo "==> Build dir: $BUILD_DIR"
echo "==> Config:    $CONFIG"

cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -GNinja -DCMAKE_BUILD_TYPE="$CONFIG"
cmake --build "$BUILD_DIR" --target BW_Fetcher

EXE="$BUILD_DIR/BW-Fetcher-linux64"
if [[ ! -f "$EXE" ]]; then
  echo "error: expected $EXE" >&2
  exit 1
fi

mkdir -p "$REPO_ROOT/builds"
printf '%s' "$BUILD_DIR" > "$REPO_ROOT/builds/latest_linux.txt"
echo ""
echo "OK  $EXE"
echo "    pointer -> builds/latest_linux.txt"
