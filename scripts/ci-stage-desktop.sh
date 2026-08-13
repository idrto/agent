#!/usr/bin/env bash
# Stage desktop Source + Target artifacts.
# Usage: bash scripts/ci-stage-desktop.sh <platform-name>
#   platform-name examples: linux-x64, windows-x64, macos-arm64
set -euo pipefail

NAME="${1:?platform name required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SRC="dist/source/${NAME}"
TGT="dist/target/${NAME}"
REL="${CARGO_TARGET_DIR:-target}/release"
mkdir -p "${SRC}" "${TGT}"

if [[ -f "${REL}/source-agent.exe" ]]; then
  cp -v "${REL}/source-agent.exe" "${SRC}/"
  cp -v "${REL}/target-agent.exe" "${TGT}/"
  cp -v "${REL}/idr_c_api.dll" "${SRC}/"
  if [[ -f "${REL}/idr_c_api.lib" ]]; then
    cp -v "${REL}/idr_c_api.lib" "${SRC}/"
  fi
elif [[ -f "${REL}/source-agent" ]]; then
  cp -v "${REL}/source-agent" "${SRC}/"
  cp -v "${REL}/target-agent" "${TGT}/"
  chmod +x "${SRC}/source-agent" "${TGT}/target-agent"
  if [[ -f "${REL}/libidr_c_api.dylib" ]]; then
    cp -v "${REL}/libidr_c_api.dylib" "${SRC}/"
  elif [[ -f "${REL}/libidr_c_api.so" ]]; then
    cp -v "${REL}/libidr_c_api.so" "${SRC}/"
  fi
else
  echo "source-agent binary not found under ${REL}" >&2
  ls -la "${REL}" >&2 || true
  exit 1
fi

cp -v crates/idr-c-api/include/idr.h "${SRC}/"
find dist -type f | sort
