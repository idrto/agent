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

# idr_dp (certificates FFI), loaded by the Dart apps from next to their exe.
for f in idr_dp.dll libidr_dp.so libidr_dp.dylib; do
  if [[ -f "${REL}/${f}" ]]; then
    cp -v "${REL}/${f}" "${SRC}/"
    cp -v "${REL}/${f}" "${TGT}/"
  fi
done
ls "${SRC}"/*idr_dp* >/dev/null 2>&1 || { echo "idr_dp not built (cargo build -p idr-dp-ffi --release)" >&2; exit 1; }

# Windows: the DLLs the binaries need at runtime that a clean PC lacks, so the
# zip runs as-is: the OpenSSL this build linked against (names read from the
# binaries, files from OPENSSL_DIR) and the Visual C++ runtime.
if [[ -f "${REL}/target-agent.exe" ]]; then
  ossl_bin="$(cygpath -u "${OPENSSL_DIR:?OPENSSL_DIR not set}")/bin"
  need=$(cat "${REL}/target-agent.exe" "${REL}/source-agent.exe" "${REL}/idr_c_api.dll" \
    | grep -aoE 'lib(ssl|crypto)-[0-9]+-x64\.dll' | sort -u)
  for f in ${need}; do
    cp -v "${ossl_bin}/${f}" "${SRC}/"
    cp -v "${ossl_bin}/${f}" "${TGT}/"
  done
  for f in vcruntime140.dll vcruntime140_1.dll msvcp140.dll; do
    cp -v "/c/Windows/System32/${f}" "${SRC}/"
    cp -v "/c/Windows/System32/${f}" "${TGT}/"
  done
fi

find dist -type f | sort
