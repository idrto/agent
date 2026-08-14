#!/usr/bin/env bash
# Clone sibling crates that this workspace path-patches.
# Usage: bash scripts/ci-clone-siblings.sh [agent-root]
#
# Branch pins (CI must match these; `git clone --depth 1` otherwise uses default/main):
#   datachannel-rs  fix/raw-sdp-forward
#   dp-sdk          e2e
set -euo pipefail

AGENT_ROOT="$(cd "${1:-.}" && pwd)"
PARENT="$(cd "${AGENT_ROOT}/.." && pwd)"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "GH_TOKEN is required to clone private/org sibling repos" >&2
  exit 1
fi

git config --global url."https://x-access-token:${GH_TOKEN}@github.com/".insteadOf "https://github.com/"

assert_branch() {
  local dest="$1" branch="$2"
  local got sha subject
  got="$(git -C "${dest}" branch --show-current)"
  sha="$(git -C "${dest}" rev-parse --short HEAD)"
  subject="$(git -C "${dest}" log -1 --format=%s)"
  echo "${dest}: branch=${got:-DETACHED} sha=${sha} ${subject}"
  if [[ "${got}" != "${branch}" ]]; then
    echo "error: ${dest} is not on ${branch} (got '${got:-DETACHED}')" >&2
    git -C "${dest}" status -sb >&2 || true
    exit 1
  fi
}

clone_repo() {
  local url="$1" dest="$2" branch="${3:-}"
  if [[ -d "${dest}/.git" ]]; then
    echo "already present: ${dest}"
    if [[ -n "${branch}" ]]; then
      assert_branch "${dest}" "${branch}"
    fi
    return
  fi
  # datachannel-rs vendors libdatachannel (+ juice/usrsctp/…) as nested
  # submodules. A plain shallow clone leaves CMakeLists.txt missing and
  # datachannel-sys's build.rs fails.
  if [[ -n "${branch}" ]]; then
    echo "cloning ${url} (branch ${branch}) -> ${dest}"
    git clone --depth 1 --recurse-submodules --shallow-submodules \
      --branch "${branch}" "${url}" "${dest}"
    assert_branch "${dest}" "${branch}"
  else
    echo "cloning ${url} -> ${dest}"
    git clone --depth 1 --recurse-submodules --shallow-submodules \
      "${url}" "${dest}"
  fi
}

clone_repo https://github.com/idrto/dns-encoded-format.git "${PARENT}/dns-encoded-format"
clone_repo https://github.com/idrto/datachannel-rs.git "${PARENT}/datachannel-rs" "fix/raw-sdp-forward"
clone_repo https://github.com/2keyapp/dp-sdk.git "${PARENT}/dp-sdk" "e2e"

if [[ ! -f "${PARENT}/datachannel-rs/datachannel-sys/libdatachannel/CMakeLists.txt" ]]; then
  echo "error: datachannel-sys/libdatachannel submodule was not checked out" >&2
  exit 1
fi
