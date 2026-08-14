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

clone_repo() {
  local url="$1" dest="$2" branch="${3:-}"
  if [[ -d "${dest}/.git" ]]; then
    echo "already present: ${dest}"
    return
  fi
  if [[ -n "${branch}" ]]; then
    echo "cloning ${url} (branch ${branch}) -> ${dest}"
    git clone --depth 1 --branch "${branch}" "${url}" "${dest}"
  else
    echo "cloning ${url} -> ${dest}"
    git clone --depth 1 "${url}" "${dest}"
  fi
}

clone_repo https://github.com/idrto/dns-encoded-format.git "${PARENT}/dns-encoded-format"
clone_repo https://github.com/idrto/datachannel-rs.git "${PARENT}/datachannel-rs" "fix/raw-sdp-forward"
clone_repo https://github.com/2keyapp/dp-sdk.git "${PARENT}/dp-sdk" "e2e"
