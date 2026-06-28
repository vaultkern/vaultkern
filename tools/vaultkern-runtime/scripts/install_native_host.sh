#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: install_native_host.sh <extension-id> <binary-path>" >&2
  exit 1
fi

extension_id="$1"
binary_path="$2"
extension_origin="chrome-extension://${extension_id}/"
destination="${HOME}/.config/google-chrome/NativeMessagingHosts/com.vaultkern.runtime.json"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

if [[ "${binary_path}" != /* ]]; then
  echo "error: binary path must be absolute: ${binary_path}" >&2
  exit 1
fi

if command -v realpath >/dev/null 2>&1; then
  if ! canonical_binary_path="$(realpath -m -- "${binary_path}")"; then
    echo "error: failed to canonicalize binary path: ${binary_path}" >&2
    exit 1
  fi
elif command -v python3 >/dev/null 2>&1; then
  if ! canonical_binary_path="$(python3 - "${binary_path}" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
  )"; then
    echo "error: failed to canonicalize binary path: ${binary_path}" >&2
    exit 1
  fi
else
  echo "error: unable to canonicalize binary path: realpath or python3 is required" >&2
  exit 1
fi

mkdir -p "$(dirname "${destination}")"
tmp_file="$(mktemp)"

trap 'rm -f "${tmp_file}"' EXIT

(
  cd "${repo_root}"
  cargo run --quiet -p vaultkern-runtime -- --print-native-host-manifest "${canonical_binary_path}" "${extension_origin}"
) > "${tmp_file}"

mv "${tmp_file}" "${destination}"
trap - EXIT

echo "${destination}"
