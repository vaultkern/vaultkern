#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
target_triple="x86_64-pc-windows-gnu"
output_dir="${repo_root}/target/vaultkern-native-setup-windows"

cd "${repo_root}"

cargo build --release --target "${target_triple}" -p vaultkern-runtime
VAULTKERN_RUNTIME_PAYLOAD_PATH="${repo_root}/target/${target_triple}/release/vaultkern-runtime.exe" \
  cargo build --release --target "${target_triple}" -p vaultkern-native-setup

rm -rf "${output_dir}"
mkdir -p "${output_dir}"

cp \
  "${repo_root}/target/${target_triple}/release/vaultkern-native-setup.exe" \
  "${output_dir}/VaultKernNativeSetup.exe"

printf 'Packaged VaultKern Native Setup at %s\n' "${output_dir}"
