#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
target_triple="x86_64-pc-windows-gnu"
output_dir="${repo_root}/target/vaultkern-native-setup-windows"
runtime_path="${repo_root}/target/${target_triple}/release/vaultkern-runtime.exe"
extension_id="${VAULTKERN_DEFAULT_EXTENSION_ID:-}"
signing_thumbprint="${VAULTKERN_WINDOWS_SIGNING_THUMBPRINT:-}"
sign_tool="${VAULTKERN_SIGNTOOL:-signtool.exe}"
timestamp_url="${VAULTKERN_WINDOWS_TIMESTAMP_URL:-}"

cd "${repo_root}"

if [[ -z "${extension_id}" ]]; then
  printf 'pinned extension id is required; set VAULTKERN_DEFAULT_EXTENSION_ID\n' >&2
  exit 1
fi
if [[ ! "${extension_id}" =~ ^[a-p]{32}$ ]]; then
  printf 'VAULTKERN_DEFAULT_EXTENSION_ID must contain exactly 32 lowercase letters from a through p\n' >&2
  exit 1
fi
export VAULTKERN_DEFAULT_EXTENSION_ID="${extension_id}"

if [[ -z "${signing_thumbprint}" ]]; then
  printf 'runtime signing certificate thumbprint is required; set VAULTKERN_WINDOWS_SIGNING_THUMBPRINT\n' >&2
  exit 1
fi
if [[ ! "${signing_thumbprint}" =~ ^[[:xdigit:]]{40}$ ]]; then
  printf 'VAULTKERN_WINDOWS_SIGNING_THUMBPRINT must be a 40-digit SHA-1 certificate thumbprint\n' >&2
  exit 1
fi
if [[ "${sign_tool}" == */* ]]; then
  if [[ ! -x "${sign_tool}" ]]; then
    printf 'configured signtool is not executable: %s\n' "${sign_tool}" >&2
    exit 1
  fi
elif ! command -v "${sign_tool}" >/dev/null 2>&1; then
  printf 'signtool is required; set VAULTKERN_SIGNTOOL to the Windows SDK signtool.exe path\n' >&2
  exit 1
fi

cargo build --release --target "${target_triple}" -p vaultkern-runtime

runtime_sign_path="${runtime_path}"
if [[ "${sign_tool}" == *.exe ]] && command -v wslpath >/dev/null 2>&1; then
  runtime_sign_path="$(wslpath -w "${runtime_path}")"
fi
if [[ -n "${timestamp_url}" ]]; then
  "${sign_tool}" sign /sha1 "${signing_thumbprint}" /fd SHA256 /tr "${timestamp_url}" /td SHA256 "${runtime_sign_path}"
else
  "${sign_tool}" sign /sha1 "${signing_thumbprint}" /fd SHA256 "${runtime_sign_path}"
fi
"${sign_tool}" verify /pa /all "${runtime_sign_path}"

VAULTKERN_RUNTIME_PAYLOAD_PATH="${runtime_path}" \
  cargo build --release --target "${target_triple}" -p vaultkern-native-setup

rm -rf "${output_dir}"
mkdir -p "${output_dir}"

cp \
  "${repo_root}/target/${target_triple}/release/vaultkern-native-setup.exe" \
  "${output_dir}/VaultKernNativeSetup.exe"

printf 'Packaged VaultKern Native Setup at %s\n' "${output_dir}"
