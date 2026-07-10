#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || -z "$1" ]]; then
  echo "usage: install_native_host_macos.sh <extension-id> <VaultKern Native.app>" >&2
  exit 1
fi

extension_id="$1"
source_bundle="$2"

if [[ ! -d "${source_bundle}" ]]; then
  echo "error: app bundle not found: ${source_bundle}" >&2
  exit 1
fi

source_parent="$(cd "$(dirname "${source_bundle}")" && pwd -P)"
source_bundle="${source_parent}/$(basename "${source_bundle}")"
app_destination="${VAULTKERN_MACOS_APP_DESTINATION:-${HOME}/Library/Application Support/VaultKern/VaultKern Native.app}"
manifest_destination="${VAULTKERN_CHROME_NATIVE_HOST_MANIFEST:-${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vaultkern.runtime.json}"

if [[ "${app_destination}" != /* || "${manifest_destination}" != /* ]]; then
  echo "error: macOS installation destinations must be absolute paths" >&2
  exit 1
fi

codesign --verify --strict "${source_bundle}"

mkdir -p "$(dirname "${app_destination}")"
destination_parent="$(cd "$(dirname "${app_destination}")" && pwd -P)"
app_destination="${destination_parent}/$(basename "${app_destination}")"
if [[ "${source_bundle}" == "${app_destination}" ]]; then
  echo "error: source and installed app bundle paths must differ" >&2
  exit 1
fi

manifest_dir="$(dirname "${manifest_destination}")"
mkdir -p "${manifest_dir}"

staging_bundle="$(mktemp -d "${destination_parent}/.VaultKern Native.staging.XXXXXX")"
backup_bundle=""
tmp_manifest=""
installation_committed=0

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "${tmp_manifest}" ]]; then
    rm -f -- "${tmp_manifest}" || true
  fi
  if [[ -n "${staging_bundle}" ]]; then
    rm -rf -- "${staging_bundle}" || true
  fi
  if [[ -n "${backup_bundle}" && -e "${backup_bundle}" ]]; then
    if [[ "${installation_committed}" -eq 1 ]]; then
      rm -rf -- "${backup_bundle}" || true
    else
      rm -rf -- "${app_destination}" || true
      if ! mv -- "${backup_bundle}" "${app_destination}"; then
        echo "error: failed to restore previous app bundle: ${backup_bundle}" >&2
      fi
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT

ditto "${source_bundle}" "${staging_bundle}"
codesign --verify --strict "${staging_bundle}"

if [[ -e "${app_destination}" || -L "${app_destination}" ]]; then
  backup_bundle="$(mktemp -d "${destination_parent}/.VaultKern Native.backup.XXXXXX")"
  rmdir "${backup_bundle}"
  mv -- "${app_destination}" "${backup_bundle}"
fi
mv -- "${staging_bundle}" "${app_destination}"
staging_bundle=""

installed_executable="${app_destination}/Contents/MacOS/vaultkern-runtime"
if [[ ! -x "${installed_executable}" ]]; then
  echo "error: installed runtime is not executable: ${installed_executable}" >&2
  exit 1
fi

tmp_manifest="$(mktemp "${manifest_dir}/.com.vaultkern.runtime.json.XXXXXX")"

"${installed_executable}" --print-native-host-manifest \
  "${installed_executable}" \
  "chrome-extension://${extension_id}/" > "${tmp_manifest}"
mv -f -- "${tmp_manifest}" "${manifest_destination}"
tmp_manifest=""
installation_committed=1
if [[ -n "${backup_bundle}" ]]; then
  rm -rf -- "${backup_bundle}"
  backup_bundle=""
fi
trap - EXIT

echo "${manifest_destination}"
