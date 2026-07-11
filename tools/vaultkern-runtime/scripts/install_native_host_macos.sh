#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

signature_team_identifier() {
  local app_bundle="$1"
  local details
  local line

  if ! details="$(codesign --display --verbose=4 "${app_bundle}" 2>&1)"; then
    echo "error: failed to inspect app signature TeamIdentifier: ${app_bundle}" >&2
    echo "${details}" >&2
    return 1
  fi
  while IFS= read -r line; do
    if [[ "${line}" == TeamIdentifier=* ]]; then
      printf '%s\n' "${line#TeamIdentifier=}"
      return 0
    fi
  done <<< "${details}"
  echo "error: app signature has no TeamIdentifier field: ${app_bundle}" >&2
  return 1
}

signature_designated_requirement() {
  local app_bundle="$1"
  local details
  local line

  if ! details="$(codesign --display --requirements - "${app_bundle}" 2>&1)"; then
    echo "error: failed to inspect app designated requirement: ${app_bundle}" >&2
    echo "${details}" >&2
    return 1
  fi
  while IFS= read -r line; do
    if [[ "${line}" == *"designated => "* ]]; then
      printf '%s\n' "${line#*designated => }"
      return 0
    fi
  done <<< "${details}"
  echo "error: app signature has no designated requirement: ${app_bundle}" >&2
  return 1
}

validate_upgrade_signature_continuity() {
  local existing_bundle="$1"
  local incoming_bundle="$2"
  local existing_team
  local incoming_team
  local existing_requirement
  local incoming_requirement

  existing_team="$(signature_team_identifier "${existing_bundle}")"
  incoming_team="$(signature_team_identifier "${incoming_bundle}")"

  if [[ -n "${existing_team}" && "${existing_team}" != "not set" ]]; then
    if [[ "${incoming_team}" != "${existing_team}" ]]; then
      echo "error: refusing native host upgrade due to TeamIdentifier drift: existing=${existing_team}, incoming=${incoming_team}" >&2
      return 1
    fi
    existing_requirement="$(signature_designated_requirement "${existing_bundle}")"
    incoming_requirement="$(signature_designated_requirement "${incoming_bundle}")"
    if [[ "${incoming_requirement}" != "${existing_requirement}" ]]; then
      echo "error: refusing native host upgrade due to designated requirement drift" >&2
      return 1
    fi
  else
    echo "error: refusing ad-hoc native host upgrade because its executable identity cannot preserve Quick Unlock Keychain ACLs; use --development-signing or remove the existing installation and Quick Unlock records explicitly" >&2
    return 1
  fi
}

validate_existing_manifest_extension() {
  local manifest="$1"
  local expected_origin="$2"
  local origin_count
  local existing_origin

  if ! origin_count="$(plutil -extract allowed_origins raw -expect array -o - "${manifest}" 2>/dev/null)"; then
    echo "error: cannot validate the existing native-host manifest; remove it explicitly before resetting the extension binding: ${manifest}" >&2
    return 1
  fi
  if ! existing_origin="$(plutil -extract allowed_origins.0 raw -expect string -o - "${manifest}" 2>/dev/null)"; then
    echo "error: cannot read the existing native-host extension origin: ${manifest}" >&2
    return 1
  fi
  if [[ "${origin_count}" != "1" || "${existing_origin}" != "${expected_origin}" ]]; then
    echo "error: refusing native host upgrade due to extension origin drift: existing=${existing_origin}, incoming=${expected_origin}" >&2
    return 1
  fi
}

if [[ $# -ne 2 || -z "$1" ]]; then
  echo "usage: install_native_host_macos.sh <extension-id> <VaultKern Native.app>" >&2
  exit 1
fi

extension_id="$1"
source_bundle="$2"

if [[ ${#extension_id} -ne 32 || "${extension_id}" == *[!a-p]* ]]; then
  echo "error: Chrome extension ID must contain exactly 32 lowercase characters in the range a-p" >&2
  exit 1
fi

if [[ ! -d "${source_bundle}" ]]; then
  echo "error: app bundle not found: ${source_bundle}" >&2
  exit 1
fi

source_parent="$(cd "$(dirname "${source_bundle}")" && pwd -P)"
source_bundle="${source_parent}/$(basename "${source_bundle}")"
app_destination="${VAULTKERN_MACOS_APP_DESTINATION:-${HOME}/Library/Application Support/VaultKern/VaultKern Native.app}"
manifest_destination="${VAULTKERN_CHROME_NATIVE_HOST_MANIFEST:-${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vaultkern.runtime.json}"
expected_extension_origin="chrome-extension://${extension_id}/"

if [[ "${app_destination}" != /* || "${manifest_destination}" != /* ]]; then
  echo "error: macOS installation destinations must be absolute paths" >&2
  exit 1
fi

if [[ -e "${manifest_destination}" || -L "${manifest_destination}" ]]; then
  validate_existing_manifest_extension "${manifest_destination}" "${expected_extension_origin}"
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
destination_replaced=0

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "${tmp_manifest}" ]]; then
    rm -f -- "${tmp_manifest}" || true
  fi
  if [[ -n "${staging_bundle}" ]]; then
    rm -rf -- "${staging_bundle}" || true
  fi
  if [[ "${installation_committed}" -ne 1 && "${destination_replaced}" -eq 1 ]]; then
    rm -rf -- "${app_destination}" || true
  fi
  if [[ -n "${backup_bundle}" && -e "${backup_bundle}" ]]; then
    if [[ "${installation_committed}" -ne 1 ]]; then
      rm -rf -- "${app_destination}" || true
      if ! mv -- "${backup_bundle}" "${app_destination}"; then
        echo "error: failed to restore previous app bundle: ${backup_bundle}" >&2
      fi
    else
      rm -rf -- "${backup_bundle}" || true
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT

ditto "${source_bundle}" "${staging_bundle}"
codesign --verify --strict "${staging_bundle}"

if [[ -e "${app_destination}" || -L "${app_destination}" ]]; then
  codesign --verify --strict "${app_destination}"
  validate_upgrade_signature_continuity "${app_destination}" "${staging_bundle}"
fi

if [[ -e "${app_destination}" || -L "${app_destination}" ]]; then
  backup_bundle="$(mktemp -d "${destination_parent}/.VaultKern Native.backup.XXXXXX")"
  rmdir "${backup_bundle}"
  mv -- "${app_destination}" "${backup_bundle}"
fi
mv -- "${staging_bundle}" "${app_destination}"
staging_bundle=""
destination_replaced=1

installed_executable="${app_destination}/Contents/MacOS/vaultkern-runtime"
if [[ ! -x "${installed_executable}" ]]; then
  echo "error: installed runtime is not executable: ${installed_executable}" >&2
  exit 1
fi

tmp_manifest="$(mktemp "${manifest_dir}/.com.vaultkern.runtime.json.XXXXXX")"

"${installed_executable}" --print-native-host-manifest \
  "${installed_executable}" \
  "${expected_extension_origin}" > "${tmp_manifest}"
mv -f -- "${tmp_manifest}" "${manifest_destination}"
tmp_manifest=""
installation_committed=1
if [[ -n "${backup_bundle}" ]]; then
  rm -rf -- "${backup_bundle}"
  backup_bundle=""
fi
trap - EXIT

echo "${manifest_destination}"
