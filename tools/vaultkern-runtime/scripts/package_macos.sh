#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: package_macos.sh <aarch64-apple-darwin|x86_64-apple-darwin> [--output-root <path>] [--prebuilt-binary <path>] [--release-signing]" >&2
}

resolve_release_signing_identity() {
  local requested_identity="$1"
  local requested_hash
  local available_identities
  local identity_hash
  local identity_name
  local line
  local team_identifier

  if ! available_identities="$(security find-identity -v -p codesigning 2>&1)"; then
    echo "error: failed to query signing identities with security find-identity" >&2
    echo "${available_identities}" >&2
    return 1
  fi

  requested_hash="$(printf '%s' "${requested_identity}" | tr '[:lower:]' '[:upper:]')"
  while IFS= read -r line; do
    if [[ "${line}" =~ ^[[:space:]]*[0-9]+\)[[:space:]]+([[:xdigit:]]{40})[[:space:]]+\"(.*)\"$ ]]; then
      identity_hash="${BASH_REMATCH[1]}"
      identity_name="${BASH_REMATCH[2]}"
      if [[ "${requested_hash}" == "${identity_hash}" || "${requested_identity}" == "${identity_name}" ]]; then
        if [[ "${identity_name}" != "Developer ID Application: "* ]]; then
          echo "error: release signing requires a Developer ID Application identity; matched ${identity_name}" >&2
          return 1
        fi
        if [[ ! "${identity_name}" =~ \(([[:alnum:]]+)\)$ ]]; then
          echo "error: Developer ID Application identity does not contain a Team ID: ${identity_name}" >&2
          return 1
        fi
        team_identifier="${BASH_REMATCH[1]}"
        printf '%s\t%s\n' "${identity_hash}" "${team_identifier}"
        return 0
      fi
    fi
  done <<< "${available_identities}"

  echo "error: VAULTKERN_CODESIGN_IDENTITY was not found by security find-identity; release signing requires a Developer ID Application identity" >&2
  return 1
}

validate_release_signature() {
  local app_bundle="$1"
  local expected_team_identifier="$2"
  local signature_details
  local requirements
  local line
  local has_apple_root=0
  local has_developer_id_authority=0
  local has_developer_id_ca=0
  local has_hardened_runtime=0
  local has_identifier=0
  local has_secure_timestamp=0
  local has_team_identifier=0
  local timestamp
  local designated_requirement=""
  local explicit_requirement
  local verification_output

  if [[ -z "${expected_team_identifier}" || "${expected_team_identifier}" == "not set" ]]; then
    echo "error: release signature has no selected TeamIdentifier" >&2
    return 1
  fi
  if ! signature_details="$(codesign --display --verbose=4 "${app_bundle}" 2>&1)"; then
    echo "error: failed to inspect release signature" >&2
    echo "${signature_details}" >&2
    return 1
  fi

  while IFS= read -r line; do
    case "${line}" in
      "Authority=Developer ID Application:"*) has_developer_id_authority=1 ;;
      "Authority=Developer ID Certification Authority") has_developer_id_ca=1 ;;
      "Authority=Apple Root CA") has_apple_root=1 ;;
      "Identifier=com.vaultkern.runtime") has_identifier=1 ;;
      "TeamIdentifier=${expected_team_identifier}") has_team_identifier=1 ;;
      CodeDirectory*"flags="*"(runtime)"*) has_hardened_runtime=1 ;;
      Timestamp=*)
        timestamp="${line#Timestamp=}"
        if [[ -n "${timestamp}" && "${timestamp}" != "not set" ]]; then
          has_secure_timestamp=1
        fi
        ;;
    esac
  done <<< "${signature_details}"

  if [[ "${has_developer_id_authority}" -ne 1 ]]; then
    echo "error: release signature is missing Authority=Developer ID Application:" >&2
    return 1
  fi
  if [[ "${has_developer_id_ca}" -ne 1 ]]; then
    echo "error: release signature is missing Authority=Developer ID Certification Authority" >&2
    return 1
  fi
  if [[ "${has_apple_root}" -ne 1 ]]; then
    echo "error: release signature is missing Authority=Apple Root CA" >&2
    return 1
  fi
  if [[ "${has_identifier}" -ne 1 ]]; then
    echo "error: release signature Identifier must be com.vaultkern.runtime" >&2
    return 1
  fi
  if [[ "${has_team_identifier}" -ne 1 ]]; then
    echo "error: release signature TeamIdentifier does not match ${expected_team_identifier}" >&2
    return 1
  fi
  if [[ "${has_hardened_runtime}" -ne 1 ]]; then
    echo "error: release signature is missing the hardened-runtime flag" >&2
    return 1
  fi
  if [[ "${has_secure_timestamp}" -ne 1 ]]; then
    echo "error: release signature is missing a secure timestamp" >&2
    return 1
  fi

  if ! requirements="$(codesign --display --requirements - "${app_bundle}" 2>&1)"; then
    echo "error: failed to inspect release designated requirement" >&2
    echo "${requirements}" >&2
    return 1
  fi
  while IFS= read -r line; do
    if [[ "${line}" == "designated =>"* ]]; then
      designated_requirement="${line}"
      break
    fi
  done <<< "${requirements}"
  if [[ "${designated_requirement}" != *'identifier "com.vaultkern.runtime"'* ]]; then
    echo "error: designated requirement is missing identifier \"com.vaultkern.runtime\"" >&2
    return 1
  fi
  if [[ "${designated_requirement}" != *"anchor apple generic"* ]]; then
    echo "error: designated requirement is missing anchor apple generic" >&2
    return 1
  fi

  explicit_requirement="identifier \"com.vaultkern.runtime\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${expected_team_identifier}\""
  if ! verification_output="$(codesign --verify --strict "-R=${explicit_requirement}" "${app_bundle}" 2>&1)"; then
    echo "error: explicit Developer ID requirement verification failed" >&2
    echo "${verification_output}" >&2
    return 1
  fi
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

target="$1"
shift

case "${target}" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *)
    echo "error: unsupported macOS target: ${target}" >&2
    usage
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime_dir="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${runtime_dir}/../.." && pwd)"
output_root="${repo_root}/target/vaultkern-runtime-macos"
prebuilt_binary=""
release_signing=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      if [[ $# -lt 2 ]]; then
        echo "error: --output-root requires a path" >&2
        exit 1
      fi
      output_root="$2"
      shift 2
      ;;
    --prebuilt-binary)
      if [[ $# -lt 2 ]]; then
        echo "error: --prebuilt-binary requires a path" >&2
        exit 1
      fi
      prebuilt_binary="$2"
      shift 2
      ;;
    --release-signing)
      release_signing=1
      shift
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

signing_identity="${VAULTKERN_CODESIGN_IDENTITY:-}"
resolved_signing_identity="${signing_identity}"
resolved_team_identifier=""
if [[ "${release_signing}" -eq 1 && ( -z "${signing_identity}" || "${signing_identity}" == "-" ) ]]; then
  echo "error: release signing requires a Developer ID Application VAULTKERN_CODESIGN_IDENTITY" >&2
  exit 1
fi
if [[ "${release_signing}" -eq 1 ]]; then
  if ! resolved_signing_record="$(resolve_release_signing_identity "${signing_identity}")"; then
    exit 1
  fi
  resolved_signing_identity="${resolved_signing_record%%$'\t'*}"
  resolved_team_identifier="${resolved_signing_record#*$'\t'}"
fi

if [[ -z "${prebuilt_binary}" ]]; then
  cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
  if [[ "${cargo_target_dir}" != /* ]]; then
    cargo_target_dir="${repo_root}/${cargo_target_dir}"
  fi
  (
    cd "${repo_root}"
    MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release -p vaultkern-runtime --target "${target}"
  )
  runtime_binary="${cargo_target_dir}/${target}/release/vaultkern-runtime"
else
  runtime_binary="${prebuilt_binary}"
fi

if [[ ! -f "${runtime_binary}" ]]; then
  echo "error: vaultkern-runtime binary not found: ${runtime_binary}" >&2
  exit 1
fi

app_bundle="${output_root}/${target}/VaultKern Native.app"
contents_dir="${app_bundle}/Contents"
executable_dir="${contents_dir}/MacOS"

rm -rf -- "${app_bundle}"
mkdir -p "${executable_dir}"
install -m 0644 "${runtime_dir}/macos/Info.plist" "${contents_dir}/Info.plist"
install -m 0755 "${runtime_binary}" "${executable_dir}/vaultkern-runtime"

if [[ -z "${signing_identity}" || "${signing_identity}" == "-" ]]; then
  codesign --force --sign - "${app_bundle}"
else
  codesign --force --options runtime --timestamp --sign "${resolved_signing_identity}" "${app_bundle}"
  if ! validate_release_signature "${app_bundle}" "${resolved_team_identifier}"; then
    rm -rf -- "${app_bundle}"
    exit 1
  fi
fi

echo "${app_bundle}"
