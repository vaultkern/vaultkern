#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: package_macos.sh <aarch64-apple-darwin|x86_64-apple-darwin> [--output-root <path>] [--prebuilt-binary <path>] [--release-signing]" >&2
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
if [[ "${release_signing}" -eq 1 && ( -z "${signing_identity}" || "${signing_identity}" == "-" ) ]]; then
  echo "error: release signing requires a non-ad-hoc VAULTKERN_CODESIGN_IDENTITY" >&2
  exit 1
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
  codesign --force --options runtime --timestamp --sign "${signing_identity}" "${app_bundle}"
fi

echo "${app_bundle}"
