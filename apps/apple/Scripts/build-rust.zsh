#!/bin/zsh
set -euo pipefail

repo_root="${SRCROOT}/../.."
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
library_name="libvaultkern_uniffi.a"
output_directory="${repo_root}/target/xcode/${CONFIGURATION}"
slice_directory="${TARGET_TEMP_DIR}/VaultKernRustSlices"
architectures=("${(@s: :)ARCHS}")
libraries=()

if (( ${#architectures} == 0 )); then
  echo "error: Xcode did not provide a target architecture" >&2
  exit 1
fi

cd "${repo_root}"
rm -rf "${slice_directory}"
mkdir -p "${slice_directory}"
rm -rf "${output_directory}"
for architecture in "${architectures[@]}"; do
  case "${architecture}" in
    arm64) rust_target="aarch64-apple-darwin" ;;
    x86_64) rust_target="x86_64-apple-darwin" ;;
    *)
      echo "error: unsupported macOS architecture ${architecture}" >&2
      exit 1
      ;;
  esac

  cargo build --locked --release --target "${rust_target}" -p vaultkern-uniffi
  architecture_library="${slice_directory}/${architecture}-${library_name}"
  cp -f "${repo_root}/target/${rust_target}/release/${library_name}" "${architecture_library}"
  libraries+=("${architecture_library}")
done

mkdir -p "${output_directory}"
if (( ${#libraries} == 1 )); then
  cp -f "${libraries[1]}" "${output_directory}/${library_name}"
else
  /usr/bin/lipo -create "${libraries[@]}" -output "${output_directory}/${library_name}"
fi
