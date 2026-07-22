#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  print -u2 "usage: install-native-host.zsh <extension-id> <VaultKern.app>"
  exit 64
fi

extension_id="$1"
app_path="${2:A}"
helper_path="$app_path/Contents/Resources/VaultKernNativeMessagingShim"

if [[ ! "$extension_id" =~ '^[a-p]{32}$' ]]; then
  print -u2 "error: extension id must contain exactly 32 letters in the range a-p"
  exit 64
fi
if [[ ! -x "$helper_path" ]]; then
  print -u2 "error: signed native messaging helper is missing: $helper_path"
  exit 66
fi

destinations=(
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vaultkern.runtime.json"
  "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.vaultkern.runtime.json"
)

for destination in $destinations; do
  /bin/mkdir -p -m 0700 "${destination:h}"
  /bin/chmod 0700 "${destination:h}"
  temporary="$(/usr/bin/mktemp "${destination:h}/.vaultkern-native-host.XXXXXX")"
  /usr/bin/plutil -create json "$temporary"
  /usr/bin/plutil -insert name -string com.vaultkern.runtime "$temporary"
  /usr/bin/plutil -insert description -string "VaultKern resident runtime bridge" "$temporary"
  /usr/bin/plutil -insert path -string "$helper_path" "$temporary"
  /usr/bin/plutil -insert type -string stdio "$temporary"
  /usr/bin/plutil -insert allowed_origins -json \
    "[\"chrome-extension://$extension_id/\"]" "$temporary"
  /bin/chmod 0600 "$temporary"
  /bin/mv -f "$temporary" "$destination"
  print -- "$destination"
done
