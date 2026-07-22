#!/bin/zsh
set -euo pipefail

helper_source="$BUILT_PRODUCTS_DIR/VaultKernNativeMessagingShim"
helper_destination="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/VaultKernNativeMessagingShim"
agent_directory="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Library/LaunchAgents"
agent_source="$SRCROOT/Config/com.vaultkern.macos.native-messaging-shim.agent.plist"

/bin/mkdir -p "${helper_destination:h}" "$agent_directory"
/usr/bin/ditto "$helper_source" "$helper_destination"
/bin/chmod 0755 "$helper_destination"
/usr/bin/ditto "$agent_source" "$agent_directory/${agent_source:t}"
