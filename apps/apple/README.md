# VaultKern Apple app

The Xcode 27 project is generated from `project.yml` and hosts the macOS 14+
SwiftUI resident app. The Rust core remains in process through the checked-in
UniFFI Swift binding and is linked as a universal static library. Install both
macOS Rust targets before producing the default universal Release build:

```zsh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

Generate and build with Xcode Beta:

```zsh
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodegen generate --spec apps/apple/project.yml
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild \
  -project apps/apple/VaultKern.xcodeproj -scheme VaultKern \
  -destination 'platform=macOS' build
```

Automatic signing uses the free Personal Team `4HBAZ2M969`. The app requires
its data-protection Keychain access group and the user-selected file sandbox
entitlement. OneDrive builds additionally require the public Azure app client
ID at Rust compile time:

```zsh
VAULTKERN_ONEDRIVE_CLIENT_ID=<public-client-id> \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project apps/apple/VaultKern.xcodeproj -scheme VaultKern build
```

The sandbox permits outbound HTTPS and the fixed loopback OAuth callback
listener. No AutoFill credential-provider entitlement is part of this target.

## Browser native messaging

The app embeds a signed `VaultKernNativeMessagingShim`. The same executable is
registered as an `SMAppService` LaunchAgent for its Mach broker and is launched
per browser port for native-messaging stdio. The resident and helper refuse XPC
peers that do not match the fixed Team ID and signing identifiers in
`Sources/IPC/IPCContract.swift`.

After building a signed app, install Chrome and Edge host manifests for the
current extension id:

```zsh
apps/apple/Scripts/install-native-host.zsh <32-letter-extension-id> \
  /absolute/path/to/VaultKern.app
```

The helper forwards framed protocol bytes only. Rust in the resident app owns
handshake negotiation, per-port cancellation, command dispatch, and fresh
Touch ID authorization for secret release or mutation commands.
