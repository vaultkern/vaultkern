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
entitlement. No AutoFill credential-provider entitlement is part of this
target.
