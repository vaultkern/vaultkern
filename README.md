# VaultKern

VaultKern is a clean-room KeePass-compatible vault core and browser runtime workspace.

The project is currently focused on a Rust kernel for KDBX parsing, vault modeling, cryptographic primitives, and a native runtime that can be used by a browser extension. It is early-stage software and should be treated as experimental until the compatibility and security surface have been hardened further.

## Workspace Layout

- `crates/vaultkern-crypto` - cryptographic helpers, key derivation, hashing, and TOTP primitives.
- `crates/vaultkern-model` - vault domain types such as groups, entries, TOTP records, and passkeys.
- `crates/vaultkern-kdbx` - KDBX headers, version handling, XML and binary format logic.
- `crates/vaultkern-core` - public Rust facade over the lower-level crates.
- `crates/vaultkern-runtime-protocol` - JSON protocol shared by the runtime and web clients.
- `tools/vaultkern-runtime` - native runtime used by browser integration.
- `tools/vkdbx` - small verification and demo CLI.
- `packages/runtime-web-client` - TypeScript client for the runtime protocol.
- `packages/shared-web-ui` - shared React UI for vault workflows.
- `apps/browser-extension` - browser extension shell.

## Requirements

- Rust toolchain with Rust 2024 edition support.
- Node.js and npm for the TypeScript workspaces.
- macOS 13 or later for the macOS native host bundle.
- Xcode Command Line Tools or Xcode selected through `xcode-select` for the macOS Swift bridge.
- For Windows browser native messaging builds, a Windows Rust target such as `x86_64-pc-windows-gnu` may be needed.

## Build and Test

Run Rust checks from the repository root:

```sh
cargo test --workspace
```

Install JavaScript dependencies and run workspace tests:

```sh
npm ci
npm test -- --run
```

Build the browser-facing TypeScript workspaces:

```sh
npm run build
```

Run the demo CLI:

```sh
cargo run -p vkdbx -- roundtrip-demo /tmp/demo.kdbx
```

## Browser Runtime

The browser extension talks to `tools/vaultkern-runtime` through the browser native messaging API. The runtime exposes vault operations over a small JSON protocol defined in `crates/vaultkern-runtime-protocol`.

Native messaging manifests are platform-specific and should be generated or installed for the local browser profile. Do not commit local native-host manifests, browser profile paths, or deployment scripts containing machine-specific paths.

### macOS Native Host

Build a separate app bundle for each supported architecture. The packaging script sets the deployment target to macOS 13.0 and writes the bundle under `target/vaultkern-runtime-macos/<target>/VaultKern Native.app`:

```sh
tools/vaultkern-runtime/scripts/package_macos.sh aarch64-apple-darwin
tools/vaultkern-runtime/scripts/package_macos.sh x86_64-apple-darwin
```

Development bundles are signed ad hoc when no identity is supplied. Ad-hoc signing is suitable for one-off testing, but its executable identity changes when the binary changes and therefore cannot preserve the Keychain ACL used by Quick Unlock. For repeatable local Quick Unlock testing, use an `Apple Development` identity and its Team ID:

```sh
VAULTKERN_CODESIGN_IDENTITY="Apple Development: Example (TEAMID)" \
  VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID="TEAMID" \
  tools/vaultkern-runtime/scripts/package_macos.sh aarch64-apple-darwin --development-signing
```

Release packaging accepts only a valid `Developer ID Application` identity present in the login keychain. Set `VAULTKERN_CODESIGN_IDENTITY` to either its exact identity name or its 40-character SHA-1 hash from `security find-identity -v -p codesigning`:

```sh
VAULTKERN_CODESIGN_IDENTITY="Developer ID Application: Example (TEAMID)" \
  VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID="TEAMID" \
  tools/vaultkern-runtime/scripts/package_macos.sh aarch64-apple-darwin --release-signing
```

Development mode accepts only `Apple Development`; release mode accepts only `Developer ID Application` and rejects ad-hoc, `Apple Development`, and self-signed identities. Both modes resolve the requested identity before building. `VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID` is an independent pinned value: packaging fails if either the selected certificate or the completed signature has a different Team ID.

Install the signed bundle for the current user with the Chrome extension ID shown on `chrome://extensions`:

```sh
tools/vaultkern-runtime/scripts/install_native_host_macos.sh \
  <extension-id> \
  "target/vaultkern-runtime-macos/aarch64-apple-darwin/VaultKern Native.app"
```

The installer copies the app to `~/Library/Application Support/VaultKern/VaultKern Native.app` and atomically writes `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vaultkern.runtime.json`. Reload the extension after installing the host. It validates Chrome's 32-character extension ID format and refuses to overwrite an existing manifest with a different extension origin; remove the manifest explicitly before intentionally rebinding the host. The macOS host also verifies that browser-origin invocations were launched by the valid Google-signed top-level Chrome process instead of trusting the origin command-line argument alone. Because a public Chrome extension ID cannot authenticate an extension instance, Quick Unlock is available only after the same native-host process has successfully unlocked that exact vault with a non-empty password. Restarting Chrome or reconnecting the native host therefore requires one password unlock before Touch ID is offered again. Key-file-only vaults remain supported for ordinary unlocks but cannot enable macOS Quick Unlock because a caller-supplied filesystem path is not an authentication proof. On upgrades from a signed installation, the installer requires the incoming bundle to preserve both its Team ID and designated requirement so persisted Quick Unlock rights retain the same code-signing identity. Ad-hoc installations are one-off only: the installer rejects upgrading them because a changed executable identity would strand their Quick Unlock Keychain records. Use `--development-signing` for iterative local development. The bundle identifier remains `com.vaultkern.runtime` across architecture-specific builds and signed upgrades.

## OneDrive Support

OneDrive integration uses a public OAuth client id with PKCE. The runtime reads the client id at compile time:

```sh
VAULTKERN_ONEDRIVE_CLIENT_ID="<public-client-id>" cargo build -p vaultkern-runtime
```

If the value is not configured, OneDrive login commands return a configuration error. Do not commit private OAuth secrets. A public desktop/native-app client id is not a client secret, but it is still better kept out of generic source commits unless it is intentionally part of the published application configuration.

## External Fixtures

This public repository does not include private KDBX compatibility fixtures.

Default tests do not require those files. Some deeper compatibility tests are gated behind the `external-fixtures` feature and expect a local `fixtures/` directory:

```sh
cargo test --features external-fixtures
```

Those tests are intended for local compatibility validation and may fail in a fresh public clone unless the private fixtures are supplied separately.

## Security Notes

VaultKern handles password vault data and cryptographic material. Treat all parsing, key handling, native messaging, and browser integration code as security-sensitive.

- Do not use this project to protect important secrets until it has had broader review.
- Avoid committing real vault files, access tokens, OAuth secrets, native-host manifests, or local browser profile data.
- Keep clean-room boundaries intact; external KeePass-compatible projects may be used for behavior comparison, but their code should not be copied.

## License

This workspace is licensed under either MIT or Apache-2.0, at your option.
