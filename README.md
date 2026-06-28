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
