# VaultKern Native Setup

`vaultkern-native-setup` is a one-shot Windows GUI utility for checking and registering the browser native messaging host. It does not run in the background and does not install itself. Users can open it, check status, register or repair the host, and close it.

## Shape

- Windows GUI executable: `VaultKernNativeSetup.exe`
- Single-file distribution: the runtime payload is embedded in the setup executable
- Runtime and manifest install path: `%ProgramFiles%\VaultKern\Browser Integration`
- Registration scope: current user `HKCU`, written to both registry views with a protected read-only user ACL
- Windows application manifest: `asInvoker`; registration and removal launch a narrow elevated commit and intentionally show UAC
- Windows subsystem: GUI, so no extra console window is opened
- Supported browsers: Chrome and Edge
- Extension id: signed packages require and pin one build-time `VAULTKERN_DEFAULT_EXTENSION_ID`; the GUI and runtime cannot override it

## Packaging

Run from the repository root:

```bash
export VAULTKERN_WINDOWS_SIGNING_THUMBPRINT="<package-signing-certificate-sha1>"
export VAULTKERN_SIGNTOOL="/mnt/c/Program Files (x86)/Windows Kits/10/bin/<sdk-version>/x64/signtool.exe"
export VAULTKERN_DEFAULT_EXTENSION_ID="<32-character-chromium-extension-id>"
tools/vaultkern-native-setup/scripts/package_windows.sh
```

The runtime shim and the final setup executable must be signed by the same certificate as the installed
VaultKern Windows package. Packaging stops before embedding the runtime when
the pinned extension id, thumbprint, or `signtool` is missing, and verifies the Authenticode
signatures after signing both artifacts. Set `VAULTKERN_WINDOWS_TIMESTAMP_URL` when the
release signature should use an RFC 3161 timestamp server.

Output directory:

```text
target/vaultkern-native-setup-windows/
```

The directory contains:

```text
VaultKernNativeSetup.exe
```

## Registration Behavior

Chrome registry path:

```text
HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime
```

Edge registry path:

```text
HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultkern.runtime
```

Manifest files written by the setup utility:

```text
%ProgramFiles%\VaultKern\Browser Integration\com.vaultkern.runtime.chrome.json
%ProgramFiles%\VaultKern\Browser Integration\com.vaultkern.runtime.edge.json
```

When `Register / Repair` is clicked, the unelevated GUI records the launching user's SID and starts its signed elevated commit mode. That mode extracts the embedded runtime to:

```text
%ProgramFiles%\VaultKern\Browser Integration\vaultkern-runtime.exe
```

The manifest points to this administrator-protected runtime path and sets `allowed_origins` to the extension id pinned into the packaged shim. The elevated commit writes identical registrations to the launching user's 32-bit and 64-bit `HKCU` views through `HKEY_USERS\<SID>`, then protects each leaf key so ordinary user processes can read but cannot replace it. This remains correct when a standard user supplies different administrator credentials at UAC. Before connecting, the shim authenticates the real browser channel and enforces that exact origin; the resident independently authenticates the signed shim and validates the forwarded origin's syntax.

Development, sideload, and E2E validation use a separately built and signed package pinned to that build's stable extension id:

```bash
VAULTKERN_DEFAULT_EXTENSION_ID="<developer-extension-id>" \
  tools/vaultkern-native-setup/scripts/package_windows.sh
```

Unsigned local builds without a build-time default may still accept a CLI argument, `VAULTKERN_EXTENSION_ID`, or the GUI field for isolated UI development, but the browser IPC path fails closed until a trusted id is embedded.

`Unregister` removes both protected browser-specific `HKCU` registry views through the same SID-bound elevated commit. It leaves the shared signed runtime and manifests under `%ProgramFiles%` so unregistering one Windows user cannot break another user's registration.

## Diagnostics

The UI shows, for each browser:

- whether the browser is installed
- whether the registry entry exists
- the manifest path referenced by the registry
- whether the manifest is valid for browser native messaging
- whether the runtime executable exists

`Copy diagnostics` copies the current diagnostic text.
