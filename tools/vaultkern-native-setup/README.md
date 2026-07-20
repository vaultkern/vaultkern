# VaultKern Native Setup

`vaultkern-native-setup` is a one-shot Windows GUI utility for checking and registering the browser native messaging host. It does not run in the background and does not install itself. Users can open it, check status, register or repair the host, and close it.

## Shape

- Windows GUI executable: `VaultKernNativeSetup.exe`
- Single-file distribution: the runtime payload is embedded in the setup executable
- Runtime install path: `%LOCALAPPDATA%\vaultkern-runtime\vaultkern-runtime.exe`
- Registration scope: current user `HKCU`; no administrator rights required
- Windows application manifest: `asInvoker`, so the `Setup` filename does not trigger installer elevation detection
- Windows subsystem: GUI, so no extra console window is opened
- Supported browsers: Chrome and Edge
- Extension id: release packages can embed a stable id with the build-time `VAULTKERN_DEFAULT_EXTENSION_ID`; development, sideload, and E2E runs can use the first CLI argument, `VAULTKERN_EXTENSION_ID`, or the GUI field for the current extension id

## Packaging

Run from the repository root:

```bash
export VAULTKERN_WINDOWS_SIGNING_THUMBPRINT="<package-signing-certificate-sha1>"
export VAULTKERN_SIGNTOOL="/mnt/c/Program Files (x86)/Windows Kits/10/bin/<sdk-version>/x64/signtool.exe"
tools/vaultkern-native-setup/scripts/package_windows.sh
```

The runtime shim must be signed by the same certificate as the installed
VaultKern Windows package. Packaging stops before embedding the runtime when
the thumbprint or `signtool` is missing, and verifies the Authenticode
signature after signing. Set `VAULTKERN_WINDOWS_TIMESTAMP_URL` when the
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
%LOCALAPPDATA%\vaultkern-runtime\com.vaultkern.runtime.chrome.json
%LOCALAPPDATA%\vaultkern-runtime\com.vaultkern.runtime.edge.json
```

When `Register / Repair` is clicked, the setup utility extracts the embedded runtime to:

```text
%LOCALAPPDATA%\vaultkern-runtime\vaultkern-runtime.exe
```

The manifest points to this stable runtime path and sets `allowed_origins` to the extension id shown in the GUI. For a future Chrome Web Store release, the packaging step should inject the production extension id with `VAULTKERN_DEFAULT_EXTENSION_ID`.

Development, sideload, and E2E validation can prefill the extension id with a CLI argument or environment variable:

```powershell
VaultKernNativeSetup.exe <developer-extension-id>
$env:VAULTKERN_EXTENSION_ID="<developer-extension-id>"; .\VaultKernNativeSetup.exe
```

When no build-time default id is present, the GUI requires the current extension id. Copy it from `chrome://extensions` or from the extension error page.

`Unregister` removes the browser-specific `HKCU` registry value and removes the browser-specific manifest file written by this tool. It does not remove the runtime executable extracted under `%LOCALAPPDATA%`.

## Diagnostics

The UI shows, for each browser:

- whether the browser is installed
- whether the registry entry exists
- the manifest path referenced by the registry
- whether the manifest is valid for browser native messaging
- whether the runtime executable exists

`Copy diagnostics` copies the current diagnostic text.
