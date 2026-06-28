function extensionId() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  return chromeApi?.runtime?.id ?? "<extension-id>";
}

function installCommand() {
  return `tools/vaultkern-runtime/scripts/install_native_host.sh ${extensionId()} /absolute/path/to/vaultkern-runtime`;
}

function edgeRegistryPath() {
  return `HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.vaultkern.runtime`;
}

function windowsExtensionPath() {
  return `C:\\Users\\Example\\vaultkern-test\\browser-extension`;
}

function windowsRuntimePath() {
  return `C:\\Users\\Example\\vaultkern-test\\runtime\\vaultkern-runtime-browser.exe`;
}

function isErrorCode(error: unknown, code: string) {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

export function renderNativeHostHelp(error: unknown) {
  if (
    isErrorCode(error, "native_host_missing") ||
    isErrorCode(error, "native_permission_denied")
  ) {
    return (
      <div>
        <h2>Install the Chromium / Edge native host</h2>
        <p>Extension ID: {extensionId()}</p>
        <ol>
          <li>Run `cargo build -p vaultkern-runtime` from the repository root.</li>
          <li>
            For Linux Chromium, run <code>{installCommand()}</code>.
          </li>
          <li>
            For Windows Edge, confirm the registry key exists at{" "}
            <code>{edgeRegistryPath()}</code> and points to the native host
            manifest.
          </li>
          <li>
            Confirm the Edge test extension is loaded from{" "}
            <code>{windowsExtensionPath()}</code> and the native host executable
            exists at <code>{windowsRuntimePath()}</code>.
          </li>
          <li>
            Confirm the Linux manifest exists at{" "}
            <code>
              ~/.config/google-chrome/NativeMessagingHosts/com.vaultkern.runtime.json
            </code>
            .
          </li>
          <li>Open <code>edge://extensions</code>, reload the extension, and try unlocking again.</li>
        </ol>
      </div>
    );
  }

  if (
    isErrorCode(error, "native_port_disconnected") ||
    isErrorCode(error, "native_timeout")
  ) {
    return (
      <div>
        <h2>Check the Chromium / Edge native host connection</h2>
        <ol>
          <li>Confirm `vaultkern-runtime` still starts with `cargo run -p vaultkern-runtime -- --help`.</li>
          <li>
            On Windows Edge, confirm <code>{windowsRuntimePath()}</code> still
            exists and is not blocked by another running process.
          </li>
          <li>Re-run the native host install script or refresh the Edge registry entry.</li>
          <li>Open <code>edge://extensions</code> and reload the extension.</li>
          <li>Try unlocking again after the host reconnects.</li>
        </ol>
      </div>
    );
  }

  return null;
}
