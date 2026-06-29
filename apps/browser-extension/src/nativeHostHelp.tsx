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

function chromeRegistryPath() {
  return `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.vaultkern.runtime`;
}

function windowsRuntimePath() {
  return `%LOCALAPPDATA%\\vaultkern-runtime\\vaultkern-runtime.exe`;
}

function windowsManifestPath(browser: "chrome" | "edge") {
  return `%LOCALAPPDATA%\\vaultkern-runtime\\com.vaultkern.runtime.${browser}.json`;
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
        <h2>Install the VaultKern native host</h2>
        <p>Current extension ID: {extensionId()}</p>
        <ol>
          <li>
            On Windows, run <code>VaultKernNativeSetup.exe</code>. If the
            extension ID field is empty, paste this current extension ID, then
            click <code>Register / Repair</code> for Chrome.
          </li>
          <li>
            Chrome should be registered at <code>{chromeRegistryPath()}</code>{" "}
            and point to <code>{windowsManifestPath("chrome")}</code>.
          </li>
          <li>
            The Windows runtime should exist at <code>{windowsRuntimePath()}</code>.
          </li>
          <li>
            For Linux Chromium, run <code>{installCommand()}</code>.
          </li>
          <li>
            If you are testing Edge separately, register{" "}
            <code>{edgeRegistryPath()}</code> and point it to{" "}
            <code>{windowsManifestPath("edge")}</code>.
          </li>
          <li>
            Confirm the Linux manifest exists at{" "}
            <code>
              ~/.config/google-chrome/NativeMessagingHosts/com.vaultkern.runtime.json
            </code>
            .
          </li>
          <li>
            Open <code>chrome://extensions</code>, reload the extension, and try
            unlocking again.
          </li>
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
            On Windows, confirm <code>{windowsRuntimePath()}</code> still exists
            and is not blocked by another running process.
          </li>
          <li>
            Re-run <code>VaultKernNativeSetup.exe</code> or refresh the native
            host manifest.
          </li>
          <li>Open <code>chrome://extensions</code> and reload the extension.</li>
          <li>Try unlocking again after the host reconnects.</li>
        </ol>
      </div>
    );
  }

  return null;
}
