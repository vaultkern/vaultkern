import { invoke } from "@tauri-apps/api/core";
import { RuntimeClient } from "@vaultkern/runtime-web-client";
import { App } from "@vaultkern/shared-web-ui";
import { createRoot } from "react-dom/client";

import { createDesktopSettingsStore } from "./settingsStore";
import { createTauriTransport } from "./tauriTransport";
import "./styles.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("VaultKern root element is missing");
}

const client = new RuntimeClient(createTauriTransport(invoke));

createRoot(rootElement).render(
  <App
    client={client}
    extensionSettingsStore={createDesktopSettingsStore(window.localStorage)}
  />
);
