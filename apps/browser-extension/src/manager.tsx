import { createRoot } from "react-dom/client";

import { App } from "@vaultkern/shared-web-ui";
import { RuntimeClient } from "@vaultkern/runtime-web-client";

import { renderNativeHostHelp } from "./nativeHostHelp";
import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { extensionTransport } from "./runtimeBridge";

const container = document.getElementById("root");
const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();

if (container) {
  createRoot(container).render(
    <App
      client={client}
      extensionSettingsStore={extensionSettingsStore}
      renderRuntimeErrorHelp={renderNativeHostHelp}
    />
  );
}
