import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { RuntimeClient } from "@vaultkern/runtime-web-client";
import type { SessionState } from "@vaultkern/runtime-web-client";
import type { ResidentAppRoute } from "@vaultkern/runtime-web-client";
import { App } from "@vaultkern/shared-web-ui";
import type {
  ResidentAppRouteSubscriber,
  SessionStateSubscriber
} from "@vaultkern/shared-web-ui";
import { createRoot } from "react-dom/client";

import { createDesktopSettingsStore } from "./settingsStore";
import { createResidentAppRouteSubscriber } from "./residentRouteSubscriber";
import { createTauriTransport } from "./tauriTransport";
import "./styles.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("VaultKern root element is missing");
}

const client = new RuntimeClient(createTauriTransport(invoke));
const settingsStore = createDesktopSettingsStore(
  () => invoke("load_desktop_settings"),
  (desired) => invoke("save_desktop_settings", { desired }),
  (credentials, expectedVaultRefId) =>
    invoke("queue_quick_unlock_enrollment", { credentials, expectedVaultRefId }),
  () => invoke("load_desktop_reconciliation_error"),
  (listener) =>
    listen<string | null>("vaultkern-reconciliation-error", (event) =>
      listener(event.payload)
    )
);
const subscribeSessionState: SessionStateSubscriber = (listener) =>
  listen<SessionState>("vaultkern-session-state", (event) => listener(event.payload));
const subscribeOpenRoute: ResidentAppRouteSubscriber =
  createResidentAppRouteSubscriber(
    () => invoke<ResidentAppRoute | null>("take_pending_resident_route"),
    (listener) =>
      listen("vaultkern-open-route", () => {
        listener();
      })
  );

createRoot(rootElement).render(
  <App
    client={client}
    extensionSettingsStore={settingsStore}
    subscribeSessionState={subscribeSessionState}
    subscribeOpenRoute={subscribeOpenRoute}
  />
);
