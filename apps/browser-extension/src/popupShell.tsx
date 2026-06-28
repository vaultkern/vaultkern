import { RuntimeClient } from "@vaultkern/runtime-web-client";

import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { renderNativeHostHelp } from "./nativeHostHelp";
import { PopupApp } from "./popup/PopupApp";
import { extensionTransport } from "./runtimeBridge";

const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();

async function getActiveTab() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const tabs = await chromeApi.tabs.query({ active: true, currentWindow: true });
  return tabs[0] as { id?: number; url?: string } | undefined;
}

export async function requestFillCandidates(vaultId: string) {
  const tab = await getActiveTab();

  if (!tab?.url) {
    return [];
  }

  return client.findFillCandidates(vaultId, tab.url);
}

export async function fillSelectedEntry(vaultId: string, entryId: string) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const tab = await getActiveTab();

  if (typeof tab?.id !== "number") {
    return;
  }

  const detail = await client.getEntryDetail(vaultId, entryId);

  try {
    await chromeApi.tabs.sendMessage(tab.id, {
      type: "fill_entry_detail",
      username: detail.username,
      password: detail.password
    });
  } catch (error) {
    console.warn("Failed to send fill message to active tab", error);
  }
}

export async function activeSiteLabel() {
  const tab = await getActiveTab();

  if (!tab?.url) {
    return "No active site";
  }

  try {
    return new URL(tab.url).host || tab.url;
  } catch {
    return tab.url;
  }
}

export function PopupShell() {
  return (
    <PopupApp
      client={client}
      extensionSettingsStore={extensionSettingsStore}
      renderRuntimeErrorHelp={renderNativeHostHelp}
      activeSite={activeSiteLabel}
      findCandidates={requestFillCandidates}
      fillEntry={fillSelectedEntry}
    />
  );
}
