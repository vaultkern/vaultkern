import { RuntimeClient } from "@vaultkern/runtime-web-client";
import type { ResidentAppRoute } from "@vaultkern/runtime-web-client";

import { renderNativeHostHelp } from "./nativeHostHelp";
import { PasskeyPromptApp } from "./popup/PasskeyPromptApp";
import { PopupApp } from "./popup/PopupApp";
import { createBrowserPasskeyPromptWorkflow } from "./popup/passkeyPromptWorkflow";
import { createPendingLoginWorkflow } from "./popup/pendingLoginWorkflow";
import { extensionTransport } from "./runtimeBridge";
import {
  pendingAutofillTransactionFromUnknown,
  type PendingAutofillTransaction
} from "./autofill/pendingSubmission";
import { PENDING_AUTOFILL_TRANSACTION_TTL_MS } from "./autofill/pendingSubmissionStore";
import { createResidentBrowserSettingsStore } from "./residentBrowserSettings";
import {
  createManualFillCapability,
  type ManualFillCapability
} from "./autofill/fillAuthorizationDescriptor";

const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createResidentBrowserSettingsStore(client);

async function getActiveTab() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const tabs = await chromeApi.tabs.query({ active: true, currentWindow: true });
  return tabs[0] as { id?: number; url?: string } | undefined;
}

async function activeTabId() {
  try {
    const tab = await getActiveTab();
    return typeof tab?.id === "number" ? tab.id : undefined;
  } catch {
    return undefined;
  }
}

function normalizedHttpFillTargetUrl(value: unknown) {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

async function fillTargetCanReceiveSecrets(tabId: number, targetUrl: string) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (
    typeof chromeApi?.tabs?.get !== "function" ||
    typeof chromeApi?.windows?.get !== "function"
  ) {
    return false;
  }

  try {
    const tab = (await chromeApi.tabs.get(tabId)) as
      | { active?: boolean; url?: string; windowId?: number }
      | undefined;
    if (tab?.active !== true || normalizedHttpFillTargetUrl(tab.url) !== targetUrl) {
      return false;
    }
    if (typeof tab.windowId !== "number") {
      return false;
    }

    const tabWindow = (await chromeApi.windows.get(tab.windowId)) as
      | { focused?: boolean }
      | undefined;
    return tabWindow?.focused === true;
  } catch {
    return false;
  }
}

function candidateListIncludesEntry(candidates: Array<{ id?: unknown }>, entryId: string) {
  return candidates.some((candidate) => candidate.id === entryId);
}

export interface FillSelectedEntryOptions {
  requireSiteCandidate?: boolean;
}

export async function requestFillCandidates(vaultId: string, siteUrl?: string) {
  if (siteUrl) {
    return client.findFillCandidates(vaultId, siteUrl);
  }

  const tab = await getActiveTab();

  if (!tab?.url) {
    return [];
  }

  return client.findFillCandidates(vaultId, tab.url);
}

export async function fillSelectedEntry(
  vaultId: string,
  entryId: string,
  options: FillSelectedEntryOptions = {}
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const tab = await getActiveTab();

  if (typeof tab?.id !== "number") {
    return;
  }
  const targetUrl = normalizedHttpFillTargetUrl(tab.url);
  if (!targetUrl) {
    return;
  }

  if (options.requireSiteCandidate !== false) {
    const currentCandidates = await client.findFillCandidates(vaultId, targetUrl);
    if (!candidateListIncludesEntry(currentCandidates, entryId)) {
      return;
    }
  }

  if (!(await fillTargetCanReceiveSecrets(tab.id, targetUrl))) {
    return;
  }
  const detail = await client.getAutofillCredential(vaultId, entryId, targetUrl);
  if (detail.id !== entryId) {
    return;
  }
  let currentSession;
  try {
    currentSession = await client.getSessionState();
  } catch {
    return;
  }
  if (!currentSession.unlocked || currentSession.activeVaultId !== vaultId) {
    return;
  }
  if (!(await fillTargetCanReceiveSecrets(tab.id, targetUrl))) {
    return;
  }
  const fillMessage: {
    type: "fill_entry_detail";
    targetUrl: string;
    fillCapability: ManualFillCapability;
    username?: string;
    password?: string;
    totp?: string;
  } = {
    type: "fill_entry_detail",
    targetUrl,
    fillCapability: createManualFillCapability({ targetUrl, entryId }),
    username: detail.username,
    password: detail.password
  };

  if (typeof detail.totp === "string" && detail.totp !== "") {
    fillMessage.totp = detail.totp;
  }

  try {
    await chromeApi.tabs.sendMessage(tab.id, fillMessage, { frameId: 0 });
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

export async function loadPendingAutofillSubmission() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (typeof chromeApi?.runtime?.sendMessage !== "function") {
    return null;
  }

  let tab: { id?: number; url?: string } | undefined;
  try {
    tab = await getActiveTab();
  } catch {
    tab = undefined;
  }
  const tabId = typeof tab?.id === "number" ? tab.id : undefined;
  const response = await chromeApi.runtime.sendMessage({
    type: "vaultkern_autofill_pending_request",
    ...(tabId === undefined ? {} : { tabId }),
    ...(typeof tab?.url === "string" ? { tabUrl: tab.url } : {})
  });
  if ((response as { ok?: unknown } | null)?.ok !== true) {
    throw new Error("Pending login save state is unavailable");
  }
  const pending = (response as { pending?: unknown } | null)?.pending;
  return pendingAutofillTransactionFromUnknown(
    pending,
    tabId ?? -1,
    Date.now(),
    PENDING_AUTOFILL_TRANSACTION_TTL_MS
  );
}

export async function dismissPendingAutofillSubmission(
  transactionId: string,
  tabId: number
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (typeof chromeApi?.runtime?.sendMessage !== "function") {
    return false;
  }
  try {
    const response = await chromeApi.runtime.sendMessage({
      type: "vaultkern_autofill_pending_clear",
      state: "dismissed",
      transactionId,
      tabId
    });
    return (
      (response as { ok?: unknown } | null)?.ok === true ||
      (await terminalPendingTransactionIsCleared(chromeApi, tabId))
    );
  } catch (error) {
    if (!(await terminalPendingTransactionIsCleared(chromeApi, tabId))) {
      throw error;
    }
    return true;
  }
}

async function terminalPendingTransactionIsCleared(
  chromeApi: any,
  tabId: number | undefined
) {
  if (tabId === undefined) {
    return false;
  }
  try {
    const response = await chromeApi.runtime.sendMessage({
      type: "vaultkern_autofill_pending_request",
      tabId
    });
    return (
      (response as { ok?: unknown; pending?: unknown } | null)?.ok === true &&
      (response as { pending?: unknown } | null)?.pending === null
    );
  } catch {
    return false;
  }
}

async function openResidentApp(route: ResidentAppRoute) {
  await client.activateResidentApp(route);
}

const pendingLoginWorkflow = createPendingLoginWorkflow({
  load: loadPendingAutofillSubmission,
  findCandidates: requestFillCandidates,
  getEntryFields: (vaultId, entryId, url) =>
    client.getAutofillEntryFields(vaultId, entryId, url),
  getCreateContext: (vaultId) => client.getAutofillCreateContext(vaultId),
  findExactMatchingEntryIds: (vaultId, fields) =>
    client.findExactMatchingEntryIds(vaultId, fields),
  dismiss: dismissPendingAutofillSubmission,
  commit: (vaultId, mutation) =>
    mutation.mode === "create"
      ? client.createAutofillEntry(vaultId, {
          parentGroupId: mutation.parentGroupId,
          expectedMatchingEntryIds: mutation.expectedMatchingEntryIds,
          ...mutation.desiredFields
        })
      : client.updateAutofillEntryFields(
          vaultId,
          mutation.entryId,
          mutation.expectedFields,
          mutation.desiredFields
        )
});

export function PopupShell() {
  const passkeyPrompt =
    typeof window === "undefined"
      ? null
      : createBrowserPasskeyPromptWorkflow(client, window.location.search);
  if (passkeyPrompt) {
    return (
      <PasskeyPromptApp
        workflow={passkeyPrompt}
        settingsStore={extensionSettingsStore}
        renderRuntimeErrorHelp={renderNativeHostHelp}
      />
    );
  }

  return (
    <PopupApp
      client={client}
      extensionSettingsStore={extensionSettingsStore}
      renderRuntimeErrorHelp={renderNativeHostHelp}
      activeSite={activeSiteLabel}
      findCandidates={requestFillCandidates}
      fillEntry={fillSelectedEntry}
      pendingLoginWorkflow={pendingLoginWorkflow}
      openResidentApp={openResidentApp}
    />
  );
}
