import { RuntimeClient } from "@vaultkern/runtime-web-client";

import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { renderNativeHostHelp } from "./nativeHostHelp";
import { PopupApp } from "./popup/PopupApp";
import { extensionTransport } from "./runtimeBridge";
import {
  pendingAutofillTransactionFromUnknown,
  type PendingAutofillPlanInput,
  type PendingAutofillTransaction
} from "./autofill/pendingSubmission";
import { PENDING_AUTOFILL_TRANSACTION_TTL_MS } from "./autofill/pendingSubmissionStore";
import {
  createManualFillCapability,
  type ManualFillCapability
} from "./autofill/fillAuthorizationDescriptor";

const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();

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
  const detail = await client.getEntryDetail(vaultId, entryId);
  if (detail.id !== entryId) {
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
  const promptSite = webAuthnPromptSiteLabel();
  if (promptSite) {
    return promptSite;
  }

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
  const candidate = response as {
    pending?: unknown;
    recovery?: unknown;
  } | null;
  const pending = candidate?.pending;
  const recoveryTabId =
    candidate?.recovery === true &&
    typeof pending === "object" &&
    pending !== null &&
    Number.isSafeInteger((pending as { tabId?: unknown }).tabId) &&
    ((pending as { tabId: number }).tabId) >= 0
      ? (pending as { tabId: number }).tabId
      : undefined;
  return pendingAutofillTransactionFromUnknown(
    pending,
    recoveryTabId ?? tabId ?? -1,
    Date.now(),
    PENDING_AUTOFILL_TRANSACTION_TTL_MS
  );
}

export async function planPendingAutofillSubmission(
  transactionId: string,
  tabId: number,
  vaultId: string,
  plan: PendingAutofillPlanInput
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (typeof chromeApi?.runtime?.sendMessage !== "function") {
    return null;
  }
  const response = await chromeApi.runtime.sendMessage({
    type: "vaultkern_autofill_pending_confirm",
    transactionId,
    tabId,
    vaultId,
    plan
  });
  const pending = pendingAutofillTransactionFromUnknown(
    (response as { pending?: unknown } | null)?.pending,
    tabId,
    Date.now(),
    PENDING_AUTOFILL_TRANSACTION_TTL_MS
  );
  if (pending?.transactionId === transactionId) {
    return pending;
  }
  return null;
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

export async function executePendingAutofillMutation(
  transactionId: string,
  tabId: number
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (typeof chromeApi?.runtime?.sendMessage !== "function") {
    return { ok: false, errorMessage: "Background login save is unavailable" };
  }
  let response: unknown;
  try {
    response = await chromeApi.runtime.sendMessage({
      type: "vaultkern_autofill_pending_execute",
      transactionId,
      tabId
    });
  } catch (error) {
    const readback = await readPendingAutofillExecution(
      chromeApi,
      tabId,
      transactionId
    );
    if (readback.settled) {
      return { ok: true };
    }
    if ("expired" in readback && readback.expired) {
      return { ok: false, expired: true };
    }
    return {
      ok: false,
      ...(readback.pending ? { pending: readback.pending } : {}),
      errorMessage: error instanceof Error ? error.message : "Login save failed"
    };
  }
  const candidate = response as {
    ok?: unknown;
    pending?: unknown;
    expired?: unknown;
    conflict?: unknown;
    error?: { message?: unknown };
  } | null;
  if (candidate?.ok === true) {
    return { ok: true };
  }
  if (candidate?.expired === true) {
    return { ok: false, expired: true };
  }
  const responsePending =
    pendingAutofillTransactionFromUnknown(
      candidate?.pending,
      tabId,
      Date.now(),
      PENDING_AUTOFILL_TRANSACTION_TTL_MS
    );
  const matchingResponsePending =
    responsePending?.transactionId === transactionId ? responsePending : null;
  const readback = await readPendingAutofillExecution(
    chromeApi,
    tabId,
    transactionId
  );
  if (readback.settled) {
    return { ok: true };
  }
  if ("expired" in readback && readback.expired) {
    return { ok: false, expired: true };
  }
  const pending = readback.pending ?? matchingResponsePending;
  return {
    ok: false,
    ...(candidate?.conflict === true ? { conflict: true } : {}),
    ...(pending ? { pending } : {}),
    ...(typeof candidate?.error?.message === "string"
      ? { errorMessage: candidate.error.message }
      : {})
  };
}

async function readPendingAutofillExecution(
  chromeApi: any,
  tabId: number,
  transactionId: string
) {
  try {
    const response = await chromeApi.runtime.sendMessage({
      type: "vaultkern_autofill_pending_status",
      tabId,
      transactionId
    });
    if ((response as { ok?: unknown } | null)?.ok !== true) {
      return { settled: false as const, pending: null };
    }
    const outcome = (response as { outcome?: unknown } | null)?.outcome;
    if (outcome === "persisted") {
      return { settled: true as const, pending: null };
    }
    if (outcome === "expired" || outcome === "expired_unknown") {
      return {
        settled: false as const,
        expired: true as const,
        pending: null
      };
    }
    const pending = pendingAutofillTransactionFromUnknown(
      (response as { pending?: unknown } | null)?.pending,
      tabId,
      Date.now(),
      PENDING_AUTOFILL_TRANSACTION_TTL_MS
    );
    return pending?.transactionId === transactionId
      ? { settled: false as const, pending }
      : { settled: false as const, pending: null };
  } catch {
    return { settled: false as const, pending: null };
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

function webAuthnPromptSiteLabel() {
  if (typeof window === "undefined") {
    return null;
  }

  const params = new URLSearchParams(window.location.search);
  if (!params.get("webauthn")) {
    return null;
  }

  const relyingParty = params.get("relyingParty");
  if (relyingParty && relyingParty.trim() !== "") {
    return relyingParty;
  }

  const origin = params.get("origin");
  if (!origin) {
    return null;
  }

  try {
    return new URL(origin).host || origin;
  } catch {
    return origin;
  }
}

type WebAuthnPromptCompleteOptions = {
  credentialId?: string;
  method?: "master_password" | "quick_unlock";
  password?: string;
};

function responseKeepsWebAuthnPromptOpen(response: unknown) {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { keepOpen?: unknown }).keepOpen === true
  );
}

async function notifyWebAuthnPromptComplete(
  type: string,
  closeMode: string,
  options: WebAuthnPromptCompleteOptions = {}
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const sendMessage = chromeApi?.runtime?.sendMessage;
  const promptParams =
    typeof window === "undefined"
      ? null
      : new URLSearchParams(window.location.search);
  const shouldNotify = promptParams?.get("webauthn") === closeMode;

  if (!shouldNotify) {
    return undefined;
  }

  function closePrompt() {
    window.close();
  }

  if (typeof sendMessage !== "function") {
    closePrompt();
    return undefined;
  }

  const requestIdValue = promptParams?.get("requestId");
  const requestId =
    requestIdValue && requestIdValue.trim() !== "" ? Number(requestIdValue) : null;
  const message: Record<string, unknown> =
    typeof requestId === "number" && Number.isFinite(requestId)
      ? { type, requestId }
      : { type };
  for (const key of ["origin", "relyingParty", "topOrigin"] as const) {
    const value = promptParams?.get(key);
    if (value) {
      message[key] = value;
    }
  }
  if (options.credentialId) {
    message.credentialId = options.credentialId;
  }
  if (options.method) {
    message.method = options.method;
  }
  if (options.password) {
    message.password = options.password;
  }
  const nonce = promptParams?.get("nonce");
  if (nonce) {
    message.nonce = nonce;
  }

  let shouldClose = true;
  try {
    const response = await Promise.resolve(
      sendMessage.call(chromeApi.runtime, message)
    );
    if (responseKeepsWebAuthnPromptOpen(response)) {
      shouldClose = false;
    }
    return response;
  } catch {
    return undefined;
  } finally {
    if (shouldClose) {
      closePrompt();
    }
  }
}

async function sendWebAuthnPromptMessage(
  type: string,
  closeMode: string,
  options: Record<string, unknown> = {}
) {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const sendMessage = chromeApi?.runtime?.sendMessage;
  const promptParams =
    typeof window === "undefined"
      ? null
      : new URLSearchParams(window.location.search);
  if (promptParams?.get("webauthn") !== closeMode) {
    return;
  }
  if (typeof sendMessage !== "function") {
    window.close();
    return;
  }

  const requestIdValue = promptParams.get("requestId");
  const requestId =
    requestIdValue && requestIdValue.trim() !== "" ? Number(requestIdValue) : null;
  const message: Record<string, unknown> =
    typeof requestId === "number" && Number.isFinite(requestId)
      ? { type, requestId }
      : { type };
  for (const key of ["origin", "relyingParty", "topOrigin", "nonce"] as const) {
    const value = promptParams.get(key);
    if (value) {
      message[key] = value;
    }
  }
  Object.assign(message, options);
  const response = await Promise.resolve(
    sendMessage.call(chromeApi.runtime, message)
  );
  if (
    response &&
    typeof response === "object" &&
    (response as { ok?: unknown }).ok === false
  ) {
    const error = (response as { error?: unknown }).error;
    throw new Error(typeof error === "string" ? error : "Passkey verification failed");
  }
  window.close();
}

function notifyUnlockComplete(
  _session: unknown,
  options?: { method: "master_password" | "quick_unlock"; password?: string }
) {
  void notifyWebAuthnPromptComplete("vaultkern_unlock_complete", "unlock", options);
}

function notifyPresenceComplete(
  _session: unknown,
  options?: { credentialId?: string }
) {
  return notifyWebAuthnPromptComplete(
    "vaultkern_presence_complete",
    "approve",
    options
  );
}

async function notifyUserVerificationComplete(
  _session: unknown,
  options: { method: "master_password" | "quick_unlock"; password?: string }
) {
  await sendWebAuthnPromptMessage(
    "vaultkern_user_verification_complete",
    "verify",
    options
  );
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
      loadPendingAutofillSubmission={loadPendingAutofillSubmission}
      planPendingAutofillSubmission={planPendingAutofillSubmission}
      dismissPendingAutofillSubmission={dismissPendingAutofillSubmission}
      executePendingAutofillMutation={executePendingAutofillMutation}
      onUnlockComplete={notifyUnlockComplete}
      onWebAuthnPresenceComplete={notifyPresenceComplete}
      onWebAuthnUserVerificationComplete={notifyUserVerificationComplete}
    />
  );
}
