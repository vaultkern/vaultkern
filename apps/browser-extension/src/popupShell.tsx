import { RuntimeClient } from "@vaultkern/runtime-web-client";

import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { renderNativeHostHelp } from "./nativeHostHelp";
import { PopupApp } from "./popup/PopupApp";
import { extensionTransport } from "./runtimeBridge";

const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();
const AUTOFILL_GENERATED_PASSWORD_CHARS =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";

export function generateAutofillPassword(length = 24) {
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.getRandomValues !== "function") {
    return undefined;
  }

  const bytes = new Uint8Array(length);
  cryptoApi.getRandomValues(bytes);
  return Array.from(
    bytes,
    (byte) => AUTOFILL_GENERATED_PASSWORD_CHARS[byte % AUTOFILL_GENERATED_PASSWORD_CHARS.length]
  ).join("");
}

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
  const fillMessage: {
    type: "fill_entry_detail";
    username?: string;
    password?: string;
    newPassword?: string;
    totp?: string;
  } = {
    type: "fill_entry_detail",
    username: detail.username,
    password: detail.password,
    newPassword: generateAutofillPassword()
  };

  if (typeof detail.totp === "string" && detail.totp !== "") {
    fillMessage.totp = detail.totp;
  }

  try {
    await chromeApi.tabs.sendMessage(tab.id, fillMessage);
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
      onUnlockComplete={notifyUnlockComplete}
      onWebAuthnPresenceComplete={notifyPresenceComplete}
      onWebAuthnUserVerificationComplete={notifyUserVerificationComplete}
    />
  );
}
