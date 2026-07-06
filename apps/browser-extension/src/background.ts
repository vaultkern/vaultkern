import { createNativeMessagingBridge } from "./nativeBridge";
import {
  EXTENSION_SETTINGS_STORAGE_KEY,
  createChromeExtensionSettingsStore
} from "./extensionSettings";
import { pendingAutofillSubmissionFromUnknown } from "./autofill/pendingSubmission";
import type { PendingAutofillSubmission } from "./autofill/pendingSubmission";
import {
  attachWebAuthnProxy,
  currentPasskeyLedgerConnectionId,
  detachWebAuthnProxy,
  recordWebAuthnDebug,
  recordWebAuthnPageRequest,
  reconcilePersistedPasskeyCeremonies,
  registerWebAuthnProxyRequestHandlers,
  resetPasskeyLedgerConnectionId
} from "./webauthnProxy";

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const extensionSettingsStore = createChromeExtensionSettingsStore();
let webAuthnProxyAttached = false;
let webAuthnProxySyncPromise: Promise<void> | null = null;
let webAuthnProxySyncRequested = false;
let passkeyProviderEnabled = false;
let nativeKeepAliveTimer: ReturnType<typeof setInterval> | null = null;
let pendingAutofillSubmission: PendingAutofillSubmission | null = null;
const NATIVE_KEEP_ALIVE_INTERVAL_MS = 20_000;
const PENDING_AUTOFILL_SUBMISSION_STORAGE_KEY = "vaultkernPendingAutofillSubmission";
const WEB_AUTHN_CONTENT_SCRIPT_FILE = "webauthnContentScript.js";
const WEB_AUTHN_PAGE_HOOK_SCRIPT_FILE = "webauthnPageHook.js";
const WEB_AUTHN_PAGE_HOOK_SCRIPT_ID = "vaultkern-webauthn-page-hook";
const WEB_AUTHN_DYNAMIC_SCRIPT_IDS = [WEB_AUTHN_PAGE_HOOK_SCRIPT_ID];
let webAuthnPageHookRegistered = false;

function isRuntimeCommand(message: unknown): message is { version: number; command: unknown } {
  return (
    typeof message === "object" &&
    message !== null &&
    "version" in message &&
    "command" in message &&
    (message as { version?: unknown }).version === 1
  );
}

function isWebAuthnPageRequest(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type === "vaultkern_webauthn_page_request"
  );
}

function storageSession() {
  return chromeApi?.storage?.session;
}

function objectRecordFromUnknown(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function storageGet(key: string): Promise<Record<string, unknown>> {
  const storage = storageSession();
  if (typeof storage?.get !== "function") {
    return Promise.resolve({});
  }

  return new Promise((resolve) => {
    let settled = false;
    const settle = (items: unknown) => {
      if (!settled) {
        settled = true;
        resolve(objectRecordFromUnknown(items));
      }
    };

    try {
      const result = storage.get(key, settle);
      if (typeof result?.then === "function") {
        result.then(settle, () => settle({}));
      }
    } catch {
      settle({});
    }
  });
}

function storageSet(items: Record<string, unknown>): Promise<void> {
  const storage = storageSession();
  if (typeof storage?.set !== "function") {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    let settled = false;
    const settle = () => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };

    try {
      const result = storage.set(items, settle);
      if (typeof result?.then === "function") {
        result.then(settle, settle);
      }
    } catch {
      settle();
    }
  });
}

function storageRemove(key: string): Promise<void> {
  const storage = storageSession();
  if (typeof storage?.remove !== "function") {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    let settled = false;
    const settle = () => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };

    try {
      const result = storage.remove(key, settle);
      if (typeof result?.then === "function") {
        result.then(settle, settle);
      }
    } catch {
      settle();
    }
  });
}

async function persistPendingAutofillSubmission(
  submission: PendingAutofillSubmission | null
) {
  if (!submission) {
    await storageRemove(PENDING_AUTOFILL_SUBMISSION_STORAGE_KEY);
    return;
  }

  await storageSet({
    [PENDING_AUTOFILL_SUBMISSION_STORAGE_KEY]: submission
  });
}

async function loadPersistedPendingAutofillSubmission() {
  const items = await storageGet(PENDING_AUTOFILL_SUBMISSION_STORAGE_KEY);
  return pendingAutofillSubmissionFromUnknown(
    items[PENDING_AUTOFILL_SUBMISSION_STORAGE_KEY]
  );
}

function newerPendingAutofillSubmission(
  left: PendingAutofillSubmission | null,
  right: PendingAutofillSubmission | null
) {
  if (!left) {
    return right;
  }
  if (!right) {
    return left;
  }
  return right.submittedAt > left.submittedAt ? right : left;
}

function handleAutofillPendingMessage(
  message: unknown,
  sendResponse: (response: unknown) => void
) {
  if (typeof message !== "object" || message === null) {
    return false;
  }

  const messageType = (message as { type?: unknown }).type;
  if (messageType === "vaultkern_autofill_submission") {
    pendingAutofillSubmission = pendingAutofillSubmissionFromUnknown(message);
    void persistPendingAutofillSubmission(pendingAutofillSubmission).then(() => {
      sendResponse({ ok: pendingAutofillSubmission !== null });
    });
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_request") {
    void loadPersistedPendingAutofillSubmission().then((persistedSubmission) => {
      pendingAutofillSubmission = newerPendingAutofillSubmission(
        pendingAutofillSubmission,
        persistedSubmission
      );
      sendResponse({ pending: pendingAutofillSubmission });
    });
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_clear") {
    pendingAutofillSubmission = null;
    void persistPendingAutofillSubmission(null).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  return false;
}

function serializeError(error: unknown) {
  if (
    error instanceof Error &&
    "code" in error &&
    typeof (error as { code?: unknown }).code === "string"
  ) {
    return {
      code: (error as { code: string }).code,
      message: error.message
    };
  }

  return {
    code: "native_unknown",
    message: error instanceof Error ? error.message : "native messaging failed"
  };
}

const nativeBridge =
  chromeApi?.runtime?.connectNative && chromeApi?.runtime?.onMessage
    ? createNativeMessagingBridge(
        chromeApi.runtime.connectNative.bind(chromeApi.runtime),
        "com.vaultkern.runtime",
        {
          onPortDetached: resetPasskeyLedgerConnectionId,
          onEvent(event) {
            void recordWebAuthnDebug(chromeApi, {
              event: "native_bridge",
              bridgeEvent: event.event,
              commandType: event.commandType,
              code: event.code,
              message: event.message
            });
          }
        }
      )
    : null;

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: unknown,
      sender: unknown,
      sendResponse: (response: unknown) => void
    ) => {
      if (handleAutofillPendingMessage(message, sendResponse)) {
        return true;
      }

      if (isWebAuthnPageRequest(message)) {
        if (webAuthnProxyAttached || webAuthnProxySyncPromise) {
          recordWebAuthnPageRequest(message, chromeApi, sender);
        }
        return false;
      }

      if (!isRuntimeCommand(message)) {
        return false;
      }

      if (!nativeBridge) {
        return false;
      }

      sendRuntimeMessage(message)
        .then(sendResponse, (error) =>
          sendResponse({ error: serializeError(error) })
        );

      return true;
    }
  );
}

if (chromeApi?.webAuthenticationProxy) {
  chromeApi.webAuthenticationProxy.onRemoteSessionStateChange?.addListener?.(() => {
    webAuthnProxyAttached = false;
    void syncWebAuthnProxy();
  });

  if (nativeBridge) {
    registerWebAuthnProxyRequestHandlers(chromeApi, sendRuntimeCommand);
  }

  void syncWebAuthnProxy();

  chromeApi.storage?.onChanged?.addListener?.(
    (changes: Record<string, unknown>, areaName: string) => {
      if (areaName !== "local" || !(EXTENSION_SETTINGS_STORAGE_KEY in changes)) {
        return;
      }

      void syncWebAuthnProxy();
    }
  );

  chromeApi.tabs?.onUpdated?.addListener?.(
    (tabId: number, changeInfo: { status?: string }) => {
      if (
        webAuthnPageHookRegistered &&
        passkeyProviderEnabled &&
        changeInfo.status === "complete"
      ) {
        void recordWebAuthnDebug(chromeApi, {
          event: "page_hook_tab_updated",
          tabId,
          status: changeInfo.status,
          enabled: passkeyProviderEnabled,
          registered: webAuthnPageHookRegistered
        });
        void injectWebAuthnPageHookIntoTab(tabId);
      }
    }
  );
}

function syncWebAuthnProxy(): Promise<void> {
  webAuthnProxySyncRequested = true;

  if (webAuthnProxySyncPromise) {
    return webAuthnProxySyncPromise;
  }

  webAuthnProxySyncPromise = (async () => {
    while (webAuthnProxySyncRequested) {
      webAuthnProxySyncRequested = false;
      await syncWebAuthnProxyOnce();
    }
  })().finally(() => {
    webAuthnProxySyncPromise = null;
    if (webAuthnProxySyncRequested) {
      void syncWebAuthnProxy();
    }
  });
  return webAuthnProxySyncPromise;
}

async function syncWebAuthnProxyOnce() {
  if (!chromeApi?.webAuthenticationProxy) {
    return;
  }

  const settings = await extensionSettingsStore.load();
  passkeyProviderEnabled = settings.passkeyProviderEnabled;
  if (settings.passkeyProviderEnabled) {
    if (webAuthnProxyAttached) {
      await registerWebAuthnPageHook();
      return;
    }

    const status = await attachWebAuthnProxy(
      chromeApi,
      nativeBridge
        ? {
            sendRuntimeCommand(command) {
              return sendRuntimeCommand(command);
            }
          }
        : undefined
    );
    webAuthnProxyAttached = status.status === "attached";
    if (webAuthnProxyAttached) {
      await reconcilePasskeyCeremonyLedger();
      await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);
      await registerWebAuthnPageHook();
    }
    return;
  }

  webAuthnProxyAttached = false;
  stopNativeKeepAlive();
  await unregisterWebAuthnPageHook();
  await detachWebAuthnProxy(chromeApi);
}

async function registerWebAuthnPageHook() {
  if (webAuthnPageHookRegistered || !chromeApi?.scripting?.registerContentScripts) {
    return;
  }

  try {
    await chromeApi.scripting.unregisterContentScripts?.({
      ids: WEB_AUTHN_DYNAMIC_SCRIPT_IDS
    });
  } catch {
    // The script may not have been registered in this browser session.
  }

  try {
    await chromeApi.scripting.registerContentScripts([
      {
        id: WEB_AUTHN_PAGE_HOOK_SCRIPT_ID,
        matches: ["<all_urls>"],
        js: [WEB_AUTHN_PAGE_HOOK_SCRIPT_FILE],
        runAt: "document_start",
        world: "MAIN",
        allFrames: true,
        matchOriginAsFallback: true,
        persistAcrossSessions: false
      }
    ]);
    webAuthnPageHookRegistered = true;
    await injectWebAuthnPageHookIntoOpenTabs();
    await recordWebAuthnDebug(chromeApi, {
      event: "page_hook_registered"
    });
  } catch (error) {
    webAuthnPageHookRegistered = false;
    await recordWebAuthnDebug(chromeApi, {
      event: "page_hook_register_error",
      message: error instanceof Error ? error.message : String(error)
    });
  }
}

async function injectWebAuthnPageHookIntoOpenTabs() {
  if (!chromeApi?.tabs?.query || !chromeApi?.scripting?.executeScript) {
    return;
  }

  let tabs: Array<{ id?: unknown }> = [];
  try {
    tabs = await chromeApi.tabs.query({
      url: ["http://*/*", "https://*/*"]
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "page_hook_open_tabs_query_error",
      message: error instanceof Error ? error.message : String(error)
    });
    return;
  }

  const tabIds = tabs
    .map((tab) => tab.id)
    .filter((tabId): tabId is number => typeof tabId === "number");
  const injectedCount = (
    await Promise.all(tabIds.map((tabId) => injectWebAuthnPageHookIntoTab(tabId)))
  ).filter(Boolean).length;
  const failedCount = tabIds.length - injectedCount;

  await recordWebAuthnDebug(chromeApi, {
    event: "page_hook_open_tabs_injected",
    injectedCount,
    failedCount
  });
}

async function injectWebAuthnPageHookIntoTab(tabId: number) {
  if (
    !(await injectWebAuthnScriptIntoTab(
      tabId,
      WEB_AUTHN_CONTENT_SCRIPT_FILE,
      "ISOLATED"
    ))
  ) {
    return false;
  }

  return injectWebAuthnScriptIntoTab(tabId, WEB_AUTHN_PAGE_HOOK_SCRIPT_FILE, "MAIN");
}

async function injectWebAuthnScriptIntoTab(
  tabId: number,
  file: string,
  world: "ISOLATED" | "MAIN"
) {
  if (!chromeApi?.scripting?.executeScript) {
    return false;
  }

  try {
    await chromeApi.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: [file],
      world
    });
    return true;
  } catch {
    return false;
  }
}

async function unregisterWebAuthnPageHook() {
  await disableWebAuthnPageHookInOpenTabs();

  if (!chromeApi?.scripting?.unregisterContentScripts) {
    webAuthnPageHookRegistered = false;
    return;
  }

  try {
    await chromeApi.scripting.unregisterContentScripts({
      ids: WEB_AUTHN_DYNAMIC_SCRIPT_IDS
    });
  } catch {
    // Disabling is idempotent even when there is no dynamic hook.
  }
  webAuthnPageHookRegistered = false;
  await recordWebAuthnDebug(chromeApi, {
    event: "page_hook_unregistered"
  });
}

async function disableWebAuthnPageHookInOpenTabs() {
  if (!chromeApi?.tabs?.query || !chromeApi?.scripting?.executeScript) {
    return;
  }

  let tabs: Array<{ id?: unknown }> = [];
  try {
    tabs = await chromeApi.tabs.query({
      url: ["http://*/*", "https://*/*"]
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "page_hook_disable_open_tabs_query_error",
      message: error instanceof Error ? error.message : String(error)
    });
    return;
  }

  const tabIds = tabs
    .map((tab) => tab.id)
    .filter((tabId): tabId is number => typeof tabId === "number");
  const disabledResults = await Promise.all(
    tabIds.map(async (tabId) => {
      try {
        await chromeApi.scripting.executeScript({
          target: { tabId, allFrames: true },
          func: disableVaultKernWebAuthnPageHook,
          world: "MAIN"
        });
        return true;
      } catch {
        return false;
      }
    })
  );
  const disabledCount = disabledResults.filter(Boolean).length;
  const failedCount = disabledResults.length - disabledCount;

  await recordWebAuthnDebug(chromeApi, {
    event: "page_hook_open_tabs_disabled",
    disabledCount,
    failedCount
  });
}

function disableVaultKernWebAuthnPageHook() {
  const hookState = globalThis as typeof globalThis & {
    __vaultkernWebAuthnPageHookEnabled?: boolean;
  };
  hookState.__vaultkernWebAuthnPageHookEnabled = false;
}

function sendRuntimeCommand(command: unknown) {
  return sendRuntimeMessage({ version: 1, command });
}

async function reconcilePasskeyCeremonyLedger() {
  if (!nativeBridge) {
    return;
  }

  try {
    await sendRuntimeCommand({
      type: "reconcile_passkey_ceremony_ledger",
      active_connection_id: currentPasskeyLedgerConnectionId()
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "passkey_ceremony_reconcile_error",
      message: error instanceof Error ? error.message : String(error)
    });
  }
}

async function sendRuntimeMessage(message: unknown) {
  if (!nativeBridge) {
    throw new Error("native bridge is unavailable");
  }

  try {
    const response = await nativeBridge.send(message);
    syncNativeKeepAliveFromResponse(response);
    return response;
  } catch (error) {
    stopNativeKeepAlive();
    throw error;
  }
}

function syncNativeKeepAliveFromResponse(response: unknown) {
  const session = sessionStateFromResponse(response);
  if (!session) {
    return;
  }

  if (
    session.unlocked &&
    session.activeVaultId &&
    passkeyProviderEnabled &&
    webAuthnProxyAttached
  ) {
    startNativeKeepAlive();
    return;
  }

  stopNativeKeepAlive();
}

function sessionStateFromResponse(response: unknown) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "session_state"
  ) {
    return null;
  }

  return response as { unlocked?: unknown; activeVaultId?: unknown };
}

function startNativeKeepAlive() {
  if (nativeKeepAliveTimer || !nativeBridge) {
    return;
  }

  nativeKeepAliveTimer = setInterval(() => {
    void sendRuntimeCommand({ type: "get_session_state" }).catch(() => undefined);
  }, NATIVE_KEEP_ALIVE_INTERVAL_MS);
}

function stopNativeKeepAlive() {
  if (!nativeKeepAliveTimer) {
    return;
  }

  clearInterval(nativeKeepAliveTimer);
  nativeKeepAliveTimer = null;
}
