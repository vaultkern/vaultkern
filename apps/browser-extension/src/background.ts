import { createNativeMessagingBridge } from "./nativeBridge";
import {
  EXTENSION_SETTINGS_STORAGE_KEY,
  createChromeExtensionSettingsStore
} from "./extensionSettings";
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
const NATIVE_KEEP_ALIVE_INTERVAL_MS = 20_000;
const WEB_AUTHN_CONTENT_SCRIPT_ID = "vaultkern-webauthn-content-bridge";
const WEB_AUTHN_PAGE_HOOK_SCRIPT_ID = "vaultkern-webauthn-page-hook";
const WEB_AUTHN_DYNAMIC_SCRIPT_IDS = [
  WEB_AUTHN_CONTENT_SCRIPT_ID,
  WEB_AUTHN_PAGE_HOOK_SCRIPT_ID
];
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

if (chromeApi?.runtime?.onMessage && nativeBridge) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: unknown,
      sender: unknown,
      sendResponse: (response: unknown) => void
    ) => {
      if (isWebAuthnPageRequest(message)) {
        if (webAuthnProxyAttached || webAuthnProxySyncPromise) {
          recordWebAuthnPageRequest(message, chromeApi, sender);
        }
        return false;
      }

      if (!isRuntimeCommand(message)) {
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

  await unregisterWebAuthnPageHook();
  const status = await detachWebAuthnProxy(chromeApi);
  if (status.status === "detached" || status.status === "unsupported") {
    webAuthnProxyAttached = false;
    stopNativeKeepAlive();
  }
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
        id: WEB_AUTHN_CONTENT_SCRIPT_ID,
        matches: ["<all_urls>"],
        js: ["webauthnContentScript.js"],
        runAt: "document_start",
        allFrames: true,
        persistAcrossSessions: false
      },
      {
        id: WEB_AUTHN_PAGE_HOOK_SCRIPT_ID,
        matches: ["<all_urls>"],
        js: ["webauthnPageHook.js"],
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
  const injectionResults = await Promise.all(
    tabIds.map((tabId) => injectWebAuthnPageHookIntoTab(tabId))
  );
  const injectedCount = injectionResults.filter(Boolean).length;
  const failedCount = injectionResults.length - injectedCount;

  await recordWebAuthnDebug(chromeApi, {
    event: "page_hook_open_tabs_injected",
    injectedCount,
    failedCount
  });
}

async function injectWebAuthnPageHookIntoTab(tabId: number) {
  if (!chromeApi?.scripting?.executeScript) {
    return false;
  }

  let tabHadFailure = false;
  try {
    await chromeApi.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: installVaultKernWebAuthnInlineBridge,
      world: "ISOLATED"
    });
  } catch {
    tabHadFailure = true;
  }

  try {
    await chromeApi.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["webauthnPageHook.js"],
      world: "MAIN"
    });
  } catch {
    tabHadFailure = true;
  }

  return !tabHadFailure;
}

function installVaultKernWebAuthnInlineBridge() {
  const pageRequestMessageType = "vaultkern_webauthn_page_request";
  const pageRequestEventType = "vaultkern_webauthn_page_request_event";
  const bridgeVersion = 1;
  const globalState = globalThis as typeof globalThis & {
    __vaultkernWebAuthnInlineBridgeVersion?: number;
    __vaultkernWebAuthnInlineBridgeInstallId?: number;
    chrome?: any;
    origin?: unknown;
  };

  if (globalState.__vaultkernWebAuthnInlineBridgeVersion === bridgeVersion) {
    return;
  }

  const installId = (globalState.__vaultkernWebAuthnInlineBridgeInstallId ?? 0) + 1;
  globalState.__vaultkernWebAuthnInlineBridgeInstallId = installId;
  globalState.__vaultkernWebAuthnInlineBridgeVersion = bridgeVersion;

  window.addEventListener(pageRequestEventType, (event: Event) => {
    if (globalState.__vaultkernWebAuthnInlineBridgeInstallId !== installId) {
      return;
    }
    forwardWebAuthnPageRequest((event as CustomEvent).detail);
  });
  window.addEventListener("message", (event: MessageEvent) => {
    if (globalState.__vaultkernWebAuthnInlineBridgeInstallId !== installId) {
      return;
    }
    if (event.source !== window) {
      return;
    }
    forwardWebAuthnPageRequest(event.data, event);
  });

  function forwardWebAuthnPageRequest(data: unknown, event?: MessageEvent) {
    const frameOrigin = originFromFrame(event);
    const ancestorOrigins = ancestorOriginsFromWindow();
    if (
      !frameOrigin ||
      !ancestorOrigins ||
      (event && event.origin !== frameOrigin) ||
      !isWebAuthnPageRequest(data)
    ) {
      return;
    }

    const chromeApi = globalState.chrome;
    if (!chromeApi?.runtime?.sendMessage) {
      return;
    }

    const sendResult = chromeApi.runtime.sendMessage({
      type: pageRequestMessageType,
      ceremony: data.ceremony,
      origin: frameOrigin,
      topOrigin: topOriginFromAncestorOrigins(ancestorOrigins),
      ancestorOrigins,
      relyingParty: optionalStringFrom(data.relyingParty),
      challenge: optionalStringFrom(data.challenge),
      allowCredentialIds: stringArrayFrom(data.allowCredentialIds),
      excludeCredentialIds: stringArrayFrom(data.excludeCredentialIds),
      mediation: optionalStringFrom(data.mediation),
      observedAt: Date.now()
    });
    if (sendResult && typeof sendResult.catch === "function") {
      sendResult.catch(() => undefined);
    }
  }

  function originFromFrame(event?: MessageEvent) {
    const windowOrigin = strictOriginFromString(window.location.origin);
    if (windowOrigin) {
      return windowOrigin;
    }

    if (typeof globalState.origin === "string") {
      const globalOrigin = strictOriginFromString(globalState.origin);
      if (globalOrigin) {
        return globalOrigin;
      }
    }

    if (event) {
      const eventOrigin = strictOriginFromString(event.origin);
      if (eventOrigin) {
        return eventOrigin;
      }
    }

    return null;
  }

  function strictOriginFromString(value: string) {
    if (value.trim() === "" || value !== value.trim() || value === "null") {
      return null;
    }
    try {
      const parsed = new URL(value);
      if (
        parsed.username !== "" ||
        parsed.password !== "" ||
        parsed.pathname !== "/" ||
        parsed.search !== "" ||
        parsed.hash !== ""
      ) {
        return null;
      }
      return parsed.origin;
    } catch {
      return null;
    }
  }

  function ancestorOriginsFromWindow() {
    const ancestorOrigins = window.location.ancestorOrigins;
    if (!ancestorOrigins || typeof ancestorOrigins.length !== "number") {
      return [];
    }

    const origins: string[] = [];
    for (const value of Array.from(ancestorOrigins as ArrayLike<unknown>)) {
      if (typeof value !== "string") {
        return null;
      }
      const origin = strictOriginFromString(value);
      if (!origin) {
        return null;
      }
      origins.push(origin);
    }
    return origins;
  }

  function topOriginFromAncestorOrigins(ancestorOrigins: string[]) {
    const topOrigin = ancestorOrigins[ancestorOrigins.length - 1];
    return typeof topOrigin === "string" ? topOrigin : undefined;
  }

  function optionalStringFrom(value: unknown) {
    return typeof value === "string" ? value : undefined;
  }

  function stringArrayFrom(value: unknown) {
    if (!Array.isArray(value)) {
      return undefined;
    }
    return value.filter((item): item is string => typeof item === "string");
  }

  function isWebAuthnPageRequest(message: unknown): message is {
    type: string;
    ceremony: "create" | "get";
    relyingParty?: string;
    challenge?: string;
    allowCredentialIds?: string[];
    excludeCredentialIds?: string[];
    mediation?: string;
  } {
    if (
      typeof message !== "object" ||
      message === null ||
      (message as { type?: unknown }).type !== pageRequestMessageType
    ) {
      return false;
    }

    const ceremony = (message as { ceremony?: unknown }).ceremony;
    return ceremony === "create" || ceremony === "get";
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
