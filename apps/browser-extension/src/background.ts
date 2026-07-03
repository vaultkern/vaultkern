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
const WEB_AUTHN_PAGE_HOOK_SCRIPT_ID = "vaultkern-webauthn-page-hook";
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
          onPortDetached: resetPasskeyLedgerConnectionId
        }
      )
    : null;

if (chromeApi?.runtime?.onMessage && nativeBridge) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: unknown,
      _sender: unknown,
      sendResponse: (response: unknown) => void
    ) => {
      if (isWebAuthnPageRequest(message)) {
        if (webAuthnProxyAttached || webAuthnProxySyncPromise) {
          recordWebAuthnPageRequest(message, chromeApi);
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
      ids: [WEB_AUTHN_PAGE_HOOK_SCRIPT_ID]
    });
  } catch {
    // The script may not have been registered in this browser session.
  }

  try {
    await chromeApi.scripting.registerContentScripts([
      {
        id: WEB_AUTHN_PAGE_HOOK_SCRIPT_ID,
        matches: ["<all_urls>"],
        js: ["webauthnPageHook.js"],
        runAt: "document_start",
        world: "MAIN",
        allFrames: true,
        matchAboutBlank: true,
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

  let injectedCount = 0;
  let failedCount = 0;
  for (const tab of tabs) {
    if (typeof tab.id !== "number") {
      continue;
    }

    let tabHadFailure = false;
    try {
      await chromeApi.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        files: ["webauthnContentScript.js"],
        world: "ISOLATED"
      });
    } catch {
      tabHadFailure = true;
    }

    try {
      await chromeApi.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        files: ["webauthnPageHook.js"],
        world: "MAIN"
      });
    } catch {
      tabHadFailure = true;
    }

    if (tabHadFailure) {
      failedCount += 1;
    } else {
      injectedCount += 1;
    }
  }

  await recordWebAuthnDebug(chromeApi, {
    event: "page_hook_open_tabs_injected",
    injectedCount,
    failedCount
  });
}

async function unregisterWebAuthnPageHook() {
  await disableWebAuthnPageHookInOpenTabs();

  if (!chromeApi?.scripting?.unregisterContentScripts) {
    webAuthnPageHookRegistered = false;
    return;
  }

  try {
    await chromeApi.scripting.unregisterContentScripts({
      ids: [WEB_AUTHN_PAGE_HOOK_SCRIPT_ID]
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

  let disabledCount = 0;
  let failedCount = 0;
  for (const tab of tabs) {
    if (typeof tab.id !== "number") {
      continue;
    }

    try {
      await chromeApi.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        func: disableVaultKernWebAuthnPageHook,
        world: "MAIN"
      });
      disabledCount += 1;
    } catch {
      failedCount += 1;
    }
  }

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
