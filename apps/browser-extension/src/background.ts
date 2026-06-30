import { createNativeMessagingBridge } from "./nativeBridge";
import {
  EXTENSION_SETTINGS_STORAGE_KEY,
  createChromeExtensionSettingsStore
} from "./extensionSettings";
import {
  attachWebAuthnProxy,
  detachWebAuthnProxy,
  recordWebAuthnPageRequest,
  registerWebAuthnProxyRequestHandlers
} from "./webauthnProxy";

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const extensionSettingsStore = createChromeExtensionSettingsStore();
let webAuthnProxyAttached = false;
let webAuthnProxySyncPromise: Promise<void> | null = null;
let webAuthnProxySyncRequested = false;
let nativeKeepAliveTimer: ReturnType<typeof setInterval> | null = null;
const NATIVE_KEEP_ALIVE_INTERVAL_MS = 20_000;

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
        "com.vaultkern.runtime"
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
  if (settings.passkeyProviderEnabled) {
    if (webAuthnProxyAttached) {
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
    return;
  }

  const status = await detachWebAuthnProxy(chromeApi);
  if (status.status === "detached" || status.status === "unsupported") {
    webAuthnProxyAttached = false;
  }
}

function sendRuntimeCommand(command: unknown) {
  return sendRuntimeMessage({ version: 1, command });
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

  if (session.unlocked && session.activeVaultId) {
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
