import {
  RUNTIME_PROTOCOL_VERSION,
  RuntimeClient,
  createNegotiatedRuntimeTransport
} from "@vaultkern/runtime-web-client";

import { createNativeMessagingBridge } from "./nativeBridge";
import { loadResidentBrowserSettings } from "./residentBrowserSettings";
import {
  pendingAutofillSubmissionFromUnknown,
  type PendingAutofillTransaction
} from "./autofill/pendingSubmission";
import {
  createPendingAutofillSubmissionStore
} from "./autofill/pendingSubmissionStore";
import {
  automaticFillCandidate,
  parseCanonicalHttpUrl,
  sameExactHttpOrigin
} from "./autofill/originPolicy";
import { createAutomaticFillCapability } from "./autofill/fillAuthorizationDescriptor";
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
const BROWSER_SETTINGS_RECONCILIATION_ALARM =
  "vaultkern-browser-settings-reconciliation";
let webAuthnProxyAttached = false;
let webAuthnProxySyncPromise: Promise<void> | null = null;
let webAuthnProxySyncRequested = false;
let browserPasskeyProxyEnabled = false;
let nativeKeepAliveTimer: ReturnType<typeof setInterval> | null = null;
let pageLoadAutofillAttemptSequence = 0;
let nativeRuntimeClient: RuntimeClient | null = null;
const pendingAutofillSubmissionStore = createPendingAutofillSubmissionStore(
  chromeApi,
  Date.now,
  () => globalThis.crypto.randomUUID()
);
const pendingAutofillTabUrls = new Map<number, string>();
const NATIVE_KEEP_ALIVE_INTERVAL_MS = 20_000;
const PENDING_AUTOFILL_ALARM_PREFIX = "vaultkern-autofill-pending:";
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
    (message as { version?: unknown }).version === RUNTIME_PROTOCOL_VERSION
  );
}

function isWebAuthnPageRequest(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type === "vaultkern_webauthn_page_request"
  );
}

function pageLoadAutofillUrl(url: string | undefined) {
  if (typeof url !== "string" || url.trim() === "") {
    return null;
  }
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

function activeVaultIdFromSessionState(response: unknown) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "session_state" ||
    (response as { unlocked?: unknown }).unlocked !== true ||
    typeof (response as { activeVaultId?: unknown }).activeVaultId !== "string"
  ) {
    return null;
  }

  return (response as { activeVaultId: string }).activeVaultId;
}

function pageLoadAutofillCredential(
  response: unknown,
  expectedEntryId: string
) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "autofill_credential"
  ) {
    return null;
  }

  const id = (response as { id?: unknown }).id;
  const username = (response as { username?: unknown }).username;
  const password = (response as { password?: unknown }).password;
  if (
    typeof id !== "string" ||
    id.trim() === "" ||
    id !== expectedEntryId ||
    typeof username !== "string" ||
    username.trim() === "" ||
    typeof password !== "string" ||
    password === ""
  ) {
    return null;
  }

  return { username, password };
}

async function pageLoadAutofillTabCanReceive(tabId: number, expectedUrl: string) {
  if (!chromeApi?.tabs?.get || !chromeApi?.windows?.get) {
    return false;
  }

  const tab = await chromeApi.tabs.get(tabId);
  if (pageLoadAutofillUrl(tab?.url) !== expectedUrl || tab?.active !== true) {
    return false;
  }
  if (typeof tab.windowId !== "number") {
    return false;
  }

  const tabWindow = await chromeApi.windows.get(tab.windowId);
  return tabWindow?.focused === true;
}

async function pageLoadAutofillStillAuthorized(vaultId: string) {
  const settings = await currentBrowserIntegrationSettings();
  if (!settings.autofillOnPageLoadEnabled) {
    return false;
  }

  const currentVaultId = activeVaultIdFromSessionState(
    await sendRuntimeCommand({ type: "get_session_state" })
  );
  return currentVaultId === vaultId;
}

function pendingAutofillTabAlarmName(tabId: number) {
  return `${PENDING_AUTOFILL_ALARM_PREFIX}tab:${tabId}`;
}

function tabIdFromPendingAutofillAlarmName(name: string) {
  if (!name.startsWith(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`)) {
    return undefined;
  }
  const tabId = Number.parseInt(
    name.slice(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`.length),
    10
  );
  return Number.isInteger(tabId) && tabId >= 0 ? tabId : undefined;
}

function trackPendingAutofillTabUrl(tabId: number, tabUrl: string | undefined) {
  if (typeof tabUrl === "string" && tabUrl.trim() !== "") {
    pendingAutofillTabUrls.set(tabId, tabUrl);
  }
}

function clearPendingAutofillAlarmForTab(tabId: number) {
  void chromeApi?.alarms?.clear?.(pendingAutofillTabAlarmName(tabId));
}

function schedulePendingAutofillExpiryForTab(
  tabId: number,
  transaction: PendingAutofillTransaction
) {
  clearPendingAutofillAlarmForTab(tabId);
  void chromeApi?.alarms?.create?.(pendingAutofillTabAlarmName(tabId), {
    when: transaction.expiresAt
  });
}

async function loadValidPendingAutofillSubmissionForTab(
  tabId: number,
  authoritativeUrl?: string
) {
  let tabUrl: unknown = authoritativeUrl;
  if (typeof tabUrl !== "string") {
    if (typeof chromeApi?.tabs?.get !== "function") {
      return { ok: false as const };
    }
    try {
      tabUrl = (await chromeApi.tabs.get(tabId))?.url;
    } catch {
      return { ok: false as const };
    }
  }
  if (typeof tabUrl !== "string" || tabUrl.trim() === "") {
    return { ok: false as const };
  }
  try {
    const pending = await pendingAutofillSubmissionStore.loadForTabUrl(
      tabId,
      tabUrl
    );
    return { ok: true as const, pending };
  } catch {
    return { ok: false as const };
  }
}

async function reconcilePendingAutofillNavigation(
  tabId: number,
  authoritativeUrl: string
) {
  const loaded = await loadValidPendingAutofillSubmissionForTab(
    tabId,
    authoritativeUrl
  );
  if (loaded.ok && !loaded.pending) {
    pendingAutofillTabUrls.delete(tabId);
    clearPendingAutofillAlarmForTab(tabId);
  }
}

function tabIdFromMessage(message: unknown) {
  const tabId = (message as { tabId?: unknown }).tabId;
  return typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0
    ? tabId
    : undefined;
}

function pendingAutofillTransactionIdFromMessage(message: unknown) {
  const transactionId = (message as { transactionId?: unknown }).transactionId;
  return typeof transactionId === "string" &&
    transactionId.length >= 16 &&
    transactionId.length <= 128
    ? transactionId
    : null;
}

function tabIdFromSender(sender: unknown) {
  const tabId = (sender as { tab?: { id?: unknown } } | null)?.tab?.id;
  return typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0
    ? tabId
    : undefined;
}

function tabUrlFromSender(sender: unknown) {
  const tabUrl = (sender as { tab?: { url?: unknown } } | null)?.tab?.url;
  return typeof tabUrl === "string" && tabUrl.trim() !== "" ? tabUrl : undefined;
}

function senderHasTrustedExtensionOrigin(sender: unknown) {
  const runtimeId = chromeApi?.runtime?.id;
  if (
    typeof runtimeId !== "string" ||
    runtimeId === "" ||
    typeof sender !== "object" ||
    sender === null
  ) {
    return false;
  }
  const candidate = sender as { id?: unknown; url?: unknown; tab?: unknown };
  if (
    candidate.id !== runtimeId ||
    typeof candidate.url !== "string"
  ) {
    return false;
  }

  try {
    const extensionUrl = chromeApi.runtime.getURL?.("") ??
      `chrome-extension://${runtimeId}/`;
    const expectedUrl = new URL(extensionUrl);
    const senderUrl = new URL(candidate.url);
    return (
      expectedUrl.protocol === "chrome-extension:" &&
      senderUrl.protocol === "chrome-extension:" &&
      senderUrl.hostname === expectedUrl.hostname &&
      senderUrl.port === expectedUrl.port
    );
  } catch {
    return false;
  }
}

function senderIsTrustedExtensionPage(sender: unknown) {
  return (
    senderHasTrustedExtensionOrigin(sender) &&
    (sender as { tab?: unknown }).tab === undefined
  );
}

function sameCanonicalHttpUrl(left: unknown, right: unknown) {
  const leftUrl = parseCanonicalHttpUrl(left);
  const rightUrl = parseCanonicalHttpUrl(right);
  return (
    leftUrl !== null &&
    rightUrl !== null &&
    leftUrl.protocol === rightUrl.protocol &&
    leftUrl.hostname === rightUrl.hostname &&
    leftUrl.effectivePort === rightUrl.effectivePort &&
    leftUrl.pathname === rightUrl.pathname &&
    leftUrl.username === rightUrl.username &&
    leftUrl.password === rightUrl.password &&
    leftUrl.search === rightUrl.search &&
    leftUrl.hash === rightUrl.hash
  );
}

function isBrowserSerializedHttpUrl(value: unknown) {
  if (typeof value !== "string" || parseCanonicalHttpUrl(value) === null) {
    return false;
  }
  try {
    return new URL(value).href === value;
  } catch {
    return false;
  }
}

function senderUrlMatchesSubmission(senderUrl: unknown, submissionUrl: string) {
  return (
    senderUrl === submissionUrl ||
    (isBrowserSerializedHttpUrl(senderUrl) &&
      isBrowserSerializedHttpUrl(submissionUrl) &&
      sameExactHttpOrigin(senderUrl, submissionUrl))
  );
}

function senderIsExtensionContentScript(
  sender: unknown,
  submissionUrl: string
) {
  if (typeof sender !== "object" || sender === null) {
    return false;
  }
  const candidate = sender as {
    id?: unknown;
    frameId?: unknown;
    documentId?: unknown;
    url?: unknown;
    tab?: { id?: unknown; url?: unknown };
  };
  if (
    candidate.id !== chromeApi?.runtime?.id ||
    candidate.frameId !== 0 ||
    tabIdFromSender(sender) === undefined
  ) {
    return false;
  }
  const documentBound =
    typeof candidate.documentId === "string" &&
    candidate.documentId.length >= 16 &&
    candidate.documentId.length <= 128;
  const senderProof =
    sameCanonicalHttpUrl(candidate.tab?.url, candidate.url) ||
    sameExactHttpOrigin(candidate.tab?.url, candidate.url) ||
    documentBound;
  if (candidate.url === submissionUrl) {
    return senderProof;
  }
  return (
    sameCanonicalHttpUrl(candidate.tab?.url, candidate.url) &&
    senderUrlMatchesSubmission(candidate.url, submissionUrl)
  );
}

function handleAutofillPendingMessage(
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void
) {
  if (typeof message !== "object" || message === null) {
    return false;
  }

  const messageType = (message as { type?: unknown }).type;
  if (messageType === "vaultkern_autofill_submission") {
    const tabId = tabIdFromSender(sender);
    void (async () => {
      const submission = pendingAutofillSubmissionFromUnknown(message);
      if (
        !submission ||
        tabId === undefined ||
        !senderIsExtensionContentScript(sender, submission.url)
      ) {
        sendResponse({ ok: false });
        return;
      }
      const transaction = await pendingAutofillSubmissionStore.putCaptured(
        tabId,
        submission
      );
      if (transaction) {
        trackPendingAutofillTabUrl(
          tabId,
          tabUrlFromSender(sender) ?? submission.url
        );
        schedulePendingAutofillExpiryForTab(tabId, transaction);
      }
      sendResponse({ ok: transaction !== null });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_request") {
    const tabId = tabIdFromMessage(message);
    void (async () => {
      if (!senderIsTrustedExtensionPage(sender) || tabId === undefined) {
        sendResponse({ ok: false });
        return;
      }
      sendResponse(await loadValidPendingAutofillSubmissionForTab(tabId));
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_clear") {
    const tabId = tabIdFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null ||
        (message as { state?: unknown }).state !== "dismissed"
      ) {
        sendResponse({ ok: false });
        return;
      }
      const transaction = await pendingAutofillSubmissionStore.dismissForTab(
        tabId,
        transactionId
      );
      if (transaction) {
        pendingAutofillTabUrls.delete(tabId);
        clearPendingAutofillAlarmForTab(tabId);
      }
      sendResponse({ ok: transaction !== null });
    })().catch(() => sendResponse({ ok: false }));
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

const rawNativeBridge =
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
const nativeBridge = rawNativeBridge
  ? createNegotiatedRuntimeTransport(rawNativeBridge, [
      "runtime-core",
      "browser-extension",
      "browser-autofill",
      "passkey-ceremonies"
    ])
  : null;
nativeRuntimeClient = nativeBridge
  ? new RuntimeClient({ send: (message) => sendRuntimeMessage(message) })
  : null;

async function currentBrowserIntegrationSettings() {
  if (!nativeRuntimeClient) {
    throw new Error("Native runtime is unavailable");
  }
  return loadResidentBrowserSettings(nativeRuntimeClient);
}

function scheduleSavedSettingsReconciliation() {
  if (chromeApi?.webAuthenticationProxy) {
    void syncWebAuthnProxy().catch((error) => {
      console.error("failed to reconcile the WebAuthn proxy", error);
    });
  }
}

async function maybeSendPageLoadAutofill(tabId: number, tabUrl: string | undefined) {
  const sequence = ++pageLoadAutofillAttemptSequence;
  const url = pageLoadAutofillUrl(tabUrl);
  let outcome = "failed";

  try {
    if (!url) {
      outcome = "invalid_target";
      return;
    }
    if (!nativeBridge || !chromeApi?.tabs?.sendMessage) {
      outcome = "unavailable";
      return;
    }

    const settings = await currentBrowserIntegrationSettings();
    if (!settings.autofillOnPageLoadEnabled) {
      outcome = "disabled";
      return;
    }

    const vaultId = activeVaultIdFromSessionState(
      await sendRuntimeCommand({ type: "get_session_state" })
    );
    if (!vaultId) {
      outcome = "vault_locked";
      return;
    }

    const candidate = automaticFillCandidate(
      await sendRuntimeCommand({
        type: "find_fill_candidates",
        vault_id: vaultId,
        url
      }),
      url
    );
    if (!candidate) {
      outcome = "candidate_rejected";
      return;
    }

    if (!(await pageLoadAutofillTabCanReceive(tabId, url))) {
      outcome = "tab_not_receptive";
      return;
    }

    if (!(await pageLoadAutofillStillAuthorized(vaultId))) {
      outcome = "authorization_revoked";
      return;
    }

    const credentials = pageLoadAutofillCredential(
      await sendRuntimeCommand({
        type: "get_autofill_credential",
        vault_id: vaultId,
        entry_id: candidate.id,
        url
      }),
      candidate.id
    );
    if (!credentials) {
      outcome = "entry_detail_rejected";
      return;
    }

    if (!(await pageLoadAutofillStillAuthorized(vaultId))) {
      outcome = "authorization_revoked";
      return;
    }

    if (!(await pageLoadAutofillTabCanReceive(tabId, url))) {
      outcome = "tab_not_receptive";
      return;
    }

    await chromeApi.tabs.sendMessage(
      tabId,
      {
        type: "fill_entry_detail",
        targetUrl: url,
        fillCapability: createAutomaticFillCapability({
          targetUrl: url,
          entryId: candidate.id
        }),
        username: credentials.username,
        password: credentials.password
      },
      { frameId: 0 }
    );
    outcome = "delivered";
  } catch {
    // Page-load autofill is opportunistic; popup/manual fill remains the reliable path.
  } finally {
    void recordWebAuthnDebug(chromeApi, {
      event: "page_load_autofill_attempt_complete",
      sequence,
      tabId,
      targetUrl: url,
      outcome
    });
  }
}

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: unknown,
      sender: unknown,
      sendResponse: (response: unknown) => void
    ) => {
      if (handleAutofillPendingMessage(message, sender, sendResponse)) {
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

      if (!senderHasTrustedExtensionOrigin(sender)) {
        return false;
      }

      if (!nativeBridge) {
        return false;
      }

      sendRuntimeMessage(message).then(
        (response) => sendResponse(response),
        (error) => sendResponse({ error: serializeError(error) })
      );

      return true;
    }
  );
}

chromeApi?.tabs?.onUpdated?.addListener?.(
  (
    tabId: number,
    changeInfo: { status?: string; url?: string },
    tab?: { url?: string }
  ) => {
    if (typeof changeInfo.url === "string" && changeInfo.url.trim() !== "") {
      trackPendingAutofillTabUrl(tabId, changeInfo.url);
      void reconcilePendingAutofillNavigation(tabId, changeInfo.url).catch(
        () => undefined
      );
    }
    if (changeInfo.status === "complete") {
      void maybeSendPageLoadAutofill(
        tabId,
        tab?.url ?? changeInfo.url ?? pendingAutofillTabUrls.get(tabId)
      );
    }
  }
);

chromeApi?.tabs?.onRemoved?.addListener?.((tabId: number) => {
  pendingAutofillTabUrls.delete(tabId);
  clearPendingAutofillAlarmForTab(tabId);
  void pendingAutofillSubmissionStore.clearForTab(tabId);
});

chromeApi?.alarms?.onAlarm?.addListener?.((alarm: { name?: string }) => {
  if (typeof alarm.name !== "string") {
    return;
  }
  if (alarm.name === BROWSER_SETTINGS_RECONCILIATION_ALARM) {
    scheduleSavedSettingsReconciliation();
    return;
  }
  const tabId = tabIdFromPendingAutofillAlarmName(alarm.name);
  if (tabId !== undefined) {
    void pendingAutofillSubmissionStore
      .clearExpired()
      .then((nextSweepAt) => {
        if (nextSweepAt !== null) {
          void chromeApi?.alarms?.create?.(alarm.name, { when: nextSweepAt });
        }
      });
  }
});

void pendingAutofillSubmissionStore.clearExpired().catch(() => undefined);

if (chromeApi?.webAuthenticationProxy) {
  chromeApi.webAuthenticationProxy.onRemoteSessionStateChange?.addListener?.(() => {
    webAuthnProxyAttached = false;
    void syncWebAuthnProxy();
  });

  if (nativeBridge) {
    registerWebAuthnProxyRequestHandlers(chromeApi, sendRuntimeCommand);
  }

  chromeApi.tabs?.onUpdated?.addListener?.(
    (tabId: number, changeInfo: { status?: string }) => {
      if (changeInfo.status === "complete") {
        scheduleSavedSettingsReconciliation();
      }
      if (
        webAuthnPageHookRegistered &&
        browserPasskeyProxyEnabled &&
        changeInfo.status === "complete"
      ) {
        void recordWebAuthnDebug(chromeApi, {
          event: "page_hook_tab_updated",
          tabId,
          status: changeInfo.status,
          enabled: browserPasskeyProxyEnabled,
          registered: webAuthnPageHookRegistered
        });
        void injectWebAuthnPageHookIntoTab(tabId);
      }
    }
  );
}

scheduleSavedSettingsReconciliation();
void chromeApi?.alarms?.create?.(BROWSER_SETTINGS_RECONCILIATION_ALARM, {
  periodInMinutes: 0.5
});

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

  const settings = await currentBrowserIntegrationSettings();
  browserPasskeyProxyEnabled = settings.browserPasskeyProxyEnabled;
  if (settings.browserPasskeyProxyEnabled) {
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
  return sendRuntimeMessage({ version: RUNTIME_PROTOCOL_VERSION, command });
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
    browserPasskeyProxyEnabled &&
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
