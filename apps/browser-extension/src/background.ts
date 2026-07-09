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
let pendingAutofillSubmissionsByTab = new Map<number, PendingAutofillSubmission>();
let pendingAutofillTabUrls = new Map<number, string>();
let pendingAutofillExpiryTimersByTab = new Map<number, ReturnType<typeof setTimeout>>();
let pendingAutofillGlobalExpiryTimer: ReturnType<typeof setTimeout> | null = null;
const NATIVE_KEEP_ALIVE_INTERVAL_MS = 20_000;
const PENDING_AUTOFILL_NAVIGATION_GRACE_MS = 2 * 60 * 1000;
const PENDING_AUTOFILL_ALARM_PREFIX = "vaultkern-autofill-pending:";
const PENDING_AUTOFILL_GLOBAL_ALARM = `${PENDING_AUTOFILL_ALARM_PREFIX}global`;
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

function hostFromUrl(url: string | undefined) {
  if (typeof url !== "string" || url.trim() === "") {
    return undefined;
  }
  try {
    const host = new URL(url).host;
    return host === "" ? null : host;
  } catch {
    return null;
  }
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

function singleFillCandidateId(response: unknown) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "fill_candidates" ||
    !Array.isArray((response as { entries?: unknown }).entries)
  ) {
    return null;
  }

  const entries = (response as { entries: unknown[] }).entries;
  if (entries.length !== 1) {
    return null;
  }

  const [entry] = entries;
  return typeof entry === "object" &&
    entry !== null &&
    typeof (entry as { id?: unknown }).id === "string"
    ? (entry as { id: string }).id
    : null;
}

function pageLoadEntryCredentials(response: unknown) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "entry_detail"
  ) {
    return null;
  }

  const username = (response as { username?: unknown }).username;
  const password = (response as { password?: unknown }).password;
  if (
    typeof username !== "string" ||
    username.trim() === "" ||
    typeof password !== "string" ||
    password === ""
  ) {
    return null;
  }

  return { username, password };
}

async function currentPageLoadAutofillUrl(tabId: number) {
  if (!chromeApi?.tabs?.get) {
    return null;
  }
  const tab = await chromeApi.tabs.get(tabId);
  return pageLoadAutofillUrl(tab?.url);
}

function pendingAutofillSubmissionIsExpired(
  submission: PendingAutofillSubmission,
  now = Date.now()
) {
  return now - submission.submittedAt > PENDING_AUTOFILL_NAVIGATION_GRACE_MS;
}

function pendingAutofillExpiryTime(submission: PendingAutofillSubmission) {
  return submission.submittedAt + PENDING_AUTOFILL_NAVIGATION_GRACE_MS + 1;
}

function pendingAutofillTabAlarmName(tabId: number) {
  return `${PENDING_AUTOFILL_ALARM_PREFIX}tab:${tabId}`;
}

function tabIdFromPendingAutofillAlarmName(name: string) {
  if (!name.startsWith(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`)) {
    return undefined;
  }
  const tabId = Number.parseInt(name.slice(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`.length), 10);
  return Number.isInteger(tabId) && tabId >= 0 ? tabId : undefined;
}

function pendingAutofillSubmissionMatchesUrl(
  submission: PendingAutofillSubmission,
  tabUrl: string | undefined
) {
  const tabHost = hostFromUrl(tabUrl);
  if (tabHost === undefined) {
    return true;
  }
  const submissionHost = hostFromUrl(submission.url);
  return submissionHost !== undefined && submissionHost !== null && submissionHost === tabHost;
}

function trackPendingAutofillTabUrl(tabId: number, tabUrl: string | undefined) {
  if (typeof tabUrl === "string" && tabUrl.trim() !== "") {
    pendingAutofillTabUrls.set(tabId, tabUrl);
  }
}

function clearPendingAutofillExpiryForTab(tabId: number) {
  const timer = pendingAutofillExpiryTimersByTab.get(tabId);
  if (timer) {
    clearTimeout(timer);
  }
  pendingAutofillExpiryTimersByTab.delete(tabId);
  void chromeApi?.alarms?.clear?.(pendingAutofillTabAlarmName(tabId));
}

function clearGlobalPendingAutofillExpiry() {
  if (pendingAutofillGlobalExpiryTimer) {
    clearTimeout(pendingAutofillGlobalExpiryTimer);
    pendingAutofillGlobalExpiryTimer = null;
  }
  void chromeApi?.alarms?.clear?.(PENDING_AUTOFILL_GLOBAL_ALARM);
}

function schedulePendingAutofillExpiryForTab(
  tabId: number,
  submission: PendingAutofillSubmission
) {
  clearPendingAutofillExpiryForTab(tabId);
  const when = pendingAutofillExpiryTime(submission);
  const timer = setTimeout(() => {
    pendingAutofillExpiryTimersByTab.delete(tabId);
    clearInvalidPendingAutofillSubmissionForTab(
      tabId,
      pendingAutofillTabUrls.get(tabId)
    );
  }, Math.max(0, when - Date.now()));
  (timer as { unref?: () => void }).unref?.();
  pendingAutofillExpiryTimersByTab.set(tabId, timer);
  void chromeApi?.alarms?.create?.(pendingAutofillTabAlarmName(tabId), { when });
}

function scheduleGlobalPendingAutofillExpiry(submission: PendingAutofillSubmission) {
  clearGlobalPendingAutofillExpiry();
  const when = pendingAutofillExpiryTime(submission);
  pendingAutofillGlobalExpiryTimer = setTimeout(() => {
    pendingAutofillGlobalExpiryTimer = null;
    clearExpiredGlobalPendingAutofillSubmission();
  }, Math.max(0, when - Date.now()));
  (pendingAutofillGlobalExpiryTimer as { unref?: () => void }).unref?.();
  void chromeApi?.alarms?.create?.(PENDING_AUTOFILL_GLOBAL_ALARM, { when });
}

function clearAllPendingAutofillExpiry() {
  for (const tabId of pendingAutofillExpiryTimersByTab.keys()) {
    clearPendingAutofillExpiryForTab(tabId);
  }
  clearGlobalPendingAutofillExpiry();
}

function recomputeLatestPendingAutofillSubmission(now = Date.now()) {
  if (
    pendingAutofillSubmission &&
    pendingAutofillSubmissionIsExpired(pendingAutofillSubmission, now)
  ) {
    pendingAutofillSubmission = null;
  }

  for (const [tabId, submission] of pendingAutofillSubmissionsByTab.entries()) {
    if (pendingAutofillSubmissionIsExpired(submission, now)) {
      pendingAutofillSubmissionsByTab.delete(tabId);
      pendingAutofillTabUrls.delete(tabId);
      clearPendingAutofillExpiryForTab(tabId);
    }
  }

  pendingAutofillSubmission = Array.from(pendingAutofillSubmissionsByTab.values()).reduce(
    newerPendingAutofillSubmission,
    pendingAutofillSubmission
  );
}

function clearPendingAutofillSubmissionForTab(tabId: number) {
  const clearedSubmission = pendingAutofillSubmissionsByTab.get(tabId) ?? null;
  pendingAutofillSubmissionsByTab.delete(tabId);
  pendingAutofillTabUrls.delete(tabId);
  clearPendingAutofillExpiryForTab(tabId);
  if (!clearedSubmission) {
    return;
  }
  if (pendingAutofillSubmission === clearedSubmission) {
    pendingAutofillSubmission = null;
  }
  recomputeLatestPendingAutofillSubmission();
}

function clearExpiredGlobalPendingAutofillSubmission(now = Date.now()) {
  if (
    pendingAutofillSubmission &&
    pendingAutofillSubmissionIsExpired(pendingAutofillSubmission, now)
  ) {
    pendingAutofillSubmission = null;
    clearGlobalPendingAutofillExpiry();
  }
  recomputeLatestPendingAutofillSubmission(now);
}

function clearInvalidPendingAutofillSubmissionForTab(
  tabId: number,
  tabUrl: string | undefined,
  now = Date.now()
) {
  const pendingSubmission = pendingAutofillSubmissionsByTab.get(tabId) ?? null;
  if (!pendingSubmission) {
    return;
  }
  if (
    pendingAutofillSubmissionIsExpired(pendingSubmission, now) ||
    !pendingAutofillSubmissionMatchesUrl(
      pendingSubmission,
      tabUrl ?? pendingAutofillTabUrls.get(tabId)
    )
  ) {
    clearPendingAutofillSubmissionForTab(tabId);
  }
}

function tabIdFromMessage(message: unknown) {
  const tabId = (message as { tabId?: unknown }).tabId;
  return typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0
    ? tabId
    : undefined;
}

function tabUrlFromMessage(message: unknown) {
  const tabUrl = (message as { tabUrl?: unknown }).tabUrl;
  return typeof tabUrl === "string" && tabUrl.trim() !== "" ? tabUrl : undefined;
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
    pendingAutofillSubmission = pendingAutofillSubmissionFromUnknown(message);
    const tabId = tabIdFromSender(sender) ?? tabIdFromMessage(message);
    if (pendingAutofillSubmission && tabId !== undefined) {
      pendingAutofillSubmissionsByTab.set(tabId, pendingAutofillSubmission);
      trackPendingAutofillTabUrl(
        tabId,
        tabUrlFromSender(sender) ?? tabUrlFromMessage(message) ?? pendingAutofillSubmission.url
      );
      clearGlobalPendingAutofillExpiry();
      schedulePendingAutofillExpiryForTab(tabId, pendingAutofillSubmission);
    } else if (pendingAutofillSubmission) {
      scheduleGlobalPendingAutofillExpiry(pendingAutofillSubmission);
    }
    sendResponse({ ok: pendingAutofillSubmission !== null });
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_request") {
    const tabId = tabIdFromMessage(message);
    const tabUrl = tabUrlFromMessage(message);
    if (tabId !== undefined) {
      trackPendingAutofillTabUrl(tabId, tabUrl);
      clearInvalidPendingAutofillSubmissionForTab(tabId, tabUrl);
    } else {
      recomputeLatestPendingAutofillSubmission();
    }
    sendResponse({
      pending:
        tabId === undefined
          ? pendingAutofillSubmission
          : pendingAutofillSubmissionsByTab.get(tabId) ?? null
    });
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_clear") {
    const tabId = tabIdFromMessage(message);
    if (tabId === undefined) {
      pendingAutofillSubmission = null;
      pendingAutofillSubmissionsByTab = new Map();
      pendingAutofillTabUrls = new Map();
      clearAllPendingAutofillExpiry();
    } else {
      clearPendingAutofillSubmissionForTab(tabId);
    }
    sendResponse({ ok: true });
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

async function maybeSendPageLoadAutofill(tabId: number, tabUrl: string | undefined) {
  const url = pageLoadAutofillUrl(tabUrl);
  if (!url || !nativeBridge || !chromeApi?.tabs?.sendMessage) {
    return;
  }

  try {
    const settings = await extensionSettingsStore.load();
    if (!settings.autofillOnPageLoadEnabled) {
      return;
    }

    const vaultId = activeVaultIdFromSessionState(
      await sendRuntimeCommand({ type: "get_session_state" })
    );
    if (!vaultId) {
      return;
    }

    const entryId = singleFillCandidateId(
      await sendRuntimeCommand({
        type: "find_fill_candidates",
        vault_id: vaultId,
        url
      })
    );
    if (!entryId) {
      return;
    }

    const credentials = pageLoadEntryCredentials(
      await sendRuntimeCommand({
        type: "get_entry_detail",
        vault_id: vaultId,
        entry_id: entryId
      })
    );
    if (!credentials) {
      return;
    }

    const currentUrl = await currentPageLoadAutofillUrl(tabId);
    if (currentUrl !== url) {
      return;
    }

    await chromeApi.tabs.sendMessage(tabId, {
      type: "fill_entry_detail",
      trigger: "pageLoad",
      allowAutomaticSecretFill: true,
      targetUrl: url,
      username: credentials.username,
      password: credentials.password
    });
  } catch {
    // Page-load autofill is opportunistic; popup/manual fill remains the reliable path.
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

chromeApi?.tabs?.onUpdated?.addListener?.(
  (
    tabId: number,
    changeInfo: { status?: string; url?: string },
    tab?: { url?: string }
  ) => {
    if (typeof changeInfo.url === "string" && changeInfo.url.trim() !== "") {
      trackPendingAutofillTabUrl(tabId, changeInfo.url);
      clearInvalidPendingAutofillSubmissionForTab(tabId, changeInfo.url);
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
  clearPendingAutofillSubmissionForTab(tabId);
});

chromeApi?.alarms?.onAlarm?.addListener?.((alarm: { name?: string }) => {
  if (alarm.name === PENDING_AUTOFILL_GLOBAL_ALARM) {
    clearExpiredGlobalPendingAutofillSubmission();
    return;
  }

  if (typeof alarm.name !== "string") {
    return;
  }
  const tabId = tabIdFromPendingAutofillAlarmName(alarm.name);
  if (tabId !== undefined) {
    clearInvalidPendingAutofillSubmissionForTab(tabId, pendingAutofillTabUrls.get(tabId));
  }
});

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
