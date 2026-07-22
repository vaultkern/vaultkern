import { RuntimeClient, createNegotiatedRuntimeTransport } from "@vaultkern/runtime-web-client";

import { createNativeMessagingBridge } from "./nativeBridge";
import {
  EXTENSION_SETTINGS_STORAGE_KEY,
  createChromeExtensionSettingsStore
} from "./extensionSettings";
import {
  pendingAutofillStateIsRecoveryProtected,
  pendingAutofillSubmissionFromUnknown,
  type PendingAutofillDesiredFields,
  type PendingAutofillExecutableTransaction
} from "./autofill/pendingSubmission";
import type {
  PendingAutofillTransaction,
  PendingAutofillTransactionState
} from "./autofill/pendingSubmission";
import {
  createPendingAutofillSubmissionStore
} from "./autofill/pendingSubmissionStore";
import {
  executePendingAutofillPersist
} from "./autofill/pendingMutationExecutor";
import {
  automaticFillCandidate,
  canonicalHttpOrigin,
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
const extensionSettingsStore = createChromeExtensionSettingsStore();
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
  () => globalThis.crypto.randomUUID(),
  {
    async findExactMatchingEntryIds(input: {
      vaultId: string;
      desiredFields: PendingAutofillDesiredFields;
    }) {
      if (!nativeRuntimeClient) {
        throw new Error("Native runtime is unavailable");
      }
      return nativeRuntimeClient.findExactMatchingEntryIds(
        input.vaultId,
        input.desiredFields
      );
    }
  }
);
const pendingAutofillTabUrls = new Map<number, string>();
const activePendingAutofillClaims = new Map<
  number,
  { transactionId: string; operationId: string }
>();
const activePendingAutofillOperationKeys = new Set<string>();
type PendingAutofillDeferredScopeExit =
  | { kind: "removed" }
  | { kind: "navigation"; observedUrl: string };
const pendingAutofillDeferredScopeExits = new Map<
  number,
  PendingAutofillDeferredScopeExit
>();
const activeDetachedAutofillRecoveries = new Map<
  string,
  Promise<boolean>
>();
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

function pageLoadEntryCredentials(
  response: unknown,
  expectedEntryId: string,
  pageUrl: string
) {
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "entry_detail"
  ) {
    return null;
  }

  const id = (response as { id?: unknown }).id;
  const detailUrl = (response as { url?: unknown }).url;
  const username = (response as { username?: unknown }).username;
  const password = (response as { password?: unknown }).password;
  if (
    typeof id !== "string" ||
    id.trim() === "" ||
    id !== expectedEntryId ||
    !sameExactHttpOrigin(detailUrl, pageUrl) ||
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
  const settings = await extensionSettingsStore.load();
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

function pendingAutofillRecoveryAlarmName(transactionId: string) {
  return `${PENDING_AUTOFILL_ALARM_PREFIX}recovery:${transactionId}`;
}

function tabIdFromPendingAutofillAlarmName(name: string) {
  if (!name.startsWith(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`)) {
    return undefined;
  }
  const tabId = Number.parseInt(name.slice(`${PENDING_AUTOFILL_ALARM_PREFIX}tab:`.length), 10);
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

function schedulePendingAutofillRecoveryExpiry(
  transaction: PendingAutofillTransaction
) {
  if (!("recoveryDeadlineAt" in transaction)) {
    return;
  }
  void chromeApi?.alarms?.create?.(
    pendingAutofillRecoveryAlarmName(transaction.transactionId),
    { when: transaction.recoveryDeadlineAt }
  );
}

function clearPendingAutofillRecoveryAlarm(transactionId: string) {
  void chromeApi?.alarms?.clear?.(
    pendingAutofillRecoveryAlarmName(transactionId)
  );
}

function schedulePendingAutofillExpiryForTab(
  tabId: number,
  transaction: PendingAutofillTransaction
) {
  clearPendingAutofillAlarmForTab(tabId);
  const when =
    transaction.state === "captured"
      ? transaction.expiresAt
      : "recoveryDeadlineAt" in transaction
        ? transaction.recoveryDeadlineAt
        : undefined;
  if (when === undefined) {
    return;
  }
  void chromeApi?.alarms?.create?.(pendingAutofillTabAlarmName(tabId), {
    when
  });
}

async function clearUnprotectedPendingAutofillSubmissionForTab(
  tabId: number,
  transactionId: string
) {
  const cleared = await pendingAutofillSubmissionStore.clearUnprotectedForTab(
    tabId,
    transactionId
  );
  if (!cleared) {
    return false;
  }
  pendingAutofillTabUrls.delete(tabId);
  clearPendingAutofillAlarmForTab(tabId);
  return true;
}

function deferPendingAutofillScopeExit(
  tabId: number,
  exit: PendingAutofillDeferredScopeExit
) {
  const current = pendingAutofillDeferredScopeExits.get(tabId);
  if (current?.kind === "removed") {
    return;
  }
  pendingAutofillDeferredScopeExits.set(tabId, exit);
}

async function settlePendingAutofillForRemovedTab(tabId: number) {
  const attemptedTransactionIds = new Set<string>();
  for (;;) {
    const current = await pendingAutofillSubmissionStore.loadForTab(tabId);
    if (!current) {
      pendingAutofillTabUrls.delete(tabId);
      clearPendingAutofillAlarmForTab(tabId);
      return;
    }
    if (attemptedTransactionIds.has(current.transactionId)) {
      return;
    }
    attemptedTransactionIds.add(current.transactionId);
    if (pendingAutofillStateIsRecoveryProtected(current.state)) {
      const detached = await pendingAutofillSubmissionStore.detachForRecovery(
        tabId,
        current.transactionId
      );
      if (!detached) {
        continue;
      }
      pendingAutofillTabUrls.delete(tabId);
      clearPendingAutofillAlarmForTab(tabId);
      schedulePendingAutofillRecoveryExpiry(detached);
      void beginDetachedAutofillRecovery(detached.transactionId);
      return;
    }
    if (
      await clearUnprotectedPendingAutofillSubmissionForTab(
        tabId,
        current.transactionId
      )
    ) {
      return;
    }
  }
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
    const transaction = await pendingAutofillSubmissionStore.loadForTabUrl(
      tabId,
      tabUrl
    );
    return { ok: true as const, pending: transaction };
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
  if (!loaded.ok || loaded.pending) {
    return;
  }
  const current = await pendingAutofillSubmissionStore.loadForTab(tabId);
  if (!current) {
    pendingAutofillTabUrls.delete(tabId);
    clearPendingAutofillAlarmForTab(tabId);
    return;
  }
  if (
    !pendingAutofillStateIsRecoveryProtected(current.state) ||
    canonicalHttpOrigin(authoritativeUrl) === current.origin
  ) {
    return;
  }
  if (activePendingAutofillClaims.has(tabId)) {
    deferPendingAutofillScopeExit(tabId, {
      kind: "navigation",
      observedUrl: authoritativeUrl
    });
    return;
  }
  const detached = await pendingAutofillSubmissionStore.detachForRecovery(
    tabId,
    current.transactionId
  );
  if (detached) {
    pendingAutofillTabUrls.delete(tabId);
    clearPendingAutofillAlarmForTab(tabId);
    schedulePendingAutofillRecoveryExpiry(detached);
    void beginDetachedAutofillRecovery(detached.transactionId);
  }
}

function tabIdFromMessage(message: unknown) {
  const tabId = (message as { tabId?: unknown }).tabId;
  return typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0
    ? tabId
    : undefined;
}

function pendingAutofillStateFromMessage(
  message: unknown
): PendingAutofillTransactionState | null {
  const state = (message as { state?: unknown }).state;
  switch (state) {
    case "captured":
    case "planned":
    case "persisting":
    case "persist_conflict":
    case "persisted":
    case "dismissed":
    case "expired":
      return state;
    default:
      return null;
  }
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

async function executePendingAutofillMutationInBackground(
  tabId: number,
  transactionId: string
) {
  if (!nativeRuntimeClient) {
    return { ok: false as const, error: serializeError(new Error("Native runtime is unavailable")) };
  }
  if (activePendingAutofillClaims.has(tabId)) {
    return { ok: false as const, busy: true };
  }

  activePendingAutofillClaims.set(tabId, {
    transactionId,
    operationId: ""
  });
  try {
    const loaded = await loadValidPendingAutofillSubmissionForTab(tabId);
    if (
      loaded.ok &&
      loaded.pending?.transactionId === transactionId
    ) {
      return await persistPendingAutofillTransaction(
        { kind: "tab", tabId },
        transactionId
      );
    }
    const recovery =
      await pendingAutofillSubmissionStore.loadRecovery(transactionId);
    return recovery?.tabId === tabId
      ? await persistPendingAutofillTransaction(
          { kind: "recovery", transactionId },
          transactionId
        )
      : { ok: false as const };
  } catch (error) {
    let pending: PendingAutofillTransaction | null = null;
    try {
      pending = await pendingAutofillSubmissionStore.loadForTab(tabId);
    } catch {
      // The original error remains authoritative.
    }
    return { ok: false as const, pending, error: serializeError(error) };
  } finally {
    const active = activePendingAutofillClaims.get(tabId);
    if (active?.transactionId === transactionId) {
      activePendingAutofillClaims.delete(tabId);
    }
    const deferredScopeExit = pendingAutofillDeferredScopeExits.get(tabId);
    if (deferredScopeExit) {
      pendingAutofillDeferredScopeExits.delete(tabId);
      try {
        if (deferredScopeExit.kind === "removed") {
          await settlePendingAutofillForRemovedTab(tabId);
        } else {
          await reconcilePendingAutofillNavigation(
            tabId,
            pendingAutofillTabUrls.get(tabId) ?? deferredScopeExit.observedUrl
          );
        }
      } catch {
        void reconcileOrphanedPendingAutofillTransactions();
      }
    }
  }
}

type PendingAutofillPersistLocation =
  | { kind: "tab"; tabId: number }
  | { kind: "recovery"; transactionId: string };

function pendingAutofillExpectedEntryId(
  transaction: PendingAutofillExecutableTransaction
) {
  return transaction.plan.mode === "update"
    ? transaction.plan.entryId
    : transaction.plan.plannedEntryId;
}

async function persistPendingAutofillTransaction(
  location: PendingAutofillPersistLocation,
  transactionId: string
) {
  if (!nativeRuntimeClient) {
    return {
      ok: false as const,
      error: serializeError(new Error("Native runtime is unavailable"))
    };
  }
  const claimed =
    location.kind === "tab"
      ? await pendingAutofillSubmissionStore.claimForTab(
          location.tabId,
          transactionId
        )
      : await pendingAutofillSubmissionStore.claimRecovery(transactionId);
  if (!claimed || claimed.state !== "persisting" || !("plan" in claimed)) {
    return { ok: false as const };
  }
  const operationKey = `${claimed.transactionId}:${claimed.operationId}`;
  if (activePendingAutofillOperationKeys.has(operationKey)) {
    return { ok: false as const, busy: true as const, pending: claimed };
  }
  if (location.kind === "tab") {
    activePendingAutofillClaims.set(location.tabId, {
      transactionId: claimed.transactionId,
      operationId: claimed.operationId
    });
  }
  activePendingAutofillOperationKeys.add(operationKey);
  try {
    const result = await executePendingAutofillPersist(
      nativeRuntimeClient,
      claimed
    );
    const binding = {
      transactionId: claimed.transactionId,
      operationId: claimed.operationId,
      vaultId: claimed.vaultId,
      entryId: pendingAutofillExpectedEntryId(claimed)
    };
    if (result.outcome === "conflict") {
      const pending =
        location.kind === "tab"
          ? await pendingAutofillSubmissionStore.recordConflictForTab(
              location.tabId,
              {
                ...binding,
                conflict: { code: result.code, retryable: result.retryable }
              }
            )
          : await pendingAutofillSubmissionStore.recordConflictRecovery(
              transactionId,
              {
                ...binding,
                conflict: { code: result.code, retryable: result.retryable }
              }
            );
      return {
        ok: false as const,
        conflict: true as const,
        pending
      };
    }
    const persisted =
      location.kind === "tab"
        ? await pendingAutofillSubmissionStore.completeForTab(
            location.tabId,
            binding
          )
        : await pendingAutofillSubmissionStore.completeRecovery(
            transactionId,
            binding
          );
    if (!persisted) {
      return {
        ok: false as const,
        pending: claimed,
        error: serializeError(new Error("Failed to record saved login"))
      };
    }
    if (location.kind === "tab") {
      pendingAutofillTabUrls.delete(location.tabId);
      clearPendingAutofillAlarmForTab(location.tabId);
    } else {
      clearPendingAutofillRecoveryAlarm(transactionId);
    }
    return { ok: true as const, pending: persisted };
  } catch (error) {
    const pending =
      location.kind === "tab"
        ? await pendingAutofillSubmissionStore.loadForTab(location.tabId)
        : await pendingAutofillSubmissionStore.loadRecovery(transactionId);
    return { ok: false as const, pending, error: serializeError(error) };
  } finally {
    activePendingAutofillOperationKeys.delete(operationKey);
    void pendingAutofillSubmissionStore.clearExpired(
      activePendingAutofillOperationKeys
    );
  }
}

async function planPendingAutofillTransactionFromMessage(
  tabId: number,
  transactionId: string,
  vaultId: string,
  plan: unknown
) {
  let recovery = false;
  let transaction = await pendingAutofillSubmissionStore.plan(
    tabId,
    transactionId,
    { vaultId, plan }
  );
  if (!transaction) {
    const detached = await pendingAutofillSubmissionStore.loadRecovery(
      transactionId
    );
    if (detached?.tabId === tabId) {
      transaction = await pendingAutofillSubmissionStore.planRecovery(
        transactionId,
        { vaultId, plan }
      );
      recovery = transaction !== null;
    }
  }
  if (transaction) {
    if (recovery) {
      schedulePendingAutofillRecoveryExpiry(transaction);
    } else {
      schedulePendingAutofillExpiryForTab(tabId, transaction);
    }
  }
  return transaction;
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
      const loaded = await loadValidPendingAutofillSubmissionForTab(tabId);
      if (!loaded.ok || loaded.pending) {
        sendResponse(loaded);
        return;
      }
      const recoveries = await pendingAutofillSubmissionStore.listRecoveries();
      const orderedRecoveries = [...recoveries].sort(
        (left, right) =>
          ("submittedAt" in left ? left.submittedAt : 0) -
            ("submittedAt" in right ? right.submittedAt : 0) ||
          left.transactionId.localeCompare(right.transactionId)
      );
      const recovery =
        orderedRecoveries.find(
          (transaction) =>
            transaction.tabId === tabId &&
            transaction.state === "persist_conflict"
        ) ??
        orderedRecoveries.find(
          (transaction) => transaction.state === "persist_conflict"
        ) ??
        orderedRecoveries.find((transaction) => transaction.tabId === tabId) ??
        orderedRecoveries[0] ??
        null;
      sendResponse({
        ok: true,
        pending: recovery,
        ...(recovery ? { recovery: true } : {})
      });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_status") {
    const tabId = tabIdFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null
      ) {
        sendResponse({ ok: false });
        return;
      }
      const tabTransaction =
        await pendingAutofillSubmissionStore.loadForTab(tabId);
      if (tabTransaction?.transactionId === transactionId) {
        sendResponse({ ok: true, pending: tabTransaction });
        return;
      }
      const recovery =
        await pendingAutofillSubmissionStore.loadRecovery(transactionId);
      if (recovery) {
        sendResponse({ ok: true, pending: recovery });
        return;
      }
      const completion =
        await pendingAutofillSubmissionStore.loadCompletion(transactionId);
      sendResponse({
        ok: true,
        pending: null,
        outcome: completion?.outcome ?? "unknown"
      });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_execute") {
    const tabId = tabIdFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null ||
        "operationId" in message
      ) {
        sendResponse({ ok: false });
        return;
      }
      sendResponse(
        await executePendingAutofillMutationInBackground(
          tabId,
          transactionId
        )
      );
    })().catch((error) =>
      sendResponse({ ok: false, error: serializeError(error) })
    );
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_plan") {
    const tabId = tabIdFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null ||
        typeof (message as { vaultId?: unknown }).vaultId !== "string" ||
        !("plan" in message)
      ) {
        sendResponse({ ok: false });
        return;
      }
      const transaction = await planPendingAutofillTransactionFromMessage(
        tabId,
        transactionId,
        (message as unknown as { vaultId: string }).vaultId,
        (message as { plan: unknown }).plan
      );
      sendResponse({ ok: transaction !== null, pending: transaction });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_confirm") {
    const tabId = tabIdFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null ||
        typeof (message as { vaultId?: unknown }).vaultId !== "string" ||
        !("plan" in message)
      ) {
        sendResponse({ ok: false });
        return;
      }
      const transaction = await planPendingAutofillTransactionFromMessage(
        tabId,
        transactionId,
        (message as unknown as { vaultId: string }).vaultId,
        (message as { plan: unknown }).plan
      );
      if (!transaction) {
        sendResponse({ ok: false });
        return;
      }
      sendResponse(
        await executePendingAutofillMutationInBackground(tabId, transactionId)
      );
    })().catch((error) =>
      sendResponse({ ok: false, error: serializeError(error) })
    );
    return true;
  }

  if (messageType === "vaultkern_autofill_pending_clear") {
    const tabId = tabIdFromMessage(message);
    const state = pendingAutofillStateFromMessage(message);
    const transactionId = pendingAutofillTransactionIdFromMessage(message);
    void (async () => {
      if (
        !senderIsTrustedExtensionPage(sender) ||
        tabId === undefined ||
        transactionId === null
      ) {
        sendResponse({ ok: false });
        return;
      }
      if (state !== "dismissed") {
        sendResponse({ ok: false });
        return;
      }
      let recovery = false;
      let transaction = await pendingAutofillSubmissionStore.dismissForTab(
        tabId,
        transactionId
      );
      if (!transaction) {
        const detached =
          await pendingAutofillSubmissionStore.loadRecovery(transactionId);
        if (detached?.tabId === tabId) {
          transaction =
            await pendingAutofillSubmissionStore.dismissRecovery(transactionId);
          recovery = transaction !== null;
        }
      }
      if (transaction) {
        if (recovery) {
          clearPendingAutofillRecoveryAlarm(transactionId);
        } else {
          pendingAutofillTabUrls.delete(tabId);
          clearPendingAutofillAlarmForTab(tabId);
        }
      }
      sendResponse({ ok: transaction !== null, pending: transaction });
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
      "database-settings",
      "one-drive",
      "passkey-ceremonies",
      "quick-unlock"
    ])
  : null;
nativeRuntimeClient = nativeBridge
  ? new RuntimeClient({ send: (message) => sendRuntimeMessage(message) })
  : null;
function scheduleSavedSettingsReconciliation() {
  if (chromeApi?.webAuthenticationProxy) {
    void syncWebAuthnProxy().catch((error) => {
      console.error("failed to reconcile the WebAuthn proxy", error);
    });
  }
}

function beginDetachedAutofillRecovery(transactionId: string) {
  const active = activeDetachedAutofillRecoveries.get(transactionId);
  if (active) {
    return active;
  }
  let recovery: Promise<boolean>;
  recovery = recoverDetachedAutofillTransaction(transactionId)
    .catch(() => false)
    .finally(() => {
      if (activeDetachedAutofillRecoveries.get(transactionId) === recovery) {
        activeDetachedAutofillRecoveries.delete(transactionId);
      }
    });
  activeDetachedAutofillRecoveries.set(transactionId, recovery);
  return recovery;
}

async function recoverDetachedAutofillTransaction(transactionId: string) {
  if (!nativeRuntimeClient) {
    return false;
  }
  const current =
    await pendingAutofillSubmissionStore.loadRecovery(transactionId);
  if (!current || current.state === "persist_conflict") {
    return false;
  }
  const result = await persistPendingAutofillTransaction(
    { kind: "recovery", transactionId },
    transactionId
  );
  return result.ok;
}

async function recoverAllDetachedAutofillTransactions() {
  if (!nativeRuntimeClient) {
    return;
  }
  let recoveries: PendingAutofillTransaction[];
  try {
    recoveries = await pendingAutofillSubmissionStore.listRecoveries();
  } catch {
    return;
  }
  await Promise.allSettled(
    recoveries.map((transaction) => {
      schedulePendingAutofillRecoveryExpiry(transaction);
      return beginDetachedAutofillRecovery(transaction.transactionId);
    })
  );
}

async function recoverAllAttachedAutofillTransactions() {
  if (!nativeRuntimeClient) {
    return;
  }
  let transactions: PendingAutofillTransaction[];
  try {
    transactions =
      await pendingAutofillSubmissionStore.listProtectedTabTransactions();
  } catch {
    return;
  }
  await Promise.allSettled(
    transactions.map((transaction) => {
      schedulePendingAutofillExpiryForTab(transaction.tabId, transaction);
      if (
        transaction.state === "persist_conflict" ||
        activePendingAutofillClaims.has(transaction.tabId)
      ) {
        return false;
      }
      return executePendingAutofillMutationInBackground(
        transaction.tabId,
        transaction.transactionId
      );
    })
  );
}

async function reconcileOrphanedPendingAutofillTransactions() {
  if (typeof chromeApi?.tabs?.get !== "function") {
    return;
  }
  let openTabIds: Set<number> | null = null;
  if (typeof chromeApi?.tabs?.query === "function") {
    try {
      const tabs = await chromeApi.tabs.query({});
      openTabIds = new Set(
        (Array.isArray(tabs) ? tabs : [])
          .map((tab) => tab?.id)
          .filter((tabId): tabId is number => typeof tabId === "number")
      );
    } catch {
      openTabIds = null;
    }
  }
  let transactions: PendingAutofillTransaction[];
  try {
    transactions = await pendingAutofillSubmissionStore.listTabTransactions();
  } catch {
    return;
  }
  for (const transaction of transactions) {
    let tabUrl: unknown;
    let tabExists = false;
    try {
      const tab = await chromeApi.tabs.get(transaction.tabId);
      tabExists = typeof tab?.id === "number";
      tabUrl = tab?.url;
    } catch {
      if (openTabIds === null || openTabIds.has(transaction.tabId)) {
        continue;
      }
      tabUrl = null;
    }
    if (tabExists && typeof tabUrl !== "string") {
      continue;
    }
    if (
      typeof tabUrl === "string" &&
      canonicalHttpOrigin(tabUrl) === transaction.origin
    ) {
      continue;
    }
    try {
      if (pendingAutofillStateIsRecoveryProtected(transaction.state)) {
        if (activePendingAutofillClaims.has(transaction.tabId)) {
          deferPendingAutofillScopeExit(
            transaction.tabId,
            tabExists && typeof tabUrl === "string"
              ? { kind: "navigation", observedUrl: tabUrl }
              : { kind: "removed" }
          );
          continue;
        }
        const detached = await pendingAutofillSubmissionStore.detachForRecovery(
          transaction.tabId,
          transaction.transactionId
        );
        if (detached) {
          pendingAutofillTabUrls.delete(transaction.tabId);
          clearPendingAutofillAlarmForTab(transaction.tabId);
          schedulePendingAutofillRecoveryExpiry(detached);
          void beginDetachedAutofillRecovery(detached.transactionId);
        }
      } else {
        await clearUnprotectedPendingAutofillSubmissionForTab(
          transaction.tabId,
          transaction.transactionId
        );
      }
    } catch {
      // Startup and future tab lifecycle events retry transient storage errors.
    }
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

    const settings = await extensionSettingsStore.load();
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

    const credentials = pageLoadEntryCredentials(
      await sendRuntimeCommand({
        type: "get_entry_detail",
        vault_id: vaultId,
        entry_id: candidate.id
      }),
      candidate.id,
      url
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
        (response) => {
          sendResponse(response);
          if (activeVaultIdFromSessionState(response)) {
            void recoverAllAttachedAutofillTransactions();
            void recoverAllDetachedAutofillTransactions();
          }
        },
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
  if (activePendingAutofillClaims.has(tabId)) {
    deferPendingAutofillScopeExit(tabId, { kind: "removed" });
    return;
  }
  void settlePendingAutofillForRemovedTab(tabId).catch(() => {
    void reconcileOrphanedPendingAutofillTransactions();
  });
});

chromeApi?.alarms?.onAlarm?.addListener?.((alarm: { name?: string }) => {
  if (typeof alarm.name !== "string") {
    return;
  }
  const tabId = tabIdFromPendingAutofillAlarmName(alarm.name);
  const recoveryAlarm = alarm.name.startsWith(
    `${PENDING_AUTOFILL_ALARM_PREFIX}recovery:`
  );
  if (tabId !== undefined || recoveryAlarm) {
    void pendingAutofillSubmissionStore
      .clearExpired(activePendingAutofillOperationKeys)
      .then((nextSweepAt) => {
        if (nextSweepAt !== null) {
          void chromeApi?.alarms?.create?.(alarm.name, { when: nextSweepAt });
        }
      })
      .finally(() => {
        void reconcileOrphanedPendingAutofillTransactions();
      });
  }
});

void (async () => {
  await pendingAutofillSubmissionStore.cleanupCompletedTransactions();
  await pendingAutofillSubmissionStore.clearExpired(
    activePendingAutofillOperationKeys
  );
  await reconcileOrphanedPendingAutofillTransactions();
  await Promise.allSettled([
    recoverAllAttachedAutofillTransactions(),
    recoverAllDetachedAutofillTransactions()
  ]);
})().catch(() => undefined);

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

chromeApi?.storage?.onChanged?.addListener?.(
  (changes: Record<string, unknown>, areaName: string) => {
    if (areaName !== "local" || !(EXTENSION_SETTINGS_STORAGE_KEY in changes)) {
      return;
    }
    scheduleSavedSettingsReconciliation();
  }
);

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
    if (isSuccessfulVaultUnlock(message, response)) {
      scheduleSavedSettingsReconciliation();
    }
    return response;
  } catch (error) {
    stopNativeKeepAlive();
    throw error;
  }
}

function isSuccessfulVaultUnlock(message: unknown, response: unknown) {
  const commandType = (
    message as { command?: { type?: unknown } } | null
  )?.command?.type;
  return (
    (commandType === "unlock_current_vault" ||
      commandType === "unlock_current_vault_with_password" ||
      commandType === "unlock_current_vault_with_quick_unlock" ||
      commandType === "unlock_vault" ||
      commandType === "unlock_with_password") &&
    sessionStateFromResponse(response)?.unlocked === true
  );
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
