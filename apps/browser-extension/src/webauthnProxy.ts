import passkeyCeremonyTransitions from "../../../tools/vaultkern-runtime/src/passkey_ceremony_transitions.json";
import psl from "psl";

export type WebAuthnProxyStatus =
  | { status: "unsupported" }
  | { status: "attached" }
  | { status: "detached" }
  | { status: "error"; message: string };

type RuntimeCommandSender = (command: Record<string, unknown>) => Promise<unknown>;

type ChromeLike = {
  runtime?: {
    lastError?: { message?: string };
    getURL?: (path: string) => string;
    onMessage?: {
      addListener?: (
        listener: (
          message: unknown,
          sender: unknown,
          sendResponse: unknown
        ) => boolean | void
      ) => void;
    };
  };
  storage?: {
    local?: {
      get?: (keys?: unknown) => Promise<Record<string, unknown>>;
      set?: (items: Record<string, unknown>) => Promise<void>;
    };
    session?: {
      get?: (keys?: unknown) => Promise<Record<string, unknown>>;
      set?: (items: Record<string, unknown>) => Promise<void>;
      remove?: (keys: unknown) => Promise<void>;
      setAccessLevel?: (accessOptions: {
        accessLevel: "TRUSTED_CONTEXTS";
      }) => Promise<void>;
    };
  };
  tabs?: {
    query?: (queryInfo: Record<string, unknown>) => Promise<Array<{ url?: string }>>;
  };
  windows?: {
    create?: (createData: Record<string, unknown>) => Promise<{ id?: number }> | void;
    update?: (windowId: number, updateInfo: Record<string, unknown>) => Promise<unknown> | void;
    remove?: (windowId: number) => Promise<unknown> | void;
    onRemoved?: {
      addListener?: (listener: (windowId: number) => void) => void;
      removeListener?: (listener: (windowId: number) => void) => void;
    };
  };
  webAuthenticationProxy?: {
    attach?: () => Promise<string | undefined> | string | undefined;
    detach?: () => Promise<string | undefined> | string | undefined;
    completeGetRequest?: (details: unknown) => Promise<void> | void;
    completeCreateRequest?: (details: unknown) => Promise<void> | void;
    completeIsUvpaaRequest?: (details: unknown) => Promise<void> | void;
    onIsUvpaaRequest?: {
      addListener?: (listener: (request: unknown) => void) => void;
    };
    onGetRequest?: {
      addListener?: (listener: (request: unknown) => void) => void;
    };
    onCreateRequest?: {
      addListener?: (listener: (request: unknown) => void) => void;
    };
    onRequestCanceled?: {
      addListener?: (listener: (request: unknown) => void) => void;
    };
  };
};

type WebAuthnOriginContext = {
  origin: string;
  topOrigin?: string;
  ancestorOrigins: string[];
  mediation?: string;
  trustedFrame?: { tabId: number; frameId: number };
};

type WebAuthnPromptContext = WebAuthnOriginContext & {
  relyingParty: string;
  credentialOptions?: PasskeyCredentialOption[];
};

type WebAuthnUserVerificationPromptContext = WebAuthnPromptContext & {
  ceremonyToken: string;
  activeVaultId: string;
};

type PasskeyCeremonyPhase =
  | "s0_pre_authorization"
  | "s1_user_authorization"
  | "s2_network_validation"
  | "s3_credential_resolution"
  | "s3b_user_selection"
  | "s4_completion_and_mutation"
  | "closed_aborted"
  | "closed_delivered"
  | "closed_failed";

type PasskeyCeremonyActivePhase = Exclude<
  PasskeyCeremonyPhase,
  "closed_aborted" | "closed_delivered" | "closed_failed"
>;

type PasskeyCeremonyTransitionContract = {
  active_phases: PasskeyCeremonyActivePhase[];
  active_edges: Array<
    readonly [PasskeyCeremonyActivePhase, PasskeyCeremonyActivePhase]
  >;
};

type PasskeyUserVerificationRequirement =
  | "discouraged"
  | "preferred"
  | "required";

type PasskeyUserVerificationMethod = "master_password" | "quick_unlock";

type UnlockUserVerificationProof = {
  method: PasskeyUserVerificationMethod;
  password?: string;
};

type PasskeyCeremonyBaseContext = {
  version: 1;
  ceremonyToken: string;
  phase: PasskeyCeremonyPhase;
  origin: string;
  topOrigin?: string;
  ancestorOrigins: string[];
  relyingParty: string;
  ceremony: "get" | "create";
  userVerification: PasskeyUserVerificationRequirement;
  challengeBase64url: string;
  requestId: number;
  tabId: number;
  frameId: number;
  frameKind: "top" | "subframe";
  relatedOriginVerified?: boolean;
  activeVaultId?: string;
  popupNonce?: string;
  promptMode?: "approve" | "unlock" | "verify";
  promptWindowId?: number;
  promptCredentialOptions?: PasskeyCredentialOption[];
  registeredAtEpochMs: number;
  expiresAtEpochMs: number;
};

type PasskeyGetCeremonyContext = PasskeyCeremonyBaseContext & {
  ceremony: "get";
  getCredentialIds: Array<string | null>;
  getClientExtensionResults: Record<string, unknown>;
};

type PasskeyCreateCeremonyContext = PasskeyCeremonyBaseContext & {
  ceremony: "create";
  createUserName: string;
  createUserDisplayName: string | null;
  createUserHandleBase64url: string;
  createPublicKeyAlgorithm: number;
  createExcludeCredentialIds: string[];
  createClientExtensionResults: Record<string, unknown>;
};

type PasskeyCeremonyContext =
  | PasskeyGetCeremonyContext
  | PasskeyCreateCeremonyContext;

type PasskeyCeremonyMirrorEnvelope = {
  version: 1;
  ceremonies: Record<string, PasskeyCeremonyContext>;
  checksum: string;
};

type PasskeyCredentialOption = {
  credentialId: string;
  username: string;
};

type PasskeyCredentialListItem = PasskeyCredentialOption & {
  userHandle: string | null;
};

type PasskeyPromptMirrorPersistence = {
  persistPresencePromptState: (
    nonce: string,
    credentialOptions?: PasskeyCredentialOption[]
  ) => Promise<void>;
  persistUnlockPromptState: (nonce: string) => Promise<void>;
  persistUserVerificationPromptState: (nonce: string) => Promise<void>;
  persistPromptWindowId: (windowId: number) => Promise<void>;
};

type UnlockCompleteSignal = {
  userVerificationProof?: UnlockUserVerificationProof;
};

type PresenceCompleteSignal = {
  credentialId?: string;
};

type UserVerificationCompleteSignal = {
  method: PasskeyUserVerificationMethod;
};

type PromptSignal<TCompleteSignal> =
  | { type: "complete"; signal: TCompleteSignal }
  | { type: "dismissed" }
  | null;

type PromptOpenResult = {
  nonce: string;
  windowId?: number;
};

type WebAuthnPromptMode = "unlock" | "approve" | "verify";

type PromptClearOptions = {
  preserveDismissed?: boolean;
};

type PromptClearState = (
  promptKey: string,
  options?: PromptClearOptions
) => void;

type PromptWindowConfig = {
  mode: WebAuthnPromptMode;
  unavailableMessage: string;
  dismissedDebugEvent: string;
  width: number;
  height: number;
};

type CanceledWebAuthnRequests = {
  legacyRequestIds: Set<number>;
  requestKeys: Set<string>;
};

type PromptState<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
> = {
  windowIds: Map<string, number>;
  activeDrivers: Set<string>;
  dismissedPromptKeys: Set<string>;
  pendingCompleteSignals: Map<string, TCompleteSignal>;
  completeWaiters: Map<string, Set<(signal: TCompleteSignal) => void>>;
  dismissWaiters: Map<string, Set<() => void>>;
  contexts: Map<string, TContext>;
  nonces: Map<string, string>;
  requestIds: Map<string, number>;
  requestKeys: Map<string, string>;
  removalCleanups: Map<string, () => void>;
};

type PromptStateRegistry = {
  unlock: PromptState<WebAuthnPromptContext, UnlockCompleteSignal>;
  approve: PromptState<WebAuthnPromptContext, PresenceCompleteSignal>;
  verify: PromptState<
    WebAuthnUserVerificationPromptContext,
    UserVerificationCompleteSignal
  >;
};

function createPromptState<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(): PromptState<TContext, TCompleteSignal> {
  return {
    windowIds: new Map<string, number>(),
    activeDrivers: new Set<string>(),
    dismissedPromptKeys: new Set<string>(),
    pendingCompleteSignals: new Map<string, TCompleteSignal>(),
    completeWaiters: new Map<string, Set<(signal: TCompleteSignal) => void>>(),
    dismissWaiters: new Map<string, Set<() => void>>(),
    contexts: new Map<string, TContext>(),
    nonces: new Map<string, string>(),
    requestIds: new Map<string, number>(),
    requestKeys: new Map<string, string>(),
    removalCleanups: new Map<string, () => void>()
  };
}

function createPromptStateRegistry(): PromptStateRegistry {
  return {
    unlock: createPromptState<WebAuthnPromptContext, UnlockCompleteSignal>(),
    approve: createPromptState<WebAuthnPromptContext, PresenceCompleteSignal>(),
    verify: createPromptState<
      WebAuthnUserVerificationPromptContext,
      UserVerificationCompleteSignal
    >()
  };
}

const promptStates = createPromptStateRegistry();

const PROMPT_WINDOW_CONFIGS: Record<WebAuthnPromptMode, PromptWindowConfig> = {
  unlock: {
    mode: "unlock",
    unavailableMessage:
      "VaultKern vault is locked and no unlock window is available",
    dismissedDebugEvent: "unlock_prompt_dismissed",
    width: 460,
    height: 620
  },
  approve: {
    mode: "approve",
    unavailableMessage: "VaultKern passkey approval window is unavailable",
    dismissedDebugEvent: "presence_prompt_dismissed",
    width: 460,
    height: 360
  },
  verify: {
    mode: "verify",
    unavailableMessage:
      "VaultKern passkey user verification window is unavailable",
    dismissedDebugEvent: "user_verification_prompt_dismissed",
    width: 460,
    height: 520
  }
};

const knownPasskeyCeremonyTokens = new Set<string>();
const knownPasskeyCeremonyTokenQueue: string[] = [];
const observedPageRequests: ObservedWebAuthnPageRequest[] = [];
const registeredUnlockMessageSources = new WeakSet<object>();
const registeredRequestHandlerSources = new WeakSet<object>();
const trustedPasskeyCeremonySessionStorage = new WeakSet<object>();
const OBSERVED_PAGE_REQUEST_MAX_AGE_MS = 120_000;
const OBSERVED_PAGE_REQUEST_WAIT_MS = 100;
const OBSERVED_PAGE_REQUEST_POLL_MS = 5;
const WEB_AUTHN_DEBUG_STORAGE_KEY = "vaultkernWebAuthnDebug";
const WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY = "vaultkernWebAuthnDebugEnabled";
const PASSKEY_CEREMONY_SESSION_STORAGE_KEY = "vaultkernPasskeyCeremonies";
const PASSKEY_CEREMONY_MIRROR_ENVELOPE_VERSION = 1;
const PASSKEY_CEREMONY_MIRROR_CHECKSUM_PREFIX = "passkey-ceremonies-v1:";
const PASSKEY_CEREMONY_PHASES = new Set<PasskeyCeremonyPhase>([
  "s0_pre_authorization",
  "s1_user_authorization",
  "s2_network_validation",
  "s3_credential_resolution",
  "s3b_user_selection",
  "s4_completion_and_mutation",
  "closed_aborted",
  "closed_delivered",
  "closed_failed"
]);
const PASSKEY_CEREMONY_TRANSITION_CONTRACT =
  passkeyCeremonyTransitions as PasskeyCeremonyTransitionContract;
const PASSKEY_CEREMONY_ACTIVE_PHASES =
  PASSKEY_CEREMONY_TRANSITION_CONTRACT.active_phases;
const PASSKEY_CEREMONY_TRANSITION_EDGES =
  PASSKEY_CEREMONY_TRANSITION_CONTRACT.active_edges;
const RELATED_ORIGIN_LABEL_LIMIT = 5;
const RELATED_ORIGIN_FETCH_TIMEOUT_MS = 5_000;
const GENERIC_PASSKEY_REQUEST_ERROR_MESSAGE = "VaultKern passkey request failed";
const PASSKEY_PUBLIC_ERROR_MIN_DELAY_MS = 75;
const MAX_KNOWN_PASSKEY_CEREMONY_TOKENS = 512;
const WEB_AUTHN_DEBUG_DISABLED_CACHE_MS = 1_000;
const webAuthnDebugWriteChains = new WeakMap<object, Promise<void>>();
let passkeyCeremonyMirrorCache = new WeakMap<
  object,
  Record<string, PasskeyCeremonyContext>
>();
const webAuthnDebugDisabledUntil = new WeakMap<object, number>();
let passkeyCeremonyMirrorMutationQueue: Promise<void> = Promise.resolve();
let passkeyLedgerConnectionId: string | null = null;

type ObservedWebAuthnPageRequest = {
  ceremony: "create" | "get";
  origin: string;
  topOrigin?: string;
  ancestorOrigins: string[];
  trustedSenderTabId?: number;
  trustedSenderFrameId?: number;
  relyingParty?: string;
  challenge?: string;
  allowCredentialIds?: string[];
  excludeCredentialIds?: string[];
  mediation?: string;
  observedAt: number;
};

export function webAuthnProxyAvailable(chromeApi: unknown): chromeApi is ChromeLike {
  const candidate = chromeApi as ChromeLike | null | undefined;
  return typeof candidate?.webAuthenticationProxy?.attach === "function";
}

export async function attachWebAuthnProxy(
  chromeApi: unknown,
  options?: { sendRuntimeCommand?: RuntimeCommandSender }
): Promise<WebAuthnProxyStatus> {
  if (!webAuthnProxyAvailable(chromeApi)) {
    void recordWebAuthnDebug(chromeApi as ChromeLike, {
      event: "attach_unsupported"
    });
    return { status: "unsupported" };
  }

  if (options?.sendRuntimeCommand) {
    registerRequestHandlers(chromeApi, options.sendRuntimeCommand);
  }

  try {
    const message = await chromeApi.webAuthenticationProxy.attach?.();
    await recordWebAuthnDebug(chromeApi, {
      event: message ? "attach_error" : "attach_success",
      message
    });
    return message ? { status: "error", message } : { status: "attached" };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "failed to attach WebAuthn proxy";
    await recordWebAuthnDebug(chromeApi, {
      event: "attach_error",
      message
    });
    return { status: "error", message };
  }
}

export async function detachWebAuthnProxy(
  chromeApi: unknown
): Promise<WebAuthnProxyStatus> {
  const candidate = chromeApi as ChromeLike | null | undefined;
  if (typeof candidate?.webAuthenticationProxy?.detach !== "function") {
    return { status: "unsupported" };
  }

  try {
    const message = await candidate.webAuthenticationProxy.detach();
    return message ? { status: "error", message } : { status: "detached" };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "failed to detach WebAuthn proxy";
    return { status: "error", message };
  }
}

export async function reconcilePersistedPasskeyCeremonies(
  chromeApi: unknown,
  sendRuntimeCommand: RuntimeCommandSender
) {
  const candidate = chromeApi as ChromeLike | null | undefined;
  await enqueuePasskeyCeremonyMirrorMutation(async () => {
    const mirrors = await loadPasskeyCeremonyMirrors(candidate);
    let changed = false;
    const now = Date.now();

    for (const [token, mirror] of Object.entries(mirrors)) {
      if (!isPasskeyCeremonyMirror(mirror) || mirror.expiresAtEpochMs <= now) {
        delete mirrors[token];
        changed = true;
        continue;
      }

      let ledger: unknown;
      try {
        ledger = await sendRuntimeCommand({
          type: "query_passkey_ceremony_ledger",
          ceremony_token: token
        });
      } catch {
        continue;
      }

      if (!passkeyCeremonyLedgerKnown(ledger)) {
        if (runtimeErrorFromResponse(ledger)) {
          continue;
        }
        if (!passkeyCeremonyLedgerUnknown(ledger)) {
          delete mirrors[token];
          changed = true;
          continue;
        }
        if (isCompletionOrLaterPhase(mirror.phase)) {
          delete mirrors[token];
          changed = true;
          continue;
        }
        if (!passkeyCeremonyReplayTransitions(mirror)) {
          delete mirrors[token];
          changed = true;
          continue;
        }

        let response: unknown;
        try {
          response = await sendRuntimeCommand({
            type: "register_passkey_ceremony",
            ceremony_token: mirror.ceremonyToken,
            connection_id: currentPasskeyLedgerConnectionId(),
            origin: mirror.origin,
            top_origin: mirror.topOrigin,
            ancestor_origins: mirror.ancestorOrigins,
            relying_party: mirror.relyingParty,
            ceremony: mirror.ceremony,
            discoverable:
              mirror.ceremony === "get" &&
              passkeyGetCredentialIdsAreDiscoverable(mirror.getCredentialIds),
            user_verification: mirror.userVerification,
            challenge_base64url: mirror.challengeBase64url,
            request_id: mirror.requestId,
            tab_id: mirror.tabId,
            frame_id: mirror.frameId,
            frame_kind: mirror.frameKind,
            registered_at_epoch_ms: mirror.registeredAtEpochMs,
            expires_at_epoch_ms: mirror.expiresAtEpochMs
          });
        } catch {
          delete mirrors[token];
          changed = true;
          continue;
        }
        try {
          requireRuntimeResponseType(
            response,
            "passkey_ceremony_registered",
            "passkey ceremony re-registration did not return success",
            "registered"
          );
        } catch {
          delete mirrors[token];
          changed = true;
          continue;
        }
        const replay = await replayPasskeyCeremonyMirrorPhase(
          sendRuntimeCommand,
          mirror
        );
        if (replay.replayedPhase) {
          const restoredMirror = {
            ...mirror,
            phase: replay.replayedPhase
          };
          mirrors[token] = restoredMirror;
          restorePasskeyCeremonyPromptState(
            chromeApi,
            sendRuntimeCommand,
            restoredMirror
          );
        } else {
          if (replay.lastNativePhase) {
            await closePersistedNativePasskeyCeremony(
              sendRuntimeCommand,
              token,
              replay.lastNativePhase
            );
          }
          delete mirrors[token];
        }
        changed = true;
        continue;
      }

      const ledgerPhase = passkeyCeremonyLedgerPhase(ledger);
      if (!ledgerPhase) {
        delete mirrors[token];
        changed = true;
        continue;
      }
      if (ledgerPhase === "s4_completion_and_mutation") {
        const deliveryState = passkeyCeremonyLedgerDeliveryState(ledger);
        if (mirror.ceremony === "get") {
          if (!passkeyCeremonyLedgerDeliveryIsClosed(deliveryState)) {
            const marked = await markPasskeyCeremonyUnknownDelivery(sendRuntimeCommand, token);
            if (!marked) {
              continue;
            }
          }
        } else {
          const durableState = passkeyCeremonyLedgerDurableState(ledger);
          if (durableState === "committed") {
            if (!passkeyCeremonyLedgerDeliveryIsClosed(deliveryState)) {
              const marked = await markPasskeyCeremonyUnknownDelivery(
                sendRuntimeCommand,
                token
              );
              if (!marked) {
                continue;
              }
            }
          } else {
            const aborted = await abortPasskeyRegistration(
              sendRuntimeCommand,
              token,
              "closed_failed"
            );
            if (!aborted) {
              continue;
            }
          }
        }
        delete mirrors[token];
        changed = true;
        continue;
      }
      if (ledgerPhase.startsWith("closed_")) {
        delete mirrors[token];
        changed = true;
      } else if (ledgerPhase === mirror.phase) {
        restorePasskeyCeremonyPromptState(chromeApi, sendRuntimeCommand, mirror);
        continue;
      } else if (passkeyCeremonyCanAdvanceMirrorPhase(mirror, ledgerPhase)) {
        const advancedMirror = passkeyCeremonyMirrorForPhase(
          { ...mirror, phase: ledgerPhase as PasskeyCeremonyPhase },
          ledgerPhase as PasskeyCeremonyPhase
        );
        if (isPasskeyCeremonyMirror(advancedMirror)) {
          mirrors[token] = advancedMirror;
        } else {
          await closePersistedNativePasskeyCeremony(
            sendRuntimeCommand,
            token,
            ledgerPhase
          );
          delete mirrors[token];
        }
        changed = true;
      } else {
        await closePersistedNativePasskeyCeremony(
          sendRuntimeCommand,
          token,
          ledgerPhase
        );
        delete mirrors[token];
        changed = true;
      }
    }

    if (changed) {
      await storePasskeyCeremonyMirrors(candidate, mirrors);
    }
  });
}

export function registerWebAuthnProxyRequestHandlers(
  chromeApi: unknown,
  sendRuntimeCommand: RuntimeCommandSender
) {
  const candidate = chromeApi as ChromeLike | null | undefined;
  if (!candidate?.webAuthenticationProxy) {
    return;
  }

  registerRequestHandlers(candidate, sendRuntimeCommand);
}

export function recordWebAuthnPageRequest(
  message: unknown,
  chromeApi?: ChromeLike,
  sender?: unknown
) {
  if (typeof message !== "object" || message === null) {
    return false;
  }

  const candidate = message as {
    ceremony?: unknown;
    origin?: unknown;
    topOrigin?: unknown;
    ancestorOrigins?: unknown;
    relyingParty?: unknown;
    challenge?: unknown;
    allowCredentialIds?: unknown;
    excludeCredentialIds?: unknown;
    mediation?: unknown;
  };
  if (candidate.ceremony !== "create" && candidate.ceremony !== "get") {
    return false;
  }
  const senderContext = trustedWebAuthnMessageSenderContextFrom(sender);
  const origin = senderContext?.origin ?? originFromUnknown(candidate.origin);
  if (!origin) {
    return false;
  }
  const ancestorOrigins = originsArrayFromUnknown(candidate.ancestorOrigins);
  if (!ancestorOrigins) {
    return false;
  }
  const explicitTopOrigin = optionalOriginFromUnknown(candidate.topOrigin);
  if (explicitTopOrigin === null) {
    return false;
  }
  const topOrigin =
    ancestorOrigins[ancestorOrigins.length - 1] ??
    explicitTopOrigin ??
    undefined;
  let relyingParty: string | undefined;
  if (candidate.relyingParty !== undefined && candidate.relyingParty !== null) {
    if (typeof candidate.relyingParty !== "string") {
      return false;
    }
    try {
      relyingParty = normalizeExplicitRelyingPartyId(candidate.relyingParty);
    } catch {
      return false;
    }
  }

  pruneObservedPageRequests(Date.now());
  observedPageRequests.push({
    ceremony: candidate.ceremony,
    origin,
    topOrigin,
    ancestorOrigins,
    trustedSenderTabId: senderContext?.tabId,
    trustedSenderFrameId: senderContext?.frameId,
    relyingParty,
    challenge:
      typeof candidate.challenge === "string" && candidate.challenge.trim() !== ""
        ? candidate.challenge
        : undefined,
    allowCredentialIds: stringArrayFrom(candidate.allowCredentialIds),
    excludeCredentialIds: stringArrayFrom(candidate.excludeCredentialIds),
    mediation: typeof candidate.mediation === "string" ? candidate.mediation : undefined,
    observedAt: Date.now()
  });
  observedPageRequests.splice(0, Math.max(0, observedPageRequests.length - 50));
  void (chromeApi
    ? recordWebAuthnDebug(chromeApi, {
        event: "page_request_observed",
        ceremony: candidate.ceremony,
        origin,
        relyingParty:
          typeof candidate.relyingParty === "string"
            ? candidate.relyingParty
            : undefined,
        challenge:
          typeof candidate.challenge === "string" ? candidate.challenge : undefined
      })
    : Promise.resolve());
  return true;
}

function registerRequestHandlers(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender
) {
  const requestSource = chromeApi.webAuthenticationProxy;
  if (!requestSource || registeredRequestHandlerSources.has(requestSource)) {
    return;
  }

  registeredRequestHandlerSources.add(requestSource);
  const canceledRequests: CanceledWebAuthnRequests = {
    legacyRequestIds: new Set<number>(),
    requestKeys: new Set<string>()
  };
  registerUnlockCompleteHandler(chromeApi, sendRuntimeCommand, canceledRequests);
  chromeApi.webAuthenticationProxy?.onRequestCanceled?.addListener?.((request) => {
    const requestId =
      typeof request === "number"
        ? request
        : (request as { requestId?: unknown } | null)?.requestId;
    if (typeof requestId === "number") {
      const requestKey = webAuthnRequestCancelKeyFromRequest(request, requestId);
      markWebAuthnRequestCanceled(canceledRequests, requestId, requestKey);
      void recordWebAuthnDebug(chromeApi, {
        event: "request_canceled",
        requestId,
        precise: Boolean(requestKey)
      });
      void closePromptWindowForRequest(
        chromeApi,
        promptStates.unlock,
        clearUnlockPromptState,
        requestId,
        requestKey
      );
      void closePromptWindowForRequest(
        chromeApi,
        promptStates.approve,
        clearPresencePromptState,
        requestId,
        requestKey
      );
      void closePromptWindowForRequest(
        chromeApi,
        promptStates.verify,
        clearUserVerificationPromptState,
        requestId,
        requestKey
      );
    }
  });
  chromeApi.webAuthenticationProxy?.onIsUvpaaRequest?.addListener?.((request) => {
    void handleIsUvpaaRequest(chromeApi, sendRuntimeCommand, request);
  });
  chromeApi.webAuthenticationProxy?.onGetRequest?.addListener?.((request) => {
    void handleGetRequest(
      chromeApi,
      sendRuntimeCommand,
      request,
      canceledRequests
    );
  });
  chromeApi.webAuthenticationProxy?.onCreateRequest?.addListener?.((request) => {
    void handleCreateRequest(
      chromeApi,
      sendRuntimeCommand,
      request,
      canceledRequests
    );
  });
}

function registerUnlockCompleteHandler(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  canceledRequests: CanceledWebAuthnRequests
) {
  const messageSource = chromeApi.runtime?.onMessage;
  if (
    !messageSource ||
    typeof messageSource.addListener !== "function" ||
    registeredUnlockMessageSources.has(messageSource)
  ) {
    return;
  }

  registeredUnlockMessageSources.add(messageSource);
  messageSource.addListener((message, sender, sendResponse) => {
    if (isUnlockCompleteMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      const promptKey = matchingPromptKey(
        promptStates.unlock.contexts,
        promptStates.unlock.nonces,
        promptStates.unlock.requestIds,
        requestId,
        message,
        sender,
        "unlock"
      );
      if (!promptKey) {
        return;
      }
      void recordWebAuthnDebug(chromeApi, {
        event: "unlock_complete_message",
        requestId
      });
      const unlockUserVerificationProof =
        unlockUserVerificationProofFromMessage(message);
      const completeSignal: UnlockCompleteSignal = {
        ...(unlockUserVerificationProof
          ? { userVerificationProof: unlockUserVerificationProof }
          : {})
      };
      const waiters = [...(promptStates.unlock.completeWaiters.get(promptKey) ?? [])];
      clearUnlockPromptState(promptKey);
      for (const waiter of waiters) {
        waiter(completeSignal);
      }
      if (waiters.length === 0) {
        promptStates.unlock.pendingCompleteSignals.set(promptKey, completeSignal);
      }
      if (waiters.length === 0 && promptStates.unlock.activeDrivers.has(promptKey)) {
        return;
      } else if (waiters.length === 0) {
        void resumePasskeyCeremonyAfterPromptComplete(
          chromeApi,
          sendRuntimeCommand,
          requestId,
          "unlock",
          undefined,
          canceledRequests,
          promptKey
        );
      }
      return;
    }

    if (isPresenceCompleteMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      const promptKey = matchingPromptKey(
        promptStates.approve.contexts,
        promptStates.approve.nonces,
        promptStates.approve.requestIds,
        requestId,
        message,
        sender,
        "approve"
      );
      if (!promptKey) {
        return;
      }
      void recordWebAuthnDebug(chromeApi, {
        event: "presence_complete_message",
        requestId
      });
      const credentialId = credentialIdFromMessage(message);
      const completeSignal: PresenceCompleteSignal = {
        ...(credentialId ? { credentialId } : {})
      };
      const waiters = [...(promptStates.approve.completeWaiters.get(promptKey) ?? [])];
      clearPresencePromptState(promptKey);
      for (const waiter of waiters) {
        waiter(completeSignal);
      }
      if (waiters.length === 0 && promptStates.approve.activeDrivers.has(promptKey)) {
        promptStates.approve.pendingCompleteSignals.set(promptKey, completeSignal);
      } else if (waiters.length === 0) {
        void resumePasskeyCeremonyAfterPromptComplete(
          chromeApi,
          sendRuntimeCommand,
          requestId,
          "approve",
          credentialId,
          canceledRequests,
          promptKey
        );
      }
    }

    if (isUserVerificationCompleteMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      const promptKey = matchingPromptKey(
        promptStates.verify.contexts,
        promptStates.verify.nonces,
        promptStates.verify.requestIds,
        requestId,
        message,
        sender,
        "verify"
      );
      if (!promptKey) {
        if (typeof sendResponse === "function") {
          sendResponse({
            ok: false,
            error: "VaultKern cannot verify this passkey prompt"
          });
        }
        return true;
      }
      const expected = promptStates.verify.contexts.get(promptKey);
      const method = userVerificationMethodFromMessage(message);
      const password = userVerificationPasswordFromMessage(message);
      if (
        !expected ||
        !method ||
        (method === "master_password" && typeof password !== "string")
      ) {
        if (typeof sendResponse === "function") {
          sendResponse({
            ok: false,
            error: "VaultKern passkey user verification is incomplete"
          });
        }
        return true;
      }
      void (async () => {
        try {
          const response = await sendRuntimeCommand({
            type: "verify_passkey_user",
            ceremony_token: expected.ceremonyToken,
            expected_phase: "s1_user_authorization",
            vault_id: expected.activeVaultId,
            method,
            ...(method === "master_password" ? { password } : {})
          });
          requireRuntimeResponseType(
            response,
            "passkey_user_verified",
            "passkey user verification failed",
            "verified"
          );
          await recordWebAuthnDebug(chromeApi, {
            event: "user_verification_complete_message",
            requestId,
            method
          });
          const waiters = [
            ...(promptStates.verify.completeWaiters.get(promptKey) ?? [])
          ];
          const completeSignal: UserVerificationCompleteSignal = { method };
          clearUserVerificationPromptState(promptKey);
          for (const waiter of waiters) {
            waiter(completeSignal);
          }
          if (typeof sendResponse === "function") {
            sendResponse({ ok: true });
          }
          if (
            waiters.length === 0 &&
            promptStates.verify.activeDrivers.has(promptKey)
          ) {
            promptStates.verify.pendingCompleteSignals.set(promptKey, completeSignal);
          } else if (waiters.length === 0) {
            void resumePasskeyCeremonyAfterPromptComplete(
              chromeApi,
              sendRuntimeCommand,
              requestId,
              "verify",
              undefined,
              canceledRequests,
              promptKey
            );
          }
        } catch (verificationError) {
          if (typeof sendResponse === "function") {
            sendResponse({
              ok: false,
              error:
                verificationError instanceof Error
                  ? verificationError.message
                  : String(verificationError)
            });
          }
        }
      })();
      return true;
    }

    if (isPresenceOptionsRequestMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      const promptKey = matchingPromptKey(
        promptStates.approve.contexts,
        promptStates.approve.nonces,
        promptStates.approve.requestIds,
        requestId,
        message,
        sender,
        "approve"
      );
      if (!promptKey) {
        return;
      }
      const expected = promptStates.approve.contexts.get(promptKey);
      if (typeof sendResponse === "function") {
        sendResponse({
          credentialOptions: expected?.credentialOptions ?? []
        });
      }
    }
  });
}

function isUnlockCompleteMessage(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type === "vaultkern_unlock_complete"
  );
}

function isPresenceCompleteMessage(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type === "vaultkern_presence_complete"
  );
}

function isUserVerificationCompleteMessage(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type ===
      "vaultkern_user_verification_complete"
  );
}

function isPresenceOptionsRequestMessage(message: unknown) {
  return (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: unknown }).type === "vaultkern_presence_options_request"
  );
}

function requestIdFromMessage(message: unknown) {
  const requestId = (message as { requestId?: unknown } | null)?.requestId;
  return typeof requestId === "number" ? requestId : null;
}

function credentialIdFromMessage(message: unknown) {
  const credentialId = (message as { credentialId?: unknown } | null)?.credentialId;
  return typeof credentialId === "string" && credentialId.trim() !== ""
    ? credentialId
    : undefined;
}

function matchingPromptKey(
  contexts: Map<string, WebAuthnPromptContext>,
  nonces: Map<string, string>,
  requestIds: Map<string, number>,
  requestId: number,
  message: unknown,
  sender: unknown,
  mode: "unlock" | "approve" | "verify"
) {
  const candidate = message as
    | {
        origin?: unknown;
        relyingParty?: unknown;
        topOrigin?: unknown;
        nonce?: unknown;
      }
    | null;
  if (typeof candidate?.nonce !== "string") {
    return null;
  }

  for (const [promptKey, expected] of contexts) {
    const expectedNonce = nonces.get(promptKey);
    if (
      requestIds.get(promptKey) === requestId &&
      typeof expectedNonce === "string" &&
      candidate.nonce === expectedNonce &&
      candidate.origin === expected.origin &&
      candidate.relyingParty === expected.relyingParty &&
      candidate.topOrigin === expected.topOrigin &&
      senderMatchesPrompt(sender, mode, requestId, expectedNonce, expected)
    ) {
      return promptKey;
    }
  }

  return null;
}

function senderMatchesPrompt(
  sender: unknown,
  mode: "unlock" | "approve" | "verify",
  requestId: number,
  nonce: string,
  expected?: WebAuthnPromptContext
) {
  const url = (sender as { url?: unknown } | null)?.url;
  if (typeof url !== "string") {
    return false;
  }
  try {
    const parsed = new URL(url);
    const topOrigin = parsed.searchParams.get("topOrigin") ?? undefined;
    return (
      parsed.protocol === "chrome-extension:" &&
      parsed.pathname.endsWith("/popup.html") &&
      parsed.searchParams.get("webauthn") === mode &&
      parsed.searchParams.get("requestId") === String(requestId) &&
      parsed.searchParams.get("nonce") === nonce &&
      (!expected ||
        (parsed.searchParams.get("origin") === expected.origin &&
          parsed.searchParams.get("relyingParty") === expected.relyingParty &&
          topOrigin === expected.topOrigin))
    );
  } catch {
    return false;
  }
}

function userVerificationMethodFromMessage(message: unknown) {
  const method = (message as { method?: unknown } | null)?.method;
  return method === "master_password" || method === "quick_unlock"
    ? method
    : null;
}

function userVerificationPasswordFromMessage(message: unknown) {
  const password = (message as { password?: unknown } | null)?.password;
  return typeof password === "string" ? password : null;
}

function unlockUserVerificationProofFromMessage(
  message: unknown
): UnlockUserVerificationProof | null {
  const method = userVerificationMethodFromMessage(message);
  if (!method) {
    return null;
  }
  if (method === "quick_unlock") {
    return { method };
  }

  const password = userVerificationPasswordFromMessage(message);
  return typeof password === "string" && password !== ""
    ? { method, password }
    : null;
}

async function handleIsUvpaaRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown
) {
  const requestId = requestIdFrom(request);
  let isUvpaa = false;
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_received",
    requestId
  });
  try {
    isUvpaa = await getPasskeyUserVerificationAvailable(sendRuntimeCommand);
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "is_uvpaa_capability_failed",
      requestId,
      error: error instanceof Error ? error.message : String(error)
    });
  }
  await chromeApi.webAuthenticationProxy?.completeIsUvpaaRequest?.({
    requestId,
    isUvpaa
  });
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_completed",
    requestId,
    isUvpaa
  });
}

async function getPasskeyUserVerificationAvailable(
  sendRuntimeCommand: RuntimeCommandSender
) {
  const response = await sendRuntimeCommand({
    type: "get_passkey_user_verification_capability"
  });
  return getPasskeyUserVerificationMethodsFromResponse(response).length > 0;
}

function getPasskeyUserVerificationMethodsFromResponse(response: unknown) {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }
  const candidate =
    response as
      | {
          type?: unknown;
          available?: unknown;
          methods?: unknown;
        }
      | null;
  if (
    candidate?.type !== "passkey_user_verification_capability" ||
    candidate.available !== true ||
    !Array.isArray(candidate.methods)
  ) {
    return [];
  }
  const methods = candidate.methods.filter(
    (method): method is "master_password" | "quick_unlock" =>
      method === "master_password" || method === "quick_unlock"
  );
  return methods.length === candidate.methods.length ? methods : [];
}

async function handleGetRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown,
  canceledRequests: CanceledWebAuthnRequests
) {
  const requestId = requestIdFrom(request);
  const requestCancelKey = webAuthnRequestCancelKeyFromRequest(request, requestId);
  let ceremonyToken: string | null = null;
  let ceremonyPhase: string | null = null;
  let ceremonyMirror: PasskeyCeremonyContext | null = null;
  const throwIfRequestCanceled = () =>
    throwIfWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  const requestIsCanceled = () =>
    webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey);
  const advanceCeremony = createPasskeyCeremonyAdvancer({
    chromeApi,
    sendRuntimeCommand,
    ceremonyToken: () => ceremonyToken,
    ceremonyMirror: () => ceremonyMirror,
    updateCeremonyMirror: (mirror) => {
      ceremonyMirror = mirror;
    },
    updateCeremonyPhase: (phase) => {
      ceremonyPhase = phase;
    },
    missingCeremonyMessage: "passkey ceremony is not registered"
  });
  const {
    persistPresencePromptState,
    persistPromptWindowId,
    persistUnlockPromptState,
    persistUserVerificationPromptState
  } = createPasskeyPromptMirrorPersistence(
    chromeApi,
    () => ceremonyMirror,
    (nextMirror) => {
      ceremonyMirror = nextMirror;
    }
  );
  await recordWebAuthnDebug(chromeApi, {
    event: "get_received",
    requestId,
    summary: requestSummaryFrom(request)
  });
  try {
    const options = requestOptionsFrom(request);
    let credentialIds = credentialIdsFromOptions(options);
    const discloseUserHandle = passkeyGetCredentialIdsAreDiscoverable(credentialIds);
    const requestedRpId = relyingPartyIdFromGetOptions(options);
    const originContext = await originContextForRequest(request, "get", options);
    if (!originContext) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    const userVerification = userVerificationRequirementFromOptions(options);
    const origin = originContext.origin;
    rejectUnsupportedMediation(options.mediation);
    rejectNonSecureWebAuthnOrigin(origin);
    const relyingParty = relyingPartyFromGetOptions(options, origin);
    let relyingPartyValidation = requestedRpId
      ? await validateOriginForRelyingParty(origin, requestedRpId)
      : { allowed: true, relatedOriginVerified: false };
    if (!relyingPartyValidation.allowed) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }
    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.get",
      options.challenge,
      originContext
    );
    const ceremonyContext = await registerPasskeyCeremony(
      sendRuntimeCommand,
      request,
      requestId,
      "get",
      originContext,
      relyingParty,
      discloseUserHandle,
      userVerification,
      String(options.challenge)
    );
    ceremonyToken = ceremonyContext.ceremonyToken;
    ceremonyPhase = "s0_pre_authorization";
    ceremonyMirror = {
      ...ceremonyContext,
      getCredentialIds: credentialIds,
      getClientExtensionResults: clientExtensionResultsForGetOptions(options)
    };
    await persistPasskeyCeremonyMirror(chromeApi, ceremonyMirror);

    const session = (await sendRuntimeCommand({
      type: "get_session_state"
    })) as { activeVaultId?: string | null };
    await recordWebAuthnDebug(chromeApi, {
      event: "get_session_state",
      requestId,
      hasActiveVault: Boolean(session.activeVaultId)
    });
    throwIfRequestCanceled();
    await advanceCeremony("s0_pre_authorization", "s1_user_authorization");
    const activeVault = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      session,
      promptContextFrom(originContext, relyingParty),
      canceledRequests,
      requestCancelKey,
      {
        onPromptPrepared: persistUnlockPromptState,
        onPromptOpened: persistPromptWindowId
      }
    );
    if (!activeVault) {
      throwIfRequestCanceled();
      return;
    }
    if (ceremonyMirror) {
      ceremonyMirror = {
        ...ceremonyMirror,
        activeVaultId: activeVault.activeVaultId
      };
      await persistPasskeyCeremonyMirror(chromeApi, ceremonyMirror);
    }
    await bindPasskeyCeremonyVault(
      sendRuntimeCommand,
      ceremonyContext.ceremonyToken,
      "s1_user_authorization",
      activeVault.activeVaultId
    );
    let userPresenceVerified = activeVault.userPresenceVerified;
    let userVerified = await verifyPasskeyUserFromUnlockProof(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      activeVault.activeVaultId,
      userVerification,
      activeVault.unlockUserVerificationProof
    );
    if (!userVerified) {
      userVerified = await userVerificationForRequest(
        chromeApi,
        sendRuntimeCommand,
        requestId,
        ceremonyContext.ceremonyToken,
        activeVault.activeVaultId,
        userVerification,
        promptContextFrom(originContext, relyingParty),
        canceledRequests,
        requestCancelKey,
        {
          onPromptPrepared: persistUserVerificationPromptState,
          onPromptOpened: persistPromptWindowId
        }
      );
    }
    if (userVerified) {
      userPresenceVerified = true;
    }
    if (!userPresenceVerified) {
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        ceremonyContext.ceremonyToken,
        promptContextFrom(originContext, relyingParty),
        canceledRequests,
        requestCancelKey,
        {
          onPromptPrepared: persistPresencePromptState,
          onPromptOpened: persistPromptWindowId
        }
      );
      if (!approved) {
        throwIfRequestCanceled();
        return;
      }
      userPresenceVerified = true;
    }
    throwIfRequestCanceled();
    relyingPartyValidation = await advanceToCredentialResolution(
      origin,
      relyingParty,
      relyingPartyValidation,
      advanceCeremony,
      () => {
        if (ceremonyMirror) {
          ceremonyMirror = { ...ceremonyMirror, relatedOriginVerified: true };
        }
      }
    );
    throwIfRequestCanceled();
    const credentialSelection = await credentialSelectionForGetRequest(
      sendRuntimeCommand,
      ceremonyContext.ceremonyToken,
      activeVault.activeVaultId,
      relyingParty,
      credentialIds
    );
    credentialIds = credentialSelection.credentialIds;
    let assertionExpectedPhase = "s3_credential_resolution";
    if (credentialSelection.promptOptions.length > 0) {
      await advanceCeremony("s3_credential_resolution", "s3b_user_selection");
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        ceremonyContext.ceremonyToken,
        promptContextFrom(originContext, relyingParty, credentialSelection.promptOptions),
        canceledRequests,
        requestCancelKey,
        {
          onPromptPrepared: (nonce) =>
            persistPresencePromptState(nonce, credentialSelection.promptOptions),
          onPromptOpened: persistPromptWindowId
        }
      );
      if (!approved) {
        throwIfRequestCanceled();
        return;
      }
      if (approved.selectedCredentialId) {
        credentialIds = [approved.selectedCredentialId];
      }
      userPresenceVerified = true;
      assertionExpectedPhase = "s3b_user_selection";
    }
    await advanceCeremony(assertionExpectedPhase, "s4_completion_and_mutation");
    const assertion = await createAssertionForAllowedCredentials(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      activeVault.activeVaultId,
      relyingParty,
      origin,
      credentialIds,
      discloseUserHandle,
      clientDataJsonBase64url,
      userPresenceVerified,
      relyingPartyValidation.relatedOriginVerified,
      canceledRequests,
      requestCancelKey
    );
    if (!assertion) {
      throwIfRequestCanceled();
      return;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "get_runtime_assertion",
      requestId,
      relyingParty,
      origin,
      credentialId: assertion.credentialId
    });
    throwIfRequestCanceled();

    const delivered = await deliverPasskeyGetAssertion(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      assertion,
      clientExtensionResultsForGetOptions(options),
      {
        completeError: "get_complete_error",
        completed: "get_completed"
      }
    );
    ceremonyPhase = "closed_delivered";
    if (!delivered) {
      return;
    }
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "get_error",
      requestId,
      error: errorSummary(error)
    });
    if (requestIsCanceled()) {
      await closePasskeyCeremony(
        chromeApi,
        sendRuntimeCommand,
        ceremonyToken,
        ceremonyPhase,
        "closed_aborted"
      );
      return;
    }
    await closePasskeyCeremonyForError(
      chromeApi,
      sendRuntimeCommand,
      ceremonyToken,
      ceremonyPhase,
      error
    );
    await completePasskeyRequestWithError(
      chromeApi,
      "get",
      requestId,
      ceremonyToken,
      error
    );
  } finally {
    clearWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  }
}

type PasskeyAssertionResponse = {
  credentialId: string;
  authenticatorDataBase64url: string;
  clientDataJsonBase64url: string;
  signatureBase64url: string;
  userHandleBase64url?: string | null;
};

type PasskeyRegistrationResponse = {
  entryId: string;
  credentialId: string;
  created: boolean;
  authenticatorDataBase64url: string;
  attestationObjectBase64url: string;
  clientDataJsonBase64url: string;
  publicKeyBase64url: string;
  publicKeyAlgorithm: number;
};

type PasskeyCredentialStatusResponse = {
  credentialId: string;
  exists: boolean;
};

type PasskeyCredentialStatusBatchResponse = {
  statuses: PasskeyCredentialStatusResponse[];
};

type PasskeyCredentialListResponse = {
  credentials: PasskeyCredentialListItem[];
};

async function deliverPasskeyGetAssertion(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  ceremonyToken: string,
  assertion: PasskeyAssertionResponse,
  clientExtensionResults: Record<string, unknown>,
  events: { completeError: string; completed: string }
) {
  try {
    await completeGetRequest(chromeApi, {
      requestId,
      responseJson: passkeyGetCredentialResponseJson(
        assertion,
        clientExtensionResults
      )
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: events.completeError,
      requestId,
      error: errorSummary(error)
    });
    await markPasskeyCeremonyUnknownDelivery(sendRuntimeCommand, ceremonyToken);
    await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
    return false;
  }

  const deliveryConfirmed = await markPasskeyCeremonyDelivered(
    sendRuntimeCommand,
    ceremonyToken
  );
  if (!deliveryConfirmed) {
    await markPasskeyCeremonyUnknownDelivery(sendRuntimeCommand, ceremonyToken);
  }
  await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
  await recordWebAuthnDebug(chromeApi, {
    event: events.completed,
    requestId
  });
  return true;
}

async function deliverPasskeyCreateRegistration(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  ceremonyToken: string,
  registration: PasskeyRegistrationResponse,
  clientExtensionResults: Record<string, unknown>,
  events: { completeError: string; completed: string }
) {
  try {
    await completeCreateRequest(chromeApi, {
      requestId,
      responseJson: passkeyCreateCredentialResponseJson(
        registration,
        clientExtensionResults
      )
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: events.completeError,
      requestId,
      error: errorSummary(error)
    });
    return false;
  }

  const deliveryConfirmed = await markPasskeyCeremonyDelivered(
    sendRuntimeCommand,
    ceremonyToken
  );
  if (!deliveryConfirmed) {
    await markPasskeyCeremonyUnknownDelivery(sendRuntimeCommand, ceremonyToken);
  }
  await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
  await recordWebAuthnDebug(chromeApi, {
    event: events.completed,
    requestId
  });
  return true;
}

async function credentialSelectionForGetRequest(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  activeVaultId: string,
  relyingParty: string,
  credentialIds: Array<string | null>
) {
  if (!(credentialIds.length === 1 && credentialIds[0] === null)) {
    return {
      credentialIds,
      promptOptions: [] as PasskeyCredentialOption[]
    };
  }

  const credentials = passkeyCredentialListFromResponse(
    await sendRuntimeCommand({
      type: "list_passkey_credentials",
      ceremony_token: ceremonyToken,
      expected_phase: "s3_credential_resolution",
      vault_id: activeVaultId,
      relying_party: relyingParty
    })
  ).credentials;

  if (credentials.length === 0) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey credential not found"
    );
  }

  return {
    credentialIds,
    promptOptions: credentials.map(({ credentialId, username }) => ({
      credentialId,
      username
    }))
  };
}

async function excludedCredentialStatusesForCreateRequest(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  activeVaultId: string,
  relyingParty: string,
  excludedCredentialIds: string[]
) {
  if (excludedCredentialIds.length === 0) {
    return [];
  }

  if (excludedCredentialIds.length === 1) {
    return [
      passkeyCredentialStatusFromResponse(
        await sendRuntimeCommand({
          type: "passkey_credential_status",
          ceremony_token: ceremonyToken,
          expected_phase: "s3_credential_resolution",
          vault_id: activeVaultId,
          credential_id: excludedCredentialIds[0],
          relying_party: relyingParty
        })
      )
    ];
  }

  return passkeyCredentialStatusBatchFromResponse(
    await sendRuntimeCommand({
      type: "passkey_credential_status_batch",
      ceremony_token: ceremonyToken,
      expected_phase: "s3_credential_resolution",
      vault_id: activeVaultId,
      credential_ids: excludedCredentialIds,
      relying_party: relyingParty
    })
  ).statuses;
}

async function createAssertionForAllowedCredentials(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  ceremonyToken: string,
  activeVaultId: string,
  relyingParty: string,
  origin: string,
  credentialIds: Array<string | null>,
  discoverable: boolean,
  clientDataJsonBase64url: string,
  userPresenceVerified: boolean,
  relatedOriginVerified: boolean,
  canceledRequests: CanceledWebAuthnRequests,
  requestCancelKey: string | null
) {
  for (const credentialId of credentialIds) {
    if (webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey)) {
      return null;
    }

    const response = await sendRuntimeCommand({
      type: "create_passkey_assertion",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      vault_id: activeVaultId,
      relying_party: relyingParty,
      origin,
      credential_id: credentialId,
      discoverable,
      user_presence_verified: userPresenceVerified,
      ...(relatedOriginVerified ? { related_origin_verified: true } : {}),
      client_data_json_base64url: clientDataJsonBase64url
    });
    const runtimeError = runtimeErrorFromResponse(response);
    if (runtimeError) {
      await recordWebAuthnDebug(chromeApi, {
        event: "get_runtime_assertion_candidate_error",
        requestId,
        credentialId,
        error: errorSummary(runtimeError)
      });
      continue;
    }

    return passkeyAssertionFromResponse(response);
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey credential not found"
  );
}

async function resumePasskeyGetAfterPromptComplete(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  promptMode: "approve" | "unlock" | "verify",
  credentialId: string | undefined,
  canceledRequests: CanceledWebAuthnRequests,
  ceremonyToken?: string
) {
  let mirror: PasskeyCeremonyContext | null = null;
  let ceremonyPhase: string | null = null;
  let requestCancelKey: string | null = null;
  const throwIfRequestCanceled = () =>
    throwIfWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  const {
    persistPresencePromptState,
    persistPromptWindowId,
    persistUserVerificationPromptState
  } = createPasskeyPromptMirrorPersistence(
    chromeApi,
    () => mirror,
    (nextMirror) => {
      mirror = nextMirror;
    }
  );

  try {
    const mirrors = await loadPasskeyCeremonyMirrorsQueued(chromeApi);
    const candidates = Object.values(mirrors).filter(
      (candidate) =>
        candidate.requestId === requestId &&
        candidate.ceremony === "get" &&
        (candidate.phase === "s1_user_authorization" ||
          (promptMode === "approve" &&
            candidate.phase === "s3b_user_selection")) &&
        candidate.promptMode === promptMode
    );
    mirror =
      (ceremonyToken
        ? candidates.find((candidate) => candidate.ceremonyToken === ceremonyToken)
        : null) ??
      candidates[0] ??
      null;
    if (!mirror) {
      return;
    }
    requestCancelKey = webAuthnRequestCancelKeyFromMirror(mirror);
    ceremonyPhase = mirror.phase;
    if (promptMode === "unlock") {
      const session = (await sendRuntimeCommand({
        type: "get_session_state"
      })) as { activeVaultId?: string | null };
      if (session.activeVaultId) {
        mirror = { ...mirror, activeVaultId: session.activeVaultId };
        await persistPasskeyCeremonyMirror(chromeApi, mirror);
      }
    }
    if (typeof mirror.activeVaultId !== "string" || mirror.activeVaultId === "") {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern passkey ceremony is missing its vault binding"
      );
    }
    await bindPasskeyCeremonyVault(
      sendRuntimeCommand,
      mirror.ceremonyToken,
      mirror.phase,
      mirror.activeVaultId
    );
    if (promptMode === "unlock") {
      let userVerified = await verifyPasskeyUserFromUnlockProof(
        chromeApi,
        sendRuntimeCommand,
        requestId,
        mirror.ceremonyToken,
        mirror.activeVaultId,
        mirror.userVerification,
        takePendingUnlockCompleteSignal(mirror.ceremonyToken)
          ?.userVerificationProof ?? null
      );
      if (!userVerified) {
        const promptContext = promptContextFromMirror(mirror);
        if (!promptContext) {
          throw new WebAuthnRequestError(
            "NotAllowedError",
            "VaultKern passkey ceremony is missing its prompt context"
          );
        }
        userVerified = await userVerificationForRequest(
          chromeApi,
          sendRuntimeCommand,
          requestId,
          mirror.ceremonyToken,
          mirror.activeVaultId,
          mirror.userVerification,
          promptContext,
          canceledRequests,
          requestCancelKey,
          {
            onPromptPrepared: persistUserVerificationPromptState,
            onPromptOpened: persistPromptWindowId
          }
        );
      }
    }

    const advanceCeremony = createPasskeyCeremonyAdvancer({
      chromeApi,
      sendRuntimeCommand,
      ceremonyToken: () => mirror?.ceremonyToken,
      ceremonyMirror: () => mirror,
      updateCeremonyMirror: (nextMirror) => {
        mirror = nextMirror;
      },
      updateCeremonyPhase: (phase) => {
        ceremonyPhase = phase;
      },
      missingCeremonyMessage: "passkey ceremony is not restored"
    });

    let credentialIds: Array<string | null>;
    let assertionExpectedPhase: string;
    let relatedOriginVerified = mirror.relatedOriginVerified === true;
    const discloseUserHandle = passkeyGetCredentialIdsAreDiscoverable(
      mirror.getCredentialIds
    );

    if (mirror.phase === "s3b_user_selection") {
      if (
        !originMatchesRelyingParty(mirror.origin, mirror.relyingParty) &&
        mirror.relatedOriginVerified !== true
      ) {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "WebAuthn request origin does not match relying party"
        );
      }
      const promptContext = promptContextFromMirror(mirror);
      if (!promptContext || (promptContext.credentialOptions ?? []).length === 0) {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey ceremony is missing its credential selection"
        );
      }
      const selectedCredentialId = selectedCredentialIdForPrompt(
        promptContext,
        credentialId
      );
      if (!selectedCredentialId) {
        throw userAbortWebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey credential was not selected"
        );
      }
      credentialIds = [selectedCredentialId];
      assertionExpectedPhase = "s3b_user_selection";
    } else {
      if (!passkeyGetCredentialIdsAreSafe(mirror.getCredentialIds)) {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey ceremony is missing its credential request"
        );
      }
      credentialIds = [...mirror.getCredentialIds];
      let relyingPartyValidation = validateOriginForRelyingParty(
        mirror.origin,
        mirror.relyingParty
      );
      if (!relyingPartyValidation.allowed) {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "WebAuthn request origin does not match relying party"
        );
      }

      relyingPartyValidation = await advanceToCredentialResolution(
        mirror.origin,
        mirror.relyingParty,
        relyingPartyValidation,
        advanceCeremony,
        () => {
          if (!mirror) {
            return;
          }
          mirror = { ...mirror, relatedOriginVerified: true };
        }
      );
      relatedOriginVerified = relyingPartyValidation.relatedOriginVerified;
      const credentialSelection = await credentialSelectionForGetRequest(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        mirror.activeVaultId,
        mirror.relyingParty,
        credentialIds
      );
      credentialIds = credentialSelection.credentialIds;
      assertionExpectedPhase = "s3_credential_resolution";

      if (credentialSelection.promptOptions.length > 0) {
        await advanceCeremony("s3_credential_resolution", "s3b_user_selection");
        const approved = await userPresenceForRequest(
          chromeApi,
          requestId,
          mirror.ceremonyToken,
          promptContextFrom(
            {
              origin: mirror.origin,
              topOrigin: mirror.topOrigin,
              ancestorOrigins: mirror.ancestorOrigins
            },
            mirror.relyingParty,
            credentialSelection.promptOptions
          ),
          canceledRequests,
          requestCancelKey,
          {
            onPromptPrepared: (nonce) =>
              persistPresencePromptState(nonce, credentialSelection.promptOptions),
            onPromptOpened: persistPromptWindowId
          }
        );
        if (!approved) {
          throwIfRequestCanceled();
          return;
        }
        if (approved.selectedCredentialId) {
          credentialIds = [approved.selectedCredentialId];
        }
        assertionExpectedPhase = "s3b_user_selection";
      }
    }

    throwIfRequestCanceled();
    await advanceCeremony(assertionExpectedPhase, "s4_completion_and_mutation");

    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.get",
      mirror.challengeBase64url,
      {
        origin: mirror.origin,
        topOrigin: mirror.topOrigin,
        ancestorOrigins: mirror.ancestorOrigins
      }
    );
    const assertion = await createAssertionForAllowedCredentials(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      mirror.ceremonyToken,
      mirror.activeVaultId,
      mirror.relyingParty,
      mirror.origin,
      credentialIds,
      discloseUserHandle,
      clientDataJsonBase64url,
      true,
      relatedOriginVerified,
      canceledRequests,
      requestCancelKey
    );
    if (!assertion) {
      throwIfRequestCanceled();
      return;
    }

    const delivered = await deliverPasskeyGetAssertion(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      mirror.ceremonyToken,
      assertion,
      getClientExtensionResultsFromMirror(mirror),
      {
        completeError: "get_resume_complete_error",
        completed: "get_resumed_after_presence_complete"
      }
    );
    ceremonyPhase = "closed_delivered";
    if (!delivered) {
      return;
    }
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "get_resume_after_presence_complete_error",
      requestId,
      error: errorSummary(error)
    });
    await closePasskeyCeremonyForError(
      chromeApi,
      sendRuntimeCommand,
      mirror?.ceremonyToken ?? null,
      ceremonyPhase,
      error
    );
    await completePasskeyRequestWithError(
      chromeApi,
      "get",
      requestId,
      mirror?.ceremonyToken ?? null,
      error
    );
  }
}

async function resumePasskeyCeremonyAfterPromptComplete(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  promptMode: "approve" | "unlock" | "verify",
  credentialId: string | undefined,
  canceledRequests: CanceledWebAuthnRequests,
  ceremonyToken?: string
) {
  await resumePasskeyGetAfterPromptComplete(
    chromeApi,
    sendRuntimeCommand,
    requestId,
    promptMode,
    credentialId,
    canceledRequests,
    ceremonyToken
  );
  await resumePasskeyCreateAfterPromptComplete(
    chromeApi,
    sendRuntimeCommand,
    requestId,
    promptMode,
    canceledRequests,
    ceremonyToken
  );
}

async function resumePasskeyCreateAfterPromptComplete(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  promptMode: "approve" | "unlock" | "verify",
  canceledRequests: CanceledWebAuthnRequests,
  ceremonyToken?: string
) {
  let mirror: PasskeyCeremonyContext | null = null;
  let ceremonyPhase: string | null = null;
  let registration: PasskeyRegistrationResponse | null = null;
  let ceremonyCommitted = false;
  let requestCancelKey: string | null = null;
  const throwIfRequestCanceled = () =>
    throwIfWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  const requestIsCanceled = () =>
    webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey);
  const { persistPromptWindowId, persistUserVerificationPromptState } =
    createPasskeyPromptMirrorPersistence(
      chromeApi,
      () => mirror,
      (nextMirror) => {
        mirror = nextMirror;
      }
    );

  try {
    const mirrors = await loadPasskeyCeremonyMirrorsQueued(chromeApi);
    const candidates = Object.values(mirrors).filter(
      (candidate) =>
        candidate.requestId === requestId &&
        candidate.ceremony === "create" &&
        candidate.phase === "s1_user_authorization" &&
        candidate.promptMode === promptMode
    );
    mirror =
      (ceremonyToken
        ? candidates.find((candidate) => candidate.ceremonyToken === ceremonyToken)
        : null) ??
      candidates[0] ??
      null;
    if (!mirror) {
      return;
    }
    requestCancelKey = webAuthnRequestCancelKeyFromMirror(mirror);
    ceremonyPhase = mirror.phase;
    if (promptMode === "unlock") {
      const session = (await sendRuntimeCommand({
        type: "get_session_state"
      })) as { activeVaultId?: string | null };
      if (session.activeVaultId) {
        mirror = { ...mirror, activeVaultId: session.activeVaultId };
        await persistPasskeyCeremonyMirror(chromeApi, mirror);
      }
    }
    if (typeof mirror.activeVaultId !== "string" || mirror.activeVaultId === "") {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern passkey ceremony is missing its vault binding"
      );
    }
    await bindPasskeyCeremonyVault(
      sendRuntimeCommand,
      mirror.ceremonyToken,
      mirror.phase,
      mirror.activeVaultId
    );
    if (promptMode === "unlock") {
      let userVerified = await verifyPasskeyUserFromUnlockProof(
        chromeApi,
        sendRuntimeCommand,
        requestId,
        mirror.ceremonyToken,
        mirror.activeVaultId,
        mirror.userVerification,
        takePendingUnlockCompleteSignal(mirror.ceremonyToken)
          ?.userVerificationProof ?? null
      );
      if (!userVerified) {
        const promptContext = promptContextFromMirror(mirror);
        if (!promptContext) {
          throw new WebAuthnRequestError(
            "NotAllowedError",
            "VaultKern passkey ceremony is missing its prompt context"
          );
        }
        userVerified = await userVerificationForRequest(
          chromeApi,
          sendRuntimeCommand,
          requestId,
          mirror.ceremonyToken,
          mirror.activeVaultId,
          mirror.userVerification,
          promptContext,
          canceledRequests,
          requestCancelKey,
          {
            onPromptPrepared: persistUserVerificationPromptState,
            onPromptOpened: persistPromptWindowId
          }
        );
      }
    }

    const createRequest = passkeyCreateRequestFromMirror(mirror);
    if (!createRequest) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern passkey ceremony is missing its registration request"
      );
    }

    const advanceCeremony = createPasskeyCeremonyAdvancer({
      chromeApi,
      sendRuntimeCommand,
      ceremonyToken: () => mirror?.ceremonyToken,
      ceremonyMirror: () => mirror,
      updateCeremonyMirror: (nextMirror) => {
        mirror = nextMirror;
      },
      updateCeremonyPhase: (phase) => {
        ceremonyPhase = phase;
      },
      missingCeremonyMessage: "passkey ceremony is not restored"
    });

    let relyingPartyValidation = validateOriginForRelyingParty(
      mirror.origin,
      mirror.relyingParty
    );
    if (!relyingPartyValidation.allowed) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }

    relyingPartyValidation = await advanceToCredentialResolution(
      mirror.origin,
      mirror.relyingParty,
      relyingPartyValidation,
      advanceCeremony,
      () => {
        if (!mirror) {
          return;
        }
        mirror = { ...mirror, relatedOriginVerified: true };
      }
    );
    const activeVaultId = mirror.activeVaultId;
    throwIfRequestCanceled();
    const excludedCredentialStatuses = await excludedCredentialStatusesForCreateRequest(
      sendRuntimeCommand,
      mirror.ceremonyToken,
      activeVaultId,
      mirror.relyingParty,
      createRequest.excludeCredentialIds
    );
    throwIfRequestCanceled();
    if (excludedCredentialStatuses.some((status) => status.exists)) {
      throw new WebAuthnRequestError(
        "InvalidStateError",
        "VaultKern passkey credential is already registered"
      );
    }

    throwIfRequestCanceled();
    await advanceCeremony("s3_credential_resolution", "s4_completion_and_mutation");
    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.create",
      mirror.challengeBase64url,
      {
        origin: mirror.origin,
        topOrigin: mirror.topOrigin,
        ancestorOrigins: mirror.ancestorOrigins
      }
    );
    registration = passkeyRegistrationFromResponse(
      await sendRuntimeCommand({
        type: "create_passkey_registration",
        ceremony_token: mirror.ceremonyToken,
        expected_phase: "s4_completion_and_mutation",
        vault_id: activeVaultId,
        relying_party: mirror.relyingParty,
        origin: mirror.origin,
        user_name: createRequest.userName,
        user_display_name: createRequest.userDisplayName,
        user_handle_base64url: createRequest.userHandleBase64url,
        public_key_algorithm: createRequest.publicKeyAlgorithm,
        ...(relyingPartyValidation.relatedOriginVerified
          ? { related_origin_verified: true }
          : {}),
        client_data_json_base64url: clientDataJsonBase64url
      })
    );
    if (requestIsCanceled()) {
      await abortPasskeyRegistrationStrict(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        "closed_aborted"
      );
      ceremonyPhase = "closed_aborted";
      await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
      return;
    }

    try {
      await savePasskeyRegistration(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        activeVaultId
      );
    } catch (error) {
      await abortPasskeyRegistrationStrict(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        "closed_failed"
      );
      ceremonyPhase = "closed_failed";
      await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
      throw error;
    }
    if (requestIsCanceled()) {
      await abortPasskeyRegistrationStrict(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        "closed_aborted"
      );
      ceremonyPhase = "closed_aborted";
      await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
      return;
    }

    await commitPasskeyRegistration(
      sendRuntimeCommand,
      mirror.ceremonyToken,
      activeVaultId,
      registration.entryId,
      registration.credentialId
    );
    ceremonyCommitted = true;
    if (requestIsCanceled()) {
      const marked = await markPasskeyCeremonyUnknownDelivery(
        sendRuntimeCommand,
        mirror.ceremonyToken
      );
      if (marked) {
        ceremonyPhase = "closed_delivered";
        await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
      }
      return;
    }

    const delivered = await deliverPasskeyCreateRegistration(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      mirror.ceremonyToken,
      registration,
      createRequest.clientExtensionResults,
      {
        completeError: "create_resume_complete_error",
        completed: "create_resumed_after_prompt_complete"
      }
    );
    if (!delivered) {
      await markPasskeyCeremonyUnknownDelivery(
        sendRuntimeCommand,
        mirror.ceremonyToken
      );
      ceremonyPhase = "closed_delivered";
      await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
      return;
    }
    ceremonyPhase = "closed_delivered";
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "create_resume_after_prompt_complete_error",
      requestId,
      error: errorSummary(error)
    });
    if (mirror && !ceremonyCommitted && ceremonyPhase === "s4_completion_and_mutation") {
      try {
        await abortS4PasskeyCreateCeremony(
          chromeApi,
          sendRuntimeCommand,
          mirror.ceremonyToken,
          ceremonyPhase,
          isUserAbortError(error) ? "closed_aborted" : "closed_failed"
        );
      } catch {
        // Preserve the original WebAuthn failure.
      }
    } else if (ceremonyCommitted && mirror) {
      await markPasskeyCeremonyUnknownDelivery(
        sendRuntimeCommand,
        mirror.ceremonyToken
      );
      await clearPasskeyCeremonyMirror(chromeApi, mirror.ceremonyToken);
    } else {
      await closePasskeyCeremonyForError(
        chromeApi,
        sendRuntimeCommand,
        mirror?.ceremonyToken ?? null,
        ceremonyPhase,
        error
      );
    }
    await completePasskeyRequestWithError(
      chromeApi,
      "create",
      requestId,
      mirror?.ceremonyToken ?? null,
      error
    );
  }
}

function runtimeErrorFromResponse(response: unknown) {
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "error"
  ) {
    const message = (response as { message?: unknown }).message;
    return new InternalPasskeyRequestError(
      typeof message === "string" ? message : "runtime command failed"
    );
  }
  return null;
}

function requireRuntimeResponseType(
  response: unknown,
  expectedType: string,
  message: string,
  successProperty?: string
) {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === expectedType &&
    (successProperty === undefined ||
      (response as Record<string, unknown>)[successProperty] === true)
  ) {
    return;
  }
  throw new InternalPasskeyRequestError(message);
}

function requirePasskeyCeremonyReconciliationSuccess(response: unknown) {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type ===
      "passkey_ceremony_reconciliation" &&
    Array.isArray((response as { reconciled?: unknown }).reconciled)
  ) {
    return;
  }
  throw new InternalPasskeyRequestError(
    "passkey ceremony reconciliation did not return success"
  );
}

function requirePasskeySaveSuccess(response: unknown) {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "saved"
  ) {
    return;
  }
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "save_vault_result" &&
    isDurablePasskeySaveStatus((response as { status?: unknown }).status)
  ) {
    return;
  }
  throw new InternalPasskeyRequestError(
    "passkey registration save did not return durable success"
  );
}

function isDurablePasskeySaveStatus(status: unknown) {
  return status === "saved" || status === "merged" || status === "saved_to_cache";
}

async function loadPasskeyCeremonyMirrors(chromeApi: ChromeLike | null | undefined) {
  const storage = chromeApi?.storage?.session;
  if (!storage?.get) {
    return {} as Record<string, PasskeyCeremonyContext>;
  }

  try {
    if (!(await ensurePasskeyCeremonySessionStorageTrusted(chromeApi))) {
      return {};
    }
    if (typeof storage === "object") {
      const cached = passkeyCeremonyMirrorCache.get(storage);
      if (cached) {
        return clonePasskeyCeremonyMirrors(cached);
      }
    }
    const result = await storage.get([PASSKEY_CEREMONY_SESSION_STORAGE_KEY]);
    const value = result[PASSKEY_CEREMONY_SESSION_STORAGE_KEY];
    const envelope = passkeyCeremonyMirrorEnvelopeFrom(value);
    if (!envelope) {
      if (typeof storage === "object") {
        passkeyCeremonyMirrorCache.set(storage, {});
      }
      return {};
    }
    const mirrors: Record<string, PasskeyCeremonyContext> = {};
    for (const [token, mirror] of Object.entries(envelope.ceremonies)) {
      if (isPasskeyCeremonyMirror(mirror) && token === mirror.ceremonyToken) {
        rememberPasskeyCeremonyToken(token);
        mirrors[token] = mirror;
      }
    }
    if (typeof storage === "object") {
      passkeyCeremonyMirrorCache.set(storage, clonePasskeyCeremonyMirrors(mirrors));
    }
    return clonePasskeyCeremonyMirrors(mirrors);
  } catch {
    return {};
  }
}

async function storePasskeyCeremonyMirrors(
  chromeApi: ChromeLike | null | undefined,
  mirrors: Record<string, PasskeyCeremonyContext>
) {
  const storage = chromeApi?.storage?.session;
  if (!storage?.set) {
    return;
  }

  const keys = Object.keys(mirrors);
  try {
    if (keys.length === 0 && storage.remove) {
      if (typeof storage === "object") {
        passkeyCeremonyMirrorCache.set(storage, {});
      }
      await storage.remove(PASSKEY_CEREMONY_SESSION_STORAGE_KEY);
      return;
    }
    if (!(await ensurePasskeyCeremonySessionStorageTrusted(chromeApi))) {
      return;
    }
    const normalizedMirrors = clonePasskeyCeremonyMirrors(mirrors);
    if (typeof storage === "object") {
      passkeyCeremonyMirrorCache.set(storage, clonePasskeyCeremonyMirrors(normalizedMirrors));
    }
    const envelope: PasskeyCeremonyMirrorEnvelope = {
      version: PASSKEY_CEREMONY_MIRROR_ENVELOPE_VERSION,
      ceremonies: normalizedMirrors,
      checksum: passkeyCeremonyMirrorChecksum(normalizedMirrors)
    };
    await storage.set({
      [PASSKEY_CEREMONY_SESSION_STORAGE_KEY]: envelope
    });
  } catch {
    // Session mirror persistence is best-effort; native ledger remains authoritative.
  }
}

function passkeyCeremonyMirrorEnvelopeFrom(
  value: unknown
): PasskeyCeremonyMirrorEnvelope | null {
  const candidate = value as Partial<PasskeyCeremonyMirrorEnvelope> | null;
  if (
    !candidate ||
    typeof candidate !== "object" ||
    Array.isArray(candidate) ||
    candidate.version !== PASSKEY_CEREMONY_MIRROR_ENVELOPE_VERSION ||
    typeof candidate.checksum !== "string" ||
    !candidate.ceremonies ||
    typeof candidate.ceremonies !== "object" ||
    Array.isArray(candidate.ceremonies)
  ) {
    return null;
  }

  if (candidate.checksum !== passkeyCeremonyMirrorChecksum(candidate.ceremonies)) {
    return null;
  }

  return {
    version: PASSKEY_CEREMONY_MIRROR_ENVELOPE_VERSION,
    ceremonies: candidate.ceremonies,
    checksum: candidate.checksum
  };
}

function passkeyCeremonyMirrorChecksum(value: unknown) {
  let hash = 0x811c9dc5;
  const input = stableJson(value);
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${PASSKEY_CEREMONY_MIRROR_CHECKSUM_PREFIX}${hash
    .toString(16)
    .padStart(8, "0")}`;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item ?? null)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

function clonePasskeyCeremonyMirrors(
  mirrors: Record<string, PasskeyCeremonyContext>
) {
  return Object.fromEntries(
    Object.entries(mirrors).map(([token, mirror]) => [
      token,
      clonePasskeyCeremonyMirror(mirror)
    ])
  ) as Record<string, PasskeyCeremonyContext>;
}

function clonePasskeyCeremonyMirror(
  mirror: PasskeyCeremonyContext
): PasskeyCeremonyContext {
  const common = {
    ...mirror,
    ancestorOrigins: [...mirror.ancestorOrigins],
    ...(mirror.promptCredentialOptions
      ? {
          promptCredentialOptions: mirror.promptCredentialOptions.map((option) => ({
            ...option
          }))
        }
      : {})
  };

  if (mirror.ceremony === "get") {
    return {
      ...common,
      ceremony: "get",
      ...(Array.isArray(mirror.getCredentialIds)
        ? { getCredentialIds: [...mirror.getCredentialIds] }
        : {}),
      ...(mirror.getClientExtensionResults
        ? { getClientExtensionResults: { ...mirror.getClientExtensionResults } }
        : {})
    };
  }

  return {
    ...common,
    ceremony: "create",
    ...(Array.isArray(mirror.createExcludeCredentialIds)
      ? { createExcludeCredentialIds: [...mirror.createExcludeCredentialIds] }
      : {}),
    ...(mirror.createClientExtensionResults
      ? { createClientExtensionResults: { ...mirror.createClientExtensionResults } }
      : {})
  };
}

async function ensurePasskeyCeremonySessionStorageTrusted(
  chromeApi: ChromeLike | null | undefined
) {
  const storage = chromeApi?.storage?.session;
  if (!storage?.setAccessLevel) {
    return false;
  }
  if (typeof storage === "object" && trustedPasskeyCeremonySessionStorage.has(storage)) {
    return true;
  }

  try {
    await storage.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    if (typeof storage === "object") {
      trustedPasskeyCeremonySessionStorage.add(storage);
    }
    return true;
  } catch {
    return false;
  }
}

function enqueuePasskeyCeremonyMirrorMutation<T>(mutation: () => Promise<T>) {
  const run = passkeyCeremonyMirrorMutationQueue.then(mutation, mutation);
  passkeyCeremonyMirrorMutationQueue = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

async function loadPasskeyCeremonyMirrorsQueued(chromeApi: ChromeLike) {
  return enqueuePasskeyCeremonyMirrorMutation(() =>
    loadPasskeyCeremonyMirrors(chromeApi)
  );
}

async function persistPasskeyCeremonyMirror(
  chromeApi: ChromeLike,
  mirror: PasskeyCeremonyContext
) {
  await enqueuePasskeyCeremonyMirrorMutation(async () => {
    const mirrors = await loadPasskeyCeremonyMirrors(chromeApi);
    mirrors[mirror.ceremonyToken] = mirror;
    await storePasskeyCeremonyMirrors(chromeApi, mirrors);
  });
}

async function clearPasskeyCeremonyMirror(
  chromeApi: ChromeLike,
  ceremonyToken: string | null
) {
  if (!ceremonyToken) {
    return;
  }
  await enqueuePasskeyCeremonyMirrorMutation(async () => {
    const mirrors = await loadPasskeyCeremonyMirrors(chromeApi);
    if (!(ceremonyToken in mirrors)) {
      return;
    }
    delete mirrors[ceremonyToken];
    await storePasskeyCeremonyMirrors(chromeApi, mirrors);
  });
}

function isPasskeyCeremonyMirror(value: unknown): value is PasskeyCeremonyContext {
  const candidate = value as Partial<PasskeyCeremonyContext> | null;
  return (
    Boolean(candidate) &&
    candidate?.version === 1 &&
    typeof candidate.ceremonyToken === "string" &&
    passkeyCeremonyPhaseIsKnown(candidate.phase) &&
    typeof candidate.origin === "string" &&
    Array.isArray(candidate.ancestorOrigins) &&
    candidate.ancestorOrigins.every((origin) => typeof origin === "string") &&
    typeof candidate.relyingParty === "string" &&
    (candidate.ceremony === "get" || candidate.ceremony === "create") &&
    passkeyUserVerificationRequirementIsKnown(candidate.userVerification) &&
    typeof candidate.challengeBase64url === "string" &&
    typeof candidate.requestId === "number" &&
    typeof candidate.tabId === "number" &&
    typeof candidate.frameId === "number" &&
    (candidate.frameKind === "top" || candidate.frameKind === "subframe") &&
    passkeyCeremonyMirrorFrameContextIsSafe(candidate) &&
    (candidate.relatedOriginVerified === undefined ||
      typeof candidate.relatedOriginVerified === "boolean") &&
    (candidate.activeVaultId === undefined ||
      typeof candidate.activeVaultId === "string") &&
    (candidate.getCredentialIds === undefined ||
      passkeyGetCredentialIdsAreSafe(candidate.getCredentialIds)) &&
    (candidate.getClientExtensionResults === undefined ||
      passkeyGetClientExtensionResultsAreSafe(candidate.getClientExtensionResults)) &&
    (candidate.createUserName === undefined ||
      (typeof candidate.createUserName === "string" &&
        candidate.createUserName.trim() !== "")) &&
    (candidate.createUserDisplayName === undefined ||
      candidate.createUserDisplayName === null ||
      typeof candidate.createUserDisplayName === "string") &&
    (candidate.createUserHandleBase64url === undefined ||
      (typeof candidate.createUserHandleBase64url === "string" &&
        candidate.createUserHandleBase64url.trim() !== "")) &&
    (candidate.createPublicKeyAlgorithm === undefined ||
      candidate.createPublicKeyAlgorithm === -7) &&
    (candidate.createExcludeCredentialIds === undefined ||
      passkeyStringListIsSafe(candidate.createExcludeCredentialIds)) &&
    (candidate.createClientExtensionResults === undefined ||
      passkeyCreateClientExtensionResultsAreSafe(
        candidate.createClientExtensionResults
      )) &&
    (candidate.popupNonce === undefined ||
      typeof candidate.popupNonce === "string") &&
    (candidate.promptMode === undefined ||
      candidate.promptMode === "approve" ||
      candidate.promptMode === "unlock" ||
      candidate.promptMode === "verify") &&
    (candidate.promptWindowId === undefined ||
      (typeof candidate.promptWindowId === "number" &&
        Number.isInteger(candidate.promptWindowId) &&
        candidate.promptWindowId > 0)) &&
    (candidate.promptCredentialOptions === undefined ||
      passkeyCredentialOptionsAreUiSafe(candidate.promptCredentialOptions)) &&
    typeof candidate.registeredAtEpochMs === "number" &&
    typeof candidate.expiresAtEpochMs === "number" &&
    passkeyCeremonyMirrorHasRequiredPayload(candidate)
  );
}

function passkeyCeremonyPhaseIsKnown(phase: unknown): phase is PasskeyCeremonyPhase {
  return typeof phase === "string" && PASSKEY_CEREMONY_PHASES.has(phase);
}

function passkeyUserVerificationRequirementIsKnown(
  requirement: unknown
): requirement is PasskeyUserVerificationRequirement {
  return (
    requirement === "discouraged" ||
    requirement === "preferred" ||
    requirement === "required"
  );
}

function passkeyCeremonyMirrorFrameContextIsSafe(
  candidate: Partial<PasskeyCeremonyContext>
) {
  if (candidate.frameKind === "top") {
    return (
      candidate.frameId === 0 &&
      candidate.topOrigin === undefined &&
      Array.isArray(candidate.ancestorOrigins) &&
      candidate.ancestorOrigins.length === 0
    );
  }
  if (candidate.frameKind === "subframe") {
    return (
      typeof candidate.frameId === "number" &&
      candidate.frameId !== 0 &&
      typeof candidate.topOrigin === "string" &&
      candidate.topOrigin.trim() !== "" &&
      Array.isArray(candidate.ancestorOrigins) &&
      candidate.ancestorOrigins.length > 0 &&
      originsHaveSameUrlOrigin(
        candidate.ancestorOrigins[candidate.ancestorOrigins.length - 1],
        candidate.topOrigin
      )
    );
  }
  return false;
}

function originsHaveSameUrlOrigin(left: string, right: string) {
  const leftOrigin = originFromUnknown(left);
  const rightOrigin = originFromUnknown(right);
  return leftOrigin !== null && rightOrigin !== null && leftOrigin === rightOrigin;
}

function passkeyCeremonyMirrorHasRequiredPayload(
  candidate: Partial<PasskeyCeremonyContext>
) {
  if (
    candidate.phase === "s4_completion_and_mutation" ||
    candidate.phase === "closed_aborted" ||
    candidate.phase === "closed_delivered" ||
    candidate.phase === "closed_failed"
  ) {
    return true;
  }

  if (
    passkeyCeremonyMirrorPhaseRequiresVaultBinding(candidate.phase) &&
    !passkeyNonemptyString(candidate.activeVaultId)
  ) {
    return false;
  }
  if (!passkeyCeremonyMirrorPhaseOriginIsConsistent(candidate)) {
    return false;
  }

  if (candidate.ceremony === "get") {
    return (
      passkeyGetCredentialIdsAreSafe(candidate.getCredentialIds) &&
      passkeyGetClientExtensionResultsAreSafe(candidate.getClientExtensionResults) &&
      candidate.createUserName === undefined &&
      candidate.createUserDisplayName === undefined &&
      candidate.createUserHandleBase64url === undefined &&
      candidate.createPublicKeyAlgorithm === undefined &&
      candidate.createExcludeCredentialIds === undefined &&
      candidate.createClientExtensionResults === undefined
    );
  }

  if (candidate.ceremony === "create") {
    return (
      passkeyCreateRequestFromMirror(candidate as PasskeyCeremonyContext) !== null &&
      candidate.getCredentialIds === undefined &&
      candidate.getClientExtensionResults === undefined
    );
  }

  return false;
}

function passkeyCeremonyMirrorPhaseRequiresVaultBinding(phase: unknown) {
  return (
    phase === "s2_network_validation" ||
    phase === "s3_credential_resolution" ||
    phase === "s3b_user_selection"
  );
}

function passkeyCeremonyMirrorPhaseOriginIsConsistent(
  candidate: Partial<PasskeyCeremonyContext>
) {
  if (
    candidate.phase === "s2_network_validation" &&
    typeof candidate.origin === "string" &&
    typeof candidate.relyingParty === "string"
  ) {
    return (
      !originMatchesRelyingParty(candidate.origin, candidate.relyingParty) &&
      originCanUseRelatedOriginVerification(candidate.origin, candidate.relyingParty) &&
      candidate.relatedOriginVerified !== true
    );
  }

  return true;
}

function restorePasskeyCeremonyPromptState(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  mirror: PasskeyCeremonyContext
) {
  if (
    typeof mirror.popupNonce !== "string" ||
    mirror.popupNonce.trim() === "" ||
    (mirror.promptMode !== "approve" &&
      mirror.promptMode !== "unlock" &&
      mirror.promptMode !== "verify") ||
    !passkeyCeremonyPhaseCanRestorePrompt(mirror.phase, mirror.promptMode) ||
    !passkeyCeremonyMirrorCanRestorePrompt(mirror)
  ) {
    return false;
  }

  const promptContext = promptContextFromMirror(mirror);
  if (!promptContext) {
    return false;
  }

  if (mirror.promptMode === "approve") {
    restorePromptState(
      chromeApi,
      sendRuntimeCommand,
      promptStates.approve,
      PROMPT_WINDOW_CONFIGS.approve,
      clearPresencePromptState,
      mirror,
      promptContext
    );
    return true;
  }

  if (mirror.promptMode === "verify") {
    if (!passkeyNonemptyString(mirror.activeVaultId)) {
      return false;
    }
    restorePromptState(
      chromeApi,
      sendRuntimeCommand,
      promptStates.verify,
      PROMPT_WINDOW_CONFIGS.verify,
      clearUserVerificationPromptState,
      mirror,
      {
        ...promptContext,
        ceremonyToken: mirror.ceremonyToken,
        activeVaultId: mirror.activeVaultId
      }
    );
    return true;
  }

  restorePromptState(
    chromeApi,
    sendRuntimeCommand,
    promptStates.unlock,
    PROMPT_WINDOW_CONFIGS.unlock,
    clearUnlockPromptState,
    mirror,
    promptContext
  );
  return true;
}

function restorePromptState<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  state: PromptState<TContext, TCompleteSignal>,
  config: PromptWindowConfig,
  clearPromptState: PromptClearState,
  mirror: PasskeyCeremonyContext,
  promptContext: TContext
) {
  state.contexts.set(mirror.ceremonyToken, promptContext);
  state.nonces.set(mirror.ceremonyToken, mirror.popupNonce ?? "");
  state.requestIds.set(mirror.ceremonyToken, mirror.requestId);
  state.requestKeys.set(
    mirror.ceremonyToken,
    webAuthnRequestCancelKeyFromMirror(mirror)
  );
  restorePromptWindow(
    chromeApi,
    sendRuntimeCommand,
    state,
    config,
    clearPromptState,
    mirror
  );
}

function restorePromptWindow<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  state: PromptState<TContext, TCompleteSignal>,
  config: PromptWindowConfig,
  clearPromptState: PromptClearState,
  mirror: PasskeyCeremonyContext
) {
  if (typeof mirror.promptWindowId !== "number") {
    return;
  }
  state.windowIds.set(mirror.ceremonyToken, mirror.promptWindowId);
  watchPromptWindow(
    chromeApi,
    state,
    config,
    clearPromptState,
    mirror.requestId,
    mirror.ceremonyToken,
    mirror.promptWindowId,
    () => {
      void completeRestoredPasskeyPromptDismissal(
        chromeApi,
        sendRuntimeCommand,
        mirror
      );
    }
  );
}

async function completeRestoredPasskeyPromptDismissal(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  mirror: PasskeyCeremonyContext
) {
  const error = userAbortWebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey prompt was dismissed"
  );
  await closePasskeyCeremonyForError(
    chromeApi,
    sendRuntimeCommand,
    mirror.ceremonyToken,
    mirror.phase,
    error
  );
  await completePasskeyRequestWithError(
    chromeApi,
    mirror.ceremony,
    mirror.requestId,
    mirror.ceremonyToken,
    error
  );
}

function passkeyCeremonyMirrorForPhase(
  mirror: PasskeyCeremonyContext,
  phase: PasskeyCeremonyPhase
): PasskeyCeremonyContext {
  if (phase === "s1_user_authorization" || phase === "s3b_user_selection") {
    return mirror;
  }

  const nextMirror = { ...mirror };
  delete nextMirror.popupNonce;
  delete nextMirror.promptMode;
  delete nextMirror.promptWindowId;
  delete nextMirror.promptCredentialOptions;
  return nextMirror;
}

function passkeyCeremonyPhaseCanRestorePrompt(
  phase: string,
  promptMode: "approve" | "unlock" | "verify"
) {
  if (promptMode === "unlock" || promptMode === "verify") {
    return phase === "s1_user_authorization";
  }
  return phase === "s1_user_authorization" || phase === "s3b_user_selection";
}

function passkeyCeremonyMirrorCanRestorePrompt(mirror: PasskeyCeremonyContext) {
  if (mirror.phase === "s3b_user_selection") {
    return (
      mirror.ceremony === "get" &&
      passkeyNonemptyString(mirror.activeVaultId) &&
      passkeyGetClientExtensionResultsAreSafe(mirror.getClientExtensionResults) &&
      passkeyCredentialOptionsAreUiSafe(mirror.promptCredentialOptions) &&
      mirror.promptCredentialOptions.length > 0
    );
  }

  if (mirror.phase !== "s1_user_authorization") {
    return false;
  }

  if (
    (mirror.promptMode === "approve" || mirror.promptMode === "verify") &&
    !passkeyNonemptyString(mirror.activeVaultId)
  ) {
    return false;
  }

  if (mirror.ceremony === "get") {
    return (
      passkeyGetCredentialIdsAreSafe(mirror.getCredentialIds) &&
      passkeyGetClientExtensionResultsAreSafe(mirror.getClientExtensionResults)
    );
  }

  return passkeyCreateRequestFromMirror(mirror) !== null;
}

function passkeyNonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function promptContextFromMirror(
  mirror: PasskeyCeremonyContext
): WebAuthnPromptContext | null {
  const credentialOptions = mirror.promptCredentialOptions ?? [];
  if (!passkeyCredentialOptionsAreUiSafe(credentialOptions)) {
    return null;
  }
  if (mirror.phase !== "s3b_user_selection" && credentialOptions.length > 0) {
    return null;
  }

  return {
    origin: mirror.origin,
    topOrigin: mirror.topOrigin,
    ancestorOrigins: mirror.ancestorOrigins,
    relyingParty: mirror.relyingParty,
    ...(credentialOptions.length > 0 ? { credentialOptions } : {})
  };
}

function passkeyCredentialOptionsAreUiSafe(
  options: unknown
): options is PasskeyCredentialOption[] {
  return (
    Array.isArray(options) &&
    options.every((option) => {
      const candidate = option as Partial<PasskeyCredentialOption> | null;
      return (
        Boolean(candidate) &&
        typeof candidate?.credentialId === "string" &&
        candidate.credentialId.trim() !== "" &&
        typeof candidate.username === "string" &&
        Object.keys(candidate).every(
          (key) => key === "credentialId" || key === "username"
        )
      );
    })
  );
}

function passkeyGetCredentialIdsAreSafe(
  credentialIds: unknown
): credentialIds is Array<string | null> {
  if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
    return false;
  }
  if (credentialIds.length === 1 && credentialIds[0] === null) {
    return true;
  }
  return credentialIds.every(
    (credentialId) =>
      typeof credentialId === "string" && credentialId.trim() !== ""
  );
}

function passkeyGetCredentialIdsAreDiscoverable(
  credentialIds: Array<string | null> | undefined
) {
  return (
    Array.isArray(credentialIds) &&
    credentialIds.length === 1 &&
    credentialIds[0] === null
  );
}

function passkeyGetClientExtensionResultsAreSafe(
  results: unknown
): results is Record<string, unknown> {
  if (!results || typeof results !== "object" || Array.isArray(results)) {
    return false;
  }

  const record = results as Record<string, unknown>;
  return Object.keys(record).every((key) => key === "appid") &&
    (record.appid === undefined || record.appid === false);
}

function getClientExtensionResultsFromMirror(mirror: PasskeyCeremonyContext) {
  return passkeyGetClientExtensionResultsAreSafe(mirror.getClientExtensionResults)
    ? mirror.getClientExtensionResults
    : {};
}

function passkeyCreateRequestFromMirror(mirror: PasskeyCeremonyContext) {
  if (
    typeof mirror.createUserName !== "string" ||
    mirror.createUserName.trim() === "" ||
    typeof mirror.createUserHandleBase64url !== "string" ||
    mirror.createUserHandleBase64url.trim() === "" ||
    mirror.createPublicKeyAlgorithm !== -7 ||
    !passkeyStringListIsSafe(mirror.createExcludeCredentialIds) ||
    !passkeyCreateClientExtensionResultsAreSafe(mirror.createClientExtensionResults)
  ) {
    return null;
  }

  return {
    userName: mirror.createUserName,
    userDisplayName:
      typeof mirror.createUserDisplayName === "string"
        ? mirror.createUserDisplayName
        : null,
    userHandleBase64url: mirror.createUserHandleBase64url,
    publicKeyAlgorithm: mirror.createPublicKeyAlgorithm,
    excludeCredentialIds: mirror.createExcludeCredentialIds,
    clientExtensionResults: mirror.createClientExtensionResults
  };
}

function passkeyStringListIsSafe(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === "string" && item.trim() !== "")
  );
}

function passkeyCreateClientExtensionResultsAreSafe(
  results: unknown
): results is Record<string, unknown> {
  if (!results || typeof results !== "object" || Array.isArray(results)) {
    return false;
  }

  const record = results as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 0) {
    return true;
  }
  if (keys.length !== 1 || keys[0] !== "credProps") {
    return false;
  }
  const credProps = record.credProps as { rk?: unknown } | null;
  return (
    Boolean(credProps) &&
    typeof credProps === "object" &&
    !Array.isArray(credProps) &&
    credProps.rk === true &&
    Object.keys(credProps).every((key) => key === "rk")
  );
}

function passkeyCeremonyLedgerKnown(response: unknown) {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "passkey_ceremony_ledger" &&
    (response as { known?: unknown }).known === true
  );
}

function passkeyCeremonyLedgerUnknown(response: unknown) {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "passkey_ceremony_ledger" &&
    (response as { known?: unknown }).known === false
  );
}

function passkeyCeremonyLedgerPhase(response: unknown) {
  const phase = (response as { phase?: unknown } | null)?.phase;
  return typeof phase === "string" ? phase : null;
}

function passkeyCeremonyLedgerDurableState(response: unknown) {
  const candidate = response as
    | { durableState?: unknown; durable_state?: unknown }
    | null;
  const durableState = candidate?.durableState ?? candidate?.durable_state;
  return typeof durableState === "string" ? durableState : null;
}

function passkeyCeremonyLedgerDeliveryState(response: unknown) {
  const candidate = response as
    | { deliveryState?: unknown; delivery_state?: unknown }
    | null;
  const deliveryState = candidate?.deliveryState ?? candidate?.delivery_state;
  if (deliveryState === "not-delivered") {
    return "not_delivered";
  }
  if (deliveryState === "unknown-delivery") {
    return "unknown_delivery";
  }
  return typeof deliveryState === "string" ? deliveryState : null;
}

function passkeyCeremonyLedgerDeliveryIsClosed(deliveryState: string | null) {
  return deliveryState === "delivered" || deliveryState === "unknown_delivery";
}

function isCompletionOrLaterPhase(phase: string) {
  return phase === "s4_completion_and_mutation" || phase.startsWith("closed_");
}

function passkeyCeremonyCanAdvanceMirrorPhase(
  mirror: PasskeyCeremonyContext,
  ledgerPhase: string
) {
  if (ledgerPhase === "s4_completion_and_mutation") {
    return false;
  }
  if (!passkeyCeremonyCanReachActivePhase(mirror, ledgerPhase)) {
    return false;
  }

  const advancedMirror = passkeyCeremonyMirrorForPhase(
    { ...mirror, phase: ledgerPhase as PasskeyCeremonyPhase },
    ledgerPhase as PasskeyCeremonyPhase
  );
  return passkeyCeremonyMirrorCanRepresentNativeAheadPhase(
    advancedMirror,
    ledgerPhase
  );
}

function passkeyCeremonyMirrorCanRepresentNativeAheadPhase(
  mirror: PasskeyCeremonyContext,
  ledgerPhase: string
) {
  if (ledgerPhase === "s3b_user_selection") {
    return passkeyCeremonyMirrorCanRestorePrompt(mirror);
  }
  return isPasskeyCeremonyMirror(mirror);
}

function passkeyCeremonyCanReachActivePhase(
  mirror: PasskeyCeremonyContext,
  to: string
) {
  const start = passkeyCeremonyActivePhaseFrom(mirror.phase);
  const target = passkeyCeremonyActivePhaseFrom(to);
  if (!start || !target || start === target) {
    return false;
  }

  const seen = new Set<PasskeyCeremonyActivePhase>([start]);
  const queue: PasskeyCeremonyActivePhase[] = [start];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      break;
    }
    for (const [edgeStart, edgeEnd] of PASSKEY_CEREMONY_TRANSITION_EDGES) {
      if (
        edgeStart !== current ||
        seen.has(edgeEnd) ||
        !passkeyCeremonyTransitionEdgeAllowed(mirror, edgeStart, edgeEnd)
      ) {
        continue;
      }
      if (edgeEnd === target) {
        return true;
      }
      seen.add(edgeEnd);
      queue.push(edgeEnd);
    }
  }

  return false;
}

function passkeyCeremonyTransitionEdgeAllowed(
  mirror: PasskeyCeremonyContext,
  from: PasskeyCeremonyActivePhase,
  to: PasskeyCeremonyActivePhase
) {
  if (from === "s1_user_authorization" && to === "s2_network_validation") {
    return (
      !originMatchesRelyingParty(mirror.origin, mirror.relyingParty) &&
      originCanUseRelatedOriginVerification(mirror.origin, mirror.relyingParty)
    );
  }
  if (from === "s1_user_authorization" && to === "s3_credential_resolution") {
    return originMatchesRelyingParty(mirror.origin, mirror.relyingParty);
  }
  if (from === "s2_network_validation" && to === "s3_credential_resolution") {
    return mirror.relatedOriginVerified === true;
  }
  return true;
}

function passkeyCeremonyActivePhaseIndex(phase: string) {
  const activePhase = passkeyCeremonyActivePhaseFrom(phase);
  return activePhase ? PASSKEY_CEREMONY_ACTIVE_PHASES.indexOf(activePhase) : -1;
}

function passkeyCeremonyActivePhaseFrom(
  phase: string
): PasskeyCeremonyActivePhase | null {
  return (PASSKEY_CEREMONY_ACTIVE_PHASES as readonly string[]).includes(phase)
    ? (phase as PasskeyCeremonyActivePhase)
    : null;
}

async function closePersistedNativePasskeyCeremony(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  ledgerPhase: string
) {
  if (passkeyCeremonyActivePhaseIndex(ledgerPhase) < 0) {
    return;
  }
  try {
    await advancePasskeyCeremonyPhase(
      sendRuntimeCommand,
      ceremonyToken,
      ledgerPhase,
      "closed_failed"
    );
  } catch {
    // The mirror is already unsafe to resume. Preserve the original recovery decision.
  }
}

function passkeyAssertionFromResponse(response: unknown): PasskeyAssertionResponse {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }

  const assertion = response as Partial<PasskeyAssertionResponse> | null;
  if (
    !assertion ||
    typeof assertion.credentialId !== "string" ||
    typeof assertion.authenticatorDataBase64url !== "string" ||
    typeof assertion.clientDataJsonBase64url !== "string" ||
    typeof assertion.signatureBase64url !== "string"
  ) {
    throw new InternalPasskeyRequestError(
      "runtime returned an invalid passkey assertion"
    );
  }
  return {
    credentialId: assertion.credentialId,
    authenticatorDataBase64url: assertion.authenticatorDataBase64url,
    clientDataJsonBase64url: assertion.clientDataJsonBase64url,
    signatureBase64url: assertion.signatureBase64url,
    userHandleBase64url:
      typeof assertion.userHandleBase64url === "string"
        ? assertion.userHandleBase64url
        : null
  };
}

function passkeyRegistrationFromResponse(response: unknown): PasskeyRegistrationResponse {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }

  const registration = response as Partial<PasskeyRegistrationResponse> | null;
  if (
    !registration ||
    typeof registration.entryId !== "string" ||
    typeof registration.credentialId !== "string" ||
    typeof registration.authenticatorDataBase64url !== "string" ||
    typeof registration.attestationObjectBase64url !== "string" ||
    typeof registration.clientDataJsonBase64url !== "string" ||
    typeof registration.publicKeyBase64url !== "string" ||
    typeof registration.publicKeyAlgorithm !== "number"
  ) {
    throw new InternalPasskeyRequestError(
      "runtime returned an invalid passkey registration"
    );
  }
  return {
    entryId: registration.entryId,
    credentialId: registration.credentialId,
    created: registration.created !== false,
    authenticatorDataBase64url: registration.authenticatorDataBase64url,
    attestationObjectBase64url: registration.attestationObjectBase64url,
    clientDataJsonBase64url: registration.clientDataJsonBase64url,
    publicKeyBase64url: registration.publicKeyBase64url,
    publicKeyAlgorithm: registration.publicKeyAlgorithm
  };
}

function passkeyCredentialStatusFromResponse(
  response: unknown
): PasskeyCredentialStatusResponse {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }

  const status = response as Partial<PasskeyCredentialStatusResponse> | null;
  if (
    !status ||
    typeof status.credentialId !== "string" ||
    typeof status.exists !== "boolean"
  ) {
    throw new InternalPasskeyRequestError(
      "runtime returned an invalid passkey credential status"
    );
  }
  return {
    credentialId: status.credentialId,
    exists: status.exists
  };
}

function passkeyCredentialStatusBatchFromResponse(
  response: unknown
): PasskeyCredentialStatusBatchResponse {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }

  const batch = response as Partial<{
    statuses: unknown;
  }> | null;
  if (!batch || !Array.isArray(batch.statuses)) {
    throw new InternalPasskeyRequestError(
      "runtime returned an invalid passkey credential status batch"
    );
  }

  return {
    statuses: batch.statuses.map(passkeyCredentialStatusFromResponse)
  };
}

function passkeyCredentialListFromResponse(
  response: unknown
): PasskeyCredentialListResponse {
  const runtimeError = runtimeErrorFromResponse(response);
  if (runtimeError) {
    throw runtimeError;
  }

  const list = response as { credentials?: unknown } | null;
  if (!list || !Array.isArray(list.credentials)) {
    throw new InternalPasskeyRequestError(
      "runtime returned an invalid passkey credential list"
    );
  }

  const credentials = list.credentials.map((credential) => {
    const candidate = credential as Partial<PasskeyCredentialListItem> | null;
    if (
      !candidate ||
      typeof candidate.credentialId !== "string" ||
      candidate.credentialId.trim() === "" ||
      typeof candidate.username !== "string"
    ) {
      throw new InternalPasskeyRequestError(
        "runtime returned an invalid passkey credential list"
      );
    }

    return {
      credentialId: candidate.credentialId,
      username: candidate.username,
      userHandle:
        typeof candidate.userHandle === "string" ? candidate.userHandle : null
    };
  });

  return { credentials };
}

async function registerPasskeyCeremony(
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown,
  requestId: number,
  ceremony: "get" | "create",
  originContext: WebAuthnOriginContext,
  relyingParty: string,
  discoverable: boolean,
  userVerification: PasskeyUserVerificationRequirement,
  challengeBase64url: string
): Promise<PasskeyCeremonyBaseContext> {
  const frame = frameContextFromRequest(request, originContext);
  const now = Date.now();
  const expiresAtEpochMs = now + 300_000;
  const ceremonyToken = newCeremonyToken();
  rememberPasskeyCeremonyToken(ceremonyToken);
  await reconcilePasskeyCeremonyLedgerBeforeRegistration(sendRuntimeCommand);
  const response = await sendRuntimeCommand({
    type: "register_passkey_ceremony",
    ceremony_token: ceremonyToken,
    connection_id: currentPasskeyLedgerConnectionId(),
    origin: originContext.origin,
    top_origin: originContext.topOrigin,
    ancestor_origins: originContext.ancestorOrigins,
    relying_party: relyingParty,
    ceremony,
    discoverable,
    user_verification: userVerification,
    challenge_base64url: challengeBase64url,
    request_id: requestId,
    tab_id: frame.tabId,
    frame_id: frame.frameId,
    frame_kind: frame.frameKind,
    registered_at_epoch_ms: now,
    expires_at_epoch_ms: expiresAtEpochMs
  });
  requireRuntimeResponseType(
    response,
    "passkey_ceremony_registered",
    "passkey ceremony registration did not return success",
    "registered"
  );

  return {
    version: 1,
    ceremonyToken,
    phase: "s0_pre_authorization",
    origin: originContext.origin,
    topOrigin: originContext.topOrigin,
    ancestorOrigins: originContext.ancestorOrigins,
    relyingParty,
    ceremony,
    userVerification,
    challengeBase64url,
    requestId,
    tabId: frame.tabId,
    frameId: frame.frameId,
    frameKind: frame.frameKind,
    registeredAtEpochMs: now,
    expiresAtEpochMs
  };
}

async function reconcilePasskeyCeremonyLedgerBeforeRegistration(
  sendRuntimeCommand: RuntimeCommandSender
) {
  const response = await sendRuntimeCommand({
    type: "reconcile_passkey_ceremony_ledger",
    active_connection_id: currentPasskeyLedgerConnectionId()
  });
  requirePasskeyCeremonyReconciliationSuccess(response);
}

async function advancePasskeyCeremonyPhase(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  expectedPhase: string,
  nextPhase: string,
  relatedOriginVerified = false
) {
  const response = await sendRuntimeCommand({
    type: "advance_passkey_ceremony_phase",
    ceremony_token: ceremonyToken,
    expected_phase: expectedPhase,
    next_phase: nextPhase,
    ...(relatedOriginVerified ? { related_origin_verified: true } : {})
  });
  requireRuntimeResponseType(
    response,
    "passkey_ceremony_advanced",
    "passkey ceremony phase advance did not return success",
    "advanced"
  );
}

async function bindPasskeyCeremonyVault(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  expectedPhase: string,
  vaultId: string
) {
  const response = await sendRuntimeCommand({
    type: "bind_passkey_ceremony_vault",
    ceremony_token: ceremonyToken,
    expected_phase: expectedPhase,
    vault_id: vaultId
  });
  requireRuntimeResponseType(
    response,
    "passkey_ceremony_vault_bound",
    "passkey ceremony vault binding did not return success",
    "bound"
  );
}

async function replayPasskeyCeremonyMirrorPhase(
  sendRuntimeCommand: RuntimeCommandSender,
  mirror: PasskeyCeremonyContext
) {
  const transitions = passkeyCeremonyReplayTransitions(mirror);
  if (!transitions) {
    return { replayedPhase: null, lastNativePhase: null };
  }

  let lastNativePhase = "s0_pre_authorization";
  for (const [expectedPhase, nextPhase, relatedOriginVerified] of transitions) {
    try {
      await advancePasskeyCeremonyPhase(
        sendRuntimeCommand,
        mirror.ceremonyToken,
        expectedPhase,
        nextPhase,
        relatedOriginVerified === true
      );
      lastNativePhase = nextPhase;
    } catch {
      return { replayedPhase: null, lastNativePhase };
    }
  }

  return { replayedPhase: mirror.phase, lastNativePhase };
}

function passkeyCeremonyReplayTransitions(
  mirror: PasskeyCeremonyContext
): Array<[string, string, boolean?]> | null {
  if (mirror.phase === "s0_pre_authorization") {
    return [];
  }
  if (mirror.phase === "s1_user_authorization") {
    return [["s0_pre_authorization", "s1_user_authorization"]];
  }
  if (mirror.phase === "s2_network_validation") {
    return [
      ["s0_pre_authorization", "s1_user_authorization"],
      ["s1_user_authorization", "s2_network_validation"]
    ];
  }
  if (mirror.phase === "s3_credential_resolution") {
    return passkeyCeremonyCredentialResolutionReplayTransitions(mirror);
  }
  if (mirror.phase === "s3b_user_selection") {
    const transitions = passkeyCeremonyCredentialResolutionReplayTransitions(mirror);
    return transitions
      ? [...transitions, ["s3_credential_resolution", "s3b_user_selection"]]
      : null;
  }

  return null;
}

function passkeyCeremonyCredentialResolutionReplayTransitions(
  mirror: PasskeyCeremonyContext
): Array<[string, string, boolean?]> | null {
  if (originMatchesRelyingParty(mirror.origin, mirror.relyingParty)) {
    return [
      ["s0_pre_authorization", "s1_user_authorization"],
      ["s1_user_authorization", "s3_credential_resolution"]
    ];
  }
  if (mirror.relatedOriginVerified === true) {
    return [
      ["s0_pre_authorization", "s1_user_authorization"],
      ["s1_user_authorization", "s2_network_validation"],
      ["s2_network_validation", "s3_credential_resolution", true]
    ];
  }
  return null;
}

async function markPasskeyCeremonyDelivered(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string
): Promise<boolean> {
  try {
    await advancePasskeyCeremonyPhase(
      sendRuntimeCommand,
      ceremonyToken,
      "s4_completion_and_mutation",
      "closed_delivered"
    );
    return true;
  } catch {
    // External delivery already happened. Native reconciliation can recover ledger state.
    return false;
  }
}

async function markPasskeyCeremonyUnknownDelivery(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string | null
) {
  if (!ceremonyToken) {
    return false;
  }
  try {
    const response = await sendRuntimeCommand({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation"
    });
    requireRuntimeResponseType(
      response,
      "passkey_ceremony_advanced",
      "passkey unknown-delivery mark did not return success",
      "advanced"
    );
    return true;
  } catch {
    return false;
  }
}

async function abortPasskeyRegistration(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  closedPhase: "closed_aborted" | "closed_failed"
) {
  try {
    await abortPasskeyRegistrationStrict(sendRuntimeCommand, ceremonyToken, closedPhase);
    return true;
  } catch {
    return false;
  }
}

async function abortPasskeyRegistrationStrict(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  closedPhase: "closed_aborted" | "closed_failed"
) {
  const response = await sendRuntimeCommand({
    type: "abort_passkey_registration",
    ceremony_token: ceremonyToken,
    expected_phase: "s4_completion_and_mutation",
    closed_phase: closedPhase
  });
  requireRuntimeResponseType(
    response,
    "saved",
    "passkey registration abort did not return success"
  );
}

async function closePasskeyCeremonyForError(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string | null,
  ceremonyPhase: string | null,
  error: unknown
) {
  const closedPhase = isUserAbortError(error) ? "closed_aborted" : "closed_failed";
  await closePasskeyCeremony(
    chromeApi,
    sendRuntimeCommand,
    ceremonyToken,
    ceremonyPhase,
    closedPhase
  );
}

async function abortS4PasskeyCreateCeremony(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string | null,
  ceremonyPhase: string | null,
  closedPhase: "closed_aborted" | "closed_failed"
) {
  if (!ceremonyToken || ceremonyPhase !== "s4_completion_and_mutation") {
    return false;
  }

  const aborted = await abortPasskeyRegistration(
    sendRuntimeCommand,
    ceremonyToken,
    closedPhase
  );
  if (!aborted) {
    return false;
  }
  await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
  return true;
}

async function closePasskeyCeremony(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string | null,
  ceremonyPhase: string | null,
  closedPhase: "closed_aborted" | "closed_failed"
) {
  await closePromptWindowsForCeremony(chromeApi, ceremonyToken);
  if (!ceremonyToken || !ceremonyPhase || ceremonyPhase.startsWith("closed_")) {
    return;
  }

  try {
    await advancePasskeyCeremonyPhase(
      sendRuntimeCommand,
      ceremonyToken,
      ceremonyPhase,
      closedPhase
    );
    await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
  } catch {
    // Preserve the original WebAuthn failure. Native reconciliation can audit stale ledgers.
  }
}

function isUserAbortError(error: unknown) {
  return error instanceof WebAuthnRequestError && error.userAbort;
}

function throwIfWebAuthnRequestCanceled(
  canceledRequests: CanceledWebAuthnRequests,
  requestId: number,
  requestCancelKey: string | null
) {
  if (webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey)) {
    throw userAbortWebAuthnRequestError(
      "NotAllowedError",
      "VaultKern WebAuthn request was canceled"
    );
  }
}

function markWebAuthnRequestCanceled(
  canceledRequests: CanceledWebAuthnRequests,
  requestId: number,
  requestCancelKey: string | null
) {
  if (requestCancelKey) {
    canceledRequests.requestKeys.add(requestCancelKey);
    return;
  }
  canceledRequests.legacyRequestIds.add(requestId);
}

function clearWebAuthnRequestCanceled(
  canceledRequests: CanceledWebAuthnRequests,
  requestId: number,
  requestCancelKey: string | null
) {
  canceledRequests.legacyRequestIds.delete(requestId);
  if (requestCancelKey) {
    canceledRequests.requestKeys.delete(requestCancelKey);
  }
}

function webAuthnRequestIsCanceled(
  canceledRequests: CanceledWebAuthnRequests,
  requestId: number,
  requestCancelKey: string | null
) {
  return (
    canceledRequests.legacyRequestIds.has(requestId) ||
    (Boolean(requestCancelKey) && canceledRequests.requestKeys.has(requestCancelKey as string))
  );
}

function webAuthnRequestCancelKeyFromRequest(
  request: unknown,
  requestId: number
): string | null {
  const candidate = request as { tabId?: unknown; frameId?: unknown } | null | undefined;
  if (typeof candidate?.tabId !== "number" || typeof candidate.frameId !== "number") {
    return null;
  }
  return webAuthnRequestCancelKey(requestId, candidate.tabId, candidate.frameId);
}

function webAuthnRequestCancelKeyFromMirror(mirror: PasskeyCeremonyContext) {
  return webAuthnRequestCancelKey(mirror.requestId, mirror.tabId, mirror.frameId);
}

function webAuthnRequestCancelKey(requestId: number, tabId: number, frameId: number) {
  return `${requestId}:${tabId}:${frameId}`;
}

function frameContextFromRequest(
  request: unknown,
  originContext: WebAuthnOriginContext
) {
  const candidate = request as
    | { tabId?: unknown; frameId?: unknown }
    | null
    | undefined;
  const frame =
    typeof candidate?.tabId === "number" && typeof candidate.frameId === "number"
      ? { tabId: candidate.tabId, frameId: candidate.frameId }
      : originContext.trustedFrame;
  if (!frame) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern cannot identify the WebAuthn request frame"
    );
  }
  if (
    frame.frameId === 0 &&
    (originContext.topOrigin || originContext.ancestorOrigins.length > 0)
  ) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern cannot identify the WebAuthn request frame"
    );
  }
  if (frame.frameId !== 0 && !originContext.topOrigin) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern cannot identify the WebAuthn request frame"
    );
  }
  if (frame.frameId !== 0 && originContext.ancestorOrigins.length === 0) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern cannot identify the WebAuthn request frame"
    );
  }

  return {
    tabId: frame.tabId,
    frameId: frame.frameId,
    frameKind: frame.frameId === 0 ? "top" : "subframe"
  };
}

function newCeremonyToken() {
  return secureRandomBase64url(16);
}

export function currentPasskeyLedgerConnectionId() {
  if (!passkeyLedgerConnectionId) {
    passkeyLedgerConnectionId = secureRandomBase64url(16);
  }
  return passkeyLedgerConnectionId;
}

export function resetPasskeyLedgerConnectionId() {
  passkeyLedgerConnectionId = null;
}

export function resetObservedWebAuthnPageRequestsForTest() {
  observedPageRequests.length = 0;
  passkeyCeremonyMirrorCache = new WeakMap();
}

function secureRandomBase64url(byteLength: number) {
  const bytes = new Uint8Array(byteLength);
  const cryptoApi = (globalThis as typeof globalThis & { crypto?: Crypto }).crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern secure random source is unavailable"
    );
  }
  cryptoApi.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

async function handleCreateRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown,
  canceledRequests: CanceledWebAuthnRequests
) {
  const requestId = requestIdFrom(request);
  const requestCancelKey = webAuthnRequestCancelKeyFromRequest(request, requestId);
  let ceremonyToken: string | null = null;
  let ceremonyPhase: string | null = null;
  let ceremonyMirror: PasskeyCeremonyContext | null = null;
  let ceremonyCommitted = false;
  const throwIfRequestCanceled = () =>
    throwIfWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  const requestIsCanceled = () =>
    webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey);
  const advanceCeremony = createPasskeyCeremonyAdvancer({
    chromeApi,
    sendRuntimeCommand,
    ceremonyToken: () => ceremonyToken,
    ceremonyMirror: () => ceremonyMirror,
    updateCeremonyMirror: (mirror) => {
      ceremonyMirror = mirror;
    },
    updateCeremonyPhase: (phase) => {
      ceremonyPhase = phase;
    },
    missingCeremonyMessage: "passkey ceremony is not registered"
  });
  const {
    persistPresencePromptState,
    persistPromptWindowId,
    persistUnlockPromptState,
    persistUserVerificationPromptState
  } = createPasskeyPromptMirrorPersistence(
    chromeApi,
    () => ceremonyMirror,
    (nextMirror) => {
      ceremonyMirror = nextMirror;
    }
  );
  await recordWebAuthnDebug(chromeApi, {
    event: "create_received",
    requestId,
    summary: requestSummaryFrom(request)
  });
  try {
    const options = createRequestOptionsFrom(request);
    rejectCrossPlatformOnlyRegistration(options);
    const userVerification = userVerificationRequirementFromOptions(options);
    const requestedRpId = relyingPartyIdFromCreateOptions(options);
    const originContext = await originContextForRequest(request, "create", options);
    if (!originContext) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    const origin = originContext.origin;
    rejectUnsupportedMediation(options.mediation);
    rejectNonSecureWebAuthnOrigin(origin);
    const relyingParty = relyingPartyFromCreateOptions(options, origin);
    let relyingPartyValidation = requestedRpId
      ? await validateOriginForRelyingParty(origin, requestedRpId)
      : { allowed: true, relatedOriginVerified: false };
    if (!relyingPartyValidation.allowed) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }
    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.create",
      options.challenge,
      originContext
    );
    const ceremonyContext = await registerPasskeyCeremony(
      sendRuntimeCommand,
      request,
      requestId,
      "create",
      originContext,
      relyingParty,
      false,
      userVerification,
      String(options.challenge)
    );
    ceremonyToken = ceremonyContext.ceremonyToken;
    ceremonyPhase = "s0_pre_authorization";
    ceremonyMirror = {
      ...ceremonyContext,
      createUserName: userNameFromCreateOptions(options),
      createUserDisplayName: userDisplayNameFromCreateOptions(options),
      createUserHandleBase64url: userHandleFromCreateOptions(options),
      createPublicKeyAlgorithm: publicKeyAlgorithmFromCreateOptions(options),
      createExcludeCredentialIds: excludedCredentialIdsFromCreateOptions(options),
      createClientExtensionResults: clientExtensionResultsForCreateOptions(options)
    };
    await persistPasskeyCeremonyMirror(chromeApi, ceremonyMirror);

    const session = (await sendRuntimeCommand({
      type: "get_session_state"
    })) as { activeVaultId?: string | null };
    await recordWebAuthnDebug(chromeApi, {
      event: "create_session_state",
      requestId,
      hasActiveVault: Boolean(session.activeVaultId)
    });
    throwIfRequestCanceled();
    await advanceCeremony("s0_pre_authorization", "s1_user_authorization");
    const activeVault = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      session,
      promptContextFrom(originContext, relyingParty),
      canceledRequests,
      requestCancelKey,
      {
        onPromptPrepared: persistUnlockPromptState,
        onPromptOpened: persistPromptWindowId
      }
    );
    if (!activeVault) {
      throwIfRequestCanceled();
      return;
    }
    if (ceremonyMirror) {
      ceremonyMirror = {
        ...ceremonyMirror,
        activeVaultId: activeVault.activeVaultId
      };
      await persistPasskeyCeremonyMirror(chromeApi, ceremonyMirror);
    }
    await bindPasskeyCeremonyVault(
      sendRuntimeCommand,
      ceremonyContext.ceremonyToken,
      "s1_user_authorization",
      activeVault.activeVaultId
    );
    let userPresenceVerified = activeVault.userPresenceVerified;
    let userVerified = await verifyPasskeyUserFromUnlockProof(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      activeVault.activeVaultId,
      userVerification,
      activeVault.unlockUserVerificationProof
    );
    if (!userVerified) {
      userVerified = await userVerificationForRequest(
        chromeApi,
        sendRuntimeCommand,
        requestId,
        ceremonyContext.ceremonyToken,
        activeVault.activeVaultId,
        userVerification,
        promptContextFrom(originContext, relyingParty),
        canceledRequests,
        requestCancelKey,
        {
          onPromptPrepared: persistUserVerificationPromptState,
          onPromptOpened: persistPromptWindowId
        }
      );
    }
    if (userVerified) {
      userPresenceVerified = true;
    }
    if (!userPresenceVerified) {
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        ceremonyContext.ceremonyToken,
        promptContextFrom(originContext, relyingParty),
        canceledRequests,
        requestCancelKey,
        {
          onPromptPrepared: persistPresencePromptState,
          onPromptOpened: persistPromptWindowId
        }
      );
      if (!approved) {
        throwIfRequestCanceled();
        return;
      }
      userPresenceVerified = true;
    }
    throwIfRequestCanceled();
    relyingPartyValidation = await advanceToCredentialResolution(
      origin,
      relyingParty,
      relyingPartyValidation,
      advanceCeremony,
      () => {
        if (ceremonyMirror) {
          ceremonyMirror = { ...ceremonyMirror, relatedOriginVerified: true };
        }
      }
    );
    const activeVaultId = activeVault.activeVaultId;

    const excludedCredentialIds = excludedCredentialIdsFromCreateOptions(options);
    throwIfRequestCanceled();
    const excludedCredentialStatuses = await excludedCredentialStatusesForCreateRequest(
      sendRuntimeCommand,
      ceremonyContext.ceremonyToken,
      activeVaultId,
      relyingParty,
      excludedCredentialIds
    );
    throwIfRequestCanceled();
    if (excludedCredentialStatuses.some((status) => status.exists)) {
      throw new WebAuthnRequestError(
        "InvalidStateError",
        "VaultKern passkey credential is already registered"
      );
    }

    await advanceCeremony("s3_credential_resolution", "s4_completion_and_mutation");
    const registrationResponse = await sendRuntimeCommand({
      type: "create_passkey_registration",
      ceremony_token: ceremonyContext.ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      vault_id: activeVaultId,
      relying_party: relyingParty,
      origin,
      user_name: userNameFromCreateOptions(options),
      user_display_name: userDisplayNameFromCreateOptions(options),
      user_handle_base64url: userHandleFromCreateOptions(options),
      public_key_algorithm: publicKeyAlgorithmFromCreateOptions(options),
      ...(relyingPartyValidation.relatedOriginVerified
        ? { related_origin_verified: true }
        : {}),
      client_data_json_base64url: clientDataJsonBase64url
    });
    const registration = passkeyRegistrationFromResponse(registrationResponse);
    const abortRegistration = async (
      closedPhase: "closed_aborted" | "closed_failed"
    ) => {
      await abortPasskeyRegistrationStrict(
        sendRuntimeCommand,
        ceremonyContext.ceremonyToken,
        closedPhase
      );
      ceremonyPhase = closedPhase;
      await clearPasskeyCeremonyMirror(chromeApi, ceremonyContext.ceremonyToken);
    };
    const markCommittedRegistrationUnknownDelivery = async () => {
      const marked = await markPasskeyCeremonyUnknownDelivery(
        sendRuntimeCommand,
        ceremonyContext.ceremonyToken
      );
      if (marked) {
        ceremonyPhase = "closed_delivered";
        await clearPasskeyCeremonyMirror(chromeApi, ceremonyContext.ceremonyToken);
      }
    };
    await recordWebAuthnDebug(chromeApi, {
      event: "create_runtime_registration",
      requestId,
      relyingParty,
      origin,
      credentialId: registration.credentialId
    });
    if (requestIsCanceled()) {
      await abortRegistration("closed_aborted");
      return;
    }

    try {
      await savePasskeyRegistration(
        sendRuntimeCommand,
        ceremonyContext.ceremonyToken,
        activeVaultId
      );
    } catch (error) {
      await abortRegistration("closed_failed");
      throw error;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "create_saved",
      requestId
    });
    if (requestIsCanceled()) {
      await abortRegistration("closed_aborted");
      return;
    }

    await commitPasskeyRegistration(
      sendRuntimeCommand,
      ceremonyContext.ceremonyToken,
      activeVaultId,
      registration.entryId,
      registration.credentialId
    );
    ceremonyCommitted = true;
    if (requestIsCanceled()) {
      await markCommittedRegistrationUnknownDelivery();
      return;
    }
    const delivered = await deliverPasskeyCreateRegistration(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      ceremonyContext.ceremonyToken,
      registration,
      clientExtensionResultsForCreateOptions(options),
      {
        completeError: "create_complete_error",
        completed: "create_completed"
      }
    );
    if (!delivered) {
      await markCommittedRegistrationUnknownDelivery();
      return;
    }
    ceremonyPhase = "closed_delivered";
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "create_error",
      requestId,
      error: errorSummary(error)
    });
    if (requestIsCanceled()) {
      if (!ceremonyCommitted) {
        if (
          !(await abortS4PasskeyCreateCeremony(
            chromeApi,
            sendRuntimeCommand,
            ceremonyToken,
            ceremonyPhase,
            "closed_aborted"
          ))
        ) {
          await closePasskeyCeremony(
            chromeApi,
            sendRuntimeCommand,
            ceremonyToken,
            ceremonyPhase,
            "closed_aborted"
          );
        }
      } else {
        await markPasskeyCeremonyUnknownDelivery(
          sendRuntimeCommand,
          ceremonyToken
        );
        await clearPasskeyCeremonyMirror(chromeApi, ceremonyToken);
      }
      return;
    }
    if (!ceremonyCommitted) {
      const closedPhase = isUserAbortError(error) ? "closed_aborted" : "closed_failed";
      if (
        !(await abortS4PasskeyCreateCeremony(
          chromeApi,
          sendRuntimeCommand,
          ceremonyToken,
          ceremonyPhase,
          closedPhase
        ))
      ) {
        await closePasskeyCeremony(
          chromeApi,
          sendRuntimeCommand,
          ceremonyToken,
          ceremonyPhase,
          closedPhase
        );
      }
    }
    await completePasskeyRequestWithError(
      chromeApi,
      "create",
      requestId,
      ceremonyToken,
      error
    );
  } finally {
    clearWebAuthnRequestCanceled(canceledRequests, requestId, requestCancelKey);
  }
}

function requestIdFrom(request: unknown) {
  const requestId = (request as { requestId?: unknown } | null)?.requestId;
  if (typeof requestId !== "number") {
    throw new WebAuthnRequestError("UnknownError", "missing WebAuthn request id");
  }
  return requestId;
}

function requestOptionsFrom(request: unknown) {
  const requestDetailsJson = (request as { requestDetailsJson?: unknown } | null)
    ?.requestDetailsJson;
  if (typeof requestDetailsJson !== "string") {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "missing WebAuthn request details"
    );
  }

  const options = JSON.parse(requestDetailsJson) as {
    rpId?: unknown;
    challenge?: unknown;
    allowCredentials?: unknown;
    userVerification?: unknown;
    mediation?: unknown;
    extensions?: { appid?: unknown };
  };
  if (typeof options.challenge !== "string") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn challenge");
  }
  return options;
}

function createRequestOptionsFrom(request: unknown) {
  const requestDetailsJson = (request as { requestDetailsJson?: unknown } | null)
    ?.requestDetailsJson;
  if (typeof requestDetailsJson !== "string") {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "missing WebAuthn request details"
    );
  }

  const options = JSON.parse(requestDetailsJson) as {
    rp?: { id?: unknown; name?: unknown };
    user?: { id?: unknown; name?: unknown; displayName?: unknown };
    challenge?: unknown;
    pubKeyCredParams?: unknown;
    excludeCredentials?: unknown;
    userVerification?: unknown;
    mediation?: unknown;
    extensions?: {
      credProps?: unknown;
    };
    authenticatorSelection?: {
      authenticatorAttachment?: unknown;
      userVerification?: unknown;
    };
  };
  if (typeof options.challenge !== "string") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn challenge");
  }
  validateCreateUserHandleOption(options);
  if (
    Array.isArray(options.pubKeyCredParams) &&
    options.pubKeyCredParams.length > 0 &&
    !options.pubKeyCredParams.some(
      (param) =>
        typeof param === "object" &&
        param !== null &&
        (param as { type?: unknown }).type === "public-key" &&
        (param as { alg?: unknown }).alg === -7
    )
  ) {
    throw new WebAuthnRequestError(
      "NotSupportedError",
      "VaultKern passkey registration requires ES256"
    );
  }
  return options;
}

function clientExtensionResultsForGetOptions(options: {
  extensions?: { appid?: unknown };
}) {
  if (
    options.extensions &&
    Object.prototype.hasOwnProperty.call(options.extensions, "appid")
  ) {
    return { appid: false };
  }

  return {};
}

function clientExtensionResultsForCreateOptions(options: {
  extensions?: { credProps?: unknown };
}) {
  if (options.extensions?.credProps === true) {
    return { credProps: { rk: true } };
  }

  return {};
}

function passkeyCreateCredentialResponseJson(
  registration: PasskeyRegistrationResponse,
  clientExtensionResults: Record<string, unknown>
) {
  return JSON.stringify({
    id: registration.credentialId,
    rawId: registration.credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults,
    response: {
      authenticatorData: registration.authenticatorDataBase64url,
      attestationObject: registration.attestationObjectBase64url,
      clientDataJSON: registration.clientDataJsonBase64url,
      publicKey: registration.publicKeyBase64url,
      publicKeyAlgorithm: registration.publicKeyAlgorithm,
      transports: ["internal"]
    }
  });
}

function passkeyGetCredentialResponseJson(
  assertion: PasskeyAssertionResponse,
  clientExtensionResults: Record<string, unknown>
) {
  return JSON.stringify({
    id: assertion.credentialId,
    rawId: assertion.credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults,
    response: {
      authenticatorData: assertion.authenticatorDataBase64url,
      clientDataJSON: assertion.clientDataJsonBase64url,
      signature: assertion.signatureBase64url,
      ...(typeof assertion.userHandleBase64url === "string"
        ? { userHandle: assertion.userHandleBase64url }
        : {})
    }
  });
}

function rejectCrossPlatformOnlyRegistration(options: {
  authenticatorSelection?: { authenticatorAttachment?: unknown };
}) {
  if (options.authenticatorSelection?.authenticatorAttachment !== "cross-platform") {
    return;
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey provider only supports platform authenticators"
  );
}

function rejectRequiredUserVerification(options: {
  userVerification?: unknown;
  authenticatorSelection?: { userVerification?: unknown };
}) {
  const userVerification =
    options.userVerification ?? options.authenticatorSelection?.userVerification;
  if (userVerification !== "required") {
    return;
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey provider does not support required user verification"
  );
}

function userVerificationRequirementFromOptions(options: {
  userVerification?: unknown;
  authenticatorSelection?: { userVerification?: unknown };
}): PasskeyUserVerificationRequirement {
  const userVerification =
    options.userVerification ?? options.authenticatorSelection?.userVerification;
  if (
    userVerification === "required" ||
    userVerification === "discouraged" ||
    userVerification === "preferred"
  ) {
    return userVerification;
  }
  return "preferred";
}

function rejectUnsupportedMediation(value: unknown) {
  const mediation = typeof value === "string" ? value : undefined;
  if (!mediation || mediation === "optional" || mediation === "required") {
    return;
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    `VaultKern passkey provider does not support ${mediation} mediation`
  );
}

function clientDataJsonBase64urlFrom(
  type: "webauthn.create" | "webauthn.get",
  challenge: unknown,
  originContext: WebAuthnOriginContext
) {
  const crossOrigin =
    (typeof originContext.topOrigin === "string" &&
      originContext.topOrigin !== originContext.origin) ||
    originContext.ancestorOrigins.some(
      (ancestorOrigin) => ancestorOrigin !== originContext.origin
    );
  return base64urlEncode(
    JSON.stringify({
      type,
      challenge,
      origin: originContext.origin,
      crossOrigin,
      ...(crossOrigin && originContext.topOrigin
        ? { topOrigin: originContext.topOrigin }
        : {})
    })
  );
}

function promptContextFrom(
  originContext: WebAuthnOriginContext,
  relyingParty: string,
  credentialOptions: PasskeyCredentialOption[] = []
): WebAuthnPromptContext {
  return {
    ...originContext,
    relyingParty,
    ...(credentialOptions.length > 0 ? { credentialOptions } : {})
  };
}

async function savePasskeyRegistration(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  vaultId: string
) {
  const saveResponse = await sendRuntimeCommand({
    type: "save_passkey_registration",
    ceremony_token: ceremonyToken,
    expected_phase: "s4_completion_and_mutation",
    vault_id: vaultId
  });
  requirePasskeySaveSuccess(saveResponse);
}

async function commitPasskeyRegistration(
  sendRuntimeCommand: RuntimeCommandSender,
  ceremonyToken: string,
  vaultId: string,
  entryId: string,
  credentialId: string
) {
  const commitResponse = await sendRuntimeCommand({
    type: "commit_passkey_registration",
    ceremony_token: ceremonyToken,
    expected_phase: "s4_completion_and_mutation",
    vault_id: vaultId,
    entry_id: entryId,
    credential_id: credentialId
  });
  requireRuntimeResponseType(
    commitResponse,
    "saved",
    "passkey registration commit did not return durable success"
  );
}

function relyingPartyIdFromGetOptions(options: { rpId?: unknown }) {
  if (options.rpId === undefined || options.rpId === null) {
    return null;
  }
  if (typeof options.rpId !== "string") {
    throw new WebAuthnRequestError("NotAllowedError", "invalid WebAuthn RP ID");
  }
  return normalizeExplicitRelyingPartyId(options.rpId);
}

function relyingPartyFromGetOptions(options: { rpId?: unknown }, origin: string) {
  return relyingPartyIdFromGetOptions(options) ?? relyingPartyFromOrigin(origin);
}

function relyingPartyIdFromCreateOptions(options: {
  rp?: { id?: unknown; name?: unknown };
}) {
  const rpId = options.rp?.id;
  if (rpId === undefined || rpId === null) {
    return null;
  }
  if (typeof rpId !== "string") {
    throw new WebAuthnRequestError("NotAllowedError", "invalid WebAuthn RP ID");
  }
  return normalizeExplicitRelyingPartyId(rpId);
}

function relyingPartyFromCreateOptions(
  options: { rp?: { id?: unknown; name?: unknown } },
  origin: string
) {
  return relyingPartyIdFromCreateOptions(options) ?? relyingPartyFromOrigin(origin);
}

function relyingPartyFromOrigin(origin: string) {
  try {
    const hostname = normalizedHostFromUrl(origin);
    if (hostname.trim() !== "") {
      return hostname;
    }
  } catch {
    // Fall through to the WebAuthn-shaped error below.
  }
  throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn RP ID");
}

function normalizeExplicitRelyingPartyId(value: string) {
  if (value.trim() === "" || value !== value.trim() || value.endsWith(".")) {
    throw new WebAuthnRequestError("NotAllowedError", "invalid WebAuthn RP ID");
  }
  return normalizeHost(value);
}

function originFromUnknown(value: unknown) {
  if (typeof value !== "string" || value.trim() === "" || value !== value.trim()) {
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

function optionalOriginFromUnknown(value: unknown) {
  if (value === undefined || value === null) {
    return undefined;
  }
  return originFromUnknown(value);
}

function originsArrayFromUnknown(value: unknown) {
  if (value === undefined || value === null) {
    return [];
  }

  if (!Array.isArray(value)) {
    return null;
  }

  const origins: string[] = [];
  for (const item of value) {
    const origin = originFromUnknown(item);
    if (!origin) {
      return null;
    }
    origins.push(origin);
  }
  return origins;
}

function topOriginFromRequestDetails(requestDetailsJson: unknown) {
  if (typeof requestDetailsJson !== "string") {
    return undefined;
  }

  try {
    const details = JSON.parse(requestDetailsJson) as {
      topOrigin?: unknown;
      ancestorOrigins?: unknown;
    };
    const ancestorOrigins = originsArrayFromUnknown(details.ancestorOrigins);
    if (!ancestorOrigins) {
      return null;
    }
    const topOrigin = optionalOriginFromUnknown(details.topOrigin);
    if (topOrigin === null) {
      return null;
    }
    return ancestorOrigins[ancestorOrigins.length - 1] ?? topOrigin;
  } catch {
    return undefined;
  }
}

function ancestorOriginsFromRequestDetails(requestDetailsJson: unknown) {
  if (typeof requestDetailsJson !== "string") {
    return [];
  }

  try {
    const details = JSON.parse(requestDetailsJson) as { ancestorOrigins?: unknown };
    return originsArrayFromUnknown(details.ancestorOrigins);
  } catch {
    return [];
  }
}

function originContextFromRequest(request: unknown) {
  const candidate = request as
    | {
        origin?: unknown;
        callerOrigin?: unknown;
        requestOrigin?: unknown;
        topOrigin?: unknown;
        callerTopOrigin?: unknown;
        topLevelOrigin?: unknown;
        ancestorOrigins?: unknown;
        requestDetailsJson?: unknown;
      }
    | null
    | undefined;
  let origin: string | null = null;
  for (const value of [
    candidate?.origin,
    candidate?.callerOrigin,
    candidate?.requestOrigin
  ]) {
    const parsedOrigin = originFromUnknown(value);
    if (parsedOrigin) {
      origin = parsedOrigin;
      break;
    }
  }

  if (typeof candidate?.requestDetailsJson === "string") {
    try {
      const details = JSON.parse(candidate.requestDetailsJson) as {
        origin?: unknown;
        topOrigin?: unknown;
      };
      const parsedOrigin = originFromUnknown(details.origin);
      if (!origin && parsedOrigin) {
        origin = parsedOrigin;
      }
    } catch {
      // Parsed elsewhere; keep this helper WebAuthn-shaped.
    }
  }

  if (!origin) {
    return null;
  }

  const topOriginCandidate = optionalOriginFromUnknown(candidate?.topOrigin);
  const callerTopOriginCandidate = optionalOriginFromUnknown(
    candidate?.callerTopOrigin
  );
  const topLevelOriginCandidate = optionalOriginFromUnknown(
    candidate?.topLevelOrigin
  );
  const detailsTopOrigin = topOriginFromRequestDetails(candidate?.requestDetailsJson);
  if (
    topOriginCandidate === null ||
    callerTopOriginCandidate === null ||
    topLevelOriginCandidate === null ||
    detailsTopOrigin === null
  ) {
    return null;
  }
  const topOrigin =
    topOriginCandidate ??
    callerTopOriginCandidate ??
    topLevelOriginCandidate ??
    detailsTopOrigin;
  const directAncestorOrigins = originsArrayFromUnknown(candidate?.ancestorOrigins);
  if (!directAncestorOrigins) {
    return null;
  }
  const detailsAncestorOrigins = ancestorOriginsFromRequestDetails(
    candidate?.requestDetailsJson
  );
  if (!detailsAncestorOrigins) {
    return null;
  }
  const ancestorOrigins =
    directAncestorOrigins.length > 0
      ? directAncestorOrigins
      : detailsAncestorOrigins;
  const mediation = mediationFromRequestDetails(candidate?.requestDetailsJson);

  return {
    origin,
    topOrigin: ancestorOrigins[ancestorOrigins.length - 1] ?? topOrigin ?? undefined,
    ancestorOrigins,
    mediation
  };
}

function trustedFrameIdsFromWebAuthnRequest(request: unknown) {
  const candidate = request as
    | { tabId?: unknown; frameId?: unknown }
    | null
    | undefined;
  return typeof candidate?.tabId === "number" && typeof candidate.frameId === "number"
    ? { tabId: candidate.tabId, frameId: candidate.frameId }
    : null;
}

function trustedWebAuthnMessageSenderContextFrom(sender: unknown) {
  const candidate = sender as
    | {
        origin?: unknown;
        url?: unknown;
        tab?: { id?: unknown };
        frameId?: unknown;
      }
    | null
    | undefined;
  const origin =
    originFromUnknown(candidate?.origin) ?? originFromSenderUrl(candidate?.url);
  if (
    !origin ||
    typeof candidate?.tab?.id !== "number" ||
    typeof candidate.frameId !== "number"
  ) {
    return null;
  }

  return {
    origin,
    tabId: candidate.tab.id,
    frameId: candidate.frameId
  };
}

function originFromSenderUrl(value: unknown) {
  if (typeof value !== "string" || value.trim() === "" || value !== value.trim()) {
    return null;
  }

  try {
    const parsed = new URL(value);
    if (parsed.username !== "" || parsed.password !== "") {
      return null;
    }
    return parsed.origin === "null" ? null : parsed.origin;
  } catch {
    return null;
  }
}

function mediationFromRequestDetails(requestDetailsJson: unknown) {
  if (typeof requestDetailsJson !== "string") {
    return undefined;
  }

  try {
    const details = JSON.parse(requestDetailsJson) as { mediation?: unknown };
    return typeof details.mediation === "string" ? details.mediation : undefined;
  } catch {
    return undefined;
  }
}

async function originContextForRequest(
  request: unknown,
  ceremony: "create" | "get",
  options: {
    challenge?: unknown;
    rpId?: unknown;
    rp?: { id?: unknown; name?: unknown };
    allowCredentials?: unknown;
    excludeCredentials?: unknown;
  }
) {
  const directOrigin = originContextFromRequest(request);
  if (directOrigin) {
    const requestFrameId = (request as { frameId?: unknown } | null | undefined)
      ?.frameId;
    const observedOrigin = originContextFromPageRequest(
      ceremony,
      options,
      directOrigin.origin
    );
    const observedAncestorChainTrusted =
      typeof requestFrameId === "number" &&
      requestFrameId !== 0 &&
      observedOrigin !== null &&
      observedOrigin.ancestorOrigins.length > 0;
    return observedOrigin
      ? {
          ...directOrigin,
          topOrigin: observedAncestorChainTrusted
            ? observedOrigin.topOrigin
            : directOrigin.topOrigin,
          ancestorOrigins: observedAncestorChainTrusted
            ? observedOrigin.ancestorOrigins
            : directOrigin.ancestorOrigins,
          mediation: directOrigin.mediation ?? observedOrigin.mediation
        }
      : directOrigin;
  }

  const requestFrame = trustedFrameIdsFromWebAuthnRequest(request);
  return waitForOriginContextFromPageRequest(
    ceremony,
    options,
    undefined,
    requestFrame ?? undefined,
    true
  );
}

function originContextFromPageRequest(
  ceremony: "create" | "get",
  options: {
    challenge?: unknown;
    rpId?: unknown;
    rp?: { id?: unknown; name?: unknown };
    allowCredentials?: unknown;
    excludeCredentials?: unknown;
  },
  expectedOrigin?: string,
  expectedFrame?: { tabId: number; frameId: number },
  requireTrustedSender = false
) {
  const challenge = typeof options.challenge === "string" ? options.challenge : null;
  if (!challenge) {
    return null;
  }

  const relyingParty =
    ceremony === "create"
      ? relyingPartyIdFromCreateOptions(options)
      : relyingPartyIdFromGetOptions(options);
  const expectedRelyingParty =
    relyingParty ?? (expectedOrigin ? relyingPartyFromOrigin(expectedOrigin) : null);
  const allowCredentialIds =
    ceremony === "get" ? credentialIdsFromOptions(options).filter(isString) : [];
  const excludeCredentialIds =
    ceremony === "create" ? excludedCredentialIdsFromCreateOptions(options) : [];
  const now = Date.now();
  pruneObservedPageRequests(now);

  for (let index = observedPageRequests.length - 1; index >= 0; index -= 1) {
    const observed = observedPageRequests[index];
    if (
      observed &&
      observedPageRequestMatches(observed, {
        ceremony,
        challenge,
        relyingParty: expectedRelyingParty,
        allowCredentialIds,
        excludeCredentialIds,
        expectedOrigin,
        expectedFrame,
        requireTrustedSender
      })
    ) {
      observedPageRequests.splice(index, 1);
      return {
        origin: observed.origin,
        topOrigin: observed.topOrigin,
        ancestorOrigins: observed.ancestorOrigins,
        mediation: observed.mediation,
        ...(typeof observed.trustedSenderTabId === "number" &&
        typeof observed.trustedSenderFrameId === "number"
          ? {
              trustedFrame: {
                tabId: observed.trustedSenderTabId,
                frameId: observed.trustedSenderFrameId
              }
            }
          : {})
      };
    }
  }

  return null;
}

async function waitForOriginContextFromPageRequest(
  ceremony: "create" | "get",
  options: {
    challenge?: unknown;
    rpId?: unknown;
    rp?: { id?: unknown; name?: unknown };
    allowCredentials?: unknown;
    excludeCredentials?: unknown;
  },
  expectedOrigin?: string,
  expectedFrame?: { tabId: number; frameId: number },
  requireTrustedSender = false
) {
  const deadline = Date.now() + OBSERVED_PAGE_REQUEST_WAIT_MS;
  for (;;) {
    const originContext = originContextFromPageRequest(
      ceremony,
      options,
      expectedOrigin,
      expectedFrame,
      requireTrustedSender
    );
    if (originContext || Date.now() >= deadline) {
      return originContext;
    }
    await delay(
      Math.min(OBSERVED_PAGE_REQUEST_POLL_MS, Math.max(0, deadline - Date.now()))
    );
  }
}

function observedPageRequestMatches(
  observed: ObservedWebAuthnPageRequest,
  expected: {
    ceremony: "create" | "get";
    challenge: string;
    relyingParty: string | null;
    allowCredentialIds: string[];
    excludeCredentialIds: string[];
    expectedOrigin?: string;
    expectedFrame?: { tabId: number; frameId: number };
    requireTrustedSender?: boolean;
  }
) {
  if (observed.ceremony !== expected.ceremony) {
    return false;
  }
  if (!observed.challenge || observed.challenge !== expected.challenge) {
    return false;
  }
  if (expected.expectedOrigin && observed.origin !== expected.expectedOrigin) {
    return false;
  }
  if (
    expected.requireTrustedSender &&
    (typeof observed.trustedSenderTabId !== "number" ||
      typeof observed.trustedSenderFrameId !== "number")
  ) {
    return false;
  }
  if (
    expected.expectedFrame &&
    (observed.trustedSenderTabId !== expected.expectedFrame.tabId ||
      observed.trustedSenderFrameId !== expected.expectedFrame.frameId)
  ) {
    return false;
  }
  if (
    expected.relyingParty &&
    observed.relyingParty !== expected.relyingParty
  ) {
    return false;
  }
  if (
    expected.allowCredentialIds.length > 0 &&
    (!observed.allowCredentialIds ||
      !sameStringSet(observed.allowCredentialIds, expected.allowCredentialIds))
  ) {
    return false;
  }
  if (
    expected.excludeCredentialIds.length > 0 &&
    (!observed.excludeCredentialIds ||
      !sameStringSet(observed.excludeCredentialIds, expected.excludeCredentialIds))
  ) {
    return false;
  }
  return true;
}

function pruneObservedPageRequests(now: number) {
  for (let index = observedPageRequests.length - 1; index >= 0; index -= 1) {
    if (now - observedPageRequests[index].observedAt > OBSERVED_PAGE_REQUEST_MAX_AGE_MS) {
      observedPageRequests.splice(index, 1);
    }
  }
}

function sameStringSet(left: string[], right: string[]) {
  if (left.length !== right.length) {
    return false;
  }

  const rightCounts = new Map<string, number>();
  for (const value of right) {
    rightCounts.set(value, (rightCounts.get(value) ?? 0) + 1);
  }

  for (const value of left) {
    const count = rightCounts.get(value) ?? 0;
    if (count === 0) {
      return false;
    }
    if (count === 1) {
      rightCounts.delete(value);
    } else {
      rightCounts.set(value, count - 1);
    }
  }

  return rightCounts.size === 0;
}

function stringArrayFrom(value: unknown) {
  return Array.isArray(value) && value.every(isString) ? value : undefined;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

type RelyingPartyValidation = {
  allowed: boolean;
  relatedOriginVerified: boolean;
  needsRelatedOriginVerification?: boolean;
};

type AdvancePasskeyCeremony = (
  expectedPhase: string,
  nextPhase: string,
  relatedOriginVerified?: boolean
) => Promise<void>;

type PasskeyCeremonyAdvancerOptions = {
  chromeApi: ChromeLike;
  sendRuntimeCommand: RuntimeCommandSender;
  ceremonyToken: () => string | null | undefined;
  ceremonyMirror: () => PasskeyCeremonyContext | null;
  updateCeremonyMirror: (mirror: PasskeyCeremonyContext) => void;
  updateCeremonyPhase: (phase: string) => void;
  missingCeremonyMessage: string;
};

function validateOriginForRelyingParty(
  origin: string,
  relyingParty: string
): RelyingPartyValidation {
  if (!originIsSecureForWebAuthn(origin)) {
    return { allowed: false, relatedOriginVerified: false };
  }

  if (originMatchesRelyingParty(origin, relyingParty)) {
    return { allowed: true, relatedOriginVerified: false };
  }

  if (originCanUseRelatedOriginVerification(origin, relyingParty)) {
    return {
      allowed: true,
      relatedOriginVerified: false,
      needsRelatedOriginVerification: true
    };
  }

  return { allowed: false, relatedOriginVerified: false };
}

function rejectNonSecureWebAuthnOrigin(origin: string) {
  if (!originIsSecureForWebAuthn(origin)) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "WebAuthn request origin does not match relying party"
    );
  }
}

function originIsSecureForWebAuthn(origin: string) {
  try {
    const parsed = new URL(origin);
    const host = normalizedHostFromUrl(origin);
    return parsed.protocol === "https:" || (parsed.protocol === "http:" && isLoopbackHost(host));
  } catch {
    return false;
  }
}

async function completeRelyingPartyValidation(
  origin: string,
  relyingParty: string | null,
  validation: RelyingPartyValidation
): Promise<RelyingPartyValidation> {
  if (!validation.needsRelatedOriginVerification) {
    return validation;
  }
  if (relyingParty && (await originAllowedByRelatedOrigins(origin, relyingParty))) {
    return { allowed: true, relatedOriginVerified: true };
  }
  return { allowed: false, relatedOriginVerified: false };
}

function createPasskeyCeremonyAdvancer({
  chromeApi,
  sendRuntimeCommand,
  ceremonyToken,
  ceremonyMirror,
  updateCeremonyMirror,
  updateCeremonyPhase,
  missingCeremonyMessage
}: PasskeyCeremonyAdvancerOptions): AdvancePasskeyCeremony {
  return async (expectedPhase, nextPhase, relatedOriginVerified = false) => {
    const token = ceremonyToken();
    if (!token) {
      throw new WebAuthnRequestError("NotAllowedError", missingCeremonyMessage);
    }
    await advancePasskeyCeremonyPhase(
      sendRuntimeCommand,
      token,
      expectedPhase,
      nextPhase,
      relatedOriginVerified
    );
    updateCeremonyPhase(nextPhase);

    const mirror = ceremonyMirror();
    if (!mirror) {
      return;
    }
    const nextMirror = passkeyCeremonyMirrorForPhase(
      { ...mirror, phase: nextPhase },
      nextPhase
    );
    updateCeremonyMirror(nextMirror);
    await persistPasskeyCeremonyMirror(chromeApi, nextMirror);
  };
}

async function advanceToCredentialResolution(
  origin: string,
  relyingParty: string,
  validation: RelyingPartyValidation,
  advanceCeremony: AdvancePasskeyCeremony,
  onRelatedOriginVerified?: () => void
) {
  const expectedPhase = validation.needsRelatedOriginVerification
    ? "s2_network_validation"
    : "s1_user_authorization";
  if (validation.needsRelatedOriginVerification) {
    await advanceCeremony("s1_user_authorization", "s2_network_validation");
  }

  const completedValidation = await completeRelyingPartyValidation(
    origin,
    relyingParty,
    validation
  );
  if (!completedValidation.allowed) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "WebAuthn request origin does not match relying party"
    );
  }
  if (completedValidation.relatedOriginVerified) {
    onRelatedOriginVerified?.();
  }
  await advanceCeremony(
    expectedPhase,
    "s3_credential_resolution",
    completedValidation.relatedOriginVerified === true
  );

  return completedValidation;
}

function originMatchesRelyingParty(origin: string, relyingParty: string) {
  try {
    const host = normalizedHostFromUrl(origin);
    const normalizedRelyingParty = normalizeHost(relyingParty);
    if (isLoopbackHost(host) || isLoopbackHost(normalizedRelyingParty)) {
      return host === normalizedRelyingParty;
    }
    if (isIpAddress(host) || isIpAddress(normalizedRelyingParty)) {
      return host === normalizedRelyingParty;
    }
    if (!psl.get(normalizedRelyingParty)) {
      return false;
    }
    return (
      host === normalizedRelyingParty ||
      host.endsWith(`.${normalizedRelyingParty}`)
    );
  } catch {
    return false;
  }
}

function originCanUseRelatedOriginVerification(origin: string, relyingParty: string) {
  try {
    const parsedOrigin = new URL(origin);
    if (parsedOrigin.protocol !== "https:") {
      return false;
    }

    const originHost = normalizedHostFromUrl(origin);
    const normalizedRelyingParty = normalizeHost(relyingParty);
    if (
      isLoopbackHost(originHost) ||
      isLoopbackHost(normalizedRelyingParty) ||
      isIpAddress(originHost) ||
      isIpAddress(normalizedRelyingParty) ||
      !psl.get(originHost) ||
      !psl.get(normalizedRelyingParty)
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

async function originAllowedByRelatedOrigins(origin: string, relyingParty: string) {
  if (typeof fetch !== "function") {
    return false;
  }

  if (!originCanUseRelatedOriginVerification(origin, relyingParty)) {
    return false;
  }

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    return false;
  }

  const normalizedRelyingParty = normalizeHost(relyingParty);

  try {
    const body = await fetchRelatedOriginsJson(
      `https://${normalizedRelyingParty}/.well-known/webauthn`
    );
    if (!body || !Array.isArray(body.origins)) {
      return false;
    }

    const normalizedOrigin = parsedOrigin.origin;
    return retainedRelatedOriginAllowlist(body.origins).includes(normalizedOrigin);
  } catch {
    return false;
  }
}

async function fetchRelatedOriginsJson(url: string) {
  const controller =
    typeof AbortController === "function" ? new AbortController() : null;
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timeoutId = setTimeout(() => {
      controller?.abort();
      resolve(null);
    }, RELATED_ORIGIN_FETCH_TIMEOUT_MS);
  });
  const request = (async () => {
    try {
      const response = await fetch(url, {
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        ...(controller ? { signal: controller.signal } : {})
      });
      if (!response.ok) {
        return null;
      }
      return (await response.json()) as { origins?: unknown };
    } catch {
      return null;
    }
  })();

  try {
    return await Promise.race([request, timeout]);
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  }
}

function retainedRelatedOriginAllowlist(origins: unknown[]) {
  const labels = new Set<string>();
  const retained: string[] = [];
  for (const origin of origins) {
    const candidateOrigin = originFromRelatedOriginAllowlistEntry(origin);
    if (!candidateOrigin) {
      continue;
    }
    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(candidateOrigin);
    } catch {
      continue;
    }
    if (parsedOrigin.protocol !== "https:") {
      continue;
    }

    const label = relatedOriginLabel(candidateOrigin);
    if (!label) {
      continue;
    }
    if (!labels.has(label)) {
      if (labels.size >= RELATED_ORIGIN_LABEL_LIMIT) {
        continue;
      }
      labels.add(label);
    }
    retained.push(candidateOrigin);
  }
  return retained;
}

function relatedOriginLabel(origin: unknown) {
  const candidateOrigin = originFromRelatedOriginAllowlistEntry(origin);
  if (!candidateOrigin) {
    return null;
  }
  try {
    const host = normalizedHostFromUrl(candidateOrigin);
    if (isLoopbackHost(host) || isIpAddress(host)) {
      return null;
    }
    return relatedOriginLabelFromHost(host);
  } catch {
    return null;
  }
}

function relatedOriginLabelFromHost(host: string) {
  const parsed = psl.parse(host);
  if ("error" in parsed || !parsed.sld) {
    return null;
  }
  return parsed.sld;
}

function originFromRelatedOriginAllowlistEntry(value: unknown) {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }

  try {
    const parsed = new URL(value);
    if (
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      (parsed.pathname !== "" && parsed.pathname !== "/")
    ) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function normalizedHostFromUrl(value: string) {
  const hostname = new URL(value).hostname;
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return normalizeHost(hostname.slice(1, -1));
  }
  return normalizeHost(hostname);
}

function normalizeHost(value: string) {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

function isLoopbackHost(host: string) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function isIpAddress(host: string) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

function userNameFromCreateOptions(options: { user?: { name?: unknown } }) {
  const name = options.user?.name;
  if (typeof name !== "string" || name.trim() === "") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn user name");
  }
  return name;
}

function userDisplayNameFromCreateOptions(options: {
  user?: { displayName?: unknown };
}) {
  const displayName = options.user?.displayName;
  return typeof displayName === "string" && displayName.trim() !== ""
    ? displayName
    : null;
}

function userHandleFromCreateOptions(options: { user?: { id?: unknown } }) {
  const userHandle = options.user?.id;
  if (typeof userHandle !== "string") {
    throw new WebAuthnRequestError("TypeError", "missing WebAuthn user id");
  }
  validateWebAuthnUserHandleLength(userHandle);
  return userHandle;
}

function publicKeyAlgorithmFromCreateOptions(options: { pubKeyCredParams?: unknown }) {
  if (!Array.isArray(options.pubKeyCredParams) || options.pubKeyCredParams.length === 0) {
    return -7;
  }

  for (const param of options.pubKeyCredParams) {
    if (
      typeof param === "object" &&
      param !== null &&
      (param as { type?: unknown }).type === "public-key" &&
      (param as { alg?: unknown }).alg === -7
    ) {
      return -7;
    }
  }

  throw new WebAuthnRequestError(
    "NotSupportedError",
    "VaultKern passkey registration requires ES256"
  );
}

function validateCreateUserHandleOption(options: { user?: { id?: unknown } }) {
  const userHandle = options.user?.id;
  if (typeof userHandle !== "string") {
    throw new WebAuthnRequestError("TypeError", "missing WebAuthn user id");
  }
  validateWebAuthnUserHandleLength(userHandle);
}

function validateWebAuthnUserHandleLength(userHandleBase64url: string) {
  const byteLength = base64urlDecodedByteLength(userHandleBase64url);
  if (byteLength < 1 || byteLength > 64) {
    throw new WebAuthnRequestError(
      "TypeError",
      "WebAuthn user id must be 1 to 64 bytes"
    );
  }
}

function base64urlDecodedByteLength(value: string) {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    throw new WebAuthnRequestError("TypeError", "WebAuthn user id must be base64url encoded");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = `${value}${padding}`.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return atob(base64).length;
  } catch {
    throw new WebAuthnRequestError("TypeError", "WebAuthn user id must be base64url encoded");
  }
}

function credentialIdsFromOptions(options: { allowCredentials?: unknown }) {
  if (!Array.isArray(options.allowCredentials)) {
    return [null];
  }

  const credentials = options.allowCredentials.filter(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      (item as { type?: unknown }).type === "public-key" &&
      typeof (item as { id?: unknown }).id === "string"
  ) as Array<{ id: string }>;
  if (credentials.length === 0) {
    return [null];
  }
  return credentials.map((credential) => credential.id);
}

function excludedCredentialIdsFromCreateOptions(options: {
  excludeCredentials?: unknown;
}) {
  if (!Array.isArray(options.excludeCredentials)) {
    return [];
  }

  return options.excludeCredentials
    .filter(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        (item as { type?: unknown }).type === "public-key" &&
        typeof (item as { id?: unknown }).id === "string"
    )
    .map((credential) => (credential as { id: string }).id);
}

function base64urlEncode(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

async function completeGetRequest(chromeApi: ChromeLike, details: unknown) {
  await chromeApi.webAuthenticationProxy?.completeGetRequest?.(details);
}

async function completeCreateRequest(chromeApi: ChromeLike, details: unknown) {
  await chromeApi.webAuthenticationProxy?.completeCreateRequest?.(details);
}

function createPasskeyPromptMirrorPersistence(
  chromeApi: ChromeLike,
  getMirror: () => PasskeyCeremonyContext | null,
  updateMirror: (mirror: PasskeyCeremonyContext) => void
): PasskeyPromptMirrorPersistence {
  const persistPromptMirror = async (
    patch: Pick<
      PasskeyCeremonyContext,
      "popupNonce" | "promptMode" | "promptWindowId" | "promptCredentialOptions"
    >
  ) => {
    const mirror = getMirror();
    if (!mirror) {
      return;
    }
    const nextMirror = {
      ...mirror,
      ...patch
    };
    updateMirror(nextMirror);
    await persistPasskeyCeremonyMirror(chromeApi, nextMirror);
  };

  return {
    persistPresencePromptState(nonce, credentialOptions = []) {
      return persistPromptMirror({
        popupNonce: nonce,
        promptMode: "approve",
        promptWindowId: undefined,
        promptCredentialOptions: credentialOptions
      });
    },
    persistUnlockPromptState(nonce) {
      return persistPromptMirror({
        popupNonce: nonce,
        promptMode: "unlock",
        promptWindowId: undefined,
        promptCredentialOptions: []
      });
    },
    persistUserVerificationPromptState(nonce) {
      return persistPromptMirror({
        popupNonce: nonce,
        promptMode: "verify",
        promptWindowId: undefined,
        promptCredentialOptions: []
      });
    },
    persistPromptWindowId(windowId) {
      return persistPromptMirror({ promptWindowId: windowId });
    }
  };
}

async function activeVaultForRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  promptKey: string,
  initialSession: { activeVaultId?: string | null },
  promptContext: WebAuthnPromptContext,
  canceledRequests: CanceledWebAuthnRequests,
  requestCancelKey: string | null,
  options: {
    onPromptPrepared?: (nonce: string) => Promise<void> | void;
    onPromptOpened?: (windowId: number) => Promise<void> | void;
  } = {}
) {
  if (initialSession.activeVaultId) {
    return {
      activeVaultId: initialSession.activeVaultId,
      userPresenceVerified: false
    };
  }

  promptStates.unlock.activeDrivers.add(promptKey);
  try {
    await recordWebAuthnDebug(chromeApi, {
      event: "unlock_prompt_opening",
      requestId
    });
    const deadline = Date.now() + 120_000;
    let unlockSignal = waitForPromptSignal(
      promptStates.unlock,
      promptKey,
      Math.min(1_000, Math.max(0, deadline - Date.now()))
    );
    const nonce = promptNonceFor(promptStates.unlock.nonces, promptKey);
    await options.onPromptPrepared?.(nonce);
    const openedPrompt = await openPromptWindow(
      chromeApi,
      promptStates.unlock,
      PROMPT_WINDOW_CONFIGS.unlock,
      clearUnlockPromptState,
      requestId,
      promptKey,
      promptContext,
      requestCancelKey,
      nonce
    );
    if (typeof openedPrompt.windowId === "number") {
      await options.onPromptOpened?.(openedPrompt.windowId);
    }

    while (Date.now() < deadline) {
      if (webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey)) {
        clearUnlockPromptState(promptKey);
        await recordWebAuthnDebug(chromeApi, {
          event: "unlock_wait_canceled",
          requestId
        });
        return null;
      }

      const signal = await unlockSignal;
      if (!signal) {
        const session = (await sendRuntimeCommand({
          type: "get_session_state"
        })) as { activeVaultId?: string | null };
        await recordWebAuthnDebug(chromeApi, {
          event: "unlock_poll_session_state",
          requestId,
          hasActiveVault: Boolean(session.activeVaultId)
        });
        if (session.activeVaultId) {
          const pendingCompleteSignal = takePendingUnlockCompleteSignal(promptKey);
          if (pendingCompleteSignal) {
            clearUnlockPromptState(promptKey);
            return {
              activeVaultId: session.activeVaultId,
              userPresenceVerified: true,
              unlockUserVerificationProof:
                pendingCompleteSignal.userVerificationProof ?? null
            };
          }
          const lateUnlockSignal = waitForPromptSignal(
            promptStates.unlock,
            promptKey,
            Math.min(1_500, Math.max(0, deadline - Date.now()))
          );
          const lateSignal = await lateUnlockSignal;
          if (lateSignal?.type === "dismissed") {
            throw userAbortWebAuthnRequestError(
              "NotAllowedError",
              "VaultKern vault unlock was dismissed"
            );
          }
          if (lateSignal?.type === "complete") {
            return {
              activeVaultId: session.activeVaultId,
              userPresenceVerified: true,
              unlockUserVerificationProof:
                lateSignal.signal.userVerificationProof ?? null
            };
          }
          clearUnlockPromptState(promptKey);
          return {
            activeVaultId: session.activeVaultId,
            userPresenceVerified: false
          };
        }
        unlockSignal = waitForPromptSignal(
          promptStates.unlock,
          promptKey,
          Math.min(1_000, Math.max(0, deadline - Date.now()))
        );
        continue;
      }
      if (signal.type === "dismissed") {
        throw userAbortWebAuthnRequestError(
          "NotAllowedError",
          "VaultKern vault unlock was dismissed"
        );
      }

      const session = (await sendRuntimeCommand({
        type: "get_session_state"
      })) as { activeVaultId?: string | null };
      await recordWebAuthnDebug(chromeApi, {
        event: "unlock_signal_session_state",
        requestId,
        hasActiveVault: Boolean(session.activeVaultId)
      });
      if (session.activeVaultId) {
        return {
          activeVaultId: session.activeVaultId,
          userPresenceVerified: true,
          unlockUserVerificationProof: signal.signal.userVerificationProof ?? null
        };
      }

      unlockSignal = waitForPromptSignal(
        promptStates.unlock,
        promptKey,
        Math.min(1_000, Math.max(0, deadline - Date.now()))
      );
      await delay(500);
    }

    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern vault unlock timed out"
    );
  } finally {
    promptStates.unlock.activeDrivers.delete(promptKey);
  }
}

function takePendingUnlockCompleteSignal(promptKey: string) {
  const signal = promptStates.unlock.pendingCompleteSignals.get(promptKey) ?? null;
  promptStates.unlock.pendingCompleteSignals.delete(promptKey);
  return signal;
}

async function verifyPasskeyUserFromUnlockProof(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  ceremonyToken: string,
  activeVaultId: string,
  userVerification: PasskeyUserVerificationRequirement,
  unlockUserVerificationProof: UnlockUserVerificationProof | null | undefined
) {
  if (userVerification === "discouraged" || !unlockUserVerificationProof) {
    return false;
  }

  const response = await sendRuntimeCommand({
    type: "verify_passkey_user",
    ceremony_token: ceremonyToken,
    expected_phase: "s1_user_authorization",
    vault_id: activeVaultId,
    method: unlockUserVerificationProof.method,
    ...(unlockUserVerificationProof.method === "master_password"
      ? { password: unlockUserVerificationProof.password }
      : {})
  });
  requireRuntimeResponseType(
    response,
    "passkey_user_verified",
    "passkey user verification failed",
    "verified"
  );
  await recordWebAuthnDebug(chromeApi, {
    event: "unlock_user_verification_complete",
    requestId,
    method: unlockUserVerificationProof.method
  });
  return true;
}

async function userPresenceForRequest(
  chromeApi: ChromeLike,
  requestId: number,
  promptKey: string,
  promptContext: WebAuthnPromptContext,
  canceledRequests: CanceledWebAuthnRequests,
  requestCancelKey: string | null,
  options: {
    onPromptPrepared?: (nonce: string) => Promise<void> | void;
    onPromptOpened?: (windowId: number) => Promise<void> | void;
  } = {}
) {
  promptStates.approve.activeDrivers.add(promptKey);
  try {
    await recordWebAuthnDebug(chromeApi, {
      event: "presence_prompt_opening",
      requestId
    });
    const nonce = promptNonceFor(promptStates.approve.nonces, promptKey);
    await options.onPromptPrepared?.(nonce);
    const openedPrompt = await openPromptWindow(
      chromeApi,
      promptStates.approve,
      PROMPT_WINDOW_CONFIGS.approve,
      clearPresencePromptState,
      requestId,
      promptKey,
      promptContext,
      requestCancelKey,
      nonce
    );
    if (typeof openedPrompt.windowId === "number") {
      await options.onPromptOpened?.(openedPrompt.windowId);
    }

    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      if (webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey)) {
        clearPresencePromptState(promptKey);
        await recordWebAuthnDebug(chromeApi, {
          event: "presence_wait_canceled",
          requestId
        });
        return false;
      }

      const signal = await waitForPromptSignal(
        promptStates.approve,
        promptKey,
        Math.min(1_000, Math.max(0, deadline - Date.now()))
      );
      if (signal?.type === "complete") {
        const selectedCredentialId = selectedCredentialIdForPrompt(
          promptContext,
          signal.signal.credentialId
        );
        return selectedCredentialId ? { selectedCredentialId } : {};
      }
      if (signal?.type === "dismissed") {
        throw userAbortWebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey approval was dismissed"
        );
      }
    }

    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey approval timed out"
    );
  } finally {
    promptStates.approve.activeDrivers.delete(promptKey);
  }
}

async function userVerificationForRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  promptKey: string,
  activeVaultId: string,
  userVerification: PasskeyUserVerificationRequirement,
  promptContext: WebAuthnPromptContext,
  canceledRequests: CanceledWebAuthnRequests,
  requestCancelKey: string | null,
  options: {
    onPromptPrepared?: (nonce: string) => Promise<void> | void;
    onPromptOpened?: (windowId: number) => Promise<void> | void;
  } = {}
) {
  if (userVerification === "discouraged") {
    return false;
  }
  promptStates.verify.activeDrivers.add(promptKey);
  try {
    let methods: Array<"master_password" | "quick_unlock">;
    try {
      methods = getPasskeyUserVerificationMethodsFromResponse(
        await sendRuntimeCommand({
          type: "get_passkey_user_verification_capability"
        })
      );
    } catch (error) {
      await recordWebAuthnDebug(chromeApi, {
        event: "user_verification_capability_failed",
        requestId,
        error: errorSummary(error)
      });
      if (userVerification === "required") {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey provider cannot verify the user"
        );
      }
      return false;
    }
    if (methods.length === 0) {
      if (userVerification === "required") {
        throw new WebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey provider cannot verify the user"
        );
      }
      return false;
    }

    await recordWebAuthnDebug(chromeApi, {
      event: "user_verification_prompt_opening",
      requestId,
      methods
    });
    const nonce = promptNonceFor(promptStates.verify.nonces, promptKey);
    await options.onPromptPrepared?.(nonce);
    const openedPrompt = await openPromptWindow(
      chromeApi,
      promptStates.verify,
      PROMPT_WINDOW_CONFIGS.verify,
      clearUserVerificationPromptState,
      requestId,
      promptKey,
      {
        ...promptContext,
        ceremonyToken: promptKey,
        activeVaultId
      },
      requestCancelKey,
      nonce
    );
    if (typeof openedPrompt.windowId === "number") {
      await options.onPromptOpened?.(openedPrompt.windowId);
    }

    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      if (webAuthnRequestIsCanceled(canceledRequests, requestId, requestCancelKey)) {
        clearUserVerificationPromptState(promptKey);
        await recordWebAuthnDebug(chromeApi, {
          event: "user_verification_wait_canceled",
          requestId
        });
        return false;
      }

      const signal = await waitForPromptSignal(
        promptStates.verify,
        promptKey,
        Math.min(1_000, Math.max(0, deadline - Date.now()))
      );
      if (signal?.type === "complete") {
        return true;
      }
      if (signal?.type === "dismissed") {
        throw userAbortWebAuthnRequestError(
          "NotAllowedError",
          "VaultKern passkey user verification was dismissed"
        );
      }
    }

    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey user verification timed out"
    );
  } finally {
    promptStates.verify.activeDrivers.delete(promptKey);
  }
}

function selectedCredentialIdForPrompt(
  promptContext: WebAuthnPromptContext,
  credentialId: string | undefined
) {
  const credentialOptions = promptContext.credentialOptions ?? [];
  if (credentialOptions.length === 0) {
    return undefined;
  }
  if (!credentialId) {
    throw userAbortWebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey credential was not selected"
    );
  }
  if (!credentialOptions.some((option) => option.credentialId === credentialId)) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey credential selection is not allowed"
    );
  }
  return credentialId;
}

function waitForPromptSignal<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  state: PromptState<TContext, TCompleteSignal>,
  promptKey: string,
  timeoutMs: number
) {
  if (state.dismissedPromptKeys.delete(promptKey)) {
    return Promise.resolve<PromptSignal<TCompleteSignal>>({ type: "dismissed" });
  }
  if (state.pendingCompleteSignals.has(promptKey)) {
    const signal = state.pendingCompleteSignals.get(promptKey);
    state.pendingCompleteSignals.delete(promptKey);
    if (signal !== undefined) {
      return Promise.resolve<PromptSignal<TCompleteSignal>>({
        type: "complete",
        signal
      });
    }
  }

  return new Promise<PromptSignal<TCompleteSignal>>((resolve) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      finish(null);
    }, timeoutMs);
    const completeWaiter = (signal: TCompleteSignal) => {
      finish({ type: "complete", signal });
    };
    const dismissWaiter = () => {
      finish({ type: "dismissed" });
    };

    function finish(signaled: PromptSignal<TCompleteSignal>) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutId);
      const completeWaiters = state.completeWaiters.get(promptKey);
      completeWaiters?.delete(completeWaiter);
      if (completeWaiters?.size === 0) {
        state.completeWaiters.delete(promptKey);
      }
      const dismissWaiters = state.dismissWaiters.get(promptKey);
      dismissWaiters?.delete(dismissWaiter);
      if (dismissWaiters?.size === 0) {
        state.dismissWaiters.delete(promptKey);
      }
      resolve(signaled);
    }

    const completeWaiters =
      state.completeWaiters.get(promptKey) ??
      new Set<(signal: TCompleteSignal) => void>();
    completeWaiters.add(completeWaiter);
    state.completeWaiters.set(promptKey, completeWaiters);
    const dismissWaiters = state.dismissWaiters.get(promptKey) ?? new Set<() => void>();
    dismissWaiters.add(dismissWaiter);
    state.dismissWaiters.set(promptKey, dismissWaiters);
  });
}

async function openPromptWindow<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  chromeApi: ChromeLike,
  state: PromptState<TContext, TCompleteSignal>,
  config: PromptWindowConfig,
  clearPromptState: PromptClearState,
  requestId: number,
  promptKey: string,
  promptContext: TContext,
  requestCancelKey: string | null,
  preparedNonce?: string
): Promise<PromptOpenResult> {
  if (!chromeApi.windows?.create) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      config.unavailableMessage
    );
  }

  const existingWindowId = state.windowIds.get(promptKey);
  if (typeof existingWindowId === "number" && chromeApi.windows.update) {
    try {
      await chromeApi.windows.update(existingWindowId, { focused: true });
      const existingNonce = state.nonces.get(promptKey);
      if (typeof existingNonce === "string") {
        return { nonce: existingNonce, windowId: existingWindowId };
      }
      clearPromptState(promptKey);
    } catch {
      clearPromptState(promptKey);
    }
  }

  const nonce = preparedNonce ?? generatePromptNonce();
  state.dismissedPromptKeys.delete(promptKey);
  state.contexts.set(promptKey, promptContext);
  state.nonces.set(promptKey, nonce);
  state.requestIds.set(promptKey, requestId);
  if (requestCancelKey) {
    state.requestKeys.set(promptKey, requestCancelKey);
  }
  const popupPath = popupPathForWebAuthnPrompt(
    config.mode,
    requestId,
    promptContext,
    nonce
  );
  const url = chromeApi.runtime?.getURL?.(popupPath) ?? popupPath;
  let created: { id?: number } | undefined;
  try {
    created = await chromeApi.windows.create({
      url,
      type: "popup",
      width: config.width,
      height: config.height,
      focused: true
    });
  } catch (error) {
    clearPromptState(promptKey);
    throw error;
  }
  if (created && typeof created.id === "number") {
    state.windowIds.set(promptKey, created.id);
    watchPromptWindow(
      chromeApi,
      state,
      config,
      clearPromptState,
      requestId,
      promptKey,
      created.id
    );
  }
  return {
    nonce,
    ...(created && typeof created.id === "number" ? { windowId: created.id } : {})
  };
}

function watchPromptWindow<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  chromeApi: ChromeLike,
  state: PromptState<TContext, TCompleteSignal>,
  config: PromptWindowConfig,
  clearPromptState: PromptClearState,
  requestId: number,
  promptKey: string,
  windowId: number,
  onUnobservedDismissed?: () => void
) {
  const onRemoved = chromeApi.windows?.onRemoved;
  if (!onRemoved?.addListener) {
    return;
  }

  state.removalCleanups.get(promptKey)?.();
  const listener = (removedWindowId: number) => {
    if (removedWindowId !== windowId) {
      return;
    }

    clearPromptState(promptKey, { preserveDismissed: true });
    state.dismissedPromptKeys.add(promptKey);
    void recordWebAuthnDebug(chromeApi, {
      event: config.dismissedDebugEvent,
      requestId,
      windowId
    });
    const waiters = [...(state.dismissWaiters.get(promptKey) ?? [])];
    for (const waiter of waiters) {
      waiter();
    }
    if (waiters.length === 0 && !state.activeDrivers.has(promptKey)) {
      onUnobservedDismissed?.();
    }
  };
  onRemoved.addListener(listener);
  state.removalCleanups.set(promptKey, () => {
    onRemoved.removeListener?.(listener);
    state.removalCleanups.delete(promptKey);
  });
}

function popupPathForWebAuthnPrompt(
  mode: "unlock" | "approve" | "verify",
  requestId: number,
  promptContext: WebAuthnPromptContext,
  nonce: string
) {
  const params = new URLSearchParams({
    webauthn: mode,
    requestId: String(requestId),
    relyingParty: promptContext.relyingParty,
    origin: promptContext.origin,
    nonce
  });
  if (promptContext.topOrigin) {
    params.set("topOrigin", promptContext.topOrigin);
  }
  return `popup.html?${params.toString()}`;
}

function promptNonceFor(nonces: Map<string, string>, promptKey: string) {
  const existingNonce = nonces.get(promptKey);
  if (typeof existingNonce === "string") {
    return existingNonce;
  }
  const nonce = generatePromptNonce();
  nonces.set(promptKey, nonce);
  return nonce;
}

function generatePromptNonce() {
  return secureRandomBase64url(16);
}

function clearUnlockPromptState(
  promptKey: string,
  options: PromptClearOptions = {}
) {
  promptStates.unlock.removalCleanups.get(promptKey)?.();
  promptStates.unlock.windowIds.delete(promptKey);
  promptStates.unlock.contexts.delete(promptKey);
  promptStates.unlock.nonces.delete(promptKey);
  promptStates.unlock.requestIds.delete(promptKey);
  promptStates.unlock.requestKeys.delete(promptKey);
  promptStates.unlock.pendingCompleteSignals.delete(promptKey);
  if (!options.preserveDismissed) {
    promptStates.unlock.dismissedPromptKeys.delete(promptKey);
  }
}

function clearPresencePromptState(
  promptKey: string,
  options: PromptClearOptions = {}
) {
  promptStates.approve.removalCleanups.get(promptKey)?.();
  promptStates.approve.windowIds.delete(promptKey);
  promptStates.approve.contexts.delete(promptKey);
  promptStates.approve.nonces.delete(promptKey);
  promptStates.approve.requestIds.delete(promptKey);
  promptStates.approve.requestKeys.delete(promptKey);
  promptStates.approve.pendingCompleteSignals.delete(promptKey);
  if (!options.preserveDismissed) {
    promptStates.approve.dismissedPromptKeys.delete(promptKey);
  }
}

function clearUserVerificationPromptState(
  promptKey: string,
  options: PromptClearOptions = {}
) {
  promptStates.verify.removalCleanups.get(promptKey)?.();
  promptStates.verify.windowIds.delete(promptKey);
  promptStates.verify.contexts.delete(promptKey);
  promptStates.verify.nonces.delete(promptKey);
  promptStates.verify.requestIds.delete(promptKey);
  promptStates.verify.requestKeys.delete(promptKey);
  promptStates.verify.pendingCompleteSignals.delete(promptKey);
  if (!options.preserveDismissed) {
    promptStates.verify.dismissedPromptKeys.delete(promptKey);
  }
}

async function closePromptWindowsForCeremony(
  chromeApi: ChromeLike,
  ceremonyToken: string | null
) {
  if (!ceremonyToken) {
    return;
  }

  const windowIds = [
    promptStates.unlock.windowIds.get(ceremonyToken),
    promptStates.approve.windowIds.get(ceremonyToken),
    promptStates.verify.windowIds.get(ceremonyToken)
  ].filter((windowId): windowId is number => typeof windowId === "number");
  clearUnlockPromptState(ceremonyToken);
  clearPresencePromptState(ceremonyToken);
  clearUserVerificationPromptState(ceremonyToken);

  if (!chromeApi.windows?.remove) {
    return;
  }
  for (const windowId of windowIds) {
    try {
      await chromeApi.windows.remove(windowId);
    } catch {
      // The user or browser may already have closed the prompt.
    }
  }
}

async function closePromptWindowForRequest<
  TContext extends WebAuthnPromptContext,
  TCompleteSignal
>(
  chromeApi: ChromeLike,
  state: PromptState<TContext, TCompleteSignal>,
  clearPromptState: PromptClearState,
  requestId: number,
  requestCancelKey: string | null
) {
  const promptKeys = promptKeysForCancellation(
    state.requestIds,
    state.requestKeys,
    requestId,
    requestCancelKey
  );
  const windowIds = promptKeys
    .map((promptKey) => state.windowIds.get(promptKey))
    .filter((windowId): windowId is number => typeof windowId === "number");
  for (const promptKey of promptKeys) {
    clearPromptState(promptKey);
  }
  if (!chromeApi.windows?.remove) {
    return;
  }
  for (const windowId of windowIds) {
    try {
      await chromeApi.windows.remove(windowId);
    } catch {
      // The user or browser may already have closed the prompt.
    }
  }
}

function promptKeysForCancellation(
  requestIds: Map<string, number>,
  requestKeys: Map<string, string>,
  requestId: number,
  requestCancelKey: string | null
) {
  return [...requestIds.entries()]
    .filter(([promptKey, candidateRequestId]) => {
      if (candidateRequestId !== requestId) {
        return false;
      }
      return !requestCancelKey || requestKeys.get(promptKey) === requestCancelKey;
    })
    .map(([promptKey]) => promptKey);
}

function delay(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function completePasskeyRequestWithError(
  chromeApi: ChromeLike,
  ceremony: "get" | "create",
  requestId: number,
  ceremonyToken: string | null | undefined,
  error: unknown
) {
  await delayPublicWebAuthnError(ceremonyToken);
  const details = {
    requestId,
    error: webAuthnError(error, Boolean(ceremonyToken))
  };
  if (ceremony === "get") {
    await completeGetRequest(chromeApi, details);
  } else {
    await completeCreateRequest(chromeApi, details);
  }
}

async function delayPublicWebAuthnError(ceremonyToken: string | null | undefined) {
  if (!ceremonyToken) {
    return;
  }
  await delay(PASSKEY_PUBLIC_ERROR_MIN_DELAY_MS);
}

class WebAuthnRequestError extends Error {
  constructor(
    public readonly name: string,
    message: string,
    public readonly options: { userAbort?: boolean } = {}
  ) {
    super(message);
  }

  get userAbort() {
    return this.options.userAbort === true;
  }
}

class InternalPasskeyRequestError extends Error {}

function userAbortWebAuthnRequestError(name: string, message: string) {
  return new WebAuthnRequestError(name, message, { userAbort: true });
}

function webAuthnError(error: unknown, concealNotAllowedDetails = false) {
  if (error instanceof InternalPasskeyRequestError) {
    return {
      name: "NotAllowedError",
      message: GENERIC_PASSKEY_REQUEST_ERROR_MESSAGE
    };
  }
  if (error instanceof WebAuthnRequestError) {
    if (concealNotAllowedDetails && error.name === "NotAllowedError") {
      return {
        name: "NotAllowedError",
        message: GENERIC_PASSKEY_REQUEST_ERROR_MESSAGE
      };
    }
    return {
      name: error.name,
      message: error.message
    };
  }
  return {
    name: "NotAllowedError",
    message: GENERIC_PASSKEY_REQUEST_ERROR_MESSAGE
  };
}

export function recordWebAuthnDebug(
  chromeApi: ChromeLike,
  event: Record<string, unknown>
) {
  const chainKey = chromeApi.storage?.local ?? chromeApi;
  if (
    typeof chainKey === "object" &&
    (webAuthnDebugDisabledUntil.get(chainKey) ?? 0) > Date.now()
  ) {
    return Promise.resolve();
  }
  const previous =
    typeof chainKey === "object"
      ? webAuthnDebugWriteChains.get(chainKey) ?? Promise.resolve()
      : Promise.resolve();
  const next = previous
    .catch(() => undefined)
    .then(() => persistWebAuthnDebug(chromeApi, event));
  if (typeof chainKey === "object") {
    webAuthnDebugWriteChains.set(chainKey, next);
  }
  void next.catch(() => undefined);
  return Promise.resolve();
}

function rememberPasskeyCeremonyToken(token: string) {
  if (token.trim() === "" || knownPasskeyCeremonyTokens.has(token)) {
    return;
  }
  knownPasskeyCeremonyTokens.add(token);
  knownPasskeyCeremonyTokenQueue.push(token);
  while (knownPasskeyCeremonyTokenQueue.length > MAX_KNOWN_PASSKEY_CEREMONY_TOKENS) {
    const expiredToken = knownPasskeyCeremonyTokenQueue.shift();
    if (expiredToken) {
      knownPasskeyCeremonyTokens.delete(expiredToken);
    }
  }
}

function redactKnownPasskeyCeremonyTokens(value: unknown): unknown {
  if (typeof value === "string") {
    return redactKnownPasskeyCeremonyTokensFromString(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactKnownPasskeyCeremonyTokens);
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, nestedValue]) => [
      redactKnownPasskeyCeremonyTokensFromString(key),
      redactKnownPasskeyCeremonyTokens(nestedValue)
    ])
  );
}

function redactKnownPasskeyCeremonyTokensFromString(value: string) {
  let redacted = value;
  for (const token of knownPasskeyCeremonyTokens) {
    redacted = redacted.replaceAll(token, "[redacted-ceremony-token]");
  }
  return redacted;
}

async function persistWebAuthnDebug(
  chromeApi: ChromeLike,
  event: Record<string, unknown>
) {
  try {
    const storage = chromeApi.storage?.local;
    if (!storage?.get || !storage.set) {
      return;
    }
    if (
      typeof storage === "object" &&
      (webAuthnDebugDisabledUntil.get(storage) ?? 0) > Date.now()
    ) {
      return;
    }
    const existing = await storage.get([
      WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY,
      WEB_AUTHN_DEBUG_STORAGE_KEY
    ]);
    if (existing[WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY] !== true) {
      if (typeof storage === "object") {
        webAuthnDebugDisabledUntil.set(
          storage,
          Date.now() + WEB_AUTHN_DEBUG_DISABLED_CACHE_MS
        );
      }
      return;
    }
    if (typeof storage === "object") {
      webAuthnDebugDisabledUntil.delete(storage);
    }
    const redactedEvent = redactKnownPasskeyCeremonyTokens(event) as Record<
      string,
      unknown
    >;
    const previous = Array.isArray(existing[WEB_AUTHN_DEBUG_STORAGE_KEY])
      ? existing[WEB_AUTHN_DEBUG_STORAGE_KEY]
      : [];
    const redactedPrevious = previous
      .slice(-49)
      .map(redactKnownPasskeyCeremonyTokens);
    await storage.set({
      [WEB_AUTHN_DEBUG_STORAGE_KEY]: [
        ...redactedPrevious,
        {
          at: new Date().toISOString(),
          ...redactedEvent
        }
      ]
    });
  } catch {
    // Best-effort diagnostics must never break WebAuthn handling.
  }
}

function requestSummaryFrom(request: unknown) {
  const requestFields = requestFieldsFrom(request);
  const requestDetailsJson = (request as { requestDetailsJson?: unknown } | null)
    ?.requestDetailsJson;
  if (typeof requestDetailsJson !== "string") {
    return { ...requestFields, hasRequestDetailsJson: false };
  }

  try {
    const options = JSON.parse(requestDetailsJson) as {
      rpId?: unknown;
      rp?: { id?: unknown; name?: unknown };
      challenge?: unknown;
      pubKeyCredParams?: Array<{ alg?: unknown; type?: unknown }>;
      excludeCredentials?: unknown[];
      allowCredentials?: unknown[];
      authenticatorSelection?: unknown;
      attestation?: unknown;
      userVerification?: unknown;
    };
    return {
      ...requestFields,
      hasRequestDetailsJson: true,
      rpId: typeof options.rpId === "string" ? options.rpId : undefined,
      rp: {
        id: typeof options.rp?.id === "string" ? options.rp.id : undefined,
        name: typeof options.rp?.name === "string" ? options.rp.name : undefined
      },
      challengeType: typeof options.challenge,
      pubKeyCredParams: Array.isArray(options.pubKeyCredParams)
        ? options.pubKeyCredParams.map((param) => ({
            type: param.type,
            alg: param.alg
          }))
        : undefined,
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      userVerification: options.userVerification
    };
  } catch (error) {
    return {
      ...requestFields,
      hasRequestDetailsJson: true,
      parseError: error instanceof Error ? error.message : String(error)
    };
  }
}

function requestFieldsFrom(request: unknown) {
  if (typeof request !== "object" || request === null) {
    return { requestType: typeof request };
  }

  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(request)) {
    if (key === "requestDetailsJson") {
      continue;
    }
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value === null
    ) {
      fields[key] = value;
    } else {
      fields[key] = typeof value;
    }
  }

  return {
    requestKeys: Object.keys(request),
    requestFields: fields
  };
}

function errorSummary(error: unknown) {
  return {
    name:
      error instanceof WebAuthnRequestError
        ? error.name
        : error instanceof Error
          ? error.name
          : "Error",
    message: error instanceof Error ? error.message : String(error)
  };
}
