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
        ) => void
      ) => void;
    };
  };
  storage?: {
    local?: {
      get?: (keys?: unknown) => Promise<Record<string, unknown>>;
      set?: (items: Record<string, unknown>) => Promise<void>;
    };
  };
  tabs?: {
    query?: (queryInfo: Record<string, unknown>) => Promise<Array<{ url?: string }>>;
  };
  windows?: {
    create?: (createData: Record<string, unknown>) => Promise<{ id?: number }> | void;
    update?: (windowId: number, updateInfo: Record<string, unknown>) => Promise<unknown> | void;
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
  mediation?: string;
};

type WebAuthnPromptContext = WebAuthnOriginContext & {
  relyingParty: string;
  credentialOptions?: PasskeyCredentialOption[];
};

type PasskeyCredentialOption = {
  credentialId: string;
  username: string;
  userHandle?: string | null;
};

type PresenceSignal =
  | { type: "complete"; credentialId?: string }
  | { type: "dismissed" }
  | null;

const unlockPromptWindowIds = new Map<number, number>();
const unlockCompleteWaiters = new Map<number, Set<() => void>>();
const unlockDismissWaiters = new Map<number, Set<() => void>>();
const unlockPromptContexts = new Map<number, WebAuthnPromptContext>();
const unlockPromptNonces = new Map<number, string>();
const unlockPromptRemovalCleanups = new Map<number, () => void>();
const presencePromptWindowIds = new Map<number, number>();
const presenceCompleteWaiters = new Map<
  number,
  Set<(credentialId?: string) => void>
>();
const presenceDismissWaiters = new Map<number, Set<() => void>>();
const presencePromptContexts = new Map<number, WebAuthnPromptContext>();
const presencePromptNonces = new Map<number, string>();
const presencePromptRemovalCleanups = new Map<number, () => void>();
const observedPageRequests: ObservedWebAuthnPageRequest[] = [];
const registeredUnlockMessageSources = new WeakSet<object>();
const registeredRequestHandlerSources = new WeakSet<object>();
const OBSERVED_PAGE_REQUEST_MAX_AGE_MS = 120_000;
const WEB_AUTHN_DEBUG_STORAGE_KEY = "vaultkernWebAuthnDebug";
const WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY = "vaultkernWebAuthnDebugEnabled";
const RELATED_ORIGIN_LABEL_LIMIT = 5;

type ObservedWebAuthnPageRequest = {
  ceremony: "create" | "get";
  origin: string;
  topOrigin?: string;
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
  chromeApi?: ChromeLike
) {
  if (typeof message !== "object" || message === null) {
    return false;
  }

  const candidate = message as {
    ceremony?: unknown;
    origin?: unknown;
    topOrigin?: unknown;
    relyingParty?: unknown;
    challenge?: unknown;
    allowCredentialIds?: unknown;
    excludeCredentialIds?: unknown;
    mediation?: unknown;
  };
  if (candidate.ceremony !== "create" && candidate.ceremony !== "get") {
    return false;
  }
  if (typeof candidate.origin !== "string" || candidate.origin.trim() === "") {
    return false;
  }

  let origin: string;
  try {
    origin = new URL(candidate.origin).origin;
  } catch {
    return false;
  }
  const topOrigin = originFromUnknown(candidate.topOrigin);

  pruneObservedPageRequests(Date.now());
  observedPageRequests.push({
    ceremony: candidate.ceremony,
    origin,
    topOrigin: topOrigin && topOrigin !== origin ? topOrigin : undefined,
    relyingParty:
      typeof candidate.relyingParty === "string" &&
      candidate.relyingParty.trim() !== ""
        ? normalizeHost(candidate.relyingParty)
        : undefined,
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
  const canceledRequests = new Set<number>();
  registerUnlockCompleteHandler(chromeApi);
  chromeApi.webAuthenticationProxy?.onRequestCanceled?.addListener?.((request) => {
    const requestId =
      typeof request === "number"
        ? request
        : (request as { requestId?: unknown } | null)?.requestId;
    if (typeof requestId === "number") {
      canceledRequests.add(requestId);
      void recordWebAuthnDebug(chromeApi, {
        event: "request_canceled",
        requestId
      });
    }
  });
  chromeApi.webAuthenticationProxy?.onIsUvpaaRequest?.addListener?.((request) => {
    void handleIsUvpaaRequest(chromeApi, request);
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

function registerUnlockCompleteHandler(chromeApi: ChromeLike) {
  const messageSource = chromeApi.runtime?.onMessage;
  if (
    !messageSource ||
    typeof messageSource.addListener !== "function" ||
    registeredUnlockMessageSources.has(messageSource)
  ) {
    return;
  }

  registeredUnlockMessageSources.add(messageSource);
  messageSource.addListener((message, sender) => {
    if (isUnlockCompleteMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      if (
        !promptCompletionMatches(
          unlockPromptContexts,
          unlockPromptNonces,
          requestId,
          message,
          sender,
          "unlock"
        )
      ) {
        return;
      }
      void recordWebAuthnDebug(chromeApi, {
        event: "unlock_complete_message",
        requestId
      });
      clearUnlockPromptState(requestId);
      for (const waiter of [...(unlockCompleteWaiters.get(requestId) ?? [])]) {
        waiter();
      }
      return;
    }

    if (isPresenceCompleteMessage(message)) {
      const requestId = requestIdFromMessage(message);
      if (typeof requestId !== "number") {
        return;
      }
      if (
        !promptCompletionMatches(
          presencePromptContexts,
          presencePromptNonces,
          requestId,
          message,
          sender,
          "approve"
        )
      ) {
        return;
      }
      void recordWebAuthnDebug(chromeApi, {
        event: "presence_complete_message",
        requestId
      });
      const credentialId = credentialIdFromMessage(message);
      clearPresencePromptState(requestId);
      for (const waiter of [...(presenceCompleteWaiters.get(requestId) ?? [])]) {
        waiter(credentialId);
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

function promptCompletionMatches(
  contexts: Map<number, WebAuthnPromptContext>,
  nonces: Map<number, string>,
  requestId: number,
  message: unknown,
  sender: unknown,
  mode: "unlock" | "approve"
) {
  const expected = contexts.get(requestId);
  const expectedNonce = nonces.get(requestId);
  const candidate = message as
    | {
        origin?: unknown;
        relyingParty?: unknown;
        topOrigin?: unknown;
        nonce?: unknown;
      }
    | null;
  return (
    Boolean(expected) &&
    typeof expectedNonce === "string" &&
    candidate?.nonce === expectedNonce &&
    candidate?.origin === expected?.origin &&
    candidate?.relyingParty === expected?.relyingParty &&
    candidate?.topOrigin === expected?.topOrigin &&
    senderMatchesPrompt(sender, mode, requestId, expectedNonce)
  );
}

function senderMatchesPrompt(
  sender: unknown,
  mode: "unlock" | "approve",
  requestId: number,
  nonce: string
) {
  const url = (sender as { url?: unknown } | null)?.url;
  if (typeof url !== "string") {
    return false;
  }
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "chrome-extension:" &&
      parsed.pathname.endsWith("/popup.html") &&
      parsed.searchParams.get("webauthn") === mode &&
      parsed.searchParams.get("requestId") === String(requestId) &&
      parsed.searchParams.get("nonce") === nonce
    );
  } catch {
    return false;
  }
}

async function handleIsUvpaaRequest(chromeApi: ChromeLike, request: unknown) {
  const requestId = requestIdFrom(request);
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_received",
    requestId
  });
  await chromeApi.webAuthenticationProxy?.completeIsUvpaaRequest?.({
    requestId,
    isUvpaa: false
  });
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_completed",
    requestId,
    isUvpaa: false
  });
}

async function handleGetRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown,
  canceledRequests: Set<number>
) {
  const requestId = requestIdFrom(request);
  await recordWebAuthnDebug(chromeApi, {
    event: "get_received",
    requestId,
    summary: requestSummaryFrom(request)
  });
  try {
    const options = requestOptionsFrom(request);
    rejectRequiredUserVerification(options);
    let credentialIds = credentialIdsFromOptions(options);
    const requestedRpId = relyingPartyIdFromGetOptions(options);
    const originContext = await originContextForRequest(request, "get", options);
    if (!originContext) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    rejectUnsupportedMediation(options, originContext);
    const origin = originContext.origin;
    const relyingParty = relyingPartyFromGetOptions(options, origin);
    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.get",
      options.challenge,
      originContext
    );

    const session = (await sendRuntimeCommand({
      type: "get_session_state"
    })) as { activeVaultId?: string | null };
    await recordWebAuthnDebug(chromeApi, {
      event: "get_session_state",
      requestId,
      hasActiveVault: Boolean(session.activeVaultId)
    });
    if (canceledRequests.has(requestId)) {
      return;
    }
    const activeVault = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      session,
      promptContextFrom(originContext, relyingParty),
      canceledRequests
    );
    if (!activeVault) {
      return;
    }
    const credentialSelection = await credentialSelectionForGetRequest(
      sendRuntimeCommand,
      activeVault.activeVaultId,
      relyingParty,
      credentialIds
    );
    credentialIds = credentialSelection.credentialIds;
    const presencePromptContext = promptContextFrom(
      originContext,
      relyingParty,
      credentialSelection.promptOptions
    );
    if (!activeVault.userPresenceVerified || credentialSelection.promptOptions.length > 0) {
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        presencePromptContext,
        canceledRequests
      );
      if (!approved) {
        return;
      }
      if (approved.selectedCredentialId) {
        credentialIds = [approved.selectedCredentialId];
      }
    }
    const relyingPartyValidation = requestedRpId
      ? await validateOriginForRelyingParty(origin, requestedRpId)
      : { allowed: true, relatedOriginVerified: false };
    if (!relyingPartyValidation.allowed) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }

    const assertion = await createAssertionForAllowedCredentials(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      activeVault.activeVaultId,
      relyingParty,
      origin,
      credentialIds,
      clientDataJsonBase64url,
      true,
      relyingPartyValidation.relatedOriginVerified,
      canceledRequests
    );
    if (!assertion) {
      return;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "get_runtime_assertion",
      requestId,
      relyingParty,
      origin,
      credentialId: assertion.credentialId
    });
    if (canceledRequests.has(requestId)) {
      return;
    }

    await completeGetRequest(chromeApi, {
      requestId,
      responseJson: JSON.stringify({
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          authenticatorData: assertion.authenticatorDataBase64url,
          clientDataJSON: assertion.clientDataJsonBase64url,
          signature: assertion.signatureBase64url,
          userHandle: assertion.userHandleBase64url ?? null
        }
      })
    });
    await recordWebAuthnDebug(chromeApi, {
      event: "get_completed",
      requestId
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "get_error",
      requestId,
      error: errorSummary(error)
    });
    if (canceledRequests.has(requestId)) {
      return;
    }
    await completeGetRequest(chromeApi, {
      requestId,
      error: webAuthnError(error)
    });
  } finally {
    canceledRequests.delete(requestId);
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

type PasskeyCredentialListResponse = {
  credentials: PasskeyCredentialOption[];
};

async function credentialSelectionForGetRequest(
  sendRuntimeCommand: RuntimeCommandSender,
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

  if (credentials.length === 1) {
    return {
      credentialIds: [credentials[0].credentialId],
      promptOptions: [] as PasskeyCredentialOption[]
    };
  }

  return {
    credentialIds,
    promptOptions: credentials
  };
}

async function createAssertionForAllowedCredentials(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  activeVaultId: string,
  relyingParty: string,
  origin: string,
  credentialIds: Array<string | null>,
  clientDataJsonBase64url: string,
  userPresenceVerified: boolean,
  relatedOriginVerified: boolean,
  canceledRequests: Set<number>
) {
  let lastError: Error | null = null;

  for (const credentialId of credentialIds) {
    if (canceledRequests.has(requestId)) {
      return null;
    }

    const response = await sendRuntimeCommand({
      type: "create_passkey_assertion",
      vault_id: activeVaultId,
      relying_party: relyingParty,
      origin,
      credential_id: credentialId,
      user_presence_verified: userPresenceVerified,
      ...(relatedOriginVerified ? { related_origin_verified: true } : {}),
      client_data_json_base64url: clientDataJsonBase64url
    });
    const runtimeError = runtimeErrorFromResponse(response);
    if (runtimeError) {
      lastError = runtimeError;
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

  throw (
    lastError ??
    new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey credential not found"
    )
  );
}

function runtimeErrorFromResponse(response: unknown) {
  if (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "error"
  ) {
    const message = (response as { message?: unknown }).message;
    return new WebAuthnRequestError(
      "NotAllowedError",
      typeof message === "string" ? message : "runtime command failed"
    );
  }
  return null;
}

function passkeyAssertionFromResponse(response: unknown): PasskeyAssertionResponse {
  const assertion = response as Partial<PasskeyAssertionResponse> | null;
  if (
    !assertion ||
    typeof assertion.credentialId !== "string" ||
    typeof assertion.authenticatorDataBase64url !== "string" ||
    typeof assertion.clientDataJsonBase64url !== "string" ||
    typeof assertion.signatureBase64url !== "string"
  ) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
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
    throw new WebAuthnRequestError(
      "NotAllowedError",
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
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "runtime returned an invalid passkey credential status"
    );
  }
  return {
    credentialId: status.credentialId,
    exists: status.exists
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
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "runtime returned an invalid passkey credential list"
    );
  }

  const credentials = list.credentials.map((credential) => {
    const candidate = credential as Partial<PasskeyCredentialOption> | null;
    if (
      !candidate ||
      typeof candidate.credentialId !== "string" ||
      candidate.credentialId.trim() === "" ||
      typeof candidate.username !== "string"
    ) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
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

async function handleCreateRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  request: unknown,
  canceledRequests: Set<number>
) {
  const requestId = requestIdFrom(request);
  await recordWebAuthnDebug(chromeApi, {
    event: "create_received",
    requestId,
    summary: requestSummaryFrom(request)
  });
  try {
    const options = createRequestOptionsFrom(request);
    rejectCrossPlatformOnlyRegistration(options);
    rejectRequiredUserVerification(options);
    const requestedRpId = relyingPartyIdFromCreateOptions(options);
    const originContext = await originContextForRequest(request, "create", options);
    if (!originContext) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    const origin = originContext.origin;
    const relyingParty = relyingPartyFromCreateOptions(options, origin);
    const clientDataJsonBase64url = clientDataJsonBase64urlFrom(
      "webauthn.create",
      options.challenge,
      originContext
    );

    const session = (await sendRuntimeCommand({
      type: "get_session_state"
    })) as { activeVaultId?: string | null };
    await recordWebAuthnDebug(chromeApi, {
      event: "create_session_state",
      requestId,
      hasActiveVault: Boolean(session.activeVaultId)
    });
    if (canceledRequests.has(requestId)) {
      return;
    }
    const activeVault = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      session,
      promptContextFrom(originContext, relyingParty),
      canceledRequests
    );
    if (!activeVault) {
      return;
    }
    if (!activeVault.userPresenceVerified) {
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        promptContextFrom(originContext, relyingParty),
        canceledRequests
      );
      if (!approved) {
        return;
      }
    }
    const relyingPartyValidation = requestedRpId
      ? await validateOriginForRelyingParty(origin, requestedRpId)
      : { allowed: true, relatedOriginVerified: false };
    if (!relyingPartyValidation.allowed) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }
    const activeVaultId = activeVault.activeVaultId;

    const excludedCredentialIds = excludedCredentialIdsFromCreateOptions(options);
    for (const credentialId of excludedCredentialIds) {
      if (canceledRequests.has(requestId)) {
        return;
      }

      const status = passkeyCredentialStatusFromResponse(
        await sendRuntimeCommand({
          type: "passkey_credential_status",
          vault_id: activeVaultId,
          credential_id: credentialId,
          relying_party: relyingParty
        })
      );
      if (status.exists) {
        throw new WebAuthnRequestError(
          "InvalidStateError",
          "VaultKern passkey credential is already registered"
        );
      }
    }

    const registrationResponse = await sendRuntimeCommand({
      type: "create_passkey_registration",
      vault_id: activeVaultId,
      relying_party: relyingParty,
      origin,
      user_name: userNameFromCreateOptions(options),
      user_display_name: userDisplayNameFromCreateOptions(options),
      user_handle_base64url: userHandleFromCreateOptions(options),
      ...(relyingPartyValidation.relatedOriginVerified
        ? { related_origin_verified: true }
        : {}),
      client_data_json_base64url: clientDataJsonBase64url
    });
    const registration = passkeyRegistrationFromResponse(registrationResponse);
    const rollbackRegistration = async (saveAfterRollback: boolean) => {
      await rollbackPasskeyRegistration(
        sendRuntimeCommand,
        activeVaultId,
        registration.entryId,
        registration.created,
        saveAfterRollback
      );
    };
    await recordWebAuthnDebug(chromeApi, {
      event: "create_runtime_registration",
      requestId,
      relyingParty,
      origin,
      credentialId: registration.credentialId
    });
    if (canceledRequests.has(requestId)) {
      await rollbackRegistration(false);
      return;
    }

    try {
      const saveResponse = await sendRuntimeCommand({
        type: "save_vault",
        vault_id: activeVaultId
      });
      const saveError = runtimeErrorFromResponse(saveResponse);
      if (saveError) {
        throw saveError;
      }
    } catch (error) {
      await rollbackRegistration(false);
      throw error;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "create_saved",
      requestId
    });
    if (canceledRequests.has(requestId)) {
      await rollbackRegistration(true);
      return;
    }

    try {
      await completeCreateRequest(chromeApi, {
        requestId,
        responseJson: JSON.stringify({
          id: registration.credentialId,
          rawId: registration.credentialId,
          type: "public-key",
          authenticatorAttachment: "platform",
          clientExtensionResults: {},
          response: {
            authenticatorData: registration.authenticatorDataBase64url,
            attestationObject: registration.attestationObjectBase64url,
            clientDataJSON: registration.clientDataJsonBase64url,
            publicKey: registration.publicKeyBase64url,
            publicKeyAlgorithm: registration.publicKeyAlgorithm,
            transports: ["internal"]
          }
        })
      });
    } catch (error) {
      await rollbackRegistration(true);
      await recordWebAuthnDebug(chromeApi, {
        event: "create_complete_error",
        requestId,
        error: errorSummary(error)
      });
      throw error;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "create_completed",
      requestId
    });
  } catch (error) {
    await recordWebAuthnDebug(chromeApi, {
      event: "create_error",
      requestId,
      error: errorSummary(error)
    });
    if (canceledRequests.has(requestId)) {
      return;
    }
    await completeCreateRequest(chromeApi, {
      requestId,
      error: webAuthnError(error)
    });
  } finally {
    canceledRequests.delete(requestId);
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
    authenticatorSelection?: {
      authenticatorAttachment?: unknown;
      userVerification?: unknown;
    };
  };
  if (typeof options.challenge !== "string") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn challenge");
  }
  if (
    Array.isArray(options.pubKeyCredParams) &&
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

function rejectUnsupportedMediation(
  options: { mediation?: unknown },
  originContext: WebAuthnOriginContext
) {
  const mediation =
    typeof options.mediation === "string"
      ? options.mediation
      : originContext.mediation;
  if (!mediation) {
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
    typeof originContext.topOrigin === "string" &&
    originContext.topOrigin !== originContext.origin;
  return base64urlEncode(
    JSON.stringify({
      type,
      challenge,
      origin: originContext.origin,
      crossOrigin,
      ...(crossOrigin ? { topOrigin: originContext.topOrigin } : {})
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

async function rollbackPasskeyRegistration(
  sendRuntimeCommand: RuntimeCommandSender,
  vaultId: string,
  entryId: string,
  created: boolean,
  saveAfterRollback: boolean
) {
  const rollbackResponse = await sendRuntimeCommand({
    type: "rollback_passkey_registration",
    vault_id: vaultId,
    entry_id: entryId,
    created
  });
  const rollbackError = runtimeErrorFromResponse(rollbackResponse);
  if (rollbackError) {
    throw rollbackError;
  }

  if (!saveAfterRollback) {
    return;
  }

  const saveResponse = await sendRuntimeCommand({
    type: "save_vault",
    vault_id: vaultId
  });
  const saveError = runtimeErrorFromResponse(saveResponse);
  if (saveError) {
    throw saveError;
  }
}

function relyingPartyIdFromGetOptions(options: { rpId?: unknown }) {
  return typeof options.rpId === "string" && options.rpId.trim() !== ""
    ? normalizeHost(options.rpId)
    : null;
}

function relyingPartyFromGetOptions(options: { rpId?: unknown }, origin: string) {
  return relyingPartyIdFromGetOptions(options) ?? relyingPartyFromOrigin(origin);
}

function relyingPartyIdFromCreateOptions(options: {
  rp?: { id?: unknown; name?: unknown };
}) {
  const rpId = options.rp?.id;
  return typeof rpId === "string" && rpId.trim() !== "" ? normalizeHost(rpId) : null;
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

function originFromUnknown(value: unknown) {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }

  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function topOriginFromRequestDetails(requestDetailsJson: unknown) {
  if (typeof requestDetailsJson !== "string") {
    return null;
  }

  try {
    const details = JSON.parse(requestDetailsJson) as { topOrigin?: unknown };
    return originFromUnknown(details.topOrigin);
  } catch {
    return null;
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

  const topOrigin =
    originFromUnknown(candidate?.topOrigin) ??
    originFromUnknown(candidate?.callerTopOrigin) ??
    originFromUnknown(candidate?.topLevelOrigin) ??
    topOriginFromRequestDetails(candidate?.requestDetailsJson);
  const mediation = mediationFromRequestDetails(candidate?.requestDetailsJson);

  return {
    origin,
    topOrigin: topOrigin && topOrigin !== origin ? topOrigin : undefined,
    mediation
  };
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
    return directOrigin;
  }

  const observedOrigin = originContextFromPageRequest(ceremony, options);
  if (observedOrigin) {
    return observedOrigin;
  }

  const deadline = Date.now() + 500;
  while (Date.now() < deadline) {
    await delay(25);
    const delayedObservedOrigin = originContextFromPageRequest(ceremony, options);
    if (delayedObservedOrigin) {
      return delayedObservedOrigin;
    }
  }

  return null;
}

function originContextFromPageRequest(
  ceremony: "create" | "get",
  options: {
    challenge?: unknown;
    rpId?: unknown;
    rp?: { id?: unknown; name?: unknown };
    allowCredentials?: unknown;
    excludeCredentials?: unknown;
  }
) {
  const challenge = typeof options.challenge === "string" ? options.challenge : null;
  if (!challenge) {
    return null;
  }

  const relyingParty =
    ceremony === "create"
      ? relyingPartyIdFromCreateOptions(options)
      : relyingPartyIdFromGetOptions(options);
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
        relyingParty,
        allowCredentialIds,
        excludeCredentialIds
      })
    ) {
      observedPageRequests.splice(index, 1);
      return {
        origin: observed.origin,
        topOrigin: observed.topOrigin,
        mediation: observed.mediation
      };
    }
  }

  return null;
}

function observedPageRequestMatches(
  observed: ObservedWebAuthnPageRequest,
  expected: {
    ceremony: "create" | "get";
    challenge: string;
    relyingParty: string | null;
    allowCredentialIds: string[];
    excludeCredentialIds: string[];
  }
) {
  if (observed.ceremony !== expected.ceremony) {
    return false;
  }
  if (!observed.challenge || observed.challenge !== expected.challenge) {
    return false;
  }
  if (
    expected.relyingParty &&
    observed.relyingParty &&
    observed.relyingParty !== expected.relyingParty
  ) {
    return false;
  }
  if (
    expected.allowCredentialIds.length > 0 &&
    observed.allowCredentialIds &&
    !sameStringSet(observed.allowCredentialIds, expected.allowCredentialIds)
  ) {
    return false;
  }
  if (
    expected.excludeCredentialIds.length > 0 &&
    observed.excludeCredentialIds &&
    !sameStringSet(observed.excludeCredentialIds, expected.excludeCredentialIds)
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

  const rightSet = new Set(right);
  return left.every((value) => rightSet.has(value));
}

function stringArrayFrom(value: unknown) {
  return Array.isArray(value) && value.every(isString) ? value : undefined;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

async function validateOriginForRelyingParty(origin: string, relyingParty: string) {
  if (originMatchesRelyingParty(origin, relyingParty)) {
    return { allowed: true, relatedOriginVerified: false };
  }

  if (await originAllowedByRelatedOrigins(origin, relyingParty)) {
    return { allowed: true, relatedOriginVerified: true };
  }

  return { allowed: false, relatedOriginVerified: false };
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

async function originAllowedByRelatedOrigins(origin: string, relyingParty: string) {
  if (typeof fetch !== "function") {
    return false;
  }

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    return false;
  }
  if (parsedOrigin.protocol !== "https:") {
    return false;
  }
  const originHost = normalizedHostFromUrl(origin);
  if (isLoopbackHost(originHost) || isIpAddress(originHost) || !psl.get(originHost)) {
    return false;
  }

  const normalizedRelyingParty = normalizeHost(relyingParty);
  if (
    isLoopbackHost(normalizedRelyingParty) ||
    isIpAddress(normalizedRelyingParty) ||
    !psl.get(normalizedRelyingParty)
  ) {
    return false;
  }

  try {
    const response = await fetch(
      `https://${normalizedRelyingParty}/.well-known/webauthn`,
      {
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      }
    );
    if (!response.ok) {
      return false;
    }

    const body = (await response.json()) as { origins?: unknown };
    if (!Array.isArray(body.origins)) {
      return false;
    }
    if (relatedOriginLabelCount(body.origins) > RELATED_ORIGIN_LABEL_LIMIT) {
      return false;
    }

    const normalizedOrigin = parsedOrigin.origin;
    return body.origins.some((candidate) => {
      const candidateOrigin = originFromUnknown(candidate);
      return candidateOrigin === normalizedOrigin;
    });
  } catch {
    return false;
  }
}

function relatedOriginLabelCount(origins: unknown[]) {
  const labels = new Set<string>();
  for (const origin of origins) {
    const label = relatedOriginLabel(origin);
    if (label) {
      labels.add(label);
    }
  }
  return labels.size;
}

function relatedOriginLabel(origin: unknown) {
  const candidateOrigin = originFromUnknown(origin);
  if (!candidateOrigin) {
    return null;
  }
  try {
    const host = normalizedHostFromUrl(candidateOrigin);
    if (isLoopbackHost(host) || isIpAddress(host)) {
      return null;
    }
    return psl.get(host);
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
  if (typeof userHandle !== "string" || userHandle.trim() === "") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn user id");
  }
  return userHandle;
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

async function activeVaultForRequest(
  chromeApi: ChromeLike,
  sendRuntimeCommand: RuntimeCommandSender,
  requestId: number,
  initialSession: { activeVaultId?: string | null },
  promptContext: WebAuthnPromptContext,
  canceledRequests: Set<number>
) {
  if (initialSession.activeVaultId) {
    return {
      activeVaultId: initialSession.activeVaultId,
      userPresenceVerified: false
    };
  }

  await recordWebAuthnDebug(chromeApi, {
    event: "unlock_prompt_opening",
    requestId
  });
  const deadline = Date.now() + 120_000;
  let unlockSignal = waitForUnlockSignal(
    requestId,
    Math.min(1_000, Math.max(0, deadline - Date.now()))
  );
  await openUnlockPrompt(chromeApi, requestId, promptContext);

  while (Date.now() < deadline) {
    if (canceledRequests.has(requestId)) {
      clearUnlockPromptState(requestId);
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
        clearUnlockPromptState(requestId);
        return {
          activeVaultId: session.activeVaultId,
          userPresenceVerified: false
        };
      }
      unlockSignal = waitForUnlockSignal(
        requestId,
        Math.min(1_000, Math.max(0, deadline - Date.now()))
      );
      continue;
    }
    if (signal === "dismissed") {
      throw new WebAuthnRequestError(
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
        userPresenceVerified: true
      };
    }

    unlockSignal = waitForUnlockSignal(
      requestId,
      Math.min(1_000, Math.max(0, deadline - Date.now()))
    );
    await delay(500);
  }

  clearUnlockPromptState(requestId);
  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern vault unlock timed out"
  );
}

async function userPresenceForRequest(
  chromeApi: ChromeLike,
  requestId: number,
  promptContext: WebAuthnPromptContext,
  canceledRequests: Set<number>
) {
  await recordWebAuthnDebug(chromeApi, {
    event: "presence_prompt_opening",
    requestId
  });
  await openPresencePrompt(chromeApi, requestId, promptContext);

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (canceledRequests.has(requestId)) {
      clearPresencePromptState(requestId);
      await recordWebAuthnDebug(chromeApi, {
        event: "presence_wait_canceled",
        requestId
      });
      return false;
    }

    const signal = await waitForPresenceSignal(
      requestId,
      Math.min(1_000, Math.max(0, deadline - Date.now()))
    );
    if (signal?.type === "complete") {
      const selectedCredentialId = selectedCredentialIdForPrompt(
        promptContext,
        signal.credentialId
      );
      return selectedCredentialId ? { selectedCredentialId } : {};
    }
    if (signal?.type === "dismissed") {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern passkey approval was dismissed"
      );
    }
  }

  clearPresencePromptState(requestId);
  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey approval timed out"
  );
}

function selectedCredentialIdForPrompt(
  promptContext: WebAuthnPromptContext,
  credentialId: string | undefined
) {
  const credentialOptions = promptContext.credentialOptions ?? [];
  if (credentialOptions.length === 0) {
    return credentialId;
  }
  if (!credentialId) {
    throw new WebAuthnRequestError(
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

function waitForUnlockSignal(requestId: number, timeoutMs: number) {
  return new Promise<"complete" | "dismissed" | null>((resolve) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      finish(null);
    }, timeoutMs);
    const completeWaiter = () => {
      finish("complete");
    };
    const dismissWaiter = () => {
      finish("dismissed");
    };

    function finish(signaled: "complete" | "dismissed" | null) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutId);
      const completeWaiters = unlockCompleteWaiters.get(requestId);
      completeWaiters?.delete(completeWaiter);
      if (completeWaiters?.size === 0) {
        unlockCompleteWaiters.delete(requestId);
      }
      const dismissWaiters = unlockDismissWaiters.get(requestId);
      dismissWaiters?.delete(dismissWaiter);
      if (dismissWaiters?.size === 0) {
        unlockDismissWaiters.delete(requestId);
      }
      resolve(signaled);
    }

    const completeWaiters = unlockCompleteWaiters.get(requestId) ?? new Set<() => void>();
    completeWaiters.add(completeWaiter);
    unlockCompleteWaiters.set(requestId, completeWaiters);
    const dismissWaiters = unlockDismissWaiters.get(requestId) ?? new Set<() => void>();
    dismissWaiters.add(dismissWaiter);
    unlockDismissWaiters.set(requestId, dismissWaiters);
  });
}

function waitForPresenceSignal(requestId: number, timeoutMs: number) {
  return new Promise<PresenceSignal>((resolve) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      finish(null);
    }, timeoutMs);
    const completeWaiter = (credentialId?: string) => {
      finish({ type: "complete", credentialId });
    };
    const dismissWaiter = () => {
      finish({ type: "dismissed" });
    };

    function finish(signaled: PresenceSignal) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutId);
      const completeWaiters = presenceCompleteWaiters.get(requestId);
      completeWaiters?.delete(completeWaiter);
      if (completeWaiters?.size === 0) {
        presenceCompleteWaiters.delete(requestId);
      }
      const dismissWaiters = presenceDismissWaiters.get(requestId);
      dismissWaiters?.delete(dismissWaiter);
      if (dismissWaiters?.size === 0) {
        presenceDismissWaiters.delete(requestId);
      }
      resolve(signaled);
    }

    const completeWaiters =
      presenceCompleteWaiters.get(requestId) ??
      new Set<(credentialId?: string) => void>();
    completeWaiters.add(completeWaiter);
    presenceCompleteWaiters.set(requestId, completeWaiters);
    const dismissWaiters = presenceDismissWaiters.get(requestId) ?? new Set<() => void>();
    dismissWaiters.add(dismissWaiter);
    presenceDismissWaiters.set(requestId, dismissWaiters);
  });
}

async function openUnlockPrompt(
  chromeApi: ChromeLike,
  requestId: number,
  promptContext: WebAuthnPromptContext
) {
  if (!chromeApi.windows?.create) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern vault is locked and no unlock window is available"
    );
  }

  const existingWindowId = unlockPromptWindowIds.get(requestId);
  if (typeof existingWindowId === "number" && chromeApi.windows.update) {
    try {
      await chromeApi.windows.update(existingWindowId, { focused: true });
      return;
    } catch {
      clearUnlockPromptState(requestId);
    }
  }

  const nonce = generatePromptNonce();
  unlockPromptContexts.set(requestId, promptContext);
  unlockPromptNonces.set(requestId, nonce);
  const popupPath = popupPathForWebAuthnPrompt("unlock", requestId, promptContext, nonce);
  const url =
    chromeApi.runtime?.getURL?.(popupPath) ??
    popupPath;
  const created = await chromeApi.windows.create({
    url,
    type: "popup",
    width: 460,
    height: 620,
    focused: true
  });
  if (created && typeof created.id === "number") {
    unlockPromptWindowIds.set(requestId, created.id);
    watchUnlockPromptWindow(chromeApi, requestId, created.id);
  }
}

async function openPresencePrompt(
  chromeApi: ChromeLike,
  requestId: number,
  promptContext: WebAuthnPromptContext
) {
  if (!chromeApi.windows?.create) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey approval window is unavailable"
    );
  }

  const existingWindowId = presencePromptWindowIds.get(requestId);
  if (typeof existingWindowId === "number" && chromeApi.windows.update) {
    try {
      await chromeApi.windows.update(existingWindowId, { focused: true });
      return;
    } catch {
      clearPresencePromptState(requestId);
    }
  }

  const nonce = generatePromptNonce();
  presencePromptContexts.set(requestId, promptContext);
  presencePromptNonces.set(requestId, nonce);
  const popupPath = popupPathForWebAuthnPrompt("approve", requestId, promptContext, nonce);
  const url =
    chromeApi.runtime?.getURL?.(popupPath) ??
    popupPath;
  const created = await chromeApi.windows.create({
    url,
    type: "popup",
    width: 460,
    height: 360,
    focused: true
  });
  if (created && typeof created.id === "number") {
    presencePromptWindowIds.set(requestId, created.id);
    watchPresencePromptWindow(chromeApi, requestId, created.id);
  }
}

function watchPresencePromptWindow(
  chromeApi: ChromeLike,
  requestId: number,
  windowId: number
) {
  const onRemoved = chromeApi.windows?.onRemoved;
  if (!onRemoved?.addListener) {
    return;
  }

  presencePromptRemovalCleanups.get(requestId)?.();
  const listener = (removedWindowId: number) => {
    if (removedWindowId !== windowId) {
      return;
    }

    clearPresencePromptState(requestId);
    void recordWebAuthnDebug(chromeApi, {
      event: "presence_prompt_dismissed",
      requestId,
      windowId
    });
    for (const waiter of [...(presenceDismissWaiters.get(requestId) ?? [])]) {
      waiter();
    }
  };
  onRemoved.addListener(listener);
  presencePromptRemovalCleanups.set(requestId, () => {
    onRemoved.removeListener?.(listener);
    presencePromptRemovalCleanups.delete(requestId);
  });
}

function watchUnlockPromptWindow(
  chromeApi: ChromeLike,
  requestId: number,
  windowId: number
) {
  const onRemoved = chromeApi.windows?.onRemoved;
  if (!onRemoved?.addListener) {
    return;
  }

  unlockPromptRemovalCleanups.get(requestId)?.();
  const listener = (removedWindowId: number) => {
    if (removedWindowId !== windowId) {
      return;
    }

    clearUnlockPromptState(requestId);
    void recordWebAuthnDebug(chromeApi, {
      event: "unlock_prompt_dismissed",
      requestId,
      windowId
    });
    for (const waiter of [...(unlockDismissWaiters.get(requestId) ?? [])]) {
      waiter();
    }
  };
  onRemoved.addListener(listener);
  unlockPromptRemovalCleanups.set(requestId, () => {
    onRemoved.removeListener?.(listener);
    unlockPromptRemovalCleanups.delete(requestId);
  });
}

function popupPathForWebAuthnPrompt(
  mode: "unlock" | "approve",
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
  if (mode === "approve" && promptContext.credentialOptions?.length) {
    params.set("credentialOptions", JSON.stringify(promptContext.credentialOptions));
  }
  return `popup.html?${params.toString()}`;
}

function generatePromptNonce() {
  const bytes = new Uint8Array(16);
  const cryptoApi = (globalThis as typeof globalThis & { crypto?: Crypto }).crypto;
  if (cryptoApi?.getRandomValues) {
    cryptoApi.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function clearUnlockPromptState(requestId: number) {
  unlockPromptRemovalCleanups.get(requestId)?.();
  unlockPromptWindowIds.delete(requestId);
  unlockPromptContexts.delete(requestId);
  unlockPromptNonces.delete(requestId);
}

function clearPresencePromptState(requestId: number) {
  presencePromptRemovalCleanups.get(requestId)?.();
  presencePromptWindowIds.delete(requestId);
  presencePromptContexts.delete(requestId);
  presencePromptNonces.delete(requestId);
}

function delay(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

class WebAuthnRequestError extends Error {
  constructor(
    public readonly name: string,
    message: string
  ) {
    super(message);
  }
}

function webAuthnError(error: unknown) {
  if (error instanceof WebAuthnRequestError) {
    return {
      name: error.name,
      message: error.message
    };
  }
  return {
    name: "NotAllowedError",
    message: error instanceof Error ? error.message : "passkey request failed"
  };
}

export function recordWebAuthnDebug(
  chromeApi: ChromeLike,
  event: Record<string, unknown>
) {
  void persistWebAuthnDebug(chromeApi, event);
  return Promise.resolve();
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
    const existing = await storage.get([
      WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY,
      WEB_AUTHN_DEBUG_STORAGE_KEY
    ]);
    if (existing[WEB_AUTHN_DEBUG_ENABLED_STORAGE_KEY] !== true) {
      return;
    }
    const previous = Array.isArray(existing[WEB_AUTHN_DEBUG_STORAGE_KEY])
      ? existing[WEB_AUTHN_DEBUG_STORAGE_KEY]
      : [];
    await storage.set({
      [WEB_AUTHN_DEBUG_STORAGE_KEY]: [
        ...previous.slice(-49),
        {
          at: new Date().toISOString(),
          ...event
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
      excludeCredentialsCount: Array.isArray(options.excludeCredentials)
        ? options.excludeCredentials.length
        : undefined,
      allowCredentialsCount: Array.isArray(options.allowCredentials)
        ? options.allowCredentials.length
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
