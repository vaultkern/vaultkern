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

let unlockPromptWindowId: number | null = null;
const unlockCompleteWaiters = new Set<() => void>();
let presencePromptWindowId: number | null = null;
const presenceCompleteWaiters = new Set<() => void>();
const observedPageRequests: ObservedWebAuthnPageRequest[] = [];
const registeredUnlockMessageSources = new WeakSet<object>();
const registeredRequestHandlerSources = new WeakSet<object>();
const OBSERVED_PAGE_REQUEST_MAX_AGE_MS = 120_000;

type ObservedWebAuthnPageRequest = {
  ceremony: "create" | "get";
  origin: string;
  relyingParty?: string;
  challenge?: string;
  allowCredentialIds?: string[];
  excludeCredentialIds?: string[];
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
    relyingParty?: unknown;
    challenge?: unknown;
    allowCredentialIds?: unknown;
    excludeCredentialIds?: unknown;
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

  pruneObservedPageRequests(Date.now());
  observedPageRequests.push({
    ceremony: candidate.ceremony,
    origin,
    relyingParty:
      typeof candidate.relyingParty === "string" &&
      candidate.relyingParty.trim() !== ""
        ? candidate.relyingParty.trim()
        : undefined,
    challenge:
      typeof candidate.challenge === "string" && candidate.challenge.trim() !== ""
        ? candidate.challenge
        : undefined,
    allowCredentialIds: stringArrayFrom(candidate.allowCredentialIds),
    excludeCredentialIds: stringArrayFrom(candidate.excludeCredentialIds),
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
  messageSource.addListener((message) => {
    if (isUnlockCompleteMessage(message)) {
      void recordWebAuthnDebug(chromeApi, {
        event: "unlock_complete_message"
      });
      for (const waiter of [...unlockCompleteWaiters]) {
        waiter();
      }
      return;
    }

    if (isPresenceCompleteMessage(message)) {
      void recordWebAuthnDebug(chromeApi, {
        event: "presence_complete_message"
      });
      for (const waiter of [...presenceCompleteWaiters]) {
        waiter();
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

async function handleIsUvpaaRequest(chromeApi: ChromeLike, request: unknown) {
  const requestId = requestIdFrom(request);
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_received",
    requestId
  });
  await chromeApi.webAuthenticationProxy?.completeIsUvpaaRequest?.({
    requestId,
    isUvpaa: true
  });
  await recordWebAuthnDebug(chromeApi, {
    event: "is_uvpaa_completed",
    requestId,
    isUvpaa: true
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
    const credentialIds = credentialIdsFromOptions(options);
    const requestedRpId = relyingPartyIdFromGetOptions(options);
    const origin = await originForRequest(request, "get", options);
    if (!origin) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    const relyingParty = relyingPartyFromGetOptions(options, origin);
    if (requestedRpId && !originMatchesRelyingParty(origin, requestedRpId)) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }
    const clientDataJsonBase64url = base64urlEncode(
      JSON.stringify({
        type: "webauthn.get",
        challenge: options.challenge,
        origin,
        crossOrigin: false
      })
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
      canceledRequests
    );
    if (!activeVault) {
      return;
    }
    if (!activeVault.userPresenceVerified) {
      const approved = await userPresenceForRequest(
        chromeApi,
        requestId,
        canceledRequests
      );
      if (!approved) {
        return;
      }
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
    const requestedRpId = relyingPartyIdFromCreateOptions(options);
    const origin = await originForRequest(request, "create", options);
    if (!origin) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "VaultKern cannot identify the WebAuthn request origin"
      );
    }
    const relyingParty = relyingPartyFromCreateOptions(options, origin);
    if (requestedRpId && !originMatchesRelyingParty(origin, requestedRpId)) {
      throw new WebAuthnRequestError(
        "NotAllowedError",
        "WebAuthn request origin does not match relying party"
      );
    }
    const clientDataJsonBase64url = base64urlEncode(
      JSON.stringify({
        type: "webauthn.create",
        challenge: options.challenge,
        origin,
        crossOrigin: false
      })
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
      canceledRequests
    );
    if (!activeVault) {
      return;
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
      client_data_json_base64url: clientDataJsonBase64url
    });
    const registration = passkeyRegistrationFromResponse(registrationResponse);
    const rollbackRegistration = async (saveAfterRollback: boolean) => {
      await rollbackPasskeyRegistration(
        sendRuntimeCommand,
        activeVaultId,
        registration.entryId,
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
      return;
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
    authenticatorSelection?: { authenticatorAttachment?: unknown };
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

async function rollbackPasskeyRegistration(
  sendRuntimeCommand: RuntimeCommandSender,
  vaultId: string,
  entryId: string,
  saveAfterRollback: boolean
) {
  const deleteResponse = await sendRuntimeCommand({
    type: "delete_entry",
    vault_id: vaultId,
    entry_id: entryId
  });
  const deleteError = runtimeErrorFromResponse(deleteResponse);
  if (deleteError) {
    throw deleteError;
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
    ? options.rpId.trim()
    : null;
}

function relyingPartyFromGetOptions(options: { rpId?: unknown }, origin: string) {
  return relyingPartyIdFromGetOptions(options) ?? relyingPartyFromOrigin(origin);
}

function relyingPartyIdFromCreateOptions(options: {
  rp?: { id?: unknown; name?: unknown };
}) {
  const rpId = options.rp?.id;
  return typeof rpId === "string" && rpId.trim() !== "" ? rpId.trim() : null;
}

function relyingPartyFromCreateOptions(
  options: { rp?: { id?: unknown; name?: unknown } },
  origin: string
) {
  return relyingPartyIdFromCreateOptions(options) ?? relyingPartyFromOrigin(origin);
}

function relyingPartyFromOrigin(origin: string) {
  try {
    const hostname = new URL(origin).hostname;
    if (hostname.trim() !== "") {
      return hostname;
    }
  } catch {
    // Fall through to the WebAuthn-shaped error below.
  }
  throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn RP ID");
}

function originFromRequest(request: unknown) {
  const candidate = request as
    | {
        origin?: unknown;
        callerOrigin?: unknown;
        requestOrigin?: unknown;
        requestDetailsJson?: unknown;
      }
    | null
    | undefined;
  for (const value of [
    candidate?.origin,
    candidate?.callerOrigin,
    candidate?.requestOrigin
  ]) {
    if (typeof value === "string" && value.trim() !== "") {
      return new URL(value).origin;
    }
  }

  if (typeof candidate?.requestDetailsJson === "string") {
    try {
      const details = JSON.parse(candidate.requestDetailsJson) as { origin?: unknown };
      if (typeof details.origin === "string" && details.origin.trim() !== "") {
        return new URL(details.origin).origin;
      }
    } catch {
      // Parsed elsewhere; keep this helper WebAuthn-shaped.
    }
  }

  return null;
}

async function originForRequest(
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
  const directOrigin = originFromRequest(request);
  if (directOrigin) {
    return directOrigin;
  }

  const observedOrigin = originFromPageRequest(ceremony, options);
  if (observedOrigin) {
    return observedOrigin;
  }

  const deadline = Date.now() + 500;
  while (Date.now() < deadline) {
    await delay(25);
    const delayedObservedOrigin = originFromPageRequest(ceremony, options);
    if (delayedObservedOrigin) {
      return delayedObservedOrigin;
    }
  }

  return null;
}

function originFromPageRequest(
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
      return observed.origin;
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

function originMatchesRelyingParty(origin: string, relyingParty: string) {
  try {
    const host = new URL(origin).hostname;
    return host === relyingParty || host.endsWith(`.${relyingParty}`);
  } catch {
    return false;
  }
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
  await openUnlockPrompt(chromeApi);

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (canceledRequests.has(requestId)) {
      await recordWebAuthnDebug(chromeApi, {
        event: "unlock_wait_canceled",
        requestId
      });
      return null;
    }

    const signaled = await waitForUnlockComplete(
      Math.min(1_000, Math.max(0, deadline - Date.now()))
    );
    if (!signaled) {
      continue;
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

    await delay(500);
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern vault unlock timed out"
  );
}

async function userPresenceForRequest(
  chromeApi: ChromeLike,
  requestId: number,
  canceledRequests: Set<number>
) {
  await recordWebAuthnDebug(chromeApi, {
    event: "presence_prompt_opening",
    requestId
  });
  await openPresencePrompt(chromeApi);

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (canceledRequests.has(requestId)) {
      await recordWebAuthnDebug(chromeApi, {
        event: "presence_wait_canceled",
        requestId
      });
      return false;
    }

    const signaled = await waitForPresenceComplete(
      Math.min(1_000, Math.max(0, deadline - Date.now()))
    );
    if (signaled) {
      return true;
    }
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern passkey approval timed out"
  );
}

function waitForUnlockComplete(timeoutMs: number) {
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      finish(false);
    }, timeoutMs);
    const waiter = () => {
      finish(true);
    };

    function finish(signaled: boolean) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutId);
      unlockCompleteWaiters.delete(waiter);
      resolve(signaled);
    }

    unlockCompleteWaiters.add(waiter);
  });
}

function waitForPresenceComplete(timeoutMs: number) {
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const timeoutId = setTimeout(() => {
      finish(false);
    }, timeoutMs);
    const waiter = () => {
      finish(true);
    };

    function finish(signaled: boolean) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutId);
      presenceCompleteWaiters.delete(waiter);
      resolve(signaled);
    }

    presenceCompleteWaiters.add(waiter);
  });
}

async function openUnlockPrompt(chromeApi: ChromeLike) {
  if (!chromeApi.windows?.create) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern vault is locked and no unlock window is available"
    );
  }

  if (unlockPromptWindowId !== null && chromeApi.windows.update) {
    try {
      await chromeApi.windows.update(unlockPromptWindowId, { focused: true });
      return;
    } catch {
      unlockPromptWindowId = null;
    }
  }

  const url =
    chromeApi.runtime?.getURL?.("popup.html?webauthn=unlock") ??
    "popup.html?webauthn=unlock";
  const created = await chromeApi.windows.create({
    url,
    type: "popup",
    width: 460,
    height: 620,
    focused: true
  });
  unlockPromptWindowId =
    created && typeof created.id === "number" ? created.id : null;
}

async function openPresencePrompt(chromeApi: ChromeLike) {
  if (!chromeApi.windows?.create) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey approval window is unavailable"
    );
  }

  if (presencePromptWindowId !== null && chromeApi.windows.update) {
    try {
      await chromeApi.windows.update(presencePromptWindowId, { focused: true });
      return;
    } catch {
      presencePromptWindowId = null;
    }
  }

  const url =
    chromeApi.runtime?.getURL?.("popup.html?webauthn=approve") ??
    "popup.html?webauthn=approve";
  const created = await chromeApi.windows.create({
    url,
    type: "popup",
    width: 460,
    height: 360,
    focused: true
  });
  presencePromptWindowId =
    created && typeof created.id === "number" ? created.id : null;
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

async function recordWebAuthnDebug(
  chromeApi: ChromeLike,
  event: Record<string, unknown>
) {
  try {
    const storage = chromeApi.storage?.local;
    if (!storage?.get || !storage.set) {
      return;
    }
    const existing = await storage.get(["vaultkernWebAuthnDebug"]);
    const previous = Array.isArray(existing.vaultkernWebAuthnDebug)
      ? existing.vaultkernWebAuthnDebug
      : [];
    await storage.set({
      vaultkernWebAuthnDebug: [
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
