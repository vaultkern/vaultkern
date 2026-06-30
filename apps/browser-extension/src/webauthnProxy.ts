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
const registeredUnlockMessageSources = new WeakSet<object>();
const registeredRequestHandlerSources = new WeakSet<object>();

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
    if (!isUnlockCompleteMessage(message)) {
      return;
    }

    void recordWebAuthnDebug(chromeApi, {
      event: "unlock_complete_message"
    });
    for (const waiter of [...unlockCompleteWaiters]) {
      waiter();
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
    const relyingParty = relyingPartyFromOptions(options);
    const credentialIds = credentialIdsFromOptions(options);
    const origin = await activeOrigin(chromeApi, relyingParty);
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
    const activeVaultId = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      session,
      canceledRequests
    );
    if (!activeVaultId) {
      return;
    }

    const assertion = await createAssertionForAllowedCredentials(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      activeVaultId,
      relyingParty,
      origin,
      credentialIds,
      clientDataJsonBase64url,
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
  credentialIds: string[],
  clientDataJsonBase64url: string,
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
    const origin = await activeOrigin(
      chromeApi,
      relyingPartyIdFromCreateOptions(options) ?? undefined
    );
    const relyingParty = relyingPartyFromCreateOptions(options, origin);
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
    const activeVaultId = await activeVaultForRequest(
      chromeApi,
      sendRuntimeCommand,
      requestId,
      session,
      canceledRequests
    );
    if (!activeVaultId) {
      return;
    }

    const excludedCredentialIds = excludedCredentialIdsFromCreateOptions(options);
    for (const credentialId of excludedCredentialIds) {
      if (canceledRequests.has(requestId)) {
        return;
      }

      const status = passkeyCredentialStatusFromResponse(
        await sendRuntimeCommand({
          type: "passkey_credential_status",
          vault_id: activeVaultId,
          credential_id: credentialId
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
    await recordWebAuthnDebug(chromeApi, {
      event: "create_runtime_registration",
      requestId,
      relyingParty,
      origin,
      credentialId: registration.credentialId
    });
    if (canceledRequests.has(requestId)) {
      return;
    }

    const saveResponse = await sendRuntimeCommand({
      type: "save_vault",
      vault_id: activeVaultId
    });
    const saveError = runtimeErrorFromResponse(saveResponse);
    if (saveError) {
      throw saveError;
    }
    await recordWebAuthnDebug(chromeApi, {
      event: "create_saved",
      requestId
    });
    if (canceledRequests.has(requestId)) {
      return;
    }

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

function relyingPartyFromOptions(options: { rpId?: unknown }) {
  if (typeof options.rpId !== "string" || options.rpId.trim() === "") {
    throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn RP ID");
  }
  return options.rpId;
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
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey selection requires an allowed credential"
    );
  }

  const credentials = options.allowCredentials.filter(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      (item as { type?: unknown }).type === "public-key" &&
      typeof (item as { id?: unknown }).id === "string"
  ) as Array<{ id: string }>;
  if (credentials.length === 0) {
    throw new WebAuthnRequestError(
      "NotAllowedError",
      "VaultKern passkey selection requires an allowed credential"
    );
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

async function activeOrigin(chromeApi: ChromeLike, relyingParty?: string) {
  const tabs = await chromeApi.tabs?.query?.({
    active: true,
    lastFocusedWindow: true
  });
  const activeUrl = tabs?.[0]?.url;
  if (activeUrl) {
    return new URL(activeUrl).origin;
  }
  if (typeof relyingParty === "string" && relyingParty.trim() !== "") {
    return `https://${relyingParty.trim()}`;
  }
  throw new WebAuthnRequestError("NotAllowedError", "missing WebAuthn origin");
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
    return initialSession.activeVaultId;
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
      return session.activeVaultId;
    }

    await delay(500);
  }

  throw new WebAuthnRequestError(
    "NotAllowedError",
    "VaultKern vault unlock timed out"
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
  const requestDetailsJson = (request as { requestDetailsJson?: unknown } | null)
    ?.requestDetailsJson;
  if (typeof requestDetailsJson !== "string") {
    return { hasRequestDetailsJson: false };
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
      hasRequestDetailsJson: true,
      parseError: error instanceof Error ? error.message : String(error)
    };
  }
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
