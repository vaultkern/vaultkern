const WEB_AUTHN_PAGE_REQUEST_MESSAGE = "vaultkern_webauthn_page_request";
const HOOK_ENABLED_MARKER = "__vaultkernWebAuthnPageHookEnabled";
const HOOK_MARKER = "__vaultkernWebAuthnHookInstalled";

type PublicKeyCredentialOptionsLike = {
  challenge?: unknown;
  rpId?: unknown;
  rp?: { id?: unknown };
  allowCredentials?: unknown;
  excludeCredentials?: unknown;
};

type CredentialsContainerWithMarker = CredentialsContainer & {
  [HOOK_MARKER]?: boolean;
};

installWebAuthnPageHook();

function installWebAuthnPageHook() {
  const hookState = globalThis as typeof globalThis & {
    [HOOK_ENABLED_MARKER]?: boolean;
  };
  hookState[HOOK_ENABLED_MARKER] = true;

  const credentials = navigator.credentials as CredentialsContainerWithMarker | undefined;
  if (!credentials || credentials[HOOK_MARKER]) {
    return;
  }

  const originalCreate = credentials.create?.bind(credentials);
  const originalGet = credentials.get?.bind(credentials);

  if (typeof originalCreate === "function") {
    credentials.create = ((options?: CredentialCreationOptions) => {
      observeWebAuthnRequest("create", options);
      return originalCreate(options);
    }) as CredentialsContainer["create"];
  }

  if (typeof originalGet === "function") {
    credentials.get = ((options?: CredentialRequestOptions) => {
      observeWebAuthnRequest("get", options);
      return originalGet(options);
    }) as CredentialsContainer["get"];
  }

  credentials[HOOK_MARKER] = true;
}

function observeWebAuthnRequest(
  ceremony: "create" | "get",
  options?: CredentialCreationOptions | CredentialRequestOptions
) {
  const hookState = globalThis as typeof globalThis & {
    [HOOK_ENABLED_MARKER]?: boolean;
  };
  if (hookState[HOOK_ENABLED_MARKER] === false) {
    return;
  }

  const publicKey = (options as { publicKey?: PublicKeyCredentialOptionsLike } | undefined)
    ?.publicKey;
  if (!publicKey || typeof publicKey !== "object") {
    return;
  }

  window.postMessage(
    {
      type: WEB_AUTHN_PAGE_REQUEST_MESSAGE,
      ceremony,
      relyingParty: relyingPartyFromOptions(publicKey),
      challenge: base64urlFrom(publicKey.challenge),
      allowCredentialIds: credentialIdsFrom(publicKey.allowCredentials),
      excludeCredentialIds: credentialIdsFrom(publicKey.excludeCredentials)
    },
    window.location.origin
  );
}

function relyingPartyFromOptions(options: PublicKeyCredentialOptionsLike) {
  const relyingParty =
    typeof options.rpId === "string"
      ? options.rpId
      : typeof options.rp?.id === "string"
        ? options.rp.id
        : window.location.hostname;
  return relyingParty.trim() === "" ? undefined : relyingParty;
}

function credentialIdsFrom(credentials: unknown) {
  if (!Array.isArray(credentials)) {
    return undefined;
  }

  return credentials
    .map((credential) =>
      typeof credential === "object" && credential !== null
        ? base64urlFrom((credential as { id?: unknown }).id)
        : null
    )
    .filter((id): id is string => typeof id === "string");
}

function base64urlFrom(value: unknown) {
  const bytes = bytesFrom(value);
  if (!bytes) {
    return undefined;
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function bytesFrom(value: unknown) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }

  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }

  return null;
}
