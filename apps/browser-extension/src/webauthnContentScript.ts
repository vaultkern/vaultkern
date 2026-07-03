const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const WEB_AUTHN_PAGE_REQUEST_MESSAGE = "vaultkern_webauthn_page_request";
const globalState = globalThis as typeof globalThis & {
  __vaultkernWebAuthnContentScriptInstalled?: boolean;
};

if (!globalState.__vaultkernWebAuthnContentScriptInstalled && chromeApi?.runtime?.sendMessage) {
  globalState.__vaultkernWebAuthnContentScriptInstalled = true;
  window.addEventListener("message", (event) => {
    const frameOrigin = originFromFrame(event);
    const ancestorOrigins = ancestorOriginsFromWindow();
    if (
      !frameOrigin ||
      !ancestorOrigins ||
      event.source !== window ||
      event.origin !== frameOrigin ||
      !isWebAuthnPageRequest(event.data)
    ) {
      return;
    }

    const sendResult = chromeApi.runtime.sendMessage({
      type: WEB_AUTHN_PAGE_REQUEST_MESSAGE,
      ceremony: event.data.ceremony,
      origin: frameOrigin,
      topOrigin: topOriginFromAncestorOrigins(ancestorOrigins),
      ancestorOrigins,
      relyingParty: optionalStringFrom(event.data.relyingParty),
      challenge: optionalStringFrom(event.data.challenge),
      allowCredentialIds: stringArrayFrom(event.data.allowCredentialIds),
      excludeCredentialIds: stringArrayFrom(event.data.excludeCredentialIds),
      mediation: optionalStringFrom(event.data.mediation),
      observedAt: Date.now()
    });
    if (sendResult && typeof sendResult.catch === "function") {
      sendResult.catch(() => undefined);
    }
  });
}

function originFromFrame(event?: MessageEvent) {
  const globalOrigin = (globalThis as typeof globalThis & { origin?: unknown }).origin;
  if (typeof globalOrigin === "string") {
    const origin = strictOriginFromString(globalOrigin);
    if (origin) {
      return origin;
    }
  }

  const windowOrigin = strictOriginFromString(window.location.origin);
  if (windowOrigin) {
    return windowOrigin;
  }

  if (event) {
    const eventOrigin = strictOriginFromString(event.origin);
    if (eventOrigin) {
      return eventOrigin;
    }
  }

  return null;
}

function strictOriginFromString(value: string) {
  if (value.trim() === "" || value !== value.trim() || value === "null") {
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

function ancestorOriginsFromWindow() {
  const ancestorOrigins = window.location.ancestorOrigins;
  if (!ancestorOrigins || typeof ancestorOrigins.length !== "number") {
    return [];
  }

  const origins: string[] = [];
  for (const value of Array.from(ancestorOrigins as ArrayLike<unknown>)) {
    if (typeof value !== "string") {
      return null;
    }
    const origin = strictOriginFromString(value);
    if (!origin) {
      return null;
    }
    origins.push(origin);
  }
  return origins;
}

function topOriginFromAncestorOrigins(ancestorOrigins: string[]) {
  const topOrigin = ancestorOrigins[ancestorOrigins.length - 1];
  return typeof topOrigin === "string" ? topOrigin : undefined;
}

function optionalStringFrom(value: unknown) {
  return typeof value === "string" ? value : undefined;
}

function stringArrayFrom(value: unknown) {
  if (!Array.isArray(value)) {
    return undefined;
  }
  return value.filter((item): item is string => typeof item === "string");
}

function isWebAuthnPageRequest(message: unknown): message is {
  type: string;
  ceremony: "create" | "get";
  relyingParty?: string;
  challenge?: string;
  allowCredentialIds?: string[];
  excludeCredentialIds?: string[];
  mediation?: string;
} {
  if (
    typeof message !== "object" ||
    message === null ||
    (message as { type?: unknown }).type !== WEB_AUTHN_PAGE_REQUEST_MESSAGE
  ) {
    return false;
  }

  const ceremony = (message as { ceremony?: unknown }).ceremony;
  return ceremony === "create" || ceremony === "get";
}

export {};
