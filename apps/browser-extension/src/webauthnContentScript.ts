(() => {
  const WEB_AUTHN_PAGE_REQUEST_MESSAGE = "vaultkern_webauthn_page_request";
  const WEB_AUTHN_PAGE_REQUEST_EVENT = "vaultkern_webauthn_page_request_event";
  const MAX_FORWARDED_BRIDGE_REQUEST_IDS = 128;
  const globalState = globalThis as typeof globalThis & {
    __vaultkernWebAuthnContentScriptInstalled?: boolean;
    __vaultkernWebAuthnContentScriptInstallId?: number;
  };
  const forwardedBridgeRequestIds = new Set<string>();
  const forwardedBridgeRequestIdQueue: string[] = [];

if (!globalState.__vaultkernWebAuthnContentScriptInstalled) {
  globalState.__vaultkernWebAuthnContentScriptInstalled = true;
  const installId = (globalState.__vaultkernWebAuthnContentScriptInstallId ?? 0) + 1;
  globalState.__vaultkernWebAuthnContentScriptInstallId = installId;
  window.addEventListener(WEB_AUTHN_PAGE_REQUEST_EVENT, (event) => {
    if (globalState.__vaultkernWebAuthnContentScriptInstallId !== installId) {
      return;
    }
    const detail = (event as CustomEvent).detail;
    forwardWebAuthnPageRequest(detail);
  });
  window.addEventListener("message", (event) => {
    if (globalState.__vaultkernWebAuthnContentScriptInstallId !== installId) {
      return;
    }
    if (
      event.source !== window ||
      !isWebAuthnPageRequest(event.data)
    ) {
      return;
    }

    forwardWebAuthnPageRequest(event.data, event);
  });
}

function forwardWebAuthnPageRequest(data: unknown, event?: MessageEvent) {
  const frameOrigin = originFromFrame(event);
  const ancestorOrigins = ancestorOriginsFromWindow();
  if (
    !frameOrigin ||
    !ancestorOrigins ||
    (event && event.origin !== frameOrigin) ||
    !isWebAuthnPageRequest(data)
  ) {
    return;
  }

  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  if (!chromeApi?.runtime?.sendMessage) {
    return;
  }
  if (isDuplicateBridgeRequest(data)) {
    return;
  }
  const sendResult = chromeApi.runtime.sendMessage({
    type: WEB_AUTHN_PAGE_REQUEST_MESSAGE,
    ceremony: data.ceremony,
    origin: frameOrigin,
    topOrigin: topOriginFromAncestorOrigins(ancestorOrigins),
    ancestorOrigins,
    relyingParty: optionalStringFrom(data.relyingParty),
    challenge: optionalStringFrom(data.challenge),
    allowCredentialIds: stringArrayFrom(data.allowCredentialIds),
    excludeCredentialIds: stringArrayFrom(data.excludeCredentialIds),
    mediation: optionalStringFrom(data.mediation),
    observedAt: Date.now()
  });
  if (sendResult && typeof sendResult.catch === "function") {
    sendResult.catch(() => undefined);
  }
}

function isDuplicateBridgeRequest(data: unknown) {
  const bridgeRequestId = bridgeRequestIdFrom(data);
  if (!bridgeRequestId) {
    return false;
  }
  if (forwardedBridgeRequestIds.has(bridgeRequestId)) {
    return true;
  }
  forwardedBridgeRequestIds.add(bridgeRequestId);
  forwardedBridgeRequestIdQueue.push(bridgeRequestId);
  while (forwardedBridgeRequestIdQueue.length > MAX_FORWARDED_BRIDGE_REQUEST_IDS) {
    const expired = forwardedBridgeRequestIdQueue.shift();
    if (expired) {
      forwardedBridgeRequestIds.delete(expired);
    }
  }
  return false;
}

function bridgeRequestIdFrom(data: unknown) {
  if (!data || typeof data !== "object") {
    return null;
  }
  const value = (data as { bridgeRequestId?: unknown }).bridgeRequestId;
  if (typeof value !== "string" || value.trim() === "" || value.length > 128) {
    return null;
  }
  return value;
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
})();

export {};
