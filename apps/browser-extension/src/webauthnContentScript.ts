const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const WEB_AUTHN_PAGE_REQUEST_MESSAGE = "vaultkern_webauthn_page_request";
const globalState = globalThis as typeof globalThis & {
  __vaultkernWebAuthnContentScriptInstalled?: boolean;
};

if (!globalState.__vaultkernWebAuthnContentScriptInstalled && chromeApi?.runtime?.sendMessage) {
  globalState.__vaultkernWebAuthnContentScriptInstalled = true;
  window.addEventListener("message", (event) => {
    if (
      event.origin !== window.location.origin ||
      !isWebAuthnPageRequest(event.data)
    ) {
      return;
    }

    const sendResult = chromeApi.runtime.sendMessage({
      type: WEB_AUTHN_PAGE_REQUEST_MESSAGE,
      ceremony: event.data.ceremony,
      origin: window.location.origin,
      topOrigin: topOriginFromWindow(),
      relyingParty: event.data.relyingParty,
      challenge: event.data.challenge,
      allowCredentialIds: event.data.allowCredentialIds,
      excludeCredentialIds: event.data.excludeCredentialIds,
      mediation: event.data.mediation,
      observedAt: Date.now()
    });
    if (sendResult && typeof sendResult.catch === "function") {
      sendResult.catch(() => undefined);
    }
  });
}

function topOriginFromWindow() {
  const ancestorOrigins = window.location.ancestorOrigins;
  const topOrigin = ancestorOrigins?.[ancestorOrigins.length - 1];
  if (typeof topOrigin === "string" && topOrigin.trim() !== "") {
    return topOrigin;
  }

  return window.location.origin;
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
