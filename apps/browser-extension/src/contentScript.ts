function isWritableVisibleInput(input: HTMLInputElement) {
  if (input.disabled || input.readOnly || input.hidden) {
    return false;
  }

  if (input.type === "hidden") {
    return false;
  }

  if (input.style.display === "none" || input.style.visibility === "hidden") {
    return false;
  }

  return true;
}

function usernameScore(input: HTMLInputElement) {
  const autocomplete = input.autocomplete.toLowerCase();
  const name = input.name.toLowerCase();
  const id = input.id.toLowerCase();
  let score = 0;

  if (autocomplete === "username" || autocomplete === "email") {
    score += 4;
  }

  if (
    name.includes("username") ||
    name.includes("email") ||
    name.includes("login") ||
    id.includes("username") ||
    id.includes("email") ||
    id.includes("login")
  ) {
    score += 2;
  }

  if (input.type === "email") {
    score += 1;
  }

  return score;
}

function pickUsernameField() {
  const candidates = Array.from(
    document.querySelectorAll('input[type="text"], input[type="email"]')
  ).filter((input): input is HTMLInputElement => input instanceof HTMLInputElement);

  return candidates
    .filter(isWritableVisibleInput)
    .map((input, index) => ({ input, score: usernameScore(input), index }))
    .sort((left, right) => right.score - left.score || left.index - right.index)[0]
    ?.input;
}

function pickPasswordField() {
  const candidates = Array.from(document.querySelectorAll('input[type="password"]')).filter(
    (input): input is HTMLInputElement => input instanceof HTMLInputElement
  );

  return candidates.filter(isWritableVisibleInput)[0] ?? null;
}

function writeFieldValue(input: HTMLInputElement, value: string) {
  input.value = value;

  for (const eventName of ["input", "change", "blur"]) {
    input.dispatchEvent(new Event(eventName, { bubbles: true }));
  }
}

export function fillLoginForm(payload: {
  username?: string;
  password?: string;
}) {
  const username = pickUsernameField();
  const password = pickPasswordField();

  if (typeof payload.username === "string" && username) {
    writeFieldValue(username, payload.username);
  }

  if (typeof payload.password === "string" && password) {
    writeFieldValue(password, payload.password);
  }
}

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const WEB_AUTHN_PAGE_REQUEST_MESSAGE = "vaultkern_webauthn_page_request";

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: { type?: string; username?: string; password?: string },
      _sender: unknown,
      _sendResponse: (response?: unknown) => void
    ) => {
      if (message.type !== "fill_entry_detail") {
        return false;
      }

      const hasUsername = typeof message.username === "string";
      const hasPassword = typeof message.password === "string";

      if (!hasUsername && !hasPassword) {
        return false;
      }

      fillLoginForm({
        username: hasUsername ? message.username : undefined,
        password: hasPassword ? message.password : undefined
      });

      return false;
    }
  );
}

if (chromeApi?.runtime?.sendMessage) {
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
      relyingParty: event.data.relyingParty,
      challenge: event.data.challenge,
      allowCredentialIds: event.data.allowCredentialIds,
      excludeCredentialIds: event.data.excludeCredentialIds,
      observedAt: Date.now()
    });
    if (sendResult && typeof sendResult.catch === "function") {
      sendResult.catch(() => undefined);
    }
  });
}

function isWebAuthnPageRequest(message: unknown): message is {
  type: string;
  ceremony: "create" | "get";
  relyingParty?: string;
  challenge?: string;
  allowCredentialIds?: string[];
  excludeCredentialIds?: string[];
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
