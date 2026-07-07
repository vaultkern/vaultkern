function isWritableVisibleInput(input: HTMLInputElement) {
  if (input.disabled || input.readOnly || input.hidden) {
    return false;
  }

  if (input.type === "hidden") {
    return false;
  }

  const style = window.getComputedStyle(input);
  if (
    style.display === "none" ||
    style.visibility === "hidden" ||
    style.visibility === "collapse"
  ) {
    return false;
  }

  if (hasTinyExplicitSize(style)) {
    return false;
  }

  const hasLayoutBox = input.getClientRects().length > 0;
  const rect = input.getBoundingClientRect();
  if (hasLayoutBox && (rect.width < 2 || rect.height < 2)) {
    return false;
  }

  if (hasLayoutBox && (rect.right < 0 || rect.bottom < 0)) {
    return false;
  }

  if (!hasLayoutBox && hasOffscreenExplicitPosition(style)) {
    return false;
  }

  return true;
}

function cssPixelValue(value: string) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function hasTinyExplicitSize(style: CSSStyleDeclaration) {
  const width = cssPixelValue(style.width);
  const height = cssPixelValue(style.height);

  return (
    (width !== null && width < 2) ||
    (height !== null && height < 2) ||
    style.maxWidth === "0px" ||
    style.maxHeight === "0px"
  );
}

function hasOffscreenExplicitPosition(style: CSSStyleDeclaration) {
  if (style.position !== "absolute" && style.position !== "fixed") {
    return false;
  }

  const left = cssPixelValue(style.left);
  const top = cssPixelValue(style.top);
  return (left !== null && left < -2) || (top !== null && top < -2);
}

function fieldTokens(input: HTMLInputElement) {
  return [
    input.autocomplete,
    input.name,
    input.id,
    input.placeholder,
    input.getAttribute("aria-label") ?? ""
  ]
    .join(" ")
    .toLowerCase();
}

function isRejectedUsernameCandidate(input: HTMLInputElement) {
  if (input.type === "search") {
    return true;
  }

  const autocomplete = input.autocomplete.toLowerCase();
  if (autocomplete === "one-time-code") {
    return true;
  }

  const tokens = fieldTokens(input);
  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  if (
    ["search", "otp", "totp", "2fa", "postcode", "zip"].some((token) =>
      tokenSet.has(token)
    )
  ) {
    return true;
  }
  return tokenSet.has("code") && autocomplete !== "username" && autocomplete !== "email";
}

function usernameScore(input: HTMLInputElement) {
  if (isRejectedUsernameCandidate(input)) {
    return -1;
  }

  const autocomplete = input.autocomplete.toLowerCase();
  const tokens = fieldTokens(input);
  let score = 0;

  if (autocomplete === "username" || autocomplete === "email") {
    score += 4;
  }

  if (
    tokens.includes("username") ||
    tokens.includes("email") ||
    tokens.includes("login")
  ) {
    score += 2;
  }

  if (input.type === "email") {
    score += 1;
  }

  return score;
}

function pickUsernameField(passwordField: HTMLInputElement | null) {
  const candidates = Array.from(
    document.querySelectorAll('input[type="text"], input[type="email"]')
  ).filter((input): input is HTMLInputElement => input instanceof HTMLInputElement);

  const scoredCandidates = candidates
    .filter(isWritableVisibleInput)
    .map((input, index) => ({ input, score: usernameScore(input), index }))
    .filter((candidate) => candidate.score >= 0)
    .sort((left, right) => right.score - left.score || left.index - right.index);

  if (passwordField?.form) {
    return (
      scoredCandidates.find((candidate) => candidate.input.form === passwordField.form)
        ?.input ??
      scoredCandidates.find((candidate) => candidate.input.form === null && candidate.score > 0)
        ?.input
    );
  }

  return (
    scoredCandidates.find((candidate) => candidate.score > 0)?.input ??
    scoredCandidates[0]?.input
  );
}

function isPasswordChangeField(input: HTMLInputElement) {
  const form = input.form;
  if (!form) {
    return false;
  }

  const passwords = Array.from(form.querySelectorAll('input[type="password"]')).filter(
    (candidate): candidate is HTMLInputElement =>
      candidate instanceof HTMLInputElement && isWritableVisibleInput(candidate)
  );

  if (passwords.length < 2) {
    return false;
  }

  return passwords.some((candidate) => {
    const tokens = fieldTokens(candidate);
    return ["old", "new", "repeat", "confirm", "change"].some(
      (fragment) => tokens.includes(fragment)
    );
  });
}

function pickPasswordField() {
  const candidates = Array.from(document.querySelectorAll('input[type="password"]')).filter(
    (input): input is HTMLInputElement => input instanceof HTMLInputElement
  );

  return (
    candidates
      .filter(isWritableVisibleInput)
      .filter((input) => !isPasswordChangeField(input))[0] ?? null
  );
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
  const password = pickPasswordField();
  const username = pickUsernameField(password);

  if (typeof payload.username === "string" && username) {
    writeFieldValue(username, payload.username);
  }

  if (typeof payload.password === "string" && password) {
    writeFieldValue(password, payload.password);
  }
}

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;

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
