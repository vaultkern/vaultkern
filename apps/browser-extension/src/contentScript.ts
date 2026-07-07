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

  if (hasHiddenAncestor(input)) {
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

  if (hasLayoutBox && rect.right < 0) {
    return false;
  }

  if (hasLayoutBox && rect.left > window.innerWidth) {
    return false;
  }

  if (
    hasLayoutBox &&
    (rect.bottom < 0 || rect.top > window.innerHeight) &&
    hasOffscreenExplicitPosition(style)
  ) {
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

function hasHiddenAncestor(input: HTMLInputElement) {
  let element = input.parentElement;
  while (element) {
    const style = window.getComputedStyle(element);
    if (
      element.hidden ||
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.visibility === "collapse"
    ) {
      return true;
    }
    element = element.parentElement;
  }
  return false;
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
  return (
    (left !== null && left < -2) ||
    (top !== null && (top < -2 || top > window.innerHeight + 2))
  );
}

function fieldTokens(input: HTMLInputElement) {
  return [
    input.autocomplete,
    input.name,
    input.id,
    input.placeholder,
    input.getAttribute("aria-label") ?? "",
    labelTextForInput(input)
  ]
    .join(" ")
    .toLowerCase();
}

function normalizedFieldTokens(input: HTMLInputElement) {
  return fieldTokens(input).replace(/[^a-z0-9]+/g, "");
}

function autocompleteTokens(input: HTMLInputElement) {
  return input.autocomplete.toLowerCase().split(/\s+/).filter(Boolean);
}

function labelTextForInput(input: HTMLInputElement) {
  const labels = Array.from(input.labels ?? []).map((label) => label.textContent ?? "");
  const labelledBy = (input.getAttribute("aria-labelledby") ?? "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => input.ownerDocument.getElementById(id)?.textContent ?? "");

  return [...labels, ...labelledBy].join(" ");
}

type UsernameCandidate = {
  input: HTMLInputElement;
  index: number;
};

type ScoredUsernameCandidate = UsernameCandidate & {
  score: number;
};

type PickUsernameOptions = {
  excludePasswordChangeContext?: boolean;
};

function isRejectedUsernameCandidate(input: HTMLInputElement) {
  if (input.type === "search") {
    return true;
  }

  const autocomplete = input.autocomplete.toLowerCase();
  const autocompleteTokenSet = new Set(autocompleteTokens(input));
  if (autocompleteTokenSet.has("one-time-code")) {
    return true;
  }

  const tokens = fieldTokens(input);
  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  const hasUsernameSignal = hasUsernameFieldSignal(input, autocomplete, tokens, tokenSet);
  if (hasPromotionalFieldSignal(normalizedFieldTokens(input), tokenSet)) {
    return true;
  }
  if (tokens.includes("subscription") && !hasUsernameSignal) {
    return true;
  }
  if (
    [
      "verificationcode",
      "securitycode",
      "authenticationcode",
      "authcode",
      "mfacode",
      "captcha",
      "searchquery",
      "zipcode"
    ].some((token) => tokens.includes(token))
  ) {
    return true;
  }
  if (
    ["search", "otp", "totp", "2fa", "postcode", "zip"].some((token) =>
      tokenSet.has(token)
    )
  ) {
    return true;
  }
  if (
    tokenSet.has("code") &&
    ["verification", "security", "authentication", "authenticator", "auth", "mfa"].some((token) =>
      tokenSet.has(token)
    )
  ) {
    return true;
  }
  return false;
}

function hasPromotionalFieldSignal(normalizedTokens: string, tokenSet: Set<string>) {
  // Reject the promotional verb while leaving subscriber account fields eligible.
  return (
    tokenSet.has("newsletter") ||
    normalizedTokens.includes("newsletter") ||
    tokenSet.has("subscribe") ||
    /subscribe(?!r)/.test(normalizedTokens)
  );
}

function hasUsernameFieldSignal(
  input: HTMLInputElement,
  autocomplete: string,
  tokens: string,
  tokenSet: Set<string>
) {
  return (
    autocomplete === "username" ||
    autocomplete === "email" ||
    input.type === "email" ||
    tokens.includes("username") ||
    tokens.includes("email") ||
    tokens.includes("login") ||
    tokenSet.has("user") ||
    tokenSet.has("account") ||
    tokenSet.has("customer") ||
    tokenSet.has("member") ||
    tokenSet.has("client") ||
    tokenSet.has("identifier")
  );
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

  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  if (
    tokenSet.has("user") ||
    tokenSet.has("account") ||
    tokenSet.has("customer") ||
    tokenSet.has("member") ||
    tokenSet.has("client") ||
    tokenSet.has("identifier")
  ) {
    score += 1;
  }

  if (input.type === "email") {
    score += 1;
  }

  return score;
}

function pickUsernameField(
  passwordField: HTMLInputElement | null,
  options: PickUsernameOptions = {}
) {
  let candidates = Array.from(
    document.querySelectorAll('input[type="text"], input[type="email"]')
  )
    .filter((input): input is HTMLInputElement => input instanceof HTMLInputElement)
    .filter(isWritableVisibleInput)
    .map((input, index) => ({ input, index }));

  if (options.excludePasswordChangeContext) {
    candidates = candidates.filter(
      (candidate) => !isUsernameInsidePasswordChangeContext(candidate.input)
    );
  }

  if (passwordField?.form) {
    const sameFormCandidates = scoreUsernameCandidates(
      candidates.filter((candidate) => candidate.input.form === passwordField.form)
    );

    return (
      sameFormCandidates.find((candidate) => candidate.score > 0)?.input ??
      (sameFormCandidates.length === 1 ? sameFormCandidates[0].input : null)
    );
  }

  if (passwordField) {
    const scopedCandidates = scoreUsernameCandidates(
      scopedFormlessUsernameCandidates(candidates, passwordField)
    );
    return (
      scopedCandidates.find((candidate) => candidate.score > 0)?.input ??
      (scopedCandidates.length === 1 ? scopedCandidates[0].input : null)
    );
  }

  const scoredCandidates = scoreUsernameCandidates(candidates);
  return (
    scoredCandidates.find((candidate) => candidate.score > 0)?.input ??
    (scoredCandidates.length === 1 ? scoredCandidates[0].input : null)
  );
}

function scoreUsernameCandidates(
  candidates: UsernameCandidate[]
): ScoredUsernameCandidate[] {
  return candidates
    .map((candidate) => ({
      ...candidate,
      score: usernameScore(candidate.input)
    }))
    .filter((candidate) => candidate.score >= 0)
    .sort((left, right) => right.score - left.score || left.index - right.index);
}

function scopedFormlessUsernameCandidates(
  candidates: UsernameCandidate[],
  passwordField: HTMLInputElement
): UsernameCandidate[] {
  const container = nearestFormlessCredentialContainer(passwordField);
  if (container) {
    return candidates.filter(
      (candidate) => candidate.input.form === null && container.contains(candidate.input)
    );
  }

  const rootRun = rootLevelCredentialRun(passwordField);
  if (!rootRun.length) {
    return [];
  }

  return candidates.filter((candidate) => rootRun.includes(candidate.input));
}

function nearestFormlessCredentialContainer(input: HTMLInputElement) {
  let container = input.parentElement;

  while (container) {
    const tagName = container.tagName.toLowerCase();
    if (tagName === "body" || tagName === "html" || tagName === "form") {
      return null;
    }

    const usernames = visibleFormlessUsernameInputs(container);
    if (usernames.length > 0) {
      const panelChildren = formLessCredentialPanelChildren(container);
      if (panelChildren.length > 1) {
        if (
          hasOnlyWrappedCredentialFields(panelChildren) &&
          hasCredentialContainerSignal(container)
        ) {
          return container;
        }
        const inputPanel = panelChildren.find((panel) => panel.contains(input));
        if (!inputPanel || visibleFormlessUsernameInputs(inputPanel).length === 0) {
          return null;
        }
        return inputPanel;
      }
      return container;
    }

    container = container.parentElement;
  }

  return null;
}

function visibleFormlessUsernameInputs(container: Element) {
  return Array.from(
    container.querySelectorAll('input[type="text"], input[type="email"]')
  ).filter(
    (candidate): candidate is HTMLInputElement =>
      candidate instanceof HTMLInputElement &&
      candidate.form === null &&
      isWritableVisibleInput(candidate) &&
      usernameScore(candidate) >= 0
  );
}

function rootLevelCredentialRun(input: HTMLInputElement) {
  const runElement = rootLevelRunElement(input);
  if (!rootLevelRunParent(runElement)) {
    return [];
  }

  const fields: HTMLInputElement[] = [input];
  let previous = adjacentRootCredentialElement(runElement.previousElementSibling, "previous");
  let previousField = credentialInputForRunElement(previous);
  while (previousField) {
    fields.unshift(previousField);
    previous = adjacentRootCredentialElement(previous?.previousElementSibling ?? null, "previous");
    previousField = credentialInputForRunElement(previous);
  }

  let next = adjacentRootCredentialElement(runElement.nextElementSibling, "next");
  let nextField = credentialInputForRunElement(next);
  while (nextField) {
    fields.push(nextField);
    next = adjacentRootCredentialElement(next?.nextElementSibling ?? null, "next");
    nextField = credentialInputForRunElement(next);
  }

  return fields.length > 1 ? fields : [];
}

function rootLevelRunElement(input: HTMLInputElement) {
  const parent = input.parentElement;
  if (parent?.tagName.toLowerCase() === "label") {
    return parent;
  }
  if (parent && rootLevelRunParent(parent) && credentialInputForRunElement(parent) === input) {
    return parent;
  }
  return input;
}

function rootLevelRunParent(element: Element) {
  const parent = element.parentElement;
  const parentTag = parent?.tagName.toLowerCase();
  return parentTag === "body" || parentTag === "html" ? parent : null;
}

function adjacentRootCredentialElement(
  candidate: Element | null,
  direction: "next" | "previous"
) {
  let element = candidate;
  while (
    element &&
    (isIgnorableRootRunSeparator(element) ||
      isTextOnlyRootRunLabel(element) ||
      (element.tagName.toLowerCase() === "label" &&
        credentialInputForRunElement(element) === null))
  ) {
    element =
      direction === "next" ? element.nextElementSibling : element.previousElementSibling;
  }
  return element;
}

function isIgnorableRootRunSeparator(element: Element) {
  return ["br", "wbr"].includes(element.tagName.toLowerCase());
}

function isTextOnlyRootRunLabel(element: Element) {
  const tagName = element.tagName.toLowerCase();
  return (
    ["span", "p", "strong", "em", "b", "i"].includes(tagName) &&
    element.children.length === 0 &&
    Boolean(element.textContent?.trim())
  );
}

function credentialInputForRunElement(candidate: Element | null) {
  if (isFormlessCredentialInput(candidate)) {
    return candidate;
  }
  const tagName = candidate?.tagName.toLowerCase();
  if (!tagName || !["article", "div", "fieldset", "label", "section"].includes(tagName)) {
    return null;
  }
  const inputs = Array.from(candidate.querySelectorAll("input")).filter(
    isFormlessCredentialInput
  );
  return inputs.length === 1 ? inputs[0] : null;
}

function isFormlessCredentialInput(candidate: Element | null): candidate is HTMLInputElement {
  return (
    candidate instanceof HTMLInputElement &&
    candidate.form === null &&
    (candidate.type === "text" || candidate.type === "email" || candidate.type === "password") &&
    isWritableVisibleInput(candidate)
  );
}

function isPasswordChangeField(input: HTMLInputElement) {
  const passwords = passwordChangeGroup(input);
  const hasGroupChangeContext = hasPasswordChangeContextSignal(input);

  if (hasNewPasswordSignal(input) && !hasCurrentPasswordSignal(input)) {
    return true;
  }
  if (passwords.length < 2) {
    return hasLocalNewPasswordConfirmationContext(input);
  }

  const hasNewOrConfirmation = passwords.some(
    (candidate) =>
      hasNewPasswordSignal(candidate) ||
      hasConfirmationPasswordSignal(candidate) ||
      hasPasswordVerificationSignal(candidate)
  );
  return (
    hasNewOrConfirmation &&
    (hasGroupChangeContext ||
      passwords.some(
        (candidate) =>
          hasNewPasswordSignal(candidate) ||
          hasCurrentPasswordSignal(candidate) ||
          hasConfirmationPasswordSignal(candidate) ||
          hasPasswordVerificationSignal(candidate) ||
          fieldTokens(candidate).includes("change")
      ))
  );
}

function hasPasswordChangeContextSignal(input: HTMLInputElement) {
  if (input.form && hasPasswordChangeContainerSignal(input.form)) {
    return true;
  }

  if (input.form) {
    return false;
  }

  const container = nearestFormlessPasswordContainer(input);
  return Boolean(container && hasPasswordChangeContainerSignal(container));
}

function passwordChangeGroup(input: HTMLInputElement) {
  const form = input.form;
  if (form) {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(
      (candidate): candidate is HTMLInputElement =>
        candidate instanceof HTMLInputElement &&
        candidate.form === form &&
        isWritableVisibleInput(candidate)
    );
  }

  const container = nearestFormlessPasswordContainer(input);
  if (container) {
    return Array.from(container.querySelectorAll('input[type="password"]')).filter(
      isVisibleFormlessPassword
    );
  }

  return rootLevelPasswordRun(input);
}

function isVisibleFormlessPassword(candidate: Element): candidate is HTMLInputElement {
  return (
    candidate instanceof HTMLInputElement &&
    candidate.form === null &&
    candidate.type === "password" &&
    isWritableVisibleInput(candidate)
  );
}

function nearestFormlessPasswordContainer(input: HTMLInputElement) {
  let container = input.parentElement;

  while (container) {
    const tagName = container.tagName.toLowerCase();
    if (tagName === "body" || tagName === "html" || tagName === "form") {
      return null;
    }

    const passwords = Array.from(container.querySelectorAll('input[type="password"]')).filter(
      isVisibleFormlessPassword
    );
    if (passwords.length > 1) {
      const panelChildren = formLessCredentialPanelChildren(container);
      if (panelChildren.length > 1) {
        if (hasOnlyWrappedPasswordFields(panelChildren, container)) {
          return container;
        }
        const inputPanel = panelChildren.find((panel) => panel.contains(input));
        if (!inputPanel || visibleFormlessPasswords(inputPanel).length < 2) {
          return null;
        }
        return inputPanel;
      }
      return container;
    }

    container = container.parentElement;
  }

  return null;
}

function formLessCredentialPanelChildren(container: Element) {
  return Array.from(container.children).filter((child) => {
    const tagName = child.tagName.toLowerCase();
    return (
      ["article", "aside", "div", "fieldset", "main", "section"].includes(tagName) &&
      (visibleFormlessPasswords(child).length > 0 || visibleFormlessUsernameInputs(child).length > 0)
    );
  });
}

function hasCredentialContainerSignal(container: Element) {
  return hasContainerSignal(container, ["login", "signin", "signon", "auth", "credential"]);
}

function hasPasswordChangeContainerSignal(container: Element) {
  return hasContainerSignal(container, [
    "login",
    "signin",
    "signon",
    "auth",
    "credential",
    "change",
    "reset"
  ]);
}

function hasPasswordResetContainerSignal(container: Element) {
  return hasContainerSignal(container, ["change", "reset"]);
}

function hasContainerSignal(container: Element, signals: string[]) {
  const normalized = [
    container.id,
    container.getAttribute("class") ?? "",
    container.getAttribute("aria-label") ?? "",
    container.getAttribute("role") ?? ""
  ]
    .join(" ")
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
  return signals.some((token) => normalized.includes(token));
}

function visibleFormlessPasswords(container: Element) {
  return Array.from(container.querySelectorAll('input[type="password"]')).filter(
    isVisibleFormlessPassword
  );
}

function hasOnlyWrappedCredentialFields(panelChildren: Element[]) {
  const counts = panelChildren.map(credentialFieldCount);
  return (
    counts.every((count) => count === 1) &&
    panelChildren.some((child) => visibleFormlessUsernameInputs(child).length === 1) &&
    panelChildren.some((child) => visibleFormlessPasswords(child).length === 1)
  );
}

function hasOnlyWrappedPasswordFields(panelChildren: Element[], container: Element) {
  const passwordChildren = panelChildren.filter(
    (child) => visibleFormlessPasswords(child).length > 0
  );
  const passwords = passwordChildren.flatMap((child) => visibleFormlessPasswords(child));
  return (
    hasPasswordChangeContainerSignal(container) &&
    passwordChildren.length > 1 &&
    passwordChildren.every((child) => visibleFormlessPasswords(child).length === 1) &&
    passwords.some(hasNewPasswordSignal) &&
    (passwords.some(hasCurrentPasswordSignal) ||
      passwords.some(hasConfirmationPasswordSignal) ||
      passwords.some(hasPasswordVerificationSignal))
  );
}

function hasLocalNewPasswordConfirmationContext(input: HTMLInputElement) {
  if (!hasConfirmationPasswordSignal(input) && !hasPasswordVerificationSignal(input)) {
    return false;
  }

  let container = input.parentElement;
  while (container) {
    const tagName = container.tagName.toLowerCase();
    if (tagName === "body" || tagName === "html" || tagName === "form") {
      return false;
    }

    const panelChildren = formLessCredentialPanelChildren(container);
    const inputPanel = panelChildren.find((panel) => panel.contains(input));
    const passwordChildren = panelChildren.filter(
      (child) => visibleFormlessPasswords(child).length > 0
    );
    if (
      inputPanel &&
      passwordChildren.length > 1 &&
      passwordChildren.every((child) => visibleFormlessPasswords(child).length === 1)
    ) {
      const passwords = passwordChildren.flatMap((child) => visibleFormlessPasswords(child));
      return (
        passwords.includes(input) &&
        passwords.some((password) => password !== input && hasNewPasswordSignal(password)) &&
        !passwords.some(hasCurrentPasswordSignal)
      );
    }

    container = container.parentElement;
  }

  return false;
}

function hasCurrentPasswordSignal(input: HTMLInputElement) {
  const tokens = fieldTokens(input);
  const normalizedTokens = normalizedFieldTokens(input);
  const autocompleteTokenSet = new Set(autocompleteTokens(input));
  return (
    autocompleteTokenSet.has("current-password") ||
    normalizedTokens.includes("currentpassword") ||
    normalizedTokens.includes("oldpassword") ||
    normalizedTokens.includes("existingpassword") ||
    tokens.includes("current") ||
    tokens.includes("old")
  );
}

function hasNewPasswordSignal(input: HTMLInputElement) {
  const tokens = fieldTokens(input);
  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  const normalizedTokens = normalizedFieldTokens(input);
  const autocompleteTokenSet = new Set(autocompleteTokens(input));
  return (
    autocompleteTokenSet.has("new-password") ||
    normalizedTokens.includes("newpassword") ||
    tokens.includes("new password") ||
    (tokenSet.has("password") &&
      (tokenSet.has("new") ||
        tokenSet.has("create") ||
        tokenSet.has("set") ||
        tokenSet.has("choose")))
  );
}

function hasConfirmationPasswordSignal(input: HTMLInputElement) {
  const tokens = fieldTokens(input);
  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  const normalizedTokens = normalizedFieldTokens(input);
  return (
    normalizedTokens.includes("confirmpassword") ||
    normalizedTokens.includes("passwordconfirmation") ||
    normalizedTokens.includes("repeatpassword") ||
    normalizedTokens.includes("reenterpassword") ||
    tokens.includes("confirm password") ||
    tokens.includes("password confirmation") ||
    tokens.includes("repeat password") ||
    (tokenSet.has("password") &&
      (tokenSet.has("confirm") ||
        tokenSet.has("confirmation") ||
        tokenSet.has("repeat") ||
        tokenSet.has("reenter") ||
        (tokenSet.has("re") && tokenSet.has("enter"))))
  );
}

function hasPasswordVerificationSignal(input: HTMLInputElement) {
  const tokens = fieldTokens(input);
  const tokenSet = new Set(tokens.split(/[^a-z0-9]+/).filter(Boolean));
  const normalizedTokens = normalizedFieldTokens(input);
  return (
    normalizedTokens.includes("verifypassword") ||
    tokens.includes("verify password") ||
    (tokenSet.has("password") && tokenSet.has("verify"))
  );
}

function credentialFieldCount(container: Element) {
  return (
    visibleFormlessUsernameInputs(container).length + visibleFormlessPasswords(container).length
  );
}

function rootLevelPasswordRun(input: HTMLInputElement) {
  const runElement = rootLevelRunElement(input);
  if (!rootLevelRunParent(runElement)) {
    return [];
  }

  const passwords: HTMLInputElement[] = [input];
  let previous = adjacentRootPasswordElement(runElement.previousElementSibling, "previous");
  while (previous) {
    passwords.unshift(previous);
    previous = adjacentRootPasswordElement(
      rootLevelRunElement(previous).previousElementSibling,
      "previous"
    );
  }

  let next = adjacentRootPasswordElement(runElement.nextElementSibling, "next");
  while (next) {
    passwords.push(next);
    next = adjacentRootPasswordElement(rootLevelRunElement(next).nextElementSibling, "next");
  }

  return passwords.length > 1 ? passwords : [];
}

function adjacentRootPasswordElement(
  candidate: Element | null,
  direction: "next" | "previous"
) {
  let element = candidate;
  while (
    element &&
    (isIgnorableRootRunSeparator(element) ||
      isTextOnlyRootRunLabel(element) ||
      (element.tagName.toLowerCase() === "label" &&
        passwordInputForRunElement(element) === null))
  ) {
    element =
      direction === "next" ? element.nextElementSibling : element.previousElementSibling;
  }
  return passwordInputForRunElement(element);
}

function passwordInputForRunElement(candidate: Element | null) {
  if (isVisibleFormlessPassword(candidate)) {
    return candidate;
  }
  const tagName = candidate?.tagName.toLowerCase();
  if (!tagName || !["article", "div", "fieldset", "label", "section"].includes(tagName)) {
    return null;
  }
  const inputs = Array.from(candidate.querySelectorAll('input[type="password"]')).filter(
    isVisibleFormlessPassword
  );
  return inputs.length === 1 ? inputs[0] : null;
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

function hasPasswordChangeContext() {
  return Array.from(document.querySelectorAll('input[type="password"]'))
    .filter((input): input is HTMLInputElement => input instanceof HTMLInputElement)
    .filter(isWritableVisibleInput)
    .some(isPasswordChangeField);
}

function isUsernameInsidePasswordChangeContext(input: HTMLInputElement) {
  if (input.form) {
    return Array.from(document.querySelectorAll('input[type="password"]')).some(
      (candidate): candidate is HTMLInputElement =>
        candidate instanceof HTMLInputElement &&
        candidate.form === input.form &&
        isWritableVisibleInput(candidate) &&
        isPasswordChangeField(candidate)
    );
  }

  const credentialContainer = nearestFormlessCredentialContainer(input);
  if (credentialContainer && hasFormlessPasswordChangeField(credentialContainer)) {
    return true;
  }

  if (
    rootLevelCredentialRun(input).some(
      (candidate) => candidate.type === "password" && isPasswordChangeField(candidate)
    )
  ) {
    return true;
  }

  let ancestor = input.parentElement;
  while (ancestor) {
    const tagName = ancestor.tagName.toLowerCase();
    if (tagName === "body" || tagName === "html" || tagName === "form") {
      return false;
    }
    if (usesAncestorPasswordChangeContextForUsername(ancestor)) {
      if (hasFormlessPasswordChangeField(ancestor)) {
        return true;
      }
    }
    ancestor = ancestor.parentElement;
  }
  return false;
}

function usesAncestorPasswordChangeContextForUsername(ancestor: Element) {
  if (hasPasswordResetContainerSignal(ancestor)) {
    return true;
  }

  const panelChildren = formLessCredentialPanelChildren(ancestor);
  return (
    panelChildren.length > 1 &&
    hasCredentialContainerSignal(ancestor) &&
    hasOnlyWrappedCredentialFields(panelChildren)
  );
}

function hasFormlessPasswordChangeField(container: Element) {
  return Array.from(container.querySelectorAll('input[type="password"]')).some(
    (candidate): candidate is HTMLInputElement =>
      candidate instanceof HTMLInputElement &&
      candidate.form === null &&
      isWritableVisibleInput(candidate) &&
      isPasswordChangeField(candidate)
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
  const shouldFillPassword = typeof payload.password === "string";
  const password = shouldFillPassword ? pickPasswordField() : null;
  const passwordChangeContext =
    shouldFillPassword && password === null && hasPasswordChangeContext();
  const username = pickUsernameField(password, {
    excludePasswordChangeContext: passwordChangeContext
  });

  if (typeof payload.username === "string" && username) {
    writeFieldValue(username, payload.username);
  }

  if (shouldFillPassword && password) {
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
