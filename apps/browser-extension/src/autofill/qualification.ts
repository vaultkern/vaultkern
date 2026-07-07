import type {
  AutofillFieldQualification,
  AutofillFieldSnapshot,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";

const USERNAME_AUTOCOMPLETE = new Set(["username"]);
const EMAIL_AUTOCOMPLETE = new Set(["email"]);
const PASSWORD_AUTOCOMPLETE = new Set(["current-password"]);
const USERNAME_INPUT_TYPES = new Set(["email", "number", "tel", "text", "url"]);
const NON_LOGIN_KEYWORDS = ["newsletter", "subscribe", "subscription", "unsubscribe", "mailinglist"];
const ACCOUNT_CREATION_EXACT_PARTS = new Set([
  "register",
  "registration",
  "signup",
  "createaccount",
  "createnewaccount",
  "createyouraccount",
  "createanaccount",
  "createpassword",
  "newpassword",
  "confirmpassword"
]);
const NEW_PASSWORD_PARTS = [
  "createpassword",
  "newpassword",
  "confirmpassword",
  "passwordconfirmation",
  "passwordconfirm",
  "passwordagain",
  "password2",
  "repeatpassword",
  "verifypassword"
];
const PASSWORD_CONFIRMATION_EXACT_PARTS = new Set(["confirm", "confirmation"]);
const PASSWORD_MASKED_CODE_PARTS = [
  "csc",
  "cccsc",
  "cvc",
  "cvv",
  "cardcsc",
  "cardcvc",
  "cardcvv",
  "cardcode",
  "otp",
  "totp",
  "onetime",
  "onetimecode",
  "onetimepassword",
  "securitycode",
  "verificationcode",
  "authenticationcode",
  "authenticatorcode",
  "mfacode",
  "2facode",
  "2stepcode",
  "2factorcode"
];
const AUTH_QUERY_CONTEXT_KEYS = new Set([
  "action",
  "auth",
  "context",
  "flow",
  "form",
  "intent",
  "mode",
  "page",
  "screen",
  "step",
  "tab",
  "type",
  "view"
]);

export interface FieldQualification {
  qualifiedAs: AutofillFieldQualification;
  eligible: boolean;
  reasons: string[];
}

function normalize(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_/-]+/g, "");
}

function hasAuthFlowContext(value: string | undefined) {
  const normalized = normalize(value);
  return (
    hasLoginContext(normalized) ||
    hasAccountCreationContext(normalized) ||
    excludedReason("", normalized) !== null
  );
}

function isQueryFlagValue(value: string) {
  const normalized = normalize(value);
  return normalized === "" || normalized === "1" || normalized === "true";
}

function authQueryContext(url: URL) {
  const terms: string[] = [];
  url.searchParams.forEach((value, key) => {
    const normalizedKey = normalize(key);
    const keyNamesAuthFlow = hasAuthFlowContext(key) && isQueryFlagValue(value);
    const keyDescribesAuthMode =
      AUTH_QUERY_CONTEXT_KEYS.has(normalizedKey) ||
      normalizedKey.endsWith("mode") ||
      normalizedKey.endsWith("action") ||
      normalizedKey.endsWith("flow") ||
      normalizedKey.endsWith("type") ||
      normalizedKey.endsWith("view");

    if (keyNamesAuthFlow) {
      terms.push(key);
      return;
    }

    if (keyDescribesAuthMode && hasAuthFlowContext(value)) {
      terms.push(`${key}=${value}`);
    }
  });
  return terms;
}

function splitUrlPart(value: string | undefined) {
  return (value ?? "").split(/[^a-z0-9]+/i).filter(Boolean);
}

function formActionContext(value: string | undefined) {
  if (!value) {
    return undefined;
  }

  try {
    const url = new URL(value, "https://vaultkern.invalid");
    const hash = url.hash ? url.hash.slice(1) : undefined;
    return [
      url.hostname,
      url.pathname,
      ...splitUrlPart(url.pathname),
      hash,
      ...splitUrlPart(hash),
      ...authQueryContext(url)
    ]
      .filter(Boolean)
      .join(",");
  } catch {
    return value.split(/[?#]/, 1)[0];
  }
}

function implicitFormActionContext(value: string | undefined) {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith("#") && !trimmed.startsWith("?")) {
    return undefined;
  }

  try {
    const url = new URL(trimmed, "https://vaultkern.invalid");
    const hash = url.hash ? url.hash.slice(1) : undefined;
    return [hash, ...authQueryContext(url)].filter(Boolean).join(",");
  } catch {
    return trimmed.split(/[?#]/, 1)[0];
  }
}

function formActionPathContext(value: string | undefined) {
  if (!value) {
    return undefined;
  }

  try {
    const url = new URL(value, "https://vaultkern.invalid");
    return url.pathname;
  } catch {
    return value.split(/[?#]/, 1)[0];
  }
}

function joinedFieldText(field: AutofillFieldSnapshot) {
  return [
    field.htmlType,
    field.htmlName,
    field.htmlId,
    field.htmlClass,
    field.autocomplete,
    field.placeholder,
    field.title,
    field.ariaLabel,
    field.labelText,
    ...(field.containerText ?? []),
    ...field.dataSetValues
  ]
    .map(normalize)
    .join(",");
}

function joinedFieldContainerText(field: AutofillFieldSnapshot) {
  return (field.containerText ?? []).map(normalize).join(",");
}

function joinedFormText(
  form: AutofillFormSnapshot | undefined,
  options: { includeAction?: boolean; includeImplicitAction?: boolean } = {}
) {
  if (!form) {
    return "";
  }
  return [
    form.htmlId,
    form.htmlName,
    form.htmlClass,
    options.includeAction === false ||
    (form.htmlActionIsImplicit && options.includeImplicitAction === false)
      ? undefined
      : formActionContext(form.htmlAction),
    options.includeAction === false ||
    (form.htmlSubmitActionIsImplicit && options.includeImplicitAction === false)
      ? undefined
      : formActionContext(form.htmlSubmitAction),
    options.includeAction !== false &&
    form.htmlActionIsImplicit &&
    options.includeImplicitAction === false
      ? implicitFormActionContext(form.htmlActionAttribute)
      : undefined,
    options.includeAction !== false &&
    form.htmlSubmitActionIsImplicit &&
    options.includeImplicitAction === false
      ? implicitFormActionContext(form.htmlSubmitActionAttribute)
      : undefined,
    form.htmlMethod,
    ...form.headingText
  ]
    .map(normalize)
    .join(",");
}

function joinedFormPromptText(form: AutofillFormSnapshot | undefined) {
  return (form?.headingText ?? []).map(normalize).join(",");
}

function joinedFieldPromptText(field: AutofillFieldSnapshot) {
  return [field.placeholder, field.title, field.ariaLabel, field.labelText]
    .map(normalize)
    .join(",");
}

function normalizedParts(text: string) {
  return text.split(",").filter(Boolean);
}

function isRegisterAccountCreationPart(part: string) {
  const routePart = part.replace(/\.[a-z0-9]+$/i, "");
  if (routePart.startsWith("registered")) {
    return false;
  }
  return (
    routePart.startsWith("register") ||
    routePart.startsWith("registration") ||
    routePart.endsWith("register") ||
    routePart.endsWith("registration")
  );
}

function isAccountCreationPart(part: string) {
  return (
    ACCOUNT_CREATION_EXACT_PARTS.has(part) ||
    isRegisterAccountCreationPart(part) ||
    part.includes("signup") ||
    part.includes("createaccount") ||
    part.includes("createnewaccount") ||
    part.includes("createyouraccount") ||
    part.includes("createanaccount") ||
    part.includes("createpassword") ||
    part.includes("newpassword") ||
    part.includes("confirmpassword")
  );
}

function hasAccountCreationContext(text: string) {
  return normalizedParts(text).some(isAccountCreationPart);
}

function hasStrongAccountCreationContext(text: string) {
  return normalizedParts(text).some(
    (part) => isAccountCreationPart(part) && !part.includes("signup")
  );
}

function fieldAutocompleteTokens(field: AutofillFieldSnapshot) {
  return new Set(
    (field.autocomplete ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
  );
}

function hasNewPasswordSignal(candidate: AutofillFieldSnapshot) {
  if (fieldAutocompleteTokens(candidate).has("new-password")) {
    return true;
  }
  return normalizedParts(joinedFieldText(candidate)).some(
    (part) =>
      PASSWORD_CONFIRMATION_EXACT_PARTS.has(part) ||
      NEW_PASSWORD_PARTS.some((keyword) => part.includes(keyword))
  );
}

function isAvailablePasswordSibling(candidate: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(candidate);
  const candidateText = joinedFieldText(candidate);
  return (
    candidate.htmlType === "password" &&
    candidate.viewable &&
    candidate.fillable &&
    !hasNewPasswordSignal(candidate) &&
    !hasPasswordMaskedCodeSignal(candidateText) &&
    !autocomplete.has("one-time-code")
  );
}

function isNewPasswordField(candidate: AutofillFieldSnapshot) {
  return (
    candidate.htmlType === "password" &&
    candidate.viewable &&
    candidate.fillable &&
    hasNewPasswordSignal(candidate)
  );
}

function isCurrentPasswordField(candidate: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(candidate);
  return (
    candidate.htmlType === "password" &&
    candidate.viewable &&
    candidate.fillable &&
    autocomplete.has("current-password")
  );
}

function hasScopedField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  predicate: (candidate: AutofillFieldSnapshot) => boolean
) {
  if (field.formOpid) {
    return snapshot.fields.some(
      (candidate) => candidate.formOpid === field.formOpid && predicate(candidate)
    );
  }
  if (field.containerOpid) {
    return snapshot.fields.some(
      (candidate) =>
        !candidate.formOpid &&
        candidate.containerOpid === field.containerOpid &&
        predicate(candidate)
    );
  }
  return false;
}

function hasPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isAvailablePasswordSibling);
}

function hasNewPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isNewPasswordField);
}

function hasCurrentPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isCurrentPasswordField);
}

function searchPartsForField(field: AutofillFieldSnapshot) {
  return [
    field.htmlType,
    field.htmlName,
    field.htmlId,
    field.htmlClass,
    field.autocomplete,
    field.placeholder,
    field.title,
    field.ariaLabel,
    field.labelText,
    ...field.dataSetValues
  ];
}

function searchPartsForForm(form: AutofillFormSnapshot | undefined) {
  if (!form) {
    return [];
  }
  return [
    form.htmlId,
    form.htmlName,
    form.htmlClass,
    form.htmlActionIsImplicit ? undefined : formActionPathContext(form.htmlAction),
    form.htmlSubmitActionIsImplicit ? undefined : formActionPathContext(form.htmlSubmitAction),
    form.htmlMethod,
    ...form.headingText
  ];
}

function hasSearchToken(parts: Array<string | undefined>) {
  return parts.some((part) =>
    (part ?? "")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .some((token) => token === "search" || token === "query" || token === "find")
  );
}

function hasFieldSearchContext(field: AutofillFieldSnapshot) {
  if (field.htmlType === "search") {
    return true;
  }
  return hasSearchToken(searchPartsForField(field));
}

function hasFormSearchContext(form: AutofillFormSnapshot | undefined) {
  return hasSearchToken(searchPartsForForm(form));
}

function isSearchField(
  field: AutofillFieldSnapshot,
  form: AutofillFormSnapshot | undefined,
  hasScopedPasswordEvidence: boolean,
  hasScopedLoginEvidence: boolean
) {
  return (
    hasFieldSearchContext(field) ||
    (hasFormSearchContext(form) && !hasScopedPasswordEvidence && !hasScopedLoginEvidence)
  );
}

function hasAnyKeyword(text: string, keywords: string[]) {
  return keywords.some((keyword) => text.includes(keyword));
}

function isLoginContextPart(part: string) {
  const routePart = part.replace(/\.[a-z0-9]+$/i, "");
  if (
    routePart.startsWith("lastlogin") ||
    routePart.startsWith("previouslogin") ||
    routePart.startsWith("recentlogin")
  ) {
    return false;
  }
  return (
    routePart === "login" ||
    routePart.startsWith("login") ||
    routePart.endsWith("login") ||
    routePart === "signin" ||
    routePart.startsWith("signin") ||
    routePart.endsWith("signin") ||
    routePart === "signon" ||
    routePart.startsWith("signon") ||
    routePart.endsWith("signon")
  );
}

function excludedReason(fieldText: string, formText: string) {
  const searchableText = `${fieldText},${formText}`;
  const searchableParts = normalizedParts(searchableText);
  if (fieldText.includes("captcha")) {
    return "excluded:captcha";
  }
  if (searchableText.includes("forgot")) {
    return "excluded:forgot";
  }
  if (
    searchableText.includes("resetpassword") ||
    searchableText.includes("passwordreset") ||
    searchableParts.some((part) => part.includes("reset") && part.includes("password")) ||
    (searchableParts.some((part) => part.includes("reset")) &&
      searchableParts.some((part) => part.includes("password")))
  ) {
    return "excluded:reset";
  }
  if (
    searchableText.includes("accountrecovery") ||
    searchableText.includes("recoveraccount") ||
    searchableText.includes("recovery")
  ) {
    return "excluded:recovery";
  }
  return null;
}

function nonLoginReason(fieldText: string, formText: string) {
  const searchableText = `${fieldText},${formText}`;
  const hasNewsletterContext = NON_LOGIN_KEYWORDS.some((keyword) => searchableText.includes(keyword));
  if (
    hasStrongAccountCreationContext(searchableText) ||
    (!hasNewsletterContext && hasAccountCreationContext(searchableText))
  ) {
    return "non-login:account-creation";
  }
  if (hasNewsletterContext) {
    return "non-login:newsletter";
  }
  return null;
}

function hasPasswordMaskedCodeSignal(fieldText: string) {
  return normalizedParts(fieldText).some((part) =>
    PASSWORD_MASKED_CODE_PARTS.some((keyword) => part.includes(keyword))
  );
}

function isUsernameLike(field: AutofillFieldSnapshot, fieldText: string) {
  if (field.tagName !== "input" || !USERNAME_INPUT_TYPES.has(field.htmlType ?? "text")) {
    return false;
  }

  const autocomplete = fieldAutocompleteTokens(field);
  const fieldTextParts = fieldText.split(",");
  if (
    [...USERNAME_AUTOCOMPLETE].some((token) => autocomplete.has(token)) ||
    [...EMAIL_AUTOCOMPLETE].some((token) => autocomplete.has(token))
  ) {
    return true;
  }

  return (
    field.htmlType === "email" ||
    fieldText.includes("username") ||
    fieldText.includes("userid") ||
    fieldTextParts.some(
      (part) =>
        part === "identifier" ||
        part === "account" ||
        part === "accountid" ||
        part === "accountname"
    ) ||
    fieldTextParts.some((part) => part === "user") ||
    fieldText.includes("email") ||
    fieldText.includes("phone") ||
    fieldText.includes("mobile") ||
    field.htmlType === "tel" ||
    fieldTextParts.some((part) => part === "tel" || part.includes("telephone")) ||
    fieldTextParts.some((part) => part === "login" || part === "loginid" || part === "loginname")
  );
}

function hasLoginContext(text: string) {
  return normalizedParts(text).some(isLoginContextPart);
}

function isPasswordLike(field: AutofillFieldSnapshot) {
  return field.tagName === "input" && field.htmlType === "password";
}

function qualificationForFillableField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  form: AutofillFormSnapshot | undefined,
  reasons: string[]
): FieldQualification {
  const fieldText = joinedFieldText(field);
  const fieldPromptText = joinedFieldPromptText(field);
  const formText = joinedFormText(form);
  const visiblePromptText = `${joinedFieldContainerText(field)},${joinedFormPromptText(form)}`;
  const negativeFormText = joinedFormText(form, { includeImplicitAction: false });
  const autocomplete = fieldAutocompleteTokens(field);
  const hasScopedPasswordEvidence = isPasswordLike(field) || hasPasswordSibling(field, snapshot);
  const loginEvidenceText = `${fieldPromptText},${joinedFieldContainerText(field)},${formText}`;

  if (isSearchField(field, form, hasScopedPasswordEvidence, hasLoginContext(loginEvidenceText))) {
    reasons.push("excluded:search");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  const excluded = excludedReason(fieldText, negativeFormText);
  if (excluded) {
    reasons.push(excluded);
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (autocomplete.has("new-password")) {
    reasons.push("excluded:new-password");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (autocomplete.has("one-time-code")) {
    reasons.push("excluded:one-time-code");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (
    field.htmlType === "password" &&
    !autocomplete.has("current-password") &&
    hasPasswordMaskedCodeSignal(fieldText)
  ) {
    reasons.push("excluded:one-time-code");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (field.htmlType !== "password" && hasPasswordMaskedCodeSignal(fieldText)) {
    reasons.push("excluded:one-time-code");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  const nonLogin = nonLoginReason(fieldText, negativeFormText);
  const hasNewsletterPasswordContext = hasPasswordSibling(field, snapshot) || isPasswordLike(field);
  const newsletterLoginPromptText = `${fieldPromptText},${visiblePromptText}`;
  const hasNewsletterLoginContext =
    nonLogin === "non-login:newsletter" &&
    (hasLoginContext(newsletterLoginPromptText) || hasNewsletterPasswordContext) &&
    (hasNewsletterPasswordContext || isUsernameLike(field, fieldText));
  const hasMixedCurrentPasswordLoginContext =
    nonLogin === "non-login:account-creation" &&
    hasLoginContext(visiblePromptText) &&
    (autocomplete.has("current-password") || hasCurrentPasswordSibling(field, snapshot));
  const hasMixedPasswordLoginContext =
    nonLogin === "non-login:account-creation" &&
    hasLoginContext(visiblePromptText) &&
    !hasNewPasswordSibling(field, snapshot) &&
    (isPasswordLike(field) || hasPasswordSibling(field, snapshot));
  if (
    nonLogin &&
    !hasNewsletterLoginContext &&
    !hasMixedCurrentPasswordLoginContext &&
    !hasMixedPasswordLoginContext
  ) {
    reasons.push(nonLogin);
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (isPasswordLike(field)) {
    if (
      hasNewPasswordSibling(field, snapshot) &&
      !hasCurrentPasswordSibling(field, snapshot) &&
      !autocomplete.has("current-password")
    ) {
      reasons.push("non-login:account-creation");
      return { qualifiedAs: "ignored", eligible: false, reasons };
    }
    if (autocomplete.has("current-password")) {
      reasons.push("autocomplete:current-password");
    }
    return { qualifiedAs: "password", eligible: true, reasons };
  }

  if (isUsernameLike(field, fieldText)) {
    const hasUsernameAutocomplete = [...USERNAME_AUTOCOMPLETE].some((token) =>
      autocomplete.has(token)
    );
    const hasEmailAutocomplete = [...EMAIL_AUTOCOMPLETE].some((token) => autocomplete.has(token));
    const fieldTextParts = fieldText.split(",");
    const hasEmailSignal =
      field.htmlType === "email" || hasEmailAutocomplete || fieldText.includes("email");
    const hasPhoneSignal =
      field.htmlType === "tel" ||
      fieldText.includes("phone") ||
      fieldText.includes("mobile") ||
      fieldTextParts.some((part) => part === "tel" || part.includes("telephone"));
    const hasGenericIdentifierSignal = fieldTextParts.some(
      (part) =>
        part === "user" ||
        part === "identifier" ||
        part === "account" ||
        part === "accountid" ||
        part === "accountname" ||
        part === "login" ||
        part === "loginid" ||
        part === "loginname"
    );
    const needsLoginEvidence =
      (hasEmailSignal || hasPhoneSignal || hasGenericIdentifierSignal) &&
      !hasUsernameAutocomplete;
    if (
      hasNewPasswordSibling(field, snapshot) &&
      !hasCurrentPasswordSibling(field, snapshot)
    ) {
      reasons.push("non-login:account-creation");
      return { qualifiedAs: "ignored", eligible: false, reasons };
    }
    if (
      needsLoginEvidence &&
      !hasPasswordSibling(field, snapshot) &&
      !hasLoginContext(loginEvidenceText)
    ) {
      return { qualifiedAs: "ignored", eligible: false, reasons };
    }
    if (autocomplete.has("username")) {
      reasons.push("autocomplete:username");
    } else if (autocomplete.has("email")) {
      reasons.push("autocomplete:email");
    }
    if (hasPasswordSibling(field, snapshot)) {
      reasons.push("form-has-password");
    }
    return { qualifiedAs: "username", eligible: true, reasons };
  }

  return { qualifiedAs: "ignored", eligible: false, reasons };
}

export function qualifyAutofillField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  form: AutofillFormSnapshot | undefined
): FieldQualification {
  const reasons = [...field.viewableReasons, ...field.fillableReasons];

  if (!field.viewable || !field.fillable) {
    return {
      qualifiedAs: "ignored",
      eligible: false,
      reasons
    };
  }

  return qualificationForFillableField(field, snapshot, form, reasons);
}
