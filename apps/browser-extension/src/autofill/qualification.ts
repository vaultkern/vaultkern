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
  "repeatpassword",
  "verifypassword"
];
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

export interface FieldQualification {
  qualifiedAs: AutofillFieldQualification;
  eligible: boolean;
  reasons: string[];
}

function normalize(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_/-]+/g, "");
}

function formActionContext(value: string | undefined) {
  if (!value) {
    return undefined;
  }

  try {
    const url = new URL(value, "https://vaultkern.invalid");
    return `${url.hostname},${url.pathname}`;
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
    ...field.dataSetValues
  ]
    .map(normalize)
    .join(",");
}

function joinedFormText(
  form: AutofillFormSnapshot | undefined,
  options: { includeImplicitAction?: boolean } = {}
) {
  if (!form) {
    return "";
  }
  return [
    form.htmlId,
    form.htmlName,
    form.htmlClass,
    form.htmlActionIsImplicit && options.includeImplicitAction === false
      ? undefined
      : formActionContext(form.htmlAction),
    form.htmlMethod,
    ...form.headingText
  ]
    .map(normalize)
    .join(",");
}

function normalizedParts(text: string) {
  return text.split(",").filter(Boolean);
}

function isRegisterAccountCreationPart(part: string) {
  if (part.startsWith("registered")) {
    return false;
  }
  return part.startsWith("register") || part.startsWith("registration");
}

function isAccountCreationPart(part: string) {
  return (
    ACCOUNT_CREATION_EXACT_PARTS.has(part) ||
    isRegisterAccountCreationPart(part) ||
    part.includes("signup") ||
    part.includes("createaccount") ||
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
  return normalizedParts(joinedFieldText(candidate)).some((part) =>
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
    form.htmlActionIsImplicit ? undefined : formActionContext(form.htmlAction),
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

function isSearchField(field: AutofillFieldSnapshot, form: AutofillFormSnapshot | undefined) {
  if (field.htmlType === "search") {
    return true;
  }
  return hasSearchToken([...searchPartsForField(field), ...searchPartsForForm(form)]);
}

function hasAnyKeyword(text: string, keywords: string[]) {
  return keywords.some((keyword) => text.includes(keyword));
}

function excludedReason(fieldText: string, formText: string) {
  const searchableText = `${fieldText},${formText}`;
  if (fieldText.includes("captcha")) {
    return "excluded:captcha";
  }
  if (searchableText.includes("forgot")) {
    return "excluded:forgot";
  }
  if (
    searchableText.includes("resetpassword") ||
    searchableText.includes("passwordreset") ||
    normalizedParts(searchableText).some(
      (part) => part.includes("reset") && part.includes("password")
    )
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
  if (NON_LOGIN_KEYWORDS.some((keyword) => searchableText.includes(keyword))) {
    return "non-login:newsletter";
  }
  if (hasAccountCreationContext(searchableText)) {
    return "non-login:account-creation";
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
  return hasAnyKeyword(text, ["login", "signin", "signon"]);
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
  const formText = joinedFormText(form);
  const negativeFormText = joinedFormText(form, { includeImplicitAction: false });
  const autocomplete = fieldAutocompleteTokens(field);

  if (isSearchField(field, form)) {
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

  const searchableText = `${fieldText},${formText}`;
  const nonLogin = nonLoginReason(fieldText, negativeFormText);
  const hasNewsletterLoginContext =
    nonLogin === "non-login:newsletter" &&
    hasLoginContext(searchableText) &&
    (hasPasswordSibling(field, snapshot) || isUsernameLike(field, fieldText));
  const hasMixedCurrentPasswordLoginContext =
    nonLogin === "non-login:account-creation" &&
    hasLoginContext(searchableText) &&
    (autocomplete.has("current-password") || hasCurrentPasswordSibling(field, snapshot));
  if (
    nonLogin &&
    !hasNewsletterLoginContext &&
    !hasMixedCurrentPasswordLoginContext
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
      !hasLoginContext(formText)
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
