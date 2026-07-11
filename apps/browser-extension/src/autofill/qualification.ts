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
const NEW_PASSWORD_AUTOCOMPLETE = new Set(["new-password"]);
const TOTP_AUTOCOMPLETE = new Set(["one-time-code"]);
const NON_LOGIN_KEYWORDS = ["newsletter", "subscribe", "subscription", "unsubscribe", "mailinglist"];
const CURRENT_PASSWORD_KEYWORDS = ["currentpassword", "oldpassword", "existingpassword"];
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
const CARD_SECURITY_CODE_PARTS = [
  "csc",
  "cccsc",
  "cvc",
  "cvv",
  "cardcsc",
  "cardcvc",
  "cardcvv",
  "cardcode",
  "cardsecuritycode",
  "cardverificationcode"
];
const RECOVERY_CODE_KEYWORDS = ["backup", "recovery"];
const TOTP_KEYWORDS = [
  "totp",
  "otp",
  "2fa",
  "2factor",
  "2step",
  "mfa",
  "onetimecode",
  "onetimepassword",
  "authenticationcode",
  "authenticator",
  "authenticatorapp",
  "authenticatorcode",
  "twofactor",
  "twostep"
];
const AUTHENTICATOR_TOTP_KEYWORDS = [
  "totp",
  "authenticationcode",
  "authenticator",
  "authenticatorapp",
  "authenticatorcode"
];
const TOTP_INPUT_TYPES = new Set(["number", "password", "tel", "text"]);

export interface FieldQualification {
  q: AutofillFieldQualification;
  el: boolean;
  why: string[];
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
    field.hy,
    field.hn,
    field.hi,
    field.hc,
    field.au,
    field.im,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...(field.ct ?? []),
    ...field.dv
  ]
    .map(normalize)
    .join(",");
}

function joinedFieldPromptText(field: AutofillFieldSnapshot) {
  return [
    field.hy,
    field.hn,
    field.hi,
    field.hc,
    field.im,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...field.dv
  ]
    .map(normalize)
    .join(",");
}

function joinedFormTextParts(
  form: AutofillFormSnapshot | undefined,
  options: { includeAction: boolean; includeSubmitText?: boolean }
) {
  if (!form) {
    return [];
  }
  const submitText = new Set(form.st ?? []);
  const headingText =
    options.includeSubmitText === false
      ? (form.ht ?? []).filter((text) => !submitText.has(text))
      : form.ht ?? [];
  return [
    form.hi,
    form.hn,
    form.hc,
    options.includeAction ? formActionContext(form.ha) : undefined,
    form.hm,
    form.al,
    ...headingText
  ];
}

function joinedFormText(form: AutofillFormSnapshot | undefined) {
  return joinedFormTextParts(form, { includeAction: true })
    .map(normalize)
    .join(",");
}

function joinedFormNonSubmitText(form: AutofillFormSnapshot | undefined) {
  return joinedFormTextParts(form, { includeAction: true, includeSubmitText: false })
    .map(normalize)
    .join(",");
}

function joinedFormPromptText(form: AutofillFormSnapshot | undefined) {
  return joinedFormTextParts(form, { includeAction: false })
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

function isAccountCreationIdentityPart(part: string) {
  return (
    part === "register" ||
    part === "registration" ||
    part === "signup" ||
    part === "createaccount" ||
    part === "createyouraccount" ||
    part === "createanaccount" ||
    isRegisterAccountCreationPart(part) ||
    part.includes("signup") ||
    part.includes("createaccount") ||
    part.includes("createyouraccount") ||
    part.includes("createanaccount")
  );
}

function hasAccountCreationIdentityContext(text: string) {
  return normalizedParts(text).some(isAccountCreationIdentityPart);
}

function fieldAutocompleteTokens(field: AutofillFieldSnapshot) {
  return new Set(
    (field.au ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
  );
}

function hasNewPasswordSignal(candidate: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(candidate);
  if ([...NEW_PASSWORD_AUTOCOMPLETE].some((token) => autocomplete.has(token))) {
    return true;
  }
  return normalizedParts(joinedFieldText(candidate)).some((part) =>
    NEW_PASSWORD_PARTS.some((keyword) => part.includes(keyword))
  );
}

function hasPasswordConfirmationSignal(candidate: AutofillFieldSnapshot) {
  return normalizedParts(joinedFieldText(candidate)).some(
    (part) =>
      part.includes("confirmpassword") ||
      part.includes("passwordconfirm") ||
      part.includes("passwordconfirmation") ||
      part.includes("repeatpassword") ||
      part.includes("verifypassword")
  );
}

function isAvailablePasswordSibling(candidate: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(candidate);
  const candidateText = joinedFieldText(candidate);
  return (
    candidate.hy === "password" &&
    candidate.vw &&
    candidate.fl &&
    !hasNewPasswordSignal(candidate) &&
    !hasPasswordMaskedCodeSignal(candidateText) &&
    !hasCardSecurityCodeSignal(candidateText) &&
    !autocomplete.has("one-time-code")
  );
}

function hasScopedField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  predicate: (candidate: AutofillFieldSnapshot) => boolean
) {
  return snapshot.f.some(
    (candidate) => candidate.so === field.so && predicate(candidate)
  );
}

function hasPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isAvailablePasswordSibling);
}

function hasOtherPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(
    field,
    snapshot,
    (candidate) => candidate.o !== field.o && isAvailablePasswordSibling(candidate)
  );
}

function isNewPasswordField(candidate: AutofillFieldSnapshot) {
  return (
    candidate.hy === "password" &&
    candidate.vw &&
    candidate.fl &&
    hasNewPasswordSignal(candidate)
  );
}

function hasNewPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isNewPasswordField);
}

function isCurrentPasswordSibling(candidate: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(candidate);
  const candidateText = joinedFieldText(candidate);
  return (
    candidate.hy === "password" &&
    candidate.vw &&
    candidate.fl &&
    (autocomplete.has("current-password") ||
      candidateText.includes("currentpassword") ||
      candidateText.includes("oldpassword") ||
      candidateText.includes("existingpassword"))
  );
}

function hasCurrentPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  return hasScopedField(field, snapshot, isCurrentPasswordSibling);
}

function searchPartsForField(field: AutofillFieldSnapshot) {
  return [
    field.hy,
    field.hn,
    field.hi,
    field.hc,
    field.au,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...field.dv
  ];
}

function searchPartsForForm(form: AutofillFormSnapshot | undefined) {
  if (!form) {
    return [];
  }
  const headingText = form.ht ?? [];
  return [
    form.hi,
    form.hn,
    form.hc,
    form.hai ? undefined : formActionContext(form.ha),
    form.hm,
    ...headingText
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
  if (field.hy === "search") {
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

function hasCardSecurityCodeSignal(fieldText: string) {
  return normalizedParts(fieldText).some((part) =>
    CARD_SECURITY_CODE_PARTS.some((keyword) => part.includes(keyword))
  );
}

function recoveryCodeReason(
  fieldText: string,
  formText: string,
  autocomplete: Set<string>
) {
  const searchableText = `${fieldText},${formText}`;
  const fieldHasRecoveryMarker = RECOVERY_CODE_KEYWORDS.some((keyword) =>
    fieldText.includes(keyword)
  );
  const formHasRecoveryMarker = RECOVERY_CODE_KEYWORDS.some((keyword) => formText.includes(keyword));
  const hasRecoveryMarker = fieldHasRecoveryMarker || formHasRecoveryMarker;
  if (!hasRecoveryMarker) {
    return null;
  }

  const formHasRecoveryCodePrompt =
    formHasRecoveryMarker &&
    (formText.includes("code") ||
      formText.includes("otp") ||
      formText.includes("totp") ||
      formText.includes("onetime"));

  if (
    !fieldHasRecoveryMarker &&
    hasAuthenticatorTotpKeyword(searchableText) &&
    !formHasRecoveryCodePrompt
  ) {
    return null;
  }

  const hasCodeContext =
    autocomplete.has("one-time-code") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp") ||
    fieldText.includes("onetime");
  return hasCodeContext ? "excluded:recovery-code" : null;
}

function isUsernameLike(field: AutofillFieldSnapshot, fieldText: string) {
  if (field.tg !== "input" || !USERNAME_INPUT_TYPES.has(field.hy ?? "text")) {
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
    field.hy === "email" ||
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
    field.hy === "tel" ||
    fieldTextParts.some((part) => part === "tel" || part.includes("telephone")) ||
    fieldTextParts.some((part) => part === "login" || part === "loginid" || part === "loginname")
  );
}

function hasLoginContext(text: string) {
  return hasAnyKeyword(text, ["login", "signin", "signon", "usernamestep"]);
}

function hasTotpKeyword(text: string) {
  return TOTP_KEYWORDS.some((keyword) => text.includes(keyword));
}

function hasAuthenticatorTotpKeyword(text: string) {
  return AUTHENTICATOR_TOTP_KEYWORDS.some((keyword) => text.includes(keyword));
}

function hasStrongTotpContext(text: string) {
  return (
    hasAuthenticatorTotpKeyword(text) ||
    text.includes("2fa") ||
    text.includes("2factor") ||
    text.includes("2step") ||
    text.includes("mfa") ||
    text.includes("otp") ||
    text.includes("totp") ||
    text.includes("twofactor") ||
    text.includes("twostep")
  );
}

function hasPhoneVerificationCodeSignal(text: string) {
  const hasPhoneContext = text.includes("phone") || text.includes("mobile");
  const hasCodeContext =
    text.includes("code") ||
    text.includes("otp") ||
    text.includes("onetime") ||
    text.includes("verification") ||
    text.includes("verify");
  return hasPhoneContext && hasCodeContext && !hasAuthenticatorTotpKeyword(text);
}

function hasOutOfBandCodeSignal(text: string) {
  return (
    text.includes("sms") ||
    text.includes("textmessage") ||
    text.includes("mobile") ||
    text.includes("emailcode") ||
    text.includes("emailotp") ||
    text.includes("emailverification") ||
    text.includes("senttoyouremail") ||
    text.includes("senttoyourmobile") ||
    text.includes("senttoyourphone")
  );
}

function hasDirectedOutOfBandCodeSignal(text: string) {
  return (
    text.includes("sms") ||
    text.includes("textmessage") ||
    text.includes("emailcode") ||
    text.includes("emailotp") ||
    text.includes("emailverification") ||
    text.includes("senttoyouremail") ||
    text.includes("senttoyourmobile") ||
    text.includes("senttoyourphone")
  );
}

function outOfBandCodeReason(
  fieldText: string,
  formText: string,
  autocomplete: Set<string>
) {
  const searchableText = `${fieldText},${formText}`;
  const hasFieldCodeContext =
    autocomplete.has("one-time-code") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp") ||
    fieldText.includes("verification") ||
    fieldText.includes("onetime");
  if (!hasFieldCodeContext) {
    return null;
  }

  if (
    hasDirectedOutOfBandCodeSignal(fieldText) ||
    hasDirectedOutOfBandCodeSignal(formText) ||
    hasPhoneVerificationCodeSignal(formText)
  ) {
    return "excluded:out-of-band-code";
  }

  if (hasAuthenticatorTotpKeyword(searchableText)) {
    return null;
  }

  if (hasOutOfBandCodeSignal(fieldText)) {
    return "excluded:out-of-band-code";
  }

  if (hasOutOfBandCodeSignal(formText)) {
    return "excluded:out-of-band-code";
  }

  return null;
}

function isTotpInputControl(field: AutofillFieldSnapshot) {
  return field.tg === "input" && TOTP_INPUT_TYPES.has(field.hy ?? "text");
}

function hasNumericCodeShape(field: AutofillFieldSnapshot, fieldText: string) {
  return (
    field.im === "numeric" ||
    field.im === "decimal" ||
    field.ml === 1 ||
    fieldText.includes("digit") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp") ||
    fieldText.includes("onetime")
  );
}

function hasFieldCodeHint(
  field: AutofillFieldSnapshot,
  fieldText: string,
  autocomplete: Set<string>
) {
  return (
    autocomplete.has("one-time-code") ||
    field.ml === 1 ||
    (field.ml !== undefined && field.ml >= 4 && field.ml <= 8) ||
    fieldText.includes("digit") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp") ||
    fieldText.includes("onetime")
  );
}

function isTotpLike(
  field: AutofillFieldSnapshot,
  fieldText: string,
  fieldPromptText: string,
  formText: string
) {
  const autocomplete = fieldAutocompleteTokens(field);
  if ([...TOTP_AUTOCOMPLETE].some((token) => autocomplete.has(token))) {
    return hasStrongTotpContext(`${fieldPromptText},${formText}`);
  }
  if (field.hy === "password") {
    return (
      !autocomplete.has("current-password") &&
      hasPasswordMaskedCodeSignal(fieldText) &&
      (hasTotpKeyword(fieldText) ||
        hasTotpKeyword(formText) ||
        hasAuthenticatorTotpKeyword(formText))
    );
  }

  if (!isTotpInputControl(field)) {
    return false;
  }

  if (hasTotpKeyword(fieldText)) {
    return (
      hasFieldCodeHint(field, fieldText, autocomplete) &&
      hasNumericCodeShape(field, fieldText)
    );
  }

  return (
    hasTotpKeyword(formText) &&
    hasFieldCodeHint(field, fieldText, autocomplete) &&
    hasNumericCodeShape(field, fieldText)
  );
}

function isPasswordLike(field: AutofillFieldSnapshot) {
  return field.tg === "input" && field.hy === "password";
}

function isCurrentPasswordLike(field: AutofillFieldSnapshot, fieldText: string) {
  if (!isPasswordLike(field)) {
    return false;
  }
  return CURRENT_PASSWORD_KEYWORDS.some((keyword) => fieldText.includes(keyword));
}

function isNewPasswordLike(field: AutofillFieldSnapshot, fieldText: string, formText: string) {
  const autocomplete = fieldAutocompleteTokens(field);
  if ([...NEW_PASSWORD_AUTOCOMPLETE].some((token) => autocomplete.has(token))) {
    return true;
  }
  if (field.hy !== "password") {
    return false;
  }
  const searchableText = `${fieldText},${formText}`;
  return hasAccountCreationContext(searchableText) && !hasLoginContext(searchableText);
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
  const formNonSubmitText = joinedFormNonSubmitText(form);
  const formPromptText = joinedFormPromptText(form);
  const autocomplete = fieldAutocompleteTokens(field);
  const siteRuleType = field.rt.find((fieldType) => fieldType !== "ignored");

  if (siteRuleType) {
    return {
      q: siteRuleType,
      el: true,
      why: reasons
    };
  }

  if (isSearchField(field, form)) {
    reasons.push("excluded:search");
    return { q: "ignored", el: false, why: reasons };
  }

  const excluded = excludedReason(fieldText, formText);
  const keepsProvenResetPasswordRole =
    excluded === "excluded:reset" &&
    isPasswordLike(field) &&
    (autocomplete.has("new-password") || hasNewPasswordSignal(field));
  if (excluded && !keepsProvenResetPasswordRole) {
    reasons.push(excluded);
    return { q: "ignored", el: false, why: reasons };
  }
  if (excluded) {
    reasons.push(excluded);
  }

  const recoveryCode = recoveryCodeReason(fieldText, formPromptText, autocomplete);
  if (recoveryCode) {
    reasons.push(recoveryCode);
    return { q: "ignored", el: false, why: reasons };
  }

  if (field.hy === "password" && hasCardSecurityCodeSignal(fieldText)) {
    reasons.push("excluded:card-security-code");
    return { q: "ignored", el: false, why: reasons };
  }

  const searchableText = `${fieldText},${formText}`;
  const searchableNonSubmitText = `${fieldText},${formNonSubmitText}`;
  const hasMixedLoginContext =
    hasLoginContext(searchableText) || !hasAccountCreationContext(searchableText);
  const nonLogin = nonLoginReason(fieldText, formText);
  const hasNewsletterLoginContext =
    nonLogin === "non-login:newsletter" &&
    hasLoginContext(searchableText) &&
    (hasPasswordSibling(field, snapshot) || isUsernameLike(field, fieldText));
  const hasMixedCurrentPasswordLoginContext =
    nonLogin === "non-login:account-creation" &&
    hasLoginContext(searchableText) &&
    (autocomplete.has("current-password") || hasCurrentPasswordSibling(field, snapshot));
  const hasAccountCreationPasswordWithoutCurrentEvidence =
    nonLogin === "non-login:account-creation" &&
    isPasswordLike(field) &&
    !autocomplete.has("current-password") &&
    !hasCurrentPasswordSibling(field, snapshot) &&
    !hasLoginContext(searchableNonSubmitText) &&
    hasAccountCreationContext(searchableNonSubmitText);
  const hasMixedLoginFormContext =
    nonLogin === "non-login:account-creation" &&
    hasLoginContext(searchableText) &&
    !hasAccountCreationPasswordWithoutCurrentEvidence &&
    ((isPasswordLike(field) &&
      (!hasAccountCreationContext(searchableNonSubmitText) ||
        hasLoginContext(searchableNonSubmitText))) ||
      hasOtherPasswordSibling(field, snapshot) ||
      hasCurrentPasswordSibling(field, snapshot));
  const isAccountCreationUsernameWithPassword =
    nonLogin === "non-login:account-creation" &&
    hasAccountCreationIdentityContext(searchableNonSubmitText) &&
    isUsernameLike(field, fieldText) &&
    (hasPasswordSibling(field, snapshot) ||
      hasNewPasswordSibling(field, snapshot) ||
      hasCurrentPasswordSibling(field, snapshot));
  const canUseCurrentPasswordInNonLoginContext =
    !nonLogin ||
    hasNewsletterLoginContext ||
    hasMixedCurrentPasswordLoginContext ||
    hasMixedLoginFormContext;
  const isUsernameInCurrentPasswordForm =
    isUsernameLike(field, fieldText) &&
    hasMixedLoginContext &&
    hasCurrentPasswordSibling(field, snapshot);
  const canUseUsernameInNonLoginContext =
    !nonLogin ||
    isUsernameInCurrentPasswordForm ||
    isAccountCreationUsernameWithPassword ||
    hasNewsletterLoginContext ||
    hasMixedCurrentPasswordLoginContext ||
    hasMixedLoginFormContext;

  if (
    [...USERNAME_AUTOCOMPLETE].some((token) => autocomplete.has(token)) &&
    isUsernameLike(field, fieldText)
  ) {
    if (nonLogin && !canUseUsernameInNonLoginContext) {
      reasons.push(nonLogin);
      return { q: "ignored", el: false, why: reasons };
    }
    if (autocomplete.has("username")) {
      reasons.push("autocomplete:username");
    } else if (autocomplete.has("email")) {
      reasons.push("autocomplete:email");
    }
    if (hasPasswordSibling(field, snapshot)) {
      reasons.push("form-has-password");
    }
    return { q: "username", el: true, why: reasons };
  }

  if (
    [...EMAIL_AUTOCOMPLETE].some((token) => autocomplete.has(token)) &&
    isUsernameLike(field, fieldText) &&
    (hasPasswordSibling(field, snapshot) || hasLoginContext(formText))
  ) {
    if (nonLogin && !canUseUsernameInNonLoginContext) {
      reasons.push(nonLogin);
      return { q: "ignored", el: false, why: reasons };
    }
    reasons.push("autocomplete:email");
    if (hasPasswordSibling(field, snapshot)) {
      reasons.push("form-has-password");
    }
    return { q: "username", el: true, why: reasons };
  }

  if (isPasswordLike(field) && autocomplete.has("current-password") && hasMixedLoginContext) {
    if (nonLogin && !canUseCurrentPasswordInNonLoginContext) {
      reasons.push(nonLogin);
      return { q: "ignored", el: false, why: reasons };
    }
    reasons.push("autocomplete:current-password");
    return { q: "currentPassword", el: true, why: reasons };
  }

  if (isCurrentPasswordLike(field, fieldText)) {
    return { q: "currentPassword", el: true, why: reasons };
  }

  if (isPasswordLike(field) && hasPasswordConfirmationSignal(field)) {
    if (autocomplete.has("new-password")) {
      reasons.push("autocomplete:new-password");
    }
    reasons.push("password-role:confirmation");
    return { q: "confirmation", el: true, why: reasons };
  }

  if (
    isNewPasswordLike(field, fieldText, formText) ||
    hasAccountCreationPasswordWithoutCurrentEvidence
  ) {
    if (autocomplete.has("new-password")) {
      reasons.push("autocomplete:new-password");
    }
    if (hasAccountCreationPasswordWithoutCurrentEvidence) {
      reasons.push("non-login:account-creation");
    }
    return { q: "newPassword", el: true, why: reasons };
  }

  if (
    nonLogin &&
    !isUsernameInCurrentPasswordForm &&
    !isAccountCreationUsernameWithPassword &&
    !hasNewsletterLoginContext &&
    !hasMixedCurrentPasswordLoginContext &&
    !hasMixedLoginFormContext
  ) {
    reasons.push(nonLogin);
    return { q: "ignored", el: false, why: reasons };
  }

  const outOfBandCode = outOfBandCodeReason(fieldText, formPromptText, autocomplete);
  if (outOfBandCode) {
    reasons.push(outOfBandCode);
    return { q: "ignored", el: false, why: reasons };
  }

  if (
    field.hy === "password" &&
    !autocomplete.has("current-password") &&
    hasPasswordMaskedCodeSignal(fieldText) &&
    !isTotpLike(field, fieldText, fieldPromptText, formPromptText)
  ) {
    reasons.push("excluded:one-time-code");
    return { q: "ignored", el: false, why: reasons };
  }

  if (isTotpLike(field, fieldText, fieldPromptText, formPromptText)) {
    if (autocomplete.has("one-time-code")) {
      reasons.push("autocomplete:one-time-code");
    }
    if (field.ml === 1) {
      reasons.push("totp:split-field");
    }
    return { q: "totp", el: true, why: reasons };
  }

  if (isPasswordLike(field)) {
    if (autocomplete.has("current-password")) {
      reasons.push("autocomplete:current-password");
    }
    return { q: "password", el: true, why: reasons };
  }

  if (isUsernameLike(field, fieldText)) {
    const hasUsernameAutocomplete = [...USERNAME_AUTOCOMPLETE].some((token) =>
      autocomplete.has(token)
    );
    const hasEmailAutocomplete = [...EMAIL_AUTOCOMPLETE].some((token) => autocomplete.has(token));
    const fieldTextParts = fieldText.split(",");
    const hasEmailSignal =
      field.hy === "email" || hasEmailAutocomplete || fieldText.includes("email");
    const hasPhoneSignal =
      field.hy === "tel" ||
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
      needsLoginEvidence &&
      !hasPasswordSibling(field, snapshot) &&
      !hasLoginContext(formText) &&
      !isAccountCreationUsernameWithPassword
    ) {
      return { q: "ignored", el: false, why: reasons };
    }
    if (autocomplete.has("username")) {
      reasons.push("autocomplete:username");
    } else if (autocomplete.has("email")) {
      reasons.push("autocomplete:email");
    }
    if (hasPasswordSibling(field, snapshot)) {
      reasons.push("form-has-password");
    }
    return { q: "username", el: true, why: reasons };
  }

  return { q: "ignored", el: false, why: reasons };
}

export function qualifyAutofillField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  form: AutofillFormSnapshot | undefined
): FieldQualification {
  const reasons = [
    ...field.vr,
    ...field.fr,
    ...field.rr
  ];

  if (!field.vw) {
    return {
      q: "ignored",
      el: false,
      why: reasons
    };
  }

  if (!field.fl) {
    const fieldText = joinedFieldText(field);
    const formText = joinedFormText(form);
    const autocomplete = fieldAutocompleteTokens(field);
    const siteRuleType = field.rt.find((fieldType) => fieldType !== "ignored");

    if (field.ro && siteRuleType === "username") {
      return { q: "username", el: true, why: reasons };
    }

    if (
      field.ro &&
      !isSearchField(field, form) &&
      !excludedReason(fieldText, formText) &&
      !nonLoginReason(fieldText, formText) &&
      isUsernameLike(field, fieldText)
    ) {
      if (autocomplete.has("username")) {
        reasons.push("autocomplete:username");
      } else if (autocomplete.has("email")) {
        reasons.push("autocomplete:email");
      }
      if (hasPasswordSibling(field, snapshot)) {
        reasons.push("form-has-password");
      }
      return { q: "username", el: true, why: reasons };
    }

    return {
      q: "ignored",
      el: false,
      why: reasons
    };
  }

  return qualificationForFillableField(field, snapshot, form, reasons);
}
