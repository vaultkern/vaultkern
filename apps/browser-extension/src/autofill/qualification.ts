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
const ACCOUNT_CREATION_KEYWORDS = [
  "register",
  "signup",
  "createaccount",
  "createpassword",
  "newpassword",
  "confirmpassword"
];

export interface FieldQualification {
  qualifiedAs: AutofillFieldQualification;
  eligible: boolean;
  reasons: string[];
}

function normalize(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
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
    field.ariaDescribedBy,
    field.labelText,
    ...field.dataSetValues
  ]
    .map(normalize)
    .join(",");
}

function joinedFormText(form: AutofillFormSnapshot | undefined) {
  if (!form) {
    return "";
  }
  return [
    form.htmlId,
    form.htmlName,
    form.htmlClass,
    form.htmlAction,
    form.htmlMethod,
    ...form.headingText
  ]
    .map(normalize)
    .join(",");
}

function fieldAutocompleteTokens(field: AutofillFieldSnapshot) {
  return new Set(
    (field.autocomplete ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
  );
}

function hasPasswordSibling(field: AutofillFieldSnapshot, snapshot: AutofillPageSnapshot) {
  if (field.formOpid) {
    return snapshot.fields.some(
      (candidate) => candidate.formOpid === field.formOpid && candidate.htmlType === "password"
    );
  }
  if (field.containerOpid) {
    return snapshot.fields.some(
      (candidate) =>
        !candidate.formOpid &&
        candidate.containerOpid === field.containerOpid &&
        candidate.htmlType === "password"
    );
  }
  return false;
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
    field.ariaDescribedBy,
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
    form.htmlAction,
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
  if (searchableText.includes("resetpassword")) {
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
  if (ACCOUNT_CREATION_KEYWORDS.some((keyword) => searchableText.includes(keyword))) {
    return "non-login:account-creation";
  }
  return null;
}

function isUsernameLike(field: AutofillFieldSnapshot, fieldText: string) {
  if (field.tagName !== "input" || !USERNAME_INPUT_TYPES.has(field.htmlType ?? "text")) {
    return false;
  }

  const autocomplete = fieldAutocompleteTokens(field);
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
    fieldText.includes("email") ||
    fieldText.includes("phone") ||
    fieldText.includes("mobile") ||
    field.htmlType === "tel" ||
    fieldText.split(",").some((part) => part === "tel" || part.includes("telephone")) ||
    fieldText.includes("login")
  );
}

function hasLoginContext(fieldText: string, formText: string) {
  return hasAnyKeyword(`${fieldText},${formText}`, ["login", "signin", "signon"]);
}

function isPasswordLike(field: AutofillFieldSnapshot) {
  const autocomplete = fieldAutocompleteTokens(field);
  return (
    field.htmlType === "password" ||
    [...PASSWORD_AUTOCOMPLETE].some((token) => autocomplete.has(token))
  );
}

function qualificationForFillableField(
  field: AutofillFieldSnapshot,
  snapshot: AutofillPageSnapshot,
  form: AutofillFormSnapshot | undefined,
  reasons: string[]
): FieldQualification {
  const fieldText = joinedFieldText(field);
  const formText = joinedFormText(form);
  const autocomplete = fieldAutocompleteTokens(field);

  if (isSearchField(field, form)) {
    reasons.push("excluded:search");
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  const excluded = excludedReason(fieldText, formText);
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

  const nonLogin = nonLoginReason(fieldText, formText);
  if (nonLogin) {
    reasons.push(nonLogin);
    return { qualifiedAs: "ignored", eligible: false, reasons };
  }

  if (isPasswordLike(field)) {
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
    const needsLoginEvidence = (field.htmlType === "email" || hasEmailAutocomplete) && !hasUsernameAutocomplete;
    if (
      needsLoginEvidence &&
      !hasPasswordSibling(field, snapshot) &&
      !hasLoginContext(fieldText, formText)
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
