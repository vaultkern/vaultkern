import type {
  AutofillFieldQualification,
  AutofillFieldSnapshot,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";

const USERNAME_AUTOCOMPLETE = new Set(["username", "email"]);
const PASSWORD_AUTOCOMPLETE = new Set(["current-password"]);
const USERNAME_INPUT_TYPES = new Set(["email", "number", "tel", "text", "url"]);
const EXCLUDED_KEYWORDS = [
  ["captcha", "excluded:captcha"],
  ["forgot", "excluded:forgot"]
] as const;
const NON_LOGIN_KEYWORDS = ["newsletter", "subscribe", "subscription", "unsubscribe", "mailinglist"];

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
  if (!field.formOpid) {
    return snapshot.fields.some((candidate) => candidate.htmlType === "password");
  }
  return snapshot.fields.some(
    (candidate) => candidate.formOpid === field.formOpid && candidate.htmlType === "password"
  );
}

function isSearchField(field: AutofillFieldSnapshot, fieldText: string) {
  return field.htmlType === "search" || /\b(search|query|find)\b/.test(fieldText);
}

function excludedReason(fieldText: string, formText: string) {
  const searchableText = `${fieldText},${formText}`;
  for (const [keyword, reason] of EXCLUDED_KEYWORDS) {
    if (searchableText.includes(keyword)) {
      return reason;
    }
  }
  return null;
}

function nonLoginReason(fieldText: string, formText: string) {
  const searchableText = `${fieldText},${formText}`;
  return NON_LOGIN_KEYWORDS.some((keyword) => searchableText.includes(keyword))
    ? "non-login:newsletter"
    : null;
}

function isUsernameLike(field: AutofillFieldSnapshot, fieldText: string) {
  if (field.tagName !== "input" || !USERNAME_INPUT_TYPES.has(field.htmlType ?? "text")) {
    return false;
  }

  const autocomplete = fieldAutocompleteTokens(field);
  if ([...USERNAME_AUTOCOMPLETE].some((token) => autocomplete.has(token))) {
    return true;
  }

  return (
    field.htmlType === "email" ||
    fieldText.includes("username") ||
    fieldText.includes("userid") ||
    fieldText.includes("email") ||
    fieldText.includes("login")
  );
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

  if (isSearchField(field, fieldText)) {
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
