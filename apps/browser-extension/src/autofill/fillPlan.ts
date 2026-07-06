import { triageAutofillPage } from "./triage";
import type {
  AutofillPageSnapshot,
  AutofillTriageFieldResult,
  AutofillFieldQualification
} from "./types";

export interface LoginFillPayload {
  username?: string;
  password?: string;
  totp?: string;
}

export interface AutofillFillAction {
  fieldOpid: string;
  elementNumber: number;
  fieldType: AutofillFieldQualification;
  value: string;
}

export interface AutofillFillPlan {
  actions: AutofillFillAction[];
}

function byDocumentOrder(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  return left.elementNumber - right.elementNumber;
}

function candidateFields(reportFields: AutofillTriageFieldResult[]) {
  return reportFields
    .filter((field) => field.eligible && field.viewable && field.fillable)
    .sort(byDocumentOrder);
}

function pickPasswordField(fields: AutofillTriageFieldResult[]) {
  const passwordFields = fields.filter((field) => field.qualifiedAs === "password");
  return (
    passwordFields.find((field) => field.reasons.includes("autocomplete:current-password")) ??
    passwordFields[0] ??
    null
  );
}

function pickUsernameField(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null
) {
  const usernameFields = fields.filter((field) => field.qualifiedAs === "username");
  if (!usernameFields.length) {
    return null;
  }

  if (passwordField?.formOpid) {
    const sameFormUsername = usernameFields.find(
      (field) => field.formOpid === passwordField.formOpid
    );
    if (sameFormUsername) {
      return sameFormUsername;
    }
  }

  return usernameFields[0];
}

function hasBlockingUsernameFallbackReason(field: AutofillTriageFieldResult) {
  return field.reasons.some(
    (reason) => reason.startsWith("excluded:") || reason.startsWith("non-login:")
  );
}

function isSingleStepEmailCandidate(field: AutofillTriageFieldResult) {
  return (
    field.qualifiedAs === "ignored" &&
    field.viewable &&
    field.fillable &&
    field.tagName === "input" &&
    field.htmlType === "email" &&
    !hasBlockingUsernameFallbackReason(field)
  );
}

function pickSingleStepEmailUsernameField(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null
) {
  if (passwordField !== null) {
    return null;
  }

  const fallbackFields = fields.filter(isSingleStepEmailCandidate).sort(byDocumentOrder);
  return fallbackFields.length === 1 ? fallbackFields[0] : null;
}

function pickTotpFields(fields: AutofillTriageFieldResult[]) {
  return fields
    .filter((field) => field.qualifiedAs === "totp" && field.viewable && field.fillable)
    .sort(byDocumentOrder);
}

function normalizeHint(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function splitFieldHintText(field: AutofillTriageFieldResult) {
  return [
    field.htmlName,
    field.htmlId,
    field.htmlClass,
    field.autocomplete,
    field.inputMode,
    field.placeholder,
    field.title,
    field.ariaLabel,
    field.ariaDescribedBy,
    field.labelText,
    ...field.dataSetValues
  ]
    .map(normalizeHint)
    .join(",");
}

function hasSplitCodeHint(field: AutofillTriageFieldResult) {
  const fieldText = splitFieldHintText(field);
  return (
    field.qualifiedAs === "totp" ||
    field.inputMode === "numeric" ||
    field.inputMode === "decimal" ||
    fieldText.includes("digit") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp")
  );
}

function isOneCharacterField(field: AutofillTriageFieldResult) {
  return field.viewable && field.fillable && field.maxLength === 1 && hasSplitCodeHint(field);
}

function splitScopeMatches(
  seed: AutofillTriageFieldResult,
  candidate: AutofillTriageFieldResult
) {
  if (seed.formOpid !== undefined) {
    return candidate.formOpid === seed.formOpid;
  }

  if (seed.containerOpid !== undefined) {
    return candidate.formOpid === undefined && candidate.containerOpid === seed.containerOpid;
  }

  return candidate.formOpid === undefined && candidate.containerOpid === undefined;
}

function pickContiguousOneCharacterFields(
  fields: AutofillTriageFieldResult[],
  seed: AutofillTriageFieldResult,
  valueLength: number
) {
  const sortedFields = [...fields].sort(byDocumentOrder);
  const seedIndex = sortedFields.findIndex((field) => field.opid === seed.opid);
  if (seedIndex < 0) {
    return [];
  }

  let startIndex = seedIndex;
  while (
    startIndex > 0 &&
    isOneCharacterField(sortedFields[startIndex - 1]) &&
    splitScopeMatches(seed, sortedFields[startIndex - 1])
  ) {
    startIndex -= 1;
  }

  let endIndex = seedIndex;
  while (
    endIndex + 1 < sortedFields.length &&
    isOneCharacterField(sortedFields[endIndex + 1]) &&
    splitScopeMatches(seed, sortedFields[endIndex + 1])
  ) {
    endIndex += 1;
  }

  const splitFields = sortedFields.slice(startIndex, endIndex + 1);
  return splitFields.length === valueLength ? splitFields : [];
}

function pickSplitTotpFields(
  fields: AutofillTriageFieldResult[],
  totpFields: AutofillTriageFieldResult[],
  valueLength: number
) {
  for (const seed of totpFields.filter(isOneCharacterField)) {
    const splitFields = pickContiguousOneCharacterFields(fields, seed, valueLength);
    if (splitFields.length === valueLength) {
      return splitFields;
    }
  }

  return [];
}

function createTotpActions(
  fields: AutofillTriageFieldResult[],
  value: string
): AutofillFillAction[] {
  const totpFields = pickTotpFields(fields);
  if (!totpFields.length) {
    return [];
  }

  const trimmedValue = value.trim();
  const splitFields = pickSplitTotpFields(fields, totpFields, trimmedValue.length);

  if (splitFields.length > 1) {
    return splitFields.map((field, index) => ({
      fieldOpid: field.opid,
      elementNumber: field.elementNumber,
      fieldType: "totp",
      value: trimmedValue[index] ?? ""
    }));
  }

  if (totpFields.length === 1) {
    const field = totpFields[0];
    if (isOneCharacterField(field)) {
      return [];
    }
    return [
      {
        fieldOpid: field.opid,
        elementNumber: field.elementNumber,
        fieldType: field.qualifiedAs,
        value: trimmedValue
      }
    ];
  }

  return [];
}

export function createLoginFillPlan(
  snapshot: AutofillPageSnapshot,
  payload: LoginFillPayload
): AutofillFillPlan {
  const report = triageAutofillPage(snapshot);
  const fields = candidateFields(report.fields);
  const passwordField = typeof payload.password === "string" ? pickPasswordField(fields) : null;
  const usernameField =
    typeof payload.username === "string"
      ? pickUsernameField(fields, passwordField) ??
        (typeof payload.password === "string"
          ? pickSingleStepEmailUsernameField(report.fields, passwordField)
          : null)
      : null;
  const actions: AutofillFillAction[] = [];

  if (usernameField && typeof payload.username === "string") {
    actions.push({
      fieldOpid: usernameField.opid,
      elementNumber: usernameField.elementNumber,
      fieldType: usernameField.qualifiedAs === "ignored" ? "username" : usernameField.qualifiedAs,
      value: payload.username
    });
  }

  if (passwordField && typeof payload.password === "string") {
    actions.push({
      fieldOpid: passwordField.opid,
      elementNumber: passwordField.elementNumber,
      fieldType: passwordField.qualifiedAs,
      value: payload.password
    });
  }

  if (typeof payload.totp === "string") {
    actions.push(...createTotpActions(report.fields, payload.totp));
  }

  return { actions };
}
