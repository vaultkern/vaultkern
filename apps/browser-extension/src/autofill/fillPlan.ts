import { triageAutofillPage } from "./triage";
import type {
  AutofillPageSnapshot,
  AutofillTriageFieldResult,
  AutofillFieldQualification
} from "./types";

export interface LoginFillPayload {
  username?: string;
  password?: string;
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
        pickSingleStepEmailUsernameField(report.fields, passwordField)
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

  return { actions };
}
