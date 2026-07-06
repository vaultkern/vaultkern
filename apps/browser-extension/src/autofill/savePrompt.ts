import { collectAutofillPageSnapshot } from "./collectPageFields";
import type { PendingAutofillSubmission } from "./pendingSubmission";
import { triageAutofillPage } from "./triage";
import type { AutofillTriageFieldResult } from "./types";

function byDocumentOrder(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  return left.elementNumber - right.elementNumber;
}

function candidateFields(fields: AutofillTriageFieldResult[]) {
  return fields
    .filter((field) => field.eligible && field.viewable && field.fillable)
    .sort(byDocumentOrder);
}

function isWritableElement(
  element: Element | undefined
): element is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  return (
    element instanceof HTMLInputElement ||
    element instanceof HTMLSelectElement ||
    element instanceof HTMLTextAreaElement
  );
}

function fieldValue(
  elements: Element[],
  field: AutofillTriageFieldResult | null | undefined,
  options: { trim?: boolean } = {}
) {
  if (!field) {
    return "";
  }
  const element = elements[field.elementNumber];
  const value = isWritableElement(element) ? element.value : "";
  return options.trim === false ? value : value.trim();
}

function pickUsernameField(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null
) {
  const usernameFields = fields.filter((field) => field.qualifiedAs === "username");
  if (passwordField?.formOpid) {
    const sameFormUsername = usernameFields.find(
      (field) => field.formOpid === passwordField.formOpid
    );
    if (sameFormUsername) {
      return sameFormUsername;
    }
  }
  return usernameFields[0] ?? null;
}

function pickPasswordChangeFields(fields: AutofillTriageFieldResult[]) {
  const newPasswordField = fields.find((field) => field.qualifiedAs === "newPassword");
  if (!newPasswordField) {
    return null;
  }
  const currentPasswordField =
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        field.formOpid === newPasswordField.formOpid &&
        field.reasons.includes("autocomplete:current-password")
    ) ??
    fields.find(
      (field) => field.qualifiedAs === "password" && field.formOpid === newPasswordField.formOpid
    ) ??
    null;
  if (!currentPasswordField) {
    return null;
  }
  return { currentPasswordField, newPasswordField };
}

function pickRegistrationPasswordField(fields: AutofillTriageFieldResult[]) {
  const newPasswordField = fields.find((field) => field.qualifiedAs === "newPassword");
  if (!newPasswordField) {
    return null;
  }
  const formFields = fields.filter((field) => field.formOpid === newPasswordField.formOpid);
  const hasCurrentPasswordField = formFields.some((field) => field.qualifiedAs === "password");
  return hasCurrentPasswordField ? null : newPasswordField;
}

export function collectAutofillSubmission(
  documentRef: Document = document,
  submittedForm?: HTMLFormElement
): PendingAutofillSubmission | null {
  const snapshot = collectAutofillPageSnapshot(documentRef);
  const report = triageAutofillPage(snapshot);
  const forms = Array.from(documentRef.querySelectorAll("form"));
  const submittedFormOpid =
    submittedForm === undefined
      ? undefined
      : snapshot.forms.find((_form, index) => forms[index] === submittedForm)?.opid;
  if (submittedForm !== undefined && submittedFormOpid === undefined) {
    return null;
  }
  const fields = candidateFields(report.fields).filter(
    (field) =>
      submittedFormOpid === undefined || field.formOpid === submittedFormOpid
  );
  const elements = Array.from(documentRef.querySelectorAll("input, select, textarea"));
  const submittedAt = Date.now();
  const url = documentRef.location.href;

  const passwordChangeFields = pickPasswordChangeFields(fields);
  if (passwordChangeFields) {
    const password = fieldValue(elements, passwordChangeFields.currentPasswordField, {
      trim: false
    });
    const newPassword = fieldValue(elements, passwordChangeFields.newPasswordField, {
      trim: false
    });
    if (password !== "" && newPassword !== "") {
      const username = fieldValue(
        elements,
        pickUsernameField(fields, passwordChangeFields.currentPasswordField)
      );
      return {
        url,
        username,
        password,
        newPassword,
        submittedAt
      };
    }
  }

  const registrationPasswordField = pickRegistrationPasswordField(fields);
  if (registrationPasswordField) {
    const password = fieldValue(elements, registrationPasswordField, { trim: false });
    const username = fieldValue(
      elements,
      pickUsernameField(fields, registrationPasswordField)
    );

    if (password !== "") {
      return {
        url,
        username,
        password,
        submittedAt
      };
    }
  }

  const passwordField =
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        field.reasons.includes("autocomplete:current-password")
    ) ??
    fields.find((field) => field.qualifiedAs === "password") ??
    null;
  const password = fieldValue(elements, passwordField, { trim: false });
  const username = fieldValue(elements, pickUsernameField(fields, passwordField));

  if (password === "") {
    return null;
  }

  return {
    url,
    username,
    password,
    submittedAt
  };
}
