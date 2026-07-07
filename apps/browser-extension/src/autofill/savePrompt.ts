import {
  collectAutofillPageSnapshot,
  collectMatchingElements,
  FIELD_SELECTOR
} from "./collectPageFields";
import type { PendingAutofillSubmission } from "./pendingSubmission";
import type { AutofillSiteRule } from "./siteRules";
import { triageAutofillPage } from "./triage";
import type { AutofillFieldQualification, AutofillTriageFieldResult } from "./types";

export interface CollectAutofillSubmissionOptions {
  siteRules?: AutofillSiteRule[];
  includeLoginSubmissions?: boolean;
}

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

function normalizeHint(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function fieldAutocompleteTokens(field: AutofillTriageFieldResult) {
  return new Set(
    (field.autocomplete ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
  );
}

function captureHintText(field: AutofillTriageFieldResult) {
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
    .map(normalizeHint)
    .join(",");
}

function captureContextText(fields: AutofillTriageFieldResult[]) {
  return fields
    .flatMap((field) => [
      captureHintText(field),
      field.formContext?.htmlId,
      field.formContext?.htmlName,
      field.formContext?.htmlClass,
      field.formContext?.htmlAction,
      field.formContext?.ariaLabel,
      ...((field.formContext?.headingText ?? []) as string[])
    ])
    .map(normalizeHint)
    .join(",");
}

function hasPasswordResetContext(fields: AutofillTriageFieldResult[]) {
  const contextText = captureContextText(fields);
  return (
    contextText.includes("forgotpassword") ||
    contextText.includes("resetpassword") ||
    contextText.includes("passwordreset") ||
    contextText.includes("changepassword") ||
    contextText.includes("updatepassword")
  );
}

function isCaptureUsernameField(field: AutofillTriageFieldResult) {
  if (field.disabled || field.tagName !== "input") {
    return false;
  }

  const autocomplete = fieldAutocompleteTokens(field);
  if (autocomplete.has("username") || autocomplete.has("email")) {
    return true;
  }

  const fieldText = captureHintText(field);
  return (
    field.qualifiedAs === "username" ||
    field.htmlType === "email" ||
    fieldText.includes("username") ||
    fieldText.includes("userid") ||
    fieldText.includes("email") ||
    fieldText.includes("login")
  );
}

function isCaptureNewPasswordField(field: AutofillTriageFieldResult) {
  if (field.disabled || field.tagName !== "input" || !field.viewable || !field.fillable) {
    return false;
  }

  const autocomplete = fieldAutocompleteTokens(field);
  if (autocomplete.has("new-password")) {
    return true;
  }

  const fieldText = captureHintText(field);
  return (
    field.qualifiedAs === "newPassword" ||
    (field.htmlType === "password" &&
      (fieldText.includes("newpassword") ||
        fieldText.includes("createpassword") ||
        fieldText.includes("confirmpassword")))
  );
}

function captureFields(fields: AutofillTriageFieldResult[]) {
  return fields
    .filter(
      (field) =>
        (field.eligible &&
          field.viewable &&
          (field.fillable || field.qualifiedAs === "username")) ||
        isCaptureUsernameField(field) ||
        isCaptureNewPasswordField(field)
    )
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

function hasSiteRuleType(
  field: AutofillTriageFieldResult,
  fieldType: AutofillFieldQualification
) {
  return field.siteRuleTypes.includes(fieldType);
}

function pickUsernameField(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null,
  elements: Element[]
) {
  const usernameFields = fields.filter(isCaptureUsernameField);
  const preferSubmittedUsername = (candidates: AutofillTriageFieldResult[]) =>
    candidates.find((field) => field.viewable && fieldValue(elements, field) !== "") ??
    candidates.find((field) => field.viewable) ??
    candidates.find((field) => fieldValue(elements, field) !== "") ??
    candidates[0] ??
    null;

  if (passwordField?.formOpid) {
    const sameFormUsernames = usernameFields.filter(
      (field) => field.formOpid === passwordField.formOpid
    );
    const sameFormRuleUsernames = sameFormUsernames.filter((field) =>
      hasSiteRuleType(field, "username")
    );
    const sameFormUsername =
      preferSubmittedUsername(sameFormRuleUsernames) ??
      preferSubmittedUsername(sameFormUsernames);
    if (sameFormUsername) {
      return sameFormUsername;
    }
  }
  return (
    preferSubmittedUsername(usernameFields.filter((field) => hasSiteRuleType(field, "username"))) ??
    preferSubmittedUsername(usernameFields)
  );
}

function pickPasswordChangeFields(fields: AutofillTriageFieldResult[]) {
  const newPasswordField =
    fields.find(
      (field) => isCaptureNewPasswordField(field) && hasSiteRuleType(field, "newPassword")
    ) ??
    fields.find(isCaptureNewPasswordField);
  if (!newPasswordField) {
    return null;
  }
  const currentPasswordField =
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        field.formOpid === newPasswordField.formOpid &&
        hasSiteRuleType(field, "currentPassword")
    ) ??
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
  const newPasswordField =
    fields.find(
      (field) => isCaptureNewPasswordField(field) && hasSiteRuleType(field, "newPassword")
    ) ??
    fields.find(isCaptureNewPasswordField);
  if (!newPasswordField) {
    return null;
  }
  const formFields = fields.filter((field) => field.formOpid === newPasswordField.formOpid);
  const hasCurrentPasswordField = formFields.some((field) => field.qualifiedAs === "password");
  return hasCurrentPasswordField ? null : newPasswordField;
}

export function collectAutofillSubmission(
  documentRef: Document = document,
  submittedForm?: HTMLFormElement,
  options: CollectAutofillSubmissionOptions = {}
): PendingAutofillSubmission | null {
  const snapshot = collectAutofillPageSnapshot(documentRef, {
    siteRules: options.siteRules
  });
  if (snapshot.siteRule?.disabled) {
    return null;
  }
  const report = triageAutofillPage(snapshot);
  const forms = collectMatchingElements(documentRef, "form");
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
  const fieldsForUsername = captureFields(report.fields).filter(
    (field) =>
      submittedFormOpid === undefined || field.formOpid === submittedFormOpid
  );
  const elements = collectMatchingElements(documentRef, FIELD_SELECTOR);
  const submittedAt = Date.now();
  const url = documentRef.location.href;

  const passwordChangeFields = pickPasswordChangeFields(fieldsForUsername);
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
        pickUsernameField(fieldsForUsername, passwordChangeFields.currentPasswordField, elements)
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

  const registrationPasswordField = pickRegistrationPasswordField(fieldsForUsername);
  if (registrationPasswordField) {
    const registrationFields = fieldsForUsername.filter(
      (field) => field.formOpid === registrationPasswordField.formOpid
    );
    const password = fieldValue(elements, registrationPasswordField, { trim: false });
    const username = fieldValue(
      elements,
      pickUsernameField(fieldsForUsername, registrationPasswordField, elements)
    );

    if (password !== "") {
      return {
        url,
        username,
        password,
        ...(hasPasswordResetContext(registrationFields) ? {} : { saveOnly: true }),
        submittedAt
      };
    }
  }

  const passwordField =
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        (hasSiteRuleType(field, "password") || hasSiteRuleType(field, "currentPassword"))
    ) ??
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        field.reasons.includes("autocomplete:current-password")
    ) ??
    fields.find((field) => field.qualifiedAs === "password") ??
    null;
  const password = fieldValue(elements, passwordField, { trim: false });
  const username = fieldValue(elements, pickUsernameField(fieldsForUsername, passwordField, elements));

  if (password === "" || options.includeLoginSubmissions === false) {
    return null;
  }

  return {
    url,
    username,
    password,
    submittedAt
  };
}
