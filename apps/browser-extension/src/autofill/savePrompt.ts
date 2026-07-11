import {
  collectAutofillPageSnapshot,
  physicalFieldForSnapshot,
  TEXT_ENCODER
} from "./collectPageFields";
import type { PendingAutofillSubmission } from "./pendingSubmission";
import type { AutofillSiteRule } from "./siteRules";
import { fieldScopeMatches } from "./scope";
import { triageAutofillPage } from "./triage";
import type { AutofillFieldQualification, AutofillTriageFieldResult } from "./types";

const MAX_CAPTURE_FIELD_BYTES = 1_048_576;
const MAX_CAPTURE_CONFIRMATION_FIELDS = 16;
const MAX_CAPTURE_CONFIRMATION_BYTES = 4 * MAX_CAPTURE_FIELD_BYTES;
let captureBuffer: Uint8Array | undefined;
const CURRENT_PASSWORD_AUTOCOMPLETE_REASON = "autocomplete:current-password";

export interface CollectAutofillSubmissionOptions {
  srs?: AutofillSiteRule[];
  ils?: boolean | "with-username";
}

function normalizeHint(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function captureHintText(field: AutofillTriageFieldResult) {
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
  ]
    .map(normalizeHint)
    .join(",");
}

function hasPasswordResetContext(fields: AutofillTriageFieldResult[]) {
  const contextText = fields
    .flatMap((field) => [
      captureHintText(field),
      field.fc?.hi,
      field.fc?.hn,
      field.fc?.hc,
      field.fc?.ha,
      field.fc?.al,
      ...((field.fc?.ht ?? []) as string[])
    ])
    .map(normalizeHint)
    .join(",");
  return /(forgot|reset|change|update)password|passwordreset/.test(
    contextText
  );
}

function isCaptureUsernameField(field: AutofillTriageFieldResult) {
  if (field.d || field.tg !== "input") {
    return false;
  }

  const htmlType = field.hy ?? "text";
  const siteRuleUsername = hasSiteRuleType(field, "username");
  const supportedType = /^(email|number|tel|text|url)$/.test(htmlType);
  if (siteRuleUsername) {
    return supportedType || htmlType === "hidden";
  }
  if (!supportedType || !field.vw) {
    return false;
  }
  if (
    !field.fl &&
    (!field.fr.length ||
      field.fr.some((reason) => reason !== "not-fillable:readonly"))
  ) {
    return false;
  }
  if (/(^| )(username|email)( |$)/.test(field.au ?? "")) {
    return true;
  }

  const fieldText = captureHintText(field);
  return (
    field.q === "username" ||
    field.hy === "email" ||
    /username|userid|email|login/.test(fieldText)
  );
}

function isCaptureNewPasswordField(field: AutofillTriageFieldResult) {
  if (field.d || field.tg !== "input" || !field.vw || !field.fl) {
    return false;
  }

  if (/(^| )new-password( |$)/.test(field.au ?? "")) {
    return true;
  }

  const fieldText = captureHintText(field);
  return (
    field.q === "newPassword" ||
    field.q === "confirmation" ||
    (field.hy === "password" &&
      /(new|create|confirm)password/.test(fieldText))
  );
}

function isCaptureCurrentPasswordField(field: AutofillTriageFieldResult) {
  return /^(password|currentPassword)$/.test(field.q);
}

function fieldValue(
  elements: Element[],
  field: AutofillTriageFieldResult | null | undefined
) {
  if (!field) {
    return "";
  }
  return (
    elements[field.n] as
      | HTMLInputElement
      | HTMLSelectElement
      | HTMLTextAreaElement
      | undefined
  )?.value ?? "";
}

function captureValueBytes(value: string, limit = MAX_CAPTURE_FIELD_BYTES) {
  if (value.length > limit) {
    return ++limit;
  }
  const encoded = TEXT_ENCODER.encodeInto(
    value,
    (captureBuffer ??= new Uint8Array(MAX_CAPTURE_FIELD_BYTES + 1)).subarray(
      0,
      ++limit
    )
  );
  return encoded.read < value.length ? limit : encoded.written;
}

function hasSiteRuleType(
  field: AutofillTriageFieldResult,
  fieldType: AutofillFieldQualification
) {
  return field.rt.includes(fieldType);
}

function pickUsernameValue(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null,
  elements: Element[]
) {
  const scoped = fields.filter(
    (field) =>
      isCaptureUsernameField(field) &&
      (!passwordField || fieldScopeMatches(field, passwordField))
  );
  const ruled = scoped.filter((field) => hasSiteRuleType(field, "username"));
  const candidates = ruled.length ? ruled : scoped;
  let selected = "";
  let priority = 4;
  for (const field of candidates) {
    const rawValue = fieldValue(elements, field);
    if (captureValueBytes(rawValue) > MAX_CAPTURE_FIELD_BYTES) {
      return null;
    }
    const value = rawValue.trim();
    const nextPriority = field.vw ? (value === "" ? 1 : 0) : value === "" ? 3 : 2;
    if (nextPriority < priority) {
      priority = nextPriority;
      selected = value;
    }
  }
  return selected;
}

function confirmedNewPasswordValue(
  fields: AutofillTriageFieldResult[],
  elements: Element[],
  passwordField: AutofillTriageFieldResult
) {
  if (fields.length > MAX_CAPTURE_CONFIRMATION_FIELDS) {
    return null;
  }
  const password = fieldValue(elements, passwordField);
  if (password === "") {
    return "";
  }
  const passwordBytes = captureValueBytes(password);
  if (passwordBytes > MAX_CAPTURE_FIELD_BYTES) {
    return null;
  }
  let bytes = passwordBytes;
  for (const field of fields) {
    if (field === passwordField) {
      continue;
    }
    const value = fieldValue(elements, field);
    const remaining = MAX_CAPTURE_CONFIRMATION_BYTES - bytes;
    const limit = Math.min(MAX_CAPTURE_FIELD_BYTES, remaining);
    const valueBytes = captureValueBytes(value, limit);
    if (valueBytes > limit || value !== password) {
      return null;
    }
    bytes += valueBytes;
  }
  return password;
}

function pickOrdinaryLoginPasswordField(fields: AutofillTriageFieldResult[]) {
  let priority = 3;
  let candidates: AutofillTriageFieldResult[] = [];
  for (const field of fields) {
    if (!isCaptureCurrentPasswordField(field)) {
      continue;
    }
    const fieldPriority =
      hasSiteRuleType(field, "password") ||
      hasSiteRuleType(field, "currentPassword")
        ? 0
        : field.why.includes(CURRENT_PASSWORD_AUTOCOMPLETE_REASON)
          ? 1
          : 2;
    if (fieldPriority > priority) {
      continue;
    }
    if (fieldPriority < priority) {
      priority = fieldPriority;
      candidates = [];
    }
    candidates.push(field);
  }
  return candidates.length === 1 ? candidates[0] : null;
}

export function collectAutofillSubmission(
  documentRef: Document = document,
  submittedForm?: HTMLFormElement,
  options: CollectAutofillSubmissionOptions = {}
): PendingAutofillSubmission | null {
  const snapshot = collectAutofillPageSnapshot(documentRef, {
    srs: options.srs
  });
  if (snapshot.sr?.d) {
    return null;
  }
  const report = triageAutofillPage(snapshot);
  const elements = snapshot.f.map(
    (field) => physicalFieldForSnapshot(snapshot, field.o)!
  );
  const submittedFormOpid =
    submittedForm === undefined
      ? undefined
      : snapshot.f.find(
          (_field, index) =>
            (elements[index] as HTMLInputElement).form === submittedForm
        )?.fo;
  if (submittedForm !== undefined && submittedFormOpid === undefined) {
    return null;
  }
  const fields = report.f.filter(
    (field) =>
      field.el &&
      field.vw &&
      field.fl &&
      (submittedFormOpid === undefined || field.fo === submittedFormOpid)
  );
  const fieldsForUsername = report.f.filter(
    (field) =>
      ((field.el &&
        field.vw &&
        (field.fl || field.q === "username")) ||
        isCaptureUsernameField(field) ||
        isCaptureNewPasswordField(field)) &&
      (submittedFormOpid === undefined || field.fo === submittedFormOpid)
  );
  const submittedAt = Date.now();
  const url = documentRef.location.href;

  if (
    new Set(
      fieldsForUsername
        .filter(
          (field) =>
            isCaptureCurrentPasswordField(field) ||
            isCaptureNewPasswordField(field)
        )
        .map((field) => field.so)
    ).size > 1
  ) {
    return null;
  }

  const newPasswordFields = fieldsForUsername.filter(isCaptureNewPasswordField);
  const newPasswordField =
    newPasswordFields.find((field) => hasSiteRuleType(field, "newPassword")) ??
    newPasswordFields.find((field) => field.q === "newPassword") ??
    newPasswordFields[0];
  if (newPasswordField) {
    const scopedFields = fieldsForUsername.filter((field) =>
      fieldScopeMatches(field, newPasswordField)
    );
    const currentPasswordField =
      scopedFields.find(
        (field) =>
          isCaptureCurrentPasswordField(field) &&
          hasSiteRuleType(field, "currentPassword")
      ) ??
      scopedFields.find(
        (field) =>
          isCaptureCurrentPasswordField(field) &&
          field.why.includes(CURRENT_PASSWORD_AUTOCOMPLETE_REASON)
      ) ??
      scopedFields.find(isCaptureCurrentPasswordField) ??
      null;
    const password = fieldValue(elements, currentPasswordField);
    if (captureValueBytes(password) > MAX_CAPTURE_FIELD_BYTES) {
      return null;
    }
    const newPassword = confirmedNewPasswordValue(
      newPasswordFields,
      elements,
      newPasswordField
    );
    if (newPassword === null) {
      return null;
    }
    if (currentPasswordField && password !== "" && newPassword !== "") {
      const username = pickUsernameValue(
        fieldsForUsername,
        currentPasswordField,
        elements
      );
      if (username === null) {
        return null;
      }
      return {
        url,
        username,
        password,
        newPassword,
        submittedAt
      };
    }
    if (!currentPasswordField && newPassword !== "") {
      const registrationFields = fieldsForUsername.filter(
        (field) => field.fo === newPasswordField.fo
      );
      const username = pickUsernameValue(
        fieldsForUsername,
        newPasswordField,
        elements
      );
      if (username === null) {
        return null;
      }
      return {
        url,
        username,
        password: newPassword,
        ...(hasPasswordResetContext(registrationFields)
          ? {}
          : { saveOnly: true }),
        submittedAt
      };
    }
  }

  const passwordField = pickOrdinaryLoginPasswordField(fields);
  const password = fieldValue(elements, passwordField);
  if (
    password === "" ||
    options.ils === false ||
    captureValueBytes(password) > MAX_CAPTURE_FIELD_BYTES
  ) {
    return null;
  }
  const username = pickUsernameValue(fieldsForUsername, passwordField, elements);
  if (username === null) {
    return null;
  }
  if (options.ils === "with-username" && username === "") {
    return null;
  }

  return {
    url,
    username,
    password,
    submittedAt
  };
}
