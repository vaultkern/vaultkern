import { resolveAutofillIntent } from "./intent";
import { credentialScopeKey, fieldScopeMatches } from "./scope";
import { triageAutofillPage } from "./triage";
import type {
  AutofillPageSnapshot,
  AutofillTriageFieldResult,
  AutofillFieldQualification
} from "./types";

export interface LoginFillPayload {
  username?: string;
  password?: string;
  newPassword?: string;
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

function isLoginPasswordRole(field: AutofillTriageFieldResult) {
  return field.qualifiedAs === "password" || field.qualifiedAs === "currentPassword";
}

function focusedLoginSegmentFields(fields: AutofillTriageFieldResult[]) {
  const sortedFields = [...fields].sort(byDocumentOrder);
  const focusedIndex = sortedFields.findIndex(
    (field) => field.focused && (field.qualifiedAs === "username" || isLoginPasswordRole(field))
  );
  if (focusedIndex < 0) {
    return fields;
  }

  let start = focusedIndex;
  let end = focusedIndex;
  const focusedField = sortedFields[focusedIndex];
  if (isLoginPasswordRole(focusedField)) {
    for (let index = focusedIndex - 1; index >= 0; index -= 1) {
      const field = sortedFields[index];
      if (field.qualifiedAs === "username") {
        start = index;
        break;
      }
      if (isLoginPasswordRole(field)) {
        break;
      }
    }
    for (let index = focusedIndex + 1; index < sortedFields.length; index += 1) {
      const field = sortedFields[index];
      if (field.qualifiedAs === "totp") {
        end = index;
        continue;
      }
      break;
    }
  } else {
    let sawPassword = false;
    for (let index = focusedIndex + 1; index < sortedFields.length; index += 1) {
      const field = sortedFields[index];
      if (field.qualifiedAs === "username") {
        break;
      }
      if (isLoginPasswordRole(field)) {
        end = index;
        sawPassword = true;
        continue;
      }
      if (field.qualifiedAs === "totp" && sawPassword) {
        end = index;
        continue;
      }
      break;
    }
  }

  const segmentFields = sortedFields.slice(start, end + 1);
  const hasUsername = segmentFields.some((field) => field.qualifiedAs === "username");
  const hasPassword = segmentFields.some(isLoginPasswordRole);
  return hasUsername && hasPassword ? segmentFields : fields;
}

function siteRuleFields(reportFields: AutofillTriageFieldResult[]) {
  return reportFields
    .filter((field) => field.viewable && field.fillable && field.siteRuleTypes.length > 0)
    .sort(byDocumentOrder);
}

function viewableSiteRuleFields(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return reportFields
    .filter((field) => field.viewable && !field.disabled && field.siteRuleTypes.includes(fieldType))
    .sort(byDocumentOrder);
}

function firstViewableSiteRuleField(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return viewableSiteRuleFields(reportFields, fieldType)[0] ?? null;
}

function firstFillableSiteRuleField(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return (
    siteRuleFields(reportFields).find((field) => field.siteRuleTypes.includes(fieldType)) ??
    null
  );
}

function actionForSiteRuleField(
  field: AutofillTriageFieldResult,
  payload: LoginFillPayload,
  skippedFieldTypes: ReadonlySet<AutofillFieldQualification> = new Set()
): AutofillFillAction | null {
  for (const fieldType of field.siteRuleTypes) {
    if (skippedFieldTypes.has(fieldType)) {
      continue;
    }

    const value =
      fieldType === "username"
        ? payload.username
        : fieldType === "password" || fieldType === "currentPassword"
          ? payload.password
          : fieldType === "newPassword"
            ? payload.newPassword
            : fieldType === "totp"
              ? payload.totp
              : undefined;

    if (typeof value === "string") {
      return {
        fieldOpid: field.opid,
        elementNumber: field.elementNumber,
        fieldType,
        value
      };
    }
  }

  return null;
}

function createSplitSiteRuleTotpActions(
  fields: AutofillTriageFieldResult[],
  value: string
) {
  const totpFields = fields
    .filter((field) => field.siteRuleTypes.includes("totp"))
    .sort(byDocumentOrder);
  const trimmedValue = value.trim();
  const splitFields = pickSplitTotpFields(fields, totpFields, trimmedValue.length);

  if (splitFields.length <= 1) {
    return [];
  }

  return splitFields.map((field, index) => ({
    fieldOpid: field.opid,
    elementNumber: field.elementNumber,
    fieldType: "totp" as const,
    value: trimmedValue[index] ?? ""
  }));
}

function credentialScopeBucket(field: AutofillTriageFieldResult) {
  return credentialScopeKey(field) ?? "root-run:0";
}

function siteRuleScopesForFieldType(
  fields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return new Set(
    fields
      .filter((field) => field.siteRuleTypes.includes(fieldType))
      .map(credentialScopeBucket)
  );
}

function siteRuleScopesForAnyFieldType(
  fields: AutofillTriageFieldResult[],
  fieldTypes: AutofillFieldQualification[]
) {
  return new Set(
    fields
      .filter((field) =>
        field.siteRuleTypes.some((fieldType) => fieldTypes.includes(fieldType))
      )
      .map(credentialScopeBucket)
  );
}

function viewableSiteRuleFieldSpansMultipleScopes(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return siteRuleScopesForFieldType(
    viewableSiteRuleFields(reportFields, fieldType),
    fieldType
  ).size > 1;
}

function fillableSiteRuleFieldSpansMultipleScopes(
  reportFields: AutofillTriageFieldResult[],
  fieldTypes: AutofillFieldQualification[]
) {
  return siteRuleScopesForAnyFieldType(siteRuleFields(reportFields), fieldTypes).size > 1;
}

function createSiteRuleActions(
  reportFields: AutofillTriageFieldResult[],
  payload: LoginFillPayload
) {
  const fields = siteRuleFields(reportFields);
  const usedFields = new Set<string>();
  const skippedFieldTypes = new Set<AutofillFieldQualification>();
  const actions: AutofillFillAction[] = [];
  const currentPasswordRuleFields = fields.filter((field) =>
    field.siteRuleTypes.some(
      (fieldType) => fieldType === "password" || fieldType === "currentPassword"
    )
  );
  if (currentPasswordRuleFields.length > 1) {
    skippedFieldTypes.add("password");
    skippedFieldTypes.add("currentPassword");
  }
  if (siteRuleScopesForFieldType(fields, "username").size > 1) {
    skippedFieldTypes.add("username");
  }
  if (siteRuleScopesForFieldType(fields, "newPassword").size > 1) {
    skippedFieldTypes.add("newPassword");
  }

  if (typeof payload.totp === "string") {
    const totpFields = fields.filter((field) => field.siteRuleTypes.includes("totp"));
    const ambiguousTotpScopes = siteRuleScopesForFieldType(fields, "totp").size > 1;
    if (!ambiguousTotpScopes) {
      for (const action of createSplitSiteRuleTotpActions(fields, payload.totp)) {
        usedFields.add(action.fieldOpid);
        actions.push(action);
      }
    }
    if (ambiguousTotpScopes || totpFields.length > 1) {
      skippedFieldTypes.add("totp");
    }
  }

  for (const field of fields) {
    if (usedFields.has(field.opid)) {
      continue;
    }
    const action = actionForSiteRuleField(field, payload, skippedFieldTypes);
    if (action) {
      usedFields.add(field.opid);
      actions.push(action);
    }
  }

  return actions;
}

function appendFallbackActions(
  primaryActions: AutofillFillAction[],
  fallbackActions: AutofillFillAction[]
) {
  const usedFieldOpids = new Set(primaryActions.map((action) => action.fieldOpid));
  const primaryFieldTypes = new Set(primaryActions.map((action) => action.fieldType));

  for (const action of fallbackActions) {
    const repeatedFieldType = action.fieldType === "newPassword";
    if (
      usedFieldOpids.has(action.fieldOpid) ||
      (!repeatedFieldType && primaryFieldTypes.has(action.fieldType))
    ) {
      continue;
    }
    usedFieldOpids.add(action.fieldOpid);
    primaryActions.push(action);
  }
}

function preferCurrentPasswordField(fields: AutofillTriageFieldResult[]) {
  return (
    fields.find((field) => field.reasons.includes("autocomplete:current-password")) ??
    fields[0] ??
    null
  );
}

function pickFirstPasswordField(fields: AutofillTriageFieldResult[]) {
  return fields.find((field) => field.qualifiedAs === "password") ?? null;
}

function scopedCredentialFields(
  fields: AutofillTriageFieldResult[],
  field: AutofillTriageFieldResult
) {
  if (field.formOpid) {
    return fields.filter((candidate) => candidate.formOpid === field.formOpid);
  }
  if (field.containerOpid) {
    return fields.filter(
      (candidate) =>
        candidate.formOpid === undefined && candidate.containerOpid === field.containerOpid
    );
  }
  return [field];
}

function isRegistrationUsernameFallback(
  field: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  const scopedFields = scopedCredentialFields(fields, field);
  return (
    scopedFields.some((candidate) => candidate.qualifiedAs === "newPassword") &&
    !scopedFields.some((candidate) => candidate.qualifiedAs === "password")
  );
}

function pickPasswordField(
  fields: AutofillTriageFieldResult[],
  usernameField?: AutofillTriageFieldResult | null
) {
  const passwordFields = fields.filter((field) => field.qualifiedAs === "password");
  if (usernameField) {
    return preferCurrentPasswordField(
      passwordFields.filter((field) => fieldScopeMatches(field, usernameField))
    );
  }

  return preferCurrentPasswordField(passwordFields);
}

function fieldHasSiblingNewPassword(
  field: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  if (!field.formOpid) {
    return false;
  }
  return fields.some(
    (candidate) =>
      candidate.qualifiedAs === "newPassword" &&
      candidate.opid !== field.opid &&
      candidate.formOpid === field.formOpid
  );
}

function fieldHasSiblingUsername(
  field: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  return fields.some(
    (candidate) =>
      candidate.qualifiedAs === "username" &&
      candidate.opid !== field.opid &&
      fieldScopeMatches(candidate, field)
  );
}

function isUnsafeLoginPasswordField(
  passwordField: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  return (
    fieldHasSiblingNewPassword(passwordField, fields) &&
    !isCurrentPasswordField(passwordField) &&
    !fieldHasSiblingUsername(passwordField, fields)
  );
}

function isPasswordChangeCurrentPasswordField(
  passwordField: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  return fieldHasSiblingNewPassword(passwordField, fields) && isCurrentPasswordField(passwordField);
}

function pickLoginPasswordField(fields: AutofillTriageFieldResult[]) {
  const passwordField = pickPasswordField(fields);
  if (!passwordField) {
    return null;
  }

  if (isUnsafeLoginPasswordField(passwordField, fields)) {
    return null;
  }

  return passwordField;
}

function pickFirstSafeLoginPasswordField(fields: AutofillTriageFieldResult[]) {
  const safePasswordFields = fields.filter(
    (field) => field.qualifiedAs === "password" && !isUnsafeLoginPasswordField(field, fields)
  );
  return (
    safePasswordFields.find(
      (field) => !isPasswordChangeCurrentPasswordField(field, fields)
    ) ??
    safePasswordFields[0] ??
    null
  );
}

function pickUnscopedPasswordAfterUsername(
  fields: AutofillTriageFieldResult[],
  usernameField: AutofillTriageFieldResult
) {
  if (usernameField.formOpid !== undefined || usernameField.containerOpid !== undefined) {
    return null;
  }

  return (
    fields.find(
      (field) =>
        field.qualifiedAs === "password" &&
        field.elementNumber > usernameField.elementNumber &&
        field.formOpid === undefined &&
        field.containerOpid === undefined
    ) ?? null
  );
}

function fieldForAction(
  fields: AutofillTriageFieldResult[],
  action: AutofillFillAction | undefined
) {
  if (!action) {
    return null;
  }
  return fields.find((field) => field.opid === action.fieldOpid) ?? null;
}

function usernameHintScore(field: AutofillTriageFieldResult) {
  const fieldText = [
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

  let score = 0;
  if (field.reasons.includes("autocomplete:username")) {
    score += 100;
  }
  if (field.reasons.includes("autocomplete:email")) {
    score += 80;
  }
  if (field.htmlType === "email") {
    score += 20;
  }
  if (fieldText.includes("username") || fieldText.includes("email")) {
    score += 10;
  }
  if (fieldText.includes("login")) {
    score += 5;
  }
  return score;
}

function pickPreferredUsernameField(fields: AutofillTriageFieldResult[]) {
  return (
    [...fields].sort(
      (left, right) =>
        usernameHintScore(right) - usernameHintScore(left) || byDocumentOrder(left, right)
    )[0] ?? null
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

  if (passwordField) {
    if (passwordField.formOpid) {
      return pickPreferredUsernameField(
        usernameFields.filter((field) => field.formOpid === passwordField.formOpid)
      );
    }

    if (passwordField.containerOpid) {
      return pickPreferredUsernameField(
        usernameFields.filter(
          (field) =>
            field.formOpid === undefined && field.containerOpid === passwordField.containerOpid
        )
      );
    }
  }

  return pickPreferredUsernameField(
    usernameFields.filter((field) => !isRegistrationUsernameFallback(field, fields))
  );
}

function hasScopedPasswordField(
  fields: AutofillTriageFieldResult[],
  usernameField: AutofillTriageFieldResult
) {
  return fields.some(
    (field) => field.qualifiedAs === "password" && fieldScopeMatches(field, usernameField)
  );
}

function pickUsernameFirstField(fields: AutofillTriageFieldResult[]) {
  return pickPreferredUsernameField(
    fields.filter(
      (field) =>
        field.qualifiedAs === "username" &&
        !isRegistrationUsernameFallback(field, fields) &&
        !hasScopedPasswordField(fields, field)
    )
  );
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
    (field.htmlType === "email" ||
      (field.htmlType === "text" && singleStepFieldHasEmailHint(field))) &&
    !hasBlockingUsernameFallbackReason(field)
  );
}

function singleStepFieldHasEmailHint(field: AutofillTriageFieldResult) {
  const fieldText = [
    field.htmlName,
    field.htmlId,
    field.htmlClass,
    field.placeholder,
    field.title,
    field.ariaLabel,
    field.labelText,
    ...field.dataSetValues
  ]
    .map(normalizeHint)
    .join(",");
  return fieldText.includes("email");
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

function pickLoginPasswordFieldInForm(
  fields: AutofillTriageFieldResult[],
  formOpid: string | undefined
) {
  if (!formOpid) {
    return null;
  }
  return pickLoginPasswordField(fields.filter((field) => fieldIsInForm(field, formOpid)));
}

function pickLoginPasswordFieldInScope(
  fields: AutofillTriageFieldResult[],
  anchorField: AutofillTriageFieldResult | null
) {
  if (!anchorField) {
    return null;
  }
  return pickLoginPasswordField(fields.filter((field) => fieldScopeMatches(field, anchorField)));
}

function fieldIsInForm(field: AutofillTriageFieldResult, formOpid: string | undefined) {
  return field.formOpid === formOpid;
}

function fieldIsInCredentialScope(
  field: AutofillTriageFieldResult,
  scopeKey: string
) {
  if (scopeKey.startsWith("root-run:")) {
    return field.formOpid === undefined && field.containerOpid === undefined;
  }
  return credentialScopeKey(field) === scopeKey;
}

const CHANGE_PASSWORD_KEYWORDS = [
  "changepassword",
  "updatepassword",
  "resetpassword",
  "currentpassword",
  "oldpassword",
  "existingpassword"
];
const EXPLICIT_CHANGE_PASSWORD_KEYWORDS = [
  "changepassword",
  "updatepassword",
  "resetpassword",
  "forgotpassword"
];

function normalizeText(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function searchableFieldText(field: AutofillTriageFieldResult) {
  return [
    field.htmlName,
    field.htmlId,
    field.htmlClass,
    field.autocomplete,
    field.placeholder,
    field.title,
    field.ariaLabel,
    field.labelText,
    ...((field.containerText ?? []) as string[]),
    field.formContext?.htmlId,
    field.formContext?.htmlName,
    field.formContext?.htmlClass,
    field.formContext?.htmlAction,
    field.formContext?.ariaLabel,
    ...((field.formContext?.headingText ?? []) as string[])
  ]
    .map(normalizeText)
    .join(",");
}

function formSearchText(formFields: AutofillTriageFieldResult[]) {
  return formFields.map(searchableFieldText).join(",");
}

function isCurrentPasswordField(field: AutofillTriageFieldResult) {
  const searchableText = searchableFieldText(field);
  return (
    field.siteRuleTypes.includes("currentPassword") ||
    field.reasons.includes("autocomplete:current-password") ||
    field.reasons.some((reason) => reason.endsWith(":currentPassword")) ||
    searchableText.includes("currentpassword") ||
    searchableText.includes("oldpassword") ||
    searchableText.includes("existingpassword")
  );
}

function formHasResetPasswordContext(formFields: AutofillTriageFieldResult[]) {
  const searchableText = formSearchText(formFields);
  return (
    searchableText.includes("resetpassword") ||
    searchableText.includes("changepassword") ||
    searchableText.includes("updatepassword") ||
    searchableText.includes("forgotpassword")
  );
}

function formHasRegistrationContext(formFields: AutofillTriageFieldResult[]) {
  const searchableText = formSearchText(formFields);
  return (
    searchableText.includes("register") ||
    searchableText.includes("signup") ||
    searchableText.includes("createaccount") ||
    searchableText.includes("createyouraccount") ||
    searchableText.includes("createanaccount") ||
    searchableText.includes("createpassword") ||
    searchableText.includes("join")
  );
}

function formHasChangePasswordContext(formFields: AutofillTriageFieldResult[]) {
  const searchableText = formSearchText(formFields);
  return CHANGE_PASSWORD_KEYWORDS.some((keyword) => searchableText.includes(keyword));
}

function formHasExplicitChangePasswordContext(formFields: AutofillTriageFieldResult[]) {
  const searchableText = formSearchText(formFields);
  return EXPLICIT_CHANGE_PASSWORD_KEYWORDS.some((keyword) => searchableText.includes(keyword));
}

function pickCurrentPasswordField(formFields: AutofillTriageFieldResult[]) {
  const passwordFields = formFields.filter((field) => field.qualifiedAs === "password");
  return passwordFields.find(isCurrentPasswordField) ?? null;
}

function scopeQualifiesForPasswordChange(
  fields: AutofillTriageFieldResult[],
  scopeKey: string
) {
  const formFields = fields.filter((field) => fieldIsInCredentialScope(field, scopeKey));
  const currentPasswordField = pickCurrentPasswordField(formFields);
  const formNewPasswordFields = formFields.filter(
    (field) => field.qualifiedAs === "newPassword"
  );
  if (!currentPasswordField || !formNewPasswordFields.length) {
    return false;
  }
  if (
    scopeKey.startsWith("container:") &&
    formFields.filter(
      (field) => field.qualifiedAs === "password" || field.qualifiedAs === "newPassword"
    ).length < 3
  ) {
    return false;
  }

  const hasAutocompleteRoles =
    (currentPasswordField.reasons.includes("autocomplete:current-password") ||
      currentPasswordField.siteRuleTypes.includes("currentPassword")) &&
    formNewPasswordFields.some((field) => field.reasons.includes("autocomplete:new-password"));
  if (scopeKey.startsWith("container:")) {
    return formHasExplicitChangePasswordContext(formFields);
  }
  return hasAutocompleteRoles || formHasChangePasswordContext(formFields);
}

function scopeHasCredentialCandidate(
  fields: AutofillTriageFieldResult[],
  scopeKey: string
) {
  return fields.some(
    (field) =>
      fieldIsInCredentialScope(field, scopeKey) &&
      (field.qualifiedAs === "username" ||
        field.qualifiedAs === "password" ||
        field.qualifiedAs === "newPassword")
  );
}

function pickPasswordChangeScopeKey(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[]
) {
  const newPasswordFields = fields.filter(
    (field) => field.qualifiedAs === "newPassword" && credentialScopeKey(field) !== null
  );
  const scopeKeys = new Set(
    newPasswordFields
      .map(credentialScopeKey)
      .filter((scopeKey): scopeKey is string => scopeKey !== null)
  );

  const focusedField = allFields.find((field) => field.focused && credentialScopeKey(field));
  const focusedScopeKey = focusedField ? credentialScopeKey(focusedField) : null;
  if (focusedScopeKey) {
    if (scopeKeys.has(focusedScopeKey)) {
      return scopeQualifiesForPasswordChange(fields, focusedScopeKey)
        ? focusedScopeKey
        : null;
    }
    if (scopeHasCredentialCandidate(fields, focusedScopeKey)) {
      return null;
    }
  }

  for (const scopeKey of scopeKeys) {
    if (scopeQualifiesForPasswordChange(fields, scopeKey)) {
      return scopeKey;
    }
  }

  return null;
}

function createPasswordChangeActions(
  fields: AutofillTriageFieldResult[],
  scopeKey: string,
  payload: LoginFillPayload
): AutofillFillAction[] {
  const formFields = fields.filter((field) => fieldIsInCredentialScope(field, scopeKey));
  const currentPasswordField = pickCurrentPasswordField(formFields);
  const actions: AutofillFillAction[] = [];

  if (typeof payload.username === "string") {
    const usernameField = formFields.find((field) => field.qualifiedAs === "username");
    if (usernameField) {
      actions.push({
        fieldOpid: usernameField.opid,
        elementNumber: usernameField.elementNumber,
        fieldType: usernameField.qualifiedAs,
        value: payload.username
      });
    }
  }

  if (currentPasswordField && typeof payload.password === "string") {
    actions.push({
      fieldOpid: currentPasswordField.opid,
      elementNumber: currentPasswordField.elementNumber,
      fieldType: currentPasswordField.qualifiedAs,
      value: payload.password
    });
  }

  if (typeof payload.newPassword === "string") {
    for (const passwordField of formFields.filter((field) => field.qualifiedAs === "newPassword")) {
      actions.push({
        fieldOpid: passwordField.opid,
        elementNumber: passwordField.elementNumber,
        fieldType: passwordField.qualifiedAs,
        value: payload.newPassword
      });
    }
  }

  return actions;
}

function hasCredentialSignal(field: AutofillTriageFieldResult) {
  const searchableText = searchableFieldText(field);
  const autocomplete = field.autocomplete ?? "";
  return (
    field.htmlType === "email" ||
    field.htmlType === "password" ||
    autocomplete.includes("username") ||
    autocomplete.includes("email") ||
    autocomplete.includes("current-password") ||
    autocomplete.includes("new-password") ||
    searchableText.includes("email") ||
    searchableText.includes("username") ||
    searchableText.includes("login") ||
    searchableText.includes("password")
  );
}

function fieldsInCredentialScope(fields: AutofillTriageFieldResult[], scopeKey: string) {
  return fields.filter((field) => fieldIsInCredentialScope(field, scopeKey));
}

function scopeHasCurrentPassword(fields: AutofillTriageFieldResult[], scopeKey: string) {
  return fields.some(
    (field) =>
      fieldIsInCredentialScope(field, scopeKey) &&
      field.qualifiedAs === "password" &&
      isCurrentPasswordField(field)
  );
}

function scopeHasCredentialSignal(fields: AutofillTriageFieldResult[], scopeKey: string) {
  return fields.some((field) => fieldIsInCredentialScope(field, scopeKey) && hasCredentialSignal(field));
}

function scopeHasNewsletterExclusion(fields: AutofillTriageFieldResult[], scopeKey: string) {
  return fields.some((field) => {
    if (!fieldIsInCredentialScope(field, scopeKey)) {
      return false;
    }
    const searchableText = searchableFieldText(field);
    return (
      field.reasons.some((reason) => reason === "non-login:newsletter") ||
      ["newsletter", "subscribe", "subscription", "unsubscribe", "mailinglist"].some((keyword) =>
        searchableText.includes(keyword)
      )
    );
  });
}

function pickRegistrationScopeKey(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[],
  options: { allowSingleNewPassword?: boolean } = {}
) {
  const newPasswordFields = fields.filter(
    (field) => field.qualifiedAs === "newPassword" && credentialScopeKey(field) !== null
  );
  if (!newPasswordFields.length) {
    return null;
  }

  const focusedField = allFields.find((field) => field.focused && credentialScopeKey(field) !== null);
  const focusedScopeKey = focusedField ? credentialScopeKey(focusedField) : null;
  if (focusedScopeKey) {
    const focusedRegistrationForm = newPasswordFields.some((field) =>
      fieldIsInCredentialScope(field, focusedScopeKey)
    );
    if (focusedRegistrationForm && !scopeHasCurrentPassword(fields, focusedScopeKey)) {
      const formFields = fieldsInCredentialScope(fields, focusedScopeKey);
      if (formHasResetPasswordContext(formFields)) {
        return null;
      }
      return focusedScopeKey;
    }
    if (scopeHasCredentialCandidate(fields, focusedScopeKey)) {
      return null;
    }
    if (
      !scopeHasNewsletterExclusion(allFields, focusedScopeKey) &&
      scopeHasCredentialSignal(allFields, focusedScopeKey)
    ) {
      return null;
    }
  }

  const loginPasswordFields = fields.filter((field) => field.qualifiedAs === "password");
  if (!loginPasswordFields.length) {
    const scopeKeys = new Set(
      newPasswordFields
        .map(credentialScopeKey)
        .filter((scopeKey): scopeKey is string => scopeKey !== null)
    );
    for (const scopeKey of scopeKeys) {
      if (scopeHasCurrentPassword(fields, scopeKey)) {
        continue;
      }
      const formFields = fieldsInCredentialScope(fields, scopeKey);
      const newPasswordCount = formFields.filter(
        (field) => field.qualifiedAs === "newPassword"
      ).length;
      if (
        formHasResetPasswordContext(formFields) ||
        !formHasRegistrationContext(formFields) ||
        (newPasswordCount < 2 && options.allowSingleNewPassword !== true)
      ) {
        continue;
      }
      return scopeKey;
    }
  }

  return null;
}

function createRegistrationActions(
  fields: AutofillTriageFieldResult[],
  scopeKey: string,
  payload: LoginFillPayload
): AutofillFillAction[] {
  const formFields = fieldsInCredentialScope(fields, scopeKey);
  const actions: AutofillFillAction[] = [];

  if (typeof payload.username === "string") {
    const usernameField = formFields.find((field) => field.qualifiedAs === "username");
    if (usernameField) {
      actions.push({
        fieldOpid: usernameField.opid,
        elementNumber: usernameField.elementNumber,
        fieldType: usernameField.qualifiedAs,
        value: payload.username
      });
    }
  }

  const registrationPassword = payload.newPassword ?? payload.password;
  if (typeof registrationPassword === "string") {
    const passwordFields = scopeHasCurrentPassword(fields, scopeKey)
      ? formFields.filter((field) => field.qualifiedAs === "newPassword")
      : formFields.filter(
          (field) => field.qualifiedAs === "newPassword" || field.qualifiedAs === "password"
        );
    for (const passwordField of passwordFields) {
      actions.push({
        fieldOpid: passwordField.opid,
        elementNumber: passwordField.elementNumber,
        fieldType: passwordField.qualifiedAs,
        value: registrationPassword
      });
    }
  }

  return actions;
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

function isAnonymousOneCharacterField(field: AutofillTriageFieldResult) {
  return (
    field.viewable &&
    field.fillable &&
    field.maxLength === 1 &&
    field.htmlName === undefined &&
    field.htmlId === undefined
  );
}

function splitSequenceKey(value: string | undefined) {
  const match = (value ?? "").toLowerCase().match(/^(.*?)(\d+)$/);
  if (!match) {
    return null;
  }

  const key = match[1].replace(/[\s_-]+$/g, "");
  return key.length > 0 ? key : null;
}

function splitSequenceKeys(field: AutofillTriageFieldResult) {
  return [field.htmlName, field.htmlId]
    .map(splitSequenceKey)
    .filter((key): key is string => key !== null);
}

function splitSequenceMatches(
  seed: AutofillTriageFieldResult,
  candidate: AutofillTriageFieldResult,
  options: { allowAnonymousFallback?: boolean } = {}
) {
  const seedKeys = splitSequenceKeys(seed);
  if (!seedKeys.length) {
    return true;
  }

  const candidateKeys = splitSequenceKeys(candidate);
  if (!candidateKeys.length) {
    return options.allowAnonymousFallback === true && isAnonymousOneCharacterField(candidate);
  }
  return candidateKeys.some((key) => seedKeys.includes(key));
}

function isContiguousSplitField(
  seed: AutofillTriageFieldResult,
  candidate: AutofillTriageFieldResult
) {
  return isOneCharacterField(candidate) || isAnonymousOneCharacterField(candidate);
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

  const seedSequenceKeys = splitSequenceKeys(seed);
  let startIndex = seedIndex;
  while (
    startIndex > 0 &&
    isContiguousSplitField(seed, sortedFields[startIndex - 1]) &&
    splitScopeMatches(seed, sortedFields[startIndex - 1]) &&
    splitSequenceMatches(seed, sortedFields[startIndex - 1], {
      allowAnonymousFallback: seedSequenceKeys.length === 0
    })
  ) {
    startIndex -= 1;
  }

  let endIndex = seedIndex;
  while (
    endIndex + 1 < sortedFields.length &&
    !(
      seedSequenceKeys.length > 0 &&
      endIndex - startIndex + 1 >= valueLength &&
      isAnonymousOneCharacterField(sortedFields[endIndex + 1])
    ) &&
    isContiguousSplitField(seed, sortedFields[endIndex + 1]) &&
    splitScopeMatches(seed, sortedFields[endIndex + 1]) &&
    splitSequenceMatches(seed, sortedFields[endIndex + 1], { allowAnonymousFallback: true })
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
  if (snapshot.siteRule?.disabled) {
    return { actions: [] };
  }
  const intent = resolveAutofillIntent(report, payload);
  const intentScopeKey =
    intent.scopeKey !== undefined && !intent.scopeKey.startsWith("site-rule:")
      ? intent.scopeKey
      : null;
  const siteRuleActions = createSiteRuleActions(report.fields, payload);
  const fields = candidateFields(report.fields);
  const actions: AutofillFillAction[] = [...siteRuleActions];
  const siteRulePasswordField = fieldForAction(
    report.fields,
    siteRuleActions.find(
      (action) => action.fieldType === "password" || action.fieldType === "currentPassword"
    )
  );
  const siteRulePasswordChangeField = fieldForAction(
    report.fields,
    siteRuleActions.find(
      (action) => action.fieldType === "currentPassword" || action.fieldType === "newPassword"
    )
  );
  const ambiguousPasswordSiteRule =
    fillableSiteRuleFieldSpansMultipleScopes(report.fields, ["password", "currentPassword"]);
  const ambiguousUsernameSiteRule =
    viewableSiteRuleFieldSpansMultipleScopes(report.fields, "username");
  const ambiguousTotpSiteRule =
    viewableSiteRuleFieldSpansMultipleScopes(report.fields, "totp");
  const siteRuleUsernameField = fieldForAction(
    report.fields,
    siteRuleActions.find((action) => action.fieldType === "username")
  ) ?? (ambiguousUsernameSiteRule
    ? null
    : firstViewableSiteRuleField(report.fields, "username"));
  const siteRuleTotpField = fieldForAction(
    report.fields,
    siteRuleActions.find((action) => action.fieldType === "totp")
  ) ?? (ambiguousTotpSiteRule
    ? null
    : firstFillableSiteRuleField(report.fields, "totp"));
  const siteRulePasswordChangeScopeKey = siteRulePasswordChangeField
    ? credentialScopeKey(siteRulePasswordChangeField)
    : null;
  const siteRuleAnchorScopeKey =
    siteRulePasswordField !== null
      ? credentialScopeKey(siteRulePasswordField)
      : siteRuleUsernameField !== null
        ? credentialScopeKey(siteRuleUsernameField)
        : siteRulePasswordChangeScopeKey ??
          (siteRuleTotpField ? credentialScopeKey(siteRuleTotpField) : null);
  const intentUsesFocusedScope = intent.reasons.some((reason) =>
    reason.startsWith("focused-")
  );
  const shouldUseResolvedScope =
    siteRuleAnchorScopeKey !== null ||
    intent.kind === "login" ||
    ((intent.kind === "usernameFirst" || intent.kind === "passwordStep") &&
      intentUsesFocusedScope) ||
    (intent.kind === "totp" && intentUsesFocusedScope) ||
    intent.kind === "registration" ||
    intent.kind === "passwordChange";
  const primaryScopeKey = siteRuleAnchorScopeKey ?? intentScopeKey;
  if (
    (ambiguousPasswordSiteRule || ambiguousUsernameSiteRule || ambiguousTotpSiteRule) &&
    siteRuleAnchorScopeKey === null &&
    !intentUsesFocusedScope
  ) {
    return { actions };
  }
  const resolvedIntentFields =
    shouldUseResolvedScope && primaryScopeKey !== null
      ? fields.filter((field) => fieldIsInCredentialScope(field, primaryScopeKey))
      : fields;
  const intentFields =
    intent.kind === "login" && intentUsesFocusedScope
      ? focusedLoginSegmentFields(resolvedIntentFields)
      : resolvedIntentFields;
  const resolvedIntentAllFields =
    shouldUseResolvedScope && primaryScopeKey !== null
      ? report.fields.filter((field) => fieldIsInCredentialScope(field, primaryScopeKey))
      : report.fields;
  const intentAllFields =
    intent.kind === "login" && intentUsesFocusedScope
      ? focusedLoginSegmentFields(resolvedIntentAllFields)
      : resolvedIntentAllFields;
  const passwordChangeFields =
    siteRulePasswordChangeScopeKey !== null
      ? fields.filter((field) =>
          fieldIsInCredentialScope(field, siteRulePasswordChangeScopeKey)
        )
      : fields;
  const passwordChangeAllFields =
    siteRulePasswordChangeScopeKey !== null
      ? report.fields.filter((field) =>
          fieldIsInCredentialScope(field, siteRulePasswordChangeScopeKey)
        )
      : report.fields;
  const passwordChangeScopeKey =
    intent.kind === "passwordChange"
      ? siteRulePasswordChangeScopeKey ??
        intentScopeKey ??
        (typeof payload.password === "string" && typeof payload.newPassword === "string"
          ? pickPasswordChangeScopeKey(passwordChangeFields, passwordChangeAllFields)
          : null)
      : null;
  const registrationScopeKey =
    intent.kind === "registration"
      ? intentScopeKey ??
        (typeof payload.password === "string" || typeof payload.newPassword === "string"
          ? pickRegistrationScopeKey(fields, report.fields, {
              allowSingleNewPassword: typeof payload.newPassword === "string"
            })
          : null)
      : null;

  if (passwordChangeScopeKey !== null) {
    appendFallbackActions(
      actions,
      createPasswordChangeActions(fields, passwordChangeScopeKey, payload)
    );
    if (typeof payload.totp === "string") {
      appendFallbackActions(
        actions,
        createTotpActions(
          report.fields.filter((field) => fieldIsInCredentialScope(field, passwordChangeScopeKey)),
          payload.totp
        )
      );
    }
    return { actions };
  }

  if (registrationScopeKey !== null) {
    appendFallbackActions(
      actions,
      createRegistrationActions(fields, registrationScopeKey, payload)
    );
    if (typeof payload.totp === "string") {
      appendFallbackActions(
        actions,
        createTotpActions(
          report.fields.filter((field) => fieldIsInCredentialScope(field, registrationScopeKey)),
          payload.totp
        )
      );
    }
    return { actions };
  }

  const initialPasswordField =
    typeof payload.password === "string"
      ? siteRulePasswordField ??
        pickLoginPasswordFieldInScope(intentFields, siteRuleUsernameField) ??
        pickLoginPasswordFieldInForm(intentFields, siteRuleUsernameField?.formOpid) ??
        pickFirstSafeLoginPasswordField(intentFields)
      : null;
  const usernameField =
    typeof payload.username === "string" && siteRuleUsernameField === null
      ? pickUsernameField(intentFields, initialPasswordField) ??
        pickUsernameFirstField(intentFields) ??
        pickSingleStepEmailUsernameField(intentAllFields, null)
      : null;
  const usernameAnchor = usernameField ?? siteRuleUsernameField;
  const passwordField =
    typeof payload.password === "string"
      ? siteRulePasswordField ??
        (usernameAnchor
          ? pickLoginPasswordFieldInScope(intentFields, usernameAnchor) ??
            pickLoginPasswordFieldInForm(intentFields, usernameAnchor.formOpid) ??
            pickLoginPasswordField(
              intentFields.filter((field) => fieldScopeMatches(field, usernameAnchor))
            ) ??
            pickUnscopedPasswordAfterUsername(intentFields, usernameAnchor)
        : pickFirstSafeLoginPasswordField(intentFields)
        )
      : null;

  const fallbackActions: AutofillFillAction[] = [];
  if (usernameField && typeof payload.username === "string") {
    fallbackActions.push({
      fieldOpid: usernameField.opid,
      elementNumber: usernameField.elementNumber,
      fieldType: usernameField.qualifiedAs === "ignored" ? "username" : usernameField.qualifiedAs,
      value: payload.username
    });
  }

  if (passwordField && typeof payload.password === "string") {
    fallbackActions.push({
      fieldOpid: passwordField.opid,
      elementNumber: passwordField.elementNumber,
      fieldType: passwordField.qualifiedAs,
      value: payload.password
    });
  }

  if (typeof payload.totp === "string") {
    const totpActionFields =
      shouldUseResolvedScope && primaryScopeKey !== null ? intentAllFields : report.fields;
    fallbackActions.push(...createTotpActions(totpActionFields, payload.totp));
  }

  appendFallbackActions(actions, fallbackActions);
  return { actions };
}
