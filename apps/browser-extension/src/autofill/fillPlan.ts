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
    .filter((field) => field.viewable && field.siteRuleTypes.includes(fieldType))
    .sort(byDocumentOrder);
}

function firstViewableSiteRuleField(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return viewableSiteRuleFields(reportFields, fieldType)[0] ?? null;
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

function createSiteRuleActions(
  reportFields: AutofillTriageFieldResult[],
  payload: LoginFillPayload
) {
  const fields = siteRuleFields(reportFields);
  const usedFields = new Set<string>();
  const skippedFieldTypes = new Set<AutofillFieldQualification>();
  const actions: AutofillFillAction[] = [];

  if (typeof payload.totp === "string") {
    const totpFields = fields.filter((field) => field.siteRuleTypes.includes("totp"));
    for (const action of createSplitSiteRuleTotpActions(fields, payload.totp)) {
      usedFields.add(action.fieldOpid);
      actions.push(action);
    }
    if (totpFields.length > 1) {
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

function fieldScopeMatches(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  if (left.formOpid !== undefined || right.formOpid !== undefined) {
    return left.formOpid !== undefined && left.formOpid === right.formOpid;
  }

  if (left.containerOpid !== undefined || right.containerOpid !== undefined) {
    return left.containerOpid !== undefined && left.containerOpid === right.containerOpid;
  }

  return false;
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

function pickLoginPasswordField(fields: AutofillTriageFieldResult[]) {
  const passwordField = pickPasswordField(fields);
  if (!passwordField) {
    return null;
  }

  if (
    fieldHasSiblingNewPassword(passwordField, fields) &&
    !isCurrentPasswordField(passwordField) &&
    !fieldHasSiblingUsername(passwordField, fields)
  ) {
    return null;
  }

  return passwordField;
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

function pickUsernameField(
  fields: AutofillTriageFieldResult[],
  passwordField: AutofillTriageFieldResult | null
) {
  const usernameFields = fields.filter((field) => field.qualifiedAs === "username");
  if (!usernameFields.length) {
    return null;
  }

  if (passwordField) {
    const sameScopeUsername = usernameFields.find((field) =>
      fieldScopeMatches(field, passwordField)
    );
    if (sameScopeUsername) {
      return sameScopeUsername;
    }
  }

  return usernameFields.find((field) => !isRegistrationUsernameFallback(field, fields)) ?? null;
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

const CHANGE_PASSWORD_KEYWORDS = [
  "changepassword",
  "updatepassword",
  "resetpassword",
  "currentpassword",
  "oldpassword",
  "existingpassword"
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

function pickCurrentPasswordField(formFields: AutofillTriageFieldResult[]) {
  const passwordFields = formFields.filter((field) => field.qualifiedAs === "password");
  return passwordFields.find(isCurrentPasswordField) ?? null;
}

function formQualifiesForPasswordChange(
  fields: AutofillTriageFieldResult[],
  formOpid: string
) {
  const formFields = fields.filter((field) => fieldIsInForm(field, formOpid));
  const currentPasswordField = pickCurrentPasswordField(formFields);
  const formNewPasswordFields = formFields.filter(
    (field) => field.qualifiedAs === "newPassword"
  );
  if (!currentPasswordField || !formNewPasswordFields.length) {
    return false;
  }

  const hasAutocompleteRoles =
    (currentPasswordField.reasons.includes("autocomplete:current-password") ||
      currentPasswordField.siteRuleTypes.includes("currentPassword")) &&
    formNewPasswordFields.some((field) => field.reasons.includes("autocomplete:new-password"));
  return hasAutocompleteRoles || formHasChangePasswordContext(formFields);
}

function pickPasswordChangeFormOpid(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[]
) {
  const newPasswordFields = fields.filter(
    (field) => field.qualifiedAs === "newPassword" && field.formOpid !== undefined
  );
  const formOpids = new Set(newPasswordFields.map((field) => field.formOpid));

  const focusedField = allFields.find((field) => field.focused && field.formOpid !== undefined);
  if (focusedField?.formOpid) {
    if (formOpids.has(focusedField.formOpid)) {
      return formQualifiesForPasswordChange(fields, focusedField.formOpid)
        ? focusedField.formOpid
        : null;
    }
    if (formHasCredentialCandidate(fields, focusedField.formOpid)) {
      return null;
    }
  }

  for (const formOpid of formOpids) {
    if (formOpid && formQualifiesForPasswordChange(fields, formOpid)) {
      return formOpid;
    }
  }

  return null;
}

function createPasswordChangeActions(
  fields: AutofillTriageFieldResult[],
  formOpid: string | undefined,
  payload: LoginFillPayload
): AutofillFillAction[] {
  const formFields = fields.filter((field) => fieldIsInForm(field, formOpid));
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

function formHasCurrentPassword(fields: AutofillTriageFieldResult[], formOpid: string) {
  return fields.some(
    (field) =>
      fieldIsInForm(field, formOpid) &&
      field.qualifiedAs === "password" &&
      isCurrentPasswordField(field)
  );
}

function formHasCredentialCandidate(
  fields: AutofillTriageFieldResult[],
  formOpid: string
) {
  return fields.some(
    (field) =>
      fieldIsInForm(field, formOpid) &&
      (field.qualifiedAs === "username" ||
        field.qualifiedAs === "password" ||
        field.qualifiedAs === "newPassword")
  );
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

function formHasCredentialSignal(
  fields: AutofillTriageFieldResult[],
  formOpid: string
) {
  return fields.some((field) => fieldIsInForm(field, formOpid) && hasCredentialSignal(field));
}

function pickRegistrationFormOpid(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[]
) {
  const newPasswordFields = fields.filter(
    (field) => field.qualifiedAs === "newPassword" && field.formOpid !== undefined
  );
  if (!newPasswordFields.length) {
    return null;
  }

  const focusedField = allFields.find((field) => field.focused && field.formOpid !== undefined);
  if (focusedField?.formOpid) {
    const focusedRegistrationForm = newPasswordFields.some((field) =>
      fieldIsInForm(field, focusedField.formOpid)
    );
    if (focusedRegistrationForm && !formHasCurrentPassword(fields, focusedField.formOpid)) {
      const formFields = fields.filter((field) => fieldIsInForm(field, focusedField.formOpid));
      if (formHasResetPasswordContext(formFields)) {
        return null;
      }
      return focusedField.formOpid;
    }
    if (formHasCredentialCandidate(fields, focusedField.formOpid)) {
      return null;
    }
    if (formHasCredentialSignal(allFields, focusedField.formOpid)) {
      return null;
    }
  }

  const loginPasswordFields = fields.filter((field) => field.qualifiedAs === "password");
  if (!loginPasswordFields.length) {
    const formOpid = newPasswordFields[0].formOpid;
    if (!formOpid || formHasCurrentPassword(fields, formOpid)) {
      return null;
    }
    const formFields = fields.filter((field) => fieldIsInForm(field, formOpid));
    if (formHasResetPasswordContext(formFields) || !formHasRegistrationContext(formFields)) {
      return null;
    }
    return formOpid;
  }

  return null;
}

function createRegistrationActions(
  fields: AutofillTriageFieldResult[],
  formOpid: string | undefined,
  payload: LoginFillPayload
): AutofillFillAction[] {
  const formFields = fields.filter((field) => fieldIsInForm(field, formOpid));
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
    const passwordFields = formHasCurrentPassword(fields, formOpid ?? "")
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
  candidate: AutofillTriageFieldResult
) {
  const seedKeys = splitSequenceKeys(seed);
  if (!seedKeys.length) {
    return true;
  }

  const candidateKeys = splitSequenceKeys(candidate);
  if (!candidateKeys.length) {
    return isAnonymousOneCharacterField(candidate);
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

  let startIndex = seedIndex;
  while (
    startIndex > 0 &&
    isContiguousSplitField(seed, sortedFields[startIndex - 1]) &&
    splitScopeMatches(seed, sortedFields[startIndex - 1]) &&
    splitSequenceMatches(seed, sortedFields[startIndex - 1])
  ) {
    startIndex -= 1;
  }

  let endIndex = seedIndex;
  while (
    endIndex + 1 < sortedFields.length &&
    isContiguousSplitField(seed, sortedFields[endIndex + 1]) &&
    splitScopeMatches(seed, sortedFields[endIndex + 1]) &&
    splitSequenceMatches(seed, sortedFields[endIndex + 1])
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
  const siteRuleUsernameField = fieldForAction(
    report.fields,
    siteRuleActions.find((action) => action.fieldType === "username")
  ) ?? firstViewableSiteRuleField(report.fields, "username");
  const passwordChangeFields =
    siteRulePasswordChangeField?.formOpid !== undefined
      ? fields.filter((field) => fieldIsInForm(field, siteRulePasswordChangeField.formOpid))
      : fields;
  const passwordChangeAllFields =
    siteRulePasswordChangeField?.formOpid !== undefined
      ? report.fields.filter((field) =>
          fieldIsInForm(field, siteRulePasswordChangeField.formOpid)
        )
      : report.fields;
  const passwordChangeFormOpid =
    typeof payload.password === "string" && typeof payload.newPassword === "string"
      ? pickPasswordChangeFormOpid(passwordChangeFields, passwordChangeAllFields)
      : null;
  const registrationFormOpid =
    typeof payload.password === "string" ? pickRegistrationFormOpid(fields, report.fields) : null;

  if (passwordChangeFormOpid !== null) {
    appendFallbackActions(
      actions,
      createPasswordChangeActions(fields, passwordChangeFormOpid, payload)
    );
    if (typeof payload.totp === "string") {
      appendFallbackActions(actions, createTotpActions(report.fields, payload.totp));
    }
    return { actions };
  }

  if (registrationFormOpid !== null) {
    appendFallbackActions(
      actions,
      createRegistrationActions(fields, registrationFormOpid, payload)
    );
    if (typeof payload.totp === "string") {
      appendFallbackActions(actions, createTotpActions(report.fields, payload.totp));
    }
    return { actions };
  }

  const initialPasswordField =
    typeof payload.password === "string"
      ? siteRulePasswordField ??
        pickLoginPasswordFieldInScope(fields, siteRuleUsernameField) ??
        pickLoginPasswordFieldInForm(fields, siteRuleUsernameField?.formOpid) ??
        pickLoginPasswordField(fields)
      : null;
  const usernameField =
    typeof payload.username === "string" && siteRuleUsernameField === null
      ? pickUsernameField(fields, initialPasswordField) ??
        pickSingleStepEmailUsernameField(report.fields, initialPasswordField)
      : null;
  const usernameAnchor = usernameField ?? siteRuleUsernameField;
  const passwordField =
    typeof payload.password === "string"
      ? siteRulePasswordField ??
        (usernameAnchor
          ? pickLoginPasswordFieldInScope(fields, usernameAnchor) ??
            pickLoginPasswordFieldInForm(fields, usernameAnchor.formOpid) ??
            pickLoginPasswordField(
              fields.filter((field) => fieldScopeMatches(field, usernameAnchor))
            ) ??
            initialPasswordField
        : pickFirstPasswordField(fields)
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
    fallbackActions.push(...createTotpActions(report.fields, payload.totp));
  }

  appendFallbackActions(actions, fallbackActions);
  return { actions };
}
