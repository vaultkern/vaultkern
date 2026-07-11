import { provesAutomaticLoginIntent, resolveAutofillIntent } from "./intent";
import { credentialScopeKey, fieldScopeMatches, resolveCredentialScopes } from "./scope";
import { triageAutofillPage } from "./triage";
import { physicalFieldForSnapshot } from "./collectPageFields";
import {
  automaticFillUrlAllowed,
  isIssuedFillCapability,
  type FillCapability
} from "./fillAuthorization";
import type {
  AutofillCredentialScope,
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

interface PendingAutofillFillAction {
  fi: string;
  n: number;
  ft: AutofillFieldQualification;
  v: string;
}

export interface AutofillFillAction extends PendingAutofillFillAction {
  t: Element | null;
  tr: Exclude<AutofillFieldQualification, "ignored">;
  trs: "groupInference" | "heuristic" | "siteRule";
  ts: {
    tg: string;
    hy?: string;
    hn?: string;
    hi?: string;
    hc?: string;
    au?: string;
    im?: string;
    ph?: string;
    ti?: string;
    al?: string;
    ad?: string;
    lt?: string;
    dv: string[];
  };
  pg: string;
  ag: string;
}

export interface AutofillFillPlan {
  ac: AutofillFillAction[];
  au?: [url: string, scopeKey: string];
  sr?: {
    id: string;
    d: boolean;
  };
}

function byDocumentOrder(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  return left.n - right.n;
}

function candidateFields(reportFields: AutofillTriageFieldResult[]) {
  return reportFields
    .filter((field) => field.el && field.vw && field.fl)
    .sort(byDocumentOrder);
}

function isLoginPasswordRole(field: AutofillTriageFieldResult) {
  return field.q === "password" || field.q === "currentPassword";
}

function focusedLoginSegmentFields(fields: AutofillTriageFieldResult[]) {
  const sortedFields = [...fields].sort(byDocumentOrder);
  const focusedIndex = sortedFields.findIndex(
    (field) => field.fs && (field.q === "username" || isLoginPasswordRole(field))
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
      if (field.q === "username") {
        start = index;
        break;
      }
      if (isLoginPasswordRole(field)) {
        break;
      }
    }
    for (let index = focusedIndex + 1; index < sortedFields.length; index += 1) {
      const field = sortedFields[index];
      if (field.q === "totp") {
        end = index;
        continue;
      }
      break;
    }
  } else {
    let sawPassword = false;
    for (let index = focusedIndex + 1; index < sortedFields.length; index += 1) {
      const field = sortedFields[index];
      if (field.q === "username") {
        break;
      }
      if (isLoginPasswordRole(field)) {
        end = index;
        sawPassword = true;
        continue;
      }
      if (field.q === "totp" && sawPassword) {
        end = index;
        continue;
      }
      break;
    }
  }

  const segmentFields = sortedFields.slice(start, end + 1);
  const hasUsername = segmentFields.some((field) => field.q === "username");
  const hasPassword = segmentFields.some(isLoginPasswordRole);
  return hasUsername && hasPassword ? segmentFields : fields;
}

function siteRuleFields(reportFields: AutofillTriageFieldResult[]) {
  return reportFields
    .filter((field) => field.vw && field.fl && field.rt.length > 0)
    .sort(byDocumentOrder);
}

function viewableSiteRuleFields(
  reportFields: AutofillTriageFieldResult[],
  fieldType: AutofillFieldQualification
) {
  return reportFields
    .filter((field) => field.vw && !field.d && field.rt.includes(fieldType))
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
    siteRuleFields(reportFields).find((field) => field.rt.includes(fieldType)) ??
    null
  );
}

function actionForSiteRuleField(
  field: AutofillTriageFieldResult,
  payload: LoginFillPayload,
  skippedFieldTypes: ReadonlySet<AutofillFieldQualification> = new Set()
): PendingAutofillFillAction | null {
  for (const fieldType of field.rt) {
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
        fi: field.o,
        n: field.n,
        ft: fieldType,
        v: value
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
    .filter((field) => field.rt.includes("totp"))
    .sort(byDocumentOrder);
  const trimmedValue = value.trim();
  const splitFields = pickSplitTotpFields(fields, totpFields, trimmedValue.length);

  if (splitFields.length <= 1) {
    return [];
  }

  return splitFields.map((field, index) => ({
    fi: field.o,
    n: field.n,
    ft: "totp" as const,
    v: trimmedValue[index] ?? ""
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
      .filter((field) => field.rt.includes(fieldType))
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
        field.rt.some((fieldType) => fieldTypes.includes(fieldType))
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
  const actions: PendingAutofillFillAction[] = [];
  const currentPasswordRuleFields = fields.filter((field) =>
    field.rt.some(
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
    const totpFields = fields.filter((field) => field.rt.includes("totp"));
    const ambiguousTotpScopes = siteRuleScopesForFieldType(fields, "totp").size > 1;
    if (!ambiguousTotpScopes) {
      for (const action of createSplitSiteRuleTotpActions(fields, payload.totp)) {
        usedFields.add(action.fi);
        actions.push(action);
      }
    }
    if (ambiguousTotpScopes || totpFields.length > 1) {
      skippedFieldTypes.add("totp");
    }
  }

  for (const field of fields) {
    if (usedFields.has(field.o)) {
      continue;
    }
    const action = actionForSiteRuleField(field, payload, skippedFieldTypes);
    if (action) {
      usedFields.add(field.o);
      actions.push(action);
    }
  }

  return actions;
}

function appendFallbackActions(
  primaryActions: PendingAutofillFillAction[],
  fallbackActions: PendingAutofillFillAction[]
) {
  const usedFieldOpids = new Set(primaryActions.map((action) => action.fi));
  const primaryFieldTypes = new Set(primaryActions.map((action) => action.ft));

  for (const action of fallbackActions) {
    const repeatedFieldType =
      action.ft === "newPassword" || action.ft === "confirmation";
    if (
      usedFieldOpids.has(action.fi) ||
      (!repeatedFieldType && primaryFieldTypes.has(action.ft))
    ) {
      continue;
    }
    usedFieldOpids.add(action.fi);
    primaryActions.push(action);
  }
}

function preferCurrentPasswordField(fields: AutofillTriageFieldResult[]) {
  return (
    fields.find((field) => field.why.includes("autocomplete:current-password")) ??
    fields[0] ??
    null
  );
}

function isNewPasswordTarget(field: AutofillTriageFieldResult) {
  return field.q === "newPassword" || field.q === "confirmation";
}

function scopedCredentialFields(
  fields: AutofillTriageFieldResult[],
  field: AutofillTriageFieldResult
) {
  return fields.filter((candidate) => fieldScopeMatches(candidate, field));
}

function isRegistrationUsernameFallback(
  field: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  const scopedFields = scopedCredentialFields(fields, field);
  return (
    scopedFields.some(isNewPasswordTarget) &&
    !scopedFields.some(isLoginPasswordRole)
  );
}

function pickPasswordField(
  fields: AutofillTriageFieldResult[],
  usernameField?: AutofillTriageFieldResult | null
) {
  const passwordFields = fields.filter(isLoginPasswordRole);
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
  return fields.some(
    (candidate) =>
      isNewPasswordTarget(candidate) &&
      candidate.o !== field.o &&
      fieldScopeMatches(candidate, field)
  );
}

function fieldHasSiblingUsername(
  field: AutofillTriageFieldResult,
  fields: AutofillTriageFieldResult[]
) {
  return fields.some(
    (candidate) =>
      candidate.q === "username" &&
      candidate.o !== field.o &&
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
    (field) => isLoginPasswordRole(field) && !isUnsafeLoginPasswordField(field, fields)
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
  return (
    fields.find(
      (field) =>
        isLoginPasswordRole(field) &&
        field.n > usernameField.n &&
        fieldScopeMatches(field, usernameField)
    ) ?? null
  );
}

function fieldForAction(
  fields: AutofillTriageFieldResult[],
  action: PendingAutofillFillAction | undefined
) {
  if (!action) {
    return null;
  }
  return fields.find((field) => field.o === action.fi) ?? null;
}

function usernameHintScore(field: AutofillTriageFieldResult) {
  const fieldText = [
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

  let score = 0;
  if (field.why.includes("autocomplete:username")) {
    score += 100;
  }
  if (field.why.includes("autocomplete:email")) {
    score += 80;
  }
  if (field.hy === "email") {
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
  const usernameFields = fields.filter((field) => field.q === "username");
  if (!usernameFields.length) {
    return null;
  }

  if (passwordField) {
    return pickPreferredUsernameField(
      usernameFields.filter((field) => fieldScopeMatches(field, passwordField))
    );
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
    (field) => isLoginPasswordRole(field) && fieldScopeMatches(field, usernameField)
  );
}

function pickUsernameFirstField(fields: AutofillTriageFieldResult[]) {
  return pickPreferredUsernameField(
    fields.filter(
      (field) =>
        field.q === "username" &&
        !isRegistrationUsernameFallback(field, fields) &&
        !hasScopedPasswordField(fields, field)
    )
  );
}

function hasBlockingUsernameFallbackReason(field: AutofillTriageFieldResult) {
  return field.why.some(
    (reason) => reason.startsWith("excluded:") || reason.startsWith("non-login:")
  );
}

function isSingleStepEmailCandidate(field: AutofillTriageFieldResult) {
  return (
    field.q === "ignored" &&
    field.vw &&
    field.fl &&
    field.tg === "input" &&
    (field.hy === "email" ||
      (field.hy === "text" && singleStepFieldHasEmailHint(field))) &&
    !hasBlockingUsernameFallbackReason(field)
  );
}

function singleStepFieldHasEmailHint(field: AutofillTriageFieldResult) {
  const fieldText = [
    field.hn,
    field.hi,
    field.hc,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...field.dv
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

function pickLoginPasswordFieldInScope(
  fields: AutofillTriageFieldResult[],
  anchorField: AutofillTriageFieldResult | null
) {
  if (!anchorField) {
    return null;
  }
  return pickLoginPasswordField(fields.filter((field) => fieldScopeMatches(field, anchorField)));
}

function fieldIsInCredentialScope(
  field: AutofillTriageFieldResult,
  scopeKey: string
) {
  return credentialScopeKey(field) === scopeKey;
}

export function automaticLoginScopeKey(
  reportFields: AutofillTriageFieldResult[]
) {
  const credentialScopes = resolveCredentialScopes(reportFields).filter(
    (scope) =>
      scope.kind !== "site-rule" &&
      scope.f.some((field) => field.q !== "ignored" || field.rt.length > 0)
  );
  if (credentialScopes.length !== 1) {
    return null;
  }

  const [scope] = credentialScopes;
  return provesAutomaticLoginIntent(scope) ? scope.k : null;
}

function strictPageLoadScopeKey(
  reportFields: AutofillTriageFieldResult[],
  payload: LoginFillPayload,
  capability: FillCapability
) {
  if (capability.kind !== "automatic") {
    return undefined;
  }
  if (!automaticFillUrlAllowed(capability.targetUrl)) {
    return null;
  }
  if (
    typeof payload.username !== "string" ||
    typeof payload.password !== "string" ||
    typeof payload.newPassword === "string" ||
    typeof payload.totp === "string"
  ) {
    return null;
  }

  return automaticLoginScopeKey(reportFields);
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
    field.hn,
    field.hi,
    field.hc,
    field.au,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...((field.ct ?? []) as string[]),
    field.fc?.hi,
    field.fc?.hn,
    field.fc?.hc,
    field.fc?.ha,
    field.fc?.al,
    ...((field.fc?.ht ?? []) as string[])
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
    field.rt.includes("currentPassword") ||
    field.why.includes("autocomplete:current-password") ||
    field.why.some((reason) => reason.endsWith(":currentPassword")) ||
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
  const passwordFields = formFields.filter(isLoginPasswordRole);
  return passwordFields.find(isCurrentPasswordField) ?? null;
}

function scopeQualifiesForPasswordChange(
  fields: AutofillTriageFieldResult[],
  scopeKey: string
) {
  const formFields = fields.filter((field) => fieldIsInCredentialScope(field, scopeKey));
  const currentPasswordField = pickCurrentPasswordField(formFields);
  const formNewPasswordFields = formFields.filter(
    (field) => field.q === "newPassword"
  );
  if (!currentPasswordField || !formNewPasswordFields.length) {
    return false;
  }
  if (
    scopeKey.startsWith("container:") &&
    formFields.filter(
      (field) => isLoginPasswordRole(field) || isNewPasswordTarget(field)
    ).length < 3
  ) {
    return false;
  }

  const hasAutocompleteRoles =
    (currentPasswordField.why.includes("autocomplete:current-password") ||
      currentPasswordField.rt.includes("currentPassword")) &&
    formNewPasswordFields.some((field) => field.why.includes("autocomplete:new-password"));
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
      (field.q === "username" ||
        isLoginPasswordRole(field) ||
        isNewPasswordTarget(field))
  );
}

function pickPasswordChangeScopeKey(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[]
) {
  const newPasswordFields = fields.filter(
    (field) => field.q === "newPassword" && credentialScopeKey(field) !== null
  );
  const scopeKeys = new Set(
    newPasswordFields
      .map(credentialScopeKey)
      .filter((scopeKey): scopeKey is string => scopeKey !== null)
  );

  const focusedField = allFields.find((field) => field.fs && credentialScopeKey(field));
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
): PendingAutofillFillAction[] {
  const formFields = fields.filter((field) => fieldIsInCredentialScope(field, scopeKey));
  const currentPasswordField = pickCurrentPasswordField(formFields);
  const allowsNewPassword = scopeQualifiesForPasswordChange(fields, scopeKey);
  const actions: PendingAutofillFillAction[] = [];

  if (typeof payload.username === "string") {
    const usernameField = formFields.find((field) => field.q === "username");
    if (usernameField) {
      actions.push({
        fi: usernameField.o,
        n: usernameField.n,
        ft: usernameField.q,
        v: payload.username
      });
    }
  }

  if (currentPasswordField && typeof payload.password === "string") {
    actions.push({
      fi: currentPasswordField.o,
      n: currentPasswordField.n,
      ft: currentPasswordField.q,
      v: payload.password
    });
  }

  if (allowsNewPassword && typeof payload.newPassword === "string") {
    for (const passwordField of formFields.filter(isNewPasswordTarget)) {
      actions.push({
        fi: passwordField.o,
        n: passwordField.n,
        ft: passwordField.q,
        v: payload.newPassword
      });
    }
  }

  return actions;
}

function hasCredentialSignal(field: AutofillTriageFieldResult) {
  const searchableText = searchableFieldText(field);
  const autocomplete = field.au ?? "";
  return (
    field.hy === "email" ||
    field.hy === "password" ||
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
      isLoginPasswordRole(field) &&
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
      field.why.some((reason) => reason === "non-login:newsletter") ||
      ["newsletter", "subscribe", "subscription", "unsubscribe", "mailinglist"].some((keyword) =>
        searchableText.includes(keyword)
      )
    );
  });
}

function newPasswordScopeKeys(fields: AutofillTriageFieldResult[]) {
  return new Set(
    fields
      .filter((field) => field.q === "newPassword" && credentialScopeKey(field) !== null)
      .map(credentialScopeKey)
      .filter((scopeKey): scopeKey is string => scopeKey !== null)
  );
}

function unfocusedRegistrationScopeKeys(
  fields: AutofillTriageFieldResult[],
  options: { allowSingleNewPassword?: boolean } = {}
) {
  const newPasswordFields = fields.filter(
    (field) => field.q === "newPassword" && credentialScopeKey(field) !== null
  );
  if (!newPasswordFields.length) {
    return [];
  }

  const loginPasswordFields = fields.filter(isLoginPasswordRole);
  if (loginPasswordFields.length) {
    return [];
  }

  const scopeKeys: string[] = [];
  for (const scopeKey of newPasswordScopeKeys(fields)) {
    if (scopeHasCurrentPassword(fields, scopeKey)) {
      continue;
    }
    const formFields = fieldsInCredentialScope(fields, scopeKey);
    const newPasswordCount = formFields.filter(isNewPasswordTarget).length;
    if (
      formHasResetPasswordContext(formFields) ||
      !formHasRegistrationContext(formFields) ||
      (newPasswordCount < 2 && options.allowSingleNewPassword !== true)
    ) {
      continue;
    }
    scopeKeys.push(scopeKey);
  }
  return scopeKeys;
}

function ambiguousNewPasswordFallbackSpansMultipleScopes(
  fields: AutofillTriageFieldResult[],
  payload: LoginFillPayload
) {
  const scopeKeys = new Set<string>();
  if (typeof payload.password === "string" && typeof payload.newPassword === "string") {
    for (const scopeKey of newPasswordScopeKeys(fields)) {
      if (scopeQualifiesForPasswordChange(fields, scopeKey)) {
        scopeKeys.add(scopeKey);
      }
    }
  }
  if (typeof payload.password === "string" || typeof payload.newPassword === "string") {
    for (const scopeKey of unfocusedRegistrationScopeKeys(fields, {
      allowSingleNewPassword: typeof payload.newPassword === "string"
    })) {
      scopeKeys.add(scopeKey);
    }
  }
  return scopeKeys.size > 1;
}

function pickRegistrationScopeKey(
  fields: AutofillTriageFieldResult[],
  allFields: AutofillTriageFieldResult[],
  options: { allowSingleNewPassword?: boolean } = {}
) {
  const newPasswordFields = fields.filter(
    (field) => field.q === "newPassword" && credentialScopeKey(field) !== null
  );
  if (!newPasswordFields.length) {
    return null;
  }

  const focusedField = allFields.find((field) => field.fs && credentialScopeKey(field) !== null);
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

  for (const scopeKey of unfocusedRegistrationScopeKeys(fields, options)) {
    return scopeKey;
  }

  return null;
}

function createRegistrationActions(
  fields: AutofillTriageFieldResult[],
  scopeKey: string,
  payload: LoginFillPayload
): PendingAutofillFillAction[] {
  const formFields = fieldsInCredentialScope(fields, scopeKey);
  const actions: PendingAutofillFillAction[] = [];

  if (typeof payload.username === "string") {
    const usernameField = formFields.find((field) => field.q === "username");
    if (usernameField) {
      actions.push({
        fi: usernameField.o,
        n: usernameField.n,
        ft: usernameField.q,
        v: payload.username
      });
    }
  }

  const registrationPassword = payload.newPassword ?? payload.password;
  if (typeof registrationPassword === "string") {
    const passwordFields = formFields.filter(isNewPasswordTarget);
    for (const passwordField of passwordFields) {
      actions.push({
        fi: passwordField.o,
        n: passwordField.n,
        ft: passwordField.q,
        v: registrationPassword
      });
    }
  }

  return actions;
}

function createPasswordResetActions(
  fields: AutofillTriageFieldResult[],
  scopeKey: string,
  payload: LoginFillPayload
): PendingAutofillFillAction[] {
  const newPassword = payload.newPassword;
  if (typeof newPassword !== "string") {
    return [];
  }
  return fieldsInCredentialScope(fields, scopeKey)
    .filter(isNewPasswordTarget)
    .map((field) => ({
      fi: field.o,
      n: field.n,
      ft: field.q,
      v: newPassword
    }));
}

function pickTotpFields(fields: AutofillTriageFieldResult[]) {
  return fields
    .filter((field) => field.q === "totp" && field.vw && field.fl)
    .sort(byDocumentOrder);
}

function normalizeHint(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function splitFieldHintText(field: AutofillTriageFieldResult) {
  return [
    field.hn,
    field.hi,
    field.hc,
    field.au,
    field.im,
    field.ph,
    field.ti,
    field.al,
    field.ad,
    field.lt,
    ...field.dv
  ]
    .map(normalizeHint)
    .join(",");
}

function hasSplitCodeHint(field: AutofillTriageFieldResult) {
  const fieldText = splitFieldHintText(field);
  return (
    field.q === "totp" ||
    field.im === "numeric" ||
    field.im === "decimal" ||
    fieldText.includes("digit") ||
    fieldText.includes("code") ||
    fieldText.includes("otp") ||
    fieldText.includes("totp")
  );
}

function isOneCharacterField(field: AutofillTriageFieldResult) {
  return field.vw && field.fl && field.ml === 1 && hasSplitCodeHint(field);
}

function isAnonymousOneCharacterField(field: AutofillTriageFieldResult) {
  return (
    field.vw &&
    field.fl &&
    field.ml === 1 &&
    field.hn === undefined &&
    field.hi === undefined
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
  return [field.hn, field.hi]
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
  return fieldScopeMatches(seed, candidate);
}

function pickContiguousOneCharacterFields(
  fields: AutofillTriageFieldResult[],
  seed: AutofillTriageFieldResult,
  valueLength: number
) {
  const sortedFields = [...fields].sort(byDocumentOrder);
  const seedIndex = sortedFields.findIndex((field) => field.o === seed.o);
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
): PendingAutofillFillAction[] {
  const totpFields = pickTotpFields(fields);
  if (!totpFields.length) {
    return [];
  }

  const trimmedValue = value.trim();
  const splitFields = pickSplitTotpFields(fields, totpFields, trimmedValue.length);

  if (splitFields.length > 1) {
    return splitFields.map((field, index) => ({
      fi: field.o,
      n: field.n,
      ft: "totp",
      v: trimmedValue[index] ?? ""
    }));
  }

  if (totpFields.length === 1) {
    const field = totpFields[0];
    if (isOneCharacterField(field)) {
      return [];
    }
    return [
      {
        fi: field.o,
        n: field.n,
        ft: field.q,
        v: trimmedValue
      }
    ];
  }

  return [];
}

function targetRoleForFieldType(
  fieldType: AutofillFieldQualification
): AutofillFillAction["tr"] | null {
  if (fieldType === "ignored") {
    return null;
  }
  return fieldType;
}

function roleCategoryForBinding(fieldType: AutofillFieldQualification) {
  if (fieldType === "password" || fieldType === "currentPassword") {
    return "password";
  }
  if (fieldType === "newPassword" || fieldType === "confirmation") {
    return "newPassword";
  }
  return fieldType;
}

function bindFillActions(
  snapshot: AutofillPageSnapshot,
  reportFields: AutofillTriageFieldResult[],
  actions: PendingAutofillFillAction[]
): AutofillFillPlan {
  const fieldByOpid = new Map(reportFields.map((field) => [field.o, field]));
  const resolvedActions: Array<{
    action: PendingAutofillFillAction;
    field: AutofillTriageFieldResult;
    targetRole: AutofillFillAction["tr"];
    physicalGroupId: string;
  }> = [];

  for (const action of actions) {
    const field = fieldByOpid.get(action.fi);
    const targetRole = targetRoleForFieldType(action.ft);
    if (!field || targetRole === null) {
      continue;
    }
    resolvedActions.push({
      action,
      field,
      targetRole,
      physicalGroupId: credentialScopeKey(field) ?? field.so
    });
  }

  if (new Set(resolvedActions.map(({ physicalGroupId }) => physicalGroupId)).size > 1) {
    return { ac: [], sr: snapshot.sr };
  }

  const boundActions = resolvedActions.map(
    ({ action, field, targetRole, physicalGroupId }): AutofillFillAction => ({
      ...action,
      t: physicalFieldForSnapshot(snapshot, action.fi),
      tr: targetRole,
      trs: field.rt.includes(action.ft)
        ? "siteRule"
        : roleCategoryForBinding(field.q) === roleCategoryForBinding(action.ft)
          ? "heuristic"
          : "groupInference",
      ts: {
        tg: field.tg,
        hy: field.hy,
        hn: field.hn,
        hi: field.hi,
        hc: field.hc,
        au: field.au,
        im: field.im,
        ph: field.ph,
        ti: field.ti,
        al: field.al,
        ad: field.ad,
        lt: field.lt,
        dv: [...field.dv]
      },
      pg: physicalGroupId,
      ag: "credential-transaction"
    })
  );

  return { ac: boundActions, sr: snapshot.sr };
}

function completeAutomaticLoginPlan(
  plan: AutofillFillPlan,
  expectedScopeKey: string | undefined,
  targetUrl: string
) {
  const usernameActions = plan.ac.filter((action) => action.tr === "username");
  const passwordActions = plan.ac.filter(
    (action) => action.tr === "password" || action.tr === "currentPassword"
  );
  const username = usernameActions[0];
  const password = passwordActions[0];
  return plan.ac.length === 2 &&
    usernameActions.length === 1 &&
    passwordActions.length === 1 &&
    username.t !== null &&
    password.t !== null &&
    username.fi !== password.fi &&
    username.t !== password.t &&
    username.pg === expectedScopeKey &&
    password.pg === expectedScopeKey
    ? { ...plan, au: [targetUrl, expectedScopeKey] as [string, string] }
    : { ac: [], sr: plan.sr };
}

export function createLoginFillPlan(
  snapshot: AutofillPageSnapshot,
  payload: LoginFillPayload,
  authorization: FillCapability | unknown
): AutofillFillPlan {
  const capability = isIssuedFillCapability(authorization) ? authorization : null;
  if (
    capability === null ||
    (snapshot.url !== undefined && capability.targetUrl !== snapshot.url)
  ) {
    return { ac: [] };
  }
  const report = triageAutofillPage(snapshot);
  const pageLoadScopeKey = strictPageLoadScopeKey(report.f, payload, capability);
  if (pageLoadScopeKey === null) {
    return { ac: [] };
  }
  if (snapshot.sr?.d) {
    return { ac: [] };
  }
  const intent = resolveAutofillIntent(report, payload);
  if (intent.kind === "ambiguous" || intent.kind === "nonCredential") {
    return { ac: [] };
  }
  const bindActions = (actions: PendingAutofillFillAction[]) => {
    const plan = bindFillActions(snapshot, report.f, actions);
    return capability.kind === "automatic"
      ? completeAutomaticLoginPlan(plan, pageLoadScopeKey, capability.targetUrl)
      : plan;
  };
  const intentScopeKey =
    intent.sk !== undefined && !intent.sk.startsWith("site-rule:")
      ? intent.sk
      : null;
  const intentUsesFocusedScope = intent.why.some((reason) =>
    reason.startsWith("focused-")
  );
  const rawSiteRuleActions = createSiteRuleActions(report.f, payload);
  const fields = candidateFields(report.f);
  const ambiguousPasswordSiteRule =
    fillableSiteRuleFieldSpansMultipleScopes(report.f, ["password", "currentPassword"]);
  const ambiguousUsernameSiteRule =
    viewableSiteRuleFieldSpansMultipleScopes(report.f, "username");
  const ambiguousNewPasswordSiteRule =
    fillableSiteRuleFieldSpansMultipleScopes(report.f, ["newPassword"]);
  const ambiguousTotpSiteRule =
    viewableSiteRuleFieldSpansMultipleScopes(report.f, "totp");
  const ambiguousNewPasswordFallback =
    ambiguousNewPasswordSiteRule &&
    ambiguousNewPasswordFallbackSpansMultipleScopes(fields, payload);
  const ambiguousCredentialSiteRule =
    ambiguousPasswordSiteRule ||
    ambiguousUsernameSiteRule ||
    ambiguousNewPasswordFallback ||
    ambiguousTotpSiteRule;
  const siteRuleActions =
    intentUsesFocusedScope && intentScopeKey !== null
      ? rawSiteRuleActions.filter((action) => {
          const field = fieldForAction(report.f, action);
          return field !== null && fieldIsInCredentialScope(field, intentScopeKey);
        })
      : rawSiteRuleActions;
  const actions: PendingAutofillFillAction[] = [...siteRuleActions];
  const siteRulePasswordField = fieldForAction(
    report.f,
    siteRuleActions.find(
      (action) => action.ft === "password" || action.ft === "currentPassword"
    )
  );
  const siteRulePasswordChangeField = fieldForAction(
    report.f,
    siteRuleActions.find(
      (action) => action.ft === "currentPassword" || action.ft === "newPassword"
    )
  );
  const siteRuleUsernameFieldCandidate = fieldForAction(
    report.f,
    siteRuleActions.find((action) => action.ft === "username")
  ) ?? (ambiguousUsernameSiteRule
    ? null
    : firstViewableSiteRuleField(report.f, "username"));
  const siteRuleUsernameField =
    intentUsesFocusedScope &&
    intentScopeKey !== null &&
    siteRuleUsernameFieldCandidate !== null &&
    !fieldIsInCredentialScope(siteRuleUsernameFieldCandidate, intentScopeKey)
      ? null
      : siteRuleUsernameFieldCandidate;
  const siteRuleTotpFieldCandidate = fieldForAction(
    report.f,
    siteRuleActions.find((action) => action.ft === "totp")
  ) ?? (ambiguousTotpSiteRule
    ? null
    : firstFillableSiteRuleField(report.f, "totp"));
  const siteRuleTotpField =
    intentUsesFocusedScope &&
    intentScopeKey !== null &&
    siteRuleTotpFieldCandidate !== null &&
    !fieldIsInCredentialScope(siteRuleTotpFieldCandidate, intentScopeKey)
      ? null
      : siteRuleTotpFieldCandidate;
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
  const shouldUseResolvedScope =
    siteRuleAnchorScopeKey !== null ||
    intent.kind === "login" ||
    intent.kind === "usernameStep" ||
    intent.kind === "totpStep" ||
    intent.kind === "registration" ||
    intent.kind === "passwordChange" ||
    intent.kind === "passwordReset";
  const primaryScopeKey = siteRuleAnchorScopeKey ?? intentScopeKey;
  if (
    ambiguousCredentialSiteRule &&
    siteRuleAnchorScopeKey === null &&
    !intentUsesFocusedScope
  ) {
    return bindActions(actions);
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
      ? report.f.filter((field) => fieldIsInCredentialScope(field, primaryScopeKey))
      : report.f;
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
      ? report.f.filter((field) =>
          fieldIsInCredentialScope(field, siteRulePasswordChangeScopeKey)
        )
      : report.f;
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
          ? pickRegistrationScopeKey(fields, report.f, {
              allowSingleNewPassword: typeof payload.newPassword === "string"
            })
          : null)
      : null;
  const passwordResetScopeKey =
    intent.kind === "passwordReset" ? intentScopeKey : null;

  if (passwordChangeScopeKey !== null) {
    appendFallbackActions(
      actions,
      createPasswordChangeActions(fields, passwordChangeScopeKey, payload)
    );
    if (typeof payload.totp === "string") {
      appendFallbackActions(
        actions,
        createTotpActions(
          report.f.filter((field) => fieldIsInCredentialScope(field, passwordChangeScopeKey)),
          payload.totp
        )
      );
    }
    return bindActions(actions);
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
          report.f.filter((field) => fieldIsInCredentialScope(field, registrationScopeKey)),
          payload.totp
        )
      );
    }
    return bindActions(actions);
  }

  if (passwordResetScopeKey !== null) {
    appendFallbackActions(
      actions,
      createPasswordResetActions(fields, passwordResetScopeKey, payload)
    );
    return bindActions(actions);
  }

  const initialPasswordField =
    typeof payload.password === "string"
      ? siteRulePasswordField ??
        pickLoginPasswordFieldInScope(intentFields, siteRuleUsernameField) ??
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
            pickLoginPasswordField(
              intentFields.filter((field) => fieldScopeMatches(field, usernameAnchor))
            ) ??
            pickUnscopedPasswordAfterUsername(intentFields, usernameAnchor)
        : pickFirstSafeLoginPasswordField(intentFields)
        )
      : null;

  const fallbackActions: PendingAutofillFillAction[] = [];
  if (usernameField && typeof payload.username === "string") {
    fallbackActions.push({
      fi: usernameField.o,
      n: usernameField.n,
      ft: usernameField.q === "ignored" ? "username" : usernameField.q,
      v: payload.username
    });
  }

  if (passwordField && typeof payload.password === "string") {
    fallbackActions.push({
      fi: passwordField.o,
      n: passwordField.n,
      ft: passwordField.q,
      v: payload.password
    });
  }

  if (typeof payload.totp === "string") {
    const totpActionFields =
      shouldUseResolvedScope && primaryScopeKey !== null ? intentAllFields : report.f;
    fallbackActions.push(...createTotpActions(totpActionFields, payload.totp));
  }

  appendFallbackActions(actions, fallbackActions);
  return bindActions(actions);
}
