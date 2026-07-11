import { resolveCredentialScopes, resolveFocusedPhysicalScope } from "./scope";
import type {
  AutofillCredentialScope,
  AutofillFieldQualification,
  AutofillFillPayload,
  AutofillIntentPlan,
  AutofillTriageFieldResult,
  AutofillTriageReport
} from "./types";

const REGISTRATION_KEYWORDS = [
  "register",
  "signup",
  "createaccount",
  "createyouraccount",
  "createanaccount",
  "createpassword",
  "join"
];

const RESET_KEYWORDS = [
  "forgotpassword",
  "resetpassword",
  "passwordreset",
  "recoverpassword"
];

const LOGIN_KEYWORDS = [
  "login",
  "signin",
  "signon",
  "logon",
  "authenticate",
  "authentication"
];

const AUTOMATIC_LOGIN_REJECTION_KEYWORDS = [
  "settings",
  "accountmanagement",
  "manageaccount",
  "manageprofile",
  "update",
  "accountsettings",
  "securitysettings",
  "profilesettings",
  "confirmaccount",
  "accountconfirmation",
  "confirmation",
  "confirmemail",
  "emailconfirmation",
  "verifyaccount",
  "verifyemail",
  "register",
  "registration",
  "signup",
  "createaccount",
  "createyouraccount",
  "createanaccount",
  "resetpassword",
  "passwordreset",
  "forgotpassword",
  "recoverpassword",
  "changepassword",
  "updatepassword",
  "changeemail",
  "updateemail"
];

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

function hasRole(scope: AutofillCredentialScope, role: AutofillFieldQualification) {
  return scope.rl.includes(role);
}

function normalizeText(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function fieldSearchText(field: AutofillTriageFieldResult) {
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
    ...field.dv,
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

function fieldRoleEvidenceText(field: AutofillTriageFieldResult) {
  return [
    field.hn,
    field.hi,
    field.hc,
    field.ph,
    field.ti,
    field.al,
    field.lt,
    ...field.dv
  ]
    .map(normalizeText)
    .join(",");
}

function fieldHasRawNewOrConfirmationEvidence(field: AutofillTriageFieldResult) {
  const autocomplete = new Set(
    (field.au ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
  );
  const text = fieldRoleEvidenceText(field);
  return (
    autocomplete.has("new-password") ||
    field.rt.includes("newPassword") ||
    [
      "newpassword",
      "createpassword",
      "confirmpassword",
      "passwordconfirm",
      "passwordconfirmation",
      "repeatpassword",
      "verifypassword"
    ].some((keyword) => text.includes(keyword))
  );
}

function scopeSearchText(scope: AutofillCredentialScope) {
  return scope.f.map(fieldSearchText).join(",");
}

function automaticContextText(scope: AutofillCredentialScope) {
  return scope.f
    .flatMap((field) => [
      ...(field.ct ?? []),
      field.fc?.hi,
      field.fc?.hn,
      field.fc?.hc,
      field.fc?.ha,
      field.fc?.al,
      ...(field.fc?.ht ?? [])
    ])
    .map(normalizeText)
    .join(",");
}

function scopeHasAnyKeyword(scope: AutofillCredentialScope, keywords: readonly string[]) {
  const text = scopeSearchText(scope);
  return keywords.some((keyword) => text.includes(keyword));
}

function fieldLooksCurrentPassword(field: AutofillTriageFieldResult) {
  const text = fieldSearchText(field);
  return (
    field.q === "currentPassword" ||
    field.rt.includes("currentPassword") ||
    field.why.includes("autocomplete:current-password") ||
    field.why.some((reason) => reason.endsWith(":currentPassword")) ||
    text.includes("currentpassword") ||
    text.includes("oldpassword") ||
    text.includes("existingpassword")
  );
}

function fieldHasVerifiedLoginSiteRule(
  field: AutofillTriageFieldResult,
  role: "username" | "password"
) {
  return role === "username"
    ? field.rt.includes("username")
    : field.rt.includes("password") ||
        field.rt.includes("currentPassword");
}

function isAutomaticFillTarget(field: AutofillTriageFieldResult) {
  return field.el && field.vw && field.fl;
}

export function provesAutomaticLoginIntent(scope: AutofillCredentialScope) {
  if (scope.f.some((field) => field.fc?.x === false)) {
    return false;
  }
  const usernameFields = scope.f.filter(
    (field) =>
      isAutomaticFillTarget(field) &&
      (field.q === "username" || field.rt.includes("username"))
  );
  const currentPasswordFields = scope.f.filter(
    (field) =>
      isAutomaticFillTarget(field) &&
      (field.q === "password" || field.q === "currentPassword") &&
      (fieldLooksCurrentPassword(field) ||
        fieldHasVerifiedLoginSiteRule(field, "password"))
  );
  if (
    usernameFields.length !== 1 ||
    currentPasswordFields.length !== 1 ||
    usernameFields[0].o === currentPasswordFields[0].o
  ) {
    return false;
  }

  if (
    scope.f.some(
      (field) =>
        field.q === "newPassword" ||
        field.q === "totp" ||
        field.rt.includes("newPassword") ||
        field.rt.includes("totp") ||
        fieldHasRawNewOrConfirmationEvidence(field)
    ) ||
    scopeHasAnyKeyword(scope, AUTOMATIC_LOGIN_REJECTION_KEYWORDS)
  ) {
    return false;
  }

  const hasVerifiedSiteRule =
    fieldHasVerifiedLoginSiteRule(usernameFields[0], "username") &&
    fieldHasVerifiedLoginSiteRule(currentPasswordFields[0], "password");
  const contextText = automaticContextText(scope);
  return hasVerifiedSiteRule || LOGIN_KEYWORDS.some((keyword) => contextText.includes(keyword));
}

function scopeHasPassword(scope: AutofillCredentialScope) {
  return hasRole(scope, "password") || hasRole(scope, "currentPassword");
}

function scopeHasCurrentPassword(scope: AutofillCredentialScope) {
  return scope.f.some(
    (field) =>
      (field.q === "password" || field.q === "currentPassword") &&
      fieldLooksCurrentPassword(field)
  );
}

function scopeHasNewPassword(scope: AutofillCredentialScope) {
  return hasRole(scope, "newPassword");
}

function scopeHasNewPasswordTarget(scope: AutofillCredentialScope) {
  return scopeHasNewPassword(scope) || hasRole(scope, "confirmation");
}

function scopeHasCredentialCandidate(scope: AutofillCredentialScope) {
  return scope.rl.some(
    (role) =>
      role === "username" ||
      role === "password" ||
      role === "currentPassword" ||
      role === "newPassword" ||
      role === "confirmation" ||
      role === "totp"
  );
}

function scopePasswordFieldCount(scope: AutofillCredentialScope) {
  return scope.f.filter(
    (field) =>
      field.q === "password" ||
      field.q === "currentPassword" ||
      field.q === "newPassword" ||
      field.q === "confirmation"
  ).length;
}

function scopeNewPasswordTargetCount(scope: AutofillCredentialScope) {
  return scope.f.filter(
    (field) =>
      field.q === "newPassword" || field.q === "confirmation"
  ).length;
}

function scopeQualifiesForLogin(scope: AutofillCredentialScope) {
  if (scopeHasNewPasswordTarget(scope)) {
    return (
      hasRole(scope, "username") &&
      scopeHasPassword(scope) &&
      scopeHasAnyKeyword(scope, LOGIN_KEYWORDS) &&
      !hasRole(scope, "confirmation") &&
      !scopeHasAnyKeyword(scope, CHANGE_PASSWORD_KEYWORDS) &&
      !scopeHasAnyKeyword(scope, RESET_KEYWORDS)
    );
  }
  return hasRole(scope, "username") && scopeHasPassword(scope);
}

function scopeQualifiesForAnyLoginStep(scope: AutofillCredentialScope) {
  return (
    scopeQualifiesForLogin(scope) ||
    scopeQualifiesForUsernameFirst(scope) ||
    scopeQualifiesForPasswordStep(scope)
  );
}

function scopeQualifiesForPasswordStep(scope: AutofillCredentialScope) {
  return (
    scopeHasPassword(scope) &&
    !hasRole(scope, "username") &&
    !scopeHasNewPasswordTarget(scope) &&
    !scopeHasAnyKeyword(scope, ["settings"])
  );
}

function scopeQualifiesForUsernameFirst(scope: AutofillCredentialScope) {
  return (
    hasRole(scope, "username") &&
    !scopeHasPassword(scope) &&
    !scopeHasNewPasswordTarget(scope) &&
    !scopeHasAnyKeyword(scope, REGISTRATION_KEYWORDS)
  );
}

function scopeQualifiesForPasswordChange(scope: AutofillCredentialScope) {
  if (!scopeHasCurrentPassword(scope) || !scopeHasNewPassword(scope)) {
    return false;
  }
  if (scope.kind === "container" && scopePasswordFieldCount(scope) < 3) {
    return false;
  }

  const hasAutocompleteRoles =
    scope.f.some(
      (field) =>
        fieldLooksCurrentPassword(field) &&
        (field.why.includes("autocomplete:current-password") ||
          field.rt.includes("currentPassword"))
    ) &&
    scope.f.some(
      (field) =>
        field.q === "newPassword" &&
        (field.why.includes("autocomplete:new-password") ||
          field.rt.includes("newPassword"))
    );

  if (scope.kind === "container") {
    return scopeHasAnyKeyword(scope, EXPLICIT_CHANGE_PASSWORD_KEYWORDS);
  }

  return hasAutocompleteRoles || scopeHasAnyKeyword(scope, CHANGE_PASSWORD_KEYWORDS);
}

function scopeHasProvenPasswordChangeRoles(scope: AutofillCredentialScope) {
  return scopeHasCurrentPassword(scope) && scopeHasNewPassword(scope);
}

function scopeQualifiesForRegistration(
  scope: AutofillCredentialScope,
  options: { allowSingleNewPassword?: boolean; allowWeakContext?: boolean } = {}
) {
  if (!scopeHasNewPassword(scope) || scopeHasPassword(scope)) {
    return false;
  }
  if (scopeHasAnyKeyword(scope, RESET_KEYWORDS)) {
    return false;
  }
  if (!scopeHasAnyKeyword(scope, REGISTRATION_KEYWORDS) && options.allowWeakContext !== true) {
    return false;
  }
  return options.allowSingleNewPassword === true || scopeNewPasswordTargetCount(scope) >= 2;
}

function scopeQualifiesForPasswordReset(scope: AutofillCredentialScope) {
  return (
    scopeHasNewPassword(scope) &&
    !scopeHasCurrentPassword(scope) &&
    scopeHasAnyKeyword(scope, RESET_KEYWORDS)
  );
}

function matchingPhysicalScopes(
  scopes: AutofillCredentialScope[],
  predicate: (scope: AutofillCredentialScope) => boolean
) {
  return scopes.filter((scope) => scope.kind !== "site-rule" && predicate(scope));
}

function plan(
  kind: AutofillIntentPlan["kind"],
  scope: AutofillCredentialScope | undefined | null,
  reason: string
): AutofillIntentPlan {
  return {
    kind,
    sk: scope?.k,
    fis: scope?.fis ?? [],
    why: [reason]
  };
}

function resolveSingleUnfocusedScope(
  scopes: AutofillCredentialScope[],
  predicate: (scope: AutofillCredentialScope) => boolean,
  kind: AutofillIntentPlan["kind"],
  reason: string
) {
  const matches = matchingPhysicalScopes(scopes, predicate);
  if (matches.length > 1) {
    return plan("ambiguous", null, `multiple-${reason}`);
  }
  return matches.length === 1 ? plan(kind, matches[0], reason) : null;
}

function scopeHasUsableSiteRuleAnchor(scope: AutofillCredentialScope) {
  return scope.f.some(
    (field) =>
      field.vw &&
      field.rt.some((fieldType) =>
        fieldType === "username" ? !field.d : field.fl
      )
  );
}

function uniqueSiteRuleBoundScope(scopes: AutofillCredentialScope[]) {
  const matches = matchingPhysicalScopes(scopes, scopeHasUsableSiteRuleAnchor);
  return matches.length === 1 ? matches[0] : null;
}

export function resolveAutofillIntent(
  report: AutofillTriageReport,
  payload: AutofillFillPayload
): AutofillIntentPlan {
  const scopes = resolveCredentialScopes(report.f);
  const hasUsername = typeof payload.username === "string";
  const hasPassword = typeof payload.password === "string";
  const hasNewPassword = typeof payload.newPassword === "string";
  const hasTotp = typeof payload.totp === "string";
  const focusedPhysicalScope = resolveFocusedPhysicalScope(report.f);
  const focused = focusedPhysicalScope
    ? scopes.find((scope) => scope.k === focusedPhysicalScope.key) ?? null
    : null;

  if (focused) {
    const focusedField = focused.f.find((field) => field.fs);
    if (hasNewPassword && scopeQualifiesForPasswordReset(focused)) {
      return plan("passwordReset", focused, "focused-scope-has-password-reset");
    }
    if (
      hasPassword &&
      scopeHasProvenPasswordChangeRoles(focused) &&
      (!hasNewPassword || scopeQualifiesForPasswordChange(focused))
    ) {
      return plan("passwordChange", focused, "focused-scope-has-current-and-new-password");
    }
    if (
      (hasPassword || hasNewPassword) &&
      scopeQualifiesForRegistration(focused, {
        allowSingleNewPassword: true,
        allowWeakContext: true
      })
    ) {
      return plan("registration", focused, "focused-scope-has-registration-password");
    }
    if (hasUsername && hasPassword && scopeQualifiesForLogin(focused)) {
      return plan("login", focused, "focused-scope-has-username-and-password");
    }
    if (hasTotp && hasRole(focused, "totp")) {
      return plan("totpStep", focused, "focused-scope-has-totp");
    }
    if (hasUsername && hasRole(focused, "username") && !scopeHasPassword(focused)) {
      return plan("usernameStep", focused, "focused-scope-has-username");
    }
    if (hasPassword && scopeQualifiesForPasswordStep(focused)) {
      return plan("login", focused, "focused-scope-has-password");
    }
    if (
      hasPassword &&
      focusedField !== undefined &&
      (focusedField.q === "password" ||
        focusedField.q === "currentPassword") &&
      fieldLooksCurrentPassword(focusedField)
    ) {
      return plan("login", focused, "focused-current-password-is-fillable");
    }
    return plan(
      scopeHasCredentialCandidate(focused) ? "ambiguous" : "nonCredential",
      focused,
      scopeHasCredentialCandidate(focused)
        ? "focused-credential-scope-is-incompatible"
        : "focused-physical-scope-is-ineligible"
    );
  }

  const siteRuleBoundScope = uniqueSiteRuleBoundScope(scopes);
  const unfocusedScopes = siteRuleBoundScope ? [siteRuleBoundScope] : scopes;

  const compatibleUnfocusedScopes = matchingPhysicalScopes(unfocusedScopes, (scope) => {
    if (hasNewPassword && scopeQualifiesForPasswordReset(scope)) {
      return true;
    }
    if (
      hasPassword &&
      hasNewPassword &&
      scopeHasProvenPasswordChangeRoles(scope) &&
      scopeQualifiesForPasswordChange(scope)
    ) {
      return true;
    }
    if (hasUsername && hasPassword && scopeQualifiesForAnyLoginStep(scope)) {
      return true;
    }
    if (
      hasUsername &&
      hasPassword &&
      scopeQualifiesForRegistration(scope)
    ) {
      return true;
    }
    if (
      hasNewPassword &&
      scopeQualifiesForRegistration(scope, { allowSingleNewPassword: true })
    ) {
      return true;
    }
    if (hasTotp && hasRole(scope, "totp")) {
      return true;
    }
    if (
      hasUsername &&
      hasRole(scope, "username") &&
      !scopeHasNewPasswordTarget(scope) &&
      !scopeHasAnyKeyword(scope, REGISTRATION_KEYWORDS)
    ) {
      return true;
    }
    return (
      hasPassword &&
      (scopeQualifiesForPasswordStep(scope) || scopeHasProvenPasswordChangeRoles(scope))
    );
  });
  if (compatibleUnfocusedScopes.length > 1) {
    return plan("ambiguous", null, "multiple-compatible-physical-scopes");
  }

  if (hasNewPassword) {
    const passwordReset = resolveSingleUnfocusedScope(
      unfocusedScopes,
      scopeQualifiesForPasswordReset,
      "passwordReset",
      "scope-has-password-reset"
    );
    if (passwordReset) {
      return passwordReset;
    }
  }

  if (hasUsername && hasPassword) {
    const explicitLogin = resolveSingleUnfocusedScope(
      unfocusedScopes,
      (scope) => scopeQualifiesForLogin(scope) && scopeHasAnyKeyword(scope, LOGIN_KEYWORDS),
      "login",
      "scope-has-explicit-login-context"
    );
    if (explicitLogin) {
      return explicitLogin;
    }

    const loginStepScopes = matchingPhysicalScopes(
      unfocusedScopes,
      scopeQualifiesForAnyLoginStep
    );
    if (loginStepScopes.length > 1) {
      return plan("ambiguous", null, "multiple-compatible-login-step-scopes");
    }
    const loginStepScope = loginStepScopes[0];
    if (loginStepScope && scopeQualifiesForLogin(loginStepScope)) {
      return plan("login", loginStepScope, "scope-has-username-and-password");
    }
    if (loginStepScope && scopeQualifiesForUsernameFirst(loginStepScope)) {
      return plan("usernameStep", loginStepScope, "scope-has-username");
    }
    if (loginStepScope && scopeQualifiesForPasswordStep(loginStepScope)) {
      return plan("login", loginStepScope, "scope-has-password");
    }

    const registration = resolveSingleUnfocusedScope(
      unfocusedScopes,
      scopeQualifiesForRegistration,
      "registration",
      "scope-has-registration-password"
    );
    if (registration) {
      return registration;
    }
  }

  if (hasPassword && hasNewPassword) {
    const passwordChange = resolveSingleUnfocusedScope(
      unfocusedScopes,
      (scope) => scopeHasProvenPasswordChangeRoles(scope) && scopeQualifiesForPasswordChange(scope),
      "passwordChange",
      "scope-has-current-and-new-password"
    );
    if (passwordChange) {
      return passwordChange;
    }
  }

  if (hasNewPassword) {
    const registration = resolveSingleUnfocusedScope(
      unfocusedScopes,
      (scope) => scopeQualifiesForRegistration(scope, { allowSingleNewPassword: true }),
      "registration",
      "scope-has-new-password"
    );
    if (registration) {
      return registration;
    }
  }

  if (hasTotp) {
    const totp = resolveSingleUnfocusedScope(
      unfocusedScopes,
      (scope) => hasRole(scope, "totp"),
      "totpStep",
      "scope-has-totp"
    );
    if (totp) {
      return totp;
    }
  }

  if (hasUsername) {
    const username = resolveSingleUnfocusedScope(
      unfocusedScopes,
      (scope) =>
        hasRole(scope, "username") &&
        !scopeHasNewPasswordTarget(scope) &&
        !scopeHasAnyKeyword(scope, REGISTRATION_KEYWORDS),
      "usernameStep",
      "scope-has-username"
    );
    if (username) {
      return username;
    }
  }

  if (hasPassword) {
    const password = resolveSingleUnfocusedScope(
      unfocusedScopes,
      scopeQualifiesForPasswordStep,
      "login",
      "scope-has-password"
    );
    if (password) {
      return password;
    }
  }

  if (hasPassword) {
    const partialPasswordChange = resolveSingleUnfocusedScope(
      unfocusedScopes,
      scopeHasProvenPasswordChangeRoles,
      "passwordChange",
      "scope-has-proven-password-change-roles"
    );
    if (partialPasswordChange) {
      return partialPasswordChange;
    }
  }

  const hasCredentialCandidate = scopes.some(
    (scope) => scope.kind !== "site-rule" && scopeHasCredentialCandidate(scope)
  );
  return {
    kind: hasCredentialCandidate ? "ambiguous" : "nonCredential",
    fis: [],
    why: ["no-compatible-scope"]
  };
}
