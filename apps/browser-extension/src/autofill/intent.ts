import { credentialScopeKey, resolveCredentialScopes } from "./scope";
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
  return scope.roles.includes(role);
}

function normalizeText(value: string | undefined) {
  return (value ?? "").toLowerCase().replace(/[\s_-]+/g, "");
}

function fieldSearchText(field: AutofillTriageFieldResult) {
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
    ...field.dataSetValues,
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

function scopeSearchText(scope: AutofillCredentialScope) {
  return scope.fields.map(fieldSearchText).join(",");
}

function scopeHasAnyKeyword(scope: AutofillCredentialScope, keywords: readonly string[]) {
  const text = scopeSearchText(scope);
  return keywords.some((keyword) => text.includes(keyword));
}

function fieldLooksCurrentPassword(field: AutofillTriageFieldResult) {
  const text = fieldSearchText(field);
  return (
    field.qualifiedAs === "currentPassword" ||
    field.siteRuleTypes.includes("currentPassword") ||
    field.reasons.includes("autocomplete:current-password") ||
    field.reasons.some((reason) => reason.endsWith(":currentPassword")) ||
    text.includes("currentpassword") ||
    text.includes("oldpassword") ||
    text.includes("existingpassword")
  );
}

function scopeHasPassword(scope: AutofillCredentialScope) {
  return hasRole(scope, "password") || hasRole(scope, "currentPassword");
}

function scopeHasCurrentPassword(scope: AutofillCredentialScope) {
  return scope.fields.some(
    (field) =>
      (field.qualifiedAs === "password" || field.qualifiedAs === "currentPassword") &&
      fieldLooksCurrentPassword(field)
  );
}

function scopeHasNewPassword(scope: AutofillCredentialScope) {
  return hasRole(scope, "newPassword");
}

function scopeHasCredentialCandidate(scope: AutofillCredentialScope) {
  return scope.roles.some(
    (role) =>
      role === "username" ||
      role === "password" ||
      role === "currentPassword" ||
      role === "newPassword" ||
      role === "totp"
  );
}

function scopePasswordFieldCount(scope: AutofillCredentialScope) {
  return scope.fields.filter(
    (field) =>
      field.qualifiedAs === "password" ||
      field.qualifiedAs === "currentPassword" ||
      field.qualifiedAs === "newPassword"
  ).length;
}

function scopeNewPasswordFieldCount(scope: AutofillCredentialScope) {
  return scope.fields.filter((field) => field.qualifiedAs === "newPassword").length;
}

function scopeQualifiesForLogin(scope: AutofillCredentialScope) {
  if (scopeHasNewPassword(scope) && !scopeHasAnyKeyword(scope, LOGIN_KEYWORDS)) {
    return false;
  }
  return (
    hasRole(scope, "username") &&
    scopeHasPassword(scope) &&
    !(scopeHasCurrentPassword(scope) && scopeHasNewPassword(scope))
  );
}

function scopeQualifiesForAnyLoginStep(scope: AutofillCredentialScope) {
  return (
    scopeQualifiesForLogin(scope) ||
    scopeQualifiesForUsernameFirst(scope) ||
    scopeQualifiesForPasswordStep(scope)
  );
}

function scopeQualifiesForPasswordStep(scope: AutofillCredentialScope) {
  return scopeHasPassword(scope) && !hasRole(scope, "username") && !scopeHasNewPassword(scope);
}

function scopeQualifiesForUsernameFirst(scope: AutofillCredentialScope) {
  return (
    hasRole(scope, "username") &&
    !scopeHasPassword(scope) &&
    !scopeHasNewPassword(scope) &&
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
    scope.fields.some(
      (field) =>
        fieldLooksCurrentPassword(field) &&
        (field.reasons.includes("autocomplete:current-password") ||
          field.siteRuleTypes.includes("currentPassword"))
    ) &&
    scope.fields.some(
      (field) =>
        field.qualifiedAs === "newPassword" &&
        (field.reasons.includes("autocomplete:new-password") ||
          field.siteRuleTypes.includes("newPassword"))
    );

  if (scope.kind === "container") {
    return scopeHasAnyKeyword(scope, EXPLICIT_CHANGE_PASSWORD_KEYWORDS);
  }

  return hasAutocompleteRoles || scopeHasAnyKeyword(scope, CHANGE_PASSWORD_KEYWORDS);
}

function scopeQualifiesForRegistration(
  scope: AutofillCredentialScope,
  options: { allowSingleNewPassword?: boolean; allowWeakContext?: boolean } = {}
) {
  if (!scopeHasNewPassword(scope) || scopeHasCurrentPassword(scope)) {
    return false;
  }
  if (scopeHasAnyKeyword(scope, RESET_KEYWORDS)) {
    return false;
  }
  if (!scopeHasAnyKeyword(scope, REGISTRATION_KEYWORDS) && options.allowWeakContext !== true) {
    return false;
  }
  return options.allowSingleNewPassword === true || scopeNewPasswordFieldCount(scope) >= 2;
}

function focusedScope(
  scopes: AutofillCredentialScope[],
  fields: AutofillTriageFieldResult[]
) {
  const focusedField = fields.find((field) => field.focused && credentialScopeKey(field) !== null);
  const focusedKey = focusedField ? credentialScopeKey(focusedField) : null;
  if (!focusedKey) {
    return null;
  }
  return scopes.find((scope) => scope.key === focusedKey) ?? null;
}

function firstMatchingScope(
  scopes: AutofillCredentialScope[],
  predicate: (scope: AutofillCredentialScope) => boolean
) {
  return scopes.find((scope) => scope.kind !== "site-rule" && predicate(scope)) ?? null;
}

function plan(
  kind: AutofillIntentPlan["kind"],
  scope: AutofillCredentialScope | undefined | null,
  reason: string
): AutofillIntentPlan {
  return {
    kind,
    scopeKey: scope?.key,
    fieldOpids: scope?.fieldOpids ?? [],
    reasons: [reason]
  };
}

export function resolveAutofillIntent(
  report: AutofillTriageReport,
  payload: AutofillFillPayload
): AutofillIntentPlan {
  const scopes = resolveCredentialScopes(report.fields);
  const hasUsername = typeof payload.username === "string";
  const hasPassword = typeof payload.password === "string";
  const hasNewPassword = typeof payload.newPassword === "string";
  const hasTotp = typeof payload.totp === "string";
  const focused = focusedScope(scopes, report.fields);

  if (focused) {
    if (hasPassword && hasNewPassword && scopeQualifiesForPasswordChange(focused)) {
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
      return plan("totp", focused, "focused-scope-has-totp");
    }
    if (hasUsername && hasRole(focused, "username") && !scopeHasPassword(focused)) {
      return plan("usernameFirst", focused, "focused-scope-has-username");
    }
    if (hasPassword && scopeQualifiesForPasswordStep(focused)) {
      return plan("passwordStep", focused, "focused-scope-has-password");
    }
    if (scopeHasCredentialCandidate(focused)) {
      return plan("none", focused, "focused-credential-scope-is-incompatible");
    }
  }

  if (hasPassword && hasNewPassword) {
    const passwordChangeScope = firstMatchingScope(scopes, scopeQualifiesForPasswordChange);
    if (passwordChangeScope) {
      return plan(
        "passwordChange",
        passwordChangeScope,
        "scope-has-current-and-new-password"
      );
    }
  }

  if (hasUsername && hasPassword) {
    const explicitLoginScope = firstMatchingScope(
      scopes,
      (scope) => scopeQualifiesForLogin(scope) && scopeHasAnyKeyword(scope, LOGIN_KEYWORDS)
    );
    if (explicitLoginScope) {
      return plan("login", explicitLoginScope, "scope-has-explicit-login-context");
    }

    const firstLoginStepScope = firstMatchingScope(scopes, scopeQualifiesForAnyLoginStep);
    if (firstLoginStepScope && scopeQualifiesForLogin(firstLoginStepScope)) {
      return plan("login", firstLoginStepScope, "scope-has-username-and-password");
    }

    if (firstLoginStepScope && scopeQualifiesForUsernameFirst(firstLoginStepScope)) {
      return plan("usernameFirst", firstLoginStepScope, "scope-has-username");
    }

    if (firstLoginStepScope && scopeQualifiesForPasswordStep(firstLoginStepScope)) {
      return plan("passwordStep", firstLoginStepScope, "scope-has-password");
    }

    const registrationScope = firstMatchingScope(scopes, (scope) =>
      scopeQualifiesForRegistration(scope)
    );
    if (registrationScope) {
      return plan("registration", registrationScope, "scope-has-registration-password");
    }
  }

  if (hasNewPassword) {
    const registrationScope = firstMatchingScope(scopes, (scope) =>
      scopeQualifiesForRegistration(scope, { allowSingleNewPassword: true })
    );
    if (registrationScope) {
      return plan("registration", registrationScope, "scope-has-new-password");
    }
  }

  if (hasTotp) {
    const totpScope = firstMatchingScope(scopes, (scope) => hasRole(scope, "totp"));
    if (totpScope) {
      return plan("totp", totpScope, "scope-has-totp");
    }
  }

  if (hasUsername) {
    const usernameScope = firstMatchingScope(scopes, scopeQualifiesForUsernameFirst);
    if (usernameScope) {
      return plan("usernameFirst", usernameScope, "scope-has-username");
    }
  }

  if (hasPassword) {
    const passwordScope = firstMatchingScope(scopes, scopeQualifiesForPasswordStep);
    if (passwordScope) {
      return plan("passwordStep", passwordScope, "scope-has-password");
    }
  }

  return {
    kind: "none",
    fieldOpids: [],
    reasons: ["no-compatible-scope"]
  };
}
