import { resolveCredentialScopes } from "./scope";
import type {
  AutofillCredentialScope,
  AutofillFieldQualification,
  AutofillFillPayload,
  AutofillIntentPlan,
  AutofillTriageReport
} from "./types";

function hasRole(scope: AutofillCredentialScope, role: AutofillFieldQualification) {
  return scope.roles.includes(role);
}

function scopeHasPassword(scope: AutofillCredentialScope) {
  return hasRole(scope, "password") || hasRole(scope, "currentPassword");
}

function plan(
  kind: AutofillIntentPlan["kind"],
  scope: AutofillCredentialScope | undefined,
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

  if (typeof payload.password === "string" && typeof payload.newPassword === "string") {
    const passwordChangeScope = scopes.find(
      (scope) => scopeHasPassword(scope) && hasRole(scope, "newPassword")
    );
    if (passwordChangeScope) {
      return plan("passwordChange", passwordChangeScope, "scope-has-current-and-new-password");
    }
  }

  if (typeof payload.newPassword === "string") {
    const registrationScope = scopes.find(
      (scope) => hasRole(scope, "newPassword") && !scopeHasPassword(scope)
    );
    if (registrationScope) {
      return plan("registration", registrationScope, "scope-has-new-password");
    }
  }

  if (typeof payload.totp === "string") {
    const totpScope = scopes.find((scope) => hasRole(scope, "totp"));
    if (totpScope) {
      return plan("totp", totpScope, "scope-has-totp");
    }
  }

  if (typeof payload.username === "string" && typeof payload.password === "string") {
    const loginScope = scopes.find(
      (scope) => hasRole(scope, "username") && scopeHasPassword(scope)
    );
    if (loginScope) {
      return plan("login", loginScope, "scope-has-username-and-password");
    }
  }

  if (typeof payload.username === "string") {
    const usernameScope = scopes.find((scope) => hasRole(scope, "username"));
    if (usernameScope) {
      return plan("usernameFirst", usernameScope, "scope-has-username");
    }
  }

  if (typeof payload.password === "string") {
    const passwordScope = scopes.find(scopeHasPassword);
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
