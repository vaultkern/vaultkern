import { describe, expect, it } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { resolveAutofillIntent } from "../intent";
import { resolveCredentialScopes } from "../scope";
import { triageAutofillPage } from "../triage";

describe("autofill scope and intent resolver", () => {
  it("groups credential fields by form and chooses the login scope for login payloads", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="register">
        <input name="signup_email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const scopes = resolveCredentialScopes(report.fields);
    const loginScope = scopes.find((scope) => scope.key === "form:form-0");
    const registrationScope = scopes.find((scope) => scope.key === "form:form-1");

    expect(loginScope?.kind).toBe("form");
    expect(loginScope?.fieldOpids).toHaveLength(2);
    expect(registrationScope?.roles).toContain("newPassword");

    const intent = resolveAutofillIntent(report, {
      username: "alice@example.com",
      password: "secret"
    });

    expect(intent.kind).toBe("login");
    expect(intent.scopeKey).toBe("form:form-0");
  });

  it("prefers explicit password-change intent when current and new passwords share a scope", () => {
    document.body.innerHTML = `
      <form id="change-password">
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const intent = resolveAutofillIntent(report, {
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect(intent.kind).toBe("passwordChange");
    expect(intent.scopeKey).toBe("form:form-0");
  });
});
