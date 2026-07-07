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

  it("chooses a focused registration scope without letting registration preempt default login", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="login_email" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
      <form id="register">
        <h2>Create account</h2>
        <input id="register-email" name="register_email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(
      resolveAutofillIntent(report, {
        username: "alice@example.com",
        password: "secret"
      })
    ).toMatchObject({ kind: "login", scopeKey: "form:form-0" });

    (document.querySelector("#register-email") as HTMLInputElement).focus();
    const focusedReport = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(
      resolveAutofillIntent(focusedReport, {
        username: "new@example.com",
        password: "generated-secret"
      })
    ).toMatchObject({ kind: "registration", scopeKey: "form:form-1" });
  });

  it("routes registration payloads only when no login/password-step scope is stronger", () => {
    document.body.innerHTML = `
      <form id="register">
        <h2>Create account</h2>
        <input name="register_email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    let report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(resolveAutofillIntent(report, { username: "new@example.com", password: "secret" }))
      .toMatchObject({ kind: "registration", scopeKey: "form:form-0" });

    document.body.innerHTML = `
      <form id="register">
        <h2>Create account</h2>
        <input name="register_email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
      <form id="password-step">
        <h2>Sign in</h2>
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
    `;
    report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(resolveAutofillIntent(report, { username: "new@example.com", password: "secret" }))
      .toMatchObject({ kind: "passwordStep", scopeKey: "form:form-1" });
    expect(resolveAutofillIntent(report, { password: "secret" })).toMatchObject({
      kind: "passwordStep",
      scopeKey: "form:form-1"
    });
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

  it("does not let an unfocused password-change scope preempt a focused login scope", () => {
    document.body.innerHTML = `
      <form id="login">
        <input id="login-email" name="login_email" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
      <form id="change-password">
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#login-email") as HTMLInputElement).focus();

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const intent = resolveAutofillIntent(report, {
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect(intent.kind).toBe("login");
    expect(intent.scopeKey).toBe("form:form-0");
  });
});
