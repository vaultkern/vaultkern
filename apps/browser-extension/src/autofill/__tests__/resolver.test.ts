import { describe, expect, it } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { resolveAutofillIntent } from "../intent";
import { resolveCredentialScopes, resolveFocusedPhysicalScope } from "../scope";
import { triageAutofillPage } from "../triage";
import { useDomRenderEnvironment } from "./renderEnvironment";

useDomRenderEnvironment();

describe("autofill scope and intent resolver", () => {
  it("emits explicit username and TOTP step intents", () => {
    document.body.innerHTML = `
      <form action="/login"><input name="email" type="email" autocomplete="username" /></form>
    `;
    let report = triageAutofillPage(collectAutofillPageSnapshot(document));
    expect(resolveAutofillIntent(report, { username: "alice@example.com" }).kind).toBe(
      "usernameStep"
    );

    document.body.innerHTML = `
      <form><h2>Authenticator code</h2><input name="totp_code" autocomplete="one-time-code" inputmode="numeric" /></form>
    `;
    report = triageAutofillPage(collectAutofillPageSnapshot(document));
    expect(resolveAutofillIntent(report, { totp: "123456" }).kind).toBe("totpStep");
  });

  it("fails closed when two no-focus login scopes are equally viable", () => {
    document.body.innerHTML = `
      <form aria-label="Sign in">
        <input name="first_email" type="email" autocomplete="username" />
        <input name="first_password" type="password" autocomplete="current-password" />
      </form>
      <form aria-label="Sign in">
        <input name="second_email" type="email" autocomplete="username" />
        <input name="second_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(
      resolveAutofillIntent(report, {
        username: "alice@example.com",
        password: "secret"
      })
    ).toMatchObject({ kind: "ambiguous", fis: [] });
  });

  it("does not let stronger login evidence hide another viable no-focus login scope", () => {
    document.body.innerHTML = `
      <form aria-label="Sign in">
        <input name="strong_email" type="email" autocomplete="username" />
        <input name="strong_password" type="password" autocomplete="current-password" />
      </form>
      <form>
        <input name="weak_email" type="email" autocomplete="username" />
        <input name="weak_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(
      resolveAutofillIntent(report, {
        username: "alice@example.com",
        password: "secret"
      })
    ).toMatchObject({ kind: "ambiguous", fis: [] });
  });

  it("fails closed when two no-focus TOTP scopes are equally viable", () => {
    document.body.innerHTML = `
      <form aria-label="Authenticator code">
        <input name="first_totp" autocomplete="one-time-code" inputmode="numeric" />
      </form>
      <form aria-label="Authenticator code">
        <input name="second_totp" autocomplete="one-time-code" inputmode="numeric" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(resolveAutofillIntent(report, { totp: "123456" })).toMatchObject({
      kind: "ambiguous",
      fis: []
    });
  });

  it.each([
    {
      name: "password reset",
      markup: `
        <form aria-label="Reset password">
          <input name="first_new" type="password" autocomplete="new-password" />
        </form>
        <form aria-label="Reset password">
          <input name="second_new" type="password" autocomplete="new-password" />
        </form>
      `,
      payload: { newPassword: "new-secret" }
    },
    {
      name: "registration",
      markup: `
        <form aria-label="Create account">
          <input name="first_new" type="password" autocomplete="new-password" />
        </form>
        <form aria-label="Create account">
          <input name="second_new" type="password" autocomplete="new-password" />
        </form>
      `,
      payload: { newPassword: "new-secret" }
    },
    {
      name: "password change",
      markup: `
        <form aria-label="Change password">
          <input name="first_current" type="password" autocomplete="current-password" />
          <input name="first_new" type="password" autocomplete="new-password" />
        </form>
        <form aria-label="Change password">
          <input name="second_current" type="password" autocomplete="current-password" />
          <input name="second_new" type="password" autocomplete="new-password" />
        </form>
      `,
      payload: { password: "old-secret", newPassword: "new-secret" }
    },
    {
      name: "username step",
      markup: `
        <form action="/login"><input name="first_user" autocomplete="username" /></form>
        <form action="/login"><input name="second_user" autocomplete="username" /></form>
      `,
      payload: { username: "alice@example.com" }
    },
    {
      name: "password step",
      markup: `
        <form aria-label="Sign in"><input name="first_password" type="password" /></form>
        <form aria-label="Sign in"><input name="second_password" type="password" /></form>
      `,
      payload: { password: "secret" }
    }
  ])("fails closed when two no-focus $name scopes are equally viable", ({ markup, payload }) => {
    document.body.innerHTML = markup;
    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(resolveAutofillIntent(report, payload)).toMatchObject({
      kind: "ambiguous",
      fis: []
    });
  });

  it("emits password reset intent for proven reset roles", () => {
    document.body.innerHTML = `
      <form action="/password/reset">
        <h2>Reset password</h2>
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="password_confirmation" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    expect(resolveAutofillIntent(report, { newPassword: "new-secret" }).kind).toBe(
      "passwordReset"
    );
  });

  it("distinguishes non-credential and ambiguous scopes", () => {
    document.body.innerHTML = `<form><input name="query" type="search" /></form>`;
    let report = triageAutofillPage(collectAutofillPageSnapshot(document));
    expect(resolveAutofillIntent(report, { username: "alice@example.com" }).kind).toBe(
      "nonCredential"
    );

    document.body.innerHTML = `
      <form>
        <input name="username" autocomplete="username" />
        <input name="password" type="password" />
        <input name="new_password" type="password" />
        <input name="password_confirmation" type="password" />
      </form>
    `;
    report = triageAutofillPage(collectAutofillPageSnapshot(document));
    expect(
      resolveAutofillIntent(report, {
        username: "alice@example.com",
        password: "old-secret"
      }).kind
    ).toBe("ambiguous");
  });

  it("focused reset physical scope preserves ignored boundary evidence", () => {
    document.body.innerHTML = `
      <form id="reset-password" aria-label="Reset password">
        <input id="reset-search" name="query" type="search" autocomplete="off" />
      </form>
      <form id="register">
        <input name="email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#reset-search") as HTMLInputElement).focus();

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const focusedScope = resolveFocusedPhysicalScope(report.f);

    expect(report.f.every((field) => field.so.length > 0)).toBe(true);
    expect(focusedScope?.key).toBe("form:form-0");
    expect(focusedScope?.fields).toHaveLength(1);
    expect(focusedScope?.fields[0]).toMatchObject({
      o: "field-0",
      q: "ignored"
    });
  });

  it("groups credential fields by form and rejects no-focus login and registration ambiguity", () => {
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
    const scopes = resolveCredentialScopes(report.f);
    const loginScope = scopes.find((scope) => scope.k === "form:form-0");
    const registrationScope = scopes.find((scope) => scope.k === "form:form-1");

    expect(loginScope?.kind).toBe("form");
    expect(loginScope?.fis).toHaveLength(2);
    expect(registrationScope?.rl).toContain("newPassword");

    const intent = resolveAutofillIntent(report, {
      username: "alice@example.com",
      password: "secret"
    });

    expect(intent).toMatchObject({ kind: "ambiguous", fis: [] });
  });

  it("requires focus to choose registration when login and registration coexist", () => {
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
    ).toMatchObject({ kind: "ambiguous", fis: [] });

    (document.querySelector("#register-email") as HTMLInputElement).focus();
    const focusedReport = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(
      resolveAutofillIntent(focusedReport, {
        username: "new@example.com",
        password: "generated-secret"
      })
    ).toMatchObject({ kind: "registration", sk: "form:form-1" });
  });

  it("keeps no-focus registration and login-step scopes ambiguous", () => {
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
      .toMatchObject({ kind: "registration", sk: "form:form-0" });

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
      .toMatchObject({ kind: "ambiguous", fis: [] });
    expect(resolveAutofillIntent(report, { password: "secret" })).toMatchObject({
      kind: "login",
      sk: "form:form-1"
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
    expect(intent.sk).toBe("form:form-0");
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
    expect(intent.sk).toBe("form:form-0");
  });
});
