import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

describe("registration detection fill flow", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills username new password and confirmation fields on a registration form", () => {
    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "generated-secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "generated-secret"
    );
    expect(
      (document.querySelector('input[name="confirm_password"]') as HTMLInputElement).value
    ).toBe("generated-secret");
  });

  it("fills the focused registration form when login and registration forms coexist", () => {
    document.body.innerHTML = `
      <form id="login-form">
        <h2>Sign in</h2>
        <input name="login_user" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
      <form id="register-form">
        <h2>Create account</h2>
        <input id="register-email" name="register_email" type="email" autocomplete="username" />
        <input name="register_new_password" type="password" autocomplete="new-password" />
        <input name="register_confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#register-email") as HTMLInputElement).focus();

    fillLoginForm({ username: "new@example.com", password: "generated-secret" });

    expect((document.querySelector('input[name="login_user"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="register_email"]') as HTMLInputElement).value
    ).toBe("new@example.com");
    expect(
      (document.querySelector('input[name="register_new_password"]') as HTMLInputElement).value
    ).toBe("generated-secret");
    expect(
      (document.querySelector('input[name="register_confirm_password"]') as HTMLInputElement).value
    ).toBe("generated-secret");
  });

  it("keeps the login form as the default target when a login form and registration form coexist", () => {
    document.body.innerHTML = `
      <form id="login-form">
        <h2>Sign in</h2>
        <input name="login_user" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
      <form id="register-form">
        <h2>Create account</h2>
        <input name="register_email" type="email" autocomplete="username" />
        <input name="register_new_password" type="password" autocomplete="new-password" />
        <input name="register_confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "current-secret" });

    expect((document.querySelector('input[name="login_user"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "current-secret"
    );
    expect(
      (document.querySelector('input[name="register_email"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="register_new_password"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="register_confirm_password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("keeps form-less login fields separate from unrelated registration fields", () => {
    document.body.innerHTML = `
      <input id="login-user" name="login_email" type="email" autocomplete="username" />
      <input id="login-password" name="login_password" type="password" autocomplete="current-password" />
      <input id="signup-password" name="signup_password" type="password" autocomplete="new-password" />
    `;
    (document.querySelector("#login-password") as HTMLInputElement).focus();

    fillLoginForm({ username: "alice@example.com", password: "current-secret" });

    expect((document.querySelector("#login-user") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "current-secret"
    );
    expect((document.querySelector("#signup-password") as HTMLInputElement).value).toBe("");
  });

  it("does not treat a current-password change form as registration", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input id="current-password" name="current_password" type="password" autocomplete="current-password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#current-password") as HTMLInputElement).focus();

    fillLoginForm({ password: "current-secret" });

    expect((document.querySelector("#current-password") as HTMLInputElement).value).toBe(
      "current-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("keeps a focused username-first login ahead of a separate signup form", () => {
    document.body.innerHTML = `
      <form id="login-form">
        <h2>Sign in</h2>
        <input id="login-email" name="login_email" type="email" autocomplete="username" />
      </form>
      <form id="register-form">
        <h2>Create account</h2>
        <input id="register-email" name="register_email" type="email" autocomplete="username" />
        <input id="register-password" name="register_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#login-email") as HTMLInputElement).focus();

    fillLoginForm({ username: "alice@example.com", password: "current-secret" });

    expect((document.querySelector("#login-email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#register-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-password") as HTMLInputElement).value).toBe("");
  });

  it("routes to a registration form when a non-credential field in that form is focused", () => {
    document.body.innerHTML = `
      <form id="login-form">
        <h2>Sign in</h2>
        <input name="login_user" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
      <form id="register-form">
        <h2>Create account</h2>
        <input id="first-name" name="first_name" type="text" />
        <input name="register_email" type="email" autocomplete="username" />
        <input name="register_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#first-name") as HTMLInputElement).focus();

    fillLoginForm({ username: "new@example.com", password: "generated-secret" });

    expect((document.querySelector('input[name="login_user"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="register_email"]') as HTMLInputElement).value
    ).toBe("new@example.com");
    expect(
      (document.querySelector('input[name="register_password"]') as HTMLInputElement).value
    ).toBe("generated-secret");
  });

  it("fills a mixed registration form primary password and confirmation", () => {
    document.body.innerHTML = `
      <form>
        <input id="email" name="email" type="email" autocomplete="username" />
        <input id="primary-password" name="password" type="password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#email") as HTMLInputElement).focus();

    fillLoginForm({ username: "new@example.com", password: "generated-secret" });

    expect((document.querySelector("#email") as HTMLInputElement).value).toBe("new@example.com");
    expect((document.querySelector("#primary-password") as HTMLInputElement).value).toBe(
      "generated-secret"
    );
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe(
      "generated-secret"
    );
  });

  it("does not route unannotated current-password change forms through registration", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input id="current-password" name="current_password" type="password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#current-password") as HTMLInputElement).focus();

    fillLoginForm({ password: "current-secret" });

    expect((document.querySelector("#current-password") as HTMLInputElement).value).toBe(
      "current-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("falls back to registration when focus is in an unrelated non-credential form", () => {
    document.body.innerHTML = `
      <form id="search-form">
        <input id="search" name="q" type="search" />
      </form>
      <form id="register-form">
        <h2>Create account</h2>
        <input id="email" name="email" type="email" autocomplete="username" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#search") as HTMLInputElement).focus();

    fillLoginForm({ username: "new@example.com", password: "generated-secret" });

    expect((document.querySelector("#email") as HTMLInputElement).value).toBe("new@example.com");
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe(
      "generated-secret"
    );
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe(
      "generated-secret"
    );
  });

  it("does not treat reset-only new-password forms as registration", () => {
    document.body.innerHTML = `
      <form>
        <h2>Reset password</h2>
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "current-secret" });

    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("fills the checked-in registration smoke page", () => {
    loadSmokeBody("register.html");

    fillLoginForm({ username: "alice@example.com", password: "generated-secret" });

    expect(
      (document.querySelector("#vaultkern-smoke-register-email") as HTMLInputElement).value
    ).toBe("alice@example.com");
    expect(
      (document.querySelector("#vaultkern-smoke-register-new-password") as HTMLInputElement).value
    ).toBe("generated-secret");
    expect(
      (document.querySelector("#vaultkern-smoke-register-confirm-password") as HTMLInputElement)
        .value
    ).toBe("generated-secret");
  });
});
