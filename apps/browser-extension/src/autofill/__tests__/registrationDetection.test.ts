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
