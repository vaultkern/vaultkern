import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

describe("password change detection fill flow", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills current new and confirmation password fields", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect(
      (document.querySelector('input[name="confirm_new_password"]') as HTMLInputElement).value
    ).toBe("new-secret");
  });

  it("fills container-scoped password change widgets without a form", () => {
    document.body.innerHTML = `
      <section id="account-panel">
        <h2>Change password</h2>
        <input id="current-password" name="current_password" type="password" autocomplete="current-password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </section>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector("#current-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("requires explicit change context for container-scoped password changes", () => {
    document.body.innerHTML = `
      <section id="account-panel">
        <input id="current-password" name="current_password" type="password" autocomplete="current-password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </section>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector("#current-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("fills the username in a change-password form when one is required", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="email" type="email" autocomplete="username" />
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect(
      (document.querySelector('input[name="confirm_new_password"]') as HTMLInputElement).value
    ).toBe("new-secret");
  });

  it("uses autocomplete roles even when the current password is not first", () => {
    document.body.innerHTML = `
      <form>
        <h2>Update credentials</h2>
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector('input[name="confirm_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("fills a two-password-field change form only when the context is explicit", () => {
    document.body.innerHTML = `
      <form>
        <h2>Update password</h2>
        <input name="old_password" type="password" />
        <input name="new_password" type="password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector('input[name="old_password"]') as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("keeps old password fields current when the form is headed new password", () => {
    document.body.innerHTML = `
      <form>
        <h2>New password</h2>
        <input id="old-password" name="old_password" type="password" />
        <input id="new-password" name="new_password" type="password" />
        <input id="confirm-password" name="confirm_password" type="password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector("#old-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("does not use a generic reset password field as the current password", () => {
    document.body.innerHTML = `
      <form>
        <h2>Reset password</h2>
        <input id="password-field" name="password" type="password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector("#password-field") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("does not group form-less current and new password fields as one change form", () => {
    document.body.innerHTML = `
      <input id="login-password" name="login_password" type="password" autocomplete="current-password" />
      <input id="signup-password" name="signup_password" type="password" autocomplete="new-password" />
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#signup-password") as HTMLInputElement).value).toBe("");
  });

  it("keeps form-less login fields fillable beside signup fields", () => {
    document.body.innerHTML = `
      <input id="login-user" name="username" autocomplete="username" />
      <input id="login-password" name="password" type="password" />
      <input id="signup-password" name="signup_password" type="password" autocomplete="new-password" />
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect((document.querySelector("#login-user") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#signup-password") as HTMLInputElement).value).toBe("");
  });

  it("keeps same-form login passwords fillable beside signup fields", () => {
    document.body.innerHTML = `
      <form>
        <section>
          <h2>Sign in</h2>
          <input id="login-user" name="username" autocomplete="username" />
          <input id="login-password" name="password" type="password" />
        </section>
        <section>
          <h2>Password setup</h2>
          <input id="signup-password" name="signup_password" type="password" autocomplete="new-password" />
        </section>
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect((document.querySelector("#login-user") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#signup-password") as HTMLInputElement).value).toBe("");
  });

  it("does not let an unfocused change-password form preempt a focused login form", () => {
    document.body.innerHTML = `
      <form id="login">
        <input id="login-user" name="username" autocomplete="username" />
        <input id="login-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="change">
        <h2>Change password</h2>
        <input id="change-current" name="current_password" type="password" autocomplete="current-password" />
        <input id="change-new" name="new_password" type="password" autocomplete="new-password" />
        <input id="change-confirm" name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;
    (document.querySelector("#login-user") as HTMLInputElement).focus();

    fillLoginForm({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });

    expect((document.querySelector("#login-user") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#change-current") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#change-new") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#change-confirm") as HTMLInputElement).value).toBe("");
  });

  it("does not put the current password into new-password fields when no new password is supplied", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector('input[name="confirm_new_password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("fills the checked-in change-password smoke page", () => {
    loadSmokeBody("change-password.html");

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector("#vaultkern-smoke-change-current-password") as HTMLInputElement).value
    ).toBe("old-secret");
    expect(
      (document.querySelector("#vaultkern-smoke-change-new-password") as HTMLInputElement).value
    ).toBe("new-secret");
    expect(
      (document.querySelector("#vaultkern-smoke-change-confirm-password") as HTMLInputElement).value
    ).toBe("new-secret");
  });
});
