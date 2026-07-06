import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

describe("login detection fill flow", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills a tel username field when it is marked as the login username", () => {
    document.body.innerHTML = `
      <form>
        <label for="phone-login">Phone</label>
        <input id="phone-login" type="tel" name="phone" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "+15551234567", password: "secret" });

    expect((document.querySelector("#phone-login") as HTMLInputElement).value).toBe(
      "+15551234567"
    );
    expect((document.querySelector('input[type="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("skips registration password fields when a login form is also present", () => {
    document.body.innerHTML = `
      <form id="register-form">
        <h2>Create account</h2>
        <input name="signup_email" type="email" autocomplete="email" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
      <form id="login-form">
        <h2>Sign in</h2>
        <input name="login_user" type="text" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice", password: "login-secret" });

    expect((document.querySelector('input[name="signup_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="confirm_password"]') as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector('input[name="login_user"]') as HTMLInputElement).value).toBe(
      "alice"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "login-secret"
    );
  });

  it("does not fill a newsletter-only email field", () => {
    document.body.innerHTML = `
      <form class="newsletter-signup">
        <h2>Subscribe to our newsletter</h2>
        <input name="email" type="email" placeholder="Email address" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
  });

  it("still fills a username-first login step when no password field is present", () => {
    document.body.innerHTML = `
      <main>
        <h1>Sign in</h1>
        <form>
          <input name="email" type="email" autocomplete="username" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
  });

  it("fills the checked-in username-first smoke page", () => {
    loadSmokeBody("username-first-login.html");

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(
      (document.querySelector("#vaultkern-smoke-username-first-email") as HTMLInputElement).value
    ).toBe("alice@example.com");
  });

  it("fills the checked-in password-step smoke page", () => {
    loadSmokeBody("password-step-login.html");

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(
      (document.querySelector("#vaultkern-smoke-password-step-password") as HTMLInputElement).value
    ).toBe("secret");
  });

  it("fills only the login fields in the checked-in noisy smoke page", () => {
    loadSmokeBody("noisy-login.html");

    fillLoginForm({ username: "alice", password: "login-secret" });

    expect((document.querySelector("#vaultkern-smoke-query") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#vaultkern-smoke-newsletter-email") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#vaultkern-smoke-signup-email") as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector("#vaultkern-smoke-new-password") as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector("#vaultkern-smoke-noisy-user") as HTMLInputElement).value).toBe(
      "alice"
    );
    expect(
      (document.querySelector("#vaultkern-smoke-noisy-password") as HTMLInputElement).value
    ).toBe("login-secret");
  });
});
