import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";
import { applyFillPlan } from "../applyFillPlan";
import { collectAutofillPageSnapshot } from "../collectPageFields";
import { createLoginFillPlan } from "../fillPlan";

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

  it("falls back to a single generic email field for username-first fill", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
  });

  it("falls back to a single text email field for username-first fill", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="text" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
  });

  it("falls back to a single generic email field for username-only fill", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
  });

  it("fills login fields collected from open shadow roots", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <form>
        <input name="shadow_email" type="email" autocomplete="username" />
        <input name="shadow_password" type="password" autocomplete="current-password" />
      </form>
    `;

    document.body.insertAdjacentHTML(
      "beforeend",
      `
        <form>
          <input name="light_email" type="email" autocomplete="username" />
          <input name="light_password" type="password" autocomplete="current-password" />
        </form>
      `
    );

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((root.querySelector('input[name="shadow_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((root.querySelector('input[name="shadow_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
    expect((document.querySelector('input[name="light_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="light_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("honors current-password autocomplete in mixed sign-in and create-account copy", () => {
    document.body.innerHTML = `
      <main>
        <h1>Create account or sign in</h1>
        <form>
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("fills username-like fields in mixed sign-in forms without username autocomplete", () => {
    document.body.innerHTML = `
      <main>
        <h1>Create account or sign in</h1>
        <form>
          <input name="email" type="email" />
          <input name="password" type="password" autocomplete="current-password" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("fills mixed sign-in forms when the password omits autocomplete", () => {
    document.body.innerHTML = `
      <main>
        <h1>Create account or sign in</h1>
        <form>
          <input name="email" type="email" />
          <input name="password" type="password" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("prefers the same form-less container when pairing login fields", () => {
    document.body.innerHTML = `
      <input name="unrelated_username" autocomplete="username" />
      <div>
        <input name="login_email" type="email" />
        <input name="login_password" type="password" />
      </div>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="unrelated_username"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("preserves password fills for unscoped form-less login fields", () => {
    document.body.innerHTML = `
      <section>
        <input name="login_email" type="email" autocomplete="username" />
      </section>
      <section>
        <input name="login_password" type="password" />
      </section>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("preserves current-password fills for unscoped form-less login fields", () => {
    document.body.innerHTML = `
      <section>
        <input name="login_email" type="email" autocomplete="username" />
      </section>
      <section>
        <input name="login_password" type="password" autocomplete="current-password" />
      </section>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("keeps password fallback near an unscoped username when settings fields follow", () => {
    document.body.innerHTML = `
      <section>
        <input name="login_email" type="email" autocomplete="username" />
      </section>
      <section>
        <input name="login_password" type="password" />
      </section>
      <form id="settings">
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
    expect((document.querySelector('input[name="current_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("does not fill username-first signup forms", () => {
    document.body.innerHTML = `
      <main>
        <h1>Create account</h1>
        <form>
          <input name="signup_user" autocomplete="username" />
          <input name="new_password" type="password" autocomplete="new-password" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="signup_user"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("applies fill plans to fields from another document realm", () => {
    const iframe = document.createElement("iframe");
    document.body.append(iframe);
    const frameDocument = iframe.contentDocument!;
    frameDocument.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const plan = createLoginFillPlan(collectAutofillPageSnapshot(frameDocument), {
      username: "alice@example.com",
      password: "secret"
    });
    applyFillPlan(plan, frameDocument);

    expect((frameDocument.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((frameDocument.querySelector('input[name="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("scopes current-password preference to the selected login form", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="login_email" type="email" />
        <input name="login_password" type="password" />
      </form>
      <form id="settings">
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
    expect((document.querySelector('input[name="current_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("prefers explicit username hints inside a shared form-less container", () => {
    document.body.innerHTML = `
      <div>
        <input name="user" type="text" />
        <input name="login_email" type="email" autocomplete="username" />
        <input name="login_password" type="password" />
      </div>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="user"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      "secret"
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
