import { beforeEach, describe, expect, it } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { triageAutofillPage } from "../triage";

function fieldByName(report: ReturnType<typeof triageAutofillPage>, htmlName: string) {
  const field = report.fields.find((candidate) => candidate.htmlName === htmlName);
  expect(field, `expected field named ${htmlName}`).toBeDefined();
  return field!;
}

describe("autofill triage", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("classifies a standard login form and keeps the field context explainable", () => {
    document.body.innerHTML = `
      <main>
        <section>
          <h2>Sign in</h2>
          <form id="login-form" name="login" action="/login" method="post">
            <label for="login-email">Email address</label>
            <input
              id="login-email"
              name="username"
              type="email"
              autocomplete="username"
              placeholder="you@example.com"
              aria-describedby="email-help"
              data-login-field="user"
            />
            <span id="email-help">Use your account email.</span>
            <label for="login-password">Password</label>
            <input
              id="login-password"
              name="password"
              type="password"
              autocomplete="current-password"
              value="secret"
            />
          </form>
        </section>
      </main>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);
    const username = fieldByName(report, "username");
    const password = fieldByName(report, "password");

    expect(username.eligible).toBe(true);
    expect(username.qualifiedAs).toBe("username");
    expect(username.reasons).toContain("autocomplete:username");
    expect(username.reasons).toContain("form-has-password");
    expect(username.labelText).toBe("Email address");
    expect(username.placeholder).toBe("you@example.com");
    expect(username.ariaDescribedBy).toBe("email-help");
    expect(username.dataSetValues).toContain("user");
    expect(username.formContext).toMatchObject({
      htmlId: "login-form",
      htmlName: "login",
      htmlMethod: "post",
      headingText: ["Sign in"]
    });

    expect(password.eligible).toBe(true);
    expect(password.qualifiedAs).toBe("password");
    expect(password.reasons).toContain("autocomplete:current-password");
    expect(password.valuePreview).toBeUndefined();
  });

  it("marks readonly disabled and hidden fields as not fillable", () => {
    document.body.innerHTML = `
      <form>
        <input name="readonly_user" type="text" readonly />
        <input name="disabled_user" type="text" disabled />
        <fieldset disabled>
          <input name="fieldset_disabled_user" type="email" autocomplete="username" />
        </fieldset>
        <input name="hidden_user" type="text" hidden />
        <input name="css_hidden_user" type="text" style="display:none" />
        <div hidden>
          <input name="ancestor_hidden_user" type="email" autocomplete="username" />
        </div>
        <div style="display:none">
          <input name="ancestor_css_hidden_user" type="email" autocomplete="username" />
        </div>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "readonly_user")).toMatchObject({
      eligible: false,
      fillable: false,
      qualifiedAs: "ignored"
    });
    expect(fieldByName(report, "readonly_user").reasons).toContain("not-fillable:readonly");
    expect(fieldByName(report, "disabled_user").reasons).toContain("not-fillable:disabled");
    expect(fieldByName(report, "fieldset_disabled_user").reasons).toContain(
      "not-fillable:disabled"
    );
    expect(fieldByName(report, "hidden_user").reasons).toContain("not-viewable:hidden");
    expect(fieldByName(report, "css_hidden_user").reasons).toContain("not-viewable:css");
    expect(fieldByName(report, "ancestor_hidden_user").reasons).toContain(
      "not-viewable:hidden"
    );
    expect(fieldByName(report, "ancestor_css_hidden_user").reasons).toContain(
      "not-viewable:css"
    );
  });

  it("excludes search newsletter captcha and forgot-password fields from login qualification", () => {
    document.body.innerHTML = `
      <form id="search">
        <input name="query" type="search" placeholder="Search" />
      </form>
      <form id="newsletter" class="newsletter-signup">
        <h2>Subscribe to our newsletter</h2>
        <input name="newsletter_email" type="email" placeholder="Email" />
      </form>
      <form id="login">
        <input name="captcha_code" type="text" placeholder="Captcha" />
        <input name="forgot_email" type="email" placeholder="Forgot password email" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "query").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "query").reasons).toContain("excluded:search");
    expect(fieldByName(report, "newsletter_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "newsletter_email").reasons).toContain("non-login:newsletter");
    expect(fieldByName(report, "captcha_code").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "captcha_code").reasons).toContain("excluded:captcha");
    expect(fieldByName(report, "forgot_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "forgot_email").reasons).toContain("excluded:forgot");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("excludes forgot-password fields when the signal is in the form context", () => {
    document.body.innerHTML = `
      <form id="forgot" action="/forgot-password">
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("excluded:forgot");
  });

  it("keeps captcha form metadata from excluding real login fields", () => {
    document.body.innerHTML = `
      <form id="login" class="login g-recaptcha" action="/login-with-captcha">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
        <input name="captcha_code" type="text" placeholder="Captcha" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "captcha_code").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "captcha_code").reasons).toContain("excluded:captcha");
  });

  it("uses preceding headings outside semantic containers as form context", () => {
    document.body.innerHTML = `
      <h2>Forgot password</h2>
      <form id="forgot">
        <input name="email" type="email" />
      </form>
      <h2>Sign in</h2>
      <form id="login">
        <input name="login_email" type="email" autocomplete="username" />
        <input name="login_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "forgot")).toMatchObject({
      headingText: ["Forgot password"]
    });
    expect(snapshot.forms.find((form) => form.htmlId === "login")).toMatchObject({
      headingText: ["Sign in"]
    });
    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("excluded:forgot");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
  });

  it("does not classify new-password fields or non-text controls as login candidates", () => {
    document.body.innerHTML = `
      <form>
        <input name="create_password" type="password" autocomplete="new-password" />
        <input name="login" type="submit" value="Sign in" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "create_password").qualifiedAs).not.toBe("password");
    expect(fieldByName(report, "login").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats offscreen and transparent honeypot fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="offscreen_email" type="email" autocomplete="username" style="position:absolute;left:-9999px" />
        <input name="transparent_email" type="email" autocomplete="username" style="opacity:0" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "offscreen_email").reasons).toContain("not-viewable:offscreen");
    expect(fieldByName(report, "transparent_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "transparent_email").reasons).toContain("not-viewable:transparent");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("does not copy later sibling section headings into an earlier form context", () => {
    document.body.innerHTML = `
      <section>
        <h2>Sign in</h2>
        <form id="login-form">
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
        </form>
        <h2>Subscribe to our newsletter</h2>
        <form id="newsletter-form">
          <input name="newsletter_email" type="email" />
        </form>
      </section>
    `;

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.forms.find((form) => form.htmlId === "login-form")).toMatchObject({
      headingText: ["Sign in"]
    });
    expect(snapshot.forms.find((form) => form.htmlId === "newsletter-form")).toMatchObject({
      headingText: ["Subscribe to our newsletter"]
    });
  });

  it("captures select textarea labels and form metadata without collecting secret values", () => {
    document.body.innerHTML = `
      <section>
        <h1>Account recovery</h1>
        <form id="profile-form" class="account-form" action="/profile">
          <label for="country">Country</label>
          <select id="country" name="country">
            <option value="">Choose</option>
            <option value="us">United States</option>
          </select>
          <label>
            Notes
            <textarea name="notes">private note</textarea>
          </label>
        </form>
      </section>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const country = snapshot.fields.find((field) => field.htmlName === "country");
    const notes = snapshot.fields.find((field) => field.htmlName === "notes");

    expect(country).toMatchObject({
      tagName: "select",
      labelText: "Country",
      htmlName: "country"
    });
    expect(country?.selectOptions).toEqual(["", "us"]);
    expect(notes).toMatchObject({
      tagName: "textarea",
      labelText: "Notes"
    });
    expect(country).not.toHaveProperty("value");
    expect(notes).not.toHaveProperty("value");
    expect(snapshot.forms[0]).toMatchObject({
      htmlId: "profile-form",
      htmlClass: "account-form",
      htmlAction: new URL("/profile", document.location.href).href,
      headingText: ["Account recovery"]
    });
  });
});
