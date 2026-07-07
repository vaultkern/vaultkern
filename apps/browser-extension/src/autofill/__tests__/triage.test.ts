import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { triageAutofillPage } from "../triage";

function fieldByName(report: ReturnType<typeof triageAutofillPage>, htmlName: string) {
  const field = report.fields.find((candidate) => candidate.htmlName === htmlName);
  expect(field, `expected field named ${htmlName}`).toBeDefined();
  return field!;
}

describe("autofill triage", () => {
  beforeEach(() => {
    document.head.innerHTML = "";
    window.history.replaceState(null, "", "/");
    document.body.innerHTML = "";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
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

  it("keeps explicitly visible descendants of visibility-hidden ancestors viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="visibility:hidden">
          <input name="email" type="email" autocomplete="username" style="visibility:visible" />
          <input name="password" type="password" autocomplete="current-password" style="visibility:visible" />
        </div>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("honors stylesheet visibility overrides under hidden ancestors", () => {
    document.head.innerHTML = `
      <style>
        .visible-login-field { visibility: visible; }
      </style>
    `;
    document.body.innerHTML = `
      <form>
        <div style="visibility:hidden">
          <input name="email" class="visible-login-field" type="email" autocomplete="username" />
          <input name="password" class="visible-login-field" type="password" autocomplete="current-password" />
        </div>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("treats fields clipped by zero-sized ancestors as hidden", () => {
    document.body.innerHTML = `
      <form>
        <div style="width:0;height:0;overflow:hidden">
          <input name="decoy_email" type="email" autocomplete="username" />
        </div>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "decoy_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "decoy_email").reasons).toContain("not-viewable:zero-size");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
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

  it("excludes search reset and recovery forms from login triage", () => {
    document.body.innerHTML = `
      <form id="site-search" action="/search">
        <input name="email" type="email" />
      </form>
      <form id="reset" action="/reset-password">
        <input name="reset_email" type="email" />
        <input name="reset_password" type="password" />
      </form>
      <form id="recovery">
        <h2>Account recovery</h2>
        <input name="recovery_email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("excluded:search");
    expect(fieldByName(report, "reset_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "reset_email").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "reset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "reset_password").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "recovery_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "recovery_email").reasons).toContain("excluded:recovery");
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

  it("preserves heading context through neutral wrapper divs", () => {
    document.body.innerHTML = `
      <div>
        <h2>Sign in</h2>
        <div>
          <form id="wrapped-login">
            <input name="wrapped_email" type="email" />
          </form>
        </div>
      </div>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "wrapped-login")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "wrapped_email").qualifiedAs).toBe("username");
  });

  it("keeps climbing past wrappers with only later headings", () => {
    document.body.innerHTML = `
      <div>
        <h2>Sign in</h2>
        <div>
          <form>
            <input name="email" type="email" />
          </form>
          <h2>Help</h2>
        </div>
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("keeps parent auth headings with neutral subheadings", () => {
    document.body.innerHTML = `
      <main>
        <h1>Create account</h1>
        <h2>Your details</h2>
        <form>
          <input name="email" type="email" />
          <input name="password" type="password" />
        </form>
      </main>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms[0].headingText).toEqual(["Create account", "Your details"]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
  });

  it("ignores hidden headings when building form context", () => {
    document.body.innerHTML = `
      <div hidden>
        <h2>Create account</h2>
      </div>
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("ignores hidden previous forms when bounding preceding form headings", () => {
    document.body.innerHTML = `
      <h2>Sign in</h2>
      <form hidden>
        <input name="template_email" type="email" />
      </form>
      <form id="visible-passwordless">
        <input name="visible_email" type="email" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(
      snapshot.forms.find((form) => form.htmlId === "visible-passwordless")?.headingText
    ).toEqual(["Sign in"]);
    expect(fieldByName(report, "template_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "visible_email").qualifiedAs).toBe("username");
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

  it("suppresses usernames that only sit beside new-password fields", () => {
    document.body.innerHTML = `
      <form>
        <input name="account" autocomplete="username" />
        <input name="password" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "account").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
  });

  it("recognizes plain user identifiers when login evidence is present", () => {
    document.body.innerHTML = `
      <form>
        <label for="plain-user">User</label>
        <input id="plain-user" name="user" />
        <input name="identifier" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "identifier").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("requires login evidence for generic user and login identifiers", () => {
    document.body.innerHTML = `
      <form id="profile">
        <input name="user" type="text" />
        <input name="last_login" type="text" />
        <input name="last_login_email" type="text" />
      </form>
      <form id="login">
        <input name="login" type="text" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "user").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "last_login").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "last_login_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("uses implicit form actions and submit text as passwordless login context", () => {
    window.history.replaceState(null, "", "/login");
    document.body.innerHTML = `
      <form id="implicit-action">
        <input name="implicit_email" type="email" />
      </form>
      <form id="button-context" action="/continue">
        <input name="button_email" type="email" />
        <button type="submit">Sign in</button>
      </form>
      <form id="external-submit-context" action="/continue">
        <input name="external_submit_email" type="email" />
      </form>
      <button type="submit" form="external-submit-context">Sign in</button>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "external-submit-context")).toMatchObject({
      headingText: ["Sign in"]
    });
    expect(fieldByName(report, "implicit_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "button_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "external_submit_email").qualifiedAs).toBe("username");
  });

  it("uses submitter formaction as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="submitter-route" action="/continue">
        <input name="submitter_email" type="email" />
        <button type="submit" formaction="/login">Continue</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "submitter-route")).toMatchObject({
      htmlSubmitAction: new URL("/login", document.location.href).href
    });
    expect(fieldByName(report, "submitter_email").qualifiedAs).toBe("username");
  });

  it("keeps implicit submitter current-page targets out of negative form context", () => {
    window.history.replaceState(null, "", "/forgot-password");
    document.body.innerHTML = `
      <form id="modal-login">
        <h2>Sign in</h2>
        <input name="submitter_hash_email" type="email" />
        <input name="submitter_hash_password" type="password" />
        <button type="submit" formaction="#">Continue</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "modal-login")).toMatchObject({
      htmlSubmitActionIsImplicit: true
    });
    expect(fieldByName(report, "submitter_hash_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "submitter_hash_password").qualifiedAs).toBe("password");
  });

  it("includes external image submit controls in form context", () => {
    document.body.innerHTML = `
      <form id="image-submit-context" action="/continue">
        <input name="image_submit_email" type="email" />
      </form>
      <input type="image" form="image-submit-context" alt="Sign in" />
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "image-submit-context")).toMatchObject({
      headingText: ["Sign in"]
    });
    expect(fieldByName(report, "image_submit_email").qualifiedAs).toBe("username");
  });

  it("preserves local context for external form-associated controls", () => {
    document.body.innerHTML = `
      <form id="login" action="/login"></form>
      <div id="external-signup">
        <h2>Create account</h2>
        <input form="login" name="external_email" type="email" />
        <input form="login" name="external_password" type="password" />
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "external_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "external_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "external_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "external_password").reasons).toContain(
      "non-login:account-creation"
    );
  });

  it("treats missing and invalid button types as submit controls", () => {
    document.body.innerHTML = `
      <form id="missing-button-type" action="/continue">
        <input name="missing_type_email" type="email" />
        <button>Sign in</button>
      </form>
      <form id="invalid-button-type" action="/continue">
        <input name="invalid_type_email" type="email" />
        <button type="not-a-button-type">Sign in</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "missing-button-type")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(snapshot.forms.find((form) => form.htmlId === "invalid-button-type")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "missing_type_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "invalid_type_email").qualifiedAs).toBe("username");
  });

  it("treats empty form actions as implicit current-page actions", () => {
    window.history.replaceState(null, "", "/search");
    document.body.innerHTML = `
      <form id="empty-action" action="">
        <input name="empty_action_email" type="email" autocomplete="username" />
        <input name="empty_action_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "empty-action")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(fieldByName(report, "empty_action_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "empty_action_password").qualifiedAs).toBe("password");
  });

  it("keeps implicit page URLs out of negative form context", () => {
    window.history.replaceState(null, "", "/forgot-password");
    document.body.innerHTML = `
      <form id="modal-login">
        <h2>Sign in</h2>
        <input name="modal_email" type="email" />
        <input name="modal_password" type="password" />
      </form>
      <form id="explicit-forgot" action="/forgot-password">
        <h2>Sign in</h2>
        <input name="forgot_email" type="email" />
        <input name="forgot_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "modal_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "modal_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "forgot_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "forgot_password").qualifiedAs).toBe("ignored");
  });

  it("keeps current-page query actions out of negative form context", () => {
    window.history.replaceState(null, "", "/forgot-password");
    document.body.innerHTML = `
      <form id="modal-login" action="?login">
        <h2>Sign in</h2>
        <input name="modal_email" type="email" />
        <input name="modal_password" type="password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "modal-login")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(fieldByName(report, "modal_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "modal_password").qualifiedAs).toBe("password");
  });

  it("keeps implicit reset action fragments in negative form context", () => {
    window.history.replaceState(null, "", "/login");
    document.body.innerHTML = `
      <form id="query-reset" action="?reset-password">
        <input name="request_email" type="email" />
        <input name="request_password" type="password" />
      </form>
      <form id="hash-reset" action="#password-reset">
        <input name="fragment_email" type="email" />
        <input name="fragment_password" type="password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "query-reset")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(snapshot.forms.find((form) => form.htmlId === "hash-reset")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(fieldByName(report, "request_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "request_email").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "request_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "request_password").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "fragment_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "fragment_email").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "fragment_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "fragment_password").reasons).toContain("excluded:reset");
  });

  it("treats whitespace-only form actions as implicit current-page actions", () => {
    window.history.replaceState(null, "", "/forgot-password");
    document.body.innerHTML = `
      <form id="blank-action-login" action="   ">
        <h2>Sign in</h2>
        <input name="blank_action_email" type="email" />
        <input name="blank_action_password" type="password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "blank-action-login")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(fieldByName(report, "blank_action_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "blank_action_password").qualifiedAs).toBe("password");
  });

  it("treats hash-only form actions as implicit current-page actions", () => {
    window.history.replaceState(null, "", "/forgot-password");
    document.body.innerHTML = `
      <form id="modal-login" action="#">
        <h2>Sign in</h2>
        <input name="modal_email" type="email" />
        <input name="modal_password" type="password" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "modal-login")).toMatchObject({
      htmlActionIsImplicit: true
    });
    expect(fieldByName(report, "modal_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "modal_password").qualifiedAs).toBe("password");
  });

  it("resolves relative form actions against the document base URL", () => {
    document.head.innerHTML = `<base href="https://example.test/sign-in/" />`;
    document.body.innerHTML = `
      <form id="base-login" action="continue">
        <input name="base_email" type="email" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "base-login")).toMatchObject({
      htmlAction: "https://example.test/sign-in/continue"
    });
    expect(fieldByName(report, "base_email").qualifiedAs).toBe("username");
  });

  it("uses login hostnames in form actions as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="auth-host" action="https://login.example.com/">
        <input name="host_email" type="email" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "host_email").qualifiedAs).toBe("username");
  });

  it("uses slash-separated sign-in routes as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="slash-route" action="/sign/in">
        <input name="route_email" type="email" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "route_email").qualifiedAs).toBe("username");
  });

  it("uses nested login route segments as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="nested-login-route" action="/auth/login/continue">
        <input name="nested_route_email" type="email" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "nested_route_email").qualifiedAs).toBe("username");
  });

  it("preserves auth mode query parameters without using redirect targets as context", () => {
    document.body.innerHTML = `
      <form id="mode-login" action="/account?mode=login">
        <input name="mode_login_email" type="email" />
        <button type="submit">Continue</button>
      </form>
      <form id="mode-signup" action="/account?mode=signup">
        <input name="mode_signup_email" type="email" />
        <input name="mode_signup_password" type="password" />
      </form>
      <form id="redirect-only" action="/account?next=/login">
        <input name="redirect_only_email" type="email" />
      </form>
      <form id="hint-only" action="/account?login_hint=user@example.com">
        <input name="hint_email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "mode_login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "mode_signup_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "mode_signup_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "mode_signup_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "redirect_only_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hint_email").qualifiedAs).toBe("ignored");
  });

  it("prefers accessible submit labels over visible button text", () => {
    document.body.innerHTML = `
      <form id="icon-submit" action="/continue">
        <input name="icon_email" type="email" />
        <button type="submit" aria-label="Sign in">
          Continue
        </button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "icon-submit")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "icon_email").qualifiedAs).toBe("username");
  });

  it("ignores auxiliary buttons when collecting submit text context", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="button">Forgot password?</button>
        <input type="button" name="create_account" value="Create account" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("ignores hidden submit buttons when collecting login context", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit" hidden>Create account</button>
        <button type="submit">Sign in</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("does not let secondary submit actions suppress logins", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit">Sign in</button>
        <button type="submit">Create account</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("preserves primary account-creation submit context", () => {
    document.body.innerHTML = `
      <form id="start">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit">Create account</button>
        <button type="submit">Sign in</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "start")?.headingText).toEqual([
      "Create account"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
  });

  it("keeps neutral primary submits from inheriting secondary submit exclusions", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit">Continue</button>
        <button type="submit">Create account</button>
        <button type="submit">Forgot password?</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([
      "Continue"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("ignores disabled submit controls when collecting submit text context", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit" disabled>Create account</button>
        <button type="submit">Continue</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([
      "Continue"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("ignores inert submit controls when collecting submit text context", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <div inert>
          <button type="submit">Create account</button>
        </div>
        <button type="submit">Continue</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login")?.headingText).toEqual([
      "Continue"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("keeps submit controls for other forms out of form context", () => {
    document.body.innerHTML = `
      <form id="signup">
        <input name="signup_email" type="email" />
        <input name="signup_password" type="password" />
        <button type="submit" form="login">Sign in</button>
      </form>
      <form id="login">
        <input name="login_email" type="email" />
        <input name="login_password" type="password" />
        <button type="submit">Sign in</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "signup")?.headingText).toEqual([]);
    expect(fieldByName(report, "signup_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "signup_email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "signup_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
  });

  it("lets subscription login context override newsletter exclusions", () => {
    document.body.innerHTML = `
      <form id="subscription-login">
        <input name="subscriber_email" type="email" />
        <input name="subscriber_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "subscriber_password").qualifiedAs).toBe("password");
  });

  it("lets subscriber password forms override newsletter exclusions", () => {
    document.body.innerHTML = `
      <form id="subscriber-portal">
        <input name="subscriber_email" type="email" />
        <input name="subscriber_password" type="password" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "subscriber_password").qualifiedAs).toBe("password");
  });

  it("lets passwordless subscription login context override newsletter exclusions", () => {
    document.body.innerHTML = `
      <form id="subscription-login">
        <input name="subscriber_email" type="email" />
        <button type="submit">Sign in</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_email").qualifiedAs).toBe("username");
  });

  it("uses image submit controls as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="image-login" action="/continue">
        <input name="image_email" type="email" />
        <input type="image" alt="Sign in" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "image-login")?.headingText).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "image_email").qualifiedAs).toBe("username");
  });

  it("requires login evidence before treating a generic email field as username", () => {
    document.body.innerHTML = `
      <form id="contact">
        <input name="email" type="email" />
        <input name="text_email" type="text" aria-label="Email address" />
      </form>
      <form id="login">
        <input name="login_email" type="email" />
        <input name="login_text_email" type="text" aria-label="Email address" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "text_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "login_text_email").qualifiedAs).toBe("username");
  });

  it("does not use status login text as passwordless login evidence", () => {
    document.body.innerHTML = `
      <form>
        <h2>Last login</h2>
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
  });

  it("uses hash-routed login pages as implicit passwordless login context", () => {
    window.history.replaceState(null, "", "/#/login");
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("requires login evidence before treating autocomplete email as username", () => {
    document.body.innerHTML = `
      <form id="contact">
        <input name="contact_email" type="email" autocomplete="email" />
      </form>
      <form id="login">
        <input name="login_email" type="email" autocomplete="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
  });

  it("uses visible field prompts as passwordless login evidence", () => {
    document.body.innerHTML = `
      <form>
        <label for="prompt-email">Sign in with email</label>
        <input id="prompt-email" name="prompt_email" type="email" />
      </form>
      <form>
        <input name="placeholder_email" type="email" placeholder="Sign in with email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "prompt_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "placeholder_email").qualifiedAs).toBe("username");
  });

  it("does not treat search substrings in login URLs as search context", () => {
    window.history.replaceState(null, "", "/search");
    document.body.innerHTML = `
      <form id="implicit-login">
        <input name="implicit_email" type="email" autocomplete="username" />
        <input name="implicit_password" type="password" autocomplete="current-password" />
      </form>
      <form id="login" action="https://research.example.com/login">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="redirect-login" action="/login?next=/newsletter/search">
        <input name="redirect_email" type="email" autocomplete="username" />
        <input name="redirect_password" type="password" autocomplete="current-password" />
      </form>
      <form id="host-login" action="https://search.example.com/login">
        <input name="host_email" type="email" autocomplete="username" />
        <input name="host_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "implicit_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "implicit_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "redirect_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "redirect_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "host_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "host_password").qualifiedAs).toBe("password");
  });

  it("lets scoped password evidence override broad form search tokens", () => {
    document.body.innerHTML = `
      <form id="search-login" action="/search/login">
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "email").reasons).toContain("form-has-password");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("lets explicit login evidence override broad search tokens for passwordless forms", () => {
    document.body.innerHTML = `
      <form id="search-login" action="/search/login">
        <h2>Sign in</h2>
        <input name="primary_email" type="email" />
      </form>
      <form id="find-login" class="find-login" action="/find/account">
        <input name="secondary_email" type="email" />
        <button type="submit">Sign in</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "primary_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "secondary_email").qualifiedAs).toBe("username");
  });

  it("keeps password sibling evidence scoped for form-less fields", () => {
    document.body.innerHTML = `
      <input name="contact_email" type="email" />
      <div>
        <input name="login_email" type="email" />
        <input name="login_password" type="password" />
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
  });

  it("does not share form-less context across semantic sections", () => {
    document.body.innerHTML = `
      <main>
        <section>
          <input name="contact_email" type="email" />
        </section>
        <section>
          <input name="login_password" type="password" />
        </section>
      </main>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
  });

  it("does not group whole semantic wrappers for form-less fields", () => {
    document.body.innerHTML = `
      <main>
        <h2>Contact</h2>
        <input name="semantic_contact_email" type="email" />
        <h2>Sign in</h2>
        <input name="semantic_login_password" type="password" />
      </main>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "semantic_contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "semantic_login_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "semantic_contact_email").containerOpid).not.toBe(
      fieldByName(report, "semantic_login_password").containerOpid
    );
  });

  it("shares local context for adjacent form-less body-level login fields", () => {
    document.body.innerHTML = `
      <input name="contact_email" type="email" />
      <hr />
      <input name="body_email" type="email" />
      <input name="body_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "body_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "body_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "body_email").containerOpid).toBe(
      fieldByName(report, "body_password").containerOpid
    );
  });

  it("splits root-level form-less runs at section headings", () => {
    document.body.innerHTML = `
      <h2>Contact</h2>
      <input name="contact_email" type="email" />
      <h2>Sign in</h2>
      <input name="login_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "contact_email").containerOpid).not.toBe(
      fieldByName(report, "login_password").containerOpid
    );
  });

  it("uses single-field form-less container context for passwordless logins", () => {
    document.body.innerHTML = `
      <div class="login">
        <input name="email" type="email" />
        <button type="submit">Sign in</button>
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("climbs past generic single-field wrappers to shared form-less context", () => {
    document.body.innerHTML = `
      <div class="login">
        <div class="field">
          <input name="wrapped_email" type="email" />
        </div>
        <div class="field">
          <input name="wrapped_password" type="password" />
        </div>
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "wrapped_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "wrapped_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "wrapped_email").containerOpid).toBe(
      fieldByName(report, "wrapped_password").containerOpid
    );
  });

  it("uses root-level submit text as passwordless form-less login context", () => {
    document.body.innerHTML = `
      <input name="root_email" type="email" />
      <button type="submit">Sign in</button>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "root_email").qualifiedAs).toBe("username");
  });

  it("uses root-level auth headings as form-less field context", () => {
    document.body.innerHTML = `
      <h1>Create account</h1>
      <input name="rootless_email" type="email" />
      <input name="rootless_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "rootless_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rootless_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "rootless_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rootless_password").reasons).toContain(
      "non-login:account-creation"
    );
  });

  it("uses shadow-root-level submit text as passwordless form-less login context", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <input name="shadow_root_email" type="email" />
      <button type="submit">Sign in</button>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "shadow_root_email").qualifiedAs).toBe("username");
  });

  it("ignores later form-less container headings for earlier fields", () => {
    document.body.innerHTML = `
      <div class="login">
        <input name="email" type="email" />
        <button type="submit">Sign in</button>
        <h2>Create account</h2>
      </div>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);
    const email = snapshot.fields.find((field) => field.htmlName === "email");

    expect(email?.containerText).not.toContain("Create account");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("shares local context for labeled root-level login fields", () => {
    document.body.innerHTML = `
      <label for="body-email">Email</label>
      <input id="body-email" name="body_email" type="email" />
      <label for="body-password">Password</label>
      <input id="body-password" name="body_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "body_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "body_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "body_email").containerOpid).toBe(
      fieldByName(report, "body_password").containerOpid
    );
  });

  it("shares local context for body-level fields wrapped in labels", () => {
    document.body.innerHTML = `
      <label>Email <input name="wrapped_email" type="email" /></label>
      <label>Password <input name="wrapped_password" type="password" /></label>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "wrapped_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "wrapped_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "wrapped_email").containerOpid).toBe(
      fieldByName(report, "wrapped_password").containerOpid
    );
  });

  it("ignores unavailable password siblings as login evidence", () => {
    document.body.innerHTML = `
      <form id="hidden-password">
        <input name="hidden_sibling_email" type="email" />
        <input name="hidden_sibling_password" type="password" hidden />
      </form>
      <form id="disabled-password">
        <input name="disabled_sibling_email" type="email" />
        <input name="disabled_sibling_password" type="password" disabled />
      </form>
      <form id="new-password">
        <input name="new_password_sibling_email" type="email" />
        <input name="new_password_sibling" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hidden_sibling_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hidden_sibling_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "disabled_sibling_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "disabled_sibling_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_password_sibling_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_password_sibling").qualifiedAs).toBe("ignored");
  });

  it("ignores hidden new-password siblings as account-creation evidence", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" />
        <input name="new_password" type="password" autocomplete="new-password" hidden />
        <button type="submit">Sign in</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "new_password").qualifiedAs).toBe("ignored");
  });

  it("suppresses account creation forms before marking generic passwords eligible", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("non-login:account-creation");
  });

  it("keeps login routes from overriding standalone account creation forms", () => {
    window.history.replaceState(null, "", "/login");
    document.body.innerHTML = `
      <form action="/login">
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("non-login:account-creation");
  });

  it("keeps login routes from overriding newsletter email forms", () => {
    window.history.replaceState(null, "", "/login");
    document.body.innerHTML = `
      <form class="newsletter" action="/login">
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:newsletter");
  });

  it("keeps internal login identifiers from overriding newsletter copy", () => {
    document.body.innerHTML = `
      <form class="newsletter">
        <input name="login_email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "login_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").reasons).toContain("non-login:newsletter");
  });

  it("prioritizes account creation over newsletter context", () => {
    document.body.innerHTML = `
      <form class="newsletter">
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("non-login:account-creation");
  });

  it("uses form-less container context when suppressing account creation cards", () => {
    document.body.innerHTML = `
      <div class="signup-card">
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("non-login:account-creation");
  });

  it("prefers owned form headings over preceding headings", () => {
    document.body.innerHTML = `
      <h2>Create account</h2>
      <form>
        <h2>Sign in</h2>
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("ignores owned headings that follow all form fields", () => {
    document.body.innerHTML = `
      <form id="login-with-secondary-copy">
        <h2>Sign in</h2>
        <input name="email" type="email" />
        <button type="submit">Continue</button>
        <h2>Create account</h2>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(
      snapshot.forms.find((form) => form.htmlId === "login-with-secondary-copy")?.headingText
    ).not.toContain("Create account");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
  });

  it("keeps internal login identifiers from overriding signup copy", () => {
    document.body.innerHTML = `
      <form id="login">
        <h2>Create account</h2>
        <input name="login_email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "login_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain(
      "non-login:account-creation"
    );
  });

  it("uses form captions and legends as auth context", () => {
    document.body.innerHTML = `
      <form id="aria-signup" aria-label="Create account">
        <input name="aria_signup_email" type="email" />
        <input name="aria_signup_password" type="password" />
      </form>
      <form id="legend-signup">
        <fieldset>
          <legend>Create account</legend>
          <input name="legend_signup_email" type="email" />
          <input name="legend_signup_password" type="password" />
        </fieldset>
      </form>
      <form id="aria-login" aria-label="Sign in">
        <input name="aria_login_email" type="email" />
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "aria-signup")?.headingText).toContain(
      "Create account"
    );
    expect(snapshot.forms.find((form) => form.htmlId === "legend-signup")?.headingText).toContain(
      "Create account"
    );
    expect(fieldByName(report, "aria_signup_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "aria_signup_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "legend_signup_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "legend_signup_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "aria_login_email").qualifiedAs).toBe("username");
  });

  it("recognizes common create-account wording without suppressing registered-user logins", () => {
    document.body.innerHTML = `
      <form id="create-your-account">
        <h2>Create your account</h2>
        <input name="create_your_email" type="email" />
        <input name="create_your_password" type="password" />
      </form>
      <form id="create-an-account">
        <h2>Create an account</h2>
        <input name="create_an_email" type="email" />
        <input name="create_an_password" type="password" />
      </form>
      <form id="create-new-account">
        <h2>Create new account</h2>
        <input name="new_copy_email" type="email" />
        <input name="new_copy_password" type="password" />
      </form>
      <form id="registered-users">
        <h2>Registered users sign in</h2>
        <input name="registered_email" type="email" autocomplete="username" />
        <input name="registered_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "create_your_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "create_your_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "create_your_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "create_your_password").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "create_an_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "create_an_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "create_an_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "create_an_password").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "new_copy_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_copy_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "new_copy_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_copy_password").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "registered_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "registered_password").qualifiedAs).toBe("password");
  });

  it("detects register action paths without suppressing registered-user logins", () => {
    document.body.innerHTML = `
      <form id="join-path" action="/register">
        <input name="register_path_email" type="email" />
        <input name="register_path_password" type="password" />
      </form>
      <form id="nested-join-path" action="/account/register">
        <input name="nested_register_email" type="email" />
        <input name="nested_register_password" type="password" />
      </form>
      <form id="suffix-path" action="/account/register.php">
        <input name="suffix_email" type="email" />
        <input name="suffix_password" type="password" />
      </form>
      <form id="html-path" action="/account/registration.html">
        <input name="html_email" type="email" />
        <input name="html_password" type="password" />
      </form>
      <form id="registered-users" action="/registered-users/sign-in">
        <input name="registered_path_email" type="email" autocomplete="username" />
        <input
          name="registered_path_password"
          type="password"
          autocomplete="current-password"
        />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "register_path_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "register_path_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "register_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "nested_register_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "nested_register_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "nested_register_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "suffix_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "suffix_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "suffix_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "html_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "html_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "html_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "registered_path_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "registered_path_password").qualifiedAs).toBe("password");
  });

  it("excludes named new-password siblings from login evidence", () => {
    document.body.innerHTML = `
      <form id="account-form">
        <input name="email" type="email" autocomplete="username" />
        <input name="new_password" type="password" />
        <input name="confirm_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "new_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "confirm_password").qualifiedAs).toBe("ignored");
  });

  it("suppresses mixed password and confirmation signup forms", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" />
        <input name="confirm_password" type="password" />
      </form>
      <form>
        <input name="again_email" type="email" autocomplete="username" />
        <input name="again_password" type="password" />
        <input name="password_again" type="password" />
      </form>
      <form>
        <input name="numbered_email" type="email" autocomplete="username" />
        <input name="numbered_password" type="password" />
        <input name="password2" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "confirm_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "again_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "again_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password_again").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "numbered_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "numbered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password2").qualifiedAs).toBe("ignored");
  });

  it("treats confirm-only password siblings as account creation", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" />
        <input name="confirm" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "email").reasons).toContain("non-login:account-creation");
    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "confirm").qualifiedAs).toBe("ignored");
  });

  it("matches password reset wording before marking passwords eligible", () => {
    document.body.innerHTML = `
      <form action="/password-reset">
        <input name="password" type="password" />
      </form>
      <form id="reset-copy">
        <h2>Reset your password</h2>
        <input name="new_password" type="password" />
      </form>
      <form id="reset">
        <input name="split_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "new_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_password").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "split_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "split_password").reasons).toContain("excluded:reset");
  });

  it("does not match tel inside unrelated words", () => {
    document.body.innerHTML = `
      <form>
        <input name="hotel" type="text" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hotel").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("recognizes phone-number username fields with password siblings", () => {
    document.body.innerHTML = `
      <form id="contact">
        <input name="contact_phone" type="tel" />
      </form>
      <form>
        <input name="phone" type="tel" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_phone").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "phone").qualifiedAs).toBe("username");
    expect(fieldByName(report, "phone").reasons).toContain("form-has-password");
  });

  it("does not classify one-time-code fields as usernames", () => {
    document.body.innerHTML = `
      <form>
        <input name="login_otp" type="text" autocomplete="one-time-code" />
      </form>
      <form id="login">
        <input name="phone_otp" type="tel" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "login_otp").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_otp").reasons).toContain("excluded:one-time-code");
    expect(fieldByName(report, "phone_otp").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "phone_otp").reasons).toContain("excluded:one-time-code");
  });

  it("does not classify password-masked OTP fields as saved-password targets", () => {
    document.body.innerHTML = `
      <form id="verification">
        <label for="otp-code">Security code</label>
        <input id="otp-code" name="otp" type="password" />
      </form>
      <form id="login">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "otp").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "otp").reasons).toContain("excluded:one-time-code");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("does not use password-masked code fields as login password evidence", () => {
    document.body.innerHTML = `
      <form id="verification">
        <input name="email" type="email" />
        <input name="otp" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "otp").qualifiedAs).toBe("ignored");
  });

  it("does not classify masked card security code fields as saved-password targets", () => {
    document.body.innerHTML = `
      <form id="payment">
        <label for="cvv">Card CVV</label>
        <input id="cvv" name="card_cvv" type="password" />
        <input name="card_code" type="password" autocomplete="cc-csc" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "card_cvv").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "card_code").qualifiedAs).toBe("ignored");
  });

  it("does not apply non-login exclusions to unresolved describedby IDs", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" autocomplete="username" />
        <input
          name="password"
          type="password"
          autocomplete="current-password"
          aria-describedby="forgot-password"
        />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("ignores current-password autocomplete on non-input controls", () => {
    document.body.innerHTML = `
      <form id="profile">
        <input name="plain_text_secret" type="text" autocomplete="current-password" />
        <textarea name="notes" autocomplete="current-password"></textarea>
        <select name="secret_select" autocomplete="current-password">
          <option value="">Choose one</option>
        </select>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "plain_text_secret").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "notes").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "secret_select").qualifiedAs).toBe("ignored");
  });

  it("uses aria-labelledby text as field label context", () => {
    document.body.innerHTML = `
      <form>
        <span id="account-label">Email address</span>
        <input name="opaque_account" type="text" aria-labelledby="account-label" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const username = fieldByName(report, "opaque_account");

    expect(username.labelText).toBe("Email address");
    expect(username.qualifiedAs).toBe("username");
  });

  it("ignores hidden labels when deriving field intent", () => {
    document.body.innerHTML = `
      <form>
        <label hidden for="email">Forgot password email</label>
        <input id="email" name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    const email = fieldByName(report, "email");

    expect(email.labelText).toBeUndefined();
    expect(email.qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("collects field types from fields whose owner document has different constructors", () => {
    const frame = document.createElement("iframe");
    document.body.append(frame);
    const frameDocument = frame.contentDocument;
    expect(frameDocument).toBeDefined();
    frameDocument!.body.innerHTML = `
      <form>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const originalInputElement = globalThis.HTMLInputElement;
    vi.stubGlobal("HTMLInputElement", class OtherRealmInputElement {});
    try {
      const report = triageAutofillPage(collectAutofillPageSnapshot(frameDocument!));

      expect(fieldByName(report, "email").qualifiedAs).toBe("username");
      expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    } finally {
      vi.stubGlobal("HTMLInputElement", originalInputElement);
    }
  });

  it("treats offscreen and transparent honeypot fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="offscreen_email" type="email" autocomplete="username" style="position:absolute;left:-9999px" />
        <input name="offscreen_em_email" type="email" autocomplete="username" style="position:absolute;left:-999em" />
        <input name="positive_left_offscreen_email" type="email" autocomplete="username" style="position:absolute;left:9999px" />
        <input name="positive_top_offscreen_email" type="email" autocomplete="username" style="position:absolute;top:9999px" />
        <input name="right_offscreen_email" type="email" autocomplete="username" style="position:absolute;right:-9999px" />
        <input name="bottom_offscreen_email" type="email" autocomplete="username" style="position:absolute;bottom:-9999px" />
        <input name="transparent_email" type="email" autocomplete="username" style="opacity:0" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "offscreen_email").reasons).toContain("not-viewable:offscreen");
    expect(fieldByName(report, "offscreen_em_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "offscreen_em_email").reasons).toContain("not-viewable:offscreen");
    expect(fieldByName(report, "positive_left_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "positive_left_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "positive_top_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "positive_top_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "right_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "right_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "bottom_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "bottom_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "transparent_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "transparent_email").reasons).toContain("not-viewable:transparent");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("does not let offscreen fields define the rendered area", () => {
    document.body.innerHTML = `
      <form>
        <input name="scroll_width_honeypot" type="email" autocomplete="username" style="position:absolute;left:9999px;top:10px;width:20px;height:20px" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const honeypot = document.querySelector<HTMLInputElement>("[name=scroll_width_honeypot]")!;
    vi.spyOn(honeypot, "getBoundingClientRect").mockReturnValue({
      x: 9999,
      y: 10,
      width: 20,
      height: 20,
      left: 9999,
      top: 10,
      right: 10019,
      bottom: 30,
      toJSON: () => ({})
    } as DOMRect);
    vi.spyOn(document.documentElement, "scrollWidth", "get").mockReturnValue(10100);
    vi.spyOn(document.body, "scrollWidth", "get").mockReturnValue(10100);
    vi.stubGlobal("innerWidth", 1280);
    vi.stubGlobal("innerHeight", 720);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "scroll_width_honeypot").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "scroll_width_honeypot").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps positioned login fields viewable when their rendered rect intersects the viewport", () => {
    document.body.innerHTML = `
      <form>
        <input name="wide_layout_email" type="email" autocomplete="username" style="position:absolute;left:1000px;top:20px;width:120px;height:20px" />
        <input name="wide_layout_password" type="password" autocomplete="current-password" style="position:absolute;left:1000px;top:50px;width:120px;height:20px" />
      </form>
    `;
    const email = document.querySelector<HTMLInputElement>("[name=wide_layout_email]")!;
    const password = document.querySelector<HTMLInputElement>("[name=wide_layout_password]")!;
    const rectFor = (top: number) =>
      ({
        x: 1000,
        y: top,
        width: 120,
        height: 20,
        left: 1000,
        top,
        right: 1120,
        bottom: top + 20,
        toJSON: () => ({})
      }) as DOMRect;
    vi.spyOn(email, "getBoundingClientRect").mockReturnValue(rectFor(20));
    vi.spyOn(password, "getBoundingClientRect").mockReturnValue(rectFor(50));
    vi.stubGlobal("innerWidth", 1280);
    vi.stubGlobal("innerHeight", 720);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "wide_layout_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "wide_layout_email").reasons).not.toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "wide_layout_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "wide_layout_password").reasons).not.toContain(
      "not-viewable:offscreen"
    );
  });

  it("treats relative and transformed offscreen fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="relative_offscreen_email" type="email" autocomplete="username" style="position:relative;left:-9999px;width:20px;height:20px" />
        <input name="translated_offscreen_email" type="email" autocomplete="username" style="transform:translateX(-9999px);width:20px;height:20px" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const relative = document.querySelector<HTMLInputElement>("[name=relative_offscreen_email]")!;
    const translated = document.querySelector<HTMLInputElement>(
      "[name=translated_offscreen_email]"
    )!;
    const offscreenRect = {
      x: -9999,
      y: 10,
      width: 20,
      height: 20,
      left: -9999,
      top: 10,
      right: -9979,
      bottom: 30,
      toJSON: () => ({})
    } as DOMRect;
    vi.spyOn(relative, "getBoundingClientRect").mockReturnValue(offscreenRect);
    vi.spyOn(translated, "getBoundingClientRect").mockReturnValue(offscreenRect);
    vi.stubGlobal("innerWidth", 1280);
    vi.stubGlobal("innerHeight", 720);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "relative_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "relative_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "translated_offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "translated_offscreen_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats stylesheet-clipped zero-size ancestors as not viewable", () => {
    document.head.innerHTML = `
      <style>
        .honeypot { width: 0; height: 0; overflow: hidden; }
      </style>
    `;
    document.body.innerHTML = `
      <form>
        <div class="honeypot">
          <input name="decoy_email" type="email" />
        </div>
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "decoy_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "decoy_email").reasons).toContain("not-viewable:zero-size");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
  });

  it("treats one-dimensional clipped ancestors as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="height:0;overflow:hidden">
          <input name="height_clipped_email" type="email" autocomplete="username" />
        </div>
        <div style="width:0;overflow:hidden">
          <input name="width_clipped_email" type="email" autocomplete="username" />
        </div>
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "height_clipped_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "height_clipped_email").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "width_clipped_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "width_clipped_email").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats content-visibility hidden ancestors as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="content-visibility:hidden">
          <input name="content_hidden_email" type="email" autocomplete="username" />
        </div>
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "content_hidden_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "content_hidden_email").reasons).toContain("not-viewable:css");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats clipped and transformed zero-size fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="clip_email" type="email" autocomplete="username" style="position:absolute;clip:rect(0 0 0 0);width:20px;height:20px" />
        <input name="clip_path_email" type="email" autocomplete="username" style="clip-path:inset(50%);width:20px;height:20px" />
        <input name="scaled_email" type="email" autocomplete="username" style="transform:scale(0);width:20px;height:20px" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const scaled = document.querySelector<HTMLInputElement>("[name=scaled_email]")!;
    vi.spyOn(scaled, "getBoundingClientRect").mockReturnValue({
      x: 0,
      y: 0,
      width: 0,
      height: 0,
      left: 0,
      top: 0,
      right: 0,
      bottom: 0,
      toJSON: () => ({})
    } as DOMRect);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "clip_path_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "scaled_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "scaled_email").reasons).toContain("not-viewable:zero-size");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("lets current-password fields override mixed sign-in and signup copy", () => {
    document.body.innerHTML = `
      <form id="mixed-auth">
        <h2>Sign in or create account</h2>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("lets mixed sign-in and signup copy keep generic login passwords eligible", () => {
    document.body.innerHTML = `
      <form id="mixed-auth">
        <h2>Sign in or create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("treats zero-sized fields and inert container fields as unavailable", () => {
    document.body.innerHTML = `
      <form>
        <input name="zero_email" type="email" autocomplete="username" style="width:0;height:0" />
        <div inert>
          <input name="inert_email" type="email" autocomplete="username" />
        </div>
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "zero_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "zero_email").reasons).toContain("not-viewable:zero-size");
    expect(fieldByName(report, "inert_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "inert_email").reasons).toContain("not-fillable:inert");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields under closed details content as not viewable", () => {
    document.body.innerHTML = `
      <details>
        <summary>Other account</summary>
        <form id="closed-login">
          <input name="closed_email" type="email" autocomplete="username" />
          <input name="closed_password" type="password" autocomplete="current-password" />
        </form>
      </details>
      <form id="login">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "closed_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "closed_email").reasons).toContain(
      "not-viewable:details-closed"
    );
    expect(fieldByName(report, "closed_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "closed_password").reasons).toContain(
      "not-viewable:details-closed"
    );
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("collects fields from open shadow roots", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <form>
        <input name="shadow_email" type="email" autocomplete="username" />
        <input name="shadow_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rootLevelHost = document.createElement("div");
    document.body.append(rootLevelHost);
    const rootLevelRoot = rootLevelHost.attachShadow({ mode: "open" });
    rootLevelRoot.innerHTML = `
      <input name="root_shadow_email" type="email" />
      <input name="root_shadow_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "shadow_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "shadow_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "root_shadow_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "root_shadow_password").qualifiedAs).toBe("password");
  });

  it("keeps form-less shadow-root field grouping local", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <input name="contact_email" type="email" />
      <hr />
      <input name="login_email" type="email" />
      <input name="login_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "login_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
  });

  it("uses shadow-root labels and host visibility for collected fields", () => {
    const hiddenHost = document.createElement("div");
    hiddenHost.hidden = true;
    document.body.append(hiddenHost);
    const hiddenRoot = hiddenHost.attachShadow({ mode: "open" });
    hiddenRoot.innerHTML = `
      <input name="hidden_shadow_email" type="email" autocomplete="username" />
    `;

    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <h2>Create account</h2>
      <form>
        <label for="shadow-user">Email address</label>
        <input id="shadow-user" name="opaque_shadow_user" type="text" />
        <input name="shadow_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hidden_shadow_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hidden_shadow_email").reasons).toContain("not-viewable:hidden");
    expect(fieldByName(report, "opaque_shadow_user").labelText).toBe("Email address");
    expect(fieldByName(report, "opaque_shadow_user").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "opaque_shadow_user").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "shadow_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "shadow_password").reasons).toContain(
      "non-login:account-creation"
    );
  });

  it("walks assigned slots when checking field visibility", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <div style="display:none">
        <slot name="login"></slot>
      </div>
    `;
    const email = document.createElement("input");
    email.name = "slotted_email";
    email.type = "email";
    email.autocomplete = "username";
    email.slot = "login";
    host.append(email);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "slotted_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "slotted_email").reasons).toContain("not-viewable:css");
  });

  it("treats unslotted shadow-host children as not viewable", () => {
    const host = document.createElement("div");
    document.body.append(host);
    host.attachShadow({ mode: "open" }).innerHTML = `
      <input name="shadow_email" type="email" autocomplete="username" />
      <input name="shadow_password" type="password" autocomplete="current-password" />
    `;
    const email = document.createElement("input");
    email.name = "unslotted_email";
    email.type = "email";
    email.autocomplete = "username";
    host.append(email);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "unslotted_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "unslotted_email").reasons).toContain(
      "not-viewable:unslotted"
    );
    expect(fieldByName(report, "shadow_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "shadow_password").qualifiedAs).toBe("password");
  });

  it("treats descendants of unslotted shadow-host children as not viewable", () => {
    const host = document.createElement("div");
    document.body.append(host);
    host.attachShadow({ mode: "open" }).innerHTML = `
      <input name="shadow_email" type="email" autocomplete="username" />
      <input name="shadow_password" type="password" autocomplete="current-password" />
    `;
    const wrapper = document.createElement("div");
    wrapper.innerHTML = `
      <input name="nested_unslotted_email" type="email" autocomplete="username" />
    `;
    host.append(wrapper);

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "nested_unslotted_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "nested_unslotted_email").reasons).toContain(
      "not-viewable:unslotted"
    );
    expect(fieldByName(report, "shadow_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "shadow_password").qualifiedAs).toBe("password");
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

  it("uses preceding shadow-root headings for wrapped forms", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <h2>Create account</h2>
      <div>
        <form>
          <input name="component_email" type="email" />
          <input name="component_password" type="password" />
        </form>
      </div>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "component_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "component_email").reasons).toContain(
      "non-login:account-creation"
    );
    expect(fieldByName(report, "component_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "component_password").reasons).toContain(
      "non-login:account-creation"
    );
  });

  it("uses only the nearest preceding heading for a form context", () => {
    document.body.innerHTML = `
      <main>
        <h2>Create account</h2>
        <p>New customers can start here.</p>
        <h2>Sign in</h2>
        <form id="login-form">
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
        </form>
      </main>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    const report = triageAutofillPage(snapshot);

    expect(snapshot.forms.find((form) => form.htmlId === "login-form")).toMatchObject({
      headingText: ["Sign in"]
    });
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
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
