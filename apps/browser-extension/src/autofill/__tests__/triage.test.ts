import { beforeEach, describe, expect, it, vi } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { triageAutofillPage } from "../triage";

function fieldByName(report: ReturnType<typeof triageAutofillPage>, htmlName: string) {
  const field = report.fields.find((candidate) => candidate.htmlName === htmlName);
  expect(field, `expected field named ${htmlName}`).toBeDefined();
  return field!;
}

function elementRect(partial: {
  left: number;
  top: number;
  width: number;
  height: number;
}): DOMRect {
  return {
    x: partial.left,
    y: partial.top,
    left: partial.left,
    top: partial.top,
    width: partial.width,
    height: partial.height,
    right: partial.left + partial.width,
    bottom: partial.top + partial.height,
    toJSON: () => ({})
  } as DOMRect;
}

function stubElementRect(element: Element, rect: DOMRect) {
  Object.defineProperty(element, "getBoundingClientRect", {
    configurable: true,
    value: () => rect
  });
}

function fakeCssStyle(values: Record<string, string>) {
  const propertyValue = (property: string) => values[property] ?? "";
  return new Proxy(
    {
      getPropertyValue: propertyValue
    },
    {
      get(target, property) {
        if (property in target) {
          return target[property as keyof typeof target];
        }
        if (typeof property === "string") {
          return values[property] ?? "";
        }
        return undefined;
      }
    }
  ) as CSSStyleDeclaration;
}

function stubPseudoElementStyles(
  styles: Array<{
    element: Element;
    pseudoElement: "::before" | "::after";
    values: Record<string, string>;
  }>
) {
  const originalGetComputedStyle = window.getComputedStyle.bind(window);
  return vi.spyOn(window, "getComputedStyle").mockImplementation((target, pseudoElt) => {
    const pseudoStyle = styles.find(
      (style) => target === style.element && pseudoElt === style.pseudoElement
    );
    if (pseudoStyle) {
      return fakeCssStyle(pseudoStyle.values);
    }
    if (pseudoElt) {
      return fakeCssStyle({ content: "none", display: "none" });
    }
    return originalGetComputedStyle(target);
  });
}

function stubPseudoElementStyle(
  element: Element,
  pseudoElement: "::before" | "::after",
  values: Record<string, string>
) {
  return stubPseudoElementStyles([{ element, pseudoElement, values }]);
}

describe("autofill triage", () => {
  beforeEach(() => {
    window.history.replaceState(null, "", "/");
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

  it("does not collect shadow-internal buttons as outer form submit context", () => {
    document.body.innerHTML = `
      <form id="login-form">
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
        <div id="widget-host"></div>
        <button type="submit">Continue</button>
      </form>
    `;
    const host = document.querySelector("#widget-host") as HTMLDivElement;
    host.attachShadow({ mode: "open" }).innerHTML = `
      <button type="submit">Create account</button>
    `;

    const snapshot = collectAutofillPageSnapshot(document);
    expect(snapshot.forms[0].submitText).toEqual(["Continue"]);
    expect(snapshot.forms[0].headingText).toEqual(["Continue"]);
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

  it("keeps single-password signup forms with sign-in copy out of login qualification", () => {
    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
        <button type="submit">Sign in</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("newPassword");
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

  it("keeps usernames beside new-password fields available for registration", () => {
    document.body.innerHTML = `
      <form>
        <input name="account" autocomplete="username" />
        <input name="password" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "account").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("newPassword");
  });

  it("does not let username autocomplete override account creation context", () => {
    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="signup_email" type="email" autocomplete="username" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "signup_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "signup_email").reasons).toContain(
      "non-login:account-creation"
    );
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

  it("preserves login submit labels on combined auth forms", () => {
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
      "Create account",
      "Sign in"
    ]);
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
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

  it("preserves later account-creation submit labels for registration forms", () => {
    document.body.innerHTML = `
      <form id="signup">
        <input name="email" type="email" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <button type="submit">Continue</button>
        <button type="submit">Create account</button>
      </form>
    `;

    const snapshot = collectAutofillPageSnapshot(document);

    expect(snapshot.forms.find((form) => form.htmlId === "signup")?.headingText).toEqual([
      "Continue",
      "Create account"
    ]);
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
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "implicit_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "implicit_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "redirect_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "redirect_password").qualifiedAs).toBe("password");
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
    expect(fieldByName(report, "new_password_sibling").qualifiedAs).toBe("newPassword");
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

  it("does not treat account creation forms as current-login candidates", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" type="email" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("newPassword");
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
      <form id="registered-users">
        <h2>Registered users sign in</h2>
        <input name="registered_email" type="email" autocomplete="username" />
        <input name="registered_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "create_your_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "create_your_password").qualifiedAs).toBe("newPassword");
    expect(fieldByName(report, "create_an_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "create_an_password").qualifiedAs).toBe("newPassword");
    expect(fieldByName(report, "registered_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "registered_password").qualifiedAs).toBe("password");
  });

  it("detects register action paths without suppressing registered-user logins", () => {
    document.body.innerHTML = `
      <form id="join-path" action="/register">
        <input name="register_path_email" type="email" />
        <input name="register_path_password" type="password" />
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

    expect(fieldByName(report, "register_path_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "register_path_password").qualifiedAs).toBe("newPassword");
    expect(fieldByName(report, "registered_path_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "registered_path_password").qualifiedAs).toBe("password");
  });

  it("keeps named new-password siblings available for registration", () => {
    document.body.innerHTML = `
      <form id="account-form">
        <input name="email" type="email" autocomplete="username" />
        <input name="new_password" type="password" />
        <input name="confirm_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "new_password").qualifiedAs).toBe("newPassword");
    expect(fieldByName(report, "confirm_password").qualifiedAs).toBe("newPassword");
  });

  it("suppresses mixed password and confirmation signup forms", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" />
        <input name="confirm_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("newPassword");
    expect(fieldByName(report, "confirm_password").qualifiedAs).toBe("newPassword");
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
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "password").reasons).toContain("excluded:reset");
    expect(fieldByName(report, "new_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "new_password").reasons).toContain("excluded:reset");
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

    expect(fieldByName(report, "login_otp").qualifiedAs).toBe("totp");
    expect(fieldByName(report, "login_otp").reasons).toContain("autocomplete:one-time-code");
    expect(fieldByName(report, "phone_otp").qualifiedAs).toBe("totp");
  });

  it("does not classify phone-delivered one-time codes as authenticator TOTP", () => {
    document.body.innerHTML = `
      <form id="sms-code">
        <label for="phone-code">Code sent to your phone</label>
        <input id="phone-code" name="code" autocomplete="one-time-code" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "code").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "code").reasons).toContain("excluded:out-of-band-code");
  });

  it("requires field-level code evidence before using MFA form context", () => {
    document.body.innerHTML = `
      <form id="mfa-setup">
        <h2>Two factor authentication setup</h2>
        <input name="phone" type="tel" inputmode="numeric" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "phone").qualifiedAs).toBe("ignored");
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

    expect(fieldByName(report, "otp").qualifiedAs).toBe("totp");
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
    expect(fieldByName(report, "otp").qualifiedAs).toBe("totp");
  });

  it("does not classify masked card security code fields as saved-password targets", () => {
    document.body.innerHTML = `
      <form id="payment">
        <input name="checkout_email" type="email" />
        <label for="cvv">Card CVV</label>
        <input id="cvv" name="card_cvv" type="password" />
        <input name="card_code" type="password" autocomplete="cc-csc" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "checkout_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "card_cvv").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "card_code").qualifiedAs).toBe("ignored");
  });

  it("does not classify generic masked security-code fields as TOTP targets", () => {
    document.body.innerHTML = `
      <form id="verification">
        <input name="security_code" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "security_code").qualifiedAs).toBe("ignored");
  });

  it("does not apply SMS code exclusions to normal password fields", () => {
    document.body.innerHTML = `
      <form id="combined-login">
        <h2>SMS verification</h2>
        <input name="password" type="password" />
        <label for="sms-code">SMS code</label>
        <input id="sms-code" name="sms_code" autocomplete="one-time-code" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "sms_code").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "sms_code").reasons).toContain("excluded:out-of-band-code");
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

  it("respects non-login exclusions before accepting current-password fields", () => {
    document.body.innerHTML = `
      <form class="newsletter">
        <h2>Subscribe to our newsletter</h2>
        <input name="subscriber_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "subscriber_password").reasons).toContain("non-login:newsletter");
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
      <style>
        .computed-clip-box {
          position: absolute;
          width: 1px;
          height: 1px;
          overflow: hidden;
        }
      </style>
      <style>
        .clip-off { transform: translate(-9999px, 0); }
      </style>
      <form>
        <input name="offscreen_email" type="email" autocomplete="username" style="position:absolute;left:-9999px" />
        <input name="positive_left_offscreen_email" type="email" autocomplete="username" style="position:absolute;left:9999px" />
        <input name="positive_top_offscreen_email" type="email" autocomplete="username" style="position:absolute;top:9999px" />
        <input name="right_offscreen_email" type="email" autocomplete="username" style="position:absolute;right:-9999px" />
        <input name="bottom_offscreen_email" type="email" autocomplete="username" style="position:absolute;bottom:-9999px" />
        <input name="transformed_email" type="email" autocomplete="username" style="transform:translateX(-9999px)" />
        <input name="clip_path_email" type="email" autocomplete="username" style="clip-path:inset(50%)" />
        <input name="geometry_box_inset_clip_email" type="email" autocomplete="username" style="clip-path:inset(50%) content-box" />
        <input name="circle_clip_email" type="email" autocomplete="username" style="clip-path:circle(0)" />
        <input name="circle_keyword_clip_email" type="email" autocomplete="username" style="clip-path:circle(closest-side at -9999px 50%)" />
        <input name="geometry_box_circle_clip_email" type="email" autocomplete="username" style="clip-path:circle(closest-side at -9999px 50%) content-box" />
        <input name="ellipse_clip_email" type="email" autocomplete="username" style="clip-path:ellipse(0 0)" />
        <input name="ellipse_keyword_clip_email" type="email" autocomplete="username" style="clip-path:ellipse(closest-side closest-side at -9999px 50%)" />
        <input name="polygon_clip_email" type="email" autocomplete="username" style="clip-path:polygon(0 0, 0 0, 0 0)" />
        <input name="geometry_box_polygon_clip_email" type="email" autocomplete="username" style="clip-path:polygon(0 0, 0 0, 0 0) content-box" />
        <input name="shape_zero_clip_email" type="email" autocomplete="username" style="clip-path:shape(from 0 0, line to 0 0, close)" />
        <input name="shape_strip_clip_email" type="email" autocomplete="username" style="clip-path:shape(from 0 0, line to 4px 0, line to 4px 100%, line to 0 100%, close)" />
        <input name="shape_offset_clip_email" type="email" autocomplete="username" style="clip-path:shape(from -9999px 0, line to -9900px 0, line to -9900px 100%, line to -9999px 100%, close)" />
        <input name="legacy_clip_email" type="email" autocomplete="username" style="position:absolute;clip:rect(0 0 0 0)" />
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="offsetRectClip"><rect x="-9999" y="0" width="200" height="30" /></clipPath>
          <clipPath id="translatedRectClip"><rect width="200" height="30" transform="translate(-9999 0)" /></clipPath>
          <clipPath id="classTranslatedRectClip"><rect class="clip-off" width="200" height="30" /></clipPath>
          <clipPath id="objectStripClip" clipPathUnits="objectBoundingBox"><rect width="0.01" height="1" /></clipPath>
          <clipPath id="objectOffsetClip" clipPathUnits="objectBoundingBox"><rect x="2" width="1" height="1" /></clipPath>
        </svg>
        <input name="offset_url_clip_email" type="email" autocomplete="username" style="clip-path:url(#offsetRectClip)" />
        <input name="translated_url_clip_email" type="email" autocomplete="username" style="clip-path:url(#translatedRectClip)" />
        <input name="class_translated_url_clip_email" type="email" autocomplete="username" style="clip-path:url(#classTranslatedRectClip)" />
        <input name="object_strip_clip_email" type="email" autocomplete="username" style="clip-path:url(#objectStripClip)" />
        <input name="object_offset_clip_email" type="email" autocomplete="username" style="clip-path:url(#objectOffsetClip)" />
        <div class="computed-clip-box">
          <input name="computed_overflow_email" type="email" autocomplete="username" />
        </div>
        <input name="transparent_email" type="email" autocomplete="username" style="opacity:0" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const name of [
      "offset_url_clip_email",
      "translated_url_clip_email",
      "class_translated_url_clip_email",
      "object_strip_clip_email",
      "object_offset_clip_email",
      "circle_keyword_clip_email",
      "ellipse_keyword_clip_email",
      "geometry_box_inset_clip_email",
      "geometry_box_circle_clip_email",
      "geometry_box_polygon_clip_email",
      "shape_zero_clip_email",
      "shape_strip_clip_email",
      "shape_offset_clip_email"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({
          left: 24,
          top:
            name.includes("_keyword_") ||
            name.startsWith("geometry_box_") ||
            name.startsWith("shape_")
              ? 920
              : 40,
          width: 185,
          height: 21
        })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "offscreen_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "offscreen_email").reasons).toContain("not-viewable:offscreen");
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
    expect(fieldByName(report, "transformed_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "transformed_email").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "clip_path_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "geometry_box_inset_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "geometry_box_inset_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "circle_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "circle_clip_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "circle_keyword_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "circle_keyword_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "geometry_box_circle_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "geometry_box_circle_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "ellipse_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ellipse_clip_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "ellipse_keyword_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ellipse_keyword_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "polygon_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "polygon_clip_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "geometry_box_polygon_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "geometry_box_polygon_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    for (const name of [
      "shape_zero_clip_email",
      "shape_strip_clip_email",
      "shape_offset_clip_email"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:clipped");
    }
    expect(fieldByName(report, "legacy_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "legacy_clip_email").reasons).toContain("not-viewable:clipped");
    expect(fieldByName(report, "offset_url_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "offset_url_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "translated_url_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "translated_url_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "class_translated_url_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "class_translated_url_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "object_strip_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "object_strip_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "object_offset_clip_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "object_offset_clip_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "computed_overflow_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "computed_overflow_email").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "transparent_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "transparent_email").reasons).toContain("not-viewable:transparent");
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps below-fold document-flow login fields viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="email"]') as HTMLInputElement,
      elementRect({ left: 24, top: 1208, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 1240, width: 185, height: 21 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "email").reasons).not.toContain("not-viewable:offscreen");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "password").reasons).not.toContain("not-viewable:offscreen");
  });

  it("keeps below-fold login fields viewable when layout uses margin or relative top", () => {
    document.body.innerHTML = `
      <form style="margin-top:900px">
        <input name="margin_email" type="email" autocomplete="username" />
        <input name="margin_password" type="password" autocomplete="current-password" />
      </form>
      <form style="position:relative;top:900px">
        <input name="relative_email" type="email" autocomplete="username" />
        <input name="relative_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const name of ["margin_email", "margin_password"]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 900, width: 185, height: 21 })
      );
    }
    for (const name of ["relative_email", "relative_password"]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 940, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "margin_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "margin_email").reasons).not.toContain("not-viewable:offscreen");
    expect(fieldByName(report, "margin_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "margin_password").reasons).not.toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "relative_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "relative_email").reasons).not.toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "relative_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "relative_password").reasons).not.toContain(
      "not-viewable:offscreen"
    );
  });

  it("keeps scrolled-past document-flow login fields viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="email"]') as HTMLInputElement,
      elementRect({ left: 24, top: -80, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="password"]') as HTMLInputElement,
      elementRect({ left: 24, top: -48, width: 185, height: 21 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "email").reasons).not.toContain("not-viewable:offscreen");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "password").reasons).not.toContain("not-viewable:offscreen");
  });

  it("treats fields whose final rect is before the viewport as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="transform:translateX(-500px)">
          <input name="parent_translated_password" type="password" autocomplete="current-password" />
        </div>
        <div style="position:relative;left:-9999px">
          <input name="parent_relative_password" type="password" autocomplete="current-password" />
        </div>
        <input name="translated_password" type="password" autocomplete="current-password" style="transform:translateX(-500px)" />
        <input name="relative_password" type="password" autocomplete="current-password" style="position:relative;left:-9999px" />
        <input name="margin_password" type="password" autocomplete="current-password" style="display:block;margin-left:-9999px" />
        <input name="percent_translate_password" type="password" autocomplete="current-password" style="translate:-800%" />
        <input name="calc_translate_password" type="password" autocomplete="current-password" style="translate:calc(-100% - 500px)" />
        <input name="viewport_translate_x_password" type="password" autocomplete="current-password" style="transform:translateX(-100vw)" />
        <input name="motion_path_password" type="password" autocomplete="current-password" style='offset-path:path("M -1000 0");offset-distance:100%' />
        <input name="translated_y_password" type="password" autocomplete="current-password" style="transform:translateY(-500px)" />
        <input name="longhand_translated_y_password" type="password" autocomplete="current-password" style="translate:0 -500px" />
        <input name="viewport_translate_y_password" type="password" autocomplete="current-password" style="translate:0 -100vh" />
        <input name="relative_y_password" type="password" autocomplete="current-password" style="position:relative;top:-500px" />
        <input name="viewport_relative_password" type="password" autocomplete="current-password" style="position:relative;left:-100vw" />
        <input name="margin_y_password" type="password" autocomplete="current-password" style="display:block;margin-top:-500px" />
        <input name="viewport_margin_password" type="password" autocomplete="current-password" style="display:block;margin-left:-100vw" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const name of [
      "parent_translated_password",
      "translated_password",
      "percent_translate_password",
      "calc_translate_password",
      "viewport_translate_x_password",
      "motion_path_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: -476, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of [
      "parent_relative_password",
      "relative_password",
      "margin_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: -9975, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of ["viewport_relative_password", "viewport_margin_password"]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: -1000, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of [
      "translated_y_password",
      "longhand_translated_y_password",
      "viewport_translate_y_password",
      "relative_y_password",
      "margin_y_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: -520, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of [
      "parent_translated_password",
      "parent_relative_password",
      "translated_password",
      "relative_password",
      "margin_password",
      "percent_translate_password",
      "calc_translate_password",
      "viewport_translate_x_password",
      "motion_path_password",
      "translated_y_password",
      "longhand_translated_y_password",
      "viewport_translate_y_password",
      "relative_y_password",
      "viewport_relative_password",
      "margin_y_password",
      "viewport_margin_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:offscreen");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats paint-suppressed credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="alphaZero"><feComponentTransfer><feFuncA type="table" tableValues="0 0" /></feComponentTransfer></filter>
          <filter id="alphaZeroDiscrete"><feComponentTransfer><feFuncA type="discrete" tableValues="0 0" /></feComponentTransfer></filter>
          <filter id="alphaZeroGamma"><feComponentTransfer><feFuncA type="gamma" amplitude="0" offset="0" /></feComponentTransfer></filter>
          <filter id="alphaZeroMatrix"><feColorMatrix type="matrix" values="1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0 0" /></filter>
          <filter id="floodAlphaZero"><feFlood flood-opacity="0" /></filter>
          <filter id="floodTransparent"><feFlood flood-color="transparent" /></filter>
          <filter id="offsetSource"><feOffset dx="-9999" dy="0" /></filter>
          <filter id="nearOffsetSource"><feOffset dx="-500" dy="0" /></filter>
          <filter id="objectOffsetSource" primitiveUnits="objectBoundingBox"><feOffset dx="-3" dy="0" /></filter>
          <mask id="blackMask"><rect width="100%" height="100%" fill="black" /></mask>
          <mask id="transparentGroupMask"><g opacity="0"><rect width="100%" height="100%" fill="white" /></g></mask>
        </svg>
        <input name="transparent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent,transparent)" />
        <input name="radial_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(transparent, transparent)" />
        <input name="radial_shape_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, transparent, transparent)" />
        <input name="conic_from_mask_password" type="password" autocomplete="current-password" style="mask-image:conic-gradient(from 0deg, transparent, transparent)" />
        <input name="linear_color_space_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(in oklab, transparent, transparent)" />
        <input name="black_luminance_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black, black);mask-mode:luminance" />
        <input name="radial_black_luminance_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, black, black);mask-mode:luminance" />
        <input name="stop_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent 0 100%)" />
        <input name="url_mask_password" type="password" autocomplete="current-password" style="mask:url(#blackMask)" />
        <input name="group_opacity_mask_password" type="password" autocomplete="current-password" style="mask:url(#transparentGroupMask)" />
        <input name="zero_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0 0" />
        <input name="zero_percent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0% 100%;mask-repeat:no-repeat" />
        <input name="tiny_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4px 100%;mask-repeat:no-repeat" />
        <input name="tiny_percent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4% 100%;mask-repeat:no-repeat" />
        <input name="positioned_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:100% 100%;mask-repeat:no-repeat;mask-position:-9999px 0" />
        <input name="svg_filter_password" type="password" autocomplete="current-password" style="filter:url(#alphaZero)" />
        <input name="svg_filter_discrete_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroDiscrete)" />
        <input name="svg_filter_gamma_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroGamma)" />
        <input name="svg_filter_matrix_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroMatrix)" />
        <input name="svg_filter_flood_password" type="password" autocomplete="current-password" style="filter:url(#floodAlphaZero)" />
        <input name="svg_filter_transparent_flood_password" type="password" autocomplete="current-password" style="filter:url(#floodTransparent)" />
        <input name="svg_filter_offset_password" type="password" autocomplete="current-password" style="filter:url(#offsetSource)" />
        <input name="svg_filter_near_offset_password" type="password" autocomplete="current-password" style="filter:url(#nearOffsetSource)" />
        <input name="svg_filter_object_offset_password" type="password" autocomplete="current-password" style="filter:url(#objectOffsetSource)" />
        <div id="ancestor-filter-offset" style="filter:url(#nearOffsetSource)">
          <input name="ancestor_svg_filter_offset_password" type="password" autocomplete="current-password" />
        </div>
        <div style="opacity:0.1">
          <div style="opacity:0.1">
            <input name="cumulative_opacity_password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div style="filter:opacity(10%)">
          <div style="filter:opacity(10%)">
            <input name="cumulative_filter_password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <input name="rotate_x_password" type="password" autocomplete="current-password" style="rotate:x 90deg" />
        <input name="rotate_y_password" type="password" autocomplete="current-password" style="rotate:y 90deg" />
        <input name="backface_password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:rotateY(180deg)" />
        <input name="backface_matrix_password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:matrix3d(-1,0,0,0,0,1,0,0,0,0,-1,0,0,0,0,1)" />
        <input name="paintless_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:transparent;-webkit-text-fill-color:transparent;outline:0;box-shadow:none;text-shadow:none" />
        <input name="same_color_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <input name="same_color_border_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:1px solid white;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <div style="background:black">
          <input name="filter_darkened_password" type="password" autocomplete="current-password" style="filter:brightness(0);background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:rgb(128, 128, 128)">
          <input name="filter_contrast_password" type="password" autocomplete="current-password" style="filter:contrast(0);background:white;color:black;border:1px solid white" />
        </div>
        <input name="filter_inverted_password" type="password" autocomplete="current-password" style="filter:invert(1);background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <input name="font_zero_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;font-size:0;outline:0;box-shadow:none;text-shadow:none" />
        <input name="text_indent_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;text-indent:-9999px;outline:0;box-shadow:none;text-shadow:none" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="rotate_x_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 0 })
    );
    stubElementRect(
      document.querySelector('input[name="rotate_y_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 0, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="positioned_mask_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    for (const name of ["zero_percent_mask_password", "tiny_percent_mask_password"]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of [
      "svg_filter_near_offset_password",
      "svg_filter_object_offset_password",
      "ancestor_svg_filter_offset_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    stubElementRect(
      document.querySelector("#ancestor-filter-offset") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 1000, height: 48 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of [
      "transparent_mask_password",
      "radial_mask_password",
      "radial_shape_mask_password",
      "conic_from_mask_password",
      "linear_color_space_mask_password",
      "black_luminance_mask_password",
      "radial_black_luminance_mask_password",
      "stop_mask_password",
      "url_mask_password",
      "group_opacity_mask_password",
      "zero_mask_password",
      "zero_percent_mask_password",
      "tiny_mask_password",
      "tiny_percent_mask_password",
      "positioned_mask_password",
      "svg_filter_password",
      "svg_filter_discrete_password",
      "svg_filter_gamma_password",
      "svg_filter_matrix_password",
      "svg_filter_flood_password",
      "svg_filter_transparent_flood_password",
      "svg_filter_offset_password",
      "svg_filter_near_offset_password",
      "svg_filter_object_offset_password",
      "ancestor_svg_filter_offset_password",
      "cumulative_opacity_password",
      "cumulative_filter_password",
      "paintless_password",
      "same_color_password",
      "same_color_border_password",
      "filter_darkened_password",
      "filter_contrast_password",
      "filter_inverted_password",
      "font_zero_password",
      "text_indent_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:transparent");
    }
    for (const name of [
      "rotate_x_password",
      "rotate_y_password",
      "backface_password",
      "backface_matrix_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:zero-size");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps repeated paint masks viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="alphaVisibleGamma"><feComponentTransfer><feFuncA type="gamma" amplitude="1" offset="0" /></feComponentTransfer></filter>
          <filter id="smallOffset"><feOffset dx="4" dy="0" /></filter>
          <mask id="visibleGroupMask"><g opacity="1"><rect width="100%" height="100%" fill="white" /></g></mask>
        </svg>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4px 100%;mask-repeat:repeat" />
        <div style="background:black">
          <input name="contrast_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        </div>
        <input name="visible_darkened_password" type="password" autocomplete="current-password" style="filter:brightness(0);background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        <input name="visible_contrast_password" type="password" autocomplete="current-password" style="filter:contrast(0);background:white;color:black;border:1px solid white" />
        <div style="background:black">
          <input name="visible_inverted_password" type="password" autocomplete="current-password" style="filter:invert(1);background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        </div>
        <input name="group_mask_password" type="password" autocomplete="current-password" style="mask:url(#visibleGroupMask)" />
        <input name="positioned_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:100% 100%;mask-repeat:no-repeat;mask-position:100% 0" />
        <input name="gamma_filtered_password" type="password" autocomplete="current-password" style="filter:url(#alphaVisibleGamma)" />
        <input name="offset_filtered_password" type="password" autocomplete="current-password" style="filter:url(#smallOffset)" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="positioned_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="offset_filtered_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 80, width: 185, height: 21 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "contrast_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "contrast_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_darkened_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_darkened_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_contrast_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_contrast_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_inverted_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_inverted_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "group_mask_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "group_mask_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "positioned_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "positioned_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "gamma_filtered_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "gamma_filtered_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "offset_filtered_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "offset_filtered_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
  });

  it("treats fully occluded credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="covered_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:88px;width:185px;height:21px" />
        <div id="cover" style="position:absolute;left:0;top:80px;width:260px;height:48px;background:white"></div>
        <input name="pointer_events_covered_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:172px;width:185px;height:21px" />
        <div id="pointer-events-cover" style="position:absolute;left:0;top:164px;width:260px;height:48px;background:white;pointer-events:none"></div>
        <input name="shadow_covered_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:256px;width:185px;height:21px" />
        <div id="shadow-cover" style="position:absolute;left:0;top:0;width:1px;height:1px;box-shadow:116px 266px 0 120px white;pointer-events:none;z-index:10"></div>
        <div id="pseudo-cover-host" style="position:absolute;left:0;top:420px;width:260px;height:48px">
          <input name="pseudo_covered_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:8px;width:185px;height:21px;z-index:1" />
        </div>
        <div id="pseudo-after-cover-host" style="position:absolute;left:0;top:472px;width:260px;height:48px">
          <input name="pseudo_after_covered_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:8px;width:185px;height:21px" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const coveredPassword = document.querySelector(
      'input[name="covered_password"]'
    ) as HTMLInputElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    const pointerEventsCoveredPassword = document.querySelector(
      'input[name="pointer_events_covered_password"]'
    ) as HTMLInputElement;
    const shadowCoveredPassword = document.querySelector(
      'input[name="shadow_covered_password"]'
    ) as HTMLInputElement;
    const pseudoCoveredPassword = document.querySelector(
      'input[name="pseudo_covered_password"]'
    ) as HTMLInputElement;
    const pseudoAfterCoveredPassword = document.querySelector(
      'input[name="pseudo_after_covered_password"]'
    ) as HTMLInputElement;
    const cover = document.querySelector("#cover") as HTMLDivElement;
    const pointerEventsCover = document.querySelector("#pointer-events-cover") as HTMLDivElement;
    const shadowCover = document.querySelector("#shadow-cover") as HTMLDivElement;
    const pseudoCoverHost = document.querySelector("#pseudo-cover-host") as HTMLDivElement;
    const pseudoAfterCoverHost = document.querySelector(
      "#pseudo-after-cover-host"
    ) as HTMLDivElement;
    stubElementRect(coveredPassword, elementRect({ left: 24, top: 88, width: 185, height: 21 }));
    stubElementRect(
      pointerEventsCoveredPassword,
      elementRect({ left: 24, top: 172, width: 185, height: 21 })
    );
    stubElementRect(
      shadowCoveredPassword,
      elementRect({ left: 24, top: 256, width: 185, height: 21 })
    );
    stubElementRect(
      pseudoCoveredPassword,
      elementRect({ left: 24, top: 428, width: 185, height: 21 })
    );
    stubElementRect(
      pseudoAfterCoveredPassword,
      elementRect({ left: 24, top: 480, width: 185, height: 21 })
    );
    stubElementRect(pointerEventsCover, elementRect({ left: 0, top: 164, width: 260, height: 48 }));
    stubElementRect(shadowCover, elementRect({ left: 0, top: 0, width: 1, height: 1 }));
    stubElementRect(pseudoCoverHost, elementRect({ left: 0, top: 420, width: 260, height: 48 }));
    stubElementRect(
      pseudoAfterCoverHost,
      elementRect({ left: 0, top: 472, width: 260, height: 48 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 140, width: 185, height: 21 }));
    const pseudoCoverStyle = {
      content: '""',
      display: "block",
      visibility: "visible",
      opacity: "1",
      position: "absolute",
      left: "0px",
      top: "0px",
      width: "260px",
      height: "48px",
      background: "rgb(255, 255, 255)",
      "background-color": "rgb(255, 255, 255)",
      "background-image": "none",
      "box-shadow": "none",
      filter: "none"
    };
    const pseudoStyle = stubPseudoElementStyles([
      {
        element: pseudoCoverHost,
        pseudoElement: "::before",
        values: { ...pseudoCoverStyle, "z-index": "2" }
      },
      {
        element: pseudoAfterCoverHost,
        pseudoElement: "::after",
        values: { ...pseudoCoverStyle, "z-index": "auto" }
      }
    ]);
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 88 && y <= 109) {
          return cover;
        }
        if (x >= 24 && x <= 209 && y >= 172 && y <= 193) {
          return pointerEventsCoveredPassword;
        }
        if (x >= 24 && x <= 209 && y >= 256 && y <= 277) {
          return shadowCoveredPassword;
        }
        if (x >= 24 && x <= 209 && y >= 428 && y <= 449) {
          return pseudoCoveredPassword;
        }
        if (x >= 24 && x <= 209 && y >= 480 && y <= 501) {
          return pseudoAfterCoveredPassword;
        }
        if (x >= 24 && x <= 209 && y >= 140 && y <= 161) {
          return realPassword;
        }
        return document.body;
      }
    });

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });
    pseudoStyle.mockRestore();

    expect(fieldByName(report, "covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "covered_password").reasons).toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "pointer_events_covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "pointer_events_covered_password").reasons).toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "shadow_covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "shadow_covered_password").reasons).toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "pseudo_covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "pseudo_covered_password").reasons).toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "pseudo_after_covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "pseudo_after_covered_password").reasons).toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps credential fields viewable under lower z-index painted siblings", () => {
    document.body.innerHTML = `
      <form>
        <input name="visible_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:88px;width:185px;height:21px" />
        <div id="background-cover" style="position:absolute;left:0;top:80px;width:260px;height:48px;background:white;pointer-events:none;z-index:-1"></div>
        <div id="background-pseudo-host" style="position:absolute;left:0;top:140px;width:260px;height:48px">
          <input name="visible_pseudo_password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:8px;width:185px;height:21px;z-index:1" />
        </div>
      </form>
    `;
    const visiblePassword = document.querySelector(
      'input[name="visible_password"]'
    ) as HTMLInputElement;
    const visiblePseudoPassword = document.querySelector(
      'input[name="visible_pseudo_password"]'
    ) as HTMLInputElement;
    const backgroundCover = document.querySelector("#background-cover") as HTMLDivElement;
    const backgroundPseudoHost = document.querySelector(
      "#background-pseudo-host"
    ) as HTMLDivElement;
    stubElementRect(visiblePassword, elementRect({ left: 24, top: 88, width: 185, height: 21 }));
    stubElementRect(
      visiblePseudoPassword,
      elementRect({ left: 24, top: 148, width: 185, height: 21 })
    );
    stubElementRect(backgroundCover, elementRect({ left: 0, top: 80, width: 260, height: 48 }));
    stubElementRect(
      backgroundPseudoHost,
      elementRect({ left: 0, top: 140, width: 260, height: 48 })
    );
    const pseudoStyle = stubPseudoElementStyle(backgroundPseudoHost, "::before", {
      content: '""',
      display: "block",
      visibility: "visible",
      opacity: "1",
      position: "absolute",
      left: "0px",
      top: "0px",
      width: "260px",
      height: "48px",
      "z-index": "0",
      background: "rgb(255, 255, 255)",
      "background-color": "rgb(255, 255, 255)",
      "background-image": "none",
      "box-shadow": "none",
      filter: "none"
    });
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 88 && y <= 109) {
          return visiblePassword;
        }
        if (x >= 24 && x <= 209 && y >= 148 && y <= 169) {
          return visiblePseudoPassword;
        }
        return document.body;
      }
    });

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });
    pseudoStyle.mockRestore();

    expect(fieldByName(report, "visible_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_password").reasons).not.toContain(
      "not-viewable:occluded"
    );
    expect(fieldByName(report, "visible_pseudo_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_pseudo_password").reasons).not.toContain(
      "not-viewable:occluded"
    );
  });

  it("treats fields whose final rect is after the viewport as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="translated_y_password" type="password" autocomplete="current-password" style="transform:translateY(900px)" />
        <input name="longhand_translated_y_password" type="password" autocomplete="current-password" style="translate:0 900px" />
        <input name="fixed_below_password" type="password" autocomplete="current-password" style="position:fixed;top:900px" />
        <input name="fixed_bottom_below_password" type="password" autocomplete="current-password" style="position:fixed;bottom:-900px" />
        <input name="relative_password" type="password" autocomplete="current-password" style="position:relative;left:9999px" />
        <input name="margin_password" type="password" autocomplete="current-password" style="display:block;margin-left:9999px" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const name of [
      "translated_y_password",
      "longhand_translated_y_password",
      "fixed_below_password",
      "fixed_bottom_below_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 920, width: 185, height: 21 })
      );
    }
    for (const name of ["relative_password", "margin_password"]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 10024, top: 40, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of [
      "translated_y_password",
      "longhand_translated_y_password",
      "fixed_below_password",
      "fixed_bottom_below_password",
      "relative_password",
      "margin_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:offscreen");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats tiny credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="tiny_password" type="password" autocomplete="current-password" style="width:1px;height:1px" />
        <input name="tiny_rect_password" type="password" autocomplete="current-password" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="tiny_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 8, height: 6 })
    );
    stubElementRect(
      document.querySelector('input[name="tiny_rect_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 72, width: 8, height: 6 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "tiny_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "tiny_password").reasons).toContain("not-viewable:tiny");
    expect(fieldByName(report, "tiny_rect_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "tiny_rect_password").reasons).toContain("not-viewable:tiny");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps no-op clipped visible login fields viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="fullObjectClip" clipPathUnits="objectBoundingBox"><rect width="1" height="1" /></clipPath>
          <clipPath id="fullPathClip"><path d="M0 0 H185 V21 H0 Z" /></clipPath>
          <clipPath id="fullNestedClip"><rect width="185" height="21" clip-path="url(#fullPathClip)" /></clipPath>
        </svg>
        <input name="email" type="email" autocomplete="username" style="clip-path:inset(0)" />
        <input name="object_email" type="email" autocomplete="username" style="clip-path:url(#fullObjectClip)" />
        <input name="path_email" type="email" autocomplete="username" style='clip-path:path("M0 0 H185 V21 H0 Z")' />
        <input name="url_path_email" type="email" autocomplete="username" style="clip-path:url(#fullPathClip)" />
        <input name="nested_url_email" type="email" autocomplete="username" style="clip-path:url(#fullNestedClip)" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
      <input name="visible_circle_probe" type="text" style="clip-path:circle(closest-side at 50% 50%)" />
      <input name="visible_ellipse_probe" type="text" style="clip-path:ellipse(closest-side closest-side at 50% 50%)" />
    `;
    const topByFieldName: Record<string, number> = {
      object_email: 80,
      path_email: 100,
      url_path_email: 120,
      nested_url_email: 140,
      visible_circle_probe: 160,
      visible_ellipse_probe: 200
    };
    for (const name of [
      "email",
      "object_email",
      "path_email",
      "url_path_email",
      "nested_url_email",
      "visible_circle_probe",
      "visible_ellipse_probe"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({
          left: 24,
          top: topByFieldName[name] ?? 40,
          width: 185,
          height: 21
        })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "email").reasons).not.toContain("not-viewable:clipped");
    expect(fieldByName(report, "object_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "object_email").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "path_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "path_email").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_path_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "url_path_email").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "nested_url_email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "nested_url_email").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "visible_circle_probe").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "visible_ellipse_probe").reasons).not.toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
  });

  it("keeps stylesheet visibility-visible descendants of hidden ancestors viewable", () => {
    document.body.innerHTML = `
      <style>
        .host {
          visibility: hidden;
        }
        .shown {
          visibility: visible;
        }
      </style>
      <form class="host">
        <input class="shown" name="email" type="email" autocomplete="username" />
        <input class="shown" name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").qualifiedAs).toBe("username");
    expect(fieldByName(report, "email").reasons).not.toContain("not-viewable:css");
    expect(fieldByName(report, "password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "password").reasons).not.toContain("not-viewable:css");
  });

  it("treats visually suppressed credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="faint_email" type="email" autocomplete="username" style="opacity:0.005" />
        <input name="percent_opacity_email" type="email" autocomplete="username" style="opacity:1%" />
        <input name="filter_email" type="email" autocomplete="username" style="filter:opacity(0)" />
        <div style="content-visibility:hidden">
          <input name="content_hidden_email" type="email" autocomplete="username" />
        </div>
        <input name="translated_password" type="password" autocomplete="current-password" style="translate:-9999px" />
        <input name="longhand_scaled_password" type="password" autocomplete="current-password" style="scale:0" />
        <input name="zoom_zero_password" type="password" autocomplete="current-password" style="zoom:0" />
        <div style="transform:scale(0)">
          <input name="ancestor_scaled_password" type="password" autocomplete="current-password" />
        </div>
        <input name="scaled_password" type="password" autocomplete="current-password" style="transform:scale(0)" />
        <input name="real_user" type="email" autocomplete="username" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="zoom_zero_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 0, height: 0 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "faint_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "faint_email").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "percent_opacity_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "percent_opacity_email").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "filter_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "filter_email").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "content_hidden_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "content_hidden_email").reasons).toContain(
      "not-viewable:css"
    );
    expect(fieldByName(report, "translated_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "translated_password").reasons).toContain(
      "not-viewable:offscreen"
    );
    expect(fieldByName(report, "longhand_scaled_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "longhand_scaled_password").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "zoom_zero_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "zoom_zero_password").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "scaled_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "scaled_password").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "ancestor_scaled_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ancestor_scaled_password").reasons).toContain(
      "not-viewable:zero-size"
    );
    expect(fieldByName(report, "real_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats near-total clipped credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="zeroClip"><rect width="0" height="0" /></clipPath>
          <clipPath id="stripClip"><rect width="4" height="100" /></clipPath>
          <rect id="zeroRect" width="0" height="0" />
          <clipPath id="zeroPolygonClip"><polygon points="0,0 0,0 0,0" /></clipPath>
          <clipPath id="zeroPathClip"><path d="M0 0Z" /></clipPath>
          <clipPath id="zeroUseClip"><use href="#zeroRect" /></clipPath>
          <clipPath id="defsUseZeroClip"><defs><rect id="defsZeroRect" width="0" height="0" /></defs><use href="#defsZeroRect" /></clipPath>
          <clipPath id="anchorZeroClip"><a><rect width="0" height="0" /></a></clipPath>
          <clipPath id="metadataZeroClip"><title>decorative title</title><rect width="0" height="0" /></clipPath>
          <rect id="visibleRect" width="200" height="30" />
          <clipPath id="nestedAttrZeroClip"><rect width="200" height="30" clip-path="url(#zeroClip)" /></clipPath>
          <clipPath id="nestedStyleZeroClip"><rect width="200" height="30" style="clip-path:url(#zeroClip)" /></clipPath>
          <clipPath id="nestedGroupZeroClip"><g clip-path="url(#zeroClip)"><rect width="200" height="30" /></g></clipPath>
          <clipPath id="nestedUseZeroClip"><use href="#visibleRect" clip-path="url(#zeroClip)" /></clipPath>
          <clipPath id="emptyGroupClip"><g></g></clipPath>
          <clipPath id="lineClip"><line x1="0" y1="0" x2="200" y2="0" /></clipPath>
          <clipPath id="emptyTextClip"><text></text></clipPath>
          <clipPath id="displayNoneRectClip"><rect style="display:none" width="200" height="30" /></clipPath>
          <clipPath id="hiddenRectClip"><rect style="visibility:hidden" width="200" height="30" /></clipPath>
          <clipPath id="evenOddPathClip"><path clip-rule="evenodd" d="M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
          <clipPath id="evenOddCoveredPathClip"><path clip-rule="evenodd" d="M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
        </svg>
        <input name="inset_password" type="password" autocomplete="current-password" style="clip-path:inset(49%)" />
        <input name="rounded_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(49% round 2px)" />
        <input name="calc_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% - 4px) 0 0)" />
        <input name="circle_password" type="password" autocomplete="current-password" style="clip-path:circle(1px)" />
        <input name="polygon_strip_password" type="password" autocomplete="current-password" style="clip-path:polygon(0 0, 4px 0, 4px 100%, 0 100%)" />
        <input name="polygon_percent_password" type="password" autocomplete="current-password" style="clip-path:polygon(0 0, 10% 0, 10% 30%, 0 30%)" />
        <input name="circle_offset_password" type="password" autocomplete="current-password" style="clip-path:circle(50% at -9999px 50%)" />
        <input name="ellipse_offset_password" type="password" autocomplete="current-password" style="clip-path:ellipse(50% 50% at -9999px 50%)" />
        <input name="css_path_password" type="password" autocomplete="current-password" style='clip-path:path("M0 0Z")' />
        <input name="css_path_strip_password" type="password" autocomplete="current-password" style='clip-path:path("M0 0 L4 0 L4 100 L0 100 Z")' />
        <input name="clip_path_rect_password" type="password" autocomplete="current-password" style="clip-path:rect(0 4px 100px 0)" />
        <input name="clip_path_xywh_password" type="password" autocomplete="current-password" style="clip-path:xywh(0 0 4px 100%)" />
        <input name="clip_path_offset_xywh_password" type="password" autocomplete="current-password" style="clip-path:xywh(-9999px 0 200px 30px)" />
        <input name="clip_path_offset_rect_password" type="password" autocomplete="current-password" style="clip-path:rect(0 -9990px 30px -10000px)" />
        <input name="inset_offset_password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% + 9799px) calc(100% - 30px) -9999px)" />
        <input name="legacy_strip_password" type="password" autocomplete="current-password" style="position:absolute;clip:rect(0 4px 100px 0)" />
        <input name="legacy_offset_password" type="password" autocomplete="current-password" style="position:absolute;clip:rect(0 -9990px 30px -10000px)" />
        <input name="url_zero_password" type="password" autocomplete="current-password" style="clip-path:url(#zeroClip)" />
        <input name="url_strip_password" type="password" autocomplete="current-password" style="clip-path:url(#stripClip)" />
        <input name="url_polygon_password" type="password" autocomplete="current-password" style="clip-path:url(#zeroPolygonClip)" />
        <input name="url_path_password" type="password" autocomplete="current-password" style="clip-path:url(#zeroPathClip)" />
        <input name="url_use_password" type="password" autocomplete="current-password" style="clip-path:url(#zeroUseClip)" />
        <input name="url_defs_use_password" type="password" autocomplete="current-password" style="clip-path:url(#defsUseZeroClip)" />
        <input name="url_anchor_password" type="password" autocomplete="current-password" style="clip-path:url(#anchorZeroClip)" />
        <input name="url_metadata_password" type="password" autocomplete="current-password" style="clip-path:url(#metadataZeroClip)" />
        <input name="url_nested_attr_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedAttrZeroClip)" />
        <input name="url_nested_style_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedStyleZeroClip)" />
        <input name="url_nested_group_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedGroupZeroClip)" />
        <input name="url_nested_use_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedUseZeroClip)" />
        <input name="url_empty_group_password" type="password" autocomplete="current-password" style="clip-path:url(#emptyGroupClip)" />
        <input name="url_line_password" type="password" autocomplete="current-password" style="clip-path:url(#lineClip)" />
        <input name="url_empty_text_password" type="password" autocomplete="current-password" style="clip-path:url(#emptyTextClip)" />
        <input name="url_display_none_password" type="password" autocomplete="current-password" style="clip-path:url(#displayNoneRectClip)" />
        <input name="url_hidden_rect_password" type="password" autocomplete="current-password" style="clip-path:url(#hiddenRectClip)" />
        <input name="url_evenodd_path_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPathClip)" />
        <input name="css_evenodd_path_password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <input name="url_evenodd_covered_path_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddCoveredPathClip)" />
        <input name="css_evenodd_covered_path_password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <div style="width:2px;height:2px;overflow:hidden">
          <input name="ancestor_clipped_password" type="password" autocomplete="current-password" />
        </div>
        <div style="width:2px;height:2px;contain:paint">
          <input name="paint_contained_password" type="password" autocomplete="current-password" />
        </div>
        <div style="width:2px;height:2px;contain:strict">
          <input name="strict_contained_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector('input[name="polygon_percent_password"]') as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    for (const name of [
      "url_evenodd_path_password",
      "css_evenodd_path_password",
      "url_evenodd_covered_path_password",
      "css_evenodd_covered_path_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of [
      "circle_offset_password",
      "ellipse_offset_password",
      "clip_path_offset_xywh_password",
      "clip_path_offset_rect_password",
      "inset_offset_password",
      "legacy_offset_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 1208, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "inset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "inset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "rounded_inset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rounded_inset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "calc_inset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "calc_inset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "circle_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "circle_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "polygon_strip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "polygon_strip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "polygon_percent_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "polygon_percent_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "circle_offset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "circle_offset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "ellipse_offset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ellipse_offset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "css_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "css_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "css_path_strip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "css_path_strip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "clip_path_rect_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_rect_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "clip_path_xywh_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_xywh_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "clip_path_offset_xywh_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_offset_xywh_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "clip_path_offset_rect_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clip_path_offset_rect_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "inset_offset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "inset_offset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "legacy_strip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "legacy_strip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "legacy_offset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "legacy_offset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_zero_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_zero_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_strip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_strip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_polygon_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_polygon_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_use_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_use_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_defs_use_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_defs_use_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_anchor_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_anchor_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_metadata_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_metadata_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_nested_attr_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_nested_attr_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_nested_style_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_nested_style_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_nested_group_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_nested_group_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_nested_use_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_nested_use_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_empty_group_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_empty_group_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_line_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_line_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_empty_text_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_empty_text_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_display_none_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_display_none_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_hidden_rect_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_hidden_rect_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_evenodd_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_evenodd_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "css_evenodd_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "css_evenodd_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_evenodd_covered_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_evenodd_covered_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "css_evenodd_covered_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "css_evenodd_covered_path_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "ancestor_clipped_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ancestor_clipped_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "paint_contained_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "paint_contained_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "strict_contained_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "strict_contained_password").reasons).toContain(
      "not-viewable:clipped"
    );
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
        <input name="shadow_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hidden_shadow_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hidden_shadow_email").reasons).toContain("not-viewable:hidden");
    expect(fieldByName(report, "opaque_shadow_user").labelText).toBe("Email address");
    expect(fieldByName(report, "opaque_shadow_user").qualifiedAs).toBe("username");
    expect(fieldByName(report, "shadow_password").qualifiedAs).toBe("newPassword");
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
