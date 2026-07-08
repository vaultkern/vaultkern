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
        <div id="auto-overflow-clip" style="position:relative;width:185px;height:21px;overflow:auto">
          <input name="auto_overflow_clipped_email" type="email" autocomplete="username" style="position:absolute;left:181px;width:185px;height:21px" />
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
    stubElementRect(
      document.querySelector("#auto-overflow-clip") as HTMLDivElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="auto_overflow_clipped_email"]') as HTMLInputElement,
      elementRect({ left: 205, top: 40, width: 185, height: 21 })
    );

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
    expect(fieldByName(report, "auto_overflow_clipped_email").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "auto_overflow_clipped_email").reasons).toContain(
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
        <input name="percent_relative_password" type="password" autocomplete="current-password" style="position:relative;left:-800%" />
        <input name="calc_relative_password" type="password" autocomplete="current-password" style="position:relative;left:calc(-100% - 500px)" />
        <input name="percent_margin_password" type="password" autocomplete="current-password" style="display:block;margin-left:-800%" />
        <input name="calc_margin_password" type="password" autocomplete="current-password" style="display:block;margin-left:calc(-100% - 500px)" />
        <input name="viewport_translate_x_password" type="password" autocomplete="current-password" style="transform:translateX(-100vw)" />
        <input name="motion_path_password" type="password" autocomplete="current-password" style='offset-path:path("M -1000 0");offset-distance:100%' />
        <input name="translated_y_password" type="password" autocomplete="current-password" style="transform:translateY(-500px)" />
        <input name="longhand_translated_y_password" type="password" autocomplete="current-password" style="translate:0 -500px" />
        <input name="viewport_translate_y_password" type="password" autocomplete="current-password" style="translate:0 -100vh" />
        <input name="relative_y_password" type="password" autocomplete="current-password" style="position:relative;top:-500px" />
        <input name="percent_relative_y_password" type="password" autocomplete="current-password" style="position:relative;top:-800%" />
        <input name="calc_relative_y_password" type="password" autocomplete="current-password" style="position:relative;top:calc(-100% - 500px)" />
        <input name="viewport_relative_password" type="password" autocomplete="current-password" style="position:relative;left:-100vw" />
        <input name="margin_y_password" type="password" autocomplete="current-password" style="display:block;margin-top:-500px" />
        <input name="percent_margin_y_password" type="password" autocomplete="current-password" style="display:block;margin-top:-800%" />
        <input name="calc_margin_y_password" type="password" autocomplete="current-password" style="display:block;margin-top:calc(-100% - 500px)" />
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
      "percent_relative_password",
      "calc_relative_password",
      "percent_margin_password",
      "calc_margin_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: -1476, top: 40, width: 185, height: 21 })
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
    for (const name of [
      "percent_relative_y_password",
      "calc_relative_y_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: -1180, width: 185, height: 21 })
      );
    }
    for (const name of [
      "percent_margin_y_password",
      "calc_margin_y_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: -1476, width: 185, height: 21 })
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
      "percent_relative_password",
      "calc_relative_password",
      "percent_margin_password",
      "calc_margin_password",
      "viewport_translate_x_password",
      "motion_path_password",
      "translated_y_password",
      "longhand_translated_y_password",
      "viewport_translate_y_password",
      "relative_y_password",
      "percent_relative_y_password",
      "calc_relative_y_password",
      "viewport_relative_password",
      "margin_y_password",
      "percent_margin_y_password",
      "calc_margin_y_password",
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
          <filter id="alphaTenLinear"><feComponentTransfer><feFuncA type="linear" slope="0.1" intercept="0" /></feComponentTransfer></filter>
          <filter id="alphaTenTable"><feComponentTransfer><feFuncA type="table" tableValues="0.1 0.1" /></feComponentTransfer></filter>
          <filter id="alphaTenMatrix"><feColorMatrix type="matrix" values="1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0.1 0" /></filter>
          <filter id="floodAlphaZero"><feFlood flood-opacity="0" /></filter>
          <filter id="floodTransparent"><feFlood flood-color="transparent" /></filter>
          <filter id="floodBlack"><feFlood flood-color="black" /></filter>
          <filter id="matrixBlack"><feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0" /></filter>
          <filter id="mergedFloodBlack"><feFlood flood-color="black" result="blackPaint" /><feMerge><feMergeNode in="blackPaint" /></feMerge></filter>
          <filter id="componentBlack"><feComponentTransfer><feFuncR type="table" tableValues="0 0" /><feFuncG type="table" tableValues="0 0" /><feFuncB type="table" tableValues="0 0" /></feComponentTransfer></filter>
          <filter id="compositeBlackIn"><feFlood flood-color="black" result="blackPaint" /><feComposite in="blackPaint" in2="SourceAlpha" operator="in" /></filter>
          <filter id="blendBlack"><feFlood flood-color="black" result="blackPaint" /><feBlend in="blackPaint" in2="SourceGraphic" mode="normal" /></filter>
          <filter id="floodNamedBlue"><feFlood flood-color="blue" /></filter>
          <filter id="compositeInTransparent"><feFlood flood-opacity="0" result="transparent" /><feComposite in="SourceGraphic" in2="transparent" operator="in" /></filter>
          <filter id="morphologyErode"><feMorphology operator="erode" radius="9999" /></filter>
          <filter id="sourceOut"><feComposite in="SourceGraphic" in2="SourceAlpha" operator="out" /></filter>
          <filter id="arithmeticZero"><feComposite in="SourceGraphic" in2="SourceAlpha" operator="arithmetic" k1="0" k2="0" k3="0" k4="0" /></filter>
          <filter id="offsetSource"><feOffset dx="-9999" dy="0" /></filter>
          <filter id="nearOffsetSource"><feOffset dx="-500" dy="0" /></filter>
          <filter id="objectOffsetSource" primitiveUnits="objectBoundingBox"><feOffset dx="-3" dy="0" /></filter>
          <mask id="blackMask"><rect width="100%" height="100%" fill="black" /></mask>
          <mask id="transparentGroupMask"><g opacity="0"><rect width="100%" height="100%" fill="white" /></g></mask>
          <mask id="nestedOpacityMask"><g opacity="0.1"><rect opacity="0.1" width="100%" height="100%" fill="white" /></g></mask>
          <mask id="fillNoneMask"><rect width="100%" height="100%" fill="none" /></mask>
          <mask id="displayNoneMask"><rect style="display:none" width="100%" height="100%" fill="white" /></mask>
          <mask id="hiddenShapeMask"><rect style="visibility:hidden" width="100%" height="100%" fill="white" /></mask>
        </svg>
        <input name="transparent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent,transparent)" />
        <input name="radial_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(transparent, transparent)" />
        <input name="radial_shape_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, transparent, transparent)" />
        <input name="conic_from_mask_password" type="password" autocomplete="current-password" style="mask-image:conic-gradient(from 0deg, transparent, transparent)" />
        <input name="linear_color_space_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(in oklab, transparent, transparent)" />
        <input name="color_function_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(color(srgb 0 0 0 / 0), color(srgb 0 0 0 / 0))" />
        <input name="black_luminance_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black, black);mask-mode:luminance" />
        <input name="radial_black_luminance_mask_password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, black, black);mask-mode:luminance" />
        <input name="stop_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent 0 100%)" />
        <input name="composite_exclude_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black),linear-gradient(black,black);mask-composite:exclude" />
        <input name="url_mask_password" type="password" autocomplete="current-password" style="mask:url(#blackMask)" />
        <input name="group_opacity_mask_password" type="password" autocomplete="current-password" style="mask:url(#transparentGroupMask)" />
        <input name="nested_opacity_mask_password" type="password" autocomplete="current-password" style="mask:url(#nestedOpacityMask)" />
        <input name="fill_none_mask_password" type="password" autocomplete="current-password" style="mask:url(#fillNoneMask)" />
        <input name="display_none_mask_password" type="password" autocomplete="current-password" style="mask:url(#displayNoneMask)" />
        <input name="hidden_shape_mask_password" type="password" autocomplete="current-password" style="mask:url(#hiddenShapeMask)" />
        <input name="data_svg_mask_password" type="password" autocomplete="current-password" style='mask-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%221%22%20height%3D%221%22%3E%3Crect%20width%3D%221%22%20height%3D%221%22%20fill%3D%22transparent%22%2F%3E%3C%2Fsvg%3E")' />
        <input name="data_svg_root_opacity_mask_password" type="password" autocomplete="current-password" style='mask-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%221%22%20height%3D%221%22%20opacity%3D%220%22%3E%3Crect%20width%3D%221%22%20height%3D%221%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E")' />
        <input name="blob_url_mask_password" type="password" autocomplete="current-password" style='mask-image:url("blob:null/transparent-mask")' />
        <input name="zero_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0 0" />
        <input name="zero_percent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0% 100%;mask-repeat:no-repeat" />
        <input name="tiny_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4px 100%;mask-repeat:no-repeat" />
        <input name="tiny_percent_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4% 100%;mask-repeat:no-repeat" />
        <input name="positioned_mask_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:100% 100%;mask-repeat:no-repeat;mask-position:-9999px 0" />
        <input name="svg_filter_password" type="password" autocomplete="current-password" style="filter:url(#alphaZero)" />
        <input name="data_svg_filter_password" type="password" autocomplete="current-password" style='filter:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%3Cfilter%20id%3D%22alphaZero%22%3E%3CfeComponentTransfer%3E%3CfeFuncA%20type%3D%22table%22%20tableValues%3D%220%200%22%2F%3E%3C%2FfeComponentTransfer%3E%3C%2Ffilter%3E%3C%2Fsvg%3E#alphaZero")' />
        <input name="blob_url_filter_password" type="password" autocomplete="current-password" style='filter:url("blob:null/alpha-zero#f")' />
        <input name="svg_filter_discrete_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroDiscrete)" />
        <input name="svg_filter_gamma_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroGamma)" />
        <input name="svg_filter_matrix_password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroMatrix)" />
        <input name="svg_filter_flood_password" type="password" autocomplete="current-password" style="filter:url(#floodAlphaZero)" />
        <input name="svg_filter_transparent_flood_password" type="password" autocomplete="current-password" style="filter:url(#floodTransparent)" />
        <div style="background:black">
          <input name="svg_filter_black_flood_password" type="password" autocomplete="current-password" style="filter:url(#floodBlack)" />
          <input name="svg_filter_black_matrix_password" type="password" autocomplete="current-password" style="filter:url(#matrixBlack)" />
          <input name="svg_filter_merged_black_flood_password" type="password" autocomplete="current-password" style="filter:url(#mergedFloodBlack)" />
          <input name="svg_filter_black_component_password" type="password" autocomplete="current-password" style="filter:url(#componentBlack)" />
          <input name="svg_filter_black_composite_password" type="password" autocomplete="current-password" style="filter:url(#compositeBlackIn)" />
          <input name="svg_filter_black_blend_password" type="password" autocomplete="current-password" style="filter:url(#blendBlack)" />
        </div>
        <div style="background:rgb(0,0,255)">
          <input name="svg_filter_named_blue_password" type="password" autocomplete="current-password" style="filter:url(#floodNamedBlue)" />
        </div>
        <input name="svg_filter_composite_in_password" type="password" autocomplete="current-password" style="filter:url(#compositeInTransparent)" />
        <input name="svg_filter_morphology_password" type="password" autocomplete="current-password" style="filter:url(#morphologyErode)" />
        <input name="svg_filter_composite_out_password" type="password" autocomplete="current-password" style="filter:url(#sourceOut)" />
        <input name="svg_filter_arithmetic_zero_password" type="password" autocomplete="current-password" style="filter:url(#arithmeticZero)" />
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
        <div style="opacity:0.1">
          <div style="filter:opacity(10%)">
            <input name="mixed_opacity_filter_password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div style="opacity:0.1">
          <input name="mixed_svg_linear_filter_password" type="password" autocomplete="current-password" style="filter:url(#alphaTenLinear)" />
          <input name="mixed_svg_table_filter_password" type="password" autocomplete="current-password" style="filter:url(#alphaTenTable)" />
          <input name="mixed_svg_matrix_filter_password" type="password" autocomplete="current-password" style="filter:url(#alphaTenMatrix)" />
        </div>
        <input name="rotate_x_password" type="password" autocomplete="current-password" style="rotate:x 90deg" />
        <input name="rotate_y_password" type="password" autocomplete="current-password" style="rotate:y 90deg" />
        <input name="backface_password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:rotateY(180deg)" />
        <input name="backface_matrix_password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:matrix3d(-1,0,0,0,0,1,0,0,0,0,-1,0,0,0,0,1)" />
        <div style="transform:rotateY(180deg);transform-style:preserve-3d">
          <input name="ancestor_backface_password" type="password" autocomplete="current-password" style="backface-visibility:hidden" />
        </div>
        <input name="calc_opacity_password" type="password" autocomplete="current-password" style="opacity:calc(0)" />
        <input name="paintless_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:transparent;-webkit-text-fill-color:transparent;outline:0;box-shadow:none;text-shadow:none" />
        <input name="same_color_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <input name="same_color_border_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:1px solid white;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <input name="tiny_font_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;-webkit-text-fill-color:black;font-size:1px;outline:0;box-shadow:none;text-shadow:none" />
        <div style="background:black">
          <input name="filter_darkened_password" type="password" autocomplete="current-password" style="filter:brightness(0);background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:black;filter:brightness(0)">
          <input name="ancestor_filter_darkened_password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:rgb(128, 128, 128)">
          <input name="filter_contrast_password" type="password" autocomplete="current-password" style="filter:contrast(0);background:white;color:black;border:1px solid white" />
        </div>
        <div style="background:rgb(128, 128, 128);filter:contrast(0)">
          <input name="ancestor_filter_contrast_password" type="password" autocomplete="current-password" style="background:white;color:black;border:1px solid white" />
        </div>
        <input name="filter_inverted_password" type="password" autocomplete="current-password" style="filter:invert(1);background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <input name="blend_screen_password" type="password" autocomplete="current-password" style="mix-blend-mode:screen;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <div style="mix-blend-mode:screen">
          <input name="ancestor_blend_screen_password" type="password" autocomplete="current-password" style="background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        </div>
        <div style="background:black">
          <input name="blend_multiply_password" type="password" autocomplete="current-password" style="mix-blend-mode:multiply;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:black">
          <div style="mix-blend-mode:multiply">
            <input name="ancestor_blend_multiply_password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
          </div>
        </div>
        <div style="background-image:linear-gradient(black, black)">
          <input name="gradient_backdrop_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none" />
        </div>
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
      "color_function_mask_password",
      "black_luminance_mask_password",
      "radial_black_luminance_mask_password",
      "stop_mask_password",
      "composite_exclude_mask_password",
      "url_mask_password",
      "group_opacity_mask_password",
      "nested_opacity_mask_password",
      "fill_none_mask_password",
      "display_none_mask_password",
      "hidden_shape_mask_password",
      "data_svg_mask_password",
      "data_svg_root_opacity_mask_password",
      "blob_url_mask_password",
      "zero_mask_password",
      "zero_percent_mask_password",
      "tiny_mask_password",
      "tiny_percent_mask_password",
      "positioned_mask_password",
      "svg_filter_password",
      "data_svg_filter_password",
      "blob_url_filter_password",
      "svg_filter_discrete_password",
      "svg_filter_gamma_password",
      "svg_filter_matrix_password",
      "svg_filter_flood_password",
      "svg_filter_transparent_flood_password",
      "svg_filter_black_flood_password",
      "svg_filter_black_matrix_password",
      "svg_filter_merged_black_flood_password",
      "svg_filter_black_component_password",
      "svg_filter_black_composite_password",
      "svg_filter_black_blend_password",
      "svg_filter_named_blue_password",
      "svg_filter_composite_in_password",
      "svg_filter_morphology_password",
      "svg_filter_composite_out_password",
      "svg_filter_arithmetic_zero_password",
      "svg_filter_offset_password",
      "svg_filter_near_offset_password",
      "svg_filter_object_offset_password",
      "ancestor_svg_filter_offset_password",
      "cumulative_opacity_password",
      "cumulative_filter_password",
      "mixed_opacity_filter_password",
      "mixed_svg_linear_filter_password",
      "mixed_svg_table_filter_password",
      "mixed_svg_matrix_filter_password",
      "calc_opacity_password",
      "paintless_password",
      "same_color_password",
      "same_color_border_password",
      "tiny_font_password",
      "filter_darkened_password",
      "ancestor_filter_darkened_password",
      "filter_contrast_password",
      "ancestor_filter_contrast_password",
      "filter_inverted_password",
      "blend_screen_password",
      "ancestor_blend_screen_password",
      "blend_multiply_password",
      "ancestor_blend_multiply_password",
      "gradient_backdrop_password",
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
      "backface_matrix_password",
      "ancestor_backface_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:zero-size");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats extended blend-mode credential decoys as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="color_dodge_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:color-dodge" />
        <div style="background:black">
          <input name="color_burn_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:color-burn" />
        </div>
        <input name="plus_lighter_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:plus-lighter" />
        <div style="background:rgb(64,64,64)">
          <input name="overlay_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:overlay" />
          <input name="hard_light_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:hard-light" />
          <input name="soft_light_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:soft-light" />
        </div>
        <div style="background:rgb(128,128,128)">
          <input name="hue_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:hue" />
          <input name="saturation_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:saturation" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, name] of [
      "color_dodge_password",
      "color_burn_password",
      "plus_lighter_password",
      "overlay_password",
      "hard_light_password",
      "soft_light_password",
      "hue_password",
      "saturation_password",
      "real_password"
    ].entries()) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of [
      "color_dodge_password",
      "color_burn_password",
      "plus_lighter_password",
      "overlay_password",
      "hard_light_password",
      "soft_light_password",
      "hue_password",
      "saturation_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:transparent");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats modern CSS color-function credential decoys as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="srgb_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:color(srgb 1 1 1);color:color(srgb 1 1 1);-webkit-text-fill-color:color(srgb 1 1 1);border:1px solid color(srgb 1 1 1);outline:0;box-shadow:none;text-shadow:none" />
        <input name="oklab_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:oklab(1 0 0);color:oklab(1 0 0);-webkit-text-fill-color:oklab(1 0 0);border:1px solid oklab(1 0 0);outline:0;box-shadow:none;text-shadow:none" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, name] of [
      "srgb_password",
      "oklab_password",
      "real_password"
    ].entries()) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of ["srgb_password", "oklab_password"]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:transparent");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by CSS grayscale filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(54,54,54)">
          <input name="grayscale_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:grayscale(1)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "grayscale_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "grayscale_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by CSS saturation filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(54,54,54)">
          <input name="saturate_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:saturate(0)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "saturate_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "saturate_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by CSS sepia filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(100,89,69)">
          <input name="sepia_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:sepia(1)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "sepia_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "sepia_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by CSS hue rotation filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(0,109,109)">
          <input name="hue_rotate_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:hue-rotate(180deg)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hue_rotate_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hue_rotate_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG saturation filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgSaturateZero">
            <feColorMatrix type="saturate" values="0" />
          </filter>
        </svg>
        <div style="background:rgb(127,127,127)">
          <input name="svg_saturate_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgSaturateZero)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_saturate_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "svg_saturate_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG hue rotation filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgHueRotateHalfTurn">
            <feColorMatrix type="hueRotate" values="180" />
          </filter>
        </svg>
        <div style="background:rgb(0,175,175)">
          <input name="svg_hue_rotate_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgHueRotateHalfTurn)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_hue_rotate_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "svg_hue_rotate_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG matrix filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgMatrixGray" color-interpolation-filters="sRGB">
            <feColorMatrix type="matrix" values="0.498 0 0 0 0 0.498 0 0 0 0 0.498 0 0 0 0 0 0 0 1 0" />
          </filter>
        </svg>
        <div style="background:rgb(127,127,127)">
          <input name="svg_matrix_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgMatrixGray)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_matrix_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "svg_matrix_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG luminance-to-alpha filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgLuminanceToAlpha">
            <feColorMatrix type="luminanceToAlpha" />
          </filter>
        </svg>
        <div style="background:black">
          <input name="svg_luminance_alpha_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgLuminanceToAlpha)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_luminance_alpha_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "svg_luminance_alpha_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG component transfer filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgComponentTransferGray">
            <feComponentTransfer color-interpolation-filters="sRGB">
              <feFuncR type="linear" slope="0.498" intercept="0" />
              <feFuncG type="linear" slope="0" intercept="0.498" />
              <feFuncB type="linear" slope="0" intercept="0.498" />
            </feComponentTransfer>
          </filter>
        </svg>
        <div style="background:rgb(127,127,127)">
          <input name="svg_component_transfer_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgComponentTransferGray)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_component_transfer_password").qualifiedAs).toBe(
      "ignored"
    );
    expect(fieldByName(report, "svg_component_transfer_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG difference blend filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgDifferenceBlend" color-interpolation-filters="sRGB">
            <feFlood flood-color="cyan" result="cyanPaint" />
            <feComposite in="cyanPaint" in2="SourceAlpha" operator="in" result="maskedCyanPaint" />
            <feBlend in="SourceGraphic" in2="maskedCyanPaint" mode="difference" />
          </filter>
        </svg>
        <div style="background:white">
          <input name="svg_difference_blend_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgDifferenceBlend)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "svg_difference_blend_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "svg_difference_blend_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by SVG blend filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="multiplyBlack">
            <feFlood flood-color="black" result="blackPaint" />
            <feBlend in="SourceGraphic" in2="blackPaint" mode="multiply" />
          </filter>
        </svg>
        <div style="background:black">
          <input name="multiply_black_password" type="password" autocomplete="current-password" style="filter:url(#multiplyBlack)" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "multiply_black_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "multiply_black_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields hidden by transparent SVG filter images as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="transparentImageFilter">
            <feImage href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%221%22%20height%3D%221%22%3E%3Crect%20width%3D%221%22%20height%3D%221%22%20fill%3D%22transparent%22%2F%3E%3C%2Fsvg%3E" x="0" y="0" width="100%" height="100%" />
          </filter>
          <filter id="blobImageFilter">
            <feImage href="blob:null/transparent-filter-image" x="0" y="0" width="100%" height="100%" />
          </filter>
        </svg>
        <input name="filtered_image_password" type="password" autocomplete="current-password" style="filter:url(#transparentImageFilter)" />
        <input name="blob_filtered_image_password" type="password" autocomplete="current-password" style="filter:url(#blobImageFilter)" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    for (const name of ["filtered_image_password", "blob_filtered_image_password"]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:transparent");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields displaced out of paint by SVG filters as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="displacedSource" x="-1000" y="-1000" width="2000" height="2000" filterUnits="userSpaceOnUse">
            <feFlood flood-color="white" result="map" />
            <feDisplacementMap in="SourceGraphic" in2="map" scale="2000" xChannelSelector="R" yChannelSelector="G" />
          </filter>
        </svg>
        <input name="displaced_password" type="password" autocomplete="current-password" style="filter:url(#displacedSource)" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "displaced_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "displaced_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats credential fields clipped to tiny SVG filter regions as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="tinyFilterRegion" x="0" y="0" width="0.01" height="0.01" filterUnits="objectBoundingBox">
            <feOffset dx="0" dy="0" />
          </filter>
        </svg>
        <input name="tiny_filter_region_password" type="password" autocomplete="current-password" style="filter:url(#tinyFilterRegion)" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, name] of [
      "tiny_filter_region_password",
      "real_password"
    ].entries()) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "tiny_filter_region_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "tiny_filter_region_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps flattened preserve-3d backface fields viewable", () => {
    document.body.innerHTML = `
      <form>
        <div style="transform:rotateY(180deg);transform-style:preserve-3d;opacity:.999">
          <input name="login_password" type="password" autocomplete="current-password" style="backface-visibility:hidden" />
        </div>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "login_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "login_password").reasons).not.toContain(
      "not-viewable:zero-size"
    );
  });

  it("treats merged filter-offset credential fields as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="mergedOffsetSource">
            <feOffset dx="-500" dy="0" result="moved" />
            <feMerge><feMergeNode in="moved" /></feMerge>
          </filter>
        </svg>
        <label id="merged-filter-label" for="merged-filter-password">Password</label>
        <input id="merged-filter-password" name="merged_filter_password" type="password" autocomplete="current-password" style="filter:url(#mergedOffsetSource)" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const mergedFilterPassword = document.querySelector(
      "#merged-filter-password"
    ) as HTMLInputElement;
    const mergedFilterLabel = document.querySelector(
      "#merged-filter-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      mergedFilterPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      mergedFilterLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return mergedFilterLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "merged_filter_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "merged_filter_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("keeps repeated paint masks viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="alphaVisibleGamma"><feComponentTransfer><feFuncA type="gamma" amplitude="1" offset="0" /></feComponentTransfer></filter>
          <filter id="smallOffset"><feOffset dx="4" dy="0" /></filter>
          <filter id="sourceOver"><feComposite in="SourceGraphic" in2="SourceAlpha" operator="over" /></filter>
          <filter id="arithmeticVisible"><feComposite in="SourceGraphic" in2="SourceAlpha" operator="arithmetic" k1="0" k2="1" k3="0" k4="0" /></filter>
          <filter id="unusedAlphaZero">
            <feComponentTransfer in="SourceGraphic" result="hiddenBranch">
              <feFuncA type="table" tableValues="0 0" />
            </feComponentTransfer>
            <feMerge><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <mask id="visibleGroupMask"><g opacity="1"><rect width="100%" height="100%" fill="white" /></g></mask>
        </svg>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4px 100%;mask-repeat:repeat" />
        <div style="background:black">
          <input name="contrast_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        </div>
        <input name="visible_darkened_password" type="password" autocomplete="current-password" style="filter:brightness(0);background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        <div style="filter:brightness(0)">
          <input name="visible_ancestor_darkened_password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <input name="visible_contrast_password" type="password" autocomplete="current-password" style="filter:contrast(0);background:white;color:black;border:1px solid white" />
        <div style="filter:contrast(0)">
          <input name="visible_ancestor_contrast_password" type="password" autocomplete="current-password" style="background:white;color:black;border:1px solid white" />
        </div>
        <div style="background:black">
          <input name="visible_inverted_password" type="password" autocomplete="current-password" style="filter:invert(1);background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        </div>
        <div style="background:black">
          <input name="visible_screen_blend_password" type="password" autocomplete="current-password" style="mix-blend-mode:screen;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:black">
          <div style="mix-blend-mode:screen">
            <input name="visible_ancestor_screen_blend_password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
          </div>
        </div>
        <input name="visible_multiply_blend_password" type="password" autocomplete="current-password" style="mix-blend-mode:multiply;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <div style="mix-blend-mode:multiply">
          <input name="visible_ancestor_multiply_blend_password" type="password" autocomplete="current-password" style="background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        </div>
        <div style="background-image:linear-gradient(black, black)">
          <input name="visible_gradient_backdrop_password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white;outline:0;box-shadow:none;text-shadow:none" />
        </div>
        <input name="group_mask_password" type="password" autocomplete="current-password" style="mask:url(#visibleGroupMask)" />
        <input name="positioned_password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:100% 100%;mask-repeat:no-repeat;mask-position:100% 0" />
        <input name="gamma_filtered_password" type="password" autocomplete="current-password" style="filter:url(#alphaVisibleGamma)" />
        <input name="offset_filtered_password" type="password" autocomplete="current-password" style="filter:url(#smallOffset)" />
        <input name="composite_over_password" type="password" autocomplete="current-password" style="filter:url(#sourceOver)" />
        <input name="arithmetic_visible_password" type="password" autocomplete="current-password" style="filter:url(#arithmeticVisible)" />
        <input name="unused_alpha_branch_password" type="password" autocomplete="current-password" style="filter:url(#unusedAlphaZero)" />
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
    expect(fieldByName(report, "visible_ancestor_darkened_password").qualifiedAs).toBe(
      "password"
    );
    expect(fieldByName(report, "visible_ancestor_darkened_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_contrast_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_contrast_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_ancestor_contrast_password").qualifiedAs).toBe(
      "password"
    );
    expect(fieldByName(report, "visible_ancestor_contrast_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_inverted_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_inverted_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_screen_blend_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_screen_blend_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_ancestor_screen_blend_password").qualifiedAs).toBe(
      "password"
    );
    expect(fieldByName(report, "visible_ancestor_screen_blend_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_multiply_blend_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_multiply_blend_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_ancestor_multiply_blend_password").qualifiedAs).toBe(
      "password"
    );
    expect(fieldByName(report, "visible_ancestor_multiply_blend_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "visible_gradient_backdrop_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "visible_gradient_backdrop_password").reasons).not.toContain(
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
    expect(fieldByName(report, "composite_over_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "composite_over_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "arithmetic_visible_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "arithmetic_visible_password").reasons).not.toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "unused_alpha_branch_password").qualifiedAs).toBe("password");
    expect(fieldByName(report, "unused_alpha_branch_password").reasons).not.toContain(
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

  it("treats fields covered by sibling pseudo-elements as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input name="pseudo_sibling_covered_password" type="password" autocomplete="current-password" />
        <div id="sibling-pseudo-cover" style="position:absolute;left:24px;top:40px;width:1px;height:1px;z-index:10"></div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const coveredPassword = document.querySelector(
      'input[name="pseudo_sibling_covered_password"]'
    ) as HTMLInputElement;
    const pseudoCover = document.querySelector("#sibling-pseudo-cover") as HTMLDivElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(coveredPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(pseudoCover, elementRect({ left: 24, top: 40, width: 1, height: 1 }));
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const pseudoStyle = stubPseudoElementStyle(pseudoCover, "::before", {
      content: '""',
      display: "block",
      visibility: "visible",
      opacity: "1",
      position: "absolute",
      left: "0px",
      top: "0px",
      width: "185px",
      height: "21px",
      background: "rgb(255, 255, 255)",
      "background-color": "rgb(255, 255, 255)",
      "background-image": "none",
      "box-shadow": "none",
      filter: "none",
      "z-index": "1"
    });
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return coveredPassword;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "pseudo_sibling_covered_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "pseudo_sibling_covered_password").reasons).toContain(
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
        <div id="wide-overflow-clip" style="width:185px;height:21px;overflow:hidden">
          <input name="visible_partial_ancestor_clip_password" type="password" autocomplete="current-password" style="position:relative;left:-20px" />
        </div>
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
      visible_partial_ancestor_clip_password: 160,
      visible_circle_probe: 160,
      visible_ellipse_probe: 200
    };
    for (const name of [
      "email",
      "object_email",
      "path_email",
      "url_path_email",
      "nested_url_email",
      "visible_partial_ancestor_clip_password",
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
    stubElementRect(
      document.querySelector("#wide-overflow-clip") as HTMLDivElement,
      elementRect({ left: 24, top: 160, width: 185, height: 21 })
    );

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
    expect(fieldByName(report, "visible_partial_ancestor_clip_password").reasons).not.toContain(
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
          <clipPath id="switchZeroClip"><switch><rect width="0" height="0" /><rect width="200" height="30" /></switch></clipPath>
          <clipPath id="metadataZeroClip"><title>decorative title</title><rect width="0" height="0" /></clipPath>
          <rect id="visibleRect" width="200" height="30" />
          <clipPath id="nestedAttrZeroClip"><rect width="200" height="30" clip-path="url(#zeroClip)" /></clipPath>
          <clipPath id="nestedStyleZeroClip"><rect width="200" height="30" style="clip-path:url(#zeroClip)" /></clipPath>
          <clipPath id="nestedGroupZeroClip"><g clip-path="url(#zeroClip)"><rect width="200" height="30" /></g></clipPath>
          <clipPath id="nestedUseZeroClip"><use href="#visibleRect" clip-path="url(#zeroClip)" /></clipPath>
          <clipPath id="emptyGroupClip"><g></g></clipPath>
          <clipPath id="lineClip"><line x1="0" y1="0" x2="200" y2="0" /></clipPath>
          <clipPath id="emptyTextClip"><text></text></clipPath>
          <clipPath id="textClip"><text x="0" y="10" font-size="10">x</text></clipPath>
          <clipPath id="displayNoneRectClip"><rect style="display:none" width="200" height="30" /></clipPath>
          <clipPath id="hiddenRectClip"><rect style="visibility:hidden" width="200" height="30" /></clipPath>
          <clipPath id="evenOddPolygonClip"><polygon clip-rule="evenodd" points="0,0 200,0 200,30 0,30 0,0 200,0 200,30 0,30" /></clipPath>
          <clipPath id="evenOddSinglePathClip"><path clip-rule="evenodd" d="M0 0 L200 0 L200 30 L0 30 L0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
          <clipPath id="evenOddPathClip"><path clip-rule="evenodd" d="M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
          <clipPath id="evenOddCoveredPathClip"><path clip-rule="evenodd" d="M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
        </svg>
        <input name="inset_password" type="password" autocomplete="current-password" style="clip-path:inset(49%)" />
        <input name="rounded_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(49% round 2px)" />
        <input name="calc_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% - 4px) 0 0)" />
        <input name="math_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(0 max(0px, calc(100% - 4px)) 0 0)" />
        <input name="clamp_inset_password" type="password" autocomplete="current-password" style="clip-path:inset(0 clamp(0px, calc(100% - 4px), 100%) 0 0)" />
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
        <input name="url_switch_password" type="password" autocomplete="current-password" style="clip-path:url(#switchZeroClip)" />
        <input name="url_metadata_password" type="password" autocomplete="current-password" style="clip-path:url(#metadataZeroClip)" />
        <input name="url_nested_attr_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedAttrZeroClip)" />
        <input name="url_nested_style_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedStyleZeroClip)" />
        <input name="url_nested_group_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedGroupZeroClip)" />
        <input name="url_nested_use_password" type="password" autocomplete="current-password" style="clip-path:url(#nestedUseZeroClip)" />
        <input name="url_empty_group_password" type="password" autocomplete="current-password" style="clip-path:url(#emptyGroupClip)" />
        <input name="url_line_password" type="password" autocomplete="current-password" style="clip-path:url(#lineClip)" />
        <input name="url_empty_text_password" type="password" autocomplete="current-password" style="clip-path:url(#emptyTextClip)" />
        <input name="url_text_password" type="password" autocomplete="current-password" style="clip-path:url(#textClip)" />
        <input name="url_display_none_password" type="password" autocomplete="current-password" style="clip-path:url(#displayNoneRectClip)" />
        <input name="url_hidden_rect_password" type="password" autocomplete="current-password" style="clip-path:url(#hiddenRectClip)" />
        <input name="data_url_clip_password" type="password" autocomplete="current-password" style='clip-path:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%3CclipPath%20id%3D%22z%22%3E%3Crect%20width%3D%220%22%20height%3D%220%22%2F%3E%3C%2FclipPath%3E%3C%2Fsvg%3E#z")' />
        <input name="blob_url_clip_password" type="password" autocomplete="current-password" style='clip-path:url("blob:null/zero-clip#z")' />
        <input name="url_evenodd_polygon_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPolygonClip)" />
        <input name="url_evenodd_single_path_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddSinglePathClip)" />
        <input name="url_evenodd_path_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPathClip)" />
        <input name="css_evenodd_path_password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <input name="url_evenodd_covered_path_password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddCoveredPathClip)" />
        <input name="css_evenodd_covered_path_password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <div style="width:2px;height:2px;overflow:hidden">
          <input name="ancestor_clipped_password" type="password" autocomplete="current-password" />
        </div>
        <div id="ancestor-strip-clip" style="width:185px;height:21px;overflow:hidden">
          <input name="ancestor_strip_clipped_password" type="password" autocomplete="current-password" style="position:relative;left:-181px" />
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
    for (const name of [
      "math_inset_password",
      "clamp_inset_password",
      "polygon_percent_password"
    ]) {
      stubElementRect(
        document.querySelector(`input[name="${name}"]`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const name of [
      "url_evenodd_path_password",
      "url_evenodd_polygon_password",
      "url_evenodd_single_path_password",
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
    stubElementRect(
      document.querySelector("#ancestor-strip-clip") as HTMLDivElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector('input[name="ancestor_strip_clipped_password"]') as HTMLInputElement,
      elementRect({ left: -157, top: 40, width: 185, height: 21 })
    );

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
    expect(fieldByName(report, "math_inset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "math_inset_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "clamp_inset_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "clamp_inset_password").reasons).toContain(
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
    expect(fieldByName(report, "url_switch_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_switch_password").reasons).toContain(
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
    expect(fieldByName(report, "url_text_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_text_password").reasons).toContain(
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
    expect(fieldByName(report, "data_url_clip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "data_url_clip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "blob_url_clip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "blob_url_clip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_evenodd_polygon_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_evenodd_polygon_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "url_evenodd_single_path_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "url_evenodd_single_path_password").reasons).toContain(
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
    expect(fieldByName(report, "ancestor_strip_clipped_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "ancestor_strip_clipped_password").reasons).toContain(
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

  it("treats fields hidden by evenodd polygon clip paths as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <input id="evenodd-polygon-password" name="evenodd_polygon_password" type="password" autocomplete="current-password" style="clip-path:polygon(evenodd, 0 0, 100% 0, 100% 100%, 0 100%, 0 0, 100% 0, 100% 100%, 0 100%)" />
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#evenodd-polygon-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "evenodd_polygon_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "evenodd_polygon_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by rounded overflow clips as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div id="rounded-clip" style="position:relative;width:200px;height:200px;overflow:hidden;border-radius:50%">
          <input name="rounded_corner_password" type="password" autocomplete="current-password" style="position:absolute;left:0;top:0;width:20px;height:20px" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#rounded-clip") as HTMLDivElement,
      elementRect({ left: 20, top: 20, width: 200, height: 200 })
    );
    stubElementRect(
      document.querySelector('input[name="rounded_corner_password"]') as HTMLInputElement,
      elementRect({ left: 20, top: 20, width: 26, height: 24 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "rounded_corner_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rounded_corner_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden outside ancestor mask clip boxes as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <div id="mask-clip" style="position:relative;width:200px;height:60px;padding-left:220px;mask-image:linear-gradient(black,black);mask-clip:content-box">
          <input name="mask_clip_password" type="password" autocomplete="current-password" style="position:absolute;left:0;top:0;width:185px;height:21px" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#mask-clip") as HTMLDivElement,
      elementRect({ left: 20, top: 20, width: 420, height: 60 })
    );
    stubElementRect(
      document.querySelector('input[name="mask_clip_password"]') as HTMLInputElement,
      elementRect({ left: 20, top: 20, width: 191, height: 25 })
    );

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "mask_clip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "mask_clip_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields missed by ancestor clip paths as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="rightRectClip"><rect x="320" y="0" width="80" height="40" /></clipPath>
          <clipPath id="rightEvenOddPathClip">
            <path clip-rule="evenodd" d="M0 0 L400 0 L400 40 L0 40 Z M0 0 L240 0 L240 40 L0 40 Z" />
          </clipPath>
        </svg>
        <label id="inset-label" for="ancestor-inset-password">Password</label>
        <div id="ancestor-inset-clip" style="width:400px;height:40px;clip-path:inset(0 0 0 320px)">
          <input id="ancestor-inset-password" name="ancestor_inset_password" type="password" autocomplete="current-password" />
        </div>
        <label id="polygon-label" for="ancestor-polygon-password">Password</label>
        <div id="ancestor-polygon-clip" style="width:400px;height:40px;clip-path:polygon(320px 0, 400px 0, 400px 40px, 320px 40px)">
          <input id="ancestor-polygon-password" name="ancestor_polygon_password" type="password" autocomplete="current-password" />
        </div>
        <label id="url-label" for="ancestor-url-password">Password</label>
        <div id="ancestor-url-clip" style="width:400px;height:40px;clip-path:url(#rightRectClip)">
          <input id="ancestor-url-password" name="ancestor_url_password" type="password" autocomplete="current-password" />
        </div>
        <label id="css-path-label" for="ancestor-css-path-password">Password</label>
        <div id="ancestor-css-path-clip" style='width:400px;height:40px;clip-path:path(evenodd, "M0 0 L400 0 L400 40 L0 40 Z M0 0 L240 0 L240 40 L0 40 Z")'>
          <input id="ancestor-css-path-password" name="ancestor_css_path_password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-path-label" for="ancestor-svg-path-password">Password</label>
        <div id="ancestor-svg-path-clip" style="width:400px;height:40px;clip-path:url(#rightEvenOddPathClip)">
          <input id="ancestor-svg-path-password" name="ancestor_svg_path_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const insetPassword = document.querySelector("#ancestor-inset-password") as HTMLInputElement;
    const polygonPassword = document.querySelector(
      "#ancestor-polygon-password"
    ) as HTMLInputElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    const urlPassword = document.querySelector("#ancestor-url-password") as HTMLInputElement;
    const cssPathPassword = document.querySelector(
      "#ancestor-css-path-password"
    ) as HTMLInputElement;
    const svgPathPassword = document.querySelector(
      "#ancestor-svg-path-password"
    ) as HTMLInputElement;
    const insetLabel = document.querySelector("#inset-label") as HTMLLabelElement;
    const polygonLabel = document.querySelector("#polygon-label") as HTMLLabelElement;
    const urlLabel = document.querySelector("#url-label") as HTMLLabelElement;
    const cssPathLabel = document.querySelector("#css-path-label") as HTMLLabelElement;
    const svgPathLabel = document.querySelector("#svg-path-label") as HTMLLabelElement;
    stubElementRect(insetPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(polygonPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    stubElementRect(urlPassword, elementRect({ left: 24, top: 152, width: 185, height: 21 }));
    stubElementRect(cssPathPassword, elementRect({ left: 24, top: 208, width: 185, height: 21 }));
    stubElementRect(svgPathPassword, elementRect({ left: 24, top: 264, width: 185, height: 21 }));
    stubElementRect(realPassword, elementRect({ left: 24, top: 320, width: 185, height: 21 }));
    stubElementRect(insetLabel, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(polygonLabel, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    stubElementRect(urlLabel, elementRect({ left: 24, top: 152, width: 185, height: 21 }));
    stubElementRect(cssPathLabel, elementRect({ left: 24, top: 208, width: 185, height: 21 }));
    stubElementRect(svgPathLabel, elementRect({ left: 24, top: 264, width: 185, height: 21 }));
    stubElementRect(
      document.querySelector("#ancestor-inset-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-polygon-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 88, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-url-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 144, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-css-path-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 200, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-svg-path-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 256, width: 400, height: 40 })
    );
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return insetLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return polygonLabel;
        }
        if (x >= 24 && x <= 209 && y >= 152 && y <= 173) {
          return urlLabel;
        }
        if (x >= 24 && x <= 209 && y >= 208 && y <= 229) {
          return cssPathLabel;
        }
        if (x >= 24 && x <= 209 && y >= 264 && y <= 285) {
          return svgPathLabel;
        }
        if (x >= 24 && x <= 209 && y >= 320 && y <= 341) {
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

    for (const name of [
      "ancestor_inset_password",
      "ancestor_polygon_password",
      "ancestor_url_password",
      "ancestor_css_path_password",
      "ancestor_svg_path_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:clipped");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields missed by rotated svg clip paths as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="rotatedLeftRectClip"><rect x="0" y="0" width="80" height="40" transform="rotate(180 200 20)" /></clipPath>
        </svg>
        <label id="rotated-clip-label" for="rotated-clip-password">Password</label>
        <div id="ancestor-rotated-clip" style="width:400px;height:40px;clip-path:url(#rotatedLeftRectClip)">
          <input id="rotated-clip-password" name="rotated_clip_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rotatedClipPassword = document.querySelector(
      "#rotated-clip-password"
    ) as HTMLInputElement;
    const rotatedClipLabel = document.querySelector(
      "#rotated-clip-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      rotatedClipPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      rotatedClipLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-rotated-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return rotatedClipLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "rotated_clip_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rotated_clip_password").reasons).toContain(
      "not-viewable:clipped"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields missed by ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <mask id="rightMask">
            <rect x="320" y="0" width="80" height="40" fill="white" />
          </mask>
          <mask id="rightEvenOddMask">
            <path fill="white" fill-rule="evenodd" d="M0 0 L400 0 L400 40 L0 40 Z M0 0 L240 0 L240 40 L0 40 Z" />
          </mask>
        </svg>
        <label id="css-mask-label" for="ancestor-css-mask-password">Password</label>
        <div id="ancestor-css-mask" style="width:400px;height:40px;mask-image:linear-gradient(black,black);mask-size:80px 100%;mask-repeat:no-repeat;mask-position:320px 0">
          <input id="ancestor-css-mask-password" name="ancestor_css_mask_password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-mask-label" for="ancestor-svg-mask-password">Password</label>
        <div id="ancestor-svg-mask" style="width:400px;height:40px;mask:url(#rightMask)">
          <input id="ancestor-svg-mask-password" name="ancestor_svg_mask_password" type="password" autocomplete="current-password" />
        </div>
        <label id="css-gradient-mask-label" for="ancestor-css-gradient-mask-password">Password</label>
        <div id="ancestor-css-gradient-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent 0 240px, black 240px 100%)">
          <input id="ancestor-css-gradient-mask-password" name="ancestor_css_gradient_mask_password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-evenodd-mask-label" for="ancestor-svg-evenodd-mask-password">Password</label>
        <div id="ancestor-svg-evenodd-mask" style="width:400px;height:40px;mask:url(#rightEvenOddMask)">
          <input id="ancestor-svg-evenodd-mask-password" name="ancestor_svg_evenodd_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const cssMaskPassword = document.querySelector(
      "#ancestor-css-mask-password"
    ) as HTMLInputElement;
    const svgMaskPassword = document.querySelector(
      "#ancestor-svg-mask-password"
    ) as HTMLInputElement;
    const cssGradientMaskPassword = document.querySelector(
      "#ancestor-css-gradient-mask-password"
    ) as HTMLInputElement;
    const svgEvenOddMaskPassword = document.querySelector(
      "#ancestor-svg-evenodd-mask-password"
    ) as HTMLInputElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    const cssMaskLabel = document.querySelector("#css-mask-label") as HTMLLabelElement;
    const svgMaskLabel = document.querySelector("#svg-mask-label") as HTMLLabelElement;
    const cssGradientMaskLabel = document.querySelector(
      "#css-gradient-mask-label"
    ) as HTMLLabelElement;
    const svgEvenOddMaskLabel = document.querySelector(
      "#svg-evenodd-mask-label"
    ) as HTMLLabelElement;
    stubElementRect(cssMaskPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(svgMaskPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    stubElementRect(
      cssGradientMaskPassword,
      elementRect({ left: 24, top: 152, width: 185, height: 21 })
    );
    stubElementRect(
      svgEvenOddMaskPassword,
      elementRect({ left: 24, top: 208, width: 185, height: 21 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 264, width: 185, height: 21 }));
    stubElementRect(cssMaskLabel, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(svgMaskLabel, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    stubElementRect(
      cssGradientMaskLabel,
      elementRect({ left: 24, top: 152, width: 185, height: 21 })
    );
    stubElementRect(
      svgEvenOddMaskLabel,
      elementRect({ left: 24, top: 208, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-css-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-svg-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 88, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-css-gradient-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 144, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#ancestor-svg-evenodd-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 200, width: 400, height: 40 })
    );
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return cssMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return svgMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 152 && y <= 173) {
          return cssGradientMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 208 && y <= 229) {
          return svgEvenOddMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 264 && y <= 285) {
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

    for (const name of [
      "ancestor_css_mask_password",
      "ancestor_svg_mask_password",
      "ancestor_css_gradient_mask_password",
      "ancestor_svg_evenodd_mask_password"
    ]) {
      expect(fieldByName(report, name).qualifiedAs).toBe("ignored");
      expect(fieldByName(report, name).reasons).toContain("not-viewable:transparent");
    }
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields missed by rotated svg mask uses as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <rect id="leftMaskRect" x="0" y="0" width="80" height="40" />
          <mask id="rotatedUseMask">
            <use href="#leftMaskRect" transform="rotate(180 200 20)" fill="white" />
          </mask>
        </svg>
        <label id="rotated-mask-label" for="rotated-mask-password">Password</label>
        <div id="ancestor-rotated-mask" style="width:400px;height:40px;mask:url(#rotatedUseMask)">
          <input id="rotated-mask-password" name="rotated_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rotatedMaskPassword = document.querySelector(
      "#rotated-mask-password"
    ) as HTMLInputElement;
    const rotatedMaskLabel = document.querySelector(
      "#rotated-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      rotatedMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      rotatedMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-rotated-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return rotatedMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "rotated_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "rotated_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by radial ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="radial-mask-label" for="radial-mask-password">Password</label>
        <div id="ancestor-radial-mask" style="width:400px;height:40px;mask-image:radial-gradient(circle at 360px 20px, black 0 40px, transparent 40px 100%)">
          <input id="radial-mask-password" name="radial_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const radialMaskPassword = document.querySelector(
      "#radial-mask-password"
    ) as HTMLInputElement;
    const radialMaskLabel = document.querySelector("#radial-mask-label") as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      radialMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      radialMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-radial-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return radialMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "radial_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "radial_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by radial ancestor mask holes as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="radial-hole-mask-label" for="radial-hole-mask-password">Password</label>
        <div id="ancestor-radial-hole-mask" style="width:400px;height:40px;mask-image:radial-gradient(circle at 116px 20px, transparent 0 100px, black 100px 120px, transparent 120px 100%)">
          <input id="radial-hole-mask-password" name="radial_hole_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const radialHoleMaskPassword = document.querySelector(
      "#radial-hole-mask-password"
    ) as HTMLInputElement;
    const radialHoleMaskLabel = document.querySelector(
      "#radial-hole-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      radialHoleMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      radialHoleMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-radial-hole-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return radialHoleMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "radial_hole_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "radial_hole_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by conic ancestor mask wedges as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="conic-mask-label" for="conic-mask-password">Password</label>
        <div id="ancestor-conic-mask" style="width:400px;height:40px;mask-image:conic-gradient(from -10deg at -200px 20px, transparent 0deg 20deg, black 20deg 360deg)">
          <input id="conic-mask-password" name="conic_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const conicMaskPassword = document.querySelector(
      "#conic-mask-password"
    ) as HTMLInputElement;
    const conicMaskLabel = document.querySelector("#conic-mask-label") as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      conicMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      conicMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-conic-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return conicMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "conic_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "conic_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields with only tiny conic ancestor mask wedges as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="conic-tiny-mask-label" for="conic-tiny-mask-password">Password</label>
        <div id="ancestor-conic-tiny-mask" style="width:400px;height:40px;mask-image:conic-gradient(from -10deg at -200px 20px, transparent 0deg 9.5deg, black 9.5deg 10.5deg, transparent 10.5deg 360deg)">
          <input id="conic-tiny-mask-password" name="conic_tiny_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const conicTinyMaskPassword = document.querySelector(
      "#conic-tiny-mask-password"
    ) as HTMLInputElement;
    const conicTinyMaskLabel = document.querySelector(
      "#conic-tiny-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      conicTinyMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      conicTinyMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-conic-tiny-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return conicTinyMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "conic_tiny_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "conic_tiny_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by repeating-radial ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="repeating-radial-mask-label" for="repeating-radial-mask-password">Password</label>
        <div id="ancestor-repeating-radial-mask" style="width:400px;height:40px;mask-image:repeating-radial-gradient(circle at 360px 20px, black 0 40px, transparent 40px 400px)">
          <input id="repeating-radial-mask-password" name="repeating_radial_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const repeatingRadialMaskPassword = document.querySelector(
      "#repeating-radial-mask-password"
    ) as HTMLInputElement;
    const repeatingRadialMaskLabel = document.querySelector(
      "#repeating-radial-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      repeatingRadialMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      repeatingRadialMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-repeating-radial-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return repeatingRadialMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "repeating_radial_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "repeating_radial_mask_password").reasons).toContain(
      "not-viewable:transparent"
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

  it("treats fields hidden by repeating-gradient ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="repeating-mask-label" for="repeating-mask-password">Password</label>
        <div id="ancestor-repeating-mask" style="width:400px;height:40px;mask-image:repeating-linear-gradient(to right, transparent 0 240px, black 240px 400px)">
          <input id="repeating-mask-password" name="repeating_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const repeatingMaskPassword = document.querySelector(
      "#repeating-mask-password"
    ) as HTMLInputElement;
    const repeatingMaskLabel = document.querySelector(
      "#repeating-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      repeatingMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      repeatingMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-repeating-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return repeatingMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "repeating_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "repeating_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields with only sparse repeating-linear ancestor mask stripes as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="sparse-repeating-mask-label" for="sparse-repeating-mask-password">Password</label>
        <div id="ancestor-sparse-repeating-mask" style="width:400px;height:40px;mask-image:repeating-linear-gradient(to right, black 0 1px, transparent 1px 40px)">
          <input id="sparse-repeating-mask-password" name="sparse_repeating_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const sparseRepeatingMaskPassword = document.querySelector(
      "#sparse-repeating-mask-password"
    ) as HTMLInputElement;
    const sparseRepeatingMaskLabel = document.querySelector(
      "#sparse-repeating-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      sparseRepeatingMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      sparseRepeatingMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-sparse-repeating-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return sparseRepeatingMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "sparse_repeating_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "sparse_repeating_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields with only sparse repeated linear mask tiles as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="sparse-tiled-mask-label" for="sparse-tiled-mask-password">Password</label>
        <div id="ancestor-sparse-tiled-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, black 0 1px, transparent 1px 40px);mask-size:40px 100%;mask-repeat:repeat">
          <input id="sparse-tiled-mask-password" name="sparse_tiled_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const sparseTiledMaskPassword = document.querySelector(
      "#sparse-tiled-mask-password"
    ) as HTMLInputElement;
    const sparseTiledMaskLabel = document.querySelector(
      "#sparse-tiled-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      sparseTiledMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      sparseTiledMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-sparse-tiled-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return sparseTiledMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "sparse_tiled_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "sparse_tiled_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by hard-stop ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="hard-stop-mask-label" for="hard-stop-mask-password">Password</label>
        <div id="ancestor-hard-stop-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent 60%, black 0)">
          <input id="hard-stop-mask-password" name="hard_stop_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const hardStopMaskPassword = document.querySelector(
      "#hard-stop-mask-password"
    ) as HTMLInputElement;
    const hardStopMaskLabel = document.querySelector(
      "#hard-stop-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      hardStopMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      hardStopMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-hard-stop-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return hardStopMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "hard_stop_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "hard_stop_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by implicit-stop ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="implicit-stop-mask-label" for="implicit-stop-mask-password">Password</label>
        <div id="ancestor-implicit-stop-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent, transparent 60%, black 60%, black)">
          <input id="implicit-stop-mask-password" name="implicit_stop_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const implicitStopMaskPassword = document.querySelector(
      "#implicit-stop-mask-password"
    ) as HTMLInputElement;
    const implicitStopMaskLabel = document.querySelector(
      "#implicit-stop-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      implicitStopMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      implicitStopMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-implicit-stop-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return implicitStopMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "implicit_stop_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "implicit_stop_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
  });

  it("treats fields hidden by color-interpolated ancestor masks as not viewable", () => {
    document.body.innerHTML = `
      <form>
        <label id="color-space-mask-label" for="color-space-mask-password">Password</label>
        <div id="ancestor-color-space-mask" style="width:400px;height:40px;mask-image:linear-gradient(in oklab, transparent 0 24px, black 24px 100%)">
          <input id="color-space-mask-password" name="color_space_mask_password" type="password" autocomplete="current-password" />
        </div>
        <input name="real_password" type="password" autocomplete="current-password" />
      </form>
    `;
    const colorSpaceMaskPassword = document.querySelector(
      "#color-space-mask-password"
    ) as HTMLInputElement;
    const colorSpaceMaskLabel = document.querySelector(
      "#color-space-mask-label"
    ) as HTMLLabelElement;
    const realPassword = document.querySelector(
      'input[name="real_password"]'
    ) as HTMLInputElement;
    stubElementRect(
      colorSpaceMaskPassword,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      colorSpaceMaskLabel,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-color-space-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(realPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return colorSpaceMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
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

    expect(fieldByName(report, "color_space_mask_password").qualifiedAs).toBe("ignored");
    expect(fieldByName(report, "color_space_mask_password").reasons).toContain(
      "not-viewable:transparent"
    );
    expect(fieldByName(report, "real_password").qualifiedAs).toBe("password");
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
