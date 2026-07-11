import { beforeEach, describe, expect, it, vi } from "vitest";

import { collectAutofillPageSnapshot } from "../collectPageFields";
import { triageAutofillPage } from "../triage";
import {
  installDomRenderEnvironment,
  useDomRenderEnvironment
} from "./renderEnvironment";

useDomRenderEnvironment();

function fieldByName(report: ReturnType<typeof triageAutofillPage>, htmlName: string) {
  const field = report.f.find((candidate) => candidate.hn === htmlName);
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

  it("emits proven current new and confirmation password roles", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="password_confirmation" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "current_password").q).toBe("currentPassword");
    expect(fieldByName(report, "new_password").q).toBe("newPassword");
    expect(fieldByName(report, "password_confirmation").q).toBe("confirmation");
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

    expect(username.el).toBe(true);
    expect(username.q).toBe("username");
    expect(username.why).toContain("autocomplete:username");
    expect(username.why).toContain("form-has-password");
    expect(username.lt).toBe("Email address");
    expect(username.ph).toBe("you@example.com");
    expect(username.ad).toBe("email-help");
    expect(username.dv).toContain("user");
    expect(username.fc).toMatchObject({
      hi: "login-form",
      hn: "login",
      hm: "post",
      ht: ["Sign in"]
    });

    expect(password.el).toBe(true);
    expect(password.q).toBe("currentPassword");
    expect(password.why).toContain("autocomplete:current-password");
    expect(password.vp).toBeUndefined();
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
    expect(snapshot.fm[0].st).toEqual(["Continue"]);
    expect(snapshot.fm[0].ht).toEqual(["Continue"]);
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
      el: false,
      fl: false,
      q: "ignored"
    });
    expect(fieldByName(report, "readonly_user").why).toContain("not-fillable:readonly");
    expect(fieldByName(report, "disabled_user").why).toContain("not-fillable:disabled");
    expect(fieldByName(report, "fieldset_disabled_user").why).toContain(
      "not-fillable:disabled"
    );
    expect(fieldByName(report, "hidden_user").why).toContain("not-viewable:hidden");
    expect(fieldByName(report, "css_hidden_user").why).toContain("not-viewable:css");
    expect(fieldByName(report, "ancestor_hidden_user").why).toContain(
      "not-viewable:hidden"
    );
    expect(fieldByName(report, "ancestor_css_hidden_user").why).toContain(
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

    expect(fieldByName(report, "query").q).toBe("ignored");
    expect(fieldByName(report, "query").why).toContain("excluded:search");
    expect(fieldByName(report, "newsletter_email").q).toBe("ignored");
    expect(fieldByName(report, "newsletter_email").why).toContain("non-login:newsletter");
    expect(fieldByName(report, "captcha_code").q).toBe("ignored");
    expect(fieldByName(report, "captcha_code").why).toContain("excluded:captcha");
    expect(fieldByName(report, "forgot_email").q).toBe("ignored");
    expect(fieldByName(report, "forgot_email").why).toContain("excluded:forgot");
    expect(fieldByName(report, "real_user").q).toBe("username");
    expect(fieldByName(report, "real_password").q).toBe("currentPassword");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("newPassword");
  });

  it("excludes forgot-password fields when the signal is in the form context", () => {
    document.body.innerHTML = `
      <form id="forgot" action="/forgot-password">
        <input name="email" type="email" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").q).toBe("ignored");
    expect(fieldByName(report, "email").why).toContain("excluded:forgot");
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

    expect(fieldByName(report, "email").q).toBe("ignored");
    expect(fieldByName(report, "email").why).toContain("excluded:search");
    expect(fieldByName(report, "reset_email").q).toBe("ignored");
    expect(fieldByName(report, "reset_email").why).toContain("excluded:reset");
    expect(fieldByName(report, "reset_password").q).toBe("ignored");
    expect(fieldByName(report, "reset_password").why).toContain("excluded:reset");
    expect(fieldByName(report, "recovery_email").q).toBe("ignored");
    expect(fieldByName(report, "recovery_email").why).toContain("excluded:recovery");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("currentPassword");
    expect(fieldByName(report, "captcha_code").q).toBe("ignored");
    expect(fieldByName(report, "captcha_code").why).toContain("excluded:captcha");
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

    expect(snapshot.fm.find((form) => form.hi === "forgot")).toMatchObject({
      ht: ["Forgot password"]
    });
    expect(snapshot.fm.find((form) => form.hi === "login")).toMatchObject({
      ht: ["Sign in"]
    });
    expect(fieldByName(report, "email").q).toBe("ignored");
    expect(fieldByName(report, "email").why).toContain("excluded:forgot");
    expect(fieldByName(report, "login_email").q).toBe("username");
    expect(fieldByName(report, "login_password").q).toBe("currentPassword");
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(fieldByName(report, "create_password").q).not.toBe("password");
    expect(fieldByName(report, "login").q).toBe("ignored");
    expect(fieldByName(report, "real_user").q).toBe("username");
    expect(fieldByName(report, "real_password").q).toBe("currentPassword");
  });

  it("keeps usernames beside new-password fields available for registration", () => {
    document.body.innerHTML = `
      <form>
        <input name="account" autocomplete="username" />
        <input name="password" type="password" autocomplete="new-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "account").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("newPassword");
  });

  it("does not let username autocomplete override account creation context", () => {
    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="signup_email" type="email" autocomplete="username" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "signup_email").q).toBe("ignored");
    expect(fieldByName(report, "signup_email").why).toContain(
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

    expect(fieldByName(report, "user").q).toBe("username");
    expect(fieldByName(report, "identifier").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(fieldByName(report, "user").q).toBe("ignored");
    expect(fieldByName(report, "last_login").q).toBe("ignored");
    expect(fieldByName(report, "last_login_email").q).toBe("ignored");
    expect(fieldByName(report, "login").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "external-submit-context")).toMatchObject({
      ht: ["Sign in"]
    });
    expect(fieldByName(report, "implicit_email").q).toBe("username");
    expect(fieldByName(report, "button_email").q).toBe("username");
    expect(fieldByName(report, "external_submit_email").q).toBe("username");
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

    expect(snapshot.fm.find((form) => form.hi === "empty-action")).toMatchObject({
      hai: true
    });
    expect(fieldByName(report, "empty_action_email").q).toBe("username");
    expect(fieldByName(report, "empty_action_password").q).toBe("currentPassword");
  });

  it("uses login hostnames in form actions as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="auth-host" action="https://login.example.com/">
        <input name="host_email" type="email" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "host_email").q).toBe("username");
  });

  it("uses slash-separated sign-in routes as passwordless login context", () => {
    document.body.innerHTML = `
      <form id="slash-route" action="/sign/in">
        <input name="route_email" type="email" />
        <button type="submit">Continue</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "route_email").q).toBe("username");
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

    expect(snapshot.fm.find((form) => form.hi === "icon-submit")?.ht).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "icon_email").q).toBe("username");
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "start")?.ht).toEqual([
      "Create account",
      "Sign in"
    ]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([
      "Continue"
    ]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(snapshot.fm.find((form) => form.hi === "signup")?.ht).toEqual([
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

    expect(snapshot.fm.find((form) => form.hi === "login")?.ht).toEqual([
      "Continue"
    ]);
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
  });

  it("lets subscription login context override newsletter exclusions", () => {
    document.body.innerHTML = `
      <form id="subscription-login">
        <input name="subscriber_email" type="email" />
        <input name="subscriber_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_email").q).toBe("username");
    expect(fieldByName(report, "subscriber_password").q).toBe("password");
  });

  it("lets passwordless subscription login context override newsletter exclusions", () => {
    document.body.innerHTML = `
      <form id="subscription-login">
        <input name="subscriber_email" type="email" />
        <button type="submit">Sign in</button>
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_email").q).toBe("username");
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

    expect(snapshot.fm.find((form) => form.hi === "image-login")?.ht).toEqual([
      "Sign in"
    ]);
    expect(fieldByName(report, "image_email").q).toBe("username");
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

    expect(fieldByName(report, "email").q).toBe("ignored");
    expect(fieldByName(report, "text_email").q).toBe("ignored");
    expect(fieldByName(report, "login_email").q).toBe("username");
    expect(fieldByName(report, "login_text_email").q).toBe("username");
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

    expect(fieldByName(report, "contact_email").q).toBe("ignored");
    expect(fieldByName(report, "login_email").q).toBe("username");
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

    expect(fieldByName(report, "implicit_email").q).toBe("username");
    expect(fieldByName(report, "implicit_password").q).toBe("currentPassword");
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("currentPassword");
    expect(fieldByName(report, "redirect_email").q).toBe("username");
    expect(fieldByName(report, "redirect_password").q).toBe("currentPassword");
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

    expect(fieldByName(report, "contact_email").q).toBe("ignored");
    expect(fieldByName(report, "login_email").q).toBe("username");
    expect(fieldByName(report, "login_password").q).toBe("password");
  });

  it("shares local context for adjacent form-less body-level login fields", () => {
    document.body.innerHTML = `
      <input name="contact_email" type="email" />
      <hr />
      <input name="body_email" type="email" />
      <input name="body_password" type="password" />
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "contact_email").q).toBe("ignored");
    expect(fieldByName(report, "body_email").q).toBe("username");
    expect(fieldByName(report, "body_password").q).toBe("password");
    expect(fieldByName(report, "body_email").co).toBe(
      fieldByName(report, "body_password").co
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

    expect(fieldByName(report, "body_email").q).toBe("username");
    expect(fieldByName(report, "body_password").q).toBe("password");
    expect(fieldByName(report, "body_email").co).toBe(
      fieldByName(report, "body_password").co
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

    expect(fieldByName(report, "hidden_sibling_email").q).toBe("ignored");
    expect(fieldByName(report, "hidden_sibling_password").q).toBe("ignored");
    expect(fieldByName(report, "disabled_sibling_email").q).toBe("ignored");
    expect(fieldByName(report, "disabled_sibling_password").q).toBe("ignored");
    expect(fieldByName(report, "new_password_sibling_email").q).toBe("ignored");
    expect(fieldByName(report, "new_password_sibling").q).toBe("newPassword");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "new_password").q).toBe("ignored");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("newPassword");
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

    expect(fieldByName(report, "create_your_email").q).toBe("username");
    expect(fieldByName(report, "create_your_password").q).toBe("newPassword");
    expect(fieldByName(report, "create_an_email").q).toBe("username");
    expect(fieldByName(report, "create_an_password").q).toBe("newPassword");
    expect(fieldByName(report, "registered_email").q).toBe("username");
    expect(fieldByName(report, "registered_password").q).toBe("currentPassword");
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

    expect(fieldByName(report, "register_path_email").q).toBe("username");
    expect(fieldByName(report, "register_path_password").q).toBe("newPassword");
    expect(fieldByName(report, "registered_path_email").q).toBe("username");
    expect(fieldByName(report, "registered_path_password").q).toBe("currentPassword");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "new_password").q).toBe("newPassword");
    expect(fieldByName(report, "confirm_password").q).toBe("confirmation");
  });

  it("does not infer a generic password role from a confirmation sibling", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" />
        <input name="confirm_password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("password");
    expect(fieldByName(report, "confirm_password").q).toBe("confirmation");
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

    expect(fieldByName(report, "password").q).toBe("ignored");
    expect(fieldByName(report, "password").why).toContain("excluded:reset");
    expect(fieldByName(report, "new_password").q).toBe("newPassword");
    expect(fieldByName(report, "new_password").why).toContain("excluded:reset");
  });

  it("does not match tel inside unrelated words", () => {
    document.body.innerHTML = `
      <form>
        <input name="hotel" type="text" />
        <input name="password" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "hotel").q).toBe("ignored");
    expect(fieldByName(report, "password").q).toBe("password");
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

    expect(fieldByName(report, "contact_phone").q).toBe("ignored");
    expect(fieldByName(report, "phone").q).toBe("username");
    expect(fieldByName(report, "phone").why).toContain("form-has-password");
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

    expect(fieldByName(report, "login_otp").q).toBe("totp");
    expect(fieldByName(report, "login_otp").why).toContain("autocomplete:one-time-code");
    expect(fieldByName(report, "phone_otp").q).toBe("totp");
  });

  it("does not classify phone-delivered one-time codes as authenticator TOTP", () => {
    document.body.innerHTML = `
      <form id="sms-code">
        <label for="phone-code">Code sent to your phone</label>
        <input id="phone-code" name="code" autocomplete="one-time-code" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "code").q).toBe("ignored");
    expect(fieldByName(report, "code").why).toContain("excluded:out-of-band-code");
  });

  it("requires field-level code evidence before using MFA form context", () => {
    document.body.innerHTML = `
      <form id="mfa-setup">
        <h2>Two factor authentication setup</h2>
        <input name="phone" type="tel" inputmode="numeric" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "phone").q).toBe("ignored");
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

    expect(fieldByName(report, "otp").q).toBe("totp");
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("currentPassword");
  });

  it("does not use password-masked code fields as login password evidence", () => {
    document.body.innerHTML = `
      <form id="verification">
        <input name="email" type="email" />
        <input name="otp" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "email").q).toBe("ignored");
    expect(fieldByName(report, "otp").q).toBe("totp");
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

    expect(fieldByName(report, "checkout_email").q).toBe("ignored");
    expect(fieldByName(report, "card_cvv").q).toBe("ignored");
    expect(fieldByName(report, "card_code").q).toBe("ignored");
  });

  it("does not classify generic masked security-code fields as TOTP targets", () => {
    document.body.innerHTML = `
      <form id="verification">
        <input name="security_code" type="password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "security_code").q).toBe("ignored");
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

    expect(fieldByName(report, "password").q).toBe("password");
    expect(fieldByName(report, "sms_code").q).toBe("ignored");
    expect(fieldByName(report, "sms_code").why).toContain("excluded:out-of-band-code");
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

    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("currentPassword");
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

    expect(fieldByName(report, "plain_text_secret").q).toBe("ignored");
    expect(fieldByName(report, "notes").q).toBe("ignored");
    expect(fieldByName(report, "secret_select").q).toBe("ignored");
  });

  it("respects non-login exclusions before accepting current-password fields", () => {
    document.body.innerHTML = `
      <form class="newsletter">
        <h2>Subscribe to our newsletter</h2>
        <input name="subscriber_password" type="password" autocomplete="current-password" />
      </form>
    `;

    const report = triageAutofillPage(collectAutofillPageSnapshot(document));

    expect(fieldByName(report, "subscriber_password").q).toBe("ignored");
    expect(fieldByName(report, "subscriber_password").why).toContain("non-login:newsletter");
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

    expect(username.lt).toBe("Email address");
    expect(username.q).toBe("username");
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
    const unregisterFrameEnvironment = installDomRenderEnvironment(frameDocument!);
    try {
      const report = triageAutofillPage(collectAutofillPageSnapshot(frameDocument!));

      expect(fieldByName(report, "email").q).toBe("username");
      expect(fieldByName(report, "password").q).toBe("password");
    } finally {
      unregisterFrameEnvironment();
      vi.stubGlobal("HTMLInputElement", originalInputElement);
    }
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

    expect(snapshot.fm.find((form) => form.hi === "login-form")).toMatchObject({
      ht: ["Sign in"]
    });
    expect(snapshot.fm.find((form) => form.hi === "newsletter-form")).toMatchObject({
      ht: ["Subscribe to our newsletter"]
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

    expect(snapshot.fm.find((form) => form.hi === "login-form")).toMatchObject({
      ht: ["Sign in"]
    });
    expect(fieldByName(report, "email").q).toBe("username");
    expect(fieldByName(report, "password").q).toBe("currentPassword");
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
    const country = snapshot.f.find((field) => field.hn === "country");
    const notes = snapshot.f.find((field) => field.hn === "notes");

    expect(country).toMatchObject({
      tg: "select",
      lt: "Country",
      hn: "country"
    });
    expect(country?.opts).toEqual(["", "us"]);
    expect(notes).toMatchObject({
      tg: "textarea",
      lt: "Notes"
    });
    expect(country).not.toHaveProperty("value");
    expect(notes).not.toHaveProperty("value");
    expect(snapshot.fm[0]).toMatchObject({
      hi: "profile-form",
      hc: "account-form",
      ha: new URL("/profile", document.location.href).href,
      ht: ["Account recovery"]
    });
  });
});
