import { beforeEach, describe, expect, it } from "vitest";

import { applyFillPlan } from "../applyFillPlan";
import { collectAutofillPageSnapshot } from "../collectPageFields";
import { createLoginFillPlan } from "../fillPlan";
import { collectAutofillSubmission } from "../savePrompt";
import { matchAutofillSiteRule } from "../siteRules";
import { triageAutofillPage } from "../triage";
import type { AutofillSiteRule } from "../siteRules";

describe("autofill site rules", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    window.history.replaceState(null, "", "/login");
  });

  it("uses host rule selectors ahead of heuristic field selection", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-user" name="email" type="email" />
        <input id="rule-user" name="account" type="text" />
        <input id="decoy-password" name="password" type="password" />
        <input id="rule-password" name="secret_text" type="text" />
      </form>
    `;
    const rules: AutofillSiteRule[] = [
      {
        id: "example-login",
        host: window.location.hostname,
        fields: {
          username: ["#rule-user"],
          password: ["#rule-password"]
        }
      }
    ];

    const snapshot = collectAutofillPageSnapshot(document, { siteRules: rules });
    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rule-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#rule-password") as HTMLInputElement).value).toBe("secret");
  });

  it("prefers the most specific path rule for the current URL", () => {
    const rules: AutofillSiteRule[] = [
      {
        id: "host",
        host: "example.com",
        fields: { username: ["#host-user"] }
      },
      {
        id: "path",
        host: "example.com",
        pathPrefix: "/account",
        fields: { username: ["#path-user"] }
      }
    ];

    expect(matchAutofillSiteRule("https://example.com/account/login", rules)?.id).toBe("path");
  });

  it("matches path prefixes only on route boundaries", () => {
    const rules: AutofillSiteRule[] = [
      {
        id: "host",
        host: "example.com",
        fields: { username: ["#host-user"] }
      },
      {
        id: "account",
        host: "example.com",
        pathPrefix: "/account",
        fields: { username: ["#account-user"] }
      },
      {
        id: "login",
        host: "example.com",
        pathPrefix: "/login",
        fields: { username: ["#login-user"] }
      }
    ];

    expect(matchAutofillSiteRule("https://example.com/account", rules)?.id).toBe("account");
    expect(matchAutofillSiteRule("https://example.com/account/profile", rules)?.id).toBe(
      "account"
    );
    expect(matchAutofillSiteRule("https://example.com/accounting", rules)?.id).toBe("host");
    expect(matchAutofillSiteRule("https://example.com/login-help", rules)?.id).toBe("host");
  });

  it("returns an empty fill plan for disabled site rules", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [{ id: "disabled", host: window.location.hostname, disabled: true }]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });

    expect(plan.actions).toEqual([]);
  });

  it("falls back to heuristic selection when a rule selector does not match", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "missing-selector",
          host: window.location.hostname,
          fields: {
            username: [".missing-user"],
            password: [".missing-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice"
    );
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("does not fill ambiguous password site-rule matches", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input class="rule-password" id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input class="rule-password" id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-password-rule",
          host: window.location.hostname,
          fields: {
            password: [".rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.actions).toEqual([]);
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
  });

  it("does not fall back to the first login when a password rule matches multiple login scopes", () => {
    document.body.innerHTML = `
      <form id="decoy-form" aria-label="Sign in">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input class="rule-password" id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input class="rule-password" id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-password-rule",
          host: window.location.hostname,
          fields: {
            password: [".rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.actions).toEqual([]);
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
  });

  it("does not let a stale username rule override focus when the password rule is ambiguous", () => {
    document.body.innerHTML = `
      <form id="decoy-form" aria-label="Sign in">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input class="rule-password" id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input class="rule-password" id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    (document.querySelector("#target-password") as HTMLInputElement).focus();
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "stale-username-ambiguous-password-rule",
          host: window.location.hostname,
          fields: {
            username: ["#decoy-user"],
            password: [".rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not let a stale partial username rule override the focused login scope", () => {
    document.body.innerHTML = `
      <form id="decoy-form" aria-label="Sign in">
        <input id="rule-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    (document.querySelector("#target-password") as HTMLInputElement).focus();
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "stale-username-rule",
          host: window.location.hostname,
          fields: {
            username: ["#rule-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#rule-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not anchor password fills to ambiguous username site-rule matches", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input class="rule-user" id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input class="rule-user" id="target-user" name="email" type="email" autocomplete="username" />
        <input id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-username-rule",
          host: window.location.hostname,
          fields: {
            username: [".rule-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.actions).toEqual([]);
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
  });

  it("uses heuristic selection for payload fields not covered by matching rules", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="rule-user" name="account" type="text" />
        <input id="password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "partial-rule",
          host: window.location.hostname,
          fields: {
            username: ["#rule-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rule-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#password") as HTMLInputElement).value).toBe("secret");
  });

  it("keeps fallback confirmation fills when a rule selects one new password field", () => {
    document.body.innerHTML = `
      <form>
        <input id="current-password" name="current_password" type="password" autocomplete="current-password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "partial-change-rule",
          host: window.location.hostname,
          fields: {
            newPassword: ["#new-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      password: "old-secret",
      newPassword: "new-secret"
    });
    applyFillPlan(plan, document);

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

  it("does not fill new-password site-rule matches across multiple scopes", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-new-password" class="rule-new-password" name="new_password" type="password" autocomplete="new-password" />
      </form>
      <form id="target-form">
        <h2>Create account</h2>
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input id="target-new-password" class="rule-new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="target-confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-new-password-rule",
          host: window.location.hostname,
          fields: {
            newPassword: [".rule-new-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      newPassword: "new-secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-new-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector("#target-confirm-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("does not fall back to the first registration when a new-password rule matches multiple registration scopes", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <h2>Create account</h2>
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-new-password" class="rule-new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="decoy-confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
      <form id="target-form">
        <h2>Create account</h2>
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input id="target-new-password" class="rule-new-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="target-confirm-password" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-new-password-rule",
          host: window.location.hostname,
          fields: {
            newPassword: [".rule-new-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      newPassword: "new-secret"
    });
    expect(plan.actions).toEqual([]);
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-confirm-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-confirm-password") as HTMLInputElement).value).toBe("");
  });

  it("uses a current-password site rule role to fill heuristic new password fields", () => {
    document.body.innerHTML = `
      <form>
        <input id="opaque-token" name="credential" type="password" />
        <input id="new-password" name="next_secret" type="password" autocomplete="new-password" />
        <input id="confirm-password" name="repeat_secret" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "current-password-rule",
          host: window.location.hostname,
          fields: {
            currentPassword: ["#opaque-token"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      password: "old-secret",
      newPassword: "new-secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#opaque-token") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector("#confirm-password") as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("qualifies rule-selected fields for submission capture", () => {
    document.body.innerHTML = `
      <form>
        <input id="rule-password" name="secret_text" type="text" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "text-password-rule",
          host: window.location.hostname,
          fields: {
            password: ["#rule-password"]
          }
        }
      ]
    });

    const report = triageAutofillPage(snapshot);
    const passwordField = report.fields.find((field) => field.htmlId === "rule-password");

    expect(passwordField?.eligible).toBe(true);
    expect(passwordField?.qualifiedAs).toBe("password");
  });

  it("captures rule-selected password fields during submission", () => {
    document.body.innerHTML = `
      <form>
        <input id="rule-user" name="account" type="text" value="alice" />
        <input id="rule-password" name="secret_text" type="text" value="captured-secret" />
      </form>
    `;
    const submission = collectAutofillSubmission(
      document,
      document.querySelector("form") as HTMLFormElement,
      {
        siteRules: [
          {
            id: "text-password-rule",
            host: window.location.hostname,
            fields: {
              username: ["#rule-user"],
              password: ["#rule-password"]
            }
          }
        ]
      }
    );

    expect(submission).toMatchObject({
      username: "alice",
      password: "captured-secret"
    });
  });

  it("prefers rule-selected fields when capturing submitted credentials", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-user" name="email" type="email" autocomplete="username" value="decoy@example.com" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" value="wrong-secret" />
        <input id="rule-user" name="account" type="text" value="alice" />
        <input id="rule-password" name="secret_text" type="text" value="captured-secret" />
      </form>
    `;
    const submission = collectAutofillSubmission(
      document,
      document.querySelector("form") as HTMLFormElement,
      {
        siteRules: [
          {
            id: "text-password-rule",
            host: window.location.hostname,
            fields: {
              username: ["#rule-user"],
              password: ["#rule-password"]
            }
          }
        ]
      }
    );

    expect(submission).toMatchObject({
      username: "alice",
      password: "captured-secret"
    });
  });

  it("uses current-password site rules when capturing password changes", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-current" name="password" type="password" value="wrong-secret" />
        <input id="rule-current" name="opaque_token" type="text" value="old-secret" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;
    const submission = collectAutofillSubmission(
      document,
      document.querySelector("form") as HTMLFormElement,
      {
        siteRules: [
          {
            id: "change-password-rule",
            host: window.location.hostname,
            fields: {
              currentPassword: ["#rule-current"]
            }
          }
        ]
      }
    );

    expect(submission).toMatchObject({
      password: "old-secret",
      newPassword: "new-secret"
    });
  });

  it("captures readonly opaque usernames selected by site rules", () => {
    document.body.innerHTML = `
      <form>
        <input id="opaque-account" name="display_token" type="text" readonly value="alice" />
        <input id="rule-password" name="secret_text" type="text" value="captured-secret" />
      </form>
    `;
    const submission = collectAutofillSubmission(
      document,
      document.querySelector("form") as HTMLFormElement,
      {
        siteRules: [
          {
            id: "readonly-username-rule",
            host: window.location.hostname,
            fields: {
              username: ["#opaque-account"],
              password: ["#rule-password"]
            }
          }
        ]
      }
    );

    expect(submission).toMatchObject({
      username: "alice",
      password: "captured-secret"
    });
  });

  it("does not capture submissions when the matching site rule is disabled", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="captured-secret" />
      </form>
    `;
    const submission = collectAutofillSubmission(
      document,
      document.querySelector("form") as HTMLFormElement,
      {
        siteRules: [
          {
            id: "disabled",
            host: window.location.hostname,
            disabled: true
          }
        ]
      }
    );

    expect(submission).toBeNull();
  });

  it("scopes fallback username selection to a rule-selected password field", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "password-only-rule",
          host: window.location.hostname,
          fields: {
            password: ["#target-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("scopes fallback password selection to a rule-selected username field", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "username-only-rule",
          host: window.location.hostname,
          fields: {
            username: ["#target-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not anchor fallback fills to a disabled username site-rule match", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="disabled-user" name="account" type="email" autocomplete="username" disabled />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form" aria-label="Sign in">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "stale-disabled-username-rule",
          host: window.location.hostname,
          fields: {
            username: ["#disabled-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("scopes form-less fallback fields to a partial rule container", () => {
    document.body.innerHTML = `
      <input id="decoy-user" name="email" type="email" autocomplete="username" />
      <div id="target-widget">
        <input id="target-user" name="email" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" />
      </div>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "formless-password-rule",
          host: window.location.hostname,
          fields: {
            password: ["#target-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("scopes credential fallback selection to a rule-selected TOTP field", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
      </form>
      <form id="target-form">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" autocomplete="current-password" />
        <input id="target-totp" name="code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "totp-only-rule",
          host: window.location.hostname,
          fields: {
            totp: ["#target-totp"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret",
      totp: "123456"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
    expect((document.querySelector("#target-totp") as HTMLInputElement).value).toBe("123456");
  });

  it("does not anchor credential fills to ambiguous TOTP site-rule matches", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
        <input id="decoy-totp" class="rule-totp" name="code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
      <form id="target-form" aria-label="Sign in with authenticator">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" autocomplete="current-password" />
        <input id="target-totp" class="rule-totp" name="code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "ambiguous-totp-rule",
          host: window.location.hostname,
          fields: {
            totp: [".rule-totp"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret",
      totp: "123456"
    });
    expect(plan.actions).toEqual([]);
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-totp") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-totp") as HTMLInputElement).value).toBe("");
  });

  it("does not anchor credential fallback to a non-fillable TOTP site-rule match", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-password" name="password" type="password" autocomplete="current-password" />
        <input id="stale-totp" name="code" inputmode="numeric" autocomplete="one-time-code" disabled />
      </form>
      <form id="signin-form" aria-label="Sign in">
        <input id="target-user" name="account" type="email" autocomplete="username" />
        <input id="target-password" name="secret" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "stale-totp-rule",
          host: window.location.hostname,
          fields: {
            totp: ["#stale-totp"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("secret");
  });

  it("scopes change-password fallback fills to the rule-selected form", () => {
    document.body.innerHTML = `
      <form id="decoy-form">
        <input id="decoy-current" name="current_password" type="password" autocomplete="current-password" />
        <input id="decoy-new" name="new_password" type="password" autocomplete="new-password" />
        <input id="decoy-confirm" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
      <form id="target-form">
        <input id="target-current" name="current_password" type="password" autocomplete="current-password" />
        <input id="target-new" name="new_password" type="password" autocomplete="new-password" />
        <input id="target-confirm" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "target-change-rule",
          host: window.location.hostname,
          fields: {
            newPassword: ["#target-new"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      password: "old-secret",
      newPassword: "new-secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-current") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-new") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#decoy-confirm") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-current") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#target-new") as HTMLInputElement).value).toBe("new-secret");
    expect((document.querySelector("#target-confirm") as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("does not fill current passwords into new-password rule fields", () => {
    document.body.innerHTML = `
      <form>
        <input id="current-password" name="current_password" type="password" autocomplete="current-password" />
        <input id="new-password" name="new_password" type="password" autocomplete="new-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "new-password-rule",
          host: window.location.hostname,
          fields: {
            newPassword: ["#new-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      password: "old-secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#current-password") as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector("#new-password") as HTMLInputElement).value).toBe("");
  });

  it("treats readonly rule-selected usernames as consumed for fallback selection", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-user" name="email" type="email" autocomplete="username" />
        <input id="opaque-user" name="account_token" type="text" readonly value="alice" />
        <input id="rule-password" name="secret_text" type="text" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "readonly-username-rule",
          host: window.location.hostname,
          fields: {
            username: ["#opaque-user"],
            password: ["#rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect((document.querySelector("#decoy-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#opaque-user") as HTMLInputElement).value).toBe("alice");
    expect((document.querySelector("#rule-password") as HTMLInputElement).value).toBe("secret");
  });

  it("splits TOTP values across multi-field site rule matches", () => {
    document.body.innerHTML = `
      <form>
        <input class="otp" maxlength="1" inputmode="numeric" />
        <input class="otp" maxlength="1" inputmode="numeric" />
        <input class="otp" maxlength="1" inputmode="numeric" />
        <input class="otp" maxlength="1" inputmode="numeric" />
        <input class="otp" maxlength="1" inputmode="numeric" />
        <input class="otp" maxlength="1" inputmode="numeric" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "split-totp-rule",
          host: window.location.hostname,
          fields: {
            totp: [".otp"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      totp: "123456"
    });
    applyFillPlan(plan, document);

    expect(
      Array.from(document.querySelectorAll<HTMLInputElement>(".otp")).map((field) => field.value)
    ).toEqual(["1", "2", "3", "4", "5", "6"]);
  });

  it("does not split ambiguous multi-scope TOTP site-rule groups", () => {
    document.body.innerHTML = `
      <form id="primary-otp">
        <input class="otp" name="primary_1" maxlength="1" inputmode="numeric" />
        <input class="otp" name="primary_2" maxlength="1" inputmode="numeric" />
        <input class="otp" name="primary_3" maxlength="1" inputmode="numeric" />
        <input class="otp" name="primary_4" maxlength="1" inputmode="numeric" />
        <input class="otp" name="primary_5" maxlength="1" inputmode="numeric" />
        <input class="otp" name="primary_6" maxlength="1" inputmode="numeric" />
      </form>
      <form id="backup-otp">
        <input class="otp" name="backup_1" maxlength="1" inputmode="numeric" />
        <input class="otp" name="backup_2" maxlength="1" inputmode="numeric" />
        <input class="otp" name="backup_3" maxlength="1" inputmode="numeric" />
        <input class="otp" name="backup_4" maxlength="1" inputmode="numeric" />
        <input class="otp" name="backup_5" maxlength="1" inputmode="numeric" />
        <input class="otp" name="backup_6" maxlength="1" inputmode="numeric" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      siteRules: [
        {
          id: "split-totp-rule",
          host: window.location.hostname,
          fields: {
            totp: [".otp"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      totp: "123456"
    });
    applyFillPlan(plan, document);

    expect(
      Array.from(document.querySelectorAll<HTMLInputElement>("#primary-otp .otp")).map(
        (field) => field.value
      )
    ).toEqual(["", "", "", "", "", ""]);
    expect(
      Array.from(document.querySelectorAll<HTMLInputElement>("#backup-otp .otp")).map(
        (field) => field.value
      )
    ).toEqual(["", "", "", "", "", ""]);
  });
});
