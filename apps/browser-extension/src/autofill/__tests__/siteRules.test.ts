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

  it("splits one TOTP site-rule group before comparing all matched fields", () => {
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
    ).toEqual(["1", "2", "3", "4", "5", "6"]);
    expect(
      Array.from(document.querySelectorAll<HTMLInputElement>("#backup-otp .otp")).map(
        (field) => field.value
      )
    ).toEqual(["", "", "", "", "", ""]);
  });
});
