import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginFormWithTestAuthorization as fillLoginForm } from "./fillTestHelpers";
import { applyFillPlan } from "../applyFillPlan";
import { collectAutofillPageSnapshot } from "../collectPageFields";
import { createLoginFillPlan } from "../fillPlan";
import {
  createAutomaticFillCapability,
  createManualFillCapability
} from "../fillAuthorization";
import { provesAutomaticLoginIntent } from "../intent";
import { resolveCredentialScopes } from "../scope";
import { triageAutofillPage } from "../triage";
import type { AutofillSiteRule } from "../siteRules";
import {
  installDomRenderEnvironment,
  useDomRenderEnvironment
} from "./renderEnvironment";

useDomRenderEnvironment();

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

function automaticLoginIntentForBody(html: string, siteRules?: AutofillSiteRule[]) {
  document.body.innerHTML = html;
  const snapshot = collectAutofillPageSnapshot(document, { srs: siteRules });
  const scope = resolveCredentialScopes(triageAutofillPage(snapshot).f).find(
    (candidate) => candidate.kind !== "site-rule"
  );
  return scope ? provesAutomaticLoginIntent(scope) : false;
}

describe("login detection fill flow", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("requires positive login intent before automatic fill", () => {
    expect(
      automaticLoginIntentForBody(`
        <form action="/session/login" method="post">
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
        </form>
      `)
    ).toBe(true);

    for (const context of [
      '<form action="/account/settings"><h2>Account settings</h2>',
      '<form action="/account/confirm"><h2>Confirm account</h2>',
      '<form action="/register"><h2>Create account</h2>',
      '<form action="/password/reset"><h2>Reset password</h2>',
      '<form action="/account/change-email"><h2>Change email</h2>',
      '<form action="/login/account/settings"><h2>Sign in to account settings</h2>',
      '<form action="/login/confirmation"><h2>Sign in confirmation</h2>'
    ]) {
      expect(
        automaticLoginIntentForBody(`
          ${context}
            <input name="email" type="email" autocomplete="username" />
            <input name="password" type="password" autocomplete="current-password" />
          </form>
        `)
      ).toBe(false);
    }

    expect(
      automaticLoginIntentForBody(`
        <form action="/login">
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
          <input name="password_confirmation" type="password" autocomplete="new-password" />
        </form>
      `)
    ).toBe(false);
  });

  it.each([
    [
      "cross-origin form action",
      '<form action="https://login.attacker.example/collect" method="post">'
    ],
    ["GET form", '<form action="/login" method="get"><h2>Sign in</h2>'],
    [
      "cross-origin submitter action",
      '<form id="login" action="/login" method="post"><h2>Sign in</h2><button type="submit" formaction="https://attacker.example/collect">Sign in</button>'
    ],
    [
      "GET submitter override",
      '<form id="login" action="/login" method="post"><h2>Sign in</h2><button type="submit" formmethod="get">Sign in</button>'
    ],
    [
      "external associated submitter",
      '<form id="login" action="/login" method="post"><h2>Sign in</h2>'
    ]
  ])("rejects automatic fill with unsafe %s", (_case, formStart) => {
    const externalSubmitter = _case === "external associated submitter";
    document.body.innerHTML = `
      ${formStart}
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
      ${externalSubmitter ? '<button form="login" type="submit" formaction="https://attacker.example/collect">Continue</button>' : ""}
    `;

    const plan = createLoginFillPlan(
      collectAutofillPageSnapshot(document),
      { username: "alice@example.com", password: "secret" },
      createAutomaticFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    expect(plan.ac).toEqual([]);
  });

  it("uses the resolved form action when a base element changes its origin", () => {
    const base = document.createElement("base");
    base.href = "https://attacker.example/base/";
    document.head.append(base);
    document.body.innerHTML = `
      <form action="collect" method="post">
        <h2>Sign in</h2>
        <input type="email" autocomplete="username" />
        <input type="password" autocomplete="current-password" />
      </form>
    `;
    try {
      const snapshot = collectAutofillPageSnapshot(document);
      expect(snapshot.fm[0].ha).toBe("https://attacker.example/base/collect");
      expect(
        createLoginFillPlan(
          snapshot,
          { username: "alice@example.com", password: "secret" },
          createAutomaticFillCapability({
            targetUrl: window.location.href,
            entryId: "entry-1"
          })
        ).ac
      ).toEqual([]);
    } finally {
      base.remove();
    }
  });

  it("accepts verified login site-rule evidence for automatic fill", () => {
    expect(
      automaticLoginIntentForBody(
        `
          <form method="post">
            <input id="rule-user" name="identity" />
            <input id="rule-password" name="secret" type="password" />
          </form>
        `,
        [
          {
            id: "verified-login",
            host: window.location.hostname,
            f: {
              username: ["#rule-user"],
              password: ["#rule-password"]
            }
          }
        ]
      )
    ).toBe(true);
  });

  it("rejects automatic fill when verified login targets are not all fillable", () => {
    document.body.innerHTML = `
      <form>
        <input id="rule-user" name="identity" hidden />
        <input id="rule-password" name="secret" type="password" />
      </form>
    `;
    const siteRules: AutofillSiteRule[] = [
      {
        id: "verified-login",
        host: window.location.hostname,
        f: {
          username: ["#rule-user"],
          password: ["#rule-password"]
        }
      }
    ];
    const snapshot = collectAutofillPageSnapshot(document, { srs: siteRules });

    const plan = createLoginFillPlan(
      snapshot,
      { username: "alice@example.com", password: "secret" },
      createAutomaticFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    expect(plan.ac).toEqual([]);
  });

  it("rejects automatic fill when one site-rule field claims both login roles", () => {
    document.body.innerHTML = `
      <form>
        <input id="both" name="credential" type="password" />
      </form>
    `;
    const fieldMappings: NonNullable<AutofillSiteRule["f"]>[] = [
      { password: ["#both"], username: ["#both"] },
      { username: ["#both"], password: ["#both"] }
    ];

    for (const f of fieldMappings) {
      const snapshot = collectAutofillPageSnapshot(document, {
        srs: [
          {
            id: "ambiguous-login-target",
            host: window.location.hostname,
            f
          }
        ]
      });
      const plan = createLoginFillPlan(
        snapshot,
        { username: "alice@example.com", password: "secret" },
        createAutomaticFillCapability({
          targetUrl: window.location.href,
          entryId: "entry-1"
        })
      );

      expect(plan.ac).toEqual([]);
    }
  });

  it("rejects settings update semantics even when page-load context contains login", () => {
    document.body.innerHTML = `
      <form action="/settings">
        <h2>Update login</h2>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm(
      { username: "alice@example.com", password: "secret" },
      createAutomaticFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe("");
  });

  it("rejects page-load login when ignored fields prove mixed password roles", () => {
    for (const mixedRoleName of ["new_password", "repeat_password", "verify_password"]) {
      document.body.innerHTML = `
        <form action="/login">
          <input name="email" type="email" autocomplete="username" />
          <input name="password" type="password" autocomplete="current-password" />
          <input name="${mixedRoleName}" type="password" hidden />
        </form>
      `;

      fillLoginForm(
        { username: "alice@example.com", password: "secret" },
        createAutomaticFillCapability({
          targetUrl: window.location.href,
          entryId: "entry-1"
        })
      );

      expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
      expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe("");
    }
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

  it("fails closed when login and registration scopes are both compatible", () => {
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
    expect((document.querySelector('input[name="login_user"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("fails closed when registration and password-step scopes are both compatible", () => {
    document.body.innerHTML = `
      <form id="register-form">
        <h2>Create account</h2>
        <input id="signup-user" name="signup_user" autocomplete="username" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
      <form id="password-step">
        <h2>Sign in</h2>
        <input id="login-password" name="login_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "login-secret" });

    expect((document.querySelector("#signup-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
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

  it("does not let unrelated password forms disable username-first fills", () => {
    document.body.innerHTML = `
      <main>
        <form id="username-step">
          <input name="email" type="email" />
        </form>
        <form id="settings">
          <input name="current_password" type="password" autocomplete="current-password" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="current_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("keeps username-first explicit fields ahead of unrelated password forms", () => {
    document.body.innerHTML = `
      <main>
        <form id="settings">
          <input name="settings_password" type="password" autocomplete="current-password" />
        </form>
        <form id="username-step">
          <input name="email" type="email" autocomplete="username" />
        </form>
      </main>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="settings_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("treats a generic email field without login evidence as non-credential", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
  });

  it("treats a generic text email hint without login evidence as non-credential", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="text" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
  });

  it("does not create username-only actions without login evidence", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com" });

    expect((document.querySelector('input[name="email"]') as HTMLInputElement).value).toBe("");
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
    (root.querySelector('input[name="shadow_password"]') as HTMLInputElement).focus();

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

  it("dispatches composed events when filling shadow-root fields", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <form>
        <input name="shadow_email" type="email" autocomplete="username" />
      </form>
    `;
    const events: string[] = [];
    for (const eventName of ["input", "change", "blur"]) {
      host.addEventListener(eventName, (event) => {
        events.push(`${event.type}:${String(event.composed)}`);
      });
    }

    fillLoginForm({ username: "alice@example.com" });

    expect((root.querySelector('input[name="shadow_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect(events).toEqual(["input:true", "change:true", "blur:true"]);
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

  it("fails closed when complete and username-only form-less scopes coexist", () => {
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
    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe("");
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

  it("fails closed when login and settings password scopes are both compatible", () => {
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

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="current_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("fails closed instead of preferring a stronger login scope", () => {
    document.body.innerHTML = `
      <form id="generic">
        <input name="generic_email" type="email" autocomplete="username" />
        <input name="generic_password" type="password" autocomplete="current-password" />
      </form>
      <form id="signin" aria-label="Sign in">
        <input name="signin_email" type="email" autocomplete="username" />
        <input name="signin_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="generic_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="generic_password"]') as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector('input[name="signin_email"]') as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector('input[name="signin_password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("fails closed when login and password-change scopes are both compatible", () => {
    document.body.innerHTML = `
      <form id="settings">
        <input name="settings_email" type="email" autocomplete="username" />
        <input name="settings_current_password" type="password" autocomplete="current-password" />
        <input name="settings_new_password" type="password" autocomplete="new-password" />
      </form>
      <form id="account">
        <input name="account_email" type="email" autocomplete="username" />
        <input name="account_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="settings_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="settings_current_password"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="settings_new_password"]') as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector('input[name="account_email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="account_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("does not treat a generic password-setup form as the login scope", () => {
    document.body.innerHTML = `
      <form id="setup">
        <h2>Password setup</h2>
        <input name="setup_email" type="email" autocomplete="username" />
        <input name="setup_password" type="password" />
        <input name="setup_new_password" type="password" autocomplete="new-password" />
      </form>
      <form id="account">
        <input name="account_email" type="email" autocomplete="username" />
        <input name="account_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="setup_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="setup_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="setup_new_password"]') as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector('input[name="account_email"]') as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector('input[name="account_password"]') as HTMLInputElement).value).toBe(
      "secret"
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
    const unregisterFrameEnvironment = installDomRenderEnvironment(frameDocument);

    try {
      const plan = createLoginFillPlan(
        collectAutofillPageSnapshot(frameDocument),
        {
          username: "alice@example.com",
          password: "secret"
        },
        createManualFillCapability({
          targetUrl: frameDocument.location.href,
          entryId: "entry-1"
        })
      );
      applyFillPlan(plan, frameDocument);

      expect((frameDocument.querySelector('input[name="email"]') as HTMLInputElement).value).toBe(
        "alice@example.com"
      );
      expect(
        (frameDocument.querySelector('input[name="password"]') as HTMLInputElement).value
      ).toBe("secret");
    } finally {
      unregisterFrameEnvironment();
    }
  });

  it("fails closed instead of selecting beside a current-password scope", () => {
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

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="current_password"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("fails closed when password-step and complete-login scopes coexist", () => {
    document.body.innerHTML = `
      <form id="password-step">
        <input name="password_step_password" type="password" autocomplete="current-password" />
      </form>
      <form id="profile">
        <input name="profile_email" type="email" autocomplete="username" />
        <input name="profile_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(
      (document.querySelector('input[name="password_step_password"]') as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector('input[name="profile_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector('input[name="profile_password"]') as HTMLInputElement).value).toBe(
      ""
    );
  });

  it("fails closed when two complete login scopes coexist", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="login_email" type="email" autocomplete="username" />
        <input name="login_password" type="password" />
      </form>
      <form id="settings">
        <input name="settings_email" type="email" autocomplete="username" />
        <input name="settings_current_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector('input[name="login_email"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="login_password"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="settings_email"]') as HTMLInputElement).value).toBe(
      ""
    );
    expect(
      (document.querySelector('input[name="settings_current_password"]') as HTMLInputElement).value
    ).toBe("");
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

  it("does not fill form-level authenticator recovery code prompts", () => {
    document.body.innerHTML = `
      <form>
        <h2>Authenticator backup code</h2>
        <label for="code">Code</label>
        <input id="code" name="code" autocomplete="one-time-code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector('input[name="code"]') as HTMLInputElement).value).toBe("");
  });

  it("does not fill phone verification OTP prompts", () => {
    document.body.innerHTML = `
      <form aria-label="Phone verification">
        <input name="otp" autocomplete="one-time-code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector('input[name="otp"]') as HTMLInputElement).value).toBe("");
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
