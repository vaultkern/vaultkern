import { beforeEach, describe, expect, it } from "vitest";

import { applyFillPlan as applyFillPlanAgainstCurrentRules } from "../applyFillPlan";
import { collectAutofillPageSnapshot as collectPageSnapshot } from "../collectPageFields";
import { createLoginFillPlan as createAuthorizedLoginFillPlan } from "../fillPlan";
import { createManualFillCapability } from "../fillAuthorization";
import { collectAutofillSubmission } from "../savePrompt";
import { matchAutofillSiteRule } from "../siteRules";
import { triageAutofillPage } from "../triage";
import type { AutofillSiteRule } from "../siteRules";
import { useDomRenderEnvironment } from "./renderEnvironment";

useDomRenderEnvironment();

const siteRulesBySnapshot = new WeakMap<object, AutofillSiteRule[] | undefined>();
const siteRulesByPlan = new WeakMap<object, AutofillSiteRule[] | undefined>();

function collectAutofillPageSnapshot(
  documentRef: Parameters<typeof collectPageSnapshot>[0],
  options: Parameters<typeof collectPageSnapshot>[1]
) {
  const snapshot = collectPageSnapshot(documentRef, options);
  siteRulesBySnapshot.set(snapshot, options?.srs);
  return snapshot;
}

function createLoginFillPlan(
  snapshot: Parameters<typeof createAuthorizedLoginFillPlan>[0],
  payload: Parameters<typeof createAuthorizedLoginFillPlan>[1]
) {
  const plan = createAuthorizedLoginFillPlan(
    snapshot,
    payload,
    createManualFillCapability({
      targetUrl: snapshot.url ?? window.location.href,
      entryId: "entry-1"
    })
  );
  siteRulesByPlan.set(plan, siteRulesBySnapshot.get(snapshot));
  return plan;
}

function applyFillPlan(
  plan: Parameters<typeof applyFillPlanAgainstCurrentRules>[0],
  documentRef: Parameters<typeof applyFillPlanAgainstCurrentRules>[1]
) {
  return applyFillPlanAgainstCurrentRules(
    plan,
    documentRef,
    undefined,
    siteRulesByPlan.get(plan)
  );
}

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
        f: {
          username: ["#rule-user"],
          password: ["#rule-password"]
        }
      }
    ];

    const snapshot = collectAutofillPageSnapshot(document, { srs: rules });
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
        f: { username: ["#host-user"] }
      },
      {
        id: "path",
        host: "example.com",
        pathPrefix: "/account",
        f: { username: ["#path-user"] }
      }
    ];

    expect(matchAutofillSiteRule("https://example.com/account/login", rules)?.id).toBe("path");
  });

  it("matches path prefixes only on route boundaries", () => {
    const rules: AutofillSiteRule[] = [
      {
        id: "host",
        host: "example.com",
        f: { username: ["#host-user"] }
      },
      {
        id: "account",
        host: "example.com",
        pathPrefix: "/account",
        f: { username: ["#account-user"] }
      },
      {
        id: "login",
        host: "example.com",
        pathPrefix: "/login",
        f: { username: ["#login-user"] }
      }
    ];

    expect(matchAutofillSiteRule("https://example.com/account", rules)?.id).toBe("account");
    expect(matchAutofillSiteRule("https://example.com/account/profile", rules)?.id).toBe(
      "account"
    );
    expect(matchAutofillSiteRule("https://example.com/accounting", rules)?.id).toBe("host");
    expect(matchAutofillSiteRule("https://example.com/login-help", rules)?.id).toBe("host");
  });

  it("canonicalizes trailing-dot and IDNA host spellings", () => {
    const asciiRule: AutofillSiteRule = {
      id: "ascii-host",
      host: "example.com",
      f: { username: ["#user"] }
    };
    const unicodeRule: AutofillSiteRule = {
      id: "unicode-host",
      host: "b\u00fccher.example.",
      f: { username: ["#user"] }
    };

    expect(matchAutofillSiteRule("https://example.com./login", [asciiRule])?.id).toBe(
      "ascii-host"
    );
    expect(
      matchAutofillSiteRule("https://xn--bcher-kva.example/login", [unicodeRule])?.id
    ).toBe("unicode-host");
    expect(
      matchAutofillSiteRule("https://b\u00fccher.example/login", [
        { ...unicodeRule, host: "xn--bcher-kva.example" }
      ])?.id
    ).toBe("unicode-host");
  });

  it("matches optional rule ports against the page effective port", () => {
    const httpsDefaultRule: AutofillSiteRule = {
      id: "https-default",
      host: "example.com:443"
    };
    const httpDefaultRule: AutofillSiteRule = {
      id: "http-default",
      host: "example.com:80"
    };
    const developmentRule: AutofillSiteRule = {
      id: "development",
      host: "example.com:8443"
    };

    expect(matchAutofillSiteRule("https://example.com/login", [httpsDefaultRule])?.id).toBe(
      "https-default"
    );
    expect(matchAutofillSiteRule("http://example.com/login", [httpDefaultRule])?.id).toBe(
      "http-default"
    );
    expect(
      matchAutofillSiteRule("https://example.com:8443/login", [developmentRule])?.id
    ).toBe("development");
    expect(matchAutofillSiteRule("http://example.com/login", [httpsDefaultRule])).toBeNull();
    expect(matchAutofillSiteRule("https://example.com/login", [developmentRule])).toBeNull();
  });

  it("prefers an explicit port rule over a hostname-only rule at the same path", () => {
    const rules: AutofillSiteRule[] = [
      { id: "all-ports", host: "example.com" },
      { id: "development-port", host: "example.com:8443" }
    ];

    expect(matchAutofillSiteRule("https://example.com:8443/login", rules)?.id).toBe(
      "development-port"
    );
  });

  it("keeps hostname-only rules port-agnostic and rejects malformed bare hosts", () => {
    const hostnameRule: AutofillSiteRule = {
      id: "hostname-only",
      host: "example.com"
    };

    expect(matchAutofillSiteRule("https://example.com:8443/login", [hostnameRule])?.id).toBe(
      "hostname-only"
    );
    for (const host of [
      "https://example.com",
      "user@example.com",
      "example.com/path",
      " example.com",
      "example.com:0",
      "example.com:65536"
    ]) {
      expect(
        matchAutofillSiteRule("https://example.com/login", [
          { id: `invalid-${host}`, host }
        ])
      ).toBeNull();
    }
    expect(matchAutofillSiteRule("not a URL", [hostnameRule])).toBeNull();
    expect(matchAutofillSiteRule(" https://example.com/login ", [hostnameRule])).toBeNull();
    expect(matchAutofillSiteRule("ftp://example.com/login", [hostnameRule])).toBeNull();
    expect(
      matchAutofillSiteRule("file:///tmp/login", [{ id: "empty-host", host: "" }])
    ).toBeNull();
  });

  it("does not let a narrower enabled rule bypass a matching disabled rule", () => {
    document.body.innerHTML = `
      <form aria-label="Sign in">
        <input id="user" type="email" autocomplete="username" />
        <input id="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rules: AutofillSiteRule[] = [
      {
        id: "site-disabled",
        host: window.location.hostname,
        d: true
      },
      {
        id: "narrow-login-rule",
        host: window.location.hostname,
        pathPrefix: "/login",
        f: {
          username: ["#user"],
          password: ["#password"]
        }
      }
    ];

    const snapshot = collectAutofillPageSnapshot(document, { srs: rules });
    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    applyFillPlan(plan, document);

    expect(snapshot.sr).toEqual({ id: "site-disabled", d: true });
    expect(
      triageAutofillPage(snapshot).f.map((field) => field.rt)
    ).toEqual([[], []]);
    expect(plan.ac).toEqual([]);
    expect((document.querySelector("#user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#password") as HTMLInputElement).value).toBe("");
  });

  it.each(["missing", "disabled", "host-mismatch", "selector-mismatch"] as const)(
    "does not apply site-rule actions when the execution rule is %s",
    (policyChange) => {
      document.body.innerHTML = `
        <form aria-label="Sign in">
          <input id="rule-user" name="opaque_account" type="text" />
          <input id="rule-password" name="opaque_secret" type="text" />
        </form>
      `;
      const plannedRule: AutofillSiteRule = {
        id: "opaque-login",
        host: window.location.hostname,
        f: {
          username: ["#rule-user"],
          password: ["#rule-password"]
        }
      };
      const snapshot = collectAutofillPageSnapshot(document, {
        srs: [plannedRule]
      });
      const plan = createLoginFillPlan(snapshot, {
        username: "alice",
        password: "secret"
      });
      let currentRules: AutofillSiteRule[];
      if (policyChange === "missing") {
        currentRules = [];
      } else if (policyChange === "disabled") {
        currentRules = [{ ...plannedRule, d: true }];
      } else if (policyChange === "host-mismatch") {
        currentRules = [{ ...plannedRule, host: "other.example" }];
      } else {
        currentRules = [
          {
            ...plannedRule,
            f: { username: ["#other-user"], password: ["#other-password"] }
          }
        ];
      }

      expect(plan.ac.map((action) => action.trs)).toEqual([
        "siteRule",
        "siteRule"
      ]);
      applyFillPlanAgainstCurrentRules(plan, document, undefined, currentRules);

      expect((document.querySelector("#rule-user") as HTMLInputElement).value).toBe("");
      expect((document.querySelector("#rule-password") as HTMLInputElement).value).toBe("");
    }
  );

  it("returns an empty fill plan for disabled site rules", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      srs: [{ id: "disabled", host: window.location.hostname, d: true }]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });

    expect(plan.ac).toEqual([]);
  });

  it("falls back to heuristic selection when a rule selector does not match", () => {
    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>
    `;
    const snapshot = collectAutofillPageSnapshot(document, {
      srs: [
        {
          id: "missing-selector",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "ambiguous-password-rule",
          host: window.location.hostname,
          f: {
            password: [".rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.ac).toEqual([]);
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
      srs: [
        {
          id: "ambiguous-password-rule",
          host: window.location.hostname,
          f: {
            password: [".rule-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.ac).toEqual([]);
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
      srs: [
        {
          id: "stale-username-ambiguous-password-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "stale-username-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "ambiguous-username-rule",
          host: window.location.hostname,
          f: {
            username: [".rule-user"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      password: "secret"
    });
    expect(plan.ac).toEqual([]);
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
      srs: [
        {
          id: "partial-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "partial-change-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "ambiguous-new-password-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "ambiguous-new-password-rule",
          host: window.location.hostname,
          f: {
            newPassword: [".rule-new-password"]
          }
        }
      ]
    });

    const plan = createLoginFillPlan(snapshot, {
      username: "alice",
      newPassword: "new-secret"
    });
    expect(plan.ac).toEqual([]);
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
      srs: [
        {
          id: "current-password-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "text-password-rule",
          host: window.location.hostname,
          f: {
            password: ["#rule-password"]
          }
        }
      ]
    });

    const report = triageAutofillPage(snapshot);
    const passwordField = report.f.find((field) => field.hi === "rule-password");

    expect(passwordField?.el).toBe(true);
    expect(passwordField?.q).toBe("password");
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
        srs: [
          {
            id: "text-password-rule",
            host: window.location.hostname,
            f: {
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
        srs: [
          {
            id: "text-password-rule",
            host: window.location.hostname,
            f: {
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
        srs: [
          {
            id: "change-password-rule",
            host: window.location.hostname,
            f: {
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
        srs: [
          {
            id: "readonly-username-rule",
            host: window.location.hostname,
            f: {
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
        srs: [
          {
            id: "disabled",
            host: window.location.hostname,
            d: true
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
      srs: [
        {
          id: "password-only-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "username-only-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "stale-disabled-username-rule",
          host: window.location.hostname,
          f: {
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
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
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
      srs: [
        {
          id: "formless-password-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "totp-only-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "ambiguous-totp-rule",
          host: window.location.hostname,
          f: {
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
    expect(plan.ac).toEqual([]);
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
      srs: [
        {
          id: "stale-totp-rule",
          host: window.location.hostname,
          f: {
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
    expect((document.querySelector("#target-user") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#target-password") as HTMLInputElement).value).toBe("");
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
      srs: [
        {
          id: "target-change-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "new-password-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "readonly-username-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "split-totp-rule",
          host: window.location.hostname,
          f: {
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
      srs: [
        {
          id: "split-totp-rule",
          host: window.location.hostname,
          f: {
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
