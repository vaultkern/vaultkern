import { beforeEach, describe, expect, it } from "vitest";

import { applyFillPlan } from "../applyFillPlan";
import { collectAutofillPageSnapshot } from "../collectPageFields";
import { createLoginFillPlan } from "../fillPlan";
import { matchAutofillSiteRule } from "../siteRules";
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
});
