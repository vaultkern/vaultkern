import "@testing-library/jest-dom/vitest";

import { createElement, useState, type ChangeEvent } from "react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { applyFillPlan } from "../applyFillPlan";
import { collectAutofillPageSnapshot } from "../collectPageFields";
import { createManualFillCapability } from "../fillAuthorization";
import { createLoginFillPlan, type LoginFillPayload } from "../fillPlan";
import type { AutofillSiteRule } from "../siteRules";
import { useDomRenderEnvironment } from "./renderEnvironment";

useDomRenderEnvironment();

function loginPlan(payload: LoginFillPayload, rules?: AutofillSiteRule[]) {
  return createLoginFillPlan(
    collectAutofillPageSnapshot(document, { srs: rules }),
    payload,
    createManualFillCapability({
      targetUrl: window.location.href,
      entryId: "entry-1"
    })
  );
}

describe("autofill transaction commit", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  afterEach(() => {
    cleanup();
  });

  it("synchronizes a replacement created by a later rollback event", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    let usernameInputCount = 0;
    let trackedPasswordState = "";

    username.addEventListener("input", () => {
      usernameInputCount += 1;
      if (usernameInputCount === 1) {
        username.setAttribute("aria-label", "changed during fill");
        return;
      }
      const replacement = password.cloneNode(true) as HTMLInputElement;
      replacement.value = "secret";
      trackedPasswordState = replacement.value;
      const syncState = () => {
        trackedPasswordState = replacement.value;
      };
      replacement.addEventListener("input", syncState);
      replacement.addEventListener("change", syncState);
      password.replaceWith(replacement);
    });

    applyFillPlan(
      loginPlan({ username: "alice@example.com", password: "secret" }),
      document
    );

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
    expect(trackedPasswordState).toBe("");
  });

  it("stages the whole group before username input and change events", () => {
    document.body.innerHTML = `
      <form>
        <input id="event-user" type="email" autocomplete="username" />
        <input id="event-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#event-user") as HTMLInputElement;
    const password = document.querySelector(
      "#event-password"
    ) as HTMLInputElement;
    const passwordValuesSeenByUsername: string[] = [];

    for (const eventName of ["input", "change"]) {
      username.addEventListener(eventName, () => {
        passwordValuesSeenByUsername.push(password.value);
      });
    }

    applyFillPlan(
      loginPlan({ username: "alice@example.com", password: "secret" }),
      document
    );

    expect(passwordValuesSeenByUsername).toEqual(["secret", "secret"]);
    expect(username.value).toBe("alice@example.com");
    expect(password.value).toBe("secret");
  });

  it("rolls back staged values when post-event validation throws", () => {
    document.body.innerHTML = `
      <form>
        <label id="throwing-label" for="throwing-user">User</label>
        <input id="throwing-user" type="email" autocomplete="username" />
        <input id="throwing-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#throwing-user") as HTMLInputElement;
    const password = document.querySelector(
      "#throwing-password"
    ) as HTMLInputElement;
    username.addEventListener("input", () => {
      document.querySelector("#throwing-label")!.textContent = "x".repeat(16_385);
    });

    expect(() =>
      applyFillPlan(
        loginPlan({ username: "alice@example.com", password: "secret" }),
        document
      )
    ).not.toThrow();
    expect(username.value).toBe("");
    expect(password.value).toBe("");
  });

  it.each(["third value", "replacement"] as const)(
    "rolls back when a username event gives a future field a %s",
    (mutation) => {
      document.body.innerHTML = `
        <form>
          <input id="future-user" type="email" autocomplete="username" />
          <input id="future-password" type="password" autocomplete="current-password" />
        </form>
      `;
      const username = document.querySelector(
        "#future-user"
      ) as HTMLInputElement;
      const password = document.querySelector(
        "#future-password"
      ) as HTMLInputElement;
      let mutated = false;
      username.addEventListener("input", () => {
        if (mutated) {
          return;
        }
        mutated = true;
        if (mutation === "third value") {
          password.value = "page-third-value";
          return;
        }
        const replacement = password.cloneNode(true) as HTMLInputElement;
        replacement.value = "secret";
        password.replaceWith(replacement);
      });

      applyFillPlan(
        loginPlan({ username: "alice@example.com", password: "secret" }),
        document
      );

      expect(username.value).toBe("");
      expect(
        (document.querySelector("#future-password") as HTMLInputElement).value
      ).toBe("");
    }
  );

  it.each(["disable", "remove"] as const)(
    "rolls back when an input event %ss the active site rule",
    (mutation) => {
      document.body.innerHTML = `
        <form>
          <input id="rule-user" />
          <input id="rule-password" type="password" />
        </form>
      `;
      const rules: AutofillSiteRule[] = [
        {
          id: "mutable-rule",
          host: window.location.hostname,
          f: {
            username: ["#rule-user"],
            password: ["#rule-password"]
          }
        }
      ];
      const plan = loginPlan(
        { username: "alice@example.com", password: "secret" },
        rules
      );
      const username = document.querySelector("#rule-user") as HTMLInputElement;
      const password = document.querySelector("#rule-password") as HTMLInputElement;
      username.addEventListener("input", () => {
        if (mutation === "disable") {
          rules[0].d = true;
        } else {
          rules.length = 0;
        }
      });

      applyFillPlan(plan, document, undefined, rules);

      expect(username.value).toBe("");
      expect(password.value).toBe("");
    }
  );

  it("updates React 19 controls when MAIN-world value descriptors are isolated", () => {
    function ControlledCredentials() {
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [, setEventCount] = useState(0);
      const inputProps = {
        onInput: () => setEventCount((count) => count + 1)
      };
      return createElement(
        "form",
        { "aria-label": "Sign in" },
        createElement("input", {
          ...inputProps,
          "aria-label": "Controlled username",
          autoComplete: "username",
          type: "email",
          value: username,
          onChange: (event: ChangeEvent<HTMLInputElement>) =>
            setUsername(event.currentTarget.value)
        }),
        createElement("input", {
          ...inputProps,
          "aria-label": "Controlled password",
          autoComplete: "current-password",
          type: "password",
          value: password,
          onChange: (event: ChangeEvent<HTMLInputElement>) =>
            setPassword(event.currentTarget.value)
        }),
        createElement(
          "output",
          { "data-testid": "controlled-state" },
          `${username}|${password}`
        )
      );
    }

    render(createElement(ControlledCredentials));
    const plan = loginPlan({
      username: "alice@example.com",
      password: "secret"
    });
    const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const descriptorSpy = vi
      .spyOn(Object, "getOwnPropertyDescriptor")
      .mockImplementation((target, property) =>
        property === "value" && target instanceof HTMLInputElement
          ? undefined
          : getOwnPropertyDescriptor(target, property)
      );

    try {
      act(() => {
        applyFillPlan(plan, document);
      });
    } finally {
      descriptorSpy.mockRestore();
    }

    expect(screen.getByTestId("controlled-state")).toHaveTextContent(
      "alice@example.com|secret"
    );
    expect(screen.getByLabelText("Controlled username")).toHaveValue(
      "alice@example.com"
    );
    expect(screen.getByLabelText("Controlled password")).toHaveValue("secret");
  });
});
