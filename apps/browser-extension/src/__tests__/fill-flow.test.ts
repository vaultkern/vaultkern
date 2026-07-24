import "@testing-library/jest-dom/vitest";
import { readFileSync } from "node:fs";
import { createElement, useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fillLoginForm as fillLoginFormWithoutAuthorization } from "../contentScript";
import { applyFillPlan } from "../autofill/applyFillPlan";
import { collectAutofillPageSnapshot } from "../autofill/collectPageFields";
import { createLoginFillPlan } from "../autofill/fillPlan";
import {
  createAutomaticFillCapability,
  createManualFillCapability
} from "../autofill/fillAuthorization";
import {
  installDomRenderEnvironment,
  useDomRenderEnvironment
} from "../autofill/__tests__/renderEnvironment";
import { fillLoginFormWithTestAuthorization as fillLoginForm } from "../autofill/__tests__/fillTestHelpers";

useDomRenderEnvironment();

const runtimeClientMocks = vi.hoisted(() => ({
  getSessionState: vi.fn(),
  getBrowserIntegrationSettings: vi.fn(),
  activateResidentApp: vi.fn(),
  listRecentVaults: vi.fn(),
  preloadCurrentVault: vi.fn(),
  addLocalVaultReference: vi.fn(),
  setCurrentVault: vi.fn(),
  openLocalVault: vi.fn(),
  lockSession: vi.fn(),
  recordUserActivity: vi.fn(),
  unlockCurrentVault: vi.fn(),
  enableQuickUnlockForCurrentVault: vi.fn(),
  unlockCurrentVaultWithQuickUnlock: vi.fn(),
  unlockWithPassword: vi.fn(),
  listGroups: vi.fn(),
  listEntries: vi.fn(),
  getEntryDetail: vi.fn(),
  getAutofillCredential: vi.fn(),
  getAutofillEntryFields: vi.fn(),
  getAutofillCreateContext: vi.fn(),
  findFillCandidates: vi.fn(),
  findExactMatchingEntryIds: vi.fn(),
  createEntry: vi.fn(),
  updateEntryFields: vi.fn()
}));

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });

  return { promise, resolve, reject };
}

function deliveredFillCapability(
  kind: "automatic" | "manual",
  targetUrl: string,
  entryId = "entry-1"
) {
  return { kind, targetUrl, entryId };
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

vi.mock("@vaultkern/runtime-web-client", () => ({
  RuntimeClient: vi.fn(() => runtimeClientMocks)
}));

vi.mock("../runtimeBridge", () => ({
  extensionTransport: {}
}));

afterEach(() => {
  cleanup();
  vi.resetModules();
});

beforeEach(() => {
  document.body.innerHTML = "";
  window.history.replaceState(null, "", "/");
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value: "visible"
  });
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
  delete (globalThis as typeof globalThis & {
    __vaultkernWebAuthnContentScriptInstalled?: boolean;
  }).__vaultkernWebAuthnContentScriptInstalled;
  delete (globalThis as typeof globalThis & {
    __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
  }).__vaultkernAllowSyntheticAutofillSubmitForTests;
  runtimeClientMocks.getSessionState.mockReset();
  runtimeClientMocks.getBrowserIntegrationSettings.mockReset();
  runtimeClientMocks.activateResidentApp.mockReset();
  runtimeClientMocks.listRecentVaults.mockReset();
  runtimeClientMocks.preloadCurrentVault.mockReset();
  runtimeClientMocks.addLocalVaultReference.mockReset();
  runtimeClientMocks.setCurrentVault.mockReset();
  runtimeClientMocks.openLocalVault.mockReset();
  runtimeClientMocks.unlockCurrentVault.mockReset();
  runtimeClientMocks.unlockCurrentVaultWithQuickUnlock.mockReset();
  runtimeClientMocks.unlockWithPassword.mockReset();
  runtimeClientMocks.lockSession.mockReset();
  runtimeClientMocks.recordUserActivity.mockReset();
  runtimeClientMocks.listGroups.mockReset();
  runtimeClientMocks.listEntries.mockReset();
  runtimeClientMocks.getEntryDetail.mockReset();
  runtimeClientMocks.getAutofillCredential.mockReset();
  runtimeClientMocks.getAutofillEntryFields.mockReset();
  runtimeClientMocks.getAutofillCreateContext.mockReset();
  runtimeClientMocks.findFillCandidates.mockReset();
  runtimeClientMocks.findExactMatchingEntryIds.mockReset();
  runtimeClientMocks.createEntry.mockReset();
  runtimeClientMocks.updateEntryFields.mockReset();
  runtimeClientMocks.enableQuickUnlockForCurrentVault.mockReset();
  runtimeClientMocks.recordUserActivity.mockResolvedValue({
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1"
  });
  runtimeClientMocks.getBrowserIntegrationSettings.mockResolvedValue({
    type: "browser_integration_settings",
    language: "en",
    clearClipboardSeconds: 30,
    autofillOnPageLoadEnabled: false,
    browserPasskeyProxyEnabled: false
  });
  runtimeClientMocks.activateResidentApp.mockResolvedValue(undefined);
  runtimeClientMocks.listRecentVaults.mockResolvedValue([]);
  runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: null
  });
  runtimeClientMocks.listGroups.mockResolvedValue({
    type: "group_tree",
    root: {
      id: "group-root",
      title: "Archive",
      entryCount: 0,
      childCount: 0,
      children: []
    }
  });
  runtimeClientMocks.getAutofillCreateContext.mockResolvedValue({
    type: "autofill_create_context",
    rootGroupId: "group-root"
  });
  runtimeClientMocks.getAutofillCredential.mockImplementation(
    async (vaultId, entryId) => {
      const detail = await runtimeClientMocks.getEntryDetail(vaultId, entryId);
      return {
        type: "autofill_credential",
        id: detail.id,
        username: detail.username,
        password: detail.password,
        totp: detail.totp
      };
    }
  );
  runtimeClientMocks.getAutofillEntryFields.mockImplementation(
    async (vaultId, entryId) => {
      const detail = await runtimeClientMocks.getEntryDetail(vaultId, entryId);
      return {
        type: "autofill_entry_fields",
        id: detail.id,
        fields: {
          title: detail.title,
          username: detail.username,
          password: detail.password,
          url: detail.url,
          notes: detail.notes,
          totpUri: detail.totpUri ?? null,
          customFields: detail.customFields ?? []
        }
      };
    }
  );
  runtimeClientMocks.createEntry.mockImplementation(async (_vaultId, input) => {
    const { parentGroupId: _parentGroupId, ...fields } = input;
    return {
      type: "entry_detail",
      id: "entry-created",
      ...fields
    };
  });
  runtimeClientMocks.findExactMatchingEntryIds.mockResolvedValue([]);
  runtimeClientMocks.updateEntryFields.mockImplementation(
    async (_vaultId, entryId, fields) => ({
      type: "entry_detail",
      id: entryId,
      ...fields
    })
  );
});

describe("fillLoginForm", () => {
  it("does not fill a tiny totp field", () => {
    document.body.innerHTML = `
      <form>
        <input id="tiny-totp" autocomplete="one-time-code" inputmode="numeric" />
      </form>
    `;
    const target = document.querySelector("#tiny-totp") as HTMLInputElement;
    stubElementRect(target, elementRect({ left: 20, top: 20, width: 1, height: 1 }));

    fillLoginForm({ totp: "123456" });

    expect(target.value).toBe("");
  });

  it("does not fill a 0x0 unslotted light-DOM field under a closed shadow host", () => {
    const host = document.createElement("div");
    host.attachShadow({ mode: "closed" }).innerHTML = "<span>closed shadow content</span>";
    const target = document.createElement("input");
    target.type = "password";
    target.autocomplete = "current-password";
    host.append(target);
    document.body.append(host);
    stubElementRect(target, elementRect({ left: 20, top: 20, width: 0, height: 0 }));

    fillLoginForm({ password: "secret" });

    expect(target.value).toBe("");
  });

  it("fills the first visible username and password field", () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    fillLoginForm({ username: "alice", password: "secret" });

    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("alice");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("secret");
  });

  it("does not write credentials for a page-load fill without explicit automatic permission", () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    fillLoginForm(
      { username: "alice", password: "secret" },
      { trigger: "pageLoad" }
    );

    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("does not accept forged automatic booleans as fill authorization", () => {
    document.body.innerHTML = `
      <form action="/login" method="post">
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm(
      { username: "alice", password: "secret" },
      { trigger: "pageLoad", allowAutomaticSecretFill: true }
    );

    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("does not mint manual authorization when fillLoginForm omits a capability", () => {
    document.body.innerHTML = `
      <form>
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginFormWithoutAuthorization({
      username: "alice@example.com",
      password: "secret"
    });

    expect((document.querySelector('input[name="username"]') as HTMLInputElement).value).toBe("");
    expect((document.querySelector('input[name="password"]') as HTMLInputElement).value).toBe("");
  });

  it("does not write credentials for a page-load change email scope", () => {
    document.body.innerHTML = `
      <form action="/account/change-email">
        <h2>Change email</h2>
        <input type="email" name="email" autocomplete="email" />
        <input type="password" name="password" autocomplete="current-password" />
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

  it("does not write credentials for an automatic page-load fill when multiple credential scopes exist", () => {
    document.body.innerHTML = `
      <form id="first">
        <input id="first-username" type="email" autocomplete="username" />
        <input id="first-password" type="password" autocomplete="current-password" />
      </form>
      <form id="second">
        <input id="second-username" type="email" autocomplete="username" />
        <input id="second-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm(
      { username: "alice", password: "secret" },
      createAutomaticFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    expect((document.querySelector("#first-username") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#first-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-username") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-password") as HTMLInputElement).value).toBe("");
  });

  it("fills only the visible username field when no password field is present", () => {
    document.body.innerHTML = `
      <form>
        <input type="hidden" name="username" value="hidden-user" />
        <input type="text" name="username" value="" />
      </form>
    `;

    fillLoginForm({ username: "alice", password: "secret" });

    expect(
      (document.querySelector('input[type="text"][name="username"]') as HTMLInputElement)
        .value
    ).toBe("alice");
    expect(
      (document.querySelector('input[type="hidden"][name="username"]') as HTMLInputElement)
        .value
    ).toBe("hidden-user");
  });

  it("fills only the visible password field when no username field is present", () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="password" value="" />
      </form>
    `;

    fillLoginForm({ username: "alice", password: "secret" });

    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("secret");
  });

  it("fills the focused password-only step instead of an earlier password-only form", () => {
    document.body.innerHTML = `
      <form id="first">
        <input id="first-password" type="password" autocomplete="current-password" value="" />
      </form>
      <form id="second">
        <input id="second-password" type="password" autocomplete="current-password" value="" />
      </form>
    `;

    (document.querySelector("#second-password") as HTMLInputElement).focus();
    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#first-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills the focused username-first step instead of an earlier username-only form", () => {
    document.body.innerHTML = `
      <form id="first">
        <input id="first-email" type="email" autocomplete="username" value="" />
      </form>
      <form id="second">
        <input id="second-email" type="email" autocomplete="username" value="" />
      </form>
    `;

    (document.querySelector("#second-email") as HTMLInputElement).focus();
    fillLoginForm({ username: "alice@example.com" });

    expect((document.querySelector("#first-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
  });

  it("focused reset scope fails closed before a separate registration form", () => {
    document.body.innerHTML = `
      <form id="reset-password" aria-label="Reset password">
        <input id="reset-search" name="query" type="search" autocomplete="off" />
      </form>
      <form id="register">
        <h2>Create account</h2>
        <input id="register-email" name="email" type="email" autocomplete="username" />
        <input id="register-password" name="new_password" type="password" autocomplete="new-password" />
        <input id="register-confirm" name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    (document.querySelector("#reset-search") as HTMLInputElement).focus();
    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#reset-search") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-confirm") as HTMLInputElement).value).toBe("");
  });

  it("focused ineligible scope does not fall through to a sibling login", () => {
    document.body.innerHTML = `
      <form id="reset-password" aria-label="Reset password">
        <input id="reset-search" name="query" type="search" autocomplete="off" />
      </form>
      <form id="login">
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    (document.querySelector("#reset-search") as HTMLInputElement).focus();
    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#login-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
  });

  it("same form sections fail closed when login and registration are both viable", () => {
    document.body.innerHTML = `
      <form id="account">
        <fieldset id="registration">
          <legend>Create account</legend>
          <input id="register-email" name="email" type="email" autocomplete="username" />
          <input id="register-password" name="new_password" type="password" autocomplete="new-password" />
          <input id="register-confirm" name="confirm_password" type="password" autocomplete="new-password" />
        </fieldset>
        <section id="login" aria-label="Sign in">
          <input id="login-email" name="identifier" type="text" autocomplete="username" />
          <input id="login-password" name="password" type="password" autocomplete="current-password" />
        </section>
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#register-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-confirm") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
  });

  it("same form sections fail closed with an unannotated viable login scope", () => {
    document.body.innerHTML = `
      <form id="account">
        <fieldset id="registration">
          <legend>Create account</legend>
          <input id="register-email" name="email" type="email" autocomplete="username" />
          <input id="register-password" name="new_password" type="password" autocomplete="new-password" />
          <input id="register-confirm" name="confirm_password" type="password" autocomplete="new-password" />
        </fieldset>
        <section id="login" aria-label="Sign in">
          <input id="login-email" name="identifier" type="text" autocomplete="username" />
          <input id="login-password" name="password" type="password" />
        </section>
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#register-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#register-confirm") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
  });

  it("fills the focused login pair inside a repeated root-level field run", () => {
    document.body.innerHTML = `
      <input id="first-email" type="email" autocomplete="username" value="" />
      <input id="first-password" type="password" autocomplete="current-password" value="" />
      <input id="second-email" type="email" autocomplete="username" value="" />
      <input id="second-password" type="password" autocomplete="current-password" value="" />
    `;

    (document.querySelector("#second-password") as HTMLInputElement).focus();
    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#first-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#first-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#second-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills the focused username login pair inside a repeated root-level field run", () => {
    document.body.innerHTML = `
      <input id="first-email" type="email" autocomplete="username" value="" />
      <input id="first-password" type="password" autocomplete="current-password" value="" />
      <input id="second-email" type="email" autocomplete="username" value="" />
      <input id="second-password" type="password" autocomplete="current-password" value="" />
    `;

    (document.querySelector("#second-email") as HTMLInputElement).focus();
    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#first-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#first-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#second-email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#second-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fails closed when complete and password-only login scopes coexist", () => {
    document.body.innerHTML = `
      <form id="decoy">
        <input id="decoy-password" type="password" autocomplete="current-password" value="" />
      </form>
      <form id="login">
        <input id="login-email" type="email" autocomplete="username" value="" />
        <input id="login-password" type="password" autocomplete="current-password" value="" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-email") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
  });

  it("fails closed for password-only login beside a partial change scope", () => {
    document.body.innerHTML = `
      <form id="login">
        <input id="login-password" type="password" value="" />
      </form>
      <form id="settings">
        <input id="settings-current-password" type="password" autocomplete="current-password" value="" />
        <input id="settings-new-password" type="password" autocomplete="new-password" value="" />
      </form>
    `;
    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#settings-current-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#settings-new-password") as HTMLInputElement).value).toBe("");
  });

  it("fails closed for partial change scope before a password-only login", () => {
    document.body.innerHTML = `
      <form id="settings">
        <input id="settings-current-password" type="password" autocomplete="current-password" value="" />
        <input id="settings-new-password" type="password" autocomplete="new-password" value="" />
      </form>
      <form id="login">
        <input id="login-password" type="password" value="" />
      </form>
    `;
    fillLoginForm({ password: "secret" });

    expect(
      (document.querySelector("#settings-current-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#settings-new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("");
  });

  it("keeps password-only fills off setup forms that also ask for a new password", () => {
    document.body.innerHTML = `
      <form id="setup">
        <input id="setup-password" type="password" value="" />
        <input id="setup-new-password" type="password" autocomplete="new-password" value="" />
      </form>
      <form id="login">
        <input id="login-password" type="password" autocomplete="current-password" value="" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#setup-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#setup-new-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("prefers writable visible fields over readonly or hidden candidates", () => {
    document.body.innerHTML = `
      <form>
        <input type="email" name="email" readonly value="readonly@example.com" />
        <input type="text" name="username" style="display:none" value="" />
        <input type="email" id="login-email" autocomplete="username" value="" />
        <input type="password" name="password" disabled value="" />
        <input type="password" id="login-password" value="" />
      </form>
    `;

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(
      (document.querySelector('input[readonly]') as HTMLInputElement).value
    ).toBe("readonly@example.com");
    expect(
      (document.querySelector('input[style*="display:none"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('#login-email') as HTMLInputElement).value
    ).toBe("alice@example.com");
    expect(
      (document.querySelector('input[disabled]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('#login-password') as HTMLInputElement).value
    ).toBe("secret");
  });

  it("does not fill non-interactive password decoys", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-password" type="password" autocomplete="current-password" style="pointer-events:none" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("rechecks field safety immediately before writing a fill plan", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    const fillPlan = {
      ac: [
        {
          fi: "field-0",
          n: 0,
          ft: "password" as const,
          v: "secret"
        }
      ]
    };

    password.style.display = "none";
    applyFillPlan(fillPlan, document);
    expect(password.value).toBe("");

    password.style.display = "";
    password.style.pointerEvents = "none";
    applyFillPlan(fillPlan, document);
    expect(password.value).toBe("");
  });

  it("rolls back connected fields when an input event reconstructs a group target", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-password" type="password" autocomplete="current-password" />
        <input id="login-email" type="email" autocomplete="username" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    const passwordsObservedByUsernameEvents: string[] = [];
    let passwordInputEvents = 0;
    username.addEventListener("input", () => {
      passwordsObservedByUsernameEvents.push(password.value);
      password.replaceWith(password.cloneNode(true));
    });
    password.addEventListener("input", () => {
      passwordInputEvents += 1;
    });

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(passwordsObservedByUsernameEvents).toContain("secret");
    expect(username.value).toBe("");
    expect(password.value).toBe("");
    expect(
      (document.querySelector("#login-password") as HTMLInputElement).value
    ).toBe("");
    expect(passwordInputEvents).toBe(0);
  });

  it("rolls back a credential group when an input event reorders its targets", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-password" type="password" autocomplete="current-password" />
        <input id="login-email" type="email" autocomplete="username" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector(
      "#login-password"
    ) as HTMLInputElement;
    let reordered = false;
    username.addEventListener("input", () => {
      if (!reordered) {
        reordered = true;
        password.before(username);
      }
    });

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(username.value).toBe("");
    expect(password.value).toBe("");
    expect(reordered).toBe(true);
  });

  it("clears a role-mutated replacement that inherited a staged secret", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector(
      "#login-password"
    ) as HTMLInputElement;
    username.addEventListener("input", () => {
      const replacement = password.cloneNode(true) as HTMLInputElement;
      replacement.type = "text";
      replacement.autocomplete = "off";
      replacement.value = password.value;
      password.replaceWith(replacement);
    });

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(username.value).toBe("");
    expect(password.value).toBe("");
    expect(
      (document.querySelector("#login-password") as HTMLInputElement).value
    ).toBe("");
  });

  it("allows event handlers to add non-binding validation attributes", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    username.addEventListener("input", () => {
      username.setAttribute("aria-invalid", "false");
      username.setAttribute("aria-busy", "false");
    });

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(username.value).toBe("alice@example.com");
    expect(password.value).toBe("secret");
  });

  it("collects at most one full snapshot for a twenty-action fill phase", () => {
    const fields = Array.from(
      { length: 20 },
      (_, index) => `
        <label for="digit-${index}">Digit ${index + 1}</label>
        <span id="digit-hint-${index}">One-time code position ${index + 1}</span>
        <input
          id="digit-${index}"
          class="totp-digit"
          name="digit_${index}"
          aria-labelledby="digit-hint-${index}"
          inputmode="numeric"
          maxlength="1"
        />`
    ).join("");
    const decoys = Array.from(
      { length: 500 },
      (_, index) => `<span data-decoy="${index}">decoy</span>`
    ).join("");
    document.body.innerHTML = `<div>${decoys}</div><form>${fields}</form>`;
    const siteRules = [
      {
        id: "split-totp",
        host: window.location.hostname,
        f: { totp: [".totp-digit"] }
      }
    ];
    const plan = createLoginFillPlan(
      collectAutofillPageSnapshot(document, { srs: siteRules }),
      { totp: "12345678901234567890" },
      createManualFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );
    expect(plan.ac).toHaveLength(20);

    const bodyChildren = document.body.children;
    let bodyTreeReads = 0;
    let bodyTreeReadLimit = Number.POSITIVE_INFINITY;
    Object.defineProperty(document.body, "children", {
      configurable: true,
      get() {
        bodyTreeReads += 1;
        if (bodyTreeReads > bodyTreeReadLimit) {
          throw new Error("more than one full snapshot traversal");
        }
        return bodyChildren;
      }
    });
    try {
      collectAutofillPageSnapshot(document, { srs: siteRules });
      expect(bodyTreeReads).toBeGreaterThan(0);
      bodyTreeReadLimit = bodyTreeReads;
      bodyTreeReads = 0;
      const rootQuery = vi
        .spyOn(document, "querySelector")
        .mockImplementation(() => {
          throw new Error("apply queried the document root");
        });
      const rootQueryAll = vi
        .spyOn(document, "querySelectorAll")
        .mockImplementation(() => {
          throw new Error("apply queried the document root");
        });
      try {
        applyFillPlan(plan, document, undefined, siteRules);
      } finally {
        rootQuery.mockRestore();
        rootQueryAll.mockRestore();
      }
      expect(bodyTreeReads).toBeLessThanOrEqual(bodyTreeReadLimit);
    } finally {
      delete (document.body as Element & { children?: HTMLCollection }).children;
    }
  }, 10_000);

  it("rolls back group values when a native setter fails before events", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" value="before-user" />
        <input id="login-password" type="password" autocomplete="current-password" value="before-secret" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    const inputEvents: string[] = [];
    username.addEventListener("input", () => inputEvents.push("username"));
    password.addEventListener("input", () => inputEvents.push("password"));
    const prototype = window.HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "value")!;
    Object.defineProperty(prototype, "value", {
      ...descriptor,
      set(value: string) {
        if (this === password && value === "secret") {
          throw new Error("setter failed");
        }
        descriptor.set!.call(this, value);
      }
    });

    try {
      fillLoginForm({ username: "alice@example.com", password: "secret" });
    } finally {
      Object.defineProperty(prototype, "value", descriptor);
    }

    expect(username.value).toBe("before-user");
    expect(password.value).toBe("before-secret");
    expect(inputEvents).toEqual([]);
  });

  it.each(["disconnected", "readonly", "replaced"] as const)(
    "does not write any credential action when one group target is %s",
    (mutation) => {
      document.body.innerHTML = `
        <form>
          <input id="login-email" type="email" autocomplete="username" />
          <input id="login-password" type="password" autocomplete="current-password" />
        </form>
      `;
      const username = document.querySelector("#login-email") as HTMLInputElement;
      const password = document.querySelector("#login-password") as HTMLInputElement;
      const plan = createLoginFillPlan(
        collectAutofillPageSnapshot(document),
        { username: "alice@example.com", password: "secret" },
        createManualFillCapability({
          targetUrl: window.location.href,
          entryId: "entry-1"
        })
      );

      if (mutation === "disconnected") {
        password.remove();
      } else if (mutation === "readonly") {
        password.readOnly = true;
      } else {
        password.replaceWith(password.cloneNode() as HTMLInputElement);
      }

      applyFillPlan(plan, document);

      expect(username.value).toBe("");
      expect(password.value).toBe("");
      expect(
        (document.querySelector("#login-password") as HTMLInputElement | null)?.value ?? ""
      ).toBe("");
    }
  );

  it("rejects a credential group when a target changes semantic role", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    const plan = createLoginFillPlan(
      collectAutofillPageSnapshot(document),
      { username: "alice@example.com", password: "secret" },
      createManualFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    password.type = "text";
    password.autocomplete = "username";
    applyFillPlan(plan, document);

    expect(username.value).toBe("");
    expect(password.value).toBe("");
  });

  it("rejects a credential group when label-derived target semantics change", () => {
    document.body.innerHTML = `
      <form>
        <label for="login-email">Account email</label>
        <input id="login-email" type="text" />
        <label for="login-password">Account password</label>
        <input id="login-password" type="password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    const usernameLabel = document.querySelector(
      'label[for="login-email"]'
    ) as HTMLLabelElement;
    const plan = createLoginFillPlan(
      collectAutofillPageSnapshot(document),
      { username: "alice@example.com", password: "secret" },
      createManualFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    expect(plan.ac).toHaveLength(2);
    username.addEventListener("input", () => {
      usernameLabel.textContent = "One-time code";
    });
    applyFillPlan(plan, document);

    expect(username.value).toBe("");
    expect(password.value).toBe("");
  });

  it("rejects a site-rule credential transaction spanning physical scopes", () => {
    document.body.innerHTML = `
      <form id="identity-scope">
        <input id="rule-username" type="email" />
      </form>
      <form id="secret-scope">
        <input id="rule-password" type="password" />
      </form>
    `;
    const username = document.querySelector("#rule-username") as HTMLInputElement;
    const password = document.querySelector("#rule-password") as HTMLInputElement;
    const snapshot = collectAutofillPageSnapshot(document, {
      srs: [
        {
          id: "cross-scope-login",
          host: window.location.hostname,
          f: {
            username: ["#rule-username"],
            password: ["#rule-password"]
          }
        }
      ]
    });
    const plan = createLoginFillPlan(
      snapshot,
      { username: "alice@example.com", password: "secret" },
      createManualFillCapability({
        targetUrl: window.location.href,
        entryId: "entry-1"
      })
    );

    password.readOnly = true;
    applyFillPlan(plan, document);

    expect(plan.ac).toEqual([]);
    expect(username.value).toBe("");
    expect(password.value).toBe("");
  });

  it("updates React controlled input state and rendered values", () => {
    function ControlledCredentials() {
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      return createElement(
        "form",
        null,
        createElement("input", {
          "aria-label": "Controlled username",
          autoComplete: "username",
          type: "email",
          value: username,
          onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
            setUsername(event.currentTarget.value)
        }),
        createElement("input", {
          "aria-label": "Controlled password",
          autoComplete: "current-password",
          type: "password",
          value: password,
          onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
            setPassword(event.currentTarget.value)
        }),
        createElement("output", { "data-testid": "controlled-state" }, `${username}|${password}`)
      );
    }

    render(createElement(ControlledCredentials));

    act(() => {
      fillLoginForm({ username: "alice@example.com", password: "secret" });
    });

    expect(screen.getByTestId("controlled-state")).toHaveTextContent(
      "alice@example.com|secret"
    );
    expect(screen.getByLabelText("Controlled username")).toHaveValue("alice@example.com");
    expect(screen.getByLabelText("Controlled password")).toHaveValue("secret");
  });

  it("rolls back connected React fields when input handling replaces a target", () => {
    function ReconstructingCredentials() {
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [passwordVersion, setPasswordVersion] = useState(0);
      return createElement(
        "form",
        null,
        createElement("input", {
          "aria-label": "Reconstructed username",
          autoComplete: "username",
          type: "email",
          value: username,
          onChange: (event: React.ChangeEvent<HTMLInputElement>) => {
            setUsername(event.currentTarget.value);
            setPasswordVersion((version) => version + 1);
          }
        }),
        createElement("input", {
          key: passwordVersion,
          "aria-label": "Reconstructed password",
          autoComplete: "current-password",
          type: "password",
          value: password,
          onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
            setPassword(event.currentTarget.value)
        }),
        createElement(
          "output",
          { "data-testid": "reconstructed-state" },
          `${username}|${password}`
        )
      );
    }

    render(createElement(ReconstructingCredentials));
    act(() => {
      fillLoginForm({ username: "alice@example.com", password: "secret" });
    });

    expect(screen.getByLabelText("Reconstructed username")).toHaveValue("");
    expect(screen.getByLabelText("Reconstructed password")).toHaveValue("");
    expect(screen.getByTestId("reconstructed-state")).toHaveTextContent(/^\|$/);
  });

  it("dispatches input change and blur events for updated fields", () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    const username = document.querySelector(
      'input[name="username"]'
    ) as HTMLInputElement;
    const password = document.querySelector(
      'input[name="password"]'
    ) as HTMLInputElement;
    const usernameEvents: string[] = [];
    const passwordEvents: string[] = [];

    for (const eventName of ["input", "change", "blur"]) {
      username.addEventListener(eventName, () => {
        usernameEvents.push(eventName);
      });
      password.addEventListener(eventName, () => {
        passwordEvents.push(eventName);
      });
    }

    fillLoginForm({ username: "alice", password: "secret" });

    expect(usernameEvents).toEqual(["input", "change", "blur"]);
    expect(passwordEvents).toEqual(["input", "change", "blur"]);
  });

  it("fills the checked-in browser smoke login page", () => {
    const smokePage = readFileSync("smoke/basic-login.html", "utf8");
    const parsed = new DOMParser().parseFromString(smokePage, "text/html");
    document.body.innerHTML = parsed.body.innerHTML;

    fillLoginForm({
      username: "alice@example.com",
      password: "secret-123"
    });

    expect(
      (document.querySelector("#vaultkern-smoke-username") as HTMLInputElement).value
    ).toBe("alice@example.com");
    expect(
      (document.querySelector("#vaultkern-smoke-password") as HTMLInputElement).value
    ).toBe("secret-123");
  });
});

describe("PopupShell fill flow", () => {
  it("renders popup chrome in Chinese from extension settings", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "zh-CN",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30
              }
            })
          ),
          set: vi.fn((_values, callback) => callback?.())
        }
      },
      tabs: {
        query: vi.fn(async () => [
          {
            id: 7,
            url: "https://example.com/login"
          }
        ]),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.getBrowserIntegrationSettings.mockResolvedValue({
      type: "browser_integration_settings",
      language: "zh-CN",
      clearClipboardSeconds: 30,
      autofillOnPageLoadEnabled: false,
      browserPasskeyProxyEnabled: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("已解锁")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "打开 VaultKern" })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "VaultKern 设置" })
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "锁定" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("主密码")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("搜索记录")).not.toBeInTheDocument();
  });

  it("keeps popup header actions visible when the current site label is long", async () => {
    const longSiteLabel = "egemppbellfgkcheombddecljjehnimc";

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => [
          {
            id: 7,
            url: `chrome-extension://${longSiteLabel}/popup.html`
          }
        ]),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const siteValue = await screen.findByText(longSiteLabel);
    const status = screen.getByText("Unlocked");
    const vaultButton = screen.getByRole("button", { name: "Open VaultKern" });
    const settingsButton = screen.getByRole("button", {
      name: "VaultKern Settings"
    });
    const siteBlock = siteValue.parentElement as HTMLElement;
    const actionBlock = status.parentElement as HTMLElement;

    expect(siteBlock.style.minWidth).toBe("0");
    expect(siteValue.style.overflow).toBe("hidden");
    expect(siteValue.style.textOverflow).toBe("ellipsis");
    expect(siteValue.style.whiteSpace).toBe("nowrap");
    expect(actionBlock.style.flexShrink).toBe("0");
    expect(vaultButton).toBeInTheDocument();
    expect(settingsButton).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock" })).not.toBeInTheDocument();
  });

  it("loads fill candidates for the active tab and fills the selected entry", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const get = vi.fn(async () => ({
      id: 7,
      url: "https://example.com/login",
      active: true,
      windowId: 1
    }));
    const getWindow = vi.fn(async () => ({ focused: true }));
    const sendMessage = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        get,
        sendMessage
      },
      windows: {
        get: getWindow
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice",
      password: "secret-123",
      totp: "123456",
      url: "https://example.com/login",
      notes: ""
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const fillButton = await screen.findByRole("button", {
      name: "Fill Example Account"
    });
    expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
      "vault-1",
      "https://example.com/login"
    );

    fireEvent.click(fillButton);

    await waitFor(() => {
      expect(runtimeClientMocks.getEntryDetail).toHaveBeenCalledWith(
        "vault-1",
        "entry-1"
      );
      expect(sendMessage).toHaveBeenCalledWith(
        7,
        {
          type: "fill_entry_detail",
          targetUrl: "https://example.com/login",
          fillCapability: deliveredFillCapability(
            "manual",
            "https://example.com/login"
          ),
          username: "alice",
          password: "secret-123",
          totp: "123456"
        },
        { frameId: 0 }
      );
      const message = sendMessage.mock.calls[0]?.[1] as { newPassword?: string };
      expect(message.newPassword).toBeUndefined();
    });
  });

  it("does not send manual-fill credentials returned for a different entry", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const get = vi.fn(async () => ({
      id: 7,
      url: "https://example.com/login",
      active: true,
      windowId: 1
    }));
    const getWindow = vi.fn(async () => ({ focused: true }));
    const sendMessage = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        get,
        sendMessage
      },
      windows: {
        get: getWindow
      }
    };

    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Requested Account",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-2",
      title: "Different Account",
      username: "mallory",
      password: "other-secret",
      url: "https://example.com/login",
      notes: ""
    });

    const { fillSelectedEntry } = await import("../popupShell");

    await fillSelectedEntry("vault-1", "entry-1");

    expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
      "vault-1",
      "https://example.com/login"
    );
    expect(runtimeClientMocks.getEntryDetail).toHaveBeenCalledWith(
      "vault-1",
      "entry-1"
    );
    expect(get).toHaveBeenCalledWith(7);
    expect(getWindow).toHaveBeenCalledWith(1);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not deliver a retrieved credential after the resident vault locks", async () => {
    const sendMessage = vi.fn(async () => undefined);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => [
          { id: 7, url: "https://example.com/login" }
        ]),
        get: vi.fn(async () => ({
          id: 7,
          url: "https://example.com/login",
          active: true,
          windowId: 1
        })),
        sendMessage
      },
      windows: {
        get: vi.fn(async () => ({ focused: true }))
      }
    };
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getAutofillCredential.mockResolvedValue({
      type: "autofill_credential",
      id: "entry-1",
      username: "alice",
      password: "secret-123",
      totp: null
    });
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null
    });

    const { fillSelectedEntry } = await import("../popupShell");
    await fillSelectedEntry("vault-1", "entry-1");

    expect(runtimeClientMocks.getAutofillCredential).toHaveBeenCalledWith(
      "vault-1",
      "entry-1",
      "https://example.com/login"
    );
    expect(runtimeClientMocks.getSessionState).toHaveBeenCalledOnce();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not send a selected entry after the active tab navigates away from its candidates", async () => {
    let activeUrl = "https://example.com/login";
    const query = vi.fn(async () => [
      {
        id: 7,
        url: activeUrl
      }
    ]);
    const get = vi.fn(async () => ({ id: 7, url: activeUrl }));
    const sendMessage = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        get,
        sendMessage
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockImplementation(async (_vaultId, url) =>
      url === "https://example.com/login"
        ? [
            {
              id: "entry-1",
              title: "Example Account",
              username: "alice",
              url: "https://example.com/login"
            }
          ]
        : []
    );
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice",
      password: "secret-123",
      url: "https://example.com/login",
      notes: ""
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const fillButton = await screen.findByRole("button", {
      name: "Fill Example Account"
    });
    await waitFor(() =>
      expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
        "vault-1",
        "https://example.com/login"
      )
    );
    const detailRequestsBeforeFill = runtimeClientMocks.getEntryDetail.mock.calls.length;
    activeUrl = "https://evil.test/login";

    fireEvent.click(fillButton);

    await waitFor(() => {
      expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
        "vault-1",
        "https://evil.test/login"
      );
    });
    expect(get).not.toHaveBeenCalled();
    expect(runtimeClientMocks.getEntryDetail).toHaveBeenCalledTimes(
      detailRequestsBeforeFill
    );
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not send a selected entry after the target tab loses focus during secret retrieval", async () => {
    let targetActive = true;
    let windowFocused = true;
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const get = vi.fn(async () => ({
      id: 7,
      url: "https://example.com/login",
      active: targetActive,
      windowId: 1
    }));
    const getWindow = vi.fn(async () => ({ focused: windowFocused }));
    const sendMessage = vi.fn(async () => undefined);
    const detailRequest = createDeferred<{
      type: "entry_detail";
      id: string;
      title: string;
      username: string;
      password: string;
      url: string;
      notes: string;
    }>();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        get,
        sendMessage
      },
      windows: {
        get: getWindow
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockReturnValue(detailRequest.promise);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Fill Example Account"
      })
    );

    await waitFor(() => {
      expect(runtimeClientMocks.getEntryDetail).toHaveBeenCalledWith(
        "vault-1",
        "entry-1"
      );
    });
    targetActive = false;
    windowFocused = false;
    detailRequest.resolve({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice",
      password: "secret-123",
      url: "https://example.com/login",
      notes: ""
    });

    await waitFor(() => {
      expect(getWindow).toHaveBeenCalledWith(1);
    });
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("shows a passkey unlock prompt when opened for a WebAuthn request", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=9&relyingParty=example.com&origin=https%3A%2F%2Fexample.com"
    );
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Work",
        sourceKind: "local",
        sourceSummary: "work.kdbx",
        lastUsedAt: 1776500010,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(
      await screen.findByText("Passkey request waiting")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Unlock your vault to continue the passkey request for example.com.")
    ).toBeInTheDocument();
  });

  it("continues a waiting passkey request after the resident app unlocks the vault", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=10&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-10"
    );
    const sendMessage = vi.fn(async () => undefined);
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };
    runtimeClientMocks.getSessionState
      .mockResolvedValueOnce({
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1"
      })
      .mockResolvedValue({
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1"
      });

    const { PopupShell } = await import("../popupShell");
    render(createElement(PopupShell));

    expect(await screen.findByText("Passkey request waiting")).toBeInTheDocument();
    await waitFor(
      () => {
        expect(sendMessage).toHaveBeenCalledWith({
          type: "vaultkern_unlock_complete",
          requestId: 10,
          origin: "https://example.com",
          relyingParty: "example.com",
          nonce: "nonce-10"
        });
        expect(closeWindow).toHaveBeenCalledOnce();
      },
      { timeout: 2_000 }
    );
  });

  it("does not complete a WebAuthn unlock prompt just because the vault is already unlocked", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=13&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-13"
    );
    const sendMessage = vi.fn(async () => undefined);
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Work",
        sourceKind: "local",
        sourceSummary: "work.kdbx",
        lastUsedAt: 1776500010,
        availability: "ready",
        supportsQuickUnlock: true,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await screen.findByText("Unlocked");
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalledWith({
      type: "vaultkern_unlock_complete",
      requestId: 13,
      origin: "https://example.com",
      relyingParty: "example.com",
      nonce: "nonce-13"
    });
    expect(closeWindow).not.toHaveBeenCalled();
    expect(runtimeClientMocks.listEntries).not.toHaveBeenCalled();
    expect(runtimeClientMocks.findFillCandidates).not.toHaveBeenCalled();
    expect(runtimeClientMocks.getEntryDetail).not.toHaveBeenCalled();
  });

  it("uses only Windows Hello for browser passkey user verification", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=verify&requestId=41&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-41"
    );
    const sendMessage = vi.fn(async () => ({ ok: true }));
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });

    const { PopupShell } = await import("../popupShell");
    render(createElement(PopupShell));

    expect(
      await screen.findByText("Verify passkey request")
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Master Password")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Verify with Windows Hello" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_user_verification_complete",
        requestId: 41,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-41",
        method: "quick_unlock"
      });
      expect(closeWindow).toHaveBeenCalledOnce();
    });
  });

  it("notifies the background page after approving an unlocked WebAuthn request", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=approve&requestId=42&relyingParty=example.com&origin=https%3A%2F%2Fexample.com"
    );
    const sendMessage = vi.fn(async () => undefined);
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Confirm passkey request")).toBeInTheDocument();
    expect(
      screen.getByText("Approve this passkey request for example.com.")
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Open Manager" })
    ).not.toBeInTheDocument();
    expect(runtimeClientMocks.listEntries).not.toHaveBeenCalled();
    expect(runtimeClientMocks.findFillCandidates).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Continue passkey request" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_presence_complete",
        requestId: 42,
        origin: "https://example.com",
        relyingParty: "example.com"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
  });

  it("sends the selected passkey credential when approving a discoverable WebAuthn request", async () => {
    const credentialOptions = [
      {
        credentialId: "Y3JlZGVudGlhbC0x",
        username: "alice@example.com"
      },
      {
        credentialId: "Y3JlZGVudGlhbC0y",
        username: "bob@example.com"
      }
    ];
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=approve&requestId=43&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-43"
    );
    const sendMessage = vi.fn(async (message: unknown) =>
      (message as { type?: unknown } | null)?.type ===
      "vaultkern_presence_options_request"
        ? { credentialOptions }
        : undefined
    );
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    const chromeApi = {
      runtime: {
        sendMessage
      }
    };
    (globalThis as typeof globalThis & { chrome: unknown }).chrome = chromeApi;
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Confirm passkey request")).toBeInTheDocument();
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("bob@example.com"));
    fireEvent.click(
      screen.getByRole("button", { name: "Continue passkey request" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_presence_complete",
        requestId: 43,
        origin: "https://example.com",
        relyingParty: "example.com",
        credentialId: "Y3JlZGVudGlhbC0y",
        nonce: "nonce-43"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
  });

  it("keeps the passkey approval popup open while background prepares credential selection", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=approve&requestId=47&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-47"
    );
    const sendMessage = vi.fn(async (message: unknown) => {
      if (
        (message as { type?: unknown } | null)?.type ===
        "vaultkern_presence_complete"
      ) {
        return { ok: true, keepOpen: true };
      }
      return { credentialOptions: [] };
    });
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Confirm passkey request")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Continue passkey request" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_presence_complete",
        requestId: 47,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-47"
      });
    });
    expect(closeWindow).not.toHaveBeenCalled();
  });

  it("ignores passkey credential options that contain non-UI fields", async () => {
    const credentialOptions = [
      {
        credentialId: "Y3JlZGVudGlhbC0x",
        username: "alice@example.com",
        privateKeyPem: "-----BEGIN PRIVATE KEY-----",
        userHandle: "user-handle",
        generatedUserId: "generated-user",
        entryId: "entry-1",
        ceremonyToken: "page-controlled-token"
      }
    ];
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=approve&requestId=44&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-44"
    );
    const sendMessage = vi.fn(async (message: unknown) =>
      (message as { type?: unknown } | null)?.type ===
      "vaultkern_presence_options_request"
        ? { credentialOptions }
        : undefined
    );
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Confirm passkey request")).toBeInTheDocument();
    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_presence_options_request",
        requestId: 44,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-44"
      });
    });
    expect(screen.queryByText("alice@example.com")).not.toBeInTheDocument();
    expect(screen.queryByText("user-handle")).not.toBeInTheDocument();
    expect(screen.queryByText("generated-user")).not.toBeInTheDocument();
    expect(screen.queryByText("entry-1")).not.toBeInTheDocument();
    expect(screen.queryByText("page-controlled-token")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Continue passkey request" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_presence_complete",
        requestId: 44,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-44"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
  });

  it("shows only locked status and opens the resident app for unlock", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Locked")).toBeInTheDocument();
    expect(screen.queryByLabelText("Master Password")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Key File Path")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unlock Vault" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open VaultKern" }));

    expect(runtimeClientMocks.activateResidentApp).toHaveBeenCalledWith("unlock");
    expect(runtimeClientMocks.unlockCurrentVault).not.toHaveBeenCalled();
    expect(runtimeClientMocks.unlockCurrentVaultWithQuickUnlock).not.toHaveBeenCalled();
  });

  it("opens resident settings instead of an extension-owned page", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => [{ id: 7, url: "https://example.com/login" }]),
        sendMessage: vi.fn(async () => undefined)
      }
    };
    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");
    render(createElement(PopupShell));

    fireEvent.click(
      await screen.findByRole("button", { name: "VaultKern Settings" })
    );

    expect(runtimeClientMocks.activateResidentApp).toHaveBeenCalledWith("settings");
  });

  it("renders fill candidates in runtime-provided order", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-2",
        title: "Most Specific",
        username: "alice",
        url: "https://example.com/login"
      },
      {
        id: "entry-1",
        title: "Less Specific",
        username: "bob",
        url: "https://example.com"
      }
    ]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const buttons = await screen.findAllByRole("button", { name: /Fill / });
    expect(buttons.map((button) => button.getAttribute("aria-label"))).toEqual([
      "Fill Most Specific",
      "Fill Less Specific"
    ]);
  });

  it("swallows tab message failure without surfacing a raw rejection", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const get = vi.fn(async () => ({
      id: 7,
      url: "https://example.com/login",
      active: true,
      windowId: 1
    }));
    const getWindow = vi.fn(async () => ({ focused: true }));
    const sendMessage = vi.fn(async () => {
      throw new Error("tab unavailable");
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        get,
        sendMessage
      },
      windows: {
        get: getWindow
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice",
      password: "secret-123",
      url: "https://example.com/login",
      notes: ""
    });

    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(
      await screen.findByRole("button", { name: "Fill Example Account" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledTimes(1);
      expect(consoleWarn).toHaveBeenCalledWith(
        "Failed to send fill message to active tab",
        expect.any(Error)
      );
    });

    consoleWarn.mockRestore();
  });
});
describe("content script fill message", () => {
  function allowSyntheticAutofillSubmitEvents() {
    (globalThis as typeof globalThis & {
      __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
    }).__vaultkernAllowSyntheticAutofillSubmitForTests = true;
  }

  it("fills the page when the content script receives entry detail", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("bob");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("root-secret");
  });

  it("does not fill a manual entry-detail message for a different page URL", async () => {
    window.history.replaceState(null, "", "/login");
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl: "https://evil.test/login",
        fillCapability: deliveredFillCapability("manual", "https://evil.test/login"),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("does not treat a page-load entry-detail message as manual fill intent", async () => {
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        trigger: "pageLoad",
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" />
        <input type="password" name="password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("honors an explicitly allowed page-load entry-detail message for one ordinary login scope", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("automatic", targetUrl),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form action="/login" method="post">
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("bob");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("root-secret");
  });

  it.each(["automatic", "manual"] as const)(
    "fails closed when %s delivery has no strong visual proof",
    async (kind) => {
      const targetUrl = window.location.href;
      const addListener = vi.fn((listener: (message: unknown) => void) => {
        listener({
          type: "fill_entry_detail",
          targetUrl,
          fillCapability: deliveredFillCapability(kind, targetUrl),
          username: "bob",
          password: "root-secret"
        });
      });
      (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
        runtime: { onMessage: { addListener } }
      };
      document.body.innerHTML = `
        <form action="/login" method="post">
          <input type="email" name="username" autocomplete="username" />
          <input type="password" name="password" autocomplete="current-password" />
        </form>
      `;
      const unregister = installDomRenderEnvironment(document, {
        vvp: undefined
      });
      try {
        vi.resetModules();
        await import("../contentScript");

        expect(
          (document.querySelector('input[name="username"]') as HTMLInputElement)
            .value
        ).toBe("");
        expect(
          (document.querySelector('input[name="password"]') as HTMLInputElement)
            .value
        ).toBe("");
      } finally {
        unregister();
      }
    }
  );

  it.each([
    "url",
    "visibility",
    "role",
    "scope",
    "epoch-child",
    "epoch-attribute",
    "epoch-text"
  ] as const)(
    "revalidates %s after asynchronous visual proof",
    async (mutation) => {
      const targetUrl = window.location.href;
      const proof = createDeferred<boolean>();
      let listener:
        | ((
            message: unknown,
            sender: unknown,
            sendResponse: (response?: unknown) => void
          ) => boolean)
        | undefined;
      const addListener = vi.fn((registered: typeof listener) => {
        listener = registered;
      });
      (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
        runtime: { onMessage: { addListener } }
      };
      document.body.innerHTML = `
        <form action="/login" method="post">
          <input type="email" name="username" autocomplete="username" />
          <input type="password" name="password" autocomplete="current-password" />
        </form>
        <p id="epoch-text">ready</p>
      `;
      const unregister = installDomRenderEnvironment(document, {
        vvp: () => proof.promise
      });
      try {
        vi.resetModules();
        await import("../contentScript");
        const sendResponse = vi.fn();
        expect(
          listener?.(
            {
              type: "fill_entry_detail",
              targetUrl,
              fillCapability: deliveredFillCapability("automatic", targetUrl),
              username: "bob",
              password: "root-secret"
            },
            {},
            sendResponse
          )
        ).toBe(true);

        if (mutation === "url") {
          window.history.pushState(null, "", "/proof-expired");
        } else if (mutation === "visibility") {
          Object.defineProperty(document, "visibilityState", {
            configurable: true,
            value: "hidden"
          });
        } else if (mutation === "role") {
          const password = document.querySelector(
            'input[name="password"]'
          ) as HTMLInputElement;
          password.type = "text";
          password.autocomplete = "username";
        } else if (mutation === "scope") {
          document.body.insertAdjacentHTML(
            "beforeend",
            `
              <form action="/login">
                <input type="email" autocomplete="username" />
                <input type="password" autocomplete="current-password" />
              </form>
            `
          );
        } else if (mutation === "epoch-child") {
          const cover = document.createElement("div");
          cover.style.cssText =
            "position:fixed;inset:0;background:white;pointer-events:none";
          document.body.append(cover);
        } else if (mutation === "epoch-attribute") {
          document.body.setAttribute("data-page-state", "changed");
        } else {
          document.querySelector("#epoch-text")!.firstChild!.nodeValue = "changed";
        }
        proof.resolve(true);
        await waitFor(() => expect(sendResponse).toHaveBeenCalledTimes(1));

        expect(
          (document.querySelector('input[name="username"]') as HTMLInputElement)
            .value
        ).toBe("");
        expect(
          (document.querySelector('input[name="password"]') as HTMLInputElement)
            .value
        ).toBe("");
      } finally {
        unregister();
      }
    }
  );

  it("does not honor a page-load entry-detail message for a different page URL", async () => {
    window.history.replaceState(null, "", "/login");
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl: "https://evil.test/login",
        fillCapability: deliveredFillCapability(
          "automatic",
          "https://evil.test/login"
        ),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("does not honor a page-load entry-detail message while the document is hidden", async () => {
    const targetUrl = window.location.href;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden"
    });
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("automatic", targetUrl),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("does not honor a manual entry-detail message while the document is hidden", async () => {
    const targetUrl = window.location.href;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden"
    });
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        username: "bob",
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" autocomplete="username" />
        <input type="password" name="password" autocomplete="current-password" />
      </form>
    `;

    vi.resetModules();
    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("fills a TOTP field when the content script receives entry detail", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        totp: "246810"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="otp" autocomplete="one-time-code" value="" />
      </form>
    `;

    await import("../contentScript");

    expect((document.querySelector('input[name="otp"]') as HTMLInputElement).value).toBe(
      "246810"
    );
  });

  it("fills available fields from a partial fill message", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        username: "bob"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="username" value="existing-user" />
        <input type="password" name="password" value="existing-password" />
      </form>
    `;

    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("bob");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("existing-password");
  });

  it("does not infer a username step from a generic email field", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        username: "alice",
        password: "secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="email" name="email" />
      </form>
    `;

    await import("../contentScript");

    expect(
      (document.querySelector('input[name="email"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("fills only the password field when the message omits username", async () => {
    const targetUrl = window.location.href;
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
        targetUrl,
        fillCapability: deliveredFillCapability("manual", targetUrl),
        password: "root-secret"
      });
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        }
      }
    };

    document.body.innerHTML = `
      <form>
        <input type="password" name="password" value="" />
      </form>
    `;

    await import("../contentScript");

    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("root-secret");
  });

  it("reports ordinary login submits so the popup can offer to save them", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="captured-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        submittedAt: expect.any(Number)
      });
    });
  });

  it("captures readonly visible usernames in ordinary login submits", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" readonly />
        <input name="password" type="password" autocomplete="current-password" value="captured-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        submittedAt: expect.any(Number)
      });
    });
  });

  it("does not capture hidden-username ordinary login submits", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="email" type="hidden" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="captured-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("reports an explicitly injected submit when SPA handlers prevent default", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="rejected-secret" />
      </form>
    `;
    document.querySelector("form")?.addEventListener("submit", (event) => {
      event.preventDefault();
    });

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "rejected-secret",
        submittedAt: expect.any(Number)
      });
    });
  });

  it("does not capture script-dispatched registration submits", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="captured-secret" />
      </form>
    `;

    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("captures submitted registration credentials when page handlers stop propagation", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="captured-secret" />
      </form>
    `;
    document.querySelector("form")?.addEventListener("submit", (event) => {
      event.stopPropagation();
    });

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("captures submitted registration credentials inside open shadow roots", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    const host = document.createElement("div");
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="captured-secret" />
        <button type="submit">Create account</button>
      </form>
    `;
    document.body.append(host);

    vi.resetModules();
    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    root.querySelector("form")?.addEventListener("submit", (event) => {
      event.preventDefault();
    });
    root.querySelector("button")?.dispatchEvent(
      new MouseEvent("click", {
        bubbles: true,
        cancelable: true,
        composed: true
      })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("captures submitted registration credentials inside dynamically attached shadow roots", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();
    const pageAttachShadow = Element.prototype.attachShadow;

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    allowSyntheticAutofillSubmitEvents();
    vi.resetModules();
    await import("../contentScript");

    const host = document.createElement("div");
    document.body.append(host);
    const root = pageAttachShadow.call(host, { mode: "open" });
    root.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="captured-secret" />
      </form>
    `;
    root.querySelector('input[name="email"]')?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Tab", bubbles: true, composed: true })
    );
    root.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("does not scan descendant trees while discovering shadow roots from input events", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    const container = document.createElement("div");
    for (let index = 0; index < 2_000; index += 1) {
      container.append(document.createElement("span"));
    }
    const target = document.createElement("input");
    container.append(target);
    document.body.append(container);

    vi.resetModules();
    await import("../contentScript");

    const querySelectorAll = vi.spyOn(Element.prototype, "querySelectorAll");
    try {
      target.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      target.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, composed: true }));

      expect(
        querySelectorAll.mock.calls.filter(([selector]) => selector === "*")
      ).toHaveLength(0);
    } finally {
      querySelectorAll.mockRestore();
    }
  });

  it("does not scan an unknown shadow root while discovering it from a key event", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    vi.resetModules();
    await import("../contentScript");

    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    for (let index = 0; index < 2_000; index += 1) {
      root.append(document.createElement("span"));
    }
    const target = document.createElement("input");
    root.append(target);

    const querySelectorAll = vi.spyOn(ShadowRoot.prototype, "querySelectorAll");
    try {
      target.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Tab", bubbles: true, composed: true })
      );

      expect(
        querySelectorAll.mock.calls.filter(([selector]) => selector === "*")
      ).toHaveLength(0);
    } finally {
      querySelectorAll.mockRestore();
    }
  });

  it("captures submitted registration credentials before page handlers clear fields", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="captured-secret" />
      </form>
    `;
    document.querySelector("form")?.addEventListener("submit", () => {
      (document.querySelector('input[name="email"]') as HTMLInputElement).value = "";
      (document.querySelector('input[name="new_password"]') as HTMLInputElement).value = "";
    });

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: "captured-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("preserves password whitespace when reporting a submitted registration form", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" value=" alice@example.com " />
        <input name="new_password" type="password" autocomplete="new-password" value=" captured secret " />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "alice@example.com",
        password: " captured secret ",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("captures an inferred username from a submitted registration form", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <h2>Create account</h2>
        <input name="email" type="email" value="new@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="generated-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "new@example.com",
        password: "generated-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("captures a forgot-password reset new-password field", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form action="/forgot-password/reset">
        <input name="email" type="hidden" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="reset-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "",
        password: "reset-secret",
        submittedAt: expect.any(Number)
      });
    });
  });

  it("reports a submitted registration form as a save candidate", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="new@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="generated-secret" />
        <input name="confirm_password" type="password" autocomplete="new-password" value="generated-secret" />
      </form>
    `;

    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_autofill_submission",
        url: expect.any(String),
        username: "new@example.com",
        password: "generated-secret",
        saveOnly: true,
        submittedAt: expect.any(Number)
      });
    });
  });

  it("ignores filled credentials outside the submitted form", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const addListener = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    document.body.innerHTML = `
      <form id="login-form">
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="captured-secret" />
      </form>
      <form id="search-form">
        <input name="q" type="search" value="pricing" />
      </form>
    `;

    await import("../contentScript");
    document.querySelector("#search-form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("forwards WebAuthn page observations with the actual page origin", async () => {
    const sendMessage = vi.fn();
    const addListener = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener
        },
        sendMessage
      }
    };

    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "create",
          origin: "https://forged.example",
          relyingParty: "localhost",
          challenge: "cmVnaXN0ZXItMQ",
          excludeCredentialIds: ["Y3JlZGVudGlhbC0x"],
          mediation: "conditional"
        }
      })
    );

    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_webauthn_page_request",
      ceremony: "create",
      origin: window.location.origin,
      topOrigin: undefined,
      ancestorOrigins: [],
      relyingParty: "localhost",
      challenge: "cmVnaXN0ZXItMQ",
      allowCredentialIds: undefined,
      excludeCredentialIds: ["Y3JlZGVudGlhbC0x"],
      mediation: "conditional",
      observedAt: expect.any(Number)
    });
  });

  it("forwards the full WebAuthn ancestor origin chain", async () => {
    const sendMessage = vi.fn();
    const originalAncestorOrigins = Object.getOwnPropertyDescriptor(
      window.location,
      "ancestorOrigins"
    );
    Object.defineProperty(window.location, "ancestorOrigins", {
      configurable: true,
      value: ["https://middle.example", "https://top.example"]
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    try {
      await import("../webauthnContentScript");

      window.dispatchEvent(
        new MessageEvent("message", {
          source: window,
          origin: window.location.origin,
          data: {
            type: "vaultkern_webauthn_page_request",
            ceremony: "get",
            relyingParty: "example.com",
            challenge: "Y2hhbGxlbmdlLTE"
          }
        })
      );
    } finally {
      if (originalAncestorOrigins) {
        Object.defineProperty(
          window.location,
          "ancestorOrigins",
          originalAncestorOrigins
        );
      } else {
        delete (window.location as Location & { ancestorOrigins?: unknown })
          .ancestorOrigins;
      }
    }

    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_webauthn_page_request",
      ceremony: "get",
      origin: window.location.origin,
      topOrigin: "https://top.example",
      ancestorOrigins: ["https://middle.example", "https://top.example"],
      relyingParty: "example.com",
      challenge: "Y2hhbGxlbmdlLTE",
      allowCredentialIds: undefined,
      excludeCredentialIds: undefined,
      mediation: undefined,
      observedAt: expect.any(Number)
    });
  });

  it("does not forward page-supplied ceremony tokens in WebAuthn observations", async () => {
    const sendMessage = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          relyingParty: "example.com",
          challenge: "Y2hhbGxlbmdlLTE",
          allowCredentialIds: [
            "Y3JlZGVudGlhbC0x",
            { ceremonyToken: "page-controlled-token" }
          ],
          excludeCredentialIds: [
            { ceremony_token: "page-controlled-token" },
            "Y3JlZGVudGlhbC0y"
          ],
          ceremonyToken: "page-controlled-token",
          ceremony_token: "page-controlled-token"
        }
      })
    );

    const forwarded = sendMessage.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(forwarded).toMatchObject({
      type: "vaultkern_webauthn_page_request",
      ceremony: "get",
      origin: window.location.origin,
      relyingParty: "example.com",
      challenge: "Y2hhbGxlbmdlLTE",
      allowCredentialIds: ["Y3JlZGVudGlhbC0x"],
      excludeCredentialIds: ["Y3JlZGVudGlhbC0y"]
    });
    expect(forwarded.ceremonyToken).toBeUndefined();
    expect(forwarded.ceremony_token).toBeUndefined();
    expect(JSON.stringify(forwarded)).not.toContain("page-controlled-token");
  });

  it("forwards WebAuthn observations from about:blank frames with the inherited origin", async () => {
    const sendMessage = vi.fn();
    const originalOrigin = Object.getOwnPropertyDescriptor(globalThis, "origin");
    Object.defineProperty(globalThis, "origin", {
      configurable: true,
      value: "https://parent.example"
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    try {
      await import("../webauthnContentScript");

      window.dispatchEvent(
        new MessageEvent("message", {
          source: window,
          origin: "https://parent.example",
          data: {
            type: "vaultkern_webauthn_page_request",
            ceremony: "get",
            relyingParty: "parent.example",
            challenge: "Y2hhbGxlbmdlLTE",
            allowCredentialIds: ["Y3JlZGVudGlhbC0x"]
          }
        })
      );
    } finally {
      if (originalOrigin) {
        Object.defineProperty(globalThis, "origin", originalOrigin);
      } else {
        delete (globalThis as typeof globalThis & { origin?: unknown }).origin;
      }
    }

    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_webauthn_page_request",
      ceremony: "get",
      origin: "https://parent.example",
      topOrigin: undefined,
      ancestorOrigins: [],
      relyingParty: "parent.example",
      challenge: "Y2hhbGxlbmdlLTE",
      allowCredentialIds: ["Y3JlZGVudGlhbC0x"],
      excludeCredentialIds: undefined,
      mediation: undefined,
      observedAt: expect.any(Number)
    });
  });

  it("installs the WebAuthn page observation bridge only once when reinjected", async () => {
    const sendMessage = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    await import("../webauthnContentScript");
    vi.resetModules();
    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          relyingParty: "example.com",
          challenge: "Y2hhbGxlbmdlLTE",
          allowCredentialIds: ["Y3JlZGVudGlhbC0x"]
        }
      })
    );

    expect(sendMessage).toHaveBeenCalledTimes(1);
  });
});
