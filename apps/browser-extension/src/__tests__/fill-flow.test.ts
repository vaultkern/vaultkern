import "@testing-library/jest-dom/vitest";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fillLoginForm } from "../contentScript";
import { applyFillPlan } from "../autofill/applyFillPlan";

const runtimeClientMocks = vi.hoisted(() => ({
  getSessionState: vi.fn(),
  listRecentVaults: vi.fn(),
  preloadCurrentVault: vi.fn(),
  addLocalVaultReference: vi.fn(),
  setCurrentVault: vi.fn(),
  openLocalVault: vi.fn(),
  lockSession: vi.fn(),
  unlockCurrentVault: vi.fn(),
  enableQuickUnlockForCurrentVault: vi.fn(),
  unlockCurrentVaultWithQuickUnlock: vi.fn(),
  unlockWithPassword: vi.fn(),
  listGroups: vi.fn(),
  listEntries: vi.fn(),
  getEntryDetail: vi.fn(),
  findFillCandidates: vi.fn(),
  createEntry: vi.fn(),
  updateEntryFields: vi.fn(),
  saveVault: vi.fn()
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
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
  delete (globalThis as typeof globalThis & {
    __vaultkernWebAuthnContentScriptInstalled?: boolean;
  }).__vaultkernWebAuthnContentScriptInstalled;
  delete (globalThis as typeof globalThis & {
    __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
  }).__vaultkernAllowSyntheticAutofillSubmitForTests;
  runtimeClientMocks.getSessionState.mockReset();
  runtimeClientMocks.listRecentVaults.mockReset();
  runtimeClientMocks.preloadCurrentVault.mockReset();
  runtimeClientMocks.addLocalVaultReference.mockReset();
  runtimeClientMocks.setCurrentVault.mockReset();
  runtimeClientMocks.openLocalVault.mockReset();
  runtimeClientMocks.unlockCurrentVault.mockReset();
  runtimeClientMocks.unlockCurrentVaultWithQuickUnlock.mockReset();
  runtimeClientMocks.unlockWithPassword.mockReset();
  runtimeClientMocks.lockSession.mockReset();
  runtimeClientMocks.listGroups.mockReset();
  runtimeClientMocks.listEntries.mockReset();
  runtimeClientMocks.getEntryDetail.mockReset();
  runtimeClientMocks.findFillCandidates.mockReset();
  runtimeClientMocks.createEntry.mockReset();
  runtimeClientMocks.updateEntryFields.mockReset();
  runtimeClientMocks.saveVault.mockReset();
  runtimeClientMocks.enableQuickUnlockForCurrentVault.mockReset();
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
  runtimeClientMocks.createEntry.mockResolvedValue({
    type: "entry_detail",
    id: "entry-created",
    title: "Example",
    username: "alice",
    password: "secret",
    url: "https://example.com/login",
    notes: ""
  });
  runtimeClientMocks.updateEntryFields.mockResolvedValue({
    type: "entry_detail",
    id: "entry-1",
    title: "Example",
    username: "alice",
    password: "new-secret",
    url: "https://example.com/login",
    notes: ""
  });
  runtimeClientMocks.saveVault.mockResolvedValue({
    type: "save_vault_result",
    status: "saved"
  });
});

describe("fillLoginForm", () => {
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

  it("keeps password-only fills on the first login password instead of later settings forms", () => {
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

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe(
      "secret"
    );
    expect(
      (document.querySelector("#settings-current-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#settings-new-password") as HTMLInputElement).value).toBe("");
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

  it("does not fill fully clipped password decoys", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-password" type="password" autocomplete="current-password" style="clip-path:circle(0)" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by external clip-path URLs", () => {
    document.body.innerHTML = `
      <form>
        <input id="data-clip-password" type="password" autocomplete="current-password" style='clip-path:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%3CclipPath%20id%3D%22z%22%3E%3Crect%20width%3D%220%22%20height%3D%220%22%2F%3E%3C%2FclipPath%3E%3C%2Fsvg%3E#z")' />
        <input id="blob-clip-password" type="password" autocomplete="current-password" style='clip-path:url("blob:null/zero-clip#z")' />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#data-clip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#blob-clip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by extended blend modes", () => {
    document.body.innerHTML = `
      <form>
        <input id="color-dodge-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:color-dodge" />
        <div style="background:black">
          <input id="color-burn-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:color-burn" />
        </div>
        <input id="plus-lighter-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:plus-lighter" />
        <div style="background:rgb(64,64,64)">
          <input id="overlay-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:overlay" />
          <input id="hard-light-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:hard-light" />
          <input id="soft-light-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:rgb(128,128,128);color:rgb(128,128,128);-webkit-text-fill-color:rgb(128,128,128);border:1px solid rgb(128,128,128);outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:soft-light" />
        </div>
        <div style="background:rgb(128,128,128)">
          <input id="hue-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:hue" />
          <input id="saturation-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;mix-blend-mode:saturation" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, id] of [
      "color-dodge-password",
      "color-burn-password",
      "plus-lighter-password",
      "overlay-password",
      "hard-light-password",
      "soft-light-password",
      "hue-password",
      "saturation-password",
      "login-password"
    ].entries()) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    fillLoginForm({ password: "secret" });

    for (const id of [
      "color-dodge-password",
      "color-burn-password",
      "plus-lighter-password",
      "overlay-password",
      "hard-light-password",
      "soft-light-password",
      "hue-password",
      "saturation-password"
    ]) {
      expect((document.querySelector(`#${id}`) as HTMLInputElement).value).toBe("");
    }
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by modern CSS color functions", () => {
    document.body.innerHTML = `
      <form>
        <input id="srgb-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:color(srgb 1 1 1);color:color(srgb 1 1 1);-webkit-text-fill-color:color(srgb 1 1 1);border:1px solid color(srgb 1 1 1);outline:0;box-shadow:none;text-shadow:none" />
        <input id="oklab-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:oklab(1 0 0);color:oklab(1 0 0);-webkit-text-fill-color:oklab(1 0 0);border:1px solid oklab(1 0 0);outline:0;box-shadow:none;text-shadow:none" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, id] of [
      "srgb-password",
      "oklab-password",
      "login-password"
    ].entries()) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#srgb-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#oklab-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by CSS grayscale filters", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(54,54,54)">
          <input id="grayscale-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:grayscale(1)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#grayscale-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by CSS saturation filters", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(54,54,54)">
          <input id="saturate-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:saturate(0)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#saturate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by CSS sepia filters", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(100,89,69)">
          <input id="sepia-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:sepia(1)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#sepia-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by CSS hue rotation filters", () => {
    document.body.innerHTML = `
      <form>
        <div style="background:rgb(0,109,109)">
          <input id="hue-rotate-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:hue-rotate(180deg)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#hue-rotate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG saturation filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgSaturateZero">
            <feColorMatrix type="saturate" values="0" />
          </filter>
        </svg>
        <div style="background:rgb(127,127,127)">
          <input id="svg-saturate-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgSaturateZero)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-saturate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG hue rotation filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgHueRotateHalfTurn">
            <feColorMatrix type="hueRotate" values="180" />
          </filter>
        </svg>
        <div style="background:rgb(0,175,175)">
          <input id="svg-hue-rotate-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgHueRotateHalfTurn)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-hue-rotate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG matrix filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgMatrixGray" color-interpolation-filters="sRGB">
            <feColorMatrix type="matrix" values="0.498 0 0 0 0 0.498 0 0 0 0 0.498 0 0 0 0 0 0 0 1 0" />
          </filter>
        </svg>
        <div style="background:rgb(127,127,127)">
          <input id="svg-matrix-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgMatrixGray)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-matrix-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG luminance-to-alpha filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="svgLuminanceToAlpha">
            <feColorMatrix type="luminanceToAlpha" />
          </filter>
        </svg>
        <div style="background:black">
          <input id="svg-luminance-alpha-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgLuminanceToAlpha)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-luminance-alpha-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG component transfer filters", () => {
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
          <input id="svg-component-transfer-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgComponentTransferGray)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-component-transfer-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG difference blend filters", () => {
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
          <input id="svg-difference-blend-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;width:185px;height:21px;background:red;color:red;-webkit-text-fill-color:red;border:1px solid red;outline:0;box-shadow:none;text-shadow:none;filter:url(#svgDifferenceBlend)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#svg-difference-blend-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by SVG blend filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="multiplyBlack">
            <feFlood flood-color="black" result="blackPaint" />
            <feBlend in="SourceGraphic" in2="blackPaint" mode="multiply" />
          </filter>
        </svg>
        <div style="background:black">
          <input id="multiply-black-password" type="password" autocomplete="current-password" style="filter:url(#multiplyBlack)" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#multiply-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys hidden by transparent SVG filter images", () => {
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
        <input id="filtered-image-password" type="password" autocomplete="current-password" style="filter:url(#transparentImageFilter)" />
        <input id="blob-filtered-image-password" type="password" autocomplete="current-password" style="filter:url(#blobImageFilter)" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#filtered-image-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#blob-filtered-image-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys displaced out of paint by SVG filters", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="displacedSource" x="-1000" y="-1000" width="2000" height="2000" filterUnits="userSpaceOnUse">
            <feFlood flood-color="white" result="map" />
            <feDisplacementMap in="SourceGraphic" in2="map" scale="2000" xChannelSelector="R" yChannelSelector="G" />
          </filter>
        </svg>
        <input id="displaced-password" type="password" autocomplete="current-password" style="filter:url(#displacedSource)" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#displaced-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys clipped to tiny SVG filter regions", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="tinyFilterRegion" x="0" y="0" width="0.01" height="0.01" filterUnits="objectBoundingBox">
            <feOffset dx="0" dy="0" />
          </filter>
        </svg>
        <input id="tiny-filter-region-password" type="password" autocomplete="current-password" style="filter:url(#tinyFilterRegion)" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const [index, id] of ["tiny-filter-region-password", "login-password"].entries()) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40 + index * 40, width: 185, height: 21 })
      );
    }

    fillLoginForm({ password: "secret" });

    expect(
      (document.querySelector("#tiny-filter-region-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys clipped away by rounded overflow ancestors", () => {
    document.body.innerHTML = `
      <form>
        <div id="rounded-clip" style="position:relative;width:200px;height:200px;overflow:hidden;border-radius:50%">
          <input id="rounded-corner-password" type="password" autocomplete="current-password" style="position:absolute;left:0;top:0;width:20px;height:20px" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#rounded-clip") as HTMLDivElement,
      elementRect({ left: 20, top: 20, width: 200, height: 200 })
    );
    stubElementRect(
      document.querySelector("#rounded-corner-password") as HTMLInputElement,
      elementRect({ left: 20, top: 20, width: 26, height: 24 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#rounded-corner-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password decoys clipped away by ancestor mask clip boxes", () => {
    document.body.innerHTML = `
      <form>
        <div id="mask-clip" style="position:relative;width:200px;height:60px;padding-left:220px;mask-image:linear-gradient(black,black);mask-clip:content-box">
          <input id="mask-clip-password" type="password" autocomplete="current-password" style="position:absolute;left:0;top:0;width:185px;height:21px" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#mask-clip") as HTMLDivElement,
      elementRect({ left: 20, top: 20, width: 420, height: 60 })
    );
    stubElementRect(
      document.querySelector("#mask-clip-password") as HTMLInputElement,
      elementRect({ left: 20, top: 20, width: 191, height: 25 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#mask-clip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill tiny password decoys", () => {
    document.body.innerHTML = `
      <form>
        <input id="decoy-password" type="password" autocomplete="current-password" style="width:1px;height:1px" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#decoy-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill visually suppressed password decoys", () => {
    document.body.innerHTML = `
      <form>
        <div id="parent-translated" style="transform:translateX(-500px)">
          <input id="parent-translated-password" type="password" autocomplete="current-password" />
        </div>
        <div id="parent-relative" style="position:relative;left:-9999px">
          <input id="parent-relative-password" type="password" autocomplete="current-password" />
        </div>
        <input id="rect-translated-password" type="password" autocomplete="current-password" style="transform:translateX(-500px)" />
        <input id="relative-password" type="password" autocomplete="current-password" style="position:relative;left:-9999px" />
        <input id="positive-relative-password" type="password" autocomplete="current-password" style="position:relative;left:9999px" />
        <input id="margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:-9999px" />
        <input id="positive-margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:9999px" />
        <input id="percent-translate-password" type="password" autocomplete="current-password" style="translate:-800%" />
        <input id="calc-translate-password" type="password" autocomplete="current-password" style="translate:calc(-100% - 500px)" />
        <input id="percent-relative-password" type="password" autocomplete="current-password" style="position:relative;left:-800%" />
        <input id="calc-relative-password" type="password" autocomplete="current-password" style="position:relative;left:calc(-100% - 500px)" />
        <input id="percent-margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:-800%" />
        <input id="calc-margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:calc(-100% - 500px)" />
        <input id="translated-y-password" type="password" autocomplete="current-password" style="transform:translateY(-500px)" />
        <input id="longhand-translated-y-password" type="password" autocomplete="current-password" style="translate:0 -500px" />
        <input id="viewport-translated-x-password" type="password" autocomplete="current-password" style="transform:translateX(-100vw)" />
        <input id="viewport-translated-y-password" type="password" autocomplete="current-password" style="translate:0 -100vh" />
        <input id="motion-path-password" type="password" autocomplete="current-password" style='offset-path:path("M -1000 0");offset-distance:100%' />
        <input id="translated-y-after-password" type="password" autocomplete="current-password" style="transform:translateY(900px)" />
        <input id="longhand-translated-y-after-password" type="password" autocomplete="current-password" style="translate:0 900px" />
        <input id="fixed-below-password" type="password" autocomplete="current-password" style="position:fixed;top:900px" />
        <input id="fixed-bottom-below-password" type="password" autocomplete="current-password" style="position:fixed;bottom:-900px" />
        <input id="relative-y-password" type="password" autocomplete="current-password" style="position:relative;top:-500px" />
        <input id="percent-relative-y-password" type="password" autocomplete="current-password" style="position:relative;top:-800%" />
        <input id="calc-relative-y-password" type="password" autocomplete="current-password" style="position:relative;top:calc(-100% - 500px)" />
        <input id="viewport-relative-password" type="password" autocomplete="current-password" style="position:relative;left:-100vw" />
        <input id="margin-y-password" type="password" autocomplete="current-password" style="display:block;margin-top:-500px" />
        <input id="percent-margin-y-password" type="password" autocomplete="current-password" style="display:block;margin-top:-800%" />
        <input id="calc-margin-y-password" type="password" autocomplete="current-password" style="display:block;margin-top:calc(-100% - 500px)" />
        <input id="viewport-margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:-100vw" />
        <input id="mask-transparent-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent,transparent)" />
        <input id="mask-radial-password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(transparent, transparent)" />
        <input id="mask-radial-shape-password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, transparent, transparent)" />
        <input id="mask-conic-password" type="password" autocomplete="current-password" style="mask-image:conic-gradient(from 0deg, transparent, transparent)" />
        <input id="mask-color-space-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(in oklab, transparent, transparent)" />
        <input id="mask-color-function-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(color(srgb 0 0 0 / 0), color(srgb 0 0 0 / 0))" />
        <input id="mask-luminance-black-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black, black);mask-mode:luminance" />
        <input id="mask-stop-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent 0 100%)" />
        <input id="mask-composite-exclude-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black),linear-gradient(black,black);mask-composite:exclude" />
        <svg width="0" height="0" aria-hidden="true">
          <mask id="blackMask"><rect width="100%" height="100%" fill="black" /></mask>
          <mask id="transparentGroupMask"><g opacity="0"><rect width="100%" height="100%" fill="white" /></g></mask>
          <mask id="nestedOpacityMask"><g opacity="0.1"><rect opacity="0.1" width="100%" height="100%" fill="white" /></g></mask>
          <mask id="fillNoneMask"><rect width="100%" height="100%" fill="none" /></mask>
          <mask id="displayNoneMask"><rect style="display:none" width="100%" height="100%" fill="white" /></mask>
          <mask id="hiddenShapeMask"><rect style="visibility:hidden" width="100%" height="100%" fill="white" /></mask>
        </svg>
        <input id="mask-url-password" type="password" autocomplete="current-password" style="mask:url(#blackMask)" />
        <input id="mask-group-opacity-password" type="password" autocomplete="current-password" style="mask:url(#transparentGroupMask)" />
        <input id="mask-nested-opacity-password" type="password" autocomplete="current-password" style="mask:url(#nestedOpacityMask)" />
        <input id="mask-fill-none-password" type="password" autocomplete="current-password" style="mask:url(#fillNoneMask)" />
        <input id="mask-display-none-password" type="password" autocomplete="current-password" style="mask:url(#displayNoneMask)" />
        <input id="mask-hidden-shape-password" type="password" autocomplete="current-password" style="mask:url(#hiddenShapeMask)" />
        <input id="mask-data-svg-password" type="password" autocomplete="current-password" style='mask-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%221%22%20height%3D%221%22%3E%3Crect%20width%3D%221%22%20height%3D%221%22%20fill%3D%22transparent%22%2F%3E%3C%2Fsvg%3E")' />
        <input id="mask-data-svg-root-opacity-password" type="password" autocomplete="current-password" style='mask-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%221%22%20height%3D%221%22%20opacity%3D%220%22%3E%3Crect%20width%3D%221%22%20height%3D%221%22%20fill%3D%22black%22%2F%3E%3C%2Fsvg%3E")' />
        <input id="mask-blob-url-password" type="password" autocomplete="current-password" style='mask-image:url("blob:null/transparent-mask")' />
        <input id="mask-zero-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0 0" />
        <input id="mask-zero-percent-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:0% 100%;mask-repeat:no-repeat" />
        <input id="mask-tiny-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4px 100%;mask-repeat:no-repeat" />
        <input id="mask-tiny-percent-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:4% 100%;mask-repeat:no-repeat" />
        <input id="mask-position-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black,black);mask-size:100% 100%;mask-repeat:no-repeat;mask-position:-9999px 0" />
        <svg width="0" height="0" aria-hidden="true">
          <filter id="alphaZero"><feComponentTransfer><feFuncA type="table" tableValues="0 0" /></feComponentTransfer></filter>
          <filter id="alphaZeroDiscrete"><feComponentTransfer><feFuncA type="discrete" tableValues="0 0" /></feComponentTransfer></filter>
          <filter id="alphaZeroGamma"><feComponentTransfer><feFuncA type="gamma" amplitude="0" offset="0" /></feComponentTransfer></filter>
          <filter id="alphaZeroMatrix"><feColorMatrix type="matrix" values="1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0 0" /></filter>
          <filter id="alphaTenLinear"><feComponentTransfer><feFuncA type="linear" slope="0.1" intercept="0" /></feComponentTransfer></filter>
          <filter id="floodAlphaZero"><feFlood flood-opacity="0" /></filter>
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
        </svg>
        <input id="svg-filter-password" type="password" autocomplete="current-password" style="filter:url(#alphaZero)" />
        <input id="data-svg-filter-password" type="password" autocomplete="current-password" style='filter:url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%3Cfilter%20id%3D%22alphaZero%22%3E%3CfeComponentTransfer%3E%3CfeFuncA%20type%3D%22table%22%20tableValues%3D%220%200%22%2F%3E%3C%2FfeComponentTransfer%3E%3C%2Ffilter%3E%3C%2Fsvg%3E#alphaZero")' />
        <input id="filter-blob-url-password" type="password" autocomplete="current-password" style='filter:url("blob:null/alpha-zero#f")' />
        <input id="svg-filter-discrete-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroDiscrete)" />
        <input id="svg-filter-gamma-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroGamma)" />
        <input id="svg-filter-matrix-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroMatrix)" />
        <input id="svg-filter-flood-password" type="password" autocomplete="current-password" style="filter:url(#floodAlphaZero)" />
        <div style="background:black">
          <input id="svg-filter-flood-black-password" type="password" autocomplete="current-password" style="filter:url(#floodBlack)" />
          <input id="svg-filter-matrix-black-password" type="password" autocomplete="current-password" style="filter:url(#matrixBlack)" />
          <input id="svg-filter-merged-flood-black-password" type="password" autocomplete="current-password" style="filter:url(#mergedFloodBlack)" />
          <input id="svg-filter-component-black-password" type="password" autocomplete="current-password" style="filter:url(#componentBlack)" />
          <input id="svg-filter-composite-black-password" type="password" autocomplete="current-password" style="filter:url(#compositeBlackIn)" />
          <input id="svg-filter-blend-black-password" type="password" autocomplete="current-password" style="filter:url(#blendBlack)" />
        </div>
        <div style="background:rgb(0,0,255)">
          <input id="svg-filter-named-blue-password" type="password" autocomplete="current-password" style="filter:url(#floodNamedBlue)" />
        </div>
        <input id="svg-filter-composite-in-password" type="password" autocomplete="current-password" style="filter:url(#compositeInTransparent)" />
        <input id="svg-filter-morphology-password" type="password" autocomplete="current-password" style="filter:url(#morphologyErode)" />
        <input id="svg-filter-composite-out-password" type="password" autocomplete="current-password" style="filter:url(#sourceOut)" />
        <input id="svg-filter-arithmetic-zero-password" type="password" autocomplete="current-password" style="filter:url(#arithmeticZero)" />
        <input id="svg-filter-offset-password" type="password" autocomplete="current-password" style="filter:url(#offsetSource)" />
        <div style="opacity:0.1">
          <div style="opacity:0.1">
            <input id="cumulative-opacity-password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div style="filter:opacity(10%)">
          <div style="filter:opacity(10%)">
            <input id="cumulative-filter-password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div style="opacity:0.1">
          <div style="filter:opacity(10%)">
            <input id="mixed-opacity-filter-password" type="password" autocomplete="current-password" />
          </div>
        </div>
        <div style="opacity:0.1">
          <input id="mixed-svg-filter-opacity-password" type="password" autocomplete="current-password" style="filter:url(#alphaTenLinear)" />
        </div>
        <input id="rotate-x-password" type="password" autocomplete="current-password" style="rotate:x 90deg" />
        <input id="rotate-y-password" type="password" autocomplete="current-password" style="rotate:y 90deg" />
        <input id="backface-password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:rotateY(180deg)" />
        <input id="backface-matrix-password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:matrix3d(-1,0,0,0,0,1,0,0,0,0,-1,0,0,0,0,1)" />
        <div style="transform:rotateY(180deg);transform-style:preserve-3d">
          <input id="ancestor-backface-password" type="password" autocomplete="current-password" style="backface-visibility:hidden" />
        </div>
        <input id="paintless-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:transparent;-webkit-text-fill-color:transparent;outline:0;box-shadow:none;text-shadow:none" />
        <input id="same-color-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <input id="same-color-border-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:1px solid white;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
        <input id="tiny-font-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;-webkit-text-fill-color:black;font-size:1px;outline:0;box-shadow:none;text-shadow:none" />
        <div style="background:black">
          <input id="filter-darkened-password" type="password" autocomplete="current-password" style="filter:brightness(0);background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:black;filter:brightness(0)">
          <input id="ancestor-filter-darkened-password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:rgb(128, 128, 128)">
          <input id="filter-contrast-password" type="password" autocomplete="current-password" style="filter:contrast(0);background:white;color:black;border:1px solid white" />
        </div>
        <div style="background:rgb(128, 128, 128);filter:contrast(0)">
          <input id="ancestor-filter-contrast-password" type="password" autocomplete="current-password" style="background:white;color:black;border:1px solid white" />
        </div>
        <input id="filter-inverted-password" type="password" autocomplete="current-password" style="filter:invert(1);background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <input id="blend-screen-password" type="password" autocomplete="current-password" style="mix-blend-mode:screen;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        <div style="mix-blend-mode:screen">
          <input id="ancestor-blend-screen-password" type="password" autocomplete="current-password" style="background:black;color:black;-webkit-text-fill-color:black;border:1px solid black" />
        </div>
        <div style="background:black">
          <input id="blend-multiply-password" type="password" autocomplete="current-password" style="mix-blend-mode:multiply;background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
        </div>
        <div style="background:black">
          <div style="mix-blend-mode:multiply">
            <input id="ancestor-blend-multiply-password" type="password" autocomplete="current-password" style="background:white;color:white;-webkit-text-fill-color:white;border:1px solid white" />
          </div>
        </div>
        <div style="background-image:linear-gradient(black, black)">
          <input id="gradient-backdrop-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;background:black;color:black;-webkit-text-fill-color:black;border:1px solid black;outline:0;box-shadow:none;text-shadow:none" />
        </div>
        <input id="font-zero-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;font-size:0;outline:0;box-shadow:none;text-shadow:none" />
        <input id="text-indent-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;text-indent:-9999px;outline:0;box-shadow:none;text-shadow:none" />
        <input id="occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:88px;width:185px;height:21px" />
        <div id="occluding-cover" style="position:absolute;left:0;top:80px;width:260px;height:48px;background:white"></div>
        <input id="pointer-events-occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:172px;width:185px;height:21px" />
        <div id="pointer-events-cover" style="position:absolute;left:0;top:164px;width:260px;height:48px;background:white;pointer-events:none"></div>
        <div id="pseudo-cover-host" style="position:absolute;left:0;top:216px;width:260px;height:48px">
          <input id="pseudo-occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:8px;width:185px;height:21px;z-index:1" />
        </div>
        <div id="pseudo-after-cover-host" style="position:absolute;left:0;top:268px;width:260px;height:48px">
          <input id="pseudo-after-occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:8px;width:185px;height:21px" />
        </div>
        <input id="translated-password" type="password" autocomplete="current-password" style="translate:-9999px" />
        <input id="longhand-scaled-password" type="password" autocomplete="current-password" style="scale:0" />
        <input id="zoom-zero-password" type="password" autocomplete="current-password" style="zoom:0" />
        <input id="calc-opacity-password" type="password" autocomplete="current-password" style="opacity:calc(0)" />
        <input id="filter-password" type="password" autocomplete="current-password" style="filter:opacity(0)" />
        <input id="scaled-password" type="password" autocomplete="current-password" style="transform:scale(0)" />
        <div style="transform:scale(0)">
          <input id="ancestor-scaled-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const id of [
      "parent-translated-password",
      "rect-translated-password",
      "percent-translate-password",
      "calc-translate-password",
      "viewport-translated-x-password",
      "motion-path-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: -476, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "percent-relative-password",
      "calc-relative-password",
      "percent-margin-password",
      "calc-margin-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: -1476, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "parent-relative-password",
      "relative-password",
      "margin-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: -9975, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of ["viewport-relative-password", "viewport-margin-password"]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: -1000, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of ["positive-relative-password", "positive-margin-password"]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 10024, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "translated-y-password",
      "longhand-translated-y-password",
      "viewport-translated-y-password",
      "relative-y-password",
      "margin-y-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: -520, width: 185, height: 21 })
      );
    }
    for (const id of [
      "percent-relative-y-password",
      "calc-relative-y-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: -1180, width: 185, height: 21 })
      );
    }
    for (const id of [
      "percent-margin-y-password",
      "calc-margin-y-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: -1476, width: 185, height: 21 })
      );
    }
    for (const id of [
      "translated-y-after-password",
      "longhand-translated-y-after-password",
      "fixed-below-password",
      "fixed-bottom-below-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 920, width: 185, height: 21 })
      );
    }
    stubElementRect(
      document.querySelector("#rotate-x-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 0 })
    );
    stubElementRect(
      document.querySelector("#rotate-y-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 0, height: 21 })
    );
    stubElementRect(
      document.querySelector("#mask-position-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    for (const id of ["mask-zero-percent-password", "mask-tiny-percent-password"]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    stubElementRect(
      document.querySelector("#zoom-zero-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 0, height: 0 })
    );
    const originalElementFromPoint = document.elementFromPoint;
    const occludedPassword = document.querySelector("#occluded-password") as HTMLInputElement;
    const occludingCover = document.querySelector("#occluding-cover") as HTMLDivElement;
    const pointerEventsOccludedPassword = document.querySelector(
      "#pointer-events-occluded-password"
    ) as HTMLInputElement;
    const pointerEventsCover = document.querySelector("#pointer-events-cover") as HTMLDivElement;
    const pseudoCoverHost = document.querySelector("#pseudo-cover-host") as HTMLDivElement;
    const pseudoOccludedPassword = document.querySelector(
      "#pseudo-occluded-password"
    ) as HTMLInputElement;
    const pseudoAfterCoverHost = document.querySelector(
      "#pseudo-after-cover-host"
    ) as HTMLDivElement;
    const pseudoAfterOccludedPassword = document.querySelector(
      "#pseudo-after-occluded-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    stubElementRect(
      occludedPassword,
      elementRect({ left: 24, top: 88, width: 185, height: 21 })
    );
    stubElementRect(
      pointerEventsOccludedPassword,
      elementRect({ left: 24, top: 172, width: 185, height: 21 })
    );
    stubElementRect(
      pointerEventsCover,
      elementRect({ left: 0, top: 164, width: 260, height: 48 })
    );
    stubElementRect(pseudoCoverHost, elementRect({ left: 0, top: 216, width: 260, height: 48 }));
    stubElementRect(
      pseudoOccludedPassword,
      elementRect({ left: 24, top: 224, width: 185, height: 21 })
    );
    stubElementRect(
      pseudoAfterCoverHost,
      elementRect({ left: 0, top: 268, width: 260, height: 48 })
    );
    stubElementRect(
      pseudoAfterOccludedPassword,
      elementRect({ left: 24, top: 276, width: 185, height: 21 })
    );
    stubElementRect(
      loginPassword,
      elementRect({ left: 24, top: 140, width: 185, height: 21 })
    );
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
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 88 && y <= 109) {
          return occludingCover;
        }
        if (x >= 24 && x <= 209 && y >= 172 && y <= 193) {
          return pointerEventsOccludedPassword;
        }
        if (x >= 24 && x <= 209 && y >= 224 && y <= 245) {
          return pseudoOccludedPassword;
        }
        if (x >= 24 && x <= 209 && y >= 276 && y <= 297) {
          return pseudoAfterOccludedPassword;
        }
        if (x >= 24 && x <= 209 && y >= 140 && y <= 161) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });
    pseudoStyle.mockRestore();

    expect((document.querySelector("#parent-translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#parent-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rect-translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#positive-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#positive-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-translate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-translate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#translated-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#longhand-translated-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#viewport-translated-x-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#viewport-translated-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#motion-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#translated-y-after-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#longhand-translated-y-after-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#fixed-below-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#fixed-bottom-below-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#relative-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-relative-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-relative-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#viewport-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#margin-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-margin-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-margin-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#viewport-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-transparent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-radial-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-radial-shape-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-conic-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-color-space-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-color-function-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-luminance-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-stop-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-composite-exclude-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-url-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-group-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-nested-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-fill-none-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-display-none-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-hidden-shape-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-data-svg-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-data-svg-root-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-blob-url-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-zero-percent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-tiny-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-tiny-percent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-position-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#data-svg-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#filter-blob-url-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-discrete-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-gamma-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-matrix-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-flood-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-flood-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-matrix-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-merged-flood-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-component-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-composite-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-blend-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-named-blue-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-composite-in-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-morphology-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-composite-out-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-arithmetic-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#cumulative-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#cumulative-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mixed-opacity-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mixed-svg-filter-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rotate-x-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rotate-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#backface-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#backface-matrix-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#ancestor-backface-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#paintless-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#same-color-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#same-color-border-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#tiny-font-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#filter-darkened-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-filter-darkened-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#filter-contrast-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-filter-contrast-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#filter-inverted-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#blend-screen-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-blend-screen-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#blend-multiply-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-blend-multiply-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#gradient-backdrop-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#font-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#text-indent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#occluded-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#pointer-events-occluded-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#pseudo-occluded-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#pseudo-after-occluded-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#longhand-scaled-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#zoom-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#scaled-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-scaled-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills backface-hidden fields when preserve-3d is flattened by grouping styles", () => {
    document.body.innerHTML = `
      <form>
        <div style="transform:rotateY(180deg);transform-style:preserve-3d;opacity:.999">
          <input id="login-password" type="password" autocomplete="current-password" style="backface-visibility:hidden" />
        </div>
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not fill password fields covered by sibling pseudo-elements", () => {
    document.body.innerHTML = `
      <form>
        <input id="pseudo-sibling-covered-password" type="password" autocomplete="current-password" />
        <div id="sibling-pseudo-cover" style="position:absolute;left:24px;top:40px;width:1px;height:1px;z-index:10"></div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const coveredPassword = document.querySelector(
      "#pseudo-sibling-covered-password"
    ) as HTMLInputElement;
    const pseudoCover = document.querySelector("#sibling-pseudo-cover") as HTMLDivElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    stubElementRect(coveredPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(pseudoCover, elementRect({ left: 24, top: 40, width: 1, height: 1 }));
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
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
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });
    pseudoStyle.mockRestore();

    expect(coveredPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat a visible label as enough for a filter-offset password decoy", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="nearOffsetSource"><feOffset dx="-500" dy="0" /></filter>
        </svg>
        <label id="decoy-label" for="decoy-password" style="position:absolute;left:24px;top:40px;width:185px;height:21px">Password</label>
        <input id="decoy-password" type="password" autocomplete="current-password" style="filter:url(#nearOffsetSource)" />
        <label id="ancestor-decoy-label" for="ancestor-decoy-password" style="position:absolute;left:24px;top:70px;width:185px;height:21px">Password</label>
        <div id="ancestor-filter-offset" style="filter:url(#nearOffsetSource)">
          <input id="ancestor-decoy-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const decoyPassword = document.querySelector("#decoy-password") as HTMLInputElement;
    const decoyLabel = document.querySelector("#decoy-label") as HTMLLabelElement;
    const ancestorDecoyPassword = document.querySelector(
      "#ancestor-decoy-password"
    ) as HTMLInputElement;
    const ancestorDecoyLabel = document.querySelector(
      "#ancestor-decoy-label"
    ) as HTMLLabelElement;
    const ancestorFilterOffset = document.querySelector(
      "#ancestor-filter-offset"
    ) as HTMLDivElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    stubElementRect(decoyPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(decoyLabel, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(
      ancestorDecoyPassword,
      elementRect({ left: 24, top: 70, width: 185, height: 21 })
    );
    stubElementRect(
      ancestorDecoyLabel,
      elementRect({ left: 24, top: 70, width: 185, height: 21 })
    );
    stubElementRect(
      ancestorFilterOffset,
      elementRect({ left: 0, top: 62, width: 1000, height: 48 })
    );
    stubElementRect(loginPassword, elementRect({ left: 24, top: 120, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return decoyLabel;
        }
        if (x >= 24 && x <= 209 && y >= 70 && y <= 91) {
          return ancestorDecoyLabel;
        }
        if (x >= 24 && x <= 209 && y >= 120 && y <= 141) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(decoyPassword.value).toBe("");
    expect(ancestorDecoyPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("fills a password field when an svg filter keeps source graphic as the final output", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="unusedAlphaZero">
            <feComponentTransfer in="SourceGraphic" result="hiddenBranch">
              <feFuncA type="table" tableValues="0 0" />
            </feComponentTransfer>
            <feMerge><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </svg>
        <input id="filtered-password" type="password" autocomplete="current-password" style="filter:url(#unusedAlphaZero)" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#filtered-password") as HTMLInputElement).value).toBe(
      "secret"
    );
  });

  it("does not treat a visible label as enough for a merged filter-offset password decoy", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <filter id="mergedOffsetSource">
            <feOffset dx="-500" dy="0" result="moved" />
            <feMerge><feMergeNode in="moved" /></feMerge>
          </filter>
        </svg>
        <label id="decoy-label" for="decoy-password" style="position:absolute;left:24px;top:40px;width:185px;height:21px">Password</label>
        <input id="decoy-password" type="password" autocomplete="current-password" style="filter:url(#mergedOffsetSource)" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const decoyPassword = document.querySelector("#decoy-password") as HTMLInputElement;
    const decoyLabel = document.querySelector("#decoy-label") as HTMLLabelElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    stubElementRect(decoyPassword, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(decoyLabel, elementRect({ left: 24, top: 40, width: 185, height: 21 }));
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return decoyLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(decoyPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for ancestor-clipped password decoys", () => {
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
          <input id="ancestor-inset-password" type="password" autocomplete="current-password" />
        </div>
        <label id="polygon-label" for="ancestor-polygon-password">Password</label>
        <div id="ancestor-polygon-clip" style="width:400px;height:40px;clip-path:polygon(320px 0, 400px 0, 400px 40px, 320px 40px)">
          <input id="ancestor-polygon-password" type="password" autocomplete="current-password" />
        </div>
        <label id="url-label" for="ancestor-url-password">Password</label>
        <div id="ancestor-url-clip" style="width:400px;height:40px;clip-path:url(#rightRectClip)">
          <input id="ancestor-url-password" type="password" autocomplete="current-password" />
        </div>
        <label id="css-path-label" for="ancestor-css-path-password">Password</label>
        <div id="ancestor-css-path-clip" style='width:400px;height:40px;clip-path:path(evenodd, "M0 0 L400 0 L400 40 L0 40 Z M0 0 L240 0 L240 40 L0 40 Z")'>
          <input id="ancestor-css-path-password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-path-label" for="ancestor-svg-path-password">Password</label>
        <div id="ancestor-svg-path-clip" style="width:400px;height:40px;clip-path:url(#rightEvenOddPathClip)">
          <input id="ancestor-svg-path-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const insetPassword = document.querySelector("#ancestor-inset-password") as HTMLInputElement;
    const polygonPassword = document.querySelector(
      "#ancestor-polygon-password"
    ) as HTMLInputElement;
    const urlPassword = document.querySelector("#ancestor-url-password") as HTMLInputElement;
    const cssPathPassword = document.querySelector(
      "#ancestor-css-path-password"
    ) as HTMLInputElement;
    const svgPathPassword = document.querySelector(
      "#ancestor-svg-path-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 320, width: 185, height: 21 }));
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
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(insetPassword.value).toBe("");
    expect(polygonPassword.value).toBe("");
    expect(urlPassword.value).toBe("");
    expect(cssPathPassword.value).toBe("");
    expect(svgPathPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for rotated svg clip path decoys", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="rotatedLeftRectClip"><rect x="0" y="0" width="80" height="40" transform="rotate(180 200 20)" /></clipPath>
        </svg>
        <label id="rotated-clip-label" for="rotated-clip-password">Password</label>
        <div id="ancestor-rotated-clip" style="width:400px;height:40px;clip-path:url(#rotatedLeftRectClip)">
          <input id="rotated-clip-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rotatedClipPassword = document.querySelector(
      "#rotated-clip-password"
    ) as HTMLInputElement;
    const rotatedClipLabel = document.querySelector(
      "#rotated-clip-label"
    ) as HTMLLabelElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return rotatedClipLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(rotatedClipPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("fills password fields when an ancestor clip path contains the control", () => {
    document.body.innerHTML = `
      <form>
        <div id="ancestor-clip" style="width:400px;height:40px;clip-path:inset(0 160px 0 0)">
          <input id="login-password" type="password" autocomplete="current-password" />
        </div>
      </form>
    `;
    stubElementRect(
      document.querySelector("#ancestor-clip") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not treat visible labels as enough for ancestor-masked password decoys", () => {
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
          <input id="ancestor-css-mask-password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-mask-label" for="ancestor-svg-mask-password">Password</label>
        <div id="ancestor-svg-mask" style="width:400px;height:40px;mask:url(#rightMask)">
          <input id="ancestor-svg-mask-password" type="password" autocomplete="current-password" />
        </div>
        <label id="css-gradient-mask-label" for="ancestor-css-gradient-mask-password">Password</label>
        <div id="ancestor-css-gradient-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent 0 240px, black 240px 100%)">
          <input id="ancestor-css-gradient-mask-password" type="password" autocomplete="current-password" />
        </div>
        <label id="svg-evenodd-mask-label" for="ancestor-svg-evenodd-mask-password">Password</label>
        <div id="ancestor-svg-evenodd-mask" style="width:400px;height:40px;mask:url(#rightEvenOddMask)">
          <input id="ancestor-svg-evenodd-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
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
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 264, width: 185, height: 21 }));
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
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(cssMaskPassword.value).toBe("");
    expect(svgMaskPassword.value).toBe("");
    expect(cssGradientMaskPassword.value).toBe("");
    expect(svgEvenOddMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for rotated svg mask use decoys", () => {
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
          <input id="rotated-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const rotatedMaskPassword = document.querySelector(
      "#rotated-mask-password"
    ) as HTMLInputElement;
    const rotatedMaskLabel = document.querySelector(
      "#rotated-mask-label"
    ) as HTMLLabelElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return rotatedMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(rotatedMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("fills password fields when an ancestor mask contains the control", () => {
    document.body.innerHTML = `
      <form>
        <div id="ancestor-mask" style="width:400px;height:40px;mask-image:linear-gradient(black,black);mask-size:240px 100%;mask-repeat:no-repeat;mask-position:0 0">
          <input id="login-password" type="password" autocomplete="current-password" />
        </div>
      </form>
    `;
    stubElementRect(
      document.querySelector("#ancestor-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills password fields through opaque alpha SVG masks", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <mask id="alphaMask" mask-type="alpha">
            <rect width="200" height="30" fill="black" />
          </mask>
        </svg>
        <input id="login-password" type="password" autocomplete="current-password" style="mask:url(#alphaMask)" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not treat visible labels as enough for radial ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="radial-mask-label" for="radial-mask-password">Password</label>
        <div id="ancestor-radial-mask" style="width:400px;height:40px;mask-image:radial-gradient(circle at 360px 20px, black 0 40px, transparent 40px 100%)">
          <input id="radial-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const radialMaskPassword = document.querySelector(
      "#radial-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const radialMaskLabel = document.querySelector("#radial-mask-label") as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return radialMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(radialMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for radial ancestor mask hole decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="radial-hole-mask-label" for="radial-hole-mask-password">Password</label>
        <div id="ancestor-radial-hole-mask" style="width:400px;height:40px;mask-image:radial-gradient(circle at 116px 20px, transparent 0 100px, black 100px 120px, transparent 120px 100%)">
          <input id="radial-hole-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const radialHoleMaskPassword = document.querySelector(
      "#radial-hole-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const radialHoleMaskLabel = document.querySelector(
      "#radial-hole-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return radialHoleMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(radialHoleMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for conic ancestor mask wedge decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="conic-mask-label" for="conic-mask-password">Password</label>
        <div id="ancestor-conic-mask" style="width:400px;height:40px;mask-image:conic-gradient(from -10deg at -200px 20px, transparent 0deg 20deg, black 20deg 360deg)">
          <input id="conic-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const conicMaskPassword = document.querySelector(
      "#conic-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const conicMaskLabel = document.querySelector("#conic-mask-label") as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return conicMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(conicMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat tiny conic ancestor mask wedges as visible password targets", () => {
    document.body.innerHTML = `
      <form>
        <label id="conic-tiny-mask-label" for="conic-tiny-mask-password">Password</label>
        <div id="ancestor-conic-tiny-mask" style="width:400px;height:40px;mask-image:conic-gradient(from -10deg at -200px 20px, transparent 0deg 9.5deg, black 9.5deg 10.5deg, transparent 10.5deg 360deg)">
          <input id="conic-tiny-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const conicTinyMaskPassword = document.querySelector(
      "#conic-tiny-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const conicTinyMaskLabel = document.querySelector(
      "#conic-tiny-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return conicTinyMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(conicTinyMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("fills password fields when a radial ancestor mask contains the control", () => {
    document.body.innerHTML = `
      <form>
        <div id="ancestor-radial-mask" style="width:400px;height:40px;mask-image:radial-gradient(circle at 116px 20px, black 0 120px, transparent 120px 100%)">
          <input id="login-password" type="password" autocomplete="current-password" />
        </div>
      </form>
    `;
    stubElementRect(
      document.querySelector("#ancestor-radial-mask") as HTMLDivElement,
      elementRect({ left: 0, top: 32, width: 400, height: 40 })
    );
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("does not treat visible labels as enough for repeating-radial ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="repeating-radial-mask-label" for="repeating-radial-mask-password">Password</label>
        <div id="ancestor-repeating-radial-mask" style="width:400px;height:40px;mask-image:repeating-radial-gradient(circle at 360px 20px, black 0 40px, transparent 40px 400px)">
          <input id="repeating-radial-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const repeatingRadialMaskPassword = document.querySelector(
      "#repeating-radial-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const repeatingRadialMaskLabel = document.querySelector(
      "#repeating-radial-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return repeatingRadialMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(repeatingRadialMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for repeating-gradient ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="repeating-mask-label" for="repeating-mask-password">Password</label>
        <div id="ancestor-repeating-mask" style="width:400px;height:40px;mask-image:repeating-linear-gradient(to right, transparent 0 240px, black 240px 400px)">
          <input id="repeating-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const repeatingMaskPassword = document.querySelector(
      "#repeating-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const repeatingMaskLabel = document.querySelector(
      "#repeating-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return repeatingMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(repeatingMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat sparse repeating-linear ancestor mask stripes as visible password targets", () => {
    document.body.innerHTML = `
      <form>
        <label id="sparse-repeating-mask-label" for="sparse-repeating-mask-password">Password</label>
        <div id="ancestor-sparse-repeating-mask" style="width:400px;height:40px;mask-image:repeating-linear-gradient(to right, black 0 1px, transparent 1px 40px)">
          <input id="sparse-repeating-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const sparseRepeatingMaskPassword = document.querySelector(
      "#sparse-repeating-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const sparseRepeatingMaskLabel = document.querySelector(
      "#sparse-repeating-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return sparseRepeatingMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(sparseRepeatingMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat sparse repeated linear mask tiles as visible password targets", () => {
    document.body.innerHTML = `
      <form>
        <label id="sparse-tiled-mask-label" for="sparse-tiled-mask-password">Password</label>
        <div id="ancestor-sparse-tiled-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, black 0 1px, transparent 1px 40px);mask-size:40px 100%;mask-repeat:repeat">
          <input id="sparse-tiled-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const sparseTiledMaskPassword = document.querySelector(
      "#sparse-tiled-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const sparseTiledMaskLabel = document.querySelector(
      "#sparse-tiled-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return sparseTiledMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(sparseTiledMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for hard-stop ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="hard-stop-mask-label" for="hard-stop-mask-password">Password</label>
        <div id="ancestor-hard-stop-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent 60%, black 0)">
          <input id="hard-stop-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const hardStopMaskPassword = document.querySelector(
      "#hard-stop-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const hardStopMaskLabel = document.querySelector(
      "#hard-stop-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return hardStopMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(hardStopMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for implicit-stop ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="implicit-stop-mask-label" for="implicit-stop-mask-password">Password</label>
        <div id="ancestor-implicit-stop-mask" style="width:400px;height:40px;mask-image:linear-gradient(to right, transparent, transparent 60%, black 60%, black)">
          <input id="implicit-stop-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const implicitStopMaskPassword = document.querySelector(
      "#implicit-stop-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const implicitStopMaskLabel = document.querySelector(
      "#implicit-stop-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return implicitStopMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(implicitStopMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not treat visible labels as enough for color-interpolated ancestor mask decoys", () => {
    document.body.innerHTML = `
      <form>
        <label id="color-space-mask-label" for="color-space-mask-password">Password</label>
        <div id="ancestor-color-space-mask" style="width:400px;height:40px;mask-image:linear-gradient(in oklab, transparent 0 24px, black 24px 100%)">
          <input id="color-space-mask-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const colorSpaceMaskPassword = document.querySelector(
      "#color-space-mask-password"
    ) as HTMLInputElement;
    const loginPassword = document.querySelector("#login-password") as HTMLInputElement;
    const colorSpaceMaskLabel = document.querySelector(
      "#color-space-mask-label"
    ) as HTMLLabelElement;
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
    stubElementRect(loginPassword, elementRect({ left: 24, top: 96, width: 185, height: 21 }));
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 40 && y <= 61) {
          return colorSpaceMaskLabel;
        }
        if (x >= 24 && x <= 209 && y >= 96 && y <= 117) {
          return loginPassword;
        }
        return document.body;
      }
    });

    fillLoginForm({ password: "secret" });
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: originalElementFromPoint
    });

    expect(colorSpaceMaskPassword.value).toBe("");
    expect(loginPassword.value).toBe("secret");
  });

  it("does not fill near-total clipped password decoys", () => {
    document.body.innerHTML = `
      <style>
        .clip-off { transform: translate(-9999px, 0); }
        .clip-collapsed { transform: scale(0); }
      </style>
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="zeroClip"><rect width="0" height="0" /></clipPath>
          <clipPath id="stripClip"><rect width="4" height="100" /></clipPath>
          <clipPath id="offsetRectClip"><rect x="-9999" y="0" width="200" height="30" /></clipPath>
          <clipPath id="offsetCircleClip"><circle cx="-9999" cy="10" r="20" /></clipPath>
          <clipPath id="translatedRectClip"><rect width="200" height="30" transform="translate(-9999 0)" /></clipPath>
          <clipPath id="scaledRectClip"><rect width="200" height="30" transform="scale(0)" /></clipPath>
          <clipPath id="classTranslatedRectClip"><rect class="clip-off" width="200" height="30" /></clipPath>
          <clipPath id="classScaledRectClip"><rect class="clip-collapsed" width="200" height="30" /></clipPath>
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
        <input id="inset-password" type="password" autocomplete="current-password" style="clip-path:inset(49%)" />
        <input id="rounded-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(49% round 2px)" />
        <input id="calc-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% - 4px) 0 0)" />
        <input id="math-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(0 max(0px, calc(100% - 4px)) 0 0)" />
        <input id="clamp-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(0 clamp(0px, calc(100% - 4px), 100%) 0 0)" />
        <input id="circle-password" type="password" autocomplete="current-password" style="clip-path:circle(1px)" />
        <input id="polygon-strip-password" type="password" autocomplete="current-password" style="clip-path:polygon(0 0, 4px 0, 4px 100%, 0 100%)" />
        <input id="polygon-percent-password" type="password" autocomplete="current-password" style="clip-path:polygon(0 0, 10% 0, 10% 30%, 0 30%)" />
        <input id="circle-offset-password" type="password" autocomplete="current-password" style="clip-path:circle(50% at -9999px 50%)" />
        <input id="ellipse-offset-password" type="password" autocomplete="current-password" style="clip-path:ellipse(50% 50% at -9999px 50%)" />
        <input id="css-path-password" type="password" autocomplete="current-password" style='clip-path:path("M0 0Z")' />
        <input id="css-path-strip-password" type="password" autocomplete="current-password" style='clip-path:path("M0 0 L4 0 L4 100 L0 100 Z")' />
        <input id="clip-path-rect-password" type="password" autocomplete="current-password" style="clip-path:rect(0 4px 100px 0)" />
        <input id="clip-path-xywh-password" type="password" autocomplete="current-password" style="clip-path:xywh(0 0 4px 100%)" />
        <input id="clip-path-offset-xywh-password" type="password" autocomplete="current-password" style="clip-path:xywh(-9999px 0 200px 30px)" />
        <input id="clip-path-offset-rect-password" type="password" autocomplete="current-password" style="clip-path:rect(0 -9990px 30px -10000px)" />
        <input id="inset-offset-password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% + 9799px) calc(100% - 30px) -9999px)" />
        <input id="legacy-strip-password" type="password" autocomplete="current-password" style="position:absolute;clip:rect(0 4px 100px 0)" />
        <input id="legacy-offset-password" type="password" autocomplete="current-password" style="position:absolute;clip:rect(0 -9990px 30px -10000px)" />
        <input id="url-zero-password" type="password" autocomplete="current-password" style="clip-path:url(#zeroClip)" />
        <input id="url-strip-password" type="password" autocomplete="current-password" style="clip-path:url(#stripClip)" />
        <input id="url-offset-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#offsetRectClip)" />
        <input id="url-offset-circle-password" type="password" autocomplete="current-password" style="clip-path:url(#offsetCircleClip)" />
        <input id="url-translated-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#translatedRectClip)" />
        <input id="url-scaled-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#scaledRectClip)" />
        <input id="url-class-translated-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#classTranslatedRectClip)" />
        <input id="url-class-scaled-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#classScaledRectClip)" />
        <input id="url-polygon-password" type="password" autocomplete="current-password" style="clip-path:url(#zeroPolygonClip)" />
        <input id="url-path-password" type="password" autocomplete="current-password" style="clip-path:url(#zeroPathClip)" />
        <input id="url-use-password" type="password" autocomplete="current-password" style="clip-path:url(#zeroUseClip)" />
        <input id="url-defs-use-password" type="password" autocomplete="current-password" style="clip-path:url(#defsUseZeroClip)" />
        <input id="url-anchor-password" type="password" autocomplete="current-password" style="clip-path:url(#anchorZeroClip)" />
        <input id="url-switch-password" type="password" autocomplete="current-password" style="clip-path:url(#switchZeroClip)" />
        <input id="url-metadata-password" type="password" autocomplete="current-password" style="clip-path:url(#metadataZeroClip)" />
        <input id="url-nested-attr-password" type="password" autocomplete="current-password" style="clip-path:url(#nestedAttrZeroClip)" />
        <input id="url-nested-style-password" type="password" autocomplete="current-password" style="clip-path:url(#nestedStyleZeroClip)" />
        <input id="url-nested-group-password" type="password" autocomplete="current-password" style="clip-path:url(#nestedGroupZeroClip)" />
        <input id="url-nested-use-password" type="password" autocomplete="current-password" style="clip-path:url(#nestedUseZeroClip)" />
        <input id="url-empty-group-password" type="password" autocomplete="current-password" style="clip-path:url(#emptyGroupClip)" />
        <input id="url-line-password" type="password" autocomplete="current-password" style="clip-path:url(#lineClip)" />
        <input id="url-empty-text-password" type="password" autocomplete="current-password" style="clip-path:url(#emptyTextClip)" />
        <input id="url-text-password" type="password" autocomplete="current-password" style="clip-path:url(#textClip)" />
        <input id="url-display-none-password" type="password" autocomplete="current-password" style="clip-path:url(#displayNoneRectClip)" />
        <input id="url-hidden-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#hiddenRectClip)" />
        <input id="url-evenodd-polygon-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPolygonClip)" />
        <input id="url-evenodd-single-path-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddSinglePathClip)" />
        <input id="url-evenodd-path-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPathClip)" />
        <input id="css-evenodd-polygon-password" type="password" autocomplete="current-password" style="clip-path:polygon(evenodd, 0 0, 100% 0, 100% 100%, 0 100%, 0 0, 100% 0, 100% 100%, 0 100%)" />
        <input id="css-evenodd-path-password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <input id="url-evenodd-covered-path-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddCoveredPathClip)" />
        <input id="css-evenodd-covered-path-password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <div style="width:2px;height:2px;overflow:hidden">
          <input id="ancestor-clipped-password" type="password" autocomplete="current-password" />
        </div>
        <div id="ancestor-strip-clip" style="width:185px;height:21px;overflow:hidden">
          <input id="ancestor-strip-clipped-password" type="password" autocomplete="current-password" style="position:relative;left:-181px" />
        </div>
        <div id="auto-overflow-clip" style="position:relative;width:185px;height:21px;overflow:auto">
          <input id="auto-overflow-clipped-password" type="password" autocomplete="current-password" style="position:absolute;left:181px;width:185px;height:21px" />
        </div>
        <div id="scroll-overflow-clip" style="position:relative;width:185px;height:21px;overflow:scroll">
          <input id="scroll-overflow-clipped-password" type="password" autocomplete="current-password" style="position:absolute;left:181px;width:185px;height:21px" />
        </div>
        <div style="width:2px;height:2px;contain:paint">
          <input id="paint-contained-password" type="password" autocomplete="current-password" />
        </div>
        <div style="width:2px;height:2px;contain:strict">
          <input id="strict-contained-password" type="password" autocomplete="current-password" />
        </div>
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    for (const id of [
      "math-inset-password",
      "clamp-inset-password",
      "polygon-percent-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "url-offset-rect-password",
      "url-offset-circle-password",
      "url-translated-rect-password",
      "url-scaled-rect-password",
      "url-class-translated-rect-password",
      "url-class-scaled-rect-password",
      "url-evenodd-polygon-password",
      "url-evenodd-single-path-password",
      "url-evenodd-path-password",
      "css-evenodd-polygon-password",
      "css-evenodd-path-password",
      "url-evenodd-covered-path-password",
      "css-evenodd-covered-path-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "circle-offset-password",
      "ellipse-offset-password",
      "clip-path-offset-xywh-password",
      "clip-path-offset-rect-password",
      "inset-offset-password",
      "legacy-offset-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 24, top: 1208, width: 185, height: 21 })
      );
    }
    stubElementRect(
      document.querySelector("#ancestor-strip-clip") as HTMLDivElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    stubElementRect(
      document.querySelector("#ancestor-strip-clipped-password") as HTMLInputElement,
      elementRect({ left: -157, top: 40, width: 185, height: 21 })
    );
    for (const id of ["auto-overflow-clip", "scroll-overflow-clip"]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLDivElement,
        elementRect({ left: 24, top: 40, width: 185, height: 21 })
      );
    }
    for (const id of [
      "auto-overflow-clipped-password",
      "scroll-overflow-clipped-password"
    ]) {
      stubElementRect(
        document.querySelector(`#${id}`) as HTMLInputElement,
        elementRect({ left: 205, top: 40, width: 185, height: 21 })
      );
    }

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rounded-inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#math-inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#clamp-inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#circle-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#polygon-strip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#polygon-percent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#circle-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#ellipse-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-path-strip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#clip-path-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#clip-path-xywh-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#clip-path-offset-xywh-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#clip-path-offset-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#inset-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#legacy-strip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#legacy-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-strip-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-offset-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-offset-circle-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-translated-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-scaled-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-class-translated-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-class-scaled-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-polygon-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-use-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-defs-use-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-anchor-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-switch-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-metadata-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-nested-attr-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-nested-style-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-nested-group-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-nested-use-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-empty-group-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-line-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-empty-text-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-text-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-display-none-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-hidden-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-polygon-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-single-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-evenodd-polygon-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-evenodd-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-covered-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-evenodd-covered-path-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-clipped-password") as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector("#ancestor-strip-clipped-password") as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector("#auto-overflow-clipped-password") as HTMLInputElement).value
    ).toBe("");
    expect(
      (document.querySelector("#scroll-overflow-clipped-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#paint-contained-password") as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector("#strict-contained-password") as HTMLInputElement).value).toBe(
      ""
    );
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills password fields when a url clip path leaves the control visible", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="visibleClip"><rect x="0" y="0" width="200" height="30" /></clipPath>
          <clipPath id="nestedVisibleClip"><rect x="0" y="0" width="200" height="30" clip-path="url(#visibleClip)" /></clipPath>
        </svg>
        <input id="login-password" type="password" autocomplete="current-password" style="clip-path:url(#nestedVisibleClip)" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills password fields under a full object-bounding-box url clip path", () => {
    document.body.innerHTML = `
      <form>
        <svg width="0" height="0" aria-hidden="true">
          <clipPath id="visibleObjectClip" clipPathUnits="objectBoundingBox">
            <rect x="0" y="0" width="1" height="1" />
          </clipPath>
        </svg>
        <input id="login-password" type="password" autocomplete="current-password" style="clip-path:url(#visibleObjectClip)" />
      </form>
    `;
    stubElementRect(
      document.querySelector("#login-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills borderless password fields when the text paint remains visible", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:rgb(0,0,0);outline:0;box-shadow:none;text-shadow:none" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
  });

  it("fills borderless password fields when the field background contrasts the page", () => {
    document.body.innerHTML = `
      <form style="background:black;padding:8px">
        <input id="contrast-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:white;color:white;-webkit-text-fill-color:white;outline:0;box-shadow:none;text-shadow:none" />
      </form>
    `;

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#contrast-password") as HTMLInputElement).value).toBe("secret");
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
      actions: [
        {
          fieldOpid: "field-0",
          elementNumber: 0,
          fieldType: "password" as const,
          value: "secret"
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

  it("does not write secrets into fields removed during earlier fill events", () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const username = document.querySelector("#login-email") as HTMLInputElement;
    const password = document.querySelector("#login-password") as HTMLInputElement;
    let leakedPassword = "";

    password.addEventListener("input", () => {
      leakedPassword = password.value;
    });
    username.addEventListener("input", () => {
      password.remove();
    });

    fillLoginForm({ username: "alice@example.com", password: "secret" });

    expect(username.value).toBe("alice@example.com");
    expect(password.value).toBe("");
    expect(leakedPassword).toBe("");
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
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("已解锁")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "锁定" })).toBeInTheDocument();
    expect(screen.getByLabelText("搜索记录")).toBeInTheDocument();
    expect(screen.getByText("选中记录")).toBeInTheDocument();
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
    const managerButton = screen.getByRole("button", { name: "Open Manager" });
    const lockButton = screen.getByRole("button", { name: "Lock" });
    const siteBlock = siteValue.parentElement as HTMLElement;
    const actionBlock = status.parentElement as HTMLElement;

    expect(siteBlock.style.minWidth).toBe("0");
    expect(siteValue.style.overflow).toBe("hidden");
    expect(siteValue.style.textOverflow).toBe("ellipsis");
    expect(siteValue.style.whiteSpace).toBe("nowrap");
    expect(actionBlock.style.flexShrink).toBe("0");
    expect(managerButton).toBeInTheDocument();
    expect(lockButton).toBeInTheDocument();
  });

  it("opens extension settings from the locked popup", async () => {
    const openOptionsPage = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { openOptionsPage },
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(await screen.findByRole("button", { name: "Extension Settings" }));

    await waitFor(() => {
      expect(openOptionsPage).toHaveBeenCalled();
    });
  });

  it("falls back to the extension options tab when the popup options API fails", async () => {
    const openOptionsPage = vi.fn(async () => {
      throw new Error("options page did not open");
    });
    const create = vi.fn(async () => undefined);
    const getURL = vi.fn((path: string) => `chrome-extension://id/${path}`);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { openOptionsPage, getURL },
      tabs: {
        create,
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(await screen.findByRole("button", { name: "Extension Settings" }));

    await waitFor(() => {
      expect(create).toHaveBeenCalledWith({
        url: "chrome-extension://id/options.html"
      });
    });
  });

  it("renders popup site candidates search and selected record details together", async () => {
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
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      },
      {
        id: "entry-2",
        title: "Fallback Account",
        username: "backup@example.com",
        url: "https://example.com"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice@example.com",
      password: "secret-123",
      url: "https://example.com/login",
      notes: "",
      totp: "123456"
    } as any);

    const { PopupShell } = await import("../popupShell");

    const { container } = render(createElement(PopupShell));

    expect(await screen.findByText("Suggested for this site")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Search records")).toBeInTheDocument();
    expect(screen.getByText("Selected record")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Open Manager" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Fallback Account" })).not.toBeInTheDocument();
    expect((container.firstElementChild as HTMLElement).style.width).toBe("460px");
    expect((container.firstElementChild as HTMLElement).style.maxHeight).toBe("600px");
    expect((container.firstElementChild as HTMLElement).style.overflowY).toBe("auto");

    fireEvent.change(screen.getByPlaceholderText("Search records"), {
      target: { value: "Fallback" }
    });

    expect(await screen.findByRole("button", { name: "Fallback Account" })).toBeInTheDocument();
  });

  it("copies username password and totp when the field itself is clicked", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const writeText = vi.fn().mockResolvedValue(undefined);

    Object.assign(navigator, {
      clipboard: { writeText }
    });

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
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice@example.com",
      password: "secret-123",
      url: "https://example.com/login",
      notes: "",
      totp: "123456"
    } as any);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Copy username alice@example.com"
      })
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Copy password"
      })
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Copy TOTP 123456"
      })
    );

    expect(writeText).toHaveBeenCalledWith("alice@example.com");
    expect(writeText).toHaveBeenCalledWith("secret-123");
    expect(writeText).toHaveBeenCalledWith("123456");
  });

  it("masks the password until the reveal toggle is pressed", async () => {
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
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice@example.com",
      password: "secret-123",
      url: "https://example.com/login",
      notes: "",
      totp: "123456"
    } as any);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("••••••••••")).toBeInTheDocument();
    expect(screen.queryByText("secret-123")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show password" }));

    expect(await screen.findByText("secret-123")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Hide password" })).toBeInTheDocument();
  });

  it("enables quick unlock during the first popup password unlock when the extension preference is on", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false,
                quickUnlockEnabled: true
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.enableQuickUnlockForCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Personal")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: ""
      });
      expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
    });
  });

  it("does not provision quick unlock after popup unlock when biometric unlock is unsupported", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false,
                quickUnlockEnabled: true
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.enableQuickUnlockForCurrentVault.mockRejectedValue(
      new Error("biometric unlock is not supported")
    );
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Personal")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    expect(await screen.findByText("Unlocked")).toBeInTheDocument();
    expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
    expect(screen.queryByText("Failed to update quick unlock")).not.toBeInTheDocument();
  });

  it("enables quick unlock during the first popup key-file-only unlock when the extension preference is on", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false,
                quickUnlockEnabled: true
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.enableQuickUnlockForCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Personal")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Key File Path"), {
      target: { value: "/tmp/demo.keyx" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "",
        keyFilePath: "/tmp/demo.keyx"
      });
      expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
    });
  });

  it("enables quick unlock when the popup unlocks before recent vaults finish loading", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false,
                quickUnlockEnabled: true
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

    const slowVaults = createDeferred<
      Array<{
        vaultRefId: string;
        displayName: string;
        sourceKind: string;
        sourceSummary: string;
        lastUsedAt: number;
        availability: string;
        supportsQuickUnlock: boolean;
        isCurrent: boolean;
      }>
    >();
    const loadedVaults = [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ];

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults
      .mockReturnValueOnce(slowVaults.promise)
      .mockResolvedValue(loadedVaults);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.enableQuickUnlockForCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByLabelText("Master Password")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
    });

    slowVaults.resolve(loadedVaults);
  });

  it("uses the saved quick unlock preference when unlocking before popup settings finish loading", async () => {
    const storageCallbacks: Array<(items: Record<string, unknown>) => void> = [];
    const savedSettings = {
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 0,
      clearClipboardSeconds: 30,
      passkeyProviderEnabled: false,
      quickUnlockEnabled: true
    };
    const resolveSavedSettings = () => {
      while (storageCallbacks.length > 0) {
        storageCallbacks.shift()?.({
          vaultkernExtensionSettings: savedSettings
        });
      }
    };
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) => {
            storageCallbacks.push(callback);
          }),
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.enableQuickUnlockForCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByLabelText("Master Password")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(storageCallbacks.length).toBeGreaterThan(0);
    });
    resolveSavedSettings();

    await waitFor(() => {
      resolveSavedSettings();
      expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
    });
  });

  it("keeps the popup unlocked when quick unlock vault refresh fails after unlock", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((_key, callback) =>
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 0,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false,
                quickUnlockEnabled: true
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
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new Error("recent vault refresh failed"));
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByLabelText("Master Password")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledTimes(1);
    });

    expect(await screen.findByText("Unlocked")).toBeInTheDocument();
    expect(screen.queryByText("Failed to unlock vault")).not.toBeInTheDocument();
  });

  it("loads fill candidates for the active tab and fills the selected entry", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const sendMessage = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        sendMessage
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
      expect(sendMessage).toHaveBeenCalledWith(7, {
        type: "fill_entry_detail",
        username: "alice",
        password: "secret-123",
        totp: "123456"
      });
      const message = sendMessage.mock.calls[0]?.[1] as { newPassword?: string };
      expect(message.newPassword).toBeUndefined();
    });
  });

  it("saves a pending login submission as a new entry after user confirmation", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "captured-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const saveButton = await screen.findByRole("button", {
      name: "Save Login"
    });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(runtimeClientMocks.listGroups).toHaveBeenCalledWith("vault-1");
      expect(runtimeClientMocks.createEntry).toHaveBeenCalledWith("vault-1", {
        parentGroupId: "group-root",
        title: "example.com",
        username: "alice",
        password: "captured-secret",
        url: "https://example.com/login",
        notes: "",
        totpUri: null,
        customFields: []
      });
      expect(runtimeClientMocks.saveVault).toHaveBeenCalledWith("vault-1");
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
  });

  it("saves a save-only registration submission as new even when the username matches", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/signup"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/signup",
            username: "alice",
            password: "new-registration-secret",
            saveOnly: true,
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Existing",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Existing",
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const saveButton = await screen.findByRole("button", {
      name: "Save Login"
    });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(runtimeClientMocks.createEntry).toHaveBeenCalledWith("vault-1", {
        parentGroupId: "group-root",
        title: "example.com",
        username: "alice",
        password: "new-registration-secret",
        url: "https://example.com/signup",
        notes: "",
        totpUri: null,
        customFields: []
      });
      expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalled();
      expect(runtimeClientMocks.saveVault).toHaveBeenCalledWith("vault-1");
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
  });

  it("updates an existing entry from a pending changed password after user confirmation", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "old-secret",
            newPassword: "new-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login",
      notes: "keep me",
      totpUri: null,
      customFields: []
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const updateButton = await screen.findByRole("button", {
      name: "Update Password"
    });
    fireEvent.click(updateButton);

    await waitFor(() => {
      expect(runtimeClientMocks.updateEntryFields).toHaveBeenCalledWith("vault-1", "entry-1", {
        title: "Example",
        username: "alice",
        password: "new-secret",
        url: "https://example.com/login",
        notes: "keep me",
        totpUri: null,
        customFields: []
      });
      expect(runtimeClientMocks.saveVault).toHaveBeenCalledWith("vault-1");
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
  });

  it("saves a pending login as new when the submitted username does not match candidates", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login?reset_token=secret#step",
            username: "bob",
            password: "captured-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Alice",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const saveButton = await screen.findByRole("button", {
      name: "Save Login"
    });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(runtimeClientMocks.createEntry).toHaveBeenCalledWith("vault-1", {
        parentGroupId: "group-root",
        title: "example.com",
        username: "bob",
        password: "captured-secret",
        url: "https://example.com/login",
        notes: "",
        totpUri: null,
        customFields: []
      });
      expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalled();
    });
  });

  it("does not show a save prompt when pending candidate lookup fails", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "captured-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
    runtimeClientMocks.findFillCandidates.mockRejectedValue(new Error("lookup failed"));

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await waitFor(() => {
      expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
        "vault-1",
        "https://example.com/login"
      );
    });
    expect(screen.queryByRole("button", { name: "Save Login" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Update Password" })).not.toBeInTheDocument();
  });

  it("does not update when multiple candidates share the submitted username", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "captured-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Alice A",
        username: "alice",
        url: "https://example.com/login"
      },
      {
        id: "entry-2",
        title: "Alice B",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await waitFor(() => {
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
    expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Update Password" })).not.toBeInTheDocument();
  });

  it("matches pending password updates by the submitted url instead of the active tab", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://other.example/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "old-secret",
            newPassword: "new-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
    runtimeClientMocks.findFillCandidates.mockImplementation(
      async (_vaultId: string, url: string) => {
        if (url === "https://other.example/login") {
          return [
            {
              id: "entry-other",
              title: "Other Site",
              username: "alice",
              url
            }
          ];
        }
        if (url === "https://example.com/login") {
          return [
            {
              id: "entry-pending",
              title: "Submitted Site",
              username: "alice",
              url
            }
          ];
        }
        return [];
      }
    );
    runtimeClientMocks.getEntryDetail.mockImplementation(async (_vaultId, entryId) => ({
      type: "entry_detail",
      id: entryId,
      title: entryId === "entry-pending" ? "Submitted Site" : "Other Site",
      username: "alice",
      password: "old-secret",
      url:
        entryId === "entry-pending"
          ? "https://example.com/login"
          : "https://other.example/login",
      notes: "keep me",
      totpUri: null,
      customFields: []
    }));

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const updateButton = await screen.findByRole("button", {
      name: "Update Password"
    });
    fireEvent.click(updateButton);

    await waitFor(() => {
      expect(runtimeClientMocks.findFillCandidates).toHaveBeenCalledWith(
        "vault-1",
        "https://example.com/login"
      );
      expect(runtimeClientMocks.updateEntryFields).toHaveBeenCalledWith(
        "vault-1",
        "entry-pending",
        {
          title: "Submitted Site",
          username: "alice",
          password: "new-secret",
          url: "https://example.com/login",
          notes: "keep me",
          totpUri: null,
          customFields: []
        }
      );
      expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalledWith(
        "vault-1",
        "entry-other",
        expect.anything()
      );
    });
  });

  it("clears a consumed pending submission when the saved password already matches", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "saved-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "saved-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await waitFor(() => {
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
    expect(screen.queryByRole("button", { name: "Update Password" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save Login" })).not.toBeInTheDocument();
  });

  it("does not update an arbitrary candidate when a changed-password submission has no username", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "",
            password: "old-secret",
            newPassword: "new-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-alice",
        title: "Alice",
        username: "alice",
        url: "https://example.com/login"
      },
      {
        id: "entry-bob",
        title: "Bob",
        username: "bob",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-alice",
      title: "Alice",
      username: "alice",
      password: "old-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await waitFor(() => {
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
    expect(screen.queryByRole("button", { name: "Update Password" })).not.toBeInTheDocument();
    expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalled();
  });

  it("does not offer a changed-password update when the current password does not match", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "mistyped-old-secret",
            newPassword: "new-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "real-old-secret",
      url: "https://example.com/login",
      notes: "",
      totpUri: null,
      customFields: []
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await waitFor(() => {
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
    expect(screen.queryByRole("button", { name: "Update Password" })).not.toBeInTheDocument();
    expect(runtimeClientMocks.updateEntryFields).not.toHaveBeenCalled();
  });

  it("does not create duplicate entries when retrying after save fails", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const runtimeSendMessage = vi.fn(async (message: unknown) => {
      if (
        typeof message === "object" &&
        message !== null &&
        (message as { type?: unknown }).type === "vaultkern_autofill_pending_request"
      ) {
        return {
          pending: {
            url: "https://example.com/login",
            username: "alice",
            password: "captured-secret",
            submittedAt: 1710000000000
          }
        };
      }
      return { ok: true };
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: runtimeSendMessage
      },
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
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);
    runtimeClientMocks.saveVault
      .mockRejectedValueOnce(new Error("disk busy"))
      .mockResolvedValueOnce({
        type: "save_vault_result",
        status: "saved"
      });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const saveButton = await screen.findByRole("button", {
      name: "Save Login"
    });
    fireEvent.click(saveButton);
    expect(await screen.findByRole("alert")).toHaveTextContent("disk busy");

    fireEvent.click(screen.getByRole("button", { name: "Save Login" }));

    await waitFor(() => {
      expect(runtimeClientMocks.saveVault).toHaveBeenCalledTimes(2);
      expect(runtimeSendMessage).toHaveBeenCalledWith(expect.objectContaining({
        type: "vaultkern_autofill_pending_clear"
      }));
    });
    expect(runtimeClientMocks.createEntry).toHaveBeenCalledTimes(1);
  });

  it("opens the full manager in a dedicated extension page", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const create = vi.fn(async () => undefined);
    const getURL = vi.fn((path: string) => `chrome-extension://test-id/${path}`);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { getURL },
      tabs: {
        query,
        create,
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "Example Account",
      username: "alice@example.com",
      password: "secret-123",
      url: "https://example.com/login",
      notes: ""
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(await screen.findByRole("button", { name: "Open Manager" }));

    await waitFor(() => {
      expect(getURL).toHaveBeenCalledWith("manager.html");
      expect(create).toHaveBeenCalledWith({
        url: "chrome-extension://test-id/manager.html"
      });
    });
  });

  it("shows the manager entry in the unlocked popup even when no record is selected", async () => {
    const create = vi.fn(async () => undefined);
    const getURL = vi.fn((path: string) => `chrome-extension://test-id/${path}`);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { getURL },
      tabs: {
        query: vi.fn(async () => [
          {
            id: 7,
            url: "https://example.com/login"
          }
        ]),
        create,
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

    fireEvent.click(await screen.findByRole("button", { name: "Open Manager" }));

    await waitFor(() => {
      expect(getURL).toHaveBeenCalledWith("manager.html");
      expect(create).toHaveBeenCalledWith({
        url: "chrome-extension://test-id/manager.html"
      });
    });
  });

  it("collapses popup search results after five records until more is requested", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
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
    runtimeClientMocks.listEntries.mockResolvedValue(
      Array.from({ length: 7 }, (_, index) => ({
        id: `entry-${index + 1}`,
        title: `Search Account ${index + 1}`,
        username: `user-${index + 1}`,
        url: `https://example.com/${index + 1}`
      }))
    );
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByPlaceholderText("Search records"), {
      target: { value: "Search Account" }
    });

    expect(await screen.findByRole("button", { name: "Search Account 1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Search Account 5" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Search Account 6" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show 2 more" }));

    expect(await screen.findByRole("button", { name: "Search Account 7" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show less" }));

    expect(screen.queryByRole("button", { name: "Search Account 6" })).not.toBeInTheDocument();
  });

  it("shows recent vaults in the locked popup and unlocks the selected current vault", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-2"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: false
      },
      {
        vaultRefId: "vault-ref-2",
        displayName: "Work",
        sourceKind: "local",
        sourceSummary: "work.kdbx",
        lastUsedAt: 1776500010,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.setCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Work")).toBeInTheDocument();
    expect(screen.queryByLabelText("Vault Path")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Personal/ }));
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.change(screen.getByLabelText("Key File Path"), {
      target: { value: "/tmp/demo.keyx" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.setCurrentVault).toHaveBeenCalledWith("vault-ref-1");
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: "/tmp/demo.keyx"
      });
    });
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

  it("unlocks the locked popup with Windows Hello when quick unlock is enabled", async () => {
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
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: true,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.unlockCurrentVaultWithQuickUnlock.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Personal")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Unlock with Windows Hello" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVaultWithQuickUnlock).toHaveBeenCalledTimes(1);
    });
    expect(await screen.findByText("Select a record to inspect fields.")).toBeInTheDocument();
  });

  it("notifies the background page after unlocking for a WebAuthn request", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=12&relyingParty=example.com&origin=https%3A%2F%2Fexample.com"
    );
    const sendMessage = vi.fn(async () => undefined);
    Object.defineProperty(window, "close", {
      configurable: true,
      value: vi.fn()
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
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_unlock_complete",
        requestId: 12,
        origin: "https://example.com",
        relyingParty: "example.com",
        method: "master_password",
        password: "demo-password"
      });
    });
  });

  it("notifies the background page that a WebAuthn unlock used quick unlock", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=14&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-14"
    );
    const sendMessage = vi.fn(async () => undefined);
    Object.defineProperty(window, "close", {
      configurable: true,
      value: vi.fn()
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
      unlocked: false,
      activeVaultId: null,
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
    runtimeClientMocks.unlockCurrentVaultWithQuickUnlock.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(
      await screen.findByRole("button", { name: "Unlock with Windows Hello" })
    );

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_unlock_complete",
        requestId: 14,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-14",
        method: "quick_unlock"
      });
    });
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

  it("does not notify WebAuthn waiters after unlocking in the regular popup", async () => {
    window.history.replaceState(null, "", "/popup.html");
    const sendMessage = vi.fn(async () => undefined);
    Object.defineProperty(window, "close", {
      configurable: true,
      value: vi.fn()
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
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(screen.queryByLabelText("Master Password")).not.toBeInTheDocument();
    });
    expect(sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "vaultkern_unlock_complete"
      })
    );
    expect(window.close).not.toHaveBeenCalled();
  });

  it("closes the temporary WebAuthn unlock window after unlocking", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=24&relyingParty=example.com&origin=https%3A%2F%2Fexample.com"
    );
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage: vi.fn(async () => undefined)
      },
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
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(closeWindow).toHaveBeenCalledTimes(1);
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

  it("hides manager access while verifying a WebAuthn request", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=verify&requestId=45&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-45"
    );
    const sendMessage = vi.fn(async () => ({ ok: true }));
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

    expect(await screen.findByText("Verify passkey request")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Open Manager" })
    ).not.toBeInTheDocument();
    expect(runtimeClientMocks.listEntries).not.toHaveBeenCalled();
    expect(runtimeClientMocks.findFillCandidates).not.toHaveBeenCalled();
    expect(runtimeClientMocks.getEntryDetail).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_user_verification_complete",
        requestId: 45,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-45",
        method: "master_password",
        password: "demo-password"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
  });

  it("auto verifies the WebAuthn prompt with Windows Hello when quick unlock is enabled", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=verify&requestId=46&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-46"
    );
    const sendMessage = vi.fn(async () => ({ ok: true }));
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

    expect(await screen.findByText("Verify passkey request")).toBeInTheDocument();
    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_user_verification_complete",
        requestId: 46,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-46",
        method: "quick_unlock"
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

  it("auto unlocks the WebAuthn prompt with Windows Hello when quick unlock is enabled", async () => {
    window.history.replaceState(
      null,
      "",
      "/popup.html?webauthn=unlock&requestId=24&relyingParty=example.com&origin=https%3A%2F%2Fexample.com"
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
      unlocked: false,
      activeVaultId: null,
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
    const quickUnlock = createDeferred<{
      unlocked: boolean;
      activeVaultId: string | null;
      currentVaultRefId: string | null;
      supportsBiometricUnlock: boolean;
    }>();
    runtimeClientMocks.unlockCurrentVaultWithQuickUnlock.mockReturnValue(
      quickUnlock.promise
    );
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(await screen.findByText("Passkey request waiting")).toBeInTheDocument();
    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVaultWithQuickUnlock).toHaveBeenCalledTimes(1);
    });
    quickUnlock.resolve({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_unlock_complete",
        requestId: 24,
        origin: "https://example.com",
        relyingParty: "example.com",
        method: "quick_unlock"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
  });

  it("waits for on-demand preload when unlocking before recent vaults finish loading", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    const recentVaults = createDeferred<[]>();
    const preload = createDeferred<{
      unlocked: boolean;
      activeVaultId: string | null;
      currentVaultRefId: string | null;
    }>();

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockReturnValue(recentVaults.promise);
    runtimeClientMocks.preloadCurrentVault.mockReturnValue(preload.promise);
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    const passwordField = await screen.findByLabelText("Master Password");
    expect(passwordField).toBeEnabled();
    expect(screen.getByText("Loading...")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Manage vaults" })).toBeInTheDocument();
    expect(runtimeClientMocks.getSessionState).toHaveBeenCalledTimes(1);
    expect(runtimeClientMocks.preloadCurrentVault).not.toHaveBeenCalled();

    fireEvent.change(passwordField, {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    expect(await screen.findByRole("button", { name: "Unlocking..." })).toBeDisabled();
    expect(runtimeClientMocks.preloadCurrentVault).toHaveBeenCalledTimes(1);
    expect(runtimeClientMocks.unlockCurrentVault).not.toHaveBeenCalled();

    preload.resolve({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: ""
      });
    });
  });

  it("starts preloading after local recent vaults have loaded", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    const recentVaults = createDeferred<
      Array<{
        vaultRefId: string;
        displayName: string;
        sourceKind: "local";
        sourceSummary: string;
        lastUsedAt: number;
        availability: "ready";
        supportsQuickUnlock: boolean;
        isCurrent: boolean;
      }>
    >();

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockReturnValue(recentVaults.promise);
    runtimeClientMocks.preloadCurrentVault.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await screen.findByLabelText("Master Password");
    expect(runtimeClientMocks.preloadCurrentVault).not.toHaveBeenCalled();

    recentVaults.resolve([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);

    await waitFor(() => {
      expect(runtimeClientMocks.preloadCurrentVault).toHaveBeenCalledTimes(1);
    });
  });

  it("surfaces preload failure and retries the unlock request on the next click", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    const preload = createDeferred<{
      unlocked: boolean;
      activeVaultId: string | null;
      currentVaultRefId: string | null;
    }>();

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "onedrive",
        sourceSummary: "OneDrive / Personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.preloadCurrentVault.mockReturnValue(preload.promise);
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    preload.reject(new Error("native messaging timed out"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "native messaging timed out"
    );
    expect(runtimeClientMocks.unlockCurrentVault).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: ""
      });
    });
  });

  it("shows progress while the locked popup is unlocking", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    const unlock = createDeferred<{
      unlocked: boolean;
      activeVaultId: string | null;
      currentVaultRefId: string | null;
    }>();

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.unlockCurrentVault.mockReturnValue(unlock.promise);
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    expect(await screen.findByRole("button", { name: "Unlocking..." })).toBeDisabled();
    expect(screen.getByLabelText("Master Password")).toBeDisabled();
    expect(screen.getByLabelText("Key File Path")).toBeDisabled();

    unlock.resolve({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: ""
      });
    });
  });

  it("treats Enter in the popup master password field as unlock", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
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
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await screen.findByText("Work");
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.keyDown(screen.getByLabelText("Master Password"), {
      key: "Enter",
      code: "Enter"
    });

    await waitFor(() => {
      expect(runtimeClientMocks.unlockCurrentVault).toHaveBeenCalledWith({
        password: "demo-password",
        keyFilePath: ""
      });
    });
  });

  it("opens the manager when there are no recent vaults", async () => {
    const getURL = vi.fn((path: string) => `chrome-extension://test-id/${path}`);
    const create = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { getURL },
      tabs: {
        query: vi.fn(async () => []),
        create,
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

    fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));

    expect(getURL).toHaveBeenCalledWith("manager.html");
    expect(create).toHaveBeenCalledWith({
      url: "chrome-extension://test-id/manager.html"
    });
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

  it("keeps search results available when site candidate lookup fails", async () => {
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
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      },
      {
        id: "entry-2",
        title: "Manual Fallback",
        username: "backup@example.com",
        url: "https://backup.example.com"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockRejectedValue(
      new Error("candidate lookup failed")
    );
    runtimeClientMocks.getEntryDetail.mockResolvedValue({
      type: "entry_detail",
      id: "entry-2",
      title: "Manual Fallback",
      username: "backup@example.com",
      password: "secret-456",
      url: "https://backup.example.com",
      notes: ""
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    expect(
      await screen.findByRole("alert", { name: "" })
    ).toHaveTextContent("candidate lookup failed");

    fireEvent.change(screen.getByPlaceholderText("Search records"), {
      target: { value: "manual" }
    });

    const [searchResult] = await screen.findAllByText("Manual Fallback");
    fireEvent.click(searchResult.closest("button")!);

    expect(await screen.findByText("Selected record")).toBeInTheDocument();
    expect(screen.getAllByText("backup@example.com")).toHaveLength(2);
  });

  it("locks the popup session and returns to the unlock form", async () => {
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
    runtimeClientMocks.listEntries.mockResolvedValue([
      {
        id: "entry-1",
        title: "Example Account",
        username: "alice@example.com",
        url: "https://example.com/login"
      }
    ]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);
    runtimeClientMocks.lockSession.mockResolvedValue({
      unlocked: false,
      activeVaultId: null
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.click(await screen.findByRole("button", { name: "Lock" }));

    await waitFor(() => {
      expect(runtimeClientMocks.lockSession).toHaveBeenCalledTimes(1);
      expect(screen.getByRole("button", { name: "Unlock Vault" })).toBeInTheDocument();
    });
  });

  it("clears popup unlock secrets after a successful unlock", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local",
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.unlockCurrentVault.mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listEntries.mockResolvedValue([]);
    runtimeClientMocks.findFillCandidates.mockResolvedValue([]);
    runtimeClientMocks.lockSession.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    fireEvent.change(await screen.findByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.change(screen.getByLabelText("Key File Path"), {
      target: { value: "/tmp/demo.keyx" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    await screen.findByRole("button", { name: "Lock" });
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Unlock Vault" })).toBeInTheDocument();
    });
    expect(screen.getByLabelText("Master Password")).toHaveValue("");
    expect(screen.getByLabelText("Key File Path")).toHaveValue("");
  });

  it("swallows tab message failure without surfacing a raw rejection", async () => {
    const query = vi.fn(async () => [
      {
        id: 7,
        url: "https://example.com/login"
      }
    ]);
    const sendMessage = vi.fn(async () => {
      throw new Error("tab unavailable");
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      tabs: {
        query,
        sendMessage
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

  it("shows native setup install help when the host is missing", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        id: "test-extension-id"
      },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Broken Vault",
        sourceKind: "local",
        sourceSummary: "broken.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.unlockCurrentVault.mockRejectedValue(
      Object.assign(new Error("Specified native messaging host not found."), {
        code: "native_host_missing"
      })
    );

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await screen.findByText("Broken Vault");
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    expect(await screen.findByText("Install the VaultKern native host")).toBeInTheDocument();
    expect(screen.getByText("Current extension ID: test-extension-id")).toBeInTheDocument();
    expect(screen.getByText(/VaultKernNativeSetup\.exe/)).toBeInTheDocument();
    expect(screen.getByText(/On Windows, run/).closest("li")).toHaveTextContent(
      "If the extension ID field is empty"
    );
    expect(screen.getByText(/On Windows, run/).closest("li")).toHaveTextContent(
      "Register / Repair for Chrome"
    );
    expect(
      screen.getByText(
        /HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com\.vaultkern\.runtime/
      )
    ).toBeInTheDocument();
    expect(screen.getByText("chrome://extensions")).toBeInTheDocument();
    expect(
      screen.getByText(/tools\/vaultkern-runtime\/scripts\/install_native_host\.sh/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com\.vaultkern\.runtime/
      )
    ).toBeInTheDocument();
  });

  it("keeps business errors as plain unlock failures without install help", async () => {
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        id: "test-extension-id"
      },
      tabs: {
        query: vi.fn(async () => []),
        sendMessage: vi.fn(async () => undefined)
      }
    };

    runtimeClientMocks.getSessionState.mockResolvedValue({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
    runtimeClientMocks.listRecentVaults.mockResolvedValue([
      {
        vaultRefId: "vault-ref-1",
        displayName: "Broken Vault",
        sourceKind: "local",
        sourceSummary: "broken.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]);
    runtimeClientMocks.unlockCurrentVault.mockRejectedValue(
      new Error("vault file not found")
    );

    const { PopupShell } = await import("../popupShell");

    render(createElement(PopupShell));

    await screen.findByText("Broken Vault");
    fireEvent.change(screen.getByLabelText("Master Password"), {
      target: { value: "demo-password" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("vault file not found");
    expect(
      screen.queryByText("Install the VaultKern native host")
    ).not.toBeInTheDocument();
  });
});

describe("content script fill message", () => {
  function allowSyntheticAutofillSubmitEvents() {
    (globalThis as typeof globalThis & {
      __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
    }).__vaultkernAllowSyntheticAutofillSubmitForTests = true;
  }

  it("fills the page when the content script receives entry detail", async () => {
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
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

  it("fills a TOTP field when the content script receives entry detail", async () => {
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
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
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
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

  it("fills only the visible username field for a username-first login step", async () => {
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
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
    ).toBe("alice");
  });

  it("fills only the password field when the message omits username", async () => {
    const addListener = vi.fn((listener: (message: unknown) => void) => {
      listener({
        type: "fill_entry_detail",
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

  it("does not report ordinary login submits before success is known", async () => {
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

    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not capture readonly ordinary login submits before success is known", async () => {
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

    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not capture hidden-username ordinary login submits before success is known", async () => {
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

    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not report a submitted form when page handlers cancel submit", async () => {
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

    await import("../contentScript");
    document.querySelector("form")?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true })
    );
    await Promise.resolve();

    expect(sendMessage).not.toHaveBeenCalled();
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
      </form>
    `;
    document.body.append(host);

    vi.resetModules();
    allowSyntheticAutofillSubmitEvents();
    await import("../contentScript");
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
      new Event("input", { bubbles: true, composed: true })
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
