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
        <input id="viewport-relative-password" type="password" autocomplete="current-password" style="position:relative;left:-100vw" />
        <input id="margin-y-password" type="password" autocomplete="current-password" style="display:block;margin-top:-500px" />
        <input id="viewport-margin-password" type="password" autocomplete="current-password" style="display:block;margin-left:-100vw" />
        <input id="mask-transparent-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent,transparent)" />
        <input id="mask-radial-password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(transparent, transparent)" />
        <input id="mask-radial-shape-password" type="password" autocomplete="current-password" style="mask-image:radial-gradient(circle, transparent, transparent)" />
        <input id="mask-conic-password" type="password" autocomplete="current-password" style="mask-image:conic-gradient(from 0deg, transparent, transparent)" />
        <input id="mask-color-space-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(in oklab, transparent, transparent)" />
        <input id="mask-luminance-black-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(black, black);mask-mode:luminance" />
        <input id="mask-stop-password" type="password" autocomplete="current-password" style="mask-image:linear-gradient(transparent 0 100%)" />
        <svg width="0" height="0" aria-hidden="true">
          <mask id="blackMask"><rect width="100%" height="100%" fill="black" /></mask>
        </svg>
        <input id="mask-url-password" type="password" autocomplete="current-password" style="mask:url(#blackMask)" />
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
          <filter id="floodAlphaZero"><feFlood flood-opacity="0" /></filter>
          <filter id="offsetSource"><feOffset dx="-9999" dy="0" /></filter>
        </svg>
        <input id="svg-filter-password" type="password" autocomplete="current-password" style="filter:url(#alphaZero)" />
        <input id="svg-filter-discrete-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroDiscrete)" />
        <input id="svg-filter-gamma-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroGamma)" />
        <input id="svg-filter-matrix-password" type="password" autocomplete="current-password" style="filter:url(#alphaZeroMatrix)" />
        <input id="svg-filter-flood-password" type="password" autocomplete="current-password" style="filter:url(#floodAlphaZero)" />
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
        <input id="rotate-x-password" type="password" autocomplete="current-password" style="rotate:x 90deg" />
        <input id="rotate-y-password" type="password" autocomplete="current-password" style="rotate:y 90deg" />
        <input id="backface-password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:rotateY(180deg)" />
        <input id="backface-matrix-password" type="password" autocomplete="current-password" style="backface-visibility:hidden;transform:matrix3d(-1,0,0,0,0,1,0,0,0,0,-1,0,0,0,0,1)" />
        <input id="paintless-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:transparent;-webkit-text-fill-color:transparent;outline:0;box-shadow:none;text-shadow:none" />
        <input id="font-zero-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;font-size:0;outline:0;box-shadow:none;text-shadow:none" />
        <input id="text-indent-password" type="password" autocomplete="current-password" style="appearance:none;-webkit-appearance:none;border:0;background:transparent;color:black;text-indent:-9999px;outline:0;box-shadow:none;text-shadow:none" />
        <input id="occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:88px;width:185px;height:21px" />
        <div id="occluding-cover" style="position:absolute;left:0;top:80px;width:260px;height:48px;background:white"></div>
        <input id="pointer-events-occluded-password" type="password" autocomplete="current-password" style="position:absolute;left:24px;top:172px;width:185px;height:21px" />
        <div id="pointer-events-cover" style="position:absolute;left:0;top:164px;width:260px;height:48px;background:white;pointer-events:none"></div>
        <input id="translated-password" type="password" autocomplete="current-password" style="translate:-9999px" />
        <input id="longhand-scaled-password" type="password" autocomplete="current-password" style="scale:0" />
        <input id="zoom-zero-password" type="password" autocomplete="current-password" style="zoom:0" />
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
    stubElementRect(
      loginPassword,
      elementRect({ left: 24, top: 140, width: 185, height: 21 })
    );
    Object.defineProperty(document, "elementFromPoint", {
      configurable: true,
      value: (x: number, y: number) => {
        if (x >= 24 && x <= 209 && y >= 88 && y <= 109) {
          return occludingCover;
        }
        if (x >= 24 && x <= 209 && y >= 172 && y <= 193) {
          return pointerEventsOccludedPassword;
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

    expect((document.querySelector("#parent-translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#parent-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rect-translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#positive-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#positive-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#percent-translate-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-translate-password") as HTMLInputElement).value).toBe("");
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
    expect((document.querySelector("#viewport-relative-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#margin-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#viewport-margin-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-transparent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-radial-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-radial-shape-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-conic-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-color-space-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-luminance-black-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-stop-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-url-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-zero-percent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-tiny-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-tiny-percent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#mask-position-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-discrete-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-gamma-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-matrix-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-flood-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#svg-filter-offset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#cumulative-opacity-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#cumulative-filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rotate-x-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rotate-y-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#backface-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#backface-matrix-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#paintless-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#font-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#text-indent-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#occluded-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#pointer-events-occluded-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#translated-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#longhand-scaled-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#zoom-zero-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#filter-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#scaled-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-scaled-password") as HTMLInputElement).value
    ).toBe("");
    expect((document.querySelector("#login-password") as HTMLInputElement).value).toBe("secret");
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
          <clipPath id="emptyGroupClip"><g></g></clipPath>
          <clipPath id="lineClip"><line x1="0" y1="0" x2="200" y2="0" /></clipPath>
          <clipPath id="emptyTextClip"><text></text></clipPath>
          <clipPath id="displayNoneRectClip"><rect style="display:none" width="200" height="30" /></clipPath>
          <clipPath id="hiddenRectClip"><rect style="visibility:hidden" width="200" height="30" /></clipPath>
          <clipPath id="evenOddPathClip"><path clip-rule="evenodd" d="M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
          <clipPath id="evenOddCoveredPathClip"><path clip-rule="evenodd" d="M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z" /></clipPath>
        </svg>
        <input id="inset-password" type="password" autocomplete="current-password" style="clip-path:inset(49%)" />
        <input id="rounded-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(49% round 2px)" />
        <input id="calc-inset-password" type="password" autocomplete="current-password" style="clip-path:inset(0 calc(100% - 4px) 0 0)" />
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
        <input id="url-empty-group-password" type="password" autocomplete="current-password" style="clip-path:url(#emptyGroupClip)" />
        <input id="url-line-password" type="password" autocomplete="current-password" style="clip-path:url(#lineClip)" />
        <input id="url-empty-text-password" type="password" autocomplete="current-password" style="clip-path:url(#emptyTextClip)" />
        <input id="url-display-none-password" type="password" autocomplete="current-password" style="clip-path:url(#displayNoneRectClip)" />
        <input id="url-hidden-rect-password" type="password" autocomplete="current-password" style="clip-path:url(#hiddenRectClip)" />
        <input id="url-evenodd-path-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddPathClip)" />
        <input id="css-evenodd-path-password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M0 0 L200 0 L200 30 L0 30 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <input id="url-evenodd-covered-path-password" type="password" autocomplete="current-password" style="clip-path:url(#evenOddCoveredPathClip)" />
        <input id="css-evenodd-covered-path-password" type="password" autocomplete="current-password" style='clip-path:path(evenodd, "M-10 -10 L210 -10 L210 40 L-10 40 Z M0 0 L200 0 L200 30 L0 30 Z")' />
        <div style="width:2px;height:2px;overflow:hidden">
          <input id="ancestor-clipped-password" type="password" autocomplete="current-password" />
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
    stubElementRect(
      document.querySelector("#polygon-percent-password") as HTMLInputElement,
      elementRect({ left: 24, top: 40, width: 185, height: 21 })
    );
    for (const id of [
      "url-offset-rect-password",
      "url-offset-circle-password",
      "url-translated-rect-password",
      "url-scaled-rect-password",
      "url-class-translated-rect-password",
      "url-class-scaled-rect-password",
      "url-evenodd-path-password",
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

    fillLoginForm({ password: "secret" });

    expect((document.querySelector("#inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#rounded-inset-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#calc-inset-password") as HTMLInputElement).value).toBe("");
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
    expect((document.querySelector("#url-empty-group-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-line-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-empty-text-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-display-none-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-hidden-rect-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-evenodd-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#url-evenodd-covered-path-password") as HTMLInputElement).value).toBe("");
    expect((document.querySelector("#css-evenodd-covered-path-password") as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector("#ancestor-clipped-password") as HTMLInputElement).value
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
        </svg>
        <input id="login-password" type="password" autocomplete="current-password" style="clip-path:url(#visibleClip)" />
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
