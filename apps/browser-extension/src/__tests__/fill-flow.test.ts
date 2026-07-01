import "@testing-library/jest-dom/vitest";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fillLoginForm } from "../contentScript";

const runtimeClientMocks = vi.hoisted(() => ({
  getSessionState: vi.fn(),
  listRecentVaults: vi.fn(),
  preloadCurrentVault: vi.fn(),
  addLocalVaultReference: vi.fn(),
  setCurrentVault: vi.fn(),
  openLocalVault: vi.fn(),
  lockSession: vi.fn(),
  unlockCurrentVault: vi.fn(),
  unlockCurrentVaultWithQuickUnlock: vi.fn(),
  unlockWithPassword: vi.fn(),
  listGroups: vi.fn(),
  listEntries: vi.fn(),
  getEntryDetail: vi.fn(),
  findFillCandidates: vi.fn()
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
        password: "secret-123"
      });
    });
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
        relyingParty: "example.com"
      });
    });
  });

  it("notifies the background page when a WebAuthn unlock popup mounts already unlocked", async () => {
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

    await waitFor(() => {
      expect(sendMessage).toHaveBeenCalledWith({
        type: "vaultkern_unlock_complete",
        requestId: 13,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-13"
      });
      expect(closeWindow).toHaveBeenCalledTimes(1);
    });
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
    expect(sendMessage).not.toHaveBeenCalled();
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
    const credentialOptions = encodeURIComponent(
      JSON.stringify([
        {
          credentialId: "Y3JlZGVudGlhbC0x",
          username: "alice@example.com",
          userHandle: "dXNlci0x"
        },
        {
          credentialId: "Y3JlZGVudGlhbC0y",
          username: "bob@example.com",
          userHandle: "dXNlci0y"
        }
      ])
    );
    window.history.replaceState(
      null,
      "",
      `/popup.html?webauthn=approve&requestId=43&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&credentialOptions=${credentialOptions}`
    );
    const sendMessage = vi.fn(async () => undefined);
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
        credentialId: "Y3JlZGVudGlhbC0y"
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
        relyingParty: "example.com"
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

    await import("../contentScript");

    expect(addListener).toHaveBeenCalledTimes(1);
    expect(
      (document.querySelector('input[name="username"]') as HTMLInputElement).value
    ).toBe("bob");
    expect(
      (document.querySelector('input[name="password"]') as HTMLInputElement).value
    ).toBe("root-secret");
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
      topOrigin: window.location.origin,
      relyingParty: "localhost",
      challenge: "cmVnaXN0ZXItMQ",
      allowCredentialIds: undefined,
      excludeCredentialIds: ["Y3JlZGVudGlhbC0x"],
      mediation: "conditional",
      observedAt: expect.any(Number)
    });
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
      topOrigin: "https://parent.example",
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
