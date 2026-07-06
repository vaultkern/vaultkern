import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const runtimeClientMocks = vi.hoisted(() => ({
  getSessionState: vi.fn(),
  listRecentVaults: vi.fn(),
  enableQuickUnlockForCurrentVault: vi.fn(),
  disableQuickUnlockForCurrentVault: vi.fn()
}));

vi.mock("@vaultkern/runtime-web-client", () => ({
  RuntimeClient: vi.fn(() => runtimeClientMocks)
}));

vi.mock("../runtimeBridge", () => ({
  extensionTransport: {}
}));

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });

  return { promise, resolve };
}

function installChromeStorage(settings: Record<string, unknown>) {
  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: vi.fn((_key, callback) =>
          callback({
            vaultkernExtensionSettings: settings
          })
        ),
        set: vi.fn((_values, callback) => callback?.())
      }
    }
  };
}

async function renderOptionsPage() {
  document.body.innerHTML = '<div id="root"></div>';
  await import("../options");
}

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = "";
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
  runtimeClientMocks.getSessionState.mockReset();
  runtimeClientMocks.listRecentVaults.mockReset();
  runtimeClientMocks.enableQuickUnlockForCurrentVault.mockReset();
  runtimeClientMocks.disableQuickUnlockForCurrentVault.mockReset();
});

afterEach(() => {
  cleanup();
});

it("syncs an off quick unlock preference after options vault data finishes loading", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });

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
      supportsQuickUnlock: true,
      isCurrent: true
    }
  ];

  runtimeClientMocks.getSessionState.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: true
  });
  runtimeClientMocks.listRecentVaults
    .mockReturnValueOnce(slowVaults.promise)
    .mockResolvedValue(loadedVaults);
  runtimeClientMocks.disableQuickUnlockForCurrentVault.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: true
  });

  await renderOptionsPage();

  const quickUnlock = await screen.findByRole("checkbox", { name: "Quick Unlock" });
  await waitFor(() => {
    expect(quickUnlock).toBeChecked();
  });
  fireEvent.click(quickUnlock);
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(runtimeClientMocks.disableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
  });

  slowVaults.resolve(loadedVaults);
});

it("retries options quick unlock setup after a locked current vault is unlocked", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });

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

  runtimeClientMocks.getSessionState
    .mockResolvedValueOnce({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })
    .mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });
  runtimeClientMocks.listRecentVaults.mockResolvedValue(loadedVaults);
  runtimeClientMocks.enableQuickUnlockForCurrentVault
    .mockRejectedValueOnce(new Error("current vault is locked"))
    .mockResolvedValue({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    });

  await renderOptionsPage();

  await waitFor(() => {
    expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
  });

  window.dispatchEvent(new Event("focus"));

  await waitFor(() => {
    expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(2);
  });
});

it("keeps options loading until biometric support is known", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });

  const slowSession = createDeferred<{
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
    supportsBiometricUnlock: boolean;
  }>();

  runtimeClientMocks.getSessionState.mockReturnValue(slowSession.promise);
  runtimeClientMocks.listRecentVaults.mockResolvedValue([]);

  await renderOptionsPage();

  expect(await screen.findByText("Loading...")).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: "Quick Unlock" })).not.toBeInTheDocument();

  slowSession.resolve({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: null,
    supportsBiometricUnlock: false
  });
});
