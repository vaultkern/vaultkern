import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const runtimeClientMocks = vi.hoisted(() => ({
  getSessionState: vi.fn(),
  getQuickUnlockState: vi.fn(),
  initializeQuickUnlockPolicy: vi.fn(),
  setQuickUnlockPolicy: vi.fn(),
  listRecentVaults: vi.fn(),
  deleteRecentVault: vi.fn(),
  enableQuickUnlockForCurrentVault: vi.fn(),
  disableQuickUnlockForCurrentVault: vi.fn()
}));

function quickUnlockState(policyEnabled: boolean | null) {
  return {
    type: "quick_unlock_state" as const,
    policyEnabled,
    capability: "available" as const,
    recordState: policyEnabled ? ("setup_required" as const) : ("absent" as const),
    canQuickUnlock: false,
    requiresPassword: false,
    lastError: null
  };
}

vi.mock("@vaultkern/runtime-web-client", () => ({
  RuntimeClient: vi.fn(() => runtimeClientMocks)
}));

vi.mock("../runtimeBridge", () => ({
  extensionTransport: {}
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

function installChromeStorage(settings: Record<string, unknown>) {
  const set = vi.fn((_values, callback) => callback?.());

  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: vi.fn((_key, callback) =>
          callback({
            vaultkernExtensionSettings: settings
          })
        ),
        set
      }
    }
  };

  return { set };
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
  runtimeClientMocks.getQuickUnlockState.mockReset();
  runtimeClientMocks.initializeQuickUnlockPolicy.mockReset();
  runtimeClientMocks.setQuickUnlockPolicy.mockReset();
  runtimeClientMocks.listRecentVaults.mockReset();
  runtimeClientMocks.deleteRecentVault.mockReset();
  runtimeClientMocks.enableQuickUnlockForCurrentVault.mockReset();
  runtimeClientMocks.disableQuickUnlockForCurrentVault.mockReset();
  runtimeClientMocks.getQuickUnlockState.mockResolvedValue(quickUnlockState(null));
  runtimeClientMocks.initializeQuickUnlockPolicy.mockImplementation(async (enabled) =>
    quickUnlockState(enabled)
  );
  runtimeClientMocks.setQuickUnlockPolicy.mockImplementation(async (enabled) =>
    quickUnlockState(enabled)
  );
});

afterEach(() => {
  cleanup();
});

it("updates the runtime-owned off policy without waiting for vault data", async () => {
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
    expect(runtimeClientMocks.setQuickUnlockPolicy).toHaveBeenCalledWith(false);
  });

  slowVaults.resolve(loadedVaults);
});

it("does not run provider enrollment from options refreshes", async () => {
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
  runtimeClientMocks.enableQuickUnlockForCurrentVault.mockResolvedValue({
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: true
  });

  await renderOptionsPage();

  await screen.findByRole("checkbox", { name: "Quick Unlock" });
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
  const stateReadsBeforeFocus = runtimeClientMocks.getQuickUnlockState.mock.calls.length;

  window.dispatchEvent(new Event("focus"));

  await waitFor(() => {
    expect(runtimeClientMocks.getQuickUnlockState.mock.calls.length).toBeGreaterThan(
      stateReadsBeforeFocus
    );
  });
  expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("submits one runtime-owned quick unlock policy update from options", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });
  const update = createDeferred<ReturnType<typeof quickUnlockState>>();
  const recentVaults = [
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
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: true
  });
  runtimeClientMocks.listRecentVaults.mockImplementation(async () => recentVaults);
  runtimeClientMocks.setQuickUnlockPolicy.mockReturnValue(update.promise);

  await renderOptionsPage();

  const quickUnlock = await screen.findByRole("checkbox", { name: "Quick Unlock" });
  fireEvent.click(quickUnlock);
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(runtimeClientMocks.setQuickUnlockPolicy).toHaveBeenCalledWith(true);
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  expect(runtimeClientMocks.setQuickUnlockPolicy).toHaveBeenCalledTimes(1);

  recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: true };
  await act(async () => {
    update.resolve(quickUnlockState(true));
    await update.promise;
  });
  await waitFor(() => {
    expect(screen.queryByText("Saving...")).not.toBeInTheDocument();
  });
});

it("keeps options loading until runtime quick unlock state is known", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });

  const slowState = createDeferred<ReturnType<typeof quickUnlockState>>();

  runtimeClientMocks.getQuickUnlockState.mockReturnValue(slowState.promise);
  runtimeClientMocks.listRecentVaults.mockResolvedValue([]);

  await renderOptionsPage();

  expect(await screen.findByText("Loading...")).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: "Quick Unlock" })).not.toBeInTheDocument();

  slowState.resolve(quickUnlockState(false));
});

it("does not run legacy disable operations on options refreshes", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });

  runtimeClientMocks.getSessionState.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-2",
    supportsBiometricUnlock: true
  });
  runtimeClientMocks.listRecentVaults.mockResolvedValue([
    {
      vaultRefId: "vault-ref-2",
      displayName: "Work",
      sourceKind: "local",
      sourceSummary: "work.kdbx",
      lastUsedAt: 1776500010,
      availability: "ready",
      supportsQuickUnlock: true,
      isCurrent: true
    }
  ]);
  runtimeClientMocks.disableQuickUnlockForCurrentVault.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-2",
    supportsBiometricUnlock: true
  });

  await renderOptionsPage();

  await screen.findByRole("checkbox", { name: "Quick Unlock" });
  expect(runtimeClientMocks.disableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("applies the recent vault limit when options settings are saved", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });

  const recentVaults = [
    {
      vaultRefId: "vault-ref-1",
      displayName: "Personal",
      sourceKind: "local",
      sourceSummary: "personal.kdbx",
      lastUsedAt: 1776500020,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: true
    },
    {
      vaultRefId: "vault-ref-2",
      displayName: "Work",
      sourceKind: "local",
      sourceSummary: "work.kdbx",
      lastUsedAt: 1776500010,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: false
    },
    {
      vaultRefId: "vault-ref-3",
      displayName: "Archive",
      sourceKind: "local",
      sourceSummary: "archive.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: false
    }
  ];

  runtimeClientMocks.getSessionState.mockResolvedValue({
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: true
  });
  runtimeClientMocks.listRecentVaults.mockResolvedValue(recentVaults);
  runtimeClientMocks.deleteRecentVault.mockResolvedValue(recentVaults.slice(0, 2));

  await renderOptionsPage();

  const limitInput = await screen.findByLabelText("Recent Databases");
  fireEvent.change(limitInput, {
    target: { value: "2" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(runtimeClientMocks.deleteRecentVault).toHaveBeenCalledWith("vault-ref-3");
  });
});

it("preserves saved quick unlock when biometric support lookup fails", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });

  runtimeClientMocks.getQuickUnlockState.mockRejectedValue(
    new Error("native host unavailable")
  );
  runtimeClientMocks.listRecentVaults.mockResolvedValue([]);

  await renderOptionsPage();

  const quickUnlock = await screen.findByRole("checkbox", { name: "Quick Unlock" });
  expect(quickUnlock).toBeChecked();
  expect(quickUnlock).toBeDisabled();

  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(chromeStorage.set).toHaveBeenCalledWith(
      {
        vaultkernExtensionSettings: expect.objectContaining({
          quickUnlockEnabled: true
        })
      },
      expect.any(Function)
    );
  });
});

it("preserves enabled quick unlock without retrying setup while biometrics are unavailable", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });
  runtimeClientMocks.getSessionState.mockResolvedValue({
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: false
  });
  runtimeClientMocks.getQuickUnlockState.mockResolvedValue({
    ...quickUnlockState(true),
    capability: "temporarily_unavailable"
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

  await renderOptionsPage();

  const quickUnlock = await screen.findByRole("checkbox", { name: "Quick Unlock" });
  expect(quickUnlock).toBeChecked();
  expect(quickUnlock).not.toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(chromeStorage.set).toHaveBeenCalled();
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  expect(runtimeClientMocks.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("saves local options when native recent vault operations fail", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: false
  });
  const saveRecentVaults = createDeferred<
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

  runtimeClientMocks.getQuickUnlockState.mockRejectedValue(
    new Error("native host unavailable")
  );
  runtimeClientMocks.listRecentVaults
    .mockRejectedValueOnce(new Error("native host unavailable"))
    .mockReturnValueOnce(saveRecentVaults.promise);

  await renderOptionsPage();

  await screen.findByText("中文");
  await new Promise((resolve) => setTimeout(resolve, 0));
  fireEvent.click(screen.getByText("中文"));
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(chromeStorage.set).toHaveBeenCalled();
  });
  expect(runtimeClientMocks.listRecentVaults).toHaveBeenCalledTimes(2);

  saveRecentVaults.reject(new Error("native recent vault unavailable"));

  await waitFor(() => {
    expect(screen.queryByText("Saving...")).not.toBeInTheDocument();
  });

  expect(chromeStorage.set).toHaveBeenCalledWith(
    {
      vaultkernExtensionSettings: expect.objectContaining({
        language: "zh-CN"
      })
    },
    expect.any(Function)
  );
  expect(screen.getAllByRole("alert")).toHaveLength(1);
});
