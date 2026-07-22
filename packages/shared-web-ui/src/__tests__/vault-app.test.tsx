import "@testing-library/jest-dom/vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
  waitFor
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type {
  DatabaseSettings,
  DatabaseSettingsCommitResult,
  DatabaseSettingsUpdate
} from "@vaultkern/runtime-web-client";
import { App, type RuntimeClientLike } from "../App";
import { DEFAULT_EXTENSION_SETTINGS } from "../extensionSettings";
import type { ExtensionSettings, ExtensionSettingsStore } from "../extensionSettings";
import { errorMessage } from "../error";
import { ManagerShell } from "../layout/ManagerShell";
import { ManagerTopBar } from "../layout/ManagerTopBar";
import { I18nProvider } from "../i18n";
import { EntryEditor } from "../screens/EntryEditor";
import { ExtensionSettingsPanel } from "../screens/ExtensionSettingsPanel";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });

  return { promise, resolve };
}

it("clears quick-unlock credentials as soon as enrollment takes ownership", async () => {
  const enrollment = createDeferred<void>();
  const onEnrollQuickUnlock = vi.fn(() => enrollment.promise);

  render(
    <I18nProvider language="en">
      <ExtensionSettingsPanel
        settings={{
          ...DEFAULT_EXTENSION_SETTINGS,
          quickUnlockEnabled: true
        }}
        saving={false}
        error={null}
        quickUnlockEnabled
        quickUnlockVaultUnlocked
        onEnrollQuickUnlock={onEnrollQuickUnlock}
        onSave={vi.fn()}
      />
    </I18nProvider>
  );

  fireEvent.change(screen.getByLabelText("Quick Unlock Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.change(screen.getByLabelText("Quick Unlock Key File Path"), {
    target: { value: "/tmp/demo.keyx" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Enable Windows Hello" }));

  expect(onEnrollQuickUnlock).toHaveBeenCalledWith({
    password: "demo-password",
    keyFilePath: "/tmp/demo.keyx"
  });
  expect(screen.getByLabelText("Quick Unlock Master Password")).toHaveValue("");
  expect(screen.getByLabelText("Quick Unlock Key File Path")).toHaveValue("");

  enrollment.resolve();
});

it("clears quick-unlock credentials when the resident session changes", async () => {
  const { rerender } = render(
    <I18nProvider language="en">
      <ExtensionSettingsPanel
        settings={{
          ...DEFAULT_EXTENSION_SETTINGS,
          quickUnlockEnabled: true
        }}
        saving={false}
        error={null}
        quickUnlockEnabled
        quickUnlockVaultUnlocked
        quickUnlockCredentialResetKey={0}
        onSave={vi.fn()}
      />
    </I18nProvider>
  );

  fireEvent.change(screen.getByLabelText("Quick Unlock Master Password"), {
    target: { value: "resident-secret" }
  });
  fireEvent.change(screen.getByLabelText("Quick Unlock Key File Path"), {
    target: { value: "C:\\keys\\resident.keyx" }
  });

  rerender(
    <I18nProvider language="en">
      <ExtensionSettingsPanel
        settings={{
          ...DEFAULT_EXTENSION_SETTINGS,
          quickUnlockEnabled: true
        }}
        saving={false}
        error={null}
        quickUnlockEnabled
        quickUnlockVaultUnlocked
        quickUnlockCredentialResetKey={1}
        onSave={vi.fn()}
      />
    </I18nProvider>
  );

  expect(screen.getByLabelText("Quick Unlock Master Password")).toHaveValue("");
  expect(screen.getByLabelText("Quick Unlock Key File Path")).toHaveValue("");
});

function committedDatabaseSettings(
  settings: DatabaseSettings,
  saveResult: DatabaseSettingsCommitResult["saveResult"] = {
    type: "save_vault_result",
    status: "saved"
  }
): DatabaseSettingsCommitResult {
  return {
    type: "database_settings_commit_result",
    settings,
    saveResult
  };
}

function createVaultSelectionMethods() {
  return {
    listRecentVaults: vi.fn(async () => []),
    addLocalVaultReference: vi.fn(),
    beginOneDriveLogin: vi.fn(),
    completePendingOneDriveLogin: vi.fn(),
    listOneDriveChildren: vi.fn(async () => []),
    addOneDriveVaultReference: vi.fn(),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn(),
    createEntry: vi.fn(),
    updateEntryFields: vi.fn(),
    deleteEntry: vi.fn(),
    saveVault: vi.fn(),
    setEntryPasskey: vi.fn(),
    clearEntryPasskey: vi.fn(),
    getEntryAttachmentContent: vi.fn(),
    addEntryAttachment: vi.fn(),
    updateEntryAttachmentMetadata: vi.fn(),
    replaceEntryAttachmentContent: vi.fn(),
    deleteEntryAttachment: vi.fn(),
    retryVaultSourceSync: vi.fn(),
    getDatabaseSettings: vi.fn(async (): Promise<DatabaseSettings> => ({
      type: "database_settings" as const,
      metadata: { name: "The Archive", description: null, defaultUsername: null },
      publicMetadata: { displayName: null, color: null, icon: null },
      history: { maxItemsPerEntry: null, maxTotalSizeBytes: null },
      recycleBin: { enabled: true },
      encryption: {
        compression: "gzip",
        cipher: "aes256",
        kdf: {
          algorithm: "argon2id",
          transformRounds: null,
          iterations: 2,
          memoryKib: 65536,
          parallelism: 1
        }
      },
      autosaveDelaySeconds: null,
      hasPassword: true
    })),
    updateDatabaseSettings: vi.fn(),
    listEntryHistory: vi.fn(async () => []),
    getEntryHistoryDetail: vi.fn(),
    deleteRecentVault: vi.fn(async () => []),
    deleteRecentVaultIfNotCurrent: vi.fn(async () => []),
    setCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    openLocalVault: vi.fn(),
    unlockCurrentVaultWithPassword: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    unlockCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    enableQuickUnlockForCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    unlockCurrentVaultWithQuickUnlock: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    disableQuickUnlockForCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    unlockWithPassword: vi.fn(),
    unlockVault: vi.fn(),
    lockSession: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }))
  };
}

it("does not let a late session reset overwrite navigation from the rendered session", async () => {
  const session = createDeferred<{
    unlocked: boolean;
    activeVaultId: string;
    currentVaultRefId: string;
  }>();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(() => session.promise)
  };
  let navigationTriggered = false;
  const observer = new MutationObserver(() => {
    const button = [...document.querySelectorAll("button")].find(
      (candidate) => candidate.textContent === "Database Settings"
    );
    if (!button) {
      return;
    }
    observer.disconnect();
    navigationTriggered = true;
    fireEvent.click(button);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  try {
    render(<App client={client as RuntimeClientLike} />);
    session.resolve({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    await waitFor(() => expect(navigationTriggered).toBe(true));
    expect(await screen.findByLabelText("Database Name")).toBeInTheDocument();
  } finally {
    observer.disconnect();
  }
});

function createSettingsStore(settings: Partial<ExtensionSettings> = {}): ExtensionSettingsStore {
  let current: ExtensionSettings = { ...DEFAULT_EXTENSION_SETTINGS, ...settings };
  return {
    load: vi.fn(async () => current),
    save: vi.fn(async (next) => {
      current = next;
    })
  };
}

it("leaves startup and unlock reconciliation to the native runtime owner", async () => {
  const settingsStore = createSettingsStore({ windowsPasskeyProviderEnabled: true });
  settingsStore.nativeReconciliationOwned = true;
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listRecentVaults: vi.fn(async () => recentVaults),
    unlockCurrentVault: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(settingsStore.load).toHaveBeenCalled();

  fireEvent.change(screen.getByLabelText("Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

  await screen.findByText("Archive");
  expect(client.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("loads desired settings even when startup session loading fails", async () => {
  const settingsStore = createSettingsStore({ windowsPasskeyProviderEnabled: true });
  settingsStore.nativeReconciliationOwned = true;
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => {
      throw new Error("simulated session load failure");
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("simulated session load failure")).toBeInTheDocument();
  expect(settingsStore.load).toHaveBeenCalled();
});

it("does not duplicate quick-unlock side effects owned by a platform reconciler", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: false });
  settingsStore.nativeReconciliationOwned = true;
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local" as const,
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready" as const,
        supportsQuickUnlock: true,
        isCurrent: true
      }
    ])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(client.disableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("does not enqueue stale quick-unlock enrollment after desired state is disabled", async () => {
  let desired = {
    ...DEFAULT_EXTENSION_SETTINGS,
    quickUnlockEnabled: true
  };
  let blockNextLoad = false;
  const blockedLoad = createDeferred<ExtensionSettings>();
  const queueQuickUnlockEnrollment = vi.fn(async () => undefined);
  const settingsStore: ExtensionSettingsStore = {
    surface: "windows",
    nativeReconciliationOwned: true,
    queueQuickUnlockEnrollment,
    load: vi.fn(() =>
      blockNextLoad ? blockedLoad.promise : Promise.resolve(desired)
    ),
    save: vi.fn(async (next) => {
      desired = next;
    })
  };
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local" as const,
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready" as const,
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.change(
    await screen.findByLabelText("Quick Unlock Master Password"),
    { target: { value: "demo-password" } }
  );
  blockNextLoad = true;
  fireEvent.click(screen.getByRole("button", { name: "Enable Windows Hello" }));
  await waitFor(() => expect(settingsStore.load).toHaveBeenCalled());

  desired = { ...desired, quickUnlockEnabled: false };
  blockedLoad.resolve(desired);

  await act(async () => {
    await blockedLoad.promise;
    await Promise.resolve();
  });
  expect(queueQuickUnlockEnrollment).not.toHaveBeenCalled();
});

it("hands quick-unlock credentials to the native owner without waiting behind reconciliation", async () => {
  const desired = {
    ...DEFAULT_EXTENSION_SETTINGS,
    quickUnlockEnabled: true
  };
  const queueQuickUnlockEnrollment = vi.fn(async () => undefined);
  const settingsStore: ExtensionSettingsStore = {
    surface: "windows",
    nativeReconciliationOwned: true,
    queueQuickUnlockEnrollment,
    load: vi.fn(async () => desired),
    save: vi.fn(async () => undefined)
  };
  const vaults = [
    {
      vaultRefId: "vault-ref-1",
      displayName: "Personal",
      sourceKind: "local" as const,
      sourceSummary: "personal.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: true
    }
  ];
  const blockedReconciliation = createDeferred<typeof vaults>();
  const listRecentVaults = vi
    .fn()
    .mockResolvedValueOnce(vaults)
    .mockReturnValueOnce(blockedReconciliation.promise)
    .mockResolvedValue(vaults);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listRecentVaults
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await screen.findByText("No entries available.");
  await waitFor(() => expect(listRecentVaults).toHaveBeenCalledTimes(2));
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.change(
    await screen.findByLabelText("Quick Unlock Master Password"),
    { target: { value: "demo-password" } }
  );
  fireEvent.click(screen.getByRole("button", { name: "Enable Windows Hello" }));

  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
  const handoffsBeforeReconciliationFinished =
    queueQuickUnlockEnrollment.mock.calls.length;
  blockedReconciliation.resolve(vaults);

  expect(handoffsBeforeReconciliationFinished).toBe(1);
  expect(queueQuickUnlockEnrollment).toHaveBeenCalledWith({
    password: "demo-password",
    keyFilePath: ""
  });
});

it("renders recent vaults and unlocks the current selection without a path field", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-2"
    }),
    listRecentVaults: vi.fn(async () => [
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
    ]),
    setCurrentVault: vi.fn(async (_vaultRefId: string) => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    })),
    unlockCurrentVault: vi.fn(async (_credentials: {
      password?: string | null;
      keyFilePath?: string | null;
    }) => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })),
    listGroups: vi.fn(async (_vaultId: string) => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    })),
    listEntries: async (_vaultId: string) => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ],
    getEntryDetail: vi.fn(async (_vaultId: string, _entryId: string) => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: "123456"
    }))
  };

  render(<App client={client} />);

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

  expect(await screen.findByText("Example")).toBeInTheDocument();
  expect(screen.getByText("alice")).toBeInTheDocument();
  expect(client.setCurrentVault).toHaveBeenCalledWith("vault-ref-1");
  expect(client.unlockCurrentVault).toHaveBeenCalledWith({
    password: "demo-password",
    keyFilePath: "/tmp/demo.keyx"
  });

  fireEvent.click(screen.getByRole("button", { name: "Example" }));

  expect(await screen.findByDisplayValue("Example")).toBeInTheDocument();
  expect(screen.getByDisplayValue("alice")).toBeInTheDocument();
  expect(screen.getByDisplayValue("secret-123")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("https://example.com")).toBeInTheDocument();
  expect(screen.getByDisplayValue("demo note")).toBeInTheDocument();
  expect(client.getEntryDetail).toHaveBeenCalledWith("vault-1", "entry-1");

  const passwordInput = screen.getByDisplayValue("secret-123");
  const passwordField = passwordInput.closest("label");
  expect(passwordField).not.toBeNull();
  fireEvent.click(
    within(passwordField as HTMLElement).getByRole("button", {
      name: "Show password"
    })
  );
  await waitFor(() => expect(passwordInput).toHaveAttribute("type", "text"));
});

it("removes rendered secrets when the resident session is invalidated by another client", async () => {
  let publishSessionState!: (state: {
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }) => void;
  const subscribeSessionState = vi.fn(async (listener: typeof publishSessionState) => {
    publishSessionState = listener;
    return () => undefined;
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "resident-secret",
      url: "https://example.com",
      notes: "",
      totp: null
    }))
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={subscribeSessionState}
    />
  );

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  expect(await screen.findByDisplayValue("resident-secret")).toBeInTheDocument();
  await waitFor(() => expect(subscribeSessionState).toHaveBeenCalledTimes(1));

  act(() => {
    publishSessionState({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
  });

  expect(screen.queryByDisplayValue("resident-secret")).not.toBeInTheDocument();
  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
});

it("refreshes the authoritative resident session when a client without push wakes", async () => {
  let currentSession = {
    unlocked: true,
    activeVaultId: "vault-1" as string | null,
    currentVaultRefId: "vault-ref-1" as string | null
  };
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => currentSession),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "resident-secret",
      url: "https://example.com",
      notes: "",
      totp: null
    }))
  } satisfies RuntimeClientLike;

  render(<App client={client} />);
  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  expect(await screen.findByDisplayValue("resident-secret")).toBeInTheDocument();

  currentSession = {
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: "vault-ref-1"
  };
  fireEvent(window, new Event("focus"));

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(screen.queryByDisplayValue("resident-secret")).not.toBeInTheDocument();
  expect(client.getSessionState).toHaveBeenCalledTimes(2);
});

it("does not let an initial session read overwrite a newer resident invalidation", async () => {
  const initialSession = createDeferred<{
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }>();
  let publishSessionState!: (state: {
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }) => void;
  const subscribeSessionState = vi.fn(async (listener: typeof publishSessionState) => {
    publishSessionState = listener;
    return () => undefined;
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(() => initialSession.promise),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={subscribeSessionState}
    />
  );

  await waitFor(() => expect(subscribeSessionState).toHaveBeenCalledTimes(1));
  act(() => {
    publishSessionState({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
  });
  initialSession.resolve({
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1"
  });
  await act(async () => {
    await initialSession.promise;
    await Promise.resolve();
  });

  expect(screen.getByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(client.listGroups).not.toHaveBeenCalled();
});

it("clears typed unlock credentials on a same-state resident lock event", async () => {
  let publishSessionState!: (state: {
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }) => void;
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    })),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local" as const,
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready" as const,
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ])
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={vi.fn(async (listener) => {
        publishSessionState = listener;
        return () => undefined;
      })}
    />
  );

  const password = await screen.findByLabelText("Master Password");
  const keyFilePath = screen.getByLabelText("Key File Path");
  fireEvent.change(password, { target: { value: "resident-secret" } });
  fireEvent.change(keyFilePath, { target: { value: "C:\\keys\\resident.keyx" } });

  act(() => {
    publishSessionState({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });
  });

  expect(screen.getByLabelText("Master Password")).toHaveValue("");
  expect(screen.getByLabelText("Key File Path")).toHaveValue("");
});

it("fails closed when resident session notifications cannot be subscribed", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ])
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={vi.fn(async () => {
        throw new Error("resident session notifications unavailable");
      })}
    />
  );

  expect(
    await screen.findByText("resident session notifications unavailable")
  ).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Example" })).not.toBeInTheDocument();
});

it("fails closed when the post-subscription session refresh cannot close the event gap", async () => {
  const subscriptionReady = createDeferred<() => void>();
  const getSessionState = vi.fn(async () => {
    throw new Error("resident session refresh unavailable");
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState,
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={vi.fn(() => subscriptionReady.promise)}
    />
  );

  expect(await screen.findByText("Loading...")).toBeInTheDocument();
  expect(getSessionState).not.toHaveBeenCalled();
  subscriptionReady.resolve(() => undefined);

  expect(
    await screen.findByText("resident session refresh unavailable")
  ).toBeInTheDocument();
  expect(screen.queryByText("No entries available.")).not.toBeInTheDocument();
});

it("unlocks the current recent vault with Windows Hello when quick unlock is enabled", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => [
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
    ]),
    unlockCurrentVaultWithQuickUnlock: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn()
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      extensionSettingsStore={createSettingsStore({ quickUnlockEnabled: true })}
    />
  );

  expect(await screen.findByText("Personal")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Unlock with Windows Hello" }));

  await waitFor(() => {
    expect(client.unlockCurrentVaultWithQuickUnlock).toHaveBeenCalledTimes(1);
  });
  expect(await screen.findByText("No entries available.")).toBeInTheDocument();
});

it("refreshes an invalidated Hello enrollment and re-enrolls after password unlock", async () => {
  const recentVaults = [
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    unlockCurrentVaultWithQuickUnlock: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: false };
      throw new Error("Windows Hello enrollment was invalidated");
    }),
    unlockCurrentVault: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    enableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: true };
      return {
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      };
    })
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      extensionSettingsStore={createSettingsStore({ quickUnlockEnabled: true })}
    />
  );

  expect(await screen.findByText("Personal")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Unlock with Windows Hello" }));

  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Windows Hello enrollment was invalidated"
  );
  await waitFor(() => {
    expect(
      screen.queryByRole("button", { name: "Unlock with Windows Hello" })
    ).not.toBeInTheDocument();
  });

  fireEvent.change(screen.getByLabelText("Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

  await waitFor(() => {
    expect(client.enableQuickUnlockForCurrentVault).toHaveBeenCalledWith({
      password: "demo-password",
      keyFilePath: ""
    });
  });
  expect(await screen.findByText("No entries available.")).toBeInTheDocument();
});

it("opens Windows settings while locked and saves only Windows-owned preferences", async () => {
  const settingsStore = createSettingsStore();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));

  expect(await screen.findByRole("heading", { name: "Windows Settings" })).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Recent Databases"), {
    target: { value: "4" }
  });
  fireEvent.change(screen.getByLabelText("Idle Lock Minutes"), {
    target: { value: "7" }
  });
  fireEvent.change(screen.getByLabelText("Clear Clipboard Seconds"), {
    target: { value: "12" }
  });
  expect(screen.queryByLabelText("Page-load autofill")).not.toBeInTheDocument();
  fireEvent.click(screen.getByLabelText("Windows passkey provider"));
  fireEvent.click(screen.getByLabelText("Quick Unlock"));
  fireEvent.click(screen.getByRole("button", { name: "中文" }));
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalledWith({
      recentVaultLimit: 4,
      language: "zh-CN",
      idleLockMinutes: 7,
      clearClipboardSeconds: 12,
      autofillOnPageLoadEnabled: false,
      browserPasskeyProxyEnabled: false,
      windowsPasskeyProviderEnabled: true,
      quickUnlockEnabled: true
    });
  });
  expect(screen.getByRole("heading", { name: "Windows 设置" })).toBeInTheDocument();
});

it("shows native reconciliation failures without turning settings persistence into a failure", async () => {
  let publishReconciliationError!: (error: string | null) => void;
  const settingsStore = Object.assign(createSettingsStore(), {
    nativeReconciliationOwned: true,
    loadReconciliationError: vi.fn(async () => "provider registration failed"),
    subscribeReconciliationError: vi.fn(
      async (listener: (error: string | null) => void) => {
        publishReconciliationError = listener;
        return () => undefined;
      }
    )
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await screen.findByRole("heading", { name: "Unlock your vault" });
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  expect(await screen.findByText("provider registration failed")).toBeInTheDocument();

  act(() => publishReconciliationError(null));
  await waitFor(() => {
    expect(screen.queryByText("provider registration failed")).not.toBeInTheDocument();
  });
});

it("keeps a reconciliation subscription failure visible after a null status refresh", async () => {
  const reconciliationStatus = createDeferred<string | null>();
  const settingsStore = Object.assign(createSettingsStore(), {
    nativeReconciliationOwned: true,
    loadReconciliationError: vi.fn(() => reconciliationStatus.promise),
    subscribeReconciliationError: vi.fn(async () => {
      throw new Error("reconciliation event stream unavailable");
    })
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await screen.findByRole("heading", { name: "Unlock your vault" });
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  expect(
    await screen.findByText("reconciliation event stream unavailable")
  ).toBeInTheDocument();

  reconciliationStatus.resolve(null);
  await act(async () => {
    await reconciliationStatus.promise;
    await Promise.resolve();
  });

  expect(
    screen.getByText("reconciliation event stream unavailable")
  ).toBeInTheDocument();
});

it("keeps the vault session usable when desired settings cannot be read", async () => {
  const settingsStore: ExtensionSettingsStore = {
    surface: "windows",
    load: vi.fn(async () => {
      throw new Error("settings read denied");
    }),
    save: vi.fn(async () => undefined)
  };
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    })),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(
    await screen.findByRole("heading", { name: "Unlock your vault" })
  ).toBeInTheDocument();
  expect(client.getSessionState).toHaveBeenCalledTimes(1);
  expect(client.listRecentVaults).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "settings read denied"
  );
});

it("persists the latest desired state without running platform effects in the renderer", async () => {
  const settingsStore = createSettingsStore();
  settingsStore.nativeReconciliationOwned = true;
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  const providerToggle = await screen.findByLabelText("Windows passkey provider");

  fireEvent.click(providerToggle);
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await waitFor(() => expect(settingsStore.save).toHaveBeenCalledTimes(1));

  fireEvent.click(providerToggle);
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await waitFor(() => expect(settingsStore.save).toHaveBeenCalledTimes(2));
  await expect(settingsStore.load()).resolves.toMatchObject({
    windowsPasskeyProviderEnabled: false
  });
});

it("confirms before leaving unsaved extension settings", async () => {
  const settingsStore = createSettingsStore();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.change(await screen.findByLabelText("Recent Databases"), {
    target: { value: "4" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Back" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Continue editing" }));
  expect(screen.getByLabelText("Recent Databases")).toHaveValue(4);

  fireEvent.click(screen.getByRole("button", { name: "Back" }));
  fireEvent.click(await screen.findByRole("button", { name: "Save changes" }));

  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalledWith(
      expect.objectContaining({ recentVaultLimit: 4 })
    );
  });
  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
});

it("coalesces save-and-continue with an extension settings save already in flight", async () => {
  const settingsStore = createSettingsStore();
  const save = createDeferred<void>();
  settingsStore.save = vi.fn(() => save.promise);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.change(await screen.findByLabelText("Recent Databases"), {
    target: { value: "4" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await screen.findByRole("button", { name: "Saving..." });

  fireEvent.click(screen.getByRole("button", { name: "Back" }));
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  expect(settingsStore.save).toHaveBeenCalledTimes(1);

  save.resolve();

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(settingsStore.save).toHaveBeenCalledTimes(1);
});

it("freezes extension settings while their save is in flight", async () => {
  const settingsStore = createSettingsStore();
  const save = createDeferred<void>();
  settingsStore.save = vi.fn(() => save.promise);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  const recentDatabases = await screen.findByLabelText("Recent Databases");
  fireEvent.change(recentDatabases, { target: { value: "4" } });
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  await screen.findByRole("button", { name: "Saving..." });
  expect(recentDatabases).toBeDisabled();
  expect(screen.getByRole("button", { name: "中文" })).toBeDisabled();
  expect(screen.getByLabelText("Windows passkey provider")).toBeDisabled();

  save.resolve();
  await waitFor(() => expect(recentDatabases).not.toBeDisabled());
  expect(recentDatabases).toHaveValue(4);
});

it("does not save quick unlock as enabled when the host does not support it", async () => {
  const settingsStore = createSettingsStore();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null,
      supportsBiometricUnlock: false
    }),
    listRecentVaults: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));

  const quickUnlock = await screen.findByRole("checkbox", {
    name: "Quick Unlock"
  });
  expect(quickUnlock).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalledWith({
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 10,
      clearClipboardSeconds: 30,
      autofillOnPageLoadEnabled: false,
      browserPasskeyProxyEnabled: false,
      windowsPasskeyProviderEnabled: false,
      quickUnlockEnabled: false
    });
  });
});

it("preserves an enabled quick-unlock desire while the host is temporarily unavailable", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: true });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    }),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Personal",
        sourceKind: "local" as const,
        sourceSummary: "personal.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready" as const,
        supportsQuickUnlock: true,
        isCurrent: true
      }
    ])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);
  await screen.findByRole("heading", { name: "Unlock your vault" });
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  const recentDatabases = await screen.findByLabelText("Recent Databases");
  fireEvent.change(recentDatabases, { target: { value: "4" } });
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalledWith(
      expect.objectContaining({
        recentVaultLimit: 4,
        quickUnlockEnabled: true
      })
    );
  });
  expect(client.disableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("toggles quick unlock for the current vault from extension settings", async () => {
  const settingsStore = createSettingsStore();
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn(),
    enableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: true };
      return {
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      };
    }),
    disableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: false };
      return {
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      };
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("No entries available.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));

  const quickUnlock = await screen.findByRole("checkbox", {
    name: "Quick Unlock"
  });
  expect(quickUnlock).not.toBeChecked();

  fireEvent.click(quickUnlock);
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalled();
  });
  expect(await screen.findByRole("checkbox", { name: "Quick Unlock" })).toBeChecked();
  expect(client.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
  expect(
    screen.getByText(
      "Enter the current master credentials once. VaultKern retains them in Windows Hello-protected storage for Quick Unlock."
    )
  ).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Quick Unlock Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.change(screen.getByLabelText("Quick Unlock Key File Path"), {
    target: { value: "/tmp/demo.keyx" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Enable Windows Hello" }));
  await waitFor(() => {
    expect(client.enableQuickUnlockForCurrentVault).toHaveBeenCalledWith({
      password: "demo-password",
      keyFilePath: "/tmp/demo.keyx"
    });
  });

  fireEvent.click(screen.getByRole("checkbox", { name: "Quick Unlock" }));
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await waitFor(() => {
    expect(client.disableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
  });
  expect(await screen.findByRole("checkbox", { name: "Quick Unlock" })).not.toBeChecked();
});

it("persists desired quick unlock state when blob revocation reconciliation fails", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: true });
  const recentVaults = [
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    disableQuickUnlockForCurrentVault: vi.fn(async () => {
      throw new Error("simulated quick unlock revocation failure");
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  const quickUnlock = await screen.findByRole("checkbox", { name: "Quick Unlock" });
  expect(quickUnlock).toBeChecked();

  fireEvent.click(quickUnlock);
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  expect(
    await screen.findByText("simulated quick unlock revocation failure")
  ).toBeInTheDocument();
  expect(client.disableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
  expect(settingsStore.save).toHaveBeenCalledTimes(1);
  expect(vi.mocked(settingsStore.save).mock.invocationCallOrder[0]).toBeLessThan(
    client.disableQuickUnlockForCurrentVault.mock.invocationCallOrder[0]!
  );
  expect((await settingsStore.load()).quickUnlockEnabled).toBe(false);
  expect(recentVaults[0]?.supportsQuickUnlock).toBe(true);
});

it("leaves both desired quick unlock and its blob unchanged when settings persistence fails", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: true });
  settingsStore.save = vi.fn(async () => {
    throw new Error("simulated settings-store failure");
  });
  let blobPresent = true;
  const recentVaults = [
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    disableQuickUnlockForCurrentVault: vi.fn(async () => {
      blobPresent = false;
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: false };
      return {
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      };
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.click(await screen.findByRole("checkbox", { name: "Quick Unlock" }));
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  expect(await screen.findByText("simulated settings-store failure")).toBeInTheDocument();
  expect((await settingsStore.load()).quickUnlockEnabled).toBe(true);
  expect(blobPresent).toBe(true);
  expect(client.disableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
  expect(screen.getByRole("checkbox", { name: "Quick Unlock" })).not.toBeChecked();
});

it("does not apply a stale quick unlock revocation after desired state changes", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: false });
  const vaultList = createDeferred<Awaited<ReturnType<RuntimeClientLike["listRecentVaults"]>>>();
  const recentVaults = [
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(() => vaultList.promise),
    disableQuickUnlockForCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }))
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await waitFor(() => expect(client.listRecentVaults).toHaveBeenCalledTimes(1));
  await settingsStore.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    quickUnlockEnabled: true
  });
  vaultList.resolve(recentVaults);

  expect(await screen.findByText("Personal")).toBeInTheDocument();
  expect(client.disableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("reconciles quick unlock against the runtime session target when the persisted selection changed elsewhere", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: false });
  const recentVaults = [
    {
      vaultRefId: "vault-ref-1",
      displayName: "Old selection",
      sourceKind: "local",
      sourceSummary: "old.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready",
      supportsQuickUnlock: true,
      isCurrent: false
    },
    {
      vaultRefId: "vault-ref-2",
      displayName: "Current selection",
      sourceKind: "local",
      sourceSummary: "current.kdbx",
      lastUsedAt: 1776500001,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: true
    }
  ];
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    disableQuickUnlockForCurrentVault: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }))
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("Current selection")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));
  fireEvent.change(await screen.findByLabelText("Recent Databases"), {
    target: { value: "9" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));

  await waitFor(() => expect(settingsStore.save).toHaveBeenCalledTimes(1));
  await waitFor(() =>
    expect(client.disableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1)
  );
});

it("renders quick-unlock enrollment from the runtime session target", async () => {
  const settingsStore = createSettingsStore({ quickUnlockEnabled: true });
  settingsStore.nativeReconciliationOwned = true;
  settingsStore.queueQuickUnlockEnrollment = vi.fn(async () => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Old selection",
        sourceKind: "local" as const,
        sourceSummary: "old.kdbx",
        lastUsedAt: 1776500000,
        availability: "ready" as const,
        supportsQuickUnlock: true,
        isCurrent: false
      },
      {
        vaultRefId: "vault-ref-2",
        displayName: "Current selection",
        sourceKind: "local" as const,
        sourceSummary: "current.kdbx",
        lastUsedAt: 1776500001,
        availability: "ready" as const,
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));

  expect(
    screen.queryByLabelText("Quick Unlock Master Password")
  ).not.toBeInTheDocument();
});

it("stores the quick unlock preference without enrolling a locked vault", async () => {
  const settingsStore = createSettingsStore();
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    enableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: true };
      return {
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1"
      };
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Windows Settings" }));

  const quickUnlock = await screen.findByRole("checkbox", {
    name: "Quick Unlock"
  });
  expect(quickUnlock).not.toBeDisabled();

  fireEvent.click(quickUnlock);
  fireEvent.click(screen.getByRole("button", { name: "Save Windows Settings" }));
  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalled();
  });
  expect(await screen.findByRole("checkbox", { name: "Quick Unlock" })).toBeChecked();
  expect(client.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
  expect(
    screen.getByText("Unlock this vault before enrolling Windows Hello.")
  ).toBeInTheDocument();
});

it("enrolls quick unlock with the credentials from a successful vault unlock", async () => {
  const settingsStore = createSettingsStore({
    quickUnlockEnabled: true
  });
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    unlockCurrentVault: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    })),
    enableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[0] = { ...recentVaults[0], supportsQuickUnlock: true };
      return {
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1",
        supportsBiometricUnlock: true
      };
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  expect(client.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();

  fireEvent.change(screen.getByLabelText("Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

  await waitFor(() => {
    expect(client.enableQuickUnlockForCurrentVault).toHaveBeenCalledWith({
      password: "demo-password",
      keyFilePath: ""
    });
  });
});

it("does not auto-enable quick unlock in the manager when biometric unlock is unsupported", async () => {
  const settingsStore = createSettingsStore({
    quickUnlockEnabled: true
  });
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
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    enableQuickUnlockForCurrentVault: vi.fn(async () => {
      throw new Error("biometric unlock is not supported");
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("Personal")).toBeInTheDocument();
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(client.enableQuickUnlockForCurrentVault).not.toHaveBeenCalled();
});

it("syncs the off quick unlock preference when switching to another current vault", async () => {
  const settingsStore = createSettingsStore({
    quickUnlockEnabled: false
  });
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
    },
    {
      vaultRefId: "vault-ref-2",
      displayName: "Work",
      sourceKind: "local",
      sourceSummary: "work.kdbx",
      lastUsedAt: 1776500010,
      availability: "ready",
      supportsQuickUnlock: true,
      isCurrent: false
    }
  ];
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: true
    }),
    listRecentVaults: vi.fn(async () => recentVaults),
    setCurrentVault: vi.fn(async (vaultRefId: string) => {
      recentVaults[0] = { ...recentVaults[0], isCurrent: false };
      recentVaults[1] = { ...recentVaults[1], isCurrent: true };
      return {
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: vaultRefId,
        supportsBiometricUnlock: true
      };
    }),
    disableQuickUnlockForCurrentVault: vi.fn(async () => {
      recentVaults[1] = { ...recentVaults[1], supportsQuickUnlock: false };
      return {
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-2",
        supportsBiometricUnlock: true
      };
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByRole("heading", { name: "Unlock your vault" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Work/ }));

  await waitFor(() => {
    expect(client.disableQuickUnlockForCurrentVault).toHaveBeenCalledTimes(1);
  });
});

it("renders database and entry workspace labels in Chinese when selected", async () => {
  const settingsStore = createSettingsStore({
    recentVaultLimit: 10,
    language: "zh-CN",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      modifiedAt: 42,
      totpUri: null,
      fieldProtection: {
        protectTitle: false,
        protectUsername: false,
        protectPassword: true,
        protectUrl: false,
        protectNotes: false
      },
      customFields: [],
      attachments: []
    }))
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("条目")).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  expect(await screen.findByText("条目详情")).toBeInTheDocument();
  expect(await screen.findByText(/更新时间/)).toBeInTheDocument();
  expect(await screen.findByText(/1970-01-01 00:00:42/)).toBeInTheDocument();
  expect(screen.getByLabelText("标题")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "数据库设置" }));
  expect(screen.queryByRole("heading", { name: "插件设置" })).not.toBeInTheDocument();
  expect(screen.getByText("数据库元数据")).toBeInTheDocument();
  expect(screen.getByLabelText("数据库名称")).toBeInTheDocument();
  expect(screen.getByText("保存与加密")).toBeInTheDocument();
  expect(screen.queryByText("凭据")).not.toBeInTheDocument();
});

it("applies the recent database limit without deleting resident vault references", async () => {
  const settingsStore = createSettingsStore({
    recentVaultLimit: 2,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30
  });
  let vaults = [
    {
      vaultRefId: "vault-ref-1",
      displayName: "One",
      sourceKind: "local" as const,
      sourceSummary: "one.kdbx",
      lastUsedAt: 3,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: true
    },
    {
      vaultRefId: "vault-ref-2",
      displayName: "Two",
      sourceKind: "local" as const,
      sourceSummary: "two.kdbx",
      lastUsedAt: 2,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: false
    },
    {
      vaultRefId: "vault-ref-3",
      displayName: "Three",
      sourceKind: "local" as const,
      sourceSummary: "three.kdbx",
      lastUsedAt: 1,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: false
    }
  ];
  const deleteRecentVaultIfNotCurrent = vi.fn(async (vaultRefId: string) => {
    vaults = vaults.filter((vault) => vault.vaultRefId !== vaultRefId);
    return vaults;
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    }),
    listRecentVaults: vi.fn(async () => vaults),
    deleteRecentVaultIfNotCurrent
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("One")).toBeInTheDocument();
  expect(await screen.findByText("Two")).toBeInTheDocument();
  expect(screen.queryByText("Three")).not.toBeInTheDocument();
  expect(client.deleteRecentVaultIfNotCurrent).not.toHaveBeenCalled();
});

it("does not let an older recent-vault projection overwrite a newer reload", async () => {
  const delayedProjectionSettings = createDeferred<ExtensionSettings>();
  const desired = {
    ...DEFAULT_EXTENSION_SETTINGS,
    recentVaultLimit: 1
  };
  let settingsLoads = 0;
  const settingsStore: ExtensionSettingsStore = {
    load: vi.fn(() => {
      settingsLoads += 1;
      return settingsLoads === 3
        ? delayedProjectionSettings.promise
        : Promise.resolve(desired);
    }),
    save: vi.fn(async () => undefined)
  };
  const oldVaults = [
    {
      vaultRefId: "vault-ref-old",
      displayName: "Old projection",
      sourceKind: "local" as const,
      sourceSummary: "old.kdbx",
      lastUsedAt: 1,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: true
    }
  ];
  const newVaults = [
    {
      vaultRefId: "vault-ref-new",
      displayName: "New projection",
      sourceKind: "local" as const,
      sourceSummary: "new.kdbx",
      lastUsedAt: 2,
      availability: "ready" as const,
      supportsQuickUnlock: false,
      isCurrent: true
    }
  ];
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi
      .fn()
      .mockResolvedValueOnce({
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-old"
      })
      .mockResolvedValue({
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-new"
      }),
    listRecentVaults: vi
      .fn()
      .mockResolvedValueOnce(oldVaults)
      .mockResolvedValue(newVaults),
    addLocalVaultReference: vi.fn(async () => newVaults[0])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await waitFor(() => expect(settingsStore.load).toHaveBeenCalledTimes(3));
  fireEvent.click(screen.getByRole("button", { name: "Manage vaults" }));
  fireEvent.click(screen.getByRole("button", { name: "Local File" }));
  expect(await screen.findByText("New projection")).toBeInTheDocument();

  delayedProjectionSettings.resolve(desired);
  await act(async () => {
    await delayedProjectionSettings.promise;
    await Promise.resolve();
  });

  expect(screen.getByText("New projection")).toBeInTheDocument();
  expect(screen.queryByText("Old projection")).not.toBeInTheDocument();
});

it("reports foreground activity to the resident instead of owning the idle deadline", async () => {
  vi.useFakeTimers();
  const settingsStore = createSettingsStore({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 1,
    clearClipboardSeconds: 30
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn(),
    recordUserActivity: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }))
  } satisfies RuntimeClientLike & {
    recordUserActivity(): Promise<SessionStateLike>;
  };

  render(<App client={client} extensionSettingsStore={settingsStore} />);
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(screen.getByText("No entries available.")).toBeInTheDocument();

  fireEvent.pointerDown(window);
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(client.recordUserActivity).toHaveBeenCalledTimes(1);

  await act(async () => {
    vi.advanceTimersByTime(60_000);
    await Promise.resolve();
  });

  expect(client.lockSession).not.toHaveBeenCalled();
});

it("shows progress while unlocking a recent vault", async () => {
  const unlock = createDeferred<{
    unlocked: boolean;
    activeVaultId: string;
    currentVaultRefId: string;
  }>();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    }),
    listRecentVaults: vi.fn(async () => [
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
    ]),
    unlockCurrentVault: vi.fn(() => unlock.promise),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  await screen.findByText("Personal");
  fireEvent.change(screen.getByLabelText("Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

  expect(await screen.findByRole("button", { name: "Unlocking..." })).toBeDisabled();
  expect(screen.getByLabelText("Master Password")).toBeDisabled();
  expect(screen.getByLabelText("Key File Path")).toBeDisabled();

  await act(async () => {
    unlock.resolve({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });
  });

  expect(await screen.findByText("No entries available.")).toBeInTheDocument();
});

it("loads database settings and preserves a conflict-copy warning after saving", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([]),
    getEntryDetail: vi.fn(),
    getDatabaseSettings: vi.fn().mockResolvedValue({
      type: "database_settings",
      metadata: {
        name: "Archive",
        description: "Old description",
        defaultUsername: "alice"
      },
      publicMetadata: {
        displayName: "Public Archive",
        color: "#445566",
        icon: "database"
      },
      history: {
        maxItemsPerEntry: 10,
        maxTotalSizeBytes: 2048
      },
      recycleBin: { enabled: true },
      encryption: {
        compression: "gzip",
        cipher: "aes256",
        kdf: {
          algorithm: "argon2d",
          transformRounds: null,
          iterations: 3,
          memoryKib: 65537,
          parallelism: 2
        }
      },
      autosaveDelaySeconds: 20,
      hasPassword: true
    }),
    updateDatabaseSettings: vi.fn().mockResolvedValue(
      committedDatabaseSettings(
        {
          type: "database_settings",
          metadata: {
            name: "Engineering",
            description: "Updated",
            defaultUsername: "ops"
          },
          publicMetadata: {
            displayName: "Engineering Public",
            color: "#2f6f73",
            icon: "database"
          },
          history: {
            maxItemsPerEntry: 9,
            maxTotalSizeBytes: 99000
          },
          recycleBin: { enabled: false },
          encryption: {
            compression: "none",
            cipher: "chacha20",
            kdf: {
              algorithm: "argon2d",
              transformRounds: null,
              iterations: 3,
              memoryKib: 65537,
              parallelism: 2
            }
          },
          autosaveDelaySeconds: 45,
          hasPassword: true
        },
        {
          type: "save_vault_result",
          status: "conflict_copy",
          conflictCopyPath: "C:\\Vaults\\Archive.conflict.kdbx"
        }
      )
    )
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(await screen.findByRole("button", { name: "Database Settings" }));
  expect(await screen.findByRole("heading", { name: "Archive" })).toBeInTheDocument();
  expect(screen.getByDisplayValue("Archive")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.change(screen.getByLabelText("Description"), {
    target: { value: "Updated" }
  });
  fireEvent.change(screen.getByLabelText("Default Username"), {
    target: { value: "ops" }
  });
  fireEvent.change(screen.getByLabelText("Public Display Name"), {
    target: { value: "Engineering Public" }
  });
  fireEvent.change(screen.getByLabelText("Public Color"), {
    target: { value: "#2f6f73" }
  });
  fireEvent.change(screen.getByLabelText("History Items Per Entry"), {
    target: { value: "9" }
  });
  fireEvent.click(screen.getByLabelText("Enable recycle bin"));
  fireEvent.change(screen.getByLabelText("Compression"), {
    target: { value: "none" }
  });
  fireEvent.change(screen.getByLabelText("Cipher"), {
    target: { value: "chacha20" }
  });
  expect(screen.getByLabelText("Key Derivation Function")).toBeDisabled();
  expect(screen.getByLabelText("Argon2 Memory MiB")).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Autosave Delay Seconds"), {
    target: { value: "45" }
  });
  expect(screen.queryByRole("button", { name: "Change password" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Remove password" })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  await waitFor(() => {
    expect(client.updateDatabaseSettings).toHaveBeenCalledWith("vault-1", {
      metadata: {
        name: "Engineering",
        description: "Updated",
        defaultUsername: "ops"
      },
      publicMetadata: {
        displayName: "Engineering Public",
        color: "#2f6f73",
        icon: "database"
      },
      history: {
        maxItemsPerEntry: 9,
        maxTotalSizeBytes: 2048
      },
      recycleBin: { enabled: false },
      encryption: {
        compression: "none",
        cipher: "chacha20",
        kdf: {
          algorithm: "argon2d",
          transformRounds: null,
          iterations: 3,
          memoryKib: 65537,
          parallelism: 2
        }
      },
      autosaveDelaySeconds: 45
    });
  });
  expect(client.saveVault).not.toHaveBeenCalled();
  expect(
    await screen.findByText(/Local edits were saved to a conflict copy:/)
  ).toHaveTextContent("C:\\Vaults\\Archive.conflict.kdbx");
  expect(screen.queryByText("Database settings saved.")).not.toBeInTheDocument();
});

it("preserves a default autosave delay when saving unrelated database settings", async () => {
  const baseClient = createVaultSelectionMethods();
  const initialSettings = await baseClient.getDatabaseSettings();
  const updateDatabaseSettings = vi.fn(
    async (_vaultId: string, _update: DatabaseSettingsUpdate) =>
      committedDatabaseSettings({
        ...initialSettings,
        metadata: { ...initialSettings.metadata, name: "Engineering" }
      })
  );
  const client = {
    ...baseClient,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    updateDatabaseSettings
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  await waitFor(() => expect(updateDatabaseSettings).toHaveBeenCalledTimes(1));
  expect(updateDatabaseSettings.mock.calls[0]?.[1]).not.toHaveProperty(
    "autosaveDelaySeconds"
  );
});

it("persists clearing a previously set autosave delay and leaves the settings page clean", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const initialSettings = {
    ...(await vaultMethods.getDatabaseSettings()),
    autosaveDelaySeconds: 20
  };
  let currentSettings = initialSettings;
  const updateDatabaseSettings = vi.fn(
    async (_vaultId: string, update: DatabaseSettingsUpdate) => {
      if (Object.prototype.hasOwnProperty.call(update, "autosaveDelaySeconds")) {
        currentSettings = {
          ...currentSettings,
          autosaveDelaySeconds: update.autosaveDelaySeconds ?? null
        };
      }
      return committedDatabaseSettings(currentSettings);
    }
  );
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    getDatabaseSettings: vi.fn(async () => currentSettings),
    updateDatabaseSettings
  } satisfies RuntimeClientLike;

  render(<App client={client} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  const autosaveDelay = await screen.findByLabelText("Autosave Delay Seconds");
  expect(autosaveDelay).toHaveValue("20");
  fireEvent.change(autosaveDelay, { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  await waitFor(() => expect(updateDatabaseSettings).toHaveBeenCalledTimes(1));
  expect(updateDatabaseSettings.mock.calls[0]?.[1]).toHaveProperty(
    "autosaveDelaySeconds",
    null
  );
  await waitFor(() => expect(autosaveDelay).toHaveValue(""));

  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Autosave Delay Seconds")).not.toBeInTheDocument();
});

it("accepts normalized database settings as the clean draft after a successful commit", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const initialSettings = await vaultMethods.getDatabaseSettings();
  vaultMethods.updateDatabaseSettings.mockImplementation(async (_vaultId, update) =>
    committedDatabaseSettings({
      ...initialSettings,
      metadata: {
        ...initialSettings.metadata,
        description: update.metadata?.description ?? null
      }
    })
  );
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Description"), {
    target: { value: "  Normalized description  " }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  await waitFor(() => expect(vaultMethods.updateDatabaseSettings).toHaveBeenCalledTimes(1));
  expect(vaultMethods.updateDatabaseSettings).toHaveBeenCalledWith(
    "vault-1",
    expect.objectContaining({
      metadata: expect.objectContaining({ description: "Normalized description" })
    })
  );
  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
});

it("does not let a database settings completion from another resident session reset the draft", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const template = await vaultMethods.getDatabaseSettings();
  const vaultASettings: DatabaseSettings = {
    ...template,
    metadata: { ...template.metadata, name: "Vault A" }
  };
  const vaultBSettings: DatabaseSettings = {
    ...template,
    metadata: { ...template.metadata, name: "Vault B" }
  };
  const vaultACommit = createDeferred<DatabaseSettingsCommitResult>();
  let publishSessionState!: (state: {
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }) => void;
  const client = {
    ...vaultMethods,
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-a",
      currentVaultRefId: "vault-ref-a"
    })),
    getDatabaseSettings: vi.fn(async (vaultId: string) =>
      vaultId === "vault-a" ? vaultASettings : vaultBSettings
    ),
    updateDatabaseSettings: vi.fn(() => vaultACommit.promise)
  } satisfies RuntimeClientLike;

  render(
    <App
      client={client}
      subscribeSessionState={vi.fn(async (listener) => {
        publishSessionState = listener;
        return () => undefined;
      })}
    />
  );

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  const vaultAName = await screen.findByLabelText("Database Name");
  expect(vaultAName).toHaveValue("Vault A");
  fireEvent.change(vaultAName, { target: { value: "Vault A saved" } });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
  await waitFor(() => expect(client.updateDatabaseSettings).toHaveBeenCalledTimes(1));

  act(() => {
    publishSessionState({
      unlocked: true,
      activeVaultId: "vault-b",
      currentVaultRefId: "vault-ref-b"
    });
  });
  fireEvent.click(await screen.findByRole("button", { name: "Database Settings" }));
  const vaultBName = await screen.findByDisplayValue("Vault B");
  fireEvent.change(vaultBName, { target: { value: "Vault B draft" } });

  await act(async () => {
    vaultACommit.resolve(
      committedDatabaseSettings({
        ...vaultASettings,
        metadata: { ...vaultASettings.metadata, name: "Vault A saved" }
      })
    );
    await vaultACommit.promise;
  });

  expect(screen.getByLabelText("Database Name")).toHaveValue("Vault B draft");
});

it("retries a failed atomic database settings commit", async () => {
  const updatedSettings: DatabaseSettings = {
    type: "database_settings" as const,
    metadata: { name: "Engineering", description: null, defaultUsername: null },
    publicMetadata: { displayName: null, color: null, icon: null },
    history: { maxItemsPerEntry: null, maxTotalSizeBytes: null },
    recycleBin: { enabled: true },
    encryption: {
      compression: "gzip",
      cipher: "aes256",
      kdf: {
        algorithm: "argon2id",
        transformRounds: null,
        iterations: 2,
        memoryKib: 65536,
        parallelism: 1
      }
    },
    autosaveDelaySeconds: 0,
    hasPassword: true
  };
  const updateDatabaseSettings = vi
    .fn()
    .mockRejectedValueOnce(new Error("simulated settings save failure"))
    .mockResolvedValueOnce(committedDatabaseSettings(updatedSettings));
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    updateDatabaseSettings
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  expect(await screen.findByText("simulated settings save failure")).toBeInTheDocument();
  expect(updateDatabaseSettings).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  await waitFor(() => expect(updateDatabaseSettings).toHaveBeenCalledTimes(2));
  expect(await screen.findByText("Database settings saved.")).toBeInTheDocument();
});

it("keeps the database settings draft editable when persistence fails", async () => {
  const vaultMethods = createVaultSelectionMethods();
  vaultMethods.updateDatabaseSettings.mockRejectedValue(
    new Error("simulated settings persistence failure")
  );
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  const name = await screen.findByLabelText("Database Name", undefined, {
    timeout: 3000
  });
  fireEvent.change(name, { target: { value: "Engineering" } });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  expect(
    await screen.findByText("simulated settings persistence failure")
  ).toBeInTheDocument();
  expect(name).toHaveValue("Engineering");
  expect(name).not.toBeDisabled();
  expect(screen.getByRole("button", { name: "Save settings" })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Discard changes" })).toBeInTheDocument();
});

it("applies a newer database settings draft before leaving after a failed save", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const initialSettings = await vaultMethods.getDatabaseSettings();
  let settingsCommitAttempt = 0;
  vaultMethods.updateDatabaseSettings.mockImplementation(async (_vaultId, update) => {
    settingsCommitAttempt += 1;
    if (settingsCommitAttempt === 1) {
      throw new Error("simulated settings save failure");
    }
    return committedDatabaseSettings({
      ...initialSettings,
      metadata: {
        name: update.metadata?.name ?? initialSettings.metadata.name,
        description:
          update.metadata?.description ?? initialSettings.metadata.description,
        defaultUsername:
          update.metadata?.defaultUsername ?? initialSettings.metadata.defaultUsername
      }
    });
  });
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));

  expect(await screen.findByText("simulated settings save failure")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Description"), {
    target: { value: "Second edit" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Statistics" }));
  fireEvent.click(await screen.findByRole("button", { name: "Save changes" }));

  await waitFor(() => {
    expect(vaultMethods.updateDatabaseSettings).toHaveBeenCalledTimes(2);
  });
  expect(vaultMethods.updateDatabaseSettings).toHaveBeenLastCalledWith(
    "vault-1",
    expect.objectContaining({
      metadata: {
        name: "Engineering",
        description: "Second edit",
        defaultUsername: null
      }
    })
  );
  expect(vaultMethods.saveVault).not.toHaveBeenCalled();
  expect(await screen.findByRole("heading", { name: "Statistics" })).toBeInTheDocument();
});

it("confirms before leaving unsaved database settings", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const updatedSettings = {
    ...(await vaultMethods.getDatabaseSettings()),
    metadata: { name: "Engineering", description: null, defaultUsername: null }
  };
  vaultMethods.updateDatabaseSettings.mockResolvedValue(
    committedDatabaseSettings(updatedSettings)
  );
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Discard changes" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Continue editing" }));
  expect(screen.getByLabelText("Database Name")).toHaveValue("Engineering");

  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));
  fireEvent.click(await screen.findByRole("button", { name: "Save changes" }));

  await waitFor(() => {
    expect(client.updateDatabaseSettings).toHaveBeenCalledWith(
      "vault-1",
      expect.objectContaining({
        metadata: { name: "Engineering", description: null, defaultUsername: null }
      })
    );
  });
  expect(client.saveVault).not.toHaveBeenCalled();
  await waitFor(() => {
    expect(screen.queryByLabelText("Database Name")).not.toBeInTheDocument();
  });
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
});

it("discarding navigation resets the database settings draft and dirty state", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  } satisfies RuntimeClientLike;

  render(<App client={client} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  const databaseName = await screen.findByLabelText("Database Name");
  fireEvent.change(databaseName, { target: { value: "Discard me" } });

  const search = screen.getByPlaceholderText("Search the archive");
  fireEvent.change(search, { target: { value: "first" } });
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Discard changes" }));

  await waitFor(() => {
    expect(screen.getByLabelText("Database Name")).toHaveValue("The Archive");
  });
  fireEvent.change(search, { target: { value: "second" } });
  expect(screen.queryByText("You have unsaved changes")).not.toBeInTheDocument();
});

it("rebases an unsaved database settings draft after source sync", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const initialSettings = await vaultMethods.getDatabaseSettings();
  let sourceRestored = false;
  vaultMethods.getDatabaseSettings.mockImplementation(async () =>
    sourceRestored
      ? {
          ...initialSettings,
          metadata: {
            ...initialSettings.metadata,
            name: "Remote Archive",
            description: "Changed on another device"
          }
        }
      : initialSettings
  );
  vaultMethods.retryVaultSourceSync.mockImplementation(async () => {
    sourceRestored = true;
    return {
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    };
  });
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        type: "vault_source_status" as const,
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Local Draft" }
  });

  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));

  await waitFor(() => {
    expect(vaultMethods.retryVaultSourceSync).toHaveBeenCalledWith("vault-1");
    expect(screen.getByLabelText("Description")).toHaveValue(
      "Changed on another device"
    );
  });
  expect(screen.getByLabelText("Database Name")).toHaveValue("Local Draft");
});

it("keeps an unsaved database settings draft when source reload fails", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const initialSettings = await vaultMethods.getDatabaseSettings();
  let sourceRestored = false;
  vaultMethods.getDatabaseSettings.mockImplementation(async () => {
    if (sourceRestored) {
      throw new Error("simulated database settings reload failure");
    }
    return initialSettings;
  });
  vaultMethods.retryVaultSourceSync.mockImplementation(async () => {
    sourceRestored = true;
    return {
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    };
  });
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        type: "vault_source_status" as const,
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Local Draft" }
  });

  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));

  expect(
    await screen.findByText("simulated database settings reload failure")
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Database Name")).toHaveValue("Local Draft");

  fireEvent.click(screen.getByRole("button", { name: "Back to archive" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
});

it("coalesces save-and-continue with a database settings save already in flight", async () => {
  const vaultMethods = createVaultSelectionMethods();
  const currentSettings = await vaultMethods.getDatabaseSettings();
  const update = createDeferred<DatabaseSettingsCommitResult>();
  vaultMethods.updateDatabaseSettings.mockImplementation(() => update.promise);
  const client = {
    ...vaultMethods,
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  fireEvent.change(await screen.findByLabelText("Database Name"), {
    target: { value: "Engineering" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
  await screen.findByRole("button", { name: "Saving..." });

  fireEvent.click(screen.getByRole("button", { name: "Statistics" }));
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  expect(vaultMethods.updateDatabaseSettings).toHaveBeenCalledTimes(1);

  update.resolve(
    committedDatabaseSettings({
      ...currentSettings,
      metadata: { ...currentSettings.metadata, name: "Engineering" }
    })
  );

  expect(await screen.findByRole("heading", { name: "Statistics" })).toBeInTheDocument();
  expect(vaultMethods.updateDatabaseSettings).toHaveBeenCalledTimes(1);
  expect(vaultMethods.saveVault).not.toHaveBeenCalled();
});

it("hides password actions until the authenticated credential flow exists", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: { id: "group-root", title: "Archive", entryCount: 0, childCount: 0, children: [] }
    }),
    listEntries: vi.fn().mockResolvedValue([]),
    getEntryDetail: vi.fn(),
    getDatabaseSettings: vi.fn().mockResolvedValue({
      type: "database_settings",
      metadata: { name: "No Password Vault", description: null, defaultUsername: null },
      publicMetadata: { displayName: null, color: null, icon: null },
      history: { maxItemsPerEntry: null, maxTotalSizeBytes: null },
      recycleBin: { enabled: true },
      encryption: {
        compression: "gzip",
        cipher: "aes256",
        kdf: {
          algorithm: "argon2id",
          transformRounds: null,
          iterations: 2,
          memoryKib: 65536,
          parallelism: 1
        }
      },
      autosaveDelaySeconds: null,
      hasPassword: false
    }),
    updateDatabaseSettings: vi.fn().mockResolvedValue({}),
    saveVault: vi.fn().mockResolvedValue({ type: "save_vault_result", status: "saved" })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  expect(await screen.findByText("No Password Vault")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));
  await screen.findByRole("heading", { name: "No Password Vault" });
  expect(screen.queryByRole("button", { name: "Add password" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Remove password" })).not.toBeInTheDocument();
});

it("shows the current kdf parameters as read-only", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: { id: "group-root", title: "Archive", entryCount: 0, childCount: 0, children: [] }
    }),
    listEntries: vi.fn().mockResolvedValue([]),
    getEntryDetail: vi.fn(),
    getDatabaseSettings: vi.fn().mockResolvedValue({
      type: "database_settings",
      metadata: { name: "Archive", description: null, defaultUsername: null },
      publicMetadata: { displayName: null, color: null, icon: null },
      history: { maxItemsPerEntry: null, maxTotalSizeBytes: null },
      recycleBin: { enabled: true },
      encryption: {
        compression: "gzip",
        cipher: "aes256",
        kdf: {
          algorithm: "argon2id",
          transformRounds: null,
          iterations: 3,
          memoryKib: 32768,
          parallelism: 2
        }
      },
      autosaveDelaySeconds: null,
      hasPassword: true
    }),
    updateDatabaseSettings: vi.fn().mockResolvedValue({}),
    saveVault: vi.fn().mockResolvedValue({ type: "save_vault_result", status: "saved" })
  };

  render(<App client={client as RuntimeClientLike} />);
  await screen.findByText("No entries available.");
  fireEvent.click(await screen.findByRole("button", { name: "Database Settings" }));

  expect(await screen.findByLabelText("Argon2 Iterations")).toBeDisabled();
  expect(screen.getByLabelText("Argon2 Memory MiB")).toBeDisabled();
  expect(screen.getByLabelText("Argon2 Parallelism")).toBeDisabled();
  expect(screen.getByLabelText("Key Derivation Function")).toBeDisabled();
  expect(screen.queryByLabelText("Transform Rounds")).not.toBeInTheDocument();
});

it("shows custom fields, attachments, and protected field markers in entry detail", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: "",
      totp: null,
      totpUri: null,
      fieldProtection: {
        protectTitle: false,
        protectUsername: true,
        protectPassword: true,
        protectUrl: false,
        protectNotes: false
      },
      customFields: [
        {
          key: "RecoveryCode",
          value: "one-time-code",
          protected: true
        },
        {
          key: "Environment",
          value: "prod",
          protected: false
        }
      ],
      attachments: [
        {
          name: "backup-codes.txt",
          size: 128,
          protectInMemory: true
        }
      ]
    })
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "GitHub" }));

  expect(await screen.findByText("Additional Properties")).toBeInTheDocument();
  expect(screen.getByText("RecoveryCode")).toBeInTheDocument();
  expect(screen.queryByText("one-time-code")).not.toBeInTheDocument();
  expect(screen.getByText("************")).toBeInTheDocument();
  expect(screen.getAllByText("Protected").length).toBeGreaterThan(0);
  expect(screen.getByText("Environment")).toBeInTheDocument();
  expect(screen.getByText("prod")).toBeInTheDocument();
  expect(screen.getByText("Attachments")).toBeInTheDocument();
  expect(screen.getByText("backup-codes.txt")).toBeInTheDocument();
  expect(screen.getByText("128 B")).toBeInTheDocument();
  expect(screen.queryByText("Protected Fields")).not.toBeInTheDocument();
  expect(screen.queryByText("Password is protected")).not.toBeInTheDocument();

  const revealRecoveryCode = screen.getByRole("button", {
    name: "Show RecoveryCode"
  });
  fireEvent.click(revealRecoveryCode);

  await waitFor(() => {
    expect(screen.getByText("one-time-code")).toBeInTheDocument();
  }, { timeout: 3000 });
});

it("manages an entry passkey from the detail pane", async () => {
  const originalPasskey = {
    username: "alice@example.com",
    credentialId: "credential-old",
    generatedUserId: "generated-user",
    relyingParty: "example.com",
    userHandle: "user-handle",
    backupEligible: true,
    backupState: false
  };
  const editedPasskey = {
    ...originalPasskey,
    credentialId: "credential-new",
    backupState: true
  };
  const setEntryPasskey = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "GitHub",
    username: "alice",
    password: "secret",
    url: "https://github.com",
    notes: "",
    totp: null,
    totpUri: null,
    passkey: editedPasskey,
    customFields: [],
    attachments: []
  }));
  const clearEntryPasskey = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "GitHub",
    username: "alice",
    password: "secret",
    url: "https://github.com",
    notes: "",
    totp: null,
    totpUri: null,
    passkey: null,
    customFields: [],
    attachments: []
  }));
  const saveVault = vi.fn(async () => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: "",
      totp: null,
      totpUri: null,
      passkey: originalPasskey,
      customFields: [],
      attachments: []
    }),
    setEntryPasskey,
    clearEntryPasskey,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "GitHub" }));

  expect(await screen.findByText("Passkey")).toBeInTheDocument();
  expect(screen.getByText("example.com")).toBeInTheDocument();
  expect(screen.queryByText("credential-old")).not.toBeInTheDocument();
  expect(screen.queryByText("generated-user")).not.toBeInTheDocument();
  expect(screen.queryByText("user-handle")).not.toBeInTheDocument();
  expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Show Credential ID" }));
  expect(screen.getByText("credential-old")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Edit passkey" }));
  expect(screen.queryByLabelText("Private Key PEM")).not.toBeInTheDocument();
  expect(screen.getByDisplayValue("credential-old")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("generated-user")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("user-handle")).toHaveAttribute("type", "password");
  const savePasskeyButton = screen.getByRole("button", { name: "Save passkey" });
  fireEvent.change(screen.getByLabelText("Credential ID"), {
    target: { value: " " }
  });
  expect(savePasskeyButton).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Credential ID"), {
    target: { value: "credential-new" }
  });
  expect(savePasskeyButton).not.toBeDisabled();
  fireEvent.click(screen.getByLabelText("Backup state"));
  fireEvent.click(savePasskeyButton);

  await waitFor(() => {
    expect(setEntryPasskey).toHaveBeenCalledWith(
      "vault-1",
      "entry-1",
      editedPasskey
    );
  });
  expect(saveVault).toHaveBeenCalledWith("vault-1");
  await waitFor(() => {
    expect(screen.queryByText("credential-new")).not.toBeInTheDocument();
  });
  fireEvent.click(screen.getByRole("button", { name: "Show Credential ID" }));
  expect(await screen.findByText("credential-new")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Clear passkey" }));

  await waitFor(() => {
    expect(clearEntryPasskey).toHaveBeenCalledWith("vault-1", "entry-1");
  });
  expect(saveVault).toHaveBeenCalledTimes(2);
  expect(await screen.findByText("No passkey.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Add passkey" })).not.toBeInTheDocument();
});

it("retries a failed passkey save without clearing the passkey again", async () => {
  const passkey = {
    username: "alice@example.com",
    credentialId: "credential-old",
    generatedUserId: null,
    relyingParty: "example.com",
    userHandle: null,
    backupEligible: true,
    backupState: false
  };
  const clearEntryPasskey = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "GitHub",
    username: "alice",
    password: "secret",
    url: "https://github.com",
    notes: "",
    totp: null,
    totpUri: null,
    passkey: null,
    customFields: [],
    attachments: []
  }));
  const saveVault = vi
    .fn()
    .mockRejectedValueOnce(new Error("simulated passkey save failure"))
    .mockResolvedValueOnce(undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: "",
      totp: null,
      totpUri: null,
      passkey,
      customFields: [],
      attachments: []
    }),
    clearEntryPasskey,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "GitHub" }));
  fireEvent.click(await screen.findByRole("button", { name: "Clear passkey" }));

  expect(await screen.findByText("simulated passkey save failure")).toBeInTheDocument();
  expect(clearEntryPasskey).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: "Retry save" }));

  await waitFor(() => expect(saveVault).toHaveBeenCalledTimes(2));
  expect(clearEntryPasskey).toHaveBeenCalledTimes(1);
});

it("renders localized passkey reveal labels without English password fragments", () => {
  render(
    <I18nProvider language="zh-CN">
      <EntryEditor
        entry={{
          type: "entry_detail",
          id: "entry-1",
          title: "GitHub",
          username: "alice",
          password: "secret",
          url: "https://github.com",
          notes: "",
          totp: null,
          totpUri: null,
          passkey: {
            username: "alice@example.com",
            credentialId: "credential-old",
            generatedUserId: "generated-user",
            relyingParty: "example.com",
            userHandle: "user-handle",
            backupEligible: true,
            backupState: false
          },
          customFields: [],
          attachments: []
        }}
        mode="view"
        draft={null}
        dirty={false}
        onChangeDraft={vi.fn()}
        onChangeCustomField={vi.fn()}
        onAddCustomField={vi.fn()}
        onDeleteCustomField={vi.fn()}
        onSave={vi.fn()}
        onCancel={vi.fn()}
        onDelete={vi.fn()}
      />
    </I18nProvider>
  );

  expect(screen.getByRole("button", { name: "显示 凭据 ID" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "显示密码 凭据 ID" })).not.toBeInTheDocument();
});

it("renders a setup empty state and starts the local add flow", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => []),
    addLocalVaultReference: vi.fn(async () => ({
      vaultRefId: "vault-ref-1",
      displayName: "Demo",
      sourceKind: "local",
      sourceSummary: "demo.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: true
    })),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));
  fireEvent.click(screen.getByRole("button", { name: "Local File" }));

  expect(client.addLocalVaultReference).toHaveBeenCalledTimes(1);
});

it("starts OneDrive setup and adds the selected kdbx file", async () => {
  const open = vi.spyOn(window, "open").mockImplementation(() => null);
  const prompt = vi.spyOn(window, "prompt");
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => []),
    beginOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_session" as const,
      authUrl: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      redirectUri: "http://127.0.0.1:53121/callback",
      expiresInSeconds: 600
    })),
    completePendingOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status" as const,
      status: "authorized",
      accountLabel: "alice@example.com"
    })),
    listOneDriveChildren: vi.fn(async () => [
      {
        driveId: "drive-1",
        itemId: "item-1",
        name: "Work Vault.kdbx",
        folder: false,
        size: 42
      },
      {
        driveId: "drive-1",
        itemId: "item-2",
        name: "Home Vault.kdbx",
        folder: false,
        size: 84
      }
    ]),
    addOneDriveVaultReference: vi.fn(async () => ({
      vaultRefId: "onedrive-ref-1",
      displayName: "Cloud Vault",
      sourceKind: "onedrive",
      sourceSummary: "alice@example.com / Cloud Vault.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: true
    })),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));
  fireEvent.click(screen.getByRole("button", { name: "OneDrive" }));

  await waitFor(() => {
    expect(client.beginOneDriveLogin).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledWith(
      "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      "_blank",
      "noopener,noreferrer"
    );
    expect(prompt).not.toHaveBeenCalled();
    expect(client.completePendingOneDriveLogin).toHaveBeenCalledTimes(1);
    expect(client.listOneDriveChildren).toHaveBeenCalledWith(null);
    expect(client.addOneDriveVaultReference).not.toHaveBeenCalled();
  });

  fireEvent.click(screen.getByRole("button", { name: "Home Vault.kdbx" }));

  await waitFor(() => {
    expect(client.addOneDriveVaultReference).toHaveBeenCalledWith("drive-1", "item-2");
  });

  open.mockRestore();
  prompt.mockRestore();
});

it("browses OneDrive folders before adding a nested kdbx file", async () => {
  const open = vi.spyOn(window, "open").mockImplementation(() => null);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => []),
    beginOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_session" as const,
      authUrl: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      redirectUri: "http://127.0.0.1:53121/callback",
      expiresInSeconds: 600
    })),
    completePendingOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status" as const,
      status: "authorized",
      accountLabel: "alice@example.com"
    })),
    listOneDriveChildren: vi.fn(async (parentItemId?: string | null) => {
      if (parentItemId === "folder-1") {
        return [
          {
            driveId: "drive-1",
            itemId: "item-2",
            name: "Nested Vault.kdbx",
            folder: false,
            size: 128
          }
        ];
      }
      return [
        {
          driveId: "drive-1",
          itemId: "folder-1",
          name: "Work",
          folder: true,
          size: null
        }
      ];
    }),
    addOneDriveVaultReference: vi.fn(async () => ({
      vaultRefId: "onedrive-ref-1",
      displayName: "Nested Vault",
      sourceKind: "onedrive",
      sourceSummary: "alice@example.com / Nested Vault.kdbx",
      lastUsedAt: 1776500000,
      availability: "ready",
      supportsQuickUnlock: false,
      isCurrent: true
    })),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));
  fireEvent.click(screen.getByRole("button", { name: "OneDrive" }));

  await waitFor(() => {
    expect(client.listOneDriveChildren).toHaveBeenCalledWith(null);
  });

  fireEvent.click(await screen.findByRole("button", { name: "Work" }));

  await waitFor(() => {
    expect(client.listOneDriveChildren).toHaveBeenCalledWith("folder-1");
  });

  fireEvent.click(await screen.findByRole("button", { name: "Nested Vault.kdbx" }));

  await waitFor(() => {
    expect(client.addOneDriveVaultReference).toHaveBeenCalledWith("drive-1", "item-2");
  });

  open.mockRestore();
});

it("shows a visible setup error when adding a local vault fails", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }),
    listRecentVaults: vi.fn(async () => []),
    addLocalVaultReference: vi.fn().mockRejectedValue(
      Object.assign(new Error("native port disconnected"), {
        code: "native_port_disconnected"
      })
    ),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(
    <App
      client={client}
      renderRuntimeErrorHelp={(error) =>
        (error as { code?: string }).code === "native_port_disconnected" ? (
          <div>Restart native host</div>
        ) : null
      }
    />
  );

  fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));
  fireEvent.click(screen.getByRole("button", { name: "Local File" }));

  expect(await screen.findByRole("alert")).toHaveTextContent(
    "native port disconnected"
  );
  expect(screen.getByText("Restart native host")).toBeInTheDocument();
});

it("removes a recent vault record from manager setup without deleting the database file", async () => {
  let vaults = [
    {
      vaultRefId: "vault-ref-1",
      displayName: "Personal",
      sourceKind: "local",
      sourceSummary: "personal.kdbx",
      lastUsedAt: 1776500000,
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
    }
  ];
  const deleteRecentVault = vi.fn(async (vaultRefId: string) => {
    vaults = vaults
      .filter((vault) => vault.vaultRefId !== vaultRefId)
      .map((vault) => ({ ...vault, isCurrent: true }));
    return vaults;
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    }),
    listRecentVaults: vi.fn(async () => vaults),
    deleteRecentVault,
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Manage vaults" }));
  expect(await screen.findByText("Personal")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Remove Personal record" }));

  await waitFor(() => {
    expect(deleteRecentVault).toHaveBeenCalledWith("vault-ref-1");
  });
  expect(screen.queryByText("Personal")).not.toBeInTheDocument();
  expect(screen.getByText("Work")).toBeInTheDocument();
  expect(screen.getByText("This only removes the recent vault record.")).toBeInTheDocument();
});

it("shows a repair action when the current vault reference is unavailable", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    }),
    listRecentVaults: vi.fn(async () => [
      {
        vaultRefId: "vault-ref-1",
        displayName: "Broken Vault",
        sourceKind: "local",
        sourceSummary: "missing.kdbx",
        lastUsedAt: 1776500000,
        availability: "needs_repair",
        supportsQuickUnlock: false,
        isCurrent: true
      }
    ]),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  expect(await screen.findByText("Broken Vault")).toBeInTheDocument();
  expect(screen.getByText("Needs repair in manager")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Manage vaults" }).length).toBeGreaterThan(0);
});

it("clears stale details before showing the newly selected entry", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 1280;

  const secondDetail = createDeferred<Awaited<
    ReturnType<RuntimeClientLike["getEntryDetail"]>
  >>();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn(async (_vaultId: string) => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Demo Vault",
        entryCount: 2,
        childCount: 0,
        children: []
      }
    })),
    listEntries: async (_vaultId: string) => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      },
      {
        id: "entry-2",
        title: "Admin",
        username: "bob",
        url: "https://admin.example.com",
        groupId: "group-root"
      }
    ],
    getEntryDetail: vi.fn(async (_vaultId: string, entryId: string) => {
      if (entryId === "entry-1") {
        return {
          type: "entry_detail" as const,
          id: "entry-1",
          title: "Example",
          username: "alice",
          password: "secret-123",
          url: "https://example.com",
          notes: "demo note"
        };
      }

      return secondDetail.promise;
    })
  };

  try {
    render(<App client={client} />);
    fireEvent(window, new Event("resize"));

    fireEvent.click(await screen.findByRole("button", { name: "Example" }));

    expect(await screen.findByDisplayValue("Example")).toBeInTheDocument();
    expect(screen.getByDisplayValue("secret-123")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Admin" }));

    expect(screen.getByText("Select an entry to view details.")).toBeInTheDocument();
    expect(screen.queryByDisplayValue("Example")).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("secret-123")).not.toBeInTheDocument();

    secondDetail.resolve({
      type: "entry_detail",
      id: "entry-2",
      title: "Admin",
      username: "bob",
      password: "root-secret",
      url: "https://admin.example.com",
      notes: "admin note"
    });

    expect(await screen.findByDisplayValue("Admin")).toBeInTheDocument();
    expect(screen.getByDisplayValue("bob")).toBeInTheDocument();
    expect(screen.getByDisplayValue("root-secret")).toBeInTheDocument();
    expect(screen.queryByDisplayValue("Example")).not.toBeInTheDocument();
    expect(client.getEntryDetail).toHaveBeenNthCalledWith(1, "vault-1", "entry-1");
    expect(client.getEntryDetail).toHaveBeenNthCalledWith(2, "vault-1", "entry-2");
  } finally {
    window.innerWidth = originalInnerWidth;
  }
});

it("renders the manager workspace with group tree and global search when unlocked", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 1,
        children: [
          {
            id: "group-personal",
            title: "Personal",
            entryCount: 1,
            childCount: 0,
            children: []
          }
        ]
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-personal"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: ""
    })
  };

  render(<App client={client} />);

  expect(await screen.findByPlaceholderText("Search the archive")).toBeInTheDocument();
  expect(await screen.findByRole("button", { name: "Personal" })).toBeInTheDocument();
  expect(screen.getByText("Entries")).toBeInTheDocument();
  expect(client.listGroups).toHaveBeenCalledWith("vault-1");
});

it("shows each group's own entry count instead of child count", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 2,
        childCount: 7,
        children: [
          {
            id: "group-child",
            title: "Personal",
            entryCount: 1,
            childCount: 0,
            children: []
          }
        ]
      }
    }),
    listEntries: vi.fn().mockResolvedValue([]),
    getEntryDetail: vi.fn()
  };

  render(<App client={client as any} />);

  expect(await screen.findByRole("button", { name: /Archive/ })).toHaveTextContent("2");
  expect(screen.getByRole("button", { name: /Personal/ })).toHaveTextContent("1");
});

it("edits an entry only after explicit save and confirms unsaved navigation", async () => {
  const saveVault = vi.fn(async () => undefined);
  const updateEntryFields = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Edited Title",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: [
      {
        key: "RecoveryCode",
        value: "edited-code",
        protected: true
      },
      {
        key: "Region",
        value: "us",
        protected: false
      }
    ]
  }));

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 2,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      },
      {
        id: "entry-2",
        title: "Admin",
        username: "bob",
        url: "https://admin.example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async (_vaultId: string, entryId: string) => ({
      type: "entry_detail" as const,
      id: entryId,
      title: entryId === "entry-1" ? "Example" : "Admin",
      username: entryId === "entry-1" ? "alice" : "bob",
      password: entryId === "entry-1" ? "secret-123" : "root-secret",
      url:
        entryId === "entry-1"
          ? "https://example.com"
          : "https://admin.example.com",
      notes: entryId === "entry-1" ? "demo note" : "admin note",
      totp: null,
      totpUri: null,
      customFields:
        entryId === "entry-1"
          ? [
              {
                key: "RecoveryCode",
                value: "old-code",
                protected: true
              }
            ]
          : []
    })),
    updateEntryFields,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Edited Title" }
  });
  fireEvent.change(screen.getByLabelText("RecoveryCode value"), {
    target: { value: "edited-code" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Add property" }));
  fireEvent.change(screen.getByLabelText("Property 2 key"), {
    target: { value: "Region" }
  });
  fireEvent.change(screen.getByLabelText("Region value"), {
    target: { value: "us" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Admin" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  expect(updateEntryFields).not.toHaveBeenCalled();

  const saveChanges = screen.getByRole("button", { name: "Save changes" });
  fireEvent.click(saveChanges);
  fireEvent.click(saveChanges);

  await waitFor(() => {
    expect(updateEntryFields).toHaveBeenCalledWith("vault-1", "entry-1", {
      title: "Edited Title",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totpUri: null,
      customFields: [
        {
          key: "RecoveryCode",
          value: "edited-code",
          protected: true
        },
        {
          key: "Region",
          value: "us",
          protected: false
        }
      ]
    });
  });
  await waitFor(() => {
    expect(saveVault).toHaveBeenCalledWith("vault-1");
  });
  expect(updateEntryFields).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);
});

it("shows an animated saving indicator while entry changes are being saved", async () => {
  const update = createDeferred<{
    type: "entry_detail";
    id: string;
    title: string;
    username: string;
    password: string;
    url: string;
    notes: string;
    totp: null;
    totpUri: null;
    customFields: [];
  }>();
  const updateEntryFields = vi.fn(() => update.promise);
  const saveVault = vi.fn(async () => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null,
      customFields: []
    })),
    updateEntryFields,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Edited Title" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  const savingButton = await screen.findByRole("button", { name: "Saving..." });
  expect(savingButton).toHaveAttribute("aria-busy", "true");
  expect(screen.getByTestId("entry-save-spinner")).toHaveStyle({
    animation: "vaultkern-save-spin 0.8s linear infinite"
  });

  update.resolve({
    type: "entry_detail",
    id: "entry-1",
    title: "Edited Title",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: []
  });

  await waitFor(() => {
    expect(saveVault).toHaveBeenCalledWith("vault-1");
  });
});

it("coalesces save-and-continue with an entry save already in flight", async () => {
  const update = createDeferred<{
    type: "entry_detail";
    id: string;
    title: string;
    username: string;
    password: string;
    url: string;
    notes: string;
    totp: null;
    totpUri: null;
    customFields: [];
  }>();
  const updateEntryFields = vi.fn(() => update.promise);
  const saveVault = vi.fn(async () => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null,
      customFields: []
    })),
    updateEntryFields,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Edited Title" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await screen.findByRole("button", { name: "Saving..." });

  fireEvent.click(screen.getByRole("button", { name: "Statistics" }));
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  expect(updateEntryFields).toHaveBeenCalledTimes(1);

  update.resolve({
    type: "entry_detail",
    id: "entry-1",
    title: "Edited Title",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: []
  });

  expect(await screen.findByRole("heading", { name: "Statistics" })).toBeInTheDocument();
  expect(updateEntryFields).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);
});

it("shows an auto-dismiss tip when save merges a changed source", async () => {
  const settingsStore = createSettingsStore();
  settingsStore.reconcile = vi.fn(async () => undefined);
  const saveVault = vi.fn(async () => ({
    type: "save_vault_result" as const,
    status: "merged" as const,
    mergeSummary: {
      mergedEntries: 1,
      historySnapshotsAdded: 0
    }
  }));
  const updateEntryFields = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Local Title",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: []
  }));

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi
      .fn()
      .mockResolvedValueOnce({
        type: "entry_detail" as const,
        id: "entry-1",
        title: "Example",
        username: "alice",
        password: "secret-123",
        url: "https://example.com",
        notes: "demo note",
        totp: null,
        totpUri: null,
        customFields: []
      })
      .mockResolvedValueOnce({
        type: "entry_detail" as const,
        id: "entry-1",
        title: "Remote Winner",
        username: "alice",
        password: "secret-123",
        url: "https://example.com",
        notes: "demo note",
        totp: null,
        totpUri: null,
        customFields: []
      }),
    updateEntryFields,
    saveVault
  };

  render(
    <App
      client={client as any}
      extensionSettingsStore={settingsStore}
    />
  );

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Local Title" }
  });
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });

  expect(screen.getByText("Vault changed on disk. Merged and saved.")).toBeInTheDocument();
  expect(screen.getByText("Remote Winner")).toBeInTheDocument();
  expect(client.getEntryDetail).toHaveBeenCalledTimes(2);
  expect(client.listEntryHistory).toHaveBeenCalledTimes(2);

  await act(async () => {
    vi.advanceTimersByTime(3000);
  });

  expect(
    screen.queryByText("Vault changed on disk. Merged and saved.")
  ).not.toBeInTheDocument();
});

it("shows a pending sync banner when save falls back to local cache", async () => {
  const saveVault = vi.fn(async () => ({
    type: "save_vault_result" as const,
    status: "saved_to_cache" as const,
    mergeSummary: null
  }));
  const updateEntryFields = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Pending Local",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: []
  }));

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: null
      }
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null,
      customFields: []
    })),
    updateEntryFields,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Pending Local" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  expect(
    await screen.findAllByText("Saved to local cache. Remote sync pending.")
  ).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Retry sync" })).toBeInTheDocument();
});

it("shows remote cache warning and retries source sync", async () => {
  let remoteRestored = false;
  const retryVaultSourceSync = vi.fn(async () => {
    remoteRestored = true;
    return {
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    };
  });
  const listEntries = vi.fn(async () =>
    [
      {
        id: "entry-shared",
        title: remoteRestored ? "Remote Updated" : "Cached Entry",
        username: remoteRestored ? "remote-user" : "cached-user",
        url: "https://remote.example",
        groupId: "group-root"
      }
    ]
  );
  const cachedDetail = createDeferred<{
    id: string;
    title: string;
    username: string;
    password: string;
    url: string;
    notes: string;
    totp: null;
    totpUri: null;
    customFields: never[];
  }>();
  const remoteDetail = {
    id: "entry-shared",
    title: "Remote Updated",
    username: "remote-user",
    password: "secret-123",
    url: "https://remote.example",
    notes: "remote note",
    totp: null,
    totpUri: null,
    customFields: []
  };
  const getEntryDetail = vi.fn(() =>
    remoteRestored ? Promise.resolve(remoteDetail) : cachedDetail.promise
  );
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    }),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries,
    getEntryDetail,
    retryVaultSourceSync
  };

  render(<App client={client as any} />);

  expect(
    await screen.findByText("Using local cache. Remote sync failed.")
  ).toBeInTheDocument();
  expect(screen.getByText("OneDrive unavailable")).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Cached Entry" }));
  await waitFor(() => {
    expect(getEntryDetail).toHaveBeenCalledTimes(1);
  });

  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));

  await waitFor(() => {
    expect(retryVaultSourceSync).toHaveBeenCalledWith("vault-1");
  });
  await waitFor(() => {
    expect(
      screen.queryByText("Using local cache. Remote sync failed.")
    ).not.toBeInTheDocument();
  });
  await waitFor(() => {
    expect(listEntries).toHaveBeenCalledTimes(2);
    expect(getEntryDetail).toHaveBeenCalledTimes(2);
  });
  expect(await screen.findByText("remote note")).toBeInTheDocument();
  await act(async () => {
    cachedDetail.resolve({
      id: "entry-shared",
      title: "Cached Entry",
      username: "cached-user",
      password: "secret-123",
      url: "https://remote.example",
      notes: "cached note",
      totp: null,
      totpUri: null,
      customFields: []
    });
    await Promise.resolve();
  });
  expect(screen.queryByText("cached note")).not.toBeInTheDocument();
});

it("rebases an unsaved entry draft after source sync", async () => {
  let sourceRestored = false;
  const initialDetail = {
    type: "entry_detail" as const,
    id: "entry-shared",
    title: "Cached Entry",
    username: "cached-user",
    password: "secret-123",
    url: "https://remote.example",
    notes: "cached note",
    totp: null,
    totpUri: null,
    customFields: [
      { key: "Local", value: "cached", protected: false },
      { key: "Remote", value: "before", protected: false }
    ]
  };
  const remoteDetail = {
    ...initialDetail,
    title: "Remote Title",
    username: "remote-user",
    notes: "remote note",
    customFields: [
      { key: "Local", value: "cached", protected: false },
      { key: "Remote", value: "after", protected: false }
    ]
  };
  const getEntryDetail = vi.fn(async () =>
    sourceRestored ? remoteDetail : initialDetail
  );
  const retryVaultSourceSync = vi.fn(async () => {
    sourceRestored = true;
    return {
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    };
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    }),
    listEntries: vi.fn(async () => [
      {
        id: "entry-shared",
        title: sourceRestored ? "Remote Title" : "Cached Entry",
        username: sourceRestored ? "remote-user" : "cached-user",
        url: "https://remote.example",
        groupId: "group-root"
      }
    ]),
    getEntryDetail,
    retryVaultSourceSync
  };

  render(<App client={client as RuntimeClientLike} />);

  fireEvent.click(await screen.findByRole("button", { name: "Cached Entry" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Local Draft" }
  });
  fireEvent.change(screen.getByLabelText("Local value"), {
    target: { value: "local draft" }
  });

  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));

  await waitFor(() => {
    expect(getEntryDetail).toHaveBeenCalledTimes(2);
    expect(screen.getByLabelText("Username")).toHaveValue("remote-user");
  });
  expect(screen.getByLabelText("Title")).toHaveValue("Local Draft");
  expect(screen.getByLabelText("Notes")).toHaveValue("remote note");
  expect(screen.getByLabelText("Local value")).toHaveValue("local draft");
  expect(screen.getByLabelText("Remote value")).toHaveValue("after");
});

it("keeps the unsaved-entry guard while source detail is reloading", async () => {
  const sourceDetailReload = createDeferred<{
    id: string;
    title: string;
    username: string;
    password: string;
    url: string;
    notes: string;
    totp: null;
    totpUri: null;
    customFields: never[];
  }>();
  const initialDetail = {
    id: "entry-shared",
    title: "Cached Entry",
    username: "cached-user",
    password: "secret-123",
    url: "https://remote.example",
    notes: "cached note",
    totp: null,
    totpUri: null,
    customFields: []
  };
  const getEntryDetail = vi
    .fn()
    .mockResolvedValueOnce(initialDetail)
    .mockImplementationOnce(() => sourceDetailReload.promise);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    }),
    listEntries: vi.fn(async () => [
      {
        id: "entry-shared",
        title: "Cached Entry",
        username: "cached-user",
        url: "https://remote.example",
        groupId: "group-root"
      }
    ]),
    getEntryDetail,
    retryVaultSourceSync: vi.fn(async () => ({
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    }))
  };

  render(<App client={client as RuntimeClientLike} />);

  fireEvent.click(await screen.findByRole("button", { name: "Cached Entry" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Unsaved Local Draft" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));
  await waitFor(() => expect(getEntryDetail).toHaveBeenCalledTimes(2));

  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  await act(async () => {
    sourceDetailReload.resolve({ ...initialDetail, title: "Remote Entry" });
    await Promise.resolve();
  });
});

it("keeps the unsaved-entry guard when source detail reload fails", async () => {
  const initialDetail = {
    id: "entry-shared",
    title: "Cached Entry",
    username: "cached-user",
    password: "secret-123",
    url: "https://remote.example",
    notes: "cached note",
    totp: null,
    totpUri: null,
    customFields: []
  };
  const getEntryDetail = vi
    .fn()
    .mockResolvedValueOnce(initialDetail)
    .mockRejectedValue(new Error("simulated source detail reload failure"));
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: "OneDrive unavailable"
      }
    }),
    listEntries: vi.fn(async () => [
      {
        id: "entry-shared",
        title: "Cached Entry",
        username: "cached-user",
        url: "https://remote.example",
        groupId: "group-root"
      }
    ]),
    getEntryDetail,
    retryVaultSourceSync: vi.fn(async () => ({
      type: "vault_source_status" as const,
      sourceKind: "onedrive",
      remoteState: "online",
      lastSyncAt: 1776500060,
      cachedAt: 1776500030,
      lastError: null
    }))
  };

  render(<App client={client as RuntimeClientLike} />);

  fireEvent.click(await screen.findByRole("button", { name: "Cached Entry" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "Unsaved Local Draft" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));
  expect(
    await screen.findByText("simulated source detail reload failure")
  ).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Database Settings" }));

  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
});

it("shows remote cache info without failure copy before sync is retried", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      sourceStatus: {
        sourceKind: "onedrive",
        remoteState: "cache",
        lastSyncAt: null,
        cachedAt: 1776500030,
        lastError: null
      }
    }),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [])
  };

  render(<App client={client as any} />);

  expect(await screen.findByText("Using local cache.")).toBeInTheDocument();
  expect(
    screen.queryByText("Using local cache. Remote sync failed.")
  ).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry sync" })).toBeInTheDocument();
});

it("creates a new entry and deletes it after explicit confirmation", async () => {
  const listEntries = vi
    .fn()
    .mockResolvedValueOnce([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ])
    .mockResolvedValueOnce([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      },
      {
        id: "entry-new",
        title: "Created",
        username: "new-user",
        url: "",
        groupId: "group-root"
      }
    ])
    .mockResolvedValueOnce([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]);
  const createEntry = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-new",
    title: "Created",
    username: "new-user",
    password: "new-secret",
    url: "",
    notes: "",
    totp: null,
    totpUri: null
  }));
  const deleteEntry = vi.fn(async () => undefined);
  const saveVault = vi.fn(async () => undefined);

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries,
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null
    })),
    createEntry,
    deleteEntry,
    saveVault
  };

  render(<App client={client as any} />);

  expect(await screen.findByRole("button", { name: "New Entry" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New Entry" }));
  fireEvent.change(await screen.findByLabelText("Title"), {
    target: { value: "Created" }
  });
  fireEvent.change(screen.getByLabelText("Username"), {
    target: { value: "new-user" }
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: "new-secret" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await waitFor(() => {
    expect(createEntry).toHaveBeenCalledWith("vault-1", {
      parentGroupId: "group-root",
      title: "Created",
      username: "new-user",
      password: "new-secret",
      url: "",
      notes: "",
      totpUri: null,
      customFields: []
    });
  });
  await waitFor(() => {
    expect(saveVault).toHaveBeenCalledWith("vault-1");
  });

  expect(await screen.findByRole("button", { name: "Created" })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Delete Entry" }));
  expect(await screen.findByText("Delete this entry permanently?")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Delete permanently" }));

  await waitFor(() => {
    expect(deleteEntry).toHaveBeenCalledWith("vault-1", "entry-new");
  });
  await waitFor(() => {
    expect(saveVault).toHaveBeenCalledTimes(2);
  });
});

it("retries a failed create save without creating the entry again", async () => {
  const createEntry = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-new",
    title: "Created once",
    username: "",
    password: "",
    url: "",
    notes: "",
    totp: null,
    totpUri: null,
    customFields: []
  }));
  const saveVault = vi
    .fn()
    .mockRejectedValueOnce(new Error("simulated durable save failure"))
    .mockResolvedValueOnce(undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn(),
    createEntry,
    saveVault
  };

  render(<App client={client as any} />);

  await screen.findByText("No entries available.");
  fireEvent.click(await screen.findByRole("button", { name: "New Entry" }));
  fireEvent.change(await screen.findByLabelText("Title"), {
    target: { value: "Created once" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  expect(await screen.findByText("simulated durable save failure")).toBeInTheDocument();
  expect(createEntry).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(
    await screen.findByText(
      "This entry changed in the current session but is not durable yet. Retry saving before leaving it."
    )
  ).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Discard changes" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Continue editing" }));

  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await waitFor(() => expect(saveVault).toHaveBeenCalledTimes(2));
  expect(createEntry).toHaveBeenCalledTimes(1);
});

it("retries a failed delete save without deleting the entry again", async () => {
  const deleteEntry = vi.fn(async () => undefined);
  const saveVault = vi
    .fn()
    .mockRejectedValueOnce(new Error("simulated delete save failure"))
    .mockResolvedValueOnce(undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret",
      url: "https://example.com",
      notes: "",
      totp: null,
      totpUri: null,
      customFields: []
    })),
    deleteEntry,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Delete Entry" }));
  fireEvent.click(await screen.findByRole("button", { name: "Delete permanently" }));

  expect(await screen.findByText("simulated delete save failure")).toBeInTheDocument();
  expect(deleteEntry).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);

  fireEvent.click(
    screen.getByRole("button", { name: "Statistics", hidden: true })
  );
  expect(await screen.findByText("You have unsaved changes")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Discard changes" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await waitFor(() => expect(saveVault).toHaveBeenCalledTimes(2));
  expect(deleteEntry).toHaveBeenCalledTimes(1);
  expect(await screen.findByRole("heading", { name: "Statistics" })).toBeInTheDocument();
});

it("generates a password into the entry editor only after explicit use", async () => {
  const originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      getRandomValues: vi.fn((array: Uint8Array) => {
        array.fill(0);
        return array;
      })
    }
  });

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn(async () => []),
    saveVault: vi.fn(async () => undefined)
  };

  try {
    render(<App client={client as any} />);

    fireEvent.click(await screen.findByRole("button", { name: "New Entry" }));
    const passwordInput = await screen.findByLabelText("Password");
    expect(passwordInput).toHaveValue("");

    fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    expect(screen.getByText("Password Generator")).toBeInTheDocument();
    expect(passwordInput).toHaveValue("");

    fireEvent.click(screen.getByRole("button", { name: "Use password" }));
    const generatedPassword = (passwordInput as HTMLInputElement).value;
    expect(generatedPassword).toHaveLength(20);
    expect(generatedPassword).toMatch(/[A-Z]/);
    expect(generatedPassword).toMatch(/[a-z]/);
    expect(generatedPassword).toMatch(/[0-9]/);
    expect(generatedPassword).toMatch(/[^A-Za-z0-9]/);
  } finally {
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: originalCrypto
    });
  }
});

it("manages entry attachments from the detail pane", async () => {
  const saveVault = vi.fn(async () => undefined);
  const getEntryAttachmentContent = vi.fn(async () => ({
    type: "entry_attachment_content" as const,
    name: "backup.txt",
    dataBase64: "aGVsbG8=",
    protectInMemory: true
  }));
  const updateEntryAttachmentMetadata = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Example",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    attachments: [
      {
        name: "backup-renamed.txt",
        size: 5,
        protectInMemory: false
      }
    ]
  }));
  const addEntryAttachment = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Example",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    attachments: [
      {
        name: "added.txt",
        size: 5,
        protectInMemory: false
      }
    ]
  }));
  const deleteEntryAttachment = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Example",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    attachments: []
  }));

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null,
      attachments: [
        {
          name: "backup.txt",
          size: 5,
          protectInMemory: true
        }
      ]
    })),
    getEntryAttachmentContent,
    updateEntryAttachmentMetadata,
    addEntryAttachment,
    deleteEntryAttachment,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Download backup.txt" }));

  await waitFor(() => {
    expect(getEntryAttachmentContent).toHaveBeenCalledWith(
      "vault-1",
      "entry-1",
      "backup.txt"
    );
  });

  fireEvent.click(screen.getByRole("button", { name: "Edit" }));
  fireEvent.change(screen.getByLabelText("Rename backup.txt"), {
    target: { value: "backup-renamed.txt" }
  });
  fireEvent.blur(screen.getByLabelText("Rename backup.txt"));

  await waitFor(() => {
    expect(updateEntryAttachmentMetadata).toHaveBeenCalledWith(
      "vault-1",
      "entry-1",
      {
        oldName: "backup.txt",
        newName: "backup-renamed.txt",
        protectInMemory: true
      }
    );
  });

  const file = new File(["hello"], "added.txt", { type: "text/plain" });
  fireEvent.change(screen.getByLabelText("Add attachment file"), {
    target: { files: [file] }
  });

  await waitFor(() => {
    expect(addEntryAttachment).toHaveBeenCalledWith("vault-1", "entry-1", {
      name: "added.txt",
      dataBase64: "aGVsbG8=",
      protectInMemory: false
    });
  });

  fireEvent.click(await screen.findByRole("button", { name: "Remove added.txt" }));

  await waitFor(() => {
    expect(deleteEntryAttachment).toHaveBeenCalledWith(
      "vault-1",
      "entry-1",
      "added.txt"
    );
  });
  expect(saveVault).toHaveBeenCalledTimes(3);
});

it("routes oversized browser attachment downloads to the Windows app", async () => {
  const getEntryAttachmentContent = vi.fn();
  const settingsStore = createSettingsStore();
  settingsStore.surface = "browser";
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "",
      totp: null,
      totpUri: null,
      attachments: [
        {
          name: "archive.bin",
          size: 800_000,
          protectInMemory: false
        }
      ]
    }),
    getEntryAttachmentContent
  };

  render(
    <App client={client as any} extensionSettingsStore={settingsStore} />
  );

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  const download = await screen.findByRole("button", {
    name: "Download archive.bin"
  });

  expect(download).toBeDisabled();
  expect(
    screen.getByText("Open the Windows app to download this large attachment.")
  ).toBeInTheDocument();
  expect(getEntryAttachmentContent).not.toHaveBeenCalled();
});

it("does not deliver an attachment response after the selected entry changes", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 1280;
  const attachment = createDeferred<{
    type: "entry_attachment_content";
    name: string;
    dataBase64: string;
    protectInMemory: boolean;
  }>();
  const originalUserAgent = Object.getOwnPropertyDescriptor(navigator, "userAgent");
  Object.defineProperty(navigator, "userAgent", {
    configurable: true,
    value: "Chrome"
  });
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 2,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "First",
        username: "alice",
        url: "https://example.com/first",
        groupId: "group-root"
      },
      {
        id: "entry-2",
        title: "Second",
        username: "bob",
        url: "https://example.com/second",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async (_vaultId: string, entryId: string) => ({
      type: "entry_detail" as const,
      id: entryId,
      title: entryId === "entry-1" ? "First" : "Second",
      username: entryId === "entry-1" ? "alice" : "bob",
      password: entryId === "entry-1" ? "first-secret" : "second-secret",
      url: `https://example.com/${entryId}`,
      notes: "",
      totp: null,
      totpUri: null,
      attachments:
        entryId === "entry-1"
          ? [{ name: "first.bin", size: 4, protectInMemory: true }]
          : []
    })),
    getEntryAttachmentContent: vi.fn(() => attachment.promise)
  };

  try {
    render(<App client={client as any} />);
    fireEvent(window, new Event("resize"));
    fireEvent.click(await screen.findByRole("button", { name: "First" }));
    fireEvent.click(await screen.findByRole("button", { name: "Download first.bin" }));
    await waitFor(() => expect(client.getEntryAttachmentContent).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: "Second" }));
    attachment.resolve({
      type: "entry_attachment_content",
      name: "first.bin",
      dataBase64: "c2VjcmV0",
      protectInMemory: true
    });
    await act(async () => {
      await attachment.promise;
    });

    expect(click).not.toHaveBeenCalled();
  } finally {
    window.innerWidth = originalInnerWidth;
    click.mockRestore();
    if (originalUserAgent) {
      Object.defineProperty(navigator, "userAgent", originalUserAgent);
    } else {
      delete (navigator as Navigator & { userAgent?: string }).userAgent;
    }
  }
});

it("does not deliver an attachment response after a resident lock notification", async () => {
  const attachment = createDeferred<{
    type: "entry_attachment_content";
    name: string;
    dataBase64: string;
    protectInMemory: boolean;
  }>();
  let publishSessionState!: (state: {
    unlocked: boolean;
    activeVaultId: string | null;
    currentVaultRefId: string | null;
  }) => void;
  const originalUserAgent = Object.getOwnPropertyDescriptor(navigator, "userAgent");
  Object.defineProperty(navigator, "userAgent", {
    configurable: true,
    value: "Chrome"
  });
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    })),
    listGroups: vi.fn(async () => ({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "resident-secret",
      url: "https://example.com",
      notes: "",
      totp: null,
      totpUri: null,
      attachments: [{ name: "secret.bin", size: 6, protectInMemory: true }]
    })),
    getEntryAttachmentContent: vi.fn(() => attachment.promise)
  } satisfies RuntimeClientLike;

  try {
    render(
      <App
        client={client}
        subscribeSessionState={vi.fn(async (listener) => {
          publishSessionState = listener;
          return () => undefined;
        })}
      />
    );
    fireEvent.click(await screen.findByRole("button", { name: "Example" }));
    fireEvent.click(await screen.findByRole("button", { name: "Download secret.bin" }));
    await waitFor(() => expect(client.getEntryAttachmentContent).toHaveBeenCalledTimes(1));

    await act(async () => {
      publishSessionState({
        unlocked: false,
        activeVaultId: null,
        currentVaultRefId: "vault-ref-1"
      });
      attachment.resolve({
        type: "entry_attachment_content",
        name: "secret.bin",
        dataBase64: "c2VjcmV0",
        protectInMemory: true
      });
      await attachment.promise;
    });

    expect(click).not.toHaveBeenCalled();
  } finally {
    click.mockRestore();
    if (originalUserAgent) {
      Object.defineProperty(navigator, "userAgent", originalUserAgent);
    } else {
      delete (navigator as Navigator & { userAgent?: string }).userAgent;
    }
  }
});

it("does not deliver an attachment after authoritative session refresh fails", async () => {
  const attachment = createDeferred<{
    type: "entry_attachment_content";
    name: string;
    dataBase64: string;
    protectInMemory: boolean;
  }>();
  const originalUserAgent = Object.getOwnPropertyDescriptor(navigator, "userAgent");
  Object.defineProperty(navigator, "userAgent", {
    configurable: true,
    value: "Chrome"
  });
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi
      .fn()
      .mockResolvedValueOnce({
        unlocked: true,
        activeVaultId: "vault-1",
        currentVaultRefId: "vault-ref-1"
      })
      .mockRejectedValue(new Error("resident unavailable")),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "resident-secret",
      url: "https://example.com",
      notes: "",
      totp: null,
      totpUri: null,
      attachments: [{ name: "secret.bin", size: 6, protectInMemory: true }]
    }),
    getEntryAttachmentContent: vi.fn(() => attachment.promise)
  };

  try {
    render(<App client={client as any} />);
    fireEvent.click(await screen.findByRole("button", { name: "Example" }));
    fireEvent.click(await screen.findByRole("button", { name: "Download secret.bin" }));
    await waitFor(() => expect(client.getEntryAttachmentContent).toHaveBeenCalledTimes(1));

    await act(async () => {
      fireEvent.focus(window);
      attachment.resolve({
        type: "entry_attachment_content",
        name: "secret.bin",
        dataBase64: "c2VjcmV0",
        protectInMemory: true
      });
      await attachment.promise;
      await Promise.resolve();
    });

    expect(click).not.toHaveBeenCalled();
  } finally {
    click.mockRestore();
    if (originalUserAgent) {
      Object.defineProperty(navigator, "userAgent", originalUserAgent);
    } else {
      delete (navigator as Navigator & { userAgent?: string }).userAgent;
    }
  }
});

it("retries a failed attachment save without adding the attachment again", async () => {
  const addEntryAttachment = vi.fn(async () => ({
    type: "entry_detail" as const,
    id: "entry-1",
    title: "Example",
    username: "alice",
    password: "secret-123",
    url: "https://example.com",
    notes: "demo note",
    totp: null,
    totpUri: null,
    customFields: [],
    attachments: [
      {
        name: "added.txt",
        size: 5,
        protectInMemory: false
      }
    ]
  }));
  const saveVault = vi
    .fn()
    .mockRejectedValueOnce(new Error("simulated attachment save failure"))
    .mockResolvedValueOnce(undefined);
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      totp: null,
      totpUri: null,
      customFields: [],
      attachments: []
    })),
    addEntryAttachment,
    saveVault
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  const file = new File(["hello"], "added.txt", { type: "text/plain" });
  fireEvent.change(screen.getByLabelText("Add attachment file"), {
    target: { files: [file] }
  });

  expect(await screen.findByText("simulated attachment save failure")).toBeInTheDocument();
  expect(addEntryAttachment).toHaveBeenCalledTimes(1);
  expect(saveVault).toHaveBeenCalledTimes(1);

  fireEvent.click(screen.getByRole("button", { name: "Retry save" }));

  await waitFor(() => expect(saveVault).toHaveBeenCalledTimes(2));
  expect(addEntryAttachment).toHaveBeenCalledTimes(1);
});

it("shows read-only entry history details", async () => {
  const listEntryHistory = vi.fn(async () => [
    {
      index: 0,
      title: "Old Example",
      username: "alice-old",
      modifiedAt: 42,
      attachmentCount: 1,
      customFieldCount: 1
    }
  ]);
  const getEntryHistoryDetail = vi.fn(async () => ({
    type: "entry_history_detail" as const,
    entryId: "entry-1",
    historyIndex: 0,
    title: "Old Example",
    username: "alice-old",
    url: "https://example.com/old",
    notes: "old note",
    modifiedAt: 42,
    customFields: [
      {
        key: "RecoveryCode",
        value: "old-code",
        protected: true
      }
    ],
    attachments: [
      {
        name: "backup.txt",
        size: 5,
        protectInMemory: true
      }
    ]
  }));

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      modifiedAt: 43,
      totp: null,
      totpUri: null
    })),
    listEntryHistory,
    getEntryHistoryDetail
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));

  expect(await screen.findByText("History")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "View history 1" }));

  await waitFor(() => {
    expect(getEntryHistoryDetail).toHaveBeenCalledWith("vault-1", "entry-1", 0);
  });
  expect((await screen.findAllByText("Old Example")).length).toBeGreaterThan(0);
  expect(screen.getAllByText("alice-old").length).toBeGreaterThan(0);
  expect(screen.getAllByText("1970-01-01 00:00:42").length).toBeGreaterThan(0);
  expect(screen.queryByText("old-secret")).not.toBeInTheDocument();
  expect(screen.queryByText("old-code")).not.toBeInTheDocument();
  expect(screen.getAllByText("************").length).toBeGreaterThan(0);
  expect(screen.getByText("backup.txt")).toBeInTheDocument();
});

it("does not let an older history-detail response replace the latest selection", async () => {
  const firstDetail = createDeferred<any>();
  const secondDetail = createDeferred<any>();
  const getEntryHistoryDetail = vi.fn(
    async (_vaultId: string, _entryId: string, historyIndex: number) =>
      historyIndex === 0 ? firstDetail.promise : secondDetail.promise
  );
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    }),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn(async () => ({
      type: "entry_detail" as const,
      id: "entry-1",
      title: "Example",
      username: "alice",
      password: "secret-123",
      url: "https://example.com",
      notes: "demo note",
      modifiedAt: 43,
      totp: null,
      totpUri: null
    })),
    listEntryHistory: vi.fn(async () => [
      {
        index: 0,
        title: "First snapshot",
        username: "first-list-user",
        modifiedAt: 40,
        attachmentCount: 0,
        customFieldCount: 0
      },
      {
        index: 1,
        title: "Second snapshot",
        username: "second-list-user",
        modifiedAt: 41,
        attachmentCount: 0,
        customFieldCount: 0
      }
    ]),
    getEntryHistoryDetail
  };

  render(<App client={client as any} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));
  fireEvent.click(await screen.findByRole("button", { name: "View history 1" }));
  fireEvent.click(screen.getByRole("button", { name: "View history 2" }));
  await waitFor(() => expect(getEntryHistoryDetail).toHaveBeenCalledTimes(2));

  secondDetail.resolve({
    type: "entry_history_detail",
    entryId: "entry-1",
    historyIndex: 1,
    title: "Second detail",
    username: "second-detail-user",
    url: "https://example.com/second",
    notes: "second",
    modifiedAt: 41,
    customFields: [],
    attachments: []
  });
  const historyDetail = await screen.findByRole("region", {
    name: "History Detail"
  });
  expect(within(historyDetail).getByText("Second detail")).toBeInTheDocument();

  firstDetail.resolve({
    type: "entry_history_detail",
    entryId: "entry-1",
    historyIndex: 0,
    title: "First detail",
    username: "first-detail-user",
    url: "https://example.com/first",
    notes: "first",
    modifiedAt: 40,
    customFields: [],
    attachments: []
  });
  await act(async () => {
    await firstDetail.promise;
  });

  expect(within(historyDetail).queryByText("First detail")).not.toBeInTheDocument();
  expect(within(historyDetail).getByText("Second detail")).toBeInTheDocument();
});

it("filters the entry workspace when a nested group is selected", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 1280;

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 2,
        children: [
          {
            id: "group-general",
            title: "General",
            entryCount: 1,
            childCount: 0,
            children: []
          },
          {
            id: "group-banking",
            title: "Banking",
            entryCount: 1,
            childCount: 0,
            children: []
          }
        ]
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-general"
      },
      {
        id: "entry-2",
        title: "Savings",
        username: "bank-user",
        url: "https://bank.example.com",
        groupId: "group-banking"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: "",
      totp: null
    })
  };

  try {
    render(<App client={client} />);
    fireEvent(window, new Event("resize"));

    expect(await screen.findByRole("button", { name: "General" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Banking" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "GitHub" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Savings" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Banking" }));

    expect(screen.getByRole("button", { name: "Savings" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "GitHub" })
    ).not.toBeInTheDocument();
  } finally {
    window.innerWidth = originalInnerWidth;
  }
});

it("keeps padded manager panes inside their grid columns in expanded mode", async () => {
  render(
    <ManagerShell
      viewMode="expanded"
      topBar={<div>Top</div>}
      groupTree={<section aria-label="Groups">Groups</section>}
      entryList={<section aria-label="Entries">Entries</section>}
      entryDetail={<section aria-label="Entry Detail">Detail</section>}
      showEntryDetail={false}
      stackedStage="groups"
      showEntryListWithDetail={false}
    />
  );

  expect((await screen.findByLabelText("Entries")).parentElement).toHaveStyle(
    "box-sizing: border-box"
  );
});

it("lets expanded manager content columns shrink within the shell", async () => {
  render(
    <ManagerShell
      viewMode="expanded"
      topBar={<div>Top</div>}
      groupTree={<section aria-label="Groups">Groups</section>}
      entryList={<section aria-label="Entries">Entries</section>}
      entryDetail={<section aria-label="Entry Detail">Detail</section>}
      showEntryDetail={false}
      stackedStage="groups"
      showEntryListWithDetail={false}
    />
  );

  const entriesPane = (await screen.findByLabelText("Entries")).parentElement;
  expect(entriesPane?.parentElement).toHaveStyle(
    "grid-template-columns: minmax(220px, 280px) minmax(0, 1fr) minmax(0, 1.2fr)"
  );
});

it("keeps the manager search control inside the wrapped top bar", () => {
  render(
    <ManagerTopBar
      searchValue=""
      onSearchChange={vi.fn()}
      onOpenStats={vi.fn()}
      onOpenSettings={vi.fn()}
    />
  );

  expect(screen.getByLabelText("Global Search")).toHaveStyle(
    "box-sizing: border-box"
  );
  expect(screen.getByText("Global Search").parentElement).toHaveStyle(
    "min-width: 0"
  );
});

it("switches the primary workspace from list to detail when a record is selected in compact mode", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 900;

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: ""
    })
  };

  try {
    render(<App client={client} />);
    fireEvent(window, new Event("resize"));

    fireEvent.click(await screen.findByRole("button", { name: "GitHub" }));

    expect(await screen.findByText("Back to entries")).toBeInTheDocument();
    expect(screen.getByDisplayValue("GitHub")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "GitHub" })
    ).not.toBeInTheDocument();
  } finally {
    window.innerWidth = originalInnerWidth;
  }
});

it("keeps the workspace in split mode until the three columns fit with shell padding", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 1120;

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-root"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: ""
    })
  };

  try {
    render(<App client={client} />);
    fireEvent(window, new Event("resize"));

    fireEvent.click(await screen.findByRole("button", { name: "GitHub" }));

    expect(await screen.findByText("Back to entries")).toBeInTheDocument();
  } finally {
    window.innerWidth = originalInnerWidth;
  }
});

it("drills from groups to entries to detail in stacked mode", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 700;

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 1,
        children: [
          {
            id: "group-general",
            title: "General",
            entryCount: 1,
            childCount: 0,
            children: []
          }
        ]
      }
    }),
    listEntries: vi.fn().mockResolvedValue([
      {
        id: "entry-1",
        title: "GitHub",
        username: "alice",
        url: "https://github.com",
        groupId: "group-general"
      }
    ]),
    getEntryDetail: vi.fn().mockResolvedValue({
      type: "entry_detail",
      id: "entry-1",
      title: "GitHub",
      username: "alice",
      password: "secret",
      url: "https://github.com",
      notes: "",
      totp: null
    })
  };

  try {
    render(<App client={client} />);
    fireEvent(window, new Event("resize"));

    expect(await screen.findByRole("button", { name: "General" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "GitHub" })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "General" }));

    expect(await screen.findByRole("button", { name: "GitHub" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "General" })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "GitHub" }));

    expect(await screen.findByText("Back to entries")).toBeInTheDocument();
    expect(screen.getByDisplayValue("GitHub")).toBeInTheDocument();
  } finally {
    window.innerWidth = originalInnerWidth;
  }
});

it("shows a visible error when session loading fails", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn().mockRejectedValue(new Error("vault is locked")),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  expect(await screen.findByRole("alert")).toHaveTextContent("vault is locked");
});

it("renders custom runtime error help for session loading failures", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn().mockRejectedValue(
      Object.assign(new Error("native host unavailable"), {
        code: "native_host_missing"
      })
    ),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(
    <App
      client={client}
      renderRuntimeErrorHelp={(error) =>
        (error as { code?: string }).code === "native_host_missing" ? (
          <div>Install native host first</div>
        ) : null
      }
    />
  );

  expect(await screen.findByText("Install native host first")).toBeInTheDocument();
});

it("renders custom runtime error help for unlock failures", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    }),
    listRecentVaults: vi.fn(async () => [
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
    ]),
    unlockCurrentVault: vi.fn().mockRejectedValue(
      Object.assign(new Error("native host unavailable"), {
        code: "native_host_missing"
      })
    ),
    listGroups: vi.fn(),
    listEntries: vi.fn(),
    getEntryDetail: vi.fn()
  };

  render(
    <App
      client={client}
      renderRuntimeErrorHelp={(error) =>
        (error as { code?: string }).code === "native_host_missing" ? (
          <div>Install native host first</div>
        ) : null
      }
    />
  );

  await screen.findByText("Broken Vault");
  fireEvent.change(screen.getByLabelText("Master Password"), {
    target: { value: "demo-password" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Unlock Vault" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("native host unavailable");
  expect(screen.getByText("Install native host first")).toBeInTheDocument();
});

it("shows a visible error when listing entries fails", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    }),
    listEntries: vi.fn().mockRejectedValue(new Error("vault is locked")),
    getEntryDetail: vi.fn()
  };

  render(<App client={client} />);

  expect(await screen.findByRole("alert")).toHaveTextContent("vault is locked");
});

it("shows a visible error when entry detail loading fails", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 1,
        childCount: 0,
        children: []
      }
    }),
    listEntries: async (_vaultId: string) => [
      {
        id: "entry-1",
        title: "Example",
        username: "alice",
        url: "https://example.com",
        groupId: "group-root"
      }
    ],
    getEntryDetail: vi.fn().mockRejectedValue(new Error("vault is locked"))
  };

  render(<App client={client} />);

  fireEvent.click(await screen.findByRole("button", { name: "Example" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("vault is locked");
});

it("shows a visible error when fill candidate loading fails", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1", currentVaultRefId: "vault-ref-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
      type: "group_tree" as const,
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    }),
    listEntries: async (_vaultId: string) => [],
    getEntryDetail: vi.fn()
  };

  render(
    <App
      client={client}
      fillHooks={{
        findCandidates: vi.fn().mockRejectedValue(new Error("vault is locked")),
        fillEntry: vi.fn()
      }}
    />
  );

  expect(await screen.findByRole("alert")).toHaveTextContent("vault is locked");
  expect(
    screen.queryByRole("button", { name: "Fill Example" })
  ).not.toBeInTheDocument();
});

it("prefers message text from plain rejected values", () => {
  expect(errorMessage({ message: "browser-style rejection" }, "fallback")).toBe(
    "browser-style rejection"
  );
  expect(errorMessage("string rejection", "fallback")).toBe("string rejection");
  expect(errorMessage({}, "fallback")).toBe("fallback");
});
