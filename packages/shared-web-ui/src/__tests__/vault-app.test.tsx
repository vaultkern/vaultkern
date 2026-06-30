import "@testing-library/jest-dom/vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App, type RuntimeClientLike } from "../App";
import type { ExtensionSettingsStore } from "../extensionSettings";
import { errorMessage } from "../error";
import { ManagerShell } from "../layout/ManagerShell";
import { ManagerTopBar } from "../layout/ManagerTopBar";

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

function createVaultSelectionMethods() {
  return {
    listRecentVaults: vi.fn(async () => []),
    addLocalVaultReference: vi.fn(),
    beginOneDriveLogin: vi.fn(),
    completeOneDriveLogin: vi.fn(),
    completePendingOneDriveLogin: vi.fn(),
    listOneDriveChildren: vi.fn(async () => []),
    addOneDriveVaultReference: vi.fn(),
    createEntry: vi.fn(),
    updateEntryFields: vi.fn(),
    deleteEntry: vi.fn(),
    saveVault: vi.fn(),
    setEntryPasskey: vi.fn(),
    clearEntryPasskey: vi.fn(),
    retryVaultSourceSync: vi.fn(),
    getDatabaseSettings: vi.fn(async () => ({
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
    unlockWithPassword: vi.fn(),
    unlockVault: vi.fn(),
    lockSession: vi.fn(async () => ({
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null
    }))
  };
}

function createSettingsStore(
  settings = {
    recentVaultLimit: 10,
    language: "en" as const,
    idleLockMinutes: 0,
    clearClipboardSeconds: 30
  }
): ExtensionSettingsStore {
  let current = settings;
  return {
    load: vi.fn(async () => current),
    save: vi.fn(async (next) => {
      current = next;
    })
  };
}

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

  fireEvent.click(screen.getByRole("button", { name: "Show password" }));
  expect(screen.getByDisplayValue("secret-123")).toHaveAttribute("type", "text");
});

it("shows browser settings and saves local extension preferences", async () => {
  const settingsStore = createSettingsStore();
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
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
    getEntryDetail: vi.fn()
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  expect(await screen.findByText("No entries available.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Settings" }));

  expect(await screen.findByRole("heading", { name: "Browser Settings" })).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Recent Databases"), {
    target: { value: "4" }
  });
  fireEvent.change(screen.getByLabelText("Idle Lock Minutes"), {
    target: { value: "7" }
  });
  fireEvent.change(screen.getByLabelText("Clear Clipboard Seconds"), {
    target: { value: "12" }
  });
  fireEvent.click(screen.getByLabelText("VaultKern passkey provider"));
  fireEvent.click(screen.getByRole("button", { name: "中文" }));
  fireEvent.click(screen.getByRole("button", { name: "Save Browser Settings" }));

  await waitFor(() => {
    expect(settingsStore.save).toHaveBeenCalledWith({
      recentVaultLimit: 4,
      language: "zh-CN",
      idleLockMinutes: 7,
      clearClipboardSeconds: 12,
      passkeyProviderEnabled: true
    });
  });
  expect(screen.getByRole("button", { name: "设置" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "浏览器设置" })).toBeInTheDocument();
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
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

  fireEvent.click(screen.getByRole("button", { name: "设置" }));
  expect(await screen.findByRole("heading", { name: "浏览器设置" })).toBeInTheDocument();
  expect(screen.getByText("数据库元数据")).toBeInTheDocument();
  expect(screen.getByLabelText("数据库名称")).toBeInTheDocument();
  expect(screen.getByText("凭据")).toBeInTheDocument();
});

it("trims recent vaults when the local recent database limit is lower", async () => {
  const settingsStore = createSettingsStore({
    recentVaultLimit: 2,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30
  });
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
        displayName: "One",
        sourceKind: "local" as const,
        sourceSummary: "one.kdbx",
        lastUsedAt: 3,
        availability: "ready" as const
      },
      {
        vaultRefId: "vault-ref-2",
        displayName: "Two",
        sourceKind: "local" as const,
        sourceSummary: "two.kdbx",
        lastUsedAt: 2,
        availability: "ready" as const
      },
      {
        vaultRefId: "vault-ref-3",
        displayName: "Three",
        sourceKind: "local" as const,
        sourceSummary: "three.kdbx",
        lastUsedAt: 1,
        availability: "ready" as const
      }
    ]),
    deleteRecentVault: vi.fn(async () => [])
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);

  await waitFor(() => {
    expect(client.deleteRecentVault).toHaveBeenCalledWith("vault-ref-3");
  });
});

it("locks an unlocked manager after local idle timeout", async () => {
  vi.useFakeTimers();
  const settingsStore = createSettingsStore({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 1,
    clearClipboardSeconds: 30
  });
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: vi.fn(async () => ({ unlocked: true, activeVaultId: "vault-1" })),
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
    getEntryDetail: vi.fn()
  } satisfies RuntimeClientLike;

  render(<App client={client} extensionSettingsStore={settingsStore} />);
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
  expect(screen.getByText("No entries available.")).toBeInTheDocument();

  await act(async () => {
    vi.advanceTimersByTime(60_000);
    await Promise.resolve();
  });

  expect(client.lockSession).toHaveBeenCalledTimes(1);
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

it("loads and saves database settings from the manager workspace", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
          algorithm: "aes_kdbx4",
          transformRounds: 100000,
          iterations: null,
          memoryKib: null,
          parallelism: null
        }
      },
      autosaveDelaySeconds: 20,
      hasPassword: true
    }),
    updateDatabaseSettings: vi.fn().mockResolvedValue({
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
          algorithm: "aes_kdbx4",
          transformRounds: 12000,
          iterations: null,
          memoryKib: null,
          parallelism: null
        }
      },
      autosaveDelaySeconds: 45,
      hasPassword: true
    }),
    saveVault: vi.fn().mockResolvedValue({ type: "save_vault_result", status: "saved" })
  };

  render(<App client={client as RuntimeClientLike} />);

  await screen.findByText("No entries available.");
  fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
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
  fireEvent.change(screen.getByLabelText("History Total Size MiB"), {
    target: { value: "2" }
  });
  fireEvent.click(screen.getByLabelText("Enable recycle bin"));
  fireEvent.change(screen.getByLabelText("Compression"), {
    target: { value: "none" }
  });
  fireEvent.change(screen.getByLabelText("Cipher"), {
    target: { value: "chacha20" }
  });
  fireEvent.change(screen.getByLabelText("Transform Rounds"), {
    target: { value: "12000" }
  });
  fireEvent.change(screen.getByLabelText("Autosave Delay Seconds"), {
    target: { value: "45" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Change password" }));
  fireEvent.change(screen.getByLabelText("New Master Password"), {
    target: { value: "new-password" }
  });
  fireEvent.change(screen.getByLabelText("Confirm New Master Password"), {
    target: { value: "new-password" }
  });

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
        maxTotalSizeBytes: 2097152
      },
      recycleBin: { enabled: false },
      encryption: {
        compression: "none",
        cipher: "chacha20",
        kdf: {
          algorithm: "aes_kdbx4",
          transformRounds: 12000,
          iterations: null,
          memoryKib: null,
          parallelism: null
        }
      },
      autosaveDelaySeconds: 45,
      credentials: {
        newPassword: "new-password",
        removePassword: false
      }
    });
  });
  expect(client.saveVault).toHaveBeenCalledWith("vault-1");
});

it("shows add password action when a database has no password", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
  fireEvent.click(screen.getByRole("button", { name: "Settings" }));
  expect(await screen.findByRole("button", { name: "Add password" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Remove password" })).not.toBeInTheDocument();
});

it("shows kdf-specific advanced encryption fields", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
  fireEvent.click(await screen.findByRole("button", { name: "Settings" }));

  expect(await screen.findByLabelText("Argon2 Iterations")).toBeInTheDocument();
  expect(screen.getByLabelText("Argon2 Memory MiB")).toBeInTheDocument();
  expect(screen.queryByLabelText("Transform Rounds")).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Key Derivation Function"), {
    target: { value: "aes_kdbx4" }
  });

  expect(screen.getByLabelText("Transform Rounds")).toBeInTheDocument();
  expect(screen.queryByLabelText("Argon2 Iterations")).not.toBeInTheDocument();
});

it("shows custom fields, attachments, and protected field markers in entry detail", async () => {
  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----",
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
  expect(screen.getByLabelText("Private Key PEM")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("credential-old")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("generated-user")).toHaveAttribute("type", "password");
  expect(screen.getByDisplayValue("user-handle")).toHaveAttribute("type", "password");
  fireEvent.change(screen.getByLabelText("Credential ID"), {
    target: { value: "credential-new" }
  });
  fireEvent.click(screen.getByLabelText("Backup state"));
  fireEvent.click(screen.getByRole("button", { name: "Save passkey" }));

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
      type: "one_drive_auth_session",
      authUrl: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      redirectUri: "http://127.0.0.1:53121/callback",
      codeVerifier: "verifier",
      expiresInSeconds: 600
    })),
    completeOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status",
      status: "authorized",
      accountLabel: "alice@example.com"
    })),
    completePendingOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status",
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
    expect(client.completeOneDriveLogin).not.toHaveBeenCalled();
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
      type: "one_drive_auth_session",
      authUrl: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      redirectUri: "http://127.0.0.1:53121/callback",
      codeVerifier: "verifier",
      expiresInSeconds: 600
    })),
    completeOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status",
      status: "authorized",
      accountLabel: "alice@example.com"
    })),
    completePendingOneDriveLogin: vi.fn(async () => ({
      type: "one_drive_auth_status",
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
  const deleteRecentVault = vi.fn(async () => [
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
    ]),
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn(async (_vaultId: string) => ({
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
          type: "entry_detail",
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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

  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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

it("shows an auto-dismiss tip when save merges a changed source", async () => {
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
    title: "Merged Title",
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    target: { value: "Merged Title" }
  });
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await act(async () => {
    await Promise.resolve();
  });

  expect(screen.getByText("Vault changed on disk. Merged and saved.")).toBeInTheDocument();

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
  const retryVaultSourceSync = vi.fn(async () => ({
    type: "vault_source_status" as const,
    sourceKind: "onedrive",
    remoteState: "online",
    lastSyncAt: 1776500060,
    cachedAt: 1776500030,
    lastError: null
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
        lastError: "OneDrive unavailable"
      }
    }),
    listGroups: vi.fn(async () => ({
      root: {
        id: "group-root",
        title: "Archive",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    retryVaultSourceSync
  };

  render(<App client={client as any} />);

  expect(
    await screen.findByText("Using local cache. Remote sync failed.")
  ).toBeInTheDocument();
  expect(screen.getByText("OneDrive unavailable")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Retry sync" }));

  await waitFor(() => {
    expect(retryVaultSourceSync).toHaveBeenCalledWith("vault-1");
  });
  await waitFor(() => {
    expect(
      screen.queryByText("Using local cache. Remote sync failed.")
    ).not.toBeInTheDocument();
  });
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
    password: "old-secret",
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    listGroups: vi.fn().mockResolvedValue({
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
  expect(screen.getAllByText("************").length).toBeGreaterThan(0);
  expect(screen.getByText("backup.txt")).toBeInTheDocument();
});

it("filters the entry workspace when a nested group is selected", async () => {
  const originalInnerWidth = window.innerWidth;
  window.innerWidth = 1280;

  const client = {
    ...createVaultSelectionMethods(),
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
    getSessionState: async () => ({ unlocked: true, activeVaultId: "vault-1" }),
    openLocalVault: vi.fn(),
    unlockWithPassword: vi.fn(),
    listGroups: vi.fn().mockResolvedValue({
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
