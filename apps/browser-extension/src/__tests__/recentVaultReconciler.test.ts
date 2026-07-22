import { expect, it, vi } from "vitest";

import { DEFAULT_EXTENSION_SETTINGS } from "@vaultkern/shared-web-ui";

import { createRecentVaultReconciler } from "../recentVaultReconciler";

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });

  return { promise, resolve };
}

it("retries the saved recent-vault limit from the long-lived background owner", async () => {
  let vaults = [
    { vaultRefId: "new", lastUsedAt: 20 },
    { vaultRefId: "old", lastUsedAt: 10 }
  ];
  const listRecentVaults = vi
    .fn()
    .mockRejectedValueOnce(new Error("native host restarted"))
    .mockImplementation(async () => vaults);
  const deleteRecentVaultIfNotCurrent = vi.fn(async (vaultRefId: string) => {
    vaults = vaults.filter((vault) => vault.vaultRefId !== vaultRefId);
    return vaults;
  });
  const reconciler = createRecentVaultReconciler(
    {
      async load() {
        return { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
      },
      async save() {}
    },
    { listRecentVaults, deleteRecentVaultIfNotCurrent }
  );

  await expect(reconciler.schedule()).rejects.toThrow("native host restarted");
  await expect(reconciler.schedule()).resolves.toBeUndefined();

  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledTimes(1);
  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledWith("old");
});

it("stops an older reconciliation when a newer desired state is scheduled", async () => {
  let savedSettings = { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
  const vaults = [
    { vaultRefId: "new", lastUsedAt: 20 },
    { vaultRefId: "old", lastUsedAt: 10 }
  ];
  const firstList = createDeferred<typeof vaults>();
  const listRecentVaults = vi
    .fn()
    .mockReturnValueOnce(firstList.promise)
    .mockResolvedValue(vaults);
  const deleteRecentVaultIfNotCurrent = vi.fn(async () => vaults);
  const settingsStore = {
    load: vi.fn(async () => savedSettings),
    save: vi.fn(async (next: typeof savedSettings) => {
      savedSettings = next;
    })
  };
  const reconciler = createRecentVaultReconciler(settingsStore, {
    listRecentVaults,
    deleteRecentVaultIfNotCurrent
  });

  const olderReconciliation = reconciler.schedule();
  await vi.waitFor(() => expect(listRecentVaults).toHaveBeenCalledTimes(1));

  await settingsStore.save({ ...savedSettings, recentVaultLimit: 2 });
  const newerReconciliation = reconciler.schedule();
  firstList.resolve(vaults);

  await Promise.all([olderReconciliation, newerReconciliation]);
  expect(deleteRecentVaultIfNotCurrent).not.toHaveBeenCalled();
});

it("re-reads saved settings before each destructive delete", async () => {
  let savedSettings = { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
  const vaults = [
    { vaultRefId: "new", lastUsedAt: 30 },
    { vaultRefId: "middle", lastUsedAt: 20 },
    { vaultRefId: "old", lastUsedAt: 10 }
  ];
  const firstDelete = createDeferred<typeof vaults>();
  const deleteRecentVaultIfNotCurrent = vi
    .fn()
    .mockReturnValueOnce(firstDelete.promise)
    .mockResolvedValue(vaults);
  const settingsStore = {
    load: vi.fn(async () => savedSettings),
    save: vi.fn(async (next: typeof savedSettings) => {
      savedSettings = next;
    })
  };
  const reconciler = createRecentVaultReconciler(settingsStore, {
    listRecentVaults: vi.fn(async () => vaults),
    deleteRecentVaultIfNotCurrent
  });

  const reconciliation = reconciler.schedule();
  await vi.waitFor(() =>
    expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledTimes(1)
  );
  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledWith("middle");

  await settingsStore.save({ ...savedSettings, recentVaultLimit: 3 });
  firstDelete.resolve([vaults[0]!, vaults[2]!]);
  await reconciliation;

  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledTimes(1);
});

it("re-reads recent vaults before deleting after a concurrent selection", async () => {
  const settingsRead = createDeferred<typeof DEFAULT_EXTENSION_SETTINGS>();
  let liveVaults = [
    { vaultRefId: "new", lastUsedAt: 20, isCurrent: true },
    { vaultRefId: "old", lastUsedAt: 10, isCurrent: false }
  ];
  const listRecentVaults = vi.fn(async () => liveVaults.map((vault) => ({ ...vault })));
  const deleteRecentVaultIfNotCurrent = vi.fn(async (vaultRefId: string) => {
    liveVaults = liveVaults.filter((vault) => vault.vaultRefId !== vaultRefId);
    return liveVaults;
  });
  const reconciler = createRecentVaultReconciler(
    {
      load: vi.fn(() => settingsRead.promise),
      async save() {}
    },
    { listRecentVaults, deleteRecentVaultIfNotCurrent }
  );

  const reconciliation = reconciler.schedule();
  await vi.waitFor(() => expect(listRecentVaults).toHaveBeenCalledTimes(1));

  liveVaults = [
    { vaultRefId: "old", lastUsedAt: 30, isCurrent: true },
    { vaultRefId: "new", lastUsedAt: 20, isCurrent: false }
  ];
  settingsRead.resolve({ ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 });
  await reconciliation;

  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledTimes(1);
  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledWith("new");
  expect(liveVaults.map((vault) => vault.vaultRefId)).toEqual(["old"]);
});

it("never trims the current vault when its timestamp predates another record", async () => {
  let liveVaults = [
    { vaultRefId: "recent", lastUsedAt: 20, isCurrent: false },
    { vaultRefId: "current", lastUsedAt: 10, isCurrent: true }
  ];
  const deleteRecentVaultIfNotCurrent = vi.fn(async (vaultRefId: string) => {
    if (vaultRefId === "current") {
      throw new Error("attempted to trim the current vault");
    }
    liveVaults = liveVaults.filter((vault) => vault.vaultRefId !== vaultRefId);
    return liveVaults;
  });
  const reconciler = createRecentVaultReconciler(
    {
      async load() {
        return { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
      },
      async save() {}
    },
    {
      listRecentVaults: vi.fn(async () => liveVaults),
      deleteRecentVaultIfNotCurrent
    }
  );

  await expect(reconciler.schedule()).resolves.toBeUndefined();
  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledTimes(1);
  expect(deleteRecentVaultIfNotCurrent).toHaveBeenCalledWith("recent");
});
