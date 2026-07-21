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
  const listRecentVaults = vi
    .fn()
    .mockRejectedValueOnce(new Error("native host restarted"))
    .mockResolvedValueOnce([
      { vaultRefId: "new", lastUsedAt: 20 },
      { vaultRefId: "old", lastUsedAt: 10 }
    ]);
  const deleteRecentVault = vi.fn(async () => undefined);
  const reconciler = createRecentVaultReconciler(
    {
      async load() {
        return { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
      },
      async save() {}
    },
    { listRecentVaults, deleteRecentVault }
  );

  await expect(reconciler.schedule()).rejects.toThrow("native host restarted");
  await expect(reconciler.schedule()).resolves.toBeUndefined();

  expect(deleteRecentVault).toHaveBeenCalledTimes(1);
  expect(deleteRecentVault).toHaveBeenCalledWith("old");
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
  const deleteRecentVault = vi.fn(async () => undefined);
  const settingsStore = {
    load: vi.fn(async () => savedSettings),
    save: vi.fn(async (next: typeof savedSettings) => {
      savedSettings = next;
    })
  };
  const reconciler = createRecentVaultReconciler(settingsStore, {
    listRecentVaults,
    deleteRecentVault
  });

  const olderReconciliation = reconciler.schedule();
  await vi.waitFor(() => expect(listRecentVaults).toHaveBeenCalledTimes(1));

  await settingsStore.save({ ...savedSettings, recentVaultLimit: 2 });
  const newerReconciliation = reconciler.schedule();
  firstList.resolve(vaults);

  await Promise.all([olderReconciliation, newerReconciliation]);
  expect(deleteRecentVault).not.toHaveBeenCalled();
});

it("re-reads saved settings before each destructive delete", async () => {
  let savedSettings = { ...DEFAULT_EXTENSION_SETTINGS, recentVaultLimit: 1 };
  const vaults = [
    { vaultRefId: "new", lastUsedAt: 30 },
    { vaultRefId: "middle", lastUsedAt: 20 },
    { vaultRefId: "old", lastUsedAt: 10 }
  ];
  const firstDelete = createDeferred<void>();
  const deleteRecentVault = vi
    .fn()
    .mockReturnValueOnce(firstDelete.promise)
    .mockResolvedValue(undefined);
  const settingsStore = {
    load: vi.fn(async () => savedSettings),
    save: vi.fn(async (next: typeof savedSettings) => {
      savedSettings = next;
    })
  };
  const reconciler = createRecentVaultReconciler(settingsStore, {
    listRecentVaults: vi.fn(async () => vaults),
    deleteRecentVault
  });

  const reconciliation = reconciler.schedule();
  await vi.waitFor(() => expect(deleteRecentVault).toHaveBeenCalledTimes(1));
  expect(deleteRecentVault).toHaveBeenCalledWith("middle");

  await settingsStore.save({ ...savedSettings, recentVaultLimit: 3 });
  firstDelete.resolve();
  await reconciliation;

  expect(deleteRecentVault).toHaveBeenCalledTimes(1);
});
