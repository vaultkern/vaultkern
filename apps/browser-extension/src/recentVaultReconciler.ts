import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";
import { normalizeBrowserExtensionSettings } from "@vaultkern/shared-web-ui";

interface RecentVaultClient {
  listRecentVaults(): Promise<Array<{ vaultRefId: string; lastUsedAt?: number | null }>>;
  deleteRecentVault(vaultRefId: string): Promise<unknown>;
}

export function createRecentVaultReconciler(
  settingsStore: ExtensionSettingsStore,
  client: RecentVaultClient
) {
  let tail = Promise.resolve();
  let epoch = 0;

  async function reconcile(reconciliationEpoch: number) {
    let remainingVaults = [...(await client.listRecentVaults())].sort(
      (left, right) => (right.lastUsedAt ?? 0) - (left.lastUsedAt ?? 0)
    );
    if (reconciliationEpoch !== epoch) {
      return;
    }

    while (reconciliationEpoch === epoch) {
      // Re-read desired state for every destructive step so there is no await
      // between confirming the current limit and starting the delete.
      const desired = normalizeBrowserExtensionSettings(await settingsStore.load());
      if (reconciliationEpoch !== epoch) {
        return;
      }
      const nextOverflowVault = remainingVaults[desired.recentVaultLimit];
      if (!nextOverflowVault) {
        return;
      }

      await client.deleteRecentVault(nextOverflowVault.vaultRefId);
      remainingVaults = remainingVaults.filter(
        (vault) => vault.vaultRefId !== nextOverflowVault.vaultRefId
      );
    }
  }

  return {
    schedule() {
      const reconciliationEpoch = ++epoch;
      const run = () => reconcile(reconciliationEpoch);
      const operation = tail.then(run, run);
      tail = operation.catch(() => undefined);
      return operation;
    }
  };
}
