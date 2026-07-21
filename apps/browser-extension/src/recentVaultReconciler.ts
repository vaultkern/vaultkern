import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";
import {
  normalizeBrowserExtensionSettings,
  sortRecentVaultsForRetention
} from "@vaultkern/shared-web-ui";

interface RecentVaultClient {
  listRecentVaults(): Promise<
    Array<{ vaultRefId: string; lastUsedAt?: number | null; isCurrent?: boolean }>
  >;
  deleteRecentVaultIfNotCurrent(
    vaultRefId: string
  ): Promise<
    Array<{ vaultRefId: string; lastUsedAt?: number | null; isCurrent?: boolean }>
  >;
}

export function createRecentVaultReconciler(
  settingsStore: ExtensionSettingsStore,
  client: RecentVaultClient
) {
  let tail = Promise.resolve();
  let epoch = 0;

  async function reconcile(reconciliationEpoch: number) {
    let remainingVaults = sortRecentVaultsForRetention(
      await client.listRecentVaults()
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
      remainingVaults = sortRecentVaultsForRetention(
        await client.listRecentVaults()
      );
      if (reconciliationEpoch !== epoch) {
        return;
      }
      const nextOverflowVault = remainingVaults[desired.recentVaultLimit];
      if (!nextOverflowVault) {
        return;
      }

      remainingVaults = await client.deleteRecentVaultIfNotCurrent(
        nextOverflowVault.vaultRefId
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
