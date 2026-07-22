import { normalizeWindowsAppSettings } from "@vaultkern/shared-web-ui";
import type {
  ExtensionSettings,
  ExtensionSettingsStore
} from "@vaultkern/shared-web-ui";

export function createDesktopSettingsStore(
  loadDesiredSettings: () => Promise<unknown>,
  saveDesiredSettings: (settings: ExtensionSettings) => Promise<unknown>,
  queueQuickUnlockEnrollment: (credentials: {
    password?: string | null;
    keyFilePath?: string | null;
  }, expectedVaultRefId: string) => Promise<unknown> = async () => undefined,
  loadReconciliationError: () => Promise<unknown> = async () => null,
  subscribeReconciliationError: (
    listener: (error: string | null) => void
  ) => Promise<() => void> = async () => () => undefined
): ExtensionSettingsStore {
  return {
    async queueQuickUnlockEnrollment(credentials, expectedVaultRefId) {
      await queueQuickUnlockEnrollment(credentials, expectedVaultRefId);
    },
    async loadReconciliationError() {
      const error = await loadReconciliationError();
      return typeof error === "string" && error.length > 0 ? error : null;
    },
    async subscribeReconciliationError(listener) {
      return subscribeReconciliationError((error) => {
        listener(typeof error === "string" && error.length > 0 ? error : null);
      });
    },
    async load() {
      return normalizeWindowsAppSettings(await loadDesiredSettings());
    },
    async save(settings) {
      await saveDesiredSettings(normalizeWindowsAppSettings(settings));
    }
  };
}
