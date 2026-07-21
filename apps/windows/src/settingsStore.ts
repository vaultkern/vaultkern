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
  }) => Promise<unknown> = async () => undefined
): ExtensionSettingsStore {
  return {
    surface: "windows",
    nativeReconciliationOwned: true,
    async queueQuickUnlockEnrollment(credentials) {
      await queueQuickUnlockEnrollment(credentials);
    },
    async load() {
      return normalizeWindowsAppSettings(await loadDesiredSettings());
    },
    async save(settings) {
      await saveDesiredSettings(normalizeWindowsAppSettings(settings));
    }
  };
}
