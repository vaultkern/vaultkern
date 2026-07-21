import { normalizeExtensionSettings } from "@vaultkern/shared-web-ui";
import type {
  ExtensionSettings,
  ExtensionSettingsReconciliationContext,
  ExtensionSettingsStore
} from "@vaultkern/shared-web-ui";

export function createDesktopSettingsStore(
  loadDesiredSettings: () => Promise<unknown>,
  saveDesiredSettings: (settings: ExtensionSettings) => Promise<unknown>,
  reconcileNativeSettings: (
    context: ExtensionSettingsReconciliationContext
  ) => Promise<unknown> = async () => undefined
): ExtensionSettingsStore {
  return {
    async load() {
      return normalizeExtensionSettings(await loadDesiredSettings());
    },
    async save(settings) {
      await saveDesiredSettings(normalizeExtensionSettings(settings));
    },
    async reconcile(context) {
      await reconcileNativeSettings(context);
    }
  };
}
