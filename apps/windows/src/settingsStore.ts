import {
  DEFAULT_EXTENSION_SETTINGS,
  normalizeExtensionSettings
} from "@vaultkern/shared-web-ui";
import type {
  ExtensionSettings,
  ExtensionSettingsReconciliationContext,
  ExtensionSettingsStore
} from "@vaultkern/shared-web-ui";

const SETTINGS_KEY = "vaultkern.desktop.settings.v1";

export function createDesktopSettingsStore(
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">,
  reconcilePasskeyProviderSetting: (
    enabled: boolean,
    context: ExtensionSettingsReconciliationContext
  ) => Promise<unknown> = async () => undefined
): ExtensionSettingsStore {
  return {
    async load() {
      return readDesktopSettings(storage);
    },
    async save(settings) {
      const normalized = normalizeExtensionSettings(settings);
      storage.setItem(SETTINGS_KEY, JSON.stringify(normalized));
    },
    async reconcile(context) {
      const desired = readDesktopSettings(storage);
      await reconcilePasskeyProviderSetting(
        desired.passkeyProviderEnabled,
        context
      );
    }
  };
}

function readDesktopSettings(
  storage: Pick<Storage, "getItem" | "removeItem">
): ExtensionSettings {
  const value = storage.getItem(SETTINGS_KEY);
  if (value === null) {
    return DEFAULT_EXTENSION_SETTINGS;
  }
  try {
    return normalizeExtensionSettings(JSON.parse(value) as Partial<ExtensionSettings>);
  } catch {
    storage.removeItem(SETTINGS_KEY);
    return DEFAULT_EXTENSION_SETTINGS;
  }
}
