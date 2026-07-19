import {
  DEFAULT_EXTENSION_SETTINGS,
  normalizeExtensionSettings
} from "@vaultkern/shared-web-ui";
import type {
  ExtensionSettings,
  ExtensionSettingsStore
} from "@vaultkern/shared-web-ui";

const SETTINGS_KEY = "vaultkern.desktop.settings.v1";

export function createDesktopSettingsStore(
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">
): ExtensionSettingsStore {
  return {
    async load() {
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
    },
    async save(settings) {
      storage.setItem(
        SETTINGS_KEY,
        JSON.stringify(normalizeExtensionSettings(settings))
      );
    }
  };
}
