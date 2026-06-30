import {
  DEFAULT_EXTENSION_SETTINGS,
  normalizeExtensionSettings
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettingsStore } from "@vaultkern/shared-web-ui";

export const EXTENSION_SETTINGS_STORAGE_KEY = "vaultkernExtensionSettings";

interface ChromeStorageArea {
  get(
    keys: string | string[] | Record<string, unknown> | null,
    callback: (items: Record<string, unknown>) => void
  ): void;
  set(items: Record<string, unknown>, callback?: () => void): void;
}

export function createChromeExtensionSettingsStore(
  storageArea?: ChromeStorageArea
): ExtensionSettingsStore {
  const storage = storageArea ?? getChromeStorage();

  if (!storage) {
    return {
      async load() {
        return DEFAULT_EXTENSION_SETTINGS;
      },
      async save() {
        return undefined;
      }
    };
  }

  return {
    async load() {
      return new Promise((resolve) => {
        storage.get(EXTENSION_SETTINGS_STORAGE_KEY, (items) => {
          resolve(normalizeExtensionSettings(items[EXTENSION_SETTINGS_STORAGE_KEY]));
        });
      });
    },
    async save(settings) {
      await new Promise<void>((resolve) => {
        storage.set(
          { [EXTENSION_SETTINGS_STORAGE_KEY]: normalizeExtensionSettings(settings) },
          resolve
        );
      });
    }
  };
}

function getChromeStorage() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  return chromeApi?.storage?.local as ChromeStorageArea | undefined;
}
