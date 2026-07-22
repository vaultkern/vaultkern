import {
  DEFAULT_EXTENSION_SETTINGS,
  normalizeBrowserExtensionSettings
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
      surface: "browser",
      async load() {
        return DEFAULT_EXTENSION_SETTINGS;
      },
      async save() {
        throw new Error("chrome settings storage is unavailable");
      }
    };
  }

  return {
    surface: "browser",
    async load() {
      return new Promise((resolve, reject) => {
        storage.get(EXTENSION_SETTINGS_STORAGE_KEY, (items) => {
          const lastError = getChromeLastError();
          if (lastError) {
            reject(new Error(lastError));
            return;
          }
          resolve(normalizeBrowserExtensionSettings(items[EXTENSION_SETTINGS_STORAGE_KEY]));
        });
      });
    },
    async save(settings) {
      await new Promise<void>((resolve, reject) => {
        storage.set(
          {
            [EXTENSION_SETTINGS_STORAGE_KEY]:
              normalizeBrowserExtensionSettings(settings)
          },
          () => {
            const lastError = getChromeLastError();
            if (lastError) {
              reject(new Error(lastError));
              return;
            }
            resolve();
          }
        );
      });
    }
  };
}

function getChromeLastError(): string | null {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  const lastError = chromeApi?.runtime?.lastError;
  return typeof lastError?.message === "string" && lastError.message
    ? lastError.message
    : null;
}

function getChromeStorage() {
  const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
  return chromeApi?.storage?.local as ChromeStorageArea | undefined;
}
