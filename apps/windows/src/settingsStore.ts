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
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">,
  applyPasskeyProviderSetting: (enabled: boolean) => Promise<unknown> = async () => undefined
): ExtensionSettingsStore {
  return {
    async load() {
      const value = storage.getItem(SETTINGS_KEY);
      if (value === null) {
        await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled
        );
        return DEFAULT_EXTENSION_SETTINGS;
      }

      try {
        const settings = normalizeExtensionSettings(
          JSON.parse(value) as Partial<ExtensionSettings>
        );
        await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          settings.passkeyProviderEnabled
        );
        return settings;
      } catch {
        storage.removeItem(SETTINGS_KEY);
        await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled
        );
        return DEFAULT_EXTENSION_SETTINGS;
      }
    },
    async save(settings) {
      const normalized = normalizeExtensionSettings(settings);
      const previousEnabled = storedPasskeyProviderSetting(storage);
      await applyPasskeyProviderSetting(normalized.passkeyProviderEnabled);
      try {
        storage.setItem(
          SETTINGS_KEY,
          JSON.stringify(normalized)
        );
      } catch (error) {
        try {
          await applyPasskeyProviderSetting(previousEnabled);
        } catch (rollbackError) {
          console.error(
            "failed to roll back the passkey-provider setting after local persistence failed",
            rollbackError
          );
        }
        throw error;
      }
    }
  };
}

function storedPasskeyProviderSetting(
  storage: Pick<Storage, "getItem">
): boolean {
  const value = storage.getItem(SETTINGS_KEY);
  if (value === null) {
    return DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled;
  }
  try {
    return normalizeExtensionSettings(
      JSON.parse(value) as Partial<ExtensionSettings>
    ).passkeyProviderEnabled;
  } catch {
    return DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled;
  }
}

async function applyInitialPasskeyProviderSetting(
  apply: (enabled: boolean) => Promise<unknown>,
  enabled: boolean
) {
  try {
    await apply(enabled);
  } catch (error) {
    console.error("failed to apply the saved passkey-provider setting", error);
  }
}
