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
        const providerEnabled = await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled
        );
        return {
          ...DEFAULT_EXTENSION_SETTINGS,
          passkeyProviderEnabled: providerEnabled
        };
      }

      try {
        const settings = normalizeExtensionSettings(
          JSON.parse(value) as Partial<ExtensionSettings>
        );
        const providerEnabled = await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          settings.passkeyProviderEnabled
        );
        return { ...settings, passkeyProviderEnabled: providerEnabled };
      } catch {
        storage.removeItem(SETTINGS_KEY);
        const providerEnabled = await applyInitialPasskeyProviderSetting(
          applyPasskeyProviderSetting,
          DEFAULT_EXTENSION_SETTINGS.passkeyProviderEnabled
        );
        return {
          ...DEFAULT_EXTENSION_SETTINGS,
          passkeyProviderEnabled: providerEnabled
        };
      }
    },
    async save(settings) {
      const normalized = normalizeExtensionSettings(settings);
      const previousEnabled = storedPasskeyProviderSetting(storage);
      const applied = await applyPasskeyProviderSetting(normalized.passkeyProviderEnabled);
      if (typeof applied === "boolean" && applied !== normalized.passkeyProviderEnabled) {
        throw new Error(
          normalized.passkeyProviderEnabled
            ? "Windows did not enable the passkey provider"
            : "Windows did not disable the passkey provider"
        );
      }
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
): Promise<boolean> {
  try {
    const applied = await apply(enabled);
    return typeof applied === "boolean" ? applied : enabled;
  } catch (error) {
    console.error("failed to apply the saved passkey-provider setting", error);
    return false;
  }
}
