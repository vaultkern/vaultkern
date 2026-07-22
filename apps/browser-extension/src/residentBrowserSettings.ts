import type { RuntimeClient } from "@vaultkern/runtime-web-client";
import {
  DEFAULT_EXTENSION_SETTINGS,
  normalizeBrowserExtensionSettings
} from "@vaultkern/shared-web-ui";
import type {
  ExtensionSettings,
  ExtensionSettingsStore
} from "@vaultkern/shared-web-ui";

export async function loadResidentBrowserSettings(
  client: Pick<RuntimeClient, "getBrowserIntegrationSettings">
): Promise<ExtensionSettings> {
  const desired = await client.getBrowserIntegrationSettings();
  return normalizeBrowserExtensionSettings({
    ...DEFAULT_EXTENSION_SETTINGS,
    language: desired.language,
    autofillOnPageLoadEnabled: desired.autofillOnPageLoadEnabled,
    browserPasskeyProxyEnabled: desired.browserPasskeyProxyEnabled
  });
}

export function createResidentBrowserSettingsStore(
  client: Pick<RuntimeClient, "getBrowserIntegrationSettings">
): Pick<ExtensionSettingsStore, "load"> {
  return {
    load: () => loadResidentBrowserSettings(client)
  };
}
