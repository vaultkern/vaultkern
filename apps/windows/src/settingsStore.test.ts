import { expect, it } from "vitest";

import { DEFAULT_EXTENSION_SETTINGS } from "@vaultkern/shared-web-ui";

import { createDesktopSettingsStore } from "./settingsStore";

it("persists normalized desktop settings in local storage", async () => {
  const store = createDesktopSettingsStore(window.localStorage);
  const settings = {
    ...DEFAULT_EXTENSION_SETTINGS,
    recentVaultLimit: 4,
    quickUnlockEnabled: true
  };

  await store.save(settings);

  await expect(store.load()).resolves.toEqual(settings);
});

it("recovers from a corrupt desktop settings value", async () => {
  window.localStorage.setItem("vaultkern.desktop.settings.v1", "not-json");

  await expect(
    createDesktopSettingsStore(window.localStorage).load()
  ).resolves.toEqual(DEFAULT_EXTENSION_SETTINGS);
});
