import { expect, it, vi } from "vitest";

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

it("applies the passkey-provider preference when settings load and save", async () => {
  const applyPasskeyProviderSetting = vi.fn(async (_enabled: boolean) => undefined);
  const store = createDesktopSettingsStore(
    window.localStorage,
    applyPasskeyProviderSetting
  );

  await store.load();
  expect(applyPasskeyProviderSetting).toHaveBeenLastCalledWith(false);

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });
  expect(applyPasskeyProviderSetting).toHaveBeenLastCalledWith(true);
});

it("rolls back the provider when persisting its setting fails", async () => {
  const applyPasskeyProviderSetting = vi.fn(async (_enabled: boolean) => undefined);
  const storage = {
    getItem: vi.fn(() => JSON.stringify(DEFAULT_EXTENSION_SETTINGS)),
    setItem: vi.fn(() => {
      throw new Error("simulated local-storage failure");
    }),
    removeItem: vi.fn()
  };
  const store = createDesktopSettingsStore(storage, applyPasskeyProviderSetting);

  await expect(
    store.save({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  ).rejects.toThrow("simulated local-storage failure");

  expect(applyPasskeyProviderSetting.mock.calls).toEqual([[true], [false]]);
});
