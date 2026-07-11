import { expect, it, vi } from "vitest";

import {
  DEFAULT_EXTENSION_SETTINGS,
  createMemoryExtensionSettingsStore,
  normalizeExtensionSettings
} from "../extensionSettings";

it("normalizes missing extension settings to defaults", () => {
  expect(normalizeExtensionSettings({})).toEqual(DEFAULT_EXTENSION_SETTINGS);
});

it("keeps page-load autofill disabled unless the user explicitly enables it", () => {
  expect(normalizeExtensionSettings({})).toMatchObject({
    autofillOnPageLoadEnabled: false
  });
  expect(
    normalizeExtensionSettings({
      autofillOnPageLoadEnabled: true
    })
  ).toMatchObject({
    autofillOnPageLoadEnabled: true
  });
});

it("persists extension settings in the memory store", async () => {
  const store = createMemoryExtensionSettingsStore();

  await store.save({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    clearClipboardSeconds: 20,
    autofillOnPageLoadEnabled: true,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });

  await expect(store.load()).resolves.toEqual({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    clearClipboardSeconds: 20,
    autofillOnPageLoadEnabled: true,
    passkeyProviderEnabled: false,
    quickUnlockEnabled: true
  });
});
