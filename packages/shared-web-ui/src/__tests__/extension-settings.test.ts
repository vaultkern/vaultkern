import { expect, it, vi } from "vitest";

import {
  DEFAULT_EXTENSION_SETTINGS,
  createMemoryExtensionSettingsStore,
  normalizeExtensionSettings
} from "../extensionSettings";

it("normalizes missing extension settings to defaults", () => {
  expect(normalizeExtensionSettings({})).toEqual(DEFAULT_EXTENSION_SETTINGS);
});

it("persists extension settings in the memory store", async () => {
  const store = createMemoryExtensionSettingsStore();

  await store.save({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    clearClipboardSeconds: 20,
    passkeyProviderEnabled: false
  });

  await expect(store.load()).resolves.toEqual({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    clearClipboardSeconds: 20,
    passkeyProviderEnabled: false
  });
});
