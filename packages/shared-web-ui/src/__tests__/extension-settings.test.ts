import { expect, it, vi } from "vitest";

import {
  DEFAULT_EXTENSION_SETTINGS,
  createMemoryExtensionSettingsStore,
  normalizeExtensionSettings,
  normalizeWindowsAppSettings
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

it("keeps browser integration desired state in the resident Windows settings", () => {
  expect(
    normalizeWindowsAppSettings({
      autofillOnPageLoadEnabled: true,
      browserPasskeyProxyEnabled: true,
      windowsPasskeyProviderEnabled: false
    })
  ).toMatchObject({
    autofillOnPageLoadEnabled: true,
    browserPasskeyProxyEnabled: true,
    windowsPasskeyProviderEnabled: false
  });
});

it("uses the legacy passkey setting only when a replacement field is absent", () => {
  expect(
    normalizeWindowsAppSettings({
      passkeyProviderEnabled: true,
      browserPasskeyProxyEnabled: false,
      windowsPasskeyProviderEnabled: false
    })
  ).toMatchObject({
    browserPasskeyProxyEnabled: false,
    windowsPasskeyProviderEnabled: false
  });
});

it("persists extension settings in the memory store", async () => {
  const store = createMemoryExtensionSettingsStore();

  await store.save({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    autofillOnPageLoadEnabled: true,
    browserPasskeyProxyEnabled: false,
    windowsPasskeyProviderEnabled: false,
    quickUnlockEnabled: true
  });

  await expect(store.load()).resolves.toEqual({
    recentVaultLimit: 3,
    language: "zh-CN",
    idleLockMinutes: 5,
    autofillOnPageLoadEnabled: true,
    browserPasskeyProxyEnabled: false,
    windowsPasskeyProviderEnabled: false,
    quickUnlockEnabled: true
  });
});
