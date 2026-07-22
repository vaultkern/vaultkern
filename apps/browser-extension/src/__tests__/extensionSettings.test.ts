import { afterEach, expect, it } from "vitest";

import { createChromeExtensionSettingsStore } from "../extensionSettings";

afterEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

it("loads extension settings from chrome storage with defaults", async () => {
  const storage = new Map<string, unknown>();
  const store = createChromeExtensionSettingsStore({
    get(keys, callback) {
      callback({ vaultkernExtensionSettings: storage.get("vaultkernExtensionSettings") });
    },
    set(values, callback) {
      for (const [key, value] of Object.entries(values)) {
        storage.set(key, value);
      }
      callback?.();
    }
  });

  await expect(store.load()).resolves.toMatchObject({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 10,
    clearClipboardSeconds: 30
  });
});

it("rejects a settings load when chrome storage reports lastError", async () => {
  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    runtime: { lastError: { message: "settings read denied" } }
  };
  const store = createChromeExtensionSettingsStore({
    get(_keys, callback) {
      callback({});
    },
    set(_values, callback) {
      callback?.();
    }
  });

  await expect(store.load()).rejects.toThrow("settings read denied");
});

it("rejects a settings save when chrome storage reports lastError", async () => {
  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    runtime: { lastError: { message: "settings write denied" } }
  };
  const store = createChromeExtensionSettingsStore({
    get(_keys, callback) {
      callback({});
    },
    set(_values, callback) {
      callback?.();
    }
  });

  await expect(
    store.save({
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 10,
      clearClipboardSeconds: 30,
      autofillOnPageLoadEnabled: false,
      browserPasskeyProxyEnabled: false,
      quickUnlockEnabled: false
    })
  ).rejects.toThrow("settings write denied");
});

it("rejects settings persistence when chrome storage is unavailable", async () => {
  const store = createChromeExtensionSettingsStore();

  await expect(
    store.save({
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 10,
      clearClipboardSeconds: 30,
      autofillOnPageLoadEnabled: false,
      browserPasskeyProxyEnabled: false,
      windowsPasskeyProviderEnabled: false,
      quickUnlockEnabled: false
    })
  ).rejects.toThrow("chrome settings storage is unavailable");
});
