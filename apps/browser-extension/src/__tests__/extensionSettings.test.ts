import { expect, it } from "vitest";

import { createChromeExtensionSettingsStore } from "../extensionSettings";

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
