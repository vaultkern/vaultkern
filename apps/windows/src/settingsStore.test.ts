import { expect, it, vi } from "vitest";

import { DEFAULT_EXTENSION_SETTINGS } from "@vaultkern/shared-web-ui";

import { createDesktopSettingsStore } from "./settingsStore";

it("persists normalized desired settings through the native store", async () => {
  let persisted: unknown = {};
  const saveDesired = vi.fn(async (settings) => {
    persisted = settings;
  });
  const store = createDesktopSettingsStore(
    async () => persisted,
    saveDesired
  );
  const settings = {
    ...DEFAULT_EXTENSION_SETTINGS,
    recentVaultLimit: 4,
    quickUnlockEnabled: true
  };

  await store.save(settings);

  expect(saveDesired).toHaveBeenCalledWith(settings);
  await expect(store.load()).resolves.toEqual(settings);
});

it("normalizes an absent native settings generation", async () => {
  const store = createDesktopSettingsStore(
    async () => ({}),
    async () => undefined
  );

  await expect(store.load()).resolves.toEqual(DEFAULT_EXTENSION_SETTINGS);
});

it("keeps load and save pure and reconciles native state explicitly", async () => {
  let persisted = DEFAULT_EXTENSION_SETTINGS;
  const reconcileNative = vi.fn(async (_context: unknown) => undefined);
  const store = createDesktopSettingsStore(
    async () => persisted,
    async (settings) => {
      persisted = settings;
    },
    reconcileNative
  );

  await store.load();
  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });
  expect(reconcileNative).not.toHaveBeenCalled();

  await store.reconcile?.({
    reason: "settings-commit",
    vaultUnlocked: false
  });
  expect(reconcileNative).toHaveBeenLastCalledWith({
    reason: "settings-commit",
    vaultUnlocked: false
  });
});

it("does not run reconciliation when native desired-state persistence fails", async () => {
  const reconcileNative = vi.fn(async () => undefined);
  const store = createDesktopSettingsStore(
    async () => DEFAULT_EXTENSION_SETTINGS,
    async () => {
      throw new Error("simulated native settings failure");
    },
    reconcileNative
  );

  await expect(
    store.save({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  ).rejects.toThrow("simulated native settings failure");
  expect(reconcileNative).not.toHaveBeenCalled();
});

it("a locked startup reconciliation never drives credential sync with empty data", async () => {
  let providerRegistered = false;
  let credentialMetadata = ["existing-credential"];
  const store = createDesktopSettingsStore(
    async () => ({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    }),
    async () => undefined,
    async (context) => {
      providerRegistered = true;
      if (context.vaultUnlocked) {
        credentialMetadata = ["unlocked-credential"];
      }
    }
  );

  await store.reconcile?.({ reason: "startup", vaultUnlocked: false });

  expect(providerRegistered).toBe(true);
  expect(credentialMetadata).toEqual(["existing-credential"]);
});

it("unlock reconciliation applies provider state persisted before a crashed reconciliation", async () => {
  let persisted = DEFAULT_EXTENSION_SETTINGS;
  let providerRegistered = false;
  const store = createDesktopSettingsStore(
    async () => persisted,
    async (settings) => {
      persisted = settings;
    },
    async (context) => {
      if (context.vaultUnlocked) {
        providerRegistered = persisted.passkeyProviderEnabled;
      }
    }
  );

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });
  expect(providerRegistered).toBe(false);

  await store.reconcile?.({ reason: "unlock", vaultUnlocked: true });

  expect(providerRegistered).toBe(true);
});

it("a reconciliation failure never rewrites desired state", async () => {
  const desired = {
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  };
  const saveDesired = vi.fn(async () => undefined);
  const store = createDesktopSettingsStore(
    async () => desired,
    saveDesired,
    async () => {
      throw new Error("plugin authenticator is unavailable");
    }
  );

  await expect(
    store.reconcile?.({ reason: "startup", vaultUnlocked: false })
  ).rejects.toThrow("plugin authenticator is unavailable");
  await expect(store.load()).resolves.toEqual(desired);
  expect(saveDesired).not.toHaveBeenCalled();
});
