import { afterEach, expect, it, vi } from "vitest";

import { DEFAULT_EXTENSION_SETTINGS } from "@vaultkern/shared-web-ui";

import { createDesktopSettingsStore } from "./settingsStore";

afterEach(() => {
  window.localStorage.clear();
});

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

it("reconciles provider registration while locked without syncing credential metadata", async () => {
  window.localStorage.setItem(
    "vaultkern.desktop.settings.v1",
    JSON.stringify({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  );
  let providerRegistered = false;
  let credentialMetadata = ["existing-credential"];
  const reconcilePlatformSettings = vi.fn(
    async (
      enabled: boolean,
      context?: { reason: string; vaultUnlocked: boolean }
    ) => {
      providerRegistered = enabled;
      if (context?.vaultUnlocked !== false) {
        credentialMetadata = [];
      }
    }
  );
  const store = createDesktopSettingsStore(
    window.localStorage,
    reconcilePlatformSettings
  ) as ReturnType<typeof createDesktopSettingsStore> & {
    reconcile?: (context: {
      reason: "startup";
      vaultUnlocked: boolean;
    }) => Promise<void>;
  };

  await store.load();
  await store.reconcile?.({ reason: "startup", vaultUnlocked: false });

  expect(providerRegistered).toBe(true);
  expect(credentialMetadata).toEqual(["existing-credential"]);
  expect(reconcilePlatformSettings).toHaveBeenLastCalledWith(true, {
    reason: "startup",
    vaultUnlocked: false
  });
});

it("keeps load and save pure and reconciles the last persisted provider preference explicitly", async () => {
  const reconcilePasskeyProviderSetting = vi.fn(
    async (_enabled: boolean, _context: unknown) => undefined
  );
  const store = createDesktopSettingsStore(
    window.localStorage,
    reconcilePasskeyProviderSetting
  );

  await store.load();
  expect(reconcilePasskeyProviderSetting).not.toHaveBeenCalled();

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });
  expect(reconcilePasskeyProviderSetting).not.toHaveBeenCalled();

  await store.reconcile?.({
    reason: "settings-commit",
    vaultUnlocked: false
  });
  expect(reconcilePasskeyProviderSetting).toHaveBeenLastCalledWith(true, {
    reason: "settings-commit",
    vaultUnlocked: false
  });
});

it("does not rewrite desired provider state when reconciliation fails", async () => {
  window.localStorage.setItem(
    "vaultkern.desktop.settings.v1",
    JSON.stringify({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  );
  const reconcilePasskeyProviderSetting = vi.fn(async () => {
    throw new Error("plugin authenticator is unavailable");
  });
  const store = createDesktopSettingsStore(
    window.localStorage,
    reconcilePasskeyProviderSetting
  );

  await expect(store.load()).resolves.toMatchObject({
    passkeyProviderEnabled: true
  });
  await expect(
    store.reconcile?.({ reason: "startup", vaultUnlocked: false })
  ).rejects.toThrow("plugin authenticator is unavailable");
  await expect(store.load()).resolves.toMatchObject({
    passkeyProviderEnabled: true
  });
});

it("does not replace desired provider state with the current Windows result", async () => {
  window.localStorage.setItem(
    "vaultkern.desktop.settings.v1",
    JSON.stringify({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  );
  const reconcilePasskeyProviderSetting = vi.fn(async () => false);

  const store = createDesktopSettingsStore(
    window.localStorage,
    reconcilePasskeyProviderSetting
  );

  await store.reconcile?.({ reason: "startup", vaultUnlocked: false });
  await expect(store.load()).resolves.toMatchObject({
    passkeyProviderEnabled: true
  });
  expect(reconcilePasskeyProviderSetting).toHaveBeenCalledWith(true, {
    reason: "startup",
    vaultUnlocked: false
  });
});

it("persists desired provider state independently of the current Windows result", async () => {
  const reconcilePasskeyProviderSetting = vi.fn(async (_enabled: boolean) => {
    return false;
  });
  const storage = {
    getItem: vi.fn(() => JSON.stringify(DEFAULT_EXTENSION_SETTINGS)),
    setItem: vi.fn(),
    removeItem: vi.fn()
  };
  const store = createDesktopSettingsStore(storage, reconcilePasskeyProviderSetting);

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });

  expect(storage.setItem).toHaveBeenCalledWith(
    "vaultkern.desktop.settings.v1",
    JSON.stringify({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: true
    })
  );
  expect(reconcilePasskeyProviderSetting).not.toHaveBeenCalled();
});

it("accepts a false Windows result when disabling the provider", async () => {
  const applyPasskeyProviderSetting = vi.fn(async () => false);
  const storage = {
    getItem: vi.fn(() =>
      JSON.stringify({
        ...DEFAULT_EXTENSION_SETTINGS,
        passkeyProviderEnabled: true
      })
    ),
    setItem: vi.fn(),
    removeItem: vi.fn()
  };
  const store = createDesktopSettingsStore(storage, applyPasskeyProviderSetting);

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: false
  });

  expect(storage.setItem).toHaveBeenCalledWith(
    "vaultkern.desktop.settings.v1",
    JSON.stringify({
      ...DEFAULT_EXTENSION_SETTINGS,
      passkeyProviderEnabled: false
    })
  );
});

it("does not touch the provider when persisting desired state fails", async () => {
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

  expect(applyPasskeyProviderSetting).not.toHaveBeenCalled();
});

it("applies a provider preference saved while locked at the next unlock reconciliation", async () => {
  const reconcilePasskeyProviderSetting = vi.fn(
    async (_enabled: boolean, _context: unknown) => undefined
  );
  const store = createDesktopSettingsStore(
    window.localStorage,
    reconcilePasskeyProviderSetting
  );

  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    passkeyProviderEnabled: true
  });
  expect(reconcilePasskeyProviderSetting).not.toHaveBeenCalled();

  await store.reconcile?.({ reason: "unlock", vaultUnlocked: true });

  expect(reconcilePasskeyProviderSetting).toHaveBeenCalledWith(true, {
    reason: "unlock",
    vaultUnlocked: true
  });
});
