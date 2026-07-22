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

it("marks native reconciliation as runtime-owned without exposing a second executor", async () => {
  let persisted = DEFAULT_EXTENSION_SETTINGS;
  const store = createDesktopSettingsStore(
    async () => persisted,
    async (settings) => {
      persisted = settings;
    }
  );

  await store.load();
  await store.save({
    ...DEFAULT_EXTENSION_SETTINGS,
    windowsPasskeyProviderEnabled: true
  });
  expect(store.nativeReconciliationOwned).toBe(true);
  expect("reconcile" in store).toBe(false);
});

it("does not run reconciliation when native desired-state persistence fails", async () => {
  const store = createDesktopSettingsStore(
    async () => DEFAULT_EXTENSION_SETTINGS,
    async () => {
      throw new Error("simulated native settings failure");
    }
  );

  await expect(
    store.save({
      ...DEFAULT_EXTENSION_SETTINGS,
      windowsPasskeyProviderEnabled: true
    })
  ).rejects.toThrow("simulated native settings failure");
  expect(store.nativeReconciliationOwned).toBe(true);
});

it("forwards manual quick-unlock enrollment only as input to the native reconciler", async () => {
  const queueEnrollment = vi.fn(async () => undefined);
  const store = createDesktopSettingsStore(
    async () => DEFAULT_EXTENSION_SETTINGS,
    async () => undefined,
    queueEnrollment
  );
  const credentials = {
    password: "demo-password",
    keyFilePath: "demo.keyx"
  };

  await store.queueQuickUnlockEnrollment?.(credentials);

  expect(queueEnrollment).toHaveBeenCalledWith(credentials);
});

it("exposes persisted and live native reconciliation failures", async () => {
  const unsubscribe = vi.fn();
  const subscribe = vi.fn(
    async (listener: (error: string | null) => void) => {
      listener(null);
      return unsubscribe;
    }
  );
  const store = createDesktopSettingsStore(
    async () => DEFAULT_EXTENSION_SETTINGS,
    async () => undefined,
    async () => undefined,
    async () => "provider registration failed",
    subscribe
  );
  const observed = vi.fn();

  await expect(store.loadReconciliationError?.()).resolves.toBe(
    "provider registration failed"
  );
  const stop = await store.subscribeReconciliationError?.(observed);
  expect(observed).toHaveBeenCalledWith(null);

  stop?.();
  expect(unsubscribe).toHaveBeenCalledTimes(1);
});
