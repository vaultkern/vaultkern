import { expect, it, vi } from "vitest";

import {
  DEFAULT_EXTENSION_SETTINGS,
  createMemoryExtensionSettingsStore,
  loadRuntimeOwnedExtensionSettings,
  normalizeExtensionSettings,
  saveRuntimeOwnedExtensionSettings
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

it("initializes an unset runtime quick unlock policy from the legacy local setting", async () => {
  const store = createMemoryExtensionSettingsStore({
    ...DEFAULT_EXTENSION_SETTINGS,
    quickUnlockEnabled: true
  });
  const initializedState = {
    type: "quick_unlock_state" as const,
    policyEnabled: true,
    capability: "available" as const,
    recordState: "setup_required" as const,
    canQuickUnlock: false,
    requiresPassword: true,
    lastError: null
  };
  const client = {
    getQuickUnlockState: vi.fn(async () => ({
      ...initializedState,
      policyEnabled: null
    })),
    initializeQuickUnlockPolicy: vi.fn(async () => initializedState)
  };

  const loaded = await loadRuntimeOwnedExtensionSettings(store, client);

  expect(client.initializeQuickUnlockPolicy).toHaveBeenCalledWith(true);
  expect(loaded.settings.quickUnlockEnabled).toBe(true);
  expect(loaded.quickUnlockState).toEqual(initializedState);
});

it("repairs the legacy local mirror from the runtime-owned policy", async () => {
  const store = createMemoryExtensionSettingsStore({
    ...DEFAULT_EXTENSION_SETTINGS,
    quickUnlockEnabled: true
  });
  const save = vi.spyOn(store, "save");
  const client = {
    getQuickUnlockState: vi.fn(async () => ({
      type: "quick_unlock_state" as const,
      policyEnabled: false,
      capability: "available" as const,
      recordState: "absent" as const,
      canQuickUnlock: false,
      requiresPassword: true,
      lastError: null
    })),
    initializeQuickUnlockPolicy: vi.fn()
  };

  const loaded = await loadRuntimeOwnedExtensionSettings(store, client);

  expect(client.initializeQuickUnlockPolicy).not.toHaveBeenCalled();
  expect(loaded.settings.quickUnlockEnabled).toBe(false);
  expect(save).toHaveBeenCalledWith(
    expect.objectContaining({ quickUnlockEnabled: false })
  );
});

it("persists the runtime quick unlock policy before updating its local mirror", async () => {
  const events: string[] = [];
  const store = createMemoryExtensionSettingsStore();
  const save = vi.spyOn(store, "save").mockImplementation(async () => {
    events.push("local");
  });
  const client = {
    setQuickUnlockPolicy: vi.fn(async () => {
      events.push("runtime");
      return {
        type: "quick_unlock_state" as const,
        policyEnabled: true,
        capability: "available" as const,
        recordState: "setup_required" as const,
        canQuickUnlock: false,
        requiresPassword: true,
        lastError: null
      };
    })
  };
  const settings = { ...DEFAULT_EXTENSION_SETTINGS, quickUnlockEnabled: true };

  const state = await saveRuntimeOwnedExtensionSettings(store, client, settings);

  expect(events).toEqual(["runtime", "local"]);
  expect(save).toHaveBeenCalledWith(settings);
  expect(state.policyEnabled).toBe(true);
});
