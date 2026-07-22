import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

function installChromeStorage(
  settings: Record<string, unknown>,
  options: { failNextSave?: string } = {}
) {
  let storedSettings = structuredClone(settings);
  let nextSaveError = options.failNextSave ?? null;
  const connectNative = vi.fn();
  const set = vi.fn((values: Record<string, unknown>, callback?: () => void) => {
    const chromeApi = (globalThis as typeof globalThis & { chrome: any }).chrome;
    if (nextSaveError) {
      chromeApi.runtime.lastError = { message: nextSaveError };
      nextSaveError = null;
      callback?.();
      delete chromeApi.runtime.lastError;
      return;
    }
    storedSettings = structuredClone(
      values.vaultkernExtensionSettings as Record<string, unknown>
    );
    callback?.();
  });

  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    runtime: { connectNative },
    storage: {
      local: {
        get: vi.fn((_key, callback) =>
          callback({
            vaultkernExtensionSettings: storedSettings
          })
        ),
        set
      }
    }
  };

  return {
    connectNative,
    set,
    readStoredSettings: () => structuredClone(storedSettings)
  };
}

async function renderOptionsPage() {
  document.body.innerHTML = '<div id="root"></div>';
  await import("../options");
}

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = "";
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

afterEach(() => {
  cleanup();
});

it("persists browser desired state without invoking resident runtime effects", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    browserPasskeyProxyEnabled: false,
    quickUnlockEnabled: true
  });

  await renderOptionsPage();

  expect(await screen.findByText("Browser Extension Settings")).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: "Quick Unlock" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox", { name: "Browser passkey proxy" }));
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(chromeStorage.set).toHaveBeenCalledWith(
      {
        vaultkernExtensionSettings: expect.objectContaining({
          browserPasskeyProxyEnabled: true,
          quickUnlockEnabled: false
        })
      },
      expect.any(Function)
    );
  });
  expect(chromeStorage.connectNative).not.toHaveBeenCalled();
});

it("does not expose the resident-owned idle deadline as a browser setting", async () => {
  installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    browserPasskeyProxyEnabled: false,
    quickUnlockEnabled: false
  });

  await renderOptionsPage();

  expect(await screen.findByText("Browser Extension Settings")).toBeInTheDocument();
  expect(screen.queryByLabelText("Idle Lock Minutes")).not.toBeInTheDocument();
});

it("persists the recent vault presentation limit", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    browserPasskeyProxyEnabled: false,
    quickUnlockEnabled: false
  });

  await renderOptionsPage();

  const limitInput = await screen.findByLabelText("Recent Databases");
  fireEvent.change(limitInput, {
    target: { value: "2" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  await waitFor(() => {
    expect(chromeStorage.set).toHaveBeenCalledWith(
      {
        vaultkernExtensionSettings: expect.objectContaining({
          recentVaultLimit: 2
        })
      },
      expect.any(Function)
    );
  });
  expect(chromeStorage.connectNative).not.toHaveBeenCalled();
});

it("keeps the browser settings draft when persistence fails", async () => {
  const chromeStorage = installChromeStorage({
    recentVaultLimit: 10,
    language: "en",
    idleLockMinutes: 0,
    clearClipboardSeconds: 30,
    browserPasskeyProxyEnabled: false,
    quickUnlockEnabled: false
  }, {
    failNextSave: "settings write denied"
  });

  await renderOptionsPage();

  fireEvent.change(await screen.findByLabelText("Recent Databases"), {
    target: { value: "4" }
  });
  fireEvent.click(await screen.findByText("中文"));
  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("settings write denied");
  expect(screen.getByLabelText("Recent Databases")).toHaveValue(4);
  expect(chromeStorage.readStoredSettings()).toMatchObject({
    recentVaultLimit: 10,
    language: "en"
  });

  fireEvent.click(screen.getByRole("button", { name: "Save Extension Settings" }));
  await waitFor(() => expect(chromeStorage.set).toHaveBeenCalledTimes(2));
  expect(chromeStorage.readStoredSettings()).toMatchObject({
    recentVaultLimit: 4,
    language: "zh-CN"
  });
  expect(chromeStorage.connectNative).not.toHaveBeenCalled();
});
