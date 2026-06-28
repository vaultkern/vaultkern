import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.resetModules();
});

beforeEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

function createPort() {
  const messageListeners: Array<(message: unknown) => void> = [];
  const disconnectListeners: Array<() => void> = [];

  return {
    postMessage: vi.fn(),
    onMessage: {
      addListener(listener: (message: unknown) => void) {
        messageListeners.push(listener);
      }
    },
    onDisconnect: {
      addListener(listener: () => void) {
        disconnectListeners.push(listener);
      }
    },
    emitMessage(message: unknown) {
      for (const listener of messageListeners) {
        listener(message);
      }
    },
    emitDisconnect() {
      for (const listener of disconnectListeners) {
        listener();
      }
    }
  };
}

describe("background bridge", () => {
  it("forwards runtime commands to the native bridge and returns the response", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    let listener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => boolean)
      | undefined;

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener(fn: typeof listener) {
            listener = fn;
          }
        }
      }
    };

    await import("../background");

    if (!listener) {
      throw new Error("background listener was not registered");
    }

    const responsePromise = new Promise<unknown>((resolve) => {
      const handled = listener(
        { version: 1, command: { type: "get_session_state" } },
        {},
        resolve
      );

      expect(handled).toBe(true);
    });

    expect(connectNative).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      supportsBiometricUnlock: false
    });

    await expect(responsePromise).resolves.toEqual({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      supportsBiometricUnlock: false
    });
  });

  it("returns a serialized error when the native bridge rejects", async () => {
    let listener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => boolean)
      | undefined;
    const connectNative = vi.fn(() => {
      throw new Error("Specified native messaging host not found.");
    });
    let resolveResponse: (response: unknown) => void = () => {};
    const responsePromise = new Promise<unknown>((resolve) => {
      resolveResponse = resolve;
    });

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener(fn: typeof listener) {
            listener = fn;
          }
        }
      }
    };

    await import("../background");

    if (!listener) {
      throw new Error("background listener was not registered");
    }

    const handled = listener(
      { version: 1, command: { type: "get_session_state" } },
      {},
      resolveResponse
    );

    expect(handled).toBe(true);

    await expect(responsePromise).resolves.toEqual({
      error: {
        code: "native_host_missing",
        message: "Specified native messaging host not found."
      }
    });
  });
});
