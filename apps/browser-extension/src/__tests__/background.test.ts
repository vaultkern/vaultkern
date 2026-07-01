import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.useRealTimers();
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
  it("keeps the native session alive after an unlocked session response", async () => {
    vi.useFakeTimers();
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
      listener?.({ version: 1, command: { type: "get_session_state" } }, {}, resolve);
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    await responsePromise;

    await vi.advanceTimersByTimeAsync(20_000);

    expect(port.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });
    expect(port.postMessage).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

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

  it("does not attach the WebAuthn proxy when no passkey provider setting is saved", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({});
          },
          set() {}
        },
        onChanged: {
          addListener() {}
        }
      },
      webAuthenticationProxy: {
        attach
      }
    };

    await import("../background");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(attach).not.toHaveBeenCalled();
  });

  it("attaches the WebAuthn proxy when explicitly enabled", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const registerContentScripts = vi.fn(async () => undefined);
    const executeScript = vi.fn(async () => undefined);
    const query = vi.fn(async () => [{ id: 7 }, { id: 8 }, { id: "not-a-tab" }]);
    let storedItems: Record<string, unknown> = {};

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
            const items = {
              ...storedItems,
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: true
              }
            };
            if (callback) {
              callback(items);
              return undefined;
            }
            return Promise.resolve(items);
          },
          set(items: Record<string, unknown>, callback?: () => void) {
            storedItems = { ...storedItems, ...items };
            callback?.();
            return Promise.resolve();
          }
        },
        onChanged: {
          addListener() {}
        }
      },
      scripting: {
        executeScript,
        registerContentScripts
      },
      tabs: {
        query
      },
      webAuthenticationProxy: {
        attach
      }
    };

    await import("../background");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(attach).toHaveBeenCalledTimes(1);
    expect(registerContentScripts).toHaveBeenCalledWith([
      {
        id: "vaultkern-webauthn-page-hook",
        matches: ["<all_urls>"],
        js: ["webauthnPageHook.js"],
        runAt: "document_start",
        world: "MAIN",
        allFrames: true,
        persistAcrossSessions: false
      }
    ]);
    expect(query).toHaveBeenCalledWith({
      url: ["http://*/*", "https://*/*"]
    });
    expect(executeScript).toHaveBeenCalledTimes(2);
    expect(executeScript).toHaveBeenCalledWith({
      target: { tabId: 7, allFrames: true },
      files: ["webauthnPageHook.js"],
      world: "MAIN"
    });
    expect(executeScript).toHaveBeenCalledWith({
      target: { tabId: 8, allFrames: true },
      files: ["webauthnPageHook.js"],
      world: "MAIN"
    });
    await vi.waitFor(() => {
      expect(storedItems.vaultkernWebAuthnDebug).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ event: "page_hook_registered" })
        ])
      );
    });
  });

  it("unregisters the WebAuthn page hook when the provider is disabled", async () => {
    const port = createPort();
    const detach = vi.fn(async () => undefined);
    const unregisterContentScripts = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false
              }
            });
          },
          set() {}
        },
        onChanged: {
          addListener() {}
        }
      },
      scripting: {
        unregisterContentScripts
      },
      webAuthenticationProxy: {
        detach
      }
    };

    await import("../background");

    await vi.waitFor(() => {
      expect(unregisterContentScripts).toHaveBeenCalledWith({
        ids: ["vaultkern-webauthn-page-hook"]
      });
    });
  });

  it("registers WebAuthn request listeners before async settings load finishes", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const addGetListener = vi.fn();
    const addCreateListener = vi.fn();
    let resolveSettings: (items: Record<string, unknown>) => void = () => {};

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            new Promise<Record<string, unknown>>((resolve) => {
              resolveSettings = resolve;
            }).then(callback);
          },
          set() {}
        },
        onChanged: {
          addListener() {}
        }
      },
      webAuthenticationProxy: {
        attach,
        onGetRequest: {
          addListener: addGetListener
        },
        onCreateRequest: {
          addListener: addCreateListener
        },
        onRequestCanceled: {
          addListener() {}
        }
      }
    };

    await import("../background");

    expect(addGetListener).toHaveBeenCalledTimes(1);
    expect(addCreateListener).toHaveBeenCalledTimes(1);
    expect(attach).not.toHaveBeenCalled();

    resolveSettings({
      vaultkernExtensionSettings: {
        recentVaultLimit: 10,
        language: "en",
        idleLockMinutes: 10,
        clearClipboardSeconds: 30,
        passkeyProviderEnabled: true
      }
    });

    await vi.waitFor(() => {
      expect(attach).toHaveBeenCalledTimes(1);
    });
  });

  it("does not attach the WebAuthn proxy when the passkey provider setting is disabled", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false
              }
            });
          },
          set() {}
        },
        onChanged: {
          addListener() {}
        }
      },
      webAuthenticationProxy: {
        attach
      }
    };

    await import("../background");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(attach).not.toHaveBeenCalled();
  });

  it("detaches the WebAuthn proxy defensively when the disabled setting loads after restart", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => undefined);

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled: false
              }
            });
          },
          set() {}
        },
        onChanged: {
          addListener() {}
        }
      },
      webAuthenticationProxy: {
        attach,
        detach
      }
    };

    await import("../background");

    await vi.waitFor(() => {
      expect(detach).toHaveBeenCalledTimes(1);
    });
    expect(attach).not.toHaveBeenCalled();
  });

  it("detaches the WebAuthn proxy when the passkey provider setting is disabled later", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => undefined);
    let passkeyProviderEnabled = true;
    let storageListener:
      | ((changes: Record<string, unknown>, areaName: string) => void)
      | undefined;

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled
              }
            });
          },
          set() {}
        },
        onChanged: {
          addListener(
            listener: (changes: Record<string, unknown>, areaName: string) => void
          ) {
            storageListener = listener;
          }
        }
      },
      webAuthenticationProxy: {
        attach,
        detach
      }
    };

    await import("../background");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(attach).toHaveBeenCalledTimes(1);

    passkeyProviderEnabled = false;
    storageListener?.({ vaultkernExtensionSettings: {} }, "local");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(detach).toHaveBeenCalledTimes(1);
  });

  it("re-runs WebAuthn proxy sync when settings change during attach", async () => {
    const port = createPort();
    let resolveAttach: () => void = () => {};
    const attach = vi.fn(
      () =>
        new Promise<undefined>((resolve) => {
          resolveAttach = () => resolve(undefined);
        })
    );
    const detach = vi.fn(async () => undefined);
    let passkeyProviderEnabled = true;
    let storageListener:
      | ((changes: Record<string, unknown>, areaName: string) => void)
      | undefined;

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative: vi.fn(() => port),
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback: (items: Record<string, unknown>) => void) {
            callback({
              vaultkernExtensionSettings: {
                recentVaultLimit: 10,
                language: "en",
                idleLockMinutes: 10,
                clearClipboardSeconds: 30,
                passkeyProviderEnabled
              }
            });
          },
          set() {}
        },
        onChanged: {
          addListener(
            listener: (changes: Record<string, unknown>, areaName: string) => void
          ) {
            storageListener = listener;
          }
        }
      },
      webAuthenticationProxy: {
        attach,
        detach
      }
    };

    await import("../background");
    await vi.waitFor(() => {
      expect(attach).toHaveBeenCalledTimes(1);
    });

    passkeyProviderEnabled = false;
    storageListener?.({ vaultkernExtensionSettings: {} }, "local");
    resolveAttach();

    await vi.waitFor(() => {
      expect(detach).toHaveBeenCalledTimes(1);
    });
  });
});
