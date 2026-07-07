import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type RuntimeMessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void
) => boolean;
type StorageChangeListener = (
  changes: Record<string, unknown>,
  areaName: string
) => void;
type TabUpdatedListener = (
  tabId: number,
  changeInfo: { status?: string; url?: string }
) => void;

function createContentScriptRegistry(initialIds: string[] = []) {
  const registeredIds = new Set(initialIds);
  const registerContentScripts = vi.fn(
    async (scripts: Array<{ id?: string }>) => {
      for (const script of scripts) {
        if (!script.id) {
          throw new Error("content script id is required");
        }
        if (registeredIds.has(script.id)) {
          throw new Error(`Duplicate script ID: ${script.id}`);
        }
      }
      for (const script of scripts) {
        registeredIds.add(script.id as string);
      }
    }
  );
  const unregisterContentScripts = vi.fn(
    async (details: { ids?: string[] }) => {
      const ids = details.ids ?? [];
      const missingIds = ids.filter((id) => !registeredIds.has(id));
      if (missingIds.length > 0) {
        throw new Error(`Nonexistent script ID: ${missingIds.join(", ")}`);
      }
      for (const id of ids) {
        registeredIds.delete(id);
      }
    }
  );

  return {
    registerContentScripts,
    unregisterContentScripts,
    hasRegisteredContentScript(id: string) {
      return registeredIds.has(id);
    }
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.resetModules();
});

beforeEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

async function flushMicrotasks() {
  for (let index = 0; index < 6; index += 1) {
    await Promise.resolve();
  }
}

function sendRuntimeMessage(
  listeners: RuntimeMessageListener[],
  message: unknown,
  sender: unknown = {}
) {
  let response: unknown;
  const handled = listeners.some((listener) =>
    listener(message, sender, (value) => {
      response = value;
    })
  );

  expect(handled).toBe(true);
  return {
    async response() {
      await flushMicrotasks();
      return response;
    }
  };
}

function createPort() {
  const messageListeners: Array<(message: unknown) => void> = [];
  const disconnectListeners: Array<() => void> = [];
  const postedMessages: unknown[] = [];

  function latestPostedRequestId() {
    const message = postedMessages.at(-1);
    return typeof message === "object" &&
      message !== null &&
      "requestId" in message &&
      typeof (message as { requestId?: unknown }).requestId === "string"
      ? (message as { requestId: string }).requestId
      : null;
  }

  return {
    postMessage: vi.fn((message: unknown) => {
      postedMessages.push(message);
    }),
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
      const requestId = latestPostedRequestId();
      const response =
        requestId !== null &&
        typeof message === "object" &&
        message !== null &&
        !("requestId" in message)
          ? { ...message, requestId }
          : message;
      for (const listener of messageListeners) {
        listener(response);
      }
    },
    emitDisconnect() {
      for (const listener of disconnectListeners) {
        listener();
      }
    }
  };
}

async function completePasskeyLedgerReconciliation(
  port: ReturnType<typeof createPort>
) {
  await vi.waitFor(() => {
    expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
      version: 1,
      command: {
        type: "reconcile_passkey_ceremony_ledger",
        active_connection_id: expect.any(String)
      }
    }));
  });
  port.emitMessage({
    type: "passkey_ceremony_reconciliation",
    reconciled: []
  });
  await flushMicrotasks();
}

function passkeyCeremonyStorage(ceremonies: Record<string, unknown>) {
  const normalizedCeremonies = Object.fromEntries(
    Object.entries(ceremonies).map(([token, ceremony]) => [
      token,
      passkeyCeremonyStorageFixture(ceremony)
    ])
  );
  return {
    version: 1,
    ceremonies: normalizedCeremonies,
    checksum: passkeyCeremonyStorageChecksum(normalizedCeremonies)
  };
}

function passkeyCeremonyStorageFixture(ceremony: unknown) {
  const candidate = ceremony as Record<string, unknown> | null;
  if (
    !candidate ||
    typeof candidate !== "object" ||
    "userVerification" in candidate
  ) {
    return ceremony;
  }
  return {
    ...candidate,
    userVerification: "preferred"
  };
}

function passkeyCeremonyStorageChecksum(value: unknown) {
  let hash = 0x811c9dc5;
  const input = stableJson(value);
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `passkey-ceremonies-v1:${hash.toString(16).padStart(8, "0")}`;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item ?? null)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

describe("background bridge", () => {
  it("stores returns and clears a pending autofill submission", async () => {
    const listeners: RuntimeMessageListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      }
    };

    await import("../background");

    await sendRuntimeMessage(listeners, {
      type: "vaultkern_autofill_submission",
      url: "https://example.com/login",
      username: "alice",
      password: "secret",
      submittedAt: 1710000000000
    }).response();

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request"
      }).response()
    ).resolves.toEqual({
      pending: {
        url: "https://example.com/login",
        username: "alice",
        password: "secret",
        submittedAt: 1710000000000
      }
    });

    await sendRuntimeMessage(listeners, {
      type: "vaultkern_autofill_pending_clear"
    }).response();

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request"
      }).response()
    ).resolves.toEqual({ pending: null });
  });

  it("scopes pending autofill submissions to their source tab", async () => {
    const listeners: RuntimeMessageListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      }
    };

    await import("../background");

    await sendRuntimeMessage(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://one.example/login",
        username: "alice",
        password: "one-secret",
        submittedAt: 1710000000000
      },
      { tab: { id: 11 } }
    ).response();
    await sendRuntimeMessage(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://two.example/login",
        username: "bob",
        password: "two-secret",
        submittedAt: 1710000001000
      },
      { tab: { id: 22 } }
    ).response();

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 11
      }).response()
    ).resolves.toMatchObject({
      pending: {
        url: "https://one.example/login",
        username: "alice",
        password: "one-secret"
      }
    });
    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 22
      }).response()
    ).resolves.toMatchObject({
      pending: {
        url: "https://two.example/login",
        username: "bob",
        password: "two-secret"
      }
    });

    await sendRuntimeMessage(listeners, {
      type: "vaultkern_autofill_pending_clear",
      tabId: 11
    }).response();

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 11
      }).response()
    ).resolves.toEqual({ pending: null });
    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 22
      }).response()
    ).resolves.toMatchObject({
      pending: {
        url: "https://two.example/login",
        username: "bob",
        password: "two-secret"
      }
    });
  });

  it("clears tab-scoped pending autofill submissions after navigation", async () => {
    const listeners: RuntimeMessageListener[] = [];
    const tabUpdatedListeners: TabUpdatedListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      },
      tabs: {
        onUpdated: {
          addListener: vi.fn((listener: TabUpdatedListener) => {
            tabUpdatedListeners.push(listener);
          })
        }
      }
    };

    await import("../background");

    await sendRuntimeMessage(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://example.com/signup",
        username: "alice",
        password: "generated-secret",
        submittedAt: 1710000000000
      },
      { tab: { id: 7 } }
    ).response();

    for (const listener of tabUpdatedListeners) {
      listener(7, { url: "https://example.com/settings" });
    }

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 7
      }).response()
    ).resolves.toEqual({ pending: null });
  });

  it("keeps fresh tab-scoped pending autofill submissions after submit redirects", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1710000005000);
    const listeners: RuntimeMessageListener[] = [];
    const tabUpdatedListeners: TabUpdatedListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      },
      tabs: {
        onUpdated: {
          addListener: vi.fn((listener: TabUpdatedListener) => {
            tabUpdatedListeners.push(listener);
          })
        }
      }
    };

    await import("../background");

    await sendRuntimeMessage(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://example.com/signup",
        username: "alice",
        password: "generated-secret",
        saveOnly: true,
        submittedAt: 1710000000000
      },
      { tab: { id: 7 } }
    ).response();

    for (const listener of tabUpdatedListeners) {
      listener(7, { url: "https://example.com/welcome" });
    }

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 7
      }).response()
    ).resolves.toMatchObject({
      pending: {
        url: "https://example.com/signup",
        username: "alice",
        password: "generated-secret",
        saveOnly: true
      }
    });
  });

  it("does not restore navigation-cleared pending submissions from stale session storage", async () => {
    const listeners: RuntimeMessageListener[] = [];
    const tabUpdatedListeners: TabUpdatedListener[] = [];
    const sessionItems: Record<string, unknown> = {};

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      },
      tabs: {
        onUpdated: {
          addListener: vi.fn((listener: TabUpdatedListener) => {
            tabUpdatedListeners.push(listener);
          })
        }
      },
      storage: {
        session: {
          get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
            callback?.({ ...sessionItems });
            return Promise.resolve({ ...sessionItems });
          },
          set(items: Record<string, unknown>, callback?: () => void) {
            Object.assign(sessionItems, items);
            callback?.();
            return Promise.resolve();
          },
          remove(_keys: unknown, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          }
        }
      }
    };

    await import("../background");

    await sendRuntimeMessage(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://example.com/signup",
        username: "alice",
        password: "generated-secret",
        submittedAt: 1710000000000
      },
      { tab: { id: 7 } }
    ).response();
    const staleSessionItems = { ...sessionItems };

    for (const listener of tabUpdatedListeners) {
      listener(7, { url: "https://example.com/settings" });
    }
    Object.assign(sessionItems, staleSessionItems);

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 7
      }).response()
    ).resolves.toEqual({ pending: null });
  });

  it("keeps pending autofill submissions memory-only across background reloads", async () => {
    const sessionItems: Record<string, unknown> = {};
    const localSet = vi.fn();
    const sessionSet = vi.fn();

    function installChrome(listeners: RuntimeMessageListener[]) {
      (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
        runtime: {
          onMessage: {
            addListener: vi.fn((listener: RuntimeMessageListener) => {
              listeners.push(listener);
            })
          }
        },
        storage: {
          session: {
            get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
              callback?.({ ...sessionItems });
              return Promise.resolve({ ...sessionItems });
            },
            set(items: Record<string, unknown>, callback?: () => void) {
              sessionSet(items);
              Object.assign(sessionItems, items);
              callback?.();
              return Promise.resolve();
            },
            remove(keys: unknown, callback?: () => void) {
              for (const key of Array.isArray(keys) ? keys : [keys]) {
                if (typeof key === "string") {
                  delete sessionItems[key];
                }
              }
              callback?.();
              return Promise.resolve();
            }
          },
          local: {
            get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
              callback?.({});
              return Promise.resolve({});
            },
            set(items: Record<string, unknown>, callback?: () => void) {
              localSet(items);
              callback?.();
              return Promise.resolve();
            },
            remove(keys: unknown, callback?: () => void) {
              callback?.();
              return Promise.resolve();
            }
          }
        }
      };
    }

    const firstListeners: RuntimeMessageListener[] = [];
    installChrome(firstListeners);
    await import("../background");

    await expect(
      sendRuntimeMessage(firstListeners, {
        type: "vaultkern_autofill_submission",
        url: "https://example.com/login",
        username: "alice",
        password: "secret",
        submittedAt: 1710000000000
      }).response()
    ).resolves.toEqual({ ok: true });
    expect(sessionItems.vaultkernPendingAutofillSubmission).toBeUndefined();
    expect(sessionSet).not.toHaveBeenCalled();
    expect(localSet).not.toHaveBeenCalled();

    vi.resetModules();
    const secondListeners: RuntimeMessageListener[] = [];
    installChrome(secondListeners);
    await import("../background");

    await expect(
      sendRuntimeMessage(secondListeners, {
        type: "vaultkern_autofill_pending_request"
      }).response()
    ).resolves.toEqual({ pending: null });
  });

  it("ignores stale pending autofill submissions from session storage", async () => {
    const sessionItems: Record<string, unknown> = {
      vaultkernPendingAutofillSubmission: {
        url: "https://old.example/login",
        username: "old",
        password: "old-secret",
        submittedAt: 1710000000000
      }
    };
    const listeners: RuntimeMessageListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: {
          addListener: vi.fn((listener: RuntimeMessageListener) => {
            listeners.push(listener);
          })
        }
      },
      storage: {
        session: {
          get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
            callback?.({ ...sessionItems });
            return Promise.resolve({ ...sessionItems });
          },
          set(_items: Record<string, unknown>, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          },
          remove(_keys: unknown, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          }
        }
      }
    };

    await import("../background");

    await expect(
      sendRuntimeMessage(listeners, {
        type: "vaultkern_autofill_pending_request"
      }).response()
    ).resolves.toEqual({ pending: null });
  });

  it("keeps the native session alive after an unlocked session response", async () => {
    vi.useFakeTimers();
    const port = createPort();
    const connectNative = vi.fn(() => port);
    const attach = vi.fn(async () => undefined);
    const listeners: RuntimeMessageListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener(fn: RuntimeMessageListener) {
            listeners.push(fn);
          }
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
                passkeyProviderEnabled: true
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
    await flushMicrotasks();
    expect(attach).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
    port.emitMessage({
      type: "passkey_ceremony_reconciliation",
      reconciled: []
    });
    await flushMicrotasks();

    if (listeners.length === 0) {
      throw new Error("background listener was not registered");
    }

    const response = sendRuntimeMessage(listeners, {
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    await expect(response.response()).resolves.toEqual({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });

    await vi.advanceTimersByTimeAsync(20_000);

    expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
      version: 1,
      command: { type: "get_session_state" }
    }));
    expect(port.postMessage).toHaveBeenCalledTimes(3);

    vi.useRealTimers();
  });

  it("stops native keep-alive and clears attach state when disabling fails to detach the proxy", async () => {
    vi.useFakeTimers();
    const port = createPort();
    const connectNative = vi.fn(() => port);
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => "detach failed");
    const listeners: RuntimeMessageListener[] = [];
    let passkeyProviderEnabled = true;
    const storageListeners: StorageChangeListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener(fn: RuntimeMessageListener) {
            listeners.push(fn);
          }
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
          addListener(listener: StorageChangeListener) {
            storageListeners.push(listener);
          }
        }
      },
      webAuthenticationProxy: {
        attach,
        detach
      }
    };

    await import("../background");
    await flushMicrotasks();
    expect(attach).toHaveBeenCalledTimes(1);
    await completePasskeyLedgerReconciliation(port);

    const response = sendRuntimeMessage(listeners, {
      version: 1,
      command: { type: "get_session_state" }
    });
    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    await expect(response.response()).resolves.toMatchObject({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    passkeyProviderEnabled = false;
    for (const listener of storageListeners) {
      listener({ vaultkernExtensionSettings: {} }, "local");
    }
    await vi.waitFor(() => {
      expect(detach).toHaveBeenCalledTimes(1);
    });
    const postedAfterDisable = port.postMessage.mock.calls.length;

    await vi.advanceTimersByTimeAsync(20_000);

    expect(port.postMessage).toHaveBeenCalledTimes(postedAfterDisable);

    passkeyProviderEnabled = true;
    for (const listener of storageListeners) {
      listener({ vaultkernExtensionSettings: {} }, "local");
    }
    await vi.waitFor(() => {
      expect(attach).toHaveBeenCalledTimes(2);
    });

    vi.useRealTimers();
  });

  it("does not keep the native session alive when passkeys are disabled", async () => {
    vi.useFakeTimers();
    const port = createPort();
    const connectNative = vi.fn(() => port);
    const listeners: RuntimeMessageListener[] = [];

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener(fn: RuntimeMessageListener) {
            listeners.push(fn);
          }
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
        attach: vi.fn(async () => undefined),
        detach: vi.fn(async () => undefined)
      }
    };

    await import("../background");
    await flushMicrotasks();

    if (listeners.length === 0) {
      throw new Error("background listener was not registered");
    }

    const response = sendRuntimeMessage(listeners, {
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });
    await expect(response.response()).resolves.toEqual({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1",
      supportsBiometricUnlock: false
    });

    await vi.advanceTimersByTimeAsync(20_000);

    expect(port.postMessage).toHaveBeenCalledTimes(1);

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
    expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
      version: 1,
      command: { type: "get_session_state" }
    }));

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
              vaultkernWebAuthnDebugEnabled: true,
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
    await completePasskeyLedgerReconciliation(port);
    await vi.waitFor(() => {
      expect(registerContentScripts).toHaveBeenCalledWith([
        {
          id: "vaultkern-webauthn-page-hook",
          matches: ["<all_urls>"],
          js: ["webauthnPageHook.js"],
          runAt: "document_start",
          world: "MAIN",
          allFrames: true,
          matchOriginAsFallback: true,
          persistAcrossSessions: false
        }
      ]);
    });
    expect(query).toHaveBeenCalledWith({
      url: ["http://*/*", "https://*/*"]
    });
    await vi.waitFor(() => {
      expect(executeScript).toHaveBeenCalledTimes(4);
    });
    const callsByTab = new Map<number, unknown[]>();
    for (const [details] of executeScript.mock.calls) {
      const tabId = (details as { target?: { tabId?: unknown } }).target?.tabId;
      if (typeof tabId !== "number") {
        continue;
      }
      callsByTab.set(tabId, [...(callsByTab.get(tabId) ?? []), details]);
    }
    for (const tabId of [7, 8]) {
      expect(callsByTab.get(tabId)).toEqual([
        {
          target: { tabId, allFrames: true },
          files: ["webauthnContentScript.js"],
          world: "ISOLATED"
        },
        {
          target: { tabId, allFrames: true },
          files: ["webauthnPageHook.js"],
          world: "MAIN"
        }
      ]);
    }
    await vi.waitFor(() => {
      expect(storedItems.vaultkernWebAuthnDebug).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ event: "page_hook_registered" })
        ])
      );
    });
  });

  it("still injects the isolated WebAuthn bridge when page hook reinjection is already installed", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const registerContentScripts = vi.fn(async () => undefined);
    const executeScript = vi.fn(async (details: { files?: string[] }) => {
      if (details.files?.includes("webauthnPageHook.js")) {
        throw new Error("page hook was already installed");
      }
    });
    const query = vi.fn(async () => [{ id: 7 }]);

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
          set(_items: Record<string, unknown>, callback?: () => void) {
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
    await completePasskeyLedgerReconciliation(port);

    await vi.waitFor(() => {
      expect(executeScript).toHaveBeenCalledWith({
        target: { tabId: 7, allFrames: true },
        files: ["webauthnContentScript.js"],
        world: "ISOLATED"
      });
    });
  });

  it("injects each open tab bridge before its MAIN-world hook without blocking other tabs", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const registerContentScripts = vi.fn(async () => undefined);
    const pageHookCalls: number[] = [];
    let resolveSlowBridge: (() => void) | undefined;
    const executeScript = vi.fn(
      async (details: { target?: { tabId?: number }; files?: string[] }) => {
        const tabId = details.target?.tabId;
        if (details.files?.includes("webauthnContentScript.js") && tabId === 7) {
          await new Promise<void>((resolve) => {
            resolveSlowBridge = resolve;
          });
          return;
        }
        if (details.files?.includes("webauthnPageHook.js") && typeof tabId === "number") {
          pageHookCalls.push(tabId);
        }
      }
    );
    const query = vi.fn(async () => [{ id: 7 }, { id: 8 }]);

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
          set(_items: Record<string, unknown>, callback?: () => void) {
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
    await completePasskeyLedgerReconciliation(port);
    await vi.waitFor(() => {
      expect(resolveSlowBridge).toBeTypeOf("function");
    });
    await vi.waitFor(() => {
      expect(pageHookCalls).toEqual([8]);
    });

    resolveSlowBridge?.();
    await vi.waitFor(() => {
      expect(pageHookCalls.sort()).toEqual([7, 8]);
    });
  });

  it("reattaches the WebAuthn proxy when Chrome wakes the worker for remote session changes", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const registerContentScripts = vi.fn(async () => undefined);
    const executeScript = vi.fn(async () => undefined);
    const query = vi.fn(async () => []);
    let remoteSessionListener: (() => void) | undefined;
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
        attach,
        onRemoteSessionStateChange: {
          addListener(listener: () => void) {
            remoteSessionListener = listener;
          }
        }
      }
    };

    await import("../background");
    await vi.waitFor(() => {
      expect(attach).toHaveBeenCalledTimes(1);
    });
    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
    port.emitMessage({
      type: "passkey_ceremony_reconciliation",
      reconciled: []
    });

    remoteSessionListener?.();

    await vi.waitFor(() => {
      expect(attach).toHaveBeenCalledTimes(2);
    });
  });

  it("rotates the passkey ledger connection id after native port reconnect", async () => {
    const firstPort = createPort();
    const secondPort = createPort();
    const connectNative = vi.fn(() =>
      connectNative.mock.calls.length === 1 ? firstPort : secondPort
    );
    const attach = vi.fn(async () => undefined);
    let remoteSessionListener: (() => void) | undefined;

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        onMessage: {
          addListener() {}
        }
      },
      storage: {
        local: {
          get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
            const items = {
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
          set(_items: Record<string, unknown>, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          }
        },
        onChanged: {
          addListener() {}
        }
      },
      scripting: {
        executeScript: vi.fn(async () => undefined),
        registerContentScripts: vi.fn(async () => undefined)
      },
      tabs: {
        query: vi.fn(async () => [])
      },
      webAuthenticationProxy: {
        attach,
        onRemoteSessionStateChange: {
          addListener(listener: () => void) {
            remoteSessionListener = listener;
          }
        }
      }
    };

    await import("../background");
    await vi.waitFor(() => {
      expect(firstPort.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
    const firstConnectionId = (
      firstPort.postMessage.mock.calls[0][0] as {
        command: { active_connection_id: string };
      }
    ).command.active_connection_id;
    firstPort.emitMessage({
      type: "passkey_ceremony_reconciliation",
      reconciled: []
    });
    await flushMicrotasks();

    firstPort.emitDisconnect();
    remoteSessionListener?.();

    await vi.waitFor(() => {
      expect(secondPort.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
    const secondConnectionId = (
      secondPort.postMessage.mock.calls[0][0] as {
        command: { active_connection_id: string };
      }
    ).command.active_connection_id;

    expect(secondConnectionId).not.toBe(firstConnectionId);
  });

  it("asks the native ledger to reconcile passkey ceremonies when attaching the proxy", async () => {
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
          get(_key: unknown, callback?: (items: Record<string, unknown>) => void) {
            const items = {
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
          set(_items: Record<string, unknown>, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          }
        },
        onChanged: {
          addListener() {}
        }
      },
      scripting: {
        executeScript: vi.fn(async () => undefined),
        registerContentScripts: vi.fn(async () => undefined)
      },
      tabs: {
        query: vi.fn(async () => [])
      },
      webAuthenticationProxy: {
        attach
      }
    };

    await import("../background");

    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
  });

  it("reconciles the native ledger before rehydrating persisted passkey ceremonies", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    let sessionItems: Record<string, unknown> = {
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-pre-s4": {
          version: 1,
          ceremonyToken: "token-pre-s4",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 107,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    };

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
          set(_items: Record<string, unknown>, callback?: () => void) {
            callback?.();
            return Promise.resolve();
          }
        },
        session: {
          setAccessLevel: vi.fn(async () => undefined),
          get(_keys?: unknown) {
            return Promise.resolve({ ...sessionItems });
          },
          set(items: Record<string, unknown>) {
            sessionItems = { ...sessionItems, ...items };
            return Promise.resolve();
          },
          remove(keys: unknown) {
            for (const key of Array.isArray(keys) ? keys : [keys]) {
              delete sessionItems[String(key)];
            }
            return Promise.resolve();
          }
        },
        onChanged: {
          addListener() {}
        }
      },
      scripting: {
        executeScript: vi.fn(async () => undefined),
        registerContentScripts: vi.fn(async () => undefined)
      },
      tabs: {
        query: vi.fn(async () => [])
      },
      webAuthenticationProxy: {
        attach
      }
    };

    await import("../background");

    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "reconcile_passkey_ceremony_ledger",
          active_connection_id: expect.any(String)
        }
      }));
    });
    port.emitMessage({
      type: "passkey_ceremony_reconciliation",
      reconciled: []
    });

    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "query_passkey_ceremony_ledger",
          ceremony_token: "token-pre-s4"
        }
      }));
    });
    port.emitMessage({ type: "passkey_ceremony_ledger", known: false });

    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: expect.objectContaining({
          type: "register_passkey_ceremony",
          ceremony_token: "token-pre-s4",
          connection_id: expect.any(String)
        })
      }));
    });
    port.emitMessage({ type: "passkey_ceremony_registered", registered: true });

    await vi.waitFor(() => {
      expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({
        version: 1,
        command: {
          type: "advance_passkey_ceremony_phase",
          ceremony_token: "token-pre-s4",
          expected_phase: "s0_pre_authorization",
          next_phase: "s1_user_authorization"
        }
      }));
    });
    port.emitMessage({ type: "passkey_ceremony_advanced", advanced: true });

    const commandTypes = port.postMessage.mock.calls.map(
      ([message]) =>
        (
          message as {
            command?: { type?: unknown };
          }
        ).command?.type
    );
    expect(commandTypes.indexOf("reconcile_passkey_ceremony_ledger")).toBeLessThan(
      commandTypes.indexOf("query_passkey_ceremony_ledger")
    );
    expect(commandTypes.indexOf("query_passkey_ceremony_ledger")).toBeLessThan(
      commandTypes.indexOf("register_passkey_ceremony")
    );
    expect(commandTypes.indexOf("register_passkey_ceremony")).toBeLessThan(
      commandTypes.indexOf("advance_passkey_ceremony_phase")
    );
  });

  it("unregisters the WebAuthn page hook when the provider is disabled", async () => {
    const port = createPort();
    const detach = vi.fn(async () => undefined);
    const scriptRegistry = createContentScriptRegistry([
      "vaultkern-webauthn-page-hook"
    ]);

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
        unregisterContentScripts: scriptRegistry.unregisterContentScripts
      },
      webAuthenticationProxy: {
        detach
      }
    };

    await import("../background");

    await vi.waitFor(() => {
      expect(scriptRegistry.unregisterContentScripts).toHaveBeenCalledWith({
        ids: ["vaultkern-webauthn-page-hook"]
      });
    });
    expect(
      scriptRegistry.hasRegisteredContentScript("vaultkern-webauthn-page-hook")
    ).toBe(false);
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
    const storageListeners: StorageChangeListener[] = [];

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
          addListener(listener: StorageChangeListener) {
            storageListeners.push(listener);
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
    await completePasskeyLedgerReconciliation(port);

    passkeyProviderEnabled = false;
    for (const listener of storageListeners) {
      listener({ vaultkernExtensionSettings: {} }, "local");
    }
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(detach).toHaveBeenCalledTimes(1);
  });

  it("disables WebAuthn page hooks already injected into open tabs", async () => {
    const port = createPort();
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => undefined);
    const scriptRegistry = createContentScriptRegistry();
    const executeScript = vi.fn(async () => undefined);
    const query = vi.fn(async () => [{ id: 7 }]);
    let passkeyProviderEnabled = true;
    const storageListeners: StorageChangeListener[] = [];

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
          addListener(listener: StorageChangeListener) {
            storageListeners.push(listener);
          }
        }
      },
      scripting: {
        executeScript,
        registerContentScripts: scriptRegistry.registerContentScripts,
        unregisterContentScripts: scriptRegistry.unregisterContentScripts
      },
      tabs: {
        query
      },
      webAuthenticationProxy: {
        attach,
        detach
      }
    };

    await import("../background");
    await completePasskeyLedgerReconciliation(port);
    await vi.waitFor(() => {
      expect(executeScript).toHaveBeenCalledWith({
        target: { tabId: 7, allFrames: true },
        files: ["webauthnPageHook.js"],
        world: "MAIN"
      });
    });
    expect(
      scriptRegistry.hasRegisteredContentScript("vaultkern-webauthn-page-hook")
    ).toBe(true);

    executeScript.mockClear();
    query.mockClear();
    scriptRegistry.unregisterContentScripts.mockClear();

    passkeyProviderEnabled = false;
    for (const listener of storageListeners) {
      listener({ vaultkernExtensionSettings: {} }, "local");
    }

    await vi.waitFor(() => {
      expect(detach).toHaveBeenCalledTimes(1);
    });
    expect(query).toHaveBeenCalledWith({
      url: ["http://*/*", "https://*/*"]
    });
    expect(executeScript).toHaveBeenCalledWith({
      target: { tabId: 7, allFrames: true },
      func: expect.any(Function),
      world: "MAIN"
    });
    const disableCall = executeScript.mock.calls.find(
      ([details]) => typeof details.func === "function"
    );
    disableCall?.[0].func();
    expect(
      (globalThis as Record<string, unknown>).__vaultkernWebAuthnPageHookEnabled
    ).toBe(false);
    delete (globalThis as Record<string, unknown>)
      .__vaultkernWebAuthnPageHookEnabled;
    expect(scriptRegistry.unregisterContentScripts).toHaveBeenCalledWith({
      ids: ["vaultkern-webauthn-page-hook"]
    });
    expect(
      scriptRegistry.hasRegisteredContentScript("vaultkern-webauthn-page-hook")
    ).toBe(false);
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
    const storageListeners: StorageChangeListener[] = [];

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
          addListener(listener: StorageChangeListener) {
            storageListeners.push(listener);
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
    for (const listener of storageListeners) {
      listener({ vaultkernExtensionSettings: {} }, "local");
    }
    resolveAttach();
    await completePasskeyLedgerReconciliation(port);

    await vi.waitFor(() => {
      expect(detach).toHaveBeenCalledTimes(1);
    });
  });
});
