import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createNativeMessagingBridge } from "../nativeBridge";

type Listener<T> = (value: T) => void;

function createPort() {
  const messageListeners: Listener<unknown>[] = [];
  const disconnectListeners: Listener<void>[] = [];

  return {
    postMessage: vi.fn((message: unknown) => {
      void message;
    }),
    onMessage: {
      addListener(listener: Listener<unknown>) {
        messageListeners.push(listener);
      }
    },
    onDisconnect: {
      addListener(listener: Listener<void>) {
        disconnectListeners.push(listener);
      }
    },
    disconnect: vi.fn(),
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

afterEach(() => {
  vi.useRealTimers();
  vi.resetAllMocks();
});

beforeEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

describe("createNativeMessagingBridge", () => {
  it("classifies missing native host errors from connectNative", async () => {
    const connectNative = vi.fn(() => {
      throw new Error("Specified native messaging host not found.");
    });

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    await expect(
      bridge.send({ version: 1, command: { type: "get_session_state" } })
    ).rejects.toMatchObject({
      code: "native_host_missing",
      message: "Specified native messaging host not found."
    });
  });

  it("classifies forbidden native host errors from connectNative", async () => {
    const connectNative = vi.fn(() => {
      throw new Error("Access to the specified native messaging host is forbidden.");
    });

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    await expect(
      bridge.send({ version: 1, command: { type: "get_session_state" } })
    ).rejects.toMatchObject({
      code: "native_permission_denied",
      message: "Access to the specified native messaging host is forbidden."
    });
  });

  it("reuses one native port and serializes requests", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const first = bridge.send({ version: 1, command: { type: "first" } });
    const second = bridge.send({ version: 1, command: { type: "second" } });

    expect(connectNative).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "first" }
    });

    port.emitMessage({ type: "first_response" });

    await expect(first).resolves.toEqual({ type: "first_response" });
    expect(port.postMessage).toHaveBeenCalledTimes(2);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "second" }
    });

    port.emitMessage({ type: "second_response" });

    await expect(second).resolves.toEqual({ type: "second_response" });
  });

  it("rejects a silent request after a timeout and continues with queued requests", async () => {
    vi.useFakeTimers();

    const firstPort = createPort();
    const secondPort = createPort();
    const connectNative = vi.fn(() =>
      connectNative.mock.calls.length === 1 ? firstPort : secondPort
    );
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25
    });

    const first = bridge.send({ version: 1, command: { type: "first" } });
    const second = bridge.send({ version: 1, command: { type: "second" } });
    const firstFailure = first.catch((error: unknown) => error);

    expect(connectNative).toHaveBeenCalledTimes(1);
    expect(firstPort.postMessage).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(25);

    await expect(firstFailure).resolves.toMatchObject({
      code: "native_timeout",
      message: "native messaging timed out"
    });
    expect(connectNative).toHaveBeenCalledTimes(2);
    expect(secondPort.postMessage).toHaveBeenCalledTimes(1);
    expect(secondPort.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "second" }
    });

    secondPort.emitMessage({ type: "second_response" });

    await expect(second).resolves.toEqual({ type: "second_response" });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while waiting for local vault file selection", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: { type: "add_local_vault_reference", path: undefined }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "vault_reference",
      vaultRefId: "vault-ref-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "vault_reference",
      vaultRefId: "vault-ref-1"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while unlocking a vault", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: { type: "unlock_current_vault_with_password", password: "demo-password" }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while unlocking the selected current vault", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: {
        type: "unlock_current_vault",
        password: "demo-password",
        key_file_path: null
      }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while creating a passkey assertion", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: {
        type: "create_passkey_assertion",
        vault_id: "vault-1",
        relying_party: "google.com",
        origin: "https://accounts.google.com",
        credential_id: "credential-1",
        client_data_json_base64url: "client-data"
      }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "error",
      code: "invalid_request",
      message: "passkey credential not found: credential-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "error",
      message: "passkey credential not found: credential-1"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while saving a vault after passkey registration", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: { type: "save_vault", vault_id: "vault-1" }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "save_vault_result",
      status: "saved"
    });

    await expect(request).resolves.toMatchObject({
      type: "save_vault_result",
      status: "saved"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while rolling back a passkey registration", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: {
        type: "rollback_passkey_registration",
        vault_id: "vault-1",
        entry_id: "entry-1",
        credential_id: "credential-1",
        created: true
      }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({ type: "saved" });

    await expect(request).resolves.toEqual({ type: "saved" });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while enabling quick unlock", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: { type: "enable_quick_unlock_for_current_vault" }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    vi.useRealTimers();
  });

  it("uses the interactive timeout while unlocking with quick unlock", async () => {
    vi.useFakeTimers();

    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime", {
      timeoutMs: 25,
      interactiveTimeoutMs: 1_000
    });

    const request = bridge.send({
      version: 1,
      command: { type: "unlock_current_vault_with_quick_unlock" }
    });

    await vi.advanceTimersByTimeAsync(25);

    expect(port.disconnect).not.toHaveBeenCalled();

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await expect(request).resolves.toMatchObject({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    vi.useRealTimers();
  });

  it("cancels stale preload before serving a new startup session request", async () => {
    const firstPort = createPort();
    const secondPort = createPort();
    const connectNative = vi.fn(() =>
      connectNative.mock.calls.length === 1 ? firstPort : secondPort
    );
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const preload = bridge.send({
      version: 1,
      command: { type: "preload_current_vault" }
    });
    const preloadFailure = preload.catch((error: unknown) => error);

    expect(firstPort.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "preload_current_vault" }
    });

    const session = bridge.send({
      version: 1,
      command: { type: "get_session_state" }
    });

    await expect(preloadFailure).resolves.toMatchObject({
      code: "native_port_disconnected",
      message: "preload canceled by startup request"
    });
    expect(firstPort.disconnect).toHaveBeenCalledTimes(1);
    expect(connectNative).toHaveBeenCalledTimes(2);
    expect(secondPort.postMessage).toHaveBeenCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });

    secondPort.emitMessage({
      type: "session_state",
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });

    await expect(session).resolves.toMatchObject({
      type: "session_state",
      currentVaultRefId: "vault-ref-1"
    });
  });

  it("drops queued preload before serving a new startup session request", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const first = bridge.send({ version: 1, command: { type: "first" } });
    const preload = bridge.send({
      version: 1,
      command: { type: "preload_current_vault" }
    });
    const preloadFailure = preload.catch((error: unknown) => error);
    const session = bridge.send({
      version: 1,
      command: { type: "get_session_state" }
    });

    expect(port.postMessage).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "first" }
    });
    await expect(preloadFailure).resolves.toMatchObject({
      code: "native_port_disconnected",
      message: "preload canceled by startup request"
    });

    port.emitMessage({ type: "first_response" });

    await expect(first).resolves.toEqual({ type: "first_response" });
    expect(port.postMessage).toHaveBeenCalledTimes(2);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: "vault-ref-1"
    });

    await expect(session).resolves.toMatchObject({
      type: "session_state",
      currentVaultRefId: "vault-ref-1"
    });
  });

  it("serves startup requests before queued popup read requests without disconnecting the active port", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const staleEntries = bridge.send({
      version: 1,
      command: { type: "list_entries", vault_id: "vault-1" }
    });
    const staleCandidates = bridge.send({
      version: 1,
      command: { type: "find_fill_candidates", vault_id: "vault-1", url: "https://example.com" }
    });
    const session = bridge.send({
      version: 1,
      command: { type: "get_session_state" }
    });

    expect(port.postMessage).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "list_entries", vault_id: "vault-1" }
    });
    expect(port.disconnect).not.toHaveBeenCalled();
    expect(connectNative).toHaveBeenCalledTimes(1);

    port.emitMessage({ type: "entry_list", entries: [] });

    await expect(staleEntries).resolves.toEqual({
      type: "entry_list",
      entries: []
    });
    expect(port.postMessage).toHaveBeenCalledTimes(2);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    await expect(session).resolves.toMatchObject({
      type: "session_state",
      activeVaultId: "vault-1"
    });
    expect(port.postMessage).toHaveBeenCalledTimes(3);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "find_fill_candidates", vault_id: "vault-1", url: "https://example.com" }
    });

    port.emitMessage({ type: "entry_list", entries: [] });

    await expect(staleCandidates).resolves.toEqual({
      type: "entry_list",
      entries: []
    });
  });

  it("keeps an active native port alive when a startup session request arrives during a read", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const candidates = bridge.send({
      version: 1,
      command: {
        type: "find_fill_candidates",
        vault_id: "vault-1",
        url: "https://accounts.google.com"
      }
    });
    const session = bridge.send({
      version: 1,
      command: { type: "get_session_state" }
    });

    expect(port.postMessage).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: {
        type: "find_fill_candidates",
        vault_id: "vault-1",
        url: "https://accounts.google.com"
      }
    });

    port.emitMessage({ type: "entry_list", entries: [] });

    await expect(candidates).resolves.toEqual({
      type: "entry_list",
      entries: []
    });
    expect(port.disconnect).not.toHaveBeenCalled();
    expect(connectNative).toHaveBeenCalledTimes(1);
    expect(port.postMessage).toHaveBeenCalledTimes(2);
    expect(port.postMessage).toHaveBeenLastCalledWith({
      version: 1,
      command: { type: "get_session_state" }
    });

    port.emitMessage({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1",
      currentVaultRefId: "vault-ref-1"
    });

    await expect(session).resolves.toMatchObject({
      type: "session_state",
      activeVaultId: "vault-1"
    });
  });

  it("rejects queued requests when the native port disconnects", async () => {
    const port = createPort();
    const connectNative = vi.fn(() => port);
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        connectNative,
        lastError: { message: "native port disconnected" }
      }
    };

    const bridge = createNativeMessagingBridge(connectNative, "com.vaultkern.runtime");

    const first = bridge.send({ version: 1, command: { type: "first" } });
    const second = bridge.send({ version: 1, command: { type: "second" } });
    const firstFailure = first.catch((error: unknown) => error);
    const secondFailure = second.catch((error: unknown) => error);

    port.emitDisconnect();

    await expect(firstFailure).resolves.toMatchObject({
      code: "native_port_disconnected",
      message: "native port disconnected"
    });
    await expect(secondFailure).resolves.toMatchObject({
      code: "native_port_disconnected",
      message: "native port disconnected"
    });
  });
});
