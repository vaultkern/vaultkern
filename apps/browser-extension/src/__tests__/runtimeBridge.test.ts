import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.resetModules();
});

beforeEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

describe("extensionTransport", () => {
  it("sends runtime commands through chrome.runtime.sendMessage", async () => {
    const sendMessage = vi
      .fn()
      .mockResolvedValueOnce({
        type: "handshake",
        protocolVersion: 1,
        capabilities: ["runtime-core", "browser-extension"]
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1",
        supportsBiometricUnlock: false
      });
    const sendNativeMessage = vi.fn();

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage,
        sendNativeMessage
      }
    };

    const { extensionTransport } = await import("../runtimeBridge");

    await extensionTransport.send({
      version: 1,
      command: { type: "get_session_state" }
    });

    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenNthCalledWith(1, {
      version: 1,
      command: { type: "get_session_state" }
    });
    expect(sendNativeMessage).not.toHaveBeenCalled();
  });

  it("rejects a runtime command when the background returns an error", async () => {
    const sendMessage = vi.fn(async () => ({
      error: {
        code: "native_host_missing",
        message: "native host unavailable"
      }
    }));

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    const { sendRuntimeCommand } = await import("../runtimeBridge");

    await expect(
      sendRuntimeCommand({ type: "get_session_state" })
    ).rejects.toMatchObject({
      code: "native_host_missing",
      message: "native host unavailable"
    });
  });

  it("rejects transport messages when the background returns an error", async () => {
    const sendMessage = vi.fn(async () => ({
      error: {
        code: "native_host_missing",
        message: "native host unavailable"
      }
    }));

    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        sendMessage
      }
    };

    const { extensionTransport } = await import("../runtimeBridge");

    await expect(
      extensionTransport.send({
        version: 1,
        command: { type: "get_session_state" }
      })
    ).rejects.toMatchObject({
      code: "native_host_missing",
      message: "native host unavailable"
    });
  });

  it("rejects when extension runtime messaging is unavailable", async () => {
    const { sendRuntimeCommand } = await import("../runtimeBridge");

    await expect(
      sendRuntimeCommand({ type: "get_session_state" })
    ).rejects.toMatchObject({
      code: "runtime_messaging_unavailable",
      message: "runtime messaging is unavailable"
    });
  });
});
