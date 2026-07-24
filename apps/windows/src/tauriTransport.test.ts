import { expect, it, vi } from "vitest";

import { createTauriTransport } from "./tauriTransport";

it("forwards runtime envelopes through the in-process Tauri command", async () => {
  const invoke = vi.fn(async (_command: string, args?: Record<string, unknown>) => {
    const envelope = args?.message as
      | { command?: { type?: unknown; capabilities?: string[] } }
      | undefined;
    if (envelope?.command?.type === "handshake") {
      return {
        type: "handshake",
        protocolVersion: 3,
        capabilities: envelope.command.capabilities ?? []
      };
    }
    return {
      type: "session_state",
      unlocked: false,
      activeVaultId: null,
      currentVaultRefId: null,
      supportsBiometricUnlock: true
    };
  });
  const transport = createTauriTransport(invoke);
  const message = {
    version: 3,
    command: { type: "get_session_state" }
  };

  await expect(transport.send(message)).resolves.toMatchObject({
    type: "session_state",
    unlocked: false
  });
  expect(invoke).toHaveBeenNthCalledWith(1, "runtime_send", {
    message: expect.objectContaining({
      command: expect.objectContaining({ type: "handshake" })
    })
  });
  expect(invoke).toHaveBeenNthCalledWith(2, "runtime_send", { message });
});
