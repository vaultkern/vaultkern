import { expect, it, vi } from "vitest";

import { createTauriTransport } from "./tauriTransport";

it("forwards runtime envelopes through the in-process Tauri command", async () => {
  const invoke = vi.fn(async () => ({
    type: "session_state",
    unlocked: false,
    activeVaultId: null,
    currentVaultRefId: null,
    supportsBiometricUnlock: true
  }));
  const transport = createTauriTransport(invoke);
  const message = {
    version: 1,
    command: { type: "get_session_state" }
  };

  await expect(transport.send(message)).resolves.toMatchObject({
    type: "session_state",
    unlocked: false
  });
  expect(invoke).toHaveBeenCalledWith("runtime_send", { message });
});
