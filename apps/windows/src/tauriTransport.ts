import type { RuntimeTransport } from "@vaultkern/runtime-web-client";

export type TauriInvoke = (
  command: string,
  args?: Record<string, unknown>
) => Promise<unknown>;

export function createTauriTransport(invoke: TauriInvoke): RuntimeTransport {
  return {
    send(message: unknown) {
      return invoke("runtime_send", { message });
    }
  };
}
