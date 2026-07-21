import {
  createNegotiatedRuntimeTransport,
  type RuntimeTransport
} from "@vaultkern/runtime-web-client";

export type TauriInvoke = (
  command: string,
  args?: Record<string, unknown>
) => Promise<unknown>;

export function createTauriTransport(invoke: TauriInvoke): RuntimeTransport {
  return createNegotiatedRuntimeTransport({
    send(message: unknown) {
      return invoke("runtime_send", { message });
    }
  }, [
    "runtime-core",
    "resident-app",
    "database-settings",
    "one-drive",
    "passkey-ceremonies",
    "quick-unlock"
  ]);
}
