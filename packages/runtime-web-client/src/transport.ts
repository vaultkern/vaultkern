export interface RuntimeTransport {
  send(message: unknown): Promise<unknown>;
  connectionGeneration?(): number;
  prepareForSend?(message: unknown): void;
}

export interface RuntimeHandshake {
  type: "handshake";
  protocolVersion: number;
  capabilities: string[];
}

export const RUNTIME_PROTOCOL_VERSION = 1;

export function createNegotiatedRuntimeTransport(
  transport: RuntimeTransport,
  capabilities: string[]
): RuntimeTransport {
  let negotiation: Promise<void> | null = null;
  let negotiationPending = false;
  let negotiatedGeneration: number | null = null;

  async function ensureNegotiated() {
    const generation = transport.connectionGeneration?.() ?? 0;
    if (
      negotiation &&
      (negotiationPending || negotiatedGeneration === generation)
    ) {
      return negotiation;
    }
    const current = negotiateRuntimeTransport(transport, capabilities);
    negotiation = current;
    negotiationPending = true;
    negotiatedGeneration = generation;
    try {
      await current;
      if (negotiation === current) {
        negotiationPending = false;
        negotiatedGeneration = transport.connectionGeneration?.() ?? generation;
      }
    } catch (error) {
      if (negotiation === current) {
        negotiation = null;
        negotiationPending = false;
        negotiatedGeneration = null;
      }
      throw error;
    }
  }

  return {
    async send(message: unknown) {
      for (;;) {
        transport.prepareForSend?.(message);
        await ensureNegotiated();

        // Another request can become active while this request awaits a shared
        // handshake. Preparing again closes that window; if preparation reset
        // the connection, negotiate the replacement before sending business
        // data to it.
        transport.prepareForSend?.(message);
        const generation = transport.connectionGeneration?.() ?? 0;
        if (negotiatedGeneration !== generation) {
          continue;
        }
        return transport.send(message);
      }
    }
  };
}

async function negotiateRuntimeTransport(
  transport: RuntimeTransport,
  capabilities: string[]
) {
  const response = await transport.send({
    version: RUNTIME_PROTOCOL_VERSION,
    command: {
      type: "handshake",
      protocol_version: RUNTIME_PROTOCOL_VERSION,
      capabilities: [...new Set(capabilities)]
    }
  });
  if (isRuntimeError(response)) {
    throw new Error(`${response.code}: ${response.message}`);
  }
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "handshake" ||
    (response as { protocolVersion?: unknown }).protocolVersion !==
      RUNTIME_PROTOCOL_VERSION ||
    !Array.isArray((response as { capabilities?: unknown }).capabilities) ||
    !(response as { capabilities: unknown[] }).capabilities.every(
      (capability) => typeof capability === "string"
    )
  ) {
    throw new Error("runtime protocol handshake returned an invalid response");
  }
  const granted = new Set(
    (response as { capabilities: string[] }).capabilities
  );
  const missing = [...new Set(capabilities)].filter(
    (capability) => !granted.has(capability)
  );
  if (missing.length > 0) {
    throw new Error(
      `runtime protocol handshake denied required capabilities: ${missing.join(", ")}`
    );
  }
}

function isRuntimeError(
  response: unknown
): response is { type: "error"; code: string; message: string } {
  return (
    typeof response === "object" &&
    response !== null &&
    (response as { type?: unknown }).type === "error" &&
    typeof (response as { code?: unknown }).code === "string" &&
    typeof (response as { message?: unknown }).message === "string"
  );
}
