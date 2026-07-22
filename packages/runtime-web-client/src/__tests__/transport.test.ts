import { describe, expect, it, vi } from "vitest";

import { createNegotiatedRuntimeTransport } from "../transport";

describe("createNegotiatedRuntimeTransport", () => {
  it("coalesces concurrent first-use handshakes before forwarding commands", async () => {
    let resolveHandshake!: (value: unknown) => void;
    const handshake = new Promise<unknown>((resolve) => {
      resolveHandshake = resolve;
    });
    const base = {
      send: vi
        .fn()
        .mockReturnValueOnce(handshake)
        .mockResolvedValueOnce({ type: "first" })
        .mockResolvedValueOnce({ type: "second" })
    };
    const transport = createNegotiatedRuntimeTransport(base, [
      "runtime-core",
      "runtime-core"
    ]);

    const first = transport.send({ version: 1, command: { type: "first" } });
    const second = transport.send({ version: 1, command: { type: "second" } });
    expect(base.send).toHaveBeenCalledTimes(1);
    expect(base.send).toHaveBeenCalledWith({
      version: 1,
      command: {
        type: "handshake",
        protocol_version: 1,
        capabilities: ["runtime-core"]
      }
    });

    resolveHandshake({
      type: "handshake",
      protocolVersion: 1,
      capabilities: ["runtime-core"]
    });
    await expect(first).resolves.toEqual({ type: "first" });
    await expect(second).resolves.toEqual({ type: "second" });
    expect(base.send).toHaveBeenCalledTimes(3);
  });

  it("keeps the first negotiation single-flight when attaching changes generation", async () => {
    let generation = 0;
    let resolveHandshake!: (value: unknown) => void;
    const handshake = new Promise<unknown>((resolve) => {
      resolveHandshake = resolve;
    });
    const base = {
      connectionGeneration: vi.fn(() => generation),
      send: vi.fn((message: unknown) => {
        const commandType = (
          message as { command?: { type?: unknown } }
        ).command?.type;
        if (commandType === "handshake") {
          generation = 1;
          return handshake;
        }
        return Promise.resolve({ type: commandType });
      })
    };
    const transport = createNegotiatedRuntimeTransport(base, ["runtime-core"]);

    const first = transport.send({ version: 1, command: { type: "first" } });
    const second = transport.send({ version: 1, command: { type: "second" } });

    expect(
      base.send.mock.calls.filter(
        ([message]) =>
          (message as { command?: { type?: unknown } }).command?.type ===
          "handshake"
      )
    ).toHaveLength(1);

    resolveHandshake({
      type: "handshake",
      protocolVersion: 1,
      capabilities: ["runtime-core"]
    });
    await expect(first).resolves.toEqual({ type: "first" });
    await expect(second).resolves.toEqual({ type: "second" });
  });

  it("renegotiates after a completed connection generation is replaced", async () => {
    let generation = 1;
    const base = {
      connectionGeneration: vi.fn(() => generation),
      send: vi.fn(async (message: unknown) => {
        const commandType = (
          message as { command?: { type?: unknown } }
        ).command?.type;
        return commandType === "handshake"
          ? {
              type: "handshake",
              protocolVersion: 1,
              capabilities: ["runtime-core"]
            }
          : { type: commandType };
      })
    };
    const transport = createNegotiatedRuntimeTransport(base, ["runtime-core"]);

    await expect(
      transport.send({ version: 1, command: { type: "first" } })
    ).resolves.toEqual({ type: "first" });
    generation = 2;
    await expect(
      transport.send({ version: 1, command: { type: "second" } })
    ).resolves.toEqual({ type: "second" });

    expect(
      base.send.mock.calls.filter(
        ([message]) =>
          (message as { command?: { type?: unknown } }).command?.type ===
          "handshake"
      )
    ).toHaveLength(2);
  });

  it("does not cache a failed negotiation", async () => {
    const base = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          type: "error",
          code: "temporary",
          message: "not ready"
        })
        .mockResolvedValueOnce({
          type: "handshake",
          protocolVersion: 1,
          capabilities: ["runtime-core"]
        })
        .mockResolvedValueOnce({ type: "session_state" })
    };
    const transport = createNegotiatedRuntimeTransport(base, ["runtime-core"]);

    await expect(
      transport.send({ version: 1, command: { type: "get_session_state" } })
    ).rejects.toMatchObject({
      code: "temporary",
      message: "not ready"
    });
    await expect(
      transport.send({ version: 1, command: { type: "get_session_state" } })
    ).resolves.toEqual({ type: "session_state" });
    expect(base.send).toHaveBeenCalledTimes(3);
  });
});
