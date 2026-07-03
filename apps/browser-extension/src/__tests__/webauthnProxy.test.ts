import { afterEach, describe, expect, it, vi } from "vitest";
import { Buffer } from "node:buffer";

import {
  attachWebAuthnProxy,
  detachWebAuthnProxy,
  recordWebAuthnDebug,
  recordWebAuthnPageRequest,
  reconcilePersistedPasskeyCeremonies,
  resetObservedWebAuthnPageRequestsForTest,
  resetPasskeyLedgerConnectionId,
  webAuthnProxyAvailable
} from "../webauthnProxy";

afterEach(() => {
  resetObservedWebAuthnPageRequestsForTest();
  resetPasskeyLedgerConnectionId();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function expectResolvesSoon<T>(promise: Promise<T>, expected: T) {
  const timeout = Symbol("timeout");
  const result = await Promise.race([
    promise,
    new Promise<symbol>((resolve) => setTimeout(() => resolve(timeout), 20))
  ]);

  expect(result).not.toBe(timeout);
  expect(result).toEqual(expected);
}

function clientDataJsonFrom(base64url: string) {
  return JSON.parse(Buffer.from(base64url, "base64url").toString("utf8"));
}

function createSessionStorage(initial: Record<string, unknown> = {}) {
  const data = { ...initial };
  return {
    setAccessLevel: vi.fn(async () => undefined),
    get: vi.fn(async (keys?: unknown) => {
      if (Array.isArray(keys)) {
        return Object.fromEntries(keys.map((key) => [key, data[String(key)]]));
      }
      if (typeof keys === "string") {
        return { [keys]: data[keys] };
      }
      return { ...data };
    }),
    set: vi.fn(async (items: Record<string, unknown>) => {
      Object.assign(data, items);
    }),
    remove: vi.fn(async (keys: unknown) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        delete data[String(key)];
      }
    }),
    snapshot() {
      return { ...data };
    }
  };
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

function passkeyCeremoniesFromStorageSnapshot(snapshot: Record<string, unknown>) {
  return (
    snapshot.vaultkernPasskeyCeremonies as
      | { ceremonies?: Record<string, unknown> }
      | undefined
  )?.ceremonies;
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

function isPasskeyCeremonyCommand(command: unknown) {
  const type = (command as { type?: unknown } | null)?.type;
  return (
    type === "register_passkey_ceremony" ||
    type === "advance_passkey_ceremony_phase" ||
    type === "bind_passkey_ceremony_vault" ||
    type === "query_passkey_ceremony_ledger" ||
    type === "reconcile_passkey_ceremony_ledger" ||
    type === "mark_passkey_ceremony_unknown_delivery" ||
    type === "abort_passkey_registration"
  );
}

function passkeyCeremonyResponse(command: unknown) {
  const type = (command as { type?: unknown } | null)?.type;
  if (type === "register_passkey_ceremony") {
    return { type: "passkey_ceremony_registered", registered: true };
  }
  if (type === "advance_passkey_ceremony_phase") {
    return { type: "passkey_ceremony_advanced", advanced: true };
  }
  if (type === "bind_passkey_ceremony_vault") {
    return { type: "passkey_ceremony_vault_bound", bound: true };
  }
  if (type === "query_passkey_ceremony_ledger") {
    return { type: "passkey_ceremony_ledger", known: false };
  }
  if (type === "reconcile_passkey_ceremony_ledger") {
    return { type: "passkey_ceremony_reconciliation", reconciled: [] };
  }
  if (type === "mark_passkey_ceremony_unknown_delivery") {
    return { type: "passkey_ceremony_advanced", advanced: true };
  }
  if (type === "abort_passkey_registration") {
    return { type: "saved" };
  }
  return undefined;
}

function isPasskeyCapabilityCommand(command: unknown) {
  return (
    (command as { type?: unknown } | null)?.type ===
    "get_passkey_user_verification_capability"
  );
}

function passkeyCapabilityResponse(command: unknown) {
  if (isPasskeyCapabilityCommand(command)) {
    return {
      type: "passkey_user_verification_capability",
      available: false,
      methods: []
    };
  }
  return undefined;
}

function runtimeCommandMock(
  implementation?: (command: Record<string, unknown>) => unknown | Promise<unknown>
) {
  const hasCustomImplementation = typeof implementation === "function";
  const business = vi.fn(implementation);
  const mock = vi.fn(async (command: Record<string, unknown>) => {
    if (isPasskeyCeremonyCommand(command)) {
      return passkeyCeremonyResponse(command);
    }
    if (isPasskeyCapabilityCommand(command) && hasCustomImplementation) {
      try {
        return (
          (await business(command)) ?? passkeyCapabilityResponse(command)
        );
      } catch (error) {
        if (
          error instanceof Error &&
          error.message.includes(
            "unexpected command: get_passkey_user_verification_capability"
          )
        ) {
          return passkeyCapabilityResponse(command);
        }
        throw error;
      }
    }
    if (!hasCustomImplementation) {
      const capabilityResponse = passkeyCapabilityResponse(command);
      if (capabilityResponse) {
        return capabilityResponse;
      }
    }
    return business(command);
  });

  const wrapped = mock as typeof mock & { business: typeof business };
  wrapped.business = business;
  (wrapped as any).mockResolvedValueOnce = (value: unknown) => {
    business.mockResolvedValueOnce(value);
    return wrapped;
  };
  (wrapped as any).mockResolvedValue = (value: unknown) => {
    business.mockResolvedValue(value);
    return wrapped;
  };
  (wrapped as any).mockImplementationOnce = (
    nextImplementation: (command: Record<string, unknown>) => unknown | Promise<unknown>
  ) => {
    business.mockImplementationOnce(nextImplementation);
    return wrapped;
  };
  (wrapped as any).mockImplementation = (
    nextImplementation: (command: Record<string, unknown>) => unknown | Promise<unknown>
  ) => {
    business.mockImplementation(nextImplementation);
    return wrapped;
  };
  return wrapped;
}

function businessRuntimeCommandCalls(sendRuntimeCommand: {
  mock: { calls: unknown[][] };
}) {
  return sendRuntimeCommand.mock.calls.filter(
    ([command]) =>
      !isPasskeyCeremonyCommand(command) && !isPasskeyCapabilityCommand(command)
  );
}

function passkeyCeremonyAdvanceCommands(sendRuntimeCommand: {
  mock: { calls: unknown[][] };
}) {
  return sendRuntimeCommand.mock.calls
    .map(([command]) => command)
    .filter(
      (command) =>
        (command as { type?: unknown } | null)?.type ===
        "advance_passkey_ceremony_phase"
    );
}

async function flushMicrotasksUntilRuntimeCommand(
  sendRuntimeCommand: { mock: { calls: unknown[][] } },
  predicate: (command: Record<string, unknown>) => boolean,
  maxMicrotasks = 100
) {
  for (let microtask = 0; microtask < maxMicrotasks; microtask += 1) {
    await Promise.resolve();
    if (
      sendRuntimeCommand.mock.calls.some(([command]) =>
        predicate(command as Record<string, unknown>)
      )
    ) {
      return;
    }
  }
}

function businessRuntimeCommand(
  sendRuntimeCommand: { mock: { calls: unknown[][] } },
  callNumber: number
) {
  return businessRuntimeCommandCalls(sendRuntimeCommand)[callNumber - 1]?.[0];
}

function expectBusinessRuntimeCommandCount(
  sendRuntimeCommand: { mock: { calls: unknown[][] } },
  count: number
) {
  expect(businessRuntimeCommandCalls(sendRuntimeCommand)).toHaveLength(count);
}

function expectBusinessRuntimeCommand(
  sendRuntimeCommand: { mock: { calls: unknown[][] } },
  callNumber: number,
  expected: unknown
) {
  expect(businessRuntimeCommand(sendRuntimeCommand, callNumber)).toMatchObject(
    expected as Record<string, unknown>
  );
}

function installPresencePrompt(chromeApi: any) {
  let messageListener:
    | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
    | undefined;
  const existingRuntime = chromeApi.runtime ?? {};
  const existingOnMessage = existingRuntime.onMessage;
  chromeApi.runtime = {
    ...existingRuntime,
    getURL:
      existingRuntime.getURL ??
      vi.fn((path: string) => `chrome-extension://id/${path}`),
    onMessage: {
      ...existingOnMessage,
      addListener(
        listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
      ) {
        messageListener = listener;
        existingOnMessage?.addListener?.(listener);
      }
    }
  };

  const create = vi.fn(async () => ({ id: 77 }));
  chromeApi.windows = {
    ...(chromeApi.windows ?? {}),
    create
  };

  return {
    create,
    latestPromptUrl() {
      return (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)?.url;
    },
    sendRaw(message: unknown, sender: unknown = {}) {
      messageListener?.(message, sender, vi.fn());
    },
    requestOptions(
      options: Partial<{
        origin: string;
        relyingParty: string;
        topOrigin: string;
        senderUrl: string | null;
      }> = {}
    ) {
      const promptUrl = (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)
        ?.url;
      const promptParams = new URL(
        promptUrl ?? "",
        "chrome-extension://id/"
      ).searchParams;
      let response: unknown;
      messageListener?.(
        {
          type: "vaultkern_presence_options_request",
          requestId: Number(promptParams.get("requestId")),
          origin: options.origin ?? promptParams.get("origin"),
          relyingParty: options.relyingParty ?? promptParams.get("relyingParty"),
          ...(options.topOrigin ?? promptParams.get("topOrigin")
            ? { topOrigin: options.topOrigin ?? promptParams.get("topOrigin") }
            : {}),
          nonce: promptParams.get("nonce")
        },
        options.senderUrl === null
          ? {}
          : { url: options.senderUrl ?? promptUrl },
        (value: unknown) => {
          response = value;
        }
      );
      return response;
    },
    async approve(
      requestId?: number,
      overrides: Partial<{
        origin: string;
        relyingParty: string;
        topOrigin: string;
        credentialId: string;
      }> = {},
      options: Partial<{
        nonce: string | null;
        senderUrl: string | null;
      }> = {}
    ) {
      await vi.waitFor(() => {
        expect(create).toHaveBeenCalled();
      });
      await Promise.resolve();
      const promptUrl = (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)
        ?.url;
      const promptParams = new URL(
        promptUrl ?? "",
        "chrome-extension://id/"
      ).searchParams;
      const approvedRequestId =
        requestId ?? Number(promptParams.get("requestId"));
      const nonce =
        options.nonce === undefined ? promptParams.get("nonce") : options.nonce;
      const message: Record<string, unknown> = {
        type: "vaultkern_presence_complete",
        requestId: approvedRequestId
      };
      for (const key of ["origin", "relyingParty", "topOrigin", "credentialId"] as const) {
        const value = overrides[key] ?? promptParams.get(key);
        if (value) {
          message[key] = value;
        }
      }
      if (nonce) {
        message.nonce = nonce;
      }
      messageListener?.(
        message,
        options.senderUrl === null
          ? {}
          : { url: options.senderUrl ?? promptUrl },
        vi.fn()
      );
    }
  };
}

function installUserVerificationPrompt(chromeApi: any) {
  let messageListener:
    | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
    | undefined;
  const existingRuntime = chromeApi.runtime ?? {};
  const existingOnMessage = existingRuntime.onMessage;
  chromeApi.runtime = {
    ...existingRuntime,
    getURL:
      existingRuntime.getURL ??
      vi.fn((path: string) => `chrome-extension://id/${path}`),
    onMessage: {
      ...existingOnMessage,
      addListener(
        listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
      ) {
        messageListener = listener;
        existingOnMessage?.addListener?.(listener);
      }
    }
  };

  const create = vi.fn(async () => ({ id: 88 }));
  chromeApi.windows = {
    ...(chromeApi.windows ?? {}),
    create
  };

  return {
    create,
    latestPromptUrl() {
      return (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)?.url;
    },
    async verify(
      options: Partial<{
        method: "master_password" | "quick_unlock";
        password: string;
        requestId: number;
        origin: string;
        relyingParty: string;
        topOrigin: string;
        nonce: string | null;
        senderUrl: string | null;
      }> = {}
    ) {
      await vi.waitFor(() => {
        expect(create).toHaveBeenCalled();
      });
      const promptUrl = (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)
        ?.url;
      const promptParams = new URL(
        promptUrl ?? "",
        "chrome-extension://id/"
      ).searchParams;
      const response = vi.fn();
      const method = options.method ?? "master_password";
      const nonce =
        options.nonce === undefined ? promptParams.get("nonce") : options.nonce;
      const message: Record<string, unknown> = {
        type: "vaultkern_user_verification_complete",
        requestId: options.requestId ?? Number(promptParams.get("requestId")),
        origin: options.origin ?? promptParams.get("origin"),
        relyingParty: options.relyingParty ?? promptParams.get("relyingParty"),
        method
      };
      if (options.topOrigin ?? promptParams.get("topOrigin")) {
        message.topOrigin = options.topOrigin ?? promptParams.get("topOrigin");
      }
      if (method === "master_password") {
        message.password = options.password ?? "database-password";
      }
      if (nonce) {
        message.nonce = nonce;
      }
      messageListener?.(
        message,
        options.senderUrl === null
          ? {}
          : { url: options.senderUrl ?? promptUrl },
        response
      );
      await vi.waitFor(() => {
        expect(response).toHaveBeenCalled();
      });
      return response.mock.calls.at(-1)?.[0];
    }
  };
}

describe("webAuthenticationProxy wrapper", () => {
  it("reports unsupported when the Chrome API is unavailable", async () => {
    const chromeApi = { runtime: {} };

    expect(webAuthnProxyAvailable(chromeApi)).toBe(false);
    await expect(attachWebAuthnProxy(chromeApi)).resolves.toEqual({
      status: "unsupported"
    });
  });

  it("attaches and detaches the Chrome WebAuthn proxy when available", async () => {
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: { attach, detach }
    };

    await expectResolvesSoon(attachWebAuthnProxy(chromeApi), {
      status: "attached"
    });
    await expectResolvesSoon(detachWebAuthnProxy(chromeApi), {
      status: "detached"
    });
    expect(attach).toHaveBeenCalledWith();
    expect(detach).toHaveBeenCalledWith();
  });

  it("reports Chrome proxy attach errors with readable messages", async () => {
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => {
          throw new Error("another extension is already attached");
        })
      }
    };

    await expectResolvesSoon(attachWebAuthnProxy(chromeApi), {
      status: "error",
      message: "another extension is already attached"
    });
  });

  it("completes WebAuthn get requests with a runtime assertion", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_reconciliation",
          reconciled: []
        };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      const capabilityResponse = passkeyCapabilityResponse(command);
      if (capabilityResponse) {
        return capabilityResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x",
        backupEligible: true,
        backupState: false
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    getListener?.({
      requestId: 7,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(1, {
      type: "reconcile_passkey_ceremony_ledger",
      active_connection_id: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "register_passkey_ceremony",
      ceremony_token: expect.any(String),
      connection_id: expect.any(String),
      origin: "https://example.com",
      top_origin: undefined,
      ancestor_origins: [],
      relying_party: "example.com",
      ceremony: "get",
      discoverable: false,
      user_verification: "preferred",
      challenge_base64url: "Y2hhbGxlbmdlLTE",
      request_id: 7,
      tab_id: 101,
      frame_id: 0,
      frame_kind: "top",
      registered_at_epoch_ms: expect.any(Number),
      expires_at_epoch_ms: expect.any(Number)
    });
    const ceremonyToken = (sendRuntimeCommand.mock.calls[1][0] as {
      ceremony_token: string;
    }).ceremony_token;
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(4, {
      type: "advance_passkey_ceremony_phase",
      ceremony_token: ceremonyToken,
      expected_phase: "s0_pre_authorization",
      next_phase: "s1_user_authorization"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(5, {
      type: "bind_passkey_ceremony_vault",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(6, {
      type: "get_passkey_user_verification_capability"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(7, {
      type: "advance_passkey_ceremony_phase",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(8, {
      type: "advance_passkey_ceremony_phase",
      ceremony_token: ceremonyToken,
      expected_phase: "s3_credential_resolution",
      next_phase: "s4_completion_and_mutation"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(9, {
      type: "create_passkey_assertion",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      discoverable: false,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(10, {
      type: "advance_passkey_ceremony_phase",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      next_phase: "closed_delivered"
    });

    const details = completeGetRequest.mock.calls[0][0];
    expect(details.requestId).toBe(7);
    const response = JSON.parse(details.responseJson);
    expect(response).toEqual({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: "auth-data",
        clientDataJSON: "client-data",
        signature: "signature",
        userHandle: "dXNlci0x"
      }
    });
  });

  it("fails closed when native rejects passkey ceremony vault binding", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "bind_passkey_ceremony_vault") {
        return { type: "passkey_ceremony_vault_bound", bound: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        throw new Error("assertion creation must not run after vault binding fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7010,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) => command.type === "bind_passkey_ceremony_vault"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "bind_passkey_ceremony_vault",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1"
    });
    expect(presencePrompt.create).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 7010,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays create errors when native rejects passkey ceremony vault binding", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "bind_passkey_ceremony_vault") {
        return { type: "passkey_ceremony_vault_bound", bound: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        throw new Error("registration creation must not run after vault binding fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 7011,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) => command.type === "bind_passkey_ceremony_vault"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "bind_passkey_ceremony_vault",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1"
    });
    expect(presencePrompt.create).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 7011,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays get errors when native rejects the S0 to S1 phase advance", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s0_pre_authorization" &&
        command.next_phase === "s1_user_authorization"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {
        throw new Error("vault binding must not run after S0 to S1 advance fails");
      }
      if (command.type === "create_passkey_assertion") {
        throw new Error("assertion creation must not run after S0 to S1 advance fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7012,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s0_pre_authorization",
      next_phase: "s1_user_authorization"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s0_pre_authorization",
      next_phase: "closed_failed"
    });
    expect(presencePrompt.create).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "bind_passkey_ceremony_vault" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 7012,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays create errors when native rejects the S0 to S1 phase advance", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s0_pre_authorization" &&
        command.next_phase === "s1_user_authorization"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {
        throw new Error("vault binding must not run after S0 to S1 advance fails");
      }
      if (command.type === "create_passkey_registration") {
        throw new Error("registration creation must not run after S0 to S1 advance fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 7013,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s0_pre_authorization",
      next_phase: "s1_user_authorization"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s0_pre_authorization",
      next_phase: "closed_failed"
    });
    expect(presencePrompt.create).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "bind_passkey_ceremony_vault" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );

    await vi.advanceTimersByTimeAsync(0);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 7013,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays get errors when native rejects the S1 to S3 phase advance", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s1_user_authorization" &&
        command.next_phase === "s3_credential_resolution"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        throw new Error("assertion creation must not run after S1 to S3 advance fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7014,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 7014,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays create errors when native rejects the S1 to S3 phase advance", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s1_user_authorization" &&
        command.next_phase === "s3_credential_resolution"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: false };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "passkey_credential_status") {
        throw new Error("exclude status lookup must not run after S1 to S3 advance fails");
      }
      if (command.type === "create_passkey_registration") {
        throw new Error("registration creation must not run after S1 to S3 advance fails");
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 7015,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_failed"
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "passkey_credential_status" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );

    await vi.advanceTimersByTimeAsync(0);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 7015,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("fails closed before registration when native returns malformed passkey reconciliation", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation" };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7011,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "reconcile_passkey_ceremony_ledger",
      active_connection_id: expect.any(String)
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(presencePrompt.create).not.toHaveBeenCalled();
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 7011,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("marks a delivered WebAuthn get ceremony unknown-delivery when delivery confirmation fails", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "closed_delivered"
      ) {
        return {
          type: "error",
          code: "invalid_request",
          message: "delivery confirmation ledger write failed"
        };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7007,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as { type?: unknown; ceremony_token?: string })
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 7007,
      responseJson: expect.any(String)
    });
    expect(completeGetRequest).not.toHaveBeenCalledWith({
      requestId: 7007,
      error: expect.anything()
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation"
    });
  });

  it("does not send a second get completion when Chrome rejects a delivered assertion", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi
      .fn()
      .mockRejectedValueOnce(new Error("Chrome rejected completion"))
      .mockResolvedValueOnce(undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 7008,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation"
    });
    expect(completeGetRequest).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalledWith({
      requestId: 7008,
      error: expect.anything()
    });

    await vi.advanceTimersByTimeAsync(75);
    expect(completeGetRequest).toHaveBeenCalledTimes(1);
  });

  it("registers WebAuthn get ceremonies before opening the approval prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const events: string[] = [];
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "advance_passkey_ceremony_phase") {
        events.push(`runtime:advance:${String(command.next_phase)}`);
      } else {
        events.push(`runtime:${command.type}`);
      }
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    presencePrompt.create.mockImplementation(async () => {
      events.push("prompt:get");
      return { id: 77 };
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 236,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tMQ",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    const registerIndex = events.indexOf("runtime:register_passkey_ceremony");
    const s1AdvanceIndex = events.indexOf(
      "runtime:advance:s1_user_authorization"
    );
    const promptIndex = events.indexOf("prompt:get");
    expect(registerIndex).toBeGreaterThanOrEqual(0);
    expect(s1AdvanceIndex).toBeGreaterThanOrEqual(0);
    expect(promptIndex).toBeGreaterThanOrEqual(0);
    expect(registerIndex).toBeLessThan(promptIndex);
    expect(s1AdvanceIndex).toBeLessThan(promptIndex);
    expect(events).not.toContain("runtime:create_passkey_assertion");

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
  });

  it("fails closed without prompting when native rejects a same-frame concurrent get ceremony", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "passkey_ceremony_reconciliation",
        reconciled: []
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message:
          "passkey ceremony already active for origin, relying party, tab, and frame"
      });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 237,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y29uY3VycmVudC1nZXQ",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(2);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "get_session_state"
    });
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 237,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("persists passkey ceremony mirrors in session storage and clears them after delivery", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 107,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    expect(sessionStorage.set).toHaveBeenCalledWith({
      vaultkernPasskeyCeremonies: expect.objectContaining({
        version: 1,
        checksum: expect.any(String),
        ceremonies: expect.objectContaining({
          [ceremonyToken]: expect.objectContaining({
            ceremonyToken,
            ceremony: "get",
            phase: "s0_pre_authorization",
            origin: "https://example.com",
            relyingParty: "example.com",
            requestId: 107,
            tabId: 101,
            frameId: 0,
            frameKind: "top"
          })
        })
      })
    });
    const persistedCeremonies = passkeyCeremoniesFromStorageSnapshot(
      sessionStorage.snapshot()
    );
    expect(persistedCeremonies?.[ceremonyToken]).toBeUndefined();
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;
    expect(
      mirrorSnapshots.some((snapshot) => {
        const mirror = snapshot[ceremonyToken];
        return (
          mirror?.phase === "s1_user_authorization" &&
          mirror.activeVaultId === "vault-1" &&
          JSON.stringify(mirror.getCredentialIds) ===
            JSON.stringify(["Y3JlZGVudGlhbC0x"]) &&
          mirror.promptMode === "approve" &&
          typeof mirror.popupNonce === "string" &&
          Array.isArray(mirror.promptCredentialOptions)
        );
      })
    ).toBe(true);
  });

  it("serializes concurrent passkey ceremony mirror writes without losing ceremonies", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const data: Record<string, unknown> = {};
    let releaseScheduled = false;
    const pendingGets: Array<() => void> = [];
    const resolveGetBatchSoon = () => {
      if (releaseScheduled) {
        return;
      }
      releaseScheduled = true;
      setTimeout(() => {
        releaseScheduled = false;
        const batch = pendingGets.splice(0);
        for (const resolve of batch) {
          resolve();
        }
      }, 0);
    };
    const sessionStorage = {
      setAccessLevel: vi.fn(async () => undefined),
      get: vi.fn(
        async (keys?: unknown) =>
          new Promise<Record<string, unknown>>((resolve) => {
            const captured =
              Array.isArray(keys)
                ? Object.fromEntries(keys.map((key) => [key, data[String(key)]]))
                : typeof keys === "string"
                  ? { [keys]: data[keys] }
                  : { ...data };
            pendingGets.push(() => resolve(captured));
            resolveGetBatchSoon();
          })
      ),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(data, items);
      }),
      remove: vi.fn(async (keys: unknown) => {
        for (const key of Array.isArray(keys) ? keys : [keys]) {
          delete data[String(key)];
        }
      }),
      snapshot() {
        return { ...data };
      }
    };
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return new Promise(() => undefined);
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    for (const [requestId, tabId, challenge] of [
      [501, 101, "Y2hhbGxlbmdlLTUwMQ"],
      [502, 102, "Y2hhbGxlbmdlLTUwMg"]
    ] as const) {
      getListener?.({
        requestId,
        tabId,
        frameId: 0,
        origin: "https://example.com",
        requestDetailsJson: JSON.stringify({
          rpId: "example.com",
          challenge,
          allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
        })
      });
    }

    await vi.waitFor(() => {
      const ceremonies = passkeyCeremoniesFromStorageSnapshot(
        sessionStorage.snapshot()
      );
      expect(Object.keys(ceremonies ?? {})).toHaveLength(2);
    });
  });

  it("does not persist an extension-ahead phase when native rejects a get transition", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        if (
          command.expected_phase === "s0_pre_authorization" &&
          command.next_phase === "s1_user_authorization"
        ) {
          return { type: "passkey_ceremony_advanced", advanced: true };
        }
        if (
          command.expected_phase === "s1_user_authorization" &&
          command.next_phase === "s3_credential_resolution"
        ) {
          return {
            type: "error",
            code: "invalid_request",
            message: "phase mismatch"
          };
        }
        if (
          command.expected_phase === "s1_user_authorization" &&
          command.next_phase === "closed_failed"
        ) {
          return { type: "passkey_ceremony_advanced", advanced: true };
        }
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command ${JSON.stringify(command)}`);
    });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 129,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(73);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });

    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;

    expect(
      mirrorSnapshots.some(
        (snapshot) => snapshot[ceremonyToken]?.phase === "s1_user_authorization"
      )
    ).toBe(true);
    expect(
      mirrorSnapshots.some(
        (snapshot) => snapshot[ceremonyToken]?.phase === "s3_credential_resolution"
      )
    ).toBe(false);
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 129,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("does not persist an extension-ahead phase when native rejects a create transition", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        if (
          command.expected_phase === "s0_pre_authorization" &&
          command.next_phase === "s1_user_authorization"
        ) {
          return { type: "passkey_ceremony_advanced", advanced: true };
        }
        if (
          command.expected_phase === "s1_user_authorization" &&
          command.next_phase === "s3_credential_resolution"
        ) {
          return {
            type: "error",
            code: "invalid_request",
            message: "phase mismatch"
          };
        }
        if (
          command.expected_phase === "s1_user_authorization" &&
          command.next_phase === "closed_failed"
        ) {
          return { type: "passkey_ceremony_advanced", advanced: true };
        }
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command ${JSON.stringify(command)}`);
    });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 130,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });

    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;

    expect(
      mirrorSnapshots.some(
        (snapshot) => snapshot[ceremonyToken]?.phase === "s1_user_authorization"
      )
    ).toBe(true);
    expect(
      mirrorSnapshots.some(
        (snapshot) => snapshot[ceremonyToken]?.phase === "s3_credential_resolution"
      )
    ).toBe(false);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "create_passkey_registration"
      })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 130,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("reconciles the native ceremony ledger before registering a new get ceremony", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 127,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const commandTypes = sendRuntimeCommand.mock.calls.map(
      ([command]) => (command as { type?: unknown }).type
    );
    const reconcileIndex = commandTypes.indexOf("reconcile_passkey_ceremony_ledger");
    const registerIndex = commandTypes.indexOf("register_passkey_ceremony");
    expect(reconcileIndex).toBeGreaterThanOrEqual(0);
    expect(registerIndex).toBeGreaterThanOrEqual(0);
    expect(reconcileIndex).toBeLessThan(registerIndex);
  });

  it("fails closed without prompting when native rejects a same-frame concurrent ceremony", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "passkey_ceremony_reconciliation",
        reconciled: []
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message:
          "passkey ceremony already active for origin, relying party, tab, and frame"
      });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 128,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y29uY3VycmVudC0x",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(2);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 128,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("locks ceremony session storage to trusted extension contexts before persisting mirrors", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sessionStorage = {
      ...createSessionStorage(),
      setAccessLevel: vi.fn(async () => undefined)
    };
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 117,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sessionStorage.setAccessLevel).toHaveBeenCalledWith({
      accessLevel: "TRUSTED_CONTEXTS"
    });
    expect(
      sessionStorage.setAccessLevel.mock.invocationCallOrder[0]
    ).toBeLessThan(sessionStorage.set.mock.invocationCallOrder[0]);
  });

  it("does not persist ceremony mirrors when trusted session storage cannot be enforced", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sessionStorage = {
      ...createSessionStorage(),
      setAccessLevel: vi.fn(async () => {
        throw new Error("storage access level rejected");
      })
    };
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 118,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sessionStorage.setAccessLevel).toHaveBeenCalledWith({
      accessLevel: "TRUSTED_CONTEXTS"
    });
    expect(sessionStorage.set).not.toHaveBeenCalled();
  });

  it("does not persist ceremony mirrors when trusted session storage access-level API is unavailable", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    delete (sessionStorage as Record<string, unknown>).setAccessLevel;
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 119,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sessionStorage.set).not.toHaveBeenCalled();
  });

  it("does not rehydrate ceremony mirrors when trusted session storage access-level API is unavailable", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-untrusted-storage": {
          version: 1,
          ceremonyToken: "token-untrusted-storage",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 120,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    delete (sessionStorage as Record<string, unknown>).setAccessLevel;
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("untrusted ceremony mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("rehydrates persisted pre-completion ceremonies and drops native-missing completion mirrors", async () => {
    const sessionStorage = createSessionStorage({
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
          popupNonce: "nonce-pre-s4",
          promptMode: "unlock",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        },
        "token-s4": {
          version: 1,
          ceremonyToken: "token-s4",
          ceremony: "create",
          phase: "s4_completion_and_mutation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 108,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      },
      windows: {
        create: vi.fn(async () => ({ id: 47 })),
        update: vi.fn(async () => undefined)
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      return { type: "passkey_ceremony_advanced", advanced: true };
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(chromeApi.windows.update).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "query_passkey_ceremony_ledger",
      ceremony_token: "token-pre-s4"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "register_passkey_ceremony",
      ceremony_token: "token-pre-s4",
      connection_id: expect.any(String),
      origin: "https://example.com",
      top_origin: undefined,
      ancestor_origins: [],
      relying_party: "example.com",
      ceremony: "get",
      discoverable: false,
      user_verification: "preferred",
      challenge_base64url: "Y2hhbGxlbmdlLTE",
      request_id: 107,
      tab_id: 101,
      frame_id: 0,
      frame_kind: "top",
      registered_at_epoch_ms: expect.any(Number),
      expires_at_epoch_ms: expect.any(Number)
    });
    expect(passkeyCeremoniesFromStorageSnapshot(sessionStorage.snapshot())).toEqual({
      "token-pre-s4": expect.objectContaining({
        ceremonyToken: "token-pre-s4",
        phase: "s1_user_authorization"
      })
    });
  });

  it("does not re-register persisted ceremonies when queryLedger returns a runtime error", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-query-error": {
          version: 1,
          ceremonyToken: "token-query-error",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 208,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "error",
          code: "invalid_request",
          message: "ledger unavailable"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony"
      })
    );
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("drops native-missing persisted ceremonies when registration response is malformed", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-register-malformed": {
          version: 1,
          ceremonyToken: "token-register-malformed",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 211,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "unexpected_success_shape" };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony",
        ceremony_token: "token-register-malformed"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "advance_passkey_ceremony_phase"
      })
    );
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("drops native-missing persisted ceremonies when registration IPC fails", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-register-throws": {
          version: 1,
          ceremonyToken: "token-register-throws",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 212,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        throw new Error("native registration transport failed");
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await expect(
      reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand)
    ).resolves.toBeUndefined();

    expect(sendRuntimeCommand).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony",
        ceremony_token: "token-register-throws"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "advance_passkey_ceremony_phase"
      })
    );
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("drops persisted ceremonies when queryLedger cannot be reached", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-query-throws": {
          version: 1,
          ceremonyToken: "token-query-throws",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 209,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        throw new Error("native bridge unavailable");
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony"
      })
    );
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("does not rehydrate expired native-missing passkey ceremony mirrors", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(200_000);
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-expired": {
          version: 1,
          ceremonyToken: "token-expired",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 209,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: 199_999
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("expired mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("preserves native-missing passkey ceremony identity and expiry during rehydrate", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(200_000);
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-near-expiry": {
          version: 1,
          ceremonyToken: "token-near-expiry",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 210,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: 210_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "register_passkey_ceremony",
      ceremony_token: "token-near-expiry",
      connection_id: expect.any(String),
      origin: "https://example.com",
      top_origin: undefined,
      ancestor_origins: [],
      relying_party: "example.com",
      ceremony: "get",
      discoverable: false,
      user_verification: "preferred",
      challenge_base64url: "Y2hhbGxlbmdlLTE",
      request_id: 210,
      tab_id: 101,
      frame_id: 0,
      frame_kind: "top",
      registered_at_epoch_ms: 1_000,
      expires_at_epoch_ms: 210_000
    });
    expect(passkeyCeremoniesFromStorageSnapshot(sessionStorage.snapshot())).toEqual({
      "token-near-expiry": expect.objectContaining({
        ceremonyToken: "token-near-expiry",
        registeredAtEpochMs: 1_000,
        expiresAtEpochMs: 210_000
      })
    });
  });

  it("marks known committed S4 mirrors unknown-delivery during rehydrate", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-committed-s4": {
          version: 1,
          ceremonyToken: "token-committed-s4",
          ceremony: "create",
          phase: "s4_completion_and_mutation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 111,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s4_completion_and_mutation",
          durableState: "committed",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: "token-committed-s4",
      expected_phase: "s4_completion_and_mutation"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("marks known committed S4 mirrors unknown-delivery when delivery state is missing", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-committed-missing-delivery": {
          version: 1,
          ceremonyToken: "token-committed-missing-delivery",
          ceremony: "create",
          phase: "s4_completion_and_mutation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 115,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s4_completion_and_mutation",
          durableState: "committed"
        };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: "token-committed-missing-delivery",
      expected_phase: "s4_completion_and_mutation"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("marks known S4 get mirrors unknown-delivery during rehydrate", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-get-s4": {
          version: 1,
          ceremonyToken: "token-get-s4",
          ceremony: "get",
          phase: "s4_completion_and_mutation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 113,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s4_completion_and_mutation",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: "token-get-s4",
      expected_phase: "s4_completion_and_mutation"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("drops known ledger mirrors when native omits the ceremony phase", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-missing-native-phase": {
          version: 1,
          ceremonyToken: "token-missing-native-phase",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 114,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("aborts known uncommitted S4 mirrors by ceremony token during rehydrate", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-mutated-s4": {
          version: 1,
          ceremonyToken: "token-mutated-s4",
          ceremony: "create",
          phase: "s4_completion_and_mutation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 112,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s4_completion_and_mutation",
          durableState: "mutated",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "abort_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: "token-mutated-s4",
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("does not rehydrate unsealed passkey ceremony mirrors", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: {
        "token-unsealed": {
          version: 1,
          ceremonyToken: "token-unsealed",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 109,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      }
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("unsealed mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate checksum-mismatched passkey ceremony mirrors", async () => {
    const sealed = passkeyCeremonyStorage({
      "token-corrupt": {
        version: 1,
        ceremonyToken: "token-corrupt",
        ceremony: "get",
        phase: "s1_user_authorization",
        origin: "https://example.com",
        ancestorOrigins: [],
        relyingParty: "example.com",
        challengeBase64url: "Y2hhbGxlbmdlLTE",
        requestId: 110,
        tabId: 101,
        frameId: 0,
        frameKind: "top",
        registeredAtEpochMs: 1_000,
        expiresAtEpochMs: Date.now() + 300_000
      }
    });
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: {
        ...sealed,
        checksum: "passkey-ceremonies-v1:00000000"
      }
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("corrupt mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate passkey ceremony mirrors with unknown phases", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-unknown-phase": {
          version: 1,
          ceremonyToken: "token-unknown-phase",
          ceremony: "get",
          phase: "s9_future_phase",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 220,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("unknown phase mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate top-frame passkey ceremony mirrors with top origin context", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-top-with-top-origin": {
          version: 1,
          ceremonyToken: "token-top-with-top-origin",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          topOrigin: "https://container.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 206,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("invalid top-frame mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("rehydrates subframe passkey ceremony mirrors when top origin matches last ancestor by origin", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-subframe-default-port-top-origin": {
          version: 1,
          ceremonyToken: "token-subframe-default-port-top-origin",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://login.example.com",
          topOrigin: "https://container.example.net",
          ancestorOrigins: [
            "https://middle.example.net",
            "https://container.example.net:443"
          ],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 207,
          tabId: 101,
          frameId: 2,
          frameKind: "subframe",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony",
        ceremony_token: "token-subframe-default-port-top-origin",
        top_origin: "https://container.example.net",
        ancestor_origins: [
          "https://middle.example.net",
          "https://container.example.net:443"
        ],
        frame_kind: "subframe"
      })
    );
    expect(passkeyCeremoniesFromStorageSnapshot(sessionStorage.snapshot())).toEqual({
      "token-subframe-default-port-top-origin": expect.objectContaining({
        phase: "s1_user_authorization"
      })
    });
  });

  it("does not rehydrate subframe passkey ceremony mirrors whose last ancestor is not an origin", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-subframe-ancestor-path": {
          version: 1,
          ceremonyToken: "token-subframe-ancestor-path",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://login.example.com",
          topOrigin: "https://container.example.net",
          ancestorOrigins: [
            "https://middle.example.net",
            "https://container.example.net/path"
          ],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 208,
          tabId: 101,
          frameId: 2,
          frameKind: "subframe",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("non-origin ancestor mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate pre-S4 get mirrors without explicit credential request payload", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-missing-get-payload": {
          version: 1,
          ceremonyToken: "token-missing-get-payload",
          ceremony: "get",
          phase: "s2_network_validation",
          origin: "https://login.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 222,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("incomplete get mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate credential-resolution mirrors without a vault binding", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-unbound-s3": {
          version: 1,
          ceremonyToken: "token-unbound-s3",
          ceremony: "get",
          phase: "s3_credential_resolution",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 223,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("unbound credential-resolution mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("does not rehydrate same-origin S2 mirrors because network validation is ROR-only", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-same-origin-s2": {
          version: 1,
          ceremonyToken: "token-same-origin-s2",
          ceremony: "get",
          phase: "s2_network_validation",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 224,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async () => {
      throw new Error("same-origin S2 mirror must not reach native");
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalled();
  });

  it("replays ledger-only phase transitions when rehydrating a native-missing S2 mirror", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s2": {
          version: 1,
          ceremonyToken: "token-s2",
          ceremony: "get",
          phase: "s2_network_validation",
          origin: "https://login.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 207,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s2",
      expected_phase: "s0_pre_authorization",
      next_phase: "s1_user_authorization"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s2",
      expected_phase: "s1_user_authorization",
      next_phase: "s2_network_validation"
    });
    expect(passkeyCeremoniesFromStorageSnapshot(sessionStorage.snapshot())).toEqual({
      "token-s2": expect.objectContaining({
        ceremonyToken: "token-s2",
        phase: "s2_network_validation"
      })
    });
  });

  it("does not rehydrate native-missing S3 mirrors that require related-origin evidence", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-ror-s3": {
          version: 1,
          ceremonyToken: "token-ror-s3",
          ceremony: "get",
          phase: "s3_credential_resolution",
          origin: "https://login.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 208,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony",
        ceremony_token: "token-ror-s3"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "advance_passkey_ceremony_phase",
        next_phase: "s3_credential_resolution"
      })
    );
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("rehydrates native-missing related-origin S3 mirrors when current evidence was persisted", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-ror-s3": {
          version: 1,
          ceremonyToken: "token-ror-s3",
          ceremony: "get",
          phase: "s3_credential_resolution",
          origin: "https://login.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 209,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          relatedOriginVerified: true,
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const fetch = vi.spyOn(globalThis, "fetch");
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(fetch).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "register_passkey_ceremony",
      ceremony_token: "token-ror-s3",
      connection_id: expect.any(String),
      origin: "https://login.example",
      top_origin: undefined,
      ancestor_origins: [],
      relying_party: "example.com",
      ceremony: "get",
      discoverable: false,
      user_verification: "preferred",
      challenge_base64url: "Y2hhbGxlbmdlLTE",
      request_id: 209,
      tab_id: 101,
      frame_id: 0,
      frame_kind: "top",
      registered_at_epoch_ms: expect.any(Number),
      expires_at_epoch_ms: expect.any(Number)
    });
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toMatchObject([
      {
        expected_phase: "s0_pre_authorization",
        next_phase: "s1_user_authorization"
      },
      {
        expected_phase: "s1_user_authorization",
        next_phase: "s2_network_validation"
      },
      {
        expected_phase: "s2_network_validation",
        next_phase: "s3_credential_resolution",
        related_origin_verified: true
      }
    ]);
    expect(passkeyCeremoniesFromStorageSnapshot(sessionStorage.snapshot())).toEqual({
      "token-ror-s3": expect.objectContaining({
        ceremonyToken: "token-ror-s3",
        phase: "s3_credential_resolution",
        relatedOriginVerified: true
      })
    });
  });

  it("closes native-missing ceremonies when phase replay fails after a partial advance", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-ror-replay-fails": {
          version: 1,
          ceremonyToken: "token-ror-replay-fails",
          ceremony: "get",
          phase: "s3_credential_resolution",
          origin: "https://login.example",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 209,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          relatedOriginVerified: true,
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_ledger", known: false };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s0_pre_authorization" &&
        command.next_phase === "s1_user_authorization"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s1_user_authorization" &&
        command.next_phase === "s2_network_validation"
      ) {
        return {
          type: "error",
          code: "invalid_request",
          message: "phase replay rejected"
        };
      }
      if (
        command.type === "advance_passkey_ceremony_phase" &&
        command.expected_phase === "s1_user_authorization" &&
        command.next_phase === "closed_failed"
      ) {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${JSON.stringify(command)}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-ror-replay-fails",
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("fails closed instead of rewinding a persisted ceremony that is ahead of native ledger", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-ahead": {
          version: 1,
          ceremonyToken: "token-ahead",
          ceremony: "get",
          phase: "s3_credential_resolution",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 210,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-ahead",
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("fails closed instead of advancing a native-ahead mirror without required payload", async () => {
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-native-ahead-incomplete": {
          version: 1,
          ceremonyToken: "token-native-ahead-incomplete",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 212,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      storage: {
        session: sessionStorage
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3_credential_resolution",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-native-ahead-incomplete",
      expected_phase: "s3_credential_resolution",
      next_phase: "closed_failed"
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("restores known equal-phase S3B prompt options without replaying side effects", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const credentialOptions = [
      {
        credentialId: "Y3JlZGVudGlhbC0x",
        username: "alice@example.com"
      },
      {
        credentialId: "Y3JlZGVudGlhbC0y",
        username: "bob@example.com"
      }
    ];
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s3b": {
          version: 1,
          ceremonyToken: "token-s3b",
          ceremony: "get",
          phase: "s3b_user_selection",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 211,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: [null],
          getClientExtensionResults: {},
          popupNonce: "nonce-s3b",
          promptMode: "approve",
          promptCredentialOptions: credentialOptions,
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined)
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3b_user_selection",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    let response: unknown;
    messageListener?.(
      {
        type: "vaultkern_presence_options_request",
        requestId: 211,
        origin: "https://evil.example",
        relyingParty: "example.com",
        nonce: "nonce-s3b"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=211&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s3b"
      },
      (value: unknown) => {
        response = value;
      }
    );
    expect(response).toBeUndefined();

    messageListener?.(
      {
        type: "vaultkern_presence_options_request",
        requestId: 211,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-s3b"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=211&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s3b"
      },
      (value: unknown) => {
        response = value;
      }
    );

    expect(response).toEqual({ credentialOptions });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "register_passkey_ceremony"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "advance_passkey_ceremony_phase"
      })
    );
  });

  it("does not restore S3B prompt options with non-UI passkey fields", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s3b-private": {
          version: 1,
          ceremonyToken: "token-s3b-private",
          ceremony: "get",
          phase: "s3b_user_selection",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 219,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          popupNonce: "nonce-s3b-private",
          promptMode: "approve",
          promptCredentialOptions: [
            {
              credentialId: "Y3JlZGVudGlhbC0x",
              username: "alice@example.com",
              privateKeyPem: "-----BEGIN PRIVATE KEY-----"
            }
          ],
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined)
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3b_user_selection",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    let response: unknown;
    messageListener?.(
      {
        type: "vaultkern_presence_options_request",
        requestId: 219,
        nonce: "nonce-s3b-private"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=219&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s3b-private"
      },
      (value: unknown) => {
        response = value;
      }
    );

    expect(response).toBeUndefined();
  });

  it("does not restore S3B prompt options without a persisted vault binding", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s3b-unbound": {
          version: 1,
          ceremonyToken: "token-s3b-unbound",
          ceremony: "get",
          phase: "s3b_user_selection",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 221,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getClientExtensionResults: {},
          popupNonce: "nonce-s3b-unbound",
          promptMode: "approve",
          promptCredentialOptions: [
            {
              credentialId: "Y3JlZGVudGlhbC0x",
              username: "alice@example.com"
            }
          ],
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined)
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3b_user_selection",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    let response: unknown;
    messageListener?.(
      {
        type: "vaultkern_presence_options_request",
        requestId: 221,
        nonce: "nonce-s3b-unbound"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=221&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s3b-unbound"
      },
      (value: unknown) => {
        response = value;
      }
    );

    expect(response).toBeUndefined();
  });

  it("resumes a known equal-phase S3B get request when the restored prompt is approved", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const credentialOptions = [
      {
        credentialId: "Y3JlZGVudGlhbC0x",
        username: "alice@example.com"
      },
      {
        credentialId: "Y3JlZGVudGlhbC0y",
        username: "bob@example.com"
      }
    ];
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s3b": {
          version: 1,
          ceremonyToken: "token-s3b",
          ceremony: "get",
          phase: "s3b_user_selection",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 212,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: [null],
          popupNonce: "nonce-s3b",
          promptMode: "approve",
          promptCredentialOptions: credentialOptions,
          getClientExtensionResults: { appid: false },
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3b_user_selection",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0y",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0y"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 212,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-s3b",
        credentialId: "Y3JlZGVudGlhbC0y"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=212&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s3b"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s3b",
      expected_phase: "s3b_user_selection",
      next_phase: "s4_completion_and_mutation"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "create_passkey_assertion",
      ceremony_token: "token-s3b",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0y",
      discoverable: true,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s3b",
      expected_phase: "s4_completion_and_mutation",
      next_phase: "closed_delivered"
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 212,
      responseJson: JSON.stringify({
        id: "Y3JlZGVudGlhbC0y",
        rawId: "Y3JlZGVudGlhbC0y",
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: { appid: false },
        response: {
          authenticatorData: "auth-data",
          clientDataJSON: "client-data",
          signature: "signature",
          userHandle: "dXNlci0y"
        }
      })
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("does not send a second resumed get completion when Chrome rejects a delivered assertion", async () => {
    vi.useFakeTimers();

    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const credentialOptions = [
      {
        credentialId: "Y3JlZGVudGlhbC0x",
        username: "alice@example.com"
      }
    ];
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-resume-get-complete-fail": {
          version: 1,
          ceremonyToken: "token-resume-get-complete-fail",
          ceremony: "get",
          phase: "s3b_user_selection",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 213,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: [null],
          popupNonce: "nonce-resume-get",
          promptMode: "approve",
          promptCredentialOptions: credentialOptions,
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeGetRequest = vi
      .fn()
      .mockRejectedValueOnce(new Error("Chrome rejected completion"))
      .mockResolvedValueOnce(undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s3b_user_selection",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 213,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-resume-get",
        credentialId: "Y3JlZGVudGlhbC0x"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=213&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-resume-get"
      },
      vi.fn()
    );

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "mark_passkey_ceremony_unknown_delivery",
      ceremony_token: "token-resume-get-complete-fail",
      expected_phase: "s4_completion_and_mutation"
    });
    expect(completeGetRequest).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalledWith({
      requestId: 213,
      error: expect.anything()
    });

    await vi.advanceTimersByTimeAsync(75);
    expect(completeGetRequest).toHaveBeenCalledTimes(1);
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("resumes a known equal-phase S1 get request when the restored approval prompt is approved", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-s1": {
          version: 1,
          ceremonyToken: "token-s1",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 213,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          popupNonce: "nonce-s1",
          promptMode: "approve",
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 213,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-s1"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=213&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-s1"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s1",
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-s1",
      expected_phase: "s3_credential_resolution",
      next_phase: "s4_completion_and_mutation"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "create_passkey_assertion",
      ceremony_token: "token-s1",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      discoverable: false,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 213,
      responseJson: JSON.stringify({
        id: "Y3JlZGVudGlhbC0x",
        rawId: "Y3JlZGVudGlhbC0x",
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          authenticatorData: "auth-data",
          clientDataJSON: "client-data",
          signature: "signature",
          userHandle: "dXNlci0x"
        }
      })
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("fails closed when a restored approval prompt window is dismissed", async () => {
    vi.useFakeTimers();

    let removedListener: ((windowId: number) => void) | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-restored-dismiss": {
          version: 1,
          ceremonyToken: "token-restored-dismiss",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 216,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          popupNonce: "nonce-dismiss",
          promptMode: "approve",
          promptWindowId: 52,
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      storage: {
        session: sessionStorage
      },
      windows: {
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(removedListener).toBeDefined();
    removedListener?.(52);

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(75);

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-restored-dismiss",
      expected_phase: "s1_user_authorization",
      next_phase: "closed_aborted"
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 216,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
    expect(chromeApi.windows.onRemoved.removeListener).toHaveBeenCalled();
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("resumes a known equal-phase S1 get request when the restored unlock prompt completes", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-unlock": {
          version: 1,
          ceremonyToken: "token-unlock",
          ceremony: "get",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "Y2hhbGxlbmdlLTE",
          requestId: 214,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          getCredentialIds: ["Y3JlZGVudGlhbC0x"],
          popupNonce: "nonce-unlock",
          promptMode: "unlock",
          getClientExtensionResults: {},
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      windows: {
        create: vi.fn(async () => ({ id: 52 })),
        update: vi.fn(async () => undefined)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(chromeApi.windows.update).not.toHaveBeenCalled();

    messageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 214,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-unlock"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=unlock&requestId=214&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-unlock"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-unlock",
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "create_passkey_assertion",
      ceremony_token: "token-unlock",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      discoverable: false,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    const resumeResponse = JSON.parse(
      (completeGetRequest.mock.calls[0]?.[0] as { responseJson: string }).responseJson
    ) as { response: Record<string, unknown> };
    expect(resumeResponse).toMatchObject({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: "auth-data",
        clientDataJSON: "client-data",
        signature: "signature"
      }
    });
    expect(resumeResponse.response).not.toHaveProperty("userHandle");
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("resumes a known equal-phase S1 create request when the restored approval prompt is approved", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const events: string[] = [];
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-create-s1": {
          version: 1,
          ceremonyToken: "token-create-s1",
          ceremony: "create",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 215,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          createUserName: "alice@example.com",
          createUserDisplayName: "Alice",
          createUserHandleBase64url: "dXNlci0x",
          createPublicKeyAlgorithm: -7,
          createExcludeCredentialIds: [],
          createClientExtensionResults: { credProps: { rk: true } },
          popupNonce: "nonce-create-s1",
          promptMode: "approve",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeCreateRequest = vi.fn(async () => {
      events.push("chrome:complete_create");
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      events.push(`runtime:${command.type}`);
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 215,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-create-s1"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=215&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-create-s1"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-create-s1",
      expected_phase: "s1_user_authorization",
      next_phase: "s3_credential_resolution"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: "token-create-s1",
      expected_phase: "s3_credential_resolution",
      next_phase: "s4_completion_and_mutation"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "create_passkey_registration",
      ceremony_token: "token-create-s1",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      public_key_algorithm: -7,
      client_data_json_base64url: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "save_passkey_registration",
      ceremony_token: "token-create-s1",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "commit_passkey_registration",
      ceremony_token: "token-create-s1",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      entry_id: "entry-1",
      credential_id: "Y3JlZGVudGlhbC0x"
    });
    expect(events.indexOf("runtime:save_passkey_registration")).toBeLessThan(
      events.indexOf("runtime:commit_passkey_registration")
    );
    expect(events.indexOf("runtime:commit_passkey_registration")).toBeLessThan(
      events.indexOf("chrome:complete_create")
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 215,
      responseJson: JSON.stringify({
        id: "Y3JlZGVudGlhbC0x",
        rawId: "Y3JlZGVudGlhbC0x",
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          authenticatorData: "auth-data",
          attestationObject: "attestation-object",
          clientDataJSON: "client-data",
          publicKey: "public-key",
          publicKeyAlgorithm: -7,
          transports: ["internal"]
        }
      })
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("resumes a known equal-phase S1 create request when the restored unlock prompt completes", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-create-unlock": {
          version: 1,
          ceremonyToken: "token-create-unlock",
          ceremony: "create",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 216,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          createUserName: "alice@example.com",
          createUserDisplayName: "Alice",
          createUserHandleBase64url: "dXNlci0x",
          createPublicKeyAlgorithm: -7,
          createExcludeCredentialIds: [],
          createClientExtensionResults: {},
          popupNonce: "nonce-create-unlock",
          promptMode: "unlock",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeCreateRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 216,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-create-unlock"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=unlock&requestId=216&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-create-unlock"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "create_passkey_registration",
      ceremony_token: "token-create-unlock",
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      public_key_algorithm: -7,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 216,
      responseJson: JSON.stringify({
        id: "Y3JlZGVudGlhbC0x",
        rawId: "Y3JlZGVudGlhbC0x",
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          authenticatorData: "auth-data",
          attestationObject: "attestation-object",
          clientDataJSON: "client-data",
          publicKey: "public-key",
          publicKeyAlgorithm: -7,
          transports: ["internal"]
        }
      })
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("keeps a resumed create registration when Chrome completion fails after commit", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-create-complete-fails": {
          version: 1,
          ceremonyToken: "token-create-complete-fails",
          ceremony: "create",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 217,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          createUserName: "alice@example.com",
          createUserDisplayName: "Alice",
          createUserHandleBase64url: "dXNlci0x",
          createPublicKeyAlgorithm: -7,
          createExcludeCredentialIds: [],
          createClientExtensionResults: {},
          popupNonce: "nonce-create-complete-fails",
          promptMode: "approve",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeCreateRequest = vi.fn(async () => {
      throw new Error("chrome completion failed");
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 217,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-create-complete-fails"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=217&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-create-complete-fails"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: "token-create-complete-fails",
        expected_phase: "s4_completion_and_mutation"
      });
    });
    expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("marks a resumed delivered create registration unknown-delivery when delivery confirmation fails", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-create-delivery-confirm-fails": {
          version: 1,
          ceremonyToken: "token-create-delivery-confirm-fails",
          ceremony: "create",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 220,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          createUserName: "alice@example.com",
          createUserDisplayName: "Alice",
          createUserHandleBase64url: "dXNlci0x",
          createPublicKeyAlgorithm: -7,
          createExcludeCredentialIds: [],
          createClientExtensionResults: {},
          popupNonce: "nonce-create-delivery-confirm-fails",
          promptMode: "approve",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeCreateRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        if (command.next_phase === "closed_delivered") {
          return {
            type: "error",
            code: "invalid_request",
            message: "delivery confirmation ledger write failed"
          };
        }
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 220,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-create-delivery-confirm-fails"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=220&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-create-delivery-confirm-fails"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: "token-create-delivery-confirm-fails",
        expected_phase: "s4_completion_and_mutation"
      });
    });
    expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("aborts a resumed uncommitted create registration by token when runtime registration fails", async () => {
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => void)
      | undefined;
    const sessionStorage = createSessionStorage({
      vaultkernPasskeyCeremonies: passkeyCeremonyStorage({
        "token-create-registration-fails": {
          version: 1,
          ceremonyToken: "token-create-registration-fails",
          ceremony: "create",
          phase: "s1_user_authorization",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challengeBase64url: "cmVnaXN0ZXItMQ",
          requestId: 218,
          tabId: 101,
          frameId: 0,
          frameKind: "top",
          activeVaultId: "vault-1",
          createUserName: "alice@example.com",
          createUserDisplayName: "Alice",
          createUserHandleBase64url: "dXNlci0x",
          createPublicKeyAlgorithm: -7,
          createExcludeCredentialIds: [],
          createClientExtensionResults: {},
          popupNonce: "nonce-create-registration-fails",
          promptMode: "approve",
          registeredAtEpochMs: 1_000,
          expiresAtEpochMs: Date.now() + 300_000
        }
      })
    });
    const completeCreateRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (
              message: unknown,
              sender: unknown,
              sendResponse: (response: unknown) => void
            ) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest
      }
    };
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "query_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_ledger",
          known: true,
          phase: "s1_user_authorization",
          durableState: "none",
          deliveryState: "not_delivered"
        };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "error",
          code: "invalid_request",
          message: "registration mutation failed"
        };
      }
      if (command.type === "abort_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    await reconcilePersistedPasskeyCeremonies(chromeApi, sendRuntimeCommand);

    messageListener?.(
      {
        type: "vaultkern_presence_complete",
        requestId: 218,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: "nonce-create-registration-fails"
      },
      {
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=218&relyingParty=example.com&origin=https%3A%2F%2Fexample.com&nonce=nonce-create-registration-fails"
      },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "abort_passkey_registration",
        ceremony_token: "token-create-registration-fails",
        expected_phase: "s4_completion_and_mutation",
        closed_phase: "closed_failed"
      });
    });
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 218,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
    expect(sessionStorage.snapshot().vaultkernPasskeyCeremonies).toBeUndefined();
  });

  it("only resumes the WebAuthn request that matches the approved prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 31,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await presencePrompt.approve(32);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(31, { origin: "https://evil.example" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    const mismatchedSenderUrl =
      "chrome-extension://id/popup.html?webauthn=approve&requestId=31&relyingParty=example.com&origin=https%3A%2F%2Fevil.example&nonce=" +
      new URL(
        presencePrompt.latestPromptUrl() ?? "",
        "chrome-extension://id/"
      ).searchParams.get("nonce");
    await presencePrompt.approve(31, {}, { senderUrl: mismatchedSenderUrl });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(31);

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("does not resume multiple active ceremonies that reuse a Chrome request id", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: command.credential_id,
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 231,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "cmV1c2VkLXJlcXVlc3QtMQ",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
      expect(sendRuntimeCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "bind_passkey_ceremony_vault",
          expected_phase: "s1_user_authorization",
          vault_id: "vault-1"
        })
      );
    });
    const firstPromptUrl = (presencePrompt.create.mock.calls[0]?.[0] as {
      url?: string;
    }).url;

    getListener?.({
      requestId: 231,
      tabId: 102,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "cmV1c2VkLXJlcXVlc3QtMg",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0y" }]
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
        type: "create_passkey_assertion",
        credential_id: "Y3JlZGVudGlhbC0y"
      });
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(
      businessRuntimeCommandCalls(sendRuntimeCommand).filter(
        ([command]) =>
          (command as { type?: unknown } | null)?.type ===
          "create_passkey_assertion"
      )
    ).toHaveLength(1);
    expect(completeGetRequest).toHaveBeenCalledTimes(1);

    const firstPromptParams = new URL(
      firstPromptUrl ?? "",
      "chrome-extension://id/"
    ).searchParams;
    presencePrompt.sendRaw(
      {
        type: "vaultkern_presence_complete",
        requestId: 231,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: firstPromptParams.get("nonce")
      },
      { url: firstPromptUrl }
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(2);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "create_passkey_assertion",
      credential_id: "Y3JlZGVudGlhbC0x"
    });
    expect(
      businessRuntimeCommandCalls(sendRuntimeCommand).filter(
        ([command]) =>
          (command as { type?: unknown } | null)?.type ===
          "create_passkey_assertion"
      )
    ).toHaveLength(2);
  });

  it("ignores presence completion messages without the prompt sender and nonce", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 31,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    presencePrompt.sendRaw(
      {
        type: "vaultkern_presence_complete",
        requestId: 31,
        origin: "https://example.com",
        relyingParty: "example.com"
      },
      { url: "https://example.com/content-script.js" }
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("rejects a Chrome get request that only has a page-observed origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0",
        allowCredentialIds: ["Y3JlZGVudGlhbC1vYnM"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 27,
      tabId: 101,
      frameId: 0,
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC1vYnM"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 27,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("uses the content-script sender origin for Chrome get requests without a direct origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      return undefined;
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest(
        {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          origin: "https://spoofed.example",
          ancestorOrigins: [],
          relyingParty: "localhost",
          challenge: "bG9jYWxob3N0LWdldA",
          allowCredentialIds: ["Y3JlZGVudGlhbC0x"]
        },
        chromeApi,
        {
          url: "http://localhost:8877/login",
          tab: { id: 101 },
          frameId: 0
        }
      )
    ).toBe(true);

    getListener?.({
      requestId: 30,
      requestDetailsJson: JSON.stringify({
        rpId: "localhost",
        challenge: "bG9jYWxob3N0LWdldA",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "localhost",
      origin: "http://localhost:8877",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 30,
      responseJson: expect.any(String)
    });
  });

  it("rejects page-observed WebAuthn origins that are not origin-shaped", () => {
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: " https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0LW1hbGZvcm1lZA",
        allowCredentialIds: ["Y3JlZGVudGlhbC1vYnM"]
      })
    ).toBe(false);
  });

  it("rejects page-observed WebAuthn relying parties that are not RP-id-shaped", () => {
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: " observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0LWJhZC1ycA",
        allowCredentialIds: ["Y3JlZGVudGlhbC1vYnM"]
      })
    ).toBe(false);
  });

  it("rejects page-observed WebAuthn ancestor chains with malformed origins", () => {
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: [" https://middle.example", "https://top.example"],
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0LWJhZC1hbmNlc3Rvcg",
        allowCredentialIds: ["Y3JlZGVudGlhbC1vYnM"]
      })
    ).toBe(false);
  });

  it("ignores page-observed ancestor origins for confirmed top-level get requests", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC10b3Atb2Jz",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://example.com",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "example.com",
        challenge: "dG9wLW9ic2VydmVkLWFuY2VzdG9y",
        allowCredentialIds: ["Y3JlZGVudGlhbC10b3Atb2Jz"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 1270,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "dG9wLW9ic2VydmVkLWFuY2VzdG9y",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC10b3Atb2Jz"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as Record<string, unknown>)
      .find((command) => command.type === "register_passkey_ceremony");
    expect(registerCommand).toMatchObject({
      top_origin: undefined,
      ancestor_origins: [],
      frame_kind: "top"
    });
    expect(
      clientDataJsonFrom(
        (businessRuntimeCommand(sendRuntimeCommand, 2) as {
          client_data_json_base64url: string;
        }).client_data_json_base64url
      )
    ).toEqual({
      type: "webauthn.get",
      challenge: "dG9wLW9ic2VydmVkLWFuY2VzdG9y",
      origin: "https://example.com",
      crossOrigin: false
    });
  });

  it("marks clientDataJSON crossOrigin when any ancestor differs from the frame origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC1taWQ",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://observed.example",
        ancestorOrigins: ["https://middle.example", "https://observed.example"],
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0LW1pZA",
        allowCredentialIds: ["Y3JlZGVudGlhbC1taWQ"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 127,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0LW1pZA",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC1taWQ"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as Record<string, unknown>)
      .find((command) => command.type === "register_passkey_ceremony");
    expect(registerCommand).toMatchObject({
      top_origin: "https://observed.example",
      ancestor_origins: ["https://middle.example", "https://observed.example"],
      frame_kind: "subframe"
    });
    expect(
      clientDataJsonFrom(
        (businessRuntimeCommand(sendRuntimeCommand, 2) as {
          client_data_json_base64url: string;
        }).client_data_json_base64url
      )
    ).toEqual({
      type: "webauthn.get",
      challenge: "b2JzZXJ2ZWQtZ2V0LW1pZA",
      origin: "https://observed.example",
      crossOrigin: true,
      topOrigin: "https://observed.example"
    });
  });

  it("does not mark clientDataJSON crossOrigin for same-origin default-port ancestors", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC1kZWZhdWx0LXBvcnQ",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://observed.example:443",
        ancestorOrigins: ["https://observed.example:443"],
        relyingParty: "observed.example",
        challenge: "ZGVmYXVsdC1wb3J0",
        allowCredentialIds: ["Y3JlZGVudGlhbC1kZWZhdWx0LXBvcnQ"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 128,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "ZGVmYXVsdC1wb3J0",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC1kZWZhdWx0LXBvcnQ"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(
      clientDataJsonFrom(
        (businessRuntimeCommand(sendRuntimeCommand, 2) as {
          client_data_json_base64url: string;
        }).client_data_json_base64url
      )
    ).toEqual({
      type: "webauthn.get",
      challenge: "ZGVmYXVsdC1wb3J0",
      origin: "https://observed.example",
      crossOrigin: false
    });
  });

  it("does not trust page-observed subframe context when allowed credential ids only match by duplicates", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "observed.example",
        challenge: "ZHVwbGljYXRlLWFsbG93LW9ic2VydmVk",
        allowCredentialIds: [
          "Y3JlZGVudGlhbC0x",
          "Y3JlZGVudGlhbC0x"
        ]
      })
    ).toBe(true);

    getListener?.({
      requestId: 129,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "ZHVwbGljYXRlLWFsbG93LW9ic2VydmVk",
        allowCredentials: [
          { type: "public-key", id: "Y3JlZGVudGlhbC0x" },
          { type: "public-key", id: "Y3JlZGVudGlhbC0y" }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 129,
        error: {
          name: "NotAllowedError",
          message: "VaultKern cannot identify the WebAuthn request frame"
        }
      });
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
  });

  it("does not trust page-observed subframe context when the observed relying party is missing", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        challenge: "bWlzc2luZy1ycC1vYnNlcnZlZA"
      })
    ).toBe(true);

    getListener?.({
      requestId: 130,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "bWlzc2luZy1ycC1vYnNlcnZlZA"
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 130,
        error: {
          name: "NotAllowedError",
          message: "VaultKern cannot identify the WebAuthn request frame"
        }
      });
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
  });

  it("does not trust page-observed subframe context when the observed allowed credential ids are missing", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "observed.example",
        challenge: "bWlzc2luZy1hbGxvdy1vYnNlcnZlZA"
      })
    ).toBe(true);

    getListener?.({
      requestId: 131,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "bWlzc2luZy1hbGxvdy1vYnNlcnZlZA",
        allowCredentials: [
          { type: "public-key", id: "Y3JlZGVudGlhbC0x" }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 131,
        error: {
          name: "NotAllowedError",
          message: "VaultKern cannot identify the WebAuthn request frame"
        }
      });
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
  });

  it("does not trust page-observed subframe context when the observed relying party conflicts with the default RP ID", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "attacker.example",
        challenge: "ZGVmYXVsdC1ycC1taXNtYXRjaA"
      })
    ).toBe(true);

    getListener?.({
      requestId: 132,
      tabId: 101,
      frameId: 5,
      origin: "https://observed.example",
      requestDetailsJson: JSON.stringify({
        challenge: "ZGVmYXVsdC1ycC1taXNtYXRjaA"
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 132,
        error: {
          name: "NotAllowedError",
          message: "VaultKern cannot identify the WebAuthn request frame"
        }
      });
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
  });

  it("rejects top-level get requests that carry top origin context", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 128,
      tabId: 101,
      frameId: 0,
      origin: "https://frame.example",
      topOrigin: "https://container.example",
      requestDetailsJson: JSON.stringify({
        rpId: "frame.example",
        challenge: "dG9wLW9yaWdpbi1vbmx5",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC10b3A"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 128,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request frame"
      }
    });
  });

  it("rejects page-observed conditional mediation when Chrome supplies the request origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://example.com",
        relyingParty: "example.com",
        challenge: "Y29uZGl0aW9uYWwtZGlyZWN0",
        allowCredentialIds: ["Y3JlZGVudGlhbC0x"],
        mediation: "conditional"
      })
    ).toBe(true);

    getListener?.({
      requestId: 32,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y29uZGl0aW9uYWwtZGlyZWN0",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 32,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey provider does not support conditional mediation"
      }
    });
  });

  it("tries later allowed credentials when earlier passkey ids are not in the vault", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey credential not found: bWlzc2luZw"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "dmF1bHRrZXJuLWNyZWRlbnRpYWw",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x",
        backupEligible: true,
        backupState: false
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://accounts.google.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 17,
      tabId: 101,
      frameId: 0,
      origin: "https://accounts.google.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "bWlzc2luZw"
          },
          {
            type: "public-key",
            id: "dmF1bHRrZXJuLWNyZWRlbnRpYWw"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://accounts.google.com",
      credential_id: "bWlzc2luZw",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://accounts.google.com",
      credential_id: "dmF1bHRrZXJuLWNyZWRlbnRpYWw",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });

    const details = completeGetRequest.mock.calls[0][0];
    expect(details.requestId).toBe(17);
    const response = JSON.parse(details.responseJson);
    expect(response.id).toBe("dmF1bHRrZXJuLWNyZWRlbnRpYWw");
    expect(response.response.userHandle).toBe("dXNlci0x");
  });

  it("returns a generic error when all allowed credentials are missing", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey credential not found: c2VjcmV0LWNyZWRlbnRpYWw"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://accounts.google.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 18,
      tabId: 101,
      frameId: 0,
      origin: "https://accounts.google.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "c2VjcmV0LWNyZWRlbnRpYWw"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 18,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("returns the same generic error for cross-RP allowed credentials", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey relying party mismatch for credential c2VjcmV0LWNyZWRlbnRpYWw"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://accounts.google.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 181,
      tabId: 101,
      frameId: 0,
      origin: "https://accounts.google.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "c2VjcmV0LWNyZWRlbnRpYWw"
          }
        ]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(73);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 181,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("delays post-authorization WebAuthn get errors before completing the request", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey credential not found: c2VjcmV0LWNyZWRlbnRpYWw"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://accounts.google.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 180,
      tabId: 101,
      frameId: 0,
      origin: "https://accounts.google.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "c2VjcmV0LWNyZWRlbnRpYWw"
          }
        ]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://accounts.google.com",
      credential_id: "c2VjcmV0LWNyZWRlbnRpYWw",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(73);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 180,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("does not let a plain approval message override allowed credentials", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: command.credential_id,
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 181,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "YWxsb3dlZC0x"
          }
        ]
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
      expect(sendRuntimeCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "bind_passkey_ceremony_vault",
          expected_phase: "s1_user_authorization",
          vault_id: "vault-1"
        })
      );
    });
    for (let microtask = 0; microtask < 50; microtask += 1) {
      await Promise.resolve();
    }
    await presencePrompt.approve(undefined, {
      credentialId: "aW5qZWN0ZWQtMg"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "YWxsb3dlZC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(JSON.parse(completeGetRequest.mock.calls[0][0].responseJson)).toMatchObject({
      id: "YWxsb3dlZC0x",
      rawId: "YWxsb3dlZC0x",
      response: {
        userHandle: "dXNlci0x"
      }
    });
  });

  it("does not let a plain approval message turn a discoverable request into a credential selection", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "list_passkey_credentials") {
        return {
          type: "passkey_credential_list",
          credentials: [
            {
              credentialId: "ZGlzY292ZXJhYmxlLTE",
              username: "alice@example.com",
              userHandle: "dXNlci0x"
            }
          ]
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: command.credential_id,
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: "dXNlci0x"
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 182,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLWRpc2NvdmVyYWJsZQ",
        allowCredentials: []
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    for (let microtask = 0; microtask < 50; microtask += 1) {
      await Promise.resolve();
    }

    await presencePrompt.approve(undefined, {
      credentialId: "aW5qZWN0ZWQtMg"
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    expect(presencePrompt.requestOptions()).toEqual({
      credentialOptions: [
        {
          credentialId: "ZGlzY292ZXJhYmxlLTE",
          username: "alice@example.com"
        }
      ]
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(undefined, {
      credentialId: "ZGlzY292ZXJhYmxlLTE"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "list_passkey_credentials",
      vault_id: "vault-1",
      relying_party: "example.com"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "ZGlzY292ZXJhYmxlLTE",
      discoverable: true,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(JSON.parse(completeGetRequest.mock.calls[0][0].responseJson)).toMatchObject({
      id: "ZGlzY292ZXJhYmxlLTE",
      rawId: "ZGlzY292ZXJhYmxlLTE",
      response: {
        userHandle: "dXNlci0x"
      }
    });
  });

  it("returns a generic WebAuthn error when runtime returns a malformed assertion", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 182,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      next_phase: "closed_failed"
    });
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 182,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("reports unsupported appid get extensions as false without failing the request", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 171,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }],
        extensions: { appid: "https://example.com/app-id.json" }
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const details = completeGetRequest.mock.calls[0][0];
    const response = JSON.parse(details.responseJson);
    expect(response.clientExtensionResults).toEqual({ appid: false });
  });

  it("ignores unknown WebAuthn get extensions without returning extension results", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 172,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }],
        extensions: {
          prf: { eval: { first: "c2FsdC0x" } },
          largeBlob: { read: true }
        }
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const response = JSON.parse(completeGetRequest.mock.calls[0][0].responseJson);
    expect(response.clientExtensionResults).toEqual({});
  });

  it("derives the default WebAuthn get RP ID from the request origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://login.example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 21,
      tabId: 101,
      frameId: 0,
      origin: "https://login.example.com",
      requestDetailsJson: JSON.stringify({
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "login.example.com",
      origin: "https://login.example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      discoverable: false,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("canonicalizes requested WebAuthn get RP IDs before signing", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 29,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "Example.COM",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      discoverable: false,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("allows discoverable WebAuthn get requests without allowed credentials", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "ZGlzY292ZXJhYmxlLTE",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          }
        ]
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "ZGlzY292ZXJhYmxlLTE",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 22,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: []
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    expect(presencePrompt.requestOptions()).toEqual({
      credentialOptions: [
        {
          credentialId: "ZGlzY292ZXJhYmxlLTE",
          username: "alice@example.com"
        }
      ]
    });
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(undefined, {
      credentialId: "ZGlzY292ZXJhYmxlLTE"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "list_passkey_credentials",
      vault_id: "vault-1",
      relying_party: "example.com"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "ZGlzY292ZXJhYmxlLTE",
      discoverable: true,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    const response = JSON.parse(completeGetRequest.mock.calls[0][0].responseJson);
    expect(response.id).toBe("ZGlzY292ZXJhYmxlLTE");
  });

  it("requires S3B account selection for single-credential discoverable WebAuthn get requests", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "ZGlzY292ZXJhYmxlLXNpbmdsZQ",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          }
        ]
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "ZGlzY292ZXJhYmxlLXNpbmdsZQ",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 1820,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLXNpbmdsZS1kaXNjb3ZlcmFibGU",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    expect(presencePrompt.requestOptions()).toEqual({
      credentialOptions: [
        {
          credentialId: "ZGlzY292ZXJhYmxlLXNpbmdsZQ",
          username: "alice@example.com"
        }
      ]
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await presencePrompt.approve(undefined, {
      credentialId: "ZGlzY292ZXJhYmxlLXNpbmdsZQ"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      credential_id: "ZGlzY292ZXJhYmxlLXNpbmdsZQ",
      discoverable: true,
      user_presence_verified: true
    });
    const response = JSON.parse(completeGetRequest.mock.calls[0][0].responseJson);
    expect(response.id).toBe("ZGlzY292ZXJhYmxlLXNpbmdsZQ");
    expect(response.response.userHandle).toBe("dXNlci0x");
  });

  it("delays discoverable WebAuthn get enumeration errors before completing the request", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "vault list failed with storage detail"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 234,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: []
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "list_passkey_credentials",
      vault_id: "vault-1",
      relying_party: "example.com"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 234,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("uses the passkey credential selected by the approval prompt for discoverable get requests", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "Y3JlZGVudGlhbC0x",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          },
          {
            credentialId: "Y3JlZGVudGlhbC0y",
            username: "bob@example.com",
            userHandle: "dXNlci0y"
          }
        ]
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0y",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0y"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 57,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tMQ"
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    const initialPromptParams = new URL(
      (presencePrompt.create.mock.calls[0][0] as { url: string }).url,
      "chrome-extension://id/"
    ).searchParams;
    expect(initialPromptParams.get("credentialOptions")).toBeNull();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    const selectionPromptParams = new URL(
      (presencePrompt.create.mock.calls[1][0] as { url: string }).url,
      "chrome-extension://id/"
    ).searchParams;
    expect(selectionPromptParams.get("credentialOptions")).toBeNull();
    expect(presencePrompt.requestOptions()).toEqual({
      credentialOptions: [
        {
          credentialId: "Y3JlZGVudGlhbC0x",
          username: "alice@example.com"
        },
        {
          credentialId: "Y3JlZGVudGlhbC0y",
          username: "bob@example.com"
        }
      ]
    });

    await presencePrompt.approve(undefined, {
      credentialId: "Y3JlZGVudGlhbC0y"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(registerCommand).toMatchObject({ discoverable: true });
    const ceremonyToken = registerCommand?.ceremony_token;
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toMatchObject([
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s0_pre_authorization",
        next_phase: "s1_user_authorization"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s1_user_authorization",
        next_phase: "s3_credential_resolution"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s3_credential_resolution",
        next_phase: "s3b_user_selection"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s3b_user_selection",
        next_phase: "s4_completion_and_mutation"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s4_completion_and_mutation",
        next_phase: "closed_delivered"
      }
    ]);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "list_passkey_credentials",
      vault_id: "vault-1",
      relying_party: "example.com"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0y",
      discoverable: true,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("delays and closes as aborted when the discoverable selection popup is dismissed", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    let removedListener: ((windowId: number) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "Y3JlZGVudGlhbC0x",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          },
          {
            credentialId: "Y3JlZGVudGlhbC0y",
            username: "bob@example.com",
            userHandle: "dXNlci0y"
          }
        ]
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 572,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tc2VsZWN0aW9uLWRpc21pc3NlZA"
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
      expect(removedListener).toBeDefined();
    });

    removedListener?.(77);

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
      expect.objectContaining({
        ceremony_token: registerCommand?.ceremony_token,
        expected_phase: "s3b_user_selection",
        next_phase: "closed_aborted"
      })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 572,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("fails closed when the discoverable selection popup submits an unlisted credential", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "Y3JlZGVudGlhbC0x",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          },
          {
            credentialId: "Y3JlZGVudGlhbC0y",
            username: "bob@example.com",
            userHandle: "dXNlci0y"
          }
        ]
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 573,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tc2VsZWN0aW9uLW1hbGljaW91cw"
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    await presencePrompt.approve(undefined, {
      credentialId: "bm90LWluLXRoZS1vcHRpb25z"
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
      expect.objectContaining({
        ceremony_token: registerCommand?.ceremony_token,
        expected_phase: "s3b_user_selection",
        next_phase: "closed_failed"
      })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 573,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("does not expose S3B credential options when the selection popup fails to open", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_list",
        credentials: [
          {
            credentialId: "Y3JlZGVudGlhbC0x",
            username: "alice@example.com",
            userHandle: "dXNlci0x"
          },
          {
            credentialId: "Y3JlZGVudGlhbC0y",
            username: "bob@example.com",
            userHandle: "dXNlci0y"
          }
        ]
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    presencePrompt.create
      .mockResolvedValueOnce({ id: 77 })
      .mockRejectedValueOnce(new Error("popup blocked"));

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 571,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tc2VsZWN0aW9uLWZhaWxz"
      })
    });

    for (let microtask = 0; microtask < 20; microtask += 1) {
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(0);
      if (presencePrompt.create.mock.calls.length >= 1) {
        break;
      }
    }
    expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    await Promise.resolve();
    const firstPromptUrl = (
      presencePrompt.create.mock.calls[0][0] as { url: string }
    ).url;
    const firstPromptParams = new URL(
      firstPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    presencePrompt.sendRaw(
      {
        type: "vaultkern_presence_complete",
        requestId: Number(firstPromptParams.get("requestId")),
        origin: firstPromptParams.get("origin"),
        relyingParty: firstPromptParams.get("relyingParty"),
        nonce: firstPromptParams.get("nonce")
      },
      { url: firstPromptUrl }
    );

    for (let microtask = 0; microtask < 20; microtask += 1) {
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(0);
      if (presencePrompt.create.mock.calls.length >= 2) {
        break;
      }
    }
    expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    const failedPromptUrl = (
      presencePrompt.create.mock.calls[1][0] as { url: string }
    ).url;

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 571,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
    expect(presencePrompt.requestOptions({ senderUrl: failedPromptUrl })).toBeUndefined();
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
  });

  it.each(["conditional", "immediate"] as const)(
    "rejects page-observed %s mediation instead of opening a modal prompt",
    async (mediation) => {
      let getListener: ((request: unknown) => void) | undefined;
      const completeGetRequest = vi.fn(async () => undefined);
      const sendRuntimeCommand = runtimeCommandMock(async (command) => {
        throw new Error(`unexpected command: ${String(command.type)}`);
      });
      const chromeApi = {
        runtime: {},
        webAuthenticationProxy: {
          attach: vi.fn(async () => undefined),
          completeGetRequest,
          onGetRequest: {
            addListener(listener: (request: unknown) => void) {
              getListener = listener;
            }
          }
        }
      };
      const challenge =
        mediation === "conditional" ? "Y29uZGl0aW9uYWwtMQ" : "aW1tZWRpYXRlLTE";

      await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
      expect(
        recordWebAuthnPageRequest({
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          origin: "https://example.com",
          relyingParty: "example.com",
          challenge,
          allowCredentialIds: ["Y3JlZGVudGlhbC0x"],
          mediation
        })
      ).toBe(true);

      getListener?.({
        requestId: mediation === "conditional" ? 31 : 58,
        tabId: 101,
        frameId: 0,
        origin: "https://example.com",
        requestDetailsJson: JSON.stringify({
          rpId: "example.com",
          challenge,
          allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
        })
      });

      await vi.waitFor(() => {
        expect(completeGetRequest).toHaveBeenCalledTimes(1);
      });
      expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: mediation === "conditional" ? 31 : 58,
        error: {
          name: "NotAllowedError",
          message: `VaultKern passkey provider does not support ${mediation} mediation`
        }
      });
    }
  );

  it("allows modal WebAuthn get observations with optional and required mediation", async () => {
    for (const mediation of ["optional", "required"]) {
      let getListener: ((request: unknown) => void) | undefined;
      const completeGetRequest = vi.fn(async () => undefined);
      const sendRuntimeCommand = runtimeCommandMock()
        .mockResolvedValueOnce({
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        })
        .mockResolvedValueOnce({
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        });
      const chromeApi = {
        runtime: {},
        tabs: {
          query: vi.fn(async () => [{ url: "https://example.com/login" }])
        },
        webAuthenticationProxy: {
          attach: vi.fn(async () => undefined),
          completeGetRequest,
          onGetRequest: {
            addListener(listener: (request: unknown) => void) {
              getListener = listener;
            }
          }
        }
      };
      const presencePrompt = installPresencePrompt(chromeApi);
      const challenge =
        mediation === "optional" ? "b3B0aW9uYWwtMQ" : "cmVxdWlyZWQtMQ";

      await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
      expect(
        recordWebAuthnPageRequest({
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          origin: "https://example.com",
          ancestorOrigins: [],
          relyingParty: "example.com",
          challenge,
          allowCredentialIds: ["Y3JlZGVudGlhbC0x"],
          mediation
        })
      ).toBe(true);

      getListener?.({
        requestId: mediation === "optional" ? 59 : 60,
        tabId: 101,
        frameId: 0,
        origin: "https://example.com",
        requestDetailsJson: JSON.stringify({
          rpId: "example.com",
          challenge,
          allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
        })
      });
      await presencePrompt.approve();

      await vi.waitFor(() => {
        expect(completeGetRequest).toHaveBeenCalledTimes(1);
      });
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: mediation === "optional" ? 59 : 60,
        responseJson: expect.any(String)
      });
      expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
        type: "get_session_state"
      });
    }
  });

  it("rejects public-suffix WebAuthn get RP IDs before session lookup or prompts", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 61,
      tabId: 101,
      frameId: 0,
      origin: "https://attacker.com",
      requestDetailsJson: JSON.stringify({
        rpId: "com",
        challenge: "bWlzbWF0Y2gtMQ",
        allowCredentials: []
      })
    });
    getListener?.({
      requestId: 62,
      tabId: 101,
      frameId: 0,
      origin: "https://attacker.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "co.uk",
        challenge: "bWlzbWF0Y2gtMg",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(2);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 61,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 62,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
  });

  it("fails get requests closed when ceremony token CSPRNG is unavailable", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.stubGlobal("crypto", {});
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6100,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y3Nwcm5nLW1pc3Npbmc",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(random).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6100,
      error: {
        name: "NotAllowedError",
        message: "VaultKern secure random source is unavailable"
      }
    });
  });

  it("fails get requests closed when prompt nonce CSPRNG is unavailable", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    resetPasskeyLedgerConnectionId();
    let randomCalls = 0;
    const cryptoApi: { getRandomValues?: (bytes: Uint8Array) => Uint8Array } = {
      getRandomValues(bytes: Uint8Array) {
        randomCalls += 1;
        bytes.fill(1);
        if (randomCalls >= 2) {
          delete cryptoApi.getRandomValues;
        }
        return bytes;
      }
    };
    vi.stubGlobal("crypto", cryptoApi);
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6102,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bm9uY2UtY3Nwcm5nLW1pc3Npbmc",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(random).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6102,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("fails create requests closed when ceremony token CSPRNG is unavailable", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    vi.stubGlobal("crypto", {});
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 6103,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "Y3JlYXRlLWNzcHJuZy1taXNzaW5n",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(random).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6103,
      error: {
        name: "NotAllowedError",
        message: "VaultKern secure random source is unavailable"
      }
    });
  });

  it("fails create requests closed when prompt nonce CSPRNG is unavailable", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    resetPasskeyLedgerConnectionId();
    let randomCalls = 0;
    const cryptoApi: { getRandomValues?: (bytes: Uint8Array) => Uint8Array } = {
      getRandomValues(bytes: Uint8Array) {
        randomCalls += 1;
        bytes.fill(2);
        if (randomCalls >= 2) {
          delete cryptoApi.getRandomValues;
        }
        return bytes;
      }
    };
    vi.stubGlobal("crypto", cryptoApi);
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 6104,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "Y3JlYXRlLW5vbmNlLWNzcHJuZy1taXNzaW5n",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(random).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "advance_passkey_ceremony_phase",
      ceremony_token: expect.any(String),
      expected_phase: "s1_user_authorization",
      next_phase: "closed_failed"
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6104,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("rejects non-secure WebAuthn get origins before session lookup or prompts", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6101,
      tabId: 101,
      frameId: 0,
      origin: "http://example.com",
      requestDetailsJson: JSON.stringify({
        challenge: "bm9uLXNlY3VyZS1vcmlnaW4",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6101,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
  });

  it("rejects non-origin-shaped WebAuthn get origins before native ledger registration", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      throw new Error("non-origin get must not reach native");
    });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6105,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com/path",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bm9uLW9yaWdpbi1nZXQ",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_session_state" })
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6105,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("rejects whitespace-padded WebAuthn get origins before native ledger registration", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      throw new Error("whitespace-padded get must not reach native");
    });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6107,
      tabId: 101,
      frameId: 0,
      origin: " https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "d2hpdGVzcGFjZS1nZXQ",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_session_state" })
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6107,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it.each([" example.com", "example.com."])(
    "rejects non-canonical WebAuthn get RP ID %s before native ledger registration",
    async (rpId) => {
      let getListener: ((request: unknown) => void) | undefined;
      const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true
      } as Response);
      const completeGetRequest = vi.fn(async () => undefined);
      const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
        if (command.type === "reconcile_passkey_ceremony_ledger") {
          return { type: "passkey_ceremony_reconciliation", reconciled: [] };
        }
        throw new Error("non-canonical get RP ID must not reach native");
      });
      const chromeApi = {
        runtime: {},
        windows: {
          create: vi.fn(async () => ({ id: 77 }))
        },
        webAuthenticationProxy: {
          attach: vi.fn(async () => undefined),
          completeGetRequest,
          onGetRequest: {
            addListener(listener: (request: unknown) => void) {
              getListener = listener;
            }
          }
        }
      };

      await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
      getListener?.({
        requestId: 6109,
        tabId: 101,
        frameId: 0,
        origin: "https://login.example.com",
        requestDetailsJson: JSON.stringify({
          rpId,
          challenge: "d2hpdGVzcGFjZS1ycC1nZXQ",
          allowCredentials: []
        })
      });

      await vi.waitFor(() => {
        expect(completeGetRequest).toHaveBeenCalledTimes(1);
      });
      expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: "register_passkey_ceremony" })
      );
      expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: "get_session_state" })
      );
      expect(fetch).not.toHaveBeenCalled();
      expect(chromeApi.windows.create).not.toHaveBeenCalled();
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 6109,
        error: {
          name: "NotAllowedError",
          message: "invalid WebAuthn RP ID"
        }
      });
    }
  );

  it("rejects malformed explicit top origins before native ledger registration", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      throw new Error("malformed topOrigin must not reach native");
    });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 6111,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      topOrigin: " https://top.example",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bWFsZm9ybWVkLXRvcC1vcmlnaW4",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_session_state" })
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 6111,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("rejects subframe get requests when the top origin is unavailable", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/frame" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 611,
      tabId: 101,
      frameId: 2,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 611,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request frame"
      }
    });
  });

  it("rejects get requests when the trusted frame position is unavailable", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 612,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 612,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request frame"
      }
    });
  });

  it("delays unauthorized related-origin get errors after approval without enumeration", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 63,
      tabId: 101,
      frameId: 0,
      origin: "https://attacker.com",
      requestDetailsJson: JSON.stringify({
        rpId: "victim.com",
        challenge: "bWlzbWF0Y2gtMg",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(fetch).toHaveBeenCalledWith(
      "https://victim.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "list_passkey_credentials" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 63,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("delays malformed related-origin get documents without credential enumeration", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: "https://youtube.com"
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 631,
      tabId: 101,
      frameId: 0,
      origin: "https://youtube.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "bWlzbWF0Y2gtMw",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://google.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "list_passkey_credentials" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 631,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("skips related-origin allowlist entries that are not exact origins", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://youtube.com/with-path"]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 64,
      tabId: 101,
      frameId: 0,
      origin: "https://youtube.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "list_passkey_credentials" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 64,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("allows related-origin get requests after well-known validation", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 32,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.co.uk",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      related_origin_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("advances related-origin get requests through the network-validation phase", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 321,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const getCommands = sendRuntimeCommand.mock.calls.map(
      ([command]) => command as { type?: unknown; next_phase?: unknown }
    );
    const bindIndex = getCommands.findIndex(
      (command) => command.type === "bind_passkey_ceremony_vault"
    );
    const s3Index = getCommands.findIndex(
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "s3_credential_resolution"
    );
    expect(bindIndex).toBeGreaterThanOrEqual(0);
    expect(bindIndex).toBeLessThan(s3Index);
    expect(getCommands[bindIndex]).toMatchObject({
      type: "bind_passkey_ceremony_vault",
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1"
    });
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toMatchObject([
      {
        expected_phase: "s0_pre_authorization",
        next_phase: "s1_user_authorization"
      },
      {
        expected_phase: "s1_user_authorization",
        next_phase: "s2_network_validation"
      },
      {
        expected_phase: "s2_network_validation",
        next_phase: "s3_credential_resolution",
        related_origin_verified: true
      },
      {
        expected_phase: "s3_credential_resolution",
        next_phase: "s4_completion_and_mutation"
      },
      {
        expected_phase: "s4_completion_and_mutation",
        next_phase: "closed_delivered"
      }
    ]);
  });

  it("persists related-origin verification evidence before credential resolution", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);
    const sessionStorage = createSessionStorage();
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 322,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;
    expect(
      mirrorSnapshots.some((snapshot) =>
        Object.values(snapshot).some(
          (mirror) =>
            mirror.phase === "s3_credential_resolution" &&
            mirror.relatedOriginVerified === true
        )
      )
    ).toBe(true);
  });

  it("uses the related-origin credential selection prompt as the user interaction", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let resolveFetch: (value: Response) => void = () => {};
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        })
    );
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        credentials: [
          {
            credentialId: "Y3JlZGVudGlhbC0x",
            username: "Alice",
            userHandle: "dXNlci0x"
          },
          {
            credentialId: "Y3JlZGVudGlhbC0y",
            username: "Bob",
            userHandle: "dXNlci0y"
          }
        ]
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0y",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0y"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 33,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTI",
        allowCredentials: []
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(fetch).toHaveBeenCalledTimes(1);
    });
    resolveFetch({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });
    const promptUrl = presencePrompt.latestPromptUrl();
    const promptParams = new URL(
      promptUrl ?? "",
      "chrome-extension://id/"
    ).searchParams;
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const promptOptions = presencePrompt.requestOptions();
    expect(promptUrl).not.toContain(ceremonyToken);
    expect(promptParams.get("credentialOptions")).toBeNull();
    expect(JSON.stringify(promptOptions)).not.toContain(ceremonyToken);
    expect(promptOptions).toEqual({
      credentialOptions: [
        {
          credentialId: "Y3JlZGVudGlhbC0x",
          username: "Alice"
        },
        {
          credentialId: "Y3JlZGVudGlhbC0y",
          username: "Bob"
        }
      ]
    });

    await presencePrompt.approve(33, { credentialId: "Y3JlZGVudGlhbC0y" });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "list_passkey_credentials",
      vault_id: "vault-1",
      relying_party: "example.com"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.co.uk",
      credential_id: "Y3JlZGVudGlhbC0y",
      user_presence_verified: true,
      related_origin_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("validates related-origin get requests after user approval before assertion", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let resolveFetch: (value: Response) => void = () => {};
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        })
    );
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 132,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 20; microtask += 1) {
      await Promise.resolve();
    }
    expect(fetch).toHaveBeenCalledTimes(1);

    resolveFetch({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
  });

  it("times out stalled related-origin well-known responses", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(() => new Promise(() => undefined))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.co.uk/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 135,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 20; microtask += 1) {
      await Promise.resolve();
    }
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(4_999);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(73);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 135,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });

    vi.useRealTimers();
  });

  it("allows related-origin responses across distinct labels within the client limit", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: [
          "https://youtube.com",
          "https://maps.com",
          "https://mail.com",
          "https://drive.com",
          "https://photos.com"
        ]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://youtube.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 133,
      tabId: 101,
      frameId: 0,
      origin: "https://youtube.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://youtube.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      related_origin_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("does not count malformed related-origin entries against the five-label budget", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: [
          "https://invalid.example/path",
          "https://youtube.com",
          "https://maps.com",
          "https://mail.com",
          "https://drive.com",
          "https://photos.com"
        ]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://photos.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 138,
      tabId: 101,
      frameId: 0,
      origin: "https://photos.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      relying_party: "google.com",
      origin: "https://photos.com",
      related_origin_verified: true
    });
  });

  it("ignores related-origin allowlist entries after the five-label budget", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: [
          "https://youtube.com",
          "https://maps.com",
          "https://mail.com",
          "https://drive.com",
          "https://photos.com",
          "https://overflow.com"
        ]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://youtube.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 136,
      tabId: 101,
      frameId: 0,
      origin: "https://youtube.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      relying_party: "google.com",
      origin: "https://youtube.com",
      related_origin_verified: true
    });
  });

  it("rejects related-origin requests whose origin appears only after the five-label budget", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: [
          "https://youtube.com",
          "https://maps.com",
          "https://mail.com",
          "https://drive.com",
          "https://photos.com",
          "https://overflow.com"
        ]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://overflow.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 137,
      tabId: 101,
      frameId: 0,
      origin: "https://overflow.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(75);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 137,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("allows related-origin responses that reuse one label across more than the client origin limit", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: [
          "https://same.com",
          "https://same.net",
          "https://same.org",
          "https://same.io",
          "https://same.dev",
          "https://same.app"
        ]
      }))
    } as unknown as Response);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://same.app/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 134,
      tabId: 101,
      frameId: 0,
      origin: "https://same.app",
      requestDetailsJson: JSON.stringify({
        rpId: "same.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "same.com",
      origin: "https://same.app",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      related_origin_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("completes WebAuthn create requests with a runtime registration and saves the vault", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    createListener?.({
      requestId: 10,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        extensions: { credProps: true }
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledWith({
        url: expect.stringMatching(
          /^chrome-extension:\/\/id\/popup\.html\?webauthn=approve&requestId=10&relyingParty=example\.com&origin=https%3A%2F%2Fexample\.com&nonce=[A-Za-z0-9_-]+$/
        ),
        type: "popup",
        width: 460,
        height: 360,
        focused: true
      });
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      public_key_algorithm: -7,
      client_data_json_base64url: expect.any(String)
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "save_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "commit_passkey_registration",
      vault_id: "vault-1",
      entry_id: "entry-1",
      credential_id: "Y3JlZGVudGlhbC0x"
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const promptUrl = presencePrompt.latestPromptUrl() ?? "";
    const promptParams = new URL(promptUrl, "chrome-extension://id/").searchParams;
    expect(promptUrl).not.toContain(ceremonyToken);
    expect(promptParams.has("ceremonyToken")).toBe(false);
    expect(promptParams.has("ceremony_token")).toBe(false);
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;
    expect(
      mirrorSnapshots.some((snapshot) => {
        const mirror = snapshot[ceremonyToken];
        return (
          mirror?.phase === "s1_user_authorization" &&
          mirror.activeVaultId === "vault-1" &&
          mirror.createUserName === "alice@example.com" &&
          mirror.createUserDisplayName === "Alice" &&
          mirror.createUserHandleBase64url === "dXNlci0x" &&
          mirror.createPublicKeyAlgorithm === -7 &&
          Array.isArray(mirror.createExcludeCredentialIds) &&
          mirror.createClientExtensionResults &&
          JSON.stringify(mirror.createClientExtensionResults) ===
            JSON.stringify({ credProps: { rk: true } })
        );
      })
    ).toBe(true);

    const details = completeCreateRequest.mock.calls[0][0];
    expect(details.requestId).toBe(10);
    const response = JSON.parse(details.responseJson);
    expect(response).toEqual({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: { credProps: { rk: true } },
      response: {
        authenticatorData: "auth-data",
        attestationObject: "attestation-object",
        clientDataJSON: "client-data",
        publicKey: "public-key",
        publicKeyAlgorithm: -7,
        transports: ["internal"]
      }
    });
  });

  it.each(["merged", "saved_to_cache"] as const)(
    "treats %s passkey registration saves as durable before completing create",
    async (saveStatus) => {
      let createListener: ((request: unknown) => void) | undefined;
      const completeCreateRequest = vi.fn(async () => undefined);
      const sendRuntimeCommand = runtimeCommandMock()
        .mockResolvedValueOnce({
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        })
        .mockResolvedValueOnce({
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          userHandleBase64url: "dXNlci0x"
        })
        .mockResolvedValueOnce({ type: "save_vault_result", status: saveStatus })
        .mockResolvedValueOnce({ type: "saved" });
      const chromeApi = {
        runtime: {},
        storage: {
          session: createSessionStorage()
        },
        tabs: {
          query: vi.fn(async () => [{ url: "https://example.com/register" }])
        },
        webAuthenticationProxy: {
          attach: vi.fn(async () => undefined),
          completeCreateRequest,
          onCreateRequest: {
            addListener(listener: (request: unknown) => void) {
              createListener = listener;
            }
          }
        }
      };
      const presencePrompt = installPresencePrompt(chromeApi);

      await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

      createListener?.({
        requestId: 11,
        tabId: 101,
        frameId: 0,
        origin: "https://example.com",
        requestDetailsJson: JSON.stringify({
          rp: { id: "example.com", name: "Example" },
          user: {
            id: "dXNlci0x",
            name: "alice@example.com",
            displayName: "Alice"
          },
          challenge: "cmVnaXN0ZXItMQ",
          pubKeyCredParams: [{ type: "public-key", alg: -7 }]
        })
      });
      await presencePrompt.approve();

      await vi.waitFor(() => {
        expect(completeCreateRequest).toHaveBeenCalledTimes(1);
      });
      expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
        type: "save_passkey_registration",
        vault_id: "vault-1"
      });
      expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
        type: "commit_passkey_registration",
        vault_id: "vault-1",
        entry_id: "entry-1",
        credential_id: "Y3JlZGVudGlhbC0x"
      });
      expect(
        sendRuntimeCommand.mock.calls.some(
          ([command]) =>
            (command as { type?: unknown }).type === "abort_passkey_registration"
        )
      ).toBe(false);
    }
  );

  it("durably commits WebAuthn create registrations before handing them to Chrome", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const events: string[] = [];
    const completeCreateRequest = vi.fn(async () => {
      events.push("chrome:complete_create");
    });
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      events.push(`runtime:${command.type}`);
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      return undefined;
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 1010,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(events).toContain("runtime:commit_passkey_registration");
      expect(events).toContain("chrome:complete_create");
    });
    expect(events.indexOf("runtime:save_passkey_registration")).toBeLessThan(
      events.indexOf("runtime:commit_passkey_registration")
    );
    expect(events.indexOf("runtime:commit_passkey_registration")).toBeLessThan(
      events.indexOf("chrome:complete_create")
    );
  });

  it("does not fetch related-origin metadata for same-origin create requests", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 42,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItc2FtZS1vcmlnaW4",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not fetch related-origin metadata for same-origin get requests", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 43,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLXNhbWUtb3JpZ2luLWdldA",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("does not send a second create completion when delivery confirmation fails after RP delivery", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      if (command.type === "register_passkey_ceremony") {
        return { type: "passkey_ceremony_registered", registered: true };
      }
      if (command.type === "advance_passkey_ceremony_phase") {
        if (command.next_phase === "closed_delivered") {
          return {
            type: "error",
            code: "invalid_request",
            message: "delivery confirmation ledger write failed"
          };
        }
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "mark_passkey_ceremony_unknown_delivery") {
        return { type: "passkey_ceremony_advanced", advanced: true };
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command ${JSON.stringify(command)}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 1011,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation"
      });
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(completeCreateRequest).toHaveBeenCalledTimes(1);
  });

  it("allows WebAuthn create requests with an empty pubKeyCredParams list", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 1012,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: []
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      public_key_algorithm: -7
    });
  });

  it("returns NotSupportedError when WebAuthn create has no supported public key algorithm", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 1013,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -257 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 1013,
      error: {
        name: "NotSupportedError",
        message: "VaultKern passkey registration requires ES256"
      }
    });
  });

  it("advances WebAuthn create requests through the ceremony ledger before registration", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 1011,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(registerCommand).toMatchObject({
      type: "register_passkey_ceremony",
      ceremony_token: expect.any(String),
      ceremony: "create",
      relying_party: "example.com",
      origin: "https://example.com",
      challenge_base64url: "cmVnaXN0ZXItMQ",
      request_id: 1011,
      tab_id: 101,
      frame_id: 0,
      frame_kind: "top"
    });
    const ceremonyToken = registerCommand?.ceremony_token;
    const createCommands = sendRuntimeCommand.mock.calls.map(
      ([command]) => command as { type?: unknown; next_phase?: unknown }
    );
    const bindIndex = createCommands.findIndex(
      (command) => command.type === "bind_passkey_ceremony_vault"
    );
    const s3Index = createCommands.findIndex(
      (command) =>
        command.type === "advance_passkey_ceremony_phase" &&
        command.next_phase === "s3_credential_resolution"
    );
    expect(bindIndex).toBeGreaterThanOrEqual(0);
    expect(bindIndex).toBeLessThan(s3Index);
    expect(createCommands[bindIndex]).toMatchObject({
      type: "bind_passkey_ceremony_vault",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1"
    });
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toMatchObject([
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s0_pre_authorization",
        next_phase: "s1_user_authorization"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s1_user_authorization",
        next_phase: "s3_credential_resolution"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s3_credential_resolution",
        next_phase: "s4_completion_and_mutation"
      },
      {
        ceremony_token: ceremonyToken,
        expected_phase: "s4_completion_and_mutation",
        next_phase: "closed_delivered"
      }
    ]);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "commit_passkey_registration",
      ceremony_token: ceremonyToken,
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1",
      entry_id: "entry-1",
      credential_id: "Y3JlZGVudGlhbC0x"
    });
  });

  it("validates related-origin create requests after user approval before registration", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let resolveFetch: (value: Response) => void = () => {};
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        })
    );
    const completeCreateRequest = vi.fn(async () => undefined);
    const sessionStorage = createSessionStorage();
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      storage: {
        session: sessionStorage
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 11,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItcmVsYXRlZA",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(fetch).toHaveBeenCalledTimes(1);
    });
    resolveFetch({
      ok: true,
      json: vi.fn(async () => ({
        origins: ["https://example.co.uk"]
      }))
    } as unknown as Response);

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.co.uk",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      related_origin_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          expected_phase: "s2_network_validation",
          next_phase: "s3_credential_resolution",
          related_origin_verified: true
        })
      ])
    );
    const mirrorSnapshots = sessionStorage.set.mock.calls
      .map(([items]) => passkeyCeremoniesFromStorageSnapshot(items as Record<string, unknown>))
      .filter(Boolean) as Array<Record<string, Record<string, unknown>>>;
    expect(
      mirrorSnapshots.some((snapshot) =>
        Object.values(snapshot).some(
          (mirror) =>
            mirror.phase === "s3_credential_resolution" &&
            mirror.relatedOriginVerified === true
        )
      )
    ).toBe(true);
  });

  it("canonicalizes requested WebAuthn create RP IDs before registering", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 30,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "Example.COM", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("registers WebAuthn create ceremonies before opening the approval prompt", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const events: string[] = [];
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      events.push(`runtime:${command.type}`);
      const ceremonyResponse = passkeyCeremonyResponse(command);
      if (ceremonyResponse) {
        return ceremonyResponse;
      }
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    presencePrompt.create.mockImplementation(async () => {
      events.push("prompt:create");
      return { id: 77 };
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 236,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    const registerIndex = events.indexOf("runtime:register_passkey_ceremony");
    const s1AdvanceIndex = events.findIndex(
      (event, index) =>
        event === "runtime:advance_passkey_ceremony_phase" &&
        (
          sendRuntimeCommand.mock.calls[index]?.[0] as
            | { next_phase?: unknown }
            | undefined
        )?.next_phase === "s1_user_authorization"
    );
    const promptIndex = events.indexOf("prompt:create");
    expect(registerIndex).toBeGreaterThanOrEqual(0);
    expect(s1AdvanceIndex).toBeGreaterThanOrEqual(0);
    expect(promptIndex).toBeGreaterThanOrEqual(0);
    expect(registerIndex).toBeLessThan(promptIndex);
    expect(s1AdvanceIndex).toBeLessThan(promptIndex);
    expect(events).not.toContain("runtime:create_passkey_registration");

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
  });

  it("omits create credProps results unless the RP requested them", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        created: true,
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 238,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    const response = JSON.parse(completeCreateRequest.mock.calls[0][0].responseJson);
    expect(response.clientExtensionResults).toEqual({});
  });

  it("ignores unknown WebAuthn create extensions without returning extension results", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        created: true,
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 239,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        extensions: {
          prf: { eval: { first: "c2FsdC0x" } },
          largeBlob: { support: "preferred" }
        }
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    const response = JSON.parse(completeCreateRequest.mock.calls[0][0].responseJson);
    expect(response.clientExtensionResults).toEqual({});
  });

  it("fails closed without prompting when native rejects a same-frame concurrent create ceremony", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "passkey_ceremony_reconciliation",
        reconciled: []
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message:
          "passkey ceremony already active for origin, relying party, tab, and frame"
      });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 237,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "Y29uY3VycmVudC1jcmVhdGU",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(2);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "get_session_state"
    });
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 237,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("rejects a Chrome create request that only has a page-observed origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "create",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://top.example"],
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtY3JlYXRl"
      })
    ).toBe(true);

    createListener?.({
      requestId: 28,
      tabId: 101,
      frameId: 0,
      requestDetailsJson: JSON.stringify({
        rp: { id: "observed.example", name: "Observed" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "b2JzZXJ2ZWQtY3JlYXRl",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 28,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("uses the content-script sender origin for Chrome create requests without a direct origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          clientDataJsonBase64url: "client-data",
          transports: ["internal"],
          clientExtensionResults: { credProps: { rk: true } }
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      return undefined;
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest(
        {
          type: "vaultkern_webauthn_page_request",
          ceremony: "create",
          origin: "https://spoofed.example",
          ancestorOrigins: [],
          relyingParty: "localhost",
          challenge: "bG9jYWxob3N0LWNyZWF0ZQ"
        },
        chromeApi,
        {
          url: "http://localhost:8877/",
          tab: { id: 101 },
          frameId: 0
        }
      )
    ).toBe(true);

    createListener?.({
      requestId: 29,
      requestDetailsJson: JSON.stringify({
        rp: { id: "localhost", name: "Localhost" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bG9jYWxob3N0LWNyZWF0ZQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "localhost",
      origin: "http://localhost:8877",
      client_data_json_base64url: expect.any(String)
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 29,
      responseJson: expect.any(String)
    });
  });

  it("waits for a trusted content-script origin observed just after a Chrome create request", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          clientDataJsonBase64url: "client-data"
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      return undefined;
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 31,
      requestDetailsJson: JSON.stringify({
        rp: { id: "localhost", name: "Localhost" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bGF0ZS1vYnNlcnZlZC1jcmVhdGU",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    setTimeout(() => {
      recordWebAuthnPageRequest(
        {
          type: "vaultkern_webauthn_page_request",
          ceremony: "create",
          origin: "https://spoofed.example",
          ancestorOrigins: [],
          relyingParty: "localhost",
          challenge: "bGF0ZS1vYnNlcnZlZC1jcmVhdGU"
        },
        chromeApi,
        {
          url: "http://localhost:8877/",
          tab: { id: 101 },
          frameId: 0
        }
      );
    }, 0);

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 31,
        responseJson: expect.any(String)
      });
    });
  });

  it("derives the default WebAuthn create RP ID from the request origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 15,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("rejects WebAuthn create requests whose RP ID is only a public suffix", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://attacker.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 25,
      tabId: 101,
      frameId: 0,
      origin: "https://attacker.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    if (presencePrompt.create.mock.calls.length > 0) {
      await presencePrompt.approve();
    }

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "create_passkey_registration"
      })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 25,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
    expect(presencePrompt.create).not.toHaveBeenCalled();
  });

  it("rejects non-secure WebAuthn create origins before session lookup or prompts", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 6102,
      tabId: 101,
      frameId: 0,
      origin: "http://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bm9uLXNlY3VyZS1jcmVhdGU",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6102,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
  });

  it("rejects non-origin-shaped WebAuthn create origins before native ledger registration", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      throw new Error("non-origin create must not reach native");
    });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 6106,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com/path",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bm9uLW9yaWdpbi1jcmVhdGU",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_session_state" })
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6106,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("rejects whitespace-padded WebAuthn create origins before native ledger registration", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return { type: "passkey_ceremony_reconciliation", reconciled: [] };
      }
      throw new Error("whitespace-padded create must not reach native");
    });
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 6108,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com ",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "d2hpdGVzcGFjZS1jcmVhdGU",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "register_passkey_ceremony" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_session_state" })
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6108,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it.each(["example.com ", "example.com."])(
    "rejects non-canonical WebAuthn create RP ID %s before native ledger registration",
    async (rpId) => {
      let createListener: ((request: unknown) => void) | undefined;
      const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true
      } as Response);
      const completeCreateRequest = vi.fn(async () => undefined);
      const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
        if (command.type === "reconcile_passkey_ceremony_ledger") {
          return { type: "passkey_ceremony_reconciliation", reconciled: [] };
        }
        throw new Error("non-canonical create RP ID must not reach native");
      });
      const chromeApi = {
        runtime: {},
        windows: {
          create: vi.fn(async () => ({ id: 77 }))
        },
        webAuthenticationProxy: {
          attach: vi.fn(async () => undefined),
          completeCreateRequest,
          onCreateRequest: {
            addListener(listener: (request: unknown) => void) {
              createListener = listener;
            }
          }
        }
      };

      await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
      createListener?.({
        requestId: 6110,
        tabId: 101,
        frameId: 0,
        origin: "https://login.example.com",
        requestDetailsJson: JSON.stringify({
          rp: { id: rpId, name: "Example" },
          user: {
            id: "dXNlci0x",
            name: "alice@example.com",
            displayName: "Alice"
          },
          challenge: "d2hpdGVzcGFjZS1ycC1jcmVhdGU",
          pubKeyCredParams: [{ type: "public-key", alg: -7 }]
        })
      });

      await vi.waitFor(() => {
        expect(completeCreateRequest).toHaveBeenCalledTimes(1);
      });
      expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: "register_passkey_ceremony" })
      );
      expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
        expect.objectContaining({ type: "get_session_state" })
      );
      expect(fetch).not.toHaveBeenCalled();
      expect(chromeApi.windows.create).not.toHaveBeenCalled();
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 6110,
        error: {
          name: "NotAllowedError",
          message: "invalid WebAuthn RP ID"
        }
      });
    }
  );

  it("rejects public-suffix WebAuthn create RP IDs before session lookup or prompts", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      windows: {
        create: vi.fn(async () => ({ id: 77 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    for (const [requestId, origin, rpId] of [
      [6105, "https://attacker.com", "com"],
      [6106, "https://attacker.co.uk", "co.uk"]
    ] as const) {
      createListener?.({
        requestId,
        tabId: 101,
        frameId: 0,
        origin,
        requestDetailsJson: JSON.stringify({
          rp: { id: rpId, name: "Public suffix" },
          user: {
            id: "dXNlci0x",
            name: "alice@example.com",
            displayName: "Alice"
          },
          challenge: `cHVibGljLXN1ZmZpeC1jcmVhdGUt${requestId}`,
          pubKeyCredParams: [{ type: "public-key", alg: -7 }]
        })
      });
    }

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(2);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(fetch).not.toHaveBeenCalled();
    expect(chromeApi.windows.create).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6105,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 6106,
      error: {
        name: "NotAllowedError",
        message: "WebAuthn request origin does not match relying party"
      }
    });
  });

  it("delays unauthorized related-origin create errors without mutation", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false
    } as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 62,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bWlzbWF0Y2gtMg",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "create_passkey_registration"
      })
    );
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 62,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("delays malformed related-origin create documents without mutation", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(async () => ({
        origins: "https://example.co.uk"
      }))
    } as unknown as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 621,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bWlzbWF0Y2gtMw",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "passkey_credential_status" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "save_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "commit_passkey_registration" })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 621,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("times out stalled related-origin create well-known responses without mutation", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: vi.fn(() => new Promise(() => undefined))
    } as unknown as Response);
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    createListener?.({
      requestId: 622,
      tabId: 101,
      frameId: 0,
      origin: "https://example.co.uk",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "bWlzbWF0Y2gtNA",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    expect(fetch).not.toHaveBeenCalled();

    await presencePrompt.approve();

    for (let microtask = 0; microtask < 20; microtask += 1) {
      await Promise.resolve();
    }
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(4_999);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(73);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/.well-known/webauthn",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error"
      })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "passkey_credential_status" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "save_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "commit_passkey_registration" })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 622,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("derives unbracketed IPv6 loopback RP IDs from the request origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 16,
      tabId: 101,
      frameId: 0,
      origin: "http://[::1]:8877",
      requestDetailsJson: JSON.stringify({
        rp: { name: "IPv6 loopback" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "::1",
      origin: "http://[::1]:8877",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("rejects page-observed conditional mediation for WebAuthn create before session lookup", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "create",
        origin: "https://example.com",
        relyingParty: "example.com",
        challenge: "Y29uZGl0aW9uYWwtY3JlYXRl",
        excludeCredentialIds: [],
        mediation: "conditional"
      })
    ).toBe(true);

    createListener?.({
      requestId: 201,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "Y29uZGl0aW9uYWwtY3JlYXRl",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 201,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey provider does not support conditional mediation"
      }
    });
  });

  it("rejects cross-platform-only WebAuthn create requests", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 20,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform"
        }
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 20,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey provider only supports platform authenticators"
      }
    });
  });

  it("rejects WebAuthn create requests that require user verification when native cannot verify the user", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 21,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required"
        }
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "verify_passkey_user" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 21,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("verifies the user before completing required-UV WebAuthn create requests", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "master_password",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const verificationPrompt = installUserVerificationPrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 221,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required"
        }
      })
    });

    await vi.waitFor(() => {
      expect(verificationPrompt.create).toHaveBeenCalledWith({
        url: expect.stringMatching(
          /^chrome-extension:\/\/id\/popup\.html\?webauthn=verify&requestId=221&relyingParty=example\.com&origin=https%3A%2F%2Fexample\.com&nonce=[A-Za-z0-9_-]+$/
        ),
        type: "popup",
        width: 460,
        height: 520,
        focused: true
      });
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const promptUrl = verificationPrompt.latestPromptUrl() ?? "";
    const promptParams = new URL(promptUrl, "chrome-extension://id/").searchParams;
    expect(promptUrl).not.toContain(ceremonyToken);
    expect(promptParams.has("ceremonyToken")).toBe(false);
    expect(promptParams.has("ceremony_token")).toBe(false);
    expect(promptParams.has("vaultId")).toBe(false);
    expect(promptParams.has("vault_id")).toBe(false);

    await expect(
      verificationPrompt.verify({ password: "database-password" })
    ).resolves.toEqual({ ok: true });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "master_password",
      password: "database-password"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "verify_passkey_user"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      public_key_algorithm: -7,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 221,
      responseJson: expect.any(String)
    });
  });

  it("returns TypeError when WebAuthn create user id is longer than 64 bytes", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 232,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: Buffer.alloc(65).toString("base64url"),
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 232,
      error: {
        name: "TypeError",
        message: "WebAuthn user id must be 1 to 64 bytes"
      }
    });
  });

  it("returns TypeError when WebAuthn create user id is empty", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 233,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 233,
      error: {
        name: "TypeError",
        message: "WebAuthn user id must be 1 to 64 bytes"
      }
    });
  });

  it("returns NotAllowedError when WebAuthn create user id is missing", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 234,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 234,
      error: {
        name: "NotAllowedError",
        message: "missing WebAuthn user id"
      }
    });
  });

  it("does not check excludeCredentials before WebAuthn create approval", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "passkey_credential_status") {
        return {
          type: "passkey_credential_status",
          credentialId: "Y3JlZGVudGlhbC0x",
          exists: false
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "bmV3LWNyZWRlbnRpYWw",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 233,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalled();
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "passkey_credential_status" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "passkey_credential_status",
          credential_id: "Y3JlZGVudGlhbC0x",
          relying_party: "example.com"
        })
      );
    });
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "passkey_credential_status",
      vault_id: "vault-1",
      credential_id: "Y3JlZGVudGlhbC0x",
      relying_party: "example.com"
    });
  });

  it("checks WebAuthn create excludeCredentials with one native batch command", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "passkey_credential_status") {
        throw new Error("exclude status lookup must be batched");
      }
      if (command.type === "passkey_credential_status_batch") {
        return {
          type: "passkey_credential_status_batch",
          statuses: [
            { credentialId: "Y3JlZGVudGlhbC0x", exists: false },
            { credentialId: "Y3JlZGVudGlhbC0y", exists: false }
          ]
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "bmV3LWNyZWRlbnRpYWw",
          created: true,
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {
        return { type: "passkey_ceremony_vault_bound", bound: true };
      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 236,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          },
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0y"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "passkey_credential_status" })
    );
    expect(sendRuntimeCommand).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "passkey_credential_status_batch",
        vault_id: "vault-1",
        credential_ids: ["Y3JlZGVudGlhbC0x", "Y3JlZGVudGlhbC0y"],
        relying_party: "example.com"
      })
    );
  });

  it("delays WebAuthn create exclude status errors before completing the request", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey status storage detail"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 235,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "passkey_credential_status",
      vault_id: "vault-1",
      credential_id: "Y3JlZGVudGlhbC0x",
      relying_party: "example.com"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 235,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("returns InvalidStateError when WebAuthn create excludes an existing credential", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_status",
        credentialId: "Y3JlZGVudGlhbC0x",
        exists: true
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 19,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "passkey_credential_status",
      vault_id: "vault-1",
      credential_id: "Y3JlZGVudGlhbC0x",
      relying_party: "example.com"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
      expect.objectContaining({
        ceremony_token: registerCommand?.ceremony_token,
        expected_phase: "s3_credential_resolution",
        next_phase: "closed_failed"
      })
    );
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 19,
      error: {
        name: "InvalidStateError",
        message: "VaultKern passkey credential is already registered"
      }
    });
  });

  it("returns NotAllowedError when an approval popup is dismissed", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    let removedListener: ((windowId: number) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 77 })),
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 41,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
      expect(removedListener).toBeDefined();
    });
    removedListener?.(77);

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
      expect.objectContaining({
        ceremony_token: registerCommand?.ceremony_token,
        expected_phase: "s1_user_authorization",
        next_phase: "closed_aborted"
      })
    );
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(chromeApi.windows.onRemoved.removeListener).toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 41,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("delays WebAuthn create errors when the approval popup is dismissed", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    let removedListener: ((windowId: number) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 78 })),
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 91,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
      expect(removedListener).toBeDefined();
    });
    removedListener?.(78);

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
      expect.objectContaining({
        ceremony_token: registerCommand?.ceremony_token,
        expected_phase: "s1_user_authorization",
        next_phase: "closed_aborted"
      })
    );
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(chromeApi.windows.onRemoved.removeListener).toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 91,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("returns a generic WebAuthn error when saving a new passkey fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "failed to save vault"
      })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 14,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 14,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
  });

  it("does not treat malformed passkey save responses as durable before Chrome delivery", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "unexpected_success" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 142,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "commit_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(75);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 142,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
    expect(completeCreateRequest).not.toHaveBeenCalledWith(
      expect.objectContaining({ responseJson: expect.any(String) })
    );
  });

  it("does not deliver a WebAuthn create response when committing the saved passkey fails", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "failed to commit passkey registration"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 141,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "mark_passkey_ceremony_unknown_delivery" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 141,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
    expect(completeCreateRequest).not.toHaveBeenCalledWith(
      expect.objectContaining({ responseJson: expect.any(String) })
    );
  });

  it("does not treat malformed passkey commit responses as durable before Chrome delivery", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "unexpected_success" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 143,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "mark_passkey_ceremony_unknown_delivery" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(75);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 143,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
    expect(completeCreateRequest).not.toHaveBeenCalledWith(
      expect.objectContaining({ responseJson: expect.any(String) })
    );
  });

  it("delays post-authorization WebAuthn create errors before completing the request", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "failed to save vault"
      })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 140,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 140,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("keeps a committed passkey when completing the WebAuthn create request fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi
      .fn()
      .mockRejectedValueOnce(new Error("Chrome rejected completion"))
      .mockResolvedValueOnce(undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 23,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation"
      });
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "commit_passkey_registration",
      vault_id: "vault-1",
      entry_id: "entry-1",
      credential_id: "Y3JlZGVudGlhbC0x"
    });
  });

  it("keeps a committed replacement when completing the WebAuthn create request fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi
      .fn()
      .mockRejectedValueOnce(new Error("Chrome rejected completion"))
      .mockResolvedValueOnce(undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0y",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x",
        created: false
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 26,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMg",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation"
      });
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "commit_passkey_registration",
      vault_id: "vault-1",
      entry_id: "entry-1",
      credential_id: "Y3JlZGVudGlhbC0y"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "delete_entry" })
    );
  });

  it("aborts a created passkey by token when Chrome cancels before save", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveRegistration: (value: unknown) => void = () => {};
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveRegistration = resolve;
          })
      )
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 24,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();
    await vi.waitFor(() => {
      expectBusinessRuntimeCommandCount(sendRuntimeCommand, 2);
    });
    cancelListener?.(24);
    resolveRegistration({
      type: "passkey_registration",
      entryId: "entry-1",
      credentialId: "Y3JlZGVudGlhbC0x",
      authenticatorDataBase64url: "auth-data",
      attestationObjectBase64url: "attestation-object",
      clientDataJsonBase64url: "client-data",
      publicKeyBase64url: "public-key",
      publicKeyAlgorithm: -7,
      userHandleBase64url: "dXNlci0x"
    });

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "abort_passkey_registration",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation",
        closed_phase: "closed_aborted"
      });
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).not.toHaveBeenCalled();
  });

  it("aborts a saved uncommitted passkey by token when Chrome cancels before commit", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "save_passkey_registration") {
        cancelListener?.(241);
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "save_vault" || command.type === "commit_passkey_registration") {
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 241,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "abort_passkey_registration",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation",
        closed_phase: "closed_aborted"
      });
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "save_vault" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "commit_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();
  });

  it("marks a committed passkey unknown-delivery when Chrome cancels before RP delivery", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_registration") {
        return {
          type: "passkey_registration",
          entryId: "entry-1",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          attestationObjectBase64url: "attestation-object",
          clientDataJsonBase64url: "client-data",
          publicKeyBase64url: "public-key",
          publicKeyAlgorithm: -7,
          userHandleBase64url: "dXNlci0x"
        };
      }
      if (command.type === "save_passkey_registration") {
        return { type: "save_vault_result", status: "saved" };
      }
      if (command.type === "commit_passkey_registration") {
        cancelListener?.(25);
        return { type: "saved" };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 25,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "mark_passkey_ceremony_unknown_delivery",
        ceremony_token: expect.any(String),
        expected_phase: "s4_completion_and_mutation"
      });
    });
    expect(completeCreateRequest).not.toHaveBeenCalled();
  });

  it("delays WebAuthn create errors when passkey registration fails", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "invalid WebAuthn origin"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 16,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await flushMicrotasksUntilRuntimeCommand(
      sendRuntimeCommand,
      (command) => command.type === "abort_passkey_registration"
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 16,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("returns a generic WebAuthn error when runtime returns a malformed registration", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        credentialId: "Y3JlZGVudGlhbC0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 18,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "abort_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      closed_phase: "closed_failed"
    });
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_passkey_registration",
      ceremony_token: expect.any(String),
      expected_phase: "s4_completion_and_mutation",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 18,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("only resumes the locked WebAuthn request that matches the unlock prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 33,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledWith({
        url: expect.stringMatching(
          /^chrome-extension:\/\/id\/popup\.html\?webauthn=unlock&requestId=33&relyingParty=example\.com&origin=https%3A%2F%2Fexample\.com&nonce=[A-Za-z0-9_-]+$/
        ),
        type: "popup",
        width: 460,
        height: 620,
        focused: true
      });
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    expect(unlockPromptUrl).not.toContain(ceremonyToken);
    expect(unlockPromptParams.has("ceremonyToken")).toBe(false);
    expect(unlockPromptParams.has("ceremony_token")).toBe(false);

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 34,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce
      },
      { url: unlockPromptUrl },
      vi.fn()
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 33,
        origin: "https://evil.example",
        relyingParty: "example.com",
        nonce: unlockNonce
      },
      { url: unlockPromptUrl },
      vi.fn()
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 33,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "get_session_state"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("latches early approval messages for the active prompt driver instead of resuming twice", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    let messageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    const sessionStorage = createSessionStorage();
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            messageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async (options: { url?: string }) => {
          const promptUrl = options.url ?? "";
          const promptParams = new URL(
            promptUrl,
            "chrome-extension://id/"
          ).searchParams;
          messageListener?.(
            {
              type: "vaultkern_presence_complete",
              requestId: Number(promptParams.get("requestId")),
              origin: promptParams.get("origin"),
              relyingParty: promptParams.get("relyingParty"),
              nonce: promptParams.get("nonce")
            },
            { url: promptUrl },
            vi.fn()
          );
          return { id: 77 };
        })
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 335,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 2);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "create_passkey_assertion"
    });

    await vi.advanceTimersByTimeAsync(121_000);
    await vi.advanceTimersByTimeAsync(100);

    expect(completeGetRequest).toHaveBeenCalledTimes(1);
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 2);
  });

  it("persists locked WebAuthn unlock prompt state for worker resume", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let sessionStateCalls = 0;
    const sessionStorage = createSessionStorage();
    const completeGetRequest = vi.fn(async () => undefined);
    let resolveWindowCreate:
      | ((value: { id: number } | PromiseLike<{ id: number }>) => void)
      | undefined;
    const windowCreateResult = new Promise<{ id: number }>((resolve) => {
      resolveWindowCreate = resolve;
    });
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        sessionStateCalls += 1;
        return sessionStateCalls === 1
          ? {
              type: "session_state",
              unlocked: false,
              activeVaultId: null
            }
          : {
              type: "session_state",
              unlocked: true,
              activeVaultId: "vault-1"
            };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      storage: {
        session: sessionStorage
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(() => windowCreateResult)
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 334,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const mirrorBeforeWindowCreateResolves = passkeyCeremoniesFromStorageSnapshot(
      sessionStorage.snapshot()
    )?.[ceremonyToken] as Record<string, unknown> | undefined;
    expect(mirrorBeforeWindowCreateResolves).toMatchObject({
      ceremonyToken,
      phase: "s1_user_authorization",
      promptMode: "unlock",
      popupNonce: unlockNonce
    });
    resolveWindowCreate?.({ id: 42 });
    await Promise.resolve();

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 334,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
  });

  it("uses a passkey-triggered master-password unlock as required get user verification", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let sessionStateCalls = 0;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        sessionStateCalls += 1;
        return sessionStateCalls === 1
          ? {
              type: "session_state",
              unlocked: false,
              activeVaultId: null
            }
          : {
              type: "session_state",
              unlocked: true,
              activeVaultId: "vault-1"
            };
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "master_password",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 35,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 35,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce,
        method: "master_password",
        password: "database-password"
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_passkey_user_verification_capability" })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "master_password",
      password: "database-password"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("uses a passkey-triggered quick unlock as required get user verification", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let sessionStateCalls = 0;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        sessionStateCalls += 1;
        return sessionStateCalls === 1
          ? {
              type: "session_state",
              unlocked: false,
              activeVaultId: null
            }
          : {
              type: "session_state",
              unlocked: true,
              activeVaultId: "vault-1"
            };
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "quick_unlock",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 35,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 35,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce,
        method: "quick_unlock"
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_passkey_user_verification_capability" })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "quick_unlock"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 4, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("waits briefly for a passkey unlock proof when session polling observes the unlocked vault first", async () => {
    vi.useFakeTimers();
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let sessionStateCalls = 0;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        sessionStateCalls += 1;
        return sessionStateCalls === 1
          ? {
              type: "session_state",
              unlocked: false,
              activeVaultId: null
            }
          : {
              type: "session_state",
              unlocked: true,
              activeVaultId: "vault-1"
            };
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "quick_unlock",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 35,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;

    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "get_session_state"
      });
    });
    expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 35,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce,
        method: "quick_unlock"
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_passkey_user_verification_capability" })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "quick_unlock"
    });
  });

  it("keeps the active unlock flow authoritative when unlock completes during session polling", async () => {
    vi.useFakeTimers();
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let sessionStateCalls = 0;
    let resolvePolledSession:
      | ((session: {
          type: "session_state";
          unlocked: boolean;
          activeVaultId: string | null;
        }) => void)
      | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        sessionStateCalls += 1;
        if (sessionStateCalls === 1) {
          return {
            type: "session_state",
            unlocked: false,
            activeVaultId: null
          };
        }
        if (sessionStateCalls === 2) {
          return new Promise((resolve) => {
            resolvePolledSession = resolve;
          });
        }
        throw new Error(`unexpected session poll ${sessionStateCalls}`);
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "quick_unlock",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 36,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;

    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => {
      expect(resolvePolledSession).toBeDefined();
    });

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 36,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce,
        method: "quick_unlock"
      },
      { url: unlockPromptUrl },
      vi.fn()
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(sessionStateCalls).toBe(2);
    expect(completeGetRequest).not.toHaveBeenCalled();

    resolvePolledSession?.({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "get_passkey_user_verification_capability" })
    );
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "quick_unlock"
    });
  });

  it("rechecks session state while waiting for an out-of-band vault unlock", async () => {
    vi.useFakeTimers();
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 43,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => {
      expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
        type: "get_session_state"
      });
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    await vi.advanceTimersByTimeAsync(1_500);
    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(2);
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("returns NotAllowedError when an unlock popup is dismissed", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    let removedListener: ((windowId: number) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: false,
      activeVaultId: null
    }));
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 })),
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 45,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
      expect(removedListener).toBeDefined();
    });
    removedListener?.(42);

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.onRemoved.removeListener).toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 45,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("does not miss unlock dismissal while polling the locked session", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    let removedListener: ((windowId: number) => void) | undefined;
    let resolvePoll: (() => void) | undefined;
    let sessionStateRequests = 0;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type !== "get_session_state") {
        throw new Error(`unexpected command: ${command.type}`);
      }
      sessionStateRequests += 1;
      if (sessionStateRequests === 1) {
        return {
          type: "session_state",
          unlocked: false,
          activeVaultId: null
        };
      }
      return new Promise((resolve) => {
        resolvePoll = () =>
          resolve({
            type: "session_state",
            unlocked: false,
            activeVaultId: null
          });
      });
    });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 43 })),
        onRemoved: {
          addListener(listener: (windowId: number) => void) {
            removedListener = listener;
          },
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 46,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
      expect(removedListener).toBeDefined();
    });
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => {
      expect(resolvePoll).toBeDefined();
    });
    removedListener?.(43);
    resolvePoll?.();

    await vi.advanceTimersByTimeAsync(75);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 46,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("closes an unlock popup that is still open when the prompt times out", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: false,
      activeVaultId: null
    }));
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`)
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 44 })),
        remove: vi.fn(async () => undefined),
        onRemoved: {
          addListener: vi.fn(),
          removeListener: vi.fn()
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 47,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    await vi.advanceTimersByTimeAsync(120_100);

    await vi.waitFor(() => {
      expect(chromeApi.windows.remove).toHaveBeenCalledWith(44);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 47,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("does not miss unlock completion sent while opening the prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async (createData: { url?: string }) => {
          const promptUrl = createData.url ?? "";
          const nonce = new URL(promptUrl).searchParams.get("nonce");
          unlockMessageListener?.(
            {
              type: "vaultkern_unlock_complete",
              requestId: 44,
              origin: "https://example.com",
              relyingParty: "example.com",
              nonce
            },
            { url: promptUrl },
            vi.fn()
          );
          return { id: 42 };
        })
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 44,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "get_session_state"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("opens an unlock window and waits for an active vault before creating a passkey", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let resolveInitialSession: (value: unknown) => void = () => {};
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveInitialSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 12,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await vi.waitFor(() => {
      expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    });
    resolveInitialSession({
      type: "session_state",
      unlocked: false,
      activeVaultId: null
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledWith({
      url: expect.stringMatching(
        /^chrome-extension:\/\/id\/popup\.html\?webauthn=unlock&requestId=12&relyingParty=example\.com&origin=https%3A%2F%2Fexample\.com&nonce=[A-Za-z0-9_-]+$/
      ),
      type: "popup",
      width: 460,
      height: 620,
      focused: true
    });
    const unlockPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const unlockPromptParams = new URL(
      unlockPromptUrl,
      "chrome-extension://id/"
    ).searchParams;
    const unlockNonce = unlockPromptParams.get("nonce");
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    expect(unlockPromptUrl).not.toContain(ceremonyToken);
    expect(unlockPromptParams.has("ceremonyToken")).toBe(false);
    expect(unlockPromptParams.has("ceremony_token")).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, 20));
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 12,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: unlockNonce
      },
      { url: unlockPromptUrl },
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "get_session_state"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("reports user-verifying platform authenticator availability as unavailable when native UV capability is unavailable", async () => {
    let isUvpaaListener: ((request: unknown) => void) | undefined;
    const completeIsUvpaaRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: false,
          methods: []
        };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeIsUvpaaRequest,
        onIsUvpaaRequest: {
          addListener(listener: (request: unknown) => void) {
            isUvpaaListener = listener;
          }
        }
      }
    };

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    isUvpaaListener?.({ requestId: 11 });

    await vi.waitFor(() => {
      expect(completeIsUvpaaRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeIsUvpaaRequest).toHaveBeenCalledWith({
      requestId: 11,
      isUvpaa: false
    });
  });

  it("reports user-verifying platform authenticator availability as available when native UV capability is available", async () => {
    let isUvpaaListener: ((request: unknown) => void) | undefined;
    const completeIsUvpaaRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeIsUvpaaRequest,
        onIsUvpaaRequest: {
          addListener(listener: (request: unknown) => void) {
            isUvpaaListener = listener;
          }
        }
      }
    };

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    isUvpaaListener?.({ requestId: 12 });

    await vi.waitFor(() => {
      expect(completeIsUvpaaRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeIsUvpaaRequest).toHaveBeenCalledWith({
      requestId: 12,
      isUvpaa: true
    });
  });

  it("returns a WebAuthn error when no active vault is unlocked", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValue({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 8,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 8,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("delays WebAuthn get errors when the approval popup cannot open", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 88,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 88,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays WebAuthn create errors when the approval popup cannot open", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 89,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 89,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays WebAuthn create errors when the unlock popup cannot open", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 90,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeCreateRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledWith({
        requestId: 90,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("delays WebAuthn get errors when the unlock popup cannot open", async () => {
    vi.useFakeTimers();

    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 91,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    await vi.advanceTimersByTimeAsync(0);
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(74);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledWith({
        requestId: 91,
        error: {
          name: "NotAllowedError",
          message: "VaultKern passkey request failed"
        }
      });
    });
  });

  it("does not accept unlock completion from a popup URL that failed to open", async () => {
    vi.useFakeTimers();

    let createListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let debugLog: unknown[] = [];
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      storage: {
        local: {
          get: vi.fn(async () => ({
            vaultkernWebAuthnDebugEnabled: true,
            vaultkernWebAuthnDebug: debugLog
          })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => {
          throw new Error("popup blocked");
        })
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 91,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    const failedPromptUrl = (chromeApi.windows.create.mock.calls[0][0] as {
      url: string;
    }).url;
    const failedPromptNonce = new URL(failedPromptUrl).searchParams.get("nonce");

    await vi.advanceTimersByTimeAsync(75);
    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });

    debugLog = [];
    chromeApi.storage.local.set.mockClear();
    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 91,
        origin: "https://example.com",
        relyingParty: "example.com",
        nonce: failedPromptNonce
      },
      { url: failedPromptUrl },
      vi.fn()
    );

    for (let microtask = 0; microtask < 10; microtask += 1) {
      await Promise.resolve();
    }
    expect(debugLog).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "unlock_complete_message",
          requestId: 91
        })
      ])
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
  });

  it("rejects WebAuthn get requests that require user verification when native cannot verify the user", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 25,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    expectBusinessRuntimeCommand(sendRuntimeCommand, 1, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "verify_passkey_user" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_assertion" })
    );
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 25,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey request failed"
      }
    });
  });

  it("verifies the user before completing required-UV WebAuthn get requests", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      if (command.type === "verify_passkey_user") {
        return {
          type: "passkey_user_verified",
          verified: true,
          method: "master_password",
          verified_at_epoch_ms: 1_783_000_000_000
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const verificationPrompt = installUserVerificationPrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 225,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(verificationPrompt.create).toHaveBeenCalledWith({
        url: expect.stringMatching(
          /^chrome-extension:\/\/id\/popup\.html\?webauthn=verify&requestId=225&relyingParty=example\.com&origin=https%3A%2F%2Fexample\.com&nonce=[A-Za-z0-9_-]+$/
        ),
        type: "popup",
        width: 460,
        height: 520,
        focused: true
      });
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    const promptUrl = verificationPrompt.latestPromptUrl() ?? "";
    const promptParams = new URL(promptUrl, "chrome-extension://id/").searchParams;
    expect(promptUrl).not.toContain(ceremonyToken);
    expect(promptParams.has("ceremonyToken")).toBe(false);
    expect(promptParams.has("ceremony_token")).toBe(false);
    expect(promptParams.has("vaultId")).toBe(false);
    expect(promptParams.has("vault_id")).toBe(false);

    await expect(
      verificationPrompt.verify({ password: "database-password" })
    ).resolves.toEqual({ ok: true });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "verify_passkey_user",
      ceremony_token: ceremonyToken,
      expected_phase: "s1_user_authorization",
      vault_id: "vault-1",
      method: "master_password",
      password: "database-password"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "verify_passkey_user"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 225,
      responseJson: expect.any(String)
    });
  });

  it("rejects WebAuthn get requests whose origin cannot be identified", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 26,
      tabId: 101,
      frameId: 0,
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 26,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("does not trust page-observed origin when Chrome does not provide one", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://example.com",
        ancestorOrigins: [],
        relyingParty: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentialIds: ["Y3JlZGVudGlhbC0x"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 261,
      tabId: 101,
      frameId: 0,
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommandCount(sendRuntimeCommand, 0);
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 261,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("records Chrome numeric WebAuthn cancellation request ids", async () => {
    let cancelListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(async () => ({
            vaultkernWebAuthnDebugEnabled: true,
            vaultkernWebAuthnDebug: debugLog
          })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };

    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    cancelListener?.(9);

    await vi.waitFor(() => {
      expect(debugLog).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            event: "request_canceled",
            requestId: 9
          })
        ])
      );
    });
  });

  it("does not persist WebAuthn diagnostics unless debug storage is enabled", async () => {
    let cancelListener: ((request: unknown) => void) | undefined;
    const storageSet = vi.fn(async () => undefined);
    const storageGet = vi.fn(async () => ({}));
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: storageGet,
          set: storageSet
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    cancelListener?.(10);
    cancelListener?.(11);
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(storageGet).toHaveBeenCalledTimes(1);
    expect(storageSet).not.toHaveBeenCalled();
  });

  it("does not record allowed credential counts in pre-authorization get diagnostics", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const get = vi.fn(async () => ({
      vaultkernWebAuthnDebugEnabled: true,
      vaultkernWebAuthnDebug: debugLog
    }));
    const set = vi.fn(async (items: Record<string, unknown>) => {
      debugLog = items.vaultkernWebAuthnDebug as unknown[];
    });
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      storage: {
        local: { get, set }
      },
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand: runtimeCommandMock() });

    getListener?.({
      requestId: 9901,
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          { type: "public-key", id: "Y3JlZGVudGlhbC0x" },
          { type: "public-key", id: "Y3JlZGVudGlhbC0y" }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(
        debugLog.some((entry) => (entry as { event?: string }).event === "get_received")
      ).toBe(true);
    });
    const received = debugLog.find(
      (entry) => (entry as { event?: string }).event === "get_received"
    ) as { summary?: Record<string, unknown> };
    expect(received.summary).not.toHaveProperty("allowCredentialsCount");
    expect(JSON.stringify(received)).not.toContain("Y3JlZGVudGlhbC0x");
    expect(JSON.stringify(received)).not.toContain("Y3JlZGVudGlhbC0y");
  });

  it("does not record excluded credential counts in pre-authorization create diagnostics", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const get = vi.fn(async () => ({
      vaultkernWebAuthnDebugEnabled: true,
      vaultkernWebAuthnDebug: debugLog
    }));
    const set = vi.fn(async (items: Record<string, unknown>) => {
      debugLog = items.vaultkernWebAuthnDebug as unknown[];
    });
    const completeCreateRequest = vi.fn(async () => undefined);
    const chromeApi = {
      storage: {
        local: { get, set }
      },
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand: runtimeCommandMock() });

    createListener?.({
      requestId: 9902,
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          { type: "public-key", id: "Y3JlZGVudGlhbC0x" },
          { type: "public-key", id: "Y3JlZGVudGlhbC0y" }
        ]
      })
    });

    await vi.waitFor(() => {
      expect(
        debugLog.some((entry) => (entry as { event?: string }).event === "create_received")
      ).toBe(true);
    });
    const received = debugLog.find(
      (entry) => (entry as { event?: string }).event === "create_received"
    ) as { summary?: Record<string, unknown> };
    expect(received.summary).not.toHaveProperty("excludeCredentialsCount");
    expect(JSON.stringify(received)).not.toContain("Y3JlZGVudGlhbC0x");
    expect(JSON.stringify(received)).not.toContain("Y3JlZGVudGlhbC0y");
  });

  it("redacts ceremony tokens from WebAuthn diagnostics stored in local storage", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(
      async (command: Record<string, unknown>) => {
        if (command.type === "get_session_state") {
          return {
            type: "session_state",
            unlocked: true,
            activeVaultId: "vault-1"
          };
        }
        if (command.type === "create_passkey_assertion") {
          return {
            type: "error",
            code: "invalid_request",
            message: `passkey ceremony not registered: ${command.ceremony_token}`
          };
        }
        return undefined;
      }
    );
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(async () => ({
            vaultkernWebAuthnDebugEnabled: true,
            vaultkernWebAuthnDebug: debugLog
          })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 232,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    await vi.waitFor(() => {
      expect(JSON.stringify(debugLog)).toContain(
        "get_runtime_assertion_candidate_error"
      );
    });
    expect(JSON.stringify(debugLog)).not.toContain(ceremonyToken);
  });

  it("redacts remembered ceremony tokens from existing WebAuthn diagnostics before rewriting local storage", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = runtimeCommandMock(
      async (command: Record<string, unknown>) => {
        if (command.type === "get_session_state") {
          return {
            type: "session_state",
            unlocked: true,
            activeVaultId: "vault-1"
          };
        }
        if (command.type === "create_passkey_assertion") {
          return {
            type: "passkey_assertion",
            credentialId: "Y3JlZGVudGlhbC0x",
            authenticatorDataBase64url: "auth-data",
            clientDataJsonBase64url: "client-data",
            signatureBase64url: "signature",
            userHandleBase64url: null
          };
        }
        return undefined;
      }
    );
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(async () => ({
            vaultkernWebAuthnDebugEnabled: true,
            vaultkernWebAuthnDebug: debugLog
          })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 233,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTI",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const ceremonyToken = (
      sendRuntimeCommand.mock.calls
        .map(([command]) => command as Record<string, unknown>)
        .find((command) => command.type === "register_passkey_ceremony") as {
        ceremony_token: string;
      }
    ).ceremony_token;
    debugLog = [
      {
        event: "previous",
        [ceremonyToken]: `value-${ceremonyToken}`,
        nested: { ceremonyToken }
      }
    ];

    await recordWebAuthnDebug(chromeApi, {
      event: "later",
      message: `later-${ceremonyToken}`
    });

    await vi.waitFor(() => {
      expect(JSON.stringify(debugLog)).toContain("[redacted-ceremony-token]");
    });
    expect(JSON.stringify(debugLog)).not.toContain(ceremonyToken);
  });

  it("redacts ceremony tokens from diagnostics when native registration fails", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    let registeredToken: string | null = null;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn(async (command: Record<string, unknown>) => {
      if (command.type === "reconcile_passkey_ceremony_ledger") {
        return {
          type: "passkey_ceremony_reconciliation",
          reconciled: []
        };
      }
      if (command.type === "register_passkey_ceremony") {
        registeredToken = command.ceremony_token as string;
        return {
          type: "error",
          code: "invalid_request",
          message: `passkey ceremony not registered: ${registeredToken}`
        };
      }
      throw new Error(`unexpected command: ${String(command.type)}`);
    });
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(async () => ({
            vaultkernWebAuthnDebugEnabled: true,
            vaultkernWebAuthnDebug: debugLog
          })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 9903,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLXJlZ2lzdGVyLWZhaWw",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(registeredToken).toEqual(expect.any(String));
    await vi.waitFor(() => {
      expect(JSON.stringify(debugLog)).toContain("[redacted-ceremony-token]");
    });
    expect(JSON.stringify(debugLog)).not.toContain(registeredToken);
  });

  it("does not block UVPAA completion on debug storage writes", async () => {
    let isUvpaaListener: ((request: unknown) => void) | undefined;
    const completeIsUvpaaRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(
            () =>
              new Promise<Record<string, unknown>>(() => {
                // Intentionally never resolves; diagnostics must not block WebAuthn.
              })
          ),
          set: vi.fn(async () => undefined)
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeIsUvpaaRequest,
        onIsUvpaaRequest: {
          addListener(listener: (request: unknown) => void) {
            isUvpaaListener = listener;
          }
        }
      }
    };
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_passkey_user_verification_capability") {
        return {
          type: "passkey_user_verification_capability",
          available: true,
          methods: ["master_password"]
        };
      }
      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    isUvpaaListener?.({ requestId: 21 });

    await vi.waitFor(() => {
      expect(completeIsUvpaaRequest).toHaveBeenCalledWith({
        requestId: 21,
        isUvpaa: true
      });
    });
  });

  it("does not complete a canceled WebAuthn get request", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveSession: (value: unknown) => void = () => {};
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const sendRuntimeCommand = runtimeCommandMock()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand
    });
    expect(cancelListener).toBeDefined();

    getListener?.({
      requestId: 9,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await vi.waitFor(() => {
      expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    });
    cancelListener?.(9);
    resolveSession({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    await vi.waitFor(() => {
      expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
        expect.objectContaining({
          ceremony_token: registerCommand?.ceremony_token,
          expected_phase: "s0_pre_authorization",
          next_phase: "closed_aborted"
        })
      );
    });
    expect(completeGetRequest).not.toHaveBeenCalled();
  });

  it("closes an open presence prompt when Chrome cancels the request", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const remove = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        remove
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    }));

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 72,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(1);
    });
    cancelListener?.(72);

    await vi.waitFor(() => {
      expect(remove).toHaveBeenCalledWith(77);
    });
    const registerCommand = sendRuntimeCommand.mock.calls
      .map(([command]) => command as { type?: unknown; ceremony_token?: string })
      .find((command) => command.type === "register_passkey_ceremony");
    await vi.waitFor(() => {
      expect(passkeyCeremonyAdvanceCommands(sendRuntimeCommand)).toContainEqual(
        expect.objectContaining({
          ceremony_token: registerCommand?.ceremony_token,
          expected_phase: "s1_user_authorization",
          next_phase: "closed_aborted"
        })
      );
    });
  });

  it("closes an open unlock prompt when Chrome cancels the request", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const remove = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        remove
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const prompt = installPresencePrompt(chromeApi);
    const sendRuntimeCommand = runtimeCommandMock(async () => ({
      type: "session_state",
      unlocked: false,
      activeVaultId: null
    }));

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    getListener?.({
      requestId: 73,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(prompt.create).toHaveBeenCalledTimes(1);
    });
    cancelListener?.(73);

    await vi.waitFor(() => {
      expect(remove).toHaveBeenCalledWith(77);
    });
  });

  it("does not treat a later WebAuthn get request with a reused id as canceled", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveFirstSession: (value: unknown) => void = () => {};
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    const sendRuntimeCommand = runtimeCommandMock()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirstSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand
    });

    getListener?.({
      requestId: 9,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await vi.waitFor(() => {
      expectBusinessRuntimeCommandCount(sendRuntimeCommand, 1);
    });
    cancelListener?.(9);
    resolveFirstSession({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(completeGetRequest).not.toHaveBeenCalled();

    getListener?.({
      requestId: 9,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tMg",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 2, {
      type: "get_session_state"
    });
    expectBusinessRuntimeCommand(sendRuntimeCommand, 3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("does not cancel a concurrent WebAuthn get prompt in another tab with the same request id", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    const sendRuntimeCommand = runtimeCommandMock(async (command) => {
      if (command.type === "get_session_state") {
        return {
          type: "session_state",
          unlocked: true,
          activeVaultId: "vault-1"
        };
      }
      if (command.type === "create_passkey_assertion") {
        return {
          type: "passkey_assertion",
          credentialId: "Y3JlZGVudGlhbC0x",
          authenticatorDataBase64url: "auth-data",
          clientDataJsonBase64url: "client-data",
          signatureBase64url: "signature",
          userHandleBase64url: null
        };
      }
      if (command.type === "bind_passkey_ceremony_vault") {

        return { type: "passkey_ceremony_vault_bound", bound: true };

      }

      throw new Error(`unexpected command: ${command.type}`);
    });

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand
    });

    getListener?.({
      requestId: 88,
      tabId: 101,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y29uY3VycmVudC1h",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    getListener?.({
      requestId: 88,
      tabId: 202,
      frameId: 0,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y29uY3VycmVudC1i",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledTimes(2);
    });

    cancelListener?.({ requestId: 88, tabId: 101, frameId: 0 });

    expect(presencePrompt.requestOptions()).toEqual({
      credentialOptions: []
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    const getResponse = JSON.parse(
      (completeGetRequest.mock.calls[0]?.[0] as { responseJson: string }).responseJson
    ) as { response: Record<string, unknown> };
    expect(getResponse).toMatchObject({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: "auth-data",
        clientDataJSON: "client-data",
        signature: "signature"
      }
    });
    expect(getResponse.response).not.toHaveProperty("userHandle");
  });

  it("serializes WebAuthn diagnostics writes without clobbering concurrent entries", async () => {
    let debugLog: unknown[] = [];
    const get = vi.fn(async () => {
      const snapshot = debugLog;
      await new Promise((resolve) => setTimeout(resolve, 0));
      return {
        vaultkernWebAuthnDebugEnabled: true,
        vaultkernWebAuthnDebug: snapshot
      };
    });
    const set = vi.fn(async (items: Record<string, unknown>) => {
      debugLog = items.vaultkernWebAuthnDebug as unknown[];
    });
    const chromeApi = {
      storage: {
        local: {
          get,
          set
        }
      }
    };

    await Promise.all([
      recordWebAuthnDebug(chromeApi, { event: "first" }),
      recordWebAuthnDebug(chromeApi, { event: "second" })
    ]);

    await vi.waitFor(() => {
      expect(debugLog.map((entry) => (entry as { event?: string }).event)).toEqual([
        "first",
        "second"
      ]);
    });
    expect(set).toHaveBeenCalledTimes(2);
  });
});
