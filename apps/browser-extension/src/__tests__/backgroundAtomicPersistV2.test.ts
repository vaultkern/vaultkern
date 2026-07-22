import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type RuntimeMessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void
) => boolean;

const EXTENSION_ID = "vaultkern-atomic-test";
const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const NEXT_TRANSACTION_ID = "00000000-0000-4000-8000-000000000102";
const OPERATION_ID = "00000000-0000-4000-8000-000000000201";
const NEXT_OPERATION_ID = "00000000-0000-4000-8000-000000000202";
const ENTRY_ID = "00000000-0000-4000-8000-000000000501";
const RUNTIME_CAPABILITIES = [
  "runtime-core",
  "browser-extension",
  "browser-autofill",
  "passkey-ceremonies"
];

function fields(password = "new-secret") {
  return {
    title: "Example",
    username: "alice",
    password,
    url: "https://example.com/login",
    notes: "",
    totpUri: null,
    customFields: []
  };
}

function updatePlan(notes = "") {
  return {
    mode: "update" as const,
    entryId: ENTRY_ID,
    expectedFields: { ...fields("old-secret"), notes },
    desiredFields: fields()
  };
}

function sessionStorage() {
  const items: Record<string, unknown> = {};
  return {
    items,
    get: vi.fn(async (key: string | null) =>
      key === null
        ? { ...items }
        : key in items
          ? { [key]: items[key] }
          : {}
    ),
    set: vi.fn(async (updates: Record<string, unknown>) => {
      Object.assign(items, structuredClone(updates));
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        delete items[key];
      }
    }),
    setAccessLevel: vi.fn(async () => undefined)
  };
}

function nativePort() {
  const messageListeners: Array<(message: unknown) => void> = [];
  const posted: unknown[] = [];
  function emit(message: Record<string, unknown>, requestId?: string) {
    const latest = posted.at(-1) as { requestId?: string } | undefined;
    const responseRequestId = requestId ?? latest?.requestId;
    const response = responseRequestId
      ? { ...message, requestId: responseRequestId }
      : message;
    for (const listener of messageListeners) {
      listener(response);
    }
  }

  return {
    posted,
    postMessage: vi.fn((message: unknown) => {
      posted.push(message);
      const command = (message as { command?: { type?: unknown } })?.command;
      if (command?.type === "handshake") {
        const requestId = (message as { requestId?: string }).requestId;
        queueMicrotask(() =>
          emit(
            {
              type: "handshake",
              protocolVersion: 1,
              capabilities: RUNTIME_CAPABILITIES
            },
            requestId
          )
        );
      }
      if (command?.type === "list_recent_vaults") {
        const requestId = (message as { requestId?: string }).requestId;
        queueMicrotask(() =>
          emit({ type: "vault_reference_list", vaults: [] }, requestId)
        );
      }
      if (command?.type === "get_browser_integration_settings") {
        const requestId = (message as { requestId?: string }).requestId;
        queueMicrotask(() =>
          emit(
            {
              type: "browser_integration_settings",
              language: "en",
              clearClipboardSeconds: 30,
              autofillOnPageLoadEnabled: false,
              browserPasskeyProxyEnabled: false
            },
            requestId
          )
        );
      }
    }),
    onMessage: {
      addListener(listener: (message: unknown) => void) {
        messageListeners.push(listener);
      }
    },
    onDisconnect: { addListener: vi.fn() },
    emit
  };
}

function commandCalls(port: ReturnType<typeof nativePort>, type: string) {
  return port.postMessage.mock.calls.filter(([message]) => {
    const command = (message as { command?: { type?: unknown } })?.command;
    return command?.type === type;
  });
}

async function flush() {
  for (let index = 0; index < 80; index += 1) {
    await Promise.resolve();
  }
}

function trustedSender() {
  return {
    id: EXTENSION_ID,
    url: `chrome-extension://${EXTENSION_ID}/popup.html`
  };
}

function trustedContentSender(overrides: Record<string, unknown> = {}) {
  return {
    id: EXTENSION_ID,
    frameId: 0,
    documentId: "document-00000001",
    url: "https://example.com/login",
    tab: { id: 7, url: "https://example.com/login" },
    ...overrides
  };
}

function send(
  listeners: RuntimeMessageListener[],
  message: unknown,
  sender: unknown = trustedSender()
) {
  let resolveResponse: (value: unknown) => void = () => undefined;
  const responsePromise = new Promise<unknown>((resolve) => {
    resolveResponse = resolve;
  });
  const handled = listeners.some((listener) =>
    listener(message, sender, (value) => {
      resolveResponse(value);
    })
  );
  expect(handled).toBe(true);
  return {
    async response() {
      return responsePromise;
    }
  };
}

async function setup(options: {
  session?: ReturnType<typeof sessionStorage>;
  recovery?: Record<string, unknown>;
} = {}) {
  const listeners: RuntimeMessageListener[] = [];
  const session = options.session ?? sessionStorage();
  const port = nativePort();
  const alarms = {
    create: vi.fn(),
    clear: vi.fn(),
    onAlarm: { addListener: vi.fn() }
  };
  if (options.recovery) {
    session.items[
      `vaultkernPendingAutofillRecovery:${options.recovery.transactionId}`
    ] = options.recovery;
  }
  (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
    runtime: {
      id: EXTENSION_ID,
      getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path}`,
      connectNative: vi.fn(() => port),
      onMessage: {
        addListener(listener: RuntimeMessageListener) {
          listeners.push(listener);
        }
      }
    },
    storage: { session },
    tabs: {
      get: vi.fn(async (tabId: number) => ({
        id: tabId,
        url: "https://example.com/login"
      })),
      query: vi.fn(async () => [{ id: 7, url: "https://example.com/login" }])
    },
    alarms
  };
  await import("../background");
  await flush();
  return { listeners, port, session, alarms };
}

async function captureAndPlan(
  listeners: RuntimeMessageListener[],
  plan = updatePlan()
) {
  await expect(
    send(
      listeners,
      {
        type: "vaultkern_autofill_submission",
        url: "https://example.com/login",
        username: "alice",
        password: "old-secret",
        newPassword: "new-secret",
        submittedAt: Date.now()
      },
      trustedContentSender()
    ).response()
  ).resolves.toEqual({ ok: true });
  const captured = (await send(listeners, {
    type: "vaultkern_autofill_pending_request",
    tabId: 7
  }).response()) as { pending: { transactionId: string } };
  const transactionId = captured.pending.transactionId;
  const planned = await send(listeners, {
    type: "vaultkern_autofill_pending_plan",
    tabId: 7,
    transactionId,
    vaultId: "vault-1",
    plan
  }).response();
  return { transactionId, planned };
}

function durable(transactionId: string, operationId: string) {
  return {
    type: "autofill_persist_result",
    transactionId,
    operationId,
    vaultId: "vault-1",
    outcome: "durable",
    disposition: "committed",
    entryId: ENTRY_ID,
    durability: "source",
    cacheState: "current",
    committedFingerprint: {
      contentSha256: "a".repeat(64),
      sizeBytes: 42
    },
    mergeSummary: null,
    receiptVersion: 1
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.resetModules();
});

beforeEach(() => {
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

describe("background atomic pending autofill V2", () => {
  it("rejects generic native commands from an HTTP content-script sender", async () => {
    const { listeners, port } = await setup();
    const handled = listeners.some((listener) =>
      listener(
        {
          version: 1,
          command: { type: "get_session_state" }
        },
        trustedContentSender(),
        () => undefined
      )
    );

    expect(handled).toBe(false);
    await flush();
    expect(commandCalls(port, "get_session_state")).toHaveLength(0);
  });

  it("allows generic native commands from the popup extension page", async () => {
    const { listeners, port } = await setup();
    const request = send(
      listeners,
      {
        version: 1,
        command: { type: "get_session_state" }
      },
      trustedSender()
    );
    await vi.waitFor(() =>
      expect(commandCalls(port, "get_session_state")).toHaveLength(1)
    );
    port.emit({ type: "session_state", unlocked: false });

    await expect(request.response()).resolves.toMatchObject({
      type: "session_state",
      unlocked: false
    });
  });

  it.each([
    ["missing runtime ID", { id: undefined }],
    ["wrong runtime ID", { id: "another-extension" }],
    ["missing frame ID", { frameId: undefined }],
    ["child frame", { frameId: 3 }],
    ["different sender URL", { url: "https://example.com/other" }],
    [
      "unproven cross-origin tab navigation",
      {
        documentId: undefined,
        tab: { id: 7, url: "https://other.example/landing" }
      }
    ]
  ])("rejects a %s submission before writing the secret WAL", async (_case, overrides) => {
    const { listeners, session } = await setup();

    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://example.com/login",
          username: "alice",
          password: "secret",
          submittedAt: Date.now()
        },
        trustedContentSender(overrides)
      ).response()
    ).resolves.toEqual({ ok: false });
    expect(session.items).toEqual({});
  });

  it("rejects a canonical-equivalent but nonidentical sender URL", async () => {
    const { listeners, session } = await setup();

    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://EXAMPLE.com:443/path/../login",
          username: "alice",
          password: "secret",
          submittedAt: Date.now()
        },
        trustedContentSender()
      ).response()
    ).resolves.toEqual({ ok: false });
    expect(session.items).toEqual({});
  });

  it("accepts a same-document submission after a canonical same-origin URL change", async () => {
    const { listeners, session } = await setup();

    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://example.com/login",
          username: "alice",
          password: "secret",
          submittedAt: Date.now()
        },
        trustedContentSender({
          url: "https://example.com/welcome",
          tab: { id: 7, url: "https://example.com/welcome" }
        })
      ).response()
    ).resolves.toEqual({ ok: true });
    expect(session.items["vaultkernPendingAutofillTransaction:7"]).toBeDefined();
  });

  it("accepts a document-bound top-frame submission during a navigation race", async () => {
    const { listeners, session } = await setup();

    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://example.com/login",
          username: "alice",
          password: "secret",
          submittedAt: Date.now()
        },
        trustedContentSender({
          tab: { id: 7, url: "https://other.example/landing" }
        })
      ).response()
    ).resolves.toEqual({ ok: true });
    expect(session.items["vaultkernPendingAutofillTransaction:7"]).toBeDefined();
  });

  it("durably plans without accepting a popup-owned operation ID", async () => {
    const { listeners, port, session } = await setup();
    const { transactionId, planned } = await captureAndPlan(listeners);

    expect(planned).toMatchObject({
      ok: true,
      pending: {
        version: 2,
        state: "planned",
        transactionId,
        operationId: expect.any(String),
        vaultId: "vault-1",
        plan: updatePlan()
      }
    });
    const wal = session.items["vaultkernPendingAutofillTransaction:7"];
    expect(wal).toMatchObject({ state: "planned", plan: updatePlan() });
    expect(wal).not.toHaveProperty("password");
    expect(wal).not.toHaveProperty("newPassword");
    expect(wal).not.toHaveProperty("username");
    expect(wal).not.toHaveProperty("submission");

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_execute",
        tabId: 7,
        transactionId,
        operationId: "00000000-0000-4000-8000-000000000999"
      }).response()
    ).resolves.toMatchObject({ ok: false });
    expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(0);
  });

  it("gives background ownership of a confirmed plan without a second execute message", async () => {
    const { listeners, port, session, alarms } = await setup();
    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://example.com/login",
          username: "alice",
          password: "old-secret",
          newPassword: "new-secret",
          submittedAt: Date.now()
        },
        trustedContentSender()
      ).response()
    ).resolves.toEqual({ ok: true });
    const captured = (await send(listeners, {
      type: "vaultkern_autofill_pending_request",
      tabId: 7
    }).response()) as { pending: { transactionId: string } };

    const confirmation = send(listeners, {
      type: "vaultkern_autofill_pending_confirm",
      tabId: 7,
      transactionId: captured.pending.transactionId,
      vaultId: "vault-1",
      plan: updatePlan()
    });

    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    const persistedCommand = commandCalls(port, "persist_autofill_mutation")[0]![0] as {
      command: { operation_id: string };
    };
    expect(session.items["vaultkernPendingAutofillTransaction:7"]).toMatchObject({
      state: "persisting"
    });
    expect(alarms.create).toHaveBeenCalledWith(
      "vaultkern-autofill-pending:tab:7",
      expect.objectContaining({ when: expect.any(Number) })
    );
    port.emit(
      durable(
        captured.pending.transactionId,
        persistedCommand.command.operation_id
      )
    );

    await expect(confirmation.response()).resolves.toMatchObject({ ok: true });
  });

  it("uses exactly one atomic command for attached durable persistence", async () => {
    const { listeners, port, session } = await setup();
    const { transactionId, planned } = await captureAndPlan(listeners);
    const operationId = (planned as { pending: { operationId: string } }).pending
      .operationId;

    const execution = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId
    });
    await vi.waitFor(() => {
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1);
    });
    expect(commandCalls(port, "persist_autofill_mutation")[0]![0]).toMatchObject({
      command: {
        type: "persist_autofill_mutation",
        transaction_id: transactionId,
        operation_id: operationId,
        vault_id: "vault-1"
      }
    });
    port.emit(durable(transactionId, operationId));

    await expect(execution.response()).resolves.toMatchObject({
      ok: true,
      pending: { state: "persisted", operationId }
    });
    for (const forbidden of [
      "get_entry_detail",
      "compare_and_update_entry_fields",
      "create_entry_if_matching_entry_ids",
      "save_vault"
    ]) {
      expect(commandCalls(port, forbidden)).toHaveLength(0);
    }
    expect(
      session.items["vaultkernPendingAutofillTransaction:7"]
    ).toBeUndefined();
    expect(JSON.stringify(session.items)).not.toContain("new-secret");
  });

  it("records a definitive conflict and only replans after a changed plan", async () => {
    const { listeners, port } = await setup();
    const { transactionId, planned } = await captureAndPlan(listeners);
    const operationId = (planned as { pending: { operationId: string } }).pending
      .operationId;
    const execution = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId
    });
    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    port.emit({
      type: "autofill_persist_result",
      transactionId,
      operationId,
      vaultId: "vault-1",
      outcome: "conflict",
      code: "update_precondition_failed",
      retryable: false
    });
    await expect(execution.response()).resolves.toMatchObject({
      ok: false,
      conflict: true,
      pending: { state: "persist_conflict", operationId }
    });

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_plan",
        tabId: 7,
        transactionId,
        vaultId: "vault-1",
        plan: updatePlan()
      }).response()
    ).resolves.toMatchObject({ ok: false });
    const changed = await send(listeners, {
      type: "vaultkern_autofill_pending_plan",
      tabId: 7,
      transactionId,
      vaultId: "vault-1",
      plan: updatePlan("changed elsewhere")
    }).response();
    expect(changed).toMatchObject({
      ok: true,
      pending: { state: "planned", operationId: expect.not.stringMatching(operationId) }
    });
  });

  it("keeps transient failure on the same operation and replays identical bytes", async () => {
    const { listeners, port } = await setup();
    const { transactionId, planned } = await captureAndPlan(listeners);
    const operationId = (planned as { pending: { operationId: string } }).pending
      .operationId;
    const first = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId
    });
    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    const firstCommand = structuredClone(
      (commandCalls(port, "persist_autofill_mutation")[0]![0] as {
        command: unknown;
      }).command
    );
    port.emit({ type: "error", code: "vault_locked", message: "locked" });
    await expect(first.response()).resolves.toMatchObject({
      ok: false,
      pending: { state: "persisting", operationId }
    });

    const retry = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId
    });
    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(2)
    );
    expect(
      (commandCalls(port, "persist_autofill_mutation")[1]![0] as {
        command: unknown;
      }).command
    ).toEqual(firstCommand);
    port.emit(durable(transactionId, operationId));
    await expect(retry.response()).resolves.toMatchObject({ ok: true });
  });

  it("replays an attached persisting operation after service-worker restart", async () => {
    const now = Date.now();
    const session = sessionStorage();
    session.items["vaultkernPendingAutofillTransaction:7"] = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "persisting",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan(),
      attemptId: "00000000-0000-4000-8000-000000000301",
      attemptCount: 1,
      lastAttemptAt: now - 100,
      leaseExpiresAt: now + 30_000
    };

    const { port } = await setup({ session });

    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    expect(commandCalls(port, "persist_autofill_mutation")[0]![0]).toMatchObject({
      command: {
        transaction_id: TRANSACTION_ID,
        operation_id: OPERATION_ID
      }
    });
  });

  it("replays an attached persisting operation after unlock", async () => {
    const now = Date.now();
    const session = sessionStorage();
    const { listeners, port } = await setup({ session });
    session.items["vaultkernPendingAutofillTransaction:7"] = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "persisting",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan()
    };

    const unlock = send(listeners, {
      version: 1,
      command: { type: "get_session_state" }
    });
    await vi.waitFor(() =>
      expect(commandCalls(port, "get_session_state")).toHaveLength(1)
    );
    port.emit({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });
    await expect(unlock.response()).resolves.toMatchObject({
      type: "session_state",
      unlocked: true
    });

    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
  });

  it("runs detached recovery through the same one-command executor", async () => {
    const now = Date.now();
    const recovery = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "planned",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan()
    };
    const { port, session, alarms } = await setup({ recovery });

    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    expect(alarms.create).toHaveBeenCalledWith(
      `vaultkern-autofill-pending:recovery:${TRANSACTION_ID}`,
      { when: recovery.recoveryDeadlineAt }
    );
    port.emit(durable(TRANSACTION_ID, OPERATION_ID));
    await vi.waitFor(() => {
      expect(
        session.items[`vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`]
      ).toBeUndefined();
    });
    expect(commandCalls(port, "save_vault")).toHaveLength(0);
    expect(commandCalls(port, "get_session_state")).toHaveLength(0);
  });

  it("serializes the same operation across attached and detached recovery", async () => {
    const now = Date.now();
    const transaction = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "planned",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan()
    };
    const session = sessionStorage();
    session.items["vaultkernPendingAutofillTransaction:7"] = transaction;
    const { listeners, port } = await setup({
      session,
      recovery: transaction
    });

    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    const duplicate = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId: TRANSACTION_ID
    });
    await flush();

    expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1);
    await expect(duplicate.response()).resolves.toMatchObject({
      ok: false,
      busy: true
    });
  });

  it("reschedules the deadline sweep for an active claim lease", async () => {
    vi.useFakeTimers();
    const now = 1_710_000_000_000;
    vi.setSystemTime(now);
    const recovery = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "planned",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 10_000,
      plan: updatePlan()
    };
    const { session, alarms } = await setup({ recovery });
    const recoveryKey = `vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`;
    const claimed = session.items[recoveryKey] as { leaseExpiresAt: number };
    const alarmName = `vaultkern-autofill-pending:recovery:${TRANSACTION_ID}`;
    const alarmListener = alarms.onAlarm.addListener.mock.calls[0]![0] as (
      alarm: { name: string }
    ) => void;
    alarms.create.mockClear();

    vi.setSystemTime(recovery.recoveryDeadlineAt + 1);
    alarmListener({ name: alarmName });
    await flush();

    expect(alarms.create).toHaveBeenCalledWith(alarmName, {
      when: claimed.leaseExpiresAt
    });
    expect(session.items[recoveryKey]).toBeDefined();
  });

  it("does not auto-retry a detached retryable conflict and replays it explicitly", async () => {
    const now = Date.now();
    const recovery = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "persist_conflict",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan(),
      conflict: { code: "active_vault_mismatch", retryable: true }
    };
    const { listeners, port } = await setup({ recovery });

    expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(0);
    const retry = send(listeners, {
      type: "vaultkern_autofill_pending_execute",
      tabId: 7,
      transactionId: TRANSACTION_ID
    });
    await vi.waitFor(() =>
      expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(1)
    );
    expect(commandCalls(port, "persist_autofill_mutation")[0]![0]).toMatchObject({
      command: {
        transaction_id: TRANSACTION_ID,
        operation_id: OPERATION_ID
      }
    });
    port.emit(durable(TRANSACTION_ID, OPERATION_ID));
    await expect(retry.response()).resolves.toMatchObject({ ok: true });
  });

  it("replans and discards detached definitive conflicts through the popup route", async () => {
    const now = Date.now();
    const recovery = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "persist_conflict",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 1_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 14 * 60 * 1_000,
      plan: updatePlan(),
      conflict: { code: "update_precondition_failed", retryable: false }
    };
    const { listeners, port, session } = await setup({ recovery });

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 9
      }).response()
    ).resolves.toMatchObject({
      ok: true,
      recovery: true,
      pending: { transactionId: TRANSACTION_ID, tabId: 7 }
    });
    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 7
      }).response()
    ).resolves.toMatchObject({
      ok: true,
      pending: {
        transactionId: TRANSACTION_ID,
        state: "persist_conflict"
      }
    });

    const replanned = await send(listeners, {
      type: "vaultkern_autofill_pending_plan",
      tabId: 7,
      transactionId: TRANSACTION_ID,
      vaultId: "vault-1",
      plan: updatePlan("changed elsewhere")
    }).response();
    expect(replanned).toMatchObject({
      ok: true,
      pending: {
        state: "planned",
        operationId: expect.not.stringMatching(OPERATION_ID),
        recoveryDeadlineAt: recovery.recoveryDeadlineAt
      }
    });
    expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(0);

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_clear",
        state: "dismissed",
        tabId: 7,
        transactionId: TRANSACTION_ID
      }).response()
    ).resolves.toMatchObject({ ok: true });
    expect(
      session.items[`vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`]
    ).toBeUndefined();
  });

  it("discovers multiple detached conflicts in a stable actionable order", async () => {
    const now = Date.now();
    const first = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "persist_conflict",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: now - 2_000,
      vaultId: "vault-1",
      recoveryDeadlineAt: now + 13 * 60 * 1_000,
      plan: updatePlan(),
      conflict: { code: "update_precondition_failed", retryable: false }
    };
    const second = {
      ...first,
      transactionId: NEXT_TRANSACTION_ID,
      operationId: NEXT_OPERATION_ID,
      tabId: 8,
      submittedAt: now - 1_000,
      recoveryDeadlineAt: now + 14 * 60 * 1_000
    };
    const session = sessionStorage();
    session.items[
      `vaultkernPendingAutofillRecovery:${NEXT_TRANSACTION_ID}`
    ] = second;
    const { listeners } = await setup({ session, recovery: first });

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 9
      }).response()
    ).resolves.toMatchObject({
      ok: true,
      recovery: true,
      pending: { transactionId: TRANSACTION_ID, tabId: 7 }
    });

    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_clear",
        state: "dismissed",
        tabId: 7,
        transactionId: TRANSACTION_ID
      }).response()
    ).resolves.toMatchObject({ ok: true });
    await expect(
      send(listeners, {
        type: "vaultkern_autofill_pending_request",
        tabId: 9
      }).response()
    ).resolves.toMatchObject({
      ok: true,
      recovery: true,
      pending: { transactionId: NEXT_TRANSACTION_ID, tabId: 8 }
    });
  });

  it("does not plan or call native when trusted session storage is unavailable", async () => {
    const session = sessionStorage();
    session.setAccessLevel.mockRejectedValue(new Error("denied"));
    const { listeners, port } = await setup({ session });

    await expect(
      send(
        listeners,
        {
          type: "vaultkern_autofill_submission",
          url: "https://example.com/login",
          username: "alice",
          password: "old-secret",
          submittedAt: Date.now()
        },
        trustedContentSender()
      ).response()
    ).resolves.toEqual({ ok: false });
    expect(commandCalls(port, "persist_autofill_mutation")).toHaveLength(0);
  });
});
