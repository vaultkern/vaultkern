import { describe, expect, it, vi } from "vitest";

import {
  createPendingAutofillSubmissionStore,
  pendingAutofillTransactionStorageKey
} from "../pendingSubmissionStore";
import type { PendingAutofillDesiredFields } from "../pendingSubmission";

const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const OPERATION_ID = "00000000-0000-4000-8000-000000000201";
const NEXT_OPERATION_ID = "00000000-0000-4000-8000-000000000202";
const PLANNED_ENTRY_ID = "00000000-0000-4000-8000-000000000301";
const ATTEMPT_ID = "00000000-0000-4000-8000-000000000401";
const NEXT_ATTEMPT_ID = "00000000-0000-4000-8000-000000000402";
const ENTRY_ID = "00000000-0000-4000-8000-000000000501";
const GROUP_ID = "00000000-0000-4000-8000-000000000601";
const MATCH_A = "00000000-0000-4000-8000-000000000701";
const MATCH_B = "00000000-0000-4000-8000-000000000702";
const MATCH_OTHER = "00000000-0000-4000-8000-000000000703";
const RECOVERY_MS = 15 * 60 * 1_000;
const MAX_FIELD_BYTES = 1_048_576;
const MAX_TOTP_URI_BYTES = 8 * 1_024;
const MAX_VAULT_ID_BYTES = 4 * 1_024;
const MAX_WAL_BYTES = 4 * 1_024 * 1_024;

function fields(password = "new-secret"): PendingAutofillDesiredFields {
  return {
    title: "Example",
    username: "alice",
    password,
    url: "https://example.com/login",
    notes: "",
    totpUri: null,
    customFields: [] as Array<{
      key: string;
      value: string;
      protected: boolean;
    }>
  };
}

function updatePlan() {
  return {
    mode: "update" as const,
    entryId: ENTRY_ID,
    expectedFields: fields("old-secret"),
    desiredFields: fields()
  };
}

function createPlan(expectedMatchingEntryIds = [MATCH_B, MATCH_A]) {
  return {
    mode: "create" as const,
    parentGroupId: GROUP_ID,
    expectedMatchingEntryIds,
    desiredFields: fields()
  };
}

function sessionStorage(initial: Record<string, unknown> = {}) {
  const items = { ...initial };
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

function idSequence(ids: string[]) {
  const remaining = [...ids];
  return vi.fn(() => remaining.shift() ?? "");
}

async function capturedStore(options: {
  now?: number;
  ids?: string[];
  storage?: ReturnType<typeof sessionStorage>;
}) {
  const currentTime = options.now ?? 1_710_000_000_000;
  const storage = options.storage ?? sessionStorage();
  const createId = idSequence(options.ids ?? [TRANSACTION_ID]);
  const store = createPendingAutofillSubmissionStore(
    { storage: { session: storage } },
    () => currentTime,
    createId
  );
  const captured = await store.putCaptured(7, {
    url: "https://example.com/login",
    username: "alice",
    password: "old-secret",
    newPassword: "new-secret",
    submittedAt: currentTime
  });
  return { currentTime, storage, createId, store, captured: captured! };
}

describe("pending autofill V2 store", () => {
  it("keeps raw submission secrets only while captured", async () => {
    const { captured } = await capturedStore({
      ids: [TRANSACTION_ID]
    });

    expect(captured).toEqual({
      version: 2,
      transactionId: TRANSACTION_ID,
      state: "captured",
      tabId: 7,
      origin: "https://example.com",
      expiresAt: captured.expiresAt,
      submission: {
        url: "https://example.com/login",
        username: "alice",
        password: "old-secret",
        newPassword: "new-secret",
        submittedAt: captured.submission.submittedAt
      }
    });
    expect(captured).not.toHaveProperty("username");
    expect(captured).not.toHaveProperty("password");
    expect(captured).not.toHaveProperty("newPassword");
  });

  it("keeps a captured transaction until its nested submission deadline", async () => {
    const { store, captured } = await capturedStore({
      ids: [TRANSACTION_ID]
    });

    await store.clearExpired();

    await expect(store.loadForTab(7)).resolves.toEqual(captured);
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toBeNull();
  });

  it("durably writes the complete create plan before it can be claimed", async () => {
    const { currentTime, storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID, ATTEMPT_ID]
    });
    storage.set.mockClear();

    const planned = await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: createPlan()
    });

    expect(planned).toMatchObject({
      version: 2,
      state: "planned",
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      recoveryDeadlineAt: currentTime + RECOVERY_MS,
      plan: {
        mode: "create",
        plannedEntryId: PLANNED_ENTRY_ID,
        expectedMatchingEntryIds: [MATCH_A, MATCH_B]
      }
    });
    expect(storage.set).toHaveBeenCalledTimes(1);
    expect(storage.set).toHaveBeenCalledWith({
      [pendingAutofillTransactionStorageKey(7)]: planned
    });
    expect(planned).not.toHaveProperty("submission");
    expect(planned).not.toHaveProperty("username");
    expect(planned).not.toHaveProperty("password");
    expect(planned).not.toHaveProperty("newPassword");

    await expect(
      store.claimForTab(7, TRANSACTION_ID)
    ).resolves.toMatchObject({
      state: "persisting",
      operationId: OPERATION_ID,
      attemptId: ATTEMPT_ID,
      attemptCount: 1
    });
  });

  it("rejects a complete update WAL that exceeds the transaction budget", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID]
    });
    const oversized = updatePlan();
    oversized.expectedFields.notes = "e".repeat(MAX_FIELD_BYTES);
    oversized.desiredFields.notes = "d".repeat(MAX_FIELD_BYTES);
    for (let index = 0; index < 3; index += 1) {
      oversized.desiredFields.customFields.push({
        key: `field-${index}`,
        value: "v".repeat(MAX_FIELD_BYTES),
        protected: true
      });
    }
    expect(JSON.stringify(oversized).length).toBeGreaterThan(MAX_WAL_BYTES);
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: oversized
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it("does not dismiss a persisting operation with an unknown outcome", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    const persisting = await store.claimForTab(7, captured.transactionId);
    storage.set.mockClear();

    await expect(
      store.dismissForTab(7, captured.transactionId)
    ).resolves.toBeNull();
    await expect(store.loadForTab(7)).resolves.toEqual(persisting);
    expect(storage.set).not.toHaveBeenCalled();
  });

  it("never plans or claims when trusted session storage cannot be enforced", async () => {
    const storage = sessionStorage();
    const createId = idSequence([TRANSACTION_ID, OPERATION_ID]);
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      createId
    );
    storage.setAccessLevel.mockRejectedValue(new Error("denied"));

    await expect(
      store.putCaptured(7, {
        url: "https://example.com/login",
        username: "alice",
        password: "secret",
        submittedAt: 1_710_000_000_000
      })
    ).resolves.toBeNull();
    await expect(
      store.plan(7, TRANSACTION_ID, {
        vaultId: "vault-1",
        plan: updatePlan()
      })
    ).resolves.toBeNull();
    await expect(store.claimForTab(7, TRANSACTION_ID)).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it.each([
    ["update entry", { ...updatePlan(), entryId: "entry-1" }],
    ["nil update entry", { ...updatePlan(), entryId: "00000000-0000-0000-0000-000000000000" }],
    ["create group", { ...createPlan(), parentGroupId: "group-root" }],
    ["create baseline", createPlan(["entry-invalid"])]
  ])("rejects a noncanonical %s UUID before durable planning", async (_case, plan) => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, { vaultId: "vault-1", plan })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
    await expect(store.loadForTab(7)).resolves.toMatchObject({
      state: "captured"
    });
  });

  it.each(["url", "username", "password", "newPassword"] as const)(
    "rejects an oversized captured %s before writing the secret WAL",
    async (field) => {
      const storage = sessionStorage();
      const store = createPendingAutofillSubmissionStore(
        { storage: { session: storage } },
        () => 1_710_000_000_000,
        idSequence([TRANSACTION_ID])
      );
      const oversized = "a".repeat(MAX_FIELD_BYTES + 1);
      const submission = {
        url: "https://example.com/login",
        username: "alice",
        password: "secret",
        newPassword: "new-secret",
        submittedAt: 1_710_000_000_000,
        [field]: field === "url" ? `https://example.com/${oversized}` : oversized
      };

      await expect(store.putCaptured(7, submission)).resolves.toBeNull();
      expect(storage.set).not.toHaveBeenCalled();
    }
  );

  it("counts captured field limits in UTF-8 bytes", async () => {
    const storage = sessionStorage();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([TRANSACTION_ID])
    );

    await expect(
      store.putCaptured(7, {
        url: "https://example.com/login",
        username: "alice",
        password: "\u00e9".repeat(MAX_FIELD_BYTES / 2 + 1),
        submittedAt: 1_710_000_000_000
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it("rejects ill-formed UTF-16 before writing the secret WAL", async () => {
    const storage = sessionStorage();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([TRANSACTION_ID])
    );

    await expect(
      store.putCaptured(7, {
        url: "https://example.com/login",
        username: "alice",
        password: "secret\ud800",
        submittedAt: 1_710_000_000_000
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it("rejects an ill-formed UTF-16 plan before durable planning", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: {
          ...createPlan(),
          desiredFields: { ...fields(), notes: "invalid\udc00" }
        }
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it.each([
    [
      "standard field",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          notes: "a".repeat(MAX_FIELD_BYTES + 1)
        }
      })
    ],
    [
      "UTF-8 standard field",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          notes: "\u00e9".repeat(MAX_FIELD_BYTES / 2 + 1)
        }
      })
    ],
    [
      "TOTP URI",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          totpUri: "a".repeat(MAX_TOTP_URI_BYTES + 1)
        }
      })
    ],
    [
      "custom field count",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          customFields: Array.from({ length: 129 }, (_, index) => ({
            key: `key-${index}`,
            value: "value",
            protected: false
          }))
        }
      })
    ],
    [
      "UTF-8 custom key",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          customFields: [
            {
              key: "\u00e9".repeat(129),
              value: "value",
              protected: false
            }
          ]
        }
      })
    ],
    [
      "aggregate field bytes",
      () => ({
        ...createPlan(),
        desiredFields: {
          ...fields(),
          customFields: Array.from({ length: 8 }, (_, index) => ({
            key: `key-${index}`,
            value: "a".repeat(MAX_FIELD_BYTES),
            protected: false
          }))
        }
      })
    ]
  ] as const)("rejects an oversized plan %s before durable planning", async (_case, makePlan) => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: makePlan()
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it.each([
    ["empty", [{ key: "", value: "value", protected: false }]],
    ["whitespace-padded", [{ key: " Tenant", value: "value", protected: false }]],
    ["control-character", [{ key: "Ten\u0000ant", value: "value", protected: false }]],
    ["Unicode control-character", [{ key: "Ten\u0085ant", value: "value", protected: false }]],
    ["XML-forbidden", [{ key: "Ten\ufffeant", value: "value", protected: false }]],
    ["reserved", [{ key: "pAsSwOrD", value: "value", protected: false }]],
    [
      "duplicate",
      [
        { key: "Tenant", value: "one", protected: false },
        { key: "Tenant", value: "two", protected: true }
      ]
    ]
  ] as const)(
    "rejects an invalid %s custom-field key before durable planning",
    async (_case, customFields) => {
      const { storage, store, captured } = await capturedStore({
        ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
      });
      storage.set.mockClear();

      await expect(
        store.plan(7, captured.transactionId, {
          vaultId: "vault-1",
          plan: {
            ...createPlan(),
            desiredFields: { ...fields(), customFields: [...customFields] }
          }
        })
      ).resolves.toBeNull();
      expect(storage.set).not.toHaveBeenCalled();
    }
  );

  it("fails closed when a recovered V2 plan exceeds schema budgets", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID]
    });
    const planned = await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    const key = pendingAutofillTransactionStorageKey(7);
    storage.items[key] = {
      ...planned,
      plan: {
        ...planned!.plan,
        desiredFields: {
          ...planned!.plan.desiredFields,
          password: "a".repeat(MAX_FIELD_BYTES + 1)
        }
      }
    };
    const restarted = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([])
    );

    await expect(restarted.loadForTab(7)).resolves.toBeNull();
  });

  it("rejects an oversized vault binding before durable planning", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID]
    });
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "v".repeat(MAX_VAULT_ID_BYTES + 1),
        plan: updatePlan()
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it("rejects more matching IDs than the native plan budget", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    const matchingIds = Array.from(
      { length: 4_097 },
      (_, index) =>
        `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`
    );
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: createPlan(matchingIds)
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });

  it.each(["", "operation-not-a-canonical-uuid"])(
    "rejects invalid generated operation ID %j without a durable plan",
    async (generatedId) => {
      const { storage, store, captured } = await capturedStore({
        ids: [TRANSACTION_ID, generatedId]
      });
      storage.set.mockClear();

      await expect(
        store.plan(7, captured.transactionId, {
          vaultId: "vault-1",
          plan: updatePlan()
        })
      ).resolves.toBeNull();
      expect(storage.set).not.toHaveBeenCalled();
    }
  );

  it.each(["", "planned-entry-not-a-canonical-uuid"])(
    "rejects invalid generated create ID %j without a durable plan",
    async (generatedId) => {
      const { storage, store, captured } = await capturedStore({
        ids: [TRANSACTION_ID, OPERATION_ID, generatedId]
      });
      storage.set.mockClear();

      await expect(
        store.plan(7, captured.transactionId, {
          vaultId: "vault-1",
          plan: createPlan()
        })
      ).resolves.toBeNull();
      expect(storage.set).not.toHaveBeenCalled();
    }
  );

  it("replays the same immutable binding across retry restart and detach", async () => {
    let now = 1_710_000_000_000;
    const storage = sessionStorage();
    const createId = idSequence([
      TRANSACTION_ID,
      OPERATION_ID,
      ATTEMPT_ID,
      NEXT_ATTEMPT_ID
    ]);
    const first = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      createId
    );
    const captured = await first.putCaptured(7, {
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      newPassword: "new-secret",
      submittedAt: now
    });
    const planned = await first.plan(7, captured!.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    const firstClaim = await first.claimForTab(7, TRANSACTION_ID);
    now += 30_000;

    const restarted = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      createId
    );
    const retry = await restarted.claimForTab(7, TRANSACTION_ID);
    storage.set.mockClear();
    const detached = await restarted.detachForRecovery(7, TRANSACTION_ID);
    expect(storage.set).toHaveBeenCalledTimes(1);
    expect(storage.set).toHaveBeenCalledWith({
      [`vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`]: retry,
      [pendingAutofillTransactionStorageKey(7)]: {
        version: 2,
        recoveryTransactionId: TRANSACTION_ID
      }
    });
    const recovery = await restarted.claimRecovery(TRANSACTION_ID);

    for (const candidate of [firstClaim, retry, detached, recovery]) {
      expect(candidate).toMatchObject({
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        vaultId: "vault-1",
        plan: planned!.plan,
        recoveryDeadlineAt: planned!.recoveryDeadlineAt
      });
    }
    expect(retry).toMatchObject({
      state: "persisting",
      attemptId: NEXT_ATTEMPT_ID,
      attemptCount: 2
    });
  });

  it("keeps the attached WAL authoritative when atomic recovery relocation fails", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID]
    });
    const planned = await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    storage.set.mockRejectedValueOnce(new Error("quota"));

    await expect(
      store.detachForRecovery(7, TRANSACTION_ID)
    ).resolves.toBeNull();
    await expect(store.loadForTab(7)).resolves.toEqual(planned);
    expect(
      storage.items[`vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`]
    ).toBeUndefined();
  });

  it("generates a new operation only for a changed conflict replan", async () => {
    const { store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID, NEXT_OPERATION_ID]
    });
    const planned = await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    const claim = await store.claimForTab(7, TRANSACTION_ID);
    await store.recordConflictForTab(7, {
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      entryId: ENTRY_ID,
      conflict: {
        code: "update_precondition_failed",
        retryable: false
      }
    });

    await expect(
      store.plan(7, TRANSACTION_ID, {
        vaultId: "vault-1",
        plan: updatePlan()
      })
    ).resolves.toBeNull();

    const changed = updatePlan();
    changed.expectedFields.notes = "changed elsewhere";
    await expect(
      store.plan(7, TRANSACTION_ID, {
        vaultId: "vault-1",
        plan: changed
      })
    ).resolves.toMatchObject({
      state: "planned",
      operationId: NEXT_OPERATION_ID,
      recoveryDeadlineAt: planned!.recoveryDeadlineAt,
      plan: changed
    });
    expect(claim?.operationId).toBe(OPERATION_ID);
  });

  it("never rebinds a conflicted plan to a different vault", async () => {
    const { store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID, NEXT_OPERATION_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    await store.recordConflictForTab(7, {
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      entryId: ENTRY_ID,
      conflict: {
        code: "active_vault_mismatch",
        retryable: true
      }
    });
    const changed = updatePlan();
    changed.expectedFields.notes = "changed elsewhere";

    await expect(
      store.plan(7, TRANSACTION_ID, {
        vaultId: "vault-2",
        plan: changed
      })
    ).resolves.toBeNull();
    await expect(store.loadForTab(7)).resolves.toMatchObject({
      state: "persist_conflict",
      vaultId: "vault-1",
      operationId: OPERATION_ID
    });
  });

  it("persists and reloads concurrent vault changes as a definitive conflict", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    await store.recordConflictForTab(7, {
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      entryId: ENTRY_ID,
      conflict: {
        code: "concurrent_vault_changes",
        retryable: false
      } as never
    });

    const restarted = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([])
    );
    await expect(restarted.loadForTab(7)).resolves.toMatchObject({
      state: "persist_conflict",
      conflict: {
        code: "concurrent_vault_changes",
        retryable: false
      }
    });
  });

  it("rejects forged retryability on a definitive conflict", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    await store.recordConflictForTab(7, {
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      entryId: ENTRY_ID,
      conflict: {
        code: "update_precondition_failed",
        retryable: false
      }
    });
    const key = pendingAutofillTransactionStorageKey(7);
    storage.items[key] = {
      ...(storage.items[key] as object),
      conflict: {
        code: "update_precondition_failed",
        retryable: true
      }
    };

    const restarted = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([])
    );
    await expect(restarted.loadForTab(7)).resolves.toBeNull();
  });

  it("writes a bounded non-secret completion before scrubbing the WAL", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    storage.set.mockClear();

    await expect(
      store.completeForTab(7, {
        transactionId: TRANSACTION_ID,
        operationId: "00000000-0000-4000-8000-000000000999",
        vaultId: "vault-1",
        entryId: ENTRY_ID
      })
    ).resolves.toBeNull();
    expect(storage.items[pendingAutofillTransactionStorageKey(7)]).toBeDefined();

    await expect(
      store.completeForTab(7, {
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        vaultId: "vault-1",
        entryId: ENTRY_ID
      })
    ).resolves.toMatchObject({ state: "persisted" });

    expect(storage.set.mock.calls.length).toBeGreaterThanOrEqual(2);
    const completionWrite = storage.set.mock.calls[0]![0];
    expect(JSON.stringify(completionWrite)).not.toContain("old-secret");
    expect(JSON.stringify(completionWrite)).not.toContain("new-secret");
    expect(storage.items[pendingAutofillTransactionStorageKey(7)]).toBeUndefined();
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      outcome: "persisted"
    });
  });

  it("keeps the recovery WAL when WebCrypto cannot bind a completion to its vault", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    vi.stubGlobal("crypto", undefined);

    try {
      await expect(
        store.completeForTab(7, {
          transactionId: TRANSACTION_ID,
          operationId: OPERATION_ID,
          vaultId: "vault-1",
          entryId: ENTRY_ID
        })
      ).resolves.toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }

    expect(storage.items[pendingAutofillTransactionStorageKey(7)]).toBeDefined();
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toBeNull();
  });

  it("removes the secret WAL when its terminal overwrite fails after completion", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID]
    });
    await store.plan(7, captured.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    const originalSet = storage.set.getMockImplementation()!;
    storage.set.mockImplementationOnce(originalSet);
    storage.set.mockRejectedValueOnce(new Error("terminal write failed"));
    storage.remove.mockClear();

    await expect(
      store.completeForTab(7, {
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        vaultId: "vault-1",
        entryId: ENTRY_ID
      })
    ).resolves.toMatchObject({ state: "persisted" });

    const key = pendingAutofillTransactionStorageKey(7);
    expect(storage.remove).toHaveBeenCalledWith(key);
    expect(storage.items[key]).toBeUndefined();
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      outcome: "persisted"
    });
  });

  it("does not expire a completion receipt while its secret WAL still exists", async () => {
    let now = 1_710_000_000_000;
    const storage = sessionStorage();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID])
    );
    const captured = await store.putCaptured(7, {
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      submittedAt: now
    });
    await store.plan(7, captured!.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    const completionKey = `vaultkernPendingAutofillCompletion:${TRANSACTION_ID}`;
    storage.items[completionKey] = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultIdHash: "hash",
      entryId: ENTRY_ID,
      outcome: "persisted",
      completedAt: now,
      expiresAt: now + 1
    };
    now += 2;

    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      outcome: "persisted"
    });
    expect(storage.items[completionKey]).toBeDefined();
    expect(JSON.stringify(storage.items)).toContain("old-secret");

    await store.cleanupCompletedTransactions();
    expect(JSON.stringify(storage.items)).not.toContain("old-secret");
  });

  it("scrubs due tab and recovery WAL without extending the hard deadline", async () => {
    let now = 1_710_000_000_000;
    const storage = sessionStorage();
    const createId = idSequence([
      TRANSACTION_ID,
      OPERATION_ID,
      ATTEMPT_ID,
      NEXT_ATTEMPT_ID
    ]);
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      createId
    );
    const captured = await store.putCaptured(7, {
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      submittedAt: now
    });
    const sensitivePlan = updatePlan();
    sensitivePlan.expectedFields.customFields = [
      { key: "legacy", value: "expected-custom-secret", protected: true }
    ];
    sensitivePlan.desiredFields.customFields = [
      { key: "tenant", value: "desired-custom-secret", protected: true }
    ];
    sensitivePlan.desiredFields.totpUri =
      "otpauth://totp/Example:alice?secret=DEADLINESECRET";
    const planned = await store.plan(7, captured!.transactionId, {
      vaultId: "vault-1",
      plan: sensitivePlan
    });
    await store.claimForTab(7, TRANSACTION_ID);
    await store.detachForRecovery(7, TRANSACTION_ID);
    const recoveryKey = `vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`;
    storage.items[recoveryKey] = {
      ...(storage.items[recoveryKey] as object),
      username: "legacy-duplicate-username",
      password: "legacy-top-password-secret",
      newPassword: "legacy-top-new-password-secret",
      mutation: {
        desiredFields: { password: "legacy-mutation-secret" }
      }
    };
    now = planned!.recoveryDeadlineAt - 1;
    const deadlineClaim = await store.claimRecovery(TRANSACTION_ID);
    expect(deadlineClaim).toMatchObject({
      recoveryDeadlineAt: planned!.recoveryDeadlineAt,
      attemptId: NEXT_ATTEMPT_ID
    });
    expect(deadlineClaim!.leaseExpiresAt).toBeGreaterThan(
      planned!.recoveryDeadlineAt
    );
    now = planned!.recoveryDeadlineAt + 1;

    await expect(
      store.clearExpired(new Set([`${TRANSACTION_ID}:${OPERATION_ID}`]))
    ).resolves.toBe(deadlineClaim!.leaseExpiresAt);
    await expect(store.loadRecovery(TRANSACTION_ID)).resolves.toMatchObject({
      recoveryDeadlineAt: planned!.recoveryDeadlineAt
    });

    now = deadlineClaim!.leaseExpiresAt! + 1;
    await store.clearExpired(new Set([`${TRANSACTION_ID}:${OPERATION_ID}`]));
    await expect(store.loadRecovery(TRANSACTION_ID)).resolves.toBeNull();
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      outcome: "expired_unknown",
      operationId: OPERATION_ID
    });
    expect(JSON.stringify(storage.items)).not.toContain("old-secret");
    expect(JSON.stringify(storage.items)).not.toContain("new-secret");
    expect(JSON.stringify(storage.items)).not.toContain("expected-custom-secret");
    expect(JSON.stringify(storage.items)).not.toContain("desired-custom-secret");
    expect(JSON.stringify(storage.items)).not.toContain("DEADLINESECRET");
    expect(JSON.stringify(storage.items)).not.toContain("legacy-duplicate-username");
    expect(JSON.stringify(storage.items)).not.toContain("legacy-top-password-secret");
    expect(JSON.stringify(storage.items)).not.toContain("legacy-top-new-password-secret");
    expect(JSON.stringify(storage.items)).not.toContain("legacy-mutation-secret");
  });

  it("caps a malformed stored deadline at the immutable recovery limit", async () => {
    const submittedAt = 1_710_000_000_000;
    const now = submittedAt + RECOVERY_MS + 1;
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({
      [key]: {
        version: 2,
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        state: "persisting",
        tabId: 7,
        origin: "https://example.com",
        submittedAt,
        vaultId: "vault-1",
        recoveryDeadlineAt: submittedAt + 24 * 60 * 60 * 1_000,
        plan: updatePlan()
      }
    });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([])
    );

    await store.clearExpired();

    expect(storage.items[key]).toBeUndefined();
    expect(JSON.stringify(storage.items)).not.toContain("new-secret");
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      outcome: "expired_unknown",
      operationId: OPERATION_ID
    });
  });

  it("scrubs a malformed future submission timestamp immediately", async () => {
    const now = 1_710_000_000_000;
    const submittedAt = now + 24 * 60 * 60 * 1_000;
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({
      [key]: {
        version: 2,
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        state: "persisting",
        tabId: 7,
        origin: "https://example.com",
        submittedAt,
        vaultId: "vault-1",
        recoveryDeadlineAt: submittedAt + RECOVERY_MS,
        plan: updatePlan()
      }
    });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([])
    );

    await store.clearExpired();

    expect(storage.items[key]).toBeUndefined();
    expect(JSON.stringify(storage.items)).not.toContain("new-secret");
  });

  it("does not trust a secret-bearing object as a pointer tombstone", async () => {
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({
      [key]: {
        version: 2,
        invalidated: true,
        password: "secret-hidden-behind-pointer"
      }
    });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => 1_710_000_000_000,
      idSequence([])
    );

    await store.clearExpired();

    expect(storage.items[key]).toBeUndefined();
    expect(JSON.stringify(storage.items)).not.toContain(
      "secret-hidden-behind-pointer"
    );
  });

  it("never downgrades a durable receipt when a duplicate WAL expires", async () => {
    let now = 1_710_000_000_000;
    const storage = sessionStorage();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID])
    );
    const captured = await store.putCaptured(7, {
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      submittedAt: now
    });
    const planned = await store.plan(7, captured!.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    const claimed = await store.claimForTab(7, TRANSACTION_ID);
    const recoveryKey = `vaultkernPendingAutofillRecovery:${TRANSACTION_ID}`;
    storage.items[recoveryKey] = structuredClone(claimed);
    await store.completeForTab(7, {
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      entryId: ENTRY_ID
    });
    const completionKey = `vaultkernPendingAutofillCompletion:${TRANSACTION_ID}`;
    storage.items[completionKey] = {
      ...(storage.items[completionKey] as object),
      expiresAt: planned!.recoveryDeadlineAt + 60_000
    };
    now = planned!.recoveryDeadlineAt + 1;

    await store.clearExpired();

    expect(storage.items[recoveryKey]).toBeUndefined();
    await expect(store.loadCompletion(TRANSACTION_ID)).resolves.toMatchObject({
      outcome: "persisted",
      operationId: OPERATION_ID,
      entryId: ENTRY_ID
    });
    expect(JSON.stringify(storage.items)).not.toContain("old-secret");
  });

  it("binds late durable completion to the entry recorded in the expiry tombstone", async () => {
    let now = 1_710_000_000_000;
    const storage = sessionStorage();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([TRANSACTION_ID, OPERATION_ID, ATTEMPT_ID])
    );
    const captured = await store.putCaptured(7, {
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      submittedAt: now
    });
    const planned = await store.plan(7, captured!.transactionId, {
      vaultId: "vault-1",
      plan: updatePlan()
    });
    await store.claimForTab(7, TRANSACTION_ID);
    now = planned!.recoveryDeadlineAt + 1;
    await store.clearExpired(new Set());

    await expect(
      store.completeForTab(7, {
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        vaultId: "vault-1",
        entryId: MATCH_OTHER
      })
    ).resolves.toBeNull();
    await expect(
      store.completeForTab(7, {
        transactionId: TRANSACTION_ID,
        operationId: OPERATION_ID,
        vaultId: "vault-1",
        entryId: ENTRY_ID
      })
    ).resolves.toMatchObject({ state: "persisted", entryId: ENTRY_ID });
  });

  it("accepts V2 create TOTP/custom fields", async () => {
    const { store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    const desiredFields = fields();
    desiredFields.totpUri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP";
    desiredFields.customFields = [
      { key: "Tenant", value: "prod", protected: true }
    ];

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: {
          ...createPlan([MATCH_A, MATCH_B]),
          desiredFields
        }
      })
    ).resolves.toMatchObject({
      plan: { desiredFields }
    });
  });

  it("rejects duplicate create baselines before durable planning", async () => {
    const { storage, store, captured } = await capturedStore({
      ids: [TRANSACTION_ID, OPERATION_ID, PLANNED_ENTRY_ID]
    });
    storage.set.mockClear();

    await expect(
      store.plan(7, captured.transactionId, {
        vaultId: "vault-1",
        plan: createPlan([MATCH_A, MATCH_A])
      })
    ).resolves.toBeNull();
    expect(storage.set).not.toHaveBeenCalled();
  });
});

describe("pending autofill V1 durable migration", () => {
  const now = 1_710_000_000_000;

  function legacyBase(state: string) {
    return {
      version: 1,
      transactionId: TRANSACTION_ID,
      state,
      tabId: 7,
      origin: "https://example.com",
      url: "https://example.com/login",
      username: "alice",
      password: "old-secret",
      newPassword: "new-secret",
      submittedAt: now - 1_000,
      expiresAt: now + 119_000
    };
  }

  function legacyUpdate(state: string) {
    return {
      ...legacyBase(state),
      vaultId: "vault-1",
      ...(state === "mutating" ? { operationId: OPERATION_ID } : {}),
      mutation: updatePlan()
    };
  }

  function legacyCreate(
    state: string,
    options: { createdEntryId?: string; baseline?: string[] } = {}
  ) {
    return {
      ...legacyBase(state),
      vaultId: "vault-1",
      ...(state === "mutating" ? { operationId: OPERATION_ID } : {}),
      mutation: {
        mode: "create",
        parentGroupId: GROUP_ID,
        ...(options.baseline
          ? { baselineMatchingEntryIds: options.baseline }
          : {}),
        ...(options.createdEntryId
          ? { createdEntryId: options.createdEntryId }
          : {}),
        desiredFields: fields()
      }
    };
  }

  it.each([
    ["captured", legacyBase("captured"), "captured"],
    ["associated", legacyUpdate("associated"), "planned"],
    ["update mutating", legacyUpdate("mutating"), "persisting"],
    ["update mutated", legacyUpdate("mutated"), "persisting"],
    ["update save_failed", legacyUpdate("save_failed"), "persisting"],
    [
      "create mutated",
      legacyCreate("mutated", {
        baseline: [MATCH_A],
        createdEntryId: PLANNED_ENTRY_ID
      }),
      "persisting"
    ],
    [
      "create save_failed",
      legacyCreate("save_failed", {
        baseline: [MATCH_A],
        createdEntryId: PLANNED_ENTRY_ID
      }),
      "persisting"
    ]
  ])("persists %s as V2 before returning it", async (_name, legacy, state) => {
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({ [key]: legacy });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([OPERATION_ID, PLANNED_ENTRY_ID])
    );

    const migrated = await store.loadForTab(7);

    expect(migrated).toMatchObject({ version: 2, state });
    expect(storage.items[key]).toEqual(migrated);
    expect(storage.set).toHaveBeenCalledWith({ [key]: migrated });
    if (state !== "captured") {
      expect(migrated).toMatchObject({
        operationId: expect.any(String),
        vaultId: "vault-1",
        recoveryDeadlineAt: expect.any(Number)
      });
    }
  });

  it("migrates save_new with a stable planned UUID and current sorted baseline", async () => {
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({ [key]: legacyCreate("save_new") });
    const findExactMatchingEntryIds = vi.fn(async () => [MATCH_B, MATCH_A]);
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([OPERATION_ID, PLANNED_ENTRY_ID]),
      { findExactMatchingEntryIds }
    );

    await expect(store.loadForTab(7)).resolves.toMatchObject({
      version: 2,
      state: "planned",
      operationId: OPERATION_ID,
      plan: {
        mode: "create",
        plannedEntryId: PLANNED_ENTRY_ID,
        expectedMatchingEntryIds: [MATCH_A, MATCH_B]
      }
    });
    expect(storage.items[key]).toMatchObject({ version: 2, state: "planned" });
  });

  it("fails closed before scanning an oversized V1 create baseline", async () => {
    const key = pendingAutofillTransactionStorageKey(7);
    const baseline = Array.from(
      { length: 4_097 },
      (_, index) =>
        `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`
    );
    const storage = sessionStorage({
      [key]: legacyCreate("mutating", { baseline })
    });
    const findExactMatchingEntryIds = vi.fn(async () => []);
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([OPERATION_ID]),
      { findExactMatchingEntryIds }
    );

    const includes = vi.spyOn(Array.prototype, "includes");
    const migrated = await store.loadForTab(7);
    const includesCalls = includes.mock.calls.length;
    includes.mockRestore();

    expect(migrated).toBeNull();
    expect(includesCalls).toBe(0);
    expect(findExactMatchingEntryIds).not.toHaveBeenCalled();
  });

  it.each([
    ["unique added match", [MATCH_A, PLANNED_ENTRY_ID], "persisting"],
    ["zero added matches", [MATCH_A], "persist_conflict"],
    [
      "multiple added matches",
      [MATCH_A, PLANNED_ENTRY_ID, MATCH_OTHER],
      "persist_conflict"
    ]
  ])("conservatively migrates create mutating with %s", async (_name, current, state) => {
    const key = pendingAutofillTransactionStorageKey(7);
    const storage = sessionStorage({
      [key]: legacyCreate("mutating", { baseline: [MATCH_A] })
    });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session: storage } },
      () => now,
      idSequence([]),
      { findExactMatchingEntryIds: vi.fn(async () => current) }
    );

    const migrated = await store.loadForTab(7);

    expect(migrated).toMatchObject({
      version: 2,
      state,
      operationId: OPERATION_ID,
      ...(state === "persisting"
        ? { plan: { plannedEntryId: PLANNED_ENTRY_ID } }
        : {
            conflict: {
              code: "legacy_create_outcome_ambiguous",
              retryable: false
            }
          })
    });
    expect(storage.items[key]).toEqual(migrated);
  });

  it.each(["persisted", "dismissed", "expired"])(
    "scrubs terminal V1 %s into a non-secret tombstone",
    async (state) => {
      const key = pendingAutofillTransactionStorageKey(7);
      const storage = sessionStorage({ [key]: legacyUpdate(state) });
      const store = createPendingAutofillSubmissionStore(
        { storage: { session: storage } },
        () => now,
        idSequence([OPERATION_ID])
      );

      await expect(store.loadForTab(7)).resolves.toBeNull();
      expect(JSON.stringify(storage.items)).not.toContain("old-secret");
      expect(JSON.stringify(storage.items)).not.toContain("new-secret");
      expect(
        Object.values(storage.items).some(
          (value) =>
            typeof value === "object" &&
            value !== null &&
            (value as { outcome?: unknown }).outcome === state
        )
      ).toBe(true);
    }
  );
});
