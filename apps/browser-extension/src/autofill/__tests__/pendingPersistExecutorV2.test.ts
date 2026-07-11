import { describe, expect, it, vi } from "vitest";

import { executePendingAutofillPersist } from "../pendingMutationExecutor";
import type { PendingAutofillDesiredFields } from "../pendingSubmission";

const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const OPERATION_ID = "00000000-0000-4000-8000-000000000201";
const PLANNED_ENTRY_ID = "00000000-0000-4000-8000-000000000301";
const ENTRY_ID = "00000000-0000-4000-8000-000000000501";
const GROUP_ID = "00000000-0000-4000-8000-000000000601";
const MATCH_A = "00000000-0000-4000-8000-000000000701";
const MATCH_B = "00000000-0000-4000-8000-000000000702";

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

function transaction(plan: unknown) {
  return {
    version: 2 as const,
    transactionId: TRANSACTION_ID,
    operationId: OPERATION_ID,
    state: "persisting" as const,
    tabId: 7,
    origin: "https://example.com",
    submittedAt: 1_710_000_000_000,
    vaultId: "vault-1",
    recoveryDeadlineAt: 1_710_000_900_000,
    attemptId: "00000000-0000-4000-8000-000000000401",
    attemptCount: 1,
    lastAttemptAt: 1_710_000_000_100,
    plan
  };
}

function durable(entryId: string) {
  return {
    type: "autofill_persist_result" as const,
    transactionId: TRANSACTION_ID,
    operationId: OPERATION_ID,
    vaultId: "vault-1",
    outcome: "durable" as const,
    disposition: "committed" as const,
    entryId,
    durability: "source" as const,
    cacheState: "current" as const,
    committedFingerprint: {
      contentSha256: "a".repeat(64),
      sizeBytes: 42
    },
    mergeSummary: null,
    receiptVersion: 1 as const
  };
}

describe("pending autofill atomic persist executor", () => {
  it("sends one update atomic call and no split mutation or save calls", async () => {
    const plan = {
      mode: "update" as const,
      entryId: ENTRY_ID,
      expectedFields: fields("old-secret"),
      desiredFields: fields()
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => durable(ENTRY_ID)),
      getEntryDetail: vi.fn(),
      compareAndUpdateEntryFields: vi.fn(),
      saveVault: vi.fn()
    };

    await expect(
      executePendingAutofillPersist(client, transaction(plan))
    ).resolves.toMatchObject({ outcome: "durable", entryId: ENTRY_ID });

    expect(client.persistAutofillMutation).toHaveBeenCalledTimes(1);
    expect(client.persistAutofillMutation).toHaveBeenCalledWith({
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      plan
    });
    expect(client.getEntryDetail).not.toHaveBeenCalled();
    expect(client.compareAndUpdateEntryFields).not.toHaveBeenCalled();
    expect(client.saveVault).not.toHaveBeenCalled();
  });

  it("sends one create call with planned UUID baseline TOTP and custom fields", async () => {
    const desiredFields = fields();
    desiredFields.totpUri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP";
    desiredFields.customFields = [
      { key: "Tenant", value: "prod", protected: true }
    ];
    const plan = {
      mode: "create" as const,
      parentGroupId: GROUP_ID,
      plannedEntryId: PLANNED_ENTRY_ID,
      expectedMatchingEntryIds: [MATCH_A, MATCH_B],
      desiredFields
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => durable(PLANNED_ENTRY_ID))
    };

    await executePendingAutofillPersist(client, transaction(plan));

    expect(client.persistAutofillMutation).toHaveBeenCalledTimes(1);
    expect(client.persistAutofillMutation).toHaveBeenCalledWith({
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      plan
    });
  });

  it("replays a byte-for-byte identical request without changing operation identity", async () => {
    const plan = {
      mode: "create" as const,
      parentGroupId: GROUP_ID,
      plannedEntryId: PLANNED_ENTRY_ID,
      expectedMatchingEntryIds: [MATCH_A],
      desiredFields: fields()
    };
    const requests: unknown[] = [];
    const client = {
      persistAutofillMutation: vi.fn(async (request: unknown) => {
        requests.push(structuredClone(request));
        return durable(PLANNED_ENTRY_ID);
      })
    };
    const pending = transaction(plan);

    await executePendingAutofillPersist(client, pending);
    pending.attemptId = "00000000-0000-4000-8000-000000000402";
    pending.attemptCount += 1;
    pending.lastAttemptAt += 1_000;
    await executePendingAutofillPersist(client, pending);

    expect(requests).toHaveLength(2);
    expect(requests[1]).toEqual(requests[0]);
  });

  it.each([
    ["transaction", { transactionId: "transaction-forged" }],
    ["operation", { operationId: "operation-forged" }],
    ["vault", { vaultId: "vault-forged" }],
    ["entry", { entryId: "entry-forged" }]
  ])("rejects a late or forged %s binding", async (_name, forged) => {
    const plan = {
      mode: "create" as const,
      parentGroupId: GROUP_ID,
      plannedEntryId: PLANNED_ENTRY_ID,
      expectedMatchingEntryIds: [],
      desiredFields: fields()
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => ({
        ...durable(PLANNED_ENTRY_ID),
        ...forged
      }))
    };

    await expect(
      executePendingAutofillPersist(client, transaction(plan))
    ).rejects.toThrow(/binding|match/i);
  });

  it("returns a typed definitive conflict without changing its operation", async () => {
    const plan = {
      mode: "update" as const,
      entryId: ENTRY_ID,
      expectedFields: fields("old-secret"),
      desiredFields: fields()
    };
    const conflict = {
      type: "autofill_persist_result" as const,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      vaultId: "vault-1",
      outcome: "conflict" as const,
      code: "update_precondition_failed" as const,
      retryable: false as const
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => conflict)
    };

    await expect(
      executePendingAutofillPersist(client, transaction(plan))
    ).resolves.toEqual(conflict);
  });

  it("rejects a noncanonical plan before calling native persistence", async () => {
    const plan = {
      mode: "update" as const,
      entryId: "ENTRY-NOT-A-UUID",
      expectedFields: fields("old-secret"),
      desiredFields: fields()
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => durable(ENTRY_ID))
    };

    await expect(
      executePendingAutofillPersist(client, transaction(plan))
    ).rejects.toThrow(/uuid|plan/i);
    expect(client.persistAutofillMutation).not.toHaveBeenCalled();
  });

  it.each([
    ["transaction", { transactionId: " ".repeat(16) }],
    ["operation", { operationId: "o".repeat(129) }],
    ["vault", { vaultId: "v".repeat(4 * 1_024 + 1) }]
  ])("rejects an invalid %s request binding before native persistence", async (_name, override) => {
    const plan = {
      mode: "update" as const,
      entryId: ENTRY_ID,
      expectedFields: fields("old-secret"),
      desiredFields: fields()
    };
    const client = {
      persistAutofillMutation: vi.fn(async () => durable(ENTRY_ID))
    };

    await expect(
      executePendingAutofillPersist(client, {
        ...transaction(plan),
        ...override
      })
    ).rejects.toThrow(/binding|invalid|missing/i);
    expect(client.persistAutofillMutation).not.toHaveBeenCalled();
  });

  it.each(["username", "password", "newPassword", "submission", "mutation"])(
    "rejects a redundant top-level %s field before native persistence",
    async (field) => {
      const plan = {
        mode: "update" as const,
        entryId: ENTRY_ID,
        expectedFields: fields("old-secret"),
        desiredFields: fields()
      };
      const client = {
        persistAutofillMutation: vi.fn(async () => durable(ENTRY_ID))
      };
      const pending = {
        ...transaction(plan),
        [field]: field === "submission" || field === "mutation" ? {} : "secret"
      };

      await expect(
        executePendingAutofillPersist(client, pending)
      ).rejects.toThrow(/redundant|secret|field/i);
      expect(client.persistAutofillMutation).not.toHaveBeenCalled();
    }
  );
});
