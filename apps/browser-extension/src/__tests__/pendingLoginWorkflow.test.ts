import { describe, expect, it, vi } from "vitest";

import { createPendingLoginWorkflow } from "../popup/pendingLoginWorkflow";
import type { PendingAutofillTransaction } from "../autofill/pendingSubmission";

const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const OPERATION_ID = "00000000-0000-4000-8000-000000000201";
const ENTRY_ID = "00000000-0000-4000-8000-000000000301";

function capturedTransaction(): PendingAutofillTransaction {
  return {
    version: 2,
    transactionId: TRANSACTION_ID,
    state: "captured",
    tabId: 7,
    origin: "https://example.com",
    submission: {
      url: "https://example.com/login?next=%2Fvault",
      username: "alice",
      password: "new-secret",
      saveOnly: true,
      submittedAt: Date.now() - 1_000
    },
    expiresAt: Date.now() + 60_000
  };
}

function persistedTransaction(): PendingAutofillTransaction {
  return {
    version: 2,
    transactionId: TRANSACTION_ID,
    state: "persisted",
    tabId: 7,
    origin: "https://example.com",
    operationId: OPERATION_ID,
    entryId: ENTRY_ID,
    completedAt: Date.now()
  };
}

function dependencies(
  transaction: PendingAutofillTransaction = capturedTransaction()
) {
  const plan = vi.fn(async (
    _transactionId: string,
    _tabId: number,
    _vaultId: string
  ) => persistedTransaction());
  return {
    load: vi.fn(async () => transaction),
    findCandidates: vi.fn(async () => []),
    getEntryFields: vi.fn(async (_vaultId, entryId) => ({
      id: entryId,
      fields: {
        username: "alice",
        password: "old-secret",
        url: "https://example.com/login"
      }
    })),
    getCreateContext: vi.fn(async () => ({ rootGroupId: "root-group" })),
    findExactMatchingEntryIds: vi.fn(async () => []),
    plan,
    dismiss: vi.fn(async () => true),
    execute: vi.fn(async () => ({ ok: true }))
  };
}

describe("pending login workflow", () => {
  it("binds a captured transaction to the vault that produced its prompt", async () => {
    const ports = dependencies();
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    expect(loaded.prompt).toMatchObject({
      mode: "save",
      vaultId: "vault-a"
    });
    expect(loaded.prompt).not.toHaveProperty("transaction");
    expect(loaded.prompt).not.toHaveProperty("entry");
    expect(JSON.stringify(loaded.prompt)).not.toContain("new-secret");
    expect(Object.isFrozen(loaded.prompt)).toBe(true);
    await expect(workflow.save(loaded.prompt!)).resolves.toMatchObject({
      status: "saved"
    });
    expect(ports.plan).toHaveBeenCalledWith(
      TRANSACTION_ID,
      7,
      "vault-a",
      expect.objectContaining({ mode: "create" })
    );
  });

  it("does not expose a planned transaction while another vault is active", async () => {
    const planned: PendingAutofillTransaction = {
      version: 2,
      transactionId: TRANSACTION_ID,
      operationId: OPERATION_ID,
      state: "planned",
      tabId: 7,
      origin: "https://example.com",
      submittedAt: Date.now() - 1_000,
      vaultId: "vault-a",
      recoveryDeadlineAt: Date.now() + 60_000,
      plan: {
        mode: "update",
        entryId: ENTRY_ID,
        expectedFields: {
          username: "alice",
          password: "old-secret",
          url: "https://example.com/login"
        },
        desiredFields: {
          username: "alice",
          password: "new-secret",
          url: "https://example.com/login"
        }
      }
    };
    const workflow = createPendingLoginWorkflow(dependencies(planned));

    await expect(workflow.loadPrompt("vault-b")).resolves.toEqual({
      prompt: null
    });
  });

  it("reports a durable save as successful when candidate refresh fails", async () => {
    const ports = dependencies();
    ports.findCandidates.mockRejectedValue(new Error("refresh unavailable"));
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    await expect(workflow.save(loaded.prompt!)).resolves.toEqual({
      status: "saved",
      candidates: null
    });
  });
});
