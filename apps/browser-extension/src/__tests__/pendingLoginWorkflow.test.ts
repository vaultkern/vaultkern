import { describe, expect, it, vi } from "vitest";

import type { PendingAutofillTransaction } from "../autofill/pendingSubmission";
import { createPendingLoginWorkflow } from "../popup/pendingLoginWorkflow";

const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const ENTRY_ID = "00000000-0000-4000-8000-000000000301";

function capturedTransaction(
  overrides: Partial<PendingAutofillTransaction["submission"]> = {}
): PendingAutofillTransaction {
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
      submittedAt: Date.now() - 1_000,
      ...overrides
    },
    expiresAt: Date.now() + 60_000
  };
}

function dependencies(
  transaction: PendingAutofillTransaction = capturedTransaction()
) {
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
    dismiss: vi.fn(async () => true),
    commit: vi.fn(async () => ({
      commit: "committed",
      saveResult: { type: "save_vault_result", status: "saved" }
    }))
  };
}

describe("pending login workflow", () => {
  it("uses exactly one ordinary resident mutation for a confirmed save", async () => {
    const ports = dependencies();
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    await expect(workflow.save(loaded.prompt!)).resolves.toMatchObject({
      status: "saved"
    });
    expect(ports.commit).toHaveBeenCalledTimes(1);
    expect(ports.commit).toHaveBeenCalledWith("vault-a", {
      mode: "create",
      parentGroupId: "root-group",
      desiredFields: {
        title: "example.com",
        username: "alice",
        password: "new-secret",
        url: "https://example.com/login",
        notes: "",
        totpUri: null,
        customFields: []
      }
    });
    expect(ports.dismiss).toHaveBeenCalledWith(TRANSACTION_ID, 7);
  });

  it("leaves an unknown result for manual retry and never replays by itself", async () => {
    const disconnected = Object.assign(new Error("native port disconnected"), {
      code: "native_port_disconnected"
    });
    const ports = dependencies();
    ports.commit
      .mockRejectedValueOnce(disconnected)
      .mockResolvedValueOnce({ commit: "committed" });
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    const unknown = await workflow.save(loaded.prompt!);
    expect(unknown).toMatchObject({
      status: "retry",
      errorMessage: expect.stringMatching(/unknown/i)
    });
    expect(ports.commit).toHaveBeenCalledTimes(1);
    expect(ports.dismiss).not.toHaveBeenCalled();

    if (unknown.status !== "retry") {
      throw new Error("expected manual retry prompt");
    }
    await workflow.save(unknown.prompt);
    expect(ports.commit).toHaveBeenCalledTimes(2);
    expect(ports.commit.mock.calls[0]?.[1]).not.toHaveProperty("operationId");
    expect(ports.commit.mock.calls[1]?.[1]).not.toHaveProperty("operationId");
  });

  it("reconnects by inspecting candidates before offering a manual update", async () => {
    const ports = dependencies(capturedTransaction({ saveOnly: undefined }));
    ports.findCandidates.mockResolvedValue([
      {
        id: ENTRY_ID,
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    const workflow = createPendingLoginWorkflow(ports);

    const loaded = await workflow.loadPrompt("vault-a");

    expect(loaded.prompt).toMatchObject({
      mode: "update",
      action: "update"
    });
    expect(ports.commit).not.toHaveBeenCalled();
  });

  it("uses a fresh checked precondition for a confirmed update", async () => {
    const ports = dependencies(capturedTransaction({ saveOnly: undefined }));
    ports.findCandidates.mockResolvedValue([
      {
        id: ENTRY_ID,
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    await workflow.save(loaded.prompt!);

    expect(ports.getEntryFields).toHaveBeenCalledWith(
      "vault-a",
      ENTRY_ID,
      "https://example.com/login?next=%2Fvault"
    );
    expect(ports.commit).toHaveBeenCalledWith("vault-a", {
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
    });
  });

  it("does not overwrite a password changed after a password-change capture", async () => {
    const ports = dependencies(
      capturedTransaction({
        saveOnly: undefined,
        password: "captured-current",
        newPassword: "captured-new"
      })
    );
    ports.findCandidates.mockResolvedValue([
      {
        id: ENTRY_ID,
        title: "Example",
        username: "alice",
        url: "https://example.com/login"
      }
    ]);
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    await expect(workflow.save(loaded.prompt!)).resolves.toEqual({
      status: "dismissed"
    });
    expect(ports.commit).not.toHaveBeenCalled();
    expect(ports.dismiss).toHaveBeenCalled();
  });
});
