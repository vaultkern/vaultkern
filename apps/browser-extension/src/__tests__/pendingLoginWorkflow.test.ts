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
    findExactMatchingEntryIds: vi.fn(async () => []),
    dismiss: vi.fn(async () => true),
    commit: vi.fn(async () => ({
      commit: "committed",
      publication: { type: "publication_result", status: "published" }
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
      expectedMatchingEntryIds: [],
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
      .mockResolvedValueOnce({
        commit: "committed",
        publication: { type: "publication_result", status: "published" }
      });
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
    expect(unknown.prompt.mode).toBe("retry");
    const inspectedRetry = await workflow.loadPrompt("vault-a");
    await workflow.save(inspectedRetry.prompt!);
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

    expect(ports.getEntryFields).toHaveBeenLastCalledWith(
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

  it("never replays a committed create when prompt cleanup fails", async () => {
    const ports = dependencies();
    ports.dismiss.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    const cleanup = await workflow.save(loaded.prompt!);

    expect(cleanup).toMatchObject({
      status: "retry",
      prompt: { mode: "cleanup", action: "retry_cleanup" },
      errorMessage: expect.stringMatching(/saved.*cleanup/i)
    });
    expect(ports.commit).toHaveBeenCalledTimes(1);
    if (cleanup.status !== "retry") {
      throw new Error("expected cleanup retry");
    }

    await expect(workflow.save(cleanup.prompt)).resolves.toEqual({
      status: "dismissed"
    });
    expect(ports.commit).toHaveBeenCalledTimes(1);
    expect(ports.dismiss).toHaveBeenCalledTimes(2);
  });

  it("keeps a conflict-split login available for a fresh inspection", async () => {
    const ports = dependencies();
    ports.commit.mockResolvedValueOnce({
      commit: "committed",
      publication: {
        type: "publication_result",
        status: "conflict_split",
        conflictCopyPath: "/vaults/example.conflict.kdbx"
      }
    });
    const workflow = createPendingLoginWorkflow(ports);
    const loaded = await workflow.loadPrompt("vault-a");

    const conflict = await workflow.save(loaded.prompt!);

    expect(conflict).toMatchObject({
      status: "retry",
      prompt: { mode: "retry", action: "retry_lookup" },
      errorMessage: expect.stringContaining("/vaults/example.conflict.kdbx")
    });
    expect(ports.dismiss).not.toHaveBeenCalled();
  });

  it("turns an already-present captured login into cleanup-only recovery", async () => {
    const ports = dependencies();
    ports.findExactMatchingEntryIds.mockResolvedValue([ENTRY_ID]);
    const workflow = createPendingLoginWorkflow(ports);

    const loaded = await workflow.loadPrompt("vault-a");

    expect(loaded).toMatchObject({
      prompt: { mode: "cleanup", action: "retry_cleanup" },
      errorMessage: expect.stringMatching(/already present/i)
    });
    await workflow.save(loaded.prompt!);
    expect(ports.commit).not.toHaveBeenCalled();
    expect(ports.dismiss).toHaveBeenCalledTimes(1);
  });
});
