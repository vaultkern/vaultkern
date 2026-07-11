import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  dismissPendingAutofillSubmission,
  executePendingAutofillMutation,
  loadPendingAutofillSubmission,
  planPendingAutofillSubmission
} from "../popupShell";
import { PopupApp } from "../popup/PopupApp";
import { useDomRenderEnvironment } from "../autofill/__tests__/renderEnvironment";

const TRANSACTION_ID = "00000000-0000-4000-8000-000000000101";
const OPERATION_ID = "00000000-0000-4000-8000-000000000201";
const ENTRY_ID = "00000000-0000-4000-8000-000000000501";
const GROUP_ID = "00000000-0000-4000-8000-000000000601";

useDomRenderEnvironment();

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

function planned(
  state: "planned" | "persist_conflict" = "planned",
  conflictCode = "update_precondition_failed"
) {
  return {
    version: 2,
    transactionId: TRANSACTION_ID,
    operationId: OPERATION_ID,
    state,
    tabId: 7,
    origin: "https://example.com",
    submittedAt: Date.now() - 1_000,
    vaultId: "vault-1",
    recoveryDeadlineAt: Date.now() + 10 * 60 * 1_000,
    plan: {
      mode: "update",
      entryId: ENTRY_ID,
      expectedFields: fields("old-secret"),
      desiredFields: fields()
    },
    ...(state === "persist_conflict"
      ? {
          conflict: {
            code: conflictCode,
            retryable: false
          }
        }
      : {})
  };
}

function plannedCreateConflict() {
  return {
    version: 2,
    transactionId: TRANSACTION_ID,
    operationId: OPERATION_ID,
    state: "persist_conflict",
    tabId: 7,
    origin: "https://example.com",
    submittedAt: Date.now() - 1_000,
    vaultId: "vault-1",
    recoveryDeadlineAt: Date.now() + 10 * 60 * 1_000,
    plan: {
      mode: "create",
      parentGroupId: GROUP_ID,
      plannedEntryId: "00000000-0000-4000-8000-000000000301",
      expectedMatchingEntryIds: [],
      desiredFields: fields()
    },
    conflict: {
      code: "create_matching_set_changed",
      retryable: false
    }
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

function popupClient(overrides: Record<string, unknown> = {}) {
  const session = {
    unlocked: true,
    activeVaultId: "vault-1",
    currentVaultRefId: "vault-ref-1",
    supportsBiometricUnlock: false
  };
  return {
    getSessionState: vi.fn(async () => session),
    listRecentVaults: vi.fn(async () => []),
    preloadCurrentVault: vi.fn(async () => session),
    addLocalVaultReference: vi.fn(),
    setCurrentVault: vi.fn(async () => session),
    lockSession: vi.fn(async () => ({ ...session, unlocked: false })),
    unlockCurrentVaultWithPassword: vi.fn(async () => session),
    unlockCurrentVault: vi.fn(async () => session),
    enableQuickUnlockForCurrentVault: vi.fn(async () => session),
    unlockCurrentVaultWithQuickUnlock: vi.fn(async () => session),
    listGroups: vi.fn(async () => ({
      type: "group_tree",
      root: {
        id: GROUP_ID,
        title: "Root",
        entryCount: 0,
        childCount: 0,
        children: []
      }
    })),
    listEntries: vi.fn(async () => []),
    getEntryDetail: vi.fn(),
    findExactMatchingEntryIds: vi.fn(async () => []),
    ...overrides
  };
}

function renderPopup(options: {
  pending: ReturnType<typeof planned> | Record<string, unknown>;
  client?: ReturnType<typeof popupClient>;
  plan?: ReturnType<typeof vi.fn>;
  dismiss?: ReturnType<typeof vi.fn>;
  execute?: ReturnType<typeof vi.fn>;
}) {
  const client = options.client ?? popupClient();
  const plan =
    options.plan ??
    vi.fn(async () => ({
      ...planned(),
      operationId: "00000000-0000-4000-8000-000000000202"
    }));
  const dismiss = options.dismiss ?? vi.fn(async () => true);
  const execute = options.execute ?? vi.fn(async () => ({ ok: true }));
  render(
    <PopupApp
      client={client}
      activeSite={async () => "example.com"}
      findCandidates={async () => []}
      fillEntry={async () => undefined}
      loadPendingAutofillSubmission={async () => options.pending as never}
      planPendingAutofillSubmission={plan as never}
      dismissPendingAutofillSubmission={dismiss}
      executePendingAutofillMutation={execute}
    />
  );
  return { client, plan, dismiss, execute };
}

describe("popup pending autofill V2 transport", () => {
  it("loads a unique detached recovery after its original tab is gone", async () => {
    const recovery = planned("persist_conflict");
    const sendMessage = vi.fn(async () => ({
      ok: true,
      recovery: true,
      pending: recovery
    }));
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage },
      tabs: {
        query: vi.fn(async () => [
          { id: 9, active: true, url: "https://other.example/" }
        ])
      }
    };

    await expect(loadPendingAutofillSubmission()).resolves.toEqual(recovery);
    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_autofill_pending_request",
      tabId: 9,
      tabUrl: "https://other.example/"
    });
  });

  it("sends a complete plan without generating or supplying operation identity", async () => {
    const sendMessage = vi.fn(async (message: unknown) => ({
      ok: true,
      pending: planned()
    }));
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };
    vi.stubGlobal("crypto", {
      randomUUID: vi.fn(() => {
        throw new Error("popup must not generate operation IDs");
      })
    });
    const plan = planned().plan;

    await expect(
      planPendingAutofillSubmission(
        TRANSACTION_ID,
        7,
        "vault-1",
        plan
      )
    ).resolves.toMatchObject({ state: "planned", operationId: OPERATION_ID });
    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_autofill_pending_confirm",
      transactionId: TRANSACTION_ID,
      tabId: 7,
      vaultId: "vault-1",
      plan
    });
  });

  it("executes without an operation ID and returns typed conflict state", async () => {
    const sendMessage = vi.fn(async (message: unknown) => ({
      ok: false,
      conflict: true,
      pending: planned("persist_conflict")
    }));
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };

    await expect(
      executePendingAutofillMutation(TRANSACTION_ID, 7)
    ).resolves.toMatchObject({
      ok: false,
      conflict: true,
      pending: { state: "persist_conflict", operationId: OPERATION_ID }
    });
    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_autofill_pending_execute",
      transactionId: TRANSACTION_ID,
      tabId: 7
    });
  });

  it("treats an expired status receipt as a terminal execution outcome", async () => {
    const sendMessage = vi.fn(async (message: unknown) => {
      const type = (message as { type?: unknown }).type;
      return type === "vaultkern_autofill_pending_status"
        ? { ok: true, pending: null, outcome: "expired_unknown" }
        : { ok: false, pending: planned() };
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };

    await expect(
      executePendingAutofillMutation(TRANSACTION_ID, 7)
    ).resolves.toEqual({ ok: false, expired: true });
    expect(sendMessage).toHaveBeenNthCalledWith(2, {
      type: "vaultkern_autofill_pending_status",
      transactionId: TRANSACTION_ID,
      tabId: 7
    });
  });

  it("uses explicit discard for conflict without claiming rollback", async () => {
    const sendMessage = vi.fn(async () => ({ ok: true }));
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };

    await expect(
      dismissPendingAutofillSubmission(TRANSACTION_ID, 7)
    ).resolves.toBe(true);
    expect(sendMessage).toHaveBeenCalledWith({
      type: "vaultkern_autofill_pending_clear",
      state: "dismissed",
      transactionId: TRANSACTION_ID,
      tabId: 7
    });
  });

  it("keeps concurrent vault changes visible as a definitive conflict", async () => {
    const sendMessage = vi.fn(async () => ({
      ok: false,
      conflict: true,
      pending: planned("persist_conflict", "concurrent_vault_changes")
    }));
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };

    await expect(
      executePendingAutofillMutation(TRANSACTION_ID, 7)
    ).resolves.toMatchObject({
      ok: false,
      conflict: true,
      pending: {
        state: "persist_conflict",
        conflict: { code: "concurrent_vault_changes", retryable: false }
      }
    });
  });

  it("targets manual secret fill only at the active top frame", async () => {
    const installedFrameIds = [0, 3];
    const deliveredFrameIds: number[] = [];
    const sendTabMessage = vi.fn(
      async (
        _tabId: number,
        _message: unknown,
        options?: { frameId?: number }
      ) => {
        deliveredFrameIds.push(
          ...(options?.frameId === undefined
            ? installedFrameIds
            : [options.frameId])
        );
      }
    );
    const sendMessage = vi.fn(async (message: unknown) => {
      const command = (message as { command?: { type?: unknown } }).command;
      if (command?.type === "find_fill_candidates") {
        return {
          type: "fill_candidates",
          entries: [
            {
              id: ENTRY_ID,
              title: "Example",
              username: "alice",
              url: "https://example.com/login"
            }
          ]
        };
      }
      if (command?.type === "get_entry_detail") {
        return {
          type: "entry_detail",
          id: ENTRY_ID,
          title: "Example",
          username: "alice",
          password: "secret",
          url: "https://example.com/login",
          notes: ""
        };
      }
      throw new Error("unexpected runtime command");
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage },
      tabs: {
        query: vi.fn(async () => [
          {
            id: 7,
            url: "https://example.com/login",
            active: true,
            windowId: 1
          }
        ]),
        get: vi.fn(async () => ({
          id: 7,
          url: "https://example.com/login",
          active: true,
          windowId: 1
        })),
        sendMessage: sendTabMessage
      },
      windows: { get: vi.fn(async () => ({ focused: true })) }
    };
    vi.resetModules();
    const { fillSelectedEntry } = await import("../popupShell");

    await fillSelectedEntry("vault-1", ENTRY_ID);

    expect(sendTabMessage).toHaveBeenCalledWith(
      7,
      expect.objectContaining({
        type: "fill_entry_detail",
        username: "alice",
        password: "secret"
      }),
      { frameId: 0 }
    );
    expect(deliveredFrameIds).toEqual([0]);
  });
});

describe("popup pending autofill V2 workflow", () => {
  it("queries create baseline before planning and executes without popup operation ID", async () => {
    const submittedAt = Date.now() - 1_000;
    const captured = {
      version: 2,
      transactionId: TRANSACTION_ID,
      state: "captured",
      tabId: 7,
      origin: "https://example.com",
      submission: {
        url: "https://example.com/login?from=submit",
        username: "alice",
        password: "new-secret",
        submittedAt
      },
      expiresAt: submittedAt + 2 * 60 * 1_000
    };
    const client = popupClient();
    const plan = vi.fn(async (_transactionId, _tabId, vaultId, inputPlan) => ({
      ...planned(),
      vaultId,
      plan: {
        ...inputPlan,
        plannedEntryId: "00000000-0000-4000-8000-000000000301"
      }
    }));
    const { execute } = renderPopup({ pending: captured, client, plan });

    fireEvent.click(await screen.findByRole("button", { name: "Save Login" }));

    await waitFor(() => expect(execute).toHaveBeenCalledWith(TRANSACTION_ID, 7));
    expect(client.findExactMatchingEntryIds).toHaveBeenCalledWith(
      "vault-1",
      expect.objectContaining({
        username: "alice",
        password: "new-secret",
        url: "https://example.com/login"
      })
    );
    expect(plan).toHaveBeenCalledWith(
      TRANSACTION_ID,
      7,
      "vault-1",
      expect.objectContaining({
        mode: "create",
        parentGroupId: GROUP_ID,
        expectedMatchingEntryIds: []
      })
    );
  });

  it("rebases an update conflict without reverting unrelated current fields", async () => {
    const currentDetail = {
      type: "entry_detail" as const,
      id: ENTRY_ID,
      title: "Renamed elsewhere",
      username: "alice",
      password: "old-secret",
      url: "https://example.com/changed-elsewhere",
      notes: "changed elsewhere",
      totpUri:
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
      customFields: [
        { key: "Environment", value: "production", protected: false }
      ]
    };
    const client = popupClient({
      getEntryDetail: vi.fn(async () => currentDetail)
    });
    const plan = vi.fn(async (_transactionId, _tabId, vaultId, inputPlan) => ({
      ...planned(),
      operationId: "00000000-0000-4000-8000-000000000202",
      vaultId,
      plan: inputPlan
    }));
    const { execute } = renderPopup({
      pending: planned("persist_conflict"),
      client,
      plan
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Replan Update" })
    );

    await waitFor(() => expect(execute).toHaveBeenCalledWith(TRANSACTION_ID, 7));
    expect(plan).toHaveBeenCalledWith(
      TRANSACTION_ID,
      7,
      "vault-1",
      expect.objectContaining({
        mode: "update",
        entryId: ENTRY_ID,
        expectedFields: expect.objectContaining({
          password: "old-secret",
          notes: "changed elsewhere"
        }),
        desiredFields: {
          title: "Renamed elsewhere",
          username: "alice",
          password: "new-secret",
          url: "https://example.com/changed-elsewhere",
          notes: "changed elsewhere",
          totpUri:
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
          customFields: [
            { key: "Environment", value: "production", protected: false }
          ]
        }
      })
    );
  });

  it("keeps an update conflict when the intended password changed concurrently", async () => {
    const client = popupClient({
      getEntryDetail: vi.fn(async () => ({
        type: "entry_detail" as const,
        id: ENTRY_ID,
        ...fields("other-secret")
      }))
    });
    const plan = vi.fn();
    const execute = vi.fn();
    renderPopup({
      pending: planned("persist_conflict"),
      client,
      plan,
      execute
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Replan Update" })
    );

    await screen.findByRole("alert");
    expect(plan).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("reconciles an already-present update with an exact no-op plan", async () => {
    const client = popupClient({
      getEntryDetail: vi.fn(async () => ({
        type: "entry_detail" as const,
        id: ENTRY_ID,
        ...fields("new-secret")
      }))
    });
    const plan = vi.fn(async (_transactionId, _tabId, vaultId, inputPlan) => ({
      ...planned(),
      operationId: "00000000-0000-4000-8000-000000000202",
      vaultId,
      plan: inputPlan
    }));
    const execute = vi.fn(async () => ({ ok: true }));
    renderPopup({
      pending: planned("persist_conflict"),
      client,
      plan,
      execute
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Replan Update" })
    );

    await waitFor(() => expect(execute).toHaveBeenCalledWith(TRANSACTION_ID, 7));
    expect(plan).toHaveBeenCalledWith(
      TRANSACTION_ID,
      7,
      "vault-1",
      expect.objectContaining({
        expectedFields: fields("new-secret"),
        desiredFields: fields("new-secret")
      })
    );
  });

  it("fails closed when an update plan claims unsupported field intent", async () => {
    const conflicted = planned("persist_conflict");
    conflicted.plan.desiredFields.notes = "popup must not author this delta";
    const client = popupClient({
      getEntryDetail: vi.fn(async () => ({
        type: "entry_detail" as const,
        id: ENTRY_ID,
        ...fields("old-secret")
      }))
    });
    const plan = vi.fn();
    const execute = vi.fn();
    renderPopup({ pending: conflicted, client, plan, execute });

    fireEvent.click(
      await screen.findByRole("button", { name: "Replan Update" })
    );

    await screen.findByRole("alert");
    expect(plan).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("does not acknowledge a newly appeared exact match and create a duplicate", async () => {
    const client = popupClient({
      findExactMatchingEntryIds: vi.fn(async () => [ENTRY_ID])
    });
    const plan = vi.fn();
    const execute = vi.fn();
    renderPopup({
      pending: plannedCreateConflict(),
      client,
      plan,
      execute
    });

    fireEvent.click(await screen.findByRole("button", { name: "Save Login" }));

    await screen.findByRole("alert");
    expect(client.findExactMatchingEntryIds).toHaveBeenCalled();
    expect(plan).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("offers explicit discard for a definitive conflict", async () => {
    const dismiss = vi.fn(async () => true);
    renderPopup({ pending: planned("persist_conflict"), dismiss });

    fireEvent.click(await screen.findByRole("button", { name: "Dismiss" }));

    await waitFor(() =>
      expect(dismiss).toHaveBeenCalledWith(TRANSACTION_ID, 7)
    );
  });

  it("retries a retryable conflict with the same operation instead of replanning", async () => {
    const retryable = {
      ...planned("persist_conflict", "active_vault_mismatch"),
      conflict: { code: "active_vault_mismatch", retryable: true }
    };
    const plan = vi.fn();
    const execute = vi.fn(async () => ({ ok: true }));
    renderPopup({ pending: retryable, plan, execute });

    fireEvent.click(
      await screen.findByRole("button", { name: "Retry Update" })
    );

    await waitFor(() => expect(execute).toHaveBeenCalledWith(TRANSACTION_ID, 7));
    expect(plan).not.toHaveBeenCalled();
  });
});
