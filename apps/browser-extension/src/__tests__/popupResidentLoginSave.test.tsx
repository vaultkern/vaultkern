import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useDomRenderEnvironment } from "../autofill/__tests__/renderEnvironment";
import type { PendingAutofillTransaction } from "../autofill/pendingSubmission";
import { PopupApp } from "../popup/PopupApp";
import { createPendingLoginWorkflow } from "../popup/pendingLoginWorkflow";

useDomRenderEnvironment();

afterEach(cleanup);

function capturedLogin(): PendingAutofillTransaction {
  return {
    version: 2,
    transactionId: "00000000-0000-4000-8000-000000000101",
    state: "captured",
    tabId: 7,
    origin: "https://example.com",
    submission: {
      url: "https://example.com/login",
      username: "alice",
      password: "secret",
      saveOnly: true,
      submittedAt: Date.now() - 1_000
    },
    expiresAt: Date.now() + 60_000
  };
}

describe("popup resident login save", () => {
  it("shows an unknown result and sends a new mutation only on manual retry", async () => {
    const disconnected = Object.assign(new Error("native port disconnected"), {
      code: "native_port_disconnected"
    });
    const commit = vi
      .fn()
      .mockRejectedValueOnce(disconnected)
      .mockResolvedValueOnce({
        commit: "committed",
        publication: {
          type: "publication_result",
          status: "published"
        }
      });
    const workflow = createPendingLoginWorkflow({
      load: vi.fn(async () => capturedLogin()),
      findCandidates: vi.fn(async () => []),
      getEntryFields: vi.fn(),
      getCreateContext: vi.fn(async () => ({ rootGroupId: "group-root" })),
      findExactMatchingEntryIds: vi.fn(async () => []),
      commit,
      dismiss: vi.fn(async () => true)
    });
    const session = {
      unlocked: true,
      activeVaultId: "vault-1"
    };

    render(
      <PopupApp
        client={{
          getSessionState: vi.fn(async () => session),
          recordUserActivity: vi.fn(async () => session)
        }}
        activeSite={async () => "example.com"}
        findCandidates={async () => []}
        fillEntry={async () => undefined}
        pendingLoginWorkflow={workflow}
        openResidentApp={async () => undefined}
      />
    );

    fireEvent.click(await screen.findByRole("button", { name: "Save Login" }));
    expect(
      await screen.findByRole("alert")
    ).toHaveTextContent(/result is unknown/i);
    expect(commit).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Save Login" }));
    await waitFor(() => {
      expect(
        screen.queryByRole("button", { name: "Save Login" })
      ).not.toBeInTheDocument();
    });
    expect(commit).toHaveBeenCalledTimes(2);
    expect(commit.mock.calls[0]?.[1]).not.toHaveProperty("operationId");
    expect(commit.mock.calls[1]?.[1]).not.toHaveProperty("operationId");
  });
});
