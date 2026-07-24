import { describe, expect, it, vi } from "vitest";

import {
  createPendingAutofillSubmissionStore,
  pendingAutofillTransactionStorageKey
} from "../pendingSubmissionStore";

function memorySession(initial: Record<string, unknown> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    setAccessLevel: vi.fn(async () => undefined),
    async get(key: string | null) {
      if (key === null) {
        return Object.fromEntries(values);
      }
      return values.has(key) ? { [key]: values.get(key) } : {};
    },
    async set(items: Record<string, unknown>) {
      for (const [key, value] of Object.entries(items)) {
        values.set(key, value);
      }
    },
    async remove(keys: string | string[]) {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        values.delete(key);
      }
    }
  };
}

const NOW = 10_000;
const submission = (password: string) => ({
  url: "https://example.com/login",
  username: "alice",
  password,
  submittedAt: NOW - 1
});

describe("pending autofill capture store", () => {
  it("keeps one bounded captured submission per tab without replay metadata", async () => {
    const session = memorySession();
    const ids = [
      "00000000-0000-4000-8000-000000000101",
      "00000000-0000-4000-8000-000000000102"
    ];
    const store = createPendingAutofillSubmissionStore(
      { storage: { session } },
      () => NOW,
      () => ids.shift()!
    );

    await store.putCaptured(7, submission("first"));
    const latest = await store.putCaptured(7, submission("second"));

    expect(await store.listTabTransactions()).toEqual([latest]);
    expect(session.values.size).toBe(1);
    expect(JSON.stringify(latest)).not.toMatch(
      /operationId|receipt|recovery|persisting|persist_conflict/
    );
    expect(session.setAccessLevel).toHaveBeenCalledTimes(1);
  });

  it("scrubs legacy planned records instead of recovering or replaying them", async () => {
    const key = pendingAutofillTransactionStorageKey(7);
    const session = memorySession({
      [key]: {
        version: 2,
        state: "planned",
        transactionId: "00000000-0000-4000-8000-000000000101",
        operationId: "00000000-0000-4000-8000-000000000201",
        tabId: 7,
        origin: "https://example.com",
        submittedAt: NOW - 1,
        recoveryDeadlineAt: NOW + 1_000
      }
    });
    const store = createPendingAutofillSubmissionStore(
      { storage: { session } },
      () => NOW
    );

    await expect(store.loadForTab(7)).resolves.toBeNull();
    expect(session.values.has(key)).toBe(false);
  });

  it("drops a captured submission when its tab leaves the exact origin", async () => {
    const session = memorySession();
    const store = createPendingAutofillSubmissionStore(
      { storage: { session } },
      () => NOW,
      () => "00000000-0000-4000-8000-000000000101"
    );
    await store.putCaptured(7, submission("secret"));

    await expect(
      store.loadForTabUrl(7, "https://other.example/login")
    ).resolves.toBeNull();
    await expect(store.loadForTab(7)).resolves.toBeNull();
  });
});
