import { canonicalHttpOrigin } from "./originPolicy";
import {
  PENDING_AUTOFILL_TRANSACTION_VERSION,
  isValidPendingAutofillToken,
  pendingAutofillSubmissionFromUnknown,
  pendingAutofillTransactionFromUnknown,
  type PendingAutofillSubmission,
  type PendingAutofillTransaction
} from "./pendingSubmission";

export const PENDING_AUTOFILL_TRANSACTION_TTL_MS = 2 * 60 * 1_000;
const PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX =
  "vaultkernPendingAutofillTransaction:";

interface SessionStorageLike {
  get(key: string | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  setAccessLevel?(options: { accessLevel: "TRUSTED_CONTEXTS" }): Promise<void>;
}

interface ChromeWithSessionStorage {
  storage?: { session?: SessionStorageLike };
}

const trustedSessionStorage = new WeakSet<object>();

export function pendingAutofillTransactionStorageKey(tabId: number) {
  return `${PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX}${tabId}`;
}

function tabIdFromStorageKey(key: string) {
  if (!key.startsWith(PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX)) {
    return null;
  }
  const suffix = key.slice(PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX.length);
  if (!/^\d+$/.test(suffix)) {
    return null;
  }
  const tabId = Number(suffix);
  return Number.isSafeInteger(tabId) && tabId >= 0 ? tabId : null;
}

async function restrictSessionStorage(storage: SessionStorageLike) {
  if (trustedSessionStorage.has(storage)) {
    return true;
  }
  if (!storage.setAccessLevel) {
    trustedSessionStorage.add(storage);
    return true;
  }
  try {
    await storage.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    trustedSessionStorage.add(storage);
    return true;
  } catch {
    return false;
  }
}

export function createPendingAutofillSubmissionStore(
  chromeApi: ChromeWithSessionStorage | undefined,
  now: () => number = Date.now,
  createId: () => string = () => globalThis.crypto.randomUUID()
) {
  const session = chromeApi?.storage?.session;
  let queue = Promise.resolve();

  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const result = queue.then(operation, operation);
    queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  async function usableSession() {
    if (!session || !(await restrictSessionStorage(session))) {
      return null;
    }
    return session;
  }

  async function loadAtKey(
    storage: SessionStorageLike,
    tabId: number
  ): Promise<PendingAutofillTransaction | null> {
    const key = pendingAutofillTransactionStorageKey(tabId);
    const raw = (await storage.get(key))[key];
    if (raw === undefined) {
      return null;
    }
    const current = now();
    const transaction = pendingAutofillTransactionFromUnknown(
      raw,
      tabId,
      current,
      PENDING_AUTOFILL_TRANSACTION_TTL_MS
    );
    if (!transaction) {
      await storage.remove(key);
    }
    return transaction;
  }

  return {
    putCaptured(tabId: number, value: unknown) {
      return serialized(async () => {
        const storage = await usableSession();
        const submission = pendingAutofillSubmissionFromUnknown(value);
        const current = now();
        if (
          !storage ||
          !Number.isSafeInteger(tabId) ||
          tabId < 0 ||
          !submission ||
          submission.submittedAt > current ||
          current - submission.submittedAt >=
            PENDING_AUTOFILL_TRANSACTION_TTL_MS
        ) {
          return null;
        }
        let transactionId: string;
        try {
          transactionId = createId();
        } catch {
          return null;
        }
        if (!isValidPendingAutofillToken(transactionId)) {
          return null;
        }
        const origin = canonicalHttpOrigin(submission.url);
        if (origin === null) {
          return null;
        }
        const transaction: PendingAutofillTransaction = {
          version: PENDING_AUTOFILL_TRANSACTION_VERSION,
          transactionId,
          state: "captured",
          tabId,
          origin,
          submission,
          expiresAt: Math.min(
            current + PENDING_AUTOFILL_TRANSACTION_TTL_MS,
            submission.submittedAt + PENDING_AUTOFILL_TRANSACTION_TTL_MS
          )
        };
        await storage.set({
          [pendingAutofillTransactionStorageKey(tabId)]: transaction
        });
        return transaction;
      });
    },

    loadForTab(tabId: number) {
      return serialized(async () => {
        const storage = await usableSession();
        return storage ? loadAtKey(storage, tabId) : null;
      });
    },

    loadForTabUrl(tabId: number, url: string) {
      return serialized(async () => {
        const storage = await usableSession();
        if (!storage) {
          return null;
        }
        const transaction = await loadAtKey(storage, tabId);
        if (!transaction) {
          return null;
        }
        if (canonicalHttpOrigin(url) !== transaction.origin) {
          await storage.remove(pendingAutofillTransactionStorageKey(tabId));
          return null;
        }
        return transaction;
      });
    },

    dismissForTab(tabId: number, transactionId: string) {
      return serialized(async () => {
        const storage = await usableSession();
        if (!storage) {
          return null;
        }
        const transaction = await loadAtKey(storage, tabId);
        if (transaction?.transactionId !== transactionId) {
          return null;
        }
        await storage.remove(pendingAutofillTransactionStorageKey(tabId));
        return transaction;
      });
    },

    clearForTab(tabId: number) {
      return serialized(async () => {
        const storage = await usableSession();
        if (!storage) {
          return false;
        }
        await storage.remove(pendingAutofillTransactionStorageKey(tabId));
        return true;
      });
    },

    listTabTransactions() {
      return serialized(async () => {
        const storage = await usableSession();
        if (!storage) {
          return [];
        }
        const items = await storage.get(null);
        const transactions: PendingAutofillTransaction[] = [];
        const invalidKeys: string[] = [];
        for (const [key, raw] of Object.entries(items)) {
          const tabId = tabIdFromStorageKey(key);
          if (tabId === null) {
            continue;
          }
          const transaction = pendingAutofillTransactionFromUnknown(
            raw,
            tabId,
            now(),
            PENDING_AUTOFILL_TRANSACTION_TTL_MS
          );
          if (transaction) {
            transactions.push(transaction);
          } else {
            invalidKeys.push(key);
          }
        }
        if (invalidKeys.length > 0) {
          await storage.remove(invalidKeys);
        }
        return transactions;
      });
    },

    clearExpired() {
      return serialized(async () => {
        const storage = await usableSession();
        if (!storage) {
          return null;
        }
        const current = now();
        const items = await storage.get(null);
        const expiredKeys: string[] = [];
        let nextExpiry: number | null = null;
        for (const [key, raw] of Object.entries(items)) {
          const tabId = tabIdFromStorageKey(key);
          if (tabId === null) {
            continue;
          }
          const transaction = pendingAutofillTransactionFromUnknown(
            raw,
            tabId,
            current,
            PENDING_AUTOFILL_TRANSACTION_TTL_MS
          );
          if (!transaction) {
            expiredKeys.push(key);
          } else {
            nextExpiry =
              nextExpiry === null
                ? transaction.expiresAt
                : Math.min(nextExpiry, transaction.expiresAt);
          }
        }
        if (expiredKeys.length > 0) {
          await storage.remove(expiredKeys);
        }
        return nextExpiry;
      });
    }
  };
}

export type PendingAutofillSubmissionStore = ReturnType<
  typeof createPendingAutofillSubmissionStore
>;

export type { PendingAutofillSubmission };
