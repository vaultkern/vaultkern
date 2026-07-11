import { canonicalHttpOrigin } from "./originPolicy";
import {
  PENDING_AUTOFILL_RECOVERY_TTL_MS,
  PENDING_AUTOFILL_TRANSACTION_VERSION,
  isCanonicalNonNilUuid,
  isValidPendingAutofillToken,
  isValidPendingAutofillVaultId,
  pendingAutofillPlanFromUnknown,
  pendingAutofillPlanInputFromUnknown,
  pendingAutofillStateIsRecoveryProtected,
  pendingAutofillSubmissionFromUnknown,
  pendingAutofillTransactionFromUnknown,
  type PendingAutofillConflictTransaction,
  type PendingAutofillDesiredFields,
  type PendingAutofillExecutableTransaction,
  type PendingAutofillPersistConflict,
  type PendingAutofillPlan,
  type PendingAutofillPlanInput,
  type PendingAutofillTerminalTransaction,
  type PendingAutofillTransaction
} from "./pendingSubmission";

export const PENDING_AUTOFILL_TRANSACTION_TTL_MS = 2 * 60 * 1_000;
const PENDING_AUTOFILL_ATTEMPT_LEASE_MS = 30 * 1_000;
const PENDING_AUTOFILL_COMPLETION_TTL_MS = 5 * 60 * 1_000;
const PENDING_AUTOFILL_MAX_MATCHING_ENTRY_IDS = 4_096;
const PENDING_AUTOFILL_MAX_WAL_BYTES = 4 * 1_024 * 1_024;
const PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX =
  "vaultkernPendingAutofillTransaction:";
const PENDING_AUTOFILL_RECOVERY_STORAGE_PREFIX =
  "vaultkernPendingAutofillRecovery:";
const PENDING_AUTOFILL_COMPLETION_STORAGE_PREFIX =
  "vaultkernPendingAutofillCompletion:";

interface SessionStorageLike {
  get(key: string | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  setAccessLevel?(options: { accessLevel: "TRUSTED_CONTEXTS" }): Promise<void>;
}

interface ChromeWithSessionStorage {
  storage?: { session?: SessionStorageLike };
}

interface LegacyMigrationOptions {
  findExactMatchingEntryIds?(input: {
    vaultId: string;
    desiredFields: PendingAutofillDesiredFields;
  }): Promise<string[]>;
}

export interface PendingAutofillCompletionRecord {
  version: typeof PENDING_AUTOFILL_TRANSACTION_VERSION;
  transactionId: string;
  operationId?: string;
  vaultIdHash?: string;
  entryId?: string;
  outcome: "persisted" | "expired_unknown" | "dismissed" | "expired";
  completedAt: number;
  expiresAt: number;
}

interface PersistBinding {
  transactionId: string;
  operationId: string;
  vaultId: string;
  entryId: string;
}

interface ConflictBinding extends PersistBinding {
  conflict: PendingAutofillPersistConflict;
}

const trustedSessionStorage = new WeakSet<object>();
const walEncoder = new TextEncoder();

function pendingWalFits(value: unknown) {
  try {
    const serialized = JSON.stringify(value);
    return (
      serialized.length <= PENDING_AUTOFILL_MAX_WAL_BYTES &&
      walEncoder.encode(serialized).byteLength <= PENDING_AUTOFILL_MAX_WAL_BYTES
    );
  } catch {
    return false;
  }
}

export function pendingAutofillTransactionStorageKey(tabId: number) {
  return `${PENDING_AUTOFILL_TRANSACTION_STORAGE_PREFIX}${tabId}`;
}

function pendingAutofillRecoveryStorageKey(transactionId: string) {
  return `${PENDING_AUTOFILL_RECOVERY_STORAGE_PREFIX}${transactionId}`;
}

function pendingAutofillCompletionStorageKey(transactionId: string) {
  return `${PENDING_AUTOFILL_COMPLETION_STORAGE_PREFIX}${transactionId}`;
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

function transactionIdFromRecoveryStorageKey(key: string) {
  return key.startsWith(PENDING_AUTOFILL_RECOVERY_STORAGE_PREFIX)
    ? key.slice(PENDING_AUTOFILL_RECOVERY_STORAGE_PREFIX.length)
    : null;
}

function transactionIdFromCompletionStorageKey(key: string) {
  return key.startsWith(PENDING_AUTOFILL_COMPLETION_STORAGE_PREFIX)
    ? key.slice(PENDING_AUTOFILL_COMPLETION_STORAGE_PREFIX.length)
    : null;
}

function expectedEntryId(transaction: PendingAutofillExecutableTransaction) {
  return transaction.plan.mode === "update"
    ? transaction.plan.entryId
    : transaction.plan.plannedEntryId;
}

function plansEqual(left: PendingAutofillPlan, right: PendingAutofillPlan) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function rawTransactionId(value: unknown) {
  return typeof value === "object" && value !== null
    ? (value as { transactionId?: unknown }).transactionId
    : undefined;
}

function rawState(value: unknown) {
  return typeof value === "object" && value !== null
    ? (value as { state?: unknown }).state
    : undefined;
}

function rawOperationId(value: unknown) {
  return typeof value === "object" && value !== null
    ? (value as { operationId?: unknown }).operationId
    : undefined;
}

function rawVaultId(value: unknown) {
  return typeof value === "object" && value !== null
    ? (value as { vaultId?: unknown }).vaultId
    : undefined;
}

function rawExpectedEntryId(value: unknown) {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const candidate = value as {
    plan?: { mode?: unknown; entryId?: unknown; plannedEntryId?: unknown };
    mutation?: { mode?: unknown; entryId?: unknown; createdEntryId?: unknown };
  };
  const plan = candidate.plan;
  const mutation = candidate.mutation;
  const entryId =
    plan?.mode === "update"
      ? plan.entryId
      : plan?.mode === "create"
        ? plan.plannedEntryId
        : mutation?.mode === "update"
          ? mutation.entryId
          : mutation?.mode === "create"
            ? mutation.createdEntryId
            : undefined;
  return isCanonicalNonNilUuid(entryId) ? entryId : undefined;
}

function rawDeadline(value: unknown, currentTime: number) {
  if (
    typeof value !== "object" ||
    value === null ||
    isPointerTombstone(value)
  ) {
    return typeof value === "object" ? null : 0;
  }
  const candidate = value as {
    state?: unknown;
    expiresAt?: unknown;
    recoveryDeadlineAt?: unknown;
    submittedAt?: unknown;
    submission?: { submittedAt?: unknown };
  };
  const submittedAt =
    candidate.state === "captured"
      ? candidate.submission?.submittedAt
      : candidate.submittedAt;
  if (
    typeof submittedAt !== "number" ||
    !Number.isSafeInteger(submittedAt) ||
    submittedAt < 0 ||
    submittedAt > currentTime
  ) {
    return 0;
  }
  if (candidate.state === "captured") {
    if (
      submittedAt >
      Number.MAX_SAFE_INTEGER - PENDING_AUTOFILL_TRANSACTION_TTL_MS
    ) {
      return 0;
    }
    const captureCap = submittedAt + PENDING_AUTOFILL_TRANSACTION_TTL_MS;
    return Number.isSafeInteger(candidate.expiresAt)
      ? Math.min(candidate.expiresAt as number, captureCap)
      : captureCap;
  }
  if (
    submittedAt > Number.MAX_SAFE_INTEGER - PENDING_AUTOFILL_RECOVERY_TTL_MS
  ) {
    return 0;
  }
  const recoveryCap = submittedAt + PENDING_AUTOFILL_RECOVERY_TTL_MS;
  return Number.isSafeInteger(candidate.recoveryDeadlineAt)
    ? Math.min(candidate.recoveryDeadlineAt as number, recoveryCap)
    : recoveryCap;
}

function storageHasTransactionWal(
  items: Record<string, unknown>,
  transactionId: string
) {
  return Object.entries(items).some(
    ([key, value]) =>
      (tabIdFromStorageKey(key) !== null ||
        transactionIdFromRecoveryStorageKey(key) !== null) &&
      rawTransactionId(value) === transactionId
  );
}

function isPointerTombstone(value: unknown) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== PENDING_AUTOFILL_TRANSACTION_VERSION ||
    Object.keys(candidate).length !== 2
  ) {
    return false;
  }
  return (
    isValidPendingAutofillToken(candidate.recoveryTransactionId) ||
    isValidPendingAutofillToken(candidate.completedTransactionId) ||
    candidate.invalidated === true
  );
}

async function restrictSessionStorage(storage: SessionStorageLike) {
  if (typeof storage !== "object" || !storage.setAccessLevel) {
    return false;
  }
  if (trustedSessionStorage.has(storage)) {
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

async function hashVaultId(vaultId: string) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return null;
  }
  try {
    const digest = await subtle.digest("SHA-256", new TextEncoder().encode(vaultId));
    if (digest.byteLength !== 32) {
      return null;
    }
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  } catch {
    return null;
  }
}

function completionRecordFromUnknown(
  value: unknown,
  expectedTransactionId: string
): PendingAutofillCompletionRecord | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  const outcomes: ReadonlySet<unknown> = new Set([
    "persisted",
    "expired_unknown",
    "dismissed",
    "expired"
  ]);
  if (
    candidate.version !== PENDING_AUTOFILL_TRANSACTION_VERSION ||
    candidate.transactionId !== expectedTransactionId ||
    !outcomes.has(candidate.outcome) ||
    typeof candidate.completedAt !== "number" ||
    !Number.isSafeInteger(candidate.completedAt) ||
    typeof candidate.expiresAt !== "number" ||
    !Number.isSafeInteger(candidate.expiresAt)
  ) {
    return null;
  }
  return {
    version: PENDING_AUTOFILL_TRANSACTION_VERSION,
    transactionId: expectedTransactionId,
    ...(isValidPendingAutofillToken(candidate.operationId)
      ? { operationId: candidate.operationId }
      : {}),
    ...(typeof candidate.vaultIdHash === "string" && candidate.vaultIdHash !== ""
      ? { vaultIdHash: candidate.vaultIdHash }
      : {}),
    ...(isCanonicalNonNilUuid(candidate.entryId)
      ? { entryId: candidate.entryId }
      : {}),
    outcome: candidate.outcome as PendingAutofillCompletionRecord["outcome"],
    completedAt: candidate.completedAt,
    expiresAt: candidate.expiresAt
  };
}

function normalizeCanonicalIds(value: unknown) {
  if (
    !Array.isArray(value) ||
    value.length > PENDING_AUTOFILL_MAX_MATCHING_ENTRY_IDS
  ) {
    return null;
  }
  const ids: string[] = [];
  const uniqueIds = new Set<string>();
  for (const id of value) {
    if (!isCanonicalNonNilUuid(id) || uniqueIds.has(id)) {
      return null;
    }
    uniqueIds.add(id);
    ids.push(id);
  }
  ids.sort();
  return ids;
}

export function createPendingAutofillSubmissionStore(
  chromeApi: ChromeWithSessionStorage | null | undefined,
  now: () => number = Date.now,
  createId: () => string = () => globalThis.crypto.randomUUID(),
  migrationOptions: LegacyMigrationOptions = {}
) {
  const storage = chromeApi?.storage?.session;
  let queue: Promise<void> = Promise.resolve();

  function exclusive<T>(operation: () => Promise<T>) {
    const result = queue.then(operation, operation);
    queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  async function trustedStorage() {
    return storage && (await restrictSessionStorage(storage)) ? storage : null;
  }

  async function persistAtKey(key: string, value: unknown) {
    if (!pendingWalFits(value)) {
      return false;
    }
    const session = await trustedStorage();
    if (!session) {
      return false;
    }
    try {
      await session.set({ [key]: value });
      return true;
    } catch {
      return false;
    }
  }

  async function loadCompletionRecordUnqueued(transactionId: string) {
    const session = await trustedStorage();
    if (!session) {
      return null;
    }
    const key = pendingAutofillCompletionStorageKey(transactionId);
    let items: Record<string, unknown>;
    try {
      items = await session.get(key);
    } catch {
      return null;
    }
    return completionRecordFromUnknown(items[key], transactionId);
  }

  async function writeCompletion(
    transactionId: string,
    outcome: PendingAutofillCompletionRecord["outcome"],
    options: { operationId?: string; vaultId?: string; entryId?: string } = {}
  ) {
    const session = await trustedStorage();
    if (!session) {
      return null;
    }
    const completedAt = now();
    const vaultIdHash =
      typeof options.vaultId === "string" && options.vaultId !== ""
        ? await hashVaultId(options.vaultId)
        : undefined;
    if (vaultIdHash === null) {
      return null;
    }
    const record: PendingAutofillCompletionRecord = {
      version: PENDING_AUTOFILL_TRANSACTION_VERSION,
      transactionId,
      ...(isValidPendingAutofillToken(options.operationId)
        ? { operationId: options.operationId }
        : {}),
      ...(vaultIdHash ? { vaultIdHash } : {}),
      ...(isCanonicalNonNilUuid(options.entryId)
        ? { entryId: options.entryId }
        : {}),
      outcome,
      completedAt,
      expiresAt: completedAt + PENDING_AUTOFILL_COMPLETION_TTL_MS
    };
    try {
      await session.set({
        [pendingAutofillCompletionStorageKey(transactionId)]: record
      });
      return record;
    } catch {
      return null;
    }
  }

  async function scrubWalKey(
    key: string,
    terminal: PendingAutofillTerminalTransaction
  ) {
    const session = await trustedStorage();
    if (!session) {
      return false;
    }
    let terminalWritten = false;
    try {
      await session.set({ [key]: terminal });
      terminalWritten = true;
    } catch {
      // The completion receipt is already authoritative; removal can still scrub.
    }
    try {
      await session.remove(key);
      return true;
    } catch {
      return terminalWritten;
    }
  }

  async function scrubInvalidWalKey(key: string) {
    const session = await trustedStorage();
    if (!session) {
      return;
    }
    try {
      await session.set({
        [key]: {
          version: PENDING_AUTOFILL_TRANSACTION_VERSION,
          invalidated: true
        }
      });
    } catch {
      // Direct removal can still scrub the malformed secret record.
    }
    try {
      await session.remove(key);
    } catch {
      // A successful overwrite already replaced the record with non-secret data.
    }
  }

  function terminalTransaction(
    transaction: Pick<PendingAutofillTransaction, "transactionId" | "tabId" | "origin">,
    state: PendingAutofillTerminalTransaction["state"],
    options: { operationId?: string; entryId?: string } = {}
  ): PendingAutofillTerminalTransaction {
    return {
      version: PENDING_AUTOFILL_TRANSACTION_VERSION,
      transactionId: transaction.transactionId,
      state,
      tabId: transaction.tabId,
      origin: transaction.origin,
      ...(isValidPendingAutofillToken(options.operationId)
        ? { operationId: options.operationId }
        : {}),
      ...(isCanonicalNonNilUuid(options.entryId)
        ? { entryId: options.entryId }
        : {}),
      completedAt: now()
    };
  }

  async function migrateLegacy(
    raw: Record<string, unknown>,
    tabId: number,
    key: string
  ): Promise<PendingAutofillTransaction | null> {
    if (raw.version !== 1 || !isValidPendingAutofillToken(raw.transactionId)) {
      return null;
    }
    const submission = pendingAutofillSubmissionFromUnknown(raw);
    const origin = submission ? canonicalHttpOrigin(submission.url) : null;
    if (
      !submission ||
      origin === null ||
      raw.tabId !== tabId ||
      raw.origin !== origin ||
      typeof raw.state !== "string"
    ) {
      return null;
    }
    if (
      raw.state === "persisted" ||
      raw.state === "dismissed" ||
      raw.state === "expired"
    ) {
      const completion = await writeCompletion(raw.transactionId, raw.state, {
        operationId: isValidPendingAutofillToken(raw.operationId) ? raw.operationId : undefined,
        vaultId: typeof raw.vaultId === "string" ? raw.vaultId : undefined
      });
      if (!completion) {
        return null;
      }
      await scrubWalKey(
        key,
        terminalTransaction(
          {
            transactionId: raw.transactionId,
            tabId,
            origin
          },
          raw.state,
          { operationId: completion.operationId }
        )
      );
      return null;
    }
    if (raw.state === "captured") {
      const expiresAt = raw.expiresAt;
      if (
        typeof expiresAt !== "number" ||
        !Number.isSafeInteger(expiresAt) ||
        expiresAt !== submission.submittedAt + PENDING_AUTOFILL_TRANSACTION_TTL_MS ||
        expiresAt <= now()
      ) {
        return null;
      }
      const migrated: PendingAutofillTransaction = {
        version: PENDING_AUTOFILL_TRANSACTION_VERSION,
        transactionId: raw.transactionId,
        state: "captured",
        tabId,
        origin,
        submission,
        expiresAt
      };
      return (await persistAtKey(key, migrated)) ? migrated : null;
    }
    if (
      raw.state !== "associated" &&
      raw.state !== "save_new" &&
      raw.state !== "mutating" &&
      raw.state !== "mutated" &&
      raw.state !== "save_failed"
    ) {
      return null;
    }
    if (!isValidPendingAutofillVaultId(raw.vaultId)) {
      return null;
    }
    const mutation = raw.mutation;
    if (typeof mutation !== "object" || mutation === null || Array.isArray(mutation)) {
      return null;
    }
    const legacyMutation = mutation as Record<string, unknown>;
    const operationId = isValidPendingAutofillToken(raw.operationId) ? raw.operationId : createId();
    if (!isValidPendingAutofillToken(operationId)) {
      return null;
    }
    const recoveryDeadlineAt = Math.min(
      now() + PENDING_AUTOFILL_RECOVERY_TTL_MS,
      submission.submittedAt + PENDING_AUTOFILL_RECOVERY_TTL_MS
    );
    const executableBase = {
      version: PENDING_AUTOFILL_TRANSACTION_VERSION,
      transactionId: raw.transactionId,
      tabId,
      origin,
      submittedAt: submission.submittedAt,
      vaultId: raw.vaultId,
      operationId,
      recoveryDeadlineAt
    } as const;
    if (legacyMutation.mode === "update") {
      if (raw.state === "save_new") {
        return null;
      }
      const plan = pendingAutofillPlanFromUnknown(legacyMutation);
      if (!plan || plan.mode !== "update") {
        return null;
      }
      const migrated: PendingAutofillTransaction = {
        ...executableBase,
        state: raw.state === "associated" ? "planned" : "persisting",
        plan
      };
      return (await persistAtKey(key, migrated)) ? migrated : null;
    }
    if (legacyMutation.mode !== "create") {
      return null;
    }
    const baseline =
      legacyMutation.baselineMatchingEntryIds === undefined
        ? undefined
        : normalizeCanonicalIds(legacyMutation.baselineMatchingEntryIds);
    if (
      legacyMutation.baselineMatchingEntryIds !== undefined &&
      baseline === null
    ) {
      return null;
    }
    const temporaryPlan = pendingAutofillPlanFromUnknown({
      mode: "create",
      parentGroupId: legacyMutation.parentGroupId,
      plannedEntryId:
        isCanonicalNonNilUuid(legacyMutation.createdEntryId)
          ? legacyMutation.createdEntryId
          : "00000000-0000-4000-8000-000000000001",
      expectedMatchingEntryIds: baseline ?? [],
      desiredFields: legacyMutation.desiredFields
    });
    if (!temporaryPlan || temporaryPlan.mode !== "create") {
      return null;
    }
    const resolveCurrent = async () => {
      if (!migrationOptions.findExactMatchingEntryIds) {
        return null;
      }
      try {
        return normalizeCanonicalIds(
          await migrationOptions.findExactMatchingEntryIds({
            vaultId: raw.vaultId as string,
            desiredFields: temporaryPlan.desiredFields
          })
        );
      } catch {
        return null;
      }
    };
    if (raw.state === "save_new" || raw.state === "associated") {
      const current = await resolveCurrent();
      if (!current) {
        return null;
      }
      const plannedEntryId = createId();
      if (!isCanonicalNonNilUuid(plannedEntryId)) {
        return null;
      }
      const plan: PendingAutofillPlan = {
        ...temporaryPlan,
        plannedEntryId,
        expectedMatchingEntryIds: current
      };
      const migrated: PendingAutofillTransaction = {
        ...executableBase,
        state: "planned",
        plan
      };
      return (await persistAtKey(key, migrated)) ? migrated : null;
    }
    if (isCanonicalNonNilUuid(legacyMutation.createdEntryId)) {
      const current = baseline ?? (await resolveCurrent());
      if (!current) {
        return null;
      }
      const migrated: PendingAutofillTransaction = {
        ...executableBase,
        state: "persisting",
        plan: {
          ...temporaryPlan,
          plannedEntryId: legacyMutation.createdEntryId,
          expectedMatchingEntryIds: baseline ??
            current.filter((id) => id !== legacyMutation.createdEntryId)
        }
      };
      return (await persistAtKey(key, migrated)) ? migrated : null;
    }
    if (raw.state !== "mutating" || !baseline) {
      return null;
    }
    const current = await resolveCurrent();
    if (!current) {
      return null;
    }
    const baselineSet = new Set(baseline);
    const added = current.filter((entryId) => !baselineSet.has(entryId));
    if (added.length === 1) {
      const migrated: PendingAutofillTransaction = {
        ...executableBase,
        state: "persisting",
        plan: {
          ...temporaryPlan,
          plannedEntryId: added[0]!,
          expectedMatchingEntryIds: baseline
        }
      };
      return (await persistAtKey(key, migrated)) ? migrated : null;
    }
    const conflict: PendingAutofillConflictTransaction | PendingAutofillTransaction = {
      ...executableBase,
      state: "persist_conflict",
      conflict: {
        code: "legacy_create_outcome_ambiguous",
        retryable: false
      }
    };
    return (await persistAtKey(key, conflict)) ? conflict : null;
  }

  async function loadAtKeyUnqueued(key: string, tabId: number) {
    const session = await trustedStorage();
    if (!session) {
      return null;
    }
    let items: Record<string, unknown>;
    try {
      items = await session.get(key);
    } catch {
      return null;
    }
    const raw = items[key];
    if (raw === undefined || isPointerTombstone(raw)) {
      return null;
    }
    if (
      typeof raw === "object" &&
      raw !== null &&
      (raw as { version?: unknown }).version === 1
    ) {
      return migrateLegacy(raw as Record<string, unknown>, tabId, key);
    }
    const transaction = pendingAutofillTransactionFromUnknown(
      raw,
      tabId,
      now(),
      PENDING_AUTOFILL_TRANSACTION_TTL_MS
    );
    if (!transaction) {
      return null;
    }
    if (
      transaction.state === "persisted" ||
      transaction.state === "dismissed" ||
      transaction.state === "expired"
    ) {
      return null;
    }
    const completion = await loadCompletionRecordUnqueued(
      transaction.transactionId
    );
    if (completion) {
      await scrubWalKey(
        key,
        terminalTransaction(transaction, "persisted", {
          operationId: completion.operationId,
          entryId: completion.entryId
        })
      );
      return null;
    }
    return transaction;
  }

  async function loadForTabUnqueued(tabId: number) {
    return loadAtKeyUnqueued(pendingAutofillTransactionStorageKey(tabId), tabId);
  }

  async function loadRecoveryUnqueued(transactionId: string) {
    const session = await trustedStorage();
    if (!session) {
      return null;
    }
    const key = pendingAutofillRecoveryStorageKey(transactionId);
    let raw: unknown;
    try {
      raw = (await session.get(key))[key];
    } catch {
      return null;
    }
    const tabId =
      typeof raw === "object" &&
      raw !== null &&
      typeof (raw as { tabId?: unknown }).tabId === "number"
        ? ((raw as { tabId: number }).tabId)
        : -1;
    const transaction = await loadAtKeyUnqueued(key, tabId);
    return transaction &&
      transaction.transactionId === transactionId &&
      pendingAutofillStateIsRecoveryProtected(transaction.state)
      ? transaction
      : null;
  }

  async function claimAtKey(
    key: string,
    current: PendingAutofillTransaction
  ) {
    if (
      current.state !== "planned" &&
      current.state !== "persisting" &&
      !(
        current.state === "persist_conflict" &&
        "plan" in current &&
        current.conflict.retryable
      )
    ) {
      return null;
    }
    if (current.recoveryDeadlineAt <= now()) {
      return null;
    }
    if (
      current.state === "persisting" &&
      typeof current.leaseExpiresAt === "number" &&
      current.leaseExpiresAt > now()
    ) {
      return current;
    }
    const attemptId = createId();
    if (!isValidPendingAutofillToken(attemptId)) {
      return null;
    }
    const claimed = {
      ...current,
      state: "persisting" as const,
      attemptId,
      attemptCount:
        current.state === "persisting" ? (current.attemptCount ?? 0) + 1 : 1,
      lastAttemptAt: now(),
      leaseExpiresAt: now() + PENDING_AUTOFILL_ATTEMPT_LEASE_MS
    };
    return (await persistAtKey(key, claimed)) ? claimed : null;
  }

  async function recordConflictAtKey(
    key: string,
    current: PendingAutofillTransaction | null,
    binding: ConflictBinding
  ) {
    if (
      !current ||
      current.state !== "persisting" ||
      current.transactionId !== binding.transactionId ||
      current.operationId !== binding.operationId ||
      current.vaultId !== binding.vaultId ||
      expectedEntryId(current) !== binding.entryId
    ) {
      return null;
    }
    const conflict: PendingAutofillConflictTransaction = {
      version: PENDING_AUTOFILL_TRANSACTION_VERSION,
      transactionId: current.transactionId,
      state: "persist_conflict",
      tabId: current.tabId,
      origin: current.origin,
      submittedAt: current.submittedAt,
      vaultId: current.vaultId,
      operationId: current.operationId,
      plan: current.plan,
      recoveryDeadlineAt: current.recoveryDeadlineAt,
      conflict: binding.conflict
    };
    return (await persistAtKey(key, conflict)) ? conflict : null;
  }

  async function completeAtKey(
    key: string,
    current: PendingAutofillTransaction | null,
    binding: PersistBinding
  ) {
    if (
      current &&
      (current.state === "planned" || current.state === "persisting") &&
      current.transactionId === binding.transactionId &&
      current.operationId === binding.operationId &&
      current.vaultId === binding.vaultId &&
      expectedEntryId(current) === binding.entryId
    ) {
      const receipt = await writeCompletion(binding.transactionId, "persisted", {
        operationId: binding.operationId,
        vaultId: binding.vaultId,
        entryId: binding.entryId
      });
      if (!receipt) {
        return null;
      }
      const terminal = terminalTransaction(current, "persisted", {
        operationId: binding.operationId,
        entryId: binding.entryId
      });
      await scrubWalKey(key, terminal);
      return terminal;
    }
    const previous = await loadCompletionRecordUnqueued(binding.transactionId);
    const vaultIdHash = await hashVaultId(binding.vaultId);
    if (
      vaultIdHash === null ||
      previous?.outcome !== "expired_unknown" ||
      previous.operationId !== binding.operationId ||
      previous.entryId !== binding.entryId ||
      previous.vaultIdHash !== vaultIdHash
    ) {
      return null;
    }
    const receipt = await writeCompletion(binding.transactionId, "persisted", {
      operationId: binding.operationId,
      vaultId: binding.vaultId,
      entryId: binding.entryId
    });
    return receipt
      ? {
          version: PENDING_AUTOFILL_TRANSACTION_VERSION,
          transactionId: binding.transactionId,
          state: "persisted" as const,
          tabId: current?.tabId ?? -1,
          origin: current?.origin ?? "https://expired.invalid",
          operationId: binding.operationId,
          entryId: binding.entryId,
          completedAt: receipt.completedAt
        }
      : null;
  }

  async function terminalizeAtKey(
    key: string,
    current: PendingAutofillTransaction,
    outcome: "dismissed" | "expired"
  ) {
    const operationId =
      "operationId" in current ? current.operationId : undefined;
    const vaultId = "vaultId" in current ? current.vaultId : undefined;
    const completion = await writeCompletion(current.transactionId, outcome, {
      operationId,
      vaultId
    });
    if (!completion) {
      return null;
    }
    const terminal = terminalTransaction(current, outcome, { operationId });
    await scrubWalKey(key, terminal);
    return terminal;
  }

  async function planAtKey(
    key: string,
    current: PendingAutofillTransaction | null,
    transactionId: string,
    input: { vaultId: string; plan: PendingAutofillPlanInput | unknown }
  ) {
    if (
      !isValidPendingAutofillVaultId(input.vaultId) ||
      !current ||
      current.transactionId !== transactionId ||
      (current.state !== "captured" && current.state !== "persist_conflict") ||
      (current.state === "persist_conflict" && input.vaultId !== current.vaultId)
    ) {
      return null;
    }
    const existingPlan =
      current.state === "persist_conflict" && "plan" in current
        ? current.plan
        : null;
    const rawMode =
      typeof input.plan === "object" && input.plan !== null
        ? (input.plan as { mode?: unknown }).mode
        : undefined;
    let retainedPlannedEntryId =
      rawMode === "create" && existingPlan?.mode === "create"
        ? existingPlan.plannedEntryId
        : undefined;
    if (
      current.state === "persist_conflict" &&
      current.conflict.code === "planned_entry_id_collision"
    ) {
      retainedPlannedEntryId = undefined;
    }
    const preliminary =
      rawMode === "create"
        ? pendingAutofillPlanInputFromUnknown(
            input.plan,
            retainedPlannedEntryId ??
              "00000000-0000-4000-8000-000000000001"
          )
        : pendingAutofillPlanInputFromUnknown(input.plan);
    if (!preliminary) {
      return null;
    }
    if (
      canonicalHttpOrigin(preliminary.desiredFields.url) !== current.origin ||
      (preliminary.mode === "update" &&
        canonicalHttpOrigin(preliminary.expectedFields.url) !== current.origin)
    ) {
      return null;
    }
    const comparablePlan = pendingAutofillPlanInputFromUnknown(
      input.plan,
      retainedPlannedEntryId
    );
    if (
      existingPlan &&
      comparablePlan &&
      "vaultId" in current &&
      input.vaultId === current.vaultId &&
      plansEqual(existingPlan, comparablePlan)
    ) {
      return null;
    }
    const operationId = createId();
    if (!isCanonicalNonNilUuid(operationId)) {
      return null;
    }
    const plannedEntryId =
      preliminary.mode === "create"
        ? retainedPlannedEntryId ?? createId()
        : undefined;
    if (
      preliminary.mode === "create" &&
      !isCanonicalNonNilUuid(plannedEntryId)
    ) {
      return null;
    }
    const plan = pendingAutofillPlanInputFromUnknown(
      input.plan,
      plannedEntryId
    );
    if (!plan) {
      return null;
    }
    const submittedAt =
      current.state === "captured"
        ? current.submission.submittedAt
        : current.submittedAt;
    const recoveryDeadlineAt =
      current.state === "captured"
        ? Math.min(
            now() + PENDING_AUTOFILL_RECOVERY_TTL_MS,
            submittedAt + PENDING_AUTOFILL_RECOVERY_TTL_MS
          )
        : current.recoveryDeadlineAt;
    const planned: PendingAutofillTransaction = {
      version: PENDING_AUTOFILL_TRANSACTION_VERSION,
      transactionId,
      state: "planned",
      tabId: current.tabId,
      origin: current.origin,
      submittedAt,
      vaultId: input.vaultId,
      operationId,
      plan,
      recoveryDeadlineAt
    };
    return (await persistAtKey(key, planned)) ? planned : null;
  }

  return {
    loadForTab(tabId: number) {
      return exclusive(() => loadForTabUnqueued(tabId));
    },

    loadForTabUrl(tabId: number, tabUrl: string) {
      return exclusive(async () => {
        const current = await loadForTabUnqueued(tabId);
        if (!current) {
          return null;
        }
        if (canonicalHttpOrigin(tabUrl) === current.origin) {
          return current;
        }
        if (pendingAutofillStateIsRecoveryProtected(current.state)) {
          return null;
        }
        await terminalizeAtKey(
          pendingAutofillTransactionStorageKey(tabId),
          current,
          "dismissed"
        );
        return null;
      });
    },

    putCaptured(tabId: number, value: unknown) {
      return exclusive(async () => {
        const session = await trustedStorage();
        const submission = pendingAutofillSubmissionFromUnknown(value);
        const origin = submission ? canonicalHttpOrigin(submission.url) : null;
        const currentTime = now();
        if (
          !session ||
          !Number.isSafeInteger(tabId) ||
          tabId < 0 ||
          !submission ||
          origin === null ||
          submission.submittedAt > currentTime ||
          submission.submittedAt + PENDING_AUTOFILL_TRANSACTION_TTL_MS <=
            currentTime
        ) {
          return null;
        }
        const existing = await loadForTabUnqueued(tabId);
        if (existing && existing.state !== "captured") {
          return null;
        }
        const transactionId = createId();
        if (!isValidPendingAutofillToken(transactionId)) {
          return null;
        }
        const captured: PendingAutofillTransaction = {
          version: PENDING_AUTOFILL_TRANSACTION_VERSION,
          transactionId,
          state: "captured",
          tabId,
          origin,
          submission,
          expiresAt:
            submission.submittedAt + PENDING_AUTOFILL_TRANSACTION_TTL_MS
        };
        if (!pendingWalFits(captured)) {
          return null;
        }
        try {
          await session.set({
            [pendingAutofillTransactionStorageKey(tabId)]: captured
          });
          return captured;
        } catch {
          return null;
        }
      });
    },

    plan(
      tabId: number,
      transactionId: string,
      input: { vaultId: string; plan: PendingAutofillPlanInput | unknown }
    ) {
      return exclusive(async () =>
        planAtKey(
          pendingAutofillTransactionStorageKey(tabId),
          await loadForTabUnqueued(tabId),
          transactionId,
          input
        )
      );
    },

    claimForTab(tabId: number, transactionId: string) {
      return exclusive(async () => {
        const current = await loadForTabUnqueued(tabId);
        return current?.transactionId === transactionId
          ? claimAtKey(pendingAutofillTransactionStorageKey(tabId), current)
          : null;
      });
    },

    recordConflictForTab(tabId: number, binding: ConflictBinding) {
      return exclusive(async () =>
        recordConflictAtKey(
          pendingAutofillTransactionStorageKey(tabId),
          await loadForTabUnqueued(tabId),
          binding
        )
      );
    },

    completeForTab(tabId: number, binding: PersistBinding) {
      return exclusive(async () =>
        completeAtKey(
          pendingAutofillTransactionStorageKey(tabId),
          await loadForTabUnqueued(tabId),
          binding
        )
      );
    },

    detachForRecovery(tabId: number, transactionId: string) {
      return exclusive(async () => {
        const session = await trustedStorage();
        const current = await loadForTabUnqueued(tabId);
        if (
          !session ||
          !current ||
          current.transactionId !== transactionId ||
          !pendingAutofillStateIsRecoveryProtected(current.state)
        ) {
          return null;
        }
        const recoveryKey = pendingAutofillRecoveryStorageKey(transactionId);
        try {
          await session.set({
            [recoveryKey]: current,
            [pendingAutofillTransactionStorageKey(tabId)]: {
              version: PENDING_AUTOFILL_TRANSACTION_VERSION,
              recoveryTransactionId: transactionId
            }
          });
          try {
            await session.remove(pendingAutofillTransactionStorageKey(tabId));
          } catch {
            // The pointer is non-secret and the recovery WAL is authoritative.
          }
          return current;
        } catch {
          return null;
        }
      });
    },

    loadRecovery(transactionId: string) {
      return exclusive(() => loadRecoveryUnqueued(transactionId));
    },

    planRecovery(
      transactionId: string,
      input: { vaultId: string; plan: PendingAutofillPlanInput | unknown }
    ) {
      return exclusive(async () =>
        planAtKey(
          pendingAutofillRecoveryStorageKey(transactionId),
          await loadRecoveryUnqueued(transactionId),
          transactionId,
          input
        )
      );
    },

    claimRecovery(transactionId: string) {
      return exclusive(async () => {
        const current = await loadRecoveryUnqueued(transactionId);
        return current
          ? claimAtKey(pendingAutofillRecoveryStorageKey(transactionId), current)
          : null;
      });
    },

    recordConflictRecovery(transactionId: string, binding: ConflictBinding) {
      return exclusive(async () =>
        recordConflictAtKey(
          pendingAutofillRecoveryStorageKey(transactionId),
          await loadRecoveryUnqueued(transactionId),
          binding
        )
      );
    },

    completeRecovery(transactionId: string, binding: PersistBinding) {
      return exclusive(async () =>
        completeAtKey(
          pendingAutofillRecoveryStorageKey(transactionId),
          await loadRecoveryUnqueued(transactionId),
          binding
        )
      );
    },

    loadCompletion(transactionId: string) {
      return exclusive(async () => {
        const completion = await loadCompletionRecordUnqueued(transactionId);
        if (!completion || completion.expiresAt > now()) {
          return completion;
        }
        const session = await trustedStorage();
        if (session) {
          const items = await session.get(null);
          if (storageHasTransactionWal(items, transactionId)) {
            return completion;
          }
          try {
            await session.remove(pendingAutofillCompletionStorageKey(transactionId));
          } catch {
            // The expired receipt is already non-secret.
          }
        }
        return null;
      });
    },

    dismissForTab(tabId: number, transactionId: string) {
      return exclusive(async () => {
        const current = await loadForTabUnqueued(tabId);
        return current?.transactionId === transactionId &&
          current.state !== "persisting"
          ? terminalizeAtKey(
              pendingAutofillTransactionStorageKey(tabId),
              current,
              "dismissed"
            )
          : null;
      });
    },

    dismissRecovery(transactionId: string) {
      return exclusive(async () => {
        const current = await loadRecoveryUnqueued(transactionId);
        return current && current.state !== "persisting"
          ? terminalizeAtKey(
              pendingAutofillRecoveryStorageKey(transactionId),
              current,
              "dismissed"
            )
          : null;
      });
    },

    listTabTransactions() {
      return exclusive(async () => {
        const session = await trustedStorage();
        if (!session) {
          return [];
        }
        const items = await session.get(null);
        const transactions: PendingAutofillTransaction[] = [];
        for (const key of Object.keys(items)) {
          const tabId = tabIdFromStorageKey(key);
          if (tabId === null) {
            continue;
          }
          const transaction = await loadForTabUnqueued(tabId);
          if (transaction) {
            transactions.push(transaction);
          }
        }
        return transactions;
      });
    },

    listProtectedTabTransactions() {
      return exclusive(async () => {
        const session = await trustedStorage();
        if (!session) {
          return [];
        }
        const items = await session.get(null);
        const transactions: PendingAutofillTransaction[] = [];
        for (const key of Object.keys(items)) {
          const tabId = tabIdFromStorageKey(key);
          if (tabId === null) {
            continue;
          }
          const transaction = await loadForTabUnqueued(tabId);
          if (
            transaction &&
            pendingAutofillStateIsRecoveryProtected(transaction.state)
          ) {
            transactions.push(transaction);
          }
        }
        return transactions;
      });
    },

    listRecoveries() {
      return exclusive(async () => {
        const session = await trustedStorage();
        if (!session) {
          return [];
        }
        const items = await session.get(null);
        const transactions: PendingAutofillTransaction[] = [];
        for (const key of Object.keys(items)) {
          const transactionId = transactionIdFromRecoveryStorageKey(key);
          if (!transactionId) {
            continue;
          }
          const transaction = await loadRecoveryUnqueued(transactionId);
          if (transaction) {
            transactions.push(transaction);
          }
        }
        return transactions;
      });
    },

    clearUnprotectedForTab(tabId: number, transactionId: string) {
      return exclusive(async () => {
        const current = await loadForTabUnqueued(tabId);
        if (
          !current ||
          current.transactionId !== transactionId ||
          pendingAutofillStateIsRecoveryProtected(current.state)
        ) {
          return false;
        }
        return Boolean(
          await terminalizeAtKey(
            pendingAutofillTransactionStorageKey(tabId),
            current,
            "dismissed"
          )
        );
      });
    },

    cleanupCompletedTransactions() {
      return exclusive(async () => {
        const session = await trustedStorage();
        if (!session) {
          return;
        }
        const items = await session.get(null);
        for (const [key, value] of Object.entries(items)) {
          const transactionId = rawTransactionId(value);
          if (
            (tabIdFromStorageKey(key) !== null ||
              transactionIdFromRecoveryStorageKey(key) !== null) &&
            isValidPendingAutofillToken(transactionId) &&
            (await loadCompletionRecordUnqueued(transactionId))
          ) {
            const tabId = tabIdFromStorageKey(key) ??
              (typeof value === "object" &&
              value !== null &&
              typeof (value as { tabId?: unknown }).tabId === "number"
                ? (value as { tabId: number }).tabId
                : -1);
            const origin =
              typeof value === "object" &&
              value !== null &&
              typeof (value as { origin?: unknown }).origin === "string"
                ? (value as { origin: string }).origin
                : "https://completed.invalid";
            await scrubWalKey(
              key,
              terminalTransaction(
                { transactionId, tabId, origin },
                "persisted"
              )
            );
          }
        }
      });
    },

    clearExpired(activeClaims: ReadonlySet<string> = new Set()) {
      return exclusive(async () => {
        const session = await trustedStorage();
        if (!session) {
          return null;
        }
        let items: Record<string, unknown>;
        try {
          items = await session.get(null);
        } catch {
          return null;
        }
        const currentTime = now();
        let nextSweepAt: number | null = null;
        for (const [key, value] of Object.entries(items)) {
          const tabId = tabIdFromStorageKey(key);
          const recoveryTransactionId = transactionIdFromRecoveryStorageKey(key);
          if (tabId === null && recoveryTransactionId === null) {
            continue;
          }
          const deadline = rawDeadline(value, currentTime);
          const transactionId = rawTransactionId(value);
          const operationId = rawOperationId(value);
          const vaultId = rawVaultId(value);
          const entryId = rawExpectedEntryId(value);
          if (deadline === null) {
            continue;
          }
          if (!isValidPendingAutofillToken(transactionId)) {
            if (deadline <= currentTime) {
              await scrubInvalidWalKey(key);
            }
            continue;
          }
          const existingCompletion =
            await loadCompletionRecordUnqueued(transactionId);
          if (existingCompletion) {
            const storedTabId =
              tabId ??
              (typeof value === "object" &&
              value !== null &&
              typeof (value as { tabId?: unknown }).tabId === "number"
                ? (value as { tabId: number }).tabId
                : -1);
            const origin =
              typeof value === "object" &&
              value !== null &&
              typeof (value as { origin?: unknown }).origin === "string"
                ? (value as { origin: string }).origin
                : "https://completed.invalid";
            await scrubWalKey(
              key,
              terminalTransaction(
                { transactionId, tabId: storedTabId, origin },
                existingCompletion.outcome === "persisted"
                  ? "persisted"
                  : existingCompletion.outcome === "dismissed"
                    ? "dismissed"
                    : "expired",
                {
                  operationId: existingCompletion.operationId,
                  entryId: existingCompletion.entryId
                }
              )
            );
            continue;
          }
          if (deadline > currentTime) {
            continue;
          }
          const leaseExpiresAt =
            typeof value === "object" &&
            value !== null &&
            typeof (value as { leaseExpiresAt?: unknown }).leaseExpiresAt ===
              "number"
              ? (value as { leaseExpiresAt: number }).leaseExpiresAt
              : 0;
          if (
            isValidPendingAutofillToken(operationId) &&
            activeClaims.has(`${transactionId}:${operationId}`) &&
            leaseExpiresAt > currentTime
          ) {
            nextSweepAt =
              nextSweepAt === null
                ? leaseExpiresAt
                : Math.min(nextSweepAt, leaseExpiresAt);
            continue;
          }
          const outcome = isValidPendingAutofillToken(operationId)
            ? "expired_unknown"
            : "expired";
          const completion = await writeCompletion(transactionId, outcome, {
            operationId: isValidPendingAutofillToken(operationId) ? operationId : undefined,
            vaultId: typeof vaultId === "string" ? vaultId : undefined,
            entryId
          });
          if (!completion) {
            continue;
          }
          const origin =
            typeof value === "object" &&
            value !== null &&
            typeof (value as { origin?: unknown }).origin === "string"
              ? (value as { origin: string }).origin
              : "https://expired.invalid";
          const storedTabId =
            tabId ??
            (typeof value === "object" &&
            value !== null &&
            typeof (value as { tabId?: unknown }).tabId === "number"
              ? (value as { tabId: number }).tabId
              : -1);
          await scrubWalKey(
            key,
            terminalTransaction(
              { transactionId, tabId: storedTabId, origin },
              "expired",
              {
                operationId: isValidPendingAutofillToken(operationId)
                  ? operationId
                  : undefined
              }
            )
          );
        }

        const after = await session.get(null);
        const walTransactionIds = new Set(
          Object.entries(after).flatMap(([key, value]) =>
            tabIdFromStorageKey(key) !== null ||
            transactionIdFromRecoveryStorageKey(key) !== null
              ? isValidPendingAutofillToken(rawTransactionId(value))
                ? [rawTransactionId(value) as string]
                : []
              : []
          )
        );
        const expiredCompletionKeys = Object.entries(after).flatMap(
          ([key, value]) => {
            const transactionId = transactionIdFromCompletionStorageKey(key);
            const completion = transactionId
              ? completionRecordFromUnknown(value, transactionId)
              : null;
            return completion &&
              completion.expiresAt <= currentTime &&
              !walTransactionIds.has(completion.transactionId)
              ? [key]
              : [];
          }
        );
        if (expiredCompletionKeys.length > 0) {
          await session.remove(expiredCompletionKeys);
        }
        return nextSweepAt;
      });
    }
  };
}

export type PendingAutofillSubmissionStore = ReturnType<
  typeof createPendingAutofillSubmissionStore
>;
