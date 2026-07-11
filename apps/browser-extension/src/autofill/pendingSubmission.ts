import type { AutofillPersistConflictCode } from "@vaultkern/runtime-web-client";

import { canonicalHttpOrigin } from "./originPolicy";

export interface PendingAutofillSubmission {
  url: string;
  username: string;
  password: string;
  newPassword?: string;
  saveOnly?: boolean;
  submittedAt: number;
}

export const PENDING_AUTOFILL_TRANSACTION_VERSION = 2 as const;
export const PENDING_AUTOFILL_RECOVERY_TTL_MS = 15 * 60 * 1_000;

export type PendingAutofillTransactionState =
  | "captured"
  | "planned"
  | "persisting"
  | "persist_conflict"
  | "persisted"
  | "dismissed"
  | "expired";

export interface PendingAutofillDesiredFields {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpUri: string | null;
  customFields: Array<{ key: string; value: string; protected: boolean }>;
}

export type PendingAutofillPlan =
  | {
      mode: "update";
      entryId: string;
      expectedFields: PendingAutofillDesiredFields;
      desiredFields: PendingAutofillDesiredFields;
    }
  | {
      mode: "create";
      parentGroupId: string;
      plannedEntryId: string;
      expectedMatchingEntryIds: string[];
      desiredFields: PendingAutofillDesiredFields;
    };

export type PendingAutofillPlanInput =
  | Extract<PendingAutofillPlan, { mode: "update" }>
  | Omit<Extract<PendingAutofillPlan, { mode: "create" }>, "plannedEntryId">;

export interface PendingAutofillPersistConflict {
  code: AutofillPersistConflictCode | "concurrent_vault_changes";
  retryable: boolean;
}

interface PendingAutofillBase {
  version: typeof PENDING_AUTOFILL_TRANSACTION_VERSION;
  transactionId: string;
  tabId: number;
  origin: string;
}

export interface PendingAutofillCapturedTransaction
  extends PendingAutofillBase {
  state: "captured";
  submission: PendingAutofillSubmission;
  expiresAt: number;
}

interface PendingAutofillExecutableBase extends PendingAutofillBase {
  submittedAt: number;
  vaultId: string;
  operationId: string;
  plan: PendingAutofillPlan;
  recoveryDeadlineAt: number;
}

export interface PendingAutofillPlannedTransaction
  extends PendingAutofillExecutableBase {
  state: "planned";
}

export interface PendingAutofillPersistingTransaction
  extends PendingAutofillExecutableBase {
  state: "persisting";
  attemptId?: string;
  attemptCount?: number;
  lastAttemptAt?: number;
  leaseExpiresAt?: number;
}

export interface PendingAutofillConflictTransaction
  extends PendingAutofillExecutableBase {
  state: "persist_conflict";
  conflict: PendingAutofillPersistConflict;
}

export interface PendingAutofillLegacyConflictTransaction
  extends PendingAutofillBase {
  state: "persist_conflict";
  submittedAt: number;
  vaultId: string;
  operationId: string;
  recoveryDeadlineAt: number;
  conflict: {
    code: "legacy_create_outcome_ambiguous";
    retryable: false;
  };
}

export interface PendingAutofillTerminalTransaction
  extends PendingAutofillBase {
  state: "persisted" | "dismissed" | "expired";
  operationId?: string;
  entryId?: string;
  completedAt: number;
}

export type PendingAutofillTransaction =
  | PendingAutofillCapturedTransaction
  | PendingAutofillPlannedTransaction
  | PendingAutofillPersistingTransaction
  | PendingAutofillConflictTransaction
  | PendingAutofillLegacyConflictTransaction
  | PendingAutofillTerminalTransaction;

export type PendingAutofillExecutableTransaction =
  | PendingAutofillPlannedTransaction
  | PendingAutofillPersistingTransaction
  | PendingAutofillConflictTransaction;

const CANONICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_FIELD_BYTES = 1_048_576;
const MAX_TOTP_URI_BYTES = 8 * 1_024;
const MAX_CUSTOM_KEY_BYTES = 256;
const MAX_CUSTOM_FIELDS = 128;
const MAX_ENTRY_FIELDS_BYTES = 8 * 1_024 * 1_024;
const MAX_MATCHING_ENTRY_IDS = 4_096;
const MAX_VAULT_ID_BYTES = 4 * 1_024;
const utf8Encoder = new TextEncoder();
const RESERVED_CUSTOM_FIELD_KEYS = new Set([
  "title",
  "username",
  "password",
  "url",
  "notes"
]);

export function isCanonicalNonNilUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value !== NIL_UUID &&
    CANONICAL_UUID.test(value)
  );
}

export function pendingAutofillStateIsRecoveryProtected(
  state: PendingAutofillTransactionState
) {
  return (
    state === "planned" ||
    state === "persisting" ||
    state === "persist_conflict"
  );
}

export function isValidPendingAutofillToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 16 &&
    value.length <= 128 &&
    value.trim() === value &&
    boundedUtf8Length(value, 128) !== null &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function boundedUtf8Length(value: string, maximum: number) {
  if (value.length > maximum || !isWellFormedUtf16(value)) {
    return null;
  }
  const bytes = utf8Encoder.encode(value).byteLength;
  return bytes <= maximum ? bytes : null;
}

function isWellFormedUtf16(value: string) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) {
        return false;
      }
      const trailing = value.charCodeAt(index + 1);
      if (trailing < 0xdc00 || trailing > 0xdfff) {
        return false;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isXml10Text(value: string) {
  return !/[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\u{10000}-\u{10ffff}]/u.test(
    value
  );
}

export function isValidPendingAutofillVaultId(
  value: unknown
): value is string {
  return (
    typeof value === "string" &&
    value !== "" &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    boundedUtf8Length(value, MAX_VAULT_ID_BYTES) !== null
  );
}

function entryFieldsFromUnknown(
  value: unknown,
  allowEmptyPassword = false
): PendingAutofillDesiredFields | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Partial<PendingAutofillDesiredFields>;
  if (
    typeof candidate.title !== "string" ||
    typeof candidate.username !== "string" ||
    typeof candidate.password !== "string" ||
    (!allowEmptyPassword && candidate.password === "") ||
    typeof candidate.url !== "string" ||
    typeof candidate.notes !== "string" ||
    (candidate.totpUri !== null && typeof candidate.totpUri !== "string") ||
    !Array.isArray(candidate.customFields)
  ) {
    return null;
  }
  let totalBytes = 0;
  for (const value of [
    candidate.title,
    candidate.username,
    candidate.password,
    candidate.url,
    candidate.notes
  ]) {
    const bytes = boundedUtf8Length(value, MAX_FIELD_BYTES);
    if (bytes === null) {
      return null;
    }
    totalBytes += bytes;
  }
  if (canonicalHttpOrigin(candidate.url) === null) {
    return null;
  }
  if (candidate.totpUri !== null) {
    const bytes = boundedUtf8Length(candidate.totpUri, MAX_TOTP_URI_BYTES);
    if (bytes === null) {
      return null;
    }
    totalBytes += bytes;
  }
  if (
    candidate.customFields.length > MAX_CUSTOM_FIELDS ||
    totalBytes > MAX_ENTRY_FIELDS_BYTES
  ) {
    return null;
  }
  const customFields: PendingAutofillDesiredFields["customFields"] = [];
  const customFieldKeys = new Set<string>();
  for (const field of candidate.customFields) {
    if (typeof field !== "object" || field === null || Array.isArray(field)) {
      return null;
    }
    const custom = field as {
      key?: unknown;
      value?: unknown;
      protected?: unknown;
    };
    if (
      typeof custom.key !== "string" ||
      typeof custom.value !== "string" ||
      typeof custom.protected !== "boolean"
    ) {
      return null;
    }
    const keyBytes = boundedUtf8Length(custom.key, MAX_CUSTOM_KEY_BYTES);
    const valueBytes = boundedUtf8Length(custom.value, MAX_FIELD_BYTES);
    if (
      keyBytes === null ||
      valueBytes === null ||
      custom.key === "" ||
      custom.key.trim() !== custom.key ||
      /\p{Cc}/u.test(custom.key) ||
      !isXml10Text(custom.key) ||
      RESERVED_CUSTOM_FIELD_KEYS.has(custom.key.toLowerCase()) ||
      customFieldKeys.has(custom.key)
    ) {
      return null;
    }
    customFieldKeys.add(custom.key);
    totalBytes += keyBytes + valueBytes;
    if (totalBytes > MAX_ENTRY_FIELDS_BYTES) {
      return null;
    }
    customFields.push({
      key: custom.key,
      value: custom.value,
      protected: custom.protected
    });
  }
  return {
    title: candidate.title,
    username: candidate.username,
    password: candidate.password,
    url: candidate.url,
    notes: candidate.notes,
    totpUri: candidate.totpUri,
    customFields
  };
}

export function pendingAutofillPlanFromUnknown(
  value: unknown
): PendingAutofillPlan | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as {
    mode?: unknown;
    entryId?: unknown;
    parentGroupId?: unknown;
    plannedEntryId?: unknown;
    expectedMatchingEntryIds?: unknown;
    expectedFields?: unknown;
    desiredFields?: unknown;
  };
  const desiredFields = entryFieldsFromUnknown(candidate.desiredFields);
  if (!desiredFields) {
    return null;
  }
  if (candidate.mode === "update") {
    const expectedFields = entryFieldsFromUnknown(candidate.expectedFields, true);
    if (!isCanonicalNonNilUuid(candidate.entryId) || !expectedFields) {
      return null;
    }
    return {
      mode: "update",
      entryId: candidate.entryId,
      expectedFields,
      desiredFields
    };
  }
  if (
    candidate.mode !== "create" ||
    !isCanonicalNonNilUuid(candidate.parentGroupId) ||
    !isCanonicalNonNilUuid(candidate.plannedEntryId) ||
    !Array.isArray(candidate.expectedMatchingEntryIds) ||
    candidate.expectedMatchingEntryIds.length > MAX_MATCHING_ENTRY_IDS
  ) {
    return null;
  }
  const matchingIds: string[] = [];
  const uniqueMatchingIds = new Set<string>();
  for (const entryId of candidate.expectedMatchingEntryIds) {
    if (!isCanonicalNonNilUuid(entryId) || uniqueMatchingIds.has(entryId)) {
      return null;
    }
    uniqueMatchingIds.add(entryId);
    matchingIds.push(entryId);
  }
  matchingIds.sort();
  return {
    mode: "create",
    parentGroupId: candidate.parentGroupId,
    plannedEntryId: candidate.plannedEntryId,
    expectedMatchingEntryIds: matchingIds,
    desiredFields
  };
}

export function pendingAutofillPlanInputFromUnknown(
  value: unknown,
  plannedEntryId?: string
): PendingAutofillPlan | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as { mode?: unknown };
  if (candidate.mode === "update") {
    return pendingAutofillPlanFromUnknown(value);
  }
  return pendingAutofillPlanFromUnknown({
    ...value,
    plannedEntryId
  });
}

export function pendingAutofillSubmissionFromUnknown(
  value: unknown
): PendingAutofillSubmission | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Partial<PendingAutofillSubmission>;
  if (
    typeof candidate.url !== "string" ||
    typeof candidate.username !== "string" ||
    typeof candidate.password !== "string" ||
    candidate.password === "" ||
    (candidate.newPassword !== undefined &&
      typeof candidate.newPassword !== "string") ||
    (candidate.saveOnly !== undefined &&
      typeof candidate.saveOnly !== "boolean") ||
    typeof candidate.submittedAt !== "number" ||
    !Number.isSafeInteger(candidate.submittedAt) ||
    candidate.submittedAt < 0
  ) {
    return null;
  }
  const submissionFields = [
    candidate.url,
    candidate.username,
    candidate.password,
    ...(typeof candidate.newPassword === "string"
      ? [candidate.newPassword]
      : [])
  ];
  if (
    submissionFields.some(
      (field) => boundedUtf8Length(field, MAX_FIELD_BYTES) === null
    ) ||
    candidate.url.trim() === "" ||
    canonicalHttpOrigin(candidate.url) === null
  ) {
    return null;
  }
  return {
    url: candidate.url,
    username: candidate.username,
    password: candidate.password,
    ...(typeof candidate.newPassword === "string" && candidate.newPassword !== ""
      ? { newPassword: candidate.newPassword }
      : {}),
    ...(candidate.saveOnly === true ? { saveOnly: true } : {}),
    submittedAt: candidate.submittedAt
  };
}

function conflictFromUnknown(value: unknown): PendingAutofillPersistConflict | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as { code?: unknown; retryable?: unknown };
  const codes: ReadonlySet<unknown> = new Set([
    "active_vault_mismatch",
    "update_precondition_failed",
    "create_matching_set_changed",
    "planned_entry_id_collision",
    "operation_binding_mismatch",
    "source_changed_retry_exhausted",
    "legacy_create_outcome_ambiguous",
    "concurrent_vault_changes"
  ]);
  if (!codes.has(candidate.code) || typeof candidate.retryable !== "boolean") {
    return null;
  }
  const retryable =
    candidate.code === "active_vault_mismatch" ||
    candidate.code === "source_changed_retry_exhausted";
  return candidate.retryable === retryable
    ? {
        code: candidate.code as PendingAutofillPersistConflict["code"],
        retryable
      }
    : null;
}

export function pendingAutofillTransactionFromUnknown(
  value: unknown,
  expectedTabId: number,
  now: number,
  expectedCaptureTtlMs: number
): PendingAutofillTransaction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== PENDING_AUTOFILL_TRANSACTION_VERSION ||
    !isValidPendingAutofillToken(candidate.transactionId) ||
    candidate.tabId !== expectedTabId ||
    typeof candidate.origin !== "string" ||
    canonicalHttpOrigin(candidate.origin) !== candidate.origin
  ) {
    return null;
  }
  const base: PendingAutofillBase = {
    version: PENDING_AUTOFILL_TRANSACTION_VERSION,
    transactionId: candidate.transactionId,
    tabId: expectedTabId,
    origin: candidate.origin
  };
  if (candidate.state === "captured") {
    const submission = pendingAutofillSubmissionFromUnknown(candidate.submission);
    if (
      !submission ||
      canonicalHttpOrigin(submission.url) !== base.origin ||
      submission.submittedAt > now ||
      typeof candidate.expiresAt !== "number" ||
      !Number.isSafeInteger(candidate.expiresAt) ||
      candidate.expiresAt !== submission.submittedAt + expectedCaptureTtlMs ||
      candidate.expiresAt <= now
    ) {
      return null;
    }
    return {
      ...base,
      state: "captured",
      submission,
      expiresAt: candidate.expiresAt
    };
  }
  if (
    candidate.state === "persisted" ||
    candidate.state === "dismissed" ||
    candidate.state === "expired"
  ) {
    if (
      typeof candidate.completedAt !== "number" ||
      !Number.isSafeInteger(candidate.completedAt)
    ) {
      return null;
    }
    return {
      ...base,
      state: candidate.state,
      ...(isValidPendingAutofillToken(candidate.operationId)
        ? { operationId: candidate.operationId }
        : {}),
      ...(isCanonicalNonNilUuid(candidate.entryId)
        ? { entryId: candidate.entryId }
        : {}),
      completedAt: candidate.completedAt
    };
  }
  const submittedAt = candidate.submittedAt;
  const recoveryDeadlineAt = candidate.recoveryDeadlineAt;
  const conflict = conflictFromUnknown(candidate.conflict);
  if (
    (candidate.state !== "planned" &&
      candidate.state !== "persisting" &&
      candidate.state !== "persist_conflict") ||
    typeof submittedAt !== "number" ||
    !Number.isSafeInteger(submittedAt) ||
    submittedAt < 0 ||
    submittedAt > now ||
    typeof recoveryDeadlineAt !== "number" ||
    !Number.isSafeInteger(recoveryDeadlineAt) ||
    recoveryDeadlineAt < submittedAt ||
    recoveryDeadlineAt > submittedAt + PENDING_AUTOFILL_RECOVERY_TTL_MS ||
    !isValidPendingAutofillToken(candidate.operationId) ||
    !isValidPendingAutofillVaultId(candidate.vaultId)
  ) {
    return null;
  }
  const plan = pendingAutofillPlanFromUnknown(candidate.plan);
  if (!plan) {
    if (
      candidate.state === "persist_conflict" &&
      conflict?.code === "legacy_create_outcome_ambiguous" &&
      conflict.retryable === false
    ) {
      return {
        ...base,
        state: "persist_conflict",
        submittedAt,
        vaultId: candidate.vaultId,
        operationId: candidate.operationId,
        recoveryDeadlineAt,
        conflict: {
          code: "legacy_create_outcome_ambiguous",
          retryable: false
        }
      };
    }
    return null;
  }
  if (
    canonicalHttpOrigin(plan.desiredFields.url) !== base.origin ||
    (plan.mode === "update" &&
      canonicalHttpOrigin(plan.expectedFields.url) !== base.origin)
  ) {
    return null;
  }
  const executable = {
    ...base,
    submittedAt,
    vaultId: candidate.vaultId,
    operationId: candidate.operationId,
    plan,
    recoveryDeadlineAt
  };
  if (candidate.state === "planned") {
    return { ...executable, state: "planned" };
  }
  if (candidate.state === "persist_conflict") {
    return conflict
      ? { ...executable, state: "persist_conflict", conflict }
      : null;
  }
  const diagnostics = [
    candidate.attemptId,
    candidate.attemptCount,
    candidate.lastAttemptAt,
    candidate.leaseExpiresAt
  ];
  if (diagnostics.some((item) => item !== undefined)) {
    if (
      !isValidPendingAutofillToken(candidate.attemptId) ||
      typeof candidate.attemptCount !== "number" ||
      !Number.isSafeInteger(candidate.attemptCount) ||
      candidate.attemptCount < 1 ||
      typeof candidate.lastAttemptAt !== "number" ||
      !Number.isSafeInteger(candidate.lastAttemptAt) ||
      typeof candidate.leaseExpiresAt !== "number" ||
      !Number.isSafeInteger(candidate.leaseExpiresAt)
    ) {
      return null;
    }
    return {
      ...executable,
      state: "persisting",
      attemptId: candidate.attemptId,
      attemptCount: candidate.attemptCount,
      lastAttemptAt: candidate.lastAttemptAt,
      leaseExpiresAt: candidate.leaseExpiresAt
    };
  }
  return { ...executable, state: "persisting" };
}
