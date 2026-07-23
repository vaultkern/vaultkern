import { canonicalHttpOrigin } from "./originPolicy";

export interface PendingAutofillSubmission {
  url: string;
  username: string;
  password: string;
  newPassword?: string;
  saveOnly?: boolean;
  submittedAt: number;
}

export interface PendingAutofillDesiredFields {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpUri: string | null;
  customFields: Array<{ key: string; value: string; protected: boolean }>;
}

export interface PendingAutofillUpdateFields {
  username: string;
  password: string;
  url: string;
}

export const PENDING_AUTOFILL_TRANSACTION_VERSION = 2 as const;

export interface PendingAutofillCapturedTransaction {
  version: typeof PENDING_AUTOFILL_TRANSACTION_VERSION;
  transactionId: string;
  state: "captured";
  tabId: number;
  origin: string;
  submission: PendingAutofillSubmission;
  expiresAt: number;
}

export type PendingAutofillTransaction = PendingAutofillCapturedTransaction;

const MAX_CAPTURE_FIELD_BYTES = 1_048_576;
const MAX_TRANSACTION_ID_BYTES = 128;
const utf8Encoder = new TextEncoder();

function boundedUtf8(value: string, maximum: number) {
  if (value.length > maximum || !isWellFormedUtf16(value)) {
    return false;
  }
  return utf8Encoder.encode(value).byteLength <= maximum;
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

export function isValidPendingAutofillToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 16 &&
    value.length <= MAX_TRANSACTION_ID_BYTES &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    boundedUtf8(value, MAX_TRANSACTION_ID_BYTES)
  );
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
    canonicalHttpOrigin(candidate.url) === null ||
    typeof candidate.username !== "string" ||
    typeof candidate.password !== "string" ||
    candidate.password === "" ||
    (candidate.newPassword !== undefined &&
      (typeof candidate.newPassword !== "string" ||
        candidate.newPassword === "")) ||
    (candidate.saveOnly !== undefined &&
      typeof candidate.saveOnly !== "boolean") ||
    typeof candidate.submittedAt !== "number" ||
    !Number.isSafeInteger(candidate.submittedAt) ||
    candidate.submittedAt < 0
  ) {
    return null;
  }
  for (const field of [
    candidate.url,
    candidate.username,
    candidate.password,
    candidate.newPassword
  ]) {
    if (
      typeof field === "string" &&
      !boundedUtf8(field, MAX_CAPTURE_FIELD_BYTES)
    ) {
      return null;
    }
  }
  return {
    url: candidate.url,
    username: candidate.username,
    password: candidate.password,
    ...(candidate.newPassword === undefined
      ? {}
      : { newPassword: candidate.newPassword }),
    ...(candidate.saveOnly === true ? { saveOnly: true } : {}),
    submittedAt: candidate.submittedAt
  };
}

export function pendingAutofillTransactionFromUnknown(
  value: unknown,
  expectedTabId: number,
  currentTime: number,
  maximumTtlMs: number
): PendingAutofillTransaction | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== PENDING_AUTOFILL_TRANSACTION_VERSION ||
    candidate.state !== "captured" ||
    !isValidPendingAutofillToken(candidate.transactionId) ||
    candidate.tabId !== expectedTabId ||
    typeof candidate.origin !== "string" ||
    typeof candidate.expiresAt !== "number" ||
    !Number.isSafeInteger(candidate.expiresAt)
  ) {
    return null;
  }
  const submission = pendingAutofillSubmissionFromUnknown(candidate.submission);
  const origin = submission ? canonicalHttpOrigin(submission.url) : null;
  if (
    !submission ||
    origin === null ||
    candidate.origin !== origin ||
    submission.submittedAt > currentTime ||
    candidate.expiresAt <= currentTime ||
    candidate.expiresAt > submission.submittedAt + maximumTtlMs
  ) {
    return null;
  }
  return {
    version: PENDING_AUTOFILL_TRANSACTION_VERSION,
    transactionId: candidate.transactionId,
    state: "captured",
    tabId: expectedTabId,
    origin,
    submission,
    expiresAt: candidate.expiresAt
  };
}
