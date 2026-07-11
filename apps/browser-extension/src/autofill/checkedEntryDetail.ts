import type { EntryDetail } from "@vaultkern/runtime-web-client";

function isOptionalString(value: unknown) {
  return value === undefined || value === null || typeof value === "string";
}

function hasValidCustomFields(value: unknown) {
  return (
    value === undefined ||
    (Array.isArray(value) &&
      value.every(
        (field) =>
          typeof field === "object" &&
          field !== null &&
          typeof (field as { key?: unknown }).key === "string" &&
          typeof (field as { value?: unknown }).value === "string" &&
          typeof (field as { protected?: unknown }).protected === "boolean"
      ))
  );
}

export function checkedEntryDetail(
  value: unknown,
  expectedId: string | null,
  createError: () => Error
): EntryDetail {
  if (typeof value !== "object" || value === null) {
    throw createError();
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.type !== "entry_detail" ||
    typeof candidate.id !== "string" ||
    candidate.id.trim() === "" ||
    (expectedId !== null && candidate.id !== expectedId) ||
    typeof candidate.title !== "string" ||
    typeof candidate.username !== "string" ||
    typeof candidate.password !== "string" ||
    typeof candidate.url !== "string" ||
    typeof candidate.notes !== "string" ||
    !isOptionalString(candidate.totp) ||
    !isOptionalString(candidate.totpUri) ||
    !hasValidCustomFields(candidate.customFields)
  ) {
    throw createError();
  }
  return candidate as unknown as EntryDetail;
}
