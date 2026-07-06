export interface PendingAutofillSubmission {
  url: string;
  username: string;
  password: string;
  newPassword?: string;
  submittedAt: number;
}

export function pendingAutofillSubmissionFromUnknown(
  value: unknown
): PendingAutofillSubmission | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const candidate = value as Partial<PendingAutofillSubmission>;
  if (
    typeof candidate.url !== "string" ||
    candidate.url.trim() === "" ||
    typeof candidate.username !== "string" ||
    typeof candidate.password !== "string" ||
    candidate.password === "" ||
    typeof candidate.submittedAt !== "number" ||
    !Number.isFinite(candidate.submittedAt)
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
    submittedAt: candidate.submittedAt
  };
}
