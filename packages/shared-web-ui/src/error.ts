export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  if (typeof error === "string" && error.trim()) {
    return error;
  }

  if (hasMessage(error)) {
    return error.message;
  }

  return fallback;
}

function hasMessage(
  value: unknown
): value is {
  message: string;
} {
  return (
    typeof value === "object" &&
    value !== null &&
    "message" in value &&
    typeof (value as { message?: unknown }).message === "string" &&
    (value as { message: string }).message.trim().length > 0
  );
}
