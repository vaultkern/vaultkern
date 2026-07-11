import { parseCanonicalHttpUrl } from "./canonicalHttpUrl";

export { parseCanonicalHttpUrl } from "./canonicalHttpUrl";

function automaticFillUrlAllowed(value: unknown) {
  try {
    if (typeof value !== "string") {
      return false;
    }
    const { protocol, hostname } = new URL(value);
    return (
      protocol === "https:" ||
      (protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(hostname))
    );
  } catch {
    return false;
  }
}

export function canonicalHttpOrigin(value: unknown): string | null {
  return parseCanonicalHttpUrl(value)?.origin ?? null;
}

export function sameExactHttpOrigin(left: unknown, right: unknown): boolean {
  const leftOrigin = canonicalHttpOrigin(left);
  return leftOrigin !== null && leftOrigin === canonicalHttpOrigin(right);
}

export function automaticFillCandidate(
  response: unknown,
  pageUrl: string
): { id: string; url: string } | null {
  if (!automaticFillUrlAllowed(pageUrl)) {
    return null;
  }
  if (
    typeof response !== "object" ||
    response === null ||
    (response as { type?: unknown }).type !== "fill_candidates" ||
    !Array.isArray((response as { entries?: unknown }).entries)
  ) {
    return null;
  }

  const entries = (response as { entries: unknown[] }).entries;
  if (entries.length !== 1) {
    return null;
  }

  const [entry] = entries;
  if (
    typeof entry !== "object" ||
    entry === null ||
    typeof (entry as { id?: unknown }).id !== "string" ||
    typeof (entry as { url?: unknown }).url !== "string"
  ) {
    return null;
  }

  const candidate = entry as { id: string; url: string };
  return sameExactHttpOrigin(candidate.url, pageUrl)
    ? { id: candidate.id, url: candidate.url }
    : null;
}
