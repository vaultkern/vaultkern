export interface AutomaticFillCapability {
  kind: "automatic";
  targetUrl: string;
  entryId: string;
}

export interface ManualFillCapability {
  kind: "manual";
  targetUrl: string;
  entryId: string;
}

export type FillCapability = AutomaticFillCapability | ManualFillCapability;

const issuedCapabilities = new WeakSet<object>();

export function automaticFillUrlAllowed(value: unknown) {
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

function issueCapability<T extends FillCapability>(capability: T): T {
  const issued = Object.freeze(capability);
  issuedCapabilities.add(issued);
  return issued;
}

export function createAutomaticFillCapability(input: {
  targetUrl: string;
  entryId: string;
}): AutomaticFillCapability {
  return issueCapability({ kind: "automatic", ...input });
}

export function createManualFillCapability(input: {
  targetUrl: string;
  entryId: string;
}): ManualFillCapability {
  return issueCapability({ kind: "manual", ...input });
}

export function isIssuedFillCapability(value: unknown): value is FillCapability {
  return typeof value === "object" && value !== null && issuedCapabilities.has(value);
}

export function acceptDeliveredFillCapability(
  value: unknown,
  expectedTargetUrl: string
): FillCapability | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }

  const candidate = value as {
    kind?: unknown;
    targetUrl?: unknown;
    entryId?: unknown;
  };
  if (
    (candidate.kind !== "automatic" && candidate.kind !== "manual") ||
    candidate.targetUrl !== expectedTargetUrl ||
    typeof candidate.entryId !== "string" ||
    candidate.entryId === ""
  ) {
    return null;
  }

  return candidate.kind === "automatic"
    ? createAutomaticFillCapability({
        targetUrl: expectedTargetUrl,
        entryId: candidate.entryId
      })
    : createManualFillCapability({
        targetUrl: expectedTargetUrl,
        entryId: candidate.entryId
      });
}
