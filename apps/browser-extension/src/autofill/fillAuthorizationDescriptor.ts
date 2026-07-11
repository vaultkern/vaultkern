import type {
  AutomaticFillCapability,
  ManualFillCapability
} from "./fillAuthorization";

export function createAutomaticFillCapability(input: {
  targetUrl: string;
  entryId: string;
}): AutomaticFillCapability {
  return { kind: "automatic", ...input };
}

export function createManualFillCapability(input: {
  targetUrl: string;
  entryId: string;
}): ManualFillCapability {
  return { kind: "manual", ...input };
}

export type { AutomaticFillCapability, ManualFillCapability } from "./fillAuthorization";
