import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("webauthn proxy structure", () => {
  it("keeps shared prompt state in one registry instead of per-mode parallel maps", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    for (const field of [
      "PromptWindowIds",
      "PromptContexts",
      "PromptNonces",
      "PromptRequestIds",
      "PromptRequestKeys",
      "PromptRemovalCleanups",
      "CompleteWaiters",
      "DismissWaiters",
      "PendingCompletePromptKeys",
      "PendingCompleteSignals"
    ]) {
      expect(source).not.toMatch(new RegExp(`const\\s+unlock${field}\\b`));
      expect(source).not.toMatch(new RegExp(`const\\s+presence${field}\\b`));
      expect(source).not.toMatch(
        new RegExp(`const\\s+userVerification${field}\\b`)
      );
    }

    expect(source).toContain("const promptStates = createPromptStateRegistry()");
    expect(source).not.toMatch(/function\s+closeUnlockPromptWindow\b/);
    expect(source).not.toMatch(/function\s+closePresencePromptWindow\b/);
    expect(source).not.toMatch(/function\s+closeUserVerificationPromptWindow\b/);
    expect(source).toContain("async function closePromptWindowForRequest");
    expect(source).not.toMatch(/function\s+waitForUnlockSignal\b/);
    expect(source).not.toMatch(/function\s+waitForPresenceSignal\b/);
    expect(source).not.toMatch(/function\s+waitForUserVerificationSignal\b/);
    expect(source).toContain("function waitForPromptSignal");
  });
});
