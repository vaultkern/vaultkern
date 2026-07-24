import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("resident mutation architecture", () => {
  it("does not retain logical operation replay or follow-up save queues in the UI", () => {
    const source = readFileSync(resolve(process.cwd(), "src/App.tsx"), "utf8");

    expect(source).not.toContain("operationId");
    expect(source).not.toContain("retryMutationSave");
    expect(source).not.toContain("PendingEntrySave");
    expect(source).not.toContain("PendingAttachmentSave");
    expect(source).not.toContain("pendingEntryDelete");
  });
});
