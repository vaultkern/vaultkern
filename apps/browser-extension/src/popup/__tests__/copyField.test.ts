import { afterEach, expect, it, vi } from "vitest";

import { copyFieldValue } from "../copyField";

afterEach(() => {
  vi.useRealTimers();
});

it("clears the clipboard after the configured delay", async () => {
  vi.useFakeTimers();
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText }
  });

  await copyFieldValue("secret", 2);

  expect(writeText).toHaveBeenCalledWith("secret");
  await vi.advanceTimersByTimeAsync(2_000);
  expect(writeText).toHaveBeenCalledWith("");
});
