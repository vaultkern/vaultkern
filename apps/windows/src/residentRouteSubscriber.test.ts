import { describe, expect, it, vi } from "vitest";

import { createResidentAppRouteSubscriber } from "./residentRouteSubscriber";

describe("resident app route subscriber", () => {
  it("delivers a route queued before the WebView listener is ready", async () => {
    let pending: "unlock" | "vaults" | "settings" | null = "settings";
    let notifyAvailable: (() => void) | undefined;
    const takePending = vi.fn(async () => {
      const route = pending;
      pending = null;
      return route;
    });
    const unlisten = vi.fn();
    const listenAvailable = vi.fn(async (listener: () => void) => {
      notifyAvailable = listener;
      return unlisten;
    });
    const listener = vi.fn();

    const subscribe = createResidentAppRouteSubscriber(
      takePending,
      listenAvailable
    );
    const unsubscribe = await subscribe(listener);

    expect(listener).toHaveBeenCalledWith("settings");

    pending = "vaults";
    notifyAvailable?.();
    await vi.waitFor(() => expect(listener).toHaveBeenLastCalledWith("vaults"));

    unsubscribe();
    expect(unlisten).toHaveBeenCalledTimes(1);
  });
});
