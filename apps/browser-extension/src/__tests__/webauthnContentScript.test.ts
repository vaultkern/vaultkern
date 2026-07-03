import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const INSTALLED_MARKER = "__vaultkernWebAuthnContentScriptInstalled";

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  delete (globalThis as Record<string, unknown>)[INSTALLED_MARKER];
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

beforeEach(() => {
  vi.resetModules();
  delete (globalThis as Record<string, unknown>)[INSTALLED_MARKER];
});

function setAncestorOrigins(ancestorOrigins: string[]) {
  Object.defineProperty(window.location, "ancestorOrigins", {
    configurable: true,
    value: ancestorOrigins
  });
}

describe("WebAuthn content script bridge", () => {
  it("forwards page observations with a complete origin-shaped ancestor chain", async () => {
    const sendMessage = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };
    setAncestorOrigins(["https://middle.example", "https://top.example"]);

    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          challenge: "Y2hhbGxlbmdl"
        }
      })
    );

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: window.location.origin,
        topOrigin: "https://top.example",
        ancestorOrigins: ["https://middle.example", "https://top.example"]
      })
    );
  });

  it("drops page observations when ancestor origins contain an opaque origin", async () => {
    const sendMessage = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };
    setAncestorOrigins(["null", "https://top.example"]);

    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          challenge: "Y2hhbGxlbmdl"
        }
      })
    );

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("does not forward page-supplied ceremony tokens or structured credential ids", async () => {
    const sendMessage = vi.fn();
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };
    setAncestorOrigins(["https://top.example"]);

    await import("../webauthnContentScript");

    window.dispatchEvent(
      new MessageEvent("message", {
        source: window,
        origin: window.location.origin,
        data: {
          type: "vaultkern_webauthn_page_request",
          ceremony: "get",
          challenge: "Y2hhbGxlbmdl",
          ceremonyToken: "page-controlled-token",
          ceremony_token: "page-controlled-token",
          allowCredentialIds: [
            "Y3JlZGVudGlhbC0x",
            { id: "page-controlled-token" }
          ],
          excludeCredentialIds: [
            { id: "page-controlled-token" },
            "Y3JlZGVudGlhbC0y"
          ]
        }
      })
    );

    expect(sendMessage).toHaveBeenCalledTimes(1);
    const payload = sendMessage.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload.ceremonyToken).toBeUndefined();
    expect(payload.ceremony_token).toBeUndefined();
    expect(payload.allowCredentialIds).toEqual(["Y3JlZGVudGlhbC0x"]);
    expect(payload.excludeCredentialIds).toEqual(["Y3JlZGVudGlhbC0y"]);
    expect(JSON.stringify(payload)).not.toContain("page-controlled-token");
  });
});
