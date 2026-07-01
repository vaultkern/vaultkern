import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ENABLED_MARKER = "__vaultkernWebAuthnPageHookEnabled";

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  delete (globalThis as Record<string, unknown>)[ENABLED_MARKER];
});

beforeEach(() => {
  vi.resetModules();
  delete (globalThis as Record<string, unknown>)[ENABLED_MARKER];
});

function installCredentialMocks() {
  const originalCreate = vi.fn(async () => null);
  const originalGet = vi.fn(async () => null);
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: {
      create: originalCreate,
      get: originalGet
    }
  });
  return { originalCreate, originalGet };
}

describe("WebAuthn page hook", () => {
  it("forwards conditional mediation on get observations", async () => {
    installCredentialMocks();
    const postMessage = vi
      .spyOn(window, "postMessage")
      .mockImplementation(() => undefined);

    await import("../webauthnPageHook");

    await navigator.credentials.get({
      mediation: "conditional",
      publicKey: {
        challenge: new Uint8Array([9, 8, 7])
      }
    } as CredentialRequestOptions);

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        mediation: "conditional"
      }),
      window.location.origin
    );
  });

  it("does not post observations while the already-injected hook is disabled", async () => {
    const { originalCreate } = installCredentialMocks();
    const postMessage = vi
      .spyOn(window, "postMessage")
      .mockImplementation(() => undefined);

    await import("../webauthnPageHook");
    (globalThis as Record<string, unknown>)[ENABLED_MARKER] = false;

    await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array([1, 2, 3])
      }
    } as CredentialCreationOptions);

    expect(originalCreate).toHaveBeenCalledTimes(1);
    expect(postMessage).not.toHaveBeenCalled();
  });

  it("re-enables an installed hook when the hook script is injected again", async () => {
    installCredentialMocks();
    const postMessage = vi
      .spyOn(window, "postMessage")
      .mockImplementation(() => undefined);

    await import("../webauthnPageHook");
    (globalThis as Record<string, unknown>)[ENABLED_MARKER] = false;

    vi.resetModules();
    await import("../webauthnPageHook");

    await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array([4, 5, 6])
      }
    } as CredentialRequestOptions);

    expect((globalThis as Record<string, unknown>)[ENABLED_MARKER]).toBe(true);
    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get"
      }),
      window.location.origin
    );
  });
});
