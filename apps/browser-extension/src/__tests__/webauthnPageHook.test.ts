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

  it("forwards immediate mediation on get observations", async () => {
    installCredentialMocks();
    const postMessage = vi
      .spyOn(window, "postMessage")
      .mockImplementation(() => undefined);

    await import("../webauthnPageHook");

    await navigator.credentials.get({
      mediation: "immediate",
      publicKey: {
        challenge: new Uint8Array([7, 8, 9])
      }
    } as CredentialRequestOptions);

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        mediation: "immediate"
      }),
      window.location.origin
    );
  });

  it("does not include ceremony tokens in page hook observations", async () => {
    installCredentialMocks();
    const postMessage = vi
      .spyOn(window, "postMessage")
      .mockImplementation(() => undefined);

    await import("../webauthnPageHook");

    await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array([3, 2, 1]),
        ceremonyToken: "page-controlled-token",
        ceremony_token: "page-controlled-token"
      }
    } as CredentialRequestOptions);

    const payload = postMessage.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({
      type: "vaultkern_webauthn_page_request",
      ceremony: "get"
    });
    expect(payload.ceremonyToken).toBeUndefined();
    expect(payload.ceremony_token).toBeUndefined();
    expect(JSON.stringify(payload)).not.toContain("page-controlled-token");
  });

  it("does not let observation postMessage failures break WebAuthn calls", async () => {
    const { originalGet } = installCredentialMocks();
    vi.spyOn(window, "postMessage").mockImplementation(() => {
      throw new SyntaxError("Invalid target origin 'null'");
    });

    await import("../webauthnPageHook");

    await expect(
      navigator.credentials.get({
        publicKey: {
          challenge: new Uint8Array([6, 5, 4])
        }
      } as CredentialRequestOptions)
    ).resolves.toBeNull();
    expect(originalGet).toHaveBeenCalledTimes(1);
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
