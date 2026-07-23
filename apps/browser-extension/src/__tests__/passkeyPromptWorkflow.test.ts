import { afterEach, describe, expect, it, vi } from "vitest";

import { createBrowserPasskeyPromptWorkflow } from "../popup/passkeyPromptWorkflow";

function runtimeClient() {
  const session = {
    unlocked: true,
    activeVaultId: "vault-1"
  };
  return {
    getSessionState: vi.fn(async () => session),
    recordUserActivity: vi.fn(async () => session),
    activateResidentApp: vi.fn(async () => undefined)
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
});

describe("browser passkey prompt workflow", () => {
  it("leaves the ordinary popup outside the passkey prompt module", () => {
    const client = runtimeClient();

    expect(createBrowserPasskeyPromptWorkflow(client, "")).toBeNull();
    expect(
      createBrowserPasskeyPromptWorkflow(client, "?webauthn=settings")
    ).toBeNull();
  });

  it("owns resident session access and fixed-route activation", async () => {
    const client = runtimeClient();
    const workflow = createBrowserPasskeyPromptWorkflow(
      client,
      "?webauthn=unlock&requestId=7&relyingParty=example.com"
    );

    expect(workflow?.request).toEqual({
      mode: "unlock",
      siteLabel: "example.com"
    });
    await expect(workflow?.getSessionState()).resolves.toEqual({
      unlocked: true,
      activeVaultId: "vault-1"
    });
    await workflow?.activateResidentApp("unlock");
    expect(client.activateResidentApp).toHaveBeenCalledWith("unlock");
  });

  it("keeps presence open and rejects a credential list with hidden fields", async () => {
    const sendMessage = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, keepOpen: true })
      .mockResolvedValueOnce({
        credentialOptions: [
          {
            credentialId: "credential-1",
            username: "alice@example.com"
          },
          {
            credentialId: "credential-2",
            username: "mallory@example.com",
            privateKeyPem: "must-not-cross-the-popup-seam"
          }
        ]
      });
    const closeWindow = vi.fn();
    Object.defineProperty(window, "close", {
      configurable: true,
      value: closeWindow
    });
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: { sendMessage }
    };
    const workflow = createBrowserPasskeyPromptWorkflow(
      runtimeClient(),
      "?webauthn=approve&requestId=11&origin=https%3A%2F%2Fexample.com&relyingParty=example.com&nonce=nonce-11"
    );

    await expect(
      workflow?.complete({
        type: "presence",
        credentialId: "credential-1"
      })
    ).resolves.toEqual({ keepOpen: true, credentialOptions: [] });
    expect(sendMessage).toHaveBeenNthCalledWith(1, {
      type: "vaultkern_presence_complete",
      requestId: 11,
      origin: "https://example.com",
      relyingParty: "example.com",
      credentialId: "credential-1",
      nonce: "nonce-11"
    });
    expect(sendMessage).toHaveBeenNthCalledWith(2, {
      type: "vaultkern_presence_options_request",
      requestId: 11,
      origin: "https://example.com",
      relyingParty: "example.com",
      nonce: "nonce-11"
    });
    expect(closeWindow).not.toHaveBeenCalled();
  });
});
