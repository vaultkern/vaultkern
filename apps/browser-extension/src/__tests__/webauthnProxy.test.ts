import { describe, expect, it, vi } from "vitest";
import { Buffer } from "node:buffer";

import {
  attachWebAuthnProxy,
  detachWebAuthnProxy,
  recordWebAuthnPageRequest,
  webAuthnProxyAvailable
} from "../webauthnProxy";

async function expectResolvesSoon<T>(promise: Promise<T>, expected: T) {
  const timeout = Symbol("timeout");
  const result = await Promise.race([
    promise,
    new Promise<symbol>((resolve) => setTimeout(() => resolve(timeout), 20))
  ]);

  expect(result).not.toBe(timeout);
  expect(result).toEqual(expected);
}

function clientDataJsonFrom(base64url: string) {
  return JSON.parse(Buffer.from(base64url, "base64url").toString("utf8"));
}

function installPresencePrompt(chromeApi: any) {
  let messageListener:
    | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
    | undefined;
  const existingRuntime = chromeApi.runtime ?? {};
  const existingOnMessage = existingRuntime.onMessage;
  chromeApi.runtime = {
    ...existingRuntime,
    getURL:
      existingRuntime.getURL ??
      vi.fn((path: string) => `chrome-extension://id/${path}`),
    onMessage: {
      ...existingOnMessage,
      addListener(
        listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
      ) {
        messageListener = listener;
        existingOnMessage?.addListener?.(listener);
      }
    }
  };

  const create = vi.fn(async () => ({ id: 77 }));
  chromeApi.windows = {
    ...(chromeApi.windows ?? {}),
    create
  };

  return {
    create,
    async approve(
      requestId?: number,
      overrides: Partial<{
        origin: string;
        relyingParty: string;
        topOrigin: string;
      }> = {}
    ) {
      await vi.waitFor(() => {
        expect(create).toHaveBeenCalled();
      });
      await new Promise((resolve) => setTimeout(resolve, 0));
      const promptUrl = (create.mock.calls.at(-1)?.[0] as { url?: string } | undefined)
        ?.url;
      const promptParams = new URL(
        promptUrl ?? "",
        "chrome-extension://id/"
      ).searchParams;
      const approvedRequestId =
        requestId ?? Number(promptParams.get("requestId"));
      const message: Record<string, unknown> = {
        type: "vaultkern_presence_complete",
        requestId: approvedRequestId
      };
      for (const key of ["origin", "relyingParty", "topOrigin"] as const) {
        const value = overrides[key] ?? promptParams.get(key);
        if (value) {
          message[key] = value;
        }
      }
      messageListener?.(
        message,
        {},
        vi.fn()
      );
    }
  };
}

describe("webAuthenticationProxy wrapper", () => {
  it("reports unsupported when the Chrome API is unavailable", async () => {
    const chromeApi = { runtime: {} };

    expect(webAuthnProxyAvailable(chromeApi)).toBe(false);
    await expect(attachWebAuthnProxy(chromeApi)).resolves.toEqual({
      status: "unsupported"
    });
  });

  it("attaches and detaches the Chrome WebAuthn proxy when available", async () => {
    const attach = vi.fn(async () => undefined);
    const detach = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: { attach, detach }
    };

    await expectResolvesSoon(attachWebAuthnProxy(chromeApi), {
      status: "attached"
    });
    await expectResolvesSoon(detachWebAuthnProxy(chromeApi), {
      status: "detached"
    });
    expect(attach).toHaveBeenCalledWith();
    expect(detach).toHaveBeenCalledWith();
  });

  it("reports Chrome proxy attach errors with readable messages", async () => {
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => {
          throw new Error("another extension is already attached");
        })
      }
    };

    await expectResolvesSoon(attachWebAuthnProxy(chromeApi), {
      status: "error",
      message: "another extension is already attached"
    });
  });

  it("completes WebAuthn get requests with a runtime assertion", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x",
        backupEligible: true,
        backupState: false
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    getListener?.({
      requestId: 7,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(1, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });

    const details = completeGetRequest.mock.calls[0][0];
    expect(details.requestId).toBe(7);
    const response = JSON.parse(details.responseJson);
    expect(response).toEqual({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: "auth-data",
        clientDataJSON: "client-data",
        signature: "signature",
        userHandle: "dXNlci0x"
      }
    });
  });

  it("only resumes the WebAuthn request that matches the approved prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 31,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await presencePrompt.approve(32);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(31, { origin: "https://evil.example" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    await presencePrompt.approve(31);

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("uses the page-observed origin when a Chrome get request omits origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC1vYnM",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "get",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0",
        allowCredentialIds: ["Y3JlZGVudGlhbC1vYnM"]
      })
    ).toBe(true);

    getListener?.({
      requestId: 27,
      requestDetailsJson: JSON.stringify({
        rpId: "observed.example",
        challenge: "b2JzZXJ2ZWQtZ2V0",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC1vYnM"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "observed.example",
      origin: "https://observed.example",
      credential_id: "Y3JlZGVudGlhbC1vYnM",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(
      clientDataJsonFrom(
        (sendRuntimeCommand.mock.calls[1][0] as {
          client_data_json_base64url: string;
        }).client_data_json_base64url
      )
    ).toEqual({
      type: "webauthn.get",
      challenge: "b2JzZXJ2ZWQtZ2V0",
      origin: "https://observed.example",
      crossOrigin: true,
      topOrigin: "https://top.example"
    });
  });

  it("tries later allowed credentials when earlier passkey ids are not in the vault", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "passkey credential not found: bWlzc2luZw"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "dmF1bHRrZXJuLWNyZWRlbnRpYWw",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x",
        backupEligible: true,
        backupState: false
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://accounts.google.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 17,
      origin: "https://accounts.google.com",
      requestDetailsJson: JSON.stringify({
        rpId: "google.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "bWlzc2luZw"
          },
          {
            type: "public-key",
            id: "dmF1bHRrZXJuLWNyZWRlbnRpYWw"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://accounts.google.com",
      credential_id: "bWlzc2luZw",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "google.com",
      origin: "https://accounts.google.com",
      credential_id: "dmF1bHRrZXJuLWNyZWRlbnRpYWw",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });

    const details = completeGetRequest.mock.calls[0][0];
    expect(details.requestId).toBe(17);
    const response = JSON.parse(details.responseJson);
    expect(response.id).toBe("dmF1bHRrZXJuLWNyZWRlbnRpYWw");
  });

  it("derives the default WebAuthn get RP ID from the request origin", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://login.example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 21,
      origin: "https://login.example.com",
      requestDetailsJson: JSON.stringify({
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "login.example.com",
      origin: "https://login.example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("allows discoverable WebAuthn get requests without allowed credentials", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "ZGlzY292ZXJhYmxlLTE",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: "dXNlci0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 22,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: []
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: null,
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
    const response = JSON.parse(completeGetRequest.mock.calls[0][0].responseJson);
    expect(response.id).toBe("ZGlzY292ZXJhYmxlLTE");
  });

  it("completes WebAuthn create requests with a runtime registration and saves the vault", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand })
    ).resolves.toEqual({ status: "attached" });

    createListener?.({
      requestId: 10,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await vi.waitFor(() => {
      expect(presencePrompt.create).toHaveBeenCalledWith({
        url: "chrome-extension://id/popup.html?webauthn=approve&requestId=10&relyingParty=example.com&origin=https%3A%2F%2Fexample.com",
        type: "popup",
        width: 460,
        height: 360,
        focused: true
      });
    });
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(1, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "save_vault",
      vault_id: "vault-1"
    });

    const details = completeCreateRequest.mock.calls[0][0];
    expect(details.requestId).toBe(10);
    const response = JSON.parse(details.responseJson);
    expect(response).toEqual({
      id: "Y3JlZGVudGlhbC0x",
      rawId: "Y3JlZGVudGlhbC0x",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: "auth-data",
        attestationObject: "attestation-object",
        clientDataJSON: "client-data",
        publicKey: "public-key",
        publicKeyAlgorithm: -7,
        transports: ["internal"]
      }
    });
  });

  it("uses the page-observed origin when a Chrome create request omits origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC1vYnM",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });
    expect(
      recordWebAuthnPageRequest({
        type: "vaultkern_webauthn_page_request",
        ceremony: "create",
        origin: "https://observed.example",
        topOrigin: "https://top.example",
        relyingParty: "observed.example",
        challenge: "b2JzZXJ2ZWQtY3JlYXRl"
      })
    ).toBe(true);

    createListener?.({
      requestId: 28,
      requestDetailsJson: JSON.stringify({
        rp: { id: "observed.example", name: "Observed" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "b2JzZXJ2ZWQtY3JlYXRl",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "observed.example",
      origin: "https://observed.example",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
    expect(
      clientDataJsonFrom(
        (sendRuntimeCommand.mock.calls[1][0] as {
          client_data_json_base64url: string;
        }).client_data_json_base64url
      )
    ).toEqual({
      type: "webauthn.create",
      challenge: "b2JzZXJ2ZWQtY3JlYXRl",
      origin: "https://observed.example",
      crossOrigin: true,
      topOrigin: "https://top.example"
    });
  });

  it("derives the default WebAuthn create RP ID from the request origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 15,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("derives unbracketed IPv6 loopback RP IDs from the request origin", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 16,
      origin: "http://[::1]:8877",
      requestDetailsJson: JSON.stringify({
        rp: { name: "IPv6 loopback" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "::1",
      origin: "http://[::1]:8877",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("rejects cross-platform-only WebAuthn create requests", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 20,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform"
        }
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 20,
      error: {
        name: "NotAllowedError",
        message: "VaultKern passkey provider only supports platform authenticators"
      }
    });
  });

  it("rejects WebAuthn create requests that require user verification", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 21,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required"
        }
      })
    });

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 21,
      error: {
        name: "NotAllowedError",
        message:
          "VaultKern passkey provider does not support required user verification"
      }
    });
  });

  it("returns InvalidStateError when WebAuthn create excludes an existing credential", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_credential_status",
        credentialId: "Y3JlZGVudGlhbC0x",
        exists: true
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 19,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [
          {
            type: "public-key",
            id: "Y3JlZGVudGlhbC0x"
          }
        ]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "passkey_credential_status",
      vault_id: "vault-1",
      credential_id: "Y3JlZGVudGlhbC0x",
      relying_party: "example.com"
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "create_passkey_registration" })
    );
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_vault",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 19,
      error: {
        name: "InvalidStateError",
        message: "VaultKern passkey credential is already registered"
      }
    });
  });

  it("returns a WebAuthn error when saving a new passkey fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "failed to save vault"
      })
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 14,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 14,
      error: {
        name: "NotAllowedError",
        message: "failed to save vault"
      }
    });
    expect(sendRuntimeCommand).toHaveBeenCalledWith({
      type: "delete_entry",
      vault_id: "vault-1",
      entry_id: "entry-1"
    });
  });

  it("rolls back a created passkey when completing the WebAuthn create request fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => {
      throw new Error("Chrome rejected completion");
    });
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" })
      .mockResolvedValueOnce({ type: "saved" })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 23,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "delete_entry",
        vault_id: "vault-1",
        entry_id: "entry-1"
      });
    });
    expect(sendRuntimeCommand).toHaveBeenLastCalledWith({
      type: "save_vault",
      vault_id: "vault-1"
    });
  });

  it("rolls back a created passkey when Chrome cancels before save", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveRegistration: (value: unknown) => void = () => {};
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveRegistration = resolve;
          })
      )
      .mockResolvedValueOnce({ type: "saved" });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 24,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();
    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledTimes(2);
    });
    cancelListener?.(24);
    resolveRegistration({
      type: "passkey_registration",
      entryId: "entry-1",
      credentialId: "Y3JlZGVudGlhbC0x",
      authenticatorDataBase64url: "auth-data",
      attestationObjectBase64url: "attestation-object",
      clientDataJsonBase64url: "client-data",
      publicKeyBase64url: "public-key",
      publicKeyAlgorithm: -7,
      userHandleBase64url: "dXNlci0x"
    });

    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledWith({
        type: "delete_entry",
        vault_id: "vault-1",
        entry_id: "entry-1"
      });
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_vault",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).not.toHaveBeenCalled();
  });

  it("returns a WebAuthn error when passkey registration fails", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "error",
        code: "invalid_request",
        message: "invalid WebAuthn origin"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 16,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_vault",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 16,
      error: {
        name: "NotAllowedError",
        message: "invalid WebAuthn origin"
      }
    });
  });

  it("returns a WebAuthn error when runtime returns a malformed registration", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        credentialId: "Y3JlZGVudGlhbC0x"
      });
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 18,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalledWith({
      type: "save_vault",
      vault_id: "vault-1"
    });
    expect(completeCreateRequest).toHaveBeenCalledWith({
      requestId: 18,
      error: {
        name: "NotAllowedError",
        message: "runtime returned an invalid passkey registration"
      }
    });
  });

  it("only resumes the locked WebAuthn request that matches the unlock prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 33,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledWith({
        url: "chrome-extension://id/popup.html?webauthn=unlock&requestId=33&relyingParty=example.com&origin=https%3A%2F%2Fexample.com",
        type: "popup",
        width: 460,
        height: 620,
        focused: true
      });
    });

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 34,
        origin: "https://example.com",
        relyingParty: "example.com"
      },
      {},
      vi.fn()
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 33,
        origin: "https://evil.example",
        relyingParty: "example.com"
      },
      {},
      vi.fn()
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalled();

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 33,
        origin: "https://example.com",
        relyingParty: "example.com"
      },
      {},
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("does not miss unlock completion sent while opening the prompt", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      })
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      windows: {
        create: vi.fn(async () => {
          unlockMessageListener?.(
            {
              type: "vaultkern_unlock_complete",
              requestId: 44,
              origin: "https://example.com",
              relyingParty: "example.com"
            },
            {},
            vi.fn()
          );
          return { id: 42 };
        })
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 44,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });

  it("opens an unlock window and waits for an active vault before creating a passkey", async () => {
    let createListener: ((request: unknown) => void) | undefined;
    let unlockMessageListener:
      | ((message: unknown, sender: unknown, sendResponse: unknown) => void)
      | undefined;
    let resolveInitialSession: (value: unknown) => void = () => {};
    const completeCreateRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveInitialSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_registration",
        entryId: "entry-1",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        attestationObjectBase64url: "attestation-object",
        clientDataJsonBase64url: "client-data",
        publicKeyBase64url: "public-key",
        publicKeyAlgorithm: -7,
        userHandleBase64url: "dXNlci0x"
      })
      .mockResolvedValueOnce({ type: "save_vault_result", status: "saved" });
    const chromeApi = {
      runtime: {
        getURL: vi.fn((path: string) => `chrome-extension://id/${path}`),
        onMessage: {
          addListener(
            listener: (message: unknown, sender: unknown, sendResponse: unknown) => void
          ) {
            unlockMessageListener = listener;
          }
        }
      },
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/register" }])
      },
      windows: {
        create: vi.fn(async () => ({ id: 42 }))
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeCreateRequest,
        onCreateRequest: {
          addListener(listener: (request: unknown) => void) {
            createListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    createListener?.({
      requestId: 12,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rp: { id: "example.com", name: "Example" },
        user: {
          id: "dXNlci0x",
          name: "alice@example.com",
          displayName: "Alice"
        },
        challenge: "cmVnaXN0ZXItMQ",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      })
    });
    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    });
    resolveInitialSession({
      type: "session_state",
      unlocked: false,
      activeVaultId: null
    });

    await vi.waitFor(() => {
      expect(chromeApi.windows.create).toHaveBeenCalledTimes(1);
    });
    expect(chromeApi.windows.create).toHaveBeenCalledWith({
      url: "chrome-extension://id/popup.html?webauthn=unlock&requestId=12&relyingParty=example.com&origin=https%3A%2F%2Fexample.com",
      type: "popup",
      width: 460,
      height: 620,
      focused: true
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);

    unlockMessageListener?.(
      {
        type: "vaultkern_unlock_complete",
        requestId: 12,
        origin: "https://example.com",
        relyingParty: "example.com"
      },
      {},
      vi.fn()
    );

    await vi.waitFor(() => {
      expect(completeCreateRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "create_passkey_registration",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      user_name: "alice@example.com",
      user_display_name: "Alice",
      user_handle_base64url: "dXNlci0x",
      client_data_json_base64url: expect.any(String)
    });
  });

  it("reports user-verifying platform authenticator availability as unavailable", async () => {
    let isUvpaaListener: ((request: unknown) => void) | undefined;
    const completeIsUvpaaRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeIsUvpaaRequest,
        onIsUvpaaRequest: {
          addListener(listener: (request: unknown) => void) {
            isUvpaaListener = listener;
          }
        }
      }
    };

    await expect(
      attachWebAuthnProxy(chromeApi, { sendRuntimeCommand: vi.fn() })
    ).resolves.toEqual({ status: "attached" });

    isUvpaaListener?.({ requestId: 11 });

    await vi.waitFor(() => {
      expect(completeIsUvpaaRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeIsUvpaaRequest).toHaveBeenCalledWith({
      requestId: 11,
      isUvpaa: false
    });
  });

  it("returns a WebAuthn error when no active vault is unlocked", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand: vi.fn(async () => ({
        type: "session_state",
        unlocked: false,
        activeVaultId: null
      }))
    });

    getListener?.({
      requestId: 8,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 8,
      error: {
        name: "NotAllowedError",
        message: "VaultKern vault is locked and no unlock window is available"
      }
    });
  });

  it("rejects WebAuthn get requests that require user verification", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 25,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 25,
      error: {
        name: "NotAllowedError",
        message:
          "VaultKern passkey provider does not support required user verification"
      }
    });
  });

  it("rejects WebAuthn get requests whose origin cannot be identified", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    const completeGetRequest = vi.fn(async () => undefined);
    const sendRuntimeCommand = vi.fn();
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand });

    getListener?.({
      requestId: 26,
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).not.toHaveBeenCalled();
    expect(completeGetRequest).toHaveBeenCalledWith({
      requestId: 26,
      error: {
        name: "NotAllowedError",
        message: "VaultKern cannot identify the WebAuthn request origin"
      }
    });
  });

  it("records Chrome numeric WebAuthn cancellation request ids", async () => {
    let cancelListener: ((request: unknown) => void) | undefined;
    let debugLog: unknown[] = [];
    const chromeApi = {
      runtime: {},
      storage: {
        local: {
          get: vi.fn(async () => ({ vaultkernWebAuthnDebug: debugLog })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            debugLog = items.vaultkernWebAuthnDebug as unknown[];
          })
        }
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };

    await attachWebAuthnProxy(chromeApi, { sendRuntimeCommand: vi.fn() });

    cancelListener?.(9);

    await vi.waitFor(() => {
      expect(debugLog).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            event: "request_canceled",
            requestId: 9
          })
        ])
      );
    });
  });

  it("does not complete a canceled WebAuthn get request", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveSession: (value: unknown) => void = () => {};
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const sendRuntimeCommand = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand
    });
    expect(cancelListener).toBeDefined();

    getListener?.({
      requestId: 9,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    cancelListener?.(9);
    resolveSession({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    expect(completeGetRequest).not.toHaveBeenCalled();
  });

  it("does not treat a later WebAuthn get request with a reused id as canceled", async () => {
    let getListener: ((request: unknown) => void) | undefined;
    let cancelListener: ((request: unknown) => void) | undefined;
    let resolveFirstSession: (value: unknown) => void = () => {};
    const completeGetRequest = vi.fn(async () => undefined);
    const chromeApi = {
      runtime: {},
      tabs: {
        query: vi.fn(async () => [{ url: "https://example.com/login" }])
      },
      webAuthenticationProxy: {
        attach: vi.fn(async () => undefined),
        completeGetRequest,
        onGetRequest: {
          addListener(listener: (request: unknown) => void) {
            getListener = listener;
          }
        },
        onRequestCanceled: {
          addListener(listener: (request: unknown) => void) {
            cancelListener = listener;
          }
        }
      }
    };
    const presencePrompt = installPresencePrompt(chromeApi);
    const sendRuntimeCommand = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirstSession = resolve;
          })
      )
      .mockResolvedValueOnce({
        type: "session_state",
        unlocked: true,
        activeVaultId: "vault-1"
      })
      .mockResolvedValueOnce({
        type: "passkey_assertion",
        credentialId: "Y3JlZGVudGlhbC0x",
        authenticatorDataBase64url: "auth-data",
        clientDataJsonBase64url: "client-data",
        signatureBase64url: "signature",
        userHandleBase64url: null
      });

    await attachWebAuthnProxy(chromeApi, {
      sendRuntimeCommand
    });

    getListener?.({
      requestId: 9,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "Y2hhbGxlbmdlLTE",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await vi.waitFor(() => {
      expect(sendRuntimeCommand).toHaveBeenCalledTimes(1);
    });
    cancelListener?.(9);
    resolveFirstSession({
      type: "session_state",
      unlocked: true,
      activeVaultId: "vault-1"
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(completeGetRequest).not.toHaveBeenCalled();

    getListener?.({
      requestId: 9,
      origin: "https://example.com",
      requestDetailsJson: JSON.stringify({
        rpId: "example.com",
        challenge: "bG9naW4tMg",
        allowCredentials: [{ type: "public-key", id: "Y3JlZGVudGlhbC0x" }]
      })
    });
    await presencePrompt.approve();

    await vi.waitFor(() => {
      expect(completeGetRequest).toHaveBeenCalledTimes(1);
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(2, {
      type: "get_session_state"
    });
    expect(sendRuntimeCommand).toHaveBeenNthCalledWith(3, {
      type: "create_passkey_assertion",
      vault_id: "vault-1",
      relying_party: "example.com",
      origin: "https://example.com",
      credential_id: "Y3JlZGVudGlhbC0x",
      user_presence_verified: true,
      client_data_json_base64url: expect.any(String)
    });
  });
});
