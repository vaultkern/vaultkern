#!/usr/bin/env node
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";

const rpName = "VaultKern SimpleWebAuthn Smoke";
const userName = "smoke-user@example.com";
const userDisplayName = "Smoke User";
const userId = new TextEncoder().encode("vaultkern-smoke-user-1");
const expectedUserHandle = bufferToBase64url(userId);

export async function createSimpleWebAuthnSmokeServer(options = {}) {
  const hostname = options.hostname ?? "localhost";
  const rpId = options.rpId ?? hostname;
  const requestedPort = options.port ?? 8877;
  const userVerification = options.userVerification ?? "preferred";
  const state = {
    currentRegistrationChallenge: null,
    currentAuthenticationChallenge: null,
    credential: null
  };

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://localhost");
      const origin = publicOrigin(server, hostname);

      if (request.method === "GET" && url.pathname === "/") {
        sendHtml(response, renderPage());
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/status") {
        sendJson(response, {
          rpId,
          rpName,
          origin,
          userName,
          expectedUserHandle,
          hasCredential: Boolean(state.credential),
          registeredCredentialId: state.credential?.id ?? null
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/register/options") {
        const registrationOptions = await generateRegistrationOptions({
          rpName,
          rpID: rpId,
          userID: userId,
          userName,
          userDisplayName,
          timeout: 60_000,
          attestationType: "none",
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "preferred",
            userVerification
          },
          excludeCredentials: state.credential ? [{ id: state.credential.id }] : [],
          supportedAlgorithmIDs: [-7]
        });

        state.currentRegistrationChallenge = registrationOptions.challenge;
        sendJson(response, registrationOptions);
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/register/verify") {
        const body = await readJson(request);
        if (!state.currentRegistrationChallenge) {
          sendJson(response, { verified: false, error: "registration options not requested" }, 400);
          return;
        }

        const verification = await verifyRegistrationResponse({
          response: body,
          expectedChallenge: state.currentRegistrationChallenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
          requireUserVerification: false,
          supportedAlgorithmIDs: [-7]
        });

        if (verification.verified) {
          state.credential = verification.registrationInfo.credential;
        }
        state.currentRegistrationChallenge = null;

        sendJson(response, {
          verified: verification.verified,
          credentialId: state.credential?.id ?? null,
          userVerified: verification.registrationInfo?.userVerified ?? false,
          credentialBackedUp: verification.registrationInfo?.credentialBackedUp ?? false,
          credentialDeviceType: verification.registrationInfo?.credentialDeviceType ?? null
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/authenticate/options") {
        if (!state.credential) {
          sendJson(response, { error: "no registered credential" }, 409);
          return;
        }

        const discoverable = url.searchParams.get("discoverable") === "1";
        const authenticationOptions = await generateAuthenticationOptions({
          rpID: rpId,
          ...(discoverable ? {} : { allowCredentials: [{ id: state.credential.id }] }),
          timeout: 60_000,
          userVerification
        });

        state.currentAuthenticationChallenge = authenticationOptions.challenge;
        sendJson(response, authenticationOptions);
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/authenticate/verify") {
        const body = await readJson(request);
        if (!state.credential) {
          sendJson(response, { verified: false, error: "no registered credential" }, 409);
          return;
        }
        if (!state.currentAuthenticationChallenge) {
          sendJson(response, { verified: false, error: "authentication options not requested" }, 400);
          return;
        }

        const verification = await verifyAuthenticationResponse({
          response: body,
          expectedChallenge: state.currentAuthenticationChallenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
          credential: state.credential,
          requireUserVerification: false
        });

        state.currentAuthenticationChallenge = null;
        if (verification.verified) {
          state.credential.counter = verification.authenticationInfo.newCounter;
        }

        sendJson(response, {
          verified: verification.verified,
          credentialId: verification.authenticationInfo.credentialID,
          newCounter: verification.authenticationInfo.newCounter,
          expectedUserHandle,
          userHandle: body.response?.userHandle ?? null,
          userHandleMatchesExpected: body.response?.userHandle === expectedUserHandle,
          userVerified: verification.authenticationInfo.userVerified,
          credentialBackedUp: verification.authenticationInfo.credentialBackedUp,
          credentialDeviceType: verification.authenticationInfo.credentialDeviceType
        });
        return;
      }

      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("not found");
    } catch (error) {
      sendJson(
        response,
        {
          error: error instanceof Error ? error.message : "simplewebauthn smoke failed"
        },
        500
      );
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, hostname, () => {
      server.off("error", reject);
      resolve();
    });
  });

  return {
    origin: publicOrigin(server, hostname),
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function publicOrigin(server, hostname) {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("simplewebauthn smoke server is not listening");
  }
  const host = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  return `http://${host}:${address.port}`;
}

function sendJson(response, value, status = 200) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(value, null, 2));
}

function sendHtml(response, value) {
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(value);
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function renderPage() {
  return String.raw`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>VaultKern SimpleWebAuthn Smoke</title>
    <style>
      body {
        color: #111827;
        font-family:
          Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        background: #f7faf9;
      }

      main {
        box-sizing: border-box;
        margin: 0 auto;
        max-width: 760px;
        min-height: 100vh;
        padding: 32px 20px;
      }

      h1 {
        font-size: 28px;
        font-weight: 700;
        margin: 0 0 8px;
      }

      p {
        color: #4b5563;
        line-height: 1.55;
        margin: 0 0 20px;
      }

      section {
        background: #ffffff;
        border: 1px solid #d8e2df;
        border-radius: 8px;
        margin-top: 16px;
        padding: 16px;
      }

      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }

      button {
        appearance: none;
        background: #176b5c;
        border: 0;
        border-radius: 6px;
        color: #ffffff;
        cursor: pointer;
        font: inherit;
        font-weight: 650;
        min-height: 40px;
        padding: 0 14px;
      }

      button.secondary {
        background: #374151;
      }

      output,
      pre {
        background: #101827;
        border-radius: 6px;
        box-sizing: border-box;
        color: #d1fae5;
        display: block;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 12px;
        line-height: 1.45;
        margin-top: 12px;
        min-height: 44px;
        overflow: auto;
        padding: 10px;
        white-space: pre-wrap;
        width: 100%;
      }

      .ok {
        color: #065f46;
      }

      .error {
        color: #991b1b;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>VaultKern SimpleWebAuthn Smoke</h1>
      <p>
        This local relying party uses SimpleWebAuthn to verify both registration and authentication.
      </p>

      <section>
        <div class="actions">
          <button id="register" type="button">Register Passkey</button>
          <button id="login" type="button" class="secondary">Login With Passkey</button>
          <button id="login-discoverable" type="button" class="secondary">
            Discoverable Login With Passkey
          </button>
          <button id="status" type="button" class="secondary">Refresh Status</button>
        </div>
        <output id="result">Ready.</output>
      </section>

      <section>
        <strong>Status</strong>
        <pre id="status-json"></pre>
      </section>
    </main>
    <script>
      const result = document.querySelector("#result");
      const statusJson = document.querySelector("#status-json");

      document.querySelector("#register").addEventListener("click", () => run(registerPasskey));
      document.querySelector("#login").addEventListener("click", () => run(loginWithPasskey));
      document
        .querySelector("#login-discoverable")
        .addEventListener("click", () => run(loginWithDiscoverablePasskey));
      document.querySelector("#status").addEventListener("click", () => run(refreshStatus));

      refreshStatus().catch(showError);

      async function run(action) {
        try {
          await action();
        } catch (error) {
          showError(error);
        } finally {
          await refreshStatus().catch(() => undefined);
        }
      }

      async function registerPasskey() {
        result.value = "Requesting registration options...";
        const options = await postJson("/api/register/options");
        const credential = await navigator.credentials.create({
          publicKey: creationOptionsFromJson(options)
        });
        result.value = "Verifying registration...";
        const verification = await postJson("/api/register/verify", credentialToJson(credential));
        result.value = JSON.stringify(verification, null, 2);
        result.className = verification.verified ? "ok" : "error";
      }

      async function loginWithPasskey() {
        return loginWithPasskeyOptions(false);
      }

      async function loginWithDiscoverablePasskey() {
        return loginWithPasskeyOptions(true);
      }

      async function loginWithPasskeyOptions(discoverable) {
        result.value = "Requesting authentication options...";
        const options = await postJson(
          discoverable ? "/api/authenticate/options?discoverable=1" : "/api/authenticate/options"
        );
        const credential = await navigator.credentials.get({
          publicKey: requestOptionsFromJson(options)
        });
        result.value = "Verifying authentication...";
        const verification = await postJson("/api/authenticate/verify", credentialToJson(credential));
        result.value = JSON.stringify(verification, null, 2);
        result.className = verification.verified ? "ok" : "error";
      }

      async function refreshStatus() {
        const status = await getJson("/api/status");
        statusJson.textContent = JSON.stringify(status, null, 2);
      }

      async function getJson(path) {
        const response = await fetch(path);
        return readResponse(response);
      }

      async function postJson(path, body) {
        const response = await fetch(path, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body)
        });
        return readResponse(response);
      }

      async function readResponse(response) {
        const json = await response.json();
        if (!response.ok) {
          throw new Error(json.error || response.statusText);
        }
        return json;
      }

      function creationOptionsFromJson(options) {
        return {
          ...options,
          challenge: base64urlToBuffer(options.challenge),
          user: {
            ...options.user,
            id: base64urlToBuffer(options.user.id)
          },
          excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
            ...credential,
            id: base64urlToBuffer(credential.id)
          }))
        };
      }

      function requestOptionsFromJson(options) {
        return {
          ...options,
          challenge: base64urlToBuffer(options.challenge),
          allowCredentials: (options.allowCredentials || []).map((credential) => ({
            ...credential,
            id: base64urlToBuffer(credential.id)
          }))
        };
      }

      function credentialToJson(credential) {
        const json = {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment,
          clientExtensionResults: credential.getClientExtensionResults()
        };

        if ("attestationObject" in credential.response) {
          json.response = {
            attestationObject: bufferToBase64url(credential.response.attestationObject),
            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
          };
          if (typeof credential.response.getTransports === "function") {
            json.response.transports = credential.response.getTransports();
          }
          if (typeof credential.response.getPublicKey === "function") {
            const publicKey = credential.response.getPublicKey();
            if (publicKey) {
              json.response.publicKey = bufferToBase64url(publicKey);
            }
          }
          if (typeof credential.response.getPublicKeyAlgorithm === "function") {
            json.response.publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
          }
          return json;
        }

        json.response = {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle
            ? bufferToBase64url(credential.response.userHandle)
            : undefined
        };
        return json;
      }

      function base64urlToBuffer(value) {
        const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
        const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
          bytes[index] = binary.charCodeAt(index);
        }
        return bytes.buffer;
      }

      function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (const byte of bytes) {
          binary += String.fromCharCode(byte);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      }

      function showError(error) {
        result.value = error instanceof Error ? error.message : String(error);
        result.className = "error";
      }
    </script>
  </body>
</html>`;
}

function bufferToBase64url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const port = Number.parseInt(readArg("--port") ?? process.env.PORT ?? "8877", 10);
  const hostname = readArg("--host") ?? "localhost";
  const server = await createSimpleWebAuthnSmokeServer({ hostname, port });
  console.log(`VaultKern SimpleWebAuthn smoke server: ${server.origin}/`);
}

function readArg(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) {
    return null;
  }
  return process.argv[index + 1] ?? null;
}
