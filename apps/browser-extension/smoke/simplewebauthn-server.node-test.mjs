import assert from "node:assert/strict";
import { test } from "node:test";

import { createSimpleWebAuthnSmokeServer } from "./simplewebauthn-server.mjs";

test("simplewebauthn smoke server exposes RP status and registration options", async () => {
  const server = await createSimpleWebAuthnSmokeServer({
    port: 0
  });

  try {
    assert.equal(new URL(server.origin).hostname, "localhost");
    const status = await fetchJson(`${server.origin}/api/status`);
    assert.equal(status.rpId, "localhost");
    assert.equal(status.origin, server.origin);
    assert.equal(status.hasCredential, false);

    const options = await fetchJson(`${server.origin}/api/register/options`, {
      method: "POST"
    });
    assert.equal(options.rp.id, "localhost");
    assert.equal(options.rp.name, "VaultKern SimpleWebAuthn Smoke");
    assert.equal(options.user.name, "smoke-user@example.com");
    assert.equal(options.pubKeyCredParams[0].alg, -7);
    assert.equal(typeof options.challenge, "string");
    assert.ok(options.challenge.length > 10);
  } finally {
    await server.close();
  }
});

test("simplewebauthn smoke server advertises the requested listener host", async () => {
  const server = await createSimpleWebAuthnSmokeServer({
    hostname: "127.0.0.1",
    port: 0
  });

  try {
    assert.equal(new URL(server.origin).hostname, "127.0.0.1");
    const status = await fetchJson(`${server.origin}/api/status`);
    assert.equal(status.rpId, "127.0.0.1");
    assert.equal(status.origin, server.origin);

    const options = await fetchJson(`${server.origin}/api/register/options`, {
      method: "POST"
    });
    assert.equal(options.rp.id, "127.0.0.1");
  } finally {
    await server.close();
  }
});

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  assert.equal(response.status, 200);
  return response.json();
}
