import { describe, expect, it } from "vitest";
import { SMOKE_HOST, smokeUrl } from "../../smoke/smokeUrls.mjs";
import { waitForWebAuthnDebugEvent } from "../../smoke/webauthnDebug.mjs";

describe("Chrome smoke server", () => {
  it("uses a WebAuthn-acceptable localhost RP host", () => {
    expect(SMOKE_HOST).toBe("localhost");
  });

  it("serves every smoke page from the bound host", async () => {
    expect(new URL(smokeUrl(8877, "basic-login.html")).hostname).toBe(SMOKE_HOST);
    expect(new URL(smokeUrl(8877, "passkey-register.html")).hostname).toBe(
      SMOKE_HOST
    );
    expect(new URL(smokeUrl(8877, "passkey-login.html")).hostname).toBe(
      SMOKE_HOST
    );
  });

  it("waits for asynchronously persisted WebAuthn debug events", async () => {
    const reads = [
      [],
      [{ event: "unlock_user_verification_complete", method: "master_password" }]
    ];

    await waitForWebAuthnDebugEvent(
      async () => reads.shift() ?? [],
      "unlock_user_verification_complete",
      { method: "master_password" },
      { label: "locked assertion", timeoutMs: 100, intervalMs: 1 }
    );

    expect(reads).toHaveLength(0);
  });
});
