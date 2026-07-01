import { describe, expect, it } from "vitest";
import { SMOKE_HOST, smokeUrl } from "../../smoke/smokeUrls.mjs";

describe("Chrome smoke server", () => {
  it("serves every smoke page from the bound host", async () => {
    expect(new URL(smokeUrl(8877, "basic-login.html")).hostname).toBe(SMOKE_HOST);
    expect(new URL(smokeUrl(8877, "passkey-register.html")).hostname).toBe(
      SMOKE_HOST
    );
    expect(new URL(smokeUrl(8877, "passkey-login.html")).hostname).toBe(
      SMOKE_HOST
    );
  });
});
