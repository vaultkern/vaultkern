import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(path: string) {
  return readFileSync(path, "utf8");
}

describe("browser popup module seams", () => {
  it("keeps passkey protocol details out of the ordinary popup", () => {
    const ordinaryPopup = source("src/popup/PopupApp.tsx");

    expect(ordinaryPopup).not.toMatch(/webauthn/i);
    expect(ordinaryPopup).not.toContain("vaultkern_presence");
    expect(ordinaryPopup).not.toContain("vaultkern_user_verification");
    expect(ordinaryPopup).not.toContain("chrome.runtime");
    expect(ordinaryPopup).not.toContain("pendingSubmission");
    expect(ordinaryPopup).not.toContain(".transaction");
  });

  it("keeps browser transport details out of passkey presentation", () => {
    const passkeyPrompt = source("src/popup/PasskeyPromptApp.tsx");

    expect(passkeyPrompt).not.toContain("chrome");
    expect(passkeyPrompt).not.toContain("vaultkern_");
  });

  it("keeps both browser workflows independent of React", () => {
    const pendingLogin = source("src/popup/pendingLoginWorkflow.ts");
    const passkeyPrompt = source("src/popup/passkeyPromptWorkflow.ts");

    expect(pendingLogin).not.toMatch(/from ["']react["']/);
    expect(passkeyPrompt).not.toMatch(/from ["']react["']/);
  });
});
