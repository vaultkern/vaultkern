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

  it("wires confirmed login saves to ordinary resident mutations", () => {
    const popupShell = source("src/popupShell.tsx");
    const start = popupShell.indexOf("const pendingLoginWorkflow");
    const wiring = popupShell.slice(start, start + 1_400);

    expect(start).toBeGreaterThanOrEqual(0);
    expect(wiring).toContain("commit:");
    expect(wiring).toContain("client.createAutofillEntry");
    expect(wiring).toContain("client.updateAutofillEntryFields");
    expect(wiring).not.toContain("plan:");
    expect(wiring).not.toContain("execute:");
    expect(wiring).not.toContain("persistAutofillMutation");
  });

  it("has no browser-side atomic persist or replay engine", () => {
    const background = source("src/background.ts");
    const popupShell = source("src/popupShell.tsx");
    const pendingStore = source("src/autofill/pendingSubmissionStore.ts");

    for (const productionSource of [background, popupShell, pendingStore]) {
      expect(productionSource).not.toContain("persist_autofill_mutation");
      expect(productionSource).not.toContain("operationId");
      expect(productionSource).not.toContain("receipt");
    }
    expect(background).not.toContain("vaultkern_autofill_pending_execute");
    expect(background).not.toContain("vaultkern_autofill_pending_status");
    expect(background).not.toContain("recoverDetachedAutofillTransaction");
    expect(pendingStore).not.toContain("RecoveryStorage");
    expect(pendingStore).not.toContain("CompletionRecord");
  });
});
