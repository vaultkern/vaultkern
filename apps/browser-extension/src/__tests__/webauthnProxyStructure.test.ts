import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("webauthn proxy structure", () => {
  it("keeps shared prompt state in one registry instead of per-mode parallel maps", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    for (const field of [
      "PromptWindowIds",
      "PromptContexts",
      "PromptNonces",
      "PromptRequestIds",
      "PromptRequestKeys",
      "PromptRemovalCleanups",
      "CompleteWaiters",
      "DismissWaiters",
      "PendingCompletePromptKeys",
      "PendingCompleteSignals"
    ]) {
      expect(source).not.toMatch(new RegExp(`const\\s+unlock${field}\\b`));
      expect(source).not.toMatch(new RegExp(`const\\s+presence${field}\\b`));
      expect(source).not.toMatch(
        new RegExp(`const\\s+userVerification${field}\\b`)
      );
    }

    expect(source).toContain("const promptStates = createPromptStateRegistry()");
    expect(source).not.toMatch(/function\s+closeUnlockPromptWindow\b/);
    expect(source).not.toMatch(/function\s+closePresencePromptWindow\b/);
    expect(source).not.toMatch(/function\s+closeUserVerificationPromptWindow\b/);
    expect(source).toContain("async function closePromptWindowForRequest");
    expect(source).not.toMatch(/function\s+waitForUnlockSignal\b/);
    expect(source).not.toMatch(/function\s+waitForPresenceSignal\b/);
    expect(source).not.toMatch(/function\s+waitForUserVerificationSignal\b/);
    expect(source).toContain("function waitForPromptSignal");
    expect(source).not.toMatch(/async function\s+openUnlockPrompt\b/);
    expect(source).not.toMatch(/async function\s+openPresencePrompt\b/);
    expect(source).not.toMatch(/async function\s+openUserVerificationPrompt\b/);
    expect(source).toContain("async function openPromptWindow");
    expect(source).not.toMatch(/function\s+watchUnlockPromptWindow\b/);
    expect(source).not.toMatch(/function\s+watchPresencePromptWindow\b/);
    expect(source).not.toMatch(/function\s+watchUserVerificationPromptWindow\b/);
    expect(source).toContain("function watchPromptWindow");
    expect(source).not.toMatch(/function\s+restoreUnlockPromptWindow\b/);
    expect(source).not.toMatch(/function\s+restorePresencePromptWindow\b/);
    expect(source).not.toMatch(/function\s+restoreUserVerificationPromptWindow\b/);
    expect(source).toContain("function restorePromptWindow");
  });

  it("loads active ceremony transitions from the runtime contract", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("passkey_ceremony_transitions.json");
    expect(source).not.toMatch(
      /const\s+PASSKEY_CEREMONY_TRANSITION_EDGES[\s\S]*?=\s*\[\s*\[/
    );
  });

  it("routes related-origin credential-resolution phase changes through one helper", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("function advanceToCredentialResolution");
    expect(source.match(/completeRelyingPartyValidation\(/g)).toHaveLength(2);
  });

  it("uses one ceremony phase advancer for live and resumed pipelines", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("function createPasskeyCeremonyAdvancer");
    expect(source.match(/const\s+advanceCeremony\s*=\s*async/g) ?? []).toHaveLength(
      0
    );
  });

  it("builds WebAuthn create success responses through one helper", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("function passkeyCreateCredentialResponseJson");
    expect(source.match(/attestationObject:/g) ?? []).toHaveLength(1);
  });

  it("builds WebAuthn get success responses through one helper", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("function passkeyGetCredentialResponseJson");
    expect(source.match(/signature:/g) ?? []).toHaveLength(1);
  });

  it("delivers WebAuthn get assertions through one helper", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("async function deliverPasskeyGetAssertion");
    expect(source.match(/responseJson: passkeyGetCredentialResponseJson/g) ?? [])
      .toHaveLength(1);
  });

  it("delivers WebAuthn create registrations through one helper", () => {
    const sourcePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../webauthnProxy.ts"
    );
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("async function deliverPasskeyCreateRegistration");
    expect(source.match(/responseJson: passkeyCreateCredentialResponseJson/g) ?? [])
      .toHaveLength(1);
  });
});
