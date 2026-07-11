import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  buildManifest,
  chromiumExtensionIdFromManifestKey,
  E2E_EXTENSION_ID,
  E2E_MANIFEST_KEY,
  writeManifest
} from "../../scripts/manifestBuild.mjs";
import {
  assertClassicContentScript,
  CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES
} from "../../scripts/verifyClassicContentScript.mjs";

const baseManifest = {
  manifest_version: 3,
  name: "VaultKern Browser",
  version: "0.1.0",
  permissions: ["storage", "nativeMessaging"],
  background: { service_worker: "background.js", type: "module" }
};

describe("manifest build", () => {
  it("rejects module syntax in the classic autofill content script", () => {
    expect(() => assertClassicContentScript("const installed = true;"))
      .not.toThrow();
    expect(() => assertClassicContentScript('import "./shared.js";')).toThrow(
      "must be a standalone classic script"
    );
    expect(() => assertClassicContentScript("export const installed = true;"))
      .toThrow("must be a standalone classic script");
    expect(() => assertClassicContentScript('void import("./shared.js");'))
      .toThrow("must not import additional chunks");
  });

  it("enforces the classic autofill content script byte budget inclusively", () => {
    expect(() =>
      assertClassicContentScript(" ".repeat(CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES))
    ).not.toThrow();
    expect(() =>
      assertClassicContentScript(
        " ".repeat(CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES + 1)
      )
    ).toThrow("61441 bytes and exceeds the 61440-byte budget");
  });

  it("rejects a production content bundle that exposes the synthetic submit bypass", () => {
    expect(() =>
      assertClassicContentScript(
        "globalThis.__vaultkernAllowSyntheticAutofillSubmitForTests = true;"
      )
    ).toThrow("must not expose the synthetic autofill submit test bypass");
  });

  it("measures the classic autofill content script budget as UTF-8 bytes", () => {
    const source = `//${"\u00e9".repeat(CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES / 2)}`;

    expect(source.length).toBeLessThanOrEqual(
      CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES
    );
    expect(Buffer.byteLength(source, "utf8")).toBeGreaterThan(
      CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES
    );
    expect(() => assertClassicContentScript(source)).toThrow(
      "bytes and exceeds the 61440-byte budget"
    );
  });

  it("declares a standalone extension options page", () => {
    const repoManifest = JSON.parse(
      readFileSync(
        join(
          dirname(fileURLToPath(import.meta.url)),
          "../../manifest.json"
        ),
        "utf8"
      )
    );

    expect(repoManifest.options_page).toBe("options.html");
  });

  it("omits the fixed extension key for normal production builds", () => {
    expect(buildManifest(baseManifest, { fixedKey: false })).not.toHaveProperty("key");
  });

  it("injects the fixed e2e key and exposes the stable Chromium extension id", () => {
    const manifest = buildManifest(baseManifest, { fixedKey: true });

    expect(manifest).toHaveProperty("key", E2E_MANIFEST_KEY);
    expect(chromiumExtensionIdFromManifestKey(E2E_MANIFEST_KEY)).toBe(E2E_EXTENSION_ID);
    expect(E2E_EXTENSION_ID).toBe("akgcahfkhhffgcafpbbeihpmniekohik");
  });

  it("writes the generated manifest to disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "vaultkern-manifest-"));
    const source = join(dir, "manifest.json");
    const destination = join(dir, "dist-manifest.json");
    writeFileSync(source, JSON.stringify(baseManifest), "utf8");

    writeManifest({ source, destination, fixedKey: true });

    const manifest = JSON.parse(readFileSync(destination, "utf8"));
    expect(manifest.key).toBe(E2E_MANIFEST_KEY);
  });

  it("installs the main-world autofill hook before the isolated content script", () => {
    const manifest = JSON.parse(readFileSync("manifest.json", "utf8"));

    const shadowHookIndex = manifest.content_scripts.findIndex(
      (script: { js?: string[] }) =>
        script.js?.includes("autofillShadowPageHook.js")
    );
    const autofillScriptIndex = manifest.content_scripts.findIndex(
      (script: { js?: string[] }) => script.js?.includes("contentScript.js")
    );

    expect(shadowHookIndex).toBeGreaterThanOrEqual(0);
    expect(autofillScriptIndex).toBeGreaterThan(shadowHookIndex);

    const shadowHook = manifest.content_scripts[shadowHookIndex];
    const autofillScript = manifest.content_scripts[autofillScriptIndex];
    expect(shadowHook).toMatchObject({
      js: ["autofillShadowPageHook.js"],
      run_at: "document_start",
      world: "MAIN"
    });
    expect(autofillScript).toMatchObject({
      js: ["contentScript.js"],
      run_at: "document_start"
    });
    expect(autofillScript.world ?? "ISOLATED").toBe("ISOLATED");
    expect(autofillScript.all_frames).not.toBe(true);
    expect(shadowHook?.all_frames).not.toBe(true);
  });

  it("keeps WebAuthn handling in every frame without a manifest page hook", () => {
    const manifest = JSON.parse(readFileSync("manifest.json", "utf8"));

    expect(manifest.content_scripts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          js: ["webauthnContentScript.js"],
          all_frames: true,
          match_origin_as_fallback: true
        })
      ])
    );
    expect(manifest.content_scripts).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          js: ["webauthnPageHook.js"]
        })
      ])
    );
  });
});
