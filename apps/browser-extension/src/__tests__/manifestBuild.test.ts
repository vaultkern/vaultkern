import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildManifest,
  chromiumExtensionIdFromManifestKey,
  E2E_EXTENSION_ID,
  E2E_MANIFEST_KEY,
  writeManifest
} from "../../scripts/manifestBuild.mjs";

const baseManifest = {
  manifest_version: 3,
  name: "VaultKern Browser",
  version: "0.1.0",
  permissions: ["storage", "nativeMessaging"],
  background: { service_worker: "background.js", type: "module" }
};

describe("manifest build", () => {
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

  it("keeps autofill top-frame only while injecting the isolated WebAuthn bridge in all frames", () => {
    const manifest = JSON.parse(readFileSync("manifest.json", "utf8"));

    expect(manifest.content_scripts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          js: ["contentScript.js"]
        }),
        expect.objectContaining({
          js: ["webauthnContentScript.js"],
          all_frames: true
        })
      ])
    );
    const autofillScript = manifest.content_scripts.find(
      (script: { js?: string[] }) => script.js?.includes("contentScript.js")
    );
    expect(autofillScript?.all_frames).not.toBe(true);
    expect(manifest.content_scripts).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          js: ["webauthnPageHook.js"]
        })
      ])
    );
  });
});
