#!/usr/bin/env node
import { writeManifest, E2E_EXTENSION_ID } from "./manifestBuild.mjs";

const fixedKey = process.argv.includes("--fixed-key");

writeManifest({
  source: "manifest.json",
  destination: "dist/manifest.json",
  fixedKey
});

if (fixedKey) {
  console.log(`e2e extension id: ${E2E_EXTENSION_ID}`);
}
