import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const E2E_MANIFEST_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkQyx/y9NAFOYWyGXaii0OMzd0EjZG7eLWFc9pehWaLxwh0JRLZMGK15xCtXyr6CtL8DE1flCbpoo3/B/yKsBYISQP4I+JVpYvhv3Xe6akb1RX8KiSihzbGGRyW4YBZUFnj5O0TBUYNzpMOWxSDeJdc7NuRkI3c5QFzQPJB7Hzeg2bZAp8bK1+SG0SP9wo7HAV7c15eiNVvDbtlFJA6NRZ5jklH4AqCh9KbaXvA6gzYvxxOaU7FZS/iD5O1z42/y9FSw1pXO80EaL/61RBgIx+5crm7QG2fjGr9S+9YUCA7HxqCuEDcgcaPexNmFZvsSRw1bI3wh6ewEIyhSxTXi9pwIDAQAB";

export const E2E_EXTENSION_ID = "akgcahfkhhffgcafpbbeihpmniekohik";

export function chromiumExtensionIdFromManifestKey(key) {
  const publicKey = Buffer.from(key, "base64");
  const idHex = createHash("sha256").update(publicKey).digest("hex").slice(0, 32);

  return Array.from(idHex, (digit) =>
    String.fromCharCode("a".charCodeAt(0) + Number.parseInt(digit, 16))
  ).join("");
}

export function buildManifest(baseManifest, options = {}) {
  const manifest = { ...baseManifest };

  if (options.fixedKey) {
    manifest.key = E2E_MANIFEST_KEY;
  } else {
    delete manifest.key;
  }

  return manifest;
}

export function writeManifest({ source, destination, fixedKey = false }) {
  const baseManifest = JSON.parse(readFileSync(source, "utf8"));
  const manifest = buildManifest(baseManifest, { fixedKey });
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}
