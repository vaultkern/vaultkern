#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { createReadStream, existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import playwright from "playwright";

import { E2E_EXTENSION_ID } from "../scripts/manifestBuild.mjs";
import { createSimpleWebAuthnSmokeServer } from "./simplewebauthn-server.mjs";
import { SMOKE_HOST, smokeUrl } from "./smokeUrls.mjs";
import { waitForWebAuthnDebugEvent } from "./webauthnDebug.mjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const extensionRoot = resolve(__dirname, "..");
const repoRoot = resolve(extensionRoot, "../..");
const extensionPath = join(extensionRoot, "dist");
const runtimePath = join(repoRoot, "target/debug/vaultkern-runtime");
const vkdbxArgs = ["run", "-p", "vkdbx", "--", "roundtrip-demo"];
const PASSKEY_CREDENTIAL_OPTIONS_POLL_MS = 250;
const PASSKEY_CREDENTIAL_OPTIONS_TIMEOUT_MS = 15_000;
const password = "smoke-password";
const username = "smoke-user@example.com";
const entryPassword = "smoke-secret";
const FIXTURE_ENTRY_ID = "smoke-fixture-entry-id";

export const REQUIRED_CHROMIUM_CASES = Object.freeze([
  "native-kdbx-totp-passkey",
  "exact-origin-automatic-authorization",
  "autofill-shadow-visibility",
  "dynamic-shadow-submit",
  "nested-dynamic-shadow-submit",
  "trusted-spa-submit",
  "controlled-react-input",
  "large-dom-performance",
  "mv3-pending-session-reload",
  "autofill-native-crash-replay"
]);

function quotePosixShellWord(value, name) {
  if (typeof value !== "string" || value === "" || value.includes("\0")) {
    throw new TypeError(`${name} must be a non-empty POSIX path without NUL bytes`);
  }
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function createNativeCrashWrapperScript({
  runtimePath: nativeRuntimePath,
  pidLogPath,
  crashMarkerPath
}) {
  const runtime = quotePosixShellWord(nativeRuntimePath, "runtimePath");
  const pidLog = quotePosixShellWord(pidLogPath, "pidLogPath");
  const crashMarker = quotePosixShellWord(crashMarkerPath, "crashMarkerPath");
  return [
    "#!/bin/sh",
    "set -eu",
    `printf '%s\\n' "$$" >> ${pidLog}`,
    `export VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER=${crashMarker}`,
    `exec ${runtime} "$@"`,
    ""
  ].join("\n");
}

export function assertNativeCrashObservation({
  firstExecution,
  markerContent,
  pidLog,
  transactionId,
  operationId
}) {
  if (
    firstExecution?.ok !== false ||
    firstExecution?.error?.code !== "native_port_disconnected" ||
    firstExecution?.pending?.state !== "persisting" ||
    firstExecution.pending.transactionId !== transactionId ||
    firstExecution.pending.operationId !== operationId
  ) {
    throw new Error(
      `first autofill persistence attempt did not disconnect after commit: ` +
        JSON.stringify(firstExecution)
    );
  }
  const markerBinding = `${transactionId}:${operationId}`;
  if (markerContent !== `${markerBinding}\n`) {
    throw new Error(
      `native crash marker did not bind the durable operation: ` +
        JSON.stringify({ markerContent, markerBinding })
    );
  }
  const nativePids = pidLog
    .split(/\r?\n/u)
    .filter((line) => line !== "")
    .map((line) => Number(line));
  if (
    nativePids.length < 2 ||
    nativePids.some((pid) => !Number.isSafeInteger(pid) || pid <= 0)
  ) {
    throw new Error(`native PID log is invalid: ${JSON.stringify(pidLog)}`);
  }
  const distinctPids = [...new Set(nativePids)];
  if (distinctPids.length < 2) {
    throw new Error(
      `autofill recovery did not start a distinct native process: ` +
        JSON.stringify(nativePids)
    );
  }
  return {
    markerBinding,
    firstPid: distinctPids[0],
    recoveryPid: distinctPids.at(-1),
    nativePids,
    disconnectCode: firstExecution.error.code
  };
}

export function assertNativeReceiptReplay({
  receiptReplay,
  transactionId,
  operationId,
  vaultId,
  entryId,
  sourceContentSha256,
  sourceSizeBytes
}) {
  const expected = {
    type: "autofill_persist_result",
    transactionId,
    operationId,
    vaultId,
    outcome: "durable",
    disposition: "replayed",
    entryId,
    durability: "source",
    cacheState: "not_applicable",
    committedFingerprint: {
      contentSha256: sourceContentSha256,
      sizeBytes: sourceSizeBytes
    },
    mergeSummary: null,
    receiptVersion: 1
  };
  if (!isDeepStrictEqual(receiptReplay, expected)) {
    throw new Error(
      `native receipt did not replay exactly: ` +
        JSON.stringify({ receiptReplay, expected })
    );
  }
  return expected;
}

export function parseRequestedCases(args) {
  if (args.length === 0) {
    return [...REQUIRED_CHROMIUM_CASES];
  }

  const requestedCases = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== "--case") {
      throw new Error(`unexpected argument: ${args[index]}`);
    }
    const caseName = args[index + 1];
    if (typeof caseName !== "string" || caseName === "" || caseName === "--case") {
      throw new Error("--case requires a case name");
    }
    if (!REQUIRED_CHROMIUM_CASES.includes(caseName)) {
      throw new Error(`unknown Chromium case: ${caseName}`);
    }
    requestedCases.push(caseName);
    index += 1;
  }
  return requestedCases;
}

export function createManualFillEntryDetailMessage(targetUrl, entryId, payload) {
  if (typeof entryId !== "string" || entryId.trim() === "") {
    throw new Error("manual fill message requires a non-empty entryId");
  }
  return {
    type: "fill_entry_detail",
    ...payload,
    targetUrl,
    fillCapability: {
      kind: "manual",
      targetUrl,
      entryId
    }
  };
}

export function createControlledResourceGate() {
  let nextRequestId = 0;
  const blockedResponses = new Map();
  const waiters = [];

  function notifyBlocked(requestId) {
    const waiter = waiters.shift();
    if (!waiter) {
      return;
    }
    clearTimeout(waiter.timer);
    waiter.resolve(requestId);
  }

  function release(requestId) {
    const response = blockedResponses.get(requestId);
    if (!response) {
      throw new Error(`controlled resource request is not blocked: ${requestId}`);
    }
    blockedResponses.delete(requestId);
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
  }

  return {
    hold(response) {
      const requestId = `controlled-resource-${++nextRequestId}`;
      blockedResponses.set(requestId, response);
      notifyBlocked(requestId);
      return requestId;
    },
    waitForBlocked(timeoutMs = 10_000) {
      const [requestId] = blockedResponses.keys();
      if (requestId) {
        return Promise.resolve(requestId);
      }
      return new Promise((resolvePromise, rejectPromise) => {
        const waiter = {
          resolve: resolvePromise,
          timer: setTimeout(() => {
            const index = waiters.indexOf(waiter);
            if (index >= 0) {
              waiters.splice(index, 1);
            }
            rejectPromise(
              new Error("controlled resource was not requested before the deadline")
            );
          }, timeoutMs)
        };
        waiters.push(waiter);
      });
    },
    release,
    releaseAll() {
      for (const requestId of [...blockedResponses.keys()]) {
        release(requestId);
      }
    }
  };
}

export function automaticAttemptCompleteDiagnostic(
  debugLog,
  { tabId, pageUrl, afterSequence, expectedOutcome }
) {
  if (!Array.isArray(debugLog)) {
    return null;
  }

  const backgroundEvent = [...debugLog].reverse().find(
    (entry) =>
      entry?.event === "page_load_autofill_attempt_complete" &&
      entry?.tabId === tabId &&
      entry?.targetUrl === pageUrl &&
      Number.isInteger(entry?.sequence) &&
      entry.sequence > afterSequence
  );
  if (!backgroundEvent) {
    return null;
  }
  if (backgroundEvent.outcome !== expectedOutcome) {
    throw new Error(
      `automatic attempt completed with unexpected outcome: ` +
        JSON.stringify({
          expectedOutcome,
          actualOutcome: backgroundEvent.outcome,
          sequence: backgroundEvent.sequence,
          tabId,
          pageUrl
        })
    );
  }

  return {
    event: "automatic-attempt-complete",
    sequence: backgroundEvent.sequence,
    outcome: backgroundEvent.outcome,
    tabId,
    targetUrl: pageUrl,
    backgroundEventAt:
      typeof backgroundEvent.at === "string" ? backgroundEvent.at : null
  };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit"
  });

  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed${result.stderr ? `\n${result.stderr}` : ""}`
    );
  }

  return result.stdout ?? "";
}

function contentType(path) {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

async function assertE2EManifest() {
  const manifest = JSON.parse(await readFile(join(extensionPath, "manifest.json"), "utf8"));
  if (manifest.key == null) {
    throw new Error("dist/manifest.json does not contain a fixed key; run npm run build:e2e first");
  }
  return manifest;
}

function chromiumExtensionArgs() {
  return [
    `--disable-extensions-except=${extensionPath}`,
    `--load-extension=${extensionPath}`,
    "--no-proxy-server",
    "--host-resolver-rules=MAP *.vaultkern.example.com 127.0.0.1, MAP vaultkern.example.com 127.0.0.1"
  ];
}

async function launchExtensionContext(profilePath) {
  const context = await playwright.chromium.launchPersistentContext(profilePath, {
    channel: "chromium",
    headless: true,
    args: chromiumExtensionArgs()
  });
  let serviceWorker = context.serviceWorkers()[0];
  if (!serviceWorker) {
    serviceWorker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
  }
  const extensionId = serviceWorker.url().split("/")[2];
  if (extensionId !== E2E_EXTENSION_ID) {
    throw new Error(`unexpected extension id: ${extensionId}, expected ${E2E_EXTENSION_ID}`);
  }
  const extensionPage = await context.newPage();
  await extensionPage.goto(`chrome-extension://${extensionId}/popup.html`);
  return { context, extensionId, extensionPage, serviceWorker };
}

async function buildControlledReactFixture(outputDir) {
  const { build } = await import("vite");
  await build({
    configFile: false,
    logLevel: "error",
    root: repoRoot,
    build: {
      emptyOutDir: true,
      outDir: outputDir,
      rollupOptions: {
        input: join(__dirname, "controlled-react-input.jsx"),
        output: {
          entryFileNames: "controlled-react-input.js"
        }
      }
    }
  });
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

async function waitForTwoAnimationFrames(page) {
  await page.evaluate(
    () =>
      new Promise((resolvePromise) =>
        requestAnimationFrame(() => requestAnimationFrame(resolvePromise))
      )
  );
}

async function targetTabId(extensionPage, targetUrl) {
  return await extensionPage.evaluate(async (url) => {
    const tab = (await chrome.tabs.query({})).find((candidate) => candidate.url === url);
    if (!tab?.id) {
      throw new Error(`target tab not found: ${url}`);
    }
    return tab.id;
  }, targetUrl);
}

export async function startSmokeServer({
  additionalRoots = [],
  controlledResourceGate = null
} = {}) {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${SMOKE_HOST}`);
    if (url.pathname === "/slow-smoke-resource") {
      if (controlledResourceGate) {
        controlledResourceGate.hold(response);
      } else {
        response.writeHead(204, { "cache-control": "no-store" });
        response.end();
      }
      return;
    }
    const name = basename(url.pathname === "/" ? "basic-login.html" : url.pathname);
    const file = [__dirname, ...additionalRoots]
      .map((root) => join(root, name))
      .find((candidate) => existsSync(candidate));

    if (!file) {
      response.writeHead(404);
      response.end("not found");
      return;
    }

    response.writeHead(200, { "content-type": contentType(file) });
    createReadStream(file).pipe(response);
  });

  await new Promise((resolvePromise) => server.listen(0, SMOKE_HOST, resolvePromise));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to bind smoke server");
  }

  return {
    port: address.port,
    url: smokeUrl(address.port, "basic-login.html"),
    automaticLoginUrl: smokeUrl(address.port, "automatic-login.html"),
    noisyLoginUrl: smokeUrl(address.port, "noisy-login.html"),
    totpUrl: smokeUrl(address.port, "totp.html"),
    controlledReactInputUrl: smokeUrl(address.port, "controlled-react-input.html"),
    autofillLargeDomUrl: smokeUrl(address.port, "autofill-large-dom.html"),
    autofillShadowVisibilityUrl: smokeUrl(
      address.port,
      "autofill-shadow-visibility.html"
    ),
    autofillClippedPasswordUrl: smokeUrl(
      address.port,
      "autofill-clipped-password.html"
    ),
    autofillLabelCoveredPasswordUrl: smokeUrl(
      address.port,
      "autofill-label-covered-password.html"
    ),
    autofillFilterOpacityLoginUrl: smokeUrl(
      address.port,
      "autofill-filter-opacity-login.html"
    ),
    autofillTransparentMaskLoginUrl: smokeUrl(
      address.port,
      "autofill-transparent-mask-login.html"
    ),
    autofillPointerOverlayLoginUrl: smokeUrl(
      address.port,
      "autofill-pointer-overlay-login.html"
    ),
    autofillPointerOverlayDecoyLoginUrl: smokeUrl(
      address.port,
      "autofill-pointer-overlay-decoy-login.html"
    ),
    autofillExact8pxPasswordUrl: smokeUrl(
      address.port,
      "autofill-exact-8px-password.html"
    ),
    autofillPartial8pxPasswordUrl: smokeUrl(
      address.port,
      "autofill-partial-8px-password.html"
    ),
    passkeyRegisterUrl: smokeUrl(address.port, "passkey-register.html"),
    passkeyUrl: smokeUrl(address.port, "passkey-login.html"),
    close: () => new Promise((resolvePromise) => server.close(resolvePromise))
  };
}

async function runAutofillShadowVisibilityCase() {
  const manifest = JSON.parse(await readFile(join(extensionPath, "manifest.json"), "utf8"));
  if (manifest.key == null) {
    throw new Error("dist/manifest.json does not contain a fixed key; run npm run build:e2e first");
  }

  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-shadow-visibility-"));
  let context;
  let server;
  try {
    server = await startSmokeServer();
    context = await playwright.chromium.launchPersistentContext(join(workDir, "profile"), {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`
      ]
    });
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    }
    const extensionId = serviceWorker.url().split("/")[2];
    const extensionPage = await context.newPage();
    await extensionPage.goto(`chrome-extension://${extensionId}/popup.html`);
    const page = await context.newPage();
    await page.goto(server.autofillShadowVisibilityUrl);

    const shadowTopology = await page.evaluate(() => {
      const unslotted = document.querySelector("#unslotted-password");
      const unslottedRect = unslotted.getBoundingClientRect();
      return {
        closed: globalThis.__vaultkernClosedShadowProbe(),
        unslotted: {
          value: unslotted.value,
          width: unslottedRect.width,
          height: unslottedRect.height,
          clientRects: unslotted.getClientRects().length
        }
      };
    });
    if (
      shadowTopology.closed.publicRoot !== null ||
      shadowTopology.closed.width <= 0 ||
      shadowTopology.closed.height <= 0
    ) {
      throw new Error(`closed-shadow fixture was not genuinely closed: ${JSON.stringify(shadowTopology)}`);
    }
    if (
      shadowTopology.unslotted.width !== 0 ||
      shadowTopology.unslotted.height !== 0 ||
      shadowTopology.unslotted.clientRects !== 0
    ) {
      throw new Error(`unslotted fixture unexpectedly rendered: ${JSON.stringify(shadowTopology)}`);
    }

    const hitTest = await page.evaluate(() => {
      const host = document.querySelector("#host");
      const target = host.shadowRoot.querySelector("#shadow-password");
      const box = target.getBoundingClientRect();
      const x = box.left + box.width / 2;
      const y = box.top + box.height / 2;
      return {
        documentTarget: document.elementFromPoint(x, y)?.id ?? null,
        shadowTarget: host.shadowRoot.elementFromPoint(x, y)?.id ?? null
      };
    });
    if (hitTest.shadowTarget !== "shadow-password") {
      throw new Error(`open shadow root hit test failed: ${JSON.stringify(hitTest)}`);
    }

    await sendFillEntryDetailWithoutCapability(
      extensionPage,
      server.autofillShadowVisibilityUrl,
      { password: entryPassword }
    );
    const unauthorizedValue = await page.evaluate(
      () => document.querySelector("#host").shadowRoot.querySelector("#shadow-password").value
    );
    if (unauthorizedValue !== "") {
      throw new Error(`shadow fill without a capability released: ${unauthorizedValue}`);
    }

    await sendFillEntryDetail(
      extensionPage,
      server.autofillShadowVisibilityUrl,
      FIXTURE_ENTRY_ID,
      {
        password: entryPassword
      }
    );
    const value = await page.evaluate(
      () => document.querySelector("#host").shadowRoot.querySelector("#shadow-password").value
    );
    if (value !== entryPassword) {
      throw new Error(
        `visible open-shadow password was rejected: ${JSON.stringify({ hitTest, value })}`
      );
    }
    const rejectedShadowValues = await page.evaluate(() => ({
      closed: globalThis.__vaultkernClosedShadowProbe().value,
      unslotted: document.querySelector("#unslotted-password").value
    }));
    if (rejectedShadowValues.closed !== "" || rejectedShadowValues.unslotted !== "") {
      throw new Error(
        `inaccessible shadow targets were filled: ${JSON.stringify(rejectedShadowValues)}`
      );
    }

    const exact8pxPage = await context.newPage();
    await exact8pxPage.goto(server.autofillExact8pxPasswordUrl);
    const exact8pxHitTest = await exact8pxPage.evaluate(() => {
      const target = document.querySelector("#exact-8px-password");
      const box = target.getBoundingClientRect();
      return {
        width: box.width,
        height: box.height,
        inner: document.elementFromPoint(box.right - 1, box.bottom - 1)?.id ?? null,
        boundary: document.elementFromPoint(box.right, box.bottom)?.id ?? null
      };
    });
    if (
      exact8pxHitTest.width !== 8 ||
      exact8pxHitTest.height !== 8 ||
      exact8pxHitTest.inner !== "exact-8px-password" ||
      exact8pxHitTest.boundary === "exact-8px-password"
    ) {
      throw new Error(`exact 8px fixture was not half-open: ${JSON.stringify(exact8pxHitTest)}`);
    }
    await sendFillEntryDetail(
      extensionPage,
      server.autofillExact8pxPasswordUrl,
      FIXTURE_ENTRY_ID,
      { password: entryPassword }
    );
    const exact8pxValue = await exact8pxPage.locator("#exact-8px-password").inputValue();
    if (exact8pxValue !== entryPassword) {
      throw new Error(
        `exact 8px password was rejected: ${JSON.stringify({ exact8pxHitTest, exact8pxValue })}`
      );
    }

    const partial8pxPage = await context.newPage();
    await partial8pxPage.goto(server.autofillPartial8pxPasswordUrl);
    const partial8pxHitTest = await partial8pxPage.evaluate(() => {
      const target = document.querySelector("#partial-8px-password");
      const box = target.getBoundingClientRect();
      return {
        inner: document.elementFromPoint(box.left + 7, box.top + 7)?.id ?? null,
        rightBoundary: document.elementFromPoint(box.left + 8, box.top + 4)?.id ?? null,
        bottomBoundary: document.elementFromPoint(box.left + 4, box.top + 8)?.id ?? null
      };
    });
    if (
      partial8pxHitTest.inner !== "partial-8px-password" ||
      partial8pxHitTest.rightBoundary !== "right-cover" ||
      partial8pxHitTest.bottomBoundary !== "bottom-cover"
    ) {
      throw new Error(
        `partial 8px fixture was not half-open: ${JSON.stringify(partial8pxHitTest)}`
      );
    }
    await sendFillEntryDetail(
      extensionPage,
      server.autofillPartial8pxPasswordUrl,
      FIXTURE_ENTRY_ID,
      { password: entryPassword }
    );
    const partial8pxValue = await partial8pxPage
      .locator("#partial-8px-password")
      .inputValue();
    if (partial8pxValue !== "") {
      throw new Error(
        `partially covered password bypassed strong visibility proof: ` +
          JSON.stringify({ partial8pxHitTest, partial8pxValue })
      );
    }

    const clippedPage = await context.newPage();
    await clippedPage.goto(server.autofillClippedPasswordUrl);
    const clippedHitTest = await clippedPage.evaluate(() => {
      const target = document.querySelector("#clipped-password");
      const box = target.getBoundingClientRect();
      const centerX = box.left + box.width / 2;
      const centerY = box.top + box.height / 2;
      return {
        center: document.elementFromPoint(centerX, centerY)?.id ?? null,
        offset: document.elementFromPoint(centerX + 4, centerY + 4)?.id ?? null
      };
    });
    if (
      clippedHitTest.center !== "clipped-password" ||
      clippedHitTest.offset === "clipped-password"
    ) {
      throw new Error(
        `clipped password fixture did not expose a one-point hit: ${JSON.stringify(clippedHitTest)}`
      );
    }
    await sendFillEntryDetail(
      extensionPage,
      server.autofillClippedPasswordUrl,
      FIXTURE_ENTRY_ID,
      { password: entryPassword }
    );
    const clippedValue = await clippedPage.locator("#clipped-password").inputValue();
    if (clippedValue !== "") {
      throw new Error(
        `circle-clipped password was filled: ${JSON.stringify({ clippedHitTest, clippedValue })}`
      );
    }

    const labelCoveredPage = await context.newPage();
    await labelCoveredPage.goto(server.autofillLabelCoveredPasswordUrl);
    const labelHitTest = await labelCoveredPage.evaluate(() => {
      const target = document.querySelector("#label-covered-password");
      const box = target.getBoundingClientRect();
      return document.elementFromPoint(
        box.left + box.width / 2,
        box.top + box.height / 2
      )?.id ?? null;
    });
    if (labelHitTest !== "password-cover") {
      throw new Error(`label-covered password fixture did not hit the label: ${labelHitTest}`);
    }
    await sendFillEntryDetail(
      extensionPage,
      server.autofillLabelCoveredPasswordUrl,
      FIXTURE_ENTRY_ID,
      { password: entryPassword }
    );
    const labelCoveredValue = await labelCoveredPage
      .locator("#label-covered-password")
      .inputValue();
    if (labelCoveredValue !== "") {
      throw new Error(
        `label-covered password was filled: ${JSON.stringify({ labelHitTest, labelCoveredValue })}`
      );
    }

    const paintVisibilityCases = [
      {
        name: "filter-opacity",
        url: server.autofillFilterOpacityLoginUrl,
        usernameId: "filtered-username",
        passwordId: "filtered-password",
        expectedTrackedVisibility: false
      },
      {
        name: "transparent-mask",
        url: server.autofillTransparentMaskLoginUrl,
        usernameId: "masked-username",
        passwordId: "masked-password",
        expectedTrackedVisibility: true
      },
      {
        name: "pointer-events-overlay",
        url: server.autofillPointerOverlayLoginUrl,
        usernameId: "covered-username",
        passwordId: "covered-password",
        expectedTrackedVisibility: false
      },
      {
        name: "pointer-events-overlay-with-hit-decoy",
        url: server.autofillPointerOverlayDecoyLoginUrl,
        usernameId: "decoy-username",
        passwordId: "decoy-password",
        expectedTrackedVisibility: false
      }
    ];
    const paintVisibilityEvidence = [];
    for (const fixtureCase of paintVisibilityCases) {
      const fixturePage = await context.newPage();
      await fixturePage.goto(fixtureCase.url);
      const evidence = await fixturePage.evaluate(
        async ({ usernameId, passwordId }) => {
          const target = document.getElementById(passwordId);
          const box = target.getBoundingClientRect();
          const trackedVisibility = await new Promise((resolvePromise) => {
            let observer;
            const timer = setTimeout(
              () => resolvePromise({ supported: false, reason: "timeout" }),
              2_000
            );
            try {
              observer = new IntersectionObserver(
                (entries) => {
                  const entry = entries.find((candidate) => candidate.target === target);
                  if (!entry) {
                    return;
                  }
                  clearTimeout(timer);
                  observer.disconnect();
                  resolvePromise({
                    supported: typeof entry.isVisible === "boolean",
                    isVisible: entry.isVisible,
                    isIntersecting: entry.isIntersecting
                  });
                },
                { trackVisibility: true, delay: 100 }
              );
              observer.observe(target);
            } catch (error) {
              clearTimeout(timer);
              resolvePromise({ supported: false, reason: String(error) });
            }
          });
          return {
            hitTarget:
              document.elementFromPoint(
                box.left + box.width / 2,
                box.top + box.height / 2
              )?.id ?? null,
            trackedVisibility,
            usernameValue: document.getElementById(usernameId).value,
            passwordValue: target.value
          };
        },
        {
          usernameId: fixtureCase.usernameId,
          passwordId: fixtureCase.passwordId
        }
      );
      if (
        evidence.hitTarget !== fixtureCase.passwordId ||
        evidence.trackedVisibility.supported !== true ||
        evidence.trackedVisibility.isVisible !==
          fixtureCase.expectedTrackedVisibility
      ) {
        throw new Error(
          `${fixtureCase.name} fixture did not reproduce Chromium paint disagreement: ` +
            JSON.stringify(evidence)
        );
      }
      await sendAutomaticFillEntryDetail(
        extensionPage,
        fixtureCase.url,
        FIXTURE_ENTRY_ID,
        { username, password: entryPassword }
      );
      const values = await fixturePage.evaluate(
        ({ usernameId, passwordId }) => ({
          username: document.getElementById(usernameId).value,
          password: document.getElementById(passwordId).value
        }),
        {
          usernameId: fixtureCase.usernameId,
          passwordId: fixtureCase.passwordId
        }
      );
      if (values.username !== "" || values.password !== "") {
        throw new Error(
          `${fixtureCase.name} visually hidden login was filled: ` +
            JSON.stringify({ evidence, values })
        );
      }
      await sendFillEntryDetail(
        extensionPage,
        fixtureCase.url,
        FIXTURE_ENTRY_ID,
        { username, password: entryPassword }
      );
      const manualValues = await fixturePage.evaluate(
        ({ usernameId, passwordId }) => ({
          username: document.getElementById(usernameId).value,
          password: document.getElementById(passwordId).value
        }),
        {
          usernameId: fixtureCase.usernameId,
          passwordId: fixtureCase.passwordId
        }
      );
      if (manualValues.username !== "" || manualValues.password !== "") {
        throw new Error(
          `${fixtureCase.name} manual fill bypassed available visual proof: ` +
            JSON.stringify({ evidence, manualValues })
        );
      }
      paintVisibilityEvidence.push({
        name: fixtureCase.name,
        ...evidence,
        automaticValues: values,
        manualValues
      });
      await fixturePage.close();
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: "autofill-shadow-visibility",
        hitTest,
        shadowTopology,
        rejectedShadowValues,
        exact8pxHitTest,
        partial8pxHitTest,
        clippedHitTest,
        labelHitTest,
        paintVisibilityEvidence
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function runDynamicShadowSubmitCase({ nested = false } = {}) {
  const caseName = nested ? "nested-dynamic-shadow-submit" : "dynamic-shadow-submit";
  const manifest = JSON.parse(await readFile(join(extensionPath, "manifest.json"), "utf8"));
  if (manifest.key == null) {
    throw new Error("dist/manifest.json does not contain a fixed key; run npm run build:e2e first");
  }

  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-dynamic-shadow-submit-"));
  let context;
  let server;
  try {
    server = await startSmokeServer();
    context = await playwright.chromium.launchPersistentContext(join(workDir, "profile"), {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`
      ]
    });
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    }
    const extensionId = serviceWorker.url().split("/")[2];
    const extensionPage = await context.newPage();
    await extensionPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await extensionPage.evaluate(() => {
      globalThis.__vaultkernDynamicShadowSubmissions = [];
      chrome.runtime.onMessage.addListener((message) => {
        if (message?.type === "vaultkern_autofill_submission") {
          globalThis.__vaultkernDynamicShadowSubmissions.push(message);
        }
      });
    });

    const page = await context.newPage();
    await page.goto(server.url);
    await page.evaluate(() => {
      document.body.innerHTML = `
        <iframe name="shadow-submit-sink" hidden></iframe>
        <div id="dynamic-shadow-host"></div>
        <div id="outer-shadow-host"></div>
      `;
      globalThis.__vaultkernShadowBridgeObservations = {
        window: 0,
        document: 0,
        host: 0
      };
      const eventType = "vaultkern:autofill:open-shadow-root";
      window.addEventListener(
        eventType,
        () => globalThis.__vaultkernShadowBridgeObservations.window += 1,
        { capture: true }
      );
      document.addEventListener(
        eventType,
        () => globalThis.__vaultkernShadowBridgeObservations.document += 1,
        { capture: true }
      );
      for (const host of document.querySelectorAll(
        "#dynamic-shadow-host, #outer-shadow-host"
      )) {
        host.addEventListener(
          eventType,
          () => globalThis.__vaultkernShadowBridgeObservations.host += 1,
          { capture: true }
        );
      }
    });
    await page.evaluate(() =>
      new Promise((resolvePromise) => requestAnimationFrame(() => resolvePromise()))
    );
    if (nested) {
      await page.evaluate(() => {
        const outerHost = document.querySelector("#outer-shadow-host");
        const outerRoot = outerHost.attachShadow({ mode: "open" });
        outerRoot.innerHTML = `<div id="inner-shadow-host"></div>`;
      });
      await page.evaluate(() =>
        new Promise((resolvePromise) => requestAnimationFrame(() => resolvePromise()))
      );
      await page.evaluate(() => {
        const outerRoot = document.querySelector("#outer-shadow-host").shadowRoot;
        const innerHost = outerRoot.querySelector("#inner-shadow-host");
        const innerRoot = innerHost.attachShadow({ mode: "open" });
        innerRoot.innerHTML = `
          <form action="/shadow-submit" target="shadow-submit-sink">
            <input name="email" type="email" autocomplete="username" value="shadow@example.com" />
            <input name="password" type="password" autocomplete="current-password" value="shadow-secret" />
            <button type="submit">Submit shadow form</button>
          </form>
        `;
      });
    } else {
      await page.evaluate(() => {
        const host = document.querySelector("#dynamic-shadow-host");
        const root = host.attachShadow({ mode: "open" });
        root.innerHTML = `
          <form action="/shadow-submit" target="shadow-submit-sink">
            <input name="email" type="email" autocomplete="username" value="shadow@example.com" />
            <input name="password" type="password" autocomplete="current-password" value="shadow-secret" />
            <button type="submit">Submit shadow form</button>
          </form>
        `;
        root.addEventListener(
          "submit",
          (event) => {
            event.preventDefault();
            event.stopImmediatePropagation();
          },
          { capture: true }
        );
      });
    }

    const bridgePrivacy = await page.evaluate(() => {
      const attachShadow = Element.prototype.attachShadow;
      return {
        marker:
          Element.prototype[Symbol.for("vaultkern.autofill.shadowPageHookInstalled")] === true,
        observations: globalThis.__vaultkernShadowBridgeObservations,
        hookSurface: {
          name: attachShadow.name,
          length: attachShadow.length,
          source: Function.prototype.toString.call(attachShadow)
        }
      };
    });
    if (
      bridgePrivacy.marker ||
      Object.values(bridgePrivacy.observations).some((count) => count !== 0) ||
      bridgePrivacy.hookSurface.name !== "attachShadow" ||
      bridgePrivacy.hookSurface.length !== 1 ||
      !bridgePrivacy.hookSurface.source.includes("[native code]") ||
      bridgePrivacy.hookSurface.source.includes("vaultkern:autofill:open-shadow-root") ||
      bridgePrivacy.hookSurface.source.includes("attachShadowWithAutofillNotification")
    ) {
      throw new Error(`shadow discovery bridge leaked to the page: ${JSON.stringify(bridgePrivacy)}`);
    }

    const submittedAfter = Date.now();
    await page.getByRole("button", { name: "Submit shadow form" }).click();
    await extensionPage.waitForFunction(
      () => globalThis.__vaultkernDynamicShadowSubmissions?.length > 0,
      undefined,
      { timeout: 5_000 }
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
    const submissions = await extensionPage.evaluate(
      () => globalThis.__vaultkernDynamicShadowSubmissions
    );
    if (
      submissions.length !== 1 ||
      new URL(submissions[0]?.url ?? "about:blank").origin !== new URL(server.url).origin ||
      submissions[0]?.url !== server.url ||
      submissions[0]?.username !== "shadow@example.com" ||
      submissions[0]?.password !== "shadow-secret" ||
      submissions[0]?.newPassword !== undefined ||
      submissions[0]?.saveOnly !== undefined ||
      typeof submissions[0]?.submittedAt !== "number" ||
      submissions[0].submittedAt < submittedAfter ||
      submissions[0].submittedAt > Date.now()
    ) {
      throw new Error(`unexpected dynamic shadow submissions: ${JSON.stringify(submissions)}`);
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: caseName,
        count: 1,
        origin: new URL(submissions[0].url).origin,
        bridgePrivacy,
        fields: {
          username: submissions[0].username,
          password: submissions[0].password
        }
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function runTrustedSpaSubmitCase() {
  const manifest = JSON.parse(await readFile(join(extensionPath, "manifest.json"), "utf8"));
  if (manifest.key == null) {
    throw new Error("dist/manifest.json does not contain a fixed key; run npm run build:e2e first");
  }

  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-trusted-spa-submit-"));
  let context;
  let server;
  try {
    server = await startSmokeServer();
    context = await playwright.chromium.launchPersistentContext(join(workDir, "profile"), {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`
      ]
    });
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    }
    const extensionId = serviceWorker.url().split("/")[2];
    const extensionPage = await context.newPage();
    await extensionPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await extensionPage.evaluate(() => {
      globalThis.__vaultkernTrustedSpaSubmissions = [];
      chrome.runtime.onMessage.addListener((message) => {
        if (message?.type === "vaultkern_autofill_submission") {
          globalThis.__vaultkernTrustedSpaSubmissions.push(message);
        }
      });
    });

    const page = await context.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) =>
      pageErrors.push({ name: error?.name, message: error?.message, stack: error?.stack })
    );
    page.on("console", (message) => {
      if (message.type() === "error") {
        pageErrors.push(message.text());
      }
    });
    await page.goto(server.url);
    await page.evaluate(() => {
      globalThis.__vaultkernSpaSubmitObservations = [];
      document
        .querySelector("#vaultkern-smoke-login-form")
        .addEventListener("submit", (event) => {
          globalThis.__vaultkernSpaSubmitObservations.push({
            isTrusted: event.isTrusted,
            defaultPrevented: event.defaultPrevented,
            submitterId: event.submitter?.id ?? null
          });
        });
    });

    await page.locator("#vaultkern-smoke-username").fill("spa@example.com");
    await page.locator("#vaultkern-smoke-password").fill("spa-secret");
    const assertNoSubmission = async (label) => {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
      const state = await extensionPage.evaluate(async (pageUrl) => {
        const tabs = await chrome.tabs.query({ url: pageUrl });
        const tab = tabs.find((candidate) => candidate.url === pageUrl);
        const response = tab?.id
          ? await chrome.runtime.sendMessage({
              type: "vaultkern_autofill_pending_request",
              tabId: tab.id
            })
          : null;
        return {
          captures: globalThis.__vaultkernTrustedSpaSubmissions,
          pending: response?.pending ?? null
        };
      }, server.url);
      if (state.captures.length !== 0 || state.pending !== null) {
        throw new Error(`${label} created an autofill submission: ${JSON.stringify(state)}`);
      }
    };

    await page.evaluate(() => {
      const form = document.querySelector("#vaultkern-smoke-login-form");
      const submitter = document.querySelector("#vaultkern-smoke-submit");
      form.requestSubmit(submitter);
    });
    await assertNoSubmission("script requestSubmit");

    await page.evaluate(() => {
      document.querySelector("#vaultkern-smoke-submit").click();
    });
    await assertNoSubmission("script button.click");

    await page.evaluate(() => {
      document.querySelector("#vaultkern-smoke-login-form").dispatchEvent(
        new SubmitEvent("submit", {
          bubbles: true,
          cancelable: true,
          composed: true
        })
      );
    });
    await assertNoSubmission("script-dispatched SubmitEvent");

    await page.evaluate(() => {
      const form = document.querySelector("#vaultkern-smoke-login-form");
      const submitter = document.querySelector("#vaultkern-smoke-submit");
      const checkbox = document.createElement("input");
      checkbox.id = "vaultkern-smoke-non-textlike";
      checkbox.type = "checkbox";
      checkbox.addEventListener(
        "keydown",
        (event) => {
          if (event.isTrusted && event.key === "Enter") {
            event.preventDefault();
            form.requestSubmit(submitter);
          }
        },
        { once: true }
      );
      form.prepend(checkbox);
    });
    await page.locator("#vaultkern-smoke-non-textlike").press("Enter");
    await assertNoSubmission("trusted Enter on non-textlike input");

    await page.locator("#vaultkern-smoke-password").press("Enter");
    await extensionPage.waitForFunction(
      () => globalThis.__vaultkernTrustedSpaSubmissions?.length === 1,
      undefined,
      { timeout: 5_000 }
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
    const enterCaptures = await extensionPage.evaluate(
      () => globalThis.__vaultkernTrustedSpaSubmissions
    );
    if (
      enterCaptures.length !== 1 ||
      enterCaptures[0]?.username !== "spa@example.com" ||
      enterCaptures[0]?.password !== "spa-secret"
    ) {
      throw new Error(`unexpected trusted Enter capture: ${JSON.stringify(enterCaptures)}`);
    }
    await extensionPage.evaluate(() => {
      globalThis.__vaultkernTrustedSpaSubmissions = [];
    });

    await page.evaluate(() => {
      const username = document.querySelector("#vaultkern-smoke-username");
      const password = document.querySelector("#vaultkern-smoke-password");
      window.addEventListener(
        "submit",
        () => {
          username.value = "rewritten@example.com";
          password.value = "rewritten-secret";
        },
        { capture: true, once: true }
      );
    });
    await page.click("#vaultkern-smoke-submit");
    await extensionPage.waitForFunction(
      () => globalThis.__vaultkernTrustedSpaSubmissions?.length === 1,
      undefined,
      { timeout: 5_000 }
    );
    const rewriteCaptures = await extensionPage.evaluate(
      () => globalThis.__vaultkernTrustedSpaSubmissions
    );
    const rewrittenValues = await page.evaluate(() => ({
      username: document.querySelector("#vaultkern-smoke-username")?.value,
      password: document.querySelector("#vaultkern-smoke-password")?.value
    }));
    if (
      rewriteCaptures.length !== 1 ||
      rewriteCaptures[0]?.username !== "spa@example.com" ||
      rewriteCaptures[0]?.password !== "spa-secret" ||
      rewrittenValues.username !== "rewritten@example.com" ||
      rewrittenValues.password !== "rewritten-secret"
    ) {
      throw new Error(
        `window capture rewrite raced credential capture: ${JSON.stringify({ rewriteCaptures, rewrittenValues })}`
      );
    }
    await extensionPage.evaluate(() => {
      globalThis.__vaultkernTrustedSpaSubmissions = [];
    });
    await page.locator("#vaultkern-smoke-username").fill("spa@example.com");
    await page.locator("#vaultkern-smoke-password").fill("spa-secret");

    await page.evaluate(() => {
      const form = document.querySelector("#vaultkern-smoke-login-form");
      const submitter = document.querySelector("#vaultkern-smoke-submit");
      const password = document.querySelector("#vaultkern-smoke-password");
      const hijackedSubmitter = document.createElement("button");
      hijackedSubmitter.id = "vaultkern-hijacked-submit";
      hijackedSubmitter.type = "submit";
      hijackedSubmitter.textContent = "Hijacked submit";
      form.append(hijackedSubmitter);
      submitter.addEventListener(
        "click",
        (event) => {
          if (event.isTrusted) {
            password.value = "hijacked-secret";
            form.requestSubmit(hijackedSubmitter);
            password.value = "spa-secret";
          }
        },
        { once: true }
      );
    });
    await page.click("#vaultkern-smoke-submit");
    await extensionPage.waitForFunction(
      () => globalThis.__vaultkernTrustedSpaSubmissions?.length === 1,
      undefined,
      { timeout: 5_000 }
    );
    const mismatchCaptures = await extensionPage.evaluate(
      () => globalThis.__vaultkernTrustedSpaSubmissions
    );
    if (
      mismatchCaptures.length !== 1 ||
      mismatchCaptures[0]?.password !== "spa-secret"
    ) {
      throw new Error(
        `mismatched submitter consumed trusted intent: ${JSON.stringify(mismatchCaptures)}`
      );
    }
    await extensionPage.evaluate(() => {
      globalThis.__vaultkernTrustedSpaSubmissions = [];
    });

    await page.evaluate(() => {
      const form = document.querySelector("#vaultkern-smoke-login-form");
      const submitter = document.querySelector("#vaultkern-smoke-submit");
      submitter.addEventListener(
        "click",
        (event) => {
          if (event.isTrusted) {
            queueMicrotask(() => form.requestSubmit(submitter));
          }
        },
        { once: true }
      );
    });
    await page.click("#vaultkern-smoke-submit");
    await extensionPage.waitForFunction(
      () => globalThis.__vaultkernTrustedSpaSubmissions?.length === 1,
      undefined,
      { timeout: 5_000 }
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
    const observations = await page.evaluate(
      () => globalThis.__vaultkernSpaSubmitObservations
    );
    const observation = observations.at(-1);
    if (observation?.isTrusted !== true || observation?.defaultPrevented !== true) {
      throw new Error(`submit was not a trusted prevented event: ${JSON.stringify(observation)}`);
    }
    const syntheticObservation = observations.find(({ isTrusted }) => isTrusted === false);
    if (syntheticObservation?.defaultPrevented !== true) {
      throw new Error(`synthetic submit observation was unexpected: ${JSON.stringify(observations)}`);
    }

    const submissions = await extensionPage.evaluate(
      () => globalThis.__vaultkernTrustedSpaSubmissions
    );
    if (
      submissions.length !== 1 ||
      submissions[0]?.url !== server.url ||
      new URL(submissions[0]?.url ?? "about:blank").origin !== new URL(server.url).origin ||
      submissions[0]?.username !== "spa@example.com" ||
      submissions[0]?.password !== "spa-secret"
    ) {
      throw new Error(`unexpected trusted SPA capture: ${JSON.stringify(submissions)}`);
    }

    await extensionPage.evaluate(async () => await chrome.action.openPopup());

    let pending = null;
    for (let attempt = 0; attempt < 20 && !pending; attempt += 1) {
      pending = await extensionPage.evaluate(async (pageUrl) => {
        const [popupView] = chrome.extension.getViews({ type: "popup" });
        if (!popupView) {
          return null;
        }
        const tabs = await chrome.tabs.query({ url: pageUrl });
        const tab = tabs.find((candidate) => candidate.url === pageUrl);
        if (!tab?.id) {
          return null;
        }
        const response = await popupView.chrome.runtime.sendMessage({
          type: "vaultkern_autofill_pending_request",
          tabId: tab.id
        });
        return response?.pending ?? null;
      }, server.url);
      if (!pending) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      }
    }
    if (
      pending?.version !== 2 ||
      pending?.state !== "captured" ||
      pending?.origin !== new URL(server.url).origin ||
      pending?.submission?.username !== "spa@example.com" ||
      pending?.submission?.password !== "spa-secret" ||
      pending?.transactionId?.length < 16
    ) {
      const diagnostics = await extensionPage.evaluate(
        async (pageUrl) => ({
          tabs: await chrome.tabs.query({ url: pageUrl }),
          session: await chrome.storage.session.get(null)
        }),
        server.url
      );
      throw new Error(
        `unexpected trusted SPA pending transaction: ${JSON.stringify({ pending, observation, diagnostics, pageErrors })}`
      );
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: "trusted-spa-submit",
        rejectedProgrammaticCaptureCount: 0,
        trustedEnterCaptureCount: enterCaptures.length,
        windowRewriteCaptureCount: rewriteCaptures.length,
        mismatchedSubmitterCaptureCount: mismatchCaptures.length,
        trustedCaptureCount: submissions.length,
        transactionId: pending.transactionId,
        observation
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function runControlledReactInputCase() {
  await assertE2EManifest();
  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-controlled-react-"));
  const fixtureBuildDir = join(workDir, "react-fixture");
  let context;
  let server;
  try {
    await buildControlledReactFixture(fixtureBuildDir);
    server = await startSmokeServer({ additionalRoots: [fixtureBuildDir] });
    const launched = await launchExtensionContext(join(workDir, "profile"));
    context = launched.context;
    const extensionPage = launched.extensionPage;

    const page = await context.newPage();
    await page.goto(server.controlledReactInputUrl);
    await page.waitForFunction(() => globalThis.__vaultkernReactReady === true);

    const fill = await sendFillEntryDetail(
      extensionPage,
      server.controlledReactInputUrl,
      FIXTURE_ENTRY_ID,
      { username, password: entryPassword }
    );
    try {
      await page.waitForFunction(
        ({ expectedUsername, expectedPassword }) => {
          const state = JSON.parse(
            document.querySelector("#react-state")?.textContent ?? "{}"
          );
          return state.username === expectedUsername && state.password === expectedPassword;
        },
        { expectedUsername: username, expectedPassword: entryPassword }
      );
    } catch (error) {
      const diagnostics = await page.evaluate(() => ({
        usernameValue: document.querySelector("#react-username")?.value,
        passwordValue: document.querySelector("#react-password")?.value,
        state: JSON.parse(document.querySelector("#react-state")?.textContent ?? "{}")
      }));
      throw new Error(
        `controlled React state did not converge: ${JSON.stringify({ fill, diagnostics })}`,
        { cause: error }
      );
    }

    const beforeRerender = await page.evaluate(() => ({
      usernameValue: document.querySelector("#react-username")?.value,
      passwordValue: document.querySelector("#react-password")?.value,
      state: JSON.parse(document.querySelector("#react-state")?.textContent ?? "{}")
    }));
    assertEqual(beforeRerender.usernameValue, username, "controlled React username DOM value");
    assertEqual(beforeRerender.passwordValue, entryPassword, "controlled React password DOM value");
    assertEqual(beforeRerender.state.username, username, "controlled React username state");
    assertEqual(beforeRerender.state.password, entryPassword, "controlled React password state");
    if (!String(beforeRerender.state.reactVersion).startsWith("19.")) {
      throw new Error(
        `controlled fixture did not use local React 19: ${beforeRerender.state.reactVersion}`
      );
    }

    const expectedEventCounts = {
      nativeInput: 1,
      nativeChange: 1,
      nativeBlur: 1,
      reactInput: 1,
      reactChange: 1
    };
    for (const field of ["username", "password"]) {
      if (
        JSON.stringify(beforeRerender.state.eventCounts?.[field]) !==
        JSON.stringify(expectedEventCounts)
      ) {
        throw new Error(
          `controlled React ${field} event counts were unexpected: ` +
            JSON.stringify(beforeRerender.state.eventCounts?.[field])
        );
      }
    }

    await page.evaluate(() => globalThis.__vaultkernReactRerender());
    await waitForTwoAnimationFrames(page);
    const afterRerender = await page.evaluate(() => ({
      usernameValue: document.querySelector("#react-username")?.value,
      passwordValue: document.querySelector("#react-password")?.value,
      state: JSON.parse(document.querySelector("#react-state")?.textContent ?? "{}")
    }));
    assertEqual(afterRerender.state.renderEpoch, 1, "controlled React rerender epoch");
    assertEqual(afterRerender.usernameValue, username, "controlled React username after rerender");
    assertEqual(
      afterRerender.passwordValue,
      entryPassword,
      "controlled React password after rerender"
    );
    assertEqual(afterRerender.state.username, username, "controlled React state after rerender");
    assertEqual(
      afterRerender.state.password,
      entryPassword,
      "controlled React password state after rerender"
    );

    console.log(
      JSON.stringify({
        ok: true,
        case: "controlled-react-input",
        reactVersion: beforeRerender.state.reactVersion,
        durationMs: fill.durationMs,
        eventCounts: beforeRerender.state.eventCounts
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function setPageLoadAutofillEnabled(extensionPage) {
  await extensionPage.evaluate(async () => {
    const { vaultkernExtensionSettings: current = {} } = await chrome.storage.local.get(
      "vaultkernExtensionSettings"
    );
    await chrome.storage.local.set({
      vaultkernWebAuthnDebugEnabled: true,
      vaultkernWebAuthnDebug: [],
      vaultkernExtensionSettings: {
        recentVaultLimit: 10,
        language: "en",
        idleLockMinutes: 10,
        clearClipboardSeconds: 30,
        browserPasskeyProxyEnabled: false,
        quickUnlockEnabled: false,
        ...current,
        autofillOnPageLoadEnabled: true
      }
    });
  });
}

async function latestAutomaticAttemptSequence(extensionPage) {
  return await extensionPage.evaluate(async () => {
    const { vaultkernWebAuthnDebug = [] } = await chrome.storage.local.get(
      "vaultkernWebAuthnDebug"
    );
    return Array.isArray(vaultkernWebAuthnDebug)
      ? vaultkernWebAuthnDebug.reduce(
          (latest, entry) =>
            entry?.event === "page_load_autofill_attempt_complete" &&
            Number.isInteger(entry?.sequence)
              ? Math.max(latest, entry.sequence)
              : latest,
          0
        )
      : 0;
  });
}

async function waitForAutomaticAttemptComplete(
  extensionPage,
  expected,
  timeoutMs = 15_000
) {
  const debugLog = await extensionPage.evaluate(
    async ({ expectedValue, timeoutMsValue }) =>
      await new Promise((resolvePromise, rejectPromise) => {
        const diagnosticMatches = (entry) =>
          entry?.event === "page_load_autofill_attempt_complete" &&
          entry?.tabId === expectedValue.tabId &&
          entry?.targetUrl === expectedValue.pageUrl &&
          Number.isInteger(entry?.sequence) &&
          entry.sequence > expectedValue.afterSequence;
        const cleanup = () => {
          clearTimeout(timer);
          chrome.storage.onChanged.removeListener(onChanged);
        };
        const inspect = (entries) => {
          if (!Array.isArray(entries) || !entries.some(diagnosticMatches)) {
            return false;
          }
          cleanup();
          resolvePromise(entries);
          return true;
        };
        const onChanged = (changes, areaName) => {
          if (areaName === "local") {
            inspect(changes.vaultkernWebAuthnDebug?.newValue);
          }
        };
        const timer = setTimeout(() => {
          cleanup();
          rejectPromise(
            new Error(
              `automatic attempt completion timed out: ` +
                JSON.stringify(expectedValue)
            )
          );
        }, timeoutMsValue);

        chrome.storage.onChanged.addListener(onChanged);
        chrome.storage.local
          .get("vaultkernWebAuthnDebug")
          .then(({ vaultkernWebAuthnDebug }) => inspect(vaultkernWebAuthnDebug))
          .catch((error) => {
            cleanup();
            rejectPromise(error);
          });
      }),
    { expectedValue: expected, timeoutMsValue: timeoutMs }
  );
  const diagnostic = automaticAttemptCompleteDiagnostic(debugLog, expected);
  if (!diagnostic) {
    throw new Error(
      `automatic attempt did not emit a terminal diagnostic: ` +
        JSON.stringify(expected)
    );
  }
  return diagnostic;
}

async function installFillDetailProbe(extensionPage, targetUrl) {
  const tabId = await targetTabId(extensionPage, targetUrl);
  await extensionPage.evaluate(async (tabIdValue) => {
    await chrome.scripting.executeScript({
      target: { tabId: tabIdValue },
      world: "ISOLATED",
      func: () => {
        if (globalThis.__vaultkernAutomaticDetailProbe) {
          globalThis.__vaultkernAutomaticDetailProbe.messages = [];
          return;
        }
        const probe = { messages: [] };
        globalThis.__vaultkernAutomaticDetailProbe = probe;
        chrome.runtime.onMessage.addListener((message) => {
          if (message?.type === "fill_entry_detail") {
            probe.messages.push(message);
          }
        });
      }
    });
  }, tabId);
  return tabId;
}

async function readFillDetailProbe(extensionPage, tabId) {
  return await extensionPage.evaluate(async (tabIdValue) => {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tabIdValue },
      world: "ISOLATED",
      func: () => globalThis.__vaultkernAutomaticDetailProbe?.messages ?? []
    });
    return result?.result ?? [];
  }, tabId);
}

async function assertSingleNativeCandidate(extensionPage, vaultId, pageUrl, entryId, label) {
  const candidates = await sendCommand(extensionPage, {
    type: "find_fill_candidates",
    vault_id: vaultId,
    url: pageUrl
  });
  if (
    !Array.isArray(candidates.entries) ||
    candidates.entries.length !== 1 ||
    candidates.entries[0]?.id !== entryId
  ) {
    throw new Error(`${label} did not have exactly one native candidate: ${JSON.stringify(candidates)}`);
  }
  return candidates.entries[0];
}

async function observeAutomaticAuthorizationScenario({
  context,
  extensionPage,
  pageUrl,
  expectSecretRelease,
  expectedEntryId,
  controlledResourceGate,
  label
}) {
  const page = await context.newPage();
  let blockedRequestId = null;
  try {
    await page.bringToFront();
    await page.goto(pageUrl, { waitUntil: "domcontentloaded" });
    blockedRequestId = await controlledResourceGate.waitForBlocked();
    const tabId = await installFillDetailProbe(extensionPage, pageUrl);
    const receptionState = await extensionPage.evaluate(async (tabIdValue) => {
      const tab = await chrome.tabs.get(tabIdValue);
      const tabWindow = await chrome.windows.get(tab.windowId);
      return { active: tab.active, windowFocused: tabWindow.focused };
    }, tabId);
    const visibilityState = await page.evaluate(() => document.visibilityState);
    if (
      receptionState.active !== true ||
      receptionState.windowFocused !== true ||
      visibilityState !== "visible"
    ) {
      throw new Error(
        `${label} was not an active visible page-load target: ` +
          JSON.stringify({ receptionState, visibilityState })
      );
    }
    const afterSequence = await latestAutomaticAttemptSequence(extensionPage);
    controlledResourceGate.release(blockedRequestId);
    blockedRequestId = null;
    await page.waitForLoadState("load");

    const attemptDiagnostic = await waitForAutomaticAttemptComplete(
      extensionPage,
      {
        tabId,
        pageUrl,
        afterSequence,
        expectedOutcome: expectSecretRelease ? "delivered" : "candidate_rejected"
      }
    );
    if (expectSecretRelease) {
      await page.waitForFunction(
        ({ expectedUsername, expectedPassword }) =>
          document.querySelector("#automatic-username")?.value === expectedUsername &&
          document.querySelector("#automatic-password")?.value === expectedPassword,
        { expectedUsername: username, expectedPassword: entryPassword },
        { timeout: 10_000 }
      );
    }

    const values = await page.evaluate(() => ({
      username: document.querySelector("#automatic-username")?.value,
      password: document.querySelector("#automatic-password")?.value
    }));
    const detailMessages = await readFillDetailProbe(extensionPage, tabId);
    if (expectSecretRelease) {
      if (
        values.username !== username ||
        values.password !== entryPassword ||
        detailMessages.length !== 1 ||
        detailMessages[0]?.fillCapability?.kind !== "automatic" ||
        detailMessages[0]?.fillCapability?.entryId !== expectedEntryId ||
        detailMessages[0]?.fillCapability?.targetUrl !== pageUrl ||
        detailMessages[0]?.username !== username ||
        detailMessages[0]?.password !== entryPassword
      ) {
        throw new Error(
          `${label} did not complete the native/background/content automatic chain: ` +
            JSON.stringify({ values, detailMessages })
        );
      }
    } else if (
      values.username !== "" ||
      values.password !== "" ||
      detailMessages.length !== 0
    ) {
      throw new Error(
        `${label} released automatic detail secrets: ${JSON.stringify({ values, detailMessages })}`
      );
    }
    return {
      detailMessageCount: detailMessages.length,
      valueState: {
        usernamePopulated: values.username !== "",
        passwordPopulated: values.password !== ""
      },
      receptionState,
      visibilityState,
      attemptDiagnostic
    };
  } finally {
    if (blockedRequestId !== null) {
      controlledResourceGate.release(blockedRequestId);
    }
    await page.close().catch(() => {});
  }
}

async function runExactOriginAutomaticAuthorizationCase() {
  await assertE2EManifest();
  if (!existsSync(runtimePath)) {
    throw new Error("target/debug/vaultkern-runtime is missing; run cargo build -p vaultkern-runtime first");
  }

  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-exact-origin-"));
  const vaultPath = join(workDir, "exact-origin.kdbx");
  const primaryResourceGate = createControlledResourceGate();
  const alternatePortResourceGate = createControlledResourceGate();
  let context;
  let primaryServer;
  let alternatePortServer;
  try {
    run("cargo", [...vkdbxArgs, vaultPath, password]);
    primaryServer = await startSmokeServer({
      controlledResourceGate: primaryResourceGate
    });
    alternatePortServer = await startSmokeServer({
      controlledResourceGate: alternatePortResourceGate
    });
    await writeNativeManifest(workDir);
    const launched = await launchExtensionContext(join(workDir, "profile"));
    context = launched.context;
    const extensionPage = launched.extensionPage;
    await setPageLoadAutofillEnabled(extensionPage);

    const opened = await sendCommand(extensionPage, {
      type: "open_local_vault",
      path: vaultPath
    });
    const vaultId = opened.vaultId;
    await sendCommand(extensionPage, {
      type: "unlock_with_password",
      vault_id: vaultId,
      password
    });
    const groups = await sendCommand(extensionPage, {
      type: "list_groups",
      vault_id: vaultId
    });
    const existingEntries = await sendCommand(extensionPage, {
      type: "list_entries",
      vault_id: vaultId
    });
    for (const entry of existingEntries.entries ?? []) {
      await sendCommand(extensionPage, {
        type: "delete_entry",
        vault_id: vaultId,
        entry_id: entry.id
      });
    }

    const recordOrigin = `http://auth.vaultkern.example.com:${primaryServer.port}`;
    const created = await sendCommand(extensionPage, {
      type: "create_entry",
      vault_id: vaultId,
      parent_group_id: groups.root.id,
      title: "Exact Origin HTTP",
      username,
      password: entryPassword,
      url: `${recordOrigin}/stored/account`,
      notes: "exact-origin Chromium fixture",
      totp_uri: null
    });
    await sendCommand(extensionPage, { type: "save_vault", vault_id: vaultId });

    const positiveUrl = `${recordOrigin}/automatic-login.html?route=login`;
    await assertSingleNativeCandidate(
      extensionPage,
      vaultId,
      positiveUrl,
      created.id,
      "same-origin different-path positive"
    );
    const positive = await observeAutomaticAuthorizationScenario({
      context,
      extensionPage,
      pageUrl: positiveUrl,
      expectSecretRelease: true,
      expectedEntryId: created.id,
      controlledResourceGate: primaryResourceGate,
      label: "same-origin different-path positive"
    });

    const negativeDefinitions = [
      {
        label: "different-port negative",
        pageUrl: `http://auth.vaultkern.example.com:${alternatePortServer.port}/automatic-login.html`,
        controlledResourceGate: alternatePortResourceGate
      },
      {
        label: "sibling-host negative",
        pageUrl: `http://app.vaultkern.example.com:${primaryServer.port}/automatic-login.html`,
        controlledResourceGate: primaryResourceGate
      }
    ];
    const negatives = [];
    for (const definition of negativeDefinitions) {
      await assertSingleNativeCandidate(
        extensionPage,
        vaultId,
        definition.pageUrl,
        created.id,
        definition.label
      );
      negatives.push({
        label: definition.label,
        ...(await observeAutomaticAuthorizationScenario({
          context,
          extensionPage,
          pageUrl: definition.pageUrl,
          expectSecretRelease: false,
          controlledResourceGate: definition.controlledResourceGate,
          label: definition.label
        }))
      });
    }

    await sendCommand(extensionPage, {
      type: "delete_entry",
      vault_id: vaultId,
      entry_id: created.id
    });
    const httpsCreated = await sendCommand(extensionPage, {
      type: "create_entry",
      vault_id: vaultId,
      parent_group_id: groups.root.id,
      title: "Exact Origin HTTPS",
      username,
      password: entryPassword,
      url: `https://auth.vaultkern.example.com:${primaryServer.port}/stored/account`,
      notes: "HTTPS downgrade Chromium fixture",
      totp_uri: null
    });
    await sendCommand(extensionPage, { type: "save_vault", vault_id: vaultId });
    const downgradeUrl = `http://auth.vaultkern.example.com:${primaryServer.port}/automatic-login.html`;
    await assertSingleNativeCandidate(
      extensionPage,
      vaultId,
      downgradeUrl,
      httpsCreated.id,
      "HTTPS-record to HTTP-page negative"
    );
    negatives.push({
      label: "HTTPS-record to HTTP-page negative",
      ...(await observeAutomaticAuthorizationScenario({
        context,
        extensionPage,
        pageUrl: downgradeUrl,
        expectSecretRelease: false,
        controlledResourceGate: primaryResourceGate,
        label: "HTTPS-record to HTTP-page negative"
      }))
    });

    console.log(
      JSON.stringify({
        ok: true,
        case: "exact-origin-automatic-authorization",
        positive,
        negatives
      })
    );
  } finally {
    primaryResourceGate.releaseAll();
    alternatePortResourceGate.releaseAll();
    await context?.close().catch(() => {});
    await primaryServer?.close().catch(() => {});
    await alternatePortServer?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function installLargeDomInstrumentation(extensionPage, tabId) {
  await extensionPage.evaluate(async (tabIdValue) => {
    await chrome.scripting.executeScript({
      target: { tabId: tabIdValue },
      world: "ISOLATED",
      func: () => {
        if (globalThis.__vaultkernLargeDomInstrumentation) {
          return;
        }
        const createStats = () => ({
          querySelectorAllCalls: 0,
          fieldSubtreeQuerySelectorAllCalls: 0,
          headingFormQuerySelectorAllCalls: 0,
          formHeadingCandidateVisits: 0,
          containerHeadingCandidateVisits: 0,
          fullTreeQuerySelectorAllCalls: 0,
          hitTestCalls: 0
        });
        const instrumentation = {
          phase: "idle",
          stats: {
            hot: createStats(),
            fill: createStats()
          }
        };
        globalThis.__vaultkernLargeDomInstrumentation = instrumentation;

        const currentStats = () => instrumentation.stats[instrumentation.phase];
        for (const prototype of [
          Document.prototype,
          Element.prototype,
          ShadowRoot.prototype
        ]) {
          const original = prototype.querySelectorAll;
          prototype.querySelectorAll = function instrumentedQuerySelectorAll(selector) {
            const result = original.call(this, selector);
            const stats = currentStats();
            if (stats) {
              stats.querySelectorAllCalls += 1;
              const normalizedSelector = String(selector).trim();
              if (normalizedSelector === "*") {
                stats.fullTreeQuerySelectorAllCalls += 1;
              }
              if (
                normalizedSelector === "input, select, textarea" &&
                (this instanceof Element || this instanceof ShadowRoot)
              ) {
                stats.fieldSubtreeQuerySelectorAllCalls += 1;
              }
              if (
                normalizedSelector === "form" ||
                normalizedSelector === "h1, h2, h3, h4, h5, h6" ||
                normalizedSelector === "form, h1, h2, h3, h4, h5, h6"
              ) {
                stats.headingFormQuerySelectorAllCalls += 1;
              }
              if (
                normalizedSelector === "form, h1, h2, h3, h4, h5, h6"
              ) {
                stats.formHeadingCandidateVisits += result.length;
              }
              if (normalizedSelector === "h1, h2, h3, h4, h5, h6") {
                stats.containerHeadingCandidateVisits += result.length;
              }
            }
            return result;
          };
        }

        for (const prototype of [Document.prototype, ShadowRoot.prototype]) {
          const original = prototype.elementFromPoint;
          prototype.elementFromPoint = function instrumentedElementFromPoint(...args) {
            const stats = currentStats();
            if (stats) {
              stats.hitTestCalls += 1;
            }
            return original.apply(this, args);
          };
        }
      }
    });
  }, tabId);
}

async function resetLargeDomInstrumentation(extensionPage, tabId, phase) {
  await extensionPage.evaluate(
    async ({ tabIdValue, phaseValue }) => {
      await chrome.scripting.executeScript({
        target: { tabId: tabIdValue },
        world: "ISOLATED",
        func: (nextPhase) => {
          const instrumentation = globalThis.__vaultkernLargeDomInstrumentation;
          if (!instrumentation) {
            throw new Error("large DOM instrumentation is not installed");
          }
          instrumentation.phase = nextPhase;
          instrumentation.stats[nextPhase] = {
            querySelectorAllCalls: 0,
            fieldSubtreeQuerySelectorAllCalls: 0,
            headingFormQuerySelectorAllCalls: 0,
            formHeadingCandidateVisits: 0,
            containerHeadingCandidateVisits: 0,
            fullTreeQuerySelectorAllCalls: 0,
            hitTestCalls: 0
          };
        },
        args: [phaseValue]
      });
    },
    { tabIdValue: tabId, phaseValue: phase }
  );
}

async function readLargeDomInstrumentation(extensionPage, tabId, phase) {
  return await extensionPage.evaluate(
    async ({ tabIdValue, phaseValue }) => {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tabIdValue },
        world: "ISOLATED",
        func: (requestedPhase) =>
          globalThis.__vaultkernLargeDomInstrumentation?.stats?.[requestedPhase] ?? null,
        args: [phaseValue]
      });
      return result?.result ?? null;
    },
    { tabIdValue: tabId, phaseValue: phase }
  );
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 0
    ? (ordered[middle - 1] + ordered[middle]) / 2
    : ordered[middle];
}

async function runLargeDomPerformanceCase() {
  await assertE2EManifest();
  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-large-dom-"));
  let context;
  let server;
  try {
    server = await startSmokeServer();
    const launched = await launchExtensionContext(join(workDir, "profile"));
    context = launched.context;
    const extensionPage = launched.extensionPage;
    const page = await context.newPage();
    await page.goto(server.autofillLargeDomUrl);
    const fixture = await page.evaluate(() => globalThis.__vaultkernLargeDomReady);
    if (
      fixture?.noiseNodes !== 50_000 ||
      fixture?.credentialFields !== 20 ||
      fixture?.formLessFields !== 1_000 ||
      fixture?.headingForms !== 200 ||
      fixture?.headingNodes !== 200 ||
      fixture?.nestedScopes !== 40 ||
      fixture?.nestedFields !== 120 ||
      fixture?.nestedForms !== 40 ||
      fixture?.nestedHeadings !== 5
    ) {
      throw new Error(`large DOM fixture was incomplete: ${JSON.stringify(fixture)}`);
    }

    const tabId = await targetTabId(extensionPage, server.autofillLargeDomUrl);
    await installLargeDomInstrumentation(extensionPage, tabId);
    await resetLargeDomInstrumentation(extensionPage, tabId, "hot");
    await page.evaluate(() => {
      const target = document.querySelector("#performance-username");
      target.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
      target.dispatchEvent(new FocusEvent("focusin", { bubbles: true, composed: true }));
      target.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true }));
      target.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, composed: true, key: "A" }));
    });
    const hotStats = await readLargeDomInstrumentation(extensionPage, tabId, "hot");
    if (!hotStats || hotStats.fullTreeQuerySelectorAllCalls !== 0) {
      throw new Error(`large DOM hot event scanned the full tree: ${JSON.stringify(hotStats)}`);
    }

    const warmupCount = 2;
    const measuredCount = 7;
    const measuredDurationsMs = [];
    let maxFillHitTests = 0;
    let maxFillSelectorCalls = 0;
    let maxFillHeadingFormSelectorCalls = 0;
    let maxFillFormHeadingCandidateVisits = 0;
    let maxFillContainerHeadingCandidateVisits = 0;
    const headingFormSelectorLimit = fixture.headingForms / 4;
    const nestedHeadingCandidateLimit = fixture.nestedScopes * 4;
    for (let iteration = 0; iteration < warmupCount + measuredCount; iteration += 1) {
      await page.evaluate(() => {
        const usernameField = document.querySelector("#performance-username");
        const passwordField = document.querySelector("#performance-password");
        usernameField.value = "";
        passwordField.value = "";
        usernameField.focus();
      });
      await resetLargeDomInstrumentation(extensionPage, tabId, "fill");
      const fill = await sendFillEntryDetail(
        extensionPage,
        server.autofillLargeDomUrl,
        FIXTURE_ENTRY_ID,
        { username, password: entryPassword }
      );
      const values = await page.evaluate(() => ({
        username: document.querySelector("#performance-username")?.value,
        password: document.querySelector("#performance-password")?.value
      }));
      if (values.username !== username || values.password !== entryPassword) {
        throw new Error(
          `large DOM fill ${iteration + 1} did not write expected values: ${JSON.stringify(values)}`
        );
      }
      const fillStats = await readLargeDomInstrumentation(extensionPage, tabId, "fill");
      if (!fillStats || fillStats.fullTreeQuerySelectorAllCalls !== 0) {
        throw new Error(
          `large DOM fill ${iteration + 1} performed a full-tree overlay scan: ` +
            JSON.stringify(fillStats)
        );
      }
      if (fillStats.fieldSubtreeQuerySelectorAllCalls !== 0) {
        throw new Error(
          `large DOM fill ${iteration + 1} rescanned a field subtree: ` +
            JSON.stringify(fillStats)
        );
      }
      if (fillStats.headingFormQuerySelectorAllCalls > headingFormSelectorLimit) {
        throw new Error(
          `large DOM fill ${iteration + 1} exceeded linear heading/form selector bound ` +
            `${headingFormSelectorLimit}: ${JSON.stringify(fillStats)}`
        );
      }
      if (
        fillStats.formHeadingCandidateVisits >= nestedHeadingCandidateLimit ||
        fillStats.containerHeadingCandidateVisits >= nestedHeadingCandidateLimit
      ) {
        throw new Error(
          `large DOM fill ${iteration + 1} exceeded nested heading candidate bound ` +
            `${nestedHeadingCandidateLimit}: ${JSON.stringify(fillStats)}`
        );
      }
      const hitTestLimit = fixture.credentialFields * 12;
      if (fillStats.hitTestCalls > hitTestLimit) {
        throw new Error(
          `large DOM fill ${iteration + 1} exceeded fixed hit-test bound ${hitTestLimit}: ` +
            JSON.stringify(fillStats)
        );
      }
      maxFillHitTests = Math.max(maxFillHitTests, fillStats.hitTestCalls);
      maxFillSelectorCalls = Math.max(
        maxFillSelectorCalls,
        fillStats.querySelectorAllCalls
      );
      maxFillHeadingFormSelectorCalls = Math.max(
        maxFillHeadingFormSelectorCalls,
        fillStats.headingFormQuerySelectorAllCalls
      );
      maxFillFormHeadingCandidateVisits = Math.max(
        maxFillFormHeadingCandidateVisits,
        fillStats.formHeadingCandidateVisits
      );
      maxFillContainerHeadingCandidateVisits = Math.max(
        maxFillContainerHeadingCandidateVisits,
        fillStats.containerHeadingCandidateVisits
      );
      if (iteration >= warmupCount) {
        measuredDurationsMs.push(fill.durationMs);
      }
    }

    const medianDurationMs = median(measuredDurationsMs);
    if (measuredDurationsMs.length < 7 || medianDurationMs > 500) {
      throw new Error(
        `large DOM median exceeded 500ms: ${JSON.stringify({ measuredDurationsMs, medianDurationMs })}`
      );
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: "large-dom-performance",
        fixture,
        warmupCount,
        measuredCount,
        measuredDurationsMs,
        medianDurationMs,
        hotStats,
        maxFillHitTests,
        maxFillSelectorCalls,
        maxFillHeadingFormSelectorCalls,
        maxFillFormHeadingCandidateVisits,
        maxFillContainerHeadingCandidateVisits,
        headingFormSelectorLimit,
        nestedHeadingCandidateLimit,
        hitTestLimit: fixture.credentialFields * 12
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function pendingSessionSnapshot(extensionPage, tabId) {
  return await extensionPage.evaluate(async (tabIdValue) => {
    const items = await chrome.storage.session.get(null);
    const key = `vaultkernPendingAutofillTransaction:${tabIdValue}`;
    return { items, key, pending: items[key] ?? null };
  }, tabId);
}

async function waitForPendingSessionSnapshot(extensionPage, tabId) {
  let snapshot = null;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    snapshot = await pendingSessionSnapshot(extensionPage, tabId);
    if (snapshot.pending) {
      return snapshot;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error(`pending session transaction did not appear: ${JSON.stringify(snapshot)}`);
}

function assertExactPendingMatches(actual, expected, label) {
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(
      `${label} changed: ` +
        JSON.stringify({ before: expected, restored: actual })
    );
  }
}

export function assertPendingSessionSecurityProof(
  { snapshot, durableStorage, isolatedStorage },
  { key, pending }
) {
  if (!snapshot || snapshot.key !== key || snapshot.pending === null) {
    throw new Error(
      `pending session key was not restored: ${JSON.stringify({ expectedKey: key, snapshot })}`
    );
  }
  const pendingSessionKeys = Object.keys(snapshot.items ?? {}).filter((itemKey) =>
    itemKey.startsWith("vaultkernPendingAutofillTransaction:")
  );
  if (pendingSessionKeys.length !== 1 || pendingSessionKeys[0] !== key) {
    throw new Error(
      `unexpected pending session keys: ${JSON.stringify(pendingSessionKeys)}`
    );
  }
  assertExactPendingMatches(
    snapshot.pending,
    pending,
    "restored pending transaction"
  );

  const secretFields = pending.submission ?? pending.plan?.desiredFields;
  if (
    typeof secretFields?.username !== "string" ||
    typeof secretFields?.password !== "string"
  ) {
    throw new Error(`pending transaction has no bounded secret fields: ${JSON.stringify(pending)}`);
  }

  const durableStorageKeys = {};
  for (const [area, items] of Object.entries(durableStorage ?? {})) {
    durableStorageKeys[area] = Object.keys(items ?? {}).sort();
    const serialized = JSON.stringify(items ?? {});
    if (
      Object.keys(items ?? {}).some((itemKey) =>
        itemKey.startsWith("vaultkernPendingAutofillTransaction:")
      ) ||
      serialized.includes(secretFields.username) ||
      serialized.includes(secretFields.password) ||
      serialized.includes(pending.transactionId)
    ) {
      throw new Error(`${area} storage retained pending secrets: ${serialized}`);
    }
  }

  if (
    !isolatedStorage ||
    isolatedStorage.readable !== false ||
    isolatedStorage.hasPendingKey !== false
  ) {
    throw new Error(
      `content isolated world retained session access: ${JSON.stringify(isolatedStorage)}`
    );
  }

  return {
    pendingSessionKey: key,
    pendingSessionKeys,
    durableStorageKeys,
    isolatedStorage
  };
}

async function collectPendingSessionSecurityProof(
  extensionPage,
  tabId,
  expected
) {
  const snapshot = await waitForPendingSessionSnapshot(extensionPage, tabId);
  const durableStorage = await extensionPage.evaluate(async () => ({
    local: await chrome.storage.local.get(null),
    sync: await chrome.storage.sync.get(null)
  }));
  const isolatedStorage = await extensionPage.evaluate(
    async ({ tabIdValue, storageKey }) => {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tabIdValue },
        world: "ISOLATED",
        func: async (key) => {
          try {
            const items = await chrome.storage.session.get(key);
            return {
              readable: true,
              hasPendingKey: Object.prototype.hasOwnProperty.call(items, key),
              items
            };
          } catch (error) {
            return {
              readable: false,
              hasPendingKey: false,
              error: String(error?.message ?? error)
            };
          }
        },
        args: [storageKey]
      });
      return result?.result ?? null;
    },
    { tabIdValue: tabId, storageKey: expected.key }
  );
  return assertPendingSessionSecurityProof(
    { snapshot, durableStorage, isolatedStorage },
    expected
  );
}

export function assertRestoredPendingMatches(actual, expected, label) {
  assertExactPendingMatches(actual, expected, label);
}

async function serviceWorkerTargets(cdp, extensionId) {
  const { targetInfos } = await cdp.send("Target.getTargets");
  return targetInfos.filter(
    (target) =>
      target.type === "service_worker" &&
      target.url.startsWith(`chrome-extension://${extensionId}/`)
  );
}

async function terminateAndRestartServiceWorker(
  context,
  extensionPage,
  extensionId,
  originalWorker
) {
  const cdp = await context.newCDPSession(extensionPage);
  const lifecycle = { registrations: [], versions: [] };
  cdp.on("ServiceWorker.workerRegistrationUpdated", (event) => {
    lifecycle.registrations.push(...event.registrations);
  });
  cdp.on("ServiceWorker.workerVersionUpdated", (event) => {
    lifecycle.versions.push(...event.versions);
  });
  try {
    await cdp.send("ServiceWorker.enable");
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    const [oldTarget] = await serviceWorkerTargets(cdp, extensionId);
    if (!oldTarget?.targetId) {
      throw new Error("MV3 service-worker target was not found before termination");
    }
    const oldVersion = lifecycle.versions.find(
      (version) => version.targetId === oldTarget.targetId
    );
    if (!oldVersion?.versionId) {
      throw new Error(`MV3 service-worker version was not found: ${JSON.stringify(lifecycle)}`);
    }
    const oldRealmNonce = await originalWorker.evaluate(() => {
      const nonce = crypto.randomUUID();
      globalThis.__vaultkernHarnessWorkerRealmNonce = nonce;
      return nonce;
    });
    await cdp.send("ServiceWorker.stopWorker", { versionId: oldVersion.versionId });

    let oldTargetGone = false;
    let stopped = false;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const targets = await serviceWorkerTargets(cdp, extensionId);
      oldTargetGone = !targets.some((target) => target.targetId === oldTarget.targetId);
      stopped = lifecycle.versions.some(
        (version) =>
          version.versionId === oldVersion.versionId &&
          version.runningStatus === "stopped"
      );
      if (oldTargetGone && stopped) {
        break;
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    if (!oldTargetGone || !stopped) {
      throw new Error(
        `MV3 worker did not reach a stopped realm: ` +
          JSON.stringify({ oldTarget, oldTargetGone, stopped, lifecycle })
      );
    }

    const expectedOrigin = `chrome-extension://${extensionId}/`;
    const scopeURL = lifecycle.registrations.find((registration) =>
      registration.scopeURL.startsWith(expectedOrigin)
    )?.scopeURL ?? expectedOrigin;
    await cdp.send("ServiceWorker.startWorker", { scopeURL });
    let newTarget = null;
    let restartedWorker = null;
    let newRealm = null;
    for (let attempt = 0; attempt < 50 && !newRealm; attempt += 1) {
      const targets = await serviceWorkerTargets(cdp, extensionId);
      newTarget = targets[0] ?? null;
      const candidates = context
        .serviceWorkers()
        .filter((worker) => worker.url().startsWith(expectedOrigin));
      for (const candidate of candidates) {
        try {
          newRealm = await candidate.evaluate(() => {
            const previousNonce =
              globalThis.__vaultkernHarnessWorkerRealmNonce ?? null;
            const nonce = crypto.randomUUID();
            globalThis.__vaultkernHarnessWorkerRealmNonce = nonce;
            return { previousNonce, nonce };
          });
          restartedWorker = candidate;
          break;
        } catch {
          // The stopped Worker wrapper may remain briefly before the new realm is ready.
        }
      }
      if (!newRealm) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      }
    }
    if (!newTarget?.targetId || !restartedWorker || !newRealm) {
      throw new Error(
        `MV3 service worker did not create a new execution realm: ` +
          JSON.stringify({ oldTarget, newTarget, scopeURL, newRealm, lifecycle })
      );
    }
    if (newRealm.previousNonce !== null || newRealm.nonce === oldRealmNonce) {
      throw new Error(
        `MV3 service-worker global memory survived termination: ` +
          JSON.stringify({ oldRealmNonce, newRealm })
      );
    }
    return {
      restartedWorker,
      diagnostics: {
        oldTargetId: oldTarget.targetId,
        newTargetId: newTarget.targetId,
        targetIdReused: newTarget.targetId === oldTarget.targetId,
        workerObjectReused: restartedWorker === originalWorker,
        terminationCommand: "ServiceWorker.stopWorker",
        scopeURL,
        oldRealmNonce,
        newRealmNonce: newRealm.nonce,
        oldRealmNonceVisibleAfterRestart: newRealm.previousNonce,
        runningStatuses: lifecycle.versions
          .filter((version) => version.versionId === oldVersion.versionId)
          .map((version) => version.runningStatus)
      }
    };
  } finally {
    await cdp.detach().catch(() => {});
  }
}

async function readPendingFromActionPopup(extensionPage, tabId) {
  await extensionPage.evaluate(async () => await chrome.action.openPopup());
  let result = null;
  for (let attempt = 0; attempt < 40 && !result; attempt += 1) {
    result = await extensionPage.evaluate(async (tabIdValue) => {
      const popupViews = chrome.extension.getViews({ type: "popup" });
      const popupView = popupViews.at(-1);
      if (!popupView) {
        return null;
      }
      const response = await popupView.chrome.runtime.sendMessage({
        type: "vaultkern_autofill_pending_request",
        tabId: tabIdValue
      });
      const result = {
        popupUrl: popupView.location.href,
        response
      };
      popupView.close();
      return result;
    }, tabId);
    if (!result) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
  }
  if (!result) {
    throw new Error("new action popup did not become available after worker restart");
  }
  return result;
}

async function runMv3PendingSessionReloadCase() {
  await assertE2EManifest();
  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-mv3-pending-"));
  let context;
  let server;
  try {
    server = await startSmokeServer();
    const launched = await launchExtensionContext(join(workDir, "profile"));
    context = launched.context;
    const { extensionId, extensionPage, serviceWorker } = launched;
    const page = await context.newPage();
    await page.goto(server.url);
    await page.evaluate(() => {
      document
        .querySelector("#vaultkern-smoke-login-form")
        .addEventListener("submit", (event) => {
          globalThis.__vaultkernReloadSubmitObservation = {
            isTrusted: event.isTrusted,
            defaultPrevented: event.defaultPrevented
          };
        });
    });
    await page.locator("#vaultkern-smoke-username").fill("reload@example.com");
    await page.locator("#vaultkern-smoke-password").fill("reload-secret");
    await page.click("#vaultkern-smoke-submit");
    const submitObservation = await page.evaluate(
      () => globalThis.__vaultkernReloadSubmitObservation
    );
    if (
      submitObservation?.isTrusted !== true ||
      submitObservation?.defaultPrevented !== true
    ) {
      throw new Error(
        `MV3 reload submit was not trusted and prevented: ${JSON.stringify(submitObservation)}`
      );
    }

    const tabId = await targetTabId(extensionPage, server.url);
    const beforeReload = await waitForPendingSessionSnapshot(extensionPage, tabId);
    const pending = beforeReload.pending;
    if (
      pending?.version !== 2 ||
      pending?.state !== "captured" ||
      pending?.tabId !== tabId ||
      pending?.origin !== new URL(server.url).origin ||
      pending?.submission?.url !== server.url ||
      pending?.submission?.username !== "reload@example.com" ||
      pending?.submission?.password !== "reload-secret" ||
      typeof pending?.transactionId !== "string" ||
      pending.transactionId.length < 16 ||
      typeof pending?.expiresAt !== "number" ||
      pending.expiresAt <= Date.now()
    ) {
      throw new Error(`captured MV3 transaction was invalid: ${JSON.stringify(pending)}`);
    }
    const expectedPending = { key: beforeReload.key, pending };
    const beforeReloadSecurity = await collectPendingSessionSecurityProof(
      extensionPage,
      tabId,
      expectedPending
    );
    const recoveries = [];
    let currentWorker = serviceWorker;
    for (let cycle = 1; cycle <= 2; cycle += 1) {
      const restart = await terminateAndRestartServiceWorker(
        context,
        extensionPage,
        extensionId,
        currentWorker
      );
      currentWorker = restart.restartedWorker;

      const securityProof = await collectPendingSessionSecurityProof(
        extensionPage,
        tabId,
        expectedPending
      );
      const popupRead = await readPendingFromActionPopup(extensionPage, tabId);
      if (popupRead.response?.ok !== true) {
        throw new Error(
          `recovery ${cycle} popup could not read pending state: ${JSON.stringify(popupRead)}`
        );
      }
      assertRestoredPendingMatches(
        popupRead.response.pending,
        pending,
        `recovery ${cycle} popup`
      );
      recoveries.push({
        cycle,
        workerTargets: restart.diagnostics,
        securityProof,
        popupUrl: popupRead.popupUrl
      });
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: "mv3-pending-session-reload",
        transactionId: pending.transactionId,
        state: pending.state,
        origin: pending.origin,
        expiresAt: pending.expiresAt,
        beforeReloadSecurity,
        recoveries,
        pendingSessionKey: beforeReload.key,
        submitObservation,
        recoveryCycles: recoveries.length
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function sendTrustedExtensionMessage(extensionPage, message, timeout = 60_000) {
  await extensionPage.evaluate(async () => await chrome.action.openPopup());
  const wrapped = await extensionPage.evaluate(
    async ({ messageValue, timeoutValue }) =>
      await new Promise((resolvePromise) => {
        const startedAt = Date.now();
        const sendFromPopup = () => {
          const popupView = chrome.extension.getViews({ type: "popup" }).at(-1);
          if (!popupView) {
            if (Date.now() - startedAt >= timeoutValue) {
              resolvePromise({ timeout: true });
              return;
            }
            setTimeout(sendFromPopup, 50);
            return;
          }
          const timer = setTimeout(
            () => resolvePromise({ timeout: true }),
            timeoutValue
          );
          popupView.chrome.runtime.sendMessage(messageValue, (response) => {
            const lastError = popupView.chrome.runtime.lastError?.message;
            clearTimeout(timer);
            popupView.close();
            resolvePromise({ lastError, response });
          });
        };
        sendFromPopup();
      }),
    { messageValue: message, timeoutValue: timeout }
  );
  if (wrapped.timeout) {
    throw new Error(`extension message timed out: ${message.type}`);
  }
  if (wrapped.lastError) {
    throw new Error(`${message.type}: ${wrapped.lastError}`);
  }
  return wrapped.response;
}

async function waitForPendingAutofillState(
  extensionPage,
  tabId,
  predicate,
  label,
  timeoutMs = 15_000
) {
  const deadline = Date.now() + timeoutMs;
  let snapshot = null;
  while (Date.now() < deadline) {
    snapshot = await pendingSessionSnapshot(extensionPage, tabId);
    if (predicate(snapshot.pending)) {
      return snapshot.pending;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error(`${label} did not appear: ${JSON.stringify(snapshot)}`);
}

async function waitForTextFile(path, label, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await readFile(path, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error(`${label} was not written: ${path}`);
}

async function sha256File(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function autofillEntryFields(detail, passwordValue) {
  return {
    title: detail.title,
    username: detail.username,
    password: passwordValue,
    url: detail.url,
    notes: detail.notes,
    totpUri: detail.totpUri ?? null,
    customFields: (detail.customFields ?? []).map((field) => ({
      key: field.key,
      value: field.value,
      protected: field.protected
    }))
  };
}

function autofillUpdatePlanCommand(plan) {
  const fields = (value) => ({
    title: value.title,
    username: value.username,
    password: value.password,
    url: value.url,
    notes: value.notes,
    totpUri: value.totpUri,
    customFields: value.customFields.map((field) => ({ ...field }))
  });
  return {
    mode: "update",
    entry_id: plan.entryId,
    expected_fields: fields(plan.expectedFields),
    desired_fields: fields(plan.desiredFields)
  };
}

async function runAutofillNativeCrashReplayCase() {
  await assertE2EManifest();
  if (!existsSync(runtimePath)) {
    throw new Error(
      "target/debug/vaultkern-runtime is missing; run cargo build -p vaultkern-runtime first"
    );
  }
  if (process.platform === "win32") {
    throw new Error("autofill native crash replay requires the POSIX native-host wrapper");
  }

  const workDir = await mkdtemp(join("/tmp", "vaultkern-autofill-native-crash-"));
  const vaultPath = join(workDir, "autofill-crash.kdbx");
  const crashMarkerPath = join(workDir, "autofill-source-committed.marker");
  const pidLogPath = join(workDir, "native-host-pids.log");
  const oldPassword = "before-native-crash";
  const desiredPassword = "after-native-crash";
  let context;
  let server;
  try {
    run("cargo", [...vkdbxArgs, vaultPath, password]);
    server = await startSmokeServer();
    await writeNativeManifest(workDir, { crashMarkerPath, pidLogPath });
    const launched = await launchExtensionContext(join(workDir, "profile"));
    context = launched.context;
    const { extensionId, extensionPage, serviceWorker } = launched;

    const opened = await sendCommand(extensionPage, {
      type: "open_local_vault",
      path: vaultPath
    });
    const vaultId = opened.vaultId;
    await sendCommand(extensionPage, {
      type: "unlock_with_password",
      vault_id: vaultId,
      password
    });
    const groups = await sendCommand(extensionPage, {
      type: "list_groups",
      vault_id: vaultId
    });
    const created = await sendCommand(extensionPage, {
      type: "create_entry",
      vault_id: vaultId,
      parent_group_id: groups.root.id,
      title: "Autofill Crash Replay",
      username,
      password: oldPassword,
      url: server.url,
      notes: "native crash replay fixture",
      totp_uri: null
    });
    await sendCommand(extensionPage, { type: "save_vault", vault_id: vaultId });
    const baselineDetail = await sendCommand(extensionPage, {
      type: "get_entry_detail",
      vault_id: vaultId,
      entry_id: created.id
    });
    const sourceHashBeforeCommit = await sha256File(vaultPath);

    const page = await context.newPage();
    await page.goto(server.url);
    await page.evaluate(() => {
      document
        .querySelector("#vaultkern-smoke-login-form")
        .addEventListener("submit", (event) => {
          globalThis.__vaultkernNativeCrashSubmitObservation = {
            isTrusted: event.isTrusted,
            defaultPrevented: event.defaultPrevented
          };
        });
    });
    await page.locator("#vaultkern-smoke-username").fill(username);
    await page.locator("#vaultkern-smoke-password").fill(desiredPassword);
    await page.click("#vaultkern-smoke-submit");
    const submitObservation = await page.evaluate(
      () => globalThis.__vaultkernNativeCrashSubmitObservation
    );
    if (
      submitObservation?.isTrusted !== true ||
      submitObservation?.defaultPrevented !== true
    ) {
      throw new Error(
        `native crash submit was not trusted and prevented: ` +
          JSON.stringify(submitObservation)
      );
    }

    const tabId = await targetTabId(extensionPage, server.url);
    const captured = (await waitForPendingSessionSnapshot(extensionPage, tabId))
      .pending;
    if (
      captured?.state !== "captured" ||
      captured.submission?.username !== username ||
      captured.submission?.password !== desiredPassword
    ) {
      throw new Error(
        `trusted submit did not capture the expected credentials: ` +
          JSON.stringify(captured)
      );
    }
    const expectedFields = autofillEntryFields(baselineDetail, oldPassword);
    const desiredFields = autofillEntryFields(
      { ...baselineDetail, username },
      desiredPassword
    );
    const plan = {
      mode: "update",
      entryId: created.id,
      expectedFields,
      desiredFields
    };
    const planned = await sendTrustedExtensionMessage(extensionPage, {
      type: "vaultkern_autofill_pending_plan",
      tabId,
      transactionId: captured.transactionId,
      vaultId,
      plan
    });
    if (
      planned?.ok !== true ||
      planned.pending?.state !== "planned" ||
      typeof planned.pending?.operationId !== "string"
    ) {
      throw new Error(
        `autofill crash plan was rejected: ` +
          JSON.stringify({ planned, captured, vaultId, plan })
      );
    }
    const transactionId = planned.pending.transactionId;
    const operationId = planned.pending.operationId;

    const firstExecution = await sendTrustedExtensionMessage(
      extensionPage,
      {
        type: "vaultkern_autofill_pending_execute",
        tabId,
        transactionId
      },
      30_000
    );
    if (
      firstExecution?.ok !== false ||
      firstExecution?.error?.code !== "native_port_disconnected"
    ) {
      throw new Error(
        `native host did not disconnect after its durable source commit: ` +
          JSON.stringify(firstExecution)
      );
    }
    const markerContent = await waitForTextFile(
      crashMarkerPath,
      "durable autofill crash marker"
    );
    const persistedWal = await waitForPendingAutofillState(
      extensionPage,
      tabId,
      (pending) =>
        pending?.state === "persisting" &&
        pending.transactionId === transactionId &&
        pending.operationId === operationId,
      "persisting autofill WAL after native disconnect"
    );
    const sourceHashAfterCommit = await sha256File(vaultPath);
    const sourceSizeAfterCommit = (await readFile(vaultPath)).byteLength;
    if (sourceHashAfterCommit === sourceHashBeforeCommit) {
      throw new Error("native crash marker appeared before the KDBX source changed");
    }

    const restart = await terminateAndRestartServiceWorker(
      context,
      extensionPage,
      extensionId,
      serviceWorker
    );
    const activeVaultConflict = await waitForPendingAutofillState(
      extensionPage,
      tabId,
      (pending) =>
        pending?.state === "persist_conflict" &&
        pending.transactionId === transactionId &&
        pending.operationId === operationId &&
        pending.conflict?.code === "active_vault_mismatch" &&
        pending.conflict?.retryable === true,
      "active-vault mismatch from the restarted native runtime"
    );
    const pidLog = await waitForTextFile(pidLogPath, "native host PID log");
    const crashProof = assertNativeCrashObservation({
      firstExecution,
      markerContent,
      pidLog,
      transactionId,
      operationId
    });

    const reopened = await sendCommand(extensionPage, {
      type: "open_local_vault",
      path: vaultPath
    });
    await sendCommand(extensionPage, {
      type: "unlock_with_password",
      vault_id: reopened.vaultId,
      password
    });
    const committedDetail = await sendCommand(extensionPage, {
      type: "get_entry_detail",
      vault_id: reopened.vaultId,
      entry_id: created.id
    });
    const committedHistory = await sendCommand(extensionPage, {
      type: "list_entry_history",
      vault_id: reopened.vaultId,
      entry_id: created.id
    });
    if (
      committedDetail.id !== created.id ||
      !isDeepStrictEqual(
        autofillEntryFields(committedDetail, committedDetail.password),
        desiredFields
      ) ||
      committedHistory.items?.length !== 1
    ) {
      throw new Error(
        `committed autofill mutation was not present after native restart: ` +
          JSON.stringify({ committedDetail, committedHistory })
      );
    }
    const committedHistoryDetail = await sendCommand(extensionPage, {
      type: "get_entry_history_detail",
      vault_id: reopened.vaultId,
      entry_id: created.id,
      history_index: committedHistory.items[0].index
    });
    const expectedHistoryDetail = {
      type: "entry_history_detail",
      entryId: created.id,
      historyIndex: committedHistory.items[0].index,
      title: baselineDetail.title,
      username: baselineDetail.username,
      password: oldPassword,
      url: baselineDetail.url,
      notes: baselineDetail.notes,
      modifiedAt: baselineDetail.modifiedAt,
      customFields: baselineDetail.customFields,
      attachments: baselineDetail.attachments
    };
    if (!isDeepStrictEqual(committedHistoryDetail, expectedHistoryDetail)) {
      throw new Error(
        `autofill commit did not preserve exactly one original history snapshot: ` +
          JSON.stringify({ committedHistoryDetail, expectedHistoryDetail })
      );
    }

    const explicitRetry = await sendTrustedExtensionMessage(extensionPage, {
      type: "vaultkern_autofill_pending_execute",
      tabId,
      transactionId
    });
    if (
      explicitRetry?.ok !== true ||
      explicitRetry.pending?.state !== "persisted" ||
      explicitRetry.pending?.transactionId !== transactionId ||
      explicitRetry.pending?.operationId !== operationId ||
      explicitRetry.pending?.entryId !== created.id
    ) {
      throw new Error(
        `same-operation autofill retry did not complete the WAL: ` +
          JSON.stringify(explicitRetry)
      );
    }
    const completion = await sendTrustedExtensionMessage(extensionPage, {
      type: "vaultkern_autofill_pending_status",
      tabId,
      transactionId
    });
    if (
      completion?.ok !== true ||
      completion.pending !== null ||
      completion.outcome !== "persisted"
    ) {
      throw new Error(`autofill completion receipt was not durable: ${JSON.stringify(completion)}`);
    }
    const sourceHashAfterRetry = await sha256File(vaultPath);
    if (sourceHashAfterRetry !== sourceHashAfterCommit) {
      throw new Error("same-operation autofill retry rewrote the committed KDBX source");
    }
    const historyAfterRetry = await sendCommand(extensionPage, {
      type: "list_entry_history",
      vault_id: reopened.vaultId,
      entry_id: created.id
    });
    if (historyAfterRetry.items?.length !== 1) {
      throw new Error(
        `same-operation retry duplicated entry history: ${JSON.stringify(historyAfterRetry)}`
      );
    }

    const receiptReplay = await sendCommand(extensionPage, {
      type: "persist_autofill_mutation",
      transaction_id: transactionId,
      operation_id: operationId,
      vault_id: reopened.vaultId,
      plan: autofillUpdatePlanCommand(plan)
    });
    assertNativeReceiptReplay({
      receiptReplay,
      transactionId,
      operationId,
      vaultId: reopened.vaultId,
      entryId: created.id,
      sourceContentSha256: sourceHashAfterCommit,
      sourceSizeBytes: sourceSizeAfterCommit
    });
    if (
      (await sha256File(vaultPath)) !== sourceHashAfterCommit ||
      (
        await sendCommand(extensionPage, {
          type: "list_entry_history",
          vault_id: reopened.vaultId,
          entry_id: created.id
        })
      ).items?.length !== 1
    ) {
      throw new Error("native receipt replay changed source bytes or entry history");
    }

    console.log(
      JSON.stringify({
        ok: true,
        case: "autofill-native-crash-replay",
        transactionId,
        operationId,
        entryId: created.id,
        submitObservation,
        persistedWalState: persistedWal.state,
        restart: restart.diagnostics,
        activeVaultConflict: activeVaultConflict.conflict,
        crashProof,
        sourceHashBeforeCommit,
        sourceHashAfterCommit,
        sourceHashAfterRetry,
        historyCount: historyAfterRetry.items.length,
        receiptDisposition: receiptReplay.disposition,
        completionOutcome: completion.outcome
      })
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

async function sendRawFillEntryDetail(extensionPage, targetUrl, message) {
  return await extensionPage.evaluate(
    async ({ targetUrl, message }) => {
      const tabs = await chrome.tabs.query({});
      const tab = tabs.find((candidate) => candidate.url === targetUrl);
      if (!tab?.id) {
        throw new Error(`target tab not found: ${targetUrl}`);
      }
      const startedAt = performance.now();
      const response = await chrome.tabs.sendMessage(tab.id, message);
      return {
        durationMs: performance.now() - startedAt,
        response
      };
    },
    { targetUrl, message }
  );
}

async function sendFillEntryDetailWithoutCapability(extensionPage, targetUrl, payload) {
  return await sendRawFillEntryDetail(extensionPage, targetUrl, {
    type: "fill_entry_detail",
    ...payload,
    targetUrl
  });
}

async function sendFillEntryDetail(extensionPage, targetUrl, entryId, payload) {
  return await sendRawFillEntryDetail(
    extensionPage,
    targetUrl,
    createManualFillEntryDetailMessage(targetUrl, entryId, payload)
  );
}

async function sendAutomaticFillEntryDetail(
  extensionPage,
  targetUrl,
  entryId,
  payload
) {
  return await sendRawFillEntryDetail(extensionPage, targetUrl, {
    type: "fill_entry_detail",
    ...payload,
    targetUrl,
    fillCapability: {
      kind: "automatic",
      targetUrl,
      entryId
    }
  });
}

async function writeNativeManifest(
  workDir,
  { crashMarkerPath = null, pidLogPath = null } = {}
) {
  const profileHostDir = join(workDir, "profile", "NativeMessagingHosts");
  await mkdir(profileHostDir, { recursive: true });
  let nativeHostPath = runtimePath;
  if (crashMarkerPath !== null || pidLogPath !== null) {
    if (typeof crashMarkerPath !== "string" || typeof pidLogPath !== "string") {
      throw new TypeError("native crash manifest requires marker and PID log paths");
    }
    nativeHostPath = join(workDir, "vaultkern-native-crash-wrapper.sh");
    await writeFile(
      nativeHostPath,
      createNativeCrashWrapperScript({
        runtimePath,
        pidLogPath,
        crashMarkerPath
      }),
      "utf8"
    );
    await chmod(nativeHostPath, 0o700);
  }
  const origin = `chrome-extension://${E2E_EXTENSION_ID}/`;
  const manifest = run(
    runtimePath,
    ["--print-native-host-manifest", nativeHostPath, origin],
    { capture: true }
  );
  const destination = join(profileHostDir, "com.vaultkern.runtime.json");
  await writeFile(destination, manifest, "utf8");
  return destination;
}

async function enablePasskeyProvider(extensionPage) {
  await extensionPage.evaluate(
    async (settings) => {
      await chrome.storage.local.set({
        vaultkernExtensionSettings: settings,
        vaultkernWebAuthnDebugEnabled: true
      });
    },
    {
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 10,
      clearClipboardSeconds: 30,
      browserPasskeyProxyEnabled: true
    }
  );
  await extensionPage.waitForFunction(
    async () => {
      const { vaultkernWebAuthnDebug } = await chrome.storage.local.get(
        "vaultkernWebAuthnDebug"
      );
      return (
        Array.isArray(vaultkernWebAuthnDebug) &&
        vaultkernWebAuthnDebug.some((entry) => entry?.event === "page_hook_registered")
      );
    },
    undefined,
    { timeout: 15_000 }
  );
}

async function sendCommand(extensionPage, command, timeout = 60_000) {
  const wrapped = await extensionPage.evaluate(
    async ({ command, timeout }) =>
      await new Promise((resolvePromise) => {
        const timer = setTimeout(() => resolvePromise({ timeout: true }), timeout);
        chrome.runtime.sendMessage({ version: 1, command }, (response) => {
          const lastError = chrome.runtime.lastError?.message;
          clearTimeout(timer);
          resolvePromise({ lastError, response });
        });
      }),
    { command, timeout }
  );

  if (wrapped.timeout) {
    throw new Error(`runtime command timed out: ${command.type}`);
  }
  if (wrapped.lastError) {
    throw new Error(`${command.type}: ${wrapped.lastError}`);
  }
  if (wrapped.response?.error) {
    throw new Error(`${command.type}: ${JSON.stringify(wrapped.response.error)}`);
  }

  return wrapped.response;
}

async function passkeyDiagnostics(extensionPage, webAuthnPage) {
  const webAuthnDebug = await extensionPage
    .evaluate(async () => await chrome.storage.local.get("vaultkernWebAuthnDebug"))
    .catch((error) => ({ readError: String(error?.message ?? error) }));
  const registeredContentScripts = await extensionPage
    .evaluate(async () => await chrome.scripting.getRegisteredContentScripts())
    .catch((error) => ({ readError: String(error?.message ?? error) }));
  const isolatedProbe = await extensionPage
    .evaluate(async (pageUrl) => {
      const [tab] = await chrome.tabs.query({ url: pageUrl });
      if (!tab?.id) {
        return { tabFound: false };
      }
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: "ISOLATED",
        func: () => ({
          contentScriptInstalled: Boolean(
            globalThis.__vaultkernWebAuthnContentScriptInstalled
          ),
          inlineBridgeInstalled:
            globalThis.__vaultkernWebAuthnInlineBridgeVersion === 1,
          globalOrigin: globalThis.origin,
          locationOrigin: window.location.origin,
          ancestorOrigins: Array.from(window.location.ancestorOrigins ?? []),
          hasChromeRuntimeSendMessage:
            typeof chrome?.runtime?.sendMessage === "function"
        })
      });
      return { tabFound: true, result: result?.result ?? null };
    }, webAuthnPage.url())
    .catch((error) => ({ readError: String(error?.message ?? error) }));
  const pageProbe = await webAuthnPage
    .evaluate(() => ({
      hookInstalled: Boolean(navigator.credentials?.__vaultkernWebAuthnHookInstalled),
      createSource: String(navigator.credentials?.create).slice(0, 200),
      getSource: String(navigator.credentials?.get).slice(0, 200),
      mainHasChromeRuntimeSendMessage:
        typeof globalThis.chrome?.runtime?.sendMessage === "function",
      messages: globalThis.__vaultkernWebAuthnMessages ?? [],
      result:
        document.querySelector("#vaultkern-passkey-register-result")?.value ||
        document.querySelector("#vaultkern-passkey-result")?.value ||
        null
    }))
    .catch((error) => ({ readError: String(error?.message ?? error) }));
  return { webAuthnDebug, registeredContentScripts, isolatedProbe, pageProbe };
}

async function approvePasskeyPrompt(context, extensionPage, webAuthnPage, label) {
  const prompt = await waitForPasskeyPromptPage(
    context,
    extensionPage,
    webAuthnPage,
    label,
    "passkey prompt"
  );
  await prompt.waitForLoadState("domcontentloaded");
  await prompt.getByRole("button", { name: "Continue passkey request" }).click();
  await prompt.waitForEvent("close", { timeout: 5_000 }).catch(() => {});
}

async function approvePasskeyPromptAndSelectCredential(
  context,
  extensionPage,
  webAuthnPage,
  label,
  credentialId
) {
  const prompt = await waitForPasskeyPromptPage(
    context,
    extensionPage,
    webAuthnPage,
    label,
    "passkey prompt"
  );
  await prompt.waitForLoadState("domcontentloaded");
  await prompt.getByRole("button", { name: "Continue passkey request" }).click();
  const selection = await waitForPromptCredentialSelectionOrClose(
    prompt,
    label,
    credentialId
  );
  if (selection.closed) {
    return;
  }

  await prompt.getByRole("radio").nth(selection.credentialIndex).check();
  await prompt.getByRole("button", { name: "Continue passkey request" }).click();
  await prompt.waitForEvent("close", { timeout: 5_000 }).catch(() => {});
}

async function waitForPromptCredentialSelectionOrClose(prompt, label, credentialId) {
  const deadline = Date.now() + PASSKEY_CREDENTIAL_OPTIONS_TIMEOUT_MS;
  let lastCredentialIds = [];

  while (Date.now() < deadline) {
    if (prompt.isClosed()) {
      return { closed: true };
    }

    try {
      const result = await prompt.evaluate(async (expectedCredentialId) => {
        const params = new URLSearchParams(window.location.search);
        const requestIdValue = params.get("requestId");
        const requestId =
          requestIdValue && requestIdValue.trim() !== ""
            ? Number(requestIdValue)
            : null;
        if (typeof requestId !== "number" || !Number.isFinite(requestId)) {
          return { credentialIndex: -1, credentialIds: [] };
        }

        const response = await chrome.runtime.sendMessage({
          type: "vaultkern_presence_options_request",
          requestId,
          ...(params.get("origin") ? { origin: params.get("origin") } : {}),
          ...(params.get("relyingParty")
            ? { relyingParty: params.get("relyingParty") }
            : {}),
          ...(params.get("topOrigin") ? { topOrigin: params.get("topOrigin") } : {}),
          ...(params.get("nonce") ? { nonce: params.get("nonce") } : {})
        });
        const options = Array.isArray(response?.credentialOptions)
          ? response.credentialOptions
          : [];
        const credentialIds = options
          .map((option) => option?.credentialId)
          .filter((value) => typeof value === "string");
        return {
          credentialIndex: credentialIds.indexOf(expectedCredentialId),
          credentialIds
        };
      }, credentialId);
      lastCredentialIds = result.credentialIds ?? [];
      if (result.credentialIndex >= 0) {
        return { closed: false, credentialIndex: result.credentialIndex };
      }
    } catch (error) {
      if (prompt.isClosed() || String(error?.message ?? error).includes("Target page")) {
        return { closed: true };
      }
      throw error;
    }

    await new Promise((resolve) =>
      setTimeout(resolve, PASSKEY_CREDENTIAL_OPTIONS_POLL_MS)
    );
  }

  throw new Error(
    `${label} did not expose credential ${credentialId} for selection; ` +
      `last credential ids: ${JSON.stringify(lastCredentialIds)}`
  );
}

async function unlockPasskeyPromptWithPassword(
  context,
  extensionPage,
  webAuthnPage,
  password,
  label
) {
  const prompt = await waitForPasskeyPromptPage(
    context,
    extensionPage,
    webAuthnPage,
    label,
    "passkey unlock prompt"
  );
  await prompt.waitForLoadState("domcontentloaded");
  await prompt.getByLabel("Master Password").fill(password);
  await prompt.getByRole("button", { name: "Unlock Vault" }).click();
  await prompt.waitForEvent("close", { timeout: 5_000 }).catch(() => {});
}

async function waitForPasskeyPromptPage(
  context,
  extensionPage,
  webAuthnPage,
  label,
  promptLabel
) {
  const existingPrompt = context
    .pages()
    .find((page) => isPasskeyPromptPage(page, extensionPage));
  if (existingPrompt) {
    return existingPrompt;
  }

  return context.waitForEvent("page", { timeout: 15_000 }).catch(async (error) => {
    const diagnostics = await passkeyDiagnostics(extensionPage, webAuthnPage);
    throw new Error(
      `${label} ${promptLabel} did not open: ${error.message}\n` +
        `Diagnostics: ${JSON.stringify(diagnostics, null, 2)}`
    );
  });
}

function isPasskeyPromptPage(page, extensionPage) {
  if (page === extensionPage || page.isClosed()) {
    return false;
  }

  try {
    const url = new URL(page.url());
    return url.pathname.endsWith("/popup.html") && url.searchParams.has("webauthn");
  } catch {
    return false;
  }
}

async function clearWebAuthnDebug(extensionPage) {
  await extensionPage.evaluate(
    async () => await chrome.storage.local.set({ vaultkernWebAuthnDebug: [] })
  );
}

async function expectWebAuthnDebugEvent(extensionPage, event, expected, label) {
  await waitForWebAuthnDebugEvent(
    async () => {
      const { vaultkernWebAuthnDebug = [] } = await extensionPage.evaluate(
        async () => await chrome.storage.local.get("vaultkernWebAuthnDebug")
      );
      return vaultkernWebAuthnDebug;
    },
    event,
    expected,
    { label }
  );
}

async function waitForPasskeyRegisterResult(extensionPage, passkeyRegisterPage, label) {
  await passkeyRegisterPage
    .waitForFunction(
      () => document.querySelector("#vaultkern-passkey-register-result")?.value
    )
    .catch(async (error) => {
      const diagnostics = await passkeyDiagnostics(
        extensionPage,
        passkeyRegisterPage
      );
      throw new Error(
        `${label} passkey result did not appear: ${error.message}\n` +
          `Diagnostics: ${JSON.stringify(diagnostics, null, 2)}`
      );
    });
  const passkeyRegisterResult = await passkeyRegisterPage
    .locator("#vaultkern-passkey-register-result")
    .evaluate((node) => node.value || node.textContent);
  if (!passkeyRegisterResult?.startsWith("credential:")) {
    const webAuthnDebug = await extensionPage
      .evaluate(async () => await chrome.storage.local.get("vaultkernWebAuthnDebug"))
      .catch((error) => ({ readError: String(error?.message ?? error) }));
    const pageProbe = await passkeyRegisterPage
      .evaluate(() => ({
        hookInstalled: Boolean(
          navigator.credentials?.__vaultkernWebAuthnHookInstalled
        ),
        createSource: String(navigator.credentials?.create).slice(0, 200),
        messages: globalThis.__vaultkernWebAuthnMessages ?? []
      }))
      .catch((error) => ({ readError: String(error?.message ?? error) }));
    throw new Error(
      `unexpected ${label} passkey register result: ${passkeyRegisterResult}\n` +
        `WebAuthn debug: ${JSON.stringify(webAuthnDebug, null, 2)}\n` +
        `Page probe: ${JSON.stringify(pageProbe, null, 2)}`
    );
  }
  return passkeyRegisterResult;
}

async function waitForPasskeyLoginResult(
  extensionPage,
  passkeyPage,
  expectedPasskeyResult,
  label
) {
  await passkeyPage
    .waitForFunction(
      () => document.querySelector("#vaultkern-passkey-result")?.value
    )
    .catch(async (error) => {
      const diagnostics = await passkeyDiagnostics(extensionPage, passkeyPage);
      throw new Error(
        `${label} passkey result did not appear: ${error.message}\n` +
          `Diagnostics: ${JSON.stringify(diagnostics, null, 2)}`
      );
    });
  const passkeyResult = await passkeyPage
    .locator("#vaultkern-passkey-result")
    .evaluate((node) => node.value || node.textContent);
  if (passkeyResult !== expectedPasskeyResult) {
    const webAuthnDebug = await extensionPage
      .evaluate(async () => await chrome.storage.local.get("vaultkernWebAuthnDebug"))
      .catch((error) => ({ readError: String(error?.message ?? error) }));
    const pageProbe = await passkeyPage
      .evaluate(() => ({
        hookInstalled: Boolean(
          navigator.credentials?.__vaultkernWebAuthnHookInstalled
        ),
        getSource: String(navigator.credentials?.get).slice(0, 200),
        messages: globalThis.__vaultkernWebAuthnMessages ?? []
      }))
      .catch((error) => ({ readError: String(error?.message ?? error) }));
    throw new Error(
      `unexpected ${label} passkey result: ${passkeyResult}\n` +
        `WebAuthn debug: ${JSON.stringify(webAuthnDebug, null, 2)}\n` +
        `Page probe: ${JSON.stringify(pageProbe, null, 2)}`
    );
  }
  return passkeyResult;
}

async function waitForSimpleWebAuthnVerification(page, label) {
  await page
    .waitForFunction(() => {
      const value = document.querySelector("#result")?.value;
      if (!value?.trim().startsWith("{")) {
        return false;
      }
      try {
        return JSON.parse(value).verified === true;
      } catch {
        return false;
      }
    })
    .catch(async (error) => {
      const state = await page
        .evaluate(() => ({
          result: document.querySelector("#result")?.value ?? null,
          status: document.querySelector("#status-json")?.textContent ?? null,
          messages: globalThis.__vaultkernWebAuthnMessages ?? []
        }))
        .catch((innerError) => ({ readError: String(innerError?.message ?? innerError) }));
      throw new Error(
        `${label} SimpleWebAuthn verification did not succeed: ${error.message}\n` +
          `Page state: ${JSON.stringify(state, null, 2)}`
      );
    });

  const value = await page.locator("#result").evaluate((node) => node.value);
  return JSON.parse(value);
}

function assertDiscoverableWebAuthnGetObservation(messages, label) {
  const getMessages = messages.filter((message) => message?.ceremony === "get");
  if (getMessages.length === 0) {
    throw new Error(
      `${label} did not observe a WebAuthn get request: ${JSON.stringify(
        messages,
        null,
        2
      )}`
    );
  }

  const messagesWithAllowedCredentials = getMessages.filter(
    (message) =>
      Array.isArray(message.allowCredentialIds) &&
      message.allowCredentialIds.length > 0
  );
  if (messagesWithAllowedCredentials.length > 0) {
    throw new Error(
      `${label} sent allowCredentials: ${JSON.stringify(
        messagesWithAllowedCredentials,
        null,
        2
      )}`
    );
  }
}

async function main() {
  const manifest = JSON.parse(await readFile(join(extensionPath, "manifest.json"), "utf8"));
  if (manifest.key == null) {
    throw new Error("dist/manifest.json does not contain a fixed key; run npm run build:e2e first");
  }
  if (!existsSync(runtimePath)) {
    throw new Error("target/debug/vaultkern-runtime is missing; run cargo build -p vaultkern-runtime first");
  }

  const workDir = await mkdtemp(join(tmpdir(), "vaultkern-browser-e2e-"));
  const vaultPath = join(workDir, "smoke.kdbx");
  let context;
  let server;
  let simpleWebAuthnServer;

  try {
    run("cargo", [...vkdbxArgs, vaultPath, password]);
    server = await startSmokeServer();
    simpleWebAuthnServer = await createSimpleWebAuthnSmokeServer({
      hostname: SMOKE_HOST,
      port: 0,
      userVerification: "discouraged"
    });
    const nativeManifest = await writeNativeManifest(workDir);

    context = await playwright.chromium.launchPersistentContext(join(workDir, "profile"), {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`
      ]
    });

    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    }
    const extensionId = serviceWorker.url().split("/")[2];
    if (extensionId !== E2E_EXTENSION_ID) {
      throw new Error(`unexpected extension id: ${extensionId}, expected ${E2E_EXTENSION_ID}`);
    }

    const extensionPage = await context.newPage();
    await extensionPage.goto(`chrome-extension://${extensionId}/popup.html`);
    const extensionInfo = await extensionPage.evaluate(() => ({
      id: chrome.runtime.id,
      name: chrome.runtime.getManifest().name,
      permissions: chrome.runtime.getManifest().permissions
    }));

    if (
      extensionInfo.name !== "VaultKern Browser" ||
      !extensionInfo.permissions.includes("nativeMessaging")
    ) {
      throw new Error(`unexpected extension manifest: ${JSON.stringify(extensionInfo)}`);
    }

    const opened = await sendCommand(extensionPage, {
      type: "open_local_vault",
      path: vaultPath
    });
    const vaultId = opened.vaultId;
    await sendCommand(extensionPage, {
      type: "unlock_with_password",
      vault_id: vaultId,
      password
    });
    const groups = await sendCommand(extensionPage, {
      type: "list_groups",
      vault_id: vaultId
    });
    const created = await sendCommand(extensionPage, {
      type: "create_entry",
      vault_id: vaultId,
      parent_group_id: groups.root.id,
      title: "Chrome E2E Smoke Login",
      username,
      password: entryPassword,
      url: server.url,
      notes: "browser extension native messaging e2e smoke",
      totp_uri: null
    });
    await sendCommand(extensionPage, { type: "save_vault", vault_id: vaultId });
    const candidates = await sendCommand(extensionPage, {
      type: "find_fill_candidates",
      vault_id: vaultId,
      url: server.url
    });
    if (!candidates.entries?.some((entry) => entry.id === created.id)) {
      throw new Error("created entry was not returned as a fill candidate");
    }

    const page = await context.newPage();
    await page.goto(server.url);
    await sendFillEntryDetailWithoutCapability(extensionPage, server.url, {
      username,
      password: entryPassword
    });

    const unauthorizedValues = await page.evaluate(() => ({
      username: document.querySelector("#vaultkern-smoke-username")?.value,
      password: document.querySelector("#vaultkern-smoke-password")?.value
    }));
    if (unauthorizedValues.username !== "" || unauthorizedValues.password !== "") {
      throw new Error(
        `fill without a capability released credentials: ${JSON.stringify(unauthorizedValues)}`
      );
    }

    await sendFillEntryDetail(extensionPage, server.url, created.id, {
      username,
      password: entryPassword
    });

    const formValues = await page.evaluate(() => ({
      username: document.querySelector("#vaultkern-smoke-username")?.value,
      password: document.querySelector("#vaultkern-smoke-password")?.value
    }));
    if (formValues.username !== username || formValues.password !== entryPassword) {
      throw new Error(`content script fill failed: ${JSON.stringify(formValues)}`);
    }

    await page.click("#vaultkern-smoke-submit");
    const submitted = await page
      .locator("#vaultkern-smoke-result")
      .evaluate((node) => node.value || node.textContent);
    const expectedSubmit = `submitted:${username}:${entryPassword.length}`;
    if (submitted !== expectedSubmit) {
      throw new Error(`unexpected submit result: ${submitted}`);
    }

    const noisyPage = await context.newPage();
    await noisyPage.goto(server.noisyLoginUrl);
    await sendFillEntryDetail(extensionPage, server.noisyLoginUrl, created.id, {
      username,
      password: entryPassword
    });
    const noisyValues = await noisyPage.evaluate(() => ({
      query: document.querySelector("#vaultkern-smoke-query")?.value,
      newsletter: document.querySelector("#vaultkern-smoke-newsletter-email")?.value,
      signup: document.querySelector("#vaultkern-smoke-signup-email")?.value,
      newPassword: document.querySelector("#vaultkern-smoke-new-password")?.value,
      username: document.querySelector("#vaultkern-smoke-noisy-user")?.value,
      password: document.querySelector("#vaultkern-smoke-noisy-password")?.value
    }));
    if (
      noisyValues.query !== "" ||
      noisyValues.newsletter !== "" ||
      noisyValues.signup !== "" ||
      noisyValues.newPassword !== "" ||
      noisyValues.username !== username ||
      noisyValues.password !== entryPassword
    ) {
      throw new Error(`noisy login fill failed: ${JSON.stringify(noisyValues)}`);
    }

    const totpPage = await context.newPage();
    await totpPage.goto(server.totpUrl);
    const smokeTotp = "112233";
    await sendFillEntryDetail(extensionPage, server.totpUrl, created.id, {
      totp: smokeTotp
    });
    const totpValue = await totpPage.evaluate(
      () => document.querySelector("#vaultkern-smoke-totp")?.value
    );
    if (totpValue !== smokeTotp) {
      throw new Error(`totp fill failed: ${JSON.stringify({ totpValue })}`);
    }

    await enablePasskeyProvider(extensionPage);

    const passkeyRegisterPage = await context.newPage();
    await passkeyRegisterPage.goto(server.passkeyRegisterUrl);
    await passkeyRegisterPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    const passkeyRegisterReady = await passkeyRegisterPage.evaluate(async () => {
      const publicKeyCredentialAvailable = typeof PublicKeyCredential !== "undefined";
      const userVerifyingPlatformAuthenticatorAvailable =
        publicKeyCredentialAvailable &&
        typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
          ? await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
          : false;
      return {
        hasButton: document.querySelector("#vaultkern-passkey-register") != null,
        publicKeyCredentialAvailable,
        userVerifyingPlatformAuthenticatorAvailable,
        hookInstalled: Boolean(
          navigator.credentials?.__vaultkernWebAuthnHookInstalled
        ),
        createSource: String(navigator.credentials?.create).slice(0, 200)
      };
    });
    if (!passkeyRegisterReady.hasButton) {
      throw new Error("passkey register smoke page did not expose the create button");
    }
    const passkeyRegistrationApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      passkeyRegisterPage,
      "registration"
    );
    await passkeyRegisterPage.click("#vaultkern-passkey-register");
    await passkeyRegistrationApproval;
    const passkeyRegisterResult = await waitForPasskeyRegisterResult(
      extensionPage,
      passkeyRegisterPage,
      "registration"
    );
    const registeredPasskeyCredentialId = passkeyRegisterResult.slice("credential:".length);

    await sendCommand(extensionPage, { type: "lock_session" });
    const reopened = await sendCommand(extensionPage, {
      type: "open_local_vault",
      path: vaultPath
    });
    await sendCommand(extensionPage, {
      type: "unlock_with_password",
      vault_id: reopened.vaultId,
      password
    });

    const passkeyPage = await context.newPage();
    await passkeyPage.goto(
      `${server.passkeyUrl}?credential=${encodeURIComponent(registeredPasskeyCredentialId)}`
    );
    await passkeyPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    const passkeySmokeReady = await passkeyPage.evaluate(() => ({
      hasButton: document.querySelector("#vaultkern-passkey-login") != null,
      publicKeyCredentialAvailable: typeof PublicKeyCredential !== "undefined",
      hookInstalled: Boolean(
        navigator.credentials?.__vaultkernWebAuthnHookInstalled
      ),
      getSource: String(navigator.credentials?.get).slice(0, 200)
    }));
    if (!passkeySmokeReady.hasButton) {
      throw new Error("passkey smoke page did not expose the login button");
    }
    const passkeyApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      passkeyPage,
      "assertion"
    );
    await passkeyPage.click("#vaultkern-passkey-login");
    await passkeyApproval;
    const expectedPasskeyResult = `credential:${registeredPasskeyCredentialId}`;
    const passkeyResult = await waitForPasskeyLoginResult(
      extensionPage,
      passkeyPage,
      expectedPasskeyResult,
      "assertion"
    );

    const storedPasskeyPage = await context.newPage();
    await storedPasskeyPage.goto(server.passkeyUrl);
    await storedPasskeyPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    if (
      !(await storedPasskeyPage.evaluate(
        () => document.querySelector("#vaultkern-passkey-login") != null
      ))
    ) {
      throw new Error("stored passkey smoke page did not expose the login button");
    }
    const storedPasskeyApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      storedPasskeyPage,
      "stored assertion"
    );
    await storedPasskeyPage.click("#vaultkern-passkey-login");
    await storedPasskeyApproval;
    const storedPasskeyResult = await waitForPasskeyLoginResult(
      extensionPage,
      storedPasskeyPage,
      expectedPasskeyResult,
      "stored assertion"
    );

    const discoverablePasskeyPage = await context.newPage();
    await discoverablePasskeyPage.goto(`${server.passkeyUrl}?discoverable=1`);
    await discoverablePasskeyPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    if (
      !(await discoverablePasskeyPage.evaluate(
        () => document.querySelector("#vaultkern-passkey-login") != null
      ))
    ) {
      throw new Error("discoverable passkey smoke page did not expose the login button");
    }
    const discoverablePasskeyApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      discoverablePasskeyPage,
      "discoverable assertion"
    );
    await discoverablePasskeyPage.click("#vaultkern-passkey-login");
    await discoverablePasskeyApproval;
    const discoverablePasskeyResult = await waitForPasskeyLoginResult(
      extensionPage,
      discoverablePasskeyPage,
      expectedPasskeyResult,
      "discoverable assertion"
    );
    const discoverableMessages = await discoverablePasskeyPage.evaluate(
      () => globalThis.__vaultkernWebAuthnMessages ?? []
    );
    assertDiscoverableWebAuthnGetObservation(
      discoverableMessages,
      "discoverable assertion"
    );

    await sendCommand(extensionPage, { type: "lock_session" });
    await clearWebAuthnDebug(extensionPage);
    const lockedPasskeyRegisterPage = await context.newPage();
    const lockedRegisterUser = "locked-register-user@example.com";
    await lockedPasskeyRegisterPage.goto(
      `${server.passkeyRegisterUrl}?uv=required&user=${encodeURIComponent(lockedRegisterUser)}`
    );
    await lockedPasskeyRegisterPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    if (
      !(await lockedPasskeyRegisterPage.evaluate(
        () => document.querySelector("#vaultkern-passkey-register") != null
      ))
    ) {
      throw new Error("locked registration page did not expose the create button");
    }
    const lockedRegistrationUnlock = unlockPasskeyPromptWithPassword(
      context,
      extensionPage,
      lockedPasskeyRegisterPage,
      password,
      "locked registration"
    );
    await lockedPasskeyRegisterPage.click("#vaultkern-passkey-register");
    await lockedRegistrationUnlock;
    const lockedPasskeyRegisterResult = await waitForPasskeyRegisterResult(
      extensionPage,
      lockedPasskeyRegisterPage,
      "locked registration"
    );
    const lockedPasskeyCredentialId = lockedPasskeyRegisterResult.slice(
      "credential:".length
    );
    await expectWebAuthnDebugEvent(
      extensionPage,
      "unlock_user_verification_complete",
      { method: "master_password" },
      "locked registration"
    );

    await sendCommand(extensionPage, { type: "lock_session" });
    await clearWebAuthnDebug(extensionPage);
    const lockedPasskeyPage = await context.newPage();
    await lockedPasskeyPage.goto(
      `${server.passkeyUrl}?credential=${encodeURIComponent(lockedPasskeyCredentialId)}&uv=required`
    );
    await lockedPasskeyPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    if (
      !(await lockedPasskeyPage.evaluate(
        () => document.querySelector("#vaultkern-passkey-login") != null
      ))
    ) {
      throw new Error("locked passkey login page did not expose the login button");
    }
    const lockedAssertionUnlock = unlockPasskeyPromptWithPassword(
      context,
      extensionPage,
      lockedPasskeyPage,
      password,
      "locked assertion"
    );
    await lockedPasskeyPage.click("#vaultkern-passkey-login");
    await lockedAssertionUnlock;
    const lockedPasskeyResult = await waitForPasskeyLoginResult(
      extensionPage,
      lockedPasskeyPage,
      `credential:${lockedPasskeyCredentialId}`,
      "locked assertion"
    );
    await expectWebAuthnDebugEvent(
      extensionPage,
      "unlock_user_verification_complete",
      { method: "master_password" },
      "locked assertion"
    );

    const simpleWebAuthnPage = await context.newPage();
    await simpleWebAuthnPage.goto(simpleWebAuthnServer.origin);
    await simpleWebAuthnPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
      window.addEventListener("message", (event) => {
        if (event.data?.type === "vaultkern_webauthn_page_request") {
          globalThis.__vaultkernWebAuthnMessages.push(event.data);
        }
      });
    });
    const simpleRegistrationApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      simpleWebAuthnPage,
      "simplewebauthn registration"
    );
    await simpleWebAuthnPage.getByRole("button", { name: "Register Passkey" }).click();
    await simpleRegistrationApproval;
    const simpleRegistrationVerification = await waitForSimpleWebAuthnVerification(
      simpleWebAuthnPage,
      "registration"
    );

    const simpleAuthenticationApproval = approvePasskeyPrompt(
      context,
      extensionPage,
      simpleWebAuthnPage,
      "simplewebauthn authentication"
    );
    await simpleWebAuthnPage.locator("#login").click();
    await simpleAuthenticationApproval;
    const simpleAuthenticationVerification = await waitForSimpleWebAuthnVerification(
      simpleWebAuthnPage,
      "authentication"
    );
    const simpleDiscoverableAuthenticationApproval =
      approvePasskeyPromptAndSelectCredential(
        context,
        extensionPage,
        simpleWebAuthnPage,
        "simplewebauthn discoverable authentication",
        simpleRegistrationVerification.credentialId
      );
    await simpleWebAuthnPage.evaluate(() => {
      globalThis.__vaultkernWebAuthnMessages = [];
    });
    await simpleWebAuthnPage.locator("#login-discoverable").click();
    await simpleDiscoverableAuthenticationApproval;
    const simpleDiscoverableAuthenticationVerification =
      await waitForSimpleWebAuthnVerification(
        simpleWebAuthnPage,
        "discoverable authentication"
      );
    if (
      simpleDiscoverableAuthenticationVerification.userHandleMatchesExpected !== true
    ) {
      throw new Error(
        "discoverable SimpleWebAuthn authentication did not return the registered userHandle: " +
          JSON.stringify(simpleDiscoverableAuthenticationVerification)
      );
    }
    const simpleDiscoverableMessages = await simpleWebAuthnPage.evaluate(
      () => globalThis.__vaultkernWebAuthnMessages ?? []
    );
    assertDiscoverableWebAuthnGetObservation(
      simpleDiscoverableMessages,
      "discoverable SimpleWebAuthn authentication"
    );

    console.log(
      JSON.stringify(
        {
          ok: true,
          extensionId,
          nativeManifest,
          smokeUrl: server.url,
          noisyLoginUrl: server.noisyLoginUrl,
          totpUrl: server.totpUrl,
          passkeyRegisterUrl: server.passkeyRegisterUrl,
          passkeySmokeUrl: server.passkeyUrl,
          publicKeyCredentialAvailable: passkeySmokeReady.publicKeyCredentialAvailable,
          userVerifyingPlatformAuthenticatorAvailable:
            passkeyRegisterReady.userVerifyingPlatformAuthenticatorAvailable,
          passkeyRegisterResult,
          passkeyResult,
          storedPasskeyResult,
          discoverablePasskeyResult,
          simpleWebAuthnRegistrationVerified:
            simpleRegistrationVerification.verified === true,
          simpleWebAuthnAuthenticationVerified:
            simpleAuthenticationVerification.verified === true,
          simpleWebAuthnDiscoverableAuthenticationVerified:
            simpleDiscoverableAuthenticationVerification.verified === true,
          simpleWebAuthnDiscoverableUserHandle:
            simpleDiscoverableAuthenticationVerification.userHandle,
          lockedPasskeyRegisterResult,
          lockedPasskeyResult,
          submitResult: submitted,
          noisyLoginResult: noisyValues,
          totpResult: totpValue
        },
        null,
        2
      )
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await simpleWebAuthnServer?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

const CHROMIUM_CASE_REGISTRY = Object.freeze({
  "native-kdbx-totp-passkey": main,
  "exact-origin-automatic-authorization": runExactOriginAutomaticAuthorizationCase,
  "autofill-shadow-visibility": runAutofillShadowVisibilityCase,
  "dynamic-shadow-submit": runDynamicShadowSubmitCase,
  "nested-dynamic-shadow-submit": () => runDynamicShadowSubmitCase({ nested: true }),
  "trusted-spa-submit": runTrustedSpaSubmitCase,
  "controlled-react-input": runControlledReactInputCase,
  "large-dom-performance": runLargeDomPerformanceCase,
  "mv3-pending-session-reload": runMv3PendingSessionReloadCase,
  "autofill-native-crash-replay": runAutofillNativeCrashReplayCase
});

async function runChromiumCases(args) {
  const requestedCases = parseRequestedCases(args);
  const executedCases = [];
  for (const caseName of requestedCases) {
    const runCase = CHROMIUM_CASE_REGISTRY[caseName];
    if (typeof runCase !== "function") {
      throw new Error(`required Chromium case is not registered: ${caseName}`);
    }
    const startedAt = performance.now();
    await runCase();
    executedCases.push({
      name: caseName,
      durationMs: performance.now() - startedAt
    });
  }
  console.log(JSON.stringify({ ok: true, executedCases }));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runChromiumCases(process.argv.slice(2)).catch((error) => {
    if (String(error?.message ?? error).includes("Executable doesn't exist")) {
      console.error("Playwright Chromium is missing. Run: npx playwright install chromium");
    }
    console.error(error.stack ?? error.message ?? String(error));
    process.exit(1);
  });
}
