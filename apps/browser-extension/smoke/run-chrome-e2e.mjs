#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createReadStream, existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import playwright from "playwright";

import { E2E_EXTENSION_ID } from "../scripts/manifestBuild.mjs";
import { SMOKE_HOST, smokeUrl } from "./smokeUrls.mjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const extensionRoot = resolve(__dirname, "..");
const repoRoot = resolve(extensionRoot, "../..");
const extensionPath = join(extensionRoot, "dist");
const runtimePath = join(repoRoot, "target/debug/vaultkern-runtime");
const vkdbxArgs = ["run", "-p", "vkdbx", "--", "roundtrip-demo"];
const password = "smoke-password";
const username = "smoke-user@example.com";
const entryPassword = "smoke-secret";

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

export async function startSmokeServer() {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${SMOKE_HOST}`);
    const name = basename(url.pathname === "/" ? "basic-login.html" : url.pathname);
    const file = join(__dirname, name);

    if (!existsSync(file)) {
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
    url: smokeUrl(address.port, "basic-login.html"),
    passkeyRegisterUrl: smokeUrl(address.port, "passkey-register.html"),
    passkeyUrl: smokeUrl(address.port, "passkey-login.html"),
    close: () => new Promise((resolvePromise) => server.close(resolvePromise))
  };
}

async function writeNativeManifest(workDir) {
  const profileHostDir = join(workDir, "profile", "NativeMessagingHosts");
  await mkdir(profileHostDir, { recursive: true });
  const origin = `chrome-extension://${E2E_EXTENSION_ID}/`;
  const manifest = run(
    runtimePath,
    ["--print-native-host-manifest", runtimePath, origin],
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
        vaultkernExtensionSettings: settings
      });
    },
    {
      recentVaultLimit: 10,
      language: "en",
      idleLockMinutes: 10,
      clearClipboardSeconds: 30,
      passkeyProviderEnabled: true
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

async function approvePasskeyPrompt(context) {
  const prompt = await context.waitForEvent("page", { timeout: 15_000 });
  await prompt.waitForLoadState("domcontentloaded");
  await prompt.getByRole("button", { name: "Continue passkey request" }).click();
  await prompt.waitForEvent("close", { timeout: 5_000 }).catch(() => {});
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

  try {
    run("cargo", [...vkdbxArgs, vaultPath, password]);
    server = await startSmokeServer();
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
    await extensionPage.evaluate(
      async ({ serverUrl, username, entryPassword }) => {
        const tabs = await chrome.tabs.query({ url: serverUrl });
        if (!tabs[0]?.id) {
          throw new Error("smoke tab not found");
        }
        await chrome.tabs.sendMessage(tabs[0].id, {
          type: "fill_entry_detail",
          username,
          password: entryPassword
        });
      },
      { serverUrl: server.url, username, entryPassword }
    );

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
    const passkeyRegisterReady = await passkeyRegisterPage.evaluate(() => ({
      hasButton: document.querySelector("#vaultkern-passkey-register") != null,
      publicKeyCredentialAvailable: typeof PublicKeyCredential !== "undefined",
      hookInstalled: Boolean(
        navigator.credentials?.__vaultkernWebAuthnHookInstalled
      ),
      createSource: String(navigator.credentials?.create).slice(0, 200)
    }));
    if (!passkeyRegisterReady.hasButton) {
      throw new Error("passkey register smoke page did not expose the create button");
    }
    const passkeyRegistrationApproval = approvePasskeyPrompt(context);
    await passkeyRegisterPage.click("#vaultkern-passkey-register");
    await passkeyRegistrationApproval;
    await passkeyRegisterPage.waitForFunction(
      () => document.querySelector("#vaultkern-passkey-register-result")?.value
    );
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
        `unexpected passkey register result: ${passkeyRegisterResult}\n` +
          `WebAuthn debug: ${JSON.stringify(webAuthnDebug, null, 2)}\n` +
          `Page probe: ${JSON.stringify(pageProbe, null, 2)}`
      );
    }
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
    const passkeyApproval = approvePasskeyPrompt(context);
    await passkeyPage.click("#vaultkern-passkey-login");
    await passkeyApproval;
    await passkeyPage.waitForFunction(
      () => document.querySelector("#vaultkern-passkey-result")?.value
    );
    const passkeyResult = await passkeyPage
      .locator("#vaultkern-passkey-result")
      .evaluate((node) => node.value || node.textContent);
    const expectedPasskeyResult = `credential:${registeredPasskeyCredentialId}`;
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
        `unexpected passkey result: ${passkeyResult}\n` +
          `WebAuthn debug: ${JSON.stringify(webAuthnDebug, null, 2)}\n` +
          `Page probe: ${JSON.stringify(pageProbe, null, 2)}`
      );
    }

    console.log(
      JSON.stringify(
        {
          ok: true,
          extensionId,
          nativeManifest,
          smokeUrl: server.url,
          passkeyRegisterUrl: server.passkeyRegisterUrl,
          passkeySmokeUrl: server.passkeyUrl,
          publicKeyCredentialAvailable: passkeySmokeReady.publicKeyCredentialAvailable,
          passkeyRegisterResult,
          passkeyResult,
          submitResult: submitted
        },
        null,
        2
      )
    );
  } finally {
    await context?.close().catch(() => {});
    await server?.close().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    if (String(error?.message ?? error).includes("Executable doesn't exist")) {
      console.error("Playwright Chromium is missing. Run: npx playwright install chromium");
    }
    console.error(error.stack ?? error.message ?? String(error));
    process.exit(1);
  });
}
