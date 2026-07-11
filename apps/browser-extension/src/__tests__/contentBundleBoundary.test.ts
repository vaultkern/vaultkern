// @vitest-environment node

import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { minify } from "terser";
import { describe, expect, it } from "vitest";

import viteConfig from "../../vite.config";

const extensionRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../.."
);
const sourceRoot = join(extensionRoot, "src");

function fakeContentChunk(code: string, additionalModuleId: string) {
  return {
    type: "chunk",
    fileName: "contentScript.js",
    name: "contentScript",
    code,
    isEntry: true,
    imports: [],
    dynamicImports: [],
    facadeModuleId: join(sourceRoot, "contentScript.ts"),
    modules: {
      [join(sourceRoot, "contentScript.ts")]: {},
      [join(sourceRoot, "autofill/savePrompt.ts")]: {},
      [additionalModuleId]: {}
    }
  };
}

async function runConfiguredOutputPlugins(bundle: Record<string, any>) {
  const plugins = ((viteConfig as any).plugins ?? []).flat(Infinity);
  for (const plugin of plugins) {
    const hook = plugin?.generateBundle;
    const handler = typeof hook === "function" ? hook : hook?.handler;
    if (handler) {
      await handler.call({}, {}, bundle, false);
    }
  }
}

async function optimizeFakeContent(
  code: string,
  additionalModuleId = "\0virtual:wire-probe"
) {
  const result = await minify(code, (viteConfig as any).build.terserOptions);
  const bundle = {
    "contentScript.js": fakeContentChunk(result.code!, additionalModuleId)
  };
  await runConfiguredOutputPlugins(bundle);
  return bundle["contentScript.js"].code;
}

async function deliveredMessages(
  source: string,
  additionalModuleId?: string
) {
  const delivered: Array<Record<string, unknown>> = [];
  const code = await optimizeFakeContent(source, additionalModuleId);
  runInNewContext(code, {
    chrome: {
      runtime: {
        sendMessage(payload: Record<string, unknown>) {
          delivered.push(payload);
        }
      }
    }
  });
  return delivered;
}

function reviewedMessage(source: string) {
  return `
    const reviewedSubmission = {};
    chrome.runtime.sendMessage({
      type: "vaultkern_autofill_submission",
      ...reviewedSubmission
    });
    ${source}
  `;
}

describe("content bundle boundary", () => {
  it("uses normal Terser minification without property mangling", () => {
    const build = (viteConfig as any).build;
    const pluginNames = ((viteConfig as any).plugins ?? [])
      .flat(Infinity)
      .map((plugin: { name?: string }) => plugin?.name);

    expect(build.minify).toBe("terser");
    expect(build.terserOptions).toEqual({ compress: { passes: 3 } });
    expect(pluginNames).not.toContain(
      "vaultkern-content-script-property-mangle"
    );
  });

  it("preserves property names across independently minified chunks", async () => {
    const terserOptions = (viteConfig as any).build.terserOptions;
    const first = await minify(
      'globalThis.first={opid:"opid",qualifiedAs:"qualifiedAs"};',
      terserOptions
    );
    const second = await minify(
      'globalThis.second={qualifiedAs:"qualifiedAs",opid:"opid"};',
      terserOptions
    );
    const sandbox: Record<string, Record<string, string>> = {};
    runInNewContext(first.code!, sandbox);
    runInNewContext(second.code!, sandbox);

    expect(sandbox.first).toEqual({
      opid: "opid",
      qualifiedAs: "qualifiedAs"
    });
    expect(sandbox.second).toEqual({
      qualifiedAs: "qualifiedAs",
      opid: "opid"
    });
  });

  it.each([
    [
      "destructuring",
      'const {sendMessage: transmit} = chrome.runtime; transmit({opid:"leak"});'
    ],
    [
      "bind",
      'const transmit = chrome.runtime.sendMessage.bind(chrome.runtime); transmit({opid:"leak"});'
    ],
    [
      "Reflect.apply",
      'Reflect.apply(chrome.runtime.sendMessage, chrome.runtime, [{opid:"leak"}]);'
    ],
    [
      "reassignment",
      'let transmit; transmit = chrome.runtime.sendMessage; transmit({opid:"leak"});'
    ]
  ])("never rewrites wire keys behind a %s sink alias", async (_name, sink) => {
    const delivered = await deliveredMessages(reviewedMessage(sink));

    expect(delivered.at(-1)).toEqual({ opid: "leak" });
  });

  it.each([
    [
      "shadowed producer",
      'function collectAutofillSubmission(){return new Proxy({opid:"leak"},{});} const submission=collectAutofillSubmission();',
      "\0virtual:shadowed-producer"
    ],
    [
      "virtual producer",
      'const submission = new Proxy({opid:"leak"}, {});',
      "\0virtual:producer"
    ],
    [
      "node_modules producer",
      'function packageProducer(){return {opid:"leak"};} const submission=packageProducer();',
      "/extension/node_modules/unreviewed-producer/index.js"
    ]
  ])(
    "never rewrites wire keys from a %s",
    async (_name, producer, moduleId) => {
      const delivered = await deliveredMessages(
        `${producer}
         chrome.runtime.sendMessage({
           type: "vaultkern_autofill_submission",
           ...submission
         });`,
        moduleId
      );

      expect(delivered).toEqual([
        {
          type: "vaultkern_autofill_submission",
          opid: "leak"
        }
      ]);
    }
  );
});
