import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import { Script } from "node:vm";
import { pathToFileURL } from "node:url";
import ts from "typescript";

export const CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES = 60 * 1024;

function countModuleImports(source, filename) {
  const sourceFile = ts.createSourceFile(
    filename,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS
  );
  let imports = 0;
  const visit = (node) => {
    if (node.kind === ts.SyntaxKind.ImportKeyword) {
      imports += 1;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return imports;
}

export function assertClassicContentScript(source, filename = "contentScript.js") {
  if (source.includes("__vaultkernAllowSyntheticAutofillSubmitForTests")) {
    throw new Error(
      `${filename} must not expose the synthetic autofill submit test bypass`
    );
  }
  try {
    new Script(source, { filename });
  } catch (error) {
    throw new Error(
      `${filename} must be a standalone classic script: ${error.message}`,
      { cause: error }
    );
  }

  const imports = countModuleImports(source, filename);
  if (imports > 0) {
    throw new Error(
      `${filename} must not import additional chunks (${imports} import found)`
    );
  }

  const bytes = Buffer.byteLength(source, "utf8");
  if (bytes > CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES) {
    throw new Error(
      `${filename} is ${bytes} bytes and exceeds the ${CLASSIC_CONTENT_SCRIPT_BUDGET_BYTES}-byte budget`
    );
  }

  return { bytes, imports };
}

export async function verifyClassicContentScript(path = "dist/contentScript.js") {
  return assertClassicContentScript(await readFile(path, "utf8"), path);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  verifyClassicContentScript()
    .then(({ bytes, imports }) => {
      console.log(
        `dist/contentScript.js: ${bytes} bytes, ${imports} imports, classic script`
      );
    })
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
