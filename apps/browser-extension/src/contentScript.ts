import { applyFillPlan } from "./autofill/applyFillPlan";
import { collectAutofillPageSnapshot } from "./autofill/collectPageFields";
import { createLoginFillPlan } from "./autofill/fillPlan";
import { collectAutofillSubmission } from "./autofill/savePrompt";

export function fillLoginForm(payload: {
  username?: string;
  password?: string;
  newPassword?: string;
  totp?: string;
}) {
  const snapshot = collectAutofillPageSnapshot(document);
  const fillPlan = createLoginFillPlan(snapshot, payload);
  applyFillPlan(fillPlan, document);
}

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const autofillSubmissionListenerRoots = new WeakSet<EventTarget>();
const dynamicShadowPatchKey = Symbol.for("vaultkern.autofill.dynamicShadowPatch");
const dynamicShadowInstallerKey = Symbol.for("vaultkern.autofill.dynamicShadowInstaller");

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: {
        type?: string;
        username?: string;
        password?: string;
        newPassword?: string;
        totp?: string;
      },
      _sender: unknown,
      _sendResponse: (response?: unknown) => void
    ) => {
      if (message.type !== "fill_entry_detail") {
        return false;
      }

      const hasUsername = typeof message.username === "string";
      const hasPassword = typeof message.password === "string";
      const hasNewPassword = typeof message.newPassword === "string";
      const hasTotp = typeof message.totp === "string";

      if (!hasUsername && !hasPassword && !hasNewPassword && !hasTotp) {
        return false;
      }

      fillLoginForm({
        username: hasUsername ? message.username : undefined,
        password: hasPassword ? message.password : undefined,
        newPassword: hasNewPassword ? message.newPassword : undefined,
        totp: hasTotp ? message.totp : undefined
      });

      return false;
    }
  );
}

function documentForAutofillSubmissionRoot(root: Document | ShadowRoot) {
  return root.nodeType === Node.DOCUMENT_NODE ? (root as Document) : root.ownerDocument;
}

function installAutofillSubmissionListener(root: Document | ShadowRoot) {
  if (autofillSubmissionListenerRoots.has(root)) {
    return;
  }
  autofillSubmissionListenerRoots.add(root);
  root.addEventListener(
    "submit",
    (event) => {
      const submittedForm =
        event.target instanceof HTMLFormElement ? event.target : undefined;
      const submission = collectAutofillSubmission(
        documentForAutofillSubmissionRoot(root),
        submittedForm,
        {
          includeLoginSubmissions: false
        }
      );
      queueMicrotask(() => {
        if (event.defaultPrevented) {
          return;
        }
        if (!submission) {
          return;
        }
        void chromeApi.runtime.sendMessage({
          type: "vaultkern_autofill_submission",
          ...submission
        });
      });
    },
    { capture: true }
  );

  root.querySelectorAll("*").forEach((element) => {
    if (element.shadowRoot) {
      installAutofillSubmissionListener(element.shadowRoot);
    }
  });
}

function installDynamicShadowRootAutofillListener() {
  if (typeof Element === "undefined" || typeof Element.prototype.attachShadow !== "function") {
    return;
  }

  (globalThis as typeof globalThis & {
    [dynamicShadowInstallerKey]?: (root: ShadowRoot) => void;
  })[dynamicShadowInstallerKey] = installAutofillSubmissionListener;

  const elementPrototype = Element.prototype as typeof Element.prototype & {
    [dynamicShadowPatchKey]?: true;
  };
  if (elementPrototype[dynamicShadowPatchKey]) {
    return;
  }

  const attachShadow = Element.prototype.attachShadow;
  Object.defineProperty(elementPrototype, dynamicShadowPatchKey, {
    configurable: false,
    enumerable: false,
    value: true
  });
  elementPrototype.attachShadow = function attachShadowWithAutofillListener(
    init: ShadowRootInit
  ) {
    const shadowRoot = attachShadow.call(this, init);
    (globalThis as typeof globalThis & {
      [dynamicShadowInstallerKey]?: (root: ShadowRoot) => void;
    })[dynamicShadowInstallerKey]?.(shadowRoot);
    return shadowRoot;
  };
}

if (chromeApi?.runtime?.sendMessage && typeof document !== "undefined") {
  installDynamicShadowRootAutofillListener();
  installAutofillSubmissionListener(document);
}
