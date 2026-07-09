import { applyFillPlan } from "./autofill/applyFillPlan";
import { collectAutofillPageSnapshot } from "./autofill/collectPageFields";
import { createLoginFillPlan } from "./autofill/fillPlan";
import type { AutofillTrigger, CreateLoginFillPlanOptions } from "./autofill/fillPlan";
import { collectAutofillSubmission } from "./autofill/savePrompt";

export function fillLoginForm(
  payload: {
    username?: string;
    password?: string;
    newPassword?: string;
    totp?: string;
  },
  options: CreateLoginFillPlanOptions = {}
) {
  const snapshot = collectAutofillPageSnapshot(document);
  const fillPlan = createLoginFillPlan(snapshot, payload, options);
  applyFillPlan(fillPlan, document);
}

function triggerFromFillMessage(trigger: unknown): AutofillTrigger {
  return trigger === "pageLoad" || trigger === "unlockContinuation" ? trigger : "manual";
}

function normalizedHttpPageUrl(value: unknown) {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

function fillTargetMatchesCurrentPage(targetUrl: unknown) {
  const expectedUrl = normalizedHttpPageUrl(targetUrl);
  const currentUrl = normalizedHttpPageUrl(window.location.href);
  return expectedUrl !== null && expectedUrl === currentUrl;
}

function pageLoadDocumentIsVisible() {
  return document.visibilityState === "visible";
}

const chromeApi = (globalThis as typeof globalThis & { chrome?: any }).chrome;
const autofillSubmissionListenerRoots = new WeakSet<EventTarget>();
const openShadowRootDiscoveryRoots = new WeakSet<Document | ShadowRoot>();
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
        trigger?: unknown;
        allowAutomaticSecretFill?: unknown;
        targetUrl?: unknown;
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

      const trigger = triggerFromFillMessage(message.trigger);
      if (!fillTargetMatchesCurrentPage(message.targetUrl)) {
        return false;
      }
      if (!pageLoadDocumentIsVisible()) {
        return false;
      }

      fillLoginForm(
        {
          username: hasUsername ? message.username : undefined,
          password: hasPassword ? message.password : undefined,
          newPassword: hasNewPassword ? message.newPassword : undefined,
          totp: hasTotp ? message.totp : undefined
        },
        {
          trigger,
          allowAutomaticSecretFill: message.allowAutomaticSecretFill === true
        }
      );

      return false;
    }
  );
}

function documentForAutofillSubmissionRoot(root: Document | ShadowRoot) {
  return root.nodeType === Node.DOCUMENT_NODE
    ? (root as Document)
    : root.ownerDocument ?? undefined;
}

function allowSyntheticAutofillSubmitForTests() {
  return (
    (globalThis as typeof globalThis & {
      __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
    }).__vaultkernAllowSyntheticAutofillSubmitForTests === true
  );
}

function shouldCaptureAutofillSubmit(event: Event) {
  return event.isTrusted || allowSyntheticAutofillSubmitForTests();
}

function installOpenShadowRoot(root: ShadowRoot) {
  installAutofillSubmissionListener(root);
}

function installOpenShadowRootsFromElement(element: Element) {
  if (element.shadowRoot) {
    installOpenShadowRoot(element.shadowRoot);
  }
  element.querySelectorAll("*").forEach((descendant) => {
    if (descendant.shadowRoot) {
      installOpenShadowRoot(descendant.shadowRoot);
    }
  });
}

function installOpenShadowRootAutofillListeners(root: Document | ShadowRoot) {
  root.querySelectorAll("*").forEach((element) => {
    installOpenShadowRootsFromElement(element);
  });
}

function discoverOpenShadowRootsFromEvent(event: Event) {
  const path = typeof event.composedPath === "function" ? event.composedPath() : [];
  for (const target of path) {
    if (typeof ShadowRoot !== "undefined" && target instanceof ShadowRoot) {
      installOpenShadowRoot(target);
    } else if (target instanceof Element) {
      installOpenShadowRootsFromElement(target);
    }
  }
}

function installOpenShadowRootDiscovery(root: Document | ShadowRoot) {
  if (openShadowRootDiscoveryRoots.has(root)) {
    return;
  }
  openShadowRootDiscoveryRoots.add(root);

  for (const eventType of ["click", "focusin", "input", "keydown"]) {
    root.addEventListener(eventType, discoverOpenShadowRootsFromEvent, { capture: true });
  }

  if (typeof MutationObserver === "function") {
    new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node instanceof Element) {
            installOpenShadowRootsFromElement(node);
          }
        });
      }
    }).observe(root, { childList: true, subtree: true });
  }
}

function installAutofillSubmissionListener(root: Document | ShadowRoot) {
  if (autofillSubmissionListenerRoots.has(root)) {
    return;
  }
  autofillSubmissionListenerRoots.add(root);
  root.addEventListener(
    "submit",
    (event) => {
      if (!shouldCaptureAutofillSubmit(event)) {
        return;
      }
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

  installOpenShadowRootAutofillListeners(root);
  installOpenShadowRootDiscovery(root);
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
