import { applyFillPlan } from "./autofill/applyFillPlan";
import { collectAutofillPageSnapshot } from "./autofill/collectPageFields";
import { createLoginFillPlan } from "./autofill/fillPlan";
import { proveVisualVisibility } from "./autofill/renderFacts";
import {
  acceptDeliveredFillCapability,
  type FillCapability
} from "./autofill/fillAuthorization";
import { collectAutofillSubmission } from "./autofill/savePrompt";

export function fillLoginForm(
  payload: {
    username?: string;
    password?: string;
    newPassword?: string;
    totp?: string;
  },
  authorization: FillCapability | unknown
) {
  const snapshot = collectAutofillPageSnapshot(document);
  const fillPlan = createLoginFillPlan(snapshot, payload, authorization);
  applyFillPlan(fillPlan, document);
}

function fillDeliveredLoginForm(
  payload: Parameters<typeof fillLoginForm>[0],
  capability: FillCapability
): void | Promise<void> {
  const ownerWindow = document.defaultView;
  if (ownerWindow === null) {
    return;
  }
  const fillPlan = createLoginFillPlan(
    collectAutofillPageSnapshot(document),
    payload,
    capability
  );
  const targets = fillPlan.ac.map(({ t: target }) =>
    target instanceof ownerWindow.HTMLElement ? target : null
  );
  if (targets.some((target) => target === null)) {
    return;
  }
  const applyIfVisible = (visible: boolean) => {
    if (
      visible &&
      fillTargetMatchesCurrentPage(capability.targetUrl) &&
      pageLoadDocumentIsVisible()
    ) {
      applyFillPlan(fillPlan, document);
    }
  };
  const proof = proveVisualVisibility(targets as HTMLElement[]);
  if (typeof proof === "boolean") {
    applyIfVisible(proof);
    return;
  }
  if (capability.kind !== "automatic") {
    return proof.then(applyIfVisible);
  }
  let changed = false;
  const observer = new MutationObserver(() => {
    changed = true;
  });
  observer.observe(document, {
    attributes: true,
    characterData: true,
    childList: true,
    subtree: true
  });
  return proof.then(
    (visible) => {
      const unchanged = !changed && observer.takeRecords().length === 0;
      observer.disconnect();
      if (unchanged) {
        applyIfVisible(visible);
      }
    },
    () => observer.disconnect()
  );
}

function normalizedHttpPageUrl(value: unknown) {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed = new URL(value);
    return /^https?:$/.test(parsed.protocol) ? parsed.href : null;
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
const OPEN_SHADOW_ROOT_EVENT = "vaultkern:autofill:open-shadow-root";
let autofillSubmitIntent:
  | [HTMLFormElement, HTMLButtonElement | HTMLInputElement | null]
  | undefined;

if (chromeApi?.runtime?.onMessage) {
  chromeApi.runtime.onMessage.addListener(
    (
      message: {
        type?: string;
        username?: string;
        password?: string;
        newPassword?: string;
        totp?: string;
        fillCapability?: unknown;
        targetUrl?: unknown;
      },
      _sender: unknown,
      sendResponse: (response?: unknown) => void
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

      if (!fillTargetMatchesCurrentPage(message.targetUrl)) {
        return false;
      }
      if (!pageLoadDocumentIsVisible()) {
        return false;
      }

      const targetUrl = normalizedHttpPageUrl(message.targetUrl);
      if (targetUrl === null) {
        return false;
      }
      const capability = acceptDeliveredFillCapability(
        message.fillCapability,
        targetUrl
      );
      if (capability === null) {
        return false;
      }

      const pending = fillDeliveredLoginForm(
        {
          username: hasUsername ? message.username : undefined,
          password: hasPassword ? message.password : undefined,
          newPassword: hasNewPassword ? message.newPassword : undefined,
          totp: hasTotp ? message.totp : undefined
        },
        capability
      );
      if (!pending) {
        return false;
      }
      void pending.then(
        () => sendResponse(),
        () => sendResponse()
      );
      return true;
    }
  );
}

function allowSyntheticAutofillSubmitForTests() {
  return (
    import.meta.env.MODE === "test" &&
    (globalThis as typeof globalThis & {
      __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
    }).__vaultkernAllowSyntheticAutofillSubmitForTests === true
  );
}

function rememberAutofillSubmitIntentFromEvent(
  event: Event,
  path: EventTarget[]
) {
  if (!event.isTrusted && !allowSyntheticAutofillSubmitForTests()) {
    return;
  }
  let form: HTMLFormElement | null = null;
  let submitter: HTMLButtonElement | HTMLInputElement | null = null;
  if (event.type === "click") {
    submitter =
      (path.find(
        (target) =>
          (target instanceof HTMLButtonElement && target.type === "submit") ||
          (target instanceof HTMLInputElement &&
            (target.type === "submit" || target.type === "image"))
      ) as HTMLButtonElement | HTMLInputElement | undefined) ?? null;
    if (submitter && !submitter.disabled) {
      form = submitter.form;
    }
  } else {
    const input = path[0];
    if (
      input instanceof HTMLInputElement &&
      !input.disabled &&
      (event as KeyboardEvent).key === "Enter" &&
      !(event as KeyboardEvent).isComposing &&
      !(event as KeyboardEvent).ctrlKey &&
      !(event as KeyboardEvent).altKey &&
      !(event as KeyboardEvent).metaKey &&
      /^(email|number|password|search|tel|text|url)$/.test(input.type)
    ) {
      form = input.form;
    }
  }
  if (form) {
    const intent: typeof autofillSubmitIntent = [form, submitter];
    autofillSubmitIntent = intent;
    setTimeout(() => {
      if (autofillSubmitIntent === intent) {
        autofillSubmitIntent = undefined;
      }
    });
  }
}

function discoverOpenShadowRootsFromEvent(event: Event) {
  const path = event.composedPath();
  rememberAutofillSubmitIntentFromEvent(event, path);
  for (const target of path) {
    if (target instanceof ShadowRoot) {
      installAutofillSubmissionListener(target);
    }
  }
}

function discoverOpenShadowRootFromPageHook(event: Event) {
  event.stopImmediatePropagation();
  const shadowRoot = (event.target as Element | null)?.shadowRoot;
  if (shadowRoot) {
    installAutofillSubmissionListener(shadowRoot);
  }
}

function installOpenShadowRootDiscovery(root: Document | ShadowRoot) {
  if (root.nodeType === Node.DOCUMENT_NODE) {
    const ownerDocument = root as Document;
    const ownerWindow = ownerDocument.defaultView;
    if (ownerWindow) {
      ownerWindow.addEventListener(
        OPEN_SHADOW_ROOT_EVENT,
        discoverOpenShadowRootFromPageHook,
        true
      );
      ownerWindow.addEventListener("click", discoverOpenShadowRootsFromEvent, true);
      ownerWindow.addEventListener("keydown", discoverOpenShadowRootsFromEvent, true);
    }
  }
}

function installAutofillSubmissionListener(root: Document | ShadowRoot) {
  if (autofillSubmissionListenerRoots.has(root)) {
    return;
  }
  autofillSubmissionListenerRoots.add(root);
  const submitTarget = (root as Document).defaultView ?? root;
  submitTarget.addEventListener(
    "submit",
    (event) => {
      const submittedForm =
        (event.target as Element | null)?.localName === "form"
          ? (event.target as HTMLFormElement)
          : undefined;
      if (!submittedForm) {
        return;
      }
      const intent = autofillSubmitIntent;
      const matchesIntent =
        intent?.[0] === submittedForm &&
        (event as SubmitEvent).submitter === intent![1];
      if (matchesIntent) {
        autofillSubmitIntent = undefined;
      } else if (!allowSyntheticAutofillSubmitForTests()) {
        return;
      }
      const submission = collectAutofillSubmission(
        root.ownerDocument ?? (root as Document),
        submittedForm,
        {
          ils: "with-username"
        }
      );
      queueMicrotask(() => {
        if (!submission) {
          return;
        }
        void chromeApi.runtime.sendMessage({
          type: "vaultkern_autofill_submission",
          ...submission
        });
      });
    },
    true
  );

  installOpenShadowRootDiscovery(root);
}

if (chromeApi?.runtime?.sendMessage && typeof document !== "undefined") {
  installAutofillSubmissionListener(document);
}
