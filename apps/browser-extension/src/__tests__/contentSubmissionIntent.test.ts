import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { useDomRenderEnvironment } from "../autofill/__tests__/renderEnvironment";

useDomRenderEnvironment();

const sendMessage = vi.fn(async () => undefined);
const addListener = vi.fn();

function dispatchTrusted(target: EventTarget, event: Event) {
  const testGlobal = globalThis as typeof globalThis & {
    __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
  };
  testGlobal.__vaultkernAllowSyntheticAutofillSubmitForTests = true;
  document.addEventListener(
    event.type,
    () => delete testGlobal.__vaultkernAllowSyntheticAutofillSubmitForTests,
    { capture: true, once: true }
  );
  try {
    target.dispatchEvent(event);
  } finally {
    delete testGlobal.__vaultkernAllowSyntheticAutofillSubmitForTests;
  }
}

function loginFormMarkup(buttons = '<button id="submit" type="submit">Sign in</button>') {
  document.body.innerHTML = `
    <form id="login">
      <input id="username" name="email" type="email" autocomplete="username" value="alice@example.com" />
      <input id="password" name="password" type="password" autocomplete="current-password" value="captured-secret" />
      ${buttons}
    </form>
  `;
  const form = document.querySelector("#login") as HTMLFormElement;
  form.addEventListener("submit", (event) => event.preventDefault());
  return form;
}

async function flushSubmissionQueue() {
  await Promise.resolve();
  await Promise.resolve();
}

describe("content-script submission intent", () => {
  beforeAll(async () => {
    const addDocumentEventListener = vi.spyOn(document, "addEventListener");
    const addWindowEventListener = vi.spyOn(window, "addEventListener");
    const queryDocument = vi.spyOn(Document.prototype, "querySelectorAll");
    (globalThis as typeof globalThis & { chrome?: unknown }).chrome = {
      runtime: {
        onMessage: { addListener },
        sendMessage
      }
    };
    vi.resetModules();
    await import("../contentScript");
    expect(addListener).toHaveBeenCalledTimes(1);
    expect(addWindowEventListener.mock.calls.some(([type]) => type === "click")).toBe(true);
    expect(addWindowEventListener.mock.calls.some(([type]) => type === "keydown")).toBe(true);
    expect(addWindowEventListener.mock.calls.some(([type]) => type === "submit")).toBe(true);
    expect(addDocumentEventListener.mock.calls.some(([type]) => type === "submit")).toBe(false);
    expect(
      queryDocument.mock.calls.some(([selector]) => selector === "*")
    ).toBe(false);
    addDocumentEventListener.mockRestore();
    addWindowEventListener.mockRestore();
    queryDocument.mockRestore();
  });

  beforeEach(() => {
    document.body.innerHTML = "";
    sendMessage.mockClear();
    delete (globalThis as typeof globalThis & {
      __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
    }).__vaultkernAllowSyntheticAutofillSubmitForTests;
  });

  afterEach(async () => {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 0));
  });

  afterAll(() => {
    delete (globalThis as typeof globalThis & { chrome?: unknown }).chrome;
  });

  it("rejects requestSubmit and HTMLElement.click without trusted user intent", async () => {
    const form = loginFormMarkup();
    const submitter = document.querySelector("#submit") as HTMLButtonElement;

    form.requestSubmit(submitter);
    submitter.click();
    await flushSubmissionQueue();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("accepts one submit from the exact trusted submit control", async () => {
    const form = loginFormMarkup();
    const submitter = document.querySelector("#submit") as HTMLButtonElement;
    let observedClick: MouseEvent | undefined;
    let observedSubmit: SubmitEvent | undefined;
    document.addEventListener("click", (event) => observedClick = event as MouseEvent, {
      capture: true,
      once: true
    });
    form.addEventListener("submit", (event) => observedSubmit = event as SubmitEvent, {
      once: true
    });

    dispatchTrusted(
      submitter,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(observedClick).toBeInstanceOf(MouseEvent);
    expect(observedSubmit?.submitter).toBe(submitter);
    expect(sendMessage).toHaveBeenCalledTimes(1);
    sendMessage.mockClear();
    form.requestSubmit(submitter);
    await flushSubmissionQueue();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("captures credentials before page window handlers rewrite the submitted form", async () => {
    loginFormMarkup();
    const submitter = document.querySelector("#submit") as HTMLButtonElement;
    window.addEventListener(
      "submit",
      () => {
        (document.querySelector("#username") as HTMLInputElement).value =
          "rewritten@example.com";
        (document.querySelector("#password") as HTMLInputElement).value =
          "rewritten-secret";
      },
      { capture: true, once: true }
    );

    dispatchTrusted(
      submitter,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        username: "alice@example.com",
        password: "captured-secret"
      })
    );
  });

  it("rejects a different submitter after a trusted submit-control click", async () => {
    const form = loginFormMarkup(`
      <button id="clicked" type="submit">Clicked</button>
      <button id="hijacked" type="submit">Hijacked</button>
    `);
    const clicked = document.querySelector("#clicked") as HTMLButtonElement;
    const hijacked = document.querySelector("#hijacked") as HTMLButtonElement;
    clicked.addEventListener("click", (event) => {
      event.preventDefault();
      form.requestSubmit(hijacked);
    });

    dispatchTrusted(
      clicked,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("keeps the exact intent after rejecting another submitter in the same form", async () => {
    const form = loginFormMarkup(`
      <button id="clicked" type="submit">Clicked</button>
      <button id="hijacked" type="submit">Hijacked</button>
    `);
    const password = document.querySelector("#password") as HTMLInputElement;
    const clicked = document.querySelector("#clicked") as HTMLButtonElement;
    const hijacked = document.querySelector("#hijacked") as HTMLButtonElement;
    clicked.addEventListener("click", () => {
      password.value = "hijacked-secret";
      form.requestSubmit(hijacked);
      password.value = "captured-secret";
    });

    dispatchTrusted(
      clicked,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ password: "captured-secret" })
    );
  });

  it("rejects a cross-form submit after a trusted submit-control click", async () => {
    const sourceForm = loginFormMarkup('<button id="source" type="submit">Source</button>');
    document.body.insertAdjacentHTML(
      "beforeend",
      `<form id="other">
        <input name="email" type="email" autocomplete="username" value="other@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="other-secret" />
        <button id="other-submit" type="submit">Other</button>
      </form>`
    );
    const source = document.querySelector("#source") as HTMLButtonElement;
    const otherForm = document.querySelector("#other") as HTMLFormElement;
    const otherSubmitter = document.querySelector("#other-submit") as HTMLButtonElement;
    otherForm.addEventListener("submit", (event) => event.preventDefault());
    source.addEventListener("click", (event) => {
      event.preventDefault();
      otherForm.requestSubmit(otherSubmitter);
    });

    dispatchTrusted(
      source,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sourceForm).not.toBe(otherForm);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("keeps the exact intent after rejecting a cross-form submit", async () => {
    const sourceForm = loginFormMarkup('<button id="source" type="submit">Source</button>');
    document.body.insertAdjacentHTML(
      "beforeend",
      `<form id="other">
        <input name="email" type="email" autocomplete="username" value="other@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="other-secret" />
        <button id="other-submit" type="submit">Other</button>
      </form>`
    );
    const source = document.querySelector("#source") as HTMLButtonElement;
    const otherForm = document.querySelector("#other") as HTMLFormElement;
    const otherSubmitter = document.querySelector("#other-submit") as HTMLButtonElement;
    otherForm.addEventListener("submit", (event) => event.preventDefault());
    source.addEventListener("click", () => otherForm.requestSubmit(otherSubmitter));

    dispatchTrusted(
      source,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sourceForm).not.toBe(otherForm);
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ password: "captured-secret" })
    );
  });

  it("rejects requestSubmit caused by a trusted non-submit button", async () => {
    const form = loginFormMarkup(`
      <button id="ordinary" type="button">Ordinary</button>
      <button id="submit" type="submit">Submit</button>
    `);
    const ordinary = document.querySelector("#ordinary") as HTMLButtonElement;
    const submitter = document.querySelector("#submit") as HTMLButtonElement;
    ordinary.addEventListener("click", () => form.requestSubmit(submitter));

    dispatchTrusted(
      ordinary,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("accepts Enter from a submittable input only in its current task", async () => {
    const form = loginFormMarkup("");
    const input = document.querySelector("#password") as HTMLInputElement;

    dispatchTrusted(
      input,
      new KeyboardEvent("keydown", {
        key: "Enter",
        bubbles: true,
        cancelable: true,
        composed: true
      })
    );
    form.requestSubmit();
    await flushSubmissionQueue();
    expect(sendMessage).toHaveBeenCalledTimes(1);

    sendMessage.mockClear();
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 0));
    form.requestSubmit();
    await flushSubmissionQueue();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("rejects a scripted submit attached to a modified Enter shortcut", async () => {
    const form = loginFormMarkup();
    const input = document.querySelector("#password") as HTMLInputElement;
    input.addEventListener("keydown", () => form.requestSubmit());

    dispatchTrusted(
      input,
      new KeyboardEvent("keydown", {
        key: "Enter",
        ctrlKey: true,
        bubbles: true,
        cancelable: true,
        composed: true
      })
    );
    await flushSubmissionQueue();

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("discovers a dynamically attached open shadow root from user intent", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = `
      <form>
        <input name="email" type="email" autocomplete="username" value="shadow@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="shadow-secret" />
        <button type="submit">Sign in</button>
      </form>
    `;
    root.querySelector("form")?.addEventListener("submit", (event) => {
      event.preventDefault();
    });
    const submitter = root.querySelector("button") as HTMLButtonElement;

    dispatchTrusted(
      submitter,
      new MouseEvent("click", { bubbles: true, cancelable: true, composed: true })
    );
    await flushSubmissionQueue();

    expect(root.host).toBe(host);
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it("does not scan added element subtrees before user intent", async () => {
    const queryElements = vi.spyOn(Element.prototype, "querySelectorAll");
    try {
      const subtree = document.createElement("section");
      for (let index = 0; index < 2_000; index += 1) {
        subtree.append(document.createElement("span"));
      }
      document.body.append(subtree);
      await flushSubmissionQueue();

      expect(
        queryElements.mock.calls.some(([selector]) => selector === "*")
      ).toBe(false);
    } finally {
      queryElements.mockRestore();
    }
  });

  it("hides the synchronous shadow bridge while installing capture first", async () => {
    const originalAttachShadow = Element.prototype.attachShadow;
    const originalName = originalAttachShadow.name;
    const originalLength = originalAttachShadow.length;
    const observations = { window: 0, document: 0, host: 0 };
    const eventType = "vaultkern:autofill:open-shadow-root";
    const host = document.createElement("div");
    document.body.append(host);
    window.addEventListener(eventType, () => observations.window += 1, {
      capture: true,
      once: true
    });
    document.addEventListener(eventType, () => observations.document += 1, {
      capture: true,
      once: true
    });
    host.addEventListener(eventType, () => observations.host += 1, {
      capture: true,
      once: true
    });

    try {
      vi.resetModules();
      await import("../autofillShadowPageHook");
      vi.resetModules();
      await import("../autofillShadowPageHook");

      const installedAttachShadow = Element.prototype.attachShadow;
      const installedSource = Function.prototype.toString.call(installedAttachShadow);
      expect(installedAttachShadow).not.toBe(originalAttachShadow);
      expect(installedAttachShadow.name).toBe(originalName);
      expect(installedAttachShadow.length).toBe(originalLength);
      expect(installedSource).toContain("[native code]");
      expect(installedSource).not.toContain(eventType);
      expect(installedSource).not.toContain("attachShadowWithAutofillNotification");

      expect(
        (Element.prototype as typeof Element.prototype & Record<symbol, unknown>)[
          Symbol.for("vaultkern.autofill.shadowPageHookInstalled")
        ]
      ).not.toBe(true);

      const root = host.attachShadow({ mode: "open" });
      expect(root.host).toBe(host);
      expect(observations).toEqual({ window: 0, document: 0, host: 0 });
      root.addEventListener(
        "submit",
        (event) => {
          event.preventDefault();
          event.stopImmediatePropagation();
        },
        { capture: true }
      );
      root.innerHTML = `
        <form>
          <input name="email" type="email" autocomplete="username" value="shadow@example.com" />
          <input name="password" type="password" autocomplete="current-password" value="shadow-secret" />
        </form>
      `;
      (globalThis as typeof globalThis & {
        __vaultkernAllowSyntheticAutofillSubmitForTests?: boolean;
      }).__vaultkernAllowSyntheticAutofillSubmitForTests = true;
      root.querySelector("form")?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true })
      );
      await flushSubmissionQueue();

      expect(sendMessage).toHaveBeenCalledTimes(1);
    } finally {
      Element.prototype.attachShadow = originalAttachShadow;
    }
  });
});
