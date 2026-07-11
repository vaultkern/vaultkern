import { beforeEach, describe, expect, it, vi } from "vitest";

import { pendingAutofillSubmissionFromUnknown } from "../pendingSubmission";
import { collectAutofillSubmission } from "../savePrompt";
import { useDomRenderEnvironment } from "./renderEnvironment";

useDomRenderEnvironment();

describe("autofill save prompt capture", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("allocates no capture buffer merely by loading the save pipeline", async () => {
    const NativeUint8Array = Uint8Array;
    let captureBuffers = 0;
    const InstrumentedUint8Array = new Proxy(NativeUint8Array, {
      construct(target, args, newTarget) {
        if (args[0] === 1_048_577) {
          captureBuffers += 1;
        }
        return Reflect.construct(target, args, newTarget);
      }
    });
    vi.stubGlobal("Uint8Array", InstrumentedUint8Array);
    vi.resetModules();
    try {
      await import("../savePrompt");
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }

    expect(captureBuffers).toBe(0);
  });

  it("marks registration captures as save-only", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
        <input name="confirm_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      url: document.location.href,
      username: "alice@example.com",
      password: "new-secret",
      saveOnly: true
    });
    expect(submission).not.toHaveProperty("newPassword");
  });

  it("does not capture registrations with mismatched confirmation passwords", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
        <input name="confirm_password" type="password" autocomplete="new-password" value="typo-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toBeNull();
  });

  it("uses shadow-aware field order when reading submitted values", () => {
    const host = document.createElement("div");
    const shadowRoot = host.attachShadow({ mode: "open" });
    shadowRoot.innerHTML = `<input name="decoy" value="shadow-value" />`;
    document.body.append(host);
    document.body.insertAdjacentHTML(
      "beforeend",
      `
        <form id="login">
          <input name="email" autocomplete="username" value="alice@example.com" />
          <input name="password" type="password" autocomplete="current-password" value="secret-123" />
        </form>
      `
    );

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#login") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "secret-123"
    });
  });

  it("reuses the bounded snapshot traversal when reading submitted values", () => {
    const noiseCount = 1_000;
    document.body.innerHTML = `
      ${Array.from({ length: noiseCount }, () => "<span></span>").join("")}
      <form id="bounded-login">
        <input autocomplete="username" value="alice@example.com" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    const counts = { field: 0, form: 0 };
    const matches = Element.prototype.matches;
    const spy = vi.spyOn(Element.prototype, "matches").mockImplementation(
      function (this: Element, selector: string) {
        if (selector === "input,select,textarea") {
          counts.field += 1;
        } else if (selector === "form") {
          counts.form += 1;
        }
        return matches.call(this, selector);
      }
    );

    try {
      expect(
        collectAutofillSubmission(
          document,
          document.querySelector("#bounded-login") as HTMLFormElement
        )
      ).toMatchObject({
        username: "alice@example.com",
        password: "secret-123"
      });
    } finally {
      spy.mockRestore();
    }

    expect(counts.form).toBe(0);
    expect(counts.field).toBeLessThan(noiseCount * 1.5);
  });

  it("rejects a username above the capture field byte cap", () => {
    document.body.innerHTML = `
      <form id="oversized-username">
        <input autocomplete="username" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    (document.querySelector('[autocomplete="username"]') as HTMLInputElement).value =
      "x".repeat(1_048_577);

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#oversized-username") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("rejects a password above the capture field byte cap", () => {
    document.body.innerHTML = `
      <form id="oversized-password">
        <input autocomplete="username" value="alice@example.com" />
        <input type="password" autocomplete="current-password" />
      </form>
    `;
    (
      document.querySelector('[autocomplete="current-password"]') as HTMLInputElement
    ).value = "x".repeat(1_048_577);

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#oversized-password") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("rejects an oversized login password before reading the username", () => {
    document.body.innerHTML = `
      <form id="guarded-login">
        <input id="guarded-username" autocomplete="username" />
        <input id="guarded-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const password = document.querySelector(
      "#guarded-password"
    ) as HTMLInputElement;
    password.value = "x".repeat(1_048_577);
    Object.defineProperty(document.querySelector("#guarded-username"), "value", {
      configurable: true,
      get() {
        throw new Error("username was read after the password cap failed");
      }
    });
    let submission: ReturnType<typeof collectAutofillSubmission> | undefined;

    expect(() => {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#guarded-login") as HTMLFormElement
      );
    }).not.toThrow();
    expect(submission).toBeNull();
  });

  it("rejects an oversized current password before reading a new password", () => {
    document.body.innerHTML = `
      <form id="guarded-password-change">
        <input id="guarded-current" type="password" autocomplete="current-password" />
        <input id="guarded-next" type="password" autocomplete="new-password" />
      </form>
    `;
    const current = document.querySelector("#guarded-current") as HTMLInputElement;
    current.value = "x".repeat(1_048_577);
    Object.defineProperty(document.querySelector("#guarded-next"), "value", {
      configurable: true,
      get() {
        throw new Error("new password was read after the current-password cap failed");
      }
    });
    let submission: ReturnType<typeof collectAutofillSubmission> | undefined;

    expect(() => {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#guarded-password-change") as HTMLFormElement
      );
    }).not.toThrow();
    expect(submission).toBeNull();
  });

  it("reads the selected username value only once", () => {
    document.body.innerHTML = `
      <form id="single-read-login">
        <input id="single-read-username" autocomplete="username" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    const username = document.querySelector(
      "#single-read-username"
    ) as HTMLInputElement;
    let reads = 0;
    Object.defineProperty(username, "value", {
      configurable: true,
      get() {
        reads += 1;
        return "alice@example.com";
      }
    });

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#single-read-login") as HTMLFormElement
      )
    ).toMatchObject({
      username: "alice@example.com",
      password: "secret-123"
    });
    expect(reads).toBe(1);
  });

  it("rejects an oversized raw username before whitespace trimming", () => {
    document.body.innerHTML = `
      <form id="raw-username-login">
        <input id="raw-username" autocomplete="username" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    (document.querySelector("#raw-username") as HTMLInputElement).value =
      "\u00a0".repeat(524_289);

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#raw-username-login") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("stops at an oversized site-rule username before reading the next candidate", () => {
    document.body.innerHTML = `
      <form id="guarded-rule-login">
        <input id="oversized-rule-username" type="hidden" />
        <input id="unread-rule-username" autocomplete="username" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    (
      document.querySelector("#oversized-rule-username") as HTMLInputElement
    ).value = "\u20ac".repeat(349_526);
    Object.defineProperty(
      document.querySelector("#unread-rule-username"),
      "value",
      {
        configurable: true,
        get() {
          throw new Error("later username was read after the raw-value cap failed");
        }
      }
    );
    let submission: ReturnType<typeof collectAutofillSubmission> | undefined;

    expect(() => {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#guarded-rule-login") as HTMLFormElement,
        {
          srs: [
            {
              id: "guarded-usernames",
              host: window.location.hostname,
              f: {
                username: [
                  "#oversized-rule-username",
                  "#unread-rule-username"
                ]
              }
            }
          ]
        }
      );
    }).not.toThrow();
    expect(submission).toBeNull();
  });

  it("rejects a new password above the capture field byte cap", () => {
    document.body.innerHTML = `
      <form id="oversized-new-password">
        <input autocomplete="username" value="alice@example.com" />
        <input class="new-password" type="password" autocomplete="new-password" />
        <input class="new-password" type="password" autocomplete="new-password" />
      </form>
    `;
    const oversized = "x".repeat(1_048_577);
    document.querySelectorAll<HTMLInputElement>(".new-password").forEach((field) => {
      field.value = oversized;
    });

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#oversized-new-password") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("rejects an oversized new password before reading its confirmation", () => {
    document.body.innerHTML = `
      <form id="guarded-new-password">
        <input autocomplete="username" value="alice@example.com" />
        <input class="guarded-new" type="password" autocomplete="new-password" />
        <input class="guarded-new" type="password" autocomplete="new-password" />
      </form>
    `;
    const fields = document.querySelectorAll<HTMLInputElement>(".guarded-new");
    fields[0].value = "x".repeat(1_048_577);
    Object.defineProperty(fields[1], "value", {
      configurable: true,
      get() {
        throw new Error("confirmation value was read after the hard cap");
      }
    });
    let submission: ReturnType<typeof collectAutofillSubmission> | undefined;

    expect(() => {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#guarded-new-password") as HTMLFormElement
      );
    }).not.toThrow();
    expect(submission).toBeNull();
  });

  it("bounds the number of compared new-password controls", () => {
    document.body.innerHTML = `
      <form id="many-confirmations">
        <input autocomplete="username" value="alice@example.com" />
        ${Array.from(
          { length: 17 },
          (_, index) =>
            `<input class="many-confirmation" name="password_${index}" type="password" autocomplete="new-password" value="same-secret" />`
        ).join("")}
      </form>
    `;
    const value = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    )!.get!;
    let reads = 0;
    vi.spyOn(HTMLInputElement.prototype, "value", "get").mockImplementation(
      function (this: HTMLInputElement) {
        if (this.classList.contains("many-confirmation")) {
          reads += 1;
        }
        return value.call(this);
      }
    );

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#many-confirmations") as HTMLFormElement
    );

    expect(submission).toBeNull();
    expect(reads).toBeLessThanOrEqual(16);
  });

  it("rejects a capture field whose UTF-8 bytes exceed its code units", () => {
    document.body.innerHTML = `
      <form id="oversized-utf8">
        <input autocomplete="username" />
        <input type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;
    (document.querySelector('[autocomplete="username"]') as HTMLInputElement).value =
      "\u{1f600}".repeat(262_145);

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#oversized-utf8") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("bounds UTF-8 encoding for one oversized capture value", () => {
    document.body.innerHTML = `
      <form id="bounded-utf8-login">
        <input autocomplete="username" value="alice@example.com" />
        <input id="bounded-utf8-password" type="password" autocomplete="current-password" />
      </form>
    `;
    const oversized = "\u20ac".repeat(349_526);
    (document.querySelector("#bounded-utf8-password") as HTMLInputElement).value =
      oversized;
    const encode = TextEncoder.prototype.encode;
    let fullyEncoded = false;
    const encodeSpy = vi
      .spyOn(TextEncoder.prototype, "encode")
      .mockImplementation(function (this: TextEncoder, input?: string) {
        if (input === oversized) {
          fullyEncoded = true;
        }
        return encode.call(this, input);
      });
    const encodeInto = TextEncoder.prototype.encodeInto;
    const destinationSizes: number[] = [];
    const encodeIntoSpy = vi
      .spyOn(TextEncoder.prototype, "encodeInto")
      .mockImplementation(function (
        this: TextEncoder,
        source: string,
        destination: Uint8Array
      ) {
        if (source === oversized) {
          destinationSizes.push(destination.byteLength);
        }
        return encodeInto.call(this, source, destination);
      });
    let submission: ReturnType<typeof collectAutofillSubmission>;
    try {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#bounded-utf8-login") as HTMLFormElement
      );
    } finally {
      encodeSpy.mockRestore();
      encodeIntoSpy.mockRestore();
    }

    expect(submission).toBeNull();
    expect(fullyEncoded).toBe(false);
    expect(destinationSizes).toEqual([1_048_577]);
  });

  it("stops UTF-8 accounting at the remaining confirmation budget", () => {
    const value = "\u20ac".repeat(300_000);
    document.body.innerHTML = `
      <form id="bounded-confirmation-utf8">
        ${Array.from(
          { length: 5 },
          (_, index) =>
            `<input class="bounded-confirmation" name="password_${index}" type="password" autocomplete="new-password" />`
        ).join("")}
      </form>
    `;
    document
      .querySelectorAll<HTMLInputElement>(".bounded-confirmation")
      .forEach((field) => {
        field.value = value;
      });
    const encode = TextEncoder.prototype.encode;
    let fullyEncoded = false;
    const encodeSpy = vi
      .spyOn(TextEncoder.prototype, "encode")
      .mockImplementation(function (this: TextEncoder, input?: string) {
        if (input === value) {
          fullyEncoded = true;
        }
        return encode.call(this, input);
      });
    const encodeInto = TextEncoder.prototype.encodeInto;
    const destinationSizes: number[] = [];
    const encodeIntoSpy = vi
      .spyOn(TextEncoder.prototype, "encodeInto")
      .mockImplementation(function (
        this: TextEncoder,
        source: string,
        destination: Uint8Array
      ) {
        if (source === value) {
          destinationSizes.push(destination.byteLength);
        }
        return encodeInto.call(this, source, destination);
      });
    let submission: ReturnType<typeof collectAutofillSubmission>;
    try {
      submission = collectAutofillSubmission(
        document,
        document.querySelector("#bounded-confirmation-utf8") as HTMLFormElement
      );
    } finally {
      encodeSpy.mockRestore();
      encodeIntoSpy.mockRestore();
    }

    expect(submission).toBeNull();
    expect(fullyEncoded).toBe(false);
    expect(destinationSizes).toEqual([
      1_048_577,
      1_048_577,
      1_048_577,
      1_048_577,
      594_305
    ]);
  });

  it("prefers visible submitted usernames over hidden same-form fallbacks", () => {
    document.body.innerHTML = `
      <form id="login">
        <input type="hidden" name="email" value="hidden@example.com" />
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="password" type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#login") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "secret-123"
    });
  });

  it("keeps ordinary login capture inside one physical section of a shared form", () => {
    document.body.innerHTML = `
      <form id="account-page">
        <section aria-label="Newsletter">
          <input name="newsletter_email" type="email" autocomplete="email" value="attacker@example.com" />
        </section>
        <section aria-label="Sign in">
          <input name="login_email" type="email" autocomplete="username" value="alice@example.com" />
          <input name="login_password" type="password" autocomplete="current-password" value="secret-123" />
        </section>
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#account-page") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "secret-123"
    });
  });

  it("keeps registration capture inside one physical section of a shared form", () => {
    document.body.innerHTML = `
      <form id="account-page">
        <section aria-label="Newsletter">
          <input name="newsletter_email" type="email" autocomplete="email" value="attacker@example.com" />
        </section>
        <section aria-label="Create account">
          <input name="register_email" type="email" autocomplete="username" value="alice@example.com" />
          <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
          <input name="confirm_password" type="password" autocomplete="new-password" value="new-secret" />
        </section>
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#account-page") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "new-secret",
      saveOnly: true
    });
  });

  it("keeps password-change capture inside one physical section of a shared form", () => {
    document.body.innerHTML = `
      <form id="account-page">
        <section aria-label="Newsletter">
          <input name="newsletter_email" type="email" autocomplete="email" value="attacker@example.com" />
        </section>
        <section aria-label="Change password">
          <input name="account_email" type="email" autocomplete="username" value="alice@example.com" />
          <input name="current_password" type="password" autocomplete="current-password" value="old-secret" />
          <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
          <input name="confirm_password" type="password" autocomplete="new-password" value="new-secret" />
        </section>
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#account-page") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });
  });

  it("fails closed when a submitted form has two registration password scopes", () => {
    document.body.innerHTML = `
      <form id="account-page">
        <section aria-label="Create account">
          <input name="first_email" autocomplete="username" value="first@example.com" />
          <input name="first_new" type="password" autocomplete="new-password" value="shared-secret" />
        </section>
        <section aria-label="Create account">
          <input name="second_email" autocomplete="username" value="second@example.com" />
          <input name="second_new" type="password" autocomplete="new-password" value="shared-secret" />
        </section>
      </form>
    `;

    expect(
      collectAutofillSubmission(
        document,
        document.querySelector("#account-page") as HTMLFormElement
      )
    ).toBeNull();
  });

  it("does not capture ordinary login submissions with ambiguous current-password fields", () => {
    document.body.innerHTML = `
      <form id="login">
        <input name="email" type="email" autocomplete="username" value="alice@example.com" />
        <input name="decoy_password" type="password" autocomplete="current-password" value="attacker-secret" />
        <input name="password" type="password" autocomplete="current-password" value="secret-123" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#login") as HTMLFormElement
    );

    expect(submission).toBeNull();
  });

  it("does not use hidden usernames as registration capture defaults", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input type="hidden" name="email" autocomplete="username" value="hidden@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "",
      password: "new-secret",
      saveOnly: true
    });
  });

  it("does not use css-hidden usernames as registration capture defaults", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" type="email" autocomplete="username" style="display:none" value="attacker@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "",
      password: "new-secret",
      saveOnly: true
    });
  });

  it("does not use pointer-events usernames as registration capture defaults", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="pointer_email" type="email" autocomplete="username" style="pointer-events:none" value="attacker@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "",
      password: "new-secret",
      saveOnly: true
    });
  });

  it("does not capture hidden new-password fields as submissions", () => {
    document.body.innerHTML = `
      <form id="signup">
        <h2>Create account</h2>
        <input name="email" autocomplete="username" value="alice@example.com" />
        <input name="new_password" type="password" autocomplete="new-password" value="hidden-secret" hidden />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#signup") as HTMLFormElement
    );

    expect(submission).toBeNull();
  });

  it("does not capture submit controls as password-change usernames", () => {
    document.body.innerHTML = `
      <form id="change-password">
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" value="old-secret" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
        <input type="submit" name="login" value="Change password" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#change-password") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "",
      password: "old-secret",
      newPassword: "new-secret"
    });
  });

  it("captures visible readonly usernames in password-change submissions", () => {
    document.body.innerHTML = `
      <form id="change-password">
        <h2>Change password</h2>
        <input name="email" type="email" autocomplete="username" readonly value="alice@example.com" />
        <input name="current_password" type="password" autocomplete="current-password" value="old-secret" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#change-password") as HTMLFormElement
    );

    expect(submission).toMatchObject({
      username: "alice@example.com",
      password: "old-secret",
      newPassword: "new-secret"
    });
  });

  it("does not capture password changes with mismatched confirmation passwords", () => {
    document.body.innerHTML = `
      <form id="change-password">
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" value="old-secret" />
        <input name="new_password" type="password" autocomplete="new-password" value="new-secret" />
        <input name="confirm_password" type="password" autocomplete="new-password" value="typo-secret" />
      </form>
    `;

    const submission = collectAutofillSubmission(
      document,
      document.querySelector("#change-password") as HTMLFormElement
    );

    expect(submission).toBeNull();
  });

  it("preserves a save-only marker when parsing pending submissions", () => {
    expect(
      pendingAutofillSubmissionFromUnknown({
        url: "https://example.com/signup",
        username: "alice@example.com",
        password: "new-secret",
        saveOnly: true,
        submittedAt: 1710000000000
      })
    ).toMatchObject({
      saveOnly: true
    });

    expect(
      pendingAutofillSubmissionFromUnknown({
        url: "https://example.com/signup",
        username: "alice@example.com",
        password: "new-secret",
        saveOnly: false,
        submittedAt: 1710000000000
      })
    ).not.toHaveProperty("saveOnly");
  });
});
