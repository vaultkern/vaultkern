import { beforeEach, describe, expect, it } from "vitest";

import { pendingAutofillSubmissionFromUnknown } from "../pendingSubmission";
import { collectAutofillSubmission } from "../savePrompt";

describe("autofill save prompt capture", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
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
