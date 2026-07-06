import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

describe("password change detection fill flow", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills current new and confirmation password fields", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect(
      (document.querySelector('input[name="confirm_new_password"]') as HTMLInputElement).value
    ).toBe("new-secret");
  });

  it("uses autocomplete roles even when the current password is not first", () => {
    document.body.innerHTML = `
      <form>
        <h2>Update credentials</h2>
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="confirm_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
    expect((document.querySelector('input[name="confirm_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("fills a two-password-field change form only when the context is explicit", () => {
    document.body.innerHTML = `
      <form>
        <h2>Update password</h2>
        <input name="old_password" type="password" />
        <input name="new_password" type="password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect((document.querySelector('input[name="old_password"]') as HTMLInputElement).value).toBe(
      "old-secret"
    );
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe(
      "new-secret"
    );
  });

  it("does not put the current password into new-password fields when no new password is supplied", () => {
    document.body.innerHTML = `
      <form>
        <h2>Change password</h2>
        <input name="current_password" type="password" autocomplete="current-password" />
        <input name="new_password" type="password" autocomplete="new-password" />
        <input name="confirm_new_password" type="password" autocomplete="new-password" />
      </form>
    `;

    fillLoginForm({ password: "old-secret" });

    expect(
      (document.querySelector('input[name="current_password"]') as HTMLInputElement).value
    ).toBe("old-secret");
    expect((document.querySelector('input[name="new_password"]') as HTMLInputElement).value).toBe("");
    expect(
      (document.querySelector('input[name="confirm_new_password"]') as HTMLInputElement).value
    ).toBe("");
  });

  it("fills the checked-in change-password smoke page", () => {
    loadSmokeBody("change-password.html");

    fillLoginForm({ password: "old-secret", newPassword: "new-secret" });

    expect(
      (document.querySelector("#vaultkern-smoke-change-current-password") as HTMLInputElement).value
    ).toBe("old-secret");
    expect(
      (document.querySelector("#vaultkern-smoke-change-new-password") as HTMLInputElement).value
    ).toBe("new-secret");
    expect(
      (document.querySelector("#vaultkern-smoke-change-confirm-password") as HTMLInputElement).value
    ).toBe("new-secret");
  });
});
