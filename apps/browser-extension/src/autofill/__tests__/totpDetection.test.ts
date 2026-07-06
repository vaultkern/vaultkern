import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it } from "vitest";

import { fillLoginForm } from "../../contentScript";

function loadSmokeBody(fileName: string) {
  const smokePage = readFileSync(`smoke/${fileName}`, "utf8");
  const parsed = new DOMParser().parseFromString(smokePage, "text/html");
  document.body.innerHTML = parsed.body.innerHTML;
}

describe("totp autofill detection", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills a single one-time-code field", () => {
    document.body.innerHTML = `
      <form>
        <label for="otp-code">Authenticator code</label>
        <input id="otp-code" name="otp" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#otp-code") as HTMLInputElement).value).toBe("123456");
  });

  it("splits a TOTP value across one-character fields in document order", () => {
    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <input name="otp_digit_1" maxlength="1" inputmode="numeric" />
        <input name="otp_digit_2" maxlength="1" inputmode="numeric" />
        <input name="otp_digit_3" maxlength="1" inputmode="numeric" />
        <input name="otp_digit_4" maxlength="1" inputmode="numeric" />
        <input name="otp_digit_5" maxlength="1" inputmode="numeric" />
        <input name="otp_digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "654321" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="otp_digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["6", "5", "4", "3", "2", "1"]);
  });

  it("does not fill recovery or backup code fields", () => {
    document.body.innerHTML = `
      <form>
        <label for="recovery-code">Recovery code</label>
        <input id="recovery-code" name="recovery_code" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#recovery-code") as HTMLInputElement).value).toBe("");
  });

  it("does not fill an ambiguous generic code field", () => {
    document.body.innerHTML = `
      <form>
        <label for="promo-code">Promo code</label>
        <input id="promo-code" name="code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#promo-code") as HTMLInputElement).value).toBe("");
  });

  it("fills the checked-in single-field TOTP smoke page", () => {
    loadSmokeBody("totp.html");

    fillLoginForm({ totp: "112233" });

    expect((document.querySelector("#vaultkern-smoke-totp") as HTMLInputElement).value).toBe(
      "112233"
    );
  });

  it("fills the checked-in split TOTP smoke page", () => {
    loadSmokeBody("totp-split.html");

    fillLoginForm({ totp: "908172" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>(".vaultkern-smoke-totp-digit")].map(
        (field) => field.value
      )
    ).toEqual(["9", "0", "8", "1", "7", "2"]);
  });
});
