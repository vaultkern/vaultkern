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

  it("does not fill SMS or email one-time-code prompts with authenticator TOTP", () => {
    document.body.innerHTML = `
      <form aria-label="SMS verification">
        <label for="sms-code">Enter the SMS code sent to your phone</label>
        <input id="sms-code" name="sms_code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#sms-code") as HTMLInputElement).value).toBe("");

    document.body.innerHTML = `
      <form aria-label="Email verification">
        <label for="email-code">Enter the email code we sent you</label>
        <input id="email-code" name="email_code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#email-code") as HTMLInputElement).value).toBe("");
  });

  it("does not let generic MFA form context override SMS or email code labels", () => {
    document.body.innerHTML = `
      <form>
        <label for="sms-code">Enter the SMS code sent to your phone</label>
        <input id="sms-code" name="sms_code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#sms-code") as HTMLInputElement).value).toBe("");

    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <label for="email-code">Enter the email code we sent you</label>
        <input id="email-code" name="email_code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#email-code") as HTMLInputElement).value).toBe("");
  });

  it("recognizes authenticator-app code prompts as TOTP", () => {
    document.body.innerHTML = `
      <form>
        <label for="authenticator-app-code">Code from your authenticator app</label>
        <input id="authenticator-app-code" name="code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#authenticator-app-code") as HTMLInputElement).value).toBe(
      "123456"
    );
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

  it("keeps explicit login fields in a combined MFA form", () => {
    document.body.innerHTML = `
      <form id="mfa-login" aria-label="Two-factor verification">
        <input id="email" type="email" autocomplete="username" />
        <input id="password" type="password" autocomplete="current-password" />
        <input id="otp-code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "secret-123",
      totp: "123456"
    });

    expect((document.querySelector("#email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#password") as HTMLInputElement).value).toBe(
      "secret-123"
    );
    expect((document.querySelector("#otp-code") as HTMLInputElement).value).toBe("123456");
  });

  it("lets explicit login autocompletes win over shared MFA field styling", () => {
    document.body.innerHTML = `
      <form>
        <input id="email" class="mfa-field" type="email" autocomplete="username" />
        <input id="password" class="mfa-field" type="password" autocomplete="current-password" />
        <input id="otp-code" class="mfa-field" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "secret-123",
      totp: "123456"
    });

    expect((document.querySelector("#email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#password") as HTMLInputElement).value).toBe(
      "secret-123"
    );
    expect((document.querySelector("#otp-code") as HTMLInputElement).value).toBe("123456");
  });

  it("honors email autocomplete before shared MFA styling", () => {
    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <input id="email" class="otp-code" type="text" autocomplete="email" />
        <input id="password" type="password" autocomplete="current-password" />
        <input id="otp-code" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "secret-123",
      totp: "123456"
    });

    expect((document.querySelector("#email") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#password") as HTMLInputElement).value).toBe(
      "secret-123"
    );
    expect((document.querySelector("#otp-code") as HTMLInputElement).value).toBe("123456");
  });

  it("does not let shared MFA styling override unannotated password fields", () => {
    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <input id="password" class="mfa-field" type="password" name="password" />
        <input id="otp-code" class="mfa-field" name="otp" inputmode="numeric" autocomplete="one-time-code" />
      </form>
    `;

    fillLoginForm({
      password: "secret-123",
      totp: "123456"
    });

    expect((document.querySelector("#password") as HTMLInputElement).value).toBe(
      "secret-123"
    );
    expect((document.querySelector("#otp-code") as HTMLInputElement).value).toBe("123456");
  });

  it("recognizes numeric two-step and two-factor MFA labels", () => {
    document.body.innerHTML = `
      <form aria-label="2-step verification">
        <input id="step-code" name="code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#step-code") as HTMLInputElement).value).toBe("123456");

    document.body.innerHTML = `
      <form aria-label="2-factor authentication">
        <input id="factor-code" name="code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "654321" });

    expect((document.querySelector("#factor-code") as HTMLInputElement).value).toBe("654321");
  });

  it("recognizes one-time-password prompts as TOTP", () => {
    document.body.innerHTML = `
      <form>
        <label for="one-time-password">One-time password</label>
        <input id="one-time-password" type="password" name="one_time_password" />
      </form>
    `;

    fillLoginForm({ password: "account-secret", totp: "123456" });

    expect((document.querySelector("#one-time-password") as HTMLInputElement).value).toBe(
      "123456"
    );
  });

  it("does not fill payment-style security code fields without MFA evidence", () => {
    document.body.innerHTML = `
      <form>
        <label for="security-code">Security code</label>
        <input id="security-code" name="security_code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#security-code") as HTMLInputElement).value).toBe("");
  });

  it("does not fill non-login newsletter fields that look like TOTP", () => {
    document.body.innerHTML = `
      <form class="newsletter">
        <h2>Subscribe to our newsletter</h2>
        <input id="newsletter-otp" name="otp_code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#newsletter-otp") as HTMLInputElement).value).toBe("");
  });

  it("recognizes authentication-code labels as TOTP", () => {
    document.body.innerHTML = `
      <form>
        <label for="auth-code">Authentication code</label>
        <input id="auth-code" name="code" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#auth-code") as HTMLInputElement).value).toBe("123456");
  });

  it("does not fill card verification code fields without MFA evidence", () => {
    document.body.innerHTML = `
      <form>
        <label for="card-code">Card verification code</label>
        <input id="card-code" name="card_verification_code" />
      </form>
    `;

    fillLoginForm({ totp: "123456" });

    expect((document.querySelector("#card-code") as HTMLInputElement).value).toBe("");
  });

  it("fills masked OTP fields with TOTP instead of the account password", () => {
    document.body.innerHTML = `
      <form>
        <input id="otp-password" type="password" name="otp" />
      </form>
    `;

    fillLoginForm({ password: "account-secret", totp: "123456" });

    expect((document.querySelector("#otp-password") as HTMLInputElement).value).toBe("123456");
  });

  it("uses form aria labels as MFA context for generic split code fields", () => {
    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <input name="digit_1" maxlength="1" inputmode="numeric" />
        <input name="digit_2" maxlength="1" inputmode="numeric" />
        <input name="digit_3" maxlength="1" inputmode="numeric" />
        <input name="digit_4" maxlength="1" inputmode="numeric" />
        <input name="digit_5" maxlength="1" inputmode="numeric" />
        <input name="digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "246810" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["2", "4", "6", "8", "1", "0"]);
  });

  it("uses form aria-labelledby text as MFA context for generic split code fields", () => {
    document.body.innerHTML = `
      <div id="mfa-title">Two-factor verification</div>
      <form aria-labelledby="mfa-title">
        <input name="digit_1" maxlength="1" inputmode="numeric" />
        <input name="digit_2" maxlength="1" inputmode="numeric" />
        <input name="digit_3" maxlength="1" inputmode="numeric" />
        <input name="digit_4" maxlength="1" inputmode="numeric" />
        <input name="digit_5" maxlength="1" inputmode="numeric" />
        <input name="digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "246810" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["2", "4", "6", "8", "1", "0"]);
  });

  it("expands a partially labeled split TOTP field group", () => {
    document.body.innerHTML = `
      <form>
        <label for="digit-1">Authenticator code</label>
        <input id="digit-1" name="digit_1" maxlength="1" inputmode="numeric" />
        <input id="digit-2" name="digit_2" maxlength="1" inputmode="numeric" />
        <input id="digit-3" name="digit_3" maxlength="1" inputmode="numeric" />
        <input id="digit-4" name="digit_4" maxlength="1" inputmode="numeric" />
        <input id="digit-5" name="digit_5" maxlength="1" inputmode="numeric" />
        <input id="digit-6" name="digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "135790" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["1", "3", "5", "7", "9", "0"]);
  });

  it("expands anonymous split TOTP fields after a numbered seed", () => {
    document.body.innerHTML = `
      <form>
        <label for="digit-1">Authenticator code</label>
        <input id="digit-1" name="digit_1" maxlength="1" inputmode="numeric" />
        <input maxlength="1" />
        <input maxlength="1" />
        <input maxlength="1" />
        <input maxlength="1" />
        <input maxlength="1" />
      </form>
    `;

    fillLoginForm({ totp: "135790" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[maxlength="1"]')].map(
        (field) => field.value
      )
    ).toEqual(["1", "3", "5", "7", "9", "0"]);
  });

  it("keeps in-form split TOTP fields scoped to the labeled group", () => {
    document.body.innerHTML = `
      <form>
        <input id="unrelated-one-char" name="middle_initial" maxlength="1" />
        <label for="digit-1">Authenticator code</label>
        <input id="digit-1" name="digit_1" maxlength="1" inputmode="numeric" />
        <input id="digit-2" name="digit_2" maxlength="1" inputmode="numeric" />
        <input id="digit-3" name="digit_3" maxlength="1" inputmode="numeric" />
        <input id="digit-4" name="digit_4" maxlength="1" inputmode="numeric" />
        <input id="digit-5" name="digit_5" maxlength="1" inputmode="numeric" />
        <input id="digit-6" name="digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "135790" });

    expect((document.querySelector("#unrelated-one-char") as HTMLInputElement).value).toBe("");
    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["1", "3", "5", "7", "9", "0"]);
  });

  it("keeps same-form split TOTP fields out of adjacent code-shaped fields", () => {
    document.body.innerHTML = `
      <form aria-label="Two-factor verification">
        <input id="account-code" name="account_code" maxlength="1" inputmode="numeric" />
        <label for="digit-1">Authenticator code</label>
        <input id="digit-1" name="digit_1" maxlength="1" inputmode="numeric" />
        <input id="digit-2" name="digit_2" maxlength="1" inputmode="numeric" />
        <input id="digit-3" name="digit_3" maxlength="1" inputmode="numeric" />
        <input id="digit-4" name="digit_4" maxlength="1" inputmode="numeric" />
        <input id="digit-5" name="digit_5" maxlength="1" inputmode="numeric" />
        <input id="digit-6" name="digit_6" maxlength="1" inputmode="numeric" />
      </form>
    `;

    fillLoginForm({ totp: "135790" });

    expect((document.querySelector("#account-code") as HTMLInputElement).value).toBe("");
    expect(
      [...document.querySelectorAll<HTMLInputElement>('input[name^="digit_"]')].map(
        (field) => field.value
      )
    ).toEqual(["1", "3", "5", "7", "9", "0"]);
  });

  it("scopes form-less split TOTP fields to their contiguous group", () => {
    document.body.innerHTML = `
      <input id="unrelated-one-char" name="middle_initial" maxlength="1" />
      <input id="separator" name="search" />
      <div>
        <label for="code-1">Authenticator code</label>
        <input id="code-1" class="otp" name="code_1" maxlength="1" inputmode="numeric" />
        <input id="code-2" class="otp" name="code_2" maxlength="1" inputmode="numeric" />
        <input id="code-3" class="otp" name="code_3" maxlength="1" inputmode="numeric" />
        <input id="code-4" class="otp" name="code_4" maxlength="1" inputmode="numeric" />
        <input id="code-5" class="otp" name="code_5" maxlength="1" inputmode="numeric" />
        <input id="code-6" class="otp" name="code_6" maxlength="1" inputmode="numeric" />
      </div>
    `;

    fillLoginForm({ totp: "112358" });

    expect((document.querySelector("#unrelated-one-char") as HTMLInputElement).value).toBe("");
    expect(
      [...document.querySelectorAll<HTMLInputElement>(".otp")].map((field) => field.value)
    ).toEqual(["1", "1", "2", "3", "5", "8"]);
  });

  it("derives a shared container for wrapped form-less split TOTP inputs", () => {
    document.body.innerHTML = `
      <div id="otp-widget">
        <label for="code-1">Authenticator code</label>
        <span><input id="code-1" class="otp" name="code_1" maxlength="1" inputmode="numeric" /></span>
        <span><input id="code-2" class="otp" name="code_2" maxlength="1" inputmode="numeric" /></span>
        <span><input id="code-3" class="otp" name="code_3" maxlength="1" inputmode="numeric" /></span>
        <span><input id="code-4" class="otp" name="code_4" maxlength="1" inputmode="numeric" /></span>
        <span><input id="code-5" class="otp" name="code_5" maxlength="1" inputmode="numeric" /></span>
        <span><input id="code-6" class="otp" name="code_6" maxlength="1" inputmode="numeric" /></span>
      </div>
    `;

    fillLoginForm({ totp: "112358" });

    expect(
      [...document.querySelectorAll<HTMLInputElement>(".otp")].map((field) => field.value)
    ).toEqual(["1", "1", "2", "3", "5", "8"]);
  });

  it("keeps form-less split TOTP fields inside one container", () => {
    document.body.innerHTML = `
      <input id="unrelated-one-char" name="middle_initial" maxlength="1" />
      <div id="otp-widget">
        <label for="code-1">Authenticator code</label>
        <input id="code-1" class="otp" name="code_1" maxlength="1" inputmode="numeric" />
        <input id="code-2" class="otp" name="code_2" maxlength="1" inputmode="numeric" />
        <input id="code-3" class="otp" name="code_3" maxlength="1" inputmode="numeric" />
        <input id="code-4" class="otp" name="code_4" maxlength="1" inputmode="numeric" />
        <input id="code-5" class="otp" name="code_5" maxlength="1" inputmode="numeric" />
        <input id="code-6" class="otp" name="code_6" maxlength="1" inputmode="numeric" />
      </div>
    `;

    fillLoginForm({ totp: "112358" });

    expect((document.querySelector("#unrelated-one-char") as HTMLInputElement).value).toBe("");
    expect(
      [...document.querySelectorAll<HTMLInputElement>(".otp")].map((field) => field.value)
    ).toEqual(["1", "1", "2", "3", "5", "8"]);
  });

  it("does not treat backup service password fields as recovery codes", () => {
    document.body.innerHTML = `
      <form>
        <input id="backup-user" name="backup_email" type="email" autocomplete="username" />
        <input id="backup-password" name="backup_password" type="password" autocomplete="current-password" />
      </form>
    `;

    fillLoginForm({
      username: "alice@example.com",
      password: "secret-123",
      totp: "123456"
    });

    expect((document.querySelector("#backup-user") as HTMLInputElement).value).toBe(
      "alice@example.com"
    );
    expect((document.querySelector("#backup-password") as HTMLInputElement).value).toBe(
      "secret-123"
    );
  });

  it("does not treat the page URL as MFA context for generic code fields", () => {
    window.history.replaceState(null, "", "/mfa");
    document.body.innerHTML = `
      <form>
        <label for="promo-code">Code</label>
        <input id="promo-code" name="code" inputmode="numeric" />
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
