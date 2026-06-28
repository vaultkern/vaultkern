import { expect, it } from "vitest";

import { generatePassword } from "../passwordGenerator";

it("generates a password with the requested length and selected character classes", () => {
  const password = generatePassword(
    {
      length: 8,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true
    },
    (length) => Uint8Array.from({ length }, (_, index) => index)
  );

  expect(password).toHaveLength(8);
  expect(password).toMatch(/[A-Z]/);
  expect(password).toMatch(/[a-z]/);
  expect(password).toMatch(/[0-9]/);
  expect(password).toMatch(/[^A-Za-z0-9]/);
});

it("falls back to lowercase letters when every character class is disabled", () => {
  const password = generatePassword(
    {
      length: 6,
      includeUppercase: false,
      includeLowercase: false,
      includeNumbers: false,
      includeSymbols: false
    },
    (length) => new Uint8Array(length)
  );

  expect(password).toHaveLength(6);
  expect(password).toMatch(/^[a-z]+$/);
});
