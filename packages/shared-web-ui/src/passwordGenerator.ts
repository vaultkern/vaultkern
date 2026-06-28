export type PasswordGeneratorOptions = {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
};

type RandomBytes = (length: number) => Uint8Array;

const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/|~";

export const DEFAULT_PASSWORD_GENERATOR_OPTIONS: PasswordGeneratorOptions = {
  length: 20,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true
};

export function generatePassword(
  options: PasswordGeneratorOptions,
  randomBytes: RandomBytes = secureRandomBytes
): string {
  const selectedPools = getSelectedPools(options);
  const length = Math.max(1, Math.floor(options.length));
  const requiredCharacters = selectedPools
    .slice(0, length)
    .map((pool, index) => pickCharacter(pool, randomBytes(1)[0] + index));
  const allCharacters = selectedPools.join("");
  const remainingLength = Math.max(0, length - requiredCharacters.length);
  const random = randomBytes(remainingLength);
  const remainingCharacters = Array.from(random, (byte) =>
    pickCharacter(allCharacters, byte)
  );

  return [...requiredCharacters, ...remainingCharacters].join("");
}

function getSelectedPools(options: PasswordGeneratorOptions): string[] {
  const pools: string[] = [];

  if (options.includeUppercase) {
    pools.push(UPPERCASE);
  }

  if (options.includeLowercase) {
    pools.push(LOWERCASE);
  }

  if (options.includeNumbers) {
    pools.push(NUMBERS);
  }

  if (options.includeSymbols) {
    pools.push(SYMBOLS);
  }

  return pools.length > 0 ? pools : [LOWERCASE];
}

function pickCharacter(characters: string, byte: number): string {
  return characters[byte % characters.length] ?? characters[0]!;
}

function secureRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
