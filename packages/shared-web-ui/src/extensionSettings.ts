export type ExtensionLanguage = "en" | "zh-CN";

export interface ExtensionSettings {
  recentVaultLimit: number;
  language: ExtensionLanguage;
  idleLockMinutes: number;
  clearClipboardSeconds: number;
  autofillOnPageLoadEnabled: boolean;
  browserPasskeyProxyEnabled: boolean;
  windowsPasskeyProviderEnabled: boolean;
  quickUnlockEnabled: boolean;
}

export type SettingsSurface = "browser" | "windows";

export interface ExtensionSettingsStore {
  surface?: SettingsSurface;
  nativeReconciliationOwned?: boolean;
  queueQuickUnlockEnrollment?(credentials: {
    password?: string | null;
    keyFilePath?: string | null;
  }): Promise<void>;
  load(): Promise<ExtensionSettings>;
  save(settings: ExtensionSettings): Promise<void>;
}

export type ExtensionSettingsReconciliationReason =
  | "startup"
  | "settings-commit"
  | "vault-save"
  | "unlock"
  | "vault-selection"
  | "manual";

export const DEFAULT_EXTENSION_SETTINGS: ExtensionSettings = {
  recentVaultLimit: 10,
  language: "en",
  idleLockMinutes: 10,
  clearClipboardSeconds: 30,
  autofillOnPageLoadEnabled: false,
  browserPasskeyProxyEnabled: false,
  windowsPasskeyProviderEnabled: false,
  quickUnlockEnabled: false
};

export function normalizeExtensionSettings(value: unknown): ExtensionSettings {
  const legacy = value as { passkeyProviderEnabled?: unknown } | null;
  const source =
    typeof value === "object" && value !== null
      ? (value as Partial<ExtensionSettings>)
      : {};

  return {
    recentVaultLimit: clampInteger(source.recentVaultLimit, 1, 50, 10),
    language: source.language === "zh-CN" ? "zh-CN" : "en",
    idleLockMinutes: clampInteger(source.idleLockMinutes, 0, 240, 10),
    clearClipboardSeconds: clampInteger(source.clearClipboardSeconds, 0, 3600, 30),
    autofillOnPageLoadEnabled: source.autofillOnPageLoadEnabled === true,
    browserPasskeyProxyEnabled:
      source.browserPasskeyProxyEnabled === true ||
      legacy?.passkeyProviderEnabled === true,
    windowsPasskeyProviderEnabled:
      source.windowsPasskeyProviderEnabled === true ||
      legacy?.passkeyProviderEnabled === true,
    quickUnlockEnabled: source.quickUnlockEnabled === true
  };
}

export function normalizeBrowserExtensionSettings(value: unknown): ExtensionSettings {
  const normalized = normalizeExtensionSettings(value);
  return {
    ...normalized,
    windowsPasskeyProviderEnabled: false,
    quickUnlockEnabled: false
  };
}

export function normalizeWindowsAppSettings(value: unknown): ExtensionSettings {
  const normalized = normalizeExtensionSettings(value);
  return {
    ...normalized,
    autofillOnPageLoadEnabled: false,
    browserPasskeyProxyEnabled: false
  };
}

export function createMemoryExtensionSettingsStore(
  initial: ExtensionSettings = DEFAULT_EXTENSION_SETTINGS
): ExtensionSettingsStore {
  let current = normalizeExtensionSettings(initial);

  return {
    surface: "windows",
    async load() {
      return current;
    },
    async save(settings) {
      current = normalizeExtensionSettings(settings);
    }
  };
}

function clampInteger(
  value: unknown,
  min: number,
  max: number,
  fallback: number
) {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}
