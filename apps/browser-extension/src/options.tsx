import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { RuntimeClient } from "@vaultkern/runtime-web-client";
import type { SessionState, VaultReference } from "@vaultkern/runtime-web-client";

import {
  DEFAULT_EXTENSION_SETTINGS,
  ExtensionSettingsPanel,
  I18nProvider,
  archiveTheme,
  errorMessage,
  normalizeExtensionSettings,
  translate
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettings } from "@vaultkern/shared-web-ui";

import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { extensionTransport } from "./runtimeBridge";

const container = document.getElementById("root");
const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();

function findCurrentVaultReference(
  session: SessionState | null,
  vaults: VaultReference[]
) {
  return (
    vaults.find((vault) => vault.vaultRefId === session?.currentVaultRefId) ??
    vaults.find((vault) => vault.isCurrent) ??
    null
  );
}

function OptionsApp() {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<SessionState | null>(null);
  const [recentVaults, setRecentVaults] = useState<VaultReference[]>([]);
  const [quickUnlockBusy, setQuickUnlockBusy] = useState(false);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);
  const quickUnlockAutoSyncAttempt = useRef<string | null>(null);

  async function loadQuickUnlockState() {
    const [loadedSession, loadedVaults] = await Promise.all([
      client.getSessionState(),
      client.listRecentVaults()
    ]);
    setSession(loadedSession);
    setRecentVaults(loadedVaults);
    setQuickUnlockError(null);
    return {
      session: loadedSession,
      recentVaults: loadedVaults
    };
  }

  useEffect(() => {
    let cancelled = false;

    async function loadOptionsData() {
      try {
        const loadedSettings = await extensionSettingsStore.load();
        if (!cancelled) {
          setSettings(normalizeExtensionSettings(loadedSettings));
          setError(null);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(
            errorMessage(
              loadError,
              translate(settings.language, "Failed to load popup data")
            )
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }

      try {
        const loadedState = await loadQuickUnlockState();
        if (!cancelled) {
          setSession(loadedState.session);
          setRecentVaults(loadedState.recentVaults);
          setQuickUnlockError(null);
        }
      } catch (loadQuickUnlockError) {
        if (!cancelled) {
          setQuickUnlockError(
            errorMessage(
              loadQuickUnlockError,
              translate(settings.language, "Failed to update quick unlock")
            )
          );
        }
      }
    }

    void loadOptionsData();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const refreshQuickUnlockState = () => {
      void loadQuickUnlockState().catch((refreshError) => {
        if (!cancelled) {
          setQuickUnlockError(
            errorMessage(
              refreshError,
              translate(settings.language, "Failed to update quick unlock")
            )
          );
        }
      });
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") {
        refreshQuickUnlockState();
      }
    };

    window.addEventListener("focus", refreshQuickUnlockState);
    document.addEventListener("visibilitychange", refreshWhenVisible);

    return () => {
      cancelled = true;
      window.removeEventListener("focus", refreshQuickUnlockState);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [settings.language]);

  async function saveSettings(nextSettings: ExtensionSettings) {
    setSaving(true);
    setError(null);

    try {
      const normalizedSettings = normalizeExtensionSettings(nextSettings);
      await extensionSettingsStore.save(normalizedSettings);
      setSettings(normalizedSettings);
      await syncQuickUnlockPreferenceToCurrentVault(
        normalizedSettings.quickUnlockEnabled
      );
    } catch (saveError) {
      setError(
        errorMessage(
          saveError,
          translate(settings.language, "Failed to save extension settings")
        )
      );
    } finally {
      setSaving(false);
    }
  }

  async function syncQuickUnlockPreferenceToCurrentVault(enabled: boolean) {
    setQuickUnlockError(null);

    let currentSession = session;
    let currentVaults = recentVaults;
    let currentVault = findCurrentVaultReference(currentSession, currentVaults);

    if (!currentVault) {
      const loadedState = await loadQuickUnlockState();
      currentSession = loadedState.session;
      currentVaults = loadedState.recentVaults;
      currentVault = findCurrentVaultReference(currentSession, currentVaults);
    }

    if (!currentVault || currentVault.supportsQuickUnlock === enabled) {
      return;
    }

    setQuickUnlockBusy(true);

    try {
      const nextSession = enabled
        ? await client.enableQuickUnlockForCurrentVault()
        : await client.disableQuickUnlockForCurrentVault();
      setSession(nextSession);
      setRecentVaults(await client.listRecentVaults());
    } catch (quickUnlockFailure) {
      setQuickUnlockError(
        errorMessage(
          quickUnlockFailure,
          translate(settings.language, "Failed to update quick unlock")
        )
      );
    } finally {
      setQuickUnlockBusy(false);
    }
  }

  const currentVaultReference =
    findCurrentVaultReference(session, recentVaults);

  useEffect(() => {
    if (
      !settings.quickUnlockEnabled ||
      quickUnlockBusy ||
      !currentVaultReference ||
      currentVaultReference.supportsQuickUnlock
    ) {
      return;
    }

    const syncKey = `${currentVaultReference.vaultRefId}:${
      session?.unlocked === true ? "unlocked" : "locked"
    }:enable`;
    if (quickUnlockAutoSyncAttempt.current === syncKey) {
      return;
    }

    quickUnlockAutoSyncAttempt.current = syncKey;
    void syncQuickUnlockPreferenceToCurrentVault(true);
  }, [
    currentVaultReference,
    quickUnlockBusy,
    session?.unlocked,
    settings.quickUnlockEnabled
  ]);

  return (
    <I18nProvider language={settings.language}>
      <main style={pageStyle}>
        <div style={shellStyle}>
          {loading ? (
            <div style={messageStyle}>Loading...</div>
          ) : (
            <ExtensionSettingsPanel
              settings={settings}
              saving={saving}
              error={error}
              quickUnlockSupported={session?.supportsBiometricUnlock !== false}
              quickUnlockEnabled={settings.quickUnlockEnabled}
              quickUnlockBusy={quickUnlockBusy}
              quickUnlockError={quickUnlockError}
              onSave={(nextSettings) => {
                void saveSettings(nextSettings);
              }}
            />
          )}
        </div>
      </main>
    </I18nProvider>
  );
}

const pageStyle = {
  minHeight: "100vh",
  margin: 0,
  display: "grid",
  placeItems: "center",
  boxSizing: "border-box" as const,
  padding: archiveTheme.spacing.xl,
  background: `radial-gradient(circle at top left, ${archiveTheme.colors.page} 0%, ${archiveTheme.colors.pageShade} 65%, #dbc29f 100%)`
};

const shellStyle = {
  width: "min(760px, 100%)",
  display: "grid",
  gap: archiveTheme.spacing.lg
};

const messageStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.lg,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  boxShadow: archiveTheme.shadow.panel
};

if (container) {
  createRoot(container).render(<OptionsApp />);
}
