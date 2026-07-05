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
        const [loadedSession, loadedVaults] = await Promise.all([
          client.getSessionState(),
          client.listRecentVaults()
        ]);
        if (!cancelled) {
          setSession(loadedSession);
          setRecentVaults(loadedVaults);
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

    if (!currentVaultReference || currentVaultReference.supportsQuickUnlock === enabled) {
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
    recentVaults.find((vault) => vault.vaultRefId === session?.currentVaultRefId) ??
    recentVaults.find((vault) => vault.isCurrent) ??
    null;

  useEffect(() => {
    if (
      !settings.quickUnlockEnabled ||
      quickUnlockBusy ||
      !currentVaultReference ||
      currentVaultReference.supportsQuickUnlock
    ) {
      return;
    }

    const syncKey = `${currentVaultReference.vaultRefId}:enable`;
    if (quickUnlockAutoSyncAttempt.current === syncKey) {
      return;
    }

    quickUnlockAutoSyncAttempt.current = syncKey;
    void syncQuickUnlockPreferenceToCurrentVault(true);
  }, [currentVaultReference, quickUnlockBusy, settings.quickUnlockEnabled]);

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
