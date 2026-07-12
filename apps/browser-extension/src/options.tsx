import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { RuntimeClient } from "@vaultkern/runtime-web-client";
import type { QuickUnlockState, VaultReference } from "@vaultkern/runtime-web-client";

import {
  DEFAULT_EXTENSION_SETTINGS,
  ExtensionSettingsPanel,
  I18nProvider,
  archiveTheme,
  errorMessage,
  loadRuntimeOwnedExtensionSettings,
  normalizeExtensionSettings,
  translate
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettings } from "@vaultkern/shared-web-ui";

import { createChromeExtensionSettingsStore } from "./extensionSettings";
import { extensionTransport } from "./runtimeBridge";

const container = document.getElementById("root");
const client = new RuntimeClient(extensionTransport);
const extensionSettingsStore = createChromeExtensionSettingsStore();

async function applyRecentVaultLimit(
  vaults: VaultReference[],
  settings: ExtensionSettings
) {
  const sortedVaults = [...vaults].sort(
    (left, right) => (right.lastUsedAt ?? 0) - (left.lastUsedAt ?? 0)
  );
  const overflowVaults = sortedVaults.slice(settings.recentVaultLimit);

  if (overflowVaults.length > 0) {
    await Promise.all(
      overflowVaults.map((vault) => client.deleteRecentVault(vault.vaultRefId))
    );
    return sortedVaults.slice(0, settings.recentVaultLimit);
  }

  return sortedVaults;
}

function OptionsApp() {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [quickUnlockState, setQuickUnlockState] = useState<QuickUnlockState | null>(null);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadOptionsData() {
      try {
        const loaded = await loadRuntimeOwnedExtensionSettings(
          extensionSettingsStore,
          client
        );
        if (!cancelled) {
          setSettings(loaded.settings);
          setQuickUnlockState(loaded.quickUnlockState);
          setQuickUnlockError(loaded.quickUnlockState.lastError);
          setError(null);
        }
      } catch (loadError) {
        if (!cancelled) {
          try {
            setSettings(normalizeExtensionSettings(await extensionSettingsStore.load()));
          } catch {
            // Preserve defaults when both local and runtime settings are unavailable.
          }
          setQuickUnlockError(
            errorMessage(
              loadError,
              translate(settings.language, "Failed to update quick unlock")
            )
          );
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

      void client.listRecentVaults().catch(() => undefined);
    }

    void loadOptionsData();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const refreshQuickUnlockState = () => {
      void loadRuntimeOwnedExtensionSettings(extensionSettingsStore, client)
        .then((loaded) => {
          if (!cancelled) {
            setSettings(loaded.settings);
            setQuickUnlockState(loaded.quickUnlockState);
            setQuickUnlockError(loaded.quickUnlockState.lastError);
          }
        })
        .catch((refreshError) => {
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
      try {
        const nextQuickUnlockState = await client.setQuickUnlockPolicy(
          normalizedSettings.quickUnlockEnabled
        );
        const authoritativeSettings = {
          ...normalizedSettings,
          quickUnlockEnabled: nextQuickUnlockState.policyEnabled === true
        };
        await extensionSettingsStore.save(authoritativeSettings);
        setSettings(authoritativeSettings);
        setQuickUnlockState(nextQuickUnlockState);
        setQuickUnlockError(nextQuickUnlockState.lastError);
      } catch (nativeSaveError) {
        const fallbackSettings = {
          ...normalizedSettings,
          quickUnlockEnabled: settings.quickUnlockEnabled
        };
        await extensionSettingsStore.save(fallbackSettings);
        setSettings(fallbackSettings);
        setQuickUnlockError(
          errorMessage(
            nativeSaveError,
            translate(settings.language, "Failed to update quick unlock")
          )
        );
      }
      await applyRecentVaultLimit(await client.listRecentVaults(), normalizedSettings);
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
              quickUnlockSupported={quickUnlockState?.capability === "available"}
              quickUnlockEnabled={settings.quickUnlockEnabled}
              quickUnlockBusy={saving || quickUnlockState === null}
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
