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
  const [session, setSession] = useState<SessionState | null>(null);
  const [recentVaults, setRecentVaults] = useState<VaultReference[]>([]);
  const [quickUnlockSupportKnown, setQuickUnlockSupportKnown] = useState(false);
  const [quickUnlockBusy, setQuickUnlockBusy] = useState(false);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);
  const quickUnlockAutoSyncAttempt = useRef<string | null>(null);
  const quickUnlockSyncInFlight = useRef<{
    key: string;
    operation: Promise<void>;
  } | null>(null);

  async function loadQuickUnlockState() {
    const sessionPromise = client.getSessionState().then((loadedSession) => {
      setSession(loadedSession);
      setQuickUnlockSupportKnown(true);
      return loadedSession;
    });
    const recentVaultsPromise = client.listRecentVaults().then((loadedVaults) => {
      setRecentVaults(loadedVaults);
      return loadedVaults;
    });
    const [loadedSession, loadedVaults] = await Promise.all([
      sessionPromise,
      recentVaultsPromise
    ]);
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
          setQuickUnlockSupportKnown(true);
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

      try {
        const loadedState = await loadQuickUnlockState();
        const visibleVaults = await applyRecentVaultLimit(
          loadedState.recentVaults,
          normalizedSettings
        );
        setRecentVaults(visibleVaults);
        await syncQuickUnlockPreferenceToCurrentVault(
          normalizedSettings.quickUnlockEnabled,
          loadedState.session,
          visibleVaults
        );
      } catch (nativeSaveError) {
        setQuickUnlockError(
          errorMessage(
            nativeSaveError,
            translate(settings.language, "Failed to update quick unlock")
          )
        );
      }
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

  async function syncQuickUnlockPreferenceToCurrentVault(
    enabled: boolean,
    sessionForSync: SessionState | null = session,
    vaultsForSync: VaultReference[] = recentVaults
  ) {
    setQuickUnlockError(null);

    let currentSession = sessionForSync;
    let currentVaults = vaultsForSync;
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
    if (enabled && currentSession?.unlocked !== true) {
      return;
    }
    if (enabled && currentSession?.supportsBiometricUnlock !== true) {
      return;
    }

    const syncKey = `${currentVault.vaultRefId}:${
      currentSession?.unlocked === true ? "unlocked" : "locked"
    }:${enabled ? "enable" : "disable"}`;
    quickUnlockAutoSyncAttempt.current = syncKey;
    const inFlight = quickUnlockSyncInFlight.current;
    if (inFlight?.key === syncKey) {
      return inFlight.operation;
    }

    const operation = (async () => {
      setQuickUnlockBusy(true);
      setQuickUnlockError(null);
      try {
        if (enabled) {
          await client.enableQuickUnlockForCurrentVault();
        } else {
          await client.disableQuickUnlockForCurrentVault();
        }
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
    })();
    quickUnlockSyncInFlight.current = { key: syncKey, operation };
    try {
      await operation;
    } finally {
      if (quickUnlockSyncInFlight.current?.operation === operation) {
        quickUnlockSyncInFlight.current = null;
      }
    }
  }

  const currentVaultReference =
    findCurrentVaultReference(session, recentVaults);

  useEffect(() => {
    if (quickUnlockBusy || !currentVaultReference) {
      return;
    }
    if (currentVaultReference.supportsQuickUnlock === settings.quickUnlockEnabled) {
      quickUnlockAutoSyncAttempt.current = null;
      return;
    }
    if (settings.quickUnlockEnabled && session?.supportsBiometricUnlock !== true) {
      return;
    }

    const syncKey = `${currentVaultReference.vaultRefId}:${
      session?.unlocked === true ? "unlocked" : "locked"
    }:${settings.quickUnlockEnabled ? "enable" : "disable"}`;
    if (quickUnlockAutoSyncAttempt.current === syncKey) {
      return;
    }

    quickUnlockAutoSyncAttempt.current = syncKey;
    void syncQuickUnlockPreferenceToCurrentVault(settings.quickUnlockEnabled);
  }, [
    currentVaultReference,
    quickUnlockBusy,
    session?.supportsBiometricUnlock,
    session?.unlocked,
    settings.quickUnlockEnabled
  ]);

  return (
    <I18nProvider language={settings.language}>
      <main style={pageStyle}>
        <div style={shellStyle}>
          {loading || !quickUnlockSupportKnown ? (
            <div style={messageStyle}>Loading...</div>
          ) : (
            <ExtensionSettingsPanel
              settings={settings}
              saving={saving}
              error={error}
              quickUnlockSupported={session?.supportsBiometricUnlock}
              quickUnlockEnabled={settings.quickUnlockEnabled}
              quickUnlockBusy={quickUnlockBusy || session === null}
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
