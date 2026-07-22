import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  DEFAULT_EXTENSION_SETTINGS,
  ExtensionSettingsPanel,
  I18nProvider,
  archiveTheme,
  errorMessage,
  normalizeBrowserExtensionSettings,
  translate
} from "@vaultkern/shared-web-ui";
import type { ExtensionSettings } from "@vaultkern/shared-web-ui";

import { createChromeExtensionSettingsStore } from "./extensionSettings";

const container = document.getElementById("root");
const extensionSettingsStore = createChromeExtensionSettingsStore();

function OptionsApp() {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadOptionsData() {
      try {
        const loadedSettings = await extensionSettingsStore.load();
        if (!cancelled) {
          setSettings(normalizeBrowserExtensionSettings(loadedSettings));
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
      const normalizedSettings = normalizeBrowserExtensionSettings(nextSettings);
      await extensionSettingsStore.save(normalizedSettings);
      setSettings(normalizedSettings);
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
              surface="browser"
              saving={saving}
              error={error}
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
