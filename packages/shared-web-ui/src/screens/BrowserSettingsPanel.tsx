import { useEffect, useState } from "react";
import type { CSSProperties } from "react";

import { archiveTheme } from "../designTokens";
import type { ExtensionLanguage, ExtensionSettings } from "../extensionSettings";
import { useText } from "../i18n";

interface BrowserSettingsPanelProps {
  settings: ExtensionSettings;
  saving: boolean;
  error: string | null;
  quickUnlockSupported?: boolean;
  quickUnlockEnabled?: boolean;
  quickUnlockBusy?: boolean;
  quickUnlockError?: string | null;
  onQuickUnlockChange?(enabled: boolean): void;
  onSave(settings: ExtensionSettings): void;
}

export function BrowserSettingsPanel({
  settings,
  saving,
  error,
  quickUnlockSupported = false,
  quickUnlockEnabled = false,
  quickUnlockBusy = false,
  quickUnlockError = null,
  onQuickUnlockChange,
  onSave
}: BrowserSettingsPanelProps) {
  const text = useText();
  const [draft, setDraft] = useState(() => toDraft(settings));

  useEffect(() => {
    setDraft(toDraft(settings));
  }, [settings]);

  return (
    <form
      style={panelStyle}
      onSubmit={(event) => {
        event.preventDefault();
        onSave({
          recentVaultLimit: parseBoundedInteger(draft.recentVaultLimit, 1, 50, 10),
          language: draft.language,
          idleLockMinutes: parseBoundedInteger(draft.idleLockMinutes, 0, 240, 10),
          clearClipboardSeconds: parseBoundedInteger(
            draft.clearClipboardSeconds,
            0,
            3600,
            30
          ),
          passkeyProviderEnabled: draft.passkeyProviderEnabled
        });
      }}
    >
      <div style={titleRowStyle}>
        <div>
          <h2 style={headingStyle}>{text("Browser Settings")}</h2>
          <p style={descriptionStyle}>
            {text("Local extension preferences. These are not stored in the KDBX database.")}
          </p>
        </div>
        <button type="submit" disabled={saving} style={primaryButtonStyle}>
          {saving ? text("Saving...") : text("Save Browser Settings")}
        </button>
      </div>

      <div style={gridStyle}>
        <label style={fieldStyle}>
          {text("Recent Databases")}
          <input
            aria-label={text("Recent Databases")}
            type="number"
            min={1}
            max={50}
            value={draft.recentVaultLimit}
            onChange={(event) =>
              setDraft({ ...draft, recentVaultLimit: event.target.value })
            }
            style={inputStyle}
          />
        </label>
        <label style={fieldStyle}>
          {text("Idle Lock Minutes")}
          <input
            aria-label={text("Idle Lock Minutes")}
            type="number"
            min={0}
            max={240}
            value={draft.idleLockMinutes}
            onChange={(event) =>
              setDraft({ ...draft, idleLockMinutes: event.target.value })
            }
            style={inputStyle}
          />
        </label>
        <label style={fieldStyle}>
          {text("Clear Clipboard Seconds")}
          <input
            aria-label={text("Clear Clipboard Seconds")}
            type="number"
            min={0}
            max={3600}
            value={draft.clearClipboardSeconds}
            onChange={(event) =>
              setDraft({ ...draft, clearClipboardSeconds: event.target.value })
            }
            style={inputStyle}
          />
        </label>
        <div style={fieldStyle}>
          {text("Language")}
          <div style={segmentedStyle} role="group" aria-label={text("Language")}>
            <button
              type="button"
              onClick={() => setDraft({ ...draft, language: "en" })}
              style={segmentStyle(draft.language === "en")}
            >
              English
            </button>
            <button
              type="button"
              onClick={() => setDraft({ ...draft, language: "zh-CN" })}
              style={segmentStyle(draft.language === "zh-CN")}
            >
              中文
            </button>
          </div>
        </div>
        <label style={checkboxFieldStyle}>
          <input
            aria-label={text("VaultKern passkey provider")}
            type="checkbox"
            checked={draft.passkeyProviderEnabled}
            onChange={(event) =>
              setDraft({
                ...draft,
                passkeyProviderEnabled: event.target.checked
              })
            }
          />
          {text("VaultKern passkey provider")}
        </label>
      </div>
      <label style={toggleRowStyle}>
        <input
          aria-label={text("Quick Unlock")}
          type="checkbox"
          checked={quickUnlockEnabled}
          disabled={!quickUnlockSupported || quickUnlockBusy}
          onChange={(event) => onQuickUnlockChange?.(event.target.checked)}
        />
        <span>{text("Quick Unlock")}</span>
      </label>
      {quickUnlockError ? <div role="alert">{quickUnlockError}</div> : null}
      <p style={noteStyle}>
        {text("Clipboard clearing writes an empty string after the delay. Browser APIs do not allow reliable background verification that the clipboard still contains the copied secret.")}
      </p>
      {error ? <div role="alert">{error}</div> : null}
    </form>
  );
}

function toDraft(settings: ExtensionSettings) {
  return {
    recentVaultLimit: String(settings.recentVaultLimit),
    language: settings.language,
    idleLockMinutes: String(settings.idleLockMinutes),
    clearClipboardSeconds: String(settings.clearClipboardSeconds),
    passkeyProviderEnabled: settings.passkeyProviderEnabled
  };
}

function parseBoundedInteger(
  value: string,
  min: number,
  max: number,
  fallback: number
) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

const panelStyle: CSSProperties = {
  display: "grid",
  gap: archiveTheme.spacing.md,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.lg,
  background: archiveTheme.colors.surface,
  boxShadow: archiveTheme.shadow.panel
};

const titleRowStyle: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  alignItems: "start",
  justifyContent: "space-between",
  gap: archiveTheme.spacing.md
};

const headingStyle: CSSProperties = {
  margin: 0,
  fontFamily: archiveTheme.font.display,
  fontSize: "1.5rem",
  fontWeight: 600
};

const descriptionStyle: CSSProperties = {
  margin: `${archiveTheme.spacing.xs} 0 0`,
  color: archiveTheme.colors.textMuted,
  lineHeight: 1.5
};

const gridStyle: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
  gap: archiveTheme.spacing.md
};

const fieldStyle: CSSProperties = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const checkboxFieldStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: archiveTheme.spacing.sm,
  minHeight: "44px",
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const toggleRowStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: archiveTheme.spacing.sm,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const inputStyle: CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const segmentedStyle: CSSProperties = {
  display: "flex",
  gap: archiveTheme.spacing.xs,
  flexWrap: "wrap"
};

function segmentStyle(active: boolean): CSSProperties {
  return {
    border: `1px solid ${active ? archiveTheme.colors.accentStrong : archiveTheme.colors.line}`,
    borderRadius: archiveTheme.radius.pill,
    padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
    background: active ? archiveTheme.colors.accentStrong : archiveTheme.colors.surfaceMuted,
    color: active ? "#fffaf2" : archiveTheme.colors.text,
    cursor: "pointer"
  };
}

const primaryButtonStyle: CSSProperties = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  cursor: "pointer"
};

const noteStyle: CSSProperties = {
  margin: 0,
  color: archiveTheme.colors.textMuted,
  lineHeight: 1.5
};
