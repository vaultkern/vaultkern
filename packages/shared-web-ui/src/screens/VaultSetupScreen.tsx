import type { ReactNode } from "react";
import type { OneDriveItem, VaultReference } from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";
import { removeRecordLabel, useLanguage, useText } from "../i18n";

export function VaultSetupScreen({
  recentVaults,
  oneDriveBrowserActive,
  oneDriveBrowserPath,
  oneDriveVaultChoices,
  onAddLocalVault,
  onAddOneDriveVault,
  onOpenOneDriveFolder,
  onOpenOneDrivePath,
  onSelectOneDriveVault,
  onDeleteVault,
  onBack,
  onOpenExtensionSettings,
  addLocalVaultBusy = false,
  addLocalVaultError,
  addLocalVaultErrorCause,
  renderRuntimeErrorHelp
}: {
  recentVaults: VaultReference[];
  oneDriveBrowserActive: boolean;
  oneDriveBrowserPath: { itemId: string; name: string }[];
  oneDriveVaultChoices: OneDriveItem[];
  onAddLocalVault: () => Promise<void>;
  onAddOneDriveVault: () => Promise<void>;
  onOpenOneDriveFolder: (folder: OneDriveItem) => Promise<void>;
  onOpenOneDrivePath: (index: number) => Promise<void>;
  onSelectOneDriveVault: (vault: OneDriveItem) => Promise<void>;
  onDeleteVault: (vaultRefId: string) => Promise<void>;
  onBack: () => void;
  onOpenExtensionSettings: () => void;
  addLocalVaultBusy?: boolean;
  addLocalVaultError?: string | null;
  addLocalVaultErrorCause?: unknown;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const text = useText();
  const language = useLanguage();
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: archiveTheme.spacing.xl,
        background: `radial-gradient(circle at top left, ${archiveTheme.colors.page} 0%, ${archiveTheme.colors.pageShade} 65%, #dbc29f 100%)`
      }}
    >
      <section style={shellStyle}>
        <div style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
          <span style={eyebrowStyle}>{text("Vault Setup")}</span>
          <h1 style={titleStyle}>{text("Add a vault")}</h1>
          <p style={subtitleStyle}>
            {text("Choose where the next vault should come from.")}
          </p>
        </div>

        {oneDriveBrowserActive ? (
          <section aria-label={text("OneDrive vaults")} style={fileBrowserSectionStyle}>
            <div style={fileBrowserHeaderStyle}>
              <div style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
                <span style={fileBrowserEyebrowStyle}>OneDrive</span>
                <h2 style={sectionTitleStyle}>{text("OneDrive vaults")}</h2>
              </div>
              <span style={fileBrowserCountStyle}>{oneDriveVaultChoices.length}</span>
            </div>
            <div style={browserChromeStyle}>
              <div style={pathLabelStyle}>{text("Current folder")}</div>
              <nav aria-label="OneDrive path" style={breadcrumbStyle}>
                <button
                  type="button"
                  onClick={() => void onOpenOneDrivePath(-1)}
                  disabled={addLocalVaultBusy || oneDriveBrowserPath.length === 0}
                  style={breadcrumbButtonStyle}
                >
                  {text("OneDrive root")}
                </button>
                {oneDriveBrowserPath.map((segment, index) => (
                  <button
                    key={segment.itemId}
                    type="button"
                    onClick={() => void onOpenOneDrivePath(index)}
                    disabled={addLocalVaultBusy || index === oneDriveBrowserPath.length - 1}
                    style={{
                      ...breadcrumbButtonStyle,
                      ...(index === oneDriveBrowserPath.length - 1
                        ? breadcrumbCurrentButtonStyle
                        : null)
                    }}
                  >
                    {segment.name}
                  </button>
                ))}
              </nav>
            </div>
            {oneDriveVaultChoices.length > 0 ? (
              <div style={fileListStyle}>
                {oneDriveVaultChoices.map((vault) => (
                  <button
                    key={`${vault.driveId}:${vault.itemId}`}
                    type="button"
                    aria-label={vault.name}
                    onClick={() =>
                      void (vault.folder
                        ? onOpenOneDriveFolder(vault)
                        : onSelectOneDriveVault(vault))
                    }
                    disabled={addLocalVaultBusy}
                    style={{
                      ...vaultChoiceButtonStyle,
                      cursor: addLocalVaultBusy ? "wait" : vaultChoiceButtonStyle.cursor,
                      opacity: addLocalVaultBusy ? 0.72 : 1
                    }}
                  >
                    <span style={fileTypeBadgeStyle}>
                      {vault.folder ? text("Folder") : text("Database file")}
                    </span>
                    <span style={{ display: "grid", gap: archiveTheme.spacing.xs, minWidth: 0 }}>
                      <span style={recordTitleStyle}>{vault.name}</span>
                      <small style={recordMetaStyle}>
                        {vault.folder
                          ? text("Open folder")
                          : formatFileSize(vault.size, text("Unknown size"))}
                      </small>
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p style={emptyStateStyle}>{text("No database files in this folder.")}</p>
            )}
          </section>
        ) : null}

        <div style={{ display: "grid", gap: archiveTheme.spacing.sm }}>
          <button
            type="button"
            onClick={() => void onAddLocalVault()}
            disabled={addLocalVaultBusy}
            style={{
              ...primaryButtonStyle,
              cursor: addLocalVaultBusy ? "wait" : primaryButtonStyle.cursor,
              opacity: addLocalVaultBusy ? 0.72 : 1
            }}
          >
            {addLocalVaultBusy ? text("Opening...") : text("Local File")}
          </button>
          <button
            type="button"
            onClick={() => void onAddOneDriveVault()}
            disabled={addLocalVaultBusy}
            style={{
              ...secondaryButtonStyle,
              cursor: addLocalVaultBusy ? "wait" : secondaryButtonStyle.cursor,
              opacity: addLocalVaultBusy ? 0.72 : 1
            }}
          >
            {addLocalVaultBusy ? text("Opening...") : "OneDrive"}
          </button>
          <button type="button" disabled style={disabledButtonStyle}>
            Dropbox ({text("Coming soon")})
          </button>
        </div>

        {addLocalVaultError ? (
          <div role="alert" style={errorPanelStyle}>
            {addLocalVaultError}
          </div>
        ) : null}
        {addLocalVaultError ? renderRuntimeErrorHelp?.(addLocalVaultErrorCause) : null}

        {recentVaults.length > 0 ? (
          <section aria-label={text("Recent vault records")} style={recordsSectionStyle}>
            <div style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
              <h2 style={sectionTitleStyle}>{text("Recent vault records")}</h2>
              <p style={subtitleStyle}>{text("This only removes the recent vault record.")}</p>
            </div>
            <div style={{ display: "grid", gap: archiveTheme.spacing.sm }}>
              {recentVaults.map((vault) => (
                <div key={vault.vaultRefId} style={recordRowStyle}>
                  <div style={{ display: "grid", gap: archiveTheme.spacing.xs, minWidth: 0 }}>
                    <strong style={recordTitleStyle}>{vault.displayName}</strong>
                    <small style={recordMetaStyle}>{vault.sourceSummary}</small>
                  </div>
                  <button
                    type="button"
                    aria-label={removeRecordLabel(language, vault.displayName)}
                    onClick={() => void onDeleteVault(vault.vaultRefId)}
                    style={dangerButtonStyle}
                  >
                    {text("Remove")}
                  </button>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <div style={footerActionsStyle}>
          <button type="button" onClick={onBack} style={secondaryButtonStyle}>
            {text("Back")}
          </button>
          <button type="button" onClick={onOpenExtensionSettings} style={secondaryButtonStyle}>
            {text("Extension Settings")}
          </button>
        </div>
      </section>
    </div>
  );
}

const shellStyle = {
  width: "min(680px, 100%)",
  display: "grid",
  gap: archiveTheme.spacing.lg,
  padding: archiveTheme.spacing.xl,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.shell,
  background: "rgba(255, 251, 244, 0.94)",
  boxShadow: archiveTheme.shadow.shell
};

const eyebrowStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.78rem",
  letterSpacing: "0.16em",
  textTransform: "uppercase" as const
};

const titleStyle = {
  margin: 0,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.display,
  fontSize: "2.6rem",
  fontWeight: 600
};

const subtitleStyle = {
  margin: 0,
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.body,
  lineHeight: 1.5
};

const primaryButtonStyle = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: archiveTheme.font.body,
  fontSize: "1rem",
  cursor: "pointer"
};

const secondaryButtonStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "1rem",
  cursor: "pointer"
};

const footerActionsStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  gap: archiveTheme.spacing.sm
};

const disabledButtonStyle = {
  ...secondaryButtonStyle,
  opacity: 0.6,
  cursor: "not-allowed"
};

const errorPanelStyle = {
  border: `1px solid ${archiveTheme.colors.danger}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: "rgba(139, 61, 42, 0.12)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body
};

const recordsSectionStyle = {
  display: "grid",
  gap: archiveTheme.spacing.sm,
  borderTop: `1px solid ${archiveTheme.colors.line}`,
  paddingTop: archiveTheme.spacing.md
};

const fileBrowserSectionStyle = {
  display: "grid",
  gap: archiveTheme.spacing.md,
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.md,
  background: "rgba(255, 248, 238, 0.96)",
  boxShadow: "0 14px 32px rgba(91, 58, 32, 0.14)"
};

const fileBrowserHeaderStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) auto",
  gap: archiveTheme.spacing.md,
  alignItems: "center",
  borderBottom: `1px solid ${archiveTheme.colors.line}`,
  paddingBottom: archiveTheme.spacing.sm
};

const fileBrowserEyebrowStyle = {
  color: archiveTheme.colors.accentStrong,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.75rem",
  letterSpacing: "0.12em",
  textTransform: "uppercase" as const
};

const fileBrowserCountStyle = {
  minWidth: "2.2rem",
  minHeight: "2.2rem",
  display: "inline-grid",
  placeItems: "center",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.pill,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.mono
};

const browserChromeStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: archiveTheme.colors.surface
};

const pathLabelStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.72rem",
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const
};

const breadcrumbStyle = {
  display: "flex",
  flexWrap: "wrap" as const,
  gap: archiveTheme.spacing.xs
};

const breadcrumbButtonStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: `${archiveTheme.spacing.xs} ${archiveTheme.spacing.sm}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.92rem",
  cursor: "pointer"
};

const breadcrumbCurrentButtonStyle = {
  borderColor: archiveTheme.colors.accentStrong,
  background: archiveTheme.colors.surfaceMuted,
  fontWeight: 700
};

const sectionTitleStyle = {
  margin: 0,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.display,
  fontSize: "1.1rem",
  fontWeight: 600
};

const recordRowStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) auto",
  gap: archiveTheme.spacing.sm,
  alignItems: "center",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: archiveTheme.colors.surfaceMuted,
  minWidth: 0
};

const vaultChoiceButtonStyle = {
  ...recordRowStyle,
  gridTemplateColumns: "auto minmax(0, 1fr)",
  width: "100%",
  textAlign: "left" as const,
  cursor: "pointer"
};

const fileListStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.xs,
  background: "rgba(255, 251, 244, 0.82)"
};

const fileTypeBadgeStyle = {
  minWidth: "6.6rem",
  display: "inline-grid",
  placeItems: "center",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: `${archiveTheme.spacing.xs} ${archiveTheme.spacing.sm}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.78rem",
  textTransform: "uppercase" as const
};

const recordTitleStyle = {
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  overflowWrap: "anywhere" as const
};

const recordMetaStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.body,
  overflowWrap: "anywhere" as const
};

const emptyStateStyle = {
  margin: 0,
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.body,
  lineHeight: 1.5
};

const dangerButtonStyle = {
  border: `1px solid ${archiveTheme.colors.danger}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: "rgba(139, 61, 42, 0.12)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.95rem",
  cursor: "pointer"
};

function formatFileSize(size: number | null, unknownLabel: string): string {
  if (size === null) {
    return unknownLabel;
  }
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${Math.round(size / 1024)} KB`;
  }
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
