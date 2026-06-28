import { useState } from "react";
import type { ReactNode } from "react";

import type { VaultReference } from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";

export function RecentVaultUnlockScreen({
  recentVaults,
  currentVaultRefId,
  labels = {
    eyebrow: "Private Archive",
    title: "Unlock your vault",
    subtitle: "Choose a recent vault, then unlock the current selection.",
    masterPassword: "Master Password",
    keyFilePath: "Key File Path",
    unlock: "Unlock Vault",
    unlocking: "Unlocking...",
    manageVaults: "Manage vaults",
    noRecentVaults: "No recent vaults",
    addFirstVault: "Open manager setup to add your first local vault.",
    local: "Local",
    needsRepair: "Needs repair in manager"
  },
  onSelectVault,
  onUnlock,
  onOpenSetup,
  error,
  renderRuntimeErrorHelp,
  errorCause,
  busy = false
}: {
  recentVaults: VaultReference[];
  currentVaultRefId: string | null;
  labels?: {
    eyebrow: string;
    title: string;
    subtitle: string;
    masterPassword: string;
    keyFilePath: string;
    unlock: string;
    unlocking: string;
    manageVaults: string;
    noRecentVaults: string;
    addFirstVault: string;
    local: string;
    needsRepair: string;
  };
  onSelectVault: (vaultRefId: string) => Promise<void>;
  onUnlock: (credentials: { password: string; keyFilePath: string }) => Promise<void>;
  onOpenSetup: () => void;
  error: string | null;
  errorCause?: unknown;
  busy?: boolean;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [password, setPassword] = useState("");
  const [keyFilePath, setKeyFilePath] = useState("");
  const currentVault =
    recentVaults.find((vault) => vault.vaultRefId === currentVaultRefId) ?? null;
  const needsRepair = currentVault?.availability === "needs_repair";

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
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) {
            void onUnlock({ password, keyFilePath });
          }
        }}
        style={shellStyle}
      >
        <div style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
          <span style={eyebrowStyle}>{labels.eyebrow}</span>
          <h1 style={titleStyle}>{labels.title}</h1>
          <p style={subtitleStyle}>{labels.subtitle}</p>
        </div>

        <div style={{ display: "grid", gap: archiveTheme.spacing.sm }}>
          {recentVaults.length > 0 ? (
            recentVaults.map((vault) => (
              <button
                key={vault.vaultRefId}
                type="button"
                aria-pressed={vault.vaultRefId === currentVaultRefId}
                onClick={() => {
                  if (!busy) {
                    void onSelectVault(vault.vaultRefId);
                  }
                }}
                disabled={busy}
                style={{
                  ...vaultButtonStyle,
                  cursor: busy ? "wait" : vaultButtonStyle.cursor,
                  opacity: busy ? 0.72 : 1,
                  borderColor:
                    vault.vaultRefId === currentVaultRefId
                      ? archiveTheme.colors.accentStrong
                      : archiveTheme.colors.line,
                  background:
                    vault.vaultRefId === currentVaultRefId
                      ? "rgba(177, 92, 56, 0.12)"
                      : archiveTheme.colors.surfaceMuted
                }}
              >
                <div style={{ display: "grid", gap: archiveTheme.spacing.xs, textAlign: "left" }}>
                  <strong>{vault.displayName}</strong>
                  <span style={metaStyle}>
                    {vault.sourceKind === "local" ? labels.local : vault.sourceKind}
                  </span>
                  <small style={subtitleStyle}>{vault.sourceSummary}</small>
                </div>
              </button>
            ))
          ) : (
            <div style={emptyStateStyle}>
              <strong>{labels.noRecentVaults}</strong>
              <p style={{ margin: 0 }}>{labels.addFirstVault}</p>
            </div>
          )}
        </div>

        {needsRepair ? (
          <div role="alert" style={repairStyle}>
            <div>{labels.needsRepair}</div>
            <button type="button" onClick={onOpenSetup} style={secondaryButtonStyle}>
              {labels.manageVaults}
            </button>
          </div>
        ) : null}

        <label style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
          {labels.masterPassword}
          <input
            aria-label={labels.masterPassword}
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={busy || recentVaults.length === 0 || needsRepair}
            style={fieldStyle}
          />
        </label>

        <label style={{ display: "grid", gap: archiveTheme.spacing.xs }}>
          {labels.keyFilePath}
          <input
            aria-label={labels.keyFilePath}
            type="text"
            value={keyFilePath}
            onChange={(event) => setKeyFilePath(event.target.value)}
            disabled={busy || recentVaults.length === 0 || needsRepair}
            style={fieldStyle}
          />
        </label>

        <div style={{ display: "flex", gap: archiveTheme.spacing.sm }}>
          <button
            type="submit"
            disabled={busy || !currentVault || needsRepair}
            style={{
              ...primaryButtonStyle,
              cursor: busy ? "wait" : primaryButtonStyle.cursor,
              opacity: busy ? 0.72 : 1
            }}
          >
            {busy ? labels.unlocking : labels.unlock}
          </button>
          <button
            type="button"
            onClick={onOpenSetup}
            disabled={busy}
            style={{
              ...secondaryButtonStyle,
              cursor: busy ? "wait" : secondaryButtonStyle.cursor,
              opacity: busy ? 0.72 : 1
            }}
          >
            {labels.manageVaults}
          </button>
        </div>

        {error ? (
          <div role="alert" style={repairStyle}>
            {error}
          </div>
        ) : null}
        {error && renderRuntimeErrorHelp ? renderRuntimeErrorHelp(errorCause) : null}
      </form>
    </div>
  );
}

const shellStyle = {
  width: "min(520px, 100%)",
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

const metaStyle = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.78rem",
  textTransform: "uppercase" as const
};

const vaultButtonStyle = {
  width: "100%",
  borderRadius: archiveTheme.radius.panel,
  border: `1px solid ${archiveTheme.colors.line}`,
  padding: archiveTheme.spacing.md,
  color: archiveTheme.colors.text,
  cursor: "pointer",
  boxSizing: "border-box" as const
};

const fieldStyle = {
  width: "100%",
  borderRadius: archiveTheme.radius.field,
  border: `1px solid ${archiveTheme.colors.line}`,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.98rem",
  boxSizing: "border-box" as const
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

const emptyStateStyle = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.md,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const repairStyle = {
  display: "grid",
  gap: archiveTheme.spacing.sm,
  borderRadius: archiveTheme.radius.field,
  padding: archiveTheme.spacing.sm,
  background: "rgba(139, 61, 42, 0.10)",
  color: archiveTheme.colors.danger,
  fontFamily: archiveTheme.font.body
};
