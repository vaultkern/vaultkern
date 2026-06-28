import type { VaultReference } from "@vaultkern/runtime-web-client";

import { popupTheme } from "./theme";

export function PopupVaultList({
  recentVaults,
  currentVaultRefId,
  onSelectVault,
  disabled = false
}: {
  recentVaults: VaultReference[];
  currentVaultRefId: string | null;
  onSelectVault: (vaultRefId: string) => Promise<void>;
  disabled?: boolean;
}) {
  return (
    <div style={{ display: "grid", gap: popupTheme.spacing.sm }}>
      {recentVaults.map((vault) => (
        <button
          key={vault.vaultRefId}
          type="button"
          onClick={() => void onSelectVault(vault.vaultRefId)}
          disabled={disabled}
          aria-pressed={vault.vaultRefId === currentVaultRefId}
          style={{
            display: "grid",
            gap: popupTheme.spacing.xs,
            textAlign: "left",
            borderRadius: popupTheme.radius.panel,
            border: `1px solid ${
              vault.vaultRefId === currentVaultRefId
                ? popupTheme.colors.accentStrong
                : popupTheme.colors.line
            }`,
            padding: popupTheme.spacing.sm,
            background:
              vault.vaultRefId === currentVaultRefId
                ? popupTheme.colors.accentSoft
                : popupTheme.colors.surfaceMuted,
            color: popupTheme.colors.text,
            fontFamily: popupTheme.font.body,
            cursor: disabled ? "wait" : "pointer",
            opacity: disabled ? 0.72 : 1
          }}
        >
          <strong>{vault.displayName}</strong>
          <span
            style={{
              color: popupTheme.colors.textMuted,
              fontFamily: popupTheme.font.mono,
              fontSize: "0.72rem",
              textTransform: "uppercase"
            }}
          >
            {vault.sourceKind === "local" ? "本地" : vault.sourceKind}
          </span>
          <small style={{ color: popupTheme.colors.textMuted }}>
            {vault.sourceSummary}
          </small>
        </button>
      ))}
    </div>
  );
}
