import { useText } from "@vaultkern/shared-web-ui";

import { popupTheme } from "./theme";

export function PopupStatusStrip({
  siteLabel,
  unlocked,
  onOpenManager,
  onOpenExtensionSettings
}: {
  siteLabel: string;
  unlocked: boolean;
  onOpenManager?: () => void;
  onOpenExtensionSettings?: () => void;
}) {
  const text = useText();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: popupTheme.spacing.sm,
        paddingBottom: popupTheme.spacing.sm,
        borderBottom: `1px solid ${popupTheme.colors.line}`
      }}
    >
      <div
        style={{
          display: "grid",
          gap: popupTheme.spacing.xs,
          minWidth: 0,
          flex: "1 1 auto"
        }}
      >
        <span
          style={{
            color: popupTheme.colors.textMuted,
            fontFamily: popupTheme.font.mono,
            fontSize: "0.72rem",
            letterSpacing: "0.12em",
            textTransform: "uppercase"
          }}
        >
          {text("Current site")}
        </span>
        <strong
          style={{
            color: popupTheme.colors.text,
            display: "block",
            fontSize: "0.95rem",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap"
          }}
        >
          {siteLabel === "No active site" ? text("No active site") : siteLabel}
        </strong>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
          flexWrap: "wrap",
          gap: popupTheme.spacing.sm,
          flexShrink: 0
        }}
      >
        <span
          style={{
            borderRadius: popupTheme.radius.pill,
            padding: `${popupTheme.spacing.xs} ${popupTheme.spacing.sm}`,
            background: unlocked
              ? popupTheme.colors.accentSoft
              : popupTheme.colors.surfaceMuted,
            color: popupTheme.colors.textMuted,
            fontFamily: popupTheme.font.mono,
            fontSize: "0.7rem",
            letterSpacing: "0.08em",
            textTransform: "uppercase"
          }}
        >
          {unlocked ? text("Unlocked") : text("Locked")}
        </span>
        {unlocked && onOpenManager ? (
          <button
            type="button"
            onClick={onOpenManager}
            style={buttonStyle}
          >
            {text("Open VaultKern")}
          </button>
        ) : null}
        {onOpenExtensionSettings ? (
          <button
            type="button"
            onClick={onOpenExtensionSettings}
            style={buttonStyle}
          >
            {text("VaultKern Settings")}
          </button>
        ) : null}
      </div>
    </div>
  );
}

const buttonStyle = {
  border: `1px solid ${popupTheme.colors.line}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.xs} ${popupTheme.spacing.sm}`,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  flexShrink: 0,
  cursor: "pointer"
};
