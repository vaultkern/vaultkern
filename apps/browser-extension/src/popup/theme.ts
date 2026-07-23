export const popupTheme = {
  colors: {
    page: "#f5ecdc",
    pageShade: "#e4cfb0",
    surface: "rgba(255, 251, 244, 0.92)",
    surfaceMuted: "rgba(247, 236, 221, 0.88)",
    line: "rgba(63, 39, 19, 0.14)",
    text: "#261910",
    textMuted: "rgba(38, 25, 16, 0.68)",
    accent: "#af6d34",
    accentStrong: "#6c3e18",
    accentSoft: "#f3dfc7"
  },
  spacing: {
    xs: "8px",
    sm: "12px",
    md: "16px",
    lg: "24px"
  },
  radius: {
    panel: "22px",
    field: "14px",
    pill: "999px"
  },
  font: {
    body: '"Avenir Next", "Segoe UI", sans-serif',
    mono: '"IBM Plex Mono", "SFMono-Regular", monospace'
  }
} as const;

export const popupShellStyle = {
  width: "460px",
  maxWidth: "100%",
  maxHeight: "600px",
  minWidth: 0,
  display: "grid",
  gap: popupTheme.spacing.md,
  padding: popupTheme.spacing.md,
  background: `linear-gradient(180deg, ${popupTheme.colors.surface} 0%, ${popupTheme.colors.accentSoft} 100%)`,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  boxSizing: "border-box" as const,
  overflowX: "hidden" as const,
  overflowY: "auto" as const
};

export const popupPrimaryActionStyle = {
  border: `1px solid ${popupTheme.colors.accentStrong}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};

export const popupSecondaryActionStyle = {
  border: `1px solid ${popupTheme.colors.line}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};

export const popupPromptStyle = {
  display: "grid",
  gap: popupTheme.spacing.xs,
  border: `1px solid ${popupTheme.colors.accentStrong}`,
  borderRadius: popupTheme.radius.panel,
  padding: popupTheme.spacing.sm,
  background: popupTheme.colors.surface,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  lineHeight: 1.45
};

export const popupMessagePanelStyle = {
  borderRadius: popupTheme.radius.panel,
  padding: popupTheme.spacing.sm,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body
};
