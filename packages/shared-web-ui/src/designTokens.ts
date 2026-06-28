export const archiveTheme = {
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
    accentSoft: "#f3dfc7",
    danger: "#8b3d2a"
  },
  spacing: {
    xs: "8px",
    sm: "12px",
    md: "16px",
    lg: "24px",
    xl: "32px"
  },
  radius: {
    shell: "30px",
    panel: "22px",
    field: "14px",
    pill: "999px"
  },
  shadow: {
    shell: "0 28px 80px rgba(83, 51, 23, 0.16)",
    panel: "0 18px 40px rgba(77, 49, 25, 0.10)"
  },
  font: {
    display: '"Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif',
    body: '"Avenir Next", "Segoe UI", sans-serif',
    mono: '"IBM Plex Mono", "SFMono-Regular", monospace'
  }
} as const;
