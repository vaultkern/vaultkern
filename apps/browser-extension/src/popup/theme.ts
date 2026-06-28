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

export function popupErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    const message = (error as { message: string }).message.trim();
    if (message) {
      return message;
    }
  }

  if (typeof error === "string" && error.trim()) {
    return error;
  }

  return fallback;
}
