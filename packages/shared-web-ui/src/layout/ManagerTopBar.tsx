import type { CSSProperties } from "react";

import { archiveTheme } from "../designTokens";

const titleStyle: CSSProperties = {
  display: "grid",
  gap: archiveTheme.spacing.xs,
  minWidth: 0
};

const searchStyle: CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  borderRadius: archiveTheme.radius.pill,
  border: `1px solid ${archiveTheme.colors.line}`,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  fontSize: "0.98rem"
};

const actionStyle: CSSProperties = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: archiveTheme.font.body,
  fontSize: "0.96rem",
  boxSizing: "border-box",
  cursor: "pointer"
};

export function ManagerTopBar({
  title = "The Archive",
  labels = {
    subtitle: "Private Archive",
    globalSearch: "Global Search",
    searchPlaceholder: "Search the archive",
    settings: "Settings",
    statistics: "Statistics"
  },
  searchValue,
  onSearchChange,
  onOpenStats,
  onOpenSettings
}: {
  title?: string;
  labels?: {
    subtitle: string;
    globalSearch: string;
    searchPlaceholder: string;
    settings: string;
    statistics: string;
  };
  searchValue: string;
  onSearchChange: (value: string) => void;
  onOpenStats: () => void;
  onOpenSettings: () => void;
}) {
  return (
    <header
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: archiveTheme.spacing.md,
        alignItems: "end"
      }}
    >
      <div style={{ ...titleStyle, flex: "1 1 220px" }}>
        <strong
          style={{
            fontFamily: archiveTheme.font.display,
            fontSize: "1.8rem",
            fontWeight: 600,
            letterSpacing: "0.04em"
          }}
        >
          {title}
        </strong>
        <span
          style={{
            color: archiveTheme.colors.textMuted,
            fontFamily: archiveTheme.font.mono,
            fontSize: "0.74rem",
            letterSpacing: "0.16em",
            textTransform: "uppercase"
          }}
        >
          {labels.subtitle}
        </span>
      </div>
      <label
        style={{
          flex: "999 1 320px",
          minWidth: 0,
          display: "grid",
          gap: archiveTheme.spacing.xs
        }}
      >
        <span
          style={{
            color: archiveTheme.colors.textMuted,
            fontFamily: archiveTheme.font.mono,
            fontSize: "0.72rem",
            letterSpacing: "0.12em",
            textTransform: "uppercase"
          }}
        >
          {labels.globalSearch}
        </span>
        <input
          aria-label={labels.globalSearch}
          placeholder={labels.searchPlaceholder}
          value={searchValue}
          onChange={(event) => onSearchChange(event.target.value)}
          style={searchStyle}
        />
      </label>
      <button
        type="button"
        onClick={onOpenSettings}
        style={{ ...actionStyle, flex: "0 0 auto" }}
      >
        {labels.settings}
      </button>
      <button
        type="button"
        onClick={onOpenStats}
        style={{ ...actionStyle, flex: "0 0 auto" }}
      >
        {labels.statistics}
      </button>
    </header>
  );
}
