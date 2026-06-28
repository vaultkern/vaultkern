import type { CSSProperties } from "react";

import type { EntrySummary } from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";
import { useText } from "../i18n";

const headerStyle: CSSProperties = {
  minWidth: 0,
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.74rem",
  letterSpacing: "0.16em",
  textTransform: "uppercase"
};

export function EntryListPane({
  entries,
  selectedEntryId,
  onSelectEntry,
  onCreateEntry,
  loading,
  emptyMessage
}: {
  entries: EntrySummary[];
  selectedEntryId: string | null;
  onSelectEntry: (entryId: string) => void;
  onCreateEntry?: () => void;
  loading?: boolean;
  emptyMessage?: string;
}) {
  const text = useText();
  return (
    <section
      aria-label={text("Entries")}
      style={{
        display: "grid",
        gap: archiveTheme.spacing.sm,
        minWidth: 0,
        alignContent: "start"
      }}
    >
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: archiveTheme.spacing.sm
        }}
      >
        <div style={headerStyle}>{text("Entries")}</div>
        {onCreateEntry ? (
          <button
            type="button"
            onClick={onCreateEntry}
            style={{
              maxWidth: "100%",
              border: `1px solid ${archiveTheme.colors.accentStrong}`,
              borderRadius: archiveTheme.radius.pill,
              padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
              background: archiveTheme.colors.accentStrong,
              color: "#fffaf2",
              fontFamily: archiveTheme.font.body,
              fontSize: "0.92rem",
              boxSizing: "border-box",
              cursor: "pointer"
            }}
          >
            {text("New Entry")}
          </button>
        ) : null}
      </div>
      {loading ? (
        <div
          style={{
            color: archiveTheme.colors.textMuted,
            fontFamily: archiveTheme.font.body
          }}
        >
          {text("Loading entries...")}
        </div>
      ) : null}
      {!loading && entries.length === 0 ? (
        <div
          style={{
            color: archiveTheme.colors.textMuted,
            fontFamily: archiveTheme.font.body
          }}
        >
          {emptyMessage ?? text("No entries available.")}
        </div>
      ) : null}
      {!loading
        ? entries.map((entry) => {
            const selected = selectedEntryId === entry.id;

            return (
              <button
                key={entry.id}
                type="button"
                aria-label={entry.title}
                aria-pressed={selected}
                onClick={() => onSelectEntry(entry.id)}
                style={{
                  display: "grid",
                  gap: archiveTheme.spacing.xs,
                  justifyItems: "start",
                  border: `1px solid ${selected ? archiveTheme.colors.accent : archiveTheme.colors.line}`,
                  borderRadius: archiveTheme.radius.panel,
                  padding: archiveTheme.spacing.md,
                  background: selected
                    ? archiveTheme.colors.accentSoft
                    : archiveTheme.colors.surface,
                  boxShadow: archiveTheme.shadow.panel,
                  color: archiveTheme.colors.text,
                  fontFamily: archiveTheme.font.body,
                  width: "100%",
                  boxSizing: "border-box",
                  textAlign: "left",
                  cursor: "pointer"
                }}
              >
                <span
                  style={{
                    fontSize: "1rem",
                    fontWeight: 600,
                    minWidth: 0,
                    maxWidth: "100%",
                    overflowWrap: "anywhere"
                  }}
                >
                  {entry.title}
                </span>
                <span
                  aria-hidden="true"
                  style={{
                    color: archiveTheme.colors.textMuted,
                    fontSize: "0.92rem",
                    minWidth: 0,
                    maxWidth: "100%",
                    overflowWrap: "anywhere"
                  }}
                >
                  {entry.username}
                </span>
              </button>
            );
          })
        : null}
    </section>
  );
}
