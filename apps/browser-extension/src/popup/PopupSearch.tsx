import { useEffect, useState } from "react";

import type { EntrySummary } from "@vaultkern/runtime-web-client";
import { showMoreText, useLanguage, useText } from "@vaultkern/shared-web-ui";
import { popupTheme } from "./theme";

const COLLAPSED_RESULT_LIMIT = 5;

export function PopupSearch({
  searchValue,
  onSearchChange,
  results,
  selectedEntryId,
  onSelectEntry
}: {
  searchValue: string;
  onSearchChange: (value: string) => void;
  results: EntrySummary[];
  selectedEntryId: string | null;
  onSelectEntry: (entryId: string) => void;
}) {
  const text = useText();
  const language = useLanguage();
  const [expanded, setExpanded] = useState(false);
  const hiddenCount = Math.max(0, results.length - COLLAPSED_RESULT_LIMIT);
  const visibleResults = expanded
    ? results
    : results.slice(0, COLLAPSED_RESULT_LIMIT);

  useEffect(() => {
    setExpanded(false);
  }, [searchValue]);

  return (
    <section style={{ display: "grid", gap: popupTheme.spacing.sm }}>
      <div
        style={{
          color: popupTheme.colors.textMuted,
          fontFamily: popupTheme.font.mono,
          fontSize: "0.72rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase"
        }}
      >
        {text("Search")}
      </div>
      <input
        aria-label={text("Search records")}
        placeholder={text("Search records")}
        value={searchValue}
        onChange={(event) => onSearchChange(event.target.value)}
        style={{
          width: "100%",
          borderRadius: popupTheme.radius.field,
          border: `1px solid ${popupTheme.colors.line}`,
          padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
          background: popupTheme.colors.surface,
          color: popupTheme.colors.text,
          fontFamily: popupTheme.font.body,
          boxSizing: "border-box"
        }}
      />
      {results.length > 0 ? (
        <ul
          style={{
            listStyle: "none",
            margin: 0,
            padding: 0,
            display: "grid",
            gap: popupTheme.spacing.xs
          }}
        >
          {visibleResults.map((entry) => {
            const selected = selectedEntryId === entry.id;
            return (
              <li key={entry.id}>
                <button
                  type="button"
                  onClick={() => onSelectEntry(entry.id)}
                  aria-label={entry.title}
                  aria-pressed={selected}
                  style={{
                    width: "100%",
                    display: "grid",
                    justifyItems: "start",
                    gap: popupTheme.spacing.xs,
                    border: `1px solid ${
                      selected
                        ? popupTheme.colors.accent
                        : popupTheme.colors.line
                    }`,
                    borderRadius: popupTheme.radius.field,
                    padding: popupTheme.spacing.sm,
                    background: selected
                      ? popupTheme.colors.accentSoft
                      : popupTheme.colors.surfaceMuted,
                    color: popupTheme.colors.text,
                    textAlign: "left",
                    fontFamily: popupTheme.font.body,
                    cursor: "pointer"
                  }}
                >
                  <span>{entry.title}</span>
                  <span
                    style={{
                      color: popupTheme.colors.textMuted,
                      fontSize: "0.82rem"
                    }}
                  >
                    {entry.username}
                  </span>
                </button>
              </li>
            );
          })}
          {hiddenCount > 0 ? (
            <li>
              <button
                type="button"
                onClick={() => setExpanded((value) => !value)}
                style={{
                  width: "100%",
                  border: `1px solid ${popupTheme.colors.line}`,
                  borderRadius: popupTheme.radius.field,
                  padding: popupTheme.spacing.sm,
                  background: "transparent",
                  color: popupTheme.colors.accentStrong,
                  fontFamily: popupTheme.font.body,
                  cursor: "pointer"
                }}
              >
                {expanded ? text("Show less") : showMoreText(language, hiddenCount)}
              </button>
            </li>
          ) : null}
        </ul>
      ) : null}
    </section>
  );
}
