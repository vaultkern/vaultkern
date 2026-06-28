import type { EntrySummary } from "@vaultkern/runtime-web-client";
import { useText } from "@vaultkern/shared-web-ui";
import { popupTheme } from "./theme";

export function SiteCandidateList({
  candidates,
  onFill,
  onSelectEntry
}: {
  candidates: EntrySummary[];
  onFill: (entryId: string) => void;
  onSelectEntry: (entryId: string) => void;
}) {
  const text = useText();

  if (candidates.length === 0) {
    return null;
  }

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
        {text("Suggested for this site")}
      </div>
      <div style={{ display: "grid", gap: popupTheme.spacing.xs }}>
        {candidates.map((entry) => (
          <div
            key={entry.id}
            style={{
              display: "grid",
              gap: popupTheme.spacing.xs,
              border: `1px solid ${popupTheme.colors.line}`,
              borderRadius: popupTheme.radius.field,
              padding: popupTheme.spacing.sm,
              background: popupTheme.colors.surfaceMuted,
              minWidth: 0
            }}
          >
            <button
              type="button"
              aria-label={entry.title}
              onClick={() => onSelectEntry(entry.id)}
              style={{
                border: "none",
                padding: 0,
                minWidth: 0,
                background: "transparent",
                color: popupTheme.colors.text,
                fontFamily: popupTheme.font.body,
                textAlign: "left",
                cursor: "pointer"
              }}
            >
              <div
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap"
                }}
              >
                {entry.title}
              </div>
              <div
                style={{
                  color: popupTheme.colors.textMuted,
                  fontSize: "0.82rem"
                }}
              >
                {entry.username}
              </div>
            </button>
            <button
              type="button"
              aria-label={`${text("Fill")} ${entry.title}`}
              onClick={() => onFill(entry.id)}
              style={{
                border: `1px solid ${popupTheme.colors.accentStrong}`,
                borderRadius: popupTheme.radius.pill,
                padding: `${popupTheme.spacing.xs} ${popupTheme.spacing.sm}`,
                background: popupTheme.colors.accentStrong,
                color: "#fffaf2",
                fontFamily: popupTheme.font.body,
                justifySelf: "start",
                cursor: "pointer"
              }}
            >
              {text("Fill")}
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}
