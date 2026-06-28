import { archiveTheme } from "../designTokens";

export function ManagerSecondaryPage({
  title,
  description,
  onBack
}: {
  title: string;
  description: string;
  onBack: () => void;
}) {
  return (
    <section
      style={{
        display: "grid",
        gap: archiveTheme.spacing.md,
        alignContent: "start"
      }}
    >
      <button
        type="button"
        onClick={onBack}
        style={{
          justifySelf: "start",
          border: `1px solid ${archiveTheme.colors.line}`,
          borderRadius: archiveTheme.radius.pill,
          padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
          background: archiveTheme.colors.surfaceMuted,
          color: archiveTheme.colors.text,
          fontFamily: archiveTheme.font.body,
          cursor: "pointer"
        }}
      >
        Back to archive
      </button>
      <div
        style={{
          display: "grid",
          gap: archiveTheme.spacing.sm
        }}
      >
        <h2
          style={{
            margin: 0,
            color: archiveTheme.colors.text,
            fontFamily: archiveTheme.font.display,
            fontSize: "2rem",
            fontWeight: 600
          }}
        >
          {title}
        </h2>
        <p
          style={{
            margin: 0,
            color: archiveTheme.colors.textMuted,
            fontFamily: archiveTheme.font.body,
            lineHeight: 1.6
          }}
        >
          {description}
        </p>
      </div>
    </section>
  );
}
