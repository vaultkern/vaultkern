import type { CSSProperties } from "react";

import { archiveTheme } from "../designTokens";
import { useText } from "../i18n";
import type { GroupTreeNode } from "../types";

const headerStyle: CSSProperties = {
  color: archiveTheme.colors.textMuted,
  fontFamily: archiveTheme.font.mono,
  fontSize: "0.74rem",
  letterSpacing: "0.16em",
  textTransform: "uppercase"
};

export function GroupTreePane({
  groups,
  selectedGroupId,
  onSelectGroup
}: {
  groups: GroupTreeNode[];
  selectedGroupId: string | null;
  onSelectGroup: (groupId: string) => void;
}) {
  const text = useText();
  return (
    <aside
      aria-label={text("Groups")}
      style={{
        display: "grid",
        gap: archiveTheme.spacing.sm,
        alignContent: "start"
      }}
    >
      <div style={headerStyle}>{text("Groups")}</div>
      {groups.map((group) => {
        const selected = selectedGroupId === group.id;

        return (
          <button
            key={group.id}
            type="button"
            onClick={() => onSelectGroup(group.id)}
            aria-pressed={selected}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: archiveTheme.spacing.sm,
              width: "100%",
              boxSizing: "border-box",
              border: `1px solid ${selected ? archiveTheme.colors.accent : archiveTheme.colors.line}`,
              borderRadius: archiveTheme.radius.field,
              padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.sm} ${archiveTheme.spacing.sm} calc(${archiveTheme.spacing.sm} + ${group.depth * 18}px)`,
              background: selected
                ? archiveTheme.colors.accentSoft
                : archiveTheme.colors.surfaceMuted,
              color: archiveTheme.colors.text,
              fontFamily: archiveTheme.font.body,
              textAlign: "left",
              cursor: "pointer"
            }}
          >
            <span>{group.title}</span>
            <span
              aria-hidden="true"
              style={{
                color: archiveTheme.colors.textMuted,
                fontFamily: archiveTheme.font.mono,
                fontSize: "0.76rem"
              }}
            >
              {group.entryCount}
            </span>
          </button>
        );
      })}
    </aside>
  );
}
