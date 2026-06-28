import type { CSSProperties, ReactNode } from "react";

import { archiveTheme } from "../designTokens";
import type { ManagerViewMode, StackedManagerStage } from "../types";

const panelStyle: CSSProperties = {
  minWidth: 0,
  boxSizing: "border-box",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.lg,
  background: archiveTheme.colors.surface,
  boxShadow: archiveTheme.shadow.panel
};

function renderContent({
  viewMode,
  groupTree,
  entryList,
  entryDetail,
  secondaryPage,
  showEntryDetail,
  stackedStage,
  showEntryListWithDetail
}: {
  viewMode: ManagerViewMode;
  groupTree: ReactNode;
  entryList: ReactNode;
  entryDetail: ReactNode;
  secondaryPage?: ReactNode;
  showEntryDetail: boolean;
  stackedStage: StackedManagerStage;
  showEntryListWithDetail: boolean;
}) {
  if (viewMode === "expanded") {
    return (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(220px, 280px) minmax(0, 1fr) minmax(0, 1.2fr)",
          gap: archiveTheme.spacing.lg,
          alignItems: "start",
          minWidth: 0
        }}
      >
        <div style={panelStyle}>{groupTree}</div>
        {secondaryPage ? (
          <div style={{ ...panelStyle, gridColumn: "2 / -1" }}>{secondaryPage}</div>
        ) : (
          <>
            <div style={panelStyle}>{entryList}</div>
            <div style={panelStyle}>{entryDetail}</div>
          </>
        )}
      </div>
    );
  }

  if (viewMode === "split") {
    return (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(200px, 260px) minmax(0, 1fr)",
          gap: archiveTheme.spacing.lg,
          alignItems: "start",
          minWidth: 0
        }}
      >
        <div style={panelStyle}>{groupTree}</div>
        <div style={panelStyle}>
          {secondaryPage ? (
            secondaryPage
          ) : showEntryDetail ? (
            showEntryListWithDetail ? (
              <div
                style={{
                  display: "grid",
                  gap: archiveTheme.spacing.md,
                  minWidth: 0
                }}
              >
                {entryList}
                {entryDetail}
              </div>
            ) : (
              entryDetail
            )
          ) : (
            entryList
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        display: "grid",
        gap: archiveTheme.spacing.lg
      }}
    >
      {secondaryPage ? <div style={panelStyle}>{secondaryPage}</div> : null}
      {!secondaryPage && stackedStage === "groups" ? (
        <div style={panelStyle}>{groupTree}</div>
      ) : null}
      {!secondaryPage && stackedStage === "entries" ? (
        <div style={panelStyle}>{entryList}</div>
      ) : null}
      {!secondaryPage && (stackedStage === "detail" || showEntryDetail) ? (
        <div style={panelStyle}>{entryDetail}</div>
      ) : null}
    </div>
  );
}

export function ManagerShell({
  viewMode,
  topBar,
  groupTree,
  entryList,
  entryDetail,
  secondaryPage,
  showEntryDetail,
  stackedStage,
  showEntryListWithDetail
}: {
  viewMode: ManagerViewMode;
  topBar: ReactNode;
  groupTree: ReactNode;
  entryList: ReactNode;
  entryDetail: ReactNode;
  secondaryPage?: ReactNode;
  showEntryDetail: boolean;
  stackedStage: StackedManagerStage;
  showEntryListWithDetail: boolean;
}) {
  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        boxSizing: "border-box",
        overflowX: "hidden",
        background: `radial-gradient(circle at top left, ${archiveTheme.colors.page} 0%, ${archiveTheme.colors.pageShade} 58%, #dbc29f 100%)`,
        color: archiveTheme.colors.text,
        padding: "clamp(16px, 4vw, 40px)",
        fontFamily: archiveTheme.font.body
      }}
    >
      <div
        style={{
          maxWidth: "1440px",
          width: "100%",
          boxSizing: "border-box",
          margin: "0 auto",
          display: "grid",
          gap: archiveTheme.spacing.xl,
          padding: "clamp(18px, 3vw, 32px)",
          border: `1px solid ${archiveTheme.colors.line}`,
          borderRadius: archiveTheme.radius.shell,
          background:
            "linear-gradient(180deg, rgba(255, 252, 246, 0.92) 0%, rgba(244, 233, 216, 0.88) 100%)",
          boxShadow: archiveTheme.shadow.shell
        }}
      >
        {topBar}
        {renderContent({
          viewMode,
          groupTree,
          entryList,
          entryDetail,
          secondaryPage,
          showEntryDetail,
          stackedStage,
          showEntryListWithDetail
        })}
      </div>
    </div>
  );
}
