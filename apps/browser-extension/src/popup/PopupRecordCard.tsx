import { useEffect, useRef, useState } from "react";

import type { EntryDetail, EntrySummary } from "@vaultkern/runtime-web-client";
import { useText } from "@vaultkern/shared-web-ui";

import { copyFieldValue } from "./copyField";
import { popupTheme } from "./theme";

export function PopupRecordCard({
  entry,
  loadDetail,
  onFill,
  clearClipboardSeconds = 0
}: {
  entry: EntrySummary | null;
  loadDetail: () => Promise<EntryDetail | null>;
  onFill: () => void;
  clearClipboardSeconds?: number;
}) {
  const text = useText();
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showPasswordEntryId, setShowPasswordEntryId] = useState<string | null>(null);
  const [detailState, setDetailState] = useState<{
    entryId: string;
    detail: EntryDetail;
  } | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const entryId = entry?.id ?? null;
  const selectionVersionRef = useRef(0);
  const previousEntryIdRef = useRef(entryId);
  if (previousEntryIdRef.current !== entryId) {
    previousEntryIdRef.current = entryId;
    selectionVersionRef.current += 1;
  }
  const detail = detailState?.entryId === entryId ? detailState.detail : null;
  const showPassword = showPasswordEntryId === entryId;
  const totp =
    typeof detail?.totp === "string" && detail.totp !== "" ? detail.totp : null;

  useEffect(() => {
    setShowPasswordEntryId(null);
    setDetailState(null);
    setDetailError(null);
  }, [entryId]);

  async function ensureDetail() {
    if (!entryId) {
      return null;
    }
    if (detail) {
      return detail;
    }
    const requestedEntryId = entryId;
    const requestedSelectionVersion = selectionVersionRef.current;
    try {
      const loadedDetail = await loadDetail();
      if (
        loadedDetail &&
        previousEntryIdRef.current === requestedEntryId &&
        selectionVersionRef.current === requestedSelectionVersion
      ) {
        setDetailState({ entryId: requestedEntryId, detail: loadedDetail });
        setDetailError(null);
        return loadedDetail;
      }
      return null;
    } catch (error) {
      if (
        previousEntryIdRef.current === requestedEntryId &&
        selectionVersionRef.current === requestedSelectionVersion
      ) {
        setDetailError(
          error instanceof Error ? error.message : text("Failed to load record detail")
        );
      }
      return null;
    }
  }

  async function handleCopy(kind: string, value: string) {
    await copyFieldValue(value, clearClipboardSeconds);
    setCopiedField(kind);
    window.setTimeout(() => {
      setCopiedField((current) => (current === kind ? null : current));
    }, 1200);
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
        {text("Selected record")}
      </div>
      <div
        style={{
          display: "grid",
          gap: popupTheme.spacing.sm,
          border: `1px solid ${popupTheme.colors.line}`,
          borderRadius: popupTheme.radius.panel,
          padding: popupTheme.spacing.md,
          background: popupTheme.colors.surface
        }}
      >
        {entry ? (
          <>
            <strong
              style={{
                color: popupTheme.colors.text,
                fontSize: "1rem",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap"
              }}
            >
              {entry.title}
            </strong>
            <FieldButton
              label={`Copy username ${entry.username}`}
              copied={copiedField === "username"}
              value={entry.username}
              onClick={() => handleCopy("username", entry.username)}
            />
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "minmax(0, 1fr) auto",
                gap: popupTheme.spacing.xs,
                alignItems: "stretch"
              }}
            >
              <FieldButton
                label={
                  text("Copy") === "复制"
                    ? `${text("Copy")} ${text("Password")}`
                    : "Copy password"
                }
                copied={copiedField === "password"}
                value={showPassword && detail ? detail.password : "••••••••••"}
                onClick={async () => {
                  const loadedDetail = await ensureDetail();
                  if (loadedDetail) {
                    await handleCopy("password", loadedDetail.password);
                  }
                }}
              />
              <button
                type="button"
                aria-label={showPassword ? text("Hide password") : text("Show password")}
                onClick={() => {
                  if (showPassword) {
                    setShowPasswordEntryId(null);
                    return;
                  }
                  const requestedEntryId = entryId;
                  const requestedSelectionVersion = selectionVersionRef.current;
                  void ensureDetail().then((loadedDetail) => {
                    if (
                      loadedDetail &&
                      requestedEntryId &&
                      previousEntryIdRef.current === requestedEntryId &&
                      selectionVersionRef.current === requestedSelectionVersion
                    ) {
                      setShowPasswordEntryId(requestedEntryId);
                    }
                  });
                }}
                style={toggleActionStyle}
              >
                {showPassword ? text("Hide password") : text("Show password")}
              </button>
            </div>
            {totp ? (
              <FieldButton
                label={`Copy TOTP ${totp}`}
                copied={copiedField === "totp"}
                value={totp}
                onClick={() => handleCopy("totp", totp)}
              />
            ) : null}
            {detailError ? (
              <div role="alert" style={{ color: popupTheme.colors.accentStrong }}>
                {detailError}
              </div>
            ) : null}
            <div
              style={{
                color: popupTheme.colors.textMuted,
                fontSize: "0.82rem",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap"
              }}
            >
              {entry.url}
            </div>
            <div
              style={{
                display: "grid",
                gap: popupTheme.spacing.xs
              }}
            >
              <button type="button" onClick={onFill} style={primaryActionStyle}>
                {text("Fill")}
              </button>
            </div>
          </>
        ) : (
          <div style={{ color: popupTheme.colors.textMuted }}>
            {text("Select a record to inspect fields.")}
          </div>
        )}
      </div>
    </section>
  );
}

function FieldButton({
  label,
  value,
  copied,
  onClick
}: {
  label: string;
  value: string;
  copied: boolean;
  onClick: () => void;
}) {
  const text = useText();
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: popupTheme.spacing.sm,
        width: "100%",
        minWidth: 0,
        border: `1px solid ${popupTheme.colors.line}`,
        borderRadius: popupTheme.radius.field,
        padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
        background: copied ? popupTheme.colors.accentSoft : popupTheme.colors.surfaceMuted,
        color: popupTheme.colors.text,
        fontFamily: popupTheme.font.body,
        cursor: "pointer"
      }}
    >
      <span
        style={{
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap"
        }}
      >
        {value}
      </span>
      <span
        style={{
          color: popupTheme.colors.textMuted,
          fontSize: "0.78rem"
        }}
      >
        {copied ? text("Copied") : text("Copy")}
      </span>
    </button>
  );
}

const primaryActionStyle = {
  border: `1px solid ${popupTheme.colors.accentStrong}`,
  borderRadius: popupTheme.radius.pill,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.accentStrong,
  color: "#fffaf2",
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};

const toggleActionStyle = {
  border: `1px solid ${popupTheme.colors.line}`,
  borderRadius: popupTheme.radius.field,
  padding: `${popupTheme.spacing.sm} ${popupTheme.spacing.md}`,
  background: popupTheme.colors.surfaceMuted,
  color: popupTheme.colors.text,
  fontFamily: popupTheme.font.body,
  cursor: "pointer"
};
