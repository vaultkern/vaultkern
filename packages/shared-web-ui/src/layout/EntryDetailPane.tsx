import type {
  EntryCustomField,
  EntryDetail,
  EntryHistoryDetail,
  EntryHistoryItem
} from "@vaultkern/runtime-web-client";

import { archiveTheme } from "../designTokens";
import { useText } from "../i18n";
import { EntryEditor } from "../screens/EntryEditor";
import type { EntryEditorMode } from "../types";

export function EntryDetailPane({
  entry,
  mode,
  draft,
  dirty,
  busy,
  error,
  historyItems,
  historyDetail,
  historyError,
  onBack,
  onStartEdit,
  onChangeDraft,
  onChangeCustomField,
  onAddCustomField,
  onDeleteCustomField,
  onDownloadAttachment,
  onAddAttachment,
  onRenameAttachment,
  onReplaceAttachment,
  onDeleteAttachment,
  onSelectHistoryItem,
  onSave,
  onCancel,
  onDelete
}: {
  entry: EntryDetail | null;
  mode: EntryEditorMode;
  draft: {
    title: string;
    username: string;
    password: string;
    url: string;
    notes: string;
    totpUri: string | null;
    customFields: EntryCustomField[];
  } | null;
  dirty: boolean;
  busy?: boolean;
  error?: string | null;
  historyItems?: EntryHistoryItem[];
  historyDetail?: EntryHistoryDetail | null;
  historyError?: string | null;
  onBack?: () => void;
  onStartEdit?: () => void;
  onChangeDraft: (field: "title" | "username" | "password" | "url" | "notes" | "totpUri", value: string) => void;
  onChangeCustomField: (
    index: number,
    field: keyof EntryCustomField,
    value: string | boolean
  ) => void;
  onAddCustomField: () => void;
  onDeleteCustomField: (index: number) => void;
  onDownloadAttachment?: (name: string) => void;
  onAddAttachment?: (file: File, protectInMemory: boolean) => void;
  onRenameAttachment?: (
    oldName: string,
    newName: string,
    protectInMemory: boolean
  ) => void;
  onReplaceAttachment?: (name: string, file: File) => void;
  onDeleteAttachment?: (name: string) => void;
  onSelectHistoryItem?: (historyIndex: number) => void;
  onSave: () => void;
  onCancel: () => void;
  onDelete?: () => void;
}) {
  const text = useText();
  return (
    <section
      aria-label={text("Entry Detail")}
      style={{
        display: "grid",
        gap: archiveTheme.spacing.md,
        alignContent: "start"
      }}
    >
      {onBack ? (
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
          {text("Back to entries")}
        </button>
      ) : null}
      {error ? (
        <div
          role="alert"
          style={{
            borderRadius: archiveTheme.radius.field,
            padding: archiveTheme.spacing.sm,
            background: "rgba(139, 61, 42, 0.10)",
            color: archiveTheme.colors.danger,
            fontFamily: archiveTheme.font.body
          }}
        >
          {error}
        </div>
      ) : null}
      <EntryEditor
        entry={entry}
        mode={mode}
        draft={draft}
        dirty={dirty}
        busy={busy}
        historyItems={historyItems}
        historyDetail={historyDetail}
        historyError={historyError}
        onStartEdit={onStartEdit}
        onChangeDraft={onChangeDraft}
        onChangeCustomField={onChangeCustomField}
        onAddCustomField={onAddCustomField}
        onDeleteCustomField={onDeleteCustomField}
        onDownloadAttachment={onDownloadAttachment}
        onAddAttachment={onAddAttachment}
        onRenameAttachment={onRenameAttachment}
        onReplaceAttachment={onReplaceAttachment}
        onDeleteAttachment={onDeleteAttachment}
        onSelectHistoryItem={onSelectHistoryItem}
        onSave={onSave}
        onCancel={onCancel}
        onDelete={onDelete}
      />
    </section>
  );
}
