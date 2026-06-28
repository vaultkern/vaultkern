import type { EntrySummary } from "@vaultkern/runtime-web-client";

import { EntryListPane } from "../layout/EntryListPane";
import { useText } from "../i18n";

export function VaultScreen({
  entries,
  loading,
  hasActiveVault,
  searchValue,
  error,
  selectedEntryId,
  onSelectEntry,
  onCreateEntry
}: {
  entries: EntrySummary[];
  loading: boolean;
  hasActiveVault: boolean;
  searchValue: string;
  error: string | null;
  selectedEntryId: string | null;
  onSelectEntry: (entryId: string) => void;
  onCreateEntry?: () => void;
}) {
  const text = useText();
  const normalizedQuery = searchValue.trim().toLowerCase();
  const filteredEntries = normalizedQuery
    ? entries.filter((entry) =>
        [entry.title, entry.username, entry.url].some((field) =>
          field.toLowerCase().includes(normalizedQuery)
        )
      )
    : entries;

  let emptyMessage = text("No entries available.");

  if (!hasActiveVault) {
    emptyMessage = text("Unlock a vault to browse entries.");
  } else if (normalizedQuery && filteredEntries.length === 0) {
    emptyMessage = text("No entries match your search.");
  } else if (entries.length === 0) {
    emptyMessage = text("No entries available.");
  }

  return (
    <div style={{ display: "grid", gap: "12px" }}>
      {error ? <div role="alert">{error}</div> : null}
      <EntryListPane
        entries={filteredEntries}
        loading={loading}
        emptyMessage={emptyMessage}
        selectedEntryId={selectedEntryId}
        onSelectEntry={onSelectEntry}
        onCreateEntry={onCreateEntry}
      />
    </div>
  );
}
