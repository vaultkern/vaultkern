import type { EntryDetail, EntrySummary } from "@vaultkern/runtime-web-client";

export type GroupTreeNode = {
  id: string;
  title: string;
  depth: number;
  childCount: number;
  entryCount: number;
};

export type ManagerViewMode = "expanded" | "split" | "stacked";

export type StackedManagerStage = "groups" | "entries" | "detail";

export type EntryEditorMode = "view" | "edit" | "create-pending";

export type ManagerSelection = {
  selectedGroupId: string | null;
  selectedEntryId: string | null;
  selectedEntry: EntryDetail | null;
  entries: EntrySummary[];
};
