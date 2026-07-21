import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  DatabaseSettings,
  DatabaseSettingsCommitResult,
  DatabaseSettingsUpdate,
  EntryAttachmentContent,
  EntryAttachmentContentUpdate,
  EntryAttachmentInput,
  EntryAttachmentMetadataUpdate,
  EntryDetail,
  EntryDraft,
  EntryHistoryDetail,
  EntryHistoryItem,
  EntryPasskey,
  EntryPasskeyUpdate,
  EntrySummary,
  GroupNode,
  GroupTree,
  OneDriveAuthSession,
  OneDriveAuthStatus,
  OneDriveItem,
  SaveVaultResult,
  SessionState,
  VaultSourceStatus,
  UnlockCredentials,
  VaultHandle,
  VaultReference
} from "@vaultkern/runtime-web-client";

import { archiveTheme } from "./designTokens";
import { errorMessage } from "./error";
import {
  DEFAULT_EXTENSION_SETTINGS,
  createMemoryExtensionSettingsStore,
  normalizeBrowserExtensionSettings,
  normalizeWindowsAppSettings,
  sortRecentVaultsForRetention
} from "./extensionSettings";
import type {
  ExtensionSettings,
  ExtensionSettingsReconciliationReason,
  ExtensionSettingsStore
} from "./extensionSettings";
import { I18nProvider, deleteEntryDescription, translate } from "./i18n";
import { DatabaseSettingsPage } from "./screens/DatabaseSettingsPage";
import { ExtensionSettingsPanel } from "./screens/ExtensionSettingsPanel";
import { EntryDetailPane } from "./layout/EntryDetailPane";
import { GroupTreePane } from "./layout/GroupTreePane";
import { ManagerSecondaryPage } from "./layout/ManagerSecondaryPage";
import { ManagerShell } from "./layout/ManagerShell";
import { ManagerTopBar } from "./layout/ManagerTopBar";
import type {
  GroupTreeNode,
  EntryEditorMode,
  ManagerSelection,
  ManagerViewMode,
  StackedManagerStage
} from "./types";
import { FillCandidatesPanel } from "./screens/FillCandidatesPanel";
import { RecentVaultUnlockScreen } from "./screens/RecentVaultUnlockScreen";
import { VaultSetupScreen } from "./screens/VaultSetupScreen";
import { VaultScreen } from "./screens/VaultScreen";

export interface RuntimeClientLike {
  getSessionState(): Promise<SessionStateLike>;
  listRecentVaults(): Promise<VaultReference[]>;
  addLocalVaultReference(path?: string): Promise<VaultReference>;
  beginOneDriveLogin(): Promise<OneDriveAuthSession>;
  completePendingOneDriveLogin(): Promise<OneDriveAuthStatus>;
  listOneDriveChildren(parentItemId?: string | null): Promise<OneDriveItem[]>;
  addOneDriveVaultReference(driveId: string, itemId: string): Promise<VaultReference>;
  setCurrentVault(vaultRefId: string): Promise<SessionStateLike>;
  retryVaultSourceSync(vaultId: string): Promise<VaultSourceStatus>;
  deleteRecentVault(vaultRefId: string): Promise<VaultReference[]>;
  deleteRecentVaultIfNotCurrent(vaultRefId: string): Promise<VaultReference[]>;
  openLocalVault(path: string): Promise<VaultHandle>;
  unlockCurrentVaultWithPassword(password: string): Promise<SessionStateLike>;
  unlockCurrentVault(credentials: UnlockCredentials): Promise<SessionStateLike>;
  enableQuickUnlockForCurrentVault(credentials: UnlockCredentials): Promise<SessionStateLike>;
  unlockCurrentVaultWithQuickUnlock(): Promise<SessionStateLike>;
  disableQuickUnlockForCurrentVault(): Promise<SessionStateLike>;
  unlockWithPassword(vaultId: string, password: string): Promise<SessionStateLike>;
  unlockVault(vaultId: string, credentials: UnlockCredentials): Promise<SessionStateLike>;
  lockSession?(): Promise<SessionStateLike>;
  listGroups(vaultId: string): Promise<GroupTree>;
  listEntries(vaultId: string): Promise<EntrySummary[]>;
  getEntryDetail(vaultId: string, entryId: string): Promise<EntryDetail>;
  createEntry(vaultId: string, input: EntryDraft & { parentGroupId: string }): Promise<EntryDetail>;
  updateEntryFields(vaultId: string, entryId: string, input: EntryDraft): Promise<EntryDetail>;
  setEntryPasskey(
    vaultId: string,
    entryId: string,
    passkey: EntryPasskeyUpdate
  ): Promise<EntryDetail>;
  clearEntryPasskey(vaultId: string, entryId: string): Promise<EntryDetail>;
  deleteEntry(vaultId: string, entryId: string): Promise<void>;
  saveVault(vaultId: string): Promise<SaveVaultResult | void>;
  getDatabaseSettings(vaultId: string): Promise<DatabaseSettings>;
  updateDatabaseSettings(
    vaultId: string,
    update: DatabaseSettingsUpdate
  ): Promise<DatabaseSettingsCommitResult>;
  getEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<EntryAttachmentContent>;
  addEntryAttachment(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentInput
  ): Promise<EntryDetail>;
  updateEntryAttachmentMetadata(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentMetadataUpdate
  ): Promise<EntryDetail>;
  replaceEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentContentUpdate
  ): Promise<EntryDetail>;
  deleteEntryAttachment(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<EntryDetail>;
  listEntryHistory(vaultId: string, entryId: string): Promise<EntryHistoryItem[]>;
  getEntryHistoryDetail(
    vaultId: string,
    entryId: string,
    historyIndex: number
  ): Promise<EntryHistoryDetail>;
}

export interface OneDrivePathSegment {
  itemId: string;
  name: string;
}

function browsableOneDriveItems(items: OneDriveItem[]) {
  return items
    .filter((item) => item.folder || item.name.toLowerCase().endsWith(".kdbx"))
    .sort((left, right) =>
      Number(right.folder) - Number(left.folder) || left.name.localeCompare(right.name)
    );
}

type SessionStateLike = Pick<
  SessionState,
  "unlocked" | "activeVaultId" | "currentVaultRefId" | "sourceStatus"
> & {
  supportsBiometricUnlock?: boolean;
};

function actualCurrentVaultReference(
  vaults: VaultReference[],
  session: SessionStateLike | null
) {
  return (
    vaults.find((vault) => vault.vaultRefId === session?.currentVaultRefId) ??
    vaults.find((vault) => vault.isCurrent) ??
    null
  );
}

interface FillHooks {
  findCandidates(vaultId: string): Promise<EntrySummary[]>;
  fillEntry(vaultId: string, entryId: string): Promise<void>;
}

type PendingAction =
  | { type: "select-entry"; entryId: string }
  | { type: "select-group"; groupId: string }
  | { type: "back-to-entries" }
  | { type: "new-entry" }
  | { type: "search"; value: string }
  | { type: "open-stats" }
  | { type: "open-database-settings" }
  | { type: "close-database-settings" }
  | { type: "open-extension-settings" }
  | { type: "close-extension-settings" };

type DialogState =
  | { type: "unsaved"; action: PendingAction }
  | { type: "delete-entry"; entryId: string; title: string };

interface PendingEntrySave {
  vaultId: string;
  detail: EntryDetail;
}

interface PendingEntryDelete {
  vaultId: string;
  entryId: string;
}

interface PendingAttachmentSave extends PendingEntrySave {
  fallbackMessage: string;
}

const COMPACT_BREAKPOINT = 1180;
const STACKED_BREAKPOINT = 760;

function getViewMode(width: number): ManagerViewMode {
  if (width < STACKED_BREAKPOINT) {
    return "stacked";
  }

  if (width < COMPACT_BREAKPOINT) {
    return "split";
  }

  return "expanded";
}

function flattenGroups(root: GroupNode): GroupTreeNode[] {
  const groups: GroupTreeNode[] = [];

  function visit(node: GroupNode, depth: number) {
    groups.push({
      id: node.id,
      title: node.title,
      depth,
      childCount: node.childCount,
      entryCount: node.entryCount
    });

    for (const child of node.children) {
      visit(child, depth + 1);
    }
  }

  visit(root, 0);
  return groups;
}

function buildDescendantIndex(root: GroupNode): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();

  function visit(node: GroupNode): Set<string> {
    const descendants = new Set<string>([node.id]);

    for (const child of node.children) {
      for (const groupId of visit(child)) {
        descendants.add(groupId);
      }
    }

    index.set(node.id, descendants);
    return descendants;
  }

  visit(root);
  return index;
}

function filterEntries(
  entries: EntrySummary[],
  searchValue: string,
  selectedGroupId: string | null,
  descendantIndex: Map<string, Set<string>>
): EntrySummary[] {
  const normalizedQuery = searchValue.trim().toLowerCase();
  const scopedEntries =
    normalizedQuery || !selectedGroupId
      ? entries
      : entries.filter((entry) =>
          descendantIndex.get(selectedGroupId)?.has(entry.groupId ?? "") ?? false
        );

  if (!normalizedQuery) {
    return scopedEntries;
  }

  return scopedEntries.filter((entry) =>
    [entry.title, entry.username, entry.url].some((field) =>
      field.toLowerCase().includes(normalizedQuery)
    )
  );
}

const APP_LABELS = {
  en: {
    topBar: {
      subtitle: "Private Archive",
      globalSearch: "Global Search",
      searchPlaceholder: "Search the archive",
      settings: "Database Settings",
      extensionSettings: "Windows Settings",
      statistics: "Statistics"
    },
    unlock: {
      eyebrow: "Private Archive",
      title: "Unlock your vault",
      subtitle: "Choose a recent vault, then unlock the current selection.",
      masterPassword: "Master Password",
      keyFilePath: "Key File Path",
      unlock: "Unlock Vault",
      unlocking: "Unlocking...",
      unlockWithWindowsHello: "Unlock with Windows Hello",
      manageVaults: "Manage vaults",
      extensionSettings: "Windows Settings",
      noRecentVaults: "No recent vaults",
      addFirstVault: "Open manager setup to add your first local vault.",
      local: "Local",
      needsRepair: "Needs repair in manager"
    }
  },
  "zh-CN": {
    topBar: {
      subtitle: "私人档案",
      globalSearch: "全局搜索",
      searchPlaceholder: "搜索数据库",
      settings: "数据库设置",
      extensionSettings: "Windows 设置",
      statistics: "统计"
    },
    unlock: {
      eyebrow: "私人档案",
      title: "解锁数据库",
      subtitle: "选择最近数据库，然后解锁当前选择。",
      masterPassword: "主密码",
      keyFilePath: "密钥文件路径",
      unlock: "解锁数据库",
      unlocking: "解锁中...",
      unlockWithWindowsHello: "使用 Windows Hello 解锁",
      manageVaults: "管理数据库",
      extensionSettings: "Windows 设置",
      noRecentVaults: "没有最近数据库",
      addFirstVault: "打开管理器设置并添加第一个本地数据库。",
      local: "本地",
      needsRepair: "需要在管理器中修复"
    }
  }
};

export function App({
  client,
  fillHooks,
  extensionSettingsStore,
  renderRuntimeErrorHelp
}: {
  client: RuntimeClientLike;
  fillHooks?: FillHooks;
  extensionSettingsStore?: ExtensionSettingsStore;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [localExtensionSettingsStore] = useState(() =>
    extensionSettingsStore ?? createMemoryExtensionSettingsStore()
  );
  const settingsSurface = localExtensionSettingsStore.surface ?? "windows";
  const normalizeSettings =
    settingsSurface === "browser"
      ? normalizeBrowserExtensionSettings
      : normalizeWindowsAppSettings;
  const [session, setSession] = useState<SessionStateLike | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionErrorCause, setSessionErrorCause] = useState<unknown>(null);
  const [viewMode, setViewMode] = useState<ManagerViewMode>(() =>
    typeof window === "undefined" ? "expanded" : getViewMode(window.innerWidth)
  );
  const [stackedStage, setStackedStage] = useState<StackedManagerStage>("groups");
  const [searchValue, setSearchValue] = useState("");
  const [showStatsPage, setShowStatsPage] = useState(false);
  const [showDatabaseSettingsPage, setShowDatabaseSettingsPage] = useState(false);
  const [showExtensionSettingsPage, setShowExtensionSettingsPage] = useState(false);
  const [databaseSettings, setDatabaseSettings] = useState<DatabaseSettings | null>(null);
  const [databaseSettingsError, setDatabaseSettingsError] = useState<string | null>(null);
  const [databaseSettingsBusy, setDatabaseSettingsBusy] = useState(false);
  const databaseSettingsDraftUpdate = useRef<DatabaseSettingsUpdate | null>(null);
  const [databaseSettingsDraftDirty, setDatabaseSettingsDraftDirty] = useState(false);
  const databaseSettingsSaveInFlight = useRef<Promise<boolean> | null>(null);
  const [databaseName, setDatabaseName] = useState<string | null>(null);
  const [groupTree, setGroupTree] = useState<GroupTree | null>(null);
  const [groupsError, setGroupsError] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [entriesError, setEntriesError] = useState<string | null>(null);
  const [entryDetail, setEntryDetail] = useState<EntryDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [historyItems, setHistoryItems] = useState<EntryHistoryItem[]>([]);
  const [historyDetail, setHistoryDetail] = useState<EntryHistoryDetail | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<EntryEditorMode>("view");
  const [draft, setDraft] = useState<EntryDraft | null>(null);
  const [pendingEntrySave, setPendingEntrySave] = useState<PendingEntrySave | null>(
    null
  );
  const [pendingPasskeySave, setPendingPasskeySave] = useState<PendingEntrySave | null>(
    null
  );
  const [pendingAttachmentSave, setPendingAttachmentSave] =
    useState<PendingAttachmentSave | null>(null);
  const [pendingEntryDelete, setPendingEntryDelete] =
    useState<PendingEntryDelete | null>(null);
  const [entryActionError, setEntryActionError] = useState<string | null>(null);
  const [dialogState, setDialogState] = useState<DialogState | null>(null);
  const [entryActionBusy, setEntryActionBusy] = useState(false);
  const [saveAndContinueBusy, setSaveAndContinueBusy] = useState(false);
  const saveDraftInFlight = useRef<Promise<boolean> | null>(null);
  const entryDraftBaseline = useRef<EntryDetail | null>(null);
  const secretViewEpoch = useRef(0);
  const historyDetailRequestEpoch = useRef(0);
  const saveAndContinueInFlight = useRef(false);
  const [showEntryListWithDetail, setShowEntryListWithDetail] = useState(false);
  const [workspaceReloadKey, setWorkspaceReloadKey] = useState(0);
  const [sourceDetailReloadKey, setSourceDetailReloadKey] = useState(0);
  const handledSourceDetailReloadKey = useRef(0);
  const [fillCandidates, setFillCandidates] = useState<EntrySummary[]>([]);
  const [fillError, setFillError] = useState<string | null>(null);
  const [recentVaults, setRecentVaults] = useState<VaultReference[]>([]);
  const [showSetup, setShowSetup] = useState(false);
  const [setupAddError, setSetupAddError] = useState<string | null>(null);
  const [setupAddErrorCause, setSetupAddErrorCause] = useState<unknown>(null);
  const [setupAddBusy, setSetupAddBusy] = useState(false);
  const [oneDriveVaultChoices, setOneDriveVaultChoices] = useState<OneDriveItem[]>([]);
  const [oneDriveBrowserActive, setOneDriveBrowserActive] = useState(false);
  const [oneDriveBrowserPath, setOneDriveBrowserPath] = useState<OneDrivePathSegment[]>([]);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockErrorCause, setUnlockErrorCause] = useState<unknown>(null);
  const [unlockBusy, setUnlockBusy] = useState(false);
  const [saveTip, setSaveTip] = useState<string | null>(null);
  const [sourceSyncBusy, setSourceSyncBusy] = useState(false);
  const [sourceSyncError, setSourceSyncError] = useState<string | null>(null);
  const [extensionSettings, setExtensionSettings] =
    useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [extensionSettingsError, setExtensionSettingsError] = useState<string | null>(
    null
  );
  const [extensionSettingsSaving, setExtensionSettingsSaving] = useState(false);
  const extensionSettingsSaveInFlight = useRef<Promise<boolean> | null>(null);
  const settingsReconciliationTail = useRef<Promise<void>>(Promise.resolve());
  const recentVaultReconciliationEpoch = useRef(0);
  const extensionSettingsDraft = useRef<ExtensionSettings | null>(null);
  const [extensionSettingsDraftDirty, setExtensionSettingsDraftDirty] =
    useState(false);
  const [settingsDraftEpoch, setSettingsDraftEpoch] = useState(0);
  const [quickUnlockBusy, setQuickUnlockBusy] = useState(false);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);
  const [settingsReconciliationError, setSettingsReconciliationError] =
    useState<string | null>(null);
  const handleDatabaseSettingsDraftChange = useCallback(
    (update: DatabaseSettingsUpdate | null, dirty: boolean) => {
      databaseSettingsDraftUpdate.current = update;
      setDatabaseSettingsDraftDirty(dirty);
    },
    []
  );
  const handleExtensionSettingsDraftChange = useCallback(
    (settings: ExtensionSettings, dirty: boolean) => {
      extensionSettingsDraft.current = settings;
      setExtensionSettingsDraftDirty(dirty);
    },
    []
  );

  async function reloadLockedState() {
    const [nextSession, nextRecentVaults] = await Promise.all([
      client.getSessionState(),
      client.listRecentVaults()
    ]);
    setSession(nextSession);
    await applyRecentVaultLimit(nextRecentVaults);
  }

  async function applyRecentVaultLimit(
    vaults: VaultReference[],
    reconciliationEpoch = recentVaultReconciliationEpoch.current
  ) {
    let remainingVaults = sortRecentVaultsForRetention(vaults);

    while (reconciliationEpoch === recentVaultReconciliationEpoch.current) {
      const desired = normalizeSettings(
        await localExtensionSettingsStore.load()
      );
      if (reconciliationEpoch !== recentVaultReconciliationEpoch.current) {
        return;
      }
      remainingVaults = sortRecentVaultsForRetention(
        await client.listRecentVaults()
      );
      if (reconciliationEpoch !== recentVaultReconciliationEpoch.current) {
        return;
      }
      const sortedVaults = remainingVaults;
      const nextOverflowVault = sortedVaults[desired.recentVaultLimit];
      if (!nextOverflowVault) {
        setRecentVaults(sortedVaults);
        return;
      }

      remainingVaults = await client.deleteRecentVaultIfNotCurrent(
        nextOverflowVault.vaultRefId
      );
    }
  }

  function saveExtensionSettings(nextSettings: ExtensionSettings) {
    if (extensionSettingsSaveInFlight.current) {
      return extensionSettingsSaveInFlight.current;
    }

    const operation = persistExtensionSettings(nextSettings);
    extensionSettingsSaveInFlight.current = operation;
    void operation.finally(() => {
      if (extensionSettingsSaveInFlight.current === operation) {
        extensionSettingsSaveInFlight.current = null;
      }
    });
    return operation;
  }

  async function persistExtensionSettings(nextSettings: ExtensionSettings) {
    setExtensionSettingsSaving(true);
    setExtensionSettingsError(null);

    try {
      const normalizedSettings = normalizeSettings(nextSettings);
      await localExtensionSettingsStore.save(normalizedSettings);
      setExtensionSettings(normalizedSettings);
      void reconcileSavedSettings("settings-commit", session);
      return true;
    } catch (saveFailure) {
      setExtensionSettingsError(
        errorMessage(
          saveFailure,
          translate(extensionSettings.language, "Failed to save extension settings")
        )
      );
      return false;
    } finally {
      setExtensionSettingsSaving(false);
    }
  }

  function reconcileSavedSettings(
    reason: ExtensionSettingsReconciliationReason,
    currentSession: SessionStateLike | null,
    credentials?: UnlockCredentials
  ): Promise<void> {
    if (
      reason === "manual" &&
      credentials &&
      localExtensionSettingsStore.nativeReconciliationOwned === true &&
      localExtensionSettingsStore.queueQuickUnlockEnrollment
    ) {
      return handoffNativeQuickUnlockEnrollment(credentials);
    }

    const reconciliationEpoch = ++recentVaultReconciliationEpoch.current;
    const run = () =>
      runSavedSettingsReconciliation(
        currentSession,
        credentials,
        reconciliationEpoch
      );
    const operation = settingsReconciliationTail.current.then(run, run);
    settingsReconciliationTail.current = operation.catch(() => undefined);
    return operation;
  }

  async function handoffNativeQuickUnlockEnrollment(
    credentials: UnlockCredentials
  ): Promise<void> {
    setQuickUnlockError(null);
    setQuickUnlockBusy(true);
    try {
      const desired = normalizeSettings(
        await localExtensionSettingsStore.load()
      );
      if (!desired.quickUnlockEnabled) {
        return;
      }
      await localExtensionSettingsStore.queueQuickUnlockEnrollment!(credentials);
    } catch (quickUnlockFailure) {
      setQuickUnlockError(
        errorMessage(
          quickUnlockFailure,
          translate(extensionSettings.language, "Failed to update quick unlock")
        )
      );
    } finally {
      setQuickUnlockBusy(false);
    }
  }

  async function runSavedSettingsReconciliation(
    currentSession: SessionStateLike | null,
    credentials: UnlockCredentials | undefined,
    reconciliationEpoch: number
  ): Promise<void> {
    setQuickUnlockError(null);
    setSettingsReconciliationError(null);
    let desired: ExtensionSettings;
    try {
      desired = normalizeSettings(await localExtensionSettingsStore.load());
    } catch (loadFailure) {
      console.error("failed to read desired settings for reconciliation", loadFailure);
      return;
    }

    const platformOwnsQuickUnlock =
      localExtensionSettingsStore.nativeReconciliationOwned === true;

    let vaults: VaultReference[];
    try {
      vaults = await client.listRecentVaults();
    } catch (vaultListFailure) {
      console.error("settings reconciliation could not list recent vaults", vaultListFailure);
      return;
    }
    try {
      await applyRecentVaultLimit(vaults, reconciliationEpoch);
    } catch (recentVaultFailure) {
      console.error("settings reconciliation could not trim recent vaults", recentVaultFailure);
    }

    if (settingsSurface === "browser") {
      return;
    }

    if (platformOwnsQuickUnlock) {
      return;
    }

    const currentVault = actualCurrentVaultReference(vaults, currentSession);
    const enabled = desired.quickUnlockEnabled;
    if (
      !currentVault ||
      currentVault.supportsQuickUnlock === enabled ||
      (enabled && (!currentSession?.unlocked || !credentials))
    ) {
      return;
    }
    try {
      const latestDesired = normalizeSettings(
        await localExtensionSettingsStore.load()
      );
      if (latestDesired.quickUnlockEnabled !== enabled) {
        return;
      }
    } catch (loadFailure) {
      console.error(
        "settings reconciliation could not confirm quick unlock state",
        loadFailure
      );
      return;
    }

    setQuickUnlockBusy(true);
    try {
      let nextSession: SessionStateLike;
      if (enabled) {
        const enrollmentCredentials = credentials;
        if (!enrollmentCredentials) {
          return;
        }
        nextSession = await client.enableQuickUnlockForCurrentVault(
          enrollmentCredentials
        );
      } else {
        nextSession = await client.disableQuickUnlockForCurrentVault();
      }
      setSession(nextSession);
    } catch (quickUnlockFailure) {
      setQuickUnlockError(
        errorMessage(
          quickUnlockFailure,
          translate(extensionSettings.language, "Failed to update quick unlock")
        )
      );
    } finally {
      setQuickUnlockBusy(false);
    }
    try {
      await applyRecentVaultLimit(
        await client.listRecentVaults(),
        reconciliationEpoch
      );
    } catch (vaultRefreshFailure) {
      console.error(
        "settings reconciliation could not refresh recent vaults",
        vaultRefreshFailure
      );
    }
  }

  function resetEditorState(nextMode: EntryEditorMode = "view") {
    entryDraftBaseline.current = null;
    setEditorMode(nextMode);
    setDraft(null);
    setPendingEntrySave(null);
    setEntryActionError(null);
    setDialogState(null);
  }

  function resetDatabaseSettingsDraftState() {
    databaseSettingsDraftUpdate.current = null;
    setDatabaseSettingsDraftDirty(false);
  }

  function resetExtensionSettingsDraftState() {
    extensionSettingsDraft.current = null;
    setExtensionSettingsDraftDirty(false);
  }

  function discardAllDrafts() {
    resetEditorState();
    resetDatabaseSettingsDraftState();
    resetExtensionSettingsDraftState();
    setSettingsDraftEpoch((current) => current + 1);
  }

  function clearDetailSelection() {
    secretViewEpoch.current += 1;
    historyDetailRequestEpoch.current += 1;
    setEntryDetail(null);
    setDetailError(null);
    setHistoryItems([]);
    setHistoryDetail(null);
    setHistoryError(null);
    setSelectedEntryId(null);
    setShowEntryListWithDetail(false);
    resetEditorState();
  }

  function handleSaveResult(result: SaveVaultResult | void) {
    if (
      result &&
      (result.status === "saved" ||
        result.status === "merged" ||
        result.status === "saved_to_cache")
    ) {
      void reconcileSavedSettings("vault-save", session);
    }
    if (result?.status === "merged") {
      setSaveTip(
        translate(extensionSettings.language, "Vault changed on disk. Merged and saved.")
      );
      setSourceDetailReloadKey((current) => current + 1);
    } else if (result?.status === "saved_to_cache") {
      setSaveTip(
        translate(extensionSettings.language, "Saved to local cache. Remote sync pending.")
      );
      setSession((current) =>
        current
          ? {
              ...current,
              sourceStatus: {
                sourceKind: current.sourceStatus?.sourceKind ?? "remote",
                remoteState: "pending_sync",
                lastSyncAt: current.sourceStatus?.lastSyncAt ?? null,
                cachedAt: current.sourceStatus?.cachedAt ?? null,
                lastError: current.sourceStatus?.lastError ?? null
              }
            }
          : current
      );
    } else if (result?.status === "conflict_copy") {
      setSaveTip(
        result.conflictCopyPath
          ? `${translate(
              extensionSettings.language,
              "Vault changed on disk. Local edits were saved to a conflict copy:"
            )} ${result.conflictCopyPath}`
          : translate(
              extensionSettings.language,
              "Vault changed on disk. Local edits were saved as a conflict copy."
            )
      );
    }
  }

  async function handleRetrySourceSync() {
    if (!session?.activeVaultId) {
      return;
    }

    setSourceSyncBusy(true);
    setSourceSyncError(null);

    try {
      const sourceStatus = await client.retryVaultSourceSync(session.activeVaultId);
      setSession((current) => (current ? { ...current, sourceStatus } : current));
      if (sourceStatus.remoteState === "online") {
        setWorkspaceReloadKey((current) => current + 1);
        setSourceDetailReloadKey((current) => current + 1);
        setSaveTip(translate(extensionSettings.language, "Remote sync restored."));
      } else if (sourceStatus.lastError) {
        setSourceSyncError(sourceStatus.lastError);
      }
    } catch (syncFailure) {
      setSourceSyncError(
        errorMessage(
          syncFailure,
          translate(extensionSettings.language, "Failed to retry remote sync")
        )
      );
    } finally {
      setSourceSyncBusy(false);
    }
  }

  async function handleAddLocalVault() {
    setSetupAddBusy(true);
    setSetupAddError(null);
    setSetupAddErrorCause(null);

    try {
      await client.addLocalVaultReference();
      setShowSetup(false);
      await reloadLockedState();
    } catch (addFailure) {
      setSetupAddError(
        errorMessage(
          addFailure,
          translate(extensionSettings.language, "Failed to add local vault")
        )
      );
      setSetupAddErrorCause(addFailure);
    } finally {
      setSetupAddBusy(false);
    }
  }

  async function handleAddOneDriveVault() {
    setSetupAddBusy(true);
    setSetupAddError(null);
    setSetupAddErrorCause(null);
    setOneDriveVaultChoices([]);
    setOneDriveBrowserActive(false);
    setOneDriveBrowserPath([]);

    try {
      const auth = await client.beginOneDriveLogin();
      window.open(auth.authUrl, "_blank", "noopener,noreferrer");
      await client.completePendingOneDriveLogin();
      const items = await client.listOneDriveChildren(null);
      setOneDriveVaultChoices(browsableOneDriveItems(items));
      setOneDriveBrowserActive(true);
    } catch (addFailure) {
      setSetupAddError(
        errorMessage(
          addFailure,
          translate(extensionSettings.language, "Failed to add OneDrive vault")
        )
      );
      setSetupAddErrorCause(addFailure);
    } finally {
      setSetupAddBusy(false);
    }
  }

  async function handleOpenOneDriveFolder(folder: OneDriveItem) {
    setSetupAddBusy(true);
    setSetupAddError(null);
    setSetupAddErrorCause(null);

    try {
      const items = await client.listOneDriveChildren(folder.itemId);
      setOneDriveVaultChoices(browsableOneDriveItems(items));
      setOneDriveBrowserPath((current) => [
        ...current,
        { itemId: folder.itemId, name: folder.name }
      ]);
      setOneDriveBrowserActive(true);
    } catch (addFailure) {
      setSetupAddError(
        errorMessage(
          addFailure,
          translate(extensionSettings.language, "Failed to add OneDrive vault")
        )
      );
      setSetupAddErrorCause(addFailure);
    } finally {
      setSetupAddBusy(false);
    }
  }

  async function handleOpenOneDrivePath(index: number) {
    setSetupAddBusy(true);
    setSetupAddError(null);
    setSetupAddErrorCause(null);

    try {
      const target = index >= 0 ? oneDriveBrowserPath[index] : null;
      const items = await client.listOneDriveChildren(target?.itemId ?? null);
      setOneDriveVaultChoices(browsableOneDriveItems(items));
      setOneDriveBrowserPath((current) => current.slice(0, index + 1));
      setOneDriveBrowserActive(true);
    } catch (addFailure) {
      setSetupAddError(
        errorMessage(
          addFailure,
          translate(extensionSettings.language, "Failed to add OneDrive vault")
        )
      );
      setSetupAddErrorCause(addFailure);
    } finally {
      setSetupAddBusy(false);
    }
  }

  async function handleSelectOneDriveVault(vault: OneDriveItem) {
    setSetupAddBusy(true);
    setSetupAddError(null);
    setSetupAddErrorCause(null);

    try {
      await client.addOneDriveVaultReference(vault.driveId, vault.itemId);
      setOneDriveVaultChoices([]);
      setOneDriveBrowserActive(false);
      setOneDriveBrowserPath([]);
      setShowSetup(false);
      await reloadLockedState();
    } catch (addFailure) {
      setSetupAddError(
        errorMessage(
          addFailure,
          translate(extensionSettings.language, "Failed to add OneDrive vault")
        )
      );
      setSetupAddErrorCause(addFailure);
    } finally {
      setSetupAddBusy(false);
    }
  }

  function handleSearchChangeImmediate(value: string) {
    setSearchValue(value);
    setShowStatsPage(false);

    if (viewMode !== "expanded") {
      clearDetailSelection();
    }

    if (viewMode === "stacked" && value.trim()) {
      setStackedStage("entries");
    }
  }

  const pendingDetailSave = pendingAttachmentSave || pendingPasskeySave;
  const hasPendingEntrySave = Boolean(pendingEntrySave || pendingDetailSave);
  const hasPendingDurableSave = hasPendingEntrySave || Boolean(pendingEntryDelete);
  const draftDirty =
    editorMode === "create-pending"
      ? hasDraftChangesFromEmpty(draft)
      : editorMode === "edit" && entryDetail && draft
        ? !draftMatchesEntry(draft, entryDetail)
        : false;
  const dirty =
    hasPendingDurableSave ||
    draftDirty ||
    (showDatabaseSettingsPage && databaseSettingsDraftDirty) ||
    (showExtensionSettingsPage && extensionSettingsDraftDirty);
  const idleLockBlocked =
    dirty ||
    entryActionBusy ||
    saveAndContinueBusy ||
    databaseSettingsBusy ||
    extensionSettingsSaving ||
    sourceSyncBusy ||
    setupAddBusy ||
    unlockBusy ||
    quickUnlockBusy;

  function performAction(action: PendingAction) {
    setDialogState(null);
    secretViewEpoch.current += 1;
    historyDetailRequestEpoch.current += 1;
    switch (action.type) {
      case "select-entry":
        setEntryDetail(null);
        setDetailError(null);
        setSelectedEntryId(action.entryId);
        setShowStatsPage(false);
        setShowEntryListWithDetail(false);
        resetEditorState();

        if (viewMode === "stacked") {
          setStackedStage("detail");
        }
        break;
      case "select-group":
        setSelectedGroupId(action.groupId);
        setShowStatsPage(false);
        clearDetailSelection();

        if (viewMode === "stacked") {
          setStackedStage("entries");
        }
        break;
      case "back-to-entries":
        clearDetailSelection();

        if (viewMode === "stacked") {
          setStackedStage("entries");
        }
        break;
      case "new-entry":
        setShowStatsPage(false);
        setSelectedEntryId(null);
        setEntryDetail(null);
        setDetailError(null);
        setEntryActionError(null);
        setShowEntryListWithDetail(true);
        setDraft(createEmptyDraft());
        setEditorMode("create-pending");

        if (viewMode === "stacked") {
          setStackedStage("detail");
        }
        break;
      case "search":
        setShowEntryListWithDetail(false);
        resetEditorState();
        handleSearchChangeImmediate(action.value);
        break;
      case "open-stats":
        setShowEntryListWithDetail(false);
        resetEditorState();
        resetDatabaseSettingsDraftState();
        resetExtensionSettingsDraftState();
        setShowDatabaseSettingsPage(false);
        setShowExtensionSettingsPage(false);
        setShowStatsPage(true);
        break;
      case "open-database-settings":
        setShowEntryListWithDetail(false);
        resetEditorState();
        resetDatabaseSettingsDraftState();
        resetExtensionSettingsDraftState();
        setShowStatsPage(false);
        setShowExtensionSettingsPage(false);
        setShowDatabaseSettingsPage(true);
        break;
      case "close-database-settings":
        resetDatabaseSettingsDraftState();
        setShowDatabaseSettingsPage(false);
        break;
      case "open-extension-settings":
        setShowEntryListWithDetail(false);
        resetEditorState();
        resetDatabaseSettingsDraftState();
        resetExtensionSettingsDraftState();
        setShowStatsPage(false);
        setShowDatabaseSettingsPage(false);
        setShowExtensionSettingsPage(true);
        break;
      case "close-extension-settings":
        resetExtensionSettingsDraftState();
        setShowExtensionSettingsPage(false);
        break;
    }
  }

  function requestAction(action: PendingAction) {
    if (dirty) {
      setDialogState({ type: "unsaved", action });
      return;
    }

    performAction(action);
  }

  function handleSelectEntry(entryId: string) {
    requestAction({ type: "select-entry", entryId });
  }

  function handleBackToEntries() {
    requestAction({ type: "back-to-entries" });
  }

  function handleSearchChange(value: string) {
    requestAction({ type: "search", value });
  }

  function saveDraft() {
    if (saveDraftInFlight.current) {
      return saveDraftInFlight.current;
    }

    const operation = saveDraftOnce();
    saveDraftInFlight.current = operation;
    void operation.finally(() => {
      if (saveDraftInFlight.current === operation) {
        saveDraftInFlight.current = null;
      }
    });
    return operation;
  }

  async function saveDraftOnce() {
    if (!session?.activeVaultId || !draft) {
      return false;
    }

    const vaultId = session.activeVaultId;
    const wasCreating = editorMode === "create-pending";
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      let detail: EntryDetail;

      if (pendingEntrySave) {
        if (pendingEntrySave.vaultId !== vaultId) {
          throw new Error("The pending entry belongs to another vault");
        }

        detail = pendingEntrySave.detail;
        if (!draftMatchesEntry(draft, detail)) {
          detail = await client.updateEntryFields(vaultId, detail.id, draft);
          setPendingEntrySave({ vaultId, detail });
        }
      } else if (wasCreating) {
        detail = await client.createEntry(vaultId, {
          parentGroupId: selectedGroupId ?? groupTree?.root.id ?? "",
          ...draft
        });
      } else if (editorMode === "edit" && selectedEntryId) {
        detail = await client.updateEntryFields(vaultId, selectedEntryId, draft);
      } else {
        return false;
      }

      setPendingEntrySave({ vaultId, detail });
      handleSaveResult(await client.saveVault(vaultId));
      setEntryDetail(detail);
      if (wasCreating) {
        setSelectedEntryId(detail.id);
        setShowEntryListWithDetail(true);
      } else {
        setShowEntryListWithDetail(false);
      }

      resetEditorState();
      setWorkspaceReloadKey((current) => current + 1);
      return true;
    } catch (mutationError) {
      setEntryActionError(
        errorMessage(
          mutationError,
          translate(extensionSettings.language, "Failed to save entry changes")
        )
      );
      return false;
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function handleSaveAndContinue(action: PendingAction) {
    if (saveAndContinueInFlight.current) {
      return;
    }
    saveAndContinueInFlight.current = true;
    setSaveAndContinueBusy(true);

    try {
      const pendingDelete = pendingEntryDelete;
      const hadDatabaseSettingsDraft = Boolean(
        showDatabaseSettingsPage &&
          databaseSettingsDraftDirty &&
          databaseSettingsDraftUpdate.current
      );
      const handledDatabaseSettings = hadDatabaseSettingsDraft;
      const hadExtensionSettingsDraft = Boolean(
        showExtensionSettingsPage &&
          extensionSettingsDraftDirty &&
          extensionSettingsDraft.current
      );
      let saved = hadDatabaseSettingsDraft
        ? await handleSaveDatabaseSettings(databaseSettingsDraftUpdate.current!)
        : hadExtensionSettingsDraft
            ? await saveExtensionSettings(extensionSettingsDraft.current!)
            : pendingDelete
              ? await handleDeleteEntry(pendingDelete.entryId)
            : pendingDetailSave
              ? await retryPendingDetailSave()
              : true;
      if (
        saved &&
        !handledDatabaseSettings &&
        !hadExtensionSettingsDraft &&
        !pendingDelete &&
        (draftDirty || !pendingDetailSave)
      ) {
        saved = await saveDraft();
      }

      if (saved) {
        performAction(action);
      }
    } finally {
      saveAndContinueInFlight.current = false;
      setSaveAndContinueBusy(false);
    }
  }

  function renderUnsavedChangesDialog() {
    if (dialogState?.type !== "unsaved") {
      return null;
    }

    return (
      <ConfirmationDialog
        title={translate(extensionSettings.language, "You have unsaved changes")}
        description={translate(
          extensionSettings.language,
          showDatabaseSettingsPage && databaseSettingsDraftDirty
              ? "Save your database settings before leaving, discard your edits, or continue editing."
              : showExtensionSettingsPage && extensionSettingsDraftDirty
                ? "Save your extension settings before leaving, discard your edits, or continue editing."
                : hasPendingEntrySave || pendingEntryDelete
                  ? "This entry changed in the current session but is not durable yet. Retry saving before leaving it."
                  : "Save before leaving this entry, discard your edits, or continue editing."
        )}
        actions={[
          {
            label: translate(extensionSettings.language, "Save changes"),
            variant: "primary",
            disabled: saveAndContinueBusy,
            onClick: () => {
              void handleSaveAndContinue(dialogState.action);
            }
          },
          ...(hasPendingDurableSave
            ? []
            : [
                {
                  label: translate(extensionSettings.language, "Discard changes"),
                  disabled: saveAndContinueBusy,
                  onClick: () => {
                    discardAllDrafts();
                    performAction(dialogState.action);
                  }
                }
              ]),
          {
            label: translate(extensionSettings.language, "Continue editing"),
            disabled: saveAndContinueBusy,
            onClick: () => setDialogState(null)
          }
        ]}
      />
    );
  }

  async function handleDeleteEntry(entryId: string) {
    if (!session?.activeVaultId) {
      return false;
    }

    const vaultId = session.activeVaultId;
    let mutationApplied =
      pendingEntryDelete?.vaultId === vaultId && pendingEntryDelete.entryId === entryId;
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      if (pendingEntryDelete && !mutationApplied) {
        throw new Error("Another entry deletion is pending");
      }
      if (!mutationApplied) {
        await client.deleteEntry(vaultId, entryId);
        mutationApplied = true;
        setPendingEntryDelete({ vaultId, entryId });
      }
      handleSaveResult(await client.saveVault(vaultId));
      setPendingEntryDelete(null);
      clearDetailSelection();
      setWorkspaceReloadKey((current) => current + 1);
      setDialogState(null);
      return true;
    } catch (deleteError) {
      setEntryActionError(
        errorMessage(
          deleteError,
          translate(extensionSettings.language, "Failed to delete entry")
        )
      );
      if (!mutationApplied) {
        setDialogState(null);
      }
      return false;
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function handleSetEntryPasskey(passkey: EntryPasskeyUpdate) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    const vaultId = session.activeVaultId;
    const entryId = selectedEntryId;
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const detail = await client.setEntryPasskey(vaultId, entryId, passkey);
      setEntryDetail(detail);
      setPendingPasskeySave({ vaultId, detail });
      handleSaveResult(await client.saveVault(vaultId));
      setPendingPasskeySave(null);
      setWorkspaceReloadKey((current) => current + 1);
    } catch (passkeyError) {
      setEntryActionError(
        errorMessage(
          passkeyError,
          translate(extensionSettings.language, "Failed to save entry passkey")
        )
      );
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function handleClearEntryPasskey() {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    const vaultId = session.activeVaultId;
    const entryId = selectedEntryId;
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const detail = await client.clearEntryPasskey(vaultId, entryId);
      setEntryDetail(detail);
      setPendingPasskeySave({ vaultId, detail });
      handleSaveResult(await client.saveVault(vaultId));
      setPendingPasskeySave(null);
      setWorkspaceReloadKey((current) => current + 1);
    } catch (passkeyError) {
      setEntryActionError(
        errorMessage(
          passkeyError,
          translate(extensionSettings.language, "Failed to save entry passkey")
        )
      );
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function retryPendingPasskeySave() {
    if (!pendingPasskeySave) {
      return false;
    }

    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      handleSaveResult(await client.saveVault(pendingPasskeySave.vaultId));
      setPendingPasskeySave(null);
      setWorkspaceReloadKey((current) => current + 1);
      return true;
    } catch (passkeyError) {
      setEntryActionError(
        errorMessage(
          passkeyError,
          translate(extensionSettings.language, "Failed to save entry passkey")
        )
      );
      return false;
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function handleDownloadAttachment(name: string) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    setEntryActionError(null);
    const requestEpoch = secretViewEpoch.current;

    try {
      const content = await client.getEntryAttachmentContent(
        session.activeVaultId,
        selectedEntryId,
        name
      );
      if (requestEpoch !== secretViewEpoch.current) {
        return;
      }
      triggerAttachmentDownload(content);
    } catch (downloadError) {
      setEntryActionError(
        errorMessage(
          downloadError,
          translate(extensionSettings.language, "Failed to download attachment")
        )
      );
    }
  }

  async function updateAttachment(
    operation: () => Promise<EntryDetail>,
    fallbackMessage: string
  ) {
    if (!session?.activeVaultId) {
      return;
    }

    const vaultId = session.activeVaultId;
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const detail = await operation();
      setEntryDetail(detail);
      setPendingAttachmentSave({ vaultId, detail, fallbackMessage });
      handleSaveResult(await client.saveVault(vaultId));
      setPendingAttachmentSave(null);
      setWorkspaceReloadKey((current) => current + 1);
    } catch (attachmentError) {
      setEntryActionError(errorMessage(attachmentError, fallbackMessage));
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function retryPendingAttachmentSave() {
    if (!pendingAttachmentSave) {
      return false;
    }

    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      handleSaveResult(await client.saveVault(pendingAttachmentSave.vaultId));
      setPendingAttachmentSave(null);
      setWorkspaceReloadKey((current) => current + 1);
      return true;
    } catch (attachmentError) {
      setEntryActionError(
        errorMessage(attachmentError, pendingAttachmentSave.fallbackMessage)
      );
      return false;
    } finally {
      setEntryActionBusy(false);
    }
  }

  async function retryPendingDetailSave() {
    if (pendingAttachmentSave) {
      return retryPendingAttachmentSave();
    }
    if (pendingPasskeySave) {
      return retryPendingPasskeySave();
    }
    return false;
  }

  async function handleAddAttachment(file: File, protectInMemory: boolean) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    const dataBase64 = await fileToBase64(file);
    await updateAttachment(
      () =>
        client.addEntryAttachment(session.activeVaultId!, selectedEntryId, {
          name: file.name,
          dataBase64,
          protectInMemory
        }),
      translate(extensionSettings.language, "Failed to add attachment")
    );
  }

  async function handleRenameAttachment(
    oldName: string,
    newName: string,
    protectInMemory: boolean
  ) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    await updateAttachment(
      () =>
        client.updateEntryAttachmentMetadata(session.activeVaultId!, selectedEntryId, {
          oldName,
          newName,
          protectInMemory
        }),
      translate(extensionSettings.language, "Failed to update attachment")
    );
  }

  async function handleReplaceAttachment(name: string, file: File) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    const dataBase64 = await fileToBase64(file);
    await updateAttachment(
      () =>
        client.replaceEntryAttachmentContent(session.activeVaultId!, selectedEntryId, {
          name,
          dataBase64
        }),
      translate(extensionSettings.language, "Failed to replace attachment")
    );
  }

  async function handleDeleteAttachment(name: string) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    await updateAttachment(
      () => client.deleteEntryAttachment(session.activeVaultId!, selectedEntryId, name),
      translate(extensionSettings.language, "Failed to delete attachment")
    );
  }

  function runDatabaseSettingsSave(operation: () => Promise<boolean>) {
    if (databaseSettingsSaveInFlight.current) {
      return databaseSettingsSaveInFlight.current;
    }

    const promise = operation();
    databaseSettingsSaveInFlight.current = promise;
    void promise.finally(() => {
      if (databaseSettingsSaveInFlight.current === promise) {
        databaseSettingsSaveInFlight.current = null;
      }
    });
    return promise;
  }

  function handleSaveDatabaseSettings(update: DatabaseSettingsUpdate) {
    return runDatabaseSettingsSave(() => saveDatabaseSettings(update));
  }

  async function saveDatabaseSettings(update: DatabaseSettingsUpdate) {
    if (!session?.activeVaultId) {
      return false;
    }

    const vaultId = session.activeVaultId;
    setDatabaseSettingsBusy(true);
    setDatabaseSettingsError(null);

    try {
      const result = await client.updateDatabaseSettings(vaultId, update);
      setDatabaseSettings(result.settings);
      setDatabaseName(result.settings.metadata.name);
      resetDatabaseSettingsDraftState();
      setSettingsDraftEpoch((current) => current + 1);
      handleSaveResult(result.saveResult);
      setWorkspaceReloadKey((current) => current + 1);
      if (result.saveResult.status === "saved") {
        setSaveTip(translate(extensionSettings.language, "Database settings saved."));
      }
      return true;
    } catch (settingsError) {
      setDatabaseSettingsError(
        errorMessage(
          settingsError,
          translate(extensionSettings.language, "Failed to save database settings")
        )
      );
      return false;
    } finally {
      setDatabaseSettingsBusy(false);
    }
  }

  async function handleSelectHistoryItem(historyIndex: number) {
    if (!session?.activeVaultId || !selectedEntryId) {
      return;
    }

    setHistoryError(null);
    const requestEpoch = secretViewEpoch.current;
    const historyRequestEpoch = ++historyDetailRequestEpoch.current;

    try {
      const detail = await client.getEntryHistoryDetail(
        session.activeVaultId,
        selectedEntryId,
        historyIndex
      );
      if (
        requestEpoch !== secretViewEpoch.current ||
        historyRequestEpoch !== historyDetailRequestEpoch.current
      ) {
        return;
      }
      setHistoryDetail(detail);
    } catch (loadError) {
      if (
        requestEpoch !== secretViewEpoch.current ||
        historyRequestEpoch !== historyDetailRequestEpoch.current
      ) {
        return;
      }
      setHistoryDetail(null);
      setHistoryError(
        errorMessage(
          loadError,
          translate(extensionSettings.language, "Failed to load entry history")
        )
      );
    }
  }

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    function handleResize() {
      setViewMode(getViewMode(window.innerWidth));
    }

    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  useEffect(() => {
    if (!saveTip || typeof window === "undefined") {
      return undefined;
    }

    const timer = window.setTimeout(() => setSaveTip(null), 3000);
    return () => window.clearTimeout(timer);
  }, [saveTip]);

  useEffect(() => {
    let cancelled = false;

    setSessionError(null);
    setSessionErrorCause(null);

    void (async () => {
      let desiredSettingsAvailable = false;
      try {
        const loadedSettings = await localExtensionSettingsStore.load();
        if (cancelled) {
          return;
        }
        const normalizedSettings = normalizeSettings(loadedSettings);
        desiredSettingsAvailable = true;
        setExtensionSettings(normalizedSettings);
        setExtensionSettingsError(null);
        void reconcileSavedSettings("startup", null);
      } catch (settingsLoadError) {
        if (cancelled) {
          return;
        }
        setExtensionSettingsError(
          errorMessage(
            settingsLoadError,
            translate(extensionSettings.language, "Failed to load settings")
          )
        );
      }

      try {
        const state = await client.getSessionState();
        if (cancelled) {
          return;
        }
        setSession(state);
        setSessionErrorCause(null);
        if (state.unlocked && desiredSettingsAvailable) {
          void reconcileSavedSettings("startup", state);
        }
      } catch (sessionLoadError) {
        if (cancelled) {
          return;
        }
        setSession(null);
        setSessionErrorCause(sessionLoadError);
        setSessionError(
          errorMessage(
            sessionLoadError,
            translate(extensionSettings.language, "Failed to load session state")
          )
        );
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [client, localExtensionSettingsStore]);

  useEffect(() => {
    if (
      typeof window === "undefined" ||
      !session?.unlocked ||
      extensionSettings.idleLockMinutes <= 0
    ) {
      return undefined;
    }
    if (!client.lockSession) return undefined;
    const requestLock = () => client.lockSession!();

    let disposed = false;
    let lockPending = false;
    let timer = window.setTimeout(handleTimeout, extensionSettings.idleLockMinutes * 60_000);

    function resetTimer() {
      window.clearTimeout(timer);
      timer = window.setTimeout(handleTimeout, extensionSettings.idleLockMinutes * 60_000);
    }

    function handleTimeout() {
      if (idleLockBlocked || lockPending) {
        resetTimer();
        return;
      }
      lockPending = true;
      clearDetailSelection();
      setFillCandidates([]);
      void requestLock()
        .then((nextSession) => {
          if (!disposed) {
            setSession(nextSession);
          }
        })
        .catch(() => {
          lockPending = false;
          if (!disposed) {
            resetTimer();
          }
        });
    }

    const events = ["pointerdown", "keydown", "wheel", "scroll"];
    for (const eventName of events) {
      window.addEventListener(eventName, resetTimer, { passive: true });
    }

    return () => {
      disposed = true;
      window.clearTimeout(timer);
      for (const eventName of events) {
        window.removeEventListener(eventName, resetTimer);
      }
    };
  }, [client, extensionSettings.idleLockMinutes, idleLockBlocked, session?.unlocked]);

  useLayoutEffect(() => {
    setSearchValue("");
    setShowStatsPage(false);
    setShowDatabaseSettingsPage(false);
    setDatabaseSettings(null);
    setDatabaseSettingsError(null);
    setDatabaseSettingsBusy(false);
    setDatabaseName(null);
    setGroupTree(null);
    setGroupsError(null);
    setSelectedGroupId(null);
    clearDetailSelection();
    setEntries([]);
    setEntriesLoading(false);
    setEntriesError(null);
    setShowEntryListWithDetail(false);
    resetEditorState();
    setFillCandidates([]);
    setFillError(null);
    setStackedStage("groups");
    setUnlockError(null);
    setUnlockErrorCause(null);
  }, [session?.activeVaultId, session?.unlocked]);

  useEffect(() => {
    if (!session?.activeVaultId) {
      setGroupTree(null);
      setGroupsError(null);
      return;
    }

    let cancelled = false;

    setGroupsError(null);

    client
      .listGroups(session.activeVaultId)
      .then((loadedGroupTree) => {
        if (!cancelled) {
          setGroupTree(loadedGroupTree);
          setSelectedGroupId((current) => current ?? loadedGroupTree.root.id);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setGroupTree(null);
          setGroupsError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load groups")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, session?.activeVaultId, workspaceReloadKey]);

  useEffect(() => {
    if (!session?.activeVaultId) {
      setEntries([]);
      setEntriesLoading(false);
      setEntriesError(null);
      return;
    }

    let cancelled = false;

    setEntriesLoading(true);
    setEntriesError(null);

    client
      .listEntries(session.activeVaultId)
      .then((loadedEntries) => {
        if (!cancelled) {
          setEntries(loadedEntries);
          setEntriesLoading(false);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setEntries([]);
          setEntriesLoading(false);
          setEntriesError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load entries")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, session?.activeVaultId, workspaceReloadKey]);

  useEffect(() => {
    if (!session?.activeVaultId || !fillHooks) {
      setFillCandidates([]);
      setFillError(null);
      return;
    }

    let cancelled = false;

    setFillError(null);

    fillHooks
      .findCandidates(session.activeVaultId)
      .then((nextEntries) => {
        if (!cancelled) {
          setFillCandidates(nextEntries);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setFillCandidates([]);
          setFillError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load fill candidates")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [fillHooks, session?.activeVaultId, workspaceReloadKey]);

  useEffect(() => {
    const forceSourceReload =
      handledSourceDetailReloadKey.current !== sourceDetailReloadKey;
    handledSourceDetailReloadKey.current = sourceDetailReloadKey;

    if (!session?.activeVaultId || !selectedEntryId) {
      setEntryDetail(null);
      setDetailError(null);
      setHistoryItems([]);
      setHistoryDetail(null);
      setHistoryError(null);
      return;
    }

    if (!forceSourceReload && entryDetail?.id === selectedEntryId) {
      setDetailError(null);
      return;
    }

    if (!forceSourceReload) {
      setEntryDetail(null);
    }
    setDetailError(null);

    let cancelled = false;
    const requestEpoch = secretViewEpoch.current;

    client
      .getEntryDetail(session.activeVaultId, selectedEntryId)
      .then((detail) => {
        if (!cancelled && requestEpoch === secretViewEpoch.current) {
          setEntryDetail(detail);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          if (!forceSourceReload) {
            setEntryDetail(null);
          }
          setDetailError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load entry detail")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    client,
    entryDetail?.id,
    selectedEntryId,
    session?.activeVaultId,
    sourceDetailReloadKey
  ]);

  useEffect(() => {
    if (editorMode !== "edit" || !entryDetail) {
      return;
    }
    const baseline = entryDraftBaseline.current;
    if (!baseline || baseline.id !== entryDetail.id) {
      entryDraftBaseline.current = entryDetail;
      return;
    }
    if (baseline === entryDetail) {
      return;
    }

    entryDraftBaseline.current = entryDetail;
    setDraft((current) =>
      current ? rebaseEntryDraft(baseline, current, entryDetail) : current
    );
  }, [editorMode, entryDetail]);

  useEffect(() => {
    if (!session?.activeVaultId) {
      setDatabaseName(null);
      return;
    }

    let cancelled = false;

    client
      .getDatabaseSettings(session.activeVaultId)
      .then((settings) => {
        if (!cancelled) {
          setDatabaseName(settings.metadata.name);
          setDatabaseSettings((current) => current ?? settings);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDatabaseName(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, session?.activeVaultId, workspaceReloadKey]);

  useEffect(() => {
    if (!session?.activeVaultId || !showDatabaseSettingsPage) {
      return;
    }

    let cancelled = false;

    setDatabaseSettingsError(null);
    setDatabaseSettingsBusy(true);

    client
      .getDatabaseSettings(session.activeVaultId)
      .then((settings) => {
        if (!cancelled) {
          setDatabaseSettings(settings);
          setDatabaseName(settings.metadata.name);
          setDatabaseSettingsBusy(false);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setDatabaseSettingsBusy(false);
          setDatabaseSettingsError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load database settings")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [client, session?.activeVaultId, showDatabaseSettingsPage, workspaceReloadKey]);

  useEffect(() => {
    historyDetailRequestEpoch.current += 1;
    if (!entryDetail || !session?.activeVaultId || !selectedEntryId) {
      setHistoryItems([]);
      setHistoryDetail(null);
      setHistoryError(null);
      return;
    }

    let cancelled = false;

    setHistoryItems([]);
    setHistoryDetail(null);
    setHistoryError(null);

    client
      .listEntryHistory(session.activeVaultId, selectedEntryId)
      .then((items) => {
        if (!cancelled) {
          setHistoryItems(items);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setHistoryError(
            errorMessage(
              loadError,
              translate(extensionSettings.language, "Failed to load entry history")
            )
          );
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    client,
    entryDetail?.id,
    selectedEntryId,
    session?.activeVaultId,
    workspaceReloadKey
  ]);

  if (!session) {
    if (sessionError) {
      return (
        <div style={messageShellStyle}>
          <div role="alert" style={messagePanelStyle}>
            {sessionError}
          </div>
          {renderRuntimeErrorHelp?.(sessionErrorCause)}
        </div>
      );
    }

    return (
      <div style={messageShellStyle}>
        <div style={messagePanelStyle}>Loading...</div>
      </div>
    );
  }

  const currentVaultReference = actualCurrentVaultReference(recentVaults, session);

  if (showExtensionSettingsPage) {
    return (
      <I18nProvider language={extensionSettings.language}>
        <div aria-hidden={dialogState !== null} style={messageShellStyle}>
          <div style={settingsPageShellStyle}>
            <button
              type="button"
              onClick={() => requestAction({ type: "close-extension-settings" })}
              style={backButtonStyle}
            >
              {translate(extensionSettings.language, "Back")}
            </button>
            <ExtensionSettingsPanel
              key={`extension-settings-${settingsDraftEpoch}`}
              settings={extensionSettings}
              surface={settingsSurface}
              saving={extensionSettingsSaving}
              error={extensionSettingsError}
              quickUnlockSupported={session?.supportsBiometricUnlock !== false}
              quickUnlockEnabled={extensionSettings.quickUnlockEnabled}
              quickUnlockEnrolled={Boolean(currentVaultReference?.supportsQuickUnlock)}
              quickUnlockVaultUnlocked={session.unlocked}
              quickUnlockBusy={quickUnlockBusy}
              quickUnlockError={quickUnlockError}
              reconciliationError={settingsReconciliationError}
              onEnrollQuickUnlock={async (credentials) => {
                await reconcileSavedSettings("manual", session, credentials);
              }}
              onSave={(settings) => {
                void saveExtensionSettings(settings);
              }}
              onDraftChange={handleExtensionSettingsDraftChange}
            />
          </div>
        </div>
        {renderUnsavedChangesDialog()}
      </I18nProvider>
    );
  }

  if (!session.unlocked) {
    const labels = APP_LABELS[extensionSettings.language];

    if (showSetup) {
      return (
        <I18nProvider language={extensionSettings.language}>
          <VaultSetupScreen
            recentVaults={recentVaults}
            oneDriveBrowserActive={oneDriveBrowserActive}
            oneDriveBrowserPath={oneDriveBrowserPath}
            oneDriveVaultChoices={oneDriveVaultChoices}
            onAddLocalVault={handleAddLocalVault}
            onAddOneDriveVault={handleAddOneDriveVault}
            onOpenOneDriveFolder={handleOpenOneDriveFolder}
            onOpenOneDrivePath={handleOpenOneDrivePath}
            onSelectOneDriveVault={handleSelectOneDriveVault}
            onDeleteVault={async (vaultRefId) => {
              const nextVaults = await client.deleteRecentVault(vaultRefId);
              await applyRecentVaultLimit(nextVaults);
              setSession((current) =>
                current?.currentVaultRefId === vaultRefId
                  ? { ...current, currentVaultRefId: null }
                  : current
              );
            }}
            onBack={() => {
              setSetupAddError(null);
              setSetupAddErrorCause(null);
              setOneDriveVaultChoices([]);
              setOneDriveBrowserActive(false);
              setOneDriveBrowserPath([]);
              setShowSetup(false);
            }}
            onOpenExtensionSettings={() =>
              requestAction({ type: "open-extension-settings" })
            }
            addLocalVaultBusy={setupAddBusy}
            addLocalVaultError={setupAddError}
            addLocalVaultErrorCause={setupAddErrorCause}
            renderRuntimeErrorHelp={renderRuntimeErrorHelp}
          />
        </I18nProvider>
      );
    }

    return (
      <RecentVaultUnlockScreen
        recentVaults={recentVaults}
        currentVaultRefId={session.currentVaultRefId}
        labels={labels.unlock}
        onSelectVault={async (vaultRefId) => {
          setUnlockError(null);
          setUnlockErrorCause(null);
          const nextSession = await client.setCurrentVault(vaultRefId);
          setSession(nextSession);
          await reconcileSavedSettings("vault-selection", nextSession);
        }}
        onUnlock={async ({ password, keyFilePath }) => {
          setUnlockBusy(true);
          setUnlockError(null);
          setUnlockErrorCause(null);
          try {
            const nextSession = await client.unlockCurrentVault({
              password,
              keyFilePath
            });
            setSession(nextSession);
            await reconcileSavedSettings("unlock", nextSession, {
              password,
              keyFilePath
            });
          } catch (unlockFailure) {
            setUnlockError(
              errorMessage(
                unlockFailure,
                translate(extensionSettings.language, "Failed to unlock vault")
              )
            );
            setUnlockErrorCause(unlockFailure);
          } finally {
            setUnlockBusy(false);
          }
        }}
        onQuickUnlock={async () => {
          setUnlockBusy(true);
          setUnlockError(null);
          setUnlockErrorCause(null);
          try {
            const nextSession = await client.unlockCurrentVaultWithQuickUnlock();
            setSession(nextSession);
            await reconcileSavedSettings("unlock", nextSession);
          } catch (unlockFailure) {
            setUnlockError(
              errorMessage(
                unlockFailure,
                translate(extensionSettings.language, "Failed to unlock vault")
              )
            );
            setUnlockErrorCause(unlockFailure);
            try {
              await applyRecentVaultLimit(await client.listRecentVaults());
            } catch {
              // Preserve the original quick-unlock error when status refresh also fails.
            }
          } finally {
            setUnlockBusy(false);
          }
        }}
        quickUnlockSupported={Boolean(session.supportsBiometricUnlock)}
        onOpenSetup={() => setShowSetup(true)}
        onOpenExtensionSettings={() => requestAction({ type: "open-extension-settings" })}
        error={unlockError}
        errorCause={unlockErrorCause}
        busy={unlockBusy}
        renderRuntimeErrorHelp={renderRuntimeErrorHelp}
      />
    );
  }

  const groups = groupTree ? flattenGroups(groupTree.root) : [];
  const descendantIndex = groupTree ? buildDescendantIndex(groupTree.root) : new Map();
  const visibleEntries = filterEntries(
    entries,
    searchValue,
    selectedGroupId,
    descendantIndex
  );
  const selection: ManagerSelection = {
    selectedGroupId,
    selectedEntryId,
    selectedEntry: entryDetail,
    entries: visibleEntries
  };
  const showEntryDetail =
    viewMode === "expanded" ||
    selection.selectedEntryId !== null ||
    editorMode === "create-pending";
  const labels = APP_LABELS[extensionSettings.language];
  const sourceStatus = session.sourceStatus;
  const sourceSyncMessage = sourceSyncError ?? sourceStatus?.lastError ?? null;
  const sourceSyncTitle =
    sourceStatus?.remoteState === "pending_sync"
      ? "Saved to local cache. Remote sync pending."
      : sourceSyncMessage
        ? "Using local cache. Remote sync failed."
        : "Using local cache.";
  const remoteCacheWarning =
    sourceStatus?.remoteState === "cache" || sourceStatus?.remoteState === "pending_sync" ? (
      <div role="alert" style={sourceSyncBannerStyle}>
        <div style={{ display: "grid", gap: archiveTheme.spacing.xs, minWidth: 0 }}>
          <strong>{translate(extensionSettings.language, sourceSyncTitle)}</strong>
          {sourceSyncMessage ? (
            <small style={sourceSyncDetailStyle}>{sourceSyncMessage}</small>
          ) : null}
        </div>
        <button
          type="button"
          onClick={() => {
            void handleRetrySourceSync();
          }}
          disabled={sourceSyncBusy || !session.activeVaultId}
          style={{
            ...sourceSyncButtonStyle,
            opacity: sourceSyncBusy || !session.activeVaultId ? 0.68 : 1,
            cursor: sourceSyncBusy || !session.activeVaultId ? "not-allowed" : "pointer"
          }}
        >
          {sourceSyncBusy
            ? translate(extensionSettings.language, "Retrying...")
            : translate(extensionSettings.language, "Retry sync")}
        </button>
      </div>
    ) : null;

  const entryListPane = (
    <div style={{ display: "grid", gap: archiveTheme.spacing.md }}>
      {viewMode === "stacked" && stackedStage === "entries" ? (
        <button
          type="button"
          onClick={() => {
            clearDetailSelection();
            setStackedStage("groups");
          }}
          style={backButtonStyle}
        >
          Back to groups
        </button>
      ) : null}
      {fillHooks ? (
        <>
          {fillError ? <div role="alert">{fillError}</div> : null}
          {fillError ? null : (
            <FillCandidatesPanel
              candidates={fillCandidates}
              onFill={(entryId) =>
                fillHooks.fillEntry(session.activeVaultId ?? "", entryId)
              }
            />
          )}
        </>
      ) : null}
      <VaultScreen
        entries={selection.entries}
        loading={entriesLoading}
        hasActiveVault={Boolean(session.activeVaultId)}
        searchValue={searchValue}
        error={entriesError}
        selectedEntryId={selection.selectedEntryId}
        onSelectEntry={handleSelectEntry}
        onCreateEntry={() => requestAction({ type: "new-entry" })}
      />
    </div>
  );

  return (
    <I18nProvider language={extensionSettings.language}>
      <div aria-hidden={dialogState !== null}>
        {remoteCacheWarning}
        <ManagerShell
          viewMode={viewMode}
          showEntryDetail={showEntryDetail}
          stackedStage={stackedStage}
          topBar={
            <ManagerTopBar
              title={databaseName || translate(extensionSettings.language, "Private Archive")}
              labels={labels.topBar}
              searchValue={searchValue}
              onSearchChange={handleSearchChange}
              onOpenStats={() => requestAction({ type: "open-stats" })}
              onOpenSettings={() => requestAction({ type: "open-database-settings" })}
              onOpenExtensionSettings={() =>
                requestAction({ type: "open-extension-settings" })
              }
            />
          }
          groupTree={
            groupsError ? (
              <div role="alert">{groupsError}</div>
            ) : (
              <GroupTreePane
                groups={groups}
                selectedGroupId={selection.selectedGroupId}
                onSelectGroup={(groupId) => requestAction({ type: "select-group", groupId })}
              />
            )
          }
          entryList={entryListPane}
          entryDetail={
            <EntryDetailPane
              entry={selection.selectedEntry}
              mode={editorMode}
              draft={draft}
              dirty={dirty}
              busy={entryActionBusy}
              pendingSave={Boolean(pendingDetailSave)}
              error={entryActionError ?? detailError}
              historyItems={historyItems}
              historyDetail={historyDetail}
              historyError={historyError}
              onBack={viewMode === "expanded" ? undefined : handleBackToEntries}
              onStartEdit={() => {
                if (!entryDetail || pendingDetailSave) {
                  return;
                }

                entryDraftBaseline.current = entryDetail;
                setDraft(entryToDraft(entryDetail));
                setShowEntryListWithDetail(true);
                setEditorMode("edit");
                setEntryActionError(null);
              }}
              onChangeDraft={(field, value) => {
                setDraft((current) => {
                  const base = current ?? createEmptyDraft();
                  return {
                    ...base,
                    [field]: field === "totpUri" ? normalizeDraftTotpUri(value) : value
                  };
                });
              }}
              onChangeCustomField={(index, field, value) => {
                setDraft((current) => {
                  const base = current ?? createEmptyDraft();
                  return {
                    ...base,
                    customFields: base.customFields.map((customField, fieldIndex) =>
                      fieldIndex === index
                        ? { ...customField, [field]: value }
                        : customField
                    )
                  };
                });
              }}
              onAddCustomField={() => {
                setDraft((current) => {
                  const base = current ?? createEmptyDraft();
                  return {
                    ...base,
                    customFields: [
                      ...base.customFields,
                      { key: "", value: "", protected: false }
                    ]
                  };
                });
              }}
              onDeleteCustomField={(index) => {
                setDraft((current) => {
                  const base = current ?? createEmptyDraft();
                  return {
                    ...base,
                    customFields: base.customFields.filter(
                      (_field, fieldIndex) => fieldIndex !== index
                    )
                  };
                });
              }}
              onDownloadAttachment={(name) => {
                void handleDownloadAttachment(name);
              }}
              onAddAttachment={(file, protectInMemory) => {
                void handleAddAttachment(file, protectInMemory);
              }}
              onRenameAttachment={(oldName, newName, protectInMemory) => {
                void handleRenameAttachment(oldName, newName, protectInMemory);
              }}
              onReplaceAttachment={(name, file) => {
                void handleReplaceAttachment(name, file);
              }}
              onDeleteAttachment={(name) => {
                void handleDeleteAttachment(name);
              }}
              onSelectHistoryItem={(historyIndex) => {
                void handleSelectHistoryItem(historyIndex);
              }}
              onSetPasskey={(passkey) => {
                void handleSetEntryPasskey(passkey);
              }}
              onClearPasskey={() => {
                void handleClearEntryPasskey();
              }}
              onRetrySave={() => {
                void retryPendingDetailSave();
              }}
              onSave={() => {
                void (pendingDetailSave ? retryPendingDetailSave() : saveDraft());
              }}
              onCancel={() => {
                if (editorMode === "create-pending") {
                  requestAction({ type: "back-to-entries" });
                  return;
                }

                if (dirty && selectedEntryId) {
                  requestAction({ type: "select-entry", entryId: selectedEntryId });
                  return;
                }

                setShowEntryListWithDetail(false);
                resetEditorState();
              }}
              onDelete={
                entryDetail
                  ? () =>
                      setDialogState({
                        type: "delete-entry",
                        entryId: entryDetail.id,
                        title: entryDetail.title
                      })
                  : undefined
              }
            />
          }
          secondaryPage={
            showStatsPage ? (
              <ManagerSecondaryPage
                title={translate(extensionSettings.language, "Statistics")}
                description={translate(extensionSettings.language, "Statistics description")}
                onBack={() => setShowStatsPage(false)}
              />
            ) : showDatabaseSettingsPage ? (
              <div style={{ display: "grid", gap: archiveTheme.spacing.lg }}>
                <button
                  type="button"
                  onClick={() => requestAction({ type: "close-database-settings" })}
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
                  {translate(extensionSettings.language, "Back to archive")}
                </button>
                <DatabaseSettingsPage
                  key={`database-settings-${settingsDraftEpoch}`}
                  settings={databaseSettings}
                  loading={databaseSettingsBusy && !databaseSettings}
                  saving={databaseSettingsBusy && Boolean(databaseSettings)}
                  error={databaseSettingsError}
                  onSave={(update) => {
                    void handleSaveDatabaseSettings(update);
                  }}
                  onDraftChange={handleDatabaseSettingsDraftChange}
                />
              </div>
            ) : undefined
          }
          showEntryListWithDetail={showEntryListWithDetail || editorMode !== "view"}
        />
      </div>
      {renderUnsavedChangesDialog()}
      {dialogState?.type === "delete-entry" ? (
        <ConfirmationDialog
          title={translate(extensionSettings.language, "Delete this entry permanently?")}
          description={
            dialogState.title
              ? deleteEntryDescription(extensionSettings.language, dialogState.title)
              : translate(
                  extensionSettings.language,
                  "This will remove the selected entry from the current vault."
                )
          }
          actions={[
            {
              label: translate(
                extensionSettings.language,
                pendingEntryDelete ? "Retry save" : "Delete permanently"
              ),
              variant: pendingEntryDelete ? "primary" : "danger",
              disabled: entryActionBusy,
              onClick: () => {
                void handleDeleteEntry(dialogState.entryId);
              }
            },
            ...(pendingEntryDelete
              ? []
              : [
                  {
                    label: translate(extensionSettings.language, "Cancel"),
                    disabled: entryActionBusy,
                    onClick: () => setDialogState(null)
                  }
                ])
          ]}
        />
      ) : null}
      {saveTip ? (
        <div role="status" style={saveTipStyle}>
          {saveTip}
        </div>
      ) : null}
    </I18nProvider>
  );
}

const messageShellStyle = {
  minHeight: "100vh",
  display: "grid",
  placeItems: "center",
  padding: archiveTheme.spacing.xl,
  background: `radial-gradient(circle at top left, ${archiveTheme.colors.page} 0%, ${archiveTheme.colors.pageShade} 65%, #dbc29f 100%)`
};

const messagePanelStyle = {
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.lg,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  boxShadow: archiveTheme.shadow.panel
};

const settingsPageShellStyle = {
  width: "min(760px, 100%)",
  display: "grid",
  gap: archiveTheme.spacing.lg
};

const saveTipStyle = {
  position: "fixed" as const,
  right: archiveTheme.spacing.lg,
  bottom: archiveTheme.spacing.lg,
  zIndex: 20,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.field,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.text,
  boxShadow: archiveTheme.shadow.panel,
  fontFamily: archiveTheme.font.body
};

const sourceSyncBannerStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) auto",
  alignItems: "center",
  gap: archiveTheme.spacing.md,
  borderBottom: `1px solid ${archiveTheme.colors.line}`,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.lg}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body
};

const sourceSyncDetailStyle = {
  color: archiveTheme.colors.textMuted,
  overflowWrap: "anywhere" as const
};

const sourceSyncButtonStyle = {
  border: `1px solid ${archiveTheme.colors.accentStrong}`,
  borderRadius: archiveTheme.radius.field,
  padding: `${archiveTheme.spacing.xs} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surface,
  color: archiveTheme.colors.accentStrong,
  fontFamily: archiveTheme.font.body,
  fontWeight: 700
};

const backButtonStyle = {
  justifySelf: "start",
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.pill,
  padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
  background: archiveTheme.colors.surfaceMuted,
  color: archiveTheme.colors.text,
  fontFamily: archiveTheme.font.body,
  cursor: "pointer"
};

function triggerAttachmentDownload(content: EntryAttachmentContent) {
  if (typeof document === "undefined") {
    return;
  }

  if (
    typeof navigator !== "undefined" &&
    navigator.userAgent.toLowerCase().includes("jsdom")
  ) {
    return;
  }

  const link = document.createElement("a");
  link.href = `data:application/octet-stream;base64,${content.dataBase64}`;
  link.download = content.name;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("failed to read file"));
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      const marker = "base64,";
      const markerIndex = result.indexOf(marker);
      resolve(markerIndex >= 0 ? result.slice(markerIndex + marker.length) : "");
    };
    reader.readAsDataURL(file);
  });
}

function createEmptyDraft(): EntryDraft {
  return {
    title: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    totpUri: null,
    customFields: []
  };
}

function entryToDraft(entry: EntryDetail): EntryDraft {
  return {
    title: entry.title,
    username: entry.username,
    password: entry.password,
    url: entry.url,
    notes: entry.notes,
    totpUri: entry.totpUri ?? null,
    customFields: entry.customFields?.map((field) => ({ ...field })) ?? []
  };
}

function rebaseEntryDraft(
  previousEntry: EntryDetail,
  current: EntryDraft,
  nextEntry: EntryDetail
): EntryDraft {
  const previous = entryToDraft(previousEntry);
  const next = entryToDraft(nextEntry);
  return {
    title: current.title === previous.title ? next.title : current.title,
    username:
      current.username === previous.username ? next.username : current.username,
    password:
      current.password === previous.password ? next.password : current.password,
    url: current.url === previous.url ? next.url : current.url,
    notes: current.notes === previous.notes ? next.notes : current.notes,
    totpUri:
      (current.totpUri ?? null) === (previous.totpUri ?? null)
        ? next.totpUri
        : current.totpUri,
    customFields: rebaseCustomFields(
      previous.customFields,
      current.customFields,
      next.customFields
    )
  };
}

function rebaseCustomFields(
  previous: EntryDraft["customFields"],
  current: EntryDraft["customFields"],
  next: EntryDraft["customFields"]
): EntryDraft["customFields"] {
  const previousByKey = uniqueCustomFieldsByKey(previous);
  const currentByKey = uniqueCustomFieldsByKey(current);
  const nextByKey = uniqueCustomFieldsByKey(next);
  if (!previousByKey || !currentByKey || !nextByKey) {
    return current.map((field) => ({ ...field }));
  }

  const deletedLocally = new Set(
    previous
      .filter((field) => !currentByKey.has(field.key))
      .map((field) => field.key)
  );
  const rebased = next
    .filter((field) => !deletedLocally.has(field.key))
    .map((field) => ({ ...field }));
  const rebasedIndexes = new Map(
    rebased.map((field, index) => [field.key, index] as const)
  );

  for (const field of current) {
    const previousField = previousByKey.get(field.key);
    if (previousField && customFieldMatches(field, previousField)) {
      continue;
    }
    const localField = { ...field };
    const rebasedIndex = rebasedIndexes.get(field.key);
    if (rebasedIndex === undefined) {
      rebasedIndexes.set(field.key, rebased.length);
      rebased.push(localField);
    } else {
      rebased[rebasedIndex] = localField;
    }
  }
  return rebased;
}

function uniqueCustomFieldsByKey(
  fields: EntryDraft["customFields"]
): Map<string, EntryDraft["customFields"][number]> | null {
  const byKey = new Map<string, EntryDraft["customFields"][number]>();
  for (const field of fields) {
    if (byKey.has(field.key)) {
      return null;
    }
    byKey.set(field.key, field);
  }
  return byKey;
}

function customFieldMatches(
  left: EntryDraft["customFields"][number],
  right: EntryDraft["customFields"][number]
): boolean {
  return (
    left.key === right.key &&
    left.value === right.value &&
    left.protected === right.protected
  );
}

function draftMatchesEntry(draft: EntryDraft, entry: EntryDetail): boolean {
  return (
    draft.title === entry.title &&
    draft.username === entry.username &&
    draft.password === entry.password &&
    draft.url === entry.url &&
    draft.notes === entry.notes &&
    (draft.totpUri ?? null) === (entry.totpUri ?? null) &&
    customFieldsMatch(draft.customFields, entry.customFields ?? [])
  );
}

function hasDraftChangesFromEmpty(draft: EntryDraft | null): boolean {
  if (!draft) {
    return false;
  }

  return (
    Object.values({
      ...draft,
      totpUri: draft.totpUri ?? "",
      customFields: ""
    }).some((value) => value !== "") || draft.customFields.length > 0
  );
}

function customFieldsMatch(
  left: EntryDraft["customFields"],
  right: EntryDraft["customFields"]
): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((field, index) => {
    const other = right[index];
    return (
      other &&
      field.key === other.key &&
      field.value === other.value &&
      field.protected === other.protected
    );
  });
}

function normalizeDraftTotpUri(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function ConfirmationDialog({
  title,
  description,
  actions
}: {
  title: string;
  description: string;
  actions: Array<{
    label: string;
    onClick: () => void;
    variant?: "primary" | "danger" | "secondary";
    disabled?: boolean;
  }>;
}) {
  return (
    <div style={dialogOverlayStyle}>
      <div role="alertdialog" aria-modal="true" style={dialogPanelStyle}>
        <div
          style={{
            display: "grid",
            gap: archiveTheme.spacing.sm
          }}
        >
          <strong
            style={{
              fontFamily: archiveTheme.font.display,
              fontSize: "1.4rem",
              fontWeight: 600
            }}
          >
            {title}
          </strong>
          <div
            style={{
              color: archiveTheme.colors.textMuted,
              fontFamily: archiveTheme.font.body,
              lineHeight: 1.5
            }}
          >
            {description}
          </div>
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: archiveTheme.spacing.sm,
            justifyContent: "flex-end"
          }}
        >
          {actions.map((action) => (
            <button
              key={action.label}
              type="button"
              onClick={action.onClick}
              disabled={action.disabled}
              style={dialogActionStyle(action.variant ?? "secondary")}
            >
              {action.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

const dialogOverlayStyle = {
  position: "fixed" as const,
  inset: 0,
  display: "grid",
  placeItems: "center",
  padding: archiveTheme.spacing.lg,
  background: "rgba(38, 25, 16, 0.36)"
};

const dialogPanelStyle = {
  width: "min(460px, 100%)",
  display: "grid",
  gap: archiveTheme.spacing.lg,
  border: `1px solid ${archiveTheme.colors.line}`,
  borderRadius: archiveTheme.radius.panel,
  padding: archiveTheme.spacing.lg,
  background: archiveTheme.colors.surface,
  boxShadow: archiveTheme.shadow.shell
};

function dialogActionStyle(variant: "primary" | "danger" | "secondary") {
  if (variant === "primary") {
    return {
      border: `1px solid ${archiveTheme.colors.accentStrong}`,
      borderRadius: archiveTheme.radius.pill,
      padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
      background: archiveTheme.colors.accentStrong,
      color: "#fffaf2",
      fontFamily: archiveTheme.font.body,
      cursor: "pointer"
    };
  }

  if (variant === "danger") {
    return {
      border: `1px solid ${archiveTheme.colors.danger}`,
      borderRadius: archiveTheme.radius.pill,
      padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
      background: "rgba(139, 61, 42, 0.12)",
      color: archiveTheme.colors.danger,
      fontFamily: archiveTheme.font.body,
      cursor: "pointer"
    };
  }

  return {
    border: `1px solid ${archiveTheme.colors.line}`,
    borderRadius: archiveTheme.radius.pill,
    padding: `${archiveTheme.spacing.sm} ${archiveTheme.spacing.md}`,
    background: archiveTheme.colors.surfaceMuted,
    color: archiveTheme.colors.text,
    fontFamily: archiveTheme.font.body,
    cursor: "pointer"
  };
}
