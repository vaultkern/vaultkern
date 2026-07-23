import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  CommittedMutation,
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
  ResidentAppRoute,
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
  recordUserActivity?(): Promise<SessionStateLike>;
  listGroups(vaultId: string): Promise<GroupTree>;
  listEntries(vaultId: string): Promise<EntrySummary[]>;
  getEntryDetail(vaultId: string, entryId: string): Promise<EntryDetail>;
  createEntry(
    vaultId: string,
    input: EntryDraft & { parentGroupId: string }
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  updateEntryFields(
    vaultId: string,
    entryId: string,
    input: EntryDraft
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  setEntryPasskey(
    vaultId: string,
    entryId: string,
    passkey: EntryPasskeyUpdate
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  clearEntryPasskey(
    vaultId: string,
    entryId: string
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  deleteEntry(
    vaultId: string,
    entryId: string
  ): Promise<void | CommittedMutation<void>>;
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
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  updateEntryAttachmentMetadata(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentMetadataUpdate
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  replaceEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentContentUpdate
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
  deleteEntryAttachment(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<EntryDetail | CommittedMutation<EntryDetail>>;
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

export type SessionStateLike = Pick<
  SessionState,
  "unlocked" | "activeVaultId" | "currentVaultRefId" | "sourceStatus"
> & {
  supportsBiometricUnlock?: boolean;
};

export type SessionStateSubscriber = (
  listener: (state: SessionStateLike) => void
) => Promise<() => void>;

export type ResidentAppRouteSubscriber = (
  listener: (route: ResidentAppRoute) => void
) => Promise<() => void>;

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
  | { type: "close-extension-settings" }
  | { type: "open-vaults" }
  | { type: "open-unlock" };

type DialogState =
  | { type: "unsaved"; action: PendingAction }
  | { type: "delete-entry"; entryId: string; title: string };

interface PendingDatabaseSettingsSave {
  vaultId: string;
  sessionEpoch: number;
  promise: Promise<boolean>;
}

interface EntryRequestOwner {
  vaultId: string;
  entryId: string;
  sessionEpoch: number;
  viewEpoch: number;
}

const COMPACT_BREAKPOINT = 1180;
const STACKED_BREAKPOINT = 760;

function isCommittedMutation<T>(
  value: T | CommittedMutation<T>
): value is CommittedMutation<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    "saveResult" in value &&
    "value" in value
  );
}

function isUnknownMutationOutcome(value: unknown) {
  if (typeof value !== "object" || value === null || !("code" in value)) {
    return false;
  }
  const code = (value as { code?: unknown }).code;
  return (
    code === "native_port_disconnected" ||
    code === "native_timeout" ||
    code === "request_outcome_unknown"
  );
}

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
  subscribeSessionState,
  subscribeOpenRoute,
  renderRuntimeErrorHelp
}: {
  client: RuntimeClientLike;
  fillHooks?: FillHooks;
  extensionSettingsStore?: ExtensionSettingsStore;
  subscribeSessionState?: SessionStateSubscriber;
  subscribeOpenRoute?: ResidentAppRouteSubscriber;
  renderRuntimeErrorHelp?: (error: unknown) => ReactNode;
}) {
  const [localExtensionSettingsStore] = useState(() =>
    extensionSettingsStore ?? createMemoryExtensionSettingsStore()
  );
  const normalizeSettings = normalizeWindowsAppSettings;
  const [session, setSession] = useState<SessionStateLike | null>(null);
  const sessionRef = useRef<SessionStateLike | null>(null);
  const residentSessionEpoch = useRef(0);
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
  const databaseSettingsSaveInFlight = useRef<PendingDatabaseSettingsSave | null>(
    null
  );
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
  const [entryDraftOutcomeUnknown, setEntryDraftOutcomeUnknown] =
    useState(false);
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
  const recentVaultProjectionEpoch = useRef(0);
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
  const [vaultSelectionBusy, setVaultSelectionBusy] = useState(false);
  const vaultSelectionInFlight = useRef<Promise<void> | null>(null);
  const [saveTip, setSaveTip] = useState<string | null>(null);
  const [sourceSyncBusy, setSourceSyncBusy] = useState(false);
  const [sourceSyncError, setSourceSyncError] = useState<string | null>(null);
  const sourceSyncRequestEpoch = useRef(0);
  const [extensionSettings, setExtensionSettings] =
    useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [extensionSettingsError, setExtensionSettingsError] = useState<string | null>(
    null
  );
  const [extensionSettingsSaving, setExtensionSettingsSaving] = useState(false);
  const extensionSettingsSaveInFlight = useRef<Promise<boolean> | null>(null);
  const settingsReconciliationTail = useRef<Promise<void>>(Promise.resolve());
  const extensionSettingsDraft = useRef<ExtensionSettings | null>(null);
  const [extensionSettingsDraftDirty, setExtensionSettingsDraftDirty] =
    useState(false);
  const [settingsDraftEpoch, setSettingsDraftEpoch] = useState(0);
  const [quickUnlockBusy, setQuickUnlockBusy] = useState(false);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);
  const [settingsReconciliationError, setSettingsReconciliationError] =
    useState<string | null>(null);
  const settingsReconciliationStatusEpoch = useRef(0);
  const openRouteHandler = useRef<(route: ResidentAppRoute) => void>(() => undefined);
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

  function acceptSessionResponse(
    nextSession: SessionStateLike,
    requestEpoch: number
  ) {
    if (requestEpoch !== residentSessionEpoch.current) {
      return false;
    }
    acceptAuthoritativeSession(nextSession);
    return true;
  }

  function ownsVaultRequest(vaultId: string, requestEpoch: number) {
    return (
      requestEpoch === residentSessionEpoch.current &&
      sessionRef.current?.unlocked === true &&
      sessionRef.current.activeVaultId === vaultId
    );
  }

  function captureEntryRequestOwner(): EntryRequestOwner | null {
    const currentSession = sessionRef.current;
    if (
      currentSession?.unlocked !== true ||
      !currentSession.activeVaultId ||
      !selectedEntryId
    ) {
      return null;
    }
    return {
      vaultId: currentSession.activeVaultId,
      entryId: selectedEntryId,
      sessionEpoch: residentSessionEpoch.current,
      viewEpoch: secretViewEpoch.current
    };
  }

  function ownsEntryProjection(owner: EntryRequestOwner) {
    return (
      ownsVaultRequest(owner.vaultId, owner.sessionEpoch) &&
      owner.viewEpoch === secretViewEpoch.current
    );
  }

  function invalidateSessionOwnedWork() {
    residentSessionEpoch.current += 1;
    recentVaultProjectionEpoch.current += 1;
    vaultSelectionInFlight.current = null;
    setVaultSelectionBusy(false);
    setUnlockBusy(false);
    setUnlockError(null);
    setUnlockErrorCause(null);
    setQuickUnlockBusy(false);
    setQuickUnlockError(null);
    saveDraftInFlight.current = null;
    saveAndContinueInFlight.current = false;
    clearDetailSelection();
    setEntryActionBusy(false);
    setSaveAndContinueBusy(false);
    databaseSettingsSaveInFlight.current = null;
    resetDatabaseSettingsDraftState();
    setDatabaseSettingsBusy(false);
    setDatabaseSettingsError(null);
    sourceSyncRequestEpoch.current += 1;
    setSourceSyncBusy(false);
    setSourceSyncError(null);
    setSaveTip(null);
  }

  function acceptAuthoritativeSession(
    nextSession: SessionStateLike,
    forceInvalidation = false
  ) {
    const current = sessionRef.current;
    const identityChanged =
      current?.unlocked !== nextSession.unlocked ||
      current?.activeVaultId !== nextSession.activeVaultId ||
      current?.currentVaultRefId !== nextSession.currentVaultRefId;
    if (identityChanged || forceInvalidation) {
      invalidateSessionOwnedWork();
    }
    sessionRef.current = nextSession;
    setSession(nextSession);
    setSessionError(null);
    setSessionErrorCause(null);
  }

  function clearAuthoritativeSession() {
    invalidateSessionOwnedWork();
    sessionRef.current = null;
    setSession(null);
  }

  function updateAuthoritativeSessionForVault(
    vaultId: string,
    update: (current: SessionStateLike) => SessionStateLike
  ) {
    const current = sessionRef.current;
    if (!current || current.activeVaultId !== vaultId) {
      return;
    }
    const nextSession = update(current);
    sessionRef.current = nextSession;
    setSession(nextSession);
  }

  async function reloadLockedState() {
    const requestEpoch = residentSessionEpoch.current;
    const [nextSession, nextRecentVaults] = await Promise.all([
      client.getSessionState(),
      client.listRecentVaults()
    ]);
    if (!acceptSessionResponse(nextSession, requestEpoch)) {
      return;
    }
    await applyRecentVaultLimit(
      nextRecentVaults,
      residentSessionEpoch.current
    );
  }

  function selectCurrentVault(vaultRefId: string) {
    if (vaultSelectionInFlight.current) {
      return vaultSelectionInFlight.current;
    }
    const requestEpoch = residentSessionEpoch.current;
    setUnlockError(null);
    setUnlockErrorCause(null);
    setVaultSelectionBusy(true);
    const operation = (async () => {
      const nextSession = await client.setCurrentVault(vaultRefId);
      if (acceptSessionResponse(nextSession, requestEpoch)) {
        await reconcileSavedSettings("vault-selection");
      }
    })();
    vaultSelectionInFlight.current = operation;
    void operation
      .catch((selectionError) => {
        if (requestEpoch === residentSessionEpoch.current) {
          setUnlockError(
            errorMessage(
              selectionError,
              translate(extensionSettings.language, "Failed to select vault")
            )
          );
          setUnlockErrorCause(selectionError);
        }
      })
      .finally(() => {
        if (vaultSelectionInFlight.current === operation) {
          vaultSelectionInFlight.current = null;
          setVaultSelectionBusy(false);
        }
      });
    return operation;
  }

  async function applyRecentVaultLimit(
    vaults: VaultReference[],
    requestEpoch: number
  ): Promise<boolean> {
    if (requestEpoch !== residentSessionEpoch.current) {
      return false;
    }
    const projectionEpoch = ++recentVaultProjectionEpoch.current;
    const desired = normalizeSettings(await localExtensionSettingsStore.load());
    if (
      requestEpoch !== residentSessionEpoch.current ||
      projectionEpoch !== recentVaultProjectionEpoch.current
    ) {
      return false;
    }
    setRecentVaults(
      sortRecentVaultsForRetention(vaults).slice(0, desired.recentVaultLimit)
    );
    return true;
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
      void reconcileSavedSettings("settings-commit");
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
    credentials?: UnlockCredentials
  ): Promise<void> {
    if (reason === "manual" && credentials) {
      return handoffNativeQuickUnlockEnrollment(credentials);
    }

    const run = () => {
      const reconciliationEpoch = residentSessionEpoch.current;
      return refreshSavedSettingsProjection(reconciliationEpoch);
    };
    const operation = settingsReconciliationTail.current.then(run, run);
    settingsReconciliationTail.current = operation.catch(() => undefined);
    return operation;
  }

  async function handoffNativeQuickUnlockEnrollment(
    credentials: UnlockCredentials
  ): Promise<void> {
    const requestEpoch = residentSessionEpoch.current;
    const expectedVaultRefId = sessionRef.current?.currentVaultRefId;
    if (!expectedVaultRefId || sessionRef.current?.unlocked !== true) {
      return;
    }
    setQuickUnlockError(null);
    setQuickUnlockBusy(true);
    try {
      if (!localExtensionSettingsStore.queueQuickUnlockEnrollment) {
        throw new Error("Quick unlock enrollment is unavailable");
      }
      const desired = normalizeSettings(
        await localExtensionSettingsStore.load()
      );
      if (
        requestEpoch !== residentSessionEpoch.current ||
        sessionRef.current?.currentVaultRefId !== expectedVaultRefId ||
        !desired.quickUnlockEnabled
      ) {
        return;
      }
      await localExtensionSettingsStore.queueQuickUnlockEnrollment(
        credentials,
        expectedVaultRefId
      );
    } catch (quickUnlockFailure) {
      if (requestEpoch === residentSessionEpoch.current) {
        setQuickUnlockError(
          errorMessage(
            quickUnlockFailure,
            translate(extensionSettings.language, "Failed to update quick unlock")
          )
        );
      }
    } finally {
      if (requestEpoch === residentSessionEpoch.current) {
        setQuickUnlockBusy(false);
      }
    }
  }

  async function refreshSavedSettingsProjection(
    requestEpoch: number
  ): Promise<void> {
    if (requestEpoch !== residentSessionEpoch.current) {
      return;
    }
    let desiredSettingsAvailable = false;
    try {
      normalizeSettings(await localExtensionSettingsStore.load());
      desiredSettingsAvailable = true;
    } catch (loadFailure) {
      console.error("failed to read desired settings for projection refresh", loadFailure);
      return;
    }
    if (!desiredSettingsAvailable || requestEpoch !== residentSessionEpoch.current) {
      return;
    }

    let vaults: VaultReference[];
    try {
      vaults = await client.listRecentVaults();
    } catch (vaultListFailure) {
      console.error("settings projection could not list recent vaults", vaultListFailure);
      return;
    }
    try {
      if (!(await applyRecentVaultLimit(vaults, requestEpoch))) {
        return;
      }
    } catch (recentVaultFailure) {
      console.error(
        "settings projection could not apply the recent-vault presentation limit",
        recentVaultFailure
      );
    }
  }

  function resetEditorState(nextMode: EntryEditorMode = "view") {
    entryDraftBaseline.current = null;
    setEntryDraftOutcomeUnknown(false);
    setEditorMode(nextMode);
    setDraft(null);
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

  function handleSaveResult(vaultId: string, result: SaveVaultResult | void) {
    if (
      result &&
      (result.status === "saved" ||
        result.status === "merged" ||
        result.status === "saved_to_cache")
    ) {
      void reconcileSavedSettings("vault-save");
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
      updateAuthoritativeSessionForVault(vaultId, (current) => ({
        ...current,
        sourceStatus: {
          sourceKind: current.sourceStatus?.sourceKind ?? "remote",
          remoteState: "pending_sync",
          lastSyncAt: current.sourceStatus?.lastSyncAt ?? null,
          cachedAt: current.sourceStatus?.cachedAt ?? null,
          lastError: current.sourceStatus?.lastError ?? null
        }
      }));
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

  function settleMutationResult<T>(
    result: T | CommittedMutation<T>
  ): { value: T; saveResult: SaveVaultResult | void } {
    if (isCommittedMutation(result)) {
      return {
        value: result.value,
        saveResult: result.saveResult
      };
    }
    return {
      value: result,
      saveResult: undefined
    };
  }

  async function handleRetrySourceSync() {
    const vaultId = session?.activeVaultId;
    if (!vaultId) {
      return;
    }

    const requestEpoch = residentSessionEpoch.current;
    const sourceRequestEpoch = ++sourceSyncRequestEpoch.current;
    const requestIsCurrent = () =>
      requestEpoch === residentSessionEpoch.current &&
      sourceRequestEpoch === sourceSyncRequestEpoch.current &&
      sessionRef.current?.activeVaultId === vaultId;
    setSourceSyncBusy(true);
    setSourceSyncError(null);

    try {
      const sourceStatus = await client.retryVaultSourceSync(vaultId);
      if (!requestIsCurrent()) {
        return;
      }
      updateAuthoritativeSessionForVault(vaultId, (current) =>
        current.activeVaultId === vaultId ? { ...current, sourceStatus } : current
      );
      if (sourceStatus.remoteState === "online") {
        setWorkspaceReloadKey((current) => current + 1);
        setSourceDetailReloadKey((current) => current + 1);
        setSaveTip(translate(extensionSettings.language, "Remote sync restored."));
      } else if (sourceStatus.lastError) {
        setSourceSyncError(sourceStatus.lastError);
      }
    } catch (syncFailure) {
      if (!requestIsCurrent()) {
        return;
      }
      setSourceSyncError(
        errorMessage(
          syncFailure,
          translate(extensionSettings.language, "Failed to retry remote sync")
        )
      );
    } finally {
      if (requestIsCurrent()) {
        setSourceSyncBusy(false);
      }
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

  const draftDirty =
    editorMode === "create-pending"
      ? hasDraftChangesFromEmpty(draft)
      : editorMode === "edit" && entryDetail && draft
        ? !draftMatchesEntry(draft, entryDetail)
        : false;
  const dirty =
    entryDraftOutcomeUnknown ||
    draftDirty ||
    (showDatabaseSettingsPage && databaseSettingsDraftDirty) ||
    (showExtensionSettingsPage && extensionSettingsDraftDirty);
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
      case "open-vaults":
        setShowEntryListWithDetail(false);
        resetEditorState();
        resetDatabaseSettingsDraftState();
        resetExtensionSettingsDraftState();
        setShowStatsPage(false);
        setShowDatabaseSettingsPage(false);
        setShowExtensionSettingsPage(false);
        setShowSetup(sessionRef.current?.unlocked !== true);
        break;
      case "open-unlock":
        setShowEntryListWithDetail(false);
        resetEditorState();
        resetDatabaseSettingsDraftState();
        resetExtensionSettingsDraftState();
        setShowStatsPage(false);
        setShowDatabaseSettingsPage(false);
        setShowExtensionSettingsPage(false);
        setShowSetup(false);
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

  openRouteHandler.current = (route) => {
    switch (route) {
      case "settings":
        requestAction({ type: "open-extension-settings" });
        break;
      case "vaults":
        requestAction({ type: "open-vaults" });
        break;
      case "unlock":
        requestAction({ type: "open-unlock" });
        break;
    }
  };

  useEffect(() => {
    if (!subscribeOpenRoute) {
      return undefined;
    }
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    void subscribeOpenRoute((route) => {
      if (!disposed) {
        openRouteHandler.current(route);
      }
    }).then((cleanup) => {
      if (disposed) {
        cleanup();
      } else {
        unsubscribe = cleanup;
      }
    });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [subscribeOpenRoute]);

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

    const requestEpoch = residentSessionEpoch.current;
    const vaultId = session.activeVaultId;
    const wasCreating = editorMode === "create-pending";
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const mutation = wasCreating
        ? await client.createEntry(vaultId, {
            parentGroupId: selectedGroupId ?? groupTree?.root.id ?? "",
            ...draft
          })
        : editorMode === "edit" && selectedEntryId
          ? await client.updateEntryFields(vaultId, selectedEntryId, draft)
          : null;
      if (mutation === null) {
        return false;
      }
      const { value: detail, saveResult } = settleMutationResult(mutation);
      if (!ownsVaultRequest(vaultId, requestEpoch)) {
        return false;
      }
      setEntryDraftOutcomeUnknown(false);
      handleSaveResult(vaultId, saveResult);
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
      if (ownsVaultRequest(vaultId, requestEpoch)) {
        setEntryDraftOutcomeUnknown(isUnknownMutationOutcome(mutationError));
        setEntryActionError(
          errorMessage(
            mutationError,
            translate(extensionSettings.language, "Failed to save entry changes")
          )
        );
      }
      return false;
    } finally {
      if (ownsVaultRequest(vaultId, requestEpoch)) {
        setEntryActionBusy(false);
      }
    }
  }

  async function handleSaveAndContinue(action: PendingAction) {
    if (saveAndContinueInFlight.current) {
      return;
    }
    const requestEpoch = residentSessionEpoch.current;
    saveAndContinueInFlight.current = true;
    setSaveAndContinueBusy(true);

    try {
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
            : true;
      if (
        saved &&
        !handledDatabaseSettings &&
        !hadExtensionSettingsDraft &&
        (draftDirty || entryDraftOutcomeUnknown)
      ) {
        saved = await saveDraft();
      }

      if (saved && requestEpoch === residentSessionEpoch.current) {
        performAction(action);
      }
    } finally {
      if (requestEpoch === residentSessionEpoch.current) {
        saveAndContinueInFlight.current = false;
        setSaveAndContinueBusy(false);
      }
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
                : entryDraftOutcomeUnknown
                  ? "The previous save request had an unknown outcome. Try again only if you intend to submit a new save request."
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
          {
            label: translate(extensionSettings.language, "Discard changes"),
            disabled: saveAndContinueBusy,
            onClick: () => {
              discardAllDrafts();
              performAction(dialogState.action);
            }
          },
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

    const requestEpoch = residentSessionEpoch.current;
    const vaultId = session.activeVaultId;
    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const mutation = await client.deleteEntry(vaultId, entryId);
      const { saveResult } = settleMutationResult(mutation);
      if (!ownsVaultRequest(vaultId, requestEpoch)) {
        return false;
      }
      handleSaveResult(vaultId, saveResult);
      clearDetailSelection();
      setWorkspaceReloadKey((current) => current + 1);
      setDialogState(null);
      return true;
    } catch (deleteError) {
      if (ownsVaultRequest(vaultId, requestEpoch)) {
        setEntryActionError(
          errorMessage(
            deleteError,
            translate(extensionSettings.language, "Failed to delete entry")
          )
        );
      }
      return false;
    } finally {
      if (ownsVaultRequest(vaultId, requestEpoch)) {
        setEntryActionBusy(false);
      }
    }
  }

  async function runEntryDetailMutation(
    owner: EntryRequestOwner,
    operation: () => Promise<EntryDetail | CommittedMutation<EntryDetail>>,
    fallbackMessage: string
  ) {
    if (!ownsEntryProjection(owner)) {
      return;
    }

    setEntryActionBusy(true);
    setEntryActionError(null);

    try {
      const mutation = await operation();
      const { value: detail, saveResult } = settleMutationResult(mutation);
      if (ownsEntryProjection(owner)) {
        setEntryDetail(detail);
      }
      if (!ownsVaultRequest(owner.vaultId, owner.sessionEpoch)) {
        return;
      }
      handleSaveResult(owner.vaultId, saveResult);
      setWorkspaceReloadKey((current) => current + 1);
    } catch (mutationError) {
      if (ownsVaultRequest(owner.vaultId, owner.sessionEpoch)) {
        if (ownsEntryProjection(owner)) {
          setEntryActionError(errorMessage(mutationError, fallbackMessage));
        }
      }
    } finally {
      if (ownsVaultRequest(owner.vaultId, owner.sessionEpoch)) {
        setEntryActionBusy(false);
      }
    }
  }

  async function handleSetEntryPasskey(passkey: EntryPasskeyUpdate) {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    await runEntryDetailMutation(
      owner,
      () => client.setEntryPasskey(owner.vaultId, owner.entryId, passkey),
      translate(extensionSettings.language, "Failed to save entry passkey")
    );
  }

  async function handleClearEntryPasskey() {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    await runEntryDetailMutation(
      owner,
      () => client.clearEntryPasskey(owner.vaultId, owner.entryId),
      translate(extensionSettings.language, "Failed to save entry passkey")
    );
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
      if (requestEpoch === secretViewEpoch.current) {
        setEntryActionError(
          errorMessage(
            downloadError,
            translate(extensionSettings.language, "Failed to download attachment")
          )
        );
      }
    }
  }

  async function updateAttachment(
    owner: EntryRequestOwner,
    operation: (
      vaultId: string,
      entryId: string
    ) => Promise<EntryDetail | CommittedMutation<EntryDetail>>,
    fallbackMessage: string
  ) {
    await runEntryDetailMutation(
      owner,
      () => operation(owner.vaultId, owner.entryId),
      fallbackMessage
    );
  }

  async function handleAddAttachment(file: File, protectInMemory: boolean) {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    const fallbackMessage = translate(
      extensionSettings.language,
      "Failed to add attachment"
    );
    let dataBase64: string;
    try {
      dataBase64 = await fileToBase64(file);
    } catch (fileError) {
      if (ownsEntryProjection(owner)) {
        setEntryActionError(errorMessage(fileError, fallbackMessage));
      }
      return;
    }
    await updateAttachment(
      owner,
      (vaultId, entryId) => {
        const input = {
          name: file.name,
          dataBase64,
          protectInMemory
        };
        return client.addEntryAttachment(vaultId, entryId, input);
      },
      fallbackMessage
    );
  }

  async function handleRenameAttachment(
    oldName: string,
    newName: string,
    protectInMemory: boolean
  ) {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    await updateAttachment(
      owner,
      (vaultId, entryId) => {
        const input = {
          oldName,
          newName,
          protectInMemory
        };
        return client.updateEntryAttachmentMetadata(vaultId, entryId, input);
      },
      translate(extensionSettings.language, "Failed to update attachment")
    );
  }

  async function handleReplaceAttachment(name: string, file: File) {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    const fallbackMessage = translate(
      extensionSettings.language,
      "Failed to replace attachment"
    );
    let dataBase64: string;
    try {
      dataBase64 = await fileToBase64(file);
    } catch (fileError) {
      if (ownsEntryProjection(owner)) {
        setEntryActionError(errorMessage(fileError, fallbackMessage));
      }
      return;
    }
    await updateAttachment(
      owner,
      (vaultId, entryId) => {
        const input = { name, dataBase64 };
        return client.replaceEntryAttachmentContent(vaultId, entryId, input);
      },
      fallbackMessage
    );
  }

  async function handleDeleteAttachment(name: string) {
    const owner = captureEntryRequestOwner();
    if (!owner) {
      return;
    }

    await updateAttachment(
      owner,
      (vaultId, entryId) =>
        client.deleteEntryAttachment(vaultId, entryId, name),
      translate(extensionSettings.language, "Failed to delete attachment")
    );
  }

  function runDatabaseSettingsSave(
    vaultId: string,
    sessionEpoch: number,
    operation: () => Promise<boolean>
  ) {
    const inFlight = databaseSettingsSaveInFlight.current;
    if (
      inFlight?.vaultId === vaultId &&
      inFlight.sessionEpoch === sessionEpoch
    ) {
      return inFlight.promise;
    }

    const promise = operation();
    const pending = { vaultId, sessionEpoch, promise };
    databaseSettingsSaveInFlight.current = pending;
    void promise.finally(() => {
      if (databaseSettingsSaveInFlight.current === pending) {
        databaseSettingsSaveInFlight.current = null;
      }
    });
    return promise;
  }

  function handleSaveDatabaseSettings(update: DatabaseSettingsUpdate) {
    const vaultId = sessionRef.current?.activeVaultId;
    if (!vaultId) {
      return Promise.resolve(false);
    }
    const sessionEpoch = residentSessionEpoch.current;
    return runDatabaseSettingsSave(vaultId, sessionEpoch, () =>
      saveDatabaseSettings(update, vaultId, sessionEpoch)
    );
  }

  async function saveDatabaseSettings(
    update: DatabaseSettingsUpdate,
    vaultId: string,
    requestEpoch: number
  ) {
    setDatabaseSettingsBusy(true);
    setDatabaseSettingsError(null);

    try {
      const result = await client.updateDatabaseSettings(vaultId, update);
      if (
        requestEpoch !== residentSessionEpoch.current ||
        sessionRef.current?.activeVaultId !== vaultId
      ) {
        return false;
      }
      setDatabaseSettings(result.settings);
      setDatabaseName(result.settings.metadata.name);
      resetDatabaseSettingsDraftState();
      setSettingsDraftEpoch((current) => current + 1);
      handleSaveResult(vaultId, result.saveResult);
      setWorkspaceReloadKey((current) => current + 1);
      if (result.saveResult.status === "saved") {
        setSaveTip(translate(extensionSettings.language, "Database settings saved."));
      }
      return true;
    } catch (settingsError) {
      if (
        requestEpoch === residentSessionEpoch.current &&
        sessionRef.current?.activeVaultId === vaultId
      ) {
        setDatabaseSettingsError(
          errorMessage(
            settingsError,
            translate(extensionSettings.language, "Failed to save database settings")
          )
        );
      }
      return false;
    } finally {
      if (
        requestEpoch === residentSessionEpoch.current &&
        sessionRef.current?.activeVaultId === vaultId
      ) {
        setDatabaseSettingsBusy(false);
      }
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

      if (subscribeSessionState) {
        return;
      }

      const requestEpoch = residentSessionEpoch.current;
      try {
        const state = await client.getSessionState();
        if (cancelled || requestEpoch !== residentSessionEpoch.current) {
          return;
        }
        acceptSessionResponse(state, requestEpoch);
        setSessionErrorCause(null);
        if (desiredSettingsAvailable) {
          void reconcileSavedSettings("startup");
        }
      } catch (sessionLoadError) {
        if (cancelled || requestEpoch !== residentSessionEpoch.current) {
          return;
        }
        clearAuthoritativeSession();
        setSessionErrorCause(sessionLoadError);
        setSessionError(
          errorMessage(
            sessionLoadError,
            translate(extensionSettings.language, "Failed to load session state")
          )
        );
        if (desiredSettingsAvailable) {
          void reconcileSavedSettings("startup");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [client, localExtensionSettingsStore, subscribeSessionState]);

  useEffect(() => {
    if (subscribeSessionState || typeof window === "undefined") {
      return undefined;
    }
    let disposed = false;
    let refreshPending = false;

    async function refreshAuthoritativeSession() {
      if (disposed || refreshPending) {
        return;
      }
      refreshPending = true;
      const requestEpoch = residentSessionEpoch.current;
      try {
        const nextSession = await client.getSessionState();
        if (!disposed && requestEpoch === residentSessionEpoch.current) {
          acceptAuthoritativeSession(nextSession);
        }
      } catch (refreshError) {
        if (!disposed && requestEpoch === residentSessionEpoch.current) {
          clearAuthoritativeSession();
          setSessionErrorCause(refreshError);
          setSessionError(
            errorMessage(refreshError, "Resident session refresh is unavailable")
          );
        }
      } finally {
        refreshPending = false;
      }
    }

    const refreshOnVisibility = () => {
      if (document.visibilityState === "visible") {
        void refreshAuthoritativeSession();
      }
    };
    const refreshOnFocus = () => void refreshAuthoritativeSession();
    const timer = window.setInterval(() => {
      void refreshAuthoritativeSession();
    }, 1000);
    window.addEventListener("focus", refreshOnFocus);
    document.addEventListener("visibilitychange", refreshOnVisibility);

    return () => {
      disposed = true;
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshOnFocus);
      document.removeEventListener("visibilitychange", refreshOnVisibility);
    };
  }, [client, subscribeSessionState]);

  useEffect(() => {
    if (!subscribeSessionState) {
      return undefined;
    }
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    clearAuthoritativeSession();

    void subscribeSessionState((nextSession) => {
      if (!disposed) {
        acceptAuthoritativeSession(nextSession, true);
        void reconcileSavedSettings(nextSession.unlocked ? "unlock" : "startup");
      }
    })
      .then((nextUnsubscribe) => {
        if (disposed) {
          nextUnsubscribe();
        } else {
          unsubscribe = nextUnsubscribe;
          const requestEpoch = residentSessionEpoch.current;
          void client
            .getSessionState()
            .then((nextSession) => {
              if (
                !disposed &&
                requestEpoch === residentSessionEpoch.current
              ) {
                acceptAuthoritativeSession(nextSession, true);
                void reconcileSavedSettings("startup");
              }
            })
            .catch((refreshError) => {
              if (
                !disposed &&
                requestEpoch === residentSessionEpoch.current
              ) {
                clearAuthoritativeSession();
                setSessionErrorCause(refreshError);
                setSessionError(
                  errorMessage(
                    refreshError,
                    "Resident session refresh is unavailable"
                  )
                );
              }
            });
        }
      })
      .catch((subscriptionError) => {
        if (!disposed) {
          clearAuthoritativeSession();
          setSessionErrorCause(subscriptionError);
          setSessionError(
            errorMessage(
              subscriptionError,
              "Resident session notifications are unavailable"
            )
          );
        }
      });

    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [client, subscribeSessionState]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    const loadReconciliationError = localExtensionSettingsStore.loadReconciliationError
      ? () => localExtensionSettingsStore.loadReconciliationError!()
      : undefined;
    const subscribeReconciliationError =
      localExtensionSettingsStore.subscribeReconciliationError
        ? (listener: (error: string | null) => void) =>
            localExtensionSettingsStore.subscribeReconciliationError!(listener)
        : undefined;

    const refreshReconciliationError = (observerError: string | null = null) => {
      if (!loadReconciliationError) {
        return;
      }
      const requestEpoch = settingsReconciliationStatusEpoch.current;
      void loadReconciliationError()
        .then((error) => {
          if (
            !disposed &&
            requestEpoch === settingsReconciliationStatusEpoch.current
          ) {
            setSettingsReconciliationError(
              observerError && error
                ? `${observerError}; ${error}`
                : observerError ?? error
            );
          }
        })
        .catch((error) => {
          if (
            !disposed &&
            requestEpoch === settingsReconciliationStatusEpoch.current
          ) {
            const loadError = errorMessage(
              error,
              "Failed to load reconciliation status"
            );
            setSettingsReconciliationError(
              observerError ? `${observerError}; ${loadError}` : loadError
            );
          }
        });
    };
    if (subscribeReconciliationError) {
      void subscribeReconciliationError((error) => {
        if (!disposed) {
          settingsReconciliationStatusEpoch.current += 1;
          setSettingsReconciliationError(error);
        }
      })
        .then((nextUnsubscribe) => {
          if (disposed) {
            nextUnsubscribe();
          } else {
            unsubscribe = nextUnsubscribe;
            refreshReconciliationError();
          }
        })
        .catch((error) => {
          const observerError = errorMessage(
            error,
            "Failed to subscribe to reconciliation status"
          );
          if (!disposed) {
            setSettingsReconciliationError(observerError);
          }
          refreshReconciliationError(observerError);
        });
    } else {
      refreshReconciliationError();
    }

    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [localExtensionSettingsStore]);

  useEffect(() => {
    if (
      typeof window === "undefined" ||
      !session?.unlocked ||
      !client.recordUserActivity
    ) {
      return undefined;
    }
    let disposed = false;
    let reportPending = false;
    let lastReportedAt = 0;

    function reportActivity() {
      const now = Date.now();
      if (reportPending || now - lastReportedAt < 15_000) {
        return;
      }
      reportPending = true;
      lastReportedAt = now;
      const requestEpoch = residentSessionEpoch.current;
      void client.recordUserActivity!()
        .then((nextSession) => {
          if (!disposed) {
            acceptSessionResponse(nextSession, requestEpoch);
          }
        })
        .catch(() => undefined)
        .finally(() => {
          reportPending = false;
        });
    }

    const events = ["pointerdown", "keydown", "wheel", "scroll"];
    for (const eventName of events) {
      window.addEventListener(eventName, reportActivity, { passive: true });
    }

    return () => {
      disposed = true;
      for (const eventName of events) {
        window.removeEventListener(eventName, reportActivity);
      }
    };
  }, [client, session?.unlocked]);

  useLayoutEffect(() => {
    sourceSyncRequestEpoch.current += 1;
    setSourceSyncBusy(false);
    setSourceSyncError(null);
    setSaveTip(null);
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
        if (!cancelled && requestEpoch === secretViewEpoch.current) {
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
              saving={extensionSettingsSaving}
              error={extensionSettingsError}
              quickUnlockSupported={session?.supportsBiometricUnlock !== false}
              quickUnlockEnabled={extensionSettings.quickUnlockEnabled}
              quickUnlockEnrolled={Boolean(currentVaultReference?.supportsQuickUnlock)}
              quickUnlockVaultUnlocked={session.unlocked}
              quickUnlockBusy={quickUnlockBusy}
              quickUnlockError={quickUnlockError}
              quickUnlockCredentialResetKey={residentSessionEpoch.current}
              reconciliationError={settingsReconciliationError}
              onEnrollQuickUnlock={async (credentials) => {
                await reconcileSavedSettings("manual", credentials);
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
              const requestEpoch = residentSessionEpoch.current;
              const nextVaults = await client.deleteRecentVault(vaultRefId);
              if (!(await applyRecentVaultLimit(nextVaults, requestEpoch))) {
                return;
              }
              const current = sessionRef.current;
              if (current?.currentVaultRefId === vaultRefId) {
                acceptAuthoritativeSession({
                  ...current,
                  unlocked: false,
                  activeVaultId: null,
                  currentVaultRefId: null
                });
              }
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
        key={`recent-unlock-${session.currentVaultRefId ?? "none"}-${residentSessionEpoch.current}`}
        recentVaults={recentVaults}
        currentVaultRefId={session.currentVaultRefId}
        labels={labels.unlock}
        onSelectVault={selectCurrentVault}
        onUnlock={async ({ password, keyFilePath }) => {
          const requestEpoch = residentSessionEpoch.current;
          setUnlockBusy(true);
          setUnlockError(null);
          setUnlockErrorCause(null);
          try {
            const nextSession = await client.unlockCurrentVault({
              password,
              keyFilePath
            });
            if (acceptSessionResponse(nextSession, requestEpoch)) {
              await reconcileSavedSettings("unlock");
            }
          } catch (unlockFailure) {
            if (requestEpoch === residentSessionEpoch.current) {
              setUnlockError(
                errorMessage(
                  unlockFailure,
                  translate(extensionSettings.language, "Failed to unlock vault")
                )
              );
              setUnlockErrorCause(unlockFailure);
            }
          } finally {
            if (requestEpoch === residentSessionEpoch.current) {
              setUnlockBusy(false);
            }
          }
        }}
        onQuickUnlock={async () => {
          const requestEpoch = residentSessionEpoch.current;
          setUnlockBusy(true);
          setUnlockError(null);
          setUnlockErrorCause(null);
          try {
            const nextSession = await client.unlockCurrentVaultWithQuickUnlock();
            if (acceptSessionResponse(nextSession, requestEpoch)) {
              await reconcileSavedSettings("unlock");
            }
          } catch (unlockFailure) {
            if (requestEpoch === residentSessionEpoch.current) {
              setUnlockError(
                errorMessage(
                  unlockFailure,
                  translate(extensionSettings.language, "Failed to unlock vault")
                )
              );
              setUnlockErrorCause(unlockFailure);
              try {
                await applyRecentVaultLimit(
                  await client.listRecentVaults(),
                  requestEpoch
                );
              } catch {
                // Preserve the original quick-unlock error when status refresh also fails.
              }
            }
          } finally {
            if (requestEpoch === residentSessionEpoch.current) {
              setUnlockBusy(false);
            }
          }
        }}
        quickUnlockSupported={Boolean(session.supportsBiometricUnlock)}
        onOpenSetup={() => setShowSetup(true)}
        onOpenExtensionSettings={() => requestAction({ type: "open-extension-settings" })}
        error={unlockError}
        errorCause={unlockErrorCause}
        busy={unlockBusy || vaultSelectionBusy}
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
              pendingSave={entryDraftOutcomeUnknown}
              error={entryActionError ?? detailError}
              historyItems={historyItems}
              historyDetail={historyDetail}
              historyError={historyError}
              onBack={viewMode === "expanded" ? undefined : handleBackToEntries}
              onStartEdit={() => {
                if (!entryDetail) {
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
                void saveDraft();
              }}
              onSave={() => {
                void saveDraft();
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
              label: translate(extensionSettings.language, "Delete permanently"),
              variant: "danger",
              disabled: entryActionBusy,
              onClick: () => {
                void handleDeleteEntry(dialogState.entryId);
              }
            },
            {
              label: translate(extensionSettings.language, "Cancel"),
              disabled: entryActionBusy,
              onClick: () => setDialogState(null)
            }
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
