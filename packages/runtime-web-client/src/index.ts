import { RUNTIME_PROTOCOL_VERSION, type RuntimeTransport } from "./transport";

export interface SessionState {
  type: "session_state";
  unlocked: boolean;
  activeVaultId: string | null;
  currentVaultRefId: string | null;
  supportsBiometricUnlock: boolean;
  sourceStatus?: VaultSourceStatus | null;
}

export type ResidentAppRoute = "unlock" | "vaults" | "settings";

export interface BrowserIntegrationSettings {
  type: "browser_integration_settings";
  language: "en" | "zh-CN";
  autofillOnPageLoadEnabled: boolean;
  browserPasskeyProxyEnabled: boolean;
}

export interface VaultSourceStatus {
  type?: "vault_source_status";
  sourceKind: string;
  remoteState: "online" | "cache" | "pending_sync" | "unknown" | string;
  lastSyncAt: number | null;
  cachedAt: number | null;
  lastError: string | null;
}

export interface VaultReference {
  vaultRefId: string;
  displayName: string;
  sourceKind: string;
  sourceSummary: string;
  lastUsedAt: number;
  availability: string;
  supportsQuickUnlock: boolean;
  isCurrent: boolean;
}

export interface VaultHandle {
  type: "vault_opened";
  vaultId: string;
  name: string;
  path: string;
}

export interface DatabaseSettings {
  type: "database_settings";
  metadata: DatabaseMetadataSettings;
  publicMetadata: DatabasePublicMetadataSettings;
  history: DatabaseHistorySettings;
  recycleBin: DatabaseRecycleBinSettings;
  encryption: DatabaseEncryptionSettings;
  autosaveDelaySeconds: number | null;
  hasPassword: boolean;
}

export interface DatabaseSettingsCommitResult {
  type: "database_settings_commit_result";
  commit: "committed";
  settings: DatabaseSettings;
  saveResult: SaveVaultResult;
}

export interface DatabaseSettingsUpdate {
  metadata?: DatabaseMetadataSettings;
  publicMetadata?: DatabasePublicMetadataSettings;
  history?: DatabaseHistorySettings;
  recycleBin?: DatabaseRecycleBinSettings;
  encryption?: DatabaseEncryptionSettings;
  credentials?: DatabaseCredentialsUpdate;
  autosaveDelaySeconds?: number | null;
}

export interface DatabaseMetadataSettings {
  name: string;
  description: string | null;
  defaultUsername: string | null;
}

export interface DatabasePublicMetadataSettings {
  displayName: string | null;
  color: string | null;
  icon: string | null;
}

export interface DatabaseHistorySettings {
  maxItemsPerEntry: number | null;
  maxTotalSizeBytes: number | null;
}

export interface DatabaseRecycleBinSettings {
  enabled: boolean;
}

export interface DatabaseEncryptionSettings {
  compression: "none" | "gzip" | string;
  cipher: "aes256" | "chacha20" | "twofish" | string;
  kdf: DatabaseKdfSettings;
}

export interface DatabaseKdfSettings {
  algorithm: "aes_kdbx4" | "argon2id" | string;
  transformRounds: number | null;
  iterations: number | null;
  memoryKib: number | null;
  parallelism: number | null;
}

export interface DatabaseCredentialsUpdate {
  newPassword: string | null;
  removePassword: boolean;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  groupId?: string;
  hasTotp?: boolean;
}

export interface AutofillCredential {
  type: "autofill_credential";
  id: string;
  username: string;
  password: string;
  totp?: string | null;
}

export interface AutofillEntryFields {
  type: "autofill_entry_fields";
  id: string;
  fields: AutofillUpdateFields;
}

export interface AutofillUpdateFields {
  username: string;
  password: string;
  url: string;
}

export interface AutofillCreateContext {
  type: "autofill_create_context";
  rootGroupId: string;
}

export interface GroupNode {
  id: string;
  title: string;
  entryCount: number;
  childCount: number;
  children: GroupNode[];
}

export interface GroupTree {
  type: "group_tree";
  root: GroupNode;
}

export interface EntryDetail {
  type: "entry_detail";
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  modifiedAt?: number;
  totp?: string | null;
  totpUri?: string | null;
  passkey?: EntryPasskey | null;
  fieldProtection?: EntryFieldProtection;
  customFields?: EntryCustomField[];
  attachments?: EntryAttachment[];
}

export interface EntryPasskey {
  username: string;
  credentialId: string;
  generatedUserId: string | null;
  relyingParty: string;
  userHandle: string | null;
  backupEligible: boolean;
  backupState: boolean;
}

export type EntryPasskeyUpdate = EntryPasskey;

export interface EntryFieldProtection {
  protectTitle: boolean;
  protectUsername: boolean;
  protectPassword: boolean;
  protectUrl: boolean;
  protectNotes: boolean;
}

export interface EntryCustomField {
  key: string;
  value: string;
  protected: boolean;
}

export interface EntryAttachment {
  name: string;
  size: number;
  protectInMemory: boolean;
}

export interface EntryAttachmentContent {
  type: "entry_attachment_content";
  name: string;
  dataBase64: string;
  protectInMemory: boolean;
}

export interface EntryAttachmentInput {
  name: string;
  dataBase64: string;
  protectInMemory: boolean;
}

export interface EntryAttachmentMetadataUpdate {
  oldName: string;
  newName: string;
  protectInMemory: boolean;
}

export interface EntryAttachmentContentUpdate {
  name: string;
  dataBase64: string;
}

export type SaveVaultResult = {
  type: "save_vault_result";
  status: "saved" | "merged" | "saved_to_cache" | "conflict_copy";
  mergeSummary?: {
    mergedEntries: number;
    historySnapshotsAdded: number;
  } | null;
  conflictCopyPath?: string;
};

export interface CommittedMutation<T> {
  value: T;
  saveResult: SaveVaultResult;
  operationId: string;
}

export interface CommittedVaultMutation {
  saveResult: SaveVaultResult;
  operationId: string;
  createdGroupId?: string;
}

interface EntryMutationResponse<T> {
  type: "entry_mutation_result";
  commit: "committed";
  publication: Omit<SaveVaultResult, "type">;
  entry?: T;
}

interface VaultMutationResponse {
  type: "vault_mutation_result";
  commit: "committed";
  publication: Omit<SaveVaultResult, "type">;
  createdGroupId?: string;
}

interface DatabaseSettingsMutationResponse {
  type: "database_settings_commit_result";
  commit: "committed";
  settings: DatabaseSettings;
  saveResult: Omit<SaveVaultResult, "type">;
}

export interface EntryHistoryItem {
  index: number;
  title: string;
  username: string;
  modifiedAt: number;
  attachmentCount: number;
  customFieldCount: number;
}

export interface EntryHistoryDetail {
  type: "entry_history_detail";
  entryId: string;
  historyIndex: number;
  title: string;
  username: string;
  url: string;
  notes: string;
  modifiedAt: number;
  customFields: EntryCustomField[];
  attachments: EntryAttachment[];
}

export interface EntryHistoryList {
  type: "entry_history_list";
  items: EntryHistoryItem[];
}

export interface EntryDraft {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpUri: string | null;
  customFields: EntryCustomField[];
}

export type AutofillPersistPlan =
  | {
      mode: "update";
      entryId: string;
      expectedFields: AutofillUpdateFields;
      desiredFields: AutofillUpdateFields;
    }
  | {
      mode: "create";
      parentGroupId: string;
      plannedEntryId: string;
      expectedMatchingEntryIds: string[];
      desiredFields: EntryDraft;
    };

export interface PersistAutofillMutationRequest {
  transactionId: string;
  operationId: string;
  vaultId: string;
  plan: AutofillPersistPlan;
}

export type AutofillPersistConflictCode =
  | "active_vault_mismatch"
  | "update_precondition_failed"
  | "create_matching_set_changed"
  | "planned_entry_id_collision"
  | "operation_binding_mismatch"
  | "concurrent_vault_changes"
  | "source_changed_retry_exhausted"
  | "legacy_create_outcome_ambiguous";

interface AutofillPersistResultBase {
  type: "autofill_persist_result";
  transactionId: string;
  operationId: string;
  vaultId: string;
}

export type AutofillPersistResult = AutofillPersistResultBase &
  (
    | ({
        outcome: "durable";
        disposition: "committed" | "replayed";
        entryId: string;
        committedFingerprint: {
          contentSha256: string;
          sizeBytes: number;
        };
        mergeSummary: {
          mergedEntries: number;
          historySnapshotsAdded: number;
        } | null;
        receiptVersion: 1;
      } &
        (
          | {
              durability: "source";
              cacheState: "not_applicable" | "current" | "write_failed";
            }
          | {
              durability: "pending_remote_cache";
              cacheState: "pending_sync";
            }
        ))
    | ({
        outcome: "conflict";
      } &
        (
          | {
              code: "active_vault_mismatch" | "source_changed_retry_exhausted";
              retryable: true;
            }
          | {
              code: Exclude<
                AutofillPersistConflictCode,
                "active_vault_mismatch" | "source_changed_retry_exhausted"
              >;
              retryable: false;
            }
        ))
  );

export interface EntryCreateInput extends EntryDraft {
  parentGroupId: string;
}

export interface FillCandidates {
  type: "fill_candidates";
  entries: EntrySummary[];
}

export interface UnlockCredentials {
  password?: string | null;
  keyFilePath?: string | null;
}

export interface VaultReferenceList {
  type: "vault_reference_list";
  vaults: VaultReference[];
}

export interface OneDriveAuthSession {
  type: "one_drive_auth_session";
  authUrl: string;
  redirectUri: string;
  expiresInSeconds: number;
}

export interface OneDriveAuthStatus {
  type: "one_drive_auth_status";
  status: "authorized" | "error" | string;
  accountLabel: string | null;
}

export interface OneDriveItem {
  driveId: string;
  itemId: string;
  name: string;
  folder: boolean;
  size: number | null;
}

export interface OneDriveItemList {
  type: "one_drive_item_list";
  items: OneDriveItem[];
}

interface RuntimeErrorResponse {
  type: "error";
  code: string;
  message: string;
}

class RuntimeResponseError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "RuntimeResponseError";
  }
}

export class RuntimeClient {
  constructor(private readonly transport: RuntimeTransport) {}

  async getSessionState(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "get_session_state"
    });
  }

  async getBrowserIntegrationSettings(): Promise<BrowserIntegrationSettings> {
    return this.sendCommand<BrowserIntegrationSettings>({
      type: "get_browser_integration_settings"
    });
  }

  async activateResidentApp(route: ResidentAppRoute): Promise<void> {
    await this.sendCommand<{ type: "resident_app_activated" }>({
      type: "activate_resident_app",
      route
    });
  }

  async listRecentVaults(): Promise<VaultReference[]> {
    const response = await this.sendCommand<VaultReferenceList>({
      type: "list_recent_vaults"
    });
    return response.vaults;
  }

  async preloadCurrentVault(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "preload_current_vault"
    });
  }

  async addLocalVaultReference(path?: string): Promise<VaultReference> {
    return this.sendCommand<VaultReference>({
      type: "add_local_vault_reference",
      path
    });
  }

  async beginOneDriveLogin(): Promise<OneDriveAuthSession> {
    return this.sendCommand<OneDriveAuthSession>({
      type: "begin_one_drive_login"
    });
  }

  async completePendingOneDriveLogin(): Promise<OneDriveAuthStatus> {
    return this.sendCommand<OneDriveAuthStatus>({
      type: "complete_pending_one_drive_login"
    });
  }

  async listOneDriveChildren(parentItemId?: string | null): Promise<OneDriveItem[]> {
    const response = await this.sendCommand<OneDriveItemList>({
      type: "list_one_drive_children",
      parent_item_id: parentItemId ?? null
    });
    return response.items;
  }

  async addOneDriveVaultReference(
    driveId: string,
    itemId: string
  ): Promise<VaultReference> {
    return this.sendCommand<VaultReference>({
      type: "add_one_drive_vault_reference",
      drive_id: driveId,
      item_id: itemId
    });
  }

  async setCurrentVault(vaultRefId: string): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "set_current_vault",
      vault_ref_id: vaultRefId
    });
  }

  async retryVaultSourceSync(vaultId: string): Promise<VaultSourceStatus> {
    return this.sendCommand<VaultSourceStatus>({
      type: "retry_vault_source_sync",
      vault_id: vaultId
    });
  }

  async deleteRecentVault(vaultRefId: string): Promise<VaultReference[]> {
    const response = await this.sendCommand<VaultReferenceList>({
      type: "delete_vault_reference",
      vault_ref_id: vaultRefId
    });
    return response.vaults;
  }

  async deleteRecentVaultIfNotCurrent(vaultRefId: string): Promise<VaultReference[]> {
    const response = await this.sendCommand<VaultReferenceList>({
      type: "delete_vault_reference_if_not_current",
      vault_ref_id: vaultRefId
    });
    return response.vaults;
  }

  async openLocalVault(path: string): Promise<VaultHandle> {
    return this.sendCommand<VaultHandle>({
      type: "open_local_vault",
      path
    });
  }

  async lockSession(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "lock_session"
    });
  }

  async recordUserActivity(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "record_user_activity"
    });
  }

  async unlockCurrentVaultWithPassword(password: string): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "unlock_current_vault_with_password",
      password
    });
  }

  async unlockCurrentVault(credentials: UnlockCredentials): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "unlock_current_vault",
      password: normalizeOptionalSecret(credentials.password),
      key_file_path: normalizeOptionalSecret(credentials.keyFilePath)
    });
  }

  async enableQuickUnlockForCurrentVault(
    credentials: UnlockCredentials
  ): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "enable_quick_unlock_for_current_vault",
      password: normalizeOptionalSecret(credentials.password),
      key_file_path: normalizeOptionalSecret(credentials.keyFilePath)
    });
  }

  async unlockCurrentVaultWithQuickUnlock(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "unlock_current_vault_with_quick_unlock"
    });
  }

  async disableQuickUnlockForCurrentVault(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "disable_quick_unlock_for_current_vault"
    });
  }

  async unlockWithPassword(
    vaultId: string,
    password: string
  ): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "unlock_with_password",
      vault_id: vaultId,
      password
    });
  }

  async unlockVault(
    vaultId: string,
    credentials: UnlockCredentials
  ): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "unlock_vault",
      vault_id: vaultId,
      password: normalizeOptionalSecret(credentials.password),
      key_file_path: normalizeOptionalSecret(credentials.keyFilePath)
    });
  }

  async listEntries(vaultId: string): Promise<EntrySummary[]> {
    const response = await this.sendCommand<{ type: "entry_list"; entries: EntrySummary[] }>({
      type: "list_entries",
      vault_id: vaultId
    });
    return response.entries;
  }

  async listGroups(vaultId: string): Promise<GroupTree> {
    return this.sendCommand<GroupTree>({
      type: "list_groups",
      vault_id: vaultId
    });
  }

  async createGroup(
    vaultId: string,
    parentGroupId: string,
    title: string,
    operationId?: string
  ): Promise<CommittedVaultMutation & { createdGroupId: string }> {
    const result = await this.sendVaultMutationCommand(
      {
        type: "create_group",
        vault_id: vaultId,
        parent_group_id: parentGroupId,
        title
      },
      operationId
    );
    if (result.createdGroupId === undefined) {
      throw new TypeError("runtime omitted the created group id");
    }
    return { ...result, createdGroupId: result.createdGroupId };
  }

  async renameGroup(
    vaultId: string,
    groupId: string,
    title: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "rename_group",
        vault_id: vaultId,
        group_id: groupId,
        title
      },
      operationId
    );
  }

  async moveGroup(
    vaultId: string,
    groupId: string,
    targetParentGroupId: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "move_group",
        vault_id: vaultId,
        group_id: groupId,
        target_parent_group_id: targetParentGroupId
      },
      operationId
    );
  }

  async deleteGroup(
    vaultId: string,
    groupId: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "delete_group",
        vault_id: vaultId,
        group_id: groupId
      },
      operationId
    );
  }

  async moveEntryToGroup(
    vaultId: string,
    entryId: string,
    targetGroupId: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "move_entry_to_group",
        vault_id: vaultId,
        entry_id: entryId,
        target_group_id: targetGroupId
      },
      operationId
    );
  }

  async getEntryDetail(
    vaultId: string,
    entryId: string
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "get_entry_detail",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async getAutofillCredential(
    vaultId: string,
    entryId: string,
    url: string
  ): Promise<AutofillCredential> {
    return this.sendCommand<AutofillCredential>({
      type: "get_autofill_credential",
      vault_id: vaultId,
      entry_id: entryId,
      url
    });
  }

  async getAutofillEntryFields(
    vaultId: string,
    entryId: string,
    url: string
  ): Promise<AutofillEntryFields> {
    return this.sendCommand<AutofillEntryFields>({
      type: "get_autofill_entry_fields",
      vault_id: vaultId,
      entry_id: entryId,
      url
    });
  }

  async getAutofillCreateContext(
    vaultId: string
  ): Promise<AutofillCreateContext> {
    return this.sendCommand<AutofillCreateContext>({
      type: "get_autofill_create_context",
      vault_id: vaultId
    });
  }

  async createEntry(
    vaultId: string,
    input: EntryCreateInput,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "create_entry",
        vault_id: vaultId,
        parent_group_id: input.parentGroupId,
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        notes: input.notes,
        totp_uri: input.totpUri
      },
      operationId,
      true
    );
  }

  async updateEntryFields(
    vaultId: string,
    entryId: string,
    input: EntryDraft,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "update_entry_fields",
        vault_id: vaultId,
        entry_id: entryId,
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        notes: input.notes,
        totp_uri: input.totpUri,
        custom_fields: input.customFields
      },
      operationId,
      true
    );
  }

  async compareAndUpdateEntryFields(
    vaultId: string,
    entryId: string,
    expectedFields: EntryDraft,
    desiredFields: EntryDraft
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendMutationCommand<EntryDetail>(vaultId, {
      type: "compare_and_update_entry_fields",
      vault_id: vaultId,
      entry_id: entryId,
      expected_fields: entryFieldsCommand(expectedFields),
      desired_fields: entryFieldsCommand(desiredFields)
    });
  }

  async persistAutofillMutation(
    request: PersistAutofillMutationRequest
  ): Promise<AutofillPersistResult> {
    const snapshot = snapshotAutofillPersistRequest(request);
    if (
      snapshot.binding.mode === "create" &&
      !isCanonicalNonNilUuid(snapshot.binding.entryId)
    ) {
      throw new TypeError("planned entry id must be a canonical non-nil UUID");
    }
    const response = await this.sendCommand<unknown>({
      type: "persist_autofill_mutation",
      transaction_id: snapshot.binding.transactionId,
      operation_id: snapshot.binding.operationId,
      vault_id: snapshot.binding.vaultId,
      plan: snapshot.commandPlan
    });
    return parseAutofillPersistResult(response, snapshot.binding);
  }

  async clearEntryTotp(
    vaultId: string,
    entryId: string,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "clear_entry_totp",
        vault_id: vaultId,
        entry_id: entryId
      },
      operationId,
      true
    );
  }

  async setEntryPasskey(
    vaultId: string,
    entryId: string,
    passkey: EntryPasskeyUpdate,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "set_entry_passkey",
        vault_id: vaultId,
        entry_id: entryId,
        passkey
      },
      operationId,
      true
    );
  }

  async clearEntryPasskey(
    vaultId: string,
    entryId: string,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "clear_entry_passkey",
        vault_id: vaultId,
        entry_id: entryId
      },
      operationId,
      true
    );
  }

  async deleteEntry(
    vaultId: string,
    entryId: string,
    operationId?: string
  ): Promise<CommittedMutation<void>> {
    const result = await this.sendEntryMutationCommand<undefined>(
      {
        type: "delete_entry",
        vault_id: vaultId,
        entry_id: entryId
      },
      operationId,
      false
    );
    return { ...result, value: undefined };
  }

  async saveVault(vaultId: string): Promise<SaveVaultResult> {
    return this.sendCommand<SaveVaultResult>({
      type: "save_vault",
      vault_id: vaultId
    });
  }

  async retryMutationSave(
    vaultId: string,
    operationId: string
  ): Promise<SaveVaultResult> {
    return this.sendMutationSave(vaultId, operationId);
  }

  async getDatabaseSettings(vaultId: string): Promise<DatabaseSettings> {
    return this.sendCommand<DatabaseSettings>({
      type: "get_database_settings",
      vault_id: vaultId
    });
  }

  async updateDatabaseSettings(
    vaultId: string,
    update: DatabaseSettingsUpdate,
    operationId?: string
  ): Promise<DatabaseSettingsCommitResult> {
    return this.sendDatabaseSettingsMutationCommand(
      {
        type: "update_database_settings",
        vault_id: vaultId,
        update
      },
      operationId
    );
  }

  async getEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<EntryAttachmentContent> {
    return this.sendCommand<EntryAttachmentContent>({
      type: "get_entry_attachment_content",
      vault_id: vaultId,
      entry_id: entryId,
      name
    });
  }

  async addEntryAttachment(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentInput,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "add_entry_attachment",
        vault_id: vaultId,
        entry_id: entryId,
        name: input.name,
        data_base64: input.dataBase64,
        protect_in_memory: input.protectInMemory
      },
      operationId,
      true
    );
  }

  async updateEntryAttachmentMetadata(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentMetadataUpdate,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "update_entry_attachment_metadata",
        vault_id: vaultId,
        entry_id: entryId,
        old_name: input.oldName,
        new_name: input.newName,
        protect_in_memory: input.protectInMemory
      },
      operationId,
      true
    );
  }

  async replaceEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentContentUpdate,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "replace_entry_attachment_content",
        vault_id: vaultId,
        entry_id: entryId,
        name: input.name,
        data_base64: input.dataBase64
      },
      operationId,
      true
    );
  }

  async deleteEntryAttachment(
    vaultId: string,
    entryId: string,
    name: string,
    operationId?: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "delete_entry_attachment",
        vault_id: vaultId,
        entry_id: entryId,
        name
      },
      operationId,
      true
    );
  }

  async listEntryHistory(
    vaultId: string,
    entryId: string
  ): Promise<EntryHistoryItem[]> {
    const response = await this.sendCommand<EntryHistoryList>({
      type: "list_entry_history",
      vault_id: vaultId,
      entry_id: entryId
    });
    return response.items;
  }

  async getEntryHistoryDetail(
    vaultId: string,
    entryId: string,
    historyIndex: number
  ): Promise<EntryHistoryDetail> {
    return this.sendCommand<EntryHistoryDetail>({
      type: "get_entry_history_detail",
      vault_id: vaultId,
      entry_id: entryId,
      history_index: historyIndex
    });
  }

  async restoreEntryHistory(
    vaultId: string,
    entryId: string,
    historyIndex: number,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "restore_entry_history",
        vault_id: vaultId,
        entry_id: entryId,
        history_index: historyIndex
      },
      operationId
    );
  }

  async clearEntryHistory(
    vaultId: string,
    entryId: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "clear_entry_history",
        vault_id: vaultId,
        entry_id: entryId
      },
      operationId
    );
  }

  async recycleEntry(
    vaultId: string,
    entryId: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "recycle_entry",
        vault_id: vaultId,
        entry_id: entryId
      },
      operationId
    );
  }

  async restoreRecycledEntry(
    vaultId: string,
    entryId: string,
    targetGroupId?: string,
    operationId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand(
      {
        type: "restore_recycled_entry",
        vault_id: vaultId,
        entry_id: entryId,
        target_group_id: targetGroupId
      },
      operationId
    );
  }

  async findFillCandidates(
    vaultId: string,
    url: string
  ): Promise<EntrySummary[]> {
    const response = await this.sendCommand<FillCandidates>({
      type: "find_fill_candidates",
      vault_id: vaultId,
      url
    });
    return response.entries;
  }

  async findExactMatchingEntryIds(
    vaultId: string,
    fields: EntryDraft
  ): Promise<string[]> {
    const response = await this.sendCommand<{
      type: "entry_id_list";
      entryIds: string[];
    }>({
      type: "find_exact_matching_entry_ids",
      vault_id: vaultId,
      fields: entryFieldsCommand(fields)
    });
    return response.entryIds;
  }

  private async sendMutationCommand<T>(
    vaultId: string,
    command: Record<string, unknown>,
    requestedOperationId?: string
  ): Promise<CommittedMutation<T>> {
    const operationId = requestedOperationId ?? createLogicalOperationId();
    const replayableCommand =
      command.type === "create_entry"
        ? { ...command, entry_id: operationId }
        : command;
    let response: T;
    try {
      response = await this.sendCommand<T>(replayableCommand, operationId);
    } catch (error) {
      if (!isAmbiguousMutationFailure(error)) {
        throw error;
      }
      try {
        response = await this.sendCommand<T>(replayableCommand, operationId);
      } catch (retryError) {
        // Once an attempt may have reached the resident writer, a later
        // business error cannot prove that the first attempt did not commit.
        // Preserve the logical operation identity so the caller can reload or
        // retry the same operation instead of treating the replay as a
        // definitive failure.
        throw new RuntimeMutationOutcomeUnknownError(operationId, retryError);
      }
    }
    try {
      const saveResult = await this.sendMutationSave(vaultId, operationId);
      return { value: response, saveResult, operationId };
    } catch (error) {
      if (error instanceof RuntimeMutationSaveError) {
        throw error.withMutationResult(response);
      }
      throw error;
    }
  }

  private async sendEntryMutationCommand<T>(
    command: Record<string, unknown>,
    requestedOperationId: string | undefined,
    requiresEntry: boolean
  ): Promise<CommittedMutation<T>> {
    const operationId = requestedOperationId ?? createLogicalOperationId();
    const replayableCommand =
      command.type === "create_entry"
        ? { ...command, entry_id: operationId }
        : command;
    let response: EntryMutationResponse<T>;
    try {
      response = await this.sendCommand<EntryMutationResponse<T>>(
        replayableCommand,
        operationId
      );
    } catch (error) {
      if (!isAmbiguousMutationFailure(error)) {
        throw error;
      }
      try {
        response = await this.sendCommand<EntryMutationResponse<T>>(
          replayableCommand,
          operationId
        );
      } catch (retryError) {
        throw new RuntimeMutationOutcomeUnknownError(operationId, retryError);
      }
    }
    if (
      response.type !== "entry_mutation_result" ||
      response.commit !== "committed" ||
      (requiresEntry && response.entry === undefined)
    ) {
      throw new TypeError("runtime returned an invalid committed entry mutation");
    }
    const value = requiresEntry
      ? ({
          type: "entry_detail",
          ...(response.entry as Record<string, unknown>)
        } as T)
      : (undefined as T);
    return {
      value,
      saveResult: {
        type: "save_vault_result",
        ...response.publication
      },
      operationId
    };
  }

  private async sendVaultMutationCommand(
    command: Record<string, unknown>,
    requestedOperationId?: string
  ): Promise<CommittedVaultMutation> {
    const operationId = requestedOperationId ?? createLogicalOperationId();
    const response = await this.sendCommittedCommand<VaultMutationResponse>(
      command,
      operationId
    );
    if (
      response.type !== "vault_mutation_result" ||
      response.commit !== "committed"
    ) {
      throw new TypeError("runtime returned an invalid committed vault mutation");
    }
    return {
      saveResult: {
        type: "save_vault_result",
        ...response.publication
      },
      operationId,
      ...(response.createdGroupId === undefined
        ? {}
        : { createdGroupId: response.createdGroupId })
    };
  }

  private async sendDatabaseSettingsMutationCommand(
    command: Record<string, unknown>,
    requestedOperationId?: string
  ): Promise<DatabaseSettingsCommitResult> {
    const operationId = requestedOperationId ?? createLogicalOperationId();
    const response =
      await this.sendCommittedCommand<DatabaseSettingsMutationResponse>(
        command,
        operationId
      );
    if (
      response.type !== "database_settings_commit_result" ||
      response.commit !== "committed"
    ) {
      throw new TypeError(
        "runtime returned an invalid committed database settings mutation"
      );
    }
    return {
      ...response,
      saveResult: {
        type: "save_vault_result",
        ...response.saveResult
      }
    };
  }

  private async sendCommittedCommand<T>(
    command: Record<string, unknown>,
    operationId: string
  ): Promise<T> {
    try {
      return await this.sendCommand<T>(command, operationId);
    } catch (error) {
      if (!isAmbiguousMutationFailure(error)) {
        throw error;
      }
      try {
        return await this.sendCommand<T>(command, operationId);
      } catch (retryError) {
        throw new RuntimeMutationOutcomeUnknownError(operationId, retryError);
      }
    }
  }

  private async sendMutationSave(
    vaultId: string,
    operationId: string
  ): Promise<SaveVaultResult> {
    const command = { type: "save_vault", vault_id: vaultId };
    try {
      return await this.sendCommand<SaveVaultResult>(command, operationId);
    } catch (error) {
      if (!isAmbiguousMutationFailure(error)) {
        throw new RuntimeMutationSaveError(operationId, error);
      }
      try {
        return await this.sendCommand<SaveVaultResult>(command, operationId);
      } catch (retryError) {
        throw new RuntimeMutationSaveError(operationId, retryError);
      }
    }
  }

  private async sendCommand<T>(
    command: Record<string, unknown>,
    operationId?: string
  ): Promise<T> {
    const response = await this.transport.send({
      version: RUNTIME_PROTOCOL_VERSION,
      ...(operationId ? { operationId } : {}),
      command
    });

    if (isRuntimeErrorResponse(response)) {
      throw new RuntimeResponseError(response.code, response.message);
    }

    return response as T;
  }
}

class RuntimeMutationOutcomeUnknownError extends Error {
  readonly code: string;

  constructor(
    readonly operationId: string,
    cause: unknown
  ) {
    super(
      cause instanceof Error
        ? `runtime mutation outcome is unknown: ${cause.message}`
        : "runtime mutation outcome is unknown",
      { cause }
    );
    this.name = "RuntimeMutationOutcomeUnknownError";
    this.code = "request_outcome_unknown";
  }
}

class RuntimeMutationSaveError extends Error {
  readonly code: string;

  constructor(
    readonly operationId: string,
    cause: unknown,
    readonly mutationResult?: unknown
  ) {
    super(cause instanceof Error ? cause.message : "runtime mutation save failed", {
      cause
    });
    this.name = "RuntimeMutationSaveError";
    this.code =
      typeof cause === "object" &&
      cause !== null &&
      "code" in cause &&
      typeof (cause as { code?: unknown }).code === "string"
        ? (cause as { code: string }).code
        : "mutation_save_failed";
  }

  withMutationResult(result: unknown) {
    return new RuntimeMutationSaveError(this.operationId, this.cause, result);
  }
}

export function runtimeMutationOperationId(error: unknown): string | null {
  if (
    typeof error !== "object" ||
    error === null ||
    !("operationId" in error) ||
    typeof (error as { operationId?: unknown }).operationId !== "string"
  ) {
    return null;
  }
  const operationId = (error as { operationId: string }).operationId;
  return isCanonicalNonNilUuid(operationId) ? operationId : null;
}

export function runtimeMutationResult<T>(error: unknown): T | null {
  if (!(error instanceof RuntimeMutationSaveError)) {
    return null;
  }
  return (error.mutationResult as T | undefined) ?? null;
}

let logicalOperationSequence = 0;

function createLogicalOperationId(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    logicalOperationSequence += 1;
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
    const sequence = logicalOperationSequence;
    bytes[0] ^= sequence & 0xff;
    bytes[1] ^= (sequence >>> 8) & 0xff;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

function isAmbiguousMutationFailure(error: unknown) {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return false;
  }
  const code = (error as { code?: unknown }).code;
  return (
    code === "native_port_disconnected" ||
    code === "native_timeout" ||
    code === "request_outcome_unknown"
  );
}

export type { RuntimeTransport };
export {
  RUNTIME_PROTOCOL_VERSION,
  createNegotiatedRuntimeTransport
} from "./transport";
export type { RuntimeHandshake } from "./transport";

function isRuntimeErrorResponse(value: unknown): value is RuntimeErrorResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "error" &&
    typeof (value as { code?: unknown }).code === "string" &&
    typeof (value as { message?: unknown }).message === "string"
  );
}

function normalizeOptionalSecret(value: string | null | undefined): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  return value;
}

function entryFieldsCommand(fields: EntryDraft) {
  return {
    title: fields.title,
    username: fields.username,
    password: fields.password,
    url: fields.url,
    notes: fields.notes,
    totpUri: fields.totpUri,
    customFields: fields.customFields.map((field) => ({
      key: field.key,
      value: field.value,
      protected: field.protected
    }))
  };
}

function autofillUpdateFieldsCommand(fields: AutofillUpdateFields) {
  return {
    username: fields.username,
    password: fields.password,
    url: fields.url
  };
}

interface AutofillPersistRequestBinding {
  readonly transactionId: string;
  readonly operationId: string;
  readonly vaultId: string;
  readonly mode: AutofillPersistPlan["mode"];
  readonly entryId: string;
}

function snapshotAutofillPersistRequest(request: PersistAutofillMutationRequest) {
  const transactionId = request.transactionId;
  const operationId = request.operationId;
  const vaultId = request.vaultId;
  const plan = request.plan;
  if (plan.mode === "update") {
    const entryId = plan.entryId;
    return {
      binding: Object.freeze({
        transactionId,
        operationId,
        vaultId,
        mode: "update" as const,
        entryId
      }),
      commandPlan: {
        mode: "update",
        entry_id: entryId,
        expected_fields: autofillUpdateFieldsCommand(plan.expectedFields),
        desired_fields: autofillUpdateFieldsCommand(plan.desiredFields)
      }
    };
  }

  const entryId = plan.plannedEntryId;
  return {
    binding: Object.freeze({
      transactionId,
      operationId,
      vaultId,
      mode: "create" as const,
      entryId
    }),
    commandPlan: {
      mode: "create",
      parent_group_id: plan.parentGroupId,
      planned_entry_id: entryId,
      expected_matching_entry_ids: [...plan.expectedMatchingEntryIds],
      desired_fields: entryFieldsCommand(plan.desiredFields)
    }
  };
}

function isCanonicalNonNilUuid(value: string): boolean {
  return (
    value !== "00000000-0000-0000-0000-000000000000" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
  );
}

const AUTOFILL_CONFLICT_CODES = new Set<AutofillPersistConflictCode>([
  "active_vault_mismatch",
  "update_precondition_failed",
  "create_matching_set_changed",
  "planned_entry_id_collision",
  "operation_binding_mismatch",
  "concurrent_vault_changes",
  "source_changed_retry_exhausted",
  "legacy_create_outcome_ambiguous"
]);

function parseAutofillPersistResult(
  value: unknown,
  binding: AutofillPersistRequestBinding
): AutofillPersistResult {
  if (!isRecord(value) || value.type !== "autofill_persist_result") {
    throw invalidAutofillPersistResult("unexpected response type");
  }
  if (
    value.transactionId !== binding.transactionId ||
    value.operationId !== binding.operationId ||
    value.vaultId !== binding.vaultId
  ) {
    throw invalidAutofillPersistResult("response identity does not match request");
  }

  if (value.outcome === "conflict") {
    requireExactKeys(value, [
      "type",
      "transactionId",
      "operationId",
      "vaultId",
      "outcome",
      "code",
      "retryable"
    ]);
    if (
      typeof value.code !== "string" ||
      !AUTOFILL_CONFLICT_CODES.has(value.code as AutofillPersistConflictCode) ||
      typeof value.retryable !== "boolean" ||
      !validConflictForPlan(
        binding.mode,
        value.code as AutofillPersistConflictCode,
        value.retryable
      )
    ) {
      throw invalidAutofillPersistResult("invalid conflict outcome");
    }
    return value as unknown as AutofillPersistResult;
  }

  if (value.outcome !== "durable") {
    throw invalidAutofillPersistResult("unknown outcome");
  }
  requireExactKeys(value, [
    "type",
    "transactionId",
    "operationId",
    "vaultId",
    "outcome",
    "disposition",
    "entryId",
    "durability",
    "cacheState",
    "committedFingerprint",
    "mergeSummary",
    "receiptVersion"
  ]);

  if (
    (value.disposition !== "committed" && value.disposition !== "replayed") ||
    value.entryId !== binding.entryId ||
    (value.durability !== "source" && value.durability !== "pending_remote_cache") ||
    !validCacheState(value.cacheState) ||
    !validDurabilityCachePair(value.durability, value.cacheState) ||
    !validCommittedFingerprint(value.committedFingerprint) ||
    !validMergeSummary(value.mergeSummary) ||
    value.receiptVersion !== 1
  ) {
    throw invalidAutofillPersistResult("invalid durable outcome");
  }
  return value as unknown as AutofillPersistResult;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactKeys(value: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !hasOwn(value, key))) {
    throw invalidAutofillPersistResult("unexpected response fields");
  }
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function validCacheState(
  value: unknown
): value is "not_applicable" | "current" | "pending_sync" | "write_failed" {
  return (
    value === "not_applicable" ||
    value === "current" ||
    value === "pending_sync" ||
    value === "write_failed"
  );
}

function validDurabilityCachePair(
  durability: "source" | "pending_remote_cache",
  cacheState: "not_applicable" | "current" | "pending_sync" | "write_failed"
): boolean {
  return durability === "pending_remote_cache"
    ? cacheState === "pending_sync"
    : cacheState !== "pending_sync";
}

function validConflictForPlan(
  mode: AutofillPersistPlan["mode"],
  code: AutofillPersistConflictCode,
  retryable: boolean
): boolean {
  const expectedRetryable =
    code === "active_vault_mismatch" || code === "source_changed_retry_exhausted";
  if (retryable !== expectedRetryable) {
    return false;
  }
  if (mode === "update") {
    return (
      code !== "create_matching_set_changed" &&
      code !== "planned_entry_id_collision" &&
      code !== "legacy_create_outcome_ambiguous"
    );
  }
  return code !== "update_precondition_failed";
}

function validCommittedFingerprint(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  try {
    requireExactKeys(value, ["contentSha256", "sizeBytes"]);
  } catch {
    return false;
  }
  return (
    typeof value.contentSha256 === "string" &&
    /^[0-9a-f]{64}$/.test(value.contentSha256) &&
    typeof value.sizeBytes === "number" &&
    Number.isSafeInteger(value.sizeBytes) &&
    value.sizeBytes >= 0
  );
}

function validMergeSummary(value: unknown): boolean {
  if (value === null) {
    return true;
  }
  if (!isRecord(value)) {
    return false;
  }
  try {
    requireExactKeys(value, ["mergedEntries", "historySnapshotsAdded"]);
  } catch {
    return false;
  }
  return isNonnegativeSafeInteger(value.mergedEntries) &&
    isNonnegativeSafeInteger(value.historySnapshotsAdded);
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function invalidAutofillPersistResult(reason: string): TypeError {
  return new TypeError(`invalid autofill persist result: ${reason}`);
}
