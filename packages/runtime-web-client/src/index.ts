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
  publication: PublicationResult;
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

export type PublicationResult = {
  type: "publication_result";
  status: "published" | "reconciled" | "pending" | "conflict_split";
  reconciliationSummary?: {
    mergedEntries: number;
    historySnapshotsAdded: number;
  } | null;
  conflictCopyPath?: string;
};

export interface CommittedMutation<T> {
  value: T;
  publication: PublicationResult;
}

export interface CommittedVaultMutation {
  publication: PublicationResult;
  createdGroupId?: string;
}

export interface CommittedAutofillMutation {
  commit: "committed";
  publication: PublicationResult;
}

interface EntryMutationResponse<T> {
  type: "entry_mutation_result";
  commit: "committed";
  publication: Omit<PublicationResult, "type">;
  entry?: T;
}

interface VaultMutationResponse {
  type: "vault_mutation_result";
  commit: "committed";
  publication: Omit<PublicationResult, "type">;
  createdGroupId?: string;
}

interface DatabaseSettingsMutationResponse {
  type: "database_settings_commit_result";
  commit: "committed";
  settings: DatabaseSettings;
  publication: Omit<PublicationResult, "type">;
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
    title: string
  ): Promise<CommittedVaultMutation & { createdGroupId: string }> {
    const result = await this.sendVaultMutationCommand({
      type: "create_group",
      vault_id: vaultId,
      parent_group_id: parentGroupId,
      title
    });
    if (result.createdGroupId === undefined) {
      throw new TypeError("runtime omitted the created group id");
    }
    return { ...result, createdGroupId: result.createdGroupId };
  }

  async renameGroup(
    vaultId: string,
    groupId: string,
    title: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "rename_group",
      vault_id: vaultId,
      group_id: groupId,
      title
    });
  }

  async moveGroup(
    vaultId: string,
    groupId: string,
    targetParentGroupId: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "move_group",
      vault_id: vaultId,
      group_id: groupId,
      target_parent_group_id: targetParentGroupId
    });
  }

  async deleteGroup(
    vaultId: string,
    groupId: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "delete_group",
      vault_id: vaultId,
      group_id: groupId
    });
  }

  async moveEntryToGroup(
    vaultId: string,
    entryId: string,
    targetGroupId: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "move_entry_to_group",
      vault_id: vaultId,
      entry_id: entryId,
      target_group_id: targetGroupId
    });
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

  async createAutofillEntry(
    vaultId: string,
    input: EntryCreateInput
  ): Promise<CommittedAutofillMutation> {
    return this.sendAutofillEntryMutationCommand({
      type: "create_autofill_entry",
      vault_id: vaultId,
      parent_group_id: input.parentGroupId,
      title: input.title,
      username: input.username,
      password: input.password,
      url: input.url,
      notes: input.notes,
      totp_uri: input.totpUri
    });
  }

  async updateAutofillEntryFields(
    vaultId: string,
    entryId: string,
    expectedFields: AutofillUpdateFields,
    desiredFields: AutofillUpdateFields
  ): Promise<CommittedAutofillMutation> {
    return this.sendAutofillEntryMutationCommand({
      type: "update_autofill_entry_fields",
      vault_id: vaultId,
      entry_id: entryId,
      expected_fields: autofillUpdateFieldsCommand(expectedFields),
      desired_fields: autofillUpdateFieldsCommand(desiredFields)
    });
  }

  async createEntry(
    vaultId: string,
    input: EntryCreateInput
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
      true
    );
  }

  async updateEntryFields(
    vaultId: string,
    entryId: string,
    input: EntryDraft
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
      true
    );
  }

  async clearEntryTotp(
    vaultId: string,
    entryId: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "clear_entry_totp",
        vault_id: vaultId,
        entry_id: entryId
      },
      true
    );
  }

  async setEntryPasskey(
    vaultId: string,
    entryId: string,
    passkey: EntryPasskeyUpdate
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "set_entry_passkey",
        vault_id: vaultId,
        entry_id: entryId,
        passkey
      },
      true
    );
  }

  async clearEntryPasskey(
    vaultId: string,
    entryId: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "clear_entry_passkey",
        vault_id: vaultId,
        entry_id: entryId
      },
      true
    );
  }

  async deleteEntry(
    vaultId: string,
    entryId: string
  ): Promise<CommittedMutation<void>> {
    const result = await this.sendEntryMutationCommand<undefined>(
      {
        type: "delete_entry",
        vault_id: vaultId,
        entry_id: entryId
      },
      false
    );
    return { ...result, value: undefined };
  }

  async getDatabaseSettings(vaultId: string): Promise<DatabaseSettings> {
    return this.sendCommand<DatabaseSettings>({
      type: "get_database_settings",
      vault_id: vaultId
    });
  }

  async updateDatabaseSettings(
    vaultId: string,
    update: DatabaseSettingsUpdate
  ): Promise<DatabaseSettingsCommitResult> {
    return this.sendDatabaseSettingsMutationCommand({
      type: "update_database_settings",
      vault_id: vaultId,
      update
    });
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
    input: EntryAttachmentInput
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
      true
    );
  }

  async updateEntryAttachmentMetadata(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentMetadataUpdate
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
      true
    );
  }

  async replaceEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentContentUpdate
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "replace_entry_attachment_content",
        vault_id: vaultId,
        entry_id: entryId,
        name: input.name,
        data_base64: input.dataBase64
      },
      true
    );
  }

  async deleteEntryAttachment(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<CommittedMutation<EntryDetail>> {
    return this.sendEntryMutationCommand<EntryDetail>(
      {
        type: "delete_entry_attachment",
        vault_id: vaultId,
        entry_id: entryId,
        name
      },
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
    historyIndex: number
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "restore_entry_history",
      vault_id: vaultId,
      entry_id: entryId,
      history_index: historyIndex
    });
  }

  async clearEntryHistory(
    vaultId: string,
    entryId: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "clear_entry_history",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async recycleEntry(
    vaultId: string,
    entryId: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "recycle_entry",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async restoreRecycledEntry(
    vaultId: string,
    entryId: string,
    targetGroupId?: string
  ): Promise<CommittedVaultMutation> {
    return this.sendVaultMutationCommand({
      type: "restore_recycled_entry",
      vault_id: vaultId,
      entry_id: entryId,
      target_group_id: targetGroupId
    });
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

  private async sendEntryMutationCommand<T>(
    command: Record<string, unknown>,
    requiresEntry: boolean
  ): Promise<CommittedMutation<T>> {
    const response =
      await this.sendCommand<EntryMutationResponse<T>>(command);
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
      publication: publicationResult(response.publication)
    };
  }

  private async sendAutofillEntryMutationCommand(
    command: Record<string, unknown>
  ): Promise<CommittedAutofillMutation> {
    const response =
      await this.sendCommand<EntryMutationResponse<never>>(command);
    if (
      response.type !== "entry_mutation_result" ||
      response.commit !== "committed"
    ) {
      throw new TypeError("runtime returned an invalid committed autofill mutation");
    }
    return {
      commit: response.commit,
      publication: publicationResult(response.publication)
    };
  }

  private async sendVaultMutationCommand(
    command: Record<string, unknown>
  ): Promise<CommittedVaultMutation> {
    const response = await this.sendCommand<VaultMutationResponse>(command);
    if (
      response.type !== "vault_mutation_result" ||
      response.commit !== "committed"
    ) {
      throw new TypeError("runtime returned an invalid committed vault mutation");
    }
    return {
      publication: publicationResult(response.publication),
      ...(response.createdGroupId === undefined
        ? {}
        : { createdGroupId: response.createdGroupId })
    };
  }

  private async sendDatabaseSettingsMutationCommand(
    command: Record<string, unknown>
  ): Promise<DatabaseSettingsCommitResult> {
    const response =
      await this.sendCommand<DatabaseSettingsMutationResponse>(command);
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
      publication: publicationResult(response.publication)
    };
  }

  private async sendCommand<T>(command: Record<string, unknown>): Promise<T> {
    const response = await this.transport.send({
      version: RUNTIME_PROTOCOL_VERSION,
      command
    });

    if (isRuntimeErrorResponse(response)) {
      throw new RuntimeResponseError(response.code, response.message);
    }

    return response as T;
  }
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

function publicationResult(
  result: Omit<PublicationResult, "type">
): PublicationResult {
  return {
    type: "publication_result",
    ...result
  };
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
