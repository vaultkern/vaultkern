import type { RuntimeTransport } from "./transport";

export interface SessionState {
  type: "session_state";
  unlocked: boolean;
  activeVaultId: string | null;
  currentVaultRefId: string | null;
  supportsBiometricUnlock: boolean;
  sourceStatus?: VaultSourceStatus | null;
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

export interface DatabaseSettingsUpdate {
  metadata?: DatabaseMetadataSettings;
  publicMetadata?: DatabasePublicMetadataSettings;
  history?: DatabaseHistorySettings;
  recycleBin?: DatabaseRecycleBinSettings;
  encryption?: DatabaseEncryptionSettings;
  credentials?: DatabaseCredentialsUpdate;
  autosaveDelaySeconds?: number;
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
  privateKeyPem: string;
  relyingParty: string;
  userHandle: string | null;
  backupEligible: boolean;
  backupState: boolean;
}

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
  status: "saved" | "merged" | "saved_to_cache";
  mergeSummary?: {
    mergedEntries: number;
    historySnapshotsAdded: number;
  } | null;
};

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
  password: string;
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
      expectedFields: EntryDraft;
      desiredFields: EntryDraft;
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
  codeVerifier: string;
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

export interface CompleteOneDriveLoginInput {
  code: string;
  redirectUri: string;
  codeVerifier: string;
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

  async completeOneDriveLogin(
    input: CompleteOneDriveLoginInput
  ): Promise<OneDriveAuthStatus> {
    return this.sendCommand<OneDriveAuthStatus>({
      type: "complete_one_drive_login",
      code: input.code,
      redirect_uri: input.redirectUri,
      code_verifier: input.codeVerifier
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

  async enableQuickUnlockForCurrentVault(): Promise<SessionState> {
    return this.sendCommand<SessionState>({
      type: "enable_quick_unlock_for_current_vault"
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

  async createEntry(
    vaultId: string,
    input: EntryCreateInput
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "create_entry",
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

  async updateEntryFields(
    vaultId: string,
    entryId: string,
    input: EntryDraft
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
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
    });
  }

  async compareAndUpdateEntryFields(
    vaultId: string,
    entryId: string,
    expectedFields: EntryDraft,
    desiredFields: EntryDraft
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
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
    entryId: string
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "clear_entry_totp",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async setEntryPasskey(
    vaultId: string,
    entryId: string,
    passkey: EntryPasskey
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "set_entry_passkey",
      vault_id: vaultId,
      entry_id: entryId,
      passkey
    });
  }

  async clearEntryPasskey(
    vaultId: string,
    entryId: string
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "clear_entry_passkey",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async deleteEntry(vaultId: string, entryId: string): Promise<void> {
    await this.sendCommand<{ type: "saved" }>({
      type: "delete_entry",
      vault_id: vaultId,
      entry_id: entryId
    });
  }

  async saveVault(vaultId: string): Promise<SaveVaultResult> {
    return this.sendCommand<SaveVaultResult>({
      type: "save_vault",
      vault_id: vaultId
    });
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
  ): Promise<DatabaseSettings> {
    return this.sendCommand<DatabaseSettings>({
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
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "add_entry_attachment",
      vault_id: vaultId,
      entry_id: entryId,
      name: input.name,
      data_base64: input.dataBase64,
      protect_in_memory: input.protectInMemory
    });
  }

  async updateEntryAttachmentMetadata(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentMetadataUpdate
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "update_entry_attachment_metadata",
      vault_id: vaultId,
      entry_id: entryId,
      old_name: input.oldName,
      new_name: input.newName,
      protect_in_memory: input.protectInMemory
    });
  }

  async replaceEntryAttachmentContent(
    vaultId: string,
    entryId: string,
    input: EntryAttachmentContentUpdate
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "replace_entry_attachment_content",
      vault_id: vaultId,
      entry_id: entryId,
      name: input.name,
      data_base64: input.dataBase64
    });
  }

  async deleteEntryAttachment(
    vaultId: string,
    entryId: string,
    name: string
  ): Promise<EntryDetail> {
    return this.sendCommand<EntryDetail>({
      type: "delete_entry_attachment",
      vault_id: vaultId,
      entry_id: entryId,
      name
    });
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

  private async sendCommand<T>(command: Record<string, unknown>): Promise<T> {
    const response = await this.transport.send({
      version: 1,
      command
    });

    if (isRuntimeErrorResponse(response)) {
      throw new RuntimeResponseError(response.code, response.message);
    }

    return response as T;
  }
}

export type { RuntimeTransport };

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
        expected_fields: entryFieldsCommand(plan.expectedFields),
        desired_fields: entryFieldsCommand(plan.desiredFields)
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
