use serde::{Deserialize, Serialize};

pub mod contracts;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolEnvelope {
    pub version: u32,
    #[serde(default, rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub command: RuntimeCommand,
}

impl ProtocolEnvelope {
    pub fn new(command: RuntimeCommand) -> Self {
        Self {
            version: 1,
            request_id: None,
            command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeCommand {
    GetSessionState,
    ListRecentVaults,
    PreloadCurrentVault,
    AddLocalVaultReference {
        path: Option<String>,
    },
    BeginOneDriveLogin,
    CompleteOneDriveLogin {
        code: String,
        redirect_uri: String,
        code_verifier: String,
    },
    CompletePendingOneDriveLogin,
    ListOneDriveChildren {
        parent_item_id: Option<String>,
    },
    AddOneDriveVaultReference {
        drive_id: String,
        item_id: String,
    },
    SetCurrentVault {
        vault_ref_id: String,
    },
    RetryVaultSourceSync {
        vault_id: String,
    },
    DeleteVaultReference {
        vault_ref_id: String,
    },
    UnlockCurrentVaultWithPassword {
        password: String,
    },
    UnlockCurrentVault {
        password: Option<String>,
        key_file_path: Option<String>,
    },
    EnableQuickUnlockForCurrentVault,
    UnlockCurrentVaultWithQuickUnlock,
    DisableQuickUnlockForCurrentVault,
    OpenLocalVault {
        path: String,
    },
    LockSession,
    UnlockWithPassword {
        vault_id: String,
        password: String,
    },
    UnlockVault {
        vault_id: String,
        password: Option<String>,
        key_file_path: Option<String>,
    },
    ListGroups {
        vault_id: String,
    },
    ListEntries {
        vault_id: String,
    },
    GetEntryDetail {
        vault_id: String,
        entry_id: String,
    },
    ListEntryHistory {
        vault_id: String,
        entry_id: String,
    },
    GetEntryHistoryDetail {
        vault_id: String,
        entry_id: String,
        history_index: usize,
    },
    CreateEntry {
        vault_id: String,
        parent_group_id: String,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        totp_uri: Option<String>,
    },
    UpdateEntryFields {
        vault_id: String,
        entry_id: String,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        totp_uri: Option<String>,
        custom_fields: Vec<EntryCustomFieldDto>,
    },
    CompareAndUpdateEntryFields {
        vault_id: String,
        entry_id: String,
        expected_fields: EntryFieldsDto,
        desired_fields: EntryFieldsDto,
    },
    PersistAutofillMutation {
        transaction_id: String,
        operation_id: String,
        vault_id: String,
        plan: AutofillPersistPlanDto,
    },
    ClearEntryTotp {
        vault_id: String,
        entry_id: String,
    },
    SetEntryPasskey {
        vault_id: String,
        entry_id: String,
        passkey: EntryPasskeyDto,
    },
    ClearEntryPasskey {
        vault_id: String,
        entry_id: String,
    },
    GetPasskeyUserVerificationCapability,
    VerifyPasskeyUser {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        method: PasskeyUserVerificationMethodDto,
        password: Option<String>,
    },
    ListPasskeyCredentials {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        relying_party: String,
    },
    RegisterPasskeyCeremony {
        ceremony_token: String,
        connection_id: String,
        origin: String,
        top_origin: Option<String>,
        ancestor_origins: Vec<String>,
        relying_party: String,
        ceremony: PasskeyCeremonyKindDto,
        #[serde(default)]
        discoverable: bool,
        #[serde(default)]
        user_verification: PasskeyUserVerificationRequirementDto,
        challenge_base64url: String,
        request_id: i64,
        tab_id: i64,
        frame_id: i64,
        frame_kind: PasskeyFrameKindDto,
        registered_at_epoch_ms: u64,
        expires_at_epoch_ms: u64,
    },
    AdvancePasskeyCeremonyPhase {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        next_phase: PasskeyCeremonyPhaseDto,
        #[serde(default)]
        related_origin_verified: bool,
    },
    BindPasskeyCeremonyVault {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
    },
    QueryPasskeyCeremonyLedger {
        ceremony_token: String,
    },
    ReconcilePasskeyCeremonyLedger {
        active_connection_id: String,
    },
    MarkPasskeyCeremonyUnknownDelivery {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
    },
    CreatePasskeyAssertion {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        relying_party: String,
        origin: String,
        #[serde(default)]
        credential_id: Option<String>,
        #[serde(default)]
        discoverable: bool,
        #[serde(default)]
        user_presence_verified: bool,
        #[serde(default)]
        related_origin_verified: bool,
        client_data_json_base64url: String,
    },
    CreatePasskeyRegistration {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        relying_party: String,
        origin: String,
        user_name: String,
        user_display_name: Option<String>,
        user_handle_base64url: String,
        public_key_algorithm: i32,
        #[serde(default)]
        related_origin_verified: bool,
        client_data_json_base64url: String,
    },
    SavePasskeyRegistration {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
    },
    AbortPasskeyRegistration {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        closed_phase: PasskeyCeremonyPhaseDto,
    },
    CommitPasskeyRegistration {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        entry_id: String,
        credential_id: String,
    },
    PasskeyCredentialStatus {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        credential_id: String,
        relying_party: String,
    },
    PasskeyCredentialStatusBatch {
        ceremony_token: String,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: String,
        credential_ids: Vec<String>,
        relying_party: String,
    },
    DeleteEntry {
        vault_id: String,
        entry_id: String,
    },
    GetEntryAttachmentContent {
        vault_id: String,
        entry_id: String,
        name: String,
    },
    AddEntryAttachment {
        vault_id: String,
        entry_id: String,
        name: String,
        data_base64: String,
        protect_in_memory: bool,
    },
    UpdateEntryAttachmentMetadata {
        vault_id: String,
        entry_id: String,
        old_name: String,
        new_name: String,
        protect_in_memory: bool,
    },
    ReplaceEntryAttachmentContent {
        vault_id: String,
        entry_id: String,
        name: String,
        data_base64: String,
    },
    DeleteEntryAttachment {
        vault_id: String,
        entry_id: String,
        name: String,
    },
    UpdateEntry {
        vault_id: String,
        entry_id: String,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    },
    SaveVault {
        vault_id: String,
    },
    GetDatabaseSettings {
        vault_id: String,
    },
    UpdateDatabaseSettings {
        vault_id: String,
        update: DatabaseSettingsUpdateDto,
    },
    FindFillCandidates {
        vault_id: String,
        url: String,
    },
    FindExactMatchingEntryIds {
        vault_id: String,
        fields: EntryFieldsDto,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeResponse {
    SessionState(SessionStateDto),
    VaultReferenceList(VaultReferenceListDto),
    VaultReference(VaultReferenceDto),
    OneDriveAuthSession(OneDriveAuthSessionDto),
    OneDriveAuthStatus(OneDriveAuthStatusDto),
    OneDriveItemList(OneDriveItemListDto),
    VaultSourceStatus(VaultSourceStatusDto),
    VaultOpened(VaultHandleDto),
    GroupTree(GroupTreeDto),
    EntryList(EntryListDto),
    EntryDetail(EntryDetailDto),
    EntryHistoryList(EntryHistoryListDto),
    EntryHistoryDetail(EntryHistoryDetailDto),
    EntryAttachmentContent(EntryAttachmentContentDto),
    FillCandidates(FillCandidateListDto),
    EntryIdList(EntryIdListDto),
    PasskeyAssertion(PasskeyAssertionDto),
    PasskeyRegistration(PasskeyRegistrationDto),
    PasskeyCredentialStatus(PasskeyCredentialStatusDto),
    PasskeyCredentialStatusBatch(PasskeyCredentialStatusBatchDto),
    PasskeyCredentialList(PasskeyCredentialListDto),
    PasskeyUserVerificationCapability(PasskeyUserVerificationCapabilityDto),
    PasskeyUserVerified(PasskeyUserVerifiedDto),
    PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto),
    PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto),
    PasskeyCeremonyVaultBound(PasskeyCeremonyVaultBoundDto),
    PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto),
    PasskeyCeremonyReconciliation(PasskeyCeremonyReconciliationDto),
    DatabaseSettings(DatabaseSettingsDto),
    Saved,
    SaveVaultResult(SaveVaultResultDto),
    AutofillPersistResult(AutofillPersistResultDto),
    Error(ErrorDto),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStateDto {
    pub unlocked: bool,
    pub active_vault_id: Option<String>,
    pub current_vault_ref_id: Option<String>,
    pub supports_biometric_unlock: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_status: Option<VaultSourceStatusDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSourceStatusDto {
    pub source_kind: String,
    pub remote_state: String,
    pub last_sync_at: Option<i64>,
    pub cached_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultReferenceDto {
    pub vault_ref_id: String,
    pub display_name: String,
    pub source_kind: String,
    pub source_summary: String,
    pub last_used_at: i64,
    pub availability: String,
    pub supports_quick_unlock: bool,
    pub is_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultReferenceListDto {
    pub vaults: Vec<VaultReferenceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneDriveAuthSessionDto {
    pub auth_url: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub expires_in_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneDriveAuthStatusDto {
    pub status: String,
    pub account_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneDriveItemDto {
    pub drive_id: String,
    pub item_id: String,
    pub name: String,
    pub folder: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneDriveItemListDto {
    pub items: Vec<OneDriveItemDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHandleDto {
    pub vault_id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseSettingsDto {
    pub metadata: DatabaseMetadataSettingsDto,
    pub public_metadata: DatabasePublicMetadataSettingsDto,
    pub history: DatabaseHistorySettingsDto,
    pub recycle_bin: DatabaseRecycleBinSettingsDto,
    pub encryption: DatabaseEncryptionSettingsDto,
    pub autosave_delay_seconds: Option<u32>,
    pub has_password: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseSettingsUpdateDto {
    #[serde(default)]
    pub metadata: Option<DatabaseMetadataSettingsDto>,
    #[serde(default)]
    pub public_metadata: Option<DatabasePublicMetadataSettingsDto>,
    #[serde(default)]
    pub history: Option<DatabaseHistorySettingsDto>,
    #[serde(default)]
    pub recycle_bin: Option<DatabaseRecycleBinSettingsDto>,
    #[serde(default)]
    pub encryption: Option<DatabaseEncryptionSettingsDto>,
    #[serde(default)]
    pub credentials: Option<DatabaseCredentialsUpdateDto>,
    #[serde(default)]
    pub autosave_delay_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseMetadataSettingsDto {
    pub name: String,
    pub description: Option<String>,
    pub default_username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabasePublicMetadataSettingsDto {
    pub display_name: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseHistorySettingsDto {
    pub max_items_per_entry: Option<i32>,
    pub max_total_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseRecycleBinSettingsDto {
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseEncryptionSettingsDto {
    pub compression: String,
    pub cipher: String,
    pub kdf: DatabaseKdfSettingsDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseKdfSettingsDto {
    pub algorithm: String,
    pub transform_rounds: Option<u64>,
    pub iterations: Option<u32>,
    pub memory_kib: Option<u32>,
    pub parallelism: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCredentialsUpdateDto {
    pub new_password: Option<String>,
    pub remove_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummaryDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group_id: String,
    pub has_totp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupNodeDto {
    pub id: String,
    pub title: String,
    pub entry_count: usize,
    pub child_count: usize,
    pub children: Vec<GroupNodeDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupTreeDto {
    pub root: GroupNodeDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryListDto {
    pub entries: Vec<EntrySummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryIdListDto {
    pub entry_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetailDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub modified_at: u64,
    pub totp: Option<String>,
    pub totp_uri: Option<String>,
    pub passkey: Option<EntryPasskeyDto>,
    pub field_protection: EntryFieldProtectionDto,
    pub custom_fields: Vec<EntryCustomFieldDto>,
    pub attachments: Vec<EntryAttachmentDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryFieldsDto {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<EntryCustomFieldDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AutofillPersistPlanDto {
    Update {
        entry_id: String,
        expected_fields: EntryFieldsDto,
        desired_fields: EntryFieldsDto,
    },
    Create {
        parent_group_id: String,
        planned_entry_id: String,
        expected_matching_entry_ids: Vec<String>,
        desired_fields: EntryFieldsDto,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct EntryPasskeyDto {
    pub username: String,
    pub credential_id: String,
    pub generated_user_id: Option<String>,
    pub private_key_pem: String,
    pub relying_party: String,
    pub user_handle: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertionDto {
    pub credential_id: String,
    pub authenticator_data_base64url: String,
    pub client_data_json_base64url: String,
    pub signature_base64url: String,
    pub user_handle_base64url: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationDto {
    pub entry_id: String,
    pub credential_id: String,
    pub created: bool,
    pub authenticator_data_base64url: String,
    pub attestation_object_base64url: String,
    pub client_data_json_base64url: String,
    pub public_key_base64url: String,
    pub public_key_algorithm: i32,
    pub user_handle_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCredentialStatusDto {
    pub credential_id: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCredentialStatusBatchDto {
    pub statuses: Vec<PasskeyCredentialStatusDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCredentialListDto {
    pub credentials: Vec<PasskeyCredentialCandidateDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCredentialCandidateDto {
    pub credential_id: String,
    pub username: String,
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUserVerificationMethodDto {
    MasterPassword,
    QuickUnlock,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUserVerificationRequirementDto {
    Discouraged,
    #[default]
    Preferred,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUserVerificationCapabilityDto {
    pub available: bool,
    pub methods: Vec<PasskeyUserVerificationMethodDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUserVerifiedDto {
    pub verified: bool,
    pub method: PasskeyUserVerificationMethodDto,
    pub verified_at_epoch_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyCeremonyKindDto {
    Get,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyFrameKindDto {
    Top,
    Subframe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasskeyCeremonyPhaseDto {
    #[serde(rename = "s0_pre_authorization")]
    PreAuthorization,
    #[serde(rename = "s1_user_authorization")]
    UserAuthorization,
    #[serde(rename = "s2_network_validation")]
    NetworkValidation,
    #[serde(rename = "s3_credential_resolution")]
    CredentialResolution,
    #[serde(rename = "s3b_user_selection")]
    UserSelection,
    #[serde(rename = "s4_completion_and_mutation")]
    CompletionAndMutation,
    #[serde(rename = "closed_aborted")]
    ClosedAborted,
    #[serde(rename = "closed_delivered")]
    ClosedDelivered,
    #[serde(rename = "closed_failed")]
    ClosedFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyCeremonyDurableStateDto {
    None,
    Snapshot,
    Mutated,
    Saved,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyCeremonyDeliveryStateDto {
    NotDelivered,
    Delivered,
    UnknownDelivery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyRegisteredDto {
    pub registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyAdvancedDto {
    pub advanced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyVaultBoundDto {
    pub bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyLedgerDto {
    pub known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<PasskeyCeremonyPhaseDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable_state: Option<PasskeyCeremonyDurableStateDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_state: Option<PasskeyCeremonyDeliveryStateDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyReconciledDto {
    pub ceremony_token: String,
    pub delivery_state: PasskeyCeremonyDeliveryStateDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCeremonyReconciliationDto {
    pub reconciled: Vec<PasskeyCeremonyReconciledDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveVaultStatusDto {
    Saved,
    Merged,
    SavedToCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeSummaryDto {
    pub merged_entries: usize,
    pub history_snapshots_added: usize,
    /// 001 merge algebra: resolved Meta / recycle-bin config conflicts.
    /// Additive extension pinned by the Phase 0 contract freeze (004).
    #[serde(default)]
    pub meta_conflicts_resolved: u32,
    /// 001 merge algebra: custom icon conflicts where the losing version was
    /// discarded (counted so the user can see a configuration conflict
    /// occurred). Additive extension pinned by the Phase 0 contract freeze.
    #[serde(default)]
    pub icon_conflicts_resolved: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveVaultResultDto {
    pub status: SaveVaultStatusDto,
    pub merge_summary: Option<MergeSummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillPersistResultDto {
    pub transaction_id: String,
    pub operation_id: String,
    pub vault_id: String,
    #[serde(flatten)]
    pub outcome: AutofillPersistOutcomeDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AutofillPersistOutcomeDto {
    Durable {
        disposition: AutofillPersistDispositionDto,
        entry_id: String,
        durability: AutofillPersistDurabilityDto,
        cache_state: AutofillCacheStateDto,
        committed_fingerprint: AutofillCommittedFingerprintDto,
        merge_summary: Option<MergeSummaryDto>,
        receipt_version: u32,
    },
    Conflict {
        code: AutofillPersistConflictCodeDto,
        retryable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillCommittedFingerprintDto {
    pub content_sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofillPersistDispositionDto {
    Committed,
    Replayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofillPersistDurabilityDto {
    Source,
    PendingRemoteCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofillCacheStateDto {
    NotApplicable,
    Current,
    PendingSync,
    WriteFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutofillPersistConflictCodeDto {
    ActiveVaultMismatch,
    UpdatePreconditionFailed,
    CreateMatchingSetChanged,
    PlannedEntryIdCollision,
    OperationBindingMismatch,
    ConcurrentVaultChanges,
    SourceChangedRetryExhausted,
    LegacyCreateOutcomeAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryHistoryItemDto {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub modified_at: u64,
    pub attachment_count: usize,
    pub custom_field_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryHistoryListDto {
    pub items: Vec<EntryHistoryItemDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryHistoryDetailDto {
    pub entry_id: String,
    pub history_index: usize,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub modified_at: u64,
    pub custom_fields: Vec<EntryCustomFieldDto>,
    pub attachments: Vec<EntryAttachmentDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryFieldProtectionDto {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryCustomFieldDto {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryAttachmentDto {
    pub name: String,
    pub size: usize,
    pub protect_in_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryAttachmentContentDto {
    pub name: String,
    pub data_base64: String,
    pub protect_in_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FillCandidateListDto {
    pub entries: Vec<EntrySummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDto {
    pub code: String,
    pub message: String,
}
