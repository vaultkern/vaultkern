use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::form_urlencoded::byte_serialize;
use uuid::Uuid;
use vaultkern_core::{
    AttachmentContentUpdate, AttachmentMetadataUpdate, Entry, EntryAttachmentInput, EntryCreate,
    EntryCustomDataInput, EntryCustomFieldInput, EntryTimesUpdate, EntryUpdate,
    ExternalKdfConfirmation, ExternalKdfPolicy, GroupMetadataUpdate, KeepassCore, PasskeyRecord,
    ThreeWayPatchRecoverySnapshot, ThreeWayPatchReport, TotpSpec, Vault,
    VaultBinTemplateMetadataUpdate, VaultCodec, VaultIdentityMetadataUpdate,
    VaultLifecycleMetadataUpdate, VaultMetadataUpdate, enforce_history_limits,
    parse_key_file_bytes, strip_retired_runtime_metadata, three_way_field_patch,
};
#[cfg(test)]
use vaultkern_runtime_protocol::RuntimeCommand;
use vaultkern_runtime_protocol::{
    AutofillCreateContextDto, AutofillCredentialDto, AutofillEntryFieldsDto,
    AutofillUpdateFieldsDto, CommitStatusDto, DatabaseEncryptionSettingsDto,
    DatabaseHistorySettingsDto, DatabaseKdfSettingsDto, DatabaseMetadataSettingsDto,
    DatabasePublicMetadataSettingsDto, DatabaseRecycleBinSettingsDto,
    DatabaseSettingsCommitResultDto, DatabaseSettingsDto, DatabaseSettingsUpdateDto,
    EntryAttachmentContentDto, EntryAttachmentDto, EntryCustomFieldDto, EntryDetailDto,
    EntryFieldProtectionDto, EntryFieldsDto, EntryHistoryDetailDto, EntryHistoryItemDto,
    EntryHistoryListDto, EntryListDto, EntryMutationResultDto, EntryPasskeyDto,
    EntryPasskeyUpdateDto, EntrySummaryDto, ErrorDto, FillCandidateListDto, GroupNodeDto,
    GroupTreeDto, OptionalSettingUpdateDto, PasskeyAssertionDto, PasskeyCeremonyAdvancedDto,
    PasskeyCeremonyDeliveryStateDto, PasskeyCeremonyDurableStateDto, PasskeyCeremonyKindDto,
    PasskeyCeremonyLedgerDto, PasskeyCeremonyPhaseDto, PasskeyCeremonyReconciledDto,
    PasskeyCeremonyReconciliationDto, PasskeyCeremonyRegisteredDto, PasskeyCeremonyVaultBoundDto,
    PasskeyCredentialCandidateDto, PasskeyCredentialListDto, PasskeyCredentialStatusBatchDto,
    PasskeyCredentialStatusDto, PasskeyFrameKindDto, PasskeyRegistrationDto,
    PasskeyUserVerificationCapabilityDto, PasskeyUserVerificationMethodDto,
    PasskeyUserVerificationRequirementDto, PasskeyUserVerifiedDto, PublicationResultDto,
    PublicationStatusDto, ReconciliationSummaryDto, RuntimeResponse, SensitiveString,
    VaultHandleDto, VaultMutationResultDto, VaultReferenceDto, VaultReferenceListDto,
    VaultSourceStatusDto,
};
use zeroize::{Zeroize, Zeroizing};

use crate::command_loop::format_error_chain;
use crate::match_fill::{FillMatchScore, score_origin_scoped_entry_match};
use crate::passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, PlatformPasskeyAssertionInput,
    PlatformPasskeyAssertionOutput, PlatformPasskeyAssertionRequest, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
    PlatformPasskeyRegistrationRequest, create_assertion, create_platform_assertion,
    create_platform_registration_with_credential_id, create_registration_with_credential_id,
    generate_passkey_credential_id, validate_passkey_registration_parameters,
};
use crate::providers::biometric::{
    BiometricProvider, TestBiometricProvider, UnsupportedBiometricProvider,
    default_biometric_provider,
};
use crate::providers::catalog::{
    ConditionalPublication, LocalPublicationError, ProviderAccessCounts, ProviderCatalog,
    RemoteObservation, RemoteSnapshot,
};
use crate::providers::durable_file::create_dir_all_durable;
use crate::providers::onedrive_token_store::OneDriveRefreshTokenStore;
use crate::providers::provider::{
    ContentIdentity, Provider, ProviderCommit, ProviderConflictCopy, ProviderError,
    ProviderRevision,
};
use crate::providers::remote_cache::{
    GenericPendingKind, PendingRemoteCacheCompletion, RemoteCacheKey, RemoteVaultCache,
    RemoteVaultCacheEntry,
};
use crate::providers::secure_storage::{
    FailingContainsSecureStorageProvider, FailingDeleteSecureStorageProvider,
    MemorySecureStorageProvider, SecureStorageProvider, UnsupportedSecureStorageProvider,
    default_secure_storage_provider, is_secure_storage_cancelled,
    purge_legacy_extension_quick_unlock_storage,
};
use crate::session::{
    LoadedVault, VaultSession, VaultSource, onedrive_remote_id, onedrive_vault_id,
};
use crate::state_paths::extension_id_from_browser_origin;
use crate::sync::{SessionBaseStore, SyncedBaseStore};
use crate::unlock::{
    MasterCredential, MasterCredentialShape, UnlockAttempt, enroll_unlock_blob,
    unlock_from_blob_with_policy, unlock_historical_snapshot_from_blob_with_policy,
};
use crate::vault_format::{
    ResidentVaultCodec, VAULT_WRITER_ID, VaultCipher, VaultCodecError, VaultCompression,
    VaultEncodingProfile, VaultEncryptionSettings, VaultKdf, VaultKdfAlgorithm, VaultKdfDecision,
    VaultKey, external_kdf_policy_details,
};
use crate::vault_reference_store::{PendingVaultCleanup, StoredVaultSource, VaultReferenceStore};

const PLATFORM_PASSKEY_RP_NAME_KEY: &str = "VaultKern.PlatformPasskey.RelyingPartyName";
const PLATFORM_PASSKEY_USER_DISPLAY_NAME_KEY: &str = "VaultKern.PlatformPasskey.UserDisplayName";
const AUTOSAVE_DELAY_SECONDS_KEY: &str = "VaultKern.AutosaveDelaySeconds";

fn requires_xml_protection(value: &str) -> bool {
    value.chars().any(|character| {
        !matches!(
            character,
            '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
        )
    })
}

fn effective_xml_field_protection(value: &str, protected: bool) -> bool {
    protected || requires_xml_protection(value)
}

fn totp_specs_semantically_equal(
    _left_title: &str,
    _left_username: &str,
    left: Option<&TotpSpec>,
    _right_title: &str,
    _right_username: &str,
    right: Option<&TotpSpec>,
) -> bool {
    left == right
}

fn canonical_custom_fields(fields: &[EntryCustomFieldDto]) -> Option<BTreeMap<&str, (&str, bool)>> {
    let canonical = fields
        .iter()
        .map(|field| {
            (
                field.key.as_str(),
                (
                    field.value.as_str(),
                    effective_xml_field_protection(&field.value, field.protected),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    (canonical.len() == fields.len()).then_some(canonical)
}

fn custom_fields_semantically_equal(
    left: &[EntryCustomFieldDto],
    right: &[EntryCustomFieldDto],
) -> bool {
    if left.len() != right.len() {
        return false;
    }

    match (
        canonical_custom_fields(left),
        canonical_custom_fields(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn totp_fields_semantically_equal(
    left_title: &str,
    left_username: &str,
    left_uri: Option<&str>,
    right_title: &str,
    right_username: &str,
    right_uri: Option<&str>,
) -> bool {
    match (left_uri, right_uri) {
        (None, None) => true,
        (Some(left_uri), Some(right_uri)) => match (
            TotpSpec::parse_otpauth(left_uri),
            TotpSpec::parse_otpauth(right_uri),
        ) {
            (Ok(left_totp), Ok(right_totp)) => totp_specs_semantically_equal(
                left_title,
                left_username,
                Some(&left_totp),
                right_title,
                right_username,
                Some(&right_totp),
            ),
            _ => false,
        },
        _ => false,
    }
}

fn entry_detail_matches_fields(detail: &EntryDetailDto, fields: &EntryFieldsDto) -> bool {
    detail.title == fields.title
        && detail.username == fields.username
        && detail.password == fields.password
        && detail.url == fields.url
        && detail.notes == fields.notes
        && totp_fields_semantically_equal(
            &detail.title,
            &detail.username,
            detail.totp_uri.as_deref(),
            &fields.title,
            &fields.username,
            fields.totp_uri.as_deref(),
        )
        && custom_fields_semantically_equal(&detail.custom_fields, &fields.custom_fields)
}

struct LoadedSourceSnapshot {
    bytes: Option<Vec<u8>>,
    fingerprint: ContentIdentity,
    provider_revision: Option<ProviderRevision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingGenericCasConflict;

impl std::fmt::Display for PendingGenericCasConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OneDrive changed during pending synchronization")
    }
}

impl std::error::Error for PendingGenericCasConflict {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasskeyCeremonyIdentity {
    pub(crate) connection_id: String,
    pub(crate) origin: String,
    pub(crate) top_origin: Option<String>,
    pub(crate) ancestor_origins: Vec<String>,
    pub(crate) relying_party: String,
    pub(crate) ceremony: PasskeyCeremonyKindDto,
    pub(crate) discoverable: bool,
    pub(crate) user_verification: PasskeyUserVerificationRequirementDto,
    pub(crate) challenge_base64url: String,
    pub(crate) request_id: i64,
    pub(crate) tab_id: i64,
    pub(crate) frame_id: i64,
    pub(crate) frame_kind: PasskeyFrameKindDto,
    pub(crate) registered_at_epoch_ms: u64,
    pub(crate) expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasskeyCeremonyLedgerEntry {
    identity: PasskeyCeremonyIdentity,
    phase: PasskeyCeremonyPhaseDto,
    vault_id: Option<String>,
    durable_state: PasskeyCeremonyDurableStateDto,
    delivery_state: PasskeyCeremonyDeliveryStateDto,
    user_verification: Option<PasskeyUserVerificationProof>,
    registration_rollback: Option<PasskeyRegistrationRollbackState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasskeyClientDataExpectations {
    challenge_base64url: String,
    top_origin: Option<String>,
    ancestor_origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasskeyUserVerificationProof {
    vault_id: String,
    method: PasskeyUserVerificationMethodDto,
    verified_at_epoch_ms: u64,
}

fn passkey_user_verification_is_valid(
    entry: &PasskeyCeremonyLedgerEntry,
    vault_id: &str,
    now_epoch_ms: u64,
) -> bool {
    entry.user_verification.as_ref().is_some_and(|proof| {
        proof.vault_id == vault_id
            && proof.verified_at_epoch_ms >= entry.identity.registered_at_epoch_ms
            && proof.verified_at_epoch_ms <= now_epoch_ms
            && proof.verified_at_epoch_ms <= entry.identity.expires_at_epoch_ms
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasskeyRegistrationRollbackState {
    vault_id: String,
    entry_id: String,
    credential_id: Option<String>,
    created: bool,
    rollback_entry: Option<Entry>,
}

struct SessionLoadedDatabase {
    vault: Vault,
}

enum SourceRefreshConflictDisposition {
    UploadedConflictCopy { warning: String },
    Pending { status: VaultSourceStatusDto },
}

#[derive(Clone)]
struct OneDriveConflictHead {
    vault: Option<Vault>,
    bytes: Vec<u8>,
    fingerprint: ContentIdentity,
    revision: ProviderRevision,
    cache_validation_token: Option<String>,
    display_name: String,
    account_label: String,
    save_profile: VaultEncodingProfile,
    key: Option<Arc<VaultKey>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictSplitInterruptionPoint {
    AfterReceiptIntent,
    AfterConflictCopy,
}

#[derive(Debug)]
struct ConflictSplitInterrupted {
    point: ConflictSplitInterruptionPoint,
}

impl std::fmt::Display for ConflictSplitInterrupted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "injected Conflict Split interruption at {:?}",
            self.point
        )
    }
}

impl std::error::Error for ConflictSplitInterrupted {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentKdfPolicy {
    Desktop,
    Mobile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuickUnlockOutcome {
    Unlocked,
    NotEnrolled,
    Cancelled,
    OpenAppRequired,
    CredentialRequired,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfDisposition {
    ConfirmationRequired,
    Refused,
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalKdfFailure {
    pub algorithm: &'static str,
    pub resource: &'static str,
    pub observed: u64,
    pub limit: Option<u64>,
    pub disposition: ExternalKdfDisposition,
}

pub fn classify_external_kdf_error(error: &anyhow::Error) -> Option<ExternalKdfFailure> {
    let (algorithm, observed, decision) = error.chain().find_map(external_kdf_policy_details)?;
    let (algorithm, resource) = match algorithm {
        VaultKdfAlgorithm::AesLegacy => ("aes_kdbx3", "rounds"),
        VaultKdfAlgorithm::Aes => ("aes_kdbx4", "rounds"),
        VaultKdfAlgorithm::Argon2d => ("argon2d", "memory_bytes"),
        VaultKdfAlgorithm::Argon2id => ("argon2id", "memory_bytes"),
    };
    let (limit, disposition) = match decision {
        VaultKdfDecision::Confirm(limit) => {
            (Some(limit), ExternalKdfDisposition::ConfirmationRequired)
        }
        VaultKdfDecision::Refuse(limit) => (Some(limit), ExternalKdfDisposition::Refused),
        VaultKdfDecision::Forbid => (None, ExternalKdfDisposition::Forbidden),
        VaultKdfDecision::Allow => return None,
    };
    Some(ExternalKdfFailure {
        algorithm,
        resource,
        observed,
        limit,
        disposition,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentRuntimeConfig {
    pub state_directory: PathBuf,
    pub temporary_directory: PathBuf,
    pub kdf_policy: ResidentKdfPolicy,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeRole {
    allow_unlock_kdf: bool,
    resident_kdf_policy: ResidentKdfPolicy,
}

impl RuntimeRole {
    const DESKTOP_RESIDENT: Self = Self {
        allow_unlock_kdf: true,
        resident_kdf_policy: ResidentKdfPolicy::Desktop,
    };

    const EXTENSION: Self = Self {
        allow_unlock_kdf: false,
        resident_kdf_policy: ResidentKdfPolicy::Desktop,
    };

    const fn resident(kdf_policy: ResidentKdfPolicy) -> Self {
        Self {
            allow_unlock_kdf: true,
            resident_kdf_policy: kdf_policy,
        }
    }
}

impl ResidentRuntimeConfig {
    fn validate(&self) -> Result<()> {
        if !self.state_directory.is_absolute() {
            anyhow::bail!("resident runtime state directory must be absolute");
        }
        if !self.temporary_directory.is_absolute() {
            anyhow::bail!("resident runtime temporary directory must be absolute");
        }
        create_dir_all_durable(&self.state_directory).with_context(|| {
            format!(
                "failed to prepare resident runtime state directory: {}",
                self.state_directory.display()
            )
        })?;
        Ok(())
    }
}

pub struct VaultCore {
    core: KeepassCore,
    vault_session: VaultSession,
    references: VaultReferenceStore,
    providers: ProviderCatalog,
    remote_cache: RemoteVaultCache,
    synced_bases: SyncedBaseStore,
    session_bases: SessionBaseStore,
    biometric: Box<dyn BiometricProvider>,
    secure_storage: Box<dyn SecureStorageProvider>,
    quick_unlock_policy_enabled: Arc<AtomicBool>,
    parent_window_handle: Option<usize>,
    allow_unlock_kdf: bool,
    resident_kdf_policy: ResidentKdfPolicy,
    pending_quick_unlock_enrollment: Option<PendingQuickUnlockEnrollment>,
    session_generation: u64,
    platform_passkey_operations: BTreeMap<Vec<u8>, PlatformPasskeyOperationLease>,
    pending_platform_relock: Option<(String, u64)>,
    passkey_ceremonies: BTreeMap<String, PasskeyCeremonyLedgerEntry>,
    passkey_credential_id_generator: Box<dyn FnMut() -> String + Send>,
    fixed_unix_time: Option<u64>,
    fixed_unix_time_ms: Option<u64>,
    conflict_split_interruption: Option<ConflictSplitInterruptionPoint>,
    #[cfg(test)]
    local_save_warnings: Vec<String>,
}

struct PendingQuickUnlockEnrollment {
    credentials: QuickUnlockReconciliationCredentials,
}

pub struct QuickUnlockReconciliationCredentials {
    vault_ref_id: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    key_file_path: Option<Zeroizing<String>>,
}

impl QuickUnlockReconciliationCredentials {
    pub fn from_protocol_input(
        password: Option<SensitiveString>,
        key_file_path: Option<String>,
    ) -> Self {
        Self {
            vault_ref_id: None,
            password: password.map(SensitiveString::into_zeroizing),
            key_file_path: key_file_path.map(Zeroizing::new),
        }
    }

    pub fn bound_to_vault_ref(mut self, vault_ref_id: &str) -> Self {
        self.vault_ref_id = Some(Zeroizing::new(vault_ref_id.to_owned()));
        self
    }

    fn vault_ref_id(&self) -> Option<&str> {
        self.vault_ref_id.as_deref().map(String::as_str)
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref().map(String::as_str)
    }

    fn key_file_path(&self) -> Option<&str> {
        self.key_file_path.as_deref().map(String::as_str)
    }
}

impl std::fmt::Debug for QuickUnlockReconciliationCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QuickUnlockReconciliationCredentials([REDACTED])")
    }
}

impl Zeroize for QuickUnlockReconciliationCredentials {
    fn zeroize(&mut self) {
        self.vault_ref_id.zeroize();
        self.password.zeroize();
        self.key_file_path.zeroize();
    }
}

impl Drop for QuickUnlockReconciliationCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for QuickUnlockReconciliationCredentials {}

struct PlatformPasskeyOperationLease {
    vault_id: String,
    session_generation: u64,
    user_verification_consumed: bool,
    pending_registration: Option<PasskeyRegistrationRollbackState>,
}

impl VaultCore {
    fn external_open_kdf_policy(&self) -> (ExternalKdfPolicy, ExternalKdfConfirmation) {
        let policy = if !self.allow_unlock_kdf {
            ExternalKdfPolicy::Extension
        } else {
            match self.resident_kdf_policy {
                ResidentKdfPolicy::Desktop => ExternalKdfPolicy::Desktop,
                ResidentKdfPolicy::Mobile => ExternalKdfPolicy::Mobile,
            }
        };
        (policy, ExternalKdfConfirmation::Unconfirmed)
    }

    fn load_session_database(
        bytes: &[u8],
        key: &VaultKey,
    ) -> std::result::Result<SessionLoadedDatabase, VaultCodecError> {
        ResidentVaultCodec
            .decode(bytes, key)
            .map(|vault| SessionLoadedDatabase { vault })
    }

    fn inspected_save_profile(&self, bytes: &[u8]) -> Result<VaultEncodingProfile> {
        VaultEncodingProfile::inspect(bytes).context("failed to inspect vault encoding profile")
    }

    fn merge_save_profile(
        base: &VaultEncodingProfile,
        local: &VaultEncodingProfile,
        remote: &VaultEncodingProfile,
    ) -> Result<VaultEncodingProfile> {
        VaultEncodingProfile::merge(base, local, remote).map_err(Into::into)
    }

    fn prepare_source_refresh_rebase(
        base_vault: &Vault,
        local_vault: &Vault,
        remote_vault: &Vault,
        base_save_profile: &VaultEncodingProfile,
        local_save_profile: &VaultEncodingProfile,
        remote_save_profile: &VaultEncodingProfile,
    ) -> Result<(Vault, VaultEncodingProfile)> {
        if !has_vaultkern_sync_lineage(base_vault, remote_vault) {
            anyhow::bail!("current generation has foreign or unclear writer lineage");
        }
        let merged_save_profile =
            Self::merge_save_profile(base_save_profile, local_save_profile, remote_save_profile)
                .context("cannot merge concurrent encryption profile changes")?;
        let patched = three_way_field_patch(base_vault, local_vault, remote_vault)
            .context("changes cannot be represented as a field patch")?;
        ensure_patch_conflict_history_is_recoverable(
            &patched.vault,
            &patched.required_history_snapshots,
        )
        .context("changes cannot be represented within vault history retention")?;
        Ok((patched.vault, merged_save_profile))
    }

    pub fn new() -> Self {
        Self::new_with_state(
            VaultReferenceStore::new_default(),
            ProviderCatalog::new_from_env(),
            RemoteVaultCache::new_default(),
            SyncedBaseStore::new_default(),
            SessionBaseStore::new(),
            default_secure_storage_provider(),
            RuntimeRole::DESKTOP_RESIDENT,
        )
    }

    /// Creates the resident runtime with platform-owned biometric and secure-storage adapters.
    ///
    /// The adapters stay behind the same runtime traits used by the Windows slice; this
    /// constructor only supplies them for hosts that reach the core through UniFFI.
    pub fn new_with_platform_adapters(
        config: ResidentRuntimeConfig,
        biometric: Box<dyn BiometricProvider>,
        secure_storage: Box<dyn SecureStorageProvider>,
        one_drive_refresh_tokens: Box<dyn OneDriveRefreshTokenStore>,
    ) -> Result<Self> {
        config.validate()?;
        let session_bases =
            SessionBaseStore::new_in(&config.temporary_directory).with_context(|| {
                format!(
                    "failed to create resident runtime session directory in {}",
                    config.temporary_directory.display()
                )
            })?;
        let state_directory = config.state_directory;
        let mut runtime = Self::new_with_state(
            VaultReferenceStore::new_at(state_directory.join("vault-references.json")),
            ProviderCatalog::new_with_platform_refresh_token_store(one_drive_refresh_tokens),
            RemoteVaultCache::new_at(state_directory.join("remote-cache")),
            SyncedBaseStore::new_at(state_directory.join("synced-bases")),
            session_bases,
            secure_storage,
            RuntimeRole::resident(config.kdf_policy),
        );
        runtime.biometric = biometric;
        Ok(runtime)
    }

    pub fn new_for_browser_origin(origin: &str) -> Self {
        if let Some(extension_id) = extension_id_from_browser_origin(origin) {
            if let Err(error) = purge_legacy_extension_quick_unlock_storage(extension_id) {
                write_runtime_warning(&format!(
                    "legacy extension quick-unlock storage could not be removed: {error:#}"
                ));
            }
            return Self::new_with_state(
                VaultReferenceStore::new_for_extension_id(extension_id),
                ProviderCatalog::new_for_extension_id(extension_id),
                RemoteVaultCache::new_for_extension_id(extension_id),
                SyncedBaseStore::new_for_extension_id(extension_id),
                SessionBaseStore::new(),
                default_secure_storage_provider(),
                RuntimeRole::EXTENSION,
            );
        }

        Self::new()
    }

    fn new_with_state(
        references: VaultReferenceStore,
        providers: ProviderCatalog,
        remote_cache: RemoteVaultCache,
        synced_bases: SyncedBaseStore,
        session_bases: SessionBaseStore,
        secure_storage: Box<dyn SecureStorageProvider>,
        role: RuntimeRole,
    ) -> Self {
        let mut vault_session = VaultSession::default();
        match references.current_vault_ref_id() {
            Ok(Some(vault_ref_id)) => vault_session.set_current_vault(vault_ref_id),
            Ok(None) => {}
            Err(error) => write_runtime_warning(&format!(
                "vault reference store could not be loaded at startup: {error:#}"
            )),
        }

        let mut runtime = Self {
            core: KeepassCore::new(),
            vault_session,
            references,
            providers,
            remote_cache,
            synced_bases,
            session_bases,
            biometric: default_biometric_provider(),
            secure_storage,
            quick_unlock_policy_enabled: Arc::new(AtomicBool::new(true)),
            parent_window_handle: None,
            allow_unlock_kdf: role.allow_unlock_kdf,
            resident_kdf_policy: role.resident_kdf_policy,
            pending_quick_unlock_enrollment: None,
            session_generation: 0,
            platform_passkey_operations: BTreeMap::new(),
            pending_platform_relock: None,
            passkey_ceremonies: BTreeMap::new(),
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
            fixed_unix_time_ms: None,
            conflict_split_interruption: None,
            #[cfg(test)]
            local_save_warnings: Vec::new(),
        };
        if let Err(error) = runtime.reconcile_deleted_vault_cleanups() {
            write_runtime_warning(&format!(
                "vault reference cleanup remains pending after startup: {error:#}"
            ));
        }
        runtime
    }

    pub fn for_tests() -> Self {
        Self {
            core: KeepassCore::new(),
            vault_session: VaultSession::default(),
            references: VaultReferenceStore::new_in_memory(),
            providers: ProviderCatalog::new_in_memory(),
            remote_cache: RemoteVaultCache::new_at(std::env::temp_dir().join(format!(
                "vaultkern-runtime-test-remote-cache-{}",
                uuid::Uuid::new_v4()
            ))),
            synced_bases: SyncedBaseStore::new_at(std::env::temp_dir().join(format!(
                "vaultkern-runtime-test-synced-bases-{}",
                uuid::Uuid::new_v4()
            ))),
            session_bases: SessionBaseStore::new(),
            biometric: Box::new(UnsupportedBiometricProvider),
            secure_storage: Box::new(UnsupportedSecureStorageProvider),
            quick_unlock_policy_enabled: Arc::new(AtomicBool::new(true)),
            parent_window_handle: None,
            allow_unlock_kdf: true,
            resident_kdf_policy: ResidentKdfPolicy::Desktop,
            pending_quick_unlock_enrollment: None,
            session_generation: 0,
            platform_passkey_operations: BTreeMap::new(),
            pending_platform_relock: None,
            passkey_ceremonies: BTreeMap::new(),
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
            fixed_unix_time_ms: None,
            conflict_split_interruption: None,
            #[cfg(test)]
            local_save_warnings: Vec::new(),
        }
    }

    pub fn for_tests_at(unix_time: u64) -> Self {
        let mut runtime = Self::for_tests();
        runtime.fixed_unix_time = Some(unix_time);
        runtime.fixed_unix_time_ms = Some(unix_time.saturating_mul(1000));
        runtime
    }

    pub fn set_test_unix_time(&mut self, unix_time: u64) {
        self.fixed_unix_time = Some(unix_time);
        self.fixed_unix_time_ms = Some(unix_time.saturating_mul(1000));
    }

    pub fn set_test_unix_time_ms(&mut self, unix_time_ms: u64) {
        self.fixed_unix_time = Some(unix_time_ms / 1000);
        self.fixed_unix_time_ms = Some(unix_time_ms);
    }

    pub fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
        self.parent_window_handle = parent_window.filter(|handle| *handle != 0);
        self.biometric
            .set_parent_window_handle(self.parent_window_handle);
        self.secure_storage
            .set_parent_window_handle(self.parent_window_handle);
    }

    pub fn bind_quick_unlock_policy_gate(&mut self, gate: Arc<AtomicBool>) {
        self.quick_unlock_policy_enabled = gate;
    }

    fn quick_unlock_policy_enabled(&self) -> bool {
        self.quick_unlock_policy_enabled.load(Ordering::Acquire)
    }

    fn ensure_quick_unlock_policy_enabled(&self) -> Result<()> {
        if !self.quick_unlock_policy_enabled() {
            anyhow::bail!("quick unlock is disabled in resident settings");
        }
        Ok(())
    }

    pub fn replace_parent_window_handle(&mut self, parent_window: Option<usize>) -> Option<usize> {
        let previous = self.parent_window_handle;
        self.set_parent_window_handle(parent_window);
        previous
    }

    fn advance_session_generation(&mut self) {
        self.session_generation = self.session_generation.wrapping_add(1);
        self.pending_platform_relock = None;
    }

    pub fn for_tests_with_passkey_credential_ids(credential_ids: Vec<String>) -> Self {
        let mut runtime = Self::for_tests();
        let mut credential_ids = credential_ids.into_iter();
        runtime.passkey_credential_id_generator = Box::new(move || {
            credential_ids
                .next()
                .unwrap_or_else(generate_passkey_credential_id)
        });
        runtime
    }

    pub fn for_tests_with_quick_unlock() -> Self {
        let mut runtime = Self::for_tests();
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        runtime
    }

    pub fn for_tests_with_quick_unlock_failing_contains() -> Self {
        let mut runtime = Self::for_tests();
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(FailingContainsSecureStorageProvider::new());
        runtime
    }

    pub fn for_tests_with_quick_unlock_failing_delete() -> Self {
        let mut runtime = Self::for_tests();
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(FailingDeleteSecureStorageProvider::new());
        runtime
    }

    pub fn for_tests_with_onedrive_item(
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) -> Self {
        let mut runtime = Self::for_tests();
        runtime
            .providers
            .insert_memory_item(drive_id, item_id, name, account_label, bytes);
        runtime
    }

    pub fn for_tests_at_with_onedrive_item(
        unix_time: u64,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) -> Self {
        let mut runtime =
            Self::for_tests_with_onedrive_item(drive_id, item_id, name, account_label, bytes);
        runtime.fixed_unix_time = Some(unix_time);
        runtime.fixed_unix_time_ms = Some(unix_time.saturating_mul(1000));
        runtime
    }

    pub fn for_tests_at_with_onedrive_item_and_remote_cache(
        unix_time: u64,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
        cache_dir: impl AsRef<Path>,
    ) -> Self {
        let mut runtime = Self::for_tests_at_with_onedrive_item(
            unix_time,
            drive_id,
            item_id,
            name,
            account_label,
            bytes,
        );
        let cache_dir = cache_dir.as_ref();
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir);
        runtime.synced_bases = SyncedBaseStore::new_at(cache_dir.join("synced-bases"));
        runtime
    }

    pub fn replace_test_onedrive_item(&mut self, drive_id: &str, item_id: &str, bytes: Vec<u8>) {
        self.providers.replace_memory_item(drive_id, item_id, bytes);
    }

    pub fn insert_test_onedrive_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) {
        self.providers
            .insert_memory_item(drive_id, item_id, name, account_label, bytes);
    }

    pub fn remove_test_onedrive_item(&mut self, drive_id: &str, item_id: &str) {
        self.providers.remove_memory_item(drive_id, item_id);
    }

    pub fn read_test_onedrive_item_bytes(&self, drive_id: &str, item_id: &str) -> Result<Vec<u8>> {
        self.providers.read_memory_item_bytes(drive_id, item_id)
    }

    pub fn test_onedrive_item_revision(&self, drive_id: &str, item_id: &str) -> Result<u64> {
        self.providers.memory_item_revision(drive_id, item_id)
    }

    pub fn set_test_onedrive_item_revision(
        &mut self,
        drive_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        self.providers
            .set_memory_item_revision(drive_id, item_id, revision)
    }

    pub fn reset_test_onedrive_access_counts(&self) {
        self.providers.reset_memory_access_counts();
    }

    pub fn test_onedrive_access_counts(&self) -> ProviderAccessCounts {
        self.providers.memory_access_counts()
    }

    pub fn queue_test_onedrive_precondition_failure(&mut self, replacement_bytes: Option<Vec<u8>>) {
        self.providers.queue_precondition_failure(replacement_bytes);
    }

    pub fn queue_test_onedrive_ambiguous_write(&mut self, committed: bool) {
        self.providers.queue_ambiguous_write(committed, true);
    }

    pub fn queue_test_onedrive_ambiguous_write_with_unavailable_readback(
        &mut self,
        committed: bool,
    ) {
        self.providers.queue_ambiguous_write(committed, false);
    }

    pub fn fail_next_test_onedrive_conflict_copy(&self) {
        self.providers.fail_next_memory_conflict_copy();
    }

    pub fn fail_next_test_onedrive_remote_state(&self) {
        self.providers.fail_next_memory_remote_state();
    }

    pub fn interrupt_next_test_conflict_split_after_receipt_intent(&mut self) {
        self.conflict_split_interruption = Some(ConflictSplitInterruptionPoint::AfterReceiptIntent);
    }

    pub fn interrupt_next_test_conflict_split_after_conflict_copy(&mut self) {
        self.conflict_split_interruption = Some(ConflictSplitInterruptionPoint::AfterConflictCopy);
    }

    fn interrupt_conflict_split_at(&mut self, point: ConflictSplitInterruptionPoint) -> Result<()> {
        if self.conflict_split_interruption == Some(point) {
            self.conflict_split_interruption = None;
            return Err(ConflictSplitInterrupted { point }.into());
        }
        Ok(())
    }

    pub fn open_local_vault(&mut self, path: &str) -> Result<VaultHandleDto> {
        let path = normalize_local_path(path)?;
        self.load_local_vault_snapshot(&path)
    }

    fn load_local_vault_snapshot(&mut self, path: &str) -> Result<VaultHandleDto> {
        let snapshot = self
            .providers
            .local(path)
            .read()
            .with_context(|| format!("failed to read vault: {path}"))?;
        let bytes = snapshot.bytes;
        let baseline_fingerprint = fingerprint_for_cached_bytes(&bytes, 0);
        let provider_revision = snapshot.revision;
        let vault_id = path.to_owned();
        self.synced_bases
            .store(&vault_id, &bytes)
            .with_context(|| format!("failed to store synced base: {vault_id}"))?;
        self.session_bases
            .store(&vault_id, &bytes)
            .with_context(|| format!("failed to store session base: {vault_id}"))?;
        let name = Path::new(path)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or(path)
            .to_owned();
        let reference = self
            .references
            .upsert_local_path(path, self.current_unix_time() as i64)?;
        self.vault_session
            .set_current_vault(reference.vault_ref_id.clone());

        self.vault_session.insert_loaded(
            vault_id.clone(),
            LoadedVault {
                source: VaultSource::LocalPath(path.to_owned()),
                name: name.clone(),
                bytes,
                baseline_fingerprint,
                provider_revision: Some(provider_revision),
                credential_shape: MasterCredentialShape {
                    has_password: false,
                    has_key_file: false,
                },
                save_profile: VaultEncodingProfile::recommended(),
                requires_source_migration: false,
                vault: None,
                transformed_key: None,
                source_status: None,
                source_account_label: None,
            },
        );

        Ok(VaultHandleDto {
            vault_id,
            name,
            path: path.to_owned(),
        })
    }

    fn interrupted_onedrive_conflict_receipt(
        &self,
        drive_id: &str,
        item_id: &str,
        cached_main: Option<&RemoteVaultCacheEntry>,
    ) -> Result<Option<RemoteVaultCacheEntry>> {
        let cache_key = RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id));
        let main_pending_kind = cached_main
            .filter(|main| main.pending_sync)
            .and_then(|main| {
                self.remote_cache
                    .generic_pending_kind(&cache_key, &main.fingerprint)
                    .ok()
            });
        if main_pending_kind == Some(GenericPendingKind::ConflictCopy) {
            return Ok(None);
        }
        let receipt_key = onedrive_conflict_receipt_cache_key(drive_id, item_id);
        let Some(receipt) = self.remote_cache.read(&receipt_key)? else {
            return Ok(None);
        };
        if let Some(receipt_source) = &receipt.conflict_receipt_source {
            let source_is_current = cached_main
                .is_none_or(|main| same_content_fingerprint(&main.fingerprint, receipt_source));
            return Ok(source_is_current.then_some(receipt));
        }
        if main_pending_kind == Some(GenericPendingKind::SourceWrite) {
            return Ok(None);
        }
        if receipt.pending_sync {
            return Ok(Some(receipt));
        }
        Ok(None)
    }

    fn promote_interrupted_onedrive_conflict_receipt(
        &self,
        cache_key: &RemoteCacheKey,
        cached_main: Option<&RemoteVaultCacheEntry>,
        receipt: RemoteVaultCacheEntry,
    ) -> Result<RemoteVaultCacheEntry> {
        let expected = cached_main
            .map(|main| main.fingerprint.clone())
            .unwrap_or_else(|| receipt.fingerprint.clone());
        let pending = RemoteVaultCacheEntry {
            bytes: receipt.bytes,
            fingerprint: receipt.fingerprint,
            display_name: cached_main
                .map(|main| main.display_name.clone())
                .unwrap_or(receipt.display_name),
            account_label: cached_main
                .map(|main| main.account_label.clone())
                .unwrap_or(receipt.account_label),
            cached_at: receipt.cached_at,
            pending_sync: true,
            conflict_receipt_source: None,
        };
        let current_kind = cached_main
            .filter(|main| main.pending_sync)
            .map(|_| self.remote_cache.generic_pending_kind(cache_key, &expected))
            .transpose()?;
        match current_kind {
            Some(GenericPendingKind::SourceWrite) => self
                .remote_cache
                .transition_source_write_to_conflict_copy(cache_key, pending.clone(), &expected)?,
            Some(GenericPendingKind::ConflictCopy) => {}
            None => self.remote_cache.write_conflict_copy_pending(
                cache_key,
                pending.clone(),
                &expected,
            )?,
        }
        Ok(pending)
    }

    fn load_source_snapshot(&mut self, source: StoredVaultSource) -> Result<VaultHandleDto> {
        match source {
            StoredVaultSource::LocalPath { path } => self.load_local_vault_snapshot(&path),
            StoredVaultSource::OneDriveItem {
                drive_id, item_id, ..
            } => {
                let vault_source = VaultSource::OneDriveItem {
                    drive_id: drive_id.clone(),
                    item_id: item_id.clone(),
                };
                let cache_key = remote_cache_key_for_source(&vault_source).expect("remote source");
                for activation_key in [
                    cache_key.clone(),
                    onedrive_conflict_receipt_cache_key(&drive_id, &item_id),
                ] {
                    if !self
                        .remote_cache
                        .recover_activation_while(&activation_key, || {
                            self.references
                                .contains_onedrive_item_fresh(&drive_id, &item_id)
                        })?
                    {
                        anyhow::bail!("OneDrive vault reference was deleted by another process");
                    }
                }
                let vault_id = vault_source.vault_id();
                let mut cached_main = self.remote_cache.read(&cache_key)?;
                if let Some(receipt) = self.interrupted_onedrive_conflict_receipt(
                    &drive_id,
                    &item_id,
                    cached_main.as_ref(),
                )? {
                    cached_main = Some(self.promote_interrupted_onedrive_conflict_receipt(
                        &cache_key,
                        cached_main.as_ref(),
                        receipt,
                    )?);
                }
                let (
                    name,
                    path_name,
                    bytes,
                    baseline_fingerprint,
                    provider_revision,
                    source_status,
                    source_account_label,
                ) = if let Some(cached) = cached_main {
                    if cached.pending_sync {
                        let display_name = cached.display_name;
                        let account_label = cached.account_label;
                        (
                            display_name.clone(),
                            display_name,
                            cached.bytes,
                            cached.fingerprint,
                            None,
                            Some(VaultSourceStatusDto {
                                source_kind: cache_key.provider_kind,
                                remote_state: "pending_sync".into(),
                                last_sync_at: None,
                                cached_at: Some(cached.cached_at),
                                last_error: None,
                            }),
                            Some(account_label),
                        )
                    } else {
                        match self.providers.remote_state(&drive_id, &item_id) {
                            Ok(state) if state.matches_identity(&cached.fingerprint) => {
                                let provider_revision = Some(state.revision().clone());
                                let display_name = cached.display_name;
                                let account_label = cached.account_label;
                                (
                                    display_name.clone(),
                                    display_name,
                                    cached.bytes,
                                    cached.fingerprint,
                                    provider_revision,
                                    Some(VaultSourceStatusDto {
                                        source_kind: cache_key.provider_kind,
                                        remote_state: "online".into(),
                                        last_sync_at: Some(self.current_unix_time() as i64),
                                        cached_at: Some(cached.cached_at),
                                        last_error: None,
                                    }),
                                    Some(account_label),
                                )
                            }
                            Ok(state) => {
                                let snapshot = self
                                    .providers
                                    .read_onedrive_observation(&drive_id, &item_id, &state)?;
                                let provider_revision = snapshot.revision.clone();
                                let fingerprint = snapshot.fingerprint;
                                let name = display_name_for_cloud_name(state.display_name());
                                let path_name = state.display_name().to_owned();
                                let account_label = cached.account_label;
                                let cached_at = self.current_unix_time() as i64;
                                self.remote_cache.write(
                                    &cache_key,
                                    RemoteVaultCacheEntry {
                                        bytes: snapshot.bytes.clone(),
                                        fingerprint: fingerprint.clone(),
                                        display_name: name.clone(),
                                        account_label: account_label.clone(),
                                        cached_at,
                                        pending_sync: false,
                                        conflict_receipt_source: None,
                                    },
                                )?;
                                (
                                    name,
                                    path_name,
                                    snapshot.bytes,
                                    fingerprint,
                                    Some(provider_revision),
                                    Some(VaultSourceStatusDto {
                                        source_kind: cache_key.provider_kind,
                                        remote_state: "online".into(),
                                        last_sync_at: Some(cached_at),
                                        cached_at: Some(cached_at),
                                        last_error: None,
                                    }),
                                    Some(account_label),
                                )
                            }
                            Err(error) => {
                                let remote_error = format_error_chain(&error);
                                let display_name = cached.display_name;
                                let account_label = cached.account_label;
                                (
                                    display_name.clone(),
                                    display_name,
                                    cached.bytes,
                                    cached.fingerprint,
                                    None,
                                    Some(VaultSourceStatusDto {
                                        source_kind: cache_key.provider_kind,
                                        remote_state: "cache".into(),
                                        last_sync_at: None,
                                        cached_at: Some(cached.cached_at),
                                        last_error: Some(remote_error),
                                    }),
                                    Some(account_label),
                                )
                            }
                        }
                    }
                } else {
                    let snapshot_result: Result<_> = match &vault_source {
                        VaultSource::OneDriveItem { drive_id, item_id } => (|| {
                            let metadata = self.providers.metadata(drive_id, item_id)?;
                            let snapshot = self.providers.onedrive(drive_id, item_id).read()?;
                            Ok((metadata, snapshot))
                        })(
                        ),
                        VaultSource::LocalPath(_) => unreachable!(),
                    };
                    match snapshot_result {
                        Ok((metadata, snapshot)) => {
                            let fingerprint = snapshot.identity;
                            let name = display_name_for_cloud_name(&metadata.name);
                            let path_name = metadata.name;
                            let account_label = metadata.account_label;
                            let cached_at = self.current_unix_time() as i64;
                            self.remote_cache.write(
                                &cache_key,
                                RemoteVaultCacheEntry {
                                    bytes: snapshot.bytes.clone(),
                                    fingerprint: fingerprint.clone(),
                                    display_name: name.clone(),
                                    account_label: account_label.clone(),
                                    cached_at,
                                    pending_sync: false,
                                    conflict_receipt_source: None,
                                },
                            )?;
                            (
                                name,
                                path_name,
                                snapshot.bytes,
                                fingerprint,
                                Some(snapshot.revision),
                                Some(VaultSourceStatusDto {
                                    source_kind: cache_key.provider_kind,
                                    remote_state: "online".into(),
                                    last_sync_at: Some(cached_at),
                                    cached_at: Some(cached_at),
                                    last_error: None,
                                }),
                                Some(account_label),
                            )
                        }
                        Err(error) => {
                            let remote_error = format_error_chain(&error);
                            let cached =
                                self.remote_cache.read(&cache_key)?.with_context(|| {
                                    format!("failed to read OneDrive vault: {}", vault_id)
                                })?;
                            let display_name = cached.display_name;
                            let account_label = cached.account_label;
                            (
                                display_name.clone(),
                                display_name,
                                cached.bytes,
                                cached.fingerprint,
                                None,
                                Some(VaultSourceStatusDto {
                                    source_kind: cache_key.provider_kind,
                                    remote_state: "cache".into(),
                                    last_sync_at: None,
                                    cached_at: Some(cached.cached_at),
                                    last_error: Some(remote_error),
                                }),
                                Some(account_label),
                            )
                        }
                    }
                };

                let pending_sync = source_status
                    .as_ref()
                    .is_some_and(|status| status.remote_state == "pending_sync");
                let session_base_bytes = if pending_sync {
                    let pending_cache_key =
                        RemoteCacheKey::new("onedrive", &onedrive_remote_id(&drive_id, &item_id));
                    match self
                        .remote_cache
                        .generic_pending_kind(&pending_cache_key, &baseline_fingerprint)
                    {
                        Ok(GenericPendingKind::SourceWrite) => self.recover_generic_pending_base(
                            &vault_id,
                            &pending_cache_key,
                            &baseline_fingerprint,
                        )?,
                        Ok(GenericPendingKind::ConflictCopy) => bytes.clone(),
                        Err(_) => self
                            .synced_bases
                            .read(&vault_id)
                            .with_context(|| format!("failed to read synced base: {vault_id}"))?
                            .with_context(|| format!("synced base is missing: {vault_id}"))?,
                    }
                } else {
                    self.synced_bases
                        .store(&vault_id, &bytes)
                        .with_context(|| format!("failed to store synced base: {vault_id}"))?;
                    bytes.clone()
                };
                self.session_bases
                    .store(&vault_id, &session_base_bytes)
                    .with_context(|| format!("failed to store session base: {vault_id}"))?;

                self.vault_session.insert_loaded(
                    vault_id.clone(),
                    LoadedVault {
                        source: vault_source,
                        name: name.clone(),
                        bytes,
                        baseline_fingerprint,
                        provider_revision,
                        credential_shape: MasterCredentialShape {
                            has_password: false,
                            has_key_file: false,
                        },
                        save_profile: VaultEncodingProfile::recommended(),
                        requires_source_migration: false,
                        vault: None,
                        transformed_key: None,
                        source_status,
                        source_account_label,
                    },
                );

                Ok(VaultHandleDto {
                    vault_id,
                    name,
                    path: format!("onedrive:{path_name}"),
                })
            }
        }
    }

    pub fn preload_current_vault_snapshot(&mut self) -> Result<()> {
        let Some(current_vault_ref_id) = self
            .vault_session
            .current_vault_ref_id()
            .map(ToOwned::to_owned)
        else {
            return Ok(());
        };
        let source = self.references.source_for(&current_vault_ref_id)?;

        let vault_id = vault_id_for_stored_source(&source);
        if self.vault_session.is_preloaded_for_unlock(&vault_id)
            || self
                .vault_session
                .find_loaded(&vault_id)
                .is_some_and(|loaded| loaded.vault.is_some())
        {
            return Ok(());
        }

        self.load_source_snapshot(source)?;
        self.vault_session.mark_preloaded_for_unlock(vault_id);
        Ok(())
    }

    pub fn add_local_vault_reference(&mut self, path: &str) -> Result<VaultReferenceDto> {
        let path = normalize_local_path(path)?;
        let reference = self
            .references
            .upsert_local_path(&path, self.current_unix_time() as i64)?;
        self.vault_session
            .set_current_vault(reference.vault_ref_id.clone());
        Ok(reference)
    }

    pub fn add_onedrive_vault_reference(
        &mut self,
        drive_id: &str,
        item_id: &str,
    ) -> Result<VaultReferenceDto> {
        let metadata = self.providers.metadata(drive_id, item_id)?;
        let source = VaultSource::OneDriveItem {
            drive_id: metadata.drive_id.clone(),
            item_id: metadata.item_id.clone(),
        };
        let cache_key = remote_cache_key_for_source(&source).expect("remote source");
        let receipt_key =
            onedrive_conflict_receipt_cache_key(&metadata.drive_id, &metadata.item_id);
        let last_used_at = self.current_unix_time() as i64;
        let references = &mut self.references;
        let reference = self.remote_cache.activate_while(&cache_key, || {
            self.remote_cache.activate_while(&receipt_key, || {
                references.upsert_onedrive_item(
                    &metadata.drive_id,
                    &metadata.item_id,
                    &metadata.name,
                    &metadata.account_label,
                    last_used_at,
                )
            })
        })?;
        self.vault_session
            .set_current_vault(reference.vault_ref_id.clone());
        Ok(reference)
    }

    pub fn list_recent_vaults(&self) -> Result<VaultReferenceListDto> {
        let mut list = self.references.list_recent_vaults()?;
        if self.quick_unlock_policy_enabled() && self.biometric.supports_quick_unlock() {
            for vault in &mut list.vaults {
                let storage_key = quick_unlock_storage_key(&vault.vault_ref_id);
                vault.supports_quick_unlock = match self.secure_storage.contains(&storage_key) {
                    Ok(contains) => contains,
                    Err(_) => false,
                };
            }
        }
        Ok(list)
    }

    pub fn set_current_vault(&mut self, vault_ref_id: &str) -> Result<()> {
        self.pending_quick_unlock_enrollment = None;
        self.references
            .mark_current(vault_ref_id, self.current_unix_time() as i64)?;
        self.vault_session
            .set_current_vault(vault_ref_id.to_owned());
        self.advance_session_generation();
        Ok(())
    }

    pub fn delete_vault_reference(&mut self, vault_ref_id: &str) -> Result<VaultReferenceListDto> {
        self.delete_vault_reference_with_current_policy(vault_ref_id, true)
    }

    pub fn delete_vault_reference_if_not_current(
        &mut self,
        vault_ref_id: &str,
    ) -> Result<VaultReferenceListDto> {
        self.delete_vault_reference_with_current_policy(vault_ref_id, false)
    }

    fn delete_vault_reference_with_current_policy(
        &mut self,
        vault_ref_id: &str,
        allow_current: bool,
    ) -> Result<VaultReferenceListDto> {
        let source = self.references.source_for(vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        let cache_keys = remote_cache_keys_for_stored_source(&source);
        let mut retirements = Vec::with_capacity(cache_keys.len());
        for cache_key in &cache_keys {
            retirements.push(self.remote_cache.begin_retirement(cache_key)?);
        }
        let deletion = if allow_current {
            self.references.delete(vault_ref_id).map(Some)
        } else {
            self.references
                .delete_if_not_current(vault_ref_id)
                .map(|cleanup| cleanup.map(|cleanup| (false, cleanup)))
        };
        let (deleted_current, cleanup) = match deletion {
            Ok(Some(deletion)) => deletion,
            Ok(None) => {
                for retirement in &retirements {
                    retirement.cancel_retirement()?;
                }
                return self.list_recent_vaults();
            }
            Err(error) => {
                drop(retirements);
                if let StoredVaultSource::OneDriveItem {
                    drive_id, item_id, ..
                } = &source
                {
                    for cache_key in &cache_keys {
                        let _ = self.remote_cache.recover_activation_while(cache_key, || {
                            self.references
                                .contains_onedrive_item_fresh(drive_id, item_id)
                        });
                    }
                }
                return Err(error);
            }
        };
        self.vault_session.remove_loaded(&vault_id);
        if deleted_current {
            self.vault_session.clear_current_vault();
        }
        let synced_bases = &self.synced_bases;
        let session_bases = &self.session_bases;
        let secure_storage = self.secure_storage.as_ref();
        let allow_unlock_kdf = self.allow_unlock_kdf;
        let cleanup_result = self.references.complete_cleanup_while(&cleanup, || {
            for retirement in &retirements {
                retirement.delete_cached_state()?;
            }
            synced_bases.delete(&vault_id)?;
            session_bases.delete(&vault_id)?;
            if allow_unlock_kdf {
                secure_storage.delete(&quick_unlock_storage_key(&cleanup.vault_ref_id))?;
            }
            Ok(())
        });
        if let Err(error) = cleanup_result {
            write_runtime_warning(&format!(
                "vault reference was deleted; orphaned state cleanup remains pending: {error:#}"
            ));
        }
        self.list_recent_vaults()
    }

    fn reconcile_deleted_vault_cleanups(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        for cleanup in self.references.pending_cleanups()? {
            if let Err(error) = self.reconcile_deleted_vault_cleanup(&cleanup) {
                failures.push(format!("{}: {error:#}", cleanup.vault_ref_id));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(failures.join("; "))
        }
    }

    fn reconcile_deleted_vault_cleanup(&mut self, cleanup: &PendingVaultCleanup) -> Result<()> {
        let cache_keys = remote_cache_keys_for_stored_source(&cleanup.source);
        let mut retirements = Vec::with_capacity(cache_keys.len());
        for cache_key in &cache_keys {
            retirements.push(self.remote_cache.begin_cleanup_after_intent(cache_key)?);
        }
        let vault_id = vault_id_for_stored_source(&cleanup.source);
        let synced_bases = &self.synced_bases;
        let session_bases = &self.session_bases;
        let secure_storage = self.secure_storage.as_ref();
        let allow_unlock_kdf = self.allow_unlock_kdf;
        let completed = self.references.complete_cleanup_while(cleanup, || {
            for retirement in &retirements {
                retirement.delete_cached_state()?;
            }
            synced_bases.delete(&vault_id)?;
            session_bases.delete(&vault_id)?;
            if allow_unlock_kdf {
                secure_storage.delete(&quick_unlock_storage_key(&cleanup.vault_ref_id))?;
            }
            Ok(())
        })?;
        if completed.is_none()
            && self
                .references
                .contains_vault_ref_fresh(&cleanup.vault_ref_id)?
        {
            for retirement in &retirements {
                retirement.cancel_retirement()?;
            }
        }
        Ok(())
    }

    pub fn unlock_with_password(&mut self, vault_id: &str, password: &str) -> Result<()> {
        self.unlock_vault(vault_id, Some(password), None)
    }

    pub fn unlock_vault(
        &mut self,
        vault_id: &str,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.unlock_vault_with_kdf_confirmation(
            vault_id,
            password,
            key_file_path,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    pub fn unlock_vault_with_kdf_confirmation(
        &mut self,
        vault_id: &str,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        let master_credential = master_credential_from_parts(password, key_file_path)?;
        let current_vault_ref_id = self.references.find_ref_id_by_path(vault_id)?.or_else(|| {
            self.vault_session
                .current_vault_ref_id()
                .map(ToOwned::to_owned)
        });
        let (policy, _) = self.external_open_kdf_policy();
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;

        let credential_shape = master_credential.shape();
        let key = master_credential.to_composite_key();
        let (vault, transformed_key, save_profile, name, migrated_base) = {
            if let Some(migration_profile) =
                ResidentVaultCodec::legacy_migration_profile(&loaded.bytes)
                    .with_context(|| format!("failed to inspect vault: {vault_id}"))?
            {
                let legacy = ResidentVaultCodec
                    .decode_with_policy(&loaded.bytes, &key, &policy, confirmation)
                    .with_context(|| format!("failed to unlock vault: {vault_id}"))?;
                let migrated = ResidentVaultCodec
                    .encode_with_composite_key(legacy, &key, migration_profile.clone())
                    .with_context(|| format!("failed to migrate legacy vault: {vault_id}"))?;
                let transformed_key = ResidentVaultCodec
                    .derive_key_with_policy(&migrated.bytes, &key, &policy, confirmation)
                    .with_context(|| format!("failed to derive migrated vault key: {vault_id}"))?;
                let vault = ResidentVaultCodec
                    .decode_diagnostic(&migrated.bytes, &transformed_key)
                    .with_context(|| format!("failed to load migrated vault: {vault_id}"))?;
                let name = vault.name.clone();
                (
                    vault,
                    transformed_key,
                    migration_profile.without_explicit_kdf(),
                    name,
                    Some(migrated.bytes),
                )
            } else {
                let transformed_key = ResidentVaultCodec
                    .derive_key_with_policy(&loaded.bytes, &key, &policy, confirmation)
                    .with_context(|| format!("failed to derive vault key: {vault_id}"))?;
                let vault = ResidentVaultCodec
                    .decode_diagnostic(&loaded.bytes, &transformed_key)
                    .with_context(|| format!("failed to unlock vault: {vault_id}"))?;
                let name = vault.name.clone();
                (
                    vault,
                    transformed_key,
                    VaultEncodingProfile::inspect(&loaded.bytes)
                        .with_context(|| format!("failed to inspect vault: {vault_id}"))?,
                    name,
                    None,
                )
            }
        };
        let requires_source_migration = migrated_base.is_some();
        if let Some(migrated_base) = migrated_base.as_deref() {
            self.synced_bases
                .store(vault_id, migrated_base)
                .with_context(|| format!("failed to store migrated synced base: {vault_id}"))?;
            self.session_bases
                .store(vault_id, migrated_base)
                .with_context(|| format!("failed to store migrated session base: {vault_id}"))?;
        }
        self.vault_session.finish_unlock(
            vault_id,
            vault,
            transformed_key,
            credential_shape,
            current_vault_ref_id,
        )?;
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.save_profile = save_profile;
        loaded.requires_source_migration = requires_source_migration;
        loaded.name = name;
        self.advance_session_generation();
        self.retry_generic_pending_publication_after_unlock(vault_id);
        Ok(())
    }

    fn retry_generic_pending_publication_after_unlock(&mut self, vault_id: &str) {
        let pending = self.vault_session.find_loaded(vault_id).and_then(|loaded| {
            loaded
                .source_status
                .as_ref()
                .is_some_and(|status| status.remote_state == "pending_sync")
                .then(|| {
                    (
                        loaded.source.clone(),
                        remote_cache_key_for_source(&loaded.source),
                        loaded.baseline_fingerprint.clone(),
                    )
                })
        });
        let Some((source, Some(cache_key), pending_fingerprint)) = pending else {
            return;
        };
        let recovering_conflict_receipt = match source {
            VaultSource::OneDriveItem { drive_id, item_id } => self
                .remote_cache
                .read(&cache_key)
                .ok()
                .and_then(|cached| {
                    self.interrupted_onedrive_conflict_receipt(&drive_id, &item_id, cached.as_ref())
                        .ok()
                        .flatten()
                })
                .is_some(),
            VaultSource::LocalPath(_) => false,
        };
        if !recovering_conflict_receipt
            && self
                .remote_cache
                .generic_pending_kind(&cache_key, &pending_fingerprint)
                .is_err()
        {
            return;
        }
        if let Err(error) = self.retry_vault_source_sync(vault_id)
            && let Some(status) = self
                .vault_session
                .find_loaded_mut(vault_id)
                .and_then(|loaded| loaded.source_status.as_mut())
        {
            status.last_error = Some(format!(
                "automatic Publication retry remains pending: {}",
                format_error_chain(&error)
            ));
        }
    }

    pub fn unlock_current_vault_with_password(&mut self, password: &str) -> Result<()> {
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let source = self.references.source_for(&current_vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        if self.vault_session.is_preloaded_for_unlock(&vault_id) {
            return self.unlock_with_password(&vault_id, password);
        }
        let handle = self.load_source_snapshot(source)?;
        self.unlock_with_password(&handle.vault_id, password)
    }

    pub fn unlock_current_vault(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.unlock_current_vault_with_kdf_confirmation(
            password,
            key_file_path,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    pub fn unlock_current_vault_with_kdf_confirmation(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let source = self.references.source_for(&current_vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        if self.vault_session.is_preloaded_for_unlock(&vault_id) {
            return self.unlock_vault_with_kdf_confirmation(
                &vault_id,
                password,
                key_file_path,
                confirmation,
            );
        }
        let handle = self.load_source_snapshot(source)?;
        self.unlock_vault_with_kdf_confirmation(
            &handle.vault_id,
            password,
            key_file_path,
            confirmation,
        )
    }

    pub fn lock_session(&mut self) {
        self.pending_quick_unlock_enrollment = None;
        self.advance_session_generation();
        let vault_ids = self
            .vault_session
            .loaded_vault_ids()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        for vault_id in vault_ids {
            let (pending_cache_key, baseline_fingerprint) =
                match self.vault_session.find_loaded(&vault_id) {
                    Some(loaded) => (
                        loaded
                            .source_status
                            .as_ref()
                            .is_some_and(|status| status.remote_state == "pending_sync")
                            .then(|| remote_cache_key_for_source(&loaded.source))
                            .flatten(),
                        loaded.baseline_fingerprint.clone(),
                    ),
                    None => continue,
                };
            let pending = pending_cache_key
                .as_ref()
                .and_then(|cache_key| self.remote_cache.read(cache_key).ok().flatten())
                .filter(|entry| entry.pending_sync);
            let session_base = pending_cache_key
                .is_none()
                .then(|| {
                    self.session_base_for_fingerprint(&vault_id, &baseline_fingerprint)
                        .ok()
                })
                .flatten();
            if let Some(loaded) = self.vault_session.find_loaded_mut(&vault_id) {
                if pending_cache_key.is_some() {
                    if let Some(pending) = pending {
                        loaded.bytes = pending.bytes;
                        loaded.baseline_fingerprint = pending.fingerprint;
                    } else {
                        loaded.bytes.clear();
                    }
                } else if loaded.bytes.is_empty() {
                    loaded.bytes = session_base.unwrap_or_default();
                }
            }
        }
        self.vault_session.lock_all();
    }

    pub fn try_lock_session(&mut self) -> Result<()> {
        self.ensure_no_active_platform_passkey_operation()?;
        self.lock_session();
        Ok(())
    }

    pub fn ensure_no_active_platform_passkey_operation(&self) -> Result<()> {
        if !self.platform_passkey_operations.is_empty() {
            anyhow::bail!("session has an active platform passkey operation");
        }
        Ok(())
    }

    pub fn close_vault(&mut self, vault_id: &str) -> Result<()> {
        if self.vault_session.find_loaded(vault_id).is_none() {
            anyhow::bail!("vault not opened: {vault_id}");
        }
        self.ensure_no_active_platform_passkey_operation()?;
        self.session_bases.delete(vault_id).with_context(|| {
            format!("failed to remove session base for closed vault: {vault_id}")
        })?;
        self.pending_quick_unlock_enrollment = None;
        self.vault_session.remove_loaded(vault_id);
        self.advance_session_generation();
        Ok(())
    }

    pub fn enable_quick_unlock_for_current_vault(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.enroll_quick_unlock_for_current_vault(password, key_file_path)
    }

    pub fn enroll_quick_unlock_for_current_vault(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.enroll_quick_unlock_for_current_vault_with_kdf_confirmation(
            password,
            key_file_path,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    pub fn enroll_quick_unlock_for_current_vault_with_kdf_confirmation(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        self.ensure_quick_unlock_policy_enabled()?;
        if !self.allow_unlock_kdf {
            anyhow::bail!("quick unlock enrollment requires the resident app");
        }
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("biometric quick unlock is not implemented on this host");
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let active_vault_id = self
            .vault_session
            .active_vault_id()
            .context("current vault is locked")?
            .to_owned();
        if self
            .vault_session
            .find_loaded(&active_vault_id)
            .is_some_and(|loaded| loaded.requires_source_migration)
        {
            anyhow::bail!("save the migrated vault before enabling quick unlock");
        }
        if self.secure_storage.store_requires_user_presence() {
            self.secure_storage.authorize_store_user_presence()?;
        } else {
            self.biometric
                .authorize("Enable quick unlock for this vault")?;
        }
        self.ensure_quick_unlock_policy_enabled()?;
        let master_credential = master_credential_from_parts(password, key_file_path)?;
        let baseline_fingerprint = self
            .vault_session
            .find_loaded(&active_vault_id)
            .with_context(|| format!("vault not opened: {active_vault_id}"))?
            .baseline_fingerprint
            .clone();
        let file_bytes = match self.read_current_snapshot(&active_vault_id, None) {
            Ok(snapshot) => snapshot
                .bytes
                .context("current vault source did not include bytes")?,
            Err(_) => self
                .session_base_for_fingerprint(&active_vault_id, &baseline_fingerprint)
                .context("synced base is unavailable for quick unlock enrollment")?,
        };
        let (policy, _) = self.external_open_kdf_policy();
        let transformed_key = ResidentVaultCodec.derive_key_with_policy(
            &file_bytes,
            &master_credential.to_composite_key(),
            &policy,
            confirmation,
        )?;
        ResidentVaultCodec
            .decode(&file_bytes, &transformed_key)
            .context("quick unlock enrollment credentials do not unlock the vault")?;
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        enroll_unlock_blob(
            self.secure_storage.as_ref(),
            &storage_key,
            &master_credential,
            &transformed_key,
        )?;
        if let Err(error) = self.ensure_quick_unlock_policy_enabled() {
            if let Err(cleanup_error) = self.secure_storage.delete(&storage_key) {
                write_runtime_warning(&format!(
                    "disabled quick-unlock enrollment cleanup remains pending: {cleanup_error:#}"
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn unlock_current_vault_with_quick_unlock(&mut self) -> Result<()> {
        match self
            .try_unlock_current_vault_with_quick_unlock(ExternalKdfConfirmation::Unconfirmed)?
        {
            QuickUnlockOutcome::Unlocked => Ok(()),
            QuickUnlockOutcome::NotEnrolled => {
                anyhow::bail!("quick unlock is not enabled for the current vault")
            }
            QuickUnlockOutcome::Cancelled => anyhow::bail!("quick unlock was cancelled"),
            QuickUnlockOutcome::OpenAppRequired => {
                anyhow::bail!("quick unlock cache miss; open the resident app once")
            }
            QuickUnlockOutcome::CredentialRequired => {
                anyhow::bail!("stored master credential no longer unlocks this vault")
            }
            QuickUnlockOutcome::Unsupported => {
                anyhow::bail!("biometric quick unlock is not implemented on this host")
            }
        }
    }

    pub fn try_unlock_current_vault_with_quick_unlock(
        &mut self,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<QuickUnlockOutcome> {
        self.ensure_quick_unlock_policy_enabled()?;
        if !self.biometric.supports_quick_unlock() {
            return Ok(QuickUnlockOutcome::Unsupported);
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        if !self.secure_storage.load_requires_user_presence() {
            if let Err(error) = self.biometric.authorize("Unlock this vault") {
                if is_secure_storage_cancelled(&error) {
                    return Ok(QuickUnlockOutcome::Cancelled);
                }
                return Err(error);
            }
        }
        self.ensure_quick_unlock_policy_enabled()?;
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        let source = self.references.source_for(&current_vault_ref_id)?;
        let handle = self.load_source_snapshot(source)?;
        let (attempt, save_profile) = {
            let loaded = self
                .vault_session
                .find_loaded(&handle.vault_id)
                .with_context(|| format!("vault not opened: {}", handle.vault_id))?;
            let (policy, _) = self.external_open_kdf_policy();
            let attempt = unlock_from_blob_with_policy(
                self.secure_storage.as_ref(),
                &storage_key,
                &loaded.bytes,
                &policy,
                confirmation,
            )?;
            (
                attempt,
                VaultEncodingProfile::inspect(&loaded.bytes)
                    .with_context(|| format!("failed to inspect vault: {}", handle.vault_id))?,
            )
        };
        let unlocked = match attempt {
            UnlockAttempt::Unlocked(unlocked) => unlocked,
            UnlockAttempt::NotEnrolled => return Ok(QuickUnlockOutcome::NotEnrolled),
            UnlockAttempt::Cancelled => return Ok(QuickUnlockOutcome::Cancelled),
            UnlockAttempt::OpenAppRequired => return Ok(QuickUnlockOutcome::OpenAppRequired),
            UnlockAttempt::CredentialRequired => {
                return Ok(QuickUnlockOutcome::CredentialRequired);
            }
        };
        self.ensure_quick_unlock_policy_enabled()?;
        self.vault_session.finish_unlock_from_blob(
            &handle.vault_id,
            unlocked.vault,
            unlocked.transformed_key,
            unlocked.credential_shape,
            Some(current_vault_ref_id),
        )?;
        let loaded = self
            .vault_session
            .find_loaded_mut(&handle.vault_id)
            .context("vault disappeared after quick unlock")?;
        loaded.save_profile = save_profile;
        loaded.name = handle.name;
        self.advance_session_generation();
        Ok(QuickUnlockOutcome::Unlocked)
    }

    pub fn disable_quick_unlock_for_current_vault(&mut self) -> Result<()> {
        if !self.allow_unlock_kdf {
            anyhow::bail!("quick unlock is owned by the resident app");
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        self.secure_storage
            .delete(&quick_unlock_storage_key(&current_vault_ref_id))
    }

    pub fn reconcile_quick_unlock(
        &mut self,
        enabled: bool,
        credentials: Option<QuickUnlockReconciliationCredentials>,
    ) -> Result<bool> {
        if self.quick_unlock_policy_enabled() != enabled {
            return Ok(false);
        }
        if !enabled {
            self.pending_quick_unlock_enrollment = None;
            return Ok(self.secure_storage.purge_quick_unlock_records()? > 0);
        }

        let Some(current_vault_ref_id) =
            self.vault_session.current_vault_ref_id().map(str::to_owned)
        else {
            self.pending_quick_unlock_enrollment = None;
            return Ok(false);
        };
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        if self.secure_storage.contains(&storage_key)? {
            self.pending_quick_unlock_enrollment = None;
            return Ok(false);
        }

        if !self.platform_passkey_is_unlocked() {
            return Ok(false);
        }

        let Some(credentials) = credentials else {
            return Ok(false);
        };
        if credentials.vault_ref_id() != Some(current_vault_ref_id.as_str()) {
            return Ok(false);
        }
        self.enable_quick_unlock_for_current_vault(
            credentials.password(),
            credentials.key_file_path(),
        )?;
        self.pending_quick_unlock_enrollment = None;
        Ok(true)
    }

    pub(crate) fn remember_quick_unlock_enrollment(
        &mut self,
        password: Option<SensitiveString>,
        key_file_path: Option<String>,
    ) {
        if !self.allow_unlock_kdf || !self.quick_unlock_policy_enabled() {
            self.pending_quick_unlock_enrollment = None;
            return;
        }
        let Some(vault_ref_id) = self.vault_session.current_vault_ref_id().map(str::to_owned)
        else {
            return;
        };
        self.pending_quick_unlock_enrollment = Some(PendingQuickUnlockEnrollment {
            credentials: QuickUnlockReconciliationCredentials::from_protocol_input(
                password,
                key_file_path,
            )
            .bound_to_vault_ref(&vault_ref_id),
        });
    }

    pub fn bind_quick_unlock_reconciliation_credentials(
        &self,
        credentials: QuickUnlockReconciliationCredentials,
        expected_vault_ref_id: &str,
    ) -> Result<QuickUnlockReconciliationCredentials> {
        self.ensure_quick_unlock_policy_enabled()?;
        let vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?;
        if vault_ref_id != expected_vault_ref_id {
            anyhow::bail!("current vault changed before quick unlock enrollment was bound");
        }
        Ok(credentials.bound_to_vault_ref(vault_ref_id))
    }

    pub fn session_state(&self) -> vaultkern_runtime_protocol::SessionStateDto {
        let mut dto = self
            .vault_session
            .to_dto(self.quick_unlock_policy_enabled() && self.biometric.supports_quick_unlock());
        dto.source_status = self.current_source_status();
        dto
    }

    pub fn passkey_user_verification_capability(&self) -> PasskeyUserVerificationCapabilityDto {
        let mut methods = Vec::new();
        let Some(active_vault_id) = self.vault_session.active_vault_id() else {
            return PasskeyUserVerificationCapabilityDto {
                available: false,
                methods,
            };
        };
        let Some(loaded) = self.vault_session.find_loaded(active_vault_id) else {
            return PasskeyUserVerificationCapabilityDto {
                available: false,
                methods,
            };
        };
        if loaded.vault.is_none() {
            return PasskeyUserVerificationCapabilityDto {
                available: false,
                methods,
            };
        }

        if self.allow_unlock_kdf
            && loaded.credential_shape.has_password
            && !loaded.credential_shape.has_key_file
        {
            methods.push(PasskeyUserVerificationMethodDto::MasterPassword);
        }

        if self.quick_unlock_policy_enabled() && self.biometric.supports_quick_unlock() {
            if let Some(vault_ref_id) = self.vault_session.current_vault_ref_id() {
                let storage_key = quick_unlock_storage_key(vault_ref_id);
                if self.secure_storage.contains(&storage_key).unwrap_or(false) {
                    methods.push(PasskeyUserVerificationMethodDto::QuickUnlock);
                }
            }
        }

        PasskeyUserVerificationCapabilityDto {
            available: !methods.is_empty(),
            methods,
        }
    }

    pub fn verify_passkey_user(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        method: PasskeyUserVerificationMethodDto,
        password: Option<&str>,
    ) -> Result<PasskeyUserVerifiedDto> {
        self.verify_passkey_user_cancellable(
            ceremony_token,
            expected_phase,
            vault_id,
            method,
            password,
            &std::sync::atomic::AtomicBool::new(false),
        )
    }

    pub(crate) fn verify_passkey_user_cancellable(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        method: PasskeyUserVerificationMethodDto,
        password: Option<&str>,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<PasskeyUserVerifiedDto> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            anyhow::bail!("browser request was cancelled");
        }
        if !matches!(
            expected_phase,
            PasskeyCeremonyPhaseDto::UserAuthorization | PasskeyCeremonyPhaseDto::UserSelection
        ) {
            anyhow::bail!("passkey user verification expected phase must allow user verification");
        }
        if self.vault_session.active_vault_id() != Some(vault_id) {
            anyhow::bail!("passkey user verification vault mismatch");
        }
        let validation_epoch_ms = self.current_unix_time_ms();
        {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if entry.phase != expected_phase {
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            validate_passkey_ceremony_not_expired(entry, validation_epoch_ms)?;
            validate_passkey_ceremony_vault_binding(entry, vault_id)?;
        }

        match method {
            PasskeyUserVerificationMethodDto::MasterPassword => {
                let password =
                    password.context("passkey user verification password is required")?;
                self.verify_passkey_user_with_master_password(vault_id, password)?;
            }
            PasskeyUserVerificationMethodDto::QuickUnlock => {
                self.verify_passkey_user_with_quick_unlock_cancellable(vault_id, cancelled)?;
            }
        }

        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            anyhow::bail!("browser request was cancelled");
        }

        let verified_at_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        validate_passkey_ceremony_not_expired(entry, verified_at_epoch_ms)?;
        bind_passkey_ceremony_vault(entry, vault_id)?;
        entry.user_verification = Some(PasskeyUserVerificationProof {
            vault_id: vault_id.to_owned(),
            method,
            verified_at_epoch_ms,
        });
        Ok(PasskeyUserVerifiedDto {
            verified: true,
            method,
            verified_at_epoch_ms: verified_at_epoch_ms as i64,
        })
    }

    fn verify_passkey_user_with_master_password(
        &self,
        vault_id: &str,
        password: &str,
    ) -> Result<()> {
        let (session_key, pending_cache_key, baseline_fingerprint) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            if loaded.vault.is_none() {
                anyhow::bail!("vault is locked: {vault_id}");
            }
            if !loaded.credential_shape.has_password || loaded.credential_shape.has_key_file {
                anyhow::bail!("passkey master password verification is unavailable");
            }
            let pending_cache_key = if loaded
                .source_status
                .as_ref()
                .is_some_and(|status| status.remote_state == "pending_sync")
            {
                remote_cache_key_for_source(&loaded.source)
            } else {
                None
            };
            (
                transformed_key_from_loaded_vault(loaded)?,
                pending_cache_key,
                loaded.baseline_fingerprint.clone(),
            )
        };
        if !self.allow_unlock_kdf {
            anyhow::bail!("passkey master password verification requires the resident app");
        }
        let base = if let Some(cache_key) = pending_cache_key {
            let pending = self
                .remote_cache
                .read(&cache_key)?
                .context("pending cache is unavailable for password verification")?;
            if !pending.pending_sync {
                anyhow::bail!("pending cache changed before password verification");
            }
            pending.bytes
        } else {
            self.session_base_for_fingerprint(vault_id, &baseline_fingerprint)
                .context("session base is unavailable for password verification")?
        };
        let candidate = MasterCredential::new(Some(password.as_bytes()), None)?;
        let (policy, confirmation) = self.external_open_kdf_policy();
        let candidate_key = ResidentVaultCodec.derive_key_with_policy(
            &base,
            &candidate.to_composite_key(),
            &policy,
            confirmation,
        )?;
        if !constant_time_bytes_eq(candidate_key.as_bytes(), session_key.as_bytes()) {
            anyhow::bail!("passkey master password verification failed");
        }
        Ok(())
    }

    fn verify_passkey_user_with_quick_unlock_cancellable(
        &self,
        vault_id: &str,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        self.ensure_quick_unlock_policy_enabled()?;
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("passkey quick unlock verification is unavailable");
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?;
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        if loaded.vault.is_none() {
            anyhow::bail!("vault is locked: {vault_id}");
        }
        let storage_key = quick_unlock_storage_key(current_vault_ref_id);
        if !self.secure_storage.contains(&storage_key).unwrap_or(false) {
            anyhow::bail!("quick unlock is not enabled for the current vault");
        }
        let authorization = self
            .biometric
            .authorize_cancellable("Verify user for passkey", cancelled);
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            anyhow::bail!("browser request was cancelled");
        }
        authorization?;
        self.ensure_quick_unlock_policy_enabled()?;
        Ok(())
    }

    pub fn list_groups(&self, vault_id: &str) -> Result<GroupTreeDto> {
        let vault = self.loaded_vault(vault_id)?;
        let view = self.core.project_vault(vault);
        Ok(GroupTreeDto {
            root: project_group_node(&view.root),
        })
    }

    pub fn list_entries(&self, vault_id: &str) -> Result<Vec<EntrySummaryDto>> {
        let vault = self.loaded_vault(vault_id)?;
        let view = self.core.project_vault(vault);
        let mut entries = Vec::new();
        collect_group_entries(&view.root, &mut entries);
        Ok(entries)
    }

    pub fn get_entry_detail(&self, vault_id: &str, entry_id: &str) -> Result<EntryDetailDto> {
        let vault = self.loaded_vault(vault_id)?;
        let mut detail = self
            .core
            .project_entry_detail(vault, entry_id)
            .with_context(|| format!("entry not found: {entry_id}"))?;
        let totp = self.core.project_entry_totp(vault, entry_id)?;
        let totp_code = totp
            .as_ref()
            .and_then(|value| totp_to_code(value, self.current_unix_time()));
        let totp_uri = totp
            .as_ref()
            .map(|value| totp_to_uri(&detail.title, &detail.username, value));
        let custom_fields = self.core.list_entry_custom_fields(vault, entry_id)?;
        let attachments = self.core.list_entry_attachments(vault, entry_id)?;
        let passkey = self
            .core
            .project_entry_passkey(vault, entry_id)?
            .map(entry_passkey_to_dto);
        Ok(EntryDetailDto {
            id: std::mem::take(&mut detail.id),
            title: std::mem::take(&mut detail.title).into(),
            username: std::mem::take(&mut detail.username).into(),
            password: std::mem::take(&mut detail.password).into(),
            url: std::mem::take(&mut detail.url).into(),
            notes: std::mem::take(&mut detail.notes).into(),
            modified_at: detail.modified_at,
            totp: totp_code.map(Into::into),
            totp_uri: totp_uri.map(Into::into),
            passkey,
            field_protection: EntryFieldProtectionDto {
                protect_title: detail.field_protection.protect_title,
                protect_username: detail.field_protection.protect_username,
                protect_password: detail.field_protection.protect_password,
                protect_url: detail.field_protection.protect_url,
                protect_notes: detail.field_protection.protect_notes,
            },
            custom_fields: custom_fields
                .into_iter()
                .map(|mut field| EntryCustomFieldDto {
                    key: std::mem::take(&mut field.key),
                    value: std::mem::take(&mut field.value).into(),
                    protected: field.protected,
                })
                .collect(),
            attachments: attachments
                .into_iter()
                .map(|attachment| EntryAttachmentDto {
                    name: attachment.name,
                    size: attachment.size,
                    protect_in_memory: attachment.protect_in_memory,
                })
                .collect(),
        })
    }

    pub fn get_database_settings(&self, vault_id: &str) -> Result<DatabaseSettingsDto> {
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let vault = loaded
            .vault
            .as_ref()
            .with_context(|| format!("vault is locked: {vault_id}"))?;

        database_settings_dto(
            vault,
            &loaded.save_profile,
            autosave_delay_seconds(vault),
            loaded.credential_shape.has_password,
        )
    }

    pub fn update_database_settings(
        &mut self,
        vault_id: &str,
        update: DatabaseSettingsUpdateDto,
    ) -> Result<DatabaseSettingsDto> {
        if update.credentials.is_some() {
            anyhow::bail!(
                "master credential changes require a fresh authenticated credential-update flow"
            );
        }
        let modified_at = self.current_unix_time();
        let modified_at_i64 = i64::try_from(modified_at)
            .context("current time is outside the KDBX timestamp domain")?;
        let settings = {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

            if let Some(encryption) = update.encryption.as_ref() {
                let requested = save_profile_from_settings(encryption.clone())?;
                if !requested.uses_retained_kdf(vault)? {
                    anyhow::bail!(
                        "KDF parameter changes require a fresh authenticated credential-update flow"
                    );
                }
            }

            let mut did_change_vault_settings = false;

            if let Some(metadata) = update.metadata {
                let mut candidate = vault.clone();
                let old_name = candidate.name.clone();
                let old_description = candidate.description.clone();
                let old_default_username = candidate.default_username.clone();
                let name = metadata.name;
                let identity_update = VaultIdentityMetadataUpdate {
                    name: Some(name.clone()),
                    generator: candidate.generator.clone(),
                    database_name_changed: candidate.database_name_changed,
                    description_changed: candidate.description_changed,
                    default_username_changed: candidate.default_username_changed,
                };
                self.core
                    .update_vault_identity_metadata(&mut candidate, identity_update)?;
                self.core.update_vault_metadata(
                    &mut candidate,
                    VaultMetadataUpdate {
                        description: Some(metadata.description.unwrap_or_default()),
                        default_username: Some(metadata.default_username.unwrap_or_default()),
                        ..VaultMetadataUpdate::default()
                    },
                )?;
                let name_changed = candidate.name != old_name;
                let description_changed = candidate.description != old_description;
                let default_username_changed = candidate.default_username != old_default_username;
                if name_changed || description_changed || default_username_changed {
                    let identity_update = VaultIdentityMetadataUpdate {
                        name: Some(candidate.name.clone()),
                        generator: candidate.generator.clone(),
                        database_name_changed: name_changed
                            .then_some(modified_at_i64)
                            .or(candidate.database_name_changed),
                        description_changed: description_changed
                            .then_some(modified_at_i64)
                            .or(candidate.description_changed),
                        default_username_changed: default_username_changed
                            .then_some(modified_at_i64)
                            .or(candidate.default_username_changed),
                    };
                    self.core
                        .update_vault_identity_metadata(&mut candidate, identity_update)?;
                }
                did_change_vault_settings |=
                    name_changed || description_changed || default_username_changed;
                *vault = candidate;
            }

            if let Some(public_metadata) = update.public_metadata {
                let previous = vault.public_custom_data.clone();
                upsert_optional_public_string(
                    vault,
                    "display-name",
                    public_metadata.display_name.as_deref(),
                );
                upsert_optional_public_string(vault, "color", public_metadata.color.as_deref());
                upsert_optional_public_string(vault, "icon", public_metadata.icon.as_deref());
                did_change_vault_settings |= vault.public_custom_data != previous;
            }

            if let Some(history) = update.history {
                let previous = (vault.history_max_items, vault.history_max_size);
                vault.history_max_items = history.max_items_per_entry;
                vault.history_max_size = history.max_total_size_bytes;
                enforce_history_limits(vault);
                did_change_vault_settings |=
                    (vault.history_max_items, vault.history_max_size) != previous;
            }

            if let Some(recycle_bin) = update.recycle_bin {
                let enabled = Some(recycle_bin.enabled);
                if vault.recycle_bin_enabled != enabled {
                    self.core.update_vault_bin_template_metadata(
                        vault,
                        VaultBinTemplateMetadataUpdate {
                            recycle_bin_enabled: Some(enabled),
                            recycle_bin_changed: Some(Some(modified_at_i64)),
                            ..VaultBinTemplateMetadataUpdate::default()
                        },
                    )?;
                    did_change_vault_settings = true;
                }
            }

            match update.autosave_delay_seconds {
                OptionalSettingUpdateDto::Unchanged => {}
                OptionalSettingUpdateDto::Clear => {
                    did_change_vault_settings |= vault
                        .public_custom_data
                        .remove(AUTOSAVE_DELAY_SECONDS_KEY)
                        .is_some();
                }
                OptionalSettingUpdateDto::Set(autosave_delay_seconds) => {
                    let encoded = autosave_delay_seconds.to_string().into_bytes();
                    if vault.public_custom_data.get(AUTOSAVE_DELAY_SECONDS_KEY) != Some(&encoded) {
                        vault
                            .public_custom_data
                            .insert(AUTOSAVE_DELAY_SECONDS_KEY.to_owned(), encoded);
                        did_change_vault_settings = true;
                    }
                }
            }

            if did_change_vault_settings {
                self.core.update_vault_lifecycle_metadata(
                    vault,
                    VaultLifecycleMetadataUpdate {
                        settings_changed: Some(modified_at_i64),
                        maintenance_history_days: vault.maintenance_history_days,
                        master_key_changed: vault.master_key_changed,
                        master_key_change_rec: vault.master_key_change_rec,
                        master_key_change_force: vault.master_key_change_force,
                        master_key_change_force_once: vault.master_key_change_force_once,
                    },
                )?;
            }

            if let Some(encryption) = update.encryption {
                let settings = vault_encryption_settings(encryption)?;
                loaded.save_profile = VaultEncodingProfile::apply_encryption_settings(
                    &loaded.save_profile,
                    vault,
                    settings,
                )?;
            }

            database_settings_dto(
                vault,
                &loaded.save_profile,
                autosave_delay_seconds(vault),
                loaded.credential_shape.has_password,
            )?
        };

        Ok(settings)
    }

    pub(crate) fn commit_database_settings(
        &mut self,
        vault_id: &str,
        update: DatabaseSettingsUpdateDto,
    ) -> Result<DatabaseSettingsCommitResultDto> {
        let previous = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            loaded.clone()
        };

        let mut completed_conflict_split = false;
        let result = (|| {
            let updated_settings = self.update_database_settings(vault_id, update)?;
            let RuntimeResponse::PublicationResult(publication) =
                self.commit_working_copy(vault_id)?
            else {
                anyhow::bail!("database settings save returned an unexpected response");
            };
            if publication.status == PublicationStatusDto::ConflictSplit {
                completed_conflict_split = self.completed_conflict_split(vault_id, &previous);
                anyhow::bail!(
                    "database settings were not committed to the active vault; conflict copy: {}",
                    publication
                        .conflict_copy_path
                        .as_deref()
                        .unwrap_or("unknown")
                );
            }
            let settings = self
                .get_database_settings(vault_id)
                .unwrap_or(updated_settings);
            Ok(DatabaseSettingsCommitResultDto {
                commit: CommitStatusDto::Committed,
                settings,
                publication,
            })
        })();

        if result.is_err() && !completed_conflict_split {
            self.restore_loaded_after_failed_commit(vault_id, previous);
        }

        result
    }

    pub(crate) fn commit_vault_mutation(
        &mut self,
        vault_id: &str,
        mutation: impl FnOnce(&mut Self) -> Result<Option<String>>,
    ) -> Result<VaultMutationResultDto> {
        let previous = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?
            .clone();

        let result = (|| {
            let created_group_id = mutation(self)?;
            let RuntimeResponse::PublicationResult(publication) =
                self.commit_working_copy(vault_id)?
            else {
                anyhow::bail!("vault mutation save returned an unexpected response");
            };
            Ok(VaultMutationResultDto {
                commit: CommitStatusDto::Committed,
                publication,
                created_group_id,
            })
        })();

        if result.is_err() {
            self.restore_loaded_after_failed_commit(vault_id, previous);
        }
        result
    }

    fn completed_conflict_split(&self, vault_id: &str, previous: &LoadedVault) -> bool {
        let Some(current) = self.vault_session.find_loaded(vault_id) else {
            return false;
        };
        let generation_changed = current.baseline_fingerprint != previous.baseline_fingerprint
            || current.provider_revision != previous.provider_revision;
        if !generation_changed {
            return false;
        }
        match current.source {
            VaultSource::LocalPath(_) => true,
            VaultSource::OneDriveItem { .. } => current
                .source_status
                .as_ref()
                .is_some_and(|status| status.remote_state == "online"),
        }
    }

    pub(crate) fn commit_entry_mutation(
        &mut self,
        vault_id: &str,
        mutation: impl FnOnce(&mut Self) -> Result<Option<EntryDetailDto>>,
    ) -> Result<EntryMutationResultDto> {
        let previous = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?
            .clone();

        let result = (|| {
            let mut entry = mutation(self)?;
            let RuntimeResponse::PublicationResult(publication) =
                self.commit_working_copy(vault_id)?
            else {
                anyhow::bail!("entry mutation save returned an unexpected response");
            };
            if matches!(
                &publication.status,
                PublicationStatusDto::Reconciled | PublicationStatusDto::ConflictSplit
            ) && let Some(mutated_entry) = entry.as_ref()
            {
                entry = self.get_entry_detail(vault_id, &mutated_entry.id).ok();
            }
            Ok(EntryMutationResultDto {
                commit: CommitStatusDto::Committed,
                publication,
                entry,
            })
        })();

        if result.is_err() {
            self.restore_loaded_after_failed_commit(vault_id, previous);
        }
        result
    }

    fn restore_loaded_after_failed_commit(&mut self, vault_id: &str, previous: LoadedVault) {
        let pending_conflict_state = self.vault_session.find_loaded(vault_id).and_then(|loaded| {
            let cache_key = remote_cache_key_for_source(&loaded.source)?;
            let fingerprint = loaded.baseline_fingerprint.clone();
            self.remote_cache
                .generic_pending_kind(&cache_key, &fingerprint)
                .ok()
                .filter(|kind| *kind == GenericPendingKind::ConflictCopy)
                .map(|_| (fingerprint, loaded.source_status.clone()))
        });
        if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
            *loaded = previous;
            if let Some((fingerprint, source_status)) = pending_conflict_state {
                loaded.baseline_fingerprint = fingerprint;
                loaded.source_status = source_status;
                loaded.bytes.clear();
            }
        }
    }

    pub fn find_fill_candidates(&self, vault_id: &str, url: &str) -> Result<FillCandidateListDto> {
        let vault = self.loaded_vault(vault_id)?;
        let mut entries = Vec::new();
        let mut index = 0;
        collect_fill_candidates(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            false,
            url,
            &mut index,
            &mut entries,
        );

        entries.sort_by(|left, right| {
            right
                .score
                .exact_path
                .cmp(&left.score.exact_path)
                .then_with(|| {
                    right
                        .score
                        .shared_path_prefix_len
                        .cmp(&left.score.shared_path_prefix_len)
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let entries = entries
            .into_iter()
            .map(|candidate| candidate.entry)
            .collect();
        Ok(FillCandidateListDto { entries })
    }

    pub fn get_autofill_credential(
        &self,
        vault_id: &str,
        entry_id: &str,
        url: &str,
    ) -> Result<AutofillCredentialDto> {
        let candidates = self.find_fill_candidates(vault_id, url)?;
        if !candidates.entries.iter().any(|entry| entry.id == entry_id) {
            anyhow::bail!("entry is not a fill candidate for the requested URL");
        }

        let detail = self.get_entry_detail(vault_id, entry_id)?;
        Ok(AutofillCredentialDto {
            id: detail.id,
            username: detail.username,
            password: detail.password,
            totp: detail.totp,
        })
    }

    pub fn get_autofill_entry_fields(
        &self,
        vault_id: &str,
        entry_id: &str,
        url: &str,
    ) -> Result<AutofillEntryFieldsDto> {
        let candidates = self.find_fill_candidates(vault_id, url)?;
        if !candidates.entries.iter().any(|entry| entry.id == entry_id) {
            anyhow::bail!("entry is not a fill candidate for the requested URL");
        }
        let vault = self.loaded_vault(vault_id)?;
        let mut fields = entry_fields_for_vault(&self.core, vault, entry_id)?;
        Ok(AutofillEntryFieldsDto {
            id: entry_id.to_owned(),
            fields: AutofillUpdateFieldsDto {
                username: std::mem::take(&mut fields.username),
                password: std::mem::take(&mut fields.password),
                url: std::mem::take(&mut fields.url),
            },
        })
    }

    pub fn get_autofill_create_context(&self, vault_id: &str) -> Result<AutofillCreateContextDto> {
        let vault = self.loaded_vault(vault_id)?;
        Ok(AutofillCreateContextDto {
            root_group_id: vault.root.id.to_string(),
        })
    }

    pub fn list_entry_history(
        &self,
        vault_id: &str,
        entry_id: &str,
    ) -> Result<EntryHistoryListDto> {
        let vault = self.loaded_vault(vault_id)?;
        let items = self
            .core
            .list_entry_history(vault, entry_id)?
            .into_iter()
            .enumerate()
            .map(|(index, item)| EntryHistoryItemDto {
                index,
                title: item.title,
                username: item.username,
                modified_at: item.modified_at,
                attachment_count: item.attachment_count,
                custom_field_count: item.custom_field_count,
            })
            .collect();

        Ok(EntryHistoryListDto { items })
    }

    pub fn get_entry_history_detail(
        &self,
        vault_id: &str,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryHistoryDetailDto> {
        let vault = self.loaded_vault(vault_id)?;
        let mut detail = self
            .core
            .project_entry_history_detail(vault, entry_id, history_index)?;
        detail.password.zeroize();
        let custom_fields =
            self.core
                .list_entry_history_custom_fields(vault, entry_id, history_index)?;
        let attachments =
            self.core
                .list_entry_history_attachments(vault, entry_id, history_index)?;

        Ok(EntryHistoryDetailDto {
            entry_id: entry_id.into(),
            history_index,
            title: std::mem::take(&mut detail.title).into(),
            username: std::mem::take(&mut detail.username).into(),
            url: std::mem::take(&mut detail.url).into(),
            notes: std::mem::take(&mut detail.notes).into(),
            modified_at: detail.modified_at,
            custom_fields: custom_fields
                .into_iter()
                .map(|mut field| {
                    let value = if field.protected {
                        String::new().into()
                    } else {
                        std::mem::take(&mut field.value).into()
                    };
                    EntryCustomFieldDto {
                        key: std::mem::take(&mut field.key),
                        value,
                        protected: field.protected,
                    }
                })
                .collect(),
            attachments: attachments
                .into_iter()
                .map(|attachment| EntryAttachmentDto {
                    name: attachment.name,
                    size: attachment.size,
                    protect_in_memory: attachment.protect_in_memory,
                })
                .collect(),
        })
    }

    fn mutate_loaded_vault<T>(
        &mut self,
        vault_id: &str,
        mutation: impl FnOnce(&KeepassCore, &mut Vault) -> Result<T>,
    ) -> Result<T> {
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let vault = loaded
            .vault
            .as_mut()
            .with_context(|| format!("vault is locked: {vault_id}"))?;
        mutation(&self.core, vault)
    }

    pub fn create_group(
        &mut self,
        vault_id: &str,
        parent_group_id: &str,
        title: String,
    ) -> Result<String> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            Ok(core.add_group(vault, parent_group_id, title)?.id)
        })
    }

    pub fn rename_group(&mut self, vault_id: &str, group_id: &str, title: String) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.update_group_metadata(
                vault,
                group_id,
                GroupMetadataUpdate {
                    title: Some(title),
                    ..GroupMetadataUpdate::default()
                },
            )?;
            Ok(())
        })
    }

    pub fn move_group(
        &mut self,
        vault_id: &str,
        group_id: &str,
        target_parent_group_id: &str,
    ) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.move_group(vault, group_id, target_parent_group_id)?;
            Ok(())
        })
    }

    pub fn delete_group(&mut self, vault_id: &str, group_id: &str) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.delete_group(vault, group_id)?;
            Ok(())
        })
    }

    pub fn move_entry_to_group(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        target_group_id: &str,
    ) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.move_entry(vault, entry_id, target_group_id)?;
            Ok(())
        })
    }

    pub fn restore_entry_history(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        history_index: usize,
    ) -> Result<()> {
        let modified_at = self.current_unix_time();
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.project_entry_history_detail(vault, entry_id, history_index)?;
            core.snapshot_entry_to_history(vault, entry_id)?;
            core.restore_entry_history(vault, entry_id, history_index)?;
            touch_entry_modified_at(core, vault, entry_id, modified_at)?;
            enforce_history_limits(vault);
            Ok(())
        })
    }

    pub fn clear_entry_history(&mut self, vault_id: &str, entry_id: &str) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.clear_entry_history(vault, entry_id)?;
            Ok(())
        })
    }

    pub fn recycle_entry(&mut self, vault_id: &str, entry_id: &str) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.soft_delete_entry_to_recycle_bin(vault, entry_id)?;
            Ok(())
        })
    }

    pub fn restore_recycled_entry(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        target_group_id: Option<&str>,
    ) -> Result<()> {
        self.mutate_loaded_vault(vault_id, |core, vault| {
            core.restore_entry_from_recycle_bin(vault, entry_id, target_group_id)?;
            Ok(())
        })
    }

    pub fn create_entry(
        &mut self,
        vault_id: &str,
        parent_group_id: &str,
        title: SensitiveString,
        username: SensitiveString,
        password: SensitiveString,
        url: SensitiveString,
        notes: SensitiveString,
        totp_uri: Option<SensitiveString>,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        let totp = parse_totp_uri(totp_uri.as_deref())?;
        let entry_id = {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

            let create = EntryCreate {
                title: take_sensitive_string(title),
                username: take_sensitive_string(username),
                password: take_sensitive_string(password),
                url: take_sensitive_string(url),
                notes: take_sensitive_string(notes),
            };
            let created = self.core.add_entry(vault, parent_group_id, create)?;

            initialize_entry_creation_times(&self.core, vault, &created.id, modified_at)?;

            if let Some(totp) = totp {
                self.core.set_entry_totp(vault, &created.id, totp)?;
            }

            created.id
        };

        self.get_entry_detail(vault_id, &entry_id)
    }

    pub(crate) fn exact_matching_entry_ids(
        &self,
        vault_id: &str,
        fields: &EntryFieldsDto,
    ) -> Result<Vec<String>> {
        anyhow::ensure!(
            self.vault_session.active_vault_id() == Some(vault_id),
            "vault is not active: {vault_id}"
        );
        let mut matching_ids = Vec::new();
        for summary in self.find_fill_candidates(vault_id, &fields.url)?.entries {
            let detail = self.get_entry_detail(vault_id, &summary.id)?;
            if entry_detail_matches_fields(&detail, fields) {
                matching_ids.push(summary.id);
            }
        }
        matching_ids.sort();
        Ok(matching_ids)
    }

    pub fn update_entry_fields(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        title: SensitiveString,
        username: SensitiveString,
        password: SensitiveString,
        url: SensitiveString,
        notes: SensitiveString,
        totp_uri: Option<SensitiveString>,
        custom_fields: Vec<EntryCustomFieldDto>,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        let requested_totp = parse_totp_uri(totp_uri.as_deref())?;
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

            let had_projectable_totp = self.core.project_entry_totp(vault, entry_id)?.is_some();
            self.core.snapshot_entry_to_history(vault, entry_id)?;
            self.core.update_entry_fields(
                vault,
                entry_id,
                EntryUpdate {
                    title: Some(take_sensitive_string(title)),
                    username: Some(take_sensitive_string(username)),
                    password: Some(take_sensitive_string(password)),
                    url: Some(take_sensitive_string(url)),
                    notes: Some(take_sensitive_string(notes)),
                },
            )?;

            match requested_totp {
                Some(totp) => {
                    self.core.set_entry_totp(vault, entry_id, totp)?;
                }
                None if had_projectable_totp => {
                    self.core.clear_entry_totp(vault, entry_id)?;
                }
                None => {}
            }

            let existing_keys = self
                .core
                .list_entry_custom_fields(vault, entry_id)?
                .into_iter()
                .map(|mut field| std::mem::take(&mut field.key))
                .collect::<Vec<_>>();
            let next_keys = custom_fields
                .iter()
                .map(|field| field.key.as_str())
                .collect::<std::collections::BTreeSet<_>>();

            for key in existing_keys {
                if !next_keys.contains(key.as_str()) {
                    self.core.delete_entry_custom_field(vault, entry_id, &key)?;
                }
            }

            for field in custom_fields {
                if !field.key.trim().is_empty() {
                    self.core.upsert_entry_custom_field(
                        vault,
                        entry_id,
                        EntryCustomFieldInput {
                            key: field.key,
                            value: take_sensitive_string(field.value),
                            protected: field.protected,
                        },
                    )?;
                }
            }

            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
            enforce_history_limits(vault);
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn clear_entry_totp(&mut self, vault_id: &str, entry_id: &str) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.clear_entry_totp(vault, entry_id)?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn set_entry_passkey(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        passkey: EntryPasskeyUpdateDto,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            let existing_passkey = cloned_entry_passkey_by_id(&vault.root, entry_id);
            let passkey = apply_passkey_metadata_update(passkey, existing_passkey)?;
            self.core.snapshot_entry_to_history(vault, entry_id)?;
            clear_platform_passkey_display_labels(&self.core, vault, entry_id)?;
            self.core.set_entry_passkey(vault, entry_id, passkey)?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
            enforce_history_limits(vault);
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn clear_entry_passkey(
        &mut self,
        vault_id: &str,
        entry_id: &str,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.snapshot_entry_to_history(vault, entry_id)?;
            self.core.clear_entry_passkey(vault, entry_id)?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
            enforce_history_limits(vault);
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn platform_passkey_is_unlocked(&self) -> bool {
        self.vault_session
            .active_vault_id()
            .and_then(|vault_id| self.vault_session.find_loaded(vault_id))
            .is_some_and(|loaded| loaded.vault.is_some())
    }

    pub fn has_active_platform_passkey_operations(&self) -> bool {
        !self.platform_passkey_operations.is_empty()
    }

    pub fn prepare_platform_passkey_operation(
        &mut self,
        operation_id: Vec<u8>,
        parent_window: Option<usize>,
    ) -> Result<(Vec<PlatformPasskeyCredential>, bool)> {
        if operation_id.len() != 16 {
            anyhow::bail!("platform passkey operation id must be 16 bytes");
        }
        if self.platform_passkey_operations.contains_key(&operation_id) {
            anyhow::bail!("platform passkey operation is already active");
        }
        let previous_parent = self.replace_parent_window_handle(parent_window);
        let was_unlocked = self.platform_passkey_is_unlocked();
        let result = (|| {
            if !was_unlocked {
                self.unlock_current_vault_with_quick_unlock()?;
            }
            let vault_id = self.active_platform_passkey_vault_id()?;
            let credentials = self.list_platform_passkey_credentials()?;
            let generation = self.session_generation;
            self.platform_passkey_operations.insert(
                operation_id,
                PlatformPasskeyOperationLease {
                    vault_id: vault_id.clone(),
                    session_generation: generation,
                    user_verification_consumed: false,
                    pending_registration: None,
                },
            );
            if !was_unlocked {
                self.pending_platform_relock = Some((vault_id, generation));
            }
            Ok((credentials, !was_unlocked))
        })();
        self.set_parent_window_handle(previous_parent);
        if result.is_err() && !was_unlocked {
            self.lock_session();
        }
        result
    }

    pub fn end_platform_passkey_operation(&mut self, operation_id: &[u8]) {
        if let Some(lease) = self.platform_passkey_operations.remove(operation_id)
            && let Some(rollback) = lease.pending_registration
            && let Err(error) = self.restore_passkey_registration_rollback(rollback)
        {
            write_runtime_warning(&format!(
                "failed to roll back an uncommitted platform passkey registration: {error:#}"
            ));
        }
        let Some((vault_id, generation)) = self.pending_platform_relock.clone() else {
            return;
        };
        let same_lease_remains = self
            .platform_passkey_operations
            .values()
            .any(|lease| lease.vault_id == vault_id && lease.session_generation == generation);
        if !same_lease_remains
            && self.session_generation == generation
            && self.vault_session.active_vault_id() == Some(vault_id.as_str())
        {
            self.pending_platform_relock = None;
            self.lock_session();
        }
    }

    pub fn register_platform_passkey_for_operation(
        &mut self,
        operation_id: &[u8],
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput> {
        self.consume_platform_passkey_operation_verification(operation_id)?;
        let (output, rollback) = self.prepare_platform_passkey_registration(input)?;
        let lease = self
            .platform_passkey_operations
            .get_mut(operation_id)
            .context("platform passkey operation ended during registration")?;
        lease.pending_registration = Some(rollback);
        Ok(output)
    }

    pub fn commit_platform_passkey_registration_operation(
        &mut self,
        operation_id: &[u8],
    ) -> Result<()> {
        let active_vault_id = self.active_platform_passkey_vault_id()?;
        let generation = self.session_generation;
        let rollback = {
            let lease = self
                .platform_passkey_operations
                .get_mut(operation_id)
                .context("platform passkey operation is not active")?;
            if lease.vault_id != active_vault_id || lease.session_generation != generation {
                anyhow::bail!("platform passkey operation no longer matches the verified vault");
            }
            lease
                .pending_registration
                .take()
                .context("platform passkey registration was not prepared")?
        };
        self.commit_platform_passkey_registration(rollback)
    }

    pub fn create_platform_passkey_assertion_for_operation(
        &mut self,
        operation_id: &[u8],
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput> {
        self.consume_platform_passkey_operation_verification(operation_id)?;
        self.create_platform_passkey_assertion(input)
    }

    fn consume_platform_passkey_operation_verification(
        &mut self,
        operation_id: &[u8],
    ) -> Result<()> {
        let active_vault_id = self.active_platform_passkey_vault_id()?;
        let generation = self.session_generation;
        let lease = self
            .platform_passkey_operations
            .get_mut(operation_id)
            .context("platform passkey operation is not active")?;
        if lease.vault_id != active_vault_id || lease.session_generation != generation {
            anyhow::bail!("platform passkey operation no longer matches the verified vault");
        }
        if lease.user_verification_consumed {
            anyhow::bail!("platform passkey user verification was already consumed");
        }
        lease.user_verification_consumed = true;
        Ok(())
    }

    pub fn list_platform_passkey_credentials(&self) -> Result<Vec<PlatformPasskeyCredential>> {
        let vault_id = self.active_platform_passkey_vault_id()?;
        let vault = self.loaded_vault(&vault_id)?;
        let mut candidates = Vec::new();
        let mut credential_counts = BTreeMap::<(String, String), usize>::new();
        visit_passkey_entries(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &mut |entry, passkey| {
                if passkey.user_handle.is_some()
                    && let Ok(credential) = platform_passkey_credential(
                        passkey,
                        entry
                            .custom_data
                            .get(PLATFORM_PASSKEY_RP_NAME_KEY)
                            .map(String::as_str)
                            .unwrap_or(&entry.title),
                        entry
                            .custom_data
                            .get(PLATFORM_PASSKEY_USER_DISPLAY_NAME_KEY)
                            .map(String::as_str)
                            .unwrap_or(&entry.username),
                    )
                {
                    let key = (passkey.relying_party.clone(), passkey.credential_id.clone());
                    *credential_counts.entry(key.clone()).or_insert(0) += 1;
                    candidates.push((key, credential));
                }
            },
        );
        let credentials = candidates
            .into_iter()
            .filter_map(|(key, credential)| (credential_counts[&key] == 1).then_some(credential))
            .collect();
        Ok(credentials)
    }

    pub fn register_platform_passkey(
        &mut self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput> {
        let (output, rollback) = self.prepare_platform_passkey_registration(input)?;
        self.commit_platform_passkey_registration(rollback)?;
        Ok(output)
    }

    fn prepare_platform_passkey_registration(
        &mut self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<(
        PlatformPasskeyRegistrationOutput,
        PasskeyRegistrationRollbackState,
    )> {
        let vault_id = self.active_platform_passkey_vault_id()?;
        let relying_party_name =
            platform_credential_label(&input.relying_party_name, &input.relying_party);
        let user_display_name =
            platform_credential_label(&input.user_display_name, &input.user_name);
        let credential_id = URL_SAFE_NO_PAD
            .decode((self.passkey_credential_id_generator)())
            .context("generated platform passkey credential id was not base64url")?;
        let registration = create_platform_registration_with_credential_id(
            PlatformPasskeyRegistrationRequest {
                relying_party: &input.relying_party,
                user_name: &input.user_name,
                user_handle: &input.user_handle,
                public_key_algorithm: input.public_key_algorithm,
                user_verified: input.user_verified,
            },
            credential_id,
        )?;
        let credential = platform_passkey_credential(
            &registration.passkey,
            &relying_party_name,
            &user_display_name,
        )?;
        let modified_at = self.current_unix_time();

        let (existing, credential_id_collision_count) = {
            let vault = self.loaded_vault(&vault_id)?;
            let existing = find_passkey_entry_id_by_relying_party_and_user_handle(
                &vault.root,
                vault.recycle_bin_group,
                vault.recycle_bin_enabled.unwrap_or(true),
                &input.relying_party,
                registration.passkey.user_handle.as_deref(),
            )
            .map(|entry_id| {
                let rollback_entry = cloned_entry_by_id(&vault.root, &entry_id)
                    .with_context(|| format!("entry not found: {entry_id}"))?;
                Ok::<_, anyhow::Error>((entry_id, rollback_entry))
            })
            .transpose()?;
            let mut collision_count = 0;
            visit_passkeys(
                &vault.root,
                vault.recycle_bin_group,
                vault.recycle_bin_enabled.unwrap_or(true),
                &mut |passkey| {
                    if passkey.credential_id == registration.passkey.credential_id {
                        collision_count += 1;
                    }
                },
            );
            (existing, collision_count)
        };
        if credential_id_collision_count != 0 {
            anyhow::bail!("platform passkey credential id collision");
        }

        let (entry_id, rollback) = if let Some((entry_id, rollback_entry)) = existing {
            let refresh_entry_title = rollback_entry
                .passkey
                .as_ref()
                .is_some_and(|passkey| rollback_entry.title == passkey.relying_party);
            let refresh_entry_username = rollback_entry
                .passkey
                .as_ref()
                .is_some_and(|passkey| rollback_entry.username == passkey.username);
            let rollback = PasskeyRegistrationRollbackState {
                vault_id: vault_id.clone(),
                entry_id: entry_id.clone(),
                credential_id: Some(registration.passkey.credential_id.clone()),
                created: false,
                rollback_entry: Some(rollback_entry),
            };
            let mutation = (|| {
                let loaded = self
                    .vault_session
                    .find_loaded_mut(&vault_id)
                    .with_context(|| format!("vault not opened: {vault_id}"))?;
                let vault = loaded
                    .vault
                    .as_mut()
                    .with_context(|| format!("vault is locked: {vault_id}"))?;
                self.core.snapshot_entry_to_history(vault, &entry_id)?;
                self.core
                    .set_entry_passkey(vault, &entry_id, registration.passkey)?;
                set_platform_passkey_display_labels(
                    &self.core,
                    vault,
                    &entry_id,
                    &relying_party_name,
                    &user_display_name,
                )?;
                if refresh_entry_title || refresh_entry_username {
                    self.core.update_entry_fields(
                        vault,
                        &entry_id,
                        EntryUpdate {
                            title: refresh_entry_title.then_some(relying_party_name.clone()),
                            username: refresh_entry_username.then_some(user_display_name.clone()),
                            password: None,
                            url: None,
                            notes: None,
                        },
                    )?;
                }
                touch_entry_modified_at(&self.core, vault, &entry_id, modified_at)?;
                enforce_history_limits(vault);
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = mutation {
                return match self.restore_passkey_registration_rollback(rollback) {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(error).context(format!(
                        "failed to roll back platform passkey mutation: {rollback_error:#}"
                    )),
                };
            }
            (entry_id, rollback)
        } else {
            let mut entry = Entry::new(relying_party_name.clone());
            entry.username = user_display_name.clone();
            entry.password = String::new();
            entry.url = format!("https://{}", input.relying_party);
            entry.notes = "Created by system passkey provider".into();
            let entry_id = entry.id.to_string();
            let rollback = PasskeyRegistrationRollbackState {
                vault_id: vault_id.clone(),
                entry_id: entry_id.clone(),
                credential_id: Some(registration.passkey.credential_id.clone()),
                created: true,
                rollback_entry: None,
            };
            let mutation = (|| {
                let loaded = self
                    .vault_session
                    .find_loaded_mut(&vault_id)
                    .with_context(|| format!("vault not opened: {vault_id}"))?;
                let vault = loaded
                    .vault
                    .as_mut()
                    .with_context(|| format!("vault is locked: {vault_id}"))?;
                vault.root.entries.push(entry);
                self.core
                    .set_entry_passkey(vault, &entry_id, registration.passkey)?;
                set_platform_passkey_display_labels(
                    &self.core,
                    vault,
                    &entry_id,
                    &relying_party_name,
                    &user_display_name,
                )?;
                initialize_entry_creation_times(&self.core, vault, &entry_id, modified_at)?;
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = mutation {
                return match self.restore_passkey_registration_rollback(rollback) {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(error).context(format!(
                        "failed to roll back platform passkey mutation: {rollback_error:#}"
                    )),
                };
            }
            (entry_id, rollback)
        };

        Ok((
            PlatformPasskeyRegistrationOutput {
                entry_id,
                credential,
                authenticator_data: registration.authenticator_data,
            },
            rollback,
        ))
    }

    fn commit_platform_passkey_registration(
        &mut self,
        rollback: PasskeyRegistrationRollbackState,
    ) -> Result<()> {
        let vault_id = rollback.vault_id.clone();
        let mut save_error = match self.commit_working_copy(&vault_id) {
            Ok(RuntimeResponse::PublicationResult(result))
                if result.status != PublicationStatusDto::ConflictSplit =>
            {
                None
            }
            Ok(RuntimeResponse::PublicationResult(result)) => Some(anyhow::anyhow!(
                "platform passkey registration was saved only to conflict copy: {}",
                result.conflict_copy_path.as_deref().unwrap_or("unknown")
            )),
            Ok(response) => Some(anyhow::anyhow!(
                "platform passkey registration received an unexpected save response: {response:?}"
            )),
            Err(error) => Some(error),
        };
        if save_error.is_none()
            && let Some(credential_id) = rollback.credential_id.as_deref()
            && self.loaded_vault(&vault_id).ok().and_then(|vault| {
                entry_has_passkey_credential(&vault.root, &rollback.entry_id, credential_id)
            }) != Some(true)
        {
            save_error = Some(anyhow::anyhow!(
                "platform passkey registration was not retained by the committed vault generation"
            ));
        }
        if let Some(save_error) = save_error {
            return match self.restore_passkey_registration_rollback(rollback) {
                Ok(()) => Err(save_error),
                Err(rollback_error) => Err(save_error).context(format!(
                    "failed to roll back platform passkey registration: {rollback_error:#}"
                )),
            };
        }
        Ok(())
    }

    pub fn create_platform_passkey_assertion(
        &self,
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput> {
        let vault_id = self.active_platform_passkey_vault_id()?;
        let vault = self.loaded_vault(&vault_id)?;
        let allowed_credential_ids = input
            .allowed_credential_ids
            .iter()
            .map(|credential_id| URL_SAFE_NO_PAD.encode(credential_id))
            .collect::<std::collections::BTreeSet<_>>();
        let mut matches = Vec::new();
        visit_passkeys(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &mut |passkey| {
                if passkey.relying_party == input.relying_party
                    && (allowed_credential_ids.is_empty()
                        || allowed_credential_ids.contains(&passkey.credential_id))
                {
                    matches.push(passkey);
                }
            },
        );
        let selected = matches
            .first()
            .copied()
            .context("platform passkey credential not found")?;
        let passkey = find_unique_passkey_by_credential_id_and_relying_party(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &selected.credential_id,
            Some(&input.relying_party),
        )?;
        let credential_id = URL_SAFE_NO_PAD
            .decode(&passkey.credential_id)
            .context("stored platform passkey credential id was not base64url")?;
        let assertion = create_platform_assertion(
            passkey,
            PlatformPasskeyAssertionRequest {
                relying_party: &input.relying_party,
                credential_id: &credential_id,
                client_data_hash: &input.client_data_hash,
                user_verified: input.user_verified,
            },
        )?;
        Ok(PlatformPasskeyAssertionOutput {
            credential_id: assertion.credential_id,
            authenticator_data: assertion.authenticator_data,
            signature_der: assertion.signature_der,
            user_handle: assertion
                .user_handle
                .context("platform passkey credential has no discoverable user handle")?,
        })
    }

    fn active_platform_passkey_vault_id(&self) -> Result<String> {
        let vault_id = self
            .vault_session
            .active_vault_id()
            .context("platform passkey operation requires an active unlocked vault")?;
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .context("platform passkey operation requires an active unlocked vault")?;
        if loaded.vault.is_none() {
            anyhow::bail!("platform passkey operation requires an active unlocked vault");
        }
        Ok(vault_id.to_owned())
    }

    pub fn create_passkey_assertion(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        relying_party: &str,
        origin: &str,
        credential_id: Option<&str>,
        discoverable: bool,
        user_presence_verified: bool,
        related_origin_verified: bool,
        client_data_json_base64url: &str,
    ) -> Result<PasskeyAssertionDto> {
        let client_data_expectations = self.validate_passkey_ceremony_for_s4(
            ceremony_token,
            expected_phase,
            PasskeyCeremonyKindDto::Get,
            vault_id,
            origin,
            relying_party,
            Some(discoverable),
            client_data_json_base64url,
        )?;
        let credential_id = credential_id.context("passkey assertion credential id is required")?;
        self.validate_passkey_user_presence_before_vault_lookup(
            ceremony_token,
            vault_id,
            user_presence_verified,
        )?;
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
        {
            let vault = self.loaded_vault(vault_id)?;
            find_unique_passkey_by_credential_id_and_relying_party(
                &vault.root,
                vault.recycle_bin_group,
                vault.recycle_bin_enabled.unwrap_or(true),
                credential_id,
                Some(relying_party),
            )?;
        }
        let user_verified =
            self.consume_passkey_ceremony_user_verification(ceremony_token, vault_id)?;
        let effective_user_presence_verified = user_presence_verified || user_verified;
        if !effective_user_presence_verified {
            anyhow::bail!("passkey user presence was not verified");
        }
        let vault = self.loaded_vault(vault_id)?;
        let passkey = find_unique_passkey_by_credential_id_and_relying_party(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            credential_id,
            Some(relying_party),
        )?;
        create_assertion(
            passkey,
            PasskeyAssertionRequest {
                relying_party,
                origin,
                credential_id: Some(credential_id),
                discoverable,
                user_presence_verified: effective_user_presence_verified,
                user_verified,
                related_origin_verified,
                client_data_json_base64url,
                challenge_base64url: &client_data_expectations.challenge_base64url,
                top_origin: client_data_expectations.top_origin.as_deref(),
                ancestor_origins: &client_data_expectations.ancestor_origins,
            },
        )
    }

    fn validate_passkey_ceremony_for_s4(
        &self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        expected_ceremony: PasskeyCeremonyKindDto,
        vault_id: &str,
        origin: &str,
        relying_party: &str,
        discoverable: Option<bool>,
        client_data_json_base64url: &str,
    ) -> Result<PasskeyClientDataExpectations> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.identity.ceremony != expected_ceremony {
            anyhow::bail!("passkey ceremony type mismatch");
        }
        if entry.identity.origin != origin {
            anyhow::bail!("passkey ceremony origin mismatch");
        }
        if entry.identity.relying_party != relying_party {
            anyhow::bail!("passkey ceremony relying party mismatch");
        }
        if let Some(discoverable) = discoverable {
            if entry.identity.discoverable != discoverable {
                anyhow::bail!("passkey ceremony discoverable mismatch");
            }
        }
        validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
        validate_passkey_ceremony_vault_binding(entry, vault_id)?;
        validate_passkey_ceremony_client_data(
            client_data_json_base64url,
            expected_ceremony,
            origin,
            &entry.identity.challenge_base64url,
            entry.identity.top_origin.as_deref(),
            &entry.identity.ancestor_origins,
        )?;
        Ok(PasskeyClientDataExpectations {
            challenge_base64url: entry.identity.challenge_base64url.clone(),
            top_origin: entry.identity.top_origin.clone(),
            ancestor_origins: entry.identity.ancestor_origins.clone(),
        })
    }

    fn consume_passkey_ceremony_user_verification(
        &mut self,
        ceremony_token: &str,
        vault_id: &str,
    ) -> Result<bool> {
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        let verified = passkey_user_verification_is_valid(entry, vault_id, now_epoch_ms);
        entry.user_verification = None;
        if entry.identity.user_verification == PasskeyUserVerificationRequirementDto::Required
            && !verified
        {
            anyhow::bail!("passkey user verification was not verified");
        }
        Ok(verified)
    }

    fn validate_passkey_user_presence_before_vault_lookup(
        &self,
        ceremony_token: &str,
        vault_id: &str,
        user_presence_verified: bool,
    ) -> Result<()> {
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        let user_verified = passkey_user_verification_is_valid(entry, vault_id, now_epoch_ms);
        if entry.identity.user_verification == PasskeyUserVerificationRequirementDto::Required
            && !user_verified
        {
            anyhow::bail!("passkey user verification was not verified");
        }
        if !user_presence_verified && !user_verified {
            anyhow::bail!("passkey user presence was not verified");
        }
        Ok(())
    }

    pub fn passkey_credential_status(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        credential_id: &str,
        relying_party: &str,
    ) -> Result<PasskeyCredentialStatusDto> {
        let batch = self.passkey_credential_status_batch(
            ceremony_token,
            expected_phase,
            vault_id,
            &[credential_id.to_owned()],
            relying_party,
        )?;
        batch
            .statuses
            .into_iter()
            .next()
            .context("passkey credential status batch returned no status")
    }

    pub fn passkey_credential_status_batch(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        credential_ids: &[String],
        relying_party: &str,
    ) -> Result<PasskeyCredentialStatusBatchDto> {
        self.validate_passkey_ceremony_for_s3_read(
            ceremony_token,
            expected_phase,
            PasskeyCeremonyKindDto::Create,
            vault_id,
            relying_party,
        )?;
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
        let vault = self.loaded_vault(vault_id)?;
        let statuses = credential_ids
            .iter()
            .map(|credential_id| PasskeyCredentialStatusDto {
                credential_id: credential_id.to_owned(),
                exists: find_passkey_by_credential_id_and_relying_party(
                    &vault.root,
                    vault.recycle_bin_group,
                    vault.recycle_bin_enabled.unwrap_or(true),
                    credential_id,
                    Some(relying_party),
                )
                .is_some(),
            })
            .collect();

        Ok(PasskeyCredentialStatusBatchDto { statuses })
    }

    pub fn list_passkey_credentials(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        relying_party: &str,
    ) -> Result<PasskeyCredentialListDto> {
        self.validate_passkey_ceremony_for_s3_read(
            ceremony_token,
            expected_phase,
            PasskeyCeremonyKindDto::Get,
            vault_id,
            relying_party,
        )?;
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
        let vault = self.loaded_vault(vault_id)?;
        let mut candidates = Vec::new();
        let mut credential_counts = BTreeMap::<String, usize>::new();
        visit_passkeys(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &mut |passkey| {
                if passkey.relying_party == relying_party {
                    *credential_counts
                        .entry(passkey.credential_id.clone())
                        .or_insert(0) += 1;
                    candidates.push(PasskeyCredentialCandidateDto {
                        credential_id: passkey.credential_id.clone(),
                        username: passkey.username.clone(),
                        user_handle: passkey.user_handle.clone(),
                    });
                }
            },
        );
        let credentials = candidates
            .into_iter()
            .filter(|candidate| credential_counts[&candidate.credential_id] == 1)
            .collect();

        Ok(PasskeyCredentialListDto { credentials })
    }

    fn validate_passkey_ceremony_for_s3_read(
        &self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        expected_ceremony: PasskeyCeremonyKindDto,
        vault_id: &str,
        relying_party: &str,
    ) -> Result<()> {
        validate_passkey_relying_party_id(relying_party)?;
        if expected_phase != PasskeyCeremonyPhaseDto::CredentialResolution {
            anyhow::bail!("passkey ceremony expected phase must be s3_credential_resolution");
        }
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.identity.ceremony != expected_ceremony {
            anyhow::bail!("passkey ceremony type mismatch");
        }
        if entry.identity.relying_party != relying_party {
            anyhow::bail!("passkey ceremony relying party mismatch");
        }
        validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
        validate_passkey_ceremony_vault_binding(entry, vault_id)?;
        Ok(())
    }

    pub(crate) fn register_passkey_ceremony(
        &mut self,
        ceremony_token: &str,
        identity: PasskeyCeremonyIdentity,
    ) -> Result<PasskeyCeremonyRegisteredDto> {
        let now_epoch_ms = self.current_unix_time_ms();
        self.prune_expired_passkey_ceremonies(now_epoch_ms);
        validate_passkey_ceremony_ttl(
            identity.registered_at_epoch_ms,
            identity.expires_at_epoch_ms,
            now_epoch_ms,
        )?;
        validate_passkey_ceremony_connection_id(&identity.connection_id)?;
        validate_passkey_ceremony_challenge(&identity.challenge_base64url)?;
        validate_passkey_ceremony_origin_and_relying_party_for_s0(
            &identity.origin,
            &identity.relying_party,
        )?;
        if let Some(top_origin) = identity.top_origin.as_deref() {
            validate_passkey_ceremony_origin_value(top_origin, "top")?;
        }
        for ancestor_origin in &identity.ancestor_origins {
            validate_passkey_ceremony_origin_value(ancestor_origin, "ancestor")?;
        }
        if identity.tab_id < 0 || identity.frame_id < 0 {
            anyhow::bail!("passkey ceremony frame position is invalid");
        }
        let expected_frame_kind = if identity.frame_id == 0 {
            PasskeyFrameKindDto::Top
        } else {
            PasskeyFrameKindDto::Subframe
        };
        if identity.frame_kind != expected_frame_kind {
            anyhow::bail!("passkey ceremony frame kind mismatch");
        }
        if identity.frame_kind == PasskeyFrameKindDto::Top
            && (identity.top_origin.is_some() || !identity.ancestor_origins.is_empty())
        {
            anyhow::bail!("passkey ceremony top frame cannot have ancestor origins");
        }
        if !identity.ancestor_origins.is_empty() && identity.top_origin.is_none() {
            anyhow::bail!("passkey ceremony top origin is required when ancestors are present");
        }
        if let (Some(top_origin), Some(last_ancestor)) =
            (&identity.top_origin, identity.ancestor_origins.last())
        {
            if !passkey_ceremony_origins_are_same_origin(top_origin, last_ancestor) {
                anyhow::bail!("passkey ceremony top origin must match the last ancestor");
            }
        }
        if identity.frame_kind == PasskeyFrameKindDto::Subframe
            && (identity.top_origin.is_none() || identity.ancestor_origins.is_empty())
        {
            anyhow::bail!("passkey ceremony subframe top origin is required");
        }

        if let Some(existing) = self.passkey_ceremonies.get(ceremony_token) {
            if existing.identity == identity {
                return Ok(PasskeyCeremonyRegisteredDto { registered: true });
            }
            anyhow::bail!("passkey ceremony token already registered");
        }
        if self.passkey_ceremonies.values().any(|existing| {
            !is_closed_passkey_ceremony_phase(existing.phase)
                && existing.identity.expires_at_epoch_ms > identity.registered_at_epoch_ms
                && existing.identity.origin == identity.origin
                && existing.identity.relying_party == identity.relying_party
                && existing.identity.tab_id == identity.tab_id
                && existing.identity.frame_id == identity.frame_id
        }) {
            anyhow::bail!(
                "passkey ceremony already active for origin, relying party, tab, and frame"
            );
        }

        self.passkey_ceremonies.insert(
            ceremony_token.to_owned(),
            PasskeyCeremonyLedgerEntry {
                identity,
                phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                vault_id: None,
                durable_state: PasskeyCeremonyDurableStateDto::None,
                delivery_state: PasskeyCeremonyDeliveryStateDto::NotDelivered,
                user_verification: None,
                registration_rollback: None,
            },
        );
        Ok(PasskeyCeremonyRegisteredDto { registered: true })
    }

    pub(crate) fn advance_passkey_ceremony_phase(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        next_phase: PasskeyCeremonyPhaseDto,
        related_origin_verified: bool,
    ) -> Result<PasskeyCeremonyAdvancedDto> {
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            if is_stale_passkey_phase_advance_noop(entry.phase, expected_phase, next_phase) {
                return Ok(PasskeyCeremonyAdvancedDto { advanced: true });
            }
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if expected_phase == PasskeyCeremonyPhaseDto::NetworkValidation
            && next_phase == PasskeyCeremonyPhaseDto::CredentialResolution
            && !related_origin_verified
        {
            anyhow::bail!("passkey ceremony related origin evidence is required");
        }
        if !is_legal_passkey_ceremony_transition(
            expected_phase,
            next_phase,
            &entry.identity,
            related_origin_verified,
        ) {
            anyhow::bail!("illegal passkey ceremony phase transition");
        }
        if next_phase == PasskeyCeremonyPhaseDto::ClosedDelivered
            && entry.identity.ceremony == PasskeyCeremonyKindDto::Create
            && entry.durable_state != PasskeyCeremonyDurableStateDto::Committed
        {
            anyhow::bail!("passkey ceremony must be committed before delivery");
        }
        if !is_closed_passkey_ceremony_phase(next_phase) {
            validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
        }
        entry.phase = next_phase;
        if next_phase == PasskeyCeremonyPhaseDto::ClosedDelivered {
            entry.delivery_state = PasskeyCeremonyDeliveryStateDto::Delivered;
        }
        Ok(PasskeyCeremonyAdvancedDto { advanced: true })
    }

    pub(crate) fn bind_passkey_ceremony_vault(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
    ) -> Result<PasskeyCeremonyVaultBoundDto> {
        let now_epoch_ms = self.current_unix_time_ms();
        {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if !is_passkey_ceremony_vault_binding_phase(expected_phase)
                || entry.phase != expected_phase
                || is_closed_passkey_ceremony_phase(entry.phase)
            {
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
            validate_passkey_ceremony_vault_binding(entry, vault_id)?;
        }
        let _ = self.loaded_vault(vault_id)?;
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .expect("passkey ceremony was checked before vault lookup");
        bind_passkey_ceremony_vault(entry, vault_id)?;
        Ok(PasskeyCeremonyVaultBoundDto { bound: true })
    }

    fn bind_passkey_ceremony_vault_after_vault_lookup(
        &mut self,
        ceremony_token: &str,
        vault_id: &str,
    ) -> Result<()> {
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        bind_passkey_ceremony_vault(entry, vault_id)
    }

    pub(crate) fn query_passkey_ceremony_ledger(
        &self,
        ceremony_token: &str,
    ) -> PasskeyCeremonyLedgerDto {
        match self.passkey_ceremonies.get(ceremony_token) {
            Some(entry) => PasskeyCeremonyLedgerDto {
                known: true,
                phase: Some(entry.phase),
                durable_state: Some(entry.durable_state),
                delivery_state: Some(entry.delivery_state),
            },
            None => PasskeyCeremonyLedgerDto {
                known: false,
                phase: None,
                durable_state: None,
                delivery_state: None,
            },
        }
    }

    pub(crate) fn reconcile_passkey_ceremony_ledger(
        &mut self,
        active_connection_id: &str,
    ) -> Result<PasskeyCeremonyReconciliationDto> {
        validate_passkey_ceremony_connection_id(active_connection_id)?;
        let now_epoch_ms = self.current_unix_time_ms();
        let mut reconciled = Vec::new();
        let mut rollback_tokens = Vec::new();
        for (ceremony_token, entry) in &mut self.passkey_ceremonies {
            if entry.phase != PasskeyCeremonyPhaseDto::CompletionAndMutation
                || entry.delivery_state != PasskeyCeremonyDeliveryStateDto::NotDelivered
                || (entry.identity.connection_id == active_connection_id
                    && entry.identity.expires_at_epoch_ms > now_epoch_ms)
            {
                continue;
            }

            if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
                entry.phase = PasskeyCeremonyPhaseDto::ClosedDelivered;
                entry.delivery_state = PasskeyCeremonyDeliveryStateDto::UnknownDelivery;
                reconciled.push(PasskeyCeremonyReconciledDto {
                    ceremony_token: ceremony_token.clone(),
                    delivery_state: PasskeyCeremonyDeliveryStateDto::UnknownDelivery,
                });
                continue;
            }

            if entry.identity.ceremony == PasskeyCeremonyKindDto::Create
                && matches!(
                    entry.durable_state,
                    PasskeyCeremonyDurableStateDto::Snapshot
                        | PasskeyCeremonyDurableStateDto::Mutated
                        | PasskeyCeremonyDurableStateDto::Saved
                )
            {
                rollback_tokens.push(ceremony_token.clone());
            }
        }

        for ceremony_token in rollback_tokens {
            if self
                .abort_passkey_registration(
                    &ceremony_token,
                    PasskeyCeremonyPhaseDto::CompletionAndMutation,
                    PasskeyCeremonyPhaseDto::ClosedFailed,
                )
                .is_err()
            {
                continue;
            }
            reconciled.push(PasskeyCeremonyReconciledDto {
                ceremony_token,
                delivery_state: PasskeyCeremonyDeliveryStateDto::NotDelivered,
            });
        }

        Ok(PasskeyCeremonyReconciliationDto { reconciled })
    }

    fn prune_expired_passkey_ceremonies(&mut self, now_epoch_ms: u64) {
        self.passkey_ceremonies.retain(|_, entry| {
            if entry.identity.expires_at_epoch_ms > now_epoch_ms {
                return true;
            }
            entry.phase == PasskeyCeremonyPhaseDto::CompletionAndMutation
                && entry.identity.ceremony == PasskeyCeremonyKindDto::Create
                && entry.durable_state != PasskeyCeremonyDurableStateDto::None
        });
    }

    pub(crate) fn mark_passkey_ceremony_unknown_delivery(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
    ) -> Result<PasskeyCeremonyAdvancedDto> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase == PasskeyCeremonyPhaseDto::ClosedDelivered
            && entry.delivery_state == PasskeyCeremonyDeliveryStateDto::UnknownDelivery
        {
            return Ok(PasskeyCeremonyAdvancedDto { advanced: true });
        }
        if entry.phase != expected_phase {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        match entry.identity.ceremony {
            PasskeyCeremonyKindDto::Create => {
                if entry.durable_state != PasskeyCeremonyDurableStateDto::Committed {
                    anyhow::bail!("passkey ceremony is not committed");
                }
            }
            PasskeyCeremonyKindDto::Get => {
                if entry.durable_state != PasskeyCeremonyDurableStateDto::None {
                    anyhow::bail!("passkey get ceremony cannot have durable state");
                }
            }
        }

        entry.phase = PasskeyCeremonyPhaseDto::ClosedDelivered;
        entry.delivery_state = PasskeyCeremonyDeliveryStateDto::UnknownDelivery;
        Ok(PasskeyCeremonyAdvancedDto { advanced: true })
    }

    fn set_passkey_registration_rollback(
        &mut self,
        ceremony_token: &str,
        rollback: PasskeyRegistrationRollbackState,
        durable_state: PasskeyCeremonyDurableStateDto,
    ) -> Result<()> {
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.identity.ceremony != PasskeyCeremonyKindDto::Create {
            anyhow::bail!("passkey ceremony type mismatch");
        }
        if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
            anyhow::bail!("passkey ceremony already committed");
        }
        entry.registration_rollback = Some(rollback);
        entry.durable_state = durable_state;
        Ok(())
    }

    fn set_passkey_ceremony_durable_state(
        &mut self,
        ceremony_token: &str,
        durable_state: PasskeyCeremonyDurableStateDto,
    ) -> Result<()> {
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.identity.ceremony != PasskeyCeremonyKindDto::Create {
            anyhow::bail!("passkey ceremony type mismatch");
        }
        if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
            anyhow::bail!("passkey ceremony already committed");
        }
        entry.durable_state = durable_state;
        Ok(())
    }

    pub fn create_passkey_registration(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        relying_party: &str,
        origin: &str,
        user_name: &str,
        user_display_name: Option<&str>,
        user_handle_base64url: &str,
        public_key_algorithm: i32,
        related_origin_verified: bool,
        client_data_json_base64url: &str,
    ) -> Result<PasskeyRegistrationDto> {
        let client_data_expectations = self.validate_passkey_ceremony_for_s4(
            ceremony_token,
            expected_phase,
            PasskeyCeremonyKindDto::Create,
            vault_id,
            origin,
            relying_party,
            None,
            client_data_json_base64url,
        )?;
        validate_passkey_registration_parameters(user_handle_base64url, public_key_algorithm)?;
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
        let user_verified =
            self.consume_passkey_ceremony_user_verification(ceremony_token, vault_id)?;
        let modified_at = self.current_unix_time();
        let credential_id = (self.passkey_credential_id_generator)();
        let registration = create_registration_with_credential_id(
            PasskeyRegistrationRequest {
                relying_party,
                origin,
                user_name,
                user_handle_base64url,
                public_key_algorithm,
                user_verified,
                related_origin_verified,
                client_data_json_base64url,
                challenge_base64url: &client_data_expectations.challenge_base64url,
                top_origin: client_data_expectations.top_origin.as_deref(),
                ancestor_origins: &client_data_expectations.ancestor_origins,
            },
            credential_id,
        )?;
        let mut response = registration.dto;

        let (existing, credential_id_collision_count) = {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            let existing = find_passkey_entry_id_by_relying_party_and_user_handle(
                &vault.root,
                vault.recycle_bin_group,
                vault.recycle_bin_enabled.unwrap_or(true),
                relying_party,
                registration.passkey.user_handle.as_deref(),
            )
            .map(|entry_id| {
                let rollback_entry = cloned_entry_by_id(&vault.root, &entry_id)
                    .with_context(|| format!("entry not found: {entry_id}"))?;
                Ok::<_, anyhow::Error>((entry_id, rollback_entry))
            })
            .transpose()?;
            let mut credential_id_collision_count = 0;
            visit_passkeys(
                &vault.root,
                vault.recycle_bin_group,
                vault.recycle_bin_enabled.unwrap_or(true),
                &mut |passkey| {
                    if passkey.credential_id == registration.passkey.credential_id {
                        credential_id_collision_count += 1;
                    }
                },
            );
            (existing, credential_id_collision_count)
        };
        let allowed_existing_collision = existing
            .as_ref()
            .and_then(|(_, rollback_entry)| rollback_entry.passkey.as_ref())
            .is_some_and(|passkey| passkey.credential_id == registration.passkey.credential_id);
        let allowed_collision_count = if allowed_existing_collision { 1 } else { 0 };
        if credential_id_collision_count > allowed_collision_count {
            anyhow::bail!("passkey credential id collision");
        }
        if let Some((entry_id, rollback_entry)) = existing {
            let refresh_entry_username = rollback_entry
                .passkey
                .as_ref()
                .is_some_and(|passkey| rollback_entry.username == passkey.username);
            let next_passkey_username = registration.passkey.username.clone();
            self.set_passkey_registration_rollback(
                ceremony_token,
                PasskeyRegistrationRollbackState {
                    vault_id: vault_id.to_owned(),
                    entry_id: entry_id.clone(),
                    credential_id: Some(registration.passkey.credential_id.clone()),
                    created: false,
                    rollback_entry: Some(rollback_entry),
                },
                PasskeyCeremonyDurableStateDto::Snapshot,
            )?;
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.snapshot_entry_to_history(vault, &entry_id)?;
            self.core
                .set_entry_passkey(vault, &entry_id, registration.passkey)?;
            if refresh_entry_username {
                self.core.update_entry_fields(
                    vault,
                    &entry_id,
                    EntryUpdate {
                        title: None,
                        username: Some(next_passkey_username),
                        password: None,
                        url: None,
                        notes: None,
                    },
                )?;
            }
            touch_entry_modified_at(&self.core, vault, &entry_id, modified_at)?;
            enforce_history_limits(vault);
            response.entry_id = entry_id;
            response.created = false;
            self.set_passkey_ceremony_durable_state(
                ceremony_token,
                PasskeyCeremonyDurableStateDto::Mutated,
            )?;
            return Ok(response);
        }
        let title = if relying_party.trim().is_empty() {
            user_display_name
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(user_name)
                .to_owned()
        } else {
            relying_party.to_owned()
        };
        let mut created_entry = Entry::new(title);
        created_entry.username = user_name.to_owned();
        created_entry.password = String::new();
        created_entry.url = format!("https://{relying_party}");
        created_entry.notes = "Created by WebAuthn passkey registration".into();
        let entry_id = created_entry.id.to_string();
        self.set_passkey_registration_rollback(
            ceremony_token,
            PasskeyRegistrationRollbackState {
                vault_id: vault_id.to_owned(),
                entry_id: entry_id.clone(),
                credential_id: Some(registration.passkey.credential_id.clone()),
                created: true,
                rollback_entry: None,
            },
            PasskeyCeremonyDurableStateDto::Snapshot,
        )?;
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            vault.root.entries.push(created_entry);
            self.core
                .set_entry_passkey(vault, &entry_id, registration.passkey)?;
            initialize_entry_creation_times(&self.core, vault, &entry_id, modified_at)?;
        }
        self.set_passkey_ceremony_durable_state(
            ceremony_token,
            PasskeyCeremonyDurableStateDto::Mutated,
        )?;
        response.entry_id = entry_id;
        Ok(response)
    }

    pub fn abort_passkey_registration(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        closed_phase: PasskeyCeremonyPhaseDto,
    ) -> Result<()> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        if !matches!(
            closed_phase,
            PasskeyCeremonyPhaseDto::ClosedAborted | PasskeyCeremonyPhaseDto::ClosedFailed
        ) {
            anyhow::bail!("passkey ceremony rollback must close aborted or failed");
        }
        let (rollback, save_after_rollback) = {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if entry.phase != expected_phase {
                if entry.identity.ceremony == PasskeyCeremonyKindDto::Create
                    && is_closed_passkey_ceremony_phase(entry.phase)
                {
                    return Ok(());
                }
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            if entry.identity.ceremony != PasskeyCeremonyKindDto::Create {
                anyhow::bail!("passkey ceremony type mismatch");
            }
            if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
                anyhow::bail!("passkey ceremony already committed");
            }
            (
                entry.registration_rollback.clone(),
                entry.durable_state == PasskeyCeremonyDurableStateDto::Saved,
            )
        };

        if let Some(rollback) = rollback {
            let vault_id = rollback.vault_id.clone();
            self.restore_passkey_registration_rollback(rollback)?;
            if save_after_rollback {
                let response = self.commit_working_copy(&vault_id)?;
                ensure_primary_passkey_save(&response)?;
            }
        }
        self.close_passkey_registration_rollback(ceremony_token, closed_phase)?;
        Ok(())
    }

    pub fn save_passkey_registration(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
    ) -> Result<RuntimeResponse> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        let now_epoch_ms = self.current_unix_time_ms();
        {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if entry.phase != expected_phase {
                if entry.identity.ceremony == PasskeyCeremonyKindDto::Create
                    && is_closed_passkey_ceremony_phase(entry.phase)
                {
                    return Ok(RuntimeResponse::Saved);
                }
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            if entry.identity.ceremony != PasskeyCeremonyKindDto::Create {
                anyhow::bail!("passkey ceremony type mismatch");
            }
            validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
            if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
                anyhow::bail!("passkey ceremony already committed");
            }
            let Some(rollback) = entry.registration_rollback.as_ref() else {
                anyhow::bail!("passkey registration rollback state missing");
            };
            if rollback.vault_id != vault_id {
                anyhow::bail!("passkey ceremony vault mismatch");
            }
        }

        let response = self.commit_working_copy(vault_id)?;
        ensure_primary_passkey_save(&response)?;
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
            anyhow::bail!("passkey ceremony already committed");
        }
        entry.durable_state = PasskeyCeremonyDurableStateDto::Saved;
        Ok(response)
    }

    fn restore_passkey_registration_rollback(
        &mut self,
        rollback: PasskeyRegistrationRollbackState,
    ) -> Result<()> {
        let loaded = self
            .vault_session
            .find_loaded_mut(&rollback.vault_id)
            .with_context(|| format!("vault not opened: {}", rollback.vault_id))?;
        let vault = loaded
            .vault
            .as_mut()
            .with_context(|| format!("vault is locked: {}", rollback.vault_id))?;

        if rollback.created {
            if let Some(credential_id) = rollback.credential_id.as_deref() {
                match entry_has_passkey_credential(&vault.root, &rollback.entry_id, credential_id) {
                    Some(true) => {}
                    Some(false) => return Ok(()),
                    None => return Ok(()),
                }
            }
            self.core.delete_entry(vault, &rollback.entry_id)?;
            return Ok(());
        }

        if let Some(rollback_entry) = rollback.rollback_entry {
            if restore_entry_from_snapshot(
                &mut vault.root,
                &rollback.entry_id,
                rollback.credential_id.as_deref(),
                rollback_entry,
            )? {
                return Ok(());
            }
            anyhow::bail!("entry not found: {}", rollback.entry_id);
        }

        if rollback.credential_id.is_some() {
            return Ok(());
        }

        if !restore_entry_from_latest_history(
            &mut vault.root,
            &rollback.entry_id,
            rollback.credential_id.as_deref(),
        )? {
            anyhow::bail!("entry not found: {}", rollback.entry_id);
        }
        Ok(())
    }

    fn close_passkey_registration_rollback(
        &mut self,
        ceremony_token: &str,
        closed_phase: PasskeyCeremonyPhaseDto,
    ) -> Result<()> {
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        entry.phase = closed_phase;
        entry.durable_state = PasskeyCeremonyDurableStateDto::None;
        entry.registration_rollback = None;
        Ok(())
    }

    pub fn commit_passkey_registration(
        &mut self,
        ceremony_token: &str,
        expected_phase: PasskeyCeremonyPhaseDto,
        vault_id: &str,
        entry_id: &str,
        credential_id: &str,
    ) -> Result<()> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        if entry.phase != expected_phase {
            if entry.identity.ceremony == PasskeyCeremonyKindDto::Create
                && is_closed_passkey_ceremony_phase(entry.phase)
            {
                return Ok(());
            }
            anyhow::bail!("passkey ceremony phase mismatch");
        }
        if entry.identity.ceremony != PasskeyCeremonyKindDto::Create {
            anyhow::bail!("passkey ceremony type mismatch");
        }
        if entry.durable_state == PasskeyCeremonyDurableStateDto::Committed {
            return Ok(());
        }
        validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
        let Some(rollback) = entry.registration_rollback.as_ref() else {
            anyhow::bail!("passkey registration rollback state missing");
        };
        if rollback.vault_id != vault_id
            || rollback.entry_id != entry_id
            || rollback.credential_id.as_deref() != Some(credential_id)
        {
            anyhow::bail!("passkey registration rollback identity mismatch");
        }
        if entry.durable_state != PasskeyCeremonyDurableStateDto::Saved {
            anyhow::bail!("passkey ceremony must be saved before commit");
        }
        entry.durable_state = PasskeyCeremonyDurableStateDto::Committed;
        entry.registration_rollback = None;
        Ok(())
    }

    pub fn delete_entry(&mut self, vault_id: &str, entry_id: &str) -> Result<()> {
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let vault = loaded
            .vault
            .as_mut()
            .with_context(|| format!("vault is locked: {vault_id}"))?;
        self.core.delete_entry(vault, entry_id)?;
        Ok(())
    }

    pub fn get_entry_attachment_content(
        &self,
        vault_id: &str,
        entry_id: &str,
        name: &str,
    ) -> Result<EntryAttachmentContentDto> {
        let vault = self.loaded_vault(vault_id)?;
        let content = self
            .core
            .project_entry_attachment_content(vault, entry_id, name)?;
        let protect_in_memory = self
            .core
            .list_entry_attachments(vault, entry_id)?
            .into_iter()
            .find(|attachment| attachment.name == content.name)
            .map(|attachment| attachment.protect_in_memory)
            .unwrap_or(false);

        Ok(EntryAttachmentContentDto {
            name: content.name,
            data_base64: BASE64_STANDARD.encode(content.data).into(),
            protect_in_memory,
        })
    }

    pub fn add_entry_attachment(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        name: String,
        data_base64: SensitiveString,
        protect_in_memory: bool,
    ) -> Result<EntryDetailDto> {
        let data = decode_base64(&data_base64)?;
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.add_entry_attachment(
                vault,
                entry_id,
                EntryAttachmentInput {
                    name,
                    data,
                    protect_in_memory,
                },
            )?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn update_entry_attachment_metadata(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        old_name: &str,
        new_name: String,
        protect_in_memory: bool,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.update_entry_attachment_metadata(
                vault,
                entry_id,
                old_name,
                AttachmentMetadataUpdate {
                    new_name: Some(new_name),
                    protect_in_memory: Some(protect_in_memory),
                },
            )?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn replace_entry_attachment_content(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        name: &str,
        data_base64: SensitiveString,
    ) -> Result<EntryDetailDto> {
        let data = decode_base64(&data_base64)?;
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.replace_entry_attachment_content(
                vault,
                entry_id,
                name,
                AttachmentContentUpdate { data },
            )?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub fn delete_entry_attachment(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        name: &str,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.delete_entry_attachment(vault, entry_id, name)?;
            touch_entry_modified_at(&self.core, vault, entry_id, modified_at)?;
        }

        self.get_entry_detail(vault_id, entry_id)
    }

    pub(crate) fn begin_protocol_command(&mut self) {
        self.pending_quick_unlock_enrollment = None;
    }

    pub(crate) fn pick_local_file(&self) -> Result<Option<String>> {
        self.providers.pick_local_file()
    }

    pub(crate) fn begin_one_drive_login(
        &mut self,
    ) -> Result<vaultkern_runtime_protocol::OneDriveAuthSessionDto> {
        self.providers.begin_login()
    }

    pub(crate) fn complete_pending_one_drive_login(
        &mut self,
    ) -> Result<vaultkern_runtime_protocol::OneDriveAuthStatusDto> {
        self.providers.complete_pending_login()
    }

    pub(crate) fn list_one_drive_children(
        &self,
        parent_item_id: Option<&str>,
    ) -> Result<vaultkern_runtime_protocol::OneDriveItemListDto> {
        self.providers.list_children(parent_item_id)
    }

    pub(crate) fn clear_quick_unlock_handoff(&mut self) {
        self.pending_quick_unlock_enrollment = None;
    }

    pub(crate) fn finish_protocol_command(&mut self) {
        self.pending_quick_unlock_enrollment = None;
    }

    pub(crate) fn take_quick_unlock_handoff(
        &mut self,
    ) -> Option<QuickUnlockReconciliationCredentials> {
        self.pending_quick_unlock_enrollment
            .take()
            .map(|pending| pending.credentials)
    }

    #[cfg(test)]
    fn handle(&mut self, command: RuntimeCommand) -> Result<RuntimeResponse> {
        self.begin_protocol_command();
        let response = crate::runtime_dispatch::dispatch(self, command);
        self.finish_protocol_command();
        response
    }

    #[cfg(test)]
    fn handle_with_quick_unlock_handoff(
        &mut self,
        command: RuntimeCommand,
    ) -> Result<(
        RuntimeResponse,
        Option<QuickUnlockReconciliationCredentials>,
    )> {
        self.begin_protocol_command();
        let response = crate::runtime_dispatch::dispatch(self, command);
        let credentials = self.take_quick_unlock_handoff();
        response.map(|response| (response, credentials))
    }

    #[cfg(test)]
    fn handle_browser_command(&mut self, command: RuntimeCommand) -> Result<RuntimeResponse> {
        if !crate::protocol_session::browser_command_allowed(&command) {
            anyhow::bail!("browser command forbidden");
        }
        self.handle(command)
    }

    fn install_committed_generation(
        &mut self,
        vault_id: &str,
        vault: Vault,
        bytes: Vec<u8>,
        fingerprint: ContentIdentity,
        mut source_status: Option<VaultSourceStatusDto>,
    ) -> Result<()> {
        let save_profile = self.inspected_save_profile(&bytes)?;
        let synced = source_status
            .as_ref()
            .is_none_or(|status| status.remote_state == "online");
        let mut retain_committed_bytes = false;
        let base_warning = synced
            .then(|| {
                let mut warnings = Vec::new();
                if let Err(error) = self.synced_bases.store(vault_id, &bytes) {
                    warnings.push(format!(
                        "failed to store synced base for {vault_id}: {error}"
                    ));
                }
                if let Err(error) = self.session_bases.store(vault_id, &bytes) {
                    retain_committed_bytes = true;
                    warnings.push(format!(
                        "failed to store session base for {vault_id}: {error}"
                    ));
                }
                (!warnings.is_empty()).then(|| warnings.join("; "))
            })
            .flatten();
        if let Some(warning) = base_warning {
            if let Some(status) = source_status.as_mut() {
                status.last_error = Some(match status.last_error.take() {
                    Some(previous) => format!("{previous}; {warning}"),
                    None => warning,
                });
            } else {
                self.record_local_save_warnings(vec![warning]);
            }
        }
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.vault = Some(vault);
        loaded.bytes = if retain_committed_bytes {
            bytes
        } else {
            Vec::new()
        };
        loaded.baseline_fingerprint = fingerprint;
        loaded.provider_revision = None;
        loaded.save_profile = save_profile;
        loaded.requires_source_migration = false;
        if let Some(source_status) = source_status {
            loaded.source_status = Some(source_status);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn install_locked_generation(
        &mut self,
        vault_id: &str,
        bytes: Vec<u8>,
        fingerprint: ContentIdentity,
        provider_revision: Option<ProviderRevision>,
        save_profile: VaultEncodingProfile,
        mut source_status: Option<VaultSourceStatusDto>,
        display_name: Option<String>,
        account_label: Option<String>,
    ) -> Result<()> {
        let mut warnings = Vec::new();
        if let Err(error) = self.synced_bases.store(vault_id, &bytes) {
            warnings.push(format!(
                "failed to store synced base for {vault_id}: {error}"
            ));
        }
        if let Err(error) = self.session_bases.store(vault_id, &bytes) {
            warnings.push(format!(
                "failed to store session base for {vault_id}: {error}"
            ));
        }
        if !warnings.is_empty()
            && let Some(status) = source_status.as_mut()
        {
            let warning = warnings.join("; ");
            status.last_error = Some(match status.last_error.take() {
                Some(previous) => format!("{previous}; {warning}"),
                None => warning,
            });
        }
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.vault = None;
        loaded.transformed_key = None;
        loaded.bytes = bytes;
        loaded.baseline_fingerprint = fingerprint;
        loaded.provider_revision = provider_revision;
        loaded.save_profile = save_profile;
        loaded.requires_source_migration = false;
        if let Some(status) = source_status {
            loaded.source_status = Some(status);
        }
        if let Some(display_name) = display_name {
            loaded.name = display_name;
        }
        if account_label.is_some() {
            loaded.source_account_label = account_label;
        }
        if !warnings.is_empty() && loaded.source_status.is_none() {
            self.record_local_save_warnings(warnings);
        }
        Ok(())
    }

    fn session_base_for_fingerprint(
        &self,
        vault_id: &str,
        expected: &ContentIdentity,
    ) -> Result<Vec<u8>> {
        let authenticates = |bytes: &[u8]| {
            let fingerprint = fingerprint_for_cached_bytes(bytes, 0);
            same_content_fingerprint(&fingerprint, expected)
        };
        let session = self
            .session_bases
            .read(vault_id)
            .with_context(|| format!("failed to read session base: {vault_id}"))?;
        if let Some(bytes) = session.filter(|bytes| authenticates(bytes)) {
            return Ok(bytes);
        }

        let retained = self
            .vault_session
            .find_loaded(vault_id)
            .filter(|loaded| !loaded.bytes.is_empty() && authenticates(&loaded.bytes))
            .map(|loaded| loaded.bytes.clone());
        let cached = self
            .vault_session
            .find_loaded(vault_id)
            .and_then(|loaded| remote_cache_key_for_source(&loaded.source))
            .map(|key| self.remote_cache.read(&key))
            .transpose()
            .context("failed to read retained remote cache base")?
            .flatten()
            .filter(|entry| authenticates(&entry.bytes));
        let expected_is_pending = cached.as_ref().is_some_and(|entry| entry.pending_sync);
        let cached = cached.map(|entry| entry.bytes);
        let synced = self
            .synced_bases
            .read(vault_id)
            .with_context(|| format!("failed to read synced base: {vault_id}"))?
            .filter(|bytes| authenticates(bytes));
        let bytes = retained
            .or(cached)
            .or(synced)
            .with_context(|| format!("session base is missing or stale: {vault_id}"))?;
        let _ = self.session_bases.store(vault_id, &bytes);
        if !expected_is_pending {
            let _ = self.synced_bases.store(vault_id, &bytes);
        }
        Ok(bytes)
    }

    fn recover_generic_pending_base(
        &self,
        vault_id: &str,
        cache_key: &RemoteCacheKey,
        pending_fingerprint: &ContentIdentity,
    ) -> Result<Vec<u8>> {
        let durable = self
            .remote_cache
            .generic_pending_base(cache_key, pending_fingerprint)?
            .map(|base| base.bytes);
        let session = self
            .session_bases
            .read(vault_id)
            .with_context(|| format!("failed to read session base: {vault_id}"))?;
        let synced = self
            .synced_bases
            .read(vault_id)
            .with_context(|| format!("failed to read synced base: {vault_id}"))?;
        let bytes = durable
            .or(session)
            .or(synced)
            .with_context(|| format!("pending Publication Base is missing: {vault_id}"))?;
        let _ = self.session_bases.store(vault_id, &bytes);
        Ok(bytes)
    }

    pub(crate) fn retry_publication_command(&mut self, vault_id: &str) -> Result<RuntimeResponse> {
        match self.commit_working_copy(vault_id) {
            Err(error) => match classified_runtime_error_response(&error) {
                Some(response) => Ok(response),
                None => Err(error),
            },
            result => result,
        }
    }

    fn commit_working_copy(&mut self, vault_id: &str) -> Result<RuntimeResponse> {
        let (
            key,
            baseline_fingerprint,
            save_profile,
            source,
            display_name,
            account_label,
            requires_source_migration,
        ) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            (
                transformed_key_from_loaded_vault(loaded)?,
                loaded.baseline_fingerprint.clone(),
                loaded.save_profile.clone(),
                loaded.source.clone(),
                loaded.name.clone(),
                loaded.source_account_label.clone(),
                loaded.requires_source_migration,
            )
        };
        if let VaultSource::OneDriveItem { drive_id, item_id } = &source {
            return self.save_onedrive_vault(
                vault_id,
                drive_id,
                item_id,
                key,
                &baseline_fingerprint,
                save_profile,
                display_name,
                account_label,
                requires_source_migration,
            );
        }
        let VaultSource::LocalPath(source_path) = &source else {
            unreachable!("OneDrive saves return through the CAS path")
        };
        self.save_local_vault(
            vault_id,
            source_path,
            key,
            &baseline_fingerprint,
            save_profile,
            requires_source_migration,
        )
    }

    fn save_local_vault(
        &mut self,
        vault_id: &str,
        source_path: &str,
        key: Arc<VaultKey>,
        baseline_fingerprint: &ContentIdentity,
        mut local_save_profile: VaultEncodingProfile,
        requires_source_migration: bool,
    ) -> Result<RuntimeResponse> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;

        let base_bytes = if requires_source_migration {
            self.session_bases
                .read(vault_id)
                .with_context(|| format!("failed to read migrated Local File Base: {vault_id}"))?
                .with_context(|| format!("migrated Local File Base is missing: {vault_id}"))?
        } else {
            self.session_base_for_fingerprint(vault_id, baseline_fingerprint)?
        };
        let base_vault = match Self::load_session_database(&base_bytes, &key) {
            Ok(database) => database.vault,
            Err(VaultCodecError::KeyMismatch) => {
                self.unlock_historical_snapshot_from_unlock_blob(vault_id, &base_bytes)
                    .context("failed to unlock the historical Local File Base")?
                    .context(
                        "Local File Base uses a historical KDF and quick unlock is unavailable",
                    )?
                    .0
            }
            Err(error) => return Err(error).context("failed to parse the Local File Base"),
        };
        let base_save_profile = self
            .inspected_save_profile(&base_bytes)
            .context("failed to inspect the Local File Base")?;
        let local_vault = self
            .loaded_vault(vault_id)
            .context("failed to read the Local Working Copy")?
            .clone();
        local_save_profile.clear_explicit_kdf();
        let (local_bytes, verified_local) = Self::serialize_and_verify_vault_candidate(
            local_vault.clone(),
            &key,
            local_save_profile.clone(),
        )
        .context("failed to verify the Local File candidate")?;
        let mut saw_source_change = false;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let current = match self.read_current_snapshot(vault_id, Some(baseline_fingerprint)) {
                Ok(current) => current,
                Err(error)
                    if matches!(
                        error.downcast_ref::<ProviderError>(),
                        Some(ProviderError::NotFound { .. })
                    ) =>
                {
                    return self.local_conflict_copy_result(
                        vault_id,
                        source_path,
                        &local_bytes,
                        verified_local,
                        key,
                    );
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to observe current Local File source: {vault_id}")
                    });
                }
            };
            let observed_revision = current
                .provider_revision
                .context("Local File snapshots always carry a Provider Revision")?;

            let (candidate_bytes, candidate_vault, merge_report) =
                if same_content_fingerprint(&current.fingerprint, baseline_fingerprint) {
                    (local_bytes.clone(), verified_local.clone(), None)
                } else {
                    saw_source_change = true;
                    let remote_bytes = current
                        .bytes
                        .context("changed Local File observation must include bytes")?;
                    let remote_vault = match Self::load_session_database(&remote_bytes, &key) {
                        Ok(database) => database.vault,
                        Err(_) => {
                            return self.local_conflict_copy_result(
                                vault_id,
                                source_path,
                                &local_bytes,
                                verified_local,
                                key,
                            );
                        }
                    };
                    if !has_vaultkern_sync_lineage(&base_vault, &remote_vault) {
                        return self.local_conflict_copy_result(
                            vault_id,
                            source_path,
                            &local_bytes,
                            verified_local,
                            key,
                        );
                    }
                    let remote_save_profile = match self.inspected_save_profile(&remote_bytes) {
                        Ok(profile) => profile,
                        Err(_) => {
                            return self.local_conflict_copy_result(
                                vault_id,
                                source_path,
                                &local_bytes,
                                verified_local,
                                key,
                            );
                        }
                    };
                    let merged_save_profile = match Self::merge_save_profile(
                        &base_save_profile,
                        &local_save_profile,
                        &remote_save_profile,
                    ) {
                        Ok(profile) => profile,
                        Err(_) => {
                            return self.local_conflict_copy_result(
                                vault_id,
                                source_path,
                                &local_bytes,
                                verified_local,
                                key,
                            );
                        }
                    };
                    let patched =
                        match three_way_field_patch(&base_vault, &local_vault, &remote_vault) {
                            Ok(patched) => patched,
                            Err(_) => {
                                return self.local_conflict_copy_result(
                                    vault_id,
                                    source_path,
                                    &local_bytes,
                                    verified_local,
                                    key,
                                );
                            }
                        };
                    if ensure_patch_conflict_history_is_recoverable(
                        &patched.vault,
                        &patched.required_history_snapshots,
                    )
                    .is_err()
                    {
                        return self.local_conflict_copy_result(
                            vault_id,
                            source_path,
                            &local_bytes,
                            verified_local,
                            key,
                        );
                    }
                    let report = patched.report;
                    let (bytes, verified) = Self::serialize_and_verify_vault_candidate(
                        patched.vault,
                        &key,
                        merged_save_profile,
                    )
                    .context("failed to verify the reconciled Local File candidate")?;
                    (bytes, verified, Some(report))
                };

            match self.write_local_source(vault_id, &candidate_bytes, &observed_revision) {
                Ok((next_revision, next_fingerprint)) => {
                    self.install_committed_generation(
                        vault_id,
                        candidate_vault,
                        candidate_bytes,
                        next_fingerprint,
                        None,
                    )?;
                    self.vault_session
                        .find_loaded_mut(vault_id)
                        .expect("published Local File remains loaded")
                        .provider_revision = Some(next_revision);
                    return Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
                        status: if saw_source_change {
                            PublicationStatusDto::Reconciled
                        } else {
                            PublicationStatusDto::Published
                        },
                        reconciliation_summary: merge_report.as_ref().map(three_way_patch_summary),
                        conflict_copy_path: None,
                    }));
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<ProviderError>(),
                        Some(ProviderError::StaleRevision { .. })
                    ) && attempt + 1 < MAX_SOURCE_ATTEMPTS =>
                {
                    saw_source_change = true;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to publish Local File: {vault_id}"));
                }
            }
        }
        unreachable!("bounded Local File source attempts must return")
    }

    fn local_conflict_copy_result(
        &mut self,
        vault_id: &str,
        source_path: &str,
        bytes: &[u8],
        verified_vault: Vault,
        key: Arc<VaultKey>,
    ) -> Result<RuntimeResponse> {
        let conflict_copy = self
            .providers
            .local(source_path)
            .preserve_conflict_copy(bytes)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to preserve Conflict Copy for: {vault_id}"))?;
        match self.providers.local(source_path).read() {
            Ok(remote) => {
                let remote_fingerprint = fingerprint_for_cached_bytes(&remote.bytes, 0);
                let remote_save_profile = match self.inspected_save_profile(&remote.bytes) {
                    Ok(profile) => profile,
                    Err(_) => {
                        self.install_pending_vault_candidate(vault_id, verified_vault)?;
                        return Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
                            status: PublicationStatusDto::ConflictSplit,
                            reconciliation_summary: None,
                            conflict_copy_path: Some(conflict_copy.identity),
                        }));
                    }
                };
                match Self::load_session_database(&remote.bytes, &key) {
                    Ok(database) => {
                        self.install_committed_generation(
                            vault_id,
                            database.vault,
                            remote.bytes,
                            remote_fingerprint,
                            None,
                        )?;
                        self.vault_session
                            .find_loaded_mut(vault_id)
                            .expect("local Conflict Split keeps the vault loaded")
                            .provider_revision = Some(remote.revision);
                        self.replace_session_transformed_key(vault_id, key)?;
                    }
                    Err(VaultCodecError::KeyMismatch) => {
                        match self
                            .refresh_transformed_key_from_unlock_blob(vault_id, &remote.bytes)?
                        {
                            Some((vault, refreshed_key)) => {
                                self.install_committed_generation(
                                    vault_id,
                                    vault,
                                    remote.bytes,
                                    remote_fingerprint,
                                    None,
                                )?;
                                self.vault_session
                                    .find_loaded_mut(vault_id)
                                    .expect("local Conflict Split keeps the vault loaded")
                                    .provider_revision = Some(remote.revision);
                                self.replace_session_transformed_key(vault_id, refreshed_key)?;
                            }
                            None => {
                                self.install_locked_generation(
                                    vault_id,
                                    remote.bytes,
                                    remote_fingerprint,
                                    Some(remote.revision),
                                    remote_save_profile,
                                    None,
                                    None,
                                    None,
                                )?;
                            }
                        }
                    }
                    Err(_) => {
                        self.install_locked_generation(
                            vault_id,
                            remote.bytes,
                            remote_fingerprint,
                            Some(remote.revision),
                            remote_save_profile,
                            None,
                            None,
                            None,
                        )?;
                    }
                }
            }
            Err(_) => {
                self.install_pending_vault_candidate(vault_id, verified_vault)?;
            }
        }
        Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
            status: PublicationStatusDto::ConflictSplit,
            reconciliation_summary: None,
            conflict_copy_path: Some(conflict_copy.identity),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn save_onedrive_vault(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        mut key: Arc<VaultKey>,
        baseline_fingerprint: &ContentIdentity,
        mut local_save_profile: VaultEncodingProfile,
        display_name: String,
        account_label: Option<String>,
        requires_source_migration: bool,
    ) -> Result<RuntimeResponse> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;

        let source = VaultSource::OneDriveItem {
            drive_id: drive_id.to_owned(),
            item_id: item_id.to_owned(),
        };
        let cache_key = remote_cache_key_for_source(&source).expect("OneDrive source");
        let account_label = account_label.unwrap_or_else(|| cache_key.provider_kind.clone());
        let local_vault = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let local_vault = loaded
                .vault
                .as_ref()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            local_vault.clone()
        };
        if self.remote_cache.read(&cache_key)?.is_some_and(|entry| {
            entry.pending_sync && same_content_fingerprint(&entry.fingerprint, baseline_fingerprint)
        }) && self
            .remote_cache
            .generic_pending_kind(&cache_key, baseline_fingerprint)?
            == GenericPendingKind::ConflictCopy
        {
            local_save_profile.clear_explicit_kdf();
            let (bytes, verified_local) =
                Self::serialize_and_verify_vault_candidate(local_vault, &key, local_save_profile)
                    .context("failed to verify the updated pending conflict copy")?;
            let response = self.save_conflict_copy_to_pending_cache(
                vault_id,
                source,
                bytes,
                baseline_fingerprint,
                display_name,
                Some(account_label),
                "updated the durable pending conflict copy".into(),
            )?;
            self.install_pending_vault_candidate(vault_id, verified_local)?;
            return Ok(response);
        }
        let pending_source_write = self.remote_cache.read(&cache_key)?.is_some_and(|entry| {
            entry.pending_sync && same_content_fingerprint(&entry.fingerprint, baseline_fingerprint)
        }) && self
            .remote_cache
            .generic_pending_kind(&cache_key, baseline_fingerprint)?
            == GenericPendingKind::SourceWrite;
        let base_bytes = if requires_source_migration {
            self.session_bases
                .read(vault_id)
                .with_context(|| format!("failed to read migrated session base: {vault_id}"))?
                .with_context(|| format!("migrated session base is missing: {vault_id}"))?
        } else if pending_source_write {
            self.recover_generic_pending_base(vault_id, &cache_key, baseline_fingerprint)?
        } else {
            self.session_base_for_fingerprint(vault_id, baseline_fingerprint)?
        };
        let base_vault = match Self::load_session_database(&base_bytes, &key) {
            Ok(database) => database.vault,
            Err(VaultCodecError::KeyMismatch) => self
                .unlock_historical_snapshot_from_unlock_blob(vault_id, &base_bytes)
                .context("failed to unlock the historical synced OneDrive base")?
                .context(
                    "synced OneDrive base uses a historical KDF and quick unlock is unavailable",
                )?
                .0,
            Err(error) => {
                return Err(error).context("failed to parse the synced OneDrive base");
            }
        };
        let base_save_profile = self
            .inspected_save_profile(&base_bytes)
            .context("failed to inspect the synced OneDrive base")?;
        local_save_profile.clear_explicit_kdf();
        if local_vault == base_vault
            && local_save_profile == base_save_profile
            && !requires_source_migration
        {
            return self.adopt_untouched_onedrive_head(
                vault_id,
                drive_id,
                item_id,
                key,
                baseline_fingerprint,
            );
        }
        let local_key = key.clone();
        let (local_bytes, verified_local) = Self::serialize_and_verify_vault_candidate(
            local_vault.clone(),
            &local_key,
            local_save_profile.clone(),
        )
        .context("failed to verify the local OneDrive candidate")?;
        let mut saw_source_change = false;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = match self.providers.remote_state(drive_id, item_id) {
                Ok(state) => state,
                Err(error) => {
                    let not_found = ProviderCatalog::is_onedrive_not_found(&error);
                    let response = if not_found {
                        self.save_conflict_copy_to_pending_cache(
                            vault_id,
                            source,
                            local_bytes,
                            baseline_fingerprint,
                            display_name,
                            Some(account_label),
                            format!(
                                "the OneDrive source was deleted; local changes remain in a durable pending conflict copy: {}",
                                format_error_chain(&error)
                            ),
                        )?
                    } else {
                        self.save_remote_vault_to_pending_cache(
                            vault_id,
                            source,
                            local_bytes,
                            baseline_fingerprint,
                            display_name,
                            Some(account_label),
                            format_error_chain(&error),
                            base_bytes.clone(),
                        )?
                    };
                    self.install_pending_vault_candidate(vault_id, verified_local.clone())?;
                    return Ok(response);
                }
            };
            let observed_revision = state.revision().clone();
            let remote_bytes = if state.matches_identity(baseline_fingerprint) {
                base_bytes.clone()
            } else {
                saw_source_change = true;
                match self
                    .providers
                    .read_onedrive_observation(drive_id, item_id, &state)
                {
                    Ok(snapshot) => snapshot.bytes,
                    Err(error) => {
                        let response = self.save_remote_vault_to_pending_cache(
                            vault_id,
                            source,
                            local_bytes,
                            baseline_fingerprint,
                            display_name,
                            Some(account_label),
                            error.to_string(),
                            base_bytes.clone(),
                        )?;
                        self.install_pending_vault_candidate(vault_id, verified_local.clone())?;
                        return Ok(response);
                    }
                }
            };
            let remote_vault = match Self::load_session_database(&remote_bytes, &key) {
                Ok(database) => database.vault,
                Err(VaultCodecError::KeyMismatch) => {
                    let Some((vault, refreshed_key)) = self
                        .refresh_transformed_key_from_unlock_blob(vault_id, &remote_bytes)
                        .context("failed to refresh quick unlock after the OneDrive KDF changed")?
                    else {
                        let remote_save_profile = self
                            .inspected_save_profile(&remote_bytes)
                            .context("failed to inspect the locked OneDrive conflict head")?;
                        let locked_head = OneDriveConflictHead {
                            vault: None,
                            bytes: remote_bytes.clone(),
                            fingerprint: state.identity_for_bytes(&remote_bytes),
                            revision: observed_revision.clone(),
                            cache_validation_token: state
                                .cache_validation_token()
                                .map(str::to_owned),
                            display_name: display_name_for_cloud_name(state.display_name()),
                            account_label: account_label.clone(),
                            save_profile: remote_save_profile,
                            key: None,
                        };
                        return self.upload_or_persist_onedrive_conflict_copy(
                            vault_id,
                            drive_id,
                            item_id,
                            &display_name,
                            &account_label,
                            baseline_fingerprint,
                            &local_bytes,
                            Some(verified_local.clone()),
                            Some(locked_head),
                            "current OneDrive generation uses a different vault key",
                        );
                    };
                    key = refreshed_key;
                    vault
                }
                Err(error) => {
                    let remote_save_profile = self
                        .inspected_save_profile(&remote_bytes)
                        .context("failed to inspect the unreadable OneDrive conflict head")?;
                    let locked_head = OneDriveConflictHead {
                        vault: None,
                        bytes: remote_bytes.clone(),
                        fingerprint: state.identity_for_bytes(&remote_bytes),
                        revision: observed_revision.clone(),
                        cache_validation_token: state.cache_validation_token().map(str::to_owned),
                        display_name: display_name_for_cloud_name(state.display_name()),
                        account_label: account_label.clone(),
                        save_profile: remote_save_profile,
                        key: None,
                    };
                    return self.upload_or_persist_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        &display_name,
                        &account_label,
                        baseline_fingerprint,
                        &local_bytes,
                        Some(verified_local.clone()),
                        Some(locked_head),
                        &format!("current OneDrive generation cannot be parsed: {error}"),
                    );
                }
            };
            let remote_save_profile = self
                .inspected_save_profile(&remote_bytes)
                .context("failed to inspect the current OneDrive generation")?;
            let conflict_head = OneDriveConflictHead {
                vault: Some(remote_vault.clone()),
                bytes: remote_bytes.clone(),
                fingerprint: state.identity_for_bytes(&remote_bytes),
                revision: observed_revision.clone(),
                cache_validation_token: state.cache_validation_token().map(str::to_owned),
                display_name: display_name_for_cloud_name(state.display_name()),
                account_label: account_label.clone(),
                save_profile: remote_save_profile.clone(),
                key: Some(key.clone()),
            };
            if !state.matches_identity(baseline_fingerprint)
                && !has_vaultkern_sync_lineage(&base_vault, &remote_vault)
            {
                return self.upload_or_persist_onedrive_conflict_copy(
                    vault_id,
                    drive_id,
                    item_id,
                    &display_name,
                    &account_label,
                    baseline_fingerprint,
                    &local_bytes,
                    Some(verified_local.clone()),
                    Some(conflict_head.clone()),
                    "current OneDrive generation has foreign or unclear writer lineage",
                );
            }
            let merged_save_profile = match Self::merge_save_profile(
                &base_save_profile,
                &local_save_profile,
                &remote_save_profile,
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    return self.upload_or_persist_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        &display_name,
                        &account_label,
                        baseline_fingerprint,
                        &local_bytes,
                        Some(verified_local.clone()),
                        Some(conflict_head.clone()),
                        &format!(
                            "concurrent OneDrive encryption profile cannot be merged: {error}"
                        ),
                    );
                }
            };
            let patched = match three_way_field_patch(&base_vault, &local_vault, &remote_vault) {
                Ok(patched) => patched,
                Err(error) => {
                    return self.upload_or_persist_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        &display_name,
                        &account_label,
                        baseline_fingerprint,
                        &local_bytes,
                        Some(verified_local.clone()),
                        Some(conflict_head.clone()),
                        &format!("concurrent changes cannot be represented: {error}"),
                    );
                }
            };
            if let Err(error) = ensure_patch_conflict_history_is_recoverable(
                &patched.vault,
                &patched.required_history_snapshots,
            ) {
                return self.upload_or_persist_onedrive_conflict_copy(
                    vault_id,
                    drive_id,
                    item_id,
                    &display_name,
                    &account_label,
                    baseline_fingerprint,
                    &local_bytes,
                    Some(verified_local.clone()),
                    Some(conflict_head),
                    &format!("concurrent changes exceed vault history retention: {error}"),
                );
            }
            let report = patched.report;
            let (bytes, verified_vault) = Self::serialize_and_verify_vault_candidate(
                patched.vault,
                &key,
                merged_save_profile,
            )
            .context("failed to verify the rebased OneDrive candidate")?;

            let write_outcome = self
                .providers
                .onedrive(drive_id, item_id)
                .publish(&observed_revision, &bytes);
            let write_outcome = match write_outcome {
                Err(ProviderError::OutcomeUnknown { message }) => {
                    let mut provider = self.providers.onedrive(drive_id, item_id);
                    match provider.read() {
                        Ok(snapshot) if snapshot.bytes == bytes => Ok(ProviderCommit {
                            revision: snapshot.revision,
                            identity: snapshot.identity,
                            cache_validation_token: snapshot.cache_validation_token,
                            warnings: vec![format!(
                                "{message}; readback confirmed that the candidate was published"
                            )],
                        }),
                        Ok(snapshot) if snapshot.bytes == remote_bytes => {
                            Err(ProviderError::OutcomeUnknown {
                                message: format!(
                                    "{message}; readback confirmed that the candidate was not published"
                                ),
                            })
                        }
                        Ok(_) => Err(ProviderError::StaleRevision {
                            message:
                                "OneDrive advanced to a third generation during outcome readback"
                                    .into(),
                        }),
                        Err(readback_error) => Err(ProviderError::OutcomeUnknown {
                            message: format!(
                                "{message}; write outcome readback failed: {readback_error}"
                            ),
                        }),
                    }
                }
                other => other,
            };

            match write_outcome {
                Ok(commit) => {
                    let fingerprint = commit.identity;
                    let cached_at = self.current_unix_time() as i64;
                    let cache_result = self.remote_cache.write_with_validation_token(
                        &cache_key,
                        RemoteVaultCacheEntry {
                            bytes: bytes.clone(),
                            fingerprint: fingerprint.clone(),
                            display_name: display_name.clone(),
                            account_label: account_label.clone(),
                            cached_at,
                            pending_sync: false,
                            conflict_receipt_source: None,
                        },
                        commit.cache_validation_token.as_deref(),
                    );
                    let status = remote_source_status_after_commit(
                        &cache_key,
                        cached_at,
                        cache_result.as_ref().err(),
                    );
                    self.install_committed_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        fingerprint,
                        Some(status),
                    )?;
                    self.vault_session
                        .find_loaded_mut(vault_id)
                        .expect("committed vault remains loaded")
                        .provider_revision = Some(commit.revision);
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
                        status: if saw_source_change {
                            PublicationStatusDto::Reconciled
                        } else {
                            PublicationStatusDto::Published
                        },
                        reconciliation_summary: saw_source_change
                            .then(|| three_way_patch_summary(&report)),
                        conflict_copy_path: None,
                    }));
                }
                Err(ProviderError::StaleRevision { .. }) if attempt + 1 < MAX_SOURCE_ATTEMPTS => {
                    saw_source_change = true;
                    continue;
                }
                Err(ProviderError::StaleRevision { message }) => {
                    let response = self.save_remote_vault_to_pending_cache(
                        vault_id,
                        source,
                        local_bytes,
                        baseline_fingerprint,
                        display_name,
                        Some(account_label),
                        format!(
                            "OneDrive Publication remains pending after repeated Stale Revision: {message}"
                        ),
                        base_bytes,
                    )?;
                    self.install_pending_vault_candidate(vault_id, verified_local)?;
                    return Ok(response);
                }
                Err(ProviderError::OutcomeUnknown { message }) => {
                    let response = self.save_remote_vault_to_pending_cache_with_base(
                        vault_id,
                        source.clone(),
                        local_bytes.clone(),
                        baseline_fingerprint,
                        display_name.clone(),
                        Some(account_label.clone()),
                        message.clone(),
                        Some(base_bytes.clone()),
                    );
                    let response = match response {
                        Ok(response) => Ok(response),
                        Err(first_error) => self
                            .save_remote_vault_to_pending_cache_with_base(
                                vault_id,
                                source,
                                local_bytes,
                                baseline_fingerprint,
                                display_name,
                                Some(account_label),
                                message,
                                Some(base_bytes),
                            )
                            .with_context(|| {
                                format!(
                                    "failed to retry pending cache after an ambiguous OneDrive write: {first_error:#}"
                                )
                            }),
                    };
                    let response = response?;
                    self.install_pending_vault_candidate(vault_id, verified_local)?;
                    return Ok(response);
                }
                Err(error) => {
                    let response = self.save_remote_vault_to_pending_cache_with_base(
                        vault_id,
                        source,
                        local_bytes,
                        baseline_fingerprint,
                        display_name,
                        Some(account_label),
                        error.to_string(),
                        Some(base_bytes),
                    );
                    let response = response?;
                    self.install_pending_vault_candidate(vault_id, verified_local)?;
                    return Ok(response);
                }
            }
        }
        unreachable!("bounded OneDrive source attempts must return")
    }

    fn adopt_untouched_onedrive_head(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        key: Arc<VaultKey>,
        baseline_fingerprint: &ContentIdentity,
    ) -> Result<RuntimeResponse> {
        let state = self.providers.remote_state(drive_id, item_id)?;
        if state.matches_identity(baseline_fingerprint) {
            return Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                reconciliation_summary: None,
                conflict_copy_path: None,
            }));
        }

        let snapshot = read_onedrive_provider(&mut self.providers, drive_id, item_id, &state)?;
        let (remote_vault, key) = match Self::load_session_database(&snapshot.bytes, &key) {
            Ok(database) => (database.vault, key),
            Err(VaultCodecError::KeyMismatch) => self
                .refresh_transformed_key_from_unlock_blob(vault_id, &snapshot.bytes)
                .context("failed to refresh quick unlock after the OneDrive KDF changed")?
                .context(
                    "changed OneDrive generation requires fresh master credentials or quick unlock",
                )?,
            Err(error) => {
                return Err(error).context("failed to parse changed OneDrive generation");
            }
        };
        let cache_key = RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id));
        let cached_at = self.current_unix_time() as i64;
        let display_name = display_name_for_cloud_name(&snapshot.name);
        let account_label = snapshot.account_label.clone();
        let cache_result = self.remote_cache.write_with_validation_token(
            &cache_key,
            RemoteVaultCacheEntry {
                bytes: snapshot.bytes.clone(),
                fingerprint: snapshot.fingerprint.clone(),
                display_name: display_name.clone(),
                account_label: account_label.clone(),
                cached_at,
                pending_sync: false,
                conflict_receipt_source: None,
            },
            snapshot.cache_validation_token.as_deref(),
        );
        let status =
            remote_source_status_after_commit(&cache_key, cached_at, cache_result.as_ref().err());
        self.install_committed_generation(
            vault_id,
            remote_vault,
            snapshot.bytes,
            snapshot.fingerprint,
            Some(status),
        )?;
        self.replace_session_transformed_key(vault_id, key)?;
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.name = display_name;
        loaded.source_account_label = Some(account_label);
        Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
            status: PublicationStatusDto::Reconciled,
            reconciliation_summary: None,
            conflict_copy_path: None,
        }))
    }

    fn refresh_transformed_key_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<Option<(Vault, Arc<VaultKey>)>> {
        self.unlock_snapshot_from_unlock_blob(vault_id, bytes, true)
    }

    fn unlock_historical_snapshot_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<Option<(Vault, Arc<VaultKey>)>> {
        self.unlock_snapshot_from_unlock_blob(vault_id, bytes, false)
    }

    fn unlock_snapshot_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
        refresh_cached_transformed_key: bool,
    ) -> Result<Option<(Vault, Arc<VaultKey>)>> {
        if !self.quick_unlock_policy_enabled() {
            return Ok(None);
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let current_source = self.references.source_for(&current_vault_ref_id)?;
        if vault_id_for_stored_source(&current_source) != vault_id {
            anyhow::bail!("current vault reference does not match the active vault");
        }
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        match self.secure_storage.contains(&storage_key) {
            Ok(true) => {}
            Ok(false) | Err(_) => return Ok(None),
        }
        if !self.secure_storage.load_requires_user_presence() {
            if !self.biometric.supports_quick_unlock() {
                return Ok(None);
            }
            self.biometric
                .authorize("Refresh quick unlock after a vault key change")?;
        }
        if !self.quick_unlock_policy_enabled() {
            return Ok(None);
        }
        let (policy, confirmation) = self.external_open_kdf_policy();
        let attempt = if refresh_cached_transformed_key {
            unlock_from_blob_with_policy(
                self.secure_storage.as_ref(),
                &storage_key,
                bytes,
                &policy,
                confirmation,
            )?
        } else {
            unlock_historical_snapshot_from_blob_with_policy(
                self.secure_storage.as_ref(),
                &storage_key,
                bytes,
                &policy,
                confirmation,
            )?
        };
        let unlocked = match attempt {
            UnlockAttempt::Unlocked(unlocked) => unlocked,
            UnlockAttempt::NotEnrolled | UnlockAttempt::CredentialRequired => return Ok(None),
            UnlockAttempt::Cancelled => anyhow::bail!("quick unlock was cancelled"),
            UnlockAttempt::OpenAppRequired => {
                anyhow::bail!("quick unlock cache miss; open the resident app once")
            }
        };
        if !self.quick_unlock_policy_enabled() {
            return Ok(None);
        }
        Ok(Some((unlocked.vault, Arc::new(unlocked.transformed_key))))
    }

    fn replace_session_transformed_key(
        &mut self,
        vault_id: &str,
        key: Arc<VaultKey>,
    ) -> Result<()> {
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.transformed_key = Some(key);
        Ok(())
    }

    fn serialize_and_verify_vault_candidate(
        mut vault: Vault,
        key: &VaultKey,
        save_profile: VaultEncodingProfile,
    ) -> Result<(Vec<u8>, Vault)> {
        let bytes = save_kdbx_with_history_limits_transformed(&mut vault, key, save_profile)
            .context("failed to serialize vault candidate")?;
        let verified = Self::load_session_database(&bytes, key)
            .context("failed to reload serialized vault candidate")?
            .vault;
        Ok((bytes, verified))
    }

    fn install_pending_vault_candidate(&mut self, vault_id: &str, vault: Vault) -> Result<()> {
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.vault = Some(vault);
        loaded.save_profile.clear_explicit_kdf();
        Ok(())
    }

    fn publish_onedrive_conflict_copy_receipt(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        expected_source: &ContentIdentity,
        display_name: &str,
        bytes: &[u8],
    ) -> Result<ProviderConflictCopy> {
        let receipt_key = onedrive_conflict_receipt_cache_key(drive_id, item_id);
        let current = self.remote_cache.read(&receipt_key)?;
        let same_candidate = current.as_ref().is_some_and(|receipt| {
            let candidate_fingerprint = fingerprint_for_cached_bytes(bytes, receipt.cached_at);
            if same_content_fingerprint(&receipt.fingerprint, &candidate_fingerprint) {
                return true;
            }
            let Ok(key) = self
                .vault_session
                .find_loaded(vault_id)
                .context("vault not opened before conflict-copy publication")
                .and_then(transformed_key_from_loaded_vault)
            else {
                return false;
            };
            let Ok(receipt_database) = Self::load_session_database(&receipt.bytes, &key) else {
                return false;
            };
            let Ok(candidate_database) = Self::load_session_database(bytes, &key) else {
                return false;
            };
            let Ok(receipt_profile) = self.inspected_save_profile(&receipt.bytes) else {
                return false;
            };
            let Ok(candidate_profile) = self.inspected_save_profile(bytes) else {
                return false;
            };
            receipt_database.vault == candidate_database.vault
                && receipt_profile == candidate_profile
        });

        if let Some(receipt) = current.as_ref().filter(|_| same_candidate)
            && !receipt.pending_sync
            && self
                .providers
                .remote_state(drive_id, &receipt.account_label)
                .and_then(|state| {
                    read_onedrive_provider(
                        &mut self.providers,
                        drive_id,
                        &receipt.account_label,
                        &state,
                    )
                })
                .is_ok_and(|snapshot| snapshot.bytes == receipt.bytes)
        {
            if receipt
                .conflict_receipt_source
                .as_ref()
                .is_none_or(|source| !same_content_fingerprint(source, expected_source))
            {
                let mut updated = receipt.clone();
                updated.conflict_receipt_source = Some(expected_source.clone());
                self.remote_cache.write(&receipt_key, updated)?;
            }
            return Ok(ProviderConflictCopy {
                identity: receipt.account_label.clone(),
                display_name: receipt.display_name.clone(),
                warnings: Vec::new(),
            });
        }

        let cached_at = self.current_unix_time() as i64;
        let pending = if let Some(receipt) = current.as_ref().filter(|_| same_candidate) {
            let mut pending = receipt.clone();
            pending.pending_sync = true;
            pending.conflict_receipt_source = Some(expected_source.clone());
            pending
        } else {
            RemoteVaultCacheEntry {
                bytes: bytes.to_vec(),
                fingerprint: fingerprint_for_cached_bytes(bytes, cached_at),
                display_name: display_name.to_owned(),
                account_label: item_id.to_owned(),
                cached_at,
                pending_sync: true,
                conflict_receipt_source: Some(expected_source.clone()),
            }
        };
        let expected = current
            .as_ref()
            .map(|entry| entry.fingerprint.clone())
            .unwrap_or_else(|| pending.fingerprint.clone());
        if current.as_ref().is_none_or(|entry| {
            !entry.pending_sync
                || !same_content_fingerprint(&entry.fingerprint, &pending.fingerprint)
                || entry
                    .conflict_receipt_source
                    .as_ref()
                    .is_none_or(|source| !same_content_fingerprint(source, expected_source))
        }) {
            self.remote_cache.write_conflict_copy_pending(
                &receipt_key,
                pending.clone(),
                &expected,
            )?;
        }
        self.interrupt_conflict_split_at(ConflictSplitInterruptionPoint::AfterReceiptIntent)?;

        let completion_time = self.current_unix_time() as i64;
        let one_drive = &mut self.providers;
        let (conflict_copy, _) = self.remote_cache.complete_generic_pending_while(
            &receipt_key,
            &pending.fingerprint,
            || {
                let conflict_copy = one_drive
                    .onedrive(drive_id, item_id)
                    .preserve_conflict_copy(&pending.bytes)
                    .map_err(anyhow::Error::from)?;
                let mut published = pending.clone();
                published.pending_sync = false;
                published.account_label = conflict_copy.identity.clone();
                published.display_name = conflict_copy.display_name.clone();
                published.cached_at = completion_time;
                Ok((conflict_copy, published))
            },
        )?;
        Ok(conflict_copy)
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_or_persist_onedrive_conflict_copy(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        display_name: &str,
        account_label: &str,
        baseline_fingerprint: &ContentIdentity,
        bytes: &[u8],
        pending_vault: Option<Vault>,
        remote_head: Option<OneDriveConflictHead>,
        reason: &str,
    ) -> Result<RuntimeResponse> {
        match self.publish_onedrive_conflict_copy_receipt(
            vault_id,
            drive_id,
            item_id,
            baseline_fingerprint,
            display_name,
            bytes,
        ) {
            Ok(conflict_copy) => {
                self.interrupt_conflict_split_at(
                    ConflictSplitInterruptionPoint::AfterConflictCopy,
                )?;
                if let Some(remote_head) = remote_head {
                    self.adopt_onedrive_conflict_head(
                        vault_id,
                        drive_id,
                        item_id,
                        baseline_fingerprint,
                        remote_head,
                        &conflict_copy,
                        reason,
                    )?;
                } else if let Some(vault) = pending_vault {
                    self.install_pending_vault_candidate(vault_id, vault)?;
                }
                Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
                    status: PublicationStatusDto::ConflictSplit,
                    reconciliation_summary: None,
                    conflict_copy_path: Some(format!("onedrive:{}", conflict_copy.display_name)),
                }))
            }
            Err(upload_error)
                if upload_error
                    .downcast_ref::<ConflictSplitInterrupted>()
                    .is_some() =>
            {
                Err(upload_error)
            }
            Err(upload_error) => {
                let response = self.save_conflict_copy_to_pending_cache(
                    vault_id,
                    VaultSource::OneDriveItem {
                        drive_id: drive_id.to_owned(),
                        item_id: item_id.to_owned(),
                    },
                    bytes.to_vec(),
                    baseline_fingerprint,
                    display_name.to_owned(),
                    Some(account_label.to_owned()),
                    format!(
                        "{reason}; conflict-copy upload failed and remains pending: {upload_error:#}"
                    ),
                )?;
                if let Some(vault) = pending_vault {
                    self.install_pending_vault_candidate(vault_id, vault)?;
                }
                Ok(response)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_onedrive_conflict_head(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        expected_cache_fingerprint: &ContentIdentity,
        remote_head: OneDriveConflictHead,
        conflict_copy: &ProviderConflictCopy,
        reason: &str,
    ) -> Result<()> {
        let OneDriveConflictHead {
            vault,
            bytes,
            fingerprint,
            revision,
            cache_validation_token,
            display_name,
            account_label,
            save_profile,
            key,
        } = remote_head;
        let source = VaultSource::OneDriveItem {
            drive_id: drive_id.to_owned(),
            item_id: item_id.to_owned(),
        };
        let cache_key = remote_cache_key_for_source(&source).expect("OneDrive source");
        let cached_at = self.current_unix_time() as i64;
        let cache_entry = RemoteVaultCacheEntry {
            bytes: bytes.clone(),
            fingerprint: fingerprint.clone(),
            display_name: display_name.clone(),
            account_label: account_label.clone(),
            cached_at,
            pending_sync: false,
            conflict_receipt_source: None,
        };
        let cache_result = match self.remote_cache.read(&cache_key) {
            Ok(Some(current))
                if current.pending_sync
                    && same_content_fingerprint(
                        &current.fingerprint,
                        expected_cache_fingerprint,
                    ) =>
            {
                self.remote_cache
                    .complete_generic_pending(&cache_key, expected_cache_fingerprint, cache_entry)
                    .map(Some)
            }
            Ok(_) => self
                .remote_cache
                .write_with_validation_token(
                    &cache_key,
                    cache_entry,
                    cache_validation_token.as_deref(),
                )
                .map(|_| None),
            Err(error) => Err(error),
        };
        let mut status =
            remote_source_status_after_commit(&cache_key, cached_at, cache_result.as_ref().err());
        if matches!(
            cache_result,
            Ok(Some(PendingRemoteCacheCompletion::DurabilityUnknown))
        ) {
            status.last_error =
                Some("remote cache completion is visible but durability is unknown".into());
        }
        let mut split_warning = format!(
            "{reason}; local changes were saved to onedrive:{}",
            conflict_copy.display_name
        );
        if !conflict_copy.warnings.is_empty() {
            split_warning.push_str(&format!("; {}", conflict_copy.warnings.join("; ")));
        }
        status.last_error = Some(match status.last_error.take() {
            Some(cache_warning) => format!("{split_warning}; {cache_warning}"),
            None => split_warning,
        });
        match (vault, key) {
            (Some(vault), Some(key)) => {
                self.install_committed_generation(
                    vault_id,
                    vault,
                    bytes,
                    fingerprint,
                    Some(status),
                )?;
                {
                    let loaded = self
                        .vault_session
                        .find_loaded_mut(vault_id)
                        .with_context(|| format!("vault not opened: {vault_id}"))?;
                    loaded.provider_revision = Some(revision);
                    loaded.name = display_name;
                    loaded.source_account_label = Some(account_label);
                }
                self.replace_session_transformed_key(vault_id, key)
            }
            (None, None) => self.install_locked_generation(
                vault_id,
                bytes,
                fingerprint,
                Some(revision),
                save_profile,
                Some(status),
                Some(display_name),
                Some(account_label),
            ),
            _ => anyhow::bail!("OneDrive conflict head has inconsistent unlock state"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn preserve_source_refresh_conflict(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        display_name: &str,
        account_label: &str,
        baseline_fingerprint: &ContentIdentity,
        local_vault: &Vault,
        local_save_profile: &VaultEncodingProfile,
        key: &VaultKey,
        reason: &str,
    ) -> Result<SourceRefreshConflictDisposition> {
        let (bytes, verified_local) = Self::serialize_and_verify_vault_candidate(
            local_vault.clone(),
            key,
            local_save_profile.clone(),
        )
        .context("failed to serialize the source-refresh conflict copy")?;
        match self.publish_onedrive_conflict_copy_receipt(
            vault_id,
            drive_id,
            item_id,
            baseline_fingerprint,
            display_name,
            &bytes,
        ) {
            Ok(conflict_copy) => Ok(SourceRefreshConflictDisposition::UploadedConflictCopy {
                warning: format!(
                    "{reason}; local changes were saved to onedrive:{}",
                    conflict_copy.display_name
                ),
            }),
            Err(upload_error) => {
                self.save_conflict_copy_to_pending_cache(
                    vault_id,
                    VaultSource::OneDriveItem {
                        drive_id: drive_id.to_owned(),
                        item_id: item_id.to_owned(),
                    },
                    bytes,
                    baseline_fingerprint,
                    display_name.to_owned(),
                    Some(account_label.to_owned()),
                    format!(
                        "{reason}; conflict-copy upload failed and remains pending: {upload_error:#}"
                    ),
                )?;
                self.install_pending_vault_candidate(vault_id, verified_local)?;
                let status = self
                    .vault_session
                    .find_loaded(vault_id)
                    .and_then(|loaded| loaded.source_status.clone())
                    .context("pending source-refresh conflict did not install a source status")?;
                Ok(SourceRefreshConflictDisposition::Pending { status })
            }
        }
    }

    fn save_remote_vault_to_pending_cache(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        expected_cache_fingerprint: &ContentIdentity,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
        base_bytes: Vec<u8>,
    ) -> Result<RuntimeResponse> {
        self.save_remote_vault_to_pending_cache_with_base(
            vault_id,
            source,
            bytes,
            expected_cache_fingerprint,
            display_name,
            account_label,
            remote_error,
            Some(base_bytes),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_remote_vault_to_pending_cache_with_base(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        expected_cache_fingerprint: &ContentIdentity,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
        pending_base_bytes: Option<Vec<u8>>,
    ) -> Result<RuntimeResponse> {
        let cache_key = remote_cache_key_for_source(&source).context("source is not remote")?;
        let pending_kind = match self.remote_cache.read(&cache_key)? {
            Some(entry)
                if entry.pending_sync
                    && same_content_fingerprint(&entry.fingerprint, expected_cache_fingerprint) =>
            {
                self.remote_cache
                    .generic_pending_kind(&cache_key, expected_cache_fingerprint)?
            }
            _ => GenericPendingKind::SourceWrite,
        };
        self.save_remote_vault_to_pending_cache_with_kind(
            vault_id,
            source,
            bytes,
            expected_cache_fingerprint,
            display_name,
            account_label,
            remote_error,
            pending_kind,
            pending_base_bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_conflict_copy_to_pending_cache(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        expected_cache_fingerprint: &ContentIdentity,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
    ) -> Result<RuntimeResponse> {
        self.save_remote_vault_to_pending_cache_with_kind(
            vault_id,
            source,
            bytes,
            expected_cache_fingerprint,
            display_name,
            account_label,
            remote_error,
            GenericPendingKind::ConflictCopy,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_remote_vault_to_pending_cache_with_kind(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        expected_cache_fingerprint: &ContentIdentity,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
        pending_kind: GenericPendingKind,
        pending_base_bytes: Option<Vec<u8>>,
    ) -> Result<RuntimeResponse> {
        let cache_key = remote_cache_key_for_source(&source).context("source is not remote")?;
        let save_profile = self
            .inspected_save_profile(&bytes)
            .context("failed to inspect pending remote vault")?;
        let cached_at = self.current_unix_time() as i64;
        let fingerprint = fingerprint_for_cached_bytes(&bytes, cached_at);
        let account_label = account_label.unwrap_or_else(|| cache_key.provider_kind.clone());
        let pending_base = pending_base_bytes.map(|bytes| RemoteVaultCacheEntry {
            fingerprint: fingerprint_for_cached_bytes(&bytes, cached_at),
            bytes,
            display_name: display_name.clone(),
            account_label: account_label.clone(),
            cached_at,
            pending_sync: false,
            conflict_receipt_source: None,
        });
        let entry = RemoteVaultCacheEntry {
            bytes: bytes.clone(),
            fingerprint: fingerprint.clone(),
            display_name,
            account_label,
            cached_at,
            pending_sync: true,
            conflict_receipt_source: None,
        };
        match pending_kind {
            GenericPendingKind::SourceWrite => self.remote_cache.write_generic_pending_with_base(
                &cache_key,
                entry,
                expected_cache_fingerprint,
                pending_base,
            )?,
            GenericPendingKind::ConflictCopy => {
                let expected_kind = self
                    .remote_cache
                    .read(&cache_key)?
                    .filter(|current| {
                        current.pending_sync
                            && same_content_fingerprint(
                                &current.fingerprint,
                                expected_cache_fingerprint,
                            )
                    })
                    .map(|_| {
                        self.remote_cache
                            .generic_pending_kind(&cache_key, expected_cache_fingerprint)
                    })
                    .transpose()?;
                match expected_kind {
                    Some(GenericPendingKind::SourceWrite) => {
                        self.remote_cache.transition_source_write_to_conflict_copy(
                            &cache_key,
                            entry,
                            expected_cache_fingerprint,
                        )?
                    }
                    _ => self.remote_cache.write_conflict_copy_pending(
                        &cache_key,
                        entry,
                        expected_cache_fingerprint,
                    )?,
                }
            }
        }
        let status = VaultSourceStatusDto {
            source_kind: cache_key.provider_kind,
            remote_state: "pending_sync".into(),
            last_sync_at: None,
            cached_at: Some(cached_at),
            last_error: Some(remote_error),
        };
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.bytes = Vec::new();
        loaded.baseline_fingerprint = fingerprint;
        loaded.save_profile = save_profile;
        loaded.source_status = Some(status);
        Ok(RuntimeResponse::PublicationResult(PublicationResultDto {
            status: match pending_kind {
                GenericPendingKind::SourceWrite => PublicationStatusDto::Pending,
                GenericPendingKind::ConflictCopy => PublicationStatusDto::ConflictSplit,
            },
            reconciliation_summary: None,
            conflict_copy_path: (pending_kind == GenericPendingKind::ConflictCopy)
                .then(|| "onedrive:pending-conflict-copy".into()),
        }))
    }

    pub fn retry_vault_source_sync(&mut self, vault_id: &str) -> Result<VaultSourceStatusDto> {
        let (source, baseline_fingerprint, key, pending_sync) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            (
                loaded.source.clone(),
                loaded.baseline_fingerprint.clone(),
                transformed_key_from_loaded_vault(loaded).ok(),
                loaded
                    .source_status
                    .as_ref()
                    .is_some_and(|status| status.remote_state == "pending_sync"),
            )
        };

        let VaultSource::OneDriveItem { drive_id, item_id } = source.clone() else {
            return Ok(VaultSourceStatusDto {
                source_kind: "local".into(),
                remote_state: "unknown".into(),
                last_sync_at: None,
                cached_at: None,
                last_error: None,
            });
        };

        let cache_key = remote_cache_key_for_source(&source).expect("remote source");
        let cached_main = self.remote_cache.read(&cache_key)?;
        if let Some(receipt) =
            self.interrupted_onedrive_conflict_receipt(&drive_id, &item_id, cached_main.as_ref())?
        {
            let pending = self.promote_interrupted_onedrive_conflict_receipt(
                &cache_key,
                cached_main.as_ref(),
                receipt,
            )?;
            let cached_at = pending.cached_at;
            let recovery = self.retry_pending_remote_vault_sync(
                vault_id,
                &drive_id,
                &item_id,
                cache_key.clone(),
                pending.fingerprint,
                key,
            );
            let status = match recovery {
                Ok(status) => status,
                Err(error) => VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind.clone(),
                    remote_state: "pending_sync".into(),
                    last_sync_at: None,
                    cached_at: Some(cached_at),
                    last_error: Some(format!(
                        "interrupted Conflict Split remains pending: {error:#}"
                    )),
                },
            };
            if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                loaded.source_status = Some(status.clone());
            }
            return Ok(status);
        }
        let shared_pending = self
            .remote_cache
            .read(&cache_key)?
            .is_some_and(|entry| entry.pending_sync);
        if pending_sync || shared_pending {
            return self.retry_pending_remote_vault_sync(
                vault_id,
                &drive_id,
                &item_id,
                cache_key,
                baseline_fingerprint,
                key,
            );
        }
        match self.providers.remote_state(&drive_id, &item_id) {
            Ok(state) if state.matches_identity(&baseline_fingerprint) => {
                self.session_base_for_fingerprint(vault_id, &baseline_fingerprint)?;
                let cached = self.remote_cache.read(&cache_key)?;
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "online".into(),
                    last_sync_at: Some(self.current_unix_time() as i64),
                    cached_at: cached.as_ref().map(|entry| entry.cached_at),
                    last_error: None,
                };
                if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                Ok(status)
            }
            Ok(state) => {
                let snapshot =
                    read_onedrive_provider(&mut self.providers, &drive_id, &item_id, &state)?;
                let remote_save_profile = self
                    .inspected_save_profile(&snapshot.bytes)
                    .context("failed to inspect OneDrive generation during source refresh")?;
                let display_name = display_name_for_cloud_name(&snapshot.name);
                let mut refresh_warning = None;
                let patched_vault = match (
                    self.vault_session.find_loaded(vault_id).and_then(|loaded| {
                        loaded
                            .vault
                            .clone()
                            .map(|vault| (vault, loaded.save_profile.clone()))
                    }),
                    key,
                ) {
                    (Some((local_vault, local_save_profile)), Some(mut key)) => {
                        let base_bytes =
                            self.session_base_for_fingerprint(vault_id, &baseline_fingerprint)?;
                        let base_vault = Self::load_session_database(&base_bytes, &key)
                            .context("failed to parse synced base during source refresh")?
                            .vault;
                        let base_save_profile = self
                            .inspected_save_profile(&base_bytes)
                            .context("failed to inspect synced base during source refresh")?;
                        let remote_vault = match Self::load_session_database(&snapshot.bytes, &key)
                        {
                            Ok(database) => database.vault,
                            Err(VaultCodecError::KeyMismatch) => {
                                let (vault, refreshed_key) = self
                                    .refresh_transformed_key_from_unlock_blob(
                                        vault_id,
                                        &snapshot.bytes,
                                    )?
                                    .context(
                                        "OneDrive KDF changed and quick unlock is unavailable",
                                    )?;
                                key = refreshed_key;
                                vault
                            }
                            Err(error) => {
                                return Err(error).context(
                                    "failed to parse OneDrive generation during source refresh",
                                );
                            }
                        };
                        let selected = match Self::prepare_source_refresh_rebase(
                            &base_vault,
                            &local_vault,
                            &remote_vault,
                            &base_save_profile,
                            &local_save_profile,
                            &remote_save_profile,
                        ) {
                            Ok((patched, merged_save_profile)) => (patched, merged_save_profile),
                            Err(error) => match self.preserve_source_refresh_conflict(
                                vault_id,
                                &drive_id,
                                &item_id,
                                &display_name,
                                &snapshot.account_label,
                                &baseline_fingerprint,
                                &local_vault,
                                &local_save_profile,
                                key.as_ref(),
                                &format!("OneDrive source refresh conflict: {error:#}"),
                            )? {
                                SourceRefreshConflictDisposition::UploadedConflictCopy {
                                    warning,
                                } => {
                                    refresh_warning = Some(warning);
                                    (remote_vault, remote_save_profile.clone())
                                }
                                SourceRefreshConflictDisposition::Pending { status } => {
                                    return Ok(status);
                                }
                            },
                        };
                        Some((selected.0, key, selected.1))
                    }
                    _ => None,
                };
                let cached_at = self.current_unix_time() as i64;
                self.remote_cache.write(
                    &cache_key,
                    RemoteVaultCacheEntry {
                        bytes: snapshot.bytes.clone(),
                        fingerprint: snapshot.fingerprint.clone(),
                        display_name: display_name.clone(),
                        account_label: snapshot.account_label.clone(),
                        cached_at,
                        pending_sync: false,
                        conflict_receipt_source: None,
                    },
                )?;
                self.synced_bases
                    .store(vault_id, &snapshot.bytes)
                    .with_context(|| format!("failed to store synced base: {vault_id}"))?;
                self.session_bases
                    .store(vault_id, &snapshot.bytes)
                    .with_context(|| format!("failed to store session base: {vault_id}"))?;
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "online".into(),
                    last_sync_at: Some(cached_at),
                    cached_at: Some(cached_at),
                    last_error: refresh_warning,
                };

                let loaded = self
                    .vault_session
                    .find_loaded_mut(vault_id)
                    .with_context(|| format!("vault not opened: {vault_id}"))?;
                if let Some((patched_vault, transformed_key, save_profile)) = patched_vault {
                    loaded.vault = Some(patched_vault);
                    loaded.transformed_key = Some(transformed_key);
                    loaded.save_profile = save_profile;
                } else {
                    loaded.save_profile = remote_save_profile;
                }
                loaded.name = display_name;
                loaded.bytes = if loaded.vault.is_some() {
                    Vec::new()
                } else {
                    snapshot.bytes
                };
                loaded.baseline_fingerprint = snapshot.fingerprint;
                loaded.source_account_label = Some(snapshot.account_label);
                loaded.source_status = Some(status.clone());
                Ok(status)
            }
            Err(error) => {
                let remote_error = format_error_chain(&error);
                let cached = self.remote_cache.read(&cache_key)?;
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "cache".into(),
                    last_sync_at: None,
                    cached_at: cached.as_ref().map(|entry| entry.cached_at),
                    last_error: Some(remote_error),
                };
                if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                Ok(status)
            }
        }
    }

    fn retry_pending_remote_vault_sync(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        cache_key: RemoteCacheKey,
        baseline_fingerprint: ContentIdentity,
        key: Option<Arc<VaultKey>>,
    ) -> Result<VaultSourceStatusDto> {
        let sync_result = self.try_upload_pending_remote_vault(
            vault_id,
            drive_id,
            item_id,
            &cache_key,
            &baseline_fingerprint,
            key,
        );
        match sync_result {
            Ok(status) => Ok(status),
            Err(error) => {
                let remote_error = format_error_chain(&error);
                let cached_at = self
                    .remote_cache
                    .read(&cache_key)?
                    .map(|entry| entry.cached_at);
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "pending_sync".into(),
                    last_sync_at: None,
                    cached_at,
                    last_error: Some(remote_error),
                };
                if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                Ok(status)
            }
        }
    }

    fn try_upload_pending_remote_vault(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        cache_key: &RemoteCacheKey,
        pending_fingerprint: &ContentIdentity,
        key: Option<Arc<VaultKey>>,
    ) -> Result<VaultSourceStatusDto> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;
        let mut key = key.context("pending remote vault requires an unlocked vault")?;
        let pending = self
            .remote_cache
            .read(cache_key)?
            .context("pending remote cache generation is missing")?;
        if !pending.pending_sync || pending.fingerprint != *pending_fingerprint {
            anyhow::bail!("pending remote cache generation changed before synchronization");
        }
        let pending_vault = Self::load_session_database(&pending.bytes, &key)
            .context("failed to parse pending remote vault")?
            .vault;
        let pending_save_profile = self
            .inspected_save_profile(&pending.bytes)
            .context("failed to inspect pending remote vault")?;
        let (sanitized_pending_bytes, _) =
            Self::serialize_and_verify_vault_candidate(pending_vault, &key, pending_save_profile)
                .context("failed to migrate pending remote vault metadata")?;
        let (local_vault, local_save_profile) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_ref()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            (vault.clone(), loaded.save_profile.clone())
        };
        let local_conflict_key = key.clone();
        let serialize_live_conflict_copy = || {
            Self::serialize_and_verify_vault_candidate(
                local_vault.clone(),
                &local_conflict_key,
                local_save_profile.clone(),
            )
            .map(|(bytes, _)| bytes)
            .context("failed to verify live pending conflict copy")
        };
        if self
            .remote_cache
            .generic_pending_kind(cache_key, pending_fingerprint)?
            == GenericPendingKind::ConflictCopy
        {
            return self.upload_pending_onedrive_conflict_copy(
                vault_id,
                drive_id,
                item_id,
                cache_key,
                &pending,
                &sanitized_pending_bytes,
                key,
                "retrying a pending conflict-copy publication",
            );
        }
        let base_bytes =
            self.recover_generic_pending_base(vault_id, cache_key, pending_fingerprint)?;
        let base_vault = Self::load_session_database(&base_bytes, &key)
            .context("failed to parse synced base during pending synchronization")?
            .vault;
        let base_save_profile = self
            .inspected_save_profile(&base_bytes)
            .context("failed to inspect synced base during pending synchronization")?;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = self.providers.remote_state(drive_id, item_id)?;
            let remote = read_onedrive_provider(&mut self.providers, drive_id, item_id, &state)?;
            let remote_vault = match Self::load_session_database(&remote.bytes, &key) {
                Ok(database) => database.vault,
                Err(VaultCodecError::KeyMismatch) => {
                    let Some((vault, refreshed_key)) =
                        self.refresh_transformed_key_from_unlock_blob(vault_id, &remote.bytes)?
                    else {
                        let local_bytes = serialize_live_conflict_copy()?;
                        return self.upload_pending_onedrive_conflict_copy(
                            vault_id,
                            drive_id,
                            item_id,
                            cache_key,
                            &pending,
                            &local_bytes,
                            key.clone(),
                            "current OneDrive generation uses a different vault key",
                        );
                    };
                    key = refreshed_key;
                    vault
                }
                Err(error) => {
                    let local_bytes = serialize_live_conflict_copy()?;
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &local_bytes,
                        key.clone(),
                        &format!("current OneDrive generation cannot be parsed: {error}"),
                    );
                }
            };
            if !has_vaultkern_sync_lineage(&base_vault, &remote_vault) {
                let local_bytes = serialize_live_conflict_copy()?;
                return self.upload_pending_onedrive_conflict_copy(
                    vault_id,
                    drive_id,
                    item_id,
                    cache_key,
                    &pending,
                    &local_bytes,
                    key.clone(),
                    "current OneDrive generation has foreign or unclear writer lineage",
                );
            }
            let remote_save_profile = self
                .inspected_save_profile(&remote.bytes)
                .context("failed to inspect current OneDrive generation during pending sync")?;
            let merged_save_profile = match Self::merge_save_profile(
                &base_save_profile,
                &local_save_profile,
                &remote_save_profile,
            ) {
                Ok(profile) => profile,
                Err(error) => {
                    let local_bytes = serialize_live_conflict_copy()?;
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &local_bytes,
                        key.clone(),
                        &error.to_string(),
                    );
                }
            };
            let patched = match three_way_field_patch(&base_vault, &local_vault, &remote_vault) {
                Ok(patched) => patched,
                Err(error) => {
                    let local_bytes = serialize_live_conflict_copy()?;
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &local_bytes,
                        key.clone(),
                        &format!("pending changes cannot be represented: {error}"),
                    );
                }
            };
            if let Err(error) = ensure_patch_conflict_history_is_recoverable(
                &patched.vault,
                &patched.required_history_snapshots,
            ) {
                let local_bytes = serialize_live_conflict_copy()?;
                return self.upload_pending_onedrive_conflict_copy(
                    vault_id,
                    drive_id,
                    item_id,
                    cache_key,
                    &pending,
                    &local_bytes,
                    key.clone(),
                    &format!("pending changes exceed vault history retention: {error}"),
                );
            }
            let (bytes, verified_vault) = Self::serialize_and_verify_vault_candidate(
                patched.vault,
                &key,
                merged_save_profile,
            )
            .context("failed to verify pending OneDrive candidate")?;
            let cached_at = self.current_unix_time() as i64;
            let display_name = pending.display_name.clone();
            let account_label = pending.account_label.clone();
            let completion = {
                let one_drive = &mut self.providers;
                self.remote_cache.complete_generic_pending_while(
                    cache_key,
                    pending_fingerprint,
                    || {
                        let fingerprint = match publish_onedrive_provider(
                            one_drive, drive_id, item_id, &bytes, &state,
                        ) {
                            Ok(ConditionalPublication::Committed { fingerprint }) => fingerprint,
                            Ok(ConditionalPublication::StaleRevision) => {
                                return Err(PendingGenericCasConflict.into());
                            }
                            Ok(ConditionalPublication::OutcomeUnknown { message }) => {
                                anyhow::bail!(
                                    "pending OneDrive write outcome is unknown: {message}"
                                );
                            }
                            Err(error) => return Err(error.into()),
                        };
                        Ok((
                            fingerprint.clone(),
                            RemoteVaultCacheEntry {
                                bytes: bytes.clone(),
                                fingerprint,
                                display_name,
                                account_label,
                                cached_at,
                                pending_sync: false,
                                conflict_receipt_source: None,
                            },
                        ))
                    },
                )
            };
            match completion {
                Ok((write_fingerprint, completion)) => {
                    let status = VaultSourceStatusDto {
                        source_kind: cache_key.provider_kind.clone(),
                        remote_state: "online".into(),
                        last_sync_at: Some(cached_at),
                        cached_at: Some(cached_at),
                        last_error: matches!(
                            completion,
                            PendingRemoteCacheCompletion::DurabilityUnknown
                        )
                        .then(|| {
                            "remote cache completion is visible but durability is unknown".into()
                        }),
                    };
                    self.install_committed_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        write_fingerprint,
                        Some(status.clone()),
                    )?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(status);
                }
                Err(error)
                    if error.downcast_ref::<PendingGenericCasConflict>().is_some()
                        && attempt + 1 < MAX_SOURCE_ATTEMPTS =>
                {
                    continue;
                }
                Err(error) if error.downcast_ref::<PendingGenericCasConflict>().is_some() => {
                    return Err(error)
                        .context("Publication remains pending after repeated Stale Revision");
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded pending OneDrive attempts must return")
    }

    fn read_onedrive_conflict_head_for_adoption(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        mut key: Arc<VaultKey>,
    ) -> Result<(OneDriveConflictHead, Option<String>)> {
        let remote_state = self.providers.remote_state(drive_id, item_id)?;
        let remote = read_onedrive_provider(&mut self.providers, drive_id, item_id, &remote_state)?;
        let remote_save_profile = self
            .inspected_save_profile(&remote.bytes)
            .context("failed to inspect the current OneDrive head after conflict fallback")?;
        let (remote_vault, remote_key, locked_reason) = match Self::load_session_database(
            &remote.bytes,
            &key,
        ) {
            Ok(database) => (Some(database.vault), Some(key.clone()), None),
            Err(VaultCodecError::KeyMismatch) => {
                match self.refresh_transformed_key_from_unlock_blob(vault_id, &remote.bytes) {
                    Ok(Some((vault, refreshed_key))) => {
                        key = refreshed_key;
                        (Some(vault), Some(key.clone()), None)
                    }
                    Ok(None) => (
                        None,
                        None,
                        Some(
                            "current OneDrive head changed KDF and was adopted in locked state"
                                .to_owned(),
                        ),
                    ),
                    Err(error) => (
                        None,
                        None,
                        Some(format!(
                            "current OneDrive head was adopted in locked state after KDF refresh failed: {error:#}"
                        )),
                    ),
                }
            }
            Err(error) => (
                None,
                None,
                Some(format!(
                    "current OneDrive head was adopted in locked state after decode failed: {error}"
                )),
            ),
        };
        let remote_head = OneDriveConflictHead {
            vault: remote_vault,
            bytes: remote.bytes,
            fingerprint: remote.fingerprint,
            revision: remote_state.revision().clone(),
            cache_validation_token: remote.cache_validation_token,
            display_name: display_name_for_cloud_name(&remote.name),
            account_label: remote.account_label,
            save_profile: remote_save_profile,
            key: remote_key,
        };
        Ok((remote_head, locked_reason))
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_pending_onedrive_conflict_copy(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        _cache_key: &RemoteCacheKey,
        pending: &RemoteVaultCacheEntry,
        bytes: &[u8],
        key: Arc<VaultKey>,
        reason: &str,
    ) -> Result<VaultSourceStatusDto> {
        let conflict_copy = self.publish_onedrive_conflict_copy_receipt(
            vault_id,
            drive_id,
            item_id,
            &pending.fingerprint,
            &pending.display_name,
            bytes,
        )?;
        let (remote_head, locked_reason) =
            self.read_onedrive_conflict_head_for_adoption(vault_id, drive_id, item_id, key)?;
        let mut adoption_reason = reason.to_owned();
        if let Some(locked_reason) = locked_reason {
            adoption_reason.push_str(&format!("; {locked_reason}"));
        }
        self.adopt_onedrive_conflict_head(
            vault_id,
            drive_id,
            item_id,
            &pending.fingerprint,
            remote_head,
            &conflict_copy,
            &adoption_reason,
        )?;
        self.vault_session
            .find_loaded(vault_id)
            .and_then(|loaded| loaded.source_status.clone())
            .context("Conflict Split did not install a OneDrive source status")
    }

    fn loaded_vault(&self, vault_id: &str) -> Result<&Vault> {
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded
            .vault
            .as_ref()
            .with_context(|| format!("vault is locked: {vault_id}"))
    }

    fn read_current_snapshot(
        &mut self,
        vault_id: &str,
        baseline: Option<&ContentIdentity>,
    ) -> Result<LoadedSourceSnapshot> {
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        match &loaded.source {
            VaultSource::LocalPath(path) => {
                let snapshot = self
                    .providers
                    .local(path)
                    .read()
                    .with_context(|| format!("failed to read current vault source: {path}"))?;
                Ok(LoadedSourceSnapshot {
                    fingerprint: snapshot.identity,
                    bytes: Some(snapshot.bytes),
                    provider_revision: Some(snapshot.revision),
                })
            }
            VaultSource::OneDriveItem { drive_id, item_id } => {
                let state = self.providers.remote_state(drive_id, item_id)?;
                let provider_revision = state.revision().clone();
                if let Some(baseline) = baseline {
                    if state.matches_identity(baseline) {
                        return Ok(LoadedSourceSnapshot {
                            bytes: None,
                            fingerprint: baseline.clone(),
                            provider_revision: Some(provider_revision),
                        });
                    }
                }
                let snapshot = self
                    .providers
                    .read_onedrive_observation(drive_id, item_id, &state)?;
                let provider_revision = snapshot.revision.clone();
                Ok(LoadedSourceSnapshot {
                    bytes: Some(snapshot.bytes),
                    fingerprint: snapshot.fingerprint,
                    provider_revision: Some(provider_revision),
                })
            }
        }
    }

    fn write_local_source(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
        expected: &ProviderRevision,
    ) -> Result<(ProviderRevision, ContentIdentity)> {
        let source = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?
            .source
            .clone();
        let VaultSource::LocalPath(path) = source else {
            anyhow::bail!("OneDrive writes require the CAS save path")
        };
        let commit = self.providers.local(path).publish(expected, bytes)?;
        self.record_local_save_warnings(commit.warnings);
        Ok((commit.revision, commit.identity))
    }

    fn record_local_save_warnings(&mut self, warnings: Vec<String>) {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        for warning in warnings {
            write_local_save_warning(&mut stderr, &warning);
            #[cfg(test)]
            self.local_save_warnings.push(warning);
        }
    }

    fn current_unix_time(&self) -> u64 {
        self.fixed_unix_time.unwrap_or_else(current_unix_time)
    }

    fn current_unix_time_ms(&self) -> u64 {
        self.fixed_unix_time_ms.unwrap_or_else(current_unix_time_ms)
    }

    fn current_source_status(&self) -> Option<VaultSourceStatusDto> {
        if let Some(active_vault_id) = self.vault_session.active_vault_id() {
            return self
                .vault_session
                .find_loaded(active_vault_id)
                .and_then(|loaded| loaded.source_status.clone());
        }

        let current_vault_ref_id = self.vault_session.current_vault_ref_id()?;
        let source = self.references.source_for(current_vault_ref_id).ok()?;
        let vault_id = vault_id_for_stored_source(&source);
        self.vault_session
            .find_loaded(&vault_id)
            .and_then(|loaded| loaded.source_status.clone())
    }
}

#[allow(dead_code)]
fn _keep_protocol_types_linked(
    _groups: GroupTreeDto,
    _entries: EntryListDto,
    _detail: EntryDetailDto,
    _candidates: FillCandidateListDto,
    _credential: AutofillCredentialDto,
    _autofill_fields: AutofillEntryFieldsDto,
    _autofill_context: AutofillCreateContextDto,
) {
}

fn collect_group_entries(group: &vaultkern_core::GroupView, output: &mut Vec<EntrySummaryDto>) {
    output.extend(group.entries.iter().map(|entry| EntrySummaryDto {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: entry.url.clone(),
        group_id: group.id.clone(),
        has_totp: entry.has_totp,
    }));

    for child in &group.children {
        collect_group_entries(child, output);
    }
}

fn collect_fill_candidates(
    group: &vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    url: &str,
    next_index: &mut usize,
    output: &mut Vec<RankedFillCandidate>,
) {
    let group_recycled = group_is_recycled(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        ancestor_recycled,
    );
    for entry in &group.entries {
        if entry_is_recycled(entry, group_recycled) {
            continue;
        }

        let index = *next_index;
        *next_index += 1;

        if entry.password.is_empty() && entry.passkey.is_some() {
            continue;
        }

        if let Some(score) = score_origin_scoped_entry_match(url, &entry.url) {
            output.push(RankedFillCandidate {
                index,
                entry: EntrySummaryDto {
                    id: entry.id.to_string(),
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    url: entry.url.clone(),
                    group_id: group.id.to_string(),
                    has_totp: entry.totp.is_some(),
                },
                score,
            });
        }
    }

    for child in &group.children {
        collect_fill_candidates(
            child,
            recycle_bin_group,
            recycle_bin_enabled,
            group_recycled,
            url,
            next_index,
            output,
        );
    }
}

fn three_way_patch_summary(report: &ThreeWayPatchReport) -> ReconciliationSummaryDto {
    ReconciliationSummaryDto {
        merged_entries: report.merged_entries,
        history_snapshots_added: report.history_snapshots_added,
        meta_conflicts_resolved: report.meta_conflicts_resolved,
        icon_conflicts_resolved: report.icon_conflicts_resolved,
    }
}

fn entry_fields_for_vault(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> Result<EntryFieldsDto> {
    let mut detail = core.project_entry_detail(vault, entry_id)?;
    let totp_uri = core
        .project_entry_totp(vault, entry_id)?
        .as_ref()
        .map(|totp| totp_to_uri(&detail.title, &detail.username, totp));
    let custom_fields = core
        .list_entry_custom_fields(vault, entry_id)?
        .into_iter()
        .map(|mut field| EntryCustomFieldDto {
            key: std::mem::take(&mut field.key),
            value: std::mem::take(&mut field.value).into(),
            protected: field.protected,
        })
        .collect();
    Ok(EntryFieldsDto {
        title: std::mem::take(&mut detail.title).into(),
        username: std::mem::take(&mut detail.username).into(),
        password: std::mem::take(&mut detail.password).into(),
        url: std::mem::take(&mut detail.url).into(),
        notes: std::mem::take(&mut detail.notes).into(),
        totp_uri: totp_uri.map(Into::into),
        custom_fields,
    })
}

fn remote_source_status_after_commit(
    cache_key: &RemoteCacheKey,
    cached_at: i64,
    cache_error: Option<&anyhow::Error>,
) -> VaultSourceStatusDto {
    VaultSourceStatusDto {
        source_kind: cache_key.provider_kind.clone(),
        remote_state: "online".into(),
        last_sync_at: Some(cached_at),
        cached_at: cache_error.is_none().then_some(cached_at),
        last_error: cache_error.map(format_error_chain),
    }
}

fn same_content_fingerprint(left: &ContentIdentity, right: &ContentIdentity) -> bool {
    left.content_sha256 == right.content_sha256 && left.size_bytes == right.size_bytes
}

fn publish_onedrive_provider(
    providers: &mut ProviderCatalog,
    drive_id: &str,
    item_id: &str,
    bytes: &[u8],
    observed: &RemoteObservation,
) -> Result<ConditionalPublication, ProviderError> {
    providers.publish_onedrive_observation(drive_id, item_id, bytes, observed)
}

fn read_onedrive_provider(
    providers: &mut ProviderCatalog,
    drive_id: &str,
    item_id: &str,
    state: &RemoteObservation,
) -> Result<RemoteSnapshot> {
    providers.read_onedrive_observation(drive_id, item_id, state)
}

fn project_group_node(group: &vaultkern_core::GroupView) -> GroupNodeDto {
    GroupNodeDto {
        id: group.id.clone(),
        title: group.title.clone(),
        entry_count: group.entry_count,
        child_count: group.child_count,
        children: group.children.iter().map(project_group_node).collect(),
    }
}

fn entry_passkey_to_dto(passkey: vaultkern_core::EntryPasskeyView) -> EntryPasskeyDto {
    EntryPasskeyDto {
        username: passkey.username,
        credential_id: passkey.credential_id,
        generated_user_id: passkey.generated_user_id,
        relying_party: passkey.relying_party,
        user_handle: passkey.user_handle,
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    }
}

fn platform_passkey_credential(
    passkey: &PasskeyRecord,
    relying_party_name: &str,
    user_display_name: &str,
) -> Result<PlatformPasskeyCredential> {
    let credential_id = URL_SAFE_NO_PAD
        .decode(&passkey.credential_id)
        .context("stored platform passkey credential id was not base64url")?;
    if credential_id.is_empty() {
        anyhow::bail!("stored platform passkey credential id is empty");
    }
    let user_handle = URL_SAFE_NO_PAD
        .decode(
            passkey
                .user_handle
                .as_deref()
                .context("platform passkey credential has no discoverable user handle")?,
        )
        .context("stored platform passkey user handle was not base64url")?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        anyhow::bail!("stored platform passkey user handle has an invalid length");
    }
    Ok(PlatformPasskeyCredential {
        credential_id,
        relying_party: passkey.relying_party.clone(),
        relying_party_name: platform_credential_label(relying_party_name, &passkey.relying_party),
        user_handle,
        user_name: passkey.username.clone(),
        user_display_name: platform_credential_label(user_display_name, &passkey.username),
    })
}

fn platform_credential_label(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn set_platform_passkey_display_labels(
    core: &KeepassCore,
    vault: &mut Vault,
    entry_id: &str,
    relying_party_name: &str,
    user_display_name: &str,
) -> Result<()> {
    for (key, value) in [
        (PLATFORM_PASSKEY_RP_NAME_KEY, relying_party_name),
        (PLATFORM_PASSKEY_USER_DISPLAY_NAME_KEY, user_display_name),
    ] {
        core.upsert_entry_custom_data(
            vault,
            entry_id,
            EntryCustomDataInput {
                key: key.to_owned(),
                value: value.to_owned(),
            },
        )?;
    }
    Ok(())
}

fn clear_platform_passkey_display_labels(
    core: &KeepassCore,
    vault: &mut Vault,
    entry_id: &str,
) -> Result<()> {
    for key in [
        PLATFORM_PASSKEY_RP_NAME_KEY,
        PLATFORM_PASSKEY_USER_DISPLAY_NAME_KEY,
    ] {
        if entry_has_custom_data_key(&vault.root, entry_id, key) {
            core.delete_entry_custom_data(vault, entry_id, key)?;
        }
    }
    Ok(())
}

fn entry_has_custom_data_key(group: &vaultkern_core::Group, entry_id: &str, key: &str) -> bool {
    group
        .entries
        .iter()
        .find(|entry| entry.id.to_string() == entry_id)
        .is_some_and(|entry| entry.custom_data.contains_key(key))
        || group
            .children
            .iter()
            .any(|child| entry_has_custom_data_key(child, entry_id, key))
}

fn apply_passkey_metadata_update(
    passkey: EntryPasskeyUpdateDto,
    existing_passkey: Option<PasskeyRecord>,
) -> Result<PasskeyRecord> {
    validate_passkey_credential_id(&passkey.credential_id)?;
    if let Some(user_handle) = &passkey.user_handle {
        validate_passkey_user_handle(user_handle)?;
    }

    let mut existing_passkey =
        existing_passkey.context("passkey metadata can only update an existing passkey")?;
    let private_key_pem = std::mem::take(&mut existing_passkey.private_key_pem);
    if private_key_pem.trim().is_empty() {
        anyhow::bail!("passkey private key material is empty");
    }

    Ok(PasskeyRecord {
        username: passkey.username,
        credential_id: passkey.credential_id,
        generated_user_id: passkey.generated_user_id,
        private_key_pem,
        relying_party: passkey.relying_party,
        user_handle: passkey.user_handle,
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    })
}

fn cloned_entry_passkey_by_id(
    group: &vaultkern_core::Group,
    entry_id: &str,
) -> Option<PasskeyRecord> {
    for entry in &group.entries {
        if entry.id.to_string() == entry_id {
            return entry.passkey.clone();
        }
    }

    group
        .children
        .iter()
        .find_map(|child| cloned_entry_passkey_by_id(child, entry_id))
}

fn validate_passkey_credential_id(credential_id_base64url: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id_base64url)
        .context("invalid passkey credential id base64url")?;
    if bytes.is_empty() {
        anyhow::bail!("passkey credential id must not be empty");
    }
    Ok(())
}

fn validate_passkey_user_handle(user_handle_base64url: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(user_handle_base64url)
        .context("invalid passkey user handle base64url")?;
    if bytes.is_empty() || bytes.len() > 64 {
        anyhow::bail!("passkey user handle must be 1 to 64 bytes");
    }
    Ok(())
}

fn find_passkey_by_credential_id_and_relying_party<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    credential_id: &str,
    relying_party: Option<&str>,
) -> Option<&'a PasskeyRecord> {
    let mut found = None;
    visit_passkeys(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        &mut |passkey| {
            if found.is_none()
                && passkey.credential_id == credential_id
                && relying_party.is_none_or(|value| passkey.relying_party == value)
            {
                found = Some(passkey);
            }
        },
    );

    found
}

fn find_unique_passkey_by_credential_id_and_relying_party<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    credential_id: &str,
    relying_party: Option<&str>,
) -> Result<&'a PasskeyRecord> {
    let mut found = None;
    let mut count = 0usize;
    visit_passkeys(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        &mut |passkey| {
            if passkey.credential_id == credential_id
                && relying_party.is_none_or(|value| passkey.relying_party == value)
            {
                count += 1;
                if found.is_none() {
                    found = Some(passkey);
                }
            }
        },
    );

    match (count, found) {
        (0, _) => anyhow::bail!("passkey credential not found: {credential_id}"),
        (1, Some(passkey)) => Ok(passkey),
        _ => anyhow::bail!("multiple passkey credentials found for credential id: {credential_id}"),
    }
}

fn find_passkey_entry_id_by_relying_party_and_user_handle(
    group: &vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    relying_party: &str,
    user_handle: Option<&str>,
) -> Option<String> {
    find_passkey_entry_id_in_group(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        false,
        relying_party,
        user_handle,
    )
}

fn find_passkey_entry_id_in_group(
    group: &vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    relying_party: &str,
    user_handle: Option<&str>,
) -> Option<String> {
    let group_recycled = group_is_recycled(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        ancestor_recycled,
    );
    for entry in &group.entries {
        if entry_is_recycled(entry, group_recycled) {
            continue;
        }
        if let Some(passkey) = entry.passkey.as_ref()
            && passkey.relying_party == relying_party
            && passkey.user_handle.as_deref() == user_handle
        {
            return Some(entry.id.to_string());
        }
    }

    for child in &group.children {
        if let Some(found) = find_passkey_entry_id_in_group(
            child,
            recycle_bin_group,
            recycle_bin_enabled,
            group_recycled,
            relying_party,
            user_handle,
        ) {
            return Some(found);
        }
    }

    None
}

fn visit_passkeys<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    visitor: &mut impl FnMut(&'a PasskeyRecord),
) {
    visit_passkey_entries(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        &mut |_, passkey| visitor(passkey),
    );
}

fn visit_passkey_entries<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    visitor: &mut impl FnMut(&'a Entry, &'a PasskeyRecord),
) {
    visit_passkey_entries_in_group(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        false,
        visitor,
    );
}

fn visit_passkey_entries_in_group<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    visitor: &mut impl FnMut(&'a Entry, &'a PasskeyRecord),
) {
    let group_recycled = group_is_recycled(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        ancestor_recycled,
    );
    for entry in &group.entries {
        if !entry_is_recycled(entry, group_recycled)
            && let Some(passkey) = entry.passkey.as_ref()
        {
            visitor(entry, passkey);
        }
    }

    for child in &group.children {
        visit_passkey_entries_in_group(
            child,
            recycle_bin_group,
            recycle_bin_enabled,
            group_recycled,
            visitor,
        );
    }
}

fn group_is_recycled(
    group: &vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
) -> bool {
    ancestor_recycled || group_is_recycle_bin(group, recycle_bin_group, recycle_bin_enabled)
}

fn entry_is_recycled(_entry: &vaultkern_core::Entry, ancestor_recycled: bool) -> bool {
    // Entry.previous_parent is also written for ordinary moves by other clients;
    // only ancestor group state is a recycle signal here.
    ancestor_recycled
}

fn group_is_recycle_bin(
    group: &vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
) -> bool {
    recycle_bin_enabled
        && recycle_bin_group.is_some_and(|recycle_bin_group| group.id == recycle_bin_group)
}

fn entry_has_passkey_credential(
    group: &vaultkern_core::Group,
    entry_id: &str,
    credential_id: &str,
) -> Option<bool> {
    for entry in &group.entries {
        if entry.id.to_string() == entry_id {
            return Some(
                entry
                    .passkey
                    .as_ref()
                    .is_some_and(|passkey| passkey.credential_id == credential_id),
            );
        }
    }

    for child in &group.children {
        if let Some(found) = entry_has_passkey_credential(child, entry_id, credential_id) {
            return Some(found);
        }
    }

    None
}

fn cloned_entry_by_id(group: &vaultkern_core::Group, entry_id: &str) -> Option<Entry> {
    for entry in &group.entries {
        if entry.id.to_string() == entry_id {
            let mut cloned = entry.clone();
            cloned.history.clear();
            return Some(cloned);
        }
    }

    for child in &group.children {
        if let Some(found) = cloned_entry_by_id(child, entry_id) {
            return Some(found);
        }
    }

    None
}

fn restore_entry_from_snapshot(
    group: &mut vaultkern_core::Group,
    entry_id: &str,
    credential_id: Option<&str>,
    mut restored: Entry,
) -> Result<bool> {
    for entry in &mut group.entries {
        if entry.id.to_string() != entry_id {
            continue;
        }

        if credential_id.is_some_and(|credential_id| {
            entry
                .passkey
                .as_ref()
                .is_none_or(|passkey| passkey.credential_id != credential_id)
        }) {
            return Ok(true);
        }

        let mut retained_history = std::mem::take(&mut entry.history);
        if retained_history.last().is_some_and(|history| {
            history_matches_passkey_registration_rollback(entry, history, credential_id)
        }) {
            retained_history.pop();
        }
        restored.history = retained_history;
        *entry = restored;
        return Ok(true);
    }

    for child in &mut group.children {
        if restore_entry_from_snapshot(child, entry_id, credential_id, restored.clone())? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn restore_entry_from_latest_history(
    group: &mut vaultkern_core::Group,
    entry_id: &str,
    credential_id: Option<&str>,
) -> Result<bool> {
    for entry in &mut group.entries {
        if entry.id.to_string() != entry_id {
            continue;
        }

        if credential_id.is_some_and(|credential_id| {
            entry
                .passkey
                .as_ref()
                .is_none_or(|passkey| passkey.credential_id != credential_id)
        }) {
            return Ok(true);
        }
        let history = entry.history.last().with_context(|| {
            format!("passkey registration rollback history not found: {entry_id}")
        })?;
        if !history_matches_passkey_registration_rollback(entry, history, credential_id) {
            anyhow::bail!("passkey registration rollback history does not match: {entry_id}");
        }
        let mut restored = entry.history.pop().with_context(|| {
            format!("passkey registration rollback history not found: {entry_id}")
        })?;
        restored.history = std::mem::take(&mut entry.history);
        *entry = restored;
        return Ok(true);
    }

    for child in &mut group.children {
        if restore_entry_from_latest_history(child, entry_id, credential_id)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn history_matches_passkey_registration_rollback(
    current: &vaultkern_core::Entry,
    history: &vaultkern_core::Entry,
    credential_id: Option<&str>,
) -> bool {
    let Some(current_passkey) = current.passkey.as_ref() else {
        return false;
    };
    if credential_id.is_some_and(|credential_id| current_passkey.credential_id != credential_id) {
        return false;
    }
    let Some(history_passkey) = history.passkey.as_ref() else {
        return false;
    };

    history_passkey.relying_party == current_passkey.relying_party
        && history_passkey.user_handle == current_passkey.user_handle
        && history_passkey.credential_id != current_passkey.credential_id
}

fn save_kdbx_with_history_limits_transformed(
    vault: &mut Vault,
    transformed_key: &VaultKey,
    save_profile: VaultEncodingProfile,
) -> std::result::Result<Vec<u8>, VaultCodecError> {
    strip_retired_runtime_metadata(vault);
    let encoded = ResidentVaultCodec.encode(vault.clone(), transformed_key, save_profile)?;
    *vault = encoded.vault;
    Ok(encoded.bytes)
}

fn has_vaultkern_sync_lineage(base: &Vault, remote: &Vault) -> bool {
    base.root.id == remote.root.id
        && base.generator.as_deref() == Some(VAULT_WRITER_ID)
        && remote.generator.as_deref() == Some(VAULT_WRITER_ID)
}

pub(crate) fn ensure_patch_conflict_history_is_recoverable(
    patched: &Vault,
    required_history_snapshots: &[ThreeWayPatchRecoverySnapshot],
) -> Result<()> {
    if required_history_snapshots.is_empty() {
        return Ok(());
    }

    let mut retained = patched.clone();
    enforce_history_limits(&mut retained);
    let retained_entries = entries_by_id(&retained.root);

    for required in required_history_snapshots {
        let Some(retained_entry) = retained_entries.get(&required.entry_id) else {
            anyhow::bail!("retention removed the entry holding a conflict recovery snapshot");
        };
        if !retained_entry.history.contains(&required.snapshot) {
            anyhow::bail!(
                "retention would discard a required conflict recovery snapshot for entry {}",
                required.entry_id
            );
        }
    }
    Ok(())
}

fn entries_by_id(group: &vaultkern_core::Group) -> BTreeMap<Uuid, &Entry> {
    fn collect<'a>(group: &'a vaultkern_core::Group, entries: &mut BTreeMap<Uuid, &'a Entry>) {
        entries.extend(group.entries.iter().map(|entry| (entry.id, entry)));
        for child in &group.children {
            collect(child, entries);
        }
    }

    let mut entries = BTreeMap::new();
    collect(group, &mut entries);
    entries
}

fn database_settings_dto(
    vault: &Vault,
    profile: &VaultEncodingProfile,
    autosave_delay_seconds: Option<u32>,
    has_password: bool,
) -> Result<DatabaseSettingsDto> {
    Ok(DatabaseSettingsDto {
        metadata: DatabaseMetadataSettingsDto {
            name: vault.name.clone(),
            description: vault.description.clone(),
            default_username: vault.default_username.clone(),
        },
        public_metadata: DatabasePublicMetadataSettingsDto {
            display_name: public_string(vault, "display-name"),
            color: public_string(vault, "color"),
            icon: public_string(vault, "icon"),
        },
        history: DatabaseHistorySettingsDto {
            max_items_per_entry: vault.history_max_items,
            max_total_size_bytes: vault.history_max_size,
        },
        recycle_bin: DatabaseRecycleBinSettingsDto {
            enabled: vault.recycle_bin_enabled.unwrap_or(true),
        },
        encryption: encryption_settings_dto(vault, profile)?,
        autosave_delay_seconds,
        has_password,
    })
}

fn encryption_settings_dto(
    vault: &Vault,
    profile: &VaultEncodingProfile,
) -> Result<DatabaseEncryptionSettingsDto> {
    let settings = profile.encryption_settings(vault)?;
    Ok(DatabaseEncryptionSettingsDto {
        compression: match settings.compression {
            VaultCompression::None => "none",
            VaultCompression::Gzip => "gzip",
        }
        .into(),
        cipher: match settings.cipher {
            VaultCipher::Aes256 => "aes256",
            VaultCipher::ChaCha20 => "chacha20",
            VaultCipher::Twofish => "twofish",
        }
        .into(),
        kdf: match settings.kdf {
            VaultKdf::Aes { rounds } => DatabaseKdfSettingsDto {
                algorithm: "aes_kdbx4".into(),
                transform_rounds: Some(rounds),
                iterations: None,
                memory_kib: None,
                parallelism: None,
            },
            VaultKdf::Argon2d {
                iterations,
                memory_kib,
                parallelism,
            } => DatabaseKdfSettingsDto {
                algorithm: "argon2d".into(),
                transform_rounds: None,
                iterations: Some(iterations),
                memory_kib: Some(memory_kib),
                parallelism: Some(parallelism),
            },
            VaultKdf::Argon2id {
                iterations,
                memory_kib,
                parallelism,
            } => DatabaseKdfSettingsDto {
                algorithm: "argon2id".into(),
                transform_rounds: None,
                iterations: Some(iterations),
                memory_kib: Some(memory_kib),
                parallelism: Some(parallelism),
            },
        },
    })
}

fn vault_encryption_settings(
    settings: DatabaseEncryptionSettingsDto,
) -> Result<VaultEncryptionSettings> {
    let compression = match settings.compression.as_str() {
        "none" => VaultCompression::None,
        "gzip" => VaultCompression::Gzip,
        value => anyhow::bail!("unsupported compression setting: {value}"),
    };
    let cipher = match settings.cipher.as_str() {
        "aes256" => VaultCipher::Aes256,
        "chacha20" => VaultCipher::ChaCha20,
        "twofish" => VaultCipher::Twofish,
        value => anyhow::bail!("unsupported cipher setting: {value}"),
    };
    let kdf = match settings.kdf.algorithm.as_str() {
        "aes_kdbx4" => VaultKdf::Aes {
            rounds: settings
                .kdf
                .transform_rounds
                .context("aes_kdbx4 requires transform_rounds")?,
        },
        "argon2d" | "argon2id" => {
            let iterations = settings
                .kdf
                .iterations
                .with_context(|| format!("{} requires iterations", settings.kdf.algorithm))?;
            let memory_kib = settings
                .kdf
                .memory_kib
                .with_context(|| format!("{} requires memory_kib", settings.kdf.algorithm))?;
            let parallelism = settings
                .kdf
                .parallelism
                .with_context(|| format!("{} requires parallelism", settings.kdf.algorithm))?;
            if settings.kdf.algorithm == "argon2d" {
                VaultKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                }
            } else {
                VaultKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                }
            }
        }
        value => anyhow::bail!("unsupported kdf setting: {value}"),
    };

    Ok(VaultEncryptionSettings {
        compression,
        cipher,
        kdf,
    })
}

fn save_profile_from_settings(
    settings: DatabaseEncryptionSettingsDto,
) -> Result<VaultEncodingProfile> {
    Ok(VaultEncodingProfile::from_encryption_settings(
        vault_encryption_settings(settings)?,
    ))
}

fn public_string(vault: &Vault, key: &str) -> Option<String> {
    vault
        .public_custom_data
        .get(key)
        .map(|value| String::from_utf8_lossy(value).into_owned())
}

fn autosave_delay_seconds(vault: &Vault) -> Option<u32> {
    vault
        .public_custom_data
        .get(AUTOSAVE_DELAY_SECONDS_KEY)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse().ok())
}

fn upsert_optional_public_string(vault: &mut Vault, key: &str, value: Option<&str>) {
    match value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }) {
        Some(value) => {
            vault
                .public_custom_data
                .insert(key.to_owned(), value.as_bytes().to_vec());
        }
        None => {
            vault.public_custom_data.remove(key);
        }
    }
}

fn touch_entry_modified_at(
    core: &KeepassCore,
    vault: &mut Vault,
    entry_id: &str,
    modified_at: u64,
) -> Result<()> {
    core.update_entry_times(
        vault,
        entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(modified_at),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )?;
    Ok(())
}

fn initialize_entry_creation_times(
    core: &KeepassCore,
    vault: &mut Vault,
    entry_id: &str,
    creation_time: u64,
) -> Result<()> {
    let expiry_time = i64::try_from(creation_time).context("creation time exceeds i64")?;
    core.update_entry_expiry(
        vault,
        entry_id,
        vaultkern_core::EntryExpiryUpdate {
            expires: false,
            expiry_time: Some(expiry_time),
        },
    )?;
    core.update_entry_times(
        vault,
        entry_id,
        EntryTimesUpdate {
            created_at: Some(creation_time),
            modified_at: Some(creation_time),
            last_accessed_at: Some(Some(creation_time)),
            usage_count: Some(Some(0)),
            location_changed_at: Some(Some(creation_time)),
        },
    )?;
    Ok(())
}

fn totp_to_code(totp: &vaultkern_core::EntryTotpView, unix_time: u64) -> Option<String> {
    let spec = vaultkern_core::TotpSpec {
        secret_base32: totp.secret_base32.clone(),
        algorithm: totp.algorithm.clone(),
        digits: totp.digits,
        period_seconds: totp.period_seconds,
        issuer: totp.issuer.clone(),
        account_name: totp.account_name.clone(),
    };

    spec.generate_at(unix_time).ok()
}

fn totp_to_uri(title: &str, username: &str, totp: &vaultkern_core::EntryTotpView) -> String {
    let issuer = totp.issuer.clone().unwrap_or_else(|| title.to_owned());
    let account_name = totp
        .account_name
        .clone()
        .unwrap_or_else(|| username.to_owned());
    let label = if account_name.is_empty() {
        percent_encode_component(&issuer)
    } else {
        format!(
            "{}:{}",
            percent_encode_component(&issuer),
            percent_encode_component(&account_name)
        )
    };
    let algorithm = format!("{:?}", totp.algorithm).to_ascii_uppercase();

    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        label = label,
        secret = percent_encode_component(&totp.secret_base32),
        issuer = percent_encode_component(&issuer),
        algorithm = algorithm,
        digits = totp.digits,
        period = totp.period_seconds,
    )
}

fn percent_encode_component(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn current_unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn fingerprint_for_cached_bytes(bytes: &[u8], cached_at: i64) -> ContentIdentity {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    ContentIdentity {
        content_sha256,
        size_bytes: bytes.len() as u64,
        observation_marker: u64::try_from(cached_at).ok(),
    }
}

fn normalize_local_path(path: &str) -> Result<String> {
    Ok(fs::canonicalize(path)
        .with_context(|| format!("failed to resolve vault path: {path}"))?
        .display()
        .to_string())
}

fn vault_id_for_stored_source(source: &StoredVaultSource) -> String {
    match source {
        StoredVaultSource::LocalPath { path } => path.clone(),
        StoredVaultSource::OneDriveItem {
            drive_id, item_id, ..
        } => onedrive_vault_id(drive_id, item_id),
    }
}

fn remote_cache_key_for_source(source: &VaultSource) -> Option<RemoteCacheKey> {
    match source {
        VaultSource::LocalPath(_) => None,
        VaultSource::OneDriveItem { drive_id, item_id } => Some(RemoteCacheKey::new(
            "onedrive",
            &onedrive_remote_id(drive_id, item_id),
        )),
    }
}

fn remote_cache_keys_for_stored_source(source: &StoredVaultSource) -> Vec<RemoteCacheKey> {
    match source {
        StoredVaultSource::LocalPath { .. } => Vec::new(),
        StoredVaultSource::OneDriveItem {
            drive_id, item_id, ..
        } => vec![
            RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id)),
            onedrive_conflict_receipt_cache_key(drive_id, item_id),
        ],
    }
}

fn onedrive_conflict_receipt_cache_key(drive_id: &str, item_id: &str) -> RemoteCacheKey {
    RemoteCacheKey::new(
        "onedrive-conflict-receipt",
        &onedrive_remote_id(drive_id, item_id),
    )
}

fn display_name_for_cloud_name(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_owned()
}

fn transformed_key_from_loaded_vault(loaded: &LoadedVault) -> Result<Arc<VaultKey>> {
    loaded
        .transformed_key
        .clone()
        .context("vault session has no transformed key")
}

fn master_credential_from_parts(
    password: Option<&str>,
    key_file_path: Option<&str>,
) -> Result<MasterCredential> {
    let key_file_path = key_file_path
        .map(normalize_local_path)
        .transpose()
        .context("invalid key file path")?;
    let key_file_contribution = key_file_path
        .as_deref()
        .map(|key_file_path| {
            let bytes = Zeroizing::new(
                fs::read(key_file_path)
                    .with_context(|| format!("failed to read key file: {key_file_path}"))?,
            );
            parse_key_file_bytes(&bytes)
                .with_context(|| format!("failed to parse key file: {key_file_path}"))
        })
        .transpose()?;
    MasterCredential::new(password.map(str::as_bytes), key_file_contribution)
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}

fn ensure_primary_passkey_save(response: &RuntimeResponse) -> Result<()> {
    let RuntimeResponse::PublicationResult(result) = response else {
        anyhow::bail!("passkey mutation received an unexpected save response: {response:?}");
    };
    if result.status == PublicationStatusDto::ConflictSplit {
        return Err(LocalPublicationError::Conflict {
            message: format!(
                "passkey mutation was saved only to conflict copy: {}",
                result.conflict_copy_path.as_deref().unwrap_or("unknown")
            ),
        }
        .into());
    }
    Ok(())
}

fn quick_unlock_storage_key(vault_ref_id: &str) -> String {
    let digest = Sha256::digest(vault_ref_id.as_bytes());
    let mut key = String::from("quick_unlock_");
    for byte in digest {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

fn write_local_save_warning(destination: &mut impl std::io::Write, warning: &str) {
    let _ = writeln!(destination, "vaultkern local save warning: {warning}");
}

fn write_runtime_warning(warning: &str) {
    let stderr = std::io::stderr();
    let mut destination = stderr.lock();
    let _ = writeln!(destination, "vaultkern runtime warning: {warning}");
}

fn classified_runtime_error_response(error: &anyhow::Error) -> Option<RuntimeResponse> {
    let code = if let Some(provider_error) = error.downcast_ref::<ProviderError>() {
        match provider_error {
            ProviderError::StaleRevision { .. } | ProviderError::NotFound { .. } => "conflict",
            ProviderError::Unavailable { .. } => "persist_io_unavailable",
            ProviderError::OutcomeUnknown { .. } => "persist_outcome_unknown",
        }
    } else {
        match error.downcast_ref::<LocalPublicationError>() {
            Some(LocalPublicationError::Conflict { .. }) => "conflict",
            Some(LocalPublicationError::BeforePublish { .. }) => "persist_io_unavailable",
            Some(LocalPublicationError::OutcomeUnknown { .. }) => "persist_outcome_unknown",
            None => return None,
        }
    };
    Some(RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: format_error_chain(error),
    }))
}

pub(crate) fn query_error_response(error: anyhow::Error) -> RuntimeResponse {
    classified_runtime_error_response(&error).unwrap_or_else(|| {
        RuntimeResponse::Error(ErrorDto {
            code: "invalid_request".into(),
            message: format_error_chain(&error),
        })
    })
}

fn validate_passkey_ceremony_ttl(
    registered_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
    now_epoch_ms: u64,
) -> Result<()> {
    let ttl_ms = expires_at_epoch_ms
        .checked_sub(registered_at_epoch_ms)
        .context("invalid passkey ceremony ttl")?;
    if ttl_ms == 0
        || ttl_ms > 300_000
        || expires_at_epoch_ms <= now_epoch_ms
        || registered_at_epoch_ms > now_epoch_ms.saturating_add(5_000)
    {
        anyhow::bail!("invalid passkey ceremony ttl");
    }
    Ok(())
}

fn validate_passkey_ceremony_not_expired(
    entry: &PasskeyCeremonyLedgerEntry,
    now_epoch_ms: u64,
) -> Result<()> {
    if entry.identity.expires_at_epoch_ms <= now_epoch_ms {
        anyhow::bail!("passkey ceremony expired");
    }
    Ok(())
}

fn validate_passkey_ceremony_connection_id(connection_id: &str) -> Result<()> {
    if connection_id.trim().is_empty() || connection_id.len() > 256 {
        anyhow::bail!("invalid passkey ceremony connection id");
    }
    Ok(())
}

fn bind_passkey_ceremony_vault(
    entry: &mut PasskeyCeremonyLedgerEntry,
    vault_id: &str,
) -> Result<()> {
    validate_passkey_ceremony_vault_binding(entry, vault_id)?;
    if entry.vault_id.is_none() {
        entry.vault_id = Some(vault_id.to_owned());
    }
    Ok(())
}

fn validate_passkey_ceremony_vault_binding(
    entry: &PasskeyCeremonyLedgerEntry,
    vault_id: &str,
) -> Result<()> {
    if vault_id.trim().is_empty() {
        anyhow::bail!("passkey ceremony vault mismatch");
    }
    match entry.vault_id.as_deref() {
        Some(bound_vault_id) if bound_vault_id != vault_id => {
            anyhow::bail!("passkey ceremony vault mismatch");
        }
        Some(_) => {}
        None => {}
    }
    Ok(())
}

fn is_passkey_ceremony_vault_binding_phase(phase: PasskeyCeremonyPhaseDto) -> bool {
    matches!(
        phase,
        PasskeyCeremonyPhaseDto::UserAuthorization
            | PasskeyCeremonyPhaseDto::CredentialResolution
            | PasskeyCeremonyPhaseDto::UserSelection
    )
}

fn is_legal_passkey_ceremony_transition(
    expected_phase: PasskeyCeremonyPhaseDto,
    next_phase: PasskeyCeremonyPhaseDto,
    identity: &PasskeyCeremonyIdentity,
    related_origin_verified: bool,
) -> bool {
    use PasskeyCeremonyPhaseDto::*;

    if related_origin_verified
        && (expected_phase, next_phase) != (NetworkValidation, CredentialResolution)
    {
        return false;
    }

    if passkey_ceremony_active_transition_edges().contains(&(expected_phase, next_phase)) {
        return passkey_ceremony_active_transition_edge_allowed(
            expected_phase,
            next_phase,
            identity,
            related_origin_verified,
        );
    }

    match (expected_phase, next_phase) {
        (CompletionAndMutation, ClosedDelivered) => true,
        (PreAuthorization, ClosedAborted | ClosedFailed)
        | (UserAuthorization, ClosedAborted | ClosedFailed)
        | (NetworkValidation, ClosedAborted | ClosedFailed)
        | (CredentialResolution, ClosedAborted | ClosedFailed)
        | (UserSelection, ClosedAborted | ClosedFailed)
        | (CompletionAndMutation, ClosedAborted | ClosedFailed) => true,
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
struct PasskeyCeremonyTransitionContract {
    active_edges: Vec<[String; 2]>,
}

type PasskeyCeremonyActiveTransitionEdge = (PasskeyCeremonyPhaseDto, PasskeyCeremonyPhaseDto);

static PASSKEY_CEREMONY_ACTIVE_TRANSITION_EDGES: OnceLock<
    Vec<PasskeyCeremonyActiveTransitionEdge>,
> = OnceLock::new();

fn passkey_ceremony_active_transition_edges() -> &'static [PasskeyCeremonyActiveTransitionEdge] {
    PASSKEY_CEREMONY_ACTIVE_TRANSITION_EDGES
        .get_or_init(|| {
            let contract: PasskeyCeremonyTransitionContract =
                serde_json::from_str(include_str!("passkey_ceremony_transitions.json"))
                    .expect("passkey ceremony transition contract must parse");
            contract
                .active_edges
                .into_iter()
                .map(|[from, to]| {
                    (
                        passkey_ceremony_phase_from_contract_id(&from)
                            .expect("passkey transition from phase must be known"),
                        passkey_ceremony_phase_from_contract_id(&to)
                            .expect("passkey transition to phase must be known"),
                    )
                })
                .collect()
        })
        .as_slice()
}

fn passkey_ceremony_phase_from_contract_id(value: &str) -> Option<PasskeyCeremonyPhaseDto> {
    match value {
        "s0_pre_authorization" => Some(PasskeyCeremonyPhaseDto::PreAuthorization),
        "s1_user_authorization" => Some(PasskeyCeremonyPhaseDto::UserAuthorization),
        "s2_network_validation" => Some(PasskeyCeremonyPhaseDto::NetworkValidation),
        "s3_credential_resolution" => Some(PasskeyCeremonyPhaseDto::CredentialResolution),
        "s3b_user_selection" => Some(PasskeyCeremonyPhaseDto::UserSelection),
        "s4_completion_and_mutation" => Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
        _ => None,
    }
}

fn passkey_ceremony_active_transition_edge_allowed(
    expected_phase: PasskeyCeremonyPhaseDto,
    next_phase: PasskeyCeremonyPhaseDto,
    identity: &PasskeyCeremonyIdentity,
    related_origin_verified: bool,
) -> bool {
    use PasskeyCeremonyPhaseDto::*;

    match (expected_phase, next_phase) {
        (UserAuthorization, NetworkValidation) => !passkey_ceremony_origin_matches_relying_party(
            &identity.origin,
            &identity.relying_party,
        ),
        (UserAuthorization, CredentialResolution) => {
            passkey_ceremony_origin_matches_relying_party(&identity.origin, &identity.relying_party)
        }
        (NetworkValidation, CredentialResolution) => related_origin_verified,
        _ => true,
    }
}

fn is_stale_passkey_phase_advance_noop(
    current_phase: PasskeyCeremonyPhaseDto,
    expected_phase: PasskeyCeremonyPhaseDto,
    next_phase: PasskeyCeremonyPhaseDto,
) -> bool {
    expected_phase == PasskeyCeremonyPhaseDto::CompletionAndMutation
        && current_phase == next_phase
        && matches!(
            next_phase,
            PasskeyCeremonyPhaseDto::ClosedAborted
                | PasskeyCeremonyPhaseDto::ClosedDelivered
                | PasskeyCeremonyPhaseDto::ClosedFailed
        )
}

fn is_closed_passkey_ceremony_phase(phase: PasskeyCeremonyPhaseDto) -> bool {
    matches!(
        phase,
        PasskeyCeremonyPhaseDto::ClosedAborted
            | PasskeyCeremonyPhaseDto::ClosedDelivered
            | PasskeyCeremonyPhaseDto::ClosedFailed
    )
}

fn passkey_ceremony_origin_matches_relying_party(origin: &str, relying_party: &str) -> bool {
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = normalize_passkey_origin_host(host);
    let relying_party = relying_party
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if parsed.scheme() != "https" {
        return parsed.scheme() == "http"
            && is_passkey_loopback_host(&host)
            && is_passkey_loopback_host(&relying_party)
            && host == relying_party;
    }
    if is_passkey_loopback_host(&host) || is_passkey_loopback_host(&relying_party) {
        return is_passkey_loopback_host(&host)
            && is_passkey_loopback_host(&relying_party)
            && host == relying_party;
    }
    if host.parse::<std::net::IpAddr>().is_ok() || relying_party.parse::<std::net::IpAddr>().is_ok()
    {
        return host == relying_party;
    }
    if psl::domain_str(&relying_party).is_none() {
        return false;
    }
    host == relying_party || host.ends_with(&format!(".{relying_party}"))
}

fn validate_passkey_ceremony_challenge(challenge_base64url: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(challenge_base64url)
        .context("invalid passkey ceremony challenge")?;
    if bytes.is_empty() {
        anyhow::bail!("invalid passkey ceremony challenge");
    }
    Ok(())
}

fn validate_passkey_ceremony_origin_value(value: &str, label: &str) -> Result<()> {
    if value.trim() != value {
        anyhow::bail!("invalid passkey ceremony {label} origin");
    }
    let parsed = url::Url::parse(value)
        .with_context(|| format!("invalid passkey ceremony {label} origin"))?;
    let host = normalize_passkey_origin_host(
        parsed
            .host_str()
            .with_context(|| format!("invalid passkey ceremony {label} origin"))?,
    );
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("invalid passkey ceremony {label} origin");
    }
    if parsed.scheme() != "https" {
        if parsed.scheme() == "http" && is_passkey_loopback_host(&host) {
            return Ok(());
        }
        anyhow::bail!("passkey ceremony {label} origin must use https");
    }
    Ok(())
}

fn validate_passkey_ceremony_origin_and_relying_party_for_s0(
    origin: &str,
    relying_party: &str,
) -> Result<()> {
    validate_passkey_relying_party_id(relying_party)?;
    if origin.trim() != origin {
        anyhow::bail!("invalid passkey origin");
    }
    let parsed = url::Url::parse(origin).context("invalid passkey origin")?;
    let host = normalize_passkey_origin_host(
        parsed
            .host_str()
            .context("passkey origin is missing a host")?,
    );
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("invalid passkey origin");
    }
    let relying_party = relying_party
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if parsed.scheme() != "https" {
        if parsed.scheme() == "http"
            && is_passkey_loopback_host(&host)
            && is_passkey_loopback_host(&relying_party)
            && host == relying_party
        {
            return Ok(());
        }
        anyhow::bail!("passkey origin must use https");
    }

    if passkey_ceremony_origin_matches_relying_party(origin, &relying_party) {
        return Ok(());
    }

    if is_passkey_loopback_host(&host)
        || is_passkey_loopback_host(&relying_party)
        || host.parse::<std::net::IpAddr>().is_ok()
        || relying_party.parse::<std::net::IpAddr>().is_ok()
    {
        anyhow::bail!("passkey origin does not match relying party");
    }

    if psl::domain_str(&host).is_none() {
        anyhow::bail!("invalid passkey origin");
    }

    Ok(())
}

fn validate_passkey_relying_party_id(relying_party: &str) -> Result<()> {
    let value = relying_party.trim();
    if value.is_empty() || value != relying_party || value.ends_with('.') {
        anyhow::bail!("invalid passkey relying party id");
    }

    let canonical = value.to_ascii_lowercase();
    if value != canonical {
        anyhow::bail!("invalid passkey relying party id");
    }
    if is_passkey_loopback_host(&canonical) || canonical.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    if canonical.len() > 253
        || canonical.contains('/')
        || canonical.contains(':')
        || canonical.contains('@')
        || canonical.contains('?')
        || canonical.contains('#')
    {
        anyhow::bail!("invalid passkey relying party id");
    }

    if canonical.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    }) {
        anyhow::bail!("invalid passkey relying party id");
    }

    if psl::domain_str(&canonical).is_none() {
        anyhow::bail!("invalid passkey relying party id");
    }

    Ok(())
}

fn is_passkey_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn normalize_passkey_origin_host(host: &str) -> String {
    let canonical = host.trim().trim_end_matches('.').to_ascii_lowercase();
    canonical
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&canonical)
        .to_owned()
}

fn validate_passkey_ceremony_client_data(
    client_data_json_base64url: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    challenge_base64url: &str,
    top_origin: Option<&str>,
    ancestor_origins: &[String],
) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(client_data_json_base64url)
        .context("invalid passkey clientDataJSON encoding")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid passkey clientDataJSON")?;
    let expected_type = match ceremony {
        PasskeyCeremonyKindDto::Get => "webauthn.get",
        PasskeyCeremonyKindDto::Create => "webauthn.create",
    };
    if value.get("type").and_then(serde_json::Value::as_str) != Some(expected_type) {
        anyhow::bail!("passkey ceremony clientDataJSON type mismatch");
    }
    let client_origin = value.get("origin").and_then(serde_json::Value::as_str);
    if !client_origin.is_some_and(|client_origin| {
        passkey_ceremony_origins_are_same_origin(client_origin, origin)
    }) {
        anyhow::bail!("passkey ceremony clientDataJSON origin mismatch");
    }
    if value.get("challenge").and_then(serde_json::Value::as_str) != Some(challenge_base64url) {
        anyhow::bail!("passkey ceremony challenge mismatch");
    }
    let expected_cross_origin = top_origin
        .is_some_and(|top_origin| !passkey_ceremony_origins_are_same_origin(top_origin, origin))
        || ancestor_origins.iter().any(|ancestor_origin| {
            !passkey_ceremony_origins_are_same_origin(ancestor_origin, origin)
        });
    if value
        .get("crossOrigin")
        .and_then(serde_json::Value::as_bool)
        != Some(expected_cross_origin)
    {
        anyhow::bail!("passkey ceremony clientDataJSON crossOrigin mismatch");
    }
    let client_top_origin = value.get("topOrigin").and_then(serde_json::Value::as_str);
    if expected_cross_origin {
        if !matches!(
            (client_top_origin, top_origin),
            (Some(client_top_origin), Some(top_origin))
                if passkey_ceremony_origins_are_same_origin(client_top_origin, top_origin)
        ) {
            anyhow::bail!("passkey ceremony clientDataJSON topOrigin mismatch");
        }
    } else if value.get("topOrigin").is_some() {
        anyhow::bail!("passkey ceremony clientDataJSON topOrigin mismatch");
    }
    Ok(())
}

fn passkey_ceremony_origins_are_same_origin(left: &str, right: &str) -> bool {
    let (Some(left), Some(right)) = (
        passkey_ceremony_origin_url(left),
        passkey_ceremony_origin_url(right),
    ) else {
        return false;
    };
    left.scheme() == right.scheme()
        && left.host_str().map(|host| host.to_ascii_lowercase())
            == right.host_str().map(|host| host.to_ascii_lowercase())
        && left.port_or_known_default() == right.port_or_known_default()
}

fn passkey_ceremony_origin_url(value: &str) -> Option<url::Url> {
    if value.trim() != value {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return None;
    }
    Some(parsed)
}

fn take_sensitive_string(value: SensitiveString) -> String {
    let mut value = value.into_zeroizing();
    std::mem::take(&mut *value)
}

fn parse_totp_uri(value: Option<&str>) -> Result<Option<TotpSpec>> {
    match value {
        Some(uri) if !uri.trim().is_empty() => TotpSpec::parse_otpauth(&uri)
            .map(Some)
            .context("invalid otpauth uri"),
        Some(_) | None => Ok(None),
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(value)
        .with_context(|| "invalid base64 attachment content")
}

struct RankedFillCandidate {
    index: usize,
    entry: EntrySummaryDto,
    score: FillMatchScore,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::durable_file::{DurableFaultInjector, DurableFaultPoint};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use vaultkern_core::{
        CompositeKey, Compression, KdbxCipher, KdbxVersion, SaveKdf, SaveProfile,
    };
    use vaultkern_runtime_protocol::{
        DatabaseCredentialsUpdateDto, EntryIdListDto, EntryPasskeyUpdateDto,
    };
    use zeroize::Zeroizing;

    #[test]
    fn browser_runtime_rejects_vault_management_before_dispatch() {
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = VaultCore::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });

        for command in [
            RuntimeCommand::GetEntryDetail {
                vault_id: "missing-vault".into(),
                entry_id: "missing-entry".into(),
            },
            RuntimeCommand::UpdateDatabaseSettings {
                vault_id: "missing-vault".into(),
                update: DatabaseSettingsUpdateDto::default(),
            },
            RuntimeCommand::DeleteVaultReferenceIfNotCurrent {
                vault_ref_id: "missing-reference".into(),
            },
        ] {
            let error = runtime
                .handle_browser_command(command)
                .expect_err("browser management commands must fail at the resident boundary");
            assert!(
                error.to_string().contains("browser command forbidden"),
                "{error:#}"
            );
        }

        assert!(
            authorizations
                .lock()
                .expect("authorization lock")
                .is_empty(),
            "forbidden browser commands must not reach a platform prompt"
        );
    }

    #[test]
    fn browser_runtime_serves_allowed_status_without_hello() {
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = VaultCore::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });

        let response = runtime
            .handle_browser_command(RuntimeCommand::GetSessionState)
            .expect("authorized status should be answered");

        assert!(
            authorizations
                .lock()
                .expect("authorization lock")
                .is_empty(),
            "an authenticated browser channel must not require per-connection Hello"
        );
        assert!(matches!(response, RuntimeResponse::SessionState(_)));
    }

    #[test]
    fn ordinary_commit_removes_retired_autofill_receipt_metadata() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let mut vault = Vault::empty("Legacy receipt");
        core.upsert_vault_custom_data(
            &mut vault,
            vaultkern_core::CustomDataItemInput {
                key: vaultkern_core::RETIRED_AUTOFILL_RECEIPT_KEY.into(),
                value: r#"{"version":1,"receipts":[{"operationId":"old"}]}"#.into(),
            },
        )
        .expect("seed retired receipt metadata");

        let directory = tempfile::tempdir().expect("temporary vault directory");
        let path = directory.path().join("legacy-receipt.kdbx");
        fs::write(
            &path,
            core.save_kdbx(&vault, &key, SaveProfile::recommended())
                .expect("serialize legacy vault"),
        )
        .expect("write legacy vault");

        let mut runtime = VaultCore::for_tests();
        let opened = runtime
            .open_local_vault(path.to_str().expect("UTF-8 path"))
            .expect("open legacy vault");
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .expect("unlock legacy vault");
        assert!(
            runtime
                .loaded_vault(&opened.vault_id)
                .expect("loaded legacy vault")
                .meta_custom_data
                .contains_key(vaultkern_core::RETIRED_AUTOFILL_RECEIPT_KEY)
        );

        let response = runtime
            .handle(RuntimeCommand::CreateGroup {
                vault_id: opened.vault_id,
                parent_group_id: vault.root.id.to_string(),
                title: "Ordinary commit".into(),
            })
            .expect("ordinary mutation should commit");
        assert!(matches!(
            response,
            RuntimeResponse::VaultMutationResult(VaultMutationResultDto {
                commit: CommitStatusDto::Committed,
                ..
            })
        ));

        let rewritten = core
            .load_kdbx(&fs::read(path).expect("read rewritten vault"), &key)
            .expect("reload rewritten vault");
        assert!(
            !rewritten
                .meta_custom_data
                .contains_key(vaultkern_core::RETIRED_AUTOFILL_RECEIPT_KEY)
        );
    }

    #[test]
    fn browser_cancellation_interrupts_passkey_user_verification_too() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .expect("enroll quick unlock");
        runtime.biometric = Box::new(WaitingCancellableBiometricProvider {
            started: started_tx,
        });
        let request_cancelled = cancelled.clone();

        std::thread::spawn(move || {
            let result = runtime.verify_passkey_user_with_quick_unlock_cancellable(
                &opened.vault_id,
                request_cancelled.as_ref(),
            );
            let _ = result_tx.send(result.map_err(|error| error.to_string()));
        });

        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("passkey verification started");
        cancelled.store(true, Ordering::Release);
        let error = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("cancellation must release passkey verification")
            .expect_err("cancelled passkey verification must not succeed");
        assert!(error.contains("browser request was cancelled"), "{error}");
    }

    #[test]
    fn quick_unlock_reconciliation_credentials_are_redacted_and_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<QuickUnlockReconciliationCredentials>();
        let credentials = QuickUnlockReconciliationCredentials::from_protocol_input(
            Some("master-password".into()),
            Some("secret-key-file.keyx".into()),
        );
        assert_eq!(
            format!("{credentials:?}"),
            "QuickUnlockReconciliationCredentials([REDACTED])"
        );
        assert!(!format!("{credentials:?}").contains("master-password"));
    }

    trait CloneTestSecret {
        fn clone(&self) -> Self;
    }

    impl CloneTestSecret for SensitiveString {
        fn clone(&self) -> Self {
            self.as_str().to_owned().into()
        }
    }

    impl CloneTestSecret for EntryCustomFieldDto {
        fn clone(&self) -> Self {
            Self {
                key: self.key.clone(),
                value: CloneTestSecret::clone(&self.value),
                protected: self.protected,
            }
        }
    }

    impl CloneTestSecret for Vec<EntryCustomFieldDto> {
        fn clone(&self) -> Self {
            self.iter().map(CloneTestSecret::clone).collect()
        }
    }

    impl CloneTestSecret for Option<SensitiveString> {
        fn clone(&self) -> Self {
            self.as_ref().map(CloneTestSecret::clone)
        }
    }

    impl CloneTestSecret for EntryFieldsDto {
        fn clone(&self) -> Self {
            Self {
                title: CloneTestSecret::clone(&self.title),
                username: CloneTestSecret::clone(&self.username),
                password: CloneTestSecret::clone(&self.password),
                url: CloneTestSecret::clone(&self.url),
                notes: CloneTestSecret::clone(&self.notes),
                totp_uri: CloneTestSecret::clone(&self.totp_uri),
                custom_fields: CloneTestSecret::clone(&self.custom_fields),
            }
        }
    }

    #[test]
    fn invalid_totp_errors_do_not_echo_secret_uris() {
        let secret = "otpauth://totp/account?secret=must-not-leak&digits=0";
        let error = parse_totp_uri(Some(secret)).expect_err("invalid TOTP must be rejected");

        assert!(error.to_string().contains("invalid otpauth uri"));
        assert!(!format!("{error:#}").contains("must-not-leak"));
    }

    #[test]
    fn external_open_kdf_policy_is_bound_to_the_runtime_role() {
        let desktop = VaultCore::for_tests();
        assert_eq!(
            desktop.external_open_kdf_policy(),
            (
                vaultkern_core::ExternalKdfPolicy::Desktop,
                vaultkern_core::ExternalKdfConfirmation::Unconfirmed,
            )
        );

        let mut mobile = VaultCore::for_tests();
        mobile.resident_kdf_policy = ResidentKdfPolicy::Mobile;
        assert_eq!(
            mobile.external_open_kdf_policy(),
            (
                vaultkern_core::ExternalKdfPolicy::Mobile,
                vaultkern_core::ExternalKdfConfirmation::Unconfirmed,
            )
        );

        let mut extension = VaultCore::for_tests();
        extension.allow_unlock_kdf = false;
        assert_eq!(
            extension.external_open_kdf_policy(),
            (
                vaultkern_core::ExternalKdfPolicy::Extension,
                vaultkern_core::ExternalKdfConfirmation::Unconfirmed,
            )
        );
    }

    #[test]
    fn external_kdf_failures_preserve_machine_readable_policy_details() {
        let error = anyhow::Error::new(VaultCodecError::ExternalKdfPolicy {
            algorithm: VaultKdfAlgorithm::Argon2id,
            observed: 300 * 1024 * 1024,
            decision: VaultKdfDecision::Confirm(256 * 1024 * 1024),
        });

        let failure = super::classify_external_kdf_error(&error).unwrap();

        assert_eq!(failure.algorithm, "argon2id");
        assert_eq!(failure.resource, "memory_bytes");
        assert_eq!(failure.observed, 300 * 1024 * 1024);
        assert_eq!(failure.limit, Some(256 * 1024 * 1024));
        assert_eq!(
            failure.disposition,
            super::ExternalKdfDisposition::ConfirmationRequired
        );
    }

    #[test]
    fn save_helper_promotes_profiles_that_cannot_represent_the_vault() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("minimum-version");
        let profile = SaveProfile {
            version: KdbxVersion::V4_0,
            cipher: KdbxCipher::Aes256,
            compression: Compression::None,
            kdf: Some(SaveKdf::AesKdbx4 { rounds: 1 }),
        };
        let original = core
            .save_kdbx(&Vault::empty("minimum version"), &key, profile.clone())
            .expect("save initial vault");
        let transformed = ResidentVaultCodec
            .derive_key_with_policy(
                &original,
                &key,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed,
            )
            .expect("derive session key");
        let mut vault = ResidentVaultCodec
            .decode(&original, &transformed)
            .expect("load initial vault");
        let mut entry = Entry::new("excluded");
        entry.exclude_from_reports = true;
        vault.root.entries.push(entry);

        let bytes = save_kdbx_with_history_limits_transformed(
            &mut vault,
            &transformed,
            VaultEncodingProfile::from_test_profile(SaveProfile {
                kdf: None,
                ..profile
            }),
        )
        .expect("runtime save should promote the file version");
        let header = vaultkern_core::inspect_kdbx_header(&bytes).expect("inspect saved header");
        let loaded = ResidentVaultCodec
            .decode(&bytes, &transformed)
            .expect("reload promoted vault");

        assert_eq!(header.version, KdbxVersion::V4_1);
        assert!(loaded.root.entries[0].exclude_from_reports);
    }

    #[test]
    fn transformed_save_helper_reuses_the_loaded_kdf_without_master_credentials() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("session-only-save");
        let original = core
            .save_kdbx(
                &Vault::empty("session key"),
                &key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::Aes256,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 2 }),
                },
            )
            .unwrap();
        let transformed = ResidentVaultCodec
            .derive_key_with_policy(
                &original,
                &key,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed,
            )
            .unwrap();
        let mut vault = ResidentVaultCodec.decode(&original, &transformed).unwrap();
        vault.description = Some("edited without retaining the password".into());

        let saved = save_kdbx_with_history_limits_transformed(
            &mut vault,
            &transformed,
            VaultEncodingProfile::from_test_profile(SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::Aes256,
                compression: Compression::None,
                kdf: None,
            }),
        )
        .unwrap();
        let reloaded = ResidentVaultCodec.decode(&saved, &transformed).unwrap();
        let original_header = vaultkern_core::KdbxHeader::decode(&original).unwrap();
        let saved_header = vaultkern_core::KdbxHeader::decode(&saved).unwrap();

        assert_eq!(
            saved_header.kdf_parameters.encode().unwrap(),
            original_header.kdf_parameters.encode().unwrap()
        );
        assert_eq!(
            reloaded.description.as_deref(),
            Some("edited without retaining the password")
        );
    }

    #[test]
    fn conflict_recovery_snapshot_is_required_even_when_it_already_existed_in_history() {
        let mut base = Vault::empty("history retention");
        base.history_max_items = Some(0);
        let mut entry = Entry::new("account");
        entry.password = "base".into();
        entry.modified_at = 10;
        let entry_id = entry.id;

        let mut remote_loser = entry.clone();
        remote_loser.password = "remote".into();
        remote_loser.modified_at = 30;
        let mut recovery_snapshot = remote_loser.clone();
        vaultkern_core::prepare_entry_history_snapshot(&mut recovery_snapshot);
        entry.history.push(recovery_snapshot);
        base.root.entries.push(entry);

        let mut local = base.clone();
        local.root.entries[0].password = "local".into();
        local.root.entries[0].modified_at = 40;
        let mut remote = base.clone();
        remote.root.entries[0].password = "remote".into();
        remote.root.entries[0].modified_at = 30;

        let patched = three_way_field_patch(&base, &local, &remote).unwrap();
        assert_eq!(patched.report.history_snapshots_added, 0);
        assert!(
            ensure_patch_conflict_history_is_recoverable(
                &patched.vault,
                &patched.required_history_snapshots,
            )
            .is_err(),
            "retention must not erase the only recovery copy of the losing value for {entry_id}"
        );
    }

    #[test]
    fn runtime_reuses_kdf_for_ordinary_saves_and_requires_reauth_for_rotation() {
        fn retained_kdf(runtime: &VaultCore, vault_id: &str) -> Vec<u8> {
            let bytes = runtime
                .synced_bases
                .read(vault_id)
                .expect("read synced base")
                .expect("synced base");
            vaultkern_core::KdbxHeader::decode(&bytes)
                .expect("saved header")
                .kdf_parameters
                .encode()
                .expect("saved KDF dictionary")
        }

        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let original_generation = retained_kdf(&runtime, &opened.vault_id);
        let error = runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(DatabaseEncryptionSettingsDto {
                        compression: "gzip".into(),
                        cipher: "aes256".into(),
                        kdf: DatabaseKdfSettingsDto {
                            algorithm: "aes_kdbx4".into(),
                            transform_rounds: Some(1),
                            iterations: None,
                            memory_kib: None,
                            parallelism: None,
                        },
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect_err("explicit KDF rotation requires reauthentication");
        assert!(
            error
                .to_string()
                .contains("fresh authenticated credential-update flow")
        );
        assert_eq!(
            retained_kdf(&runtime, &opened.vault_id),
            original_generation
        );

        let mut compression_only = runtime
            .get_database_settings(&opened.vault_id)
            .expect("current database settings")
            .encryption;
        compression_only.compression = "none".into();
        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(compression_only),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect("change compression without changing the KDF");
        runtime
            .commit_working_copy(&opened.vault_id)
            .expect("compression-only save");
        assert_eq!(
            retained_kdf(&runtime, &opened.vault_id),
            original_generation
        );
    }

    #[test]
    fn database_settings_updates_advance_three_way_merge_timestamps() {
        let mut runtime = VaultCore::for_tests_at(200);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let base = runtime.loaded_vault(&opened.vault_id).unwrap().clone();

        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    metadata: Some(DatabaseMetadataSettingsDto {
                        name: "Local name".into(),
                        description: Some("Local description".into()),
                        default_username: Some("local-user".into()),
                    }),
                    public_metadata: Some(DatabasePublicMetadataSettingsDto {
                        display_name: Some("Local display name".into()),
                        color: Some("#112233".into()),
                        icon: Some("database".into()),
                    }),
                    history: Some(DatabaseHistorySettingsDto {
                        max_items_per_entry: Some(10),
                        max_total_size_bytes: Some(1_000_000),
                    }),
                    recycle_bin: Some(DatabaseRecycleBinSettingsDto { enabled: false }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();

        let local = runtime.loaded_vault(&opened.vault_id).unwrap().clone();
        assert_eq!(local.database_name_changed, Some(200));
        assert_eq!(local.description_changed, Some(200));
        assert_eq!(local.default_username_changed, Some(200));
        assert_eq!(local.settings_changed, Some(200));
        assert_eq!(local.recycle_bin_changed, Some(200));
        assert_eq!(local.root.title, base.root.title);
        assert_eq!(local.root.times, base.root.times);

        let mut remote = base.clone();
        remote.maintenance_history_days = Some(42);
        let merged = three_way_field_patch(&base, &local, &remote).unwrap();
        assert_eq!(merged.vault.name, "Local name");
        assert_eq!(merged.vault.maintenance_history_days, Some(42));
    }

    #[test]
    fn explicit_null_clears_the_autosave_delay() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Set(45),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect("set autosave delay");

        let clear_update: DatabaseSettingsUpdateDto = serde_json::from_value(serde_json::json!({
            "autosaveDelaySeconds": null
        }))
        .expect("deserialize an explicit clear");
        runtime
            .update_database_settings(&opened.vault_id, clear_update)
            .expect("clear autosave delay");

        assert_eq!(
            runtime
                .get_database_settings(&opened.vault_id)
                .expect("read database settings")
                .autosave_delay_seconds,
            None
        );
    }

    #[test]
    fn autosave_delay_set_and_clear_roundtrip_through_kdbx() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: opened.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Set(45),
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("persist autosave delay");

        drop(runtime);
        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.path).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            reopened
                .get_database_settings(&handle.vault_id)
                .unwrap()
                .autosave_delay_seconds,
            Some(45)
        );

        reopened
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: handle.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Clear,
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("persist cleared autosave delay");
        drop(reopened);

        let mut cleared = VaultCore::for_tests();
        let handle = cleared.open_local_vault(&opened.path).unwrap();
        cleared
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            cleared
                .get_database_settings(&handle.vault_id)
                .unwrap()
                .autosave_delay_seconds,
            None
        );
    }

    #[test]
    fn database_settings_command_rolls_back_the_model_when_persistence_fails() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let before = runtime
            .get_database_settings(&opened.vault_id)
            .expect("database settings before failed commit");
        let model_before = runtime
            .loaded_vault(&opened.vault_id)
            .expect("vault model before failed commit")
            .clone();
        let source_before = std::fs::read(&opened.path).expect("source before failed commit");
        arm_local_write_fault(&mut runtime, DurableFaultPoint::BeforeTargetReplace);

        let response = runtime
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: opened.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    metadata: Some(DatabaseMetadataSettingsDto {
                        name: "must not leak from a failed commit".into(),
                        description: before.metadata.description.clone(),
                        default_username: before.metadata.default_username.clone(),
                    }),
                    history: Some(DatabaseHistorySettingsDto {
                        max_items_per_entry: Some(0),
                        max_total_size_bytes: Some(0),
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("settings failures are protocol responses");

        assert!(matches!(response, RuntimeResponse::Error(_)));
        assert_eq!(
            runtime
                .get_database_settings(&opened.vault_id)
                .expect("database settings after failed commit"),
            before
        );
        assert_eq!(
            runtime
                .loaded_vault(&opened.vault_id)
                .expect("vault model after failed commit"),
            &model_before
        );
        assert_eq!(
            std::fs::read(&opened.path).expect("source after failed commit"),
            source_before
        );
    }

    #[test]
    fn onedrive_settings_unknown_commit_is_confirmed_before_base_cache_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_101);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        runtime.queue_test_onedrive_ambiguous_write(true);
        runtime.session_bases.fail_next_store_for_tests();

        let result = runtime
            .commit_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Set(37),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect("a read-back-confirmed remote commit must not become a settings failure");

        assert_eq!(result.settings.autosave_delay_seconds, Some(37));
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let remote_vault = ResidentVaultCodec.decode(&remote, &transformed).unwrap();
        assert_eq!(autosave_delay_seconds(&remote_vault), Some(37));
    }

    #[test]
    fn onedrive_unknown_commit_with_unavailable_readback_survives_session_base_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_102);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        runtime.queue_test_onedrive_ambiguous_write_with_unavailable_readback(true);
        runtime.session_bases.fail_next_store_for_tests();

        let response = runtime
            .commit_working_copy(&vault_id)
            .expect("the candidate and its durable base must remain pending");

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        assert_eq!(
            runtime
                .remote_cache
                .read(&RemoteCacheKey::new("onedrive", "drive-1:item-1"))
                .unwrap()
                .expect("durable pending candidate")
                .pending_sync,
            true
        );

        let status = runtime
            .retry_vault_source_sync(&vault_id)
            .expect("the durable synced base must repair the missing session base");
        assert_eq!(status.remote_state, "online");
        assert_eq!(runtime.list_entries(&vault_id).unwrap().len(), 1);
    }

    #[test]
    fn onedrive_unknown_commit_retries_a_transient_pending_cache_publish_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_103);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let cache_root = runtime
            .remote_cache
            .paths_for_tests(&cache_key)
            .metadata_path
            .parent()
            .unwrap()
            .to_path_buf();
        runtime.remote_cache = RemoteVaultCache::new_at_with_faults(
            cache_root,
            DurableFaultInjector::fail_once(DurableFaultPoint::ManifestTempCreated),
        );
        runtime.queue_test_onedrive_ambiguous_write_with_unavailable_readback(true);

        let response = runtime
            .commit_working_copy(&vault_id)
            .expect("a transient pending-cache failure must be retried before giving up");

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        let pending = runtime
            .remote_cache
            .read(&cache_key)
            .unwrap()
            .expect("pending candidate after retry");
        assert!(pending.pending_sync);
        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();
        assert_eq!(status.remote_state, "online");
    }

    #[test]
    fn failed_conflict_upload_leaves_a_receipt_intent_that_retry_completes() {
        let mut runtime = demo_onedrive_runtime(1_700_000_105);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let mut metadata = runtime.get_database_settings(&vault_id).unwrap().metadata;
        metadata.name = "local conflict candidate".into();
        runtime
            .update_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    metadata: Some(metadata),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        let mut foreign_key = CompositeKey::default();
        foreign_key.add_password("demo-password");
        let foreign = runtime
            .core
            .save_kdbx(
                &Vault::empty("foreign"),
                &foreign_key,
                SaveProfile::recommended(),
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);
        runtime.fail_next_test_onedrive_conflict_copy();

        let response = runtime.commit_working_copy(&vault_id).unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        let receipt_key = onedrive_conflict_receipt_cache_key("drive-1", "item-1");
        assert!(
            runtime
                .remote_cache
                .read(&receipt_key)
                .unwrap()
                .expect("durable conflict-copy intent")
                .pending_sync
        );

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();
        assert_eq!(status.remote_state, "online", "{status:?}");
        assert!(
            runtime
                .vault_session
                .find_loaded(&vault_id)
                .is_some_and(|loaded| loaded.vault.is_none()),
            "a Remote Head without an available transformed key is adopted locked"
        );
        assert!(
            !runtime
                .remote_cache
                .read(&receipt_key)
                .unwrap()
                .expect("published conflict-copy receipt")
                .pending_sync
        );
    }

    #[test]
    fn published_onedrive_conflict_copy_retains_local_and_adopts_remote_locked() {
        let mut runtime = demo_onedrive_runtime(1_700_000_106);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        {
            let loaded = runtime.vault_session.find_loaded_mut(&vault_id).unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            let core = KeepassCore::new();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            vault.history_max_items = Some(1);
        }
        let mut foreign_key = CompositeKey::default();
        foreign_key.add_password("foreign-password");
        let foreign = runtime
            .core
            .save_kdbx(
                &Vault::empty("foreign"),
                &foreign_key,
                SaveProfile::recommended(),
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign.clone());

        let response = runtime.commit_working_copy(&vault_id).unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        let loaded = runtime.vault_session.find_loaded(&vault_id).unwrap();
        assert!(loaded.vault.is_none());
        assert_eq!(loaded.bytes, foreign);
        assert_eq!(
            runtime.session_bases.read(&vault_id).unwrap().unwrap(),
            foreign
        );

        runtime
            .unlock_with_password(&vault_id, "foreign-password")
            .unwrap();
        assert_eq!(runtime.loaded_vault(&vault_id).unwrap().name, "foreign");

        let receipt = runtime
            .remote_cache
            .read(&onedrive_conflict_receipt_cache_key("drive-1", "item-1"))
            .unwrap()
            .expect("published Conflict Copy receipt");
        let mut local_key = CompositeKey::default();
        local_key.add_password("demo-password");
        let local_copy = runtime
            .core
            .load_kdbx(&receipt.bytes, &local_key)
            .expect("decode retained Local Conflict Copy");
        assert_eq!(
            local_copy.root.entries[0].history.len(),
            1,
            "the durable Conflict Copy must contain the exact retained Local model"
        );
    }

    #[test]
    fn pending_conflict_copy_reopens_without_a_separate_synced_base() {
        let mut runtime = demo_onedrive_runtime(1_700_000_105);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        let mut foreign_key = CompositeKey::default();
        foreign_key.add_password("foreign-password");
        let foreign = runtime
            .core
            .save_kdbx(
                &Vault::empty("foreign"),
                &foreign_key,
                SaveProfile::recommended(),
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);
        runtime.fail_next_test_onedrive_conflict_copy();

        let response = runtime.commit_working_copy(&vault_id).unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        runtime.synced_bases.delete(&vault_id).unwrap();
        runtime.vault_session.remove_loaded(&vault_id);

        runtime
            .load_source_snapshot(StoredVaultSource::OneDriveItem {
                drive_id: "drive-1".into(),
                item_id: "item-1".into(),
                account_label: "alice@example.com".into(),
            })
            .expect("the durable pending conflict copy is sufficient to reopen the vault");
        let loaded = runtime.vault_session.find_loaded(&vault_id).unwrap();
        assert!(
            loaded
                .source_status
                .as_ref()
                .is_some_and(|status| status.remote_state == "pending_sync")
        );
    }

    #[test]
    fn pending_source_write_reopens_from_its_authenticated_base_without_a_synced_base() {
        let mut runtime = demo_onedrive_runtime(1_700_000_105);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        runtime.queue_test_onedrive_ambiguous_write(false);
        runtime.commit_working_copy(&vault_id).unwrap();
        runtime.synced_bases.delete(&vault_id).unwrap();
        runtime.vault_session.remove_loaded(&vault_id);

        runtime
            .load_source_snapshot(StoredVaultSource::OneDriveItem {
                drive_id: "drive-1".into(),
                item_id: "item-1".into(),
                account_label: "alice@example.com".into(),
            })
            .expect("the pending manifest carries its authenticated fixed Base");
        let loaded = runtime.vault_session.find_loaded(&vault_id).unwrap();
        assert!(
            loaded
                .source_status
                .as_ref()
                .is_some_and(|status| status.remote_state == "pending_sync")
        );
        assert!(runtime.session_bases.read(&vault_id).unwrap().is_some());
    }

    #[test]
    fn deleting_a_vault_reference_retires_its_published_conflict_receipt() {
        let mut runtime = demo_onedrive_runtime(1_700_000_106);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let mut metadata = runtime.get_database_settings(&vault_id).unwrap().metadata;
        metadata.name = "local conflict candidate".into();
        runtime
            .update_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    metadata: Some(metadata),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        let mut foreign_key = CompositeKey::default();
        foreign_key.add_password("demo-password");
        let foreign = runtime
            .core
            .save_kdbx(
                &Vault::empty("foreign"),
                &foreign_key,
                SaveProfile::recommended(),
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        let receipt_key = onedrive_conflict_receipt_cache_key("drive-1", "item-1");
        assert!(runtime.remote_cache.read(&receipt_key).unwrap().is_some());
        let vault_ref_id = runtime
            .references
            .list_recent_vaults()
            .unwrap()
            .vaults
            .into_iter()
            .next()
            .unwrap()
            .vault_ref_id;

        runtime.delete_vault_reference(&vault_ref_id).unwrap();
        assert!(runtime.remote_cache.read(&receipt_key).unwrap().is_none());
    }

    #[test]
    fn database_settings_conflict_copy_is_not_acknowledged_as_a_commit() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let before = runtime
            .get_database_settings(&opened.vault_id)
            .expect("settings before conflict");
        std::fs::remove_file(&opened.path).expect("remove active source");

        let response = runtime
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: opened.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    metadata: Some(DatabaseMetadataSettingsDto {
                        name: "must remain a draft".into(),
                        description: None,
                        default_username: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("settings conflicts are protocol responses");

        let RuntimeResponse::Error(error) = response else {
            panic!("conflict-copy settings must fail, got {response:?}");
        };
        assert!(error.message.contains("conflict copy"), "{error:?}");
        assert_eq!(
            runtime.get_database_settings(&opened.vault_id).unwrap(),
            before
        );
    }

    #[test]
    fn database_settings_conflict_splits_then_retry_targets_adopted_remote() {
        let mut runtime = demo_onedrive_runtime(1_700_000_107);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let before = runtime.get_database_settings(&vault_id).unwrap();
        let mut foreign_key = CompositeKey::default();
        foreign_key.add_password("demo-password");
        let foreign = runtime
            .core
            .save_kdbx(
                &Vault::empty("foreign"),
                &foreign_key,
                SaveProfile::recommended(),
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);
        let update = || DatabaseSettingsUpdateDto {
            metadata: Some(DatabaseMetadataSettingsDto {
                name: "desired local settings".into(),
                description: before.metadata.description.clone(),
                default_username: before.metadata.default_username.clone(),
            }),
            ..DatabaseSettingsUpdateDto::default()
        };

        let first = runtime
            .commit_database_settings(&vault_id, update())
            .expect_err("conflict copy is not an active-vault settings commit");
        assert!(format!("{first:#}").contains("conflict copy"));
        assert!(
            runtime
                .vault_session
                .find_loaded(&vault_id)
                .is_some_and(|loaded| loaded.vault.is_none())
        );
        runtime
            .unlock_with_password(&vault_id, "demo-password")
            .expect("unlock the adopted Remote Head");
        assert_eq!(
            runtime
                .get_database_settings(&vault_id)
                .unwrap()
                .metadata
                .name,
            "foreign"
        );
        let second = runtime
            .commit_database_settings(&vault_id, update())
            .expect("retry applies to the adopted Remote Head");
        assert_eq!(
            second.publication.status,
            PublicationStatusDto::Published,
            "{second:?}"
        );
        assert_eq!(second.settings.metadata.name, "desired local settings");

        let RuntimeResponse::OneDriveItemList(list) = runtime
            .handle(RuntimeCommand::ListOneDriveChildren {
                parent_item_id: None,
            })
            .unwrap()
        else {
            panic!("expected OneDrive item list");
        };
        assert_eq!(
            list.items
                .iter()
                .filter(|item| item.name.contains("VaultKern conflict"))
                .count(),
            1
        );
    }

    #[test]
    fn database_settings_reconcile_a_published_local_outcome_unknown() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .providers
            .replace_local_file_with_write_faults(DurableFaultInjector::fail_once(
                DurableFaultPoint::LocalFinalReadback,
            ));

        let committed = runtime
            .commit_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Set(47),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect("readback must reconcile the published settings as committed");
        assert_eq!(committed.settings.autosave_delay_seconds, Some(47));
        assert_eq!(
            runtime
                .get_database_settings(&opened.vault_id)
                .unwrap()
                .autosave_delay_seconds,
            Some(47)
        );
        drop(runtime);

        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.vault_id).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            reopened
                .get_database_settings(&handle.vault_id)
                .unwrap()
                .autosave_delay_seconds,
            Some(47)
        );
    }

    #[test]
    fn onedrive_pending_conflict_copy_does_not_acknowledge_database_settings() {
        let mut runtime = demo_onedrive_runtime(1_700_000_103);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let before = runtime.get_database_settings(&vault_id).unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut foreign = ResidentVaultCodec.decode(&remote, &transformed).unwrap();
        foreign.root.id = Uuid::new_v4();
        let foreign = save_kdbx_with_history_limits_transformed(
            &mut foreign,
            &transformed,
            VaultEncodingProfile::from_test_profile(SaveProfile {
                kdf: None,
                ..SaveProfile::recommended()
            }),
        )
        .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);
        runtime.fail_next_test_onedrive_conflict_copy();

        let error = runtime
            .commit_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    autosave_delay_seconds: OptionalSettingUpdateDto::Set(44),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect_err("pending conflict-copy recovery is not an active-source commit");

        assert!(error.to_string().contains("conflict copy"));
        assert_eq!(runtime.get_database_settings(&vault_id).unwrap(), before);
        let pending_fingerprint = runtime
            .vault_session
            .find_loaded(&vault_id)
            .unwrap()
            .baseline_fingerprint
            .clone();
        assert_eq!(
            runtime
                .remote_cache
                .generic_pending_kind(
                    &RemoteCacheKey::new("onedrive", "drive-1:item-1"),
                    &pending_fingerprint,
                )
                .unwrap(),
            GenericPendingKind::ConflictCopy
        );
    }

    #[test]
    fn database_settings_command_acknowledges_a_verified_published_generation() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        arm_local_backup_loss_after_publish(&mut runtime, &opened.path);

        let response = runtime
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: opened.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    metadata: Some(DatabaseMetadataSettingsDto {
                        name: "published but indeterminate".into(),
                        description: None,
                        default_username: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("published settings saves are protocol responses");

        let RuntimeResponse::DatabaseSettingsCommitResult(result) = response else {
            panic!("expected durable settings result, got {response:?}");
        };
        assert_eq!(result.settings.metadata.name, "published but indeterminate");
        assert_eq!(result.publication.status, PublicationStatusDto::Published);
        assert_eq!(
            runtime
                .get_database_settings(&opened.vault_id)
                .expect("settings after durable commit")
                .metadata
                .name,
            "published but indeterminate"
        );

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let persisted = KeepassCore::new()
            .load_kdbx(
                &std::fs::read(&opened.path).expect("read indeterminate source"),
                &key,
            )
            .expect("load visible published settings");
        assert_eq!(persisted.name, "published but indeterminate");
    }

    #[test]
    fn database_settings_command_returns_only_after_the_settings_are_durable() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);

        let response = runtime
            .handle(RuntimeCommand::UpdateDatabaseSettings {
                vault_id: opened.vault_id.clone(),
                update: DatabaseSettingsUpdateDto {
                    metadata: Some(DatabaseMetadataSettingsDto {
                        name: "durable settings".into(),
                        description: None,
                        default_username: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            })
            .expect("commit database settings");

        let RuntimeResponse::DatabaseSettingsCommitResult(result) = response else {
            panic!("expected committed database settings response");
        };
        assert_eq!(result.settings.metadata.name, "durable settings");
        assert_eq!(result.publication.status, PublicationStatusDto::Published);

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let saved = KeepassCore::new()
            .load_kdbx(
                &std::fs::read(&opened.path).expect("read committed source"),
                &key,
            )
            .expect("load committed source");
        assert_eq!(saved.name, "durable settings");
    }

    #[test]
    fn unlock_adopts_loaded_cipher_compression_and_kdf_settings() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("loaded-profile");
        let source = core
            .save_kdbx(
                &Vault::empty("loaded profile"),
                &key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::ChaCha20,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 1 }),
                },
            )
            .expect("save source");
        let source_kdf = vaultkern_core::KdbxHeader::decode(&source)
            .expect("source header")
            .kdf_parameters
            .encode()
            .expect("source KDF");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("loaded-profile.kdbx");
        std::fs::write(&path, source).expect("write source");
        let mut runtime = VaultCore::for_tests();
        let opened = runtime
            .open_local_vault(path.to_str().expect("UTF-8 path"))
            .expect("open source");
        runtime
            .unlock_vault(&opened.vault_id, Some("loaded-profile"), None)
            .expect("unlock source");

        let settings = runtime
            .get_database_settings(&opened.vault_id)
            .expect("loaded settings");
        assert_eq!(settings.encryption.cipher, "chacha20");
        assert_eq!(settings.encryption.compression, "none");
        assert_eq!(settings.encryption.kdf.algorithm, "aes_kdbx4");
        assert_eq!(settings.encryption.kdf.transform_rounds, Some(1));

        runtime
            .commit_working_copy(&opened.vault_id)
            .expect("ordinary save");
        let rewritten = std::fs::read(path).expect("read rewritten source");
        let rewritten_header =
            vaultkern_core::KdbxHeader::decode(&rewritten).expect("saved header");
        assert_eq!(rewritten_header.cipher, KdbxCipher::ChaCha20);
        assert_eq!(rewritten_header.compression, Compression::None);
        assert_eq!(
            rewritten_header
                .kdf_parameters
                .encode()
                .expect("rewritten KDF"),
            source_kdf
        );
    }

    #[test]
    fn external_open_reports_confirmation_before_running_a_high_cost_kdf() {
        let mut parameters = vaultkern_core::VariantDictionary::default();
        parameters.insert(
            "$UUID",
            vaultkern_core::VariantValue::Bytes(
                uuid::Uuid::from_bytes([
                    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00,
                    0x69, 0x2E, 0xB7,
                ])
                .into_bytes()
                .to_vec(),
            ),
        );
        parameters.insert("R", vaultkern_core::VariantValue::UInt64(600_000_001));
        parameters.insert("S", vaultkern_core::VariantValue::Bytes(vec![0; 32]));
        let mut header = vaultkern_core::KdbxHeader::new(
            vaultkern_core::KdbxVersion::V4_1,
            vaultkern_core::KdbxCipher::Aes256,
        );
        header.encryption_iv = vec![0; 16];
        header.kdf_parameters = parameters;
        let header_bytes = header.encode().expect("encode header");
        let mut bytes = header_bytes.clone();
        bytes.extend(Sha256::digest(&header_bytes));
        bytes.extend([0; 32]);

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("high-cost.kdbx");
        std::fs::write(&path, bytes).expect("write external database");
        let mut runtime = VaultCore::for_tests();
        let opened = runtime
            .open_local_vault(path.to_str().expect("UTF-8 path"))
            .expect("open file handle");
        let error = runtime
            .unlock_vault(&opened.vault_id, Some("password"), None)
            .expect_err("unconfirmed desktop policy must stop before the KDF");

        assert!(
            format_error_chain(&error).contains("external KDF policy Confirm(600000000)"),
            "unexpected error: {}",
            format_error_chain(&error)
        );
    }

    #[test]
    fn onedrive_component_boundaries_do_not_alias_vault_or_cache_ids() {
        let left = VaultSource::OneDriveItem {
            drive_id: "drive:tenant".into(),
            item_id: "item".into(),
        };
        let right = VaultSource::OneDriveItem {
            drive_id: "drive".into(),
            item_id: "tenant:item".into(),
        };

        assert_ne!(left.vault_id(), right.vault_id());
        assert_ne!(
            remote_cache_key_for_source(&left),
            remote_cache_key_for_source(&right)
        );
    }

    struct LoadRejectingSecureStorageProvider {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl LoadRejectingSecureStorageProvider {
        fn new() -> Self {
            Self {
                values: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SecureStorageProvider for LoadRejectingSecureStorageProvider {
        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.values
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn load(&self, _key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            anyhow::bail!("quick unlock secret should not be decrypted while listing vaults")
        }

        fn contains(&self, key: &str) -> Result<bool> {
            Ok(self.values.borrow().contains_key(key))
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }

    struct PresenceLoadingSecureStorageProvider {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl PresenceLoadingSecureStorageProvider {
        fn new() -> Self {
            Self {
                values: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SecureStorageProvider for PresenceLoadingSecureStorageProvider {
        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.values
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.values.borrow().get(key).cloned().map(Zeroizing::new))
        }

        fn contains(&self, key: &str) -> Result<bool> {
            Ok(self.values.borrow().contains_key(key))
        }

        fn load_requires_user_presence(&self) -> bool {
            true
        }

        fn store_requires_user_presence(&self) -> bool {
            true
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }

    struct LoadPresenceOnlySecureStorageProvider {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl LoadPresenceOnlySecureStorageProvider {
        fn new() -> Self {
            Self {
                values: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SecureStorageProvider for LoadPresenceOnlySecureStorageProvider {
        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.values
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.values.borrow().get(key).cloned().map(Zeroizing::new))
        }

        fn contains(&self, key: &str) -> Result<bool> {
            Ok(self.values.borrow().contains_key(key))
        }

        fn load_requires_user_presence(&self) -> bool {
            true
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }

    struct EarlyAuthorizingSecureStorageProvider {
        authorizations: Arc<AtomicUsize>,
        stores: Arc<AtomicUsize>,
        values: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl EarlyAuthorizingSecureStorageProvider {
        fn new(authorizations: Arc<AtomicUsize>, stores: Arc<AtomicUsize>) -> Self {
            Self {
                authorizations,
                stores,
                values: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SecureStorageProvider for EarlyAuthorizingSecureStorageProvider {
        fn authorize_store_user_presence(&self) -> Result<()> {
            self.authorizations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.stores.fetch_add(1, Ordering::SeqCst);
            self.values
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.values.borrow().get(key).cloned().map(Zeroizing::new))
        }

        fn contains(&self, key: &str) -> Result<bool> {
            Ok(self.values.borrow().contains_key(key))
        }

        fn store_requires_user_presence(&self) -> bool {
            true
        }

        fn load_requires_user_presence(&self) -> bool {
            true
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }

    struct ParentWindowRecordingSecureStorageProvider {
        parent_window: Arc<Mutex<Option<usize>>>,
    }

    impl SecureStorageProvider for ParentWindowRecordingSecureStorageProvider {
        fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
            *self.parent_window.lock().expect("parent window lock") = parent_window;
        }

        fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
            Ok(())
        }

        fn load(&self, _key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(None)
        }

        fn contains(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }

        fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingBiometricProvider {
        authorizations: Arc<Mutex<Vec<String>>>,
    }

    impl BiometricProvider for CountingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, reason: &str) -> Result<()> {
            self.authorizations
                .lock()
                .expect("authorization lock")
                .push(reason.to_owned());
            Ok(())
        }
    }

    struct WaitingCancellableBiometricProvider {
        started: std::sync::mpsc::SyncSender<()>,
    }

    impl BiometricProvider for WaitingCancellableBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, _reason: &str) -> Result<()> {
            panic!("browser verification must use the cancellable provider entrypoint")
        }

        fn authorize_cancellable(&self, _reason: &str, cancelled: &AtomicBool) -> Result<()> {
            self.started
                .send(())
                .expect("publish biometric verification start");
            while !cancelled.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            anyhow::bail!("browser request was cancelled")
        }
    }

    struct RecordingBiometricProvider {
        authorized_at_epoch_ms: Arc<Mutex<Option<u64>>>,
    }

    impl BiometricProvider for RecordingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, _reason: &str) -> Result<()> {
            std::thread::sleep(std::time::Duration::from_millis(25));
            *self
                .authorized_at_epoch_ms
                .lock()
                .expect("authorization timestamp lock") = Some(current_unix_time_ms());
            Ok(())
        }
    }

    fn open_unlocked_demo_vault(runtime: &mut VaultCore) -> (tempfile::TempDir, VaultHandleDto) {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        (dir, opened)
    }

    #[test]
    fn full_credential_unlock_installs_transformed_key_and_discards_file_bytes() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let loaded = runtime.vault_session.find_loaded(&opened.vault_id).unwrap();

        assert!(loaded.bytes.is_empty());
        assert!(
            runtime
                .session_bases
                .read(&opened.vault_id)
                .unwrap()
                .is_some()
        );
        assert!(loaded.transformed_key.is_some());
        assert_eq!(
            loaded.credential_shape,
            MasterCredentialShape {
                has_password: true,
                has_key_file: false,
            }
        );
    }

    #[test]
    fn source_refresh_of_an_unlocked_vault_discards_downloaded_file_bytes() {
        let mut runtime = demo_onedrive_runtime(1_700_000_001);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let current = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut credential = CompositeKey::default();
        credential.add_password("demo-password");
        let transformed = ResidentVaultCodec
            .derive_key_with_policy(
                &current,
                &credential,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed,
            )
            .unwrap();
        let mut remote = KeepassCore::new().load_kdbx(&current, &credential).unwrap();
        remote.description = Some("remote refresh".into());
        let save_profile = runtime.inspected_save_profile(&current).unwrap();
        let remote_bytes =
            save_kdbx_with_history_limits_transformed(&mut remote, &transformed, save_profile)
                .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);
        runtime
            .session_bases
            .delete(&vault_id)
            .expect("delete the recoverable in-process base");

        assert_eq!(
            runtime
                .retry_vault_source_sync(&vault_id)
                .unwrap()
                .remote_state,
            "online"
        );

        let loaded = runtime.vault_session.find_loaded(&vault_id).unwrap();
        assert!(loaded.vault.is_some());
        assert!(loaded.bytes.is_empty());
    }

    #[test]
    fn quick_unlock_refreshes_the_single_blob_after_a_source_salt_change() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime.lock_session();

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let replacement = KeepassCore::new()
            .save_kdbx(
                &Vault::empty("rotated-salt"),
                &key,
                SaveProfile::recommended(),
            )
            .unwrap();
        std::fs::write(&opened.path, replacement).unwrap();

        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        let loaded = runtime.vault_session.find_loaded(&opened.vault_id).unwrap();
        assert_eq!(loaded.vault.as_ref().unwrap().name, "rotated-salt");
        assert!(loaded.transformed_key.is_some());
        assert!(loaded.bytes.is_empty());

        runtime.lock_session();
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        assert_eq!(
            runtime
                .vault_session
                .find_loaded(&opened.vault_id)
                .unwrap()
                .vault
                .as_ref()
                .unwrap()
                .name,
            "rotated-salt"
        );
    }

    fn arm_source_change_after_merge_snapshot(
        runtime: &mut VaultCore,
        opened: &VaultHandleDto,
    ) -> Vec<u8> {
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let generation_b = KeepassCore::new()
            .save_kdbx(
                &Vault::empty("external-generation"),
                &key,
                SaveProfile::recommended(),
            )
            .unwrap();
        let path = opened.path.clone();
        let replacement = generation_b.clone();
        runtime
            .providers
            .replace_local_file_with_before_write_hook(std::sync::Arc::new(move || {
                std::fs::write(&path, &replacement).unwrap()
            }));
        generation_b
    }

    fn arm_source_deletion_after_merge_snapshot(runtime: &mut VaultCore, opened: &VaultHandleDto) {
        let path = opened.path.clone();
        runtime
            .providers
            .replace_local_file_with_before_write_hook(std::sync::Arc::new(move || {
                std::fs::remove_file(&path).unwrap()
            }));
    }

    fn arm_local_write_fault(runtime: &mut VaultCore, point: DurableFaultPoint) {
        runtime
            .providers
            .replace_local_file_with_write_faults(DurableFaultInjector::fail_once(point));
    }

    fn arm_local_backup_loss_after_publish(runtime: &mut VaultCore, source_path: &str) {
        let parent = Path::new(source_path)
            .parent()
            .expect("vault source parent")
            .to_owned();
        runtime
            .providers
            .replace_local_file_with_write_faults(DurableFaultInjector::run_once(
                DurableFaultPoint::TargetReplaced,
                move || {
                    let backup = std::fs::read_dir(&parent)
                        .expect("read vault source parent")
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .find(|path| {
                            path.file_name()
                                .is_some_and(|name| name.to_string_lossy().contains(".bak."))
                        })
                        .expect("published local backup");
                    std::fs::remove_file(backup).expect("remove published local backup");
                },
            ));
    }

    #[test]
    fn save_after_source_change_during_commit_writes_a_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let generation_b = arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .commit_working_copy(&opened.vault_id)
            .expect("source change after the merge snapshot must be recoverable");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, PublicationStatusDto::ConflictSplit);
        assert_eq!(std::fs::read(&opened.path).unwrap(), generation_b);
        assert!(
            Path::new(
                result
                    .conflict_copy_path
                    .as_deref()
                    .expect("conflict-copy path")
            )
            .exists()
        );
    }

    #[test]
    fn save_after_source_change_preserves_the_source_and_writes_a_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let external = KeepassCore::new()
            .save_kdbx(
                &Vault::empty("external-generation"),
                &key,
                SaveProfile::recommended(),
            )
            .unwrap();
        std::fs::write(&opened.path, &external).unwrap();

        let response = runtime
            .commit_working_copy(&opened.vault_id)
            .expect("source change should take the recoverable conflict path");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, PublicationStatusDto::ConflictSplit);
        assert_eq!(std::fs::read(&opened.path).unwrap(), external);
        let conflict_path = result.conflict_copy_path.expect("conflict-copy path");
        assert_eq!(
            Path::new(&conflict_path).parent(),
            Path::new(&opened.path).parent()
        );
        let conflict_bytes = std::fs::read(conflict_path).unwrap();
        let conflict_vault = KeepassCore::new().load_kdbx(&conflict_bytes, &key).unwrap();
        assert_eq!(conflict_vault.root.entries.len(), 1);
        let loaded = runtime.vault_session.find_loaded(&opened.vault_id).unwrap();
        assert!(loaded.vault.is_none());
        assert_eq!(loaded.bytes, external);
        assert_eq!(
            runtime
                .session_bases
                .read(&opened.vault_id)
                .unwrap()
                .unwrap(),
            external
        );
        runtime
            .unlock_with_password(&opened.vault_id, "demo-password")
            .expect("unlock adopted external generation");
        assert_eq!(
            runtime.loaded_vault(&opened.vault_id).unwrap().name,
            "external-generation"
        );
    }

    #[test]
    fn save_after_source_deletion_writes_a_recoverable_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        std::fs::remove_file(&opened.path).unwrap();

        let response = runtime
            .commit_working_copy(&opened.vault_id)
            .expect("missing source should take the recoverable conflict path");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, PublicationStatusDto::ConflictSplit);
        assert!(!Path::new(&opened.path).exists());
        let conflict_path = result.conflict_copy_path.expect("conflict-copy path");
        let conflict_bytes = std::fs::read(conflict_path).unwrap();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let conflict_vault = KeepassCore::new().load_kdbx(&conflict_bytes, &key).unwrap();
        assert_eq!(conflict_vault.root.entries.len(), 1);
    }

    #[test]
    fn local_write_returns_the_provider_revision() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let expected = runtime
            .providers
            .local(&opened.path)
            .read()
            .unwrap()
            .revision;

        let (committed_revision, committed_fingerprint) = runtime
            .write_local_source(&opened.vault_id, b"candidate-generation", &expected)
            .unwrap();
        let visible = runtime.providers.local(&opened.path).read().unwrap();

        assert_eq!(committed_revision, visible.revision);
        assert!(same_content_fingerprint(
            &committed_fingerprint,
            &fingerprint_for_cached_bytes(&visible.bytes, 0)
        ));
        assert_eq!(visible.bytes, b"candidate-generation");
    }

    #[test]
    fn save_command_reports_source_change_as_a_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let generation_b = arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: opened.vault_id.clone(),
            })
            .expect("source conflicts must be command responses");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected conflict-copy response, got {response:?}");
        };
        assert_eq!(result.status, PublicationStatusDto::ConflictSplit);
        assert!(
            Path::new(
                result
                    .conflict_copy_path
                    .as_deref()
                    .expect("conflict-copy path")
            )
            .exists()
        );
        assert_eq!(std::fs::read(&opened.path).unwrap(), generation_b);
    }

    #[test]
    fn save_command_reports_source_deletion_as_a_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_source_deletion_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: opened.vault_id.clone(),
            })
            .expect("source deletion must be a command response");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected conflict-copy response, got {response:?}");
        };
        assert_eq!(result.status, PublicationStatusDto::ConflictSplit);
        assert!(
            Path::new(
                result
                    .conflict_copy_path
                    .as_deref()
                    .expect("conflict-copy path")
            )
            .exists()
        );
        assert!(!std::path::Path::new(&opened.path).exists());
    }

    #[test]
    fn save_command_reports_pre_publish_failure_as_io_unavailable() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::BeforeTargetReplace);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: opened.vault_id.clone(),
            })
            .expect("pre-publish failures must be command responses");

        let RuntimeResponse::Error(error) = response else {
            panic!("expected local save failure response, got {response:?}");
        };
        assert_eq!(error.code, "persist_io_unavailable");
        assert!(error.message.contains("failed before publish"));
    }

    #[test]
    fn save_command_acknowledges_a_verified_published_generation() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_backup_loss_after_publish(&mut runtime, &opened.path);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: opened.vault_id.clone(),
            })
            .expect("a reconciled publish should be a protocol response");

        let RuntimeResponse::PublicationResult(result) = response else {
            panic!("expected durable save response, got {response:?}");
        };
        assert_eq!(result.status, PublicationStatusDto::Published);
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        assert_eq!(
            KeepassCore::new()
                .load_kdbx(&std::fs::read(&opened.path).unwrap(), &key)
                .unwrap()
                .root
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn successful_save_records_durable_cleanup_warnings() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::Cleanup);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: opened.vault_id.clone(),
            })
            .expect("cleanup failure does not invalidate a durable save");

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));
        assert_eq!(runtime.local_save_warnings.len(), 1);
        assert!(runtime.local_save_warnings[0].contains("retained durable backup"));
    }

    #[test]
    fn committed_local_save_survives_synced_base_write_failure() {
        let mut runtime = VaultCore::for_tests();
        let (dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let blocked_root = dir.path().join("blocked-synced-base-root");
        std::fs::write(&blocked_root, b"not a directory").unwrap();
        runtime.synced_bases = SyncedBaseStore::new_at(blocked_root.join("bases"));

        let response = runtime
            .commit_working_copy(&opened.vault_id)
            .expect("the primary KDBX commit already succeeded");

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));
        assert!(
            runtime
                .local_save_warnings
                .iter()
                .any(|warning| warning.contains("failed to store synced base"))
        );
        assert!(matches!(
            runtime.commit_working_copy(&opened.vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        assert_eq!(
            KeepassCore::new()
                .load_kdbx(&std::fs::read(&opened.path).unwrap(), &key)
                .unwrap()
                .root
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn committed_local_save_remains_current_after_session_base_write_failure_and_lock() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.session_bases.fail_next_store_for_tests();

        let response = runtime
            .commit_working_copy(&opened.vault_id)
            .expect("the primary KDBX commit already succeeded");
        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));

        runtime.lock_session();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .expect("the committed generation must remain unlockable after locking");

        assert_eq!(runtime.list_entries(&opened.vault_id).unwrap().len(), 1);
    }

    #[test]
    fn lock_repairs_a_missing_session_base_from_the_durable_synced_base() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.commit_working_copy(&opened.vault_id).unwrap();
        runtime.session_bases.delete(&opened.vault_id).unwrap();

        runtime.lock_session();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .expect("locking must recover bytes from the authenticated durable base");

        assert_eq!(runtime.list_entries(&opened.vault_id).unwrap().len(), 1);
    }

    #[test]
    fn offline_quick_unlock_enrollment_repairs_a_missing_session_base() {
        let mut runtime = demo_onedrive_runtime(1_700_000_104);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        runtime.session_bases.delete(&vault_id).unwrap();
        runtime.remove_test_onedrive_item("drive-1", "item-1");

        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .expect("the authenticated durable base must repair offline enrollment");

        assert!(
            runtime
                .list_recent_vaults()
                .unwrap()
                .vaults
                .into_iter()
                .find(|vault| vault.is_current)
                .expect("current vault reference")
                .supports_quick_unlock
        );
    }

    #[test]
    fn committed_onedrive_save_survives_synced_base_write_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_100);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        runtime.synced_bases.fail_next_store_for_tests();

        let response = runtime
            .commit_working_copy(&vault_id)
            .expect("the remote KDBX commit already succeeded");

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));
        assert!(
            runtime
                .session_state()
                .source_status
                .and_then(|status| status.last_error)
                .is_some_and(|error| error.contains("failed to store synced base"))
        );
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        assert_eq!(
            KeepassCore::new()
                .load_kdbx(
                    &runtime
                        .read_test_onedrive_item_bytes("drive-1", "item-1")
                        .unwrap(),
                    &key,
                )
                .unwrap()
                .root
                .entries
                .len(),
            1
        );
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));
    }

    #[test]
    fn committed_onedrive_save_remains_current_after_session_base_write_failure_and_lock() {
        let mut runtime = demo_onedrive_runtime(1_700_000_100);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        runtime.session_bases.fail_next_store_for_tests();

        let response = runtime
            .commit_working_copy(&vault_id)
            .expect("the remote KDBX commit already succeeded");
        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));

        create_demo_entry(&mut runtime, &vault_id);
        assert!(matches!(
            runtime
                .commit_working_copy(&vault_id)
                .expect("retained committed bytes must repair the missing session base"),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));

        runtime.lock_session();
        runtime
            .unlock_vault(&vault_id, Some("demo-password"), None)
            .expect("the committed generation must remain unlockable after locking");

        assert_eq!(runtime.list_entries(&vault_id).unwrap().len(), 2);
    }

    #[test]
    fn onedrive_save_recovers_an_old_kdf_base_after_base_refresh_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_100);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();

        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let current = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let remote = KeepassCore::new().load_kdbx(&current, &key).unwrap();
        let mut rotated_profile = SaveProfile::recommended();
        rotated_profile.kdf = Some(SaveKdf::AesKdbx4 { rounds: 1 });
        let rotated = KeepassCore::new()
            .save_kdbx(&remote, &key, rotated_profile)
            .unwrap();
        assert_ne!(
            vaultkern_core::derive_transformed_key(&current, &key)
                .unwrap()
                .as_bytes(),
            vaultkern_core::derive_transformed_key(&rotated, &key)
                .unwrap()
                .as_bytes(),
            "the external save must actually rotate the KDF"
        );
        runtime.replace_test_onedrive_item("drive-1", "item-1", rotated);
        runtime.synced_bases.fail_next_store_for_tests();

        let adopted = runtime
            .commit_working_copy(&vault_id)
            .expect("the rotated remote head should be adopted despite a base-cache failure");
        assert!(matches!(
            adopted,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Reconciled,
                ..
            })
        ));
        assert!(
            runtime
                .session_state()
                .source_status
                .and_then(|status| status.last_error)
                .is_some_and(|error| error.contains("failed to store synced base"))
        );
        create_demo_entry(&mut runtime, &vault_id);

        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Published,
                ..
            })
        ));
    }

    struct RejectingWarningWriter;

    impl std::io::Write for RejectingWarningWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "warning sink is unavailable",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn local_save_warning_output_failure_is_ignored() {
        write_local_save_warning(&mut RejectingWarningWriter, "retained durable backup");
    }

    #[test]
    fn passkey_save_command_preserves_local_conflict_code() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let ceremony_token = "ceremony-local-save-conflict";
        insert_test_create_passkey_ceremony(
            &mut runtime,
            ceremony_token,
            &opened.vault_id,
            &entry.id,
            PasskeyCeremonyDurableStateDto::Mutated,
        );
        arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::SavePasskeyRegistration {
                ceremony_token: ceremony_token.into(),
                expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: opened.vault_id.clone(),
            })
            .expect("passkey save conflicts must be command responses");

        let RuntimeResponse::Error(error) = response else {
            panic!("expected passkey save conflict, got {response:?}");
        };
        assert_eq!(error.code, "conflict");
        assert_eq!(
            runtime.passkey_ceremonies[ceremony_token].durable_state,
            PasskeyCeremonyDurableStateDto::Mutated
        );
    }

    #[test]
    fn passkey_rollback_command_preserves_local_conflict_code() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let ceremony_token = "ceremony-local-rollback-conflict";
        insert_test_create_passkey_ceremony(
            &mut runtime,
            ceremony_token,
            &opened.vault_id,
            &entry.id,
            PasskeyCeremonyDurableStateDto::Saved,
        );
        arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::AbortPasskeyRegistration {
                ceremony_token: ceremony_token.into(),
                expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                closed_phase: PasskeyCeremonyPhaseDto::ClosedAborted,
            })
            .expect("passkey rollback conflicts must be command responses");

        let RuntimeResponse::Error(error) = response else {
            panic!("expected passkey rollback conflict, got {response:?}");
        };
        assert_eq!(error.code, "conflict");
        assert_eq!(
            runtime.passkey_ceremonies[ceremony_token].phase,
            PasskeyCeremonyPhaseDto::CompletionAndMutation
        );
    }

    fn open_unlocked_demo_onedrive(runtime: &mut VaultCore) -> String {
        runtime
            .add_onedrive_vault_reference("drive-1", "item-1")
            .unwrap();
        runtime
            .unlock_current_vault_with_password("demo-password")
            .unwrap();
        "onedrive:drive-1:item-1".into()
    }

    #[test]
    fn initial_onedrive_open_does_not_acknowledge_online_without_a_cache_commit() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_001);
        runtime.remote_cache = RemoteVaultCache::new_at_with_faults(
            cache_dir.path(),
            DurableFaultInjector::fail_once(DurableFaultPoint::ManifestTempCreated),
        );
        runtime
            .add_onedrive_vault_reference("drive-1", "item-1")
            .unwrap();

        let error = runtime
            .unlock_current_vault_with_password("demo-password")
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("failed to write remote cache manifest temp"),
            "{error}"
        );
        assert!(!runtime.session_state().unlocked);
    }

    fn demo_onedrive_runtime(unix_time: u64) -> VaultCore {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        VaultCore::for_tests_at_with_onedrive_item(
            unix_time,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            bytes,
        )
    }

    fn create_demo_entry(runtime: &mut VaultCore, vault_id: &str) -> EntryDetailDto {
        let root_group_id = runtime.list_groups(vault_id).unwrap().root.id;
        runtime
            .create_entry(
                vault_id,
                &root_group_id,
                "Example".into(),
                "alice".into(),
                "secret".into(),
                "https://example.com".into(),
                "".into(),
                None,
            )
            .unwrap()
    }

    fn install_test_passkey(runtime: &mut VaultCore, vault_id: &str, entry_id: &str) {
        let loaded = runtime.vault_session.find_loaded_mut(vault_id).unwrap();
        runtime
            .core
            .set_entry_passkey(
                loaded.vault.as_mut().unwrap(),
                entry_id,
                PasskeyRecord {
                    username: "legacy@example.com".into(),
                    credential_id: URL_SAFE_NO_PAD.encode(b"legacy-credential"),
                    generated_user_id: None,
                    private_key_pem: String::from("test-private-key").into(),
                    relying_party: "example.com".into(),
                    user_handle: Some(URL_SAFE_NO_PAD.encode(b"legacy-user")),
                    backup_eligible: false,
                    backup_state: false,
                },
            )
            .unwrap();
    }

    #[test]
    fn platform_plugin_registration_persists_a_kpex_entry_and_asserts_after_reopen() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user-1".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect("platform registration");

        let detail = runtime
            .get_entry_detail(&opened.vault_id, &registration.entry_id)
            .expect("created passkey entry");
        let passkey = detail.passkey.expect("KPEX passkey record");
        assert_eq!(
            passkey.credential_id,
            URL_SAFE_NO_PAD.encode(&registration.credential.credential_id)
        );
        assert_eq!(passkey.relying_party, "example.com");
        assert_eq!(registration.authenticator_data[32] & 0x45, 0x45);

        drop(runtime);
        let mut reopened = VaultCore::for_tests();
        let handle = reopened
            .open_local_vault(&opened.vault_id)
            .expect("reopen saved vault");
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .expect("unlock saved vault");
        let assertion = reopened
            .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
                relying_party: "example.com".into(),
                allowed_credential_ids: vec![registration.credential.credential_id.clone()],
                client_data_hash: vec![0x51; 32],
                user_verified: true,
            })
            .expect("assert using the persisted key");
        assert_eq!(
            assertion.credential_id,
            registration.credential.credential_id
        );
        assert_eq!(assertion.user_handle, b"platform-user-1");
        assert_ne!(assertion.authenticator_data[32] & 0x04, 0);
    }

    #[test]
    fn platform_registration_reconciles_a_published_local_outcome_unknown() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .providers
            .replace_local_file_with_write_faults(DurableFaultInjector::fail_once(
                DurableFaultPoint::LocalFinalReadback,
            ));

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"published-unknown-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect("readback must reconcile the published credential as committed");

        assert!(
            runtime
                .list_platform_passkey_credentials()
                .unwrap()
                .iter()
                .any(|credential| credential.credential_id
                    == registration.credential.credential_id)
        );
        drop(runtime);

        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.vault_id).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        assert!(
            reopened
                .list_platform_passkey_credentials()
                .unwrap()
                .iter()
                .any(|credential| credential.credential_id
                    == registration.credential.credential_id)
        );
    }

    #[test]
    fn platform_credential_sync_skips_non_discoverable_kpex_entries() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        let non_discoverable = create_demo_entry(&mut runtime, &opened.vault_id);
        install_test_passkey(&mut runtime, &opened.vault_id, &non_discoverable.id);
        runtime
            .set_entry_passkey(
                &opened.vault_id,
                &non_discoverable.id,
                EntryPasskeyUpdateDto {
                    username: "legacy@example.net".into(),
                    credential_id: URL_SAFE_NO_PAD.encode(b"legacy-credential"),
                    generated_user_id: None,
                    relying_party: "example.net".into(),
                    user_handle: None,
                    backup_eligible: false,
                    backup_state: false,
                },
            )
            .unwrap();

        let credentials = runtime
            .list_platform_passkey_credentials()
            .expect("non-discoverable KPEX entries must not poison platform sync");

        assert_eq!(credentials, vec![registration.credential]);
    }

    #[test]
    fn platform_credential_sync_skips_malformed_kpex_entries() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        let malformed = create_demo_entry(&mut runtime, &opened.vault_id);
        let loaded = runtime
            .vault_session
            .find_loaded_mut(&opened.vault_id)
            .expect("loaded vault");
        let entry = loaded
            .vault
            .as_mut()
            .expect("unlocked vault")
            .root
            .entries
            .iter_mut()
            .find(|entry| entry.id.to_string() == malformed.id)
            .expect("malformed fixture entry");
        entry.passkey = Some(PasskeyRecord {
            username: "broken@example.net".into(),
            credential_id: "not base64url!".into(),
            generated_user_id: None,
            private_key_pem: String::from("malformed fixture key").into(),
            relying_party: "example.net".into(),
            user_handle: Some(URL_SAFE_NO_PAD.encode(b"broken-user")),
            backup_eligible: false,
            backup_state: false,
        });

        let credentials = runtime
            .list_platform_passkey_credentials()
            .expect("a malformed KPEX entry must not poison platform sync");

        assert_eq!(credentials, vec![registration.credential]);
    }

    #[test]
    fn platform_reregistration_persists_current_display_labels_independently_of_entry_fields() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let first = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example Inc".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"platform-label-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();

        let replacement = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example Corporation".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice Smith".into(),
                user_handle: b"platform-label-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        assert_ne!(
            replacement.credential.credential_id,
            first.credential.credential_id
        );

        let entry = runtime
            .get_entry_detail(&opened.vault_id, &replacement.entry_id)
            .unwrap();
        assert_eq!(entry.title, "Example Inc");
        assert_eq!(entry.username, "Alice");
        let credentials = runtime.list_platform_passkey_credentials().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].relying_party_name, "Example Corporation");
        assert_eq!(credentials[0].user_display_name, "Alice Smith");

        drop(runtime);
        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.vault_id).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        let credentials = reopened.list_platform_passkey_credentials().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].relying_party_name, "Example Corporation");
        assert_eq!(credentials[0].user_display_name, "Alice Smith");
    }

    #[test]
    fn manual_passkey_replacement_does_not_reuse_platform_display_labels() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example Inc".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"platform-label-replacement".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        runtime
            .update_entry_fields(
                &opened.vault_id,
                &registration.entry_id,
                "Manual Login".into(),
                "manual-user".into(),
                String::new().into(),
                "https://other.example".into(),
                String::new().into(),
                None,
                Vec::new(),
            )
            .unwrap();
        let replacement = runtime
            .get_entry_detail(&opened.vault_id, &registration.entry_id)
            .unwrap()
            .passkey
            .unwrap();
        let replacement = EntryPasskeyUpdateDto {
            username: "manual-account".into(),
            credential_id: URL_SAFE_NO_PAD.encode(b"manual-platform-replacement"),
            generated_user_id: replacement.generated_user_id,
            relying_party: "other.example".into(),
            user_handle: replacement.user_handle,
            backup_eligible: replacement.backup_eligible,
            backup_state: replacement.backup_state,
        };
        runtime
            .set_entry_passkey(&opened.vault_id, &registration.entry_id, replacement)
            .unwrap();

        let credentials = runtime.list_platform_passkey_credentials().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].relying_party_name, "Manual Login");
        assert_eq!(credentials[0].user_display_name, "manual-user");
    }

    #[test]
    fn platform_plugin_registration_rolls_back_memory_when_durable_save_fails() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::BeforeTargetReplace);

        let error = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user-2".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect_err("pre-publish save failure must fail registration");

        assert!(
            error.to_string().contains("failed to publish Local File"),
            "{error:#}"
        );
        assert!(runtime.list_entries(&opened.vault_id).unwrap().is_empty());
    }

    #[test]
    fn platform_plugin_registration_reconciles_a_visible_post_publish_generation() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::TargetReplaced);

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user-ambiguous".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect("the visible published credential should complete registration");

        drop(runtime);
        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.vault_id).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        let detail = reopened
            .get_entry_detail(&handle.vault_id, &registration.entry_id)
            .unwrap();
        assert_eq!(
            detail.passkey.unwrap().credential_id,
            URL_SAFE_NO_PAD.encode(registration.credential.credential_id)
        );
    }

    #[test]
    fn platform_plugin_reregistration_acknowledges_a_verified_publish() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .vault_session
            .find_loaded_mut(&opened.vault_id)
            .unwrap()
            .vault
            .as_mut()
            .unwrap()
            .history_max_items = Some(0);

        let first = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"platform-user-outcome-unknown".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        arm_local_backup_loss_after_publish(&mut runtime, &opened.path);

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"platform-user-outcome-unknown".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect("a verified published generation must complete the ceremony");

        let credentials = runtime.list_platform_passkey_credentials().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(
            credentials[0].credential_id,
            registration.credential.credential_id
        );
        assert_ne!(
            registration.credential.credential_id,
            first.credential.credential_id
        );
    }

    #[test]
    fn platform_registration_fails_if_a_concurrent_merge_drops_its_credential() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let base_passkey = create_platform_registration_with_credential_id(
            PlatformPasskeyRegistrationRequest {
                relying_party: "example.com",
                user_name: "alice@example.com",
                user_handle: b"shared-user",
                public_key_algorithm: -7,
                user_verified: true,
            },
            b"base-credential".to_vec(),
        )
        .unwrap()
        .passkey;
        let mut base = Vault::empty("Cloud Vault");
        let entry = Entry::new("Example account");
        let entry_id = entry.id.to_string();
        base.root.entries.push(entry);
        core.set_entry_passkey(&mut base, &entry_id, base_passkey)
            .unwrap();
        base.root.entries[0].modified_at = 10;
        let base_bytes = core
            .save_kdbx(&base, &key, SaveProfile::recommended())
            .unwrap();
        let transformed_key = ResidentVaultCodec
            .derive_key_with_policy(
                &base_bytes,
                &key,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed,
            )
            .unwrap();

        let remote_passkey = create_platform_registration_with_credential_id(
            PlatformPasskeyRegistrationRequest {
                relying_party: "example.com",
                user_name: "alice@example.com",
                user_handle: b"shared-user",
                public_key_algorithm: -7,
                user_verified: true,
            },
            b"remote-credential".to_vec(),
        )
        .unwrap()
        .passkey;
        let mut remote = ResidentVaultCodec
            .decode(&base_bytes, &transformed_key)
            .unwrap();
        core.set_entry_passkey(&mut remote, &entry_id, remote_passkey)
            .unwrap();
        remote.root.entries[0].modified_at = 300;
        let remote_bytes = save_kdbx_with_history_limits_transformed(
            &mut remote,
            &transformed_key,
            VaultEncodingProfile::from_test_profile(SaveProfile {
                kdf: None,
                ..SaveProfile::recommended()
            }),
        )
        .unwrap();

        let local_credential_id = b"local-credential".to_vec();
        let generated_id = URL_SAFE_NO_PAD.encode(&local_credential_id);
        let mut runtime = VaultCore::for_tests_at_with_onedrive_item(
            200,
            "drive-1",
            "item-1",
            "Cloud Vault.kdbx",
            "alice@example.com",
            base_bytes,
        );
        runtime.passkey_credential_id_generator = Box::new(move || generated_id.clone());
        runtime
            .add_onedrive_vault_reference("drive-1", "item-1")
            .unwrap();
        runtime
            .unlock_current_vault_with_password("demo-password")
            .unwrap();
        runtime.queue_test_onedrive_precondition_failure(Some(remote_bytes));

        let result = runtime.register_platform_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "example.com".into(),
            relying_party_name: "example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: "alice@example.com".into(),
            user_handle: b"shared-user".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        });

        let credentials = runtime.list_platform_passkey_credentials().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].credential_id, b"remote-credential");
        assert_ne!(credentials[0].credential_id, local_credential_id);
        let error =
            result.expect_err("a credential discarded by the merge must not complete registration");
        assert!(
            error
                .to_string()
                .contains("platform passkey registration was not retained"),
            "{error:#}"
        );
    }

    #[test]
    fn platform_plugin_registration_fails_when_save_is_diverted_to_a_conflict_copy() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let current = std::fs::read(&opened.vault_id).unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&opened.vault_id).unwrap(),
        )
        .unwrap();
        let mut foreign = ResidentVaultCodec.decode(&current, &transformed).unwrap();
        foreign.root.id = Uuid::new_v4();
        let profile = runtime.inspected_save_profile(&current).unwrap();
        let foreign_generation =
            save_kdbx_with_history_limits_transformed(&mut foreign, &transformed, profile).unwrap();
        std::fs::write(&opened.vault_id, foreign_generation).unwrap();

        let error = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"platform-user-conflict".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect_err("a conflict copy must not complete WebAuthn registration");

        assert!(error.to_string().contains("conflict copy"));
        assert!(runtime.list_entries(&opened.vault_id).unwrap().is_empty());
    }

    #[test]
    fn platform_plugin_selects_one_matching_credential_for_discoverable_assertions() {
        let locked = VaultCore::for_tests();
        let error = locked
            .list_platform_passkey_credentials()
            .expect_err("no active unlocked vault must fail closed");
        assert!(error.to_string().contains("active unlocked vault"));

        let mut runtime = VaultCore::for_tests();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        let first = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"user-a".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        let second = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "bob@example.com".into(),
                user_display_name: "bob@example.com".into(),
                user_handle: b"user-b".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();

        let discoverable = runtime
            .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
                relying_party: "example.com".into(),
                allowed_credential_ids: Vec::new(),
                client_data_hash: vec![0x72; 32],
                user_verified: true,
            })
            .expect("the authenticator should select one discoverable credential");
        assert_eq!(discoverable.credential_id, first.credential.credential_id);

        let selected = runtime
            .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
                relying_party: "example.com".into(),
                allowed_credential_ids: vec![second.credential.credential_id.clone()],
                client_data_hash: vec![0x72; 32],
                user_verified: true,
            })
            .unwrap();
        assert_eq!(selected.credential_id, second.credential.credential_id);
        assert_ne!(selected.credential_id, first.credential.credential_id);
    }

    #[test]
    fn platform_plugin_rejects_duplicate_credential_ids_for_the_same_relying_party() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let credential_id = b"duplicate-platform-credential".to_vec();
        let first = create_platform_registration_with_credential_id(
            PlatformPasskeyRegistrationRequest {
                relying_party: "example.com",
                user_name: "alice@example.com",
                user_handle: b"user-a",
                public_key_algorithm: -7,
                user_verified: true,
            },
            credential_id.clone(),
        )
        .unwrap()
        .passkey;
        let second = create_platform_registration_with_credential_id(
            PlatformPasskeyRegistrationRequest {
                relying_party: "example.com",
                user_name: "bob@example.com",
                user_handle: b"user-b",
                public_key_algorithm: -7,
                user_verified: true,
            },
            credential_id.clone(),
        )
        .unwrap()
        .passkey;
        let loaded = runtime
            .vault_session
            .find_loaded_mut(&opened.vault_id)
            .unwrap();
        let vault = loaded.vault.as_mut().unwrap();
        let mut first_entry = Entry::new("First duplicate");
        first_entry.passkey = Some(first);
        let mut second_entry = Entry::new("Second duplicate");
        second_entry.passkey = Some(second);
        vault.root.entries.extend([first_entry, second_entry]);

        assert!(
            runtime
                .list_platform_passkey_credentials()
                .unwrap()
                .is_empty(),
            "ambiguous credentials must not be advertised to Windows"
        );

        let error = runtime
            .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
                relying_party: "example.com".into(),
                allowed_credential_ids: vec![credential_id],
                client_data_hash: vec![0x51; 32],
                user_verified: true,
            })
            .expect_err("an ambiguous credential id must not select an arbitrary private key");

        assert!(
            error
                .to_string()
                .contains("multiple passkey credentials found for credential id")
        );
    }

    #[test]
    fn runtime_creation_uses_the_product_clock_for_all_keepass_entry_times() {
        let creation_time = 1_700_000_123;
        let mut runtime = VaultCore::for_tests_at(creation_time);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let created = create_demo_entry(&mut runtime, &opened.vault_id);
        let entry = runtime
            .loaded_vault(&opened.vault_id)
            .expect("loaded vault")
            .root
            .entries
            .iter()
            .find(|entry| entry.id.to_string() == created.id)
            .expect("created entry");

        assert_eq!(entry.created_at, creation_time);
        assert_eq!(entry.modified_at, creation_time);
        assert_eq!(entry.expiry_time, Some(creation_time as i64));
        assert_eq!(entry.last_accessed_at, Some(creation_time));
        assert_eq!(entry.usage_count, Some(0));
        assert_eq!(entry.location_changed_at, Some(creation_time));
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(
            entry.auto_type,
            Some(vaultkern_core::AutoTypeConfig::default())
        );
    }

    #[test]
    fn runtime_creation_rejects_invalid_totp_before_adding_the_entry() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let root_group_id = runtime.list_groups(&opened.vault_id).unwrap().root.id;
        let before = runtime
            .loaded_vault(&opened.vault_id)
            .expect("loaded vault")
            .root
            .entries
            .len();

        assert!(
            runtime
                .create_entry(
                    &opened.vault_id,
                    &root_group_id,
                    "Invalid TOTP".into(),
                    "alice".into(),
                    "secret".into(),
                    "https://example.com".into(),
                    String::new().into(),
                    Some("otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer".into()),
                )
                .is_err()
        );
        assert_eq!(
            runtime
                .loaded_vault(&opened.vault_id)
                .expect("loaded vault")
                .root
                .entries
                .len(),
            before
        );
    }

    #[test]
    fn ordinary_entry_update_preserves_hidden_unprojectable_totp_source() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let created = create_demo_entry(&mut runtime, &opened.vault_id);
        let raw_key = "HmacOtp-Secret";
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .expect("loaded vault");
            let entry = loaded
                .vault
                .as_mut()
                .expect("unlocked vault")
                .root
                .entries
                .iter_mut()
                .find(|entry| entry.id.to_string() == created.id)
                .expect("created entry");
            entry.attributes.insert(
                raw_key.into(),
                vaultkern_core::CustomField {
                    value: "raw-hotp-secret".into(),
                    protected: false,
                },
            );
        }

        runtime
            .update_entry_fields(
                &opened.vault_id,
                &created.id,
                created.title,
                created.username,
                "changed password".into(),
                created.url,
                created.notes,
                None,
                created.custom_fields,
            )
            .expect("ordinary entry update");

        let entry = runtime
            .loaded_vault(&opened.vault_id)
            .expect("loaded vault")
            .root
            .entries
            .iter()
            .find(|entry| entry.id.to_string() == created.id)
            .expect("updated entry");
        assert_eq!(
            entry
                .attributes
                .get(raw_key)
                .map(|field| field.value.as_str()),
            Some("raw-hotp-secret")
        );
    }

    fn entry_fields(detail: &EntryDetailDto) -> EntryFieldsDto {
        EntryFieldsDto {
            title: detail.title.clone(),
            username: detail.username.clone(),
            password: detail.password.clone(),
            url: detail.url.clone(),
            notes: detail.notes.clone(),
            totp_uri: detail.totp_uri.clone(),
            custom_fields: detail.custom_fields.clone(),
        }
    }

    fn insert_test_create_passkey_ceremony(
        runtime: &mut VaultCore,
        ceremony_token: &str,
        vault_id: &str,
        entry_id: &str,
        durable_state: PasskeyCeremonyDurableStateDto,
    ) {
        let now_epoch_ms = runtime.current_unix_time_ms();
        runtime.passkey_ceremonies.insert(
            ceremony_token.into(),
            PasskeyCeremonyLedgerEntry {
                identity: PasskeyCeremonyIdentity {
                    connection_id: "connection-pending-save".into(),
                    origin: "https://example.com".into(),
                    top_origin: None,
                    ancestor_origins: vec![],
                    relying_party: "example.com".into(),
                    ceremony: PasskeyCeremonyKindDto::Create,
                    discoverable: true,
                    user_verification: PasskeyUserVerificationRequirementDto::Preferred,
                    challenge_base64url: "AQ".into(),
                    request_id: 1,
                    tab_id: 1,
                    frame_id: 0,
                    frame_kind: PasskeyFrameKindDto::Top,
                    registered_at_epoch_ms: now_epoch_ms,
                    expires_at_epoch_ms: now_epoch_ms + 60_000,
                },
                phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: Some(vault_id.into()),
                durable_state,
                delivery_state: PasskeyCeremonyDeliveryStateDto::NotDelivered,
                user_verification: None,
                registration_rollback: Some(PasskeyRegistrationRollbackState {
                    vault_id: vault_id.into(),
                    entry_id: entry_id.into(),
                    credential_id: None,
                    created: true,
                    rollback_entry: None,
                }),
            },
        );
    }

    #[test]
    fn lowering_history_limit_prunes_live_state_without_later_resurrection() {
        let mut runtime = VaultCore::for_tests_at(1_700_000_000);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            let core = KeepassCore::new();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
        }
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            2
        );

        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    history: Some(DatabaseHistorySettingsDto {
                        max_items_per_entry: Some(1),
                        max_total_size_bytes: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );
        runtime.commit_working_copy(&opened.vault_id).unwrap();

        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    history: Some(DatabaseHistorySettingsDto {
                        max_items_per_entry: Some(2),
                        max_total_size_bytes: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        runtime.commit_working_copy(&opened.vault_id).unwrap();

        let mut restarted = VaultCore::for_tests_at(1_700_000_001);
        let reopened = restarted.open_local_vault(&opened.path).unwrap();
        restarted
            .unlock_vault(&reopened.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            restarted
                .list_entry_history(&reopened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );
    }

    #[test]
    fn local_save_installs_the_exact_history_retained_model_that_was_published() {
        let mut runtime = VaultCore::for_tests_at(1_700_000_000);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            let core = KeepassCore::new();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            // A third-party or older writer may leave more snapshots in the
            // model than its declared retention permits.
            vault.history_max_items = Some(1);
        }

        runtime.commit_working_copy(&opened.vault_id).unwrap();

        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1,
            "the resident model must be the same retained model that was committed"
        );

        runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    history: Some(DatabaseHistorySettingsDto {
                        max_items_per_entry: Some(2),
                        max_total_size_bytes: None,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        runtime.commit_working_copy(&opened.vault_id).unwrap();

        let mut restarted = VaultCore::for_tests_at(1_700_000_001);
        let reopened = restarted.open_local_vault(&opened.path).unwrap();
        restarted
            .unlock_vault(&reopened.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            restarted
                .list_entry_history(&reopened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1,
            "raising the limit must not resurrect snapshots pruned by an earlier commit"
        );
    }

    #[test]
    fn invalid_local_remote_keeps_the_exact_history_retained_conflict_copy_active() {
        let mut runtime = VaultCore::for_tests_at(1_700_000_002);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            let core = KeepassCore::new();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            core.snapshot_entry_to_history(vault, &entry.id).unwrap();
            vault.history_max_items = Some(1);
        }
        std::fs::write(&opened.path, b"external generation").unwrap();

        let response = runtime.commit_working_copy(&opened.vault_id).unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1,
            "a recoverable conflict-copy commit must install the exact retained model it published"
        );
    }

    #[test]
    fn generic_onedrive_ambiguous_write_and_cache_failure_rolls_back_runtime_state() {
        let mut runtime = demo_onedrive_runtime(1_700_000_034);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();
        runtime
            .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                entry.title.clone(),
                entry.username.clone(),
                "local-before-cache-failure".into(),
                entry.url.clone(),
                entry.notes.clone(),
                entry.totp_uri.clone(),
                entry.custom_fields.clone(),
            )
            .unwrap();
        let vault_before = runtime.loaded_vault(&vault_id).unwrap().clone();
        let key_before = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let base_before = runtime.synced_bases.read(&vault_id).unwrap().unwrap();

        let core = KeepassCore::new();
        let mut master_key = CompositeKey::default();
        master_key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut remote_vault = core.load_database(&remote, &master_key).unwrap().vault;
        remote_vault.description = Some("remote-before-cache-failure".into());
        let rotated = core
            .save_kdbx(
                &remote_vault,
                &master_key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::ChaCha20,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
                },
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", rotated);

        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let current_cache = runtime.remote_cache.read(&cache_key).unwrap().unwrap();
        let failing_cache_dir = tempfile::tempdir().unwrap();
        let healthy_cache = RemoteVaultCache::new_at(failing_cache_dir.path());
        healthy_cache.write(&cache_key, current_cache).unwrap();
        runtime.remote_cache = RemoteVaultCache::new_at_with_faults(
            failing_cache_dir.path(),
            DurableFaultInjector::fail_in_order([
                DurableFaultPoint::ManifestTempCreated,
                DurableFaultPoint::ManifestTempCreated,
            ]),
        );
        runtime.queue_test_onedrive_ambiguous_write(false);

        runtime
            .commit_working_copy(&vault_id)
            .expect_err("failed pending cache must fail the save");

        assert_eq!(
            runtime.synced_bases.read(&vault_id).unwrap().unwrap(),
            base_before
        );
        assert_eq!(runtime.loaded_vault(&vault_id).unwrap(), &vault_before);
        assert_eq!(
            transformed_key_from_loaded_vault(
                runtime.vault_session.find_loaded(&vault_id).unwrap()
            )
            .unwrap()
            .as_bytes(),
            key_before.as_bytes()
        );
    }

    #[test]
    fn exact_matching_uses_effective_xml_custom_field_protection() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let unsafe_detail = runtime
            .update_entry_fields(
                &opened.vault_id,
                &entry.id,
                entry.title.clone(),
                entry.username.clone(),
                entry.password.clone(),
                entry.url.clone(),
                entry.notes.clone(),
                None,
                vec![EntryCustomFieldDto {
                    key: "XmlUnsafe".into(),
                    value: "value\0after".into(),
                    protected: true,
                }],
            )
            .unwrap();
        let mut unsafe_query = entry_fields(&unsafe_detail);
        unsafe_query.custom_fields[0].protected = false;

        let unsafe_matches = runtime
            .handle(RuntimeCommand::FindExactMatchingEntryIds {
                vault_id: opened.vault_id.clone(),
                fields: unsafe_query,
            })
            .unwrap();

        assert!(matches!(
            unsafe_matches,
            RuntimeResponse::EntryIdList(EntryIdListDto { entry_ids })
                if entry_ids == vec![entry.id.clone()]
        ));

        let safe_detail = runtime
            .update_entry_fields(
                &opened.vault_id,
                &entry.id,
                unsafe_detail.title,
                unsafe_detail.username,
                unsafe_detail.password,
                unsafe_detail.url,
                unsafe_detail.notes,
                None,
                vec![EntryCustomFieldDto {
                    key: "XmlSafe".into(),
                    value: "safe value".into(),
                    protected: true,
                }],
            )
            .unwrap();
        let mut safe_query = entry_fields(&safe_detail);
        safe_query.custom_fields[0].protected = false;

        let safe_matches = runtime
            .handle(RuntimeCommand::FindExactMatchingEntryIds {
                vault_id: opened.vault_id,
                fields: safe_query,
            })
            .unwrap();

        assert!(matches!(
            safe_matches,
            RuntimeResponse::EntryIdList(EntryIdListDto { entry_ids }) if entry_ids.is_empty()
        ));
    }

    #[test]
    fn exact_matching_rejects_duplicate_custom_field_keys_instead_of_collapsing_them() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let detail = runtime
            .update_entry_fields(
                &opened.vault_id,
                &entry.id,
                entry.title.clone(),
                entry.username.clone(),
                entry.password.clone(),
                entry.url.clone(),
                entry.notes.clone(),
                None,
                vec![EntryCustomFieldDto {
                    key: "Duplicate".into(),
                    value: "actual".into(),
                    protected: false,
                }],
            )
            .unwrap();
        let mut query = entry_fields(&detail);
        query.custom_fields = vec![
            EntryCustomFieldDto {
                key: "Duplicate".into(),
                value: "wrong".into(),
                protected: false,
            },
            EntryCustomFieldDto {
                key: "Duplicate".into(),
                value: "actual".into(),
                protected: false,
            },
        ];

        let response = runtime
            .handle(RuntimeCommand::FindExactMatchingEntryIds {
                vault_id: opened.vault_id,
                fields: query,
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::EntryIdList(EntryIdListDto { entry_ids }) if entry_ids.is_empty()
        ));
    }

    #[test]
    fn generic_pending_save_survives_lock_and_direct_password_unlock() {
        let mut runtime = demo_onedrive_runtime(1_700_000_057);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();
        let desired_fields = EntryFieldsDto {
            notes: "durable pending edit".into(),
            ..entry_fields(&entry)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                desired_fields.title.clone(),
                desired_fields.username.clone(),
                desired_fields.password.clone(),
                desired_fields.url.clone(),
                desired_fields.notes.clone(),
                desired_fields.totp_uri.clone(),
                desired_fields.custom_fields.clone(),
            )
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        let pending = runtime
            .remote_cache
            .read(&RemoteCacheKey::new("onedrive", "drive-1:item-1"))
            .unwrap()
            .expect("durable pending Working Copy");
        assert!(pending.pending_sync);
        assert!(KeepassCore::new().inspect_database(&pending.bytes).is_ok());
        assert!(
            !pending
                .bytes
                .windows(b"durable pending edit".len())
                .any(|window| window == b"durable pending edit"),
            "durable pending material must remain encrypted KDBX bytes"
        );
        assert!(
            runtime
                .vault_session
                .find_loaded(&vault_id)
                .unwrap()
                .bytes
                .is_empty()
        );

        runtime.lock_session();
        runtime
            .unlock_with_password(&vault_id, "demo-password")
            .unwrap();

        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );
        assert_eq!(
            runtime
                .retry_vault_source_sync(&vault_id)
                .unwrap()
                .remote_state,
            "online"
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );
    }

    #[test]
    fn concurrent_generic_saves_keep_each_runtime_three_way_base_isolated() {
        let mut seed = demo_onedrive_runtime(1_700_000_057);
        let vault_id = open_unlocked_demo_onedrive(&mut seed);
        let first_entry = create_demo_entry(&mut seed, &vault_id);
        let second_entry = create_demo_entry(&mut seed, &vault_id);
        seed.commit_working_copy(&vault_id).unwrap();
        let baseline_bytes = seed
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();

        let cache_dir = tempfile::tempdir().unwrap();
        let mut first = VaultCore::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_058,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            baseline_bytes.clone(),
            cache_dir.path(),
        );
        let mut second = VaultCore::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_059,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            baseline_bytes,
            cache_dir.path(),
        );
        assert_eq!(open_unlocked_demo_onedrive(&mut first), vault_id);
        assert_eq!(open_unlocked_demo_onedrive(&mut second), vault_id);

        let first_edit = EntryFieldsDto {
            notes: "first runtime edit".into(),
            ..entry_fields(&first.get_entry_detail(&vault_id, &first_entry.id).unwrap())
        };
        first
            .update_entry_fields(
                &vault_id,
                &first_entry.id,
                first_edit.title.clone(),
                first_edit.username.clone(),
                first_edit.password.clone(),
                first_edit.url.clone(),
                first_edit.notes.clone(),
                first_edit.totp_uri.clone(),
                first_edit.custom_fields.clone(),
            )
            .unwrap();
        first.commit_working_copy(&vault_id).unwrap();
        second.replace_test_onedrive_item(
            "drive-1",
            "item-1",
            first
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
        );

        let second_edit = EntryFieldsDto {
            password: "second-runtime-secret".into(),
            ..entry_fields(
                &second
                    .get_entry_detail(&vault_id, &second_entry.id)
                    .unwrap(),
            )
        };
        second
            .update_entry_fields(
                &vault_id,
                &second_entry.id,
                second_edit.title.clone(),
                second_edit.username.clone(),
                second_edit.password.clone(),
                second_edit.url.clone(),
                second_edit.notes.clone(),
                second_edit.totp_uri.clone(),
                second_edit.custom_fields.clone(),
            )
            .unwrap();

        let response = second.commit_working_copy(&vault_id).unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Reconciled,
                ..
            })
        ));
        assert_eq!(
            entry_fields(&second.get_entry_detail(&vault_id, &first_entry.id).unwrap()),
            first_edit
        );
        assert_eq!(
            entry_fields(
                &second
                    .get_entry_detail(&vault_id, &second_entry.id)
                    .unwrap()
            ),
            second_edit
        );
    }

    #[test]
    fn generic_pending_cache_without_previous_still_accepts_later_generic_saves() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let cleanup = runtime.remote_cache.begin_retirement(&cache_key).unwrap();
        cleanup.delete_cached_state().unwrap();
        drop(cleanup);
        runtime
            .remote_cache
            .activate_while(&cache_key, || Ok(()))
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime
                .handle(RuntimeCommand::RetryVaultPublication {
                    vault_id: vault_id.clone(),
                })
                .unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        let edited_fields = EntryFieldsDto {
            notes: "second generic pending save".into(),
            ..entry_fields(&entry)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                edited_fields.title,
                edited_fields.username,
                edited_fields.password,
                edited_fields.url,
                edited_fields.notes,
                edited_fields.totp_uri,
                edited_fields.custom_fields,
            )
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);

        let response = runtime
            .handle(RuntimeCommand::RetryVaultPublication {
                vault_id: vault_id.clone(),
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        assert_eq!(
            runtime.current_source_status().unwrap().remote_state,
            "pending_sync"
        );
    }

    #[test]
    fn generic_pending_retry_preserves_later_live_edits() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();

        let pending_fields = EntryFieldsDto {
            notes: "durable pending edit".into(),
            ..entry_fields(&entry)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                pending_fields.title.clone(),
                pending_fields.username.clone(),
                pending_fields.password.clone(),
                pending_fields.url.clone(),
                pending_fields.notes.clone(),
                pending_fields.totp_uri.clone(),
                pending_fields.custom_fields.clone(),
            )
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));

        let live_fields = EntryFieldsDto {
            username: "edited after pending cache".into(),
            ..pending_fields
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                live_fields.title.clone(),
                live_fields.username.clone(),
                live_fields.password.clone(),
                live_fields.url.clone(),
                live_fields.notes.clone(),
                live_fields.totp_uri.clone(),
                live_fields.custom_fields.clone(),
            )
            .unwrap();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "online");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let durable = KeepassCore::new()
            .load_database(&remote, &key)
            .unwrap()
            .vault;
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &durable, &entry.id).unwrap(),
            live_fields
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            live_fields
        );
    }

    #[test]
    fn generic_pending_conflict_copy_preserves_later_live_edits() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let target = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();

        runtime
            .vault_session
            .find_loaded_mut(&vault_id)
            .unwrap()
            .save_profile
            .set_test_compression(VaultCompression::None);
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));

        let live_fields = EntryFieldsDto {
            username: "edited after pending cache".into(),
            ..entry_fields(&target)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &target.id,
                live_fields.title.clone(),
                live_fields.username.clone(),
                live_fields.password.clone(),
                live_fields.url.clone(),
                live_fields.notes.clone(),
                live_fields.totp_uri.clone(),
                live_fields.custom_fields.clone(),
            )
            .unwrap();

        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let mut remote_vault = ResidentVaultCodec.decode(&remote, &transformed).unwrap();
        let changed_remote = save_kdbx_with_history_limits_transformed(
            &mut remote_vault,
            &transformed,
            VaultEncodingProfile::from_test_profile(SaveProfile {
                cipher: KdbxCipher::ChaCha20,
                kdf: None,
                ..SaveProfile::recommended()
            }),
        )
        .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_remote);

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "online");
        let conflicts = runtime
            .providers
            .list_children(None)
            .unwrap()
            .items
            .into_iter()
            .filter(|item| item.item_id.starts_with("vaultkern-conflict-"))
            .collect::<Vec<_>>();
        assert_eq!(conflicts.len(), 1);
        let conflict = &conflicts[0];
        let conflict_bytes = runtime
            .read_test_onedrive_item_bytes(&conflict.drive_id, &conflict.item_id)
            .unwrap();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let core = KeepassCore::new();
        let conflict_vault = core.load_database(&conflict_bytes, &key).unwrap().vault;
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &conflict_vault, &target.id).unwrap(),
            live_fields
        );

        let retry = runtime.retry_vault_source_sync(&vault_id).unwrap();
        assert_eq!(retry.remote_state, "online");
        let conflict_count = runtime
            .providers
            .list_children(None)
            .unwrap()
            .items
            .into_iter()
            .filter(|item| item.item_id.starts_with("vaultkern-conflict-"))
            .count();
        assert_eq!(conflict_count, 1, "conflict fallback must be idempotent");
    }

    #[test]
    fn stale_retry_exhaustion_never_reclassifies_remote_edits_as_local() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_059);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();

        let base_bytes = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let base = ResidentVaultCodec
            .decode(&base_bytes, &transformed)
            .unwrap();
        let base_username = entry.username.clone();
        let remote_generation = |username: &str, modified_at: u64| {
            let mut vault = base.clone();
            let remote_entry = vault
                .root
                .entries
                .iter_mut()
                .find(|candidate| candidate.id.to_string() == entry.id)
                .unwrap();
            remote_entry.username = username.into();
            remote_entry.modified_at = modified_at;
            save_kdbx_with_history_limits_transformed(
                &mut vault,
                &transformed,
                VaultEncodingProfile::from_test_profile(SaveProfile {
                    kdf: None,
                    ..SaveProfile::recommended()
                }),
            )
            .unwrap()
        };
        let remote_r1 = remote_generation("remote-r1", 200);
        let remote_r2 = remote_generation("remote-r2", 300);
        let remote_r3 = remote_generation(&base_username, 400);

        let local_fields = EntryFieldsDto {
            notes: "local edit that must remain recoverable".into(),
            ..entry_fields(&entry)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                local_fields.title.clone(),
                local_fields.username.clone(),
                local_fields.password.clone(),
                local_fields.url.clone(),
                local_fields.notes.clone(),
                local_fields.totp_uri.clone(),
                local_fields.custom_fields.clone(),
            )
            .unwrap();

        for replacement in [remote_r1, remote_r2, remote_r3] {
            runtime.queue_test_onedrive_precondition_failure(Some(replacement));
        }

        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        let pending_local = runtime.get_entry_detail(&vault_id, &entry.id).unwrap();
        assert_eq!(pending_local.username, base_username);
        assert_eq!(pending_local.notes, local_fields.notes);

        let second_local_fields = EntryFieldsDto {
            notes: "newest edit while Publication remains pending".into(),
            ..entry_fields(&pending_local)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                second_local_fields.title.clone(),
                second_local_fields.username.clone(),
                second_local_fields.password.clone(),
                second_local_fields.url.clone(),
                second_local_fields.notes.clone(),
                second_local_fields.totp_uri.clone(),
                second_local_fields.custom_fields.clone(),
            )
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime.commit_working_copy(&vault_id).unwrap(),
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::Pending,
                ..
            })
        ));
        let pending_fingerprint = runtime
            .vault_session
            .find_loaded(&vault_id)
            .unwrap()
            .baseline_fingerprint
            .clone();
        assert_eq!(
            runtime
                .remote_cache
                .generic_pending_kind(
                    &RemoteCacheKey::new("onedrive", "drive-1:item-1"),
                    &pending_fingerprint,
                )
                .unwrap(),
            GenericPendingKind::SourceWrite
        );

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();
        assert_eq!(status.remote_state, "online");

        let main_bytes = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let main = ResidentVaultCodec
            .decode(&main_bytes, &transformed)
            .unwrap();
        let main_entry = main
            .root
            .entries
            .iter()
            .find(|candidate| candidate.id.to_string() == entry.id)
            .unwrap();
        assert_eq!(
            main_entry.username,
            base_username.as_str(),
            "R2 must not be replayed over the later R3 restoration"
        );
        assert_eq!(main_entry.notes, second_local_fields.notes.as_str());

        let conflict_count = runtime
            .providers
            .list_children(None)
            .unwrap()
            .items
            .into_iter()
            .filter(|item| item.item_id.starts_with("vaultkern-conflict-"))
            .count();
        assert_eq!(conflict_count, 0);
    }

    #[test]
    fn deleted_onedrive_source_preserves_edits_as_a_pending_conflict_copy() {
        let mut runtime = demo_onedrive_runtime(1_700_000_102);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.commit_working_copy(&vault_id).unwrap();
        let desired = EntryFieldsDto {
            notes: "recover after remote deletion".into(),
            ..entry_fields(&entry)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &entry.id,
                desired.title,
                desired.username,
                desired.password,
                desired.url,
                desired.notes,
                desired.totp_uri,
                desired.custom_fields,
            )
            .unwrap();
        runtime.remove_test_onedrive_item("drive-1", "item-1");

        let response = runtime.commit_working_copy(&vault_id).unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::PublicationResult(PublicationResultDto {
                status: PublicationStatusDto::ConflictSplit,
                ..
            })
        ));
        let pending_fingerprint = runtime
            .vault_session
            .find_loaded(&vault_id)
            .unwrap()
            .baseline_fingerprint
            .clone();
        assert_eq!(
            runtime
                .remote_cache
                .generic_pending_kind(
                    &RemoteCacheKey::new("onedrive", "drive-1:item-1"),
                    &pending_fingerprint,
                )
                .unwrap(),
            GenericPendingKind::ConflictCopy
        );
    }

    #[test]
    fn runtime_kdbx_roundtrips_sha256_eight_digit_totp_with_history() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let root_id = runtime.list_groups(&opened.vault_id).unwrap().root.id;
        let entry = runtime
            .create_entry(
                &opened.vault_id,
                &root_id,
                "Example".into(),
                "alice".into(),
                "secret".into(),
                "https://example.com".into(),
                String::new().into(),
                None,
            )
            .unwrap();
        runtime.commit_working_copy(&opened.vault_id).unwrap();
        let mut updater = VaultCore::for_tests();
        let update_handle = updater.open_local_vault(&opened.path).unwrap();
        updater
            .unlock_vault(&update_handle.vault_id, Some("demo-password"), None)
            .unwrap();
        updater
            .update_entry_fields(
                &update_handle.vault_id,
                &entry.id,
                entry.title.clone(),
                entry.username.clone(),
                entry.password.clone(),
                entry.url.clone(),
                entry.notes.clone(),
                Some(
                    "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45"
                        .into(),
                ),
                entry.custom_fields.clone(),
            )
            .unwrap();
        updater
            .commit_working_copy(&update_handle.vault_id)
            .unwrap();

        let mut reopened = VaultCore::for_tests();
        let handle = reopened.open_local_vault(&opened.path).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();

        assert_eq!(
            reopened
                .get_entry_detail(&handle.vault_id, &entry.id)
                .unwrap()
                .totp_uri
                .as_deref(),
            Some(
                "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45"
            )
        );
    }

    #[test]
    fn locking_clears_decrypted_vault_and_keeps_encrypted_snapshot_for_reunlock() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();

        runtime.lock_session();

        let loaded = runtime.vault_session.find_loaded(&opened.vault_id).unwrap();
        assert!(!loaded.bytes.is_empty());
        assert!(loaded.vault.is_none());
        assert_eq!(
            loaded.credential_shape,
            MasterCredentialShape {
                has_password: true,
                has_key_file: false,
            }
        );

        std::fs::remove_file(&path).unwrap();

        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();

        let session = runtime.session_state();
        assert!(session.unlocked);
        assert_eq!(
            session.active_vault_id.as_deref(),
            Some(opened.vault_id.as_str())
        );
    }

    #[test]
    fn current_source_status_covers_active_selected_locked_and_missing_states() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let expected = VaultSourceStatusDto {
            source_kind: "test".into(),
            remote_state: "active".into(),
            last_sync_at: Some(42),
            cached_at: Some(41),
            last_error: None,
        };
        runtime
            .vault_session
            .find_loaded_mut(&opened.vault_id)
            .unwrap()
            .source_status = Some(expected.clone());

        assert_eq!(
            runtime.session_state().source_status,
            Some(expected.clone())
        );

        runtime.lock_session();
        assert_eq!(runtime.session_state().source_status, Some(expected));

        let missing_dir = tempfile::tempdir().unwrap();
        let missing_path = missing_dir.path().join("selected-only.kdbx");
        std::fs::write(&missing_path, b"not loaded").unwrap();
        runtime
            .add_local_vault_reference(missing_path.to_str().unwrap())
            .unwrap();

        assert!(runtime.session_state().source_status.is_none());
    }

    #[test]
    fn passkey_user_verification_capability_requires_an_unlocked_vault() {
        let mut runtime = VaultCore::for_tests();

        let response = runtime
            .handle(RuntimeCommand::GetPasskeyUserVerificationCapability)
            .unwrap();

        assert_eq!(
            response,
            RuntimeResponse::PasskeyUserVerificationCapability(
                PasskeyUserVerificationCapabilityDto {
                    available: false,
                    methods: vec![],
                }
            )
        );
    }

    #[test]
    fn set_entry_passkey_rejects_invalid_user_handle() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);

        let error = runtime
            .set_entry_passkey(
                &opened.vault_id,
                &entry.id,
                EntryPasskeyUpdateDto {
                    username: "alice@example.com".into(),
                    credential_id: "Y3JlZC0x".into(),
                    generated_user_id: None,
                    relying_party: "example.com".into(),
                    user_handle: Some("alice@example.com".into()),
                    backup_eligible: true,
                    backup_state: true,
                },
            )
            .unwrap_err();

        assert!(
            format_error_chain(&error).contains("invalid passkey user handle base64url"),
            "{error:?}"
        );
    }

    #[test]
    fn set_entry_passkey_rejects_manual_creation_without_registration() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);

        let error = runtime
            .set_entry_passkey(
                &opened.vault_id,
                &entry.id,
                EntryPasskeyUpdateDto {
                    username: "alice@example.com".into(),
                    credential_id: "Y3JlZC0x".into(),
                    generated_user_id: None,
                    relying_party: "example.com".into(),
                    user_handle: Some("dXNlci0x".into()),
                    backup_eligible: true,
                    backup_state: true,
                },
            )
            .unwrap_err();

        assert!(
            format_error_chain(&error)
                .contains("passkey metadata can only update an existing passkey"),
            "{error:?}"
        );
        assert!(
            runtime
                .get_entry_detail(&opened.vault_id, &entry.id)
                .unwrap()
                .passkey
                .is_none()
        );
    }

    #[test]
    fn set_entry_passkey_rejects_invalid_credential_id() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);

        let error = runtime
            .set_entry_passkey(
                &opened.vault_id,
                &entry.id,
                EntryPasskeyUpdateDto {
                    username: "alice@example.com".into(),
                    credential_id: "not base64url!".into(),
                    generated_user_id: None,
                    relying_party: "example.com".into(),
                    user_handle: Some("dXNlci0x".into()),
                    backup_eligible: true,
                    backup_state: true,
                },
            )
            .unwrap_err();

        assert!(
            format_error_chain(&error).contains("invalid passkey credential id base64url"),
            "{error:?}"
        );
    }

    #[test]
    fn passkey_user_verification_capability_reports_master_password_for_unlocked_vault() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();

        let response = runtime
            .handle(RuntimeCommand::GetPasskeyUserVerificationCapability)
            .unwrap();

        assert_eq!(
            response,
            RuntimeResponse::PasskeyUserVerificationCapability(
                PasskeyUserVerificationCapabilityDto {
                    available: true,
                    methods: vec![PasskeyUserVerificationMethodDto::MasterPassword],
                }
            )
        );
    }

    #[test]
    fn extension_runtime_does_not_offer_master_password_passkey_verification() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        runtime.allow_unlock_kdf = false;

        let response = runtime
            .handle(RuntimeCommand::GetPasskeyUserVerificationCapability)
            .unwrap();

        assert_eq!(
            response,
            RuntimeResponse::PasskeyUserVerificationCapability(
                PasskeyUserVerificationCapabilityDto {
                    available: false,
                    methods: vec![],
                }
            )
        );
    }

    #[test]
    fn deleting_vault_reference_removes_its_synced_base_copy() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_with_password(&opened.vault_id, "demo-password")
            .unwrap();
        let vault_ref_id = runtime
            .session_state()
            .current_vault_ref_id
            .expect("opened vault reference");
        assert!(
            runtime
                .synced_bases
                .read(&opened.vault_id)
                .unwrap()
                .is_some()
        );

        runtime.delete_vault_reference(&vault_ref_id).unwrap();

        assert!(
            runtime
                .synced_bases
                .read(&opened.vault_id)
                .unwrap()
                .is_none()
        );
        assert!(runtime.list_entries(&opened.vault_id).is_err());
        assert!(!runtime.session_state().unlocked);
    }

    #[test]
    fn deleting_vault_reference_commits_before_retryable_cleanup() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cleanup-pending.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests_with_quick_unlock_failing_delete();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        let vault_ref_id = runtime
            .session_state()
            .current_vault_ref_id
            .expect("opened vault reference");

        let references = runtime.delete_vault_reference(&vault_ref_id).unwrap();

        assert!(references.vaults.is_empty());
        assert!(runtime.list_entries(&opened.vault_id).is_err());
        assert_eq!(runtime.references.pending_cleanups().unwrap().len(), 1);

        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        runtime.reconcile_deleted_vault_cleanups().unwrap();
        assert!(runtime.references.pending_cleanups().unwrap().is_empty());
    }

    #[test]
    fn disabling_global_quick_unlock_revokes_every_known_vault_blob() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_first_dir, _first) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let first_ref = runtime
            .session_state()
            .current_vault_ref_id
            .expect("first vault reference");

        let (_second_dir, _second) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime.set_current_vault(&first_ref).unwrap();

        assert_eq!(
            runtime
                .list_recent_vaults()
                .unwrap()
                .vaults
                .into_iter()
                .filter(|vault| vault.supports_quick_unlock)
                .count(),
            2
        );

        runtime.bind_quick_unlock_policy_gate(Arc::new(AtomicBool::new(false)));
        assert!(runtime.reconcile_quick_unlock(false, None).unwrap());
        assert!(
            runtime
                .list_recent_vaults()
                .unwrap()
                .vaults
                .iter()
                .all(|vault| !vault.supports_quick_unlock)
        );
    }

    #[test]
    fn disabled_quick_unlock_policy_rejects_a_stale_blob_before_unlock() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let vault_ref_id = runtime
            .vault_session
            .current_vault_ref_id()
            .expect("current vault reference")
            .to_owned();
        let storage_key = quick_unlock_storage_key(&vault_ref_id);
        runtime.lock_session();

        runtime.bind_quick_unlock_policy_gate(Arc::new(AtomicBool::new(false)));
        assert!(
            !runtime.reconcile_quick_unlock(true, None).unwrap(),
            "a stale enabled reconciliation snapshot must be skipped"
        );

        assert!(
            runtime.secure_storage.contains(&storage_key).unwrap(),
            "the policy gate must remain authoritative even when reconciliation has not deleted the stale blob"
        );
        let error = runtime
            .unlock_current_vault_with_quick_unlock()
            .expect_err("disabled desired state must reject the stale blob");
        assert!(error.to_string().contains("disabled"), "{error:#}");
        assert!(!runtime.platform_passkey_is_unlocked());
        assert!(runtime.secure_storage.contains(&storage_key).unwrap());
        assert!(
            runtime
                .list_recent_vaults()
                .unwrap()
                .vaults
                .iter()
                .all(|vault| !vault.supports_quick_unlock)
        );
    }

    #[test]
    fn quick_unlock_policy_closing_during_user_presence_does_not_release_the_vault() {
        struct DisablePolicyOnLoadStore {
            gate: Arc<AtomicBool>,
            values: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
        }

        impl SecureStorageProvider for DisablePolicyOnLoadStore {
            fn store(&self, key: &str, value: &[u8]) -> Result<()> {
                self.values
                    .borrow_mut()
                    .insert(key.to_owned(), Zeroizing::new(value.to_vec()));
                Ok(())
            }

            fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
                let value = self.values.borrow().get(key).cloned();
                self.gate.store(false, Ordering::Release);
                Ok(value)
            }

            fn contains(&self, key: &str) -> Result<bool> {
                Ok(self.values.borrow().contains_key(key))
            }

            fn load_requires_user_presence(&self) -> bool {
                true
            }

            fn delete(&self, key: &str) -> Result<()> {
                self.values.borrow_mut().remove(key);
                Ok(())
            }
        }

        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let storage_key = quick_unlock_storage_key(
            runtime
                .vault_session
                .current_vault_ref_id()
                .expect("current vault reference"),
        );
        let blob = runtime
            .secure_storage
            .load(&storage_key)
            .unwrap()
            .expect("enrolled quick-unlock blob");
        let gate = Arc::new(AtomicBool::new(true));
        runtime.secure_storage = Box::new(DisablePolicyOnLoadStore {
            gate: Arc::clone(&gate),
            values: RefCell::new(BTreeMap::from([(storage_key, blob)])),
        });
        runtime.bind_quick_unlock_policy_gate(gate);
        runtime.lock_session();

        let error = runtime
            .unlock_current_vault_with_quick_unlock()
            .expect_err("policy closing during Hello must win over a decrypted blob");

        assert!(error.to_string().contains("disabled"), "{error:#}");
        assert!(!runtime.platform_passkey_is_unlocked());
    }

    #[test]
    fn quick_unlock_credentials_cannot_enroll_a_different_current_vault() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        let credentials = QuickUnlockReconciliationCredentials::from_protocol_input(
            Some("demo-password".into()),
            None,
        )
        .bound_to_vault_ref("another-vault-reference");

        assert!(
            !runtime
                .reconcile_quick_unlock(true, Some(credentials))
                .expect("mismatched enrollment is skipped")
        );
        assert!(
            runtime
                .list_recent_vaults()
                .unwrap()
                .vaults
                .iter()
                .all(|vault| !vault.supports_quick_unlock)
        );
    }

    #[test]
    fn manual_quick_unlock_credentials_are_bound_only_to_the_expected_current_vault() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        let actual_vault_ref_id = runtime
            .session_state()
            .current_vault_ref_id
            .expect("current vault reference");
        let credentials = QuickUnlockReconciliationCredentials::from_protocol_input(
            Some("demo-password".into()),
            None,
        );

        let error = runtime
            .bind_quick_unlock_reconciliation_credentials(credentials, "stale-vault-reference")
            .expect_err("a stale settings page must not bind credentials to another vault");
        assert!(error.to_string().contains("current vault changed"));

        let credentials = QuickUnlockReconciliationCredentials::from_protocol_input(
            Some("demo-password".into()),
            None,
        );
        let bound = runtime
            .bind_quick_unlock_reconciliation_credentials(credentials, &actual_vault_ref_id)
            .expect("matching vault reference binds credentials");
        assert_eq!(bound.vault_ref_id(), Some(actual_vault_ref_id.as_str()));
    }

    #[test]
    fn quick_unlock_reconciliation_drops_failed_credentials_and_retries_from_a_fresh_handoff() {
        struct FailFirstStore {
            fail_next: std::cell::Cell<bool>,
            values: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
        }

        impl SecureStorageProvider for FailFirstStore {
            fn store(&self, key: &str, value: &[u8]) -> Result<()> {
                if self.fail_next.replace(false) {
                    anyhow::bail!("injected enrollment store failure");
                }
                self.values
                    .borrow_mut()
                    .insert(key.to_owned(), Zeroizing::new(value.to_vec()));
                Ok(())
            }

            fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
                Ok(self.values.borrow().get(key).cloned())
            }

            fn contains(&self, key: &str) -> Result<bool> {
                Ok(self.values.borrow().contains_key(key))
            }

            fn delete(&self, key: &str) -> Result<()> {
                self.values.borrow_mut().remove(key);
                Ok(())
            }

            fn purge_quick_unlock_records(&self) -> Result<usize> {
                let count = self.values.borrow().len();
                self.values.borrow_mut().clear();
                Ok(count)
            }
        }

        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        let vault_ref_id = runtime
            .session_state()
            .current_vault_ref_id
            .expect("current vault reference");
        runtime.secure_storage = Box::new(FailFirstStore {
            fail_next: std::cell::Cell::new(true),
            values: RefCell::new(BTreeMap::new()),
        });
        assert!(
            runtime
                .reconcile_quick_unlock(
                    true,
                    Some(
                        QuickUnlockReconciliationCredentials::from_protocol_input(
                            Some("demo-password".into()),
                            None,
                        )
                        .bound_to_vault_ref(&vault_ref_id)
                    ),
                )
                .is_err()
        );
        assert!(runtime.pending_quick_unlock_enrollment.is_none());
        assert!(
            runtime
                .reconcile_quick_unlock(
                    true,
                    Some(
                        QuickUnlockReconciliationCredentials::from_protocol_input(
                            Some("demo-password".into()),
                            None,
                        )
                        .bound_to_vault_ref(&vault_ref_id)
                    ),
                )
                .unwrap()
        );
        assert!(runtime.pending_quick_unlock_enrollment.is_none());
        assert!(runtime.list_recent_vaults().unwrap().vaults[0].supports_quick_unlock);
    }

    #[test]
    fn ordinary_runtime_handle_discards_password_unlock_credentials_before_returning() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        runtime.lock_session();

        let response = runtime
            .handle(RuntimeCommand::UnlockCurrentVaultWithPassword {
                password: "demo-password".into(),
            })
            .expect("password unlock");

        assert!(matches!(response, RuntimeResponse::SessionState(_)));
        assert!(runtime.platform_passkey_is_unlocked());
        assert!(
            runtime.pending_quick_unlock_enrollment.is_none(),
            "the ordinary/native runtime path must not retain plaintext unlock credentials"
        );
    }

    #[test]
    fn resident_runtime_handle_moves_password_unlock_credentials_into_a_one_shot_handoff() {
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        runtime.lock_session();

        let (response, credentials) = runtime
            .handle_with_quick_unlock_handoff(RuntimeCommand::UnlockCurrentVaultWithPassword {
                password: "demo-password".into(),
            })
            .expect("password unlock with reconciliation handoff");

        assert!(matches!(response, RuntimeResponse::SessionState(_)));
        let credentials = credentials.expect("one-shot quick unlock handoff");
        assert_eq!(credentials.password(), Some("demo-password"));
        assert!(credentials.key_file_path.is_none());
        assert!(runtime.pending_quick_unlock_enrollment.is_none());
    }

    #[test]
    fn expired_pre_completion_passkey_ceremony_does_not_block_matching_registration() {
        let mut runtime = VaultCore::for_tests_at(100);

        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "expired-pre-completion-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Preferred,
                challenge_base64url: "Y2hhbGxlbmdlLTE".into(),
                request_id: 42,
                tab_id: 7,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms: 100_000,
                expires_at_epoch_ms: 101_000,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "expired-pre-completion-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                related_origin_verified: false,
            })
            .unwrap();

        runtime.set_test_unix_time_ms(102_000);
        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "replacement-pre-completion-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Preferred,
                challenge_base64url: "Y2hhbGxlbmdlLTI".into(),
                request_id: 43,
                tab_id: 7,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms: 102_000,
                expires_at_epoch_ms: 103_000,
            })
            .unwrap();

        let response = runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "expired-pre-completion-token".into(),
            })
            .unwrap();

        assert_eq!(
            response,
            RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
                known: false,
                phase: None,
                durable_state: None,
                delivery_state: None,
            })
        );
    }

    #[test]
    fn passkey_user_verification_timestamp_is_not_before_same_second_registration() {
        let mut runtime = VaultCore::for_tests_at(100);
        runtime.set_test_unix_time_ms(100_750);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "same-second-uv-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Required,
                challenge_base64url: "Y2hhbGxlbmdlLTE".into(),
                request_id: 42,
                tab_id: 42,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms: 100_500,
                expires_at_epoch_ms: 400_000,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "same-second-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                related_origin_verified: false,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::BindPasskeyCeremonyVault {
                ceremony_token: "same-second-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id.clone(),
            })
            .unwrap();

        let verified = runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: "same-second-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id,
                method: PasskeyUserVerificationMethodDto::MasterPassword,
                password: Some("demo-password".into()),
            })
            .unwrap();

        let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
            panic!("expected passkey UV proof, got {verified:?}");
        };
        assert!(verified.verified_at_epoch_ms >= 100_500);
    }

    #[test]
    fn passkey_master_password_user_verification_does_not_redecrypt_loaded_vault() {
        let mut runtime = VaultCore::for_tests_at(100);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "password-uv-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Required,
                challenge_base64url: "Y2hhbGxlbmdlLTE".into(),
                request_id: 42,
                tab_id: 42,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms: 100_000,
                expires_at_epoch_ms: 400_000,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "password-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                related_origin_verified: false,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::BindPasskeyCeremonyVault {
                ceremony_token: "password-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id.clone(),
            })
            .unwrap();

        runtime
            .vault_session
            .find_loaded_mut(&opened.vault_id)
            .unwrap()
            .bytes = b"not a kdbx".to_vec();

        let verified = runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: "password-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id,
                method: PasskeyUserVerificationMethodDto::MasterPassword,
                password: Some("demo-password".into()),
            })
            .unwrap();

        let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
            panic!("expected passkey UV proof, got {verified:?}");
        };
        assert!(verified.verified);
    }

    #[test]
    fn passkey_master_password_verification_repairs_a_missing_session_base() {
        let mut runtime = VaultCore::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime.session_bases.delete(&opened.vault_id).unwrap();

        runtime
            .verify_passkey_user_with_master_password(&opened.vault_id, "demo-password")
            .expect("the authenticated durable base must repair password verification");
    }

    #[test]
    fn passkey_quick_unlock_user_verification_records_completion_time() {
        let authorized_at_epoch_ms = Arc::new(Mutex::new(None));
        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        runtime.biometric = Box::new(RecordingBiometricProvider {
            authorized_at_epoch_ms: authorized_at_epoch_ms.clone(),
        });
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        *authorized_at_epoch_ms
            .lock()
            .expect("authorization timestamp lock") = None;
        let registered_at_epoch_ms = runtime.current_unix_time_ms();

        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "quick-uv-time-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Required,
                challenge_base64url: "Y2hhbGxlbmdlLTE".into(),
                request_id: 42,
                tab_id: 42,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms,
                expires_at_epoch_ms: registered_at_epoch_ms + 300_000,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "quick-uv-time-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                related_origin_verified: false,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::BindPasskeyCeremonyVault {
                ceremony_token: "quick-uv-time-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id.clone(),
            })
            .unwrap();

        let verified = runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: "quick-uv-time-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id,
                method: PasskeyUserVerificationMethodDto::QuickUnlock,
                password: None,
            })
            .unwrap();

        let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
            panic!("expected passkey UV proof, got {verified:?}");
        };
        let authorized_at = authorized_at_epoch_ms
            .lock()
            .expect("authorization timestamp lock")
            .expect("quick unlock authorization timestamp");
        assert!(verified.verified_at_epoch_ms as u64 >= authorized_at);
    }

    #[test]
    fn passkey_user_verification_capability_reports_quick_unlock_without_loading_secret() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        runtime.secure_storage = Box::new(LoadRejectingSecureStorageProvider::new());
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();

        let response = runtime
            .handle(RuntimeCommand::GetPasskeyUserVerificationCapability)
            .unwrap();

        assert_eq!(
            response,
            RuntimeResponse::PasskeyUserVerificationCapability(
                PasskeyUserVerificationCapabilityDto {
                    available: true,
                    methods: vec![
                        PasskeyUserVerificationMethodDto::MasterPassword,
                        PasskeyUserVerificationMethodDto::QuickUnlock,
                    ],
                }
            )
        );
    }

    #[test]
    fn listing_recent_vaults_checks_quick_unlock_without_loading_secret() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        runtime.secure_storage = Box::new(LoadRejectingSecureStorageProvider::new());
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime.lock_session();

        let listed = runtime.list_recent_vaults().unwrap();

        assert_eq!(listed.vaults.len(), 1);
        assert!(listed.vaults[0].supports_quick_unlock);
    }

    #[test]
    fn listing_recent_vaults_preserves_quick_unlock_after_probe_failures() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests_with_quick_unlock_failing_contains();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let storage_key = quick_unlock_storage_key(
            runtime
                .vault_session
                .current_vault_ref_id()
                .expect("current vault reference"),
        );
        runtime.lock_session();

        let listed = runtime.list_recent_vaults().unwrap();

        assert_eq!(listed.vaults.len(), 1);
        assert!(!listed.vaults[0].supports_quick_unlock);
        assert!(
            runtime.secure_storage.load(&storage_key).unwrap().is_some(),
            "a read-only availability probe must not delete enrolled credentials"
        );
    }

    #[test]
    fn credential_change_requires_a_fresh_authenticated_flow() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("old-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let mut runtime = VaultCore::for_tests_with_quick_unlock();
        runtime.secure_storage = Box::new(LoadRejectingSecureStorageProvider::new());
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("old-password"), None)
            .unwrap();
        let error = runtime
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    credentials: Some(DatabaseCredentialsUpdateDto {
                        new_password: Some("new-password".into()),
                        remove_password: false,
                    }),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .expect_err("credential changes cannot reuse session plaintext");

        assert!(
            error
                .to_string()
                .contains("fresh authenticated credential-update flow")
        );
        runtime.commit_working_copy(&opened.vault_id).unwrap();
    }

    #[test]
    fn quick_unlock_enrollment_and_unlock_avoid_external_authorization_when_storage_enforces_presence()
     {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = VaultCore::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });
        runtime.secure_storage = Box::new(PresenceLoadingSecureStorageProvider::new());

        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime.lock_session();

        runtime.unlock_current_vault_with_quick_unlock().unwrap();

        assert!(
            authorizations
                .lock()
                .expect("authorization lock")
                .is_empty()
        );
    }

    #[test]
    fn quick_unlock_enrollment_uses_external_authorization_when_only_load_enforces_presence() {
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = VaultCore::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });
        runtime.secure_storage = Box::new(LoadPresenceOnlySecureStorageProvider::new());
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();

        assert_eq!(
            authorizations
                .lock()
                .expect("authorization lock")
                .as_slice(),
            ["Enable quick unlock for this vault".to_owned()]
        );
    }

    #[test]
    fn quick_unlock_platform_authorization_precedes_credential_validation_and_blob_write() {
        let authorizations = Arc::new(AtomicUsize::new(0));
        let stores = Arc::new(AtomicUsize::new(0));
        let mut runtime = VaultCore::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider::default());
        runtime.secure_storage = Box::new(EarlyAuthorizingSecureStorageProvider::new(
            authorizations.clone(),
            stores.clone(),
        ));
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .enroll_quick_unlock_for_current_vault(Some("wrong-password"), None)
            .expect_err("wrong credentials must not be enrolled");

        assert_eq!(authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(stores.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_parent_window_handle_is_forwarded_to_secure_storage() {
        let parent_window = Arc::new(Mutex::new(None));
        let mut runtime = VaultCore::for_tests();
        runtime.secure_storage = Box::new(ParentWindowRecordingSecureStorageProvider {
            parent_window: parent_window.clone(),
        });

        runtime.set_parent_window_handle(Some(0x1234));
        assert_eq!(
            *parent_window.lock().expect("parent window lock"),
            Some(0x1234)
        );

        runtime.set_parent_window_handle(None);
        assert_eq!(*parent_window.lock().expect("parent window lock"), None);
    }

    #[test]
    fn passkey_quick_unlock_user_verification_requires_a_fresh_prompt() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = VaultCore::for_tests_at(100);
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());

        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_vault(&opened.vault_id, Some("demo-password"), None)
            .unwrap();
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        runtime.lock_session();

        runtime
            .handle(RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token: "quick-unlock-uv-token".into(),
                connection_id: "connection-1".into(),
                origin: "https://example.com".into(),
                top_origin: None,
                ancestor_origins: vec![],
                relying_party: "example.com".into(),
                ceremony: PasskeyCeremonyKindDto::Get,
                discoverable: false,
                user_verification: PasskeyUserVerificationRequirementDto::Required,
                challenge_base64url: "Y2hhbGxlbmdlLTE".into(),
                request_id: 42,
                tab_id: 42,
                frame_id: 0,
                frame_kind: PasskeyFrameKindDto::Top,
                registered_at_epoch_ms: 100_000,
                expires_at_epoch_ms: 400_000,
            })
            .unwrap();
        runtime
            .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token: "quick-unlock-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
                next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                related_origin_verified: false,
            })
            .unwrap();

        runtime.set_test_unix_time(120);
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        runtime
            .handle(RuntimeCommand::BindPasskeyCeremonyVault {
                ceremony_token: "quick-unlock-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id.clone(),
            })
            .unwrap();

        let verified = runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: "quick-unlock-uv-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id: opened.vault_id,
                method: PasskeyUserVerificationMethodDto::QuickUnlock,
                password: None,
            })
            .unwrap();

        let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
            panic!("expected passkey UV proof, got {verified:?}");
        };
        assert!(verified.verified);
        assert_eq!(
            authorizations
                .lock()
                .expect("authorization lock")
                .as_slice(),
            [
                "Enable quick unlock for this vault".to_owned(),
                "Unlock this vault".to_owned(),
                "Verify user for passkey".to_owned(),
            ]
        );
    }
}
