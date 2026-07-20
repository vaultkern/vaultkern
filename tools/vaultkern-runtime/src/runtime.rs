use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock};
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
    AttachmentContentUpdate, AttachmentMetadataUpdate, Compression, CustomDataItemInput, Entry,
    EntryAttachmentInput, EntryCreate, EntryCustomFieldInput, EntryTimesUpdate, EntryUpdate,
    ExternalKdfConfirmation, ExternalKdfPolicy, KdbxCipher, KdbxError, KdbxVersion, KeepassCore,
    PasskeyRecord, SaveKdf, SaveProfile, ThreeWayPatchReport, TotpSpec, TransformedKey, Vault,
    VaultBinTemplateMetadataUpdate, VaultIdentityMetadataUpdate, VaultLifecycleMetadataUpdate,
    VaultMetadataUpdate, derive_transformed_key_with_policy, load_kdbx_with_transformed_key,
    load_kdbx_with_transformed_key_diagnostic, parse_key_file_bytes, required_version,
    retained_or_recommended_save_kdf, save_kdbx_with_transformed_key, three_way_field_patch,
};
use vaultkern_runtime_protocol::{
    AutofillCacheStateDto, AutofillCommittedFingerprintDto, AutofillPersistConflictCodeDto,
    AutofillPersistDispositionDto, AutofillPersistDurabilityDto, AutofillPersistOutcomeDto,
    AutofillPersistPlanDto, AutofillPersistResultDto, DatabaseEncryptionSettingsDto,
    DatabaseHistorySettingsDto, DatabaseKdfSettingsDto, DatabaseMetadataSettingsDto,
    DatabasePublicMetadataSettingsDto, DatabaseRecycleBinSettingsDto, DatabaseSettingsDto,
    DatabaseSettingsUpdateDto, EntryAttachmentContentDto, EntryAttachmentDto, EntryCustomFieldDto,
    EntryDetailDto, EntryFieldProtectionDto, EntryFieldsDto, EntryHistoryDetailDto,
    EntryHistoryItemDto, EntryHistoryListDto, EntryIdListDto, EntryListDto, EntryPasskeyDto,
    EntrySummaryDto, ErrorDto, FillCandidateListDto, GroupNodeDto, GroupTreeDto, MergeSummaryDto,
    PasskeyAssertionDto, PasskeyCeremonyAdvancedDto, PasskeyCeremonyDeliveryStateDto,
    PasskeyCeremonyDurableStateDto, PasskeyCeremonyKindDto, PasskeyCeremonyLedgerDto,
    PasskeyCeremonyPhaseDto, PasskeyCeremonyReconciledDto, PasskeyCeremonyReconciliationDto,
    PasskeyCeremonyRegisteredDto, PasskeyCeremonyVaultBoundDto, PasskeyCredentialCandidateDto,
    PasskeyCredentialListDto, PasskeyCredentialStatusBatchDto, PasskeyCredentialStatusDto,
    PasskeyFrameKindDto, PasskeyRegistrationDto, PasskeyUserVerificationCapabilityDto,
    PasskeyUserVerificationMethodDto, PasskeyUserVerificationRequirementDto,
    PasskeyUserVerifiedDto, RuntimeCommand, RuntimeResponse, SaveVaultResultDto,
    SaveVaultStatusDto, VaultHandleDto, VaultReferenceDto, VaultReferenceListDto,
    VaultSourceStatusDto,
};

use crate::autofill_persist::{
    AUTOFILL_RECEIPT_KEY, AutofillPersistEngineError, AutofillPersistEngineInput,
    AutofillPersistLogicalOutcome, PreparedAutofillPersist, effective_xml_field_protection,
    plan_sha256, prepare_autofill_persist, totp_specs_semantically_equal,
};
use crate::command_loop::format_error_chain;
use crate::match_fill::{FillMatchScore, score_entry_match};
use crate::passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, PlatformPasskeyAssertionInput,
    PlatformPasskeyAssertionOutput, PlatformPasskeyAssertionRequest, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
    PlatformPasskeyRegistrationRequest, create_assertion, create_platform_assertion,
    create_platform_registration_with_credential_id, create_registration_with_credential_id,
    generate_passkey_credential_id,
};
use crate::providers::biometric::{
    BiometricProvider, TestBiometricProvider, UnsupportedBiometricProvider,
    default_biometric_provider,
};
use crate::providers::local_file::{
    LocalFileCommitError, LocalFileVaultSourceProvider, VaultSourceFingerprint,
};
use crate::providers::onedrive::{
    OneDriveConditionalWriteOutcome, OneDriveMemoryAccessCounts, OneDriveMemoryWriteBehavior,
    OneDriveVaultSourceProvider,
};
use crate::providers::remote_cache::{
    PendingRemoteCacheChain, PendingRemoteCacheChainError, PendingRemoteCacheCompletion,
    RemoteCacheKey, RemoteVaultCache, RemoteVaultCacheEntry,
};
use crate::providers::secure_storage::{
    FailingContainsSecureStorageProvider, FailingDeleteSecureStorageProvider,
    MemorySecureStorageProvider, SecureStorageProvider, UnsupportedSecureStorageProvider,
    default_secure_storage_provider, default_secure_storage_provider_for_extension_id,
};
use crate::session::{
    LoadedVault, VaultSession, VaultSource, onedrive_remote_id, onedrive_vault_id,
};
use crate::state_paths::extension_id_from_browser_origin;
use crate::sync::{SyncedBaseStore, write_local_conflict_copy};
use crate::unlock::{
    MasterCredential, MasterCredentialShape, UnlockAttempt, enroll_unlock_blob, unlock_from_blob,
    unlock_historical_snapshot_from_blob,
};
use crate::vault_reference_store::{StoredVaultSource, VaultReferenceStore};

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
    fingerprint: VaultSourceFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingAutofillSyncRequired;

impl std::fmt::Display for PendingAutofillSyncRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "retry vault source sync before saving while an autofill operation is pending"
        )
    }
}

impl std::error::Error for PendingAutofillSyncRequired {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingGenericCasConflict;

impl std::fmt::Display for PendingGenericCasConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OneDrive changed during pending synchronization")
    }
}

impl std::error::Error for PendingGenericCasConflict {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasskeyCeremonyIdentity {
    connection_id: String,
    origin: String,
    top_origin: Option<String>,
    ancestor_origins: Vec<String>,
    relying_party: String,
    ceremony: PasskeyCeremonyKindDto,
    discoverable: bool,
    user_verification: PasskeyUserVerificationRequirementDto,
    challenge_base64url: String,
    request_id: i64,
    tab_id: i64,
    frame_id: i64,
    frame_kind: PasskeyFrameKindDto,
    registered_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
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

pub struct Runtime {
    core: KeepassCore,
    vault_session: VaultSession,
    references: VaultReferenceStore,
    local_files: LocalFileVaultSourceProvider,
    one_drive: OneDriveVaultSourceProvider,
    remote_cache: RemoteVaultCache,
    synced_bases: SyncedBaseStore,
    biometric: Box<dyn BiometricProvider>,
    secure_storage: Box<dyn SecureStorageProvider>,
    allow_unlock_kdf: bool,
    passkey_ceremonies: BTreeMap<String, PasskeyCeremonyLedgerEntry>,
    recent_unlock_user_verification: Option<PasskeyUserVerificationProof>,
    passkey_credential_id_generator: Box<dyn FnMut() -> String>,
    fixed_unix_time: Option<u64>,
    fixed_unix_time_ms: Option<u64>,
    #[cfg(test)]
    local_save_warnings: Vec<String>,
}

impl Runtime {
    fn external_open_kdf_policy() -> (ExternalKdfPolicy, ExternalKdfConfirmation) {
        (
            ExternalKdfPolicy::Desktop,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    fn load_session_database(
        bytes: &[u8],
        key: &TransformedKey,
    ) -> std::result::Result<SessionLoadedDatabase, KdbxError> {
        load_kdbx_with_transformed_key(bytes, key).map(|vault| SessionLoadedDatabase { vault })
    }

    fn inspected_save_profile(&self, bytes: &[u8]) -> Result<SaveProfile> {
        let inspection = self
            .core
            .inspect_database(bytes)
            .context("failed to inspect KDBX save profile")?;
        Ok(SaveProfile {
            version: inspection.save_target_version,
            cipher: inspection.header.cipher,
            compression: inspection.header.compression,
            kdf: None,
        })
    }

    fn merge_save_profile(
        base: &SaveProfile,
        local: &SaveProfile,
        remote: &SaveProfile,
    ) -> Result<SaveProfile> {
        let mut local = local.clone();
        local.kdf = None;
        if &local == base {
            return Ok(remote.clone());
        }
        if remote == base || remote == &local {
            return Ok(local);
        }
        anyhow::bail!("KDBX encryption profile changed concurrently")
    }

    pub fn new() -> Self {
        Self::new_with_state(
            VaultReferenceStore::new_default(),
            OneDriveVaultSourceProvider::new_from_env(),
            RemoteVaultCache::new_default(),
            SyncedBaseStore::new_default(),
            default_secure_storage_provider(),
            true,
        )
    }

    pub fn new_for_browser_origin(origin: &str) -> Self {
        if let Some(extension_id) = extension_id_from_browser_origin(origin) {
            return Self::new_with_state(
                VaultReferenceStore::new_for_extension_id(extension_id),
                OneDriveVaultSourceProvider::new_from_env_for_extension_id(extension_id),
                RemoteVaultCache::new_for_extension_id(extension_id),
                SyncedBaseStore::new_for_extension_id(extension_id),
                default_secure_storage_provider_for_extension_id(Some(extension_id)),
                false,
            );
        }

        Self::new()
    }

    fn new_with_state(
        references: VaultReferenceStore,
        one_drive: OneDriveVaultSourceProvider,
        remote_cache: RemoteVaultCache,
        synced_bases: SyncedBaseStore,
        secure_storage: Box<dyn SecureStorageProvider>,
        allow_unlock_kdf: bool,
    ) -> Self {
        let mut vault_session = VaultSession::default();
        if let Some(vault_ref_id) = references.current_vault_ref_id() {
            vault_session.set_current_vault(vault_ref_id.to_owned());
        }

        Self {
            core: KeepassCore::new(),
            vault_session,
            references,
            local_files: LocalFileVaultSourceProvider::default(),
            one_drive,
            remote_cache,
            synced_bases,
            biometric: default_biometric_provider(),
            secure_storage,
            allow_unlock_kdf,
            passkey_ceremonies: BTreeMap::new(),
            recent_unlock_user_verification: None,
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
            fixed_unix_time_ms: None,
            #[cfg(test)]
            local_save_warnings: Vec::new(),
        }
    }

    pub fn for_tests() -> Self {
        Self {
            core: KeepassCore::new(),
            vault_session: VaultSession::default(),
            references: VaultReferenceStore::new_in_memory(),
            local_files: LocalFileVaultSourceProvider::default(),
            one_drive: OneDriveVaultSourceProvider::new_in_memory(),
            remote_cache: RemoteVaultCache::new_at(std::env::temp_dir().join(format!(
                "vaultkern-runtime-test-remote-cache-{}",
                uuid::Uuid::new_v4()
            ))),
            synced_bases: SyncedBaseStore::new_at(std::env::temp_dir().join(format!(
                "vaultkern-runtime-test-synced-bases-{}",
                uuid::Uuid::new_v4()
            ))),
            biometric: Box::new(UnsupportedBiometricProvider),
            secure_storage: Box::new(UnsupportedSecureStorageProvider),
            allow_unlock_kdf: true,
            passkey_ceremonies: BTreeMap::new(),
            recent_unlock_user_verification: None,
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
            fixed_unix_time_ms: None,
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
        self.secure_storage.set_parent_window_handle(parent_window);
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
            .one_drive
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
        self.one_drive.replace_memory_item(drive_id, item_id, bytes);
    }

    pub fn insert_test_onedrive_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) {
        self.one_drive
            .insert_memory_item(drive_id, item_id, name, account_label, bytes);
    }

    pub fn remove_test_onedrive_item(&mut self, drive_id: &str, item_id: &str) {
        self.one_drive.remove_memory_item(drive_id, item_id);
    }

    pub fn read_test_onedrive_item_bytes(&self, drive_id: &str, item_id: &str) -> Result<Vec<u8>> {
        self.one_drive.read_memory_item_bytes(drive_id, item_id)
    }

    pub fn test_onedrive_item_revision(&self, drive_id: &str, item_id: &str) -> Result<u64> {
        self.one_drive.memory_item_revision(drive_id, item_id)
    }

    pub fn set_test_onedrive_item_revision(
        &mut self,
        drive_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        self.one_drive
            .set_memory_item_revision(drive_id, item_id, revision)
    }

    pub fn reset_test_onedrive_access_counts(&self) {
        self.one_drive.reset_memory_access_counts();
    }

    pub fn test_onedrive_access_counts(&self) -> OneDriveMemoryAccessCounts {
        self.one_drive.memory_access_counts()
    }

    pub fn queue_test_onedrive_precondition_failure(&mut self, replacement_bytes: Option<Vec<u8>>) {
        self.one_drive.queue_memory_write_behavior(
            OneDriveMemoryWriteBehavior::PreconditionFailed { replacement_bytes },
        );
    }

    pub fn queue_test_onedrive_ambiguous_write(&mut self, committed: bool) {
        self.one_drive.queue_memory_write_behavior(if committed {
            OneDriveMemoryWriteBehavior::OutcomeUnknownCommitted
        } else {
            OneDriveMemoryWriteBehavior::OutcomeUnknownNotCommitted
        });
    }

    pub fn open_local_vault(&mut self, path: &str) -> Result<VaultHandleDto> {
        let path = normalize_local_path(path)?;
        self.load_local_vault_snapshot(&path)
    }

    fn load_local_vault_snapshot(&mut self, path: &str) -> Result<VaultHandleDto> {
        let snapshot = self
            .local_files
            .read_snapshot(path)
            .with_context(|| format!("failed to read vault: {path}"))?;
        let bytes = snapshot.bytes;
        let baseline_fingerprint = snapshot.fingerprint;
        let vault_id = path.to_owned();
        self.synced_bases
            .store(&vault_id, &bytes)
            .with_context(|| format!("failed to store synced base: {vault_id}"))?;
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
                credential_shape: MasterCredentialShape {
                    has_password: false,
                    has_key_file: false,
                },
                save_profile: SaveProfile::recommended(),
                requires_source_migration: false,
                autosave_delay_seconds: None,
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

    fn load_source_snapshot(&mut self, source: StoredVaultSource) -> Result<VaultHandleDto> {
        match source {
            StoredVaultSource::LocalPath(path) => self.load_local_vault_snapshot(&path),
            StoredVaultSource::OneDriveItem {
                drive_id, item_id, ..
            } => {
                let vault_source = VaultSource::OneDriveItem {
                    drive_id: drive_id.clone(),
                    item_id: item_id.clone(),
                };
                let cache_key = remote_cache_key_for_source(&vault_source).expect("remote source");
                let vault_id = vault_source.vault_id();
                let (
                    name,
                    path_name,
                    bytes,
                    baseline_fingerprint,
                    source_status,
                    source_account_label,
                ) = if let Some(cached) = self.remote_cache.read(&cache_key)? {
                    if cached.pending_sync {
                        let display_name = cached.display_name;
                        let account_label = cached.account_label;
                        (
                            display_name.clone(),
                            display_name,
                            cached.bytes,
                            cached.fingerprint,
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
                        match self.one_drive.remote_state(&drive_id, &item_id) {
                            Ok(state) if state.matches_fingerprint(&cached.fingerprint) => {
                                let display_name = cached.display_name;
                                let account_label = cached.account_label;
                                (
                                    display_name.clone(),
                                    display_name,
                                    cached.bytes,
                                    cached.fingerprint,
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
                                    .one_drive
                                    .read_snapshot_from_state(&drive_id, &item_id, &state)?;
                                let name = display_name_for_cloud_name(&snapshot.name);
                                let path_name = snapshot.name.clone();
                                let account_label = snapshot.account_label.clone();
                                let cached_at = self.current_unix_time() as i64;
                                self.remote_cache.write(
                                    &cache_key,
                                    RemoteVaultCacheEntry {
                                        bytes: snapshot.bytes.clone(),
                                        fingerprint: snapshot.fingerprint.clone(),
                                        display_name: name.clone(),
                                        account_label: account_label.clone(),
                                        cached_at,
                                        pending_sync: false,
                                    },
                                )?;
                                (
                                    name,
                                    path_name,
                                    snapshot.bytes,
                                    snapshot.fingerprint,
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
                    let snapshot_result = match &vault_source {
                        VaultSource::OneDriveItem { drive_id, item_id } => {
                            self.one_drive.read_snapshot(drive_id, item_id)
                        }
                        VaultSource::LocalPath(_) => unreachable!(),
                    };
                    match snapshot_result {
                        Ok(snapshot) => {
                            let name = display_name_for_cloud_name(&snapshot.name);
                            let path_name = snapshot.name.clone();
                            let account_label = snapshot.account_label.clone();
                            let cached_at = self.current_unix_time() as i64;
                            let _ = self.remote_cache.write(
                                &cache_key,
                                RemoteVaultCacheEntry {
                                    bytes: snapshot.bytes.clone(),
                                    fingerprint: snapshot.fingerprint.clone(),
                                    display_name: name.clone(),
                                    account_label: account_label.clone(),
                                    cached_at,
                                    pending_sync: false,
                                },
                            );
                            (
                                name,
                                path_name,
                                snapshot.bytes,
                                snapshot.fingerprint,
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

                if !source_status
                    .as_ref()
                    .is_some_and(|status| status.remote_state == "pending_sync")
                {
                    self.synced_bases
                        .store(&vault_id, &bytes)
                        .with_context(|| format!("failed to store synced base: {vault_id}"))?;
                }

                self.vault_session.insert_loaded(
                    vault_id.clone(),
                    LoadedVault {
                        source: vault_source,
                        name: name.clone(),
                        bytes,
                        baseline_fingerprint,
                        credential_shape: MasterCredentialShape {
                            has_password: false,
                            has_key_file: false,
                        },
                        save_profile: SaveProfile::recommended(),
                        requires_source_migration: false,
                        autosave_delay_seconds: None,
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
        let metadata = self.one_drive.metadata(drive_id, item_id)?;
        let reference = self.references.upsert_onedrive_item(
            &metadata.drive_id,
            &metadata.item_id,
            &metadata.name,
            &metadata.account_label,
            self.current_unix_time() as i64,
        )?;
        self.vault_session
            .set_current_vault(reference.vault_ref_id.clone());
        Ok(reference)
    }

    pub fn list_recent_vaults(&self) -> Result<VaultReferenceListDto> {
        let mut list = self.references.list_recent_vaults();
        if self.biometric.supports_quick_unlock() {
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
        self.references
            .mark_current(vault_ref_id, self.current_unix_time() as i64)?;
        self.vault_session
            .set_current_vault(vault_ref_id.to_owned());
        Ok(())
    }

    pub fn delete_vault_reference(&mut self, vault_ref_id: &str) -> Result<VaultReferenceListDto> {
        let source = self.references.source_for(vault_ref_id).ok();
        let vault_id = source.as_ref().map(vault_id_for_stored_source);
        if let Some(cache_key) = source.as_ref().and_then(remote_cache_key_for_stored_source) {
            self.remote_cache.delete(&cache_key)?;
        }
        if let Some(source) = source.as_ref() {
            self.synced_bases
                .delete(&vault_id_for_stored_source(source))?;
        }
        let deleted_current = self.references.delete(vault_ref_id)?;
        if let Some(vault_id) = vault_id.as_deref() {
            self.vault_session.remove_loaded(vault_id);
        }
        let _ = self
            .secure_storage
            .delete(&quick_unlock_storage_key(vault_ref_id));
        if deleted_current {
            self.vault_session.clear_current_vault();
        }
        self.list_recent_vaults()
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
        let master_credential = master_credential_from_parts(password, key_file_path)?;
        let current_vault_ref_id = self.references.find_ref_id_by_path(vault_id).or_else(|| {
            self.vault_session
                .current_vault_ref_id()
                .map(ToOwned::to_owned)
        });
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;

        let credential_shape = master_credential.shape();
        let key = master_credential.to_composite_key();
        let (vault, transformed_key, save_profile, name, migrated_base) = {
            let (policy, confirmation) = Self::external_open_kdf_policy();
            let inspection = self
                .core
                .inspect_database(&loaded.bytes)
                .with_context(|| format!("failed to inspect vault: {vault_id}"))?;
            if matches!(
                inspection.header.version,
                KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1
            ) {
                let legacy = self
                    .core
                    .load_kdbx_with_policy(&loaded.bytes, &key, &policy, confirmation)
                    .with_context(|| format!("failed to unlock vault: {vault_id}"))?;
                let migration_profile = SaveProfile {
                    version: inspection.save_target_version,
                    cipher: inspection.header.cipher,
                    compression: inspection.header.compression,
                    kdf: Some(SaveKdf::recommended()),
                };
                let migrated = self
                    .core
                    .save_kdbx(&legacy, &key, migration_profile.clone())
                    .with_context(|| format!("failed to migrate legacy vault: {vault_id}"))?;
                let transformed_key =
                    derive_transformed_key_with_policy(&migrated, &key, &policy, confirmation)
                        .with_context(|| {
                            format!("failed to derive migrated vault key: {vault_id}")
                        })?;
                let vault = load_kdbx_with_transformed_key_diagnostic(&migrated, &transformed_key)
                    .with_context(|| format!("failed to load migrated vault: {vault_id}"))?;
                let name = vault.name.clone();
                (
                    vault,
                    transformed_key,
                    SaveProfile {
                        kdf: None,
                        ..migration_profile
                    },
                    name,
                    Some(migrated),
                )
            } else {
                let transformed_key =
                    derive_transformed_key_with_policy(&loaded.bytes, &key, &policy, confirmation)
                        .with_context(|| format!("failed to derive vault key: {vault_id}"))?;
                let vault =
                    load_kdbx_with_transformed_key_diagnostic(&loaded.bytes, &transformed_key)
                        .with_context(|| format!("failed to unlock vault: {vault_id}"))?;
                let name = vault.name.clone();
                (
                    vault,
                    transformed_key,
                    SaveProfile {
                        version: inspection.save_target_version,
                        cipher: inspection.header.cipher,
                        compression: inspection.header.compression,
                        kdf: None,
                    },
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
        self.recent_unlock_user_verification = None;
        Ok(())
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
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let source = self.references.source_for(&current_vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        if self.vault_session.is_preloaded_for_unlock(&vault_id) {
            return self.unlock_vault(&vault_id, password, key_file_path);
        }
        let handle = self.load_source_snapshot(source)?;
        self.unlock_vault(&handle.vault_id, password, key_file_path)
    }

    pub fn lock_session(&mut self) {
        let vault_ids = self
            .vault_session
            .loaded_vault_ids()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        for vault_id in vault_ids {
            if let Ok(Some(bytes)) = self.synced_bases.read(&vault_id) {
                if let Some(loaded) = self.vault_session.find_loaded_mut(&vault_id) {
                    loaded.bytes = bytes;
                }
            }
        }
        self.vault_session.lock_all();
        self.recent_unlock_user_verification = None;
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
        let master_credential = master_credential_from_parts(password, key_file_path)?;
        let file_bytes = match self.read_current_snapshot(&active_vault_id, None) {
            Ok(snapshot) => snapshot
                .bytes
                .context("current vault source did not include bytes")?,
            Err(_) => self
                .synced_bases
                .read(&active_vault_id)?
                .context("synced base is unavailable for quick unlock enrollment")?,
        };
        let (policy, confirmation) = Self::external_open_kdf_policy();
        let transformed_key = derive_transformed_key_with_policy(
            &file_bytes,
            &master_credential.to_composite_key(),
            &policy,
            confirmation,
        )?;
        load_kdbx_with_transformed_key(&file_bytes, &transformed_key)
            .context("quick unlock enrollment credentials do not unlock the vault")?;
        enroll_unlock_blob(
            self.secure_storage.as_ref(),
            &quick_unlock_storage_key(&current_vault_ref_id),
            &master_credential,
            &transformed_key,
        )?;
        Ok(())
    }

    pub fn unlock_current_vault_with_quick_unlock(&mut self) -> Result<()> {
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("biometric quick unlock is not implemented on this host");
        }
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        if !self.secure_storage.load_requires_user_presence() {
            self.biometric.authorize("Unlock this vault")?;
        }
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        let source = self.references.source_for(&current_vault_ref_id)?;
        let handle = self.load_source_snapshot(source)?;
        let (attempt, save_profile) = {
            let loaded = self
                .vault_session
                .find_loaded(&handle.vault_id)
                .with_context(|| format!("vault not opened: {}", handle.vault_id))?;
            let inspection = self
                .core
                .inspect_database(&loaded.bytes)
                .with_context(|| format!("failed to inspect vault: {}", handle.vault_id))?;
            let attempt = unlock_from_blob(
                self.secure_storage.as_ref(),
                &storage_key,
                &loaded.bytes,
                self.allow_unlock_kdf,
            )?;
            (
                attempt,
                SaveProfile {
                    version: inspection.save_target_version,
                    cipher: inspection.header.cipher,
                    compression: inspection.header.compression,
                    kdf: None,
                },
            )
        };
        let unlocked = match attempt {
            UnlockAttempt::Unlocked(unlocked) => unlocked,
            UnlockAttempt::NotEnrolled => {
                anyhow::bail!("quick unlock is not enabled for the current vault")
            }
            UnlockAttempt::Cancelled => anyhow::bail!("quick unlock was cancelled"),
            UnlockAttempt::OpenAppRequired => {
                anyhow::bail!("quick unlock cache miss; open the resident app once")
            }
            UnlockAttempt::CredentialRequired => {
                anyhow::bail!("stored master credential no longer unlocks this vault")
            }
        };
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
        self.record_recent_unlock_user_verification(
            &handle.vault_id,
            PasskeyUserVerificationMethodDto::QuickUnlock,
        );
        Ok(())
    }

    pub fn disable_quick_unlock_for_current_vault(&mut self) -> Result<()> {
        let current_vault_ref_id = self
            .vault_session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        self.secure_storage
            .delete(&quick_unlock_storage_key(&current_vault_ref_id))
    }

    pub fn session_state(&self) -> vaultkern_runtime_protocol::SessionStateDto {
        let mut dto = self
            .vault_session
            .to_dto(self.biometric.supports_quick_unlock());
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

        if self.biometric.supports_quick_unlock() {
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
        let recent_unlock_verified = {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if entry.phase != expected_phase {
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            validate_passkey_ceremony_not_expired(entry, validation_epoch_ms)?;
            validate_passkey_ceremony_vault_binding(entry, vault_id)?;
            self.recent_unlock_user_verification_matches(
                entry,
                vault_id,
                method,
                validation_epoch_ms,
            )
        };

        match method {
            PasskeyUserVerificationMethodDto::MasterPassword => {
                if !recent_unlock_verified {
                    let password =
                        password.context("passkey user verification password is required")?;
                    self.verify_passkey_user_with_master_password(vault_id, password)?;
                }
            }
            PasskeyUserVerificationMethodDto::QuickUnlock => {
                if !recent_unlock_verified {
                    self.verify_passkey_user_with_quick_unlock(vault_id)?;
                }
            }
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

    fn record_recent_unlock_user_verification(
        &mut self,
        vault_id: &str,
        method: PasskeyUserVerificationMethodDto,
    ) {
        let now_epoch_ms = self.current_unix_time_ms();
        self.recent_unlock_user_verification = Some(PasskeyUserVerificationProof {
            vault_id: vault_id.to_owned(),
            method,
            verified_at_epoch_ms: now_epoch_ms,
        });
    }

    fn recent_unlock_user_verification_matches(
        &self,
        entry: &PasskeyCeremonyLedgerEntry,
        vault_id: &str,
        method: PasskeyUserVerificationMethodDto,
        now_epoch_ms: u64,
    ) -> bool {
        self.recent_unlock_user_verification
            .as_ref()
            .is_some_and(|proof| {
                proof.vault_id == vault_id
                    && proof.method == method
                    && proof.verified_at_epoch_ms >= entry.identity.registered_at_epoch_ms
                    && proof.verified_at_epoch_ms <= now_epoch_ms
                    && proof.verified_at_epoch_ms <= entry.identity.expires_at_epoch_ms
            })
    }

    fn verify_passkey_user_with_master_password(
        &self,
        vault_id: &str,
        password: &str,
    ) -> Result<()> {
        let (session_key, pending_cache_key) = {
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
            self.synced_bases
                .read(vault_id)?
                .context("synced base is unavailable for password verification")?
        };
        let candidate = MasterCredential::new(Some(password.as_bytes()), None)?;
        let (policy, confirmation) = Self::external_open_kdf_policy();
        let candidate_key = derive_transformed_key_with_policy(
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

    fn verify_passkey_user_with_quick_unlock(&self, vault_id: &str) -> Result<()> {
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
        self.biometric.authorize("Verify user for passkey")?;
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
        let detail = self
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
            id: detail.id,
            title: detail.title,
            username: detail.username,
            password: detail.password,
            url: detail.url,
            notes: detail.notes,
            modified_at: detail.modified_at,
            totp: totp_code,
            totp_uri,
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
                .map(|field| EntryCustomFieldDto {
                    key: field.key,
                    value: field.value,
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

        Ok(database_settings_dto(
            vault,
            &loaded.save_profile,
            loaded.autosave_delay_seconds,
            loaded.credential_shape.has_password,
        ))
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
                let requested_kdf = requested
                    .kdf
                    .as_ref()
                    .expect("settings always carry explicit KDF parameters");
                if requested_kdf != &retained_or_recommended_save_kdf(vault)? {
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
                let mut requested = save_profile_from_settings(encryption)?;
                let requested_kdf = requested
                    .kdf
                    .take()
                    .expect("settings always carry explicit KDF parameters");
                let preserves_retained_kdf = loaded.save_profile.kdf.is_none()
                    && requested_kdf == retained_or_recommended_save_kdf(vault)?;
                requested.kdf = (!preserves_retained_kdf).then_some(requested_kdf);
                loaded.save_profile = requested;
            }

            if let Some(autosave_delay_seconds) = update.autosave_delay_seconds {
                loaded.autosave_delay_seconds = Some(autosave_delay_seconds);
            }

            database_settings_dto(
                vault,
                &loaded.save_profile,
                loaded.autosave_delay_seconds,
                loaded.credential_shape.has_password,
            )
        };

        Ok(settings)
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
            left.score
                .host_match
                .cmp(&right.score.host_match)
                .then_with(|| right.score.exact_path.cmp(&left.score.exact_path))
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
        let detail = self
            .core
            .project_entry_history_detail(vault, entry_id, history_index)?;
        let custom_fields =
            self.core
                .list_entry_history_custom_fields(vault, entry_id, history_index)?;
        let attachments =
            self.core
                .list_entry_history_attachments(vault, entry_id, history_index)?;

        Ok(EntryHistoryDetailDto {
            entry_id: entry_id.into(),
            history_index,
            title: detail.title,
            username: detail.username,
            password: detail.password,
            url: detail.url,
            notes: detail.notes,
            modified_at: detail.modified_at,
            custom_fields: custom_fields
                .into_iter()
                .map(|field| EntryCustomFieldDto {
                    key: field.key,
                    value: field.value,
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

    pub fn create_entry(
        &mut self,
        vault_id: &str,
        parent_group_id: &str,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        totp_uri: Option<String>,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        let totp = parse_totp_uri(totp_uri)?;
        let entry_id = {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

            let created = self.core.add_entry(
                vault,
                parent_group_id,
                EntryCreate {
                    title,
                    username,
                    password,
                    url,
                    notes,
                },
            )?;

            initialize_entry_creation_times(&self.core, vault, &created.id, modified_at)?;

            if let Some(totp) = totp {
                self.core.set_entry_totp(vault, &created.id, totp)?;
            }

            created.id
        };

        self.get_entry_detail(vault_id, &entry_id)
    }

    fn exact_matching_entry_ids(
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
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
        totp_uri: Option<String>,
        custom_fields: Vec<EntryCustomFieldDto>,
    ) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        let requested_totp = parse_totp_uri(totp_uri)?;
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
                    title: Some(title),
                    username: Some(username),
                    password: Some(password),
                    url: Some(url),
                    notes: Some(notes),
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
                .map(|field| field.key)
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
                            value: field.value,
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

    pub fn compare_and_update_entry_fields(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        expected_fields: EntryFieldsDto,
        desired_fields: EntryFieldsDto,
    ) -> Result<Option<EntryDetailDto>> {
        if self.vault_session.active_vault_id() != Some(vault_id) {
            return Ok(None);
        }
        if parse_totp_uri(desired_fields.totp_uri.clone()).is_err() {
            return Ok(None);
        }
        let current = match self.get_entry_detail(vault_id, entry_id) {
            Ok(current) => current,
            Err(_) => return Ok(None),
        };
        if !entry_detail_matches_fields(&current, &expected_fields) {
            return Ok(None);
        }
        if expected_fields == desired_fields {
            return Ok(Some(current));
        }
        self.update_entry_fields(
            vault_id,
            entry_id,
            desired_fields.title,
            desired_fields.username,
            desired_fields.password,
            desired_fields.url,
            desired_fields.notes,
            desired_fields.totp_uri,
            desired_fields.custom_fields,
        )
        .map(Some)
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
        passkey: EntryPasskeyDto,
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
            let passkey = dto_to_passkey_record(passkey)?;
            self.core.snapshot_entry_to_history(vault, entry_id)?;
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

    pub fn list_platform_passkey_credentials(&self) -> Result<Vec<PlatformPasskeyCredential>> {
        let vault_id = self.active_platform_passkey_vault_id()?;
        let vault = self.loaded_vault(&vault_id)?;
        let mut passkeys = Vec::new();
        visit_passkeys(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &mut |passkey| passkeys.push(passkey),
        );
        Ok(passkeys
            .into_iter()
            .filter(|passkey| passkey.user_handle.is_some())
            .filter_map(|passkey| platform_passkey_credential(passkey).ok())
            .collect())
    }

    pub fn register_platform_passkey(
        &mut self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput> {
        let vault_id = self.active_platform_passkey_vault_id()?;
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
        let credential = platform_passkey_credential(&registration.passkey)?;
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
            let refresh_entry_username = rollback_entry
                .passkey
                .as_ref()
                .is_some_and(|passkey| rollback_entry.username == passkey.username);
            let next_username = registration.passkey.username.clone();
            let rollback = PasskeyRegistrationRollbackState {
                vault_id: vault_id.clone(),
                entry_id: entry_id.clone(),
                credential_id: Some(registration.passkey.credential_id.clone()),
                created: false,
                rollback_entry: Some(rollback_entry),
            };
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
            if refresh_entry_username {
                self.core.update_entry_fields(
                    vault,
                    &entry_id,
                    EntryUpdate {
                        title: None,
                        username: Some(next_username),
                        password: None,
                        url: None,
                        notes: None,
                    },
                )?;
            }
            touch_entry_modified_at(&self.core, vault, &entry_id, modified_at)?;
            enforce_history_limits(vault);
            (entry_id, rollback)
        } else {
            let mut entry = Entry::new(input.relying_party.clone());
            entry.username = input.user_name;
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
            initialize_entry_creation_times(&self.core, vault, &entry_id, modified_at)?;
            (entry_id, rollback)
        };

        let save_error = match self.save_vault(&vault_id) {
            Ok(RuntimeResponse::SaveVaultResult(result))
                if result.status != SaveVaultStatusDto::ConflictCopy =>
            {
                None
            }
            Ok(RuntimeResponse::SaveVaultResult(result)) => Some(anyhow::anyhow!(
                "platform passkey registration was saved only to conflict copy: {}",
                result.conflict_copy_path.as_deref().unwrap_or("unknown")
            )),
            Ok(response) => Some(anyhow::anyhow!(
                "platform passkey registration received an unexpected save response: {response:?}"
            )),
            Err(error) => Some(error),
        };
        if let Some(save_error) = save_error {
            return match self.restore_passkey_registration_rollback(rollback) {
                Ok(()) => Err(save_error),
                Err(rollback_error) => Err(save_error).context(format!(
                    "failed to roll back platform passkey registration: {rollback_error:#}"
                )),
            };
        }

        let retained_credential_id = URL_SAFE_NO_PAD.encode(&credential.credential_id);
        let retained_vault = self.loaded_vault(&vault_id)?;
        find_unique_passkey_by_credential_id_and_relying_party(
            &retained_vault.root,
            retained_vault.recycle_bin_group,
            retained_vault.recycle_bin_enabled.unwrap_or(true),
            &retained_credential_id,
            Some(&credential.relying_party),
        )
        .context("platform passkey registration was not retained after the durable save")?;

        Ok(PlatformPasskeyRegistrationOutput {
            entry_id,
            credential,
            authenticator_data: registration.authenticator_data,
        })
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
        let user_verified = self.passkey_ceremony_user_verified(ceremony_token, vault_id)?;
        let credential_id = credential_id.context("passkey assertion credential id is required")?;
        let effective_user_presence_verified = user_presence_verified || user_verified;
        if !effective_user_presence_verified {
            anyhow::bail!("passkey user presence was not verified");
        }
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
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

    fn passkey_ceremony_user_verified(&self, ceremony_token: &str, vault_id: &str) -> Result<bool> {
        let now_epoch_ms = self.current_unix_time_ms();
        let entry = self
            .passkey_ceremonies
            .get(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        let verified = entry.user_verification.as_ref().is_some_and(|proof| {
            proof.vault_id == vault_id
                && proof.verified_at_epoch_ms >= entry.identity.registered_at_epoch_ms
                && proof.verified_at_epoch_ms <= now_epoch_ms
        });
        if entry.identity.user_verification == PasskeyUserVerificationRequirementDto::Required
            && !verified
        {
            anyhow::bail!("passkey user verification was not verified");
        }
        Ok(verified)
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

    fn register_passkey_ceremony(
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

    fn advance_passkey_ceremony_phase(
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

    fn bind_passkey_ceremony_vault(
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

    fn query_passkey_ceremony_ledger(&self, ceremony_token: &str) -> PasskeyCeremonyLedgerDto {
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

    fn reconcile_passkey_ceremony_ledger(
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

    fn mark_passkey_ceremony_unknown_delivery(
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
        let user_verified = self.passkey_ceremony_user_verified(ceremony_token, vault_id)?;
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
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
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
                let response = self.save_vault(&vault_id)?;
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

        let response = self.save_vault(vault_id)?;
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
            data_base64: BASE64_STANDARD.encode(content.data),
            protect_in_memory,
        })
    }

    pub fn add_entry_attachment(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        name: String,
        data_base64: String,
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
        data_base64: String,
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

    pub fn handle(&mut self, command: RuntimeCommand) -> Result<RuntimeResponse> {
        match command {
            RuntimeCommand::GetSessionState => {
                Ok(RuntimeResponse::SessionState(self.session_state()))
            }
            RuntimeCommand::ListRecentVaults => self
                .list_recent_vaults()
                .map(RuntimeResponse::VaultReferenceList),
            RuntimeCommand::PreloadCurrentVault => self
                .preload_current_vault_snapshot()
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::AddLocalVaultReference { path } => {
                let selected = match path {
                    Some(path) => path,
                    None => self
                        .local_files
                        .pick()?
                        .context("local vault selection canceled")?,
                };

                self.add_local_vault_reference(&selected)
                    .map(RuntimeResponse::VaultReference)
            }
            RuntimeCommand::BeginOneDriveLogin => self
                .one_drive
                .begin_login()
                .map(RuntimeResponse::OneDriveAuthSession),
            RuntimeCommand::CompleteOneDriveLogin {
                code,
                redirect_uri,
                code_verifier,
            } => self
                .one_drive
                .complete_login(&code, &redirect_uri, &code_verifier)
                .map(RuntimeResponse::OneDriveAuthStatus),
            RuntimeCommand::CompletePendingOneDriveLogin => self
                .one_drive
                .complete_pending_login()
                .map(RuntimeResponse::OneDriveAuthStatus),
            RuntimeCommand::ListOneDriveChildren { parent_item_id } => self
                .one_drive
                .list_children(parent_item_id.as_deref())
                .map(RuntimeResponse::OneDriveItemList),
            RuntimeCommand::AddOneDriveVaultReference { drive_id, item_id } => self
                .add_onedrive_vault_reference(&drive_id, &item_id)
                .map(RuntimeResponse::VaultReference),
            RuntimeCommand::SetCurrentVault { vault_ref_id } => self
                .set_current_vault(&vault_ref_id)
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::RetryVaultSourceSync { vault_id } => self
                .retry_vault_source_sync(&vault_id)
                .map(RuntimeResponse::VaultSourceStatus),
            RuntimeCommand::DeleteVaultReference { vault_ref_id } => self
                .delete_vault_reference(&vault_ref_id)
                .map(RuntimeResponse::VaultReferenceList),
            RuntimeCommand::UnlockCurrentVaultWithPassword { password } => self
                .unlock_current_vault_with_password(&password)
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::UnlockCurrentVault {
                password,
                key_file_path,
            } => self
                .unlock_current_vault(password.as_deref(), key_file_path.as_deref())
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::EnableQuickUnlockForCurrentVault {
                password,
                key_file_path,
            } => self
                .enable_quick_unlock_for_current_vault(
                    password.as_deref(),
                    key_file_path.as_deref(),
                )
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::UnlockCurrentVaultWithQuickUnlock => self
                .unlock_current_vault_with_quick_unlock()
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::DisableQuickUnlockForCurrentVault => self
                .disable_quick_unlock_for_current_vault()
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::OpenLocalVault { path } => self
                .open_local_vault(&path)
                .map(RuntimeResponse::VaultOpened),
            RuntimeCommand::LockSession => {
                self.lock_session();
                Ok(RuntimeResponse::SessionState(self.session_state()))
            }
            RuntimeCommand::UnlockWithPassword { vault_id, password } => self
                .unlock_with_password(&vault_id, &password)
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::UnlockVault {
                vault_id,
                password,
                key_file_path,
            } => self
                .unlock_vault(&vault_id, password.as_deref(), key_file_path.as_deref())
                .map(|_| RuntimeResponse::SessionState(self.session_state())),
            RuntimeCommand::CreateEntry {
                vault_id,
                parent_group_id,
                title,
                username,
                password,
                url,
                notes,
                totp_uri,
            } => self
                .create_entry(
                    &vault_id,
                    &parent_group_id,
                    title,
                    username,
                    password,
                    url,
                    notes,
                    totp_uri,
                )
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::UpdateEntryFields {
                vault_id,
                entry_id,
                title,
                username,
                password,
                url,
                notes,
                totp_uri,
                custom_fields,
            } => self
                .update_entry_fields(
                    &vault_id,
                    &entry_id,
                    title,
                    username,
                    password,
                    url,
                    notes,
                    totp_uri,
                    custom_fields,
                )
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::CompareAndUpdateEntryFields {
                vault_id,
                entry_id,
                expected_fields,
                desired_fields,
            } => Ok(
                match self.compare_and_update_entry_fields(
                    &vault_id,
                    &entry_id,
                    expected_fields,
                    desired_fields,
                )? {
                    Some(detail) => RuntimeResponse::EntryDetail(detail),
                    None => RuntimeResponse::Error(ErrorDto {
                        code: "conflict".into(),
                        message: "entry fields changed after planning".into(),
                    }),
                },
            ),
            RuntimeCommand::PersistAutofillMutation {
                transaction_id,
                operation_id,
                vault_id,
                plan,
            } => self.persist_autofill_mutation(transaction_id, operation_id, vault_id, plan),
            RuntimeCommand::ClearEntryTotp { vault_id, entry_id } => self
                .clear_entry_totp(&vault_id, &entry_id)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::SetEntryPasskey {
                vault_id,
                entry_id,
                passkey,
            } => self
                .set_entry_passkey(&vault_id, &entry_id, passkey)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::ClearEntryPasskey { vault_id, entry_id } => self
                .clear_entry_passkey(&vault_id, &entry_id)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::GetPasskeyUserVerificationCapability => {
                Ok(RuntimeResponse::PasskeyUserVerificationCapability(
                    self.passkey_user_verification_capability(),
                ))
            }
            RuntimeCommand::VerifyPasskeyUser {
                ceremony_token,
                expected_phase,
                vault_id,
                method,
                password,
            } => self
                .verify_passkey_user(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    method,
                    password.as_deref(),
                )
                .map(RuntimeResponse::PasskeyUserVerified),
            RuntimeCommand::DeleteEntry { vault_id, entry_id } => self
                .delete_entry(&vault_id, &entry_id)
                .map(|_| RuntimeResponse::Saved),
            RuntimeCommand::GetEntryAttachmentContent {
                vault_id,
                entry_id,
                name,
            } => self
                .get_entry_attachment_content(&vault_id, &entry_id, &name)
                .map(RuntimeResponse::EntryAttachmentContent),
            RuntimeCommand::AddEntryAttachment {
                vault_id,
                entry_id,
                name,
                data_base64,
                protect_in_memory,
            } => self
                .add_entry_attachment(&vault_id, &entry_id, name, data_base64, protect_in_memory)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::UpdateEntryAttachmentMetadata {
                vault_id,
                entry_id,
                old_name,
                new_name,
                protect_in_memory,
            } => self
                .update_entry_attachment_metadata(
                    &vault_id,
                    &entry_id,
                    &old_name,
                    new_name,
                    protect_in_memory,
                )
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::ReplaceEntryAttachmentContent {
                vault_id,
                entry_id,
                name,
                data_base64,
            } => self
                .replace_entry_attachment_content(&vault_id, &entry_id, &name, data_base64)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::DeleteEntryAttachment {
                vault_id,
                entry_id,
                name,
            } => self
                .delete_entry_attachment(&vault_id, &entry_id, &name)
                .map(RuntimeResponse::EntryDetail),
            RuntimeCommand::SaveVault { vault_id } => self.save_vault_command(&vault_id),
            RuntimeCommand::GetDatabaseSettings { vault_id } => {
                Ok(match self.get_database_settings(&vault_id) {
                    Ok(settings) => RuntimeResponse::DatabaseSettings(settings),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::UpdateDatabaseSettings { vault_id, update } => {
                Ok(match self.update_database_settings(&vault_id, update) {
                    Ok(settings) => RuntimeResponse::DatabaseSettings(settings),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::ListGroups { vault_id } => Ok(match self.list_groups(&vault_id) {
                Ok(groups) => RuntimeResponse::GroupTree(groups),
                Err(error) => query_error_response(error),
            }),
            RuntimeCommand::ListEntries { vault_id } => Ok(match self.list_entries(&vault_id) {
                Ok(entries) => RuntimeResponse::EntryList(EntryListDto { entries }),
                Err(error) => query_error_response(error),
            }),
            RuntimeCommand::GetEntryDetail { vault_id, entry_id } => {
                Ok(match self.get_entry_detail(&vault_id, &entry_id) {
                    Ok(detail) => RuntimeResponse::EntryDetail(detail),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::ListEntryHistory { vault_id, entry_id } => {
                Ok(match self.list_entry_history(&vault_id, &entry_id) {
                    Ok(history) => RuntimeResponse::EntryHistoryList(history),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::GetEntryHistoryDetail {
                vault_id,
                entry_id,
                history_index,
            } => Ok(
                match self.get_entry_history_detail(&vault_id, &entry_id, history_index) {
                    Ok(detail) => RuntimeResponse::EntryHistoryDetail(detail),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::FindFillCandidates { vault_id, url } => {
                Ok(match self.find_fill_candidates(&vault_id, &url) {
                    Ok(candidates) => RuntimeResponse::FillCandidates(candidates),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::FindExactMatchingEntryIds { vault_id, fields } => {
                Ok(match self.exact_matching_entry_ids(&vault_id, &fields) {
                    Ok(entry_ids) => RuntimeResponse::EntryIdList(EntryIdListDto { entry_ids }),
                    Err(error) => query_error_response(error),
                })
            }
            RuntimeCommand::ListPasskeyCredentials {
                ceremony_token,
                expected_phase,
                vault_id,
                relying_party,
            } => Ok(
                match self.list_passkey_credentials(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &relying_party,
                ) {
                    Ok(credentials) => RuntimeResponse::PasskeyCredentialList(credentials),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::RegisterPasskeyCeremony {
                ceremony_token,
                connection_id,
                origin,
                top_origin,
                ancestor_origins,
                relying_party,
                ceremony,
                discoverable,
                user_verification,
                challenge_base64url,
                request_id,
                tab_id,
                frame_id,
                frame_kind,
                registered_at_epoch_ms,
                expires_at_epoch_ms,
            } => self
                .register_passkey_ceremony(
                    &ceremony_token,
                    PasskeyCeremonyIdentity {
                        connection_id,
                        origin,
                        top_origin,
                        ancestor_origins,
                        relying_party,
                        ceremony,
                        discoverable,
                        user_verification,
                        challenge_base64url,
                        request_id,
                        tab_id,
                        frame_id,
                        frame_kind,
                        registered_at_epoch_ms,
                        expires_at_epoch_ms,
                    },
                )
                .map(RuntimeResponse::PasskeyCeremonyRegistered),
            RuntimeCommand::AdvancePasskeyCeremonyPhase {
                ceremony_token,
                expected_phase,
                next_phase,
                related_origin_verified,
            } => self
                .advance_passkey_ceremony_phase(
                    &ceremony_token,
                    expected_phase,
                    next_phase,
                    related_origin_verified,
                )
                .map(RuntimeResponse::PasskeyCeremonyAdvanced),
            RuntimeCommand::BindPasskeyCeremonyVault {
                ceremony_token,
                expected_phase,
                vault_id,
            } => self
                .bind_passkey_ceremony_vault(&ceremony_token, expected_phase, &vault_id)
                .map(RuntimeResponse::PasskeyCeremonyVaultBound),
            RuntimeCommand::QueryPasskeyCeremonyLedger { ceremony_token } => {
                Ok(RuntimeResponse::PasskeyCeremonyLedger(
                    self.query_passkey_ceremony_ledger(&ceremony_token),
                ))
            }
            RuntimeCommand::ReconcilePasskeyCeremonyLedger {
                active_connection_id,
            } => self
                .reconcile_passkey_ceremony_ledger(&active_connection_id)
                .map(RuntimeResponse::PasskeyCeremonyReconciliation),
            RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
                ceremony_token,
                expected_phase,
            } => Ok(
                match self.mark_passkey_ceremony_unknown_delivery(&ceremony_token, expected_phase) {
                    Ok(response) => RuntimeResponse::PasskeyCeremonyAdvanced(response),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::CreatePasskeyAssertion {
                ceremony_token,
                expected_phase,
                vault_id,
                relying_party,
                origin,
                credential_id,
                discoverable,
                user_presence_verified,
                related_origin_verified,
                client_data_json_base64url,
            } => Ok(
                match self.create_passkey_assertion(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &relying_party,
                    &origin,
                    credential_id.as_deref(),
                    discoverable,
                    user_presence_verified,
                    related_origin_verified,
                    &client_data_json_base64url,
                ) {
                    Ok(assertion) => RuntimeResponse::PasskeyAssertion(assertion),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::CreatePasskeyRegistration {
                ceremony_token,
                expected_phase,
                vault_id,
                relying_party,
                origin,
                user_name,
                user_display_name,
                user_handle_base64url,
                public_key_algorithm,
                related_origin_verified,
                client_data_json_base64url,
            } => Ok(
                match self.create_passkey_registration(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &relying_party,
                    &origin,
                    &user_name,
                    user_display_name.as_deref(),
                    &user_handle_base64url,
                    public_key_algorithm,
                    related_origin_verified,
                    &client_data_json_base64url,
                ) {
                    Ok(registration) => RuntimeResponse::PasskeyRegistration(registration),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::SavePasskeyRegistration {
                ceremony_token,
                expected_phase,
                vault_id,
            } => Ok(
                match self.save_passkey_registration(&ceremony_token, expected_phase, &vault_id) {
                    Ok(response) => response,
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::AbortPasskeyRegistration {
                ceremony_token,
                expected_phase,
                closed_phase,
            } => Ok(
                match self.abort_passkey_registration(&ceremony_token, expected_phase, closed_phase)
                {
                    Ok(()) => RuntimeResponse::Saved,
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::CommitPasskeyRegistration {
                ceremony_token,
                expected_phase,
                vault_id,
                entry_id,
                credential_id,
            } => Ok(
                match self.commit_passkey_registration(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &entry_id,
                    &credential_id,
                ) {
                    Ok(()) => RuntimeResponse::Saved,
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::PasskeyCredentialStatus {
                ceremony_token,
                expected_phase,
                vault_id,
                credential_id,
                relying_party,
            } => Ok(
                match self.passkey_credential_status(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &credential_id,
                    &relying_party,
                ) {
                    Ok(status) => RuntimeResponse::PasskeyCredentialStatus(status),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::PasskeyCredentialStatusBatch {
                ceremony_token,
                expected_phase,
                vault_id,
                credential_ids,
                relying_party,
            } => Ok(
                match self.passkey_credential_status_batch(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    &credential_ids,
                    &relying_party,
                ) {
                    Ok(status) => RuntimeResponse::PasskeyCredentialStatusBatch(status),
                    Err(error) => query_error_response(error),
                },
            ),
            RuntimeCommand::UpdateEntry { .. } => Ok(RuntimeResponse::Error(ErrorDto {
                code: "unsupported".into(),
                message: "command is not implemented yet".into(),
            })),
        }
    }

    fn persist_autofill_mutation(
        &mut self,
        transaction_id: String,
        operation_id: String,
        vault_id: String,
        plan: AutofillPersistPlanDto,
    ) -> Result<RuntimeResponse> {
        let active_vault_id = self.vault_session.active_vault_id();
        if active_vault_id != Some(vault_id.as_str()) {
            if active_vault_id.is_none()
                && self
                    .vault_session
                    .find_loaded(&vault_id)
                    .is_some_and(|loaded| loaded.vault.is_none())
            {
                return Ok(autofill_persist_error(
                    "vault_locked",
                    "the requested vault is locked",
                ));
            }
            return Ok(autofill_persist_conflict(
                &transaction_id,
                &operation_id,
                &vault_id,
                AutofillPersistConflictCodeDto::ActiveVaultMismatch,
            ));
        }

        let (
            source,
            baseline_fingerprint,
            base_loaded,
            key,
            save_profile,
            display_name,
            account_label,
        ) = {
            let loaded = self
                .vault_session
                .find_loaded(&vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let Some(vault) = loaded.vault.as_ref() else {
                return Ok(autofill_persist_error(
                    "vault_locked",
                    "the requested vault is locked",
                ));
            };
            (
                loaded.source.clone(),
                loaded.baseline_fingerprint.clone(),
                vault.clone(),
                transformed_key_from_loaded_vault(loaded)?,
                loaded.save_profile.clone(),
                loaded.name.clone(),
                loaded
                    .source_account_label
                    .clone()
                    .unwrap_or_else(|| "OneDrive".into()),
            )
        };
        let pending_chain = match &source {
            VaultSource::OneDriveItem { drive_id, item_id } => {
                let cache_key =
                    RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id));
                Some(self.remote_cache.read_pending_chain(&cache_key))
            }
            VaultSource::LocalPath(_) => None,
        };
        let loaded_pending_autofill = pending_chain.as_ref().is_some_and(|result| {
            result.as_ref().is_ok_and(|chain| {
                same_content_fingerprint(&baseline_fingerprint, &chain.pending.fingerprint)
            })
        });
        let baseline_bytes = self
            .synced_bases
            .read(&vault_id)
            .with_context(|| format!("failed to read synced base: {vault_id}"))?
            .with_context(|| format!("synced base is missing: {vault_id}"))?;
        let baseline_bytes_fingerprint = fingerprint_for_cached_bytes(&baseline_bytes, 0);
        let source_identity_sha256 = autofill_source_identity_sha256(&source);
        if let Err(error) = plan_sha256(&transaction_id, &vault_id, &source_identity_sha256, &plan)
        {
            return Ok(autofill_engine_error_response(
                &transaction_id,
                &operation_id,
                &vault_id,
                error,
            ));
        }
        let baseline_source = if loaded_pending_autofill {
            base_loaded.clone()
        } else {
            match Self::load_session_database(&baseline_bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    match self
                        .unlock_historical_snapshot_from_unlock_blob(&vault_id, &baseline_bytes)
                    {
                        Ok(Some((vault, _))) => vault,
                        Ok(None) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                "the loaded vault baseline uses a historical KDF and quick unlock is unavailable",
                            ));
                        }
                        Err(error) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                format!(
                                    "failed to unlock the historical vault baseline: {error:#}"
                                ),
                            ));
                        }
                    }
                }
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "source_corrupt",
                        format!("failed to parse the loaded vault baseline: {error}"),
                    ));
                }
            }
        };
        let baseline_save_profile = match self.inspected_save_profile(&baseline_bytes) {
            Ok(profile) => profile,
            Err(error) => {
                return Ok(autofill_persist_error(
                    "source_corrupt",
                    format!("failed to inspect the loaded vault baseline: {error:#}"),
                ));
            }
        };
        let base_loaded = {
            let mut normalized = base_loaded;
            let bytes = match save_kdbx_with_history_limits_transformed(
                &mut normalized,
                &key,
                save_profile.clone(),
            ) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to normalize the loaded vault snapshot: {error}"),
                    ));
                }
            };
            match Self::load_session_database(&bytes, &key) {
                Ok(database) => database.vault,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to verify the loaded vault snapshot: {error}"),
                    ));
                }
            }
        };

        match source {
            VaultSource::LocalPath(path) => self.persist_local_autofill_mutation(
                &transaction_id,
                &operation_id,
                &vault_id,
                &path,
                &source_identity_sha256,
                &plan,
                &base_loaded,
                &baseline_source,
                &baseline_fingerprint,
                key,
                &baseline_save_profile,
                save_profile,
            ),
            VaultSource::OneDriveItem { drive_id, item_id } => self
                .persist_or_replay_pending_onedrive_autofill_mutation(
                    &transaction_id,
                    &operation_id,
                    &vault_id,
                    &drive_id,
                    &item_id,
                    pending_chain.expect("OneDrive source has a pending-cache read"),
                    &source_identity_sha256,
                    &plan,
                    &base_loaded,
                    &baseline_source,
                    &baseline_fingerprint,
                    &baseline_bytes_fingerprint,
                    key,
                    &baseline_save_profile,
                    save_profile,
                    &display_name,
                    &account_label,
                ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_or_replay_pending_onedrive_autofill_mutation(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        pending_chain: std::result::Result<PendingRemoteCacheChain, PendingRemoteCacheChainError>,
        source_identity_sha256: &str,
        plan: &AutofillPersistPlanDto,
        base_loaded: &Vault,
        baseline_source: &Vault,
        baseline_fingerprint: &VaultSourceFingerprint,
        baseline_bytes_fingerprint: &VaultSourceFingerprint,
        mut key: Arc<TransformedKey>,
        baseline_save_profile: &SaveProfile,
        save_profile: SaveProfile,
        display_name: &str,
        account_label: &str,
    ) -> Result<RuntimeResponse> {
        let cache_key = RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id));
        let chain = match pending_chain {
            Ok(chain) => chain,
            Err(
                PendingRemoteCacheChainError::Missing | PendingRemoteCacheChainError::NotPending,
            ) => {
                return self.persist_onedrive_autofill_mutation(
                    transaction_id,
                    operation_id,
                    vault_id,
                    drive_id,
                    item_id,
                    source_identity_sha256,
                    plan,
                    base_loaded,
                    baseline_source,
                    baseline_fingerprint,
                    key,
                    baseline_save_profile,
                    save_profile,
                    display_name,
                    account_label,
                );
            }
            Err(error) => {
                return Ok(autofill_persist_error(
                    "persist_io_unavailable",
                    format!(
                        "remote cache must be synchronized before autofill persistence: {error}"
                    ),
                ));
            }
        };
        if chain.operation_id != operation_id {
            return Ok(autofill_persist_error(
                "persist_io_unavailable",
                "another autofill operation is awaiting remote synchronization",
            ));
        }
        let pending_vault = match Self::load_session_database(&chain.pending.bytes, &key) {
            Ok(database) => database.vault,
            Err(KdbxError::HeaderHmacMismatch) => {
                match self.refresh_transformed_key_from_unlock_blob(vault_id, &chain.pending.bytes)
                {
                    Ok(Some((vault, refreshed_key))) => {
                        key = refreshed_key;
                        vault
                    }
                    Ok(None) => {
                        return Ok(autofill_persist_error(
                            "credential_required",
                            "the pending remote autofill generation requires fresh master credentials",
                        ));
                    }
                    Err(error) => {
                        return Ok(autofill_persist_error(
                            "credential_required",
                            format!(
                                "failed to refresh quick unlock for the pending autofill generation: {error:#}"
                            ),
                        ));
                    }
                }
            }
            Err(error) => {
                return Ok(autofill_persist_error(
                    "source_corrupt",
                    format!("failed to parse pending remote autofill generation: {error}"),
                ));
            }
        };
        let pending_save_profile = match self.inspected_save_profile(&chain.pending.bytes) {
            Ok(profile) => profile,
            Err(error) => {
                return Ok(autofill_persist_error(
                    "source_corrupt",
                    format!("failed to inspect pending remote autofill generation: {error:#}"),
                ));
            }
        };
        let loaded_pending =
            same_content_fingerprint(baseline_fingerprint, &chain.pending.fingerprint);
        let plan_baseline_vault = if loaded_pending {
            None
        } else {
            if !same_content_fingerprint(baseline_fingerprint, &chain.plan_baseline.fingerprint)
                || !same_content_fingerprint(
                    baseline_bytes_fingerprint,
                    &chain.plan_baseline.fingerprint,
                )
            {
                return Ok(autofill_persist_error(
                    "source_corrupt",
                    "loaded generation matches neither the pending candidate nor its plan baseline",
                ));
            }
            Some(baseline_source.clone())
        };
        let (engine_baseline, engine_local) = match plan_baseline_vault.as_ref() {
            Some(plan_baseline) => (plan_baseline, base_loaded),
            None => (&pending_vault, &pending_vault),
        };
        let prepared = match prepare_autofill_persist(AutofillPersistEngineInput {
            baseline_source: engine_baseline,
            base_loaded: engine_local,
            current_source: &pending_vault,
            transaction_id,
            operation_id,
            vault_id,
            source_identity_sha256,
            plan,
            now_epoch_ms: self.current_unix_time_ms(),
        }) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Ok(autofill_engine_error_response(
                    transaction_id,
                    operation_id,
                    vault_id,
                    error,
                ));
            }
        };
        let entry_id = match &prepared.outcome {
            AutofillPersistLogicalOutcome::Replayed { entry_id }
            | AutofillPersistLogicalOutcome::ReplayedNeedsPublish { entry_id } => entry_id.clone(),
            AutofillPersistLogicalOutcome::NeedsPublish { .. } => {
                return Ok(autofill_persist_error(
                    "source_corrupt",
                    "pending remote autofill receipt did not replay exactly",
                ));
            }
        };
        let adopted_save_profile = if loaded_pending {
            None
        } else {
            match Self::merge_save_profile(
                baseline_save_profile,
                &save_profile,
                &pending_save_profile,
            ) {
                Ok(profile) => Some(profile),
                Err(_) => {
                    return Ok(autofill_persist_conflict(
                        transaction_id,
                        operation_id,
                        vault_id,
                        AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
                    ));
                }
            }
        };
        if !loaded_pending {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            loaded.vault = Some(prepared.candidate);
            loaded.bytes = Vec::new();
            loaded.baseline_fingerprint = chain.pending.fingerprint.clone();
            loaded.save_profile = adopted_save_profile.expect("stale runtime profile was merged");
            loaded.source_status = Some(VaultSourceStatusDto {
                source_kind: cache_key.provider_kind.clone(),
                remote_state: "pending_sync".into(),
                last_sync_at: None,
                cached_at: Some(chain.pending.cached_at),
                last_error: None,
            });
        }
        self.replace_session_transformed_key(vault_id, key)?;
        Ok(autofill_persist_durable(
            transaction_id,
            operation_id,
            vault_id,
            &entry_id,
            AutofillPersistDispositionDto::Replayed,
            AutofillPersistDurabilityDto::PendingRemoteCache,
            AutofillCacheStateDto::PendingSync,
            &chain.pending.fingerprint,
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_local_autofill_mutation(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
        vault_id: &str,
        path: &str,
        source_identity_sha256: &str,
        plan: &AutofillPersistPlanDto,
        base_loaded: &Vault,
        baseline_source: &Vault,
        baseline_fingerprint: &VaultSourceFingerprint,
        mut key: Arc<TransformedKey>,
        baseline_save_profile: &SaveProfile,
        save_profile: SaveProfile,
    ) -> Result<RuntimeResponse> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let (transaction, snapshot) = match self.local_files.begin_write(path) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to read the current vault generation: {error}"),
                    ));
                }
            };
            let current_source = match Self::load_session_database(&snapshot.bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    match self.refresh_transformed_key_from_unlock_blob(vault_id, &snapshot.bytes) {
                        Ok(Some((vault, refreshed_key))) => {
                            key = refreshed_key;
                            vault
                        }
                        Ok(None) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                "the current vault generation requires fresh master credentials",
                            ));
                        }
                        Err(error) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                format!("failed to refresh quick unlock: {error:#}"),
                            ));
                        }
                    }
                }
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "source_corrupt",
                        format!("failed to parse the current vault generation: {error}"),
                    ));
                }
            };
            let current_save_profile = match self.inspected_save_profile(&snapshot.bytes) {
                Ok(profile) => profile,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "source_corrupt",
                        format!("failed to inspect the current vault generation: {error:#}"),
                    ));
                }
            };
            let merged_save_profile = match Self::merge_save_profile(
                baseline_save_profile,
                &save_profile,
                &current_save_profile,
            ) {
                Ok(profile) => profile,
                Err(_) => {
                    return Ok(autofill_persist_conflict(
                        transaction_id,
                        operation_id,
                        vault_id,
                        AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
                    ));
                }
            };
            let prepared = match prepare_autofill_persist(AutofillPersistEngineInput {
                baseline_source,
                base_loaded,
                current_source: &current_source,
                transaction_id,
                operation_id,
                vault_id,
                source_identity_sha256,
                plan,
                now_epoch_ms: self.current_unix_time_ms(),
            }) {
                Ok(prepared) => prepared,
                Err(error) => {
                    return Ok(autofill_engine_error_response(
                        transaction_id,
                        operation_id,
                        vault_id,
                        error,
                    ));
                }
            };

            if let AutofillPersistLogicalOutcome::Replayed { entry_id } = &prepared.outcome
                && merged_save_profile == current_save_profile
            {
                debug_assert_eq!(prepared.candidate, current_source);
                self.install_committed_autofill_generation(
                    vault_id,
                    prepared.candidate,
                    snapshot.bytes,
                    snapshot.fingerprint.clone(),
                    None,
                )?;
                self.replace_session_transformed_key(vault_id, key.clone())?;
                return Ok(autofill_persist_durable(
                    transaction_id,
                    operation_id,
                    vault_id,
                    entry_id,
                    AutofillPersistDispositionDto::Replayed,
                    AutofillPersistDurabilityDto::Source,
                    AutofillCacheStateDto::NotApplicable,
                    &snapshot.fingerprint,
                    merge_summary_for_source_change(baseline_fingerprint, &snapshot.fingerprint),
                ));
            }

            let (entry_id, disposition) = match &prepared.outcome {
                AutofillPersistLogicalOutcome::NeedsPublish { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Committed)
                }
                AutofillPersistLogicalOutcome::ReplayedNeedsPublish { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Replayed)
                }
                AutofillPersistLogicalOutcome::Replayed { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Replayed)
                }
            };
            let (bytes, verified_vault) = match self.serialize_and_verify_autofill_candidate(
                prepared,
                transaction_id,
                operation_id,
                vault_id,
                source_identity_sha256,
                plan,
                &key,
                merged_save_profile,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to verify the candidate vault generation: {error}"),
                    ));
                }
            };

            match transaction.commit(&snapshot.fingerprint, &bytes) {
                Ok(commit) => {
                    self.install_committed_autofill_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        commit.fingerprint.clone(),
                        None,
                    )?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(autofill_persist_durable(
                        transaction_id,
                        operation_id,
                        vault_id,
                        &entry_id,
                        disposition,
                        AutofillPersistDurabilityDto::Source,
                        AutofillCacheStateDto::NotApplicable,
                        &commit.fingerprint,
                        merge_summary_for_source_change(
                            baseline_fingerprint,
                            &snapshot.fingerprint,
                        ),
                    ));
                }
                Err(LocalFileCommitError::Conflict { .. }) if attempt + 1 < MAX_SOURCE_ATTEMPTS => {
                    continue;
                }
                Err(LocalFileCommitError::Conflict { .. }) => {
                    return Ok(autofill_persist_conflict(
                        transaction_id,
                        operation_id,
                        vault_id,
                        AutofillPersistConflictCodeDto::SourceChangedRetryExhausted,
                    ));
                }
                Err(LocalFileCommitError::BeforePublish { source }) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to publish the vault generation: {source}"),
                    ));
                }
                Err(LocalFileCommitError::OutcomeUnknown { source }) => {
                    return Ok(autofill_persist_error(
                        "persist_outcome_unknown",
                        format!("the vault publish outcome is unknown: {source}"),
                    ));
                }
            }
        }
        unreachable!("bounded autofill source attempts must return")
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_onedrive_autofill_mutation(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        source_identity_sha256: &str,
        plan: &AutofillPersistPlanDto,
        base_loaded: &Vault,
        baseline_source: &Vault,
        baseline_fingerprint: &VaultSourceFingerprint,
        mut key: Arc<TransformedKey>,
        baseline_save_profile: &SaveProfile,
        save_profile: SaveProfile,
        display_name: &str,
        account_label: &str,
    ) -> Result<RuntimeResponse> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;
        let cache_key = RemoteCacheKey::new("onedrive", &onedrive_remote_id(drive_id, item_id));

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = match self.one_drive.remote_state(drive_id, item_id) {
                Ok(state) => state,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to read current OneDrive state: {error:#}"),
                    ));
                }
            };
            let snapshot = match self
                .one_drive
                .read_snapshot_from_state(drive_id, item_id, &state)
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to read current OneDrive generation: {error:#}"),
                    ));
                }
            };
            let current_source = match Self::load_session_database(&snapshot.bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    match self.refresh_transformed_key_from_unlock_blob(vault_id, &snapshot.bytes) {
                        Ok(Some((vault, refreshed_key))) => {
                            key = refreshed_key;
                            vault
                        }
                        Ok(None) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                "the current OneDrive generation requires fresh master credentials",
                            ));
                        }
                        Err(error) => {
                            return Ok(autofill_persist_error(
                                "credential_required",
                                format!("failed to refresh quick unlock: {error:#}"),
                            ));
                        }
                    }
                }
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "source_corrupt",
                        format!("failed to parse the current OneDrive generation: {error}"),
                    ));
                }
            };
            let current_save_profile = match self.inspected_save_profile(&snapshot.bytes) {
                Ok(profile) => profile,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "source_corrupt",
                        format!("failed to inspect the current OneDrive generation: {error:#}"),
                    ));
                }
            };
            let merged_save_profile = match Self::merge_save_profile(
                baseline_save_profile,
                &save_profile,
                &current_save_profile,
            ) {
                Ok(profile) => profile,
                Err(_) => {
                    return Ok(autofill_persist_conflict(
                        transaction_id,
                        operation_id,
                        vault_id,
                        AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
                    ));
                }
            };
            let prepared = match prepare_autofill_persist(AutofillPersistEngineInput {
                baseline_source,
                base_loaded,
                current_source: &current_source,
                transaction_id,
                operation_id,
                vault_id,
                source_identity_sha256,
                plan,
                now_epoch_ms: self.current_unix_time_ms(),
            }) {
                Ok(prepared) => prepared,
                Err(error) => {
                    return Ok(autofill_engine_error_response(
                        transaction_id,
                        operation_id,
                        vault_id,
                        error,
                    ));
                }
            };

            if let AutofillPersistLogicalOutcome::Replayed { entry_id } = &prepared.outcome
                && merged_save_profile == current_save_profile
            {
                debug_assert_eq!(prepared.candidate, current_source);
                let cached_at = self.current_unix_time() as i64;
                let cache_result = self.remote_cache.write_with_source_etag(
                    &cache_key,
                    RemoteVaultCacheEntry {
                        bytes: snapshot.bytes.clone(),
                        fingerprint: snapshot.fingerprint.clone(),
                        display_name: display_name.into(),
                        account_label: account_label.into(),
                        cached_at,
                        pending_sync: false,
                    },
                    state.e_tag.as_deref(),
                );
                let (cache_state, status) = remote_source_status_after_commit(
                    &cache_key,
                    cached_at,
                    cache_result.as_ref().err(),
                );
                self.install_committed_autofill_generation(
                    vault_id,
                    prepared.candidate,
                    snapshot.bytes,
                    snapshot.fingerprint.clone(),
                    Some(status),
                )?;
                self.replace_session_transformed_key(vault_id, key.clone())?;
                return Ok(autofill_persist_durable(
                    transaction_id,
                    operation_id,
                    vault_id,
                    entry_id,
                    AutofillPersistDispositionDto::Replayed,
                    AutofillPersistDurabilityDto::Source,
                    cache_state,
                    &snapshot.fingerprint,
                    merge_summary_for_source_change(baseline_fingerprint, &snapshot.fingerprint),
                ));
            }

            let (entry_id, disposition) = match &prepared.outcome {
                AutofillPersistLogicalOutcome::NeedsPublish { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Committed)
                }
                AutofillPersistLogicalOutcome::ReplayedNeedsPublish { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Replayed)
                }
                AutofillPersistLogicalOutcome::Replayed { entry_id } => {
                    (entry_id.clone(), AutofillPersistDispositionDto::Replayed)
                }
            };
            let (bytes, verified_vault) = match self.serialize_and_verify_autofill_candidate(
                prepared,
                transaction_id,
                operation_id,
                vault_id,
                source_identity_sha256,
                plan,
                &key,
                merged_save_profile,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("failed to verify the OneDrive candidate: {error:#}"),
                    ));
                }
            };

            match self
                .one_drive
                .conditional_write(drive_id, item_id, &bytes, &state)
            {
                Ok(OneDriveConditionalWriteOutcome::Committed { fingerprint, e_tag }) => {
                    let cached_at = self.current_unix_time() as i64;
                    let cache_result = self.remote_cache.write_with_source_etag(
                        &cache_key,
                        RemoteVaultCacheEntry {
                            bytes: bytes.clone(),
                            fingerprint: fingerprint.clone(),
                            display_name: display_name.into(),
                            account_label: account_label.into(),
                            cached_at,
                            pending_sync: false,
                        },
                        e_tag.as_deref(),
                    );
                    let (cache_state, status) = remote_source_status_after_commit(
                        &cache_key,
                        cached_at,
                        cache_result.as_ref().err(),
                    );
                    self.install_committed_autofill_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        fingerprint.clone(),
                        Some(status),
                    )?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(autofill_persist_durable(
                        transaction_id,
                        operation_id,
                        vault_id,
                        &entry_id,
                        disposition,
                        AutofillPersistDurabilityDto::Source,
                        cache_state,
                        &fingerprint,
                        merge_summary_for_source_change(
                            baseline_fingerprint,
                            &snapshot.fingerprint,
                        ),
                    ));
                }
                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed)
                    if attempt + 1 < MAX_SOURCE_ATTEMPTS =>
                {
                    continue;
                }
                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed) => {
                    return Ok(autofill_persist_conflict(
                        transaction_id,
                        operation_id,
                        vault_id,
                        AutofillPersistConflictCodeDto::SourceChangedRetryExhausted,
                    ));
                }
                Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown { message }) => {
                    let cached_at = self.current_unix_time() as i64;
                    let pending_fingerprint = fingerprint_for_cached_bytes(&bytes, cached_at);
                    if let Err(cache_error) = self.remote_cache.write_pending_autofill(
                        &cache_key,
                        RemoteVaultCacheEntry {
                            bytes: bytes.clone(),
                            fingerprint: pending_fingerprint.clone(),
                            display_name: display_name.into(),
                            account_label: account_label.into(),
                            cached_at,
                            pending_sync: true,
                        },
                        RemoteVaultCacheEntry {
                            bytes: snapshot.bytes.clone(),
                            fingerprint: snapshot.fingerprint.clone(),
                            display_name: display_name.into(),
                            account_label: account_label.into(),
                            cached_at,
                            pending_sync: false,
                        },
                        baseline_fingerprint,
                        state.e_tag.as_deref(),
                        state.memory_revision(),
                        operation_id,
                    ) {
                        return Ok(autofill_persist_error(
                            "persist_outcome_unknown",
                            format!(
                                "OneDrive write outcome is unknown ({message}); pending cache also failed: {cache_error:#}"
                            ),
                        ));
                    }
                    let status = VaultSourceStatusDto {
                        source_kind: cache_key.provider_kind.clone(),
                        remote_state: "pending_sync".into(),
                        last_sync_at: None,
                        cached_at: Some(cached_at),
                        last_error: Some(message),
                    };
                    self.install_committed_autofill_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        pending_fingerprint.clone(),
                        Some(status),
                    )?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(autofill_persist_durable(
                        transaction_id,
                        operation_id,
                        vault_id,
                        &entry_id,
                        disposition,
                        AutofillPersistDurabilityDto::PendingRemoteCache,
                        AutofillCacheStateDto::PendingSync,
                        &pending_fingerprint,
                        merge_summary_for_source_change(
                            baseline_fingerprint,
                            &snapshot.fingerprint,
                        ),
                    ));
                }
                Err(error) => {
                    return Ok(autofill_persist_error(
                        "persist_io_unavailable",
                        format!("conditional OneDrive write failed: {error}"),
                    ));
                }
            }
        }
        unreachable!("bounded OneDrive source attempts must return")
    }

    #[allow(clippy::too_many_arguments)]
    fn serialize_and_verify_autofill_candidate(
        &self,
        prepared: PreparedAutofillPersist,
        transaction_id: &str,
        operation_id: &str,
        vault_id: &str,
        source_identity_sha256: &str,
        plan: &AutofillPersistPlanDto,
        key: &TransformedKey,
        save_profile: SaveProfile,
    ) -> Result<(Vec<u8>, Vault)> {
        let PreparedAutofillPersist {
            mut candidate,
            outcome,
            plan_sha256: _,
        } = prepared;
        let requires_postcondition =
            matches!(outcome, AutofillPersistLogicalOutcome::NeedsPublish { .. });
        let entry_id = match &outcome {
            AutofillPersistLogicalOutcome::NeedsPublish { entry_id }
            | AutofillPersistLogicalOutcome::ReplayedNeedsPublish { entry_id }
            | AutofillPersistLogicalOutcome::Replayed { entry_id } => entry_id,
        };
        let expected_target_state =
            if candidate.history_max_items.is_some() || candidate.history_max_size.is_some() {
                let mut serialized_candidate = candidate.clone();
                enforce_history_limits(&mut serialized_candidate);
                serialized_autofill_target_state(&serialized_candidate, entry_id)?
            } else {
                serialized_autofill_target_state(&candidate, entry_id)?
            };
        let bytes = save_kdbx_with_history_limits_transformed(&mut candidate, key, save_profile)
            .context("failed to serialize the autofill candidate")?;
        let verified = Self::load_session_database(&bytes, key)
            .context("failed to reload the serialized autofill candidate")?
            .vault;
        let replay_check = prepare_autofill_persist(AutofillPersistEngineInput {
            baseline_source: &verified,
            base_loaded: &verified,
            current_source: &verified,
            transaction_id,
            operation_id,
            vault_id,
            source_identity_sha256,
            plan,
            now_epoch_ms: self.current_unix_time_ms(),
        })
        .map_err(|error| anyhow::anyhow!("serialized receipt verification failed: {error:?}"))?;
        if !matches!(
            replay_check.outcome,
            AutofillPersistLogicalOutcome::Replayed { .. }
        ) || replay_check.candidate != verified
        {
            anyhow::bail!("serialized receipt is not an exact replay binding");
        }
        let verified_target_state = serialized_autofill_target_state(&verified, entry_id)?;
        if verified_target_state != expected_target_state {
            anyhow::bail!("serialized target entry state changed during KDBX roundtrip");
        }
        if requires_postcondition {
            if count_live_entry_id(&verified.root, entry_id) != 1 {
                anyhow::bail!("serialized target entry identity is not unique");
            }
            let desired_fields = match plan {
                AutofillPersistPlanDto::Update { desired_fields, .. }
                | AutofillPersistPlanDto::Create { desired_fields, .. } => desired_fields,
            };
            let actual_fields = entry_fields_for_vault(&self.core, &verified, entry_id)?;
            if !entry_fields_semantically_equal(&actual_fields, desired_fields) {
                anyhow::bail!("serialized target entry does not satisfy the planned postcondition");
            }
        }
        Ok((bytes, verified))
    }

    fn install_committed_autofill_generation(
        &mut self,
        vault_id: &str,
        vault: Vault,
        bytes: Vec<u8>,
        fingerprint: VaultSourceFingerprint,
        mut source_status: Option<VaultSourceStatusDto>,
    ) -> Result<()> {
        let save_profile = self.inspected_save_profile(&bytes)?;
        let synced = source_status
            .as_ref()
            .is_none_or(|status| status.remote_state == "online");
        let base_warning = synced
            .then(|| self.synced_bases.store(vault_id, &bytes).err())
            .flatten()
            .map(|error| format!("failed to store synced base for {vault_id}: {error}"));
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
        loaded.bytes = Vec::new();
        loaded.baseline_fingerprint = fingerprint;
        loaded.save_profile = save_profile;
        loaded.requires_source_migration = false;
        if let Some(source_status) = source_status {
            loaded.source_status = Some(source_status);
        }
        Ok(())
    }

    fn ensure_generic_save_allowed(&self, vault_id: &str) -> Result<()> {
        let remote_cache_key = self
            .vault_session
            .find_loaded(vault_id)
            .and_then(|loaded| remote_cache_key_for_source(&loaded.source));
        if let Some(cache_key) = remote_cache_key {
            match self.remote_cache.read_pending_chain(&cache_key) {
                Err(
                    PendingRemoteCacheChainError::Missing
                    | PendingRemoteCacheChainError::NotPending
                    | PendingRemoteCacheChainError::MissingOperationBinding,
                ) => {}
                Ok(_)
                | Err(
                    PendingRemoteCacheChainError::Legacy
                    | PendingRemoteCacheChainError::DegradedCurrent
                    | PendingRemoteCacheChainError::PreviousMissing
                    | PendingRemoteCacheChainError::PreviousCorrupt { .. }
                    | PendingRemoteCacheChainError::ObservedMissing
                    | PendingRemoteCacheChainError::ObservedCorrupt { .. }
                    | PendingRemoteCacheChainError::Corrupt { .. }
                    | PendingRemoteCacheChainError::Io { .. },
                ) => return Err(PendingAutofillSyncRequired.into()),
            }
        }
        Ok(())
    }

    fn save_vault_command(&mut self, vault_id: &str) -> Result<RuntimeResponse> {
        match self.save_vault(vault_id) {
            Err(error) => match classified_runtime_error_response(&error) {
                Some(response) => Ok(response),
                None => Err(error),
            },
            result => result,
        }
    }

    pub fn save_vault(&mut self, vault_id: &str) -> Result<RuntimeResponse> {
        self.ensure_generic_save_allowed(vault_id)?;
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
        let VaultSource::LocalPath(source_path) = source else {
            unreachable!("OneDrive saves return through the CAS path")
        };
        let current = match self.read_current_snapshot(vault_id, Some(&baseline_fingerprint)) {
            Ok(current) => current,
            Err(error) if error_chain_has_io_kind(&error, std::io::ErrorKind::NotFound) => {
                let bytes = self.save_loaded_vault_bytes(vault_id, &key, save_profile)?;
                return self.local_conflict_copy_result(vault_id, &source_path, &bytes);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read current vault source: {vault_id}"));
            }
        };

        if current.fingerprint != baseline_fingerprint {
            let bytes = self.save_loaded_vault_bytes(vault_id, &key, save_profile)?;
            return self.local_conflict_copy_result(vault_id, &source_path, &bytes);
        }

        let bytes = {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let Some(vault) = loaded.vault.as_mut() else {
                anyhow::bail!("vault is locked: {vault_id}");
            };
            let bytes = save_kdbx_with_history_limits_transformed(vault, &key, save_profile)
                .with_context(|| format!("failed to save vault: {vault_id}"))?;
            loaded.save_profile.kdf = None;
            bytes
        };

        let next_fingerprint = match self.write_local_source(vault_id, &bytes, &current.fingerprint)
        {
            Ok(fingerprint) => fingerprint,
            Err(error)
                if matches!(
                    error.downcast_ref::<LocalFileCommitError>(),
                    Some(LocalFileCommitError::Conflict { .. })
                ) =>
            {
                return self.local_conflict_copy_result(vault_id, &source_path, &bytes);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to write vault: {vault_id}"));
            }
        };
        {
            let loaded = self
                .vault_session
                .find_loaded_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            loaded.bytes = Vec::new();
            loaded.baseline_fingerprint = next_fingerprint;
            loaded.requires_source_migration = false;
        }
        if let Err(error) = self.synced_bases.store(vault_id, &bytes) {
            self.record_local_save_warnings(vec![format!(
                "failed to store synced base for {vault_id}: {error}"
            )]);
        }
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::Saved,
            merge_summary: None,
            conflict_copy_path: None,
        }))
    }

    fn local_conflict_copy_result(
        &self,
        vault_id: &str,
        source_path: &str,
        bytes: &[u8],
    ) -> Result<RuntimeResponse> {
        let conflict_copy_path =
            write_local_conflict_copy(Path::new(source_path), bytes, self.current_unix_time())
                .with_context(|| format!("failed to write conflict copy for: {vault_id}"))?;
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::ConflictCopy,
            merge_summary: None,
            conflict_copy_path: Some(conflict_copy_path.to_string_lossy().into_owned()),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn save_onedrive_vault(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        mut key: Arc<TransformedKey>,
        baseline_fingerprint: &VaultSourceFingerprint,
        mut local_save_profile: SaveProfile,
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
        let local_vault = self.loaded_vault(vault_id)?.clone();
        let base_bytes = self
            .synced_bases
            .read(vault_id)
            .with_context(|| format!("failed to read synced base: {vault_id}"))?
            .with_context(|| format!("synced base is missing: {vault_id}"))?;
        let base_vault = match Self::load_session_database(&base_bytes, &key) {
            Ok(database) => database.vault,
            Err(KdbxError::HeaderHmacMismatch) => self
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
        local_save_profile.kdf = None;
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
        let (local_bytes, verified_local) = Self::serialize_and_verify_vault_candidate(
            local_vault.clone(),
            &key,
            local_save_profile.clone(),
        )
        .context("failed to verify the local OneDrive candidate")?;
        let mut saw_source_change = false;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = match self.one_drive.remote_state(drive_id, item_id) {
                Ok(state) => state,
                Err(error) => {
                    let response = self.save_remote_vault_to_pending_cache(
                        vault_id,
                        source,
                        local_bytes,
                        baseline_fingerprint,
                        display_name,
                        Some(account_label),
                        format_error_chain(&error),
                    )?;
                    self.install_pending_vault_candidate(vault_id, verified_local.clone())?;
                    return Ok(response);
                }
            };
            let remote_bytes = if state.matches_fingerprint(baseline_fingerprint) {
                base_bytes.clone()
            } else {
                saw_source_change = true;
                match self
                    .one_drive
                    .read_snapshot_from_state(drive_id, item_id, &state)
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
                            format_error_chain(&error),
                        )?;
                        self.install_pending_vault_candidate(vault_id, verified_local.clone())?;
                        return Ok(response);
                    }
                }
            };
            let remote_vault = match Self::load_session_database(&remote_bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    let Some((vault, refreshed_key)) = self
                        .refresh_transformed_key_from_unlock_blob(vault_id, &remote_bytes)
                        .context("failed to refresh quick unlock after the OneDrive KDF changed")?
                    else {
                        return self.upload_onedrive_conflict_copy(
                            drive_id,
                            item_id,
                            &display_name,
                            &local_bytes,
                        );
                    };
                    key = refreshed_key;
                    vault
                }
                Err(_) => {
                    return self.upload_onedrive_conflict_copy(
                        drive_id,
                        item_id,
                        &display_name,
                        &local_bytes,
                    );
                }
            };
            let remote_save_profile = self
                .inspected_save_profile(&remote_bytes)
                .context("failed to inspect the current OneDrive generation")?;
            let merged_save_profile = match Self::merge_save_profile(
                &base_save_profile,
                &local_save_profile,
                &remote_save_profile,
            ) {
                Ok(profile) => profile,
                Err(_) => {
                    return self.upload_onedrive_conflict_copy(
                        drive_id,
                        item_id,
                        &display_name,
                        &local_bytes,
                    );
                }
            };
            let patched = match three_way_field_patch(&base_vault, &local_vault, &remote_vault) {
                Ok(patched) => patched,
                Err(_) => {
                    return self.upload_onedrive_conflict_copy(
                        drive_id,
                        item_id,
                        &display_name,
                        &local_bytes,
                    );
                }
            };
            let report = patched.report;
            let (bytes, verified_vault) = Self::serialize_and_verify_vault_candidate(
                patched.vault,
                &key,
                merged_save_profile,
            )
            .context("failed to verify the rebased OneDrive candidate")?;

            match self
                .one_drive
                .conditional_write(drive_id, item_id, &bytes, &state)
            {
                Ok(OneDriveConditionalWriteOutcome::Committed { fingerprint, e_tag }) => {
                    let cached_at = self.current_unix_time() as i64;
                    let cache_result = self.remote_cache.write_with_source_etag(
                        &cache_key,
                        RemoteVaultCacheEntry {
                            bytes: bytes.clone(),
                            fingerprint: fingerprint.clone(),
                            display_name: display_name.clone(),
                            account_label: account_label.clone(),
                            cached_at,
                            pending_sync: false,
                        },
                        e_tag.as_deref(),
                    );
                    let (_, status) = remote_source_status_after_commit(
                        &cache_key,
                        cached_at,
                        cache_result.as_ref().err(),
                    );
                    self.install_committed_autofill_generation(
                        vault_id,
                        verified_vault,
                        bytes,
                        fingerprint,
                        Some(status),
                    )?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                        status: if saw_source_change {
                            SaveVaultStatusDto::Merged
                        } else {
                            SaveVaultStatusDto::Saved
                        },
                        merge_summary: saw_source_change.then(|| three_way_patch_summary(&report)),
                        conflict_copy_path: None,
                    }));
                }
                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed)
                    if attempt + 1 < MAX_SOURCE_ATTEMPTS =>
                {
                    saw_source_change = true;
                    continue;
                }
                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed) => {
                    return self.upload_onedrive_conflict_copy(
                        drive_id,
                        item_id,
                        &display_name,
                        &bytes,
                    );
                }
                Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown { message }) => {
                    self.synced_bases
                        .store(vault_id, &remote_bytes)
                        .with_context(|| {
                            format!("failed to store pending OneDrive base: {vault_id}")
                        })?;
                    let response = self.save_remote_vault_to_pending_cache(
                        vault_id,
                        source,
                        bytes,
                        baseline_fingerprint,
                        display_name,
                        Some(account_label),
                        message,
                    );
                    let response = match response {
                        Ok(response) => response,
                        Err(error) => {
                            self.synced_bases.store(vault_id, &base_bytes).with_context(|| {
                                format!(
                                    "failed to restore the synced OneDrive base after pending cache failure: {error:#}"
                                )
                            })?;
                            return Err(error);
                        }
                    };
                    self.install_pending_vault_candidate(vault_id, verified_vault)?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
                    return Ok(response);
                }
                Err(error) => {
                    self.synced_bases
                        .store(vault_id, &remote_bytes)
                        .with_context(|| {
                            format!("failed to store pending OneDrive base: {vault_id}")
                        })?;
                    let response = self.save_remote_vault_to_pending_cache(
                        vault_id,
                        source,
                        bytes,
                        baseline_fingerprint,
                        display_name,
                        Some(account_label),
                        error.to_string(),
                    );
                    let response = match response {
                        Ok(response) => response,
                        Err(error) => {
                            self.synced_bases.store(vault_id, &base_bytes).with_context(|| {
                                format!(
                                    "failed to restore the synced OneDrive base after pending cache failure: {error:#}"
                                )
                            })?;
                            return Err(error);
                        }
                    };
                    self.install_pending_vault_candidate(vault_id, verified_vault)?;
                    self.replace_session_transformed_key(vault_id, key.clone())?;
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
        key: Arc<TransformedKey>,
        baseline_fingerprint: &VaultSourceFingerprint,
    ) -> Result<RuntimeResponse> {
        let state = self.one_drive.remote_state(drive_id, item_id)?;
        if state.matches_fingerprint(baseline_fingerprint) {
            return Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
                merge_summary: None,
                conflict_copy_path: None,
            }));
        }

        let snapshot = self
            .one_drive
            .read_snapshot_from_state(drive_id, item_id, &state)?;
        let (remote_vault, key) = match Self::load_session_database(&snapshot.bytes, &key) {
            Ok(database) => (database.vault, key),
            Err(KdbxError::HeaderHmacMismatch) => self
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
        let cache_result = self.remote_cache.write_with_source_etag(
            &cache_key,
            RemoteVaultCacheEntry {
                bytes: snapshot.bytes.clone(),
                fingerprint: snapshot.fingerprint.clone(),
                display_name: display_name.clone(),
                account_label: account_label.clone(),
                cached_at,
                pending_sync: false,
            },
            state.e_tag.as_deref(),
        );
        let (_, status) =
            remote_source_status_after_commit(&cache_key, cached_at, cache_result.as_ref().err());
        self.install_committed_autofill_generation(
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
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::Merged,
            merge_summary: None,
            conflict_copy_path: None,
        }))
    }

    fn refresh_transformed_key_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<Option<(Vault, Arc<TransformedKey>)>> {
        self.unlock_snapshot_from_unlock_blob(vault_id, bytes, true)
    }

    fn unlock_historical_snapshot_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<Option<(Vault, Arc<TransformedKey>)>> {
        self.unlock_snapshot_from_unlock_blob(vault_id, bytes, false)
    }

    fn unlock_snapshot_from_unlock_blob(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
        refresh_cached_transformed_key: bool,
    ) -> Result<Option<(Vault, Arc<TransformedKey>)>> {
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
        let attempt = if refresh_cached_transformed_key {
            unlock_from_blob(
                self.secure_storage.as_ref(),
                &storage_key,
                bytes,
                self.allow_unlock_kdf,
            )?
        } else {
            unlock_historical_snapshot_from_blob(
                self.secure_storage.as_ref(),
                &storage_key,
                bytes,
                self.allow_unlock_kdf,
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
        Ok(Some((unlocked.vault, Arc::new(unlocked.transformed_key))))
    }

    fn replace_session_transformed_key(
        &mut self,
        vault_id: &str,
        key: Arc<TransformedKey>,
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
        key: &TransformedKey,
        save_profile: SaveProfile,
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
        loaded.save_profile.kdf = None;
        Ok(())
    }

    fn upload_onedrive_conflict_copy(
        &mut self,
        drive_id: &str,
        item_id: &str,
        display_name: &str,
        bytes: &[u8],
    ) -> Result<RuntimeResponse> {
        let name = onedrive_conflict_copy_name(display_name, self.current_unix_time());
        let item = self
            .one_drive
            .upload_sibling_conflict_copy(drive_id, item_id, &name, bytes)?;
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::ConflictCopy,
            merge_summary: None,
            conflict_copy_path: Some(format!("onedrive:{}", item.name)),
        }))
    }

    fn save_loaded_vault_bytes(
        &mut self,
        vault_id: &str,
        key: &TransformedKey,
        save_profile: SaveProfile,
    ) -> Result<Vec<u8>> {
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let Some(vault) = loaded.vault.as_mut() else {
            anyhow::bail!("vault is locked: {vault_id}");
        };
        let bytes = save_kdbx_with_history_limits_transformed(vault, key, save_profile)
            .with_context(|| format!("failed to save vault: {vault_id}"))?;
        loaded.save_profile.kdf = None;
        Ok(bytes)
    }

    fn save_remote_vault_to_pending_cache(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        expected_cache_fingerprint: &VaultSourceFingerprint,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
    ) -> Result<RuntimeResponse> {
        let cache_key = remote_cache_key_for_source(&source).context("source is not remote")?;
        let save_profile = self
            .inspected_save_profile(&bytes)
            .context("failed to inspect pending remote vault")?;
        let cached_at = self.current_unix_time() as i64;
        let fingerprint = fingerprint_for_cached_bytes(&bytes, cached_at);
        let account_label = account_label.unwrap_or_else(|| cache_key.provider_kind.clone());
        self.remote_cache.write_generic_pending(
            &cache_key,
            RemoteVaultCacheEntry {
                bytes: bytes.clone(),
                fingerprint: fingerprint.clone(),
                display_name,
                account_label,
                cached_at,
                pending_sync: true,
            },
            expected_cache_fingerprint,
        )?;
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
        loaded.bytes = bytes;
        loaded.baseline_fingerprint = fingerprint;
        loaded.save_profile = save_profile;
        loaded.source_status = Some(status);
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::SavedToCache,
            merge_summary: None,
            conflict_copy_path: None,
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
        let shared_pending = self.remote_cache.read_pending_chain(&cache_key);
        if pending_sync || shared_pending.is_ok() {
            return self.retry_pending_remote_vault_sync(
                vault_id,
                &drive_id,
                &item_id,
                cache_key,
                baseline_fingerprint,
                key,
            );
        }
        match shared_pending {
            Err(
                PendingRemoteCacheChainError::Missing | PendingRemoteCacheChainError::NotPending,
            ) => {}
            Err(
                PendingRemoteCacheChainError::MissingOperationBinding
                | PendingRemoteCacheChainError::Legacy,
            ) => {
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind.clone(),
                    remote_state: "pending_sync".into(),
                    last_sync_at: None,
                    cached_at: self.remote_cache.read(&cache_key)?.map(|entry| entry.cached_at),
                    last_error: Some(
                        "another runtime owns a generic pending cache generation; reload before synchronization"
                            .into(),
                    ),
                };
                if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                return Ok(status);
            }
            Err(error) => {
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind.clone(),
                    remote_state: "pending_sync".into(),
                    last_sync_at: None,
                    cached_at: self
                        .remote_cache
                        .read(&cache_key)?
                        .map(|entry| entry.cached_at),
                    last_error: Some(error.to_string()),
                };
                if let Some(loaded) = self.vault_session.find_loaded_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                return Ok(status);
            }
            Ok(_) => unreachable!("shared pending handled above"),
        }

        match self.one_drive.remote_state(&drive_id, &item_id) {
            Ok(state) if state.matches_fingerprint(&baseline_fingerprint) => {
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
                let snapshot = self
                    .one_drive
                    .read_snapshot_from_state(&drive_id, &item_id, &state)?;
                let remote_save_profile = self
                    .inspected_save_profile(&snapshot.bytes)
                    .context("failed to inspect OneDrive generation during source refresh")?;
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
                        let base_bytes = self
                            .synced_bases
                            .read(vault_id)
                            .with_context(|| format!("failed to read synced base: {vault_id}"))?
                            .with_context(|| format!("synced base is missing: {vault_id}"))?;
                        let base_vault = Self::load_session_database(&base_bytes, &key)
                            .context("failed to parse synced base during source refresh")?
                            .vault;
                        let base_save_profile = self
                            .inspected_save_profile(&base_bytes)
                            .context("failed to inspect synced base during source refresh")?;
                        let remote_vault = match Self::load_session_database(&snapshot.bytes, &key)
                        {
                            Ok(database) => database.vault,
                            Err(KdbxError::HeaderHmacMismatch) => {
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
                        let merged_save_profile = Self::merge_save_profile(
                            &base_save_profile,
                            &local_save_profile,
                            &remote_save_profile,
                        )
                        .context(
                            "OneDrive refresh cannot merge concurrent encryption profile changes",
                        )?;
                        Some((
                            three_way_field_patch(&base_vault, &local_vault, &remote_vault)
                                .context("OneDrive refresh cannot be represented as a field patch")?
                                .vault,
                            key,
                            merged_save_profile,
                        ))
                    }
                    _ => None,
                };
                let cached_at = self.current_unix_time() as i64;
                let display_name = display_name_for_cloud_name(&snapshot.name);
                self.remote_cache.write(
                    &cache_key,
                    RemoteVaultCacheEntry {
                        bytes: snapshot.bytes.clone(),
                        fingerprint: snapshot.fingerprint.clone(),
                        display_name: display_name.clone(),
                        account_label: snapshot.account_label.clone(),
                        cached_at,
                        pending_sync: false,
                    },
                )?;
                self.synced_bases
                    .store(vault_id, &snapshot.bytes)
                    .with_context(|| format!("failed to store synced base: {vault_id}"))?;
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "online".into(),
                    last_sync_at: Some(cached_at),
                    cached_at: Some(cached_at),
                    last_error: None,
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
                loaded.bytes = snapshot.bytes;
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
        baseline_fingerprint: VaultSourceFingerprint,
        key: Option<Arc<TransformedKey>>,
    ) -> Result<VaultSourceStatusDto> {
        let sync_result = match self.remote_cache.read_pending_chain(&cache_key) {
            Ok(chain) => self.try_sync_pending_autofill_chain(
                vault_id,
                drive_id,
                item_id,
                &cache_key,
                chain,
                key.clone(),
            ),
            Err(
                PendingRemoteCacheChainError::MissingOperationBinding
                | PendingRemoteCacheChainError::Legacy,
            ) => self.try_upload_pending_remote_vault(
                vault_id,
                drive_id,
                item_id,
                &cache_key,
                &baseline_fingerprint,
                key.clone(),
            ),
            Err(error) => Err(anyhow::anyhow!(error)),
        };
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

    #[allow(clippy::too_many_arguments)]
    fn try_sync_pending_autofill_chain(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        cache_key: &RemoteCacheKey,
        chain: PendingRemoteCacheChain,
        key: Option<Arc<TransformedKey>>,
    ) -> Result<VaultSourceStatusDto> {
        const MAX_SOURCE_ATTEMPTS: usize = 3;
        let mut key = key.context("pending autofill cache requires an unlocked vault")?;
        let initial_key = key.clone();
        let pending_vault = match Self::load_session_database(&chain.pending.bytes, &key) {
            Ok(database) => database.vault,
            Err(KdbxError::HeaderHmacMismatch) => {
                let (vault, refreshed_key) = self
                    .refresh_transformed_key_from_unlock_blob(vault_id, &chain.pending.bytes)?
                    .context(
                        "pending autofill generation changed KDF and quick unlock is unavailable",
                    )?;
                key = refreshed_key;
                vault
            }
            Err(error) => {
                return Err(error)
                    .context("failed to parse authenticated pending autofill generation");
            }
        };
        let pending_save_profile = self
            .inspected_save_profile(&chain.pending.bytes)
            .context("failed to inspect authenticated pending autofill generation")?;
        let plan_baseline_vault = match Self::load_session_database(
            &chain.plan_baseline.bytes,
            &key,
        ) {
            Ok(database) => database.vault,
            Err(KdbxError::HeaderHmacMismatch) => {
                let initial_vault = if initial_key.as_bytes() != key.as_bytes() {
                    match Self::load_session_database(&chain.plan_baseline.bytes, &initial_key) {
                        Ok(database) => Some(database.vault),
                        Err(KdbxError::HeaderHmacMismatch) => None,
                        Err(error) => {
                            return Err(error).context(
                                "failed to parse authenticated autofill plan baseline generation",
                            );
                        }
                    }
                } else {
                    None
                };
                match initial_vault {
                        Some(vault) => vault,
                        None => self
                            .unlock_historical_snapshot_from_unlock_blob(
                                vault_id,
                                &chain.plan_baseline.bytes,
                            )?
                            .context(
                                "authenticated autofill plan baseline uses a historical KDF and quick unlock is unavailable",
                            )?
                            .0,
                    }
            }
            Err(error) => {
                return Err(error)
                    .context("failed to parse authenticated autofill plan baseline generation");
            }
        };
        let plan_baseline_save_profile = self
            .inspected_save_profile(&chain.plan_baseline.bytes)
            .context("failed to inspect authenticated autofill plan baseline generation")?;
        let observed_source_vault = Self::load_session_database(&chain.observed_source.bytes, &key)
            .context("failed to parse authenticated autofill observed source generation")?
            .vault;
        let observed_source_save_profile = self
            .inspected_save_profile(&chain.observed_source.bytes)
            .context("failed to inspect authenticated autofill observed source generation")?;
        let binding =
            required_pending_autofill_receipt_binding(&pending_vault, &chain.operation_id)?;
        let source = VaultSource::OneDriveItem {
            drive_id: drive_id.into(),
            item_id: item_id.into(),
        };
        let source_identity_sha256 = autofill_source_identity_sha256(&source);
        if binding.source_identity_sha256 != source_identity_sha256 {
            anyhow::bail!(
                "pending autofill receipt source identity does not match the vault source"
            );
        }
        let plan = reconstruct_pending_autofill_plan(
            &self.core,
            &plan_baseline_vault,
            &pending_vault,
            &binding,
        )?;
        let reconstructed_plan_sha256 = plan_sha256(
            &binding.transaction_id,
            vault_id,
            &binding.source_identity_sha256,
            &plan,
        )
        .map_err(|error| anyhow::anyhow!("pending autofill plan is invalid: {error:?}"))?;
        if reconstructed_plan_sha256 != binding.plan_sha256 {
            anyhow::bail!("pending autofill plan digest does not match authenticated generations");
        }
        if !matches!(
            (chain.source_etag.as_ref(), chain.source_revision),
            (Some(_), None) | (None, Some(_))
        ) {
            anyhow::bail!("pending autofill cache source condition is missing or ambiguous");
        }
        let (loaded_fingerprint, live_vault, live_save_profile) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let live_vault = loaded
                .vault
                .as_ref()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            (
                loaded.baseline_fingerprint.clone(),
                live_vault.clone(),
                loaded.save_profile.clone(),
            )
        };
        let normalized_live = self
            .normalize_autofill_vault_snapshot(live_vault, &key, live_save_profile.clone())
            .context("failed to normalize the live pending autofill generation")?;
        let (live_vault, live_save_profile) = if same_content_fingerprint(
            &loaded_fingerprint,
            &chain.pending.fingerprint,
        ) {
            (normalized_live, live_save_profile)
        } else if same_content_fingerprint(&loaded_fingerprint, &chain.plan_baseline.fingerprint) {
            let prepared = prepare_autofill_persist(AutofillPersistEngineInput {
                baseline_source: &plan_baseline_vault,
                base_loaded: &normalized_live,
                current_source: &pending_vault,
                transaction_id: &binding.transaction_id,
                operation_id: &chain.operation_id,
                vault_id,
                source_identity_sha256: &binding.source_identity_sha256,
                plan: &plan,
                now_epoch_ms: self.current_unix_time_ms(),
            })
            .map_err(|error| {
                anyhow::anyhow!("stale runtime could not adopt shared pending state: {error:?}")
            })?;
            if matches!(
                prepared.outcome,
                AutofillPersistLogicalOutcome::NeedsPublish { .. }
            ) {
                anyhow::bail!("shared pending generation did not replay its bound receipt");
            }
            let adopted_save_profile = Self::merge_save_profile(
                &plan_baseline_save_profile,
                &live_save_profile,
                &pending_save_profile,
            )
            .context("stale runtime encryption profile conflicts with shared pending state")?;
            (prepared.candidate, adopted_save_profile)
        } else {
            anyhow::bail!(
                "loaded generation matches neither the shared pending candidate nor its plan baseline"
            );
        };
        let live_matches_pending = live_vault == pending_vault;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = self.one_drive.remote_state(drive_id, item_id)?;
            let remote = self
                .one_drive
                .read_snapshot_from_state(drive_id, item_id, &state)?;
            let remote_vault = match Self::load_session_database(&remote.bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    let (vault, refreshed_key) = self
                        .refresh_transformed_key_from_unlock_blob(vault_id, &remote.bytes)?
                        .context(
                            "current OneDrive generation changed KDF and quick unlock is unavailable",
                        )?;
                    key = refreshed_key;
                    vault
                }
                Err(error) => {
                    return Err(error).context(
                        "failed to parse current OneDrive generation during pending sync",
                    );
                }
            };
            let remote_save_profile = self
                .inspected_save_profile(&remote.bytes)
                .context("failed to inspect current OneDrive generation during pending sync")?;
            let merged_save_profile = Self::merge_save_profile(
                &observed_source_save_profile,
                &live_save_profile,
                &remote_save_profile,
            )
            .context("pending autofill encryption profile changed concurrently")?;
            let remote_binding =
                pending_autofill_receipt_binding(&remote_vault, &chain.operation_id)?;
            if remote_binding
                .as_ref()
                .is_some_and(|remote_binding| remote_binding != &binding)
            {
                anyhow::bail!("remote autofill receipt operation binding changed");
            }
            if remote_binding.is_none() {
                validate_unreceipted_pending_target_unchanged(
                    &plan_baseline_vault,
                    &observed_source_vault,
                    &remote_vault,
                    &binding,
                )?;
            }

            if same_content_fingerprint(&remote.fingerprint, &chain.pending.fingerprint)
                && live_matches_pending
                && merged_save_profile == remote_save_profile
            {
                if remote_binding.as_ref() != Some(&binding) {
                    anyhow::bail!("remote pending bytes do not contain the bound autofill receipt");
                }
                return self.finish_pending_autofill_sync(
                    vault_id,
                    cache_key,
                    &chain.operation_id,
                    &chain.pending.fingerprint,
                    remote_vault,
                    remote.bytes,
                    remote.fingerprint,
                    state.e_tag.as_deref(),
                    key.clone(),
                );
            }

            let mut local_for_engine = live_vault.clone();
            let baseline_for_engine = if remote_binding.is_some() {
                &pending_vault
            } else {
                remove_pending_autofill_operation_receipt(
                    &self.core,
                    &mut local_for_engine,
                    &chain.operation_id,
                )?;
                &observed_source_vault
            };
            let prepared = prepare_autofill_persist(AutofillPersistEngineInput {
                baseline_source: baseline_for_engine,
                base_loaded: &local_for_engine,
                current_source: &remote_vault,
                transaction_id: &binding.transaction_id,
                operation_id: &chain.operation_id,
                vault_id,
                source_identity_sha256: &binding.source_identity_sha256,
                plan: &plan,
                now_epoch_ms: self.current_unix_time_ms(),
            })
            .map_err(|error| anyhow::anyhow!("pending autofill merge failed: {error:?}"))?;

            if matches!(
                &prepared.outcome,
                AutofillPersistLogicalOutcome::Replayed { .. }
            ) && merged_save_profile == remote_save_profile
            {
                if prepared.candidate != remote_vault {
                    anyhow::bail!(
                        "pending autofill replay candidate differs from the current source"
                    );
                }
                return self.finish_pending_autofill_sync(
                    vault_id,
                    cache_key,
                    &chain.operation_id,
                    &chain.pending.fingerprint,
                    prepared.candidate,
                    remote.bytes,
                    remote.fingerprint,
                    state.e_tag.as_deref(),
                    key.clone(),
                );
            }

            let (bytes, verified_vault) = self.serialize_and_verify_autofill_candidate(
                prepared,
                &binding.transaction_id,
                &chain.operation_id,
                vault_id,
                &binding.source_identity_sha256,
                &plan,
                &key,
                merged_save_profile,
            )?;
            match self
                .one_drive
                .conditional_write(drive_id, item_id, &bytes, &state)?
            {
                OneDriveConditionalWriteOutcome::Committed { fingerprint, e_tag } => {
                    return self.finish_pending_autofill_sync(
                        vault_id,
                        cache_key,
                        &chain.operation_id,
                        &chain.pending.fingerprint,
                        verified_vault,
                        bytes,
                        fingerprint,
                        e_tag.as_deref(),
                        key.clone(),
                    );
                }
                OneDriveConditionalWriteOutcome::PreconditionFailed
                    if attempt + 1 < MAX_SOURCE_ATTEMPTS =>
                {
                    continue;
                }
                OneDriveConditionalWriteOutcome::PreconditionFailed => {
                    anyhow::bail!("OneDrive changed during every pending autofill sync attempt")
                }
                OneDriveConditionalWriteOutcome::OutcomeUnknown { message } => {
                    anyhow::bail!("pending autofill sync outcome is unknown: {message}")
                }
            }
        }
        unreachable!("bounded pending autofill sync attempts must return")
    }

    fn normalize_autofill_vault_snapshot(
        &self,
        mut vault: Vault,
        key: &TransformedKey,
        save_profile: SaveProfile,
    ) -> Result<Vault> {
        let bytes = save_kdbx_with_history_limits_transformed(&mut vault, key, save_profile)
            .context("failed to serialize autofill vault snapshot")?;
        Ok(Self::load_session_database(&bytes, key)
            .context("failed to reload autofill vault snapshot")?
            .vault)
    }

    fn finish_pending_autofill_sync(
        &mut self,
        vault_id: &str,
        cache_key: &RemoteCacheKey,
        operation_id: &str,
        expected_pending: &VaultSourceFingerprint,
        vault: Vault,
        bytes: Vec<u8>,
        fingerprint: VaultSourceFingerprint,
        source_etag: Option<&str>,
        key: Arc<TransformedKey>,
    ) -> Result<VaultSourceStatusDto> {
        let cached_at = self.current_unix_time() as i64;
        let (display_name, account_label) = {
            let loaded = self
                .vault_session
                .find_loaded(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            (
                loaded.name.clone(),
                loaded
                    .source_account_label
                    .clone()
                    .unwrap_or_else(|| cache_key.provider_kind.clone()),
            )
        };
        let completion = self.remote_cache.complete_pending_autofill(
            cache_key,
            operation_id,
            expected_pending,
            RemoteVaultCacheEntry {
                bytes: bytes.clone(),
                fingerprint: fingerprint.clone(),
                display_name,
                account_label,
                cached_at,
                pending_sync: false,
            },
            source_etag,
        )?;
        let status = VaultSourceStatusDto {
            source_kind: cache_key.provider_kind.clone(),
            remote_state: "online".into(),
            last_sync_at: Some(cached_at),
            cached_at: Some(cached_at),
            last_error: matches!(completion, PendingRemoteCacheCompletion::DurabilityUnknown)
                .then(|| "remote cache completion is visible but durability is unknown".into()),
        };
        self.install_committed_autofill_generation(
            vault_id,
            vault,
            bytes,
            fingerprint,
            Some(status.clone()),
        )?;
        self.replace_session_transformed_key(vault_id, key)?;
        Ok(status)
    }

    fn try_upload_pending_remote_vault(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        cache_key: &RemoteCacheKey,
        pending_fingerprint: &VaultSourceFingerprint,
        key: Option<Arc<TransformedKey>>,
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
        let _pending_vault = Self::load_session_database(&pending.bytes, &key)
            .context("failed to parse pending remote vault")?
            .vault;
        let _pending_save_profile = self
            .inspected_save_profile(&pending.bytes)
            .context("failed to inspect pending remote vault")?;
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
        let base_bytes = self
            .synced_bases
            .read(vault_id)
            .with_context(|| format!("failed to read synced base: {vault_id}"))?
            .with_context(|| format!("synced base is missing: {vault_id}"))?;
        let base_vault = Self::load_session_database(&base_bytes, &key)
            .context("failed to parse synced base during pending synchronization")?
            .vault;
        let base_save_profile = self
            .inspected_save_profile(&base_bytes)
            .context("failed to inspect synced base during pending synchronization")?;

        for attempt in 0..MAX_SOURCE_ATTEMPTS {
            let state = self.one_drive.remote_state(drive_id, item_id)?;
            let remote = self
                .one_drive
                .read_snapshot_from_state(drive_id, item_id, &state)?;
            let remote_vault = match Self::load_session_database(&remote.bytes, &key) {
                Ok(database) => database.vault,
                Err(KdbxError::HeaderHmacMismatch) => {
                    let Some((vault, refreshed_key)) =
                        self.refresh_transformed_key_from_unlock_blob(vault_id, &remote.bytes)?
                    else {
                        return self.upload_pending_onedrive_conflict_copy(
                            vault_id,
                            drive_id,
                            item_id,
                            cache_key,
                            &pending,
                            &pending.bytes,
                            "current OneDrive generation uses a different vault key",
                        );
                    };
                    key = refreshed_key;
                    vault
                }
                Err(error) => {
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &pending.bytes,
                        &format!("current OneDrive generation cannot be parsed: {error}"),
                    );
                }
            };
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
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &pending.bytes,
                        &error.to_string(),
                    );
                }
            };
            let patched = match three_way_field_patch(&base_vault, &local_vault, &remote_vault) {
                Ok(patched) => patched,
                Err(error) => {
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &pending.bytes,
                        &format!("pending changes cannot be represented: {error}"),
                    );
                }
            };
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
                let one_drive = &mut self.one_drive;
                self.remote_cache.complete_generic_pending_while(
                    cache_key,
                    pending_fingerprint,
                    || {
                        let fingerprint =
                            match one_drive.conditional_write(drive_id, item_id, &bytes, &state) {
                                Ok(OneDriveConditionalWriteOutcome::Committed {
                                    fingerprint,
                                    e_tag: _,
                                }) => fingerprint,
                                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed) => {
                                    return Err(PendingGenericCasConflict.into());
                                }
                                Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown { message }) => {
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
                    self.install_committed_autofill_generation(
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
                    return self.upload_pending_onedrive_conflict_copy(
                        vault_id,
                        drive_id,
                        item_id,
                        cache_key,
                        &pending,
                        &bytes,
                        &error.to_string(),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded pending OneDrive attempts must return")
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_pending_onedrive_conflict_copy(
        &mut self,
        vault_id: &str,
        drive_id: &str,
        item_id: &str,
        cache_key: &RemoteCacheKey,
        pending: &RemoteVaultCacheEntry,
        bytes: &[u8],
        reason: &str,
    ) -> Result<VaultSourceStatusDto> {
        let name = onedrive_conflict_copy_name(&pending.display_name, self.current_unix_time());
        let item = self
            .one_drive
            .upload_sibling_conflict_copy(drive_id, item_id, &name, bytes)?;
        let status = VaultSourceStatusDto {
            source_kind: cache_key.provider_kind.clone(),
            remote_state: "pending_sync".into(),
            last_sync_at: None,
            cached_at: Some(pending.cached_at),
            last_error: Some(format!(
                "{reason}; local changes were saved to onedrive:{}",
                item.name
            )),
        };
        let loaded = self
            .vault_session
            .find_loaded_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.source_status = Some(status.clone());
        Ok(status)
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
        &self,
        vault_id: &str,
        baseline: Option<&VaultSourceFingerprint>,
    ) -> Result<LoadedSourceSnapshot> {
        let loaded = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        match &loaded.source {
            VaultSource::LocalPath(path) => {
                let snapshot = self
                    .local_files
                    .read_snapshot(path)
                    .with_context(|| format!("failed to read current vault source: {path}"))?;
                Ok(LoadedSourceSnapshot {
                    bytes: Some(snapshot.bytes),
                    fingerprint: snapshot.fingerprint,
                })
            }
            VaultSource::OneDriveItem { drive_id, item_id } => {
                let state = self.one_drive.remote_state(drive_id, item_id)?;
                if let Some(baseline) = baseline {
                    if state.matches_fingerprint(baseline) {
                        return Ok(LoadedSourceSnapshot {
                            bytes: None,
                            fingerprint: baseline.clone(),
                        });
                    }
                }
                let snapshot = self
                    .one_drive
                    .read_snapshot_from_state(drive_id, item_id, &state)?;
                Ok(LoadedSourceSnapshot {
                    bytes: Some(snapshot.bytes),
                    fingerprint: snapshot.fingerprint,
                })
            }
        }
    }

    fn write_local_source(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
        expected: &VaultSourceFingerprint,
    ) -> Result<VaultSourceFingerprint> {
        let source = self
            .vault_session
            .find_loaded(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?
            .source
            .clone();
        let VaultSource::LocalPath(path) = source else {
            anyhow::bail!("OneDrive writes require the CAS save path")
        };
        let commit = self
            .local_files
            .write_if_unchanged(&path, expected, bytes)?;
        self.record_local_save_warnings(commit.warnings);
        Ok(commit.fingerprint)
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

        if let Some(score) = score_entry_match(url, &entry.url) {
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

fn autofill_persist_error(code: &str, message: impl Into<String>) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: message.into(),
    })
}

fn autofill_persist_conflict(
    transaction_id: &str,
    operation_id: &str,
    vault_id: &str,
    code: AutofillPersistConflictCodeDto,
) -> RuntimeResponse {
    let retryable = matches!(
        code,
        AutofillPersistConflictCodeDto::ActiveVaultMismatch
            | AutofillPersistConflictCodeDto::SourceChangedRetryExhausted
    );
    RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
        transaction_id: transaction_id.into(),
        operation_id: operation_id.into(),
        vault_id: vault_id.into(),
        outcome: AutofillPersistOutcomeDto::Conflict { code, retryable },
    })
}

#[allow(clippy::too_many_arguments)]
fn autofill_persist_durable(
    transaction_id: &str,
    operation_id: &str,
    vault_id: &str,
    entry_id: &str,
    disposition: AutofillPersistDispositionDto,
    durability: AutofillPersistDurabilityDto,
    cache_state: AutofillCacheStateDto,
    fingerprint: &VaultSourceFingerprint,
    merge_summary: Option<MergeSummaryDto>,
) -> RuntimeResponse {
    RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
        transaction_id: transaction_id.into(),
        operation_id: operation_id.into(),
        vault_id: vault_id.into(),
        outcome: AutofillPersistOutcomeDto::Durable {
            disposition,
            entry_id: entry_id.into(),
            durability,
            cache_state,
            committed_fingerprint: AutofillCommittedFingerprintDto {
                content_sha256: fingerprint.content_sha256.clone(),
                size_bytes: fingerprint.size_bytes,
            },
            merge_summary,
            receipt_version: 1,
        },
    })
}

fn autofill_engine_error_response(
    transaction_id: &str,
    operation_id: &str,
    vault_id: &str,
    error: AutofillPersistEngineError,
) -> RuntimeResponse {
    match error {
        AutofillPersistEngineError::Conflict(code) => {
            autofill_persist_conflict(transaction_id, operation_id, vault_id, code)
        }
        AutofillPersistEngineError::MergeConflict(_message) => autofill_persist_conflict(
            transaction_id,
            operation_id,
            vault_id,
            AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
        ),
        AutofillPersistEngineError::InvalidPlan(message) => {
            autofill_persist_error("invalid_autofill_plan", message)
        }
        AutofillPersistEngineError::InvalidLedger(message) => {
            autofill_persist_error("source_corrupt", message)
        }
        AutofillPersistEngineError::Mutation(message) => {
            autofill_persist_error("source_corrupt", message)
        }
    }
}

fn autofill_source_identity_sha256(source: &VaultSource) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"vaultkern-autofill-source-v1\0");
    match source {
        VaultSource::LocalPath(path) => {
            hasher.update(b"local\0");
            hash_length_prefixed(&mut hasher, path.as_bytes());
        }
        VaultSource::OneDriveItem { drive_id, item_id } => {
            hasher.update(b"onedrive\0");
            hash_length_prefixed(&mut hasher, drive_id.as_bytes());
            hash_length_prefixed(&mut hasher, item_id.as_bytes());
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn entry_fields_for_vault(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> Result<EntryFieldsDto> {
    let detail = core.project_entry_detail(vault, entry_id)?;
    let totp_uri = core
        .project_entry_totp(vault, entry_id)?
        .as_ref()
        .map(|totp| totp_to_uri(&detail.title, &detail.username, totp));
    let custom_fields = core
        .list_entry_custom_fields(vault, entry_id)?
        .into_iter()
        .map(|field| EntryCustomFieldDto {
            key: field.key,
            value: field.value,
            protected: field.protected,
        })
        .collect();
    Ok(EntryFieldsDto {
        title: detail.title,
        username: detail.username,
        password: detail.password,
        url: detail.url,
        notes: detail.notes,
        totp_uri,
        custom_fields,
    })
}

fn entry_fields_semantically_equal(left: &EntryFieldsDto, right: &EntryFieldsDto) -> bool {
    left.title == right.title
        && left.username == right.username
        && left.password == right.password
        && left.url == right.url
        && left.notes == right.notes
        && totp_fields_semantically_equal(
            &left.title,
            &left.username,
            left.totp_uri.as_deref(),
            &right.title,
            &right.username,
            right.totp_uri.as_deref(),
        )
        && custom_fields_semantically_equal(&left.custom_fields, &right.custom_fields)
}

fn count_live_entry_id(group: &vaultkern_core::Group, entry_id: &str) -> usize {
    group
        .entries
        .iter()
        .filter(|entry| entry.id.to_string() == entry_id)
        .count()
        + group
            .children
            .iter()
            .map(|child| count_live_entry_id(child, entry_id))
            .sum::<usize>()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializedAutofillTargetState {
    parent_id: Option<Uuid>,
    entry: Option<Entry>,
    recycled: bool,
    deleted_objects: Vec<vaultkern_core::DeletedObject>,
}

fn serialized_autofill_target_state(
    vault: &Vault,
    entry_id: &str,
) -> Result<SerializedAutofillTargetState> {
    let entry_id = Uuid::parse_str(entry_id).context("invalid autofill target entry ID")?;
    let located = locate_serialized_autofill_entry(
        &vault.root,
        entry_id,
        vault.recycle_bin_group,
        vault.recycle_bin_enabled.unwrap_or(true),
        false,
    );
    let mut deleted_objects = vault
        .deleted_objects
        .iter()
        .filter(|item| item.id == entry_id)
        .cloned()
        .collect::<Vec<_>>();
    deleted_objects.sort_by_key(|item| item.deleted_at);
    Ok(SerializedAutofillTargetState {
        parent_id: located.as_ref().map(|(parent_id, _, _)| *parent_id),
        entry: located.as_ref().map(|(_, entry, _)| entry.clone()),
        recycled: located.is_some_and(|(_, _, recycled)| recycled),
        deleted_objects,
    })
}

fn validate_unreceipted_pending_target_unchanged(
    plan_baseline: &Vault,
    observed_source: &Vault,
    remote: &Vault,
    binding: &PendingAutofillReceiptBinding,
) -> Result<()> {
    let plan_baseline_state = serialized_autofill_target_state(plan_baseline, &binding.entry_id)?;
    let observed_state = serialized_autofill_target_state(observed_source, &binding.entry_id)?;
    let remote_state = serialized_autofill_target_state(remote, &binding.entry_id)?;
    match binding.mode {
        PendingAutofillReceiptMode::Update => {
            if observed_state != remote_state {
                anyhow::bail!("pending autofill target changed without a bound receipt");
            }
        }
        PendingAutofillReceiptMode::Create => {
            let is_completely_absent = |state: &SerializedAutofillTargetState| {
                state.parent_id.is_none()
                    && state.entry.is_none()
                    && !state.recycled
                    && state.deleted_objects.is_empty()
            };
            if !is_completely_absent(&plan_baseline_state) || observed_state != remote_state {
                anyhow::bail!("pending autofill create target collided without a bound receipt");
            }
        }
    }
    Ok(())
}

fn locate_serialized_autofill_entry(
    group: &vaultkern_core::Group,
    entry_id: Uuid,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
) -> Option<(Uuid, Entry, bool)> {
    let recycled = ancestor_recycled
        || (recycle_bin_enabled && recycle_bin_group.is_some_and(|id| id == group.id));
    if let Some(entry) = group.entries.iter().find(|entry| entry.id == entry_id) {
        return Some((
            group.id,
            normalized_serialized_entry(entry.clone()),
            recycled,
        ));
    }
    group.children.iter().find_map(|child| {
        locate_serialized_autofill_entry(
            child,
            entry_id,
            recycle_bin_group,
            recycle_bin_enabled,
            recycled,
        )
    })
}

fn normalized_serialized_entry(mut entry: Entry) -> Entry {
    if let Some(totp) = &mut entry.totp {
        if totp.issuer.is_none() {
            totp.issuer = Some(entry.title.clone());
        }
        let account_name = totp
            .account_name
            .clone()
            .unwrap_or_else(|| entry.username.clone());
        totp.account_name = (!account_name.is_empty()).then_some(account_name);
    }
    if entry.icon_id == Some(0) {
        entry.icon_id = None;
    }
    if entry.auto_type.as_ref().is_some_and(|auto_type| {
        auto_type.enabled.is_none()
            && auto_type.obfuscation.is_none()
            && auto_type.default_sequence.is_none()
            && auto_type.associations.is_empty()
    }) {
        entry.auto_type = None;
    }
    entry.raw_state = Default::default();
    entry.opaque_xml.clear();
    entry.custom_data_blocks.clear();
    entry.history = entry
        .history
        .into_iter()
        .map(normalized_serialized_entry)
        .collect();
    entry
}

fn merge_summary_for_source_change(
    _baseline: &VaultSourceFingerprint,
    _current: &VaultSourceFingerprint,
) -> Option<MergeSummaryDto> {
    // The C1 merge engine preserves more than the legacy merge report can
    // represent. Do not fabricate counts; a later typed summary can expose
    // exact three-way decisions without changing durability semantics.
    None
}

fn three_way_patch_summary(report: &ThreeWayPatchReport) -> MergeSummaryDto {
    MergeSummaryDto {
        merged_entries: report.merged_entries,
        history_snapshots_added: report.history_snapshots_added,
        meta_conflicts_resolved: report.meta_conflicts_resolved,
        icon_conflicts_resolved: report.icon_conflicts_resolved,
    }
}

fn remote_source_status_after_commit(
    cache_key: &RemoteCacheKey,
    cached_at: i64,
    cache_error: Option<&anyhow::Error>,
) -> (AutofillCacheStateDto, VaultSourceStatusDto) {
    let cache_state = if cache_error.is_some() {
        AutofillCacheStateDto::WriteFailed
    } else {
        AutofillCacheStateDto::Current
    };
    (
        cache_state,
        VaultSourceStatusDto {
            source_kind: cache_key.provider_kind.clone(),
            remote_state: "online".into(),
            last_sync_at: Some(cached_at),
            cached_at: cache_error.is_none().then_some(cached_at),
            last_error: cache_error.map(format_error_chain),
        },
    )
}

fn same_content_fingerprint(left: &VaultSourceFingerprint, right: &VaultSourceFingerprint) -> bool {
    left.content_sha256 == right.content_sha256 && left.size_bytes == right.size_bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAutofillReceiptMode {
    Update,
    Create,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAutofillReceiptBinding {
    transaction_id: String,
    source_identity_sha256: String,
    plan_sha256: String,
    mode: PendingAutofillReceiptMode,
    entry_id: String,
}

fn pending_autofill_receipt_binding(
    vault: &Vault,
    operation_id: &str,
) -> Result<Option<PendingAutofillReceiptBinding>> {
    let Some(ledger) = vault.meta_custom_data.get(AUTOFILL_RECEIPT_KEY) else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(ledger).context("pending autofill receipt ledger is malformed")?;
    if value.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        anyhow::bail!("pending autofill receipt ledger version is invalid");
    }
    let receipts = value
        .get("receipts")
        .and_then(serde_json::Value::as_array)
        .context("pending autofill receipt ledger has no receipt array")?;
    let matching = receipts
        .iter()
        .filter(|receipt| {
            receipt
                .get("operationId")
                .and_then(serde_json::Value::as_str)
                == Some(operation_id)
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Ok(None);
    }
    if matching.len() != 1 {
        anyhow::bail!("pending autofill operation receipt is duplicated");
    }
    let receipt = matching[0];
    for field in [
        "transactionId",
        "sourceIdentitySha256",
        "planSha256",
        "entryId",
    ] {
        if receipt
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            anyhow::bail!("pending autofill receipt field {field} is invalid");
        }
    }
    let sha_is_valid = |field: &str| {
        receipt
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    };
    if !sha_is_valid("sourceIdentitySha256") || !sha_is_valid("planSha256") {
        anyhow::bail!("pending autofill receipt digest is invalid");
    }
    let entry_id = receipt["entryId"].as_str().expect("checked entry ID");
    if Uuid::parse_str(entry_id)
        .ok()
        .is_none_or(|parsed| parsed.to_string() != entry_id)
    {
        anyhow::bail!("pending autofill receipt entry ID is invalid");
    }
    if !matches!(
        receipt.get("mode").and_then(serde_json::Value::as_str),
        Some("update" | "create")
    ) || receipt
        .get("committedAtEpochMs")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        anyhow::bail!("pending autofill receipt mode or timestamp is invalid");
    }
    Ok(Some(PendingAutofillReceiptBinding {
        transaction_id: receipt["transactionId"]
            .as_str()
            .expect("checked transaction ID")
            .into(),
        source_identity_sha256: receipt["sourceIdentitySha256"]
            .as_str()
            .expect("checked source identity")
            .into(),
        plan_sha256: receipt["planSha256"]
            .as_str()
            .expect("checked plan digest")
            .into(),
        mode: match receipt["mode"].as_str().expect("checked receipt mode") {
            "update" => PendingAutofillReceiptMode::Update,
            "create" => PendingAutofillReceiptMode::Create,
            _ => unreachable!("checked receipt mode"),
        },
        entry_id: entry_id.into(),
    }))
}

fn required_pending_autofill_receipt_binding(
    vault: &Vault,
    operation_id: &str,
) -> Result<PendingAutofillReceiptBinding> {
    pending_autofill_receipt_binding(vault, operation_id)?
        .context("pending autofill operation receipt is missing")
}

fn remove_pending_autofill_operation_receipt(
    core: &KeepassCore,
    vault: &mut Vault,
    operation_id: &str,
) -> Result<()> {
    let ledger = vault
        .meta_custom_data
        .get(AUTOFILL_RECEIPT_KEY)
        .context("pending autofill generation has no receipt ledger")?;
    let mut value: serde_json::Value =
        serde_json::from_str(ledger).context("pending autofill receipt ledger is malformed")?;
    let receipts = value
        .get_mut("receipts")
        .and_then(serde_json::Value::as_array_mut)
        .context("pending autofill receipt ledger has no receipt array")?;
    let before = receipts.len();
    receipts.retain(|receipt| {
        receipt
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            != Some(operation_id)
    });
    if receipts.len() + 1 != before {
        anyhow::bail!("pending autofill operation receipt is missing or duplicated");
    }
    core.upsert_vault_custom_data(
        vault,
        CustomDataItemInput {
            key: AUTOFILL_RECEIPT_KEY.into(),
            value: serde_json::to_string(&value)
                .context("failed to rewrite pending autofill receipt ledger")?,
        },
    )
    .context("failed to reconcile the pending autofill receipt ledger")?;
    Ok(())
}

fn reconstruct_pending_autofill_plan(
    core: &KeepassCore,
    previous: &Vault,
    pending: &Vault,
    binding: &PendingAutofillReceiptBinding,
) -> Result<AutofillPersistPlanDto> {
    match binding.mode {
        PendingAutofillReceiptMode::Update => Ok(AutofillPersistPlanDto::Update {
            entry_id: binding.entry_id.clone(),
            expected_fields: entry_fields_for_vault(core, previous, &binding.entry_id)
                .context("pending update baseline entry is missing")?,
            desired_fields: entry_fields_for_vault(core, pending, &binding.entry_id)
                .context("pending update target entry is missing")?,
        }),
        PendingAutofillReceiptMode::Create => {
            let target_id = Uuid::parse_str(&binding.entry_id)
                .context("pending create target entry ID is invalid")?;
            let (parent_group_id, target, recycled) = locate_serialized_autofill_entry(
                &pending.root,
                target_id,
                pending.recycle_bin_group,
                pending.recycle_bin_enabled.unwrap_or(true),
                false,
            )
            .context("pending create target entry is missing")?;
            if recycled {
                anyhow::bail!("pending create target entry is recycled");
            }
            let mut expected_matching_entry_ids = Vec::new();
            collect_matching_model_entry_ids(
                &previous.root,
                &target,
                previous.recycle_bin_group,
                previous.recycle_bin_enabled.unwrap_or(true),
                false,
                &mut expected_matching_entry_ids,
            );
            expected_matching_entry_ids.sort();
            Ok(AutofillPersistPlanDto::Create {
                parent_group_id: parent_group_id.to_string(),
                planned_entry_id: binding.entry_id.clone(),
                expected_matching_entry_ids,
                desired_fields: entry_fields_for_vault(core, pending, &binding.entry_id)?,
            })
        }
    }
}

fn collect_matching_model_entry_ids(
    group: &vaultkern_core::Group,
    target: &Entry,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    matches: &mut Vec<String>,
) {
    let recycled = ancestor_recycled
        || (recycle_bin_enabled && recycle_bin_group.is_some_and(|id| id == group.id));
    if !recycled {
        matches.extend(
            group
                .entries
                .iter()
                .filter(|entry| {
                    entry.title == target.title
                        && entry.username == target.username
                        && entry.password == target.password
                        && entry.url == target.url
                        && entry.notes == target.notes
                        && totp_specs_semantically_equal(
                            &entry.title,
                            &entry.username,
                            entry.totp.as_ref(),
                            &target.title,
                            &target.username,
                            target.totp.as_ref(),
                        )
                        && entry.attributes == target.attributes
                })
                .map(|entry| entry.id.to_string()),
        );
    }
    for child in &group.children {
        collect_matching_model_entry_ids(
            child,
            target,
            recycle_bin_group,
            recycle_bin_enabled,
            recycled,
            matches,
        );
    }
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
        private_key_pem: passkey.private_key_pem,
        relying_party: passkey.relying_party,
        user_handle: passkey.user_handle,
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    }
}

fn platform_passkey_credential(passkey: &PasskeyRecord) -> Result<PlatformPasskeyCredential> {
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
        relying_party_name: passkey.relying_party.clone(),
        user_handle,
        user_name: passkey.username.clone(),
        user_display_name: passkey.username.clone(),
    })
}

fn dto_to_passkey_record(passkey: EntryPasskeyDto) -> Result<PasskeyRecord> {
    validate_passkey_credential_id(&passkey.credential_id)?;
    if let Some(user_handle) = &passkey.user_handle {
        validate_passkey_user_handle(user_handle)?;
    }

    Ok(PasskeyRecord {
        username: passkey.username,
        credential_id: passkey.credential_id,
        generated_user_id: passkey.generated_user_id,
        private_key_pem: passkey.private_key_pem,
        relying_party: passkey.relying_party,
        user_handle: passkey.user_handle,
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    })
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
    visit_passkeys_in_group(
        group,
        recycle_bin_group,
        recycle_bin_enabled,
        false,
        visitor,
    );
}

fn visit_passkeys_in_group<'a>(
    group: &'a vaultkern_core::Group,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    visitor: &mut impl FnMut(&'a PasskeyRecord),
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
            visitor(passkey);
        }
    }

    for child in &group.children {
        visit_passkeys_in_group(
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
    transformed_key: &TransformedKey,
    mut save_profile: SaveProfile,
) -> std::result::Result<Vec<u8>, KdbxError> {
    if required_version(vault) == KdbxVersion::V4_1 {
        save_profile.version = KdbxVersion::V4_1;
    }

    let has_history_limits = vault.history_max_items.is_some() || vault.history_max_size.is_some();
    let mut history_snapshots =
        has_history_limits.then(|| clone_entry_histories(&vault.root).into_iter());
    if has_history_limits {
        enforce_history_limits(vault);
    }
    let result = save_kdbx_with_transformed_key(vault, transformed_key, &save_profile);
    if let Some(history_snapshots) = &mut history_snapshots {
        restore_entry_histories(&mut vault.root, history_snapshots);
    }
    let bytes = result?;
    let header = vaultkern_core::KdbxHeader::decode(&bytes)?;
    vault.kdf_parameters = Some(header.kdf_parameters.encode()?);
    Ok(bytes)
}

fn clone_entry_histories(group: &vaultkern_core::Group) -> Vec<Vec<Entry>> {
    let mut snapshots = Vec::new();
    collect_entry_histories(group, &mut snapshots);
    snapshots
}

fn collect_entry_histories(group: &vaultkern_core::Group, snapshots: &mut Vec<Vec<Entry>>) {
    for entry in &group.entries {
        snapshots.push(entry.history.clone());
    }

    for child in &group.children {
        collect_entry_histories(child, snapshots);
    }
}

fn restore_entry_histories(
    group: &mut vaultkern_core::Group,
    snapshots: &mut std::vec::IntoIter<Vec<Entry>>,
) {
    for entry in &mut group.entries {
        if let Some(history) = snapshots.next() {
            entry.history = history;
        }
    }

    for child in &mut group.children {
        restore_entry_histories(child, snapshots);
    }
}

fn enforce_history_limits(vault: &mut Vault) {
    if let Some(max_items) = vault
        .history_max_items
        .and_then(|value| usize::try_from(value).ok())
    {
        enforce_history_item_limit(&mut vault.root, max_items);
    }

    if let Some(max_size) = vault
        .history_max_size
        .and_then(|value| usize::try_from(value).ok())
    {
        enforce_history_size_limit(vault, max_size);
    }
}

fn enforce_history_item_limit(group: &mut vaultkern_core::Group, max_items: usize) {
    for entry in &mut group.entries {
        while entry.history.len() > max_items {
            entry.history.remove(0);
        }
    }

    for child in &mut group.children {
        enforce_history_item_limit(child, max_items);
    }
}

fn enforce_history_size_limit(vault: &mut Vault, max_size: usize) {
    while total_history_size(&vault.root) > max_size {
        if !remove_oldest_history_item(&mut vault.root) {
            break;
        }
    }
}

fn total_history_size(group: &vaultkern_core::Group) -> usize {
    let entry_size = group
        .entries
        .iter()
        .flat_map(|entry| entry.history.iter())
        .map(estimated_entry_size)
        .sum::<usize>();
    let child_size = group.children.iter().map(total_history_size).sum::<usize>();
    entry_size + child_size
}

fn remove_oldest_history_item(group: &mut vaultkern_core::Group) -> bool {
    let Some(path) = oldest_history_path(group) else {
        return false;
    };
    remove_history_item_at_path(group, &path)
}

fn oldest_history_path(group: &vaultkern_core::Group) -> Option<Vec<usize>> {
    let mut oldest: Option<(u64, Vec<usize>)> = None;
    collect_oldest_history_path(group, &mut Vec::new(), &mut oldest);
    oldest.map(|(_, path)| path)
}

fn collect_oldest_history_path(
    group: &vaultkern_core::Group,
    group_path: &mut Vec<usize>,
    oldest: &mut Option<(u64, Vec<usize>)>,
) {
    for (entry_index, entry) in group.entries.iter().enumerate() {
        if let Some(history) = entry.history.first() {
            let mut path = group_path.clone();
            path.push(entry_index);
            let modified_at = history.modified_at;
            if oldest
                .as_ref()
                .map(|(oldest_modified_at, _)| modified_at < *oldest_modified_at)
                .unwrap_or(true)
            {
                *oldest = Some((modified_at, path));
            }
        }
    }

    for (child_index, child) in group.children.iter().enumerate() {
        group_path.push(child_index);
        collect_oldest_history_path(child, group_path, oldest);
        group_path.pop();
    }
}

fn remove_history_item_at_path(group: &mut vaultkern_core::Group, path: &[usize]) -> bool {
    if path.len() == 1 {
        return group
            .entries
            .get_mut(path[0])
            .and_then(|entry| {
                if entry.history.is_empty() {
                    None
                } else {
                    Some(entry.history.remove(0))
                }
            })
            .is_some();
    }

    let Some((child_index, rest)) = path.split_first() else {
        return false;
    };
    group
        .children
        .get_mut(*child_index)
        .map(|child| remove_history_item_at_path(child, rest))
        .unwrap_or(false)
}

fn estimated_entry_size(entry: &vaultkern_core::Entry) -> usize {
    entry.title.len()
        + entry.username.len()
        + entry.password.len()
        + entry.url.len()
        + entry.notes.len()
        + entry
            .attributes
            .iter()
            .map(|(key, field)| key.len() + field.value.len())
            .sum::<usize>()
        + entry
            .attachments
            .iter()
            .map(|(name, attachment)| name.len() + attachment.data.len())
            .sum::<usize>()
}

fn database_settings_dto(
    vault: &Vault,
    profile: &SaveProfile,
    autosave_delay_seconds: Option<u32>,
    has_password: bool,
) -> DatabaseSettingsDto {
    DatabaseSettingsDto {
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
        encryption: encryption_settings_dto(vault, profile),
        autosave_delay_seconds,
        has_password,
    }
}

fn encryption_settings_dto(vault: &Vault, profile: &SaveProfile) -> DatabaseEncryptionSettingsDto {
    let kdf = profile
        .kdf
        .clone()
        .or_else(|| retained_or_recommended_save_kdf(vault).ok())
        .unwrap_or_else(SaveKdf::recommended);
    DatabaseEncryptionSettingsDto {
        compression: match profile.compression {
            Compression::None => "none",
            Compression::Gzip => "gzip",
        }
        .into(),
        cipher: match profile.cipher {
            KdbxCipher::Aes256 => "aes256",
            KdbxCipher::ChaCha20 => "chacha20",
            KdbxCipher::Twofish => "twofish",
        }
        .into(),
        kdf: match kdf {
            SaveKdf::AesKdbx4 { rounds } => DatabaseKdfSettingsDto {
                algorithm: "aes_kdbx4".into(),
                transform_rounds: Some(rounds),
                iterations: None,
                memory_kib: None,
                parallelism: None,
            },
            SaveKdf::Argon2d {
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
            SaveKdf::Argon2id {
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
    }
}

fn save_profile_from_settings(settings: DatabaseEncryptionSettingsDto) -> Result<SaveProfile> {
    let compression = match settings.compression.as_str() {
        "none" => Compression::None,
        "gzip" => Compression::Gzip,
        value => anyhow::bail!("unsupported compression setting: {value}"),
    };
    let cipher = match settings.cipher.as_str() {
        "aes256" => KdbxCipher::Aes256,
        "chacha20" => KdbxCipher::ChaCha20,
        "twofish" => KdbxCipher::Twofish,
        value => anyhow::bail!("unsupported cipher setting: {value}"),
    };
    let kdf = match settings.kdf.algorithm.as_str() {
        "aes_kdbx4" => SaveKdf::AesKdbx4 {
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
                SaveKdf::Argon2d {
                    iterations,
                    memory_kib,
                    parallelism,
                }
            } else {
                SaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                }
            }
        }
        value => anyhow::bail!("unsupported kdf setting: {value}"),
    };

    Ok(SaveProfile {
        version: vaultkern_core::KdbxVersion::V4_1,
        cipher,
        compression,
        kdf: Some(kdf),
    })
}

fn public_string(vault: &Vault, key: &str) -> Option<String> {
    vault
        .public_custom_data
        .get(key)
        .map(|value| String::from_utf8_lossy(value).into_owned())
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

fn fingerprint_for_cached_bytes(bytes: &[u8], cached_at: i64) -> VaultSourceFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    VaultSourceFingerprint {
        content_sha256,
        size_bytes: bytes.len() as u64,
        modified_at: u64::try_from(cached_at).ok(),
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
        StoredVaultSource::LocalPath(path) => path.clone(),
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

fn remote_cache_key_for_stored_source(source: &StoredVaultSource) -> Option<RemoteCacheKey> {
    match source {
        StoredVaultSource::LocalPath(_) => None,
        StoredVaultSource::OneDriveItem {
            drive_id, item_id, ..
        } => Some(RemoteCacheKey::new(
            "onedrive",
            &onedrive_remote_id(drive_id, item_id),
        )),
    }
}

fn display_name_for_cloud_name(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_owned()
}

fn onedrive_conflict_copy_name(display_name: &str, timestamp: u64) -> String {
    let stem = Path::new(display_name)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("vault");
    format!("{stem} (VaultKern conflict {timestamp}).kdbx")
}

fn transformed_key_from_loaded_vault(loaded: &LoadedVault) -> Result<Arc<TransformedKey>> {
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
            let bytes = fs::read(key_file_path)
                .with_context(|| format!("failed to read key file: {key_file_path}"))?;
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

fn error_chain_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == kind)
    })
}

fn ensure_primary_passkey_save(response: &RuntimeResponse) -> Result<()> {
    let RuntimeResponse::SaveVaultResult(result) = response else {
        anyhow::bail!("passkey mutation received an unexpected save response: {response:?}");
    };
    if result.status == SaveVaultStatusDto::ConflictCopy {
        return Err(LocalFileCommitError::Conflict {
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

fn classified_runtime_error_response(error: &anyhow::Error) -> Option<RuntimeResponse> {
    let code = match error.downcast_ref::<LocalFileCommitError>() {
        Some(LocalFileCommitError::Conflict { .. }) => "conflict",
        Some(LocalFileCommitError::BeforePublish { .. }) => "persist_io_unavailable",
        Some(LocalFileCommitError::OutcomeUnknown { .. }) => "persist_outcome_unknown",
        None if error.is::<PendingAutofillSyncRequired>() => "pending_autofill_sync_required",
        None => return None,
    };
    Some(RuntimeResponse::Error(ErrorDto {
        code: code.into(),
        message: format_error_chain(error),
    }))
}

fn query_error_response(error: anyhow::Error) -> RuntimeResponse {
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

fn parse_totp_uri(value: Option<String>) -> Result<Option<TotpSpec>> {
    match value {
        Some(uri) if !uri.trim().is_empty() => TotpSpec::parse_otpauth(&uri)
            .map(Some)
            .with_context(|| format!("invalid otpauth uri: {uri}")),
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
    use vaultkern_core::CompositeKey;
    use vaultkern_runtime_protocol::{
        AutofillCacheStateDto, AutofillPersistDispositionDto, AutofillPersistDurabilityDto,
        AutofillPersistOutcomeDto, AutofillPersistPlanDto, AutofillPersistResultDto,
        DatabaseCredentialsUpdateDto,
    };

    #[test]
    fn external_open_uses_desktop_unconfirmed_kdf_policy() {
        assert_eq!(
            Runtime::external_open_kdf_policy(),
            (
                vaultkern_core::ExternalKdfPolicy::Desktop,
                vaultkern_core::ExternalKdfConfirmation::Unconfirmed,
            )
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
        let transformed = derive_transformed_key_with_policy(
            &original,
            &key,
            &ExternalKdfPolicy::Desktop,
            ExternalKdfConfirmation::Unconfirmed,
        )
        .expect("derive session key");
        let mut vault =
            load_kdbx_with_transformed_key(&original, &transformed).expect("load initial vault");
        let mut entry = Entry::new("excluded");
        entry.exclude_from_reports = true;
        vault.root.entries.push(entry);

        let bytes = save_kdbx_with_history_limits_transformed(
            &mut vault,
            &transformed,
            SaveProfile {
                kdf: None,
                ..profile
            },
        )
        .expect("runtime save should promote the file version");
        let header = vaultkern_core::inspect_kdbx_header(&bytes).expect("inspect saved header");
        let loaded =
            load_kdbx_with_transformed_key(&bytes, &transformed).expect("reload promoted vault");

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
        let transformed = derive_transformed_key_with_policy(
            &original,
            &key,
            &ExternalKdfPolicy::Desktop,
            ExternalKdfConfirmation::Unconfirmed,
        )
        .unwrap();
        let mut vault = load_kdbx_with_transformed_key(&original, &transformed).unwrap();
        vault.description = Some("edited without retaining the password".into());

        let saved = save_kdbx_with_history_limits_transformed(
            &mut vault,
            &transformed,
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::Aes256,
                compression: Compression::None,
                kdf: None,
            },
        )
        .unwrap();
        let reloaded = load_kdbx_with_transformed_key(&saved, &transformed).unwrap();
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
    fn runtime_reuses_kdf_for_ordinary_saves_and_requires_reauth_for_rotation() {
        fn retained_kdf(runtime: &Runtime, vault_id: &str) -> Vec<u8> {
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

        let mut runtime = Runtime::for_tests();
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
            .save_vault(&opened.vault_id)
            .expect("compression-only save");
        assert_eq!(
            retained_kdf(&runtime, &opened.vault_id),
            original_generation
        );
    }

    #[test]
    fn database_settings_updates_advance_three_way_merge_timestamps() {
        let mut runtime = Runtime::for_tests_at(200);
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
        remote.name = "Earlier remote name".into();
        remote.database_name_changed = Some(100);
        let merged = three_way_field_patch(&base, &local, &remote).unwrap();
        assert_eq!(merged.vault.name, "Local name");
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
        let mut runtime = Runtime::for_tests();
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

        runtime.save_vault(&opened.vault_id).expect("ordinary save");
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
        let mut runtime = Runtime::for_tests();
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

        fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
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

        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.values.borrow().get(key).cloned())
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

        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.values.borrow().get(key).cloned())
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
        authorizations: std::rc::Rc<std::cell::Cell<usize>>,
        stores: std::rc::Rc<std::cell::Cell<usize>>,
        values: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl EarlyAuthorizingSecureStorageProvider {
        fn new(
            authorizations: std::rc::Rc<std::cell::Cell<usize>>,
            stores: std::rc::Rc<std::cell::Cell<usize>>,
        ) -> Self {
            Self {
                authorizations,
                stores,
                values: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl SecureStorageProvider for EarlyAuthorizingSecureStorageProvider {
        fn authorize_store_user_presence(&self) -> Result<()> {
            self.authorizations
                .set(self.authorizations.get().saturating_add(1));
            Ok(())
        }

        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.stores.set(self.stores.get().saturating_add(1));
            self.values
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.values.borrow().get(key).cloned())
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
        parent_window: std::rc::Rc<std::cell::Cell<Option<usize>>>,
    }

    impl SecureStorageProvider for ParentWindowRecordingSecureStorageProvider {
        fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
            self.parent_window.set(parent_window);
        }

        fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
            Ok(())
        }

        fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn contains(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }

        fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn history_snapshot_restore_preserves_duplicate_entry_histories_by_position() {
        let duplicate_id = Uuid::new_v4();
        let mut group = vaultkern_core::Group::new("Root");

        let mut first = Entry::new("First");
        first.id = duplicate_id;
        first.history.push(Entry::new("First old"));
        let mut second = Entry::new("Second");
        second.id = duplicate_id;
        second.history.push(Entry::new("Second old"));
        group.entries.push(first);
        group.entries.push(second);

        let mut snapshots = clone_entry_histories(&group).into_iter();
        group.entries[0].history.clear();
        group.entries[1].history.clear();

        restore_entry_histories(&mut group, &mut snapshots);

        assert_eq!(group.entries[0].history[0].title, "First old");
        assert_eq!(group.entries[1].history[0].title, "Second old");
    }

    #[derive(Default)]
    struct CountingBiometricProvider {
        authorizations: std::rc::Rc<RefCell<Vec<String>>>,
    }

    impl BiometricProvider for CountingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, reason: &str) -> Result<()> {
            self.authorizations.borrow_mut().push(reason.to_owned());
            Ok(())
        }
    }

    struct RecordingBiometricProvider {
        authorized_at_epoch_ms: std::rc::Rc<RefCell<Option<u64>>>,
    }

    impl BiometricProvider for RecordingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, _reason: &str) -> Result<()> {
            std::thread::sleep(std::time::Duration::from_millis(25));
            *self.authorized_at_epoch_ms.borrow_mut() = Some(current_unix_time_ms());
            Ok(())
        }
    }

    fn open_unlocked_demo_vault(runtime: &mut Runtime) -> (tempfile::TempDir, VaultHandleDto) {
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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let loaded = runtime.vault_session.find_loaded(&opened.vault_id).unwrap();

        assert!(loaded.bytes.is_empty());
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
    fn quick_unlock_refreshes_the_single_blob_after_a_source_salt_change() {
        let mut runtime = Runtime::for_tests_with_quick_unlock();
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
        runtime: &mut Runtime,
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
        runtime.local_files =
            LocalFileVaultSourceProvider::with_before_write_hook(std::sync::Arc::new(move || {
                std::fs::write(&path, &replacement).unwrap()
            }));
        generation_b
    }

    fn arm_source_deletion_after_merge_snapshot(runtime: &mut Runtime, opened: &VaultHandleDto) {
        let path = opened.path.clone();
        runtime.local_files =
            LocalFileVaultSourceProvider::with_before_write_hook(std::sync::Arc::new(move || {
                std::fs::remove_file(&path).unwrap()
            }));
    }

    fn arm_local_write_fault(runtime: &mut Runtime, point: DurableFaultPoint) {
        runtime.local_files =
            LocalFileVaultSourceProvider::with_write_faults(DurableFaultInjector::fail_once(point));
    }

    #[test]
    fn save_after_source_change_during_commit_writes_a_conflict_copy() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let generation_b = arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .save_vault(&opened.vault_id)
            .expect("source change after the merge snapshot must be recoverable");

        let RuntimeResponse::SaveVaultResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
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
        let mut runtime = Runtime::for_tests();
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
            .save_vault(&opened.vault_id)
            .expect("source change should take the recoverable conflict path");

        let RuntimeResponse::SaveVaultResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
        assert_eq!(std::fs::read(&opened.path).unwrap(), external);
        let conflict_path = result.conflict_copy_path.expect("conflict-copy path");
        assert_eq!(
            Path::new(&conflict_path).parent(),
            Path::new(&opened.path).parent()
        );
        let conflict_bytes = std::fs::read(conflict_path).unwrap();
        let conflict_vault = KeepassCore::new().load_kdbx(&conflict_bytes, &key).unwrap();
        assert_eq!(conflict_vault.root.entries.len(), 1);
    }

    #[test]
    fn save_after_source_deletion_writes_a_recoverable_conflict_copy() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        std::fs::remove_file(&opened.path).unwrap();

        let response = runtime
            .save_vault(&opened.vault_id)
            .expect("missing source should take the recoverable conflict path");

        let RuntimeResponse::SaveVaultResult(result) = response else {
            panic!("expected save result");
        };
        assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
        assert!(!Path::new(&opened.path).exists());
        let conflict_path = result.conflict_copy_path.expect("conflict-copy path");
        let conflict_bytes = std::fs::read(conflict_path).unwrap();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let conflict_vault = KeepassCore::new().load_kdbx(&conflict_bytes, &key).unwrap();
        assert_eq!(conflict_vault.root.entries.len(), 1);
    }

    #[test]
    fn local_write_returns_the_commit_fingerprint() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let expected = runtime
            .local_files
            .read_snapshot(&opened.path)
            .unwrap()
            .fingerprint;

        let committed = runtime
            .write_local_source(&opened.vault_id, b"candidate-generation", &expected)
            .unwrap();
        let visible = runtime.local_files.read_snapshot(&opened.path).unwrap();

        assert_eq!(committed, visible.fingerprint);
        assert_eq!(visible.bytes, b"candidate-generation");
    }

    #[test]
    fn save_command_reports_source_change_as_a_conflict_copy() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let generation_b = arm_source_change_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: opened.vault_id.clone(),
            })
            .expect("source conflicts must be command responses");

        let RuntimeResponse::SaveVaultResult(result) = response else {
            panic!("expected conflict-copy response, got {response:?}");
        };
        assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_source_deletion_after_merge_snapshot(&mut runtime, &opened);

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: opened.vault_id.clone(),
            })
            .expect("source deletion must be a command response");

        let RuntimeResponse::SaveVaultResult(result) = response else {
            panic!("expected conflict-copy response, got {response:?}");
        };
        assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::BeforeTargetReplace);

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
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
    fn save_command_reconciles_a_visible_post_publish_generation() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::TargetReplaced);

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: opened.vault_id.clone(),
            })
            .expect("a visible published generation should be reconciled");

        assert!(matches!(
            response,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
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
    fn successful_save_records_durable_cleanup_warnings() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::Cleanup);

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: opened.vault_id.clone(),
            })
            .expect("cleanup failure does not invalidate a durable save");

        assert!(matches!(
            response,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
                ..
            })
        ));
        assert_eq!(runtime.local_save_warnings.len(), 1);
        assert!(runtime.local_save_warnings[0].contains("retained durable backup"));
    }

    #[test]
    fn committed_local_save_survives_synced_base_write_failure() {
        let mut runtime = Runtime::for_tests();
        let (dir, opened) = open_unlocked_demo_vault(&mut runtime);
        create_demo_entry(&mut runtime, &opened.vault_id);
        let blocked_root = dir.path().join("blocked-synced-base-root");
        std::fs::write(&blocked_root, b"not a directory").unwrap();
        runtime.synced_bases = SyncedBaseStore::new_at(blocked_root.join("bases"));

        let response = runtime
            .save_vault(&opened.vault_id)
            .expect("the primary KDBX commit already succeeded");

        assert!(matches!(
            response,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
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
            runtime.save_vault(&opened.vault_id).unwrap(),
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
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
    fn committed_onedrive_save_survives_synced_base_write_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_100);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        create_demo_entry(&mut runtime, &vault_id);
        runtime.synced_bases.fail_next_store_for_tests();

        let response = runtime
            .save_vault(&vault_id)
            .expect("the remote KDBX commit already succeeded");

        assert!(matches!(
            response,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
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
            runtime.save_vault(&vault_id).unwrap(),
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
                ..
            })
        ));
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
            .save_vault(&vault_id)
            .expect("the rotated remote head should be adopted despite a base-cache failure");
        assert!(matches!(
            adopted,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Merged,
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
            runtime.save_vault(&vault_id).unwrap(),
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
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
        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests();
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

    fn open_unlocked_demo_onedrive(runtime: &mut Runtime) -> String {
        runtime
            .add_onedrive_vault_reference("drive-1", "item-1")
            .unwrap();
        runtime
            .unlock_current_vault_with_password("demo-password")
            .unwrap();
        "onedrive:drive-1:item-1".into()
    }

    fn demo_onedrive_runtime(unix_time: u64) -> Runtime {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        Runtime::for_tests_at_with_onedrive_item(
            unix_time,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            bytes,
        )
    }

    fn create_demo_entry(runtime: &mut Runtime, vault_id: &str) -> EntryDetailDto {
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

    #[test]
    fn platform_plugin_registration_persists_a_kpex_entry_and_asserts_after_reopen() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
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
        let mut reopened = Runtime::for_tests();
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
    fn platform_credential_sync_skips_non_discoverable_kpex_entries() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_handle: b"platform-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        let non_discoverable = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime
            .set_entry_passkey(
                &opened.vault_id,
                &non_discoverable.id,
                EntryPasskeyDto {
                    username: "legacy@example.net".into(),
                    credential_id: URL_SAFE_NO_PAD.encode(b"legacy-credential"),
                    generated_user_id: None,
                    private_key_pem: "legacy-private-key".into(),
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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
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
            private_key_pem: "malformed fixture key".into(),
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
    fn platform_plugin_registration_rolls_back_memory_when_durable_save_fails() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::BeforeTargetReplace);

        let error = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_handle: b"platform-user-2".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect_err("pre-publish save failure must fail registration");

        assert!(error.to_string().contains("failed to write vault"));
        assert!(runtime.list_entries(&opened.vault_id).unwrap().is_empty());
    }

    #[test]
    fn platform_plugin_registration_reconciles_a_visible_post_publish_generation() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        arm_local_write_fault(&mut runtime, DurableFaultPoint::TargetReplaced);

        let registration = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_handle: b"platform-user-ambiguous".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .expect("the visible published credential should complete registration");

        drop(runtime);
        let mut reopened = Runtime::for_tests();
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
        let transformed_key = derive_transformed_key_with_policy(
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
        let mut remote = load_kdbx_with_transformed_key(&base_bytes, &transformed_key).unwrap();
        core.set_entry_passkey(&mut remote, &entry_id, remote_passkey)
            .unwrap();
        remote.root.entries[0].modified_at = 300;
        let remote_bytes = save_kdbx_with_history_limits_transformed(
            &mut remote,
            &transformed_key,
            SaveProfile {
                kdf: None,
                ..SaveProfile::recommended()
            },
        )
        .unwrap();

        let local_credential_id = b"local-credential".to_vec();
        let generated_id = URL_SAFE_NO_PAD.encode(&local_credential_id);
        let mut runtime = Runtime::for_tests_at_with_onedrive_item(
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
            user_name: "alice@example.com".into(),
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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let mut foreign_generation = std::fs::read(&opened.vault_id).unwrap();
        foreign_generation.push(0);
        std::fs::write(&opened.vault_id, foreign_generation).unwrap();

        let error = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
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
        let locked = Runtime::for_tests();
        let error = locked
            .list_platform_passkey_credentials()
            .expect_err("no active unlocked vault must fail closed");
        assert!(error.to_string().contains("active unlocked vault"));

        let mut runtime = Runtime::for_tests();
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);
        let first = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_handle: b"user-a".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            })
            .unwrap();
        let second = runtime
            .register_platform_passkey(PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                user_name: "bob@example.com".into(),
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
        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests_at(creation_time);
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
        let mut runtime = Runtime::for_tests();
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
                    String::new(),
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
        let mut runtime = Runtime::for_tests();
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

    fn upsert_test_vault_custom_data(
        core: &KeepassCore,
        vault: &mut Vault,
        key: &str,
        value: &str,
    ) {
        core.upsert_vault_custom_data(
            vault,
            CustomDataItemInput {
                key: key.into(),
                value: value.into(),
            },
        )
        .unwrap();
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

    fn begin_pending_update(
        runtime: &mut Runtime,
        transaction_id: &str,
        operation_id: &str,
        desired_password: &str,
        remote_was_committed: bool,
    ) -> (String, EntryDetailDto, EntryDetailDto, EntryFieldsDto) {
        let vault_id = open_unlocked_demo_onedrive(runtime);
        let target = create_demo_entry(runtime, &vault_id);
        let unrelated = create_demo_entry(runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&target);
        let desired_fields = EntryFieldsDto {
            password: desired_password.into(),
            ..expected_fields.clone()
        };
        runtime.queue_test_onedrive_ambiguous_write(remote_was_committed);

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: transaction_id.into(),
                operation_id: operation_id.into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        (vault_id, target, unrelated, desired_fields)
    }

    fn begin_pending_after_observed_target_change(
        runtime: &mut Runtime,
        transaction_id: &str,
        operation_id: &str,
    ) -> (
        String,
        EntryDetailDto,
        EntryDetailDto,
        EntryFieldsDto,
        String,
    ) {
        let vault_id = open_unlocked_demo_onedrive(runtime);
        let target = create_demo_entry(runtime, &vault_id);
        let unrelated = create_demo_entry(runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&target);
        let desired_fields = EntryFieldsDto {
            password: "pending-after-observed-target-change".into(),
            ..expected_fields.clone()
        };
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut observed_vault = core.load_database(&remote, &key).unwrap().vault;
        let root_id = observed_vault.root.id.to_string();
        let observed_parent = core
            .add_group(&mut observed_vault, &root_id, "Observed before PUT")
            .unwrap();
        core.move_entry(&mut observed_vault, &target.id, &observed_parent.id)
            .unwrap();
        core.update_entry_presentation_metadata(
            &mut observed_vault,
            &target.id,
            vaultkern_core::EntryPresentationMetadataUpdate {
                icon_id: Some(Some(42)),
                ..Default::default()
            },
        )
        .unwrap();
        let observed_bytes = core
            .save_kdbx(&observed_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", observed_bytes);
        runtime.queue_test_onedrive_ambiguous_write(false);
        let pending = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: transaction_id.into(),
                operation_id: operation_id.into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();
        assert!(matches!(
            pending,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        (
            vault_id,
            target,
            unrelated,
            desired_fields,
            observed_parent.id,
        )
    }

    fn assert_pending_sync_rejected_without_put(
        runtime: &mut Runtime,
        vault_id: &str,
        expected_remote: &[u8],
        expected_error_fragment: &str,
    ) {
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(vault_id).unwrap();

        assert_eq!(status.remote_state, "pending_sync");
        assert!(
            status
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error_fragment)),
            "unexpected pending sync error: {:?}",
            status.last_error
        );
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            expected_remote
        );
        assert!(
            runtime
                .remote_cache
                .read_pending_chain(&RemoteCacheKey::new("onedrive", "drive-1:item-1"))
                .is_ok()
        );
    }

    fn assert_pending_sync_merges_live_edit(remote_was_committed: bool) {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(if remote_was_committed {
            1_700_000_056
        } else {
            1_700_000_057
        });
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let transaction_id = if remote_was_committed {
            "transaction-live-edit-committed"
        } else {
            "transaction-live-edit-uncommitted"
        };
        let operation_id = if remote_was_committed {
            "operation-live-edit-committed"
        } else {
            "operation-live-edit-uncommitted"
        };
        let (vault_id, target, unrelated, desired_fields) = begin_pending_update(
            &mut runtime,
            transaction_id,
            operation_id,
            "pending-live-edit-secret",
            remote_was_committed,
        );
        let unrelated_fields = EntryFieldsDto {
            notes: "edited after the ambiguous write".into(),
            ..entry_fields(&unrelated)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                unrelated_fields.title.clone(),
                unrelated_fields.username.clone(),
                unrelated_fields.password.clone(),
                unrelated_fields.url.clone(),
                unrelated_fields.notes.clone(),
                unrelated_fields.totp_uri.clone(),
                unrelated_fields.custom_fields.clone(),
            )
            .unwrap();
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
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
            entry_fields_for_vault(&runtime.core, &durable, &target.id).unwrap(),
            desired_fields
        );
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &durable, &unrelated.id).unwrap(),
            unrelated_fields
        );
        let live = runtime.loaded_vault(&vault_id).unwrap();
        assert_eq!(
            entry_fields_for_vault(&runtime.core, live, &unrelated.id).unwrap(),
            unrelated_fields
        );
    }

    fn insert_test_create_passkey_ceremony(
        runtime: &mut Runtime,
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
    fn compare_and_update_rejects_stale_fields_before_history_or_mutation() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let mut expected = entry_fields(&entry);
        expected.notes = "stale snapshot".into();
        let mut desired = entry_fields(&entry);
        desired.password = "new-secret".into();

        let response = runtime
            .handle(RuntimeCommand::CompareAndUpdateEntryFields {
                vault_id: opened.vault_id.clone(),
                entry_id: entry.id.clone(),
                expected_fields: expected,
                desired_fields: desired,
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected conflict response, got {response:?}");
        };
        assert_eq!(error.code, "conflict");
        assert_eq!(
            runtime
                .get_entry_detail(&opened.vault_id, &entry.id)
                .unwrap(),
            entry
        );
        assert!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn atomic_autofill_conflict_retryability_is_derived_from_the_conflict_code() {
        let cases = [
            (AutofillPersistConflictCodeDto::ActiveVaultMismatch, true),
            (
                AutofillPersistConflictCodeDto::UpdatePreconditionFailed,
                false,
            ),
            (
                AutofillPersistConflictCodeDto::CreateMatchingSetChanged,
                false,
            ),
            (
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision,
                false,
            ),
            (
                AutofillPersistConflictCodeDto::OperationBindingMismatch,
                false,
            ),
            (
                AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
                false,
            ),
            (
                AutofillPersistConflictCodeDto::SourceChangedRetryExhausted,
                true,
            ),
            (
                AutofillPersistConflictCodeDto::LegacyCreateOutcomeAmbiguous,
                false,
            ),
        ];

        for (code, expected_retryable) in cases {
            let response = autofill_persist_conflict(
                "transaction-conflict-map",
                "operation-conflict-map",
                "vault-conflict-map",
                code,
            );
            let RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome:
                    AutofillPersistOutcomeDto::Conflict {
                        code: actual_code,
                        retryable,
                    },
                ..
            }) = response
            else {
                panic!("expected conflict response for {code:?}");
            };
            assert_eq!(actual_code, code);
            assert_eq!(retryable, expected_retryable, "conflict code {code:?}");
        }
    }

    #[test]
    fn compare_and_update_succeeds_once_and_preserves_unwritten_entry_state() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let created = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime
            .set_entry_passkey(
                &opened.vault_id,
                &created.id,
                EntryPasskeyDto {
                    username: "alice@example.com".into(),
                    credential_id: "Y3JlZC0x".into(),
                    generated_user_id: Some("generated-user".into()),
                    private_key_pem: "pem".into(),
                    relying_party: "example.com".into(),
                    user_handle: Some("dXNlci0x".into()),
                    backup_eligible: true,
                    backup_state: true,
                },
            )
            .unwrap();
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            runtime
                .core
                .update_entry_field_protection(
                    loaded.vault.as_mut().unwrap(),
                    &created.id,
                    vaultkern_core::EntryFieldProtectionUpdate {
                        protect_title: Some(true),
                        protect_username: Some(true),
                        protect_password: Some(false),
                        protect_url: Some(true),
                        protect_notes: Some(true),
                    },
                )
                .unwrap();
        }
        let before = runtime
            .add_entry_attachment(
                &opened.vault_id,
                &created.id,
                "proof.txt".into(),
                "cHJvb2Y=".into(),
                true,
            )
            .unwrap();
        let history_before = runtime
            .list_entry_history(&opened.vault_id, &created.id)
            .unwrap()
            .items
            .len();
        assert!(before.passkey.is_some());
        assert!(before.field_protection.protect_title);
        assert!(before.field_protection.protect_username);
        assert!(!before.field_protection.protect_password);
        assert!(before.field_protection.protect_url);
        assert!(before.field_protection.protect_notes);
        let expected = entry_fields(&before);
        let desired = EntryFieldsDto {
            password: "new-secret".into(),
            notes: "updated".into(),
            ..expected.clone()
        };

        let first = runtime
            .handle(RuntimeCommand::CompareAndUpdateEntryFields {
                vault_id: opened.vault_id.clone(),
                entry_id: created.id.clone(),
                expected_fields: expected.clone(),
                desired_fields: desired.clone(),
            })
            .unwrap();
        let RuntimeResponse::EntryDetail(updated) = first else {
            panic!("expected update, got {first:?}");
        };
        assert!(entry_detail_matches_fields(&updated, &desired));
        assert_eq!(updated.passkey, before.passkey);
        assert_eq!(updated.attachments, before.attachments);
        assert_eq!(updated.field_protection, before.field_protection);
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &created.id)
                .unwrap()
                .items
                .len(),
            history_before + 1
        );

        let second = runtime
            .handle(RuntimeCommand::CompareAndUpdateEntryFields {
                vault_id: opened.vault_id.clone(),
                entry_id: created.id.clone(),
                expected_fields: expected,
                desired_fields: desired,
            })
            .unwrap();
        let RuntimeResponse::Error(error) = second else {
            panic!("expected replay conflict, got {second:?}");
        };
        assert_eq!(error.code, "conflict");
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &created.id)
                .unwrap()
                .items
                .len(),
            history_before + 1
        );
    }

    #[test]
    fn compare_and_update_no_op_is_idempotent_without_history() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let fields = entry_fields(&entry);

        for _ in 0..2 {
            let response = runtime
                .handle(RuntimeCommand::CompareAndUpdateEntryFields {
                    vault_id: opened.vault_id.clone(),
                    entry_id: entry.id.clone(),
                    expected_fields: fields.clone(),
                    desired_fields: fields.clone(),
                })
                .unwrap();
            assert!(matches!(response, RuntimeResponse::EntryDetail(_)));
        }
        assert!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn pending_create_reconstruction_matches_semantic_totp_spellings() {
        let mut previous = Vault::empty("Autofill");
        let mut existing = Entry::new("Example");
        existing.username = "alice".into();
        existing.password = "secret".into();
        existing.url = "https://example.com/login".into();
        existing.totp = Some(
            TotpSpec::parse_otpauth("otpauth://totp/Example%3Aalice?secret=JBSWY3DPEHPK3PXP")
                .unwrap(),
        );
        let existing_id = existing.id.to_string();
        previous.root.entries.push(existing);
        let mut target = previous.root.entries[0].clone();
        let target_totp = target.totp.as_mut().unwrap();
        target_totp.issuer = Some("Example".into());
        target_totp.account_name = Some("alice".into());
        let mut matching_ids = Vec::new();

        collect_matching_model_entry_ids(
            &previous.root,
            &target,
            previous.recycle_bin_group,
            previous.recycle_bin_enabled.unwrap_or(true),
            false,
            &mut matching_ids,
        );

        assert_eq!(matching_ids, [existing_id]);
    }

    #[test]
    fn conditional_update_requires_the_command_time_active_vault() {
        let mut runtime = Runtime::for_tests();
        let (_first_dir, first) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &first.vault_id);
        let fields = entry_fields(&entry);
        runtime.save_vault(&first.vault_id).unwrap();
        let (_second_dir, second) = open_unlocked_demo_vault(&mut runtime);
        assert_eq!(
            runtime.vault_session.active_vault_id(),
            Some(second.vault_id.as_str())
        );

        let update = runtime
            .handle(RuntimeCommand::CompareAndUpdateEntryFields {
                vault_id: first.vault_id.clone(),
                entry_id: entry.id.clone(),
                expected_fields: fields.clone(),
                desired_fields: EntryFieldsDto {
                    password: "new-secret".into(),
                    ..fields.clone()
                },
            })
            .unwrap();
        let RuntimeResponse::Error(error) = update else {
            panic!("expected active-vault conflict, got {update:?}");
        };
        assert_eq!(error.code, "conflict");
        runtime.open_local_vault(&first.path).unwrap();
        runtime
            .unlock_with_password(&first.vault_id, "demo-password")
            .unwrap();
        assert_eq!(
            runtime
                .get_entry_detail(&first.vault_id, &entry.id)
                .unwrap(),
            entry
        );
    }

    #[test]
    fn atomic_autofill_update_commits_once_and_replays_without_rewriting() {
        let mut runtime = Runtime::for_tests_at(1_700_000_000);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let fields = entry_fields(&entry);
        runtime.save_vault(&opened.vault_id).unwrap();
        let desired_fields = EntryFieldsDto {
            password: "durable-secret".into(),
            ..fields.clone()
        };
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-update-1".into(),
            operation_id: "operation-update-1".into(),
            vault_id: opened.vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: entry.id.clone(),
                expected_fields: fields,
                desired_fields: desired_fields.clone(),
            },
        };

        let committed = runtime.handle(command.clone()).unwrap();
        let RuntimeResponse::AutofillPersistResult(committed) = committed else {
            panic!("expected durable autofill result, got {committed:?}");
        };
        assert!(matches!(
            committed.outcome,
            AutofillPersistOutcomeDto::Durable {
                disposition: AutofillPersistDispositionDto::Committed,
                durability: AutofillPersistDurabilityDto::Source,
                cache_state: AutofillCacheStateDto::NotApplicable,
                receipt_version: 1,
                ..
            }
        ));
        assert_eq!(
            entry_fields(
                &runtime
                    .get_entry_detail(&opened.vault_id, &entry.id)
                    .unwrap()
            ),
            desired_fields
        );
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );
        let committed_bytes = std::fs::read(&opened.path).unwrap();

        let replayed = runtime.handle(command.clone()).unwrap();
        let RuntimeResponse::AutofillPersistResult(replayed) = replayed else {
            panic!("expected replay result, got {replayed:?}");
        };
        assert!(matches!(
            replayed.outcome,
            AutofillPersistOutcomeDto::Durable {
                disposition: AutofillPersistDispositionDto::Replayed,
                ..
            }
        ));
        assert_eq!(std::fs::read(&opened.path).unwrap(), committed_bytes);
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );

        let mut restarted = Runtime::for_tests_at(1_700_000_001);
        let reopened = restarted.open_local_vault(&opened.path).unwrap();
        restarted
            .unlock_vault(&reopened.vault_id, Some("demo-password"), None)
            .unwrap();
        let replayed_after_restart = restarted.handle(command.clone()).unwrap();
        assert!(matches!(
            replayed_after_restart,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ..
                },
                ..
            })
        ));
        assert_eq!(std::fs::read(&opened.path).unwrap(), committed_bytes);
        assert_eq!(
            restarted
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );

        let mut encryption = restarted
            .get_database_settings(&opened.vault_id)
            .unwrap()
            .encryption;
        encryption.compression = "none".into();
        restarted
            .update_database_settings(
                &opened.vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(encryption),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        let replayed_with_profile_change = restarted.handle(command).unwrap();
        assert!(matches!(
            replayed_with_profile_change,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ..
                },
                ..
            })
        ));
        let changed_profile = std::fs::read(&opened.path).unwrap();
        assert_eq!(
            vaultkern_core::KdbxHeader::decode(&changed_profile)
                .unwrap()
                .compression,
            Compression::None
        );
    }

    #[test]
    fn atomic_autofill_local_refreshes_quick_unlock_after_external_kdf_rotation() {
        let mut runtime = Runtime::for_tests_at(1_700_000_000);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        runtime
            .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let expected_fields = entry_fields(&entry);

        let core = KeepassCore::new();
        let mut master_key = CompositeKey::default();
        master_key.add_password("demo-password");
        let source = std::fs::read(&opened.path).unwrap();
        let source_vault = core.load_database(&source, &master_key).unwrap().vault;
        let rotated = core
            .save_kdbx(
                &source_vault,
                &master_key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::ChaCha20,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
                },
            )
            .unwrap();
        std::fs::write(&opened.path, rotated).unwrap();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-local-kdf-rotation".into(),
                operation_id: "operation-local-kdf-rotation".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "after-local-kdf-rotation".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    durability: AutofillPersistDurabilityDto::Source,
                    ..
                },
                ..
            })
        ));
        let durable = std::fs::read(&opened.path).unwrap();
        let durable_header = vaultkern_core::KdbxHeader::decode(&durable).unwrap();
        assert_eq!(durable_header.cipher, KdbxCipher::ChaCha20);
        assert_eq!(durable_header.compression, Compression::None);
        runtime.lock_session();
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        assert!(runtime.session_state().unlocked);
    }

    #[test]
    fn atomic_autofill_update_verifies_after_history_limit_pruning() {
        let mut runtime = Runtime::for_tests_at(1_700_000_000);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        let fields = entry_fields(&entry);
        {
            let loaded = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            KeepassCore::new()
                .snapshot_entry_to_history(vault, &entry.id)
                .unwrap();
            vault.history_max_items = Some(1);
        }
        runtime.save_vault(&opened.vault_id).unwrap();

        let desired_fields = EntryFieldsDto {
            password: "durable-secret".into(),
            ..fields.clone()
        };
        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-history-limit".into(),
                operation_id: "operation-history-limit".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            entry_fields(
                &runtime
                    .get_entry_detail(&opened.vault_id, &entry.id)
                    .unwrap()
            ),
            desired_fields
        );
        assert_eq!(
            runtime
                .list_entry_history(&opened.vault_id, &entry.id)
                .unwrap()
                .items
                .len(),
            1
        );
    }

    #[test]
    fn lowering_history_limit_prunes_live_state_without_later_resurrection() {
        let mut runtime = Runtime::for_tests_at(1_700_000_000);
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
        runtime.save_vault(&opened.vault_id).unwrap();

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
        runtime.save_vault(&opened.vault_id).unwrap();

        let mut restarted = Runtime::for_tests_at(1_700_000_001);
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
    fn atomic_autofill_create_uses_one_planned_id_across_a_fresh_runtime_replay() {
        let mut runtime = Runtime::for_tests_at(1_700_000_010);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let parent_group_id = runtime.list_groups(&opened.vault_id).unwrap().root.id;
        let planned_entry_id = "12345678-1234-4abc-8def-1234567890ab";
        let desired_fields = EntryFieldsDto {
            title: "Created by autofill".into(),
            username: "alice".into(),
            password: "new-secret".into(),
            url: "https://example.com/login".into(),
            notes: String::new(),
            totp_uri: None,
            custom_fields: vec![],
        };
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-create-1".into(),
            operation_id: "operation-create-1".into(),
            vault_id: opened.vault_id.clone(),
            plan: AutofillPersistPlanDto::Create {
                parent_group_id,
                planned_entry_id: planned_entry_id.into(),
                expected_matching_entry_ids: vec![],
                desired_fields: desired_fields.clone(),
            },
        };

        let committed = runtime.handle(command.clone()).unwrap();
        assert!(matches!(
            committed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    ref entry_id,
                    ..
                },
                ..
            }) if entry_id == planned_entry_id
        ));
        assert_eq!(runtime.list_entries(&opened.vault_id).unwrap().len(), 1);
        assert_eq!(
            entry_fields(
                &runtime
                    .get_entry_detail(&opened.vault_id, planned_entry_id)
                    .unwrap()
            ),
            desired_fields
        );
        let committed_bytes = std::fs::read(&opened.path).unwrap();

        let mut restarted = Runtime::for_tests_at(1_700_000_011);
        let reopened = restarted.open_local_vault(&opened.path).unwrap();
        restarted
            .unlock_vault(&reopened.vault_id, Some("demo-password"), None)
            .unwrap();
        let replayed = restarted.handle(command).unwrap();
        assert!(matches!(
            replayed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ref entry_id,
                    ..
                },
                ..
            }) if entry_id == planned_entry_id
        ));
        assert_eq!(restarted.list_entries(&opened.vault_id).unwrap().len(), 1);
        assert_eq!(std::fs::read(&opened.path).unwrap(), committed_bytes);
    }

    #[test]
    fn atomic_autofill_validation_returns_before_source_io() {
        let mut runtime = Runtime::for_tests();
        let (_first_dir, first) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &first.vault_id);
        runtime.save_vault(&first.vault_id).unwrap();
        let fields = entry_fields(&entry);
        let (_second_dir, second) = open_unlocked_demo_vault(&mut runtime);
        assert_eq!(
            runtime.vault_session.active_vault_id(),
            Some(second.vault_id.as_str())
        );
        std::fs::remove_file(&first.path).unwrap();

        let mismatch = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-mismatch".into(),
                operation_id: "operation-mismatch".into(),
                vault_id: first.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-run".into(),
                        ..fields.clone()
                    },
                },
            })
            .unwrap();
        assert!(matches!(
            mismatch,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Conflict {
                    code: AutofillPersistConflictCodeDto::ActiveVaultMismatch,
                    retryable: true,
                },
                ..
            })
        ));
        let encoded = serde_json::to_value(&mismatch).unwrap();
        assert_eq!(encoded["retryable"], true);
        assert_eq!(
            serde_json::from_value::<RuntimeResponse>(encoded).unwrap(),
            mismatch
        );

        runtime.lock_session();
        std::fs::remove_file(&second.path).unwrap();
        let locked = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-locked".into(),
                operation_id: "operation-locked".into(),
                vault_id: second.vault_id,
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id,
                    expected_fields: fields.clone(),
                    desired_fields: fields,
                },
            })
            .unwrap();
        let RuntimeResponse::Error(error) = locked else {
            panic!("expected stable locked error, got {locked:?}");
        };
        assert_eq!(error.code, "vault_locked");
    }

    #[test]
    fn corrupt_current_source_does_not_swap_the_live_autofill_candidate() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let fields = entry_fields(&entry);
        let corrupt_bytes = b"not a KDBX generation".to_vec();
        std::fs::write(&opened.path, &corrupt_bytes).unwrap();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-corrupt".into(),
                operation_id: "operation-corrupt".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap".into(),
                        ..fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected corrupt source error, got {response:?}");
        };
        assert_eq!(error.code, "source_corrupt");
        assert_eq!(
            runtime
                .get_entry_detail(&opened.vault_id, &entry.id)
                .unwrap(),
            entry
        );
        assert_eq!(std::fs::read(&opened.path).unwrap(), corrupt_bytes);
    }

    #[test]
    fn local_sink_rejection_does_not_mutate_live_or_durable_vault_state() {
        let mut runtime = Runtime::for_tests();
        let (dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let fields = entry_fields(&entry);
        let source_before = std::fs::read(&opened.path).unwrap();
        let alias = dir.path().join("personal-alias.kdbx");
        std::fs::hard_link(&opened.path, &alias).unwrap();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-sink-failure".into(),
                operation_id: "operation-sink-failure".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap".into(),
                        ..fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected sink error, got {response:?}");
        };
        assert_eq!(error.code, "persist_io_unavailable");
        assert_eq!(
            runtime
                .get_entry_detail(&opened.vault_id, &entry.id)
                .unwrap(),
            entry
        );
        assert_eq!(std::fs::read(&opened.path).unwrap(), source_before);
        assert_eq!(std::fs::read(alias).unwrap(), source_before);
    }

    #[test]
    fn atomic_autofill_three_way_merge_preserves_external_delete_move_and_metadata() {
        let mut runtime = Runtime::for_tests_at(1_700_000_020);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let target = create_demo_entry(&mut runtime, &opened.vault_id);
        let deleted = create_demo_entry(&mut runtime, &opened.vault_id);
        let moved = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let expected_fields = entry_fields(&target);
        let desired_fields = EntryFieldsDto {
            password: "merged-secret".into(),
            ..expected_fields.clone()
        };

        let mut external = Runtime::for_tests_at(1_700_000_021);
        let external_opened = external.open_local_vault(&opened.path).unwrap();
        external
            .unlock_vault(&external_opened.vault_id, Some("demo-password"), None)
            .unwrap();
        let external_group_id = {
            let core = &external.core;
            let loaded = external
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap();
            let vault = loaded.vault.as_mut().unwrap();
            let root_id = vault.root.id.to_string();
            let group = core.add_group(vault, &root_id, "Externally moved").unwrap();
            core.move_entry(vault, &moved.id, &group.id).unwrap();
            core.delete_entry(vault, &deleted.id).unwrap();
            upsert_test_vault_custom_data(core, vault, "external-meta", "preserved");
            group.id
        };
        external.save_vault(&opened.vault_id).unwrap();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-external-merge".into(),
                operation_id: "operation-external-merge".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();
        assert!(
            matches!(
                &response,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        disposition: AutofillPersistDispositionDto::Committed,
                        ..
                    },
                    ..
                })
            ),
            "unexpected persist response: {response:?}"
        );

        let committed = runtime.loaded_vault(&opened.vault_id).unwrap();
        assert_eq!(
            committed
                .meta_custom_data
                .get("external-meta")
                .map(String::as_str),
            Some("preserved")
        );
        assert!(
            runtime
                .core
                .find_entry_view_by_id(committed, &deleted.id)
                .is_none()
        );
        assert!(
            runtime
                .core
                .find_group_view_by_id(committed, &external_group_id)
                .unwrap()
                .entries
                .iter()
                .any(|entry| entry.id == moved.id)
        );
        assert_eq!(
            entry_fields(
                &runtime
                    .get_entry_detail(&opened.vault_id, &target.id)
                    .unwrap()
            ),
            desired_fields
        );

        let mut reopened = Runtime::for_tests();
        let disk = reopened.open_local_vault(&opened.path).unwrap();
        reopened
            .unlock_vault(&disk.vault_id, Some("demo-password"), None)
            .unwrap();
        let durable = reopened.loaded_vault(&opened.vault_id).unwrap();
        assert_eq!(
            durable
                .meta_custom_data
                .get("external-meta")
                .map(String::as_str),
            Some("preserved")
        );
        assert!(
            reopened
                .core
                .find_entry_view_by_id(durable, &deleted.id)
                .is_none()
        );
        assert!(
            reopened
                .core
                .find_group_view_by_id(durable, &external_group_id)
                .unwrap()
                .entries
                .iter()
                .any(|entry| entry.id == moved.id)
        );
    }

    #[test]
    fn replay_publish_preserves_a_post_receipt_target_delete() {
        let mut runtime = Runtime::for_tests_at(1_700_000_025);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-delete-replay".into(),
            operation_id: "operation-delete-replay".into(),
            vault_id: opened.vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: entry.id.clone(),
                expected_fields: expected_fields.clone(),
                desired_fields: EntryFieldsDto {
                    password: "committed-secret".into(),
                    ..expected_fields
                },
            },
        };
        let committed = runtime.handle(command.clone()).unwrap();
        assert!(
            matches!(committed, RuntimeResponse::AutofillPersistResult(_)),
            "unexpected initial persist response: {committed:?}"
        );
        {
            let core = &runtime.core;
            let vault = runtime
                .vault_session
                .find_loaded_mut(&opened.vault_id)
                .unwrap()
                .vault
                .as_mut()
                .unwrap();
            upsert_test_vault_custom_data(core, vault, "local-after-receipt", "preserved");
        }

        let mut external = Runtime::for_tests_at(1_700_000_026);
        let external_opened = external.open_local_vault(&opened.path).unwrap();
        external
            .unlock_vault(&external_opened.vault_id, Some("demo-password"), None)
            .unwrap();
        external.delete_entry(&opened.vault_id, &entry.id).unwrap();
        external.save_vault(&opened.vault_id).unwrap();

        let replayed = runtime.handle(command.clone()).unwrap();

        assert!(matches!(
            replayed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ..
                },
                ..
            })
        ));
        let committed = runtime.loaded_vault(&opened.vault_id).unwrap();
        assert!(
            runtime
                .core
                .find_entry_view_by_id(committed, &entry.id)
                .is_none()
        );
        assert_eq!(
            committed
                .meta_custom_data
                .get("local-after-receipt")
                .map(String::as_str),
            Some("preserved")
        );
    }

    #[test]
    fn runtime_maps_three_way_engine_conflicts_without_swapping_live_state() {
        let mut runtime = Runtime::for_tests_at(1_700_000_027);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let target = create_demo_entry(&mut runtime, &opened.vault_id);
        let other = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let target_expected = entry_fields(&target);
        runtime
            .update_entry_fields(
                &opened.vault_id,
                &other.id,
                other.title.clone(),
                other.username.clone(),
                "local-divergence".into(),
                other.url.clone(),
                other.notes.clone(),
                other.totp_uri.clone(),
                other.custom_fields.clone(),
            )
            .unwrap();
        let local_other = runtime
            .get_entry_detail(&opened.vault_id, &other.id)
            .unwrap();

        let mut external = Runtime::for_tests_at(1_700_000_028);
        let external_opened = external.open_local_vault(&opened.path).unwrap();
        external
            .unlock_vault(&external_opened.vault_id, Some("demo-password"), None)
            .unwrap();
        external
            .update_entry_fields(
                &opened.vault_id,
                &other.id,
                other.title.clone(),
                other.username.clone(),
                "external-divergence".into(),
                other.url.clone(),
                other.notes.clone(),
                other.totp_uri.clone(),
                other.custom_fields.clone(),
            )
            .unwrap();
        external.save_vault(&opened.vault_id).unwrap();
        let durable_before = std::fs::read(&opened.path).unwrap();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-merge-conflict".into(),
                operation_id: "operation-merge-conflict".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields: target_expected.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-apply".into(),
                        ..target_expected
                    },
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Conflict {
                    code: AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
                    retryable: false,
                },
                ..
            })
        ));
        assert_eq!(
            runtime
                .get_entry_detail(&opened.vault_id, &target.id)
                .unwrap(),
            target
        );
        assert_eq!(
            runtime
                .get_entry_detail(&opened.vault_id, &other.id)
                .unwrap(),
            local_other
        );
        assert_eq!(std::fs::read(&opened.path).unwrap(), durable_before);
    }

    #[test]
    fn atomic_autofill_onedrive_update_commits_and_replays_without_a_second_put() {
        let mut runtime = demo_onedrive_runtime(1_700_000_030);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let desired_fields = EntryFieldsDto {
            password: "remote-secret".into(),
            ..expected_fields.clone()
        };
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-remote".into(),
            operation_id: "operation-remote".into(),
            vault_id: vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: entry.id.clone(),
                expected_fields,
                desired_fields: desired_fields.clone(),
            },
        };

        let committed = runtime.handle(command.clone()).unwrap();
        assert!(matches!(
            committed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    durability: AutofillPersistDurabilityDto::Source,
                    cache_state: AutofillCacheStateDto::Current,
                    ..
                },
                ..
            })
        ));
        let remote_after_commit = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );

        let replayed = runtime.handle(command.clone()).unwrap();
        assert!(matches!(
            replayed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    durability: AutofillPersistDurabilityDto::Source,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_after_commit
        );

        let mut encryption = runtime.get_database_settings(&vault_id).unwrap().encryption;
        encryption.compression = "none".into();
        runtime
            .update_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(encryption),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        runtime.reset_test_onedrive_access_counts();
        let replayed_with_profile_change = runtime.handle(command).unwrap();
        assert!(matches!(
            replayed_with_profile_change,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ..
                },
                ..
            })
        ));
        assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
        let changed_profile = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        assert_eq!(
            vaultkern_core::KdbxHeader::decode(&changed_profile)
                .unwrap()
                .compression,
            Compression::None
        );
    }

    #[test]
    fn atomic_autofill_onedrive_refreshes_quick_unlock_after_remote_kdf_rotation() {
        let mut runtime = demo_onedrive_runtime(1_700_000_030);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        runtime
            .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let expected_fields = entry_fields(&entry);

        let core = KeepassCore::new();
        let mut master_key = CompositeKey::default();
        master_key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let remote_vault = core.load_database(&remote, &master_key).unwrap().vault;
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

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-remote-kdf-rotation".into(),
                operation_id: "operation-remote-kdf-rotation".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "after-kdf-rotation".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    durability: AutofillPersistDurabilityDto::Source,
                    ..
                },
                ..
            })
        ));
        let durable = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let durable_header = vaultkern_core::KdbxHeader::decode(&durable).unwrap();
        assert_eq!(durable_header.cipher, KdbxCipher::ChaCha20);
        assert_eq!(durable_header.compression, Compression::None);
        let durable_vault = core.load_database(&durable, &master_key).unwrap().vault;
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &durable_vault, &entry.id)
                .unwrap()
                .password,
            "after-kdf-rotation"
        );
        runtime.lock_session();
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        assert!(runtime.session_state().unlocked);
    }

    #[test]
    fn atomic_autofill_onedrive_rereads_after_a_typed_precondition_failure() {
        let mut runtime = demo_onedrive_runtime(1_700_000_031);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        runtime.queue_test_onedrive_precondition_failure(None);
        runtime.reset_test_onedrive_access_counts();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-remote-412".into(),
                operation_id: "operation-remote-412".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id,
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "after-retry".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    ..
                },
                ..
            })
        ));
        let counts = runtime.test_onedrive_access_counts();
        assert_eq!(counts.remote_state_reads, 2);
        assert_eq!(counts.snapshot_from_state_reads, 2);
    }

    #[test]
    fn atomic_autofill_onedrive_reports_retryable_conflict_only_after_three_cas_losses() {
        let mut runtime = demo_onedrive_runtime(1_700_000_031);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        for _ in 0..3 {
            runtime.queue_test_onedrive_precondition_failure(None);
        }
        runtime.reset_test_onedrive_access_counts();

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-remote-exhausted".into(),
                operation_id: "operation-remote-exhausted".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Conflict {
                    code: AutofillPersistConflictCodeDto::SourceChangedRetryExhausted,
                    retryable: true,
                },
                ..
            })
        ));
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 3);
        assert_eq!(
            runtime.get_entry_detail(&vault_id, &entry.id).unwrap(),
            entry
        );
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
    }

    #[test]
    fn atomic_autofill_onedrive_source_success_survives_cache_mirror_failure() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_032);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let desired_fields = EntryFieldsDto {
            password: "source-is-durable".into(),
            ..expected_fields.clone()
        };
        runtime.remote_cache = RemoteVaultCache::new_at_with_faults(
            cache_dir.path(),
            crate::providers::durable_file::DurableFaultInjector::fail_once(
                crate::providers::durable_file::DurableFaultPoint::ManifestTempCreated,
            ),
        );

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-cache-warning".into(),
                operation_id: "operation-cache-warning".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::Source,
                    cache_state: AutofillCacheStateDto::WriteFailed,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let transformed = transformed_key_from_loaded_vault(
            runtime.vault_session.find_loaded(&vault_id).unwrap(),
        )
        .unwrap();
        let loaded_remote = load_kdbx_with_transformed_key(&remote, &transformed).unwrap();
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &loaded_remote, &entry.id).unwrap(),
            desired_fields
        );
    }

    #[test]
    fn atomic_autofill_onedrive_ambiguous_write_requires_a_durable_pending_cache() {
        let mut runtime = demo_onedrive_runtime(1_700_000_033);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let desired_fields = EntryFieldsDto {
            password: "pending-secret".into(),
            ..expected_fields.clone()
        };
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-pending".into(),
            operation_id: "operation-pending".into(),
            vault_id: vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: entry.id.clone(),
                expected_fields,
                desired_fields: desired_fields.clone(),
            },
        };

        let response = runtime.handle(command.clone()).unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    cache_state: AutofillCacheStateDto::PendingSync,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );
        assert_eq!(
            runtime.current_source_status().unwrap().remote_state,
            "pending_sync"
        );
        runtime.reset_test_onedrive_access_counts();
        let replayed = runtime.handle(command).unwrap();
        assert!(matches!(
            replayed,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    cache_state: AutofillCacheStateDto::PendingSync,
                    ..
                },
                ..
            })
        ));
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
    }

    #[test]
    fn atomic_autofill_onedrive_ambiguous_write_and_cache_failure_returns_unknown_without_swap() {
        let mut runtime = demo_onedrive_runtime(1_700_000_034);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let bad_cache_dir = tempfile::tempdir().unwrap();
        let bad_cache_path = bad_cache_dir.path().join("not-a-directory");
        std::fs::write(&bad_cache_path, b"file").unwrap();
        runtime.remote_cache = RemoteVaultCache::new_at(&bad_cache_path);
        runtime.queue_test_onedrive_ambiguous_write(false);

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-unknown".into(),
                operation_id: "operation-unknown".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected unknown outcome error, got {response:?}");
        };
        assert_eq!(error.code, "persist_io_unavailable");
        assert_eq!(
            runtime.get_entry_detail(&vault_id, &entry.id).unwrap(),
            entry
        );
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
    }

    #[test]
    fn generic_onedrive_ambiguous_write_and_cache_failure_rolls_back_runtime_state() {
        let mut runtime = demo_onedrive_runtime(1_700_000_034);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
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
            DurableFaultInjector::fail_once(DurableFaultPoint::ManifestTempCreated),
        );
        runtime.queue_test_onedrive_ambiguous_write(false);

        runtime
            .save_vault(&vault_id)
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
    fn atomic_autofill_ambiguous_write_rejects_missing_previous_cache_without_swap() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_035);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        runtime.remote_cache.delete(&cache_key).unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-missing-previous-cache".into(),
                operation_id: "operation-missing-previous-cache".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap-missing-cache".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected unknown persistence outcome, got {response:?}");
        };
        assert_eq!(error.code, "persist_outcome_unknown");
        assert!(error.message.contains("authenticated previous generation"));
        assert_eq!(
            runtime.get_entry_detail(&vault_id, &entry.id).unwrap(),
            entry
        );
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert!(matches!(
            runtime.remote_cache.read_pending_chain(&cache_key),
            Err(PendingRemoteCacheChainError::Missing)
        ));
    }

    #[test]
    fn atomic_autofill_ambiguous_write_rejects_corrupt_previous_cache_without_swap() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_036);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let paths = runtime.remote_cache.paths_for_tests(&cache_key);
        let manifest_before = std::fs::read(&paths.metadata_path).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_before).unwrap();
        let generation_path = paths
            .metadata_path
            .parent()
            .unwrap()
            .join(manifest["generation"].as_str().unwrap());
        std::fs::write(generation_path, b"tampered").unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-corrupt-previous-cache".into(),
                operation_id: "operation-corrupt-previous-cache".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap-corrupt-cache".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected unknown persistence outcome, got {response:?}");
        };
        assert_eq!(error.code, "persist_io_unavailable");
        assert!(
            error
                .message
                .contains("synchronized before autofill persistence")
        );
        assert_eq!(
            runtime.get_entry_detail(&vault_id, &entry.id).unwrap(),
            entry
        );
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(std::fs::read(paths.metadata_path).unwrap(), manifest_before);
        assert!(matches!(
            runtime.remote_cache.read_pending_chain(&cache_key),
            Err(PendingRemoteCacheChainError::DegradedCurrent)
                | Err(PendingRemoteCacheChainError::Corrupt { .. })
        ));
    }

    #[test]
    fn atomic_autofill_ambiguous_write_rejects_a_changed_cache_plan_baseline() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_037);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let mut competing_cache_vault = runtime
            .core
            .load_database(&remote_before, &key)
            .unwrap()
            .vault;
        upsert_test_vault_custom_data(
            &runtime.core,
            &mut competing_cache_vault,
            "competing-cache-writer",
            "must-not-be-plan-baseline",
        );
        let competing_cache_bytes = runtime
            .core
            .save_kdbx(&competing_cache_vault, &key, SaveProfile::recommended())
            .unwrap();
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let cached_at = runtime.current_unix_time() as i64;
        runtime
            .remote_cache
            .write(
                &cache_key,
                RemoteVaultCacheEntry {
                    fingerprint: fingerprint_for_cached_bytes(&competing_cache_bytes, cached_at),
                    bytes: competing_cache_bytes,
                    display_name: "Vault".into(),
                    account_label: "alice@example.com".into(),
                    cached_at,
                    pending_sync: false,
                },
            )
            .unwrap();
        let manifest_path = runtime
            .remote_cache
            .paths_for_tests(&cache_key)
            .metadata_path;
        let manifest_before = std::fs::read(&manifest_path).unwrap();
        runtime.queue_test_onedrive_ambiguous_write(false);

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-cache-baseline-race".into(),
                operation_id: "operation-cache-baseline-race".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "must-not-swap-cache-race".into(),
                        ..expected_fields
                    },
                },
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected cache baseline race rejection, got {response:?}");
        };
        assert_eq!(error.code, "persist_outcome_unknown");
        assert!(error.message.contains("plan baseline"));
        assert_eq!(
            runtime.get_entry_detail(&vault_id, &entry.id).unwrap(),
            entry
        );
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(std::fs::read(manifest_path).unwrap(), manifest_before);
    }

    #[test]
    fn atomic_autofill_roundtrip_canonicalizes_xml_unsafe_custom_field_protection() {
        let mut runtime = Runtime::for_tests_at(1_700_000_038);
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);
        runtime.save_vault(&opened.vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let desired_fields = EntryFieldsDto {
            custom_fields: vec![EntryCustomFieldDto {
                key: "XmlUnsafe".into(),
                value: "value\0after".into(),
                protected: false,
            }],
            ..expected_fields.clone()
        };

        let response = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-xml-unsafe-field".into(),
                operation_id: "operation-xml-unsafe-field".into(),
                vault_id: opened.vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields,
                    desired_fields,
                },
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Committed,
                    ..
                },
                ..
            })
        ));
        let detail = runtime
            .get_entry_detail(&opened.vault_id, &entry.id)
            .unwrap();
        assert_eq!(
            detail.custom_fields,
            vec![EntryCustomFieldDto {
                key: "XmlUnsafe".into(),
                value: "value\0after".into(),
                protected: true,
            }]
        );
        let mut reopened = Runtime::for_tests();
        let handle = reopened.open_local_vault(&opened.path).unwrap();
        reopened
            .unlock_vault(&handle.vault_id, Some("demo-password"), None)
            .unwrap();
        assert_eq!(
            reopened
                .get_entry_detail(&handle.vault_id, &entry.id)
                .unwrap()
                .custom_fields,
            detail.custom_fields
        );
    }

    #[test]
    fn exact_matching_uses_effective_xml_custom_field_protection() {
        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests();
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
    fn pending_autofill_sync_distinguishes_ambiguous_remote_commit_after_restart() {
        for remote_was_committed in [true, false] {
            let cache_dir = tempfile::tempdir().unwrap();
            let core = KeepassCore::new();
            let mut key = CompositeKey::default();
            key.add_password("demo-password");
            let initial_bytes = core
                .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
                .unwrap();
            let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
                1_700_000_040,
                "drive-1",
                "item-1",
                "Vault.kdbx",
                "alice@example.com",
                initial_bytes,
                cache_dir.path(),
            );
            let vault_id = open_unlocked_demo_onedrive(&mut first);
            let entry = create_demo_entry(&mut first, &vault_id);
            first.save_vault(&vault_id).unwrap();
            let expected_fields = entry_fields(&entry);
            let desired_fields = EntryFieldsDto {
                password: "restart-pending-secret".into(),
                ..expected_fields.clone()
            };
            let command = RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-restart-pending".into(),
                operation_id: "operation-restart-pending".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            };
            first.queue_test_onedrive_ambiguous_write(remote_was_committed);
            let response = first.handle(command.clone()).unwrap();
            assert!(matches!(
                response,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                        ..
                    },
                    ..
                })
            ));
            let ambiguous_remote = first
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap();
            let ambiguous_remote_revision = first
                .test_onedrive_item_revision("drive-1", "item-1")
                .unwrap();

            let mut restarted = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
                1_700_000_041,
                "drive-1",
                "item-1",
                "Vault.kdbx",
                "alice@example.com",
                ambiguous_remote,
                cache_dir.path(),
            );
            restarted
                .set_test_onedrive_item_revision("drive-1", "item-1", ambiguous_remote_revision)
                .unwrap();
            let restarted_vault_id = open_unlocked_demo_onedrive(&mut restarted);
            assert_eq!(
                restarted.current_source_status().unwrap().remote_state,
                "pending_sync"
            );
            restarted.reset_test_onedrive_access_counts();
            let replayed = restarted.handle(command).unwrap();
            assert!(matches!(
                replayed,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        disposition: AutofillPersistDispositionDto::Replayed,
                        durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                        ..
                    },
                    ..
                })
            ));
            assert_eq!(
                restarted.test_onedrive_access_counts().remote_state_reads,
                0
            );
            assert_eq!(
                restarted
                    .list_entry_history(&restarted_vault_id, &entry.id)
                    .unwrap()
                    .items
                    .len(),
                1
            );
            restarted.reset_test_onedrive_access_counts();

            let status = restarted
                .retry_vault_source_sync(&restarted_vault_id)
                .unwrap();

            assert_eq!(status.remote_state, "online");
            assert_eq!(
                restarted.test_onedrive_access_counts().writes,
                usize::from(!remote_was_committed),
                "remote_was_committed={remote_was_committed}"
            );
            assert_eq!(
                entry_fields(
                    &restarted
                        .get_entry_detail(&restarted_vault_id, &entry.id)
                        .unwrap()
                ),
                desired_fields
            );
        }
    }

    #[test]
    fn pending_autofill_sync_three_way_merges_remote_changes_before_conditional_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let initial_bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_050,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            initial_bytes,
            cache_dir.path(),
        );
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let target = create_demo_entry(&mut first, &vault_id);
        let externally_deleted = create_demo_entry(&mut first, &vault_id);
        first.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&target);
        let desired_fields = EntryFieldsDto {
            password: "pending-three-way-secret".into(),
            ..expected_fields.clone()
        };
        first.queue_test_onedrive_ambiguous_write(false);
        let response = first
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-pending-three-way".into(),
                operation_id: "operation-pending-three-way".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields,
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));

        let remote_before_external = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut external_vault = core
            .load_database(&remote_before_external, &key)
            .unwrap()
            .vault;
        core.delete_entry(&mut external_vault, &externally_deleted.id)
            .unwrap();
        upsert_test_vault_custom_data(
            &core,
            &mut external_vault,
            "remote-during-pending",
            "preserved",
        );
        let external_bytes = core
            .save_kdbx(&external_vault, &key, SaveProfile::recommended())
            .unwrap();
        first.replace_test_onedrive_item("drive-1", "item-1", external_bytes.clone());
        let external_revision = first
            .test_onedrive_item_revision("drive-1", "item-1")
            .unwrap();

        let mut restarted = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_051,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            external_bytes,
            cache_dir.path(),
        );
        restarted
            .set_test_onedrive_item_revision("drive-1", "item-1", external_revision)
            .unwrap();
        let restarted_vault_id = open_unlocked_demo_onedrive(&mut restarted);
        restarted.reset_test_onedrive_access_counts();

        let status = restarted
            .retry_vault_source_sync(&restarted_vault_id)
            .unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(restarted.test_onedrive_access_counts().writes, 1);
        let merged = restarted.loaded_vault(&restarted_vault_id).unwrap();
        assert_eq!(
            entry_fields_for_vault(&restarted.core, merged, &target.id).unwrap(),
            desired_fields
        );
        assert!(
            restarted
                .core
                .find_entry_view_by_id(merged, &externally_deleted.id)
                .is_none()
        );
        assert_eq!(
            merged
                .meta_custom_data
                .get("remote-during-pending")
                .map(String::as_str),
            Some("preserved")
        );
    }

    #[test]
    fn pending_autofill_sync_refreshes_quick_unlock_after_remote_kdf_rotation() {
        let mut runtime = demo_onedrive_runtime(1_700_000_051);
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let (vault_id, target, _, desired_fields) = begin_pending_update(
            &mut runtime,
            "transaction-pending-kdf-rotation",
            "operation-pending-kdf-rotation",
            "pending-kdf-rotation-secret",
            false,
        );
        runtime
            .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();

        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let remote_vault = core.load_database(&remote, &key).unwrap().vault;
        let rotated = core
            .save_kdbx(
                &remote_vault,
                &key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::ChaCha20,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
                },
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", rotated);

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(
            status.remote_state, "online",
            "unexpected pending sync error: {:?}",
            status.last_error
        );
        assert_eq!(status.last_error, None);
        let durable = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let durable_header = vaultkern_core::KdbxHeader::decode(&durable).unwrap();
        assert_eq!(durable_header.cipher, KdbxCipher::ChaCha20);
        assert_eq!(durable_header.compression, Compression::None);
        let durable = core.load_database(&durable, &key).unwrap().vault;
        assert_eq!(
            entry_fields_for_vault(&runtime.core, &durable, &target.id).unwrap(),
            desired_fields
        );
        runtime.lock_session();
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        assert!(runtime.session_state().unlocked);
    }

    #[test]
    fn pending_autofill_created_after_remote_kdf_rotation_remains_retryable() {
        let mut runtime = demo_onedrive_runtime(1_700_000_052);
        let authorizations = std::rc::Rc::new(RefCell::new(Vec::new()));
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let target = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        runtime
            .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        let expected_fields = entry_fields(&target);
        let desired_fields = EntryFieldsDto {
            password: "pending-after-kdf-rotation".into(),
            ..expected_fields.clone()
        };

        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let remote_vault = core.load_database(&remote, &key).unwrap().vault;
        let rotated = core
            .save_kdbx(
                &remote_vault,
                &key,
                SaveProfile {
                    version: KdbxVersion::V4_1,
                    cipher: KdbxCipher::ChaCha20,
                    compression: Compression::None,
                    kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
                },
            )
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", rotated);
        runtime.queue_test_onedrive_ambiguous_write(false);

        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-pending-after-kdf-rotation".into(),
            operation_id: "operation-pending-after-kdf-rotation".into(),
            vault_id: vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: target.id.clone(),
                expected_fields,
                desired_fields: desired_fields.clone(),
            },
        };
        let response = runtime.handle(command.clone()).unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        runtime
            .verify_passkey_user_with_master_password(&vault_id, "demo-password")
            .unwrap();

        let stale_session_key = Arc::new(
            derive_transformed_key_with_policy(
                &remote,
                &key,
                &ExternalKdfPolicy::Desktop,
                ExternalKdfConfirmation::Unconfirmed,
            )
            .unwrap(),
        );
        let chain = runtime
            .remote_cache
            .read_pending_chain(&RemoteCacheKey::new("onedrive", "drive-1:item-1"))
            .unwrap();
        let stale_save_profile = runtime.inspected_save_profile(&remote).unwrap();
        {
            let loaded = runtime.vault_session.find_loaded_mut(&vault_id).unwrap();
            loaded.vault = Some(remote_vault.clone());
            loaded.baseline_fingerprint = chain.plan_baseline.fingerprint;
            loaded.save_profile = stale_save_profile;
        }
        runtime
            .replace_session_transformed_key(&vault_id, stale_session_key.clone())
            .unwrap();
        authorizations.borrow_mut().clear();
        let adopted = runtime.handle(command.clone()).unwrap();
        assert!(matches!(
            adopted,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        assert_eq!(authorizations.borrow().len(), 1);

        runtime.allow_unlock_kdf = false;
        let replayed = runtime.handle(command.clone()).unwrap();
        assert!(
            matches!(
                replayed,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        disposition: AutofillPersistDispositionDto::Replayed,
                        durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                        ..
                    },
                    ..
                })
            ),
            "unexpected replay response: {replayed:?}"
        );
        runtime.allow_unlock_kdf = true;
        runtime
            .replace_session_transformed_key(&vault_id, stale_session_key)
            .unwrap();
        authorizations.borrow_mut().clear();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(
            status.remote_state, "online",
            "unexpected pending sync error: {:?}",
            status.last_error
        );
        assert_eq!(status.last_error, None);
        assert_eq!(authorizations.borrow().len(), 1);
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
        runtime.lock_session();
        runtime.unlock_current_vault_with_quick_unlock().unwrap();
        assert!(runtime.session_state().unlocked);
    }

    #[test]
    fn pending_autofill_sync_preserves_a_later_encryption_profile_edit() {
        for (remote_was_committed, suffix) in [(false, "not-committed"), (true, "committed")] {
            let mut runtime = demo_onedrive_runtime(1_700_000_053);
            let (vault_id, target, _, desired_fields) = begin_pending_update(
                &mut runtime,
                &format!("transaction-pending-profile-{suffix}"),
                &format!("operation-pending-profile-{suffix}"),
                "pending-profile-secret",
                remote_was_committed,
            );
            let mut encryption = runtime.get_database_settings(&vault_id).unwrap().encryption;
            encryption.compression = "none".into();
            runtime
                .update_database_settings(
                    &vault_id,
                    DatabaseSettingsUpdateDto {
                        encryption: Some(encryption),
                        ..DatabaseSettingsUpdateDto::default()
                    },
                )
                .unwrap();
            runtime.reset_test_onedrive_access_counts();

            let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

            assert_eq!(
                status.remote_state, "online",
                "unexpected pending sync error ({suffix}): {:?}",
                status.last_error
            );
            assert_eq!(runtime.test_onedrive_access_counts().writes, 1, "{suffix}");
            let durable = runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap();
            assert_eq!(
                vaultkern_core::KdbxHeader::decode(&durable)
                    .unwrap()
                    .compression,
                Compression::None,
                "{suffix}"
            );
            assert_eq!(
                entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
                desired_fields,
                "{suffix}"
            );
        }
    }

    #[test]
    fn pending_autofill_sync_rejects_unreceipted_remote_target_move_without_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_052);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, target, _, desired_fields) = begin_pending_update(
            &mut runtime,
            "transaction-unreceipted-move",
            "operation-unreceipted-move",
            "pending-move-secret",
            false,
        );
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut remote_vault = core.load_database(&remote, &key).unwrap().vault;
        let root_id = remote_vault.root.id.to_string();
        let moved_group = core
            .add_group(&mut remote_vault, &root_id, "Remote move")
            .unwrap();
        core.move_entry(&mut remote_vault, &target.id, &moved_group.id)
            .unwrap();
        let changed_remote = core
            .save_kdbx(&remote_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_remote.clone());

        assert_pending_sync_rejected_without_put(
            &mut runtime,
            &vault_id,
            &changed_remote,
            "pending autofill target changed without a bound receipt",
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_sync_rejects_unreceipted_remote_target_metadata_edit_without_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_053);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, target, _, desired_fields) = begin_pending_update(
            &mut runtime,
            "transaction-unreceipted-metadata",
            "operation-unreceipted-metadata",
            "pending-metadata-secret",
            false,
        );
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut remote_vault = core.load_database(&remote, &key).unwrap().vault;
        core.update_entry_presentation_metadata(
            &mut remote_vault,
            &target.id,
            vaultkern_core::EntryPresentationMetadataUpdate {
                icon_id: Some(Some(42)),
                ..Default::default()
            },
        )
        .unwrap();
        let changed_remote = core
            .save_kdbx(&remote_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_remote.clone());

        assert_pending_sync_rejected_without_put(
            &mut runtime,
            &vault_id,
            &changed_remote,
            "pending autofill target changed without a bound receipt",
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_sync_rejects_unreceipted_remote_desired_fields_without_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_054);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, target, _, desired_fields) = begin_pending_update(
            &mut runtime,
            "transaction-unreceipted-desired",
            "operation-unreceipted-desired",
            "pending-already-desired",
            false,
        );
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut remote_vault = core.load_database(&remote, &key).unwrap().vault;
        core.update_entry_fields(
            &mut remote_vault,
            &target.id,
            EntryUpdate {
                password: Some(desired_fields.password.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        let changed_remote = core
            .save_kdbx(&remote_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_remote.clone());

        assert_pending_sync_rejected_without_put(
            &mut runtime,
            &vault_id,
            &changed_remote,
            "pending autofill target changed without a bound receipt",
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_sync_accepts_the_target_state_observed_by_the_ambiguous_write() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_054);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, target, _, desired_fields, observed_parent_id) =
            begin_pending_after_observed_target_change(
                &mut runtime,
                "transaction-observed-target-state",
                "operation-observed-target-state",
            );
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
        let durable = runtime.loaded_vault(&vault_id).unwrap();
        assert_eq!(
            entry_fields_for_vault(&runtime.core, durable, &target.id).unwrap(),
            desired_fields
        );
        let target_state = serialized_autofill_target_state(durable, &target.id).unwrap();
        assert_eq!(
            target_state.parent_id,
            Some(Uuid::parse_str(&observed_parent_id).unwrap())
        );
        assert_eq!(target_state.entry.and_then(|entry| entry.icon_id), Some(42));
    }

    #[test]
    fn pending_autofill_sync_merges_unrelated_remote_change_after_the_observed_source() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_054);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, target, unrelated, desired_fields, observed_parent_id) =
            begin_pending_after_observed_target_change(
                &mut runtime,
                "transaction-observed-then-unrelated",
                "operation-observed-then-unrelated",
            );
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut changed_vault = core.load_database(&remote, &key).unwrap().vault;
        let unrelated_fields = EntryFieldsDto {
            notes: "remote changed after the observed source".into(),
            ..entry_fields(&unrelated)
        };
        core.update_entry_fields(
            &mut changed_vault,
            &unrelated.id,
            EntryUpdate {
                notes: Some(unrelated_fields.notes.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        upsert_test_vault_custom_data(
            &core,
            &mut changed_vault,
            "after-observed-source",
            "preserved",
        );
        let changed_bytes = core
            .save_kdbx(&changed_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_bytes);
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
        let durable = runtime.loaded_vault(&vault_id).unwrap();
        assert_eq!(
            entry_fields_for_vault(&runtime.core, durable, &target.id).unwrap(),
            desired_fields
        );
        assert_eq!(
            entry_fields_for_vault(&runtime.core, durable, &unrelated.id).unwrap(),
            unrelated_fields
        );
        assert_eq!(
            durable
                .meta_custom_data
                .get("after-observed-source")
                .map(String::as_str),
            Some("preserved")
        );
        let target_state = serialized_autofill_target_state(durable, &target.id).unwrap();
        assert_eq!(
            target_state.parent_id,
            Some(Uuid::parse_str(&observed_parent_id).unwrap())
        );
        assert_eq!(target_state.entry.and_then(|entry| entry.icon_id), Some(42));
    }

    #[test]
    fn pending_autofill_sync_rejects_unreceipted_create_id_collision_without_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_055);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let parent_group_id = runtime.list_groups(&vault_id).unwrap().root.id;
        let planned_entry_id = "12345678-1234-4abc-8def-1234567890ac";
        let desired_fields = EntryFieldsDto {
            title: "Unreceipted create".into(),
            username: "alice".into(),
            password: "collision-secret".into(),
            url: "https://example.com/create".into(),
            notes: "remote has fields but no receipt".into(),
            totp_uri: None,
            custom_fields: vec![],
        };
        runtime.queue_test_onedrive_ambiguous_write(false);
        let pending = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-unreceipted-create".into(),
                operation_id: "operation-unreceipted-create".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Create {
                    parent_group_id: parent_group_id.clone(),
                    planned_entry_id: planned_entry_id.into(),
                    expected_matching_entry_ids: vec![],
                    desired_fields: desired_fields.clone(),
                },
            })
            .unwrap();
        assert!(matches!(
            pending,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let remote = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut remote_vault = core.load_database(&remote, &key).unwrap().vault;
        core.add_entry_with_id(
            &mut remote_vault,
            &parent_group_id,
            planned_entry_id,
            EntryCreate {
                title: desired_fields.title.clone(),
                username: desired_fields.username.clone(),
                password: desired_fields.password.clone(),
                url: desired_fields.url.clone(),
                notes: desired_fields.notes.clone(),
            },
        )
        .unwrap();
        let changed_remote = core
            .save_kdbx(&remote_vault, &key, SaveProfile::recommended())
            .unwrap();
        runtime.replace_test_onedrive_item("drive-1", "item-1", changed_remote.clone());

        assert_pending_sync_rejected_without_put(
            &mut runtime,
            &vault_id,
            &changed_remote,
            "pending autofill create target collided without a bound receipt",
        );
        assert_eq!(
            entry_fields(
                &runtime
                    .get_entry_detail(&vault_id, planned_entry_id)
                    .unwrap()
            ),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_sync_merges_live_edit_when_remote_commit_was_unknown() {
        assert_pending_sync_merges_live_edit(false);
    }

    #[test]
    fn pending_autofill_sync_puts_live_edit_when_remote_already_matches_pending() {
        assert_pending_sync_merges_live_edit(true);
    }

    #[test]
    fn pending_autofill_completion_post_publish_fault_never_strands_runtime_state() {
        for point in [
            crate::providers::durable_file::DurableFaultPoint::CacheManifestDurable,
            crate::providers::durable_file::DurableFaultPoint::ManifestReplaced,
        ] {
            let cache_dir = tempfile::tempdir().unwrap();
            let mut runtime = demo_onedrive_runtime(1_700_000_057);
            runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
            let (vault_id, target, _, desired_fields) = begin_pending_update(
                &mut runtime,
                "transaction-completion-publish-fault",
                "operation-completion-publish-fault",
                "completion-publish-fault-secret",
                false,
            );
            runtime.remote_cache = RemoteVaultCache::new_at_with_faults(
                cache_dir.path(),
                crate::providers::durable_file::DurableFaultInjector::fail_once(point),
            );

            let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

            assert_eq!(status.remote_state, "online", "{point:?}");
            assert_eq!(
                entry_fields(&runtime.get_entry_detail(&vault_id, &target.id).unwrap()),
                desired_fields,
                "{point:?}"
            );
            assert!(matches!(
                runtime
                    .remote_cache
                    .read_pending_chain(&RemoteCacheKey::new("onedrive", "drive-1:item-1")),
                Err(PendingRemoteCacheChainError::NotPending)
            ));
        }
    }

    #[test]
    fn generic_save_is_rejected_while_an_autofill_operation_is_pending() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, _, unrelated, _) = begin_pending_update(
            &mut runtime,
            "transaction-save-while-pending",
            "operation-save-while-pending",
            "pending-save-secret",
            false,
        );
        let edited_fields = EntryFieldsDto {
            notes: "must remain an in-memory edit".into(),
            ..entry_fields(&unrelated)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                edited_fields.title.clone(),
                edited_fields.username.clone(),
                edited_fields.password.clone(),
                edited_fields.url.clone(),
                edited_fields.notes.clone(),
                edited_fields.totp_uri.clone(),
                edited_fields.custom_fields.clone(),
            )
            .unwrap();
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let chain_before = runtime.remote_cache.read_pending_chain(&cache_key).unwrap();
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        runtime.reset_test_onedrive_access_counts();

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault_id.clone(),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected pending autofill save rejection, got {response:?}");
        };
        assert_eq!(error.code, "pending_autofill_sync_required");
        assert!(error.message.contains("retry vault source sync"));
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(
            runtime.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &unrelated.id).unwrap()),
            edited_fields
        );
    }

    #[test]
    fn stale_runtime_cannot_overwrite_a_shared_autofill_pending_chain() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut first = demo_onedrive_runtime(1_700_000_058);
        first.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let target = create_demo_entry(&mut first, &vault_id);
        let unrelated = create_demo_entry(&mut first, &vault_id);
        first.save_vault(&vault_id).unwrap();
        let baseline_bytes = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();

        let mut stale = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_059,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            baseline_bytes.clone(),
            cache_dir.path(),
        );
        assert_eq!(open_unlocked_demo_onedrive(&mut stale), vault_id);
        assert_eq!(
            stale.current_source_status().unwrap().remote_state,
            "online"
        );

        let desired_fields = EntryFieldsDto {
            password: "pending-shared-secret".into(),
            ..entry_fields(&target)
        };
        first.queue_test_onedrive_ambiguous_write(false);
        let pending = first
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-shared-pending".into(),
                operation_id: "operation-shared-pending".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields: entry_fields(&target),
                    desired_fields,
                },
            })
            .unwrap();
        assert!(matches!(
            pending,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let chain_before = first.remote_cache.read_pending_chain(&cache_key).unwrap();
        let remote_before = stale
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let stale_edit = EntryFieldsDto {
            notes: "stale runtime live edit".into(),
            ..entry_fields(&unrelated)
        };
        stale
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                stale_edit.title,
                stale_edit.username,
                stale_edit.password,
                stale_edit.url,
                stale_edit.notes,
                stale_edit.totp_uri,
                stale_edit.custom_fields,
            )
            .unwrap();
        stale.reset_test_onedrive_access_counts();

        let response = stale
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault_id.clone(),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected shared pending save rejection, got {response:?}");
        };
        assert_eq!(error.code, "pending_autofill_sync_required");
        assert_eq!(stale.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(stale.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            stale
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(
            first.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );

        let unrelated_now = stale.get_entry_detail(&vault_id, &unrelated.id).unwrap();
        stale.reset_test_onedrive_access_counts();
        let second_operation = stale
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-must-not-bypass-shared-pending".into(),
                operation_id: "operation-must-not-bypass-shared-pending".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: unrelated.id.clone(),
                    expected_fields: entry_fields(&unrelated_now),
                    desired_fields: EntryFieldsDto {
                        password: "second-operation-must-not-publish".into(),
                        ..entry_fields(&unrelated_now)
                    },
                },
            })
            .unwrap();
        let RuntimeResponse::Error(error) = second_operation else {
            panic!("expected shared pending operation rejection, got {second_operation:?}");
        };
        assert_eq!(error.code, "persist_io_unavailable");
        assert_eq!(stale.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(stale.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            first.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );

        let vault_ref_id = stale.list_recent_vaults().unwrap().vaults[0]
            .vault_ref_id
            .clone();
        let delete_error = stale
            .delete_vault_reference(&vault_ref_id)
            .expect_err("deleting a stale reference must preserve shared pending durability");
        assert!(delete_error.to_string().contains("pending remote cache"));
        assert!(
            stale
                .list_recent_vaults()
                .unwrap()
                .vaults
                .iter()
                .any(|reference| reference.vault_ref_id == vault_ref_id)
        );
        assert_eq!(
            first.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );
    }

    #[test]
    fn stale_runtime_replays_the_same_shared_operation_and_preserves_live_edits() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut first = demo_onedrive_runtime(1_700_000_060);
        first.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let target = create_demo_entry(&mut first, &vault_id);
        let unrelated = create_demo_entry(&mut first, &vault_id);
        first.save_vault(&vault_id).unwrap();
        let baseline_bytes = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();

        let mut stale = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_061,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            baseline_bytes.clone(),
            cache_dir.path(),
        );
        assert_eq!(open_unlocked_demo_onedrive(&mut stale), vault_id);
        let stale_unrelated = EntryFieldsDto {
            notes: "preserve stale runtime edit during replay".into(),
            ..entry_fields(&unrelated)
        };
        stale
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                stale_unrelated.title.clone(),
                stale_unrelated.username.clone(),
                stale_unrelated.password.clone(),
                stale_unrelated.url.clone(),
                stale_unrelated.notes.clone(),
                stale_unrelated.totp_uri.clone(),
                stale_unrelated.custom_fields.clone(),
            )
            .unwrap();
        let mut stale_encryption = stale.get_database_settings(&vault_id).unwrap().encryption;
        stale_encryption.compression = "none".into();
        stale
            .update_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(stale_encryption),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        let mut stale_retry = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_062,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            baseline_bytes,
            cache_dir.path(),
        );
        assert_eq!(open_unlocked_demo_onedrive(&mut stale_retry), vault_id);
        let retry_live_edit = EntryFieldsDto {
            notes: "preserve stale retry edit".into(),
            ..entry_fields(&unrelated)
        };
        stale_retry
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                retry_live_edit.title.clone(),
                retry_live_edit.username.clone(),
                retry_live_edit.password.clone(),
                retry_live_edit.url.clone(),
                retry_live_edit.notes.clone(),
                retry_live_edit.totp_uri.clone(),
                retry_live_edit.custom_fields.clone(),
            )
            .unwrap();
        let mut retry_encryption = stale_retry
            .get_database_settings(&vault_id)
            .unwrap()
            .encryption;
        retry_encryption.compression = "none".into();
        stale_retry
            .update_database_settings(
                &vault_id,
                DatabaseSettingsUpdateDto {
                    encryption: Some(retry_encryption),
                    ..DatabaseSettingsUpdateDto::default()
                },
            )
            .unwrap();
        let desired_fields = EntryFieldsDto {
            password: "same-operation-shared-secret".into(),
            ..entry_fields(&target)
        };
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-same-shared-pending".into(),
            operation_id: "operation-same-shared-pending".into(),
            vault_id: vault_id.clone(),
            plan: AutofillPersistPlanDto::Update {
                entry_id: target.id.clone(),
                expected_fields: entry_fields(&target),
                desired_fields: desired_fields.clone(),
            },
        };
        first.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            first.handle(command.clone()).unwrap(),
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let chain_before = first.remote_cache.read_pending_chain(&cache_key).unwrap();
        stale.reset_test_onedrive_access_counts();

        let replay = stale.handle(command).unwrap();

        assert!(matches!(
            replay,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    ..
                },
                ..
            })
        ));
        assert_eq!(stale.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(stale.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            entry_fields(&stale.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
        assert_eq!(
            entry_fields(&stale.get_entry_detail(&vault_id, &unrelated.id).unwrap()),
            stale_unrelated
        );
        assert_eq!(
            stale
                .get_database_settings(&vault_id)
                .unwrap()
                .encryption
                .compression,
            "none"
        );
        let stale_loaded = stale.vault_session.find_loaded(&vault_id).unwrap();
        assert!(stale_loaded.bytes.is_empty());
        assert!(same_content_fingerprint(
            &stale_loaded.baseline_fingerprint,
            &chain_before.pending.fingerprint,
        ));
        assert_eq!(
            stale.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );

        stale_retry.reset_test_onedrive_access_counts();
        let status = stale_retry.retry_vault_source_sync(&vault_id).unwrap();
        assert_eq!(status.remote_state, "online");
        assert_eq!(
            entry_fields(&stale_retry.get_entry_detail(&vault_id, &target.id).unwrap()),
            desired_fields
        );
        assert_eq!(
            entry_fields(
                &stale_retry
                    .get_entry_detail(&vault_id, &unrelated.id)
                    .unwrap()
            ),
            retry_live_edit
        );
        assert_eq!(stale_retry.test_onedrive_access_counts().writes, 1);
        let durable = stale_retry
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        assert_eq!(
            vaultkern_core::KdbxHeader::decode(&durable)
                .unwrap()
                .compression,
            Compression::None
        );
        assert!(matches!(
            stale_retry.remote_cache.read_pending_chain(&cache_key),
            Err(PendingRemoteCacheChainError::NotPending)
        ));
    }

    #[test]
    fn generic_save_fails_closed_when_the_pending_autofill_chain_is_corrupt() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, _, _, _) = begin_pending_update(
            &mut runtime,
            "transaction-save-corrupt-pending",
            "operation-save-corrupt-pending",
            "pending-corrupt-save-secret",
            false,
        );
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let paths = runtime.remote_cache.paths_for_tests(&cache_key);
        let manifest_before = std::fs::read(&paths.metadata_path).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_before).unwrap();
        let previous_path = paths.metadata_path.parent().unwrap().join(
            manifest["previousGeneration"]["generation"]
                .as_str()
                .unwrap(),
        );
        std::fs::write(previous_path, b"tampered").unwrap();
        let remote_before = runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        runtime.reset_test_onedrive_access_counts();

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault_id.clone(),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected corrupt pending save rejection, got {response:?}");
        };
        assert_eq!(error.code, "pending_autofill_sync_required");
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            remote_before
        );
        assert_eq!(std::fs::read(paths.metadata_path).unwrap(), manifest_before);
    }

    #[test]
    fn generic_pending_cache_without_previous_still_accepts_later_generic_saves() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        runtime.remote_cache.delete(&cache_key).unwrap();
        runtime.remove_test_onedrive_item("drive-1", "item-1");
        assert!(matches!(
            runtime
                .handle(RuntimeCommand::SaveVault {
                    vault_id: vault_id.clone(),
                })
                .unwrap(),
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::SavedToCache,
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

        let response = runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault_id.clone(),
            })
            .unwrap();

        assert!(matches!(
            response,
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::SavedToCache,
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
        runtime.save_vault(&vault_id).unwrap();

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
            runtime.save_vault(&vault_id).unwrap(),
            RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
                status: SaveVaultStatusDto::SavedToCache,
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
    fn passkey_save_does_not_mark_mutation_saved_while_autofill_sync_is_pending() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, _, unrelated, _) = begin_pending_update(
            &mut runtime,
            "transaction-passkey-save-pending",
            "operation-passkey-save-pending",
            "pending-passkey-save-secret",
            false,
        );
        let ceremony_token = "ceremony-passkey-save-pending";
        insert_test_create_passkey_ceremony(
            &mut runtime,
            ceremony_token,
            &vault_id,
            &unrelated.id,
            PasskeyCeremonyDurableStateDto::Mutated,
        );
        runtime.reset_test_onedrive_access_counts();

        let error = runtime
            .save_passkey_registration(
                ceremony_token,
                PasskeyCeremonyPhaseDto::CompletionAndMutation,
                &vault_id,
            )
            .expect_err("an internal save must fail while autofill sync is pending");

        assert!(error.to_string().contains("retry vault source sync"));
        assert_eq!(
            runtime.passkey_ceremonies[ceremony_token].durable_state,
            PasskeyCeremonyDurableStateDto::Mutated
        );
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
    }

    #[test]
    fn passkey_abort_does_not_close_when_rollback_save_is_blocked_by_pending_autofill() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_058);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let (vault_id, _, unrelated, _) = begin_pending_update(
            &mut runtime,
            "transaction-passkey-abort-pending",
            "operation-passkey-abort-pending",
            "pending-passkey-abort-secret",
            false,
        );
        let ceremony_token = "ceremony-passkey-abort-pending";
        insert_test_create_passkey_ceremony(
            &mut runtime,
            ceremony_token,
            &vault_id,
            &unrelated.id,
            PasskeyCeremonyDurableStateDto::Saved,
        );
        runtime.reset_test_onedrive_access_counts();

        let error = runtime
            .abort_passkey_registration(
                ceremony_token,
                PasskeyCeremonyPhaseDto::CompletionAndMutation,
                PasskeyCeremonyPhaseDto::ClosedAborted,
            )
            .expect_err("a blocked rollback save must not close the passkey ceremony");

        assert!(error.to_string().contains("retry vault source sync"));
        assert_eq!(
            runtime.passkey_ceremonies[ceremony_token].phase,
            PasskeyCeremonyPhaseDto::CompletionAndMutation
        );
        assert_eq!(
            runtime.passkey_ceremonies[ceremony_token].durable_state,
            PasskeyCeremonyDurableStateDto::Saved
        );
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
    }

    #[test]
    fn pending_autofill_command_replay_preserves_later_live_edits_without_remote_io() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut runtime = demo_onedrive_runtime(1_700_000_059);
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let transaction_id = "transaction-command-replay-live-edit";
        let operation_id = "operation-command-replay-live-edit";
        let (vault_id, target, unrelated, desired_fields) = begin_pending_update(
            &mut runtime,
            transaction_id,
            operation_id,
            "pending-command-replay-secret",
            false,
        );
        let edited_fields = EntryFieldsDto {
            notes: "live edit after pending command".into(),
            ..entry_fields(&unrelated)
        };
        runtime
            .update_entry_fields(
                &vault_id,
                &unrelated.id,
                edited_fields.title.clone(),
                edited_fields.username.clone(),
                edited_fields.password.clone(),
                edited_fields.url.clone(),
                edited_fields.notes.clone(),
                edited_fields.totp_uri.clone(),
                edited_fields.custom_fields.clone(),
            )
            .unwrap();
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let chain_before = runtime.remote_cache.read_pending_chain(&cache_key).unwrap();
        runtime.reset_test_onedrive_access_counts();

        let replay = runtime
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: transaction_id.into(),
                operation_id: operation_id.into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: target.id.clone(),
                    expected_fields: entry_fields(&target),
                    desired_fields,
                },
            })
            .unwrap();

        assert!(matches!(
            replay,
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                    cache_state: AutofillCacheStateDto::PendingSync,
                    ..
                },
                ..
            })
        ));
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            runtime.remote_cache.read_pending_chain(&cache_key).unwrap(),
            chain_before
        );
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &unrelated.id).unwrap()),
            edited_fields
        );
    }

    #[test]
    fn pending_autofill_create_reconstructs_the_bound_plan_and_keeps_one_planned_id() {
        let cache_dir = tempfile::tempdir().unwrap();
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let initial_bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_060,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            initial_bytes,
            cache_dir.path(),
        );
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let parent_group_id = first.list_groups(&vault_id).unwrap().root.id;
        let planned_entry_id = "12345678-1234-4abc-8def-1234567890ab";
        let desired_fields = EntryFieldsDto {
            title: "Pending create".into(),
            username: "alice".into(),
            password: "created-once".into(),
            url: "https://example.com/login".into(),
            notes: String::new(),
            totp_uri: None,
            custom_fields: vec![],
        };
        let command = RuntimeCommand::PersistAutofillMutation {
            transaction_id: "transaction-pending-create".into(),
            operation_id: "operation-pending-create".into(),
            vault_id: vault_id.clone(),
            plan: AutofillPersistPlanDto::Create {
                parent_group_id,
                planned_entry_id: planned_entry_id.into(),
                expected_matching_entry_ids: vec![],
                desired_fields: desired_fields.clone(),
            },
        };
        first.queue_test_onedrive_ambiguous_write(false);
        let pending = first.handle(command.clone()).unwrap();
        assert!(
            matches!(
                &pending,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                        ..
                    },
                    ..
                })
            ),
            "unexpected pending create response: {pending:?}"
        );
        let remote = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let revision = first
            .test_onedrive_item_revision("drive-1", "item-1")
            .unwrap();

        let mut restarted = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_061,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            remote,
            cache_dir.path(),
        );
        restarted
            .set_test_onedrive_item_revision("drive-1", "item-1", revision)
            .unwrap();
        let restarted_vault_id = open_unlocked_demo_onedrive(&mut restarted);
        assert!(matches!(
            restarted.handle(command).unwrap(),
            RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                outcome: AutofillPersistOutcomeDto::Durable {
                    disposition: AutofillPersistDispositionDto::Replayed,
                    ..
                },
                ..
            })
        ));
        assert_eq!(
            restarted.list_entries(&restarted_vault_id).unwrap().len(),
            1
        );

        let status = restarted
            .retry_vault_source_sync(&restarted_vault_id)
            .unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(
            restarted.list_entries(&restarted_vault_id).unwrap().len(),
            1
        );
        assert_eq!(
            entry_fields(
                &restarted
                    .get_entry_detail(&restarted_vault_id, planned_entry_id)
                    .unwrap()
            ),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_sync_preserves_remote_post_receipt_target_edits_without_put() {
        let cache_dir = tempfile::tempdir().unwrap();
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");
        let initial_bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();
        let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_070,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            initial_bytes,
            cache_dir.path(),
        );
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let entry = create_demo_entry(&mut first, &vault_id);
        first.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        first.queue_test_onedrive_ambiguous_write(true);
        assert!(matches!(
            first
                .handle(RuntimeCommand::PersistAutofillMutation {
                    transaction_id: "transaction-post-receipt-edit".into(),
                    operation_id: "operation-post-receipt-edit".into(),
                    vault_id: vault_id.clone(),
                    plan: AutofillPersistPlanDto::Update {
                        entry_id: entry.id.clone(),
                        expected_fields: expected_fields.clone(),
                        desired_fields: EntryFieldsDto {
                            password: "operation-secret".into(),
                            ..expected_fields
                        },
                    },
                })
                .unwrap(),
            RuntimeResponse::AutofillPersistResult(_)
        ));
        let committed_remote = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let mut edited_vault = core.load_database(&committed_remote, &key).unwrap().vault;
        let edited_entry = core
            .find_entry_view_by_id(&edited_vault, &entry.id)
            .unwrap();
        core.update_entry_fields(
            &mut edited_vault,
            &entry.id,
            EntryUpdate {
                title: Some(edited_entry.title),
                username: Some("alice".into()),
                password: Some("post-receipt-edit".into()),
                url: Some(edited_entry.url),
                notes: Some(String::new()),
            },
        )
        .unwrap();
        upsert_test_vault_custom_data(&core, &mut edited_vault, "post-receipt-meta", "preserved");
        let edited_remote = core
            .save_kdbx(&edited_vault, &key, SaveProfile::recommended())
            .unwrap();
        first.replace_test_onedrive_item("drive-1", "item-1", edited_remote.clone());
        let edited_revision = first
            .test_onedrive_item_revision("drive-1", "item-1")
            .unwrap();

        let mut restarted = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_071,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            edited_remote,
            cache_dir.path(),
        );
        restarted
            .set_test_onedrive_item_revision("drive-1", "item-1", edited_revision)
            .unwrap();
        let restarted_vault_id = open_unlocked_demo_onedrive(&mut restarted);
        restarted.reset_test_onedrive_access_counts();

        let status = restarted
            .retry_vault_source_sync(&restarted_vault_id)
            .unwrap();

        assert_eq!(status.remote_state, "online");
        assert_eq!(restarted.test_onedrive_access_counts().writes, 0);
        let durable = restarted.loaded_vault(&restarted_vault_id).unwrap();
        assert_eq!(
            entry_fields_for_vault(&restarted.core, durable, &entry.id)
                .unwrap()
                .password,
            "post-receipt-edit"
        );
        assert_eq!(
            durable
                .meta_custom_data
                .get("post-receipt-meta")
                .map(String::as_str),
            Some("preserved")
        );
    }

    #[test]
    fn pending_autofill_sync_rejects_a_corrupt_previous_generation_before_remote_io() {
        let mut runtime = demo_onedrive_runtime(1_700_000_080);
        let vault_id = open_unlocked_demo_onedrive(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &vault_id);
        runtime.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        runtime.queue_test_onedrive_ambiguous_write(false);
        assert!(matches!(
            runtime
                .handle(RuntimeCommand::PersistAutofillMutation {
                    transaction_id: "transaction-corrupt-chain".into(),
                    operation_id: "operation-corrupt-chain".into(),
                    vault_id: vault_id.clone(),
                    plan: AutofillPersistPlanDto::Update {
                        entry_id: entry.id,
                        expected_fields: expected_fields.clone(),
                        desired_fields: EntryFieldsDto {
                            password: "pending".into(),
                            ..expected_fields
                        },
                    },
                })
                .unwrap(),
            RuntimeResponse::AutofillPersistResult(_)
        ));
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let paths = runtime.remote_cache.paths_for_tests(&cache_key);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&paths.metadata_path).unwrap()).unwrap();
        let previous_name = manifest["previousGeneration"]["generation"]
            .as_str()
            .unwrap();
        let previous_path = paths.metadata_path.parent().unwrap().join(previous_name);
        std::fs::write(previous_path, b"tampered").unwrap();
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "pending_sync");
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
    }

    #[test]
    fn pending_autofill_sync_rejects_a_corrupt_observed_generation_before_remote_io() {
        let mut runtime = demo_onedrive_runtime(1_700_000_081);
        let (vault_id, entry, _, desired_fields, _) = begin_pending_after_observed_target_change(
            &mut runtime,
            "transaction-corrupt-observed",
            "operation-corrupt-observed",
        );
        let cache_key = RemoteCacheKey::new("onedrive", "drive-1:item-1");
        let paths = runtime.remote_cache.paths_for_tests(&cache_key);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&paths.metadata_path).unwrap()).unwrap();
        let observed_name = manifest["observedGeneration"]["generation"]
            .as_str()
            .unwrap();
        let observed_path = paths.metadata_path.parent().unwrap().join(observed_name);
        std::fs::write(observed_path, b"tampered").unwrap();
        runtime.reset_test_onedrive_access_counts();

        let status = runtime.retry_vault_source_sync(&vault_id).unwrap();

        assert_eq!(status.remote_state, "pending_sync");
        assert!(
            status
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("observed source generation is corrupt"))
        );
        assert_eq!(runtime.test_onedrive_access_counts().remote_state_reads, 0);
        assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
        assert_eq!(
            entry_fields(&runtime.get_entry_detail(&vault_id, &entry.id).unwrap()),
            desired_fields
        );
    }

    #[test]
    fn pending_autofill_restart_reconstructs_semantically_equivalent_totp_plan() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut first = demo_onedrive_runtime(1_700_000_090);
        first.remote_cache = RemoteVaultCache::new_at(cache_dir.path());
        let vault_id = open_unlocked_demo_onedrive(&mut first);
        let entry = create_demo_entry(&mut first, &vault_id);
        first.save_vault(&vault_id).unwrap();
        let expected_fields = entry_fields(&entry);
        let noncanonical_totp = "otpauth://totp/Example%3Aalice?period=45&digits=8&algorithm=SHA256&secret=JBSWY3DPEHPK3PXP";
        first.queue_test_onedrive_ambiguous_write(false);
        let pending = first
            .handle(RuntimeCommand::PersistAutofillMutation {
                transaction_id: "transaction-totp-restart".into(),
                operation_id: "operation-totp-restart".into(),
                vault_id: vault_id.clone(),
                plan: AutofillPersistPlanDto::Update {
                    entry_id: entry.id.clone(),
                    expected_fields: expected_fields.clone(),
                    desired_fields: EntryFieldsDto {
                        password: "totp-pending".into(),
                        totp_uri: Some(noncanonical_totp.into()),
                        ..expected_fields
                    },
                },
            })
            .unwrap();
        assert!(
            matches!(
                &pending,
                RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
                    outcome: AutofillPersistOutcomeDto::Durable {
                        durability: AutofillPersistDurabilityDto::PendingRemoteCache,
                        ..
                    },
                    ..
                })
            ),
            "unexpected TOTP pending response: {pending:?}"
        );
        let remote = first
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap();
        let revision = first
            .test_onedrive_item_revision("drive-1", "item-1")
            .unwrap();

        let mut restarted = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_091,
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            remote,
            cache_dir.path(),
        );
        restarted
            .set_test_onedrive_item_revision("drive-1", "item-1", revision)
            .unwrap();
        let restarted_vault_id = open_unlocked_demo_onedrive(&mut restarted);

        let status = restarted
            .retry_vault_source_sync(&restarted_vault_id)
            .unwrap();

        assert_eq!(status.remote_state, "online");
        let detail = restarted
            .get_entry_detail(&restarted_vault_id, &entry.id)
            .unwrap();
        assert_eq!(detail.password, "totp-pending");
        assert_eq!(
            detail.totp_uri.as_deref(),
            Some(
                "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45"
            )
        );
    }

    #[test]
    fn runtime_kdbx_roundtrips_sha256_eight_digit_totp_with_history() {
        let mut runtime = Runtime::for_tests();
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
                String::new(),
                None,
            )
            .unwrap();
        runtime.save_vault(&opened.vault_id).unwrap();
        let mut updater = Runtime::for_tests();
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
        updater.save_vault(&update_handle.vault_id).unwrap();

        let mut reopened = Runtime::for_tests();
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

        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests();

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
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);

        let error = runtime
            .set_entry_passkey(
                &opened.vault_id,
                &entry.id,
                EntryPasskeyDto {
                    username: "alice@example.com".into(),
                    credential_id: "Y3JlZC0x".into(),
                    generated_user_id: None,
                    private_key_pem: "pem".into(),
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
    fn set_entry_passkey_rejects_invalid_credential_id() {
        let mut runtime = Runtime::for_tests();
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        let entry = create_demo_entry(&mut runtime, &opened.vault_id);

        let error = runtime
            .set_entry_passkey(
                &opened.vault_id,
                &entry.id,
                EntryPasskeyDto {
                    username: "alice@example.com".into(),
                    credential_id: "not base64url!".into(),
                    generated_user_id: None,
                    private_key_pem: "pem".into(),
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

        let mut runtime = Runtime::for_tests();
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
        let mut runtime = Runtime::for_tests();
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

        let mut runtime = Runtime::for_tests();
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
    fn expired_pre_completion_passkey_ceremony_does_not_block_matching_registration() {
        let mut runtime = Runtime::for_tests_at(100);

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
        let mut runtime = Runtime::for_tests_at(100);
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
        let mut runtime = Runtime::for_tests_at(100);
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
    fn passkey_quick_unlock_user_verification_records_completion_time() {
        let authorized_at_epoch_ms = std::rc::Rc::new(RefCell::new(None));
        let mut runtime = Runtime::for_tests_with_quick_unlock();
        runtime.biometric = Box::new(RecordingBiometricProvider {
            authorized_at_epoch_ms: authorized_at_epoch_ms.clone(),
        });
        let (_dir, opened) = open_unlocked_demo_vault(&mut runtime);
        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();
        *authorized_at_epoch_ms.borrow_mut() = None;
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
            .borrow()
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

        let mut runtime = Runtime::for_tests_with_quick_unlock();
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

        let mut runtime = Runtime::for_tests_with_quick_unlock();
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

        let mut runtime = Runtime::for_tests_with_quick_unlock_failing_contains();
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

        let mut runtime = Runtime::for_tests_with_quick_unlock();
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
        runtime.save_vault(&opened.vault_id).unwrap();
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

        let authorizations = std::rc::Rc::new(RefCell::new(Vec::new()));
        let mut runtime = Runtime::for_tests();
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

        assert!(authorizations.borrow().is_empty());
    }

    #[test]
    fn quick_unlock_enrollment_uses_external_authorization_when_only_load_enforces_presence() {
        let authorizations = std::rc::Rc::new(RefCell::new(Vec::new()));
        let mut runtime = Runtime::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider {
            authorizations: authorizations.clone(),
        });
        runtime.secure_storage = Box::new(LoadPresenceOnlySecureStorageProvider::new());
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
            .unwrap();

        assert_eq!(
            authorizations.borrow().as_slice(),
            ["Enable quick unlock for this vault".to_owned()]
        );
    }

    #[test]
    fn quick_unlock_platform_authorization_precedes_credential_validation_and_blob_write() {
        let authorizations = std::rc::Rc::new(std::cell::Cell::new(0));
        let stores = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut runtime = Runtime::for_tests();
        runtime.biometric = Box::new(CountingBiometricProvider::default());
        runtime.secure_storage = Box::new(EarlyAuthorizingSecureStorageProvider::new(
            authorizations.clone(),
            stores.clone(),
        ));
        let (_dir, _opened) = open_unlocked_demo_vault(&mut runtime);

        runtime
            .enroll_quick_unlock_for_current_vault(Some("wrong-password"), None)
            .expect_err("wrong credentials must not be enrolled");

        assert_eq!(authorizations.get(), 1);
        assert_eq!(stores.get(), 0);
    }

    #[test]
    fn native_parent_window_handle_is_forwarded_to_secure_storage() {
        let parent_window = std::rc::Rc::new(std::cell::Cell::new(None));
        let mut runtime = Runtime::for_tests();
        runtime.secure_storage = Box::new(ParentWindowRecordingSecureStorageProvider {
            parent_window: parent_window.clone(),
        });

        runtime.set_parent_window_handle(Some(0x1234));
        assert_eq!(parent_window.get(), Some(0x1234));

        runtime.set_parent_window_handle(None);
        assert_eq!(parent_window.get(), None);
    }

    #[test]
    fn passkey_quick_unlock_user_verification_reuses_same_ceremony_unlock() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("demo-password");

        let bytes = core
            .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, bytes).unwrap();

        let authorizations = std::rc::Rc::new(RefCell::new(Vec::new()));
        let mut runtime = Runtime::for_tests_at(100);
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
            authorizations.borrow().as_slice(),
            [
                "Enable quick unlock for this vault".to_owned(),
                "Unlock this vault".to_owned(),
            ]
        );
    }
}
