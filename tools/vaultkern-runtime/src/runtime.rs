use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::form_urlencoded::byte_serialize;
use uuid::Uuid;
use vaultkern_core::{
    AttachmentContentUpdate, AttachmentMetadataUpdate, CompositeKey, Compression, CoreError, Entry,
    EntryAttachmentInput, EntryCreate, EntryCustomFieldInput, EntryTimesUpdate, EntryUpdate,
    KdbxCipher, KdbxError, KeepassCore, PasskeyRecord, SaveKdf, SaveProfile, TotpSpec, Vault,
};
use vaultkern_runtime_protocol::{
    DatabaseEncryptionSettingsDto, DatabaseHistorySettingsDto, DatabaseKdfSettingsDto,
    DatabaseMetadataSettingsDto, DatabasePublicMetadataSettingsDto, DatabaseRecycleBinSettingsDto,
    DatabaseSettingsDto, DatabaseSettingsUpdateDto, EntryAttachmentContentDto, EntryAttachmentDto,
    EntryCustomFieldDto, EntryDetailDto, EntryFieldProtectionDto, EntryHistoryDetailDto,
    EntryHistoryItemDto, EntryHistoryListDto, EntryListDto, EntryPasskeyDto, EntrySummaryDto,
    ErrorDto, FillCandidateListDto, GroupNodeDto, GroupTreeDto, MergeSummaryDto,
    PasskeyAssertionDto, PasskeyCeremonyAdvancedDto, PasskeyCeremonyDeliveryStateDto,
    PasskeyCeremonyDurableStateDto, PasskeyCeremonyKindDto, PasskeyCeremonyLedgerDto,
    PasskeyCeremonyPhaseDto, PasskeyCeremonyReconciledDto, PasskeyCeremonyReconciliationDto,
    PasskeyCeremonyRegisteredDto, PasskeyCeremonyVaultBoundDto, PasskeyCredentialCandidateDto,
    PasskeyCredentialListDto, PasskeyCredentialStatusDto, PasskeyFrameKindDto,
    PasskeyRegistrationDto, PasskeyUserVerificationCapabilityDto, PasskeyUserVerificationMethodDto,
    PasskeyUserVerificationRequirementDto, PasskeyUserVerifiedDto, RuntimeCommand, RuntimeResponse,
    SaveVaultResultDto, SaveVaultStatusDto, VaultHandleDto, VaultReferenceDto,
    VaultReferenceListDto, VaultSourceStatusDto,
};

use crate::command_loop::format_error_chain;
use crate::match_fill::{FillMatchScore, score_entry_match};
use crate::passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, create_assertion,
    create_registration_with_credential_id, generate_passkey_credential_id,
};
use crate::providers::biometric::{
    BiometricProvider, TestBiometricProvider, UnsupportedBiometricProvider,
    default_biometric_provider,
};
use crate::providers::local_file::{LocalFileVaultSourceProvider, VaultSourceFingerprint};
use crate::providers::onedrive::{OneDriveMemoryAccessCounts, OneDriveVaultSourceProvider};
use crate::providers::remote_cache::{RemoteCacheKey, RemoteVaultCache, RemoteVaultCacheEntry};
use crate::providers::secure_storage::{
    FailingContainsSecureStorageProvider, FailingDeleteSecureStorageProvider,
    FailingStoreSecureStorageProvider, MemorySecureStorageProvider, SecureStorageProvider,
    UnsupportedSecureStorageProvider, default_secure_storage_provider,
    default_secure_storage_provider_for_extension_id,
};
use crate::session::SessionState;
use crate::state_paths::extension_id_from_browser_origin;
use crate::vault_reference_store::{StoredVaultSource, VaultReferenceStore};

struct LoadedVault {
    source: VaultSource,
    name: String,
    bytes: Vec<u8>,
    baseline_fingerprint: VaultSourceFingerprint,
    password: Option<String>,
    key_file_path: Option<String>,
    save_profile: SaveProfile,
    autosave_delay_seconds: Option<u32>,
    vault: Option<Vault>,
    source_status: Option<VaultSourceStatusDto>,
    source_account_label: Option<String>,
    quick_unlock_refresh_pending: bool,
}

impl LoadedVault {
    fn clear_unlock_secrets(&mut self) {
        self.password = None;
        self.key_file_path = None;
        self.vault = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VaultSource {
    LocalPath(String),
    OneDriveItem { drive_id: String, item_id: String },
}

struct LoadedSourceSnapshot {
    bytes: Option<Vec<u8>>,
    fingerprint: VaultSourceFingerprint,
    one_drive_etag: Option<String>,
}

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

impl VaultSource {
    fn vault_id(&self) -> String {
        match self {
            Self::LocalPath(path) => path.clone(),
            Self::OneDriveItem { drive_id, item_id } => {
                format!("onedrive:{drive_id}:{item_id}")
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct VaultCredentials {
    password: Option<String>,
    key_file_path: Option<String>,
}

impl VaultCredentials {
    fn from_parts(password: Option<&str>, key_file_path: Option<&str>) -> Result<Self> {
        let password = password.map(ToOwned::to_owned);
        let key_file_path = key_file_path
            .map(normalize_local_path)
            .transpose()
            .context("invalid key file path")?;
        if password.is_none() && key_file_path.is_none() {
            anyhow::bail!("no unlock credentials provided");
        }
        Ok(Self {
            password,
            key_file_path,
        })
    }
}

pub struct Runtime {
    core: KeepassCore,
    session: SessionState,
    references: VaultReferenceStore,
    local_files: LocalFileVaultSourceProvider,
    one_drive: OneDriveVaultSourceProvider,
    remote_cache: RemoteVaultCache,
    biometric: Box<dyn BiometricProvider>,
    secure_storage: Box<dyn SecureStorageProvider>,
    loaded: BTreeMap<String, LoadedVault>,
    passkey_ceremonies: BTreeMap<String, PasskeyCeremonyLedgerEntry>,
    recent_unlock_user_verification: Option<PasskeyUserVerificationProof>,
    passkey_credential_id_generator: Box<dyn FnMut() -> String>,
    fixed_unix_time: Option<u64>,
}

impl Runtime {
    pub fn new() -> Self {
        Self::new_with_state(
            VaultReferenceStore::new_default(),
            OneDriveVaultSourceProvider::new_from_env(),
            RemoteVaultCache::new_default(),
            default_secure_storage_provider(),
        )
    }

    pub fn new_for_browser_origin(origin: &str) -> Self {
        if let Some(extension_id) = extension_id_from_browser_origin(origin) {
            return Self::new_with_state(
                VaultReferenceStore::new_for_extension_id(extension_id),
                OneDriveVaultSourceProvider::new_from_env_for_extension_id(extension_id),
                RemoteVaultCache::new_for_extension_id(extension_id),
                default_secure_storage_provider_for_extension_id(Some(extension_id)),
            );
        }

        Self::new()
    }

    fn new_with_state(
        references: VaultReferenceStore,
        one_drive: OneDriveVaultSourceProvider,
        remote_cache: RemoteVaultCache,
        secure_storage: Box<dyn SecureStorageProvider>,
    ) -> Self {
        let mut session = SessionState::default();
        if let Some(vault_ref_id) = references.current_vault_ref_id() {
            session.set_current_vault(vault_ref_id.to_owned());
        }

        Self {
            core: KeepassCore::new(),
            session,
            references,
            local_files: LocalFileVaultSourceProvider,
            one_drive,
            remote_cache,
            biometric: default_biometric_provider(),
            secure_storage,
            loaded: BTreeMap::new(),
            passkey_ceremonies: BTreeMap::new(),
            recent_unlock_user_verification: None,
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
        }
    }

    pub fn for_tests() -> Self {
        Self {
            core: KeepassCore::new(),
            session: SessionState::default(),
            references: VaultReferenceStore::new_in_memory(),
            local_files: LocalFileVaultSourceProvider,
            one_drive: OneDriveVaultSourceProvider::new_in_memory(),
            remote_cache: RemoteVaultCache::new_at(std::env::temp_dir().join(format!(
                "vaultkern-runtime-test-remote-cache-{}",
                uuid::Uuid::new_v4()
            ))),
            biometric: Box::new(UnsupportedBiometricProvider),
            secure_storage: Box::new(UnsupportedSecureStorageProvider),
            loaded: BTreeMap::new(),
            passkey_ceremonies: BTreeMap::new(),
            recent_unlock_user_verification: None,
            passkey_credential_id_generator: Box::new(generate_passkey_credential_id),
            fixed_unix_time: None,
        }
    }

    pub fn for_tests_at(unix_time: u64) -> Self {
        let mut runtime = Self::for_tests();
        runtime.fixed_unix_time = Some(unix_time);
        runtime
    }

    pub fn set_test_unix_time(&mut self, unix_time: u64) {
        self.fixed_unix_time = Some(unix_time);
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

    pub fn for_tests_with_quick_unlock_failing_store_after(stores_before_failure: usize) -> Self {
        let mut runtime = Self::for_tests();
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(FailingStoreSecureStorageProvider::new(
            stores_before_failure,
        ));
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
        runtime.remote_cache = RemoteVaultCache::new_at(cache_dir);
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

    pub fn reset_test_onedrive_access_counts(&self) {
        self.one_drive.reset_memory_access_counts();
    }

    pub fn test_onedrive_access_counts(&self) -> OneDriveMemoryAccessCounts {
        self.one_drive.memory_access_counts()
    }

    pub fn open_local_vault(&mut self, path: &str) -> Result<VaultHandleDto> {
        let path = normalize_local_path(path)?;
        self.load_local_vault_snapshot(&path)
    }

    fn load_local_vault_snapshot(&mut self, path: &str) -> Result<VaultHandleDto> {
        let snapshot = self
            .local_files
            .read_snapshot(&path)
            .with_context(|| format!("failed to read vault: {path}"))?;
        let bytes = snapshot.bytes;
        let baseline_fingerprint = snapshot.fingerprint;
        let vault_id = path.to_owned();
        let name = Path::new(&path)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or(&path)
            .to_owned();
        let reference = self
            .references
            .upsert_local_path(&path, self.current_unix_time() as i64)?;
        self.session
            .set_current_vault(reference.vault_ref_id.clone());

        self.loaded.insert(
            vault_id.clone(),
            LoadedVault {
                source: VaultSource::LocalPath(path.to_owned()),
                name: name.clone(),
                bytes,
                baseline_fingerprint,
                password: None,
                key_file_path: None,
                save_profile: SaveProfile::recommended(),
                autosave_delay_seconds: None,
                vault: None,
                source_status: None,
                source_account_label: None,
                quick_unlock_refresh_pending: false,
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

                self.loaded.insert(
                    vault_id.clone(),
                    LoadedVault {
                        source: vault_source,
                        name: name.clone(),
                        bytes,
                        baseline_fingerprint,
                        password: None,
                        key_file_path: None,
                        save_profile: SaveProfile::recommended(),
                        autosave_delay_seconds: None,
                        vault: None,
                        source_status,
                        source_account_label,
                        quick_unlock_refresh_pending: false,
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
        let Some(current_vault_ref_id) = self.session.current_vault_ref_id().map(ToOwned::to_owned)
        else {
            return Ok(());
        };
        let source = self.references.source_for(&current_vault_ref_id)?;

        let vault_id = vault_id_for_stored_source(&source);
        if self.loaded.contains_key(&vault_id) {
            return Ok(());
        }

        self.load_source_snapshot(source)?;
        Ok(())
    }

    pub fn add_local_vault_reference(&mut self, path: &str) -> Result<VaultReferenceDto> {
        let path = normalize_local_path(path)?;
        let reference = self
            .references
            .upsert_local_path(&path, self.current_unix_time() as i64)?;
        self.session
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
        self.session
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
                    Err(_) => {
                        let _ = self.secure_storage.delete(&storage_key);
                        false
                    }
                };
            }
        }
        Ok(list)
    }

    pub fn set_current_vault(&mut self, vault_ref_id: &str) -> Result<()> {
        self.references
            .mark_current(vault_ref_id, self.current_unix_time() as i64)?;
        self.session.set_current_vault(vault_ref_id.to_owned());
        Ok(())
    }

    pub fn delete_vault_reference(&mut self, vault_ref_id: &str) -> Result<VaultReferenceListDto> {
        let source = self.references.source_for(vault_ref_id).ok();
        let deleted_current = self.references.delete(vault_ref_id)?;
        let _ = self
            .secure_storage
            .delete(&quick_unlock_storage_key(vault_ref_id));
        if let Some(cache_key) = source.as_ref().and_then(remote_cache_key_for_stored_source) {
            self.remote_cache.delete(&cache_key)?;
        }
        if deleted_current {
            self.session.clear_current_vault();
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
        let credentials = VaultCredentials::from_parts(password, key_file_path)?;
        let current_vault_ref_id = self
            .references
            .find_ref_id_by_path(vault_id)
            .or_else(|| self.session.current_vault_ref_id().map(ToOwned::to_owned));
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;

        let key = composite_key_from_credentials(&credentials)?;

        let database = self
            .core
            .load_database(&loaded.bytes, &key)
            .with_context(|| format!("failed to unlock vault: {vault_id}"))?;
        loaded.name = database.vault.name.clone();
        loaded.password = credentials.password;
        loaded.key_file_path = credentials.key_file_path;
        loaded.vault = Some(database.vault);
        self.session
            .unlock(vault_id.to_owned(), current_vault_ref_id);
        self.recent_unlock_user_verification = None;
        Ok(())
    }

    pub fn unlock_current_vault_with_password(&mut self, password: &str) -> Result<()> {
        let current_vault_ref_id = self
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let source = self.references.source_for(&current_vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        if self.loaded.contains_key(&vault_id) {
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
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let source = self.references.source_for(&current_vault_ref_id)?;
        let vault_id = vault_id_for_stored_source(&source);
        if self.loaded.contains_key(&vault_id) {
            return self.unlock_vault(&vault_id, password, key_file_path);
        }

        let handle = self.load_source_snapshot(source)?;
        self.unlock_vault(&handle.vault_id, password, key_file_path)
    }

    pub fn lock_session(&mut self) {
        for loaded in self.loaded.values_mut() {
            loaded.clear_unlock_secrets();
        }
        self.recent_unlock_user_verification = None;
        self.session.lock();
    }

    pub fn enable_quick_unlock_for_current_vault(&mut self) -> Result<()> {
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("biometric quick unlock is not implemented on this host");
        }
        let current_vault_ref_id = self
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        let active_vault_id = self
            .session
            .active_vault_id()
            .context("current vault is locked")?
            .to_owned();
        let loaded = self
            .loaded
            .get(&active_vault_id)
            .with_context(|| format!("vault not opened: {active_vault_id}"))?;
        let credentials = VaultCredentials {
            password: loaded.password.clone(),
            key_file_path: loaded.key_file_path.clone(),
        };
        if credentials.password.is_none() && credentials.key_file_path.is_none() {
            anyhow::bail!("current vault has no reusable unlock credentials");
        }

        self.biometric
            .authorize("Enable quick unlock for this vault")?;
        let bytes = serde_json::to_vec(&credentials)
            .context("failed to encode quick unlock credentials")?;
        self.secure_storage
            .store(&quick_unlock_storage_key(&current_vault_ref_id), &bytes)
    }

    pub fn unlock_current_vault_with_quick_unlock(&mut self) -> Result<()> {
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("biometric quick unlock is not implemented on this host");
        }
        let current_vault_ref_id = self
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        self.biometric.authorize("Unlock this vault")?;
        let bytes = self
            .secure_storage
            .load(&quick_unlock_storage_key(&current_vault_ref_id))?
            .context("quick unlock is not enabled for the current vault")?;
        let credentials: VaultCredentials =
            serde_json::from_slice(&bytes).context("failed to decode quick unlock credentials")?;
        let storage_key = quick_unlock_storage_key(&current_vault_ref_id);
        match self.unlock_current_vault(
            credentials.password.as_deref(),
            credentials.key_file_path.as_deref(),
        ) {
            Ok(()) => {
                let active_vault_id = self.session.active_vault_id().map(ToOwned::to_owned);
                if let Some(active_vault_id) = active_vault_id {
                    self.record_recent_unlock_user_verification(
                        &active_vault_id,
                        PasskeyUserVerificationMethodDto::QuickUnlock,
                    );
                }
                Ok(())
            }
            Err(error) => {
                if is_unlock_credentials_error(&error) {
                    self.secure_storage.delete(&storage_key)?;
                }
                Err(error)
            }
        }
    }

    pub fn disable_quick_unlock_for_current_vault(&mut self) -> Result<()> {
        let current_vault_ref_id = self
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?
            .to_owned();
        self.secure_storage
            .delete(&quick_unlock_storage_key(&current_vault_ref_id))
    }

    pub fn session_state(&self) -> vaultkern_runtime_protocol::SessionStateDto {
        let mut dto = self.session.to_dto(self.biometric.supports_quick_unlock());
        dto.source_status = self.current_source_status();
        dto
    }

    pub fn passkey_user_verification_capability(&self) -> PasskeyUserVerificationCapabilityDto {
        let mut methods = Vec::new();
        let Some(active_vault_id) = self.session.active_vault_id() else {
            return PasskeyUserVerificationCapabilityDto {
                available: false,
                methods,
            };
        };
        let Some(loaded) = self.loaded.get(active_vault_id) else {
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

        if loaded.password.is_some() {
            methods.push(PasskeyUserVerificationMethodDto::MasterPassword);
        }

        if self.biometric.supports_quick_unlock() {
            if let Some(vault_ref_id) = self.session.current_vault_ref_id() {
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
        if expected_phase != PasskeyCeremonyPhaseDto::UserAuthorization {
            anyhow::bail!("passkey user verification expected phase must be s1_user_authorization");
        }
        if self.session.active_vault_id() != Some(vault_id) {
            anyhow::bail!("passkey user verification vault mismatch");
        }
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
        let recent_unlock_verified = {
            let entry = self
                .passkey_ceremonies
                .get(ceremony_token)
                .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
            if entry.phase != expected_phase {
                anyhow::bail!("passkey ceremony phase mismatch");
            }
            validate_passkey_ceremony_not_expired(entry, now_epoch_ms)?;
            validate_passkey_ceremony_vault_binding(entry, vault_id)?;
            self.recent_unlock_user_verification_matches(entry, vault_id, method, now_epoch_ms)
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

        let entry = self
            .passkey_ceremonies
            .get_mut(ceremony_token)
            .with_context(|| format!("passkey ceremony not registered: {ceremony_token}"))?;
        bind_passkey_ceremony_vault(entry, vault_id)?;
        entry.user_verification = Some(PasskeyUserVerificationProof {
            vault_id: vault_id.to_owned(),
            method,
            verified_at_epoch_ms: now_epoch_ms,
        });
        Ok(PasskeyUserVerifiedDto {
            verified: true,
            method,
            verified_at_epoch_ms: now_epoch_ms as i64,
        })
    }

    fn record_recent_unlock_user_verification(
        &mut self,
        vault_id: &str,
        method: PasskeyUserVerificationMethodDto,
    ) {
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        let loaded = self
            .loaded
            .get(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        if loaded.vault.is_none() {
            anyhow::bail!("vault is locked: {vault_id}");
        }
        if loaded.password.is_none() {
            anyhow::bail!("passkey master password verification is unavailable");
        }
        let credentials = VaultCredentials {
            password: Some(password.to_owned()),
            key_file_path: loaded.key_file_path.clone(),
        };
        let key = composite_key_from_credentials(&credentials)?;
        self.core
            .load_database(&loaded.bytes, &key)
            .with_context(|| format!("failed to verify passkey user for vault: {vault_id}"))?;
        Ok(())
    }

    fn verify_passkey_user_with_quick_unlock(&self, vault_id: &str) -> Result<()> {
        if !self.biometric.supports_quick_unlock() {
            anyhow::bail!("passkey quick unlock verification is unavailable");
        }
        let current_vault_ref_id = self
            .session
            .current_vault_ref_id()
            .context("no current vault selected")?;
        let loaded = self
            .loaded
            .get(vault_id)
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
            .loaded
            .get(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let vault = loaded
            .vault
            .as_ref()
            .with_context(|| format!("vault is locked: {vault_id}"))?;

        Ok(database_settings_dto(
            vault,
            &loaded.save_profile,
            loaded.autosave_delay_seconds,
            loaded.password.is_some(),
        ))
    }

    pub fn update_database_settings(
        &mut self,
        vault_id: &str,
        update: DatabaseSettingsUpdateDto,
    ) -> Result<DatabaseSettingsDto> {
        let settings = {
            let loaded = self
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

            if let Some(metadata) = update.metadata {
                vault.name = metadata.name.clone();
                vault.root.title = metadata.name;
                vault.description = empty_string_as_none(metadata.description);
                vault.default_username = empty_string_as_none(metadata.default_username);
            }

            if let Some(public_metadata) = update.public_metadata {
                upsert_optional_public_string(
                    vault,
                    "display-name",
                    public_metadata.display_name.as_deref(),
                );
                upsert_optional_public_string(vault, "color", public_metadata.color.as_deref());
                upsert_optional_public_string(vault, "icon", public_metadata.icon.as_deref());
            }

            if let Some(history) = update.history {
                vault.history_max_items = history.max_items_per_entry;
                vault.history_max_size = history.max_total_size_bytes;
            }

            if let Some(recycle_bin) = update.recycle_bin {
                vault.recycle_bin_enabled = Some(recycle_bin.enabled);
            }

            if let Some(encryption) = update.encryption {
                loaded.save_profile = save_profile_from_settings(encryption)?;
            }

            if let Some(credentials) = update.credentials {
                if credentials.remove_password {
                    loaded.password = None;
                } else if let Some(password) = credentials.new_password {
                    loaded.password = Some(password);
                }
                loaded.quick_unlock_refresh_pending = true;
            }

            if let Some(autosave_delay_seconds) = update.autosave_delay_seconds {
                loaded.autosave_delay_seconds = Some(autosave_delay_seconds);
            }

            database_settings_dto(
                vault,
                &loaded.save_profile,
                loaded.autosave_delay_seconds,
                loaded.password.is_some(),
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
        let entry_id = {
            let loaded = self
                .loaded
                .get_mut(vault_id)
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

            if let Some(totp) = parse_totp_uri(totp_uri)? {
                self.core.set_entry_totp(vault, &created.id, totp)?;
            }

            touch_entry_modified_at(&self.core, vault, &created.id, modified_at)?;

            created.id
        };

        self.get_entry_detail(vault_id, &entry_id)
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
        {
            let loaded = self
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;

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

            match parse_totp_uri(totp_uri)? {
                Some(totp) => {
                    self.core.set_entry_totp(vault, entry_id, totp)?;
                }
                None => {
                    self.core.clear_entry_totp(vault, entry_id)?;
                }
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

    pub fn clear_entry_totp(&mut self, vault_id: &str, entry_id: &str) -> Result<EntryDetailDto> {
        let modified_at = self.current_unix_time();
        {
            let loaded = self
                .loaded
                .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            self.core.snapshot_entry_to_history(vault, entry_id)?;
            self.core
                .set_entry_passkey(vault, entry_id, dto_to_passkey_record(passkey))?;
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
                .loaded
                .get_mut(vault_id)
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
        self.validate_passkey_ceremony_for_s4(
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
        if !user_presence_verified && !user_verified {
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
                user_presence_verified,
                user_verified,
                related_origin_verified,
                client_data_json_base64url,
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
    ) -> Result<()> {
        if expected_phase != PasskeyCeremonyPhaseDto::CompletionAndMutation {
            anyhow::bail!("passkey ceremony expected phase must be s4_completion_and_mutation");
        }
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        Ok(())
    }

    fn passkey_ceremony_user_verified(&self, ceremony_token: &str, vault_id: &str) -> Result<bool> {
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        Ok(PasskeyCredentialStatusDto {
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
        let mut credentials = Vec::new();
        visit_passkeys(
            &vault.root,
            vault.recycle_bin_group,
            vault.recycle_bin_enabled.unwrap_or(true),
            &mut |passkey| {
                if passkey.relying_party == relying_party {
                    credentials.push(PasskeyCredentialCandidateDto {
                        credential_id: passkey.credential_id.clone(),
                        username: passkey.username.clone(),
                        user_handle: passkey.user_handle.clone(),
                    });
                }
            },
        );

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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
        self.prune_expired_closed_passkey_ceremonies(now_epoch_ms);
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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

    fn prune_expired_closed_passkey_ceremonies(&mut self, now_epoch_ms: u64) {
        self.passkey_ceremonies.retain(|_, entry| {
            !is_closed_passkey_ceremony_phase(entry.phase)
                || entry.identity.expires_at_epoch_ms > now_epoch_ms
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
        self.validate_passkey_ceremony_for_s4(
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
            },
            credential_id,
        )?;
        let _ = self.loaded_vault(vault_id)?;
        self.bind_passkey_ceremony_vault_after_vault_lookup(ceremony_token, vault_id)?;
        let mut response = registration.dto;

        let (existing, credential_id_collision_count) = {
            let loaded = self
                .loaded
                .get_mut(vault_id)
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
                    rollback_entry: Some(rollback_entry.clone()),
                },
                PasskeyCeremonyDurableStateDto::Snapshot,
            )?;
            let loaded = self
                .loaded
                .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let vault = loaded
                .vault
                .as_mut()
                .with_context(|| format!("vault is locked: {vault_id}"))?;
            vault.root.entries.push(created_entry);
            self.core
                .set_entry_passkey(vault, &entry_id, registration.passkey)?;
            touch_entry_modified_at(&self.core, vault, &entry_id, modified_at)?;
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
                self.save_vault(&vault_id)?;
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
            .loaded
            .get_mut(&rollback.vault_id)
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
        let now_epoch_ms = self.current_unix_time().saturating_mul(1000);
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
            .loaded
            .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
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
                .loaded
                .get_mut(vault_id)
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
            RuntimeCommand::EnableQuickUnlockForCurrentVault => self
                .enable_quick_unlock_for_current_vault()
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
            RuntimeCommand::SaveVault { vault_id } => self.save_vault(&vault_id),
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
            RuntimeCommand::UpdateEntry { .. } => Ok(RuntimeResponse::Error(ErrorDto {
                code: "unsupported".into(),
                message: "command is not implemented yet".into(),
            })),
        }
    }

    pub fn save_vault(&mut self, vault_id: &str) -> Result<RuntimeResponse> {
        let (key, baseline_fingerprint, save_profile, source, display_name, account_label) = {
            let loaded = self
                .loaded
                .get(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            (
                composite_key_from_loaded_vault(loaded)?,
                loaded.baseline_fingerprint.clone(),
                loaded.save_profile.clone(),
                loaded.source.clone(),
                loaded.name.clone(),
                loaded.source_account_label.clone(),
            )
        };
        let current = match self.read_current_snapshot(vault_id, Some(&baseline_fingerprint)) {
            Ok(current) => current,
            Err(error) => {
                if remote_cache_key_for_source(&source).is_some() {
                    let remote_error = format_error_chain(&error);
                    let bytes = self.save_loaded_vault_bytes(vault_id, &key, save_profile)?;
                    return self.save_remote_vault_to_pending_cache(
                        vault_id,
                        source,
                        bytes,
                        display_name,
                        account_label,
                        remote_error,
                    );
                }
                return Err(error)
                    .with_context(|| format!("failed to read current vault source: {vault_id}"));
            }
        };

        let (bytes, merge_summary) = {
            let loaded = self
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            let Some(vault) = loaded.vault.as_mut() else {
                anyhow::bail!("vault is locked: {vault_id}");
            };
            let merge_summary = if current.fingerprint == baseline_fingerprint {
                None
            } else {
                let current_bytes = current.bytes.as_deref().with_context(|| {
                    format!("changed vault source did not include bytes: {vault_id}")
                })?;
                let summary = self
                    .core
                    .load_and_merge_kdbx(vault, current_bytes, &key)
                    .with_context(|| format!("failed to merge current vault source: {vault_id}"))?;
                Some(MergeSummaryDto {
                    merged_entries: summary.merged_entries,
                    history_snapshots_added: summary.history_snapshots_added,
                })
            };
            let bytes = save_kdbx_with_history_limits(&self.core, vault, &key, save_profile)
                .with_context(|| format!("failed to save vault: {vault_id}"))?;
            (bytes, merge_summary)
        };

        let write_fingerprint =
            match self.write_source(vault_id, &bytes, current.one_drive_etag.as_deref()) {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    if remote_cache_key_for_source(&source).is_some() {
                        let remote_error = format_error_chain(&error);
                        return self.save_remote_vault_to_pending_cache(
                            vault_id,
                            source,
                            bytes,
                            display_name,
                            account_label,
                            remote_error,
                        );
                    }
                    return Err(error)
                        .with_context(|| format!("failed to write vault: {vault_id}"));
                }
            };
        let (next_bytes, next_fingerprint) = if let Some(fingerprint) = write_fingerprint {
            (bytes, fingerprint)
        } else {
            let refreshed = self
                .read_current_snapshot(vault_id, None)
                .with_context(|| format!("failed to refresh saved vault source: {vault_id}"))?;
            (
                refreshed.bytes.with_context(|| {
                    format!("refreshed vault source did not include bytes: {vault_id}")
                })?,
                refreshed.fingerprint,
            )
        };
        let next_source_status = if let Some(cache_key) = remote_cache_key_for_source(&source) {
            let cached_at = self.current_unix_time() as i64;
            let account_label = account_label.unwrap_or_else(|| cache_key.provider_kind.clone());
            self.remote_cache.write(
                &cache_key,
                RemoteVaultCacheEntry {
                    bytes: next_bytes.clone(),
                    fingerprint: next_fingerprint.clone(),
                    display_name,
                    account_label,
                    cached_at,
                    pending_sync: false,
                },
            )?;
            Some(VaultSourceStatusDto {
                source_kind: cache_key.provider_kind,
                remote_state: "online".into(),
                last_sync_at: Some(cached_at),
                cached_at: Some(cached_at),
                last_error: None,
            })
        } else {
            None
        };
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        if let Some(status) = next_source_status {
            loaded.source_status = Some(status);
        }
        loaded.bytes = next_bytes;
        loaded.baseline_fingerprint = next_fingerprint;
        self.refresh_quick_unlock_credentials_after_successful_save(vault_id)?;
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: if merge_summary.is_some() {
                SaveVaultStatusDto::Merged
            } else {
                SaveVaultStatusDto::Saved
            },
            merge_summary,
        }))
    }

    fn save_loaded_vault_bytes(
        &mut self,
        vault_id: &str,
        key: &CompositeKey,
        save_profile: SaveProfile,
    ) -> Result<Vec<u8>> {
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let Some(vault) = loaded.vault.as_mut() else {
            anyhow::bail!("vault is locked: {vault_id}");
        };
        save_kdbx_with_history_limits(&self.core, vault, key, save_profile)
            .with_context(|| format!("failed to save vault: {vault_id}"))
    }

    fn save_remote_vault_to_pending_cache(
        &mut self,
        vault_id: &str,
        source: VaultSource,
        bytes: Vec<u8>,
        display_name: String,
        account_label: Option<String>,
        remote_error: String,
    ) -> Result<RuntimeResponse> {
        let cache_key = remote_cache_key_for_source(&source).context("source is not remote")?;
        let cached_at = self.current_unix_time() as i64;
        let fingerprint = fingerprint_for_cached_bytes(&bytes, cached_at);
        let account_label = account_label.unwrap_or_else(|| cache_key.provider_kind.clone());
        self.remote_cache.write(
            &cache_key,
            RemoteVaultCacheEntry {
                bytes: bytes.clone(),
                fingerprint: fingerprint.clone(),
                display_name,
                account_label,
                cached_at,
                pending_sync: true,
            },
        )?;
        let status = VaultSourceStatusDto {
            source_kind: cache_key.provider_kind,
            remote_state: "pending_sync".into(),
            last_sync_at: None,
            cached_at: Some(cached_at),
            last_error: Some(remote_error),
        };
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.bytes = bytes;
        loaded.baseline_fingerprint = fingerprint;
        loaded.source_status = Some(status);
        self.refresh_quick_unlock_credentials_after_successful_save(vault_id)?;
        Ok(RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
            status: SaveVaultStatusDto::SavedToCache,
            merge_summary: None,
        }))
    }

    pub fn retry_vault_source_sync(&mut self, vault_id: &str) -> Result<VaultSourceStatusDto> {
        let (source, baseline_fingerprint, key, pending_sync) = {
            let loaded = self
                .loaded
                .get(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            (
                loaded.source.clone(),
                loaded.baseline_fingerprint.clone(),
                composite_key_from_loaded_vault(loaded).ok(),
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
        if pending_sync {
            return self.retry_pending_remote_vault_sync(
                vault_id,
                &drive_id,
                &item_id,
                cache_key,
                baseline_fingerprint,
                key.as_ref(),
            );
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
                if let Some(loaded) = self.loaded.get_mut(vault_id) {
                    loaded.source_status = Some(status.clone());
                }
                Ok(status)
            }
            Ok(state) => {
                let snapshot = self
                    .one_drive
                    .read_snapshot_from_state(&drive_id, &item_id, &state)?;
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
                let status = VaultSourceStatusDto {
                    source_kind: cache_key.provider_kind,
                    remote_state: "online".into(),
                    last_sync_at: Some(cached_at),
                    cached_at: Some(cached_at),
                    last_error: None,
                };

                let loaded = self
                    .loaded
                    .get_mut(vault_id)
                    .with_context(|| format!("vault not opened: {vault_id}"))?;
                if let (Some(vault), Some(key)) = (loaded.vault.as_mut(), key.as_ref()) {
                    if snapshot.fingerprint != baseline_fingerprint {
                        self.core.load_and_merge_kdbx(vault, &snapshot.bytes, key)?;
                    }
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
                if let Some(loaded) = self.loaded.get_mut(vault_id) {
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
        key: Option<&CompositeKey>,
    ) -> Result<VaultSourceStatusDto> {
        match self.try_upload_pending_remote_vault(
            vault_id,
            drive_id,
            item_id,
            &cache_key,
            &baseline_fingerprint,
            key,
        ) {
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
                if let Some(loaded) = self.loaded.get_mut(vault_id) {
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
        baseline_fingerprint: &VaultSourceFingerprint,
        key: Option<&CompositeKey>,
    ) -> Result<VaultSourceStatusDto> {
        let state = self.one_drive.remote_state(drive_id, item_id)?;
        let remote_snapshot = if state.matches_fingerprint(baseline_fingerprint) {
            None
        } else {
            Some(
                self.one_drive
                    .read_snapshot_from_state(drive_id, item_id, &state)?,
            )
        };

        let cached_at = self.current_unix_time() as i64;
        let (bytes, display_name, account_label) = {
            let loaded = self
                .loaded
                .get_mut(vault_id)
                .with_context(|| format!("vault not opened: {vault_id}"))?;
            if let Some(snapshot) = remote_snapshot.as_ref() {
                let (Some(vault), Some(key)) = (loaded.vault.as_mut(), key) else {
                    anyhow::bail!("pending remote vault requires unlock credentials to merge");
                };
                self.core.load_and_merge_kdbx(vault, &snapshot.bytes, key)?;
            }
            let bytes = if let (Some(vault), Some(key)) = (loaded.vault.as_mut(), key) {
                save_kdbx_with_history_limits(&self.core, vault, key, loaded.save_profile.clone())
                    .with_context(|| format!("failed to save vault: {vault_id}"))?
            } else {
                loaded.bytes.clone()
            };
            (
                bytes,
                loaded.name.clone(),
                loaded
                    .source_account_label
                    .clone()
                    .unwrap_or_else(|| cache_key.provider_kind.clone()),
            )
        };

        let write_fingerprint = self.one_drive.write_with_known_etag(
            drive_id,
            item_id,
            &bytes,
            state.e_tag.as_deref(),
        )?;
        self.remote_cache.write(
            cache_key,
            RemoteVaultCacheEntry {
                bytes: bytes.clone(),
                fingerprint: write_fingerprint.clone(),
                display_name,
                account_label,
                cached_at,
                pending_sync: false,
            },
        )?;
        let status = VaultSourceStatusDto {
            source_kind: cache_key.provider_kind.clone(),
            remote_state: "online".into(),
            last_sync_at: Some(cached_at),
            cached_at: Some(cached_at),
            last_error: None,
        };
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.bytes = bytes;
        loaded.baseline_fingerprint = write_fingerprint;
        loaded.source_status = Some(status.clone());
        Ok(status)
    }

    fn loaded_vault(&self, vault_id: &str) -> Result<&Vault> {
        let loaded = self
            .loaded
            .get(vault_id)
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
            .loaded
            .get(vault_id)
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
                    one_drive_etag: None,
                })
            }
            VaultSource::OneDriveItem { drive_id, item_id } => {
                let state = self.one_drive.remote_state(drive_id, item_id)?;
                if let Some(baseline) = baseline {
                    if state.matches_fingerprint(baseline) {
                        return Ok(LoadedSourceSnapshot {
                            bytes: None,
                            fingerprint: baseline.clone(),
                            one_drive_etag: state.e_tag,
                        });
                    }
                }
                let snapshot = self
                    .one_drive
                    .read_snapshot_from_state(drive_id, item_id, &state)?;
                Ok(LoadedSourceSnapshot {
                    bytes: Some(snapshot.bytes),
                    fingerprint: snapshot.fingerprint,
                    one_drive_etag: state.e_tag,
                })
            }
        }
    }

    fn write_source(
        &mut self,
        vault_id: &str,
        bytes: &[u8],
        one_drive_etag: Option<&str>,
    ) -> Result<Option<VaultSourceFingerprint>> {
        let source = self
            .loaded
            .get(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?
            .source
            .clone();
        match source {
            VaultSource::LocalPath(path) => {
                self.local_files.write(&path, bytes)?;
                Ok(None)
            }
            VaultSource::OneDriveItem { drive_id, item_id } => Ok(Some(
                self.one_drive
                    .write_with_known_etag(&drive_id, &item_id, bytes, one_drive_etag)?,
            )),
        }
    }

    fn current_unix_time(&self) -> u64 {
        self.fixed_unix_time.unwrap_or_else(current_unix_time)
    }

    fn current_source_status(&self) -> Option<VaultSourceStatusDto> {
        if let Some(active_vault_id) = self.session.active_vault_id() {
            return self
                .loaded
                .get(active_vault_id)
                .and_then(|loaded| loaded.source_status.clone());
        }

        let current_vault_ref_id = self.session.current_vault_ref_id()?;
        let source = self.references.source_for(current_vault_ref_id).ok()?;
        let vault_id = vault_id_for_stored_source(&source);
        self.loaded
            .get(&vault_id)
            .and_then(|loaded| loaded.source_status.clone())
    }

    fn vault_ref_id_for_loaded_vault(&self, vault_id: &str) -> Option<String> {
        if self.session.active_vault_id() == Some(vault_id) {
            if let Some(vault_ref_id) = self.session.current_vault_ref_id() {
                return Some(vault_ref_id.to_owned());
            }
        }

        self.references.find_ref_id_by_path(vault_id)
    }

    fn refresh_quick_unlock_credentials_after_successful_save(
        &mut self,
        vault_id: &str,
    ) -> Result<()> {
        let refresh_pending = self
            .loaded
            .get(vault_id)
            .is_some_and(|loaded| loaded.quick_unlock_refresh_pending);
        if !refresh_pending {
            return Ok(());
        }

        if !self.biometric.supports_quick_unlock() {
            self.clear_quick_unlock_refresh_pending(vault_id)?;
            return Ok(());
        }
        let Some(vault_ref_id) = self.vault_ref_id_for_loaded_vault(vault_id) else {
            self.clear_quick_unlock_refresh_pending(vault_id)?;
            return Ok(());
        };
        let storage_key = quick_unlock_storage_key(&vault_ref_id);
        let contains_quick_unlock = match self.secure_storage.contains(&storage_key) {
            Ok(contains) => contains,
            Err(_) => {
                let _ = self.secure_storage.delete(&storage_key);
                self.clear_quick_unlock_refresh_pending(vault_id)?;
                return Ok(());
            }
        };
        if !contains_quick_unlock {
            self.clear_quick_unlock_refresh_pending(vault_id)?;
            return Ok(());
        }

        let loaded = self
            .loaded
            .get(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        let credentials = VaultCredentials {
            password: loaded.password.clone(),
            key_file_path: loaded.key_file_path.clone(),
        };

        if credentials.password.is_none() && credentials.key_file_path.is_none() {
            let _ = self.secure_storage.delete(&storage_key);
            self.clear_quick_unlock_refresh_pending(vault_id)?;
            return Ok(());
        }

        let bytes = serde_json::to_vec(&credentials)
            .context("failed to encode quick unlock credentials")?;
        if self.secure_storage.store(&storage_key, &bytes).is_err() {
            let _ = self.secure_storage.delete(&storage_key);
        }
        self.clear_quick_unlock_refresh_pending(vault_id)?;
        Ok(())
    }

    fn clear_quick_unlock_refresh_pending(&mut self, vault_id: &str) -> Result<()> {
        let loaded = self
            .loaded
            .get_mut(vault_id)
            .with_context(|| format!("vault not opened: {vault_id}"))?;
        loaded.quick_unlock_refresh_pending = false;
        Ok(())
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

fn dto_to_passkey_record(passkey: EntryPasskeyDto) -> PasskeyRecord {
    PasskeyRecord {
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

fn save_kdbx_with_history_limits(
    core: &KeepassCore,
    vault: &mut Vault,
    key: &CompositeKey,
    save_profile: SaveProfile,
) -> std::result::Result<Vec<u8>, KdbxError> {
    if vault.history_max_items.is_none() && vault.history_max_size.is_none() {
        return core.save_kdbx(vault, key, save_profile);
    }

    let mut history_snapshots = clone_entry_histories(&vault.root).into_iter();
    enforce_history_limits(vault);
    let result = core.save_kdbx(vault, key, save_profile);
    restore_entry_histories(&mut vault.root, &mut history_snapshots);
    result
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
        encryption: encryption_settings_dto(profile),
        autosave_delay_seconds,
        has_password,
    }
}

fn encryption_settings_dto(profile: &SaveProfile) -> DatabaseEncryptionSettingsDto {
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
        kdf: match profile.kdf {
            SaveKdf::AesKdbx4 { rounds } => DatabaseKdfSettingsDto {
                algorithm: "aes_kdbx4".into(),
                transform_rounds: Some(rounds),
                iterations: None,
                memory_kib: None,
                parallelism: None,
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
        "argon2id" => SaveKdf::Argon2id {
            iterations: settings
                .kdf
                .iterations
                .context("argon2id requires iterations")?,
            memory_kib: settings
                .kdf
                .memory_kib
                .context("argon2id requires memory_kib")?,
            parallelism: settings
                .kdf
                .parallelism
                .context("argon2id requires parallelism")?,
        },
        value => anyhow::bail!("unsupported kdf setting: {value}"),
    };

    Ok(SaveProfile {
        version: vaultkern_core::KdbxVersion::V4_1,
        cipher,
        compression,
        kdf,
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

fn empty_string_as_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
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
        } => format!("onedrive:{drive_id}:{item_id}"),
    }
}

fn remote_cache_key_for_source(source: &VaultSource) -> Option<RemoteCacheKey> {
    match source {
        VaultSource::LocalPath(_) => None,
        VaultSource::OneDriveItem { drive_id, item_id } => Some(RemoteCacheKey::new(
            "onedrive",
            &format!("{drive_id}:{item_id}"),
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
            &format!("{drive_id}:{item_id}"),
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

fn composite_key_from_loaded_vault(loaded: &LoadedVault) -> Result<CompositeKey> {
    composite_key_from_credentials(&VaultCredentials {
        password: loaded.password.clone(),
        key_file_path: loaded.key_file_path.clone(),
    })
}

fn composite_key_from_credentials(credentials: &VaultCredentials) -> Result<CompositeKey> {
    let mut key = CompositeKey::default();
    if let Some(password) = credentials.password.as_ref() {
        key.add_password(password.clone());
    }
    if let Some(key_file_path) = credentials.key_file_path.as_ref() {
        let bytes = fs::read(key_file_path)
            .with_context(|| format!("failed to read key file: {key_file_path}"))?;
        key.add_key_file_content(&bytes)
            .with_context(|| format!("failed to parse key file: {key_file_path}"))?;
    }
    Ok(key)
}

fn quick_unlock_storage_key(vault_ref_id: &str) -> String {
    let digest = Sha256::digest(vault_ref_id.as_bytes());
    let mut key = String::from("quick_unlock_");
    for byte in digest {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

fn is_unlock_credentials_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<KdbxError>(),
            Some(
                KdbxError::HeaderHmacMismatch
                    | KdbxError::PayloadHmacMismatch
                    | KdbxError::HeaderHashMismatch
                    | KdbxError::PayloadHashMismatch
            )
        ) || matches!(
            cause.downcast_ref::<CoreError>(),
            Some(CoreError::Kdbx(
                KdbxError::HeaderHmacMismatch
                    | KdbxError::PayloadHmacMismatch
                    | KdbxError::HeaderHashMismatch
                    | KdbxError::PayloadHashMismatch
            ))
        )
    })
}

fn query_error_response(error: anyhow::Error) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: "invalid_request".into(),
        message: format_error_chain(&error),
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

    match (expected_phase, next_phase) {
        (PreAuthorization, UserAuthorization) => true,
        (UserAuthorization, NetworkValidation) => !passkey_ceremony_origin_matches_relying_party(
            &identity.origin,
            &identity.relying_party,
        ),
        (UserAuthorization, CredentialResolution) => {
            passkey_ceremony_origin_matches_relying_party(&identity.origin, &identity.relying_party)
        }
        (NetworkValidation, CredentialResolution) => related_origin_verified,
        (CredentialResolution, UserSelection) => true,
        (CredentialResolution, CompletionAndMutation) => true,
        (UserSelection, CompletionAndMutation) => true,
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
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
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
    let host = parsed
        .host_str()
        .with_context(|| format!("invalid passkey ceremony {label} origin"))?
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
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
    let host = parsed
        .host_str()
        .context("passkey origin is missing a host")?
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
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
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use vaultkern_runtime_protocol::DatabaseCredentialsUpdateDto;

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

        fn delete(&self, key: &str) -> Result<()> {
            self.values.borrow_mut().remove(key);
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

        let loaded = runtime.loaded.get(&opened.vault_id).unwrap();
        assert!(!loaded.bytes.is_empty());
        assert!(loaded.vault.is_none());
        assert!(loaded.password.is_none());
        assert!(loaded.key_file_path.is_none());

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
        runtime.enable_quick_unlock_for_current_vault().unwrap();

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
        runtime.enable_quick_unlock_for_current_vault().unwrap();
        runtime.lock_session();

        let listed = runtime.list_recent_vaults().unwrap();

        assert_eq!(listed.vaults.len(), 1);
        assert!(listed.vaults[0].supports_quick_unlock);
    }

    #[test]
    fn listing_recent_vaults_treats_quick_unlock_probe_failures_as_disabled() {
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
        runtime.enable_quick_unlock_for_current_vault().unwrap();
        runtime.lock_session();

        let listed = runtime.list_recent_vaults().unwrap();

        assert_eq!(listed.vaults.len(), 1);
        assert!(!listed.vaults[0].supports_quick_unlock);
    }

    #[test]
    fn refreshing_quick_unlock_after_save_checks_presence_without_loading_secret() {
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
        runtime.enable_quick_unlock_for_current_vault().unwrap();
        runtime
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
            .unwrap();

        runtime.save_vault(&opened.vault_id).unwrap();
    }

    #[test]
    fn quick_unlock_requires_biometric_authorization_even_when_secret_load_is_protected() {
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
        runtime.enable_quick_unlock_for_current_vault().unwrap();
        runtime.lock_session();

        runtime.unlock_current_vault_with_quick_unlock().unwrap();

        assert_eq!(
            authorizations.borrow().as_slice(),
            [
                "Enable quick unlock for this vault".to_owned(),
                "Unlock this vault".to_owned(),
            ]
        );
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
        runtime.enable_quick_unlock_for_current_vault().unwrap();
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
