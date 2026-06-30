use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::form_urlencoded::byte_serialize;
use vaultkern_core::{
    AttachmentContentUpdate, AttachmentMetadataUpdate, CompositeKey, Compression,
    EntryAttachmentInput, EntryCreate, EntryCustomFieldInput, EntryTimesUpdate, EntryUpdate,
    KdbxCipher, KeepassCore, SaveKdf, SaveProfile, TotpSpec, Vault,
};
use vaultkern_runtime_protocol::{
    DatabaseEncryptionSettingsDto, DatabaseHistorySettingsDto, DatabaseKdfSettingsDto,
    DatabaseMetadataSettingsDto, DatabasePublicMetadataSettingsDto, DatabaseRecycleBinSettingsDto,
    DatabaseSettingsDto, DatabaseSettingsUpdateDto, EntryAttachmentContentDto, EntryAttachmentDto,
    EntryCustomFieldDto, EntryDetailDto, EntryFieldProtectionDto, EntryHistoryDetailDto,
    EntryHistoryItemDto, EntryHistoryListDto, EntryListDto, EntrySummaryDto, ErrorDto,
    FillCandidateListDto, GroupNodeDto, GroupTreeDto, MergeSummaryDto, RuntimeCommand,
    RuntimeResponse, SaveVaultResultDto, SaveVaultStatusDto, VaultHandleDto, VaultReferenceDto,
    VaultReferenceListDto, VaultSourceStatusDto,
};

use crate::command_loop::format_error_chain;
use crate::match_fill::{FillMatchScore, score_entry_match};
use crate::providers::biometric::{
    BiometricProvider, TestBiometricProvider, UnsupportedBiometricProvider,
    default_biometric_provider,
};
use crate::providers::local_file::{LocalFileVaultSourceProvider, VaultSourceFingerprint};
use crate::providers::onedrive::{OneDriveMemoryAccessCounts, OneDriveVaultSourceProvider};
use crate::providers::remote_cache::{RemoteCacheKey, RemoteVaultCache, RemoteVaultCacheEntry};
use crate::providers::secure_storage::{
    MemorySecureStorageProvider, SecureStorageProvider, UnsupportedSecureStorageProvider,
    default_secure_storage_provider,
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
    fixed_unix_time: Option<u64>,
}

impl Runtime {
    pub fn new() -> Self {
        Self::new_with_state(
            VaultReferenceStore::new_default(),
            OneDriveVaultSourceProvider::new_from_env(),
            RemoteVaultCache::new_default(),
        )
    }

    pub fn new_for_browser_origin(origin: &str) -> Self {
        if let Some(extension_id) = extension_id_from_browser_origin(origin) {
            return Self::new_with_state(
                VaultReferenceStore::new_for_extension_id(extension_id),
                OneDriveVaultSourceProvider::new_from_env_for_extension_id(extension_id),
                RemoteVaultCache::new_for_extension_id(extension_id),
            );
        }

        Self::new()
    }

    fn new_with_state(
        references: VaultReferenceStore,
        one_drive: OneDriveVaultSourceProvider,
        remote_cache: RemoteVaultCache,
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
            secure_storage: default_secure_storage_provider(),
            loaded: BTreeMap::new(),
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
            fixed_unix_time: None,
        }
    }

    pub fn for_tests_at(unix_time: u64) -> Self {
        let mut runtime = Self::for_tests();
        runtime.fixed_unix_time = Some(unix_time);
        runtime
    }

    pub fn for_tests_with_quick_unlock() -> Self {
        let mut runtime = Self::for_tests();
        runtime.biometric = Box::new(TestBiometricProvider);
        runtime.secure_storage = Box::new(MemorySecureStorageProvider::new());
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
                vault.supports_quick_unlock = self
                    .secure_storage
                    .load(&quick_unlock_storage_key(&vault.vault_ref_id))?
                    .is_some();
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
        self.unlock_current_vault(
            credentials.password.as_deref(),
            credentials.key_file_path.as_deref(),
        )
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
        }

        if let Some(autosave_delay_seconds) = update.autosave_delay_seconds {
            loaded.autosave_delay_seconds = Some(autosave_delay_seconds);
        }

        Ok(database_settings_dto(
            vault,
            &loaded.save_profile,
            loaded.autosave_delay_seconds,
            loaded.password.is_some(),
        ))
    }

    pub fn find_fill_candidates(&self, vault_id: &str, url: &str) -> Result<FillCandidateListDto> {
        let mut entries = self
            .list_entries(vault_id)?
            .into_iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                score_entry_match(url, &entry.url).map(|score| RankedFillCandidate {
                    index,
                    entry,
                    score,
                })
            })
            .collect::<Vec<_>>();

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
            let bytes = self
                .core
                .save_kdbx(vault, &key, save_profile)
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
        self.core
            .save_kdbx(vault, key, save_profile)
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
                self.core
                    .save_kdbx(vault, key, loaded.save_profile.clone())
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

fn project_group_node(group: &vaultkern_core::GroupView) -> GroupNodeDto {
    GroupNodeDto {
        id: group.id.clone(),
        title: group.title.clone(),
        entry_count: group.entry_count,
        child_count: group.child_count,
        children: group.children.iter().map(project_group_node).collect(),
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

fn query_error_response(error: anyhow::Error) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: "invalid_request".into(),
        message: format_error_chain(&error),
    })
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
}
