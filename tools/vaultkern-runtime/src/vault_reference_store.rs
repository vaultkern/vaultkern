use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaultkern_runtime_protocol::{VaultReferenceDto, VaultReferenceListDto};

use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, TargetExpectation, TempWriteFaultPoints,
    create_dir_all_durable, path_file_identity, publish_temp, remove_if_exists, sync_parent,
    unique_sibling_path, write_verified_temp,
};
use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVaultReference {
    vault_ref_id: String,
    #[serde(default = "default_local_source_kind")]
    source_kind: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    one_drive: Option<StoredOneDriveReference>,
    display_name: String,
    source_summary: String,
    last_used_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredOneDriveReference {
    drive_id: String,
    item_id: String,
    account_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredVaultSource {
    LocalPath(String),
    OneDriveItem {
        drive_id: String,
        item_id: String,
        account_label: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VaultReferenceStoreData {
    current_vault_ref_id: Option<String>,
    #[serde(default)]
    quick_unlock_enabled: Option<bool>,
    #[serde(default)]
    quick_unlock_invalidated_vault_ref_ids: BTreeSet<String>,
    #[serde(default)]
    quick_unlock_invalidate_new_vault_records: bool,
    vaults: Vec<StoredVaultReference>,
}

enum StoreBacking {
    InMemory(VaultReferenceStoreData),
    Persistent {
        path: PathBuf,
        data: VaultReferenceStoreData,
    },
}

pub struct VaultReferenceStore {
    backing: StoreBacking,
}

impl VaultReferenceStore {
    pub fn new_default() -> Self {
        Self::new_at(default_store_path())
    }

    pub fn new_for_extension_id(extension_id: &str) -> Self {
        Self::new_at(extension_state_dir(extension_id).join("vault-references.json"))
    }

    fn new_at(path: PathBuf) -> Self {
        let data = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<VaultReferenceStoreData>(&bytes)
                .unwrap_or_else(|_| fail_closed_store_data()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                VaultReferenceStoreData::default()
            }
            Err(_) => fail_closed_store_data(),
        };

        Self {
            backing: StoreBacking::Persistent { path, data },
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            backing: StoreBacking::InMemory(VaultReferenceStoreData::default()),
        }
    }

    pub fn current_vault_ref_id(&self) -> Option<&str> {
        self.data().current_vault_ref_id.as_deref()
    }

    pub fn quick_unlock_policy(&self) -> Option<bool> {
        self.data().quick_unlock_enabled
    }

    pub fn initialize_quick_unlock_policy(&mut self, enabled: bool) -> Result<bool> {
        if self.data().quick_unlock_enabled.is_some() {
            return Ok(false);
        }
        let data = self.data_mut();
        data.quick_unlock_enabled = Some(enabled);
        if !enabled {
            data.quick_unlock_invalidate_new_vault_records = true;
            data.quick_unlock_invalidated_vault_ref_ids
                .extend(data.vaults.iter().map(|vault| vault.vault_ref_id.clone()));
        }
        self.persist()?;
        Ok(true)
    }

    pub fn set_quick_unlock_policy(&mut self, enabled: bool) -> Result<()> {
        let data = self.data_mut();
        data.quick_unlock_enabled = Some(enabled);
        if !enabled {
            data.quick_unlock_invalidate_new_vault_records = true;
            data.quick_unlock_invalidated_vault_ref_ids
                .extend(data.vaults.iter().map(|vault| vault.vault_ref_id.clone()));
        }
        self.persist()
    }

    pub fn quick_unlock_record_is_invalidated(&self, vault_ref_id: &str) -> bool {
        self.data()
            .quick_unlock_invalidated_vault_ref_ids
            .contains(vault_ref_id)
    }

    pub fn invalidate_quick_unlock_record(&mut self, vault_ref_id: &str) -> Result<()> {
        if !self
            .data_mut()
            .quick_unlock_invalidated_vault_ref_ids
            .insert(vault_ref_id.to_owned())
        {
            return Ok(());
        }
        self.persist()
    }

    pub fn clear_quick_unlock_record_invalidation(&mut self, vault_ref_id: &str) -> Result<()> {
        if !self
            .data_mut()
            .quick_unlock_invalidated_vault_ref_ids
            .remove(vault_ref_id)
        {
            return Ok(());
        }
        self.persist()
    }

    pub fn upsert_local_path(
        &mut self,
        path: &str,
        last_used_at: i64,
    ) -> Result<VaultReferenceDto> {
        let vault_ref_id = local_vault_ref_id(path);
        let display_name = display_name_for_path(path);
        let source_summary = source_summary_for_path(path);
        let data = self.data_mut();

        if let Some(vault) = data
            .vaults
            .iter_mut()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
        {
            vault.display_name = display_name;
            vault.source_summary = source_summary;
            vault.last_used_at = last_used_at;
        } else {
            data.vaults.push(StoredVaultReference {
                vault_ref_id: vault_ref_id.clone(),
                path: path.to_owned(),
                source_kind: "local".into(),
                one_drive: None,
                display_name,
                source_summary,
                last_used_at,
            });
        }

        data.current_vault_ref_id = Some(vault_ref_id.clone());
        if data.quick_unlock_invalidate_new_vault_records {
            data.quick_unlock_invalidated_vault_ref_ids
                .insert(vault_ref_id.clone());
        }
        sort_vaults(&mut data.vaults);
        self.persist()?;
        Ok(self.dto_for(&vault_ref_id))
    }

    pub fn upsert_onedrive_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        display_name: &str,
        account_label: &str,
        last_used_at: i64,
    ) -> Result<VaultReferenceDto> {
        let vault_ref_id = onedrive_vault_ref_id(drive_id, item_id);
        let source_summary = format!("{account_label} / {display_name}");
        let data = self.data_mut();

        if let Some(vault) = data
            .vaults
            .iter_mut()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
        {
            vault.source_kind = "onedrive".into();
            vault.path.clear();
            vault.one_drive = Some(StoredOneDriveReference {
                drive_id: drive_id.to_owned(),
                item_id: item_id.to_owned(),
                account_label: account_label.to_owned(),
            });
            vault.display_name = display_name_for_cloud_name(display_name);
            vault.source_summary = source_summary;
            vault.last_used_at = last_used_at;
        } else {
            data.vaults.push(StoredVaultReference {
                vault_ref_id: vault_ref_id.clone(),
                source_kind: "onedrive".into(),
                path: String::new(),
                one_drive: Some(StoredOneDriveReference {
                    drive_id: drive_id.to_owned(),
                    item_id: item_id.to_owned(),
                    account_label: account_label.to_owned(),
                }),
                display_name: display_name_for_cloud_name(display_name),
                source_summary,
                last_used_at,
            });
        }

        data.current_vault_ref_id = Some(vault_ref_id.clone());
        if data.quick_unlock_invalidate_new_vault_records {
            data.quick_unlock_invalidated_vault_ref_ids
                .insert(vault_ref_id.clone());
        }
        sort_vaults(&mut data.vaults);
        self.persist()?;
        Ok(self.dto_for(&vault_ref_id))
    }

    pub fn list_recent_vaults(&self) -> VaultReferenceListDto {
        let mut vaults = self
            .data()
            .vaults
            .iter()
            .map(|vault| self.dto_from(vault))
            .collect::<Vec<_>>();

        vaults.sort_by(|left, right| {
            right
                .is_current
                .cmp(&left.is_current)
                .then_with(|| right.last_used_at.cmp(&left.last_used_at))
                .then_with(|| left.display_name.cmp(&right.display_name))
        });

        VaultReferenceListDto { vaults }
    }

    pub fn mark_current(&mut self, vault_ref_id: &str, last_used_at: i64) -> Result<()> {
        let data = self.data_mut();
        let Some(vault) = data
            .vaults
            .iter_mut()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
        else {
            anyhow::bail!("vault reference not found: {vault_ref_id}");
        };

        vault.last_used_at = last_used_at;
        data.current_vault_ref_id = Some(vault_ref_id.to_owned());
        sort_vaults(&mut data.vaults);
        self.persist()
    }

    pub fn delete(&mut self, vault_ref_id: &str) -> Result<bool> {
        let data = self.data_mut();
        let initial_len = data.vaults.len();
        data.vaults
            .retain(|vault| vault.vault_ref_id != vault_ref_id);
        let removed = data.vaults.len() != initial_len;

        if !removed {
            anyhow::bail!("vault reference not found: {vault_ref_id}");
        }

        let deleted_current = data.current_vault_ref_id.as_deref() == Some(vault_ref_id);
        if deleted_current {
            data.current_vault_ref_id = None;
        }
        data.quick_unlock_invalidated_vault_ref_ids
            .remove(vault_ref_id);

        self.persist()?;
        Ok(deleted_current)
    }

    pub fn source_for(&self, vault_ref_id: &str) -> Result<StoredVaultSource> {
        let vault = self
            .data()
            .vaults
            .iter()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
            .with_context(|| format!("vault reference not found: {vault_ref_id}"))?;

        if vault.source_kind == "onedrive" {
            let one_drive = vault.one_drive.as_ref().with_context(|| {
                format!("OneDrive vault reference is incomplete: {vault_ref_id}")
            })?;
            return Ok(StoredVaultSource::OneDriveItem {
                drive_id: one_drive.drive_id.clone(),
                item_id: one_drive.item_id.clone(),
                account_label: one_drive.account_label.clone(),
            });
        }

        Ok(StoredVaultSource::LocalPath(vault.path.clone()))
    }

    fn dto_for(&self, vault_ref_id: &str) -> VaultReferenceDto {
        let vault = self
            .data()
            .vaults
            .iter()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
            .expect("vault reference should exist");
        self.dto_from(vault)
    }

    fn dto_from(&self, vault: &StoredVaultReference) -> VaultReferenceDto {
        let is_onedrive = vault.source_kind == "onedrive";
        VaultReferenceDto {
            vault_ref_id: vault.vault_ref_id.clone(),
            display_name: vault.display_name.clone(),
            source_kind: vault.source_kind.clone(),
            source_summary: vault.source_summary.clone(),
            last_used_at: vault.last_used_at,
            availability: if is_onedrive || Path::new(&vault.path).exists() {
                "ready".into()
            } else {
                "needs_repair".into()
            },
            supports_quick_unlock: false,
            is_current: self.current_vault_ref_id() == Some(vault.vault_ref_id.as_str()),
        }
    }

    fn data(&self) -> &VaultReferenceStoreData {
        match &self.backing {
            StoreBacking::InMemory(data) => data,
            StoreBacking::Persistent { data, .. } => data,
        }
    }

    fn data_mut(&mut self) -> &mut VaultReferenceStoreData {
        match &mut self.backing {
            StoreBacking::InMemory(data) => data,
            StoreBacking::Persistent { data, .. } => data,
        }
    }

    fn persist(&self) -> Result<()> {
        let StoreBacking::Persistent { path, data } = &self.backing else {
            return Ok(());
        };

        persist_data_at_with_faults(path, data, &DurableFaultInjector::default())
    }
}

fn fail_closed_store_data() -> VaultReferenceStoreData {
    VaultReferenceStoreData {
        quick_unlock_enabled: Some(false),
        quick_unlock_invalidate_new_vault_records: true,
        ..VaultReferenceStoreData::default()
    }
}

fn persist_data_at_with_faults(
    path: &Path,
    data: &VaultReferenceStoreData,
    faults: &DurableFaultInjector,
) -> Result<()> {
    let parent = path
        .parent()
        .context("vault reference store path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create vault reference store dir: {}",
            parent.display()
        )
    })?;
    let durable_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve vault reference store dir: {}",
            parent.display()
        )
    })?;
    create_dir_all_durable(&durable_parent).with_context(|| {
        format!(
            "failed to validate vault reference store dir: {}",
            durable_parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .context("vault reference store path has no file name")?;
    let durable_path = durable_parent.join(file_name);
    let bytes =
        serde_json::to_vec_pretty(data).context("failed to encode vault reference store")?;
    let expectation = match fs::symlink_metadata(&durable_path) {
        Ok(metadata) => TargetExpectation::Identity(
            path_file_identity(&durable_path, &metadata)
                .context("failed to identify the existing vault reference store")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TargetExpectation::Missing,
        Err(error) => return Err(error).context("failed to inspect the vault reference store"),
    };
    let backup = unique_sibling_path(&durable_path, "backup")
        .context("failed to allocate a vault reference store backup path")?;
    let temp = write_verified_temp(
        &durable_path,
        &bytes,
        faults,
        TempWriteFaultPoints {
            created: DurableFaultPoint::ManifestTempCreated,
            written: DurableFaultPoint::ManifestTempWritten,
            synced: DurableFaultPoint::ManifestTempSynced,
            verified: DurableFaultPoint::ManifestReadbackVerified,
        },
    )
    .context("failed to write a durable vault reference store temporary file")?;
    publish_temp(
        temp,
        &durable_path,
        expectation,
        Some(&backup),
        faults,
        DurableFaultPoint::BeforeManifestReplace,
        DurableFaultPoint::ManifestReplaced,
        DurableFaultPoint::ManifestParentSynced,
    )
    .map_err(|error| error.source)
    .context("failed to publish the vault reference store")?;
    remove_if_exists(&backup).context("failed to remove the vault reference store backup")?;
    sync_parent(&durable_path).context("failed to sync vault reference store backup cleanup")
}

fn sort_vaults(vaults: &mut [StoredVaultReference]) {
    vaults.sort_by(|left, right| {
        right
            .last_used_at
            .cmp(&left.last_used_at)
            .then_with(|| left.display_name.cmp(&right.display_name))
    });
}

fn local_vault_ref_id(path: &str) -> String {
    let digest = Sha256::digest(path.as_bytes());
    format!("local-{:x}", digest)
}

fn onedrive_vault_ref_id(drive_id: &str, item_id: &str) -> String {
    let digest = Sha256::digest(format!("{drive_id}:{item_id}").as_bytes());
    format!("onedrive-{:x}", digest)
}

fn display_name_for_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_owned()
}

fn display_name_for_cloud_name(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_owned()
}

fn default_local_source_kind() -> String {
    "local".into()
}

fn source_summary_for_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_owned()
}

fn default_store_path() -> PathBuf {
    runtime_state_dir().join("vault-references.json")
}

#[cfg(test)]
mod tests {
    use super::{VaultReferenceStore, persist_data_at_with_faults};
    use crate::providers::durable_file::{DurableFaultInjector, DurableFaultPoint};

    #[test]
    fn quick_unlock_policy_persists_and_initialization_is_one_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("vault-references.json");
        let mut store = VaultReferenceStore::new_at(path.clone());

        assert_eq!(store.quick_unlock_policy(), None);
        assert!(store.initialize_quick_unlock_policy(true).unwrap());
        assert!(!store.initialize_quick_unlock_policy(false).unwrap());
        assert_eq!(store.quick_unlock_policy(), Some(true));

        let mut reloaded = VaultReferenceStore::new_at(path);
        assert_eq!(reloaded.quick_unlock_policy(), Some(true));
        reloaded.set_quick_unlock_policy(false).unwrap();
        assert_eq!(reloaded.quick_unlock_policy(), Some(false));
    }

    #[test]
    fn disabling_quick_unlock_persistently_invalidates_known_vault_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("vault-references.json");
        let mut store = VaultReferenceStore::new_at(path.clone());
        let reference = store.upsert_local_path("/tmp/personal.kdbx", 1).unwrap();

        store.set_quick_unlock_policy(false).unwrap();

        let reloaded = VaultReferenceStore::new_at(path);
        assert!(reloaded.quick_unlock_record_is_invalidated(&reference.vault_ref_id));
    }

    #[test]
    fn corrupt_store_fails_closed_and_invalidates_readded_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("vault-references.json");
        std::fs::write(&path, b"{truncated").unwrap();

        let mut store = VaultReferenceStore::new_at(path);
        assert_eq!(store.quick_unlock_policy(), Some(false));

        store.set_quick_unlock_policy(true).unwrap();
        let reference = store
            .upsert_local_path("/tmp/readded-personal.kdbx", 1)
            .unwrap();

        assert!(store.quick_unlock_record_is_invalidated(&reference.vault_ref_id));
    }

    #[test]
    fn failed_atomic_policy_write_preserves_the_previous_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("vault-references.json");
        let mut store = VaultReferenceStore::new_at(path.clone());
        store.set_quick_unlock_policy(true).unwrap();
        let mut replacement = store.data().clone();
        replacement.quick_unlock_enabled = Some(false);

        let error = persist_data_at_with_faults(
            &path,
            &replacement,
            &DurableFaultInjector::fail_once(DurableFaultPoint::ManifestTempSynced),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected durable file failure"));
        assert_eq!(
            VaultReferenceStore::new_at(path).quick_unlock_policy(),
            Some(true)
        );
    }
}
