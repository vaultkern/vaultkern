use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaultkern_runtime_protocol::{VaultReferenceDto, VaultReferenceListDto};

use crate::providers::durable_file::{ExclusiveFileLock, create_dir_all_durable};
use crate::state_paths::{extension_state_dir, runtime_state_dir};
use crate::sync::durable_replace;

const STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredVaultSource {
    LocalPath {
        path: String,
    },
    OneDriveItem {
        drive_id: String,
        item_id: String,
        account_label: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingVaultCleanup {
    pub(crate) vault_ref_id: String,
    pub(crate) source: StoredVaultSource,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VaultReferenceStoreData {
    current_vault_ref_id: Option<String>,
    vaults: Vec<StoredVaultReference>,
    #[serde(default)]
    pending_cleanups: Vec<PendingVaultCleanup>,
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
        let data = read_store_data(&path).unwrap_or_default();

        Self {
            backing: StoreBacking::Persistent { path, data },
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            backing: StoreBacking::InMemory(VaultReferenceStoreData::default()),
        }
    }

    pub fn current_vault_ref_id(&self) -> Result<Option<String>> {
        Ok(self.fresh_data()?.current_vault_ref_id)
    }

    pub fn upsert_local_path(
        &mut self,
        path: &str,
        last_used_at: i64,
    ) -> Result<VaultReferenceDto> {
        let vault_ref_id = local_vault_ref_id(path);
        let display_name = display_name_for_path(path);
        let source_summary = source_summary_for_path(path);
        self.mutate(|data| {
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
            data.pending_cleanups
                .retain(|cleanup| cleanup.vault_ref_id != vault_ref_id);
            sort_vaults(&mut data.vaults);
            Ok(())
        })?;
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
        self.mutate(|data| {
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
            data.pending_cleanups
                .retain(|cleanup| cleanup.vault_ref_id != vault_ref_id);
            sort_vaults(&mut data.vaults);
            Ok(())
        })?;
        Ok(self.dto_for(&vault_ref_id))
    }

    pub fn list_recent_vaults(&self) -> Result<VaultReferenceListDto> {
        let data = self.fresh_data()?;
        let current_vault_ref_id = data.current_vault_ref_id.as_deref();
        let mut vaults = data
            .vaults
            .iter()
            .map(|vault| self.dto_from(vault, current_vault_ref_id))
            .collect::<Vec<_>>();

        vaults.sort_by(|left, right| {
            right
                .is_current
                .cmp(&left.is_current)
                .then_with(|| right.last_used_at.cmp(&left.last_used_at))
                .then_with(|| left.display_name.cmp(&right.display_name))
        });

        Ok(VaultReferenceListDto { vaults })
    }

    pub fn mark_current(&mut self, vault_ref_id: &str, last_used_at: i64) -> Result<()> {
        self.mutate(|data| {
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
            Ok(())
        })
    }

    pub fn delete(&mut self, vault_ref_id: &str) -> Result<(bool, PendingVaultCleanup)> {
        self.mutate(|data| {
            let stored = data
                .vaults
                .iter()
                .find(|vault| vault.vault_ref_id == vault_ref_id)
                .cloned()
                .with_context(|| format!("vault reference not found: {vault_ref_id}"))?;
            let cleanup = PendingVaultCleanup {
                vault_ref_id: vault_ref_id.to_owned(),
                source: stored_source(&stored, vault_ref_id)?,
            };
            data.vaults
                .retain(|vault| vault.vault_ref_id != vault_ref_id);
            let deleted_current = data.current_vault_ref_id.as_deref() == Some(vault_ref_id);
            if deleted_current {
                data.current_vault_ref_id = None;
            }

            data.pending_cleanups
                .retain(|pending| pending.vault_ref_id != vault_ref_id);
            data.pending_cleanups.push(cleanup.clone());
            Ok((deleted_current, cleanup))
        })
    }

    pub(crate) fn pending_cleanups(&self) -> Result<Vec<PendingVaultCleanup>> {
        Ok(self.fresh_data()?.pending_cleanups)
    }

    pub(crate) fn complete_cleanup_while<T>(
        &mut self,
        cleanup: &PendingVaultCleanup,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let intent_is_current = |data: &VaultReferenceStoreData| {
            data.pending_cleanups.contains(cleanup)
                && !data
                    .vaults
                    .iter()
                    .any(|vault| vault.vault_ref_id == cleanup.vault_ref_id)
        };
        match &mut self.backing {
            StoreBacking::InMemory(data) => {
                if !intent_is_current(data) {
                    return Ok(None);
                }
                let result = action()?;
                data.pending_cleanups
                    .retain(|candidate| candidate != cleanup);
                Ok(Some(result))
            }
            StoreBacking::Persistent { path, data } => {
                let parent = path
                    .parent()
                    .context("vault reference store has no parent")?;
                create_dir_all_durable(parent)?;
                let lock_path = store_lock_path(path)?;
                let _lock =
                    ExclusiveFileLock::acquire_with_timeout(&lock_path, STORE_LOCK_TIMEOUT)?;
                let mut next = read_store_data(path)?;
                if !intent_is_current(&next) {
                    *data = next;
                    return Ok(None);
                }
                let result = action()?;
                next.pending_cleanups
                    .retain(|candidate| candidate != cleanup);
                let bytes = serde_json::to_vec_pretty(&next)
                    .context("failed to encode vault reference store")?;
                durable_replace(path, &bytes).with_context(|| {
                    format!("failed to write vault reference store: {}", path.display())
                })?;
                *data = next;
                Ok(Some(result))
            }
        }
    }

    pub fn source_for(&self, vault_ref_id: &str) -> Result<StoredVaultSource> {
        let data = self.fresh_data()?;
        let vault = data
            .vaults
            .iter()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
            .with_context(|| format!("vault reference not found: {vault_ref_id}"))?;

        stored_source(vault, vault_ref_id)
    }

    pub fn find_ref_id_by_path(&self, path: &str) -> Result<Option<String>> {
        Ok(self
            .fresh_data()?
            .vaults
            .iter()
            .find(|vault| vault.path == path)
            .map(|vault| vault.vault_ref_id.clone()))
    }

    pub(crate) fn contains_onedrive_item_fresh(
        &self,
        drive_id: &str,
        item_id: &str,
    ) -> Result<bool> {
        let contains = |data: &VaultReferenceStoreData| {
            data.vaults.iter().any(|vault| {
                vault.source_kind == "onedrive"
                    && vault.one_drive.as_ref().is_some_and(|source| {
                        source.drive_id == drive_id && source.item_id == item_id
                    })
            })
        };
        match &self.backing {
            StoreBacking::InMemory(data) => Ok(contains(data)),
            StoreBacking::Persistent { path, .. } => {
                let parent = path
                    .parent()
                    .context("vault reference store has no parent")?;
                create_dir_all_durable(parent)?;
                let lock_path = store_lock_path(path)?;
                let _lock =
                    ExclusiveFileLock::acquire_with_timeout(&lock_path, STORE_LOCK_TIMEOUT)?;
                Ok(contains(&read_store_data(path)?))
            }
        }
    }

    pub(crate) fn contains_vault_ref_fresh(&self, vault_ref_id: &str) -> Result<bool> {
        Ok(self
            .fresh_data()?
            .vaults
            .iter()
            .any(|vault| vault.vault_ref_id == vault_ref_id))
    }

    fn dto_for(&self, vault_ref_id: &str) -> VaultReferenceDto {
        let vault = self
            .data()
            .vaults
            .iter()
            .find(|vault| vault.vault_ref_id == vault_ref_id)
            .expect("vault reference should exist");
        self.dto_from(vault, self.data().current_vault_ref_id.as_deref())
    }

    fn dto_from(
        &self,
        vault: &StoredVaultReference,
        current_vault_ref_id: Option<&str>,
    ) -> VaultReferenceDto {
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
            is_current: current_vault_ref_id == Some(vault.vault_ref_id.as_str()),
        }
    }

    fn data(&self) -> &VaultReferenceStoreData {
        match &self.backing {
            StoreBacking::InMemory(data) => data,
            StoreBacking::Persistent { data, .. } => data,
        }
    }

    fn fresh_data(&self) -> Result<VaultReferenceStoreData> {
        match &self.backing {
            StoreBacking::InMemory(data) => Ok(data.clone()),
            StoreBacking::Persistent { path, .. } => {
                let parent = path
                    .parent()
                    .context("vault reference store has no parent")?;
                create_dir_all_durable(parent)?;
                let lock_path = store_lock_path(path)?;
                let _lock =
                    ExclusiveFileLock::acquire_with_timeout(&lock_path, STORE_LOCK_TIMEOUT)?;
                read_store_data(path)
            }
        }
    }

    fn mutate<T>(
        &mut self,
        mutation: impl FnOnce(&mut VaultReferenceStoreData) -> Result<T>,
    ) -> Result<T> {
        match &mut self.backing {
            StoreBacking::InMemory(data) => {
                let mut next = data.clone();
                let result = mutation(&mut next)?;
                *data = next;
                Ok(result)
            }
            StoreBacking::Persistent { path, data } => {
                let parent = path
                    .parent()
                    .context("vault reference store has no parent")?;
                create_dir_all_durable(parent).with_context(|| {
                    format!(
                        "failed to create vault reference store dir: {}",
                        parent.display()
                    )
                })?;
                let lock_path = store_lock_path(path)?;
                let _lock = ExclusiveFileLock::acquire_with_timeout(&lock_path, STORE_LOCK_TIMEOUT)
                    .with_context(|| {
                        format!("failed to lock vault reference store: {}", path.display())
                    })?;
                let mut next = read_store_data(path)?;
                let result = mutation(&mut next)?;
                let bytes = serde_json::to_vec_pretty(&next)
                    .context("failed to encode vault reference store")?;
                durable_replace(path, &bytes).with_context(|| {
                    format!("failed to write vault reference store: {}", path.display())
                })?;
                *data = next;
                Ok(result)
            }
        }
    }
}

fn read_store_data(path: &Path) -> Result<VaultReferenceStoreData> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid vault reference store: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(VaultReferenceStoreData::default())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read vault reference store: {}", path.display())),
    }
}

fn store_lock_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("vault reference store path has no UTF-8 file name")?;
    Ok(path.with_file_name(format!("{file_name}.lock")))
}

fn stored_source(vault: &StoredVaultReference, vault_ref_id: &str) -> Result<StoredVaultSource> {
    if vault.source_kind == "onedrive" {
        let one_drive = vault
            .one_drive
            .as_ref()
            .with_context(|| format!("OneDrive vault reference is incomplete: {vault_ref_id}"))?;
        return Ok(StoredVaultSource::OneDriveItem {
            drive_id: one_drive.drive_id.clone(),
            item_id: one_drive.item_id.clone(),
            account_label: one_drive.account_label.clone(),
        });
    }
    Ok(StoredVaultSource::LocalPath {
        path: vault.path.clone(),
    })
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
    use super::VaultReferenceStore;
    use std::cell::Cell;
    use std::fs;

    #[test]
    fn persistent_mutations_reload_under_the_shared_store_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-references.json");
        let mut first = VaultReferenceStore::new_at(path.clone());
        let mut stale_second = VaultReferenceStore::new_at(path.clone());

        first.upsert_local_path("first.kdbx", 10).unwrap();
        stale_second.upsert_local_path("second.kdbx", 20).unwrap();

        let reloaded = VaultReferenceStore::new_at(path);
        let vaults = reloaded.list_recent_vaults().unwrap().vaults;
        assert_eq!(vaults.len(), 2);
        assert!(
            vaults
                .iter()
                .any(|vault| vault.source_summary == "first.kdbx")
        );
        assert!(
            vaults
                .iter()
                .any(|vault| vault.source_summary == "second.kdbx")
        );
    }

    #[test]
    fn corrupt_store_is_never_replaced_with_an_empty_default() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-references.json");
        fs::write(&path, b"{not-json").unwrap();
        let mut store = VaultReferenceStore::new_at(path.clone());

        let error = store
            .upsert_local_path("personal.kdbx", 10)
            .unwrap_err()
            .to_string();

        assert!(error.contains("invalid vault reference store"));
        assert_eq!(fs::read(path).unwrap(), b"{not-json");
    }

    #[test]
    fn stale_cleanup_intent_cannot_delete_a_reactivated_reference() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault-references.json");
        let mut cleanup_owner = VaultReferenceStore::new_at(path.clone());
        let mut activator = VaultReferenceStore::new_at(path);
        let reference = cleanup_owner
            .upsert_local_path("personal.kdbx", 10)
            .unwrap();
        let (_, cleanup) = cleanup_owner.delete(&reference.vault_ref_id).unwrap();
        activator.upsert_local_path("personal.kdbx", 20).unwrap();
        let ran = Cell::new(false);

        let result = cleanup_owner
            .complete_cleanup_while(&cleanup, || {
                ran.set(true);
                Ok(())
            })
            .unwrap();

        assert!(result.is_none());
        assert!(!ran.get());
        assert_eq!(cleanup_owner.list_recent_vaults().unwrap().vaults.len(), 1);
    }
}
