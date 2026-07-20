use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock, TargetExpectation,
    TempWriteFaultPoints, create_dir_all_durable, path_file_identity, publish_temp,
    remove_if_exists, sha256_hex, sync_directory, write_verified_temp,
};
use crate::state_paths::{extension_state_dir, runtime_state_dir};

const BASE_WRITE_POINTS: TempWriteFaultPoints = TempWriteFaultPoints {
    created: DurableFaultPoint::GenerationTempCreated,
    written: DurableFaultPoint::GenerationTempWritten,
    synced: DurableFaultPoint::GenerationTempSynced,
    verified: DurableFaultPoint::GenerationReadbackVerified,
};

pub(crate) struct SyncedBaseStore {
    root: PathBuf,
    #[cfg(test)]
    fail_next_store: std::cell::Cell<bool>,
}

impl SyncedBaseStore {
    pub(crate) fn new_default() -> Self {
        Self {
            root: runtime_state_dir().join("synced-bases"),
            #[cfg(test)]
            fail_next_store: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn new_for_extension_id(extension_id: &str) -> Self {
        Self {
            root: extension_state_dir(extension_id).join("synced-bases"),
            #[cfg(test)]
            fail_next_store: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn new_at(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            #[cfg(test)]
            fail_next_store: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn store(&self, vault_id: &str, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_next_store.replace(false) {
            return Err(io::Error::other("injected synced-base write failure"));
        }
        create_dir_all_durable(&self.root)?;
        let (target, lock_path) = self.paths(vault_id);
        let _lock = ExclusiveFileLock::acquire(&lock_path)?;
        durable_replace(&target, bytes)
    }

    pub(crate) fn read(&self, vault_id: &str) -> io::Result<Option<Vec<u8>>> {
        if !self.root.exists() {
            return Ok(None);
        }
        create_dir_all_durable(&self.root)?;
        let (target, lock_path) = self.paths(vault_id);
        let _lock = ExclusiveFileLock::acquire(&lock_path)?;
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "synced base is not a regular file",
                ))
            }
            Ok(_) => fs::read(target).map(Some),
        }
    }

    pub(crate) fn delete(&self, vault_id: &str) -> io::Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        create_dir_all_durable(&self.root)?;
        let (target, lock_path) = self.paths(vault_id);
        let _lock = ExclusiveFileLock::acquire(&lock_path)?;
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "synced base is not a regular file",
                ))
            }
            Ok(_) => {
                remove_if_exists(&target)?;
                sync_directory(&self.root)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_store_for_tests(&self) {
        self.fail_next_store.set(true);
    }

    fn paths(&self, vault_id: &str) -> (PathBuf, PathBuf) {
        let digest = sha256_hex(vault_id.as_bytes());
        (
            self.root.join(format!("{digest}.kdbx")),
            self.root.join(format!("{digest}.lock")),
        )
    }
}

pub(crate) fn write_local_conflict_copy(
    source_path: &Path,
    bytes: &[u8],
    timestamp: u64,
) -> io::Result<PathBuf> {
    let source_path = match fs::canonicalize(source_path) {
        Ok(source_path) => source_path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = source_path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "vault path has no parent")
            })?;
            let file_name = source_path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "vault path has no file name")
            })?;
            fs::canonicalize(parent)?.join(file_name)
        }
        Err(error) => return Err(error),
    };
    let parent = source_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vault path has no parent"))?;
    let stem = source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("vault");
    let faults = DurableFaultInjector::default();

    for collision in 0..128u32 {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        let target = parent.join(format!(
            "{stem} (VaultKern conflict {timestamp}{suffix}).kdbx"
        ));
        let temp = write_verified_temp(&target, bytes, &faults, BASE_WRITE_POINTS)?;
        match publish_temp(
            temp,
            &target,
            TargetExpectation::Missing,
            None,
            &faults,
            DurableFaultPoint::BeforeGenerationPublish,
            DurableFaultPoint::GenerationPublished,
            DurableFaultPoint::GenerationParentSynced,
        ) {
            Ok(()) => return Ok(target),
            Err(error) if error.target_conflict => continue,
            Err(error) => return Err(error.source),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique conflict-copy path",
    ))
}

fn durable_replace(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let expectation = match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => TargetExpectation::Missing,
        Err(error) => return Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "synced base target is not a regular file",
            ));
        }
        Ok(metadata) => {
            let current = fs::read(target)?;
            TargetExpectation::IdentityAndContent {
                identity: path_file_identity(target, &metadata)?,
                content_sha256: sha256_hex(&current),
                size_bytes: metadata.len(),
                modified_at: metadata.modified().ok(),
            }
        }
    };
    let faults = DurableFaultInjector::default();
    let temp = write_verified_temp(target, bytes, &faults, BASE_WRITE_POINTS)?;
    publish_temp(
        temp,
        target,
        expectation,
        None,
        &faults,
        DurableFaultPoint::BeforeGenerationPublish,
        DurableFaultPoint::GenerationPublished,
        DurableFaultPoint::GenerationParentSynced,
    )
    .map_err(|error| error.source)
}

#[cfg(test)]
mod tests {
    use super::{SyncedBaseStore, write_local_conflict_copy};

    #[test]
    fn synced_base_round_trip_survives_atomic_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let store = SyncedBaseStore::new_at(dir.path().join("bases"));

        assert_eq!(store.read("vault-a").unwrap(), None);
        store.store("vault-a", b"base-one").unwrap();
        assert_eq!(
            store.read("vault-a").unwrap().as_deref(),
            Some(&b"base-one"[..])
        );
        store.store("vault-a", b"base-two").unwrap();
        assert_eq!(
            store.read("vault-a").unwrap().as_deref(),
            Some(&b"base-two"[..])
        );
    }

    #[test]
    fn conflict_copy_is_a_durable_kdbx_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("personal.kdbx");
        std::fs::write(&source, b"remote-head").unwrap();

        let copy = write_local_conflict_copy(&source, b"local-edits", 1_784_439_300).unwrap();

        assert_eq!(
            copy.parent(),
            std::fs::canonicalize(&source).unwrap().parent()
        );
        assert_eq!(
            copy.extension().and_then(|value| value.to_str()),
            Some("kdbx")
        );
        assert!(
            copy.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("VaultKern conflict")
        );
        assert_eq!(std::fs::read(&copy).unwrap(), b"local-edits");
        assert_eq!(std::fs::read(&source).unwrap(), b"remote-head");
    }
}
