use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::providers::local_file::VaultSourceFingerprint;
use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCacheKey {
    pub provider_kind: String,
    pub remote_id: String,
}

impl RemoteCacheKey {
    pub fn new(provider_kind: &str, remote_id: &str) -> Self {
        Self {
            provider_kind: provider_kind.to_owned(),
            remote_id: remote_id.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVaultCacheEntry {
    pub bytes: Vec<u8>,
    pub fingerprint: VaultSourceFingerprint,
    pub display_name: String,
    pub account_label: String,
    pub cached_at: i64,
    pub pending_sync: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteVaultCache {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RemoteVaultCachePaths {
    pub bytes_path: PathBuf,
    pub metadata_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteVaultCacheMetadata {
    provider_kind: String,
    remote_id: String,
    display_name: String,
    account_label: String,
    fingerprint: VaultSourceFingerprint,
    cached_at: i64,
    #[serde(default)]
    pending_sync: bool,
}

impl RemoteVaultCache {
    pub fn new_default() -> Self {
        Self {
            root: default_cache_dir(),
        }
    }

    pub fn new_for_extension_id(extension_id: &str) -> Self {
        Self {
            root: extension_state_dir(extension_id).join("remote-cache"),
        }
    }

    pub fn new_at(path: impl AsRef<Path>) -> Self {
        Self {
            root: path.as_ref().to_path_buf(),
        }
    }

    pub fn read(&self, key: &RemoteCacheKey) -> Result<Option<RemoteVaultCacheEntry>> {
        let paths = self.paths(key);
        let Ok(metadata_bytes) = fs::read(&paths.metadata_path) else {
            return Ok(None);
        };
        let Ok(metadata) = serde_json::from_slice::<RemoteVaultCacheMetadata>(&metadata_bytes)
        else {
            return Ok(None);
        };
        if metadata.provider_kind != key.provider_kind || metadata.remote_id != key.remote_id {
            return Ok(None);
        }
        let Ok(bytes) = fs::read(&paths.bytes_path) else {
            return Ok(None);
        };

        Ok(Some(RemoteVaultCacheEntry {
            bytes,
            fingerprint: metadata.fingerprint,
            display_name: metadata.display_name,
            account_label: metadata.account_label,
            cached_at: metadata.cached_at,
            pending_sync: metadata.pending_sync,
        }))
    }

    pub fn write(&self, key: &RemoteCacheKey, entry: RemoteVaultCacheEntry) -> Result<()> {
        let paths = self.paths(key);
        if let Some(parent) = paths.bytes_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create remote vault cache dir: {}",
                    parent.display()
                )
            })?;
        }

        let metadata = RemoteVaultCacheMetadata {
            provider_kind: key.provider_kind.clone(),
            remote_id: key.remote_id.clone(),
            display_name: entry.display_name,
            account_label: entry.account_label,
            fingerprint: entry.fingerprint,
            cached_at: entry.cached_at,
            pending_sync: entry.pending_sync,
        };
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)
            .context("failed to encode remote cache metadata")?;

        fs::write(&paths.bytes_path, entry.bytes).with_context(|| {
            format!(
                "failed to write remote vault cache bytes: {}",
                paths.bytes_path.display()
            )
        })?;
        fs::write(&paths.metadata_path, metadata_bytes).with_context(|| {
            format!(
                "failed to write remote vault cache metadata: {}",
                paths.metadata_path.display()
            )
        })
    }

    pub fn delete(&self, key: &RemoteCacheKey) -> Result<()> {
        let paths = self.paths(key);
        remove_file_if_exists(&paths.bytes_path)?;
        remove_file_if_exists(&paths.metadata_path)
    }

    #[cfg(test)]
    pub fn paths_for_tests(&self, key: &RemoteCacheKey) -> RemoteVaultCachePaths {
        self.paths(key)
    }

    fn paths(&self, key: &RemoteCacheKey) -> RemoteVaultCachePaths {
        let digest = cache_key_digest(key);
        RemoteVaultCachePaths {
            bytes_path: self.root.join(format!("{digest}.kdbx")),
            metadata_path: self.root.join(format!("{digest}.json")),
        }
    }
}

fn cache_key_digest(key: &RemoteCacheKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.provider_kind.as_bytes());
    hasher.update(b":");
    hasher.update(key.remote_id.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove remote vault cache file: {}",
                path.display()
            )
        }),
    }
}

fn default_cache_dir() -> PathBuf {
    runtime_state_dir().join("remote-cache")
}

#[cfg(test)]
mod tests {
    use super::{RemoteCacheKey, RemoteVaultCache, RemoteVaultCacheEntry};
    use crate::providers::local_file::VaultSourceFingerprint;

    fn fingerprint() -> VaultSourceFingerprint {
        VaultSourceFingerprint {
            content_sha256: "abc123".into(),
            size_bytes: 4,
            modified_at: Some(42),
        }
    }

    fn key() -> RemoteCacheKey {
        RemoteCacheKey::new("onedrive", "drive-1:item-1")
    }

    #[test]
    fn cache_file_names_are_stable_and_do_not_expose_remote_ids() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let paths = cache.paths_for_tests(&key());

        assert_eq!(paths.bytes_path, cache.paths_for_tests(&key()).bytes_path);
        let bytes_name = paths.bytes_path.file_name().unwrap().to_string_lossy();
        assert!(bytes_name.ends_with(".kdbx"));
        assert!(!bytes_name.contains("drive-1"));
        assert!(!bytes_name.contains("item-1"));
        assert!(!bytes_name.contains("onedrive"));
    }

    #[test]
    fn write_then_read_roundtrips_bytes_and_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        cache
            .write(
                &key(),
                RemoteVaultCacheEntry {
                    bytes: b"kdbx".to_vec(),
                    fingerprint: fingerprint(),
                    display_name: "Cloud Vault".into(),
                    account_label: "alice@example.com".into(),
                    cached_at: 1_776_500_000,
                    pending_sync: false,
                },
            )
            .unwrap();

        let cached = cache.read(&key()).unwrap().expect("cache hit");
        assert_eq!(cached.bytes, b"kdbx");
        assert_eq!(cached.fingerprint, fingerprint());
        assert_eq!(cached.display_name, "Cloud Vault");
        assert_eq!(cached.account_label, "alice@example.com");
        assert_eq!(cached.cached_at, 1_776_500_000);
        assert!(!cached.pending_sync);
    }

    #[test]
    fn write_then_read_preserves_pending_sync_marker() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        cache
            .write(
                &key(),
                RemoteVaultCacheEntry {
                    bytes: b"kdbx".to_vec(),
                    fingerprint: fingerprint(),
                    display_name: "Cloud Vault".into(),
                    account_label: "alice@example.com".into(),
                    cached_at: 1_776_500_010,
                    pending_sync: true,
                },
            )
            .unwrap();

        let cached = cache.read(&key()).unwrap().expect("cache hit");
        assert!(cached.pending_sync);
    }

    #[test]
    fn corrupted_metadata_is_treated_as_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let paths = cache.paths_for_tests(&key());
        std::fs::create_dir_all(paths.metadata_path.parent().unwrap()).unwrap();
        std::fs::write(paths.metadata_path, b"not json").unwrap();
        std::fs::write(paths.bytes_path, b"kdbx").unwrap();

        assert!(cache.read(&key()).unwrap().is_none());
    }

    #[test]
    fn delete_is_idempotent_and_removes_cached_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        cache.delete(&key()).unwrap();
        cache
            .write(
                &key(),
                RemoteVaultCacheEntry {
                    bytes: b"kdbx".to_vec(),
                    fingerprint: fingerprint(),
                    display_name: "Cloud Vault".into(),
                    account_label: "alice@example.com".into(),
                    cached_at: 1_776_500_000,
                    pending_sync: false,
                },
            )
            .unwrap();

        let paths = cache.paths_for_tests(&key());
        assert!(paths.bytes_path.exists());
        assert!(paths.metadata_path.exists());

        cache.delete(&key()).unwrap();
        cache.delete(&key()).unwrap();

        assert!(!paths.bytes_path.exists());
        assert!(!paths.metadata_path.exists());
    }
}
