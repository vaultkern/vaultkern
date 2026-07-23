use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock, TargetExpectation,
    TempWriteFaultPoints, create_dir_all_durable, durable_path, opened_file_identity,
    path_file_identity, publish_temp, remove_and_sync_absence, remove_if_exists, sha256_hex,
    sync_directory, sync_parent, sync_published_target, unique_sibling_path, write_verified_temp,
};
use crate::providers::local_file::VaultSourceFingerprint;
use crate::state_paths::{extension_state_dir, runtime_state_dir};
use crate::sync::durable_replace;

const REMOTE_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteVaultCacheReadStatus {
    Missing,
    Current {
        entry: RemoteVaultCacheEntry,
        source_etag: Option<String>,
    },
    Degraded {
        entry: RemoteVaultCacheEntry,
        source_etag: Option<String>,
        warning: String,
    },
    Corrupt {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingRemoteCacheCompletion {
    Durable,
    DurabilityUnknown,
}

#[derive(Debug)]
pub(crate) struct PendingRemoteCacheConflict {
    message: String,
}

impl PendingRemoteCacheConflict {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PendingRemoteCacheConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PendingRemoteCacheConflict {}

#[derive(Debug, Clone)]
pub struct RemoteVaultCache {
    root: PathBuf,
    faults: DurableFaultInjector,
    lock_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct RemoteVaultCachePaths {
    pub bytes_path: PathBuf,
    pub metadata_path: PathBuf,
    pub lock_path: PathBuf,
    pub retired_path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct RemoteCacheCleanupGuard<'a> {
    cache: &'a RemoteVaultCache,
    key: RemoteCacheKey,
    paths: RemoteVaultCachePaths,
    _lock: ExclusiveFileLock,
}

impl RemoteCacheCleanupGuard<'_> {
    pub(crate) fn delete_cached_state(&self) -> Result<()> {
        self.cache.delete_files_locked(&self.key, &self.paths)
    }

    pub(crate) fn cancel_retirement(&self) -> Result<()> {
        remove_and_sync_absence(&self.paths.retired_path).with_context(|| {
            format!(
                "failed to cancel stale remote cache retirement: {}",
                self.paths.retired_path.display()
            )
        })
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteVaultCacheManifestV2 {
    version: u8,
    provider_kind: String,
    remote_id: String,
    display_name: String,
    account_label: String,
    generation: String,
    content_sha256: String,
    size_bytes: u64,
    source_etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_revision: Option<u64>,
    source_modified_at: Option<u64>,
    cached_at: i64,
    pending_sync: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_kind: Option<RemoteVaultPendingKind>,
    previous_generation: Option<RemoteVaultGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_generation: Option<RemoteVaultGeneration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteVaultGeneration {
    generation: String,
    content_sha256: String,
    size_bytes: u64,
    source_etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_revision: Option<u64>,
    source_modified_at: Option<u64>,
    display_name: String,
    account_label: String,
    cached_at: i64,
    pending_sync: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_kind: Option<RemoteVaultPendingKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RemoteVaultPendingKind {
    None,
    Generic,
    GenericFixedBase,
    ConflictCopy,
    #[serde(rename = "autofill")]
    RetiredAutofill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenericPendingKind {
    SourceWrite,
    ConflictCopy,
}

impl GenericPendingKind {
    fn manifest_kind(self) -> RemoteVaultPendingKind {
        match self {
            Self::SourceWrite => RemoteVaultPendingKind::GenericFixedBase,
            Self::ConflictCopy => RemoteVaultPendingKind::ConflictCopy,
        }
    }
}

fn resident_pending_kind_matches(
    actual: Option<RemoteVaultPendingKind>,
    expected: Option<GenericPendingKind>,
) -> bool {
    match (actual, expected) {
        (
            Some(
                RemoteVaultPendingKind::Generic
                | RemoteVaultPendingKind::GenericFixedBase
                | RemoteVaultPendingKind::RetiredAutofill,
            ),
            None | Some(GenericPendingKind::SourceWrite),
        ) => true,
        (
            Some(RemoteVaultPendingKind::ConflictCopy),
            None | Some(GenericPendingKind::ConflictCopy),
        ) => true,
        _ => false,
    }
}

#[derive(Debug)]
enum CacheManifestPublishOutcome {
    Durable,
    DurabilityUnknown { source: anyhow::Error },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenericPendingWriteMode {
    Update,
    Complete,
}

#[derive(Debug, Clone, Copy)]
struct GenericPendingWriteProof<'a> {
    mode: GenericPendingWriteMode,
    expected_fingerprint: &'a VaultSourceFingerprint,
    kind: Option<GenericPendingKind>,
}

#[derive(Debug)]
struct CacheManifestNotPublished {
    source: anyhow::Error,
}

impl std::fmt::Display for CacheManifestNotPublished {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cache manifest was not published: {:#}",
            self.source
        )
    }
}

impl std::error::Error for CacheManifestNotPublished {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Clone)]
struct AuthenticatedCacheEntry {
    entry: RemoteVaultCacheEntry,
    generation: RemoteVaultGeneration,
    fallback: Option<RemoteVaultGeneration>,
    observed: Option<RemoteVaultGeneration>,
    legacy: bool,
}

#[derive(Debug, Clone)]
enum AuthenticatedCacheRead {
    Missing,
    Current(AuthenticatedCacheEntry),
    Degraded(AuthenticatedCacheEntry),
    Corrupt(String),
}

impl RemoteVaultCache {
    pub fn new_default() -> Self {
        Self {
            root: durable_path(&default_cache_dir()),
            faults: DurableFaultInjector::default(),
            lock_timeout: REMOTE_CACHE_LOCK_TIMEOUT,
        }
    }

    pub fn new_for_extension_id(extension_id: &str) -> Self {
        Self {
            root: durable_path(&extension_state_dir(extension_id).join("remote-cache")),
            faults: DurableFaultInjector::default(),
            lock_timeout: REMOTE_CACHE_LOCK_TIMEOUT,
        }
    }

    pub fn new_at(path: impl AsRef<Path>) -> Self {
        Self {
            root: durable_path(path.as_ref()),
            faults: DurableFaultInjector::default(),
            lock_timeout: REMOTE_CACHE_LOCK_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_at_with_faults(path: impl AsRef<Path>, faults: DurableFaultInjector) -> Self {
        Self {
            root: durable_path(path.as_ref()),
            faults,
            lock_timeout: REMOTE_CACHE_LOCK_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn new_at_with_lock_timeout(path: impl AsRef<Path>, lock_timeout: Duration) -> Self {
        Self {
            root: durable_path(path.as_ref()),
            faults: DurableFaultInjector::default(),
            lock_timeout,
        }
    }

    pub fn read(&self, key: &RemoteCacheKey) -> Result<Option<RemoteVaultCacheEntry>> {
        Ok(match self.read_status(key)? {
            RemoteVaultCacheReadStatus::Current { entry, .. }
            | RemoteVaultCacheReadStatus::Degraded { entry, .. } => Some(entry),
            RemoteVaultCacheReadStatus::Missing | RemoteVaultCacheReadStatus::Corrupt { .. } => {
                None
            }
        })
    }

    pub fn read_status(&self, key: &RemoteCacheKey) -> Result<RemoteVaultCacheReadStatus> {
        if !self.root.exists() {
            return Ok(RemoteVaultCacheReadStatus::Missing);
        }
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "remote vault cache root is not a private directory: {}",
                self.root.display()
            )
        })?;
        let paths = self.paths(key);
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        Ok(match self.read_authenticated_locked(key) {
            AuthenticatedCacheRead::Missing => RemoteVaultCacheReadStatus::Missing,
            AuthenticatedCacheRead::Current(cached) => RemoteVaultCacheReadStatus::Current {
                source_etag: cached.generation.source_etag.clone(),
                entry: cached.entry,
            },
            AuthenticatedCacheRead::Degraded(cached) => RemoteVaultCacheReadStatus::Degraded {
                source_etag: cached.generation.source_etag.clone(),
                entry: cached.entry,
                warning:
                    "current cache generation failed authentication; using previous generation"
                        .to_owned(),
            },
            AuthenticatedCacheRead::Corrupt(reason) => {
                RemoteVaultCacheReadStatus::Corrupt { reason }
            }
        })
    }

    pub fn write(&self, key: &RemoteCacheKey, entry: RemoteVaultCacheEntry) -> Result<()> {
        self.write_with_source_etag(key, entry, None)
    }

    pub fn write_with_source_etag(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        source_etag: Option<&str>,
    ) -> Result<()> {
        require_durable_cache_publish(self.write_with_source_context(
            key,
            entry,
            None,
            source_etag,
            None,
            None,
        )?)
    }

    pub(crate) fn write_generic_pending_with_base(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        expected_current: &VaultSourceFingerprint,
        base: Option<RemoteVaultCacheEntry>,
    ) -> Result<()> {
        self.write_resident_pending(
            key,
            entry,
            expected_current,
            GenericPendingKind::SourceWrite,
            base,
        )
    }

    pub(crate) fn write_conflict_copy_pending(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        expected_current: &VaultSourceFingerprint,
    ) -> Result<()> {
        self.write_resident_pending(
            key,
            entry,
            expected_current,
            GenericPendingKind::ConflictCopy,
            None,
        )
    }

    fn write_resident_pending(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        expected_current: &VaultSourceFingerprint,
        kind: GenericPendingKind,
        base: Option<RemoteVaultCacheEntry>,
    ) -> Result<()> {
        if !entry.pending_sync {
            bail!("generic pending cache entry must be marked pending_sync");
        }
        require_durable_cache_publish(self.write_with_source_context(
            key,
            entry,
            base,
            None,
            None,
            Some(GenericPendingWriteProof {
                mode: GenericPendingWriteMode::Update,
                expected_fingerprint: expected_current,
                kind: Some(kind),
            }),
        )?)
    }

    pub(crate) fn complete_generic_pending(
        &self,
        key: &RemoteCacheKey,
        expected_pending: &VaultSourceFingerprint,
        entry: RemoteVaultCacheEntry,
    ) -> Result<PendingRemoteCacheCompletion> {
        if entry.pending_sync {
            bail!("completed generic cache entry cannot be pending_sync");
        }
        Ok(
            match self.write_with_source_context(
                key,
                entry,
                None,
                None,
                None,
                Some(GenericPendingWriteProof {
                    mode: GenericPendingWriteMode::Complete,
                    expected_fingerprint: expected_pending,
                    kind: None,
                }),
            )? {
                CacheManifestPublishOutcome::Durable => PendingRemoteCacheCompletion::Durable,
                CacheManifestPublishOutcome::DurabilityUnknown { .. } => {
                    PendingRemoteCacheCompletion::DurabilityUnknown
                }
            },
        )
    }

    pub(crate) fn complete_generic_pending_while<T>(
        &self,
        key: &RemoteCacheKey,
        expected_pending: &VaultSourceFingerprint,
        source_write: impl FnOnce() -> Result<(T, RemoteVaultCacheEntry)>,
    ) -> Result<(T, PendingRemoteCacheCompletion)> {
        let paths = self.paths(key);
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "failed to create remote vault cache dir: {}",
                self.root.display()
            )
        })?;
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        self.require_generic_pending_locked(key, expected_pending)?;
        let (value, entry) = source_write()?;
        if entry.pending_sync {
            bail!("completed generic cache entry cannot be pending_sync");
        }
        let outcome = self.write_with_source_context_locked(
            key,
            entry,
            None,
            None,
            None,
            Some(GenericPendingWriteProof {
                mode: GenericPendingWriteMode::Complete,
                expected_fingerprint: expected_pending,
                kind: None,
            }),
        )?;
        let completion = match outcome {
            CacheManifestPublishOutcome::Durable => PendingRemoteCacheCompletion::Durable,
            CacheManifestPublishOutcome::DurabilityUnknown { .. } => {
                PendingRemoteCacheCompletion::DurabilityUnknown
            }
        };
        Ok((value, completion))
    }

    pub(crate) fn generic_pending_kind(
        &self,
        key: &RemoteCacheKey,
        expected_pending: &VaultSourceFingerprint,
    ) -> Result<GenericPendingKind> {
        let paths = self.paths(key);
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "failed to create remote vault cache dir: {}",
                self.root.display()
            )
        })?;
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        let AuthenticatedCacheRead::Current(current) = self.read_authenticated_locked(key) else {
            return Err(PendingRemoteCacheConflict::new(
                "pending cache is unavailable before synchronization",
            )
            .into());
        };
        if !current.entry.pending_sync
            || !same_content_fingerprint(&current.entry.fingerprint, expected_pending)
        {
            return Err(PendingRemoteCacheConflict::new(
                "pending cache changed before synchronization",
            )
            .into());
        }
        match current.generation.pending_kind {
            Some(
                RemoteVaultPendingKind::Generic
                | RemoteVaultPendingKind::GenericFixedBase
                | RemoteVaultPendingKind::RetiredAutofill,
            ) => Ok(GenericPendingKind::SourceWrite),
            Some(RemoteVaultPendingKind::ConflictCopy) => Ok(GenericPendingKind::ConflictCopy),
            None if current.legacy => Ok(GenericPendingKind::SourceWrite),
            _ => Err(PendingRemoteCacheConflict::new(
                "pending cache kind is not a resident synchronization operation",
            )
            .into()),
        }
    }

    pub(crate) fn generic_pending_base(
        &self,
        key: &RemoteCacheKey,
        expected_pending: &VaultSourceFingerprint,
    ) -> Result<Option<RemoteVaultCacheEntry>> {
        let paths = self.paths(key);
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "failed to create remote vault cache dir: {}",
                self.root.display()
            )
        })?;
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        let AuthenticatedCacheRead::Current(current) = self.read_authenticated_locked(key) else {
            return Err(PendingRemoteCacheConflict::new(
                "pending cache is unavailable before reading its Base",
            )
            .into());
        };
        if !current.entry.pending_sync
            || !same_content_fingerprint(&current.entry.fingerprint, expected_pending)
            || (!current.legacy
                && !matches!(
                    current.generation.pending_kind,
                    Some(
                        RemoteVaultPendingKind::GenericFixedBase
                            | RemoteVaultPendingKind::RetiredAutofill
                    )
                ))
        {
            if current.generation.pending_kind == Some(RemoteVaultPendingKind::Generic) {
                return Ok(None);
            }
            return Err(PendingRemoteCacheConflict::new(
                "source-write pending cache changed before reading its Base",
            )
            .into());
        }
        let base =
            if current.generation.pending_kind == Some(RemoteVaultPendingKind::RetiredAutofill) {
                current.fallback
            } else {
                current.observed
            };
        let Some(base) = base else {
            return Ok(None);
        };
        if base.pending_sync || base.pending_kind != Some(RemoteVaultPendingKind::None) {
            return Err(PendingRemoteCacheConflict::new(
                "generic pending Base is not a committed generation",
            )
            .into());
        }
        let digest = cache_key_digest(key);
        let base = self
            .read_generation(&digest, &base, false)
            .map_err(|reason| {
                PendingRemoteCacheConflict::new(format!(
                    "generic pending Base is corrupt: {reason}"
                ))
            })?;
        Ok(Some(base.entry))
    }

    fn require_generic_pending_locked(
        &self,
        key: &RemoteCacheKey,
        expected_pending: &VaultSourceFingerprint,
    ) -> Result<()> {
        let AuthenticatedCacheRead::Current(current) = self.read_authenticated_locked(key) else {
            return Err(PendingRemoteCacheConflict::new(
                "generic pending cache is unavailable before source write",
            )
            .into());
        };
        let pending_is_generic = current.entry.pending_sync
            && (resident_pending_kind_matches(current.generation.pending_kind, None)
                || (current.legacy && current.observed.is_none()));
        if !pending_is_generic
            || !same_content_fingerprint(&current.entry.fingerprint, expected_pending)
        {
            return Err(PendingRemoteCacheConflict::new(
                "generic pending cache changed before source write",
            )
            .into());
        }
        Ok(())
    }

    fn write_with_source_context(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        base: Option<RemoteVaultCacheEntry>,
        source_etag: Option<&str>,
        source_revision: Option<u64>,
        generic_proof: Option<GenericPendingWriteProof<'_>>,
    ) -> Result<CacheManifestPublishOutcome> {
        let paths = self.paths(key);
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "failed to create remote vault cache dir: {}",
                self.root.display()
            )
        })?;
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        self.write_with_source_context_locked(
            key,
            entry,
            base,
            source_etag,
            source_revision,
            generic_proof,
        )
    }

    fn write_with_source_context_locked(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        base: Option<RemoteVaultCacheEntry>,
        source_etag: Option<&str>,
        source_revision: Option<u64>,
        generic_proof: Option<GenericPendingWriteProof<'_>>,
    ) -> Result<CacheManifestPublishOutcome> {
        let paths = self.paths(key);
        match fs::symlink_metadata(&paths.retired_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!(
                    "remote cache retirement marker is not a regular file: {}",
                    paths.retired_path.display()
                );
            }
            Ok(_) => bail!("remote cache was retired after its vault reference was deleted"),
        }

        let actual_sha256 = sha256_hex(&entry.bytes);
        if entry.fingerprint.content_sha256 != actual_sha256
            || entry.fingerprint.size_bytes != entry.bytes.len() as u64
        {
            bail!("remote cache fingerprint does not authenticate the supplied bytes");
        }
        let generic_update =
            generic_proof.is_some_and(|proof| proof.mode == GenericPendingWriteMode::Update);
        if base.is_some() && !generic_update {
            bail!("only a fixed-Base pending write may retain a Base generation");
        }
        if let Some(base) = &base
            && !fingerprint_authenticates(&base.fingerprint, &base.bytes)
        {
            bail!("pending Base fingerprint does not authenticate the supplied bytes");
        }

        let digest = cache_key_digest(key);
        let authenticated = self.read_authenticated_locked(key);
        let mut previous = match authenticated {
            AuthenticatedCacheRead::Current(previous) => {
                if let Some(proof) = generic_proof {
                    let expected_matches = same_content_fingerprint(
                        &previous.entry.fingerprint,
                        proof.expected_fingerprint,
                    );
                    if proof.mode == GenericPendingWriteMode::Complete
                        && !previous.entry.pending_sync
                    {
                        let completed_pending = previous
                            .fallback
                            .as_ref()
                            .filter(|generation| {
                                generation.pending_sync
                                    && resident_pending_kind_matches(
                                        generation.pending_kind,
                                        proof.kind,
                                    )
                                    && generation.content_sha256
                                        == proof.expected_fingerprint.content_sha256
                                    && generation.size_bytes
                                        == proof.expected_fingerprint.size_bytes
                            })
                            .and_then(|generation| {
                                self.read_generation(&digest, generation, false).ok()
                            });
                        if completed_pending.is_some()
                            && same_content_fingerprint(
                                &previous.entry.fingerprint,
                                &entry.fingerprint,
                            )
                        {
                            return Ok(CacheManifestPublishOutcome::Durable);
                        }
                    }
                    let pending_is_generic = previous.entry.pending_sync
                        && (resident_pending_kind_matches(
                            previous.generation.pending_kind,
                            proof.kind,
                        ) || (previous.legacy
                            && proof.kind != Some(GenericPendingKind::ConflictCopy)
                            && previous.observed.is_none()));
                    let authorized = match proof.mode {
                        GenericPendingWriteMode::Update => {
                            expected_matches && (!previous.entry.pending_sync || pending_is_generic)
                        }
                        GenericPendingWriteMode::Complete => expected_matches && pending_is_generic,
                    };
                    if !authorized {
                        return Err(PendingRemoteCacheConflict::new(
                            "generic pending cache proof does not match the committed generation",
                        )
                        .into());
                    }
                } else if previous.entry.pending_sync {
                    return Err(PendingRemoteCacheConflict::new(
                        "ordinary cache write cannot replace a pending generation",
                    )
                    .into());
                }
                Some(previous)
            }
            AuthenticatedCacheRead::Degraded(_) => {
                return Err(PendingRemoteCacheConflict::new(
                    "degraded committed cache state cannot be overwritten without explicit recovery",
                )
                .into());
            }
            AuthenticatedCacheRead::Corrupt(reason) => {
                return Err(PendingRemoteCacheConflict::new(format!(
                    "corrupt committed cache state cannot be overwritten without explicit recovery: {reason}"
                ))
                .into());
            }
            AuthenticatedCacheRead::Missing
                if generic_proof
                    .is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete) =>
            {
                return Err(PendingRemoteCacheConflict::new(
                    "pending cache completion requires an authenticated previous generation",
                )
                .into());
            }
            AuthenticatedCacheRead::Missing => None,
        };

        if let Some(previous) = &mut previous
            && previous.legacy
        {
            previous.generation.generation = self.ensure_generation(
                &digest,
                &previous.entry.bytes,
                &previous.entry.fingerprint.content_sha256,
            )?;
            previous.generation.pending_kind = Some(if previous.entry.pending_sync {
                RemoteVaultPendingKind::Generic
            } else {
                RemoteVaultPendingKind::None
            });
            previous.legacy = false;
        }

        let inherited_base = generic_proof
            .filter(|proof| proof.mode == GenericPendingWriteMode::Update)
            .filter(|_| base.is_none())
            .and_then(|_| previous.as_ref())
            .and_then(|previous| {
                if previous.entry.pending_sync {
                    if previous.generation.pending_kind
                        == Some(RemoteVaultPendingKind::RetiredAutofill)
                    {
                        previous.fallback.clone()
                    } else {
                        previous.observed.clone().or_else(|| {
                            previous
                                .fallback
                                .as_ref()
                                .filter(|generation| {
                                    !generation.pending_sync
                                        && generation.pending_kind
                                            == Some(RemoteVaultPendingKind::None)
                                })
                                .cloned()
                        })
                    }
                } else {
                    Some(previous.generation.clone())
                }
            });

        let generation = generation_name(&digest, &actual_sha256)
            .ok_or_else(|| anyhow!("remote cache content SHA-256 is not canonical"))?;
        let previous_generation = previous.and_then(|previous| {
            if generic_proof.is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete) {
                Some(previous.generation)
            } else if previous.generation.generation == generation {
                previous.fallback
            } else {
                Some(previous.generation)
            }
        });
        let observed_generation = base
            .map(|base| {
                let content_sha256 = base.fingerprint.content_sha256.clone();
                let generation = self.ensure_generation(&digest, &base.bytes, &content_sha256)?;
                Ok::<_, anyhow::Error>(RemoteVaultGeneration {
                    generation,
                    content_sha256,
                    size_bytes: base.bytes.len() as u64,
                    source_etag: None,
                    source_revision: None,
                    source_modified_at: base.fingerprint.modified_at,
                    display_name: base.display_name,
                    account_label: base.account_label,
                    cached_at: base.cached_at,
                    pending_sync: false,
                    pending_kind: Some(RemoteVaultPendingKind::None),
                })
            })
            .transpose()?
            .or(inherited_base);

        let ensured_generation = self.ensure_generation(&digest, &entry.bytes, &actual_sha256)?;
        debug_assert_eq!(ensured_generation, generation);
        let manifest = RemoteVaultCacheManifestV2 {
            version: 3,
            provider_kind: key.provider_kind.clone(),
            remote_id: key.remote_id.clone(),
            display_name: entry.display_name,
            account_label: entry.account_label,
            generation,
            content_sha256: actual_sha256,
            size_bytes: entry.bytes.len() as u64,
            source_etag: source_etag.map(str::to_owned),
            source_revision,
            source_modified_at: entry.fingerprint.modified_at,
            cached_at: entry.cached_at,
            pending_sync: entry.pending_sync,
            pending_kind: Some(if entry.pending_sync {
                generic_proof
                    .and_then(|proof| proof.kind)
                    .unwrap_or(GenericPendingKind::SourceWrite)
                    .manifest_kind()
            } else {
                RemoteVaultPendingKind::None
            }),
            previous_generation,
            observed_generation,
        };
        let metadata_bytes = serde_json::to_vec_pretty(&manifest)
            .context("failed to encode remote cache metadata")?;
        let publish = self.publish_manifest(&paths.metadata_path, &metadata_bytes)?;
        match &publish {
            CacheManifestPublishOutcome::Durable => self.cleanup_generations(&digest, &manifest),
            CacheManifestPublishOutcome::DurabilityUnknown { .. } => {
                let visible = self.read_authenticated_locked(key);
                if generic_proof
                    .is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete)
                    && !matches!(
                        visible,
                        AuthenticatedCacheRead::Current(ref current)
                            if !current.entry.pending_sync
                                && same_content_fingerprint(
                                    &current.entry.fingerprint,
                                    &entry.fingerprint,
                                )
                    )
                {
                    return Err(anyhow!(
                        "cache completion publish outcome is unknown and the resolved generation is not visible"
                    ));
                }
            }
        }
        Ok(publish)
    }

    fn ensure_deletable_locked(&self, key: &RemoteCacheKey) -> Result<()> {
        match self.read_authenticated_locked(key) {
            AuthenticatedCacheRead::Missing => {}
            AuthenticatedCacheRead::Current(current) if !current.entry.pending_sync => {}
            AuthenticatedCacheRead::Current(_) => {
                return Err(PendingRemoteCacheConflict::new(
                    "pending remote cache cannot be deleted without explicit resolution",
                )
                .into());
            }
            AuthenticatedCacheRead::Degraded(_) => {
                return Err(PendingRemoteCacheConflict::new(
                    "degraded remote cache cannot be deleted without explicit recovery",
                )
                .into());
            }
            AuthenticatedCacheRead::Corrupt(reason) => {
                return Err(PendingRemoteCacheConflict::new(format!(
                    "corrupt remote cache cannot be deleted without explicit recovery: {reason}"
                ))
                .into());
            }
        }
        Ok(())
    }

    pub(crate) fn activate_while<T>(
        &self,
        key: &RemoteCacheKey,
        commit_reference: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "remote vault cache root is not a private directory: {}",
                self.root.display()
            )
        })?;
        let paths = self.paths(key);
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .with_context(|| {
                format!(
                    "failed to acquire remote vault cache lock: {}",
                    paths.lock_path.display()
                )
            })?;
        let result = commit_reference()?;
        remove_and_sync_absence(&paths.retired_path).with_context(|| {
            format!(
                "failed to clear remote vault cache retirement marker: {}",
                paths.retired_path.display()
            )
        })?;
        Ok(result)
    }

    pub(crate) fn recover_activation_while(
        &self,
        key: &RemoteCacheKey,
        reference_is_current: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        if !self.root.exists() {
            return Ok(true);
        }
        create_dir_all_durable(&self.root)?;
        let paths = self.paths(key);
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)?;
        if !reference_is_current()? {
            return Ok(false);
        }
        if paths.retired_path.exists() {
            remove_and_sync_absence(&paths.retired_path)?;
        }
        Ok(true)
    }

    pub(crate) fn begin_retirement(
        &self,
        key: &RemoteCacheKey,
    ) -> Result<RemoteCacheCleanupGuard<'_>> {
        create_dir_all_durable(&self.root)?;
        let paths = self.paths(key);
        let lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)?;
        self.ensure_deletable_locked(key)?;
        self.persist_retirement_marker(&paths)?;
        Ok(RemoteCacheCleanupGuard {
            cache: self,
            key: key.clone(),
            paths,
            _lock: lock,
        })
    }

    pub(crate) fn begin_cleanup_after_intent(
        &self,
        key: &RemoteCacheKey,
    ) -> Result<RemoteCacheCleanupGuard<'_>> {
        create_dir_all_durable(&self.root)?;
        let paths = self.paths(key);
        let lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)?;
        self.ensure_cleanup_intent_deletable_locked(key)?;
        self.persist_retirement_marker(&paths)?;
        Ok(RemoteCacheCleanupGuard {
            cache: self,
            key: key.clone(),
            paths,
            _lock: lock,
        })
    }

    fn persist_retirement_marker(&self, paths: &RemoteVaultCachePaths) -> Result<()> {
        durable_replace(&paths.retired_path, b"VaultKern remote cache retired v1\n").with_context(
            || {
                format!(
                    "failed to persist remote vault cache retirement marker: {}",
                    paths.retired_path.display()
                )
            },
        )
    }

    fn delete_files_locked(
        &self,
        key: &RemoteCacheKey,
        paths: &RemoteVaultCachePaths,
    ) -> Result<()> {
        // The manifest is the commit point.  Make its absence durable before
        // deleting generations so a crash can only expose Missing, never a
        // manifest that points at an already-removed generation.
        remove_and_sync_absence(&paths.metadata_path)?;
        remove_file_if_exists(&paths.bytes_path)?;
        let digest = cache_key_digest(key);
        for entry in fs::read_dir(&self.root).with_context(|| {
            format!(
                "failed to enumerate remote vault cache dir: {}",
                self.root.display()
            )
        })? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_generation_name(&digest, &name) {
                remove_file_if_exists(&entry.path())?;
            }
        }
        sync_directory(&self.root).with_context(|| {
            format!(
                "failed to synchronize remote vault cache dir: {}",
                self.root.display()
            )
        })
    }

    fn ensure_cleanup_intent_deletable_locked(&self, key: &RemoteCacheKey) -> Result<()> {
        match self.read_authenticated_locked(key) {
            AuthenticatedCacheRead::Missing => Ok(()),
            AuthenticatedCacheRead::Current(current)
            | AuthenticatedCacheRead::Degraded(current)
                if current.entry.pending_sync =>
            {
                Err(PendingRemoteCacheConflict::new(
                    "pending remote cache appeared after cleanup was requested",
                )
                .into())
            }
            AuthenticatedCacheRead::Current(_) | AuthenticatedCacheRead::Degraded(_) => Ok(()),
            AuthenticatedCacheRead::Corrupt(_) => {
                let paths = self.paths(key);
                let pending = read_regular_file(&paths.metadata_path)
                    .ok()
                    .and_then(|bytes| {
                        serde_json::from_slice::<RemoteVaultCacheManifestV2>(&bytes).ok()
                    })
                    .is_some_and(|manifest| manifest.pending_sync);
                if pending {
                    Err(PendingRemoteCacheConflict::new(
                        "pending remote cache became corrupt after cleanup was requested",
                    )
                    .into())
                } else {
                    Ok(())
                }
            }
        }
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
            lock_path: self.root.join(format!("{digest}.lock")),
            retired_path: self.root.join(format!("{digest}.retired")),
        }
    }

    fn read_authenticated_locked(&self, key: &RemoteCacheKey) -> AuthenticatedCacheRead {
        let paths = self.paths(key);
        let metadata_bytes = match read_regular_file(&paths.metadata_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return AuthenticatedCacheRead::Missing;
            }
            Err(error) => {
                return AuthenticatedCacheRead::Corrupt(format!(
                    "could not read committed cache manifest: {error}"
                ));
            }
        };
        let value = match serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
            Ok(value) => value,
            Err(error) => {
                return AuthenticatedCacheRead::Corrupt(format!(
                    "committed cache manifest is not valid JSON: {error}"
                ));
            }
        };
        match value.get("version").and_then(serde_json::Value::as_u64) {
            Some(version @ (2 | 3)) => {
                let manifest = match serde_json::from_value::<RemoteVaultCacheManifestV2>(value) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        return AuthenticatedCacheRead::Corrupt(format!(
                            "versioned cache manifest is malformed: {error}"
                        ));
                    }
                };
                if manifest.version as u64 != version
                    || manifest.provider_kind != key.provider_kind
                    || manifest.remote_id != key.remote_id
                {
                    return AuthenticatedCacheRead::Corrupt(
                        "cache manifest identity does not match its digest key".to_owned(),
                    );
                }
                if version == 3
                    && (!generation_pending_schema_is_valid(&manifest.current_generation())
                        || manifest
                            .previous_generation
                            .as_ref()
                            .is_some_and(|generation| {
                                !generation_pending_schema_is_valid(generation)
                            })
                        || manifest
                            .observed_generation
                            .as_ref()
                            .is_some_and(|generation| {
                                !generation_pending_schema_is_valid(generation)
                            }))
                {
                    return AuthenticatedCacheRead::Corrupt(
                        "cache manifest pending kind is inconsistent with its fields".into(),
                    );
                }
                let digest = cache_key_digest(key);
                let current = manifest.current_generation();
                match self.read_generation(&digest, &current, false) {
                    Ok(mut entry) => {
                        entry.fallback = manifest.previous_generation;
                        entry.observed = manifest.observed_generation;
                        entry.legacy = version != 3;
                        AuthenticatedCacheRead::Current(entry)
                    }
                    Err(current_error) => match manifest.previous_generation.as_ref() {
                        Some(previous) => match self.read_generation(&digest, previous, true) {
                            Ok(mut entry) => {
                                entry.legacy = version != 3;
                                AuthenticatedCacheRead::Degraded(entry)
                            }
                            Err(previous_error) => AuthenticatedCacheRead::Corrupt(format!(
                                "current generation failed authentication ({current_error}); previous generation also failed ({previous_error})"
                            )),
                        },
                        None => AuthenticatedCacheRead::Corrupt(format!(
                            "current generation failed authentication: {current_error}"
                        )),
                    },
                }
            }
            Some(version) => AuthenticatedCacheRead::Corrupt(format!(
                "unsupported remote cache manifest version {version}"
            )),
            None => {
                let metadata = match serde_json::from_value::<RemoteVaultCacheMetadata>(value) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        return AuthenticatedCacheRead::Corrupt(format!(
                            "legacy cache metadata is malformed: {error}"
                        ));
                    }
                };
                if metadata.provider_kind != key.provider_kind
                    || metadata.remote_id != key.remote_id
                {
                    return AuthenticatedCacheRead::Corrupt(
                        "legacy cache metadata identity does not match its digest key".to_owned(),
                    );
                }
                let bytes = match read_regular_file(&paths.bytes_path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return AuthenticatedCacheRead::Corrupt(format!(
                            "legacy cache bytes are missing or unreadable: {error}"
                        ));
                    }
                };
                if !fingerprint_authenticates(&metadata.fingerprint, &bytes) {
                    return AuthenticatedCacheRead::Corrupt(
                        "legacy cache bytes do not match metadata hash and size".to_owned(),
                    );
                }
                let generation = RemoteVaultGeneration {
                    generation: paths
                        .bytes_path
                        .file_name()
                        .expect("cache path has a file name")
                        .to_string_lossy()
                        .into_owned(),
                    content_sha256: metadata.fingerprint.content_sha256.clone(),
                    size_bytes: metadata.fingerprint.size_bytes,
                    source_etag: None,
                    source_revision: None,
                    source_modified_at: metadata.fingerprint.modified_at,
                    display_name: metadata.display_name.clone(),
                    account_label: metadata.account_label.clone(),
                    cached_at: metadata.cached_at,
                    pending_sync: metadata.pending_sync,
                    pending_kind: None,
                };
                AuthenticatedCacheRead::Current(AuthenticatedCacheEntry {
                    entry: RemoteVaultCacheEntry {
                        bytes,
                        fingerprint: metadata.fingerprint,
                        display_name: metadata.display_name,
                        account_label: metadata.account_label,
                        cached_at: metadata.cached_at,
                        pending_sync: metadata.pending_sync,
                    },
                    generation,
                    fallback: None,
                    observed: None,
                    legacy: true,
                })
            }
        }
    }

    fn read_generation(
        &self,
        digest: &str,
        generation: &RemoteVaultGeneration,
        degraded: bool,
    ) -> std::result::Result<AuthenticatedCacheEntry, String> {
        let expected_name = generation_name(digest, &generation.content_sha256)
            .ok_or_else(|| "manifest generation SHA-256 is not canonical".to_owned())?;
        if generation.generation != expected_name {
            return Err("manifest generation name does not bind its digest and hash".to_owned());
        }
        let bytes = read_regular_file(&self.root.join(&generation.generation))
            .map_err(|error| format!("generation is missing or unreadable: {error}"))?;
        let fingerprint = VaultSourceFingerprint {
            content_sha256: generation.content_sha256.clone(),
            size_bytes: generation.size_bytes,
            modified_at: generation.source_modified_at,
        };
        if !fingerprint_authenticates(&fingerprint, &bytes) {
            return Err("generation bytes do not match manifest hash and size".to_owned());
        }
        Ok(AuthenticatedCacheEntry {
            entry: RemoteVaultCacheEntry {
                bytes,
                fingerprint,
                display_name: generation.display_name.clone(),
                account_label: generation.account_label.clone(),
                cached_at: generation.cached_at,
                pending_sync: generation.pending_sync || degraded,
            },
            generation: generation.clone(),
            fallback: None,
            observed: None,
            legacy: false,
        })
    }

    fn ensure_generation(&self, digest: &str, bytes: &[u8], sha256: &str) -> Result<String> {
        let name = generation_name(digest, sha256)
            .ok_or_else(|| anyhow!("remote cache content SHA-256 is not canonical"))?;
        let target = self.root.join(&name);
        if target.exists() {
            let existing = read_regular_file(&target).with_context(|| {
                format!(
                    "failed to verify immutable remote cache generation: {}",
                    target.display()
                )
            })?;
            if existing.len() != bytes.len() || sha256_hex(&existing) != sha256 {
                bail!(
                    "immutable remote cache generation failed authentication: {}",
                    target.display()
                );
            }
            return Ok(name);
        }

        let temp = write_verified_temp(
            &target,
            bytes,
            &self.faults,
            TempWriteFaultPoints {
                created: DurableFaultPoint::GenerationTempCreated,
                written: DurableFaultPoint::GenerationTempWritten,
                synced: DurableFaultPoint::GenerationTempSynced,
                verified: DurableFaultPoint::GenerationReadbackVerified,
            },
        )
        .with_context(|| {
            format!(
                "failed to write remote cache generation temp: {}",
                target.display()
            )
        })?;
        if let Err(error) = publish_temp(
            temp,
            &target,
            TargetExpectation::Missing,
            None,
            &self.faults,
            DurableFaultPoint::BeforeGenerationPublish,
            DurableFaultPoint::GenerationPublished,
            DurableFaultPoint::GenerationParentSynced,
        ) {
            return Err(error.source).with_context(|| {
                format!(
                    "failed to publish remote cache generation: {}",
                    target.display()
                )
            });
        }
        Ok(name)
    }

    fn publish_manifest(&self, target: &Path, bytes: &[u8]) -> Result<CacheManifestPublishOutcome> {
        let target_expectation = manifest_target_expectation(target).with_context(|| {
            format!(
                "failed to verify remote cache manifest target: {}",
                target.display()
            )
        })?;
        let temp = write_verified_temp(
            target,
            bytes,
            &self.faults,
            TempWriteFaultPoints {
                created: DurableFaultPoint::ManifestTempCreated,
                written: DurableFaultPoint::ManifestTempWritten,
                synced: DurableFaultPoint::ManifestTempSynced,
                verified: DurableFaultPoint::ManifestReadbackVerified,
            },
        )
        .with_context(|| {
            format!(
                "failed to write remote cache manifest temp: {}",
                target.display()
            )
        })?;
        let backup = match create_manifest_backup(target) {
            Ok(backup) => backup,
            Err(error) => {
                let _ = temp.discard();
                return Err(error).with_context(|| {
                    format!(
                        "failed to preserve remote cache manifest: {}",
                        target.display()
                    )
                });
            }
        };
        if let Err(error) = publish_temp(
            temp,
            target,
            target_expectation,
            backup.as_deref(),
            &self.faults,
            DurableFaultPoint::BeforeManifestReplace,
            DurableFaultPoint::ManifestReplaced,
            DurableFaultPoint::ManifestParentSynced,
        ) {
            if !error.published {
                if let Some(backup) = &backup {
                    let _ = remove_if_exists(backup);
                }
                let _ = sync_parent(target);
                return Err(CacheManifestNotPublished {
                    source: anyhow!(error.source).context(format!(
                        "failed to publish remote cache manifest: {}",
                        target.display()
                    )),
                }
                .into());
            }
            let publish_error = anyhow!(error.source).context(format!(
                "remote cache manifest was replaced but durability was not confirmed: {}",
                target.display()
            ));
            let visible_repair_error = if read_regular_file(target)
                .ok()
                .is_some_and(|current| current == bytes)
            {
                match sync_published_target(target).and_then(|_| sync_parent(target)) {
                    Ok(()) => {
                        if let Some(backup) = backup {
                            let _ = remove_if_exists(&backup).and_then(|_| sync_parent(target));
                        }
                        return Ok(CacheManifestPublishOutcome::Durable);
                    }
                    Err(repair_error) => Some(repair_error),
                }
            } else {
                None
            };

            let restore = (|| -> Result<()> {
                if let Some(backup) = backup.as_deref() {
                    let previous = read_regular_file(backup).with_context(|| {
                        format!(
                            "remote cache manifest backup disappeared before recovery: {}",
                            backup.display()
                        )
                    })?;
                    durable_replace(target, &previous)?;
                } else {
                    remove_and_sync_absence(target)?;
                }
                Ok(())
            })();
            return match restore {
                Ok(()) => {
                    if let Some(backup) = backup {
                        let _ = remove_if_exists(&backup).and_then(|_| sync_parent(target));
                    }
                    Err(CacheManifestNotPublished {
                        source: if let Some(repair_error) = visible_repair_error {
                            publish_error.context(format!(
                                "visible manifest durability repair failed ({repair_error}); the previous manifest state was restored"
                            ))
                        } else {
                            publish_error.context(
                                "the previous remote cache manifest state was restored",
                            )
                        },
                    }
                    .into())
                }
                Err(recovery_error) => Ok(CacheManifestPublishOutcome::DurabilityUnknown {
                    source: publish_error.context(match visible_repair_error {
                        Some(repair_error) => format!(
                            "visible manifest durability repair failed ({repair_error}) and rollback failed ({recovery_error})"
                        ),
                        None => format!(
                            "failed to recover either manifest state: {recovery_error}"
                        ),
                    }),
                }),
            };
        }

        let _post_durable_fault = self
            .faults
            .check(DurableFaultPoint::CacheManifestDurable)
            .err();

        if let Some(backup) = backup {
            let _ = remove_if_exists(&backup).and_then(|_| sync_parent(target));
        }
        Ok(CacheManifestPublishOutcome::Durable)
    }

    fn cleanup_generations(&self, digest: &str, manifest: &RemoteVaultCacheManifestV2) {
        let mut keep = vec![manifest.generation.as_str()];
        if let Some(previous) = &manifest.previous_generation {
            keep.push(previous.generation.as_str());
        }
        if let Some(observed) = &manifest.observed_generation {
            keep.push(observed.generation.as_str());
        }
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        let mut removed = false;
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_generation_name(digest, &name) && !keep.contains(&name.as_str()) {
                removed |= remove_if_exists(&entry.path()).is_ok();
            }
        }
        if removed {
            let _ = sync_directory(&self.root);
        }
    }
}

impl RemoteVaultCacheManifestV2 {
    fn current_generation(&self) -> RemoteVaultGeneration {
        RemoteVaultGeneration {
            generation: self.generation.clone(),
            content_sha256: self.content_sha256.clone(),
            size_bytes: self.size_bytes,
            source_etag: self.source_etag.clone(),
            source_revision: self.source_revision,
            source_modified_at: self.source_modified_at,
            display_name: self.display_name.clone(),
            account_label: self.account_label.clone(),
            cached_at: self.cached_at,
            pending_sync: self.pending_sync,
            pending_kind: self.pending_kind,
        }
    }
}

fn fingerprint_authenticates(fingerprint: &VaultSourceFingerprint, bytes: &[u8]) -> bool {
    fingerprint.size_bytes == bytes.len() as u64 && fingerprint.content_sha256 == sha256_hex(bytes)
}

fn same_content_fingerprint(left: &VaultSourceFingerprint, right: &VaultSourceFingerprint) -> bool {
    left.size_bytes == right.size_bytes && left.content_sha256 == right.content_sha256
}

fn require_durable_cache_publish(outcome: CacheManifestPublishOutcome) -> Result<()> {
    match outcome {
        CacheManifestPublishOutcome::Durable => Ok(()),
        CacheManifestPublishOutcome::DurabilityUnknown { source } => {
            Err(source).context("remote cache publish durability is unknown")
        }
    }
}

fn generation_pending_schema_is_valid(generation: &RemoteVaultGeneration) -> bool {
    match generation.pending_kind {
        Some(RemoteVaultPendingKind::None) => !generation.pending_sync,
        Some(
            RemoteVaultPendingKind::Generic
            | RemoteVaultPendingKind::GenericFixedBase
            | RemoteVaultPendingKind::ConflictCopy
            | RemoteVaultPendingKind::RetiredAutofill,
        ) => generation.pending_sync,
        None => false,
    }
}

fn generation_name(digest: &str, sha256: &str) -> Option<String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(format!("{digest}.{sha256}.kdbx"))
}

fn is_generation_name(digest: &str, name: &str) -> bool {
    let Some(sha256) = name
        .strip_prefix(&format!("{digest}."))
        .and_then(|name| name.strip_suffix(".kdbx"))
    else {
        return false;
    };
    generation_name(digest, sha256).as_deref() == Some(name)
}

fn manifest_target_expectation(path: &Path) -> io::Result<TargetExpectation> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(TargetExpectation::Missing),
        Err(error) => Err(error),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "remote cache manifest target is not a regular file",
                ));
            }
            reject_cache_reparse_point(&metadata)?;
            Ok(TargetExpectation::Identity(path_file_identity(
                path, &metadata,
            )?))
        }
    }
}

fn read_regular_file(path: &Path) -> io::Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote cache path is not a regular file",
        ));
    }
    reject_cache_reparse_point(&path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    let before_identity = opened_file_identity(&file, &before)?;
    if !before.is_file() || before_identity != path_file_identity(path, &path_metadata)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "remote cache path changed while opening",
        ));
    }
    reject_cache_reparse_point(&before)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let after_identity = opened_file_identity(&file, &after)?;
    let final_path_metadata = fs::symlink_metadata(path)?;
    reject_cache_reparse_point(&final_path_metadata)?;
    if before_identity != after_identity
        || after_identity != path_file_identity(path, &final_path_metadata)?
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "remote cache path changed while reading",
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn reject_cache_reparse_point(metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote cache path is a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_cache_reparse_point(_metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

fn create_manifest_backup(target: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "remote cache manifest target is not a regular file",
            ));
        }
        Ok(_) => {}
    }

    #[cfg(unix)]
    {
        for _ in 0..128 {
            let backup = unique_sibling_path(target, "bak")?;
            match fs::hard_link(target, &backup) {
                Ok(()) => {
                    sync_parent(target)?;
                    return Ok(Some(backup));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique remote cache manifest backup",
        ))
    }
    #[cfg(windows)]
    {
        Ok(Some(unique_sibling_path(target, "bak")?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        for _ in 0..128 {
            let backup = unique_sibling_path(target, "bak")?;
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&backup)
            {
                Ok(_) => {
                    fs::copy(target, &backup)?;
                    sync_parent(target)?;
                    return Ok(Some(backup));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique remote cache manifest backup",
        ))
    }
}

fn cache_key_digest(key: &RemoteCacheKey) -> String {
    let mut hasher = Sha256::new();
    let provider_kind = key.provider_kind.replace('%', "%25").replace(':', "%3A");
    hasher.update(provider_kind.as_bytes());
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
    use super::{
        PendingRemoteCacheCompletion, PendingRemoteCacheConflict, RemoteCacheKey, RemoteVaultCache,
        RemoteVaultCacheEntry, RemoteVaultCacheMetadata, RemoteVaultCacheReadStatus,
        cache_key_digest,
    };
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock, sha256_hex,
    };
    use crate::providers::local_file::VaultSourceFingerprint;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};

    fn fingerprint(bytes: &[u8], modified_at: u64) -> VaultSourceFingerprint {
        VaultSourceFingerprint {
            content_sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            modified_at: Some(modified_at),
        }
    }

    fn entry(bytes: &[u8], modified_at: u64, pending_sync: bool) -> RemoteVaultCacheEntry {
        RemoteVaultCacheEntry {
            bytes: bytes.to_vec(),
            fingerprint: fingerprint(bytes, modified_at),
            display_name: "Cloud Vault".into(),
            account_label: "alice@example.com".into(),
            cached_at: 1_776_500_000 + modified_at as i64,
            pending_sync,
        }
    }

    fn key() -> RemoteCacheKey {
        RemoteCacheKey::new("onedrive", "drive-1:item-1")
    }

    #[test]
    fn cache_key_digest_preserves_component_boundaries() {
        assert_ne!(
            cache_key_digest(&RemoteCacheKey::new("provider:tenant", "item")),
            cache_key_digest(&RemoteCacheKey::new("provider", "tenant:item"))
        );
    }

    #[test]
    fn cache_lock_contention_returns_instead_of_waiting_for_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at_with_lock_timeout(
            dir.path(),
            std::time::Duration::from_millis(40),
        );
        cache.write(&key(), entry(b"current", 1, false)).unwrap();
        let paths = cache.paths_for_tests(&key());
        let held = ExclusiveFileLock::acquire(&paths.lock_path).unwrap();
        let competing_cache = cache.clone();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            result_tx.send(competing_cache.read_status(&key())).unwrap();
        });

        let result = result_rx.recv_timeout(std::time::Duration::from_millis(250));
        drop(held);
        handle.join().unwrap();

        let error = result
            .expect("cache contender waited indefinitely for the held lock")
            .expect_err("cache contender unexpectedly acquired the held lock");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn generic_completion_rejects_stale_pending_before_source_write() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let current = entry(b"current", 1, false);
        cache.write(&key(), current.clone()).unwrap();
        let pending_a = entry(b"pending-a", 2, true);
        cache
            .write_generic_pending_with_base(&key(), pending_a.clone(), &current.fingerprint, None)
            .unwrap();
        let pending_b = entry(b"pending-b", 3, true);
        cache
            .write_generic_pending_with_base(&key(), pending_b, &pending_a.fingerprint, None)
            .unwrap();
        let source_write_called = std::cell::Cell::new(false);

        let result = cache.complete_generic_pending_while(&key(), &pending_a.fingerprint, || {
            source_write_called.set(true);
            Ok(((), entry(b"remote", 4, false)))
        });

        assert!(result.is_err());
        assert!(!source_write_called.get());
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"pending-b");
    }

    #[test]
    fn generic_completion_holds_cache_lock_across_source_write() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let current = entry(b"current", 1, false);
        cache.write(&key(), current.clone()).unwrap();
        let pending = entry(b"pending", 2, true);
        cache
            .write_generic_pending_with_base(&key(), pending.clone(), &current.fingerprint, None)
            .unwrap();
        let competing_cache = cache.clone();
        let expected = pending.fingerprint.clone();
        let competing = entry(b"competing", 3, true);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let handle = std::cell::RefCell::new(None);

        cache
            .complete_generic_pending_while(&key(), &pending.fingerprint, || {
                handle.replace(Some(std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let result = competing_cache.write_generic_pending_with_base(
                        &key(),
                        competing,
                        &expected,
                        None,
                    );
                    finished_tx.send(result.is_ok()).unwrap();
                })));
                started_rx.recv().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
                assert!(finished_rx.try_recv().is_err());
                Ok(((), entry(b"remote", 4, false)))
            })
            .unwrap();

        handle.into_inner().unwrap().join().unwrap();
        assert!(!finished_rx.recv().unwrap());
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"remote");
    }

    fn read_manifest(cache: &RemoteVaultCache) -> Value {
        let paths = cache.paths_for_tests(&key());
        serde_json::from_slice(&fs::read(paths.metadata_path).unwrap()).unwrap()
    }

    fn generation_path(cache: &RemoteVaultCache, generation: &str) -> PathBuf {
        cache
            .paths_for_tests(&key())
            .metadata_path
            .parent()
            .unwrap()
            .join(generation)
    }

    fn current_generation_path(cache: &RemoteVaultCache) -> PathBuf {
        let manifest = read_manifest(cache);
        generation_path(cache, manifest["generation"].as_str().unwrap())
    }

    fn sidecar_artifacts(root: &Path) -> Vec<String> {
        let mut names = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".vaultkern.tmp.") || name.contains(".vaultkern.bak."))
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn replace_only_temp_file(root: &Path, bytes: &[u8]) {
        let temp = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".vaultkern.tmp.")
            })
            .expect("verified temp exists")
            .path();
        fs::remove_file(&temp).unwrap();
        fs::write(temp, bytes).unwrap();
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

        cache.write(&key(), entry(b"kdbx", 42, false)).unwrap();

        let cached = cache.read(&key()).unwrap().expect("cache hit");
        assert_eq!(cached.bytes, b"kdbx");
        assert_eq!(cached.fingerprint, fingerprint(b"kdbx", 42));
        assert_eq!(cached.display_name, "Cloud Vault");
        assert_eq!(cached.account_label, "alice@example.com");
        assert_eq!(cached.cached_at, 1_776_500_042);
        assert!(!cached.pending_sync);

        let paths = cache.paths_for_tests(&key());
        assert!(
            !paths.bytes_path.exists(),
            "v2 must not rewrite the v1 path"
        );
        let manifest = read_manifest(&cache);
        assert_eq!(manifest["version"], 3);
        assert_eq!(manifest["contentSha256"], sha256_hex(b"kdbx"));
        assert_eq!(manifest["sizeBytes"], 4);
        assert!(manifest["sourceEtag"].is_null());
        assert!(manifest["previousGeneration"].is_null());
        let generation = manifest["generation"].as_str().unwrap();
        assert!(generation.ends_with(&format!(".{}.kdbx", sha256_hex(b"kdbx"))));
        assert_eq!(
            fs::read(generation_path(&cache, generation)).unwrap(),
            b"kdbx"
        );
    }

    #[test]
    fn newly_created_cache_root_roundtrips() {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nested").join("remote-cache");
        let cache = RemoteVaultCache::new_at(&root);
        cache.write(&key(), entry(b"private", 1, false)).unwrap();
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"private");

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&root).unwrap();
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }

    #[cfg(windows)]
    #[test]
    fn non_verbatim_cache_root_supports_long_durable_names() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let parent = tempfile::tempdir().unwrap();
        let wide = parent.path().as_os_str().encode_wide().collect::<Vec<_>>();
        let verbatim_prefix = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        let ordinary_parent = if wide.starts_with(&verbatim_prefix) {
            PathBuf::from(OsString::from_wide(&wide[verbatim_prefix.len()..]))
        } else {
            parent.path().to_path_buf()
        };
        let root = ordinary_parent.join(format!(
            "vaultkern-runtime-test-remote-cache-{}",
            uuid::Uuid::new_v4()
        ));
        let cache = RemoteVaultCache::new_at(&root);

        cache.write(&key(), entry(b"long-path", 1, false)).unwrap();

        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"long-path");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_cache_root_is_rejected_before_creating_artifacts() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        let error = cache
            .write(&key(), entry(b"unsafe", 1, false))
            .expect_err("writable cache roots are not trustworthy");

        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("private"))
        );
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_nonsticky_cache_parent_is_rejected_before_root_creation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("unsafe-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let root = parent.join("remote-cache");

        RemoteVaultCache::new_at(&root)
            .write(&key(), entry(b"unsafe", 1, false))
            .expect_err("a replaceable cache parent cannot anchor private state");

        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_symlink_cache_root_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let attacker = dir.path().join("attacker");
        let redirected = attacker.join("remote-cache");
        fs::create_dir_all(&redirected).unwrap();
        let link = dir.path().join("state-link");
        symlink(&attacker, &link).unwrap();
        let cache = RemoteVaultCache::new_at(link.join("remote-cache"));

        cache
            .write(&key(), entry(b"redirected", 1, false))
            .expect_err("every cache path component must reject symlinks");

        assert!(fs::read_dir(&redirected).unwrap().next().is_none());
    }

    #[test]
    fn write_then_read_preserves_pending_sync_marker() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        cache.write(&key(), entry(b"kdbx", 10, true)).unwrap();

        let cached = cache.read(&key()).unwrap().expect("cache hit");
        assert!(cached.pending_sync);
    }

    #[test]
    fn generic_pending_updates_require_the_exact_loaded_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_generic_pending_with_base(
                &key(),
                entry(b"pending-1", 11, true),
                &fingerprint(b"baseline", 10),
                None,
            )
            .unwrap();

        let stale_error = cache
            .write_generic_pending_with_base(
                &key(),
                entry(b"stale-must-not-win", 12, true),
                &fingerprint(b"baseline", 10),
                None,
            )
            .expect_err("a stale generic pending writer must lose its cache CAS");
        assert!(stale_error.is::<PendingRemoteCacheConflict>());
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"pending-1");

        cache
            .write_generic_pending_with_base(
                &key(),
                entry(b"pending-2", 13, true),
                &fingerprint(b"pending-1", 11),
                None,
            )
            .unwrap();
        let ordinary_error = cache
            .write(&key(), entry(b"ordinary-must-not-win", 14, false))
            .expect_err("ordinary writes cannot bypass generic pending CAS");
        assert!(ordinary_error.is::<PendingRemoteCacheConflict>());

        let wrong_completion = cache
            .complete_generic_pending(
                &key(),
                &fingerprint(b"pending-1", 11),
                entry(b"resolved", 15, false),
            )
            .expect_err("generic completion must bind the latest pending generation");
        assert!(wrong_completion.is::<PendingRemoteCacheConflict>());
        assert_eq!(
            cache
                .complete_generic_pending(
                    &key(),
                    &fingerprint(b"pending-2", 13),
                    entry(b"resolved", 15, false),
                )
                .unwrap(),
            PendingRemoteCacheCompletion::Durable
        );
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"resolved");
    }

    #[test]
    fn generic_pending_base_survives_later_pending_generations() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let base = entry(b"fixed-base", 10, false);
        cache.write(&key(), base.clone()).unwrap();
        let pending_1 = entry(b"pending-1", 11, true);
        cache
            .write_generic_pending_with_base(
                &key(),
                pending_1.clone(),
                &base.fingerprint,
                Some(base.clone()),
            )
            .unwrap();
        let pending_2 = entry(b"pending-2", 12, true);
        cache
            .write_generic_pending_with_base(
                &key(),
                pending_2.clone(),
                &pending_1.fingerprint,
                Some(base.clone()),
            )
            .unwrap();

        assert_eq!(
            cache
                .generic_pending_base(&key(), &pending_2.fingerprint)
                .unwrap(),
            Some(base)
        );
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
        assert!(matches!(
            cache.read_status(&key()).unwrap(),
            RemoteVaultCacheReadStatus::Corrupt { .. }
        ));
    }

    #[test]
    fn source_etag_is_preserved_in_v2_manifest_and_typed_read_status() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache
            .write_with_source_etag(&key(), entry(b"kdbx", 42, false), Some("etag-42"))
            .unwrap();

        assert_eq!(read_manifest(&cache)["sourceEtag"], "etag-42");
        assert!(matches!(
            cache.read_status(&key()).unwrap(),
            RemoteVaultCacheReadStatus::Current {
                source_etag: Some(etag),
                ..
            } if etag == "etag-42"
        ));
    }

    #[test]
    fn write_rejects_a_fingerprint_that_does_not_authenticate_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let mut invalid = entry(b"kdbx", 42, false);
        invalid.fingerprint.content_sha256 = "0".repeat(64);

        let error = cache
            .write(&key(), invalid)
            .expect_err("unauthenticated write must fail");

        assert!(error.to_string().contains("fingerprint"));
        assert!(cache.read(&key()).unwrap().is_none());
    }

    #[test]
    fn corrupt_current_generation_falls_back_to_authenticated_previous_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"old-kdbx", 1, false)).unwrap();
        cache.write(&key(), entry(b"new-kdbx", 2, false)).unwrap();
        let manifest = read_manifest(&cache);
        let current = generation_path(&cache, manifest["generation"].as_str().unwrap());
        let previous_name = manifest["previousGeneration"]["generation"]
            .as_str()
            .unwrap();
        let previous = generation_path(&cache, previous_name);
        assert!(current.exists());
        assert!(previous.exists());

        fs::write(&current, b"corrupt").unwrap();
        let fallback = cache.read(&key()).unwrap().expect("previous generation");
        assert_eq!(fallback.bytes, b"old-kdbx");
        assert_eq!(fallback.fingerprint, fingerprint(b"old-kdbx", 1));
        assert!(fallback.pending_sync, "degraded fallback must be visible");
        assert!(matches!(
            cache.read_status(&key()).unwrap(),
            RemoteVaultCacheReadStatus::Degraded { .. }
        ));

        fs::write(previous, b"also-corrupt").unwrap();
        assert!(cache.read(&key()).unwrap().is_none());
    }

    #[test]
    fn rewriting_same_generation_keeps_the_real_previous_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"first", 1, false)).unwrap();
        cache.write(&key(), entry(b"second", 2, false)).unwrap();
        let before = read_manifest(&cache);
        let true_previous = before["previousGeneration"]["generation"]
            .as_str()
            .unwrap()
            .to_owned();

        cache.write(&key(), entry(b"second", 3, true)).unwrap();

        let after = read_manifest(&cache);
        assert_ne!(
            after["generation"],
            after["previousGeneration"]["generation"]
        );
        assert_eq!(after["previousGeneration"]["generation"], true_previous);
        assert!(generation_path(&cache, &true_previous).exists());
    }

    #[test]
    fn immutable_generation_reuse_rejects_corrupted_existing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"kdbx", 42, false)).unwrap();
        fs::write(current_generation_path(&cache), b"bad!").unwrap();

        let error = cache
            .write(&key(), entry(b"kdbx", 43, false))
            .expect_err("immutable generation must be verified before reuse");

        assert!(error.to_string().contains("authentication"));
        assert!(matches!(
            cache.read_status(&key()).unwrap(),
            RemoteVaultCacheReadStatus::Corrupt { .. }
        ));
    }

    #[test]
    fn cleanup_removes_orphans_without_deleting_manifest_current_or_previous() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"first", 1, false)).unwrap();
        cache.write(&key(), entry(b"second", 2, false)).unwrap();
        let digest = read_manifest(&cache)["generation"]
            .as_str()
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .to_owned();
        let orphan = dir.path().join(format!("{digest}.{}.kdbx", "0".repeat(64)));
        fs::write(&orphan, b"orphan").unwrap();

        cache.write(&key(), entry(b"third", 3, false)).unwrap();

        let manifest = read_manifest(&cache);
        assert!(generation_path(&cache, manifest["generation"].as_str().unwrap()).exists());
        assert!(
            generation_path(
                &cache,
                manifest["previousGeneration"]["generation"]
                    .as_str()
                    .unwrap()
            )
            .exists()
        );
        assert!(!orphan.exists());
    }

    #[test]
    fn locked_readers_never_observe_cleanup_as_a_false_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(RemoteVaultCache::new_at_with_lock_timeout(
            dir.path(),
            std::time::Duration::from_secs(10),
        ));
        cache.write(&key(), entry(b"seed", 0, false)).unwrap();
        let writer = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                for index in 1..=40_u64 {
                    let bytes = format!("generation-{index}").into_bytes();
                    cache.write(&key(), entry(&bytes, index, false)).unwrap();
                }
            })
        };
        let readers = (0..4)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        assert!(matches!(
                            cache.read_status(&key()).unwrap(),
                            RemoteVaultCacheReadStatus::Current { .. }
                                | RemoteVaultCacheReadStatus::Degraded { .. }
                        ));
                    }
                })
            })
            .collect::<Vec<_>>();
        writer.join().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
    }

    #[test]
    fn v1_pair_is_authenticated_and_migrates_without_deleting_legacy_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let paths = cache.paths_for_tests(&key());
        fs::create_dir_all(dir.path()).unwrap();
        let legacy_bytes = b"legacy-kdbx";
        let metadata = RemoteVaultCacheMetadata {
            provider_kind: key().provider_kind,
            remote_id: key().remote_id,
            display_name: "Legacy Vault".into(),
            account_label: "legacy@example.com".into(),
            fingerprint: fingerprint(legacy_bytes, 7),
            cached_at: 1_776_500_007,
            pending_sync: false,
        };
        fs::write(&paths.bytes_path, legacy_bytes).unwrap();
        fs::write(
            &paths.metadata_path,
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let legacy = cache.read(&key()).unwrap().expect("authenticated v1 hit");
        assert_eq!(legacy.bytes, legacy_bytes);
        cache.write(&key(), entry(b"v2-kdbx", 8, false)).unwrap();

        assert_eq!(read_manifest(&cache)["version"], 3);
        assert_eq!(fs::read(&paths.bytes_path).unwrap(), legacy_bytes);
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"v2-kdbx");
    }

    #[test]
    fn torn_or_tampered_v1_pair_is_a_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        let paths = cache.paths_for_tests(&key());
        fs::create_dir_all(dir.path()).unwrap();
        let metadata = RemoteVaultCacheMetadata {
            provider_kind: key().provider_kind,
            remote_id: key().remote_id,
            display_name: "Legacy Vault".into(),
            account_label: "legacy@example.com".into(),
            fingerprint: fingerprint(b"expected", 7),
            cached_at: 1_776_500_007,
            pending_sync: false,
        };
        fs::write(&paths.bytes_path, b"tampered").unwrap();
        fs::write(&paths.metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();

        assert!(cache.read(&key()).unwrap().is_none());
    }

    #[test]
    fn faulted_generation_or_manifest_publish_never_exposes_mixed_cache_state() {
        let before_pointer = [
            DurableFaultPoint::GenerationTempCreated,
            DurableFaultPoint::GenerationTempWritten,
            DurableFaultPoint::GenerationTempSynced,
            DurableFaultPoint::GenerationReadbackVerified,
            DurableFaultPoint::BeforeGenerationPublish,
            DurableFaultPoint::GenerationPublished,
            DurableFaultPoint::GenerationParentSynced,
            DurableFaultPoint::ManifestTempCreated,
            DurableFaultPoint::ManifestTempWritten,
            DurableFaultPoint::ManifestTempSynced,
            DurableFaultPoint::ManifestReadbackVerified,
            DurableFaultPoint::BeforeManifestReplace,
        ];
        for point in before_pointer {
            let dir = tempfile::tempdir().unwrap();
            let cache = RemoteVaultCache::new_at(dir.path());
            cache.write(&key(), entry(b"old-kdbx", 1, false)).unwrap();
            let faulted = RemoteVaultCache::new_at_with_faults(
                dir.path(),
                DurableFaultInjector::fail_once(point),
            );

            assert!(faulted.write(&key(), entry(b"new-kdbx", 2, false)).is_err());
            assert_eq!(
                cache.read(&key()).unwrap().unwrap().bytes,
                b"old-kdbx",
                "{point:?}"
            );
            assert!(sidecar_artifacts(dir.path()).is_empty(), "{point:?}");
        }

        for point in [
            DurableFaultPoint::ManifestReplaced,
            DurableFaultPoint::ManifestParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cache = RemoteVaultCache::new_at(dir.path());
            cache.write(&key(), entry(b"old-kdbx", 1, false)).unwrap();
            let faulted = RemoteVaultCache::new_at_with_faults(
                dir.path(),
                DurableFaultInjector::fail_once(point),
            );

            faulted
                .write(&key(), entry(b"new-kdbx", 2, false))
                .expect("visible manifest repair must reconcile the committed generation");
            let visible = cache.read(&key()).unwrap().unwrap();
            assert_eq!(visible.bytes, b"new-kdbx", "{point:?}");
            assert_eq!(
                visible.fingerprint.content_sha256,
                sha256_hex(&visible.bytes)
            );
        }
    }

    #[test]
    fn swapped_generation_and_manifest_temps_are_never_published() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let cache = RemoteVaultCache::new_at(&root);
        cache.write(&key(), entry(b"old-kdbx", 1, false)).unwrap();
        let generation_faulted = RemoteVaultCache::new_at_with_faults(
            &root,
            DurableFaultInjector::run_once(DurableFaultPoint::BeforeTempPublishValidation, {
                let root = root.clone();
                move || replace_only_temp_file(&root, b"attacker-generation")
            }),
        );
        assert!(
            generation_faulted
                .write(&key(), entry(b"new-kdbx", 2, false))
                .is_err()
        );
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"old-kdbx");

        let manifest_faulted = RemoteVaultCache::new_at_with_faults(
            &root,
            DurableFaultInjector::run_once(DurableFaultPoint::BeforeTempPublishValidation, {
                let root = root.clone();
                move || replace_only_temp_file(&root, b"attacker-manifest")
            }),
        );
        assert!(
            manifest_faulted
                .write(&key(), entry(b"old-kdbx", 3, true))
                .is_err()
        );
        let visible = cache.read(&key()).unwrap().unwrap();
        assert_eq!(visible.bytes, b"old-kdbx");
        assert!(!visible.pending_sync, "old manifest must remain committed");
    }

    #[test]
    fn concurrent_writers_publish_one_complete_generation_and_keep_current_and_previous() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0_u8..8)
            .map(|index| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let bytes = format!("candidate-{index}").into_bytes();
                    barrier.wait();
                    RemoteVaultCache::new_at(root)
                        .write(&key(), entry(&bytes, index as u64, false))
                        .unwrap();
                    bytes
                })
            })
            .collect::<Vec<_>>();
        let candidates = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let cache = RemoteVaultCache::new_at(dir.path());

        let visible = cache.read(&key()).unwrap().expect("complete cache hit");
        assert!(candidates.contains(&visible.bytes));
        assert_eq!(
            visible.fingerprint.content_sha256,
            sha256_hex(&visible.bytes)
        );
        let manifest = read_manifest(&cache);
        let current = generation_path(&cache, manifest["generation"].as_str().unwrap());
        let previous = generation_path(
            &cache,
            manifest["previousGeneration"]["generation"]
                .as_str()
                .unwrap(),
        );
        assert!(current.exists());
        assert!(previous.exists());
    }

    #[test]
    fn subprocess_sigkill_at_every_cache_boundary_never_exposes_a_mixed_pair() {
        let points = [
            DurableFaultPoint::GenerationTempCreated,
            DurableFaultPoint::GenerationTempWritten,
            DurableFaultPoint::GenerationTempSynced,
            DurableFaultPoint::GenerationReadbackVerified,
            DurableFaultPoint::BeforeGenerationPublish,
            DurableFaultPoint::GenerationPublished,
            DurableFaultPoint::GenerationParentSynced,
            DurableFaultPoint::ManifestTempCreated,
            DurableFaultPoint::ManifestTempWritten,
            DurableFaultPoint::ManifestTempSynced,
            DurableFaultPoint::ManifestReadbackVerified,
            DurableFaultPoint::BeforeManifestReplace,
            DurableFaultPoint::ManifestReplaced,
            DurableFaultPoint::ManifestParentSynced,
        ];
        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let cache = RemoteVaultCache::new_at(dir.path());
            cache.write(&key(), entry(b"old-kdbx", 1, false)).unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::remote_cache::tests::subprocess_cache_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_CACHE_CRASH_ROOT", dir.path())
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_was_abruptly_killed(status, point);

            let visible = cache
                .read(&key())
                .unwrap()
                .expect("authenticated cache hit");
            assert!(
                visible.bytes == b"old-kdbx" || visible.bytes == b"new-kdbx",
                "{point:?} exposed mixed cache state"
            );
            assert_eq!(
                visible.fingerprint.content_sha256,
                sha256_hex(&visible.bytes)
            );
            assert_eq!(visible.fingerprint.size_bytes, visible.bytes.len() as u64);
            if !matches!(
                point,
                DurableFaultPoint::ManifestReplaced | DurableFaultPoint::ManifestParentSynced
            ) {
                assert_eq!(visible.bytes, b"old-kdbx", "{point:?}");
            }
        }
    }

    #[test]
    fn first_cache_write_survives_sigkill_after_manifest_and_new_root_are_durable() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nested").join("remote-cache");
        assert!(!root.exists());
        let point = DurableFaultPoint::CacheManifestDurable;
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "providers::remote_cache::tests::subprocess_cache_crash_child",
                "--ignored",
            ])
            .env("VAULTKERN_CACHE_CRASH_ROOT", &root)
            .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_was_abruptly_killed(status, point);

        let visible = RemoteVaultCache::new_at(&root)
            .read(&key())
            .unwrap()
            .expect("first committed cache generation");
        assert_eq!(visible.bytes, b"new-kdbx");
        assert_eq!(visible.fingerprint.content_sha256, sha256_hex(b"new-kdbx"));
    }

    #[test]
    fn separate_process_cache_writers_are_serialized_by_the_digest_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut children = (0_u8..6)
            .map(|index| {
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "providers::remote_cache::tests::subprocess_cache_writer_child",
                        "--ignored",
                    ])
                    .env("VAULTKERN_CACHE_WRITER_ROOT", dir.path())
                    .env("VAULTKERN_CACHE_WRITER_INDEX", index.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }

        let cache = RemoteVaultCache::new_at(dir.path());
        let visible = cache.read(&key()).unwrap().expect("complete cache hit");
        assert!((0_u8..6).any(|index| visible.bytes == format!("process-{index}").as_bytes()));
        assert_eq!(
            visible.fingerprint.content_sha256,
            sha256_hex(&visible.bytes)
        );
        let manifest = read_manifest(&cache);
        assert!(generation_path(&cache, manifest["generation"].as_str().unwrap()).exists());
        assert!(
            generation_path(
                &cache,
                manifest["previousGeneration"]["generation"]
                    .as_str()
                    .unwrap()
            )
            .exists()
        );
    }

    #[test]
    #[ignore]
    fn subprocess_cache_crash_child() {
        let Ok(root) = std::env::var("VAULTKERN_CACHE_CRASH_ROOT") else {
            return;
        };
        let point = DurableFaultPoint::from_test_name(
            &std::env::var("VAULTKERN_DURABLE_CRASH_POINT").unwrap(),
        )
        .unwrap();
        let cache =
            RemoteVaultCache::new_at_with_faults(root, DurableFaultInjector::crash_once(point));
        let _ = cache.write(&key(), entry(b"new-kdbx", 2, false));
        panic!("crash point was not reached: {point:?}");
    }

    #[test]
    #[ignore]
    fn subprocess_cache_writer_child() {
        let Ok(root) = std::env::var("VAULTKERN_CACHE_WRITER_ROOT") else {
            return;
        };
        let index = std::env::var("VAULTKERN_CACHE_WRITER_INDEX")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let bytes = format!("process-{index}").into_bytes();
        RemoteVaultCache::new_at(root)
            .write(&key(), entry(&bytes, index as u64, false))
            .unwrap();
    }

    #[cfg(unix)]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{point:?}");
    }

    #[cfg(windows)]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        assert_eq!(status.code(), Some(86), "{point:?}");
    }

    #[cfg(not(any(unix, windows)))]
    fn assert_was_abruptly_killed(status: std::process::ExitStatus, point: DurableFaultPoint) {
        assert!(!status.success(), "{point:?}");
    }

    #[test]
    fn delete_is_idempotent_and_removes_cached_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());

        let missing = cache.begin_retirement(&key()).unwrap();
        missing.delete_cached_state().unwrap();
        drop(missing);
        cache.activate_while(&key(), || Ok(())).unwrap();
        cache.write(&key(), entry(b"kdbx", 42, false)).unwrap();

        let paths = cache.paths_for_tests(&key());
        assert!(paths.metadata_path.exists());
        let generation = current_generation_path(&cache);
        assert!(generation.exists());

        let retirement = cache.begin_retirement(&key()).unwrap();
        retirement.delete_cached_state().unwrap();
        drop(retirement);
        let retry = cache.begin_cleanup_after_intent(&key()).unwrap();
        retry.delete_cached_state().unwrap();

        assert!(!paths.bytes_path.exists());
        assert!(!paths.metadata_path.exists());
        assert!(!generation.exists());
    }

    #[test]
    fn committed_cleanup_intent_can_finish_after_a_crash_left_a_corrupt_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"kdbx", 42, false)).unwrap();
        let paths = cache.paths_for_tests(&key());
        let generation = current_generation_path(&cache);

        fs::remove_file(&generation).unwrap();
        assert!(cache.begin_retirement(&key()).is_err());

        let cleanup = cache.begin_cleanup_after_intent(&key()).unwrap();
        cleanup.delete_cached_state().unwrap();
        drop(cleanup);
        assert!(!paths.metadata_path.exists());
        let cleanup = cache.begin_cleanup_after_intent(&key()).unwrap();
        cleanup.delete_cached_state().unwrap();
        drop(cleanup);
        assert!(cache.write(&key(), entry(b"orphan", 43, true)).is_err());

        cache.activate_while(&key(), || Ok(())).unwrap();
        cache.write(&key(), entry(b"re-added", 44, false)).unwrap();
    }

    #[test]
    fn retirement_marker_blocks_a_concurrent_pending_write_before_reference_commit() {
        let dir = tempfile::tempdir().unwrap();
        let first = RemoteVaultCache::new_at(dir.path());
        let concurrent = RemoteVaultCache::new_at(dir.path());
        first.write(&key(), entry(b"clean", 1, false)).unwrap();
        let clean_guard = first.begin_retirement(&key()).unwrap();
        drop(clean_guard);

        let error = concurrent
            .write(&key(), entry(b"pending-edit", 2, true))
            .unwrap_err();
        assert!(error.to_string().contains("retired"));
    }
}
