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
    path_file_identity, publish_temp, remove_if_exists, sha256_hex, sync_directory, sync_parent,
    unique_sibling_path, write_verified_temp,
};
use crate::providers::local_file::VaultSourceFingerprint;
use crate::state_paths::{extension_state_dir, runtime_state_dir};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRemoteCacheChain {
    pub(crate) pending: RemoteVaultCacheEntry,
    pub(crate) plan_baseline: RemoteVaultCacheEntry,
    pub(crate) observed_source: RemoteVaultCacheEntry,
    pub(crate) source_etag: Option<String>,
    pub(crate) source_revision: Option<u64>,
    pub(crate) operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingRemoteCacheChainError {
    Missing,
    NotPending,
    Legacy,
    DegradedCurrent,
    PreviousMissing,
    PreviousCorrupt { reason: String },
    ObservedMissing,
    ObservedCorrupt { reason: String },
    MissingOperationBinding,
    Corrupt { reason: String },
    Io { message: String },
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

impl std::fmt::Display for PendingRemoteCacheChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(formatter, "pending remote cache is missing"),
            Self::NotPending => write!(formatter, "remote cache generation is not pending"),
            Self::Legacy => write!(
                formatter,
                "legacy remote cache has no authenticated generation chain"
            ),
            Self::DegradedCurrent => {
                write!(
                    formatter,
                    "pending remote cache current generation is degraded"
                )
            }
            Self::PreviousMissing => write!(
                formatter,
                "pending remote cache previous generation is missing"
            ),
            Self::PreviousCorrupt { reason } => {
                write!(
                    formatter,
                    "pending remote cache previous generation is corrupt: {reason}"
                )
            }
            Self::ObservedMissing => write!(
                formatter,
                "pending remote cache observed source generation is missing"
            ),
            Self::ObservedCorrupt { reason } => write!(
                formatter,
                "pending remote cache observed source generation is corrupt: {reason}"
            ),
            Self::MissingOperationBinding => {
                write!(
                    formatter,
                    "pending remote cache has no autofill operation binding"
                )
            }
            Self::Corrupt { reason } => {
                write!(formatter, "pending remote cache is corrupt: {reason}")
            }
            Self::Io { message } => write!(formatter, "pending remote cache I/O failed: {message}"),
        }
    }
}

impl std::error::Error for PendingRemoteCacheChainError {}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_operation_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_operation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RemoteVaultPendingKind {
    None,
    Generic,
    Autofill,
}

#[derive(Debug)]
enum CacheManifestPublishOutcome {
    Durable,
    DurabilityUnknown { source: anyhow::Error },
}

#[derive(Debug, Clone, Copy)]
struct PendingAutofillCompletionProof<'a> {
    operation_id: &'a str,
    pending_fingerprint: &'a VaultSourceFingerprint,
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

    pub(crate) fn read_pending_chain(
        &self,
        key: &RemoteCacheKey,
    ) -> std::result::Result<PendingRemoteCacheChain, PendingRemoteCacheChainError> {
        if !self.root.exists() {
            return Err(PendingRemoteCacheChainError::Missing);
        }
        create_dir_all_durable(&self.root).map_err(|error| PendingRemoteCacheChainError::Io {
            message: format!("{error:#}"),
        })?;
        let paths = self.paths(key);
        let _lock = ExclusiveFileLock::acquire_with_timeout(&paths.lock_path, self.lock_timeout)
            .map_err(|error| PendingRemoteCacheChainError::Io {
                message: error.to_string(),
            })?;
        let current = match self.read_authenticated_locked(key) {
            AuthenticatedCacheRead::Missing => return Err(PendingRemoteCacheChainError::Missing),
            AuthenticatedCacheRead::Degraded(_) => {
                return Err(PendingRemoteCacheChainError::DegradedCurrent);
            }
            AuthenticatedCacheRead::Corrupt(reason) => {
                return Err(PendingRemoteCacheChainError::Corrupt { reason });
            }
            AuthenticatedCacheRead::Current(current) => current,
        };
        self.pending_chain_from_current(key, current)
    }

    fn pending_chain_from_current(
        &self,
        key: &RemoteCacheKey,
        current: AuthenticatedCacheEntry,
    ) -> std::result::Result<PendingRemoteCacheChain, PendingRemoteCacheChainError> {
        if !current.entry.pending_sync {
            return Err(PendingRemoteCacheChainError::NotPending);
        }
        if current.legacy {
            return Err(PendingRemoteCacheChainError::Legacy);
        }
        if current.generation.pending_kind != Some(RemoteVaultPendingKind::Autofill) {
            return if current.generation.pending_kind == Some(RemoteVaultPendingKind::Generic)
                && current.generation.pending_operation_id.is_none()
            {
                Err(PendingRemoteCacheChainError::MissingOperationBinding)
            } else {
                Err(PendingRemoteCacheChainError::Corrupt {
                    reason: "pending cache kind and operation binding are inconsistent".into(),
                })
            };
        }
        let operation_id = current
            .generation
            .pending_operation_id
            .clone()
            .filter(|operation_id| valid_pending_operation_id(operation_id))
            .ok_or_else(|| PendingRemoteCacheChainError::Corrupt {
                reason: "autofill pending operation binding is invalid".into(),
            })?;
        let plan_baseline_generation = current
            .fallback
            .as_ref()
            .ok_or(PendingRemoteCacheChainError::PreviousMissing)?;
        let observed_generation = current
            .observed
            .as_ref()
            .ok_or(PendingRemoteCacheChainError::ObservedMissing)?;
        if plan_baseline_generation.pending_sync
            || plan_baseline_generation.pending_operation_id.is_some()
            || plan_baseline_generation.pending_kind != Some(RemoteVaultPendingKind::None)
        {
            return Err(PendingRemoteCacheChainError::PreviousCorrupt {
                reason: "plan baseline generation is marked pending".into(),
            });
        }
        if observed_generation.pending_sync
            || observed_generation.pending_operation_id.is_some()
            || observed_generation.pending_kind != Some(RemoteVaultPendingKind::None)
        {
            return Err(PendingRemoteCacheChainError::ObservedCorrupt {
                reason: "observed source generation is marked pending".into(),
            });
        }
        let current_condition = (
            current.generation.source_etag.as_ref(),
            current.generation.source_revision,
        );
        let observed_condition = (
            observed_generation.source_etag.as_ref(),
            observed_generation.source_revision,
        );
        if !matches!(current_condition, (Some(_), None) | (None, Some(_)))
            || current_condition != observed_condition
        {
            return Err(PendingRemoteCacheChainError::Corrupt {
                reason: "pending and observed generations have inconsistent source conditions"
                    .into(),
            });
        }
        if current.generation.content_sha256 == plan_baseline_generation.content_sha256
            || current.generation.content_sha256 == observed_generation.content_sha256
        {
            return Err(PendingRemoteCacheChainError::Corrupt {
                reason: "pending candidate does not differ from its authenticated inputs".into(),
            });
        }
        let digest = cache_key_digest(key);
        let plan_baseline = self
            .read_generation(&digest, plan_baseline_generation, false)
            .map_err(|reason| PendingRemoteCacheChainError::PreviousCorrupt { reason })?;
        let observed_source = self
            .read_generation(&digest, observed_generation, false)
            .map_err(|reason| PendingRemoteCacheChainError::ObservedCorrupt { reason })?;
        Ok(PendingRemoteCacheChain {
            pending: current.entry,
            plan_baseline: plan_baseline.entry,
            observed_source: observed_source.entry,
            source_etag: current.generation.source_etag,
            source_revision: current.generation.source_revision,
            operation_id,
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
            None,
            source_etag,
            None,
            None,
            None,
            None,
        )?)
    }

    pub(crate) fn write_pending_autofill(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        observed_source: RemoteVaultCacheEntry,
        expected_plan_baseline: &VaultSourceFingerprint,
        source_etag: Option<&str>,
        source_revision: Option<u64>,
        operation_id: &str,
    ) -> Result<()> {
        if !entry.pending_sync {
            bail!("autofill pending cache entry must be marked pending_sync");
        }
        if operation_id.is_empty()
            || operation_id.len() > 128
            || operation_id.trim() != operation_id
            || operation_id.chars().any(char::is_control)
        {
            bail!("invalid autofill pending cache operation ID");
        }
        if !matches!(
            (source_etag, source_revision),
            (Some(_), None) | (None, Some(_))
        ) {
            bail!("autofill pending cache requires exactly one source condition");
        }
        if observed_source.pending_sync {
            bail!("autofill observed source cache entry cannot be pending_sync");
        }
        if same_content_fingerprint(&entry.fingerprint, &observed_source.fingerprint)
            || same_content_fingerprint(&entry.fingerprint, expected_plan_baseline)
        {
            bail!("autofill pending candidate must differ from its authenticated inputs");
        }
        require_durable_cache_publish(self.write_with_source_context(
            key,
            entry,
            Some(observed_source),
            Some(expected_plan_baseline),
            source_etag,
            source_revision,
            Some(operation_id),
            None,
            None,
        )?)
    }

    pub(crate) fn complete_pending_autofill(
        &self,
        key: &RemoteCacheKey,
        operation_id: &str,
        expected_pending: &VaultSourceFingerprint,
        entry: RemoteVaultCacheEntry,
        source_etag: Option<&str>,
    ) -> Result<PendingRemoteCacheCompletion> {
        if entry.pending_sync {
            bail!("completed autofill cache entry cannot be pending_sync");
        }
        Ok(
            match self.write_with_source_context(
                key,
                entry,
                None,
                None,
                source_etag,
                None,
                None,
                Some(PendingAutofillCompletionProof {
                    operation_id,
                    pending_fingerprint: expected_pending,
                }),
                None,
            )? {
                CacheManifestPublishOutcome::Durable => PendingRemoteCacheCompletion::Durable,
                CacheManifestPublishOutcome::DurabilityUnknown { .. } => {
                    PendingRemoteCacheCompletion::DurabilityUnknown
                }
            },
        )
    }

    pub(crate) fn write_generic_pending(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        expected_current: &VaultSourceFingerprint,
    ) -> Result<()> {
        if !entry.pending_sync {
            bail!("generic pending cache entry must be marked pending_sync");
        }
        require_durable_cache_publish(self.write_with_source_context(
            key,
            entry,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(GenericPendingWriteProof {
                mode: GenericPendingWriteMode::Update,
                expected_fingerprint: expected_current,
            }),
        )?)
    }

    #[cfg(test)]
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
                None,
                None,
                None,
                Some(GenericPendingWriteProof {
                    mode: GenericPendingWriteMode::Complete,
                    expected_fingerprint: expected_pending,
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
            None,
            None,
            None,
            Some(GenericPendingWriteProof {
                mode: GenericPendingWriteMode::Complete,
                expected_fingerprint: expected_pending,
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
            && ((current.generation.pending_kind == Some(RemoteVaultPendingKind::Generic)
                && current.generation.pending_operation_id.is_none())
                || (current.legacy
                    && current.generation.pending_operation_id.is_none()
                    && current.observed.is_none()));
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
        observed_source: Option<RemoteVaultCacheEntry>,
        expected_plan_baseline: Option<&VaultSourceFingerprint>,
        source_etag: Option<&str>,
        source_revision: Option<u64>,
        pending_operation_id: Option<&str>,
        completion_proof: Option<PendingAutofillCompletionProof<'_>>,
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
            observed_source,
            expected_plan_baseline,
            source_etag,
            source_revision,
            pending_operation_id,
            completion_proof,
            generic_proof,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_with_source_context_locked(
        &self,
        key: &RemoteCacheKey,
        entry: RemoteVaultCacheEntry,
        observed_source: Option<RemoteVaultCacheEntry>,
        expected_plan_baseline: Option<&VaultSourceFingerprint>,
        source_etag: Option<&str>,
        source_revision: Option<u64>,
        pending_operation_id: Option<&str>,
        completion_proof: Option<PendingAutofillCompletionProof<'_>>,
        generic_proof: Option<GenericPendingWriteProof<'_>>,
    ) -> Result<CacheManifestPublishOutcome> {
        let paths = self.paths(key);

        let actual_sha256 = sha256_hex(&entry.bytes);
        if entry.fingerprint.content_sha256 != actual_sha256
            || entry.fingerprint.size_bytes != entry.bytes.len() as u64
        {
            bail!("remote cache fingerprint does not authenticate the supplied bytes");
        }
        if pending_operation_id.is_some() != observed_source.is_some()
            || pending_operation_id.is_some() != expected_plan_baseline.is_some()
            || (completion_proof.is_some() && pending_operation_id.is_some())
            || (generic_proof.is_some()
                && (pending_operation_id.is_some() || completion_proof.is_some()))
        {
            bail!("autofill pending cache requires an observed source and expected plan baseline");
        }
        if let Some(observed_source) = &observed_source
            && !fingerprint_authenticates(&observed_source.fingerprint, &observed_source.bytes)
        {
            bail!("observed source fingerprint does not authenticate the supplied bytes");
        }

        let digest = cache_key_digest(key);
        let authenticated = self.read_authenticated_locked(key);
        let mut previous = match authenticated {
            AuthenticatedCacheRead::Current(previous) => {
                if let Some(proof) = completion_proof {
                    if !previous.entry.pending_sync {
                        let completed_pending = previous
                            .fallback
                            .as_ref()
                            .filter(|generation| {
                                generation.pending_sync
                                    && generation.pending_kind
                                        == Some(RemoteVaultPendingKind::Autofill)
                                    && generation.pending_operation_id.as_deref()
                                        == Some(proof.operation_id)
                                    && generation.content_sha256
                                        == proof.pending_fingerprint.content_sha256
                                    && generation.size_bytes == proof.pending_fingerprint.size_bytes
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
                        return Err(PendingRemoteCacheConflict::new(
                            "completed cache generation does not carry the requested autofill proof",
                        )
                        .into());
                    }
                    let chain = self
                        .pending_chain_from_current(key, previous.clone())
                        .map_err(|error| {
                            PendingRemoteCacheConflict::new(format!(
                                "autofill pending completion proof failed: {error}"
                            ))
                        })?;
                    if chain.operation_id != proof.operation_id
                        || !same_content_fingerprint(
                            &chain.pending.fingerprint,
                            proof.pending_fingerprint,
                        )
                    {
                        return Err(PendingRemoteCacheConflict::new(
                            "autofill pending completion does not match the operation and generation",
                        )
                        .into());
                    }
                } else if let Some(proof) = generic_proof {
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
                                    && generation.pending_kind
                                        == Some(RemoteVaultPendingKind::Generic)
                                    && generation.pending_operation_id.is_none()
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
                        && ((previous.generation.pending_kind
                            == Some(RemoteVaultPendingKind::Generic)
                            && previous.generation.pending_operation_id.is_none())
                            || (previous.legacy
                                && previous.generation.pending_operation_id.is_none()
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
                } else if pending_operation_id.is_some() {
                    if previous.entry.pending_sync {
                        let chain = self
                            .pending_chain_from_current(key, previous.clone())
                            .map_err(|error| {
                                PendingRemoteCacheConflict::new(format!(
                                    "another pending cache generation blocks autofill publish: {error}"
                                ))
                            })?;
                        let same_publish = chain.operation_id
                            == pending_operation_id.expect("pending operation")
                            && same_content_fingerprint(
                                &chain.pending.fingerprint,
                                &entry.fingerprint,
                            )
                            && observed_source.as_ref().is_some_and(|observed| {
                                same_content_fingerprint(
                                    &chain.observed_source.fingerprint,
                                    &observed.fingerprint,
                                )
                            })
                            && expected_plan_baseline.is_some_and(|baseline| {
                                same_content_fingerprint(&chain.plan_baseline.fingerprint, baseline)
                            })
                            && chain.source_etag.as_deref() == source_etag
                            && chain.source_revision == source_revision;
                        if same_publish {
                            return Ok(CacheManifestPublishOutcome::Durable);
                        }
                        return Err(PendingRemoteCacheConflict::new(
                            "another autofill operation is already durable in the remote cache",
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
                if pending_operation_id.is_some()
                    || completion_proof.is_some()
                    || generic_proof
                        .is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete) =>
            {
                return Err(PendingRemoteCacheConflict::new(
                    "autofill pending cache requires an authenticated previous generation",
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
        if pending_operation_id.is_some()
            && previous.as_ref().is_none_or(|previous| {
                expected_plan_baseline.is_none_or(|expected| {
                    previous.entry.fingerprint.content_sha256 != expected.content_sha256
                        || previous.entry.fingerprint.size_bytes != expected.size_bytes
                })
            })
        {
            bail!("authenticated cache plan baseline changed before pending publish");
        }

        let generation = generation_name(&digest, &actual_sha256)
            .ok_or_else(|| anyhow!("remote cache content SHA-256 is not canonical"))?;
        let previous_generation = previous.and_then(|previous| {
            if pending_operation_id.is_some()
                || completion_proof.is_some()
                || generic_proof
                    .is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete)
            {
                Some(previous.generation)
            } else if previous.generation.generation == generation {
                previous.fallback
            } else {
                Some(previous.generation)
            }
        });
        if pending_operation_id.is_some() && previous_generation.is_none() {
            bail!("autofill pending cache requires an authenticated previous generation");
        }
        let observed_generation = observed_source
            .map(|observed_source| {
                let content_sha256 = observed_source.fingerprint.content_sha256.clone();
                let generation =
                    self.ensure_generation(&digest, &observed_source.bytes, &content_sha256)?;
                Ok::<_, anyhow::Error>(RemoteVaultGeneration {
                    generation,
                    content_sha256,
                    size_bytes: observed_source.bytes.len() as u64,
                    source_etag: source_etag.map(str::to_owned),
                    source_revision,
                    source_modified_at: observed_source.fingerprint.modified_at,
                    display_name: observed_source.display_name,
                    account_label: observed_source.account_label,
                    cached_at: observed_source.cached_at,
                    pending_sync: false,
                    pending_kind: Some(RemoteVaultPendingKind::None),
                    pending_operation_id: None,
                })
            })
            .transpose()?;
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
            pending_kind: Some(if pending_operation_id.is_some() {
                RemoteVaultPendingKind::Autofill
            } else if entry.pending_sync {
                RemoteVaultPendingKind::Generic
            } else {
                RemoteVaultPendingKind::None
            }),
            pending_operation_id: pending_operation_id.map(str::to_owned),
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
                if !matches!(
                    visible,
                    AuthenticatedCacheRead::Current(ref current)
                        if !current.entry.pending_sync
                            && same_content_fingerprint(&current.entry.fingerprint, &entry.fingerprint)
                ) && (completion_proof.is_some()
                    || generic_proof
                        .is_some_and(|proof| proof.mode == GenericPendingWriteMode::Complete))
                {
                    return Err(anyhow!(
                        "autofill cache completion publish outcome is unknown and the resolved generation is not visible"
                    ));
                }
            }
        }
        Ok(publish)
    }

    pub fn delete(&self, key: &RemoteCacheKey) -> Result<()> {
        let paths = self.paths(key);
        if !self.root.exists() {
            return Ok(());
        }
        create_dir_all_durable(&self.root).with_context(|| {
            format!(
                "remote vault cache root is not a private directory: {}",
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
        remove_file_if_exists(&paths.metadata_path)?;
        let _ = sync_directory(&self.root);
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
                    pending_operation_id: None,
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
            return Ok(CacheManifestPublishOutcome::DurabilityUnknown {
                source: anyhow!(error.source).context(format!(
                    "remote cache manifest was replaced but durability is unknown: {}",
                    target.display()
                )),
            });
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
            pending_operation_id: self.pending_operation_id.clone(),
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

fn valid_pending_operation_id(operation_id: &str) -> bool {
    !operation_id.is_empty()
        && operation_id.len() <= 128
        && operation_id.trim() == operation_id
        && !operation_id.chars().any(char::is_control)
}

fn generation_pending_schema_is_valid(generation: &RemoteVaultGeneration) -> bool {
    match generation.pending_kind {
        Some(RemoteVaultPendingKind::None) => {
            !generation.pending_sync && generation.pending_operation_id.is_none()
        }
        Some(RemoteVaultPendingKind::Generic) => {
            generation.pending_sync && generation.pending_operation_id.is_none()
        }
        Some(RemoteVaultPendingKind::Autofill) => {
            generation.pending_sync
                && generation
                    .pending_operation_id
                    .as_deref()
                    .is_some_and(valid_pending_operation_id)
        }
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
        PendingRemoteCacheChainError, PendingRemoteCacheCompletion, PendingRemoteCacheConflict,
        RemoteCacheKey, RemoteVaultCache, RemoteVaultCacheEntry, RemoteVaultCacheMetadata,
        RemoteVaultCacheReadStatus, cache_key_digest,
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
            .write_generic_pending(&key(), pending_a.clone(), &current.fingerprint)
            .unwrap();
        let pending_b = entry(b"pending-b", 3, true);
        cache
            .write_generic_pending(&key(), pending_b, &pending_a.fingerprint)
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
            .write_generic_pending(&key(), pending.clone(), &current.fingerprint)
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
                    let result =
                        competing_cache.write_generic_pending(&key(), competing, &expected);
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
    fn pending_chain_authenticates_pending_plan_baseline_observed_and_source_condition() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache
            .write_with_source_etag(&key(), entry(b"baseline", 10, false), Some("etag-10"))
            .unwrap();
        cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"baseline", 10),
                Some("etag-10"),
                None,
                "operation-1",
            )
            .unwrap();

        let chain = cache.read_pending_chain(&key()).unwrap();

        assert_eq!(chain.pending.bytes, b"pending");
        assert_eq!(chain.plan_baseline.bytes, b"baseline");
        assert_eq!(chain.observed_source.bytes, b"observed");
        assert_eq!(chain.source_etag.as_deref(), Some("etag-10"));
        assert_eq!(chain.source_revision, None);
        assert_eq!(chain.operation_id, "operation-1");
    }

    #[test]
    fn pending_chain_preserves_memory_revision_condition() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"baseline", 10),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();

        let chain = cache.read_pending_chain(&key()).unwrap();

        assert_eq!(chain.source_etag, None);
        assert_eq!(chain.source_revision, Some(10));
    }

    #[test]
    fn ordinary_write_and_delete_cannot_destroy_an_operation_bound_pending_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"baseline", 10),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();
        let chain_before = cache.read_pending_chain(&key()).unwrap();
        let manifest_before = fs::read(cache.paths_for_tests(&key()).metadata_path).unwrap();

        let write_error = cache
            .write(&key(), entry(b"unrelated-writer", 12, false))
            .expect_err("ordinary cache writes must not replace an autofill pending chain");
        assert!(write_error.is::<PendingRemoteCacheConflict>());
        let delete_error = cache
            .delete(&key())
            .expect_err("ordinary cache deletion must not remove pending durability");
        assert!(delete_error.is::<PendingRemoteCacheConflict>());

        assert_eq!(cache.read_pending_chain(&key()).unwrap(), chain_before);
        assert_eq!(
            fs::read(cache.paths_for_tests(&key()).metadata_path).unwrap(),
            manifest_before
        );
    }

    #[test]
    fn generic_pending_updates_require_the_exact_loaded_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_generic_pending(
                &key(),
                entry(b"pending-1", 11, true),
                &fingerprint(b"baseline", 10),
            )
            .unwrap();

        let stale_error = cache
            .write_generic_pending(
                &key(),
                entry(b"stale-must-not-win", 12, true),
                &fingerprint(b"baseline", 10),
            )
            .expect_err("a stale generic pending writer must lose its cache CAS");
        assert!(stale_error.is::<PendingRemoteCacheConflict>());
        assert_eq!(cache.read(&key()).unwrap().unwrap().bytes, b"pending-1");

        cache
            .write_generic_pending(
                &key(),
                entry(b"pending-2", 13, true),
                &fingerprint(b"pending-1", 11),
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
    fn pending_completion_requires_the_exact_operation_and_pending_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"baseline", 10),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();

        for (operation_id, expected_pending) in [
            ("operation-2", fingerprint(b"pending", 11)),
            ("operation-1", fingerprint(b"other", 11)),
        ] {
            let error = cache
                .complete_pending_autofill(
                    &key(),
                    operation_id,
                    &expected_pending,
                    entry(b"resolved", 12, false),
                    None,
                )
                .expect_err("completion proof must match the committed pending chain");
            assert!(error.is::<PendingRemoteCacheConflict>());
        }

        assert_eq!(
            cache
                .complete_pending_autofill(
                    &key(),
                    "operation-1",
                    &fingerprint(b"pending", 11),
                    entry(b"resolved", 12, false),
                    None,
                )
                .unwrap(),
            PendingRemoteCacheCompletion::Durable
        );
        let resolved = cache.read(&key()).unwrap().unwrap();
        assert_eq!(resolved.bytes, b"resolved");
        assert!(!resolved.pending_sync);

        for (operation_id, expected_pending) in [
            ("operation-2", fingerprint(b"pending", 11)),
            ("operation-1", fingerprint(b"other", 11)),
        ] {
            let error = cache
                .complete_pending_autofill(
                    &key(),
                    operation_id,
                    &expected_pending,
                    entry(b"resolved", 12, false),
                    None,
                )
                .expect_err("idempotent completion still requires the original proof");
            assert!(error.is::<PendingRemoteCacheConflict>());
        }

        assert_eq!(
            cache
                .complete_pending_autofill(
                    &key(),
                    "operation-1",
                    &fingerprint(b"pending", 11),
                    entry(b"resolved", 12, false),
                    None,
                )
                .unwrap(),
            PendingRemoteCacheCompletion::Durable
        );
    }

    #[test]
    fn pending_completion_reports_post_publish_durability_without_stranding_state() {
        for (point, expected) in [
            (
                DurableFaultPoint::CacheManifestDurable,
                PendingRemoteCacheCompletion::Durable,
            ),
            (
                DurableFaultPoint::ManifestReplaced,
                PendingRemoteCacheCompletion::DurabilityUnknown,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cache = RemoteVaultCache::new_at(dir.path());
            cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
            cache
                .write_pending_autofill(
                    &key(),
                    entry(b"pending", 11, true),
                    entry(b"observed", 10, false),
                    &fingerprint(b"baseline", 10),
                    None,
                    Some(10),
                    "operation-1",
                )
                .unwrap();
            let faulted = RemoteVaultCache::new_at_with_faults(
                dir.path(),
                DurableFaultInjector::fail_once(point),
            );

            assert_eq!(
                faulted
                    .complete_pending_autofill(
                        &key(),
                        "operation-1",
                        &fingerprint(b"pending", 11),
                        entry(b"resolved", 12, false),
                        None,
                    )
                    .unwrap(),
                expected,
                "{point:?}"
            );
            let resolved = cache.read(&key()).unwrap().unwrap();
            assert_eq!(resolved.bytes, b"resolved", "{point:?}");
            assert!(!resolved.pending_sync, "{point:?}");
        }
    }

    #[test]
    fn pending_chain_rejects_inconsistent_generation_flags_and_source_conditions() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
        cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"baseline", 10),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();
        let paths = cache.paths_for_tests(&key());
        let mut manifest = read_manifest(&cache);
        manifest["observedGeneration"]["pendingSync"] = Value::Bool(true);
        manifest["observedGeneration"]["sourceRevision"] = Value::from(11_u64);
        fs::write(
            &paths.metadata_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            cache.read_pending_chain(&key()),
            Err(PendingRemoteCacheChainError::Corrupt { .. })
        ));
        let error = cache
            .write(&key(), entry(b"repair-must-not-destroy-chain", 12, false))
            .expect_err("ordinary writes must fail closed on a corrupt committed manifest");
        assert!(error.is::<PendingRemoteCacheConflict>());
    }

    #[test]
    fn tagged_pending_manifest_cannot_be_downgraded_by_removing_its_operation_fields() {
        for removed_field in ["pendingKind", "pendingOperationId"] {
            let dir = tempfile::tempdir().unwrap();
            let cache = RemoteVaultCache::new_at(dir.path());
            cache.write(&key(), entry(b"baseline", 10, false)).unwrap();
            cache
                .write_pending_autofill(
                    &key(),
                    entry(b"pending", 11, true),
                    entry(b"observed", 10, false),
                    &fingerprint(b"baseline", 10),
                    None,
                    Some(10),
                    "operation-1",
                )
                .unwrap();
            let paths = cache.paths_for_tests(&key());
            let mut manifest = read_manifest(&cache);
            manifest.as_object_mut().unwrap().remove(removed_field);
            fs::write(
                &paths.metadata_path,
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();

            assert!(matches!(
                cache.read_pending_chain(&key()),
                Err(PendingRemoteCacheChainError::Corrupt { .. })
            ));
            let error = cache
                .write(&key(), entry(b"must-not-repair", 12, false))
                .expect_err("ordinary writer cannot repair away an unknown pending kind");
            assert!(error.is::<PendingRemoteCacheConflict>(), "{removed_field}");
        }
    }

    #[test]
    fn pending_chain_fails_closed_when_observed_source_is_missing_or_corrupt() {
        let missing_dir = tempfile::tempdir().unwrap();
        let missing = RemoteVaultCache::new_at(missing_dir.path());
        missing
            .write(&key(), entry(b"plan-baseline", 9, false))
            .unwrap();
        missing
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"plan-baseline", 9),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();
        let mut manifest = read_manifest(&missing);
        manifest
            .as_object_mut()
            .unwrap()
            .remove("observedGeneration");
        fs::write(
            missing.paths_for_tests(&key()).metadata_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            missing.read_pending_chain(&key()),
            Err(PendingRemoteCacheChainError::ObservedMissing)
        ));

        let corrupt_dir = tempfile::tempdir().unwrap();
        let corrupt = RemoteVaultCache::new_at(corrupt_dir.path());
        corrupt
            .write(&key(), entry(b"plan-baseline", 9, false))
            .unwrap();
        corrupt
            .write_pending_autofill(
                &key(),
                entry(b"pending", 11, true),
                entry(b"observed", 10, false),
                &fingerprint(b"plan-baseline", 9),
                None,
                Some(10),
                "operation-1",
            )
            .unwrap();
        let manifest = read_manifest(&corrupt);
        let observed = generation_path(
            &corrupt,
            manifest["observedGeneration"]["generation"]
                .as_str()
                .unwrap(),
        );
        fs::write(observed, b"tampered").unwrap();

        assert!(matches!(
            corrupt.read_pending_chain(&key()),
            Err(PendingRemoteCacheChainError::ObservedCorrupt { .. })
        ));
    }

    #[test]
    fn pending_writer_rejects_missing_authenticated_previous_without_publishing() {
        let missing_dir = tempfile::tempdir().unwrap();
        let missing = RemoteVaultCache::new_at(missing_dir.path());
        let error = missing
            .write_pending_autofill(
                &key(),
                entry(b"pending", 1, true),
                entry(b"observed", 1, false),
                &fingerprint(b"baseline", 1),
                None,
                Some(1),
                "operation-1",
            )
            .expect_err("pending durability requires an authenticated previous generation");

        assert!(error.to_string().contains("authenticated previous"));
        assert!(matches!(
            missing.read_pending_chain(&key()),
            Err(PendingRemoteCacheChainError::Missing)
        ));
        assert!(!missing.paths_for_tests(&key()).metadata_path.exists());
    }

    #[test]
    fn pending_writer_rejects_corrupt_current_and_preserves_the_committed_manifest() {
        let corrupt_dir = tempfile::tempdir().unwrap();
        let corrupt = RemoteVaultCache::new_at(corrupt_dir.path());
        corrupt.write(&key(), entry(b"baseline", 1, false)).unwrap();
        let manifest_path = corrupt.paths_for_tests(&key()).metadata_path;
        let manifest_before = fs::read(&manifest_path).unwrap();
        fs::write(current_generation_path(&corrupt), b"tampered").unwrap();

        let error = corrupt
            .write_pending_autofill(
                &key(),
                entry(b"pending", 2, true),
                entry(b"observed", 1, false),
                &fingerprint(b"baseline", 1),
                None,
                Some(1),
                "operation-1",
            )
            .expect_err("corrupt cache state cannot anchor pending durability");

        assert!(error.to_string().contains("corrupt committed cache state"));
        assert_eq!(fs::read(manifest_path).unwrap(), manifest_before);
        assert!(matches!(
            corrupt.read_status(&key()).unwrap(),
            RemoteVaultCacheReadStatus::Corrupt { .. }
        ));
    }

    #[test]
    fn pending_writer_rejects_a_plan_baseline_changed_by_another_cache_writer() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RemoteVaultCache::new_at(dir.path());
        cache
            .write(&key(), entry(b"competing-baseline", 2, false))
            .unwrap();
        let manifest_path = cache.paths_for_tests(&key()).metadata_path;
        let manifest_before = fs::read(&manifest_path).unwrap();

        let error = cache
            .write_pending_autofill(
                &key(),
                entry(b"pending", 3, true),
                entry(b"observed", 2, false),
                &fingerprint(b"loaded-baseline", 1),
                None,
                Some(2),
                "operation-1",
            )
            .expect_err("the authenticated cache baseline must match the loaded plan baseline");

        assert!(error.to_string().contains("plan baseline changed"));
        assert_eq!(fs::read(manifest_path).unwrap(), manifest_before);
        assert_eq!(
            cache.read(&key()).unwrap().unwrap().bytes,
            b"competing-baseline"
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
        let cache = Arc::new(RemoteVaultCache::new_at(dir.path()));
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

            assert!(faulted.write(&key(), entry(b"new-kdbx", 2, false)).is_err());
            let visible = cache.read(&key()).unwrap().unwrap();
            assert!(
                visible.bytes == b"old-kdbx" || visible.bytes == b"new-kdbx",
                "{point:?}"
            );
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

        cache.delete(&key()).unwrap();
        cache.write(&key(), entry(b"kdbx", 42, false)).unwrap();

        let paths = cache.paths_for_tests(&key());
        assert!(paths.metadata_path.exists());
        let generation = current_generation_path(&cache);
        assert!(generation.exists());

        cache.delete(&key()).unwrap();
        cache.delete(&key()).unwrap();

        assert!(!paths.bytes_path.exists());
        assert!(!paths.metadata_path.exists());
        assert!(!generation.exists());
    }
}
