use super::durable_file::{
    DurableFaultInjector, DurableFaultPoint, DurableFileIdentity, ExclusiveFileLock,
    TargetExpectation, TempWriteFaultPoints, VerifiedTemp, opened_file_identity,
    path_file_identity, publish_temp, remove_if_exists, sha256_hex, sync_parent,
    sync_published_target, unique_sibling_path, write_verified_temp,
};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const LOCAL_WRITER_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileSnapshot {
    pub bytes: Vec<u8>,
    pub fingerprint: VaultSourceFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSourceFingerprint {
    pub content_sha256: String,
    pub size_bytes: u64,
    pub modified_at: Option<u64>,
}

pub struct LocalFileVaultSourceProvider {
    write_faults: DurableFaultInjector,
    writer_lock_timeout: Duration,
    #[cfg(test)]
    before_write: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl Default for LocalFileVaultSourceProvider {
    fn default() -> Self {
        Self {
            write_faults: DurableFaultInjector::default(),
            writer_lock_timeout: LOCAL_WRITER_LOCK_TIMEOUT,
            #[cfg(test)]
            before_write: None,
        }
    }
}

#[derive(Debug)]
pub struct LocalFileWriteTxn {
    _lock: ExclusiveFileLock,
    target: PathBuf,
    initial_file: File,
    initial_identity: DurableFileIdentity,
    initial_fingerprint: VaultSourceFingerprint,
    initial_metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCommit {
    pub fingerprint: VaultSourceFingerprint,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum LocalFileCommitError {
    Conflict { message: String },
    BeforePublish { source: io::Error },
    OutcomeUnknown { source: io::Error },
}

impl fmt::Display for LocalFileCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { message } => {
                write!(formatter, "local vault write conflict: {message}")
            }
            Self::BeforePublish { source } => {
                write!(
                    formatter,
                    "local vault write failed before publish: {source}"
                )
            }
            Self::OutcomeUnknown { source } => write!(
                formatter,
                "local vault write may have published but durability is unknown: {source}"
            ),
        }
    }
}

impl std::error::Error for LocalFileCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict { .. } => None,
            Self::BeforePublish { source } | Self::OutcomeUnknown { source } => Some(source),
        }
    }
}

impl LocalFileVaultSourceProvider {
    #[cfg(test)]
    pub(crate) fn with_before_write_hook(
        before_write: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            write_faults: DurableFaultInjector::default(),
            writer_lock_timeout: LOCAL_WRITER_LOCK_TIMEOUT,
            before_write: Some(before_write),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_write_faults(write_faults: DurableFaultInjector) -> Self {
        Self {
            write_faults,
            writer_lock_timeout: LOCAL_WRITER_LOCK_TIMEOUT,
            before_write: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_writer_lock_timeout(writer_lock_timeout: Duration) -> Self {
        Self {
            writer_lock_timeout,
            ..Self::default()
        }
    }

    pub fn pick(&self) -> anyhow::Result<Option<String>> {
        pick_local_vault_path()
    }

    pub fn read_snapshot(&self, path: &str) -> std::io::Result<LocalFileSnapshot> {
        let target = fs::canonicalize(path)?;
        let opened = read_opened_snapshot(&target, false)?;
        Ok(opened.snapshot)
    }

    pub fn begin_write(&self, path: &str) -> io::Result<(LocalFileWriteTxn, LocalFileSnapshot)> {
        let target = fs::canonicalize(path)?;
        let lock_path = local_lock_path(&target)?;
        let lock = ExclusiveFileLock::acquire_with_timeout(&lock_path, self.writer_lock_timeout)?;
        cleanup_pre_publish_hardlink_backups(&target)?;
        let opened = read_opened_snapshot(&target, true)?;
        let OpenedSnapshot {
            snapshot,
            metadata,
            identity,
            file,
        } = opened;
        let transaction = LocalFileWriteTxn {
            _lock: lock,
            target,
            initial_file: file,
            initial_identity: identity,
            initial_fingerprint: snapshot.fingerprint.clone(),
            initial_metadata: metadata,
        };
        Ok((transaction, snapshot))
    }

    pub fn write_if_unchanged(
        &self,
        path: &str,
        expected: &VaultSourceFingerprint,
        bytes: &[u8],
    ) -> Result<DurableCommit, LocalFileCommitError> {
        #[cfg(test)]
        if let Some(before_write) = &self.before_write {
            before_write();
        }
        let (transaction, _) = self.begin_write(path).map_err(classify_begin_write_error)?;
        transaction.commit_inner(expected, bytes, &self.write_faults)
    }
}

fn classify_begin_write_error(source: io::Error) -> LocalFileCommitError {
    match source.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::NotFound => LocalFileCommitError::Conflict {
            message: source.to_string(),
        },
        _ => LocalFileCommitError::BeforePublish { source },
    }
}

impl LocalFileWriteTxn {
    pub fn commit(
        self,
        expected: &VaultSourceFingerprint,
        bytes: &[u8],
    ) -> Result<DurableCommit, LocalFileCommitError> {
        self.commit_inner(expected, bytes, &DurableFaultInjector::default())
    }

    #[cfg(test)]
    fn commit_with_faults(
        self,
        expected: &VaultSourceFingerprint,
        bytes: &[u8],
        faults: &DurableFaultInjector,
    ) -> Result<DurableCommit, LocalFileCommitError> {
        self.commit_inner(expected, bytes, faults)
    }

    fn commit_inner(
        self,
        expected: &VaultSourceFingerprint,
        bytes: &[u8],
        faults: &DurableFaultInjector,
    ) -> Result<DurableCommit, LocalFileCommitError> {
        if expected != &self.initial_fingerprint {
            return Err(LocalFileCommitError::Conflict {
                message: "expected fingerprint does not match the opened generation".to_owned(),
            });
        }
        self.ensure_current_generation()?;

        let mut temp = write_verified_temp(
            &self.target,
            bytes,
            faults,
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .map_err(|source| LocalFileCommitError::BeforePublish { source })?;

        if let Err(source) =
            preserve_file_metadata(&mut temp, &self.initial_file, &self.initial_metadata)
        {
            let _ = temp.discard();
            return Err(LocalFileCommitError::BeforePublish { source });
        }

        let backup = match self.publish_backup(faults) {
            Ok(backup) => backup,
            Err(source) => {
                let _ = temp.discard();
                return Err(LocalFileCommitError::BeforePublish { source });
            }
        };

        if let Err(error) = self.ensure_current_generation() {
            let _ = temp.discard();
            let _ = remove_if_exists(&backup);
            let _ = sync_parent(&self.target);
            return Err(error);
        }

        let publish_result = publish_temp(
            temp,
            &self.target,
            TargetExpectation::IdentityAndContent {
                identity: self.initial_identity,
                content_sha256: self.initial_fingerprint.content_sha256.clone(),
                size_bytes: self.initial_fingerprint.size_bytes,
                modified_at: self.initial_metadata.modified().ok(),
            },
            Some(&backup),
            faults,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        );
        if let Err(error) = publish_result {
            if error.published {
                return match reconcile_published_commit(
                    &self.target,
                    &backup,
                    self.initial_identity,
                    &self.initial_fingerprint,
                    bytes,
                    faults,
                ) {
                    Ok(commit) => Ok(commit),
                    Err(reconcile_error) => match rollback_published_commit(
                        &self.target,
                        &backup,
                        self.initial_identity,
                        &self.initial_fingerprint,
                        bytes,
                        faults,
                    ) {
                        Ok(()) => Err(LocalFileCommitError::BeforePublish {
                            source: io::Error::new(
                                reconcile_error.kind(),
                                format!(
                                    "{}; published-generation reconciliation failed ({reconcile_error}); the previous generation was restored",
                                    error.source
                                ),
                            ),
                        }),
                        Err(rollback_error) => Err(LocalFileCommitError::OutcomeUnknown {
                            source: io::Error::new(
                                reconcile_error.kind(),
                                format!(
                                    "{}; published-generation reconciliation failed ({reconcile_error}) and rollback failed ({rollback_error})",
                                    error.source
                                ),
                            ),
                        }),
                    },
                };
            }
            let _ = remove_if_exists(&backup);
            let _ = sync_parent(&self.target);
            if error.target_conflict {
                return Err(LocalFileCommitError::Conflict {
                    message: error.source.to_string(),
                });
            }
            return Err(LocalFileCommitError::BeforePublish {
                source: error.source,
            });
        }

        let final_readback = faults
            .check(DurableFaultPoint::LocalFinalReadback)
            .and_then(|_| read_opened_snapshot(&self.target, false));
        let snapshot = match final_readback {
            Ok(opened) if opened.snapshot.bytes == bytes => opened.snapshot,
            result => {
                let mismatch = match result {
                    Ok(_) => io::Error::new(
                        io::ErrorKind::InvalidData,
                        "published local vault does not match intended bytes",
                    ),
                    Err(error) => error,
                };
                match reconcile_published_commit(
                    &self.target,
                    &backup,
                    self.initial_identity,
                    &self.initial_fingerprint,
                    bytes,
                    faults,
                ) {
                    Ok(mut commit) => {
                        commit.warnings.push(format!(
                            "initial final readback failed, but an independent readback reconciled the durable published generation: {mismatch}"
                        ));
                        return Ok(commit);
                    }
                    Err(reconcile_error) => {
                        return match persist_local_recovery_candidate(&self.target, &backup, bytes)
                        {
                            Ok(recovery) => Err(LocalFileCommitError::OutcomeUnknown {
                                source: io::Error::new(
                                    mismatch.kind(),
                                    format!(
                                        "{mismatch}; independent published-generation reconciliation failed ({reconcile_error}); the intended candidate was retained at {}",
                                        recovery.display()
                                    ),
                                ),
                            }),
                            Err(recovery_error) => Err(LocalFileCommitError::OutcomeUnknown {
                                source: io::Error::new(
                                    mismatch.kind(),
                                    format!(
                                        "{mismatch}; independent published-generation reconciliation failed ({reconcile_error}); failed to retain the intended candidate: {recovery_error}"
                                    ),
                                ),
                            }),
                        };
                    }
                }
            }
        };

        let mut warnings = Vec::new();
        let backup_is_original =
            verify_backup_generation(&backup, self.initial_identity, &self.initial_fingerprint);
        if let Err(source) = backup_is_original {
            warnings.push(format!(
                "pre-save generation was unavailable or externally changed after publish: {source}"
            ));
        } else if let Err(source) = faults.check(DurableFaultPoint::Cleanup) {
            warnings.push(format!("retained durable backup: {source}"));
        } else if let Err(source) =
            remove_if_exists(&backup).and_then(|_| sync_parent(&self.target))
        {
            warnings.push(format!("could not remove durable backup: {source}"));
        }
        Ok(DurableCommit {
            fingerprint: snapshot.fingerprint,
            warnings,
        })
    }

    fn ensure_current_generation(&self) -> Result<(), LocalFileCommitError> {
        let opened = read_opened_snapshot(&self.target, false).map_err(|error| {
            LocalFileCommitError::Conflict {
                message: format!("could not verify current generation: {error}"),
            }
        })?;
        if opened.identity != self.initial_identity
            || !same_content(&opened.snapshot.fingerprint, &self.initial_fingerprint)
        {
            return Err(LocalFileCommitError::Conflict {
                message: "the local vault changed after it was opened".to_owned(),
            });
        }
        Ok(())
    }

    fn publish_backup(&self, faults: &DurableFaultInjector) -> io::Result<PathBuf> {
        #[cfg(all(unix, not(target_os = "android")))]
        {
            let mut published = None;
            for _ in 0..128 {
                let backup = unique_sibling_path(&self.target, "bak")?;
                match fs::hard_link(&self.target, &backup) {
                    Ok(()) => {
                        published = Some(backup);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            let backup = published.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "could not create a unique local vault backup",
                )
            })?;
            if let Err(error) = sync_parent(&self.target)
                .and_then(|_| faults.check(DurableFaultPoint::BackupPublished))
            {
                let _ = remove_if_exists(&backup);
                let _ = sync_parent(&self.target);
                return Err(error);
            }
            Ok(backup)
        }
        #[cfg(any(windows, target_os = "android"))]
        {
            let mut published = None;
            for _ in 0..128 {
                let backup = unique_sibling_path(&self.target, "bak")?;
                let mut backup_file = match OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&backup)
                {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                };
                let copy_result = (|| {
                    let mut source = File::open(&self.target)?;
                    io::copy(&mut source, &mut backup_file)?;
                    #[cfg(target_os = "android")]
                    preserve_android_backup_metadata(&source, &backup_file)?;
                    backup_file.sync_all()?;
                    sync_parent(&self.target)?;
                    faults.check(DurableFaultPoint::BackupPublished)
                })();
                if let Err(error) = copy_result {
                    drop(backup_file);
                    let _ = remove_if_exists(&backup);
                    let _ = sync_parent(&self.target);
                    return Err(error);
                }
                published = Some(backup);
                break;
            }
            published.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "could not create a unique local vault backup",
                )
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let backup = unique_sibling_path(&self.target, "bak")?;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&backup)?;
            fs::copy(&self.target, &backup)?;
            sync_parent(&self.target)?;
            faults.check(DurableFaultPoint::BackupPublished)?;
            Ok(backup)
        }
    }
}

#[cfg(target_os = "android")]
fn preserve_android_backup_metadata(original: &File, backup: &File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let original_metadata = original.metadata()?;
    backup.set_permissions(fs::Permissions::from_mode(original_metadata.mode()))?;
    preserve_extended_attributes(original, backup)?;
    let backup_metadata = backup.metadata()?;
    if backup_metadata.uid() != original_metadata.uid()
        || backup_metadata.gid() != original_metadata.gid()
        || backup_metadata.mode() != original_metadata.mode()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable Android backup did not preserve ownership and mode",
        ));
    }
    Ok(())
}

fn reconcile_published_commit(
    target: &Path,
    backup: &Path,
    initial_identity: DurableFileIdentity,
    initial_fingerprint: &VaultSourceFingerprint,
    intended_bytes: &[u8],
    faults: &DurableFaultInjector,
) -> io::Result<DurableCommit> {
    let opened = read_opened_snapshot(target, false)?;
    if opened.snapshot.bytes != intended_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "visible local vault does not match the intended published generation",
        ));
    }

    faults.check(DurableFaultPoint::LocalPublishedRepair)?;
    sync_published_target(target)?;
    sync_parent(target)?;

    let mut warnings = Vec::new();
    if let Err(source) = verify_backup_generation(backup, initial_identity, initial_fingerprint) {
        warnings.push(format!(
            "retained an unavailable or externally changed pre-save generation while reconciling the published vault: {source}"
        ));
    } else if let Err(source) = remove_if_exists(backup).and_then(|_| sync_parent(target)) {
        warnings.push(format!(
            "could not remove durable backup after reconciling published generation: {source}"
        ));
    }

    let snapshot = read_opened_snapshot(target, false)?.snapshot;
    if snapshot.bytes != intended_bytes {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local vault changed while reconciling the published generation",
        ));
    }

    Ok(DurableCommit {
        fingerprint: snapshot.fingerprint,
        warnings,
    })
}

fn rollback_published_commit(
    target: &Path,
    backup: &Path,
    initial_identity: DurableFileIdentity,
    initial_fingerprint: &VaultSourceFingerprint,
    intended_bytes: &[u8],
    faults: &DurableFaultInjector,
) -> io::Result<()> {
    verify_backup_generation(backup, initial_identity, initial_fingerprint)?;
    let current = read_opened_snapshot(target, false)?;
    if current.snapshot.bytes != intended_bytes {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local vault changed before the previous generation could be restored",
        ));
    }
    let previous = read_opened_snapshot(backup, false)?;
    let replaced_candidate_backup = unique_sibling_path(target, "rollback")?;
    let rollback_faults = DurableFaultInjector::default();
    let mut temp = write_verified_temp(
        target,
        &previous.snapshot.bytes,
        &rollback_faults,
        TempWriteFaultPoints {
            created: DurableFaultPoint::TempCreated,
            written: DurableFaultPoint::TempWritten,
            synced: DurableFaultPoint::TempSynced,
            verified: DurableFaultPoint::TempReadbackVerified,
        },
    )?;
    if let Err(error) = preserve_file_metadata(&mut temp, &previous.file, &previous.metadata)
        .and_then(|_| faults.check(DurableFaultPoint::LocalRollbackPublished))
    {
        let _ = temp.discard();
        return Err(error);
    }
    if let Err(error) = publish_temp(
        temp,
        target,
        TargetExpectation::IdentityAndContent {
            identity: current.identity,
            content_sha256: current.snapshot.fingerprint.content_sha256,
            size_bytes: current.snapshot.fingerprint.size_bytes,
            modified_at: current.metadata.modified().ok(),
        },
        Some(&replaced_candidate_backup),
        &rollback_faults,
        DurableFaultPoint::BeforeTargetReplace,
        DurableFaultPoint::TargetReplaced,
        DurableFaultPoint::ParentSynced,
    ) {
        if !error.published
            || read_opened_snapshot(target, false)
                .ok()
                .is_none_or(|opened| opened.snapshot.bytes != previous.snapshot.bytes)
        {
            return Err(error.source);
        }
        sync_published_target(target)?;
        sync_parent(target)?;
    }
    let restored = read_opened_snapshot(target, false)?;
    if !same_content(&restored.snapshot.fingerprint, initial_fingerprint) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restored local vault does not match the previous generation",
        ));
    }
    remove_if_exists(backup)?;
    remove_if_exists(&replaced_candidate_backup)?;
    sync_parent(target)
}

fn persist_local_recovery_candidate(
    target: &Path,
    original_backup: &Path,
    intended_bytes: &[u8],
) -> io::Result<PathBuf> {
    let recovery = unique_sibling_path(target, "recovery")?;
    fs::copy(original_backup, &recovery)?;
    File::open(&recovery)?.sync_all()?;
    sync_parent(&recovery)?;
    let placeholder = read_opened_snapshot(&recovery, false)?;
    let faults = DurableFaultInjector::default();
    let mut temp = write_verified_temp(
        &recovery,
        intended_bytes,
        &faults,
        TempWriteFaultPoints {
            created: DurableFaultPoint::TempCreated,
            written: DurableFaultPoint::TempWritten,
            synced: DurableFaultPoint::TempSynced,
            verified: DurableFaultPoint::TempReadbackVerified,
        },
    )?;
    preserve_file_metadata(&mut temp, &placeholder.file, &placeholder.metadata)?;
    let replaced_placeholder = unique_sibling_path(&recovery, "bak")?;
    if let Err(error) = publish_temp(
        temp,
        &recovery,
        TargetExpectation::IdentityAndContent {
            identity: placeholder.identity,
            content_sha256: placeholder.snapshot.fingerprint.content_sha256,
            size_bytes: placeholder.snapshot.fingerprint.size_bytes,
            modified_at: placeholder.metadata.modified().ok(),
        },
        Some(&replaced_placeholder),
        &faults,
        DurableFaultPoint::BeforeTargetReplace,
        DurableFaultPoint::TargetReplaced,
        DurableFaultPoint::ParentSynced,
    ) {
        if !error.published
            || read_opened_snapshot(&recovery, false)
                .ok()
                .is_none_or(|opened| opened.snapshot.bytes != intended_bytes)
        {
            return Err(error.source);
        }
        sync_published_target(&recovery)?;
        sync_parent(&recovery)?;
    }
    let verified = read_opened_snapshot(&recovery, false)?;
    if verified.snapshot.bytes != intended_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local recovery copy does not match the intended candidate",
        ));
    }
    let _ = remove_if_exists(&replaced_placeholder).and_then(|_| sync_parent(&recovery));
    Ok(recovery)
}

#[derive(Debug)]
struct OpenedSnapshot {
    snapshot: LocalFileSnapshot,
    metadata: Metadata,
    identity: DurableFileIdentity,
    file: File,
}

fn read_opened_snapshot(path: &Path, reject_hard_links: bool) -> io::Result<OpenedSnapshot> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local vault target must be a regular file, not a link or special file",
        ));
    }
    reject_reparse_point(&path_metadata)?;
    reject_unsafe_link_count(&path_metadata, reject_hard_links)?;

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
    reject_unsafe_opened_link_count(&file, reject_hard_links)?;
    let before_identity = opened_file_identity(&file, &before)?;
    if !before.is_file() || before_identity != path_file_identity(path, &path_metadata)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local vault target changed while it was being opened",
        ));
    }
    reject_unsafe_link_count(&before, reject_hard_links)?;

    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let after_identity = opened_file_identity(&file, &after)?;
    let final_path_metadata = fs::symlink_metadata(path)?;
    reject_reparse_point(&final_path_metadata)?;
    if before_identity != after_identity
        || after_identity != path_file_identity(path, &final_path_metadata)?
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local vault changed while it was being read",
        ));
    }

    Ok(OpenedSnapshot {
        snapshot: LocalFileSnapshot {
            fingerprint: fingerprint_for_bytes(&bytes, &after),
            bytes,
        },
        identity: after_identity,
        metadata: after,
        file,
    })
}

fn local_lock_path(target: &Path) -> io::Result<PathBuf> {
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?
        .to_string_lossy();
    Ok(target.with_file_name(format!("{name}.vaultkern.lock")))
}

#[cfg(unix)]
fn cleanup_pre_publish_hardlink_backups(target: &Path) -> io::Result<()> {
    let target_metadata = fs::symlink_metadata(target)?;
    if target_metadata.file_type().is_symlink() || !target_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local vault target must be a regular file",
        ));
    }
    let target_identity = path_file_identity(target, &target_metadata)?;
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no parent"))?;
    let target_name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?
        .to_string_lossy();
    let prefix = format!(".{target_name}.vaultkern.bak.");
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_file()
            && path_file_identity(&path, &metadata)? == target_identity
        {
            fs::remove_file(path)?;
            removed = true;
        }
    }
    if removed {
        sync_parent(target)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn cleanup_pre_publish_hardlink_backups(_target: &Path) -> io::Result<()> {
    Ok(())
}

fn verify_backup_generation(
    backup: &Path,
    expected_identity: DurableFileIdentity,
    expected: &VaultSourceFingerprint,
) -> io::Result<()> {
    let opened = read_opened_snapshot(backup, false)?;
    #[cfg(all(unix, not(target_os = "android")))]
    if opened.identity != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable backup no longer identifies the pre-publish inode",
        ));
    }
    let _ = expected_identity;
    if !same_content(&opened.snapshot.fingerprint, expected) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable backup changed across the publish boundary",
        ));
    }
    Ok(())
}

fn same_content(left: &VaultSourceFingerprint, right: &VaultSourceFingerprint) -> bool {
    left.content_sha256 == right.content_sha256 && left.size_bytes == right.size_bytes
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn preserve_extended_attributes(original: &File, replacement: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let original_xattrs = read_file_xattrs(original)?;
    let replacement_xattrs = read_file_xattrs(replacement)?;
    for name in replacement_xattrs.keys() {
        if original_xattrs.contains_key(name) {
            continue;
        }
        let name = std::ffi::CString::new(name.clone()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "extended attribute name contains NUL",
            )
        })?;
        let result = unsafe { libc::fremovexattr(replacement.as_raw_fd(), name.as_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    for (name, value) in &original_xattrs {
        if replacement_xattrs.get(name) == Some(value) {
            continue;
        }
        let name = std::ffi::CString::new(name.clone()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "extended attribute name contains NUL",
            )
        })?;
        let value_pointer = if value.is_empty() {
            std::ptr::null()
        } else {
            value.as_ptr().cast()
        };
        let result = unsafe {
            libc::fsetxattr(
                replacement.as_raw_fd(),
                name.as_ptr(),
                value_pointer,
                value.len(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if read_file_xattrs(replacement)? != original_xattrs {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable temp did not preserve extended attributes",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn preserve_extended_attributes(original: &File, replacement: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let result = unsafe {
        libc::fcopyfile(
            original.as_raw_fd(),
            replacement.as_raw_fd(),
            std::ptr::null_mut(),
            libc::COPYFILE_ACL | libc::COPYFILE_XATTR,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn preserve_extended_attributes(_original: &File, _replacement: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic ACL and extended-attribute preservation is unavailable on this Unix platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_file_xattrs(file: &File) -> io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    use std::os::fd::AsRawFd;

    let mut names = Vec::new();
    loop {
        let size = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            break;
        }
        names.resize(size as usize, 0);
        let read =
            unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(error);
        }
        names.truncate(read as usize);
        break;
    }

    let mut xattrs = BTreeMap::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let c_name = std::ffi::CString::new(name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "extended attribute name contains NUL",
            )
        })?;
        let value = loop {
            let size = unsafe {
                libc::fgetxattr(file.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0)
            };
            if size < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut value = vec![0_u8; size as usize];
            let value_pointer = if value.is_empty() {
                std::ptr::null_mut()
            } else {
                value.as_mut_ptr().cast()
            };
            let read = unsafe {
                libc::fgetxattr(
                    file.as_raw_fd(),
                    c_name.as_ptr(),
                    value_pointer,
                    value.len(),
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ERANGE) {
                    continue;
                }
                return Err(error);
            }
            value.truncate(read as usize);
            break value;
        };
        xattrs.insert(name.to_vec(), value);
    }
    Ok(xattrs)
}

#[cfg(unix)]
fn reject_unsafe_link_count(metadata: &Metadata, reject: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if reject && metadata.nlink() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local vault target has multiple hard links",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unsafe_link_count(_metadata: &Metadata, _reject: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn reject_unsafe_opened_link_count(file: &File, reject: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    if !reject {
        return Ok(());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.nNumberOfLinks > 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local vault target has multiple hard links",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_unsafe_opened_link_count(_file: &File, _reject: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn reject_reparse_point(metadata: &Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local vault target is a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn preserve_file_metadata(
    temp: &mut VerifiedTemp,
    original_file: &File,
    original: &Metadata,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let file = temp.file();
    let temp_metadata = file.metadata()?;
    if temp_metadata.uid() != original.uid() || temp_metadata.gid() != original.gid() {
        let result = unsafe { libc::fchown(file.as_raw_fd(), original.uid(), original.gid()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    file.set_permissions(fs::Permissions::from_mode(original.mode()))?;
    preserve_extended_attributes(original_file, file)?;
    let preserved = file.metadata()?;
    if preserved.uid() != original.uid()
        || preserved.gid() != original.gid()
        || preserved.mode() != original.mode()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable temp did not preserve Unix ownership and mode",
        ));
    }
    file.sync_all()
}

#[cfg(not(unix))]
fn preserve_file_metadata(
    temp: &mut VerifiedTemp,
    _original_file: &File,
    _original: &Metadata,
) -> io::Result<()> {
    temp.file().sync_all()
}

#[cfg_attr(not(windows), allow(dead_code))]
fn decode_picker_stdout(stdout: Vec<u8>) -> anyhow::Result<Option<String>> {
    let path = String::from_utf8(stdout)
        .map_err(|_| anyhow::anyhow!("local vault picker returned non-UTF-8 output"))?
        .trim()
        .to_owned();

    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

fn fingerprint_for_bytes(bytes: &[u8], metadata: &std::fs::Metadata) -> VaultSourceFingerprint {
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs());

    VaultSourceFingerprint {
        content_sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
        modified_at,
    }
}

#[cfg(windows)]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    let script = r#"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Filter = 'KeePass Vault (*.kdbx)|*.kdbx|All Files (*.*)|*.*'
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  Write-Output $dialog.FileName
}
"#;

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-STA", "-Command", script])
        .output()
        .map_err(anyhow::Error::from)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to open local vault picker: {}", stderr.trim());
    }

    decode_picker_stdout(output.stdout)
}

#[cfg(not(windows))]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    anyhow::bail!("local vault picker is only implemented on Windows")
}

#[cfg(test)]
mod tests {
    use super::{
        LocalFileCommitError, LocalFileVaultSourceProvider, VaultSourceFingerprint,
        decode_picker_stdout, local_lock_path,
    };
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock, sha256_hex,
    };
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn sidecar_artifacts(dir: &std::path::Path) -> Vec<String> {
        let mut names = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".vaultkern.tmp.") || name.contains(".vaultkern.bak."))
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn replace_only_temp_file(dir: &std::path::Path, bytes: &[u8]) {
        let temp = fs::read_dir(dir)
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

    #[cfg(unix)]
    fn write_current(path: &std::path::Path, bytes: &[u8]) {
        let provider = LocalFileVaultSourceProvider::default();
        let path = path.to_str().unwrap();
        let snapshot = provider.read_snapshot(path).unwrap();
        provider
            .write_if_unchanged(path, &snapshot.fingerprint, bytes)
            .unwrap();
    }

    #[test]
    fn picker_stdout_decodes_utf8_paths_without_corruption() {
        let path = decode_picker_stdout("C:\\Users\\Example\\Desktop\\测试.kdbx\r\n".into())
            .expect("decode picker stdout");

        assert_eq!(
            path,
            Some("C:\\Users\\Example\\Desktop\\测试.kdbx".to_owned())
        );
    }

    #[test]
    fn picker_stdout_rejects_non_utf8_paths_instead_of_corrupting_them() {
        let gb2312_path = b"C:\\Users\\Example\\Desktop\\\xb2\xe2\xca\xd4.kdbx\r\n".to_vec();

        let error = decode_picker_stdout(gb2312_path).expect_err("non-UTF-8 should fail");

        assert!(error.to_string().contains("non-UTF-8"));
    }

    #[test]
    fn transaction_rejects_changed_expected_fingerprint_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        fs::write(&path, b"external-generation").unwrap();
        let error = transaction
            .commit(&snapshot.fingerprint, b"candidate-generation")
            .expect_err("stale expected fingerprint must conflict");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"external-generation");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[test]
    fn write_if_unchanged_rejects_stale_baseline_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"generation-a").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let baseline = provider.read_snapshot(path.to_str().unwrap()).unwrap();

        fs::write(&path, b"generation-b").unwrap();
        let error = provider
            .write_if_unchanged(
                path.to_str().unwrap(),
                &baseline.fingerprint,
                b"generation-c",
            )
            .expect_err("stale merge baseline must conflict");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"generation-b");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[test]
    fn write_if_unchanged_rejects_a_non_exact_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"generation-a").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let mut expected = provider
            .read_snapshot(path.to_str().unwrap())
            .unwrap()
            .fingerprint;
        expected.modified_at = Some(expected.modified_at.unwrap_or_default().saturating_add(1));

        let error = provider
            .write_if_unchanged(path.to_str().unwrap(), &expected, b"generation-c")
            .expect_err("every fingerprint field must match the locked generation");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"generation-a");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[test]
    fn write_if_unchanged_classifies_locked_read_races_as_conflicts() {
        let error = super::classify_begin_write_error(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "local vault changed while it was being read",
        ));

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert!(
            error
                .to_string()
                .contains("changed while it was being read")
        );
    }

    #[test]
    fn write_if_unchanged_classifies_source_deletion_as_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"generation-a").unwrap();
        let baseline = LocalFileVaultSourceProvider::default()
            .read_snapshot(path.to_str().unwrap())
            .unwrap();
        let target = path.clone();
        let provider =
            LocalFileVaultSourceProvider::with_before_write_hook(std::sync::Arc::new(move || {
                fs::remove_file(&target).unwrap()
            }));

        let error = provider
            .write_if_unchanged(
                path.to_str().unwrap(),
                &baseline.fingerprint,
                b"generation-c",
            )
            .expect_err("a deleted merge source must conflict");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn writer_lock_contention_fails_fast_instead_of_waiting_for_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"generation-a").unwrap();
        let provider =
            LocalFileVaultSourceProvider::with_writer_lock_timeout(Duration::from_millis(100));
        let baseline = provider.read_snapshot(path.to_str().unwrap()).unwrap();
        let canonical = fs::canonicalize(&path).unwrap();
        let holder = ExclusiveFileLock::acquire(&local_lock_path(&canonical).unwrap()).unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _ = released.recv_timeout(Duration::from_secs(1));
            drop(holder);
        });

        let started = Instant::now();
        let result = provider.write_if_unchanged(
            path.to_str().unwrap(),
            &baseline.fingerprint,
            b"generation-b",
        );
        let elapsed = started.elapsed();
        let _ = release.send(());
        holder.join().unwrap();
        let error = result.expect_err("writer-lock contention must time out");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert!(elapsed < Duration::from_millis(750), "waited {elapsed:?}");
        assert_eq!(fs::read(path).unwrap(), b"generation-a");
    }

    #[test]
    fn prepublish_faults_leave_the_original_generation_and_no_temporary_files() {
        let points = [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempWritten,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::TempReadbackVerified,
            DurableFaultPoint::BackupPublished,
            DurableFaultPoint::BeforeTargetReplace,
        ];

        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.kdbx");
            fs::write(&path, b"old-generation").unwrap();
            let provider = LocalFileVaultSourceProvider::default();
            let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

            let error = transaction
                .commit_with_faults(
                    &snapshot.fingerprint,
                    b"new-generation",
                    &DurableFaultInjector::fail_once(point),
                )
                .expect_err("fault must fail commit");

            assert!(matches!(error, LocalFileCommitError::BeforePublish { .. }));
            assert_eq!(fs::read(&path).unwrap(), b"old-generation", "{point:?}");
            assert!(sidecar_artifacts(dir.path()).is_empty(), "{point:?}");
        }
    }

    #[test]
    fn post_publish_faults_reconcile_the_visible_generation() {
        for point in [
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.kdbx");
            fs::write(&path, b"old-generation").unwrap();
            let provider = LocalFileVaultSourceProvider::default();
            let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

            let committed = transaction
                .commit_with_faults(
                    &snapshot.fingerprint,
                    b"new-generation",
                    &DurableFaultInjector::fail_once(point),
                )
                .expect("a visible intended generation should reconcile");

            assert_eq!(fs::read(&path).unwrap(), b"new-generation");
            assert_eq!(
                committed.fingerprint,
                provider
                    .read_snapshot(path.to_str().unwrap())
                    .unwrap()
                    .fingerprint
            );
            assert!(sidecar_artifacts(dir.path()).is_empty());
        }
    }

    #[test]
    fn failed_post_publish_repair_restores_the_original_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let error = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"new-generation",
                &DurableFaultInjector::fail_in_order([
                    DurableFaultPoint::TargetReplaced,
                    DurableFaultPoint::LocalPublishedRepair,
                ]),
            )
            .expect_err("a failed durability repair must not leave a reported-failed publish");

        assert!(matches!(error, LocalFileCommitError::BeforePublish { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"old-generation");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[test]
    fn third_generation_before_final_readback_retains_the_candidate_recovery_copy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let path = root.join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();
        let target = path.clone();

        let error = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"candidate-generation",
                &DurableFaultInjector::run_once(DurableFaultPoint::LocalFinalReadback, move || {
                    fs::write(&target, b"external-generation").unwrap()
                }),
            )
            .expect_err("a third generation must make the commit outcome unknown");

        assert!(matches!(error, LocalFileCommitError::OutcomeUnknown { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"external-generation");
        let recoveries = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".vaultkern.recovery.")
            })
            .map(|entry| fs::read(entry.path()).unwrap())
            .collect::<Vec<_>>();
        assert!(
            recoveries
                .iter()
                .any(|bytes| bytes == b"candidate-generation"),
            "the displaced candidate must remain recoverable"
        );
    }

    #[test]
    fn final_readback_fault_reconciles_the_visible_candidate_without_recovery_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let commit = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"candidate-generation",
                &DurableFaultInjector::fail_once(DurableFaultPoint::LocalFinalReadback),
            )
            .expect("an independent readback must reconcile the visible candidate");

        assert_eq!(fs::read(&path).unwrap(), b"candidate-generation");
        assert_eq!(
            commit.fingerprint.content_sha256,
            sha256_hex(b"candidate-generation")
        );
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn pre_replace_crash_backup_does_not_block_the_next_commit() {
        use std::os::unix::fs::MetadataExt;

        for point in [
            DurableFaultPoint::BackupPublished,
            DurableFaultPoint::BeforeTargetReplace,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.kdbx");
            fs::write(&path, b"old-generation").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::local_file::tests::subprocess_local_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_LOCAL_CRASH_PATH", &path)
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_was_abruptly_killed(status, point);
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 2, "{point:?}");

            write_current(&path, b"retry-generation");

            assert_eq!(fs::read(&path).unwrap(), b"retry-generation");
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        }
    }

    #[test]
    fn final_content_cas_rejects_an_in_place_write_at_the_publish_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();
        let target = path.clone();

        let error = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"candidate-generation",
                &DurableFaultInjector::run_once(
                    DurableFaultPoint::BeforeTargetReplace,
                    move || {
                        fs::write(&target, b"external-generation").unwrap();
                    },
                ),
            )
            .expect_err("same-inode content change must fail the final CAS");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"external-generation");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn post_replace_change_to_the_old_inode_does_not_hide_a_durable_target() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let path = root.join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let committed = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"candidate-generation",
                &DurableFaultInjector::run_once(DurableFaultPoint::TargetReplaced, move || {
                    let backup = fs::read_dir(&root)
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .contains(".vaultkern.bak.")
                        })
                        .expect("backup exists after replace")
                        .path();
                    fs::write(backup, b"external-generation").unwrap();
                }),
            )
            .expect("the intended target is durable even if the old inode changed");

        assert_eq!(fs::read(&path).unwrap(), b"candidate-generation");
        assert_eq!(sidecar_artifacts(dir.path()).len(), 1);
        assert_eq!(committed.warnings.len(), 1);
    }

    #[test]
    fn cleanup_failure_is_a_warning_after_a_durable_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let committed = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"new-generation",
                &DurableFaultInjector::fail_once(DurableFaultPoint::Cleanup),
            )
            .expect("cleanup must not downgrade a durable commit");

        assert_eq!(fs::read(&path).unwrap(), b"new-generation");
        assert_eq!(committed.warnings.len(), 1);
        assert_eq!(sidecar_artifacts(dir.path()).len(), 1);
    }

    #[test]
    fn swapped_verified_temp_is_rejected_before_local_target_publish() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let path = root.join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let error = transaction
            .commit_with_faults(
                &snapshot.fingerprint,
                b"new-generation",
                &DurableFaultInjector::run_once(
                    DurableFaultPoint::BeforeTempPublishValidation,
                    move || replace_only_temp_file(&root, b"attacker-generation"),
                ),
            )
            .expect_err("replaced temp must not be published");

        assert!(matches!(error, LocalFileCommitError::BeforePublish { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"old-generation");
        assert!(sidecar_artifacts(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn durable_write_preserves_mode_and_rejects_hard_link_aliases() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let alias = dir.path().join("alias.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        let provider = LocalFileVaultSourceProvider::default();

        let error = provider
            .begin_write(path.to_str().unwrap())
            .expect_err("multi-link target must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        fs::remove_file(alias).unwrap();
        write_current(&path, b"new-generation");
        assert_eq!(fs::read(&path).unwrap(), b"new-generation");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let lock_path = dir.path().join("vault.kdbx.vaultkern.lock");
        let lock_metadata = fs::metadata(&lock_path).unwrap();
        assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(lock_metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(lock_metadata.nlink(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_write_preserves_posix_acl_and_extended_attributes() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        fn set_xattr(path: &std::path::Path, name: &str, value: &[u8]) {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let name = CString::new(name).unwrap();
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        }

        fn get_xattr(path: &std::path::Path, name: &str) -> Vec<u8> {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let name = CString::new(name).unwrap();
            let size =
                unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
            assert!(size >= 0, "{}", std::io::Error::last_os_error());
            let mut value = vec![0_u8; size as usize];
            let read = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            assert_eq!(read, size);
            value
        }

        fn acl_entry(tag: u16, permissions: u16, id: u32) -> [u8; 8] {
            let mut entry = [0_u8; 8];
            entry[..2].copy_from_slice(&tag.to_le_bytes());
            entry[2..4].copy_from_slice(&permissions.to_le_bytes());
            entry[4..].copy_from_slice(&id.to_le_bytes());
            entry
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let mut acl = 2_u32.to_le_bytes().to_vec();
        acl.extend(acl_entry(0x01, 0o6, u32::MAX));
        acl.extend(acl_entry(0x02, 0o4, 65_534));
        acl.extend(acl_entry(0x04, 0o0, u32::MAX));
        acl.extend(acl_entry(0x10, 0o4, u32::MAX));
        acl.extend(acl_entry(0x20, 0o0, u32::MAX));
        set_xattr(&path, "system.posix_acl_access", &acl);
        set_xattr(&path, "user.vaultkern.test", b"preserve-me");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );

        write_current(&path, b"new-generation");

        assert_eq!(get_xattr(&path, "system.posix_acl_access"), acl);
        assert_eq!(get_xattr(&path, "user.vaultkern.test"), b"preserve-me");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_hard_link_is_rejected_before_permissions_are_changed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let lock_path = dir.path().join("vault.kdbx.vaultkern.lock");
        let lock_alias = dir.path().join("lock-alias");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        drop(provider.begin_write(path.to_str().unwrap()).unwrap());
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(&lock_path, &lock_alias).unwrap();

        let error = provider
            .begin_write(path.to_str().unwrap())
            .expect_err("hard-linked lock must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            fs::metadata(&lock_alias).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_target_symlink_swap_conflicts_without_following_the_replacement() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.kdbx");
        let decoy = dir.path().join("decoy.kdbx");
        fs::write(&target, b"old-generation").unwrap();
        fs::write(&decoy, b"decoy-generation").unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(target.to_str().unwrap()).unwrap();
        fs::remove_file(&target).unwrap();
        symlink(&decoy, &target).unwrap();

        let error = transaction
            .commit(&snapshot.fingerprint, b"candidate-generation")
            .expect_err("replaced target link must conflict");

        assert!(matches!(error, LocalFileCommitError::Conflict { .. }));
        assert_eq!(fs::read(&decoy).unwrap(), b"decoy-generation");
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_path_updates_its_canonical_target_without_replacing_the_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.kdbx");
        let link = dir.path().join("vault.kdbx");
        fs::write(&target, b"old-generation").unwrap();
        symlink(&target, &link).unwrap();

        write_current(&link, b"new-generation");

        assert_eq!(fs::read(&target).unwrap(), b"new-generation");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn subprocess_sigkill_at_every_local_boundary_leaves_only_old_or_new_target() {
        let points = [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempWritten,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::TempReadbackVerified,
            DurableFaultPoint::BackupPublished,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
            DurableFaultPoint::Cleanup,
        ];
        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.kdbx");
            fs::write(&path, b"old-generation").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::local_file::tests::subprocess_local_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_LOCAL_CRASH_PATH", &path)
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_was_abruptly_killed(status, point);

            let visible = LocalFileVaultSourceProvider::default()
                .read_snapshot(path.to_str().unwrap())
                .unwrap();
            assert!(
                visible.bytes == b"old-generation" || visible.bytes == b"new-generation",
                "{point:?} exposed a partial target"
            );
            if matches!(
                point,
                DurableFaultPoint::TempCreated
                    | DurableFaultPoint::TempWritten
                    | DurableFaultPoint::TempSynced
                    | DurableFaultPoint::TempReadbackVerified
                    | DurableFaultPoint::BackupPublished
                    | DurableFaultPoint::BeforeTargetReplace
            ) {
                assert_eq!(visible.bytes, b"old-generation", "{point:?}");
            }
            if point == DurableFaultPoint::Cleanup {
                assert_eq!(visible.bytes, b"new-generation");
            }
        }
    }

    #[test]
    fn two_processes_with_the_same_expected_fingerprint_have_one_cas_winner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let expected = LocalFileVaultSourceProvider::default()
            .read_snapshot(path.to_str().unwrap())
            .unwrap()
            .fingerprint;
        let spawn = |candidate: &'static str| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::local_file::tests::subprocess_local_writer_child",
                    "--ignored",
                ])
                .env("VAULTKERN_LOCAL_WRITER_PATH", &path)
                .env("VAULTKERN_LOCAL_WRITER_CANDIDATE", candidate)
                .env("VAULTKERN_LOCAL_EXPECTED_SHA256", &expected.content_sha256)
                .env(
                    "VAULTKERN_LOCAL_EXPECTED_SIZE",
                    expected.size_bytes.to_string(),
                )
                .env(
                    "VAULTKERN_LOCAL_EXPECTED_MODIFIED_AT",
                    expected
                        .modified_at
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                )
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut first = spawn("candidate-a");
        let mut second = spawn("candidate-b");
        let mut codes = [
            first.wait().unwrap().code().unwrap(),
            second.wait().unwrap().code().unwrap(),
        ];
        codes.sort();

        assert_eq!(codes, [0, 42]);
        let visible = fs::read(&path).unwrap();
        assert!(visible == b"candidate-a" || visible == b"candidate-b");
    }

    #[test]
    #[ignore]
    fn subprocess_local_crash_child() {
        let Ok(path) = std::env::var("VAULTKERN_LOCAL_CRASH_PATH") else {
            return;
        };
        let point = DurableFaultPoint::from_test_name(
            &std::env::var("VAULTKERN_DURABLE_CRASH_POINT").unwrap(),
        )
        .unwrap();
        let provider = LocalFileVaultSourceProvider::default();
        let (transaction, snapshot) = provider.begin_write(&path).unwrap();
        let _ = transaction.commit_with_faults(
            &snapshot.fingerprint,
            b"new-generation",
            &DurableFaultInjector::crash_once(point),
        );
        panic!("crash point was not reached: {point:?}");
    }

    #[test]
    #[ignore]
    fn subprocess_local_writer_child() {
        let Ok(path) = std::env::var("VAULTKERN_LOCAL_WRITER_PATH") else {
            return;
        };
        let candidate = std::env::var("VAULTKERN_LOCAL_WRITER_CANDIDATE").unwrap();
        let expected = VaultSourceFingerprint {
            content_sha256: std::env::var("VAULTKERN_LOCAL_EXPECTED_SHA256").unwrap(),
            size_bytes: std::env::var("VAULTKERN_LOCAL_EXPECTED_SIZE")
                .unwrap()
                .parse()
                .unwrap(),
            modified_at: std::env::var("VAULTKERN_LOCAL_EXPECTED_MODIFIED_AT")
                .unwrap()
                .parse()
                .ok(),
        };
        let (transaction, _) = LocalFileVaultSourceProvider::default()
            .begin_write(&path)
            .unwrap();
        match transaction.commit(&expected, candidate.as_bytes()) {
            Ok(_) => {}
            Err(LocalFileCommitError::Conflict { .. }) => std::process::exit(42),
            Err(error) => panic!("unexpected writer error: {error}"),
        }
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
}
