use super::durable_file::{
    DurableFaultInjector, DurableFaultPoint, DurableFileIdentity, ExclusiveFileLock,
    TargetExpectation, TempWriteFaultPoints, VerifiedTemp, opened_file_identity,
    path_file_identity, publish_temp, remove_if_exists, sha256_hex, sync_parent,
    unique_sibling_path, write_verified_temp,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

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

pub struct LocalFileVaultSourceProvider;

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

impl LocalFileCommitError {
    fn into_io_error(self) -> io::Error {
        let kind = match self {
            Self::Conflict { .. } => io::ErrorKind::WouldBlock,
            Self::BeforePublish { .. } | Self::OutcomeUnknown { .. } => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl LocalFileVaultSourceProvider {
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
        let lock = ExclusiveFileLock::acquire(&lock_path)?;
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

    pub fn write(&self, path: &str, bytes: &[u8]) -> std::io::Result<()> {
        let (transaction, snapshot) = self.begin_write(path)?;
        transaction
            .commit(&snapshot.fingerprint, bytes)
            .map(|_| ())
            .map_err(LocalFileCommitError::into_io_error)
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
        if !same_content(expected, &self.initial_fingerprint) {
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
                return Err(LocalFileCommitError::OutcomeUnknown {
                    source: error.source,
                });
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

        // The final target hash closes every testable pre-rename window. This
        // old-inode check also prevents a measured non-cooperating write from
        // being reported as success. No portable rename API can linearize an
        // arbitrary write through an already-open third-party descriptor, so
        // the sidecar lock remains the contract for cooperative writers.
        if let Err(source) =
            verify_backup_generation(&backup, self.initial_identity, &self.initial_fingerprint)
        {
            return Err(LocalFileCommitError::OutcomeUnknown { source });
        }

        let mut warnings = Vec::new();
        if let Err(source) = faults.check(DurableFaultPoint::Cleanup) {
            warnings.push(format!("retained durable backup: {source}"));
        } else if let Err(source) =
            remove_if_exists(&backup).and_then(|_| sync_parent(&self.target))
        {
            warnings.push(format!("could not remove durable backup: {source}"));
        }

        let snapshot = read_opened_snapshot(&self.target, false)
            .map_err(|source| LocalFileCommitError::OutcomeUnknown { source })?
            .snapshot;
        if snapshot.bytes != bytes {
            return Err(LocalFileCommitError::OutcomeUnknown {
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "published local vault does not match intended bytes",
                ),
            });
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
        #[cfg(unix)]
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
            return Ok(backup);
        }
        #[cfg(windows)]
        {
            let backup = unique_sibling_path(&self.target, "bak")?;
            faults.check(DurableFaultPoint::BackupPublished)?;
            return Ok(backup);
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
    #[cfg(unix)]
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

#[cfg(target_os = "linux")]
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

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn preserve_extended_attributes(_original: &File, _replacement: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic ACL and extended-attribute preservation is unavailable on this Unix platform",
    ))
}

#[cfg(target_os = "linux")]
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

#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
fn decode_picker_stdout(stdout: Vec<u8>) -> anyhow::Result<Option<String>> {
    let path = String::from_utf8(stdout)
        .map_err(|_| anyhow::anyhow!("local vault picker returned non-UTF-8 output"))?;
    let path = path
        .strip_suffix("\r\n")
        .or_else(|| path.strip_suffix('\n'))
        .unwrap_or(&path)
        .to_owned();

    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

#[cfg(target_os = "macos")]
const MACOS_PICKER_SCRIPT: &str = r#"use framework "UniformTypeIdentifiers"
use scripting additions

try
    set kdbxType to current application's UTType's typeWithFilenameExtension:"kdbx" conformingToType:(current application's UTTypeData)
    if kdbxType is missing value then error "Unable to resolve the .kdbx file type"
    set kdbxTypeIdentifier to (kdbxType's identifier()) as text
    set selectedVault to choose file with prompt "Select a KeePass vault" of type {kdbxTypeIdentifier} invisibles true multiple selections allowed false showing package contents false
    return POSIX path of selectedVault
on error number -128
    return ""
end try"#;

#[cfg(target_os = "macos")]
fn pick_macos_local_vault_path_with(
    runner: impl FnOnce(&mut std::process::Command) -> std::io::Result<std::process::Output>,
) -> anyhow::Result<Option<String>> {
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command.args(["-e", MACOS_PICKER_SCRIPT]);
    let output = runner(&mut command).map_err(anyhow::Error::from)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            anyhow::bail!("failed to open macOS local vault picker: {}", output.status);
        }
        anyhow::bail!("failed to open macOS local vault picker: {stderr}");
    }

    decode_picker_stdout(output.stdout)
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

#[cfg(target_os = "macos")]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    pick_macos_local_vault_path_with(std::process::Command::output)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn pick_local_vault_path() -> anyhow::Result<Option<String>> {
    anyhow::bail!("local vault picker is only implemented on Windows and macOS")
}

#[cfg(test)]
mod tests {
    use super::{
        LocalFileCommitError, LocalFileVaultSourceProvider, VaultSourceFingerprint,
        decode_picker_stdout,
    };
    #[cfg(target_os = "macos")]
    use super::{MACOS_PICKER_SCRIPT, pick_macos_local_vault_path_with};
    use crate::providers::durable_file::{DurableFaultInjector, DurableFaultPoint};
    use std::fs;
    #[cfg(target_os = "macos")]
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    #[cfg(target_os = "macos")]
    use std::process::{ExitStatus, Output};

    #[cfg(target_os = "macos")]
    fn command_output(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        Output {
            status: ExitStatus::from_raw(exit_code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

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

    #[test]
    fn picker_stdout_preserves_unicode_and_spaces_while_removing_one_crlf() {
        let path =
            decode_picker_stdout("C:\\Users\\Example\\Desktop\\ 测试 vault.kdbx \r\n".into())
                .expect("decode picker stdout");

        assert_eq!(
            path,
            Some("C:\\Users\\Example\\Desktop\\ 测试 vault.kdbx ".to_owned())
        );
    }

    #[test]
    fn picker_stdout_removes_only_one_line_ending() {
        assert_eq!(
            decode_picker_stdout(b"/tmp/vault.kdbx\n\n".to_vec()).expect("decode picker stdout"),
            Some("/tmp/vault.kdbx\n".to_owned())
        );
        assert_eq!(
            decode_picker_stdout(b"/tmp/vault.kdbx\r\n\r\n".to_vec())
                .expect("decode picker stdout"),
            Some("/tmp/vault.kdbx\r\n".to_owned())
        );
    }

    #[test]
    fn picker_stdout_maps_empty_output_to_none() {
        assert_eq!(
            decode_picker_stdout(Vec::new()).expect("decode picker stdout"),
            None
        );
        assert_eq!(
            decode_picker_stdout(b"\n".to_vec()).expect("decode picker stdout"),
            None
        );
    }

    #[test]
    fn picker_stdout_rejects_non_utf8_paths_instead_of_corrupting_them() {
        let gb2312_path = b"C:\\Users\\Example\\Desktop\\\xb2\xe2\xca\xd4.kdbx\r\n".to_vec();

        let error = decode_picker_stdout(gb2312_path).expect_err("non-UTF-8 should fail");

        assert!(error.to_string().contains("non-UTF-8"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_runner_uses_osascript_and_static_picker_script() {
        let path = pick_macos_local_vault_path_with(|command| {
            assert_eq!(command.get_program(), "/usr/bin/osascript");
            let args = command
                .get_args()
                .map(|arg| arg.to_str().expect("UTF-8 command argument"))
                .collect::<Vec<_>>();
            assert_eq!(args, ["-e", MACOS_PICKER_SCRIPT]);
            assert!(MACOS_PICKER_SCRIPT.contains("use framework \"UniformTypeIdentifiers\""));
            assert!(MACOS_PICKER_SCRIPT.contains("use scripting additions"));
            assert!(MACOS_PICKER_SCRIPT.contains("typeWithFilenameExtension:\"kdbx\""));
            assert!(MACOS_PICKER_SCRIPT.contains("of type {kdbxTypeIdentifier}"));
            assert!(!MACOS_PICKER_SCRIPT.contains("of type {\"kdbx\"}"));
            assert!(MACOS_PICKER_SCRIPT.contains("on error number -128"));
            assert!(MACOS_PICKER_SCRIPT.contains(
                "choose file with prompt \"Select a KeePass vault\" of type {kdbxTypeIdentifier} invisibles true multiple selections allowed false showing package contents false"
            ));
            assert!(MACOS_PICKER_SCRIPT.contains("return POSIX path"));

            Ok(command_output(
                0,
                "/Users/Example/测试 vault.kdbx\n".as_bytes(),
                b"",
            ))
        })
        .expect("run macOS picker");

        assert_eq!(path, Some("/Users/Example/测试 vault.kdbx".to_owned()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_reports_failed_child_stderr() {
        let error = pick_macos_local_vault_path_with(|_| {
            Ok(command_output(
                7,
                b"",
                b"37:42: execution error: picker failed (-2700)\n",
            ))
        })
        .expect_err("failed picker should be reported");

        assert_eq!(
            error.to_string(),
            "failed to open macOS local vault picker: 37:42: execution error: picker failed (-2700)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picker_reports_exit_status_when_stderr_is_empty() {
        let error = pick_macos_local_vault_path_with(|_| Ok(command_output(7, b"", b" \r\n")))
            .expect_err("failed picker should be reported");

        assert_eq!(
            error.to_string(),
            "failed to open macOS local vault picker: exit status: 7"
        );
    }

    #[test]
    fn transaction_rejects_changed_expected_fingerprint_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider;
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
            let provider = LocalFileVaultSourceProvider;
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
    fn directory_sync_failure_reports_unknown_and_keeps_a_complete_backup() {
        for point in [
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.kdbx");
            fs::write(&path, b"old-generation").unwrap();
            let provider = LocalFileVaultSourceProvider;
            let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

            let error = transaction
                .commit_with_faults(
                    &snapshot.fingerprint,
                    b"new-generation",
                    &DurableFaultInjector::fail_once(point),
                )
                .expect_err("post-replace failure is outcome unknown");

            assert!(matches!(error, LocalFileCommitError::OutcomeUnknown { .. }));
            assert_eq!(fs::read(&path).unwrap(), b"new-generation");
            let backups = sidecar_artifacts(dir.path());
            assert_eq!(backups.len(), 1);
            assert_eq!(
                fs::read(dir.path().join(&backups[0])).unwrap(),
                b"old-generation"
            );
        }
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

            LocalFileVaultSourceProvider
                .write(path.to_str().unwrap(), b"retry-generation")
                .expect("retry must clean only the pre-publish hard-link backup");

            assert_eq!(fs::read(&path).unwrap(), b"retry-generation");
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        }
    }

    #[test]
    fn final_content_cas_rejects_an_in_place_write_at_the_publish_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider;
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
    fn post_replace_change_to_the_old_inode_is_never_reported_as_success() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let path = root.join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider;
        let (transaction, snapshot) = provider.begin_write(path.to_str().unwrap()).unwrap();

        let error = transaction
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
            .expect_err("a changed pre-publish inode makes the outcome unknown");

        assert!(matches!(error, LocalFileCommitError::OutcomeUnknown { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"candidate-generation");
        assert_eq!(sidecar_artifacts(dir.path()).len(), 1);
    }

    #[test]
    fn cleanup_failure_is_a_warning_after_a_durable_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, b"old-generation").unwrap();
        let provider = LocalFileVaultSourceProvider;
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
        let provider = LocalFileVaultSourceProvider;
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
        let provider = LocalFileVaultSourceProvider;

        let error = provider
            .begin_write(path.to_str().unwrap())
            .expect_err("multi-link target must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        fs::remove_file(alias).unwrap();
        provider
            .write(path.to_str().unwrap(), b"new-generation")
            .unwrap();
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

        LocalFileVaultSourceProvider
            .write(path.to_str().unwrap(), b"new-generation")
            .unwrap();

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
        let provider = LocalFileVaultSourceProvider;
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
        let provider = LocalFileVaultSourceProvider;
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

        LocalFileVaultSourceProvider
            .write(link.to_str().unwrap(), b"new-generation")
            .unwrap();

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

            let visible = LocalFileVaultSourceProvider
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
        let expected = LocalFileVaultSourceProvider
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
        let provider = LocalFileVaultSourceProvider;
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
            modified_at: None,
        };
        let (transaction, _) = LocalFileVaultSourceProvider.begin_write(&path).unwrap();
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
