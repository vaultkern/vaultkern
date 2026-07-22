use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
#[cfg(any(windows, test))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::providers::durable_file::{ExclusiveFileLock, remove_and_sync_absence};
use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[cfg(windows)]
use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, TargetExpectation, TempWriteFaultPoints,
    create_dir_all_durable, opened_file_identity, path_file_identity, publish_temp,
    remove_if_exists, sync_parent, sync_published_target, write_verified_temp,
};
#[cfg(any(windows, test))]
use crate::providers::durable_file::{VerifiedTemp, unique_sibling_path};
#[cfg(windows)]
use crate::sync::durable_replace;

const TOKEN_FILE_NAME: &str = "onedrive-refresh-token.dpapi";
#[cfg(any(windows, test))]
const MAX_PROTECTED_REFRESH_TOKEN_BYTES: usize = 64 * 1024;
const TOKEN_STORE_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub(crate) trait OneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn store(&self, token: &str) -> Result<()>;
    #[allow(dead_code)]
    fn delete(&self) -> Result<()>;
}

#[derive(Debug)]
struct OneDriveRefreshTokenStoreUnavailable;

impl std::fmt::Display for OneDriveRefreshTokenStoreUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "persistent OneDrive refresh-token storage is unavailable on this platform; reauthenticate to reconnect OneDrive",
        )
    }
}

impl std::error::Error for OneDriveRefreshTokenStoreUnavailable {}

pub(crate) fn is_unavailable_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<OneDriveRefreshTokenStoreUnavailable>()
        .is_some()
}

pub(crate) fn production_default() -> Box<dyn OneDriveRefreshTokenStore> {
    production_store(
        runtime_state_dir().join(TOKEN_FILE_NAME),
        "vaultkern-runtime/default",
    )
}

pub(crate) fn production_for_extension_id(
    extension_id: &str,
) -> Box<dyn OneDriveRefreshTokenStore> {
    if !is_safe_extension_id_path_component(extension_id) {
        return Box::new(InvalidExtensionIdOneDriveRefreshTokenStore);
    }
    production_store(
        extension_state_dir(extension_id).join(TOKEN_FILE_NAME),
        &format!("vaultkern-runtime/extension/{extension_id}"),
    )
}

fn is_safe_extension_id_path_component(extension_id: &str) -> bool {
    !extension_id.is_empty()
        && extension_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn production_store(path: PathBuf, scope: &str) -> Box<dyn OneDriveRefreshTokenStore> {
    if let Err(error) = remove_legacy_plaintext_token(&path) {
        return Box::new(FailedOneDriveRefreshTokenStore {
            message: format!("failed to remove legacy plaintext OneDrive refresh token: {error:#}"),
        });
    }
    #[cfg(windows)]
    {
        Box::new(WindowsOneDriveRefreshTokenStore::new(path, scope))
    }
    #[cfg(not(windows))]
    {
        let _ = (path, scope);
        Box::new(UnavailableOneDriveRefreshTokenStore)
    }
}

fn remove_legacy_plaintext_token(protected_path: &std::path::Path) -> Result<()> {
    let Some(parent) = protected_path.parent() else {
        return Ok(());
    };
    validate_existing_directory_ancestry(parent)?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("OneDrive refresh-token cleanup parent is not a real directory")
        }
        Ok(_) => {}
    }
    let identity = existing_directory_identity(parent)?;
    let legacy_path = parent.join("onedrive-refresh-token");
    match fs::symlink_metadata(&legacy_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!(
                "legacy OneDrive refresh-token path is not a regular file: {}",
                legacy_path.display()
            )
        }
        Ok(_) => {}
    }
    let _lock = acquire_token_store_lock(protected_path)?;
    validate_existing_directory_identity(parent, identity)?;
    remove_and_sync_absence(&legacy_path).with_context(|| {
        format!(
            "failed to durably delete legacy OneDrive refresh token: {}",
            legacy_path.display()
        )
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExistingDirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExistingDirectoryIdentity {
    volume: u32,
    index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, PartialEq, Eq)]
struct ExistingDirectoryIdentity {
    canonical_path: PathBuf,
    modified: Option<std::time::SystemTime>,
}

#[cfg(unix)]
fn existing_directory_identity(path: &std::path::Path) -> Result<ExistingDirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        anyhow::bail!("OneDrive refresh-token cleanup parent is not a real directory");
    }
    Ok(ExistingDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn existing_directory_identity(path: &std::path::Path) -> Result<ExistingDirectoryIdentity> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        anyhow::bail!("OneDrive refresh-token cleanup parent is not a real directory");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let information = opened_file_information(&file)?;
    Ok(ExistingDirectoryIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn existing_directory_identity(path: &std::path::Path) -> Result<ExistingDirectoryIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        anyhow::bail!("OneDrive refresh-token cleanup parent is not a real directory");
    }
    Ok(ExistingDirectoryIdentity {
        canonical_path: fs::canonicalize(path)?,
        modified: metadata.modified().ok(),
    })
}

fn validate_existing_directory_identity(
    path: &std::path::Path,
    expected: ExistingDirectoryIdentity,
) -> Result<()> {
    if existing_directory_identity(path)? != expected {
        anyhow::bail!(
            "OneDrive refresh-token cleanup parent changed before legacy deletion: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_existing_directory_ancestry(path: &std::path::Path) -> Result<()> {
    use std::path::Component;

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                anyhow::bail!("OneDrive refresh-token path contains parent traversal")
            }
        }

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            anyhow::bail!(
                "OneDrive refresh-token path contains a link or non-directory component: {}",
                current.display()
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                anyhow::bail!(
                    "OneDrive refresh-token path contains a reparse-point component: {}",
                    current.display()
                );
            }
        }
    }
    Ok(())
}

fn token_lock_path(path: &std::path::Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("OneDrive refresh-token path has no file name")?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(any(windows, test))]
fn token_backup_path(path: &std::path::Path, target_exists: bool) -> Result<Option<PathBuf>> {
    target_exists
        .then(|| unique_sibling_path(path, "bak").map_err(anyhow::Error::from))
        .transpose()
}

#[cfg(any(windows, test))]
fn token_target_exists(path: &std::path::Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        anyhow::bail!(
            "protected OneDrive refresh-token path is not a private regular file: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!(
                "protected OneDrive refresh-token path is not a private regular file: {}",
                path.display()
            );
        }
    }
    Ok(true)
}

fn acquire_token_store_lock(path: &std::path::Path) -> Result<ExclusiveFileLock> {
    acquire_token_store_lock_with_timeout(path, TOKEN_STORE_LOCK_TIMEOUT)
}

fn acquire_token_store_lock_with_timeout(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<ExclusiveFileLock> {
    let lock_path = token_lock_path(path)?;
    ExclusiveFileLock::acquire_with_timeout(&lock_path, timeout).with_context(|| {
        format!(
            "failed to acquire OneDrive refresh-token store lock: {}",
            lock_path.display()
        )
    })
}

pub(crate) struct EphemeralOneDriveRefreshTokenStore {
    token: RefCell<Option<Zeroizing<String>>>,
}

struct InvalidExtensionIdOneDriveRefreshTokenStore;

struct FailedOneDriveRefreshTokenStore {
    message: String,
}

impl OneDriveRefreshTokenStore for FailedOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        anyhow::bail!(self.message.clone())
    }

    fn store(&self, _token: &str) -> Result<()> {
        anyhow::bail!(self.message.clone())
    }

    fn delete(&self) -> Result<()> {
        anyhow::bail!(self.message.clone())
    }
}

impl OneDriveRefreshTokenStore for InvalidExtensionIdOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        invalid_extension_id()
    }

    fn store(&self, _token: &str) -> Result<()> {
        invalid_extension_id()
    }

    fn delete(&self) -> Result<()> {
        invalid_extension_id()
    }
}

fn invalid_extension_id<T>() -> Result<T> {
    anyhow::bail!("invalid OneDrive token-store extension id")
}

impl Default for EphemeralOneDriveRefreshTokenStore {
    fn default() -> Self {
        Self {
            token: RefCell::new(None),
        }
    }
}

impl OneDriveRefreshTokenStore for EphemeralOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self.token.borrow().as_ref().cloned())
    }

    fn store(&self, token: &str) -> Result<()> {
        self.token.replace(Some(Zeroizing::new(token.to_owned())));
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        self.token.replace(None);
        Ok(())
    }
}

#[cfg(not(windows))]
pub(crate) struct UnavailableOneDriveRefreshTokenStore;

#[cfg(not(windows))]
impl OneDriveRefreshTokenStore for UnavailableOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        unavailable()
    }

    fn store(&self, _token: &str) -> Result<()> {
        unavailable()
    }

    fn delete(&self) -> Result<()> {
        unavailable()
    }
}

#[cfg(any(windows, test))]
fn enforce_temp_metadata_or_discard(
    temp: VerifiedTemp,
    enforce: impl FnOnce(&std::path::Path) -> Result<()>,
) -> Result<VerifiedTemp> {
    if let Err(error) = enforce(temp.path()) {
        return match temp.discard() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error).context(format!(
                "failed to discard OneDrive refresh-token temp file after metadata enforcement failure: {cleanup_error}"
            )),
        };
    }
    Ok(temp)
}

#[cfg(not(windows))]
fn unavailable<T>() -> Result<T> {
    Err(OneDriveRefreshTokenStoreUnavailable.into())
}

#[cfg(windows)]
pub(crate) struct WindowsOneDriveRefreshTokenStore {
    path: PathBuf,
    entropy: [u8; 32],
    faults: DurableFaultInjector,
}

#[cfg(windows)]
impl WindowsOneDriveRefreshTokenStore {
    pub(crate) fn new(path: PathBuf, scope: &str) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"VaultKern OneDrive refresh-token DPAPI v1\0");
        hasher.update(scope.as_bytes());
        Self {
            path,
            entropy: hasher.finalize().into(),
            faults: DurableFaultInjector::default(),
        }
    }

    #[cfg(test)]
    fn new_with_faults(path: PathBuf, scope: &str, faults: DurableFaultInjector) -> Self {
        let mut store = Self::new(path, scope);
        store.faults = faults;
        store
    }
}

#[cfg(windows)]
impl OneDriveRefreshTokenStore for WindowsOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        let Some(parent) = self.path.parent() else {
            anyhow::bail!("OneDrive refresh-token path has no parent directory");
        };
        validate_existing_directory_ancestry(parent)?;
        if !parent.exists() {
            return Ok(None);
        }
        enforce_private_acl(parent, true)?;
        let _lock = acquire_token_store_lock(&self.path)?;
        enforce_private_acl(&token_lock_path(&self.path)?, false)?;
        if !token_target_exists(&self.path)? {
            return Ok(None);
        }
        enforce_private_acl(&self.path, false)?;
        let Some(ciphertext) = read_regular_file(&self.path)? else {
            return Ok(None);
        };
        unprotect_refresh_token(&ciphertext, &self.entropy)
            .context("failed to unprotect persisted OneDrive refresh token")
            .map(Some)
    }

    fn store(&self, token: &str) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("OneDrive refresh-token path has no parent directory")?;
        validate_existing_directory_ancestry(parent)?;
        create_dir_all_durable(parent).with_context(|| {
            format!(
                "failed to create private OneDrive refresh-token directory: {}",
                parent.display()
            )
        })?;
        enforce_private_acl(parent, true)?;
        let _lock = acquire_token_store_lock(&self.path)?;
        enforce_private_acl(&token_lock_path(&self.path)?, false)?;
        let target_exists = token_target_exists(&self.path)?;
        if target_exists {
            enforce_private_acl(&self.path, false)?;
        }
        let protected = protect_refresh_token(token, &self.entropy)
            .context("failed to protect OneDrive refresh token")?;
        validate_protected_payload_size(protected.len() as u64)?;
        let expectation = target_expectation(&self.path)?;
        let temp = write_verified_temp(
            &self.path,
            &protected,
            &self.faults,
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .with_context(|| {
            format!(
                "failed to write protected OneDrive refresh-token temp file: {}",
                self.path.display()
            )
        })?;
        let temp = enforce_temp_metadata_or_discard(temp, |path| enforce_private_acl(path, false))?;
        let backup = token_backup_path(&self.path, target_exists)?;
        let publish = publish_temp(
            temp,
            &self.path,
            expectation,
            backup.as_deref(),
            &self.faults,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        );
        if let Err(error) = publish {
            let failure = anyhow::Error::new(error.source).context(format!(
                "failed to publish protected OneDrive refresh token: {}",
                self.path.display()
            ));
            if error.published {
                let intended_visible = match read_regular_file(&self.path) {
                    Ok(current) => {
                        current.is_some_and(|current| current.as_slice() == protected.as_slice())
                    }
                    Err(read_error) => {
                        if let Err(recovery_error) =
                            restore_previous_token_state(&self.path, backup.as_deref())
                        {
                            return Err(failure.context(format!(
                                "token publish readback failed ({read_error:#}) and rollback failed ({recovery_error:#})"
                            )));
                        }
                        return Err(failure.context(format!(
                            "token publish readback failed; the previous token state was restored: {read_error:#}"
                        )));
                    }
                };
                if intended_visible {
                    match sync_published_target(&self.path)
                        .and_then(|_| sync_parent(&self.path))
                        .map_err(anyhow::Error::from)
                        .and_then(|_| enforce_private_acl(&self.path, false))
                    {
                        Ok(()) => {
                            let _ = cleanup_token_sidecars(&self.path);
                            return Ok(());
                        }
                        Err(repair_error) => {
                            if let Err(recovery_error) =
                                restore_previous_token_state(&self.path, backup.as_deref())
                            {
                                return Err(failure.context(format!(
                                    "new token became visible, durability or ACL repair failed ({repair_error:#}), and rollback failed ({recovery_error:#})"
                                )));
                            }
                            return Err(failure.context(format!(
                                "new token became visible but failed durability or ACL repair; the previous token state was restored: {repair_error:#}"
                            )));
                        }
                    }
                }
                if let Err(recovery_error) =
                    restore_previous_token_state(&self.path, backup.as_deref())
                {
                    return Err(failure.context(format!(
                        "failed to restore the previous protected OneDrive refresh token: {recovery_error:#}"
                    )));
                }
            }
            return Err(failure);
        }
        if let Err(acl_error) = enforce_private_acl(&self.path, false) {
            restore_previous_token_state(&self.path, backup.as_deref()).with_context(|| {
                format!(
                    "protected token ACL validation failed ({acl_error:#}) and rollback also failed"
                )
            })?;
            return Err(acl_error)
                .context("protected OneDrive refresh token failed final ACL verification");
        }
        if let Some(backup) = backup {
            let _ = remove_if_exists(&backup).and_then(|_| sync_parent(&self.path));
        }
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        let Some(parent) = self.path.parent() else {
            anyhow::bail!("OneDrive refresh-token path has no parent directory");
        };
        validate_existing_directory_ancestry(parent)?;
        if !parent.exists() {
            return Ok(());
        }
        enforce_private_acl(parent, true)?;
        let _lock = acquire_token_store_lock(&self.path)?;
        enforce_private_acl(&token_lock_path(&self.path)?, false)?;
        if token_target_exists(&self.path)? {
            enforce_private_acl(&self.path, false)?;
        }
        cleanup_token_sidecars(&self.path)?;
        remove_and_sync_absence(&self.path).with_context(|| {
            format!(
                "failed to delete protected OneDrive refresh token: {}",
                self.path.display()
            )
        })?;
        Ok(())
    }
}

#[cfg(windows)]
fn cleanup_token_sidecars(path: &std::path::Path) -> Result<()> {
    let parent = path
        .parent()
        .context("OneDrive refresh-token path has no parent directory")?;
    let name = path
        .file_name()
        .context("OneDrive refresh-token path has no file name")?
        .to_string_lossy();
    let temp_prefix = format!(".{name}.vaultkern.tmp.");
    let backup_prefix = format!(".{name}.vaultkern.bak.");
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if entry_name.starts_with(&temp_prefix) || entry_name.starts_with(&backup_prefix) {
            remove_if_exists(&entry.path())?;
        }
    }
    sync_parent(path).context("failed to sync OneDrive refresh-token sidecar deletion")
}

#[cfg(windows)]
fn restore_previous_token_state(
    target: &std::path::Path,
    backup: Option<&std::path::Path>,
) -> Result<()> {
    if let Some(backup) = backup {
        let previous = read_regular_file(backup)?.with_context(|| {
            format!(
                "protected OneDrive refresh-token backup is missing: {}",
                backup.display()
            )
        })?;
        durable_replace(target, &previous)?;
        enforce_private_acl(target, false)?;
        remove_if_exists(backup)?;
        sync_parent(target)?;
    } else {
        remove_and_sync_absence(target)?;
    }
    Ok(())
}

#[cfg(any(windows, test))]
struct TokenSecurityContext {
    user_sid: String,
    owner_sid: String,
}

#[cfg(any(windows, test))]
impl TokenSecurityContext {
    fn new(user_sid: String, owner_sid: String) -> Self {
        Self {
            user_sid,
            owner_sid,
        }
    }

    fn private_sddl(&self, directory: bool) -> String {
        if directory {
            format!(
                "D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                self.user_sid
            )
        } else {
            format!("D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", self.user_sid)
        }
    }

    fn validate_owner(&self, owner_sid: &str, path: &std::path::Path) -> Result<()> {
        if owner_sid != self.owner_sid {
            anyhow::bail!(
                "OneDrive refresh-token ACL target is owned by another user: {}",
                path.display()
            );
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PrivateAclEntry {
    ace_type: u8,
    flags: u8,
    mask: u32,
    sid: String,
}

#[cfg(any(windows, test))]
fn private_acl_entries_match(expected: &[PrivateAclEntry], actual: &[PrivateAclEntry]) -> bool {
    let mut expected = expected.to_vec();
    let mut actual = actual.to_vec();
    expected.sort_unstable();
    actual.sort_unstable();
    expected == actual
}

#[cfg(any(windows, test))]
fn validate_single_link_count(link_count: u32, path: &std::path::Path) -> Result<()> {
    if link_count != 1 {
        anyhow::bail!(
            "OneDrive refresh-token path must not be a hard link: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn enforce_private_acl(path: &std::path::Path, directory: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect OneDrive refresh-token ACL target: {}",
            path.display()
        )
    })?;
    let expected_type = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if metadata.file_type().is_symlink()
        || !expected_type
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        anyhow::bail!(
            "OneDrive refresh-token ACL target is not a real {}: {}",
            if directory { "directory" } else { "file" },
            path.display()
        );
    }
    if !directory {
        validate_single_link_regular_file(path)?;
    }

    let security = current_token_security_context()?;
    let owner_sid = file_owner_sid_string(path)?;
    security.validate_owner(&owner_sid, path)?;

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let descriptor = security_descriptor_from_sddl(&security.private_sddl(directory))?;
    let result = unsafe {
        SetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to apply private OneDrive refresh-token ACL: {}",
                path.display()
            )
        });
    }
    verify_private_acl(path, directory)
}

#[cfg(windows)]
fn verify_private_acl(path: &std::path::Path, directory: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetFileSecurityW};

    let security = current_token_security_context()?;
    let owner_sid = file_owner_sid_string(path)?;
    security.validate_owner(&owner_sid, path)?;
    if !directory {
        validate_single_link_regular_file(path)?;
    }

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut required = 0_u32;
    unsafe {
        GetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to size OneDrive refresh-token security descriptor: {}",
                path.display()
            )
        });
    }
    let word_size = std::mem::size_of::<usize>();
    let mut descriptor = vec![0_usize; (required as usize).div_ceil(word_size)];
    let result = unsafe {
        GetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to read OneDrive refresh-token security descriptor: {}",
                path.display()
            )
        });
    }

    let expected = security_descriptor_from_sddl(&security.private_sddl(directory))?;
    let (actual_protected, actual_entries) =
        private_acl_from_descriptor(descriptor.as_mut_ptr().cast())?;
    let (expected_protected, expected_entries) = private_acl_from_descriptor(expected.0)?;
    if !actual_protected
        || !expected_protected
        || !private_acl_entries_match(&expected_entries, &actual_entries)
    {
        anyhow::bail!(
            "OneDrive refresh-token ACL is not private: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn security_descriptor_from_sddl(sddl: &str) -> Result<LocalPointer> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    let sddl_wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    let descriptor = LocalPointer(descriptor);
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to build private OneDrive refresh-token ACL");
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn private_acl_from_descriptor(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<(bool, Vec<PrivateAclEntry>)> {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce,
        GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        SE_DACL_PROTECTED,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect OneDrive refresh-token ACL control flags");
    }

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect OneDrive refresh-token DACL");
    }
    if present == 0 || dacl.is_null() {
        anyhow::bail!("OneDrive refresh-token ACL has no private DACL");
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to size OneDrive refresh-token DACL");
    }

    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect OneDrive refresh-token DACL entry");
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            anyhow::bail!("OneDrive refresh-token ACL contains an unexpected entry");
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        entries.push(PrivateAclEntry {
            ace_type: header.AceType,
            flags: header.AceFlags,
            mask: ace.Mask,
            sid: sid_to_string(sid)?,
        });
    }

    Ok((control & SE_DACL_PROTECTED != 0, entries))
}

#[cfg(windows)]
fn current_token_security_context() -> Result<TokenSecurityContext> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open the current process token");
    }
    let token = OwnedHandle(token);
    let user = token_information_buffer(token.0, TokenUser)?;
    let token_user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };
    let user_sid = sid_to_string(token_user.User.Sid)?;
    let owner = token_information_buffer(token.0, TokenOwner)?;
    let token_owner = unsafe { &*owner.as_ptr().cast::<TOKEN_OWNER>() };
    let owner_sid = sid_to_string(token_owner.Owner)?;
    Ok(TokenSecurityContext::new(user_sid, owner_sid))
}

#[cfg(windows)]
fn token_information_buffer(
    token: windows_sys::Win32::Foundation::HANDLE,
    information_class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>> {
    use windows_sys::Win32::Security::GetTokenInformation;

    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(
            token,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to size token information");
    }
    let word_size = std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; (required as usize).div_ceil(word_size)];
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to read token information");
    }
    Ok(buffer)
}

#[cfg(windows)]
fn file_owner_sid_string(path: &std::path::Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    };

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut required = 0_u32;
    unsafe {
        GetFileSecurityW(
            path_wide.as_ptr(),
            OWNER_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to size OneDrive refresh-token owner descriptor: {}",
                path.display()
            )
        });
    }
    let word_size = std::mem::size_of::<usize>();
    let mut descriptor = vec![0_usize; (required as usize).div_ceil(word_size)];
    if unsafe {
        GetFileSecurityW(
            path_wide.as_ptr(),
            OWNER_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to read OneDrive refresh-token owner descriptor: {}",
                path.display()
            )
        });
    }
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(descriptor.as_mut_ptr().cast(), &mut owner, &mut defaulted)
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect OneDrive refresh-token owner SID");
    }
    sid_to_string(owner)
}

#[cfg(windows)]
fn sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    if sid.is_null() {
        anyhow::bail!("Windows user SID is missing");
    }
    let mut sid_string = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_string) } == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to format a Windows user SID");
    }
    let sid_string = LocalPointer(sid_string.cast());
    let mut len = 0;
    unsafe {
        while *sid_string.0.cast::<u16>().add(len) != 0 {
            len += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(sid_string.0.cast::<u16>(), len))
            .context("Windows user SID uses invalid UTF-16")
    }
}

#[cfg(windows)]
fn target_expectation(path: &std::path::Path) -> Result<TargetExpectation> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(TargetExpectation::Missing)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect protected OneDrive refresh token: {}",
                path.display()
            )
        }),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                anyhow::bail!(
                    "protected OneDrive refresh-token path is not a private regular file: {}",
                    path.display()
                );
            }
            validate_single_link_regular_file(path)?;
            Ok(TargetExpectation::Identity(path_file_identity(
                path, &metadata,
            )?))
        }
    }
}

#[cfg(windows)]
fn read_regular_file(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let path_metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        anyhow::bail!(
            "protected OneDrive refresh-token path is not a private regular file: {}",
            path.display()
        );
    }
    let expected_identity = path_file_identity(path, &path_metadata)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    validate_opened_file_link_count(&file, path)?;
    let before = file.metadata()?;
    if !before.is_file() || opened_file_identity(&file, &before)? != expected_identity {
        anyhow::bail!("protected OneDrive refresh-token file changed while opening");
    }
    let bytes = read_bounded_protected_payload(&mut file, before.len())?;
    let after = file.metadata()?;
    let final_path_metadata = fs::symlink_metadata(path)?;
    if opened_file_identity(&file, &after)? != expected_identity
        || path_file_identity(path, &final_path_metadata)? != expected_identity
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
    {
        anyhow::bail!("protected OneDrive refresh-token file changed while reading");
    }
    Ok(Some(bytes))
}

#[cfg(windows)]
fn validate_single_link_regular_file(path: &std::path::Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    validate_opened_file_link_count(&file, path)
}

#[cfg(windows)]
fn validate_opened_file_link_count(file: &fs::File, path: &std::path::Path) -> Result<()> {
    let information = opened_file_information(file).with_context(|| {
        format!(
            "failed to inspect OneDrive refresh-token hard-link count: {}",
            path.display()
        )
    })?;
    validate_single_link_count(information.nNumberOfLinks, path)
}

#[cfg(windows)]
fn opened_file_information(
    file: &fs::File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(information)
}

#[cfg(any(windows, test))]
fn read_bounded_protected_payload(
    reader: &mut impl std::io::Read,
    declared_len: u64,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    validate_protected_payload_size(declared_len)?;
    let mut bytes = Vec::new();
    std::io::Read::take(reader, (MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    validate_protected_payload_size(bytes.len() as u64)?;
    Ok(bytes)
}

#[cfg(any(windows, test))]
fn validate_protected_payload_size(len: u64) -> Result<()> {
    if len > MAX_PROTECTED_REFRESH_TOKEN_BYTES as u64 {
        anyhow::bail!("protected OneDrive refresh-token payload is too large");
    }
    Ok(())
}

#[cfg(windows)]
fn protect_refresh_token(token: &str, entropy: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = data_blob(token.as_bytes())?;
    let entropy = data_blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let output = LocalBlob::new(output, false);
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(output.as_slice().to_vec())
}

#[cfg(windows)]
fn unprotect_refresh_token(ciphertext: &[u8], entropy: &[u8]) -> Result<Zeroizing<String>> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = data_blob(ciphertext)?;
    let entropy = data_blob(entropy)?;
    let mut description = ptr::null_mut();
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptUnprotectData(
            &input,
            &mut description,
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let output = LocalBlob::new(output, true);
    let _description = LocalPointer(description.cast());
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut plaintext = Zeroizing::new(output.as_slice().to_vec());
    match String::from_utf8(std::mem::take(&mut *plaintext)) {
        Ok(token) => Ok(Zeroizing::new(token)),
        Err(error) => {
            let _invalid_plaintext = Zeroizing::new(error.into_bytes());
            anyhow::bail!("persisted OneDrive refresh token is not valid UTF-8")
        }
    }
}

#[cfg(windows)]
fn data_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(bytes.len()).context("DPAPI input is too large")?;
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: len,
            pbData: bytes.as_ptr().cast_mut(),
        },
    )
}

#[cfg(windows)]
struct LocalBlob {
    blob: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
    wipe: bool,
}

#[cfg(windows)]
impl LocalBlob {
    fn new(
        blob: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
        wipe: bool,
    ) -> Self {
        Self { blob, wipe }
    }

    fn as_slice(&self) -> &[u8] {
        if self.blob.cbData == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.blob.pbData, self.blob.cbData as usize) }
    }
}

#[cfg(windows)]
impl Drop for LocalBlob {
    fn drop(&mut self) {
        if self.blob.pbData.is_null() {
            return;
        }
        unsafe {
            if self.wipe {
                zeroize_plaintext_bytes(std::slice::from_raw_parts_mut(
                    self.blob.pbData,
                    self.blob.cbData as usize,
                ));
            }
            windows_sys::Win32::Foundation::LocalFree(self.blob.pbData.cast());
        }
    }
}

#[cfg(any(windows, test))]
fn zeroize_plaintext_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[cfg(windows)]
struct LocalPointer(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for LocalPointer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemoryOneDriveRefreshTokenStore {
    token: std::sync::Arc<std::sync::Mutex<Option<Zeroizing<String>>>>,
}

#[cfg(test)]
impl OneDriveRefreshTokenStore for MemoryOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self.token.lock().expect("memory token store lock").clone())
    }

    fn store(&self, token: &str) -> Result<()> {
        *self.token.lock().expect("memory token store lock") =
            Some(Zeroizing::new(token.to_owned()));
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        *self.token.lock().expect("memory token store lock") = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::OneDriveRefreshTokenStore;
    use super::{
        MAX_PROTECTED_REFRESH_TOKEN_BYTES, PrivateAclEntry, TokenSecurityContext,
        acquire_token_store_lock, acquire_token_store_lock_with_timeout,
        enforce_temp_metadata_or_discard, private_acl_entries_match, production_for_extension_id,
        production_store, read_bounded_protected_payload, token_backup_path, token_lock_path,
        validate_protected_payload_size, validate_single_link_count, zeroize_plaintext_bytes,
    };
    #[cfg(unix)]
    use super::{token_target_exists, validate_existing_directory_identity};
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, TempWriteFaultPoints, write_verified_temp,
    };

    #[test]
    fn private_temp_enforcement_failure_discards_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("onedrive-refresh-token.dpapi");
        let temp = write_verified_temp(
            &target,
            b"protected-payload",
            &DurableFaultInjector::default(),
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .unwrap();
        let temp_path = temp.path().to_owned();

        let error = enforce_temp_metadata_or_discard(temp, |_| {
            anyhow::bail!("simulated ACL enforcement failure")
        })
        .expect_err("metadata enforcement failure must be reported");

        assert!(format!("{error:#}").contains("simulated ACL enforcement failure"));
        assert!(!temp_path.exists());
    }

    #[test]
    fn protected_payload_reader_rejects_declared_size_above_limit() {
        let mut bytes = std::io::Cursor::new(vec![0_u8; MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1]);

        let error = read_bounded_protected_payload(
            &mut bytes,
            (MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1) as u64,
        )
        .expect_err("oversized protected token payload must be rejected");

        assert!(format!("{error:#}").contains("too large"));
    }

    #[test]
    fn protected_payload_reader_stops_growth_beyond_limit() {
        let mut bytes = std::io::Cursor::new(vec![0_u8; MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1]);

        let error =
            read_bounded_protected_payload(&mut bytes, MAX_PROTECTED_REFRESH_TOKEN_BYTES as u64)
                .expect_err("a growing protected token payload must remain bounded");

        assert!(format!("{error:#}").contains("too large"));
        assert_eq!(
            bytes.position(),
            (MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1) as u64
        );
    }

    #[test]
    fn protected_payload_writer_rejects_size_above_reader_limit() {
        validate_protected_payload_size(MAX_PROTECTED_REFRESH_TOKEN_BYTES as u64).unwrap();

        let error = validate_protected_payload_size((MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1) as u64)
            .expect_err("the writer must not publish a payload the reader will reject");

        assert!(format!("{error:#}").contains("too large"));
    }

    #[test]
    fn private_acl_binds_the_current_user_sid_instead_of_owner_rights() {
        let security =
            TokenSecurityContext::new("S-1-5-21-user".to_owned(), "S-1-5-32-owner".to_owned());
        let directory = security.private_sddl(true);
        let file = security.private_sddl(false);

        assert_eq!(
            directory,
            "D:P(A;OICI;FA;;;S-1-5-21-user)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        assert_eq!(file, "D:P(A;;FA;;;S-1-5-21-user)(A;;FA;;;SY)(A;;FA;;;BA)");
        assert!(!directory.contains(";;;OW"));
        assert!(!file.contains(";;;OW"));
        security
            .validate_owner("S-1-5-32-owner", std::path::Path::new("token.dpapi"))
            .unwrap();
    }

    #[test]
    fn private_acl_rejects_an_owner_other_than_the_current_user() {
        let security =
            TokenSecurityContext::new("S-1-5-21-user".to_owned(), "S-1-5-21-owner".to_owned());
        let error = security
            .validate_owner("S-1-5-21-other", std::path::Path::new("token.dpapi"))
            .expect_err("foreign-owned token paths must be rejected");

        assert!(format!("{error:#}").contains("owned by another user"));
    }

    #[test]
    fn private_acl_comparison_ignores_ace_order_but_not_permissions() {
        let entry = |sid: &str, mask| PrivateAclEntry {
            ace_type: 0,
            flags: 3,
            mask,
            sid: sid.to_owned(),
        };
        let expected = vec![
            entry("S-1-5-21-user", 0x001f_01ff),
            entry("S-1-5-18", 0x001f_01ff),
            entry("S-1-5-32-544", 0x001f_01ff),
        ];
        let reordered = vec![
            expected[2].clone(),
            expected[0].clone(),
            expected[1].clone(),
        ];
        let mut weakened = reordered.clone();
        weakened[0].mask = 0x0012_0089;

        assert!(private_acl_entries_match(&expected, &reordered));
        assert!(!private_acl_entries_match(&expected, &weakened));
    }

    #[test]
    fn token_file_requires_exactly_one_hard_link() {
        validate_single_link_count(1, std::path::Path::new("token.dpapi")).unwrap();
        let error = validate_single_link_count(2, std::path::Path::new("token.dpapi"))
            .expect_err("hard-linked token files must be rejected");
        assert!(format!("{error:#}").contains("hard link"));
    }

    #[test]
    fn token_backup_is_allocated_only_for_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("onedrive-refresh-token.dpapi");

        assert!(token_backup_path(&target, false).unwrap().is_none());
        let backup = token_backup_path(&target, true).unwrap().unwrap();
        assert_eq!(backup.parent(), target.parent());
        assert_ne!(backup, target);
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".bak.")
        );
    }

    #[cfg(unix)]
    #[test]
    fn broken_token_symlink_is_not_treated_as_a_missing_token() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("onedrive-refresh-token.dpapi");
        symlink(dir.path().join("missing"), &target).unwrap();

        let error =
            token_target_exists(&target).expect_err("a broken token symlink must fail closed");
        assert!(format!("{error:#}").contains("regular file"));
    }

    #[test]
    fn dpapi_plaintext_wipe_zeroizes_the_entire_buffer() {
        let mut plaintext = *b"fixture-refresh-token";

        zeroize_plaintext_bytes(&mut plaintext);

        assert!(plaintext.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn token_store_lock_serializes_mutations_on_a_sibling_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("onedrive-refresh-token.dpapi");
        let first = acquire_token_store_lock(&target).unwrap();
        let lock_path = token_lock_path(&target).unwrap();
        assert_eq!(
            lock_path.file_name().unwrap(),
            "onedrive-refresh-token.dpapi.lock"
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let second = acquire_token_store_lock(&target).unwrap();
            sender.send(second).unwrap();
        });

        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(first);
        let second = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        drop(second);
        thread.join().unwrap();
    }

    #[test]
    fn token_store_lock_contention_returns_instead_of_waiting_for_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("onedrive-refresh-token.dpapi");
        let held = acquire_token_store_lock(&target).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sender
                .send(acquire_token_store_lock_with_timeout(
                    &target,
                    std::time::Duration::from_millis(40),
                ))
                .unwrap();
        });

        let result = receiver.recv_timeout(std::time::Duration::from_millis(250));
        drop(held);
        thread.join().unwrap();

        let error = result
            .expect("token-store contender waited indefinitely for the held lock")
            .expect_err("token-store contender unexpectedly acquired the held lock");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn invalid_extension_id_cannot_select_legacy_cleanup_path() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_path = dir.path().join("onedrive-refresh-token");
        std::fs::write(&legacy_path, b"must-not-be-deleted").unwrap();
        let invalid_extension_id = dir.path().to_str().unwrap();

        let store = production_for_extension_id(invalid_extension_id);
        let error = store
            .load()
            .expect_err("an invalid extension id must produce an unusable store");

        assert!(format!("{error:#}").contains("invalid OneDrive token-store extension id"));
        assert!(legacy_path.exists());
    }

    #[test]
    fn production_store_removes_the_selected_legacy_plaintext_file() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_path = dir.path().join("onedrive-refresh-token");
        std::fs::write(&legacy_path, b"legacy-plaintext-token").unwrap();

        let _store = production_store(
            dir.path().join("onedrive-refresh-token.dpapi"),
            "test/default",
        );

        assert!(!legacy_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn production_store_does_not_follow_legacy_cleanup_symlink_ancestry() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let legacy_path = external.path().join("onedrive-refresh-token");
        std::fs::write(&legacy_path, b"must-not-be-deleted").unwrap();
        let linked_parent = root.path().join("linked-parent");
        symlink(external.path(), &linked_parent).unwrap();

        let _store = production_store(
            linked_parent.join("onedrive-refresh-token.dpapi"),
            "test/default",
        );

        assert!(legacy_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_cleanup_rejects_a_replaced_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("state");
        std::fs::create_dir(&parent).unwrap();
        let identity = super::existing_directory_identity(&parent).unwrap();
        std::fs::rename(&parent, root.path().join("original-state")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let replacement_legacy = parent.join("onedrive-refresh-token");
        std::fs::write(&replacement_legacy, b"must-not-be-deleted").unwrap();

        let error = validate_existing_directory_identity(&parent, identity)
            .expect_err("a replaced cleanup parent must be rejected");

        assert!(format!("{error:#}").contains("changed"));
        assert!(replacement_legacy.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn production_store_requires_reauthentication_without_a_platform_backend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = production_store(path.clone(), "test/default");

        let load_error = match store.load() {
            Ok(_) => panic!("production token loading must be unavailable"),
            Err(error) => error,
        };
        let store_error = store
            .store("fixture-refresh-token")
            .expect_err("production token persistence must be unavailable");

        assert!(format!("{load_error:#}").contains("reauthenticate"));
        assert!(format!("{store_error:#}").contains("reauthenticate"));
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_round_trips_without_persisting_plaintext() {
        use super::{WindowsOneDriveRefreshTokenStore, verify_private_acl};

        const TOKEN: &str = "fixture-refresh-token-never-plaintext";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default");

        store.store(TOKEN).unwrap();

        verify_private_acl(dir.path(), true).unwrap();
        verify_private_acl(&path, false).unwrap();
        let persisted = std::fs::read(&path).unwrap();
        assert_ne!(persisted, TOKEN.as_bytes());
        assert!(
            !persisted
                .windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes())
        );
        assert_eq!(
            store.load().unwrap().as_deref().map(String::as_str),
            Some(TOKEN)
        );

        store.delete().unwrap();
        assert!(!path.exists());
        assert!(store.load().unwrap().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_repairs_a_recoverable_post_publish_failure() {
        use super::WindowsOneDriveRefreshTokenStore;

        const OLD_TOKEN: &str = "fixture-refresh-token-before-failure";
        const TOKEN: &str = "fixture-refresh-token-published-before-failure";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default")
            .store(OLD_TOKEN)
            .unwrap();
        let store = WindowsOneDriveRefreshTokenStore::new_with_faults(
            path.clone(),
            "test/default",
            DurableFaultInjector::fail_once(DurableFaultPoint::TargetReplaced),
        );

        store
            .store(TOKEN)
            .expect("a visible replacement must be repaired and acknowledged");
        assert_eq!(
            store.load().unwrap().as_deref().map(String::as_str),
            Some(TOKEN)
        );
        let backups = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|candidate| {
                candidate
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".bak.")
            })
            .collect::<Vec<_>>();
        assert!(backups.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_removes_backup_after_successful_replacement() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new(path, "test/default");
        store.store("refresh-token-1").unwrap();
        store.store("refresh-token-2").unwrap();

        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".bak.")
        }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_rejects_oversized_protected_payload_before_dpapi() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        std::fs::write(&path, vec![0_u8; MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1]).unwrap();
        let store = WindowsOneDriveRefreshTokenStore::new(path, "test/default");

        let error = store
            .load()
            .expect_err("oversized protected payload must fail before DPAPI processing");

        assert!(format!("{error:#}").contains("too large"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_does_not_publish_a_payload_above_the_reader_limit() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default");
        let token = "x".repeat(MAX_PROTECTED_REFRESH_TOKEN_BYTES);

        let error = store
            .store(&token)
            .expect_err("oversized protected output must not be published");

        assert!(format!("{error:#}").contains("too large"));
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_scope_entropy_prevents_cross_scope_decryption() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default")
            .store("fixture-refresh-token")
            .unwrap();

        let error = WindowsOneDriveRefreshTokenStore::new(path, "test/extension")
            .load()
            .expect_err("a different token-store scope must not decrypt the payload");

        assert!(!format!("{error:#}").contains("fixture-refresh-token"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_rejects_corrupted_ciphertext() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default");
        store.store("fixture-refresh-token").unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x80;
        std::fs::write(&path, bytes).unwrap();

        let error = store
            .load()
            .expect_err("corrupted protected payload must fail closed");

        assert!(!format!("{error:#}").contains("fixture-refresh-token"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_rejects_a_hard_linked_token_target() {
        use super::WindowsOneDriveRefreshTokenStore;

        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("other-file");
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        std::fs::write(&original, b"not-a-token").unwrap();
        std::fs::hard_link(&original, &path).unwrap();
        let store = WindowsOneDriveRefreshTokenStore::new(path, "test/default");

        let error = store
            .load()
            .expect_err("hard-linked token targets must fail before DPAPI processing");

        assert!(format!("{error:#}").contains("hard link"));
        assert_eq!(std::fs::read(original).unwrap(), b"not-a-token");
    }
}
