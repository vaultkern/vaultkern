#[cfg(any(windows, test))]
use anyhow::Context;
use anyhow::Result;
use std::cell::RefCell;
use std::collections::BTreeMap;
#[cfg(any(windows, test))]
use std::fs;
#[cfg(any(windows, test))]
use std::io;
#[cfg(any(windows, test))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(windows, test))]
use std::time::Duration;

#[cfg(windows)]
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
#[cfg(windows)]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[cfg(any(windows, test))]
use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, DurableFileIdentity, ExclusiveFileLock,
    TargetExpectation, TempWriteFaultPoints, create_dir_all_durable, opened_file_identity,
    path_file_identity, publish_temp, remove_if_exists, sync_parent, unique_sibling_path,
    write_verified_temp,
};

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_ENVELOPE_VERSION: u8 = 3;
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_ENVELOPE_SCHEME: &str = "windows-passport-rsa-pkcs1-aes-256-gcm-hello-v3";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_KEY_STORAGE_PROVIDER: &str = "Microsoft Passport Key Storage Provider";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_NGC_AUTH_MANDATORY: u32 = 1;
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_GESTURE_REQUIRED: u32 = 1;
#[cfg(any(windows, test))]
const QUICK_UNLOCK_RECORD_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(any(windows, test))]
const WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1177;
#[cfg(any(windows, test))]
const NTE_BAD_KEY_STATE: u32 = 0x8009_000b;
#[cfg(any(windows, test))]
const NTE_NO_KEY: u32 = 0x8009_000d;
#[cfg(any(windows, test))]
const NTE_BAD_KEYSET: u32 = 0x8009_0016;

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Deserialize, Serialize)]
struct QuickUnlockEnvelope {
    version: u8,
    scheme: String,
    wrapped_key: String,
    nonce: String,
    ciphertext: String,
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn is_quick_unlock_envelope(bytes: &[u8]) -> bool {
    serde_json::from_slice::<QuickUnlockEnvelope>(bytes)
        .map(|envelope| {
            envelope.version == QUICK_UNLOCK_ENVELOPE_VERSION
                && envelope.scheme == QUICK_UNLOCK_ENVELOPE_SCHEME
        })
        .unwrap_or(false)
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn quick_unlock_key_storage_provider_name() -> &'static str {
    QUICK_UNLOCK_KEY_STORAGE_PROVIDER
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn quick_unlock_ngc_cache_type() -> u32 {
    QUICK_UNLOCK_NGC_AUTH_MANDATORY
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn quick_unlock_gesture_required() -> u32 {
    QUICK_UNLOCK_GESTURE_REQUIRED
}

#[cfg(any(windows, test))]
fn quick_unlock_persistent_key_name(user_sid: &str, dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(dir.to_string_lossy().as_bytes());
    let suffix = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{user_sid}//VaultKern/QuickUnlock/{suffix}")
}

#[cfg(any(windows, test))]
fn publish_quick_unlock_record(path: &Path, bytes: &[u8]) -> Result<()> {
    publish_quick_unlock_record_with(
        path,
        bytes,
        &DurableFaultInjector::default(),
        QUICK_UNLOCK_RECORD_LOCK_TIMEOUT,
    )
}

#[cfg(any(windows, test))]
fn publish_quick_unlock_record_with(
    path: &Path,
    bytes: &[u8],
    faults: &DurableFaultInjector,
    lock_timeout: Duration,
) -> Result<()> {
    let parent = path
        .parent()
        .context("quick unlock record path has no parent directory")?;
    create_dir_all_durable(parent).with_context(|| {
        format!(
            "failed to create private quick unlock record directory: {}",
            parent.display()
        )
    })?;
    let parent_guard = QuickUnlockParentGuard::acquire(parent).with_context(|| {
        format!(
            "failed to bind quick unlock record parent directory: {}",
            parent.display()
        )
    })?;

    let lock_path = quick_unlock_record_lock_path(path)?;
    let _lock =
        ExclusiveFileLock::acquire_with_timeout(&lock_path, lock_timeout).with_context(|| {
            format!(
                "failed to acquire quick unlock record lock: {}",
                lock_path.display()
            )
        })?;
    parent_guard.validate(parent)?;
    let expectation = quick_unlock_target_expectation(path)?;
    let replacing = matches!(expectation, TargetExpectation::Identity(_));
    let backup = replacing
        .then(|| unique_sibling_path(path, "bak"))
        .transpose()?;
    let temp = write_verified_temp(
        path,
        bytes,
        faults,
        TempWriteFaultPoints {
            created: DurableFaultPoint::TempCreated,
            written: DurableFaultPoint::TempWritten,
            synced: DurableFaultPoint::TempSynced,
            verified: DurableFaultPoint::TempReadbackVerified,
        },
    )
    .with_context(|| format!("failed to prepare quick unlock record: {}", path.display()))?;
    if let Err(source) = faults
        .check(DurableFaultPoint::BeforeTargetReplace)
        .and_then(|_| parent_guard.validate(parent))
    {
        let _ = temp.discard();
        return Err(anyhow::Error::new(source).context(format!(
            "quick unlock record was not published: {}",
            path.display()
        )));
    }
    if let Err(error) = publish_temp(
        temp,
        path,
        expectation,
        backup.as_deref(),
        faults,
        DurableFaultPoint::BeforeTargetReplace,
        DurableFaultPoint::TargetReplaced,
        DurableFaultPoint::ParentSynced,
    ) {
        let state = if error.published && quick_unlock_replacement_outcome_is_unknown(&error.source)
        {
            "quick unlock record publication outcome is unknown; recovery artifacts were preserved"
        } else if error.published {
            "quick unlock record was published, but durability or cleanup was not fully confirmed"
        } else if error.target_conflict {
            "quick unlock record target changed before atomic publication"
        } else {
            "quick unlock record was not published"
        };
        return Err(
            anyhow::Error::new(error.source).context(format!("{state}: {}", path.display()))
        );
    }

    parent_guard.validate(parent).with_context(|| {
        format!(
            "quick unlock record was published, but parent directory identity changed: {}",
            parent.display()
        )
    })?;
    faults.check(DurableFaultPoint::Cleanup).with_context(|| {
        format!(
            "quick unlock record was published, but cleanup was not confirmed: {}",
            path.display()
        )
    })?;
    cleanup_quick_unlock_sidecars(path).with_context(|| {
        format!(
            "quick unlock record was published, but recovery cleanup was not confirmed: {}",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(any(windows, test))]
struct QuickUnlockParentGuard {
    identity: DurableFileIdentity,
    #[cfg(windows)]
    _handle: fs::File,
}

#[cfg(any(windows, test))]
impl QuickUnlockParentGuard {
    fn acquire(parent: &Path) -> io::Result<Self> {
        let handle = open_quick_unlock_parent(parent)?;
        let identity = opened_file_identity(&handle, &handle.metadata()?)?;
        let guard = Self {
            identity,
            #[cfg(windows)]
            _handle: handle,
        };
        guard.validate(parent)?;
        Ok(guard)
    }

    fn validate(&self, parent: &Path) -> io::Result<()> {
        let current = open_quick_unlock_parent(parent)?;
        let current_identity = opened_file_identity(&current, &current.metadata()?)?;
        if current_identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "quick unlock record parent directory changed during publication",
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn open_quick_unlock_parent(parent: &Path) -> io::Result<fs::File> {
    let path_metadata = fs::symlink_metadata(parent)?;
    validate_quick_unlock_parent_metadata(&path_metadata)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let handle = options.open(parent)?;
    let opened_metadata = handle.metadata()?;
    validate_quick_unlock_parent_metadata(&opened_metadata)?;
    #[cfg(not(windows))]
    if opened_file_identity(&handle, &opened_metadata)?
        != path_file_identity(parent, &path_metadata)?
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "quick unlock record parent directory changed while it was opened",
        ));
    }
    Ok(handle)
}

#[cfg(any(windows, test))]
fn validate_quick_unlock_parent_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quick unlock record parent is not a real directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quick unlock record parent is a reparse point",
            ));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn quick_unlock_replacement_outcome_is_unknown(error: &io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2)
}

#[cfg(any(windows, test))]
fn quick_unlock_record_lock_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("quick unlock record path has no file name")?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(any(windows, test))]
fn cleanup_quick_unlock_sidecars(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("quick unlock record path has no parent directory")?;
    let name = path
        .file_name()
        .context("quick unlock record path has no file name")?
        .to_string_lossy();
    let temp_prefix = format!(".{name}.vaultkern.tmp.");
    let backup_prefix = format!(".{name}.vaultkern.bak.");
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if entry_name.starts_with(&temp_prefix) || entry_name.starts_with(&backup_prefix) {
            remove_if_exists(&entry.path()).with_context(|| {
                format!(
                    "failed to remove stale quick unlock record sidecar: {}",
                    entry.path().display()
                )
            })?;
            removed = true;
        }
    }
    if removed {
        sync_parent(path).with_context(|| {
            format!(
                "failed to sync quick unlock record directory after stale sidecar cleanup: {}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn quick_unlock_target_expectation(path: &Path) -> Result<TargetExpectation> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TargetExpectation::Missing);
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        anyhow::bail!(
            "quick unlock record target is not a private regular file: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!(
                "quick unlock record target is a reparse point: {}",
                path.display()
            );
        }
    }
    Ok(TargetExpectation::Identity(path_file_identity(
        path, &metadata,
    )?))
}

#[derive(Debug)]
pub(crate) struct SecureStorageError {
    kind: SecureStorageErrorKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureStorageErrorKind {
    Cancelled,
    #[cfg(any(windows, test))]
    HelloKeyInvalidated,
    #[cfg(any(windows, test))]
    RecordInvalidated,
}

impl SecureStorageError {
    #[cfg(any(windows, test))]
    pub(crate) fn cancelled(message: impl Into<String>) -> Self {
        Self {
            kind: SecureStorageErrorKind::Cancelled,
            message: message.into(),
        }
    }

    #[cfg(any(windows, test))]
    fn hello_key_invalidated(message: impl Into<String>) -> Self {
        Self {
            kind: SecureStorageErrorKind::HelloKeyInvalidated,
            message: message.into(),
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn record_invalidated(message: impl Into<String>) -> Self {
        Self {
            kind: SecureStorageErrorKind::RecordInvalidated,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SecureStorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SecureStorageError {}

pub(crate) fn is_secure_storage_cancelled(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SecureStorageError>()
            .is_some_and(|error| error.kind == SecureStorageErrorKind::Cancelled)
    })
}

pub(crate) fn is_secure_storage_invalidated(error: &anyhow::Error) -> bool {
    #[cfg(any(windows, test))]
    {
        return error.chain().any(|cause| {
            cause
                .downcast_ref::<SecureStorageError>()
                .is_some_and(|error| {
                    matches!(
                        error.kind,
                        SecureStorageErrorKind::HelloKeyInvalidated
                            | SecureStorageErrorKind::RecordInvalidated
                    )
                })
        });
    }
    #[cfg(not(any(windows, test)))]
    {
        let _ = error;
        false
    }
}

#[cfg(any(windows, test))]
fn is_hello_key_invalidated(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SecureStorageError>()
            .is_some_and(|error| error.kind == SecureStorageErrorKind::HelloKeyInvalidated)
    })
}

#[cfg(any(windows, test))]
fn is_hello_key_invalidated_status(status: u32) -> bool {
    matches!(status, NTE_BAD_KEY_STATE | NTE_NO_KEY | NTE_BAD_KEYSET)
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelloKeyOpenDisposition {
    UseOpened,
    CreateMissing,
    ReturnError,
}

#[cfg(any(windows, test))]
fn hello_key_open_disposition(status: u32, create_if_missing: bool) -> HelloKeyOpenDisposition {
    if status == 0 {
        HelloKeyOpenDisposition::UseOpened
    } else if matches!(status, NTE_NO_KEY | NTE_BAD_KEYSET) && create_if_missing {
        HelloKeyOpenDisposition::CreateMissing
    } else {
        HelloKeyOpenDisposition::ReturnError
    }
}

#[cfg(any(windows, test))]
fn verify_or_recreate_hello_key<T>(
    verify: impl FnOnce() -> Result<T>,
    recreate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    match verify() {
        Ok(value) => Ok(value),
        Err(verification_error) if is_hello_key_invalidated(&verification_error) => recreate()
            .with_context(|| {
            format!(
                "failed to replace an invalidated Windows Hello key after verification failed: {verification_error:#}"
            )
        }),
        Err(error) => Err(error),
    }
}

#[allow(dead_code)]
pub trait SecureStorageProvider {
    fn set_parent_window_handle(&mut self, _parent_window: Option<usize>) {}

    fn authorize_store_user_presence(&self) -> Result<()> {
        Ok(())
    }
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn contains(&self, key: &str) -> Result<bool>;
    fn store_requires_user_presence(&self) -> bool {
        false
    }
    fn load_requires_user_presence(&self) -> bool {
        false
    }
    fn delete(&self, key: &str) -> Result<()>;
}

pub struct UnsupportedSecureStorageProvider;

impl SecureStorageProvider for UnsupportedSecureStorageProvider {
    fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
        anyhow::bail!("secure storage is not implemented on this host")
    }

    fn load(&self, _key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(None)
    }

    fn contains(&self, _key: &str) -> Result<bool> {
        Ok(false)
    }

    fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }
}

pub(crate) fn default_secure_storage_provider() -> Box<dyn SecureStorageProvider> {
    default_secure_storage_provider_for_extension_id(None)
}

pub(crate) fn default_secure_storage_provider_for_extension_id(
    extension_id: Option<&str>,
) -> Box<dyn SecureStorageProvider> {
    #[cfg(windows)]
    {
        Box::new(WindowsHelloSecureStorageProvider::new(
            quick_unlock_storage_dir(extension_id),
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = extension_id;
        Box::new(UnsupportedSecureStorageProvider)
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn quick_unlock_storage_dir(extension_id: Option<&str>) -> PathBuf {
    extension_id
        .map(|id| extension_state_dir(id).join("quick-unlock"))
        .unwrap_or_else(|| runtime_state_dir().join("quick-unlock"))
}

#[cfg(windows)]
pub(crate) struct WindowsHelloSecureStorageProvider {
    dir: PathBuf,
    parent_window: Option<usize>,
}

#[cfg(windows)]
impl WindowsHelloSecureStorageProvider {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            parent_window: None,
        }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.bin"))
    }

    fn wrapping_key_name(&self) -> Result<Vec<u16>> {
        let sid = current_user_sid()?;
        Ok(wide_null(&quick_unlock_persistent_key_name(
            &sid, &self.dir,
        )))
    }
}

#[cfg(windows)]
impl SecureStorageProvider for WindowsHelloSecureStorageProvider {
    fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
        self.parent_window = parent_window.filter(|handle| *handle != 0);
    }

    fn authorize_store_user_presence(&self) -> Result<()> {
        let key_name = self.wrapping_key_name()?;
        verify_or_recreate_hello_key(
            || {
                with_hello_key(&key_name, true, self.parent_window, |key, created| {
                    verify_hello_key_for_enrollment(key, created)
                })
            },
            || recreate_hello_key(&key_name, self.parent_window),
        )
    }

    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data_key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 12];
        fill_random(&mut data_key[..])?;
        fill_random(&mut nonce)?;

        let cipher = Aes256Gcm::new_from_slice(&data_key[..])
            .map_err(|_| anyhow::anyhow!("failed to initialize quick unlock cipher"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), value)
            .map_err(|_| anyhow::anyhow!("failed to encrypt quick unlock credentials"))?;
        let wrapped_key = with_hello_key(
            &self.wrapping_key_name()?,
            false,
            self.parent_window,
            |key, _created| ncrypt_encrypt_pkcs1(key, &data_key[..]),
        )?;
        let envelope = QuickUnlockEnvelope {
            version: QUICK_UNLOCK_ENVELOPE_VERSION,
            scheme: QUICK_UNLOCK_ENVELOPE_SCHEME.into(),
            wrapped_key: BASE64_STANDARD.encode(wrapped_key),
            nonce: BASE64_STANDARD.encode(nonce),
            ciphertext: BASE64_STANDARD.encode(ciphertext),
        };
        let bytes = serde_json::to_vec(&envelope)
            .context("failed to encode quick unlock credential envelope")?;
        publish_quick_unlock_record(&self.path_for(key), &bytes)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let envelope: QuickUnlockEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
            SecureStorageError::record_invalidated(format!(
                "quick unlock credentials use an unsupported legacy format: {error}"
            ))
        })?;
        if envelope.version != QUICK_UNLOCK_ENVELOPE_VERSION
            || envelope.scheme != QUICK_UNLOCK_ENVELOPE_SCHEME
        {
            return Err(SecureStorageError::record_invalidated(
                "quick unlock credentials use an unsupported envelope",
            )
            .into());
        }
        let wrapped_key = BASE64_STANDARD
            .decode(envelope.wrapped_key)
            .map_err(|error| {
                SecureStorageError::record_invalidated(format!(
                    "failed to decode wrapped quick unlock key: {error}"
                ))
            })?;
        let nonce = BASE64_STANDARD.decode(envelope.nonce).map_err(|error| {
            SecureStorageError::record_invalidated(format!(
                "failed to decode quick unlock nonce: {error}"
            ))
        })?;
        let ciphertext = BASE64_STANDARD
            .decode(envelope.ciphertext)
            .map_err(|error| {
                SecureStorageError::record_invalidated(format!(
                    "failed to decode encrypted quick unlock credentials: {error}"
                ))
            })?;
        if nonce.len() != 12 {
            return Err(SecureStorageError::record_invalidated(
                "quick unlock credential envelope has an invalid nonce",
            )
            .into());
        }

        let data_key = with_hello_key(
            &self.wrapping_key_name()?,
            false,
            self.parent_window,
            |key, _created| {
                require_fresh_hello_gesture(
                    key,
                    "Verify with Windows Hello to unlock this VaultKern vault",
                )?;
                ncrypt_decrypt_pkcs1(key, &wrapped_key)
            },
        )?;
        let cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|_| {
            SecureStorageError::record_invalidated(
                "decrypted quick unlock data key has an invalid length",
            )
        })?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| {
                    SecureStorageError::record_invalidated(
                        "failed to decrypt quick unlock credentials",
                    )
                })?,
        );
        Ok(Some(plaintext))
    }

    fn contains(&self, key: &str) -> Result<bool> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(false);
        }
        Ok(is_quick_unlock_envelope(&fs::read(path)?))
    }

    fn store_requires_user_presence(&self) -> bool {
        true
    }

    fn load_requires_user_presence(&self) -> bool {
        true
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            fs::remove_file(&path)?;
            sync_parent(&path)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn verify_hello_key_for_enrollment(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    created: bool,
) -> Result<()> {
    if created {
        return Ok(());
    }
    let mut challenge = [0u8; 32];
    fill_random(&mut challenge)?;
    let wrapped_challenge = ncrypt_encrypt_pkcs1(key, &challenge)?;
    require_fresh_hello_gesture(
        key,
        "Verify with Windows Hello to enable quick unlock for this VaultKern vault",
    )?;
    let unwrapped = ncrypt_decrypt_pkcs1(key, &wrapped_challenge)?;
    if unwrapped.as_slice() != challenge {
        anyhow::bail!("Windows Hello quick unlock key verification failed");
    }
    Ok(())
}

#[cfg(windows)]
fn fill_random(bytes: &mut [u8]) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            u32::try_from(bytes.len()).context("random buffer is too large")?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        anyhow::bail!(
            "failed to generate quick unlock random bytes: 0x{:08x}",
            status as u32
        );
    }
    Ok(())
}

#[cfg(windows)]
fn with_hello_key<T>(
    key_name: &[u16],
    create_if_missing: bool,
    parent_window: Option<usize>,
    operation: impl FnOnce(
        windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
        bool,
    ) -> Result<T>,
) -> Result<T> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCryptCreatePersistedKey, NCryptFinalizeKey,
        NCryptOpenKey, NCryptOpenStorageProvider,
    };

    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let provider_name = wide_null(quick_unlock_key_storage_provider_name());
    check_ncrypt(
        unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) },
        "failed to open Microsoft Passport key storage provider",
    )?;
    let _provider = NcryptHandle(provider);

    let mut key = 0;
    let mut created = false;
    let open_status = unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0) };
    match hello_key_open_disposition(open_status as u32, create_if_missing) {
        HelloKeyOpenDisposition::UseOpened => {}
        HelloKeyOpenDisposition::CreateMissing => {
            check_ncrypt(
                unsafe {
                    NCryptCreatePersistedKey(
                        provider,
                        &mut key,
                        NCRYPT_RSA_ALGORITHM,
                        key_name.as_ptr(),
                        0,
                        0,
                    )
                },
                "failed to create quick unlock Windows Hello key",
            )?;
            created = true;
        }
        HelloKeyOpenDisposition::ReturnError => {
            check_ncrypt(open_status, "failed to open quick unlock Windows Hello key")?;
        }
    }

    with_owned_ncrypt_handle(key, |key| {
        set_hello_parent_window(key, parent_window)?;
        if created {
            configure_hello_key(key)?;
            check_ncrypt(
                unsafe { NCryptFinalizeKey(key, 0) },
                "failed to finalize quick unlock Windows Hello key",
            )?;
        }

        operation(key, created)
    })
}

#[cfg(windows)]
fn recreate_hello_key(key_name: &[u16], parent_window: Option<usize>) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
        NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptOpenStorageProvider,
    };

    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let provider_name = wide_null(quick_unlock_key_storage_provider_name());
    check_ncrypt(
        unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) },
        "failed to open Microsoft Passport key storage provider",
    )?;
    let _provider = NcryptHandle(provider);

    let mut key = 0;
    check_ncrypt(
        unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                NCRYPT_RSA_ALGORITHM,
                key_name.as_ptr(),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG,
            )
        },
        "failed to replace invalidated quick unlock Windows Hello key",
    )?;
    with_owned_ncrypt_handle(key, |key| {
        set_hello_parent_window(key, parent_window)?;
        configure_hello_key(key)?;
        check_ncrypt(
            unsafe { NCryptFinalizeKey(key, 0) },
            "failed to finalize replacement quick unlock Windows Hello key",
        )
    })
}

#[cfg(windows)]
fn set_hello_parent_window(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    parent_window: Option<usize>,
) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_WINDOW_HANDLE_PROPERTY, NCryptSetProperty,
    };

    let Some(parent_window) = parent_window else {
        return Ok(());
    };
    let window_handle = parent_window as windows_sys::Win32::Foundation::HWND;
    let window_handle_bytes = bytes_of(&window_handle);
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                window_handle_bytes.as_ptr(),
                u32::try_from(window_handle_bytes.len())?,
                0,
            )
        },
        "failed to set the Windows Hello parent window",
    )
}

#[cfg(windows)]
fn configure_hello_key(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCryptSetProperty,
    };

    let length = 2048u32;
    let length_bytes = bytes_of(&length);
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_LENGTH_PROPERTY,
                length_bytes.as_ptr(),
                u32::try_from(length_bytes.len())?,
                0,
            )
        },
        "failed to set quick unlock key length",
    )?;
    let usage = NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG;
    let usage_bytes = bytes_of(&usage);
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_KEY_USAGE_PROPERTY,
                usage_bytes.as_ptr(),
                u32::try_from(usage_bytes.len())?,
                0,
            )
        },
        "failed to set quick unlock key usage",
    )?;

    let cache_type = quick_unlock_ngc_cache_type();
    let cache_type_bytes = bytes_of(&cache_type);
    let primary = wide_null("NgcCacheType");
    let mut status = unsafe {
        NCryptSetProperty(
            key,
            primary.as_ptr(),
            cache_type_bytes.as_ptr(),
            u32::try_from(cache_type_bytes.len())?,
            0,
        )
    };
    if status != 0 {
        let deprecated = wide_null("NgcCacheTypeProperty");
        status = unsafe {
            NCryptSetProperty(
                key,
                deprecated.as_ptr(),
                cache_type_bytes.as_ptr(),
                u32::try_from(cache_type_bytes.len())?,
                0,
            )
        };
    }
    check_ncrypt(status, "failed to require Windows Hello authentication")
}

#[cfg(windows)]
fn require_fresh_hello_gesture(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    context: &str,
) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_USE_CONTEXT_PROPERTY, NCryptSetProperty,
    };

    let gesture_required = quick_unlock_gesture_required();
    let gesture_bytes = bytes_of(&gesture_required);
    let gesture_property = wide_null("PinCacheIsGestureRequired");
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                gesture_property.as_ptr(),
                gesture_bytes.as_ptr(),
                u32::try_from(gesture_bytes.len())?,
                0,
            )
        },
        "failed to require a fresh Windows Hello gesture",
    )?;
    let context = wide_null(context);
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_USE_CONTEXT_PROPERTY,
                context.as_ptr().cast::<u8>(),
                u32::try_from(context.len() * std::mem::size_of::<u16>())?,
                0,
            )
        },
        "failed to set Windows Hello use context",
    )
}

#[cfg(windows)]
fn ncrypt_encrypt_pkcs1(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    value: &[u8],
) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{NCRYPT_PAD_PKCS1_FLAG, NCryptEncrypt};

    let mut output_len = 0u32;
    check_ncrypt(
        unsafe {
            NCryptEncrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("quick unlock key is too large")?,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut output_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        },
        "failed to measure wrapped quick unlock key",
    )?;
    let mut output = vec![0u8; usize::try_from(output_len)?];
    check_ncrypt(
        unsafe {
            NCryptEncrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("quick unlock key is too large")?,
                std::ptr::null_mut(),
                output.as_mut_ptr(),
                output_len,
                &mut output_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        },
        "failed to wrap quick unlock key",
    )?;
    output.truncate(usize::try_from(output_len)?);
    Ok(output)
}

#[cfg(windows)]
fn ncrypt_decrypt_pkcs1(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    value: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use windows_sys::Win32::Security::Cryptography::{NCRYPT_PAD_PKCS1_FLAG, NCryptDecrypt};

    let mut output_len = 0u32;
    check_ncrypt(
        unsafe {
            NCryptDecrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("wrapped quick unlock key is too large")?,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut output_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        },
        "failed to measure unwrapped quick unlock key",
    )?;
    let mut output = Zeroizing::new(vec![0u8; usize::try_from(output_len)?]);
    check_ncrypt(
        unsafe {
            NCryptDecrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("wrapped quick unlock key is too large")?,
                std::ptr::null_mut(),
                output.as_mut_ptr(),
                output_len,
                &mut output_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        },
        "failed to unwrap quick unlock key with Windows Hello",
    )?;
    output.truncate(usize::try_from(output_len)?);
    Ok(output)
}

#[cfg(windows)]
fn current_user_sid() -> Result<String> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        anyhow::bail!("failed to open current process token: {}", unsafe {
            GetLastError()
        });
    }
    let _token = WindowsHandle(token);

    let mut required = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    if required == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        anyhow::bail!("failed to measure current user SID: {}", unsafe {
            GetLastError()
        });
    }
    let word_bytes = std::mem::size_of::<usize>();
    let mut buffer = vec![0usize; usize::try_from(required)?.div_ceil(word_bytes)];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        anyhow::bail!("failed to read current user SID: {}", unsafe {
            GetLastError()
        });
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } == 0 {
        anyhow::bail!("failed to format current user SID: {}", unsafe {
            GetLastError()
        });
    }
    let mut len = 0usize;
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
        }
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, len) })
        .context("current user SID is not valid UTF-16")?;
    unsafe {
        LocalFree(sid_text.cast());
    }
    Ok(sid)
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(any(windows, test))]
struct OwnedResource<H: Copy, C: FnMut(H)> {
    handle: H,
    close: C,
}

#[cfg(any(windows, test))]
impl<H: Copy, C: FnMut(H)> Drop for OwnedResource<H, C> {
    fn drop(&mut self) {
        (self.close)(self.handle);
    }
}

#[cfg(any(windows, test))]
fn with_owned_resource<T, H: Copy, C: FnMut(H)>(
    handle: H,
    close: C,
    operation: impl FnOnce(H) -> Result<T>,
) -> Result<T> {
    let _resource = OwnedResource { handle, close };
    operation(handle)
}

#[cfg(windows)]
fn with_owned_ncrypt_handle<T>(
    handle: windows_sys::Win32::Security::Cryptography::NCRYPT_HANDLE,
    operation: impl FnOnce(windows_sys::Win32::Security::Cryptography::NCRYPT_HANDLE) -> Result<T>,
) -> Result<T> {
    with_owned_resource(
        handle,
        |handle| unsafe {
            windows_sys::Win32::Security::Cryptography::NCryptFreeObject(handle);
        },
        operation,
    )
}

#[cfg(windows)]
struct NcryptHandle(windows_sys::Win32::Security::Cryptography::NCRYPT_HANDLE);

#[cfg(windows)]
impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                windows_sys::Win32::Security::Cryptography::NCryptFreeObject(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn check_ncrypt(status: windows_sys::core::HRESULT, message: &str) -> Result<()> {
    if status == 0 {
        Ok(())
    } else if matches!(status as u32, 0x8009_0036 | 0x8007_04c7) {
        Err(SecureStorageError::cancelled(format!("{message}: 0x{:08x}", status as u32)).into())
    } else if is_hello_key_invalidated_status(status as u32) {
        Err(SecureStorageError::hello_key_invalidated(format!(
            "{message}: 0x{:08x}",
            status as u32
        ))
        .into())
    } else {
        anyhow::bail!("{message}: 0x{:08x}", status as u32)
    }
}

#[cfg(windows)]
fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) struct MemorySecureStorageProvider {
    values: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemorySecureStorageProvider {
    pub(crate) fn new() -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
        }
    }
}

impl SecureStorageProvider for MemorySecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.values
            .borrow_mut()
            .insert(key.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.values.borrow().get(key).cloned())
    }

    fn contains(&self, key: &str) -> Result<bool> {
        Ok(self.values.borrow().contains_key(key))
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.values.borrow_mut().remove(key);
        Ok(())
    }
}

pub(crate) struct FailingContainsSecureStorageProvider {
    values: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl FailingContainsSecureStorageProvider {
    pub(crate) fn new() -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
        }
    }
}

impl SecureStorageProvider for FailingContainsSecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.values
            .borrow_mut()
            .insert(key.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.values.borrow().get(key).cloned())
    }

    fn contains(&self, _key: &str) -> Result<bool> {
        anyhow::bail!("injected secure storage contains failure")
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.values.borrow_mut().remove(key);
        Ok(())
    }
}

pub(crate) struct FailingDeleteSecureStorageProvider {
    values: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl FailingDeleteSecureStorageProvider {
    pub(crate) fn new() -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
        }
    }
}

impl SecureStorageProvider for FailingDeleteSecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.values
            .borrow_mut()
            .insert(key.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.values.borrow().get(key).cloned())
    }

    fn contains(&self, key: &str) -> Result<bool> {
        Ok(self.values.borrow().contains_key(key))
    }

    fn delete(&self, _key: &str) -> Result<()> {
        anyhow::bail!("injected secure storage delete failure")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MemorySecureStorageProvider, SecureStorageError, SecureStorageProvider,
        is_quick_unlock_envelope, is_secure_storage_cancelled, publish_quick_unlock_record,
        publish_quick_unlock_record_with, quick_unlock_gesture_required,
        quick_unlock_key_storage_provider_name, quick_unlock_ngc_cache_type,
        quick_unlock_persistent_key_name, quick_unlock_record_lock_path,
        quick_unlock_replacement_outcome_is_unknown, quick_unlock_storage_dir,
        verify_or_recreate_hello_key, with_owned_resource,
    };
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock,
    };
    use zeroize::Zeroizing;

    #[test]
    fn loaded_secure_storage_bytes_have_zeroizing_ownership() {
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}

        let storage = MemorySecureStorageProvider::new();
        storage.store("vault", b"secret").unwrap();
        let loaded = storage.load("vault").unwrap().unwrap();

        assert_zeroizing(&loaded);
        assert_eq!(loaded.as_slice(), b"secret");
    }
    use crate::state_paths::{extension_state_dir, runtime_state_dir};
    use std::time::Duration;

    #[test]
    fn owned_resource_closes_once_when_setup_fails() {
        let closes = std::cell::Cell::new(0);

        let error = with_owned_resource(
            7usize,
            |_| closes.set(closes.get() + 1),
            |_| -> anyhow::Result<()> { anyhow::bail!("injected setup failure") },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected setup failure"));
        assert_eq!(closes.get(), 1);
    }

    #[test]
    fn hello_reenrollment_recreates_an_invalidated_persisted_key() {
        let recreated = std::cell::Cell::new(false);

        let result = verify_or_recreate_hello_key(
            || {
                Err::<_, anyhow::Error>(
                    SecureStorageError::hello_key_invalidated(
                        "persisted Hello key was invalidated",
                    )
                    .into(),
                )
            },
            || {
                recreated.set(true);
                Ok("replacement key")
            },
        )
        .unwrap();

        assert_eq!(result, "replacement key");
        assert!(recreated.get());
    }

    #[test]
    fn hello_reenrollment_does_not_replace_a_key_after_a_transient_verification_failure() {
        let recreated = std::cell::Cell::new(false);

        let error = verify_or_recreate_hello_key(
            || anyhow::bail!("Microsoft Passport KSP is temporarily unavailable"),
            || {
                recreated.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("temporarily unavailable"));
        assert!(!recreated.get());
    }

    #[test]
    fn hello_reenrollment_does_not_replace_a_key_when_the_user_cancels() {
        let recreated = std::cell::Cell::new(false);

        let error = verify_or_recreate_hello_key(
            || Err::<(), _>(SecureStorageError::cancelled("Windows Hello was cancelled").into()),
            || {
                recreated.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(is_secure_storage_cancelled(&error));
        assert!(!recreated.get());
    }

    #[test]
    fn only_definitive_hello_key_failures_trigger_reenrollment() {
        assert!(super::is_hello_key_invalidated_status(
            super::NTE_BAD_KEY_STATE
        ));
        assert!(super::is_hello_key_invalidated_status(super::NTE_NO_KEY));
        assert!(super::is_hello_key_invalidated_status(
            super::NTE_BAD_KEYSET
        ));
        assert!(!super::is_hello_key_invalidated_status(0x8009_0010));
        assert!(!super::is_hello_key_invalidated_status(0x8009_0030));
    }

    #[test]
    fn hello_key_creation_only_follows_a_definitive_missing_key_status() {
        use super::HelloKeyOpenDisposition::{CreateMissing, ReturnError, UseOpened};

        assert_eq!(super::hello_key_open_disposition(0, true), UseOpened);
        assert_eq!(
            super::hello_key_open_disposition(super::NTE_NO_KEY, true),
            CreateMissing
        );
        assert_eq!(
            super::hello_key_open_disposition(super::NTE_BAD_KEYSET, true),
            CreateMissing
        );
        assert_eq!(
            super::hello_key_open_disposition(super::NTE_BAD_KEY_STATE, true),
            ReturnError
        );
        assert_eq!(
            super::hello_key_open_disposition(0x8009_0030, true),
            ReturnError
        );
        assert_eq!(
            super::hello_key_open_disposition(super::NTE_NO_KEY, false),
            ReturnError
        );
        assert_eq!(
            super::hello_key_open_disposition(super::NTE_BAD_KEYSET, false),
            ReturnError
        );
    }

    #[test]
    fn quick_unlock_record_publication_creates_and_atomically_replaces_complete_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");

        publish_quick_unlock_record(&record, b"first complete envelope").unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"first complete envelope");

        publish_quick_unlock_record(&record, b"second complete envelope").unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"second complete envelope");
    }

    #[test]
    fn quick_unlock_record_pre_publish_faults_preserve_the_complete_old_record() {
        let points = [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempWritten,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::TempReadbackVerified,
            DurableFaultPoint::BeforeTempPublishValidation,
            DurableFaultPoint::BeforeTargetReplace,
        ];

        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let record = dir.path().join("record.bin");
            std::fs::write(&record, b"complete old envelope").unwrap();

            let result = publish_quick_unlock_record_with(
                &record,
                b"complete new envelope",
                &DurableFaultInjector::fail_once(point),
                Duration::from_secs(1),
            );

            assert!(result.is_err(), "{point:?} unexpectedly succeeded");
            assert_eq!(
                std::fs::read(&record).unwrap(),
                b"complete old envelope",
                "{point:?} changed the record before publish"
            );

            let missing_record = dir.path().join("missing-record.bin");
            assert!(
                publish_quick_unlock_record_with(
                    &missing_record,
                    b"complete new envelope",
                    &DurableFaultInjector::fail_once(point),
                    Duration::from_secs(1),
                )
                .is_err(),
                "{point:?} unexpectedly published a new record"
            );
            assert!(
                !missing_record.exists(),
                "{point:?} exposed a partial first record"
            );
        }
    }

    #[test]
    fn quick_unlock_record_post_publish_faults_report_new_record_as_visible() {
        let points = [
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
            DurableFaultPoint::Cleanup,
        ];

        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let record = dir.path().join("record.bin");
            std::fs::write(&record, b"complete old envelope").unwrap();

            let error = publish_quick_unlock_record_with(
                &record,
                b"complete new envelope",
                &DurableFaultInjector::fail_once(point),
                Duration::from_secs(1),
            )
            .unwrap_err();

            assert!(
                format!("{error:#}").contains("was published"),
                "{point:?} did not report the published state: {error:#}"
            );
            assert_eq!(
                std::fs::read(&record).unwrap(),
                b"complete new envelope",
                "{point:?} did not leave the complete published record"
            );
        }
    }

    #[test]
    fn quick_unlock_record_lock_contention_times_out_and_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");
        let lock_path = quick_unlock_record_lock_path(&record).unwrap();
        let held = ExclusiveFileLock::acquire(&lock_path).unwrap();
        let started = std::time::Instant::now();

        let error = publish_quick_unlock_record_with(
            &record,
            b"complete envelope",
            &DurableFaultInjector::default(),
            Duration::from_millis(40),
        )
        .unwrap_err();

        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(!record.exists());

        drop(held);
        publish_quick_unlock_record(&record, b"complete envelope").unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"complete envelope");
    }

    #[test]
    fn quick_unlock_record_rejects_target_identity_replacement_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");
        let intruding_record = dir.path().join("intruding-record.bin");
        std::fs::write(&record, b"complete old envelope").unwrap();
        std::fs::write(&intruding_record, b"intruding complete envelope").unwrap();
        let replaced_record = record.clone();
        let faults =
            DurableFaultInjector::run_once(DurableFaultPoint::BeforeTargetReplace, move || {
                #[cfg(windows)]
                std::fs::remove_file(&replaced_record).unwrap();
                std::fs::rename(&intruding_record, &replaced_record).unwrap();
            });

        let error = publish_quick_unlock_record_with(
            &record,
            b"complete new envelope",
            &faults,
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("target changed"));
        assert_eq!(
            std::fs::read(&record).unwrap(),
            b"intruding complete envelope"
        );
    }

    #[test]
    fn quick_unlock_record_preserves_recovery_sidecars_until_a_publish_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");
        let recovery_temp = dir.path().join(".record.bin.vaultkern.tmp.recovery");
        let recovery_backup = dir.path().join(".record.bin.vaultkern.bak.recovery");
        std::fs::write(&recovery_temp, b"complete pending envelope").unwrap();
        std::fs::write(&recovery_backup, b"complete previous envelope").unwrap();

        let error = publish_quick_unlock_record_with(
            &record,
            b"complete retry envelope",
            &DurableFaultInjector::fail_once(DurableFaultPoint::BeforeTargetReplace),
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("was not published"));
        assert!(!record.exists());
        assert_eq!(
            std::fs::read(&recovery_temp).unwrap(),
            b"complete pending envelope"
        );
        assert_eq!(
            std::fs::read(&recovery_backup).unwrap(),
            b"complete previous envelope"
        );

        publish_quick_unlock_record(&record, b"complete retry envelope").unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"complete retry envelope");
        assert!(!recovery_temp.exists());
        assert!(!recovery_backup.exists());
    }

    #[test]
    fn windows_error_1177_is_classified_as_outcome_unknown() {
        assert!(quick_unlock_replacement_outcome_is_unknown(
            &std::io::Error::from_raw_os_error(1177)
        ));
        assert!(!quick_unlock_replacement_outcome_is_unknown(
            &std::io::Error::from_raw_os_error(1176)
        ));
        assert!(!quick_unlock_replacement_outcome_is_unknown(
            &std::io::Error::other("post-publish cleanup failed")
        ));
    }

    #[test]
    fn quick_unlock_record_never_publishes_through_a_rebound_parent() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("records");
        let displaced_parent = dir.path().join("displaced-records");
        std::fs::create_dir(&parent).unwrap();
        let record = parent.join("record.bin");
        std::fs::write(&record, b"complete old envelope").unwrap();

        let callback_parent = parent.clone();
        let callback_displaced_parent = displaced_parent.clone();
        let parent_rebound = Arc::new(AtomicBool::new(false));
        let callback_parent_rebound = Arc::clone(&parent_rebound);
        let faults =
            DurableFaultInjector::run_once(DurableFaultPoint::BeforeTargetReplace, move || {
                if std::fs::rename(&callback_parent, &callback_displaced_parent).is_err() {
                    return;
                }
                callback_parent_rebound.store(true, Ordering::Release);
                std::fs::create_dir(&callback_parent).unwrap();
                let _ = std::fs::rename(
                    callback_displaced_parent.join("record.bin"),
                    callback_parent.join("record.bin"),
                );
                let temp_name = std::fs::read_dir(&callback_displaced_parent)
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .find(|name| {
                        name.to_string_lossy()
                            .starts_with(".record.bin.vaultkern.tmp.")
                    });
                if let Some(temp_name) = temp_name {
                    let _ = std::fs::rename(
                        callback_displaced_parent.join(&temp_name),
                        callback_parent.join(temp_name),
                    );
                }
            });

        let result = publish_quick_unlock_record_with(
            &record,
            b"complete new envelope",
            &faults,
            Duration::from_secs(1),
        );

        if parent_rebound.load(Ordering::Acquire) {
            let error = result.expect_err("publication followed the rebound parent");
            assert!(format!("{error:#}").contains("parent directory changed"));
            assert_ne!(
                std::fs::read(&record).ok().as_deref(),
                Some(b"complete new envelope".as_slice())
            );
        } else {
            result.unwrap();
            assert_eq!(std::fs::read(&record).unwrap(), b"complete new envelope");
            assert!(!displaced_parent.exists());
        }
    }

    #[test]
    fn quick_unlock_record_publication_cleans_stale_temp_and_backup_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");
        let stale_temp = dir.path().join(".record.bin.vaultkern.tmp.stale");
        let stale_backup = dir.path().join(".record.bin.vaultkern.bak.stale");
        std::fs::write(&stale_temp, b"partial abandoned envelope").unwrap();
        std::fs::write(&stale_backup, b"old abandoned envelope").unwrap();

        publish_quick_unlock_record(&record, b"complete envelope").unwrap();

        assert_eq!(std::fs::read(&record).unwrap(), b"complete envelope");
        assert!(!stale_temp.exists());
        assert!(!stale_backup.exists());
    }

    #[test]
    fn quick_unlock_record_concurrent_readers_only_observe_complete_generations() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("record.bin");
        let first = vec![b'a'; 256 * 1024];
        let second = vec![b'b'; 256 * 1024];
        publish_quick_unlock_record(&record, &first).unwrap();

        let keep_reading = Arc::new(AtomicBool::new(true));
        let reader_flag = Arc::clone(&keep_reading);
        let reader_record = record.clone();
        let reader_first = first.clone();
        let reader_second = second.clone();
        let reader = std::thread::spawn(move || {
            let mut successful_reads = 0usize;
            while reader_flag.load(Ordering::Acquire) {
                match std::fs::read(&reader_record) {
                    Ok(bytes) => {
                        assert!(bytes == reader_first || bytes == reader_second);
                        successful_reads += 1;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
                        ) || (cfg!(windows)
                            && (error.kind() == std::io::ErrorKind::NotFound
                                || error.raw_os_error() == Some(32))) =>
                    {
                        // ReplaceFileW can briefly make a concurrent path open miss or
                        // return ERROR_SHARING_VIOLATION;
                        // every successful read must still be a complete generation.
                    }
                    Err(error) => panic!("concurrent quick unlock read failed: {error}"),
                }
            }
            successful_reads
        });

        for _ in 0..4 {
            publish_quick_unlock_record(&record, &second).unwrap();
            publish_quick_unlock_record(&record, &first).unwrap();
        }
        publish_quick_unlock_record(&record, &second).unwrap();
        keep_reading.store(false, Ordering::Release);

        assert!(reader.join().unwrap() > 0);
        assert_eq!(std::fs::read(&record).unwrap(), second);
    }

    #[test]
    fn subprocess_crash_at_each_record_boundary_leaves_only_old_or_new_bytes() {
        use std::process::{Command, Stdio};

        let points = [
            DurableFaultPoint::TempCreated,
            DurableFaultPoint::TempWritten,
            DurableFaultPoint::TempSynced,
            DurableFaultPoint::TempReadbackVerified,
            DurableFaultPoint::BeforeTempPublishValidation,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
            DurableFaultPoint::Cleanup,
        ];
        for point in points {
            let dir = tempfile::tempdir().unwrap();
            let record = dir.path().join("record.bin");
            std::fs::write(&record, b"complete old envelope").unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::secure_storage::tests::subprocess_quick_unlock_record_crash_child",
                    "--ignored",
                ])
                .env("VAULTKERN_QUICK_UNLOCK_CRASH_PATH", &record)
                .env("VAULTKERN_DURABLE_CRASH_POINT", format!("{point:?}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(!status.success(), "{point:?} did not stop the child");

            let visible = std::fs::read(&record).unwrap();
            assert!(
                visible == b"complete old envelope" || visible == b"complete new envelope",
                "{point:?} exposed partial record bytes"
            );
            if matches!(
                point,
                DurableFaultPoint::TempCreated
                    | DurableFaultPoint::TempWritten
                    | DurableFaultPoint::TempSynced
                    | DurableFaultPoint::TempReadbackVerified
                    | DurableFaultPoint::BeforeTempPublishValidation
                    | DurableFaultPoint::BeforeTargetReplace
            ) {
                assert_eq!(visible, b"complete old envelope", "{point:?}");
            } else {
                assert_eq!(visible, b"complete new envelope", "{point:?}");
            }

            publish_quick_unlock_record(&record, &visible).unwrap();
            let sidecars = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| {
                    name.starts_with(".record.bin.vaultkern.tmp.")
                        || name.starts_with(".record.bin.vaultkern.bak.")
                })
                .collect::<Vec<_>>();
            assert!(sidecars.is_empty(), "stale sidecars remained: {sidecars:?}");
        }
    }

    #[test]
    #[ignore]
    fn subprocess_quick_unlock_record_crash_child() {
        let Ok(path) = std::env::var("VAULTKERN_QUICK_UNLOCK_CRASH_PATH") else {
            return;
        };
        let point = DurableFaultPoint::from_test_name(
            &std::env::var("VAULTKERN_DURABLE_CRASH_POINT").unwrap(),
        )
        .unwrap();
        let _ = publish_quick_unlock_record_with(
            std::path::Path::new(&path),
            b"complete new envelope",
            &DurableFaultInjector::crash_once(point),
            Duration::from_secs(1),
        );
        panic!("crash point was not reached: {point:?}");
    }

    #[cfg(unix)]
    #[test]
    fn quick_unlock_record_rejects_symlink_target_and_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.bin");
        std::fs::write(&outside, b"outside complete envelope").unwrap();
        let linked_record = dir.path().join("linked-record.bin");
        symlink(&outside, &linked_record).unwrap();

        assert!(publish_quick_unlock_record(&linked_record, b"new").is_err());
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"outside complete envelope"
        );

        let real_parent = dir.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = dir.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(publish_quick_unlock_record(&linked_parent.join("record.bin"), b"new").is_err());
        assert!(!real_parent.join("record.bin").exists());
    }

    #[cfg(windows)]
    #[test]
    fn quick_unlock_record_rejects_reparse_target_and_parent() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.bin");
        std::fs::write(&outside, b"outside complete envelope").unwrap();
        let linked_record = dir.path().join("linked-record.bin");
        symlink_file(&outside, &linked_record).unwrap();
        assert!(publish_quick_unlock_record(&linked_record, b"new").is_err());
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"outside complete envelope"
        );

        let real_parent = dir.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = dir.path().join("linked-parent");
        symlink_dir(&real_parent, &linked_parent).unwrap();
        assert!(publish_quick_unlock_record(&linked_parent.join("record.bin"), b"new").is_err());
        assert!(!real_parent.join("record.bin").exists());
    }

    #[test]
    fn quick_unlock_storage_dir_is_scoped_by_extension_id() {
        assert_eq!(
            quick_unlock_storage_dir(Some("kblgblkjghklighdgmejjfondchkjcgf")),
            extension_state_dir("kblgblkjghklighdgmejjfondchkjcgf").join("quick-unlock")
        );
        assert_eq!(
            quick_unlock_storage_dir(None),
            runtime_state_dir().join("quick-unlock")
        );
    }

    #[test]
    fn quick_unlock_presence_marker_rejects_legacy_dpapi_blobs() {
        assert!(!is_quick_unlock_envelope(b"legacy-dpapi-ciphertext"));
        assert!(is_quick_unlock_envelope(
            br#"{"version":3,"scheme":"windows-passport-rsa-pkcs1-aes-256-gcm-hello-v3","wrapped_key":"","nonce":"","ciphertext":""}"#
        ));
        assert!(!is_quick_unlock_envelope(
            br#"{"version":1,"scheme":"windows-cng-rsa-oaep-sha256-aes-256-gcm","wrapped_key":"","nonce":"","ciphertext":""}"#
        ));
    }

    #[test]
    fn quick_unlock_uses_passport_ksp_and_sid_scoped_key_name() {
        assert_eq!(
            quick_unlock_key_storage_provider_name(),
            "Microsoft Passport Key Storage Provider"
        );
        let name = quick_unlock_persistent_key_name(
            "S-1-5-21-111-222-333-1001",
            std::path::Path::new(r"C:\Users\test\VaultKern\quick-unlock"),
        );
        let prefix = "S-1-5-21-111-222-333-1001//VaultKern/QuickUnlock/";
        assert!(name.starts_with(prefix));
        assert_eq!(name.len(), prefix.len() + 64);
    }

    #[test]
    fn quick_unlock_requires_auth_mandatory_and_a_fresh_gesture() {
        assert_eq!(quick_unlock_ngc_cache_type(), 1);
        assert_eq!(quick_unlock_gesture_required(), 1);
    }
}
