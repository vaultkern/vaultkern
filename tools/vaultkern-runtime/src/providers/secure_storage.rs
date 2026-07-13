#[cfg(any(windows, test))]
use anyhow::Context;
use anyhow::Result;
use std::cell::RefCell;
use std::collections::BTreeMap;
#[cfg(any(windows, test))]
use std::fs;
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
#[cfg(windows)]
use sha2::{Digest, Sha256};

use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[cfg(any(windows, test))]
use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock, TargetExpectation,
    TempWriteFaultPoints, create_dir_all_durable, path_file_identity, publish_temp,
    remove_if_exists, sync_parent, unique_sibling_path, write_verified_temp,
};

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_ENVELOPE_VERSION: u8 = 2;
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_ENVELOPE_SCHEME: &str =
    "windows-cng-rsa-oaep-sha256-aes-256-gcm-windows-hello-v2";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_KEY_STORAGE_PROVIDER: &str = "Microsoft Platform Crypto Provider";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const QUICK_UNLOCK_KEY_UI_POLICY_FLAG: u32 = 4;
#[cfg(any(windows, test))]
const QUICK_UNLOCK_RECORD_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

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
fn quick_unlock_key_ui_policy_flag() -> u32 {
    QUICK_UNLOCK_KEY_UI_POLICY_FLAG
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

    let lock_path = quick_unlock_record_lock_path(path)?;
    let _lock =
        ExclusiveFileLock::acquire_with_timeout(&lock_path, lock_timeout).with_context(|| {
            format!(
                "failed to acquire quick unlock record lock: {}",
                lock_path.display()
            )
        })?;
    let expectation = quick_unlock_target_expectation(path)?;
    cleanup_quick_unlock_sidecars(path)?;
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
        if !error.published
            && let Some(backup) = backup.as_deref()
        {
            let _ = remove_if_exists(backup);
        }
        let state = if error.published {
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

    faults.check(DurableFaultPoint::Cleanup).with_context(|| {
        format!(
            "quick unlock record was published, but cleanup was not confirmed: {}",
            path.display()
        )
    })?;
    if let Some(backup) = backup {
        remove_if_exists(&backup).with_context(|| {
            format!(
                "quick unlock record was published, but backup cleanup was not confirmed: {}",
                backup.display()
            )
        })?;
        sync_parent(path).with_context(|| {
            format!(
                "quick unlock record was published, but cleanup durability was not confirmed: {}",
                path.display()
            )
        })?;
    }
    Ok(())
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

#[allow(dead_code)]
pub trait SecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn contains(&self, key: &str) -> Result<bool>;
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

    fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
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
}

#[cfg(windows)]
impl WindowsHelloSecureStorageProvider {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.bin"))
    }

    fn wrapping_key_name(&self) -> Vec<u16> {
        let mut hasher = Sha256::new();
        hasher.update(self.dir.to_string_lossy().as_bytes());
        let digest = hasher.finalize();
        let suffix = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        wide_null(&format!("VaultKern Quick Unlock Hello v2 {suffix}"))
    }
}

#[cfg(windows)]
impl SecureStorageProvider for WindowsHelloSecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data_key = [0u8; 32];
        let mut nonce = [0u8; 12];
        fill_random(&mut data_key)?;
        fill_random(&mut nonce)?;

        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| anyhow::anyhow!("failed to initialize quick unlock cipher"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), value)
            .map_err(|_| anyhow::anyhow!("failed to encrypt quick unlock credentials"))?;
        let wrapped_key = with_hello_key(&self.wrapping_key_name(), true, |key| {
            ncrypt_encrypt_oaep_sha256(key, &data_key)
        })?;
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

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let envelope: QuickUnlockEnvelope = serde_json::from_slice(&bytes)
            .context("quick unlock credentials use an unsupported legacy format")?;
        if envelope.version != QUICK_UNLOCK_ENVELOPE_VERSION
            || envelope.scheme != QUICK_UNLOCK_ENVELOPE_SCHEME
        {
            anyhow::bail!("quick unlock credentials use an unsupported envelope");
        }
        let wrapped_key = BASE64_STANDARD
            .decode(envelope.wrapped_key)
            .context("failed to decode wrapped quick unlock key")?;
        let nonce = BASE64_STANDARD
            .decode(envelope.nonce)
            .context("failed to decode quick unlock nonce")?;
        let ciphertext = BASE64_STANDARD
            .decode(envelope.ciphertext)
            .context("failed to decode encrypted quick unlock credentials")?;
        if nonce.len() != 12 {
            anyhow::bail!("quick unlock credential envelope has an invalid nonce");
        }

        let data_key = with_hello_key(&self.wrapping_key_name(), false, |key| {
            ncrypt_decrypt_oaep_sha256(key, &wrapped_key)
        })?;
        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| anyhow::anyhow!("failed to initialize quick unlock cipher"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("failed to decrypt quick unlock credentials"))?;
        Ok(Some(plaintext))
    }

    fn contains(&self, key: &str) -> Result<bool> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(false);
        }
        Ok(is_quick_unlock_envelope(&fs::read(path)?))
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
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
    operation: impl FnOnce(windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE) -> Result<T>,
) -> Result<T> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
        NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptOpenKey, NCryptOpenStorageProvider,
    };

    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let provider_name = wide_null(quick_unlock_key_storage_provider_name());
    check_ncrypt(
        unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) },
        "failed to open TPM platform key storage provider",
    )?;
    let _provider = NcryptHandle(provider);

    let mut key = 0;
    let open_status = unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0) };
    if open_status != 0 {
        if !create_if_missing {
            check_ncrypt(open_status, "failed to open quick unlock Windows Hello key")?;
        }
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
            "failed to create quick unlock Windows Hello key",
        )?;
        configure_hello_key(key)?;
        check_ncrypt(
            unsafe { NCryptFinalizeKey(key, 0) },
            "failed to finalize quick unlock Windows Hello key",
        )?;
    }
    let _key = NcryptHandle(key);

    operation(key)
}

#[cfg(windows)]
fn configure_hello_key(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY,
        NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY, NCryptSetProperty,
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
    let usage = NCRYPT_ALLOW_DECRYPT_FLAG;
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

    let title = wide_null("VaultKern Quick Unlock");
    let friendly_name = wide_null("VaultKern Quick Unlock");
    let description = wide_null("Protect saved vault credentials with Windows Hello");
    let policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: quick_unlock_key_ui_policy_flag(),
        pszCreationTitle: title.as_ptr(),
        pszFriendlyName: friendly_name.as_ptr(),
        pszDescription: description.as_ptr(),
    };
    let policy_bytes = bytes_of(&policy);
    check_ncrypt(
        unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_UI_POLICY_PROPERTY,
                policy_bytes.as_ptr(),
                u32::try_from(policy_bytes.len())?,
                0,
            )
        },
        "failed to set quick unlock Windows Hello policy",
    )
}

#[cfg(windows)]
fn ncrypt_encrypt_oaep_sha256(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    value: &[u8],
) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, NCRYPT_PAD_OAEP_FLAG, NCryptEncrypt,
    };

    let mut padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let mut output_len = 0u32;
    check_ncrypt(
        unsafe {
            NCryptEncrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("quick unlock key is too large")?,
                (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
                std::ptr::null_mut(),
                0,
                &mut output_len,
                NCRYPT_PAD_OAEP_FLAG,
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
                (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
                output.as_mut_ptr(),
                output_len,
                &mut output_len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        },
        "failed to wrap quick unlock key",
    )?;
    output.truncate(usize::try_from(output_len)?);
    Ok(output)
}

#[cfg(windows)]
fn ncrypt_decrypt_oaep_sha256(
    key: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE,
    value: &[u8],
) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, NCRYPT_PAD_OAEP_FLAG, NCryptDecrypt,
    };

    let mut padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let mut output_len = 0u32;
    check_ncrypt(
        unsafe {
            NCryptDecrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("wrapped quick unlock key is too large")?,
                (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
                std::ptr::null_mut(),
                0,
                &mut output_len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        },
        "failed to measure unwrapped quick unlock key",
    )?;
    let mut output = vec![0u8; usize::try_from(output_len)?];
    check_ncrypt(
        unsafe {
            NCryptDecrypt(
                key,
                value.as_ptr(),
                u32::try_from(value.len()).context("wrapped quick unlock key is too large")?,
                (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
                output.as_mut_ptr(),
                output_len,
                &mut output_len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        },
        "failed to unwrap quick unlock key with Windows Hello",
    )?;
    output.truncate(usize::try_from(output_len)?);
    Ok(output)
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
    values: RefCell<BTreeMap<String, Vec<u8>>>,
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
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
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

pub(crate) struct FailingStoreSecureStorageProvider {
    values: RefCell<BTreeMap<String, Vec<u8>>>,
    stores_before_failure: RefCell<usize>,
}

impl FailingStoreSecureStorageProvider {
    pub(crate) fn new(stores_before_failure: usize) -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
            stores_before_failure: RefCell::new(stores_before_failure),
        }
    }
}

impl SecureStorageProvider for FailingStoreSecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut stores_before_failure = self.stores_before_failure.borrow_mut();
        if *stores_before_failure == 0 {
            anyhow::bail!("injected secure storage store failure");
        }

        *stores_before_failure -= 1;
        self.values
            .borrow_mut()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
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
    values: RefCell<BTreeMap<String, Vec<u8>>>,
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
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
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
    values: RefCell<BTreeMap<String, Vec<u8>>>,
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
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
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
        is_quick_unlock_envelope, publish_quick_unlock_record, publish_quick_unlock_record_with,
        quick_unlock_key_storage_provider_name, quick_unlock_key_ui_policy_flag,
        quick_unlock_record_lock_path, quick_unlock_storage_dir,
    };
    use crate::providers::durable_file::{
        DurableFaultInjector, DurableFaultPoint, ExclusiveFileLock,
    };
    use crate::state_paths::{extension_state_dir, runtime_state_dir};
    use std::time::Duration;

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
                        ) => {}
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
            br#"{"version":2,"scheme":"windows-cng-rsa-oaep-sha256-aes-256-gcm-windows-hello-v2","wrapped_key":"","nonce":"","ciphertext":""}"#
        ));
        assert!(!is_quick_unlock_envelope(
            br#"{"version":1,"scheme":"windows-cng-rsa-oaep-sha256-aes-256-gcm","wrapped_key":"","nonce":"","ciphertext":""}"#
        ));
    }

    #[test]
    fn quick_unlock_uses_tpm_platform_key_storage_provider() {
        assert_eq!(
            quick_unlock_key_storage_provider_name(),
            "Microsoft Platform Crypto Provider"
        );
    }

    #[test]
    fn quick_unlock_key_policy_does_not_request_a_second_key_password() {
        const NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG: u32 = 2;
        const NCRYPT_UI_FINGERPRINT_PROTECTION_FLAG: u32 = 4;

        assert_eq!(
            quick_unlock_key_ui_policy_flag(),
            NCRYPT_UI_FINGERPRINT_PROTECTION_FLAG
        );
        assert_ne!(
            quick_unlock_key_ui_policy_flag(),
            NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG
        );
    }
}
