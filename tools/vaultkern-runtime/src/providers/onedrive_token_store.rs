use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

#[cfg(any(windows, test))]
use anyhow::Context;
use anyhow::Result;
use zeroize::Zeroizing;

use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[cfg(any(windows, test))]
use crate::providers::durable_file::VerifiedTemp;
#[cfg(windows)]
use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, TargetExpectation, TempWriteFaultPoints,
    create_dir_all_durable, opened_file_identity, path_file_identity, publish_temp,
    remove_if_exists, sync_parent, write_verified_temp,
};

const TOKEN_FILE_NAME: &str = "onedrive-refresh-token.dpapi";
#[cfg(any(windows, test))]
const MAX_PROTECTED_REFRESH_TOKEN_BYTES: usize = 64 * 1024;

pub(crate) trait OneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn store(&self, token: &str) -> Result<OneDriveRefreshTokenStoreOutcome>;
    #[allow(dead_code)]
    fn delete(&self) -> Result<()>;
}

#[derive(Debug)]
pub(crate) enum OneDriveRefreshTokenStoreOutcome {
    Durable,
    #[allow(dead_code)]
    PublishedDurabilityUnknown(anyhow::Error),
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
    production_store(
        extension_state_dir(extension_id).join(TOKEN_FILE_NAME),
        &format!("vaultkern-runtime/extension/{extension_id}"),
    )
}

fn production_store(path: PathBuf, scope: &str) -> Box<dyn OneDriveRefreshTokenStore> {
    remove_legacy_plaintext_token(&path);
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

fn remove_legacy_plaintext_token(protected_path: &std::path::Path) {
    if let Some(parent) = protected_path.parent() {
        let _ = fs::remove_file(parent.join("onedrive-refresh-token"));
    }
}

pub(crate) struct EphemeralOneDriveRefreshTokenStore {
    token: RefCell<Option<Zeroizing<String>>>,
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

    fn store(&self, token: &str) -> Result<OneDriveRefreshTokenStoreOutcome> {
        self.token.replace(Some(Zeroizing::new(token.to_owned())));
        Ok(OneDriveRefreshTokenStoreOutcome::Durable)
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

    fn store(&self, _token: &str) -> Result<OneDriveRefreshTokenStoreOutcome> {
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
        if self.path.exists() {
            if let Some(parent) = self.path.parent() {
                enforce_private_acl(parent, true)?;
            }
            enforce_private_acl(&self.path, false)?;
        }
        let Some(ciphertext) = read_regular_file(&self.path)? else {
            return Ok(None);
        };
        unprotect_refresh_token(&ciphertext, &self.entropy)
            .context("failed to unprotect persisted OneDrive refresh token")
            .map(Some)
    }

    fn store(&self, token: &str) -> Result<OneDriveRefreshTokenStoreOutcome> {
        let parent = self
            .path
            .parent()
            .context("OneDrive refresh-token path has no parent directory")?;
        create_dir_all_durable(parent).with_context(|| {
            format!(
                "failed to create private OneDrive refresh-token directory: {}",
                parent.display()
            )
        })?;
        enforce_private_acl(parent, true)?;
        if self.path.exists() {
            enforce_private_acl(&self.path, false)?;
        }
        let protected = protect_refresh_token(token, &self.entropy)
            .context("failed to protect OneDrive refresh token")?;
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
        let publish_result = publish_temp(
            temp,
            &self.path,
            expectation,
            None,
            &self.faults,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        );
        if let Err(error) = publish_result {
            let published = error.published;
            let error = anyhow::Error::new(error.source).context(format!(
                "failed to publish protected OneDrive refresh token: {}",
                self.path.display()
            ));
            if published {
                return Ok(OneDriveRefreshTokenStoreOutcome::PublishedDurabilityUnknown(error));
            }
            return Err(error);
        }
        match enforce_private_acl(&self.path, false) {
            Ok(()) => Ok(OneDriveRefreshTokenStoreOutcome::Durable),
            Err(error) => Ok(
                OneDriveRefreshTokenStoreOutcome::PublishedDurabilityUnknown(error.context(
                    "protected OneDrive refresh token was published but final ACL verification failed",
                )),
            ),
        }
    }

    fn delete(&self) -> Result<()> {
        let existed = self.path.exists();
        remove_if_exists(&self.path).with_context(|| {
            format!(
                "failed to delete protected OneDrive refresh token: {}",
                self.path.display()
            )
        })?;
        if existed {
            sync_parent(&self.path).with_context(|| {
                format!(
                    "failed to sync OneDrive refresh-token directory: {}",
                    self.path.display()
                )
            })?;
        }
        Ok(())
    }
}

#[cfg(windows)]
const PRIVATE_DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
#[cfg(windows)]
const PRIVATE_FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

#[cfg(windows)]
fn enforce_private_acl(path: &std::path::Path, directory: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
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

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let expected_sddl = if directory {
        PRIVATE_DIRECTORY_SDDL
    } else {
        PRIVATE_FILE_SDDL
    };
    let sddl_wide = expected_sddl
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
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
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetFileSecurityW};

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

    let mut sddl = std::ptr::null_mut();
    let mut sddl_len = 0_u32;
    let result = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_mut_ptr().cast(),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            &mut sddl_len,
        )
    };
    let sddl = LocalPointer(sddl.cast());
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect private OneDrive refresh-token ACL");
    }
    let mut actual_units =
        unsafe { std::slice::from_raw_parts(sddl.0.cast::<u16>(), sddl_len as usize) };
    if actual_units.last() == Some(&0) {
        actual_units = &actual_units[..actual_units.len() - 1];
    }
    let actual = String::from_utf16(actual_units)
        .context("OneDrive refresh-token ACL uses invalid UTF-16")?;
    let expected = if directory {
        PRIVATE_DIRECTORY_SDDL
    } else {
        PRIVATE_FILE_SDDL
    };
    if actual != expected {
        anyhow::bail!(
            "OneDrive refresh-token ACL is not private: {}",
            path.display()
        );
    }
    Ok(())
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

#[cfg(any(windows, test))]
fn read_bounded_protected_payload(
    reader: &mut impl std::io::Read,
    declared_len: u64,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    if declared_len > MAX_PROTECTED_REFRESH_TOKEN_BYTES as u64 {
        anyhow::bail!("protected OneDrive refresh-token payload is too large");
    }
    let mut bytes = Vec::new();
    std::io::Read::take(reader, (MAX_PROTECTED_REFRESH_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROTECTED_REFRESH_TOKEN_BYTES {
        anyhow::bail!("protected OneDrive refresh-token payload is too large");
    }
    Ok(bytes)
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
                std::ptr::write_bytes(self.blob.pbData, 0, self.blob.cbData as usize);
            }
            windows_sys::Win32::Foundation::LocalFree(self.blob.pbData.cast());
        }
    }
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

    fn store(&self, token: &str) -> Result<OneDriveRefreshTokenStoreOutcome> {
        *self.token.lock().expect("memory token store lock") =
            Some(Zeroizing::new(token.to_owned()));
        Ok(OneDriveRefreshTokenStoreOutcome::Durable)
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
        MAX_PROTECTED_REFRESH_TOKEN_BYTES, enforce_temp_metadata_or_discard, production_store,
        read_bounded_protected_payload,
    };
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
    fn windows_store_preserves_published_token_when_durability_is_unknown() {
        use super::{OneDriveRefreshTokenStoreOutcome, WindowsOneDriveRefreshTokenStore};

        const TOKEN: &str = "fixture-refresh-token-published-before-failure";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new_with_faults(
            path,
            "test/default",
            DurableFaultInjector::fail_once(DurableFaultPoint::TargetReplaced),
        );

        let outcome = store.store(TOKEN).unwrap();

        let OneDriveRefreshTokenStoreOutcome::PublishedDurabilityUnknown(error) = outcome else {
            panic!("post-publish failure must report unknown durability")
        };
        assert!(format!("{error:#}").contains("TargetReplaced"));
        assert_eq!(
            store.load().unwrap().as_deref().map(String::as_str),
            Some(TOKEN)
        );
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
}
