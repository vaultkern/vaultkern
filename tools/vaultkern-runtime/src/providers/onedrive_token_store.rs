use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[cfg(windows)]
use crate::providers::durable_file::{
    DurableFaultInjector, DurableFaultPoint, TargetExpectation, TempWriteFaultPoints,
    create_dir_all_durable, opened_file_identity, path_file_identity, publish_temp,
    remove_if_exists, sync_parent, write_verified_temp,
};

const TOKEN_FILE_NAME: &str = "onedrive-refresh-token.dpapi";

pub(crate) trait OneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn store(&self, token: &str) -> Result<()>;
    #[allow(dead_code)]
    fn delete(&self) -> Result<()>;
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
struct UnavailableOneDriveRefreshTokenStore;

#[cfg(not(windows))]
impl OneDriveRefreshTokenStore for UnavailableOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        unavailable()
    }

    fn store(&self, _token: &str) -> Result<()> {
        anyhow::bail!(
            "persistent OneDrive refresh-token storage is unavailable on this platform; reauthenticate when the process restarts"
        )
    }

    fn delete(&self) -> Result<()> {
        unavailable()
    }
}

#[cfg(not(windows))]
fn unavailable<T>() -> Result<T> {
    anyhow::bail!(
        "persistent OneDrive refresh-token storage is unavailable on this platform; reauthenticate to reconnect OneDrive"
    )
}

#[cfg(windows)]
pub(crate) struct WindowsOneDriveRefreshTokenStore {
    path: PathBuf,
    entropy: [u8; 32],
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
        }
    }
}

#[cfg(windows)]
impl OneDriveRefreshTokenStore for WindowsOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
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
        create_dir_all_durable(parent).with_context(|| {
            format!(
                "failed to create private OneDrive refresh-token directory: {}",
                parent.display()
            )
        })?;
        let protected = protect_refresh_token(token, &self.entropy)
            .context("failed to protect OneDrive refresh token")?;
        let expectation = target_expectation(&self.path)?;
        let faults = DurableFaultInjector::default();
        let temp = write_verified_temp(
            &self.path,
            &protected,
            &faults,
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
        publish_temp(
            temp,
            &self.path,
            expectation,
            None,
            &faults,
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        )
        .map_err(|error| error.source)
        .with_context(|| {
            format!(
                "failed to publish protected OneDrive refresh token: {}",
                self.path.display()
            )
        })
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
    use std::io::Read;
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
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
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
    use super::{OneDriveRefreshTokenStore, production_store};

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
        use super::WindowsOneDriveRefreshTokenStore;

        const TOKEN: &str = "fixture-refresh-token-never-plaintext";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onedrive-refresh-token.dpapi");
        let store = WindowsOneDriveRefreshTokenStore::new(path.clone(), "test/default");

        store.store(TOKEN).unwrap();

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
        bytes[bytes.len() / 2] ^= 0x80;
        std::fs::write(&path, bytes).unwrap();

        let error = store
            .load()
            .expect_err("corrupted protected payload must fail closed");

        assert!(!format!("{error:#}").contains("fixture-refresh-token"));
    }
}
