use anyhow::Result;
use std::cell::RefCell;
use std::collections::BTreeMap;
#[cfg(windows)]
use std::fs;
use std::path::PathBuf;

use crate::state_paths::{extension_state_dir, runtime_state_dir};

#[allow(dead_code)]
pub trait SecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
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
        Box::new(DpapiSecureStorageProvider::new(quick_unlock_storage_dir(
            extension_id,
        )))
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
pub(crate) struct DpapiSecureStorageProvider {
    dir: PathBuf,
}

#[cfg(windows)]
impl DpapiSecureStorageProvider {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.bin"))
    }
}

#[cfg(windows)]
impl SecureStorageProvider for DpapiSecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let protected = protect_with_current_user(value)?;
        fs::write(self.path_for(key), protected)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(None);
        }
        let protected = fs::read(path)?;
        unprotect_with_current_user(&protected).map(Some)
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
fn protect_with_current_user(value: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    copy_and_free_blob(output)
}

#[cfg(windows)]
fn unprotect_with_current_user(value: &[u8]) -> Result<Vec<u8>> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let mut description = null_mut();

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            &mut description,
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if !description.is_null() {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(description as _);
        }
    }
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    copy_and_free_blob(output)
}

#[cfg(windows)]
fn copy_and_free_blob(
    output: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Result<Vec<u8>> {
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let value = bytes.to_vec();
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(output.pbData as _);
    }
    Ok(value)
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

    fn delete(&self, key: &str) -> Result<()> {
        self.values.borrow_mut().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::quick_unlock_storage_dir;
    use crate::state_paths::{extension_state_dir, runtime_state_dir};

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
}
