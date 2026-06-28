use anyhow::Result;

#[allow(dead_code)]
pub trait SecureStorageProvider {
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
}

pub struct UnsupportedSecureStorageProvider;

impl SecureStorageProvider for UnsupportedSecureStorageProvider {
    fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
        anyhow::bail!("secure storage is not implemented on this host")
    }

    fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}
