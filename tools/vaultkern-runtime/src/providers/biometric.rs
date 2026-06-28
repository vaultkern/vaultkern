use anyhow::Result;

#[allow(dead_code)]
pub trait BiometricProvider {
    fn supports_quick_unlock(&self) -> bool;
    fn authorize(&self) -> Result<()>;
}

pub struct UnsupportedBiometricProvider;

impl BiometricProvider for UnsupportedBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        false
    }

    fn authorize(&self) -> Result<()> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }
}
