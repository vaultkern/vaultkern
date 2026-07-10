use anyhow::Result;

#[allow(dead_code)]
pub trait BiometricProvider {
    fn supports_quick_unlock(&self) -> bool;
    fn authorize(&self, reason: &str) -> Result<()>;
}

pub struct UnsupportedBiometricProvider;

impl BiometricProvider for UnsupportedBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        false
    }

    fn authorize(&self, _reason: &str) -> Result<()> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }
}

#[cfg(windows)]
pub struct WindowsHelloBiometricProvider;

#[cfg(windows)]
impl BiometricProvider for WindowsHelloBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        use windows::Security::Credentials::UI::{
            UserConsentVerifier, UserConsentVerifierAvailability,
        };

        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|operation| operation.join())
            .map(|availability| availability == UserConsentVerifierAvailability::Available)
            .unwrap_or(false)
    }

    fn authorize(&self, reason: &str) -> Result<()> {
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier,
        };
        use windows::core::HSTRING;

        let result = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
            .and_then(|operation| operation.join())?;
        if result == UserConsentVerificationResult::Verified {
            Ok(())
        } else {
            anyhow::bail!("biometric quick unlock was not authorized")
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn default_biometric_provider() -> Box<dyn BiometricProvider> {
    #[cfg(windows)]
    {
        Box::new(WindowsHelloBiometricProvider)
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedBiometricProvider)
    }
}

pub(crate) struct TestBiometricProvider;

impl BiometricProvider for TestBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        true
    }

    fn authorize(&self, _reason: &str) -> Result<()> {
        Ok(())
    }
}
