use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

#[allow(dead_code)]
pub trait BiometricProvider: Send {
    fn set_parent_window_handle(&mut self, _parent_window: Option<usize>) {}
    fn supports_quick_unlock(&self) -> bool;
    fn authorize(&self, reason: &str) -> Result<()>;

    fn authorize_cancellable(&self, reason: &str, cancelled: &AtomicBool) -> Result<()> {
        if cancelled.load(Ordering::Acquire) {
            anyhow::bail!("biometric authorization was cancelled");
        }
        self.authorize(reason)?;
        if cancelled.load(Ordering::Acquire) {
            anyhow::bail!("biometric authorization was cancelled");
        }
        Ok(())
    }
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
#[derive(Default)]
pub struct WindowsHelloBiometricProvider {
    parent_window: Option<usize>,
}

#[cfg(windows)]
impl BiometricProvider for WindowsHelloBiometricProvider {
    fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
        self.parent_window = parent_window.filter(|handle| *handle != 0);
    }

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
        self.authorize_cancellable(reason, &AtomicBool::new(false))
    }

    fn authorize_cancellable(&self, reason: &str, cancelled: &AtomicBool) -> Result<()> {
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier,
        };
        use windows::core::HSTRING;
        use windows_future::AsyncStatus;

        let reason = HSTRING::from(reason);
        let operation = if let Some(parent_window) = self.parent_window {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::System::WinRT::IUserConsentVerifierInterop;

            let interop =
                windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            unsafe {
                interop.RequestVerificationForWindowAsync(
                    HWND(parent_window as *mut std::ffi::c_void),
                    &reason,
                )?
            }
        } else {
            UserConsentVerifier::RequestVerificationAsync(&reason)?
        };
        let result = loop {
            if cancelled.load(Ordering::Acquire) {
                let _ = operation.Cancel();
                anyhow::bail!("biometric authorization was cancelled");
            }
            let status = operation.Status()?;
            if status == AsyncStatus::Completed || status == AsyncStatus::Error {
                break operation.GetResults()?;
            }
            if status == AsyncStatus::Canceled {
                anyhow::bail!("biometric authorization was cancelled");
            }
            if status != AsyncStatus::Started {
                anyhow::bail!("biometric authorization entered an unknown async state");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        if result == UserConsentVerificationResult::Verified {
            Ok(())
        } else {
            anyhow::bail!("biometric quick unlock was not authorized")
        }
    }
}

pub(crate) fn default_biometric_provider() -> Box<dyn BiometricProvider> {
    #[cfg(windows)]
    {
        Box::new(WindowsHelloBiometricProvider::default())
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
