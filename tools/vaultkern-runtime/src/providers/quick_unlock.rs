use anyhow::Result;

use super::biometric::BiometricProvider;
#[cfg(windows)]
use super::biometric::WindowsHelloBiometricProvider;
use super::secure_storage::SecureStorageProvider;
#[cfg(windows)]
use super::secure_storage::{WindowsHelloSecureStorageProvider, quick_unlock_storage_dir};

pub trait QuickUnlockProvider {
    fn is_supported(&self) -> bool;
    fn contains(&self, key: &str) -> Result<bool>;
    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()>;
    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>>;
    fn refresh(&self, key: &str, value: &[u8]) -> Result<()>;
    fn verify_user(&self, reason: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

pub(crate) struct ComposedQuickUnlockProvider {
    biometric: Box<dyn BiometricProvider>,
    storage: Box<dyn SecureStorageProvider>,
}

impl ComposedQuickUnlockProvider {
    pub(crate) fn new(
        biometric: Box<dyn BiometricProvider>,
        storage: Box<dyn SecureStorageProvider>,
    ) -> Self {
        Self { biometric, storage }
    }
}

impl QuickUnlockProvider for ComposedQuickUnlockProvider {
    fn is_supported(&self) -> bool {
        self.biometric.supports_quick_unlock()
    }

    fn contains(&self, key: &str) -> Result<bool> {
        self.storage.contains(key)
    }

    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()> {
        self.biometric.authorize(reason)?;
        self.storage.store(key, value)
    }

    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        self.biometric.authorize(reason)?;
        self.storage.load(key)
    }

    fn refresh(&self, key: &str, value: &[u8]) -> Result<()> {
        self.storage.store(key, value)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.biometric.authorize(reason)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.storage.delete(key)
    }
}

pub(crate) struct UnsupportedQuickUnlockProvider;

impl QuickUnlockProvider for UnsupportedQuickUnlockProvider {
    fn is_supported(&self) -> bool {
        false
    }

    fn contains(&self, _key: &str) -> Result<bool> {
        Ok(false)
    }

    fn enable(&self, _key: &str, _value: &[u8], _reason: &str) -> Result<()> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }

    fn unlock(&self, _key: &str, _reason: &str) -> Result<Option<Vec<u8>>> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }

    fn refresh(&self, _key: &str, _value: &[u8]) -> Result<()> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }

    fn verify_user(&self, _reason: &str) -> Result<()> {
        anyhow::bail!("biometric quick unlock is not implemented on this host")
    }

    fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) fn default_quick_unlock_provider() -> Box<dyn QuickUnlockProvider> {
    default_quick_unlock_provider_for_extension_id(None)
}

#[allow(dead_code)]
pub(crate) fn default_quick_unlock_provider_for_extension_id(
    extension_id: Option<&str>,
) -> Box<dyn QuickUnlockProvider> {
    #[cfg(windows)]
    {
        Box::new(ComposedQuickUnlockProvider::new(
            Box::new(WindowsHelloBiometricProvider),
            Box::new(WindowsHelloSecureStorageProvider::new(
                quick_unlock_storage_dir(extension_id),
            )),
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = extension_id;
        Box::new(UnsupportedQuickUnlockProvider)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use anyhow::Result;

    use super::{
        ComposedQuickUnlockProvider, QuickUnlockProvider, default_quick_unlock_provider,
        default_quick_unlock_provider_for_extension_id,
    };
    use crate::providers::biometric::BiometricProvider;
    use crate::providers::secure_storage::SecureStorageProvider;

    struct RecordingBiometricProvider {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl BiometricProvider for RecordingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            true
        }

        fn authorize(&self, reason: &str) -> Result<()> {
            self.events.borrow_mut().push(format!("authorize:{reason}"));
            Ok(())
        }
    }

    struct RecordingSecureStorageProvider {
        events: Rc<RefCell<Vec<String>>>,
        value: RefCell<Option<Vec<u8>>>,
    }

    impl SecureStorageProvider for RecordingSecureStorageProvider {
        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.events.borrow_mut().push(format!("store:{key}"));
            self.value.replace(Some(value.to_vec()));
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.events.borrow_mut().push(format!("load:{key}"));
            Ok(self.value.borrow().clone())
        }

        fn contains(&self, key: &str) -> Result<bool> {
            self.events.borrow_mut().push(format!("contains:{key}"));
            Ok(self.value.borrow().is_some())
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.events.borrow_mut().push(format!("delete:{key}"));
            self.value.replace(None);
            Ok(())
        }
    }

    fn composed_test_provider(
        events: Rc<RefCell<Vec<String>>>,
        value: Option<Vec<u8>>,
    ) -> ComposedQuickUnlockProvider {
        ComposedQuickUnlockProvider::new(
            Box::new(RecordingBiometricProvider {
                events: events.clone(),
            }),
            Box::new(RecordingSecureStorageProvider {
                events,
                value: RefCell::new(value),
            }),
        )
    }

    #[test]
    fn composed_unlock_authorizes_once_before_loading() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), Some(b"secret".to_vec()));

        assert_eq!(
            provider.unlock("vault", "Unlock this vault").unwrap(),
            Some(b"secret".to_vec())
        );
        assert_eq!(
            events.borrow().as_slice(),
            ["authorize:Unlock this vault", "load:vault"]
        );
    }

    #[test]
    fn composed_enable_authorizes_once_before_storing() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), None);

        provider
            .enable("vault", b"secret", "Enable quick unlock")
            .unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            ["authorize:Enable quick unlock", "store:vault"]
        );
    }

    #[test]
    fn composed_contains_never_authorizes_or_loads() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), Some(b"secret".to_vec()));

        assert!(provider.contains("vault").unwrap());
        assert_eq!(events.borrow().as_slice(), ["contains:vault"]);
    }

    #[test]
    fn composed_refresh_stores_without_authorizing() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), None);

        provider.refresh("vault", b"new").unwrap();
        assert_eq!(events.borrow().as_slice(), ["store:vault"]);
    }

    #[test]
    fn composed_verify_user_only_authorizes() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), None);

        provider.verify_user("Verify user").unwrap();
        assert_eq!(events.borrow().as_slice(), ["authorize:Verify user"]);
    }

    #[test]
    fn composed_delete_delegates_to_storage() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), Some(b"secret".to_vec()));

        provider.delete("vault").unwrap();
        assert_eq!(events.borrow().as_slice(), ["delete:vault"]);
    }

    #[test]
    fn composed_support_delegates_to_biometric_provider() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events, None);

        assert!(provider.is_supported());
    }

    #[cfg(not(windows))]
    #[test]
    fn default_provider_is_unsupported_off_windows() {
        let provider = default_quick_unlock_provider();

        assert!(!provider.is_supported());
        assert!(!provider.contains("vault").unwrap());
        assert!(provider.enable("vault", b"secret", "Enable").is_err());
        assert!(provider.unlock("vault", "Unlock").is_err());
        assert!(provider.refresh("vault", b"new").is_err());
        assert!(provider.verify_user("Verify").is_err());
        provider.delete("vault").unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn extension_scoped_provider_is_unsupported_off_windows() {
        let provider = default_quick_unlock_provider_for_extension_id(Some("extension-id"));

        assert!(!provider.is_supported());
    }
}
