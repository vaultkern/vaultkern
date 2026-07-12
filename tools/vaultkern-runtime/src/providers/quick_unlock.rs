use anyhow::Result;

#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::rc::Rc;

use super::biometric::BiometricProvider;
#[cfg(not(target_os = "macos"))]
use super::biometric::default_biometric_provider;
#[cfg(target_os = "macos")]
use super::macos_quick_unlock::MacOsQuickUnlockProvider;
use super::secure_storage::SecureStorageProvider;
#[cfg(not(target_os = "macos"))]
use super::secure_storage::{
    default_secure_storage_provider, default_secure_storage_provider_for_extension_id,
};

pub trait QuickUnlockProvider {
    fn is_implemented(&self) -> bool {
        true
    }

    fn requires_same_process_credential_proof(&self) -> bool {
        false
    }

    fn requires_password_credential(&self) -> bool {
        false
    }

    fn is_supported(&self) -> bool;
    fn contains(&self, key: &str) -> Result<bool>;
    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()>;
    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>>;
    fn refresh(&self, key: &str, value: &[u8]) -> Result<()>;
    fn verify_user(&self, reason: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct MemoryQuickUnlockFailures {
    pub(crate) contains: bool,
    pub(crate) refresh: bool,
    pub(crate) delete: bool,
}

#[cfg(test)]
pub(crate) struct MemoryQuickUnlockProvider {
    values: RefCell<BTreeMap<String, Vec<u8>>>,
    operations: Rc<RefCell<Vec<String>>>,
    failures: MemoryQuickUnlockFailures,
    verify_user_callback: Option<Box<dyn Fn()>>,
    requires_process_proof: bool,
}

#[cfg(test)]
impl MemoryQuickUnlockProvider {
    pub(crate) fn new(operations: Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
            operations,
            failures: MemoryQuickUnlockFailures::default(),
            verify_user_callback: None,
            requires_process_proof: false,
        }
    }

    pub(crate) fn with_failures(mut self, failures: MemoryQuickUnlockFailures) -> Self {
        self.failures = failures;
        self
    }

    pub(crate) fn with_verify_user_callback(mut self, callback: impl Fn() + 'static) -> Self {
        self.verify_user_callback = Some(Box::new(callback));
        self
    }

    pub(crate) fn requiring_same_process_credential_proof(mut self) -> Self {
        self.requires_process_proof = true;
        self
    }

    fn record(&self, operation: impl Into<String>) {
        self.operations.borrow_mut().push(operation.into());
    }
}

#[cfg(test)]
impl QuickUnlockProvider for MemoryQuickUnlockProvider {
    fn requires_same_process_credential_proof(&self) -> bool {
        self.requires_process_proof
    }

    fn requires_password_credential(&self) -> bool {
        self.requires_process_proof
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn contains(&self, key: &str) -> Result<bool> {
        self.record("contains");
        if self.failures.contains {
            anyhow::bail!("injected quick unlock contains failure");
        }
        Ok(self.values.borrow().contains_key(key))
    }

    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()> {
        self.record(format!("enable:{reason}"));
        self.values
            .borrow_mut()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        self.record(format!("unlock:{reason}"));
        Ok(self.values.borrow().get(key).cloned())
    }

    fn refresh(&self, key: &str, value: &[u8]) -> Result<()> {
        self.record("refresh");
        if self.failures.refresh {
            anyhow::bail!("injected quick unlock refresh failure");
        }
        if let Some(stored) = self.values.borrow_mut().get_mut(key) {
            *stored = value.to_owned();
        }
        Ok(())
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.record(format!("verify_user:{reason}"));
        if let Some(callback) = &self.verify_user_callback {
            callback();
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.record("delete");
        if self.failures.delete {
            anyhow::bail!("injected quick unlock delete failure");
        }
        self.values.borrow_mut().remove(key);
        Ok(())
    }
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
    fn is_implemented(&self) -> bool {
        self.biometric.is_implemented()
    }

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
        if self.storage.contains(key)? {
            self.storage.store(key, value)?;
        }
        Ok(())
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
    fn is_implemented(&self) -> bool {
        false
    }

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

pub(crate) fn default_quick_unlock_provider() -> Box<dyn QuickUnlockProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsQuickUnlockProvider::new_default())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(ComposedQuickUnlockProvider::new(
            default_biometric_provider(),
            default_secure_storage_provider(),
        ))
    }
}

pub(crate) fn default_quick_unlock_provider_for_extension_id(
    extension_id: Option<&str>,
) -> Box<dyn QuickUnlockProvider> {
    #[cfg(target_os = "macos")]
    {
        match extension_id {
            Some(extension_id) => {
                Box::new(MacOsQuickUnlockProvider::new_for_extension_id(extension_id))
            }
            None => Box::new(MacOsQuickUnlockProvider::new_default()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(ComposedQuickUnlockProvider::new(
            default_biometric_provider(),
            default_secure_storage_provider_for_extension_id(extension_id),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use anyhow::Result;

    use super::{ComposedQuickUnlockProvider, QuickUnlockProvider};
    #[cfg(not(any(windows, target_os = "macos")))]
    use super::{default_quick_unlock_provider, default_quick_unlock_provider_for_extension_id};
    use crate::providers::biometric::BiometricProvider;
    use crate::providers::secure_storage::SecureStorageProvider;

    struct RecordingBiometricProvider {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl BiometricProvider for RecordingBiometricProvider {
        fn supports_quick_unlock(&self) -> bool {
            self.events.borrow_mut().push("support".into());
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

    struct FailingRefreshSecureStorageProvider {
        events: Rc<RefCell<Vec<String>>>,
        fail_contains: bool,
        fail_store: bool,
        fail_delete: bool,
    }

    impl SecureStorageProvider for FailingRefreshSecureStorageProvider {
        fn store(&self, key: &str, _value: &[u8]) -> Result<()> {
            self.events.borrow_mut().push(format!("store:{key}"));
            if self.fail_store {
                anyhow::bail!("injected refresh store failure");
            }
            Ok(())
        }

        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.events.borrow_mut().push(format!("load:{key}"));
            Ok(None)
        }

        fn contains(&self, key: &str) -> Result<bool> {
            self.events.borrow_mut().push(format!("contains:{key}"));
            if self.fail_contains {
                anyhow::bail!("injected refresh contains failure");
            }
            Ok(true)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.events.borrow_mut().push(format!("delete:{key}"));
            if self.fail_delete {
                anyhow::bail!("injected refresh cleanup failure");
            }
            Ok(())
        }
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

    fn composed_failing_refresh_provider(
        events: Rc<RefCell<Vec<String>>>,
        fail_contains: bool,
        fail_store: bool,
        fail_delete: bool,
    ) -> ComposedQuickUnlockProvider {
        ComposedQuickUnlockProvider::new(
            Box::new(RecordingBiometricProvider {
                events: events.clone(),
            }),
            Box::new(FailingRefreshSecureStorageProvider {
                events,
                fail_contains,
                fail_store,
                fail_delete,
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
    fn composed_refresh_checks_presence_and_stores_without_support_probe_or_authorization() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), Some(b"old".to_vec()));

        provider.refresh("vault", b"new").unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            ["contains:vault", "store:vault"]
        );
    }

    #[test]
    fn composed_refresh_does_not_create_a_missing_record() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_test_provider(events.clone(), None);

        provider.refresh("vault", b"new").unwrap();

        assert_eq!(provider.unlock("vault", "Unlock").unwrap(), None);
        assert_eq!(
            events.borrow().as_slice(),
            ["contains:vault", "authorize:Unlock", "load:vault"]
        );
    }

    #[test]
    fn composed_refresh_does_not_delete_after_store_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_failing_refresh_provider(events.clone(), false, true, false);

        let error = provider.refresh("vault", b"new").unwrap_err();

        assert!(format!("{error:#}").contains("injected refresh store failure"));
        assert_eq!(
            events.borrow().as_slice(),
            ["contains:vault", "store:vault"]
        );
    }

    #[test]
    fn composed_refresh_does_not_delete_after_contains_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_failing_refresh_provider(events.clone(), true, false, false);

        let error = provider.refresh("vault", b"new").unwrap_err();

        assert!(format!("{error:#}").contains("injected refresh contains failure"));
        assert_eq!(events.borrow().as_slice(), ["contains:vault"]);
    }

    #[test]
    fn composed_refresh_never_attempts_destructive_cleanup_after_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let provider = composed_failing_refresh_provider(events.clone(), false, true, true);

        let error = provider.refresh("vault", b"new").unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("injected refresh store failure"));
        assert!(!error.contains("injected refresh cleanup failure"));
        assert_eq!(
            events.borrow().as_slice(),
            ["contains:vault", "store:vault"]
        );
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

    #[cfg(not(any(windows, target_os = "macos")))]
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

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn extension_scoped_provider_is_unsupported_off_windows() {
        let provider = default_quick_unlock_provider_for_extension_id(Some("extension-id"));

        assert!(!provider.is_supported());
    }
}
