use anyhow::Result;

use super::macos_local_authentication::{
    MacLocalAuthentication, MacLocalAuthenticationApi, is_missing_item_error,
};
use super::quick_unlock::QuickUnlockProvider;

pub(crate) struct MacOsQuickUnlockProvider {
    local_authentication: Box<dyn MacLocalAuthenticationApi>,
}

impl MacOsQuickUnlockProvider {
    pub(crate) fn new_default() -> Self {
        Self::new(Box::new(MacLocalAuthentication))
    }

    fn new(local_authentication: Box<dyn MacLocalAuthenticationApi>) -> Self {
        Self {
            local_authentication,
        }
    }

    fn remove_missing_ok(&self, identifier: &str) -> Result<()> {
        match self.local_authentication.remove(identifier) {
            Ok(()) => Ok(()),
            Err(error) if is_missing_item_error(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl QuickUnlockProvider for MacOsQuickUnlockProvider {
    fn is_supported(&self) -> bool {
        self.local_authentication.is_touch_id_available()
    }

    fn contains(&self, key: &str) -> Result<bool> {
        self.local_authentication.contains(key)
    }

    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()> {
        self.local_authentication.authorize(reason)?;
        self.remove_missing_ok(key)?;
        self.local_authentication.save(key, value)
    }

    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        self.local_authentication.authorize_and_load(key, reason)
    }

    fn refresh(&self, key: &str, value: &[u8]) -> Result<()> {
        self.remove_missing_ok(key)?;
        self.local_authentication.save(key, value)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.local_authentication.authorize(reason)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.remove_missing_ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use anyhow::Result;

    use super::MacOsQuickUnlockProvider;
    use crate::providers::macos_local_authentication::{
        MacLocalAuthenticationApi, MacLocalAuthenticationError,
    };
    use crate::providers::quick_unlock::QuickUnlockProvider;

    #[derive(Default)]
    struct FakeState {
        touch_id_available: bool,
        cancel_next_authorization: bool,
        operations: Vec<String>,
        records: BTreeMap<String, Vec<u8>>,
    }

    struct FakeMacLocalAuthenticationApi {
        state: Rc<RefCell<FakeState>>,
    }

    impl MacLocalAuthenticationApi for FakeMacLocalAuthenticationApi {
        fn is_touch_id_available(&self) -> bool {
            let mut state = self.state.borrow_mut();
            state.operations.push("is_touch_id_available".into());
            state.touch_id_available
        }

        fn authorize(&self, reason: &str) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("authorize:{reason}"));
            if state.cancel_next_authorization {
                state.cancel_next_authorization = false;
                anyhow::bail!("user cancelled Touch ID authorization");
            }
            Ok(())
        }

        fn contains(&self, identifier: &str) -> Result<bool> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("contains:{identifier}"));
            Ok(state.records.contains_key(identifier))
        }

        fn save(&self, identifier: &str, secret: &[u8]) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("save:{identifier}"));
            state.records.insert(identifier.into(), secret.into());
            Ok(())
        }

        fn authorize_and_load(&self, identifier: &str, reason: &str) -> Result<Option<Vec<u8>>> {
            let mut state = self.state.borrow_mut();
            state
                .operations
                .push(format!("authorize_and_load:{identifier}:{reason}"));
            Ok(state.records.get(identifier).cloned())
        }

        fn remove(&self, identifier: &str) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.operations.push(format!("remove:{identifier}"));
            if state.records.remove(identifier).is_some() {
                Ok(())
            } else {
                Err(MacLocalAuthenticationError::MissingItem.into())
            }
        }
    }

    fn provider(touch_id_available: bool) -> (MacOsQuickUnlockProvider, Rc<RefCell<FakeState>>) {
        let state = Rc::new(RefCell::new(FakeState {
            touch_id_available,
            ..FakeState::default()
        }));
        let provider = MacOsQuickUnlockProvider::new(Box::new(FakeMacLocalAuthenticationApi {
            state: state.clone(),
        }));
        (provider, state)
    }

    #[test]
    fn support_requires_strict_touch_id_availability() {
        let (available, available_state) = provider(true);
        let (unavailable, unavailable_state) = provider(false);

        assert!(available.is_supported());
        assert!(!unavailable.is_supported());
        assert_eq!(
            available_state.borrow().operations,
            ["is_touch_id_available"]
        );
        assert_eq!(
            unavailable_state.borrow().operations,
            ["is_touch_id_available"]
        );
    }

    #[test]
    fn enable_authorizes_then_removes_then_saves() {
        let (provider, state) = provider(true);

        provider
            .enable("vault", b"secret", "Enable quick unlock")
            .unwrap();

        assert_eq!(
            state.borrow().operations,
            [
                "authorize:Enable quick unlock",
                "remove:vault",
                "save:vault"
            ]
        );
        assert_eq!(state.borrow().records.get("vault").unwrap(), b"secret");
    }

    #[test]
    fn unlock_is_one_authorize_and_load_operation() {
        let (provider, state) = provider(true);
        state
            .borrow_mut()
            .records
            .insert("vault".into(), b"secret".to_vec());

        assert_eq!(
            provider.unlock("vault", "Unlock this vault").unwrap(),
            Some(b"secret".to_vec())
        );
        assert_eq!(
            state.borrow().operations,
            ["authorize_and_load:vault:Unlock this vault"]
        );
    }

    #[test]
    fn contains_never_authorizes_or_loads() {
        let (provider, state) = provider(true);
        state
            .borrow_mut()
            .records
            .insert("vault".into(), b"secret".to_vec());

        assert!(provider.contains("vault").unwrap());
        assert_eq!(state.borrow().operations, ["contains:vault"]);
    }

    #[test]
    fn refresh_removes_then_saves_without_authorizing() {
        let (provider, state) = provider(true);
        state
            .borrow_mut()
            .records
            .insert("vault".into(), b"old".to_vec());

        provider.refresh("vault", b"new").unwrap();

        assert_eq!(state.borrow().operations, ["remove:vault", "save:vault"]);
        assert_eq!(state.borrow().records.get("vault").unwrap(), b"new");
    }

    #[test]
    fn verify_user_performs_one_transient_authorization() {
        let (provider, state) = provider(true);

        provider.verify_user("Verify with Quick Unlock").unwrap();

        assert_eq!(
            state.borrow().operations,
            ["authorize:Verify with Quick Unlock"]
        );
    }

    #[test]
    fn cancelled_enable_retains_existing_record() {
        let (provider, state) = provider(true);
        {
            let mut state = state.borrow_mut();
            state.records.insert("vault".into(), b"old".to_vec());
            state.cancel_next_authorization = true;
        }

        assert!(
            provider
                .enable("vault", b"new", "Enable quick unlock")
                .is_err()
        );

        assert_eq!(state.borrow().operations, ["authorize:Enable quick unlock"]);
        assert_eq!(state.borrow().records.get("vault").unwrap(), b"old");
    }

    #[test]
    fn delete_is_idempotent_when_record_is_missing() {
        let (provider, state) = provider(true);

        provider.delete("vault").unwrap();
        provider.delete("vault").unwrap();

        assert_eq!(state.borrow().operations, ["remove:vault", "remove:vault"]);
    }

    #[test]
    fn explicit_reenable_replaces_existing_record() {
        let (provider, state) = provider(true);
        state
            .borrow_mut()
            .records
            .insert("vault".into(), b"old".to_vec());

        provider
            .enable("vault", b"new", "Enable quick unlock")
            .unwrap();

        assert_eq!(
            state.borrow().operations,
            [
                "authorize:Enable quick unlock",
                "remove:vault",
                "save:vault"
            ]
        );
        assert_eq!(state.borrow().records.get("vault").unwrap(), b"new");
    }
}
