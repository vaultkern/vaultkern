use anyhow::Result;
use sha2::{Digest, Sha256};

use super::macos_local_authentication::{
    MacLocalAuthentication, MacLocalAuthenticationApi, is_missing_item_error,
};
use super::quick_unlock::QuickUnlockProvider;

pub(crate) struct MacOsQuickUnlockProvider {
    local_authentication: Box<dyn MacLocalAuthenticationApi>,
    identifier_scope: String,
}

impl MacOsQuickUnlockProvider {
    pub(crate) fn new_default() -> Self {
        Self::new(Box::new(MacLocalAuthentication), None)
    }

    pub(crate) fn new_for_extension_id(extension_id: &str) -> Self {
        Self::new(Box::new(MacLocalAuthentication), Some(extension_id))
    }

    fn new(
        local_authentication: Box<dyn MacLocalAuthenticationApi>,
        extension_id: Option<&str>,
    ) -> Self {
        Self {
            local_authentication,
            identifier_scope: identifier_scope(extension_id),
        }
    }

    fn backend_identifier(&self, key: &str) -> String {
        format!(
            "com.vaultkern.quick-unlock.v1:{}:{key}",
            self.identifier_scope
        )
    }

    fn remove_if_present(&self, identifier: &str) -> Result<bool> {
        match self.local_authentication.remove(identifier) {
            Ok(()) => Ok(true),
            Err(error) if is_missing_item_error(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn identifier_scope(extension_id: Option<&str>) -> String {
    let Some(extension_id) = extension_id else {
        return "default".into();
    };
    let digest = Sha256::digest(extension_id.as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("extension-{digest}")
}

impl QuickUnlockProvider for MacOsQuickUnlockProvider {
    fn is_supported(&self) -> bool {
        self.local_authentication.is_touch_id_available()
    }

    fn contains(&self, key: &str) -> Result<bool> {
        self.local_authentication
            .contains(&self.backend_identifier(key))
    }

    fn enable(&self, key: &str, value: &[u8], reason: &str) -> Result<()> {
        let identifier = self.backend_identifier(key);
        self.local_authentication.authorize(reason)?;
        self.remove_if_present(&identifier)?;
        self.local_authentication.save(&identifier, value)
    }

    fn unlock(&self, key: &str, reason: &str) -> Result<Option<Vec<u8>>> {
        self.local_authentication
            .authorize_and_load(&self.backend_identifier(key), reason)
    }

    fn refresh(&self, key: &str, value: &[u8]) -> Result<()> {
        let identifier = self.backend_identifier(key);
        if self.remove_if_present(&identifier)? {
            self.local_authentication.save(&identifier, value)?;
        }
        Ok(())
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.local_authentication.authorize(reason)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.remove_if_present(&self.backend_identifier(key))
            .map(|_| ())
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
        let provider = provider_with_state(state.clone(), None);
        (provider, state)
    }

    fn provider_with_state(
        state: Rc<RefCell<FakeState>>,
        extension_id: Option<&str>,
    ) -> MacOsQuickUnlockProvider {
        MacOsQuickUnlockProvider::new(
            Box::new(FakeMacLocalAuthenticationApi { state }),
            extension_id,
        )
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
        let identifier = provider.backend_identifier("vault");

        provider
            .enable("vault", b"secret", "Enable quick unlock")
            .unwrap();

        assert_eq!(
            state.borrow().operations,
            [
                "authorize:Enable quick unlock",
                &format!("remove:{identifier}"),
                &format!("save:{identifier}")
            ]
        );
        assert_eq!(state.borrow().records.get(&identifier).unwrap(), b"secret");
    }

    #[test]
    fn unlock_is_one_authorize_and_load_operation() {
        let (provider, state) = provider(true);
        let identifier = provider.backend_identifier("vault");
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), b"secret".to_vec());

        assert_eq!(
            provider.unlock("vault", "Unlock this vault").unwrap(),
            Some(b"secret".to_vec())
        );
        assert_eq!(
            state.borrow().operations,
            [format!("authorize_and_load:{identifier}:Unlock this vault")]
        );
    }

    #[test]
    fn contains_never_authorizes_or_loads() {
        let (provider, state) = provider(true);
        let identifier = provider.backend_identifier("vault");
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), b"secret".to_vec());

        assert!(provider.contains("vault").unwrap());
        assert_eq!(
            state.borrow().operations,
            [format!("contains:{identifier}")]
        );
    }

    #[test]
    fn refresh_removes_then_saves_without_authorizing() {
        let (provider, state) = provider(true);
        let identifier = provider.backend_identifier("vault");
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), b"old".to_vec());

        provider.refresh("vault", b"new").unwrap();

        assert_eq!(
            state.borrow().operations,
            [format!("remove:{identifier}"), format!("save:{identifier}")]
        );
        assert_eq!(state.borrow().records.get(&identifier).unwrap(), b"new");
    }

    #[test]
    fn refresh_of_missing_record_does_not_create_quick_unlock() {
        let (provider, state) = provider(true);

        provider.refresh("vault", b"new").unwrap();

        assert!(state.borrow().records.is_empty());
        assert_eq!(state.borrow().operations.len(), 1);
        assert!(state.borrow().operations[0].starts_with("remove:"));
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
        let identifier = provider.backend_identifier("vault");
        {
            let mut state = state.borrow_mut();
            state.records.insert(identifier.clone(), b"old".to_vec());
            state.cancel_next_authorization = true;
        }

        assert!(
            provider
                .enable("vault", b"new", "Enable quick unlock")
                .is_err()
        );

        assert_eq!(state.borrow().operations, ["authorize:Enable quick unlock"]);
        assert_eq!(state.borrow().records.get(&identifier).unwrap(), b"old");
    }

    #[test]
    fn delete_is_idempotent_when_record_is_missing() {
        let (provider, state) = provider(true);
        let identifier = provider.backend_identifier("vault");

        provider.delete("vault").unwrap();
        provider.delete("vault").unwrap();

        assert_eq!(
            state.borrow().operations,
            [
                format!("remove:{identifier}"),
                format!("remove:{identifier}")
            ]
        );
    }

    #[test]
    fn explicit_reenable_replaces_existing_record() {
        let (provider, state) = provider(true);
        let identifier = provider.backend_identifier("vault");
        state
            .borrow_mut()
            .records
            .insert(identifier.clone(), b"old".to_vec());

        provider
            .enable("vault", b"new", "Enable quick unlock")
            .unwrap();

        assert_eq!(
            state.borrow().operations,
            [
                "authorize:Enable quick unlock",
                &format!("remove:{identifier}"),
                &format!("save:{identifier}")
            ]
        );
        assert_eq!(state.borrow().records.get(&identifier).unwrap(), b"new");
    }

    #[test]
    fn extension_scopes_do_not_share_backend_identifiers() {
        let state = Rc::new(RefCell::new(FakeState {
            touch_id_available: true,
            ..FakeState::default()
        }));
        let first = provider_with_state(state.clone(), Some("extension-a"));
        let second = provider_with_state(state.clone(), Some("extension-b"));

        first.enable("vault", b"secret", "Enable").unwrap();
        state.borrow_mut().operations.clear();

        assert!(!second.contains("vault").unwrap());
    }

    #[test]
    fn default_scope_is_stable_across_provider_instances() {
        let state = Rc::new(RefCell::new(FakeState {
            touch_id_available: true,
            ..FakeState::default()
        }));
        let first = provider_with_state(state.clone(), None);
        let second = provider_with_state(state.clone(), None);

        first.enable("vault", b"secret", "Enable").unwrap();
        state.borrow_mut().operations.clear();

        assert!(second.contains("vault").unwrap());
    }
}
