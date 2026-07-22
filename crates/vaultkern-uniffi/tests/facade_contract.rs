use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use vaultkern_uniffi::{
    EntryFieldsDto, PlatformAdapterError, PlatformPasskeyAssertionInput,
    PlatformPasskeyRegistrationInput, SaveVaultStatusDto, UnlockBlobAdapter, VaultSession,
};

const FIXTURE_PASSWORD: &str = "vaultkern-external-fixture";

#[derive(Debug, Clone, Copy)]
enum FakeLoadFailure {
    Cancelled,
    Invalidated,
}

#[derive(Debug, Default)]
struct FakeUnlockBlobAdapter {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    authorization_reasons: Mutex<Vec<String>>,
    fail_load_presence_query: AtomicBool,
    load_failure: Mutex<Option<FakeLoadFailure>>,
    reentrant_session: Mutex<Option<Weak<VaultSession>>>,
    reentrant_call_failed: AtomicBool,
}

impl UnlockBlobAdapter for FakeUnlockBlobAdapter {
    fn supports_unlock_blob(&self) -> Result<bool, PlatformAdapterError> {
        let reentrant_session = self
            .reentrant_session
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(session) = reentrant_session {
            self.reentrant_call_failed
                .store(session.session_state().is_err(), Ordering::Release);
        }
        Ok(true)
    }

    fn authorize(&self, reason: String) -> Result<(), PlatformAdapterError> {
        self.authorization_reasons.lock().unwrap().push(reason);
        Ok(())
    }

    fn store_requires_user_presence(&self) -> Result<bool, PlatformAdapterError> {
        Ok(false)
    }

    fn load_requires_user_presence(&self) -> Result<bool, PlatformAdapterError> {
        if self.fail_load_presence_query.load(Ordering::Acquire) {
            return Err(PlatformAdapterError::Failure {
                details: "injected load presence query failure".into(),
            });
        }
        Ok(false)
    }

    fn authorize_store_user_presence(&self) -> Result<(), PlatformAdapterError> {
        Ok(())
    }

    fn store_blob(&self, key: String, value: Vec<u8>) -> Result<(), PlatformAdapterError> {
        self.blobs.lock().unwrap().insert(key, value);
        Ok(())
    }

    fn load_blob(&self, key: String) -> Result<Option<Vec<u8>>, PlatformAdapterError> {
        match *self.load_failure.lock().unwrap() {
            Some(FakeLoadFailure::Cancelled) => return Err(PlatformAdapterError::Cancelled),
            Some(FakeLoadFailure::Invalidated) => return Err(PlatformAdapterError::Invalidated),
            None => {}
        }
        Ok(self.blobs.lock().unwrap().get(&key).cloned())
    }

    fn contains_blob(&self, key: String) -> Result<bool, PlatformAdapterError> {
        Ok(self.blobs.lock().unwrap().contains_key(&key))
    }

    fn delete_blob(&self, key: String) -> Result<(), PlatformAdapterError> {
        self.blobs.lock().unwrap().remove(&key);
        Ok(())
    }
}

fn copied_fixture() -> (tempfile::TempDir, String) {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vaultkern-kdbx/tests/fixtures/keepassxc-2.7.6-kdbx4.1.kdbx");
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("smoke.kdbx");
    std::fs::copy(source, &target).unwrap();
    (dir, target.to_string_lossy().into_owned())
}

fn opened_session() -> (
    tempfile::TempDir,
    Arc<VaultSession>,
    Arc<FakeUnlockBlobAdapter>,
    String,
) {
    let (dir, path) = copied_fixture();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(adapter.clone());
    let handle = session.open_vault(path).unwrap();
    session
        .unlock()
        .unlock_vault(handle.vault_id.clone(), Some(FIXTURE_PASSWORD.into()), None)
        .unwrap();
    (dir, session, adapter, handle.vault_id)
}

#[test]
fn ffi_session_opens_lists_reads_edits_and_saves_using_protocol_vocabulary() {
    let (_dir, session, _adapter, vault_id) = opened_session();

    let entries = session.list_entries(vault_id.clone()).unwrap();
    assert!(!entries.is_empty());
    let first = session
        .read_entry(vault_id.clone(), entries[0].id.clone())
        .unwrap();
    let entry_id = first.id.as_str().to_owned();
    let edited_title = format!("{} (edited over UniFFI)", first.title.as_str());

    let edited = session
        .edit_entry(
            vault_id.clone(),
            entry_id.clone(),
            EntryFieldsDto {
                title: edited_title.clone().into(),
                username: first.username,
                password: first.password,
                url: first.url,
                notes: first.notes,
                totp_uri: first.totp_uri,
                custom_fields: first.custom_fields,
            },
        )
        .unwrap();
    assert_eq!(edited.id.as_str(), entry_id);
    assert_eq!(edited.title.as_str(), edited_title);

    let saved = session.save(vault_id).unwrap();
    assert!(matches!(
        saved.status,
        SaveVaultStatusDto::Saved | SaveVaultStatusDto::Merged
    ));
}

#[test]
fn ffi_unlock_blob_roundtrip_uses_the_platform_adapter_and_revoke_removes_it() {
    let (_dir, session, adapter, vault_id) = opened_session();
    let unlock = session.unlock();

    unlock.enroll(Some(FIXTURE_PASSWORD.into()), None).unwrap();
    assert_eq!(adapter.blobs.lock().unwrap().len(), 1);

    let closed = session.close_vault().unwrap();
    assert!(!closed.unlocked);
    let unlocked = unlock.unlock_with_blob().unwrap();
    assert!(unlocked.unlocked);
    assert_eq!(unlocked.active_vault_id.as_deref(), Some(vault_id.as_str()));
    assert!(!session.list_entries(vault_id).unwrap().is_empty());

    unlock.revoke().unwrap();
    assert!(adapter.blobs.lock().unwrap().is_empty());
    session.close_vault().unwrap();
    assert!(unlock.unlock_with_blob().is_err());
    assert_eq!(adapter.authorization_reasons.lock().unwrap().len(), 3);
}

#[test]
fn failed_load_presence_query_requires_explicit_authorization() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let unlock = session.unlock();

    unlock.enroll(Some(FIXTURE_PASSWORD.into()), None).unwrap();
    session.close_vault().unwrap();
    let authorizations_before = adapter.authorization_reasons.lock().unwrap().len();
    adapter
        .fail_load_presence_query
        .store(true, Ordering::Release);

    assert!(unlock.unlock_with_blob().unwrap().unlocked);
    assert_eq!(
        adapter.authorization_reasons.lock().unwrap().len(),
        authorizations_before + 1,
        "an unavailable capability query must fail closed by requiring authorization"
    );
}

#[test]
fn cancelled_unlock_blob_load_preserves_the_enrollment() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let unlock = session.unlock();

    unlock.enroll(Some(FIXTURE_PASSWORD.into()), None).unwrap();
    session.close_vault().unwrap();
    *adapter.load_failure.lock().unwrap() = Some(FakeLoadFailure::Cancelled);

    let error = unlock.unlock_with_blob().unwrap_err();
    assert!(error.to_string().contains("quick unlock was cancelled"));
    assert_eq!(adapter.blobs.lock().unwrap().len(), 1);
}

#[test]
fn invalidated_unlock_blob_load_deletes_the_enrollment() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let unlock = session.unlock();

    unlock.enroll(Some(FIXTURE_PASSWORD.into()), None).unwrap();
    session.close_vault().unwrap();
    *adapter.load_failure.lock().unwrap() = Some(FakeLoadFailure::Invalidated);

    let error = unlock.unlock_with_blob().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("quick unlock is not enabled for the current vault")
    );
    assert!(adapter.blobs.lock().unwrap().is_empty());
}

#[test]
fn ffi_sync_and_platform_passkey_entry_points_delegate_to_the_runtime_modules() {
    let (_dir, session, _adapter, vault_id) = opened_session();

    let sync_status = session.sync().trigger(vault_id).unwrap();
    assert_eq!(sync_status.source_kind, "local");
    assert_eq!(session.sync().status().unwrap(), None);

    let registration_operation = vec![1; 16];
    let prepared = session
        .prepare_passkey_operation(registration_operation.clone())
        .unwrap();
    assert!(prepared.credentials.is_empty());
    let registration = session
        .register_passkey(
            registration_operation.clone(),
            PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"alice-user-handle".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            },
        )
        .unwrap();
    assert!(!registration.credential.credential_id.is_empty());
    session
        .commit_passkey_registration(registration_operation.clone())
        .unwrap();
    session
        .end_passkey_operation(registration_operation)
        .unwrap();
    assert!(
        session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );

    let assertion_operation = vec![2; 16];
    session
        .prepare_passkey_operation(assertion_operation.clone())
        .unwrap();
    let assertion_input = PlatformPasskeyAssertionInput {
        relying_party: "example.com".into(),
        allowed_credential_ids: vec![registration.credential.credential_id.clone()],
        client_data_hash: vec![7; 32],
        user_verified: true,
    };
    let assertion = session
        .assert_passkey(assertion_operation.clone(), assertion_input.clone())
        .unwrap();
    assert!(!assertion.signature_der.is_empty());
    assert!(
        session
            .assert_passkey(assertion_operation.clone(), assertion_input)
            .unwrap_err()
            .to_string()
            .contains("user verification was already consumed")
    );
    session.end_passkey_operation(assertion_operation).unwrap();
}

#[test]
fn abandoned_passkey_registration_is_rolled_back() {
    let (_dir, session, _adapter, _vault_id) = opened_session();
    let operation_id = vec![3; 16];
    session
        .prepare_passkey_operation(operation_id.clone())
        .unwrap();

    let registration = session
        .register_passkey(
            operation_id.clone(),
            PlatformPasskeyRegistrationInput {
                relying_party: "rollback.example".into(),
                relying_party_name: "Rollback Example".into(),
                user_name: "alice@rollback.example".into(),
                user_display_name: "Alice".into(),
                user_handle: b"rollback-user-handle".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            },
        )
        .unwrap();
    session.end_passkey_operation(operation_id).unwrap();

    assert!(
        !session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );
}

#[test]
fn exported_session_handle_is_safe_to_share_between_platform_threads() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<VaultSession>();
}

#[test]
fn foreign_callback_reentry_returns_without_deadlocking_the_runtime() {
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(adapter.clone());
    *adapter.reentrant_session.lock().unwrap() = Some(Arc::downgrade(&session));
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let _ = sender.send(session.session_state());
    });

    let outer_result = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("foreign callback reentry must not deadlock the runtime");
    assert!(outer_result.is_ok());
    assert!(adapter.reentrant_call_failed.load(Ordering::Acquire));
}

#[test]
fn ffi_secret_fields_are_redacted_from_rust_debug_output() {
    let fields = EntryFieldsDto {
        title: "debug-secret-title".into(),
        username: "debug-secret-username".into(),
        password: "debug-secret-password".into(),
        url: "debug-secret-url".into(),
        notes: "debug-secret-notes".into(),
        totp_uri: Some("debug-secret-totp".into()),
        custom_fields: Vec::new(),
    };

    let debug = format!("{fields:?}");
    assert!(debug.contains("[REDACTED]"));
    for secret in [
        "debug-secret-title",
        "debug-secret-username",
        "debug-secret-password",
        "debug-secret-url",
        "debug-secret-notes",
        "debug-secret-totp",
    ] {
        assert!(!debug.contains(secret));
    }
}
