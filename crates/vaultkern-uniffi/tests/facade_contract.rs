use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vaultkern_uniffi::{
    EntryFieldsDto, PlatformAdapterError, PlatformPasskeyAssertionInput,
    PlatformPasskeyRegistrationInput, SaveVaultStatusDto, UnlockBlobAdapter, VaultSession,
};

const FIXTURE_PASSWORD: &str = "vaultkern-external-fixture";

#[derive(Debug, Default)]
struct FakeUnlockBlobAdapter {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    authorization_reasons: Mutex<Vec<String>>,
}

impl UnlockBlobAdapter for FakeUnlockBlobAdapter {
    fn supports_unlock_blob(&self) -> Result<bool, PlatformAdapterError> {
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
fn ffi_sync_and_platform_passkey_entry_points_delegate_to_the_runtime_modules() {
    let (_dir, session, _adapter, vault_id) = opened_session();

    let sync_status = session.sync().trigger(vault_id).unwrap();
    assert_eq!(sync_status.source_kind, "local");
    assert_eq!(session.sync().status().unwrap(), None);

    let registration = session
        .register_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "example.com".into(),
            relying_party_name: "Example".into(),
            user_name: "alice@example.com".into(),
            user_display_name: "Alice".into(),
            user_handle: b"alice-user-handle".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        })
        .unwrap();
    assert!(!registration.credential.credential_id.is_empty());
    assert!(
        session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );

    let assertion = session
        .assert_passkey(PlatformPasskeyAssertionInput {
            relying_party: "example.com".into(),
            allowed_credential_ids: vec![registration.credential.credential_id],
            client_data_hash: vec![7; 32],
            user_verified: true,
        })
        .unwrap();
    assert!(!assertion.signature_der.is_empty());
}

#[test]
fn exported_session_handle_is_safe_to_share_between_platform_threads() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<VaultSession>();
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
