use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex, Weak};
use std::time::Duration;

use vaultkern_uniffi::{
    EntryFieldsDto, OneDriveTokenAdapter, PlatformAdapterError, PlatformPasskeyAssertionInput,
    PlatformPasskeyRegistrationInput, ResidentPlatform, SaveVaultStatusDto, SensitiveBytes,
    SensitiveString, UnlockBlobAdapter, UnlockBlobStatusDto, VaultPasskeyOperation, VaultSession,
    VaultSessionConfig,
};

const FIXTURE_PASSWORD: &str = "vaultkern-external-fixture";

fn session_config(root: &std::path::Path, platform: ResidentPlatform) -> VaultSessionConfig {
    VaultSessionConfig {
        platform,
        state_directory: root.join("state").to_string_lossy().into_owned(),
        temporary_directory: root.join("temporary").to_string_lossy().into_owned(),
    }
}

#[derive(Debug, Clone, Copy)]
enum FakeLoadFailure {
    Cancelled,
    Invalidated,
}

#[derive(Debug)]
struct SupportsGate {
    claimed: AtomicBool,
    entered: Barrier,
    release: Barrier,
}

impl SupportsGate {
    fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }
}

#[derive(Default)]
struct FakeUnlockBlobAdapter {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    authorization_reasons: Mutex<Vec<String>>,
    fail_load_presence_query: AtomicBool,
    load_failure: Mutex<Option<FakeLoadFailure>>,
    supports_gate: Mutex<Option<Arc<SupportsGate>>>,
    reentrant_session: Mutex<Option<Weak<VaultSession>>>,
    reentrant_call_failed: AtomicBool,
    cross_thread_reentrant_session: Mutex<Option<Weak<VaultSession>>>,
    cross_thread_reentrant_call_failed: AtomicBool,
    passkey_operation_to_drop: Mutex<Option<Arc<VaultPasskeyOperation>>>,
}

impl std::fmt::Debug for FakeUnlockBlobAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeUnlockBlobAdapter")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct FakeOneDriveTokenAdapter {
    token: Mutex<Option<String>>,
}

impl OneDriveTokenAdapter for FakeOneDriveTokenAdapter {
    fn load_refresh_token(&self) -> Result<Option<SensitiveString>, PlatformAdapterError> {
        Ok(self.token.lock().unwrap().clone().map(Into::into))
    }

    fn store_refresh_token(&self, token: SensitiveString) -> Result<(), PlatformAdapterError> {
        *self.token.lock().unwrap() = Some(token.as_str().to_owned());
        Ok(())
    }

    fn delete_refresh_token(&self) -> Result<(), PlatformAdapterError> {
        self.token.lock().unwrap().take();
        Ok(())
    }
}

impl UnlockBlobAdapter for FakeUnlockBlobAdapter {
    fn supports_unlock_blob(&self) -> Result<bool, PlatformAdapterError> {
        let gate = self.supports_gate.lock().unwrap().clone();
        if let Some(gate) = gate
            && !gate.claimed.swap(true, Ordering::AcqRel)
        {
            gate.entered.wait();
            gate.release.wait();
        }
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
        let cross_thread_session = self
            .cross_thread_reentrant_session
            .lock()
            .unwrap()
            .take()
            .and_then(|session| session.upgrade());
        if let Some(session) = cross_thread_session {
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(session.session_state());
            });
            let failed_fast = receiver
                .recv_timeout(Duration::from_millis(200))
                .is_ok_and(|result| result.is_err());
            self.cross_thread_reentrant_call_failed
                .store(failed_fast, Ordering::Release);
        }
        self.passkey_operation_to_drop.lock().unwrap().take();
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

    fn store_blob(&self, key: String, value: SensitiveBytes) -> Result<(), PlatformAdapterError> {
        self.blobs
            .lock()
            .unwrap()
            .insert(key, value.as_slice().to_vec());
        Ok(())
    }

    fn load_blob(&self, key: String) -> Result<Option<SensitiveBytes>, PlatformAdapterError> {
        match *self.load_failure.lock().unwrap() {
            Some(FakeLoadFailure::Cancelled) => return Err(PlatformAdapterError::Cancelled),
            Some(FakeLoadFailure::Invalidated) => return Err(PlatformAdapterError::Invalidated),
            None => {}
        }
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .map(Into::into))
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

#[test]
fn resident_runtime_requires_explicit_absolute_host_directories() {
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let invalid = VaultSessionConfig {
        platform: ResidentPlatform::Android,
        state_directory: "relative-state".into(),
        temporary_directory: "relative-temporary".into(),
    };

    let result = VaultSession::new(
        invalid,
        adapter,
        Arc::new(FakeOneDriveTokenAdapter::default()),
    );

    assert!(result.is_err());
}

#[test]
fn resident_runtime_reports_an_unusable_host_temporary_directory_without_panicking() {
    let root = tempfile::tempdir().unwrap();
    let temporary_file = root.path().join("not-a-directory");
    std::fs::write(&temporary_file, b"occupied").unwrap();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let config = VaultSessionConfig {
        platform: ResidentPlatform::Macos,
        state_directory: root.path().join("state").to_string_lossy().into_owned(),
        temporary_directory: temporary_file.to_string_lossy().into_owned(),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        VaultSession::new(
            config,
            adapter,
            Arc::new(FakeOneDriveTokenAdapter::default()),
        )
    }));

    assert!(
        result.is_ok(),
        "constructor must not panic on a host path error"
    );
    assert!(result.unwrap().is_err());
}

fn opened_session() -> (
    tempfile::TempDir,
    Arc<VaultSession>,
    Arc<FakeUnlockBlobAdapter>,
    String,
) {
    let (dir, path) = copied_fixture();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(
        session_config(dir.path(), ResidentPlatform::Android),
        adapter.clone(),
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
    let handle = session.open_vault(path).unwrap();
    session
        .unlock()
        .unlock_vault(
            handle.vault_id.clone(),
            Some(FIXTURE_PASSWORD.into()),
            None,
            false,
        )
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
fn ffi_session_exposes_core_fill_candidate_matching() {
    let (_dir, session, _adapter, vault_id) = opened_session();
    let first = session
        .read_entry(
            vault_id.clone(),
            session.list_entries(vault_id.clone()).unwrap()[0]
                .id
                .clone(),
        )
        .unwrap();
    let entry_id = first.id.as_str().to_owned();
    session
        .edit_entry(
            vault_id.clone(),
            entry_id.clone(),
            EntryFieldsDto {
                title: first.title,
                username: first.username,
                password: first.password,
                url: "https://login.example.com/account".into(),
                notes: first.notes,
                totp_uri: first.totp_uri,
                custom_fields: first.custom_fields,
            },
        )
        .unwrap();

    let candidates = session
        .find_fill_candidates(vault_id.clone(), "https://login.example.com/account".into())
        .unwrap();
    assert_eq!(candidates[0].id, entry_id);
    assert!(
        session
            .find_fill_candidates(vault_id, "https://unrelated.invalid/login".into())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn ffi_sources_expose_the_existing_runtime_reference_vocabulary() {
    let (_dir, session, _adapter, _vault_id) = opened_session();

    let recent = session.sources().list_recent().unwrap();

    assert_eq!(recent.vaults.len(), 1);
    assert_eq!(recent.vaults[0].source_kind, "local");
    assert!(recent.vaults[0].is_current);
    assert!(session.capabilities().one_drive_account_setup);
}

#[test]
fn ffi_unlock_blob_roundtrip_uses_the_platform_adapter_and_revoke_removes_it() {
    let (_dir, session, adapter, vault_id) = opened_session();
    let unlock = session.unlock();

    unlock
        .enroll(Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();
    assert_eq!(adapter.blobs.lock().unwrap().len(), 1);

    let closed = session.lock_session().unwrap();
    assert!(!closed.unlocked);
    let unlocked = unlock.unlock_with_blob(false).unwrap();
    assert_eq!(unlocked.status, UnlockBlobStatusDto::Unlocked);
    assert!(unlocked.state.unlocked);
    assert_eq!(
        unlocked.state.active_vault_id.as_deref(),
        Some(vault_id.as_str())
    );
    assert!(!session.list_entries(vault_id).unwrap().is_empty());

    unlock.revoke().unwrap();
    assert!(adapter.blobs.lock().unwrap().is_empty());
    session.lock_session().unwrap();
    assert_eq!(
        unlock.unlock_with_blob(false).unwrap().status,
        UnlockBlobStatusDto::NotEnrolled
    );
    assert_eq!(adapter.authorization_reasons.lock().unwrap().len(), 3);
}

#[test]
fn close_vault_releases_the_loaded_vault_while_lock_session_keeps_it_reopenable() {
    let (_dir, session, _adapter, vault_id) = opened_session();

    assert!(!session.lock_session().unwrap().unlocked);
    assert!(session.list_entries(vault_id.clone()).is_err());
    assert!(
        session
            .unlock()
            .unlock_vault(vault_id.clone(), Some(FIXTURE_PASSWORD.into()), None, false,)
            .unwrap()
            .unlocked
    );
    session.lock_session().unwrap();

    let state = session.close_vault(vault_id.clone()).unwrap();

    assert!(!state.unlocked);
    let error = session.list_entries(vault_id).unwrap_err();
    assert!(error.to_string().contains("vault not opened"));
}

#[test]
fn failed_close_cleanup_keeps_the_vault_loaded_for_a_retry() {
    let (dir, session, _adapter, vault_id) = opened_session();
    let temporary_root = dir.path().join("temporary");
    let session_directory = std::fs::read_dir(&temporary_root)
        .unwrap()
        .find(|entry| entry.as_ref().is_ok_and(|entry| entry.path().is_dir()))
        .expect("session-base directory")
        .unwrap()
        .path();
    let displaced_directory = temporary_root.join("displaced-session-bases");
    std::fs::rename(&session_directory, &displaced_directory).unwrap();
    std::fs::write(&session_directory, b"occupied").unwrap();

    let close_result = session.close_vault(vault_id.clone());

    std::fs::remove_file(&session_directory).unwrap();
    std::fs::rename(&displaced_directory, &session_directory).unwrap();
    assert!(close_result.is_err());
    assert!(
        session.list_entries(vault_id.clone()).is_ok(),
        "a failed close must leave the loaded vault available for retry"
    );
    session.close_vault(vault_id).unwrap();
}

#[test]
fn current_source_can_be_loaded_and_unlocked_after_only_its_reference_remains() {
    let (_dir, session, _adapter, vault_id) = opened_session();
    session.close_vault(vault_id.clone()).unwrap();

    let state = session
        .unlock()
        .unlock_current(Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();

    assert!(state.unlocked);
    assert_eq!(state.active_vault_id.as_deref(), Some(vault_id.as_str()));
    assert!(!session.list_entries(vault_id).unwrap().is_empty());
}

#[test]
fn failed_load_presence_query_requires_explicit_authorization() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let unlock = session.unlock();

    unlock
        .enroll(Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();
    session.lock_session().unwrap();
    let authorizations_before = adapter.authorization_reasons.lock().unwrap().len();
    adapter
        .fail_load_presence_query
        .store(true, Ordering::Release);

    let result = unlock.unlock_with_blob(false).unwrap();
    assert_eq!(result.status, UnlockBlobStatusDto::Unlocked);
    assert!(result.state.unlocked);
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

    unlock
        .enroll(Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();
    session.lock_session().unwrap();
    *adapter.load_failure.lock().unwrap() = Some(FakeLoadFailure::Cancelled);

    let result = unlock.unlock_with_blob(false).unwrap();
    assert_eq!(result.status, UnlockBlobStatusDto::Cancelled);
    assert!(!result.state.unlocked);
    assert_eq!(adapter.blobs.lock().unwrap().len(), 1);
}

#[test]
fn invalidated_unlock_blob_load_deletes_the_enrollment() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let unlock = session.unlock();

    unlock
        .enroll(Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();
    session.lock_session().unwrap();
    *adapter.load_failure.lock().unwrap() = Some(FakeLoadFailure::Invalidated);

    let result = unlock.unlock_with_blob(false).unwrap();
    assert_eq!(result.status, UnlockBlobStatusDto::NotEnrolled);
    assert!(!result.state.unlocked);
    assert!(adapter.blobs.lock().unwrap().is_empty());
}

#[test]
fn ffi_sync_and_platform_passkey_entry_points_delegate_to_the_runtime_modules() {
    let (_dir, session, _adapter, vault_id) = opened_session();

    let sync_status = session.sync().trigger(vault_id).unwrap();
    assert_eq!(sync_status.source_kind, "local");
    assert_eq!(session.sync().status().unwrap(), None);

    let registration_operation = vec![1; 16];
    let registration_scope = session
        .begin_passkey_operation(registration_operation)
        .unwrap();
    assert!(registration_scope.credentials().unwrap().is_empty());
    let registration = registration_scope
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
    registration_scope.commit_registration().unwrap();
    registration_scope.finish().unwrap();
    assert!(
        session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );

    let assertion_operation = vec![2; 16];
    let assertion_scope = session
        .begin_passkey_operation(assertion_operation)
        .unwrap();
    let assertion_input = PlatformPasskeyAssertionInput {
        relying_party: "example.com".into(),
        allowed_credential_ids: vec![registration.credential.credential_id.clone()],
        client_data_hash: vec![7; 32],
        user_verified: true,
    };
    let assertion = assertion_scope
        .assert_passkey(assertion_input.clone())
        .unwrap();
    assert!(!assertion.signature_der.is_empty());
    assert!(
        assertion_scope
            .assert_passkey(assertion_input)
            .unwrap_err()
            .to_string()
            .contains("user verification was already consumed")
    );
    assertion_scope.finish().unwrap();
}

#[test]
fn abandoned_passkey_registration_is_rolled_back() {
    let (_dir, session, _adapter, _vault_id) = opened_session();
    let operation = session.begin_passkey_operation(vec![3; 16]).unwrap();

    let registration = operation
        .register_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "rollback.example".into(),
            relying_party_name: "Rollback Example".into(),
            user_name: "alice@rollback.example".into(),
            user_display_name: "Alice".into(),
            user_handle: b"rollback-user-handle".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        })
        .unwrap();
    drop(operation);

    assert!(
        !session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );
}

#[test]
fn session_lock_is_rejected_while_a_platform_passkey_lease_is_active() {
    let (_dir, session, _adapter, _vault_id) = opened_session();
    let operation = session.begin_passkey_operation(vec![5; 16]).unwrap();

    assert!(session.lock_session().is_err());
    operation.finish().unwrap();
    assert!(!session.lock_session().unwrap().unlocked);
}

#[test]
fn ordinary_session_save_cannot_persist_an_uncommitted_passkey_registration() {
    let (_dir, session, _adapter, vault_id) = opened_session();
    let operation = session.begin_passkey_operation(vec![7; 16]).unwrap();
    operation
        .register_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "uncommitted.example".into(),
            relying_party_name: "Uncommitted Example".into(),
            user_name: "alice@uncommitted.example".into(),
            user_display_name: "Alice".into(),
            user_handle: b"uncommitted-user-handle".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        })
        .unwrap();

    assert!(session.save(vault_id.clone()).is_err());
    drop(operation);
    assert!(session.save(vault_id).is_ok());
}

#[test]
fn uniffi_serializes_passkey_leases_to_keep_registration_commits_isolated() {
    let (_dir, session, _adapter, _vault_id) = opened_session();
    let first = session.begin_passkey_operation(vec![8; 16]).unwrap();

    assert!(session.begin_passkey_operation(vec![9; 16]).is_err());
    first.finish().unwrap();
    session
        .begin_passkey_operation(vec![9; 16])
        .unwrap()
        .finish()
        .unwrap();
}

#[test]
fn closing_another_loaded_vault_cannot_invalidate_an_active_passkey_lease() {
    let (dir, session, _adapter, first_vault_id) = opened_session();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vaultkern-kdbx/tests/fixtures/keepassxc-2.7.6-kdbx4.1.kdbx");
    let second_path = dir.path().join("second.kdbx");
    std::fs::copy(fixture, &second_path).unwrap();
    let second = session
        .open_vault(second_path.to_string_lossy().into_owned())
        .unwrap();
    session
        .unlock()
        .unlock_vault(second.vault_id, Some(FIXTURE_PASSWORD.into()), None, false)
        .unwrap();
    let operation = session.begin_passkey_operation(vec![6; 16]).unwrap();

    assert!(session.close_vault(first_vault_id.clone()).is_err());
    operation.finish().unwrap();
    session.close_vault(first_vault_id).unwrap();
}

#[test]
fn passkey_registration_dropped_inside_adapter_callback_is_rolled_back() {
    let (_dir, session, adapter, _vault_id) = opened_session();
    let operation = session.begin_passkey_operation(vec![4; 16]).unwrap();
    let registration = operation
        .register_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "callback-rollback.example".into(),
            relying_party_name: "Callback Rollback Example".into(),
            user_name: "alice@callback-rollback.example".into(),
            user_display_name: "Alice".into(),
            user_handle: b"callback-rollback-user-handle".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        })
        .unwrap();
    *adapter.passkey_operation_to_drop.lock().unwrap() = Some(operation);

    session.session_state().unwrap();

    assert!(
        !session
            .list_passkey_credentials()
            .unwrap()
            .iter()
            .any(|credential| credential.credential_id == registration.credential.credential_id)
    );
}

#[test]
fn macos_resident_does_not_expose_android_direct_passkey_persistence() {
    let root = tempfile::tempdir().unwrap();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(
        session_config(root.path(), ResidentPlatform::Macos),
        adapter,
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();

    let capabilities = session.capabilities();

    assert!(!capabilities.direct_passkey_persistence);
    assert!(!capabilities.apple_passkey_outbox);
    let error = match session.begin_passkey_operation(vec![9; 16]) {
        Ok(_) => panic!("macOS resident must not expose direct passkey persistence"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("apple_passkey_outbox"));
}

#[test]
fn exported_session_handle_is_safe_to_share_between_platform_threads() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<VaultSession>();
}

#[test]
fn independent_platform_thread_fails_fast_while_an_adapter_callback_is_active() {
    let root = tempfile::tempdir().unwrap();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(
        session_config(root.path(), ResidentPlatform::Android),
        adapter.clone(),
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
    let gate = Arc::new(SupportsGate::new());
    *adapter.supports_gate.lock().unwrap() = Some(gate.clone());

    let first_session = session.clone();
    let first = std::thread::spawn(move || first_session.session_state());
    gate.entered.wait();

    let second_session = session.clone();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        sender.send(second_session.session_state()).unwrap();
    });

    let concurrent = receiver
        .recv_timeout(Duration::from_millis(100))
        .expect("adapter callback contention must fail fast");
    assert!(matches!(
        concurrent,
        Err(vaultkern_uniffi::VaultKernError::AdapterCallbackActive)
    ));
    gate.release.wait();
    assert!(first.join().unwrap().is_ok());
}

#[test]
fn foreign_callback_reentry_returns_without_deadlocking_the_runtime() {
    let root = tempfile::tempdir().unwrap();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(
        session_config(root.path(), ResidentPlatform::Android),
        adapter.clone(),
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
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
fn foreign_callback_may_call_an_independent_session_on_the_same_thread() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let first_adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let second_adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let first = VaultSession::new(
        session_config(first_root.path(), ResidentPlatform::Android),
        first_adapter.clone(),
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
    let second = VaultSession::new(
        session_config(second_root.path(), ResidentPlatform::Android),
        second_adapter,
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
    *first_adapter.reentrant_session.lock().unwrap() = Some(Arc::downgrade(&second));

    assert!(first.session_state().is_ok());
    assert!(!first_adapter.reentrant_call_failed.load(Ordering::Acquire));
}

#[test]
fn cross_thread_foreign_callback_reentry_fails_fast_instead_of_deadlocking() {
    let root = tempfile::tempdir().unwrap();
    let adapter = Arc::new(FakeUnlockBlobAdapter::default());
    let session = VaultSession::new(
        session_config(root.path(), ResidentPlatform::Android),
        adapter.clone(),
        Arc::new(FakeOneDriveTokenAdapter::default()),
    )
    .unwrap();
    *adapter.cross_thread_reentrant_session.lock().unwrap() = Some(Arc::downgrade(&session));

    assert!(session.session_state().is_ok());
    assert!(
        adapter
            .cross_thread_reentrant_call_failed
            .load(Ordering::Acquire)
    );
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
