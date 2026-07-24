use vaultkern_core::{
    CompositeKey, Compression, EntryCreate, EntryTimesUpdate, KdbxCipher, KdbxVersion, KeepassCore,
    SaveKdf, SaveProfile, Vault,
};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{
    DatabaseSettingsUpdateDto, RuntimeCommand, RuntimeResponse, SaveVaultStatusDto,
};

fn retry_publication(runtime: &mut Runtime, vault_id: &str) -> anyhow::Result<RuntimeResponse> {
    runtime.handle(RuntimeCommand::SaveVault {
        vault_id: vault_id.to_owned(),
    })
}

fn key() -> CompositeKey {
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    key
}

fn create_entry(
    core: &KeepassCore,
    vault: &mut Vault,
    title: &str,
    username: &str,
    modified_at: u64,
) -> String {
    let root_id = vault.root.id.to_string();
    let created = core
        .add_entry(
            vault,
            &root_id,
            EntryCreate {
                title: title.into(),
                username: username.into(),
                password: format!("{title}-password"),
                url: format!("https://{}.example", title.to_ascii_lowercase()),
                notes: String::new().into(),
            },
        )
        .unwrap();
    core.update_entry_times(
        vault,
        &created.id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(modified_at),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    created.id
}

fn stage_entry_update(
    runtime: &mut Runtime,
    vault_id: &str,
    entry_id: &str,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
) {
    runtime
        .update_entry_fields(
            vault_id,
            entry_id,
            title.into(),
            username.into(),
            password.into(),
            url.into(),
            notes.into(),
            None,
            vec![],
        )
        .expect("stage the Working Copy without invoking the Runtime Protocol commit path");
}

#[test]
fn runtime_opens_unlocks_and_saves_onedrive_vault_reference() {
    let core = KeepassCore::new();
    let bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();

    let mut runtime = Runtime::for_tests_with_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes,
    );
    let reference = runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();

    assert_eq!(reference.source_kind, "onedrive");
    assert_eq!(reference.availability, "ready");

    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let session = runtime.session_state();
    assert!(session.unlocked);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: session.active_vault_id.unwrap(),
        })
        .unwrap();

    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Saved && result.merge_summary.is_none()
    ));
}

#[test]
fn runtime_persists_a_local_onedrive_encryption_profile_change() {
    let core = KeepassCore::new();
    let bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let mut runtime = Runtime::for_tests_with_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    let mut encryption = runtime.get_database_settings(&vault_id).unwrap().encryption;
    encryption.compression = "none".into();
    runtime
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                encryption: Some(encryption),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();

    retry_publication(&mut runtime, &vault_id).unwrap();

    let saved = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let header = vaultkern_core::KdbxHeader::decode(&saved).unwrap();
    assert_eq!(header.compression, Compression::None);
}

#[test]
fn runtime_unlocks_remote_vault_from_cache_when_metadata_check_fails() {
    let core = KeepassCore::new();
    let mut vault = Vault::empty("Cloud Vault");
    create_entry(&core, &mut vault, "Cached", "alice", 10);
    let bytes = core
        .save_kdbx(&vault, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes.clone(),
        cache_dir.path(),
    );
    first
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    first
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes,
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.remove_test_onedrive_item("drive-1", "item-1");

    second
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let session = second.session_state();
    let status = session.source_status.expect("source status");

    assert!(session.unlocked);
    assert_eq!(status.source_kind, "onedrive");
    assert_eq!(status.remote_state, "cache");
    assert_eq!(status.cached_at, Some(100));
    let last_error = status.last_error.expect("remote error");
    assert!(last_error.contains("OneDrive"), "{last_error}");

    let entries = second
        .list_entries(session.active_vault_id.as_deref().unwrap())
        .unwrap();
    assert!(entries.iter().any(|entry| entry.title == "Cached"));
}

#[test]
fn runtime_opens_cached_remote_vault_by_checking_metadata_without_downloading_content() {
    let core = KeepassCore::new();
    let mut cached_vault = Vault::empty("Cloud Vault");
    create_entry(&core, &mut cached_vault, "Cached", "alice", 10);
    let cached_bytes = core
        .save_kdbx(&cached_vault, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        cached_bytes.clone(),
        cache_dir.path(),
    );
    first
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    first
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        cached_bytes,
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.reset_test_onedrive_access_counts();
    second
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let session = second.session_state();
    let status = session.source_status.expect("source status");
    assert_eq!(status.source_kind, "onedrive");
    assert_eq!(status.remote_state, "online");
    assert_eq!(status.last_sync_at, Some(200));
    assert_eq!(status.cached_at, Some(100));
    assert_eq!(status.last_error, None);
    let counts = second.test_onedrive_access_counts();
    assert_eq!(counts.remote_state_reads, 1);
    assert_eq!(counts.snapshot_reads, 0);
    assert_eq!(counts.snapshot_from_state_reads, 0);

    let entries = second
        .list_entries(session.active_vault_id.as_deref().unwrap())
        .unwrap();
    assert!(entries.iter().any(|entry| entry.title == "Cached"));
}

#[test]
fn runtime_refreshes_cached_remote_vault_when_metadata_changed() {
    let core = KeepassCore::new();
    let mut cached_vault = Vault::empty("Cloud Vault");
    create_entry(&core, &mut cached_vault, "Cached", "alice", 10);
    let cached_bytes = core
        .save_kdbx(&cached_vault, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        cached_bytes,
        cache_dir.path(),
    );
    first
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    first
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let mut remote_vault = Vault::empty("Cloud Vault");
    create_entry(&core, &mut remote_vault, "Remote", "bob", 20);
    let mut remote_bytes = core
        .save_kdbx(&remote_vault, &key(), SaveProfile::recommended())
        .unwrap();
    remote_bytes.push(0);
    remote_bytes.pop();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        remote_bytes.clone(),
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);
    second.reset_test_onedrive_access_counts();
    second
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let session = second.session_state();
    let status = session.source_status.expect("source status");
    assert_eq!(status.remote_state, "online");
    assert_eq!(status.last_sync_at, Some(200));
    assert_eq!(status.cached_at, Some(200));
    let counts = second.test_onedrive_access_counts();
    assert_eq!(counts.remote_state_reads, 1);
    assert_eq!(counts.snapshot_reads, 1);

    let entries = second
        .list_entries(session.active_vault_id.as_deref().unwrap())
        .unwrap();
    assert!(entries.iter().any(|entry| entry.title == "Remote"));
    assert!(!entries.iter().any(|entry| entry.title == "Cached"));
}

#[test]
fn runtime_reports_cache_status_when_remote_provider_fails() {
    let core = KeepassCore::new();
    let bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        123,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes.clone(),
        cache_dir.path(),
    );
    first
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    first
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        456,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes,
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.remove_test_onedrive_item("drive-1", "item-1");
    second
        .handle(RuntimeCommand::PreloadCurrentVault)
        .expect("preload from cache");
    let vault_id = "onedrive:drive-1:item-1".to_owned();
    let response = second
        .handle(RuntimeCommand::RetryVaultSourceSync { vault_id })
        .expect("retry sync from cache");

    let status = match response {
        RuntimeResponse::VaultSourceStatus(status) => status,
        other => panic!("expected source status, got {other:?}"),
    };

    assert_eq!(status.source_kind, "onedrive");
    assert_eq!(status.remote_state, "cache");
    assert_eq!(status.cached_at, Some(123));
    let last_error = status.last_error.expect("remote error");
    assert!(last_error.contains("OneDrive"), "{last_error}");
}

#[test]
fn runtime_retries_remote_sync_and_clears_cache_status_after_recovery() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    create_entry(&core, &mut initial, "Cached", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime.remove_test_onedrive_item("drive-1", "item-1");

    let mut recovered = core.load_database(&initial_bytes, &key()).unwrap().vault;
    create_entry(&core, &mut recovered, "Recovered", "bob", 20);
    let recovered_bytes = core
        .save_kdbx(&recovered, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        recovered_bytes,
    );

    let vault_id = "onedrive:drive-1:item-1".to_owned();
    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    match response {
        RuntimeResponse::VaultSourceStatus(status) => {
            assert_eq!(status.source_kind, "onedrive");
            assert_eq!(status.remote_state, "online");
            assert_eq!(status.last_sync_at, Some(100));
            assert_eq!(status.last_error, None);
        }
        other => panic!("expected source status, got {other:?}"),
    }

    let entries = runtime.list_entries(&vault_id).unwrap();
    assert!(entries.iter().any(|entry| entry.title == "Recovered"));
    assert_eq!(
        runtime.session_state().source_status.unwrap().remote_state,
        "online"
    );
}

#[test]
fn runtime_retry_sync_checks_metadata_without_downloading_unchanged_remote_vault() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    create_entry(&core, &mut initial, "Cached", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    match response {
        RuntimeResponse::VaultSourceStatus(status) => {
            assert_eq!(status.remote_state, "online");
            assert_eq!(status.last_sync_at, Some(100));
            assert_eq!(status.last_error, None);
        }
        other => panic!("expected source status, got {other:?}"),
    }
    let counts = runtime.test_onedrive_access_counts();
    assert_eq!(counts.remote_state_reads, 1);
    assert_eq!(counts.snapshot_reads, 0);
    assert_eq!(counts.snapshot_from_state_reads, 0);
}

#[test]
fn runtime_retry_sync_refreshes_quick_unlock_after_remote_kdf_rotation() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-retry-after-kdf-rotation".into()),
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(
            &remote,
            &key(),
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::ChaCha20,
                compression: Compression::None,
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
            },
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::VaultSourceStatus(status)
            if status.remote_state == "online" && status.last_error.is_none()
    ));
    assert_eq!(
        runtime
            .get_entry_detail(&vault_id, &entry_id)
            .unwrap()
            .notes,
        "remote-retry-after-kdf-rotation"
    );
    retry_publication(&mut runtime, &vault_id).unwrap();
    let saved = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let saved_header = vaultkern_core::KdbxHeader::decode(&saved).unwrap();
    assert_eq!(saved_header.cipher, KdbxCipher::ChaCha20);
    assert_eq!(saved_header.compression, Compression::None);

    runtime.lock_session();
    runtime.unlock_current_vault_with_quick_unlock().unwrap();
    assert!(runtime.session_state().unlocked);
}

#[test]
fn runtime_updates_remote_cache_after_successful_save() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Cached", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Saved Offline Cache",
        "alice",
        "saved-password",
        "https://saved.example",
        "saved",
    );
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.remove_test_onedrive_item("drive-1", "item-1");
    second
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    let entries = second
        .list_entries(second.session_state().active_vault_id.as_deref().unwrap())
        .unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.title == "Saved Offline Cache")
    );
}

#[test]
fn runtime_saves_remote_vault_to_pending_cache_when_remote_write_fails() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Cached", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Unsaved Remote Failure",
        "alice",
        "unsaved-password",
        "https://unsaved.example",
        "unsaved",
    );
    runtime.queue_test_onedrive_ambiguous_write(false);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    match response {
        RuntimeResponse::SaveVaultResult(result) => {
            assert_eq!(result.status, SaveVaultStatusDto::SavedToCache);
            assert_eq!(result.merge_summary, None);
        }
        other => panic!("expected save result, got {other:?}"),
    }
    let status = runtime
        .session_state()
        .source_status
        .expect("source status");
    assert_eq!(status.remote_state, "pending_sync");
    assert_eq!(status.cached_at, Some(100));
    assert!(status.last_error.is_some());

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.remove_test_onedrive_item("drive-1", "item-1");
    second
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let entries = second
        .list_entries(second.session_state().active_vault_id.as_deref().unwrap())
        .unwrap();

    assert!(
        entries
            .iter()
            .any(|entry| entry.title == "Unsaved Remote Failure")
    );
    assert!(!entries.iter().any(|entry| entry.title == "Cached"));
    assert_eq!(
        second.session_state().source_status.unwrap().remote_state,
        "pending_sync"
    );
}

#[test]
fn runtime_retries_pending_cache_by_uploading_local_version() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Cached", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Pending Local",
        "alice",
        "pending-password",
        "https://pending.example",
        "pending",
    );
    runtime.queue_test_onedrive_ambiguous_write(false);
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    match response {
        RuntimeResponse::VaultSourceStatus(status) => {
            assert_eq!(status.remote_state, "online");
            assert_eq!(status.last_error, None);
        }
        other => panic!("expected source status, got {other:?}"),
    }

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let database = core.load_database(&uploaded, &key()).unwrap();
    let entries = core.project_vault(&database.vault).root.entries;
    assert!(entries.iter().any(|entry| entry.title == "Pending Local"));
}

#[test]
fn runtime_retries_pending_cache_by_merging_changed_remote_before_upload() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Local", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Pending Local",
        "alice",
        "pending-password",
        "https://pending.example",
        "pending",
    );
    runtime.queue_test_onedrive_ambiguous_write(false);
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    let mut remote_changed = core.load_database(&initial_bytes, &key()).unwrap().vault;
    create_entry(&core, &mut remote_changed, "Remote", "bob", 20);
    let remote_changed_bytes = core
        .save_kdbx(&remote_changed, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        remote_changed_bytes,
    );

    let retry = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        retry,
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let database = core.load_database(&uploaded, &key()).unwrap();
    let entries = core.project_vault(&database.vault).root.entries;
    assert!(
        entries.iter().any(|entry| entry.title == "Pending Local"),
        "uploaded entries: {entries:?}"
    );
    assert!(entries.iter().any(|entry| entry.title == "Remote"));
}

#[test]
fn runtime_publishes_deleted_source_pending_as_conflict_copy_after_remote_kdf_rotation() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "pending-password",
        "https://account.example",
        "",
    );
    runtime.remove_test_onedrive_item("drive-1", "item-1");
    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::ConflictCopy
                && result.conflict_copy_path.as_deref()
                    == Some("onedrive:pending-conflict-copy")
    ));

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-after-kdf-rotation".into()),
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(
            &remote,
            &key(),
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::ChaCha20,
                compression: Compression::None,
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
            },
        )
        .unwrap();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        remote_bytes,
    );

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::VaultSourceStatus(status)
            if status.remote_state == "online"
                && status.last_error.as_deref()
                    .is_some_and(|error| error.contains("VaultKern conflict"))
    ));
    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let uploaded_header = vaultkern_core::KdbxHeader::decode(&uploaded).unwrap();
    assert_eq!(uploaded_header.cipher, KdbxCipher::ChaCha20);
    assert_eq!(uploaded_header.compression, Compression::None);
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "Account-password");
    assert_eq!(entry.notes, "remote-after-kdf-rotation");

    let RuntimeResponse::OneDriveItemList(list) = runtime
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap()
    else {
        panic!("expected OneDrive item list");
    };
    let conflict = list
        .items
        .iter()
        .find(|item| item.name.contains("VaultKern conflict"))
        .expect("pending local generation must remain recoverable");
    let conflict_vault = core
        .load_database(
            &runtime
                .read_test_onedrive_item_bytes(&conflict.drive_id, &conflict.item_id)
                .unwrap(),
            &key(),
        )
        .unwrap()
        .vault;
    let conflict_entry = core
        .project_entry_detail(&conflict_vault, &entry_id)
        .unwrap();
    assert_eq!(conflict_entry.password, "pending-password");

    runtime.lock_session();
    runtime.unlock_current_vault_with_quick_unlock().unwrap();
    assert!(runtime.session_state().unlocked);
}

#[test]
fn kdf_rotated_rebase_with_unknown_put_keeps_a_retryable_remote_base() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-before-unknown-put",
        "https://account.example",
        "",
    );

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-before-unknown-put".into()),
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(
            &remote,
            &key(),
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::ChaCha20,
                compression: Compression::None,
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
            },
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);
    runtime.queue_test_onedrive_ambiguous_write(false);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::SavedToCache
                && result.conflict_copy_path.is_none()
    ));

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::VaultSourceStatus(status)
            if status.remote_state == "online" && status.last_error.is_none()
    ));
    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "local-before-unknown-put");
    assert_eq!(entry.notes, "remote-before-unknown-put");
}

#[test]
fn runtime_retries_generic_pending_with_fresh_three_way_patch_after_cas_failure() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "pending-password",
        "https://account.example",
        "",
    );
    runtime.queue_test_onedrive_ambiguous_write(false);
    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::SavedToCache
    ));

    let mut raced_remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut raced_remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-notes".into()),
        },
    )
    .unwrap();
    let raced_remote_bytes = core
        .save_kdbx(&raced_remote, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.queue_test_onedrive_precondition_failure(Some(raced_remote_bytes));
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::VaultSourceStatus(status)
            if status.remote_state == "online" && status.last_error.is_none()
    ));
    assert_eq!(runtime.test_onedrive_access_counts().writes, 2);

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "pending-password");
    assert_eq!(entry.notes, "remote-notes");
}

#[test]
fn runtime_pending_cas_exhaustion_stays_pending_without_conflict_split() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "pending-password",
        "https://account.example",
        "keep me",
    );
    runtime.queue_test_onedrive_ambiguous_write(false);
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    for attempt in 1..=3 {
        let mut raced_remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
        core.update_entry_fields(
            &mut raced_remote,
            &entry_id,
            vaultkern_core::EntryUpdate {
                title: None,
                username: None,
                password: None,
                url: None,
                notes: Some(format!("final-cas-race-{attempt}")),
            },
        )
        .unwrap();
        let raced_remote_bytes = core
            .save_kdbx(&raced_remote, &key(), SaveProfile::recommended())
            .unwrap();
        runtime.queue_test_onedrive_precondition_failure(Some(raced_remote_bytes));
    }
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::VaultSourceStatus(status) = response else {
        panic!("expected source status");
    };
    assert_eq!(status.remote_state, "pending_sync");
    let error = status.last_error.expect("Stale Revision recovery message");
    assert!(error.contains("Stale Revision"), "{error}");
    assert_eq!(runtime.test_onedrive_access_counts().writes, 3);
    assert_eq!(
        runtime
            .get_entry_detail(&vault_id, &entry_id)
            .unwrap()
            .notes,
        "keep me",
        "Stale Revision must not replace Local with a rejected merge candidate"
    );

    let list = runtime
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap();
    let RuntimeResponse::OneDriveItemList(list) = list else {
        panic!("expected OneDrive list");
    };
    assert_eq!(list.items.len(), 1);

    let retry = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        retry,
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "pending-password");
    assert_eq!(entry.notes, "keep me");
}

#[test]
fn deleting_remote_vault_reference_removes_offline_cache() {
    let core = KeepassCore::new();
    let bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes.clone(),
        cache_dir.path(),
    );
    let reference = runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .delete_vault_reference(&reference.vault_ref_id)
        .unwrap();

    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        bytes,
        cache_dir.path(),
    );
    second
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    second.remove_test_onedrive_item("drive-1", "item-1");

    let error = second
        .unlock_current_vault_with_password("demo-password")
        .unwrap_err()
        .to_string();
    assert!(error.contains("failed to read OneDrive vault"), "{error}");
}

#[test]
fn runtime_rebases_local_fields_onto_a_changed_onedrive_source() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let local_entry_id = create_entry(&core, &mut initial, "Local", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();

    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    let reference = runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    stage_entry_update(
        &mut runtime,
        &vault_id,
        &local_entry_id,
        "Local Updated",
        "alice",
        "local-password",
        "https://local.example/app",
        "local edit",
    );

    let mut external = core.load_database(&initial_bytes, &key()).unwrap().vault;
    create_entry(&core, &mut external, "External", "bob", 90);
    let external_bytes = core
        .save_kdbx(&external, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", external_bytes);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .expect("007 field patch should rebase representable changes");
    assert!(
        matches!(
            &response,
            RuntimeResponse::SaveVaultResult(result)
                if result.status == SaveVaultStatusDto::Merged
                    && result.merge_summary.is_some()
                    && result.conflict_copy_path.is_none()
        ),
        "unexpected save response: {response:?}"
    );

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let database = core.load_database(&uploaded, &key()).unwrap();
    let entries = core.project_vault(&database.vault).root.entries;
    assert!(entries.iter().any(|entry| entry.title == "Local Updated"));
    assert!(entries.iter().any(|entry| entry.title == "External"));
    assert_eq!(
        reference.vault_ref_id,
        runtime.session_state().current_vault_ref_id.unwrap()
    );
}

#[test]
fn runtime_adopts_changed_remote_without_writing_when_local_is_untouched() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-only".into()),
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes.clone());
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
                && result.conflict_copy_path.is_none()
    ));
    let counts = runtime.test_onedrive_access_counts();
    assert_eq!(counts.writes, 0);
    assert_eq!(counts.snapshot_from_state_reads, 1);
    assert_eq!(
        runtime
            .get_entry_detail(&vault_id, &entry_id.to_string())
            .unwrap()
            .notes,
        "remote-only"
    );
    assert_eq!(
        runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap(),
        remote_bytes
    );

    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-after-adopt",
        "https://account.example",
        "remote-only",
    );

    let mut changed_again = remote;
    core.update_entry_fields(
        &mut changed_again,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-after-adopt".into()),
        },
    )
    .unwrap();
    // Deliberately older than the local edit: only a correctly refreshed base
    // can distinguish independent fields without relying on last-writer-wins.
    core.update_entry_times(
        &mut changed_again,
        &entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(20),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    let changed_again_bytes = core
        .save_kdbx(&changed_again, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", changed_again_bytes);
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
                && result.conflict_copy_path.is_none()
    ));
    assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "local-after-adopt");
    assert_eq!(entry.notes, "remote-after-adopt");
}

#[test]
fn runtime_adopts_untouched_remote_after_kdf_rotation_with_quick_unlock() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-only-after-kdf-rotation".into()),
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(
            &remote,
            &key(),
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::ChaCha20,
                compression: Compression::None,
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
            },
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);
    runtime.reset_test_onedrive_access_counts();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
                && result.conflict_copy_path.is_none()
    ));
    assert_eq!(runtime.test_onedrive_access_counts().writes, 0);
    assert_eq!(
        runtime
            .get_entry_detail(&vault_id, &entry_id)
            .unwrap()
            .notes,
        "remote-only-after-kdf-rotation"
    );
    let encryption = runtime.get_database_settings(&vault_id).unwrap().encryption;
    assert_eq!(encryption.cipher, "chacha20");
    assert_eq!(encryption.compression, "none");

    runtime.lock_session();
    runtime.unlock_current_vault_with_quick_unlock().unwrap();
    assert!(runtime.session_state().unlocked);
}

#[test]
fn runtime_retries_etag_cas_with_a_fresh_three_way_patch() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-password",
        "https://account.example",
        "",
    );

    let mut raced_remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut raced_remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-notes".into()),
        },
    )
    .unwrap();
    core.update_entry_times(
        &mut raced_remote,
        &entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(30),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    let raced_remote_bytes = core
        .save_kdbx(&raced_remote, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.queue_test_onedrive_precondition_failure(Some(raced_remote_bytes));

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
    ));
    assert_eq!(runtime.test_onedrive_access_counts().writes, 2);

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "local-password");
    assert_eq!(entry.notes, "remote-notes");
}

#[test]
fn retention_that_cannot_keep_the_conflict_loser_uses_a_conflict_copy() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    initial.history_max_items = Some(0);
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-password",
        "https://account.example",
        "",
    );

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: Some("remote-password".into()),
            url: None,
            notes: None,
        },
    )
    .unwrap();
    core.update_entry_times(
        &mut remote,
        &entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(30),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    let remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.queue_test_onedrive_precondition_failure(Some(remote_bytes.clone()));

    let response = runtime
        .handle(RuntimeCommand::SaveVault { vault_id })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::ConflictCopy
                && result.conflict_copy_path.is_some()
    ));
    assert_eq!(
        runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap(),
        remote_bytes
    );
}

#[test]
fn runtime_refreshes_quick_unlock_after_remote_kdf_rotation_before_merging() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.set_test_unix_time(100);
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-password",
        "https://account.example",
        "",
    );

    let mut rotated_remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    core.update_entry_fields(
        &mut rotated_remote,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("remote-after-kdf-rotation".into()),
        },
    )
    .unwrap();
    core.update_entry_times(
        &mut rotated_remote,
        &entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(30),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    let rotated_remote_bytes = core
        .save_kdbx(
            &rotated_remote,
            &key(),
            SaveProfile {
                version: KdbxVersion::V4_1,
                cipher: KdbxCipher::ChaCha20,
                compression: Compression::None,
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
            },
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", rotated_remote_bytes);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
    ));

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let uploaded_header = vaultkern_core::KdbxHeader::decode(&uploaded).unwrap();
    assert_eq!(uploaded_header.cipher, KdbxCipher::ChaCha20);
    assert_eq!(uploaded_header.compression, Compression::None);
    let vault = core.load_database(&uploaded, &key()).unwrap().vault;
    let entry = core.project_entry_detail(&vault, &entry_id).unwrap();
    assert_eq!(entry.password, "local-password");
    assert_eq!(entry.notes, "remote-after-kdf-rotation");

    runtime.lock_session();
    runtime.unlock_current_vault_with_quick_unlock().unwrap();
    assert!(runtime.session_state().unlocked);
}

#[test]
fn remote_kdf_rotation_with_unrelated_lineage_splits_once_then_adopts_remote() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    runtime.set_test_unix_time(100);
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Local copy",
        "alice",
        "local-password",
        "https://local.example",
        "keep me",
    );

    let unrelated = core
        .save_kdbx(
            &Vault::empty("Unrelated remote"),
            &key(),
            SaveProfile {
                kdf: Some(SaveKdf::AesKdbx4 { rounds: 10 }),
                ..SaveProfile::recommended()
            },
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", unrelated);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .expect("Conflict Split must preserve Local before adopting Remote");
    let RuntimeResponse::SaveVaultResult(result) = response else {
        panic!("expected SaveVaultResult");
    };
    assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
    assert!(runtime.list_entries(&vault_id).unwrap().is_empty());

    let response = runtime
        .handle(RuntimeCommand::SaveVault { vault_id })
        .expect("the adopted Remote Head must be the new common Base");
    let RuntimeResponse::SaveVaultResult(result) = response else {
        panic!("expected SaveVaultResult");
    };
    assert_eq!(result.status, SaveVaultStatusDto::Saved);
}

#[test]
fn unrepresentable_remote_lineage_uploads_a_sibling_conflict_copy() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Local copy",
        "alice",
        "local-password",
        "https://local.example",
        "keep me",
    );

    let unrelated = core
        .save_kdbx(
            &Vault::empty("Unrelated remote"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", unrelated);

    let response = runtime
        .handle(RuntimeCommand::SaveVault { vault_id })
        .unwrap();
    let conflict_path = match response {
        RuntimeResponse::SaveVaultResult(result) => {
            assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
            result
                .conflict_copy_path
                .expect("OneDrive conflict-copy path")
        }
        other => panic!("expected save result, got {other:?}"),
    };
    assert!(conflict_path.starts_with("onedrive:"));

    let list = runtime
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap();
    let RuntimeResponse::OneDriveItemList(list) = list else {
        panic!("expected OneDrive list");
    };
    assert_eq!(list.items.len(), 2);
    assert!(
        list.items
            .iter()
            .any(|item| item.name.contains("VaultKern conflict"))
    );
}

#[test]
fn foreign_writer_with_same_root_uses_a_conflict_copy_instead_of_field_patch() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    initial.generator = Some("VaultKern".into());
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-password",
        "https://account.example",
        "",
    );

    let mut foreign = core.load_database(&initial_bytes, &key()).unwrap().vault;
    foreign.generator = Some("KeePassXC".into());
    core.update_entry_fields(
        &mut foreign,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("foreign-notes".into()),
        },
    )
    .unwrap();
    let foreign_bytes = core
        .save_kdbx(&foreign, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", foreign_bytes.clone());

    let response = runtime
        .handle(RuntimeCommand::SaveVault { vault_id })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::ConflictCopy
    ));
    assert_eq!(
        runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap(),
        foreign_bytes
    );
}

#[test]
fn failed_conflict_copy_upload_falls_back_to_durable_pending_state() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    initial.generator = Some("VaultKern".into());
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Account",
        "alice",
        "local-password",
        "https://account.example",
        "",
    );

    let mut foreign = core.load_database(&initial_bytes, &key()).unwrap().vault;
    foreign.generator = Some("KeePassXC".into());
    core.update_entry_fields(
        &mut foreign,
        &entry_id,
        vaultkern_core::EntryUpdate {
            title: None,
            username: None,
            password: None,
            url: None,
            notes: Some("foreign-notes".into()),
        },
    )
    .unwrap();
    let foreign_bytes = core
        .save_kdbx(&foreign, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", foreign_bytes.clone());
    runtime.fail_next_test_onedrive_conflict_copy();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::ConflictCopy
                && result.conflict_copy_path.as_deref()
                    == Some("onedrive:pending-conflict-copy")
    ));
    assert_eq!(
        runtime.session_state().source_status.unwrap().remote_state,
        "pending_sync"
    );
    assert_eq!(
        runtime
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap(),
        foreign_bytes
    );
}

#[test]
fn failed_unrepresentable_patch_conflict_copy_also_falls_back_to_pending() {
    let core = KeepassCore::new();
    let mut initial = Vault::empty("Cloud Vault");
    let entry_id = create_entry(&core, &mut initial, "Account", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    stage_entry_update(
        &mut runtime,
        &vault_id,
        &entry_id,
        "Local",
        "alice",
        "local-password",
        "https://local.example",
        "keep me",
    );
    let unrelated = core
        .save_kdbx(
            &Vault::empty("Unrelated remote"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", unrelated);
    runtime.fail_next_test_onedrive_conflict_copy();

    let response = runtime
        .handle(RuntimeCommand::SaveVault { vault_id })
        .unwrap();
    assert!(matches!(
        response,
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::ConflictCopy
                && result.conflict_copy_path.as_deref()
                    == Some("onedrive:pending-conflict-copy")
    ));
}

#[test]
fn source_refresh_turns_unrepresentable_live_edits_into_a_terminal_conflict_copy() {
    let core = KeepassCore::new();
    let initial = Vault::empty("Cloud Vault");
    let initial_bytes = core
        .save_kdbx(&initial, &key(), SaveProfile::recommended())
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        100,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    let mut local_metadata = runtime.get_database_settings(&vault_id).unwrap().metadata;
    local_metadata.name = "Local name".into();
    runtime
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(local_metadata),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();

    let mut remote = core.load_database(&initial_bytes, &key()).unwrap().vault;
    remote.name = "Remote name".into();
    remote.database_name_changed = Some(200);
    remote.settings_changed = Some(200);
    let remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", remote_bytes);

    let response = runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::VaultSourceStatus(status) = response else {
        panic!("expected source status");
    };
    assert_eq!(status.remote_state, "online");
    assert!(
        status
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("VaultKern conflict"))
    );
    assert_eq!(
        runtime
            .get_database_settings(&vault_id)
            .unwrap()
            .metadata
            .name,
        "Remote name"
    );

    let list = runtime
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap();
    let RuntimeResponse::OneDriveItemList(list) = list else {
        panic!("expected OneDrive list");
    };
    assert_eq!(list.items.len(), 2);
}

#[test]
fn repeated_generic_pending_saves_keep_the_fixed_base() {
    let core = KeepassCore::new();
    let initial_bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        200,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    let mut first_edit = runtime.get_database_settings(&vault_id).unwrap().metadata;
    first_edit.name = "first pending name".into();
    runtime
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(first_edit),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();
    runtime.queue_test_onedrive_ambiguous_write(false);
    assert!(matches!(
        retry_publication(&mut runtime, &vault_id).unwrap(),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::SavedToCache
    ));

    let mut second_edit = runtime.get_database_settings(&vault_id).unwrap().metadata;
    second_edit.description = Some("second pending description".into());
    runtime
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(second_edit),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();
    runtime.queue_test_onedrive_ambiguous_write(false);
    assert!(matches!(
        retry_publication(&mut runtime, &vault_id).unwrap(),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::SavedToCache
    ));

    assert_eq!(
        runtime
            .retry_vault_source_sync(&vault_id)
            .unwrap()
            .remote_state,
        "online"
    );
    let durable = core
        .load_database(
            &runtime
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            &key(),
        )
        .unwrap()
        .vault;
    assert_eq!(durable.name, "first pending name");
    assert_eq!(
        durable.description.as_deref(),
        Some("second pending description")
    );
}

#[test]
fn shared_synced_base_changes_do_not_rebase_an_existing_generic_pending_save() {
    let core = KeepassCore::new();
    let initial_bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let mut seed = Runtime::for_tests_at_with_onedrive_item(
        299,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );
    seed.add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    seed.unlock_current_vault_with_password("demo-password")
        .unwrap();
    let seed_vault_id = seed.session_state().active_vault_id.unwrap();
    let mut seed_edit = seed.get_database_settings(&seed_vault_id).unwrap().metadata;
    seed_edit.description = Some("shared lineage".into());
    seed.update_database_settings(
        &seed_vault_id,
        DatabaseSettingsUpdateDto {
            metadata: Some(seed_edit),
            ..DatabaseSettingsUpdateDto::default()
        },
    )
    .unwrap();
    retry_publication(&mut seed, &seed_vault_id).unwrap();
    let initial_bytes = seed
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut first = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        300,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes.clone(),
        cache_dir.path(),
    );
    let mut second = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
        301,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
        cache_dir.path(),
    );
    for runtime in [&mut first, &mut second] {
        runtime
            .add_onedrive_vault_reference("drive-1", "item-1")
            .unwrap();
        runtime
            .unlock_current_vault_with_password("demo-password")
            .unwrap();
    }
    let vault_id = first.session_state().active_vault_id.unwrap();

    let mut first_edit = first.get_database_settings(&vault_id).unwrap().metadata;
    first_edit.name = "first runtime pending name".into();
    first
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(first_edit),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();
    first.queue_test_onedrive_ambiguous_write(false);
    assert!(matches!(
        retry_publication(&mut first, &vault_id).unwrap(),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::SavedToCache
    ));

    let mut second_edit = second.get_database_settings(&vault_id).unwrap().metadata;
    second_edit.description = Some("second runtime remote description".into());
    second
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(second_edit),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();
    retry_publication(&mut second, &vault_id).unwrap();
    first.replace_test_onedrive_item(
        "drive-1",
        "item-1",
        second
            .read_test_onedrive_item_bytes("drive-1", "item-1")
            .unwrap(),
    );

    let retry_status = first.retry_vault_source_sync(&vault_id).unwrap();
    assert_eq!(retry_status.remote_state, "online");
    assert!(
        retry_status
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("VaultKern conflict"))
    );
    let durable = core
        .load_database(
            &first
                .read_test_onedrive_item_bytes("drive-1", "item-1")
                .unwrap(),
            &key(),
        )
        .unwrap()
        .vault;
    assert_eq!(durable.name, "Cloud Vault");
    assert_eq!(
        durable.description.as_deref(),
        Some("second runtime remote description")
    );

    let RuntimeResponse::OneDriveItemList(list) = first
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap()
    else {
        panic!("expected OneDrive item list");
    };
    let conflict = list
        .items
        .iter()
        .find(|item| item.name.contains("VaultKern conflict"))
        .expect("pending candidate must remain recoverable as a conflict copy");
    let conflict_vault = core
        .load_database(
            &first
                .read_test_onedrive_item_bytes(&conflict.drive_id, &conflict.item_id)
                .unwrap(),
            &key(),
        )
        .unwrap()
        .vault;
    assert_eq!(conflict_vault.name, "first runtime pending name");
}

#[test]
fn logical_conflict_splits_once_and_next_save_uses_the_adopted_remote() {
    let core = KeepassCore::new();
    let initial_bytes = core
        .save_kdbx(
            &Vault::empty("Cloud Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    let mut runtime = Runtime::for_tests_at_with_onedrive_item(
        400,
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();
    let mut local = runtime.get_database_settings(&vault_id).unwrap().metadata;
    local.name = "recoverable local name".into();
    runtime
        .update_database_settings(
            &vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(local),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .unwrap();
    let foreign = core
        .save_kdbx(
            &Vault::empty("Foreign Vault"),
            &key(),
            SaveProfile::recommended(),
        )
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", foreign);

    let first = retry_publication(&mut runtime, &vault_id).unwrap();
    let conflict_path = match first {
        RuntimeResponse::SaveVaultResult(result) => {
            assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
            result.conflict_copy_path.unwrap()
        }
        other => panic!("expected conflict copy, got {other:?}"),
    };
    assert!(conflict_path.starts_with("onedrive:"));
    runtime
        .unlock_with_password(&vault_id, "demo-password")
        .expect("unlock the adopted Remote Head");
    assert!(matches!(
        retry_publication(&mut runtime, &vault_id).unwrap(),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Saved
    ));

    let RuntimeResponse::OneDriveItemList(list) = runtime
        .handle(RuntimeCommand::ListOneDriveChildren {
            parent_item_id: None,
        })
        .unwrap()
    else {
        panic!("expected OneDrive item list");
    };
    assert_eq!(
        list.items
            .iter()
            .filter(|item| item.name.contains("VaultKern conflict"))
            .count(),
        1
    );
}
