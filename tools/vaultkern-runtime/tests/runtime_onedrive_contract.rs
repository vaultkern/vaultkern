use vaultkern_core::{
    CompositeKey, EntryCreate, EntryTimesUpdate, KeepassCore, SaveProfile, Vault,
};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{
    MergeSummaryDto, RuntimeCommand, RuntimeResponse, SaveVaultStatusDto,
};

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
                notes: String::new(),
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
        initial_bytes,
        cache_dir.path(),
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime.remove_test_onedrive_item("drive-1", "item-1");

    let mut recovered = initial;
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
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id,
            title: "Saved Offline Cache".into(),
            username: "alice".into(),
            password: "saved-password".into(),
            url: "https://saved.example".into(),
            notes: "saved".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();
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
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id,
            title: "Unsaved Remote Failure".into(),
            username: "alice".into(),
            password: "unsaved-password".into(),
            url: "https://unsaved.example".into(),
            notes: "unsaved".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();
    runtime.remove_test_onedrive_item("drive-1", "item-1");

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
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id,
            title: "Pending Local".into(),
            username: "alice".into(),
            password: "pending-password".into(),
            url: "https://pending.example".into(),
            notes: "pending".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();
    runtime.remove_test_onedrive_item("drive-1", "item-1");
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();
    runtime.insert_test_onedrive_item(
        "drive-1",
        "item-1",
        "Cloud Vault.kdbx",
        "alice@example.com",
        initial_bytes,
    );

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
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id,
            title: "Pending Local".into(),
            username: "alice".into(),
            password: "pending-password".into(),
            url: "https://pending.example".into(),
            notes: "pending".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();
    runtime.remove_test_onedrive_item("drive-1", "item-1");
    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    let mut remote_changed = initial;
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

    runtime
        .handle(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    let uploaded = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let database = core.load_database(&uploaded, &key()).unwrap();
    let entries = core.project_vault(&database.vault).root.entries;
    assert!(entries.iter().any(|entry| entry.title == "Pending Local"));
    assert!(entries.iter().any(|entry| entry.title == "Remote"));
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
fn runtime_merges_changed_onedrive_source_before_save() {
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
        initial_bytes,
    );
    let reference = runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let vault_id = runtime.session_state().active_vault_id.unwrap();

    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: local_entry_id,
            title: "Local Updated".into(),
            username: "alice".into(),
            password: "local-password".into(),
            url: "https://local.example/app".into(),
            notes: "local edit".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();

    let mut external = initial;
    create_entry(&core, &mut external, "External", "bob", 90);
    let external_bytes = core
        .save_kdbx(&external, &key(), SaveProfile::recommended())
        .unwrap();
    runtime.replace_test_onedrive_item("drive-1", "item-1", external_bytes);

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        })
        .unwrap();

    match response {
        RuntimeResponse::SaveVaultResult(result) => {
            assert_eq!(result.status, SaveVaultStatusDto::Merged);
            assert_eq!(
                result.merge_summary,
                Some(MergeSummaryDto {
                    merged_entries: 1,
                    history_snapshots_added: 0,
                    meta_conflicts_resolved: 0,
                    icon_conflicts_resolved: 0,
                })
            );
        }
        other => panic!("expected save result, got {other:?}"),
    }

    runtime.set_current_vault(&reference.vault_ref_id).unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    let entries = runtime.list_entries(&vault_id).unwrap();
    assert!(entries.iter().any(|entry| entry.title == "Local Updated"));
    assert!(entries.iter().any(|entry| entry.title == "External"));
}
