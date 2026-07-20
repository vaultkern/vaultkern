#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, EntryCreate, EntryTimesUpdate, EntryUpdate, KeepassCore, SaveProfile, Vault,
};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{
    DatabaseCredentialsUpdateDto, DatabaseEncryptionSettingsDto, DatabaseHistorySettingsDto,
    DatabaseMetadataSettingsDto, DatabasePublicMetadataSettingsDto, DatabaseRecycleBinSettingsDto,
    DatabaseSettingsUpdateDto, RuntimeCommand, RuntimeResponse, SaveVaultResultDto,
    SaveVaultStatusDto,
};

fn saved_response() -> RuntimeResponse {
    RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
        status: SaveVaultStatusDto::Saved,
        merge_summary: None,
        conflict_copy_path: None,
    })
}

fn create_entry_in_root(
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

fn fixture_path(name: &str) -> std::path::PathBuf {
    if let Some(root) = std::env::var_os("VAULTKERN_EXTERNAL_FIXTURES") {
        return std::path::PathBuf::from(root).join(name);
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/kdbx")
        .join(name)
}

#[test]
fn runtime_opens_legacy_kdbx2_and_kdbx3_and_migrates_them_on_save() {
    for fixture in ["Format200.kdbx", "Format300.kdbx"] {
        let source = fixture_path(fixture);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(fixture);
        std::fs::copy(source, &path).unwrap();

        let mut runtime = Runtime::for_tests();
        let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
        runtime
            .unlock_with_password(&opened.vault_id, "a")
            .unwrap_or_else(|error| panic!("{fixture} must stay on the password path: {error:#}"));
        runtime.save_vault(&opened.vault_id).unwrap();

        let migrated = std::fs::read(&path).unwrap();
        let inspection = KeepassCore::new().inspect_database(&migrated).unwrap();
        assert_eq!(
            inspection.header.version,
            vaultkern_core::KdbxVersion::V4_1,
            "{fixture}"
        );
        let mut key = CompositeKey::default();
        key.add_password("a");
        KeepassCore::new()
            .load_kdbx(&migrated, &key)
            .unwrap_or_else(|error| panic!("migrated {fixture} must reopen: {error:#}"));
    }
}

#[test]
fn runtime_migrates_unchanged_legacy_onedrive_vault_on_save() {
    let bytes = std::fs::read(fixture_path("Format300.kdbx")).unwrap();
    let mut runtime = Runtime::for_tests_with_onedrive_item(
        "drive-1",
        "item-1",
        "legacy.kdbx",
        "alice@example.com",
        bytes,
    );
    runtime
        .add_onedrive_vault_reference("drive-1", "item-1")
        .unwrap();
    runtime
        .unlock_current_vault_with_password("a")
        .expect("KDBX 3 OneDrive vault unlock");
    let vault_id = runtime
        .session_state()
        .active_vault_id
        .expect("active OneDrive vault");

    runtime.save_vault(&vault_id).unwrap();

    let migrated = runtime
        .read_test_onedrive_item_bytes("drive-1", "item-1")
        .unwrap();
    let inspection = KeepassCore::new().inspect_database(&migrated).unwrap();
    assert_eq!(inspection.header.version, vaultkern_core::KdbxVersion::V4_1);
    assert_eq!(runtime.test_onedrive_access_counts().writes, 1);
}

#[test]
fn runtime_requires_legacy_migration_save_before_quick_unlock_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.kdbx");
    std::fs::copy(fixture_path("Format300.kdbx"), &path).unwrap();
    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime.unlock_with_password(&opened.vault_id, "a").unwrap();

    let error = runtime
        .enable_quick_unlock_for_current_vault(Some("a"), None)
        .expect_err("legacy source must be saved before quick-unlock enrollment");

    assert!(
        error
            .to_string()
            .contains("save the migrated vault before enabling quick unlock"),
        "{error:#}"
    );

    runtime.save_vault(&opened.vault_id).unwrap();
    runtime
        .enable_quick_unlock_for_current_vault(Some("a"), None)
        .expect("saved migration can enroll quick unlock");
    runtime.lock_session();
    runtime
        .unlock_current_vault_with_quick_unlock()
        .expect("migrated vault can quick-unlock after enrollment");
}

#[test]
fn runtime_can_open_unlock_mutate_and_save_local_vault() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    let current_vault_ref_id = runtime.session_state().current_vault_ref_id;

    assert!(current_vault_ref_id.is_some());

    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();
    let session = runtime.session_state();

    assert!(session.unlocked);
    assert_eq!(
        session.active_vault_id.as_deref(),
        Some(vault.vault_id.as_str())
    );
    assert_eq!(session.current_vault_ref_id, current_vault_ref_id);

    runtime.lock_session();

    let session = runtime.session_state();
    assert!(!session.unlocked);
    assert_eq!(session.active_vault_id, None);
    assert_eq!(session.current_vault_ref_id, current_vault_ref_id);
}

#[test]
fn runtime_browser_v0_loop_finds_edits_saves_and_reopens_local_fill_candidate() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(
            &Vault::empty("browser-v0"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create browser v0 vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("browser-v0.kdbx");
    std::fs::write(&path, bytes).expect("write browser v0 vault");

    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open local vault");
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .expect("unlock local vault");

    let root_id = runtime
        .list_groups(&handle.vault_id)
        .expect("list groups")
        .root
        .id;

    let exact = match runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: handle.vault_id.clone(),
            parent_group_id: root_id.clone(),
            title: "Exact Login".into(),
            username: "alice".into(),
            password: "old-secret".into(),
            url: "https://app.example.com/login".into(),
            notes: "created from browser v0 contract".into(),
            totp_uri: None,
        })
        .expect("create exact login")
    {
        RuntimeResponse::EntryDetail(detail) => detail,
        other => panic!("expected entry detail, got {other:?}"),
    };

    runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: handle.vault_id.clone(),
            parent_group_id: root_id.clone(),
            title: "Parent Login".into(),
            username: "parent".into(),
            password: "parent-secret".into(),
            url: "https://example.com/login".into(),
            notes: String::new(),
            totp_uri: None,
        })
        .expect("create parent login");
    runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: handle.vault_id.clone(),
            parent_group_id: root_id,
            title: "Unrelated Tenant".into(),
            username: "mallory".into(),
            password: "tenant-secret".into(),
            url: "https://login.bank.co.uk/login".into(),
            notes: String::new(),
            totp_uri: None,
        })
        .expect("create unrelated tenant");

    let candidates = match runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id.clone(),
            url: "https://app.example.com/login?next=%2Fdashboard".into(),
        })
        .expect("find fill candidates")
    {
        RuntimeResponse::FillCandidates(candidates) => candidates.entries,
        other => panic!("expected fill candidates, got {other:?}"),
    };
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].id, exact.id);
    assert_eq!(candidates[0].title, "Exact Login");
    assert_eq!(candidates[1].title, "Parent Login");

    let unrelated = match runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id.clone(),
            url: "https://evil.co.uk/login".into(),
        })
        .expect("find unrelated candidates")
    {
        RuntimeResponse::FillCandidates(candidates) => candidates.entries,
        other => panic!("expected fill candidates, got {other:?}"),
    };
    assert!(unrelated.is_empty());

    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: handle.vault_id.clone(),
            entry_id: exact.id.clone(),
            title: "Exact Login".into(),
            username: "alice@example.com".into(),
            password: "rotated-secret".into(),
            url: "https://app.example.com/login".into(),
            notes: "rotated from browser v0 contract".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .expect("update exact login");

    assert_eq!(
        runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: handle.vault_id.clone(),
            })
            .expect("save local vault"),
        saved_response()
    );

    let mut reopened_runtime = Runtime::for_tests();
    let reopened = reopened_runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("reopen local vault");
    reopened_runtime
        .unlock_with_password(&reopened.vault_id, "demo-password")
        .expect("unlock reopened vault");

    let reopened_candidates = match reopened_runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: reopened.vault_id.clone(),
            url: "https://app.example.com/login".into(),
        })
        .expect("find reopened candidates")
    {
        RuntimeResponse::FillCandidates(candidates) => candidates.entries,
        other => panic!("expected fill candidates, got {other:?}"),
    };
    assert_eq!(reopened_candidates[0].id, exact.id);

    let detail = match reopened_runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: reopened.vault_id,
            entry_id: exact.id,
        })
        .expect("get reopened entry detail")
    {
        RuntimeResponse::EntryDetail(detail) => detail,
        other => panic!("expected entry detail, got {other:?}"),
    };
    assert_eq!(detail.username, "alice@example.com");
    assert_eq!(detail.password, "rotated-secret");
    assert_eq!(detail.notes, "rotated from browser v0 contract");
}

#[test]
fn runtime_unlocks_password_plus_key_file_vault_from_key_file_path() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("password-plus-key.kdbx");
    let key_path = dir.path().join("password-plus-key.key");
    std::fs::copy(fixture_path("KeyFileProtected.kdbx"), &db_path).unwrap();
    std::fs::copy(fixture_path("KeyFileProtected.key"), &key_path).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(db_path.to_str().unwrap()).unwrap();
    runtime
        .unlock_vault(&vault.vault_id, Some("a"), Some(key_path.to_str().unwrap()))
        .unwrap();

    let entries = runtime.list_entries(&vault.vault_id).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].title, "entry1");
}

#[test]
fn runtime_unlocks_key_file_only_vault_from_key_file_path() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("key-only.kdbx");
    let key_path = dir.path().join("key-only.key");
    std::fs::copy(fixture_path("KeyFileProtectedNoPassword.kdbx"), &db_path).unwrap();
    std::fs::copy(fixture_path("KeyFileProtectedNoPassword.key"), &key_path).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(db_path.to_str().unwrap()).unwrap();
    runtime
        .unlock_vault(&vault.vault_id, None, Some(key_path.to_str().unwrap()))
        .unwrap();

    let entries = runtime.list_entries(&vault.vault_id).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].title, "entry1");
}

#[test]
fn runtime_saves_key_file_unlocked_vault_with_same_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("key-save.kdbx");
    let key_path = dir.path().join("key-save.key");
    std::fs::copy(fixture_path("KeyFileProtectedNoPassword.kdbx"), &db_path).unwrap();
    std::fs::copy(fixture_path("KeyFileProtectedNoPassword.key"), &key_path).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(db_path.to_str().unwrap()).unwrap();
    runtime
        .unlock_vault(&vault.vault_id, None, Some(key_path.to_str().unwrap()))
        .unwrap();

    assert_eq!(
        runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault.vault_id.clone(),
            })
            .unwrap(),
        saved_response()
    );

    runtime.lock_session();
    let reopened = runtime.open_local_vault(db_path.to_str().unwrap()).unwrap();
    runtime
        .unlock_vault(&reopened.vault_id, None, Some(key_path.to_str().unwrap()))
        .unwrap();
    assert_eq!(runtime.list_entries(&reopened.vault_id).unwrap().len(), 2);
}

#[test]
fn runtime_reports_saved_when_source_has_not_changed() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault.vault_id.clone(),
        })
        .unwrap();

    assert_eq!(response, saved_response());
}

#[test]
fn runtime_updates_database_settings_without_retaining_master_credentials() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("old-password");
    let bytes = core
        .save_kdbx(&Vault::empty("settings"), &key, SaveProfile::recommended())
        .expect("create vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.kdbx");
    std::fs::write(&path, bytes).expect("write vault");

    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .expect("unlock vault");

    let before = runtime
        .get_database_settings(&handle.vault_id)
        .expect("get initial settings");
    assert_eq!(before.metadata.name, "settings");
    assert_eq!(before.encryption.compression, "gzip");
    assert!(before.has_password);
    let retained_kdf = before.encryption.kdf.clone();

    let updated = runtime
        .update_database_settings(
            &handle.vault_id,
            DatabaseSettingsUpdateDto {
                metadata: Some(DatabaseMetadataSettingsDto {
                    name: "Engineering Vault".into(),
                    description: Some("Database settings contract".into()),
                    default_username: Some("ops".into()),
                }),
                public_metadata: Some(DatabasePublicMetadataSettingsDto {
                    display_name: Some("Engineering".into()),
                    color: Some("#2f6f73".into()),
                    icon: Some("database".into()),
                }),
                history: Some(DatabaseHistorySettingsDto {
                    max_items_per_entry: Some(9),
                    max_total_size_bytes: Some(99_000),
                }),
                recycle_bin: Some(DatabaseRecycleBinSettingsDto { enabled: false }),
                encryption: Some(DatabaseEncryptionSettingsDto {
                    compression: "none".into(),
                    cipher: "chacha20".into(),
                    kdf: retained_kdf.clone(),
                }),
                credentials: None,
                autosave_delay_seconds: Some(45),
            },
        )
        .expect("update settings");

    assert_eq!(updated.metadata.name, "Engineering Vault");
    assert_eq!(
        updated.public_metadata.display_name.as_deref(),
        Some("Engineering")
    );
    assert_eq!(updated.history.max_items_per_entry, Some(9));
    assert!(!updated.recycle_bin.enabled);
    assert_eq!(updated.encryption.compression, "none");
    assert_eq!(updated.encryption.cipher, "chacha20");
    assert_eq!(updated.encryption.kdf, retained_kdf);
    assert_eq!(updated.autosave_delay_seconds, Some(45));

    runtime
        .save_vault(&handle.vault_id)
        .expect("save with new settings");

    let saved = std::fs::read(&path).expect("read saved vault");
    let reloaded = core
        .load_database(&saved, &key)
        .expect("reload with the original master credential");
    assert_eq!(reloaded.vault.name, "Engineering Vault");
    assert_eq!(
        reloaded.vault.description.as_deref(),
        Some("Database settings contract")
    );
    assert_eq!(reloaded.vault.default_username.as_deref(), Some("ops"));
    assert_eq!(reloaded.vault.history_max_items, Some(9));
    assert_eq!(reloaded.vault.history_max_size, Some(99_000));
    assert_eq!(reloaded.vault.recycle_bin_enabled, Some(false));
    assert_eq!(
        reloaded.vault.public_custom_data.get("display-name"),
        Some(&b"Engineering".to_vec())
    );
    assert_eq!(
        reloaded.inspection.header.compression,
        vaultkern_core::Compression::None
    );
    assert_eq!(
        reloaded.inspection.header.cipher,
        vaultkern_core::KdbxCipher::ChaCha20
    );
}

#[test]
fn runtime_rejects_password_removal_without_a_fresh_authenticated_flow() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("initial-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("passwordless"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("passwordless.kdbx");
    std::fs::write(&path, bytes).expect("write vault");

    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "initial-password")
        .expect("unlock vault");
    let error = runtime
        .update_database_settings(
            &handle.vault_id,
            DatabaseSettingsUpdateDto {
                credentials: Some(DatabaseCredentialsUpdateDto {
                    new_password: None,
                    remove_password: true,
                }),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .expect_err("password removal needs a fresh authenticated flow");
    assert!(
        error
            .to_string()
            .contains("fresh authenticated credential-update flow")
    );
    runtime
        .save_vault(&handle.vault_id)
        .expect("save unchanged master credential");

    let empty_key = CompositeKey::default();
    let saved = std::fs::read(&path).unwrap();
    assert!(core.load_database(&saved, &empty_key).is_err());
    let reloaded = core
        .load_database(&saved, &key)
        .expect("reload with password");
    assert_eq!(reloaded.vault.name, "passwordless");
}

#[test]
fn runtime_history_settings_limit_entry_history_after_updates() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("history-limits"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("history-limits.kdbx");
    std::fs::write(&path, bytes).expect("write vault");

    let mut runtime = Runtime::for_tests_at(100);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .expect("unlock vault");
    let root_id = runtime.list_groups(&handle.vault_id).unwrap().root.id;
    let created = runtime
        .create_entry(
            &handle.vault_id,
            &root_id,
            "First".into(),
            "alice".into(),
            "secret".into(),
            "https://example.com".into(),
            "initial".into(),
            None,
        )
        .expect("create entry");

    runtime
        .update_database_settings(
            &handle.vault_id,
            DatabaseSettingsUpdateDto {
                history: Some(DatabaseHistorySettingsDto {
                    max_items_per_entry: Some(1),
                    max_total_size_bytes: Some(1024 * 1024),
                }),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .expect("set history limit");

    runtime
        .update_entry_fields(
            &handle.vault_id,
            &created.id,
            "Second".into(),
            "alice".into(),
            "secret-2".into(),
            "https://example.com/2".into(),
            "second".into(),
            None,
            vec![],
        )
        .expect("first update");
    runtime
        .update_entry_fields(
            &handle.vault_id,
            &created.id,
            "Third".into(),
            "alice".into(),
            "secret-3".into(),
            "https://example.com/3".into(),
            "third".into(),
            None,
            vec![],
        )
        .expect("second update");

    let history = runtime
        .list_entry_history(&handle.vault_id, &created.id)
        .expect("list history");
    assert_eq!(history.items.len(), 1);
    assert_eq!(history.items[0].title, "Second");
}

#[test]
fn runtime_history_settings_limit_total_history_size_after_updates() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("history-size"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("history-size.kdbx");
    std::fs::write(&path, bytes).expect("write vault");

    let mut runtime = Runtime::for_tests_at(100);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .expect("unlock vault");
    let root_id = runtime.list_groups(&handle.vault_id).unwrap().root.id;
    let created = runtime
        .create_entry(
            &handle.vault_id,
            &root_id,
            "Tiny".into(),
            "alice".into(),
            "secret".into(),
            "https://example.com".into(),
            "initial".into(),
            None,
        )
        .expect("create entry");

    runtime
        .update_database_settings(
            &handle.vault_id,
            DatabaseSettingsUpdateDto {
                history: Some(DatabaseHistorySettingsDto {
                    max_items_per_entry: Some(10),
                    max_total_size_bytes: Some(1),
                }),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .expect("set total history size limit");
    runtime
        .update_entry_fields(
            &handle.vault_id,
            &created.id,
            "Large".into(),
            "alice".into(),
            "secret-2".into(),
            "https://example.com/large".into(),
            "this snapshot is larger than one byte".into(),
            None,
            vec![],
        )
        .expect("update entry");

    let history = runtime
        .list_entry_history(&handle.vault_id, &created.id)
        .expect("list history");
    assert!(history.items.is_empty());
}

#[test]
fn runtime_writes_conflict_copy_without_overwriting_external_entries() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut initial_vault = Vault::empty("demo");
    let local_entry_id = create_entry_in_root(&core, &mut initial_vault, "Local", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial_vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, initial_bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(100);
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault.vault_id.clone(),
            entry_id: local_entry_id.clone(),
            title: "Local Updated".into(),
            username: "alice".into(),
            password: "local-password".into(),
            url: "https://local.example/app".into(),
            notes: "local edit".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();

    let mut external_vault = initial_vault.clone();
    create_entry_in_root(&core, &mut external_vault, "External", "bob", 90);
    let external_bytes = core
        .save_kdbx(&external_vault, &key, SaveProfile::recommended())
        .unwrap();
    std::fs::write(&path, external_bytes).unwrap();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault.vault_id.clone(),
        })
        .unwrap();

    let RuntimeResponse::SaveVaultResult(result) = response else {
        panic!("expected save vault result, got {response:?}");
    };
    assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
    assert_eq!(result.merge_summary, None);
    let conflict_path = result
        .conflict_copy_path
        .expect("conflict copy path must be returned");

    let source = core
        .load_kdbx(&std::fs::read(&path).unwrap(), &key)
        .expect("reload externally changed source");
    assert!(
        source
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Local")
    );
    assert!(
        source
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "External")
    );
    assert!(
        !source
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Local Updated")
    );

    let conflict = core
        .load_kdbx(&std::fs::read(conflict_path).unwrap(), &key)
        .expect("reload local conflict copy");
    assert!(
        conflict
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Local Updated")
    );
    assert!(
        !conflict
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "External")
    );
}

#[test]
fn runtime_conflict_copy_keeps_local_mutation_while_source_stays_external() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut initial_vault = Vault::empty("demo");
    let entry_id = create_entry_in_root(&core, &mut initial_vault, "Shared", "alice", 10);
    let initial_bytes = core
        .save_kdbx(&initial_vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, initial_bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(200);
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault.vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Local Wins".into(),
            username: "alice".into(),
            password: "local-secret".into(),
            url: "https://local.example".into(),
            notes: "local".into(),
            totp_uri: None,
            custom_fields: vec![],
        })
        .unwrap();

    let mut external_vault = initial_vault.clone();
    core.update_entry_fields(
        &mut external_vault,
        &entry_id,
        EntryUpdate {
            title: Some("External Older".into()),
            username: None,
            password: Some("external-secret".into()),
            url: None,
            notes: None,
        },
    )
    .unwrap();
    core.update_entry_times(
        &mut external_vault,
        &entry_id,
        EntryTimesUpdate {
            created_at: None,
            modified_at: Some(100),
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    )
    .unwrap();
    let external_bytes = core
        .save_kdbx(&external_vault, &key, SaveProfile::recommended())
        .unwrap();
    std::fs::write(&path, external_bytes).unwrap();

    let response = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault.vault_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::SaveVaultResult(result) = response else {
        panic!("expected save vault result, got {response:?}");
    };
    assert_eq!(result.status, SaveVaultStatusDto::ConflictCopy);
    let conflict_path = result
        .conflict_copy_path
        .expect("conflict copy path must be returned");

    let source = core
        .load_kdbx(&std::fs::read(&path).unwrap(), &key)
        .expect("reload external source");
    let source_detail = core
        .project_entry_detail(&source, &entry_id)
        .expect("project external entry");
    assert_eq!(source_detail.title, "External Older");
    assert_eq!(source_detail.password, "external-secret");

    let conflict = core
        .load_kdbx(&std::fs::read(conflict_path).unwrap(), &key)
        .expect("reload local conflict copy");
    let conflict_detail = core
        .project_entry_detail(&conflict, &entry_id)
        .expect("project local conflict entry");
    assert_eq!(conflict_detail.title, "Local Wins");
    assert_eq!(conflict_detail.password, "local-secret");
}

#[test]
fn runtime_persists_created_entry_after_save_roundtrip() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();

    let root_id = runtime.list_groups(&vault.vault_id).unwrap().root.id;
    let created = runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: vault.vault_id.clone(),
            parent_group_id: root_id,
            title: "Created".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "created by runtime".into(),
            totp_uri: None,
        })
        .unwrap();
    let created_id = match created {
        RuntimeResponse::EntryDetail(detail) => detail.id,
        other => panic!("expected entry detail, got {other:?}"),
    };

    assert_eq!(
        runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault.vault_id.clone(),
            })
            .unwrap(),
        saved_response()
    );

    let reopened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&reopened.vault_id, "demo-password")
        .unwrap();
    let entries = runtime.list_entries(&reopened.vault_id).unwrap();

    assert!(entries.iter().any(|entry| entry.id == created_id));
    assert!(entries.iter().any(|entry| entry.title == "Created"));
}

#[test]
fn runtime_persists_updated_and_deleted_entries_after_save_roundtrip() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();

    let root_id = runtime.list_groups(&vault.vault_id).unwrap().root.id;
    let created = runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: vault.vault_id.clone(),
            parent_group_id: root_id,
            title: "Created".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "created by runtime".into(),
            totp_uri: None,
        })
        .unwrap();
    let entry_id = match created {
        RuntimeResponse::EntryDetail(detail) => detail.id,
        other => panic!("expected entry detail, got {other:?}"),
    };

    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: vault.vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Updated".into(),
            username: "alice".into(),
            password: "secret-2".into(),
            url: "https://example.com/app".into(),
            notes: "updated by runtime".into(),
            totp_uri: None,
            custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
                key: "Region".into(),
                value: "us".into(),
                protected: false,
            }],
        })
        .unwrap();
    assert_eq!(
        runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: vault.vault_id.clone(),
            })
            .unwrap(),
        saved_response()
    );

    let mut reopened_runtime = Runtime::for_tests();
    let reopened = reopened_runtime
        .open_local_vault(path.to_str().unwrap())
        .unwrap();
    reopened_runtime
        .unlock_with_password(&reopened.vault_id, "demo-password")
        .unwrap();

    let updated_detail = match reopened_runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: reopened.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap()
    {
        RuntimeResponse::EntryDetail(detail) => detail,
        other => panic!("expected entry detail, got {other:?}"),
    };
    assert_eq!(updated_detail.title, "Updated");
    assert_eq!(updated_detail.password, "secret-2");
    assert_eq!(updated_detail.custom_fields.len(), 1);
    assert_eq!(updated_detail.custom_fields[0].key, "Region");
    assert_eq!(updated_detail.custom_fields[0].value, "us");

    reopened_runtime
        .handle(RuntimeCommand::DeleteEntry {
            vault_id: reopened.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    assert_eq!(
        reopened_runtime
            .handle(RuntimeCommand::SaveVault {
                vault_id: reopened.vault_id.clone(),
            })
            .unwrap(),
        saved_response()
    );

    let mut final_runtime = Runtime::for_tests();
    let final_handle = final_runtime
        .open_local_vault(path.to_str().unwrap())
        .unwrap();
    final_runtime
        .unlock_with_password(&final_handle.vault_id, "demo-password")
        .unwrap();
    let entries = final_runtime.list_entries(&final_handle.vault_id).unwrap();

    assert!(!entries.iter().any(|entry| entry.id == entry_id));
    assert!(!entries.iter().any(|entry| entry.title == "Updated"));
}
