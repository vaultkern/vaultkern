use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::RuntimeCommand;

#[test]
fn runtime_tracks_recent_local_vaults_and_switches_current_selection() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("personal.kdbx");
    let second = dir.path().join("work.kdbx");
    std::fs::write(&first, &bytes).unwrap();
    std::fs::write(&second, &bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let first_ref = runtime
        .add_local_vault_reference(first.to_str().unwrap())
        .unwrap();
    let second_ref = runtime
        .add_local_vault_reference(second.to_str().unwrap())
        .unwrap();

    let listed = runtime.list_recent_vaults().unwrap();
    assert_eq!(listed.vaults.len(), 2);
    assert_eq!(listed.vaults[0].vault_ref_id, second_ref.vault_ref_id);
    assert!(listed.vaults[0].is_current);

    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    assert!(runtime.session_state().unlocked);

    runtime.set_current_vault(&first_ref.vault_ref_id).unwrap();
    let session = runtime.session_state();
    assert!(!session.unlocked);
    assert!(
        runtime.list_entries(second.to_str().unwrap()).is_err(),
        "switching vaults must discard the previous vault's unlock material"
    );
    assert_eq!(
        session.current_vault_ref_id.as_deref(),
        Some(first_ref.vault_ref_id.as_str())
    );
}

#[test]
fn preloading_after_switching_back_reloads_discarded_encrypted_bytes() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("personal.kdbx");
    let second = dir.path().join("work.kdbx");
    std::fs::write(&first, &bytes).unwrap();
    std::fs::write(&second, &bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let first_ref = runtime
        .add_local_vault_reference(first.to_str().unwrap())
        .unwrap();
    let second_ref = runtime
        .add_local_vault_reference(second.to_str().unwrap())
        .unwrap();

    runtime.set_current_vault(&first_ref.vault_ref_id).unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime.set_current_vault(&second_ref.vault_ref_id).unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime.set_current_vault(&first_ref.vault_ref_id).unwrap();

    runtime.handle(RuntimeCommand::PreloadCurrentVault).unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .expect("returning to a previously unlocked vault must reload its source bytes");
    assert_eq!(
        runtime.session_state().active_vault_id.as_deref(),
        Some(first.to_str().unwrap())
    );
}

#[test]
fn preloading_after_lock_reads_the_current_source_generation() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let initial = core
        .save_kdbx(&Vault::empty("initial"), &key, SaveProfile::recommended())
        .unwrap();
    let replacement = core
        .save_kdbx(
            &Vault::empty("external-generation"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, initial).unwrap();

    let mut runtime = Runtime::for_tests();
    let opened = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&opened.vault_id, "demo-password")
        .unwrap();
    runtime.lock_session();
    std::fs::write(&path, replacement).unwrap();

    runtime.handle(RuntimeCommand::PreloadCurrentVault).unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();

    assert_eq!(
        runtime
            .get_database_settings(&opened.vault_id)
            .unwrap()
            .metadata
            .name,
        "external-generation"
    );
}

#[test]
fn listing_recent_vaults_keeps_current_vault_loading_local_only() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();

    runtime
        .handle(vaultkern_runtime_protocol::RuntimeCommand::ListRecentVaults)
        .unwrap();

    std::fs::remove_file(&path).unwrap();

    let error = runtime
        .unlock_current_vault_with_password("wrong-password")
        .unwrap_err()
        .to_string();

    assert!(error.contains("failed to read vault"), "{error}");
}

#[test]
fn preloading_current_vault_snapshot_keeps_unlock_retry_fast() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();

    runtime
        .handle(vaultkern_runtime_protocol::RuntimeCommand::PreloadCurrentVault)
        .unwrap();

    std::fs::remove_file(&path).unwrap();

    let error = runtime
        .unlock_current_vault_with_password("wrong-password")
        .unwrap_err()
        .to_string();

    assert!(error.contains("failed to unlock vault"), "{error}");
}

#[test]
fn runtime_deletes_recent_vault_reference_without_deleting_database_file() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let vault_ref = runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();

    let listed = runtime
        .handle(
            vaultkern_runtime_protocol::RuntimeCommand::DeleteVaultReference {
                vault_ref_id: vault_ref.vault_ref_id.clone(),
            },
        )
        .unwrap();

    assert!(path.exists());
    assert_eq!(
        listed,
        vaultkern_runtime_protocol::RuntimeResponse::VaultReferenceList(
            vaultkern_runtime_protocol::VaultReferenceListDto { vaults: vec![] }
        )
    );
    assert_eq!(runtime.session_state().current_vault_ref_id, None);
}

#[test]
fn deleting_recent_vault_reference_removes_quick_unlock_credentials() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let vault_ref = runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();

    runtime
        .delete_vault_reference(&vault_ref.vault_ref_id)
        .unwrap();
    runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();

    let listed = runtime.list_recent_vaults().unwrap();
    assert_eq!(listed.vaults.len(), 1);
    assert!(!listed.vaults[0].supports_quick_unlock);
}

#[test]
fn deleting_recent_vault_reference_ignores_quick_unlock_delete_failures() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock_failing_delete();
    let vault_ref = runtime
        .add_local_vault_reference(path.to_str().unwrap())
        .unwrap();
    runtime
        .unlock_current_vault_with_password("demo-password")
        .unwrap();
    runtime
        .enroll_quick_unlock_for_current_vault(Some("demo-password"), None)
        .unwrap();

    let listed = runtime
        .delete_vault_reference(&vault_ref.vault_ref_id)
        .unwrap();

    assert_eq!(listed.vaults.len(), 0);
    assert_eq!(runtime.session_state().current_vault_ref_id, None);
}
