use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Verifier},
    pkcs8::DecodePrivateKey,
};
use sha2::{Digest, Sha256};
use vaultkern_core::{
    Attachment, CompositeKey, CustomField, Entry, EntryFieldProtection, Group, KeepassCore,
    PasskeyRecord, SaveProfile, TotpSpec, Vault,
};
use vaultkern_runtime::{QuickUnlockReconciliationCredentials, Runtime};
use vaultkern_runtime_protocol::{
    DatabaseCredentialsUpdateDto, DatabaseSettingsUpdateDto, EntryPasskeyDto,
    EntryPasskeyUpdateDto, PasskeyCeremonyDeliveryStateDto, PasskeyCeremonyDurableStateDto,
    PasskeyCeremonyKindDto, PasskeyCeremonyLedgerDto, PasskeyCeremonyPhaseDto, PasskeyFrameKindDto,
    PasskeyUserVerificationMethodDto, PasskeyUserVerificationRequirementDto, RuntimeCommand,
    RuntimeResponse,
};

const TEST_PASSKEY_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCrpkgmenhRkrdg3Y\n7G0+YmeyFRGgpisH5R5e75gwVHGhRANCAASOCmJegf0Fo1V7ixK+W5u/Jx8bpbIq\nCY0G7WFVp5KD6xMSKPekuRmz+kxK2wiZrN6MrH8kbCDmwLZRxnM73nXs\n-----END PRIVATE KEY-----\n";

fn clone_test_passkey_update(passkey: &EntryPasskeyUpdateDto) -> EntryPasskeyUpdateDto {
    serde_json::from_value(serde_json::to_value(passkey).expect("serialize test passkey update"))
        .expect("deserialize test passkey update")
}

#[test]
fn runtime_returns_group_tree_entry_list_detail_and_fill_candidates_for_unlocked_local_vault() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();

    let mut entry = Entry::new("Example");
    entry.username = "alice".into();
    entry.password = "secret".into();
    entry.url = "https://app.example.com/login".into();
    entry.notes = "runtime contract".into();
    entry.field_protection = EntryFieldProtection {
        protect_title: false,
        protect_username: true,
        protect_password: true,
        protect_url: false,
        protect_notes: false,
    };
    entry.attributes.insert(
        "RecoveryCode".into(),
        CustomField {
            value: "one-time-code".into(),
            protected: true,
        },
    );
    entry.attachments.insert(
        "backup-codes.txt".into(),
        Attachment {
            name: "backup-codes.txt".into(),
            data: vec![1; 128],
            protect_in_memory: true,
        },
    );
    entry.totp = TotpSpec::parse_otpauth(
        "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test",
    )
    .ok();
    let entry_id = entry.id.to_string();
    let mut child_group = Group::new("General");
    let child_group_id = child_group.id.to_string();
    child_group.entries.push(entry);
    vault.root.children.push(child_group);

    let mut extra = Entry::new("Other");
    extra.username = "bob".into();
    extra.url = "https://example.net".into();
    vault.root.entries.push(extra);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let groups = runtime
        .handle(RuntimeCommand::ListGroups {
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert_eq!(
        groups,
        RuntimeResponse::GroupTree(vaultkern_runtime_protocol::GroupTreeDto {
            root: vaultkern_runtime_protocol::GroupNodeDto {
                id: root_id.clone(),
                title: "demo".into(),
                entry_count: 1,
                child_count: 1,
                children: vec![vaultkern_runtime_protocol::GroupNodeDto {
                    id: child_group_id.clone(),
                    title: "General".into(),
                    entry_count: 1,
                    child_count: 0,
                    children: vec![],
                }],
            },
        })
    );

    let list = runtime
        .handle(RuntimeCommand::ListEntries {
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert_eq!(
        list,
        RuntimeResponse::EntryList(vaultkern_runtime_protocol::EntryListDto {
            entries: vec![
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: vault.root.entries[0].id.to_string(),
                    title: "Other".into(),
                    username: "bob".into(),
                    url: "https://example.net".into(),
                    group_id: root_id.clone(),
                    has_totp: false,
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: entry_id.clone(),
                    title: "Example".into(),
                    username: "alice".into(),
                    url: "https://app.example.com/login".into(),
                    group_id: child_group_id.clone(),
                    has_totp: true,
                },
            ],
        })
    );

    let detail = runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    assert_eq!(
        detail,
        RuntimeResponse::EntryDetail(vaultkern_runtime_protocol::EntryDetailDto {
            id: entry_id.clone(),
            title: "Example".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://app.example.com/login".into(),
            notes: "runtime contract".into(),
            modified_at: 0,
            totp: Some("287082".into()),
            totp_uri: Some(
                "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test&algorithm=SHA1&digits=6&period=30"
                    .into(),
            ),
            passkey: None,
            field_protection: vaultkern_runtime_protocol::EntryFieldProtectionDto {
                protect_title: false,
                protect_username: true,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            },
            custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
                key: "RecoveryCode".into(),
                value: "one-time-code".into(),
                protected: true,
            }],
            attachments: vec![vaultkern_runtime_protocol::EntryAttachmentDto {
                name: "backup-codes.txt".into(),
                size: 128,
                protect_in_memory: true,
            }],
        })
    );

    let fill = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id.clone(),
            url: "https://example.com/dashboard".into(),
        })
        .unwrap();
    assert_eq!(
        fill,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: vec![vaultkern_runtime_protocol::EntrySummaryDto {
                id: entry_id,
                title: "Example".into(),
                username: "alice".into(),
                url: "https://app.example.com/login".into(),
                group_id: child_group_id,
                has_totp: true,
            }],
        })
    );
}

#[test]
fn runtime_unlocks_current_vault_with_device_quick_unlock() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();
    vault.root.entries.push(Entry::new("Quick"));
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quick.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();
    let vault_ref_id = runtime
        .session_state()
        .current_vault_ref_id
        .expect("current vault reference");

    assert!(
        runtime
            .reconcile_quick_unlock(
                true,
                Some(
                    QuickUnlockReconciliationCredentials::from_protocol_input(
                        Some("demo-password".into()),
                        None,
                    )
                    .bound_to_vault_ref(&vault_ref_id)
                ),
            )
            .unwrap()
    );

    let recent = runtime.handle(RuntimeCommand::ListRecentVaults).unwrap();
    let RuntimeResponse::VaultReferenceList(recent) = recent else {
        panic!("expected recent vault list");
    };
    assert_eq!(recent.vaults.len(), 1);
    assert!(recent.vaults[0].supports_quick_unlock);

    runtime.handle(RuntimeCommand::LockSession).unwrap();
    let unlocked = runtime
        .handle(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)
        .unwrap();
    let RuntimeResponse::SessionState(state) = unlocked else {
        panic!("expected session state");
    };
    assert!(state.unlocked);
    assert_eq!(
        state.active_vault_id.as_deref(),
        Some(handle.vault_id.as_str())
    );
    assert!(state.supports_biometric_unlock);

    let groups = runtime
        .handle(RuntimeCommand::ListGroups {
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert_eq!(
        groups,
        RuntimeResponse::GroupTree(vaultkern_runtime_protocol::GroupTreeDto {
            root: vaultkern_runtime_protocol::GroupNodeDto {
                id: root_id,
                title: "demo".into(),
                entry_count: 1,
                child_count: 0,
                children: vec![],
            },
        })
    );

    assert!(runtime.reconcile_quick_unlock(false, None).unwrap());
    let recent = runtime.handle(RuntimeCommand::ListRecentVaults).unwrap();
    let RuntimeResponse::VaultReferenceList(recent) = recent else {
        panic!("expected recent vault list");
    };
    assert!(!recent.vaults[0].supports_quick_unlock);
}

#[test]
fn runtime_rejects_implicit_password_change_and_keeps_quick_unlock() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("old-password");
    let bytes = core
        .save_kdbx(&Vault::empty("rotating"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rotating.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .unwrap();
    runtime
        .enroll_quick_unlock_for_current_vault(Some("old-password"), None)
        .unwrap();

    let error = runtime
        .update_database_settings(
            &handle.vault_id,
            DatabaseSettingsUpdateDto {
                credentials: Some(DatabaseCredentialsUpdateDto {
                    new_password: Some("new-password".into()),
                    remove_password: false,
                }),
                ..DatabaseSettingsUpdateDto::default()
            },
        )
        .expect_err("password changes require a fresh authenticated flow");
    assert!(
        error
            .to_string()
            .contains("fresh authenticated credential-update flow")
    );
    runtime.handle(RuntimeCommand::LockSession).unwrap();

    let unlocked = runtime
        .handle(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)
        .unwrap();
    let RuntimeResponse::SessionState(state) = unlocked else {
        panic!("expected session state");
    };
    assert!(state.unlocked);
    assert_eq!(
        state.active_vault_id.as_deref(),
        Some(handle.vault_id.as_str())
    );
}

#[test]
fn runtime_deletes_quick_unlock_credentials_when_stored_password_is_stale() {
    let core = KeepassCore::new();
    let mut old_key = CompositeKey::default();
    old_key.add_password("old-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("stale-quick-unlock"),
            &old_key,
            SaveProfile::recommended(),
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stale-quick-unlock.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .unwrap();
    runtime
        .enroll_quick_unlock_for_current_vault(Some("old-password"), None)
        .unwrap();
    runtime.handle(RuntimeCommand::LockSession).unwrap();

    let mut new_key = CompositeKey::default();
    new_key.add_password("new-password");
    let replacement = core
        .save_kdbx(
            &Vault::empty("stale-quick-unlock"),
            &new_key,
            SaveProfile::recommended(),
        )
        .unwrap();
    std::fs::write(&path, replacement).unwrap();
    runtime.open_local_vault(path.to_str().unwrap()).unwrap();

    let quick_unlock = runtime.handle(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock);
    assert!(quick_unlock.is_err());

    let recent = runtime.handle(RuntimeCommand::ListRecentVaults).unwrap();
    let RuntimeResponse::VaultReferenceList(recent) = recent else {
        panic!("expected recent vault list");
    };
    assert!(!recent.vaults[0].supports_quick_unlock);
}

#[test]
fn runtime_sorts_fill_candidates_by_host_then_path_similarity() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();

    let mut descendant = Entry::new("Descendant Host");
    descendant.username = "descendant".into();
    descendant.url = "https://auth.app.example.com/login/reset".into();
    let descendant_id = descendant.id.to_string();
    vault.root.entries.push(descendant);

    let mut exact_path = Entry::new("Exact Path");
    exact_path.username = "exact".into();
    exact_path.url = "https://app.example.com/login/reset".into();
    let exact_path_id = exact_path.id.to_string();
    vault.root.entries.push(exact_path);

    let mut ancestor = Entry::new("Parent Domain");
    ancestor.username = "ancestor".into();
    ancestor.url = "https://example.com/login/reset".into();
    let ancestor_id = ancestor.id.to_string();
    vault.root.entries.push(ancestor);

    let mut exact_host_broader_path = Entry::new("Broader Path");
    exact_host_broader_path.username = "broad".into();
    exact_host_broader_path.url = "https://app.example.com/login".into();
    let broader_path_id = exact_host_broader_path.id.to_string();
    vault.root.entries.push(exact_host_broader_path);

    let mut sibling = Entry::new("Sibling Host");
    sibling.username = "sibling".into();
    sibling.url = "https://admin.example.com/login/reset".into();
    let sibling_id = sibling.id.to_string();
    vault.root.entries.push(sibling);

    let mut invalid = Entry::new("Invalid Url");
    invalid.username = "invalid".into();
    invalid.url = "not a url".into();
    vault.root.entries.push(invalid);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let fill = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id.clone(),
            url: "https://app.example.com/login/reset?next=%2Fdashboard#section".into(),
        })
        .unwrap();
    assert_eq!(
        fill,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: vec![
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: exact_path_id,
                    title: "Exact Path".into(),
                    username: "exact".into(),
                    url: "https://app.example.com/login/reset".into(),
                    group_id: root_id.clone(),
                    has_totp: false,
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: broader_path_id,
                    title: "Broader Path".into(),
                    username: "broad".into(),
                    url: "https://app.example.com/login".into(),
                    group_id: root_id.clone(),
                    has_totp: false,
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: ancestor_id,
                    title: "Parent Domain".into(),
                    username: "ancestor".into(),
                    url: "https://example.com/login/reset".into(),
                    group_id: root_id.clone(),
                    has_totp: false,
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: descendant_id,
                    title: "Descendant Host".into(),
                    username: "descendant".into(),
                    url: "https://auth.app.example.com/login/reset".into(),
                    group_id: root_id.clone(),
                    has_totp: false,
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: sibling_id,
                    title: "Sibling Host".into(),
                    username: "sibling".into(),
                    url: "https://admin.example.com/login/reset".into(),
                    group_id: root_id,
                    has_totp: false,
                },
            ],
        })
    );
}

#[test]
fn runtime_includes_moved_live_entries_in_fill_candidates() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id;
    let mut entry = Entry::new("Moved Login");
    entry.previous_parent = Some(root_id);
    entry.username = "alice".into();
    entry.password = "secret".into();
    entry.url = "https://app.example.com/login".into();
    let entry_id = entry.id.to_string();
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let fill = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id,
            url: "https://app.example.com/login".into(),
        })
        .unwrap();
    assert_eq!(
        fill,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: vec![vaultkern_runtime_protocol::EntrySummaryDto {
                id: entry_id,
                title: "Moved Login".into(),
                username: "alice".into(),
                url: "https://app.example.com/login".into(),
                group_id: root_id.to_string(),
                has_totp: false,
            }],
        })
    );
}

#[test]
fn runtime_returns_empty_fill_candidates_for_hostless_page_urls() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.username = "alice".into();
    entry.url = "https://app.example.com/login".into();
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let file_url = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id.clone(),
            url: "file:///tmp/demo.html".into(),
        })
        .unwrap();
    assert_eq!(
        file_url,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: Vec::new(),
        })
    );

    let about_blank = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id,
            url: "about:blank".into(),
        })
        .unwrap();
    assert_eq!(
        about_blank,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: Vec::new(),
        })
    );
}

#[test]
fn runtime_excludes_passkey_only_entries_from_password_fill_candidates() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();

    let mut passkey_only = Entry::new("Passkey Only");
    passkey_only.username = "alice@example.com".into();
    passkey_only.url = "https://example.com/login".into();
    passkey_only.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: Some("generated-user".into()),
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    });
    vault.root.entries.push(passkey_only);

    let mut password_entry = Entry::new("Password Entry");
    password_entry.username = "alice@example.com".into();
    password_entry.password = "secret".into();
    password_entry.url = "https://example.com/login".into();
    let password_entry_id = password_entry.id.to_string();
    vault.root.entries.push(password_entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let fill = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id,
            url: "https://example.com/login".into(),
        })
        .unwrap();

    assert_eq!(
        fill,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: vec![vaultkern_runtime_protocol::EntrySummaryDto {
                id: password_entry_id,
                title: "Password Entry".into(),
                username: "alice@example.com".into(),
                url: "https://example.com/login".into(),
                group_id: root_id,
                has_totp: false,
            }],
        })
    );
}

#[test]
fn runtime_excludes_recycle_bin_entries_from_password_fill_candidates() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();

    let mut active_entry = Entry::new("Active Password");
    active_entry.username = "alice@example.com".into();
    active_entry.password = "secret".into();
    active_entry.url = "https://example.com/login".into();
    let active_entry_id = active_entry.id.to_string();
    vault.root.entries.push(active_entry);

    let mut deleted_entry = Entry::new("Deleted Password");
    deleted_entry.username = "deleted@example.com".into();
    deleted_entry.password = "deleted-secret".into();
    deleted_entry.url = "https://example.com/login".into();
    let mut recycle_bin = Group::new("Recycle Bin");
    let recycle_bin_id = recycle_bin.id;
    recycle_bin.entries.push(deleted_entry);
    vault.recycle_bin_enabled = Some(true);
    vault.recycle_bin_group = Some(recycle_bin_id);
    vault.root.children.push(recycle_bin);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let fill = runtime
        .handle(RuntimeCommand::FindFillCandidates {
            vault_id: handle.vault_id,
            url: "https://example.com/login".into(),
        })
        .unwrap();

    assert_eq!(
        fill,
        RuntimeResponse::FillCandidates(vaultkern_runtime_protocol::FillCandidateListDto {
            entries: vec![vaultkern_runtime_protocol::EntrySummaryDto {
                id: active_entry_id,
                title: "Active Password".into(),
                username: "alice@example.com".into(),
                url: "https://example.com/login".into(),
                group_id: root_id,
                has_totp: false,
            }],
        })
    );
}

#[test]
fn runtime_returns_protocol_errors_for_query_failures() {
    let mut runtime = Runtime::for_tests();

    let list = runtime
        .handle(RuntimeCommand::ListEntries {
            vault_id: "missing".into(),
        })
        .unwrap();
    assert_eq!(
        list,
        RuntimeResponse::Error(vaultkern_runtime_protocol::ErrorDto {
            code: "invalid_request".into(),
            message: "vault not opened: missing".into(),
        })
    );
}

#[test]
fn runtime_creates_updates_and_deletes_entries_through_protocol_commands() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let root_id = runtime.list_groups(&handle.vault_id).unwrap().root.id;
    let created = runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: handle.vault_id.clone(),
            parent_group_id: root_id,
            entry_id: None,
            title: "Example".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "demo".into(),
            totp_uri: Some(
                "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
                    .into(),
            ),
        })
        .unwrap();

    let entry_id = match created {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.title, "Example");
            assert_eq!(detail.username, "alice");
            assert_eq!(detail.totp.as_deref(), Some("287082"));
            assert_eq!(
                detail.totp_uri.as_deref(),
                Some(
                    "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test&algorithm=SHA1&digits=6&period=30"
                )
            );
            detail.id
        }
        other => panic!("expected entry detail, got {other:?}"),
    };

    let updated = runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Example 2".into(),
            username: "alice".into(),
            password: "secret-2".into(),
            url: "https://example.com/app".into(),
            notes: "updated".into(),
            totp_uri: None,
            custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
                key: "RecoveryCode".into(),
                value: "edited-code".into(),
                protected: true,
            }],
        })
        .unwrap();
    match updated {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.title, "Example 2");
            assert_eq!(detail.password, "secret-2");
            assert_eq!(detail.totp, None);
            assert_eq!(detail.totp_uri, None);
            assert_eq!(detail.custom_fields.len(), 1);
            assert_eq!(detail.custom_fields[0].key, "RecoveryCode");
            assert_eq!(detail.custom_fields[0].value, "edited-code");
            assert!(detail.custom_fields[0].protected);
        }
        other => panic!("expected updated entry detail, got {other:?}"),
    }

    let deleted = runtime
        .handle(RuntimeCommand::DeleteEntry {
            vault_id: handle.vault_id,
            entry_id: entry_id.clone(),
        })
        .unwrap();
    assert_eq!(deleted, RuntimeResponse::Saved);
}

#[test]
fn runtime_replays_a_create_with_the_same_planned_entry_id_without_duplication() {
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
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();
    let root_id = runtime.list_groups(&handle.vault_id).unwrap().root.id;
    let entry_id = "11111111-1111-4111-8111-111111111111";

    for _ in 0..2 {
        let response = runtime
            .handle(RuntimeCommand::CreateEntry {
                vault_id: handle.vault_id.clone(),
                parent_group_id: root_id.clone(),
                entry_id: Some(entry_id.into()),
                title: "Original".into(),
                username: "alice".into(),
                password: "secret".into(),
                url: "https://example.com".into(),
                notes: String::new().into(),
                totp_uri: None,
            })
            .unwrap();
        let RuntimeResponse::EntryDetail(detail) = response else {
            panic!("expected entry detail");
        };
        assert_eq!(detail.id, entry_id);
        assert_eq!(detail.title, "Original");
    }

    let collision = runtime.handle(RuntimeCommand::CreateEntry {
        vault_id: handle.vault_id.clone(),
        parent_group_id: root_id,
        entry_id: Some(entry_id.into()),
        title: "must not overwrite the committed entry".into(),
        username: "alice".into(),
        password: "secret".into(),
        url: "https://example.com".into(),
        notes: String::new().into(),
        totp_uri: None,
    });
    assert!(
        collision
            .unwrap_err()
            .to_string()
            .contains("planned entry id collision")
    );

    let entries = runtime.list_entries(&handle.vault_id).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn runtime_sets_and_clears_entry_passkey() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();
    let mut entry = Entry::new("Example");
    let entry_id = entry.id.to_string();
    entry.passkey = Some(PasskeyRecord {
        username: "legacy@example.com".into(),
        credential_id: "bGVnYWN5LWNlcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("bGVnYWN5LXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let passkey = EntryPasskeyUpdateDto {
        username: "alice@example.com".into(),
        credential_id: "credential-base64url".into(),
        generated_user_id: Some("generated-user".into()),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    };
    let expected_passkey = EntryPasskeyDto {
        username: passkey.username.clone(),
        credential_id: passkey.credential_id.clone(),
        generated_user_id: passkey.generated_user_id.clone(),
        relying_party: passkey.relying_party.clone(),
        user_handle: passkey.user_handle.clone(),
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    };

    let updated = runtime
        .handle(RuntimeCommand::SetEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            passkey: clone_test_passkey_update(&passkey),
        })
        .unwrap();
    match updated {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.id, entry_id);
            assert_eq!(detail.passkey.as_ref(), Some(&expected_passkey));
        }
        other => panic!("expected entry detail, got {other:?}"),
    }

    let detail = runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    match detail {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.passkey, Some(expected_passkey));
        }
        other => panic!("expected entry detail, got {other:?}"),
    }

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 1);

    let cleared = runtime
        .handle(RuntimeCommand::ClearEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    match cleared {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.passkey, None);
        }
        other => panic!("expected entry detail, got {other:?}"),
    }

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id.clone(),
            entry_id,
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 2);

    assert_eq!(
        runtime.list_groups(&handle.vault_id).unwrap().root.id,
        root_id
    );
}

#[test]
fn runtime_set_and_clear_entry_passkey_enforces_history_limit() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    vault.history_max_items = Some(1);
    let mut entry = Entry::new("Example");
    let entry_id = entry.id.to_string();
    entry.passkey = Some(PasskeyRecord {
        username: "legacy@example.com".into(),
        credential_id: "bGVnYWN5LWNlcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("bGVnYWN5LXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let passkey = EntryPasskeyUpdateDto {
        username: "alice@example.com".into(),
        credential_id: "credential-base64url".into(),
        generated_user_id: Some("generated-user".into()),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    };

    runtime
        .handle(RuntimeCommand::SetEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            passkey: clone_test_passkey_update(&passkey),
        })
        .unwrap();
    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 1);

    runtime
        .handle(RuntimeCommand::SetEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            passkey,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::ClearEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id,
            entry_id,
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 1);
}

#[test]
fn runtime_creates_passkey_assertion_for_matching_relying_party() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: Some("generated-user".into()),
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_get_ceremony_at_s4(&mut runtime, "assertion-token-1", "Y2hhbGxlbmdlLTE");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_base64url.clone(),
        })
        .unwrap();

    let RuntimeResponse::PasskeyAssertion(assertion) = response else {
        panic!("expected passkey assertion, got {response:?}");
    };
    assert_eq!(assertion.credential_id, "Y3JlZGVudGlhbC0x");
    assert_eq!(
        assertion.client_data_json_base64url,
        client_data_json_base64url
    );
    assert_eq!(assertion.user_handle_base64url, None);
    assert!(assertion.backup_eligible);
    assert!(!assertion.backup_state);

    let authenticator_data = URL_SAFE_NO_PAD
        .decode(assertion.authenticator_data_base64url)
        .unwrap();
    assert_eq!(authenticator_data.len(), 37);
    assert_eq!(
        &authenticator_data[..32],
        Sha256::digest(b"example.com").as_slice()
    );
    assert_eq!(authenticator_data[32], 0x0d);
    assert_eq!(&authenticator_data[33..], [0, 0, 0, 0]);

    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed_payload = authenticator_data;
    signed_payload.extend_from_slice(&client_data_hash);
    let signature = Signature::from_der(
        &URL_SAFE_NO_PAD
            .decode(assertion.signature_base64url)
            .unwrap(),
    )
    .unwrap();
    let signing_key = SigningKey::from_pkcs8_pem(TEST_PASSKEY_PRIVATE_KEY).unwrap();
    signing_key
        .verifying_key()
        .verify(&signed_payload, &signature)
        .unwrap();

    register_get_ceremony_at_s4(&mut runtime, "assertion-token-1-upgrade", "Y2hhbGxlbmdlLTE");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-1-upgrade".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected discoverable mismatch error, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony discoverable mismatch"),
        "{error:?}"
    );
}

#[test]
fn preferred_uv_ceremony_cannot_release_a_passkey_without_fresh_verification() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXByZWZlcnJlZA","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-preferred-no-uv",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLXByZWZlcnJlZA",
        PasskeyUserVerificationRequirementDto::Preferred,
    );
    advance_ceremony_from_s1_to_s4(&mut runtime, "assertion-token-preferred-no-uv");

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-preferred-no-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected fresh UV error, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey user verification was not verified")
    );
}

#[test]
fn runtime_rejects_required_user_verification_without_token_bound_proof() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXJlcXVpcmVk","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s4_with_user_verification(
        &mut runtime,
        "assertion-token-required-missing",
        PasskeyCeremonyKindDto::Get,
        "https://example.com",
        "example.com",
        "Y2hhbGxlbmdlLXJlcXVpcmVk",
        false,
        PasskeyUserVerificationRequirementDto::Required,
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-required-missing".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_base64url.clone(),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected required UV error, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey user verification was not verified")
    );
}

#[test]
fn runtime_sets_assertion_uv_flag_after_master_password_user_verification() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXV2","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-uv",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLXV2",
        PasskeyUserVerificationRequirementDto::Required,
    );
    let verified = runtime
        .handle(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "assertion-token-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: vault_id.clone(),
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: Some("demo-password".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
        panic!("expected UV proof, got {verified:?}");
    };
    assert!(verified.verified);
    advance_ceremony_from_s1_to_s4(&mut runtime, "assertion-token-uv");

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: client_data_json_base64url.clone(),
        })
        .unwrap();

    let RuntimeResponse::PasskeyAssertion(assertion) = response else {
        panic!("expected passkey assertion, got {response:?}");
    };
    let authenticator_data = URL_SAFE_NO_PAD
        .decode(assertion.authenticator_data_base64url)
        .unwrap();
    assert_ne!(authenticator_data[32] & 0x04, 0);

    let replay = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();
    let RuntimeResponse::Error(error) = replay else {
        panic!("expected consumed UV proof error, got {replay:?}");
    };
    assert!(
        error
            .message
            .contains("passkey user verification was not verified")
    );
}

#[test]
fn runtime_sets_assertion_uv_flag_after_user_selection_user_verification() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXMzYi11dg","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s3_with_discoverable_and_user_verification(
        &mut runtime,
        "assertion-token-s3b-uv",
        PasskeyCeremonyKindDto::Get,
        "https://example.com",
        "example.com",
        "Y2hhbGxlbmdlLXMzYi11dg",
        true,
        PasskeyUserVerificationRequirementDto::Required,
        None,
    );
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "assertion-token-s3b-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::UserSelection,
            related_origin_verified: false,
        })
        .unwrap();
    let verified = runtime
        .handle(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "assertion-token-s3b-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserSelection,
            vault_id: vault_id.clone(),
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: Some("demo-password".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
        panic!("expected UV proof, got {verified:?}");
    };
    assert!(verified.verified);
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "assertion-token-s3b-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserSelection,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-s3b-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();

    let RuntimeResponse::PasskeyAssertion(assertion) = response else {
        panic!("expected passkey assertion, got {response:?}");
    };
    let authenticator_data = URL_SAFE_NO_PAD
        .decode(assertion.authenticator_data_base64url)
        .unwrap();
    assert_ne!(authenticator_data[32] & 0x04, 0);
}

#[test]
fn runtime_treats_user_verification_as_user_presence_for_assertion() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXV2LXVw","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-uv-up",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLXV2LXVw",
        PasskeyUserVerificationRequirementDto::Required,
    );
    let verified = runtime
        .handle(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "assertion-token-uv-up".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: vault_id.clone(),
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: Some("demo-password".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyUserVerified(verified) = verified else {
        panic!("expected UV proof, got {verified:?}");
    };
    assert!(verified.verified);
    advance_ceremony_from_s1_to_s4(&mut runtime, "assertion-token-uv-up");

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-uv-up".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: false,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();

    let RuntimeResponse::PasskeyAssertion(assertion) = response else {
        panic!("expected passkey assertion, got {response:?}");
    };
    let authenticator_data = URL_SAFE_NO_PAD
        .decode(assertion.authenticator_data_base64url)
        .unwrap();
    assert_ne!(authenticator_data[32] & 0x01, 0);
    assert_ne!(authenticator_data[32] & 0x04, 0);
}

#[test]
fn runtime_does_not_reuse_plain_unlock_as_passkey_user_verification() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-plain-unlock-uv",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLXV2",
        PasskeyUserVerificationRequirementDto::Required,
    );

    runtime.lock_session();
    runtime
        .unlock_with_password(&vault_id, "demo-password")
        .unwrap();

    let error = runtime
        .handle(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "assertion-token-plain-unlock-uv".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id,
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: None,
        })
        .unwrap_err();

    assert!(format!("{error:#}").contains("passkey user verification password is required"));
}

#[test]
fn runtime_does_not_reuse_user_verification_across_ceremony_tokens() {
    let (mut runtime, _dir, vault_id) = runtime_with_example_passkey();
    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLXV2LTI","origin":"https://example.com","crossOrigin":false}"#;
    let client_data_json_base64url = URL_SAFE_NO_PAD.encode(client_data_json);
    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-uv-source",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLXV2",
        PasskeyUserVerificationRequirementDto::Required,
    );
    runtime
        .handle(RuntimeCommand::VerifyPasskeyUser {
            ceremony_token: "assertion-token-uv-source".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: vault_id.clone(),
            method: PasskeyUserVerificationMethodDto::MasterPassword,
            password: Some("demo-password".into()),
        })
        .unwrap();
    register_ceremony_at_s4_with_user_verification(
        &mut runtime,
        "assertion-token-uv-target",
        PasskeyCeremonyKindDto::Get,
        "https://example.com",
        "example.com",
        "Y2hhbGxlbmdlLXV2LTI",
        false,
        PasskeyUserVerificationRequirementDto::Required,
    );

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-uv-target".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url,
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected required UV error, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("passkey user verification was not verified")
    );
}

#[test]
fn runtime_rejects_passkey_assertion_when_ceremony_switches_vault_after_binding() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut first_vault = Vault::empty("first");
    let mut first_entry = Entry::new("First");
    first_entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Zmlyc3QtY3JlZGVudGlhbA".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("Zmlyc3QtdXNlcg".into()),
        backup_eligible: true,
        backup_state: true,
    });
    first_vault.root.entries.push(first_entry);

    let mut second_vault = Vault::empty("second");
    let mut second_entry = Entry::new("Second");
    second_entry.passkey = Some(PasskeyRecord {
        username: "mallory@example.com".into(),
        credential_id: "c2Vjb25kLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("c2Vjb25kLXVzZXI".into()),
        backup_eligible: true,
        backup_state: true,
    });
    second_vault.root.entries.push(second_entry);

    let dir = tempfile::tempdir().unwrap();
    let first_path = dir.path().join("first.kdbx");
    let second_path = dir.path().join("second.kdbx");
    std::fs::write(
        &first_path,
        core.save_kdbx(&first_vault, &key, SaveProfile::recommended())
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &second_path,
        core.save_kdbx(&second_vault, &key, SaveProfile::recommended())
            .unwrap(),
    )
    .unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let first_handle = runtime
        .open_local_vault(first_path.to_str().unwrap())
        .unwrap();
    runtime
        .unlock_with_password(&first_handle.vault_id, "demo-password")
        .unwrap();

    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: "assertion-vault-binding-token".into(),
            connection_id: "connection-1".into(),
            origin: "https://example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: "Y2hhbGxlbmdl".into(),
            request_id: 42,
            tab_id: 7,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "assertion-vault-binding-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token: "assertion-vault-binding-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            vault_id: first_handle.vault_id,
        })
        .unwrap();
    let second_handle = runtime
        .open_local_vault(second_path.to_str().unwrap())
        .unwrap();
    runtime
        .unlock_with_password(&second_handle.vault_id, "demo-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "assertion-vault-binding-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: "assertion-vault-binding-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();

    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}"#;
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-vault-binding-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: second_handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("c2Vjb25kLWNyZWRlbnRpYWw".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data_json),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected vault mismatch error, got {response:?}");
    };
    assert!(
        error.message.contains("passkey ceremony vault mismatch"),
        "unexpected error: {}",
        error.message
    );
}

#[test]
fn runtime_rejects_duplicate_active_passkey_credentials_for_allowed_credential() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    for username in ["alice@example.com", "bob@example.com"] {
        let mut entry = Entry::new(username);
        entry.passkey = Some(PasskeyRecord {
            username: username.into(),
            credential_id: "ZHVwbGljYXRlLWNyZWRlbnRpYWw".into(),
            generated_user_id: None,
            private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: true,
            backup_state: true,
        });
        vault.root.entries.push(entry);
    }

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let client_data_json = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#;
    register_get_ceremony_at_s4(&mut runtime, "assertion-token-duplicate", "Y2hhbGxlbmdlLTE");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-duplicate".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("ZHVwbGljYXRlLWNyZWRlbnRpYWw".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data_json),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected duplicate credential error, got {response:?}");
    };
    assert!(
        error
            .message
            .contains("multiple passkey credentials found for credential id")
    );
}

#[test]
fn runtime_rejects_passkey_assertion_without_user_presence() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_ceremony_at_s1_with_user_verification(
        &mut runtime,
        "assertion-token-2",
        PasskeyCeremonyKindDto::Get,
        "Y2hhbGxlbmdlLTE",
        PasskeyUserVerificationRequirementDto::Preferred,
    );
    advance_ceremony_from_s1_to_s4(&mut runtime, "assertion-token-2");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-2".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(error.message.contains("user presence was not verified"));
}

#[test]
fn runtime_rejects_passkey_assertion_for_relying_party_mismatch() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s4_for(
        &mut runtime,
        "assertion-token-3",
        "https://evil.example.net",
        "evil.example.net",
        "Y2hhbGxlbmdlLTE",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-3".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "evil.example.net".into(),
            origin: "https://evil.example.net".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://evil.example.net","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(error.message.contains("passkey credential not found"));
}

#[test]
fn runtime_rejects_passkey_assertion_when_vault_is_locked() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();

    register_get_ceremony_at_s4(&mut runtime, "assertion-token-4", "Y2hhbGxlbmdlLTE");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-4".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(error.message.contains("vault is locked"));
}

#[test]
fn runtime_rejects_missing_passkey_assertion_credential_id_before_vault_access() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();

    register_discoverable_get_ceremony_at_s4(
        &mut runtime,
        "assertion-token-missing-selected-id",
        "Y2hhbGxlbmdlLTE",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-missing-selected-id".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(
        error
            .message
            .contains("passkey assertion credential id is required"),
        "{error:?}"
    );
}

#[test]
fn runtime_rejects_passkey_assertion_for_unknown_credential() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s4(&mut runtime, "assertion-token-5", "Y2hhbGxlbmdlLTE");
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-5".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("dW5rbm93bg".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(error.message.contains("passkey credential not found"));
}

#[test]
fn runtime_allows_loopback_http_origin_for_passkey_assertion_smoke_tests() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "127.0.0.1".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let origin = "http://127.0.0.1:58777";
    register_get_ceremony_at_s4_for(
        &mut runtime,
        "assertion-token-loopback",
        origin,
        "127.0.0.1",
        "Y2hhbGxlbmdlLTE",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-loopback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "127.0.0.1".into(),
            origin: origin.into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                format!(
                    r#"{{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"{origin}","crossOrigin":false}}"#
                )
                .as_bytes(),
            ),
        })
        .unwrap();

    assert!(matches!(response, RuntimeResponse::PasskeyAssertion(_)));
}

#[test]
fn runtime_allows_bracketed_ipv6_loopback_http_origin_for_passkey_assertion_smoke_tests() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "::1".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let origin = "http://[::1]:58777";
    register_get_ceremony_at_s4_for(
        &mut runtime,
        "assertion-token-ipv6-loopback",
        origin,
        "::1",
        "Y2hhbGxlbmdlLTE",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-ipv6-loopback".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "::1".into(),
            origin: origin.into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                format!(
                    r#"{{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"{origin}","crossOrigin":false}}"#
                )
                .as_bytes(),
            ),
        })
        .unwrap();

    assert!(matches!(response, RuntimeResponse::PasskeyAssertion(_)));
}

#[test]
fn runtime_rejects_passkey_assertion_when_client_data_frame_context_mismatches_ledger() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    for (token, client_data_json, expected_error) in [
        (
            "assertion-token-cross-origin-false",
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://login.example.com","crossOrigin":false}"#
                .as_slice(),
            "passkey ceremony clientDataJSON crossOrigin mismatch",
        ),
        (
            "assertion-token-missing-top-origin",
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTE","origin":"https://login.example.com","crossOrigin":true}"#
                .as_slice(),
            "passkey ceremony clientDataJSON topOrigin mismatch",
        ),
    ] {
        register_get_subframe_ceremony_at_s4(&mut runtime, token, "Y2hhbGxlbmdlLTE");
        let response = runtime
            .handle(RuntimeCommand::CreatePasskeyAssertion {
                ceremony_token: token.into(),
                expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: handle.vault_id.clone(),
                relying_party: "example.com".into(),
                origin: "https://login.example.com".into(),
                credential_id: Some("Y3JlZGVudGlhbC0x".into()),
                discoverable: false,
                user_presence_verified: true,
                related_origin_verified: false,
                client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data_json),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected frame context mismatch error, got {response:?}");
        };
        assert!(
            error.message.contains(expected_error),
            "unexpected error for {token}: {}",
            error.message
        );
    }
}

#[test]
fn runtime_creates_passkey_registration_entry_and_can_assert_with_it() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let vault = Vault::empty("demo");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let create_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(&mut runtime, "registration-token-1", "cmVnaXN0ZXItMQ");
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(create_client_data),
        })
        .unwrap();

    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };
    assert_eq!(registration.public_key_algorithm, -7);
    assert_eq!(registration.user_handle_base64url, "dXNlci0x");
    assert!(!registration.credential_id.is_empty());
    assert!(!registration.attestation_object_base64url.is_empty());
    let registration_authenticator_data = URL_SAFE_NO_PAD
        .decode(&registration.authenticator_data_base64url)
        .expect("decode registration authenticator data");
    assert_eq!(registration_authenticator_data[32], 0x5d);
    assert!(!registration.public_key_base64url.is_empty());

    let detail = runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: registration.entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryDetail(detail) = detail else {
        panic!("expected entry detail, got {detail:?}");
    };
    assert_eq!(detail.title, "example.com");
    assert_eq!(detail.username, "alice@example.com");
    let passkey = detail
        .passkey
        .expect("registered entry should have a passkey");
    assert_eq!(passkey.credential_id, registration.credential_id);
    assert_eq!(passkey.relying_party, "example.com");
    assert_eq!(passkey.user_handle, Some("dXNlci0x".into()));
    assert!(passkey.backup_eligible);
    assert!(passkey.backup_state);
    assert!(
        !serde_json::to_value(&passkey)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("privateKeyPem")
    );

    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: handle.vault_id.clone(),
        })
        .expect("save registered passkey entry");
    let saved = std::fs::read(&path).expect("read saved passkey vault");
    let loaded = core
        .load_kdbx(&saved, &key)
        .expect("load saved passkey vault");
    let created_entry = loaded
        .root
        .entries
        .iter()
        .find(|entry| entry.id.to_string() == registration.entry_id)
        .expect("created passkey entry");
    assert!(
        created_entry
            .passkey
            .as_ref()
            .expect("saved KPEX payload")
            .private_key_pem
            .contains("BEGIN PRIVATE KEY")
    );
    assert_eq!(created_entry.created_at, 59);
    assert_eq!(created_entry.modified_at, 59);
    assert_eq!(created_entry.expiry_time, Some(59));
    assert_eq!(created_entry.last_accessed_at, Some(59));
    assert_eq!(created_entry.usage_count, Some(0));
    assert_eq!(created_entry.location_changed_at, Some(59));

    let get_client_data = br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_get_ceremony_at_s4(&mut runtime, "assertion-token-6", "bG9naW4tMQ");
    let assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-6".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some(registration.credential_id),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(get_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(assertion) = assertion else {
        panic!("expected passkey assertion, got {assertion:?}");
    };
    let assertion_authenticator_data = URL_SAFE_NO_PAD
        .decode(&assertion.authenticator_data_base64url)
        .expect("decode assertion authenticator data");
    assert_eq!(assertion_authenticator_data[32], 0x1d);
}

#[test]
fn runtime_rejects_passkey_registration_when_generated_credential_id_collides() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let colliding_credential_id = "Y29sbGlkaW5nLWNyZWRlbnRpYWw";
    let mut vault = Vault::empty("demo");
    let mut existing = Entry::new("Existing");
    existing.passkey = Some(PasskeyRecord {
        username: "existing@example.net".into(),
        credential_id: colliding_credential_id.into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "other.example".into(),
        user_handle: Some("b3RoZXItdXNlcg".into()),
        backup_eligible: true,
        backup_state: true,
    });
    vault.root.entries.push(existing);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime =
        Runtime::for_tests_with_passkey_credential_ids(vec![colliding_credential_id.into()]);
    runtime.set_test_unix_time(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let create_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(
        &mut runtime,
        "registration-token-collision",
        "cmVnaXN0ZXItMQ",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-collision".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(create_client_data),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected collision error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(error.message.contains("passkey credential id collision"));

    register_get_ceremony_at_s3(&mut runtime, "list-after-collision-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-collision-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected credential list, got {credentials:?}");
    };
    assert!(credentials.credentials.is_empty());
}

#[test]
fn runtime_reregisters_passkey_by_overwriting_matching_rp_and_user_handle() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let vault = Vault::empty("demo");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(&mut runtime, "registration-token-2", "cmVnaXN0ZXItMQ");
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-2".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(first_registration) = first_registration else {
        panic!("expected passkey registration, got {first_registration:?}");
    };
    assert!(first_registration.created);

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(&mut runtime, "registration-token-3", "cmVnaXN0ZXItMg");
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-3".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice-renamed@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(second_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(second_registration) = second_registration else {
        panic!("expected passkey registration, got {second_registration:?}");
    };
    assert!(!second_registration.created);

    assert_eq!(second_registration.entry_id, first_registration.entry_id);
    assert_ne!(
        second_registration.credential_id,
        first_registration.credential_id
    );

    register_get_ceremony_at_s3(&mut runtime, "list-after-reregister-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-reregister-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        second_registration.credential_id
    );

    let detail = runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: first_registration.entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryDetail(detail) = detail else {
        panic!("expected entry detail, got {detail:?}");
    };
    assert_eq!(detail.username, "alice-renamed@example.com");
    assert_eq!(
        detail
            .passkey
            .as_ref()
            .map(|passkey| passkey.username.as_str()),
        Some("alice-renamed@example.com")
    );

    let get_client_data = br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_discoverable_get_ceremony_at_s4(&mut runtime, "assertion-token-7", "bG9naW4tMQ");
    let assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-7".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some(second_registration.credential_id.clone()),
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(get_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(assertion) = assertion else {
        panic!("expected passkey assertion, got {assertion:?}");
    };
    assert_eq!(assertion.credential_id, second_registration.credential_id);
}

#[test]
fn runtime_omits_duplicate_passkey_credential_ids_from_discoverable_list() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let duplicate_credential_id = "ZHVwbGljYXRlLWNyZWRlbnRpYWw";
    for (title, username, user_handle) in [
        ("Duplicate A", "alice-a@example.com", "ZHVwbGljYXRlLWE"),
        ("Duplicate B", "alice-b@example.com", "ZHVwbGljYXRlLWI"),
    ] {
        let mut entry = Entry::new(title);
        entry.passkey = Some(PasskeyRecord {
            username: username.into(),
            credential_id: duplicate_credential_id.into(),
            generated_user_id: None,
            private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
            relying_party: "example.com".into(),
            user_handle: Some(user_handle.into()),
            backup_eligible: false,
            backup_state: false,
        });
        vault.root.entries.push(entry);
    }
    let mut unique_entry = Entry::new("Unique");
    unique_entry.passkey = Some(PasskeyRecord {
        username: "unique@example.com".into(),
        credential_id: "dW5pcXVlLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dW5pcXVlLXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(unique_entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-duplicate-credentials-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-duplicate-credentials-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };

    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        "dW5pcXVlLWNyZWRlbnRpYWw"
    );
}

#[test]
fn runtime_reregisters_moved_live_passkey_without_creating_duplicate() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Moved Passkey");
    entry.previous_parent = Some(vault.root.id);
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "bW92ZWQtb2xkLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let entry_id = entry.id.to_string();
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItbW92ZWQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(
        &mut runtime,
        "registration-token-moved",
        "cmVnaXN0ZXItbW92ZWQ",
    );
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-moved".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };
    assert!(!registration.created);
    assert_eq!(registration.entry_id, entry_id);

    register_get_ceremony_at_s3(&mut runtime, "list-after-moved-reregister-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-moved-reregister-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        registration.credential_id
    );
}

#[test]
fn runtime_reregistration_preserves_user_fields_and_enforces_history_limit() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    vault.history_max_items = Some(1);
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4(&mut runtime, "registration-token-4", "cmVnaXN0ZXItMQ");
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-4".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(first_registration) = first_registration else {
        panic!("expected passkey registration, got {first_registration:?}");
    };

    runtime
        .handle(RuntimeCommand::UpdateEntryFields {
            vault_id: handle.vault_id.clone(),
            entry_id: first_registration.entry_id.clone(),
            title: "Curated Login".into(),
            username: "human-edited".into(),
            password: "keep-this-secret".into(),
            url: "https://accounts.example.com/custom".into(),
            notes: "hand-written notes".into(),
            totp_uri: None,
            custom_fields: Vec::new(),
        })
        .unwrap();

    for (challenge, user_name) in [
        ("cmVnaXN0ZXItMg", "rp-updated-1@example.com"),
        ("cmVnaXN0ZXItMw", "rp-updated-2@example.com"),
    ] {
        let ceremony_token = format!("registration-token-{challenge}");
        register_create_ceremony_at_s4(&mut runtime, &ceremony_token, challenge);
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://example.com","crossOrigin":false}}"#
        );
        let response = runtime
            .handle(RuntimeCommand::CreatePasskeyRegistration {
                ceremony_token,
                expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: handle.vault_id.clone(),
                relying_party: "example.com".into(),
                origin: "https://example.com".into(),
                user_name: user_name.into(),
                user_display_name: None,
                user_handle_base64url: "dXNlci0x".into(),
                public_key_algorithm: -7,
                related_origin_verified: false,
                client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
            })
            .unwrap();
        let RuntimeResponse::PasskeyRegistration(registration) = response else {
            panic!("expected passkey registration, got {response:?}");
        };
        assert!(!registration.created);
    }

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id.clone(),
            entry_id: first_registration.entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 1);

    let detail = runtime
        .handle(RuntimeCommand::GetEntryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: first_registration.entry_id.clone(),
        })
        .unwrap();
    let RuntimeResponse::EntryDetail(detail) = detail else {
        panic!("expected entry detail, got {detail:?}");
    };
    assert_eq!(detail.title, "Curated Login");
    assert_eq!(detail.username, "human-edited");
    assert_eq!(detail.password, "keep-this-secret");
    assert_eq!(detail.url, "https://accounts.example.com/custom");
    assert_eq!(detail.notes, "hand-written notes");
    assert_eq!(
        detail
            .passkey
            .as_ref()
            .map(|passkey| passkey.username.as_str()),
        Some("rp-updated-2@example.com")
    );

    let saved = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(saved, RuntimeResponse::SaveVaultResult(_)));

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id,
            entry_id: first_registration.entry_id,
        })
        .unwrap();
    let RuntimeResponse::EntryHistoryList(history) = history else {
        panic!("expected history list, got {history:?}");
    };
    assert_eq!(history.items.len(), 1);
}

#[test]
fn runtime_rolls_back_overwritten_passkey_registration_from_history() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-rollback");
    let mut vault = Vault::empty("Passkey Rollback");
    vault.history_max_items = Some(0);
    vault.root.entries.push(Entry::new("Seed"));
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-rollback.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-rollback")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "registration-token-5",
        "cmVnaXN0ZXItMQ",
        "passkey-rollback",
    );
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-5".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(first_registration) = first_registration else {
        panic!("expected passkey registration, got {first_registration:?}");
    };

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "registration-token-6",
        "cmVnaXN0ZXItMg",
        "passkey-rollback",
    );
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-6".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(second_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(second_registration) = second_registration else {
        panic!("expected passkey registration, got {second_registration:?}");
    };
    assert!(!second_registration.created);

    let saved = runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(saved, RuntimeResponse::SaveVaultResult(_)));

    runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "registration-token-6".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-after-rollback-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-rollback-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        first_registration.credential_id
    );
}

#[test]
fn runtime_commits_overwritten_passkey_registration_by_dropping_pending_rollback() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-commit");
    let mut vault = Vault::empty("Passkey Commit");
    vault.root.entries.push(Entry::new("Seed"));
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-commit.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-commit")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "registration-token-7",
        "cmVnaXN0ZXItMQ",
        "passkey-commit",
    );
    runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-7".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "registration-token-8",
        "cmVnaXN0ZXItMg",
        "passkey-commit",
    );
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "registration-token-8".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(second_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(second_registration) = second_registration else {
        panic!("expected passkey registration, got {second_registration:?}");
    };
    assert!(!second_registration.created);

    runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "registration-token-8".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "registration-token-8".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            entry_id: second_registration.entry_id.clone(),
            credential_id: second_registration.credential_id.clone(),
        })
        .unwrap();

    let abort_after_commit = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "registration-token-8".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();
    let RuntimeResponse::Error(error) = abort_after_commit else {
        panic!("expected post-commit abort error, got {abort_after_commit:?}");
    };
    assert!(error.message.contains("passkey ceremony already committed"));

    register_get_ceremony_at_s3(&mut runtime, "list-after-commit-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-commit-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        second_registration.credential_id
    );
}

#[test]
fn runtime_rejects_passkey_registration_commit_when_rollback_identity_differs() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-commit-mismatch");
    let vault = Vault::empty("Passkey Commit Mismatch");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-commit-mismatch.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-commit-mismatch")
        .unwrap();

    let challenge = "cmVnaXN0ZXItY29tbWl0LW1pc21hdGNo";
    let client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItY29tbWl0LW1pc21hdGNo","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "commit-mismatch-token",
        challenge,
        "passkey-commit-mismatch",
    );
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "commit-mismatch-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };

    let mismatched_commit = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "commit-mismatch-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            entry_id: "wrong-entry".into(),
            credential_id: registration.credential_id,
        })
        .unwrap();
    let RuntimeResponse::Error(error) = mismatched_commit else {
        panic!("expected commit mismatch error, got {mismatched_commit:?}");
    };
    assert!(
        error
            .message
            .contains("passkey registration rollback identity mismatch")
    );

    let aborted = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "commit-mismatch-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();
    assert_eq!(aborted, RuntimeResponse::Saved);

    register_get_ceremony_at_s3(&mut runtime, "list-after-commit-mismatch-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-commit-mismatch-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert!(credentials.credentials.is_empty());
}

#[test]
fn runtime_rejects_passkey_registration_commit_before_durable_save() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-commit-before-save");
    let vault = Vault::empty("Passkey Commit Before Save");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-commit-before-save.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-commit-before-save")
        .unwrap();

    let challenge = "cmVnaXN0ZXItY29tbWl0LWJlZm9yZS1zYXZl";
    let client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItY29tbWl0LWJlZm9yZS1zYXZl","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "commit-before-save-token",
        challenge,
        "passkey-commit-before-save",
    );
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "commit-before-save-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };

    let early_commit = runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token: "commit-before-save-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            entry_id: registration.entry_id,
            credential_id: registration.credential_id,
        })
        .unwrap();
    let RuntimeResponse::Error(error) = early_commit else {
        panic!("expected early commit error, got {early_commit:?}");
    };
    assert!(
        error
            .message
            .contains("passkey ceremony must be saved before commit")
    );
    assert_eq!(
        runtime
            .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
                ceremony_token: "commit-before-save-token".into(),
            })
            .unwrap(),
        RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
            known: true,
            phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
            durable_state: Some(PasskeyCeremonyDurableStateDto::Mutated),
            delivery_state: Some(PasskeyCeremonyDeliveryStateDto::NotDelivered),
        })
    );
}

#[test]
fn runtime_aborts_uncommitted_passkey_registration_by_ceremony_token() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-abort");
    let vault = Vault::empty("Passkey Abort");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-abort.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-abort")
        .unwrap();

    let challenge = "cmVnaXN0ZXItYWJvcnQ";
    let client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItYWJvcnQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "abort-token-1",
        challenge,
        "passkey-abort",
    );
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "abort-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };
    assert!(registration.created);

    let aborted = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "abort-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();
    assert_eq!(aborted, RuntimeResponse::Saved);

    register_get_ceremony_at_s3(&mut runtime, "list-after-abort-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-abort-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert!(credentials.credentials.is_empty());

    let ledger = runtime
        .handle(RuntimeCommand::QueryPasskeyCeremonyLedger {
            ceremony_token: "abort-token-1".into(),
        })
        .unwrap();
    assert_eq!(
        ledger,
        RuntimeResponse::PasskeyCeremonyLedger(
            vaultkern_runtime_protocol::PasskeyCeremonyLedgerDto {
                known: true,
                phase: Some(PasskeyCeremonyPhaseDto::ClosedFailed),
                durable_state: Some(
                    vaultkern_runtime_protocol::PasskeyCeremonyDurableStateDto::None
                ),
                delivery_state: Some(
                    vaultkern_runtime_protocol::PasskeyCeremonyDeliveryStateDto::NotDelivered
                ),
            }
        )
    );
}

#[test]
fn runtime_aborts_saved_uncommitted_passkey_registration_by_ceremony_token() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-saved-abort");
    let vault = Vault::empty("Passkey Saved Abort");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-saved-abort.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-saved-abort")
        .unwrap();

    let challenge = "cmVnaXN0ZXItc2F2ZWQtYWJvcnQ";
    let client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItc2F2ZWQtYWJvcnQ","origin":"https://example.com","crossOrigin":false}"#;
    register_create_ceremony_at_s4_with_password(
        &mut runtime,
        "saved-abort-token-1",
        challenge,
        "passkey-saved-abort",
    );
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token: "saved-abort-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            public_key_algorithm: -7,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data),
        })
        .unwrap();
    assert!(matches!(
        registration,
        RuntimeResponse::PasskeyRegistration(_)
    ));

    let saved = runtime
        .handle(RuntimeCommand::SavePasskeyRegistration {
            ceremony_token: "saved-abort-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
        })
        .unwrap();
    assert!(matches!(saved, RuntimeResponse::SaveVaultResult(_)));

    let aborted = runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "saved-abort-token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();
    assert_eq!(aborted, RuntimeResponse::Saved);
    drop(runtime);

    let mut reopened = Runtime::for_tests_at(59);
    let reopened_handle = reopened
        .open_local_vault(path.to_str().unwrap())
        .expect("reopen vault");
    reopened
        .unlock_with_password(&reopened_handle.vault_id, "passkey-saved-abort")
        .unwrap();
    register_get_ceremony_at_s3(&mut reopened, "list-after-saved-abort-token");
    let credentials = reopened
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-saved-abort-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: reopened_handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert!(credentials.credentials.is_empty());
}

#[test]
fn runtime_ignores_stale_passkey_registration_rollback_for_newer_credentials() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("passkey-rollback");
    let vault = Vault::empty("Passkey Rollback");
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save seed vault");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passkey-rollback.kdbx");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-rollback")
        .unwrap();

    let mut registrations = Vec::new();
    for challenge in ["cmVnaXN0ZXItMQ", "cmVnaXN0ZXItMg", "cmVnaXN0ZXItMw"] {
        let ceremony_token = format!("registration-token-rollback-{challenge}");
        register_create_ceremony_at_s4_with_password(
            &mut runtime,
            &ceremony_token,
            challenge,
            "passkey-rollback",
        );
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://example.com","crossOrigin":false}}"#
        );
        let response = runtime
            .handle(RuntimeCommand::CreatePasskeyRegistration {
                ceremony_token,
                expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
                vault_id: handle.vault_id.clone(),
                relying_party: "example.com".into(),
                origin: "https://example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: Some("Alice".into()),
                user_handle_base64url: "dXNlci0x".into(),
                public_key_algorithm: -7,
                related_origin_verified: false,
                client_data_json_base64url: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
            })
            .unwrap();
        let RuntimeResponse::PasskeyRegistration(registration) = response else {
            panic!("expected passkey registration, got {response:?}");
        };
        registrations.push(registration);
    }

    runtime
        .handle(RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token: "registration-token-rollback-cmVnaXN0ZXItMg".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
        })
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-after-second-rollback-token");
    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-after-second-rollback-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = credentials else {
        panic!("expected passkey credential list, got {credentials:?}");
    };
    assert_eq!(credentials.credentials.len(), 1);
    assert_eq!(
        credentials.credentials[0].credential_id,
        registrations[2].credential_id
    );
}

#[test]
fn runtime_reports_passkey_credential_status() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_create_ceremony_at_s3(&mut runtime, "status-token-example");
    let existing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-token-example".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            credential_id: "Y3JlZGVudGlhbC0x".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(existing) = existing else {
        panic!("expected passkey credential status, got {existing:?}");
    };
    assert_eq!(existing.credential_id, "Y3JlZGVudGlhbC0x");
    assert!(existing.exists);

    let missing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-token-example".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            credential_id: "bWlzc2luZw".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(missing) = missing else {
        panic!("expected passkey credential status, got {missing:?}");
    };
    assert_eq!(missing.credential_id, "bWlzc2luZw");
    assert!(!missing.exists);
}

#[test]
fn runtime_reports_passkey_credential_status_batch() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_create_ceremony_at_s3(&mut runtime, "status-batch-token-example");
    let response = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatusBatch {
            ceremony_token: "status-batch-token-example".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            credential_ids: vec!["Y3JlZGVudGlhbC0x".into(), "bWlzc2luZw".into()],
            relying_party: "example.com".into(),
        })
        .unwrap();

    let RuntimeResponse::PasskeyCredentialStatusBatch(statuses) = response else {
        panic!("expected passkey credential status batch, got {response:?}");
    };
    assert_eq!(statuses.statuses.len(), 2);
    assert_eq!(statuses.statuses[0].credential_id, "Y3JlZGVudGlhbC0x");
    assert!(statuses.statuses[0].exists);
    assert_eq!(statuses.statuses[1].credential_id, "bWlzc2luZw");
    assert!(!statuses.statuses[1].exists);
}

#[test]
fn runtime_scopes_passkey_credential_status_to_relying_party() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut other_rp_entry = Entry::new("Other");
    other_rp_entry.passkey = Some(PasskeyRecord {
        username: "alice@example.net".into(),
        credential_id: "c2hhcmVkLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "other.example".into(),
        user_handle: None,
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(other_rp_entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_create_ceremony_at_s3(&mut runtime, "status-token-example-scope");
    let scoped_missing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-token-example-scope".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            credential_id: "c2hhcmVkLWNyZWRlbnRpYWw".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(scoped_missing) = scoped_missing else {
        panic!("expected passkey credential status, got {scoped_missing:?}");
    };
    assert!(!scoped_missing.exists);

    register_ceremony_at_s3(
        &mut runtime,
        "status-token-other-scope",
        PasskeyCeremonyKindDto::Create,
        "https://other.example",
        "other.example",
        "Y2hhbGxlbmdl",
    );
    let scoped_existing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-token-other-scope".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            credential_id: "c2hhcmVkLWNyZWRlbnRpYWw".into(),
            relying_party: "other.example".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(scoped_existing) = scoped_existing else {
        panic!("expected passkey credential status, got {scoped_existing:?}");
    };
    assert!(scoped_existing.exists);
}

#[test]
fn runtime_rejects_structurally_invalid_passkey_list_relying_party_before_vault_read() {
    let mut runtime = Runtime::for_tests_at(59);

    for relying_party in ["", "com", "https://example.com", "example.com/login"] {
        let response = runtime
            .handle(RuntimeCommand::ListPasskeyCredentials {
                ceremony_token: "invalid-list-rp-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
                vault_id: "missing-vault".into(),
                relying_party: relying_party.into(),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected error for invalid relying party {relying_party:?}, got {response:?}");
        };
        assert_eq!(error.code, "invalid_request");
        assert!(
            error.message.contains("invalid passkey relying party id"),
            "unexpected error for {relying_party:?}: {}",
            error.message
        );
    }
}

#[test]
fn runtime_rejects_structurally_invalid_passkey_status_relying_party_before_vault_read() {
    let mut runtime = Runtime::for_tests_at(59);

    for relying_party in ["", "com", "https://example.com", "example.com/login"] {
        let response = runtime
            .handle(RuntimeCommand::PasskeyCredentialStatus {
                ceremony_token: "invalid-status-rp-token".into(),
                expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
                vault_id: "missing-vault".into(),
                credential_id: "Y3JlZGVudGlhbC0x".into(),
                relying_party: relying_party.into(),
            })
            .unwrap();

        let RuntimeResponse::Error(error) = response else {
            panic!("expected error for invalid relying party {relying_party:?}, got {response:?}");
        };
        assert_eq!(error.code, "invalid_request");
        assert!(
            error.message.contains("invalid passkey relying party id"),
            "unexpected error for {relying_party:?}: {}",
            error.message
        );
    }
}

#[test]
fn runtime_creates_discoverable_passkey_assertion_for_relying_party() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "ZGlzY292ZXJhYmxlLTE".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: false,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let get_client_data = br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#;
    register_discoverable_get_ceremony_at_s4(
        &mut runtime,
        "assertion-token-discoverable",
        "bG9naW4tMQ",
    );
    let missing_selection = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-discoverable".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(get_client_data),
        })
        .unwrap();
    let RuntimeResponse::Error(error) = missing_selection else {
        panic!("expected missing selection error, got {missing_selection:?}");
    };
    assert!(
        error
            .message
            .contains("passkey assertion credential id is required"),
        "{error:?}"
    );

    let selected_client_data = br#"{"type":"webauthn.get","challenge":"bG9naW4tMg","origin":"https://example.com","crossOrigin":false}"#;
    register_discoverable_get_ceremony_at_s4(
        &mut runtime,
        "assertion-token-selected-discoverable",
        "bG9naW4tMg",
    );
    let selected_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-selected-discoverable".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("ZGlzY292ZXJhYmxlLTE".into()),
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(selected_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(selected_assertion) = selected_assertion else {
        panic!("expected selected passkey assertion, got {selected_assertion:?}");
    };
    assert_eq!(
        selected_assertion.user_handle_base64url,
        Some("dXNlci0x".into())
    );
}

#[test]
fn runtime_lists_passkey_credentials_for_relying_party_selection() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    for (username, credential_id, relying_party, user_handle) in [
        (
            "alice@example.com",
            "ZGlzY292ZXJhYmxlLTE",
            "example.com",
            Some("dXNlci0x"),
        ),
        (
            "bob@example.com",
            "ZGlzY292ZXJhYmxlLTI",
            "example.com",
            Some("dXNlci0y"),
        ),
        ("carol@example.net", "b3RoZXItcnA", "other.example", None),
    ] {
        let mut entry = Entry::new(username);
        entry.passkey = Some(PasskeyRecord {
            username: username.into(),
            credential_id: credential_id.into(),
            generated_user_id: None,
            private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
            relying_party: relying_party.into(),
            user_handle: user_handle.map(str::to_owned),
            backup_eligible: false,
            backup_state: false,
        });
        vault.root.entries.push(entry);
    }

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-selection-token");
    let response = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-selection-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credentials) = response else {
        panic!("expected passkey credential list, got {response:?}");
    };

    assert_eq!(credentials.credentials.len(), 2);
    assert_eq!(credentials.credentials[0].username, "alice@example.com");
    assert_eq!(
        credentials.credentials[0].credential_id,
        "ZGlzY292ZXJhYmxlLTE"
    );
    assert_eq!(
        credentials.credentials[1].user_handle.as_deref(),
        Some("dXNlci0y")
    );
}

#[test]
fn runtime_skips_recycled_passkeys_for_status_and_assertions() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut active_entry = Entry::new("Active");
    active_entry.passkey = Some(PasskeyRecord {
        username: "active@example.com".into(),
        credential_id: "YWN0aXZlLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("YWN0aXZlLXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });

    let mut moved_live_entry = Entry::new("Moved Live");
    moved_live_entry.previous_parent = Some(vault.root.id);
    moved_live_entry.passkey = Some(PasskeyRecord {
        username: "moved@example.com".into(),
        credential_id: "bW92ZWQtbGl2ZS1jcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "moved.example.com".into(),
        user_handle: Some("bW92ZWQtdXNlcg".into()),
        backup_eligible: false,
        backup_state: false,
    });

    let mut recycled_entry = Entry::new("Deleted");
    recycled_entry.passkey = Some(PasskeyRecord {
        username: "deleted@example.com".into(),
        credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("ZGVsZXRlZC11c2Vy".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut recycle_bin = Group::new("Recycle Bin");
    let recycle_bin_id = recycle_bin.id;
    recycle_bin.entries.push(recycled_entry);
    let mut moved_group_entry = Entry::new("Moved Group");
    moved_group_entry.passkey = Some(PasskeyRecord {
        username: "moved-group@example.com".into(),
        credential_id: "bW92ZWQtZ3JvdXAtY3JlZGVudGlhbA".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "moved-group.example.com".into(),
        user_handle: Some("bW92ZWQtZ3JvdXAtdXNlcg".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut moved_group = Group::new("Moved Group");
    moved_group.previous_parent = Some(vault.root.id);
    moved_group.entries.push(moved_group_entry);
    vault.recycle_bin_enabled = Some(true);
    vault.recycle_bin_group = Some(recycle_bin_id);
    vault.root.children.push(recycle_bin);
    vault.root.children.push(moved_group);
    vault.root.entries.push(moved_live_entry);
    vault.root.entries.push(active_entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-active-recycle-token");
    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-active-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credential_list) = credential_list else {
        panic!("expected credential list, got {credential_list:?}");
    };
    assert_eq!(credential_list.credentials.len(), 1);
    assert_eq!(
        credential_list.credentials[0].credential_id,
        "YWN0aXZlLWNyZWRlbnRpYWw"
    );

    register_create_ceremony_at_s3(&mut runtime, "status-deleted-recycle-token");
    let status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-deleted-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(status) = status else {
        panic!("expected credential status, got {status:?}");
    };
    assert!(!status.exists);

    register_ceremony_at_s3(
        &mut runtime,
        "status-moved-group-recycle-token",
        PasskeyCeremonyKindDto::Create,
        "https://moved-group.example.com",
        "moved-group.example.com",
        "Y2hhbGxlbmdl",
    );
    let moved_group_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-moved-group-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            credential_id: "bW92ZWQtZ3JvdXAtY3JlZGVudGlhbA".into(),
            relying_party: "moved-group.example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(moved_group_status) = moved_group_status else {
        panic!("expected credential status, got {moved_group_status:?}");
    };
    assert!(moved_group_status.exists);

    register_ceremony_at_s3(
        &mut runtime,
        "status-moved-recycle-token",
        PasskeyCeremonyKindDto::Create,
        "https://moved.example.com",
        "moved.example.com",
        "Y2hhbGxlbmdl",
    );
    let moved_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-moved-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            credential_id: "bW92ZWQtbGl2ZS1jcmVkZW50aWFs".into(),
            relying_party: "moved.example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(moved_status) = moved_status else {
        panic!("expected credential status, got {moved_status:?}");
    };
    assert!(moved_status.exists);

    register_get_ceremony_at_s4_for(
        &mut runtime,
        "assertion-token-moved-group",
        "https://moved-group.example.com",
        "moved-group.example.com",
        "bG9naW4tMQ",
    );
    let moved_group_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-moved-group".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "moved-group.example.com".into(),
            origin: "https://moved-group.example.com".into(),
            credential_id: Some("bW92ZWQtZ3JvdXAtY3JlZGVudGlhbA".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://moved-group.example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(moved_group_assertion) = moved_group_assertion else {
        panic!("expected passkey assertion, got {moved_group_assertion:?}");
    };
    assert_eq!(
        moved_group_assertion.credential_id,
        "bW92ZWQtZ3JvdXAtY3JlZGVudGlhbA"
    );

    register_get_ceremony_at_s4(&mut runtime, "assertion-token-deleted", "bG9naW4tMQ");
    let deleted_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-deleted".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("ZGVsZXRlZC1jcmVkZW50aWFs".into()),
            discoverable: false,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();
    let RuntimeResponse::Error(error) = deleted_assertion else {
        panic!("expected error, got {deleted_assertion:?}");
    };
    assert!(error.message.contains("passkey credential not found"));

    register_discoverable_get_ceremony_at_s4(
        &mut runtime,
        "assertion-token-active-discoverable",
        "bG9naW4tMQ",
    );
    let discoverable_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-active-discoverable".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("YWN0aXZlLWNyZWRlbnRpYWw".into()),
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(assertion) = discoverable_assertion else {
        panic!("expected passkey assertion, got {discoverable_assertion:?}");
    };
    assert_eq!(assertion.credential_id, "YWN0aXZlLWNyZWRlbnRpYWw");
}

#[test]
fn runtime_keeps_group_named_recycle_bin_live_without_uuid_metadata() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut active_entry = Entry::new("Active");
    active_entry.passkey = Some(PasskeyRecord {
        username: "active@example.com".into(),
        credential_id: "YWN0aXZlLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("YWN0aXZlLXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });

    let mut recycled_entry = Entry::new("Deleted");
    recycled_entry.passkey = Some(PasskeyRecord {
        username: "deleted@example.com".into(),
        credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("ZGVsZXRlZC11c2Vy".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut recycle_bin = Group::new("Recycle Bin");
    recycle_bin.entries.push(recycled_entry);
    vault.recycle_bin_enabled = Some(true);
    vault.recycle_bin_group = None;
    vault.root.children.push(recycle_bin);
    vault.root.entries.push(active_entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-named-recycle-token");
    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-named-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credential_list) = credential_list else {
        panic!("expected credential list, got {credential_list:?}");
    };
    assert_eq!(credential_list.credentials.len(), 2);
    assert_eq!(
        credential_list.credentials[0].credential_id,
        "YWN0aXZlLWNyZWRlbnRpYWw"
    );
    assert_eq!(
        credential_list.credentials[1].credential_id,
        "ZGVsZXRlZC1jcmVkZW50aWFs"
    );

    register_create_ceremony_at_s3(&mut runtime, "status-named-recycle-token");
    let deleted_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-named-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(deleted_status) = deleted_status else {
        panic!("expected credential status, got {deleted_status:?}");
    };
    assert!(deleted_status.exists);
}

#[test]
fn runtime_does_not_skip_active_group_named_recycle_bin_when_recycle_bin_is_disabled() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut active_entry = Entry::new("Active");
    active_entry.passkey = Some(PasskeyRecord {
        username: "active@example.com".into(),
        credential_id: "YWN0aXZlLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("YWN0aXZlLXVzZXI".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut recycle_named_group = Group::new("Recycle Bin");
    recycle_named_group.entries.push(active_entry);
    vault.recycle_bin_enabled = Some(false);
    vault.recycle_bin_group = None;
    vault.root.children.push(recycle_named_group);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-disabled-recycle-token");
    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-disabled-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credential_list) = credential_list else {
        panic!("expected credential list, got {credential_list:?}");
    };
    assert_eq!(credential_list.credentials.len(), 1);
    assert_eq!(
        credential_list.credentials[0].credential_id,
        "YWN0aXZlLWNyZWRlbnRpYWw"
    );
}

#[test]
fn runtime_does_not_skip_recycle_bin_uuid_group_when_recycle_bin_is_disabled() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut active_entry = Entry::new("Active");
    active_entry.passkey = Some(PasskeyRecord {
        username: "active@example.com".into(),
        credential_id: "YWN0aXZlLXV1aWQtZGlzYWJsZWQ".into(),
        generated_user_id: None,
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("YWN0aXZlLXV1aWQtdXNlcg".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut recycle_group = Group::new("Recycle Bin");
    let recycle_group_id = recycle_group.id;
    recycle_group.entries.push(active_entry);
    vault.recycle_bin_enabled = Some(false);
    vault.recycle_bin_group = Some(recycle_group_id);
    vault.root.children.push(recycle_group);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_get_ceremony_at_s3(&mut runtime, "list-disabled-uuid-recycle-token");
    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
            ceremony_token: "list-disabled-uuid-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialList(credential_list) = credential_list else {
        panic!("expected credential list, got {credential_list:?}");
    };
    assert_eq!(credential_list.credentials.len(), 1);
    assert_eq!(
        credential_list.credentials[0].credential_id,
        "YWN0aXZlLXV1aWQtZGlzYWJsZWQ"
    );

    register_create_ceremony_at_s3(&mut runtime, "status-disabled-uuid-recycle-token");
    let status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token: "status-disabled-uuid-recycle-token".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            vault_id: handle.vault_id,
            credential_id: "YWN0aXZlLXV1aWQtZGlzYWJsZWQ".into(),
            relying_party: "example.com".into(),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(status) = status else {
        panic!("expected credential status, got {status:?}");
    };
    assert!(status.exists);
}

#[test]
fn runtime_rejects_discoverable_passkey_assertion_without_selected_credential() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    for (username, credential_id) in [
        ("alice@example.com", "ZGlzY292ZXJhYmxlLTE"),
        ("bob@example.com", "ZGlzY292ZXJhYmxlLTI"),
    ] {
        let mut entry = Entry::new(username);
        entry.passkey = Some(PasskeyRecord {
            username: username.into(),
            credential_id: credential_id.into(),
            generated_user_id: None,
            private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
            relying_party: "example.com".into(),
            user_handle: None,
            backup_eligible: false,
            backup_state: false,
        });
        vault.root.entries.push(entry);
    }

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    register_discoverable_get_ceremony_at_s4(
        &mut runtime,
        "assertion-token-multiple-discoverable",
        "bG9naW4tMQ",
    );
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token: "assertion-token-multiple-discoverable".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
            discoverable: true,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#,
            ),
        })
        .unwrap();

    let RuntimeResponse::Error(error) = response else {
        panic!("expected error, got {response:?}");
    };
    assert_eq!(error.code, "invalid_request");
    assert!(
        error
            .message
            .contains("passkey assertion credential id is required")
    );
}

#[test]
fn runtime_manages_entry_attachments_through_protocol_commands() {
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
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let root_id = runtime.list_groups(&handle.vault_id).unwrap().root.id;
    let created = runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: handle.vault_id.clone(),
            parent_group_id: root_id,
            entry_id: None,
            title: "Example".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "demo".into(),
            totp_uri: None,
        })
        .unwrap();
    let entry_id = match created {
        RuntimeResponse::EntryDetail(detail) => detail.id,
        other => panic!("expected entry detail, got {other:?}"),
    };

    let added = runtime
        .handle(RuntimeCommand::AddEntryAttachment {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "backup.txt".into(),
            data_base64: "aGVsbG8=".into(),
            protect_in_memory: true,
        })
        .unwrap();
    match added {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.attachments.len(), 1);
            assert_eq!(detail.attachments[0].name, "backup.txt");
            assert_eq!(detail.attachments[0].size, 5);
            assert!(detail.attachments[0].protect_in_memory);
        }
        other => panic!("expected entry detail, got {other:?}"),
    }

    let content = runtime
        .handle(RuntimeCommand::GetEntryAttachmentContent {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "backup.txt".into(),
        })
        .unwrap();
    assert_eq!(
        content,
        RuntimeResponse::EntryAttachmentContent(
            vaultkern_runtime_protocol::EntryAttachmentContentDto {
                name: "backup.txt".into(),
                data_base64: "aGVsbG8=".into(),
                protect_in_memory: true,
            }
        )
    );

    let renamed = runtime
        .handle(RuntimeCommand::UpdateEntryAttachmentMetadata {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            old_name: "backup.txt".into(),
            new_name: "backup-renamed.txt".into(),
            protect_in_memory: false,
        })
        .unwrap();
    match renamed {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.attachments.len(), 1);
            assert_eq!(detail.attachments[0].name, "backup-renamed.txt");
            assert!(!detail.attachments[0].protect_in_memory);
        }
        other => panic!("expected entry detail, got {other:?}"),
    }

    runtime
        .handle(RuntimeCommand::ReplaceEntryAttachmentContent {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "backup-renamed.txt".into(),
            data_base64: "dXBkYXRlZA==".into(),
        })
        .unwrap();
    let replaced_content = runtime
        .handle(RuntimeCommand::GetEntryAttachmentContent {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "backup-renamed.txt".into(),
        })
        .unwrap();
    assert_eq!(
        replaced_content,
        RuntimeResponse::EntryAttachmentContent(
            vaultkern_runtime_protocol::EntryAttachmentContentDto {
                name: "backup-renamed.txt".into(),
                data_base64: "dXBkYXRlZA==".into(),
                protect_in_memory: false,
            }
        )
    );

    let deleted = runtime
        .handle(RuntimeCommand::DeleteEntryAttachment {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "backup-renamed.txt".into(),
        })
        .unwrap();
    match deleted {
        RuntimeResponse::EntryDetail(detail) => {
            assert!(detail.attachments.is_empty());
        }
        other => panic!("expected entry detail, got {other:?}"),
    }
}

#[test]
fn runtime_returns_entry_history_through_protocol_commands() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Current Example");
    entry.username = "alice".into();
    entry.password = "current-secret".into();
    entry.url = "https://example.com/current".into();
    entry.notes = "current note".into();

    let mut snapshot = Entry::new("Old Example");
    snapshot.id = entry.id;
    snapshot.username = "alice-old".into();
    snapshot.password = "old-secret".into();
    snapshot.url = "https://example.com/old".into();
    snapshot.notes = "old note".into();
    snapshot.modified_at = 42;
    snapshot.attributes.insert(
        "RecoveryCode".into(),
        CustomField {
            value: "old-code".into(),
            protected: true,
        },
    );
    snapshot.attachments.insert(
        "backup.txt".into(),
        Attachment {
            name: "backup.txt".into(),
            data: b"hello".to_vec(),
            protect_in_memory: true,
        },
    );
    entry.history.push(snapshot);
    let entry_id = entry.id.to_string();
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();

    let history = runtime
        .handle(RuntimeCommand::ListEntryHistory {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
        })
        .unwrap();
    match history {
        RuntimeResponse::EntryHistoryList(list) => {
            assert_eq!(list.items.len(), 1);
            assert_eq!(list.items[0].index, 0);
            assert_eq!(list.items[0].title, "Old Example");
            assert_eq!(list.items[0].username, "alice-old");
            assert_eq!(list.items[0].modified_at, 42);
            assert_eq!(list.items[0].attachment_count, 1);
            assert_eq!(list.items[0].custom_field_count, 1);
        }
        other => panic!("expected history list, got {other:?}"),
    }

    let detail = runtime
        .handle(RuntimeCommand::GetEntryHistoryDetail {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            history_index: 0,
        })
        .unwrap();
    let detail_json = serde_json::to_string(&detail).unwrap();
    assert!(
        !detail_json.contains("old-secret"),
        "history response serialized the historical password"
    );
    assert!(
        !detail_json.contains("old-code"),
        "history response serialized a protected historical custom-field value"
    );
    match detail {
        RuntimeResponse::EntryHistoryDetail(detail) => {
            assert_eq!(detail.entry_id, entry_id);
            assert_eq!(detail.history_index, 0);
            assert_eq!(detail.title, "Old Example");
            assert_eq!(detail.username, "alice-old");
            assert_eq!(detail.url, "https://example.com/old");
            assert_eq!(detail.notes, "old note");
            assert_eq!(detail.modified_at, 42);
            assert_eq!(detail.custom_fields.len(), 1);
            assert_eq!(detail.custom_fields[0].key, "RecoveryCode");
            assert!(detail.custom_fields[0].value.is_empty());
            assert!(detail.custom_fields[0].protected);
            assert_eq!(detail.attachments.len(), 1);
            assert_eq!(detail.attachments[0].name, "backup.txt");
            assert_eq!(detail.attachments[0].size, 5);
            assert!(detail.attachments[0].protect_in_memory);
        }
        other => panic!("expected history detail, got {other:?}"),
    }
}

#[test]
fn runtime_updates_entry_modified_time_after_manager_mutations() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(&Vault::empty("demo"), &key, SaveProfile::recommended())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(1234);
    let vault = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&vault.vault_id, "demo-password")
        .unwrap();
    let root_id = runtime.list_groups(&vault.vault_id).unwrap().root.id;
    let created = match runtime
        .handle(RuntimeCommand::CreateEntry {
            vault_id: vault.vault_id.clone(),
            parent_group_id: root_id,
            entry_id: None,
            title: "Created".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: String::new().into(),
            totp_uri: None,
        })
        .unwrap()
    {
        RuntimeResponse::EntryDetail(detail) => detail,
        other => panic!("expected entry detail, got {other:?}"),
    };

    runtime
        .handle(RuntimeCommand::SaveVault {
            vault_id: vault.vault_id.clone(),
        })
        .unwrap();

    let loaded = core
        .load_kdbx(&std::fs::read(&path).unwrap(), &key)
        .expect("reload saved vault");
    let times = core
        .project_entry_times(&loaded, &created.id)
        .expect("project entry times");
    assert_eq!(times.modified_at, 1234);
}

fn register_create_ceremony_at_s4(runtime: &mut Runtime, token: &str, challenge_base64url: &str) {
    register_ceremony_at_s4(
        runtime,
        token,
        PasskeyCeremonyKindDto::Create,
        "https://example.com",
        "example.com",
        challenge_base64url,
    );
}

fn register_create_ceremony_at_s4_with_password(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
    password: &str,
) {
    register_ceremony_at_s4_with_user_verification_and_password(
        runtime,
        token,
        PasskeyCeremonyKindDto::Create,
        "https://example.com",
        "example.com",
        challenge_base64url,
        false,
        PasskeyUserVerificationRequirementDto::Preferred,
        Some(password),
    );
}

fn register_create_ceremony_at_s3(runtime: &mut Runtime, token: &str) {
    register_ceremony_at_s3(
        runtime,
        token,
        PasskeyCeremonyKindDto::Create,
        "https://example.com",
        "example.com",
        "Y2hhbGxlbmdl",
    );
}

fn register_get_ceremony_at_s4(runtime: &mut Runtime, token: &str, challenge_base64url: &str) {
    register_get_ceremony_at_s4_for(
        runtime,
        token,
        "https://example.com",
        "example.com",
        challenge_base64url,
    );
}

fn register_get_subframe_ceremony_at_s4(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
) {
    let request_id = test_id_from_token(token);
    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: token.into(),
            connection_id: "connection-1".into(),
            origin: "https://login.example.com".into(),
            top_origin: Some("https://container.example.net".into()),
            ancestor_origins: vec!["https://container.example.net".into()],
            relying_party: "example.com".into(),
            ceremony: PasskeyCeremonyKindDto::Get,
            discoverable: false,
            user_verification: PasskeyUserVerificationRequirementDto::Preferred,
            challenge_base64url: challenge_base64url.into(),
            request_id,
            tab_id: request_id as i64,
            frame_id: 1,
            frame_kind: PasskeyFrameKindDto::Subframe,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    if let Some(vault_id) = runtime.session_state().active_vault_id {
        runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: token.into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id,
                method: PasskeyUserVerificationMethodDto::MasterPassword,
                password: Some("demo-password".into()),
            })
            .unwrap();
    }
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_discoverable_get_ceremony_at_s4(
    runtime: &mut Runtime,
    token: &str,
    challenge_base64url: &str,
) {
    register_ceremony_at_s4_with_discoverable(
        runtime,
        token,
        PasskeyCeremonyKindDto::Get,
        "https://example.com",
        "example.com",
        challenge_base64url,
        true,
    );
}

fn register_get_ceremony_at_s3(runtime: &mut Runtime, token: &str) {
    register_get_ceremony_at_s3_for(runtime, token, "https://example.com", "example.com");
}

fn register_get_ceremony_at_s3_for(
    runtime: &mut Runtime,
    token: &str,
    origin: &str,
    relying_party: &str,
) {
    register_ceremony_at_s3(
        runtime,
        token,
        PasskeyCeremonyKindDto::Get,
        origin,
        relying_party,
        "Y2hhbGxlbmdl",
    );
}

fn register_get_ceremony_at_s4_for(
    runtime: &mut Runtime,
    token: &str,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_ceremony_at_s4(
        runtime,
        token,
        PasskeyCeremonyKindDto::Get,
        origin,
        relying_party,
        challenge_base64url,
    );
}

fn register_ceremony_at_s4(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_ceremony_at_s4_with_discoverable(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        false,
    );
}

fn register_ceremony_at_s4_with_discoverable(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    discoverable: bool,
) {
    register_ceremony_at_s4_with_user_verification_and_password(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        discoverable,
        PasskeyUserVerificationRequirementDto::Preferred,
        Some("demo-password"),
    );
}

fn register_ceremony_at_s4_with_user_verification(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    discoverable: bool,
    user_verification: PasskeyUserVerificationRequirementDto,
) {
    register_ceremony_at_s4_with_user_verification_and_password(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        discoverable,
        user_verification,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn register_ceremony_at_s4_with_user_verification_and_password(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    discoverable: bool,
    user_verification: PasskeyUserVerificationRequirementDto,
    verification_password: Option<&str>,
) {
    register_ceremony_at_s3_with_discoverable_and_user_verification(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        discoverable,
        user_verification,
        verification_password,
    );
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_ceremony_at_s3(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
) {
    register_ceremony_at_s3_with_discoverable(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        false,
    );
}

fn register_ceremony_at_s3_with_discoverable(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    discoverable: bool,
) {
    register_ceremony_at_s3_with_discoverable_and_user_verification(
        runtime,
        token,
        ceremony,
        origin,
        relying_party,
        challenge_base64url,
        discoverable,
        PasskeyUserVerificationRequirementDto::Preferred,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn register_ceremony_at_s3_with_discoverable_and_user_verification(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    origin: &str,
    relying_party: &str,
    challenge_base64url: &str,
    discoverable: bool,
    user_verification: PasskeyUserVerificationRequirementDto,
    verification_password: Option<&str>,
) {
    let request_id = test_id_from_token(token);
    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: token.into(),
            connection_id: "connection-1".into(),
            origin: origin.into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: relying_party.into(),
            ceremony,
            discoverable,
            user_verification,
            challenge_base64url: challenge_base64url.into(),
            request_id,
            tab_id: request_id as i64,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
    if verification_password.is_some()
        && let Some(vault_id) = runtime.session_state().active_vault_id
    {
        runtime
            .handle(RuntimeCommand::VerifyPasskeyUser {
                ceremony_token: token.into(),
                expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
                vault_id,
                method: PasskeyUserVerificationMethodDto::MasterPassword,
                password: verification_password.map(Into::into),
            })
            .unwrap();
    }
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
}

fn register_ceremony_at_s1_with_user_verification(
    runtime: &mut Runtime,
    token: &str,
    ceremony: PasskeyCeremonyKindDto,
    challenge_base64url: &str,
    user_verification: PasskeyUserVerificationRequirementDto,
) {
    let request_id = test_id_from_token(token);
    runtime
        .handle(RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token: token.into(),
            connection_id: "connection-1".into(),
            origin: "https://example.com".into(),
            top_origin: None,
            ancestor_origins: vec![],
            relying_party: "example.com".into(),
            ceremony,
            discoverable: false,
            user_verification,
            challenge_base64url: challenge_base64url.into(),
            request_id,
            tab_id: request_id,
            frame_id: 0,
            frame_kind: PasskeyFrameKindDto::Top,
            registered_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 301_000,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            related_origin_verified: false,
        })
        .unwrap();
}

fn advance_ceremony_from_s1_to_s4(runtime: &mut Runtime, token: &str) {
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
            next_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            related_origin_verified: false,
        })
        .unwrap();
    runtime
        .handle(RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token: token.into(),
            expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
            next_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
            related_origin_verified: false,
        })
        .unwrap();
}

fn runtime_with_example_passkey() -> (Runtime, tempfile::TempDir, String) {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut entry = Entry::new("Example");
    entry.passkey = Some(PasskeyRecord {
        username: "alice@example.com".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        generated_user_id: Some("generated-user".into()),
        private_key_pem: String::from(TEST_PASSKEY_PRIVATE_KEY).into(),
        relying_party: "example.com".into(),
        user_handle: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    });
    vault.root.entries.push(entry);

    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_at(59);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "demo-password")
        .unwrap();
    (runtime, dir, handle.vault_id)
}

fn test_id_from_token(token: &str) -> i64 {
    let hash = token.bytes().fold(17_u64, |value, byte| {
        value.wrapping_mul(131).wrapping_add(u64::from(byte))
    });
    (1_000 + (hash % 1_000_000)) as i64
}
