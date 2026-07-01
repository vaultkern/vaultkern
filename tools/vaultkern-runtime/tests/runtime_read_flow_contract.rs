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
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{
    DatabaseCredentialsUpdateDto, DatabaseSettingsUpdateDto, RuntimeCommand, RuntimeResponse,
};

const TEST_PASSKEY_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCrpkgmenhRkrdg3Y\n7G0+YmeyFRGgpisH5R5e75gwVHGhRANCAASOCmJegf0Fo1V7ixK+W5u/Jx8bpbIq\nCY0G7WFVp5KD6xMSKPekuRmz+kxK2wiZrN6MrH8kbCDmwLZRxnM73nXs\n-----END PRIVATE KEY-----\n";

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
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: entry_id.clone(),
                    title: "Example".into(),
                    username: "alice".into(),
                    url: "https://app.example.com/login".into(),
                    group_id: child_group_id.clone(),
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
            vault_id: handle.vault_id,
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

    let enabled = runtime
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();
    assert_eq!(
        enabled,
        RuntimeResponse::SessionState(vaultkern_runtime_protocol::SessionStateDto {
            unlocked: true,
            active_vault_id: Some(handle.vault_id.clone()),
            current_vault_ref_id: runtime.session_state().current_vault_ref_id,
            supports_biometric_unlock: true,
            source_status: None,
        })
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

    runtime
        .handle(RuntimeCommand::DisableQuickUnlockForCurrentVault)
        .unwrap();
    let recent = runtime.handle(RuntimeCommand::ListRecentVaults).unwrap();
    let RuntimeResponse::VaultReferenceList(recent) = recent else {
        panic!("expected recent vault list");
    };
    assert!(!recent.vaults[0].supports_quick_unlock);
}

#[test]
fn runtime_refreshes_quick_unlock_credentials_after_password_change() {
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
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();

    runtime
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
        .unwrap();
    runtime.save_vault(&handle.vault_id).unwrap();
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
fn runtime_keeps_existing_quick_unlock_credentials_when_password_save_fails() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("old-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("unsaved-password-change"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsaved-password-change.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();

    runtime
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
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(runtime.save_vault(&handle.vault_id).is_err());

    runtime.handle(RuntimeCommand::LockSession).unwrap();
    let unlocked = runtime
        .handle(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock)
        .unwrap();
    let RuntimeResponse::SessionState(state) = unlocked else {
        panic!("expected session state");
    };
    assert!(state.unlocked);
}

#[test]
fn runtime_deletes_quick_unlock_credentials_when_refresh_store_fails() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("old-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("failing-refresh"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failing-refresh.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock_failing_store_after(1);
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();

    runtime
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
        .unwrap();
    runtime.save_vault(&handle.vault_id).unwrap();

    let recent = runtime.handle(RuntimeCommand::ListRecentVaults).unwrap();
    let RuntimeResponse::VaultReferenceList(recent) = recent else {
        panic!("expected recent vault list");
    };
    assert!(!recent.vaults[0].supports_quick_unlock);
}

#[test]
fn runtime_save_succeeds_when_quick_unlock_refresh_contains_fails() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("old-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("failing-refresh-contains"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failing-refresh-contains.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock_failing_contains();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "old-password")
        .unwrap();
    runtime
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();

    runtime
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
        .unwrap();

    let saved = runtime.save_vault(&handle.vault_id).unwrap();
    let RuntimeResponse::SaveVaultResult(result) = saved else {
        panic!("expected save result");
    };
    assert_eq!(
        result.status,
        vaultkern_runtime_protocol::SaveVaultStatusDto::Saved
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
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
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
fn runtime_disables_quick_unlock_after_password_removal() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("password-to-remove");
    let bytes = core
        .save_kdbx(
            &Vault::empty("passwordless"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("passwordless.kdbx");
    std::fs::write(&path, bytes).unwrap();

    let mut runtime = Runtime::for_tests_with_quick_unlock();
    let handle = runtime.open_local_vault(path.to_str().unwrap()).unwrap();
    runtime
        .unlock_with_password(&handle.vault_id, "password-to-remove")
        .unwrap();
    runtime
        .handle(RuntimeCommand::EnableQuickUnlockForCurrentVault)
        .unwrap();

    runtime
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
        .unwrap();
    runtime.save_vault(&handle.vault_id).unwrap();

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
            vault_id: handle.vault_id,
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
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: broader_path_id,
                    title: "Broader Path".into(),
                    username: "broad".into(),
                    url: "https://app.example.com/login".into(),
                    group_id: root_id.clone(),
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: ancestor_id,
                    title: "Parent Domain".into(),
                    username: "ancestor".into(),
                    url: "https://example.com/login/reset".into(),
                    group_id: root_id.clone(),
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: descendant_id,
                    title: "Descendant Host".into(),
                    username: "descendant".into(),
                    url: "https://auth.app.example.com/login/reset".into(),
                    group_id: root_id.clone(),
                },
                vaultkern_runtime_protocol::EntrySummaryDto {
                    id: sibling_id,
                    title: "Sibling Host".into(),
                    username: "sibling".into(),
                    url: "https://admin.example.com/login/reset".into(),
                    group_id: root_id,
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
fn runtime_sets_and_clears_entry_passkey() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let root_id = vault.root.id.to_string();
    let entry = Entry::new("Example");
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

    let passkey = vaultkern_runtime_protocol::EntryPasskeyDto {
        username: "alice@example.com".into(),
        credential_id: "credential-base64url".into(),
        generated_user_id: Some("generated-user".into()),
        private_key_pem: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".into(),
        relying_party: "example.com".into(),
        user_handle: Some("user-handle".into()),
        backup_eligible: true,
        backup_state: false,
    };

    let updated = runtime
        .handle(RuntimeCommand::SetEntryPasskey {
            vault_id: handle.vault_id.clone(),
            entry_id: entry_id.clone(),
            passkey: passkey.clone(),
        })
        .unwrap();
    match updated {
        RuntimeResponse::EntryDetail(detail) => {
            assert_eq!(detail.id, entry_id);
            assert_eq!(detail.passkey, Some(passkey.clone()));
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
            assert_eq!(detail.passkey, Some(passkey));
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
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
    assert_eq!(assertion.user_handle_base64url, Some("dXNlci0x".into()));
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
    assert_eq!(authenticator_data[32], 0x09);
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "evil.example.net".into(),
            origin: "https://evil.example.net".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("dW5rbm93bg".into()),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "127.0.0.1".into(),
            origin: origin.into(),
            credential_id: Some("Y3JlZGVudGlhbC0x".into()),
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
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
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
    assert_eq!(registration_authenticator_data[32], 0x59);
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
    assert!(passkey.private_key_pem.contains("BEGIN PRIVATE KEY"));

    let get_client_data = br#"{"type":"webauthn.get","challenge":"bG9naW4tMQ","origin":"https://example.com","crossOrigin":false}"#;
    let assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some(registration.credential_id),
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
    assert_eq!(assertion_authenticator_data[32], 0x19);
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
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(first_registration) = first_registration else {
        panic!("expected passkey registration, got {first_registration:?}");
    };
    assert!(first_registration.created);

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice-renamed@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
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

    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
    let assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
    let registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(registration) = registration else {
        panic!("expected passkey registration, got {registration:?}");
    };
    assert!(!registration.created);
    assert_eq!(registration.entry_id, entry_id);

    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
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
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://example.com","crossOrigin":false}}"#
        );
        let response = runtime
            .handle(RuntimeCommand::CreatePasskeyRegistration {
                vault_id: handle.vault_id.clone(),
                relying_party: "example.com".into(),
                origin: "https://example.com".into(),
                user_name: user_name.into(),
                user_display_name: None,
                user_handle_base64url: "dXNlci0x".into(),
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
    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-rollback")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    let first_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(first_registration) = first_registration else {
        panic!("expected passkey registration, got {first_registration:?}");
    };

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
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
        .handle(RuntimeCommand::RollbackPasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            entry_id: second_registration.entry_id,
            credential_id: Some(second_registration.credential_id),
            created: false,
        })
        .unwrap();

    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-commit")
        .unwrap();

    let first_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMQ","origin":"https://example.com","crossOrigin":false}"#;
    runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(first_registration_client_data),
        })
        .unwrap();

    let second_registration_client_data = br#"{"type":"webauthn.create","challenge":"cmVnaXN0ZXItMg","origin":"https://example.com","crossOrigin":false}"#;
    let second_registration = runtime
        .handle(RuntimeCommand::CreatePasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: Some("Alice".into()),
            user_handle_base64url: "dXNlci0x".into(),
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(second_registration_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyRegistration(second_registration) = second_registration else {
        panic!("expected passkey registration, got {second_registration:?}");
    };
    assert!(!second_registration.created);

    runtime
        .handle(RuntimeCommand::CommitPasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            entry_id: second_registration.entry_id.clone(),
            credential_id: second_registration.credential_id.clone(),
        })
        .unwrap();

    runtime
        .handle(RuntimeCommand::RollbackPasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            entry_id: second_registration.entry_id,
            credential_id: Some(second_registration.credential_id.clone()),
            created: false,
        })
        .unwrap();

    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
    let mut runtime = Runtime::for_tests();
    let handle = runtime
        .open_local_vault(path.to_str().unwrap())
        .expect("open vault");
    runtime
        .unlock_with_password(&handle.vault_id, "passkey-rollback")
        .unwrap();

    let mut registrations = Vec::new();
    for challenge in ["cmVnaXN0ZXItMQ", "cmVnaXN0ZXItMg", "cmVnaXN0ZXItMw"] {
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://example.com","crossOrigin":false}}"#
        );
        let response = runtime
            .handle(RuntimeCommand::CreatePasskeyRegistration {
                vault_id: handle.vault_id.clone(),
                relying_party: "example.com".into(),
                origin: "https://example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: Some("Alice".into()),
                user_handle_base64url: "dXNlci0x".into(),
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
        .handle(RuntimeCommand::RollbackPasskeyRegistration {
            vault_id: handle.vault_id.clone(),
            entry_id: registrations[1].entry_id.clone(),
            credential_id: Some(registrations[1].credential_id.clone()),
            created: false,
        })
        .unwrap();

    let credentials = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let existing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id.clone(),
            credential_id: "Y3JlZGVudGlhbC0x".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(existing) = existing else {
        panic!("expected passkey credential status, got {existing:?}");
    };
    assert_eq!(existing.credential_id, "Y3JlZGVudGlhbC0x");
    assert!(existing.exists);

    let missing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id,
            credential_id: "bWlzc2luZw".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(missing) = missing else {
        panic!("expected passkey credential status, got {missing:?}");
    };
    assert_eq!(missing.credential_id, "bWlzc2luZw");
    assert!(!missing.exists);
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let scoped_missing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id.clone(),
            credential_id: "c2hhcmVkLWNyZWRlbnRpYWw".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(scoped_missing) = scoped_missing else {
        panic!("expected passkey credential status, got {scoped_missing:?}");
    };
    assert!(!scoped_missing.exists);

    let scoped_existing = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id,
            credential_id: "c2hhcmVkLWNyZWRlbnRpYWw".into(),
            relying_party: Some("other.example".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(scoped_existing) = scoped_existing else {
        panic!("expected passkey credential status, got {scoped_existing:?}");
    };
    assert!(scoped_existing.exists);
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
    let assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
            user_presence_verified: true,
            related_origin_verified: false,
            client_data_json_base64url: URL_SAFE_NO_PAD.encode(get_client_data),
        })
        .unwrap();
    let RuntimeResponse::PasskeyAssertion(assertion) = assertion else {
        panic!("expected passkey assertion, got {assertion:?}");
    };
    assert_eq!(assertion.credential_id, "ZGlzY292ZXJhYmxlLTE");
    assert_eq!(assertion.user_handle_base64url, Some("dXNlci0x".into()));
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
            private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
        relying_party: "example.com".into(),
        user_handle: Some("ZGVsZXRlZC11c2Vy".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut recycle_bin = Group::new("Recycle Bin");
    let recycle_bin_id = recycle_bin.id;
    recycle_bin.entries.push(recycled_entry);
    let mut group_deleted_entry = Entry::new("Group Deleted");
    group_deleted_entry.passkey = Some(PasskeyRecord {
        username: "group-deleted@example.com".into(),
        credential_id: "Z3JvdXAtZGVsZXRlZC1jcmVkZW50aWFs".into(),
        generated_user_id: None,
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
        relying_party: "example.com".into(),
        user_handle: Some("Z3JvdXAtZGVsZXRlZC11c2Vy".into()),
        backup_eligible: false,
        backup_state: false,
    });
    let mut group_deleted = Group::new("Papierkorb");
    group_deleted.previous_parent = Some(vault.root.id);
    group_deleted.entries.push(group_deleted_entry);
    vault.recycle_bin_enabled = Some(true);
    vault.recycle_bin_group = Some(recycle_bin_id);
    vault.root.children.push(recycle_bin);
    vault.root.children.push(group_deleted);
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

    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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

    let status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id.clone(),
            credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(status) = status else {
        panic!("expected credential status, got {status:?}");
    };
    assert!(!status.exists);

    let group_deleted_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id.clone(),
            credential_id: "Z3JvdXAtZGVsZXRlZC1jcmVkZW50aWFs".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(group_deleted_status) = group_deleted_status
    else {
        panic!("expected credential status, got {group_deleted_status:?}");
    };
    assert!(!group_deleted_status.exists);

    let moved_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id.clone(),
            credential_id: "bW92ZWQtbGl2ZS1jcmVkZW50aWFs".into(),
            relying_party: Some("moved.example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(moved_status) = moved_status else {
        panic!("expected credential status, got {moved_status:?}");
    };
    assert!(moved_status.exists);

    let deleted_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id.clone(),
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: Some("ZGVsZXRlZC1jcmVkZW50aWFs".into()),
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

    let discoverable_assertion = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
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
fn runtime_skips_passkeys_in_recycle_bin_named_group_without_uuid_metadata() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");

    let mut vault = Vault::empty("demo");
    let mut active_entry = Entry::new("Active");
    active_entry.passkey = Some(PasskeyRecord {
        username: "active@example.com".into(),
        credential_id: "YWN0aXZlLWNyZWRlbnRpYWw".into(),
        generated_user_id: None,
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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

    let deleted_status = runtime
        .handle(RuntimeCommand::PasskeyCredentialStatus {
            vault_id: handle.vault_id,
            credential_id: "ZGVsZXRlZC1jcmVkZW50aWFs".into(),
            relying_party: Some("example.com".into()),
        })
        .unwrap();
    let RuntimeResponse::PasskeyCredentialStatus(deleted_status) = deleted_status else {
        panic!("expected credential status, got {deleted_status:?}");
    };
    assert!(!deleted_status.exists);
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
        private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let credential_list = runtime
        .handle(RuntimeCommand::ListPasskeyCredentials {
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
fn runtime_rejects_discoverable_passkey_assertion_when_multiple_accounts_match() {
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
            private_key_pem: TEST_PASSKEY_PRIVATE_KEY.into(),
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

    let response = runtime
        .handle(RuntimeCommand::CreatePasskeyAssertion {
            vault_id: handle.vault_id,
            relying_party: "example.com".into(),
            origin: "https://example.com".into(),
            credential_id: None,
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
            .contains("multiple passkey credentials found for relying party")
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
    match detail {
        RuntimeResponse::EntryHistoryDetail(detail) => {
            assert_eq!(detail.entry_id, entry_id);
            assert_eq!(detail.history_index, 0);
            assert_eq!(detail.title, "Old Example");
            assert_eq!(detail.username, "alice-old");
            assert_eq!(detail.password, "old-secret");
            assert_eq!(detail.url, "https://example.com/old");
            assert_eq!(detail.notes, "old note");
            assert_eq!(detail.modified_at, 42);
            assert_eq!(detail.custom_fields.len(), 1);
            assert_eq!(detail.custom_fields[0].key, "RecoveryCode");
            assert_eq!(detail.custom_fields[0].value, "old-code");
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
            title: "Created".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: String::new(),
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
