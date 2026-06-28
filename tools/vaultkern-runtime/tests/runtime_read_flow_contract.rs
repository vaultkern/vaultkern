use vaultkern_core::{
    Attachment, CompositeKey, CustomField, Entry, EntryFieldProtection, Group, KeepassCore,
    SaveProfile, TotpSpec, Vault,
};
use vaultkern_runtime::Runtime;
use vaultkern_runtime_protocol::{RuntimeCommand, RuntimeResponse};

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
