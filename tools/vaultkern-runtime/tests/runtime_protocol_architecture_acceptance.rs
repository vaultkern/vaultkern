mod support;

use support::RuntimeProtocolHarness;
use vaultkern_core::{
    CompositeKey, EntryCreate, KeepassCore, SaveProfile, Vault, derive_transformed_key,
    save_kdbx_with_transformed_key,
};
use vaultkern_runtime_protocol::{
    CommitStatusDto, PROTOCOL_VERSION, RuntimeCommand, RuntimeResponse, SaveVaultStatusDto,
};

fn key() -> CompositeKey {
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    key
}

fn empty_vault_bytes() -> Vec<u8> {
    KeepassCore::new()
        .save_kdbx(
            &Vault::empty("Architecture Acceptance"),
            &key(),
            SaveProfile::recommended(),
        )
        .expect("create in-memory KDBX snapshot")
}

fn vault_with_entry_bytes() -> (Vec<u8>, String) {
    let core = KeepassCore::new();
    let mut vault = Vault::empty("Architecture Acceptance");
    let root_id = vault.root.id.to_string();
    let entry = core
        .add_entry(
            &mut vault,
            &root_id,
            EntryCreate {
                title: "Base account".into(),
                username: "base-user".into(),
                password: "base-password".into(),
                url: "https://base.example".into(),
                notes: String::new(),
            },
        )
        .expect("create base entry");
    vault.root.entries[0].modified_at = 1_500_000_000;
    let bytes = core
        .save_kdbx(&vault, &key(), SaveProfile::recommended())
        .expect("create in-memory KDBX snapshot with an entry");
    (bytes, entry.id)
}

fn foreign_remote_head_bytes(base_bytes: &[u8]) -> (Vec<u8>, String) {
    let core = KeepassCore::new();
    let base = core
        .load_database(base_bytes, &key())
        .expect("decode Base for a same-key foreign Remote Head");
    let transformed_key =
        derive_transformed_key(base_bytes, &key()).expect("derive Base transformed key");
    let mut vault = Vault::empty("Foreign Remote Head");
    vault.kdf_parameters = base.vault.kdf_parameters;
    let root_id = vault.root.id.to_string();
    let entry = core
        .add_entry(
            &mut vault,
            &root_id,
            EntryCreate {
                title: "Remote-only account".into(),
                username: "remote-user".into(),
                password: "remote-password".into(),
                url: "https://remote-only.example".into(),
                notes: String::new(),
            },
        )
        .expect("create foreign Remote Head entry");
    let bytes = save_kdbx_with_transformed_key(
        &vault,
        &transformed_key,
        &SaveProfile {
            version: base.inspection.save_target_version,
            cipher: base.inspection.header.cipher,
            compression: base.inspection.header.compression,
            kdf: None,
        },
    )
    .expect("encode same-key foreign Remote Head");
    (bytes, entry.id)
}

#[test]
fn resident_protocol_harness_observes_successful_and_stale_publication() {
    let core = KeepassCore::new();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(empty_vault_bytes());

    assert!(matches!(
        harness.command(RuntimeCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![
                "runtime-core".into(),
                "resident-app".into(),
                "one-drive".into(),
            ],
        }),
        RuntimeResponse::Handshake(_)
    ));

    assert!(matches!(
        harness.command(RuntimeCommand::AddOneDriveVaultReference {
            drive_id: harness.drive_id().into(),
            item_id: harness.item_id().into(),
        }),
        RuntimeResponse::VaultReference(_)
    ));
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            assert!(state.unlocked);
            state.active_vault_id.expect("active vault after unlock")
        }
        _ => panic!("expected unlocked session state"),
    };
    let root_id = match harness.command(RuntimeCommand::ListGroups {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups.root.id,
        _ => panic!("expected group tree"),
    };
    let before_publication = harness.provider_snapshot();
    let created = match harness.command(RuntimeCommand::CreateEntry {
        vault_id: vault_id.clone(),
        parent_group_id: root_id.clone(),
        entry_id: None,
        title: "Local account".into(),
        username: "alice".into(),
        password: "first-password".into(),
        url: "https://local.example".into(),
        notes: String::new().into(),
        totp_uri: None,
    }) {
        RuntimeResponse::EntryMutationResult(result) => {
            assert_eq!(result.commit, CommitStatusDto::Committed);
            assert_eq!(result.publication.status, SaveVaultStatusDto::Saved);
            result.entry.expect("created entry detail")
        }
        _ => panic!("expected committed entry mutation"),
    };

    let first_publication = harness.provider_snapshot();
    assert_ne!(first_publication.bytes, before_publication.bytes);
    assert!(first_publication.revision > before_publication.revision);

    let mut remote = core
        .load_database(&first_publication.bytes, &key())
        .expect("decode first Provider snapshot")
        .vault;
    core.add_entry(
        &mut remote,
        &root_id,
        EntryCreate {
            title: "Remote account".into(),
            username: "bob".into(),
            password: "remote-password".into(),
            url: "https://remote.example".into(),
            notes: String::new(),
        },
    )
    .expect("advance the Remote Head");
    let first_remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .expect("encode first advanced Remote Head");
    core.add_entry(
        &mut remote,
        &root_id,
        EntryCreate {
            title: "Second remote account".into(),
            username: "carol".into(),
            password: "second-remote-password".into(),
            url: "https://second-remote.example".into(),
            notes: String::new(),
        },
    )
    .expect("advance the Remote Head again");
    let second_remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .expect("encode second advanced Remote Head");
    harness.reject_next_publication_as_stale(first_remote_bytes);
    harness.reject_next_publication_as_stale(second_remote_bytes);

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: created.id.clone(),
            title: "Local account".into(),
            username: "alice".into(),
            password: "second-password".into(),
            url: "https://local.example".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::Merged
    ));
    let entries = match harness.command(RuntimeCommand::ListEntries {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::EntryList(entries) => entries.entries,
        _ => panic!("expected entry list"),
    };
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|entry| entry.title == "Local account"));
    assert!(entries.iter().any(|entry| entry.title == "Remote account"));
    assert!(
        entries
            .iter()
            .any(|entry| entry.title == "Second remote account")
    );

    assert!(matches!(
        harness.command(RuntimeCommand::DeleteEntry {
            vault_id,
            entry_id: created.id,
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::Saved
                && result.entry.is_none()
    ));
    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode deletion publication")
        .vault;
    assert_eq!(published.root.entries.len(), 2);
    assert!(
        published
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Remote account")
    );
    assert!(
        published
            .root
            .entries
            .iter()
            .any(|entry| entry.title == "Second remote account")
    );
}

#[test]
fn stale_reconciliation_keeps_base_and_local_fixed_until_publication_is_confirmed() {
    let core = KeepassCore::new();
    let (base_bytes, entry_id) = vault_with_entry_bytes();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(base_bytes.clone());
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            state.active_vault_id.expect("active vault after unlock")
        }
        other => panic!("expected unlocked session, got {other:?}"),
    };

    let mut first_remote = core
        .load_database(&base_bytes, &key())
        .expect("decode Base")
        .vault;
    let first_remote_entry = first_remote
        .root
        .entries
        .iter_mut()
        .find(|entry| entry.id.to_string() == entry_id)
        .expect("remote entry");
    first_remote_entry.title = "First remote title".into();
    first_remote_entry.username = "remote-user".into();
    first_remote_entry.modified_at = 1_600_000_000;
    let first_remote_bytes = core
        .save_kdbx(&first_remote, &key(), SaveProfile::recommended())
        .expect("encode first Remote Head");

    let mut second_remote = first_remote;
    let second_remote_entry = second_remote
        .root
        .entries
        .iter_mut()
        .find(|entry| entry.id.to_string() == entry_id)
        .expect("second remote entry");
    second_remote_entry.title = "Base account".into();
    second_remote_entry.username = "base-user".into();
    second_remote_entry.modified_at = 1_800_000_000;
    let second_remote_bytes = core
        .save_kdbx(&second_remote, &key(), SaveProfile::recommended())
        .expect("encode second Remote Head");

    harness.reject_next_publication_as_stale(first_remote_bytes);
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Local title".into(),
            username: "base-user".into(),
            password: "base-password".into(),
            url: "https://base.example".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::SavedToCache
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::GetEntryDetail {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        RuntimeResponse::EntryDetail(detail)
            if detail.title == "Local title" && detail.username == "base-user"
    ));

    harness.reject_next_publication_as_stale(second_remote_bytes);
    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode confirmed Publication")
        .vault;
    let published_entry = core
        .project_entry_detail(&published, &entry_id)
        .expect("published entry");
    assert_eq!(published_entry.title, "Local title");
    assert_eq!(published_entry.username, "base-user");

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id,
            entry_id,
            title: "Local title".into(),
            username: "base-user".into(),
            password: "base-password".into(),
            url: "https://base.example".into(),
            notes: "after confirmed Base advancement".into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::Saved
    ));
}

#[test]
fn successful_conflict_split_preserves_local_then_adopts_remote_head() {
    let core = KeepassCore::new();
    let (base_bytes, local_entry_id) = vault_with_entry_bytes();
    let (remote_bytes, remote_entry_id) = foreign_remote_head_bytes(&base_bytes);
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(base_bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            state.active_vault_id.expect("active vault after unlock")
        }
        other => panic!("expected unlocked session, got {other:?}"),
    };

    harness.reject_next_publication_as_stale(remote_bytes.clone());
    let conflict_identity = match harness.command(RuntimeCommand::UpdateEntryFields {
        vault_id: vault_id.clone(),
        entry_id: local_entry_id.clone(),
        title: "Local conflict edit".into(),
        username: "base-user".into(),
        password: "local-password".into(),
        url: "https://base.example".into(),
        notes: String::new().into(),
        totp_uri: None,
        custom_fields: vec![],
    }) {
        RuntimeResponse::EntryMutationResult(result) => {
            assert_eq!(result.commit, CommitStatusDto::Committed);
            assert_eq!(result.publication.status, SaveVaultStatusDto::ConflictCopy);
            result
                .publication
                .conflict_copy_path
                .expect("provider Conflict Copy identity")
        }
        other => panic!("expected Conflict Split result, got {other:?}"),
    };
    assert_eq!(harness.provider_snapshot().bytes, remote_bytes);

    let active_entries = match harness.command(RuntimeCommand::ListEntries {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::EntryList(entries) => entries.entries,
        other => panic!("expected active entry list, got {other:?}"),
    };
    assert_eq!(active_entries.len(), 1);
    assert_eq!(active_entries[0].id, remote_entry_id);

    let conflict_name = conflict_identity
        .strip_prefix("onedrive:")
        .expect("OneDrive Conflict Copy identity");
    let items = match harness.command(RuntimeCommand::ListOneDriveChildren {
        parent_item_id: None,
    }) {
        RuntimeResponse::OneDriveItemList(items) => items.items,
        other => panic!("expected Provider item list, got {other:?}"),
    };
    let conflict_item = items
        .iter()
        .find(|item| item.name == conflict_name)
        .expect("durable sibling Conflict Copy");
    let conflict_vault = core
        .load_database(&harness.provider_item_bytes(&conflict_item.item_id), &key())
        .expect("decode Conflict Copy")
        .vault;
    let local_copy = core
        .project_entry_detail(&conflict_vault, &local_entry_id)
        .expect("local entry in Conflict Copy");
    assert_eq!(local_copy.title, "Local conflict edit");
    assert_eq!(local_copy.password, "local-password");

    let remote_root_id = match harness.command(RuntimeCommand::ListGroups {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups.root.id,
        other => panic!("expected Remote Head group tree, got {other:?}"),
    };
    assert!(matches!(
        harness.command(RuntimeCommand::CreateEntry {
            vault_id,
            parent_group_id: remote_root_id,
            entry_id: None,
            title: "After Conflict Split".into(),
            username: "alice".into(),
            password: "after-split-password".into(),
            url: "https://after-split.example".into(),
            notes: String::new().into(),
            totp_uri: None,
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::Saved
    ));
}

#[test]
fn failed_conflict_copy_preservation_keeps_local_until_retry_completes_split() {
    let core = KeepassCore::new();
    let (base_bytes, local_entry_id) = vault_with_entry_bytes();
    let (remote_bytes, remote_entry_id) = foreign_remote_head_bytes(&base_bytes);
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(base_bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            state.active_vault_id.expect("active vault after unlock")
        }
        other => panic!("expected unlocked session, got {other:?}"),
    };

    harness.reject_next_publication_as_stale(remote_bytes.clone());
    harness.fail_next_conflict_copy_preservation();
    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: local_entry_id.clone(),
            title: "First local conflict edit".into(),
            username: "base-user".into(),
            password: "local-password".into(),
            url: "https://base.example".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::ConflictCopy
                && result.publication.conflict_copy_path.as_deref()
                    == Some("onedrive:pending-conflict-copy")
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::GetEntryDetail {
            vault_id: vault_id.clone(),
            entry_id: local_entry_id.clone(),
        }),
        RuntimeResponse::EntryDetail(detail) if detail.title == "First local conflict edit"
    ));
    assert_eq!(harness.provider_snapshot().bytes, remote_bytes);

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: local_entry_id.clone(),
            title: "Latest local conflict edit".into(),
            username: "base-user".into(),
            password: "latest-local-password".into(),
            url: "https://base.example".into(),
            notes: "committed while Conflict Copy was pending".into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::ConflictCopy
    ));
    let items_before_retry = match harness.command(RuntimeCommand::ListOneDriveChildren {
        parent_item_id: None,
    }) {
        RuntimeResponse::OneDriveItemList(items) => items.items,
        other => panic!("expected Provider item list, got {other:?}"),
    };
    assert_eq!(items_before_retry.len(), 1);

    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: vault_id.clone(),
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    let active_entries = match harness.command(RuntimeCommand::ListEntries { vault_id }) {
        RuntimeResponse::EntryList(entries) => entries.entries,
        other => panic!("expected active entry list, got {other:?}"),
    };
    assert_eq!(active_entries.len(), 1);
    assert_eq!(active_entries[0].id, remote_entry_id);

    let items = match harness.command(RuntimeCommand::ListOneDriveChildren {
        parent_item_id: None,
    }) {
        RuntimeResponse::OneDriveItemList(items) => items.items,
        other => panic!("expected Provider item list, got {other:?}"),
    };
    let conflict_item = items
        .iter()
        .find(|item| item.name.contains("VaultKern conflict"))
        .expect("retried durable Conflict Copy");
    let conflict_vault = core
        .load_database(&harness.provider_item_bytes(&conflict_item.item_id), &key())
        .expect("decode retried Conflict Copy")
        .vault;
    let local_copy = core
        .project_entry_detail(&conflict_vault, &local_entry_id)
        .expect("latest Local entry in Conflict Copy");
    assert_eq!(local_copy.title, "Latest local conflict edit");
    assert_eq!(local_copy.password, "latest-local-password");
    assert_eq!(
        local_copy.notes,
        "committed while Conflict Copy was pending"
    );
}

#[test]
fn local_file_flow_publishes_through_the_runtime_protocol() {
    let directory = tempfile::tempdir().expect("temporary local Provider directory");
    let path = directory.path().join("local-provider.kdbx");
    std::fs::write(&path, empty_vault_bytes()).expect("write local Provider snapshot");
    let mut harness = RuntimeProtocolHarness::resident();
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec!["runtime-core".into(), "resident-app".into()],
    });

    let vault_id = match harness.command(RuntimeCommand::OpenLocalVault {
        path: path.to_string_lossy().into_owned(),
    }) {
        RuntimeResponse::VaultOpened(handle) => handle.vault_id,
        _ => panic!("expected opened local vault"),
    };
    assert!(matches!(
        harness.command(RuntimeCommand::UnlockWithPassword {
            vault_id: vault_id.clone(),
            password: "demo-password".into(),
        }),
        RuntimeResponse::SessionState(state) if state.unlocked
    ));
    let root_id = match harness.command(RuntimeCommand::ListGroups {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups.root.id,
        _ => panic!("expected group tree"),
    };
    let created = match harness.command(RuntimeCommand::CreateEntry {
        vault_id: vault_id.clone(),
        parent_group_id: root_id,
        entry_id: None,
        title: "Local Provider entry".into(),
        username: "alice".into(),
        password: "secret".into(),
        url: "https://local-provider.example".into(),
        notes: String::new().into(),
        totp_uri: None,
    }) {
        RuntimeResponse::EntryMutationResult(result) => {
            assert_eq!(result.commit, CommitStatusDto::Committed);
            assert_eq!(result.publication.status, SaveVaultStatusDto::Saved);
            result.entry.expect("created local entry detail")
        }
        _ => panic!("expected committed local entry mutation"),
    };

    let published = std::fs::read(path).expect("read published local Provider snapshot");
    let vault = KeepassCore::new()
        .load_database(&published, &key())
        .expect("decode published local Provider snapshot")
        .vault;
    assert!(
        vault
            .root
            .entries
            .iter()
            .any(|entry| entry.id.to_string() == created.id)
    );
}

#[test]
fn resident_entry_commit_can_finish_while_publication_is_pending() {
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(empty_vault_bytes());
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            state.active_vault_id.expect("active vault after unlock")
        }
        _ => panic!("expected unlocked session"),
    };
    let root_id = match harness.command(RuntimeCommand::ListGroups {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups.root.id,
        _ => panic!("expected group tree"),
    };
    let before = harness.provider_snapshot();
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();

    let created = match harness.command(RuntimeCommand::CreateEntry {
        vault_id: vault_id.clone(),
        parent_group_id: root_id,
        entry_id: None,
        title: "Offline account".into(),
        username: "alice".into(),
        password: "first-password".into(),
        url: "https://offline.example".into(),
        notes: String::new().into(),
        totp_uri: None,
    }) {
        RuntimeResponse::EntryMutationResult(result) => {
            assert_eq!(result.commit, CommitStatusDto::Committed);
            assert_eq!(result.publication.status, SaveVaultStatusDto::SavedToCache);
            result.entry.expect("pending committed entry")
        }
        _ => panic!("expected pending committed entry mutation"),
    };
    let still_remote = harness.provider_snapshot();
    assert_eq!(still_remote.bytes, before.bytes);

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: created.id.clone(),
            title: "Offline account updated".into(),
            username: "alice".into(),
            password: "second-password".into(),
            url: "https://offline.example".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::GetEntryDetail {
            vault_id,
            entry_id: created.id,
        }),
        RuntimeResponse::EntryDetail(detail)
            if detail.title == "Offline account updated"
                && detail.password == "second-password"
    ));
}

#[test]
fn pending_publication_survives_lock_restart_later_commit_and_retry() {
    let core = KeepassCore::new();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(empty_vault_bytes());
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    let vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            state.active_vault_id.expect("active vault after unlock")
        }
        other => panic!("expected unlocked session, got {other:?}"),
    };
    let root_id = match harness.command(RuntimeCommand::ListGroups {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups.root.id,
        other => panic!("expected group tree, got {other:?}"),
    };
    let remote_before = harness.provider_snapshot();
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();

    let entry_id = match harness.command(RuntimeCommand::CreateEntry {
        vault_id: vault_id.clone(),
        parent_group_id: root_id,
        entry_id: None,
        title: "Offline account".into(),
        username: "alice".into(),
        password: "first-password".into(),
        url: "https://offline.example".into(),
        notes: String::new().into(),
        totp_uri: None,
    }) {
        RuntimeResponse::EntryMutationResult(result) => {
            assert_eq!(result.commit, CommitStatusDto::Committed);
            assert_eq!(result.publication.status, SaveVaultStatusDto::SavedToCache);
            result.entry.expect("committed offline entry").id
        }
        other => panic!("expected pending entry mutation, got {other:?}"),
    };
    assert_eq!(harness.provider_snapshot().bytes, remote_before.bytes);

    assert!(matches!(
        harness.command(RuntimeCommand::LockSession),
        RuntimeResponse::SessionState(state) if !state.unlocked
    ));
    let writes_before_unlock = harness.provider_write_count();
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    assert!(matches!(
        harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
            password: "demo-password".into(),
        }),
        RuntimeResponse::SessionState(state)
            if state.unlocked
                && state
                    .source_status
                    .as_ref()
                    .is_some_and(|status| status.remote_state == "pending_sync")
    ));
    assert_eq!(
        harness.provider_write_count(),
        writes_before_unlock + 1,
        "unlock automatically retries Publication without replaying the mutation"
    );
    assert!(matches!(
        harness.command(RuntimeCommand::GetEntryDetail {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        RuntimeResponse::EntryDetail(detail)
            if detail.title == "Offline account" && detail.password == "first-password"
    ));

    harness.command(RuntimeCommand::LockSession);
    harness.restart_resident();
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
        ],
    });
    harness.command(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: harness.drive_id().into(),
        item_id: harness.item_id().into(),
    });
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    let restarted_vault_id = match harness.command(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    }) {
        RuntimeResponse::SessionState(state) => {
            assert!(state.unlocked);
            assert!(
                state
                    .source_status
                    .is_some_and(|status| status.remote_state == "pending_sync")
            );
            state.active_vault_id.expect("active vault after restart")
        }
        other => panic!("expected restarted session, got {other:?}"),
    };
    assert_eq!(
        harness.provider_write_count(),
        1,
        "restart recovery automatically retries the durable pending Publication"
    );
    assert!(matches!(
        harness.command(RuntimeCommand::GetEntryDetail {
            vault_id: restarted_vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        RuntimeResponse::EntryDetail(detail)
            if detail.title == "Offline account" && detail.password == "first-password"
    ));

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: restarted_vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Offline account updated".into(),
            username: "alice".into(),
            password: "second-password".into(),
            url: "https://offline.example".into(),
            notes: "later commit".into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryMutationResult(result)
            if result.commit == CommitStatusDto::Committed
                && result.publication.status == SaveVaultStatusDto::SavedToCache
    ));
    assert_eq!(harness.provider_snapshot().bytes, remote_before.bytes);

    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: restarted_vault_id.clone(),
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    let published = harness.provider_snapshot();
    assert!(published.revision > remote_before.revision);
    let published_vault = core
        .load_database(&published.bytes, &key())
        .expect("decode recovered Publication")
        .vault;
    let published_entry = core
        .project_entry_detail(&published_vault, &entry_id)
        .expect("published recovered entry");
    assert_eq!(published_entry.title, "Offline account updated");
    assert_eq!(published_entry.password, "second-password");
    assert_eq!(published_entry.notes, "later commit");

    let writes_after_confirmation = harness.provider_write_count();
    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: restarted_vault_id,
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    assert_eq!(
        harness.provider_write_count(),
        writes_after_confirmation,
        "confirmed Publication clears the durable pending write"
    );
}

#[test]
fn harness_keeps_browser_commands_behind_the_protocol_session_boundary() {
    let mut harness = RuntimeProtocolHarness::browser_with_in_memory_vault(empty_vault_bytes());
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "browser-extension".into(),
            "browser-autofill".into(),
        ],
    });

    assert!(matches!(
        harness.command(RuntimeCommand::OpenLocalVault {
            path: "/not-authorized.kdbx".into(),
        }),
        RuntimeResponse::Error(error) if error.code == "browser_command_forbidden"
    ));
}
