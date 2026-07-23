mod support;

use support::RuntimeProtocolHarness;
use vaultkern_core::{
    CompositeKey, EntryCreate, EntryCustomFieldInput, EntryUpdate, KeepassCore, PasskeyRecord,
    SaveProfile, TotpAlgorithm, TotpSpec, Vault, derive_transformed_key,
    save_kdbx_with_transformed_key,
};
use vaultkern_runtime_protocol::{
    CommitStatusDto, DatabaseCredentialsUpdateDto, DatabaseEncryptionSettingsDto,
    DatabaseHistorySettingsDto, DatabaseMetadataSettingsDto, DatabaseRecycleBinSettingsDto,
    DatabaseSettingsUpdateDto, EntryCustomFieldDto, OptionalSettingUpdateDto, PROTOCOL_VERSION,
    RuntimeCommand, RuntimeResponse, SaveVaultStatusDto,
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

fn vault_with_entry_adjacent_data_bytes() -> (Vec<u8>, String) {
    let core = KeepassCore::new();
    let mut vault = Vault::empty("Entry-adjacent Acceptance");
    let root_id = vault.root.id.to_string();
    let entry_id = core
        .add_entry(
            &mut vault,
            &root_id,
            EntryCreate {
                title: "Adjacent account".into(),
                username: "alice".into(),
                password: "base-password".into(),
                url: "https://adjacent.example".into(),
                notes: String::new(),
            },
        )
        .expect("create adjacent mutation entry")
        .id;
    core.set_entry_totp(
        &mut vault,
        &entry_id,
        TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("VaultKern".into()),
            account_name: Some("alice".into()),
        },
    )
    .expect("seed TOTP");
    core.upsert_entry_custom_field(
        &mut vault,
        &entry_id,
        EntryCustomFieldInput {
            key: "Environment".into(),
            value: "staging".into(),
            protected: true,
        },
    )
    .expect("seed custom field");
    core.set_entry_passkey(
        &mut vault,
        &entry_id,
        PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            generated_user_id: None,
            private_key_pem: String::from("acceptance-private-key").into(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: true,
            backup_state: true,
        },
    )
    .expect("seed Entry passkey");
    let bytes = core
        .save_kdbx(&vault, &key(), SaveProfile::recommended())
        .expect("encode entry-adjacent acceptance vault");
    (bytes, entry_id)
}

fn vault_with_remaining_mutation_data_bytes() -> (Vec<u8>, String, String) {
    let core = KeepassCore::new();
    let mut vault = Vault::empty("Remaining Mutation Acceptance");
    let root_id = vault.root.id.to_string();
    let entry_id = core
        .add_entry(
            &mut vault,
            &root_id,
            EntryCreate {
                title: "Historic account".into(),
                username: "historic-user".into(),
                password: "historic-password".into(),
                url: "https://history.example".into(),
                notes: "history snapshot".into(),
            },
        )
        .expect("create history restoration entry")
        .id;
    core.snapshot_entry_to_history(&mut vault, &entry_id)
        .expect("seed entry history");
    core.update_entry_fields(
        &mut vault,
        &entry_id,
        EntryUpdate {
            title: Some("Current account".into()),
            username: Some("current-user".into()),
            password: Some("current-password".into()),
            url: Some("https://current.example".into()),
            notes: Some("current state".into()),
        },
    )
    .expect("seed current entry state");
    let bytes = core
        .save_kdbx(&vault, &key(), SaveProfile::recommended())
        .expect("encode remaining-mutation acceptance vault");
    (bytes, root_id, entry_id)
}

fn expect_adjacent_commit(
    response: RuntimeResponse,
    expected_status: SaveVaultStatusDto,
) -> vaultkern_runtime_protocol::EntryDetailDto {
    let result = match response {
        RuntimeResponse::EntryMutationResult(result) => result,
        RuntimeResponse::Error(error) => panic!(
            "expected committed entry-adjacent mutation, got error {}: {}",
            error.code, error.message
        ),
        RuntimeResponse::EntryDetail(_) => {
            panic!("expected committed entry-adjacent mutation, got entry_detail")
        }
        _ => panic!("expected committed entry-adjacent mutation, got another response type"),
    };
    assert_eq!(result.commit, CommitStatusDto::Committed);
    assert_eq!(result.publication.status, expected_status);
    result
        .entry
        .expect("entry-adjacent mutation returns detail")
}

fn expect_vault_commit(
    response: RuntimeResponse,
    expected_status: SaveVaultStatusDto,
) -> Option<String> {
    let RuntimeResponse::VaultMutationResult(result) = response else {
        panic!("expected committed vault mutation");
    };
    assert_eq!(result.commit, CommitStatusDto::Committed);
    assert_eq!(result.publication.status, expected_status);
    result.created_group_id
}

fn group_tree_contains(
    group: &vaultkern_runtime_protocol::GroupNodeDto,
    group_id: &str,
    title: &str,
) -> bool {
    (group.id == group_id && group.title == title)
        || group
            .children
            .iter()
            .any(|child| group_tree_contains(child, group_id, title))
}

fn expect_history_len(
    harness: &mut RuntimeProtocolHarness,
    vault_id: &str,
    entry_id: &str,
    expected: usize,
) {
    match harness.command(RuntimeCommand::ListEntryHistory {
        vault_id: vault_id.into(),
        entry_id: entry_id.into(),
    }) {
        RuntimeResponse::EntryHistoryList(history) => assert_eq!(history.items.len(), expected),
        other => panic!("expected entry history list, got {other:?}"),
    }
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
fn entry_adjacent_protocol_intents_commit_and_publish_without_follow_up_save() {
    let core = KeepassCore::new();
    let (bytes, entry_id) = vault_with_entry_adjacent_data_bytes();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "passkey-ceremonies".into(),
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
    let writes_before = harness.provider_write_count();

    let detail = expect_adjacent_commit(
        harness.command(RuntimeCommand::ClearEntryTotp {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    assert!(detail.totp.is_none());

    let detail = expect_adjacent_commit(
        harness.command(RuntimeCommand::AddEntryAttachment {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "recovery.txt".into(),
            data_base64: "aGVsbG8=".into(),
            protect_in_memory: true,
        }),
        SaveVaultStatusDto::Saved,
    );
    assert!(
        detail
            .attachments
            .iter()
            .any(|attachment| attachment.name == "recovery.txt" && attachment.protect_in_memory)
    );

    let detail = expect_adjacent_commit(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Adjacent account".into(),
            username: "alice".into(),
            password: "base-password".into(),
            url: "https://adjacent.example".into(),
            notes: "custom field committed".into(),
            totp_uri: None,
            custom_fields: vec![EntryCustomFieldDto {
                key: "Environment".into(),
                value: "production".into(),
                protected: true,
            }],
        }),
        SaveVaultStatusDto::Saved,
    );
    assert!(detail.custom_fields.iter().any(|field| {
        field.key == "Environment" && field.value == "production" && field.protected
    }));

    let detail = expect_adjacent_commit(
        harness.command(RuntimeCommand::ClearEntryPasskey {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    assert!(detail.passkey.is_none());
    assert_eq!(harness.provider_write_count(), writes_before + 4);

    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode published adjacent mutations")
        .vault;
    assert!(
        core.project_entry_totp(&published, &entry_id)
            .expect("project published TOTP")
            .is_none()
    );
    assert!(
        core.project_entry_passkey(&published, &entry_id)
            .expect("project published passkey")
            .is_none()
    );
    assert!(
        core.list_entry_custom_fields(&published, &entry_id)
            .expect("project published custom fields")
            .iter()
            .any(|field| {
                field.key == "Environment" && field.value == "production" && field.protected
            })
    );
    assert!(
        core.list_entry_attachments(&published, &entry_id)
            .expect("project published attachments")
            .iter()
            .any(|attachment| attachment.name == "recovery.txt" && attachment.protect_in_memory)
    );
}

#[test]
fn entry_adjacent_pending_commits_survive_restart_and_publish_in_receive_order() {
    let core = KeepassCore::new();
    let (bytes, entry_id) = vault_with_entry_adjacent_data_bytes();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "passkey-ceremonies".into(),
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
    let remote_before = harness.provider_snapshot();

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_adjacent_commit(
        harness.command(RuntimeCommand::ClearEntryTotp {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::SavedToCache,
    );
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_adjacent_commit(
        harness.command(RuntimeCommand::AddEntryAttachment {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            name: "pending.txt".into(),
            data_base64: "cGVuZGluZw==".into(),
            protect_in_memory: true,
        }),
        SaveVaultStatusDto::SavedToCache,
    );
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_adjacent_commit(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            title: "Adjacent account".into(),
            username: "alice".into(),
            password: "latest-password".into(),
            url: "https://adjacent.example".into(),
            notes: "latest pending state".into(),
            totp_uri: None,
            custom_fields: vec![EntryCustomFieldDto {
                key: "Environment".into(),
                value: "pending-production".into(),
                protected: true,
            }],
        }),
        SaveVaultStatusDto::SavedToCache,
    );
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_adjacent_commit(
        harness.command(RuntimeCommand::ClearEntryPasskey {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::SavedToCache,
    );
    assert_eq!(harness.provider_snapshot().bytes, remote_before.bytes);

    harness.command(RuntimeCommand::LockSession);
    harness.restart_resident();
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "passkey-ceremonies".into(),
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
        other => panic!("expected restarted pending session, got {other:?}"),
    };
    let detail = match harness.command(RuntimeCommand::GetEntryDetail {
        vault_id: restarted_vault_id.clone(),
        entry_id: entry_id.clone(),
    }) {
        RuntimeResponse::EntryDetail(detail) => detail,
        other => panic!("expected recovered adjacent entry, got {other:?}"),
    };
    assert_eq!(detail.password, "latest-password");
    assert!(detail.totp.is_none());
    assert!(detail.passkey.is_none());
    assert!(detail.custom_fields.iter().any(|field| {
        field.key == "Environment" && field.value == "pending-production" && field.protected
    }));
    assert!(
        detail
            .attachments
            .iter()
            .any(|attachment| attachment.name == "pending.txt" && attachment.protect_in_memory)
    );

    match harness.command(RuntimeCommand::RetryVaultSourceSync {
        vault_id: restarted_vault_id.clone(),
    }) {
        RuntimeResponse::VaultSourceStatus(status) => {
            assert_eq!(status.remote_state, "pending_sync", "{status:?}")
        }
        RuntimeResponse::Error(error) => {
            panic!(
                "retry adjacent Publication failed: {}: {}",
                error.code, error.message
            )
        }
        _ => panic!("retry adjacent Publication returned another response type"),
    }
    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: restarted_vault_id,
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));
    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode retried adjacent Publication")
        .vault;
    let published_detail = core
        .project_entry_detail(&published, &entry_id)
        .expect("project retried adjacent entry");
    assert_eq!(published_detail.password, "latest-password");
    assert!(
        core.project_entry_totp(&published, &entry_id)
            .expect("project retried TOTP")
            .is_none()
    );
    assert!(
        core.project_entry_passkey(&published, &entry_id)
            .expect("project retried passkey")
            .is_none()
    );
    assert!(
        core.list_entry_custom_fields(&published, &entry_id)
            .expect("project retried custom fields")
            .iter()
            .any(|field| {
                field.key == "Environment" && field.value == "pending-production" && field.protected
            })
    );
    assert!(
        core.list_entry_attachments(&published, &entry_id)
            .expect("project retried attachments")
            .iter()
            .any(|attachment| attachment.name == "pending.txt" && attachment.protect_in_memory)
    );
}

#[test]
fn remaining_kdbx_mutations_commit_and_publish_through_one_protocol_intent() {
    let core = KeepassCore::new();
    let (bytes, root_id, entry_id) = vault_with_remaining_mutation_data_bytes();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "database-settings".into(),
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
    let writes_before = harness.provider_write_count();

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateDatabaseSettings {
            vault_id: vault_id.clone(),
            update: DatabaseSettingsUpdateDto {
                credentials: Some(DatabaseCredentialsUpdateDto {
                    new_password: Some("not-an-implicit-settings-write".into()),
                    remove_password: false,
                }),
                ..DatabaseSettingsUpdateDto::default()
            },
        }),
        RuntimeResponse::Error(error)
            if error.message.contains("fresh authenticated credential-update flow")
    ));
    assert_eq!(
        harness.provider_write_count(),
        writes_before,
        "credential invariants reject an implicit settings write before Publication"
    );

    let parent_group_id = expect_vault_commit(
        harness.command(RuntimeCommand::CreateGroup {
            vault_id: vault_id.clone(),
            parent_group_id: root_id.clone(),
            title: "Working Parent".into(),
        }),
        SaveVaultStatusDto::Saved,
    )
    .expect("create parent group returns its id");
    let group_id = expect_vault_commit(
        harness.command(RuntimeCommand::CreateGroup {
            vault_id: vault_id.clone(),
            parent_group_id: root_id.clone(),
            title: "Working".into(),
        }),
        SaveVaultStatusDto::Saved,
    )
    .expect("create child group returns its id");
    expect_vault_commit(
        harness.command(RuntimeCommand::RenameGroup {
            vault_id: vault_id.clone(),
            group_id: group_id.clone(),
            title: "Archive".into(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_vault_commit(
        harness.command(RuntimeCommand::MoveGroup {
            vault_id: vault_id.clone(),
            group_id: group_id.clone(),
            target_parent_group_id: parent_group_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_vault_commit(
        harness.command(RuntimeCommand::MoveEntryToGroup {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            target_group_id: group_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_vault_commit(
        harness.command(RuntimeCommand::RestoreEntryHistory {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            history_index: 0,
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_vault_commit(
        harness.command(RuntimeCommand::ClearEntryHistory {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_history_len(&mut harness, &vault_id, &entry_id, 0);
    expect_vault_commit(
        harness.command(RuntimeCommand::RecycleEntry {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_history_len(&mut harness, &vault_id, &entry_id, 0);
    expect_vault_commit(
        harness.command(RuntimeCommand::RestoreRecycledEntry {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            target_group_id: Some(root_id.clone()),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_history_len(&mut harness, &vault_id, &entry_id, 0);
    expect_vault_commit(
        harness.command(RuntimeCommand::DeleteGroup {
            vault_id: vault_id.clone(),
            group_id: parent_group_id.clone(),
        }),
        SaveVaultStatusDto::Saved,
    );
    expect_history_len(&mut harness, &vault_id, &entry_id, 0);

    let current_settings = match harness.command(RuntimeCommand::GetDatabaseSettings {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::DatabaseSettings(settings) => settings,
        other => panic!("expected current database settings, got {other:?}"),
    };
    let settings_result = match harness.command(RuntimeCommand::UpdateDatabaseSettings {
        vault_id: vault_id.clone(),
        update: DatabaseSettingsUpdateDto {
            metadata: Some(DatabaseMetadataSettingsDto {
                name: "Published Settings".into(),
                description: Some("committed with the vault".into()),
                default_username: Some("settings-user".into()),
            }),
            history: Some(DatabaseHistorySettingsDto {
                max_items_per_entry: Some(7),
                max_total_size_bytes: Some(70_000),
            }),
            recycle_bin: Some(DatabaseRecycleBinSettingsDto { enabled: false }),
            encryption: Some(DatabaseEncryptionSettingsDto {
                compression: "none".into(),
                cipher: "chacha20".into(),
                kdf: current_settings.encryption.kdf,
            }),
            autosave_delay_seconds: OptionalSettingUpdateDto::Set(15),
            ..DatabaseSettingsUpdateDto::default()
        },
    }) {
        RuntimeResponse::DatabaseSettingsCommitResult(result) => result,
        other => panic!("expected committed database settings, got {other:?}"),
    };
    assert_eq!(settings_result.commit, CommitStatusDto::Committed);
    assert_eq!(
        settings_result.save_result.status,
        SaveVaultStatusDto::Saved
    );
    expect_history_len(&mut harness, &vault_id, &entry_id, 0);
    assert_eq!(harness.provider_write_count(), writes_before + 11);

    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode published remaining mutations");
    assert_eq!(published.vault.name, "Published Settings");
    assert_eq!(published.vault.history_max_items, Some(7));
    assert_eq!(published.vault.recycle_bin_enabled, Some(false));
    assert!(
        core.find_group_view_by_id(&published.vault, &group_id)
            .is_none()
    );
    assert!(
        core.find_group_view_by_id(&published.vault, &parent_group_id)
            .is_none()
    );
    let restored = core
        .project_entry_detail(&published.vault, &entry_id)
        .expect("project restored entry");
    assert_eq!(restored.title, "Historic account");
    assert!(
        core.list_entry_history(&published.vault, &entry_id)
            .expect("project cleared history")
            .is_empty()
    );
    assert!(
        core.list_deleted_objects(&published.vault)
            .iter()
            .all(|deleted| deleted.id != entry_id)
    );
    assert_eq!(
        published.inspection.header.compression,
        vaultkern_core::Compression::None
    );
    assert_eq!(
        published.inspection.header.cipher,
        vaultkern_core::KdbxCipher::ChaCha20
    );
}

#[test]
fn remaining_kdbx_pending_commits_survive_restart_as_one_working_copy() {
    let core = KeepassCore::new();
    let (bytes, root_id, entry_id) = vault_with_remaining_mutation_data_bytes();
    let mut harness = RuntimeProtocolHarness::resident_with_in_memory_vault(bytes);
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "database-settings".into(),
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
    let remote_before = harness.provider_snapshot();

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    let group_id = expect_vault_commit(
        harness.command(RuntimeCommand::CreateGroup {
            vault_id: vault_id.clone(),
            parent_group_id: root_id,
            title: "Pending Group".into(),
        }),
        SaveVaultStatusDto::SavedToCache,
    )
    .expect("pending group creation returns its id");

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_vault_commit(
        harness.command(RuntimeCommand::MoveEntryToGroup {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            target_group_id: group_id.clone(),
        }),
        SaveVaultStatusDto::SavedToCache,
    );

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_vault_commit(
        harness.command(RuntimeCommand::RestoreEntryHistory {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            history_index: 0,
        }),
        SaveVaultStatusDto::SavedToCache,
    );

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_vault_commit(
        harness.command(RuntimeCommand::RecycleEntry {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
        }),
        SaveVaultStatusDto::SavedToCache,
    );

    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    expect_vault_commit(
        harness.command(RuntimeCommand::RestoreRecycledEntry {
            vault_id: vault_id.clone(),
            entry_id: entry_id.clone(),
            target_group_id: Some(group_id.clone()),
        }),
        SaveVaultStatusDto::SavedToCache,
    );

    let current_settings = match harness.command(RuntimeCommand::GetDatabaseSettings {
        vault_id: vault_id.clone(),
    }) {
        RuntimeResponse::DatabaseSettings(settings) => settings,
        other => panic!("expected current settings, got {other:?}"),
    };
    harness.make_next_publication_outcome_unknown_and_readback_unavailable();
    let settings_result = match harness.command(RuntimeCommand::UpdateDatabaseSettings {
        vault_id: vault_id.clone(),
        update: DatabaseSettingsUpdateDto {
            metadata: Some(DatabaseMetadataSettingsDto {
                name: "Pending Settings".into(),
                description: Some("survives restart".into()),
                default_username: Some("pending-user".into()),
            }),
            history: Some(DatabaseHistorySettingsDto {
                max_items_per_entry: Some(5),
                max_total_size_bytes: Some(50_000),
            }),
            recycle_bin: Some(DatabaseRecycleBinSettingsDto { enabled: true }),
            encryption: Some(DatabaseEncryptionSettingsDto {
                compression: "none".into(),
                cipher: "chacha20".into(),
                kdf: current_settings.encryption.kdf,
            }),
            ..DatabaseSettingsUpdateDto::default()
        },
    }) {
        RuntimeResponse::DatabaseSettingsCommitResult(result) => result,
        other => panic!("expected pending settings commit, got {other:?}"),
    };
    assert_eq!(settings_result.commit, CommitStatusDto::Committed);
    assert_eq!(
        settings_result.save_result.status,
        SaveVaultStatusDto::SavedToCache
    );
    assert_eq!(harness.provider_snapshot().bytes, remote_before.bytes);

    harness.command(RuntimeCommand::LockSession);
    harness.restart_resident();
    harness.command(RuntimeCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        capabilities: vec![
            "runtime-core".into(),
            "resident-app".into(),
            "one-drive".into(),
            "database-settings".into(),
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
        other => panic!("expected restarted pending session, got {other:?}"),
    };

    let groups = match harness.command(RuntimeCommand::ListGroups {
        vault_id: restarted_vault_id.clone(),
    }) {
        RuntimeResponse::GroupTree(groups) => groups,
        other => panic!("expected recovered group tree, got {other:?}"),
    };
    assert!(group_tree_contains(
        &groups.root,
        &group_id,
        "Pending Group"
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::ListEntries {
            vault_id: restarted_vault_id.clone(),
        }),
        RuntimeResponse::EntryList(entries)
            if entries.entries.iter().any(|entry| {
                entry.id == entry_id
                    && entry.title == "Historic account"
                    && entry.group_id == group_id
            })
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::GetDatabaseSettings {
            vault_id: restarted_vault_id.clone(),
        }),
        RuntimeResponse::DatabaseSettings(settings)
            if settings.metadata.name == "Pending Settings"
                && settings.history.max_items_per_entry == Some(5)
                && settings.encryption.cipher == "chacha20"
    ));

    match harness.command(RuntimeCommand::RetryVaultSourceSync {
        vault_id: restarted_vault_id.clone(),
    }) {
        RuntimeResponse::VaultSourceStatus(status) => {
            assert_eq!(status.remote_state, "pending_sync", "{status:?}");
        }
        other => panic!("expected pending retry status, got {other:?}"),
    }
    assert!(matches!(
        harness.command(RuntimeCommand::RetryVaultSourceSync {
            vault_id: restarted_vault_id,
        }),
        RuntimeResponse::VaultSourceStatus(status) if status.remote_state == "online"
    ));

    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode restarted remaining-mutation publication");
    assert_eq!(published.vault.name, "Pending Settings");
    assert_eq!(published.vault.history_max_items, Some(5));
    assert!(
        core.find_group_view_by_id(&published.vault, &group_id)
            .is_some_and(|group| group.title == "Pending Group")
    );
    let restored = core
        .project_entry_detail(&published.vault, &entry_id)
        .expect("project restarted restored entry");
    assert_eq!(restored.title, "Historic account");
    assert_eq!(
        core.find_entry_view_by_id(&published.vault, &entry_id)
            .expect("project restarted entry group-independent view")
            .id,
        entry_id
    );
    assert_eq!(
        published.inspection.header.cipher,
        vaultkern_core::KdbxCipher::ChaCha20
    );
}

#[test]
fn remaining_kdbx_mutation_reconciles_repeated_stale_heads_from_fixed_base() {
    let core = KeepassCore::new();
    let (base_bytes, root_id, _) = vault_with_remaining_mutation_data_bytes();
    let mut first_remote = core
        .load_database(&base_bytes, &key())
        .expect("decode remaining-mutation Base")
        .vault;
    let first_remote_id = core
        .add_entry(
            &mut first_remote,
            &root_id,
            EntryCreate {
                title: "First remote tree edit".into(),
                username: "remote-one".into(),
                password: "remote-one-password".into(),
                url: "https://remote-one.example".into(),
                notes: String::new(),
            },
        )
        .expect("create first remote tree edit")
        .id;
    let first_remote_bytes = core
        .save_kdbx(&first_remote, &key(), SaveProfile::recommended())
        .expect("encode first remaining-mutation Remote Head");

    let mut second_remote = first_remote;
    let second_remote_id = core
        .add_entry(
            &mut second_remote,
            &root_id,
            EntryCreate {
                title: "Second remote tree edit".into(),
                username: "remote-two".into(),
                password: "remote-two-password".into(),
                url: "https://remote-two.example".into(),
                notes: String::new(),
            },
        )
        .expect("create second remote tree edit")
        .id;
    let second_remote_bytes = core
        .save_kdbx(&second_remote, &key(), SaveProfile::recommended())
        .expect("encode second remaining-mutation Remote Head");

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
    harness.reject_next_publication_as_stale(first_remote_bytes);
    harness.reject_next_publication_as_stale(second_remote_bytes);

    let group_id = expect_vault_commit(
        harness.command(RuntimeCommand::CreateGroup {
            vault_id,
            parent_group_id: root_id,
            title: "Local reconciled group".into(),
        }),
        SaveVaultStatusDto::Merged,
    )
    .expect("reconciled group creation returns its id");

    let published = core
        .load_database(&harness.provider_snapshot().bytes, &key())
        .expect("decode reconciled remaining-mutation Publication")
        .vault;
    assert!(
        core.find_group_view_by_id(&published, &group_id)
            .is_some_and(|group| group.title == "Local reconciled group")
    );
    assert!(
        core.find_entry_view_by_id(&published, &first_remote_id)
            .is_some_and(|entry| entry.title == "First remote tree edit")
    );
    assert!(
        core.find_entry_view_by_id(&published, &second_remote_id)
            .is_some_and(|entry| entry.title == "Second remote tree edit")
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
    assert!(matches!(
        harness.command(RuntimeCommand::CreateGroup {
            vault_id: "not-authorized".into(),
            parent_group_id: "not-authorized".into(),
            title: "not-authorized".into(),
        }),
        RuntimeResponse::Error(error) if error.code == "browser_command_forbidden"
    ));
}
