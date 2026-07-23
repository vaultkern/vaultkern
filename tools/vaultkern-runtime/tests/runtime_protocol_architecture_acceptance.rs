mod support;

use support::RuntimeProtocolHarness;
use vaultkern_core::{CompositeKey, EntryCreate, KeepassCore, SaveProfile, Vault};
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
    let remote_bytes = core
        .save_kdbx(&remote, &key(), SaveProfile::recommended())
        .expect("encode advanced Remote Head");
    harness.reject_next_publication_as_stale(remote_bytes);

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
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| entry.title == "Local account"));
    assert!(entries.iter().any(|entry| entry.title == "Remote account"));

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
    assert_eq!(published.root.entries.len(), 1);
    assert_eq!(published.root.entries[0].title, "Remote account");
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
