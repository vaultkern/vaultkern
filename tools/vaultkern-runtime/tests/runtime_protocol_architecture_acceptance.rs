mod support;

use support::RuntimeProtocolHarness;
use vaultkern_core::{CompositeKey, EntryCreate, KeepassCore, SaveProfile, Vault};
use vaultkern_runtime_protocol::{
    PROTOCOL_VERSION, RuntimeCommand, RuntimeResponse, SaveVaultStatusDto,
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
        RuntimeResponse::EntryDetail(detail) => detail,
        _ => panic!("expected created entry"),
    };

    let before_publication = harness.provider_snapshot();
    assert!(matches!(
        harness.command(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        }),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Saved
    ));
    let first_publication = harness.provider_snapshot();
    assert_ne!(first_publication.bytes, before_publication.bytes);
    assert!(first_publication.revision > before_publication.revision);

    assert!(matches!(
        harness.command(RuntimeCommand::UpdateEntryFields {
            vault_id: vault_id.clone(),
            entry_id: created.id,
            title: "Local account".into(),
            username: "alice".into(),
            password: "second-password".into(),
            url: "https://local.example".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }),
        RuntimeResponse::EntryDetail(_)
    ));

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
        harness.command(RuntimeCommand::SaveVault {
            vault_id: vault_id.clone(),
        }),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Merged
    ));
    let entries = match harness.command(RuntimeCommand::ListEntries { vault_id }) {
        RuntimeResponse::EntryList(entries) => entries.entries,
        _ => panic!("expected entry list"),
    };
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| entry.title == "Local account"));
    assert!(entries.iter().any(|entry| entry.title == "Remote account"));
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
    assert!(matches!(
        harness.command(RuntimeCommand::CreateEntry {
            vault_id: vault_id.clone(),
            parent_group_id: root_id,
            entry_id: None,
            title: "Local Provider entry".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://local-provider.example".into(),
            notes: String::new().into(),
            totp_uri: None,
        }),
        RuntimeResponse::EntryDetail(_)
    ));
    assert!(matches!(
        harness.command(RuntimeCommand::SaveVault { vault_id }),
        RuntimeResponse::SaveVaultResult(result)
            if result.status == SaveVaultStatusDto::Saved
    ));

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
            .any(|entry| entry.title == "Local Provider entry")
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
