#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    AttachmentContentUpdate, AttachmentMetadataUpdate, CompositeKey, EntryAttachmentInput,
    EntryCreate, EntryPresentationMetadataUpdate, EntryUpdate, GroupFlags, GroupMetadataUpdate,
    KdbxVersion, KeepassCore, MemoryProtection, StableSaveProfile, Vault,
    VaultIdentityMetadataUpdate, VaultMetadataUpdate, VaultSelectionMetadataUpdate,
};

const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryReadOnlyDigest {
    history_len: usize,
    latest_summary: (String, String, usize, usize),
    latest_detail: (String, String, String, String, String),
    latest_custom_fields: Vec<(String, bool)>,
    latest_custom_data: Vec<(String, String)>,
    latest_attachments: Vec<(String, usize, bool)>,
}

#[test]
fn code_built_vault_supports_pause_line_contract_on_stable_roundtrip() {
    let core = KeepassCore::new();
    let mut vault = core.empty_vault("PauseLine");
    let root_id = vault.root.id.to_string();

    let general = core
        .add_group(&mut vault, &root_id, "General")
        .expect("create general group");
    let archive = core
        .add_group(&mut vault, &root_id, "Archive")
        .expect("create archive group");

    let metadata = core
        .update_vault_metadata(
            &mut vault,
            VaultMetadataUpdate {
                description: Some("Kernel pause-line demo".into()),
                default_username: Some("demo-user".into()),
                color: Some("#224466".into()),
                history_max_items: Some(24),
                history_max_size: Some(12_345_678),
                memory_protection: Some(demo_memory_protection()),
            },
        )
        .expect("update pause-line metadata");
    assert_eq!(
        metadata.description.as_deref(),
        Some("Kernel pause-line demo")
    );
    assert_eq!(metadata.default_username.as_deref(), Some("demo-user"));
    assert_eq!(metadata.color.as_deref(), Some("#224466"));
    assert_eq!(metadata.history_max_items, Some(24));
    assert_eq!(metadata.history_max_size, Some(12_345_678));
    assert_eq!(metadata.memory_protection, Some(demo_memory_protection()));

    let selection = core
        .update_vault_selection_metadata(
            &mut vault,
            VaultSelectionMetadataUpdate {
                last_selected_group_id: Some(Some(general.id.clone())),
                last_top_visible_group_id: Some(Some(archive.id.clone())),
            },
        )
        .expect("update vault selection");
    assert_eq!(
        selection.last_selected_group_id.as_deref(),
        Some(general.id.as_str())
    );
    assert_eq!(
        selection.last_top_visible_group_id.as_deref(),
        Some(archive.id.as_str())
    );

    let identity = core
        .update_vault_identity_metadata(
            &mut vault,
            VaultIdentityMetadataUpdate {
                name: Some("PauseLine UI".into()),
                generator: Some("kernel-pause-line-contract".into()),
                ..Default::default()
            },
        )
        .expect("update vault identity");
    assert_eq!(identity.name, "PauseLine UI");
    assert_eq!(
        identity.generator.as_deref(),
        Some("kernel-pause-line-contract")
    );

    let general_detail = core
        .update_group_metadata(
            &mut vault,
            &general.id,
            GroupMetadataUpdate {
                title: Some("General".into()),
                notes: Some("Primary demo group".into()),
                icon_id: Some(48),
                flags: Some(GroupFlags {
                    is_expanded: Some(true),
                    enable_auto_type: None,
                    enable_searching: None,
                }),
            },
        )
        .expect("update general metadata");
    assert_eq!(general_detail.title, "General");
    assert_eq!(general_detail.icon_id, Some(48));

    let created_entry = core
        .add_entry(
            &mut vault,
            &general.id,
            EntryCreate {
                title: "Email".into(),
                username: "alice".into(),
                password: "secret".into(),
                url: "https://example.com".into(),
                notes: "demo entry".into(),
            },
        )
        .expect("create entry");
    let entry_id = created_entry.id.clone();

    let updated_entry = core
        .update_entry_fields(
            &mut vault,
            &entry_id,
            EntryUpdate {
                username: Some("alice@example.com".into()),
                notes: Some("demo entry updated".into()),
                ..Default::default()
            },
        )
        .expect("update entry fields");
    assert_eq!(updated_entry.username, "alice@example.com");

    let presentation = core
        .update_entry_presentation_metadata(
            &mut vault,
            &entry_id,
            EntryPresentationMetadataUpdate {
                icon_id: Some(Some(7)),
                foreground_color: Some(Some("#112233".into())),
                background_color: Some(Some("#445566".into())),
                override_url: Some(Some("cmd://demo".into())),
            },
        )
        .expect("update entry presentation");
    assert_eq!(presentation.icon_id, Some(7));
    assert_eq!(presentation.foreground_color.as_deref(), Some("#112233"));
    assert_eq!(presentation.background_color.as_deref(), Some("#445566"));
    assert_eq!(presentation.override_url.as_deref(), Some("cmd://demo"));

    core.add_entry_attachment(
        &mut vault,
        &entry_id,
        EntryAttachmentInput {
            name: "seed.bin".into(),
            data: b"seed".to_vec(),
            protect_in_memory: false,
        },
    )
    .expect("add attachment");
    let attachments = core
        .update_entry_attachment_metadata(
            &mut vault,
            &entry_id,
            "seed.bin",
            AttachmentMetadataUpdate {
                new_name: Some("notes.txt".into()),
                protect_in_memory: Some(true),
            },
        )
        .expect("rename attachment");
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].name, "notes.txt");
    assert!(attachments[0].protect_in_memory);

    let attachments = core
        .replace_entry_attachment_content(
            &mut vault,
            &entry_id,
            "notes.txt",
            AttachmentContentUpdate {
                data: b"hello pause line".to_vec(),
            },
        )
        .expect("replace attachment content");
    assert_eq!(attachments.len(), 1);

    let live_content = core
        .project_entry_attachment_content(&vault, &entry_id, "notes.txt")
        .expect("project attachment content");
    assert_eq!(live_content.data, b"hello pause line".to_vec());

    core.soft_delete_entry_to_recycle_bin(&mut vault, &entry_id)
        .expect("soft delete entry");
    let bin_metadata = core.project_vault_bin_template_metadata(&vault);
    assert_eq!(bin_metadata.recycle_bin_enabled, Some(true));
    assert!(bin_metadata.recycle_bin_group_id.is_some());
    assert_eq!(core.list_deleted_objects(&vault).len(), 1);

    core.restore_entry_from_recycle_bin(&mut vault, &entry_id, Some(&archive.id))
        .expect("restore entry into archive");
    assert!(core.list_deleted_objects(&vault).is_empty());
    assert_eq!(
        core.find_group_view_by_id(&vault, &archive.id)
            .expect("archive group after restore")
            .entry_count,
        1
    );
    assert_eq!(
        core.project_entry_attachment_content(&vault, &entry_id, "notes.txt")
            .expect("restored attachment content")
            .data,
        b"hello pause line".to_vec()
    );

    let loaded = save_and_load_with_stable_profile(&core, &vault, "pause-line");
    assert_eq!(loaded.summary.name, "PauseLine UI");
    assert_eq!(loaded.inspection.header.version, KdbxVersion::V4_1);

    let reloaded_metadata = core.project_vault_metadata(&loaded.vault);
    assert_eq!(
        reloaded_metadata.description.as_deref(),
        Some("Kernel pause-line demo")
    );
    assert_eq!(
        reloaded_metadata.default_username.as_deref(),
        Some("demo-user")
    );
    assert_eq!(reloaded_metadata.color.as_deref(), Some("#224466"));
    assert_eq!(reloaded_metadata.history_max_items, Some(24));
    assert_eq!(reloaded_metadata.history_max_size, Some(12_345_678));
    assert_eq!(
        reloaded_metadata.memory_protection,
        Some(demo_memory_protection())
    );

    let reloaded_selection = core.project_vault_selection_metadata(&loaded.vault);
    assert_eq!(
        reloaded_selection.last_selected_group_id.as_deref(),
        Some(general.id.as_str())
    );
    assert_eq!(
        reloaded_selection.last_top_visible_group_id.as_deref(),
        Some(archive.id.as_str())
    );

    let reloaded_identity = core.project_vault_identity_metadata(&loaded.vault);
    assert_eq!(reloaded_identity.name, "PauseLine UI");
    assert_eq!(
        reloaded_identity.generator.as_deref(),
        Some("kernel-pause-line-contract")
    );

    let reloaded_general = core
        .project_group_detail(&loaded.vault, &general.id)
        .expect("reloaded general detail");
    assert_eq!(reloaded_general.title, "General");
    assert_eq!(reloaded_general.icon_id, Some(48));
    assert_eq!(reloaded_general.notes, "Primary demo group");

    let reloaded_archive = core
        .find_group_view_by_id(&loaded.vault, &archive.id)
        .expect("reloaded archive view");
    assert_eq!(reloaded_archive.entry_count, 1);

    let reloaded_entry = core
        .project_entry_detail(&loaded.vault, &entry_id)
        .expect("reloaded entry detail");
    assert_eq!(reloaded_entry.title, "Email");
    assert_eq!(reloaded_entry.username, "alice@example.com");
    assert_eq!(reloaded_entry.password, "secret");
    assert_eq!(reloaded_entry.url, "https://example.com");
    assert_eq!(reloaded_entry.notes, "demo entry updated");

    let reloaded_presentation = core
        .project_entry_presentation_metadata(&loaded.vault, &entry_id)
        .expect("reloaded entry presentation");
    assert_eq!(reloaded_presentation.icon_id, Some(7));
    assert_eq!(
        reloaded_presentation.foreground_color.as_deref(),
        Some("#112233")
    );
    assert_eq!(
        reloaded_presentation.background_color.as_deref(),
        Some("#445566")
    );
    assert_eq!(
        reloaded_presentation.override_url.as_deref(),
        Some("cmd://demo")
    );

    let reloaded_content = core
        .project_entry_attachment_content(&loaded.vault, &entry_id, "notes.txt")
        .expect("reloaded attachment content");
    assert_eq!(reloaded_content.data, b"hello pause line".to_vec());

    let reloaded_bin = core.project_vault_bin_template_metadata(&loaded.vault);
    assert_eq!(reloaded_bin.recycle_bin_enabled, Some(true));
    assert!(reloaded_bin.recycle_bin_group_id.is_some());
    assert!(core.list_deleted_objects(&loaded.vault).is_empty());
}

#[test]
fn sync_fixture_supports_read_only_history_contract_after_stable_roundtrip() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let entry_id = vault.root.entries[0].id.to_string();

    let before = collect_history_read_only_digest(&core, &vault, &entry_id);
    assert_eq!(before.history_len, 10);
    assert_eq!(
        before.latest_summary,
        ("Sample Entry".into(), "User Name".into(), 4, 1)
    );
    assert_eq!(
        before.latest_detail,
        (
            "Sample Entry".into(),
            "User Name".into(),
            "Password".into(),
            "http://www.somesite.com/".into(),
            "Notes".into(),
        )
    );
    assert_eq!(
        before.latest_attachments,
        vec![("Sample attachment.txt".into(), 16, false)]
    );

    let loaded = save_and_load_with_stable_profile(&core, &vault, "a");
    let after = collect_history_read_only_digest(&core, &loaded.vault, &entry_id);
    assert_eq!(after, before);
}

fn collect_history_read_only_digest(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> HistoryReadOnlyDigest {
    let history = core
        .list_entry_history(vault, entry_id)
        .expect("list entry history");
    let latest_index = history.len() - 1;
    let latest_summary = history
        .last()
        .map(|item| {
            (
                item.title.clone(),
                item.username.clone(),
                item.custom_field_count,
                item.attachment_count,
            )
        })
        .expect("latest history summary");
    let latest_detail = core
        .project_entry_history_detail(vault, entry_id, latest_index)
        .map(|detail| {
            (
                detail.title,
                detail.username,
                detail.password,
                detail.url,
                detail.notes,
            )
        })
        .expect("project latest history detail");
    let latest_custom_fields = core
        .list_entry_history_custom_fields(vault, entry_id, latest_index)
        .expect("list latest history custom fields")
        .into_iter()
        .map(|field| (field.key, field.protected))
        .collect();
    let latest_custom_data = core
        .list_entry_history_custom_data(vault, entry_id, latest_index)
        .expect("list latest history custom data")
        .into_iter()
        .map(|item| (item.key, item.value))
        .collect();
    let latest_attachments = core
        .list_entry_history_attachments(vault, entry_id, latest_index)
        .expect("list latest history attachments")
        .into_iter()
        .map(|attachment| {
            (
                attachment.name,
                attachment.size,
                attachment.protect_in_memory,
            )
        })
        .collect();

    HistoryReadOnlyDigest {
        history_len: history.len(),
        latest_summary,
        latest_detail,
        latest_custom_fields,
        latest_custom_data,
        latest_attachments,
    }
}

fn demo_memory_protection() -> MemoryProtection {
    MemoryProtection {
        protect_title: true,
        protect_username: true,
        protect_password: true,
        protect_url: false,
        protect_notes: true,
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn save_and_load_with_stable_profile(
    core: &KeepassCore,
    vault: &Vault,
    password: &str,
) -> vaultkern_core::LoadedDatabase {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let bytes = core
        .save_kdbx_with_stable_profile(vault, &key, StableSaveProfile::recommended())
        .expect("save with stable profile");
    core.load_database(&bytes, &key)
        .expect("load database after stable save")
}
