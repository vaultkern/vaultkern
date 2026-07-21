#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryProjectionDigest {
    detail: (
        String,
        String,
        Option<u32>,
        String,
        String,
        String,
        String,
        Option<String>,
        Vec<String>,
    ),
    presentation: (Option<String>, Option<String>, Option<String>),
    lineage: (Option<String>, bool),
    times: (u64, u64, Option<u64>, Option<u64>, Option<u64>),
    custom_fields: Vec<(String, String, bool)>,
    custom_data: Vec<(String, String)>,
    attachments: Vec<(String, Vec<u8>, bool)>,
    totp: Option<(String, String, u32, u64, Option<String>, Option<String>)>,
    passkey: Option<(
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        bool,
        bool,
    )>,
    auto_type: (
        Option<bool>,
        Option<i32>,
        Option<String>,
        Vec<(String, String)>,
    ),
}

#[test]
fn external_fixtures_expose_entry_projection_oracle() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_RECYCLE_BIN_WITH_DATA, "123"),
    ] {
        let loaded = load_fixture(&core, fixture, password);
        assert_eq!(
            collect_entry_projection_matrix(&core, &loaded),
            collect_raw_entry_projection_matrix(&loaded)
        );
    }
}

#[test]
fn external_entry_projection_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_RECYCLE_BIN_WITH_DATA, "123"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external entry projection fixture");
        let before = collect_entry_projection_matrix(&core, &loaded);
        assert_eq!(before, collect_raw_entry_projection_matrix(&loaded));

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external entry projection fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload external entry projection fixture");
        let after = collect_entry_projection_matrix(&core, &reloaded);

        assert_eq!(after, before);
        assert_eq!(after, collect_raw_entry_projection_matrix(&reloaded));
    }
}

fn collect_entry_projection_matrix(
    core: &KeepassCore,
    vault: &Vault,
) -> Vec<(String, EntryProjectionDigest)> {
    collect_entry_projection_matrix_for_group(core, vault, &vault.root, String::new())
}

fn collect_raw_entry_projection_matrix(vault: &Vault) -> Vec<(String, EntryProjectionDigest)> {
    collect_raw_entry_projection_matrix_for_group(&vault.root, String::new())
}

fn collect_entry_projection_matrix_for_group(
    core: &KeepassCore,
    vault: &Vault,
    group: &vaultkern_core::Group,
    path: String,
) -> Vec<(String, EntryProjectionDigest)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            collect_entry_projection_digest(core, vault, &entry.id.to_string()),
        ));
    }
    for child in &group.children {
        rows.extend(collect_entry_projection_matrix_for_group(
            core,
            vault,
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_raw_entry_projection_matrix_for_group(
    group: &vaultkern_core::Group,
    path: String,
) -> Vec<(String, EntryProjectionDigest)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            collect_raw_entry_projection_digest(entry),
        ));
    }
    for child in &group.children {
        rows.extend(collect_raw_entry_projection_matrix_for_group(
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_entry_projection_digest(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> EntryProjectionDigest {
    let detail = core
        .project_entry_detail(vault, entry_id)
        .expect("project entry detail");
    let presentation = core
        .project_entry_presentation_metadata(vault, entry_id)
        .expect("project entry presentation metadata");
    let lineage = core
        .project_entry_lineage_report_metadata(vault, entry_id)
        .expect("project entry lineage metadata");
    let times = core
        .project_entry_times(vault, entry_id)
        .expect("project entry times");
    let custom_fields = core
        .list_entry_custom_fields(vault, entry_id)
        .expect("list entry custom fields")
        .into_iter()
        .map(|field| (field.key, field.value, field.protected))
        .collect();
    let custom_data = core
        .list_entry_custom_data(vault, entry_id)
        .expect("list entry custom data")
        .into_iter()
        .map(|item| (item.key, item.value))
        .collect();
    let attachments = core
        .list_entry_attachments(vault, entry_id)
        .expect("list entry attachments")
        .into_iter()
        .map(|attachment| {
            let name = attachment.name;
            let content = core
                .project_entry_attachment_content(vault, entry_id, &name)
                .expect("project entry attachment content");
            assert_eq!(content.name, name);
            (name, content.data, attachment.protect_in_memory)
        })
        .collect();
    let totp = core
        .project_entry_totp(vault, entry_id)
        .expect("project entry totp");
    let passkey = core
        .project_entry_passkey(vault, entry_id)
        .expect("project entry passkey");
    let auto_type = core
        .project_entry_auto_type(vault, entry_id)
        .expect("project entry auto type");

    EntryProjectionDigest {
        detail: (
            detail.id,
            detail.title,
            detail.icon_id,
            detail.username,
            detail.password,
            detail.url,
            detail.notes,
            detail.custom_icon_id,
            detail.tags,
        ),
        presentation: (
            presentation.foreground_color,
            presentation.background_color,
            presentation.override_url,
        ),
        lineage: (lineage.previous_parent_id, lineage.exclude_from_reports),
        times: (
            times.created_at,
            times.modified_at,
            times.last_accessed_at,
            times.usage_count,
            times.location_changed_at,
        ),
        custom_fields,
        custom_data,
        attachments,
        totp: totp.map(|value| {
            (
                value.secret_base32,
                format!("{:?}", value.algorithm),
                value.digits,
                value.period_seconds,
                value.issuer,
                value.account_name,
            )
        }),
        passkey: passkey.as_ref().map(|value| {
            (
                value.username.clone(),
                value.credential_id.clone(),
                value.generated_user_id.clone(),
                value.relying_party.clone(),
                value.user_handle.clone(),
                value.backup_eligible,
                value.backup_state,
            )
        }),
        auto_type: (
            auto_type.enabled,
            auto_type.obfuscation,
            auto_type.default_sequence,
            auto_type
                .associations
                .into_iter()
                .map(|assoc| (assoc.window, assoc.sequence))
                .collect(),
        ),
    }
}

fn collect_raw_entry_projection_digest(entry: &vaultkern_core::Entry) -> EntryProjectionDigest {
    EntryProjectionDigest {
        detail: (
            entry.id.to_string(),
            entry.title.clone(),
            entry.icon_id,
            entry.username.clone(),
            entry.password.clone(),
            entry.url.clone(),
            entry.notes.clone(),
            entry.custom_icon_id.map(|id| id.to_string()),
            entry.tags.iter().cloned().collect(),
        ),
        presentation: (
            entry.foreground_color.clone(),
            entry.background_color.clone(),
            entry.override_url.clone(),
        ),
        lineage: (
            entry.previous_parent.map(|id| id.to_string()),
            entry.exclude_from_reports,
        ),
        times: (
            entry.created_at,
            entry.modified_at,
            entry.last_accessed_at,
            entry.usage_count,
            entry.location_changed_at,
        ),
        custom_fields: entry
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.value.clone(), value.protected))
            .collect(),
        custom_data: entry
            .custom_data
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        attachments: entry
            .attachments
            .values()
            .map(|attachment| {
                (
                    attachment.name.clone(),
                    attachment.data.as_bytes().to_vec(),
                    attachment.protect_in_memory,
                )
            })
            .collect(),
        totp: entry.totp.as_ref().map(|value| {
            (
                value.secret_base32.clone(),
                format!("{:?}", value.algorithm),
                value.digits,
                value.period_seconds,
                value.issuer.clone(),
                value.account_name.clone(),
            )
        }),
        passkey: entry.passkey.as_ref().map(|value| {
            (
                value.username.clone(),
                value.credential_id.clone(),
                value.generated_user_id.clone(),
                value.relying_party.clone(),
                value.user_handle.clone(),
                value.backup_eligible,
                value.backup_state,
            )
        }),
        auto_type: entry
            .auto_type
            .as_ref()
            .map(|value| {
                (
                    value.enabled,
                    value.obfuscation,
                    value.default_sequence.clone(),
                    value
                        .associations
                        .iter()
                        .map(|assoc| (assoc.window.clone(), assoc.sequence.clone()))
                        .collect(),
                )
            })
            .unwrap_or((None, None, None, Vec::new())),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}
