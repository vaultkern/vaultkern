#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, EntryFieldProtection, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD: &[u8] =
    include_bytes!("../../../fixtures/kdbx/SyncDatabaseDifferentPassword.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryProjectionDigest {
    summaries: Vec<(String, String, usize, usize)>,
    last_detail: Option<(String, String, String, String, String)>,
    last_custom_fields: Vec<(String, bool)>,
    last_attachments: Vec<(String, usize, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistorySnapshotDigest {
    summary: (String, String, usize, usize),
    detail: (String, String, String, String, String),
    custom_fields: Vec<(String, bool)>,
    attachments: Vec<(String, usize, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncFixtureHistoryDigest {
    root_history_len: usize,
    root_snapshot_3: HistorySnapshotDigest,
    root_snapshot_9: HistorySnapshotDigest,
    subgroup_history_len: usize,
    subgroup_snapshot_1: HistorySnapshotDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserFixtureHistoryDigest {
    root_history_len: usize,
    root_snapshots: Vec<HistorySnapshotDigest>,
    subgroup_history_len: usize,
    subgroup_snapshot_0: HistorySnapshotDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistorySemanticSnapshotDigest {
    detail: (
        String,
        Option<u32>,
        String,
        String,
        String,
        String,
        Option<String>,
        Vec<String>,
    ),
    field_protection: EntryFieldProtection,
    custom_fields: Vec<(String, String, bool)>,
    custom_data: Vec<(String, String)>,
    attachments: Vec<(String, Vec<u8>, bool)>,
    totp: Option<(String, String, u32, u64, Option<String>, Option<String>)>,
    passkey: Option<(
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        bool,
        bool,
    )>,
}

#[test]
fn multi_fixture_exposes_richer_history_projection_oracle() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_NEW_DATABASE_MULTI, "a");

    let single_entry_id = vault.root.entries[0].id.to_string();
    assert_eq!(
        collect_history_projection(&core, &vault, &single_entry_id),
        HistoryProjectionDigest {
            summaries: vec![
                ("Sample Entry".into(), "User Name".into(), 0, 0),
                ("Sample Entry".into(), "User Name".into(), 0, 2),
                ("Sample Entry".into(), "User Name".into(), 0, 2),
                ("Sample Entry".into(), "User Name".into(), 0, 4),
                ("Sample Entry".into(), "User Name".into(), 0, 4),
                ("Sample Entry".into(), "User Name".into(), 0, 4),
            ],
            last_detail: Some((
                "Sample Entry".into(),
                "User Name".into(),
                "Password".into(),
                "http://www.somesite.com/".into(),
                "Notes".into(),
            )),
            last_custom_fields: vec![
                ("TOTP Seed".into(), true),
                ("TOTP Settings".into(), false),
                ("TestAttribute1".into(), false),
                ("testattribute1".into(), false),
            ],
            last_attachments: Vec::new(),
        }
    );

    let multi_entry_1_id = vault.root.entries[1].id.to_string();
    assert_eq!(
        collect_history_projection(&core, &vault, &multi_entry_1_id),
        HistoryProjectionDigest {
            summaries: vec![
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 0),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 2),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 2),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry 2".into(), "User Name 2".into(), 0, 4),
            ],
            last_detail: Some((
                "Sample Entry 2".into(),
                "User Name 2".into(),
                "Password2".into(),
                "http://www.somesite.com/".into(),
                "Notes".into(),
            )),
            last_custom_fields: vec![
                ("TOTP Seed".into(), true),
                ("TOTP Settings".into(), false),
                ("TestAttribute1".into(), false),
                ("testattribute1".into(), false),
            ],
            last_attachments: Vec::new(),
        }
    );

    let multi_entry_2_id = vault.root.entries[2].id.to_string();
    assert_eq!(
        collect_history_projection(&core, &vault, &multi_entry_2_id),
        HistoryProjectionDigest {
            summaries: vec![
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 0),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 2),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 2),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry - Clone".into(), "User Name".into(), 0, 4),
                ("Sample Entry 3".into(), "User Name 3".into(), 0, 4),
            ],
            last_detail: Some((
                "Sample Entry 3".into(),
                "User Name 3".into(),
                "Password3".into(),
                "http://www.somesite.com/".into(),
                "Notes".into(),
            )),
            last_custom_fields: vec![
                ("TOTP Seed".into(), true),
                ("TOTP Settings".into(), false),
                ("TestAttribute1".into(), false),
                ("testattribute1".into(), false),
            ],
            last_attachments: Vec::new(),
        }
    );

    let bank_entry = find_group_by_title(
        find_group_by_title(&vault.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup")
    .entries
    .first()
    .expect("bank entry");
    let bank_entry_id = bank_entry.id.to_string();
    assert_eq!(
        collect_history_projection(&core, &vault, &bank_entry_id),
        HistoryProjectionDigest {
            summaries: vec![("Subgroup Entry".into(), "".into(), 0, 0)],
            last_detail: Some((
                "Subgroup Entry".into(),
                "".into(),
                "".into(),
                "".into(),
                "".into(),
            )),
            last_custom_fields: Vec::new(),
            last_attachments: Vec::new(),
        }
    );
}

#[test]
fn merge_fixture_exposes_richer_history_projection_oracle() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");

    let root_entry_id = vault.root.entries[0].id.to_string();
    assert_eq!(
        collect_history_projection(&core, &vault, &root_entry_id),
        HistoryProjectionDigest {
            summaries: vec![
                ("Sample Entry".into(), "User Name".into(), 0, 0),
                ("Sample Entry".into(), "User Name".into(), 0, 1),
                ("Sample Entry".into(), "User Name 1".into(), 0, 1),
            ],
            last_detail: Some((
                "Sample Entry".into(),
                "User Name 1".into(),
                "Password".into(),
                "http://www.somesite.com/".into(),
                "Notes".into(),
            )),
            last_custom_fields: vec![("ba".into(), false)],
            last_attachments: Vec::new(),
        }
    );
}

#[test]
fn sync_fixture_exposes_richer_history_projection_oracle() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");

    assert_eq!(
        collect_sync_fixture_history_digest(&core, &vault),
        SyncFixtureHistoryDigest {
            root_history_len: 10,
            root_snapshot_3: HistorySnapshotDigest {
                summary: ("Sample Entry".into(), "User Name".into(), 0, 1),
                detail: (
                    "Sample Entry".into(),
                    "User Name".into(),
                    "Password".into(),
                    "http://www.somesite.com/".into(),
                    "Notes".into(),
                ),
                custom_fields: vec![("ba".into(), false)],
                attachments: Vec::new(),
            },
            root_snapshot_9: HistorySnapshotDigest {
                summary: ("Sample Entry".into(), "User Name".into(), 1, 4),
                detail: (
                    "Sample Entry".into(),
                    "User Name".into(),
                    "Password".into(),
                    "http://www.somesite.com/".into(),
                    "Notes".into(),
                ),
                custom_fields: vec![
                    ("TOTP Seed".into(), true),
                    ("TOTP Settings".into(), false),
                    ("TestAttribute1".into(), false),
                    ("testattribute1".into(), false),
                ],
                attachments: vec![("Sample attachment.txt".into(), 16, false)],
            },
            subgroup_history_len: 2,
            subgroup_snapshot_1: HistorySnapshotDigest {
                summary: ("Subgroup Entry".into(), "Bank User Name".into(), 0, 0),
                detail: (
                    "Subgroup Entry".into(),
                    "Bank User Name".into(),
                    "SecurePassword".into(),
                    "https:/www.bank.com".into(),
                    "Important note".into(),
                ),
                custom_fields: Vec::new(),
                attachments: Vec::new(),
            },
        }
    );
}

#[test]
fn sync_history_variants_preserve_richer_projection_oracle_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load sync history fixture");
        let before = collect_sync_fixture_history_digest(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite sync history fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload sync history fixture");
        let after = collect_sync_fixture_history_digest(&core, &reloaded);

        assert_eq!(after, before);
    }
}

#[test]
fn browser_fixture_exposes_richer_history_projection_oracle() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");

    assert_eq!(
        collect_browser_fixture_history_digest(&core, &vault),
        BrowserFixtureHistoryDigest {
            root_history_len: 3,
            root_snapshots: vec![
                HistorySnapshotDigest {
                    summary: ("Sample Entry".into(), "User Name".into(), 0, 0),
                    detail: (
                        "Sample Entry".into(),
                        "User Name".into(),
                        "Password".into(),
                        "http://www.somesite.com/".into(),
                        "Notes".into(),
                    ),
                    custom_fields: Vec::new(),
                    attachments: Vec::new(),
                },
                HistorySnapshotDigest {
                    summary: ("Sample Entry".into(), "User Name".into(), 0, 2),
                    detail: (
                        "Sample Entry".into(),
                        "User Name".into(),
                        "Password".into(),
                        "http://www.somesite.com/".into(),
                        "Notes".into(),
                    ),
                    custom_fields: vec![
                        ("TOTP Seed".into(), true),
                        ("TOTP Settings".into(), false),
                    ],
                    attachments: Vec::new(),
                },
                HistorySnapshotDigest {
                    summary: ("Sample Entry".into(), "User Name".into(), 0, 2),
                    detail: (
                        "Sample Entry".into(),
                        "User Name".into(),
                        "Password".into(),
                        "http://www.somesite.com/".into(),
                        "Notes".into(),
                    ),
                    custom_fields: vec![
                        ("TOTP Seed".into(), true),
                        ("TOTP Settings".into(), false),
                    ],
                    attachments: Vec::new(),
                },
            ],
            subgroup_history_len: 1,
            subgroup_snapshot_0: HistorySnapshotDigest {
                summary: ("Subgroup Entry".into(), "".into(), 0, 0),
                detail: (
                    "Subgroup Entry".into(),
                    "".into(),
                    "".into(),
                    "".into(),
                    "".into(),
                ),
                custom_fields: Vec::new(),
                attachments: Vec::new(),
            },
        }
    );
}

#[test]
fn browser_history_projection_facade_preserves_richer_oracle_on_roundtrip() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let loaded = core
        .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
        .expect("load browser history fixture");
    let before = collect_browser_fixture_history_digest(&core, &loaded);

    let rewritten = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("rewrite browser history fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload browser history fixture");
    let after = collect_browser_fixture_history_digest(&core, &reloaded);

    assert_eq!(after, before);
}

#[test]
fn external_history_projection_facade_preserves_multi_and_merge_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external fixture");
        let before = collect_history_projection_matrix(&core, &loaded);

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten external fixture");
        let after = collect_history_projection_matrix(&core, &reloaded);

        assert_eq!(after, before);
    }
}

#[test]
fn external_history_semantic_projection_facade_matches_raw_model_oracle() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b"),
    ] {
        let loaded = load_fixture(&core, fixture, password);
        assert_eq!(
            collect_history_semantic_projection_matrix(&core, &loaded),
            collect_raw_history_semantic_matrix(&loaded)
        );
    }
}

#[test]
fn external_history_semantic_projection_facade_preserves_raw_model_oracle_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b"),
    ] {
        let mut key = CompositeKey::default();
        key.add_password(password);

        let loaded = core
            .load_kdbx(fixture, &key)
            .expect("load external history semantic fixture");
        let before = collect_history_semantic_projection_matrix(&core, &loaded);
        assert_eq!(before, collect_raw_history_semantic_matrix(&loaded));

        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite external history semantic fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload external history semantic fixture");
        let after = collect_history_semantic_projection_matrix(&core, &reloaded);

        assert_eq!(after, before);
        assert_eq!(after, collect_raw_history_semantic_matrix(&reloaded));
    }
}

fn collect_history_projection_matrix(
    core: &KeepassCore,
    vault: &Vault,
) -> Vec<(String, HistoryProjectionDigest)> {
    collect_history_projection_matrix_for_group(core, vault, &vault.root, String::new())
}

fn collect_history_semantic_projection_matrix(
    core: &KeepassCore,
    vault: &Vault,
) -> Vec<(String, Vec<HistorySemanticSnapshotDigest>)> {
    collect_history_semantic_projection_matrix_for_group(core, vault, &vault.root, String::new())
}

fn collect_raw_history_semantic_matrix(
    vault: &Vault,
) -> Vec<(String, Vec<HistorySemanticSnapshotDigest>)> {
    collect_raw_history_semantic_matrix_for_group(&vault.root, String::new())
}

fn collect_history_projection_matrix_for_group(
    core: &KeepassCore,
    vault: &Vault,
    group: &vaultkern_core::Group,
    path: String,
) -> Vec<(String, HistoryProjectionDigest)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        let entry_id = entry.id.to_string();
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            collect_history_projection(core, vault, &entry_id),
        ));
    }
    for child in &group.children {
        rows.extend(collect_history_projection_matrix_for_group(
            core,
            vault,
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_history_semantic_projection_matrix_for_group(
    core: &KeepassCore,
    vault: &Vault,
    group: &vaultkern_core::Group,
    path: String,
) -> Vec<(String, Vec<HistorySemanticSnapshotDigest>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        let entry_id = entry.id.to_string();
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            (0..entry.history.len())
                .map(|history_index| {
                    collect_history_semantic_projection_digest(
                        core,
                        vault,
                        &entry_id,
                        history_index,
                    )
                })
                .collect(),
        ));
    }
    for child in &group.children {
        rows.extend(collect_history_semantic_projection_matrix_for_group(
            core,
            vault,
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_raw_history_semantic_matrix_for_group(
    group: &vaultkern_core::Group,
    path: String,
) -> Vec<(String, Vec<HistorySemanticSnapshotDigest>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            entry
                .history
                .iter()
                .map(collect_raw_history_semantic_digest)
                .collect(),
        ));
    }
    for child in &group.children {
        rows.extend(collect_raw_history_semantic_matrix_for_group(
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_history_projection(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> HistoryProjectionDigest {
    let summaries = core
        .list_entry_history(vault, entry_id)
        .expect("list history")
        .into_iter()
        .map(|item| {
            (
                item.title,
                item.username,
                item.attachment_count,
                item.custom_field_count,
            )
        })
        .collect::<Vec<_>>();

    let last_index = summaries.len().checked_sub(1);
    let last_detail = last_index.map(|index| {
        let detail = core
            .project_entry_history_detail(vault, entry_id, index)
            .expect("project history detail");
        (
            detail.title,
            detail.username,
            detail.password,
            detail.url,
            detail.notes,
        )
    });

    let last_custom_fields = last_index
        .map(|index| {
            core.list_entry_history_custom_fields(vault, entry_id, index)
                .expect("list history custom fields")
                .into_iter()
                .map(|field| (field.key, field.protected))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let last_attachments = last_index
        .map(|index| {
            core.list_entry_history_attachments(vault, entry_id, index)
                .expect("list history attachments")
                .into_iter()
                .map(|attachment| {
                    (
                        attachment.name,
                        attachment.size,
                        attachment.protect_in_memory,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    HistoryProjectionDigest {
        summaries,
        last_detail,
        last_custom_fields,
        last_attachments,
    }
}

fn collect_sync_fixture_history_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> SyncFixtureHistoryDigest {
    let root_entry_id = vault.root.entries[0].id.to_string();
    let subgroup_entry_id = find_group_by_title(
        find_group_by_title(&vault.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup")
    .entries[0]
        .id
        .to_string();

    SyncFixtureHistoryDigest {
        root_history_len: core
            .list_entry_history(vault, &root_entry_id)
            .expect("list sync root history")
            .len(),
        root_snapshot_3: collect_history_snapshot_digest(core, vault, &root_entry_id, 3),
        root_snapshot_9: collect_history_snapshot_digest(core, vault, &root_entry_id, 9),
        subgroup_history_len: core
            .list_entry_history(vault, &subgroup_entry_id)
            .expect("list sync subgroup history")
            .len(),
        subgroup_snapshot_1: collect_history_snapshot_digest(core, vault, &subgroup_entry_id, 1),
    }
}

fn collect_browser_fixture_history_digest(
    core: &KeepassCore,
    vault: &Vault,
) -> BrowserFixtureHistoryDigest {
    let root_entry_id = vault.root.entries[0].id.to_string();
    let subgroup_entry_id = find_group_by_title(
        find_group_by_title(&vault.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup")
    .entries[0]
        .id
        .to_string();

    let root_history_len = core
        .list_entry_history(vault, &root_entry_id)
        .expect("list browser root history")
        .len();

    BrowserFixtureHistoryDigest {
        root_history_len,
        root_snapshots: (0..root_history_len)
            .map(|index| collect_history_snapshot_digest(core, vault, &root_entry_id, index))
            .collect(),
        subgroup_history_len: core
            .list_entry_history(vault, &subgroup_entry_id)
            .expect("list browser subgroup history")
            .len(),
        subgroup_snapshot_0: collect_history_snapshot_digest(core, vault, &subgroup_entry_id, 0),
    }
}

fn collect_history_snapshot_digest(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
    history_index: usize,
) -> HistorySnapshotDigest {
    let summary = core
        .list_entry_history(vault, entry_id)
        .expect("list history")
        .into_iter()
        .nth(history_index)
        .map(|item| {
            (
                item.title,
                item.username,
                item.attachment_count,
                item.custom_field_count,
            )
        })
        .expect("history summary");

    let detail = core
        .project_entry_history_detail(vault, entry_id, history_index)
        .expect("project history detail");
    let custom_fields = core
        .list_entry_history_custom_fields(vault, entry_id, history_index)
        .expect("list history custom fields")
        .into_iter()
        .map(|field| (field.key, field.protected))
        .collect::<Vec<_>>();
    let attachments = core
        .list_entry_history_attachments(vault, entry_id, history_index)
        .expect("list history attachments")
        .into_iter()
        .map(|attachment| {
            (
                attachment.name,
                attachment.size,
                attachment.protect_in_memory,
            )
        })
        .collect::<Vec<_>>();

    HistorySnapshotDigest {
        summary,
        detail: (
            detail.title,
            detail.username,
            detail.password,
            detail.url,
            detail.notes,
        ),
        custom_fields,
        attachments,
    }
}

fn collect_history_semantic_projection_digest(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
    history_index: usize,
) -> HistorySemanticSnapshotDigest {
    let detail = core
        .project_entry_history_detail(vault, entry_id, history_index)
        .expect("project history semantic detail");
    let field_protection = core
        .project_entry_history_field_protection(vault, entry_id, history_index)
        .expect("project history field protection");
    let custom_fields = core
        .list_entry_history_custom_fields(vault, entry_id, history_index)
        .expect("list history semantic custom fields")
        .into_iter()
        .map(|field| (field.key, field.value, field.protected))
        .collect();
    let custom_data = core
        .list_entry_history_custom_data(vault, entry_id, history_index)
        .expect("list history semantic custom data")
        .into_iter()
        .map(|item| (item.key, item.value))
        .collect();
    let attachments = core
        .list_entry_history_attachments(vault, entry_id, history_index)
        .expect("list history semantic attachments")
        .into_iter()
        .map(|attachment| {
            let name = attachment.name;
            let content = core
                .project_entry_history_attachment_content(vault, entry_id, history_index, &name)
                .expect("project history semantic attachment content");
            assert_eq!(content.name, name);
            (name, content.data, attachment.protect_in_memory)
        })
        .collect();
    let totp = core
        .project_entry_history_totp(vault, entry_id, history_index)
        .expect("project history semantic totp")
        .map(|value| {
            (
                value.secret_base32,
                format!("{:?}", value.algorithm),
                value.digits,
                value.period_seconds,
                value.issuer,
                value.account_name,
            )
        });
    let passkey = core
        .project_entry_history_passkey(vault, entry_id, history_index)
        .expect("project history semantic passkey")
        .map(|value| {
            (
                value.username,
                value.credential_id,
                value.generated_user_id,
                value.private_key_pem,
                value.relying_party,
                value.user_handle,
                value.backup_eligible,
                value.backup_state,
            )
        });

    HistorySemanticSnapshotDigest {
        detail: (
            detail.title,
            detail.icon_id,
            detail.username,
            detail.password,
            detail.url,
            detail.notes,
            detail.custom_icon_id,
            detail.tags,
        ),
        field_protection,
        custom_fields,
        custom_data,
        attachments,
        totp,
        passkey,
    }
}

fn collect_raw_history_semantic_digest(
    entry: &vaultkern_core::Entry,
) -> HistorySemanticSnapshotDigest {
    HistorySemanticSnapshotDigest {
        detail: (
            entry.title.clone(),
            entry.icon_id,
            entry.username.clone(),
            entry.password.clone(),
            entry.url.clone(),
            entry.notes.clone(),
            entry.custom_icon_id.map(|id| id.to_string()),
            entry.tags.iter().cloned().collect(),
        ),
        field_protection: entry.field_protection.clone(),
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
                    attachment.data.clone(),
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
                value.private_key_pem.clone(),
                value.relying_party.clone(),
                value.user_handle.clone(),
                value.backup_eligible,
                value.backup_state,
            )
        }),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn find_group_by_title<'a>(
    group: &'a vaultkern_core::Group,
    title: &str,
) -> Option<&'a vaultkern_core::Group> {
    if group.title == title {
        return Some(group);
    }
    for child in &group.children {
        if let Some(found) = find_group_by_title(child, title) {
            return Some(found);
        }
    }
    None
}
