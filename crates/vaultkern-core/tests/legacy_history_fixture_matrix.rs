#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, Entry, EntryFieldProtection, Group, KdbxVersion, KeepassCore, SaveProfile, Vault,
};

const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD: &[u8] =
    include_bytes!("../../../fixtures/kdbx/SyncDatabaseDifferentPassword.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistorySummary {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    attrs: Vec<(String, bool)>,
    attachments: Vec<(String, usize, bool)>,
    protection: EntryFieldProtection,
    auto_enabled: Option<bool>,
    auto_assoc_count: usize,
    expires: bool,
    expiry_time: Option<i64>,
}

#[test]
fn loads_legacy_history_fixtures_with_model_matrix_oracle() {
    let core = KeepassCore::new();

    let merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    assert_eq!(summarize_history(&merge.root.entries[0]).len(), 3);
    assert_history_snapshot(
        &merge.root.entries[0].history[0],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[],
        &[],
        0,
        Some(1283804880),
    );
    assert_history_snapshot(
        &merge.root.entries[0].history[2],
        "Sample Entry",
        "User Name 1",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[("ba", false)],
        &[],
        0,
        Some(1283804880),
    );

    let multi = load_fixture(&core, FIXTURE_NEW_DATABASE_MULTI, "a");
    assert_eq!(multi.root.entries[0].history.len(), 6);
    assert_history_snapshot(
        &multi.root.entries[0].history[3],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[
            ("TOTP Seed", true),
            ("TOTP Settings", false),
            ("TestAttribute1", false),
            ("testattribute1", false),
        ],
        &[],
        1,
        Some(1283804880),
    );
    assert_history_snapshot(
        &multi.root.entries[1].history[6],
        "Sample Entry 2",
        "User Name 2",
        "Password2",
        "http://www.somesite.com/",
        "Notes",
        &[
            ("TOTP Seed", true),
            ("TOTP Settings", false),
            ("TestAttribute1", false),
            ("testattribute1", false),
        ],
        &[],
        1,
        Some(1283804880),
    );
    assert_history_snapshot(
        &multi.root.entries[2].history[6],
        "Sample Entry 3",
        "User Name 3",
        "Password3",
        "http://www.somesite.com/",
        "Notes",
        &[
            ("TOTP Seed", true),
            ("TOTP Settings", false),
            ("TestAttribute1", false),
            ("testattribute1", false),
        ],
        &[],
        1,
        Some(1283804880),
    );
    let multi_subgroup = find_group_by_title(
        find_group_by_title(&multi.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup");
    assert_history_snapshot(
        &multi_subgroup.entries[0].history[0],
        "Subgroup Entry",
        "",
        "",
        "",
        "",
        &[],
        &[],
        0,
        Some(1560668107),
    );

    let sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    assert_eq!(sync.root.entries[0].history.len(), 10);
    assert_history_snapshot(
        &sync.root.entries[0].history[3],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[("ba", false)],
        &[],
        1,
        Some(1283804880),
    );
    assert_history_snapshot(
        &sync.root.entries[0].history[9],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[
            ("TOTP Seed", true),
            ("TOTP Settings", false),
            ("TestAttribute1", false),
            ("testattribute1", false),
        ],
        &[("Sample attachment.txt", 16, false)],
        1,
        Some(1283804880),
    );
    let sync_subgroup = find_group_by_title(
        find_group_by_title(&sync.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup");
    assert_history_snapshot(
        &sync_subgroup.entries[0].history[1],
        "Subgroup Entry",
        "Bank User Name",
        "SecurePassword",
        "https:/www.bank.com",
        "Important note",
        &[],
        &[],
        0,
        Some(1560668107),
    );
}

#[test]
fn legacy_history_fixtures_preserve_model_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (bytes, password) in [
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
    ] {
        let loaded = load_fixture(&core, bytes, password);
        let before = collect_history_matrix(&loaded);

        let mut key = CompositeKey::default();
        key.add_password(password);
        let rewritten = core
            .save_kdbx(&loaded, &key, SaveProfile::recommended())
            .expect("rewrite legacy history fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten legacy history fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten legacy history fixture");

        assert_eq!(inspection.header.version, KdbxVersion::V4_1);
        assert_eq!(collect_history_matrix(&reloaded), before);
    }
}

#[test]
fn loads_sync_history_variant_with_model_matrix_oracle() {
    let core = KeepassCore::new();
    let vault = load_fixture(&core, FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b");

    assert!(vault.name.is_empty());
    assert_eq!(vault.root.entries.len(), 1);
    assert_eq!(vault.root.children.len(), 7);

    assert_history_snapshot(
        &vault.root.entries[0].history[3],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[("ba", false)],
        &[],
        1,
        Some(1283804880),
    );
    assert_history_snapshot(
        &vault.root.entries[0].history[9],
        "Sample Entry",
        "User Name",
        "Password",
        "http://www.somesite.com/",
        "Notes",
        &[
            ("TOTP Seed", true),
            ("TOTP Settings", false),
            ("TestAttribute1", false),
            ("testattribute1", false),
        ],
        &[("Sample attachment.txt", 16, false)],
        1,
        Some(1283804880),
    );

    let subgroup = find_group_by_title(
        find_group_by_title(&vault.root, "Homebanking").expect("homebanking"),
        "Subgroup",
    )
    .expect("subgroup");
    assert_history_snapshot(
        &subgroup.entries[0].history[1],
        "Subgroup Entry",
        "Bank User Name",
        "SecurePassword",
        "https:/www.bank.com",
        "Important note",
        &[],
        &[],
        0,
        Some(1560668107),
    );
}

#[test]
fn sync_history_variant_matches_primary_fixture_and_roundtrips() {
    let core = KeepassCore::new();

    let primary = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let variant = load_fixture(&core, FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b");
    let primary_matrix = collect_history_matrix(&primary);
    let variant_matrix = collect_history_matrix(&variant);

    assert_eq!(variant_matrix, primary_matrix);

    let mut key = CompositeKey::default();
    key.add_password("b");
    let rewritten = core
        .save_kdbx(&variant, &key, SaveProfile::recommended())
        .expect("rewrite sync variant");
    let inspection = core
        .inspect_database(&rewritten)
        .expect("inspect rewritten sync variant");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload rewritten sync variant");

    assert_eq!(inspection.header.version, KdbxVersion::V4_1);
    assert_eq!(collect_history_matrix(&reloaded), variant_matrix);
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn collect_history_matrix(vault: &Vault) -> Vec<(String, Vec<HistorySummary>)> {
    collect_history_matrix_for_group(&vault.root, String::new())
}

fn collect_history_matrix_for_group(
    group: &Group,
    path: String,
) -> Vec<(String, Vec<HistorySummary>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            summarize_history(entry),
        ));
    }
    for child in &group.children {
        rows.extend(collect_history_matrix_for_group(child, group_path.clone()));
    }
    rows
}

fn summarize_history(entry: &Entry) -> Vec<HistorySummary> {
    entry.history.iter().map(summarize_entry).collect()
}

fn summarize_entry(entry: &Entry) -> HistorySummary {
    HistorySummary {
        title: entry.title.clone(),
        username: entry.username.clone(),
        password: entry.password.clone(),
        url: entry.url.clone(),
        notes: entry.notes.clone(),
        attrs: entry
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.protected))
            .collect(),
        attachments: entry
            .attachments
            .iter()
            .map(|(name, attachment)| {
                (
                    name.clone(),
                    attachment.data.len(),
                    attachment.protect_in_memory,
                )
            })
            .collect(),
        protection: entry.field_protection,
        auto_enabled: entry.auto_type.as_ref().and_then(|auto| auto.enabled),
        auto_assoc_count: entry
            .auto_type
            .as_ref()
            .map(|auto| auto.associations.len())
            .unwrap_or(0),
        expires: entry.expires,
        expiry_time: entry.expiry_time,
    }
}

#[allow(clippy::too_many_arguments)]
fn assert_history_snapshot(
    entry: &Entry,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
    attrs: &[(&str, bool)],
    attachments: &[(&str, usize, bool)],
    auto_assoc_count: usize,
    expiry_time: Option<i64>,
) {
    assert_eq!(entry.title, title);
    assert_eq!(entry.username, username);
    assert_eq!(entry.password, password);
    assert_eq!(entry.url, url);
    assert_eq!(entry.notes, notes);
    assert_eq!(
        entry
            .attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.protected))
            .collect::<Vec<_>>(),
        attrs.to_vec()
    );
    assert_eq!(
        entry
            .attachments
            .iter()
            .map(|(name, attachment)| (
                name.as_str(),
                attachment.data.len(),
                attachment.protect_in_memory
            ))
            .collect::<Vec<_>>(),
        attachments.to_vec()
    );
    assert_eq!(
        entry.field_protection,
        EntryFieldProtection {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        }
    );
    assert_eq!(
        entry.auto_type.as_ref().and_then(|auto| auto.enabled),
        Some(true)
    );
    assert_eq!(
        entry
            .auto_type
            .as_ref()
            .map(|auto| auto.associations.len())
            .unwrap_or(0),
        auto_assoc_count
    );
    assert!(!entry.expires);
    assert_eq!(entry.expiry_time, expiry_time);
}

fn find_group_by_title<'a>(group: &'a Group, title: &str) -> Option<&'a Group> {
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
