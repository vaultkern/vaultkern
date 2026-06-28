#![cfg(feature = "external-fixtures")]

use std::collections::BTreeMap;

use vaultkern_core::{
    CompositeKey, Entry, EntryCustomDataItemDetailInput, EntryCustomDataItemView, Group,
    GroupCustomDataItemDetailInput, GroupCustomDataItemView, KeepassCore, SaveProfile, Vault,
};
use vaultkern_model::CustomDataBlock;

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");

#[test]
fn external_fixtures_expose_group_custom_data_detail_projection_matrix() {
    let core = KeepassCore::new();

    for (fixture, password) in fixture_matrix() {
        let vault = load_fixture(&core, fixture, password);
        assert_eq!(
            collect_group_custom_data_detail_matrix(&core, &vault),
            collect_raw_group_custom_data_detail_matrix(&vault)
        );
    }
}

#[test]
fn external_fixtures_expose_entry_custom_data_detail_projection_matrix() {
    let core = KeepassCore::new();

    for (fixture, password) in fixture_matrix() {
        let vault = load_fixture(&core, fixture, password);
        assert_eq!(
            collect_entry_custom_data_detail_matrix(&core, &vault),
            collect_raw_entry_custom_data_detail_matrix(&vault)
        );
    }
}

#[test]
fn external_group_custom_data_detail_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in fixture_matrix() {
        let loaded = load_fixture(&core, fixture, password);
        let before = collect_group_custom_data_detail_matrix(&core, &loaded);
        let after = collect_group_custom_data_detail_matrix(
            &core,
            &save_and_reload(&core, &loaded, password),
        );
        assert_eq!(after, before);
    }
}

#[test]
fn external_entry_custom_data_detail_projection_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in fixture_matrix() {
        let loaded = load_fixture(&core, fixture, password);
        let before = collect_entry_custom_data_detail_matrix(&core, &loaded);
        let after = collect_entry_custom_data_detail_matrix(
            &core,
            &save_and_reload(&core, &loaded, password),
        );
        assert_eq!(after, before);
    }
}

#[test]
fn external_group_custom_data_detail_mutation_oracle_preserves_timestamps_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_group_id = find_group_by_path(&browser.root, &["General"])
        .expect("browser general group")
        .id
        .to_string();
    core.upsert_group_custom_data_detail(
        &mut browser,
        &browser_group_id,
        GroupCustomDataItemDetailInput {
            key: "GROUP_STAGE_DETAIL".into(),
            value: "browser-group".into(),
            last_modified: Some(1_700_000_101),
        },
    )
    .expect("upsert browser group custom data detail");
    let browser_before = core
        .list_group_custom_data_detail(&browser, &browser_group_id)
        .expect("list browser group custom data detail");
    let browser_after = core
        .list_group_custom_data_detail(&save_and_reload(&core, &browser, "a"), &browser_group_id)
        .expect("list reloaded browser group custom data detail");
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_group_id = find_group_by_path(&sync.root, &["Homebanking", "Subgroup"])
        .expect("sync subgroup")
        .id
        .to_string();
    core.upsert_group_custom_data_detail(
        &mut sync,
        &sync_group_id,
        GroupCustomDataItemDetailInput {
            key: "GROUP_STAGE_DETAIL".into(),
            value: "sync-group".into(),
            last_modified: Some(1_700_000_102),
        },
    )
    .expect("upsert sync group custom data detail");
    let sync_before = core
        .list_group_custom_data_detail(&sync, &sync_group_id)
        .expect("list sync group custom data detail");
    let sync_after = core
        .list_group_custom_data_detail(&save_and_reload(&core, &sync, "a"), &sync_group_id)
        .expect("list reloaded sync group custom data detail");
    assert_eq!(sync_after, sync_before);
}

#[test]
fn external_entry_custom_data_detail_mutation_oracle_preserves_timestamps_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_entry_id = browser.root.entries[0].id.to_string();
    core.upsert_entry_custom_data_detail(
        &mut browser,
        &browser_entry_id,
        EntryCustomDataItemDetailInput {
            key: "ENTRY_STAGE_DETAIL".into(),
            value: "browser-entry".into(),
            last_modified: Some(1_700_000_201),
        },
    )
    .expect("upsert browser entry custom data detail");
    let browser_before = core
        .list_entry_custom_data_detail(&browser, &browser_entry_id)
        .expect("list browser entry custom data detail");
    let browser_after = core
        .list_entry_custom_data_detail(&save_and_reload(&core, &browser, "a"), &browser_entry_id)
        .expect("list reloaded browser entry custom data detail");
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_entry_id = find_group_by_path(&sync.root, &["Homebanking", "Subgroup"])
        .expect("sync subgroup")
        .entries[0]
        .id
        .to_string();
    core.upsert_entry_custom_data_detail(
        &mut sync,
        &sync_entry_id,
        EntryCustomDataItemDetailInput {
            key: "ENTRY_STAGE_DETAIL".into(),
            value: "sync-entry".into(),
            last_modified: Some(1_700_000_202),
        },
    )
    .expect("upsert sync entry custom data detail");
    let sync_before = core
        .list_entry_custom_data_detail(&sync, &sync_entry_id)
        .expect("list sync entry custom data detail");
    let sync_after = core
        .list_entry_custom_data_detail(&save_and_reload(&core, &sync, "a"), &sync_entry_id)
        .expect("list reloaded sync entry custom data detail");
    assert_eq!(sync_after, sync_before);
}

fn fixture_matrix() -> [(&'static [u8], &'static str); 5] {
    [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_NEW_DATABASE_MULTI, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
        (FIXTURE_FORMAT300, "a"),
    ]
}

fn collect_group_custom_data_detail_matrix(
    core: &KeepassCore,
    vault: &Vault,
) -> Vec<(String, Vec<GroupCustomDataItemView>)> {
    collect_group_custom_data_detail_matrix_for_group(core, vault, &vault.root, String::new())
}

fn collect_group_custom_data_detail_matrix_for_group(
    core: &KeepassCore,
    vault: &Vault,
    group: &Group,
    path: String,
) -> Vec<(String, Vec<GroupCustomDataItemView>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = vec![(
        group_path.clone(),
        core.list_group_custom_data_detail(vault, &group.id.to_string())
            .expect("list group custom data detail"),
    )];
    for child in &group.children {
        rows.extend(collect_group_custom_data_detail_matrix_for_group(
            core,
            vault,
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_raw_group_custom_data_detail_matrix(
    vault: &Vault,
) -> Vec<(String, Vec<GroupCustomDataItemView>)> {
    collect_raw_group_custom_data_detail_matrix_for_group(&vault.root, String::new())
}

fn collect_raw_group_custom_data_detail_matrix_for_group(
    group: &Group,
    path: String,
) -> Vec<(String, Vec<GroupCustomDataItemView>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = vec![(
        group_path.clone(),
        raw_group_custom_data_detail_items(group),
    )];
    for child in &group.children {
        rows.extend(collect_raw_group_custom_data_detail_matrix_for_group(
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_entry_custom_data_detail_matrix(
    core: &KeepassCore,
    vault: &Vault,
) -> Vec<(String, Vec<EntryCustomDataItemView>)> {
    collect_entry_custom_data_detail_matrix_for_group(core, vault, &vault.root, String::new())
}

fn collect_entry_custom_data_detail_matrix_for_group(
    core: &KeepassCore,
    vault: &Vault,
    group: &Group,
    path: String,
) -> Vec<(String, Vec<EntryCustomDataItemView>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            core.list_entry_custom_data_detail(vault, &entry.id.to_string())
                .expect("list entry custom data detail"),
        ));
    }
    for child in &group.children {
        rows.extend(collect_entry_custom_data_detail_matrix_for_group(
            core,
            vault,
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn collect_raw_entry_custom_data_detail_matrix(
    vault: &Vault,
) -> Vec<(String, Vec<EntryCustomDataItemView>)> {
    collect_raw_entry_custom_data_detail_matrix_for_group(&vault.root, String::new())
}

fn collect_raw_entry_custom_data_detail_matrix_for_group(
    group: &Group,
    path: String,
) -> Vec<(String, Vec<EntryCustomDataItemView>)> {
    let group_path = if path.is_empty() {
        group.title.clone()
    } else {
        format!("{path}/{}", group.title)
    };
    let mut rows = Vec::new();
    for (index, entry) in group.entries.iter().enumerate() {
        rows.push((
            format!("{group_path}/entry[{index}]:{}", entry.title),
            raw_entry_custom_data_detail_items(entry),
        ));
    }
    for child in &group.children {
        rows.extend(collect_raw_entry_custom_data_detail_matrix_for_group(
            child,
            group_path.clone(),
        ));
    }
    rows
}

fn raw_group_custom_data_detail_items(group: &Group) -> Vec<GroupCustomDataItemView> {
    let mut projected = BTreeMap::new();
    for block in &group.custom_data_blocks {
        insert_group_items_from_block(&mut projected, block);
    }
    for (key, value) in &group.custom_data {
        projected
            .entry(key.clone())
            .or_insert_with(|| GroupCustomDataItemView {
                key: key.clone(),
                value: value.clone(),
                last_modified: None,
            });
    }
    projected.into_values().collect()
}

fn raw_entry_custom_data_detail_items(entry: &Entry) -> Vec<EntryCustomDataItemView> {
    let mut projected = BTreeMap::new();
    for block in &entry.custom_data_blocks {
        insert_entry_items_from_block(&mut projected, block);
    }
    for (key, value) in &entry.custom_data {
        projected
            .entry(key.clone())
            .or_insert_with(|| EntryCustomDataItemView {
                key: key.clone(),
                value: value.clone(),
                last_modified: None,
            });
    }
    projected.into_values().collect()
}

fn insert_group_items_from_block(
    projected: &mut BTreeMap<String, GroupCustomDataItemView>,
    block: &CustomDataBlock,
) {
    for item in &block.items {
        projected.insert(
            item.key.clone(),
            GroupCustomDataItemView {
                key: item.key.clone(),
                value: item.value.clone(),
                last_modified: item.last_modified,
            },
        );
    }
}

fn insert_entry_items_from_block(
    projected: &mut BTreeMap<String, EntryCustomDataItemView>,
    block: &CustomDataBlock,
) {
    for item in &block.items {
        projected.insert(
            item.key.clone(),
            EntryCustomDataItemView {
                key: item.key.clone(),
                value: item.value.clone(),
                last_modified: item.last_modified,
            },
        );
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load external custom-data detail fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite external custom-data detail fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload external custom-data detail fixture")
}

fn find_group_by_path<'a>(root: &'a Group, path: &[&str]) -> Option<&'a Group> {
    let mut current = root;
    for segment in path {
        current = current
            .children
            .iter()
            .find(|group| group.title == *segment)?;
    }
    Some(current)
}
