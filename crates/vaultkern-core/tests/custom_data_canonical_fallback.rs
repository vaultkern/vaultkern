#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, CustomDataItemInput, CustomDataItemView, Entry, EntryCustomDataInput, Group,
    KeepassCore, PublicCustomDataItemInput, SaveProfile, Vault,
};
use vaultkern_model::{CustomDataBlock, CustomDataItem, OpaqueXmlAnchor};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");

#[test]
fn facade_mutation_preserves_split_custom_data_blocks_on_roundtrip() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("custom-data-fallback");

    let vault = split_custom_data_source_vault();
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save split custom data source");
    let mut loaded = core
        .load_kdbx(&bytes, &key)
        .expect("load split custom data source");

    assert_eq!(loaded.meta_custom_data_blocks.len(), 2);
    let group_id = loaded.root.children[0].id.to_string();
    let entry_id = loaded.root.children[0].entries[0].id.to_string();
    assert_eq!(loaded.root.children[0].custom_data_blocks.len(), 2);
    assert_eq!(
        loaded.root.children[0].entries[0].custom_data_blocks.len(),
        2
    );

    core.upsert_vault_custom_data(
        &mut loaded,
        CustomDataItemInput {
            key: "meta-c".into(),
            value: "3".into(),
        },
    )
    .expect("upsert vault custom data");
    core.upsert_group_custom_data(
        &mut loaded,
        &group_id,
        CustomDataItemInput {
            key: "group-c".into(),
            value: "3".into(),
        },
    )
    .expect("upsert group custom data");
    core.upsert_entry_custom_data(
        &mut loaded,
        &entry_id,
        EntryCustomDataInput {
            key: "entry-c".into(),
            value: "3".into(),
        },
    )
    .expect("upsert entry custom data");
    core.upsert_vault_public_custom_data(
        &mut loaded,
        PublicCustomDataItemInput {
            key: "public-c".into(),
            value: b"3".to_vec(),
        },
    )
    .expect("upsert public custom data");

    let rewritten = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save mutated vault");
    let inspected = core
        .inspect_kdbx_header(&rewritten)
        .expect("inspect rewritten header");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated vault");

    assert_eq!(
        reloaded.meta_custom_data.get("meta-c").map(String::as_str),
        Some("3")
    );
    assert_eq!(reloaded.meta_custom_data_blocks.len(), 2);

    let reloaded_group = &reloaded.root.children[0];
    assert_eq!(
        reloaded_group
            .custom_data
            .get("group-c")
            .map(String::as_str),
        Some("3")
    );
    assert_eq!(reloaded_group.custom_data_blocks.len(), 2);

    let reloaded_entry = &reloaded_group.entries[0];
    assert_eq!(
        reloaded_entry
            .custom_data
            .get("entry-c")
            .map(String::as_str),
        Some("3")
    );
    assert_eq!(reloaded_entry.custom_data_blocks.len(), 2);

    assert_eq!(
        inspected.public_custom_data.get("public-c"),
        Some(&b"3".to_vec())
    );
    assert_eq!(
        reloaded.public_custom_data.get("public-c"),
        Some(&b"3".to_vec())
    );
}

#[test]
fn facade_deletion_removes_only_affected_split_custom_data_blocks_on_roundtrip() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("custom-data-fallback-delete");

    let vault = split_custom_data_source_vault();
    let bytes = core
        .save_kdbx(&vault, &key, SaveProfile::recommended())
        .expect("save split custom data source");
    let mut loaded = core
        .load_kdbx(&bytes, &key)
        .expect("load split custom data source");

    let group_id = loaded.root.children[0].id.to_string();
    let entry_id = loaded.root.children[0].entries[0].id.to_string();

    core.delete_vault_custom_data(&mut loaded, "meta-a")
        .expect("delete vault custom data");
    core.delete_group_custom_data(&mut loaded, &group_id, "group-a")
        .expect("delete group custom data");
    core.delete_entry_custom_data(&mut loaded, &entry_id, "entry-a")
        .expect("delete entry custom data");
    core.delete_vault_public_custom_data(&mut loaded, "public-a")
        .expect("delete public custom data");

    let rewritten = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save mutated vault");
    let inspected = core
        .inspect_kdbx_header(&rewritten)
        .expect("inspect rewritten header");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated vault");

    assert_eq!(
        reloaded
            .meta_custom_data
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["meta-b".to_string()]
    );
    assert_eq!(reloaded.meta_custom_data_blocks.len(), 1);

    let reloaded_group = &reloaded.root.children[0];
    assert_eq!(
        reloaded_group
            .custom_data
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["group-b".to_string()]
    );
    assert_eq!(reloaded_group.custom_data_blocks.len(), 1);

    let reloaded_entry = &reloaded_group.entries[0];
    assert_eq!(
        reloaded_entry
            .custom_data
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["entry-b".to_string()]
    );
    assert_eq!(reloaded_entry.custom_data_blocks.len(), 1);

    assert_eq!(
        inspected
            .public_custom_data
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["public-b".to_string()]
    );
    assert_eq!(
        reloaded
            .public_custom_data
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["public-b".to_string()]
    );
}

#[test]
fn derived_external_fixture_mutation_preserves_split_custom_data_blocks() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let mut loaded = core
        .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
        .expect("load browser fixture");
    assert_eq!(loaded.meta_custom_data_blocks.len(), 1);
    assert_eq!(loaded.root.entries[0].custom_data_blocks.len(), 1);

    split_existing_blocks(
        &mut loaded.meta_custom_data_blocks,
        &loaded.meta_custom_data,
    );
    let entry_custom_data = loaded.root.entries[0].custom_data.clone();
    split_existing_blocks(
        &mut loaded.root.entries[0].custom_data_blocks,
        &entry_custom_data,
    );

    let split_bytes = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save derived split browser fixture");
    let mut split_loaded = core
        .load_kdbx(&split_bytes, &key)
        .expect("reload derived split browser fixture");
    assert_eq!(split_loaded.meta_custom_data_blocks.len(), 2);
    assert_eq!(split_loaded.root.entries[0].custom_data_blocks.len(), 2);

    let root_entry_id = split_loaded.root.entries[0].id.to_string();
    core.upsert_vault_custom_data(
        &mut split_loaded,
        CustomDataItemInput {
            key: "_LAST_MODIFIED".into(),
            value: "mutated-meta".into(),
        },
    )
    .expect("update vault custom data");
    core.upsert_entry_custom_data(
        &mut split_loaded,
        &root_entry_id,
        EntryCustomDataInput {
            key: "_LAST_MODIFIED".into(),
            value: "mutated-entry".into(),
        },
    )
    .expect("mutate root entry custom data");

    let rewritten = core
        .save_kdbx(&split_loaded, &key, SaveProfile::recommended())
        .expect("save mutated derived browser fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated derived browser fixture");

    assert_eq!(reloaded.meta_custom_data_blocks.len(), 2);
    assert_eq!(reloaded.root.entries[0].custom_data_blocks.len(), 2);
    assert_eq!(
        reloaded
            .meta_custom_data
            .get("_LAST_MODIFIED")
            .map(String::as_str),
        Some("mutated-meta")
    );
    assert_eq!(
        reloaded.root.entries[0]
            .custom_data
            .get("_LAST_MODIFIED")
            .map(String::as_str),
        Some("mutated-entry")
    );
    assert_eq!(reloaded.root.title, "NewDatabase");
    assert_eq!(reloaded.root.entries[0].title, "Sample Entry");
}

#[test]
fn derived_external_fixture_deletion_removes_only_affected_split_custom_data_blocks() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let mut loaded = core
        .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
        .expect("load browser fixture");
    split_existing_blocks(
        &mut loaded.meta_custom_data_blocks,
        &loaded.meta_custom_data,
    );
    let entry_custom_data = loaded.root.entries[0].custom_data.clone();
    split_existing_blocks(
        &mut loaded.root.entries[0].custom_data_blocks,
        &entry_custom_data,
    );

    let split_bytes = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save derived split browser fixture");
    let mut split_loaded = core
        .load_kdbx(&split_bytes, &key)
        .expect("reload derived split browser fixture");

    let root_entry_id = split_loaded.root.entries[0].id.to_string();
    core.delete_vault_custom_data(&mut split_loaded, "KPXC_BROWSER_test")
        .expect("delete meta custom data");
    core.delete_entry_custom_data(&mut split_loaded, &root_entry_id, "_LAST_MODIFIED")
        .expect("delete root entry custom data");

    let rewritten = core
        .save_kdbx(&split_loaded, &key, SaveProfile::recommended())
        .expect("save mutated derived browser fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated derived browser fixture");

    assert_eq!(reloaded.meta_custom_data_blocks.len(), 1);
    assert_eq!(reloaded.root.entries[0].custom_data_blocks.len(), 1);
    assert!(!reloaded.meta_custom_data.contains_key("KPXC_BROWSER_test"));
    assert!(
        !reloaded.root.entries[0]
            .custom_data
            .contains_key("_LAST_MODIFIED")
    );
}

#[test]
fn derived_newdatabase_meta_mutation_preserves_split_custom_data_blocks() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let mut loaded = core
        .load_kdbx(FIXTURE_NEW_DATABASE, &key)
        .expect("load newdatabase fixture");
    assert_eq!(loaded.meta_custom_data_blocks.len(), 1);
    split_existing_blocks(
        &mut loaded.meta_custom_data_blocks,
        &loaded.meta_custom_data,
    );

    let split_bytes = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save derived split newdatabase fixture");
    let mut split_loaded = core
        .load_kdbx(&split_bytes, &key)
        .expect("reload derived split newdatabase fixture");
    assert_eq!(split_loaded.meta_custom_data_blocks.len(), 2);

    core.upsert_vault_custom_data(
        &mut split_loaded,
        CustomDataItemInput {
            key: "_LAST_MODIFIED".into(),
            value: "mutated-newdb-meta".into(),
        },
    )
    .expect("update new database custom data");

    let rewritten = core
        .save_kdbx(&split_loaded, &key, SaveProfile::recommended())
        .expect("save mutated derived newdatabase fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated derived newdatabase fixture");

    assert_eq!(reloaded.meta_custom_data_blocks.len(), 2);
    assert_eq!(
        reloaded
            .meta_custom_data
            .get("_LAST_MODIFIED")
            .map(String::as_str),
        Some("mutated-newdb-meta")
    );
    assert_eq!(reloaded.root.title, "NewDatabase");
}

#[test]
fn derived_browser_group_mutation_preserves_split_custom_data_blocks() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let mut loaded = core
        .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
        .expect("load browser fixture");
    let general_group_id = inject_split_group_custom_data(
        &mut loaded,
        &["General"],
        &[("group-a", "1"), ("group-b", "2")],
    );

    let split_bytes = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save derived split browser group fixture");
    let mut split_loaded = core
        .load_kdbx(&split_bytes, &key)
        .expect("reload derived split browser group fixture");

    assert_eq!(
        core.list_group_custom_data(&split_loaded, &general_group_id)
            .expect("list browser group custom data"),
        vec![
            CustomDataItemView {
                key: "group-a".into(),
                value: "1".into(),
            },
            CustomDataItemView {
                key: "group-b".into(),
                value: "2".into(),
            },
        ]
    );
    assert_eq!(
        find_group_by_path(&split_loaded.root, &["General"])
            .expect("general group")
            .custom_data_blocks
            .len(),
        2
    );

    core.upsert_group_custom_data(
        &mut split_loaded,
        &general_group_id,
        CustomDataItemInput {
            key: "group-c".into(),
            value: "3".into(),
        },
    )
    .expect("mutate browser group custom data");

    let rewritten = core
        .save_kdbx(&split_loaded, &key, SaveProfile::recommended())
        .expect("save mutated derived browser group fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated derived browser group fixture");

    assert_eq!(
        core.list_group_custom_data(&reloaded, &general_group_id)
            .expect("list reloaded browser group custom data"),
        vec![
            CustomDataItemView {
                key: "group-a".into(),
                value: "1".into(),
            },
            CustomDataItemView {
                key: "group-b".into(),
                value: "2".into(),
            },
            CustomDataItemView {
                key: "group-c".into(),
                value: "3".into(),
            },
        ]
    );
    assert_eq!(
        find_group_by_path(&reloaded.root, &["General"])
            .expect("reloaded general group")
            .custom_data_blocks
            .len(),
        2
    );
    assert_eq!(reloaded.root.title, "NewDatabase");
}

#[test]
fn derived_sync_group_deletion_removes_only_affected_split_custom_data_blocks() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("a");

    let mut loaded = core
        .load_kdbx(FIXTURE_SYNC_DATABASE, &key)
        .expect("load sync fixture");
    let subgroup_id = inject_split_group_custom_data(
        &mut loaded,
        &["Homebanking", "Subgroup"],
        &[("group-a", "1"), ("group-b", "2")],
    );

    let split_bytes = core
        .save_kdbx(&loaded, &key, SaveProfile::recommended())
        .expect("save derived split sync group fixture");
    let mut split_loaded = core
        .load_kdbx(&split_bytes, &key)
        .expect("reload derived split sync group fixture");

    assert_eq!(
        core.list_group_custom_data(&split_loaded, &subgroup_id)
            .expect("list sync subgroup custom data"),
        vec![
            CustomDataItemView {
                key: "group-a".into(),
                value: "1".into(),
            },
            CustomDataItemView {
                key: "group-b".into(),
                value: "2".into(),
            },
        ]
    );
    assert_eq!(
        find_group_by_path(&split_loaded.root, &["Homebanking", "Subgroup"])
            .expect("sync subgroup")
            .custom_data_blocks
            .len(),
        2
    );

    core.delete_group_custom_data(&mut split_loaded, &subgroup_id, "group-a")
        .expect("delete sync subgroup custom data");

    let rewritten = core
        .save_kdbx(&split_loaded, &key, SaveProfile::recommended())
        .expect("save mutated derived sync group fixture");
    let reloaded = core
        .load_kdbx(&rewritten, &key)
        .expect("reload mutated derived sync group fixture");

    assert_eq!(
        core.list_group_custom_data(&reloaded, &subgroup_id)
            .expect("list reloaded sync subgroup custom data"),
        vec![CustomDataItemView {
            key: "group-b".into(),
            value: "2".into(),
        }]
    );
    assert_eq!(
        find_group_by_path(&reloaded.root, &["Homebanking", "Subgroup"])
            .expect("reloaded sync subgroup")
            .custom_data_blocks
            .len(),
        1
    );
    assert_eq!(
        find_group_by_path(&reloaded.root, &["Homebanking", "Subgroup"])
            .expect("reloaded sync subgroup")
            .entries[0]
            .title,
        "Subgroup Entry"
    );
}

fn split_custom_data_source_vault() -> Vault {
    let mut vault = Vault::empty("CustomDataFallback");
    vault.meta_custom_data.insert("meta-a".into(), "1".into());
    vault.meta_custom_data.insert("meta-b".into(), "2".into());
    vault.meta_custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item("meta-a", "1")],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item("meta-b", "2")],
            after: after_first_custom_data_block(),
        },
    ];
    vault
        .public_custom_data
        .insert("public-a".into(), b"1".to_vec());
    vault
        .public_custom_data
        .insert("public-b".into(), b"2".to_vec());

    let mut group = Group::new("Child");
    group.custom_data.insert("group-a".into(), "1".into());
    group.custom_data.insert("group-b".into(), "2".into());
    group.custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item("group-a", "1")],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item("group-b", "2")],
            after: after_first_custom_data_block(),
        },
    ];

    let mut entry = Entry::new("Entry");
    entry.custom_data.insert("entry-a".into(), "1".into());
    entry.custom_data.insert("entry-b".into(), "2".into());
    entry.custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item("entry-a", "1")],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item("entry-b", "2")],
            after: after_first_custom_data_block(),
        },
    ];

    group.entries.push(entry);
    vault.root.children.push(group);
    vault
}

fn split_blocks(map: &std::collections::BTreeMap<String, String>) -> Vec<CustomDataBlock> {
    split_blocks_after(map, None)
}

fn split_existing_blocks(
    blocks: &mut Vec<CustomDataBlock>,
    map: &std::collections::BTreeMap<String, String>,
) {
    let first_after = blocks.first().and_then(|block| block.after.clone());
    *blocks = split_blocks_after(map, first_after);
}

fn split_blocks_after(
    map: &std::collections::BTreeMap<String, String>,
    first_after: Option<OpaqueXmlAnchor>,
) -> Vec<CustomDataBlock> {
    let items = map
        .iter()
        .map(|(key, value)| CustomDataItem {
            key: key.clone(),
            value: value.clone(),
            last_modified: None,
        })
        .collect::<Vec<_>>();
    assert!(
        items.len() >= 2,
        "need at least two custom data items to split"
    );
    vec![
        CustomDataBlock {
            items: vec![items[0].clone()],
            after: first_after,
        },
        CustomDataBlock {
            items: items[1..].to_vec(),
            after: after_first_custom_data_block(),
        },
    ]
}

fn after_first_custom_data_block() -> Option<OpaqueXmlAnchor> {
    Some(OpaqueXmlAnchor {
        element_name: "CustomData".into(),
        occurrence: 1,
    })
}

fn custom_data_item(key: &str, value: &str) -> CustomDataItem {
    CustomDataItem {
        key: key.into(),
        value: value.into(),
        last_modified: None,
    }
}

fn inject_split_group_custom_data(
    vault: &mut Vault,
    path: &[&str],
    items: &[(&str, &str)],
) -> String {
    let group = find_group_by_path_mut(&mut vault.root, path).expect("group by path");
    for (key, value) in items {
        group
            .custom_data
            .insert((*key).to_string(), (*value).to_string());
    }
    group.custom_data_blocks = split_blocks(&group.custom_data);
    group.id.to_string()
}

fn find_group_by_path<'a>(group: &'a Group, path: &[&str]) -> Option<&'a Group> {
    let (head, tail) = path.split_first()?;
    let child = group.children.iter().find(|child| child.title == *head)?;
    if tail.is_empty() {
        Some(child)
    } else {
        find_group_by_path(child, tail)
    }
}

fn find_group_by_path_mut<'a>(group: &'a mut Group, path: &[&str]) -> Option<&'a mut Group> {
    let (head, tail) = path.split_first()?;
    let child = group
        .children
        .iter_mut()
        .find(|child| child.title == *head)?;
    if tail.is_empty() {
        Some(child)
    } else {
        find_group_by_path_mut(child, tail)
    }
}
