#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, CustomDataItemView, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupCustomDataMutationDigest {
    items: Vec<CustomDataItemView>,
}

#[test]
fn external_fixtures_support_group_custom_data_mutation_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let general_group_id = find_group_by_path(&browser.root, &["General"])
        .expect("browser general group")
        .id
        .to_string();
    apply_browser_group_mutation(&core, &mut browser, &general_group_id);
    assert_eq!(
        collect_group_custom_data_digest(&core, &browser, &general_group_id),
        GroupCustomDataMutationDigest {
            items: vec![CustomDataItemView {
                key: "GROUP_STAGE".into(),
                value: "browser-group".into(),
            }],
        }
    );

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let subgroup_id = find_group_by_path(&sync.root, &["Homebanking", "Subgroup"])
        .expect("sync subgroup")
        .id
        .to_string();
    apply_sync_group_mutation(&core, &mut sync, &subgroup_id);
    assert_eq!(
        collect_group_custom_data_digest(&core, &sync, &subgroup_id),
        GroupCustomDataMutationDigest {
            items: vec![CustomDataItemView {
                key: "GROUP_STAGE".into(),
                value: "sync-group".into(),
            }],
        }
    );
}

#[test]
fn external_group_custom_data_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let general_group_id = find_group_by_path(&browser.root, &["General"])
        .expect("browser general group")
        .id
        .to_string();
    apply_browser_group_mutation(&core, &mut browser, &general_group_id);
    let browser_before = collect_group_custom_data_digest(&core, &browser, &general_group_id);
    let browser_after = collect_group_custom_data_digest(
        &core,
        &save_and_reload(&core, &browser, "a"),
        &general_group_id,
    );
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let subgroup_id = find_group_by_path(&sync.root, &["Homebanking", "Subgroup"])
        .expect("sync subgroup")
        .id
        .to_string();
    apply_sync_group_mutation(&core, &mut sync, &subgroup_id);
    let sync_before = collect_group_custom_data_digest(&core, &sync, &subgroup_id);
    let sync_after =
        collect_group_custom_data_digest(&core, &save_and_reload(&core, &sync, "a"), &subgroup_id);
    assert_eq!(sync_after, sync_before);
}

fn apply_browser_group_mutation(core: &KeepassCore, vault: &mut Vault, group_id: &str) {
    core.upsert_group_custom_data(
        vault,
        group_id,
        vaultkern_core::CustomDataItemInput {
            key: "GROUP_STAGE".into(),
            value: "browser-group".into(),
        },
    )
    .expect("insert browser group custom data");
    core.upsert_group_custom_data(
        vault,
        group_id,
        vaultkern_core::CustomDataItemInput {
            key: "GROUP_TEMP".into(),
            value: "delete-me".into(),
        },
    )
    .expect("insert browser transient group custom data");
    core.delete_group_custom_data(vault, group_id, "GROUP_TEMP")
        .expect("delete browser transient group custom data");
}

fn apply_sync_group_mutation(core: &KeepassCore, vault: &mut Vault, group_id: &str) {
    core.upsert_group_custom_data(
        vault,
        group_id,
        vaultkern_core::CustomDataItemInput {
            key: "GROUP_STAGE".into(),
            value: "sync-group".into(),
        },
    )
    .expect("insert sync group custom data");
}

fn collect_group_custom_data_digest(
    core: &KeepassCore,
    vault: &Vault,
    group_id: &str,
) -> GroupCustomDataMutationDigest {
    GroupCustomDataMutationDigest {
        items: core
            .list_group_custom_data(vault, group_id)
            .expect("list group custom data"),
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let bytes = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("save fixture");
    core.load_kdbx(&bytes, &key).expect("reload fixture")
}

fn find_group_by_path<'a>(
    root: &'a vaultkern_core::Group,
    path: &[&str],
) -> Option<&'a vaultkern_core::Group> {
    let mut current = root;
    for segment in path {
        current = current
            .children
            .iter()
            .find(|group| group.title == *segment)?;
    }
    Some(current)
}
