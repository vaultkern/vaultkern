#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, EntryCustomDataInput, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryCustomDataMutationDigest {
    items: Vec<(String, String)>,
}

#[test]
fn external_fixtures_support_entry_custom_data_mutation_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_entry_id = browser.root.entries[0].id.to_string();
    apply_browser_entry_mutation(&core, &mut browser, &browser_entry_id);
    assert_eq!(
        collect_entry_custom_data_digest(&core, &browser, &browser_entry_id),
        EntryCustomDataMutationDigest {
            items: vec![
                ("ENTRY_STAGE".into(), "browser-entry".into()),
                (
                    "KeePassXC-Browser Settings".into(),
                    "{\"Allow\":[\"github.com\"],\"Deny\":[],\"Realm\":\"\"}".into(),
                ),
                (
                    "_LAST_MODIFIED".into(),
                    "Fri Apr 11 14:00:00 2026 GMT".into()
                ),
            ],
        }
    );

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let subgroup =
        find_group_by_path(&sync.root, &["Homebanking", "Subgroup"]).expect("sync subgroup");
    let sync_entry_id = subgroup.entries[0].id.to_string();
    apply_sync_entry_mutation(&core, &mut sync, &sync_entry_id);
    assert_eq!(
        collect_entry_custom_data_digest(&core, &sync, &sync_entry_id),
        EntryCustomDataMutationDigest {
            items: vec![("ENTRY_STAGE".into(), "sync-entry".into())],
        }
    );
}

#[test]
fn external_entry_custom_data_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_entry_id = browser.root.entries[0].id.to_string();
    apply_browser_entry_mutation(&core, &mut browser, &browser_entry_id);
    let browser_before = collect_entry_custom_data_digest(&core, &browser, &browser_entry_id);
    let browser_after = collect_entry_custom_data_digest(
        &core,
        &save_and_reload(&core, &browser, "a"),
        &browser_entry_id,
    );
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let subgroup =
        find_group_by_path(&sync.root, &["Homebanking", "Subgroup"]).expect("sync subgroup");
    let sync_entry_id = subgroup.entries[0].id.to_string();
    apply_sync_entry_mutation(&core, &mut sync, &sync_entry_id);
    let sync_before = collect_entry_custom_data_digest(&core, &sync, &sync_entry_id);
    let sync_after = collect_entry_custom_data_digest(
        &core,
        &save_and_reload(&core, &sync, "a"),
        &sync_entry_id,
    );
    assert_eq!(sync_after, sync_before);
}

fn apply_browser_entry_mutation(core: &KeepassCore, vault: &mut Vault, entry_id: &str) {
    core.upsert_entry_custom_data(
        vault,
        entry_id,
        EntryCustomDataInput {
            key: "_LAST_MODIFIED".into(),
            value: "Fri Apr 11 14:00:00 2026 GMT".into(),
        },
    )
    .expect("update browser root entry custom data");
    core.upsert_entry_custom_data(
        vault,
        entry_id,
        EntryCustomDataInput {
            key: "ENTRY_STAGE".into(),
            value: "browser-entry".into(),
        },
    )
    .expect("insert browser root entry custom data");
}

fn apply_sync_entry_mutation(core: &KeepassCore, vault: &mut Vault, entry_id: &str) {
    core.upsert_entry_custom_data(
        vault,
        entry_id,
        EntryCustomDataInput {
            key: "ENTRY_STAGE".into(),
            value: "sync-entry".into(),
        },
    )
    .expect("insert sync entry custom data");
    core.upsert_entry_custom_data(
        vault,
        entry_id,
        EntryCustomDataInput {
            key: "ENTRY_TEMP".into(),
            value: "delete-me".into(),
        },
    )
    .expect("insert sync transient custom data");
    core.delete_entry_custom_data(vault, entry_id, "ENTRY_TEMP")
        .expect("delete sync transient custom data");
}

fn collect_entry_custom_data_digest(
    core: &KeepassCore,
    vault: &Vault,
    entry_id: &str,
) -> EntryCustomDataMutationDigest {
    EntryCustomDataMutationDigest {
        items: core
            .list_entry_custom_data(vault, entry_id)
            .expect("list entry custom data")
            .into_iter()
            .map(|item| (item.key, item.value))
            .collect(),
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
