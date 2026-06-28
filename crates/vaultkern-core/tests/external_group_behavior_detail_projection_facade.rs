#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, Group, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupBehaviorProjectionDigest {
    root_view: RootViewDigest,
    behavior: GroupBehaviorDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootViewDigest {
    id: String,
    title: String,
    entry_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupBehaviorDigest {
    default_auto_type_sequence: Option<String>,
    last_top_visible_entry_id: Option<String>,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
}

#[test]
fn external_fixtures_expose_group_behavior_detail_projection_oracle() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
    ] {
        let vault = load_fixture(&core, fixture, password);
        let expected = collect_expected_group_behavior_digest(&vault.root);
        let actual =
            collect_group_behavior_projection_digest(&core, &vault, &vault.root.id.to_string());

        assert_eq!(actual, expected);
    }
}

#[test]
fn external_group_behavior_detail_projection_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a"),
        (FIXTURE_SYNC_DATABASE, "a"),
        (FIXTURE_MERGE_DATABASE, "a"),
    ] {
        let loaded = load_fixture(&core, fixture, password);
        let before =
            collect_group_behavior_projection_digest(&core, &loaded, &loaded.root.id.to_string());

        let reloaded = save_and_reload(&core, &loaded, password);
        let after = collect_group_behavior_projection_digest(
            &core,
            &reloaded,
            &reloaded.root.id.to_string(),
        );

        assert_eq!(after, before);
    }
}

fn collect_expected_group_behavior_digest(group: &Group) -> GroupBehaviorProjectionDigest {
    GroupBehaviorProjectionDigest {
        root_view: RootViewDigest {
            id: group.id.to_string(),
            title: group.title.clone(),
            entry_count: group.entries.len(),
            child_count: group.children.len(),
        },
        behavior: GroupBehaviorDigest {
            default_auto_type_sequence: group.default_auto_type_sequence.clone(),
            last_top_visible_entry_id: group.last_top_visible_entry.map(|id| id.to_string()),
            enable_auto_type: group.flags.enable_auto_type,
            enable_searching: group.flags.enable_searching,
        },
    }
}

fn collect_group_behavior_projection_digest(
    core: &KeepassCore,
    vault: &Vault,
    group_id: &str,
) -> GroupBehaviorProjectionDigest {
    let view = core
        .find_group_view_by_id(vault, group_id)
        .expect("find root group view");
    let behavior = core
        .project_group_behavior_metadata(vault, group_id)
        .expect("project group behavior metadata");

    GroupBehaviorProjectionDigest {
        root_view: RootViewDigest {
            id: view.id,
            title: view.title,
            entry_count: view.entry_count,
            child_count: view.child_count,
        },
        behavior: GroupBehaviorDigest {
            default_auto_type_sequence: behavior.default_auto_type_sequence,
            last_top_visible_entry_id: behavior.last_top_visible_entry_id,
            enable_auto_type: behavior.enable_auto_type,
            enable_searching: behavior.enable_searching,
        },
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load group behavior detail projection fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite group behavior detail projection fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload group behavior detail projection fixture")
}
