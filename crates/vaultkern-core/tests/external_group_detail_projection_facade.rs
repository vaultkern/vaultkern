#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, Group, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupDetailProjectionDigest {
    view: GroupViewDigest,
    detail: GroupDetailDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupViewDigest {
    id: String,
    title: String,
    icon_id: Option<u32>,
    entry_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupDetailDigest {
    id: String,
    title: String,
    icon_id: Option<u32>,
    notes: String,
    custom_icon_id: Option<String>,
    tags: Vec<String>,
}

#[test]
fn external_fixtures_expose_group_detail_projection_oracle() {
    let core = KeepassCore::new();

    for (fixture, password, path) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a", vec!["General"]),
        (FIXTURE_SYNC_DATABASE, "a", vec!["Homebanking", "Subgroup"]),
        (FIXTURE_MERGE_DATABASE, "a", vec!["TestExtraGroup"]),
    ] {
        let vault = load_fixture(&core, fixture, password);
        let group = find_group_by_path(&vault.root, &path).expect("target group");
        let expected = collect_expected_group_detail_digest(group);
        let actual = collect_group_detail_projection_digest(&core, &vault, &group.id.to_string());

        assert_eq!(actual, expected);
    }
}

#[test]
fn external_group_detail_projection_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    for (fixture, password, path) in [
        (FIXTURE_NEW_DATABASE_BROWSER, "a", vec!["General"]),
        (FIXTURE_SYNC_DATABASE, "a", vec!["Homebanking", "Subgroup"]),
        (FIXTURE_MERGE_DATABASE, "a", vec!["TestExtraGroup"]),
    ] {
        let loaded = load_fixture(&core, fixture, password);
        let group = find_group_by_path(&loaded.root, &path).expect("loaded target group");
        let before = collect_group_detail_projection_digest(&core, &loaded, &group.id.to_string());

        let reloaded = save_and_reload(&core, &loaded, password);
        let group = find_group_by_path(&reloaded.root, &path).expect("reloaded target group");
        let after = collect_group_detail_projection_digest(&core, &reloaded, &group.id.to_string());

        assert_eq!(after, before);
    }
}

fn collect_expected_group_detail_digest(group: &Group) -> GroupDetailProjectionDigest {
    GroupDetailProjectionDigest {
        view: GroupViewDigest {
            id: group.id.to_string(),
            title: group.title.clone(),
            icon_id: group.icon_id,
            entry_count: group.entries.len(),
            child_count: group.children.len(),
        },
        detail: GroupDetailDigest {
            id: group.id.to_string(),
            title: group.title.clone(),
            icon_id: group.icon_id,
            notes: group.notes.clone(),
            custom_icon_id: group.custom_icon_id.map(|id| id.to_string()),
            tags: group.tags.iter().cloned().collect(),
        },
    }
}

fn collect_group_detail_projection_digest(
    core: &KeepassCore,
    vault: &Vault,
    group_id: &str,
) -> GroupDetailProjectionDigest {
    let view = core
        .find_group_view_by_id(vault, group_id)
        .expect("find group view");
    let detail = core
        .project_group_detail(vault, group_id)
        .expect("project group detail");

    GroupDetailProjectionDigest {
        view: GroupViewDigest {
            id: view.id,
            title: view.title,
            icon_id: view.icon_id,
            entry_count: view.entry_count,
            child_count: view.child_count,
        },
        detail: GroupDetailDigest {
            id: detail.id,
            title: detail.title,
            icon_id: detail.icon_id,
            notes: detail.notes,
            custom_icon_id: detail.custom_icon_id,
            tags: detail.tags,
        },
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load group detail projection fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite group detail projection fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload group detail projection fixture")
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
