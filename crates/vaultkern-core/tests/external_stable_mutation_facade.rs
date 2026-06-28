#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, EntryCreate, EntryUpdate, KeepassCore, MutationError, SaveProfile, Vault,
};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserMutationDigest {
    updated_entry: EntryMutationDigest,
    general_group: GroupMutationDigest,
    created_group: GroupMutationDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncMutationDigest {
    created_entry: EntryMutationDigest,
    subgroup: GroupMutationDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MergeMutationDigest {
    extra_group: GroupMutationDigest,
    deleted_entry_present: bool,
    deleted_group_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryMutationDigest {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    history_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupMutationDigest {
    id: String,
    title: String,
    entry_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone)]
struct BrowserMutationRefs {
    updated_entry_id: String,
    general_group_id: String,
    created_group_id: String,
}

#[derive(Debug, Clone)]
struct SyncMutationRefs {
    created_entry_id: String,
    subgroup_id: String,
}

#[derive(Debug, Clone)]
struct MergeMutationRefs {
    extra_group_id: String,
    deleted_entry_id: String,
    deleted_group_id: String,
}

#[test]
fn external_fixtures_support_stable_mutation_crud_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_browser_mutations(&core, &mut browser);
    let root_id = browser.root.id.to_string();
    assert_eq!(
        core.delete_group(&mut browser, &root_id),
        Err(MutationError::CannotDeleteRootGroup)
    );

    assert_eq!(
        collect_browser_digest(&core, &browser, &browser_refs),
        BrowserMutationDigest {
            updated_entry: EntryMutationDigest {
                id: browser_refs.updated_entry_id.clone(),
                title: "Browser External Updated".into(),
                username: "browser-user".into(),
                password: "browser-pass".into(),
                url: "https://external.browser.example".into(),
                notes: "browser external notes".into(),
                history_count: 1,
            },
            general_group: GroupMutationDigest {
                id: browser_refs.general_group_id.clone(),
                title: "General".into(),
                entry_count: 0,
                child_count: 2,
            },
            created_group: GroupMutationDigest {
                id: browser_refs.created_group_id.clone(),
                title: "Browser Mutation Group".into(),
                entry_count: 0,
                child_count: 0,
            },
        }
    );

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_sync_mutations(&core, &mut sync);
    assert_eq!(
        collect_sync_digest(&core, &sync, &sync_refs),
        SyncMutationDigest {
            created_entry: EntryMutationDigest {
                id: sync_refs.created_entry_id.clone(),
                title: "Sync Created Entry".into(),
                username: "sync-user".into(),
                password: "sync-pass".into(),
                url: "https://sync.example.com".into(),
                notes: "sync external notes".into(),
                history_count: 0,
            },
            subgroup: GroupMutationDigest {
                id: sync_refs.subgroup_id.clone(),
                title: "Subgroup".into(),
                entry_count: 2,
                child_count: 0,
            },
        }
    );

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_merge_mutations(&core, &mut merge);
    assert_eq!(
        collect_merge_digest(&core, &merge, &merge_refs),
        MergeMutationDigest {
            extra_group: GroupMutationDigest {
                id: merge_refs.extra_group_id.clone(),
                title: "TestExtraGroup".into(),
                entry_count: 0,
                child_count: 0,
            },
            deleted_entry_present: false,
            deleted_group_present: false,
        }
    );
}

#[test]
fn external_stable_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_browser_mutations(&core, &mut browser);
    let browser_before = collect_browser_digest(&core, &browser, &browser_refs);
    let browser_after =
        collect_browser_digest(&core, &save_and_reload(&core, &browser, "a"), &browser_refs);
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_sync_mutations(&core, &mut sync);
    let sync_before = collect_sync_digest(&core, &sync, &sync_refs);
    let sync_after = collect_sync_digest(&core, &save_and_reload(&core, &sync, "a"), &sync_refs);
    assert_eq!(sync_after, sync_before);

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_merge_mutations(&core, &mut merge);
    let merge_before = collect_merge_digest(&core, &merge, &merge_refs);
    let merge_after =
        collect_merge_digest(&core, &save_and_reload(&core, &merge, "a"), &merge_refs);
    assert_eq!(merge_after, merge_before);
}

fn apply_browser_mutations(core: &KeepassCore, vault: &mut Vault) -> BrowserMutationRefs {
    let subgroup =
        find_group_by_path(&vault.root, &["Homebanking", "Subgroup"]).expect("browser subgroup");
    let subgroup_entry =
        find_entry_in_group(subgroup, "Subgroup Entry").expect("browser subgroup entry");
    let subgroup_entry_id = subgroup_entry.id.to_string();
    let general = find_group_by_path(&vault.root, &["General"]).expect("browser general");
    let general_group_id = general.id.to_string();

    core.update_entry_fields(
        vault,
        &subgroup_entry_id,
        EntryUpdate {
            title: Some("Browser External Updated".into()),
            username: Some("browser-user".into()),
            password: Some("browser-pass".into()),
            url: Some("https://external.browser.example".into()),
            notes: Some("browser external notes".into()),
        },
    )
    .expect("update browser entry");

    let created_group = core
        .add_group(vault, &general_group_id, "Browser Mutation Group")
        .expect("add browser mutation group");

    BrowserMutationRefs {
        updated_entry_id: subgroup_entry_id,
        general_group_id,
        created_group_id: created_group.id,
    }
}

fn apply_sync_mutations(core: &KeepassCore, vault: &mut Vault) -> SyncMutationRefs {
    let subgroup =
        find_group_by_path(&vault.root, &["Homebanking", "Subgroup"]).expect("sync subgroup");
    let subgroup_id = subgroup.id.to_string();
    let created_entry = core
        .add_entry(
            vault,
            &subgroup_id,
            EntryCreate {
                title: "Sync Created Entry".into(),
                username: "sync-user".into(),
                password: "sync-pass".into(),
                url: "https://sync.example.com".into(),
                notes: "sync external notes".into(),
            },
        )
        .expect("add sync created entry");

    SyncMutationRefs {
        created_entry_id: created_entry.id,
        subgroup_id,
    }
}

fn apply_merge_mutations(core: &KeepassCore, vault: &mut Vault) -> MergeMutationRefs {
    let extra_group =
        find_group_by_path(&vault.root, &["TestExtraGroup"]).expect("merge extra group");
    let extra_group_id = extra_group.id.to_string();
    let extra_entry = find_entry_in_group(extra_group, "b").expect("merge extra entry");
    let extra_entry_id = extra_entry.id.to_string();
    let homebanking = find_group_by_path(&vault.root, &["Homebanking"]).expect("merge homebanking");
    let homebanking_id = homebanking.id.to_string();

    core.delete_entry(vault, &extra_entry_id)
        .expect("delete merge extra entry");
    core.delete_group(vault, &homebanking_id)
        .expect("delete merge homebanking");

    MergeMutationRefs {
        extra_group_id,
        deleted_entry_id: extra_entry_id,
        deleted_group_id: homebanking_id,
    }
}

fn collect_browser_digest(
    core: &KeepassCore,
    vault: &Vault,
    refs: &BrowserMutationRefs,
) -> BrowserMutationDigest {
    BrowserMutationDigest {
        updated_entry: collect_entry_digest(core, vault, &refs.updated_entry_id),
        general_group: collect_group_digest(core, vault, &refs.general_group_id),
        created_group: collect_group_digest(core, vault, &refs.created_group_id),
    }
}

fn collect_sync_digest(
    core: &KeepassCore,
    vault: &Vault,
    refs: &SyncMutationRefs,
) -> SyncMutationDigest {
    SyncMutationDigest {
        created_entry: collect_entry_digest(core, vault, &refs.created_entry_id),
        subgroup: collect_group_digest(core, vault, &refs.subgroup_id),
    }
}

fn collect_merge_digest(
    core: &KeepassCore,
    vault: &Vault,
    refs: &MergeMutationRefs,
) -> MergeMutationDigest {
    MergeMutationDigest {
        extra_group: collect_group_digest(core, vault, &refs.extra_group_id),
        deleted_entry_present: core
            .find_entry_view_by_id(vault, &refs.deleted_entry_id)
            .is_some(),
        deleted_group_present: core
            .find_group_view_by_id(vault, &refs.deleted_group_id)
            .is_some(),
    }
}

fn collect_entry_digest(core: &KeepassCore, vault: &Vault, entry_id: &str) -> EntryMutationDigest {
    let detail = core
        .project_entry_detail(vault, entry_id)
        .expect("project entry detail");
    let view = core
        .find_entry_view_by_id(vault, entry_id)
        .expect("find entry view");

    EntryMutationDigest {
        id: detail.id,
        title: detail.title,
        username: detail.username,
        password: detail.password,
        url: detail.url,
        notes: detail.notes,
        history_count: view.history_count,
    }
}

fn collect_group_digest(core: &KeepassCore, vault: &Vault, group_id: &str) -> GroupMutationDigest {
    let group = core
        .find_group_view_by_id(vault, group_id)
        .expect("find group view");

    GroupMutationDigest {
        id: group.id,
        title: group.title,
        entry_count: group.entry_count,
        child_count: group.child_count,
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key).expect("load mutation fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite mutation fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload mutation fixture")
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

fn find_entry_in_group<'a>(
    group: &'a vaultkern_core::Group,
    title: &str,
) -> Option<&'a vaultkern_core::Entry> {
    group.entries.iter().find(|entry| entry.title == title)
}
