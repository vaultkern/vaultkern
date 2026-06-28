#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, GroupBehaviorMetadataUpdate, KeepassCore, SaveProfile, Vault};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupBehaviorMutationDigest {
    behavior: GroupBehaviorDigest,
    raw: RawBehaviorDigest,
    structure: GroupStructureDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupBehaviorDigest {
    default_auto_type_sequence: Option<String>,
    last_top_visible_entry_id: Option<String>,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawBehaviorDigest {
    default_auto_type_sequence: Option<String>,
    last_top_visible_entry_id: Option<String>,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupStructureDigest {
    id: String,
    title: String,
    entry_count: usize,
    child_count: usize,
}

#[derive(Debug, Clone)]
struct GroupBehaviorRefs {
    group_id: String,
    top_entry_id: String,
}

#[test]
fn external_fixtures_support_group_behavior_metadata_mutation_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_group_behavior_mutation(
        &core,
        &mut browser,
        &["Homebanking", "Subgroup"],
        "{USERNAME}{TAB}{PASSWORD}{ENTER}",
    );
    assert_eq!(
        collect_group_behavior_digest(&core, &browser, &browser_refs),
        GroupBehaviorMutationDigest {
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
                last_top_visible_entry_id: Some(browser_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            raw: RawBehaviorDigest {
                default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
                last_top_visible_entry_id: Some(browser_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            structure: GroupStructureDigest {
                id: browser_refs.group_id.clone(),
                title: "Subgroup".into(),
                entry_count: 1,
                child_count: 0,
            },
        }
    );

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_group_behavior_mutation(
        &core,
        &mut sync,
        &["Homebanking", "Subgroup"],
        "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}",
    );
    assert_eq!(
        collect_group_behavior_digest(&core, &sync, &sync_refs),
        GroupBehaviorMutationDigest {
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into()),
                last_top_visible_entry_id: Some(sync_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            raw: RawBehaviorDigest {
                default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into()),
                last_top_visible_entry_id: Some(sync_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            structure: GroupStructureDigest {
                id: sync_refs.group_id.clone(),
                title: "Subgroup".into(),
                entry_count: 1,
                child_count: 0,
            },
        }
    );

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_group_behavior_mutation(
        &core,
        &mut merge,
        &["TestExtraGroup"],
        "{DELAY 100}{USERNAME}{TAB}{PASSWORD}",
    );
    assert_eq!(
        collect_group_behavior_digest(&core, &merge, &merge_refs),
        GroupBehaviorMutationDigest {
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: Some("{DELAY 100}{USERNAME}{TAB}{PASSWORD}".into()),
                last_top_visible_entry_id: Some(merge_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            raw: RawBehaviorDigest {
                default_auto_type_sequence: Some("{DELAY 100}{USERNAME}{TAB}{PASSWORD}".into()),
                last_top_visible_entry_id: Some(merge_refs.top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            structure: GroupStructureDigest {
                id: merge_refs.group_id.clone(),
                title: "TestExtraGroup".into(),
                entry_count: 1,
                child_count: 0,
            },
        }
    );
}

#[test]
fn external_group_behavior_metadata_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_group_behavior_mutation(
        &core,
        &mut browser,
        &["Homebanking", "Subgroup"],
        "{USERNAME}{TAB}{PASSWORD}{ENTER}",
    );
    let browser_before = collect_group_behavior_digest(&core, &browser, &browser_refs);
    let browser_after =
        collect_group_behavior_digest(&core, &save_and_reload(&core, &browser, "a"), &browser_refs);
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_group_behavior_mutation(
        &core,
        &mut sync,
        &["Homebanking", "Subgroup"],
        "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}",
    );
    let sync_before = collect_group_behavior_digest(&core, &sync, &sync_refs);
    let sync_after =
        collect_group_behavior_digest(&core, &save_and_reload(&core, &sync, "a"), &sync_refs);
    assert_eq!(sync_after, sync_before);

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_group_behavior_mutation(
        &core,
        &mut merge,
        &["TestExtraGroup"],
        "{DELAY 100}{USERNAME}{TAB}{PASSWORD}",
    );
    let merge_before = collect_group_behavior_digest(&core, &merge, &merge_refs);
    let merge_after =
        collect_group_behavior_digest(&core, &save_and_reload(&core, &merge, "a"), &merge_refs);
    assert_eq!(merge_after, merge_before);
}

fn apply_group_behavior_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
    path: &[&str],
    sequence: &str,
) -> GroupBehaviorRefs {
    let group = find_group_by_path(&vault.root, path).expect("target group");
    let group_id = group.id.to_string();
    let top_entry_id = group.entries[0].id.to_string();

    let behavior = core
        .update_group_behavior_metadata(
            vault,
            &group_id,
            GroupBehaviorMetadataUpdate {
                default_auto_type_sequence: Some(sequence.into()),
                last_top_visible_entry_id: Some(top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
        )
        .expect("update group behavior metadata");

    assert_eq!(
        behavior.default_auto_type_sequence.as_deref(),
        Some(sequence)
    );
    assert_eq!(
        behavior.last_top_visible_entry_id.as_deref(),
        Some(top_entry_id.as_str())
    );

    GroupBehaviorRefs {
        group_id,
        top_entry_id,
    }
}

fn collect_group_behavior_digest(
    core: &KeepassCore,
    vault: &Vault,
    refs: &GroupBehaviorRefs,
) -> GroupBehaviorMutationDigest {
    let behavior = core
        .project_group_behavior_metadata(vault, &refs.group_id)
        .expect("project group behavior metadata");
    let group = core
        .find_group_view_by_id(vault, &refs.group_id)
        .expect("find group view");
    let raw = find_group_by_id(&vault.root, &refs.group_id).expect("find raw group");

    GroupBehaviorMutationDigest {
        behavior: GroupBehaviorDigest {
            default_auto_type_sequence: behavior.default_auto_type_sequence,
            last_top_visible_entry_id: behavior.last_top_visible_entry_id,
            enable_auto_type: behavior.enable_auto_type,
            enable_searching: behavior.enable_searching,
        },
        raw: RawBehaviorDigest {
            default_auto_type_sequence: raw.default_auto_type_sequence.clone(),
            last_top_visible_entry_id: raw.last_top_visible_entry.map(|id| id.to_string()),
            enable_auto_type: raw.flags.enable_auto_type,
            enable_searching: raw.flags.enable_searching,
        },
        structure: GroupStructureDigest {
            id: group.id,
            title: group.title,
            entry_count: group.entry_count,
            child_count: group.child_count,
        },
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load group behavior mutation fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite group behavior mutation fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload group behavior mutation fixture")
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

fn find_group_by_id<'a>(
    group: &'a vaultkern_core::Group,
    id: &str,
) -> Option<&'a vaultkern_core::Group> {
    if group.id.to_string() == id {
        return Some(group);
    }
    for child in &group.children {
        if let Some(found) = find_group_by_id(child, id) {
            return Some(found);
        }
    }
    None
}
