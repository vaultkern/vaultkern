#![cfg(feature = "external-fixtures")]

use vaultkern_core::{
    CompositeKey, GroupFlags, GroupMetadataUpdate, KeepassCore, SaveProfile, Vault,
};

const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
    include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
const FIXTURE_MERGE_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupMetadataMutationDigest {
    updated_view: GroupViewDigest,
    projected_view: GroupViewDigest,
    detail: GroupDetailDigest,
    behavior: GroupBehaviorDigest,
    raw_flags: RawFlagsDigest,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupBehaviorDigest {
    default_auto_type_sequence: Option<String>,
    last_top_visible_entry_id: Option<String>,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawFlagsDigest {
    is_expanded: Option<bool>,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
}

#[derive(Debug, Clone)]
struct GroupMutationRefs {
    group_id: String,
}

#[test]
fn external_fixtures_support_group_metadata_mutation_oracle() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_group_metadata_mutation(
        &core,
        &mut browser,
        &["General"],
        GroupMetadataUpdate {
            title: Some("Browser General Updated".into()),
            notes: Some("browser group notes".into()),
            icon_id: Some(33),
            flags: Some(GroupFlags {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            }),
        },
    );
    assert_eq!(
        collect_group_metadata_digest(&core, &browser, &browser_refs.group_id),
        GroupMetadataMutationDigest {
            updated_view: GroupViewDigest {
                id: browser_refs.group_id.clone(),
                title: "Browser General Updated".into(),
                icon_id: Some(33),
                entry_count: 0,
                child_count: 1,
            },
            projected_view: GroupViewDigest {
                id: browser_refs.group_id.clone(),
                title: "Browser General Updated".into(),
                icon_id: Some(33),
                entry_count: 0,
                child_count: 1,
            },
            detail: GroupDetailDigest {
                id: browser_refs.group_id.clone(),
                title: "Browser General Updated".into(),
                icon_id: Some(33),
                notes: "browser group notes".into(),
            },
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: None,
                last_top_visible_entry_id: None,
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            },
            raw_flags: RawFlagsDigest {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            },
        }
    );

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_group_metadata_mutation(
        &core,
        &mut sync,
        &["Homebanking", "Subgroup"],
        GroupMetadataUpdate {
            title: Some("Sync Bank Group Updated".into()),
            notes: Some("sync group notes".into()),
            icon_id: Some(14),
            flags: Some(GroupFlags {
                is_expanded: Some(true),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            }),
        },
    );
    assert_eq!(
        collect_group_metadata_digest(&core, &sync, &sync_refs.group_id),
        GroupMetadataMutationDigest {
            updated_view: GroupViewDigest {
                id: sync_refs.group_id.clone(),
                title: "Sync Bank Group Updated".into(),
                icon_id: Some(14),
                entry_count: 1,
                child_count: 0,
            },
            projected_view: GroupViewDigest {
                id: sync_refs.group_id.clone(),
                title: "Sync Bank Group Updated".into(),
                icon_id: Some(14),
                entry_count: 1,
                child_count: 0,
            },
            detail: GroupDetailDigest {
                id: sync_refs.group_id.clone(),
                title: "Sync Bank Group Updated".into(),
                icon_id: Some(14),
                notes: "sync group notes".into(),
            },
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: None,
                last_top_visible_entry_id: None,
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
            raw_flags: RawFlagsDigest {
                is_expanded: Some(true),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
        }
    );

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_group_metadata_mutation(
        &core,
        &mut merge,
        &["TestExtraGroup"],
        GroupMetadataUpdate {
            title: Some("Merge Extra Group Updated".into()),
            notes: Some("merge group notes".into()),
            icon_id: Some(12),
            flags: Some(GroupFlags {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            }),
        },
    );
    assert_eq!(
        collect_group_metadata_digest(&core, &merge, &merge_refs.group_id),
        GroupMetadataMutationDigest {
            updated_view: GroupViewDigest {
                id: merge_refs.group_id.clone(),
                title: "Merge Extra Group Updated".into(),
                icon_id: Some(12),
                entry_count: 1,
                child_count: 0,
            },
            projected_view: GroupViewDigest {
                id: merge_refs.group_id.clone(),
                title: "Merge Extra Group Updated".into(),
                icon_id: Some(12),
                entry_count: 1,
                child_count: 0,
            },
            detail: GroupDetailDigest {
                id: merge_refs.group_id.clone(),
                title: "Merge Extra Group Updated".into(),
                icon_id: Some(12),
                notes: "merge group notes".into(),
            },
            behavior: GroupBehaviorDigest {
                default_auto_type_sequence: None,
                last_top_visible_entry_id: None,
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            },
            raw_flags: RawFlagsDigest {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            },
        }
    );
}

#[test]
fn external_group_metadata_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut browser = load_fixture(&core, FIXTURE_NEW_DATABASE_BROWSER, "a");
    let browser_refs = apply_group_metadata_mutation(
        &core,
        &mut browser,
        &["General"],
        GroupMetadataUpdate {
            title: Some("Browser General Updated".into()),
            notes: Some("browser group notes".into()),
            icon_id: Some(33),
            flags: Some(GroupFlags {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            }),
        },
    );
    let browser_before = collect_group_metadata_digest(&core, &browser, &browser_refs.group_id);
    let browser_after = collect_group_metadata_digest(
        &core,
        &save_and_reload(&core, &browser, "a"),
        &browser_refs.group_id,
    );
    assert_eq!(browser_after, browser_before);

    let mut sync = load_fixture(&core, FIXTURE_SYNC_DATABASE, "a");
    let sync_refs = apply_group_metadata_mutation(
        &core,
        &mut sync,
        &["Homebanking", "Subgroup"],
        GroupMetadataUpdate {
            title: Some("Sync Bank Group Updated".into()),
            notes: Some("sync group notes".into()),
            icon_id: Some(14),
            flags: Some(GroupFlags {
                is_expanded: Some(true),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            }),
        },
    );
    let sync_before = collect_group_metadata_digest(&core, &sync, &sync_refs.group_id);
    let sync_after = collect_group_metadata_digest(
        &core,
        &save_and_reload(&core, &sync, "a"),
        &sync_refs.group_id,
    );
    assert_eq!(sync_after, sync_before);

    let mut merge = load_fixture(&core, FIXTURE_MERGE_DATABASE, "a");
    let merge_refs = apply_group_metadata_mutation(
        &core,
        &mut merge,
        &["TestExtraGroup"],
        GroupMetadataUpdate {
            title: Some("Merge Extra Group Updated".into()),
            notes: Some("merge group notes".into()),
            icon_id: Some(12),
            flags: Some(GroupFlags {
                is_expanded: Some(false),
                enable_auto_type: Some(true),
                enable_searching: Some(false),
            }),
        },
    );
    let merge_before = collect_group_metadata_digest(&core, &merge, &merge_refs.group_id);
    let merge_after = collect_group_metadata_digest(
        &core,
        &save_and_reload(&core, &merge, "a"),
        &merge_refs.group_id,
    );
    assert_eq!(merge_after, merge_before);
}

fn apply_group_metadata_mutation(
    core: &KeepassCore,
    vault: &mut Vault,
    path: &[&str],
    update: GroupMetadataUpdate,
) -> GroupMutationRefs {
    let group = find_group_by_path(&vault.root, path).expect("target group");
    let group_id = group.id.to_string();

    let updated = core
        .update_group_metadata(vault, &group_id, update)
        .expect("update group metadata");

    assert_eq!(updated.id, group_id);

    GroupMutationRefs { group_id }
}

fn collect_group_metadata_digest(
    core: &KeepassCore,
    vault: &Vault,
    group_id: &str,
) -> GroupMetadataMutationDigest {
    let updated_view = core
        .find_group_view_by_id(vault, group_id)
        .expect("find updated group view");
    let detail = core
        .project_group_detail(vault, group_id)
        .expect("project group detail");
    let behavior = core
        .project_group_behavior_metadata(vault, group_id)
        .expect("project group behavior metadata");
    let raw = find_group_by_id(&vault.root, group_id).expect("find raw group");

    GroupMetadataMutationDigest {
        updated_view: GroupViewDigest {
            id: group_id.into(),
            title: updated_view.title.clone(),
            icon_id: updated_view.icon_id,
            entry_count: updated_view.entry_count,
            child_count: updated_view.child_count,
        },
        projected_view: GroupViewDigest {
            id: updated_view.id,
            title: updated_view.title,
            icon_id: updated_view.icon_id,
            entry_count: updated_view.entry_count,
            child_count: updated_view.child_count,
        },
        detail: GroupDetailDigest {
            id: detail.id,
            title: detail.title,
            icon_id: detail.icon_id,
            notes: detail.notes,
        },
        behavior: GroupBehaviorDigest {
            default_auto_type_sequence: behavior.default_auto_type_sequence,
            last_top_visible_entry_id: behavior.last_top_visible_entry_id,
            enable_auto_type: behavior.enable_auto_type,
            enable_searching: behavior.enable_searching,
        },
        raw_flags: RawFlagsDigest {
            is_expanded: raw.flags.is_expanded,
            enable_auto_type: raw.flags.enable_auto_type,
            enable_searching: raw.flags.enable_searching,
        },
    }
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load group metadata mutation fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite group metadata mutation fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload group metadata mutation fixture")
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
