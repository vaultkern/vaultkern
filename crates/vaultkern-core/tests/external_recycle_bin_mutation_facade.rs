#![cfg(feature = "external-fixtures")]

use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault};

const FIXTURE_RECYCLE_BIN_NOT_YET_CREATED: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinNotYetCreated.kdbx");
const FIXTURE_RECYCLE_BIN_EMPTY: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinEmpty.kdbx");
const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
    include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftDeleteDigest {
    deleted_entry_id: String,
    deleted_entry_title: String,
    deleted_entry_previous_parent_id: Option<String>,
    recycle_bin_group_id: String,
    recycle_bin_title: String,
    recycle_bin_entry_count: usize,
    recycle_bin_child_count: usize,
    root_child_titles: Vec<String>,
    deleted_objects_count: usize,
    deleted_object_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestoreDigest {
    restored_entry_id: String,
    restored_entry_title: String,
    restored_entry_previous_parent_id: Option<String>,
    target_group_id: String,
    target_group_title: String,
    target_group_entry_titles: Vec<String>,
    recycle_bin_group_id: String,
    recycle_bin_title: String,
    recycle_bin_entry_count: usize,
    recycle_bin_child_count: usize,
    deleted_objects_count: usize,
    deleted_object_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct SoftDeleteRefs {
    deleted_entry_id: String,
    deleted_entry_title: String,
    expected_previous_parent_id: String,
    recycle_bin_group_id: String,
}

#[derive(Debug, Clone)]
struct RestoreRefs {
    restored_entry_id: String,
    restored_entry_title: String,
    target_group_id: String,
    target_group_title: String,
    expected_target_group_entry_titles: Vec<String>,
    recycle_bin_group_id: String,
    expected_deleted_object_ids: Vec<String>,
}

#[test]
fn external_fixtures_support_recycle_bin_mutation_oracle() {
    let core = KeepassCore::new();

    let mut not_yet_created = load_fixture(&core, FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, "123");
    let not_yet_created_expected_deleted_object_ids =
        collect_deleted_object_ids(&core, &not_yet_created);
    let not_yet_created_refs = soft_delete_first_active_entry(&core, &mut not_yet_created);
    assert_eq!(
        collect_soft_delete_digest(&core, &not_yet_created, &not_yet_created_refs),
        SoftDeleteDigest {
            deleted_entry_id: not_yet_created_refs.deleted_entry_id.clone(),
            deleted_entry_title: not_yet_created_refs.deleted_entry_title.clone(),
            deleted_entry_previous_parent_id: Some(
                not_yet_created_refs.expected_previous_parent_id.clone()
            ),
            recycle_bin_group_id: not_yet_created_refs.recycle_bin_group_id.clone(),
            recycle_bin_title: "Recycle Bin".into(),
            recycle_bin_entry_count: 1,
            recycle_bin_child_count: 0,
            root_child_titles: vec![
                "Mail".into(),
                "Network".into(),
                "Computer logins".into(),
                "Recycle Bin".into(),
            ],
            deleted_objects_count: not_yet_created_expected_deleted_object_ids.len(),
            deleted_object_ids: not_yet_created_expected_deleted_object_ids,
        }
    );

    let mut empty = load_fixture(&core, FIXTURE_RECYCLE_BIN_EMPTY, "123");
    let empty_expected_deleted_object_ids = collect_deleted_object_ids(&core, &empty);
    let empty_existing_recycle_bin_id = empty
        .recycle_bin_group
        .expect("existing recycle bin id")
        .to_string();
    let empty_refs = soft_delete_first_active_entry(&core, &mut empty);
    assert_eq!(
        empty_refs.recycle_bin_group_id,
        empty_existing_recycle_bin_id
    );
    assert_eq!(
        collect_soft_delete_digest(&core, &empty, &empty_refs),
        SoftDeleteDigest {
            deleted_entry_id: empty_refs.deleted_entry_id.clone(),
            deleted_entry_title: empty_refs.deleted_entry_title.clone(),
            deleted_entry_previous_parent_id: Some(empty_refs.expected_previous_parent_id.clone()),
            recycle_bin_group_id: empty_refs.recycle_bin_group_id.clone(),
            recycle_bin_title: "Recycle Bin".into(),
            recycle_bin_entry_count: 1,
            recycle_bin_child_count: 0,
            root_child_titles: vec![
                "Mail".into(),
                "Network".into(),
                "Computer logins".into(),
                "Recycle Bin".into(),
            ],
            deleted_objects_count: empty_expected_deleted_object_ids.len(),
            deleted_object_ids: empty_expected_deleted_object_ids,
        }
    );

    let mut with_data = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");
    let with_data_refs = soft_delete_and_restore_first_active_entry(&core, &mut with_data);
    assert_eq!(
        collect_restore_digest(&core, &with_data, &with_data_refs),
        RestoreDigest {
            restored_entry_id: with_data_refs.restored_entry_id.clone(),
            restored_entry_title: with_data_refs.restored_entry_title.clone(),
            restored_entry_previous_parent_id: None,
            target_group_id: with_data_refs.target_group_id.clone(),
            target_group_title: with_data_refs.target_group_title.clone(),
            target_group_entry_titles: with_data_refs.expected_target_group_entry_titles.clone(),
            recycle_bin_group_id: with_data_refs.recycle_bin_group_id.clone(),
            recycle_bin_title: "Recycle Bin".into(),
            recycle_bin_entry_count: 2,
            recycle_bin_child_count: 2,
            deleted_objects_count: with_data_refs.expected_deleted_object_ids.len(),
            deleted_object_ids: with_data_refs.expected_deleted_object_ids.clone(),
        }
    );
}

#[test]
fn external_recycle_bin_mutation_oracle_preserves_fixture_matrix_on_roundtrip() {
    let core = KeepassCore::new();

    let mut not_yet_created = load_fixture(&core, FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, "123");
    let not_yet_created_refs = soft_delete_first_active_entry(&core, &mut not_yet_created);
    let not_yet_created_before =
        collect_soft_delete_digest(&core, &not_yet_created, &not_yet_created_refs);
    let not_yet_created_reloaded = save_and_reload(&core, &not_yet_created, "123");
    let not_yet_created_after =
        collect_soft_delete_digest(&core, &not_yet_created_reloaded, &not_yet_created_refs);
    assert_eq!(not_yet_created_after, not_yet_created_before);

    let mut empty = load_fixture(&core, FIXTURE_RECYCLE_BIN_EMPTY, "123");
    let empty_refs = soft_delete_first_active_entry(&core, &mut empty);
    let empty_before = collect_soft_delete_digest(&core, &empty, &empty_refs);
    let empty_reloaded = save_and_reload(&core, &empty, "123");
    let empty_after = collect_soft_delete_digest(&core, &empty_reloaded, &empty_refs);
    assert_eq!(empty_after, empty_before);

    let mut with_data = load_fixture(&core, FIXTURE_RECYCLE_BIN_WITH_DATA, "123");
    let with_data_refs = soft_delete_and_restore_first_active_entry(&core, &mut with_data);
    let with_data_before = collect_restore_digest(&core, &with_data, &with_data_refs);
    let with_data_reloaded = save_and_reload(&core, &with_data, "123");
    let with_data_after = collect_restore_digest(&core, &with_data_reloaded, &with_data_refs);
    assert_eq!(with_data_after, with_data_before);
}

fn soft_delete_first_active_entry(core: &KeepassCore, vault: &mut Vault) -> SoftDeleteRefs {
    let recycle_bin_group_id = vault.recycle_bin_group.map(|id| id.to_string());
    let (parent_group_id, entry_id, entry_title) =
        find_first_active_entry(&vault.root, recycle_bin_group_id.as_deref())
            .expect("active entry outside recycle bin");

    let deleted = core
        .soft_delete_entry_to_recycle_bin(vault, &entry_id)
        .expect("soft delete active entry");
    let recycle_bin_group_id = vault
        .recycle_bin_group
        .expect("recycle bin group id after soft delete")
        .to_string();

    assert_eq!(deleted.id, entry_id);

    SoftDeleteRefs {
        deleted_entry_id: entry_id,
        deleted_entry_title: entry_title,
        expected_previous_parent_id: parent_group_id,
        recycle_bin_group_id,
    }
}

fn soft_delete_and_restore_first_active_entry(
    core: &KeepassCore,
    vault: &mut Vault,
) -> RestoreRefs {
    let expected_deleted_object_ids = collect_deleted_object_ids(core, vault);
    let recycle_bin_group_id = vault
        .recycle_bin_group
        .expect("existing recycle bin group id")
        .to_string();
    let (target_group_id, entry_id, entry_title) =
        find_first_active_entry(&vault.root, Some(&recycle_bin_group_id))
            .expect("active entry outside recycle bin");
    let target_group =
        find_group_by_id(&vault.root, &target_group_id).expect("restore target group");
    let target_group_title = target_group.title.clone();
    let expected_target_group_entry_titles = target_group
        .entries
        .iter()
        .map(|entry| entry.title.clone())
        .collect::<Vec<_>>();

    core.soft_delete_entry_to_recycle_bin(vault, &entry_id)
        .expect("soft delete active entry into populated recycle bin");

    let restored = core
        .restore_entry_from_recycle_bin(vault, &entry_id, None)
        .expect("restore recycle bin entry");
    assert_eq!(restored.id, entry_id);

    RestoreRefs {
        restored_entry_id: entry_id,
        restored_entry_title: entry_title,
        target_group_id,
        target_group_title,
        expected_target_group_entry_titles,
        recycle_bin_group_id,
        expected_deleted_object_ids,
    }
}

fn collect_soft_delete_digest(
    core: &KeepassCore,
    vault: &Vault,
    refs: &SoftDeleteRefs,
) -> SoftDeleteDigest {
    let deleted_entry = core
        .find_entry_view_by_id(vault, &refs.deleted_entry_id)
        .expect("deleted entry view");
    let lineage = core
        .project_entry_lineage_report_metadata(vault, &refs.deleted_entry_id)
        .expect("deleted entry lineage");
    let recycle_bin = core
        .find_group_view_by_id(vault, &refs.recycle_bin_group_id)
        .expect("recycle bin view");

    SoftDeleteDigest {
        deleted_entry_id: deleted_entry.id,
        deleted_entry_title: deleted_entry.title,
        deleted_entry_previous_parent_id: lineage.previous_parent_id,
        recycle_bin_group_id: recycle_bin.id,
        recycle_bin_title: recycle_bin.title,
        recycle_bin_entry_count: recycle_bin.entry_count,
        recycle_bin_child_count: recycle_bin.child_count,
        root_child_titles: vault
            .root
            .children
            .iter()
            .map(|group| group.title.clone())
            .collect(),
        deleted_objects_count: core.list_deleted_objects(vault).len(),
        deleted_object_ids: collect_deleted_object_ids(core, vault),
    }
}

fn collect_restore_digest(core: &KeepassCore, vault: &Vault, refs: &RestoreRefs) -> RestoreDigest {
    let restored_entry = core
        .find_entry_view_by_id(vault, &refs.restored_entry_id)
        .expect("restored entry view");
    let lineage = core
        .project_entry_lineage_report_metadata(vault, &refs.restored_entry_id)
        .expect("restored entry lineage");
    let recycle_bin = core
        .find_group_view_by_id(vault, &refs.recycle_bin_group_id)
        .expect("recycle bin view");
    let target_group = core
        .find_group_view_by_id(vault, &refs.target_group_id)
        .expect("target group view");

    RestoreDigest {
        restored_entry_id: restored_entry.id,
        restored_entry_title: restored_entry.title,
        restored_entry_previous_parent_id: lineage.previous_parent_id,
        target_group_id: target_group.id,
        target_group_title: target_group.title,
        target_group_entry_titles: target_group
            .entries
            .into_iter()
            .map(|entry| entry.title)
            .collect(),
        recycle_bin_group_id: recycle_bin.id,
        recycle_bin_title: recycle_bin.title,
        recycle_bin_entry_count: recycle_bin.entry_count,
        recycle_bin_child_count: recycle_bin.child_count,
        deleted_objects_count: core.list_deleted_objects(vault).len(),
        deleted_object_ids: collect_deleted_object_ids(core, vault),
    }
}

fn collect_deleted_object_ids(core: &KeepassCore, vault: &Vault) -> Vec<String> {
    let mut ids = core
        .list_deleted_objects(vault)
        .into_iter()
        .map(|item| item.id)
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn load_fixture(core: &KeepassCore, bytes: &[u8], password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    core.load_kdbx(bytes, &key)
        .expect("load recycle bin fixture")
}

fn save_and_reload(core: &KeepassCore, vault: &Vault, password: &str) -> Vault {
    let mut key = CompositeKey::default();
    key.add_password(password);
    let rewritten = core
        .save_kdbx(vault, &key, SaveProfile::recommended())
        .expect("rewrite recycle bin fixture");
    core.load_kdbx(&rewritten, &key)
        .expect("reload recycle bin fixture")
}

fn find_first_active_entry(
    group: &vaultkern_core::Group,
    recycle_bin_group_id: Option<&str>,
) -> Option<(String, String, String)> {
    if Some(group.id.to_string().as_str()) != recycle_bin_group_id {
        if let Some(entry) = group.entries.first() {
            return Some((
                group.id.to_string(),
                entry.id.to_string(),
                entry.title.clone(),
            ));
        }
    }

    for child in &group.children {
        if let Some(found) = find_first_active_entry(child, recycle_bin_group_id) {
            return Some(found);
        }
    }

    None
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
