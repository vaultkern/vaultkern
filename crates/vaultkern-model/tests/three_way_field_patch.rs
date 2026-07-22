use uuid::Uuid;
use vaultkern_model::{
    Attachment, CustomDataBlock, CustomDataItem, CustomField, CustomIcon, DeletedObject, Entry,
    Group, GroupTimes, OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, ThreeWayPatchError,
    TotpSpec, Vault, reconcile_custom_data_blocks, three_way_field_patch,
};

fn base_vault() -> (Vault, Uuid) {
    let mut vault = Vault::empty("Shared");
    let mut entry = Entry::new("Account");
    entry.username = "alice".into();
    entry.password = "base-password".into();
    entry.notes = "base-notes".into();
    entry.modified_at = 10;
    let entry_id = entry.id;
    vault.root.entries.push(entry);
    (vault, entry_id)
}

fn entry(group: &Group, id: Uuid) -> Option<&Entry> {
    group
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .or_else(|| group.children.iter().find_map(|child| entry(child, id)))
}

fn entry_mut(group: &mut Group, id: Uuid) -> Option<&mut Entry> {
    if let Some(index) = group.entries.iter().position(|entry| entry.id == id) {
        return group.entries.get_mut(index);
    }
    group
        .children
        .iter_mut()
        .find_map(|child| entry_mut(child, id))
}

fn parent_of(group: &Group, id: Uuid) -> Option<Uuid> {
    if group.entries.iter().any(|entry| entry.id == id) {
        return Some(group.id);
    }
    group.children.iter().find_map(|child| parent_of(child, id))
}

fn custom_data_item<'a>(blocks: &'a [CustomDataBlock], key: &str) -> &'a CustomDataItem {
    blocks
        .iter()
        .flat_map(|block| &block.items)
        .filter(|item| item.key == key)
        .next_back()
        .unwrap_or_else(|| panic!("missing CustomData item {key}"))
}

fn seed_meta_custom_data(vault: &mut Vault, key: &str, value: &str, last_modified: i64) {
    vault
        .meta_custom_data
        .insert(key.to_owned(), value.to_owned());
    reconcile_custom_data_blocks(
        &mut vault.meta_custom_data_blocks,
        &mut vault.meta_opaque_xml,
        &mut vault.meta_raw_state.node_order,
        &vault.meta_custom_data,
        Some((key, Some(last_modified))),
    );
}

fn seed_group_custom_data(group: &mut Group, key: &str, value: &str, last_modified: i64) {
    group.custom_data.insert(key.to_owned(), value.to_owned());
    reconcile_custom_data_blocks(
        &mut group.custom_data_blocks,
        &mut group.opaque_xml,
        &mut group.raw_state.node_order,
        &group.custom_data,
        Some((key, Some(last_modified))),
    );
}

fn seed_entry_custom_data(entry: &mut Entry, key: &str, value: &str, last_modified: i64) {
    entry.custom_data.insert(key.to_owned(), value.to_owned());
    reconcile_custom_data_blocks(
        &mut entry.custom_data_blocks,
        &mut entry.opaque_xml,
        &mut entry.raw_state.node_order,
        &entry.custom_data,
        Some((key, Some(last_modified))),
    );
}

#[test]
fn disjoint_meta_custom_data_changes_merge_with_item_fidelity() {
    let mut base = Vault::empty("Shared");
    seed_meta_custom_data(&mut base, "base", "base-value", 10);

    let mut local = base.clone();
    seed_meta_custom_data(&mut local, "local-receipt", "receipt", 20);
    let mut remote = base.clone();
    seed_meta_custom_data(&mut remote, "remote-extension", "remote", 30);

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert_eq!(patched.vault.meta_custom_data["local-receipt"], "receipt");
    assert_eq!(patched.vault.meta_custom_data["remote-extension"], "remote");
    assert_eq!(
        custom_data_item(&patched.vault.meta_custom_data_blocks, "local-receipt").last_modified,
        Some(20)
    );
    assert_eq!(
        custom_data_item(&patched.vault.meta_custom_data_blocks, "remote-extension").last_modified,
        Some(30)
    );
}

#[test]
fn disjoint_group_and_entry_custom_data_changes_merge_with_item_fidelity() {
    let mut base = Vault::empty("Shared");
    let mut group = Group::new("Group");
    seed_group_custom_data(&mut group, "base-group", "base", 10);
    let mut account = Entry::new("Account");
    seed_entry_custom_data(&mut account, "base-entry", "base", 10);
    let account_id = account.id;
    group.entries.push(account);
    base.root.children.push(group);

    let mut local = base.clone();
    seed_group_custom_data(&mut local.root.children[0], "local-group", "local", 20);
    seed_entry_custom_data(
        entry_mut(&mut local.root, account_id).unwrap(),
        "local-entry",
        "local",
        20,
    );
    let mut remote = base.clone();
    seed_group_custom_data(&mut remote.root.children[0], "remote-group", "remote", 30);
    seed_entry_custom_data(
        entry_mut(&mut remote.root, account_id).unwrap(),
        "remote-entry",
        "remote",
        30,
    );

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged_group = &patched.vault.root.children[0];
    assert_eq!(merged_group.custom_data["local-group"], "local");
    assert_eq!(merged_group.custom_data["remote-group"], "remote");
    assert_eq!(
        custom_data_item(&merged_group.custom_data_blocks, "local-group").last_modified,
        Some(20)
    );
    assert_eq!(
        custom_data_item(&merged_group.custom_data_blocks, "remote-group").last_modified,
        Some(30)
    );
    let merged_entry = entry(&patched.vault.root, account_id).unwrap();
    assert_eq!(merged_entry.custom_data["local-entry"], "local");
    assert_eq!(merged_entry.custom_data["remote-entry"], "remote");
    assert_eq!(
        custom_data_item(&merged_entry.custom_data_blocks, "local-entry").last_modified,
        Some(20)
    );
    assert_eq!(
        custom_data_item(&merged_entry.custom_data_blocks, "remote-entry").last_modified,
        Some(30)
    );
}

#[test]
fn custom_data_rebase_preserves_one_sided_layout_but_rejects_two_layout_rewrites() {
    let mut base = Vault::empty("Shared");
    seed_meta_custom_data(&mut base, "first", "1", 10);
    seed_meta_custom_data(&mut base, "second", "2", 11);

    let mut local = base.clone();
    local.meta_custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "first").clone()],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "second").clone()],
            after: None,
        },
    ];
    let one_sided = three_way_field_patch(&base, &local, &base).unwrap();
    assert_eq!(
        one_sided.vault.meta_custom_data_blocks,
        local.meta_custom_data_blocks
    );

    let mut remote = base.clone();
    remote.meta_custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "second").clone()],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "first").clone()],
            after: None,
        },
    ];
    assert!(matches!(
        three_way_field_patch(&base, &local, &remote),
        Err(ThreeWayPatchError::FidelityConflict {
            object: "meta",
            id: None,
            field: "CustomData fidelity",
        })
    ));
}

#[test]
fn disjoint_custom_data_deletes_reconcile_blocks_anchors_and_node_order() {
    let mut base = Vault::empty("Shared");
    seed_meta_custom_data(&mut base, "local-delete", "1", 10);
    seed_meta_custom_data(&mut base, "remote-delete", "2", 11);
    base.meta_custom_data_blocks = vec![
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "local-delete").clone()],
            after: None,
        },
        CustomDataBlock {
            items: vec![custom_data_item(&base.meta_custom_data_blocks, "remote-delete").clone()],
            after: Some(OpaqueXmlAnchor {
                element_name: "CustomData".into(),
                occurrence: 1,
            }),
        },
    ];
    base.meta_raw_state.node_order = vec![
        "CustomData".into(),
        "CustomData".into(),
        "ForeignExtension".into(),
    ];
    base.meta_opaque_xml.push(OpaqueXmlFragment {
        xml: "<ForeignExtension />".into(),
        after: Some(OpaqueXmlAnchor {
            element_name: "CustomData".into(),
            occurrence: 2,
        }),
    });

    let mut local = base.clone();
    local.meta_custom_data.remove("local-delete");
    reconcile_custom_data_blocks(
        &mut local.meta_custom_data_blocks,
        &mut local.meta_opaque_xml,
        &mut local.meta_raw_state.node_order,
        &local.meta_custom_data,
        None,
    );
    let mut remote = base.clone();
    remote.meta_custom_data.remove("remote-delete");
    reconcile_custom_data_blocks(
        &mut remote.meta_custom_data_blocks,
        &mut remote.meta_opaque_xml,
        &mut remote.meta_raw_state.node_order,
        &remote.meta_custom_data,
        None,
    );

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert!(patched.vault.meta_custom_data.is_empty());
    assert!(patched.vault.meta_custom_data_blocks.is_empty());
    assert_eq!(
        patched.vault.meta_raw_state.node_order,
        vec!["ForeignExtension"]
    );
    assert_eq!(patched.vault.meta_opaque_xml[0].after, None);
}

#[test]
fn independent_entry_fields_and_keyed_units_are_rebased_onto_remote() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.password = "local-password".into();
    local_entry.attributes.insert(
        "local-field".into(),
        CustomField {
            value: "local".into(),
            protected: false,
        },
    );
    local_entry.attachments.insert(
        "local.txt".into(),
        Attachment::new("local.txt", b"local".to_vec(), false),
    );
    local_entry.modified_at = 20;

    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    remote_entry.notes = "remote-notes".into();
    remote_entry.attributes.insert(
        "remote-field".into(),
        CustomField {
            value: "remote".into(),
            protected: true,
        },
    );
    remote_entry.attachments.insert(
        "remote.txt".into(),
        Attachment::new("remote.txt", b"remote".to_vec(), true),
    );
    remote_entry.modified_at = 30;

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged = entry(&patched.vault.root, entry_id).unwrap();
    assert_eq!(merged.password, "local-password");
    assert_eq!(merged.notes, "remote-notes");
    assert_eq!(merged.attributes["local-field"].value, "local");
    assert_eq!(merged.attributes["remote-field"].value, "remote");
    assert_eq!(merged.attachments["local.txt"].data.as_bytes(), b"local");
    assert_eq!(merged.attachments["remote.txt"].data.as_bytes(), b"remote");
}

#[test]
fn independent_standard_field_protection_changes_are_rebased_per_field() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.field_protection.protect_title = true;
    local_entry.modified_at = 20;

    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    remote_entry.field_protection.protect_password = false;
    remote_entry.modified_at = 30;

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged = entry(&patched.vault.root, entry_id).unwrap();
    assert!(merged.field_protection.protect_title);
    assert!(!merged.field_protection.protect_password);
}

#[test]
fn duplicate_modeled_meta_uuids_fall_back_instead_of_being_collapsed() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.password = "local-password".into();
    local_entry.modified_at = 20;
    let duplicate_id = Uuid::new_v4();

    let mut remote = base.clone();
    remote.custom_icons = vec![
        CustomIcon {
            id: duplicate_id,
            data: vec![1],
            name: Some("First".into()),
            last_modified: Some(10),
        },
        CustomIcon {
            id: duplicate_id,
            data: vec![2],
            name: Some("Second".into()),
            last_modified: Some(20),
        },
    ];
    assert!(three_way_field_patch(&base, &local, &remote).is_err());

    let mut remote = base.clone();
    remote.deleted_objects = vec![
        DeletedObject {
            id: duplicate_id,
            deleted_at: 10,
        },
        DeletedObject {
            id: duplicate_id,
            deleted_at: 20,
        },
    ];
    assert!(three_way_field_patch(&base, &local, &remote).is_err());
}

#[test]
fn totp_and_passkey_are_independent_whole_units() {
    let (mut base, entry_id) = base_vault();
    let base_entry = entry_mut(&mut base.root, entry_id).unwrap();
    base_entry.totp = Some(
        TotpSpec::parse_otpauth("otpauth://totp/Base:alice?secret=JBSWY3DPEHPK3PXP&issuer=Base")
            .unwrap(),
    );
    base_entry.attributes.insert(
        "otp".into(),
        CustomField {
            value: "otpauth://totp/Base:alice?secret=JBSWY3DPEHPK3PXP&issuer=Base".into(),
            protected: true,
        },
    );
    let base_passkey = passkey("base-credential");
    base_passkey.write_to_attributes(&mut base_entry.attributes);
    base_entry.passkey = Some(base_passkey);

    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.totp = Some(
        TotpSpec::parse_otpauth("otpauth://totp/Local:alice?secret=KRUGS4ZANFZSAYJA&issuer=Local")
            .unwrap(),
    );
    local_entry.attributes.insert(
        "otp".into(),
        CustomField {
            value: "otpauth://totp/Local:alice?secret=KRUGS4ZANFZSAYJA&issuer=Local".into(),
            protected: true,
        },
    );
    local_entry.modified_at = 40;

    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    let remote_passkey = passkey("remote-credential");
    remote_passkey.write_to_attributes(&mut remote_entry.attributes);
    remote_entry.passkey = Some(remote_passkey.clone());
    remote_entry.modified_at = 50;

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged = entry(&patched.vault.root, entry_id).unwrap();
    assert_eq!(
        merged.totp.as_ref().unwrap().issuer.as_deref(),
        Some("Local")
    );
    assert!(merged.attributes["otp"].value.contains("Local"));
    assert_eq!(merged.passkey.as_ref(), Some(&remote_passkey));
    assert_eq!(
        merged.attributes[PasskeyRecord::CREDENTIAL_ID_KEY].value,
        "remote-credential"
    );
}

fn passkey(credential_id: &str) -> PasskeyRecord {
    PasskeyRecord {
        username: "alice".into(),
        credential_id: credential_id.into(),
        generated_user_id: None,
        private_key_pem: format!("private-{credential_id}").into(),
        relying_party: "example.com".into(),
        user_handle: Some("user-handle".into()),
        backup_eligible: false,
        backup_state: false,
    }
}

#[test]
fn same_field_uses_later_entry_timestamp_and_preserves_loser_in_history() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.password = "local-later".into();
    local_entry.modified_at = 40;
    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    remote_entry.password = "remote-earlier".into();
    remote_entry.modified_at = 30;

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged = entry(&patched.vault.root, entry_id).unwrap();
    assert_eq!(merged.password, "local-later");
    assert!(
        merged
            .history
            .iter()
            .any(|snapshot| snapshot.password == "remote-earlier")
    );
    assert_eq!(patched.report.history_snapshots_added, 1);
}

#[test]
fn same_field_timestamp_tie_keeps_remote() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.password = "local".into();
    local_entry.modified_at = 40;
    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    remote_entry.password = "remote".into();
    remote_entry.modified_at = 40;

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert_eq!(
        entry(&patched.vault.root, entry_id).unwrap().password,
        "remote"
    );
}

#[test]
fn edit_beats_delete_but_untouched_peer_allows_delete() {
    let (base, entry_id) = base_vault();
    let mut local_edit = base.clone();
    let edited = entry_mut(&mut local_edit.root, entry_id).unwrap();
    edited.title = "Edited locally".into();
    edited.modified_at = 20;
    let mut remote_delete = base.clone();
    remote_delete.root.entries.clear();
    remote_delete.deleted_objects.push(DeletedObject {
        id: entry_id,
        deleted_at: 30,
    });

    let restored = three_way_field_patch(&base, &local_edit, &remote_delete).unwrap();
    assert_eq!(
        entry(&restored.vault.root, entry_id).unwrap().title,
        "Edited locally"
    );
    assert!(
        restored
            .vault
            .deleted_objects
            .iter()
            .all(|deleted| deleted.id != entry_id)
    );

    let mut local_delete = base.clone();
    local_delete.root.entries.clear();
    let deleted = three_way_field_patch(&base, &local_delete, &base).unwrap();
    assert!(entry(&deleted.vault.root, entry_id).is_none());
}

#[test]
fn conflicting_parents_use_location_changed_at_with_remote_tie_break() {
    let (mut base, entry_id) = base_vault();
    let mut first = Group::new("First");
    first.entries = std::mem::take(&mut base.root.entries);
    let first_id = first.id;
    let second = Group::new("Second");
    let second_id = second.id;
    base.root.children = vec![first, second];

    let mut local = base.clone();
    let mut moved = local.root.children[0].entries.remove(0);
    moved.location_changed_at = Some(50);
    local.root.children[1].entries.push(moved);

    let mut remote = base.clone();
    let mut moved = remote.root.children[0].entries.remove(0);
    moved.location_changed_at = Some(50);
    remote.root.entries.push(moved);

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert_eq!(
        parent_of(&patched.vault.root, entry_id),
        Some(patched.vault.root.id)
    );
    assert_ne!(parent_of(&patched.vault.root, entry_id), Some(second_id));
    assert_ne!(parent_of(&patched.vault.root, entry_id), Some(first_id));
}

#[test]
fn deleting_group_cannot_orphan_a_changed_descendant() {
    let (mut base, entry_id) = base_vault();
    let mut child = Group::new("Folder");
    child.entries = std::mem::take(&mut base.root.entries);
    let child_id = child.id;
    base.root.children.push(child);

    let mut local = base.clone();
    let edited = entry_mut(&mut local.root, entry_id).unwrap();
    edited.notes = "changed inside deleted group".into();
    edited.modified_at = 20;
    let mut remote = base.clone();
    remote.root.children.clear();

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert!(
        patched
            .vault
            .root
            .children
            .iter()
            .any(|group| group.id == child_id)
    );
    assert_eq!(
        entry(&patched.vault.root, entry_id).unwrap().notes,
        "changed inside deleted group"
    );
}

#[test]
fn moving_existing_entry_into_remotely_deleted_group_preserves_destination() {
    let (mut base, entry_id) = base_vault();
    let source = Group::new("Source");
    let destination = Group::new("Destination");
    let destination_id = destination.id;
    base.root.children = vec![source, destination];

    let mut local = base.clone();
    let mut moved = local.root.entries.remove(0);
    moved.location_changed_at = Some(20);
    local.root.children[1].entries.push(moved);

    let mut remote = base.clone();
    remote.root.children.remove(1);

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    assert_eq!(
        parent_of(&patched.vault.root, entry_id),
        Some(destination_id)
    );
    assert!(
        patched
            .vault
            .root
            .children
            .iter()
            .any(|group| group.id == destination_id)
    );
}

#[test]
fn moving_existing_group_into_remotely_deleted_group_preserves_destination() {
    let mut base = Vault::empty("Shared");
    let moved = Group::new("Moved");
    let moved_id = moved.id;
    let destination = Group::new("Destination");
    let destination_id = destination.id;
    base.root.children = vec![moved, destination];

    let mut local = base.clone();
    let mut moved = local.root.children.remove(0);
    moved.times = Some(GroupTimes {
        created_at: 0,
        modified_at: 20,
        expires: false,
        expiry_time: None,
        last_accessed_at: None,
        usage_count: None,
        location_changed_at: Some(20),
    });
    local.root.children[0].children.push(moved);

    let mut remote = base.clone();
    remote.root.children.remove(1);

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let destination = patched
        .vault
        .root
        .children
        .iter()
        .find(|group| group.id == destination_id)
        .expect("move destination survives its concurrent deletion");
    assert!(
        destination
            .children
            .iter()
            .any(|group| group.id == moved_id)
    );
}

#[test]
fn concurrent_group_field_edits_fall_back_when_loser_has_no_history() {
    let mut base = Vault::empty("Shared");
    let mut folder = Group::new("Base");
    folder.times = Some(GroupTimes {
        created_at: 0,
        modified_at: 10,
        expires: false,
        expiry_time: None,
        last_accessed_at: None,
        usage_count: None,
        location_changed_at: None,
    });
    let folder_id = folder.id;
    base.root.children.push(folder);

    let mut local = base.clone();
    local.root.children[0].title = "Local".into();
    local.root.children[0].times.as_mut().unwrap().modified_at = 20;

    let mut remote = base.clone();
    remote.root.children[0].title = "Remote".into();
    remote.root.children[0].times.as_mut().unwrap().modified_at = 30;

    assert!(matches!(
        three_way_field_patch(&base, &local, &remote),
        Err(ThreeWayPatchError::FidelityConflict {
            object: "group",
            id: Some(id),
            ..
        }) if id == folder_id
    ));
}

#[test]
fn concurrent_meta_field_edits_fall_back_when_loser_has_no_history() {
    let mut base = Vault::empty("Base");
    base.database_name_changed = Some(10);

    let mut local = base.clone();
    local.name = "Local".into();
    local.database_name_changed = Some(20);

    let mut remote = base.clone();
    remote.name = "Remote".into();
    remote.database_name_changed = Some(30);

    assert!(matches!(
        three_way_field_patch(&base, &local, &remote),
        Err(ThreeWayPatchError::FidelityConflict {
            object: "meta",
            id: None,
            ..
        })
    ));
}

#[test]
fn renaming_group_during_remote_delete_preserves_unchanged_subtree() {
    let (mut base, entry_id) = base_vault();
    let mut nested = Group::new("Nested");
    nested.entries = std::mem::take(&mut base.root.entries);
    let nested_id = nested.id;
    let mut folder = Group::new("Folder");
    folder.children.push(nested);
    let folder_id = folder.id;
    base.root.children.push(folder);

    let mut local = base.clone();
    local.root.children[0].title = "Renamed locally".into();
    let mut remote = base.clone();
    remote.root.children.clear();

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let restored = patched
        .vault
        .root
        .children
        .iter()
        .find(|group| group.id == folder_id)
        .expect("renamed group survives the delete/edit race");

    assert_eq!(restored.title, "Renamed locally");
    assert!(restored.children.iter().any(|group| group.id == nested_id));
    assert!(entry(restored, entry_id).is_some());
}

#[test]
fn history_is_a_union_and_meta_fields_patch_independently() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    local.name = "Local name".into();
    local.database_name_changed = Some(20);
    let mut local_history = entry(&local.root, entry_id).unwrap().clone();
    local_history.password = "local history".into();
    local_history.history.clear();
    entry_mut(&mut local.root, entry_id)
        .unwrap()
        .history
        .push(local_history);

    let mut remote = base.clone();
    remote.description = Some("Remote description".into());
    remote.description_changed = Some(30);
    let mut remote_history = entry(&remote.root, entry_id).unwrap().clone();
    remote_history.password = "remote history".into();
    remote_history.history.clear();
    entry_mut(&mut remote.root, entry_id)
        .unwrap()
        .history
        .push(remote_history);

    let patched = three_way_field_patch(&base, &local, &remote).unwrap();
    let merged = entry(&patched.vault.root, entry_id).unwrap();
    assert_eq!(patched.vault.name, "Local name");
    assert_eq!(
        patched.vault.description.as_deref(),
        Some("Remote description")
    );
    assert!(
        merged
            .history
            .iter()
            .any(|item| item.password == "local history")
    );
    assert!(
        merged
            .history
            .iter()
            .any(|item| item.password == "remote history")
    );
}

#[test]
fn concurrent_additions_with_the_same_uuid_fall_back() {
    let base = Vault::empty("Shared");
    let mut local = base.clone();
    let mut remote = base.clone();
    let mut local_entry = Entry::new("Local");
    let mut remote_entry = Entry::new("Remote");
    remote_entry.id = local_entry.id;
    local_entry.modified_at = 20;
    remote_entry.modified_at = 30;
    local.root.entries.push(local_entry);
    remote.root.entries.push(remote_entry);

    assert!(three_way_field_patch(&base, &local, &remote).is_err());
}

#[test]
fn conflicting_group_moves_that_form_a_cycle_fall_back() {
    let mut base = Vault::empty("Shared");
    let group_a = Group::new("A");
    let group_b = Group::new("B");
    base.root.children = vec![group_a, group_b];

    let mut local = base.clone();
    let moved_a = local.root.children.remove(0);
    local.root.children[0].children.push(moved_a);

    let mut remote = base.clone();
    let moved_b = remote.root.children.remove(1);
    remote.root.children[0].children.push(moved_b);

    assert!(three_way_field_patch(&base, &local, &remote).is_err());
}

#[test]
fn concurrent_unknown_xml_changes_fall_back_instead_of_dropping_luggage() {
    let (base, entry_id) = base_vault();
    let mut local = base.clone();
    let local_entry = entry_mut(&mut local.root, entry_id).unwrap();
    local_entry.opaque_xml.push(OpaqueXmlFragment {
        xml: "<LocalExtension />".into(),
        after: None,
    });
    local_entry.modified_at = 20;

    let mut remote = base.clone();
    let remote_entry = entry_mut(&mut remote.root, entry_id).unwrap();
    remote_entry.opaque_xml.push(OpaqueXmlFragment {
        xml: "<RemoteExtension />".into(),
        after: None,
    });
    remote_entry.modified_at = 30;

    assert!(three_way_field_patch(&base, &local, &remote).is_err());
}

#[test]
fn local_sibling_reordering_falls_back_instead_of_being_silently_dropped() {
    let (mut base, _) = base_vault();
    base.root.entries.push(Entry::new("Second account"));
    let mut local = base.clone();
    local.root.entries.swap(0, 1);

    assert!(three_way_field_patch(&base, &local, &base).is_err());
}

#[test]
fn local_group_reordering_uses_the_same_conflict_copy_fallback() {
    let mut base = Vault::empty("Shared");
    base.root.children = vec![Group::new("First"), Group::new("Second")];
    let mut local = base.clone();
    local.root.children.swap(0, 1);

    assert!(three_way_field_patch(&base, &local, &base).is_err());
}

#[test]
fn local_entry_move_keeps_its_destination_insertion_order() {
    let mut base = Vault::empty("Shared");
    let mut source = Group::new("Source");
    let mut moved = Entry::new("Moved");
    moved.id = Uuid::from_u128(1);
    source.entries.push(moved);
    let mut destination = Group::new("Destination");
    let mut first = Entry::new("First");
    first.id = Uuid::from_u128(2);
    let mut second = Entry::new("Second");
    second.id = Uuid::from_u128(3);
    destination.entries = vec![first, second];
    base.root.children = vec![source, destination];

    let mut local = base.clone();
    let mut moved = local.root.children[0].entries.remove(0);
    moved.location_changed_at = Some(20);
    local.root.children[1].entries.insert(1, moved);

    let patched = three_way_field_patch(&base, &local, &base).unwrap();
    let destination = patched
        .vault
        .root
        .children
        .iter()
        .find(|group| group.title == "Destination")
        .unwrap();
    assert_eq!(
        destination
            .entries
            .iter()
            .map(|entry| entry.title.as_str())
            .collect::<Vec<_>>(),
        vec!["First", "Moved", "Second"]
    );
}

#[test]
fn local_group_move_keeps_its_destination_insertion_order() {
    let mut base = Vault::empty("Shared");
    let mut destination = Group::new("Destination");
    destination.children = vec![Group::new("First"), Group::new("Second")];
    base.root.children = vec![Group::new("Source"), destination, Group::new("Moved")];

    let mut local = base.clone();
    let mut moved = local.root.children.remove(2);
    moved.times = Some(GroupTimes {
        created_at: 0,
        modified_at: 20,
        expires: false,
        expiry_time: None,
        last_accessed_at: None,
        usage_count: None,
        location_changed_at: Some(20),
    });
    local.root.children[1].children.insert(1, moved);

    let patched = three_way_field_patch(&base, &local, &base).unwrap();
    let destination = patched
        .vault
        .root
        .children
        .iter()
        .find(|group| group.title == "Destination")
        .unwrap();
    assert_eq!(
        destination
            .children
            .iter()
            .map(|group| group.title.as_str())
            .collect::<Vec<_>>(),
        vec!["First", "Moved", "Second"]
    );
}

#[test]
fn local_move_and_remote_destination_reorder_fall_back() {
    let mut base = Vault::empty("Shared");
    let mut source = Group::new("Source");
    source.entries.push(Entry::new("Moved"));
    let mut destination = Group::new("Destination");
    destination.entries = vec![Entry::new("First"), Entry::new("Second")];
    base.root.children = vec![source, destination];

    let mut local = base.clone();
    let mut moved = local.root.children[0].entries.remove(0);
    moved.location_changed_at = Some(20);
    local.root.children[1].entries.insert(1, moved);

    let mut remote = base.clone();
    remote.root.children[1].entries.swap(0, 1);

    assert!(three_way_field_patch(&base, &local, &remote).is_err());
}
