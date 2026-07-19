use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    Attachment, AttachmentMap, CustomDataBlock, CustomField, CustomIcon, DeletedObject, Entry,
    Group, OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, TotpSpec, Vault,
    is_totp_persistent_attribute_key, materialize_entry_persistent_attributes,
    prepare_entry_history_snapshot, reconcile_custom_data_blocks,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreeWayPatchReport {
    pub merged_entries: usize,
    pub merged_groups: usize,
    pub history_snapshots_added: usize,
    pub meta_conflicts_resolved: u32,
    pub icon_conflicts_resolved: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayPatchResult {
    pub vault: Vault,
    pub report: ThreeWayPatchReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ThreeWayPatchError {
    #[error("three-way patch roots do not share a UUID")]
    RootLineageMismatch,
    #[error("duplicate entry UUID in {side}: {id}")]
    DuplicateEntry { side: &'static str, id: Uuid },
    #[error("duplicate group UUID in {side}: {id}")]
    DuplicateGroup { side: &'static str, id: Uuid },
    #[error("concurrent object addition reused UUID: {id}")]
    ConcurrentObjectAddition { id: Uuid },
    #[error("patched object refers to missing parent group: {id}")]
    MissingParent { id: Uuid },
    #[error("patched group hierarchy contains a cycle at: {id}")]
    GroupCycle { id: Uuid },
    #[error("concurrent {field} changes cannot be patched for {object} {id:?}")]
    FidelityConflict {
        object: &'static str,
        id: Option<Uuid>,
        field: &'static str,
    },
}

#[derive(Clone)]
struct FlatEntry {
    value: Entry,
    parent: Uuid,
    order: usize,
}

#[derive(Clone)]
struct FlatGroup {
    value: Group,
    parent: Option<Uuid>,
    order: usize,
}

struct FlatVault {
    root_id: Uuid,
    entries: BTreeMap<Uuid, FlatEntry>,
    groups: BTreeMap<Uuid, FlatGroup>,
}

#[derive(Default)]
struct FieldMerge {
    conflict: bool,
    changed_from_remote: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct TotpUnit {
    projected: Option<TotpSpec>,
    attributes: BTreeMap<String, CustomField>,
}

#[derive(Clone, PartialEq, Eq)]
struct PasskeyUnit {
    projected: Option<PasskeyRecord>,
    attributes: BTreeMap<String, CustomField>,
}

/// Applies this device's `diff(base, local)` to the current remote head.
///
/// This is deliberately a model-only operation. Callers must serialize and
/// verify the returned vault before publishing it under an external CAS.
pub fn three_way_field_patch(
    base: &Vault,
    local: &Vault,
    remote: &Vault,
) -> Result<ThreeWayPatchResult, ThreeWayPatchError> {
    let base_flat = flatten_vault(base, "base")?;
    let local_flat = flatten_vault(local, "local")?;
    let remote_flat = flatten_vault(remote, "remote")?;
    if base_flat.root_id != local_flat.root_id || base_flat.root_id != remote_flat.root_id {
        return Err(ThreeWayPatchError::RootLineageMismatch);
    }
    ensure_fidelity_conflicts_representable(
        base,
        local,
        remote,
        &base_flat,
        &local_flat,
        &remote_flat,
    )?;

    let mut report = ThreeWayPatchReport::default();
    let groups = merge_groups(&base_flat, &local_flat, &remote_flat, &mut report)?;
    validate_group_hierarchy(base_flat.root_id, &groups)?;
    let entries = merge_entries(&base_flat, &local_flat, &remote_flat, &groups, &mut report)?;
    let root = rebuild_tree(base_flat.root_id, &groups, &entries, &mut BTreeSet::new())?;
    let mut vault = merge_meta(base, local, remote, &mut report);
    vault.root = root;
    normalize_group_attachment_content(&mut vault.root);
    Ok(ThreeWayPatchResult { vault, report })
}

fn ensure_fidelity_conflicts_representable(
    base: &Vault,
    local: &Vault,
    remote: &Vault,
    base_flat: &FlatVault,
    local_flat: &FlatVault,
    remote_flat: &FlatVault,
) -> Result<(), ThreeWayPatchError> {
    ensure_fidelity_field(
        &base.meta_opaque_xml,
        &local.meta_opaque_xml,
        &remote.meta_opaque_xml,
        "meta",
        None,
        "opaque XML",
    )?;
    ensure_fidelity_field(
        &base.root_opaque_xml,
        &local.root_opaque_xml,
        &remote.root_opaque_xml,
        "root",
        None,
        "opaque XML",
    )?;
    ensure_fidelity_field(
        &base.meta_custom_data_blocks,
        &local.meta_custom_data_blocks,
        &remote.meta_custom_data_blocks,
        "meta",
        None,
        "CustomData fidelity",
    )?;

    for (id, base_entry) in &base_flat.entries {
        let (Some(local_entry), Some(remote_entry)) =
            (local_flat.entries.get(id), remote_flat.entries.get(id))
        else {
            continue;
        };
        ensure_fidelity_field(
            &base_entry.value.opaque_xml,
            &local_entry.value.opaque_xml,
            &remote_entry.value.opaque_xml,
            "entry",
            Some(*id),
            "opaque XML",
        )?;
        ensure_fidelity_field(
            &base_entry.value.custom_data_blocks,
            &local_entry.value.custom_data_blocks,
            &remote_entry.value.custom_data_blocks,
            "entry",
            Some(*id),
            "CustomData fidelity",
        )?;
    }
    for (id, base_group) in &base_flat.groups {
        let (Some(local_group), Some(remote_group)) =
            (local_flat.groups.get(id), remote_flat.groups.get(id))
        else {
            continue;
        };
        ensure_fidelity_field(
            &base_group.value.opaque_xml,
            &local_group.value.opaque_xml,
            &remote_group.value.opaque_xml,
            "group",
            Some(*id),
            "opaque XML",
        )?;
        ensure_fidelity_field(
            &base_group.value.custom_data_blocks,
            &local_group.value.custom_data_blocks,
            &remote_group.value.custom_data_blocks,
            "group",
            Some(*id),
            "CustomData fidelity",
        )?;
    }
    Ok(())
}

fn ensure_fidelity_field<T: Eq>(
    base: &T,
    local: &T,
    remote: &T,
    object: &'static str,
    id: Option<Uuid>,
    field: &'static str,
) -> Result<(), ThreeWayPatchError> {
    if local != base && remote != base && local != remote {
        return Err(ThreeWayPatchError::FidelityConflict { object, id, field });
    }
    Ok(())
}

fn validate_group_hierarchy(
    root_id: Uuid,
    groups: &BTreeMap<Uuid, FlatGroup>,
) -> Result<(), ThreeWayPatchError> {
    let root = groups
        .get(&root_id)
        .ok_or(ThreeWayPatchError::MissingParent { id: root_id })?;
    if root.parent.is_some() {
        return Err(ThreeWayPatchError::RootLineageMismatch);
    }
    for id in groups.keys().copied() {
        let mut current = id;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return Err(ThreeWayPatchError::GroupCycle { id: current });
            }
            let group = groups
                .get(&current)
                .ok_or(ThreeWayPatchError::MissingParent { id: current })?;
            match group.parent {
                Some(parent) => current = parent,
                None if current == root_id => break,
                None => return Err(ThreeWayPatchError::MissingParent { id }),
            }
        }
    }
    Ok(())
}

fn flatten_vault(vault: &Vault, side: &'static str) -> Result<FlatVault, ThreeWayPatchError> {
    let mut flat = FlatVault {
        root_id: vault.root.id,
        entries: BTreeMap::new(),
        groups: BTreeMap::new(),
    };
    flatten_group(&vault.root, None, 0, side, &mut flat)?;
    Ok(flat)
}

fn flatten_group(
    group: &Group,
    parent: Option<Uuid>,
    order: usize,
    side: &'static str,
    flat: &mut FlatVault,
) -> Result<(), ThreeWayPatchError> {
    let mut shell = group.clone();
    shell.entries.clear();
    shell.children.clear();
    if flat
        .groups
        .insert(
            group.id,
            FlatGroup {
                value: shell,
                parent,
                order,
            },
        )
        .is_some()
    {
        return Err(ThreeWayPatchError::DuplicateGroup { side, id: group.id });
    }
    for (entry_order, entry) in group.entries.iter().enumerate() {
        if flat
            .entries
            .insert(
                entry.id,
                FlatEntry {
                    value: entry.clone(),
                    parent: group.id,
                    order: entry_order,
                },
            )
            .is_some()
        {
            return Err(ThreeWayPatchError::DuplicateEntry { side, id: entry.id });
        }
    }
    for (child_order, child) in group.children.iter().enumerate() {
        flatten_group(child, Some(group.id), child_order, side, flat)?;
    }
    Ok(())
}

fn merge_entries(
    base: &FlatVault,
    local: &FlatVault,
    remote: &FlatVault,
    groups: &BTreeMap<Uuid, FlatGroup>,
    report: &mut ThreeWayPatchReport,
) -> Result<BTreeMap<Uuid, FlatEntry>, ThreeWayPatchError> {
    let ids = union_keys3(&base.entries, &local.entries, &remote.entries);
    let mut merged = BTreeMap::new();
    for id in ids {
        let base_entry = base.entries.get(&id);
        let local_entry = local.entries.get(&id);
        let remote_entry = remote.entries.get(&id);
        let result = match (base_entry, local_entry, remote_entry) {
            (None, None, Some(remote)) => Some(remote.clone()),
            (None, Some(local), None) => Some(local.clone()),
            (None, Some(local), Some(remote)) => {
                if same_entry_record(local, remote) {
                    Some(remote.clone())
                } else {
                    return Err(ThreeWayPatchError::ConcurrentObjectAddition { id });
                }
            }
            (Some(_), None, None) => None,
            (Some(base), Some(local), None) => {
                (!same_entry_record(base, local)).then(|| local.clone())
            }
            (Some(base), None, Some(remote)) => {
                (!same_entry_record(base, remote)).then(|| remote.clone())
            }
            (Some(base), Some(local), Some(remote)) => {
                let (value, changed) =
                    merge_entry(&base.value, &local.value, &remote.value, report);
                let (parent, location_changed_at, location_conflict) = merge_location(
                    base.parent,
                    local.parent,
                    remote.parent,
                    local.value.location_changed_at,
                    remote.value.location_changed_at,
                );
                let mut value = value;
                value.location_changed_at = location_changed_at;
                if location_conflict {
                    let local_wins = local.value.location_changed_at.unwrap_or(0)
                        > remote.value.location_changed_at.unwrap_or(0);
                    add_losing_history_snapshot(
                        &mut value,
                        if local_wins {
                            &remote.value
                        } else {
                            &local.value
                        },
                        report,
                    );
                }
                if changed || parent != remote.parent || value != remote.value {
                    report.merged_entries += 1;
                }
                Some(FlatEntry {
                    value,
                    parent,
                    order: remote.order,
                })
            }
            (None, None, None) => unreachable!(),
        };
        if let Some(entry) = result {
            if !groups.contains_key(&entry.parent) {
                return Err(ThreeWayPatchError::MissingParent { id: entry.parent });
            }
            merged.insert(id, entry);
        }
    }
    Ok(merged)
}

fn merge_groups(
    base: &FlatVault,
    local: &FlatVault,
    remote: &FlatVault,
    report: &mut ThreeWayPatchReport,
) -> Result<BTreeMap<Uuid, FlatGroup>, ThreeWayPatchError> {
    let ids = union_keys3(&base.groups, &local.groups, &remote.groups);
    let mut merged = BTreeMap::new();
    for id in ids {
        let base_group = base.groups.get(&id);
        let local_group = local.groups.get(&id);
        let remote_group = remote.groups.get(&id);
        let result = match (base_group, local_group, remote_group) {
            (None, None, Some(remote)) => Some(remote.clone()),
            (None, Some(local), None) => Some(local.clone()),
            (None, Some(_), Some(remote_group)) => {
                if subtrees_equal(local, remote, id) {
                    Some(remote_group.clone())
                } else {
                    return Err(ThreeWayPatchError::ConcurrentObjectAddition { id });
                }
            }
            (Some(_), None, None) => None,
            (Some(_), Some(local_group), None) => {
                subtree_changed(base, local, id).then(|| local_group.clone())
            }
            (Some(_), None, Some(remote_group)) => {
                subtree_changed(base, remote, id).then(|| remote_group.clone())
            }
            (Some(base_group), Some(local_group), Some(remote_group)) => {
                let local_timestamp = group_modified_at(&local_group.value);
                let remote_timestamp = group_modified_at(&remote_group.value);
                let (mut value, changed) = merge_group_fields(
                    &base_group.value,
                    &local_group.value,
                    &remote_group.value,
                    local_timestamp > remote_timestamp,
                );
                let (parent, location_changed_at, _) =
                    match (base_group.parent, local_group.parent, remote_group.parent) {
                        (None, None, None) => (None, group_location_changed_at(&value), false),
                        (Some(base_parent), Some(local_parent), Some(remote_parent)) => {
                            let (parent, changed_at, conflict) = merge_location(
                                base_parent,
                                local_parent,
                                remote_parent,
                                group_location_changed_at(&local_group.value),
                                group_location_changed_at(&remote_group.value),
                            );
                            (Some(parent), changed_at, conflict)
                        }
                        _ => return Err(ThreeWayPatchError::RootLineageMismatch),
                    };
                set_group_location_changed_at(&mut value, location_changed_at);
                if changed || parent != remote_group.parent || value != remote_group.value {
                    report.merged_groups += 1;
                }
                Some(FlatGroup {
                    value,
                    parent,
                    order: remote_group.order,
                })
            }
            (None, None, None) => unreachable!(),
        };
        if let Some(group) = result {
            merged.insert(id, group);
        }
    }

    for (id, group) in &merged {
        if let Some(parent) = group.parent
            && !merged.contains_key(&parent)
        {
            return Err(ThreeWayPatchError::MissingParent { id: *id });
        }
    }
    Ok(merged)
}

fn merge_entry(
    base: &Entry,
    local: &Entry,
    remote: &Entry,
    report: &mut ThreeWayPatchReport,
) -> (Entry, bool) {
    let prefer_local = local.modified_at > remote.modified_at;
    let mut state = FieldMerge::default();
    let mut merged = remote.clone();

    macro_rules! field {
        ($name:ident) => {
            merged.$name = merge_value(
                &base.$name,
                &local.$name,
                &remote.$name,
                prefer_local,
                &mut state,
            );
        };
    }
    field!(title);
    field!(username);
    field!(password);
    field!(url);
    field!(notes);
    field!(field_protection);
    field!(tags);
    field!(foreground_color);
    field!(background_color);
    field!(override_url);
    field!(created_at);
    field!(expires);
    field!(expiry_time);
    field!(last_accessed_at);
    field!(usage_count);
    field!(auto_type);
    field!(previous_parent);
    field!(exclude_from_reports);
    field!(raw_state);
    field!(opaque_xml);
    field!(custom_data_blocks);

    let (icon_id, custom_icon_id) = merge_value(
        &(base.icon_id, base.custom_icon_id),
        &(local.icon_id, local.custom_icon_id),
        &(remote.icon_id, remote.custom_icon_id),
        prefer_local,
        &mut state,
    );
    merged.icon_id = icon_id;
    merged.custom_icon_id = custom_icon_id;

    let mut attributes = merge_keyed_map_filtered(
        &base.attributes,
        &local.attributes,
        &remote.attributes,
        prefer_local,
        &mut state,
        |key| !is_reserved_credential_attribute(key),
    );
    let totp = merge_value(
        &totp_unit(base),
        &totp_unit(local),
        &totp_unit(remote),
        prefer_local,
        &mut state,
    );
    attributes.extend(totp.attributes.clone());
    merged.totp = totp.projected;
    let passkey = merge_value(
        &passkey_unit(base),
        &passkey_unit(local),
        &passkey_unit(remote),
        prefer_local,
        &mut state,
    );
    attributes.extend(passkey.attributes.clone());
    merged.passkey = passkey.projected;
    merged.attributes = attributes;

    merged.attachments = attachment_map(merge_keyed_map_filtered(
        &base.attachments,
        &local.attachments,
        &remote.attachments,
        prefer_local,
        &mut state,
        |_| true,
    ));
    merged.custom_data = merge_keyed_map_filtered(
        &base.custom_data,
        &local.custom_data,
        &remote.custom_data,
        prefer_local,
        &mut state,
        |_| true,
    );
    reconcile_custom_data_blocks(
        &mut merged.custom_data_blocks,
        &mut merged.opaque_xml,
        &mut merged.raw_state.node_order,
        &merged.custom_data,
        None,
    );

    merged.history = history_union(&base.history, &local.history, &remote.history);
    merged.modified_at = local.modified_at.max(remote.modified_at);
    if state.conflict {
        add_losing_history_snapshot(
            &mut merged,
            if prefer_local { remote } else { local },
            report,
        );
    }
    normalize_entry_slots(&mut merged);
    (merged, state.changed_from_remote || state.conflict)
}

fn merge_group_fields(
    base: &Group,
    local: &Group,
    remote: &Group,
    prefer_local: bool,
) -> (Group, bool) {
    let mut state = FieldMerge::default();
    let mut merged = remote.clone();
    merged.entries.clear();
    merged.children.clear();
    macro_rules! field {
        ($name:ident) => {
            merged.$name = merge_value(
                &base.$name,
                &local.$name,
                &remote.$name,
                prefer_local,
                &mut state,
            );
        };
    }
    field!(title);
    field!(notes);
    field!(tags);
    field!(times);
    field!(flags);
    field!(default_auto_type_sequence);
    field!(last_top_visible_entry);
    field!(previous_parent);
    field!(raw_state);
    field!(opaque_xml);
    field!(custom_data_blocks);
    let (icon_id, custom_icon_id) = merge_value(
        &(base.icon_id, base.custom_icon_id),
        &(local.icon_id, local.custom_icon_id),
        &(remote.icon_id, remote.custom_icon_id),
        prefer_local,
        &mut state,
    );
    merged.icon_id = icon_id;
    merged.custom_icon_id = custom_icon_id;
    merged.custom_data = merge_keyed_map_filtered(
        &base.custom_data,
        &local.custom_data,
        &remote.custom_data,
        prefer_local,
        &mut state,
        |_| true,
    );
    reconcile_custom_data_blocks(
        &mut merged.custom_data_blocks,
        &mut merged.opaque_xml,
        &mut merged.raw_state.node_order,
        &merged.custom_data,
        None,
    );
    (merged, state.changed_from_remote || state.conflict)
}

fn merge_meta(
    base: &Vault,
    local: &Vault,
    remote: &Vault,
    report: &mut ThreeWayPatchReport,
) -> Vault {
    let prefer_local = local.settings_changed.unwrap_or(0) > remote.settings_changed.unwrap_or(0);
    let mut state = FieldMerge::default();
    let mut merged = remote.clone();

    macro_rules! field {
        ($name:ident) => {
            merged.$name = merge_value(
                &base.$name,
                &local.$name,
                &remote.$name,
                prefer_local,
                &mut state,
            );
        };
    }
    let (name, name_changed) = merge_value(
        &(base.name.clone(), base.database_name_changed),
        &(local.name.clone(), local.database_name_changed),
        &(remote.name.clone(), remote.database_name_changed),
        local.database_name_changed.unwrap_or(0) > remote.database_name_changed.unwrap_or(0),
        &mut state,
    );
    merged.name = name;
    merged.database_name_changed = name_changed;
    let (description, description_changed) = merge_value(
        &(base.description.clone(), base.description_changed),
        &(local.description.clone(), local.description_changed),
        &(remote.description.clone(), remote.description_changed),
        local.description_changed.unwrap_or(0) > remote.description_changed.unwrap_or(0),
        &mut state,
    );
    merged.description = description;
    merged.description_changed = description_changed;
    let (default_username, default_username_changed) = merge_value(
        &(base.default_username.clone(), base.default_username_changed),
        &(
            local.default_username.clone(),
            local.default_username_changed,
        ),
        &(
            remote.default_username.clone(),
            remote.default_username_changed,
        ),
        local.default_username_changed.unwrap_or(0) > remote.default_username_changed.unwrap_or(0),
        &mut state,
    );
    merged.default_username = default_username;
    merged.default_username_changed = default_username_changed;

    field!(generator);
    field!(settings_changed);
    field!(meta_raw_state);
    field!(root_raw_state);
    field!(public_custom_data);
    field!(maintenance_history_days);
    field!(color);
    field!(master_key_changed);
    field!(master_key_change_rec);
    field!(master_key_change_force);
    field!(master_key_change_force_once);
    field!(history_max_items);
    field!(history_max_size);
    field!(last_selected_group);
    field!(last_top_visible_group);
    field!(memory_protection);
    field!(recycle_bin_enabled);
    field!(recycle_bin_group);
    field!(recycle_bin_changed);
    field!(entry_templates_group);
    field!(entry_templates_group_changed);
    field!(meta_opaque_xml);
    field!(root_opaque_xml);
    field!(meta_custom_data_blocks);
    // The remote KDF header is the generation being rebased onto.
    merged.kdf_parameters = remote.kdf_parameters.clone();

    merged.meta_custom_data = merge_keyed_map_filtered(
        &base.meta_custom_data,
        &local.meta_custom_data,
        &remote.meta_custom_data,
        prefer_local,
        &mut state,
        |_| true,
    );
    reconcile_custom_data_blocks(
        &mut merged.meta_custom_data_blocks,
        &mut merged.meta_opaque_xml,
        &mut merged.meta_raw_state.node_order,
        &merged.meta_custom_data,
        None,
    );
    merged.deleted_objects = merge_deleted_objects(
        &base.deleted_objects,
        &local.deleted_objects,
        &remote.deleted_objects,
    );
    let (icons, icon_conflicts) = merge_custom_icons(
        &base.custom_icons,
        &local.custom_icons,
        &remote.custom_icons,
    );
    merged.custom_icons = icons;
    report.icon_conflicts_resolved += icon_conflicts;
    if state.conflict {
        report.meta_conflicts_resolved += 1;
    }
    merged
}

fn merge_value<T: Clone + Eq>(
    base: &T,
    local: &T,
    remote: &T,
    prefer_local: bool,
    state: &mut FieldMerge,
) -> T {
    let selected = if local == base {
        remote
    } else if remote == base {
        local
    } else if local == remote {
        remote
    } else {
        state.conflict = true;
        if prefer_local { local } else { remote }
    };
    if selected != remote {
        state.changed_from_remote = true;
    }
    selected.clone()
}

fn merge_keyed_map_filtered<K, V, F>(
    base: &BTreeMap<K, V>,
    local: &BTreeMap<K, V>,
    remote: &BTreeMap<K, V>,
    prefer_local: bool,
    state: &mut FieldMerge,
    include: F,
) -> BTreeMap<K, V>
where
    K: Clone + Ord,
    V: Clone + Eq,
    F: Fn(&K) -> bool,
{
    let keys = union_keys3(base, local, remote);
    let mut merged = BTreeMap::new();
    for key in keys {
        if !include(&key) {
            continue;
        }
        let value = merge_value(
            &base.get(&key).cloned(),
            &local.get(&key).cloned(),
            &remote.get(&key).cloned(),
            prefer_local,
            state,
        );
        if let Some(value) = value {
            merged.insert(key, value);
        }
    }
    merged
}

fn union_keys3<K: Clone + Ord, V>(
    first: &BTreeMap<K, V>,
    second: &BTreeMap<K, V>,
    third: &BTreeMap<K, V>,
) -> BTreeSet<K> {
    first
        .keys()
        .chain(second.keys())
        .chain(third.keys())
        .cloned()
        .collect()
}

fn merge_location(
    base: Uuid,
    local: Uuid,
    remote: Uuid,
    local_changed_at: Option<u64>,
    remote_changed_at: Option<u64>,
) -> (Uuid, Option<u64>, bool) {
    if local == base {
        return (remote, remote_changed_at, false);
    }
    if remote == base {
        return (local, local_changed_at, false);
    }
    if local == remote {
        return (
            remote,
            Some(
                local_changed_at
                    .unwrap_or(0)
                    .max(remote_changed_at.unwrap_or(0)),
            ),
            false,
        );
    }
    if local_changed_at.unwrap_or(0) > remote_changed_at.unwrap_or(0) {
        (local, local_changed_at, true)
    } else {
        (remote, remote_changed_at, true)
    }
}

fn same_entry_record(left: &FlatEntry, right: &FlatEntry) -> bool {
    left.parent == right.parent && left.value == right.value
}

fn same_group_record(left: &FlatGroup, right: &FlatGroup) -> bool {
    left.parent == right.parent && left.value == right.value
}

fn subtree_changed(base: &FlatVault, side: &FlatVault, root: Uuid) -> bool {
    let Some(base_root) = base.groups.get(&root) else {
        return true;
    };
    if side
        .groups
        .get(&root)
        .is_none_or(|group| !same_group_record(base_root, group))
    {
        return true;
    }
    for (id, group) in &base.groups {
        if *id != root
            && group_is_below(base, *id, root)
            && side
                .groups
                .get(id)
                .is_none_or(|candidate| !same_group_record(group, candidate))
        {
            return true;
        }
    }
    for (id, entry) in &base.entries {
        if group_is_below_or_same(base, entry.parent, root)
            && side
                .entries
                .get(id)
                .is_none_or(|candidate| !same_entry_record(entry, candidate))
        {
            return true;
        }
    }
    side.groups
        .iter()
        .any(|(id, _)| !base.groups.contains_key(id) && group_is_below_or_same(side, *id, root))
        || side.entries.iter().any(|(id, entry)| {
            !base.entries.contains_key(id) && group_is_below_or_same(side, entry.parent, root)
        })
}

fn subtrees_equal(left: &FlatVault, right: &FlatVault, root: Uuid) -> bool {
    let left_groups = left
        .groups
        .iter()
        .filter(|(id, _)| group_is_below_or_same(left, **id, root))
        .map(|(id, group)| (*id, group.parent, &group.value))
        .collect::<Vec<_>>();
    let right_groups = right
        .groups
        .iter()
        .filter(|(id, _)| group_is_below_or_same(right, **id, root))
        .map(|(id, group)| (*id, group.parent, &group.value))
        .collect::<Vec<_>>();
    let left_entries = left
        .entries
        .iter()
        .filter(|(_, entry)| group_is_below_or_same(left, entry.parent, root))
        .map(|(id, entry)| (*id, entry.parent, &entry.value))
        .collect::<Vec<_>>();
    let right_entries = right
        .entries
        .iter()
        .filter(|(_, entry)| group_is_below_or_same(right, entry.parent, root))
        .map(|(id, entry)| (*id, entry.parent, &entry.value))
        .collect::<Vec<_>>();
    left_groups == right_groups && left_entries == right_entries
}

fn group_is_below(flat: &FlatVault, candidate: Uuid, ancestor: Uuid) -> bool {
    candidate != ancestor && group_is_below_or_same(flat, candidate, ancestor)
}

fn group_is_below_or_same(flat: &FlatVault, mut candidate: Uuid, ancestor: Uuid) -> bool {
    let mut visited = BTreeSet::new();
    loop {
        if candidate == ancestor {
            return true;
        }
        if !visited.insert(candidate) {
            return false;
        }
        let Some(parent) = flat.groups.get(&candidate).and_then(|group| group.parent) else {
            return false;
        };
        candidate = parent;
    }
}

fn rebuild_tree(
    id: Uuid,
    groups: &BTreeMap<Uuid, FlatGroup>,
    entries: &BTreeMap<Uuid, FlatEntry>,
    visiting: &mut BTreeSet<Uuid>,
) -> Result<Group, ThreeWayPatchError> {
    if !visiting.insert(id) {
        return Err(ThreeWayPatchError::GroupCycle { id });
    }
    let record = groups
        .get(&id)
        .ok_or(ThreeWayPatchError::MissingParent { id })?;
    let mut group = record.value.clone();
    let mut child_ids = groups
        .iter()
        .filter_map(|(child_id, child)| (child.parent == Some(id)).then_some(*child_id))
        .collect::<Vec<_>>();
    child_ids.sort_by_key(|child_id| {
        let child = &groups[child_id];
        (child.order, *child_id)
    });
    group.children = child_ids
        .into_iter()
        .map(|child_id| rebuild_tree(child_id, groups, entries, visiting))
        .collect::<Result<Vec<_>, _>>()?;
    let mut entry_ids = entries
        .iter()
        .filter_map(|(entry_id, entry)| (entry.parent == id).then_some(*entry_id))
        .collect::<Vec<_>>();
    entry_ids.sort_by_key(|entry_id| {
        let entry = &entries[entry_id];
        (entry.order, *entry_id)
    });
    group.entries = entry_ids
        .into_iter()
        .map(|entry_id| entries[&entry_id].value.clone())
        .collect();
    normalize_group_slots(&mut group);
    visiting.remove(&id);
    Ok(group)
}

fn history_union(base: &[Entry], local: &[Entry], remote: &[Entry]) -> Vec<Entry> {
    let mut merged = remote.to_vec();
    for entry in base.iter().chain(local) {
        if !merged.contains(entry) {
            merged.push(entry.clone());
        }
    }
    merged
}

fn add_losing_history_snapshot(
    merged: &mut Entry,
    losing: &Entry,
    report: &mut ThreeWayPatchReport,
) {
    let mut snapshot = losing.clone();
    prepare_entry_history_snapshot(&mut snapshot);
    if !merged.history.contains(&snapshot) {
        merged.history.push(snapshot);
        report.history_snapshots_added += 1;
    }
}

fn totp_unit(entry: &Entry) -> TotpUnit {
    TotpUnit {
        projected: entry.totp.clone(),
        attributes: entry
            .attributes
            .iter()
            .filter(|(key, _)| is_totp_persistent_attribute_key(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn passkey_unit(entry: &Entry) -> PasskeyUnit {
    PasskeyUnit {
        projected: entry.passkey.clone(),
        attributes: entry
            .attributes
            .iter()
            .filter(|(key, _)| PasskeyRecord::is_persistent_attribute_key(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn is_reserved_credential_attribute(key: &str) -> bool {
    is_totp_persistent_attribute_key(key) || PasskeyRecord::is_persistent_attribute_key(key)
}

fn attachment_map(values: BTreeMap<String, Attachment>) -> AttachmentMap {
    let mut attachments = AttachmentMap::default();
    for (name, attachment) in values {
        attachments.insert(name, attachment);
    }
    attachments
}

fn merge_deleted_objects(
    base: &[DeletedObject],
    local: &[DeletedObject],
    remote: &[DeletedObject],
) -> Vec<DeletedObject> {
    let map = |items: &[DeletedObject]| {
        items
            .iter()
            .map(|item| (item.id, item.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let base = map(base);
    let local = map(local);
    let remote = map(remote);
    let mut state = FieldMerge::default();
    let mut merged = Vec::new();
    for id in union_keys3(&base, &local, &remote) {
        let local_value = local.get(&id).cloned();
        let remote_value = remote.get(&id).cloned();
        let prefer_local = local_value
            .as_ref()
            .map(|item| item.deleted_at)
            .unwrap_or(i64::MIN)
            > remote_value
                .as_ref()
                .map(|item| item.deleted_at)
                .unwrap_or(i64::MIN);
        if let Some(value) = merge_value(
            &base.get(&id).cloned(),
            &local_value,
            &remote_value,
            prefer_local,
            &mut state,
        ) {
            merged.push(value);
        }
    }
    merged
}

fn merge_custom_icons(
    base: &[CustomIcon],
    local: &[CustomIcon],
    remote: &[CustomIcon],
) -> (Vec<CustomIcon>, u32) {
    let map = |items: &[CustomIcon]| {
        items
            .iter()
            .map(|item| (item.id, item.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let base = map(base);
    let local = map(local);
    let remote = map(remote);
    let mut merged = Vec::new();
    let mut conflicts = 0;
    for id in union_keys3(&base, &local, &remote) {
        let mut state = FieldMerge::default();
        let local_value = local.get(&id).cloned();
        let remote_value = remote.get(&id).cloned();
        let prefer_local = local_value
            .as_ref()
            .and_then(|item| item.last_modified)
            .unwrap_or(i64::MIN)
            > remote_value
                .as_ref()
                .and_then(|item| item.last_modified)
                .unwrap_or(i64::MIN);
        if let Some(value) = merge_value(
            &base.get(&id).cloned(),
            &local_value,
            &remote_value,
            prefer_local,
            &mut state,
        ) {
            merged.push(value);
        }
        conflicts += u32::from(state.conflict);
    }
    (merged, conflicts)
}

fn group_modified_at(group: &Group) -> u64 {
    group.times.map(|times| times.modified_at).unwrap_or(0)
}

fn group_location_changed_at(group: &Group) -> Option<u64> {
    group.times.and_then(|times| times.location_changed_at)
}

fn set_group_location_changed_at(group: &mut Group, value: Option<u64>) {
    if let Some(times) = group.times.as_mut() {
        times.location_changed_at = value;
    }
}

fn normalize_entry_slots(entry: &mut Entry) {
    let mut string_keys = BTreeSet::from([
        "Title".to_owned(),
        "UserName".to_owned(),
        "Password".to_owned(),
        "URL".to_owned(),
        "Notes".to_owned(),
    ]);
    string_keys.extend(
        materialize_entry_persistent_attributes(entry)
            .iter()
            .map(|(key, _)| key.to_owned()),
    );
    retain_tracked_slots(
        "String",
        &mut entry.raw_state.node_order,
        &mut entry.raw_state.string_order,
        &string_keys,
        &mut entry.opaque_xml,
        &mut entry.custom_data_blocks,
    );
    let binary_names = entry.attachments.keys().cloned().collect::<BTreeSet<_>>();
    retain_tracked_slots(
        "Binary",
        &mut entry.raw_state.node_order,
        &mut entry.raw_state.binary_order,
        &binary_names,
        &mut entry.opaque_xml,
        &mut entry.custom_data_blocks,
    );
}

fn normalize_group_slots(group: &mut Group) {
    let entry_ids = group.entries.iter().map(|entry| entry.id).collect();
    retain_tracked_slots(
        "Entry",
        &mut group.raw_state.node_order,
        &mut group.raw_state.entry_order,
        &entry_ids,
        &mut group.opaque_xml,
        &mut group.custom_data_blocks,
    );
    let group_ids = group.children.iter().map(|child| child.id).collect();
    retain_tracked_slots(
        "Group",
        &mut group.raw_state.node_order,
        &mut group.raw_state.group_order,
        &group_ids,
        &mut group.opaque_xml,
        &mut group.custom_data_blocks,
    );
}

fn retain_tracked_slots<T: Clone + Ord>(
    element: &str,
    node_order: &mut Vec<String>,
    tracked: &mut Vec<T>,
    current: &BTreeSet<T>,
    opaque_xml: &mut [OpaqueXmlFragment],
    custom_data_blocks: &mut [CustomDataBlock],
) {
    let original_nodes = std::mem::take(node_order);
    let original_tracked = std::mem::take(tracked);
    let mut replacements = Vec::new();
    let mut retained = BTreeSet::new();
    let mut counts = BTreeMap::<String, usize>::new();
    let mut last_anchor = None;
    let mut slot = 0;
    for name in original_nodes {
        if name == element {
            let identity = original_tracked.get(slot);
            slot += 1;
            if let Some(identity) = identity
                && current.contains(identity)
                && retained.insert(identity.clone())
            {
                node_order.push(name.clone());
                tracked.push(identity.clone());
                let occurrence = counts.entry(name.clone()).or_insert(0);
                *occurrence += 1;
                last_anchor = Some(OpaqueXmlAnchor {
                    element_name: name,
                    occurrence: *occurrence,
                });
            }
            replacements.push(last_anchor.clone());
            continue;
        }
        node_order.push(name.clone());
        let occurrence = counts.entry(name.clone()).or_insert(0);
        *occurrence += 1;
        last_anchor = Some(OpaqueXmlAnchor {
            element_name: name,
            occurrence: *occurrence,
        });
    }
    for anchor in opaque_xml
        .iter_mut()
        .map(|fragment| &mut fragment.after)
        .chain(custom_data_blocks.iter_mut().map(|block| &mut block.after))
    {
        let Some(existing) = anchor.as_ref() else {
            continue;
        };
        if existing.element_name == element {
            *anchor = existing
                .occurrence
                .checked_sub(1)
                .and_then(|index| replacements.get(index).cloned())
                .flatten();
        }
    }
}

fn normalize_group_attachment_content(group: &mut Group) {
    let mut pool = crate::AttachmentContentPool::new();
    fn normalize(group: &mut Group, pool: &mut crate::AttachmentContentPool) {
        for entry in &mut group.entries {
            normalize_entry_attachment_content(entry, pool);
        }
        for child in &mut group.children {
            normalize(child, pool);
        }
    }
    normalize(group, &mut pool);
}

fn normalize_entry_attachment_content(entry: &mut Entry, pool: &mut crate::AttachmentContentPool) {
    for attachment in entry.attachments.values_mut() {
        if let Ok(content) = pool.intern_content(&attachment.data) {
            attachment.data = content;
        }
    }
    for history in &mut entry.history {
        normalize_entry_attachment_content(history, pool);
    }
}
