use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use vaultkern_core::{
    CustomField, Entry, EntryCreate, Group, KeepassCore, MutationError, TotpAlgorithm, TotpSpec,
    Vault,
};
use vaultkern_runtime_protocol::{
    AutofillPersistConflictCodeDto, AutofillPersistPlanDto, EntryFieldsDto,
};

pub(crate) const AUTOFILL_RECEIPT_KEY: &str = "io.vaultkern.autofill.persist.receipts.v1";
const PLAN_DIGEST_DOMAIN: &str = "vaultkern-autofill-persist-v1";
const RECEIPT_VERSION: u32 = 1;
const MAX_RECEIPTS: usize = 64;
const RECEIPT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_LEDGER_BYTES: usize = 256 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_VAULT_ID_BYTES: usize = 4 * 1024;
const MAX_FIELD_BYTES: usize = 1024 * 1024;
const MAX_TOTP_URI_BYTES: usize = 8 * 1024;
const MAX_CUSTOM_KEY_BYTES: usize = 256;
const MAX_CUSTOM_FIELDS: usize = 128;
const MAX_MATCHING_IDS: usize = 4_096;
const MAX_PLAN_BYTES: usize = 8 * 1024 * 1024;
const RESERVED_CUSTOM_FIELD_KEYS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AutofillPersistEngineError {
    InvalidPlan(String),
    InvalidLedger(String),
    Conflict(AutofillPersistConflictCodeDto),
    MergeConflict(String),
    Mutation(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AutofillPersistLogicalOutcome {
    NeedsPublish { entry_id: String },
    Replayed { entry_id: String },
    ReplayedNeedsPublish { entry_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedAutofillPersist {
    pub(crate) candidate: Vault,
    pub(crate) outcome: AutofillPersistLogicalOutcome,
    pub(crate) plan_sha256: String,
}

pub(crate) struct AutofillPersistEngineInput<'a> {
    pub(crate) baseline_source: &'a Vault,
    pub(crate) base_loaded: &'a Vault,
    pub(crate) current_source: &'a Vault,
    pub(crate) transaction_id: &'a str,
    pub(crate) operation_id: &'a str,
    pub(crate) vault_id: &'a str,
    pub(crate) source_identity_sha256: &'a str,
    pub(crate) plan: &'a AutofillPersistPlanDto,
    pub(crate) now_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReceiptLedger {
    version: u32,
    receipts: Vec<AutofillReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AutofillReceipt {
    operation_id: String,
    transaction_id: String,
    source_identity_sha256: String,
    plan_sha256: String,
    mode: ReceiptMode,
    entry_id: String,
    committed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptMode {
    Update,
    Create,
}

#[derive(Debug, Clone)]
struct ValidatedFields {
    dto: EntryFieldsDto,
    custom_fields: BTreeMap<String, CustomField>,
    totp: Option<TotpSpec>,
}

#[derive(Debug, Clone)]
enum ValidatedPlan {
    Update {
        entry_id: String,
        expected_fields: ValidatedFields,
        desired_fields: ValidatedFields,
    },
    Create {
        parent_group_id: String,
        planned_entry_id: String,
        expected_matching_entry_ids: Vec<String>,
        desired_fields: ValidatedFields,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Located<T> {
    parent_id: Option<Uuid>,
    value: T,
}

#[derive(Debug, Clone)]
struct Indexed<T> {
    located: Located<T>,
    order: usize,
}

#[derive(Debug)]
struct VaultIndex {
    groups: BTreeMap<Uuid, Indexed<Group>>,
    entries: BTreeMap<Uuid, Indexed<Entry>>,
    deleted_objects: BTreeMap<Uuid, Indexed<vaultkern_core::DeletedObject>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostReceiptEntryState {
    located: Option<Located<Entry>>,
    recycled: bool,
    deleted_objects: Vec<vaultkern_core::DeletedObject>,
}

impl ValidatedPlan {
    fn from_dto(plan: &AutofillPersistPlanDto) -> Result<Self, AutofillPersistEngineError> {
        match plan {
            AutofillPersistPlanDto::Update {
                entry_id,
                expected_fields,
                desired_fields,
            } => {
                validate_canonical_uuid("entry_id", entry_id)?;
                let expected_fields = validate_fields("expected_fields", expected_fields)?;
                let desired_fields = validate_fields("desired_fields", desired_fields)?;
                validate_desired_fields("desired_fields", &desired_fields)?;
                if http_origin("expected_fields.url", &expected_fields.dto.url)?
                    != http_origin("desired_fields.url", &desired_fields.dto.url)?
                {
                    return invalid_plan("update URLs must have the same exact origin");
                }
                Ok(Self::Update {
                    entry_id: entry_id.clone(),
                    expected_fields,
                    desired_fields,
                })
            }
            AutofillPersistPlanDto::Create {
                parent_group_id,
                planned_entry_id,
                expected_matching_entry_ids,
                desired_fields,
            } => {
                validate_canonical_uuid("parent_group_id", parent_group_id)?;
                validate_canonical_uuid("planned_entry_id", planned_entry_id)?;
                if expected_matching_entry_ids.len() > MAX_MATCHING_IDS {
                    return invalid_plan("too many expected matching entry IDs");
                }
                let mut matching_ids = expected_matching_entry_ids.clone();
                for entry_id in &matching_ids {
                    validate_canonical_uuid("expected_matching_entry_id", entry_id)?;
                }
                matching_ids.sort();
                if matching_ids.windows(2).any(|pair| pair[0] == pair[1]) {
                    return invalid_plan("expected matching entry IDs must be unique");
                }
                let desired_fields = validate_fields("desired_fields", desired_fields)?;
                validate_desired_fields("desired_fields", &desired_fields)?;
                Ok(Self::Create {
                    parent_group_id: parent_group_id.clone(),
                    planned_entry_id: planned_entry_id.clone(),
                    expected_matching_entry_ids: matching_ids,
                    desired_fields,
                })
            }
        }
    }

    fn mode(&self) -> ReceiptMode {
        match self {
            Self::Update { .. } => ReceiptMode::Update,
            Self::Create { .. } => ReceiptMode::Create,
        }
    }

    fn entry_id(&self) -> &str {
        match self {
            Self::Update { entry_id, .. } => entry_id,
            Self::Create {
                planned_entry_id, ..
            } => planned_entry_id,
        }
    }
}

fn merge_autofill_candidate(
    baseline: &Vault,
    local: &Vault,
    current: &Vault,
) -> Result<Vault, AutofillPersistEngineError> {
    validate_vault_identifiers(baseline)?;
    validate_vault_identifiers(local)?;
    validate_vault_identifiers(current)?;
    if baseline.root.id != local.root.id || baseline.root.id != current.root.id {
        return merge_conflict("vault root identity changed");
    }
    if local == current {
        return Ok(local.clone());
    }
    if local == baseline {
        return Ok(current.clone());
    }
    if current == baseline {
        return Ok(local.clone());
    }
    let baseline_index = index_vault(baseline)?;
    let local_index = index_vault(local)?;
    let current_index = index_vault(current)?;
    let mut groups = merge_indexed_maps(
        &baseline_index.groups,
        &local_index.groups,
        &current_index.groups,
        "group",
    )?;
    let mut entries = merge_indexed_maps(
        &baseline_index.entries,
        &local_index.entries,
        &current_index.entries,
        "entry",
    )?;
    let deleted_objects = merge_indexed_maps(
        &baseline_index.deleted_objects,
        &local_index.deleted_objects,
        &current_index.deleted_objects,
        "deleted object",
    )?;

    if entries.keys().any(|id| groups.contains_key(id)) {
        return merge_conflict("entry and group UUID namespaces collide");
    }
    merge_sibling_orders(
        &baseline_index.groups,
        &local_index.groups,
        &current_index.groups,
        &mut groups,
        "group",
    )?;
    merge_sibling_orders(
        &baseline_index.entries,
        &local_index.entries,
        &current_index.entries,
        &mut entries,
        "entry",
    )?;

    let baseline_shell = vault_shell(baseline);
    let local_shell = vault_shell(local);
    let current_shell = vault_shell(current);
    let mut candidate = choose_three_way_value(
        &baseline_shell,
        &local_shell,
        &current_shell,
        "vault metadata",
    )?;
    candidate.meta_custom_data = merge_unknown_meta_custom_data(baseline, local, current)?;
    // Blocks are a serialization layout for the semantic map. Starting from
    // the durable source preserves its opaque layout when possible; the KDBX
    // writer canonicalizes it if the merged map no longer matches.
    candidate.meta_custom_data_blocks = current.meta_custom_data_blocks.clone();
    candidate.deleted_objects = deleted_objects
        .values()
        .map(|record| record.located.value.clone())
        .collect();
    candidate.deleted_objects.sort_by_key(|item| item.id);
    candidate.root = rebuild_group_tree(baseline.root.id, &groups, &entries)?;
    Ok(candidate)
}

fn validate_vault_identifiers(vault: &Vault) -> Result<(), AutofillPersistEngineError> {
    fn visit(
        group: &Group,
        groups: &mut BTreeSet<Uuid>,
        entries: &mut BTreeSet<Uuid>,
    ) -> Result<(), AutofillPersistEngineError> {
        if !groups.insert(group.id) {
            return merge_conflict(format!("duplicate group UUID {}", group.id));
        }
        for entry in &group.entries {
            if !entries.insert(entry.id) {
                return merge_conflict(format!("duplicate entry UUID {}", entry.id));
            }
        }
        for child in &group.children {
            visit(child, groups, entries)?;
        }
        Ok(())
    }

    let mut groups = BTreeSet::new();
    let mut entries = BTreeSet::new();
    visit(&vault.root, &mut groups, &mut entries)?;
    if entries.iter().any(|id| groups.contains(id)) {
        return merge_conflict("entry and group UUID namespaces collide");
    }
    let mut deleted = BTreeSet::new();
    for item in &vault.deleted_objects {
        if !deleted.insert(item.id) {
            return merge_conflict(format!("duplicate deleted-object UUID {}", item.id));
        }
    }
    Ok(())
}

fn vault_shell(vault: &Vault) -> Vault {
    let mut shell = vault.clone();
    let mut root = Group::new("");
    root.id = Uuid::nil();
    shell.root = root;
    shell.deleted_objects.clear();
    shell.meta_custom_data.clear();
    shell.meta_custom_data_blocks.clear();
    shell
}

fn index_vault(vault: &Vault) -> Result<VaultIndex, AutofillPersistEngineError> {
    fn visit_group(
        group: &Group,
        parent_id: Option<Uuid>,
        order: usize,
        groups: &mut BTreeMap<Uuid, Indexed<Group>>,
        entries: &mut BTreeMap<Uuid, Indexed<Entry>>,
    ) -> Result<(), AutofillPersistEngineError> {
        let mut shell = group.clone();
        shell.entries.clear();
        shell.children.clear();
        if groups
            .insert(
                group.id,
                Indexed {
                    located: Located {
                        parent_id,
                        value: shell,
                    },
                    order,
                },
            )
            .is_some()
        {
            return merge_conflict(format!("duplicate group UUID {}", group.id));
        }
        for (entry_order, entry) in group.entries.iter().enumerate() {
            if entries
                .insert(
                    entry.id,
                    Indexed {
                        located: Located {
                            parent_id: Some(group.id),
                            value: entry.clone(),
                        },
                        order: entry_order,
                    },
                )
                .is_some()
            {
                return merge_conflict(format!("duplicate entry UUID {}", entry.id));
            }
        }
        for (child_order, child) in group.children.iter().enumerate() {
            visit_group(child, Some(group.id), child_order, groups, entries)?;
        }
        Ok(())
    }

    let mut groups = BTreeMap::new();
    let mut entries = BTreeMap::new();
    visit_group(&vault.root, None, 0, &mut groups, &mut entries)?;
    let mut deleted_objects = BTreeMap::new();
    for (order, item) in vault.deleted_objects.iter().enumerate() {
        if deleted_objects
            .insert(
                item.id,
                Indexed {
                    located: Located {
                        parent_id: None,
                        value: item.clone(),
                    },
                    order,
                },
            )
            .is_some()
        {
            return merge_conflict(format!("duplicate deleted-object UUID {}", item.id));
        }
    }
    Ok(VaultIndex {
        groups,
        entries,
        deleted_objects,
    })
}

fn merge_indexed_maps<T: Clone + PartialEq + Eq>(
    baseline: &BTreeMap<Uuid, Indexed<T>>,
    local: &BTreeMap<Uuid, Indexed<T>>,
    current: &BTreeMap<Uuid, Indexed<T>>,
    kind: &str,
) -> Result<BTreeMap<Uuid, Indexed<T>>, AutofillPersistEngineError> {
    let ids = baseline
        .keys()
        .chain(local.keys())
        .chain(current.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut merged = BTreeMap::new();
    for id in ids {
        let baseline_record = baseline.get(&id);
        let local_record = local.get(&id);
        let current_record = current.get(&id);
        let baseline_state = baseline_record.map(|record| &record.located);
        let local_state = local_record.map(|record| &record.located);
        let current_state = current_record.map(|record| &record.located);
        let selected = if local_state == current_state {
            current_record.or(local_record)
        } else if local_state == baseline_state {
            current_record
        } else if current_state == baseline_state {
            local_record
        } else {
            return merge_conflict(format!("concurrent {kind} change for {id}"));
        };
        if let Some(selected) = selected {
            merged.insert(id, selected.clone());
        }
    }
    Ok(merged)
}

fn merge_sibling_orders<T>(
    baseline: &BTreeMap<Uuid, Indexed<T>>,
    local: &BTreeMap<Uuid, Indexed<T>>,
    current: &BTreeMap<Uuid, Indexed<T>>,
    merged: &mut BTreeMap<Uuid, Indexed<T>>,
    kind: &str,
) -> Result<(), AutofillPersistEngineError> {
    let mut final_siblings = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
    for (id, record) in merged.iter() {
        if let Some(parent_id) = record.located.parent_id {
            final_siblings.entry(parent_id).or_default().insert(*id);
        }
    }
    let baseline_sequences = sibling_sequences(baseline);
    let local_sequences = sibling_sequences(local);
    let current_sequences = sibling_sequences(current);

    for (parent_id, final_ids) in final_siblings {
        let baseline_order = filtered_sibling_sequence(&baseline_sequences, parent_id, &final_ids);
        let local_order = filtered_sibling_sequence(&local_sequences, parent_id, &final_ids);
        let current_order = filtered_sibling_sequence(&current_sequences, parent_id, &final_ids);
        let selected = choose_three_way_value(
            &baseline_order,
            &local_order,
            &current_order,
            &format!("{kind} sibling order under {parent_id}"),
        )?;
        let selected_ids = selected.iter().copied().collect::<BTreeSet<_>>();
        if selected.len() != final_ids.len() || selected_ids != final_ids {
            return merge_conflict(format!("incomplete {kind} sibling order under {parent_id}"));
        }
        for (order, id) in selected.into_iter().enumerate() {
            merged.get_mut(&id).expect("merged sibling").order = order;
        }
    }
    Ok(())
}

fn sibling_sequences<T>(index: &BTreeMap<Uuid, Indexed<T>>) -> BTreeMap<Uuid, Vec<Uuid>> {
    let mut records = BTreeMap::<Uuid, Vec<(usize, Uuid)>>::new();
    for (id, record) in index {
        if let Some(parent_id) = record.located.parent_id {
            records
                .entry(parent_id)
                .or_default()
                .push((record.order, *id));
        }
    }
    records
        .into_iter()
        .map(|(parent_id, mut siblings)| {
            siblings.sort_by_key(|(order, _)| *order);
            (parent_id, siblings.into_iter().map(|(_, id)| id).collect())
        })
        .collect()
}

fn filtered_sibling_sequence(
    sequences: &BTreeMap<Uuid, Vec<Uuid>>,
    parent_id: Uuid,
    final_ids: &BTreeSet<Uuid>,
) -> Vec<Uuid> {
    sequences
        .get(&parent_id)
        .into_iter()
        .flatten()
        .filter(|id| final_ids.contains(id))
        .copied()
        .collect()
}

fn reconcile_candidate_sibling_orders(
    baseline: &Vault,
    local: &Vault,
    current: &Vault,
    candidate: &mut Vault,
) -> Result<(), AutofillPersistEngineError> {
    #[derive(Default)]
    struct Orders {
        groups: BTreeMap<Uuid, Vec<Uuid>>,
        entries: BTreeMap<Uuid, Vec<Uuid>>,
    }

    fn collect(group: &Group, orders: &mut Orders) {
        orders.entries.insert(
            group.id,
            group.entries.iter().map(|entry| entry.id).collect(),
        );
        orders.groups.insert(
            group.id,
            group.children.iter().map(|child| child.id).collect(),
        );
        for child in &group.children {
            collect(child, orders);
        }
    }

    fn from_vault(vault: &Vault) -> Orders {
        let mut orders = Orders::default();
        collect(&vault.root, &mut orders);
        orders
    }

    fn select_orders(
        baseline: &BTreeMap<Uuid, Vec<Uuid>>,
        local: &BTreeMap<Uuid, Vec<Uuid>>,
        current: &BTreeMap<Uuid, Vec<Uuid>>,
        final_orders: &BTreeMap<Uuid, Vec<Uuid>>,
        kind: &str,
    ) -> Result<BTreeMap<Uuid, Vec<Uuid>>, AutofillPersistEngineError> {
        let mut selected_orders = BTreeMap::new();
        for (parent_id, final_order) in final_orders {
            let final_ids = final_order.iter().copied().collect::<BTreeSet<_>>();
            if final_ids.len() != final_order.len() {
                return merge_conflict(format!("duplicate {kind} sibling under {parent_id}"));
            }
            let baseline_order = filtered_sibling_sequence(baseline, *parent_id, &final_ids);
            let local_order = filtered_sibling_sequence(local, *parent_id, &final_ids);
            let current_order = filtered_sibling_sequence(current, *parent_id, &final_ids);
            let selected = choose_three_way_value(
                &baseline_order,
                &local_order,
                &current_order,
                &format!("{kind} sibling order under {parent_id}"),
            )?;
            let selected_ids = selected.iter().copied().collect::<BTreeSet<_>>();
            if selected.len() != final_ids.len() || selected_ids != final_ids {
                return merge_conflict(format!(
                    "incomplete {kind} sibling order under {parent_id}"
                ));
            }
            selected_orders.insert(*parent_id, selected);
        }
        Ok(selected_orders)
    }

    fn apply(
        group: &mut Group,
        group_orders: &BTreeMap<Uuid, Vec<Uuid>>,
        entry_orders: &BTreeMap<Uuid, Vec<Uuid>>,
    ) -> Result<(), AutofillPersistEngineError> {
        let entry_order = entry_orders.get(&group.id).ok_or_else(|| {
            AutofillPersistEngineError::MergeConflict(format!(
                "missing entry sibling order under {}",
                group.id
            ))
        })?;
        let mut entries = std::mem::take(&mut group.entries)
            .into_iter()
            .map(|entry| (entry.id, entry))
            .collect::<BTreeMap<_, _>>();
        if entries.len() != entry_order.len() {
            return merge_conflict(format!("incomplete entry sibling order under {}", group.id));
        }
        group.entries = entry_order
            .iter()
            .map(|id| {
                entries.remove(id).ok_or_else(|| {
                    AutofillPersistEngineError::MergeConflict(format!(
                        "missing entry sibling {id} under {}",
                        group.id
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let group_order = group_orders.get(&group.id).ok_or_else(|| {
            AutofillPersistEngineError::MergeConflict(format!(
                "missing group sibling order under {}",
                group.id
            ))
        })?;
        let mut children = std::mem::take(&mut group.children)
            .into_iter()
            .map(|child| (child.id, child))
            .collect::<BTreeMap<_, _>>();
        if children.len() != group_order.len() {
            return merge_conflict(format!("incomplete group sibling order under {}", group.id));
        }
        group.children = group_order
            .iter()
            .map(|id| {
                children.remove(id).ok_or_else(|| {
                    AutofillPersistEngineError::MergeConflict(format!(
                        "missing group sibling {id} under {}",
                        group.id
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for child in &mut group.children {
            apply(child, group_orders, entry_orders)?;
        }
        Ok(())
    }

    validate_vault_identifiers(candidate)?;
    let baseline_orders = from_vault(baseline);
    let local_orders = from_vault(local);
    let current_orders = from_vault(current);
    let final_orders = from_vault(candidate);
    let group_orders = select_orders(
        &baseline_orders.groups,
        &local_orders.groups,
        &current_orders.groups,
        &final_orders.groups,
        "group",
    )?;
    let entry_orders = select_orders(
        &baseline_orders.entries,
        &local_orders.entries,
        &current_orders.entries,
        &final_orders.entries,
        "entry",
    )?;
    apply(&mut candidate.root, &group_orders, &entry_orders)?;
    Ok(())
}

fn choose_three_way_value<T: Clone + PartialEq + Eq>(
    baseline: &T,
    local: &T,
    current: &T,
    kind: &str,
) -> Result<T, AutofillPersistEngineError> {
    if local == current {
        Ok(local.clone())
    } else if local == baseline {
        Ok(current.clone())
    } else if current == baseline {
        Ok(local.clone())
    } else {
        merge_conflict(format!("concurrent {kind} change"))
    }
}

fn merge_unknown_meta_custom_data(
    baseline: &Vault,
    local: &Vault,
    current: &Vault,
) -> Result<BTreeMap<String, String>, AutofillPersistEngineError> {
    let keys = baseline
        .meta_custom_data
        .keys()
        .chain(local.meta_custom_data.keys())
        .chain(current.meta_custom_data.keys())
        .filter(|key| key.as_str() != AUTOFILL_RECEIPT_KEY)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut merged = BTreeMap::new();
    for key in keys {
        let baseline_value = baseline.meta_custom_data.get(&key);
        let local_value = local.meta_custom_data.get(&key);
        let current_value = current.meta_custom_data.get(&key);
        let selected = if local_value == current_value {
            local_value
        } else if local_value == baseline_value {
            current_value
        } else if current_value == baseline_value {
            local_value
        } else {
            return merge_conflict(format!("concurrent meta custom-data change for {key}"));
        };
        if let Some(value) = selected {
            merged.insert(key, value.clone());
        }
    }
    Ok(merged)
}

fn rebuild_group_tree(
    root_id: Uuid,
    groups: &BTreeMap<Uuid, Indexed<Group>>,
    entries: &BTreeMap<Uuid, Indexed<Entry>>,
) -> Result<Group, AutofillPersistEngineError> {
    fn sort_siblings(
        records: &mut [(usize, Uuid)],
        kind: &str,
        parent_id: Uuid,
    ) -> Result<(), AutofillPersistEngineError> {
        records.sort_by_key(|(order, _)| *order);
        if records.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return merge_conflict(format!("duplicate {kind} sibling order under {parent_id}"));
        }
        Ok(())
    }

    let Some(root) = groups.get(&root_id) else {
        return merge_conflict("vault root was deleted");
    };
    if root.located.parent_id.is_some()
        || groups
            .iter()
            .any(|(id, record)| *id != root_id && record.located.parent_id.is_none())
    {
        return merge_conflict("group tree has multiple or relocated roots");
    }

    let mut children = BTreeMap::<Uuid, Vec<(usize, Uuid)>>::new();
    for (id, record) in groups {
        if *id == root_id {
            continue;
        }
        let Some(parent_id) = record.located.parent_id else {
            return merge_conflict(format!("group {id} has no parent"));
        };
        if !groups.contains_key(&parent_id) {
            return merge_conflict(format!("group {id} has missing parent {parent_id}"));
        }
        children
            .entry(parent_id)
            .or_default()
            .push((record.order, *id));
    }
    for (parent_id, records) in &mut children {
        sort_siblings(records, "group", *parent_id)?;
    }

    let mut entries_by_parent = BTreeMap::<Uuid, Vec<(usize, Uuid)>>::new();
    for (id, record) in entries {
        let Some(parent_id) = record.located.parent_id else {
            return merge_conflict(format!("entry {id} has no parent"));
        };
        if !groups.contains_key(&parent_id) {
            return merge_conflict(format!("entry {id} has missing parent {parent_id}"));
        }
        entries_by_parent
            .entry(parent_id)
            .or_default()
            .push((record.order, *id));
    }
    for (parent_id, records) in &mut entries_by_parent {
        sort_siblings(records, "entry", *parent_id)?;
    }

    fn build(
        id: Uuid,
        groups: &BTreeMap<Uuid, Indexed<Group>>,
        entries: &BTreeMap<Uuid, Indexed<Entry>>,
        children: &BTreeMap<Uuid, Vec<(usize, Uuid)>>,
        entries_by_parent: &BTreeMap<Uuid, Vec<(usize, Uuid)>>,
        visiting: &mut BTreeSet<Uuid>,
        visited: &mut BTreeSet<Uuid>,
    ) -> Result<Group, AutofillPersistEngineError> {
        if !visiting.insert(id) {
            return merge_conflict(format!("group cycle at {id}"));
        }
        let mut group = groups
            .get(&id)
            .ok_or_else(|| AutofillPersistEngineError::MergeConflict("missing group".into()))?
            .located
            .value
            .clone();
        group.entries = entries_by_parent
            .get(&id)
            .into_iter()
            .flatten()
            .map(|(_, entry_id)| {
                entries
                    .get(entry_id)
                    .expect("indexed entry")
                    .located
                    .value
                    .clone()
            })
            .collect();
        group.children = children
            .get(&id)
            .into_iter()
            .flatten()
            .map(|(_, child_id)| {
                build(
                    *child_id,
                    groups,
                    entries,
                    children,
                    entries_by_parent,
                    visiting,
                    visited,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        visiting.remove(&id);
        visited.insert(id);
        Ok(group)
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let root = build(
        root_id,
        groups,
        entries,
        &children,
        &entries_by_parent,
        &mut visiting,
        &mut visited,
    )?;
    if visited.len() != groups.len() {
        return merge_conflict("group tree contains an unreachable cycle");
    }
    Ok(root)
}

pub(crate) fn prepare_autofill_persist(
    input: AutofillPersistEngineInput<'_>,
) -> Result<PreparedAutofillPersist, AutofillPersistEngineError> {
    validate_token("transaction_id", input.transaction_id, MAX_REQUEST_ID_BYTES)?;
    validate_token("operation_id", input.operation_id, MAX_REQUEST_ID_BYTES)?;
    validate_token("vault_id", input.vault_id, MAX_VAULT_ID_BYTES)?;
    validate_sha256("source_identity_sha256", input.source_identity_sha256)
        .map_err(AutofillPersistEngineError::InvalidPlan)?;
    let plan = ValidatedPlan::from_dto(input.plan)?;
    let plan_sha256 = hash_validated_plan(
        input.transaction_id,
        input.vault_id,
        input.source_identity_sha256,
        &plan,
    );
    let intended_receipt = AutofillReceipt {
        operation_id: input.operation_id.into(),
        transaction_id: input.transaction_id.into(),
        source_identity_sha256: input.source_identity_sha256.into(),
        plan_sha256: plan_sha256.clone(),
        mode: plan.mode(),
        entry_id: plan.entry_id().into(),
        committed_at_epoch_ms: input.now_epoch_ms,
    };

    let base_receipts = dedupe_receipts(read_ledger(input.base_loaded)?.receipts)?;
    let current_receipts = dedupe_receipts(read_ledger(input.current_source)?.receipts)?;
    let base_operation_receipt = base_receipts.get(input.operation_id);
    let current_operation_receipt = current_receipts.get(input.operation_id);
    for existing in [base_operation_receipt, current_operation_receipt]
        .into_iter()
        .flatten()
    {
        if !same_receipt_binding(existing, &intended_receipt) {
            return conflict(AutofillPersistConflictCodeDto::OperationBindingMismatch);
        }
    }
    let base_has_operation_receipt = base_operation_receipt.is_some();
    let current_has_operation_receipt = current_operation_receipt.is_some();
    let mut merged_receipts = merge_receipt_maps(base_receipts, current_receipts)?;
    let core = KeepassCore::new();
    let mut candidate = merge_autofill_candidate(
        input.baseline_source,
        input.base_loaded,
        input.current_source,
    )?;

    if current_has_operation_receipt {
        if base_has_operation_receipt {
            reconcile_post_receipt_entry(
                &mut candidate,
                input.baseline_source,
                input.base_loaded,
                input.current_source,
                plan.entry_id(),
            )?;
        } else {
            force_entry_state_from_source(&mut candidate, input.current_source, plan.entry_id())?;
        }
        reconcile_candidate_sibling_orders(
            input.baseline_source,
            input.base_loaded,
            input.current_source,
            &mut candidate,
        )?;
        protect_target_xml_forbidden_fields(&mut candidate, plan.entry_id());
        write_pruned_ledger(
            &mut candidate,
            merged_receipts.into_values().collect(),
            input.operation_id,
            input.now_epoch_ms,
        )?;
        let outcome = if candidate == *input.current_source {
            AutofillPersistLogicalOutcome::Replayed {
                entry_id: plan.entry_id().into(),
            }
        } else {
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: plan.entry_id().into(),
            }
        };
        return Ok(PreparedAutofillPersist {
            candidate,
            outcome,
            plan_sha256,
        });
    }

    if base_has_operation_receipt {
        ensure_base_only_recovery_postcondition(input.current_source, &plan)?;
        force_entry_state_from_source(&mut candidate, input.base_loaded, plan.entry_id())?;
    } else {
        apply_idempotent_mutation(
            &core,
            &mut candidate,
            input.base_loaded,
            input.current_source,
            &plan,
            input.now_epoch_ms,
        )?;
    }
    if base_has_operation_receipt {
        reconcile_candidate_sibling_orders(
            input.baseline_source,
            input.base_loaded,
            input.current_source,
            &mut candidate,
        )?;
    }

    protect_target_xml_forbidden_fields(&mut candidate, plan.entry_id());
    insert_receipt(&mut merged_receipts, intended_receipt)?;
    write_pruned_ledger(
        &mut candidate,
        merged_receipts.into_values().collect(),
        input.operation_id,
        input.now_epoch_ms,
    )?;
    Ok(PreparedAutofillPersist {
        candidate,
        outcome: AutofillPersistLogicalOutcome::NeedsPublish {
            entry_id: plan.entry_id().into(),
        },
        plan_sha256,
    })
}

pub(crate) fn plan_sha256(
    transaction_id: &str,
    vault_id: &str,
    source_identity_sha256: &str,
    plan: &AutofillPersistPlanDto,
) -> Result<String, AutofillPersistEngineError> {
    validate_token("transaction_id", transaction_id, MAX_REQUEST_ID_BYTES)?;
    validate_token("vault_id", vault_id, MAX_VAULT_ID_BYTES)?;
    validate_sha256("source_identity_sha256", source_identity_sha256)
        .map_err(AutofillPersistEngineError::InvalidPlan)?;
    let plan = ValidatedPlan::from_dto(plan)?;
    Ok(hash_validated_plan(
        transaction_id,
        vault_id,
        source_identity_sha256,
        &plan,
    ))
}

fn validate_token(
    name: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), AutofillPersistEngineError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return invalid_plan(format!("invalid {name}"));
    }
    Ok(())
}

fn validate_canonical_uuid(name: &str, value: &str) -> Result<Uuid, AutofillPersistEngineError> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| AutofillPersistEngineError::InvalidPlan(format!("invalid {name}")))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return invalid_plan(format!("invalid {name}"));
    }
    Ok(parsed)
}

fn validate_sha256(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("invalid {name}"));
    }
    Ok(())
}

fn validate_fields(
    name: &str,
    fields: &EntryFieldsDto,
) -> Result<ValidatedFields, AutofillPersistEngineError> {
    let standard_fields = [
        ("title", &fields.title),
        ("username", &fields.username),
        ("password", &fields.password),
        ("url", &fields.url),
        ("notes", &fields.notes),
    ];
    let mut total_bytes = 0usize;
    for (field_name, value) in standard_fields {
        if value.len() > MAX_FIELD_BYTES {
            return invalid_plan(format!("{name}.{field_name} is too large"));
        }
        total_bytes = total_bytes.saturating_add(value.len());
    }
    let totp = match fields.totp_uri.as_deref() {
        None => None,
        Some(uri)
            if uri.is_empty()
                || uri.trim() != uri
                || uri.chars().any(char::is_control)
                || uri.len() > MAX_TOTP_URI_BYTES =>
        {
            return invalid_plan(format!("invalid {name}.totp_uri"));
        }
        Some(uri) => {
            let spec = TotpSpec::parse_otpauth(uri).map_err(|_| {
                AutofillPersistEngineError::InvalidPlan(format!("invalid {name}.totp_uri"))
            })?;
            if !valid_totp_spec(&spec) {
                return invalid_plan(format!("invalid {name}.totp_uri"));
            }
            Some(spec)
        }
    };
    total_bytes = total_bytes.saturating_add(
        fields
            .totp_uri
            .as_ref()
            .map(|value| value.len())
            .unwrap_or(0),
    );
    if fields.custom_fields.len() > MAX_CUSTOM_FIELDS {
        return invalid_plan(format!("too many {name}.custom_fields"));
    }
    let mut custom_fields = BTreeMap::new();
    for field in &fields.custom_fields {
        if field.key.is_empty()
            || field.key.trim() != field.key
            || field.key.len() > MAX_CUSTOM_KEY_BYTES
            || field.key.chars().any(char::is_control)
            || requires_xml_protection(&field.key)
            || RESERVED_CUSTOM_FIELD_KEYS
                .iter()
                .any(|reserved| field.key.eq_ignore_ascii_case(reserved))
            || field.value.len() > MAX_FIELD_BYTES
        {
            return invalid_plan(format!("invalid {name}.custom_fields"));
        }
        total_bytes = total_bytes
            .saturating_add(field.key.len())
            .saturating_add(field.value.len());
        if custom_fields
            .insert(
                field.key.clone(),
                CustomField {
                    value: field.value.clone(),
                    protected: effective_xml_field_protection(&field.value, field.protected),
                },
            )
            .is_some()
        {
            return invalid_plan(format!("duplicate {name}.custom_fields key"));
        }
    }
    if total_bytes > MAX_PLAN_BYTES {
        return invalid_plan(format!("{name} is too large"));
    }
    Ok(ValidatedFields {
        dto: fields.clone(),
        custom_fields,
        totp,
    })
}

fn valid_totp_spec(spec: &TotpSpec) -> bool {
    let mut saw_padding = false;
    if spec.secret_base32.is_empty()
        || !spec.secret_base32.chars().all(|character| {
            if character == '=' {
                saw_padding = true;
                true
            } else {
                !saw_padding && (character.is_ascii_alphabetic() || matches!(character, '2'..='7'))
            }
        })
        || !(1..=9).contains(&spec.digits)
        || spec.period_seconds == 0
    {
        return false;
    }
    spec.generate_at(0).is_ok()
}

fn requires_xml_protection(value: &str) -> bool {
    value.chars().any(|character| {
        !matches!(
            character,
            '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
        )
    })
}

pub(crate) fn effective_xml_field_protection(value: &str, protected: bool) -> bool {
    protected || requires_xml_protection(value)
}

pub(crate) fn totp_specs_semantically_equal(
    left_title: &str,
    left_username: &str,
    left: Option<&TotpSpec>,
    right_title: &str,
    right_username: &str,
    right: Option<&TotpSpec>,
) -> bool {
    fn effective_account_name<'a>(spec: &'a TotpSpec, username: &'a str) -> Option<&'a str> {
        let value = spec.account_name.as_deref().unwrap_or(username);
        (!value.is_empty()).then_some(value)
    }

    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.secret_base32
                .trim_end_matches('=')
                .eq_ignore_ascii_case(right.secret_base32.trim_end_matches('='))
                && left.algorithm == right.algorithm
                && left.digits == right.digits
                && left.period_seconds == right.period_seconds
                && left.issuer.as_deref().unwrap_or(left_title)
                    == right.issuer.as_deref().unwrap_or(right_title)
                && effective_account_name(left, left_username)
                    == effective_account_name(right, right_username)
        }
        _ => false,
    }
}

fn validate_desired_fields(
    name: &str,
    fields: &ValidatedFields,
) -> Result<(), AutofillPersistEngineError> {
    if fields.dto.password.is_empty() {
        return invalid_plan(format!("{name}.password must not be empty"));
    }
    http_origin(&format!("{name}.url"), &fields.dto.url)?;
    Ok(())
}

fn http_origin(name: &str, value: &str) -> Result<String, AutofillPersistEngineError> {
    if value.trim() != value || value.chars().any(char::is_control) {
        return invalid_plan(format!("invalid {name}"));
    }
    let parsed = Url::parse(value)
        .map_err(|_| AutofillPersistEngineError::InvalidPlan(format!("invalid {name}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return invalid_plan(format!("invalid {name}"));
    }
    Ok(parsed.origin().ascii_serialization())
}

fn hash_validated_plan(
    transaction_id: &str,
    vault_id: &str,
    source_identity_sha256: &str,
    plan: &ValidatedPlan,
) -> String {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, PLAN_DIGEST_DOMAIN.as_bytes());
    hash_component(&mut hasher, transaction_id.as_bytes());
    hash_component(&mut hasher, vault_id.as_bytes());
    hash_component(&mut hasher, source_identity_sha256.as_bytes());
    match plan {
        ValidatedPlan::Update {
            entry_id,
            expected_fields,
            desired_fields,
        } => {
            hash_component(&mut hasher, b"update");
            hash_component(&mut hasher, entry_id.as_bytes());
            hash_fields(&mut hasher, expected_fields);
            hash_fields(&mut hasher, desired_fields);
        }
        ValidatedPlan::Create {
            parent_group_id,
            planned_entry_id,
            expected_matching_entry_ids,
            desired_fields,
        } => {
            hash_component(&mut hasher, b"create");
            hash_component(&mut hasher, parent_group_id.as_bytes());
            hash_component(&mut hasher, planned_entry_id.as_bytes());
            hash_count(&mut hasher, expected_matching_entry_ids.len());
            for entry_id in expected_matching_entry_ids {
                hash_component(&mut hasher, entry_id.as_bytes());
            }
            hash_fields(&mut hasher, desired_fields);
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hash_count(hasher: &mut Sha256, count: usize) {
    hasher.update((count as u64).to_be_bytes());
}

fn hash_fields(hasher: &mut Sha256, fields: &ValidatedFields) {
    for value in [
        &fields.dto.title,
        &fields.dto.username,
        &fields.dto.password,
        &fields.dto.url,
        &fields.dto.notes,
    ] {
        hash_component(hasher, value.as_bytes());
    }
    match fields.totp.as_ref() {
        Some(totp) => {
            hasher.update([1]);
            hash_component(
                hasher,
                totp.secret_base32
                    .trim_end_matches('=')
                    .to_ascii_uppercase()
                    .as_bytes(),
            );
            hasher.update([match totp.algorithm {
                TotpAlgorithm::Sha1 => 1,
                TotpAlgorithm::Sha256 => 2,
                TotpAlgorithm::Sha512 => 3,
            }]);
            hasher.update(totp.digits.to_be_bytes());
            hasher.update(totp.period_seconds.to_be_bytes());
            hash_component(
                hasher,
                totp.issuer
                    .as_deref()
                    .unwrap_or(&fields.dto.title)
                    .as_bytes(),
            );
            let account_name = totp.account_name.as_deref().unwrap_or(&fields.dto.username);
            hash_optional_component(hasher, (!account_name.is_empty()).then_some(account_name));
        }
        None => hasher.update([0]),
    }
    hash_count(hasher, fields.custom_fields.len());
    for (key, value) in &fields.custom_fields {
        hash_component(hasher, key.as_bytes());
        hash_component(hasher, value.value.as_bytes());
        hasher.update([u8::from(value.protected)]);
    }
}

fn hash_optional_component(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_component(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn read_ledger(vault: &Vault) -> Result<ReceiptLedger, AutofillPersistEngineError> {
    let Some(value) = vault.meta_custom_data.get(AUTOFILL_RECEIPT_KEY) else {
        return Ok(ReceiptLedger {
            version: RECEIPT_VERSION,
            receipts: Vec::new(),
        });
    };
    if value.len() > MAX_LEDGER_BYTES {
        return invalid_ledger("receipt ledger is too large");
    }
    let ledger: ReceiptLedger = serde_json::from_str(value).map_err(|_| {
        AutofillPersistEngineError::InvalidLedger("malformed receipt ledger".into())
    })?;
    if ledger.version != RECEIPT_VERSION || ledger.receipts.len() > MAX_RECEIPTS {
        return invalid_ledger("unsupported or oversized receipt ledger");
    }
    for receipt in &ledger.receipts {
        validate_receipt(receipt)?;
    }
    Ok(ledger)
}

fn validate_receipt(receipt: &AutofillReceipt) -> Result<(), AutofillPersistEngineError> {
    validate_token(
        "receipt.operation_id",
        &receipt.operation_id,
        MAX_REQUEST_ID_BYTES,
    )
    .map_err(|_| AutofillPersistEngineError::InvalidLedger("invalid receipt".into()))?;
    validate_token(
        "receipt.transaction_id",
        &receipt.transaction_id,
        MAX_REQUEST_ID_BYTES,
    )
    .map_err(|_| AutofillPersistEngineError::InvalidLedger("invalid receipt".into()))?;
    validate_sha256(
        "receipt.source_identity_sha256",
        &receipt.source_identity_sha256,
    )
    .map_err(AutofillPersistEngineError::InvalidLedger)?;
    validate_sha256("receipt.plan_sha256", &receipt.plan_sha256)
        .map_err(AutofillPersistEngineError::InvalidLedger)?;
    validate_canonical_uuid("receipt.entry_id", &receipt.entry_id).map_err(|_| {
        AutofillPersistEngineError::InvalidLedger("invalid receipt entry ID".into())
    })?;
    Ok(())
}

fn same_receipt_binding(left: &AutofillReceipt, right: &AutofillReceipt) -> bool {
    left.operation_id == right.operation_id
        && left.transaction_id == right.transaction_id
        && left.source_identity_sha256 == right.source_identity_sha256
        && left.plan_sha256 == right.plan_sha256
        && left.mode == right.mode
        && left.entry_id == right.entry_id
}

fn dedupe_receipts(
    receipts: Vec<AutofillReceipt>,
) -> Result<BTreeMap<String, AutofillReceipt>, AutofillPersistEngineError> {
    let mut by_operation = BTreeMap::<String, AutofillReceipt>::new();
    for receipt in receipts {
        if let Some(existing) = by_operation.get_mut(&receipt.operation_id) {
            if !same_receipt_binding(existing, &receipt) {
                return conflict(AutofillPersistConflictCodeDto::OperationBindingMismatch);
            }
            if receipt.committed_at_epoch_ms > existing.committed_at_epoch_ms {
                *existing = receipt;
            }
        } else {
            by_operation.insert(receipt.operation_id.clone(), receipt);
        }
    }
    Ok(by_operation)
}

fn merge_receipt_maps(
    mut base: BTreeMap<String, AutofillReceipt>,
    current: BTreeMap<String, AutofillReceipt>,
) -> Result<BTreeMap<String, AutofillReceipt>, AutofillPersistEngineError> {
    for (_, receipt) in current {
        insert_receipt(&mut base, receipt)?;
    }
    Ok(base)
}

fn insert_receipt(
    receipts: &mut BTreeMap<String, AutofillReceipt>,
    receipt: AutofillReceipt,
) -> Result<(), AutofillPersistEngineError> {
    if let Some(existing) = receipts.get_mut(&receipt.operation_id) {
        if !same_receipt_binding(existing, &receipt) {
            return conflict(AutofillPersistConflictCodeDto::OperationBindingMismatch);
        }
        if receipt.committed_at_epoch_ms > existing.committed_at_epoch_ms {
            *existing = receipt;
        }
    } else {
        receipts.insert(receipt.operation_id.clone(), receipt);
    }
    Ok(())
}

fn write_pruned_ledger(
    candidate: &mut Vault,
    mut receipts: Vec<AutofillReceipt>,
    current_operation_id: &str,
    now_epoch_ms: u64,
) -> Result<(), AutofillPersistEngineError> {
    let current_index = receipts
        .iter()
        .position(|receipt| receipt.operation_id == current_operation_id)
        .ok_or_else(|| {
            AutofillPersistEngineError::InvalidLedger("current receipt is missing".into())
        })?;
    let current = receipts.swap_remove(current_index);
    let cutoff = now_epoch_ms.saturating_sub(RECEIPT_RETENTION_MS);
    receipts.retain(|receipt| receipt.committed_at_epoch_ms >= cutoff);
    receipts.sort_by(|left, right| {
        right
            .committed_at_epoch_ms
            .cmp(&left.committed_at_epoch_ms)
            .then_with(|| right.operation_id.cmp(&left.operation_id))
    });
    receipts.truncate(MAX_RECEIPTS - 1);
    receipts.push(current);
    receipts.sort_by(|left, right| {
        left.committed_at_epoch_ms
            .cmp(&right.committed_at_epoch_ms)
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
    let ledger = ReceiptLedger {
        version: RECEIPT_VERSION,
        receipts,
    };
    let json = serde_json::to_string(&ledger)
        .map_err(|_| AutofillPersistEngineError::InvalidLedger("cannot encode ledger".into()))?;
    if json.len() > MAX_LEDGER_BYTES {
        return invalid_ledger("encoded receipt ledger is too large");
    }
    candidate
        .meta_custom_data
        .insert(AUTOFILL_RECEIPT_KEY.into(), json);
    Ok(())
}

fn ensure_base_only_recovery_postcondition(
    current_source: &Vault,
    plan: &ValidatedPlan,
) -> Result<(), AutofillPersistEngineError> {
    match plan {
        ValidatedPlan::Update {
            entry_id,
            desired_fields,
            ..
        } => {
            if live_entry_matches_fields(current_source, entry_id, desired_fields) {
                Ok(())
            } else {
                conflict(AutofillPersistConflictCodeDto::UpdatePreconditionFailed)
            }
        }
        ValidatedPlan::Create {
            planned_entry_id,
            expected_matching_entry_ids,
            desired_fields,
            ..
        } => {
            let baseline_contains_planned = expected_matching_entry_ids
                .binary_search(planned_entry_id)
                .is_ok();
            if !baseline_contains_planned
                && live_entry_matches_fields(current_source, planned_entry_id, desired_fields)
            {
                Ok(())
            } else {
                conflict(AutofillPersistConflictCodeDto::PlannedEntryIdCollision)
            }
        }
    }
}

fn apply_idempotent_mutation(
    core: &KeepassCore,
    candidate: &mut Vault,
    base_loaded: &Vault,
    current_source: &Vault,
    plan: &ValidatedPlan,
    now_epoch_ms: u64,
) -> Result<(), AutofillPersistEngineError> {
    match plan {
        ValidatedPlan::Update {
            entry_id,
            expected_fields,
            desired_fields,
        } => {
            if live_entry_matches_fields(current_source, entry_id, desired_fields) {
                if live_entry_matches_fields(base_loaded, entry_id, expected_fields) {
                    force_entry_state_from_source(candidate, current_source, entry_id)?;
                }
                return Ok(());
            }
            if !live_entry_matches_fields(current_source, entry_id, expected_fields) {
                return conflict(AutofillPersistConflictCodeDto::UpdatePreconditionFailed);
            }
            if live_entry_matches_fields(candidate, entry_id, desired_fields) {
                return Ok(());
            }
            if !live_entry_matches_fields(candidate, entry_id, expected_fields) {
                return conflict(AutofillPersistConflictCodeDto::UpdatePreconditionFailed);
            }
            if !same_validated_fields(expected_fields, desired_fields) {
                core.snapshot_entry_to_history(candidate, entry_id)
                    .map_err(mutation_error)?;
                let entry = find_entry_mut(candidate, entry_id).ok_or_else(|| {
                    AutofillPersistEngineError::Mutation("entry disappeared".into())
                })?;
                apply_fields(entry, desired_fields, now_epoch_ms);
            }
            Ok(())
        }
        ValidatedPlan::Create {
            parent_group_id,
            planned_entry_id,
            expected_matching_entry_ids,
            desired_fields,
        } => {
            let baseline_contains_planned = expected_matching_entry_ids
                .binary_search(planned_entry_id)
                .is_ok();
            if let Some((entry, recycled)) = find_entry(current_source, planned_entry_id) {
                if !recycled
                    && !baseline_contains_planned
                    && entry_matches_validated(entry, desired_fields)
                {
                    return Ok(());
                }
                return conflict(AutofillPersistConflictCodeDto::PlannedEntryIdCollision);
            }
            if baseline_contains_planned {
                return conflict(AutofillPersistConflictCodeDto::PlannedEntryIdCollision);
            }
            if !group_is_live(current_source, parent_group_id)
                || !group_is_live(candidate, parent_group_id)
            {
                return conflict(AutofillPersistConflictCodeDto::CreateMatchingSetChanged);
            }
            if exact_matching_entry_ids(current_source, desired_fields)
                != *expected_matching_entry_ids
            {
                return conflict(AutofillPersistConflictCodeDto::CreateMatchingSetChanged);
            }
            if let Some((entry, recycled)) = find_entry(candidate, planned_entry_id) {
                if !recycled && entry_matches_validated(entry, desired_fields) {
                    let candidate_matching_without_planned: Vec<_> =
                        exact_matching_entry_ids(candidate, desired_fields)
                            .into_iter()
                            .filter(|entry_id| entry_id != planned_entry_id)
                            .collect();
                    if candidate_matching_without_planned == *expected_matching_entry_ids {
                        return Ok(());
                    }
                    return conflict(AutofillPersistConflictCodeDto::CreateMatchingSetChanged);
                }
                return conflict(AutofillPersistConflictCodeDto::PlannedEntryIdCollision);
            }
            if exact_matching_entry_ids(candidate, desired_fields) != *expected_matching_entry_ids {
                return conflict(AutofillPersistConflictCodeDto::CreateMatchingSetChanged);
            }
            let created = core
                .add_entry_with_id(
                    candidate,
                    parent_group_id,
                    planned_entry_id,
                    EntryCreate {
                        title: desired_fields.dto.title.clone(),
                        username: desired_fields.dto.username.clone(),
                        password: desired_fields.dto.password.clone(),
                        url: desired_fields.dto.url.clone(),
                        notes: desired_fields.dto.notes.clone(),
                    },
                )
                .map_err(|error| match error {
                    MutationError::UuidCollision(_) => AutofillPersistEngineError::Conflict(
                        AutofillPersistConflictCodeDto::PlannedEntryIdCollision,
                    ),
                    other => mutation_error(other),
                })?;
            let entry = find_entry_mut(candidate, &created.id).ok_or_else(|| {
                AutofillPersistEngineError::Mutation("created entry missing".into())
            })?;
            apply_fields(entry, desired_fields, now_epoch_ms);
            Ok(())
        }
    }
}

fn same_validated_fields(left: &ValidatedFields, right: &ValidatedFields) -> bool {
    left.dto.title == right.dto.title
        && left.dto.username == right.dto.username
        && left.dto.password == right.dto.password
        && left.dto.url == right.dto.url
        && left.dto.notes == right.dto.notes
        && totp_specs_semantically_equal(
            &left.dto.title,
            &left.dto.username,
            left.totp.as_ref(),
            &right.dto.title,
            &right.dto.username,
            right.totp.as_ref(),
        )
        && left.custom_fields == right.custom_fields
}

fn apply_fields(entry: &mut Entry, fields: &ValidatedFields, now_epoch_ms: u64) {
    let next_modified_at = (now_epoch_ms / 1_000).max(entry.modified_at.saturating_add(1));
    entry.title = fields.dto.title.clone();
    entry.username = fields.dto.username.clone();
    entry.password = fields.dto.password.clone();
    entry.url = fields.dto.url.clone();
    entry.notes = fields.dto.notes.clone();
    entry.totp = fields.totp.clone();
    entry.attributes = fields.custom_fields.clone();
    protect_xml_forbidden_fields(entry);
    entry.modified_at = next_modified_at;
}

fn protect_xml_forbidden_fields(entry: &mut Entry) {
    entry.field_protection.protect_title |= requires_xml_protection(&entry.title);
    entry.field_protection.protect_username |= requires_xml_protection(&entry.username);
    entry.field_protection.protect_password |= requires_xml_protection(&entry.password);
    entry.field_protection.protect_url |= requires_xml_protection(&entry.url);
    entry.field_protection.protect_notes |= requires_xml_protection(&entry.notes);
    for field in entry.attributes.values_mut() {
        field.protected = effective_xml_field_protection(&field.value, field.protected);
    }
}

fn protect_target_xml_forbidden_fields(candidate: &mut Vault, entry_id: &str) {
    let Some(entry) = find_entry_mut(candidate, entry_id) else {
        return;
    };
    protect_xml_forbidden_fields(entry);
    for history_entry in &mut entry.history {
        protect_xml_forbidden_fields(history_entry);
    }
}

fn live_entry_matches_fields(vault: &Vault, entry_id: &str, fields: &ValidatedFields) -> bool {
    find_entry(vault, entry_id)
        .map(|(entry, recycled)| !recycled && entry_matches_validated(entry, fields))
        .unwrap_or(false)
}

fn entry_matches_validated(entry: &Entry, fields: &ValidatedFields) -> bool {
    entry.title == fields.dto.title
        && entry.username == fields.dto.username
        && entry.password == fields.dto.password
        && entry.url == fields.dto.url
        && entry.notes == fields.dto.notes
        && totp_specs_semantically_equal(
            &entry.title,
            &entry.username,
            entry.totp.as_ref(),
            &fields.dto.title,
            &fields.dto.username,
            fields.totp.as_ref(),
        )
        && custom_fields_match(&entry.attributes, &fields.custom_fields)
}

fn custom_fields_match(
    actual: &BTreeMap<String, CustomField>,
    expected: &BTreeMap<String, CustomField>,
) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|(key, expected_field)| {
            actual.get(key).is_some_and(|actual_field| {
                actual_field.value == expected_field.value
                    && effective_xml_field_protection(&actual_field.value, actual_field.protected)
                        == expected_field.protected
            })
        })
}

fn force_entry_state_from_source(
    candidate: &mut Vault,
    source: &Vault,
    entry_id: &str,
) -> Result<(), AutofillPersistEngineError> {
    let id = Uuid::parse_str(entry_id)
        .map_err(|_| AutofillPersistEngineError::Mutation("invalid entry ID".into()))?;
    let candidate_position =
        locate_entry(&candidate.root, id).map(|(parent_id, index, _)| (parent_id, index));
    remove_entry_from_group(&mut candidate.root, id);
    candidate.deleted_objects.retain(|item| item.id != id);
    candidate.deleted_objects.extend(
        source
            .deleted_objects
            .iter()
            .filter(|item| item.id == id)
            .cloned(),
    );
    let Some((parent_id, _, entry)) = locate_entry(&source.root, id) else {
        return Ok(());
    };
    let parent = find_group_by_uuid_mut(&mut candidate.root, parent_id).ok_or_else(|| {
        AutofillPersistEngineError::Mutation("current entry parent is missing from merge".into())
    })?;
    let index = candidate_position
        .filter(|(candidate_parent_id, _)| *candidate_parent_id == parent_id)
        .map(|(_, index)| index)
        .unwrap_or(parent.entries.len());
    parent
        .entries
        .insert(index.min(parent.entries.len()), entry);
    Ok(())
}

fn reconcile_post_receipt_entry(
    candidate: &mut Vault,
    baseline_source: &Vault,
    base_loaded: &Vault,
    current_source: &Vault,
    entry_id: &str,
) -> Result<(), AutofillPersistEngineError> {
    let baseline = post_receipt_entry_state(baseline_source, entry_id)?;
    let local = post_receipt_entry_state(base_loaded, entry_id)?;
    let current = post_receipt_entry_state(current_source, entry_id)?;
    let source = if local == current {
        current_source
    } else if local == baseline {
        current_source
    } else if current == baseline {
        base_loaded
    } else {
        return merge_conflict(format!(
            "concurrent post-receipt entry change for {entry_id}"
        ));
    };
    force_entry_state_from_source(candidate, source, entry_id)
}

fn post_receipt_entry_state(
    vault: &Vault,
    entry_id: &str,
) -> Result<PostReceiptEntryState, AutofillPersistEngineError> {
    let id = Uuid::parse_str(entry_id)
        .map_err(|_| AutofillPersistEngineError::Mutation("invalid entry ID".into()))?;
    let located = locate_entry(&vault.root, id).map(|(parent_id, _, entry)| Located {
        parent_id: Some(parent_id),
        value: entry,
    });
    let mut deleted = vault
        .deleted_objects
        .iter()
        .filter(|item| item.id == id)
        .cloned()
        .collect::<Vec<_>>();
    deleted.sort_by_key(|item| item.deleted_at);
    Ok(PostReceiptEntryState {
        located,
        recycled: find_entry(vault, entry_id)
            .map(|(_, recycled)| recycled)
            .unwrap_or(false),
        deleted_objects: deleted,
    })
}

fn locate_entry(group: &Group, entry_id: Uuid) -> Option<(Uuid, usize, Entry)> {
    if let Some(index) = group.entries.iter().position(|entry| entry.id == entry_id) {
        return Some((group.id, index, group.entries[index].clone()));
    }
    group
        .children
        .iter()
        .find_map(|child| locate_entry(child, entry_id))
}

fn remove_entry_from_group(group: &mut Group, entry_id: Uuid) -> bool {
    let original_len = group.entries.len();
    group.entries.retain(|entry| entry.id != entry_id);
    let mut removed = group.entries.len() != original_len;
    for child in &mut group.children {
        removed |= remove_entry_from_group(child, entry_id);
    }
    removed
}

fn find_group_by_uuid_mut(group: &mut Group, group_id: Uuid) -> Option<&mut Group> {
    if group.id == group_id {
        return Some(group);
    }
    group
        .children
        .iter_mut()
        .find_map(|child| find_group_by_uuid_mut(child, group_id))
}

fn find_entry<'a>(vault: &'a Vault, entry_id: &str) -> Option<(&'a Entry, bool)> {
    let id = Uuid::parse_str(entry_id).ok()?;
    find_entry_in_group(
        &vault.root,
        id,
        vault.recycle_bin_group,
        vault.recycle_bin_enabled.unwrap_or(true),
        false,
    )
}

fn find_entry_in_group(
    group: &Group,
    entry_id: Uuid,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
) -> Option<(&Entry, bool)> {
    let recycled = ancestor_recycled
        || (recycle_bin_enabled && recycle_bin_group.is_some_and(|id| id == group.id));
    if let Some(entry) = group.entries.iter().find(|entry| entry.id == entry_id) {
        return Some((entry, recycled));
    }
    group.children.iter().find_map(|child| {
        find_entry_in_group(
            child,
            entry_id,
            recycle_bin_group,
            recycle_bin_enabled,
            recycled,
        )
    })
}

fn find_entry_mut<'a>(vault: &'a mut Vault, entry_id: &str) -> Option<&'a mut Entry> {
    let id = Uuid::parse_str(entry_id).ok()?;
    find_entry_in_group_mut(&mut vault.root, id)
}

fn find_entry_in_group_mut(group: &mut Group, entry_id: Uuid) -> Option<&mut Entry> {
    if let Some(index) = group.entries.iter().position(|entry| entry.id == entry_id) {
        return group.entries.get_mut(index);
    }
    group
        .children
        .iter_mut()
        .find_map(|child| find_entry_in_group_mut(child, entry_id))
}

fn exact_matching_entry_ids(vault: &Vault, fields: &ValidatedFields) -> Vec<String> {
    let mut matches = Vec::new();
    collect_matching_entry_ids(
        &vault.root,
        fields,
        vault.recycle_bin_group,
        vault.recycle_bin_enabled.unwrap_or(true),
        false,
        &mut matches,
    );
    matches.sort();
    matches
}

fn collect_matching_entry_ids(
    group: &Group,
    fields: &ValidatedFields,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
    matches: &mut Vec<String>,
) {
    let recycled = ancestor_recycled
        || (recycle_bin_enabled && recycle_bin_group.is_some_and(|id| id == group.id));
    if !recycled {
        matches.extend(
            group
                .entries
                .iter()
                .filter(|entry| entry_matches_validated(entry, fields))
                .map(|entry| entry.id.to_string()),
        );
    }
    for child in &group.children {
        collect_matching_entry_ids(
            child,
            fields,
            recycle_bin_group,
            recycle_bin_enabled,
            recycled,
            matches,
        );
    }
}

fn group_is_live(vault: &Vault, group_id: &str) -> bool {
    let Ok(id) = Uuid::parse_str(group_id) else {
        return false;
    };
    group_is_live_in_tree(
        &vault.root,
        id,
        vault.recycle_bin_group,
        vault.recycle_bin_enabled.unwrap_or(true),
        false,
    )
}

fn group_is_live_in_tree(
    group: &Group,
    group_id: Uuid,
    recycle_bin_group: Option<Uuid>,
    recycle_bin_enabled: bool,
    ancestor_recycled: bool,
) -> bool {
    let recycled = ancestor_recycled
        || (recycle_bin_enabled && recycle_bin_group.is_some_and(|id| id == group.id));
    (!recycled && group.id == group_id)
        || group.children.iter().any(|child| {
            group_is_live_in_tree(
                child,
                group_id,
                recycle_bin_group,
                recycle_bin_enabled,
                recycled,
            )
        })
}

fn mutation_error(error: MutationError) -> AutofillPersistEngineError {
    AutofillPersistEngineError::Mutation(error.to_string())
}

fn invalid_plan<T>(message: impl Into<String>) -> Result<T, AutofillPersistEngineError> {
    Err(AutofillPersistEngineError::InvalidPlan(message.into()))
}

fn invalid_ledger<T>(message: impl Into<String>) -> Result<T, AutofillPersistEngineError> {
    Err(AutofillPersistEngineError::InvalidLedger(message.into()))
}

fn merge_conflict<T>(message: impl Into<String>) -> Result<T, AutofillPersistEngineError> {
    Err(AutofillPersistEngineError::MergeConflict(message.into()))
}

fn conflict<T>(code: AutofillPersistConflictCodeDto) -> Result<T, AutofillPersistEngineError> {
    Err(AutofillPersistEngineError::Conflict(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultkern_core::{DeletedObject, EntryCreate, EntryUpdate, KeepassCore, TotpSpec, Vault};
    use vaultkern_runtime_protocol::{
        AutofillPersistConflictCodeDto, AutofillPersistPlanDto, EntryCustomFieldDto, EntryFieldsDto,
    };

    const ENTRY_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const PLANNED_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const OTHER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const PENDING_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const GROUP_A_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    const GROUP_B_ID: &str = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    const SOURCE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const VAULT_ID: &str = "/vault/demo.kdbx";
    const TRANSACTION_ID: &str = "transaction-1";
    const OPERATION_ID: &str = "operation-1";
    const NOW_MS: u64 = 1_800_000_000_000;
    const TOTP_URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45";

    fn fields(password: &str) -> EntryFieldsDto {
        EntryFieldsDto {
            title: "Example".into(),
            username: "alice".into(),
            password: password.into(),
            url: "https://example.com/login".into(),
            notes: "notes".into(),
            totp_uri: None,
            custom_fields: vec![],
        }
    }

    fn fields_with_custom(password: &str, reverse: bool) -> EntryFieldsDto {
        let mut custom_fields = vec![
            EntryCustomFieldDto {
                key: "Alpha".into(),
                value: "a".into(),
                protected: false,
            },
            EntryCustomFieldDto {
                key: "Zeta".into(),
                value: "z".into(),
                protected: true,
            },
        ];
        if reverse {
            custom_fields.reverse();
        }
        EntryFieldsDto {
            custom_fields,
            ..fields(password)
        }
    }

    fn fields_with_custom_and_totp(password: &str) -> EntryFieldsDto {
        EntryFieldsDto {
            totp_uri: Some(TOTP_URI.into()),
            custom_fields: vec![
                EntryCustomFieldDto {
                    key: "RecoveryCode".into(),
                    value: "alpha-beta".into(),
                    protected: true,
                },
                EntryCustomFieldDto {
                    key: "Region".into(),
                    value: "eu-west".into(),
                    protected: false,
                },
            ],
            ..fields(password)
        }
    }

    fn update_plan(expected: EntryFieldsDto, desired: EntryFieldsDto) -> AutofillPersistPlanDto {
        AutofillPersistPlanDto::Update {
            entry_id: ENTRY_ID.into(),
            expected_fields: expected,
            desired_fields: desired,
        }
    }

    fn create_plan(
        parent_group_id: &str,
        expected_matching_entry_ids: Vec<String>,
        desired_fields: EntryFieldsDto,
    ) -> AutofillPersistPlanDto {
        AutofillPersistPlanDto::Create {
            parent_group_id: parent_group_id.into(),
            planned_entry_id: PLANNED_ID.into(),
            expected_matching_entry_ids,
            desired_fields,
        }
    }

    fn empty_vault() -> Vault {
        Vault::empty("Autofill")
    }

    fn add_entry(vault: &mut Vault, entry_id: &str, fields: &EntryFieldsDto) {
        let core = KeepassCore::new();
        let parent_group_id = vault.root.id.to_string();
        core.add_entry_with_id(
            vault,
            &parent_group_id,
            entry_id,
            EntryCreate {
                title: fields.title.clone(),
                username: fields.username.clone(),
                password: fields.password.clone(),
                url: fields.url.clone(),
                notes: fields.notes.clone(),
            },
        )
        .expect("add fixture entry");
        for field in &fields.custom_fields {
            core.upsert_entry_custom_field(
                vault,
                entry_id,
                vaultkern_core::EntryCustomFieldInput {
                    key: field.key.clone(),
                    value: field.value.clone(),
                    protected: field.protected,
                },
            )
            .expect("add fixture custom field");
        }
        if let Some(uri) = &fields.totp_uri {
            core.set_entry_totp(
                vault,
                entry_id,
                TotpSpec::parse_otpauth(uri).expect("parse fixture TOTP"),
            )
            .expect("add fixture TOTP");
        }
    }

    fn vault_with_entry(entry_fields: &EntryFieldsDto) -> Vault {
        let mut vault = empty_vault();
        add_entry(&mut vault, ENTRY_ID, entry_fields);
        vault
    }

    fn execute(
        base_loaded: &Vault,
        current_source: &Vault,
        plan: &AutofillPersistPlanDto,
    ) -> Result<PreparedAutofillPersist, AutofillPersistEngineError> {
        execute_with_baseline(base_loaded, base_loaded, current_source, plan)
    }

    fn execute_with_baseline(
        baseline_source: &Vault,
        base_loaded: &Vault,
        current_source: &Vault,
        plan: &AutofillPersistPlanDto,
    ) -> Result<PreparedAutofillPersist, AutofillPersistEngineError> {
        execute_with_binding(
            base_loaded,
            current_source,
            baseline_source,
            plan,
            TRANSACTION_ID,
            OPERATION_ID,
            NOW_MS,
        )
    }

    fn execute_with_binding(
        base_loaded: &Vault,
        current_source: &Vault,
        baseline_source: &Vault,
        plan: &AutofillPersistPlanDto,
        transaction_id: &str,
        operation_id: &str,
        now_epoch_ms: u64,
    ) -> Result<PreparedAutofillPersist, AutofillPersistEngineError> {
        prepare_autofill_persist(AutofillPersistEngineInput {
            baseline_source,
            base_loaded,
            current_source,
            transaction_id,
            operation_id,
            vault_id: VAULT_ID,
            source_identity_sha256: SOURCE_SHA,
            plan,
            now_epoch_ms,
        })
    }

    fn entry_count(vault: &Vault) -> usize {
        fn count(group: &vaultkern_core::Group) -> usize {
            group.entries.len() + group.children.iter().map(count).sum::<usize>()
        }
        count(&vault.root)
    }

    fn root_entry_ids(vault: &Vault) -> Vec<String> {
        vault
            .root
            .entries
            .iter()
            .map(|entry| entry.id.to_string())
            .collect()
    }

    fn root_child_ids(vault: &Vault) -> Vec<String> {
        vault
            .root
            .children
            .iter()
            .map(|group| group.id.to_string())
            .collect()
    }

    fn count_entry_id(group: &Group, entry_id: Uuid) -> usize {
        group
            .entries
            .iter()
            .filter(|entry| entry.id == entry_id)
            .count()
            + group
                .children
                .iter()
                .map(|child| count_entry_id(child, entry_id))
                .sum::<usize>()
    }

    fn entry_password(vault: &Vault, entry_id: &str) -> Option<String> {
        KeepassCore::new()
            .project_entry_detail(vault, entry_id)
            .ok()
            .map(|entry| entry.password)
    }

    fn history_count(vault: &Vault, entry_id: &str) -> usize {
        KeepassCore::new()
            .find_entry_view_by_id(vault, entry_id)
            .expect("fixture entry")
            .history_count
    }

    fn set_entry_password_and_modified(
        vault: &mut Vault,
        entry_id: &str,
        password: &str,
        modified_at: u64,
    ) {
        let entry = find_entry_mut(vault, entry_id).expect("fixture entry");
        entry.password = password.into();
        entry.modified_at = modified_at;
    }

    fn ledger(vault: &Vault) -> ReceiptLedger {
        serde_json::from_str(
            vault
                .meta_custom_data
                .get(AUTOFILL_RECEIPT_KEY)
                .expect("receipt ledger"),
        )
        .expect("valid receipt ledger")
    }

    fn receipt(
        operation_id: &str,
        transaction_id: &str,
        plan_sha256: &str,
        entry_id: &str,
        committed_at_epoch_ms: u64,
    ) -> AutofillReceipt {
        AutofillReceipt {
            operation_id: operation_id.into(),
            transaction_id: transaction_id.into(),
            source_identity_sha256: SOURCE_SHA.into(),
            plan_sha256: plan_sha256.into(),
            mode: ReceiptMode::Update,
            entry_id: entry_id.into(),
            committed_at_epoch_ms,
        }
    }

    #[test]
    fn plan_digest_is_domain_separated_length_prefixed_and_canonical() {
        let expected = fields_with_custom("old-secret", true);
        let desired = fields_with_custom("new-secret", false);
        let plan = update_plan(expected.clone(), desired.clone());

        let digest = plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &plan).unwrap();
        assert_eq!(
            digest,
            "8f43045c3d351d2a9438795b2617f2bd5c444e5f4812ae1f164e3020b4c19181"
        );

        let reordered = update_plan(
            fields_with_custom("old-secret", false),
            fields_with_custom("new-secret", true),
        );
        assert_eq!(
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &reordered).unwrap(),
            digest
        );
        assert_ne!(
            plan_sha256("transaction-2", VAULT_ID, SOURCE_SHA, &plan).unwrap(),
            digest
        );
        let changed = update_plan(
            expected,
            EntryFieldsDto {
                password: "third-secret".into(),
                ..desired
            },
        );
        assert_ne!(
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &changed).unwrap(),
            digest
        );
    }

    #[test]
    fn create_digest_sorts_matching_ids_without_rewriting_the_plan() {
        let vault = empty_vault();
        let parent = vault.root.id.to_string();
        let unsorted_ids = vec![OTHER_ID.into(), ENTRY_ID.into()];
        let unsorted = create_plan(&parent, unsorted_ids.clone(), fields("secret"));
        let sorted = create_plan(
            &parent,
            vec![ENTRY_ID.into(), OTHER_ID.into()],
            fields("secret"),
        );

        assert_eq!(
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &unsorted).unwrap(),
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &sorted).unwrap()
        );
        let AutofillPersistPlanDto::Create {
            expected_matching_entry_ids,
            ..
        } = unsorted
        else {
            unreachable!()
        };
        assert_eq!(expected_matching_entry_ids, unsorted_ids);
    }

    #[test]
    fn plan_digest_canonicalizes_semantically_equivalent_totp_uris() {
        let mut canonical = fields("secret");
        canonical.totp_uri = Some(TOTP_URI.into());
        let mut reordered = fields("secret");
        reordered.totp_uri = Some(
            "otpauth://totp/Example%3Aalice?period=45&digits=08&algorithm=HMAC-SHA-256&issuer=Example&secret=JBSWY3DPEHPK3PXP"
                .into(),
        );
        let canonical = create_plan(&empty_vault().root.id.to_string(), Vec::new(), canonical);
        let AutofillPersistPlanDto::Create {
            parent_group_id, ..
        } = &canonical
        else {
            unreachable!()
        };
        let reordered = create_plan(parent_group_id, Vec::new(), reordered);
        let mut fallback_fields = fields("secret");
        fallback_fields.totp_uri = Some(
            "otpauth://totp/ignored?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=45"
                .into(),
        );
        let fallback = create_plan(parent_group_id, Vec::new(), fallback_fields);
        let mut normalized_secret_fields = fields("secret");
        normalized_secret_fields.totp_uri =
            Some(TOTP_URI.replace("JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp===="));
        let normalized_secret = create_plan(parent_group_id, Vec::new(), normalized_secret_fields);

        let canonical_digest =
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &canonical).unwrap();
        assert_eq!(
            canonical_digest,
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &reordered).unwrap()
        );
        assert_eq!(
            canonical_digest,
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &fallback).unwrap()
        );
        assert_eq!(
            canonical_digest,
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &normalized_secret,).unwrap()
        );

        let mut changed_fields = fields("secret");
        changed_fields.totp_uri = Some(TOTP_URI.replace("period=45", "period=46"));
        let changed = create_plan(parent_group_id, Vec::new(), changed_fields);
        assert_ne!(
            canonical_digest,
            plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &changed).unwrap()
        );
    }

    #[test]
    fn invalid_ids_lengths_fields_and_duplicate_custom_keys_fail_without_mutation() {
        let current = vault_with_entry(&fields("old-secret"));
        let base = current.clone();
        let base_before = base.clone();
        let current_before = current.clone();
        let mut duplicate_fields = fields("new-secret");
        duplicate_fields.custom_fields = vec![
            EntryCustomFieldDto {
                key: "Duplicate".into(),
                value: "one".into(),
                protected: false,
            },
            EntryCustomFieldDto {
                key: "Duplicate".into(),
                value: "two".into(),
                protected: true,
            },
        ];
        let invalid_plans = [
            AutofillPersistPlanDto::Update {
                entry_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into(),
                expected_fields: fields("old-secret"),
                desired_fields: fields("new-secret"),
            },
            AutofillPersistPlanDto::Create {
                parent_group_id: base.root.id.simple().to_string(),
                planned_entry_id: PLANNED_ID.into(),
                expected_matching_entry_ids: vec![],
                desired_fields: fields("new-secret"),
            },
            AutofillPersistPlanDto::Create {
                parent_group_id: base.root.id.to_string(),
                planned_entry_id: "00000000-0000-0000-0000-000000000000".into(),
                expected_matching_entry_ids: vec![],
                desired_fields: fields("new-secret"),
            },
            update_plan(fields("old-secret"), duplicate_fields),
            update_plan(
                fields("old-secret"),
                EntryFieldsDto {
                    title: "x".repeat(MAX_FIELD_BYTES + 1),
                    ..fields("new-secret")
                },
            ),
        ];

        for plan in invalid_plans {
            assert!(matches!(
                execute(&base, &current, &plan),
                Err(AutofillPersistEngineError::InvalidPlan(_))
            ));
            assert_eq!(base, base_before);
            assert_eq!(current, current_before);
        }

        let plan = update_plan(fields("old-secret"), fields("new-secret"));
        assert!(matches!(
            execute_with_binding(&base, &current, &base, &plan, "", OPERATION_ID, NOW_MS),
            Err(AutofillPersistEngineError::InvalidPlan(_))
        ));
        assert!(matches!(
            execute_with_binding(
                &base,
                &current,
                &base,
                &plan,
                TRANSACTION_ID,
                &"o".repeat(MAX_REQUEST_ID_BYTES + 1),
                NOW_MS
            ),
            Err(AutofillPersistEngineError::InvalidPlan(_))
        ));
    }

    #[test]
    fn duplicate_matching_ids_reserved_custom_keys_and_invalid_totp_fail_closed() {
        let current = vault_with_entry(&fields("old-secret"));
        let parent = current.root.id.to_string();
        let mut reserved = fields("new-secret");
        reserved.custom_fields.push(EntryCustomFieldDto {
            key: "Password".into(),
            value: "shadow".into(),
            protected: true,
        });
        let mut invalid_key = fields("new-secret");
        invalid_key.custom_fields.push(EntryCustomFieldDto {
            key: "line\nbreak".into(),
            value: "value".into(),
            protected: false,
        });
        let mut invalid_xml_key = fields("new-secret");
        invalid_xml_key.custom_fields.push(EntryCustomFieldDto {
            key: "Ten\u{fffe}ant".into(),
            value: "value".into(),
            protected: false,
        });
        let mut invalid_totp = fields("new-secret");
        invalid_totp.totp_uri = Some("otpauth://totp/Example?secret=%%%".into());
        let mut invalid_totp_control = fields("new-secret");
        invalid_totp_control.totp_uri =
            Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Bad\0Issuer".into());
        let mut invalid_value = fields("new-secret");
        invalid_value.custom_fields.push(EntryCustomFieldDto {
            key: "Oversized".into(),
            value: "x".repeat(MAX_FIELD_BYTES + 1),
            protected: false,
        });
        let plans = [
            create_plan(
                &parent,
                vec![OTHER_ID.into(), OTHER_ID.into()],
                fields("secret"),
            ),
            update_plan(fields("old-secret"), reserved),
            update_plan(fields("old-secret"), invalid_key),
            update_plan(fields("old-secret"), invalid_xml_key),
            update_plan(fields("old-secret"), invalid_value),
            update_plan(fields("old-secret"), invalid_totp),
            update_plan(fields("old-secret"), invalid_totp_control),
        ];
        let before = current.clone();

        for plan in plans {
            assert!(matches!(
                execute(&current, &current, &plan),
                Err(AutofillPersistEngineError::InvalidPlan(_))
            ));
            assert_eq!(current, before);
        }
    }

    #[test]
    fn forged_password_url_and_cross_origin_plans_fail_without_mutation() {
        let expected = fields("old-secret");
        let current = vault_with_entry(&expected);
        let parent = current.root.id.to_string();
        let invalid_plans = [
            update_plan(expected.clone(), fields("")),
            update_plan(
                expected.clone(),
                EntryFieldsDto {
                    url: "javascript:alert(1)".into(),
                    ..fields("new-secret")
                },
            ),
            update_plan(
                expected.clone(),
                EntryFieldsDto {
                    url: "https://other.example/login".into(),
                    ..fields("new-secret")
                },
            ),
            create_plan(&parent, vec![], fields("")),
            create_plan(
                &parent,
                vec![],
                EntryFieldsDto {
                    url: "file:///tmp/login".into(),
                    ..fields("new-secret")
                },
            ),
        ];
        let before = current.clone();

        for plan in invalid_plans {
            assert!(matches!(
                execute(&current, &current, &plan),
                Err(AutofillPersistEngineError::InvalidPlan(_))
            ));
            assert_eq!(current, before);
        }

        let expected_empty_password = fields("");
        let current = vault_with_entry(&expected_empty_password);
        let desired_same_origin = EntryFieldsDto {
            url: "https://example.com/changed/path?next=1".into(),
            ..fields("new-secret")
        };
        assert!(
            execute(
                &current,
                &current,
                &update_plan(expected_empty_password, desired_same_origin)
            )
            .is_ok()
        );
    }

    #[test]
    fn update_roundtrips_custom_fields_and_totp_with_one_history_snapshot() {
        let expected = fields("old-secret");
        let desired = fields_with_custom_and_totp("new-secret");
        let current = vault_with_entry(&expected);
        let prepared = execute(
            &current,
            &current,
            &update_plan(expected.clone(), desired.clone()),
        )
        .unwrap();

        let (entry, recycled) = find_entry(&prepared.candidate, ENTRY_ID).unwrap();
        assert!(!recycled);
        assert!(entry_matches_validated(
            entry,
            &validate_fields("desired", &desired).unwrap()
        ));
        assert_eq!(entry.history.len(), 1);
        assert!(entry_matches_validated(
            &entry.history[0],
            &validate_fields("expected", &expected).unwrap()
        ));
    }

    #[test]
    fn update_accepts_entry_totp_using_title_and_username_fallbacks() {
        let expected = fields_with_custom_and_totp("old-secret");
        let desired = EntryFieldsDto {
            password: "new-secret".into(),
            ..expected.clone()
        };
        let mut current = vault_with_entry(&expected);
        let entry = find_entry_mut(&mut current, ENTRY_ID).unwrap();
        let totp = entry.totp.as_mut().unwrap();
        totp.issuer = None;
        totp.account_name = None;

        let prepared = execute(&current, &current, &update_plan(expected, desired)).unwrap();
        let entry = find_entry(&prepared.candidate, ENTRY_ID).unwrap().0;

        assert_eq!(entry.password, "new-secret");
        assert_eq!(entry.history.len(), 1);
    }

    #[test]
    fn semantically_unchanged_totp_fallback_does_not_add_history() {
        let desired = fields_with_custom_and_totp("secret");
        let mut current = vault_with_entry(&desired);
        let entry = find_entry_mut(&mut current, ENTRY_ID).unwrap();
        let totp = entry.totp.as_mut().unwrap();
        totp.issuer = None;
        totp.account_name = None;

        let prepared = execute(&current, &current, &update_plan(desired.clone(), desired)).unwrap();

        assert!(
            find_entry(&prepared.candidate, ENTRY_ID)
                .unwrap()
                .0
                .history
                .is_empty()
        );
    }

    #[test]
    fn update_protects_xml_forbidden_field_values_before_serialization() {
        let expected = fields("old-secret");
        let mut desired = fields("new\0secret");
        desired.title = "Example\0Title".into();
        desired.username = "alice\0name".into();
        desired.notes = "notes\0body".into();
        desired.custom_fields.push(EntryCustomFieldDto {
            key: "UnsafeValue".into(),
            value: "custom\0value".into(),
            protected: false,
        });
        let mut current = vault_with_entry(&expected);
        find_entry_mut(&mut current, ENTRY_ID)
            .unwrap()
            .field_protection
            .protect_password = false;

        let prepared = execute(&current, &current, &update_plan(expected, desired)).unwrap();
        let entry = find_entry(&prepared.candidate, ENTRY_ID).unwrap().0;

        assert!(entry.field_protection.protect_title);
        assert!(entry.field_protection.protect_username);
        assert!(entry.field_protection.protect_password);
        assert!(entry.field_protection.protect_notes);
        assert!(entry.attributes["UnsafeValue"].protected);
    }

    #[test]
    fn idempotent_update_still_protects_xml_forbidden_field_values() {
        let mut desired = fields("secret");
        desired.username = "alice\0name".into();
        desired.custom_fields.push(EntryCustomFieldDto {
            key: "UnsafeValue".into(),
            value: "custom\0value".into(),
            protected: false,
        });
        let current = vault_with_entry(&desired);

        let prepared = execute(&current, &current, &update_plan(desired.clone(), desired)).unwrap();
        let entry = find_entry(&prepared.candidate, ENTRY_ID).unwrap().0;

        assert!(entry.field_protection.protect_username);
        assert!(entry.attributes["UnsafeValue"].protected);
        assert!(entry.history.is_empty());
    }

    #[test]
    fn create_roundtrips_nonempty_custom_fields_and_totp() {
        let current = empty_vault();
        let desired = fields_with_custom_and_totp("secret");
        let prepared = execute(
            &current,
            &current,
            &create_plan(&current.root.id.to_string(), vec![], desired.clone()),
        )
        .unwrap();

        let (entry, recycled) = find_entry(&prepared.candidate, PLANNED_ID).unwrap();
        assert!(!recycled);
        assert!(entry_matches_validated(
            entry,
            &validate_fields("desired", &desired).unwrap()
        ));
        assert!(entry.history.is_empty());
    }

    #[test]
    fn create_matching_set_accepts_entry_totp_fallbacks() {
        let desired = fields_with_custom_and_totp("secret");
        let mut current = vault_with_entry(&desired);
        let entry = find_entry_mut(&mut current, ENTRY_ID).unwrap();
        let totp = entry.totp.as_mut().unwrap();
        totp.issuer = None;
        totp.account_name = None;
        let plan = create_plan(&current.root.id.to_string(), vec![ENTRY_ID.into()], desired);

        let prepared = execute(&current, &current, &plan).unwrap();

        assert!(find_entry(&prepared.candidate, PLANNED_ID).is_some());
    }

    #[test]
    fn update_from_expected_adds_one_history_and_a_canonical_receipt() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let current = vault_with_entry(&expected);
        let mut base = current.clone();
        base.meta_custom_data
            .insert("keep.me".into(), "untouched".into());
        let base_before = base.clone();
        let current_before = current.clone();
        let plan = update_plan(expected, desired);

        let prepared = execute_with_baseline(&current, &base, &current, &plan).unwrap();

        assert_eq!(
            prepared.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(
            entry_password(&prepared.candidate, ENTRY_ID).as_deref(),
            Some("new-secret")
        );
        assert_eq!(history_count(&prepared.candidate, ENTRY_ID), 1);
        assert_eq!(
            prepared
                .candidate
                .meta_custom_data
                .get("keep.me")
                .map(String::as_str),
            Some("untouched")
        );
        let expected_json = format!(
            "{{\"version\":1,\"receipts\":[{{\"operationId\":\"operation-1\",\"transactionId\":\"transaction-1\",\"sourceIdentitySha256\":\"{SOURCE_SHA}\",\"planSha256\":\"{}\",\"mode\":\"update\",\"entryId\":\"{ENTRY_ID}\",\"committedAtEpochMs\":{NOW_MS}}}]}}",
            prepared.plan_sha256
        );
        assert_eq!(
            prepared
                .candidate
                .meta_custom_data
                .get(AUTOFILL_RECEIPT_KEY),
            Some(&expected_json)
        );
        assert_eq!(base, base_before);
        assert_eq!(current, current_before);
    }

    #[test]
    fn update_modified_time_is_monotonic_when_the_clock_moves_backward() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut current = vault_with_entry(&expected);
        let future_modified_at = NOW_MS / 1_000 + 100;
        find_entry_mut(&mut current, ENTRY_ID).unwrap().modified_at = future_modified_at;

        let prepared = execute(&current, &current, &update_plan(expected, desired)).unwrap();

        assert_eq!(
            find_entry(&prepared.candidate, ENTRY_ID)
                .unwrap()
                .0
                .modified_at,
            future_modified_at + 1
        );
    }

    #[test]
    fn update_at_desired_only_restores_receipt_while_third_state_conflicts() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let desired_current = vault_with_entry(&desired);
        let base = desired_current.clone();
        let plan = update_plan(expected.clone(), desired.clone());

        let prepared = execute(&base, &desired_current, &plan).unwrap();
        assert_eq!(history_count(&prepared.candidate, ENTRY_ID), 0);
        assert_eq!(ledger(&prepared.candidate).receipts.len(), 1);

        let third = vault_with_entry(&fields("third-secret"));
        let third_before = third.clone();
        assert_eq!(
            execute(&third, &third, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::UpdatePreconditionFailed
            ))
        );
        assert_eq!(third, third_before);
    }

    #[test]
    fn candidate_preserves_pending_base_entries_and_independent_current_edits() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut original = vault_with_entry(&expected);
        add_entry(&mut original, OTHER_ID, &fields("other-old"));
        set_entry_password_and_modified(&mut original, ENTRY_ID, "old-secret", 10);
        set_entry_password_and_modified(&mut original, OTHER_ID, "other-old", 10);

        let mut base = original.clone();
        add_entry(&mut base, PENDING_ID, &fields("pending-local"));
        let mut current = original.clone();
        set_entry_password_and_modified(&mut current, OTHER_ID, "external-edit", 20);

        let prepared =
            execute_with_baseline(&original, &base, &current, &update_plan(expected, desired))
                .unwrap();

        assert_eq!(
            entry_password(&prepared.candidate, ENTRY_ID).as_deref(),
            Some("new-secret")
        );
        assert_eq!(
            entry_password(&prepared.candidate, OTHER_ID).as_deref(),
            Some("external-edit")
        );
        assert_eq!(
            entry_password(&prepared.candidate, PENDING_ID).as_deref(),
            Some("pending-local")
        );
    }

    #[test]
    fn three_way_merge_preserves_one_sided_entry_reorder_with_other_side_value_change() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut baseline = vault_with_entry(&expected);
        add_entry(&mut baseline, OTHER_ID, &fields("other-secret"));
        let mut local = baseline.clone();
        local.root.entries.swap(0, 1);
        let mut current = baseline.clone();
        find_entry_mut(&mut current, OTHER_ID)
            .unwrap()
            .tags
            .insert("remote-edit".into());

        let candidate =
            execute_with_baseline(&baseline, &local, &current, &update_plan(expected, desired))
                .unwrap()
                .candidate;

        assert_eq!(root_entry_ids(&candidate), vec![OTHER_ID, ENTRY_ID]);
        assert!(
            find_entry(&candidate, OTHER_ID)
                .unwrap()
                .0
                .tags
                .contains("remote-edit")
        );
    }

    #[test]
    fn three_way_merge_preserves_one_sided_group_reorder_with_other_side_value_change() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut baseline = vault_with_entry(&expected);
        let mut group_a = Group::new("A");
        group_a.id = Uuid::parse_str(GROUP_A_ID).unwrap();
        let mut group_b = Group::new("B");
        group_b.id = Uuid::parse_str(GROUP_B_ID).unwrap();
        baseline.root.children = vec![group_a, group_b];
        let mut local = baseline.clone();
        local.root.children.swap(0, 1);
        let mut current = baseline.clone();
        current.root.children[1].notes = "remote-edit".into();

        let candidate =
            execute_with_baseline(&baseline, &local, &current, &update_plan(expected, desired))
                .unwrap()
                .candidate;

        assert_eq!(root_child_ids(&candidate), vec![GROUP_B_ID, GROUP_A_ID]);
        assert_eq!(candidate.root.children[0].notes, "remote-edit");
    }

    #[test]
    fn sibling_order_reconciliation_moves_attachment_storage_without_cloning_it() {
        let expected = fields("old-secret");
        let mut baseline = vault_with_entry(&expected);
        add_entry(&mut baseline, OTHER_ID, &fields("other-secret"));
        find_entry_mut(&mut baseline, ENTRY_ID)
            .unwrap()
            .attachments
            .insert(
                "large.bin".into(),
                vaultkern_core::Attachment {
                    name: "large.bin".into(),
                    data: vec![0x5a; 4_096],
                    protect_in_memory: false,
                },
            );
        let mut local = baseline.clone();
        local.root.entries.swap(0, 1);
        let mut current = baseline.clone();
        find_entry_mut(&mut current, OTHER_ID)
            .unwrap()
            .tags
            .insert("remote-edit".into());
        let mut candidate = merge_autofill_candidate(&baseline, &local, &current).unwrap();
        let before = find_entry(&candidate, ENTRY_ID).unwrap().0.attachments["large.bin"]
            .data
            .as_ptr();

        reconcile_candidate_sibling_orders(&baseline, &local, &current, &mut candidate).unwrap();

        let after = find_entry(&candidate, ENTRY_ID).unwrap().0.attachments["large.bin"]
            .data
            .as_ptr();
        assert_eq!(after, before);
        assert_eq!(root_entry_ids(&candidate), vec![OTHER_ID, ENTRY_ID]);
    }

    #[test]
    fn three_way_merge_rejects_independent_same_parent_insertions() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let baseline = vault_with_entry(&expected);
        let mut local = baseline.clone();
        add_entry(&mut local, OTHER_ID, &fields("local-insert"));
        let mut current = baseline.clone();
        add_entry(&mut current, PENDING_ID, &fields("current-insert"));

        assert!(matches!(
            execute_with_baseline(&baseline, &local, &current, &update_plan(expected, desired),),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn three_way_merge_rejects_different_concurrent_reorders() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut baseline = vault_with_entry(&expected);
        add_entry(&mut baseline, OTHER_ID, &fields("other-secret"));
        add_entry(&mut baseline, PENDING_ID, &fields("pending-secret"));
        let mut local = baseline.clone();
        local.root.entries.swap(0, 1);
        let mut current = baseline.clone();
        current.root.entries.swap(1, 2);

        assert!(matches!(
            execute_with_baseline(&baseline, &local, &current, &update_plan(expected, desired),),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn current_deletion_and_move_of_unrelated_entries_are_not_resurrected_or_duplicated() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let core = KeepassCore::new();
        let mut original = vault_with_entry(&expected);
        add_entry(&mut original, OTHER_ID, &fields("other-secret"));
        let root_id = original.root.id.to_string();
        let group_a = core.add_group(&mut original, &root_id, "A").unwrap().id;
        let group_b = core.add_group(&mut original, &root_id, "B").unwrap().id;
        core.move_entry(&mut original, OTHER_ID, &group_a).unwrap();
        let mut local = original.clone();
        add_entry(&mut local, PENDING_ID, &fields("pending-local"));

        let mut deleted = original.clone();
        core.delete_entry(&mut deleted, OTHER_ID).unwrap();
        deleted.deleted_objects.push(DeletedObject {
            id: Uuid::parse_str(OTHER_ID).unwrap(),
            deleted_at: 42,
        });
        let deleted_candidate = execute_with_baseline(
            &original,
            &local,
            &deleted,
            &update_plan(expected.clone(), desired.clone()),
        )
        .unwrap()
        .candidate;
        assert!(find_entry(&deleted_candidate, OTHER_ID).is_none());
        assert!(find_entry(&deleted_candidate, PENDING_ID).is_some());
        assert!(
            deleted_candidate
                .deleted_objects
                .iter()
                .any(|item| item.id.to_string() == OTHER_ID)
        );

        let mut moved = original.clone();
        core.move_entry(&mut moved, OTHER_ID, &group_b).unwrap();
        let moved_candidate =
            execute_with_baseline(&original, &local, &moved, &update_plan(expected, desired))
                .unwrap()
                .candidate;
        let other_id = Uuid::parse_str(OTHER_ID).unwrap();
        assert_eq!(count_entry_id(&moved_candidate.root, other_id), 1);
        assert!(find_entry(&moved_candidate, PENDING_ID).is_some());
        assert_eq!(
            locate_entry(&moved_candidate.root, other_id).map(|(parent, _, _)| parent),
            Some(Uuid::parse_str(&group_b).unwrap())
        );
    }

    #[test]
    fn three_way_merge_preserves_disjoint_unknown_metadata_changes() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let mut base = original.clone();
        base.meta_custom_data
            .insert("local.pending".into(), "local".into());
        let mut current = original.clone();
        current
            .meta_custom_data
            .insert("external.current".into(), "remote".into());

        let candidate =
            execute_with_baseline(&original, &base, &current, &update_plan(expected, desired))
                .unwrap()
                .candidate;

        assert_eq!(
            candidate
                .meta_custom_data
                .get("local.pending")
                .map(String::as_str),
            Some("local")
        );
        assert_eq!(
            candidate
                .meta_custom_data
                .get("external.current")
                .map(String::as_str),
            Some("remote")
        );
    }

    #[test]
    fn divergent_concurrent_change_to_the_same_unrelated_entry_fails_closed() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut original = vault_with_entry(&expected);
        add_entry(&mut original, OTHER_ID, &fields("other-old"));
        set_entry_password_and_modified(&mut original, OTHER_ID, "other-old", 10);
        let mut base = original.clone();
        set_entry_password_and_modified(&mut base, OTHER_ID, "local-edit", 20);
        let mut current = original.clone();
        set_entry_password_and_modified(&mut current, OTHER_ID, "external-edit", 30);

        assert!(matches!(
            execute_with_baseline(&original, &base, &current, &update_plan(expected, desired),),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn divergent_concurrent_non_field_changes_to_the_target_fail_closed() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let mut local = original.clone();
        find_entry_mut(&mut local, ENTRY_ID)
            .unwrap()
            .tags
            .insert("local-tag".into());
        let mut current = original.clone();
        find_entry_mut(&mut current, ENTRY_ID)
            .unwrap()
            .tags
            .insert("current-tag".into());

        assert!(matches!(
            execute_with_baseline(&original, &local, &current, &update_plan(expected, desired)),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn raw_current_third_state_conflicts_even_when_timestamp_merge_prefers_base_expected() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut base = vault_with_entry(&expected);
        let mut current = base.clone();
        set_entry_password_and_modified(&mut base, ENTRY_ID, "old-secret", 100);
        set_entry_password_and_modified(&mut current, ENTRY_ID, "third-secret", 50);
        let base_before = base.clone();
        let current_before = current.clone();

        assert_eq!(
            execute(&base, &current, &update_plan(expected, desired)),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::UpdatePreconditionFailed
            ))
        );
        assert_eq!(base, base_before);
        assert_eq!(current, current_before);
    }

    #[test]
    fn old_in_memory_update_without_receipt_conflicts_with_a_changed_source() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let current = vault_with_entry(&expected);
        let mut base = current.clone();
        set_entry_password_and_modified(&mut base, ENTRY_ID, "old-secret", 10);
        let core = KeepassCore::new();
        core.snapshot_entry_to_history(&mut base, ENTRY_ID).unwrap();
        set_entry_password_and_modified(&mut base, ENTRY_ID, "new-secret", 20);
        let mut raw_current = current.clone();
        set_entry_password_and_modified(&mut raw_current, ENTRY_ID, "old-secret", 10);

        assert!(matches!(
            execute_with_baseline(
                &current,
                &base,
                &raw_current,
                &update_plan(expected, desired),
            ),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn concurrent_exact_target_postcondition_without_receipt_fails_closed() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut baseline = vault_with_entry(&expected);
        set_entry_password_and_modified(&mut baseline, ENTRY_ID, "old-secret", 10);
        let mut base = baseline.clone();
        KeepassCore::new()
            .snapshot_entry_to_history(&mut base, ENTRY_ID)
            .unwrap();
        set_entry_password_and_modified(&mut base, ENTRY_ID, "new-secret", 20);
        let mut current = baseline.clone();
        set_entry_password_and_modified(&mut current, ENTRY_ID, "new-secret", 30);

        assert!(matches!(
            execute_with_baseline(&baseline, &base, &current, &update_plan(expected, desired)),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn receipt_replay_preserves_a_local_target_only_reorder_for_publish() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut original = vault_with_entry(&expected);
        add_entry(&mut original, OTHER_ID, &fields("other-secret"));
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let mut local = committed.clone();
        local.root.entries.swap(0, 1);

        let replayed = execute_with_baseline(&committed, &local, &committed, &plan).unwrap();

        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(
            root_entry_ids(&replayed.candidate),
            vec![OTHER_ID, ENTRY_ID]
        );
    }

    #[test]
    fn base_only_receipt_recovery_preserves_the_current_target_reorder() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut original = vault_with_entry(&expected);
        add_entry(&mut original, OTHER_ID, &fields("other-secret"));
        let plan = update_plan(expected, desired);
        let base_with_receipt = execute(&original, &original, &plan).unwrap().candidate;
        let mut current = base_with_receipt.clone();
        current.meta_custom_data.remove(AUTOFILL_RECEIPT_KEY);
        current.root.entries.swap(0, 1);

        let recovered = execute(&base_with_receipt, &current, &plan).unwrap();

        assert_eq!(
            recovered.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(
            root_entry_ids(&recovered.candidate),
            vec![OTHER_ID, ENTRY_ID]
        );
    }

    #[test]
    fn current_receipt_replays_without_overwriting_later_entry_edit_or_delete() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let core = KeepassCore::new();

        let mut edited = committed.clone();
        core.update_entry_fields(
            &mut edited,
            ENTRY_ID,
            EntryUpdate {
                password: Some("later-edit".into()),
                ..EntryUpdate::default()
            },
        )
        .unwrap();
        let replayed = execute(&original, &edited, &plan).unwrap();
        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::Replayed {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(replayed.candidate, edited);

        let mut deleted = committed.clone();
        core.delete_entry(&mut deleted, ENTRY_ID).unwrap();
        let replayed = execute(&original, &deleted, &plan).unwrap();
        assert!(
            KeepassCore::new()
                .find_entry_view_by_id(&replayed.candidate, ENTRY_ID)
                .is_none()
        );
        assert_eq!(replayed.candidate, deleted);
    }

    #[test]
    fn current_receipt_replay_preserves_pending_base_changes_for_publish() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let mut base_with_pending = original.clone();
        add_entry(&mut base_with_pending, PENDING_ID, &fields("pending-local"));

        let replayed =
            execute_with_baseline(&original, &base_with_pending, &committed, &plan).unwrap();

        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(
            entry_password(&replayed.candidate, PENDING_ID).as_deref(),
            Some("pending-local")
        );
        assert_eq!(
            entry_password(&replayed.candidate, ENTRY_ID).as_deref(),
            Some("new-secret")
        );
        assert_eq!(ledger(&replayed.candidate).receipts.len(), 1);
    }

    #[test]
    fn receipts_on_both_sources_preserve_later_local_target_edit_and_delete() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;

        let mut locally_edited = committed.clone();
        KeepassCore::new()
            .update_entry_fields(
                &mut locally_edited,
                ENTRY_ID,
                EntryUpdate {
                    password: Some("local-later-edit".into()),
                    ..EntryUpdate::default()
                },
            )
            .unwrap();
        let replayed =
            execute_with_baseline(&committed, &locally_edited, &committed, &plan).unwrap();
        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(
            entry_password(&replayed.candidate, ENTRY_ID).as_deref(),
            Some("local-later-edit")
        );

        let mut locally_deleted = committed.clone();
        KeepassCore::new()
            .delete_entry(&mut locally_deleted, ENTRY_ID)
            .unwrap();
        let replayed =
            execute_with_baseline(&committed, &locally_deleted, &committed, &plan).unwrap();
        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert!(find_entry(&replayed.candidate, ENTRY_ID).is_none());

        let mut locally_recycled = committed.clone();
        KeepassCore::new()
            .soft_delete_entry_to_recycle_bin(&mut locally_recycled, ENTRY_ID)
            .unwrap();
        let replayed =
            execute_with_baseline(&committed, &locally_recycled, &committed, &plan).unwrap();
        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::ReplayedNeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert!(find_entry(&replayed.candidate, ENTRY_ID).unwrap().1);
        assert!(
            replayed
                .candidate
                .deleted_objects
                .iter()
                .any(|item| item.id.to_string() == ENTRY_ID)
        );
    }

    #[test]
    fn receipts_on_both_sources_preserve_a_one_sided_current_target_edit() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let mut current = committed.clone();
        set_entry_password_and_modified(&mut current, ENTRY_ID, "current-later-edit", 100);

        let replayed = execute_with_baseline(&committed, &committed, &current, &plan).unwrap();

        assert_eq!(
            replayed.outcome,
            AutofillPersistLogicalOutcome::Replayed {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(replayed.candidate, current);
    }

    #[test]
    fn receipts_on_both_sources_preserve_one_sided_current_move_and_deleted_marker() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let mut original = vault_with_entry(&expected);
        let root_id = original.root.id.to_string();
        let target_group_id = KeepassCore::new()
            .add_group(&mut original, &root_id, "Moved target")
            .unwrap()
            .id;
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let mut current = committed.clone();
        KeepassCore::new()
            .move_entry(&mut current, ENTRY_ID, &target_group_id)
            .unwrap();
        current.deleted_objects.push(DeletedObject {
            id: Uuid::parse_str(ENTRY_ID).unwrap(),
            deleted_at: 200,
        });

        let replayed = execute_with_baseline(&committed, &committed, &current, &plan).unwrap();

        assert_eq!(replayed.candidate, current);
    }

    #[test]
    fn receipts_on_both_sources_reject_concurrent_hard_delete_and_recycle() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;
        let mut local = committed.clone();
        let mut current = committed.clone();
        KeepassCore::new()
            .delete_entry(&mut local, ENTRY_ID)
            .unwrap();
        KeepassCore::new()
            .soft_delete_entry_to_recycle_bin(&mut current, ENTRY_ID)
            .unwrap();

        assert!(matches!(
            execute_with_baseline(&committed, &local, &current, &plan),
            Err(AutofillPersistEngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn receipts_on_both_sources_reject_divergent_target_edits_regardless_of_timestamp() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let committed = execute(&original, &original, &plan).unwrap().candidate;

        for (local_modified_at, current_modified_at) in [(100, 100), (100, 101), (101, 100)] {
            let mut local = committed.clone();
            let mut current = committed.clone();
            set_entry_password_and_modified(
                &mut local,
                ENTRY_ID,
                "local-later-edit",
                local_modified_at,
            );
            set_entry_password_and_modified(
                &mut current,
                ENTRY_ID,
                "current-later-edit",
                current_modified_at,
            );

            assert!(matches!(
                execute_with_baseline(&committed, &local, &current, &plan),
                Err(AutofillPersistEngineError::MergeConflict(_))
            ));
        }
    }

    #[test]
    fn base_only_update_receipt_requires_exact_current_postcondition() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected.clone(), desired.clone());
        let base_with_receipt = execute(&original, &original, &plan).unwrap().candidate;

        let mut current_desired = base_with_receipt.clone();
        current_desired
            .meta_custom_data
            .remove(AUTOFILL_RECEIPT_KEY);
        let restored = execute(&base_with_receipt, &current_desired, &plan).unwrap();
        assert_eq!(
            restored.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert_eq!(history_count(&restored.candidate, ENTRY_ID), 1);

        let mut base_deleted_after_receipt = base_with_receipt.clone();
        KeepassCore::new()
            .delete_entry(&mut base_deleted_after_receipt, ENTRY_ID)
            .unwrap();
        let restored = execute(&base_deleted_after_receipt, &current_desired, &plan).unwrap();
        assert_eq!(
            restored.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: ENTRY_ID.into()
            }
        );
        assert!(find_entry(&restored.candidate, ENTRY_ID).is_none());

        let current_expected = original.clone();
        assert_eq!(
            execute(&base_with_receipt, &current_expected, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::UpdatePreconditionFailed
            ))
        );
        let mut current_third = original;
        set_entry_password_and_modified(&mut current_third, ENTRY_ID, "third-secret", 20);
        assert_eq!(
            execute(&base_with_receipt, &current_third, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::UpdatePreconditionFailed
            ))
        );
    }

    #[test]
    fn receipt_binding_mismatch_conflicts_for_current_or_base_provenance() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let original = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let with_receipt = execute(&original, &original, &plan).unwrap().candidate;

        assert_eq!(
            execute_with_binding(
                &original,
                &with_receipt,
                &original,
                &plan,
                "transaction-other",
                OPERATION_ID,
                NOW_MS
            ),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::OperationBindingMismatch
            ))
        );
        assert_eq!(
            execute_with_binding(
                &with_receipt,
                &original,
                &with_receipt,
                &plan,
                "transaction-other",
                OPERATION_ID,
                NOW_MS
            ),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::OperationBindingMismatch
            ))
        );
    }

    #[test]
    fn create_uses_planned_id_once_and_stripped_receipt_fallback_never_duplicates() {
        let current = empty_vault();
        let base = current.clone();
        let plan = create_plan(&current.root.id.to_string(), vec![], fields("secret"));

        let first = execute(&base, &current, &plan).unwrap();
        assert_eq!(
            first.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: PLANNED_ID.into()
            }
        );
        assert_eq!(entry_count(&first.candidate), 1);
        assert_eq!(
            entry_password(&first.candidate, PLANNED_ID).as_deref(),
            Some("secret")
        );

        let replay = execute(&base, &first.candidate, &plan).unwrap();
        assert_eq!(
            replay.outcome,
            AutofillPersistLogicalOutcome::Replayed {
                entry_id: PLANNED_ID.into()
            }
        );
        assert_eq!(entry_count(&replay.candidate), 1);

        let mut stripped = first.candidate.clone();
        stripped.meta_custom_data.remove(AUTOFILL_RECEIPT_KEY);
        let restored = execute(&stripped, &stripped, &plan).unwrap();
        assert_eq!(
            restored.outcome,
            AutofillPersistLogicalOutcome::NeedsPublish {
                entry_id: PLANNED_ID.into()
            }
        );
        assert_eq!(entry_count(&restored.candidate), 1);
        assert_eq!(ledger(&restored.candidate).receipts.len(), 1);
    }

    #[test]
    fn create_rejects_planned_id_collision_and_matching_set_change() {
        let desired = fields("secret");
        let mut collision = empty_vault();
        add_entry(&mut collision, PLANNED_ID, &fields("different"));
        let collision_plan = create_plan(&collision.root.id.to_string(), vec![], desired.clone());
        assert_eq!(
            execute(&collision, &collision, &collision_plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision
            ))
        );

        let mut changed = empty_vault();
        add_entry(&mut changed, OTHER_ID, &desired);
        let changed_plan = create_plan(&changed.root.id.to_string(), vec![], desired);
        assert_eq!(
            execute(&changed, &changed, &changed_plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::CreateMatchingSetChanged
            ))
        );
    }

    #[test]
    fn create_existing_exact_id_is_adopted_only_when_absent_from_baseline() {
        let desired = fields("secret");
        let mut current = empty_vault();
        add_entry(&mut current, PLANNED_ID, &desired);
        let parent = current.root.id.to_string();

        let adopted = execute(
            &current,
            &current,
            &create_plan(&parent, vec![], desired.clone()),
        )
        .unwrap();
        assert_eq!(entry_count(&adopted.candidate), 1);
        assert_eq!(history_count(&adopted.candidate, PLANNED_ID), 0);

        assert_eq!(
            execute(
                &current,
                &current,
                &create_plan(&parent, vec![PLANNED_ID.into()], desired),
            ),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision
            ))
        );
    }

    #[test]
    fn base_only_create_receipt_never_recreates_a_missing_or_changed_result() {
        let current = empty_vault();
        let plan = create_plan(&current.root.id.to_string(), vec![], fields("secret"));
        let base_with_receipt = execute(&current, &current, &plan).unwrap().candidate;

        assert_eq!(
            execute(&base_with_receipt, &current, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision
            ))
        );
        let mut exact = current.clone();
        add_entry(&mut exact, PLANNED_ID, &fields("secret"));
        let restored = execute(&base_with_receipt, &exact, &plan).unwrap();
        assert_eq!(entry_count(&restored.candidate), 1);
        assert_eq!(history_count(&restored.candidate, PLANNED_ID), 0);

        let mut changed = current.clone();
        add_entry(&mut changed, PLANNED_ID, &fields("later-edit"));
        assert_eq!(
            execute(&base_with_receipt, &changed, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision
            ))
        );
    }

    #[test]
    fn current_create_receipt_replays_after_later_edit_or_delete() {
        let current = empty_vault();
        let plan = create_plan(&current.root.id.to_string(), vec![], fields("secret"));
        let committed = execute(&current, &current, &plan).unwrap().candidate;
        let core = KeepassCore::new();

        let mut edited = committed.clone();
        core.update_entry_fields(
            &mut edited,
            PLANNED_ID,
            EntryUpdate {
                password: Some("later-edit".into()),
                ..EntryUpdate::default()
            },
        )
        .unwrap();
        assert_eq!(execute(&current, &edited, &plan).unwrap().candidate, edited);

        let mut deleted = committed;
        core.delete_entry(&mut deleted, PLANNED_ID).unwrap();
        assert_eq!(
            execute(&current, &deleted, &plan).unwrap().candidate,
            deleted
        );
    }

    #[test]
    fn ledger_is_canonical_deduped_pruned_and_never_drops_current_operation() {
        let desired = fields("new-secret");
        let current = vault_with_entry(&desired);
        let mut base = current.clone();
        let plan = update_plan(fields("old-secret"), desired);
        let plan_sha = plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &plan).unwrap();
        let receipts = (0..MAX_RECEIPTS)
            .map(|index| {
                receipt(
                    &format!("historical-{index:02}"),
                    &format!("transaction-{index:02}"),
                    &plan_sha,
                    &uuid::Uuid::from_u128(index as u128 + 1).to_string(),
                    NOW_MS,
                )
            })
            .collect();
        base.meta_custom_data.insert(
            AUTOFILL_RECEIPT_KEY.into(),
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION,
                receipts,
            })
            .unwrap(),
        );

        let prepared = execute(&base, &current, &plan).unwrap();
        let ledger = ledger(&prepared.candidate);
        assert_eq!(ledger.receipts.len(), MAX_RECEIPTS);
        assert!(
            ledger
                .receipts
                .iter()
                .any(|item| item.operation_id == OPERATION_ID)
        );
        assert!(
            !ledger
                .receipts
                .iter()
                .any(|item| item.operation_id == "historical-00")
        );
        let canonical = serde_json::to_string(&ledger).unwrap();
        assert_eq!(
            prepared
                .candidate
                .meta_custom_data
                .get(AUTOFILL_RECEIPT_KEY),
            Some(&canonical)
        );
    }

    #[test]
    fn ledger_dedupes_identical_bindings_and_rejects_conflicting_results() {
        let desired = fields("new-secret");
        let current = vault_with_entry(&desired);
        let plan = update_plan(fields("old-secret"), desired);
        let plan_sha = plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &plan).unwrap();
        let mut base = current.clone();
        let duplicate = receipt(
            "historical",
            "transaction-h",
            &plan_sha,
            OTHER_ID,
            NOW_MS - 20,
        );
        base.meta_custom_data.insert(
            AUTOFILL_RECEIPT_KEY.into(),
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION,
                receipts: vec![
                    duplicate.clone(),
                    AutofillReceipt {
                        committed_at_epoch_ms: NOW_MS - 10,
                        ..duplicate.clone()
                    },
                ],
            })
            .unwrap(),
        );

        let prepared = execute(&base, &current, &plan).unwrap();
        let historical: Vec<_> = ledger(&prepared.candidate)
            .receipts
            .into_iter()
            .filter(|item| item.operation_id == "historical")
            .collect();
        assert_eq!(historical.len(), 1);
        assert_eq!(historical[0].committed_at_epoch_ms, NOW_MS - 10);

        let mut conflicting = current.clone();
        conflicting.meta_custom_data.insert(
            AUTOFILL_RECEIPT_KEY.into(),
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION,
                receipts: vec![
                    duplicate.clone(),
                    AutofillReceipt {
                        entry_id: PENDING_ID.into(),
                        ..duplicate
                    },
                ],
            })
            .unwrap(),
        );
        assert_eq!(
            execute(&current, &conflicting, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::OperationBindingMismatch
            ))
        );
    }

    #[test]
    fn ledger_rejects_unknown_version_and_prunes_receipts_older_than_thirty_days() {
        let desired = fields("new-secret");
        let current = vault_with_entry(&desired);
        let plan = update_plan(fields("old-secret"), desired);
        let plan_sha = plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &plan).unwrap();
        let mut unknown_version = current.clone();
        unknown_version.meta_custom_data.insert(
            AUTOFILL_RECEIPT_KEY.into(),
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION + 1,
                receipts: vec![],
            })
            .unwrap(),
        );
        assert!(matches!(
            execute(&current, &unknown_version, &plan),
            Err(AutofillPersistEngineError::InvalidLedger(_))
        ));

        let mut base = current.clone();
        base.meta_custom_data.insert(
            AUTOFILL_RECEIPT_KEY.into(),
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION,
                receipts: vec![
                    receipt(
                        "expired",
                        "transaction-expired",
                        &plan_sha,
                        OTHER_ID,
                        NOW_MS - RECEIPT_RETENTION_MS - 1,
                    ),
                    receipt(
                        "retained",
                        "transaction-retained",
                        &plan_sha,
                        PENDING_ID,
                        NOW_MS - RECEIPT_RETENTION_MS + 1,
                    ),
                ],
            })
            .unwrap(),
        );

        let ids: Vec<_> = ledger(&execute(&base, &current, &plan).unwrap().candidate)
            .receipts
            .into_iter()
            .map(|item| item.operation_id)
            .collect();
        assert!(!ids.iter().any(|id| id == "expired"));
        assert!(ids.iter().any(|id| id == "retained"));
        assert!(ids.iter().any(|id| id == OPERATION_ID));
    }

    #[test]
    fn malformed_or_oversized_ledgers_fail_closed() {
        let expected = fields("old-secret");
        let desired = fields("new-secret");
        let pristine = vault_with_entry(&expected);
        let plan = update_plan(expected, desired);
        let plan_sha = plan_sha256(TRANSACTION_ID, VAULT_ID, SOURCE_SHA, &plan).unwrap();

        let mut malformed_values = vec!["{".into(), "x".repeat(MAX_LEDGER_BYTES + 1)];
        let receipts = (0..=MAX_RECEIPTS)
            .map(|index| {
                receipt(
                    &format!("operation-{index}"),
                    &format!("transaction-{index}"),
                    &plan_sha,
                    &uuid::Uuid::from_u128(index as u128 + 1).to_string(),
                    NOW_MS,
                )
            })
            .collect();
        malformed_values.push(
            serde_json::to_string(&ReceiptLedger {
                version: RECEIPT_VERSION,
                receipts,
            })
            .unwrap(),
        );

        for value in malformed_values {
            let mut current = pristine.clone();
            current
                .meta_custom_data
                .insert(AUTOFILL_RECEIPT_KEY.into(), value);
            let current_before = current.clone();
            assert!(matches!(
                execute(&pristine, &current, &plan),
                Err(AutofillPersistEngineError::InvalidLedger(_))
            ));
            assert_eq!(current, current_before);
        }
    }

    #[test]
    fn planned_id_deleted_marker_is_a_collision_without_partial_candidate() {
        let mut current = empty_vault();
        current.deleted_objects.push(DeletedObject {
            id: uuid::Uuid::parse_str(PLANNED_ID).unwrap(),
            deleted_at: 1,
        });
        let plan = create_plan(&current.root.id.to_string(), vec![], fields("secret"));
        assert_eq!(
            execute(&current, &current, &plan),
            Err(AutofillPersistEngineError::Conflict(
                AutofillPersistConflictCodeDto::PlannedEntryIdCollision
            ))
        );
        assert_eq!(entry_count(&current), 0);
    }
}
