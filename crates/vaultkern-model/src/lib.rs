use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Weak};

#[cfg(test)]
use std::sync::atomic::AtomicBool;

use data_encoding::BASE32_NOPAD;
use thiserror::Error;
use uuid::Uuid;
use vaultkern_crypto::{OtpAlgorithm, generate_totp};
use zeroize::{Zeroize, Zeroizing};

mod canonical_serialization;

pub use canonical_serialization::{
    CANONICAL_ENTRY_SCHEMA_VERSION_V1, CANONICAL_SERIALIZATION_MAGIC, CanonicalSerializationError,
    canonical_entry_bytes_v1, canonical_entry_content_hash_v1,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("feature not implemented yet")]
    Unimplemented,
    #[error("entry not found")]
    EntryNotFound,
    #[error("attachment content hash collision")]
    AttachmentContentHashCollision,
}

pub type Result<T> = std::result::Result<T, ModelError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomField {
    pub value: String,
    pub protected: bool,
}

enum MaterializedPersistentValue<'a> {
    Borrowed(&'a str),
    Owned(Zeroizing<String>),
}

/// One field in the transient persistent-attribute view.
pub struct MaterializedPersistentAttribute<'a> {
    value: MaterializedPersistentValue<'a>,
    protected: bool,
}

impl MaterializedPersistentAttribute<'_> {
    pub fn value(&self) -> &str {
        match &self.value {
            MaterializedPersistentValue::Borrowed(value) => value,
            MaterializedPersistentValue::Owned(value) => value.as_str(),
        }
    }

    pub fn protected(&self) -> bool {
        self.protected
    }
}

impl fmt::Debug for MaterializedPersistentAttribute<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedPersistentAttribute")
            .field("value", &"[REDACTED]")
            .field("protected", &self.protected)
            .finish()
    }
}

/// Transient materialized entry attributes shared by canonical and KDBX writers.
pub struct MaterializedPersistentAttributes<'a> {
    fields: BTreeMap<String, MaterializedPersistentAttribute<'a>>,
    has_projectable_passkey: bool,
}

impl<'a> MaterializedPersistentAttributes<'a> {
    fn from_entry(attributes: &'a BTreeMap<String, CustomField>) -> Self {
        Self {
            fields: attributes
                .iter()
                .map(|(key, field)| {
                    (
                        key.clone(),
                        MaterializedPersistentAttribute {
                            value: MaterializedPersistentValue::Borrowed(&field.value),
                            protected: field.protected,
                        },
                    )
                })
                .collect(),
            has_projectable_passkey: false,
        }
    }

    fn insert_borrowed(&mut self, key: impl Into<String>, value: &'a str, protected: bool) {
        self.fields.insert(
            key.into(),
            MaterializedPersistentAttribute {
                value: MaterializedPersistentValue::Borrowed(value),
                protected,
            },
        );
    }

    fn insert_static(&mut self, key: impl Into<String>, value: &'static str, protected: bool) {
        self.fields.insert(
            key.into(),
            MaterializedPersistentAttribute {
                value: MaterializedPersistentValue::Borrowed(value),
                protected,
            },
        );
    }

    fn insert_owned(
        &mut self,
        key: impl Into<String>,
        value: impl Into<Zeroizing<String>>,
        protected: bool,
    ) {
        self.fields.insert(
            key.into(),
            MaterializedPersistentAttribute {
                value: MaterializedPersistentValue::Owned(value.into()),
                protected,
            },
        );
    }

    fn insert_value(
        &mut self,
        key: impl Into<String>,
        value: MaterializedPersistentValue<'a>,
        protected: bool,
    ) {
        self.fields.insert(
            key.into(),
            MaterializedPersistentAttribute { value, protected },
        );
    }

    pub fn get(&self, key: &str) -> Option<&MaterializedPersistentAttribute<'a>> {
        self.fields.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn has_projectable_passkey(&self) -> bool {
        self.has_projectable_passkey
    }

    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (&str, &MaterializedPersistentAttribute<'a>)> {
        self.fields.iter().map(|(key, field)| (key.as_str(), field))
    }

    #[cfg(test)]
    fn to_custom_fields_for_test(&self) -> BTreeMap<String, CustomField> {
        self.iter()
            .map(|(key, field)| {
                (
                    key.to_owned(),
                    CustomField {
                        value: field.value().to_owned(),
                        protected: field.protected(),
                    },
                )
            })
            .collect()
    }
}

impl fmt::Debug for MaterializedPersistentAttributes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.fields.iter()).finish()
    }
}

impl<'a> std::ops::Index<&str> for MaterializedPersistentAttributes<'a> {
    type Output = MaterializedPersistentAttribute<'a>;

    fn index(&self, key: &str) -> &Self::Output {
        &self.fields[key]
    }
}

impl<'a> std::ops::Index<&String> for MaterializedPersistentAttributes<'a> {
    type Output = MaterializedPersistentAttribute<'a>;

    fn index(&self, key: &String) -> &Self::Output {
        &self.fields[key]
    }
}

impl PartialEq<BTreeMap<String, CustomField>> for MaterializedPersistentAttributes<'_> {
    fn eq(&self, other: &BTreeMap<String, CustomField>) -> bool {
        self.len() == other.len()
            && self.iter().all(|(key, field)| {
                other.get(key).is_some_and(|other| {
                    field.value() == other.value && field.protected() == other.protected
                })
            })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentContentId([u8; 32]);

impl AttachmentContentId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(vaultkern_crypto::sha256_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AttachmentContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AttachmentContentId")
            .field(&self.0)
            .finish()
    }
}

struct AttachmentContentInner {
    id: AttachmentContentId,
    bytes: Vec<u8>,
    #[cfg(test)]
    drop_probe: Option<Arc<AtomicBool>>,
}

impl Drop for AttachmentContentInner {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // Volatile stores keep the final-owner wipe observable to the allocator.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            probe.store(
                self.bytes.iter().all(|byte| *byte == 0),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }
}

#[derive(Clone)]
pub struct AttachmentContent(Arc<AttachmentContentInner>);

impl AttachmentContent {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let id = AttachmentContentId::from_bytes(&bytes);
        Self::from_parts(id, bytes)
    }

    fn from_parts(id: AttachmentContentId, bytes: Vec<u8>) -> Self {
        Self(Arc::new(AttachmentContentInner {
            id,
            bytes,
            #[cfg(test)]
            drop_probe: None,
        }))
    }

    pub fn id(&self) -> AttachmentContentId {
        self.0.id
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn len(&self) -> usize {
        self.0.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.bytes.is_empty()
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    #[cfg(test)]
    fn strong_count(&self) -> usize {
        Arc::strong_count(&self.0)
    }

    #[cfg(test)]
    fn new_with_drop_probe_for_test(bytes: &[u8], probe: Arc<AtomicBool>) -> Self {
        Self(Arc::new(AttachmentContentInner {
            id: AttachmentContentId::from_bytes(bytes),
            bytes: bytes.to_vec(),
            drop_probe: Some(probe),
        }))
    }
}

impl fmt::Debug for AttachmentContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentContent")
            .field("id", &self.id())
            .field("len", &self.len())
            .finish()
    }
}

impl PartialEq for AttachmentContent {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for AttachmentContent {}

impl std::ops::Deref for AttachmentContent {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for AttachmentContent {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq<Vec<u8>> for AttachmentContent {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

#[derive(Debug, Default)]
pub struct AttachmentContentPool {
    contents: BTreeMap<AttachmentContentId, Weak<AttachmentContentInner>>,
}

impl AttachmentContentPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, bytes: &[u8]) -> Result<AttachmentContent> {
        let id = AttachmentContentId::from_bytes(bytes);
        self.intern_with_id(id, bytes)
    }

    pub fn intern_vec(&mut self, bytes: Vec<u8>) -> Result<AttachmentContent> {
        let id = AttachmentContentId::from_bytes(&bytes);
        if let Some(existing) = self.contents.get(&id).and_then(Weak::upgrade) {
            if existing.bytes != bytes {
                return Err(ModelError::AttachmentContentHashCollision);
            }
            return Ok(AttachmentContent(existing));
        }

        let content = AttachmentContent::from_parts(id, bytes);
        self.contents.insert(id, Arc::downgrade(&content.0));
        Ok(content)
    }

    pub fn intern_content(&mut self, content: &AttachmentContent) -> Result<AttachmentContent> {
        let id = content.id();
        if let Some(existing) = self.contents.get(&id).and_then(Weak::upgrade) {
            if existing.bytes.as_slice() != content.as_bytes() {
                return Err(ModelError::AttachmentContentHashCollision);
            }
            return Ok(AttachmentContent(existing));
        }

        self.contents.insert(id, Arc::downgrade(&content.0));
        Ok(content.clone())
    }

    fn intern_with_id(
        &mut self,
        id: AttachmentContentId,
        bytes: &[u8],
    ) -> Result<AttachmentContent> {
        if let Some(existing) = self.contents.get(&id).and_then(Weak::upgrade) {
            if existing.bytes.as_slice() != bytes {
                return Err(ModelError::AttachmentContentHashCollision);
            }
            return Ok(AttachmentContent(existing));
        }

        let content = AttachmentContent::from_parts(id, bytes.to_vec());
        self.contents.insert(id, Arc::downgrade(&content.0));
        Ok(content)
    }

    #[cfg(test)]
    fn intern_with_id_for_test(
        &mut self,
        id: AttachmentContentId,
        bytes: &[u8],
    ) -> Result<AttachmentContent> {
        self.intern_with_id(id, bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub data: AttachmentContent,
    pub protect_in_memory: bool,
}

impl Attachment {
    pub fn new(
        name: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
        protect_in_memory: bool,
    ) -> Self {
        Self::with_content(
            name,
            AttachmentContent::from_bytes(bytes),
            protect_in_memory,
        )
    }

    pub fn with_content(
        name: impl Into<String>,
        content: AttachmentContent,
        protect_in_memory: bool,
    ) -> Self {
        Self {
            name: name.into(),
            data: content,
            protect_in_memory,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachmentMap(BTreeMap<String, Attachment>);

impl AttachmentMap {
    pub fn insert<V>(&mut self, key: String, value: V) -> Option<Attachment>
    where
        V: Into<Attachment>,
    {
        self.0.insert(key, value.into())
    }
}

impl std::ops::Deref for AttachmentMap {
    type Target = BTreeMap<String, Attachment>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for AttachmentMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObject {
    pub id: Uuid,
    pub deleted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomIcon {
    pub id: Uuid,
    pub data: Vec<u8>,
    pub name: Option<String>,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueXmlAnchor {
    pub element_name: String,
    pub occurrence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueXmlFragment {
    pub xml: String,
    pub after: Option<OpaqueXmlAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataBlock {
    pub items: Vec<CustomDataItem>,
    pub after: Option<OpaqueXmlAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataItem {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

/// Reconciles CustomData's semantic map with its fidelity blocks after a mutation.
pub fn reconcile_custom_data_blocks(
    blocks: &mut Vec<CustomDataBlock>,
    opaque_xml: &mut [OpaqueXmlFragment],
    node_order: &mut Vec<String>,
    merged: &BTreeMap<String, String>,
    updated_item: Option<(&str, Option<i64>)>,
) {
    let mut retained_blocks = Vec::with_capacity(blocks.len());
    let mut retained_occurrences = Vec::with_capacity(blocks.len());
    let mut replacement_anchors = Vec::with_capacity(blocks.len());
    for mut block in std::mem::take(blocks) {
        let was_empty = block.items.is_empty();
        block.items.retain(|item| merged.contains_key(&item.key));
        let retargeted_after =
            retarget_custom_data_anchor(block.after.take(), &replacement_anchors);
        if was_empty || !block.items.is_empty() {
            retained_occurrences.push(true);
            block.after = retargeted_after;
            retained_blocks.push(block);
            replacement_anchors.push(Some(OpaqueXmlAnchor {
                element_name: "CustomData".into(),
                occurrence: retained_blocks.len(),
            }));
        } else {
            retained_occurrences.push(false);
            replacement_anchors.push(retargeted_after);
        }
    }
    *blocks = retained_blocks;
    for fragment in opaque_xml {
        fragment.after = retarget_custom_data_anchor(fragment.after.take(), &replacement_anchors);
    }
    let mut custom_data_occurrence = 0;
    node_order.retain(|name| {
        if name != "CustomData" {
            return true;
        }
        let retained = retained_occurrences
            .get(custom_data_occurrence)
            .copied()
            .unwrap_or(true);
        custom_data_occurrence += 1;
        retained
    });

    let mut last_position_by_key = BTreeMap::new();
    for (block_index, block) in blocks.iter().enumerate() {
        for (item_index, item) in block.items.iter().enumerate() {
            last_position_by_key.insert(item.key.clone(), (block_index, item_index));
        }
    }

    let mut missing_items = Vec::new();
    for (key, value) in merged {
        if let Some(&(block_index, item_index)) = last_position_by_key.get(key) {
            let item = &mut blocks[block_index].items[item_index];
            item.value.clone_from(value);
            if let Some((updated_key, last_modified)) = updated_item
                && updated_key == key
            {
                item.last_modified = last_modified;
            }
        } else {
            let last_modified = updated_item
                .filter(|(updated_key, _)| *updated_key == key)
                .and_then(|(_, last_modified)| last_modified);
            missing_items.push(CustomDataItem {
                key: key.clone(),
                value: value.clone(),
                last_modified,
            });
        }
    }

    if missing_items.is_empty() {
        return;
    }
    if let Some(block) = blocks.last_mut() {
        block.items.extend(missing_items);
    } else {
        blocks.push(CustomDataBlock {
            items: missing_items,
            after: None,
        });
    }
}

fn retarget_custom_data_anchor(
    anchor: Option<OpaqueXmlAnchor>,
    replacement_anchors: &[Option<OpaqueXmlAnchor>],
) -> Option<OpaqueXmlAnchor> {
    let anchor = anchor?;
    if anchor.element_name != "CustomData" {
        return Some(anchor);
    }
    let Some(index) = anchor.occurrence.checked_sub(1) else {
        return Some(anchor);
    };
    replacement_anchors
        .get(index)
        .cloned()
        .unwrap_or(Some(anchor))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetaRawState {
    pub node_order: Vec<String>,
    pub description_raw: Option<String>,
    pub default_username_raw: Option<String>,
    pub color_raw: Option<String>,
    pub memory_protection_auto_enable_visual_hiding_raw: Option<String>,
    pub has_custom_icons_node: bool,
    pub recycle_bin_group_raw: Option<String>,
    pub entry_templates_group_raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootRawState {
    pub node_order: Vec<String>,
    pub has_deleted_objects_node: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupRawState {
    pub node_order: Vec<String>,
    /// UUIDs that own the retained `Entry` fidelity slots in `node_order`.
    pub entry_order: Vec<Uuid>,
    /// UUIDs that own the retained child `Group` fidelity slots in `node_order`.
    pub group_order: Vec<Uuid>,
    pub default_auto_type_sequence_raw: Option<String>,
    pub enable_auto_type_raw: Option<String>,
    pub enable_searching_raw: Option<String>,
    pub last_top_visible_entry_raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryRawState {
    pub node_order: Vec<String>,
    /// Keys that own the retained `String` fidelity slots in `node_order`.
    pub string_order: Vec<String>,
    /// Names that own the retained `Binary` fidelity slots in `node_order`.
    pub binary_order: Vec<String>,
    pub foreground_color_raw: Option<String>,
    pub background_color_raw: Option<String>,
    pub override_url_raw: Option<String>,
    pub tags_raw: Option<String>,
    pub quality_check_raw: Option<String>,
    pub has_history_node: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryProtection {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFieldProtection {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

impl Default for EntryFieldProtection {
    fn default() -> Self {
        Self {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoTypeAssociation {
    pub window: String,
    pub sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutoTypeConfig {
    pub enabled: Option<bool>,
    pub obfuscation: Option<i32>,
    pub default_sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GroupFlags {
    pub is_expanded: Option<bool>,
    pub enable_auto_type: Option<bool>,
    pub enable_searching: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupTimes {
    pub created_at: u64,
    pub modified_at: u64,
    pub expires: bool,
    pub expiry_time: Option<i64>,
    pub last_accessed_at: Option<u64>,
    pub usage_count: Option<u64>,
    pub location_changed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    pub username: String,
    pub credential_id: String,
    pub generated_user_id: Option<String>,
    pub private_key_pem: String,
    pub relying_party: String,
    pub user_handle: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Clone, Copy)]
struct PasskeyPersistentView<'a> {
    username: &'a str,
    credential_id: &'a str,
    generated_user_id: Option<&'a str>,
    private_key_pem: &'a str,
    relying_party: &'a str,
    user_handle: Option<&'a str>,
    backup_eligible: bool,
    backup_state: bool,
}

impl<'a> PasskeyPersistentView<'a> {
    fn from_record(passkey: &'a PasskeyRecord) -> Self {
        Self {
            username: &passkey.username,
            credential_id: &passkey.credential_id,
            generated_user_id: passkey.generated_user_id.as_deref(),
            private_key_pem: &passkey.private_key_pem,
            relying_party: &passkey.relying_party,
            user_handle: passkey.user_handle.as_deref(),
            backup_eligible: passkey.backup_eligible,
            backup_state: passkey.backup_state,
        }
    }

    fn from_attributes(attributes: &'a BTreeMap<String, CustomField>) -> Option<Self> {
        Some(Self {
            username: &attributes.get(PasskeyRecord::USERNAME_KEY)?.value,
            credential_id: &attributes.get(PasskeyRecord::CREDENTIAL_ID_KEY)?.value,
            generated_user_id: attributes
                .get(PasskeyRecord::GENERATED_USER_ID_KEY)
                .map(|field| field.value.as_str()),
            private_key_pem: &attributes.get(PasskeyRecord::PRIVATE_KEY_PEM_KEY)?.value,
            relying_party: &attributes.get(PasskeyRecord::RELYING_PARTY_KEY)?.value,
            user_handle: attributes
                .get(PasskeyRecord::USER_HANDLE_KEY)
                .map(|field| field.value.as_str()),
            backup_eligible: parse_passkey_flag(attributes.get(PasskeyRecord::FLAG_BE_KEY))?,
            backup_state: parse_passkey_flag(attributes.get(PasskeyRecord::FLAG_BS_KEY))?,
        })
    }

    fn visit_attributes(self, mut visit: impl FnMut(&'static str, &'a str, bool)) {
        visit(PasskeyRecord::USERNAME_KEY, self.username, false);
        visit(PasskeyRecord::CREDENTIAL_ID_KEY, self.credential_id, true);
        if let Some(generated_user_id) = self.generated_user_id {
            visit(
                PasskeyRecord::GENERATED_USER_ID_KEY,
                generated_user_id,
                false,
            );
        }
        visit(
            PasskeyRecord::PRIVATE_KEY_PEM_KEY,
            self.private_key_pem,
            true,
        );
        visit(PasskeyRecord::RELYING_PARTY_KEY, self.relying_party, false);
        if let Some(user_handle) = self.user_handle {
            visit(PasskeyRecord::USER_HANDLE_KEY, user_handle, true);
        }
        visit(
            PasskeyRecord::FLAG_BE_KEY,
            if self.backup_eligible { "1" } else { "0" },
            false,
        );
        visit(
            PasskeyRecord::FLAG_BS_KEY,
            if self.backup_state { "1" } else { "0" },
            false,
        );
    }
}

impl PasskeyRecord {
    pub const USERNAME_KEY: &'static str = "KPEX_PASSKEY_USERNAME";
    pub const CREDENTIAL_ID_KEY: &'static str = "KPEX_PASSKEY_CREDENTIAL_ID";
    pub const GENERATED_USER_ID_KEY: &'static str = "KPEX_PASSKEY_GENERATED_USER_ID";
    pub const PRIVATE_KEY_PEM_KEY: &'static str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
    pub const RELYING_PARTY_KEY: &'static str = "KPEX_PASSKEY_RELYING_PARTY";
    pub const USER_HANDLE_KEY: &'static str = "KPEX_PASSKEY_USER_HANDLE";
    pub const FLAG_BE_KEY: &'static str = "KPEX_PASSKEY_FLAG_BE";
    pub const FLAG_BS_KEY: &'static str = "KPEX_PASSKEY_FLAG_BS";

    /// Returns whether a key belongs to the persistent passkey source representation.
    pub fn is_persistent_attribute_key(key: &str) -> bool {
        matches!(
            key,
            Self::USERNAME_KEY
                | Self::CREDENTIAL_ID_KEY
                | Self::GENERATED_USER_ID_KEY
                | Self::PRIVATE_KEY_PEM_KEY
                | Self::RELYING_PARTY_KEY
                | Self::USER_HANDLE_KEY
                | Self::FLAG_BE_KEY
                | Self::FLAG_BS_KEY
        )
    }

    /// Returns whether a persistent passkey source attribute must be protected.
    pub fn is_sensitive_persistent_attribute_key(key: &str) -> bool {
        matches!(
            key,
            Self::CREDENTIAL_ID_KEY
                | Self::GENERATED_USER_ID_KEY
                | Self::PRIVATE_KEY_PEM_KEY
                | Self::USER_HANDLE_KEY
        )
    }

    pub fn write_to_attributes(&self, attributes: &mut BTreeMap<String, CustomField>) {
        attributes.remove(Self::GENERATED_USER_ID_KEY);
        attributes.remove(Self::USER_HANDLE_KEY);
        PasskeyPersistentView::from_record(self).visit_attributes(|key, value, protected| {
            attributes.insert(
                key.into(),
                CustomField {
                    value: value.to_owned(),
                    protected,
                },
            );
        });
    }

    pub fn from_attributes(attributes: &BTreeMap<String, CustomField>) -> Option<Self> {
        let view = PasskeyPersistentView::from_attributes(attributes)?;
        Some(Self {
            username: view.username.to_owned(),
            credential_id: view.credential_id.to_owned(),
            generated_user_id: view.generated_user_id.map(str::to_owned),
            private_key_pem: view.private_key_pem.to_owned(),
            relying_party: view.relying_party.to_owned(),
            user_handle: view.user_handle.map(str::to_owned),
            backup_eligible: view.backup_eligible,
            backup_state: view.backup_state,
        })
    }
}

fn parse_passkey_flag(field: Option<&CustomField>) -> Option<bool> {
    match field.map(|field| field.value.as_str()) {
        None | Some("0") => Some(false),
        Some("1") => Some(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Some(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Some(true),
        Some(_) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSpec {
    pub secret_base32: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period_seconds: u64,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

impl Zeroize for TotpSpec {
    fn zeroize(&mut self) {
        self.secret_base32.zeroize();
        self.issuer.zeroize();
        self.account_name.zeroize();
    }
}

impl TotpSpec {
    pub fn parse_otpauth(uri: &str) -> Result<Self> {
        const PREFIX: &str = "otpauth://totp/";
        if !uri
            .get(..PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        {
            return Err(ModelError::Unimplemented);
        }

        let payload = &uri[PREFIX.len()..];
        let (label, query) = payload.split_once('?').ok_or(ModelError::Unimplemented)?;
        let (label_issuer, account_name) = if let Some((issuer, account)) = label.split_once(':') {
            // Our writer uses a literal separator, so encoded spaces here are account data.
            (
                Some(percent_decode(issuer)?),
                Some(percent_decode(account)?),
            )
        } else if let Some((issuer, account)) = split_once_encoded_label_separator(label) {
            (
                Some(percent_decode(issuer)?),
                Some(percent_decode(trim_encoded_label_spaces(account))?),
            )
        } else {
            let account = percent_decode(label)?;
            (None, (!account.is_empty()).then_some(account))
        };
        let label_issuer = label_issuer.filter(|issuer| !issuer.is_empty());
        let mut secret: Option<Zeroizing<String>> = None;
        let mut query_issuer: Option<Option<String>> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period_seconds = 30_u64;
        let mut query_names = BTreeSet::new();

        for pair in query.split('&') {
            if pair.is_empty() {
                return Err(ModelError::Unimplemented);
            }
            let (key, value) = pair.split_once('=').ok_or(ModelError::Unimplemented)?;
            if !matches!(key, "secret" | "issuer" | "algorithm" | "digits" | "period")
                || !query_names.insert(key)
            {
                return Err(ModelError::Unimplemented);
            }
            let value = Zeroizing::new(percent_decode(value)?);
            match key {
                "secret" => secret = Some(value),
                "issuer" => {
                    query_issuer = Some((!value.is_empty()).then(|| value.as_str().to_owned()))
                }
                "algorithm" => {
                    algorithm = match value.as_str().to_ascii_uppercase().as_str() {
                        "SHA1" | "HMAC-SHA-1" => TotpAlgorithm::Sha1,
                        "SHA256" | "HMAC-SHA-256" => TotpAlgorithm::Sha256,
                        "SHA512" | "HMAC-SHA-512" => TotpAlgorithm::Sha512,
                        _ => return Err(ModelError::Unimplemented),
                    }
                }
                "digits" => {
                    digits = value
                        .as_str()
                        .parse()
                        .map_err(|_| ModelError::Unimplemented)?
                }
                "period" => {
                    period_seconds = value
                        .as_str()
                        .parse()
                        .map_err(|_| ModelError::Unimplemented)?
                }
                _ => unreachable!("query names were validated above"),
            }
        }

        let mut secret = secret.ok_or(ModelError::Unimplemented)?;
        if secret.is_empty() {
            return Err(ModelError::Unimplemented);
        }
        let issuer = query_issuer.unwrap_or(label_issuer);
        let account_name = account_name
            .filter(|account| !account.is_empty())
            .ok_or(ModelError::Unimplemented)?;
        if issuer.is_none() && account_name.contains(':') {
            return Err(ModelError::Unimplemented);
        }
        Ok(Self {
            secret_base32: std::mem::take(&mut *secret),
            algorithm,
            digits,
            period_seconds,
            issuer,
            account_name: Some(account_name),
        })
    }

    pub fn generate_at(&self, unix_time: u64) -> Result<String> {
        let algorithm = match self.algorithm {
            TotpAlgorithm::Sha1 => OtpAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => OtpAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => OtpAlgorithm::Sha512,
        };

        let normalized = Zeroizing::new(self.secret_base32.replace('=', "").to_ascii_uppercase());
        let secret = Zeroizing::new(
            BASE32_NOPAD
                .decode(normalized.as_bytes())
                .map_err(|_| ModelError::Unimplemented)?,
        );

        generate_totp(
            secret.as_slice(),
            algorithm,
            self.digits,
            self.period_seconds,
            unix_time,
        )
        .map_err(|_| ModelError::Unimplemented)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub field_protection: EntryFieldProtection,
    pub tags: BTreeSet<String>,
    pub attributes: BTreeMap<String, CustomField>,
    pub attachments: AttachmentMap,
    pub history: Vec<Entry>,
    pub totp: Option<TotpSpec>,
    pub passkey: Option<PasskeyRecord>,
    pub icon_id: Option<u32>,
    pub custom_icon_id: Option<Uuid>,
    pub foreground_color: Option<String>,
    pub background_color: Option<String>,
    pub override_url: Option<String>,
    pub created_at: u64,
    pub modified_at: u64,
    pub expires: bool,
    pub expiry_time: Option<i64>,
    pub last_accessed_at: Option<u64>,
    pub usage_count: Option<u64>,
    pub location_changed_at: Option<u64>,
    pub auto_type: Option<AutoTypeConfig>,
    pub custom_data: BTreeMap<String, String>,
    pub custom_data_blocks: Vec<CustomDataBlock>,
    pub previous_parent: Option<Uuid>,
    pub exclude_from_reports: bool,
    pub raw_state: EntryRawState,
    pub opaque_xml: Vec<OpaqueXmlFragment>,
}

impl Entry {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            field_protection: EntryFieldProtection::default(),
            tags: BTreeSet::new(),
            attributes: BTreeMap::new(),
            attachments: AttachmentMap::default(),
            history: Vec::new(),
            totp: None,
            passkey: None,
            icon_id: Some(0),
            custom_icon_id: None,
            foreground_color: None,
            background_color: None,
            override_url: None,
            created_at: 0,
            modified_at: 0,
            expires: false,
            expiry_time: Some(0),
            last_accessed_at: Some(0),
            usage_count: Some(0),
            location_changed_at: Some(0),
            auto_type: Some(AutoTypeConfig::default()),
            custom_data: BTreeMap::new(),
            custom_data_blocks: Vec::new(),
            previous_parent: None,
            exclude_from_reports: false,
            raw_state: EntryRawState::default(),
            opaque_xml: Vec::new(),
        }
    }
}

/// Converts a current entry clone into a one-level history snapshot.
pub fn prepare_entry_history_snapshot(entry: &mut Entry) {
    entry.history.clear();
    if entry.raw_state.has_history_node
        || entry
            .raw_state
            .node_order
            .iter()
            .any(|name| name == "History")
    {
        retarget_removed_entry_known_nodes(entry, "History");
    }
    entry.raw_state.has_history_node = false;
}

fn retarget_removed_entry_known_nodes(entry: &mut Entry, element_name: &str) {
    let original_order = entry.raw_state.node_order.clone();
    let mut retained_counts = BTreeMap::<String, usize>::new();
    let mut predecessor = None;
    let mut replacements = Vec::new();
    for name in &original_order {
        if name == element_name {
            replacements.push(predecessor.clone());
            continue;
        }
        let occurrence = retained_counts.entry(name.clone()).or_insert(0);
        *occurrence += 1;
        predecessor = Some(OpaqueXmlAnchor {
            element_name: name.clone(),
            occurrence: *occurrence,
        });
    }

    for anchor in entry
        .custom_data_blocks
        .iter_mut()
        .map(|block| &mut block.after)
        .chain(
            entry
                .opaque_xml
                .iter_mut()
                .map(|fragment| &mut fragment.after),
        )
    {
        let Some(existing) = anchor.as_ref() else {
            continue;
        };
        if existing.element_name != element_name {
            continue;
        }
        *anchor = existing
            .occurrence
            .checked_sub(1)
            .and_then(|index| replacements.get(index).cloned())
            .flatten();
    }
    entry
        .raw_state
        .node_order
        .retain(|name| name != element_name);
}

/// Builds the transient persistent-attribute view after overlaying credential projections.
pub fn materialize_entry_persistent_attributes(
    entry: &Entry,
) -> MaterializedPersistentAttributes<'_> {
    let mut attributes = MaterializedPersistentAttributes::from_entry(&entry.attributes);
    let raw_totp = entry
        .totp
        .is_none()
        .then(|| totp_from_persistent_attributes(&entry.attributes))
        .flatten()
        .map(Zeroizing::new);
    if let Some(totp) = entry.totp.as_ref() {
        overlay_totp_projection(
            &mut attributes,
            entry,
            totp,
            MaterializedPersistentValue::Borrowed(&totp.secret_base32),
        );
    } else if let Some(totp) = raw_totp.as_deref() {
        overlay_totp_projection(
            &mut attributes,
            entry,
            totp,
            MaterializedPersistentValue::Owned(Zeroizing::new(totp.secret_base32.clone())),
        );
    } else {
        for (key, field) in &mut attributes.fields {
            if is_totp_secret_persistent_attribute_key(key) {
                field.protected = true;
            }
        }
    }

    let passkey = entry
        .passkey
        .as_ref()
        .map(PasskeyPersistentView::from_record)
        .or_else(|| PasskeyPersistentView::from_attributes(&entry.attributes));
    if let Some(passkey) = passkey {
        attributes.has_projectable_passkey = true;
        attributes
            .fields
            .retain(|key, _| !PasskeyRecord::is_persistent_attribute_key(key));
        passkey.visit_attributes(|key, value, protected| {
            attributes.insert_borrowed(key, value, protected);
        });
    } else {
        for (key, field) in &mut attributes.fields {
            if PasskeyRecord::is_sensitive_persistent_attribute_key(key) {
                field.protected = true;
            }
        }
    }
    attributes
}

fn overlay_totp_projection<'a>(
    attributes: &mut MaterializedPersistentAttributes<'a>,
    entry: &Entry,
    totp: &TotpSpec,
    secret: MaterializedPersistentValue<'a>,
) {
    attributes
        .fields
        .retain(|key, _| !is_totp_persistent_attribute_key(key));
    let (attribute_algorithm, uri_algorithm) = match totp.algorithm {
        TotpAlgorithm::Sha1 => ("HMAC-SHA-1", "SHA1"),
        TotpAlgorithm::Sha256 => ("HMAC-SHA-256", "SHA256"),
        TotpAlgorithm::Sha512 => ("HMAC-SHA-512", "SHA512"),
    };
    attributes.insert_owned("otp", entry_otpauth_uri(entry, totp, uri_algorithm), true);
    attributes.insert_value("TimeOtp-Secret-Base32", secret, true);
    attributes.insert_static("TimeOtp-Algorithm", attribute_algorithm, false);
    attributes.insert_owned(
        "TimeOtp-Length",
        Zeroizing::new(totp.digits.to_string()),
        false,
    );
    attributes.insert_owned(
        "TimeOtp-Period",
        Zeroizing::new(totp.period_seconds.to_string()),
        false,
    );
}

/// Projects the TOTP represented by persistent source attributes using KDBX precedence rules.
pub fn totp_from_persistent_attributes(fields: &BTreeMap<String, CustomField>) -> Option<TotpSpec> {
    if fields
        .keys()
        .any(|key| is_totp_persistent_attribute_key(key) && !is_projectable_totp_attribute_key(key))
    {
        return None;
    }

    if let Some(uri_field) = fields.get("otp") {
        let uri = Zeroizing::new(TotpSpec::parse_otpauth(&uri_field.value).ok()?);
        if fields.contains_key("TimeOtp-Secret-Base32") {
            if !discrete_totp_matches(fields, &uri) {
                return None;
            }
        } else if !present_discrete_totp_parameters_match(fields, &uri) {
            return None;
        }
        return Some((*uri).clone());
    }

    None
}

fn discrete_totp_matches(fields: &BTreeMap<String, CustomField>, uri: &TotpSpec) -> bool {
    fields
        .get("TimeOtp-Secret-Base32")
        .is_some_and(|field| field.value == uri.secret_base32)
        && parse_discrete_totp_algorithm(fields.get("TimeOtp-Algorithm"))
            .is_some_and(|algorithm| algorithm == uri.algorithm)
        && parse_discrete_totp_number(fields.get("TimeOtp-Length"), 6_u32)
            .is_some_and(|digits| digits == uri.digits)
        && parse_discrete_totp_number(fields.get("TimeOtp-Period"), 30_u64)
            .is_some_and(|period| period == uri.period_seconds)
}

fn present_discrete_totp_parameters_match(
    fields: &BTreeMap<String, CustomField>,
    uri: &TotpSpec,
) -> bool {
    fields.get("TimeOtp-Algorithm").is_none_or(|field| {
        parse_discrete_totp_algorithm(Some(field)).is_some_and(|value| value == uri.algorithm)
    }) && fields.get("TimeOtp-Length").is_none_or(|field| {
        field
            .value
            .parse::<u32>()
            .is_ok_and(|value| value == uri.digits)
    }) && fields.get("TimeOtp-Period").is_none_or(|field| {
        field
            .value
            .parse::<u64>()
            .is_ok_and(|value| value == uri.period_seconds)
    })
}

fn parse_discrete_totp_algorithm(field: Option<&CustomField>) -> Option<TotpAlgorithm> {
    match field.map(|field| field.value.as_str()) {
        None => Some(TotpAlgorithm::Sha1),
        Some(value) if value.eq_ignore_ascii_case("HMAC-SHA-1") => Some(TotpAlgorithm::Sha1),
        Some(value) if value.eq_ignore_ascii_case("HMAC-SHA-256") => Some(TotpAlgorithm::Sha256),
        Some(value) if value.eq_ignore_ascii_case("HMAC-SHA-512") => Some(TotpAlgorithm::Sha512),
        Some(_) => None,
    }
}

fn parse_discrete_totp_number<T>(field: Option<&CustomField>, default: T) -> Option<T>
where
    T: std::str::FromStr,
{
    match field {
        Some(field) => field.value.parse().ok(),
        None => Some(default),
    }
}

fn is_projectable_totp_attribute_key(key: &str) -> bool {
    matches!(
        key,
        "otp" | "TimeOtp-Secret-Base32" | "TimeOtp-Algorithm" | "TimeOtp-Length" | "TimeOtp-Period"
    )
}

/// Returns whether an attribute key belongs to the persistent TOTP source representation.
pub fn is_totp_persistent_attribute_key(key: &str) -> bool {
    matches!(
        key,
        "otp"
            | "TimeOtp-Secret"
            | "TimeOtp-Secret-Hex"
            | "TimeOtp-Secret-Base32"
            | "TimeOtp-Secret-Base64"
            | "TimeOtp-Algorithm"
            | "TimeOtp-Length"
            | "TimeOtp-Period"
            | "HmacOtp-Secret"
            | "HmacOtp-Secret-Hex"
            | "HmacOtp-Secret-Base32"
            | "HmacOtp-Secret-Base64"
            | "HmacOtp-Counter"
    )
}

/// Returns whether a persistent TOTP/HOTP source attribute must be protected.
pub fn is_totp_secret_persistent_attribute_key(key: &str) -> bool {
    matches!(
        key,
        "otp"
            | "TimeOtp-Secret"
            | "TimeOtp-Secret-Hex"
            | "TimeOtp-Secret-Base32"
            | "TimeOtp-Secret-Base64"
            | "HmacOtp-Secret"
            | "HmacOtp-Secret-Hex"
            | "HmacOtp-Secret-Base32"
            | "HmacOtp-Secret-Base64"
            | "HmacOtp-Counter"
    )
}

fn entry_otpauth_uri(entry: &Entry, totp: &TotpSpec, algorithm: &str) -> Zeroizing<String> {
    let (label, issuer) = match (&totp.issuer, &totp.account_name) {
        (None, Some(account_name)) if !account_name.is_empty() => {
            (percent_encode_component(account_name), None)
        }
        (None, _) => (
            format!(
                "{}:{}",
                percent_encode_component(&entry.title),
                percent_encode_component(&entry.username)
            ),
            Some(entry.title.as_str()),
        ),
        (Some(issuer), account_name) => {
            let account_name = account_name.as_deref().unwrap_or(&entry.username);
            (
                format!(
                    "{}:{}",
                    percent_encode_component(issuer),
                    percent_encode_component(account_name)
                ),
                Some(issuer.as_str()),
            )
        }
    };
    let encoded_secret = Zeroizing::new(percent_encode_component(&totp.secret_base32));
    let mut uri = Zeroizing::new(format!(
        "otpauth://totp/{label}?secret={secret}",
        secret = encoded_secret.as_str(),
    ));
    if let Some(issuer) = issuer {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode_component(issuer));
    }
    uri.push_str(&format!(
        "&algorithm={algorithm}&digits={digits}&period={period}",
        digits = totp.digits,
        period = totp.period_seconds,
    ));
    uri
}

fn percent_encode_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{byte:02X}"));
            }
        }
    }
    encoded
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: Uuid,
    pub title: String,
    pub notes: String,
    pub icon_id: Option<u32>,
    pub custom_icon_id: Option<Uuid>,
    pub tags: BTreeSet<String>,
    pub entries: Vec<Entry>,
    pub children: Vec<Group>,
    pub times: Option<GroupTimes>,
    pub flags: GroupFlags,
    pub default_auto_type_sequence: Option<String>,
    pub last_top_visible_entry: Option<Uuid>,
    pub custom_data: BTreeMap<String, String>,
    pub custom_data_blocks: Vec<CustomDataBlock>,
    pub previous_parent: Option<Uuid>,
    pub raw_state: GroupRawState,
    pub opaque_xml: Vec<OpaqueXmlFragment>,
}

impl Group {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            notes: String::new(),
            icon_id: None,
            custom_icon_id: None,
            tags: BTreeSet::new(),
            entries: Vec::new(),
            children: Vec::new(),
            times: None,
            flags: GroupFlags::default(),
            default_auto_type_sequence: None,
            last_top_visible_entry: None,
            custom_data: BTreeMap::new(),
            custom_data_blocks: Vec::new(),
            previous_parent: None,
            raw_state: GroupRawState::default(),
            opaque_xml: Vec::new(),
        }
    }
}

fn reconcile_group_entry_nodes(group: &mut Group, old_identities: &[Uuid]) {
    let new_identities = group
        .entries
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    reconcile_keyed_known_nodes(
        "Entry",
        &mut group.raw_state.node_order,
        &mut group.raw_state.entry_order,
        &mut group.opaque_xml,
        &mut group.custom_data_blocks,
        (old_identities, &new_identities, &[]),
    );
}

fn reconcile_group_child_nodes(group: &mut Group, old_identities: &[Uuid]) {
    let new_identities = group
        .children
        .iter()
        .map(|child| child.id)
        .collect::<Vec<_>>();
    reconcile_keyed_known_nodes(
        "Group",
        &mut group.raw_state.node_order,
        &mut group.raw_state.group_order,
        &mut group.opaque_xml,
        &mut group.custom_data_blocks,
        (old_identities, &new_identities, &[]),
    );
}

/// Reconciles keyed KDBX fidelity slots after semantic identities change.
#[doc(hidden)]
pub fn reconcile_keyed_known_nodes<T: Clone + Eq>(
    element_name: &str,
    node_order: &mut Vec<String>,
    tracked_identities: &mut Vec<T>,
    opaque_xml: &mut [OpaqueXmlFragment],
    custom_data_blocks: &mut [CustomDataBlock],
    identity_change: (&[T], &[T], &[(T, T)]),
) {
    let (old_identities, new_identities, renamed_identities) = identity_change;
    let tracked_mapping = tracked_identities
        .iter()
        .map(|old_identity| {
            let identity = renamed_identities
                .iter()
                .find_map(|(old, new)| (old == old_identity).then_some(new))
                .unwrap_or(old_identity);
            new_identities.contains(identity).then(|| identity.clone())
        })
        .collect::<Vec<_>>();
    let mut effective_new_identities = tracked_mapping
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let untracked_new_identities = new_identities
        .iter()
        .filter(|identity| !effective_new_identities.contains(identity))
        .cloned()
        .collect::<Vec<_>>();
    effective_new_identities.extend(untracked_new_identities);

    let mapped_identities = old_identities
        .iter()
        .map(|old_identity| {
            let identity = renamed_identities
                .iter()
                .find_map(|(old, new)| (old == old_identity).then_some(new))
                .unwrap_or(old_identity);
            effective_new_identities
                .contains(identity)
                .then(|| identity.clone())
        })
        .collect::<Vec<_>>();

    let mut replacement_anchors = Vec::with_capacity(old_identities.len());
    for (old_occurrence, mapped_identity) in mapped_identities.iter().enumerate() {
        let replacement = mapped_identity.as_ref().map_or_else(
            || {
                keyed_predecessor_anchor(
                    node_order,
                    element_name,
                    old_occurrence + 1,
                    &replacement_anchors,
                )
            },
            |identity| {
                let occurrence = effective_new_identities
                    .iter()
                    .position(|candidate| candidate == identity)
                    .expect("mapped keyed identity")
                    + 1;
                Some(OpaqueXmlAnchor {
                    element_name: element_name.into(),
                    occurrence,
                })
            },
        );
        replacement_anchors.push(replacement);
    }

    for anchor in custom_data_blocks
        .iter_mut()
        .filter_map(|block| block.after.as_mut())
        .chain(
            opaque_xml
                .iter_mut()
                .filter_map(|fragment| fragment.after.as_mut()),
        )
    {
        if anchor.element_name != element_name {
            continue;
        }
        let Some(index) = anchor.occurrence.checked_sub(1) else {
            continue;
        };
        let Some(replacement) = replacement_anchors.get(index) else {
            continue;
        };
        match replacement {
            Some(replacement) => anchor.clone_from(replacement),
            None => {
                anchor.element_name.clear();
                anchor.occurrence = 0;
            }
        }
    }
    for block in custom_data_blocks {
        if block
            .after
            .as_ref()
            .is_some_and(|anchor| anchor.element_name.is_empty())
        {
            block.after = None;
        }
    }
    for fragment in opaque_xml {
        if fragment
            .after
            .as_ref()
            .is_some_and(|anchor| anchor.element_name.is_empty())
        {
            fragment.after = None;
        }
    }

    let mut occurrence = 0;
    node_order.retain(|name| {
        if name != element_name {
            return true;
        }
        let retained = tracked_mapping.get(occurrence).is_none_or(Option::is_some);
        occurrence += 1;
        retained
    });
    *tracked_identities = tracked_mapping.into_iter().flatten().collect();
}

fn keyed_predecessor_anchor(
    node_order: &[String],
    element_name: &str,
    old_occurrence: usize,
    replacement_anchors: &[Option<OpaqueXmlAnchor>],
) -> Option<OpaqueXmlAnchor> {
    let mut occurrence = 0;
    let removed_index = node_order.iter().position(|name| {
        if name != element_name {
            return false;
        }
        occurrence += 1;
        occurrence == old_occurrence
    });
    let Some(removed_index) = removed_index else {
        return old_occurrence
            .checked_sub(2)
            .and_then(|index| replacement_anchors.get(index).cloned().flatten());
    };

    let index = removed_index.checked_sub(1)?;
    let name = &node_order[index];
    let occurrence = node_order[..=index]
        .iter()
        .filter(|candidate| *candidate == name)
        .count();
    if name == element_name {
        replacement_anchors.get(occurrence - 1).cloned().flatten()
    } else {
        Some(OpaqueXmlAnchor {
            element_name: name.clone(),
            occurrence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub generator: Option<String>,
    pub settings_changed: Option<i64>,
    pub name: String,
    pub database_name_changed: Option<i64>,
    pub description: Option<String>,
    pub description_changed: Option<i64>,
    pub default_username: Option<String>,
    pub default_username_changed: Option<i64>,
    pub meta_custom_data: BTreeMap<String, String>,
    pub meta_custom_data_blocks: Vec<CustomDataBlock>,
    pub meta_raw_state: MetaRawState,
    pub root_raw_state: RootRawState,
    pub root: Group,
    /// Exact encoded KDBX4 `KdfParameters` dictionary retained across ordinary saves.
    pub kdf_parameters: Option<Vec<u8>>,
    pub public_custom_data: BTreeMap<String, Vec<u8>>,
    pub deleted_objects: Vec<DeletedObject>,
    pub maintenance_history_days: Option<i32>,
    pub color: Option<String>,
    pub master_key_changed: Option<i64>,
    pub master_key_change_rec: Option<i64>,
    pub master_key_change_force: Option<i64>,
    pub master_key_change_force_once: Option<bool>,
    pub custom_icons: Vec<CustomIcon>,
    pub history_max_items: Option<i32>,
    pub history_max_size: Option<i64>,
    pub last_selected_group: Option<Uuid>,
    pub last_top_visible_group: Option<Uuid>,
    pub memory_protection: Option<MemoryProtection>,
    pub recycle_bin_enabled: Option<bool>,
    pub recycle_bin_group: Option<Uuid>,
    pub recycle_bin_changed: Option<i64>,
    pub entry_templates_group: Option<Uuid>,
    pub entry_templates_group_changed: Option<i64>,
    pub meta_opaque_xml: Vec<OpaqueXmlFragment>,
    pub root_opaque_xml: Vec<OpaqueXmlFragment>,
}

impl Vault {
    pub fn empty(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            generator: None,
            settings_changed: None,
            root: Group::new(name.clone()),
            name,
            database_name_changed: None,
            description: None,
            description_changed: None,
            default_username: None,
            default_username_changed: None,
            meta_custom_data: BTreeMap::new(),
            meta_custom_data_blocks: Vec::new(),
            meta_raw_state: MetaRawState::default(),
            root_raw_state: RootRawState {
                has_deleted_objects_node: true,
                ..RootRawState::default()
            },
            kdf_parameters: None,
            public_custom_data: BTreeMap::new(),
            deleted_objects: Vec::new(),
            maintenance_history_days: None,
            color: None,
            master_key_changed: None,
            master_key_change_rec: None,
            master_key_change_force: None,
            master_key_change_force_once: None,
            custom_icons: Vec::new(),
            history_max_items: None,
            history_max_size: None,
            last_selected_group: None,
            last_top_visible_group: None,
            memory_protection: None,
            recycle_bin_enabled: None,
            recycle_bin_group: None,
            recycle_bin_changed: None,
            entry_templates_group: None,
            entry_templates_group_changed: None,
            meta_opaque_xml: Vec::new(),
            root_opaque_xml: Vec::new(),
        }
    }

    pub fn search(&self, term: &str) -> Vec<&Entry> {
        let needle = term.to_ascii_lowercase();
        let mut matches = Vec::new();
        collect_search(&self.root, &needle, &mut matches);
        matches
    }

    pub fn merge_from(&mut self, other: &Vault) -> MergeReport {
        let mut report = MergeReport::default();
        let mut content_pool = AttachmentContentPool::new();
        normalize_group_attachment_content(&mut self.root, &mut content_pool);
        let deleted_objects = merged_deleted_objects(self, other);
        let mut merged_entry_ids = prune_vault_for_tombstones(self, &deleted_objects);

        let mut incoming = other.clone();
        merged_entry_ids.extend(prune_vault_for_tombstones(&mut incoming, &deleted_objects));
        self.deleted_objects = deleted_objects.into_values().collect();
        merge_group(
            &mut self.root,
            &incoming.root,
            &mut content_pool,
            &mut merged_entry_ids,
            &mut report,
        );
        report.merged_entries = merged_entry_ids.len();
        report
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MergeReport {
    pub merged_entries: usize,
    pub history_snapshots_added: usize,
}

fn merged_deleted_objects(local: &Vault, incoming: &Vault) -> BTreeMap<Uuid, DeletedObject> {
    let mut merged = BTreeMap::<Uuid, DeletedObject>::new();
    for tombstone in local
        .deleted_objects
        .iter()
        .chain(&incoming.deleted_objects)
    {
        let candidate = tombstone.clone();
        merged
            .entry(candidate.id)
            .and_modify(|existing| {
                if candidate.deleted_at > existing.deleted_at {
                    existing.deleted_at = candidate.deleted_at;
                }
            })
            .or_insert(candidate);
    }
    merged
}

fn prune_vault_for_tombstones(
    vault: &mut Vault,
    tombstones: &BTreeMap<Uuid, DeletedObject>,
) -> BTreeSet<Uuid> {
    let mut removed_entry_ids = BTreeSet::new();
    prune_group_for_tombstones(
        &mut vault.root,
        tombstones,
        None,
        &mut removed_entry_ids,
        true,
    );
    removed_entry_ids
}

fn prune_group_for_tombstones(
    group: &mut Group,
    tombstones: &BTreeMap<Uuid, DeletedObject>,
    inherited_deletion: Option<i64>,
    removed_entry_ids: &mut BTreeSet<Uuid>,
    is_root: bool,
) -> bool {
    let group_deletion = latest_deletion(
        latest_deletion(
            inherited_deletion,
            tombstones.get(&group.id).map(|item| item.deleted_at),
        ),
        group
            .previous_parent
            .and_then(|id| tombstones.get(&id))
            .map(|item| item.deleted_at),
    );
    let subtree_deletion = group_deletion
        .filter(|deleted_at| deletion_wins(*deleted_at, group_location_update(group)));
    let old_entry_ids = group
        .entries
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let old_entry_count = group.entries.len();
    group.entries.retain(|entry| {
        let deletion = latest_deletion(
            latest_deletion(
                subtree_deletion,
                tombstones.get(&entry.id).map(|item| item.deleted_at),
            ),
            entry
                .previous_parent
                .and_then(|id| tombstones.get(&id))
                .map(|item| item.deleted_at),
        );
        let keep =
            !deletion.is_some_and(|deleted_at| deletion_wins(deleted_at, entry_last_update(entry)));
        if !keep {
            removed_entry_ids.insert(entry.id);
        }
        keep
    });
    if group.entries.len() != old_entry_count {
        reconcile_group_entry_nodes(group, &old_entry_ids);
    }

    let old_child_ids = group
        .children
        .iter()
        .map(|child| child.id)
        .collect::<Vec<_>>();
    let old_child_count = group.children.len();
    group.children.retain_mut(|child| {
        prune_group_for_tombstones(
            child,
            tombstones,
            subtree_deletion,
            removed_entry_ids,
            false,
        )
    });
    if group.children.len() != old_child_count {
        reconcile_group_child_nodes(group, &old_child_ids);
    }

    let group_survives = group_deletion
        .is_none_or(|deleted_at| !deletion_wins(deleted_at, group_last_update(group)));
    is_root || group_survives || !group.entries.is_empty() || !group.children.is_empty()
}

fn latest_deletion(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn entry_last_update(entry: &Entry) -> u64 {
    entry
        .modified_at
        .max(entry.location_changed_at.unwrap_or(0))
}

fn group_last_update(group: &Group) -> u64 {
    group
        .times
        .map(|times| {
            times
                .modified_at
                .max(times.location_changed_at.unwrap_or(0))
        })
        .unwrap_or(0)
}

fn group_location_update(group: &Group) -> u64 {
    group
        .times
        .and_then(|times| times.location_changed_at)
        .unwrap_or(0)
}

fn deletion_wins(deleted_at: i64, last_update: u64) -> bool {
    i128::from(deleted_at) > i128::from(last_update)
}

fn collect_search<'a>(group: &'a Group, needle: &str, matches: &mut Vec<&'a Entry>) {
    for entry in &group.entries {
        let mut haystacks = vec![
            entry.title.as_str(),
            entry.username.as_str(),
            entry.password.as_str(),
            entry.url.as_str(),
            entry.notes.as_str(),
        ];
        for tag in &entry.tags {
            haystacks.push(tag.as_str());
        }
        for field in entry.attributes.values() {
            haystacks.push(field.value.as_str());
        }

        if haystacks
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(needle))
        {
            matches.push(entry);
        }
    }

    for child in &group.children {
        collect_search(child, needle, matches);
    }
}

fn merge_group(
    target: &mut Group,
    source: &Group,
    content_pool: &mut AttachmentContentPool,
    merged_entry_ids: &mut BTreeSet<Uuid>,
    report: &mut MergeReport,
) {
    for incoming_entry in &source.entries {
        if let Some(index) = target
            .entries
            .iter()
            .position(|entry| entry.id == incoming_entry.id)
        {
            let existing = &mut target.entries[index];
            if incoming_entry.modified_at > existing.modified_at {
                let mut snapshot = existing.clone();
                prepare_entry_history_snapshot(&mut snapshot);
                let mut merged = incoming_entry.clone();
                merged.history.push(snapshot);
                normalize_entry_attachment_content(&mut merged, content_pool);
                *existing = merged;
                merged_entry_ids.insert(incoming_entry.id);
                report.history_snapshots_added += 1;
            }
        } else {
            let mut incoming_entry = incoming_entry.clone();
            normalize_entry_attachment_content(&mut incoming_entry, content_pool);
            merged_entry_ids.insert(incoming_entry.id);
            target.entries.push(incoming_entry);
        }
    }

    for incoming_group in &source.children {
        if let Some(index) = target
            .children
            .iter()
            .position(|group| group.id == incoming_group.id)
        {
            merge_group(
                &mut target.children[index],
                incoming_group,
                content_pool,
                merged_entry_ids,
                report,
            );
        } else {
            let mut incoming_group = incoming_group.clone();
            normalize_group_attachment_content(&mut incoming_group, content_pool);
            target.children.push(incoming_group);
        }
    }
}

fn normalize_group_attachment_content(group: &mut Group, content_pool: &mut AttachmentContentPool) {
    for entry in &mut group.entries {
        normalize_entry_attachment_content(entry, content_pool);
    }
    for child in &mut group.children {
        normalize_group_attachment_content(child, content_pool);
    }
}

fn normalize_entry_attachment_content(entry: &mut Entry, content_pool: &mut AttachmentContentPool) {
    for attachment in entry.attachments.values_mut() {
        if let Ok(content) = content_pool.intern_content(&attachment.data) {
            attachment.data = content;
        }
    }
    for history in &mut entry.history {
        normalize_entry_attachment_content(history, content_pool);
    }
}

fn split_once_encoded_label_separator(input: &str) -> Option<(&str, &str)> {
    let index = input.as_bytes().windows(3).position(|bytes| {
        bytes[0] == b'%' && bytes[1] == b'3' && matches!(bytes[2], b'A' | b'a')
    })?;
    Some((&input[..index], &input[index + 3..]))
}

fn trim_encoded_label_spaces(mut input: &str) -> &str {
    while input.as_bytes().starts_with(b"%20") {
        input = &input[3..];
    }
    input
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let Some(value) = decode_hex_byte(bytes[index + 1], bytes[index + 2]) {
                    decoded.push(value);
                    index += 3;
                    continue;
                }
                decoded.push(bytes[index]);
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    match String::from_utf8(std::mem::take(&mut *decoded)) {
        Ok(decoded) => Ok(decoded),
        Err(error) => {
            let _invalid_bytes = Zeroizing::new(error.into_bytes());
            Err(ModelError::Unimplemented)
        }
    }
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    Some(nibble(high)? << 4 | nibble(low)?)
}

#[cfg(test)]
mod tests {
    use super::{
        Attachment, AttachmentContent, AttachmentContentId, AttachmentContentPool, CustomField,
        DeletedObject, Entry, Group, GroupTimes, MaterializedPersistentValue, ModelError,
        OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, TotpAlgorithm, TotpSpec, Vault,
        is_totp_persistent_attribute_key, materialize_entry_persistent_attributes,
        totp_from_persistent_attributes,
    };
    use std::collections::BTreeMap;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn attachment_content_is_shared_across_entry_and_history_clones() {
        let bytes = vec![0x5a; 1024 * 1024];
        let mut pool = AttachmentContentPool::new();
        let content = pool.intern(&bytes).expect("intern content");
        let mut entry = Entry::new("large attachment");
        entry.attachments.insert(
            "large.bin".into(),
            Attachment::with_content("large.bin", content.clone(), true),
        );
        entry.history.push(entry.clone());

        let clone = entry.clone();
        let original_content = &entry.attachments["large.bin"].data;
        let cloned_content = &clone.attachments["large.bin"].data;
        let history_content = &entry.history[0].attachments["large.bin"].data;

        assert!(original_content.ptr_eq(cloned_content));
        assert!(original_content.ptr_eq(history_content));
        assert_eq!(original_content.as_bytes(), bytes.as_slice());
        assert!(original_content.strong_count() >= 4);
    }

    #[test]
    fn new_entry_uses_kdbx_structural_defaults() {
        let entry = Entry::new("defaults");

        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.auto_type, Some(super::AutoTypeConfig::default()));
        assert_eq!(entry.expiry_time, Some(0));
        assert_eq!(entry.last_accessed_at, Some(0));
        assert_eq!(entry.usage_count, Some(0));
        assert_eq!(entry.location_changed_at, Some(0));
    }

    #[test]
    fn attachment_pool_deduplicates_bytes_and_rejects_hash_collisions() {
        let mut pool = AttachmentContentPool::new();
        let first = pool.intern(b"same bytes").expect("first content");
        let same = pool.intern(b"same bytes").expect("same content");
        let different = pool.intern(b"different bytes").expect("different content");

        assert!(first.ptr_eq(&same));
        assert!(!first.ptr_eq(&different));
        assert_eq!(
            data_encoding::HEXLOWER.encode(first.id().as_bytes()),
            "58100dc8fc06562ce3e578231dc948e083520ee49c4b4ee5a5a28bb4b4003feb"
        );

        let forced_id = AttachmentContentId::from_bytes(b"forced id source");
        let _forced = pool
            .intern_with_id_for_test(forced_id, b"first collision value")
            .expect("seed forced id");
        assert_eq!(
            pool.intern_with_id_for_test(forced_id, b"second collision value"),
            Err(ModelError::AttachmentContentHashCollision)
        );
    }

    #[test]
    fn attachment_content_debug_is_redacted_and_last_owner_zeroizes() {
        let secret = b"attachment-secret-that-must-not-leak";
        let zeroized = Arc::new(AtomicBool::new(false));
        let content = AttachmentContent::new_with_drop_probe_for_test(secret, zeroized.clone());
        let clone = content.clone();

        let debug = format!("{content:?}");
        assert!(!debug.contains("attachment-secret"));
        assert!(debug.contains("len"));
        let error = ModelError::AttachmentContentHashCollision.to_string();
        assert!(!error.contains("attachment-secret"));

        drop(content);
        assert!(!zeroized.load(Ordering::SeqCst));
        drop(clone);
        assert!(zeroized.load(Ordering::SeqCst));
    }

    #[test]
    fn otpauth_parser_and_generator_match_rfc_vector() {
        let spec = TotpSpec::parse_otpauth(
            "otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=6&period=30",
        )
        .expect("parse otpauth");

        assert_eq!(spec.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(spec.digits, 6);
        assert_eq!(spec.period_seconds, 30);
        assert_eq!(spec.issuer.as_deref(), Some("ACME"));
        assert_eq!(spec.account_name.as_deref(), Some("alice@example.com"));
        assert_eq!(spec.generate_at(59).expect("generate"), "287082");
    }

    #[test]
    fn otpauth_parser_prefers_a_literal_separator_over_encoded_component_colons() {
        let spec = TotpSpec::parse_otpauth(
            "otpauth://totp/Issuer%3AProd:account%3Awest?secret=SECRET&issuer=Issuer%3AProd",
        )
        .expect("parse otpauth");

        assert_eq!(spec.issuer.as_deref(), Some("Issuer:Prod"));
        assert_eq!(spec.account_name.as_deref(), Some("account:west"));
    }

    #[test]
    fn otpauth_parser_rejects_an_empty_account_name() {
        assert!(
            TotpSpec::parse_otpauth("otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer").is_err()
        );
    }

    #[test]
    fn otpauth_parser_preserves_encoded_leading_spaces_after_a_literal_separator() {
        let spec = TotpSpec::parse_otpauth(
            "otpauth://totp/Issuer:%20%20alice?secret=SECRET&issuer=Issuer",
        )
        .expect("parse otpauth");

        assert_eq!(spec.account_name.as_deref(), Some("  alice"));
    }

    #[test]
    fn otpauth_parser_rejects_an_empty_account_when_the_issuer_contains_a_colon() {
        assert!(
            TotpSpec::parse_otpauth(
                "otpauth://totp/Issuer%3AProd:?secret=SECRET&issuer=Issuer%3AProd",
            )
            .is_err()
        );
    }

    #[test]
    fn otpauth_parser_rejects_an_absent_account_without_an_issuer() {
        assert!(TotpSpec::parse_otpauth("otpauth://totp/?secret=SECRET").is_err());
    }

    #[test]
    fn otpauth_parser_uses_an_unprefixed_label_as_the_account_name() {
        let spec =
            TotpSpec::parse_otpauth("otpauth://totp/alice?secret=SECRET").expect("parse otpauth");

        assert_eq!(spec.account_name.as_deref(), Some("alice"));
    }

    #[test]
    fn otpauth_parser_preserves_an_unprefixed_account_matching_the_query_issuer() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/GitHub?secret=SECRET&issuer=GitHub")
            .expect("parse otpauth");

        assert_eq!(spec.issuer.as_deref(), Some("GitHub"));
        assert_eq!(spec.account_name.as_deref(), Some("GitHub"));
    }

    #[test]
    fn otpauth_parser_accepts_a_url_encoded_label_separator() {
        for label in ["Example%3Aalice", "Example%3aalice", "Example%3A%20alice"] {
            let spec = TotpSpec::parse_otpauth(&format!(
                "otpauth://totp/{label}?secret=SECRET&issuer=Example"
            ))
            .expect("parse otpauth");

            assert_eq!(spec.issuer.as_deref(), Some("Example"));
            assert_eq!(spec.account_name.as_deref(), Some("alice"));
        }
    }

    #[test]
    fn otpauth_parser_infers_the_issuer_from_the_label_prefix() {
        let spec =
            TotpSpec::parse_otpauth("otpauth://totp/Example:alice%40example.com?secret=SECRET")
                .expect("parse otpauth");

        assert_eq!(spec.issuer.as_deref(), Some("Example"));
        assert_eq!(spec.account_name.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn otpauth_parser_preserves_a_literal_plus_in_the_label() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/alice+prod%40example.com?secret=SECRET")
            .expect("parse otpauth");

        assert_eq!(spec.account_name.as_deref(), Some("alice+prod@example.com"));
    }

    #[test]
    fn otpauth_parser_accepts_case_insensitive_uri_scheme_and_host() {
        let spec = TotpSpec::parse_otpauth("OTPAUTH://TOTP/alice%40example.com?secret=SECRET")
            .expect("parse otpauth");

        assert_eq!(spec.account_name.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn otpauth_parser_preserves_malformed_percent_escape_before_unicode() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/%Aé?secret=SECRET")
            .expect("malformed escape remains literal");

        assert_eq!(spec.account_name.as_deref(), Some("%Aé"));
    }

    #[test]
    fn otpauth_parser_rejects_lossy_query_shapes() {
        for uri in [
            "otpauth://totp/alice?secret=SECRET&image=logo.png",
            "otpauth://totp/alice?secret=SECRET&secret=OTHER",
            "otpauth://totp/alice?secret=SECRET&issuer",
            "otpauth://totp/alice?secret=SECRET&&period=30",
            "otpauth://totp/alice?secret=SECRET&",
            "otpauth://totp/alice?secret=SECRET&Issuer=Example",
        ] {
            assert!(
                TotpSpec::parse_otpauth(uri).is_err(),
                "lossy query was projected: {uri}"
            );
        }
    }

    #[test]
    fn otpauth_parser_rejects_invalid_utf8_components() {
        for uri in [
            "otpauth://totp/%FF?secret=SECRET",
            "otpauth://totp/alice?secret=%FF",
            "otpauth://totp/alice?secret=SECRET&issuer=%C3%28",
        ] {
            assert!(
                TotpSpec::parse_otpauth(uri).is_err(),
                "invalid UTF-8 was projected: {uri}"
            );
        }
    }

    #[test]
    fn otpauth_parser_rejects_noninvertible_projection_states() {
        for uri in [
            "otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer",
            "otpauth://totp/?secret=SECRET",
            "otpauth://totp/alice?secret=",
            "otpauth://totp/%3Aaccount%3Awest?secret=SECRET",
            "otpauth://totp/Issuer:account%3Awest?secret=SECRET&issuer=",
        ] {
            assert!(
                TotpSpec::parse_otpauth(uri).is_err(),
                "non-invertible URI was projected: {uri}"
            );
        }
    }

    #[test]
    fn otpauth_parser_normalizes_an_empty_issuer_to_absent() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/alice?secret=SECRET&issuer=")
            .expect("empty issuer means no issuer");

        assert_eq!(spec.issuer, None);
        assert_eq!(spec.account_name.as_deref(), Some("alice"));
    }

    #[test]
    fn passkey_record_roundtrips_through_attribute_map() {
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-123".into(),
            generated_user_id: Some("generated-user".into()),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".into(),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle".into()),
            backup_eligible: true,
            backup_state: false,
        };

        let mut attributes = BTreeMap::new();
        passkey.write_to_attributes(&mut attributes);

        assert!(attributes.contains_key("KPEX_PASSKEY_USERNAME"));
        assert!(!attributes.contains_key("Passkey Username"));
        let restored = PasskeyRecord::from_attributes(&attributes).expect("restore passkey");
        assert_eq!(restored, passkey);
    }

    #[test]
    fn invalid_passkey_flags_keep_the_raw_source_unprojected() {
        let mut entry = Entry::new("invalid passkey flag");
        for (key, value) in [
            (PasskeyRecord::USERNAME_KEY, "alice"),
            (PasskeyRecord::CREDENTIAL_ID_KEY, "credential"),
            (PasskeyRecord::PRIVATE_KEY_PEM_KEY, "private-key"),
            (PasskeyRecord::RELYING_PARTY_KEY, "example.com"),
            (PasskeyRecord::FLAG_BE_KEY, "yes"),
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
        }

        assert!(PasskeyRecord::from_attributes(&entry.attributes).is_none());
        let materialized = materialize_entry_persistent_attributes(&entry);
        assert_eq!(materialized[PasskeyRecord::FLAG_BE_KEY].value(), "yes");
        assert!(materialized[PasskeyRecord::CREDENTIAL_ID_KEY].protected());
        assert!(materialized[PasskeyRecord::PRIVATE_KEY_PEM_KEY].protected());
    }

    #[test]
    fn materialized_persistent_attributes_redact_secret_values_from_debug() {
        let mut entry = Entry::new("debug redaction");
        entry.attributes.insert(
            PasskeyRecord::PRIVATE_KEY_PEM_KEY.into(),
            CustomField {
                value: "never-print-this-private-key".into(),
                protected: false,
            },
        );

        let materialized = materialize_entry_persistent_attributes(&entry);
        let debug = format!("{materialized:?}");

        assert!(!debug.contains("never-print-this-private-key"));
    }

    #[test]
    fn materialized_persistent_attributes_borrow_sources_and_zeroize_owned_secrets() {
        let mut entry = Entry::new("materialized lifecycle");
        entry.attributes.insert(
            "unchanged".into(),
            CustomField {
                value: "borrow-me".into(),
                protected: false,
            },
        );
        entry.totp = Some(TotpSpec {
            secret_base32: "BORROWEDSECRET".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: None,
            account_name: None,
        });
        let attribute_pointer = entry.attributes["unchanged"].value.as_ptr();
        let secret_pointer = entry
            .totp
            .as_ref()
            .expect("TOTP projection")
            .secret_base32
            .as_ptr();

        let materialized = materialize_entry_persistent_attributes(&entry);

        assert_eq!(
            materialized["unchanged"].value().as_ptr(),
            attribute_pointer
        );
        assert_eq!(
            materialized["TimeOtp-Secret-Base32"].value().as_ptr(),
            secret_pointer
        );
        assert!(matches!(
            &materialized.fields["otp"].value,
            MaterializedPersistentValue::Owned(_)
        ));
    }

    #[test]
    fn unprojectable_totp_namespace_is_preserved_and_protected() {
        let mut fields = BTreeMap::new();
        for (key, value) in [
            (
                "otp",
                "otpauth://totp/alice?secret=URISECRET&algorithm=SHA1&digits=6&period=30",
            ),
            ("TimeOtp-Secret-Base32", "DISCRETESECRET"),
            ("TimeOtp-Algorithm", "HMAC-SHA-1"),
            ("TimeOtp-Length", "6"),
            ("TimeOtp-Period", "30"),
            ("TimeOtp-Secret", "alternate"),
            ("TimeOtp-Secret-Hex", "616c7465726e617465"),
            ("TimeOtp-Secret-Base64", "YWx0ZXJuYXRl"),
            ("HmacOtp-Secret", "hotp"),
            ("HmacOtp-Secret-Hex", "686f7470"),
            ("HmacOtp-Secret-Base32", "NBUHI4A"),
            ("HmacOtp-Secret-Base64", "aG90cA=="),
            ("HmacOtp-Counter", "7"),
        ] {
            fields.insert(
                key.into(),
                CustomField {
                    value: value.into(),
                    protected: false,
                },
            );
            assert!(
                is_totp_persistent_attribute_key(key),
                "unreserved key: {key}"
            );
        }

        assert!(totp_from_persistent_attributes(&fields).is_none());
        let mut entry = Entry::new("raw OTP");
        entry.attributes = fields.clone();
        let materialized = materialize_entry_persistent_attributes(&entry);

        assert_eq!(materialized.len(), fields.len());
        for (key, original) in fields {
            assert_eq!(
                materialized[&key].value(),
                original.value,
                "value for {key}"
            );
            let should_be_protected = !matches!(
                key.as_str(),
                "TimeOtp-Algorithm" | "TimeOtp-Length" | "TimeOtp-Period"
            );
            assert_eq!(
                materialized[&key].protected(),
                should_be_protected,
                "protection for {key}"
            );
        }
    }

    #[test]
    fn conflicting_uri_and_discrete_totp_sources_remain_verbatim() {
        let fields = BTreeMap::from([
            (
                "otp".into(),
                CustomField {
                    value:
                        "otpauth://totp/alice?secret=URISECRET&algorithm=SHA256&digits=8&period=45"
                            .into(),
                    protected: true,
                },
            ),
            (
                "TimeOtp-Secret-Base32".into(),
                CustomField {
                    value: "DIFFERENT".into(),
                    protected: true,
                },
            ),
            (
                "TimeOtp-Algorithm".into(),
                CustomField {
                    value: "HMAC-SHA-256".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Length".into(),
                CustomField {
                    value: "8".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Period".into(),
                CustomField {
                    value: "45".into(),
                    protected: false,
                },
            ),
        ]);

        assert!(totp_from_persistent_attributes(&fields).is_none());
        let mut entry = Entry::new("conflicting OTP");
        entry.attributes = fields.clone();
        assert_eq!(materialize_entry_persistent_attributes(&entry), fields);
    }

    #[test]
    fn equivalent_uri_and_discrete_totp_sources_project_once() {
        let fields = BTreeMap::from([
            (
                "otp".into(),
                CustomField {
                    value:
                        "otpauth://totp/alice?secret=abcd%3D%3D&algorithm=SHA256&digits=8&period=45"
                            .into(),
                    protected: true,
                },
            ),
            (
                "TimeOtp-Secret-Base32".into(),
                CustomField {
                    value: "abcd==".into(),
                    protected: true,
                },
            ),
            (
                "TimeOtp-Algorithm".into(),
                CustomField {
                    value: "hmac-sha-256".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Length".into(),
                CustomField {
                    value: "8".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Period".into(),
                CustomField {
                    value: "45".into(),
                    protected: false,
                },
            ),
        ]);

        let projected = totp_from_persistent_attributes(&fields).expect("equivalent TOTP");
        assert_eq!(projected.secret_base32, "abcd==");
        assert_eq!(projected.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(projected.digits, 8);
        assert_eq!(projected.period_seconds, 45);
    }

    #[test]
    fn discrete_only_totp_source_is_retained_verbatim() {
        let fields = BTreeMap::from([
            (
                "TimeOtp-Secret-Base32".into(),
                CustomField {
                    value: "abcd==".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Algorithm".into(),
                CustomField {
                    value: "hmac-sha-256".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Length".into(),
                CustomField {
                    value: "08".into(),
                    protected: false,
                },
            ),
            (
                "TimeOtp-Period".into(),
                CustomField {
                    value: "045".into(),
                    protected: false,
                },
            ),
        ]);
        let mut entry = Entry::new("discrete only");
        entry.attributes = fields.clone();

        assert!(totp_from_persistent_attributes(&fields).is_none());
        let materialized = materialize_entry_persistent_attributes(&entry);
        for (key, field) in fields {
            assert_eq!(materialized[&key].value(), field.value);
            assert_eq!(
                materialized[&key].protected(),
                key == "TimeOtp-Secret-Base32"
            );
        }
    }

    #[test]
    fn uri_without_discrete_secret_compares_only_present_parameters() {
        let matching = BTreeMap::from([
            (
                "otp".into(),
                CustomField {
                    value: "otpauth://totp/alice?secret=SECRET&algorithm=SHA512&digits=8&period=45"
                        .into(),
                    protected: true,
                },
            ),
            (
                "TimeOtp-Algorithm".into(),
                CustomField {
                    value: "HMAC-SHA-512".into(),
                    protected: false,
                },
            ),
        ]);
        assert!(totp_from_persistent_attributes(&matching).is_some());

        let mut conflicting = matching;
        conflicting.insert(
            "TimeOtp-Length".into(),
            CustomField {
                value: "6".into(),
                protected: false,
            },
        );
        assert!(totp_from_persistent_attributes(&conflicting).is_none());
    }

    #[test]
    fn malformed_discrete_totp_parameters_remain_verbatim() {
        for (key, invalid) in [
            ("TimeOtp-Algorithm", "MD5"),
            ("TimeOtp-Length", "six"),
            ("TimeOtp-Period", "thirty"),
        ] {
            let mut fields = BTreeMap::from([(
                "TimeOtp-Secret-Base32".into(),
                CustomField {
                    value: "SECRET".into(),
                    protected: true,
                },
            )]);
            fields.insert(
                key.into(),
                CustomField {
                    value: invalid.into(),
                    protected: false,
                },
            );

            assert!(
                totp_from_persistent_attributes(&fields).is_none(),
                "malformed {key} was projected"
            );
            let mut entry = Entry::new(format!("malformed {key}"));
            entry.attributes = fields.clone();
            assert_eq!(materialize_entry_persistent_attributes(&entry), fields);
        }
    }

    #[test]
    fn structured_totp_projection_removes_the_complete_reserved_namespace() {
        let mut entry = Entry::new("structured OTP");
        for key in [
            "otp",
            "TimeOtp-Secret",
            "TimeOtp-Secret-Hex",
            "TimeOtp-Secret-Base32",
            "TimeOtp-Secret-Base64",
            "TimeOtp-Algorithm",
            "TimeOtp-Length",
            "TimeOtp-Period",
            "HmacOtp-Secret",
            "HmacOtp-Secret-Hex",
            "HmacOtp-Secret-Base32",
            "HmacOtp-Secret-Base64",
            "HmacOtp-Counter",
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: "stale".into(),
                    protected: false,
                },
            );
        }
        entry.totp = Some(TotpSpec {
            secret_base32: "SECRET".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("Example".into()),
            account_name: Some("alice".into()),
        });

        let materialized = materialize_entry_persistent_attributes(&entry);
        assert_eq!(materialized.len(), 5);
        assert_eq!(materialized["TimeOtp-Secret-Base32"].value(), "SECRET");
        for stale_key in [
            "TimeOtp-Secret",
            "TimeOtp-Secret-Hex",
            "TimeOtp-Secret-Base64",
            "HmacOtp-Secret",
            "HmacOtp-Secret-Hex",
            "HmacOtp-Secret-Base32",
            "HmacOtp-Secret-Base64",
            "HmacOtp-Counter",
        ] {
            assert!(
                !materialized.contains_key(stale_key),
                "stale key: {stale_key}"
            );
        }
    }

    #[test]
    fn persistent_attributes_overlay_projections_without_mutating_entry_attributes() {
        let mut entry = Entry::new("Example Login");
        entry.username = "alice@example.com".into();
        entry.attributes.insert(
            "Custom".into(),
            CustomField {
                value: "kept".into(),
                protected: false,
            },
        );
        for key in [
            "otp",
            PasskeyRecord::CREDENTIAL_ID_KEY,
            PasskeyRecord::GENERATED_USER_ID_KEY,
            PasskeyRecord::USER_HANDLE_KEY,
        ] {
            entry.attributes.insert(
                key.into(),
                CustomField {
                    value: "stale".into(),
                    protected: false,
                },
            );
        }
        entry.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period_seconds: 45,
            issuer: None,
            account_name: None,
        });
        entry.passkey = Some(PasskeyRecord {
            username: "alice".into(),
            credential_id: "credential".into(),
            generated_user_id: None,
            private_key_pem: "private-key".into(),
            relying_party: "example.com".into(),
            user_handle: None,
            backup_eligible: true,
            backup_state: false,
        });

        let attributes = materialize_entry_persistent_attributes(&entry);

        assert_eq!(entry.attributes["otp"].value, "stale");
        assert_eq!(attributes.len(), 12);
        let custom = attributes.get("Custom").expect("custom attribute");
        assert_eq!(custom.value(), "kept");
        assert!(!custom.protected());
        let otp = attributes.get("otp").expect("OTP attribute");
        assert_eq!(
            otp.value(),
            "otpauth://totp/Example%20Login:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Login&algorithm=SHA512&digits=8&period=45"
        );
        assert!(otp.protected());
        let discrete_secret = attributes
            .get("TimeOtp-Secret-Base32")
            .expect("discrete TOTP secret");
        assert_eq!(discrete_secret.value(), "JBSWY3DPEHPK3PXP");
        assert!(discrete_secret.protected());
        assert_eq!(attributes["TimeOtp-Algorithm"].value(), "HMAC-SHA-512");
        assert_eq!(attributes["TimeOtp-Length"].value(), "8");
        assert_eq!(attributes["TimeOtp-Period"].value(), "45");
        assert_eq!(
            attributes[PasskeyRecord::CREDENTIAL_ID_KEY].value(),
            "credential"
        );
        assert!(attributes[PasskeyRecord::CREDENTIAL_ID_KEY].protected());
        assert_eq!(
            attributes[PasskeyRecord::PRIVATE_KEY_PEM_KEY].value(),
            "private-key"
        );
        assert!(attributes[PasskeyRecord::PRIVATE_KEY_PEM_KEY].protected());
        assert!(!attributes.contains_key(PasskeyRecord::GENERATED_USER_ID_KEY));
        assert!(!attributes.contains_key(PasskeyRecord::USER_HANDLE_KEY));
    }

    #[test]
    fn persistent_totp_algorithm_spellings_match_kdbx_output() {
        for (algorithm, attribute_algorithm, uri_algorithm) in [
            (TotpAlgorithm::Sha1, "HMAC-SHA-1", "SHA1"),
            (TotpAlgorithm::Sha256, "HMAC-SHA-256", "SHA256"),
            (TotpAlgorithm::Sha512, "HMAC-SHA-512", "SHA512"),
        ] {
            let mut entry = Entry::new("Example");
            entry.totp = Some(TotpSpec {
                secret_base32: "SECRET".into(),
                algorithm,
                digits: 6,
                period_seconds: 30,
                issuer: Some("Issuer".into()),
                account_name: Some("account".into()),
            });

            let attributes = materialize_entry_persistent_attributes(&entry);

            assert_eq!(attributes["TimeOtp-Algorithm"].value(), attribute_algorithm);
            assert_eq!(
                attributes["otp"].value(),
                format!(
                    "otpauth://totp/Issuer:account?secret=SECRET&issuer=Issuer&algorithm={uri_algorithm}&digits=6&period=30"
                )
            );
        }
    }

    #[test]
    fn persistent_totp_uses_a_separator_for_an_empty_account() {
        let mut entry = Entry::new("Example");
        entry.totp = Some(TotpSpec {
            secret_base32: "SECRET".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("Issuer".into()),
            account_name: Some(String::new()),
        });

        let attributes = materialize_entry_persistent_attributes(&entry);

        assert_eq!(
            attributes["otp"].value(),
            "otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn persistent_totp_without_issuer_treats_an_empty_account_as_absent() {
        let mut entry = Entry::new("Example");
        entry.username = "fallback-account".into();
        entry.totp = Some(TotpSpec {
            secret_base32: "SECRET".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: None,
            account_name: Some(String::new()),
        });

        let attributes = materialize_entry_persistent_attributes(&entry);

        assert_eq!(
            attributes["otp"].value(),
            "otpauth://totp/Example:fallback-account?secret=SECRET&issuer=Example&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn passkey_record_requires_kpex_username_attribute() {
        let attributes = BTreeMap::from([
            (
                "Passkey Username".into(),
                CustomField {
                    value: "alice".into(),
                    protected: false,
                },
            ),
            (
                PasskeyRecord::CREDENTIAL_ID_KEY.into(),
                CustomField {
                    value: "cred-123".into(),
                    protected: true,
                },
            ),
            (
                PasskeyRecord::PRIVATE_KEY_PEM_KEY.into(),
                CustomField {
                    value: "pem".into(),
                    protected: true,
                },
            ),
            (
                PasskeyRecord::RELYING_PARTY_KEY.into(),
                CustomField {
                    value: "example.com".into(),
                    protected: false,
                },
            ),
        ]);

        assert!(PasskeyRecord::from_attributes(&attributes).is_none());
    }

    #[test]
    fn vault_search_finds_titles_urls_tags_and_usernames() {
        let mut vault = Vault::empty("Demo");
        let mut entry = Entry::new("Example Account");
        entry.username = "alice".into();
        entry.url = "https://example.com/login".into();
        entry.tags.insert("work".into());
        vault.root.entries.push(entry);

        assert_eq!(vault.search("example").len(), 1);
        assert_eq!(vault.search("alice").len(), 1);
        assert_eq!(vault.search("work").len(), 1);
        assert!(vault.search("missing").is_empty());
    }

    #[test]
    fn merge_prefers_newer_entry_and_preserves_history() {
        let mut local = Vault::empty("Local");
        let mut base = Entry::new("Shared");
        base.id = uuid::Uuid::nil();
        base.password = "old-secret".into();
        base.modified_at = 10;
        base.raw_state.node_order = vec!["Times".into(), "History".into()];
        base.raw_state.has_history_node = true;
        base.opaque_xml.push(OpaqueXmlFragment {
            xml: "<AfterHistory />".into(),
            after: Some(OpaqueXmlAnchor {
                element_name: "History".into(),
                occurrence: 1,
            }),
        });
        base.attachments.insert(
            "large.bin".into(),
            Attachment::new("large.bin", vec![0x3c; 1024 * 1024], false),
        );
        local.root.entries.push(base.clone());

        let mut incoming = Vault::empty("Incoming");
        let mut updated = base;
        updated.password = "new-secret".into();
        updated.modified_at = 20;
        incoming.root.entries.push(updated);

        let report = local.merge_from(&incoming);
        let merged = local.root.entries.first().expect("merged entry");

        assert_eq!(merged.password, "new-secret");
        assert_eq!(merged.history.len(), 1);
        assert_eq!(merged.history[0].password, "old-secret");
        assert!(!merged.history[0].raw_state.has_history_node);
        assert_eq!(merged.history[0].raw_state.node_order, ["Times"]);
        assert_eq!(
            merged.history[0].opaque_xml[0].after,
            Some(OpaqueXmlAnchor {
                element_name: "Times".into(),
                occurrence: 1,
            })
        );
        assert!(
            merged.attachments["large.bin"]
                .data
                .ptr_eq(&merged.history[0].attachments["large.bin"].data)
        );
        assert_eq!(report.merged_entries, 1);
        assert_eq!(report.history_snapshots_added, 1);
    }

    #[test]
    fn merge_normalizes_independently_owned_attachment_content() {
        let mut local = Vault::empty("Local");
        let mut local_entry = Entry::new("Shared");
        local_entry.id = uuid::Uuid::nil();
        local_entry.modified_at = 10;
        local_entry.attachments.insert(
            "shared.bin".into(),
            Attachment::new("shared.bin", b"same bytes".to_vec(), false),
        );
        local.root.entries.push(local_entry);

        let mut incoming = Vault::empty("Incoming");
        let mut incoming_entry = Entry::new("Shared");
        incoming_entry.id = uuid::Uuid::nil();
        incoming_entry.modified_at = 20;
        incoming_entry.attachments.insert(
            "shared.bin".into(),
            Attachment::new("shared.bin", b"same bytes".to_vec(), true),
        );
        incoming.root.entries.push(incoming_entry);

        assert!(
            !local.root.entries[0].attachments["shared.bin"]
                .data
                .ptr_eq(&incoming.root.entries[0].attachments["shared.bin"].data)
        );

        local.merge_from(&incoming);
        let merged = &local.root.entries[0];
        assert!(
            merged.attachments["shared.bin"]
                .data
                .ptr_eq(&merged.history[0].attachments["shared.bin"].data)
        );
        assert!(merged.attachments["shared.bin"].protect_in_memory);
        assert!(!merged.history[0].attachments["shared.bin"].protect_in_memory);
    }

    #[test]
    fn merge_preserves_incoming_history_when_newer_entry_wins() {
        let mut local = Vault::empty("Local");
        let mut base = Entry::new("Shared");
        base.id = uuid::Uuid::nil();
        base.password = "local-current".into();
        base.modified_at = 20;
        let mut local_history = base.clone();
        local_history.password = "local-history".into();
        local_history.modified_at = 10;
        local_history.history.clear();
        base.history.push(local_history);
        local.root.entries.push(base.clone());

        let mut incoming = Vault::empty("Incoming");
        let mut updated = base;
        updated.password = "remote-current".into();
        updated.modified_at = 40;
        updated.history.clear();
        let mut remote_history = updated.clone();
        remote_history.password = "remote-history".into();
        remote_history.modified_at = 30;
        remote_history.history.clear();
        updated.history.push(remote_history);
        incoming.root.entries.push(updated);

        let report = local.merge_from(&incoming);
        let merged = local.root.entries.first().expect("merged entry");

        assert_eq!(merged.password, "remote-current");
        assert_eq!(
            merged
                .history
                .iter()
                .map(|entry| entry.password.as_str())
                .collect::<Vec<_>>(),
            vec!["remote-history", "local-current"]
        );
        assert_eq!(report.merged_entries, 1);
        assert_eq!(report.history_snapshots_added, 1);
    }

    #[test]
    fn merge_applies_latest_tombstone_to_older_entries_on_both_sides() {
        let entry_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Local");
        let mut local_entry = Entry::new("local stale copy");
        local_entry.id = entry_id;
        local_entry.modified_at = 10;
        local.root.entries.push(local_entry);
        local.deleted_objects.push(DeletedObject {
            id: entry_id,
            deleted_at: 15,
        });

        let mut incoming = Vault::empty("Incoming");
        let mut incoming_entry = Entry::new("remote stale copy");
        incoming_entry.id = entry_id;
        incoming_entry.modified_at = 20;
        incoming.root.entries.push(incoming_entry);
        incoming.deleted_objects.extend([
            DeletedObject {
                id: entry_id,
                deleted_at: 12,
            },
            DeletedObject {
                id: entry_id,
                deleted_at: 30,
            },
        ]);

        local.merge_from(&incoming);

        assert!(local.root.entries.is_empty());
        assert_eq!(
            local.deleted_objects,
            [DeletedObject {
                id: entry_id,
                deleted_at: 30,
            }]
        );
    }

    #[test]
    fn merge_keeps_equal_or_newer_entry_edits_and_move_timestamps() {
        let equal_id = uuid::Uuid::new_v4();
        let moved_id = uuid::Uuid::new_v4();
        let resurrected_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Local");
        local.deleted_objects.extend([
            DeletedObject {
                id: equal_id,
                deleted_at: 20,
            },
            DeletedObject {
                id: moved_id,
                deleted_at: 30,
            },
            DeletedObject {
                id: resurrected_id,
                deleted_at: 40,
            },
        ]);

        let mut incoming = Vault::empty("Incoming");
        let mut equal = Entry::new("equal edit survives");
        equal.id = equal_id;
        equal.modified_at = 20;
        let mut moved = Entry::new("newer move survives");
        moved.id = moved_id;
        moved.modified_at = 10;
        moved.location_changed_at = Some(31);
        let mut resurrected = Entry::new("newer edit resurrects");
        resurrected.id = resurrected_id;
        resurrected.modified_at = 41;
        incoming.root.entries.extend([equal, moved, resurrected]);

        local.merge_from(&incoming);

        assert_eq!(local.root.entries.len(), 3);
        assert!(local.root.entries.iter().any(|entry| entry.id == equal_id));
        assert!(local.root.entries.iter().any(|entry| entry.id == moved_id));
        assert!(
            local
                .root
                .entries
                .iter()
                .any(|entry| entry.id == resurrected_id)
        );
        assert_eq!(local.deleted_objects.len(), 3);
    }

    #[test]
    fn merge_group_tombstone_removes_stale_subtree_but_keeps_newer_descendant() {
        let deleted_group_id = uuid::Uuid::new_v4();
        let surviving_group_id = uuid::Uuid::new_v4();
        let survivor_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Local");
        local.deleted_objects.extend([
            DeletedObject {
                id: deleted_group_id,
                deleted_at: 50,
            },
            DeletedObject {
                id: surviving_group_id,
                deleted_at: 50,
            },
        ]);

        let mut incoming = Vault::empty("Incoming");
        let mut stale_group = Group::new("stale subtree");
        stale_group.id = deleted_group_id;
        stale_group.times = Some(group_times(20));
        let mut stale_entry = Entry::new("stale entry");
        stale_entry.modified_at = 30;
        stale_group.entries.push(stale_entry);

        let mut surviving_group = Group::new("container survives");
        surviving_group.id = surviving_group_id;
        surviving_group.times = Some(group_times(20));
        let mut survivor = Entry::new("newer descendant");
        survivor.id = survivor_id;
        survivor.modified_at = 51;
        surviving_group.entries.push(survivor);
        incoming
            .root
            .children
            .extend([stale_group, surviving_group]);

        local.merge_from(&incoming);

        assert_eq!(local.root.children.len(), 1);
        assert_eq!(local.root.children[0].id, surviving_group_id);
        assert_eq!(local.root.children[0].entries[0].id, survivor_id);
    }

    #[test]
    fn merge_root_group_tombstone_prunes_stale_descendants_but_keeps_root() {
        let mut local = Vault::empty("Local");
        let root_id = local.root.id;
        let mut stale = Entry::new("stale");
        stale.modified_at = 10;
        local.root.entries.push(stale);

        let mut incoming = local.clone();
        incoming.deleted_objects.push(DeletedObject {
            id: root_id,
            deleted_at: 20,
        });

        local.merge_from(&incoming);

        assert_eq!(local.root.id, root_id);
        assert!(local.root.entries.is_empty());
        assert_eq!(local.deleted_objects[0].id, root_id);
    }

    #[test]
    fn merge_group_delete_competes_with_entries_moved_out_of_that_group() {
        let deleted_group_id = uuid::Uuid::new_v4();
        let stale_move_id = uuid::Uuid::new_v4();
        let newer_move_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Local");
        local.deleted_objects.push(DeletedObject {
            id: deleted_group_id,
            deleted_at: 50,
        });

        let mut incoming = local.clone();
        incoming.deleted_objects.clear();
        let mut destination = Group::new("Destination");
        let mut stale_move = Entry::new("stale move");
        stale_move.id = stale_move_id;
        stale_move.modified_at = 10;
        stale_move.previous_parent = Some(deleted_group_id);
        stale_move.location_changed_at = Some(40);
        let mut newer_move = Entry::new("newer move");
        newer_move.id = newer_move_id;
        newer_move.modified_at = 10;
        newer_move.previous_parent = Some(deleted_group_id);
        newer_move.location_changed_at = Some(51);
        destination.entries.extend([stale_move, newer_move]);
        incoming.root.children.push(destination);

        local.merge_from(&incoming);

        assert_eq!(local.root.children.len(), 1);
        assert_eq!(local.root.children[0].entries.len(), 1);
        assert_eq!(local.root.children[0].entries[0].id, newer_move_id);
    }

    #[test]
    fn merge_rejects_stale_group_move_from_deleted_parent() {
        let deleted_parent_id = uuid::Uuid::new_v4();
        let moved_group_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Shared");
        local.deleted_objects.push(DeletedObject {
            id: deleted_parent_id,
            deleted_at: 50,
        });

        let mut incoming = local.clone();
        incoming.deleted_objects.clear();
        let mut moved_group = Group::new("stale moved group");
        moved_group.id = moved_group_id;
        moved_group.previous_parent = Some(deleted_parent_id);
        moved_group.times = Some(GroupTimes {
            location_changed_at: Some(40),
            ..group_times(10)
        });
        incoming.root.children.push(moved_group);

        local.merge_from(&incoming);

        assert!(local.root.children.is_empty());
    }

    #[test]
    fn merge_preserves_subtree_of_group_moved_after_deletion() {
        let moved_group_id = uuid::Uuid::new_v4();
        let moved_entry_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Shared");
        local.deleted_objects.push(DeletedObject {
            id: moved_group_id,
            deleted_at: 50,
        });

        let mut incoming = local.clone();
        incoming.deleted_objects.clear();
        let mut moved_group = Group::new("newer moved group");
        moved_group.id = moved_group_id;
        moved_group.times = Some(GroupTimes {
            location_changed_at: Some(51),
            ..group_times(10)
        });
        let mut entry = Entry::new("subtree secret");
        entry.id = moved_entry_id;
        entry.modified_at = 10;
        moved_group.entries.push(entry);
        incoming.root.children.push(moved_group);

        local.merge_from(&incoming);

        assert_eq!(local.root.children.len(), 1);
        assert_eq!(local.root.children[0].entries.len(), 1);
        assert_eq!(local.root.children[0].entries[0].id, moved_entry_id);
    }

    #[test]
    fn tombstone_merge_report_is_direction_independent() {
        let mut live = Vault::empty("Shared");
        let mut entry = Entry::new("stale");
        entry.modified_at = 10;
        let entry_id = entry.id;
        live.root.entries.push(entry);

        let mut deleted = live.clone();
        deleted.root.entries.clear();
        deleted.deleted_objects.push(DeletedObject {
            id: entry_id,
            deleted_at: 20,
        });

        let mut live_target = live.clone();
        let live_target_report = live_target.merge_from(&deleted);
        let mut deleted_target = deleted;
        let deleted_target_report = deleted_target.merge_from(&live);

        assert_eq!(live_target, deleted_target);
        assert_eq!(live_target_report, deleted_target_report);
        assert_eq!(live_target_report.merged_entries, 1);
    }

    #[test]
    fn tombstone_merge_report_counts_a_resurrected_entry_once() {
        let mut local = Vault::empty("Shared");
        let mut stale = Entry::new("stale");
        stale.modified_at = 10;
        let entry_id = stale.id;
        local.root.entries.push(stale);
        local.deleted_objects.push(DeletedObject {
            id: entry_id,
            deleted_at: 15,
        });

        let mut incoming = local.clone();
        incoming.root.entries[0].title = "resurrected".into();
        incoming.root.entries[0].modified_at = 20;

        let report = local.merge_from(&incoming);

        assert_eq!(local.root.entries[0].title, "resurrected");
        assert_eq!(report.merged_entries, 1);
    }

    #[test]
    fn merge_tombstone_pruning_retargets_group_fidelity_anchors() {
        let deleted_entry_id = uuid::Uuid::new_v4();
        let deleted_group_id = uuid::Uuid::new_v4();
        let mut local = Vault::empty("Local");
        let mut entry = Entry::new("deleted");
        entry.id = deleted_entry_id;
        entry.modified_at = 10;
        local.root.entries.push(entry);
        let mut child = Group::new("deleted");
        child.id = deleted_group_id;
        child.times = Some(group_times(10));
        local.root.children.push(child);
        local.root.raw_state.node_order = vec![
            "Name".into(),
            "Entry".into(),
            "Group".into(),
            "CustomData".into(),
        ];
        local.root.raw_state.entry_order = vec![deleted_entry_id];
        local.root.raw_state.group_order = vec![deleted_group_id];
        local.root.opaque_xml.push(OpaqueXmlFragment {
            xml: "<AfterEntry />".into(),
            after: Some(OpaqueXmlAnchor {
                element_name: "Entry".into(),
                occurrence: 1,
            }),
        });
        local.root.custom_data_blocks.push(super::CustomDataBlock {
            items: Vec::new(),
            after: Some(OpaqueXmlAnchor {
                element_name: "Group".into(),
                occurrence: 1,
            }),
        });

        let mut incoming = Vault::empty("Incoming");
        incoming.deleted_objects.extend([
            DeletedObject {
                id: deleted_entry_id,
                deleted_at: 20,
            },
            DeletedObject {
                id: deleted_group_id,
                deleted_at: 20,
            },
        ]);

        local.merge_from(&incoming);

        assert_eq!(local.root.raw_state.node_order, ["Name", "CustomData"]);
        assert!(local.root.raw_state.entry_order.is_empty());
        assert!(local.root.raw_state.group_order.is_empty());
        assert_eq!(
            local.root.opaque_xml[0].after,
            Some(OpaqueXmlAnchor {
                element_name: "Name".into(),
                occurrence: 1,
            })
        );
        assert_eq!(
            local.root.custom_data_blocks[0].after,
            Some(OpaqueXmlAnchor {
                element_name: "Name".into(),
                occurrence: 1,
            })
        );
    }

    #[test]
    fn tombstone_merge_is_two_sided_convergent_for_delete_and_resurrect() {
        let mut base = Vault::empty("Shared");
        let mut entry = Entry::new("Shared entry");
        entry.modified_at = 10;
        let entry_id = entry.id;
        base.root.entries.push(entry);

        let mut deleted = base.clone();
        deleted.root.entries.clear();
        deleted.deleted_objects.push(DeletedObject {
            id: entry_id,
            deleted_at: 20,
        });
        let mut resurrected = base;
        resurrected.root.entries[0].title = "Resurrected".into();
        resurrected.root.entries[0].modified_at = 21;

        let mut delete_then_edit = deleted.clone();
        delete_then_edit.merge_from(&resurrected);
        let mut edit_then_delete = resurrected;
        edit_then_delete.merge_from(&deleted);

        assert_eq!(delete_then_edit, edit_then_delete);
        assert_eq!(delete_then_edit.root.entries[0].title, "Resurrected");
        assert_eq!(delete_then_edit.deleted_objects.len(), 1);
    }

    #[test]
    fn tombstone_merge_is_idempotent() {
        let mut local = Vault::empty("Shared");
        let mut stale = Entry::new("Stale");
        stale.modified_at = 10;
        let stale_id = stale.id;
        local.root.entries.push(stale);

        let mut incoming = local.clone();
        incoming.root.entries.clear();
        incoming.deleted_objects.push(DeletedObject {
            id: stale_id,
            deleted_at: 20,
        });

        local.merge_from(&incoming);
        let merged_once = local.clone();
        local.merge_from(&incoming);

        assert_eq!(local, merged_once);
    }

    fn group_times(modified_at: u64) -> GroupTimes {
        GroupTimes {
            created_at: 0,
            modified_at,
            expires: false,
            expiry_time: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        }
    }

    #[test]
    fn passkey_attributes_do_not_destroy_existing_custom_fields() {
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-123".into(),
            generated_user_id: None,
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: None,
            backup_eligible: false,
            backup_state: false,
        };

        let mut attributes = BTreeMap::from([(
            "custom".into(),
            CustomField {
                value: "kept".into(),
                protected: false,
            },
        )]);
        passkey.write_to_attributes(&mut attributes);

        assert_eq!(
            attributes.get("custom").map(|field| field.value.as_str()),
            Some("kept")
        );
    }

    #[test]
    fn passkey_attributes_clear_optional_kpex_fields_when_absent() {
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-123".into(),
            generated_user_id: None,
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: None,
            backup_eligible: false,
            backup_state: false,
        };

        let mut attributes = BTreeMap::from([
            (
                PasskeyRecord::GENERATED_USER_ID_KEY.into(),
                CustomField {
                    value: "stale-generated-user".into(),
                    protected: false,
                },
            ),
            (
                PasskeyRecord::USER_HANDLE_KEY.into(),
                CustomField {
                    value: "stale-user-handle".into(),
                    protected: true,
                },
            ),
        ]);

        passkey.write_to_attributes(&mut attributes);

        assert!(!attributes.contains_key(PasskeyRecord::GENERATED_USER_ID_KEY));
        assert!(!attributes.contains_key(PasskeyRecord::USER_HANDLE_KEY));
    }

    #[test]
    fn nested_group_search_reaches_children() {
        let mut vault = Vault::empty("Demo");
        let mut child = Group::new("Nested");
        child.entries.push(Entry::new("Nested Entry"));
        vault.root.children.push(child);

        assert_eq!(vault.search("Nested Entry").len(), 1);
    }
}
