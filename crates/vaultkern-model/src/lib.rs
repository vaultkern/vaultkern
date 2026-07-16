use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Weak};

#[cfg(test)]
use std::sync::atomic::AtomicBool;

use data_encoding::BASE32_NOPAD;
use thiserror::Error;
use uuid::Uuid;
use vaultkern_crypto::{OtpAlgorithm, generate_totp};

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetaRawState {
    pub node_order: Vec<String>,
    pub description_raw: Option<String>,
    pub default_username_raw: Option<String>,
    pub color_raw: Option<String>,
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
    pub default_auto_type_sequence_raw: Option<String>,
    pub enable_auto_type_raw: Option<String>,
    pub enable_searching_raw: Option<String>,
    pub last_top_visible_entry_raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryRawState {
    pub node_order: Vec<String>,
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

impl PasskeyRecord {
    pub const USERNAME_KEY: &'static str = "KPEX_PASSKEY_USERNAME";
    pub const CREDENTIAL_ID_KEY: &'static str = "KPEX_PASSKEY_CREDENTIAL_ID";
    pub const GENERATED_USER_ID_KEY: &'static str = "KPEX_PASSKEY_GENERATED_USER_ID";
    pub const PRIVATE_KEY_PEM_KEY: &'static str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
    pub const RELYING_PARTY_KEY: &'static str = "KPEX_PASSKEY_RELYING_PARTY";
    pub const USER_HANDLE_KEY: &'static str = "KPEX_PASSKEY_USER_HANDLE";
    pub const FLAG_BE_KEY: &'static str = "KPEX_PASSKEY_FLAG_BE";
    pub const FLAG_BS_KEY: &'static str = "KPEX_PASSKEY_FLAG_BS";

    pub fn write_to_attributes(&self, attributes: &mut BTreeMap<String, CustomField>) {
        attributes.remove(Self::GENERATED_USER_ID_KEY);
        attributes.remove(Self::USER_HANDLE_KEY);
        attributes.insert(
            Self::USERNAME_KEY.into(),
            CustomField {
                value: self.username.clone(),
                protected: false,
            },
        );
        attributes.insert(
            Self::CREDENTIAL_ID_KEY.into(),
            CustomField {
                value: self.credential_id.clone(),
                protected: true,
            },
        );
        if let Some(generated_user_id) = &self.generated_user_id {
            attributes.insert(
                Self::GENERATED_USER_ID_KEY.into(),
                CustomField {
                    value: generated_user_id.clone(),
                    protected: false,
                },
            );
        }
        attributes.insert(
            Self::PRIVATE_KEY_PEM_KEY.into(),
            CustomField {
                value: self.private_key_pem.clone(),
                protected: true,
            },
        );
        attributes.insert(
            Self::RELYING_PARTY_KEY.into(),
            CustomField {
                value: self.relying_party.clone(),
                protected: false,
            },
        );
        if let Some(user_handle) = &self.user_handle {
            attributes.insert(
                Self::USER_HANDLE_KEY.into(),
                CustomField {
                    value: user_handle.clone(),
                    protected: true,
                },
            );
        }
        attributes.insert(
            Self::FLAG_BE_KEY.into(),
            CustomField {
                value: if self.backup_eligible { "1" } else { "0" }.into(),
                protected: false,
            },
        );
        attributes.insert(
            Self::FLAG_BS_KEY.into(),
            CustomField {
                value: if self.backup_state { "1" } else { "0" }.into(),
                protected: false,
            },
        );
    }

    pub fn from_attributes(attributes: &BTreeMap<String, CustomField>) -> Option<Self> {
        Some(Self {
            username: attributes.get(Self::USERNAME_KEY)?.value.clone(),
            credential_id: attributes.get(Self::CREDENTIAL_ID_KEY)?.value.clone(),
            generated_user_id: attributes
                .get(Self::GENERATED_USER_ID_KEY)
                .map(|field| field.value.clone()),
            private_key_pem: attributes.get(Self::PRIVATE_KEY_PEM_KEY)?.value.clone(),
            relying_party: attributes.get(Self::RELYING_PARTY_KEY)?.value.clone(),
            user_handle: attributes
                .get(Self::USER_HANDLE_KEY)
                .map(|field| field.value.clone()),
            backup_eligible: attributes
                .get(Self::FLAG_BE_KEY)
                .map(|field| field.value == "1" || field.value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            backup_state: attributes
                .get(Self::FLAG_BS_KEY)
                .map(|field| field.value == "1" || field.value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        })
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
            (
                Some(percent_decode(issuer)),
                Some(percent_decode(trim_encoded_label_spaces(account))),
            )
        } else if let Some((issuer, account)) = split_once_encoded_label_separator(label) {
            (
                Some(percent_decode(issuer)),
                Some(percent_decode(trim_encoded_label_spaces(account))),
            )
        } else {
            let account = percent_decode(label);
            (None, (!account.is_empty()).then_some(account))
        };
        let mut secret = None;
        let mut issuer = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period_seconds = 30_u64;

        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_decode(value);
            match key {
                "secret" => secret = Some(value),
                "issuer" => issuer = Some(value),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" | "HMAC-SHA-1" => TotpAlgorithm::Sha1,
                        "SHA256" | "HMAC-SHA-256" => TotpAlgorithm::Sha256,
                        "SHA512" | "HMAC-SHA-512" => TotpAlgorithm::Sha512,
                        _ => return Err(ModelError::Unimplemented),
                    }
                }
                "digits" => digits = value.parse().map_err(|_| ModelError::Unimplemented)?,
                "period" => {
                    period_seconds = value.parse().map_err(|_| ModelError::Unimplemented)?
                }
                _ => {}
            }
        }

        if issuer.is_none() {
            issuer = label_issuer;
        }

        Ok(Self {
            secret_base32: secret.ok_or(ModelError::Unimplemented)?,
            algorithm,
            digits,
            period_seconds,
            issuer,
            account_name,
        })
    }

    pub fn generate_at(&self, unix_time: u64) -> Result<String> {
        let algorithm = match self.algorithm {
            TotpAlgorithm::Sha1 => OtpAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => OtpAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => OtpAlgorithm::Sha512,
        };

        let normalized = self.secret_base32.replace('=', "").to_ascii_uppercase();
        let secret = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| ModelError::Unimplemented)?;

        generate_totp(
            &secret,
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
            expiry_time: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
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

/// Builds the transient persistent-attribute view after overlaying credential projections.
pub fn materialize_entry_persistent_attributes(entry: &Entry) -> BTreeMap<String, CustomField> {
    let mut attributes = entry.attributes.clone();
    if let Some(totp) = &entry.totp {
        let (attribute_algorithm, uri_algorithm) = match totp.algorithm {
            TotpAlgorithm::Sha1 => ("HMAC-SHA-1", "SHA1"),
            TotpAlgorithm::Sha256 => ("HMAC-SHA-256", "SHA256"),
            TotpAlgorithm::Sha512 => ("HMAC-SHA-512", "SHA512"),
        };
        attributes.insert(
            "otp".into(),
            CustomField {
                value: entry_otpauth_uri(entry, totp, uri_algorithm),
                protected: true,
            },
        );
        attributes.insert(
            "TimeOtp-Secret-Base32".into(),
            CustomField {
                value: totp.secret_base32.clone(),
                protected: true,
            },
        );
        attributes.insert(
            "TimeOtp-Algorithm".into(),
            CustomField {
                value: attribute_algorithm.into(),
                protected: false,
            },
        );
        attributes.insert(
            "TimeOtp-Length".into(),
            CustomField {
                value: totp.digits.to_string(),
                protected: false,
            },
        );
        attributes.insert(
            "TimeOtp-Period".into(),
            CustomField {
                value: totp.period_seconds.to_string(),
                protected: false,
            },
        );
    }
    if let Some(passkey) = &entry.passkey {
        passkey.write_to_attributes(&mut attributes);
    }
    attributes
}

fn entry_otpauth_uri(entry: &Entry, totp: &TotpSpec, algorithm: &str) -> String {
    let issuer = totp.issuer.clone().unwrap_or_else(|| entry.title.clone());
    let account_name = totp
        .account_name
        .clone()
        .unwrap_or_else(|| entry.username.clone());
    let label = if account_name.is_empty() {
        format!("{}:", percent_encode_component(&issuer))
    } else {
        format!(
            "{}:{}",
            percent_encode_component(&issuer),
            percent_encode_component(&account_name)
        )
    };
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        label = label,
        secret = percent_encode_component(&totp.secret_base32),
        issuer = percent_encode_component(&issuer),
        algorithm = algorithm,
        digits = totp.digits,
        period = totp.period_seconds,
    )
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
            root_raw_state: RootRawState::default(),
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
        merge_group(&mut self.root, &other.root, &mut content_pool, &mut report);
        report
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MergeReport {
    pub merged_entries: usize,
    pub history_snapshots_added: usize,
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
                snapshot.history.clear();
                let mut merged = incoming_entry.clone();
                merged.history.push(snapshot);
                normalize_entry_attachment_content(&mut merged, content_pool);
                *existing = merged;
                report.merged_entries += 1;
                report.history_snapshots_added += 1;
            }
        } else {
            let mut incoming_entry = incoming_entry.clone();
            normalize_entry_attachment_content(&mut incoming_entry, content_pool);
            target.entries.push(incoming_entry);
            report.merged_entries += 1;
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

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
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

    String::from_utf8_lossy(&decoded).into_owned()
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
        Entry, Group, ModelError, PasskeyRecord, TotpAlgorithm, TotpSpec, Vault,
        materialize_entry_persistent_attributes,
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
    fn otpauth_parser_preserves_an_empty_account_name() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer")
            .expect("parse otpauth");

        assert_eq!(spec.account_name.as_deref(), Some(""));
    }

    #[test]
    fn otpauth_parser_preserves_an_empty_account_when_the_issuer_contains_a_colon() {
        let spec = TotpSpec::parse_otpauth(
            "otpauth://totp/Issuer%3AProd:?secret=SECRET&issuer=Issuer%3AProd",
        )
        .expect("parse otpauth");

        assert_eq!(spec.issuer.as_deref(), Some("Issuer:Prod"));
        assert_eq!(spec.account_name.as_deref(), Some(""));
    }

    #[test]
    fn otpauth_parser_does_not_invent_an_empty_account_without_an_issuer() {
        let spec = TotpSpec::parse_otpauth("otpauth://totp/?secret=SECRET").expect("parse otpauth");

        assert_eq!(spec.account_name, None);
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
        assert_eq!(
            attributes.get("Custom"),
            Some(&CustomField {
                value: "kept".into(),
                protected: false,
            })
        );
        assert_eq!(
            attributes.get("otp"),
            Some(&CustomField {
                value: "otpauth://totp/Example%20Login:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Login&algorithm=SHA512&digits=8&period=45".into(),
                protected: true,
            })
        );
        assert_eq!(
            attributes.get("TimeOtp-Secret-Base32"),
            Some(&CustomField {
                value: "JBSWY3DPEHPK3PXP".into(),
                protected: true,
            })
        );
        assert_eq!(attributes["TimeOtp-Algorithm"].value, "HMAC-SHA-512");
        assert_eq!(attributes["TimeOtp-Length"].value, "8");
        assert_eq!(attributes["TimeOtp-Period"].value, "45");
        assert_eq!(
            attributes[PasskeyRecord::CREDENTIAL_ID_KEY].value,
            "credential"
        );
        assert!(attributes[PasskeyRecord::CREDENTIAL_ID_KEY].protected);
        assert_eq!(
            attributes[PasskeyRecord::PRIVATE_KEY_PEM_KEY].value,
            "private-key"
        );
        assert!(attributes[PasskeyRecord::PRIVATE_KEY_PEM_KEY].protected);
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

            assert_eq!(attributes["TimeOtp-Algorithm"].value, attribute_algorithm);
            assert_eq!(
                attributes["otp"].value,
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
            attributes["otp"].value,
            "otpauth://totp/Issuer:?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30"
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
