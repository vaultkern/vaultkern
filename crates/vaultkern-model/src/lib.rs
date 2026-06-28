use std::collections::{BTreeMap, BTreeSet};

use data_encoding::BASE32_NOPAD;
use thiserror::Error;
use uuid::Uuid;
use vaultkern_crypto::{OtpAlgorithm, generate_totp};

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("feature not implemented yet")]
    Unimplemented,
    #[error("entry not found")]
    EntryNotFound,
}

pub type Result<T> = std::result::Result<T, ModelError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomField {
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
    pub protect_in_memory: bool,
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
    pub const USERNAME_KEY: &'static str = "Passkey Username";
    pub const CREDENTIAL_ID_KEY: &'static str = "KPEX_PASSKEY_CREDENTIAL_ID";
    pub const GENERATED_USER_ID_KEY: &'static str = "KPEX_PASSKEY_GENERATED_USER_ID";
    pub const PRIVATE_KEY_PEM_KEY: &'static str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
    pub const RELYING_PARTY_KEY: &'static str = "KPEX_PASSKEY_RELYING_PARTY";
    pub const USER_HANDLE_KEY: &'static str = "KPEX_PASSKEY_USER_HANDLE";
    pub const FLAG_BE_KEY: &'static str = "KPEX_PASSKEY_FLAG_BE";
    pub const FLAG_BS_KEY: &'static str = "KPEX_PASSKEY_FLAG_BS";

    pub fn write_to_attributes(&self, attributes: &mut BTreeMap<String, CustomField>) {
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
        if !uri.starts_with(PREFIX) {
            return Err(ModelError::Unimplemented);
        }

        let payload = &uri[PREFIX.len()..];
        let (label, query) = payload.split_once('?').ok_or(ModelError::Unimplemented)?;
        let label = percent_decode(label);

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

        let account_name = label
            .split_once(':')
            .map(|(_, account)| account.to_string());

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
    pub attachments: BTreeMap<String, Attachment>,
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
            attachments: BTreeMap::new(),
            history: Vec::new(),
            totp: None,
            passkey: None,
            icon_id: None,
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
            auto_type: None,
            custom_data: BTreeMap::new(),
            custom_data_blocks: Vec::new(),
            previous_parent: None,
            exclude_from_reports: false,
            raw_state: EntryRawState::default(),
            opaque_xml: Vec::new(),
        }
    }
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
        merge_group(&mut self.root, &other.root, &mut report);
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

fn merge_group(target: &mut Group, source: &Group, report: &mut MergeReport) {
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
                *existing = merged;
                report.merged_entries += 1;
                report.history_snapshots_added += 1;
            }
        } else {
            target.entries.push(incoming_entry.clone());
            report.merged_entries += 1;
        }
    }

    for incoming_group in &source.children {
        if let Some(index) = target
            .children
            .iter()
            .position(|group| group.id == incoming_group.id)
        {
            merge_group(&mut target.children[index], incoming_group, report);
        } else {
            target.children.push(incoming_group.clone());
        }
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let Ok(value) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                    decoded.push(value);
                    index += 3;
                    continue;
                }
                decoded.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                decoded.push(b' ');
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

#[cfg(test)]
mod tests {
    use super::{CustomField, Entry, Group, PasskeyRecord, TotpAlgorithm, TotpSpec, Vault};
    use std::collections::BTreeMap;

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

        let restored = PasskeyRecord::from_attributes(&attributes).expect("restore passkey");
        assert_eq!(restored, passkey);
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
        assert_eq!(report.merged_entries, 1);
        assert_eq!(report.history_snapshots_added, 1);
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
    fn nested_group_search_reaches_children() {
        let mut vault = Vault::empty("Demo");
        let mut child = Group::new("Nested");
        child.entries.push(Entry::new("Nested Entry"));
        vault.root.children.push(child);

        assert_eq!(vault.search("Nested Entry").len(), 1);
    }
}
