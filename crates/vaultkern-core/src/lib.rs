use std::error::Error as StdError;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
pub use vaultkern_crypto::{CompositeKey, CryptoError, KdfProfile, parse_key_file_bytes};
pub use vaultkern_kdbx::{
    Compression, ExternalKdfAlgorithm, ExternalKdfConfirmation, ExternalKdfDecision,
    ExternalKdfParameter, ExternalKdfParameters, ExternalKdfPolicy, ExternalKdfRequest,
    ExternalKdfResource, KdbxCipher, KdbxError, KdbxHeader, KdbxHeaderSummary, KdbxVersion,
    KdfPolicyEvaluator, SaveKdf, SaveProfile, VariantDictionary, VariantValue, inspect_kdbx_header,
    load_kdbx as load_kdbx_bytes, load_kdbx_with_policy, required_version,
    save_kdbx as save_kdbx_bytes,
};
use vaultkern_model::Attachment as ModelAttachment;
pub use vaultkern_model::{
    AttachmentContent, AttachmentContentId, AttachmentMap, AutoTypeAssociation, AutoTypeConfig,
    CustomField, CustomIcon, DeletedObject, Entry, EntryFieldProtection, Group, GroupFlags,
    GroupTimes, MemoryProtection, MergeReport, ModelError, PasskeyRecord, TotpAlgorithm, TotpSpec,
    Vault,
};

#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
    pub protect_in_memory: bool,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Attachment")
            .field("name", &self.name)
            .field("data_len", &self.data.len())
            .field("protect_in_memory", &self.protect_in_memory)
            .finish()
    }
}

impl From<Attachment> for ModelAttachment {
    fn from(attachment: Attachment) -> Self {
        ModelAttachment::new(
            attachment.name,
            attachment.data,
            attachment.protect_in_memory,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSummary {
    pub name: String,
    pub root_title: String,
    pub groups: usize,
    pub entries: usize,
    pub attachments: usize,
    pub deleted_objects: usize,
    pub custom_data_items: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadWarning {
    LegacyFormat(KdbxVersion),
    SaveWillUpgradeToV4_1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseInspection {
    pub header: KdbxHeaderSummary,
    pub save_target_version: KdbxVersion,
    pub warnings: Vec<LoadWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDatabase {
    pub vault: Vault,
    pub summary: VaultSummary,
    pub inspection: DatabaseInspection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSummaryView {
    pub merged_entries: usize,
    pub history_snapshots_added: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryView {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub icon_id: Option<u32>,
    pub custom_icon_id: Option<String>,
    pub tags: Vec<String>,
    pub attachment_count: usize,
    pub custom_field_count: usize,
    pub history_count: usize,
    pub has_totp: bool,
    pub has_passkey: bool,
    pub expires: bool,
    pub field_protection: EntryFieldProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDetailView {
    pub id: String,
    pub title: String,
    pub icon_id: Option<u32>,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub modified_at: u64,
    pub custom_icon_id: Option<String>,
    pub tags: Vec<String>,
    pub field_protection: EntryFieldProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHistoryDetailView {
    pub title: String,
    pub icon_id: Option<u32>,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub modified_at: u64,
    pub custom_icon_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: String,
    pub title: String,
    pub icon_id: Option<u32>,
    pub custom_icon_id: Option<String>,
    pub entry_count: usize,
    pub child_count: usize,
    pub entries: Vec<EntryView>,
    pub children: Vec<GroupView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDetailView {
    pub id: String,
    pub title: String,
    pub icon_id: Option<u32>,
    pub notes: String,
    pub custom_icon_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultView {
    pub summary: VaultSummary,
    pub root: GroupView,
    pub deleted_objects: usize,
    pub recycle_bin_enabled: Option<bool>,
    pub recycle_bin_group_id: Option<String>,
    pub entry_templates_group_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMetadataView {
    pub description: Option<String>,
    pub default_username: Option<String>,
    pub color: Option<String>,
    pub history_max_items: Option<i32>,
    pub history_max_size: Option<i64>,
    pub memory_protection: Option<MemoryProtection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSelectionMetadataView {
    pub last_selected_group_id: Option<String>,
    pub last_top_visible_group_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLifecycleMetadataView {
    pub settings_changed: Option<i64>,
    pub maintenance_history_days: Option<i32>,
    pub master_key_changed: Option<i64>,
    pub master_key_change_rec: Option<i64>,
    pub master_key_change_force: Option<i64>,
    pub master_key_change_force_once: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultBinTemplateMetadataView {
    pub recycle_bin_enabled: Option<bool>,
    pub recycle_bin_group_id: Option<String>,
    pub recycle_bin_changed: Option<i64>,
    pub entry_templates_group_id: Option<String>,
    pub entry_templates_group_changed: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultIdentityMetadataView {
    pub name: String,
    pub generator: Option<String>,
    pub database_name_changed: Option<i64>,
    pub description_changed: Option<i64>,
    pub default_username_changed: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCustomDataSemanticView {
    pub last_modified: Option<String>,
    pub fdo_secrets_exposed_group_id: Option<String>,
    pub keepassxc_browser_items: Vec<CustomDataItemView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBehaviorMetadataView {
    pub default_auto_type_sequence: Option<String>,
    pub last_top_visible_entry_id: Option<String>,
    pub enable_auto_type: Option<bool>,
    pub enable_searching: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLineageTagMetadataView {
    pub tags: Vec<String>,
    pub previous_parent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTimesView {
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    pub last_accessed_at: Option<u64>,
    pub usage_count: Option<u64>,
    pub location_changed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupExpiryView {
    pub expires: Option<bool>,
    pub expiry_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPresentationMetadataView {
    pub icon_id: Option<u32>,
    pub foreground_color: Option<String>,
    pub background_color: Option<String>,
    pub override_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCustomFieldView {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryLineageReportMetadataView {
    pub previous_parent_id: Option<String>,
    pub exclude_from_reports: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryTotpView {
    pub secret_base32: String,
    pub algorithm: vaultkern_model::TotpAlgorithm,
    pub digits: u32,
    pub period_seconds: u64,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPasskeyView {
    pub username: String,
    pub credential_id: String,
    pub generated_user_id: Option<String>,
    pub private_key_pem: String,
    pub relying_party: String,
    pub user_handle: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAutoTypeAssociationView {
    pub window: String,
    pub sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAutoTypeView {
    pub enabled: Option<bool>,
    pub obfuscation: Option<i32>,
    pub default_sequence: Option<String>,
    pub associations: Vec<EntryAutoTypeAssociationView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryTimesView {
    pub created_at: u64,
    pub modified_at: u64,
    pub last_accessed_at: Option<u64>,
    pub usage_count: Option<u64>,
    pub location_changed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObjectView {
    pub id: String,
    pub deleted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDatabaseView {
    pub database: VaultView,
    pub inspection: DatabaseInspection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMatchView {
    pub entry: EntryView,
    pub group_id: String,
    pub group_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHistoryItemView {
    pub title: String,
    pub username: String,
    pub modified_at: u64,
    pub attachment_count: usize,
    pub custom_field_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCreate {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryUpdate {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupMetadataUpdate {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub icon_id: Option<u32>,
    pub flags: Option<GroupFlags>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupBehaviorMetadataUpdate {
    pub default_auto_type_sequence: Option<String>,
    pub last_top_visible_entry_id: Option<String>,
    pub enable_auto_type: Option<bool>,
    pub enable_searching: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupLineageTagMetadataUpdate {
    pub tags: Option<Vec<String>>,
    pub previous_parent_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupTimesUpdate {
    pub created_at: Option<Option<u64>>,
    pub modified_at: Option<Option<u64>>,
    pub last_accessed_at: Option<Option<u64>>,
    pub usage_count: Option<Option<u64>>,
    pub location_changed_at: Option<Option<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryPresentationMetadataUpdate {
    pub icon_id: Option<Option<u32>>,
    pub foreground_color: Option<Option<String>>,
    pub background_color: Option<Option<String>>,
    pub override_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryLineageReportMetadataUpdate {
    pub previous_parent_id: Option<Option<String>>,
    pub exclude_from_reports: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAutoTypeAssociationInput {
    pub window: String,
    pub sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryAutoTypeUpdate {
    pub enabled: Option<Option<bool>>,
    pub obfuscation: Option<Option<i32>>,
    pub default_sequence: Option<Option<String>>,
    pub associations: Option<Vec<EntryAutoTypeAssociationInput>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryTimesUpdate {
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    pub last_accessed_at: Option<Option<u64>>,
    pub usage_count: Option<Option<u64>>,
    pub location_changed_at: Option<Option<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomIconView {
    pub id: String,
    pub data: Vec<u8>,
    pub name: Option<String>,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomIconInput {
    pub id: Option<String>,
    pub data: Vec<u8>,
    pub name: Option<String>,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataItemView {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCustomDataItemView {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCustomDataItemDetailInput {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCustomDataItemView {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCustomDataItemDetailInput {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCustomDataItemView {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCustomDataItemDetailInput {
    pub key: String,
    pub value: String,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataItemInput {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
    pub protect_in_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentContentView {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttachmentMetadataUpdate {
    pub new_name: Option<String>,
    pub protect_in_memory: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentContentUpdate {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCustomDataItemView {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCustomDataItemInput {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultMetadataUpdate {
    pub description: Option<String>,
    pub default_username: Option<String>,
    pub color: Option<String>,
    pub history_max_items: Option<i32>,
    pub history_max_size: Option<i64>,
    pub memory_protection: Option<MemoryProtection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultSelectionMetadataUpdate {
    pub last_selected_group_id: Option<Option<String>>,
    pub last_top_visible_group_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultLifecycleMetadataUpdate {
    pub settings_changed: Option<i64>,
    pub maintenance_history_days: Option<i32>,
    pub master_key_changed: Option<i64>,
    pub master_key_change_rec: Option<i64>,
    pub master_key_change_force: Option<i64>,
    pub master_key_change_force_once: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultBinTemplateMetadataUpdate {
    pub recycle_bin_enabled: Option<Option<bool>>,
    pub recycle_bin_group_id: Option<Option<String>>,
    pub recycle_bin_changed: Option<Option<i64>>,
    pub entry_templates_group_id: Option<Option<String>>,
    pub entry_templates_group_changed: Option<Option<i64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultIdentityMetadataUpdate {
    pub name: Option<String>,
    pub generator: Option<String>,
    pub database_name_changed: Option<i64>,
    pub description_changed: Option<i64>,
    pub default_username_changed: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryExpiryUpdate {
    pub expires: bool,
    pub expiry_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupExpiryUpdate {
    pub expires: bool,
    pub expiry_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryFieldProtectionUpdate {
    pub protect_title: Option<bool>,
    pub protect_username: Option<bool>,
    pub protect_password: Option<bool>,
    pub protect_url: Option<bool>,
    pub protect_notes: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCustomFieldInput {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

fn is_reserved_entry_custom_field_key(key: &str) -> bool {
    matches!(
        key,
        "Title"
            | "UserName"
            | "Password"
            | "URL"
            | "Notes"
            | "otp"
            | "TimeOtp-Secret-Base32"
            | "TimeOtp-Algorithm"
            | "TimeOtp-Length"
            | "TimeOtp-Period"
    ) || key.starts_with("KPEX_PASSKEY_")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAttachmentInput {
    pub name: String,
    pub data: Vec<u8>,
    pub protect_in_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCustomDataInput {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableSaveCipher {
    Aes256,
    ChaCha20,
    Twofish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableSaveCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StableSaveKdf {
    Recommended,
    AesKdbx4 {
        rounds: u64,
    },
    Argon2id {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableSaveProfile {
    pub cipher: StableSaveCipher,
    pub compression: StableSaveCompression,
    pub kdf: StableSaveKdf,
}

impl StableSaveProfile {
    pub fn recommended() -> Self {
        Self {
            cipher: StableSaveCipher::Aes256,
            compression: StableSaveCompression::Gzip,
            kdf: StableSaveKdf::Recommended,
        }
    }

    pub fn aes_compatibility() -> Self {
        Self {
            cipher: StableSaveCipher::Aes256,
            compression: StableSaveCompression::Gzip,
            kdf: StableSaveKdf::AesKdbx4 { rounds: 100_000 },
        }
    }

    pub fn to_save_profile(&self) -> SaveProfile {
        SaveProfile {
            version: KdbxVersion::V4_1,
            cipher: match self.cipher {
                StableSaveCipher::Aes256 => KdbxCipher::Aes256,
                StableSaveCipher::ChaCha20 => KdbxCipher::ChaCha20,
                StableSaveCipher::Twofish => KdbxCipher::Twofish,
            },
            compression: match self.compression {
                StableSaveCompression::None => Compression::None,
                StableSaveCompression::Gzip => Compression::Gzip,
            },
            kdf: match self.kdf {
                StableSaveKdf::Recommended => SaveProfile::recommended().kdf,
                StableSaveKdf::AesKdbx4 { rounds } => SaveKdf::AesKdbx4 { rounds },
                StableSaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                } => SaveKdf::Argon2id {
                    iterations,
                    memory_kib,
                    parallelism,
                },
            },
        }
    }
}

#[derive(Debug)]
pub enum CoreError {
    Kdbx(KdbxError),
    Crypto(CryptoError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kdbx(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl StdError for CoreError {}

impl From<KdbxError> for CoreError {
    fn from(value: KdbxError) -> Self {
        Self::Kdbx(value)
    }
}

impl From<CryptoError> for CoreError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    GroupNotFound(String),
    EntryNotFound(String),
    HistoryIndexOutOfBounds(usize),
    CustomFieldNotFound(String),
    ReservedCustomFieldKey(String),
    InvalidEntryValue(String),
    AttachmentNotFound(String),
    AttachmentAlreadyExists(String),
    AttachmentContentHashCollision,
    CustomDataNotFound(String),
    CustomIconNotFound(String),
    InvalidUuid(String),
    UuidCollision(String),
    CannotDeleteRootGroup,
    CannotMoveRootGroup,
    CannotMoveGroupIntoDescendant,
}

impl fmt::Display for MutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupNotFound(id) => write!(f, "group not found: {id}"),
            Self::EntryNotFound(id) => write!(f, "entry not found: {id}"),
            Self::HistoryIndexOutOfBounds(index) => {
                write!(f, "history index out of bounds: {index}")
            }
            Self::CustomFieldNotFound(key) => write!(f, "custom field not found: {key}"),
            Self::ReservedCustomFieldKey(key) => {
                write!(f, "reserved custom field key: {key}")
            }
            Self::InvalidEntryValue(message) => write!(f, "invalid entry value: {message}"),
            Self::AttachmentNotFound(name) => write!(f, "attachment not found: {name}"),
            Self::AttachmentAlreadyExists(name) => write!(f, "attachment already exists: {name}"),
            Self::AttachmentContentHashCollision => {
                write!(f, "attachment content hash collision")
            }
            Self::CustomDataNotFound(key) => write!(f, "custom data not found: {key}"),
            Self::CustomIconNotFound(id) => write!(f, "custom icon not found: {id}"),
            Self::InvalidUuid(value) => write!(f, "invalid uuid: {value}"),
            Self::UuidCollision(value) => write!(f, "uuid is already in use: {value}"),
            Self::CannotDeleteRootGroup => write!(f, "cannot delete root group"),
            Self::CannotMoveRootGroup => write!(f, "cannot move root group"),
            Self::CannotMoveGroupIntoDescendant => {
                write!(f, "cannot move group into its descendant")
            }
        }
    }
}

impl StdError for MutationError {}

#[derive(Debug, Clone, Default)]
pub struct KeepassCore;

impl KeepassCore {
    pub fn new() -> Self {
        Self
    }

    pub fn empty_vault(&self, name: impl Into<String>) -> Vault {
        Vault::empty(name)
    }

    pub fn capabilities(&self) -> Vec<&'static str> {
        vec![
            "composite-key",
            "key-file",
            "totp",
            "variant-dictionary",
            "search",
            "merge",
            "passkey-model",
            "kdbx-byte-api",
            "attachments-roundtrip",
            "stable-binding-facade",
            "stable-query-facade",
            "stable-mutation-facade",
            "stable-save-profile-facade",
            "stable-rich-entry-mutation-facade",
            "stable-recycle-bin-mutation-facade",
            "stable-group-metadata-mutation-facade",
            "stable-advanced-entry-semantic-mutation-facade",
            "stable-entry-history-mutation-facade",
            "stable-vault-metadata-mutation-facade",
            "stable-entry-field-protection-mutation-facade",
            "stable-group-behavior-metadata-mutation-facade",
            "stable-custom-icon-mutation-facade",
            "stable-vault-group-custom-data-facade",
            "stable-merge-facade",
            "stable-node-move-facade",
            "stable-attachment-metadata-facade",
            "stable-attachment-content-replace-facade",
            "stable-attachment-content-projection-facade",
            "stable-public-custom-data-facade",
            "stable-entry-presentation-metadata-facade",
            "stable-entry-lineage-report-metadata-facade",
            "stable-entry-auto-type-facade",
            "stable-entry-times-facade",
            "stable-group-times-facade",
            "stable-group-expiry-facade",
            "stable-vault-selection-metadata-facade",
            "stable-vault-lifecycle-metadata-facade",
            "stable-vault-bin-template-metadata-facade",
            "stable-vault-identity-metadata-facade",
            "stable-group-lineage-tag-metadata-facade",
            "stable-entry-semantic-projection-facade",
            "stable-entry-detail-projection-facade",
            "stable-group-detail-projection-facade",
            "stable-group-behavior-detail-projection-facade",
            "stable-entry-history-detail-projection-facade",
            "stable-entry-history-attachment-projection-facade",
            "stable-entry-history-semantic-projection-facade",
            "stable-entry-history-presentation-metadata-projection-facade",
            "stable-entry-history-lineage-report-projection-facade",
            "stable-entry-custom-icon-projection-facade",
            "stable-group-custom-icon-projection-facade",
            "stable-icon-detail-projection-facade",
            "stable-entry-history-icon-detail-projection-facade",
        ]
    }

    pub fn save_kdbx(
        &self,
        vault: &Vault,
        composite_key: &CompositeKey,
        profile: SaveProfile,
    ) -> Result<Vec<u8>, vaultkern_kdbx::KdbxError> {
        save_kdbx_bytes(vault, composite_key, &profile)
    }

    pub fn save_kdbx_with_stable_profile(
        &self,
        vault: &Vault,
        composite_key: &CompositeKey,
        profile: StableSaveProfile,
    ) -> Result<Vec<u8>, vaultkern_kdbx::KdbxError> {
        self.save_kdbx(vault, composite_key, profile.to_save_profile())
    }

    pub fn load_kdbx(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
    ) -> Result<Vault, vaultkern_kdbx::KdbxError> {
        load_kdbx_bytes(bytes, composite_key)
    }

    pub fn load_kdbx_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<Vault, vaultkern_kdbx::KdbxError> {
        load_kdbx_with_policy(bytes, composite_key, policy, confirmation)
    }

    pub fn inspect_kdbx_header(
        &self,
        bytes: &[u8],
    ) -> Result<KdbxHeaderSummary, vaultkern_kdbx::KdbxError> {
        inspect_kdbx_header(bytes)
    }

    pub fn summarize_vault(&self, vault: &Vault) -> VaultSummary {
        summarize_vault(vault)
    }

    pub fn inspect_database(&self, bytes: &[u8]) -> Result<DatabaseInspection, CoreError> {
        let header = inspect_kdbx_header(bytes)?;
        Ok(build_inspection(header))
    }

    pub fn project_vault(&self, vault: &Vault) -> VaultView {
        project_vault(vault)
    }

    pub fn project_vault_metadata(&self, vault: &Vault) -> VaultMetadataView {
        project_vault_metadata(vault)
    }

    pub fn project_vault_selection_metadata(&self, vault: &Vault) -> VaultSelectionMetadataView {
        project_vault_selection_metadata(vault)
    }

    pub fn project_vault_lifecycle_metadata(&self, vault: &Vault) -> VaultLifecycleMetadataView {
        project_vault_lifecycle_metadata(vault)
    }

    pub fn project_vault_bin_template_metadata(
        &self,
        vault: &Vault,
    ) -> VaultBinTemplateMetadataView {
        project_vault_bin_template_metadata(vault)
    }

    pub fn project_vault_identity_metadata(&self, vault: &Vault) -> VaultIdentityMetadataView {
        project_vault_identity_metadata(vault)
    }

    pub fn project_vault_custom_data_semantics(
        &self,
        vault: &Vault,
    ) -> VaultCustomDataSemanticView {
        project_vault_custom_data_semantics(vault)
    }

    pub fn project_group_behavior_metadata(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<GroupBehaviorMetadataView, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_behavior_metadata(group))
    }

    pub fn project_group_lineage_tag_metadata(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<GroupLineageTagMetadataView, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_lineage_tag_metadata(group))
    }

    pub fn project_group_detail(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<GroupDetailView, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_detail(group))
    }

    pub fn project_group_times(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<GroupTimesView, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_times(group))
    }

    pub fn project_group_expiry(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<GroupExpiryView, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_expiry(group))
    }

    pub fn project_entry_presentation_metadata(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<EntryPresentationMetadataView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_presentation_metadata(entry))
    }

    pub fn project_entry_lineage_report_metadata(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<EntryLineageReportMetadataView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_lineage_report_metadata(entry))
    }

    pub fn project_entry_totp(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Option<EntryTotpView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(entry.totp.as_ref().map(project_entry_totp))
    }

    pub fn project_entry_detail(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<EntryDetailView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_detail(entry))
    }

    pub fn project_entry_history_detail(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryHistoryDetailView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_history_detail(snapshot))
    }

    pub fn project_entry_history_presentation_metadata(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryPresentationMetadataView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_presentation_metadata(snapshot))
    }

    pub fn project_entry_history_lineage_report_metadata(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryLineageReportMetadataView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_lineage_report_metadata(snapshot))
    }

    pub fn project_entry_history_field_protection(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryFieldProtection, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(snapshot.field_protection)
    }

    pub fn project_entry_history_totp(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<Option<EntryTotpView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(snapshot.totp.as_ref().map(project_entry_totp))
    }

    pub fn project_entry_passkey(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Option<EntryPasskeyView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(entry.passkey.as_ref().map(project_entry_passkey))
    }

    pub fn project_entry_history_passkey(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<Option<EntryPasskeyView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(snapshot.passkey.as_ref().map(project_entry_passkey))
    }

    pub fn project_entry_auto_type(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<EntryAutoTypeView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_auto_type(entry))
    }

    pub fn project_entry_history_auto_type(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryAutoTypeView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_auto_type(snapshot))
    }

    pub fn project_entry_times(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<EntryTimesView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_times(entry))
    }

    pub fn project_entry_history_times(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<EntryTimesView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_times(snapshot))
    }

    pub fn find_group_view_by_id(&self, vault: &Vault, id: &str) -> Option<GroupView> {
        find_group_by_id(&vault.root, id).map(project_group)
    }

    pub fn find_entry_view_by_id(&self, vault: &Vault, id: &str) -> Option<EntryView> {
        find_entry_by_id(&vault.root, id).map(project_entry)
    }

    pub fn search_entries_view(&self, vault: &Vault, term: &str) -> Vec<EntryMatchView> {
        search_entries_view(vault, term)
    }

    pub fn summarize_merge_report(&self, report: &MergeReport) -> MergeSummaryView {
        project_merge_report(report)
    }

    pub fn list_entry_history(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Vec<EntryHistoryItemView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(entry.history.iter().map(project_history_item).collect())
    }

    pub fn list_entry_attachments(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Vec<AttachmentView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_attachment_items(&entry.attachments))
    }

    pub fn project_entry_attachment_content(
        &self,
        vault: &Vault,
        entry_id: &str,
        name: &str,
    ) -> Result<AttachmentContentView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let attachment = entry
            .attachments
            .get(name)
            .ok_or_else(|| MutationError::AttachmentNotFound(name.into()))?;
        Ok(AttachmentContentView {
            name: attachment.name.clone(),
            data: attachment.data.as_bytes().to_vec(),
        })
    }

    pub fn list_entry_history_attachments(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<Vec<AttachmentView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let history_item = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_attachment_items(&history_item.attachments))
    }

    pub fn project_entry_history_attachment_content(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
        name: &str,
    ) -> Result<AttachmentContentView, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let history_item = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        let attachment = history_item
            .attachments
            .get(name)
            .ok_or_else(|| MutationError::AttachmentNotFound(name.into()))?;
        Ok(AttachmentContentView {
            name: attachment.name.clone(),
            data: attachment.data.as_bytes().to_vec(),
        })
    }

    pub fn list_entry_custom_fields(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Vec<EntryCustomFieldView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_custom_fields(&entry.attributes))
    }

    pub fn list_entry_history_custom_fields(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<Vec<EntryCustomFieldView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_entry_custom_fields(&snapshot.attributes))
    }

    pub fn list_entry_custom_data(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_custom_data_items(&entry.custom_data))
    }

    pub fn list_entry_custom_data_detail(
        &self,
        vault: &Vault,
        entry_id: &str,
    ) -> Result<Vec<EntryCustomDataItemView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        Ok(project_entry_custom_data_items(entry))
    }

    pub fn list_entry_history_custom_data(
        &self,
        vault: &Vault,
        entry_id: &str,
        history_index: usize,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        let entry = find_entry_by_id(&vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let snapshot = entry
            .history
            .get(history_index)
            .ok_or(MutationError::HistoryIndexOutOfBounds(history_index))?;
        Ok(project_custom_data_items(&snapshot.custom_data))
    }

    pub fn list_deleted_objects(&self, vault: &Vault) -> Vec<DeletedObjectView> {
        vault
            .deleted_objects
            .iter()
            .map(|item| DeletedObjectView {
                id: item.id.to_string(),
                deleted_at: item.deleted_at,
            })
            .collect()
    }

    pub fn list_custom_icons(&self, vault: &Vault) -> Vec<CustomIconView> {
        vault.custom_icons.iter().map(project_custom_icon).collect()
    }

    pub fn list_vault_custom_data(&self, vault: &Vault) -> Vec<CustomDataItemView> {
        project_custom_data_items(&vault.meta_custom_data)
    }

    pub fn list_vault_custom_data_detail(&self, vault: &Vault) -> Vec<VaultCustomDataItemView> {
        project_vault_custom_data_items(vault)
    }

    pub fn list_vault_public_custom_data(&self, vault: &Vault) -> Vec<PublicCustomDataItemView> {
        project_public_custom_data_items(&vault.public_custom_data)
    }

    pub fn list_group_custom_data(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_custom_data_items(&group.custom_data))
    }

    pub fn list_group_custom_data_detail(
        &self,
        vault: &Vault,
        group_id: &str,
    ) -> Result<Vec<GroupCustomDataItemView>, MutationError> {
        let group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        Ok(project_group_custom_data_items(group))
    }

    pub fn update_entry_fields(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryUpdate,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;

        if let Some(title) = update.title {
            entry.title = title;
        }
        if let Some(username) = update.username {
            entry.username = username;
        }
        if let Some(password) = update.password {
            entry.password = password;
        }
        if let Some(url) = update.url {
            entry.url = url;
        }
        if let Some(notes) = update.notes {
            entry.notes = notes;
        }

        Ok(project_entry(entry))
    }

    pub fn update_entry_presentation_metadata(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryPresentationMetadataUpdate,
    ) -> Result<EntryPresentationMetadataView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;

        if let Some(icon_id) = update.icon_id {
            entry.icon_id = icon_id;
        }
        if let Some(foreground_color) = update.foreground_color {
            entry.foreground_color = foreground_color;
            entry.raw_state.foreground_color_raw = None;
        }
        if let Some(background_color) = update.background_color {
            entry.background_color = background_color;
            entry.raw_state.background_color_raw = None;
        }
        if let Some(override_url) = update.override_url {
            entry.override_url = override_url;
            entry.raw_state.override_url_raw = None;
        }

        Ok(project_entry_presentation_metadata(entry))
    }

    pub fn update_entry_lineage_report_metadata(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryLineageReportMetadataUpdate,
    ) -> Result<EntryLineageReportMetadataView, MutationError> {
        if let Some(previous_parent_id) = &update.previous_parent_id
            && let Some(group_id) = previous_parent_id
        {
            let parsed = parse_uuid(group_id)?;
            if find_group_by_id(&vault.root, group_id).is_none() {
                return Err(MutationError::GroupNotFound(group_id.clone()));
            }
            let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
                .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
            entry.previous_parent = Some(parsed);
            if let Some(exclude_from_reports) = update.exclude_from_reports {
                entry.exclude_from_reports = exclude_from_reports;
                entry.raw_state.quality_check_raw = None;
            }
            return Ok(project_entry_lineage_report_metadata(entry));
        }

        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;

        if let Some(previous_parent_id) = update.previous_parent_id {
            entry.previous_parent = match previous_parent_id {
                Some(_) => entry.previous_parent,
                None => None,
            };
        }
        if let Some(exclude_from_reports) = update.exclude_from_reports {
            entry.exclude_from_reports = exclude_from_reports;
            entry.raw_state.quality_check_raw = None;
        }

        Ok(project_entry_lineage_report_metadata(entry))
    }

    pub fn update_entry_auto_type(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryAutoTypeUpdate,
    ) -> Result<EntryAutoTypeView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let auto_type = entry.auto_type.get_or_insert_with(AutoTypeConfig::default);

        if let Some(enabled) = update.enabled {
            auto_type.enabled = enabled;
        }
        if let Some(obfuscation) = update.obfuscation {
            auto_type.obfuscation = obfuscation;
        }
        if let Some(default_sequence) = update.default_sequence {
            auto_type.default_sequence = default_sequence;
        }
        if let Some(associations) = update.associations {
            auto_type.associations = associations
                .into_iter()
                .map(|association| AutoTypeAssociation {
                    window: association.window,
                    sequence: association.sequence,
                })
                .collect();
        }

        Ok(project_entry_auto_type(entry))
    }

    pub fn update_entry_times(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryTimesUpdate,
    ) -> Result<EntryTimesView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;

        if let Some(created_at) = update.created_at {
            entry.created_at = created_at;
        }
        if let Some(modified_at) = update.modified_at {
            entry.modified_at = modified_at;
        }
        if let Some(last_accessed_at) = update.last_accessed_at {
            entry.last_accessed_at = last_accessed_at;
        }
        if let Some(usage_count) = update.usage_count {
            entry.usage_count = usage_count;
        }
        if let Some(location_changed_at) = update.location_changed_at {
            entry.location_changed_at = location_changed_at;
        }

        Ok(project_entry_times(entry))
    }

    pub fn add_entry(
        &self,
        vault: &mut Vault,
        parent_group_id: &str,
        create: EntryCreate,
    ) -> Result<EntryView, MutationError> {
        let entry_id = Uuid::new_v4().to_string();
        self.add_entry_with_id(vault, parent_group_id, &entry_id, create)
    }

    pub fn add_entry_with_id(
        &self,
        vault: &mut Vault,
        parent_group_id: &str,
        entry_id: &str,
        create: EntryCreate,
    ) -> Result<EntryView, MutationError> {
        let parsed_entry_id = parse_uuid(entry_id)?;
        if parsed_entry_id.is_nil() || parsed_entry_id.to_string() != entry_id {
            return Err(MutationError::InvalidUuid(entry_id.into()));
        }
        if group_or_entry_uses_uuid(&vault.root, parsed_entry_id)
            || vault
                .deleted_objects
                .iter()
                .any(|deleted| deleted.id == parsed_entry_id)
        {
            return Err(MutationError::UuidCollision(entry_id.into()));
        }

        let parent = find_group_by_id_mut(&mut vault.root, parent_group_id)
            .ok_or_else(|| MutationError::GroupNotFound(parent_group_id.into()))?;

        let mut entry = Entry::new(create.title);
        entry.id = parsed_entry_id;
        entry.username = create.username;
        entry.password = create.password;
        entry.url = create.url;
        entry.notes = create.notes;
        parent.entries.push(entry);
        let entry = parent.entries.last().expect("created entry");
        Ok(project_entry(entry))
    }

    pub fn delete_entry(&self, vault: &mut Vault, entry_id: &str) -> Result<(), MutationError> {
        if delete_entry_from_group(&mut vault.root, entry_id) {
            Ok(())
        } else {
            Err(MutationError::EntryNotFound(entry_id.into()))
        }
    }

    pub fn add_group(
        &self,
        vault: &mut Vault,
        parent_group_id: &str,
        title: impl Into<String>,
    ) -> Result<GroupView, MutationError> {
        let parent = find_group_by_id_mut(&mut vault.root, parent_group_id)
            .ok_or_else(|| MutationError::GroupNotFound(parent_group_id.into()))?;
        parent.children.push(Group::new(title));
        let group = parent.children.last().expect("created group");
        Ok(project_group(group))
    }

    pub fn delete_group(&self, vault: &mut Vault, group_id: &str) -> Result<(), MutationError> {
        if vault.root.id.to_string() == group_id {
            return Err(MutationError::CannotDeleteRootGroup);
        }
        if delete_group_from_group(&mut vault.root, group_id) {
            Ok(())
        } else {
            Err(MutationError::GroupNotFound(group_id.into()))
        }
    }

    pub fn merge_vaults(&self, target: &mut Vault, source: &Vault) -> MergeSummaryView {
        let report = target.merge_from(source);
        project_merge_report(&report)
    }

    pub fn load_and_merge_kdbx(
        &self,
        target: &mut Vault,
        bytes: &[u8],
        composite_key: &CompositeKey,
    ) -> Result<MergeSummaryView, CoreError> {
        let source = self.load_kdbx(bytes, composite_key)?;
        Ok(self.merge_vaults(target, &source))
    }

    pub fn move_entry(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        target_group_id: &str,
    ) -> Result<EntryView, MutationError> {
        let (entry, _) = take_entry_from_group(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let target_group = find_group_by_id_mut(&mut vault.root, target_group_id)
            .ok_or_else(|| MutationError::GroupNotFound(target_group_id.into()))?;
        target_group.entries.push(entry);
        let entry = target_group.entries.last().expect("moved entry");
        Ok(project_entry(entry))
    }

    pub fn move_group(
        &self,
        vault: &mut Vault,
        group_id: &str,
        target_parent_group_id: &str,
    ) -> Result<GroupView, MutationError> {
        if vault.root.id.to_string() == group_id {
            return Err(MutationError::CannotMoveRootGroup);
        }
        let moving_group = find_group_by_id(&vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        if moving_group.id.to_string() == target_parent_group_id
            || group_contains_id(moving_group, target_parent_group_id)
        {
            return Err(MutationError::CannotMoveGroupIntoDescendant);
        }

        let moved_group = take_group_from_group(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        let target_parent = find_group_by_id_mut(&mut vault.root, target_parent_group_id)
            .ok_or_else(|| MutationError::GroupNotFound(target_parent_group_id.into()))?;
        target_parent.children.push(moved_group);
        let group = target_parent.children.last().expect("moved group");
        Ok(project_group(group))
    }

    pub fn update_group_metadata(
        &self,
        vault: &mut Vault,
        group_id: &str,
        update: GroupMetadataUpdate,
    ) -> Result<GroupView, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;

        if let Some(title) = update.title {
            group.title = title;
        }
        if let Some(notes) = update.notes {
            group.notes = notes;
        }
        if let Some(icon_id) = update.icon_id {
            group.icon_id = Some(icon_id);
        }
        if let Some(flags) = update.flags {
            group.flags = flags;
        }

        Ok(project_group(group))
    }

    pub fn update_group_behavior_metadata(
        &self,
        vault: &mut Vault,
        group_id: &str,
        update: GroupBehaviorMetadataUpdate,
    ) -> Result<GroupBehaviorMetadataView, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;

        if let Some(sequence) = update.default_auto_type_sequence {
            group.default_auto_type_sequence = Some(sequence);
        }
        if let Some(last_top_visible_entry_id) = update.last_top_visible_entry_id {
            let parsed = Uuid::parse_str(&last_top_visible_entry_id)
                .map_err(|_| MutationError::InvalidUuid(last_top_visible_entry_id.clone()))?;
            group.last_top_visible_entry = Some(parsed);
        }
        if let Some(enable_auto_type) = update.enable_auto_type {
            group.flags.enable_auto_type = Some(enable_auto_type);
        }
        if let Some(enable_searching) = update.enable_searching {
            group.flags.enable_searching = Some(enable_searching);
        }

        Ok(project_group_behavior_metadata(group))
    }

    pub fn update_group_lineage_tag_metadata(
        &self,
        vault: &mut Vault,
        group_id: &str,
        update: GroupLineageTagMetadataUpdate,
    ) -> Result<GroupLineageTagMetadataView, MutationError> {
        let previous_parent = match update.previous_parent_id.as_ref() {
            Some(Some(previous_parent_id)) => {
                let parsed = parse_uuid(previous_parent_id)?;
                if find_group_by_id(&vault.root, previous_parent_id).is_none() {
                    return Err(MutationError::GroupNotFound(previous_parent_id.clone()));
                }
                Some(Some(parsed))
            }
            Some(None) => Some(None),
            None => None,
        };

        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;

        if let Some(tags) = update.tags {
            group.tags = tags.into_iter().collect();
        }
        if let Some(previous_parent) = previous_parent {
            group.previous_parent = previous_parent;
        }

        Ok(project_group_lineage_tag_metadata(group))
    }

    pub fn update_group_times(
        &self,
        vault: &mut Vault,
        group_id: &str,
        update: GroupTimesUpdate,
    ) -> Result<GroupTimesView, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        let times = group.times.get_or_insert(GroupTimes {
            created_at: 0,
            modified_at: 0,
            expires: false,
            expiry_time: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        });

        if let Some(created_at) = update.created_at.flatten() {
            times.created_at = created_at;
        }
        if let Some(modified_at) = update.modified_at.flatten() {
            times.modified_at = modified_at;
        }
        if let Some(last_accessed_at) = update.last_accessed_at {
            times.last_accessed_at = last_accessed_at;
        }
        if let Some(usage_count) = update.usage_count {
            times.usage_count = usage_count;
        }
        if let Some(location_changed_at) = update.location_changed_at {
            times.location_changed_at = location_changed_at;
        }

        Ok(project_group_times(group))
    }

    pub fn update_group_expiry(
        &self,
        vault: &mut Vault,
        group_id: &str,
        update: GroupExpiryUpdate,
    ) -> Result<GroupExpiryView, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        let times = group.times.get_or_insert(GroupTimes {
            created_at: 0,
            modified_at: 0,
            expires: false,
            expiry_time: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        });
        times.expires = update.expires;
        times.expiry_time = update.expiry_time;
        Ok(project_group_expiry(group))
    }

    pub fn update_group_custom_icon(
        &self,
        vault: &mut Vault,
        group_id: &str,
        custom_icon_id: Option<String>,
    ) -> Result<GroupView, MutationError> {
        let parsed_custom_icon_id = match custom_icon_id {
            Some(id) => Some(parse_uuid(&id)?),
            None => None,
        };
        if let Some(custom_icon_id) = parsed_custom_icon_id
            && !vault
                .custom_icons
                .iter()
                .any(|icon| icon.id == custom_icon_id)
        {
            return Err(MutationError::CustomIconNotFound(
                custom_icon_id.to_string(),
            ));
        }

        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        group.custom_icon_id = parsed_custom_icon_id;
        Ok(project_group(group))
    }

    pub fn update_entry_custom_icon(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        custom_icon_id: Option<String>,
    ) -> Result<EntryView, MutationError> {
        let parsed_custom_icon_id = match custom_icon_id {
            Some(id) => Some(parse_uuid(&id)?),
            None => None,
        };
        if let Some(custom_icon_id) = parsed_custom_icon_id
            && !vault
                .custom_icons
                .iter()
                .any(|icon| icon.id == custom_icon_id)
        {
            return Err(MutationError::CustomIconNotFound(
                custom_icon_id.to_string(),
            ));
        }

        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.custom_icon_id = parsed_custom_icon_id;
        Ok(project_entry(entry))
    }

    pub fn upsert_custom_icon(
        &self,
        vault: &mut Vault,
        input: CustomIconInput,
    ) -> Result<CustomIconView, MutationError> {
        let icon_id = match input.id {
            Some(value) => parse_uuid(&value)?,
            None => Uuid::new_v4(),
        };

        if let Some(existing) = vault
            .custom_icons
            .iter_mut()
            .find(|icon| icon.id == icon_id)
        {
            existing.data = input.data;
            existing.name = input.name;
            existing.last_modified = input.last_modified;
            return Ok(project_custom_icon(existing));
        }

        vault.custom_icons.push(CustomIcon {
            id: icon_id,
            data: input.data,
            name: input.name,
            last_modified: input.last_modified,
        });
        let icon = vault.custom_icons.last().expect("inserted custom icon");
        Ok(project_custom_icon(icon))
    }

    pub fn delete_custom_icon(
        &self,
        vault: &mut Vault,
        icon_id: &str,
    ) -> Result<(), MutationError> {
        let parsed_icon_id = parse_uuid(icon_id)?;
        let Some(index) = vault
            .custom_icons
            .iter()
            .position(|icon| icon.id == parsed_icon_id)
        else {
            return Err(MutationError::CustomIconNotFound(icon_id.into()));
        };
        vault.custom_icons.remove(index);
        clear_custom_icon_references_from_group(&mut vault.root, parsed_icon_id);
        Ok(())
    }

    pub fn upsert_vault_custom_data(
        &self,
        vault: &mut Vault,
        item: CustomDataItemInput,
    ) -> Vec<CustomDataItemView> {
        let key = item.key;
        vault.meta_custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut vault.meta_custom_data_blocks,
            &vault.meta_custom_data,
            Some((&key, None)),
        );
        project_custom_data_items(&vault.meta_custom_data)
    }

    pub fn upsert_vault_custom_data_detail(
        &self,
        vault: &mut Vault,
        item: VaultCustomDataItemDetailInput,
    ) -> Vec<VaultCustomDataItemView> {
        let key = item.key;
        vault.meta_custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut vault.meta_custom_data_blocks,
            &vault.meta_custom_data,
            Some((&key, item.last_modified)),
        );
        project_vault_custom_data_items(vault)
    }

    pub fn delete_vault_custom_data(
        &self,
        vault: &mut Vault,
        key: &str,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        if vault.meta_custom_data.remove(key).is_none() {
            return Err(MutationError::CustomDataNotFound(key.into()));
        }
        canonicalize_custom_data_blocks(
            &mut vault.meta_custom_data_blocks,
            &vault.meta_custom_data,
            None,
        );
        Ok(project_custom_data_items(&vault.meta_custom_data))
    }

    pub fn upsert_vault_public_custom_data(
        &self,
        vault: &mut Vault,
        item: PublicCustomDataItemInput,
    ) -> Vec<PublicCustomDataItemView> {
        vault.public_custom_data.insert(item.key, item.value);
        project_public_custom_data_items(&vault.public_custom_data)
    }

    pub fn delete_vault_public_custom_data(
        &self,
        vault: &mut Vault,
        key: &str,
    ) -> Result<Vec<PublicCustomDataItemView>, MutationError> {
        if vault.public_custom_data.remove(key).is_none() {
            return Err(MutationError::CustomDataNotFound(key.into()));
        }
        Ok(project_public_custom_data_items(&vault.public_custom_data))
    }

    pub fn upsert_group_custom_data(
        &self,
        vault: &mut Vault,
        group_id: &str,
        item: CustomDataItemInput,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        let key = item.key;
        group.custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut group.custom_data_blocks,
            &group.custom_data,
            Some((&key, None)),
        );
        Ok(project_custom_data_items(&group.custom_data))
    }

    pub fn upsert_group_custom_data_detail(
        &self,
        vault: &mut Vault,
        group_id: &str,
        item: GroupCustomDataItemDetailInput,
    ) -> Result<Vec<GroupCustomDataItemView>, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        let key = item.key;
        group.custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut group.custom_data_blocks,
            &group.custom_data,
            Some((&key, item.last_modified)),
        );
        Ok(project_group_custom_data_items(group))
    }

    pub fn delete_group_custom_data(
        &self,
        vault: &mut Vault,
        group_id: &str,
        key: &str,
    ) -> Result<Vec<CustomDataItemView>, MutationError> {
        let group = find_group_by_id_mut(&mut vault.root, group_id)
            .ok_or_else(|| MutationError::GroupNotFound(group_id.into()))?;
        if group.custom_data.remove(key).is_none() {
            return Err(MutationError::CustomDataNotFound(key.into()));
        }
        canonicalize_custom_data_blocks(&mut group.custom_data_blocks, &group.custom_data, None);
        Ok(project_custom_data_items(&group.custom_data))
    }

    pub fn update_vault_metadata(
        &self,
        vault: &mut Vault,
        update: VaultMetadataUpdate,
    ) -> VaultMetadataView {
        if let Some(description) = update.description {
            vault.description = Some(description);
        }
        if let Some(default_username) = update.default_username {
            vault.default_username = Some(default_username);
        }
        if let Some(color) = update.color {
            vault.color = Some(color);
        }
        if let Some(history_max_items) = update.history_max_items {
            vault.history_max_items = Some(history_max_items);
        }
        if let Some(history_max_size) = update.history_max_size {
            vault.history_max_size = Some(history_max_size);
        }
        if let Some(memory_protection) = update.memory_protection {
            vault.memory_protection = Some(memory_protection);
        }

        project_vault_metadata(vault)
    }

    pub fn update_vault_selection_metadata(
        &self,
        vault: &mut Vault,
        update: VaultSelectionMetadataUpdate,
    ) -> Result<VaultSelectionMetadataView, MutationError> {
        if let Some(last_selected_group_id) = update.last_selected_group_id {
            vault.last_selected_group = match last_selected_group_id {
                Some(group_id) => {
                    let parsed = parse_uuid(&group_id)?;
                    if find_group_by_id(&vault.root, &group_id).is_none() {
                        return Err(MutationError::GroupNotFound(group_id));
                    }
                    Some(parsed)
                }
                None => None,
            };
        }
        if let Some(last_top_visible_group_id) = update.last_top_visible_group_id {
            vault.last_top_visible_group = match last_top_visible_group_id {
                Some(group_id) => {
                    let parsed = parse_uuid(&group_id)?;
                    if find_group_by_id(&vault.root, &group_id).is_none() {
                        return Err(MutationError::GroupNotFound(group_id));
                    }
                    Some(parsed)
                }
                None => None,
            };
        }

        Ok(project_vault_selection_metadata(vault))
    }

    pub fn update_vault_lifecycle_metadata(
        &self,
        vault: &mut Vault,
        update: VaultLifecycleMetadataUpdate,
    ) -> VaultLifecycleMetadataView {
        vault.settings_changed = update.settings_changed;
        vault.maintenance_history_days = update.maintenance_history_days;
        vault.master_key_changed = update.master_key_changed;
        vault.master_key_change_rec = update.master_key_change_rec;
        vault.master_key_change_force = update.master_key_change_force;
        vault.master_key_change_force_once = update.master_key_change_force_once;
        project_vault_lifecycle_metadata(vault)
    }

    pub fn update_vault_bin_template_metadata(
        &self,
        vault: &mut Vault,
        update: VaultBinTemplateMetadataUpdate,
    ) -> Result<VaultBinTemplateMetadataView, MutationError> {
        if let Some(recycle_bin_enabled) = update.recycle_bin_enabled {
            vault.recycle_bin_enabled = recycle_bin_enabled;
        }
        if let Some(recycle_bin_group_id) = update.recycle_bin_group_id {
            vault.recycle_bin_group = match recycle_bin_group_id {
                Some(group_id) => {
                    let parsed = parse_uuid(&group_id)?;
                    if find_group_by_id(&vault.root, &group_id).is_none() {
                        return Err(MutationError::GroupNotFound(group_id));
                    }
                    Some(parsed)
                }
                None => None,
            };
        }
        if let Some(recycle_bin_changed) = update.recycle_bin_changed {
            vault.recycle_bin_changed = recycle_bin_changed;
        }
        if let Some(entry_templates_group_id) = update.entry_templates_group_id {
            vault.entry_templates_group = match entry_templates_group_id {
                Some(group_id) => {
                    let parsed = parse_uuid(&group_id)?;
                    if find_group_by_id(&vault.root, &group_id).is_none() {
                        return Err(MutationError::GroupNotFound(group_id));
                    }
                    Some(parsed)
                }
                None => None,
            };
        }
        if let Some(entry_templates_group_changed) = update.entry_templates_group_changed {
            vault.entry_templates_group_changed = entry_templates_group_changed;
        }

        Ok(project_vault_bin_template_metadata(vault))
    }

    pub fn update_vault_identity_metadata(
        &self,
        vault: &mut Vault,
        update: VaultIdentityMetadataUpdate,
    ) -> VaultIdentityMetadataView {
        if let Some(name) = update.name {
            vault.name = name;
        }
        vault.generator = update.generator;
        vault.database_name_changed = update.database_name_changed;
        vault.description_changed = update.description_changed;
        vault.default_username_changed = update.default_username_changed;
        project_vault_identity_metadata(vault)
    }

    pub fn replace_entry_tags(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        tags: Vec<String>,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if let Some(tag) = tags.iter().find(|tag| tag.is_empty() || tag.contains(';')) {
            return Err(MutationError::InvalidEntryValue(format!(
                "tag cannot be empty or contain ';': {tag:?}"
            )));
        }
        entry.tags = tags.into_iter().collect();
        entry.raw_state.tags_raw = None;
        Ok(project_entry(entry))
    }

    pub fn upsert_entry_custom_field(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        field: EntryCustomFieldInput,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if field.key.is_empty() {
            return Err(MutationError::InvalidEntryValue(
                "custom field key cannot be empty".into(),
            ));
        }
        if is_reserved_entry_custom_field_key(&field.key) {
            return Err(MutationError::ReservedCustomFieldKey(field.key));
        }
        entry.attributes.insert(
            field.key,
            CustomField {
                value: field.value,
                protected: field.protected,
            },
        );
        Ok(project_entry(entry))
    }

    pub fn delete_entry_custom_field(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        key: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if entry.attributes.remove(key).is_none() {
            return Err(MutationError::CustomFieldNotFound(key.into()));
        }
        Ok(project_entry(entry))
    }

    pub fn add_entry_attachment(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        attachment: EntryAttachmentInput,
    ) -> Result<EntryView, MutationError> {
        let content = shared_attachment_content(&vault.root, &attachment.data)?;
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if attachment.name.is_empty() {
            return Err(MutationError::InvalidEntryValue(
                "attachment name cannot be empty".into(),
            ));
        }
        let name = attachment.name.clone();
        entry.attachments.insert(
            name,
            ModelAttachment::with_content(attachment.name, content, attachment.protect_in_memory),
        );
        Ok(project_entry(entry))
    }

    pub fn delete_entry_attachment(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        name: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if entry.attachments.remove(name).is_none() {
            return Err(MutationError::AttachmentNotFound(name.into()));
        }
        Ok(project_entry(entry))
    }

    pub fn update_entry_attachment_metadata(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        name: &str,
        update: AttachmentMetadataUpdate,
    ) -> Result<Vec<AttachmentView>, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if update.new_name.as_deref() == Some("") {
            return Err(MutationError::InvalidEntryValue(
                "attachment name cannot be empty".into(),
            ));
        }
        let mut attachment = entry
            .attachments
            .remove(name)
            .ok_or_else(|| MutationError::AttachmentNotFound(name.into()))?;

        let target_name = update.new_name.unwrap_or_else(|| attachment.name.clone());
        if target_name != name && entry.attachments.contains_key(&target_name) {
            entry.attachments.insert(name.into(), attachment);
            return Err(MutationError::AttachmentAlreadyExists(target_name));
        }

        attachment.name = target_name.clone();
        if let Some(protect_in_memory) = update.protect_in_memory {
            attachment.protect_in_memory = protect_in_memory;
        }
        entry.attachments.insert(target_name, attachment);
        Ok(project_attachment_items(&entry.attachments))
    }

    pub fn replace_entry_attachment_content(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        name: &str,
        update: AttachmentContentUpdate,
    ) -> Result<Vec<AttachmentView>, MutationError> {
        let content = shared_attachment_content(&vault.root, &update.data)?;
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let attachment = entry
            .attachments
            .get_mut(name)
            .ok_or_else(|| MutationError::AttachmentNotFound(name.into()))?;
        attachment.data = content;
        Ok(project_attachment_items(&entry.attachments))
    }

    pub fn update_entry_expiry(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryExpiryUpdate,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.expires = update.expires;
        entry.expiry_time = update.expiry_time;
        Ok(project_entry(entry))
    }

    pub fn update_entry_field_protection(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        update: EntryFieldProtectionUpdate,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if let Some(value) = update.protect_title {
            entry.field_protection.protect_title = value;
        }
        if let Some(value) = update.protect_username {
            entry.field_protection.protect_username = value;
        }
        if let Some(value) = update.protect_password {
            entry.field_protection.protect_password = value;
        }
        if let Some(value) = update.protect_url {
            entry.field_protection.protect_url = value;
        }
        if let Some(value) = update.protect_notes {
            entry.field_protection.protect_notes = value;
        }
        Ok(project_entry(entry))
    }

    pub fn set_entry_totp(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        totp: TotpSpec,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.totp = Some(totp);
        Ok(project_entry(entry))
    }

    pub fn clear_entry_totp(
        &self,
        vault: &mut Vault,
        entry_id: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.totp = None;
        Ok(project_entry(entry))
    }

    pub fn set_entry_passkey(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        passkey: PasskeyRecord,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.passkey = Some(passkey);
        Ok(project_entry(entry))
    }

    pub fn clear_entry_passkey(
        &self,
        vault: &mut Vault,
        entry_id: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.passkey = None;
        Ok(project_entry(entry))
    }

    pub fn upsert_entry_custom_data(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        item: EntryCustomDataInput,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if item.key.is_empty() {
            return Err(MutationError::InvalidEntryValue(
                "custom data key cannot be empty".into(),
            ));
        }
        let key = item.key;
        entry.custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut entry.custom_data_blocks,
            &entry.custom_data,
            Some((&key, None)),
        );
        Ok(project_entry(entry))
    }

    pub fn upsert_entry_custom_data_detail(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        item: EntryCustomDataItemDetailInput,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if item.key.is_empty() {
            return Err(MutationError::InvalidEntryValue(
                "custom data key cannot be empty".into(),
            ));
        }
        let key = item.key;
        entry.custom_data.insert(key.clone(), item.value);
        canonicalize_custom_data_blocks(
            &mut entry.custom_data_blocks,
            &entry.custom_data,
            Some((&key, item.last_modified)),
        );
        Ok(project_entry(entry))
    }

    pub fn delete_entry_custom_data(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        key: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        if entry.custom_data.remove(key).is_none() {
            return Err(MutationError::CustomDataNotFound(key.into()));
        }
        canonicalize_custom_data_blocks(&mut entry.custom_data_blocks, &entry.custom_data, None);
        Ok(project_entry(entry))
    }

    pub fn snapshot_entry_to_history(
        &self,
        vault: &mut Vault,
        entry_id: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        entry.history.push(snapshot);
        Ok(project_entry(entry))
    }

    pub fn clear_entry_history(
        &self,
        vault: &mut Vault,
        entry_id: &str,
    ) -> Result<EntryView, MutationError> {
        let entry = find_entry_by_id_mut(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.history.clear();
        Ok(project_entry(entry))
    }

    pub fn soft_delete_entry_to_recycle_bin(
        &self,
        vault: &mut Vault,
        entry_id: &str,
    ) -> Result<EntryView, MutationError> {
        let recycle_bin_id = ensure_recycle_bin(vault);
        let (mut entry, parent_group_id) = take_entry_from_group(&mut vault.root, entry_id)
            .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
        entry.previous_parent = Some(parent_group_id);

        let deleted_at = current_unix_timestamp();
        vault.deleted_objects.retain(|item| item.id != entry.id);
        vault.deleted_objects.push(DeletedObject {
            id: entry.id,
            deleted_at,
        });

        let recycle_bin = find_group_by_id_mut(&mut vault.root, &recycle_bin_id)
            .ok_or_else(|| MutationError::GroupNotFound(recycle_bin_id.clone()))?;
        recycle_bin.entries.push(entry);
        let entry = recycle_bin.entries.last().expect("moved recycle bin entry");
        Ok(project_entry(entry))
    }

    pub fn restore_entry_from_recycle_bin(
        &self,
        vault: &mut Vault,
        entry_id: &str,
        target_group_id: Option<&str>,
    ) -> Result<EntryView, MutationError> {
        let recycle_bin_id = vault
            .recycle_bin_group
            .map(|id| id.to_string())
            .ok_or_else(|| MutationError::GroupNotFound("recycle-bin".into()))?;
        let mut entry = {
            let recycle_bin = find_group_by_id_mut(&mut vault.root, &recycle_bin_id)
                .ok_or_else(|| MutationError::GroupNotFound(recycle_bin_id.clone()))?;
            let index = recycle_bin
                .entries
                .iter()
                .position(|entry| entry.id.to_string() == entry_id)
                .ok_or_else(|| MutationError::EntryNotFound(entry_id.into()))?;
            recycle_bin.entries.remove(index)
        };

        let target_group_id = target_group_id
            .map(str::to_owned)
            .or_else(|| entry.previous_parent.map(|id| id.to_string()))
            .ok_or_else(|| MutationError::GroupNotFound("restore-target".into()))?;
        entry.previous_parent = None;

        let target_group = find_group_by_id_mut(&mut vault.root, &target_group_id)
            .ok_or_else(|| MutationError::GroupNotFound(target_group_id.clone()))?;
        target_group.entries.push(entry);
        let entry = target_group.entries.last().expect("restored entry");
        vault
            .deleted_objects
            .retain(|item| item.id.to_string() != entry_id);
        Ok(project_entry(entry))
    }

    pub fn load_database(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
    ) -> Result<LoadedDatabase, CoreError> {
        self.load_database_with_policy(
            bytes,
            composite_key,
            &ExternalKdfPolicy::Mobile,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    pub fn load_database_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<LoadedDatabase, CoreError> {
        let header = inspect_kdbx_header(bytes)?;
        let vault = load_kdbx_with_policy(bytes, composite_key, policy, confirmation)?;
        Ok(LoadedDatabase {
            summary: summarize_vault(&vault),
            inspection: build_inspection(header),
            vault,
        })
    }

    pub fn load_database_view(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
    ) -> Result<LoadedDatabaseView, CoreError> {
        self.load_database_view_with_policy(
            bytes,
            composite_key,
            &ExternalKdfPolicy::Mobile,
            ExternalKdfConfirmation::Unconfirmed,
        )
    }

    pub fn load_database_view_with_policy(
        &self,
        bytes: &[u8],
        composite_key: &CompositeKey,
        policy: &dyn KdfPolicyEvaluator,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<LoadedDatabaseView, CoreError> {
        let header = inspect_kdbx_header(bytes)?;
        let vault = load_kdbx_with_policy(bytes, composite_key, policy, confirmation)?;
        Ok(LoadedDatabaseView {
            database: project_vault(&vault),
            inspection: build_inspection(header),
        })
    }
}

fn summarize_vault(vault: &Vault) -> VaultSummary {
    let mut groups = 1_usize;
    let mut entries = 0_usize;
    let mut attachments = 0_usize;
    let mut custom_data_items = vault.meta_custom_data.len() + vault.public_custom_data.len();

    fn walk(
        group: &Group,
        groups: &mut usize,
        entries: &mut usize,
        attachments: &mut usize,
        custom_data_items: &mut usize,
    ) {
        *custom_data_items += group.custom_data.len();

        for entry in &group.entries {
            *entries += 1;
            *attachments += entry.attachments.len();
            *custom_data_items += entry.custom_data.len();
        }

        for child in &group.children {
            *groups += 1;
            walk(child, groups, entries, attachments, custom_data_items);
        }
    }

    walk(
        &vault.root,
        &mut groups,
        &mut entries,
        &mut attachments,
        &mut custom_data_items,
    );

    VaultSummary {
        name: vault.name.clone(),
        root_title: vault.root.title.clone(),
        groups,
        entries,
        attachments,
        deleted_objects: vault.deleted_objects.len(),
        custom_data_items,
    }
}

fn project_vault(vault: &Vault) -> VaultView {
    VaultView {
        summary: summarize_vault(vault),
        root: project_group(&vault.root),
        deleted_objects: vault.deleted_objects.len(),
        recycle_bin_enabled: vault.recycle_bin_enabled,
        recycle_bin_group_id: vault.recycle_bin_group.map(|id| id.to_string()),
        entry_templates_group_id: vault.entry_templates_group.map(|id| id.to_string()),
    }
}

fn project_vault_metadata(vault: &Vault) -> VaultMetadataView {
    VaultMetadataView {
        description: vault.description.clone(),
        default_username: vault.default_username.clone(),
        color: vault.color.clone(),
        history_max_items: vault.history_max_items,
        history_max_size: vault.history_max_size,
        memory_protection: vault.memory_protection,
    }
}

fn project_vault_selection_metadata(vault: &Vault) -> VaultSelectionMetadataView {
    VaultSelectionMetadataView {
        last_selected_group_id: vault.last_selected_group.map(|id| id.to_string()),
        last_top_visible_group_id: vault.last_top_visible_group.map(|id| id.to_string()),
    }
}

fn project_vault_lifecycle_metadata(vault: &Vault) -> VaultLifecycleMetadataView {
    VaultLifecycleMetadataView {
        settings_changed: vault.settings_changed,
        maintenance_history_days: vault.maintenance_history_days,
        master_key_changed: vault.master_key_changed,
        master_key_change_rec: vault.master_key_change_rec,
        master_key_change_force: vault.master_key_change_force,
        master_key_change_force_once: vault.master_key_change_force_once,
    }
}

fn project_vault_bin_template_metadata(vault: &Vault) -> VaultBinTemplateMetadataView {
    VaultBinTemplateMetadataView {
        recycle_bin_enabled: vault.recycle_bin_enabled,
        recycle_bin_group_id: vault.recycle_bin_group.map(|id| id.to_string()),
        recycle_bin_changed: vault.recycle_bin_changed,
        entry_templates_group_id: vault.entry_templates_group.map(|id| id.to_string()),
        entry_templates_group_changed: vault.entry_templates_group_changed,
    }
}

fn project_vault_identity_metadata(vault: &Vault) -> VaultIdentityMetadataView {
    VaultIdentityMetadataView {
        name: vault.name.clone(),
        generator: vault.generator.clone(),
        database_name_changed: vault.database_name_changed,
        description_changed: vault.description_changed,
        default_username_changed: vault.default_username_changed,
    }
}

fn project_vault_custom_data_semantics(vault: &Vault) -> VaultCustomDataSemanticView {
    VaultCustomDataSemanticView {
        last_modified: vault.meta_custom_data.get("_LAST_MODIFIED").cloned(),
        fdo_secrets_exposed_group_id: vault
            .meta_custom_data
            .get("FDO_SECRETS_EXPOSED_GROUP")
            .cloned(),
        keepassxc_browser_items: vault
            .meta_custom_data
            .iter()
            .filter(|(key, _)| key.starts_with("KPXC_BROWSER_"))
            .map(|(key, value)| CustomDataItemView {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    }
}

fn project_group_behavior_metadata(group: &Group) -> GroupBehaviorMetadataView {
    GroupBehaviorMetadataView {
        default_auto_type_sequence: group.default_auto_type_sequence.clone(),
        last_top_visible_entry_id: group.last_top_visible_entry.map(|id| id.to_string()),
        enable_auto_type: group.flags.enable_auto_type,
        enable_searching: group.flags.enable_searching,
    }
}

fn project_group_lineage_tag_metadata(group: &Group) -> GroupLineageTagMetadataView {
    GroupLineageTagMetadataView {
        tags: group.tags.iter().cloned().collect(),
        previous_parent_id: group.previous_parent.map(|id| id.to_string()),
    }
}

fn project_group_times(group: &Group) -> GroupTimesView {
    match group.times {
        Some(times) => GroupTimesView {
            created_at: Some(times.created_at),
            modified_at: Some(times.modified_at),
            last_accessed_at: times.last_accessed_at,
            usage_count: times.usage_count,
            location_changed_at: times.location_changed_at,
        },
        None => GroupTimesView {
            created_at: None,
            modified_at: None,
            last_accessed_at: None,
            usage_count: None,
            location_changed_at: None,
        },
    }
}

fn project_group_expiry(group: &Group) -> GroupExpiryView {
    match group.times {
        Some(times) => GroupExpiryView {
            expires: Some(times.expires),
            expiry_time: times.expiry_time,
        },
        None => GroupExpiryView {
            expires: None,
            expiry_time: None,
        },
    }
}

fn project_entry_presentation_metadata(entry: &Entry) -> EntryPresentationMetadataView {
    EntryPresentationMetadataView {
        icon_id: entry.icon_id,
        foreground_color: entry.foreground_color.clone(),
        background_color: entry.background_color.clone(),
        override_url: entry.override_url.clone(),
    }
}

fn project_entry_lineage_report_metadata(entry: &Entry) -> EntryLineageReportMetadataView {
    EntryLineageReportMetadataView {
        previous_parent_id: entry.previous_parent.map(|id| id.to_string()),
        exclude_from_reports: entry.exclude_from_reports,
    }
}

fn project_entry_totp(totp: &TotpSpec) -> EntryTotpView {
    EntryTotpView {
        secret_base32: totp.secret_base32.clone(),
        algorithm: totp.algorithm.clone(),
        digits: totp.digits,
        period_seconds: totp.period_seconds,
        issuer: totp.issuer.clone(),
        account_name: totp.account_name.clone(),
    }
}

fn project_entry_passkey(passkey: &PasskeyRecord) -> EntryPasskeyView {
    EntryPasskeyView {
        username: passkey.username.clone(),
        credential_id: passkey.credential_id.clone(),
        generated_user_id: passkey.generated_user_id.clone(),
        private_key_pem: passkey.private_key_pem.clone(),
        relying_party: passkey.relying_party.clone(),
        user_handle: passkey.user_handle.clone(),
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    }
}

fn project_entry_custom_fields(
    items: &std::collections::BTreeMap<String, CustomField>,
) -> Vec<EntryCustomFieldView> {
    items
        .iter()
        .map(|(key, value)| EntryCustomFieldView {
            key: key.clone(),
            value: value.value.clone(),
            protected: value.protected,
        })
        .collect()
}

fn project_entry_auto_type(entry: &Entry) -> EntryAutoTypeView {
    match &entry.auto_type {
        Some(auto_type) => EntryAutoTypeView {
            enabled: auto_type.enabled,
            obfuscation: auto_type.obfuscation,
            default_sequence: auto_type.default_sequence.clone(),
            associations: auto_type
                .associations
                .iter()
                .map(|association| EntryAutoTypeAssociationView {
                    window: association.window.clone(),
                    sequence: association.sequence.clone(),
                })
                .collect(),
        },
        None => EntryAutoTypeView {
            enabled: None,
            obfuscation: None,
            default_sequence: None,
            associations: Vec::new(),
        },
    }
}

fn project_entry_times(entry: &Entry) -> EntryTimesView {
    EntryTimesView {
        created_at: entry.created_at,
        modified_at: entry.modified_at,
        last_accessed_at: entry.last_accessed_at,
        usage_count: entry.usage_count,
        location_changed_at: entry.location_changed_at,
    }
}

fn project_custom_icon(icon: &CustomIcon) -> CustomIconView {
    CustomIconView {
        id: icon.id.to_string(),
        data: icon.data.clone(),
        name: icon.name.clone(),
        last_modified: icon.last_modified,
    }
}

fn project_custom_data_items(
    items: &std::collections::BTreeMap<String, String>,
) -> Vec<CustomDataItemView> {
    items
        .iter()
        .map(|(key, value)| CustomDataItemView {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn project_vault_custom_data_items(vault: &Vault) -> Vec<VaultCustomDataItemView> {
    let mut projected = std::collections::BTreeMap::new();

    for block in &vault.meta_custom_data_blocks {
        for item in &block.items {
            projected.insert(
                item.key.clone(),
                VaultCustomDataItemView {
                    key: item.key.clone(),
                    value: item.value.clone(),
                    last_modified: item.last_modified,
                },
            );
        }
    }

    for (key, value) in &vault.meta_custom_data {
        projected
            .entry(key.clone())
            .or_insert_with(|| VaultCustomDataItemView {
                key: key.clone(),
                value: value.clone(),
                last_modified: None,
            });
    }

    projected.into_values().collect()
}

fn project_group_custom_data_items(group: &Group) -> Vec<GroupCustomDataItemView> {
    let mut projected = std::collections::BTreeMap::new();

    for block in &group.custom_data_blocks {
        for item in &block.items {
            projected.insert(
                item.key.clone(),
                GroupCustomDataItemView {
                    key: item.key.clone(),
                    value: item.value.clone(),
                    last_modified: item.last_modified,
                },
            );
        }
    }

    for (key, value) in &group.custom_data {
        projected
            .entry(key.clone())
            .or_insert_with(|| GroupCustomDataItemView {
                key: key.clone(),
                value: value.clone(),
                last_modified: None,
            });
    }

    projected.into_values().collect()
}

fn project_entry_custom_data_items(entry: &Entry) -> Vec<EntryCustomDataItemView> {
    let mut projected = std::collections::BTreeMap::new();

    for block in &entry.custom_data_blocks {
        for item in &block.items {
            projected.insert(
                item.key.clone(),
                EntryCustomDataItemView {
                    key: item.key.clone(),
                    value: item.value.clone(),
                    last_modified: item.last_modified,
                },
            );
        }
    }

    for (key, value) in &entry.custom_data {
        projected
            .entry(key.clone())
            .or_insert_with(|| EntryCustomDataItemView {
                key: key.clone(),
                value: value.clone(),
                last_modified: None,
            });
    }

    projected.into_values().collect()
}

fn canonicalize_custom_data_blocks(
    blocks: &mut Vec<vaultkern_model::CustomDataBlock>,
    merged: &std::collections::BTreeMap<String, String>,
    updated_item: Option<(&str, Option<i64>)>,
) {
    let mut last_modified_by_key = std::collections::BTreeMap::new();
    for block in blocks.iter() {
        for item in &block.items {
            last_modified_by_key.insert(item.key.clone(), item.last_modified);
        }
    }
    if let Some((key, last_modified)) = updated_item {
        last_modified_by_key.insert(key.to_string(), last_modified);
    }

    if merged.is_empty() {
        blocks.clear();
        return;
    }

    let items = merged
        .iter()
        .map(|(key, value)| vaultkern_model::CustomDataItem {
            key: key.clone(),
            value: value.clone(),
            last_modified: last_modified_by_key.get(key).copied().flatten(),
        })
        .collect();
    *blocks = vec![vaultkern_model::CustomDataBlock { items, after: None }];
}

fn project_attachment_items(
    attachments: &std::collections::BTreeMap<String, ModelAttachment>,
) -> Vec<AttachmentView> {
    attachments
        .values()
        .map(|attachment| AttachmentView {
            name: attachment.name.clone(),
            size: attachment.data.len(),
            protect_in_memory: attachment.protect_in_memory,
        })
        .collect()
}

fn project_public_custom_data_items(
    items: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Vec<PublicCustomDataItemView> {
    items
        .iter()
        .map(|(key, value)| PublicCustomDataItemView {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn project_merge_report(report: &MergeReport) -> MergeSummaryView {
    MergeSummaryView {
        merged_entries: report.merged_entries,
        history_snapshots_added: report.history_snapshots_added,
    }
}

fn project_group(group: &Group) -> GroupView {
    GroupView {
        id: group.id.to_string(),
        title: group.title.clone(),
        icon_id: group.icon_id,
        custom_icon_id: group.custom_icon_id.map(|id| id.to_string()),
        entry_count: group.entries.len(),
        child_count: group.children.len(),
        entries: group.entries.iter().map(project_entry).collect(),
        children: group.children.iter().map(project_group).collect(),
    }
}

fn project_group_detail(group: &Group) -> GroupDetailView {
    GroupDetailView {
        id: group.id.to_string(),
        title: group.title.clone(),
        icon_id: group.icon_id,
        notes: group.notes.clone(),
        custom_icon_id: group.custom_icon_id.map(|id| id.to_string()),
        tags: group.tags.iter().cloned().collect(),
    }
}

fn project_entry(entry: &Entry) -> EntryView {
    EntryView {
        id: entry.id.to_string(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: entry.url.clone(),
        icon_id: entry.icon_id,
        custom_icon_id: entry.custom_icon_id.map(|id| id.to_string()),
        tags: entry.tags.iter().cloned().collect(),
        attachment_count: entry.attachments.len(),
        custom_field_count: entry.attributes.len(),
        history_count: entry.history.len(),
        has_totp: entry.totp.is_some(),
        has_passkey: entry.passkey.is_some(),
        expires: entry.expires,
        field_protection: entry.field_protection,
    }
}

fn project_entry_detail(entry: &Entry) -> EntryDetailView {
    EntryDetailView {
        id: entry.id.to_string(),
        title: entry.title.clone(),
        icon_id: entry.icon_id,
        username: entry.username.clone(),
        password: entry.password.clone(),
        url: entry.url.clone(),
        notes: entry.notes.clone(),
        modified_at: entry.modified_at,
        custom_icon_id: entry.custom_icon_id.map(|id| id.to_string()),
        tags: entry.tags.iter().cloned().collect(),
        field_protection: entry.field_protection,
    }
}

fn project_entry_history_detail(entry: &Entry) -> EntryHistoryDetailView {
    EntryHistoryDetailView {
        title: entry.title.clone(),
        icon_id: entry.icon_id,
        username: entry.username.clone(),
        password: entry.password.clone(),
        url: entry.url.clone(),
        notes: entry.notes.clone(),
        modified_at: entry.modified_at,
        custom_icon_id: entry.custom_icon_id.map(|id| id.to_string()),
        tags: entry.tags.iter().cloned().collect(),
    }
}

fn project_history_item(entry: &Entry) -> EntryHistoryItemView {
    EntryHistoryItemView {
        title: entry.title.clone(),
        username: entry.username.clone(),
        modified_at: entry.modified_at,
        attachment_count: entry.attachments.len(),
        custom_field_count: entry.attributes.len(),
    }
}

fn find_group_by_id<'a>(group: &'a Group, id: &str) -> Option<&'a Group> {
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

fn parse_uuid(value: &str) -> Result<Uuid, MutationError> {
    Uuid::parse_str(value).map_err(|_| MutationError::InvalidUuid(value.into()))
}

fn group_or_entry_uses_uuid(group: &Group, id: Uuid) -> bool {
    group.id == id
        || group.entries.iter().any(|entry| entry.id == id)
        || group
            .children
            .iter()
            .any(|child| group_or_entry_uses_uuid(child, id))
}

fn clear_custom_icon_references_from_group(group: &mut Group, icon_id: Uuid) {
    if group.custom_icon_id == Some(icon_id) {
        group.custom_icon_id = None;
    }
    for entry in &mut group.entries {
        clear_custom_icon_references_from_entry(entry, icon_id);
    }
    for child in &mut group.children {
        clear_custom_icon_references_from_group(child, icon_id);
    }
}

fn clear_custom_icon_references_from_entry(entry: &mut Entry, icon_id: Uuid) {
    if entry.custom_icon_id == Some(icon_id) {
        entry.custom_icon_id = None;
    }
    for history_entry in &mut entry.history {
        clear_custom_icon_references_from_entry(history_entry, icon_id);
    }
}

fn find_entry_by_id<'a>(group: &'a Group, id: &str) -> Option<&'a Entry> {
    if let Some(found) = group
        .entries
        .iter()
        .find(|entry| entry.id.to_string() == id)
    {
        return Some(found);
    }
    for child in &group.children {
        if let Some(found) = find_entry_by_id(child, id) {
            return Some(found);
        }
    }
    None
}

fn shared_attachment_content(
    group: &Group,
    bytes: &[u8],
) -> Result<AttachmentContent, MutationError> {
    let id = AttachmentContentId::from_bytes(bytes);
    Ok(find_shared_attachment_content(group, id, bytes)?
        .unwrap_or_else(|| AttachmentContent::from_bytes(bytes.to_vec())))
}

fn find_shared_attachment_content(
    group: &Group,
    id: AttachmentContentId,
    bytes: &[u8],
) -> Result<Option<AttachmentContent>, MutationError> {
    for entry in &group.entries {
        for attachment in entry.attachments.values() {
            if attachment.data.id() == id {
                if attachment.data.as_bytes() != bytes {
                    return Err(MutationError::AttachmentContentHashCollision);
                }
                return Ok(Some(attachment.data.clone()));
            }
        }
        for history in &entry.history {
            if let Some(content) = find_shared_attachment_content_in_entry(history, id, bytes)? {
                return Ok(Some(content));
            }
        }
    }
    for child in &group.children {
        if let Some(content) = find_shared_attachment_content(child, id, bytes)? {
            return Ok(Some(content));
        }
    }
    Ok(None)
}

fn find_shared_attachment_content_in_entry(
    entry: &Entry,
    id: AttachmentContentId,
    bytes: &[u8],
) -> Result<Option<AttachmentContent>, MutationError> {
    for attachment in entry.attachments.values() {
        if attachment.data.id() == id {
            if attachment.data.as_bytes() != bytes {
                return Err(MutationError::AttachmentContentHashCollision);
            }
            return Ok(Some(attachment.data.clone()));
        }
    }
    for history in &entry.history {
        if let Some(content) = find_shared_attachment_content_in_entry(history, id, bytes)? {
            return Ok(Some(content));
        }
    }
    Ok(None)
}

fn find_group_by_id_mut<'a>(group: &'a mut Group, id: &str) -> Option<&'a mut Group> {
    if group.id.to_string() == id {
        return Some(group);
    }
    for child in &mut group.children {
        if let Some(found) = find_group_by_id_mut(child, id) {
            return Some(found);
        }
    }
    None
}

fn find_entry_by_id_mut<'a>(group: &'a mut Group, id: &str) -> Option<&'a mut Entry> {
    if let Some(index) = group
        .entries
        .iter()
        .position(|entry| entry.id.to_string() == id)
    {
        return group.entries.get_mut(index);
    }
    for child in &mut group.children {
        if let Some(found) = find_entry_by_id_mut(child, id) {
            return Some(found);
        }
    }
    None
}

fn delete_entry_from_group(group: &mut Group, entry_id: &str) -> bool {
    if let Some(index) = group
        .entries
        .iter()
        .position(|entry| entry.id.to_string() == entry_id)
    {
        group.entries.remove(index);
        return true;
    }
    for child in &mut group.children {
        if delete_entry_from_group(child, entry_id) {
            return true;
        }
    }
    false
}

fn delete_group_from_group(group: &mut Group, group_id: &str) -> bool {
    if let Some(index) = group
        .children
        .iter()
        .position(|child| child.id.to_string() == group_id)
    {
        group.children.remove(index);
        return true;
    }
    for child in &mut group.children {
        if delete_group_from_group(child, group_id) {
            return true;
        }
    }
    false
}

fn take_group_from_group(group: &mut Group, group_id: &str) -> Option<Group> {
    if let Some(index) = group
        .children
        .iter()
        .position(|child| child.id.to_string() == group_id)
    {
        return Some(group.children.remove(index));
    }
    for child in &mut group.children {
        if let Some(found) = take_group_from_group(child, group_id) {
            return Some(found);
        }
    }
    None
}

fn take_entry_from_group(group: &mut Group, entry_id: &str) -> Option<(Entry, uuid::Uuid)> {
    if let Some(index) = group
        .entries
        .iter()
        .position(|entry| entry.id.to_string() == entry_id)
    {
        return Some((group.entries.remove(index), group.id));
    }
    for child in &mut group.children {
        if let Some(found) = take_entry_from_group(child, entry_id) {
            return Some(found);
        }
    }
    None
}

fn group_contains_id(group: &Group, id: &str) -> bool {
    for child in &group.children {
        if child.id.to_string() == id || group_contains_id(child, id) {
            return true;
        }
    }
    false
}

fn ensure_recycle_bin(vault: &mut Vault) -> String {
    if let Some(id) = vault.recycle_bin_group {
        let id_str = id.to_string();
        if find_group_by_id(&vault.root, &id_str).is_some() {
            vault.recycle_bin_enabled = Some(true);
            return id_str;
        }
    }

    let recycle_bin = Group::new("Recycle Bin");
    let recycle_bin_id = recycle_bin.id;
    vault.root.children.push(recycle_bin);
    vault.recycle_bin_enabled = Some(true);
    vault.recycle_bin_group = Some(recycle_bin_id);
    if vault.recycle_bin_changed.is_none() {
        vault.recycle_bin_changed = Some(current_unix_timestamp());
    }
    recycle_bin_id.to_string()
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn search_entries_view(vault: &Vault, term: &str) -> Vec<EntryMatchView> {
    let needle = term.to_ascii_lowercase();
    let mut matches = Vec::new();
    let mut path = vec![vault.root.title.clone()];
    collect_entry_matches(&vault.root, &needle, &mut path, &mut matches);
    matches
}

fn collect_entry_matches(
    group: &Group,
    needle: &str,
    path: &mut Vec<String>,
    matches: &mut Vec<EntryMatchView>,
) {
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
            matches.push(EntryMatchView {
                entry: project_entry(entry),
                group_id: group.id.to_string(),
                group_path: path.clone(),
            });
        }
    }

    for child in &group.children {
        path.push(child.title.clone());
        collect_entry_matches(child, needle, path, matches);
        path.pop();
    }
}

fn build_inspection(header: KdbxHeaderSummary) -> DatabaseInspection {
    let mut warnings = Vec::new();

    match header.version {
        KdbxVersion::V2_0 | KdbxVersion::V3_0 | KdbxVersion::V3_1 => {
            warnings.push(LoadWarning::LegacyFormat(header.version));
            warnings.push(LoadWarning::SaveWillUpgradeToV4_1);
        }
        KdbxVersion::V4_0 => warnings.push(LoadWarning::SaveWillUpgradeToV4_1),
        KdbxVersion::V4_1 => {}
    }

    DatabaseInspection {
        header,
        save_target_version: KdbxVersion::V4_1,
        warnings,
    }
}

#[cfg(test)]
mod internal_tests {
    use super::{
        CompositeKey, CustomIcon, DeletedObject, EntryAttachmentInput, EntryCreate,
        EntryCustomFieldInput, EntryLineageReportMetadataUpdate, ExternalKdfConfirmation,
        ExternalKdfDecision, ExternalKdfPolicy, Group, KdbxCipher, KdbxError, KdbxHeader,
        KdbxVersion, KeepassCore, MutationError, SaveProfile, VariantDictionary, VariantValue,
    };
    use uuid::Uuid;
    use vaultkern_crypto::sha256_bytes;
    use vaultkern_model::{Entry, Vault};

    #[test]
    fn core_load_facades_require_an_external_kdf_policy_decision() {
        let core = KeepassCore::new();
        let key = CompositeKey::default();
        let bytes = core
            .save_kdbx(&Vault::empty("policy"), &key, SaveProfile::recommended())
            .expect("save test database");

        assert!(matches!(
            core.load_kdbx_with_policy(
                &bytes,
                &key,
                &ExternalKdfPolicy::Extension,
                ExternalKdfConfirmation::Confirmed,
            ),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Forbid,
                ..
            })
        ));

        for error in [
            core.load_database_with_policy(
                &bytes,
                &key,
                &ExternalKdfPolicy::Extension,
                ExternalKdfConfirmation::Confirmed,
            )
            .map(|_| ()),
            core.load_database_view_with_policy(
                &bytes,
                &key,
                &ExternalKdfPolicy::Extension,
                ExternalKdfConfirmation::Confirmed,
            )
            .map(|_| ()),
        ] {
            assert!(matches!(
                error,
                Err(super::CoreError::Kdbx(KdbxError::ExternalKdfPolicy {
                    decision: ExternalKdfDecision::Forbid,
                    ..
                }))
            ));
        }
    }

    #[test]
    fn core_compatibility_load_uses_the_conservative_mobile_policy() {
        let mut parameters = VariantDictionary::default();
        parameters.insert(
            "$UUID",
            VariantValue::Bytes(
                Uuid::from_bytes([
                    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00,
                    0x69, 0x2E, 0xB7,
                ])
                .into_bytes()
                .to_vec(),
            ),
        );
        parameters.insert("R", VariantValue::UInt64(600_000_001));
        parameters.insert("S", VariantValue::Bytes(vec![0; 32]));
        let mut header = KdbxHeader::new(KdbxVersion::V4_1, KdbxCipher::Aes256);
        header.encryption_iv = vec![0; 16];
        header.kdf_parameters = parameters;
        let header_bytes = header.encode().expect("encode header");
        let mut bytes = header_bytes.clone();
        bytes.extend(sha256_bytes(&header_bytes));
        bytes.extend([0; 32]);

        let core = KeepassCore::new();
        let key = CompositeKey::default();
        assert!(matches!(
            core.load_kdbx(&bytes, &key),
            Err(KdbxError::ExternalKdfPolicy {
                decision: ExternalKdfDecision::Refuse(600_000_000),
                ..
            })
        ));
        for error in [
            core.load_database(&bytes, &key).map(|_| ()),
            core.load_database_view(&bytes, &key).map(|_| ()),
        ] {
            assert!(matches!(
                error,
                Err(super::CoreError::Kdbx(KdbxError::ExternalKdfPolicy {
                    decision: ExternalKdfDecision::Refuse(600_000_000),
                    ..
                }))
            ));
        }
    }

    #[test]
    fn entry_lineage_report_metadata_update_clears_quality_check_raw_state() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryMeta");
        let mut entry = Entry::new("Entry");
        entry.raw_state.quality_check_raw = Some("True".into());
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let metadata = core
            .update_entry_lineage_report_metadata(
                &mut vault,
                &entry_id,
                EntryLineageReportMetadataUpdate {
                    previous_parent_id: None,
                    exclude_from_reports: Some(false),
                },
            )
            .expect("update entry lineage/report metadata");

        assert!(!metadata.exclude_from_reports);
        assert!(vault.root.entries[0].raw_state.quality_check_raw.is_none());
    }

    #[test]
    fn entry_lineage_report_metadata_parent_update_clears_quality_check_raw_state() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryMeta");
        let group = Group::new("Original");
        let parent_group_id = group.id.to_string();
        let mut entry = Entry::new("Entry");
        entry.raw_state.quality_check_raw = Some("True".into());
        let entry_id = entry.id.to_string();
        vault.root.children.push(group);
        vault.root.entries.push(entry);

        let metadata = core
            .update_entry_lineage_report_metadata(
                &mut vault,
                &entry_id,
                EntryLineageReportMetadataUpdate {
                    previous_parent_id: Some(Some(parent_group_id)),
                    exclude_from_reports: Some(false),
                },
            )
            .expect("update entry lineage/report metadata");

        assert!(!metadata.exclude_from_reports);
        assert!(vault.root.entries[0].raw_state.quality_check_raw.is_none());
    }

    #[test]
    fn add_entry_with_id_rejects_invalid_nil_and_noncanonical_uuids_before_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Stable IDs");
        let parent_group_id = vault.root.id.to_string();

        for invalid in [
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "12345678-1234-4ABC-8DEF-1234567890AB",
            "1234567812344abc8def1234567890ab",
        ] {
            let before = vault.clone();
            assert_eq!(
                core.add_entry_with_id(
                    &mut vault,
                    &parent_group_id,
                    invalid,
                    stable_entry_create(),
                ),
                Err(MutationError::InvalidUuid(invalid.into()))
            );
            assert_eq!(vault, before);
        }
    }

    #[test]
    fn add_entry_with_id_rejects_group_entry_and_deleted_marker_collisions_before_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Stable IDs");
        let parent_group_id = vault.root.id.to_string();

        let live_group = Group::new("Live group");
        let live_group_id = live_group.id;
        vault.root.children.push(live_group);

        let mut recycle_group = Group::new("Recycle Bin");
        let recycle_group_id = recycle_group.id;
        let recycled_entry = Entry::new("Recycled entry");
        let recycled_entry_id = recycled_entry.id;
        recycle_group.entries.push(recycled_entry);
        vault.recycle_bin_enabled = Some(true);
        vault.recycle_bin_group = Some(recycle_group_id);
        vault.root.children.push(recycle_group);

        let live_entry = Entry::new("Live entry");
        let live_entry_id = live_entry.id;
        vault.root.entries.push(live_entry);

        let deleted_id = Uuid::new_v4();
        vault.deleted_objects.push(DeletedObject {
            id: deleted_id,
            deleted_at: 1,
        });

        for collision in [
            live_group_id,
            recycle_group_id,
            live_entry_id,
            recycled_entry_id,
            deleted_id,
        ] {
            let before = vault.clone();
            let collision = collision.to_string();
            assert_eq!(
                core.add_entry_with_id(
                    &mut vault,
                    &parent_group_id,
                    &collision,
                    stable_entry_create(),
                ),
                Err(MutationError::UuidCollision(collision))
            );
            assert_eq!(vault, before);
        }
    }

    #[test]
    fn add_entry_with_id_uses_the_planned_uuid_and_keeps_random_add_entry_api() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Stable IDs");
        let parent_group_id = vault.root.id.to_string();
        let planned_id = "12345678-1234-4abc-8def-1234567890ab";
        let planned_uuid = Uuid::parse_str(planned_id).unwrap();
        let mut history_owner = Entry::new("History owner");
        let mut history_snapshot = Entry::new("History snapshot");
        history_snapshot.id = planned_uuid;
        history_owner.history.push(history_snapshot);
        vault.root.entries.push(history_owner);
        vault.custom_icons.push(CustomIcon {
            id: planned_uuid,
            data: vec![1, 2, 3],
            name: Some("Separate namespace".into()),
            last_modified: None,
        });

        let planned = core
            .add_entry_with_id(
                &mut vault,
                &parent_group_id,
                planned_id,
                stable_entry_create(),
            )
            .expect("create entry with planned UUID");
        let random = core
            .add_entry(&mut vault, &parent_group_id, stable_entry_create())
            .expect("create entry with existing random API");

        assert_eq!(planned.id, planned_id);
        assert_ne!(random.id, planned_id);
        assert_ne!(random.id, Uuid::nil().to_string());
    }

    #[test]
    fn attachment_facade_reuses_content_across_entries_and_history_clones() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("shared attachments");
        let first = Entry::new("first");
        let first_id = first.id.to_string();
        let second = Entry::new("second");
        let second_id = second.id.to_string();
        vault.root.entries.extend([first, second]);

        for (entry_id, name) in [(&first_id, "first.bin"), (&second_id, "second.bin")] {
            core.add_entry_attachment(
                &mut vault,
                entry_id,
                EntryAttachmentInput {
                    name: name.into(),
                    data: vec![0x4d; 1024 * 1024],
                    protect_in_memory: false,
                },
            )
            .expect("add shared attachment");
        }
        let history = vault.root.entries[0].clone();
        vault.root.entries[0].history.push(history);

        let first = &vault.root.entries[0].attachments["first.bin"].data;
        let second = &vault.root.entries[1].attachments["second.bin"].data;
        let history = &vault.root.entries[0].history[0].attachments["first.bin"].data;
        assert!(first.ptr_eq(second));
        assert!(first.ptr_eq(history));
    }

    #[test]
    fn custom_field_facade_rejects_persistence_reserved_keys_without_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("reserved custom fields");
        let entry = Entry::new("entry");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        for key in [
            "Title",
            "UserName",
            "Password",
            "URL",
            "Notes",
            "otp",
            "TimeOtp-Secret-Base32",
            "TimeOtp-Algorithm",
            "TimeOtp-Length",
            "TimeOtp-Period",
            "KPEX_PASSKEY_PRIVATE_KEY_PEM",
            "KPEX_PASSKEY_FUTURE_FIELD",
        ] {
            let before = vault.clone();
            let error = core
                .upsert_entry_custom_field(
                    &mut vault,
                    &entry_id,
                    EntryCustomFieldInput {
                        key: key.into(),
                        value: "must not be inserted".into(),
                        protected: true,
                    },
                )
                .expect_err("reserved key should be rejected");

            assert_eq!(
                error.to_string(),
                format!("reserved custom field key: {key}")
            );
            assert_eq!(vault, before);
        }
    }

    fn stable_entry_create() -> EntryCreate {
        EntryCreate {
            title: "Example".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com/login".into(),
            notes: "planned UUID".into(),
        }
    }
}

#[cfg(all(test, feature = "external-fixtures"))]
mod tests {
    use super::{
        Attachment, AttachmentContentUpdate, AttachmentMetadataUpdate, AttachmentView,
        AutoTypeAssociation, AutoTypeConfig, CompositeKey, CustomDataItemInput, CustomDataItemView,
        CustomIcon, CustomIconInput, CustomIconView, DeletedObjectView, Entry,
        EntryAttachmentInput, EntryAutoTypeAssociationInput, EntryAutoTypeAssociationView,
        EntryAutoTypeUpdate, EntryCreate, EntryCustomDataInput, EntryCustomFieldInput,
        EntryExpiryUpdate, EntryFieldProtection, EntryFieldProtectionUpdate, EntryHistoryItemView,
        EntryPresentationMetadataUpdate, EntryTimesUpdate, EntryUpdate, Group,
        GroupBehaviorMetadataUpdate, GroupExpiryUpdate, GroupFlags, GroupMetadataUpdate,
        GroupTimes, GroupTimesUpdate, KeepassCore, LoadWarning, MemoryProtection, MergeSummaryView,
        PasskeyRecord, PublicCustomDataItemInput, PublicCustomDataItemView, StableSaveCipher,
        StableSaveCompression, StableSaveKdf, StableSaveProfile, TotpSpec, Vault,
        VaultBinTemplateMetadataUpdate, VaultIdentityMetadataUpdate, VaultLifecycleMetadataUpdate,
        VaultMetadataUpdate, VaultSelectionMetadataUpdate,
    };
    use vaultkern_model::{CustomField, TotpAlgorithm, canonical_entry_bytes_v1};

    const FIXTURE_FORMAT200: &[u8] = include_bytes!("../../../fixtures/kdbx/Format200.kdbx");
    const FIXTURE_FORMAT300: &[u8] = include_bytes!("../../../fixtures/kdbx/Format300.kdbx");
    const FIXTURE_FORMAT400: &[u8] = include_bytes!("../../../fixtures/kdbx/Format400.kdbx");
    const FIXTURE_PROTECTED_STRINGS: &[u8] =
        include_bytes!("../../../fixtures/kdbx/ProtectedStrings.kdbx");
    const FIXTURE_NON_ASCII: &[u8] = include_bytes!("../../../fixtures/kdbx/NonAscii.kdbx");
    const FIXTURE_COMPRESSED: &[u8] = include_bytes!("../../../fixtures/kdbx/Compressed.kdbx");
    const FIXTURE_FILE_KEY_BINARY_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyBinary.kdbx");
    const FIXTURE_FILE_KEY_BINARY: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyBinary.key");
    const FIXTURE_FILE_KEY_HEX_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.kdbx");
    const FIXTURE_FILE_KEY_HEX: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyHex.key");
    const FIXTURE_FILE_KEY_HASHED_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyHashed.kdbx");
    const FIXTURE_FILE_KEY_HASHED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyHashed.key");
    const FIXTURE_FILE_KEY_XML_DB: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.kdbx");
    const FIXTURE_FILE_KEY_XML: &[u8] = include_bytes!("../../../fixtures/kdbx/FileKeyXml.key");
    const FIXTURE_FILE_KEY_XML_V2_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.kdbx");
    const FIXTURE_FILE_KEY_XML_V2: &[u8] =
        include_bytes!("../../../fixtures/kdbx/FileKeyXmlV2.keyx");
    const FIXTURE_KEY_FILE_PROTECTED_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtected.kdbx");
    const FIXTURE_KEY_FILE_PROTECTED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtected.key");
    const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.kdbx");
    const FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD: &[u8] =
        include_bytes!("../../../fixtures/kdbx/KeyFileProtectedNoPassword.key");
    const FIXTURE_NEW_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase.kdbx");
    const FIXTURE_NEW_DATABASE2: &[u8] = include_bytes!("../../../fixtures/kdbx/NewDatabase2.kdbx");
    const FIXTURE_NEW_DATABASE_BROWSER: &[u8] =
        include_bytes!("../../../fixtures/kdbx/NewDatabaseBrowser.kdbx");
    const FIXTURE_NEW_DATABASE_MULTI: &[u8] =
        include_bytes!("../../../fixtures/kdbx/NewDatabaseMulti.kdbx");
    const FIXTURE_MERGE_DATABASE: &[u8] =
        include_bytes!("../../../fixtures/kdbx/MergeDatabase.kdbx");
    const FIXTURE_SYNC_DATABASE: &[u8] = include_bytes!("../../../fixtures/kdbx/SyncDatabase.kdbx");
    const FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD: &[u8] =
        include_bytes!("../../../fixtures/kdbx/SyncDatabaseDifferentPassword.kdbx");
    const FIXTURE_RECYCLE_BIN_DISABLED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinDisabled.kdbx");
    const FIXTURE_RECYCLE_BIN_NOT_YET_CREATED: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinNotYetCreated.kdbx");
    const FIXTURE_RECYCLE_BIN_EMPTY: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinEmpty.kdbx");
    const FIXTURE_RECYCLE_BIN_WITH_DATA: &[u8] =
        include_bytes!("../../../fixtures/kdbx/RecycleBinWithData.kdbx");
    const FIXTURE_USER_TEST: &[u8] = include_bytes!("../../../fixtures/kdbx/test.kdbx");
    const FIXTURE_USER_TEST4: &[u8] = include_bytes!("../../../fixtures/kdbx/test4.kdbx");

    #[test]
    fn facade_creates_vault_and_reports_capabilities() {
        let core = KeepassCore::new();
        let vault = core.empty_vault("Demo");
        let capabilities = core.capabilities();

        assert_eq!(vault.name, "Demo");
        assert!(capabilities.contains(&"composite-key"));
        assert!(capabilities.contains(&"key-file"));
        assert!(capabilities.contains(&"totp"));
        assert!(capabilities.contains(&"variant-dictionary"));
        assert!(capabilities.contains(&"kdbx-byte-api"));
        assert!(capabilities.contains(&"stable-binding-facade"));
        assert!(capabilities.contains(&"stable-query-facade"));
        assert!(capabilities.contains(&"stable-mutation-facade"));
        assert!(capabilities.contains(&"stable-save-profile-facade"));
        assert!(capabilities.contains(&"stable-rich-entry-mutation-facade"));
        assert!(capabilities.contains(&"stable-recycle-bin-mutation-facade"));
        assert!(capabilities.contains(&"stable-group-metadata-mutation-facade"));
        assert!(capabilities.contains(&"stable-advanced-entry-semantic-mutation-facade"));
        assert!(capabilities.contains(&"stable-entry-history-mutation-facade"));
        assert!(capabilities.contains(&"stable-vault-metadata-mutation-facade"));
        assert!(capabilities.contains(&"stable-group-behavior-metadata-mutation-facade"));
        assert!(capabilities.contains(&"stable-entry-field-protection-mutation-facade"));
        assert!(capabilities.contains(&"stable-custom-icon-mutation-facade"));
        assert!(capabilities.contains(&"stable-vault-group-custom-data-facade"));
        assert!(capabilities.contains(&"stable-merge-facade"));
        assert!(capabilities.contains(&"stable-node-move-facade"));
        assert!(capabilities.contains(&"stable-attachment-metadata-facade"));
        assert!(capabilities.contains(&"stable-attachment-content-replace-facade"));
        assert!(capabilities.contains(&"stable-attachment-content-projection-facade"));
        assert!(capabilities.contains(&"stable-public-custom-data-facade"));
        assert!(capabilities.contains(&"stable-entry-presentation-metadata-facade"));
        assert!(capabilities.contains(&"stable-entry-lineage-report-metadata-facade"));
        assert!(capabilities.contains(&"stable-entry-auto-type-facade"));
        assert!(capabilities.contains(&"stable-entry-times-facade"));
        assert!(capabilities.contains(&"stable-group-times-facade"));
        assert!(capabilities.contains(&"stable-group-expiry-facade"));
        assert!(capabilities.contains(&"stable-vault-selection-metadata-facade"));
        assert!(capabilities.contains(&"stable-vault-lifecycle-metadata-facade"));
        assert!(capabilities.contains(&"stable-vault-bin-template-metadata-facade"));
        assert!(capabilities.contains(&"stable-vault-identity-metadata-facade"));
        assert!(capabilities.contains(&"stable-group-lineage-tag-metadata-facade"));
        assert!(capabilities.contains(&"stable-entry-semantic-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-detail-projection-facade"));
        assert!(capabilities.contains(&"stable-group-detail-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-history-detail-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-history-attachment-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-history-semantic-projection-facade"));
        assert!(
            capabilities.contains(&"stable-entry-history-presentation-metadata-projection-facade")
        );
        assert!(capabilities.contains(&"stable-entry-history-lineage-report-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-custom-icon-projection-facade"));
        assert!(capabilities.contains(&"stable-group-custom-icon-projection-facade"));
        assert!(capabilities.contains(&"stable-icon-detail-projection-facade"));
        assert!(capabilities.contains(&"stable-entry-history-icon-detail-projection-facade"));
        assert!(capabilities.contains(&"stable-group-behavior-detail-projection-facade"));
    }

    #[test]
    fn load_database_returns_summary_and_upgrade_warning_for_kdbx3_fixture() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_database(FIXTURE_FORMAT300, &key)
            .expect("load stable facade");

        assert_eq!(loaded.summary.name, "Test Database Format 0x00030000");
        assert_eq!(loaded.summary.root_title, "Format300");
        assert_eq!(loaded.summary.entries, 1);
        assert_eq!(loaded.inspection.header.version, super::KdbxVersion::V3_0);
        assert!(
            loaded
                .inspection
                .warnings
                .contains(&LoadWarning::LegacyFormat(super::KdbxVersion::V3_0))
        );
        assert!(
            loaded
                .inspection
                .warnings
                .contains(&LoadWarning::SaveWillUpgradeToV4_1)
        );
    }

    #[test]
    fn inspect_database_reports_save_target_for_kdbx4_fixture() {
        let core = KeepassCore::new();

        let inspection = core
            .inspect_database(FIXTURE_FORMAT400)
            .expect("inspect stable facade");

        assert_eq!(inspection.header.version, super::KdbxVersion::V4_0);
        assert_eq!(inspection.save_target_version, super::KdbxVersion::V4_1);
        assert!(
            inspection
                .warnings
                .contains(&LoadWarning::SaveWillUpgradeToV4_1)
        );
    }

    #[test]
    fn facade_projects_vault_into_binding_friendly_tree() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Facade");
        vault.recycle_bin_enabled = Some(true);

        let mut child = Group::new("Child");
        let child_id = child.id.to_string();

        let mut entry = Entry::new("Example");
        let entry_id = entry.id.to_string();
        entry.username = "alice".into();
        entry.url = "https://example.com".into();
        entry.tags.insert("prod".into());
        entry.attachments.insert(
            "a.txt".into(),
            Attachment {
                name: "a.txt".into(),
                data: b"x".to_vec(),
                protect_in_memory: false,
            },
        );
        entry.attributes.insert(
            "custom".into(),
            CustomField {
                value: "value".into(),
                protected: false,
            },
        );
        entry.totp = Some(
            TotpSpec::parse_otpauth(
                "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test",
            )
            .expect("totp"),
        );
        child.entries.push(entry);
        vault.root.children.push(child);

        let view = core.project_vault(&vault);

        assert_eq!(view.summary.name, "Facade");
        assert_eq!(view.root.children.len(), 1);
        assert_eq!(view.root.children[0].id, child_id);
        assert_eq!(view.root.children[0].title, "Child");
        assert_eq!(view.root.children[0].entries.len(), 1);
        assert_eq!(view.root.children[0].entries[0].id, entry_id);
        assert_eq!(view.root.children[0].entries[0].title, "Example");
        assert_eq!(view.root.children[0].entries[0].username, "alice");
        assert_eq!(
            view.root.children[0].entries[0].tags,
            vec!["prod".to_string()]
        );
        assert_eq!(view.root.children[0].entries[0].attachment_count, 1);
        assert_eq!(view.root.children[0].entries[0].custom_field_count, 1);
        assert!(view.root.children[0].entries[0].has_totp);
        assert!(!view.root.children[0].entries[0].has_passkey);
        assert_eq!(view.recycle_bin_enabled, Some(true));
    }

    #[test]
    fn load_database_view_returns_inspection_and_root_tree() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let view = core
            .load_database_view(FIXTURE_FORMAT300, &key)
            .expect("load database view");

        assert_eq!(view.inspection.header.version, super::KdbxVersion::V3_0);
        assert!(
            view.inspection
                .warnings
                .contains(&LoadWarning::LegacyFormat(super::KdbxVersion::V3_0))
        );
        assert_eq!(
            view.database.summary.name,
            "Test Database Format 0x00030000"
        );
        assert_eq!(view.database.root.title, "Format300");
        assert_eq!(view.database.root.children.len(), 6);
        assert_eq!(view.database.root.entries.len(), 1);
        assert_eq!(view.database.root.entries[0].title, "Sample Entry");
        assert_eq!(view.database.root.entries[0].username, "User Name");
        assert_eq!(
            view.database.root.entries[0].url,
            "http://www.somesite.com/"
        );
    }

    #[test]
    fn facade_finds_group_and_entry_views_by_uuid() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Queries");
        let mut child = Group::new("Child");
        let child_id = child.id.to_string();

        let mut entry = Entry::new("Example");
        let entry_id = entry.id.to_string();
        entry.username = "alice".into();
        child.entries.push(entry);
        vault.root.children.push(child);

        let group = core
            .find_group_view_by_id(&vault, &child_id)
            .expect("group view by id");
        let entry = core
            .find_entry_view_by_id(&vault, &entry_id)
            .expect("entry view by id");

        assert_eq!(group.id, child_id);
        assert_eq!(group.title, "Child");
        assert_eq!(entry.id, entry_id);
        assert_eq!(entry.title, "Example");
        assert_eq!(entry.username, "alice");
    }

    #[test]
    fn facade_projects_group_detail() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Details");
        let group_id = group.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(2);
        group.icon_id = Some(24);
        group.notes = "group notes".into();
        group.custom_icon_id = Some(custom_icon_id);
        group.tags.insert("alpha".into());
        group.tags.insert("team".into());
        vault.root.children.push(group);

        let detail = core
            .project_group_detail(&vault, &group_id)
            .expect("project group detail");

        assert_eq!(detail.id, group_id);
        assert_eq!(detail.title, "Details");
        assert_eq!(detail.notes, "group notes");
        assert_eq!(detail.icon_id, Some(24));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["alpha".to_string(), "team".to_string()]);
    }

    #[test]
    fn group_detail_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Details");
        let group_id = group.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(2);
        group.icon_id = Some(24);
        group.notes = "group notes".into();
        group.custom_icon_id = Some(custom_icon_id);
        group.tags.insert("alpha".into());
        group.tags.insert("team".into());
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("group-detail");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group detail");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload group detail");
        let detail = core
            .project_group_detail(&loaded, &group_id)
            .expect("project group detail");

        assert_eq!(detail.id, group_id);
        assert_eq!(detail.title, "Details");
        assert_eq!(detail.notes, "group notes");
        assert_eq!(detail.icon_id, Some(24));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["alpha".to_string(), "team".to_string()]);
    }

    #[test]
    fn facade_projects_group_behavior_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Behavior");
        let top_entry = Entry::new("Top");
        let top_entry_id = top_entry.id.to_string();
        group.entries.push(top_entry);
        let group_id = group.id.to_string();
        group.default_auto_type_sequence = Some("{USERNAME}{TAB}{PASSWORD}".into());
        group.last_top_visible_entry =
            Some(uuid::Uuid::parse_str(&top_entry_id).expect("top entry id should be valid uuid"));
        group.flags.enable_auto_type = Some(false);
        group.flags.enable_searching = Some(true);
        vault.root.children.push(group);

        let behavior = core
            .project_group_behavior_metadata(&vault, &group_id)
            .expect("project group behavior");

        assert_eq!(
            behavior.default_auto_type_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}")
        );
        assert_eq!(
            behavior.last_top_visible_entry_id.as_deref(),
            Some(top_entry_id.as_str())
        );
        assert_eq!(behavior.enable_auto_type, Some(false));
        assert_eq!(behavior.enable_searching, Some(true));
    }

    #[test]
    fn group_behavior_detail_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Behavior");
        let top_entry = Entry::new("Top");
        let top_entry_id = top_entry.id.to_string();
        group.entries.push(top_entry);
        let group_id = group.id.to_string();
        group.default_auto_type_sequence = Some("{USERNAME}{TAB}{PASSWORD}".into());
        group.last_top_visible_entry =
            Some(uuid::Uuid::parse_str(&top_entry_id).expect("top entry id should be valid uuid"));
        group.flags.enable_auto_type = Some(false);
        group.flags.enable_searching = Some(true);
        vault.root.children.push(group);

        let mut key = CompositeKey::default();
        key.add_password("group-behavior-detail");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group behavior detail");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload group behavior detail");

        let behavior = core
            .project_group_behavior_metadata(&loaded, &group_id)
            .expect("project group behavior");

        assert_eq!(
            behavior.default_auto_type_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}")
        );
        assert_eq!(
            behavior.last_top_visible_entry_id.as_deref(),
            Some(top_entry_id.as_str())
        );
        assert_eq!(behavior.enable_auto_type, Some(false));
        assert_eq!(behavior.enable_searching, Some(true));
    }

    #[test]
    fn facade_search_returns_binding_friendly_entry_matches() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Queries");
        let mut child = Group::new("Child");

        let mut entry = Entry::new("Example");
        entry.username = "alice".into();
        entry.url = "https://example.com".into();
        entry.tags.insert("prod".into());
        child.entries.push(entry);
        vault.root.children.push(child);

        let matches = core.search_entries_view(&vault, "alice");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].entry.title, "Example");
        assert_eq!(matches[0].entry.username, "alice");
        assert_eq!(
            matches[0].group_path,
            vec!["Queries".to_string(), "Child".to_string()]
        );
        assert_eq!(matches[0].group_id, vault.root.children[0].id.to_string());
    }

    #[test]
    fn facade_updates_entry_fields_by_uuid() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let mut child = Group::new("Child");

        let mut entry = Entry::new("Before");
        let entry_id = entry.id.to_string();
        entry.username = "old-user".into();
        entry.password = "old-pass".into();
        entry.url = "https://old.example.com".into();
        entry.notes = "old notes".into();
        child.entries.push(entry);
        vault.root.children.push(child);

        let updated = core
            .update_entry_fields(
                &mut vault,
                &entry_id,
                EntryUpdate {
                    title: Some("After".into()),
                    username: Some("new-user".into()),
                    password: Some("new-pass".into()),
                    url: Some("https://new.example.com".into()),
                    notes: Some("new notes".into()),
                },
            )
            .expect("update entry");

        assert_eq!(updated.id, entry_id);
        assert_eq!(updated.title, "After");
        assert_eq!(updated.username, "new-user");
        assert_eq!(updated.url, "https://new.example.com");

        let stored = core
            .find_entry_view_by_id(&vault, &entry_id)
            .expect("stored entry");
        assert_eq!(stored.title, "After");
        assert_eq!(stored.username, "new-user");
        assert_eq!(stored.url, "https://new.example.com");
        assert_eq!(
            vault.root.children[0].entries[0].password.as_str(),
            "new-pass"
        );
        assert_eq!(vault.root.children[0].entries[0].notes, "new notes");
    }

    #[test]
    fn facade_adds_and_deletes_entry_under_group() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let parent_id = vault.root.id.to_string();

        let created = core
            .add_entry(
                &mut vault,
                &parent_id,
                EntryCreate {
                    title: "Created".into(),
                    username: "alice".into(),
                    password: "secret".into(),
                    url: "https://example.com".into(),
                    notes: "created in facade".into(),
                },
            )
            .expect("add entry");

        assert_eq!(vault.root.entries.len(), 1);
        assert_eq!(created.title, "Created");
        assert_eq!(created.username, "alice");
        assert_eq!(vault.root.entries[0].password, "secret");

        core.delete_entry(&mut vault, &created.id)
            .expect("delete entry");

        assert!(core.find_entry_view_by_id(&vault, &created.id).is_none());
        assert!(vault.root.entries.is_empty());
    }

    #[test]
    fn facade_adds_and_deletes_group_under_parent() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let root_id = vault.root.id.to_string();

        let child = core
            .add_group(&mut vault, &root_id, "Created Group")
            .expect("add group");

        assert_eq!(child.title, "Created Group");
        assert_eq!(vault.root.children.len(), 1);
        assert_eq!(vault.root.children[0].title, "Created Group");

        core.delete_group(&mut vault, &child.id)
            .expect("delete group");

        assert!(core.find_group_view_by_id(&vault, &child.id).is_none());
        assert!(vault.root.children.is_empty());
    }

    #[test]
    fn facade_rejects_deleting_root_group() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let root_id = vault.root.id.to_string();

        let error = core
            .delete_group(&mut vault, &root_id)
            .expect_err("root deletion should be rejected");

        assert_eq!(error, super::MutationError::CannotDeleteRootGroup);
        assert_eq!(vault.root.title, "Mutations");
    }

    #[test]
    fn facade_replaces_entry_tags_by_uuid() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let mut entry = Entry::new("Tagged");
        let entry_id = entry.id.to_string();
        entry.tags.insert("old".into());
        vault.root.entries.push(entry);

        let updated = core
            .replace_entry_tags(&mut vault, &entry_id, vec!["prod".into(), "ios".into()])
            .expect("replace tags");

        assert_eq!(updated.tags, vec!["ios".to_string(), "prod".to_string()]);
        assert_eq!(
            vault.root.entries[0]
                .tags
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["ios".to_string(), "prod".to_string()]
        );
    }

    #[test]
    fn entry_tag_updates_invalidate_raw_fidelity_state() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let mut entry = Entry::new("Tagged");
        let entry_id = entry.id.to_string();
        entry.tags.insert("old".into());
        entry.raw_state.tags_raw = Some("old".into());
        vault.root.entries.push(entry);

        core.replace_entry_tags(&mut vault, &entry_id, vec!["new".into()])
            .expect("replace tags");

        assert_eq!(vault.root.entries[0].tags.iter().next().unwrap(), "new");
        assert_eq!(vault.root.entries[0].raw_state.tags_raw, None);
    }

    #[test]
    fn facade_rejects_unrepresentable_entry_tags_without_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let entry = Entry::new("Tagged");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        for tags in [vec![String::new()], vec!["one;two".into()]] {
            let before = vault.clone();
            assert!(
                core.replace_entry_tags(&mut vault, &entry_id, tags)
                    .is_err()
            );
            assert_eq!(vault, before);
        }
    }

    #[test]
    fn facade_upserts_and_deletes_entry_custom_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let entry = Entry::new("Custom");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let updated = core
            .upsert_entry_custom_field(
                &mut vault,
                &entry_id,
                EntryCustomFieldInput {
                    key: "OtpSeed".into(),
                    value: "secret".into(),
                    protected: true,
                },
            )
            .expect("upsert custom field");
        assert_eq!(updated.custom_field_count, 1);
        assert_eq!(vault.root.entries[0].attributes["OtpSeed"].value, "secret");
        assert!(vault.root.entries[0].attributes["OtpSeed"].protected);

        let updated = core
            .delete_entry_custom_field(&mut vault, &entry_id, "OtpSeed")
            .expect("delete custom field");
        assert_eq!(updated.custom_field_count, 0);
        assert!(!vault.root.entries[0].attributes.contains_key("OtpSeed"));
    }

    #[test]
    fn facade_rejects_empty_entry_map_keys_without_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let entry = Entry::new("Custom");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let before = vault.clone();
        assert!(
            core.upsert_entry_custom_field(
                &mut vault,
                &entry_id,
                EntryCustomFieldInput {
                    key: String::new(),
                    value: "value".into(),
                    protected: false,
                },
            )
            .is_err()
        );
        assert_eq!(vault, before);

        assert!(
            core.upsert_entry_custom_data(
                &mut vault,
                &entry_id,
                EntryCustomDataInput {
                    key: String::new(),
                    value: "value".into(),
                },
            )
            .is_err()
        );
        assert_eq!(vault, before);

        assert!(
            core.upsert_entry_custom_data_detail(
                &mut vault,
                &entry_id,
                super::EntryCustomDataItemDetailInput {
                    key: String::new(),
                    value: "value".into(),
                    last_modified: None,
                },
            )
            .is_err()
        );
        assert_eq!(vault, before);
    }

    #[test]
    fn facade_mutates_attachments_and_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Mutations");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let updated = core
            .add_entry_attachment(
                &mut vault,
                &entry_id,
                EntryAttachmentInput {
                    name: "a.txt".into(),
                    data: b"hello".to_vec(),
                    protect_in_memory: true,
                },
            )
            .expect("add attachment");
        assert_eq!(updated.attachment_count, 1);
        assert_eq!(
            vault.root.entries[0].attachments["a.txt"].data,
            b"hello".to_vec()
        );
        assert!(vault.root.entries[0].attachments["a.txt"].protect_in_memory);

        let mut key = CompositeKey::default();
        key.add_password("roundtrip");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save after attachment");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload after attachment");
        assert_eq!(
            loaded.root.entries[0].attachments["a.txt"].data,
            b"hello".to_vec()
        );
        assert!(loaded.root.entries[0].attachments["a.txt"].protect_in_memory);

        let updated = core
            .delete_entry_attachment(&mut vault, &entry_id, "a.txt")
            .expect("delete attachment");
        assert_eq!(updated.attachment_count, 0);
        assert!(!vault.root.entries[0].attachments.contains_key("a.txt"));
    }

    #[test]
    fn facade_rejects_empty_attachment_names_without_mutation() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let before = vault.clone();
        assert!(
            core.add_entry_attachment(
                &mut vault,
                &entry_id,
                EntryAttachmentInput {
                    name: String::new(),
                    data: b"content".to_vec(),
                    protect_in_memory: false,
                },
            )
            .is_err()
        );
        assert_eq!(vault, before);

        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "file.bin".into(),
                data: b"content".to_vec(),
                protect_in_memory: false,
            },
        )
        .expect("add valid attachment");
        let before = vault.clone();
        assert!(
            core.update_entry_attachment_metadata(
                &mut vault,
                &entry_id,
                "file.bin",
                AttachmentMetadataUpdate {
                    new_name: Some(String::new()),
                    protect_in_memory: None,
                },
            )
            .is_err()
        );
        assert_eq!(vault, before);
    }

    #[test]
    fn facade_updates_attachment_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: false,
            },
        )
        .expect("add attachment");

        let attachments = core
            .update_entry_attachment_metadata(
                &mut vault,
                &entry_id,
                "a.txt",
                AttachmentMetadataUpdate {
                    new_name: Some("renamed.txt".into()),
                    protect_in_memory: Some(true),
                },
            )
            .expect("update attachment metadata");

        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "renamed.txt".into(),
                size: 5,
                protect_in_memory: true,
            }]
        );
        assert!(!vault.root.entries[0].attachments.contains_key("a.txt"));
        assert_eq!(
            vault.root.entries[0].attachments["renamed.txt"].name,
            "renamed.txt"
        );
        assert!(vault.root.entries[0].attachments["renamed.txt"].protect_in_memory);
    }

    #[test]
    fn attachment_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: false,
            },
        )
        .expect("add attachment");
        core.update_entry_attachment_metadata(
            &mut vault,
            &entry_id,
            "a.txt",
            AttachmentMetadataUpdate {
                new_name: Some("renamed.txt".into()),
                protect_in_memory: Some(true),
            },
        )
        .expect("update attachment metadata");

        let mut key = CompositeKey::default();
        key.add_password("attachment-metadata");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save attachment metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload attachment metadata");
        let attachments = core
            .list_entry_attachments(&loaded, &entry_id)
            .expect("list attachments");

        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "renamed.txt".into(),
                size: 5,
                protect_in_memory: true,
            }]
        );
    }

    #[test]
    fn facade_replaces_attachment_content_and_preserves_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: true,
            },
        )
        .expect("add attachment");

        let attachments = core
            .replace_entry_attachment_content(
                &mut vault,
                &entry_id,
                "a.txt",
                AttachmentContentUpdate {
                    data: b"updated-bytes".to_vec(),
                },
            )
            .expect("replace attachment content");

        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "a.txt".into(),
                size: 13,
                protect_in_memory: true,
            }]
        );
        assert_eq!(
            vault.root.entries[0].attachments["a.txt"].data,
            b"updated-bytes".to_vec()
        );
        assert_eq!(vault.root.entries[0].attachments["a.txt"].name, "a.txt");
        assert!(vault.root.entries[0].attachments["a.txt"].protect_in_memory);
    }

    #[test]
    fn attachment_content_replace_facade_roundtrips_updated_bytes() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: true,
            },
        )
        .expect("add attachment");
        core.replace_entry_attachment_content(
            &mut vault,
            &entry_id,
            "a.txt",
            AttachmentContentUpdate {
                data: b"updated-bytes".to_vec(),
            },
        )
        .expect("replace attachment content");

        let mut key = CompositeKey::default();
        key.add_password("attachment-content");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save attachment content");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload attachment content");

        assert_eq!(
            loaded.root.entries[0].attachments["a.txt"].data,
            b"updated-bytes".to_vec()
        );
        assert!(loaded.root.entries[0].attachments["a.txt"].protect_in_memory);
        let attachments = core
            .list_entry_attachments(&loaded, &entry_id)
            .expect("list attachments");
        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "a.txt".into(),
                size: 13,
                protect_in_memory: true,
            }]
        );
    }

    #[test]
    fn facade_projects_attachment_content() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: true,
            },
        )
        .expect("add attachment");

        let content = core
            .project_entry_attachment_content(&vault, &entry_id, "a.txt")
            .expect("project attachment content");

        assert_eq!(content.name, "a.txt");
        assert_eq!(content.data, b"hello".to_vec());
    }

    #[test]
    fn attachment_content_projection_facade_roundtrips_bytes() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Attachments");
        let entry = Entry::new("Attachment");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        core.add_entry_attachment(
            &mut vault,
            &entry_id,
            EntryAttachmentInput {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: true,
            },
        )
        .expect("add attachment");

        let mut key = CompositeKey::default();
        key.add_password("attachment-content-view");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save attachment content");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload attachment content");
        let content = core
            .project_entry_attachment_content(&loaded, &entry_id, "a.txt")
            .expect("project attachment content");

        assert_eq!(content.name, "a.txt");
        assert_eq!(content.data, b"hello".to_vec());
    }

    #[test]
    fn facade_soft_deletes_entry_to_recycle_bin_and_records_deleted_object() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Recycle");
        let mut group = Group::new("Active");
        let group_id = group.id.to_string();
        let entry = Entry::new("Disposable");
        let entry_id = entry.id.to_string();
        group.entries.push(entry);
        vault.root.children.push(group);

        let deleted = core
            .soft_delete_entry_to_recycle_bin(&mut vault, &entry_id)
            .expect("soft delete entry");
        let deleted_objects = core.list_deleted_objects(&vault);

        assert_eq!(deleted.id, entry_id);
        assert!(vault.root.children[0].entries.is_empty());
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert!(vault.recycle_bin_group.is_some());
        assert_eq!(deleted_objects.len(), 1);
        assert_eq!(
            deleted_objects,
            vec![DeletedObjectView {
                id: entry_id.clone(),
                deleted_at: vault.deleted_objects[0].deleted_at,
            }]
        );

        let recycle_bin_id = vault.recycle_bin_group.expect("recycle bin id");
        let recycle_bin = core
            .find_group_view_by_id(&vault, &recycle_bin_id.to_string())
            .expect("recycle bin view");
        assert_eq!(recycle_bin.title, "Recycle Bin");
        assert_eq!(recycle_bin.entries.len(), 1);
        assert_eq!(recycle_bin.entries[0].title, "Disposable");
        assert_eq!(
            vault.root.children[1].entries[0].previous_parent,
            Some(group_id.parse().expect("uuid"))
        );
    }

    #[test]
    fn facade_restores_entry_from_recycle_bin_and_clears_deleted_object() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Recycle");
        let mut group = Group::new("Active");
        let group_id = group.id.to_string();
        let entry = Entry::new("Disposable");
        let entry_id = entry.id.to_string();
        group.entries.push(entry);
        vault.root.children.push(group);

        core.soft_delete_entry_to_recycle_bin(&mut vault, &entry_id)
            .expect("soft delete entry");

        let restored = core
            .restore_entry_from_recycle_bin(&mut vault, &entry_id, None)
            .expect("restore entry");

        assert_eq!(restored.id, entry_id);
        assert_eq!(vault.deleted_objects.len(), 0);
        assert!(core.list_deleted_objects(&vault).is_empty());
        let group = core
            .find_group_view_by_id(&vault, &group_id)
            .expect("restored group");
        assert_eq!(group.entries.len(), 1);
        assert_eq!(group.entries[0].title, "Disposable");
        let recycle_bin = core
            .find_group_view_by_id(
                &vault,
                &vault.recycle_bin_group.expect("recycle bin id").to_string(),
            )
            .expect("recycle bin view");
        assert!(recycle_bin.entries.is_empty());
    }

    #[test]
    fn recycle_bin_mutation_roundtrips_deleted_objects_and_bin_contents() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Recycle");
        vault.root.entries.push(Entry::new("Disposable"));
        let entry_id = vault.root.entries[0].id.to_string();

        core.soft_delete_entry_to_recycle_bin(&mut vault, &entry_id)
            .expect("soft delete entry");

        let mut key = CompositeKey::default();
        key.add_password("recycle");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save recycle bin state");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload recycle bin state");

        assert_eq!(loaded.deleted_objects.len(), 1);
        assert_eq!(loaded.root.entries.len(), 0);
        let recycle_bin_id = loaded.recycle_bin_group.expect("loaded recycle bin id");
        let recycle_bin = core
            .find_group_view_by_id(&loaded, &recycle_bin_id.to_string())
            .expect("loaded recycle bin view");
        assert_eq!(recycle_bin.entries.len(), 1);
        assert_eq!(recycle_bin.entries[0].id, entry_id);
    }

    #[test]
    fn facade_updates_group_metadata_by_uuid() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let group = Group::new("Before");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        let updated = core
            .update_group_metadata(
                &mut vault,
                &group_id,
                GroupMetadataUpdate {
                    title: Some("After".into()),
                    notes: Some("group notes".into()),
                    icon_id: Some(42),
                    flags: Some(GroupFlags {
                        is_expanded: Some(true),
                        enable_auto_type: Some(false),
                        enable_searching: Some(true),
                    }),
                },
            )
            .expect("update group metadata");

        assert_eq!(updated.id, group_id);
        assert_eq!(updated.title, "After");
        assert_eq!(updated.icon_id, Some(42));
        assert_eq!(vault.root.children[0].notes, "group notes");
        assert_eq!(vault.root.children[0].flags.is_expanded, Some(true));
        assert_eq!(vault.root.children[0].flags.enable_auto_type, Some(false));
        assert_eq!(vault.root.children[0].flags.enable_searching, Some(true));
    }

    #[test]
    fn group_metadata_mutation_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let group = Group::new("Before");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        core.update_group_metadata(
            &mut vault,
            &group_id,
            GroupMetadataUpdate {
                title: Some("After".into()),
                notes: Some("group notes".into()),
                icon_id: Some(42),
                flags: Some(GroupFlags {
                    is_expanded: Some(true),
                    enable_auto_type: Some(false),
                    enable_searching: Some(true),
                }),
            },
        )
        .expect("update group metadata");

        let mut key = CompositeKey::default();
        key.add_password("groups");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group metadata");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload group metadata");

        let group = core
            .find_group_view_by_id(&loaded, &group_id)
            .expect("loaded group");
        assert_eq!(group.title, "After");
        assert_eq!(group.icon_id, Some(42));
        assert_eq!(loaded.root.children[0].notes, "group notes");
        assert_eq!(loaded.root.children[0].flags.is_expanded, Some(true));
        assert_eq!(loaded.root.children[0].flags.enable_auto_type, Some(false));
        assert_eq!(loaded.root.children[0].flags.enable_searching, Some(true));
    }

    #[test]
    fn facade_updates_group_behavior_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Behavior");
        let entry = Entry::new("Top");
        let top_entry_id = entry.id.to_string();
        group.entries.push(entry);
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        let behavior = core
            .update_group_behavior_metadata(
                &mut vault,
                &group_id,
                GroupBehaviorMetadataUpdate {
                    default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}".into()),
                    last_top_visible_entry_id: Some(top_entry_id.clone()),
                    enable_auto_type: Some(false),
                    enable_searching: Some(true),
                },
            )
            .expect("update group behavior metadata");

        assert_eq!(
            behavior.default_auto_type_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}")
        );
        assert_eq!(
            behavior.last_top_visible_entry_id.as_deref(),
            Some(top_entry_id.as_str())
        );
        assert_eq!(behavior.enable_auto_type, Some(false));
        assert_eq!(behavior.enable_searching, Some(true));
        assert_eq!(
            vault.root.children[0].default_auto_type_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}")
        );
        assert_eq!(
            vault.root.children[0]
                .last_top_visible_entry
                .map(|id| id.to_string())
                .as_deref(),
            Some(top_entry_id.as_str())
        );
        assert_eq!(vault.root.children[0].flags.enable_auto_type, Some(false));
        assert_eq!(vault.root.children[0].flags.enable_searching, Some(true));
    }

    #[test]
    fn group_behavior_metadata_mutation_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Behavior");
        let entry = Entry::new("Top");
        let top_entry_id = entry.id.to_string();
        group.entries.push(entry);
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        core.update_group_behavior_metadata(
            &mut vault,
            &group_id,
            GroupBehaviorMetadataUpdate {
                default_auto_type_sequence: Some("{USERNAME}{TAB}{PASSWORD}".into()),
                last_top_visible_entry_id: Some(top_entry_id.clone()),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            },
        )
        .expect("update group behavior metadata");

        let mut key = CompositeKey::default();
        key.add_password("group-behavior");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group behavior");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload group behavior");
        let behavior = core
            .project_group_behavior_metadata(&loaded, &group_id)
            .expect("project group behavior");

        assert_eq!(
            behavior.default_auto_type_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}")
        );
        assert_eq!(
            behavior.last_top_visible_entry_id.as_deref(),
            Some(top_entry_id.as_str())
        );
        assert_eq!(behavior.enable_auto_type, Some(false));
        assert_eq!(behavior.enable_searching, Some(true));
    }

    #[test]
    fn facade_updates_group_times() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Timed");
        let group_id = group.id.to_string();
        group.times = Some(GroupTimes {
            created_at: 1,
            modified_at: 2,
            expires: true,
            expiry_time: Some(999),
            last_accessed_at: Some(3),
            usage_count: Some(4),
            location_changed_at: Some(5),
        });
        vault.root.children.push(group);

        let times = core
            .update_group_times(
                &mut vault,
                &group_id,
                GroupTimesUpdate {
                    created_at: Some(Some(10)),
                    modified_at: Some(Some(11)),
                    last_accessed_at: Some(Some(12)),
                    usage_count: Some(Some(13)),
                    location_changed_at: Some(None),
                },
            )
            .expect("update group times");

        assert_eq!(times.created_at, Some(10));
        assert_eq!(times.modified_at, Some(11));
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, None);
        assert_eq!(
            vault.root.children[0].times,
            Some(GroupTimes {
                created_at: 10,
                modified_at: 11,
                expires: true,
                expiry_time: Some(999),
                last_accessed_at: Some(12),
                usage_count: Some(13),
                location_changed_at: None,
            })
        );
    }

    #[test]
    fn group_times_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Timed");
        let group_id = group.id.to_string();
        group.times = Some(GroupTimes {
            created_at: 1,
            modified_at: 2,
            expires: true,
            expiry_time: Some(999),
            last_accessed_at: Some(3),
            usage_count: Some(4),
            location_changed_at: Some(5),
        });
        vault.root.children.push(group);

        core.update_group_times(
            &mut vault,
            &group_id,
            GroupTimesUpdate {
                created_at: Some(Some(10)),
                modified_at: Some(Some(11)),
                last_accessed_at: Some(Some(12)),
                usage_count: Some(Some(13)),
                location_changed_at: Some(Some(14)),
            },
        )
        .expect("update group times");

        let mut key = CompositeKey::default();
        key.add_password("group-times");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group times");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload group times");
        let times = core
            .project_group_times(&loaded, &group_id)
            .expect("project group times");
        let group = &loaded.root.children[0];

        assert_eq!(times.created_at, Some(10));
        assert_eq!(times.modified_at, Some(11));
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, Some(14));
        assert_eq!(group.times.as_ref().map(|value| value.expires), Some(true));
        assert_eq!(
            group.times.as_ref().and_then(|value| value.expiry_time),
            Some(999)
        );
    }

    #[test]
    fn facade_updates_group_expiry() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let mut group = Group::new("Expiry");
        let group_id = group.id.to_string();
        group.times = Some(GroupTimes {
            created_at: 1,
            modified_at: 2,
            expires: false,
            expiry_time: None,
            last_accessed_at: Some(3),
            usage_count: Some(4),
            location_changed_at: Some(5),
        });
        vault.root.children.push(group);

        let expiry = core
            .update_group_expiry(
                &mut vault,
                &group_id,
                GroupExpiryUpdate {
                    expires: true,
                    expiry_time: Some(1_900_000_000),
                },
            )
            .expect("update group expiry");

        assert_eq!(expiry.expires, Some(true));
        assert_eq!(expiry.expiry_time, Some(1_900_000_000));
        assert_eq!(
            vault.root.children[0].times.map(|times| times.expires),
            Some(true)
        );
        assert_eq!(
            vault.root.children[0]
                .times
                .and_then(|times| times.expiry_time),
            Some(1_900_000_000)
        );
    }

    #[test]
    fn group_expiry_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Groups");
        let group = Group::new("Expiry");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        core.update_group_expiry(
            &mut vault,
            &group_id,
            GroupExpiryUpdate {
                expires: true,
                expiry_time: Some(1_900_000_000),
            },
        )
        .expect("update group expiry");

        let mut key = CompositeKey::default();
        key.add_password("group-expiry");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group expiry");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload group expiry");
        let expiry = core
            .project_group_expiry(&loaded, &group_id)
            .expect("project group expiry");

        assert_eq!(expiry.expires, Some(true));
        assert_eq!(expiry.expiry_time, Some(1_900_000_000));
    }

    #[test]
    fn facade_manages_custom_icons_and_assigns_them_to_nodes() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Icons");
        let group = Group::new("Group");
        let group_id = group.id.to_string();
        vault.root.children.push(group);
        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        assert!(core.list_custom_icons(&vault).is_empty());

        let icon = core
            .upsert_custom_icon(
                &mut vault,
                CustomIconInput {
                    id: None,
                    data: vec![1, 2, 3],
                    name: Some("Created Icon".into()),
                    last_modified: Some(1_700_000_001),
                },
            )
            .expect("create custom icon");
        let icon_id = icon.id.clone();
        assert_eq!(core.list_custom_icons(&vault), vec![icon.clone()]);

        let updated_icon = core
            .upsert_custom_icon(
                &mut vault,
                CustomIconInput {
                    id: Some(icon_id.clone()),
                    data: vec![9, 8, 7],
                    name: Some("Updated Icon".into()),
                    last_modified: Some(1_700_000_002),
                },
            )
            .expect("update custom icon");
        assert_eq!(updated_icon.data, vec![9, 8, 7]);
        assert_eq!(updated_icon.name.as_deref(), Some("Updated Icon"));
        assert_eq!(updated_icon.last_modified, Some(1_700_000_002));

        let group_view = core
            .update_group_custom_icon(&mut vault, &group_id, Some(icon_id.clone()))
            .expect("assign group custom icon");
        assert_eq!(group_view.custom_icon_id.as_deref(), Some(icon_id.as_str()));

        let entry_view = core
            .update_entry_custom_icon(&mut vault, &entry_id, Some(icon_id.clone()))
            .expect("assign entry custom icon");
        assert_eq!(entry_view.custom_icon_id.as_deref(), Some(icon_id.as_str()));

        core.delete_custom_icon(&mut vault, &icon_id)
            .expect("delete custom icon");
        assert!(core.list_custom_icons(&vault).is_empty());
        assert_eq!(vault.root.children[0].custom_icon_id, None);
        assert_eq!(vault.root.entries[0].custom_icon_id, None);
    }

    #[test]
    fn custom_icon_mutation_roundtrips_assigned_icons() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Icons");
        let group = Group::new("Group");
        let group_id = group.id.to_string();
        vault.root.children.push(group);
        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let icon_id = uuid::Uuid::new_v4().to_string();
        core.upsert_custom_icon(
            &mut vault,
            CustomIconInput {
                id: Some(icon_id.clone()),
                data: vec![4, 5, 6, 7],
                name: Some("Roundtrip Icon".into()),
                last_modified: Some(1_700_000_003),
            },
        )
        .expect("insert custom icon");
        core.update_group_custom_icon(&mut vault, &group_id, Some(icon_id.clone()))
            .expect("assign group icon");
        core.update_entry_custom_icon(&mut vault, &entry_id, Some(icon_id.clone()))
            .expect("assign entry icon");

        let mut key = CompositeKey::default();
        key.add_password("custom-icons");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save custom icons");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload custom icons");

        assert_eq!(
            core.list_custom_icons(&loaded),
            vec![CustomIconView {
                id: icon_id.clone(),
                data: vec![4, 5, 6, 7],
                name: Some("Roundtrip Icon".into()),
                last_modified: Some(1_700_000_003),
            }]
        );
        assert_eq!(
            core.find_group_view_by_id(&loaded, &group_id)
                .expect("group view")
                .custom_icon_id
                .as_deref(),
            Some(icon_id.as_str())
        );
        assert_eq!(
            core.find_entry_view_by_id(&loaded, &entry_id)
                .expect("entry view")
                .custom_icon_id
                .as_deref(),
            Some(icon_id.as_str())
        );
    }

    #[test]
    fn custom_icon_view_projects_metadata_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Icons");
        let icon_id = uuid::Uuid::new_v4();
        vault.custom_icons.push(CustomIcon {
            id: icon_id,
            data: vec![1, 2, 3, 4],
            name: Some("Browser Icon".into()),
            last_modified: Some(1_700_000_005),
        });

        assert_eq!(
            core.list_custom_icons(&vault),
            vec![CustomIconView {
                id: icon_id.to_string(),
                data: vec![1, 2, 3, 4],
                name: Some("Browser Icon".into()),
                last_modified: Some(1_700_000_005),
            }]
        );
    }

    #[test]
    fn facade_manages_vault_and_group_custom_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        let group = Group::new("Group");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        assert!(core.list_vault_custom_data(&vault).is_empty());
        assert!(
            core.list_group_custom_data(&vault, &group_id)
                .expect("list group custom data")
                .is_empty()
        );

        let vault_items = core.upsert_vault_custom_data(
            &mut vault,
            CustomDataItemInput {
                key: "client".into(),
                value: "ios".into(),
            },
        );
        assert_eq!(
            vault_items,
            vec![CustomDataItemView {
                key: "client".into(),
                value: "ios".into(),
            }]
        );

        let group_items = core
            .upsert_group_custom_data(
                &mut vault,
                &group_id,
                CustomDataItemInput {
                    key: "scope".into(),
                    value: "shared".into(),
                },
            )
            .expect("upsert group custom data");
        assert_eq!(
            group_items,
            vec![CustomDataItemView {
                key: "scope".into(),
                value: "shared".into(),
            }]
        );

        core.delete_vault_custom_data(&mut vault, "client")
            .expect("delete vault custom data");
        core.delete_group_custom_data(&mut vault, &group_id, "scope")
            .expect("delete group custom data");

        assert!(core.list_vault_custom_data(&vault).is_empty());
        assert!(
            core.list_group_custom_data(&vault, &group_id)
                .expect("list group custom data")
                .is_empty()
        );
    }

    #[test]
    fn vault_and_group_custom_data_mutation_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        let group = Group::new("Group");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        core.upsert_vault_custom_data(
            &mut vault,
            CustomDataItemInput {
                key: "client".into(),
                value: "web".into(),
            },
        );
        core.upsert_group_custom_data(
            &mut vault,
            &group_id,
            CustomDataItemInput {
                key: "scope".into(),
                value: "team".into(),
            },
        )
        .expect("upsert group custom data");

        let mut key = CompositeKey::default();
        key.add_password("vault-group-custom-data");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save custom data");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload custom data");

        assert_eq!(
            core.list_vault_custom_data(&loaded),
            vec![CustomDataItemView {
                key: "client".into(),
                value: "web".into(),
            }]
        );
        assert_eq!(
            core.list_group_custom_data(&loaded, &group_id)
                .expect("list group custom data"),
            vec![CustomDataItemView {
                key: "scope".into(),
                value: "team".into(),
            }]
        );
    }

    #[test]
    fn vault_custom_data_detail_projects_meta_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        vault.meta_custom_data.insert("client".into(), "web".into());
        vault
            .meta_custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "client".into(),
                    value: "web".into(),
                    last_modified: Some(1_700_000_006),
                }],
                after: None,
            });

        assert_eq!(
            core.list_vault_custom_data_detail(&vault),
            vec![super::VaultCustomDataItemView {
                key: "client".into(),
                value: "web".into(),
                last_modified: Some(1_700_000_006),
            }]
        );
    }

    #[test]
    fn vault_custom_data_detail_reflects_mutation_after_upsert_and_delete() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        vault.meta_custom_data.insert("client".into(), "web".into());
        vault
            .meta_custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "client".into(),
                    value: "web".into(),
                    last_modified: Some(1_700_000_006),
                }],
                after: None,
            });

        core.upsert_vault_custom_data(
            &mut vault,
            super::CustomDataItemInput {
                key: "client".into(),
                value: "desktop".into(),
            },
        );
        core.upsert_vault_custom_data(
            &mut vault,
            super::CustomDataItemInput {
                key: "channel".into(),
                value: "stable".into(),
            },
        );
        core.delete_vault_custom_data(&mut vault, "client")
            .expect("delete updated client custom data");

        assert_eq!(
            core.list_vault_custom_data_detail(&vault),
            vec![super::VaultCustomDataItemView {
                key: "channel".into(),
                value: "stable".into(),
                last_modified: None,
            }]
        );
    }

    #[test]
    fn vault_custom_data_detail_upsert_preserves_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");

        assert_eq!(
            core.upsert_vault_custom_data_detail(
                &mut vault,
                super::VaultCustomDataItemDetailInput {
                    key: "client".into(),
                    value: "web".into(),
                    last_modified: Some(1_700_000_009),
                },
            ),
            vec![super::VaultCustomDataItemView {
                key: "client".into(),
                value: "web".into(),
                last_modified: Some(1_700_000_009),
            }]
        );
    }

    #[test]
    fn group_custom_data_detail_projects_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        let mut group = Group::new("Group");
        let group_id = group.id.to_string();
        group.custom_data.insert("scope".into(), "shared".into());
        group
            .custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "scope".into(),
                    value: "shared".into(),
                    last_modified: Some(1_700_000_007),
                }],
                after: None,
            });
        vault.root.children.push(group);

        assert_eq!(
            core.list_group_custom_data_detail(&vault, &group_id)
                .expect("list group custom data detail"),
            vec![super::GroupCustomDataItemView {
                key: "scope".into(),
                value: "shared".into(),
                last_modified: Some(1_700_000_007),
            }]
        );
    }

    #[test]
    fn group_custom_data_detail_clears_stale_item_timestamp_after_simple_upsert() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        let mut group = Group::new("Group");
        let group_id = group.id.to_string();
        group.custom_data.insert("scope".into(), "shared".into());
        group
            .custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "scope".into(),
                    value: "shared".into(),
                    last_modified: Some(1_700_000_007),
                }],
                after: None,
            });
        vault.root.children.push(group);

        core.upsert_group_custom_data(
            &mut vault,
            &group_id,
            super::CustomDataItemInput {
                key: "scope".into(),
                value: "local".into(),
            },
        )
        .expect("upsert group custom data");

        assert_eq!(
            core.list_group_custom_data_detail(&vault, &group_id)
                .expect("list group custom data detail"),
            vec![super::GroupCustomDataItemView {
                key: "scope".into(),
                value: "local".into(),
                last_modified: None,
            }]
        );
    }

    #[test]
    fn group_custom_data_detail_upsert_preserves_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("CustomData");
        let group = Group::new("Group");
        let group_id = group.id.to_string();
        vault.root.children.push(group);

        assert_eq!(
            core.upsert_group_custom_data_detail(
                &mut vault,
                &group_id,
                super::GroupCustomDataItemDetailInput {
                    key: "scope".into(),
                    value: "shared".into(),
                    last_modified: Some(1_700_000_010),
                },
            )
            .expect("upsert group custom data detail"),
            vec![super::GroupCustomDataItemView {
                key: "scope".into(),
                value: "shared".into(),
                last_modified: Some(1_700_000_010),
            }]
        );
    }

    #[test]
    fn facade_manages_vault_public_custom_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("PublicCustomData");

        assert!(core.list_vault_public_custom_data(&vault).is_empty());

        let items = core.upsert_vault_public_custom_data(
            &mut vault,
            PublicCustomDataItemInput {
                key: "client".into(),
                value: b"ios".to_vec(),
            },
        );
        assert_eq!(
            items,
            vec![PublicCustomDataItemView {
                key: "client".into(),
                value: b"ios".to_vec(),
            }]
        );

        core.delete_vault_public_custom_data(&mut vault, "client")
            .expect("delete public custom data");
        assert!(core.list_vault_public_custom_data(&vault).is_empty());
    }

    #[test]
    fn public_custom_data_facade_roundtrips_through_load_and_inspect() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("PublicCustomData");
        core.upsert_vault_public_custom_data(
            &mut vault,
            PublicCustomDataItemInput {
                key: "client".into(),
                value: b"web".to_vec(),
            },
        );

        let mut key = CompositeKey::default();
        key.add_password("public-custom-data");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save public custom data");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload public custom data");
        let inspected = core
            .inspect_kdbx_header(&bytes)
            .expect("inspect public custom data");

        assert_eq!(
            core.list_vault_public_custom_data(&loaded),
            vec![PublicCustomDataItemView {
                key: "client".into(),
                value: b"web".to_vec(),
            }]
        );
        assert_eq!(
            inspected.public_custom_data.get("client"),
            Some(&b"web".to_vec())
        );
    }

    #[test]
    fn facade_updates_entry_presentation_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Presentation");
        let entry = Entry::new("Styled");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let presentation = core
            .update_entry_presentation_metadata(
                &mut vault,
                &entry_id,
                EntryPresentationMetadataUpdate {
                    icon_id: Some(Some(7)),
                    foreground_color: Some(Some("#112233".into())),
                    background_color: Some(Some("#445566".into())),
                    override_url: Some(Some("https://override.example".into())),
                },
            )
            .expect("update presentation metadata");

        assert_eq!(presentation.icon_id, Some(7));
        assert_eq!(presentation.foreground_color.as_deref(), Some("#112233"));
        assert_eq!(presentation.background_color.as_deref(), Some("#445566"));
        assert_eq!(
            presentation.override_url.as_deref(),
            Some("https://override.example")
        );
        assert_eq!(vault.root.entries[0].icon_id, Some(7));
        assert_eq!(
            vault.root.entries[0].foreground_color.as_deref(),
            Some("#112233")
        );
        assert_eq!(
            vault.root.entries[0].background_color.as_deref(),
            Some("#445566")
        );
        assert_eq!(
            vault.root.entries[0].override_url.as_deref(),
            Some("https://override.example")
        );
    }

    #[test]
    fn presentation_updates_invalidate_raw_fidelity_state() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Presentation");
        let mut entry = Entry::new("Styled");
        let entry_id = entry.id.to_string();
        entry.raw_state.foreground_color_raw = Some("#111111".into());
        entry.raw_state.background_color_raw = Some("#222222".into());
        entry.raw_state.override_url_raw = Some("https://old.example".into());
        vault.root.entries.push(entry);

        core.update_entry_presentation_metadata(
            &mut vault,
            &entry_id,
            EntryPresentationMetadataUpdate {
                icon_id: None,
                foreground_color: Some(None),
                background_color: Some(Some("#445566".into())),
                override_url: Some(None),
            },
        )
        .expect("update presentation metadata");

        let raw = &vault.root.entries[0].raw_state;
        assert_eq!(raw.foreground_color_raw, None);
        assert_eq!(raw.background_color_raw, None);
        assert_eq!(raw.override_url_raw, None);
    }

    #[test]
    fn entry_presentation_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Presentation");
        let entry = Entry::new("Styled");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        core.update_entry_presentation_metadata(
            &mut vault,
            &entry_id,
            EntryPresentationMetadataUpdate {
                icon_id: Some(Some(7)),
                foreground_color: Some(Some("#112233".into())),
                background_color: Some(Some("#445566".into())),
                override_url: Some(Some("https://override.example".into())),
            },
        )
        .expect("update presentation metadata");

        let mut key = CompositeKey::default();
        key.add_password("presentation");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save presentation metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload presentation metadata");
        let presentation = core
            .project_entry_presentation_metadata(&loaded, &entry_id)
            .expect("project presentation metadata");

        assert_eq!(presentation.icon_id, Some(7));
        assert_eq!(presentation.foreground_color.as_deref(), Some("#112233"));
        assert_eq!(presentation.background_color.as_deref(), Some("#445566"));
        assert_eq!(
            presentation.override_url.as_deref(),
            Some("https://override.example")
        );
    }

    #[test]
    fn facade_updates_entry_auto_type() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("AutoType");
        let entry = Entry::new("Styled");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let auto_type = core
            .update_entry_auto_type(
                &mut vault,
                &entry_id,
                EntryAutoTypeUpdate {
                    enabled: Some(Some(true)),
                    obfuscation: Some(Some(2)),
                    default_sequence: Some(Some("{TITLE}{ENTER}".into())),
                    associations: Some(vec![EntryAutoTypeAssociationInput {
                        window: "KeePass".into(),
                        sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
                    }]),
                },
            )
            .expect("update entry auto type");

        assert_eq!(auto_type.enabled, Some(true));
        assert_eq!(auto_type.obfuscation, Some(2));
        assert_eq!(
            auto_type.default_sequence.as_deref(),
            Some("{TITLE}{ENTER}")
        );
        assert_eq!(
            auto_type.associations,
            vec![EntryAutoTypeAssociationView {
                window: "KeePass".into(),
                sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
            }]
        );
        assert_eq!(
            vault.root.entries[0].auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(2),
                default_sequence: Some("{TITLE}{ENTER}".into()),
                associations: vec![AutoTypeAssociation {
                    window: "KeePass".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
                }],
            })
        );
    }

    #[test]
    fn entry_auto_type_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("AutoType");
        let entry = Entry::new("Styled");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        core.update_entry_auto_type(
            &mut vault,
            &entry_id,
            EntryAutoTypeUpdate {
                enabled: Some(Some(true)),
                obfuscation: Some(Some(2)),
                default_sequence: Some(Some("{TITLE}{ENTER}".into())),
                associations: Some(vec![EntryAutoTypeAssociationInput {
                    window: "KeePass".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
                }]),
            },
        )
        .expect("update entry auto type");

        let mut key = CompositeKey::default();
        key.add_password("auto-type");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save auto type");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload auto type");
        let auto_type = core
            .project_entry_auto_type(&loaded, &entry_id)
            .expect("project entry auto type");

        assert_eq!(auto_type.enabled, Some(true));
        assert_eq!(auto_type.obfuscation, Some(2));
        assert_eq!(
            auto_type.default_sequence.as_deref(),
            Some("{TITLE}{ENTER}")
        );
        assert_eq!(
            auto_type.associations,
            vec![EntryAutoTypeAssociationView {
                window: "KeePass".into(),
                sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
            }]
        );
    }

    #[test]
    fn facade_updates_entry_times() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Times");
        let mut entry = Entry::new("Timed");
        let entry_id = entry.id.to_string();
        entry.created_at = 1;
        entry.modified_at = 2;
        entry.last_accessed_at = Some(3);
        entry.usage_count = Some(4);
        entry.location_changed_at = Some(5);
        entry.expires = true;
        entry.expiry_time = Some(999);
        vault.root.entries.push(entry);

        let times = core
            .update_entry_times(
                &mut vault,
                &entry_id,
                EntryTimesUpdate {
                    created_at: Some(10),
                    modified_at: Some(11),
                    last_accessed_at: Some(Some(12)),
                    usage_count: Some(Some(13)),
                    location_changed_at: Some(None),
                },
            )
            .expect("update entry times");

        assert_eq!(times.created_at, 10);
        assert_eq!(times.modified_at, 11);
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, None);
        assert_eq!(vault.root.entries[0].created_at, 10);
        assert_eq!(vault.root.entries[0].modified_at, 11);
        assert_eq!(vault.root.entries[0].last_accessed_at, Some(12));
        assert_eq!(vault.root.entries[0].usage_count, Some(13));
        assert_eq!(vault.root.entries[0].location_changed_at, None);
        assert!(vault.root.entries[0].expires);
        assert_eq!(vault.root.entries[0].expiry_time, Some(999));
    }

    #[test]
    fn entry_times_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Times");
        let mut entry = Entry::new("Timed");
        let entry_id = entry.id.to_string();
        entry.created_at = 1;
        entry.modified_at = 2;
        entry.last_accessed_at = Some(3);
        entry.usage_count = Some(4);
        entry.location_changed_at = Some(5);
        entry.expires = true;
        entry.expiry_time = Some(999);
        vault.root.entries.push(entry);

        core.update_entry_times(
            &mut vault,
            &entry_id,
            EntryTimesUpdate {
                created_at: Some(10),
                modified_at: Some(11),
                last_accessed_at: Some(Some(12)),
                usage_count: Some(Some(13)),
                location_changed_at: Some(Some(14)),
            },
        )
        .expect("update entry times");

        let mut key = CompositeKey::default();
        key.add_password("times");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save times");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload times");
        let times = core
            .project_entry_times(&loaded, &entry_id)
            .expect("project entry times");
        let entry = &loaded.root.entries[0];

        assert_eq!(times.created_at, 10);
        assert_eq!(times.modified_at, 11);
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, Some(14));
        assert!(entry.expires);
        assert_eq!(entry.expiry_time, Some(999));
    }

    #[test]
    fn facade_merges_vaults_and_reports_summary() {
        let core = KeepassCore::new();
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

        let summary = core.merge_vaults(&mut local, &incoming);

        assert_eq!(
            summary,
            MergeSummaryView {
                merged_entries: 1,
                history_snapshots_added: 1,
            }
        );
        assert_eq!(local.root.entries[0].password, "new-secret");
        assert_eq!(local.root.entries[0].history.len(), 1);
        assert_eq!(local.root.entries[0].history[0].password, "old-secret");
    }

    #[test]
    fn merge_facade_loads_kdbx_and_merges_into_target() {
        let core = KeepassCore::new();
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

        let mut key = CompositeKey::default();
        key.add_password("merge");
        let bytes = core
            .save_kdbx(&incoming, &key, super::SaveProfile::recommended())
            .expect("save merge source");

        let summary = core
            .load_and_merge_kdbx(&mut local, &bytes, &key)
            .expect("load and merge kdbx");

        assert_eq!(
            summary,
            MergeSummaryView {
                merged_entries: 1,
                history_snapshots_added: 1,
            }
        );
        assert_eq!(local.root.entries[0].password, "new-secret");
        assert_eq!(local.root.entries[0].history.len(), 1);
    }

    #[test]
    fn facade_moves_entry_and_group_between_parents() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Move");

        let group_a = Group::new("A");
        let group_b = Group::new("B");
        let group_b_id = group_b.id.to_string();
        vault.root.children.push(group_a);
        vault.root.children.push(group_b);

        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.children[0].entries.push(entry);

        let moved_entry = core
            .move_entry(&mut vault, &entry_id, &group_b_id)
            .expect("move entry");
        assert_eq!(moved_entry.id, entry_id);
        assert!(vault.root.children[0].entries.is_empty());
        assert_eq!(vault.root.children[1].entries.len(), 1);
        assert_eq!(vault.root.children[1].entries[0].title, "Entry");

        let mut nested = Group::new("Nested");
        let nested_id = nested.id.to_string();
        let leaf = Group::new("Leaf");
        nested.children.push(leaf);
        vault.root.children[0].children.push(nested);

        let moved_group = core
            .move_group(&mut vault, &nested_id, &group_b_id)
            .expect("move group");
        assert_eq!(moved_group.id, nested_id);
        assert!(vault.root.children[0].children.is_empty());
        assert_eq!(vault.root.children[1].children.len(), 1);
        assert_eq!(vault.root.children[1].children[0].title, "Nested");
    }

    #[test]
    fn facade_rejects_invalid_group_move_boundaries() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Move");
        let root_id = vault.root.id.to_string();
        let parent = Group::new("Parent");
        let parent_id = parent.id.to_string();
        let child = Group::new("Child");
        let child_id = child.id.to_string();
        vault.root.children.push(parent);
        vault.root.children[0].children.push(child);

        let root_error = core
            .move_group(&mut vault, &root_id, &parent_id)
            .expect_err("reject moving root");
        assert_eq!(root_error, super::MutationError::CannotMoveRootGroup);

        let descendant_error = core
            .move_group(&mut vault, &parent_id, &child_id)
            .expect_err("reject moving group into descendant");
        assert_eq!(
            descendant_error,
            super::MutationError::CannotMoveGroupIntoDescendant
        );
    }

    #[test]
    fn node_move_facade_roundtrips_moved_structure() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Move");

        let group_a = Group::new("A");
        let group_a_id = group_a.id.to_string();
        let group_b = Group::new("B");
        let group_b_id = group_b.id.to_string();
        vault.root.children.push(group_a);
        vault.root.children.push(group_b);

        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.children[0].entries.push(entry);

        let group_c = Group::new("C");
        let group_c_id = group_c.id.to_string();
        vault.root.children[0].children.push(group_c);

        core.move_entry(&mut vault, &entry_id, &group_b_id)
            .expect("move entry");
        core.move_group(&mut vault, &group_c_id, &group_b_id)
            .expect("move group");

        let mut key = CompositeKey::default();
        key.add_password("move");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save moved structure");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload moved structure");

        let loaded_group_b = find_group(&loaded.root, &group_b_id).expect("group b");
        assert_eq!(loaded_group_b.entries.len(), 1);
        assert_eq!(loaded_group_b.entries[0].id.to_string(), entry_id);
        assert_eq!(loaded_group_b.children.len(), 1);
        assert_eq!(loaded_group_b.children[0].id.to_string(), group_c_id);
        let loaded_group_a = find_group(&loaded.root, &group_a_id).expect("group a");
        assert!(loaded_group_a.entries.is_empty());
        assert!(loaded_group_a.children.is_empty());
    }

    #[test]
    fn facade_updates_entry_expiry_by_uuid() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("Expiry");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let updated = core
            .update_entry_expiry(
                &mut vault,
                &entry_id,
                EntryExpiryUpdate {
                    expires: true,
                    expiry_time: Some(1_800_000_000),
                },
            )
            .expect("update expiry");

        assert!(updated.expires);
        assert!(vault.root.entries[0].expires);
        assert_eq!(vault.root.entries[0].expiry_time, Some(1_800_000_000));
    }

    #[test]
    fn facade_sets_and_clears_entry_totp() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("Totp");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        let totp = TotpSpec::parse_otpauth(
            "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test",
        )
        .expect("totp spec");

        let updated = core
            .set_entry_totp(&mut vault, &entry_id, totp.clone())
            .expect("set totp");
        assert!(updated.has_totp);
        assert_eq!(vault.root.entries[0].totp.as_ref(), Some(&totp));

        let updated = core
            .clear_entry_totp(&mut vault, &entry_id)
            .expect("clear totp");
        assert!(!updated.has_totp);
        assert!(vault.root.entries[0].totp.is_none());
    }

    #[test]
    fn facade_sets_and_clears_entry_passkey() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("Passkey");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-1".into(),
            generated_user_id: Some("generated-user".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        };

        let updated = core
            .set_entry_passkey(&mut vault, &entry_id, passkey.clone())
            .expect("set passkey");
        assert!(updated.has_passkey);
        assert_eq!(vault.root.entries[0].passkey.as_ref(), Some(&passkey));

        let updated = core
            .clear_entry_passkey(&mut vault, &entry_id)
            .expect("clear passkey");
        assert!(!updated.has_passkey);
        assert!(vault.root.entries[0].passkey.is_none());
    }

    #[test]
    fn facade_upserts_and_deletes_entry_custom_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("CustomData");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        core.upsert_entry_custom_data(
            &mut vault,
            &entry_id,
            EntryCustomDataInput {
                key: "client".into(),
                value: "ios".into(),
            },
        )
        .expect("upsert custom data");
        assert_eq!(
            vault.root.entries[0].custom_data.get("client"),
            Some(&"ios".into())
        );

        core.delete_entry_custom_data(&mut vault, &entry_id, "client")
            .expect("delete custom data");
        assert!(!vault.root.entries[0].custom_data.contains_key("client"));
    }

    #[test]
    fn entry_custom_data_mutations_keep_canonical_bytes_across_kdbx_roundtrip() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let simple = Entry::new("Simple");
        let simple_id = simple.id.to_string();
        let detailed = Entry::new("Detailed");
        let detailed_id = detailed.id.to_string();
        let mut split = Entry::new("Split");
        let split_id = split.id.to_string();
        split.custom_data.extend([
            ("changed".into(), "old".into()),
            ("kept".into(), "value".into()),
        ]);
        split.custom_data_blocks = vec![
            vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "changed".into(),
                    value: "old".into(),
                    last_modified: Some(1),
                }],
                after: None,
            },
            vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "kept".into(),
                    value: "value".into(),
                    last_modified: Some(2),
                }],
                after: None,
            },
        ];
        vault.root.entries.extend([simple, detailed, split]);

        core.upsert_entry_custom_data(
            &mut vault,
            &simple_id,
            EntryCustomDataInput {
                key: "client".into(),
                value: "desktop".into(),
            },
        )
        .expect("upsert simple custom data");
        core.upsert_entry_custom_data_detail(
            &mut vault,
            &detailed_id,
            super::EntryCustomDataItemDetailInput {
                key: "client".into(),
                value: "desktop".into(),
                last_modified: None,
            },
        )
        .expect("upsert detailed custom data");
        core.upsert_entry_custom_data(
            &mut vault,
            &split_id,
            EntryCustomDataInput {
                key: "changed".into(),
                value: "new".into(),
            },
        )
        .expect("upsert split custom data");
        let expected = vault
            .root
            .entries
            .iter()
            .map(|entry| canonical_entry_bytes_v1(entry).expect("canonical bytes"))
            .collect::<Vec<_>>();

        let mut key = CompositeKey::default();
        key.add_password("custom-data-canonical");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save custom data");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload custom data");
        let actual = loaded
            .root
            .entries
            .iter()
            .map(|entry| canonical_entry_bytes_v1(entry).expect("loaded canonical bytes"))
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn custom_data_mutations_canonicalize_blocks_without_losing_unrelated_item_times() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Custom data");
        vault.meta_custom_data.insert("kept".into(), "meta".into());
        vault.meta_custom_data_blocks = vec![vaultkern_model::CustomDataBlock {
            items: vec![vaultkern_model::CustomDataItem {
                key: "kept".into(),
                value: "meta".into(),
                last_modified: Some(11),
            }],
            after: None,
        }];

        vault.root.custom_data.insert("kept".into(), "group".into());
        vault.root.custom_data_blocks = vec![vaultkern_model::CustomDataBlock {
            items: vec![vaultkern_model::CustomDataItem {
                key: "kept".into(),
                value: "group".into(),
                last_modified: Some(22),
            }],
            after: None,
        }];

        let mut entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        entry.custom_data.insert("kept".into(), "entry".into());
        entry.custom_data_blocks = vec![vaultkern_model::CustomDataBlock {
            items: vec![vaultkern_model::CustomDataItem {
                key: "kept".into(),
                value: "entry".into(),
                last_modified: Some(33),
            }],
            after: None,
        }];
        vault.root.entries.push(entry);

        core.upsert_vault_custom_data(
            &mut vault,
            CustomDataItemInput {
                key: "added".into(),
                value: "meta".into(),
            },
        );
        let root_id = vault.root.id.to_string();
        core.upsert_group_custom_data(
            &mut vault,
            &root_id,
            CustomDataItemInput {
                key: "added".into(),
                value: "group".into(),
            },
        )
        .expect("upsert group custom data");
        core.upsert_entry_custom_data(
            &mut vault,
            &entry_id,
            EntryCustomDataInput {
                key: "added".into(),
                value: "entry".into(),
            },
        )
        .expect("upsert entry custom data");

        let mut key = CompositeKey::default();
        key.add_password("custom-data-times");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save custom data");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload custom data");

        assert_eq!(loaded.meta_custom_data_blocks.len(), 1);
        assert_eq!(loaded.root.custom_data_blocks.len(), 1);
        assert_eq!(loaded.root.entries[0].custom_data_blocks.len(), 1);
        assert_eq!(
            loaded.meta_custom_data_blocks[0]
                .items
                .iter()
                .find(|item| item.key == "kept")
                .and_then(|item| item.last_modified),
            Some(11)
        );
        assert_eq!(
            loaded.root.custom_data_blocks[0]
                .items
                .iter()
                .find(|item| item.key == "kept")
                .and_then(|item| item.last_modified),
            Some(22)
        );
        assert_eq!(
            loaded.root.entries[0].custom_data_blocks[0]
                .items
                .iter()
                .find(|item| item.key == "kept")
                .and_then(|item| item.last_modified),
            Some(33)
        );
    }

    #[test]
    fn entry_custom_data_detail_projects_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let mut entry = Entry::new("CustomData");
        let entry_id = entry.id.to_string();
        entry.custom_data.insert("client".into(), "ios".into());
        entry
            .custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "client".into(),
                    value: "ios".into(),
                    last_modified: Some(1_700_000_008),
                }],
                after: None,
            });
        vault.root.entries.push(entry);

        assert_eq!(
            core.list_entry_custom_data_detail(&vault, &entry_id)
                .expect("list entry custom data detail"),
            vec![super::EntryCustomDataItemView {
                key: "client".into(),
                value: "ios".into(),
                last_modified: Some(1_700_000_008),
            }]
        );
    }

    #[test]
    fn entry_custom_data_detail_clears_stale_item_timestamp_after_simple_upsert() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let mut entry = Entry::new("CustomData");
        let entry_id = entry.id.to_string();
        entry.custom_data.insert("client".into(), "ios".into());
        entry
            .custom_data_blocks
            .push(vaultkern_model::CustomDataBlock {
                items: vec![vaultkern_model::CustomDataItem {
                    key: "client".into(),
                    value: "ios".into(),
                    last_modified: Some(1_700_000_008),
                }],
                after: None,
            });
        vault.root.entries.push(entry);

        core.upsert_entry_custom_data(
            &mut vault,
            &entry_id,
            super::EntryCustomDataInput {
                key: "client".into(),
                value: "android".into(),
            },
        )
        .expect("upsert entry custom data");

        assert_eq!(
            core.list_entry_custom_data_detail(&vault, &entry_id)
                .expect("list entry custom data detail"),
            vec![super::EntryCustomDataItemView {
                key: "client".into(),
                value: "android".into(),
                last_modified: None,
            }]
        );
    }

    #[test]
    fn entry_custom_data_detail_upsert_preserves_item_last_modified() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("CustomData");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let updated = core
            .upsert_entry_custom_data_detail(
                &mut vault,
                &entry_id,
                super::EntryCustomDataItemDetailInput {
                    key: "client".into(),
                    value: "ios".into(),
                    last_modified: Some(1_700_000_011),
                },
            )
            .expect("upsert entry custom data detail");

        assert_eq!(
            core.list_entry_custom_data_detail(&vault, &entry_id)
                .expect("list entry custom data detail"),
            vec![super::EntryCustomDataItemView {
                key: "client".into(),
                value: "ios".into(),
                last_modified: Some(1_700_000_011),
            }]
        );
        assert_eq!(updated.history_count, 0);
    }

    #[test]
    fn advanced_entry_semantic_mutation_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Semantic");
        let entry = Entry::new("Semantic");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let totp = TotpSpec::parse_otpauth(
            "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test",
        )
        .expect("totp spec");
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-1".into(),
            generated_user_id: Some("generated-user".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        };

        core.update_entry_expiry(
            &mut vault,
            &entry_id,
            EntryExpiryUpdate {
                expires: true,
                expiry_time: Some(1_800_000_000),
            },
        )
        .expect("update expiry");
        core.set_entry_totp(&mut vault, &entry_id, totp.clone())
            .expect("set totp");
        core.set_entry_passkey(&mut vault, &entry_id, passkey.clone())
            .expect("set passkey");
        core.upsert_entry_custom_data(
            &mut vault,
            &entry_id,
            EntryCustomDataInput {
                key: "client".into(),
                value: "ios".into(),
            },
        )
        .expect("upsert custom data");

        let mut key = CompositeKey::default();
        key.add_password("semantic");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save semantic fields");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload semantic fields");

        let loaded_entry = loaded
            .root
            .entries
            .iter()
            .find(|entry| entry.id.to_string() == entry_id)
            .expect("loaded entry");
        assert!(loaded_entry.expires);
        assert_eq!(loaded_entry.expiry_time, Some(1_800_000_000));
        assert_eq!(loaded_entry.totp.as_ref(), Some(&totp));
        assert_eq!(loaded_entry.passkey.as_ref(), Some(&passkey));
        assert_eq!(loaded_entry.custom_data.get("client"), Some(&"ios".into()));
    }

    #[test]
    fn facade_snapshots_entry_to_history_and_lists_summaries() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        entry.username = "alice".into();
        entry.modified_at = 123;
        entry.attachments.insert(
            "note.txt".into(),
            Attachment {
                name: "note.txt".into(),
                data: b"hello".to_vec(),
                protect_in_memory: false,
            },
        );
        entry.attributes.insert(
            "custom".into(),
            CustomField {
                value: "value".into(),
                protected: false,
            },
        );
        vault.root.entries.push(entry);

        let updated = core
            .snapshot_entry_to_history(&mut vault, &entry_id)
            .expect("snapshot entry");
        let history = core
            .list_entry_history(&vault, &entry_id)
            .expect("list history");

        assert_eq!(updated.history_count, 1);
        assert_eq!(vault.root.entries[0].history.len(), 1);
        assert!(vault.root.entries[0].history[0].history.is_empty());
        assert_eq!(
            history,
            vec![EntryHistoryItemView {
                title: "Current".into(),
                username: "alice".into(),
                modified_at: 123,
                attachment_count: 1,
                custom_field_count: 1,
            }]
        );
    }

    #[test]
    fn facade_clears_entry_history() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.title = "Older".into();
        snapshot.history.clear();
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let updated = core
            .clear_entry_history(&mut vault, &entry_id)
            .expect("clear history");

        assert_eq!(updated.history_count, 0);
        assert!(vault.root.entries[0].history.is_empty());
    }

    #[test]
    fn entry_history_mutation_roundtrips_snapshots() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        entry.username = "alice".into();
        entry.modified_at = 123;
        vault.root.entries.push(entry);

        core.snapshot_entry_to_history(&mut vault, &entry_id)
            .expect("snapshot entry");

        let mut key = CompositeKey::default();
        key.add_password("history-facade");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history facade");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload history facade");
        let history = core
            .list_entry_history(&loaded, &entry_id)
            .expect("list reloaded history");

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].title, "Current");
        assert_eq!(history[0].username, "alice");
        assert_eq!(history[0].modified_at, 123);
    }

    #[test]
    fn facade_projects_entry_history_detail() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(1);
        let mut snapshot = entry.clone();
        snapshot.title = "Older".into();
        snapshot.icon_id = Some(9);
        snapshot.custom_icon_id = Some(custom_icon_id);
        snapshot.username = "alice".into();
        snapshot.password = "secret".into();
        snapshot.url = "https://example.com".into();
        snapshot.notes = "history notes".into();
        snapshot.tags.insert("prod".into());
        snapshot.history.clear();
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let detail = core
            .project_entry_history_detail(&vault, &entry_id, 0)
            .expect("project history detail");

        assert_eq!(detail.title, "Older");
        assert_eq!(detail.username, "alice");
        assert_eq!(detail.password, "secret");
        assert_eq!(detail.url, "https://example.com");
        assert_eq!(detail.notes, "history notes");
        assert_eq!(detail.icon_id, Some(9));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["prod".to_string()]);
    }

    #[test]
    fn entry_history_detail_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(1);
        let mut snapshot = entry.clone();
        snapshot.title = "Older".into();
        snapshot.icon_id = Some(9);
        snapshot.custom_icon_id = Some(custom_icon_id);
        snapshot.username = "alice".into();
        snapshot.password = "secret".into();
        snapshot.url = "https://example.com".into();
        snapshot.notes = "history notes".into();
        snapshot.tags.insert("prod".into());
        snapshot.history.clear();
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-detail");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history detail");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload history detail");
        let detail = core
            .project_entry_history_detail(&loaded, &entry_id, 0)
            .expect("project history detail");

        assert_eq!(detail.title, "Older");
        assert_eq!(detail.username, "alice");
        assert_eq!(detail.password, "secret");
        assert_eq!(detail.url, "https://example.com");
        assert_eq!(detail.notes, "history notes");
        assert_eq!(detail.icon_id, Some(9));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["prod".to_string()]);
    }

    #[test]
    fn facade_projects_entry_history_attachment_content() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.attachments.insert(
            "note.txt".into(),
            Attachment {
                name: "note.txt".into(),
                data: b"hello-history".to_vec(),
                protect_in_memory: true,
            },
        );
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let attachments = core
            .list_entry_history_attachments(&vault, &entry_id, 0)
            .expect("list history attachments");
        let content = core
            .project_entry_history_attachment_content(&vault, &entry_id, 0, "note.txt")
            .expect("project history attachment content");

        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "note.txt".into(),
                size: 13,
                protect_in_memory: true,
            }]
        );
        assert_eq!(content.name, "note.txt");
        assert_eq!(content.data, b"hello-history".to_vec());
    }

    #[test]
    fn entry_history_attachment_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.attachments.insert(
            "note.txt".into(),
            Attachment {
                name: "note.txt".into(),
                data: b"hello-history".to_vec(),
                protect_in_memory: true,
            },
        );
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-attachment");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history attachment");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload history attachment");
        let attachments = core
            .list_entry_history_attachments(&loaded, &entry_id, 0)
            .expect("list history attachments");
        let content = core
            .project_entry_history_attachment_content(&loaded, &entry_id, 0, "note.txt")
            .expect("project history attachment content");

        assert_eq!(
            attachments,
            vec![AttachmentView {
                name: "note.txt".into(),
                size: 13,
                protect_in_memory: true,
            }]
        );
        assert_eq!(content.name, "note.txt");
        assert_eq!(content.data, b"hello-history".to_vec());
    }

    #[test]
    fn facade_projects_entry_history_semantic_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistorySemantic");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.attributes.insert(
            "Secret".into(),
            vaultkern_model::CustomField {
                value: "history-secret".into(),
                protected: true,
            },
        );
        snapshot.custom_data.insert("color".into(), "amber".into());
        snapshot.totp = Some(TotpSpec {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("HistoryIssuer".into()),
            account_name: Some("HistoryAccount".into()),
        });
        snapshot.passkey = Some(PasskeyRecord {
            username: "history-user".into(),
            credential_id: "history-credential".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let totp = core
            .project_entry_history_totp(&vault, &entry_id, 0)
            .expect("project history totp");
        let passkey = core
            .project_entry_history_passkey(&vault, &entry_id, 0)
            .expect("project history passkey");
        let custom_fields = core
            .list_entry_history_custom_fields(&vault, &entry_id, 0)
            .expect("list history custom fields");
        let custom_data = core
            .list_entry_history_custom_data(&vault, &entry_id, 0)
            .expect("list history custom data");

        assert_eq!(
            totp.as_ref().and_then(|value| value.issuer.as_deref()),
            Some("HistoryIssuer")
        );
        assert_eq!(
            passkey.as_ref().map(|value| value.credential_id.as_str()),
            Some("history-credential")
        );
        assert_eq!(custom_fields.len(), 1);
        assert_eq!(custom_fields[0].key, "Secret");
        assert_eq!(custom_fields[0].value, "history-secret");
        assert!(custom_fields[0].protected);
        assert_eq!(
            custom_data,
            vec![super::CustomDataItemView {
                key: "color".into(),
                value: "amber".into(),
            }]
        );
    }

    #[test]
    fn entry_history_semantic_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistorySemantic");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.attributes.insert(
            "Secret".into(),
            vaultkern_model::CustomField {
                value: "history-secret".into(),
                protected: true,
            },
        );
        snapshot.custom_data.insert("color".into(), "amber".into());
        snapshot.totp = Some(TotpSpec {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("HistoryIssuer".into()),
            account_name: Some("HistoryAccount".into()),
        });
        snapshot.passkey = Some(PasskeyRecord {
            username: "history-user".into(),
            credential_id: "history-credential".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-semantic");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history semantic");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload history semantic");

        let totp = core
            .project_entry_history_totp(&loaded, &entry_id, 0)
            .expect("project history totp");
        let passkey = core
            .project_entry_history_passkey(&loaded, &entry_id, 0)
            .expect("project history passkey");
        let custom_fields = core
            .list_entry_history_custom_fields(&loaded, &entry_id, 0)
            .expect("list history custom fields");
        let custom_data = core
            .list_entry_history_custom_data(&loaded, &entry_id, 0)
            .expect("list history custom data");

        assert_eq!(
            totp.as_ref().and_then(|value| value.issuer.as_deref()),
            Some("HistoryIssuer")
        );
        assert_eq!(
            passkey.as_ref().map(|value| value.credential_id.as_str()),
            Some("history-credential")
        );
        assert_eq!(custom_fields.len(), 1);
        assert_eq!(custom_fields[0].key, "Secret");
        assert_eq!(custom_fields[0].value, "history-secret");
        assert!(custom_fields[0].protected);
        assert_eq!(
            custom_data,
            vec![super::CustomDataItemView {
                key: "color".into(),
                value: "amber".into(),
            }]
        );
    }

    #[test]
    fn facade_projects_entry_history_presentation_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistoryPresentation");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.icon_id = Some(7);
        snapshot.custom_icon_id = Some(uuid::Uuid::nil());
        snapshot.foreground_color = Some("#112233".into());
        snapshot.background_color = Some("#445566".into());
        snapshot.override_url = Some("cmd://history".into());
        snapshot.field_protection = EntryFieldProtection {
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: true,
            protect_notes: false,
        };
        snapshot.auto_type = Some(AutoTypeConfig {
            enabled: Some(true),
            obfuscation: Some(1),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
            associations: vec![AutoTypeAssociation {
                window: "HistoryWindow".into(),
                sequence: "{PASSWORD}".into(),
            }],
        });
        snapshot.created_at = 10;
        snapshot.modified_at = 11;
        snapshot.last_accessed_at = Some(12);
        snapshot.usage_count = Some(13);
        snapshot.location_changed_at = Some(14);
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let metadata = core
            .project_entry_history_presentation_metadata(&vault, &entry_id, 0)
            .expect("project history presentation metadata");
        let protection = core
            .project_entry_history_field_protection(&vault, &entry_id, 0)
            .expect("project history field protection");
        let auto_type = core
            .project_entry_history_auto_type(&vault, &entry_id, 0)
            .expect("project history auto type");
        let times = core
            .project_entry_history_times(&vault, &entry_id, 0)
            .expect("project history times");

        assert_eq!(metadata.icon_id, Some(7));
        assert_eq!(metadata.foreground_color.as_deref(), Some("#112233"));
        assert_eq!(metadata.background_color.as_deref(), Some("#445566"));
        assert_eq!(metadata.override_url.as_deref(), Some("cmd://history"));
        assert_eq!(
            protection,
            EntryFieldProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: true,
                protect_notes: false,
            }
        );
        assert_eq!(auto_type.enabled, Some(true));
        assert_eq!(auto_type.obfuscation, Some(1));
        assert_eq!(
            auto_type.default_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
        );
        assert_eq!(
            auto_type.associations,
            vec![EntryAutoTypeAssociationView {
                window: "HistoryWindow".into(),
                sequence: "{PASSWORD}".into(),
            }]
        );
        assert_eq!(times.created_at, 10);
        assert_eq!(times.modified_at, 11);
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, Some(14));
    }

    #[test]
    fn entry_history_presentation_metadata_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistoryPresentation");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.icon_id = Some(7);
        snapshot.custom_icon_id = Some(uuid::Uuid::nil());
        snapshot.foreground_color = Some("#112233".into());
        snapshot.background_color = Some("#445566".into());
        snapshot.override_url = Some("cmd://history".into());
        snapshot.field_protection = EntryFieldProtection {
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: true,
            protect_notes: false,
        };
        snapshot.auto_type = Some(AutoTypeConfig {
            enabled: Some(true),
            obfuscation: Some(1),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
            associations: vec![AutoTypeAssociation {
                window: "HistoryWindow".into(),
                sequence: "{PASSWORD}".into(),
            }],
        });
        snapshot.created_at = 10;
        snapshot.modified_at = 11;
        snapshot.last_accessed_at = Some(12);
        snapshot.usage_count = Some(13);
        snapshot.location_changed_at = Some(14);
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-presentation");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history presentation");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload history presentation");

        let metadata = core
            .project_entry_history_presentation_metadata(&loaded, &entry_id, 0)
            .expect("project history presentation metadata");
        let protection = core
            .project_entry_history_field_protection(&loaded, &entry_id, 0)
            .expect("project history field protection");
        let auto_type = core
            .project_entry_history_auto_type(&loaded, &entry_id, 0)
            .expect("project history auto type");
        let times = core
            .project_entry_history_times(&loaded, &entry_id, 0)
            .expect("project history times");

        assert_eq!(metadata.icon_id, Some(7));
        assert_eq!(metadata.foreground_color.as_deref(), Some("#112233"));
        assert_eq!(metadata.background_color.as_deref(), Some("#445566"));
        assert_eq!(metadata.override_url.as_deref(), Some("cmd://history"));
        assert_eq!(
            protection,
            EntryFieldProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: true,
                protect_notes: false,
            }
        );
        assert_eq!(auto_type.enabled, Some(true));
        assert_eq!(auto_type.obfuscation, Some(1));
        assert_eq!(
            auto_type.default_sequence.as_deref(),
            Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
        );
        assert_eq!(
            auto_type.associations,
            vec![EntryAutoTypeAssociationView {
                window: "HistoryWindow".into(),
                sequence: "{PASSWORD}".into(),
            }]
        );
        assert_eq!(times.created_at, 10);
        assert_eq!(times.modified_at, 11);
        assert_eq!(times.last_accessed_at, Some(12));
        assert_eq!(times.usage_count, Some(13));
        assert_eq!(times.location_changed_at, Some(14));
    }

    #[test]
    fn facade_projects_entry_history_lineage_report_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistoryLineage");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let previous_parent_id = uuid::Uuid::nil();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.previous_parent = Some(previous_parent_id);
        snapshot.exclude_from_reports = true;
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let metadata = core
            .project_entry_history_lineage_report_metadata(&vault, &entry_id, 0)
            .expect("project history lineage/report metadata");

        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(previous_parent_id.to_string().as_str())
        );
        assert!(metadata.exclude_from_reports);
    }

    #[test]
    fn entry_history_lineage_report_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("HistoryLineage");
        let mut entry = Entry::new("Current");
        let entry_id = entry.id.to_string();
        let previous_parent_id = uuid::Uuid::nil();
        let mut snapshot = entry.clone();
        snapshot.history.clear();
        snapshot.previous_parent = Some(previous_parent_id);
        snapshot.exclude_from_reports = true;
        entry.history.push(snapshot);
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("history-lineage");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history lineage");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload history lineage");

        let metadata = core
            .project_entry_history_lineage_report_metadata(&loaded, &entry_id, 0)
            .expect("project history lineage/report metadata");

        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(previous_parent_id.to_string().as_str())
        );
        assert!(metadata.exclude_from_reports);
    }

    #[test]
    fn facade_updates_vault_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        let metadata = core.update_vault_metadata(
            &mut vault,
            VaultMetadataUpdate {
                description: Some("Description".into()),
                default_username: Some("default-user".into()),
                color: Some("#123456".into()),
                history_max_items: Some(42),
                history_max_size: Some(9_999),
                memory_protection: Some(MemoryProtection {
                    protect_title: true,
                    protect_username: false,
                    protect_password: true,
                    protect_url: false,
                    protect_notes: true,
                }),
            },
        );

        assert_eq!(metadata.description.as_deref(), Some("Description"));
        assert_eq!(metadata.default_username.as_deref(), Some("default-user"));
        assert_eq!(metadata.color.as_deref(), Some("#123456"));
        assert_eq!(metadata.history_max_items, Some(42));
        assert_eq!(metadata.history_max_size, Some(9_999));
        assert_eq!(
            metadata.memory_protection,
            Some(MemoryProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: true,
            })
        );
        assert_eq!(vault.description.as_deref(), Some("Description"));
        assert_eq!(vault.default_username.as_deref(), Some("default-user"));
        assert_eq!(vault.color.as_deref(), Some("#123456"));
    }

    #[test]
    fn vault_metadata_mutation_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        core.update_vault_metadata(
            &mut vault,
            VaultMetadataUpdate {
                description: Some("Description".into()),
                default_username: Some("default-user".into()),
                color: Some("#123456".into()),
                history_max_items: Some(42),
                history_max_size: Some(9_999),
                memory_protection: Some(MemoryProtection {
                    protect_title: true,
                    protect_username: false,
                    protect_password: true,
                    protect_url: false,
                    protect_notes: true,
                }),
            },
        );

        let mut key = CompositeKey::default();
        key.add_password("vault-meta");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save vault metadata");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload vault metadata");
        let metadata = core.project_vault_metadata(&loaded);

        assert_eq!(metadata.description.as_deref(), Some("Description"));
        assert_eq!(metadata.default_username.as_deref(), Some("default-user"));
        assert_eq!(metadata.color.as_deref(), Some("#123456"));
        assert_eq!(metadata.history_max_items, Some(42));
        assert_eq!(metadata.history_max_size, Some(9_999));
        assert_eq!(
            metadata.memory_protection,
            Some(MemoryProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: true,
            })
        );
    }

    #[test]
    fn facade_updates_vault_selection_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");
        let selected_group = Group::new("Selected");
        let selected_group_id = selected_group.id.to_string();
        let top_group = Group::new("Top");
        let top_group_id = top_group.id.to_string();
        vault.root.children.push(selected_group);
        vault.root.children.push(top_group);

        let selection = core
            .update_vault_selection_metadata(
                &mut vault,
                VaultSelectionMetadataUpdate {
                    last_selected_group_id: Some(Some(selected_group_id.clone())),
                    last_top_visible_group_id: Some(Some(top_group_id.clone())),
                },
            )
            .expect("update vault selection metadata");

        assert_eq!(
            selection.last_selected_group_id.as_deref(),
            Some(selected_group_id.as_str())
        );
        assert_eq!(
            selection.last_top_visible_group_id.as_deref(),
            Some(top_group_id.as_str())
        );
        assert_eq!(
            vault
                .last_selected_group
                .map(|id| id.to_string())
                .as_deref(),
            Some(selected_group_id.as_str())
        );
        assert_eq!(
            vault
                .last_top_visible_group
                .map(|id| id.to_string())
                .as_deref(),
            Some(top_group_id.as_str())
        );
    }

    #[test]
    fn vault_selection_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");
        let selected_group = Group::new("Selected");
        let selected_group_id = selected_group.id.to_string();
        let top_group = Group::new("Top");
        let top_group_id = top_group.id.to_string();
        vault.root.children.push(selected_group);
        vault.root.children.push(top_group);

        core.update_vault_selection_metadata(
            &mut vault,
            VaultSelectionMetadataUpdate {
                last_selected_group_id: Some(Some(selected_group_id.clone())),
                last_top_visible_group_id: Some(Some(top_group_id.clone())),
            },
        )
        .expect("update vault selection metadata");

        let mut key = CompositeKey::default();
        key.add_password("vault-selection");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save vault selection metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload vault selection metadata");
        let selection = core.project_vault_selection_metadata(&loaded);

        assert_eq!(
            selection.last_selected_group_id.as_deref(),
            Some(selected_group_id.as_str())
        );
        assert_eq!(
            selection.last_top_visible_group_id.as_deref(),
            Some(top_group_id.as_str())
        );
    }

    #[test]
    fn facade_updates_vault_lifecycle_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        let lifecycle = core.update_vault_lifecycle_metadata(
            &mut vault,
            VaultLifecycleMetadataUpdate {
                settings_changed: Some(1_700_000_000),
                maintenance_history_days: Some(30),
                master_key_changed: Some(1_700_000_004),
                master_key_change_rec: Some(90),
                master_key_change_force: Some(180),
                master_key_change_force_once: Some(true),
            },
        );

        assert_eq!(lifecycle.settings_changed, Some(1_700_000_000));
        assert_eq!(lifecycle.maintenance_history_days, Some(30));
        assert_eq!(lifecycle.master_key_changed, Some(1_700_000_004));
        assert_eq!(lifecycle.master_key_change_rec, Some(90));
        assert_eq!(lifecycle.master_key_change_force, Some(180));
        assert_eq!(lifecycle.master_key_change_force_once, Some(true));
        assert_eq!(vault.settings_changed, Some(1_700_000_000));
        assert_eq!(vault.maintenance_history_days, Some(30));
        assert_eq!(vault.master_key_changed, Some(1_700_000_004));
        assert_eq!(vault.master_key_change_rec, Some(90));
        assert_eq!(vault.master_key_change_force, Some(180));
        assert_eq!(vault.master_key_change_force_once, Some(true));
    }

    #[test]
    fn vault_lifecycle_metadata_projection_exposes_settings_changed_and_force_once() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");
        vault.settings_changed = Some(1_700_000_000);
        vault.master_key_change_force_once = Some(true);

        let lifecycle = core.project_vault_lifecycle_metadata(&vault);

        assert_eq!(lifecycle.settings_changed, Some(1_700_000_000));
        assert_eq!(lifecycle.master_key_change_force_once, Some(true));
    }

    #[test]
    fn vault_lifecycle_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        core.update_vault_lifecycle_metadata(
            &mut vault,
            VaultLifecycleMetadataUpdate {
                settings_changed: Some(1_700_000_000),
                maintenance_history_days: Some(30),
                master_key_changed: Some(1_700_000_004),
                master_key_change_rec: Some(90),
                master_key_change_force: Some(180),
                master_key_change_force_once: Some(true),
            },
        );

        let mut key = CompositeKey::default();
        key.add_password("vault-lifecycle");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save vault lifecycle metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload vault lifecycle metadata");
        let lifecycle = core.project_vault_lifecycle_metadata(&loaded);

        assert_eq!(lifecycle.settings_changed, Some(1_700_000_000));
        assert_eq!(lifecycle.maintenance_history_days, Some(30));
        assert_eq!(lifecycle.master_key_changed, Some(1_700_000_004));
        assert_eq!(lifecycle.master_key_change_rec, Some(90));
        assert_eq!(lifecycle.master_key_change_force, Some(180));
        assert_eq!(lifecycle.master_key_change_force_once, Some(true));
    }

    #[test]
    fn facade_updates_vault_bin_template_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");
        let recycle_bin = Group::new("Recycle");
        let recycle_bin_id = recycle_bin.id.to_string();
        let templates = Group::new("Templates");
        let templates_id = templates.id.to_string();
        vault.root.children.push(recycle_bin);
        vault.root.children.push(templates);

        let metadata = core
            .update_vault_bin_template_metadata(
                &mut vault,
                VaultBinTemplateMetadataUpdate {
                    recycle_bin_enabled: Some(Some(true)),
                    recycle_bin_group_id: Some(Some(recycle_bin_id.clone())),
                    recycle_bin_changed: Some(Some(1_282_752_777)),
                    entry_templates_group_id: Some(Some(templates_id.clone())),
                    entry_templates_group_changed: Some(Some(1_281_226_259)),
                },
            )
            .expect("update vault bin/template metadata");

        assert_eq!(metadata.recycle_bin_enabled, Some(true));
        assert_eq!(
            metadata.recycle_bin_group_id.as_deref(),
            Some(recycle_bin_id.as_str())
        );
        assert_eq!(metadata.recycle_bin_changed, Some(1_282_752_777));
        assert_eq!(
            metadata.entry_templates_group_id.as_deref(),
            Some(templates_id.as_str())
        );
        assert_eq!(metadata.entry_templates_group_changed, Some(1_281_226_259));
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert_eq!(
            vault.recycle_bin_group.map(|id| id.to_string()).as_deref(),
            Some(recycle_bin_id.as_str())
        );
        assert_eq!(vault.recycle_bin_changed, Some(1_282_752_777));
        assert_eq!(
            vault
                .entry_templates_group
                .map(|id| id.to_string())
                .as_deref(),
            Some(templates_id.as_str())
        );
        assert_eq!(vault.entry_templates_group_changed, Some(1_281_226_259));
    }

    #[test]
    fn vault_bin_template_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");
        let recycle_bin = Group::new("Recycle");
        let recycle_bin_id = recycle_bin.id.to_string();
        let templates = Group::new("Templates");
        let templates_id = templates.id.to_string();
        vault.root.children.push(recycle_bin);
        vault.root.children.push(templates);

        core.update_vault_bin_template_metadata(
            &mut vault,
            VaultBinTemplateMetadataUpdate {
                recycle_bin_enabled: Some(Some(true)),
                recycle_bin_group_id: Some(Some(recycle_bin_id.clone())),
                recycle_bin_changed: Some(Some(1_282_752_777)),
                entry_templates_group_id: Some(Some(templates_id.clone())),
                entry_templates_group_changed: Some(Some(1_281_226_259)),
            },
        )
        .expect("update vault bin/template metadata");

        let mut key = CompositeKey::default();
        key.add_password("vault-bin-template");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save vault bin/template metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload vault bin/template metadata");
        let metadata = core.project_vault_bin_template_metadata(&loaded);

        assert_eq!(metadata.recycle_bin_enabled, Some(true));
        assert_eq!(
            metadata.recycle_bin_group_id.as_deref(),
            Some(recycle_bin_id.as_str())
        );
        assert_eq!(metadata.recycle_bin_changed, Some(1_282_752_777));
        assert_eq!(
            metadata.entry_templates_group_id.as_deref(),
            Some(templates_id.as_str())
        );
        assert_eq!(metadata.entry_templates_group_changed, Some(1_281_226_259));
    }

    #[test]
    fn facade_updates_vault_identity_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        let identity = core.update_vault_identity_metadata(
            &mut vault,
            VaultIdentityMetadataUpdate {
                name: Some("Renamed".into()),
                generator: Some("Codex".into()),
                database_name_changed: Some(1_700_000_001),
                description_changed: Some(1_700_000_002),
                default_username_changed: Some(1_700_000_003),
            },
        );

        assert_eq!(identity.name, "Renamed");
        assert_eq!(identity.generator.as_deref(), Some("Codex"));
        assert_eq!(identity.database_name_changed, Some(1_700_000_001));
        assert_eq!(identity.description_changed, Some(1_700_000_002));
        assert_eq!(identity.default_username_changed, Some(1_700_000_003));
        assert_eq!(vault.name, "Renamed");
        assert_eq!(vault.generator.as_deref(), Some("Codex"));
        assert_eq!(vault.database_name_changed, Some(1_700_000_001));
        assert_eq!(vault.description_changed, Some(1_700_000_002));
        assert_eq!(vault.default_username_changed, Some(1_700_000_003));
    }

    #[test]
    fn vault_identity_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("VaultMeta");

        core.update_vault_identity_metadata(
            &mut vault,
            VaultIdentityMetadataUpdate {
                name: Some("Renamed".into()),
                generator: Some("Codex".into()),
                database_name_changed: Some(1_700_000_001),
                description_changed: Some(1_700_000_002),
                default_username_changed: Some(1_700_000_003),
            },
        );

        let mut key = CompositeKey::default();
        key.add_password("vault-identity");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save vault identity metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload vault identity metadata");
        let identity = core.project_vault_identity_metadata(&loaded);

        assert_eq!(identity.name, "Renamed");
        assert_eq!(identity.generator.as_deref(), Some("Codex"));
        assert_eq!(identity.database_name_changed, Some(1_700_000_001));
        assert_eq!(identity.description_changed, Some(1_700_000_002));
        assert_eq!(identity.default_username_changed, Some(1_700_000_003));
    }

    #[test]
    fn facade_updates_entry_lineage_report_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryMeta");
        let group = Group::new("Original");
        let parent_group_id = group.id.to_string();
        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.children.push(group);
        vault.root.entries.push(entry);

        let metadata = core
            .update_entry_lineage_report_metadata(
                &mut vault,
                &entry_id,
                super::EntryLineageReportMetadataUpdate {
                    previous_parent_id: Some(Some(parent_group_id.clone())),
                    exclude_from_reports: Some(true),
                },
            )
            .expect("update entry lineage/report metadata");

        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(parent_group_id.as_str())
        );
        assert!(metadata.exclude_from_reports);
        assert_eq!(
            vault.root.entries[0]
                .previous_parent
                .map(|id| id.to_string())
                .as_deref(),
            Some(parent_group_id.as_str())
        );
        assert!(vault.root.entries[0].exclude_from_reports);
    }

    #[test]
    fn entry_lineage_report_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryMeta");
        let group = Group::new("Original");
        let parent_group_id = group.id.to_string();
        let entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        vault.root.children.push(group);
        vault.root.entries.push(entry);

        core.update_entry_lineage_report_metadata(
            &mut vault,
            &entry_id,
            super::EntryLineageReportMetadataUpdate {
                previous_parent_id: Some(Some(parent_group_id.clone())),
                exclude_from_reports: Some(true),
            },
        )
        .expect("update entry lineage/report metadata");

        let mut key = CompositeKey::default();
        key.add_password("entry-lineage-report");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save entry lineage/report metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload entry lineage/report metadata");
        let metadata = core
            .project_entry_lineage_report_metadata(&loaded, &entry_id)
            .expect("project entry lineage/report metadata");

        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(parent_group_id.as_str())
        );
        assert!(metadata.exclude_from_reports);
    }

    #[test]
    fn facade_updates_group_lineage_tag_metadata() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("GroupMeta");
        let previous_parent = Group::new("Previous");
        let previous_parent_id = previous_parent.id.to_string();
        let group = Group::new("EntryGroup");
        let group_id = group.id.to_string();
        vault.root.children.push(previous_parent);
        vault.root.children.push(group);

        let metadata = core
            .update_group_lineage_tag_metadata(
                &mut vault,
                &group_id,
                super::GroupLineageTagMetadataUpdate {
                    tags: Some(vec!["beta".into(), "alpha".into()]),
                    previous_parent_id: Some(Some(previous_parent_id.clone())),
                },
            )
            .expect("update group lineage/tag metadata");

        assert_eq!(metadata.tags, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(previous_parent_id.as_str())
        );
        assert_eq!(
            vault.root.children[1]
                .previous_parent
                .map(|id| id.to_string())
                .as_deref(),
            Some(previous_parent_id.as_str())
        );
        assert_eq!(
            vault.root.children[1]
                .tags
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn group_lineage_tag_metadata_facade_roundtrips_updated_fields() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("GroupMeta");
        let previous_parent = Group::new("Previous");
        let previous_parent_id = previous_parent.id.to_string();
        let group = Group::new("EntryGroup");
        let group_id = group.id.to_string();
        vault.root.children.push(previous_parent);
        vault.root.children.push(group);

        core.update_group_lineage_tag_metadata(
            &mut vault,
            &group_id,
            super::GroupLineageTagMetadataUpdate {
                tags: Some(vec!["beta".into(), "alpha".into()]),
                previous_parent_id: Some(Some(previous_parent_id.clone())),
            },
        )
        .expect("update group lineage/tag metadata");

        let mut key = CompositeKey::default();
        key.add_password("group-lineage-tag");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save group lineage/tag metadata");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload group lineage/tag metadata");
        let metadata = core
            .project_group_lineage_tag_metadata(&loaded, &group_id)
            .expect("project group lineage/tag metadata");

        assert_eq!(metadata.tags, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(
            metadata.previous_parent_id.as_deref(),
            Some(previous_parent_id.as_str())
        );
    }

    #[test]
    fn facade_projects_entry_semantic_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntrySemantic");
        let mut entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        entry.attributes.insert(
            "Secret".into(),
            vaultkern_model::CustomField {
                value: "s3cr3t".into(),
                protected: true,
            },
        );
        entry.custom_data.insert("color".into(), "blue".into());
        entry.totp = Some(TotpSpec {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("Issuer".into()),
            account_name: Some("Account".into()),
        });
        entry.passkey = Some(PasskeyRecord {
            username: "passkey-user".into(),
            credential_id: "credential-id".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        vault.root.entries.push(entry);

        let totp = core
            .project_entry_totp(&vault, &entry_id)
            .expect("project totp");
        let passkey = core
            .project_entry_passkey(&vault, &entry_id)
            .expect("project passkey");
        let custom_fields = core
            .list_entry_custom_fields(&vault, &entry_id)
            .expect("list custom fields");
        let custom_data = core
            .list_entry_custom_data(&vault, &entry_id)
            .expect("list custom data");

        assert_eq!(
            totp.as_ref().and_then(|value| value.issuer.as_deref()),
            Some("Issuer")
        );
        assert_eq!(
            passkey.as_ref().map(|value| value.credential_id.as_str()),
            Some("credential-id")
        );
        assert_eq!(custom_fields.len(), 1);
        assert_eq!(custom_fields[0].key, "Secret");
        assert_eq!(custom_fields[0].value, "s3cr3t");
        assert!(custom_fields[0].protected);
        assert_eq!(
            custom_data,
            vec![super::CustomDataItemView {
                key: "color".into(),
                value: "blue".into(),
            }]
        );
    }

    #[test]
    fn entry_semantic_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntrySemantic");
        let mut entry = Entry::new("Entry");
        let entry_id = entry.id.to_string();
        entry.attributes.insert(
            "Secret".into(),
            vaultkern_model::CustomField {
                value: "s3cr3t".into(),
                protected: true,
            },
        );
        entry.custom_data.insert("color".into(), "blue".into());
        entry.totp = Some(TotpSpec {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            issuer: Some("Issuer".into()),
            account_name: Some("Account".into()),
        });
        entry.passkey = Some(PasskeyRecord {
            username: "passkey-user".into(),
            credential_id: "credential-id".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "pem".into(),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("entry-semantic");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save entry semantic");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload entry semantic");

        let totp = core
            .project_entry_totp(&loaded, &entry_id)
            .expect("project totp");
        let passkey = core
            .project_entry_passkey(&loaded, &entry_id)
            .expect("project passkey");
        let custom_fields = core
            .list_entry_custom_fields(&loaded, &entry_id)
            .expect("list custom fields");
        let custom_data = core
            .list_entry_custom_data(&loaded, &entry_id)
            .expect("list custom data");

        assert_eq!(
            totp.as_ref().and_then(|value| value.issuer.as_deref()),
            Some("Issuer")
        );
        assert_eq!(
            passkey.as_ref().map(|value| value.credential_id.as_str()),
            Some("credential-id")
        );
        assert_eq!(custom_fields.len(), 1);
        assert_eq!(custom_fields[0].key, "Secret");
        assert_eq!(custom_fields[0].value, "s3cr3t");
        assert!(custom_fields[0].protected);
        assert_eq!(
            custom_data,
            vec![super::CustomDataItemView {
                key: "color".into(),
                value: "blue".into(),
            }]
        );
    }

    #[test]
    fn facade_projects_entry_detail() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryDetail");
        let mut entry = Entry::new("Example");
        let entry_id = entry.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(1);
        entry.icon_id = Some(42);
        entry.custom_icon_id = Some(custom_icon_id);
        entry.username = "alice".into();
        entry.password = "secret".into();
        entry.url = "https://example.com/login".into();
        entry.notes = "note".into();
        entry.tags.insert("prod".into());
        entry.tags.insert("team".into());
        vault.root.entries.push(entry);

        let detail = core
            .project_entry_detail(&vault, &entry_id)
            .expect("project entry detail");

        assert_eq!(detail.id, entry_id);
        assert_eq!(detail.title, "Example");
        assert_eq!(detail.username, "alice");
        assert_eq!(detail.password, "secret");
        assert_eq!(detail.url, "https://example.com/login");
        assert_eq!(detail.notes, "note");
        assert_eq!(detail.icon_id, Some(42));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["prod".to_string(), "team".to_string()]);
    }

    #[test]
    fn entry_detail_projection_facade_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("EntryDetail");
        let mut entry = Entry::new("Example");
        let entry_id = entry.id.to_string();
        let custom_icon_id = uuid::Uuid::from_u128(1);
        entry.icon_id = Some(42);
        entry.custom_icon_id = Some(custom_icon_id);
        entry.username = "alice".into();
        entry.password = "secret".into();
        entry.url = "https://example.com/login".into();
        entry.notes = "note".into();
        entry.tags.insert("prod".into());
        entry.tags.insert("team".into());
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("entry-detail");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save entry detail");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload entry detail");
        let detail = core
            .project_entry_detail(&loaded, &entry_id)
            .expect("project entry detail");

        assert_eq!(detail.id, entry_id);
        assert_eq!(detail.title, "Example");
        assert_eq!(detail.username, "alice");
        assert_eq!(detail.password, "secret");
        assert_eq!(detail.url, "https://example.com/login");
        assert_eq!(detail.notes, "note");
        assert_eq!(detail.icon_id, Some(42));
        assert_eq!(
            detail.custom_icon_id.as_deref(),
            Some(custom_icon_id.to_string().as_str())
        );
        assert_eq!(detail.tags, vec!["prod".to_string(), "team".to_string()]);
    }

    #[test]
    fn facade_updates_entry_field_protection() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Protection");
        let entry = Entry::new("Protected");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        let updated = core
            .update_entry_field_protection(
                &mut vault,
                &entry_id,
                EntryFieldProtectionUpdate {
                    protect_title: Some(true),
                    protect_username: Some(true),
                    protect_password: Some(false),
                    protect_url: Some(true),
                    protect_notes: Some(true),
                },
            )
            .expect("update field protection");

        assert_eq!(
            updated.field_protection,
            EntryFieldProtection {
                protect_title: true,
                protect_username: true,
                protect_password: false,
                protect_url: true,
                protect_notes: true,
            }
        );
        assert_eq!(
            vault.root.entries[0].field_protection,
            updated.field_protection
        );
    }

    #[test]
    fn entry_field_protection_mutation_roundtrips() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Protection");
        let entry = Entry::new("Protected");
        let entry_id = entry.id.to_string();
        vault.root.entries.push(entry);

        core.update_entry_field_protection(
            &mut vault,
            &entry_id,
            EntryFieldProtectionUpdate {
                protect_title: Some(true),
                protect_username: Some(true),
                protect_password: Some(false),
                protect_url: Some(true),
                protect_notes: Some(true),
            },
        )
        .expect("update field protection");

        let mut key = CompositeKey::default();
        key.add_password("field-protection");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save field protection");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload field protection");
        let loaded_entry = loaded
            .root
            .entries
            .iter()
            .find(|entry| entry.id.to_string() == entry_id)
            .expect("loaded entry");

        assert_eq!(
            loaded_entry.field_protection,
            EntryFieldProtection {
                protect_title: true,
                protect_username: true,
                protect_password: false,
                protect_url: true,
                protect_notes: true,
            }
        );
    }

    #[test]
    fn stable_save_profile_recommended_preset_maps_to_expected_save_profile() {
        let stable = StableSaveProfile::recommended();
        let mapped = stable.to_save_profile();

        assert_eq!(mapped, super::SaveProfile::recommended());
    }

    #[test]
    fn stable_save_profile_saves_with_binding_friendly_options() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("SaveFacade");
        vault.root.entries.push(Entry::new("Example"));

        let mut key = CompositeKey::default();
        key.add_password("save-profile");

        let stable = StableSaveProfile {
            cipher: StableSaveCipher::ChaCha20,
            compression: StableSaveCompression::None,
            kdf: StableSaveKdf::AesKdbx4 { rounds: 42 },
        };

        let bytes = core
            .save_kdbx_with_stable_profile(&vault, &key, stable.clone())
            .expect("save with stable profile");
        let inspection = core.inspect_database(&bytes).expect("inspect saved bytes");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload saved bytes");

        assert_eq!(inspection.header.version, super::KdbxVersion::V4_1);
        assert_eq!(inspection.header.cipher, super::KdbxCipher::ChaCha20);
        assert_eq!(inspection.header.compression, super::Compression::None);
        assert_eq!(loaded.name, "SaveFacade");
        assert_eq!(loaded.root.entries.len(), 1);
        assert_eq!(
            stable.to_save_profile().kdf,
            super::SaveKdf::AesKdbx4 { rounds: 42 }
        );
    }

    #[test]
    fn byte_api_roundtrips_vault_with_attachment_totp_passkey_and_public_custom_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Phase2");
        vault
            .public_custom_data
            .insert("client".into(), b"ios".to_vec());

        let mut entry = Entry::new("Example");
        entry.username = "alice".into();
        entry.password = "s3cret".into();
        entry.url = "https://example.com".into();
        entry.notes = "hello".into();
        entry.created_at = 1710000000;
        entry.modified_at = 1710000100;
        entry.attachments.insert(
            "hello.txt".into(),
            vaultkern_model::Attachment::new("hello.txt", b"hello attachment".to_vec(), true),
        );
        entry.totp = Some(
            TotpSpec::parse_otpauth("otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=6&period=30")
                .expect("totp spec"),
        );
        entry.passkey = Some(PasskeyRecord {
            username: "alice".into(),
            credential_id: "cred-1".into(),
            generated_user_id: Some("generated-user".into()),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        entry.attributes.insert(
            "Secret".into(),
            CustomField {
                value: "protected-value".into(),
                protected: true,
            },
        );
        vault.root.entries.push(entry);

        let mut key = CompositeKey::default();
        key.add_password("master-password");

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save bytes");
        let loaded = core.load_kdbx(&bytes, &key).expect("load bytes");

        assert_eq!(loaded.name, vault.name);
        assert_eq!(loaded.public_custom_data, vault.public_custom_data);
        let loaded_entry = loaded.root.entries.first().expect("entry");
        assert_eq!(loaded_entry.username, "alice");
        assert_eq!(
            loaded_entry
                .attachments
                .get("hello.txt")
                .expect("attachment")
                .data,
            b"hello attachment".to_vec()
        );
        assert!(
            loaded_entry
                .attributes
                .get("Secret")
                .expect("protected field")
                .protected
        );
        assert!(loaded_entry.totp.is_some());
        assert!(loaded_entry.passkey.is_some());
    }

    #[test]
    fn inspect_header_reports_cipher_version_and_public_custom_data() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Inspect");
        vault
            .public_custom_data
            .insert("client".into(), b"android".to_vec());
        let mut key = CompositeKey::default();
        key.add_password("header-check");

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save bytes");
        let summary = core.inspect_kdbx_header(&bytes).expect("inspect header");

        assert_eq!(summary.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_eq!(summary.cipher, vaultkern_kdbx::KdbxCipher::Aes256);
        assert_eq!(
            summary.public_custom_data.get("client"),
            Some(&b"android".to_vec())
        );
    }

    #[test]
    fn summary_counts_public_custom_data_items() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("Summary");
        vault.meta_custom_data.insert("meta".into(), "a".into());
        vault
            .public_custom_data
            .insert("public".into(), b"b".to_vec());

        let mut group = vaultkern_model::Group::new("Nested");
        group.custom_data.insert("group".into(), "c".into());
        let mut entry = Entry::new("Entry");
        entry.custom_data.insert("entry".into(), "d".into());
        group.entries.push(entry);
        vault.root.children.push(group);

        let summary = core.summarize_vault(&vault);
        assert_eq!(summary.custom_data_items, 4);
    }

    #[test]
    fn load_database_summary_counts_public_custom_data_items() {
        let core = KeepassCore::new();
        let mut vault = Vault::empty("SummaryLoad");
        vault.meta_custom_data.insert("meta".into(), "a".into());
        vault
            .public_custom_data
            .insert("public".into(), b"b".to_vec());

        let mut key = CompositeKey::default();
        key.add_password("summary-load");
        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save summary fixture");
        let loaded = core
            .load_database(&bytes, &key)
            .expect("load summary fixture");

        assert_eq!(loaded.summary.custom_data_items, 2);
    }

    #[test]
    fn load_rejects_corrupted_header_hmac_and_block_hmac() {
        let core = KeepassCore::new();
        let vault = Vault::empty("Corrupt");
        let mut key = CompositeKey::default();
        key.add_password("corrupt-check");

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save bytes");

        let mut broken_header = bytes.clone();
        broken_header[80] ^= 0xFF;
        assert!(core.load_kdbx(&broken_header, &key).is_err());

        let mut broken_payload = bytes;
        let last = broken_payload.len() - 1;
        broken_payload[last] ^= 0xFF;
        assert!(core.load_kdbx(&broken_payload, &key).is_err());
    }

    #[test]
    fn loads_external_kdbx3_fixture_with_protected_strings() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("masterpw");

        let loaded = core
            .load_database(FIXTURE_PROTECTED_STRINGS, &key)
            .expect("load protected strings fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V3_1
        );
        assert_eq!(
            loaded.inspection.warnings,
            vec![
                LoadWarning::LegacyFormat(vaultkern_kdbx::KdbxVersion::V3_1),
                LoadWarning::SaveWillUpgradeToV4_1,
            ]
        );
        assert_protected_strings_fixture_contents(&loaded.vault);
    }

    #[test]
    fn protected_strings_fixture_upgrades_to_kdbx4_1_without_losing_protection_semantics() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("masterpw");

        let loaded = core
            .load_database(FIXTURE_PROTECTED_STRINGS, &key)
            .expect("load protected strings fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("rewrite protected strings fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten protected strings fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten protected strings fixture");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_protected_strings_fixture_contents(&reloaded);
    }

    #[test]
    fn loads_external_kdbx4_fixture_and_rewrites_as_4_1() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("t");

        let loaded = core
            .load_database(FIXTURE_FORMAT400, &key)
            .expect("load format400 fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V4_0
        );
        assert_eq!(
            loaded.inspection.header.cipher,
            vaultkern_kdbx::KdbxCipher::ChaCha20
        );
        assert_eq!(
            loaded.inspection.save_target_version,
            vaultkern_kdbx::KdbxVersion::V4_1
        );
        assert_eq!(loaded.inspection.warnings.len(), 1);

        let vault = &loaded.vault;
        assert_eq!(vault.name, "Format400");
        assert_eq!(vault.database_name_changed, Some(1_489_501_066));
        assert_eq!(vault.description, None);
        assert_eq!(vault.default_username, None);
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
        assert_eq!(vault.deleted_objects.len(), 10);
        assert_eq!(vault.meta_opaque_xml.len(), 1);
        assert_eq!(vault.root.title, "Format400");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));
        assert_eq!(vault.root.entries.len(), 1);
        assert!(vault.root.children.is_empty());

        let entry = vault.root.entries.first().expect("entry");
        assert_eq!(entry.title, "Format400");
        assert_eq!(entry.username, "Format400");
        assert_eq!(entry.password, "Format400");
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.usage_count, Some(1));
        assert_eq!(entry.history.len(), 0);
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: None,
                associations: Vec::new(),
            })
        );
        assert_eq!(
            entry
                .attributes
                .get("Format400")
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("Format400", true))
        );
        assert_eq!(
            entry.attachments.get("Format400").map(|attachment| (
                attachment.data.as_bytes().to_vec(),
                attachment.protect_in_memory
            )),
            Some((b"Format400\n".to_vec(), false))
        );

        let bytes = core
            .save_kdbx(vault, &key, super::SaveProfile::recommended())
            .expect("rewrite format400 fixture");
        let summary = core
            .inspect_kdbx_header(&bytes)
            .expect("inspect rewritten header");
        assert_eq!(summary.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_eq!(summary.cipher, vaultkern_kdbx::KdbxCipher::Aes256);

        let rewritten = core
            .load_kdbx(&bytes, &key)
            .expect("reload rewritten bytes");
        assert_eq!(rewritten.name, "Format400");
        assert_eq!(rewritten.deleted_objects.len(), 10);
        assert_eq!(rewritten.root.title, "Format400");
        assert_eq!(rewritten.root.icon_id, Some(49));
        assert_eq!(rewritten.root.entries.len(), 1);
        let rewritten_entry = rewritten.root.entries.first().expect("rewritten entry");
        assert_eq!(rewritten_entry.title, "Format400");
        assert_eq!(rewritten_entry.username, "Format400");
        assert_eq!(rewritten_entry.password, "Format400");
        assert_eq!(rewritten_entry.usage_count, Some(1));
        assert_eq!(
            rewritten_entry
                .attributes
                .get("Format400")
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("Format400", true))
        );
        assert_eq!(
            rewritten_entry
                .attachments
                .get("Format400")
                .map(|attachment| (
                    attachment.data.as_bytes().to_vec(),
                    attachment.protect_in_memory
                )),
            Some((b"Format400\n".to_vec(), false))
        );
    }

    #[test]
    fn loads_external_kdbx3_format300_fixture() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_database(FIXTURE_FORMAT300, &key)
            .expect("load format300 fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V3_0
        );
        assert_eq!(
            loaded.inspection.header.cipher,
            vaultkern_kdbx::KdbxCipher::Aes256
        );
        assert_eq!(
            loaded.inspection.header.compression,
            vaultkern_kdbx::Compression::Gzip
        );
        assert_eq!(
            loaded.inspection.save_target_version,
            vaultkern_kdbx::KdbxVersion::V4_1
        );
        assert_eq!(
            loaded.inspection.warnings,
            vec![
                LoadWarning::LegacyFormat(vaultkern_kdbx::KdbxVersion::V3_0),
                LoadWarning::SaveWillUpgradeToV4_1,
            ]
        );
        assert_format300_fixture_contents(&loaded.vault);
    }

    #[test]
    fn kdbx3_format300_upgrades_to_kdbx4_1_without_losing_key_fields() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_database(FIXTURE_FORMAT300, &key)
            .expect("load format300 fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("rewrite format300 fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten format300 fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten format300 fixture");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_format300_fixture_contents(&reloaded);
    }

    #[test]
    fn loads_external_kdbx2_format200_fixture_with_field_oracle() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_database(FIXTURE_FORMAT200, &key)
            .expect("load format200 fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V2_0
        );
        assert_eq!(loaded.vault.root.title, "Format200");
        assert_eq!(
            loaded.vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: true,
                protect_password: false,
                protect_url: true,
                protect_notes: false,
            })
        );

        assert_eq!(loaded.vault.root.entries.len(), 1);
        let entry = &loaded.vault.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.username, "User Name");
        assert_eq!(entry.attachments.len(), 2);
        assert_eq!(
            entry
                .attachments
                .get("myattach.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"abcdefghijk".to_vec())
        );
        assert_eq!(
            entry
                .attachments
                .get("test.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"this is a test".to_vec())
        );

        assert_eq!(entry.history.len(), 2);
        assert!(entry.history[0].attachments.is_empty());
        assert_eq!(
            entry.history[1]
                .attachments
                .get("myattach.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"abcdefghijk".to_vec())
        );
        assert!(
            entry.attachments["myattach.txt"]
                .data
                .ptr_eq(&entry.history[1].attachments["myattach.txt"].data)
        );
    }

    #[test]
    fn kdbx2_format200_upgrades_to_kdbx4_1_without_losing_key_fields() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_database(FIXTURE_FORMAT200, &key)
            .expect("load format200 fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("save upgraded kdbx4");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect upgraded database");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload upgraded database");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_eq!(reloaded.root.title, "Format200");
        assert_eq!(
            reloaded.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: true,
                protect_password: false,
                protect_url: true,
                protect_notes: false,
            })
        );

        let entry = &reloaded.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.username, "User Name");
        assert_eq!(entry.attachments.len(), 2);
        assert_eq!(
            entry
                .attachments
                .get("myattach.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"abcdefghijk".to_vec())
        );
        assert_eq!(
            entry
                .attachments
                .get("test.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"this is a test".to_vec())
        );
        assert_eq!(entry.history.len(), 2);
        assert!(entry.history[0].attachments.is_empty());
        assert_eq!(
            entry.history[1]
                .attachments
                .get("myattach.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"abcdefghijk".to_vec())
        );
    }

    #[test]
    fn inspect_header_supports_external_kdbx3_fixture() {
        let core = KeepassCore::new();

        let summary = core
            .inspect_kdbx_header(FIXTURE_FORMAT300)
            .expect("inspect format300 header");

        assert_eq!(summary.version, vaultkern_kdbx::KdbxVersion::V3_0);
        assert_eq!(summary.cipher, vaultkern_kdbx::KdbxCipher::Aes256);
    }

    #[test]
    fn loads_user_v3_fixture_with_expected_fields_and_expiry() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("123456");

        let vault = core
            .load_kdbx(FIXTURE_USER_TEST, &key)
            .expect("load user test fixture");

        assert_test_fixture_contents(&vault, false);
    }

    #[test]
    fn loads_user_v4_fixture_with_expected_fields_and_expiry() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("123456");

        let vault = core
            .load_kdbx(FIXTURE_USER_TEST4, &key)
            .expect("load user test4 fixture");

        assert_test_fixture_contents(&vault, true);
    }

    #[test]
    fn user_fixtures_preserve_protected_semantics_on_roundtrip() {
        let core = KeepassCore::new();

        for (bytes, expected_attachment_protection) in
            [(FIXTURE_USER_TEST, false), (FIXTURE_USER_TEST4, true)]
        {
            let mut key = CompositeKey::default();
            key.add_password("123456");

            let loaded = core.load_kdbx(bytes, &key).expect("load user fixture");
            let rewritten = core
                .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
                .expect("save user fixture");
            let reloaded = core
                .load_kdbx(&rewritten, &key)
                .expect("reload user fixture");

            assert_test_fixture_contents(&reloaded, expected_attachment_protection);
        }
    }

    #[test]
    fn loads_non_ascii_fixture_with_unicode_title_and_deleted_object() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("Δöض");

        let loaded = core
            .load_database(FIXTURE_NON_ASCII, &key)
            .expect("load non-ascii fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V3_1
        );
        assert_eq!(
            loaded.inspection.header.cipher,
            vaultkern_kdbx::KdbxCipher::Aes256
        );
        assert_eq!(
            loaded.inspection.header.compression,
            vaultkern_kdbx::Compression::None
        );
        assert_eq!(
            loaded.inspection.warnings,
            vec![
                LoadWarning::LegacyFormat(vaultkern_kdbx::KdbxVersion::V3_1),
                LoadWarning::SaveWillUpgradeToV4_1,
            ]
        );
        assert_non_ascii_fixture_contents(&loaded.vault);
    }

    #[test]
    fn non_ascii_fixture_upgrades_to_kdbx4_1_without_losing_unicode_fields() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("Δöض");

        let loaded = core
            .load_database(FIXTURE_NON_ASCII, &key)
            .expect("load non-ascii fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("rewrite non-ascii fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten non-ascii fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten non-ascii fixture");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_non_ascii_fixture_contents(&reloaded);
    }

    #[test]
    fn loads_compressed_fixture_and_reports_gzip_header() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("");

        let loaded = core
            .load_database(FIXTURE_COMPRESSED, &key)
            .expect("load compressed fixture");

        assert_eq!(
            loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V3_1
        );
        assert_eq!(
            loaded.inspection.header.cipher,
            vaultkern_kdbx::KdbxCipher::Aes256
        );
        assert_eq!(
            loaded.inspection.header.compression,
            vaultkern_kdbx::Compression::Gzip
        );
        assert_eq!(
            loaded.inspection.warnings,
            vec![
                LoadWarning::LegacyFormat(vaultkern_kdbx::KdbxVersion::V3_1),
                LoadWarning::SaveWillUpgradeToV4_1,
            ]
        );
        assert_compressed_fixture_contents(&loaded.vault);
    }

    #[test]
    fn compressed_fixture_upgrades_to_kdbx4_1_without_losing_key_fields() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("");

        let loaded = core
            .load_database(FIXTURE_COMPRESSED, &key)
            .expect("load compressed fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("rewrite compressed fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten compressed fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload rewritten compressed fixture");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_compressed_fixture_contents(&reloaded);
    }

    #[test]
    fn opens_external_databases_with_parsed_key_files() {
        let core = KeepassCore::new();

        let mut binary_key = CompositeKey::default();
        binary_key
            .add_key_file_content(FIXTURE_FILE_KEY_BINARY)
            .expect("binary key file");
        let binary_vault = core
            .load_kdbx(FIXTURE_FILE_KEY_BINARY_DB, &binary_key)
            .expect("load binary key file db");
        assert_eq!(binary_vault.name, "FileKeyBinary Database");

        let mut hex_key = CompositeKey::default();
        hex_key
            .add_key_file_content(FIXTURE_FILE_KEY_HEX)
            .expect("hex key file");
        let hex_vault = core
            .load_kdbx(FIXTURE_FILE_KEY_HEX_DB, &hex_key)
            .expect("load hex key file db");
        assert_eq!(hex_vault.name, "FileKeyHex Database");

        let mut hashed_key = CompositeKey::default();
        hashed_key
            .add_key_file_content(FIXTURE_FILE_KEY_HASHED)
            .expect("hashed key file");
        let hashed_vault = core
            .load_kdbx(FIXTURE_FILE_KEY_HASHED_DB, &hashed_key)
            .expect("load hashed key file db");
        assert_eq!(hashed_vault.name, "FileKeyHashed Database");

        let mut xml_key = CompositeKey::default();
        xml_key
            .add_key_file_content(FIXTURE_FILE_KEY_XML)
            .expect("xml v1 key file");
        let xml_vault = core
            .load_kdbx(FIXTURE_FILE_KEY_XML_DB, &xml_key)
            .expect("load xml v1 key file db");
        assert_eq!(xml_vault.name, "FileKeyXml Database");

        let mut xml_v2_key = CompositeKey::default();
        xml_v2_key
            .add_key_file_content(FIXTURE_FILE_KEY_XML_V2)
            .expect("xml v2 key file");
        let xml_v2_vault = core
            .load_kdbx(FIXTURE_FILE_KEY_XML_V2_DB, &xml_v2_key)
            .expect("load xml v2 key file db");
        assert_eq!(xml_v2_vault.name, "FileKeyXmlV2 Database");
    }

    #[test]
    fn loads_file_key_fixture_matrix_with_field_oracle() {
        let core = KeepassCore::new();

        assert_file_key_fixture(
            &core,
            FIXTURE_FILE_KEY_BINARY_DB,
            FIXTURE_FILE_KEY_BINARY,
            vaultkern_kdbx::KdbxVersion::V2_0,
            "FileKeyBinary Database",
            "FileKeyBinary",
        );
        assert_file_key_fixture(
            &core,
            FIXTURE_FILE_KEY_HEX_DB,
            FIXTURE_FILE_KEY_HEX,
            vaultkern_kdbx::KdbxVersion::V2_0,
            "FileKeyHex Database",
            "FileKeyHex",
        );
        assert_file_key_fixture(
            &core,
            FIXTURE_FILE_KEY_HASHED_DB,
            FIXTURE_FILE_KEY_HASHED,
            vaultkern_kdbx::KdbxVersion::V2_0,
            "FileKeyHashed Database",
            "FileKeyHashed",
        );
        assert_file_key_fixture(
            &core,
            FIXTURE_FILE_KEY_XML_DB,
            FIXTURE_FILE_KEY_XML,
            vaultkern_kdbx::KdbxVersion::V2_0,
            "FileKeyXml Database",
            "FileKeyXml",
        );
        assert_file_key_fixture(
            &core,
            FIXTURE_FILE_KEY_XML_V2_DB,
            FIXTURE_FILE_KEY_XML_V2,
            vaultkern_kdbx::KdbxVersion::V3_1,
            "FileKeyXmlV2 Database",
            "Database",
        );
    }

    #[test]
    fn file_key_fixture_matrix_upgrades_to_kdbx4_1_without_losing_key_fields() {
        let core = KeepassCore::new();

        assert_file_key_fixture_roundtrip(
            &core,
            FIXTURE_FILE_KEY_BINARY_DB,
            FIXTURE_FILE_KEY_BINARY,
            "FileKeyBinary Database",
            "FileKeyBinary",
        );
        assert_file_key_fixture_roundtrip(
            &core,
            FIXTURE_FILE_KEY_HEX_DB,
            FIXTURE_FILE_KEY_HEX,
            "FileKeyHex Database",
            "FileKeyHex",
        );
        assert_file_key_fixture_roundtrip(
            &core,
            FIXTURE_FILE_KEY_HASHED_DB,
            FIXTURE_FILE_KEY_HASHED,
            "FileKeyHashed Database",
            "FileKeyHashed",
        );
        assert_file_key_fixture_roundtrip(
            &core,
            FIXTURE_FILE_KEY_XML_DB,
            FIXTURE_FILE_KEY_XML,
            "FileKeyXml Database",
            "FileKeyXml",
        );
        assert_file_key_fixture_roundtrip(
            &core,
            FIXTURE_FILE_KEY_XML_V2_DB,
            FIXTURE_FILE_KEY_XML_V2,
            "FileKeyXmlV2 Database",
            "Database",
        );
    }

    #[test]
    fn opens_password_plus_key_file_and_key_file_only_databases() {
        let core = KeepassCore::new();

        let mut password_and_key = CompositeKey::default();
        password_and_key.add_password("a");
        password_and_key
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
            .expect("protected key file");
        let password_and_key_vault = core
            .load_kdbx(FIXTURE_KEY_FILE_PROTECTED_DB, &password_and_key)
            .expect("load password plus key file db");
        assert_eq!(password_and_key_vault.root.entries.len(), 2);
        assert_eq!(password_and_key_vault.root.entries[0].title, "entry1");
        assert_eq!(password_and_key_vault.root.entries[1].title, "entry2");

        let mut key_only = CompositeKey::default();
        key_only
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
            .expect("key-only file");
        let key_only_vault = core
            .load_kdbx(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key_only)
            .expect("load key-only db");
        assert_eq!(key_only_vault.root.entries.len(), 2);
        assert_eq!(key_only_vault.root.entries[0].title, "entry1");
        assert_eq!(key_only_vault.root.entries[1].title, "entry2");
    }

    #[test]
    fn loads_key_file_protected_fixtures_with_field_oracle() {
        let core = KeepassCore::new();

        let mut password_and_key = CompositeKey::default();
        password_and_key.add_password("a");
        password_and_key
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
            .expect("protected key file");
        let password_and_key_loaded = core
            .load_database(FIXTURE_KEY_FILE_PROTECTED_DB, &password_and_key)
            .expect("load password plus key file db");

        let mut key_only = CompositeKey::default();
        key_only
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
            .expect("key-only file");
        let key_only_loaded = core
            .load_database(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key_only)
            .expect("load key-only db");

        assert_eq!(
            password_and_key_loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V4_0
        );
        assert_eq!(
            key_only_loaded.inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V4_0
        );
        assert_key_file_fixture_contents(
            &password_and_key_loaded.vault,
            1_550_181_928,
            1_550_181_945,
        );
        assert_key_file_fixture_contents(&key_only_loaded.vault, 1_550_343_234, 1_550_343_246);
    }

    #[test]
    fn key_file_protected_fixtures_upgrade_to_kdbx4_1_without_losing_key_fields() {
        let core = KeepassCore::new();

        let mut password_and_key = CompositeKey::default();
        password_and_key.add_password("a");
        password_and_key
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED)
            .expect("protected key file");
        let password_and_key_loaded = core
            .load_database(FIXTURE_KEY_FILE_PROTECTED_DB, &password_and_key)
            .expect("load password plus key file db");
        let password_and_key_rewritten = core
            .save_kdbx(
                &password_and_key_loaded.vault,
                &password_and_key,
                super::SaveProfile::recommended(),
            )
            .expect("rewrite password plus key db");
        let password_and_key_inspection = core
            .inspect_database(&password_and_key_rewritten)
            .expect("inspect rewritten password plus key db");
        let password_and_key_reloaded = core
            .load_kdbx(&password_and_key_rewritten, &password_and_key)
            .expect("reload rewritten password plus key db");

        assert_eq!(
            password_and_key_inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V4_1
        );
        assert_key_file_fixture_contents(&password_and_key_reloaded, 1_550_181_928, 1_550_181_945);

        let mut key_only = CompositeKey::default();
        key_only
            .add_key_file_content(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD)
            .expect("key-only file");
        let key_only_loaded = core
            .load_database(FIXTURE_KEY_FILE_PROTECTED_NO_PASSWORD_DB, &key_only)
            .expect("load key-only db");
        let key_only_rewritten = core
            .save_kdbx(
                &key_only_loaded.vault,
                &key_only,
                super::SaveProfile::recommended(),
            )
            .expect("rewrite key-only db");
        let key_only_inspection = core
            .inspect_database(&key_only_rewritten)
            .expect("inspect rewritten key-only db");
        let key_only_reloaded = core
            .load_kdbx(&key_only_rewritten, &key_only)
            .expect("reload rewritten key-only db");

        assert_eq!(
            key_only_inspection.header.version,
            vaultkern_kdbx::KdbxVersion::V4_1
        );
        assert_key_file_fixture_contents(&key_only_reloaded, 1_550_343_234, 1_550_343_246);
    }

    #[test]
    fn loads_structured_database_metadata_from_fixture() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE, &key)
            .expect("load rich metadata fixture");

        assert_eq!(vault.description, None);
        assert_eq!(vault.default_username, None);
        assert_eq!(vault.generator.as_deref(), Some("KeePass"));
        assert_eq!(vault.database_name_changed, Some(1_283_804_892));
        assert_eq!(vault.description_changed, Some(1_283_804_892));
        assert_eq!(vault.default_username_changed, Some(1_283_804_892));
        assert_eq!(vault.maintenance_history_days, Some(365));
        assert_eq!(vault.color, None);
        assert_eq!(vault.master_key_changed, Some(1_283_804_892));
        assert_eq!(vault.master_key_change_rec, Some(-1));
        assert_eq!(vault.master_key_change_force, Some(-1));
        assert!(vault.custom_icons.is_empty());
        assert_eq!(vault.history_max_items, Some(10));
        assert_eq!(vault.history_max_size, Some(6_291_456));
        assert_eq!(vault.last_selected_group, Some(vault.root.id));
        assert_eq!(vault.last_top_visible_group, Some(vault.root.id));
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_structured_database_metadata() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("metadata-roundtrip");

        let mut vault = Vault::empty("Meta");
        vault.generator = Some("Codex".into());
        vault.settings_changed = Some(1_700_000_000);
        vault.description = Some("Description".into());
        vault.database_name_changed = Some(1_700_000_001);
        vault.description_changed = Some(1_700_000_002);
        vault.default_username_changed = Some(1_700_000_003);
        vault.default_username = Some("default-user".into());
        vault.maintenance_history_days = Some(30);
        vault.color = Some("#123456".into());
        vault.master_key_changed = Some(1_700_000_004);
        vault.master_key_change_rec = Some(90);
        vault.master_key_change_force = Some(180);
        vault.master_key_change_force_once = Some(true);
        let icon_id = vault.root.id;
        vault.custom_icons.push(CustomIcon {
            id: icon_id,
            data: vec![1, 2, 3, 4],
            name: Some("Meta Icon".into()),
            last_modified: Some(1_700_000_005),
        });
        vault.history_max_items = Some(42);
        vault.history_max_size = Some(9_999);
        vault.last_selected_group = Some(vault.root.id);
        vault.last_top_visible_group = Some(vault.root.id);
        vault.memory_protection = Some(MemoryProtection {
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: true,
        });

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save metadata");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload metadata");

        assert_eq!(loaded.generator.as_deref(), Some("Codex"));
        assert_eq!(loaded.settings_changed, Some(1_700_000_000));
        assert_eq!(loaded.description.as_deref(), Some("Description"));
        assert_eq!(loaded.database_name_changed, Some(1_700_000_001));
        assert_eq!(loaded.description_changed, Some(1_700_000_002));
        assert_eq!(loaded.default_username_changed, Some(1_700_000_003));
        assert_eq!(loaded.default_username.as_deref(), Some("default-user"));
        assert_eq!(loaded.maintenance_history_days, Some(30));
        assert_eq!(loaded.color.as_deref(), Some("#123456"));
        assert_eq!(loaded.master_key_changed, Some(1_700_000_004));
        assert_eq!(loaded.master_key_change_rec, Some(90));
        assert_eq!(loaded.master_key_change_force, Some(180));
        assert_eq!(loaded.master_key_change_force_once, Some(true));
        assert_eq!(loaded.custom_icons.len(), 1);
        assert_eq!(loaded.custom_icons[0].id, icon_id);
        assert_eq!(loaded.custom_icons[0].data, vec![1, 2, 3, 4]);
        assert_eq!(loaded.custom_icons[0].name.as_deref(), Some("Meta Icon"));
        assert_eq!(loaded.custom_icons[0].last_modified, Some(1_700_000_005));
        assert_eq!(loaded.history_max_items, Some(42));
        assert_eq!(loaded.history_max_size, Some(9_999));
        assert_eq!(loaded.last_selected_group, Some(vault.root.id));
        assert_eq!(loaded.last_top_visible_group, Some(vault.root.id));
        assert_eq!(
            loaded.memory_protection,
            Some(MemoryProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: true,
            })
        );
    }

    #[test]
    fn loads_group_and_entry_schema_depth_from_external_fixture() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE, &key)
            .expect("load group entry rich fixture");

        let general = &vault.root.children[0];
        assert_eq!(general.title, "General");
        assert_eq!(general.notes, "");
        assert_eq!(general.icon_id, Some(48));
        assert_eq!(
            general.times,
            Some(GroupTimes {
                created_at: 1_283_804_904,
                modified_at: 1_283_804_904,
                expires: false,
                expiry_time: Some(1_283_804_880),
                last_accessed_at: Some(1_283_804_904),
                usage_count: Some(0),
                location_changed_at: Some(1_283_804_904),
            })
        );
        assert_eq!(
            general.flags,
            GroupFlags {
                is_expanded: Some(true),
                enable_auto_type: None,
                enable_searching: None,
            }
        );
        assert_eq!(general.default_auto_type_sequence, None);
        assert_eq!(general.last_top_visible_entry, None);

        let entry = &vault.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.custom_icon_id, None);
        assert_eq!(entry.foreground_color.as_deref(), Some(""));
        assert_eq!(entry.background_color.as_deref(), Some(""));
        assert_eq!(entry.override_url.as_deref(), Some(""));
        assert_eq!(entry.created_at, 1_283_804_904);
        assert_eq!(entry.modified_at, 1_636_321_720);
        assert_eq!(entry.expiry_time, Some(1_283_804_880));
        assert_eq!(entry.last_accessed_at, Some(1_636_321_720));
        assert_eq!(entry.usage_count, Some(0));
        assert_eq!(entry.location_changed_at, Some(1_283_804_904));
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: Some(String::new()),
                associations: vec![AutoTypeAssociation {
                    window: "Target Window".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into(),
                }],
            })
        );
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
    }

    #[test]
    fn loads_external_browser_fixture_with_group_tree() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
            .expect("load browser fixture");

        assert_eq!(vault.root.title, "NewDatabase");
        assert_eq!(vault.root.entries.len(), 1);
        assert_eq!(vault.root.entries[0].title, "Sample Entry");
        assert_eq!(vault.root.children.len(), 6);
        let general = find_group_by_title(&vault.root, "General").expect("general group");
        let subgroup = find_group_by_title(general, "SubGroup").expect("subgroup");
        assert!(subgroup.children.is_empty());
        assert!(subgroup.entries.is_empty());
    }

    #[test]
    fn loads_external_kdbx4_fixture_matrix() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let new_database2 = core
            .load_kdbx(FIXTURE_NEW_DATABASE2, &key)
            .expect("load newdatabase2 fixture");
        let general = find_group_by_title(&new_database2.root, "General").expect("general group");
        assert_eq!(general.entries.len(), 1);
        assert_eq!(general.entries[0].title, "Unicode");

        let multi = core
            .load_kdbx(FIXTURE_NEW_DATABASE_MULTI, &key)
            .expect("load newdatabase multi fixture");
        assert_eq!(multi.root.entries.len(), 3);
        assert_eq!(multi.root.entries[0].title, "Single Entry");
        assert_eq!(multi.root.entries[1].title, "Multi Entry 1");
        assert_eq!(multi.root.entries[2].title, "Multi Entry 2");

        let merge = core
            .load_kdbx(FIXTURE_MERGE_DATABASE, &key)
            .expect("load merge fixture");
        assert_eq!(merge.root.children.len(), 7);
        let general = find_group_by_title(&merge.root, "General").expect("general group");
        assert_eq!(general.entries.len(), 1);
        assert_eq!(
            merge.root.children.last().map(|group| group.entries.len()),
            Some(1)
        );
    }

    #[test]
    fn loads_structured_custom_data_from_browser_fixture() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
            .expect("load browser fixture");

        assert_eq!(vault.meta_custom_data.len(), 3);
        assert_eq!(
            vault
                .meta_custom_data
                .get("KPXC_BROWSER_test")
                .map(String::as_str),
            Some("9l41TH7Lky0zfXdjKr+xhduR6k33qAPuMppy4bPlJ2M=")
        );
        let entry = &vault.root.entries[0];
        assert_eq!(entry.custom_data.len(), 2);
        assert_eq!(
            entry
                .custom_data
                .get("KeePassXC-Browser Settings")
                .map(String::as_str),
            Some("{\"Allow\":[\"github.com\"],\"Deny\":[],\"Realm\":\"\"}")
        );
    }

    #[test]
    fn loads_external_fixture_metadata_custom_data_oracle() {
        let core = KeepassCore::new();

        let mut browser_key = CompositeKey::default();
        browser_key.add_password("a");
        let browser = core
            .load_database(FIXTURE_NEW_DATABASE_BROWSER, &browser_key)
            .expect("load browser fixture");
        assert_eq!(browser.summary.custom_data_items, 5);
        assert_eq!(core.list_vault_custom_data(&browser.vault).len(), 3);
        assert_eq!(
            core.list_vault_custom_data(&browser.vault),
            vec![
                CustomDataItemView {
                    key: "KPXC_BROWSER_test".into(),
                    value: "9l41TH7Lky0zfXdjKr+xhduR6k33qAPuMppy4bPlJ2M=".into(),
                },
                CustomDataItemView {
                    key: "KPXC_BROWSER_test2".into(),
                    value: "YM1zuHGk5GLctep1gEmms/MuCVFBNWPdUBrmviqj/Q8=".into(),
                },
                CustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Wed Apr 29 20:57:45 2020 GMT".into(),
                },
            ]
        );
        let browser_entry_id = browser.vault.root.entries[0].id.to_string();
        assert_eq!(
            core.list_entry_custom_data(&browser.vault, &browser_entry_id)
                .expect("browser entry custom data"),
            vec![
                CustomDataItemView {
                    key: "KeePassXC-Browser Settings".into(),
                    value: "{\"Allow\":[\"github.com\"],\"Deny\":[],\"Realm\":\"\"}".into(),
                },
                CustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Wed Apr 29 20:57:45 2020 GMT".into(),
                },
            ]
        );

        let mut new_database_key = CompositeKey::default();
        new_database_key.add_password("a");
        let new_database = core
            .load_database(FIXTURE_NEW_DATABASE, &new_database_key)
            .expect("load newdatabase fixture");
        assert_eq!(new_database.summary.custom_data_items, 2);
        assert_eq!(
            core.list_vault_custom_data(&new_database.vault),
            vec![
                CustomDataItemView {
                    key: "FDO_SECRETS_EXPOSED_GROUP".into(),
                    value: "{87f9f6bf-2e09-2344-a972-a1d1de394774}".into(),
                },
                CustomDataItemView {
                    key: "_LAST_MODIFIED".into(),
                    value: "Sun Nov 7 21:48:24 2021 GMT".into(),
                },
            ]
        );
        let new_database_entry_id = new_database.vault.root.entries[0].id.to_string();
        assert_eq!(
            core.list_entry_custom_data(&new_database.vault, &new_database_entry_id)
                .expect("newdatabase entry custom data"),
            Vec::<CustomDataItemView>::new()
        );
    }

    #[test]
    fn loads_browser_fixture_with_richer_field_oracle() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE_BROWSER, &key)
            .expect("load browser fixture");

        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));

        let root_entry = &vault.root.entries[0];
        assert_eq!(root_entry.title, "Sample Entry");
        assert_eq!(root_entry.username, "User Name");
        assert_eq!(root_entry.url, "https://github.com/login");
        assert_eq!(root_entry.notes, "Notes");
        assert_eq!(root_entry.history.len(), 3);
        assert_eq!(
            root_entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            root_entry
                .auto_type
                .as_ref()
                .map(|auto| auto.associations.len()),
            Some(1)
        );
        assert_eq!(
            root_entry
                .history
                .iter()
                .map(|entry| entry.url.as_str())
                .collect::<Vec<_>>(),
            vec![
                "http://www.somesite.com/",
                "http://www.somesite.com/",
                "http://www.somesite.com/",
            ]
        );
        assert!(root_entry.history.iter().all(|entry| {
            entry.title == "Sample Entry"
                && entry.username == "User Name"
                && entry.password == "Password"
                && entry.notes == "Notes"
                && entry.attachments.is_empty()
                && entry.field_protection
                    == EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    }
        }));

        let general = find_group_by_title(&vault.root, "General").expect("general group");
        let subgroup = find_group_by_title(general, "SubGroup").expect("general subgroup");
        assert_eq!(subgroup.icon_id, Some(48));
        assert!(subgroup.entries.is_empty());

        let homebanking = find_group_by_title(&vault.root, "Homebanking").expect("homebanking");
        let bank_subgroup = find_group_by_title(homebanking, "Subgroup").expect("bank subgroup");
        assert_eq!(bank_subgroup.entries.len(), 1);
        let bank_entry = &bank_subgroup.entries[0];
        assert_eq!(bank_entry.title, "Subgroup Entry");
        assert_eq!(bank_entry.username, "Bank User Name");
        assert_eq!(bank_entry.url, "https:/www.bank.com");
        assert_eq!(bank_entry.notes, "Important note");
        assert_eq!(bank_entry.history.len(), 1);
        assert_eq!(
            bank_entry.history.first().map(|entry| (
                entry.title.as_str(),
                entry.username.as_str(),
                entry.password.as_str(),
                entry.url.as_str(),
                entry.notes.as_str(),
                entry.attachments.len(),
                entry.field_protection,
            )),
            Some((
                "Subgroup Entry",
                "",
                "",
                "",
                "",
                0,
                EntryFieldProtection {
                    protect_title: false,
                    protect_username: false,
                    protect_password: true,
                    protect_url: false,
                    protect_notes: false,
                },
            ))
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_structured_custom_data() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("custom-data-roundtrip");

        let mut vault = Vault::empty("CustomData");
        vault
            .meta_custom_data
            .insert("meta-key".into(), "meta-value".into());
        let mut group = vaultkern_model::Group::new("Nested");
        group
            .custom_data
            .insert("group-key".into(), "group-value".into());
        let group_id = group.id;
        vault.root.children.push(group);

        let mut entry = Entry::new("Entry");
        entry
            .custom_data
            .insert("entry-key".into(), "entry-value".into());
        vault.root.entries.push(entry);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save custom data");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload custom data");

        assert_eq!(
            loaded.meta_custom_data.get("meta-key").map(String::as_str),
            Some("meta-value")
        );
        let loaded_group = find_group(&loaded.root, &group_id.to_string()).expect("loaded group");
        assert_eq!(
            loaded_group
                .custom_data
                .get("group-key")
                .map(String::as_str),
            Some("group-value")
        );
        let loaded_entry = &loaded.root.entries[0];
        assert_eq!(
            loaded_entry
                .custom_data
                .get("entry-key")
                .map(String::as_str),
            Some("entry-value")
        );
    }

    #[test]
    fn external_fixtures_preserve_metadata_custom_data_on_roundtrip() {
        let core = KeepassCore::new();

        for (bytes, password, expected_count) in [
            (FIXTURE_NEW_DATABASE_BROWSER, "a", 5usize),
            (FIXTURE_NEW_DATABASE, "a", 2usize),
        ] {
            let mut key = CompositeKey::default();
            key.add_password(password);

            let loaded = core.load_database(bytes, &key).expect("load fixture");
            let rewritten = core
                .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
                .expect("save fixture");
            let reloaded = core
                .load_database(&rewritten, &key)
                .expect("reload fixture");

            assert_eq!(reloaded.summary.custom_data_items, expected_count);
            assert_eq!(
                reloaded.vault.meta_custom_data,
                loaded.vault.meta_custom_data
            );
            assert_eq!(
                reloaded.vault.public_custom_data,
                loaded.vault.public_custom_data
            );
            assert_eq!(
                reloaded.vault.root.custom_data,
                loaded.vault.root.custom_data
            );
            assert_eq!(
                reloaded.vault.root.entries[0].custom_data,
                loaded.vault.root.entries[0].custom_data
            );
        }
    }

    #[test]
    fn loads_external_sync_fixtures_with_expected_group_summary() {
        let core = KeepassCore::new();

        let mut same_key = CompositeKey::default();
        same_key.add_password("a");
        let synced = core
            .load_kdbx(FIXTURE_SYNC_DATABASE, &same_key)
            .expect("load sync fixture");
        assert_eq!(synced.root.children.len(), 7);
        let general = find_group_by_title(&synced.root, "General").expect("general group");
        assert_eq!(general.entries.len(), 1);
        assert_eq!(
            synced.root.children.last().map(|group| group.entries.len()),
            Some(1)
        );

        let mut different_password = CompositeKey::default();
        different_password.add_password("b");
        let synced = core
            .load_kdbx(
                FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD,
                &different_password,
            )
            .expect("load sync fixture with different password");
        assert_eq!(synced.root.children.len(), 7);
        let general = find_group_by_title(&synced.root, "General").expect("general group");
        assert_eq!(general.entries.len(), 1);
        assert_eq!(
            synced.root.children.last().map(|group| group.entries.len()),
            Some(1)
        );
    }

    #[test]
    fn loads_merge_fixture_with_richer_field_oracle() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_MERGE_DATABASE, &key)
            .expect("load merge fixture");

        assert_eq!(vault.root.title, "NewDatabase");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.entries.len(), 1);
        assert_eq!(vault.root.children.len(), 7);

        let root_entry = &vault.root.entries[0];
        assert_eq!(root_entry.title, "Sample Entry");
        assert_eq!(root_entry.username, "User Name");
        assert_eq!(root_entry.url, "http://www.somesite.com/");
        assert_eq!(root_entry.notes, "Notes");
        assert_eq!(root_entry.history.len(), 3);
        assert_eq!(
            root_entry
                .history
                .iter()
                .map(|entry| (
                    entry.title.as_str(),
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                    entry.attachments.len(),
                    entry.field_protection,
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Sample Entry",
                    "User Name",
                    "Password",
                    "http://www.somesite.com/",
                    "Notes",
                    0,
                    EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    },
                ),
                (
                    "Sample Entry",
                    "User Name",
                    "Password",
                    "http://www.somesite.com/",
                    "Notes",
                    0,
                    EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    },
                ),
                (
                    "Sample Entry",
                    "User Name 1",
                    "Password",
                    "http://www.somesite.com/",
                    "Notes",
                    0,
                    EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    },
                ),
            ]
        );

        let general = find_group_by_title(&vault.root, "General").expect("general group");
        assert_eq!(general.entries.len(), 1);
        assert_eq!(general.entries[0].title, "pc");

        let extra = find_group_by_title(&vault.root, "TestExtraGroup").expect("extra group");
        assert_eq!(extra.entries.len(), 1);
        assert_eq!(extra.entries[0].title, "b");

        let homebanking = find_group_by_title(&vault.root, "Homebanking").expect("homebanking");
        assert!(homebanking.children.is_empty());
        assert!(homebanking.entries.is_empty());
    }

    #[test]
    fn loads_sync_fixtures_with_richer_field_oracle() {
        let core = KeepassCore::new();

        for (bytes, password, expected_name) in [
            (FIXTURE_SYNC_DATABASE, "a", Some("SyncDatabase")),
            (FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b", None),
        ] {
            let mut key = CompositeKey::default();
            key.add_password(password);

            let vault = core.load_kdbx(bytes, &key).expect("load sync fixture");

            assert_eq!(
                if vault.name.is_empty() {
                    None
                } else {
                    Some(vault.name.as_str())
                },
                expected_name
            );
            assert_eq!(vault.root.title, "NewDatabase");
            assert_eq!(vault.root.icon_id, Some(49));
            assert_eq!(vault.root.children.len(), 7);
            assert_eq!(vault.root.entries.len(), 1);

            let root_entry = &vault.root.entries[0];
            assert_eq!(root_entry.title, "Sample Entry");
            assert_eq!(root_entry.username, "User Name");
            assert_eq!(root_entry.url, "http://www.somesite.com/");
            assert_eq!(root_entry.notes, "Notes");
            assert_eq!(root_entry.history.len(), 10);
            assert_eq!(root_entry.attachments.len(), 1);
            assert_eq!(root_entry.history[0].title, "Sample Entry");
            assert_eq!(root_entry.history[0].username, "User Name");
            assert_eq!(root_entry.history[0].password, "Password");
            assert_eq!(root_entry.history[0].url, "http://www.somesite.com/");
            assert_eq!(root_entry.history[0].notes, "Notes");
            assert!(root_entry.history[0].attachments.is_empty());
            assert_eq!(
                root_entry.history[2].field_protection,
                EntryFieldProtection {
                    protect_title: false,
                    protect_username: false,
                    protect_password: true,
                    protect_url: false,
                    protect_notes: false,
                }
            );
            assert_eq!(
                root_entry
                    .attachments
                    .get("Sample attachment.txt")
                    .map(|attachment| attachment.data.as_bytes().to_vec()),
                Some(b"Sample content\n".to_vec())
            );
            assert_eq!(
                root_entry.history.last().and_then(|entry| {
                    entry
                        .attachments
                        .get("Sample attachment.txt")
                        .map(|attachment| attachment.data.as_bytes().to_vec())
                }),
                Some(b"Sample content \n".to_vec())
            );
            assert_eq!(
                root_entry.history.last().map(|entry| (
                    entry.title.as_str(),
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                )),
                Some((
                    "Sample Entry",
                    "User Name",
                    "Password",
                    "http://www.somesite.com/",
                    "Notes",
                ))
            );

            let subgroup = find_group_by_title(
                find_group_by_title(&vault.root, "Homebanking").expect("homebanking"),
                "Subgroup",
            )
            .expect("subgroup");
            assert_eq!(subgroup.entries.len(), 1);
            let bank_entry = &subgroup.entries[0];
            assert_eq!(bank_entry.title, "Subgroup Entry");
            assert_eq!(bank_entry.username, "Bank User Name");
            assert_eq!(bank_entry.url, "https://www.bank.com");
            assert_eq!(bank_entry.notes, "Important note");
            assert_eq!(bank_entry.history.len(), 2);
            assert_eq!(
                bank_entry.history.first().map(|entry| (
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                    entry.field_protection,
                )),
                Some((
                    "",
                    "",
                    "",
                    "",
                    EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    },
                ))
            );
            assert_eq!(
                bank_entry.history.get(1).map(|entry| (
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                    entry.field_protection,
                )),
                Some((
                    "Bank User Name",
                    "SecurePassword",
                    "https:/www.bank.com",
                    "Important note",
                    EntryFieldProtection {
                        protect_title: false,
                        protect_username: false,
                        protect_password: true,
                        protect_url: false,
                        protect_notes: false,
                    },
                ))
            );
        }
    }

    #[test]
    fn kdbx4_roundtrip_preserves_group_custom_icon_uuid() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("group-custom-icon");

        let mut vault = Vault::empty("GroupIcons");
        let custom_icon_id = vaultkern_model::CustomIcon {
            id: vault.root.id,
            data: vec![9, 8, 7, 6],
            name: None,
            last_modified: None,
        };
        vault.custom_icons.push(custom_icon_id.clone());

        let mut group = vaultkern_model::Group::new("Styled");
        group.custom_icon_id = Some(custom_icon_id.id);
        let group_id = group.id;
        vault.root.children.push(group);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save bytes");
        let loaded = core.load_kdbx(&bytes, &key).expect("load bytes");
        let loaded_group = find_group(&loaded.root, &group_id.to_string()).expect("group");
        assert_eq!(loaded_group.custom_icon_id, Some(custom_icon_id.id));
    }

    #[test]
    fn kdbx4_roundtrip_preserves_entry_history_with_attachments() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("history-roundtrip");

        let mut vault = Vault::empty("History");
        let mut entry = Entry::new("Current");
        entry.username = "user-current".into();
        entry.url = "https://current.example".into();
        entry.notes = "current notes".into();
        entry.created_at = 100;
        entry.modified_at = 200;
        entry.usage_count = Some(9);
        entry.attachments.insert(
            "current.txt".into(),
            Attachment {
                name: "current.txt".into(),
                data: b"current".to_vec(),
                protect_in_memory: true,
            },
        );

        let mut history_a = Entry::new("Older");
        history_a.username = "user-a".into();
        history_a.url = "https://older.example".into();
        history_a.notes = "older notes".into();
        history_a.created_at = 10;
        history_a.modified_at = 11;
        history_a.usage_count = Some(3);
        history_a.attachments.insert(
            "archive.txt".into(),
            Attachment {
                name: "archive.txt".into(),
                data: b"archive-a".to_vec(),
                protect_in_memory: false,
            },
        );

        let mut history_b = Entry::new("Middle");
        history_b.username = "user-b".into();
        history_b.url = "https://middle.example".into();
        history_b.notes = "middle notes".into();
        history_b.created_at = 20;
        history_b.modified_at = 21;
        history_b.usage_count = Some(7);
        history_b.attachments.insert(
            "archive.txt".into(),
            Attachment {
                name: "archive.txt".into(),
                data: b"archive-b".to_vec(),
                protect_in_memory: false,
            },
        );

        entry.history.push(history_a);
        entry.history.push(history_b);
        vault.root.entries.push(entry);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save history");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload history");

        let entry = &loaded.root.entries[0];
        assert_eq!(entry.history.len(), 2);
        assert_eq!(entry.history[0].title, "Older");
        assert_eq!(entry.history[0].url, "https://older.example");
        assert_eq!(entry.history[0].usage_count, Some(3));
        assert_eq!(
            entry.history[0]
                .attachments
                .get("archive.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"archive-a".to_vec())
        );
        assert_eq!(entry.history[1].title, "Middle");
        assert_eq!(entry.history[1].url, "https://middle.example");
        assert_eq!(entry.history[1].usage_count, Some(7));
        assert_eq!(
            entry.history[1]
                .attachments
                .get("archive.txt")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(b"archive-b".to_vec())
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_attachment_protection_flags_for_shared_binary_data() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("attachment-protection");

        let mut vault = Vault::empty("AttachmentProtection");
        let shared = b"same-bytes".to_vec();

        let mut protected_entry = Entry::new("ProtectedAttachment");
        protected_entry.attachments.insert(
            "protected.bin".into(),
            Attachment {
                name: "protected.bin".into(),
                data: shared.clone(),
                protect_in_memory: true,
            },
        );

        let mut unprotected_entry = Entry::new("UnprotectedAttachment");
        unprotected_entry.attachments.insert(
            "plain.bin".into(),
            Attachment {
                name: "plain.bin".into(),
                data: shared,
                protect_in_memory: false,
            },
        );

        vault.root.entries.push(protected_entry);
        vault.root.entries.push(unprotected_entry);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save attachment protection fixture");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload attachment protection fixture");

        assert_eq!(
            loaded.root.entries[0]
                .attachments
                .get("protected.bin")
                .map(|attachment| attachment.protect_in_memory),
            Some(true)
        );
        assert_eq!(
            loaded.root.entries[1]
                .attachments
                .get("plain.bin")
                .map(|attachment| attachment.protect_in_memory),
            Some(false)
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_attachment_index_stability_across_entries_and_history() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("attachment-index-stability");

        let attachment_a = b"qwerty".to_vec();
        let attachment_b = b"asdf".to_vec();
        let attachment_c = b"zxcv".to_vec();

        let mut vault = Vault::empty("AttachmentIndex");

        let mut entry1 = Entry::new("Entry1");
        entry1.attachments.insert(
            "a".into(),
            Attachment {
                name: "a".into(),
                data: attachment_a.clone(),
                protect_in_memory: false,
            },
        );

        let mut entry2 = Entry::new("Entry2");
        entry2.attachments.insert(
            "a".into(),
            Attachment {
                name: "a".into(),
                data: attachment_a.clone(),
                protect_in_memory: false,
            },
        );
        entry2.attachments.insert(
            "b".into(),
            Attachment {
                name: "b".into(),
                data: attachment_b.clone(),
                protect_in_memory: false,
            },
        );

        let mut entry3 = Entry::new("Entry3");
        entry3.attachments.insert(
            "a".into(),
            Attachment {
                name: "a".into(),
                data: attachment_a.clone(),
                protect_in_memory: false,
            },
        );
        entry3.attachments.insert(
            "b".into(),
            Attachment {
                name: "b".into(),
                data: attachment_b.clone(),
                protect_in_memory: false,
            },
        );
        entry3.attachments.insert(
            "x".into(),
            Attachment {
                name: "x".into(),
                data: attachment_c.clone(),
                protect_in_memory: false,
            },
        );
        entry3.attachments.insert(
            "y".into(),
            Attachment {
                name: "y".into(),
                data: attachment_c.clone(),
                protect_in_memory: false,
            },
        );

        let mut history = Entry::new("Entry3 history");
        history.attachments.insert(
            "x".into(),
            Attachment {
                name: "x".into(),
                data: attachment_c.clone(),
                protect_in_memory: false,
            },
        );
        history.attachments.insert(
            "y".into(),
            Attachment {
                name: "y".into(),
                data: attachment_b.clone(),
                protect_in_memory: false,
            },
        );
        entry3.history.push(history);

        vault.root.entries.push(entry1);
        vault.root.entries.push(entry2);
        vault.root.entries.push(entry3);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save attachment index stability fixture");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload attachment index stability fixture");

        assert_eq!(
            loaded.root.entries[0]
                .attachments
                .get("a")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_a.clone())
        );

        assert_eq!(
            loaded.root.entries[1]
                .attachments
                .get("a")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_a.clone())
        );
        assert_eq!(
            loaded.root.entries[1]
                .attachments
                .get("b")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_b.clone())
        );

        assert_eq!(
            loaded.root.entries[2]
                .attachments
                .get("a")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_a)
        );
        assert_eq!(
            loaded.root.entries[2]
                .attachments
                .get("b")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_b.clone())
        );
        assert_eq!(
            loaded.root.entries[2]
                .attachments
                .get("x")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_c.clone())
        );
        assert_eq!(
            loaded.root.entries[2]
                .attachments
                .get("y")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_c.clone())
        );

        assert_eq!(loaded.root.entries[2].history.len(), 1);
        assert_eq!(
            loaded.root.entries[2].history[0]
                .attachments
                .get("x")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_c)
        );
        assert_eq!(
            loaded.root.entries[2].history[0]
                .attachments
                .get("y")
                .map(|attachment| attachment.data.as_bytes().to_vec()),
            Some(attachment_b)
        );
    }

    #[test]
    fn external_kdbx4_golden_roundtrip_preserves_summary() {
        let core = KeepassCore::new();

        for (bytes, password) in [
            (FIXTURE_NEW_DATABASE, "a"),
            (FIXTURE_NEW_DATABASE_BROWSER, "a"),
            (FIXTURE_SYNC_DATABASE, "a"),
        ] {
            let mut key = CompositeKey::default();
            key.add_password(password);

            let loaded = core.load_kdbx(bytes, &key).expect("load fixture");
            let summary_before = summarize_group_for_golden(&loaded.root, "");

            let rewritten = core
                .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
                .expect("save fixture");
            let reloaded = core.load_kdbx(&rewritten, &key).expect("reload fixture");
            let summary_after = summarize_group_for_golden(&reloaded.root, "");

            assert_eq!(summary_after, summary_before);
        }
    }

    #[test]
    fn loads_multi_fixture_with_richer_history_oracle() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let vault = core
            .load_kdbx(FIXTURE_NEW_DATABASE_MULTI, &key)
            .expect("load multi fixture");

        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.entries.len(), 3);

        let single = &vault.root.entries[0];
        assert_eq!(single.title, "Single Entry");
        assert_eq!(single.username, "User Name");
        assert_eq!(single.history.len(), 6);
        assert!(
            single
                .history
                .iter()
                .all(|entry| entry.title == "Sample Entry"
                    && entry.url == "http://www.somesite.com/")
        );

        let multi_1 = &vault.root.entries[1];
        assert_eq!(multi_1.title, "Multi Entry 1");
        assert_eq!(multi_1.username, "Multi Name 1");
        assert_eq!(multi_1.history.len(), 7);
        assert_eq!(
            multi_1.history.last().map(|entry| entry.title.as_str()),
            Some("Sample Entry 2")
        );
        assert_eq!(
            multi_1.history.last().map(|entry| entry.username.as_str()),
            Some("User Name 2")
        );

        let multi_2 = &vault.root.entries[2];
        assert_eq!(multi_2.title, "Multi Entry 2");
        assert_eq!(multi_2.username, "Multi Name 2");
        assert_eq!(multi_2.history.len(), 7);
        assert_eq!(
            multi_2.history.last().map(|entry| entry.title.as_str()),
            Some("Sample Entry 3")
        );
        assert_eq!(
            multi_2.history.last().map(|entry| entry.username.as_str()),
            Some("User Name 3")
        );

        let homebanking = find_group_by_title(&vault.root, "Homebanking").expect("homebanking");
        let subgroup = find_group_by_title(homebanking, "Subgroup").expect("bank subgroup");
        let bank_entry = &subgroup.entries[0];
        assert_eq!(bank_entry.title, "Subgroup Entry");
        assert_eq!(bank_entry.history.len(), 1);
        assert_eq!(
            bank_entry.history.first().map(|entry| entry.title.as_str()),
            Some("Subgroup Entry")
        );
    }

    #[test]
    fn rich_browser_and_multi_fixtures_preserve_field_oracle_on_roundtrip() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        for bytes in [FIXTURE_NEW_DATABASE_BROWSER, FIXTURE_NEW_DATABASE_MULTI] {
            let loaded = core.load_kdbx(bytes, &key).expect("load fixture");
            let rewritten = core
                .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
                .expect("save fixture");
            let reloaded = core.load_kdbx(&rewritten, &key).expect("reload fixture");

            assert_eq!(reloaded.root.title, loaded.root.title);
            assert_eq!(reloaded.root.icon_id, loaded.root.icon_id);
            assert_eq!(reloaded.root.children.len(), loaded.root.children.len());
            assert_eq!(reloaded.root.entries.len(), loaded.root.entries.len());

            for (entry, roundtrip) in loaded.root.entries.iter().zip(reloaded.root.entries.iter()) {
                assert_eq!(roundtrip.title, entry.title);
                assert_eq!(roundtrip.username, entry.username);
                assert_eq!(roundtrip.url, entry.url);
                assert_eq!(roundtrip.notes, entry.notes);
                assert_eq!(roundtrip.custom_data, entry.custom_data);
                assert_eq!(roundtrip.history.len(), entry.history.len());
                assert_eq!(roundtrip.field_protection, entry.field_protection);
                assert_eq!(
                    roundtrip
                        .auto_type
                        .as_ref()
                        .map(|auto| auto.associations.len()),
                    entry.auto_type.as_ref().map(|auto| auto.associations.len())
                );
            }

            let loaded_home =
                find_group_by_title(&loaded.root, "Homebanking").expect("loaded home");
            let reloaded_home =
                find_group_by_title(&reloaded.root, "Homebanking").expect("reloaded home");
            let loaded_sub = find_group_by_title(loaded_home, "Subgroup").expect("loaded subgroup");
            let reloaded_sub =
                find_group_by_title(reloaded_home, "Subgroup").expect("reloaded subgroup");
            assert_eq!(reloaded_sub.entries.len(), loaded_sub.entries.len());
            assert_eq!(reloaded_sub.entries[0].title, loaded_sub.entries[0].title);
            assert_eq!(
                reloaded_sub.entries[0].username,
                loaded_sub.entries[0].username
            );
            assert_eq!(reloaded_sub.entries[0].url, loaded_sub.entries[0].url);
            assert_eq!(reloaded_sub.entries[0].notes, loaded_sub.entries[0].notes);
            assert_eq!(
                reloaded_sub.entries[0].history.len(),
                loaded_sub.entries[0].history.len()
            );
        }
    }

    #[test]
    fn merge_and_sync_fixtures_preserve_field_oracle_on_roundtrip() {
        let core = KeepassCore::new();

        for (bytes, password) in [
            (FIXTURE_MERGE_DATABASE, "a"),
            (FIXTURE_SYNC_DATABASE, "a"),
            (FIXTURE_SYNC_DATABASE_DIFFERENT_PASSWORD, "b"),
        ] {
            let mut key = CompositeKey::default();
            key.add_password(password);

            let loaded = core.load_kdbx(bytes, &key).expect("load fixture");
            let rewritten = core
                .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
                .expect("save fixture");
            let reloaded = core.load_kdbx(&rewritten, &key).expect("reload fixture");

            assert_eq!(
                if reloaded.name.is_empty() {
                    None
                } else {
                    Some(reloaded.name.as_str())
                },
                if loaded.name.is_empty() {
                    None
                } else {
                    Some(loaded.name.as_str())
                }
            );
            assert_eq!(reloaded.root.title, loaded.root.title);
            assert_eq!(reloaded.root.icon_id, loaded.root.icon_id);
            assert_eq!(reloaded.root.children.len(), loaded.root.children.len());
            assert_eq!(reloaded.root.entries.len(), loaded.root.entries.len());

            let loaded_root_entry = &loaded.root.entries[0];
            let reloaded_root_entry = &reloaded.root.entries[0];
            assert_eq!(reloaded_root_entry.title, loaded_root_entry.title);
            assert_eq!(reloaded_root_entry.username, loaded_root_entry.username);
            assert_eq!(reloaded_root_entry.url, loaded_root_entry.url);
            assert_eq!(reloaded_root_entry.notes, loaded_root_entry.notes);
            assert_eq!(
                reloaded_root_entry.history.len(),
                loaded_root_entry.history.len()
            );
            assert_eq!(
                reloaded_root_entry.field_protection,
                loaded_root_entry.field_protection
            );
            assert_eq!(
                reloaded_root_entry
                    .attachments
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                loaded_root_entry
                    .attachments
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            );

            let loaded_general =
                find_group_by_title(&loaded.root, "General").expect("loaded general group");
            let reloaded_general =
                find_group_by_title(&reloaded.root, "General").expect("reloaded general group");
            assert_eq!(reloaded_general.entries.len(), loaded_general.entries.len());
            if let (Some(loaded_entry), Some(reloaded_entry)) = (
                loaded_general.entries.first(),
                reloaded_general.entries.first(),
            ) {
                assert_eq!(reloaded_entry.title, loaded_entry.title);
            }

            let loaded_extra = find_group_by_title(&loaded.root, "TestExtraGroup");
            let reloaded_extra = find_group_by_title(&reloaded.root, "TestExtraGroup");
            assert_eq!(reloaded_extra.is_some(), loaded_extra.is_some());
            if let (Some(loaded_group), Some(reloaded_group)) = (loaded_extra, reloaded_extra) {
                assert_eq!(reloaded_group.entries.len(), loaded_group.entries.len());
                assert_eq!(
                    reloaded_group.entries[0].title,
                    loaded_group.entries[0].title
                );
            }

            let loaded_home =
                find_group_by_title(&loaded.root, "Homebanking").expect("loaded homebanking");
            let reloaded_home =
                find_group_by_title(&reloaded.root, "Homebanking").expect("reloaded homebanking");
            assert_eq!(reloaded_home.children.len(), loaded_home.children.len());
            if let (Some(loaded_sub), Some(reloaded_sub)) = (
                find_group_by_title(loaded_home, "Subgroup"),
                find_group_by_title(reloaded_home, "Subgroup"),
            ) {
                assert_eq!(reloaded_sub.entries.len(), loaded_sub.entries.len());
                assert_eq!(reloaded_sub.entries[0].title, loaded_sub.entries[0].title);
                assert_eq!(
                    reloaded_sub.entries[0].username,
                    loaded_sub.entries[0].username
                );
                assert_eq!(reloaded_sub.entries[0].url, loaded_sub.entries[0].url);
                assert_eq!(reloaded_sub.entries[0].notes, loaded_sub.entries[0].notes);
                assert_eq!(
                    reloaded_sub.entries[0].history.len(),
                    loaded_sub.entries[0].history.len()
                );
            }
        }
    }

    #[test]
    fn rich_history_fixtures_preserve_deep_history_oracle_on_roundtrip() {
        let core = KeepassCore::new();

        for (bytes, password, expected_root_history, expected_bank_history) in [
            (FIXTURE_NEW_DATABASE_BROWSER, "a", 3usize, Some(1usize)),
            (FIXTURE_SYNC_DATABASE, "a", 10usize, Some(2usize)),
        ] {
            let mut key = CompositeKey::default();
            key.add_password(password);

            let loaded = core.load_kdbx(bytes, &key).expect("load fixture");
            let rewritten = core
                .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
                .expect("save fixture");
            let reloaded = core.load_kdbx(&rewritten, &key).expect("reload fixture");

            let loaded_root = &loaded.root.entries[0];
            let reloaded_root = &reloaded.root.entries[0];
            assert_eq!(reloaded_root.history.len(), expected_root_history);
            assert_eq!(reloaded_root.history.len(), loaded_root.history.len());
            assert_eq!(
                reloaded_root
                    .history
                    .iter()
                    .map(|entry| (
                        entry.title.as_str(),
                        entry.username.as_str(),
                        entry.password.as_str(),
                        entry.url.as_str(),
                        entry.notes.as_str(),
                        entry.attachments.keys().cloned().collect::<Vec<_>>(),
                        entry.field_protection,
                    ))
                    .collect::<Vec<_>>(),
                loaded_root
                    .history
                    .iter()
                    .map(|entry| (
                        entry.title.as_str(),
                        entry.username.as_str(),
                        entry.password.as_str(),
                        entry.url.as_str(),
                        entry.notes.as_str(),
                        entry.attachments.keys().cloned().collect::<Vec<_>>(),
                        entry.field_protection,
                    ))
                    .collect::<Vec<_>>()
            );

            let loaded_home =
                find_group_by_title(&loaded.root, "Homebanking").expect("loaded home");
            let reloaded_home =
                find_group_by_title(&reloaded.root, "Homebanking").expect("reloaded home");
            let loaded_sub = find_group_by_title(loaded_home, "Subgroup").expect("loaded subgroup");
            let reloaded_sub =
                find_group_by_title(reloaded_home, "Subgroup").expect("reloaded subgroup");
            let loaded_bank = &loaded_sub.entries[0];
            let reloaded_bank = &reloaded_sub.entries[0];
            assert_eq!(
                reloaded_bank.history.len(),
                expected_bank_history.unwrap_or(0)
            );
            assert_eq!(reloaded_bank.history.len(), loaded_bank.history.len());
            assert_eq!(
                reloaded_bank
                    .history
                    .iter()
                    .map(|entry| (
                        entry.title.as_str(),
                        entry.username.as_str(),
                        entry.password.as_str(),
                        entry.url.as_str(),
                        entry.notes.as_str(),
                        entry.attachments.keys().cloned().collect::<Vec<_>>(),
                        entry.field_protection,
                    ))
                    .collect::<Vec<_>>(),
                loaded_bank
                    .history
                    .iter()
                    .map(|entry| (
                        entry.title.as_str(),
                        entry.username.as_str(),
                        entry.password.as_str(),
                        entry.url.as_str(),
                        entry.notes.as_str(),
                        entry.attachments.keys().cloned().collect::<Vec<_>>(),
                        entry.field_protection,
                    ))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn merge_history_fixture_preserves_deep_history_oracle_on_roundtrip() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("a");

        let loaded = core
            .load_kdbx(FIXTURE_MERGE_DATABASE, &key)
            .expect("load merge fixture");
        let rewritten = core
            .save_kdbx(&loaded, &key, super::SaveProfile::recommended())
            .expect("save merge fixture");
        let reloaded = core
            .load_kdbx(&rewritten, &key)
            .expect("reload merge fixture");

        let loaded_root = &loaded.root.entries[0];
        let reloaded_root = &reloaded.root.entries[0];
        assert_eq!(reloaded_root.history.len(), 3);
        assert_eq!(reloaded_root.history.len(), loaded_root.history.len());
        assert_eq!(
            reloaded_root
                .history
                .iter()
                .map(|entry| (
                    entry.title.as_str(),
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                    entry.attachments.keys().cloned().collect::<Vec<_>>(),
                    entry.field_protection,
                ))
                .collect::<Vec<_>>(),
            loaded_root
                .history
                .iter()
                .map(|entry| (
                    entry.title.as_str(),
                    entry.username.as_str(),
                    entry.password.as_str(),
                    entry.url.as_str(),
                    entry.notes.as_str(),
                    entry.attachments.keys().cloned().collect::<Vec<_>>(),
                    entry.field_protection,
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn kdbx4_roundtrip_preserves_group_and_entry_schema_depth() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("group-entry-roundtrip");

        let mut vault = Vault::empty("Schema");
        vault.root.notes = "Root notes".into();
        vault.root.icon_id = Some(49);
        vault.root.times = Some(GroupTimes {
            created_at: 1,
            modified_at: 2,
            expires: false,
            expiry_time: None,
            last_accessed_at: Some(3),
            usage_count: Some(4),
            location_changed_at: Some(5),
        });
        vault.root.flags = GroupFlags {
            is_expanded: Some(true),
            enable_auto_type: Some(false),
            enable_searching: Some(true),
        };
        vault.root.default_auto_type_sequence = Some("{USERNAME}".into());
        vault.root.last_top_visible_entry = Some(vault.root.id);

        let mut entry = Entry::new("Depth");
        entry.icon_id = Some(7);
        entry.custom_icon_id = Some(vault.root.id);
        entry.foreground_color = Some("#112233".into());
        entry.background_color = Some("#445566".into());
        entry.override_url = Some("https://override.example".into());
        entry.created_at = 10;
        entry.modified_at = 11;
        entry.expires = true;
        entry.expiry_time = Some(12);
        entry.last_accessed_at = Some(13);
        entry.usage_count = Some(14);
        entry.location_changed_at = Some(15);
        entry.field_protection = EntryFieldProtection {
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: true,
            protect_notes: false,
        };
        entry.auto_type = Some(AutoTypeConfig {
            enabled: Some(true),
            obfuscation: Some(2),
            default_sequence: Some("{TITLE}{ENTER}".into()),
            associations: vec![AutoTypeAssociation {
                window: "App".into(),
                sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
            }],
        });
        vault.root.entries.push(entry);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save schema depth");
        let loaded = core.load_kdbx(&bytes, &key).expect("reload schema depth");

        assert_eq!(loaded.root.notes, "Root notes");
        assert_eq!(loaded.root.icon_id, Some(49));
        assert_eq!(
            loaded.root.times,
            Some(GroupTimes {
                created_at: 1,
                modified_at: 2,
                expires: false,
                expiry_time: None,
                last_accessed_at: Some(3),
                usage_count: Some(4),
                location_changed_at: Some(5),
            })
        );
        assert_eq!(
            loaded.root.flags,
            GroupFlags {
                is_expanded: Some(true),
                enable_auto_type: Some(false),
                enable_searching: Some(true),
            }
        );
        assert_eq!(
            loaded.root.default_auto_type_sequence.as_deref(),
            Some("{USERNAME}")
        );
        assert_eq!(loaded.root.last_top_visible_entry, Some(vault.root.id));

        let entry = &loaded.root.entries[0];
        assert_eq!(entry.icon_id, Some(7));
        assert_eq!(entry.custom_icon_id, Some(vault.root.id));
        assert_eq!(entry.foreground_color.as_deref(), Some("#112233"));
        assert_eq!(entry.background_color.as_deref(), Some("#445566"));
        assert_eq!(
            entry.override_url.as_deref(),
            Some("https://override.example")
        );
        assert_eq!(entry.last_accessed_at, Some(13));
        assert_eq!(entry.usage_count, Some(14));
        assert_eq!(entry.location_changed_at, Some(15));
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: true,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(2),
                default_sequence: Some("{TITLE}{ENTER}".into()),
                associations: vec![AutoTypeAssociation {
                    window: "App".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
                }],
            })
        );
    }

    #[test]
    fn loads_recycle_bin_metadata_from_external_fixtures() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("123");

        let disabled = core
            .load_database(FIXTURE_RECYCLE_BIN_DISABLED, &key)
            .expect("load recycle bin disabled fixture");
        assert_recycle_bin_fixture(
            &disabled.vault,
            Some(false),
            None,
            &["Mail", "Network", "Computer logins"],
            None,
        );

        let not_created = core
            .load_database(FIXTURE_RECYCLE_BIN_NOT_YET_CREATED, &key)
            .expect("load recycle bin not yet created fixture");
        assert_recycle_bin_fixture(
            &not_created.vault,
            Some(true),
            None,
            &["Mail", "Network", "Computer logins"],
            None,
        );

        let empty = core
            .load_database(FIXTURE_RECYCLE_BIN_EMPTY, &key)
            .expect("load recycle bin empty fixture");
        assert_recycle_bin_fixture(
            &empty.vault,
            Some(true),
            Some(("Recycle Bin", 0, 0, &[])),
            &["Mail", "Network", "Computer logins", "Recycle Bin"],
            None,
        );

        let with_data = core
            .load_database(FIXTURE_RECYCLE_BIN_WITH_DATA, &key)
            .expect("load recycle bin with data fixture");
        assert_recycle_bin_fixture(
            &with_data.vault,
            Some(true),
            Some(("Recycle Bin", 2, 2, &["Abandoned stuff", "Mac related"])),
            &["Mail", "Network", "Computer logins", "Recycle Bin"],
            Some(("Obsolete e-mail", &["Abandoned stuff", "Mac related"])),
        );
    }

    #[test]
    fn recycle_bin_fixture_matrix_upgrades_to_kdbx4_1_without_losing_semantics() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("123");

        let fixtures = [
            (
                FIXTURE_RECYCLE_BIN_DISABLED,
                Some(false),
                None,
                &["Mail", "Network", "Computer logins"][..],
                None,
            ),
            (
                FIXTURE_RECYCLE_BIN_NOT_YET_CREATED,
                Some(true),
                None,
                &["Mail", "Network", "Computer logins"][..],
                None,
            ),
            (
                FIXTURE_RECYCLE_BIN_EMPTY,
                Some(true),
                Some(("Recycle Bin", 0, 0, &[][..])),
                &["Mail", "Network", "Computer logins", "Recycle Bin"][..],
                None,
            ),
            (
                FIXTURE_RECYCLE_BIN_WITH_DATA,
                Some(true),
                Some(("Recycle Bin", 2, 2, &["Abandoned stuff", "Mac related"][..])),
                &["Mail", "Network", "Computer logins", "Recycle Bin"][..],
                Some(("Obsolete e-mail", &["Abandoned stuff", "Mac related"][..])),
            ),
        ];

        for (fixture, enabled, recycle_bin_shape, root_children, with_data_shape) in fixtures {
            let loaded = core
                .load_database(fixture, &key)
                .expect("load recycle bin fixture");
            let rewritten = core
                .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
                .expect("rewrite recycle bin fixture");
            let inspection = core
                .inspect_database(&rewritten)
                .expect("inspect rewritten recycle bin fixture");
            let reloaded = core
                .load_kdbx(&rewritten, &key)
                .expect("reload rewritten recycle bin fixture");

            assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
            assert_recycle_bin_fixture(
                &reloaded,
                enabled,
                recycle_bin_shape,
                root_children,
                with_data_shape,
            );
        }
    }

    #[test]
    fn kdbx4_roundtrip_preserves_recycle_bin_and_template_group_metadata() {
        let core = KeepassCore::new();
        let mut key = CompositeKey::default();
        key.add_password("roundtrip-metadata");

        let mut vault = Vault::empty("Metadata");
        let recycle_bin = vaultkern_model::Group::new("Recycle Bin");
        let recycle_bin_id = recycle_bin.id;
        let templates = vaultkern_model::Group::new("Templates");
        let templates_id = templates.id;
        vault.root.children.push(recycle_bin);
        vault.root.children.push(templates);
        vault.recycle_bin_enabled = Some(true);
        vault.recycle_bin_group = Some(recycle_bin_id);
        vault.recycle_bin_changed = Some(1_282_752_777);
        vault.entry_templates_group = Some(templates_id);
        vault.entry_templates_group_changed = Some(1_281_226_259);

        let bytes = core
            .save_kdbx(&vault, &key, super::SaveProfile::recommended())
            .expect("save metadata fixture");
        let loaded = core
            .load_kdbx(&bytes, &key)
            .expect("reload metadata fixture");

        assert_eq!(loaded.recycle_bin_enabled, Some(true));
        assert_eq!(loaded.recycle_bin_group, Some(recycle_bin_id));
        assert_eq!(loaded.recycle_bin_changed, Some(1_282_752_777));
        assert_eq!(loaded.entry_templates_group, Some(templates_id));
        assert_eq!(loaded.entry_templates_group_changed, Some(1_281_226_259));
    }

    fn assert_test_fixture_contents(vault: &Vault, expected_attachment_protection: bool) {
        assert_eq!(vault.root.entries.len(), 1);
        let entry = vault.root.entries.first().expect("entry");
        assert_eq!(entry.title, "test");
        assert_eq!(entry.username, "test");
        assert_eq!(entry.password, "test");
        assert_eq!(entry.url, "test.com");
        assert_eq!(entry.notes, "test");
        assert!(entry.tags.contains("test"));
        assert!(entry.expires);
        assert_eq!(
            entry.expiry_time.map(|value| value / 60),
            Some(1_806_508_800 / 60)
        );
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.attachments.get("test").map(|attachment| (
                attachment.data.as_bytes().to_vec(),
                attachment.protect_in_memory
            )),
            Some((b"test".to_vec(), expected_attachment_protection))
        );
        assert_eq!(
            entry
                .attributes
                .get("test")
                .map(|field| (field.value.as_str(), field.protected)),
            Some(("test", false))
        );
        assert_eq!(
            entry
                .attributes
                .get("protected")
                .map(|field| field.value.as_str()),
            Some("protected")
        );
        assert_eq!(
            entry
                .attributes
                .get("protected")
                .map(|field| field.protected),
            Some(true)
        );
    }

    fn assert_key_file_fixture_contents(
        vault: &Vault,
        first_created_at: u64,
        second_created_at: u64,
    ) {
        assert_eq!(vault.root.entries.len(), 2);

        let first = &vault.root.entries[0];
        assert_eq!(first.title, "entry1");
        assert_eq!(first.username, "username");
        assert_eq!(first.password, "password");
        assert_eq!(first.url, "");
        assert_eq!(first.notes, "");
        assert!(first.tags.is_empty());
        assert_eq!(
            first.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert!(first.attributes.is_empty());
        assert!(first.attachments.is_empty());
        assert!(first.history.is_empty());
        assert_eq!(first.icon_id, Some(0));
        assert_eq!(first.created_at, first_created_at);
        assert_eq!(first.expires, false);
        assert_eq!(first.expiry_time, Some(first_created_at as i64));
        assert_eq!(first.usage_count, Some(0));
        assert_eq!(
            first.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: Some(String::new()),
                associations: Vec::new(),
            })
        );

        let second = &vault.root.entries[1];
        assert_eq!(second.title, "entry2");
        assert_eq!(second.username, "username");
        assert_eq!(second.password, "password");
        assert_eq!(second.url, "");
        assert_eq!(second.notes, "");
        assert!(second.tags.is_empty());
        assert_eq!(
            second.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert!(second.attributes.is_empty());
        assert!(second.attachments.is_empty());
        assert!(second.history.is_empty());
        assert_eq!(second.icon_id, Some(0));
        assert_eq!(second.created_at, second_created_at);
        assert_eq!(second.expires, false);
        assert_eq!(second.expiry_time, Some(second_created_at as i64));
        assert_eq!(second.usage_count, Some(0));
        assert_eq!(
            second.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: Some(String::new()),
                associations: Vec::new(),
            })
        );
    }

    fn assert_format300_fixture_contents(vault: &Vault) {
        assert_eq!(vault.generator.as_deref(), Some("KeePass"));
        assert_eq!(vault.name, "Test Database Format 0x00030000");
        assert_eq!(vault.database_name_changed, Some(1_348_590_987));
        assert_eq!(vault.description, None);
        assert_eq!(vault.default_username, None);
        assert_eq!(vault.maintenance_history_days, Some(365));
        assert_eq!(vault.master_key_changed, Some(1_348_590_935));
        assert_eq!(vault.master_key_change_rec, Some(-1));
        assert_eq!(vault.master_key_change_force, Some(-1));
        assert_eq!(vault.history_max_items, Some(10));
        assert_eq!(vault.history_max_size, Some(6_291_456));
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
        assert_eq!(vault.deleted_objects.len(), 2);
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert!(vault.recycle_bin_group.is_some());
        assert_eq!(vault.recycle_bin_changed, Some(1_348_590_935));
        assert_eq!(vault.entry_templates_group, None);
        assert_eq!(vault.entry_templates_group_changed, Some(1_348_590_935));

        assert_eq!(vault.root.title, "Format300");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));
        assert_eq!(vault.root.entries.len(), 1);
        assert_eq!(
            vault
                .root
                .children
                .iter()
                .map(|group| group.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "General",
                "Windows",
                "Network",
                "Internet",
                "eMail",
                "Homebanking"
            ]
        );
        assert_eq!(
            vault.root.last_top_visible_entry,
            Some(vault.root.entries[0].id)
        );

        let entry = &vault.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.username, "User Name");
        assert_eq!(entry.password, "Password");
        assert_eq!(entry.url, "http://www.somesite.com/");
        assert_eq!(entry.notes, "Notes");
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.history.len(), 0);
        assert_eq!(entry.usage_count, Some(0));
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: None,
                associations: vec![AutoTypeAssociation {
                    window: "Target Window".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into(),
                }],
            })
        );

        let expected_icons = [48, 38, 3, 1, 19, 37];
        for (group, expected_icon) in vault.root.children.iter().zip(expected_icons) {
            assert_eq!(group.icon_id, Some(expected_icon));
            assert!(group.entries.is_empty());
            assert!(group.children.is_empty());
            assert_eq!(group.flags.is_expanded, Some(true));
        }
    }

    fn assert_protected_strings_fixture_contents(vault: &Vault) {
        assert_eq!(vault.generator.as_deref(), Some("KeePass"));
        assert_eq!(vault.name, "Protected Strings Test");
        assert_eq!(vault.database_name_changed, Some(1_309_365_789));
        assert_eq!(vault.history_max_items, Some(10));
        assert_eq!(vault.history_max_size, Some(6_291_456));
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
        assert_eq!(vault.deleted_objects.len(), 1);
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert_eq!(vault.recycle_bin_group, None);
        assert_eq!(vault.recycle_bin_changed, Some(1_309_366_154));
        assert_eq!(vault.entry_templates_group, None);
        assert_eq!(vault.entry_templates_group_changed, Some(1_309_365_718));

        assert_eq!(vault.root.title, "Protected");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));
        assert_eq!(vault.root.entries.len(), 1);
        assert!(vault.root.children.is_empty());
        assert_eq!(
            vault.root.last_top_visible_entry,
            Some(vault.root.entries[0].id)
        );

        let entry = &vault.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.username, "Protected User Name");
        assert_eq!(entry.password, "ProtectedPassword");
        assert_eq!(entry.url, "http://www.somesite.com/");
        assert_eq!(entry.notes, "Notes");
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.usage_count, Some(4));
        assert_eq!(entry.history.len(), 1);
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry
                .attributes
                .get("TestProtected")
                .map(|field| field.value.as_str()),
            Some("ABC")
        );
        assert_eq!(
            entry
                .attributes
                .get("TestProtected")
                .map(|field| field.protected),
            Some(true)
        );
        assert_eq!(
            entry
                .attributes
                .get("TestUnprotected")
                .map(|field| field.value.as_str()),
            Some("DEF")
        );
        assert_eq!(
            entry
                .attributes
                .get("TestUnprotected")
                .map(|field| field.protected),
            Some(false)
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: None,
                associations: vec![AutoTypeAssociation {
                    window: "Target Window".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into(),
                }],
            })
        );

        let history = &entry.history[0];
        assert_eq!(history.title, "Sample Entry");
        assert_eq!(history.username, "Protected User Name");
        assert_eq!(history.password, "ProtectedPassword");
        assert_eq!(history.url, "http://www.somesite.com/");
        assert_eq!(history.notes, "Notes");
        assert_eq!(history.usage_count, Some(2));
        assert_eq!(
            history.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            history
                .attributes
                .get("TestProtected")
                .map(|field| field.protected),
            Some(true)
        );
        assert_eq!(
            history
                .attributes
                .get("TestUnprotected")
                .map(|field| field.protected),
            Some(false)
        );
        assert_eq!(
            history.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: None,
                associations: vec![AutoTypeAssociation {
                    window: "Target Window".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into(),
                }],
            })
        );
    }

    fn assert_non_ascii_fixture_contents(vault: &Vault) {
        assert_eq!(vault.generator.as_deref(), Some("KeePass"));
        assert_eq!(vault.name, "NonAsciiTest");
        assert_eq!(vault.database_name_changed, Some(1_284_927_373));
        assert_eq!(vault.history_max_items, Some(10));
        assert_eq!(vault.history_max_size, Some(6_291_456));
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
        assert_eq!(vault.deleted_objects.len(), 1);
        assert_eq!(vault.deleted_objects[0].deleted_at, 1_284_927_398);
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert_eq!(vault.recycle_bin_group, None);
        assert_eq!(vault.recycle_bin_changed, Some(1_284_933_314));
        assert_eq!(vault.entry_templates_group, None);
        assert_eq!(vault.entry_templates_group_changed, Some(1_284_927_220));

        assert_eq!(vault.root.title, "EmptyPassword");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));
        assert_eq!(vault.root.entries.len(), 1);
        assert!(vault.root.children.is_empty());

        let entry = &vault.root.entries[0];
        assert_eq!(entry.title, "秘密");
        assert_eq!(entry.username, "");
        assert_eq!(entry.password, "🚗🐎🔋📎");
        assert_eq!(entry.url, "");
        assert_eq!(entry.notes, "");
        assert_eq!(entry.icon_id, Some(49));
        assert_eq!(entry.history.len(), 0);
        assert_eq!(entry.usage_count, Some(0));
        assert!(!entry.expires);
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: Some(String::new()),
                associations: Vec::new(),
            })
        );
    }

    fn assert_compressed_fixture_contents(vault: &Vault) {
        assert_eq!(vault.generator.as_deref(), Some("KeePass"));
        assert_eq!(vault.name, "Compressed");
        assert_eq!(vault.database_name_changed, Some(1_285_268_778));
        assert_eq!(vault.history_max_items, Some(10));
        assert_eq!(vault.history_max_size, Some(6_291_456));
        assert_eq!(
            vault.memory_protection,
            Some(MemoryProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            })
        );
        assert!(vault.deleted_objects.is_empty());
        assert_eq!(vault.recycle_bin_enabled, Some(true));
        assert_eq!(vault.recycle_bin_group, None);
        assert_eq!(vault.recycle_bin_changed, Some(1_285_268_774));
        assert_eq!(vault.entry_templates_group, None);
        assert_eq!(vault.entry_templates_group_changed, Some(1_285_268_774));

        assert_eq!(vault.root.title, "Compressed");
        assert_eq!(vault.root.icon_id, Some(49));
        assert_eq!(vault.root.flags.is_expanded, Some(true));
        assert_eq!(vault.root.entries.len(), 1);
        assert_eq!(
            vault
                .root
                .children
                .iter()
                .map(|group| group.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "General",
                "Windows",
                "Network",
                "Internet",
                "eMail",
                "Homebanking"
            ]
        );
        assert_eq!(
            vault.root.last_top_visible_entry,
            Some(vault.root.entries[0].id)
        );

        let entry = &vault.root.entries[0];
        assert_eq!(entry.title, "Sample Entry");
        assert_eq!(entry.username, "User Name");
        assert_eq!(entry.password, "Password");
        assert_eq!(entry.url, "http://www.somesite.com/");
        assert_eq!(entry.notes, "Notes");
        assert_eq!(entry.icon_id, Some(0));
        assert_eq!(entry.history.len(), 0);
        assert_eq!(entry.usage_count, Some(0));
        assert_eq!(
            entry.field_protection,
            EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: false,
            }
        );
        assert_eq!(
            entry.auto_type,
            Some(AutoTypeConfig {
                enabled: Some(true),
                obfuscation: Some(0),
                default_sequence: None,
                associations: vec![AutoTypeAssociation {
                    window: "Target Window".into(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}".into(),
                }],
            })
        );

        let expected_icons = [48, 38, 3, 1, 19, 37];
        for (group, expected_icon) in vault.root.children.iter().zip(expected_icons) {
            assert_eq!(group.icon_id, Some(expected_icon));
            assert!(group.entries.is_empty());
            assert!(group.children.is_empty());
            assert_eq!(group.flags.is_expanded, Some(true));
        }
    }

    fn assert_recycle_bin_fixture(
        vault: &Vault,
        enabled: Option<bool>,
        recycle_bin_shape: Option<(&str, usize, usize, &[&str])>,
        root_children: &[&str],
        with_data_shape: Option<(&str, &[&str])>,
    ) {
        assert_eq!(vault.recycle_bin_enabled, enabled);
        assert_eq!(vault.entry_templates_group, None);
        assert!(vault.recycle_bin_changed.is_some());
        assert!(vault.entry_templates_group_changed.is_some());
        assert_eq!(
            vault
                .root
                .children
                .iter()
                .map(|group| group.title.as_str())
                .collect::<Vec<_>>(),
            root_children
        );

        match recycle_bin_shape {
            Some((expected_title, expected_entries, expected_children, expected_child_titles)) => {
                let recycle_bin_id = vault.recycle_bin_group.expect("recycle bin group id");
                let recycle_bin = find_group(&vault.root, &recycle_bin_id.to_string())
                    .expect("recycle bin group");
                assert_eq!(recycle_bin.title, expected_title);
                assert_eq!(recycle_bin.entries.len(), expected_entries);
                assert_eq!(recycle_bin.children.len(), expected_children);
                assert_eq!(
                    recycle_bin
                        .children
                        .iter()
                        .map(|child| child.title.as_str())
                        .collect::<Vec<_>>(),
                    expected_child_titles
                );
            }
            None => {
                assert_eq!(vault.recycle_bin_group, None);
            }
        }

        if let Some((recycle_bin_root_entry_title, expected_recycle_bin_children)) = with_data_shape
        {
            let recycle_bin_id = vault.recycle_bin_group.expect("recycle bin group id");
            let recycle_bin =
                find_group(&vault.root, &recycle_bin_id.to_string()).expect("recycle bin group");
            assert_eq!(
                recycle_bin
                    .entries
                    .first()
                    .map(|entry| entry.title.as_str()),
                Some(recycle_bin_root_entry_title)
            );
            assert_eq!(
                recycle_bin
                    .children
                    .iter()
                    .map(|child| child.title.as_str())
                    .collect::<Vec<_>>(),
                expected_recycle_bin_children
            );
        }
    }

    fn assert_file_key_fixture(
        core: &KeepassCore,
        db_bytes: &[u8],
        key_file: &[u8],
        expected_version: vaultkern_kdbx::KdbxVersion,
        expected_name: &str,
        expected_root_title: &str,
    ) {
        let mut key = CompositeKey::default();
        key.add_key_file_content(key_file).expect("key file");
        let loaded = core.load_database(db_bytes, &key).expect("load fixture");

        assert_eq!(loaded.inspection.header.version, expected_version);
        assert_eq!(loaded.vault.name, expected_name);
        assert_eq!(loaded.vault.root.title, expected_root_title);
        assert!(loaded.vault.root.entries.is_empty());
        assert_eq!(
            loaded
                .vault
                .root
                .children
                .iter()
                .map(|group| group.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "General",
                "Windows",
                "Network",
                "Internet",
                "eMail",
                "Homebanking"
            ]
        );
        assert!(
            loaded
                .vault
                .root
                .children
                .iter()
                .all(|group| group.entries.is_empty() && group.children.is_empty())
        );
    }

    fn assert_file_key_fixture_roundtrip(
        core: &KeepassCore,
        db_bytes: &[u8],
        key_file: &[u8],
        expected_name: &str,
        expected_root_title: &str,
    ) {
        let mut key = CompositeKey::default();
        key.add_key_file_content(key_file).expect("key file");
        let loaded = core.load_database(db_bytes, &key).expect("load fixture");
        let rewritten = core
            .save_kdbx(&loaded.vault, &key, super::SaveProfile::recommended())
            .expect("rewrite fixture");
        let inspection = core
            .inspect_database(&rewritten)
            .expect("inspect rewritten fixture");
        let reloaded = core.load_kdbx(&rewritten, &key).expect("reload fixture");

        assert_eq!(inspection.header.version, vaultkern_kdbx::KdbxVersion::V4_1);
        assert_eq!(reloaded.name, expected_name);
        assert_eq!(reloaded.root.title, expected_root_title);
        assert!(reloaded.root.entries.is_empty());
        assert_eq!(
            reloaded
                .root
                .children
                .iter()
                .map(|group| group.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "General",
                "Windows",
                "Network",
                "Internet",
                "eMail",
                "Homebanking"
            ]
        );
        assert!(
            reloaded
                .root
                .children
                .iter()
                .all(|group| group.entries.is_empty() && group.children.is_empty())
        );
    }

    fn find_group<'a>(
        group: &'a vaultkern_model::Group,
        id: &str,
    ) -> Option<&'a vaultkern_model::Group> {
        if group.id.to_string() == id {
            return Some(group);
        }
        for child in &group.children {
            if let Some(found) = find_group(child, id) {
                return Some(found);
            }
        }
        None
    }

    fn find_group_by_title<'a>(
        group: &'a vaultkern_model::Group,
        title: &str,
    ) -> Option<&'a vaultkern_model::Group> {
        if group.title == title {
            return Some(group);
        }
        for child in &group.children {
            if let Some(found) = find_group_by_title(child, title) {
                return Some(found);
            }
        }
        None
    }

    fn summarize_group_for_golden(group: &vaultkern_model::Group, path: &str) -> Vec<String> {
        let mut summary = Vec::new();
        summarize_group_into(group, path, &mut summary);
        summary
    }

    fn summarize_group_into(group: &vaultkern_model::Group, path: &str, summary: &mut Vec<String>) {
        for entry in &group.entries {
            summary.push(format!(
                "E|{}|{}|hist={}|att={}|custom={}",
                path,
                entry.title,
                entry.history.len(),
                entry.attachments.len(),
                entry.custom_data.len()
            ));
        }
        for child in &group.children {
            let child_path = if path.is_empty() {
                child.title.clone()
            } else {
                format!("{path}/{}", child.title)
            };
            summary.push(format!(
                "G|{}|entries={}|children={}|custom={}",
                child_path,
                child.entries.len(),
                child.children.len(),
                child.custom_data.len()
            ));
            summarize_group_into(child, &child_path, summary);
        }
    }
}
