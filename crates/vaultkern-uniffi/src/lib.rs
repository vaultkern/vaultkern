//! UniFFI boundary for the resident vaultkern core.
//!
//! The exported records deliberately use the runtime protocol's D5 names and
//! field vocabulary.  This crate only converts ownership and integer widths at
//! the FFI edge; business behavior remains in `vaultkern-runtime`.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use vaultkern_runtime::{
    BiometricProvider, PlatformPasskeyAssertionInput as RuntimePlatformPasskeyAssertionInput,
    PlatformPasskeyAssertionOutput as RuntimePlatformPasskeyAssertionOutput,
    PlatformPasskeyCredential as RuntimePlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput as RuntimePlatformPasskeyRegistrationInput,
    PlatformPasskeyRegistrationOutput as RuntimePlatformPasskeyRegistrationOutput, Runtime,
    SecureStorageError, SecureStorageProvider,
};
use vaultkern_runtime_protocol as protocol;
use zeroize::{Zeroize, Zeroizing};

/// Rust-owned secret text that lowers to the protocol's string vocabulary but
/// zeroizes its allocation whenever Rust retains or drops it.
pub struct SensitiveString(Zeroizing<String>);

impl SensitiveString {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SensitiveString {}

impl PartialEq<str> for SensitiveString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for SensitiveString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl From<String> for SensitiveString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<&str> for SensitiveString {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

impl From<SensitiveString> for String {
    fn from(value: SensitiveString) -> Self {
        value.as_str().to_owned()
    }
}

uniffi::custom_type!(SensitiveString, String);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultKernError {
    #[error("{details}")]
    Core { details: String },
    #[error("vaultkern runtime state is unavailable")]
    StateUnavailable,
}

impl From<anyhow::Error> for VaultKernError {
    fn from(error: anyhow::Error) -> Self {
        Self::Core {
            details: format!("{error:#}"),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformAdapterError {
    #[error("platform operation was cancelled")]
    Cancelled,
    #[error("platform-protected data was invalidated")]
    Invalidated,
    #[error("{details}")]
    Failure { details: String },
    #[error("unexpected platform adapter failure")]
    Unexpected,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformAdapterError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected
    }
}

fn secure_storage_adapter_error(error: PlatformAdapterError) -> anyhow::Error {
    match error {
        PlatformAdapterError::Cancelled => {
            SecureStorageError::cancelled("platform unlock blob access was cancelled").into()
        }
        PlatformAdapterError::Invalidated => {
            SecureStorageError::invalidated("platform unlock blob was invalidated").into()
        }
        error => anyhow::Error::new(error),
    }
}

/// Platform-owned protected storage and user-presence operations for one
/// unlock blob per vault.  Implementations live in Swift/Kotlin; the Rust core
/// continues to consume its existing biometric and secure-storage traits.
#[uniffi::export(with_foreign)]
pub trait UnlockBlobAdapter: Send + Sync + fmt::Debug {
    fn supports_unlock_blob(&self) -> Result<bool, PlatformAdapterError>;
    fn authorize(&self, reason: String) -> Result<(), PlatformAdapterError>;
    fn store_requires_user_presence(&self) -> Result<bool, PlatformAdapterError>;
    fn load_requires_user_presence(&self) -> Result<bool, PlatformAdapterError>;
    fn authorize_store_user_presence(&self) -> Result<(), PlatformAdapterError>;
    fn store_blob(&self, key: String, value: Vec<u8>) -> Result<(), PlatformAdapterError>;
    fn load_blob(&self, key: String) -> Result<Option<Vec<u8>>, PlatformAdapterError>;
    fn contains_blob(&self, key: String) -> Result<bool, PlatformAdapterError>;
    fn delete_blob(&self, key: String) -> Result<(), PlatformAdapterError>;
}

#[derive(Debug)]
struct AdapterBiometricProvider {
    adapter: Arc<dyn UnlockBlobAdapter>,
}

impl BiometricProvider for AdapterBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        self.adapter.supports_unlock_blob().unwrap_or(false)
    }

    fn authorize(&self, reason: &str) -> anyhow::Result<()> {
        self.adapter
            .authorize(reason.to_owned())
            .map_err(anyhow::Error::new)
    }
}

#[derive(Debug)]
struct AdapterSecureStorageProvider {
    adapter: Arc<dyn UnlockBlobAdapter>,
}

impl SecureStorageProvider for AdapterSecureStorageProvider {
    fn authorize_store_user_presence(&self) -> anyhow::Result<()> {
        self.adapter
            .authorize_store_user_presence()
            .map_err(secure_storage_adapter_error)
    }

    fn store(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        self.adapter
            .store_blob(key.to_owned(), value.to_vec())
            .map_err(secure_storage_adapter_error)
    }

    fn load(&self, key: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.adapter
            .load_blob(key.to_owned())
            .map(|value| value.map(Zeroizing::new))
            .map_err(secure_storage_adapter_error)
    }

    fn contains(&self, key: &str) -> anyhow::Result<bool> {
        self.adapter
            .contains_blob(key.to_owned())
            .map_err(secure_storage_adapter_error)
    }

    fn store_requires_user_presence(&self) -> bool {
        self.adapter.store_requires_user_presence().unwrap_or(true)
    }

    fn load_requires_user_presence(&self) -> bool {
        self.adapter.load_requires_user_presence().unwrap_or(false)
    }

    fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.adapter
            .delete_blob(key.to_owned())
            .map_err(secure_storage_adapter_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultHandleDto {
    pub vault_id: String,
    pub name: String,
    pub path: String,
}

impl From<protocol::VaultHandleDto> for VaultHandleDto {
    fn from(value: protocol::VaultHandleDto) -> Self {
        Self {
            vault_id: value.vault_id,
            name: value.name,
            path: value.path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultSourceStatusDto {
    pub source_kind: String,
    pub remote_state: String,
    pub last_sync_at: Option<i64>,
    pub cached_at: Option<i64>,
    pub last_error: Option<String>,
}

impl From<protocol::VaultSourceStatusDto> for VaultSourceStatusDto {
    fn from(value: protocol::VaultSourceStatusDto) -> Self {
        Self {
            source_kind: value.source_kind,
            remote_state: value.remote_state,
            last_sync_at: value.last_sync_at,
            cached_at: value.cached_at,
            last_error: value.last_error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SessionStateDto {
    pub unlocked: bool,
    pub active_vault_id: Option<String>,
    pub current_vault_ref_id: Option<String>,
    pub supports_biometric_unlock: bool,
    pub source_status: Option<VaultSourceStatusDto>,
}

impl From<protocol::SessionStateDto> for SessionStateDto {
    fn from(value: protocol::SessionStateDto) -> Self {
        Self {
            unlocked: value.unlocked,
            active_vault_id: value.active_vault_id,
            current_vault_ref_id: value.current_vault_ref_id,
            supports_biometric_unlock: value.supports_biometric_unlock,
            source_status: value.source_status.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EntrySummaryDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group_id: String,
    pub has_totp: bool,
}

impl From<protocol::EntrySummaryDto> for EntrySummaryDto {
    fn from(value: protocol::EntrySummaryDto) -> Self {
        Self {
            id: value.id,
            title: value.title,
            username: value.username,
            url: value.url,
            group_id: value.group_id,
            has_totp: value.has_totp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EntryFieldProtectionDto {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

impl From<protocol::EntryFieldProtectionDto> for EntryFieldProtectionDto {
    fn from(value: protocol::EntryFieldProtectionDto) -> Self {
        Self {
            protect_title: value.protect_title,
            protect_username: value.protect_username,
            protect_password: value.protect_password,
            protect_url: value.protect_url,
            protect_notes: value.protect_notes,
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntryCustomFieldDto {
    pub key: SensitiveString,
    pub value: SensitiveString,
    pub protected: bool,
}

impl From<protocol::EntryCustomFieldDto> for EntryCustomFieldDto {
    fn from(value: protocol::EntryCustomFieldDto) -> Self {
        Self {
            key: value.key.into(),
            value: take_sensitive_string(value.value),
            protected: value.protected,
        }
    }
}

impl From<EntryCustomFieldDto> for protocol::EntryCustomFieldDto {
    fn from(value: EntryCustomFieldDto) -> Self {
        Self {
            key: String::from(value.key),
            value: String::from(value.value).into(),
            protected: value.protected,
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntryAttachmentDto {
    pub name: SensitiveString,
    pub size: u64,
    pub protect_in_memory: bool,
}

impl From<protocol::EntryAttachmentDto> for EntryAttachmentDto {
    fn from(value: protocol::EntryAttachmentDto) -> Self {
        Self {
            name: value.name.into(),
            size: value.size as u64,
            protect_in_memory: value.protect_in_memory,
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntryPasskeyDto {
    pub username: SensitiveString,
    pub credential_id: SensitiveString,
    pub generated_user_id: Option<SensitiveString>,
    pub relying_party: SensitiveString,
    pub user_handle: Option<SensitiveString>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl From<protocol::EntryPasskeyDto> for EntryPasskeyDto {
    fn from(value: protocol::EntryPasskeyDto) -> Self {
        Self {
            username: value.username.into(),
            credential_id: value.credential_id.into(),
            generated_user_id: value.generated_user_id.map(Into::into),
            relying_party: value.relying_party.into(),
            user_handle: value.user_handle.map(Into::into),
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntryDetailDto {
    pub id: SensitiveString,
    pub title: SensitiveString,
    pub username: SensitiveString,
    pub password: SensitiveString,
    pub url: SensitiveString,
    pub notes: SensitiveString,
    pub modified_at: u64,
    pub totp: Option<SensitiveString>,
    pub totp_uri: Option<SensitiveString>,
    pub passkey: Option<EntryPasskeyDto>,
    pub field_protection: EntryFieldProtectionDto,
    pub custom_fields: Vec<EntryCustomFieldDto>,
    pub attachments: Vec<EntryAttachmentDto>,
}

impl From<protocol::EntryDetailDto> for EntryDetailDto {
    fn from(value: protocol::EntryDetailDto) -> Self {
        Self {
            id: value.id.into(),
            title: take_sensitive_string(value.title),
            username: take_sensitive_string(value.username),
            password: take_sensitive_string(value.password),
            url: take_sensitive_string(value.url),
            notes: take_sensitive_string(value.notes),
            modified_at: value.modified_at,
            totp: value.totp.map(take_sensitive_string),
            totp_uri: value.totp_uri.map(take_sensitive_string),
            passkey: value.passkey.map(Into::into),
            field_protection: value.field_protection.into(),
            custom_fields: value.custom_fields.into_iter().map(Into::into).collect(),
            attachments: value.attachments.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntryFieldsDto {
    pub title: SensitiveString,
    pub username: SensitiveString,
    pub password: SensitiveString,
    pub url: SensitiveString,
    pub notes: SensitiveString,
    pub totp_uri: Option<SensitiveString>,
    pub custom_fields: Vec<EntryCustomFieldDto>,
}

impl From<EntryFieldsDto> for protocol::EntryFieldsDto {
    fn from(value: EntryFieldsDto) -> Self {
        Self {
            title: String::from(value.title).into(),
            username: String::from(value.username).into(),
            password: String::from(value.password).into(),
            url: String::from(value.url).into(),
            notes: String::from(value.notes).into(),
            totp_uri: value.totp_uri.map(String::from).map(Into::into),
            custom_fields: value.custom_fields.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SaveVaultStatusDto {
    Saved,
    Merged,
    SavedToCache,
    ConflictCopy,
}

impl From<protocol::SaveVaultStatusDto> for SaveVaultStatusDto {
    fn from(value: protocol::SaveVaultStatusDto) -> Self {
        match value {
            protocol::SaveVaultStatusDto::Saved => Self::Saved,
            protocol::SaveVaultStatusDto::Merged => Self::Merged,
            protocol::SaveVaultStatusDto::SavedToCache => Self::SavedToCache,
            protocol::SaveVaultStatusDto::ConflictCopy => Self::ConflictCopy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MergeSummaryDto {
    pub merged_entries: u64,
    pub history_snapshots_added: u64,
    pub meta_conflicts_resolved: u32,
    pub icon_conflicts_resolved: u32,
}

impl From<protocol::MergeSummaryDto> for MergeSummaryDto {
    fn from(value: protocol::MergeSummaryDto) -> Self {
        Self {
            merged_entries: value.merged_entries as u64,
            history_snapshots_added: value.history_snapshots_added as u64,
            meta_conflicts_resolved: value.meta_conflicts_resolved,
            icon_conflicts_resolved: value.icon_conflicts_resolved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SaveVaultResultDto {
    pub status: SaveVaultStatusDto,
    pub merge_summary: Option<MergeSummaryDto>,
    pub conflict_copy_path: Option<String>,
}

impl From<protocol::SaveVaultResultDto> for SaveVaultResultDto {
    fn from(value: protocol::SaveVaultResultDto) -> Self {
        Self {
            status: value.status.into(),
            merge_summary: value.merge_summary.map(Into::into),
            conflict_copy_path: value.conflict_copy_path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyCredential {
    pub credential_id: Vec<u8>,
    pub relying_party: String,
    pub relying_party_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

impl From<RuntimePlatformPasskeyCredential> for PlatformPasskeyCredential {
    fn from(value: RuntimePlatformPasskeyCredential) -> Self {
        Self {
            credential_id: value.credential_id,
            relying_party: value.relying_party,
            relying_party_name: value.relying_party_name,
            user_handle: value.user_handle,
            user_name: value.user_name,
            user_display_name: value.user_display_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyRegistrationInput {
    pub relying_party: String,
    pub relying_party_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    pub public_key_algorithm: i32,
    pub user_verified: bool,
}

impl From<PlatformPasskeyRegistrationInput> for RuntimePlatformPasskeyRegistrationInput {
    fn from(value: PlatformPasskeyRegistrationInput) -> Self {
        Self {
            relying_party: value.relying_party,
            relying_party_name: value.relying_party_name,
            user_name: value.user_name,
            user_display_name: value.user_display_name,
            user_handle: value.user_handle,
            public_key_algorithm: value.public_key_algorithm,
            user_verified: value.user_verified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyRegistrationOutput {
    pub entry_id: String,
    pub credential: PlatformPasskeyCredential,
    pub authenticator_data: Vec<u8>,
}

impl From<RuntimePlatformPasskeyRegistrationOutput> for PlatformPasskeyRegistrationOutput {
    fn from(value: RuntimePlatformPasskeyRegistrationOutput) -> Self {
        Self {
            entry_id: value.entry_id,
            credential: value.credential.into(),
            authenticator_data: value.authenticator_data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyOperation {
    pub credentials: Vec<PlatformPasskeyCredential>,
    pub fresh_user_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyAssertionInput {
    pub relying_party: String,
    pub allowed_credential_ids: Vec<Vec<u8>>,
    pub client_data_hash: Vec<u8>,
    pub user_verified: bool,
}

impl From<PlatformPasskeyAssertionInput> for RuntimePlatformPasskeyAssertionInput {
    fn from(value: PlatformPasskeyAssertionInput) -> Self {
        Self {
            relying_party: value.relying_party,
            allowed_credential_ids: value.allowed_credential_ids,
            client_data_hash: value.client_data_hash,
            user_verified: value.user_verified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformPasskeyAssertionOutput {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature_der: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl From<RuntimePlatformPasskeyAssertionOutput> for PlatformPasskeyAssertionOutput {
    fn from(value: RuntimePlatformPasskeyAssertionOutput) -> Self {
        Self {
            credential_id: value.credential_id,
            authenticator_data: value.authenticator_data,
            signature_der: value.signature_der,
            user_handle: value.user_handle,
        }
    }
}

struct SharedRuntime {
    runtime: Mutex<Runtime>,
}

impl SharedRuntime {
    fn lock(&self) -> Result<MutexGuard<'_, Runtime>, VaultKernError> {
        self.runtime
            .try_lock()
            .map_err(|_| VaultKernError::StateUnavailable)
    }
}

#[derive(uniffi::Object)]
pub struct VaultSession {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultSession {
    #[uniffi::constructor]
    pub fn new(unlock_blob_adapter: Arc<dyn UnlockBlobAdapter>) -> Arc<Self> {
        let biometric = Box::new(AdapterBiometricProvider {
            adapter: Arc::clone(&unlock_blob_adapter),
        });
        let secure_storage = Box::new(AdapterSecureStorageProvider {
            adapter: unlock_blob_adapter,
        });
        Arc::new(Self {
            shared: Arc::new(SharedRuntime {
                runtime: Mutex::new(Runtime::new_with_platform_adapters(
                    biometric,
                    secure_storage,
                )),
            }),
        })
    }

    pub fn unlock(&self) -> Arc<VaultUnlock> {
        Arc::new(VaultUnlock {
            shared: Arc::clone(&self.shared),
        })
    }

    pub fn sync(&self) -> Arc<VaultSync> {
        Arc::new(VaultSync {
            shared: Arc::clone(&self.shared),
        })
    }

    pub fn open_vault(&self, path: String) -> Result<VaultHandleDto, VaultKernError> {
        self.shared
            .lock()?
            .open_local_vault(&path)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn close_vault(&self) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.lock_session();
        Ok(runtime.session_state().into())
    }

    pub fn session_state(&self) -> Result<SessionStateDto, VaultKernError> {
        Ok(self.shared.lock()?.session_state().into())
    }

    pub fn list_entries(&self, vault_id: String) -> Result<Vec<EntrySummaryDto>, VaultKernError> {
        self.shared
            .lock()?
            .list_entries(&vault_id)
            .map(|entries| entries.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    pub fn read_entry(
        &self,
        vault_id: String,
        entry_id: String,
    ) -> Result<EntryDetailDto, VaultKernError> {
        self.shared
            .lock()?
            .get_entry_detail(&vault_id, &entry_id)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn edit_entry(
        &self,
        vault_id: String,
        entry_id: String,
        fields: EntryFieldsDto,
    ) -> Result<EntryDetailDto, VaultKernError> {
        let fields: protocol::EntryFieldsDto = fields.into();
        self.shared
            .lock()?
            .update_entry_fields(
                &vault_id,
                &entry_id,
                fields.title,
                fields.username,
                fields.password,
                fields.url,
                fields.notes,
                fields.totp_uri,
                fields.custom_fields,
            )
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn save(&self, vault_id: String) -> Result<SaveVaultResultDto, VaultKernError> {
        match self.shared.lock()?.save_vault(&vault_id)? {
            protocol::RuntimeResponse::SaveVaultResult(result) => Ok(result.into()),
            _ => Err(VaultKernError::Core {
                details: "vault save returned an unexpected runtime response".into(),
            }),
        }
    }

    pub fn list_passkey_credentials(
        &self,
    ) -> Result<Vec<PlatformPasskeyCredential>, VaultKernError> {
        self.shared
            .lock()?
            .list_platform_passkey_credentials()
            .map(|credentials| credentials.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    pub fn prepare_passkey_operation(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<PlatformPasskeyOperation, VaultKernError> {
        let (credentials, fresh_user_verification) = self
            .shared
            .lock()?
            .prepare_platform_passkey_operation(operation_id, None)?;
        Ok(PlatformPasskeyOperation {
            credentials: credentials.into_iter().map(Into::into).collect(),
            fresh_user_verification,
        })
    }

    pub fn end_passkey_operation(&self, operation_id: Vec<u8>) -> Result<(), VaultKernError> {
        self.shared
            .lock()?
            .end_platform_passkey_operation(&operation_id);
        Ok(())
    }

    pub fn register_passkey(
        &self,
        operation_id: Vec<u8>,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput, VaultKernError> {
        self.shared
            .lock()?
            .register_platform_passkey_for_operation(&operation_id, input.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_passkey_registration(&self, operation_id: Vec<u8>) -> Result<(), VaultKernError> {
        self.shared
            .lock()?
            .commit_platform_passkey_registration_operation(&operation_id)
            .map_err(Into::into)
    }

    pub fn assert_passkey(
        &self,
        operation_id: Vec<u8>,
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput, VaultKernError> {
        self.shared
            .lock()?
            .create_platform_passkey_assertion_for_operation(&operation_id, input.into())
            .map(Into::into)
            .map_err(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct VaultUnlock {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultUnlock {
    pub fn unlock_vault(
        &self,
        vault_id: String,
        mut password: Option<String>,
        mut key_file_path: Option<String>,
    ) -> Result<SessionStateDto, VaultKernError> {
        let result = (|| {
            let mut runtime = self.shared.lock()?;
            runtime.unlock_vault(&vault_id, password.as_deref(), key_file_path.as_deref())?;
            Ok(runtime.session_state().into())
        })();
        password.zeroize();
        key_file_path.zeroize();
        result
    }

    pub fn enroll(
        &self,
        mut password: Option<String>,
        mut key_file_path: Option<String>,
    ) -> Result<SessionStateDto, VaultKernError> {
        let result = (|| {
            let mut runtime = self.shared.lock()?;
            runtime.enroll_quick_unlock_for_current_vault(
                password.as_deref(),
                key_file_path.as_deref(),
            )?;
            Ok(runtime.session_state().into())
        })();
        password.zeroize();
        key_file_path.zeroize();
        result
    }

    pub fn unlock_with_blob(&self) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.unlock_current_vault_with_quick_unlock()?;
        Ok(runtime.session_state().into())
    }

    pub fn revoke(&self) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.disable_quick_unlock_for_current_vault()?;
        Ok(runtime.session_state().into())
    }
}

#[derive(uniffi::Object)]
pub struct VaultSync {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultSync {
    pub fn trigger(&self, vault_id: String) -> Result<VaultSourceStatusDto, VaultKernError> {
        self.shared
            .lock()?
            .retry_vault_source_sync(&vault_id)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn status(&self) -> Result<Option<VaultSourceStatusDto>, VaultKernError> {
        Ok(self
            .shared
            .lock()?
            .session_state()
            .source_status
            .map(Into::into))
    }
}

fn take_sensitive_string(value: protocol::SensitiveString) -> SensitiveString {
    let mut value = value.into_zeroizing();
    std::mem::take(&mut *value).into()
}

#[cfg(test)]
mod tests {
    use super::SensitiveString;

    #[test]
    fn lowering_sensitive_text_does_not_reuse_the_zeroizing_allocation() {
        let sensitive = SensitiveString::from("ffi-transfer-secret".to_owned());
        let zeroizing_allocation = sensitive.as_str().as_ptr();

        let lowered = String::from(sensitive);

        assert_eq!(lowered, "ffi-transfer-secret");
        assert_ne!(lowered.as_ptr(), zeroizing_allocation);
    }
}

uniffi::setup_scaffolding!();
