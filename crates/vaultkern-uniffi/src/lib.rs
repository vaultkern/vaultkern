//! UniFFI boundary for the resident vaultkern core.
//!
//! The exported records deliberately use the runtime protocol's D5 names and
//! field vocabulary.  This crate only converts ownership and integer widths at
//! the FFI edge; business behavior remains in `vaultkern-runtime`.

use std::cell::RefCell;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use vaultkern_runtime::{
    BiometricProvider, ExternalKdfConfirmation, ExternalKdfDisposition, OneDriveRefreshTokenStore,
    PlatformPasskeyAssertionInput as RuntimePlatformPasskeyAssertionInput,
    PlatformPasskeyAssertionOutput as RuntimePlatformPasskeyAssertionOutput,
    PlatformPasskeyCredential as RuntimePlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput as RuntimePlatformPasskeyRegistrationInput,
    PlatformPasskeyRegistrationOutput as RuntimePlatformPasskeyRegistrationOutput,
    QuickUnlockOutcome, ResidentKdfPolicy, ResidentRuntimeConfig, Runtime, SecureStorageError,
    SecureStorageProvider, classify_external_kdf_error,
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

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
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

/// Rust-owned secret bytes used for platform protected-storage transfers.
/// The language bindings map this to explicit, redacted, clearable wrappers.
pub struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<SensitiveBytes> for Vec<u8> {
    fn from(value: SensitiveBytes) -> Self {
        value.as_slice().to_vec()
    }
}

uniffi::custom_type!(SensitiveBytes, Vec<u8>);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultKernError {
    #[error("{details}")]
    Core { details: String },
    #[error("vaultkern runtime state is unavailable")]
    StateUnavailable,
    #[error("a platform adapter callback cannot re-enter the same vault session")]
    ReentrantCall,
    #[error("a platform adapter callback is active for this vault session")]
    AdapterCallbackActive,
    #[error("platform capability is unavailable: {capability} ({details})")]
    UnsupportedCapability { capability: String, details: String },
    #[error("external KDF requires confirmation: {algorithm} {resource}={observed}, limit={limit}")]
    KdfConfirmationRequired {
        algorithm: String,
        resource: String,
        observed: u64,
        limit: u64,
    },
    #[error("external KDF was refused: {algorithm} {resource}={observed}, limit={limit}")]
    KdfRefused {
        algorithm: String,
        resource: String,
        observed: u64,
        limit: u64,
    },
    #[error("external KDF is forbidden in this process: {algorithm} {resource}={observed}")]
    KdfForbidden {
        algorithm: String,
        resource: String,
        observed: u64,
    },
}

impl From<anyhow::Error> for VaultKernError {
    fn from(error: anyhow::Error) -> Self {
        if let Some(failure) = classify_external_kdf_error(&error) {
            let algorithm = failure.algorithm.to_owned();
            let resource = failure.resource.to_owned();
            return match (failure.disposition, failure.limit) {
                (ExternalKdfDisposition::ConfirmationRequired, Some(limit)) => {
                    Self::KdfConfirmationRequired {
                        algorithm,
                        resource,
                        observed: failure.observed,
                        limit,
                    }
                }
                (ExternalKdfDisposition::Refused, Some(limit)) => Self::KdfRefused {
                    algorithm,
                    resource,
                    observed: failure.observed,
                    limit,
                },
                (ExternalKdfDisposition::Forbidden, _) => Self::KdfForbidden {
                    algorithm,
                    resource,
                    observed: failure.observed,
                },
                _ => Self::Core {
                    details: "external KDF policy classification was internally inconsistent"
                        .into(),
                },
            };
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ResidentPlatform {
    Macos,
    Android,
}

impl ResidentPlatform {
    fn compiled_platform() -> Option<Self> {
        #[cfg(target_os = "android")]
        {
            return Some(Self::Android);
        }
        #[cfg(target_os = "macos")]
        {
            return Some(Self::Macos);
        }
        #[cfg(not(any(target_os = "android", target_os = "macos")))]
        {
            None
        }
    }

    fn validate_for_compiled_platform(
        self,
        compiled_platform: Option<Self>,
    ) -> Result<(), VaultKernError> {
        if let Some(compiled_platform) = compiled_platform
            && self != compiled_platform
        {
            return Err(VaultKernError::Core {
                details: format!(
                    "resident platform declaration {self:?} does not match compiled host {compiled_platform:?}"
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultSessionConfig {
    pub platform: ResidentPlatform,
    pub state_directory: String,
    pub temporary_directory: String,
}

impl From<VaultSessionConfig> for ResidentRuntimeConfig {
    fn from(value: VaultSessionConfig) -> Self {
        Self {
            state_directory: value.state_directory.into(),
            temporary_directory: value.temporary_directory.into(),
            kdf_policy: match value.platform {
                ResidentPlatform::Macos => ResidentKdfPolicy::Desktop,
                ResidentPlatform::Android => ResidentKdfPolicy::Mobile,
            },
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformAdapterError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected
    }
}

#[derive(Debug, Default)]
struct AdapterCallState {
    active_callbacks: usize,
    runtime_call_active: bool,
}

#[derive(Debug, Default)]
struct AdapterCallGate {
    state: Mutex<AdapterCallState>,
    changed: Condvar,
}

impl AdapterCallGate {
    fn enter(&self) -> AdapterCallPermit<'_> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active_callbacks += 1;
        }
        self.changed.notify_all();
        AdapterCallPermit { gate: self }
    }

    fn reserve_runtime_call(&self) -> Result<RuntimeCallReservation<'_>, VaultKernError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.active_callbacks != 0 {
                return Err(VaultKernError::AdapterCallbackActive);
            }
            if !state.runtime_call_active {
                state.runtime_call_active = true;
                return Ok(RuntimeCallReservation { gate: self });
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn call<T>(&self, callback: impl FnOnce() -> T) -> T {
        let _permit = self.enter();
        callback()
    }
}

struct AdapterCallPermit<'a> {
    gate: &'a AdapterCallGate,
}

impl Drop for AdapterCallPermit<'_> {
    fn drop(&mut self) {
        {
            let mut state = self
                .gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert_ne!(state.active_callbacks, 0);
            state.active_callbacks = state.active_callbacks.saturating_sub(1);
        }
        self.gate.changed.notify_all();
    }
}

struct RuntimeCallReservation<'a> {
    gate: &'a AdapterCallGate,
}

impl Drop for RuntimeCallReservation<'_> {
    fn drop(&mut self) {
        {
            let mut state = self
                .gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(state.runtime_call_active);
            state.runtime_call_active = false;
        }
        self.gate.changed.notify_all();
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
    fn store_blob(&self, key: String, value: SensitiveBytes) -> Result<(), PlatformAdapterError>;
    fn load_blob(&self, key: String) -> Result<Option<SensitiveBytes>, PlatformAdapterError>;
    fn contains_blob(&self, key: String) -> Result<bool, PlatformAdapterError>;
    fn delete_blob(&self, key: String) -> Result<(), PlatformAdapterError>;
}

/// Platform-owned protected storage for the existing OneDrive refresh token.
/// OAuth presentation remains a platform concern; the runtime owns token use.
#[uniffi::export(with_foreign)]
pub trait OneDriveTokenAdapter: Send + Sync + fmt::Debug {
    fn load_refresh_token(&self) -> Result<Option<SensitiveString>, PlatformAdapterError>;
    fn store_refresh_token(&self, token: SensitiveString) -> Result<(), PlatformAdapterError>;
    fn delete_refresh_token(&self) -> Result<(), PlatformAdapterError>;
}

#[derive(Debug)]
struct AdapterOneDriveRefreshTokenStore {
    adapter: Arc<dyn OneDriveTokenAdapter>,
    calls: Arc<AdapterCallGate>,
}

impl OneDriveRefreshTokenStore for AdapterOneDriveRefreshTokenStore {
    fn load(&self) -> anyhow::Result<Option<Zeroizing<String>>> {
        self.calls
            .call(|| self.adapter.load_refresh_token())
            .map(|token| token.map(SensitiveString::into_zeroizing))
            .map_err(anyhow::Error::new)
    }

    fn store(&self, token: &str) -> anyhow::Result<()> {
        self.calls
            .call(|| self.adapter.store_refresh_token(token.into()))
            .map_err(anyhow::Error::new)
    }

    fn delete(&self) -> anyhow::Result<()> {
        self.calls
            .call(|| self.adapter.delete_refresh_token())
            .map_err(anyhow::Error::new)
    }
}

#[derive(Debug)]
struct AdapterBiometricProvider {
    adapter: Arc<dyn UnlockBlobAdapter>,
    calls: Arc<AdapterCallGate>,
}

impl BiometricProvider for AdapterBiometricProvider {
    fn supports_quick_unlock(&self) -> bool {
        self.calls
            .call(|| self.adapter.supports_unlock_blob())
            .unwrap_or(false)
    }

    fn authorize(&self, reason: &str) -> anyhow::Result<()> {
        self.calls
            .call(|| self.adapter.authorize(reason.to_owned()))
            .map_err(secure_storage_adapter_error)
    }
}

#[derive(Debug)]
struct AdapterSecureStorageProvider {
    adapter: Arc<dyn UnlockBlobAdapter>,
    calls: Arc<AdapterCallGate>,
}

impl SecureStorageProvider for AdapterSecureStorageProvider {
    fn authorize_store_user_presence(&self) -> anyhow::Result<()> {
        self.calls
            .call(|| self.adapter.authorize_store_user_presence())
            .map_err(secure_storage_adapter_error)
    }

    fn store(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        self.calls
            .call(|| {
                self.adapter
                    .store_blob(key.to_owned(), value.to_vec().into())
            })
            .map_err(secure_storage_adapter_error)
    }

    fn load(&self, key: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.calls
            .call(|| self.adapter.load_blob(key.to_owned()))
            .map(|value| value.map(SensitiveBytes::into_zeroizing))
            .map_err(secure_storage_adapter_error)
    }

    fn contains(&self, key: &str) -> anyhow::Result<bool> {
        self.calls
            .call(|| self.adapter.contains_blob(key.to_owned()))
            .map_err(secure_storage_adapter_error)
    }

    fn store_requires_user_presence(&self) -> bool {
        self.calls
            .call(|| self.adapter.store_requires_user_presence())
            .unwrap_or(true)
    }

    fn load_requires_user_presence(&self) -> bool {
        self.calls
            .call(|| self.adapter.load_requires_user_presence())
            .unwrap_or(false)
    }

    fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.calls
            .call(|| self.adapter.delete_blob(key.to_owned()))
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
pub struct VaultReferenceDto {
    pub vault_ref_id: String,
    pub display_name: String,
    pub source_kind: String,
    pub source_summary: String,
    pub last_used_at: i64,
    pub availability: String,
    pub supports_quick_unlock: bool,
    pub is_current: bool,
}

impl From<protocol::VaultReferenceDto> for VaultReferenceDto {
    fn from(value: protocol::VaultReferenceDto) -> Self {
        Self {
            vault_ref_id: value.vault_ref_id,
            display_name: value.display_name,
            source_kind: value.source_kind,
            source_summary: value.source_summary,
            last_used_at: value.last_used_at,
            availability: value.availability,
            supports_quick_unlock: value.supports_quick_unlock,
            is_current: value.is_current,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultReferenceListDto {
    pub vaults: Vec<VaultReferenceDto>,
}

impl From<protocol::VaultReferenceListDto> for VaultReferenceListDto {
    fn from(value: protocol::VaultReferenceListDto) -> Self {
        Self {
            vaults: value.vaults.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OneDriveAuthSessionDto {
    pub auth_url: String,
    pub redirect_uri: String,
    pub expires_in_seconds: u32,
}

impl From<protocol::OneDriveAuthSessionDto> for OneDriveAuthSessionDto {
    fn from(value: protocol::OneDriveAuthSessionDto) -> Self {
        Self {
            auth_url: value.auth_url,
            redirect_uri: value.redirect_uri,
            expires_in_seconds: value.expires_in_seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OneDriveAuthStatusDto {
    pub status: String,
    pub account_label: Option<String>,
}

impl From<protocol::OneDriveAuthStatusDto> for OneDriveAuthStatusDto {
    fn from(value: protocol::OneDriveAuthStatusDto) -> Self {
        Self {
            status: value.status,
            account_label: value.account_label,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OneDriveItemDto {
    pub drive_id: String,
    pub item_id: String,
    pub name: String,
    pub folder: bool,
    pub size: Option<u64>,
}

impl From<protocol::OneDriveItemDto> for OneDriveItemDto {
    fn from(value: protocol::OneDriveItemDto) -> Self {
        Self {
            drive_id: value.drive_id,
            item_id: value.item_id,
            name: value.name,
            folder: value.folder,
            size: value.size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OneDriveItemListDto {
    pub items: Vec<OneDriveItemDto>,
}

impl From<protocol::OneDriveItemListDto> for OneDriveItemListDto {
    fn from(value: protocol::OneDriveItemListDto) -> Self {
        Self {
            items: value.items.into_iter().map(Into::into).collect(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnlockBlobStatusDto {
    Unlocked,
    NotEnrolled,
    Cancelled,
    OpenAppRequired,
    CredentialRequired,
    Unsupported,
}

impl From<QuickUnlockOutcome> for UnlockBlobStatusDto {
    fn from(value: QuickUnlockOutcome) -> Self {
        match value {
            QuickUnlockOutcome::Unlocked => Self::Unlocked,
            QuickUnlockOutcome::NotEnrolled => Self::NotEnrolled,
            QuickUnlockOutcome::Cancelled => Self::Cancelled,
            QuickUnlockOutcome::OpenAppRequired => Self::OpenAppRequired,
            QuickUnlockOutcome::CredentialRequired => Self::CredentialRequired,
            QuickUnlockOutcome::Unsupported => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnlockBlobResultDto {
    pub status: UnlockBlobStatusDto,
    pub state: SessionStateDto,
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
            value: value.value.into_zeroizing().into(),
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
            title: value.title.into_zeroizing().into(),
            username: value.username.into_zeroizing().into(),
            password: value.password.into_zeroizing().into(),
            url: value.url.into_zeroizing().into(),
            notes: value.notes.into_zeroizing().into(),
            totp_uri: value
                .totp_uri
                .map(SensitiveString::into_zeroizing)
                .map(Into::into),
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
pub struct PlatformCapabilitiesDto {
    pub direct_passkey_persistence: bool,
    pub apple_passkey_outbox: bool,
    pub one_drive_account_setup: bool,
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
    platform: ResidentPlatform,
    adapter_calls: Arc<AdapterCallGate>,
    deferred_passkey_finishes: Mutex<Vec<Vec<u8>>>,
}

thread_local! {
    static ACTIVE_RUNTIME_CALLS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

struct RuntimeCallPermit {
    identity: usize,
}

impl RuntimeCallPermit {
    fn enter(identity: usize) -> Result<Self, VaultKernError> {
        ACTIVE_RUNTIME_CALLS.with(|active| {
            let mut active = active.borrow_mut();
            if active.contains(&identity) {
                Err(VaultKernError::ReentrantCall)
            } else {
                active.push(identity);
                Ok(Self { identity })
            }
        })
    }
}

impl Drop for RuntimeCallPermit {
    fn drop(&mut self) {
        ACTIVE_RUNTIME_CALLS.with(|active| {
            let mut active = active.borrow_mut();
            let identity = active.pop();
            debug_assert_eq!(identity, Some(self.identity));
        });
    }
}

struct SharedRuntimeGuard<'a> {
    runtime: MutexGuard<'a, Runtime>,
    _runtime_call: RuntimeCallReservation<'a>,
    _permit: RuntimeCallPermit,
    deferred_passkey_finishes: &'a Mutex<Vec<Vec<u8>>>,
}

impl SharedRuntimeGuard<'_> {
    fn drain_deferred_passkey_finishes(&mut self) {
        let operation_ids = {
            let mut deferred = self
                .deferred_passkey_finishes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *deferred)
        };
        for operation_id in operation_ids {
            self.runtime.end_platform_passkey_operation(&operation_id);
        }
    }
}

impl Deref for SharedRuntimeGuard<'_> {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl DerefMut for SharedRuntimeGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}

impl Drop for SharedRuntimeGuard<'_> {
    fn drop(&mut self) {
        self.drain_deferred_passkey_finishes();
    }
}

impl SharedRuntime {
    fn lock(&self) -> Result<SharedRuntimeGuard<'_>, VaultKernError> {
        let identity = self as *const Self as usize;
        let permit = RuntimeCallPermit::enter(identity)?;
        let runtime_call = self.adapter_calls.reserve_runtime_call()?;
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| VaultKernError::StateUnavailable)?;
        let mut guard = SharedRuntimeGuard {
            runtime,
            _runtime_call: runtime_call,
            _permit: permit,
            deferred_passkey_finishes: &self.deferred_passkey_finishes,
        };
        guard.drain_deferred_passkey_finishes();
        Ok(guard)
    }

    fn lock_for_session_mutation(&self) -> Result<SharedRuntimeGuard<'_>, VaultKernError> {
        let guard = self.lock()?;
        guard.ensure_no_active_platform_passkey_operation()?;
        Ok(guard)
    }

    fn defer_passkey_finish(&self, operation_id: Vec<u8>) {
        self.deferred_passkey_finishes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(operation_id);
    }
}

#[derive(uniffi::Object)]
pub struct VaultSession {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultSession {
    #[uniffi::constructor]
    pub fn new(
        config: VaultSessionConfig,
        unlock_blob_adapter: Arc<dyn UnlockBlobAdapter>,
        one_drive_token_adapter: Arc<dyn OneDriveTokenAdapter>,
    ) -> Result<Arc<Self>, VaultKernError> {
        let platform = config.platform;
        platform.validate_for_compiled_platform(ResidentPlatform::compiled_platform())?;
        let adapter_calls = Arc::new(AdapterCallGate::default());
        let biometric = Box::new(AdapterBiometricProvider {
            adapter: Arc::clone(&unlock_blob_adapter),
            calls: Arc::clone(&adapter_calls),
        });
        let secure_storage = Box::new(AdapterSecureStorageProvider {
            adapter: unlock_blob_adapter,
            calls: Arc::clone(&adapter_calls),
        });
        let one_drive_refresh_tokens = Box::new(AdapterOneDriveRefreshTokenStore {
            adapter: one_drive_token_adapter,
            calls: Arc::clone(&adapter_calls),
        });
        let runtime = Runtime::new_with_platform_adapters(
            config.into(),
            biometric,
            secure_storage,
            one_drive_refresh_tokens,
        )?;
        Ok(Arc::new(Self {
            shared: Arc::new(SharedRuntime {
                runtime: Mutex::new(runtime),
                platform,
                adapter_calls,
                deferred_passkey_finishes: Mutex::new(Vec::new()),
            }),
        }))
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

    pub fn sources(&self) -> Arc<VaultSources> {
        Arc::new(VaultSources {
            shared: Arc::clone(&self.shared),
        })
    }

    pub fn open_vault(&self, path: String) -> Result<VaultHandleDto, VaultKernError> {
        self.shared
            .lock_for_session_mutation()?
            .open_local_vault(&path)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn lock_session(&self) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.try_lock_session()?;
        Ok(runtime.session_state().into())
    }

    pub fn close_vault(&self, vault_id: String) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.close_vault(&vault_id)?;
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
            .lock_for_session_mutation()?
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
        match self
            .shared
            .lock_for_session_mutation()?
            .save_vault(&vault_id)?
        {
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

    pub fn capabilities(&self) -> PlatformCapabilitiesDto {
        PlatformCapabilitiesDto {
            direct_passkey_persistence: self.shared.platform == ResidentPlatform::Android,
            apple_passkey_outbox: false,
            one_drive_account_setup: true,
        }
    }

    pub fn begin_passkey_operation(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<Arc<VaultPasskeyOperation>, VaultKernError> {
        if self.shared.platform != ResidentPlatform::Android {
            return Err(VaultKernError::UnsupportedCapability {
                capability: "apple_passkey_outbox".into(),
                details: "macOS credential extensions require the D3 outbox boundary; resident direct persistence is Android-only".into(),
            });
        }
        let (credentials, fresh_user_verification) = self
            .shared
            .lock_for_session_mutation()?
            .prepare_platform_passkey_operation(operation_id.clone(), None)?;
        Ok(Arc::new(VaultPasskeyOperation {
            shared: Arc::clone(&self.shared),
            operation_id,
            credentials: credentials.into_iter().map(Into::into).collect(),
            fresh_user_verification,
            closed: AtomicBool::new(false),
        }))
    }
}

#[derive(uniffi::Object)]
pub struct VaultPasskeyOperation {
    shared: Arc<SharedRuntime>,
    operation_id: Vec<u8>,
    credentials: Vec<PlatformPasskeyCredential>,
    fresh_user_verification: bool,
    closed: AtomicBool,
}

impl VaultPasskeyOperation {
    fn ensure_open(&self) -> Result<(), VaultKernError> {
        if self.closed.load(Ordering::Acquire) {
            Err(VaultKernError::Core {
                details: "platform passkey operation is closed".into(),
            })
        } else {
            Ok(())
        }
    }

    fn close_once(&self) -> Result<(), VaultKernError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self.shared.lock().map(|mut runtime| {
            runtime.end_platform_passkey_operation(&self.operation_id);
        });
        if result.is_err() {
            self.closed.store(false, Ordering::Release);
        }
        result
    }
}

impl Drop for VaultPasskeyOperation {
    fn drop(&mut self) {
        if let Err(VaultKernError::ReentrantCall | VaultKernError::AdapterCallbackActive) =
            self.close_once()
        {
            self.closed.store(true, Ordering::Release);
            self.shared.defer_passkey_finish(self.operation_id.clone());
        }
    }
}

#[uniffi::export]
impl VaultPasskeyOperation {
    pub fn credentials(&self) -> Result<Vec<PlatformPasskeyCredential>, VaultKernError> {
        self.ensure_open()?;
        Ok(self.credentials.clone())
    }

    pub fn fresh_user_verification(&self) -> Result<bool, VaultKernError> {
        self.ensure_open()?;
        Ok(self.fresh_user_verification)
    }

    pub fn register_passkey(
        &self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput, VaultKernError> {
        self.ensure_open()?;
        self.shared
            .lock()?
            .register_platform_passkey_for_operation(&self.operation_id, input.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn commit_registration(&self) -> Result<(), VaultKernError> {
        self.ensure_open()?;
        self.shared
            .lock()?
            .commit_platform_passkey_registration_operation(&self.operation_id)
            .map_err(Into::into)
    }

    pub fn assert_passkey(
        &self,
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput, VaultKernError> {
        self.ensure_open()?;
        self.shared
            .lock()?
            .create_platform_passkey_assertion_for_operation(&self.operation_id, input.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn finish(&self) -> Result<(), VaultKernError> {
        self.close_once()
    }
}

#[derive(uniffi::Object)]
pub struct VaultUnlock {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultUnlock {
    pub fn unlock_current(
        &self,
        password: Option<SensitiveString>,
        mut key_file_path: Option<String>,
        kdf_confirmed: bool,
    ) -> Result<SessionStateDto, VaultKernError> {
        let result = (|| {
            let mut runtime = self.shared.lock_for_session_mutation()?;
            runtime.unlock_current_vault_with_kdf_confirmation(
                password.as_ref().map(SensitiveString::as_str),
                key_file_path.as_deref(),
                if kdf_confirmed {
                    ExternalKdfConfirmation::Confirmed
                } else {
                    ExternalKdfConfirmation::Unconfirmed
                },
            )?;
            Ok(runtime.session_state().into())
        })();
        key_file_path.zeroize();
        result
    }

    pub fn unlock_current_with_key_file(
        &self,
        password: Option<SensitiveString>,
        key_file: SensitiveBytes,
        kdf_confirmed: bool,
    ) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock_for_session_mutation()?;
        runtime.unlock_current_vault_with_key_file_bytes_and_kdf_confirmation(
            password.as_ref().map(SensitiveString::as_str),
            key_file.into_zeroizing(),
            if kdf_confirmed {
                ExternalKdfConfirmation::Confirmed
            } else {
                ExternalKdfConfirmation::Unconfirmed
            },
        )?;
        Ok(runtime.session_state().into())
    }

    pub fn unlock_vault(
        &self,
        vault_id: String,
        password: Option<SensitiveString>,
        mut key_file_path: Option<String>,
        kdf_confirmed: bool,
    ) -> Result<SessionStateDto, VaultKernError> {
        let result = (|| {
            let mut runtime = self.shared.lock_for_session_mutation()?;
            runtime.unlock_vault_with_kdf_confirmation(
                &vault_id,
                password.as_ref().map(SensitiveString::as_str),
                key_file_path.as_deref(),
                if kdf_confirmed {
                    ExternalKdfConfirmation::Confirmed
                } else {
                    ExternalKdfConfirmation::Unconfirmed
                },
            )?;
            Ok(runtime.session_state().into())
        })();
        key_file_path.zeroize();
        result
    }

    pub fn enroll(
        &self,
        password: Option<SensitiveString>,
        mut key_file_path: Option<String>,
        kdf_confirmed: bool,
    ) -> Result<SessionStateDto, VaultKernError> {
        let result = (|| {
            let mut runtime = self.shared.lock()?;
            runtime.enroll_quick_unlock_for_current_vault_with_kdf_confirmation(
                password.as_ref().map(SensitiveString::as_str),
                key_file_path.as_deref(),
                if kdf_confirmed {
                    ExternalKdfConfirmation::Confirmed
                } else {
                    ExternalKdfConfirmation::Unconfirmed
                },
            )?;
            Ok(runtime.session_state().into())
        })();
        key_file_path.zeroize();
        result
    }

    pub fn enroll_with_key_file(
        &self,
        password: Option<SensitiveString>,
        key_file: SensitiveBytes,
        kdf_confirmed: bool,
    ) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.enroll_quick_unlock_for_current_vault_with_key_file_bytes_and_kdf_confirmation(
            password.as_ref().map(SensitiveString::as_str),
            key_file.into_zeroizing(),
            if kdf_confirmed {
                ExternalKdfConfirmation::Confirmed
            } else {
                ExternalKdfConfirmation::Unconfirmed
            },
        )?;
        Ok(runtime.session_state().into())
    }

    pub fn unlock_with_blob(
        &self,
        kdf_confirmed: bool,
    ) -> Result<UnlockBlobResultDto, VaultKernError> {
        let mut runtime = self.shared.lock_for_session_mutation()?;
        let status = runtime.try_unlock_current_vault_with_quick_unlock(if kdf_confirmed {
            ExternalKdfConfirmation::Confirmed
        } else {
            ExternalKdfConfirmation::Unconfirmed
        })?;
        Ok(UnlockBlobResultDto {
            status: status.into(),
            state: runtime.session_state().into(),
        })
    }

    pub fn revoke(&self) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock()?;
        runtime.disable_quick_unlock_for_current_vault()?;
        Ok(runtime.session_state().into())
    }
}

#[derive(uniffi::Object)]
pub struct VaultSources {
    shared: Arc<SharedRuntime>,
}

#[uniffi::export]
impl VaultSources {
    pub fn list_recent(&self) -> Result<VaultReferenceListDto, VaultKernError> {
        self.shared
            .lock()?
            .list_recent_vaults()
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn add_local_vault(&self, path: String) -> Result<VaultReferenceDto, VaultKernError> {
        self.shared
            .lock_for_session_mutation()?
            .add_local_vault_reference(&path)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn current_local_vault_path(&self) -> Result<Option<String>, VaultKernError> {
        self.shared
            .lock()?
            .current_local_vault_path()
            .map_err(Into::into)
    }

    pub fn begin_one_drive_login(&self) -> Result<OneDriveAuthSessionDto, VaultKernError> {
        match self
            .shared
            .lock()?
            .handle(protocol::RuntimeCommand::BeginOneDriveLogin)?
        {
            protocol::RuntimeResponse::OneDriveAuthSession(session) => Ok(session.into()),
            _ => Err(VaultKernError::Core {
                details: "OneDrive login returned an unexpected runtime response".into(),
            }),
        }
    }

    pub fn complete_pending_one_drive_login(
        &self,
    ) -> Result<OneDriveAuthStatusDto, VaultKernError> {
        match self
            .shared
            .lock()?
            .handle(protocol::RuntimeCommand::CompletePendingOneDriveLogin)?
        {
            protocol::RuntimeResponse::OneDriveAuthStatus(status) => Ok(status.into()),
            _ => Err(VaultKernError::Core {
                details: "OneDrive login completion returned an unexpected runtime response".into(),
            }),
        }
    }

    pub fn list_one_drive_children(
        &self,
        parent_item_id: Option<String>,
    ) -> Result<OneDriveItemListDto, VaultKernError> {
        match self
            .shared
            .lock()?
            .handle(protocol::RuntimeCommand::ListOneDriveChildren { parent_item_id })?
        {
            protocol::RuntimeResponse::OneDriveItemList(items) => Ok(items.into()),
            _ => Err(VaultKernError::Core {
                details: "OneDrive listing returned an unexpected runtime response".into(),
            }),
        }
    }

    pub fn add_one_drive_vault(
        &self,
        drive_id: String,
        item_id: String,
    ) -> Result<VaultReferenceDto, VaultKernError> {
        match self
            .shared
            .lock_for_session_mutation()?
            .handle(protocol::RuntimeCommand::AddOneDriveVaultReference { drive_id, item_id })?
        {
            protocol::RuntimeResponse::VaultReference(reference) => Ok(reference.into()),
            _ => Err(VaultKernError::Core {
                details: "OneDrive vault selection returned an unexpected runtime response".into(),
            }),
        }
    }

    pub fn set_current_vault(
        &self,
        vault_ref_id: String,
    ) -> Result<SessionStateDto, VaultKernError> {
        let mut runtime = self.shared.lock_for_session_mutation()?;
        runtime.set_current_vault(&vault_ref_id)?;
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
            .lock_for_session_mutation()?
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
    use super::{
        AdapterCallGate, ResidentPlatform, SensitiveString, SharedRuntime, VaultKernError,
    };

    #[test]
    fn lowering_sensitive_text_does_not_reuse_the_zeroizing_allocation() {
        let sensitive = SensitiveString::from("ffi-transfer-secret".to_owned());
        let zeroizing_allocation = sensitive.as_str().as_ptr();

        let lowered = String::from(sensitive);

        assert_eq!(lowered, "ffi-transfer-secret");
        assert_ne!(lowered.as_ptr(), zeroizing_allocation);
    }

    #[test]
    fn ffi_error_preserves_external_kdf_confirmation_details() {
        let error = anyhow::Error::new(vaultkern_core::KdbxError::ExternalKdfPolicy {
            algorithm: vaultkern_core::ExternalKdfAlgorithm::AesKdbx4,
            observed: 700_000_000,
            decision: vaultkern_core::ExternalKdfDecision::Confirm(600_000_000),
        });

        assert!(matches!(
            VaultKernError::from(error),
            VaultKernError::KdfConfirmationRequired {
                algorithm,
                resource,
                observed: 700_000_000,
                limit: 600_000_000,
            } if algorithm == "aes_kdbx4" && resource == "rounds"
        ));
    }

    #[test]
    fn resident_platform_declaration_must_match_the_compiled_host() {
        assert!(
            ResidentPlatform::Android
                .validate_for_compiled_platform(Some(ResidentPlatform::Android))
                .is_ok()
        );
        assert!(
            ResidentPlatform::Macos
                .validate_for_compiled_platform(Some(ResidentPlatform::Macos))
                .is_ok()
        );
        assert!(
            ResidentPlatform::Android
                .validate_for_compiled_platform(Some(ResidentPlatform::Macos))
                .is_err()
        );
        assert!(
            ResidentPlatform::Macos
                .validate_for_compiled_platform(Some(ResidentPlatform::Android))
                .is_err()
        );
    }

    #[test]
    fn ordinary_runtime_contention_serializes_between_threads() {
        let shared = std::sync::Arc::new(SharedRuntime {
            runtime: std::sync::Mutex::new(vaultkern_runtime::Runtime::for_tests()),
            platform: ResidentPlatform::Android,
            adapter_calls: std::sync::Arc::new(AdapterCallGate::default()),
            deferred_passkey_finishes: std::sync::Mutex::new(Vec::new()),
        });
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_shared = std::sync::Arc::clone(&shared);
        let first_entered = std::sync::Arc::clone(&entered);
        let first_release = std::sync::Arc::clone(&release);
        let first = std::thread::spawn(move || {
            let _guard = first_shared.lock().unwrap();
            first_entered.wait();
            first_release.wait();
        });
        entered.wait();

        let second_shared = std::sync::Arc::clone(&shared);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sender.send(second_shared.lock().is_ok()).unwrap();
        });

        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        release.wait();
        first.join().unwrap();
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
        );
    }

    #[test]
    fn runtime_waiter_fails_fast_if_an_adapter_callback_starts_after_it_waits() {
        let shared = std::sync::Arc::new(SharedRuntime {
            runtime: std::sync::Mutex::new(vaultkern_runtime::Runtime::for_tests()),
            platform: ResidentPlatform::Android,
            adapter_calls: std::sync::Arc::new(AdapterCallGate::default()),
            deferred_passkey_finishes: std::sync::Mutex::new(Vec::new()),
        });
        let held = shared.lock().unwrap();
        let started = std::sync::Arc::new(std::sync::Barrier::new(2));
        let waiting_shared = std::sync::Arc::clone(&shared);
        let waiting_started = std::sync::Arc::clone(&started);
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            waiting_started.wait();
            let result = waiting_shared.lock().map(|_| ());
            sender.send(result).unwrap();
        });
        started.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let callback = shared.adapter_calls.enter();
        let result = receiver
            .recv_timeout(std::time::Duration::from_millis(500))
            .expect("a newly active callback must interrupt an existing runtime waiter");

        assert!(matches!(result, Err(VaultKernError::AdapterCallbackActive)));
        drop(callback);
        drop(held);
        waiter.join().unwrap();
    }
}

uniffi::setup_scaffolding!();
