mod autofill_persist;
mod command_loop;
mod match_fill;
pub mod native_host;
mod passkey;
mod protocol_session;
mod providers;
#[cfg(any(windows, test))]
pub mod resident_ipc;
mod runtime;
mod session;
mod state_paths;
mod sync;
mod unlock;
mod vault_reference_store;

pub use command_loop::{
    encode_zeroizing_json, install_redacted_panic_hook, run_browser_stdio_loop, run_stdio_loop,
};
pub use native_host::render_manifest;
pub use passkey::{
    PlatformPasskeyAssertionInput, PlatformPasskeyAssertionOutput, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
};
pub use protocol_session::{RuntimeProtocolDispatch, RuntimeProtocolSession};
pub use providers::biometric::BiometricProvider;
pub use providers::local_file::LocalFileProvider;
pub use providers::memory::InMemoryProvider;
pub use providers::onedrive::{
    OneDriveMemoryWriteBehavior, OneDriveProvider, OneDriveVaultSourceProvider,
};
pub use providers::onedrive_token_store::OneDriveRefreshTokenStore;
pub use providers::provider::{
    Provider, ProviderCommit, ProviderConflictCopy, ProviderError, ProviderRevision,
    ProviderSnapshot,
};
pub use providers::secure_storage::{SecureStorageError, SecureStorageProvider};
pub use runtime::{
    ExternalKdfDisposition, ExternalKdfFailure, QuickUnlockOutcome,
    QuickUnlockReconciliationCredentials, ResidentKdfPolicy, ResidentRuntimeConfig, Runtime,
    classify_external_kdf_error,
};
pub use state_paths::is_supported_browser_origin;
pub use vaultkern_core::ExternalKdfConfirmation;
