//! Resident Runtime façade.
//!
//! Runtime composes platform adapters and dispatches Runtime Protocol commands.
//! The authoritative vault session and all Working Copy, Commit, Publication,
//! reconciliation, and Conflict Split behavior live behind [`VaultCore`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use vaultkern_runtime_protocol::{RuntimeCommand, RuntimeResponse};

use crate::protocol_session;
use crate::providers::biometric::BiometricProvider;
use crate::providers::onedrive_token_store::OneDriveRefreshTokenStore;
use crate::providers::secure_storage::SecureStorageProvider;
use crate::runtime_dispatch;
use crate::vault_core::VaultCore;

pub use crate::vault_core::{
    ExternalKdfDisposition, ExternalKdfFailure, QuickUnlockOutcome,
    QuickUnlockReconciliationCredentials, ResidentKdfPolicy, ResidentRuntimeConfig,
    classify_external_kdf_error,
};

/// Composition root and Runtime Protocol dispatcher for the resident.
pub struct Runtime {
    pub(crate) vault_core: VaultCore,
}

impl Runtime {
    fn from_vault_core(vault_core: VaultCore) -> Self {
        Self { vault_core }
    }

    pub fn new() -> Self {
        Self::from_vault_core(VaultCore::new())
    }

    pub fn new_with_platform_adapters(
        config: ResidentRuntimeConfig,
        biometric: Box<dyn BiometricProvider>,
        secure_storage: Box<dyn SecureStorageProvider>,
        one_drive_refresh_tokens: Box<dyn OneDriveRefreshTokenStore>,
    ) -> Result<Self> {
        VaultCore::new_with_platform_adapters(
            config,
            biometric,
            secure_storage,
            one_drive_refresh_tokens,
        )
        .map(Self::from_vault_core)
    }

    pub fn new_for_browser_origin(origin: &str) -> Self {
        Self::from_vault_core(VaultCore::new_for_browser_origin(origin))
    }

    pub fn for_tests() -> Self {
        Self::from_vault_core(VaultCore::for_tests())
    }

    pub fn for_tests_at(unix_time: u64) -> Self {
        Self::from_vault_core(VaultCore::for_tests_at(unix_time))
    }

    pub fn for_tests_with_passkey_credential_ids(credential_ids: Vec<String>) -> Self {
        Self::from_vault_core(VaultCore::for_tests_with_passkey_credential_ids(
            credential_ids,
        ))
    }

    pub fn for_tests_with_quick_unlock() -> Self {
        Self::from_vault_core(VaultCore::for_tests_with_quick_unlock())
    }

    pub fn for_tests_with_quick_unlock_failing_contains() -> Self {
        Self::from_vault_core(VaultCore::for_tests_with_quick_unlock_failing_contains())
    }

    pub fn for_tests_with_quick_unlock_failing_delete() -> Self {
        Self::from_vault_core(VaultCore::for_tests_with_quick_unlock_failing_delete())
    }

    pub fn for_tests_with_onedrive_item(
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) -> Self {
        Self::from_vault_core(VaultCore::for_tests_with_onedrive_item(
            drive_id,
            item_id,
            name,
            account_label,
            bytes,
        ))
    }

    pub fn for_tests_at_with_onedrive_item(
        unix_time: u64,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) -> Self {
        Self::from_vault_core(VaultCore::for_tests_at_with_onedrive_item(
            unix_time,
            drive_id,
            item_id,
            name,
            account_label,
            bytes,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_tests_at_with_onedrive_item_and_remote_cache(
        unix_time: u64,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
        cache_dir: impl AsRef<Path>,
    ) -> Self {
        Self::from_vault_core(VaultCore::for_tests_at_with_onedrive_item_and_remote_cache(
            unix_time,
            drive_id,
            item_id,
            name,
            account_label,
            bytes,
            cache_dir,
        ))
    }

    pub fn handle_browser_command(&mut self, command: RuntimeCommand) -> Result<RuntimeResponse> {
        let cancelled = AtomicBool::new(false);
        self.handle_browser_command_cancellable(command, &cancelled)
    }

    pub fn handle_browser_command_cancellable(
        &mut self,
        command: RuntimeCommand,
        cancelled: &AtomicBool,
    ) -> Result<RuntimeResponse> {
        self.handle_browser_command_cancellable_with_quick_unlock_handoff(command, cancelled)
            .map(|(response, _)| response)
    }

    pub fn handle_browser_command_cancellable_with_quick_unlock_handoff(
        &mut self,
        command: RuntimeCommand,
        cancelled: &AtomicBool,
    ) -> Result<(
        RuntimeResponse,
        Option<QuickUnlockReconciliationCredentials>,
    )> {
        self.authorize_browser_command_only(&command, cancelled)?;
        self.dispatch_with_quick_unlock_handoff_cancellable(command, cancelled)
    }

    pub fn authorize_browser_command_only(
        &mut self,
        command: &RuntimeCommand,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        if cancelled.load(Ordering::Acquire) {
            anyhow::bail!("browser request was cancelled");
        }
        if !protocol_session::browser_command_allowed(command) {
            anyhow::bail!("browser command forbidden");
        }
        if cancelled.load(Ordering::Acquire) {
            anyhow::bail!("browser request was cancelled");
        }
        Ok(())
    }

    pub fn handle(&mut self, command: RuntimeCommand) -> Result<RuntimeResponse> {
        self.vault_core.begin_protocol_command();
        let response = runtime_dispatch::dispatch(&mut self.vault_core, command);
        self.vault_core.finish_protocol_command();
        response
    }

    pub fn handle_with_quick_unlock_handoff(
        &mut self,
        command: RuntimeCommand,
    ) -> Result<(
        RuntimeResponse,
        Option<QuickUnlockReconciliationCredentials>,
    )> {
        self.vault_core.begin_protocol_command();
        let response = runtime_dispatch::dispatch(&mut self.vault_core, command);
        let credentials = self.vault_core.take_quick_unlock_handoff();
        response.map(|response| (response, credentials))
    }

    fn dispatch_with_quick_unlock_handoff_cancellable(
        &mut self,
        command: RuntimeCommand,
        cancelled: &AtomicBool,
    ) -> Result<(
        RuntimeResponse,
        Option<QuickUnlockReconciliationCredentials>,
    )> {
        self.vault_core.begin_protocol_command();
        let response = match command {
            RuntimeCommand::VerifyPasskeyUser {
                ceremony_token,
                expected_phase,
                vault_id,
                method,
                password,
            } => self
                .vault_core
                .verify_passkey_user_cancellable(
                    &ceremony_token,
                    expected_phase,
                    &vault_id,
                    method,
                    password.as_deref(),
                    cancelled,
                )
                .map(RuntimeResponse::PasskeyUserVerified),
            command => runtime_dispatch::dispatch(&mut self.vault_core, command),
        };
        let credentials = self.vault_core.take_quick_unlock_handoff();
        response.map(|response| (response, credentials))
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
