//! Explicit resident API ports used by platform shells and acceptance harnesses.
//!
//! Runtime deliberately delegates only named capabilities. It does not expose
//! VaultCore through Deref, so adding a new platform bypass requires an
//! intentional API decision.

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::Result;
use vaultkern_core::ExternalKdfConfirmation;
use vaultkern_runtime_protocol::*;

use crate::passkey::{
    PlatformPasskeyAssertionInput, PlatformPasskeyAssertionOutput, PlatformPasskeyCredential,
    PlatformPasskeyRegistrationInput, PlatformPasskeyRegistrationOutput,
};
use crate::providers::catalog::ProviderAccessCounts;
use crate::runtime::{QuickUnlockOutcome, QuickUnlockReconciliationCredentials, Runtime};

impl Runtime {
    pub fn set_parent_window_handle(&mut self, parent_window: Option<usize>) {
        self.vault_core.set_parent_window_handle(parent_window);
    }

    pub fn replace_parent_window_handle(&mut self, parent_window: Option<usize>) -> Option<usize> {
        self.vault_core.replace_parent_window_handle(parent_window)
    }

    pub fn set_test_unix_time(&mut self, unix_time: u64) {
        self.vault_core.set_test_unix_time(unix_time);
    }

    pub fn set_test_unix_time_ms(&mut self, unix_time_ms: u64) {
        self.vault_core.set_test_unix_time_ms(unix_time_ms);
    }

    pub fn bind_quick_unlock_policy_gate(&mut self, gate: Arc<AtomicBool>) {
        self.vault_core.bind_quick_unlock_policy_gate(gate);
    }

    pub fn replace_test_onedrive_item(&mut self, drive_id: &str, item_id: &str, bytes: Vec<u8>) {
        self.vault_core
            .replace_test_onedrive_item(drive_id, item_id, bytes);
    }

    pub fn insert_test_onedrive_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) {
        self.vault_core
            .insert_test_onedrive_item(drive_id, item_id, name, account_label, bytes);
    }

    pub fn remove_test_onedrive_item(&mut self, drive_id: &str, item_id: &str) {
        self.vault_core.remove_test_onedrive_item(drive_id, item_id);
    }

    pub fn read_test_onedrive_item_bytes(&self, drive_id: &str, item_id: &str) -> Result<Vec<u8>> {
        self.vault_core
            .read_test_onedrive_item_bytes(drive_id, item_id)
    }

    pub fn test_onedrive_item_revision(&self, drive_id: &str, item_id: &str) -> Result<u64> {
        self.vault_core
            .test_onedrive_item_revision(drive_id, item_id)
    }

    pub fn set_test_onedrive_item_revision(
        &mut self,
        drive_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        self.vault_core
            .set_test_onedrive_item_revision(drive_id, item_id, revision)
    }

    pub fn reset_test_onedrive_access_counts(&self) {
        self.vault_core.reset_test_onedrive_access_counts();
    }

    pub fn test_onedrive_access_counts(&self) -> ProviderAccessCounts {
        self.vault_core.test_onedrive_access_counts()
    }

    pub fn queue_test_onedrive_precondition_failure(&mut self, replacement_bytes: Option<Vec<u8>>) {
        self.vault_core
            .queue_test_onedrive_precondition_failure(replacement_bytes);
    }

    pub fn queue_test_onedrive_ambiguous_write(&mut self, committed: bool) {
        self.vault_core
            .queue_test_onedrive_ambiguous_write(committed);
    }

    pub fn queue_test_onedrive_ambiguous_write_with_unavailable_readback(
        &mut self,
        committed: bool,
    ) {
        self.vault_core
            .queue_test_onedrive_ambiguous_write_with_unavailable_readback(committed);
    }

    pub fn fail_next_test_onedrive_conflict_copy(&self) {
        self.vault_core.fail_next_test_onedrive_conflict_copy();
    }

    pub fn open_local_vault(&mut self, path: &str) -> Result<VaultHandleDto> {
        self.vault_core.open_local_vault(path)
    }

    pub fn add_local_vault_reference(&mut self, path: &str) -> Result<VaultReferenceDto> {
        self.vault_core.add_local_vault_reference(path)
    }

    pub fn add_onedrive_vault_reference(
        &mut self,
        drive_id: &str,
        item_id: &str,
    ) -> Result<VaultReferenceDto> {
        self.vault_core
            .add_onedrive_vault_reference(drive_id, item_id)
    }

    pub fn list_recent_vaults(&self) -> Result<VaultReferenceListDto> {
        self.vault_core.list_recent_vaults()
    }

    pub fn set_current_vault(&mut self, vault_ref_id: &str) -> Result<()> {
        self.vault_core.set_current_vault(vault_ref_id)
    }

    pub fn delete_vault_reference(&mut self, vault_ref_id: &str) -> Result<VaultReferenceListDto> {
        self.vault_core.delete_vault_reference(vault_ref_id)
    }

    pub fn unlock_with_password(&mut self, vault_id: &str, password: &str) -> Result<()> {
        self.vault_core.unlock_with_password(vault_id, password)
    }

    pub fn unlock_vault(
        &mut self,
        vault_id: &str,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.vault_core
            .unlock_vault(vault_id, password, key_file_path)
    }

    pub fn unlock_vault_with_kdf_confirmation(
        &mut self,
        vault_id: &str,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        self.vault_core.unlock_vault_with_kdf_confirmation(
            vault_id,
            password,
            key_file_path,
            confirmation,
        )
    }

    pub fn unlock_current_vault_with_password(&mut self, password: &str) -> Result<()> {
        self.vault_core.unlock_current_vault_with_password(password)
    }

    pub fn unlock_current_vault_with_kdf_confirmation(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        self.vault_core.unlock_current_vault_with_kdf_confirmation(
            password,
            key_file_path,
            confirmation,
        )
    }

    pub fn unlock_current_vault_with_quick_unlock(&mut self) -> Result<()> {
        self.vault_core.unlock_current_vault_with_quick_unlock()
    }

    pub fn lock_session(&mut self) {
        self.vault_core.lock_session();
    }

    pub fn try_lock_session(&mut self) -> Result<()> {
        self.vault_core.try_lock_session()
    }

    pub fn ensure_no_active_platform_passkey_operation(&self) -> Result<()> {
        self.vault_core
            .ensure_no_active_platform_passkey_operation()
    }

    pub fn close_vault(&mut self, vault_id: &str) -> Result<()> {
        self.vault_core.close_vault(vault_id)
    }

    pub fn enable_quick_unlock_for_current_vault(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.vault_core
            .enable_quick_unlock_for_current_vault(password, key_file_path)
    }

    pub fn enroll_quick_unlock_for_current_vault(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
    ) -> Result<()> {
        self.vault_core
            .enroll_quick_unlock_for_current_vault(password, key_file_path)
    }

    pub fn enroll_quick_unlock_for_current_vault_with_kdf_confirmation(
        &mut self,
        password: Option<&str>,
        key_file_path: Option<&str>,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<()> {
        self.vault_core
            .enroll_quick_unlock_for_current_vault_with_kdf_confirmation(
                password,
                key_file_path,
                confirmation,
            )
    }

    pub fn try_unlock_current_vault_with_quick_unlock(
        &mut self,
        confirmation: ExternalKdfConfirmation,
    ) -> Result<QuickUnlockOutcome> {
        self.vault_core
            .try_unlock_current_vault_with_quick_unlock(confirmation)
    }

    pub fn reconcile_quick_unlock(
        &mut self,
        enabled: bool,
        credentials: Option<QuickUnlockReconciliationCredentials>,
    ) -> Result<bool> {
        self.vault_core.reconcile_quick_unlock(enabled, credentials)
    }

    pub fn disable_quick_unlock_for_current_vault(&mut self) -> Result<()> {
        self.vault_core.disable_quick_unlock_for_current_vault()
    }

    pub fn bind_quick_unlock_reconciliation_credentials(
        &self,
        credentials: QuickUnlockReconciliationCredentials,
        expected_vault_ref_id: &str,
    ) -> Result<QuickUnlockReconciliationCredentials> {
        self.vault_core
            .bind_quick_unlock_reconciliation_credentials(credentials, expected_vault_ref_id)
    }

    pub fn platform_passkey_is_unlocked(&self) -> bool {
        self.vault_core.platform_passkey_is_unlocked()
    }

    pub fn has_active_platform_passkey_operations(&self) -> bool {
        self.vault_core.has_active_platform_passkey_operations()
    }

    pub fn prepare_platform_passkey_operation(
        &mut self,
        operation_id: Vec<u8>,
        parent_window: Option<usize>,
    ) -> Result<(Vec<PlatformPasskeyCredential>, bool)> {
        self.vault_core
            .prepare_platform_passkey_operation(operation_id, parent_window)
    }

    pub fn end_platform_passkey_operation(&mut self, operation_id: &[u8]) {
        self.vault_core.end_platform_passkey_operation(operation_id);
    }

    pub fn register_platform_passkey_for_operation(
        &mut self,
        operation_id: &[u8],
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput> {
        self.vault_core
            .register_platform_passkey_for_operation(operation_id, input)
    }

    pub fn register_platform_passkey(
        &mut self,
        input: PlatformPasskeyRegistrationInput,
    ) -> Result<PlatformPasskeyRegistrationOutput> {
        self.vault_core.register_platform_passkey(input)
    }

    pub fn commit_platform_passkey_registration_operation(
        &mut self,
        operation_id: &[u8],
    ) -> Result<()> {
        self.vault_core
            .commit_platform_passkey_registration_operation(operation_id)
    }

    pub fn create_platform_passkey_assertion_for_operation(
        &mut self,
        operation_id: &[u8],
        input: PlatformPasskeyAssertionInput,
    ) -> Result<PlatformPasskeyAssertionOutput> {
        self.vault_core
            .create_platform_passkey_assertion_for_operation(operation_id, input)
    }

    pub fn list_platform_passkey_credentials(&self) -> Result<Vec<PlatformPasskeyCredential>> {
        self.vault_core.list_platform_passkey_credentials()
    }

    pub fn session_state(&self) -> SessionStateDto {
        self.vault_core.session_state()
    }

    pub fn list_groups(&self, vault_id: &str) -> Result<GroupTreeDto> {
        self.vault_core.list_groups(vault_id)
    }

    pub fn list_entries(&self, vault_id: &str) -> Result<Vec<EntrySummaryDto>> {
        self.vault_core.list_entries(vault_id)
    }

    pub fn list_entry_history(
        &self,
        vault_id: &str,
        entry_id: &str,
    ) -> Result<EntryHistoryListDto> {
        self.vault_core.list_entry_history(vault_id, entry_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_entry(
        &mut self,
        vault_id: &str,
        parent_group_id: &str,
        title: SensitiveString,
        username: SensitiveString,
        password: SensitiveString,
        url: SensitiveString,
        notes: SensitiveString,
        totp_uri: Option<SensitiveString>,
    ) -> Result<EntryDetailDto> {
        self.vault_core.create_entry(
            vault_id,
            parent_group_id,
            title,
            username,
            password,
            url,
            notes,
            totp_uri,
        )
    }

    pub fn get_entry_detail(&self, vault_id: &str, entry_id: &str) -> Result<EntryDetailDto> {
        self.vault_core.get_entry_detail(vault_id, entry_id)
    }

    pub fn get_database_settings(&self, vault_id: &str) -> Result<DatabaseSettingsDto> {
        self.vault_core.get_database_settings(vault_id)
    }

    pub fn update_database_settings(
        &mut self,
        vault_id: &str,
        update: DatabaseSettingsUpdateDto,
    ) -> Result<DatabaseSettingsDto> {
        self.vault_core.update_database_settings(vault_id, update)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_entry_fields(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        title: SensitiveString,
        username: SensitiveString,
        password: SensitiveString,
        url: SensitiveString,
        notes: SensitiveString,
        totp_uri: Option<SensitiveString>,
        custom_fields: Vec<EntryCustomFieldDto>,
    ) -> Result<EntryDetailDto> {
        self.vault_core.update_entry_fields(
            vault_id,
            entry_id,
            title,
            username,
            password,
            url,
            notes,
            totp_uri,
            custom_fields,
        )
    }

    pub fn retry_vault_source_sync(&mut self, vault_id: &str) -> Result<VaultSourceStatusDto> {
        self.vault_core.retry_vault_source_sync(vault_id)
    }
}
