//! Runtime Protocol command dispatch.
//!
//! This module owns the exhaustive wire-command routing while VaultCore owns
//! Working Copy, Commit, Publication, reconciliation, and Conflict Split behavior.

use anyhow::{Context, Result};
use vaultkern_runtime_protocol::*;

use crate::match_fill::score_origin_scoped_entry_match;
use crate::vault_core::{
    ExactEntryFields, PasskeyCeremonyIdentity, VaultCore, query_error_response,
};

pub(crate) fn dispatch(core: &mut VaultCore, command: RuntimeCommand) -> Result<RuntimeResponse> {
    match command {
        RuntimeCommand::Handshake {
            protocol_version,
            capabilities,
        } => Ok(RuntimeResponse::Handshake(HandshakeDto {
            protocol_version,
            capabilities,
        })),
        RuntimeCommand::GetSessionState => Ok(RuntimeResponse::SessionState(core.session_state())),
        RuntimeCommand::ListRecentVaults => core
            .list_recent_vaults()
            .map(RuntimeResponse::VaultReferenceList),
        RuntimeCommand::PreloadCurrentVault => core
            .preload_current_vault_snapshot()
            .map(|_| RuntimeResponse::SessionState(core.session_state())),
        RuntimeCommand::AddLocalVaultReference { path } => {
            let selected = match path {
                Some(path) => path,
                None => core
                    .pick_local_file()?
                    .context("local vault selection canceled")?,
            };

            core.add_local_vault_reference(&selected)
                .map(RuntimeResponse::VaultReference)
        }
        RuntimeCommand::BeginOneDriveLogin => core
            .begin_one_drive_login()
            .map(RuntimeResponse::OneDriveAuthSession),
        RuntimeCommand::CompletePendingOneDriveLogin => core
            .complete_pending_one_drive_login()
            .map(RuntimeResponse::OneDriveAuthStatus),
        RuntimeCommand::ListOneDriveChildren { parent_item_id } => core
            .list_one_drive_children(parent_item_id.as_deref())
            .map(RuntimeResponse::OneDriveItemList),
        RuntimeCommand::AddOneDriveVaultReference { drive_id, item_id } => core
            .add_onedrive_vault_reference(&drive_id, &item_id)
            .map(RuntimeResponse::VaultReference),
        RuntimeCommand::SetCurrentVault { vault_ref_id } => core
            .set_current_vault(&vault_ref_id)
            .map(|_| RuntimeResponse::SessionState(core.session_state())),
        RuntimeCommand::RetryVaultSourceSync { vault_id } => core
            .retry_vault_source_sync(&vault_id)
            .map(RuntimeResponse::VaultSourceStatus),
        RuntimeCommand::DeleteVaultReference { vault_ref_id } => core
            .delete_vault_reference(&vault_ref_id)
            .map(RuntimeResponse::VaultReferenceList),
        RuntimeCommand::DeleteVaultReferenceIfNotCurrent { vault_ref_id } => core
            .delete_vault_reference_if_not_current(&vault_ref_id)
            .map(RuntimeResponse::VaultReferenceList),
        RuntimeCommand::UnlockCurrentVaultWithPassword { password } => {
            core.unlock_current_vault_with_password(&password)?;
            core.remember_quick_unlock_enrollment(Some(password), None);
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::UnlockCurrentVault {
            password,
            key_file_path,
        } => {
            core.unlock_current_vault(password.as_deref(), key_file_path.as_deref())?;
            core.remember_quick_unlock_enrollment(password, key_file_path);
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::EnableQuickUnlockForCurrentVault { .. }
        | RuntimeCommand::DisableQuickUnlockForCurrentVault => {
            anyhow::bail!("quick unlock is managed by resident-app settings reconciliation")
        }
        RuntimeCommand::UnlockCurrentVaultWithQuickUnlock => {
            core.unlock_current_vault_with_quick_unlock()?;
            core.clear_quick_unlock_handoff();
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::OpenLocalVault { path } => core
            .open_local_vault(&path)
            .map(RuntimeResponse::VaultOpened),
        RuntimeCommand::LockSession => {
            core.lock_session();
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::RecordUserActivity => {
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::UnlockWithPassword { vault_id, password } => {
            core.unlock_with_password(&vault_id, &password)?;
            core.remember_quick_unlock_enrollment(Some(password), None);
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::UnlockVault {
            vault_id,
            password,
            key_file_path,
        } => {
            core.unlock_vault(&vault_id, password.as_deref(), key_file_path.as_deref())?;
            core.remember_quick_unlock_enrollment(password, key_file_path);
            Ok(RuntimeResponse::SessionState(core.session_state()))
        }
        RuntimeCommand::CreateGroup {
            vault_id,
            parent_group_id,
            title,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime
                    .create_group(&vault_id, &parent_group_id, title)
                    .map(Some)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::RenameGroup {
            vault_id,
            group_id,
            title,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.rename_group(&vault_id, &group_id, title)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::MoveGroup {
            vault_id,
            group_id,
            target_parent_group_id,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.move_group(&vault_id, &group_id, &target_parent_group_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::DeleteGroup { vault_id, group_id } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.delete_group(&vault_id, &group_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::MoveEntryToGroup {
            vault_id,
            entry_id,
            target_group_id,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.move_entry_to_group(&vault_id, &entry_id, &target_group_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::RestoreEntryHistory {
            vault_id,
            entry_id,
            history_index,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.restore_entry_history(&vault_id, &entry_id, history_index)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::ClearEntryHistory { vault_id, entry_id } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.clear_entry_history(&vault_id, &entry_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::RecycleEntry { vault_id, entry_id } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.recycle_entry(&vault_id, &entry_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::RestoreRecycledEntry {
            vault_id,
            entry_id,
            target_group_id,
        } => core
            .commit_vault_mutation(&vault_id, |runtime| {
                runtime.restore_recycled_entry(&vault_id, &entry_id, target_group_id.as_deref())?;
                Ok(None)
            })
            .map(RuntimeResponse::VaultMutationResult),
        RuntimeCommand::CreateEntry {
            vault_id,
            parent_group_id,
            title,
            username,
            password,
            url,
            notes,
            totp_uri,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .create_entry(
                        &vault_id,
                        &parent_group_id,
                        title,
                        username,
                        password,
                        url,
                        notes,
                        totp_uri,
                    )
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::UpdateEntryFields {
            vault_id,
            entry_id,
            title,
            username,
            password,
            url,
            notes,
            totp_uri,
            custom_fields,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .update_entry_fields(
                        &vault_id,
                        &entry_id,
                        title,
                        username,
                        password,
                        url,
                        notes,
                        totp_uri,
                        custom_fields,
                    )
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::CreateAutofillEntry {
            vault_id,
            parent_group_id,
            mut expected_matching_entry_ids,
            title,
            username,
            password,
            url,
            notes,
            totp_uri,
        } => {
            if password.is_empty() || score_origin_scoped_entry_match(&url, &url).is_none() {
                return Ok(RuntimeResponse::Error(ErrorDto {
                    code: "invalid_autofill_mutation".into(),
                    message: "browser login create fields are invalid".into(),
                }));
            }
            expected_matching_entry_ids.sort();
            let current_matching_entry_ids = core.exact_matching_entry_ids_for(
                &vault_id,
                ExactEntryFields {
                    title: title.as_str(),
                    username: username.as_str(),
                    password: password.as_str(),
                    url: url.as_str(),
                    notes: notes.as_str(),
                    totp_uri: totp_uri.as_deref(),
                    custom_fields: &[],
                },
            )?;
            if current_matching_entry_ids != expected_matching_entry_ids {
                return Ok(RuntimeResponse::Error(ErrorDto {
                    code: "create_matching_set_changed".into(),
                    message: "matching logins changed after confirmation".into(),
                }));
            }
            core.commit_entry_mutation(&vault_id, |runtime| {
                runtime.create_entry(
                    &vault_id,
                    &parent_group_id,
                    title,
                    username,
                    password,
                    url,
                    notes,
                    totp_uri,
                )?;
                Ok(None)
            })
            .map(RuntimeResponse::EntryMutationResult)
        }
        RuntimeCommand::UpdateAutofillEntryFields {
            vault_id,
            entry_id,
            expected_fields,
            desired_fields,
        } => {
            if desired_fields.password.is_empty()
                || score_origin_scoped_entry_match(&expected_fields.url, &desired_fields.url)
                    .is_none()
            {
                return Ok(RuntimeResponse::Error(ErrorDto {
                    code: "invalid_autofill_mutation".into(),
                    message: "browser login update fields are invalid".into(),
                }));
            }
            let current =
                core.get_autofill_entry_fields(&vault_id, &entry_id, &expected_fields.url)?;
            if current.fields != expected_fields {
                return Ok(RuntimeResponse::Error(ErrorDto {
                    code: "conflict".into(),
                    message: "entry fields changed after confirmation".into(),
                }));
            }
            if current.fields == desired_fields {
                return core
                    .unchanged_entry_mutation_result(&vault_id)
                    .map(RuntimeResponse::EntryMutationResult);
            }
            core.commit_entry_mutation(&vault_id, |runtime| {
                let current = runtime.get_entry_detail(&vault_id, &entry_id)?;
                runtime.update_entry_fields(
                    &vault_id,
                    &entry_id,
                    current.title,
                    desired_fields.username,
                    desired_fields.password,
                    desired_fields.url,
                    current.notes,
                    current.totp_uri,
                    current.custom_fields,
                )?;
                Ok(None)
            })
            .map(RuntimeResponse::EntryMutationResult)
        }
        RuntimeCommand::ClearEntryTotp { vault_id, entry_id } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime.clear_entry_totp(&vault_id, &entry_id).map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::SetEntryPasskey {
            vault_id,
            entry_id,
            passkey,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .set_entry_passkey(&vault_id, &entry_id, passkey)
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::ClearEntryPasskey { vault_id, entry_id } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime.clear_entry_passkey(&vault_id, &entry_id).map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::GetPasskeyUserVerificationCapability => {
            Ok(RuntimeResponse::PasskeyUserVerificationCapability(
                core.passkey_user_verification_capability(),
            ))
        }
        RuntimeCommand::VerifyPasskeyUser {
            ceremony_token,
            expected_phase,
            vault_id,
            method,
            password,
        } => core
            .verify_passkey_user(
                &ceremony_token,
                expected_phase,
                &vault_id,
                method,
                password.as_deref(),
            )
            .map(RuntimeResponse::PasskeyUserVerified),
        RuntimeCommand::DeleteEntry { vault_id, entry_id } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime.delete_entry(&vault_id, &entry_id)?;
                Ok(None)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::GetEntryAttachmentContent {
            vault_id,
            entry_id,
            name,
        } => core
            .get_entry_attachment_content(&vault_id, &entry_id, &name)
            .map(RuntimeResponse::EntryAttachmentContent),
        RuntimeCommand::AddEntryAttachment {
            vault_id,
            entry_id,
            name,
            data_base64,
            protect_in_memory,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .add_entry_attachment(
                        &vault_id,
                        &entry_id,
                        name,
                        data_base64,
                        protect_in_memory,
                    )
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::UpdateEntryAttachmentMetadata {
            vault_id,
            entry_id,
            old_name,
            new_name,
            protect_in_memory,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .update_entry_attachment_metadata(
                        &vault_id,
                        &entry_id,
                        &old_name,
                        new_name,
                        protect_in_memory,
                    )
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::ReplaceEntryAttachmentContent {
            vault_id,
            entry_id,
            name,
            data_base64,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .replace_entry_attachment_content(&vault_id, &entry_id, &name, data_base64)
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::DeleteEntryAttachment {
            vault_id,
            entry_id,
            name,
        } => core
            .commit_entry_mutation(&vault_id, |runtime| {
                runtime
                    .delete_entry_attachment(&vault_id, &entry_id, &name)
                    .map(Some)
            })
            .map(RuntimeResponse::EntryMutationResult),
        RuntimeCommand::RetryVaultPublication { vault_id } => {
            core.retry_publication_command(&vault_id)
        }
        RuntimeCommand::GetDatabaseSettings { vault_id } => {
            Ok(match core.get_database_settings(&vault_id) {
                Ok(settings) => RuntimeResponse::DatabaseSettings(settings),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::UpdateDatabaseSettings { vault_id, update } => {
            Ok(match core.commit_database_settings(&vault_id, update) {
                Ok(result) => RuntimeResponse::DatabaseSettingsCommitResult(result),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::ListGroups { vault_id } => Ok(match core.list_groups(&vault_id) {
            Ok(groups) => RuntimeResponse::GroupTree(groups),
            Err(error) => query_error_response(error),
        }),
        RuntimeCommand::ListEntries { vault_id } => Ok(match core.list_entries(&vault_id) {
            Ok(entries) => RuntimeResponse::EntryList(EntryListDto { entries }),
            Err(error) => query_error_response(error),
        }),
        RuntimeCommand::GetEntryDetail { vault_id, entry_id } => {
            Ok(match core.get_entry_detail(&vault_id, &entry_id) {
                Ok(detail) => RuntimeResponse::EntryDetail(detail),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::ListEntryHistory { vault_id, entry_id } => {
            Ok(match core.list_entry_history(&vault_id, &entry_id) {
                Ok(history) => RuntimeResponse::EntryHistoryList(history),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::GetEntryHistoryDetail {
            vault_id,
            entry_id,
            history_index,
        } => Ok(
            match core.get_entry_history_detail(&vault_id, &entry_id, history_index) {
                Ok(detail) => RuntimeResponse::EntryHistoryDetail(detail),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::FindFillCandidates { vault_id, url } => {
            Ok(match core.find_fill_candidates(&vault_id, &url) {
                Ok(candidates) => RuntimeResponse::FillCandidates(candidates),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::GetAutofillCredential {
            vault_id,
            entry_id,
            url,
        } => Ok(
            match core.get_autofill_credential(&vault_id, &entry_id, &url) {
                Ok(credential) => RuntimeResponse::AutofillCredential(credential),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::GetAutofillEntryFields {
            vault_id,
            entry_id,
            url,
        } => Ok(
            match core.get_autofill_entry_fields(&vault_id, &entry_id, &url) {
                Ok(fields) => RuntimeResponse::AutofillEntryFields(fields),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::GetAutofillCreateContext { vault_id } => {
            Ok(match core.get_autofill_create_context(&vault_id) {
                Ok(context) => RuntimeResponse::AutofillCreateContext(context),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::ActivateResidentApp { .. } => Ok(RuntimeResponse::Error(ErrorDto {
            code: "resident_ui_unavailable".into(),
            message: "resident app activation is only available through the desktop bridge".into(),
        })),
        RuntimeCommand::GetBrowserIntegrationSettings => Ok(RuntimeResponse::Error(ErrorDto {
            code: "desktop_settings_unavailable".into(),
            message: "browser integration settings are owned by the resident shell".into(),
        })),
        RuntimeCommand::FindExactMatchingEntryIds { vault_id, fields } => {
            Ok(match core.exact_matching_entry_ids(&vault_id, &fields) {
                Ok(entry_ids) => RuntimeResponse::EntryIdList(EntryIdListDto { entry_ids }),
                Err(error) => query_error_response(error),
            })
        }
        RuntimeCommand::ListPasskeyCredentials {
            ceremony_token,
            expected_phase,
            vault_id,
            relying_party,
        } => Ok(
            match core.list_passkey_credentials(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &relying_party,
            ) {
                Ok(credentials) => RuntimeResponse::PasskeyCredentialList(credentials),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::RegisterPasskeyCeremony {
            ceremony_token,
            connection_id,
            origin,
            top_origin,
            ancestor_origins,
            relying_party,
            ceremony,
            discoverable,
            user_verification,
            challenge_base64url,
            request_id,
            tab_id,
            frame_id,
            frame_kind,
            registered_at_epoch_ms,
            expires_at_epoch_ms,
        } => core
            .register_passkey_ceremony(
                &ceremony_token,
                PasskeyCeremonyIdentity {
                    connection_id,
                    origin,
                    top_origin,
                    ancestor_origins,
                    relying_party,
                    ceremony,
                    discoverable,
                    user_verification,
                    challenge_base64url,
                    request_id,
                    tab_id,
                    frame_id,
                    frame_kind,
                    registered_at_epoch_ms,
                    expires_at_epoch_ms,
                },
            )
            .map(RuntimeResponse::PasskeyCeremonyRegistered),
        RuntimeCommand::AdvancePasskeyCeremonyPhase {
            ceremony_token,
            expected_phase,
            next_phase,
            related_origin_verified,
        } => core
            .advance_passkey_ceremony_phase(
                &ceremony_token,
                expected_phase,
                next_phase,
                related_origin_verified,
            )
            .map(RuntimeResponse::PasskeyCeremonyAdvanced),
        RuntimeCommand::BindPasskeyCeremonyVault {
            ceremony_token,
            expected_phase,
            vault_id,
        } => core
            .bind_passkey_ceremony_vault(&ceremony_token, expected_phase, &vault_id)
            .map(RuntimeResponse::PasskeyCeremonyVaultBound),
        RuntimeCommand::QueryPasskeyCeremonyLedger { ceremony_token } => {
            Ok(RuntimeResponse::PasskeyCeremonyLedger(
                core.query_passkey_ceremony_ledger(&ceremony_token),
            ))
        }
        RuntimeCommand::ReconcilePasskeyCeremonyLedger {
            active_connection_id,
        } => core
            .reconcile_passkey_ceremony_ledger(&active_connection_id)
            .map(RuntimeResponse::PasskeyCeremonyReconciliation),
        RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token,
            expected_phase,
        } => Ok(
            match core.mark_passkey_ceremony_unknown_delivery(&ceremony_token, expected_phase) {
                Ok(response) => RuntimeResponse::PasskeyCeremonyAdvanced(response),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::CreatePasskeyAssertion {
            ceremony_token,
            expected_phase,
            vault_id,
            relying_party,
            origin,
            credential_id,
            discoverable,
            user_presence_verified,
            related_origin_verified,
            client_data_json_base64url,
        } => Ok(
            match core.create_passkey_assertion(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &relying_party,
                &origin,
                credential_id.as_deref(),
                discoverable,
                user_presence_verified,
                related_origin_verified,
                &client_data_json_base64url,
            ) {
                Ok(assertion) => RuntimeResponse::PasskeyAssertion(assertion),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::CreatePasskeyRegistration {
            ceremony_token,
            expected_phase,
            vault_id,
            relying_party,
            origin,
            user_name,
            user_display_name,
            user_handle_base64url,
            public_key_algorithm,
            related_origin_verified,
            client_data_json_base64url,
        } => Ok(
            match core.create_passkey_registration(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &relying_party,
                &origin,
                &user_name,
                user_display_name.as_deref(),
                &user_handle_base64url,
                public_key_algorithm,
                related_origin_verified,
                &client_data_json_base64url,
            ) {
                Ok(registration) => RuntimeResponse::PasskeyRegistration(registration),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::SavePasskeyRegistration {
            ceremony_token,
            expected_phase,
            vault_id,
        } => Ok(
            match core.save_passkey_registration(&ceremony_token, expected_phase, &vault_id) {
                Ok(response) => response,
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::AbortPasskeyRegistration {
            ceremony_token,
            expected_phase,
            closed_phase,
        } => Ok(
            match core.abort_passkey_registration(&ceremony_token, expected_phase, closed_phase) {
                Ok(()) => RuntimeResponse::Saved,
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::CommitPasskeyRegistration {
            ceremony_token,
            expected_phase,
            vault_id,
            entry_id,
            credential_id,
        } => Ok(
            match core.commit_passkey_registration(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &entry_id,
                &credential_id,
            ) {
                Ok(()) => RuntimeResponse::Saved,
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::PasskeyCredentialStatus {
            ceremony_token,
            expected_phase,
            vault_id,
            credential_id,
            relying_party,
        } => Ok(
            match core.passkey_credential_status(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &credential_id,
                &relying_party,
            ) {
                Ok(status) => RuntimeResponse::PasskeyCredentialStatus(status),
                Err(error) => query_error_response(error),
            },
        ),
        RuntimeCommand::PasskeyCredentialStatusBatch {
            ceremony_token,
            expected_phase,
            vault_id,
            credential_ids,
            relying_party,
        } => Ok(
            match core.passkey_credential_status_batch(
                &ceremony_token,
                expected_phase,
                &vault_id,
                &credential_ids,
                &relying_party,
            ) {
                Ok(status) => RuntimeResponse::PasskeyCredentialStatusBatch(status),
                Err(error) => query_error_response(error),
            },
        ),
    }
}
