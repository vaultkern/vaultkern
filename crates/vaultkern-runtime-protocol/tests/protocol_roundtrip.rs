use vaultkern_runtime_protocol::{
    AutofillCacheStateDto, AutofillCommittedFingerprintDto, AutofillPersistConflictCodeDto,
    AutofillPersistDispositionDto, AutofillPersistDurabilityDto, AutofillPersistOutcomeDto,
    AutofillPersistPlanDto, AutofillPersistResultDto, AutofillUpdateFieldsDto, CommitStatusDto,
    DatabaseCredentialsUpdateDto, DatabaseEncryptionSettingsDto, DatabaseHistorySettingsDto,
    DatabaseKdfSettingsDto, DatabaseMetadataSettingsDto, DatabasePublicMetadataSettingsDto,
    DatabaseRecycleBinSettingsDto, DatabaseSettingsCommitResultDto, DatabaseSettingsDto,
    DatabaseSettingsUpdateDto, EntryAttachmentContentDto, EntryDetailDto, EntryFieldsDto,
    EntryHistoryDetailDto, EntryHistoryItemDto, EntryHistoryListDto, EntryMutationResultDto,
    EntryPasskeyDto, EntryPasskeyUpdateDto, EntrySummaryDto, FillCandidateListDto, GroupNodeDto,
    GroupTreeDto, HandshakeDto, MergeSummaryDto, OneDriveAuthSessionDto, OneDriveAuthStatusDto,
    OneDriveItemDto, OneDriveItemListDto, OptionalSettingUpdateDto, PROTOCOL_VERSION,
    PasskeyAssertionDto, PasskeyCeremonyAdvancedDto, PasskeyCeremonyDeliveryStateDto,
    PasskeyCeremonyDurableStateDto, PasskeyCeremonyKindDto, PasskeyCeremonyLedgerDto,
    PasskeyCeremonyPhaseDto, PasskeyCeremonyReconciledDto, PasskeyCeremonyReconciliationDto,
    PasskeyCeremonyRegisteredDto, PasskeyCredentialCandidateDto, PasskeyCredentialListDto,
    PasskeyCredentialStatusBatchDto, PasskeyCredentialStatusDto, PasskeyFrameKindDto,
    PasskeyRegistrationDto, PasskeyUserVerificationCapabilityDto, PasskeyUserVerificationMethodDto,
    PasskeyUserVerificationRequirementDto, PasskeyUserVerifiedDto, ProtocolEnvelope,
    RuntimeCommand, RuntimeResponse, SaveVaultResultDto, SaveVaultStatusDto, SessionStateDto,
    VaultHandleDto, VaultMutationResultDto, VaultReferenceDto, VaultReferenceListDto,
    VaultSourceStatusDto,
};

static_assertions::assert_not_impl_any!(RuntimeResponse: Clone);
static_assertions::assert_not_impl_any!(EntryDetailDto: Clone);
static_assertions::assert_not_impl_any!(EntryMutationResultDto: Clone);
static_assertions::assert_not_impl_any!(EntryFieldsDto: Clone);
static_assertions::assert_not_impl_any!(AutofillPersistPlanDto: Clone);
static_assertions::assert_not_impl_any!(EntryHistoryDetailDto: Clone);
static_assertions::assert_not_impl_any!(vaultkern_runtime_protocol::EntryCustomFieldDto: Clone);
static_assertions::assert_not_impl_any!(EntryAttachmentContentDto: Clone);
static_assertions::assert_not_impl_any!(EntryPasskeyDto: Clone);

fn autofill_update_fields(password: &str) -> AutofillUpdateFieldsDto {
    AutofillUpdateFieldsDto {
        username: "username".into(),
        password: password.into(),
        url: "https://example.com".into(),
    }
}

#[test]
fn narrowed_browser_autofill_dtos_start_a_new_protocol_major() {
    assert_eq!(PROTOCOL_VERSION, 2);
}

#[test]
fn protocol_roundtrips_the_version_and_capability_handshake() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::Handshake {
        protocol_version: 2,
        capabilities: vec!["runtime-core".into(), "browser-extension".into()],
    });
    let decoded: ProtocolEnvelope =
        serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
    assert_eq!(decoded, envelope);

    let response = RuntimeResponse::Handshake(HandshakeDto {
        protocol_version: 2,
        capabilities: vec!["runtime-core".into()],
    });
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["type"], "handshake");
    assert_eq!(json["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(json["capabilities"], serde_json::json!(["runtime-core"]));
}

#[test]
fn protocol_decodes_the_inert_logical_operation_id_for_compatibility() {
    let envelope: ProtocolEnvelope = serde_json::from_value(serde_json::json!({
        "version": 2,
        "operationId": "client-a-save-1",
        "command": {
            "type": "save_vault",
            "vault_id": "vault-1"
        }
    }))
    .unwrap();

    let encoded = serde_json::to_value(envelope).unwrap();
    assert_eq!(encoded["operationId"], "client-a-save-1");
}

#[test]
fn protocol_envelope_serializes_open_local_vault_command() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::OpenLocalVault {
        path: "/tmp/demo.kdbx".into(),
    });

    let json = serde_json::to_string(&envelope).unwrap();

    assert!(json.contains("\"version\":2"));
    assert!(json.contains("\"open_local_vault\""));
    assert!(json.contains("/tmp/demo.kdbx"));
}

#[test]
fn database_optional_setting_updates_distinguish_unchanged_clear_and_set() {
    let unchanged = serde_json::to_value(DatabaseSettingsUpdateDto::default()).unwrap();
    assert!(unchanged.get("autosaveDelaySeconds").is_none());

    let clear: DatabaseSettingsUpdateDto =
        serde_json::from_value(serde_json::json!({ "autosaveDelaySeconds": null })).unwrap();
    assert_eq!(
        clear.autosave_delay_seconds,
        OptionalSettingUpdateDto::Clear
    );
    assert_eq!(
        serde_json::to_value(&clear).unwrap()["autosaveDelaySeconds"],
        serde_json::Value::Null
    );

    let set: DatabaseSettingsUpdateDto =
        serde_json::from_value(serde_json::json!({ "autosaveDelaySeconds": 30 })).unwrap();
    assert_eq!(
        set.autosave_delay_seconds,
        OptionalSettingUpdateDto::Set(30)
    );
}

#[test]
fn protocol_rejects_the_superseded_conditional_create_command() {
    let json = r#"{
        "version": 2,
        "command": {
            "type": "create_entry_if_matching_entry_ids",
            "vault_id": "vault-1",
            "parent_group_id": "group-root",
            "fields": {
                "title": "Example",
                "username": "alice",
                "password": "secret",
                "url": "https://example.com",
                "notes": "",
                "totpUri": null,
                "customFields": [{"key":"Tenant","value":"prod","protected":true}]
            },
            "expected_matching_entry_ids": []
        }
    }"#;

    assert!(serde_json::from_str::<ProtocolEnvelope>(json).is_err());
}

#[test]
fn protocol_roundtrips_database_settings_commands_and_response() {
    let get = ProtocolEnvelope::new(RuntimeCommand::GetDatabaseSettings {
        vault_id: "vault-1".into(),
    });
    let update = ProtocolEnvelope::new(RuntimeCommand::UpdateDatabaseSettings {
        vault_id: "vault-1".into(),
        update: DatabaseSettingsUpdateDto {
            metadata: Some(DatabaseMetadataSettingsDto {
                name: "Project Vault".into(),
                description: Some("Shared engineering secrets".into()),
                default_username: Some("engineer".into()),
            }),
            public_metadata: Some(DatabasePublicMetadataSettingsDto {
                display_name: Some("Project".into()),
                color: Some("#2f6f73".into()),
                icon: Some("database".into()),
            }),
            history: Some(DatabaseHistorySettingsDto {
                max_items_per_entry: Some(12),
                max_total_size_bytes: Some(1_048_576),
            }),
            recycle_bin: Some(DatabaseRecycleBinSettingsDto { enabled: true }),
            encryption: Some(DatabaseEncryptionSettingsDto {
                compression: "none".into(),
                cipher: "chacha20".into(),
                kdf: DatabaseKdfSettingsDto {
                    algorithm: "aes_kdbx4".into(),
                    transform_rounds: Some(200_000),
                    iterations: None,
                    memory_kib: None,
                    parallelism: None,
                },
            }),
            credentials: Some(DatabaseCredentialsUpdateDto {
                new_password: Some("new-secret".into()),
                remove_password: false,
            }),
            autosave_delay_seconds: OptionalSettingUpdateDto::Set(30),
        },
    });
    let settings = DatabaseSettingsDto {
        metadata: DatabaseMetadataSettingsDto {
            name: "Project Vault".into(),
            description: Some("Shared engineering secrets".into()),
            default_username: Some("engineer".into()),
        },
        public_metadata: DatabasePublicMetadataSettingsDto {
            display_name: Some("Project".into()),
            color: Some("#2f6f73".into()),
            icon: Some("database".into()),
        },
        history: DatabaseHistorySettingsDto {
            max_items_per_entry: Some(12),
            max_total_size_bytes: Some(1_048_576),
        },
        recycle_bin: DatabaseRecycleBinSettingsDto { enabled: true },
        encryption: DatabaseEncryptionSettingsDto {
            compression: "none".into(),
            cipher: "chacha20".into(),
            kdf: DatabaseKdfSettingsDto {
                algorithm: "aes_kdbx4".into(),
                transform_rounds: Some(200_000),
                iterations: None,
                memory_kib: None,
                parallelism: None,
            },
        },
        autosave_delay_seconds: Some(30),
        has_password: true,
    };
    let response = RuntimeResponse::DatabaseSettings(settings.clone());

    for envelope in [get, update] {
        assert_eq!(
            serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&envelope).unwrap())
                .unwrap(),
            envelope
        );
    }

    let value = serde_json::to_value(&response).expect("serialize settings response");
    assert_eq!(value["type"], "database_settings");
    assert_eq!(value["metadata"]["defaultUsername"], "engineer");
    assert_eq!(value["publicMetadata"]["displayName"], "Project");
    assert_eq!(value["history"]["maxTotalSizeBytes"], 1_048_576);
    assert_eq!(value["encryption"]["kdf"]["transformRounds"], 200_000);
    assert_eq!(value["hasPassword"], true);

    let decoded: RuntimeResponse = serde_json::from_value(value).expect("deserialize response");
    assert_eq!(decoded, response);

    let commit_response =
        RuntimeResponse::DatabaseSettingsCommitResult(DatabaseSettingsCommitResultDto {
            commit: CommitStatusDto::Committed,
            settings,
            save_result: SaveVaultResultDto {
                status: SaveVaultStatusDto::Saved,
                merge_summary: None,
                conflict_copy_path: None,
            },
        });
    let value = serde_json::to_value(&commit_response).expect("serialize commit response");
    assert_eq!(value["type"], "database_settings_commit_result");
    assert_eq!(value["commit"], "committed");
    assert_eq!(value["settings"]["metadata"]["name"], "Project Vault");
    assert_eq!(value["saveResult"]["status"], "saved");
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(value).expect("deserialize commit response"),
        commit_response
    );
}

#[test]
fn protocol_roundtrips_remaining_vault_mutations_and_commit_result() {
    let commands = [
        RuntimeCommand::CreateGroup {
            vault_id: "vault-1".into(),
            parent_group_id: "group-root".into(),
            title: "Work".into(),
        },
        RuntimeCommand::RenameGroup {
            vault_id: "vault-1".into(),
            group_id: "group-1".into(),
            title: "Archive".into(),
        },
        RuntimeCommand::MoveGroup {
            vault_id: "vault-1".into(),
            group_id: "group-1".into(),
            target_parent_group_id: "group-2".into(),
        },
        RuntimeCommand::DeleteGroup {
            vault_id: "vault-1".into(),
            group_id: "group-1".into(),
        },
        RuntimeCommand::MoveEntryToGroup {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            target_group_id: "group-1".into(),
        },
        RuntimeCommand::RestoreEntryHistory {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            history_index: 2,
        },
        RuntimeCommand::ClearEntryHistory {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
        },
        RuntimeCommand::RecycleEntry {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
        },
        RuntimeCommand::RestoreRecycledEntry {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            target_group_id: Some("group-root".into()),
        },
    ];
    for command in commands {
        let envelope = ProtocolEnvelope::new(command);
        assert_eq!(
            serde_json::from_value::<ProtocolEnvelope>(
                serde_json::to_value(&envelope).expect("serialize vault mutation command")
            )
            .expect("deserialize vault mutation command"),
            envelope
        );
    }

    let response = RuntimeResponse::VaultMutationResult(VaultMutationResultDto {
        commit: CommitStatusDto::Committed,
        publication: SaveVaultResultDto {
            status: SaveVaultStatusDto::SavedToCache,
            merge_summary: None,
            conflict_copy_path: None,
        },
        created_group_id: Some("group-created".into()),
    });
    let value = serde_json::to_value(&response).expect("serialize vault mutation result");
    assert_eq!(value["type"], "vault_mutation_result");
    assert_eq!(value["commit"], "committed");
    assert_eq!(value["publication"]["status"], "saved_to_cache");
    assert_eq!(value["createdGroupId"], "group-created");
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(value)
            .expect("deserialize vault mutation result"),
        response
    );
}

#[test]
fn protocol_roundtrips_session_state_response() {
    let response = RuntimeResponse::SessionState(SessionStateDto {
        unlocked: false,
        active_vault_id: None,
        current_vault_ref_id: None,
        supports_biometric_unlock: false,
        source_status: None,
    });

    let json = serde_json::to_string(&response).unwrap();
    let decoded: RuntimeResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_remote_source_status() {
    let source_status = VaultSourceStatusDto {
        source_kind: "onedrive".into(),
        remote_state: "cache".into(),
        last_sync_at: Some(1_776_500_000),
        cached_at: Some(1_776_500_030),
        last_error: Some("remote unavailable".into()),
    };
    let session = RuntimeResponse::SessionState(SessionStateDto {
        unlocked: true,
        active_vault_id: Some("onedrive:drive-1:item-1".into()),
        current_vault_ref_id: Some("vault-ref-1".into()),
        supports_biometric_unlock: false,
        source_status: Some(source_status.clone()),
    });
    let retry = ProtocolEnvelope::new(RuntimeCommand::RetryVaultSourceSync {
        vault_id: "onedrive:drive-1:item-1".into(),
    });
    let status_response = RuntimeResponse::VaultSourceStatus(source_status.clone());

    let session_value = serde_json::to_value(&session).expect("serialize session");
    assert_eq!(session_value["type"], "session_state");
    assert_eq!(
        session_value["sourceStatus"]["sourceKind"],
        source_status.source_kind
    );
    assert_eq!(session_value["sourceStatus"]["remoteState"], "cache");
    assert_eq!(
        session_value["sourceStatus"]["lastError"],
        "remote unavailable"
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(session_value).unwrap(),
        session
    );

    let retry_json = serde_json::to_string(&retry).expect("serialize retry command");
    assert!(retry_json.contains("retry_vault_source_sync"));
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&retry_json).unwrap(),
        retry
    );

    let status_value = serde_json::to_value(&status_response).expect("serialize status");
    assert_eq!(status_value["type"], "vault_source_status");
    assert_eq!(status_value["remoteState"], "cache");
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(status_value).unwrap(),
        status_response
    );
}

#[test]
fn protocol_roundtrips_save_vault_result_response() {
    let response = RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
        status: SaveVaultStatusDto::Merged,
        merge_summary: Some(MergeSummaryDto {
            merged_entries: 2,
            history_snapshots_added: 1,
            meta_conflicts_resolved: 1,
            icon_conflicts_resolved: 1,
        }),
        conflict_copy_path: None,
    });

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["type"], "save_vault_result");
    assert_eq!(value["status"], "merged");
    assert_eq!(value["mergeSummary"]["mergedEntries"], 2);
    assert_eq!(value["mergeSummary"]["historySnapshotsAdded"], 1);
    assert_eq!(value["mergeSummary"]["metaConflictsResolved"], 1);
    assert_eq!(value["mergeSummary"]["iconConflictsResolved"], 1);

    // Additive evolution: a summary emitted by an older peer (without the
    // two conflict counters) still deserializes, defaulting them to zero.
    let legacy: MergeSummaryDto =
        serde_json::from_str(r#"{"mergedEntries":2,"historySnapshotsAdded":1}"#)
            .expect("deserialize legacy merge summary");
    assert_eq!(legacy.meta_conflicts_resolved, 0);
    assert_eq!(legacy.icon_conflicts_resolved, 0);

    let decoded: RuntimeResponse = serde_json::from_value(value).expect("deserialize response");
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_local_cache_save_result_response() {
    let response = RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
        status: SaveVaultStatusDto::SavedToCache,
        merge_summary: None,
        conflict_copy_path: None,
    });

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["type"], "save_vault_result");
    assert_eq!(value["status"], "saved_to_cache");
    assert!(value["mergeSummary"].is_null());

    let decoded: RuntimeResponse = serde_json::from_value(value).expect("deserialize response");
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_conflict_copy_save_result() {
    let response = RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
        status: SaveVaultStatusDto::ConflictCopy,
        merge_summary: None,
        conflict_copy_path: Some(r"C:\Vaults\personal (VaultKern conflict 1).kdbx".into()),
    });

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["status"], "conflict_copy");
    assert_eq!(
        value["conflictCopyPath"],
        r"C:\Vaults\personal (VaultKern conflict 1).kdbx"
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(value).unwrap(),
        response
    );
}

#[test]
fn protocol_roundtrips_recent_vault_commands() {
    let list = ProtocolEnvelope::new(RuntimeCommand::ListRecentVaults);
    let preload = ProtocolEnvelope::new(RuntimeCommand::PreloadCurrentVault);
    let set_current = ProtocolEnvelope::new(RuntimeCommand::SetCurrentVault {
        vault_ref_id: "vault-ref-1".into(),
    });
    let delete = ProtocolEnvelope::new(RuntimeCommand::DeleteVaultReference {
        vault_ref_id: "vault-ref-1".into(),
    });
    let guarded_delete = ProtocolEnvelope::new(RuntimeCommand::DeleteVaultReferenceIfNotCurrent {
        vault_ref_id: "vault-ref-2".into(),
    });
    let unlock = ProtocolEnvelope::new(RuntimeCommand::UnlockCurrentVaultWithPassword {
        password: "demo-password".into(),
    });

    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&list).unwrap()).unwrap(),
        list
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&preload).unwrap())
            .unwrap(),
        preload
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&set_current).unwrap())
            .unwrap(),
        set_current
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&guarded_delete).unwrap())
            .unwrap(),
        guarded_delete
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&unlock).unwrap()).unwrap(),
        unlock
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&delete).unwrap()).unwrap(),
        delete
    );
}

#[test]
fn protocol_roundtrips_onedrive_commands() {
    let begin = ProtocolEnvelope::new(RuntimeCommand::BeginOneDriveLogin);
    let complete_pending = ProtocolEnvelope::new(RuntimeCommand::CompletePendingOneDriveLogin);
    let list = ProtocolEnvelope::new(RuntimeCommand::ListOneDriveChildren {
        parent_item_id: Some("folder-1".into()),
    });
    let add = ProtocolEnvelope::new(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: "drive-1".into(),
        item_id: "item-1".into(),
    });

    for envelope in [begin, complete_pending, list, add] {
        assert_eq!(
            serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&envelope).unwrap())
                .unwrap(),
            envelope
        );
    }
}

#[test]
fn protocol_roundtrips_onedrive_responses() {
    let auth = RuntimeResponse::OneDriveAuthSession(OneDriveAuthSessionDto {
        auth_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize".into(),
        redirect_uri: "http://127.0.0.1:53121/callback".into(),
        expires_in_seconds: 600,
    });
    let status = RuntimeResponse::OneDriveAuthStatus(OneDriveAuthStatusDto {
        status: "authorized".into(),
        account_label: Some("alice@example.com".into()),
    });
    let items = RuntimeResponse::OneDriveItemList(OneDriveItemListDto {
        items: vec![OneDriveItemDto {
            drive_id: "drive-1".into(),
            item_id: "item-1".into(),
            name: "Vault.kdbx".into(),
            folder: false,
            size: Some(42),
        }],
    });

    let auth_json = serde_json::to_value(&auth).expect("serialize auth response");
    assert_eq!(auth_json["type"], "one_drive_auth_session");
    assert_eq!(
        auth_json["authUrl"],
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
    );
    assert_eq!(auth_json["expiresInSeconds"], 600);
    assert!(
        auth_json.get("codeVerifier").is_none(),
        "the PKCE verifier must remain inside the runtime"
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(auth_json).unwrap(),
        auth
    );

    let status_json = serde_json::to_value(&status).expect("serialize status response");
    assert_eq!(status_json["type"], "one_drive_auth_status");
    assert_eq!(status_json["accountLabel"], "alice@example.com");
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(status_json).unwrap(),
        status
    );

    let item_json = serde_json::to_value(&items).expect("serialize item response");
    assert_eq!(item_json["type"], "one_drive_item_list");
    assert_eq!(item_json["items"][0]["itemId"], "item-1");
    assert_eq!(item_json["items"][0]["folder"], false);
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(item_json).unwrap(),
        items
    );
}

#[test]
fn protocol_roundtrips_recent_vault_list_shape() {
    let response = RuntimeResponse::VaultReferenceList(VaultReferenceListDto {
        vaults: vec![VaultReferenceDto {
            vault_ref_id: "vault-ref-1".into(),
            display_name: "Demo Vault".into(),
            source_kind: "local".into(),
            source_summary: "demo.kdbx".into(),
            last_used_at: 1_776_500_000,
            availability: "ready".into(),
            supports_quick_unlock: false,
            is_current: true,
        }],
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();
    let vaults = object.get("vaults").unwrap().as_array().unwrap();

    assert_eq!(object.get("type").unwrap(), "vault_reference_list");
    assert_eq!(vaults[0].get("vaultRefId").unwrap(), "vault-ref-1");
    assert_eq!(vaults[0].get("sourceKind").unwrap(), "local");
    assert_eq!(vaults[0].get("isCurrent").unwrap(), true);

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_vault_opened_response_shape() {
    let response = RuntimeResponse::VaultOpened(VaultHandleDto {
        vault_id: "vault-1".into(),
        name: "Demo".into(),
        path: "/tmp/demo.kdbx".into(),
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "vault_opened");
    assert_eq!(object.get("vaultId").unwrap(), "vault-1");
    assert_eq!(object.get("name").unwrap(), "Demo");
    assert_eq!(object.get("path").unwrap(), "/tmp/demo.kdbx");

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_entry_detail_response_shape() {
    let response = RuntimeResponse::EntryDetail(EntryDetailDto {
        id: "entry-1".into(),
        title: "Email".into(),
        username: "user@example.com".into(),
        password: "secret".into(),
        url: "https://example.com".into(),
        notes: "demo".into(),
        modified_at: 42,
        totp: Some("123456".into()),
        totp_uri: Some(
            "otpauth://totp/Test:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
                .into(),
        ),
        passkey: Some(EntryPasskeyDto {
            username: "alice@example.com".into(),
            credential_id: "credential-base64url".into(),
            generated_user_id: Some("generated-user".into()),
            relying_party: "example.com".into(),
            user_handle: Some("user-handle".into()),
            backup_eligible: true,
            backup_state: false,
        }),
        field_protection: vaultkern_runtime_protocol::EntryFieldProtectionDto {
            protect_title: false,
            protect_username: true,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        },
        custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
            key: "RecoveryCode".into(),
            value: "one-time-code".into(),
            protected: true,
        }],
        attachments: vec![vaultkern_runtime_protocol::EntryAttachmentDto {
            name: "backup-codes.txt".into(),
            size: 128,
            protect_in_memory: true,
        }],
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "entry_detail");
    assert_eq!(object.get("id").unwrap(), "entry-1");
    assert_eq!(object.get("title").unwrap(), "Email");
    assert_eq!(object.get("username").unwrap(), "user@example.com");
    assert_eq!(object.get("password").unwrap(), "secret");
    assert_eq!(object.get("url").unwrap(), "https://example.com");
    assert_eq!(object.get("notes").unwrap(), "demo");
    assert_eq!(object.get("modifiedAt").unwrap(), 42);
    assert_eq!(object.get("totp").unwrap(), "123456");
    assert_eq!(
        object.get("totpUri").unwrap(),
        "otpauth://totp/Test:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test"
    );
    let passkey = object.get("passkey").unwrap().as_object().unwrap();
    assert_eq!(passkey.get("username").unwrap(), "alice@example.com");
    assert_eq!(passkey.get("credentialId").unwrap(), "credential-base64url");
    assert_eq!(passkey.get("generatedUserId").unwrap(), "generated-user");
    assert!(
        !passkey.contains_key("privateKeyPem"),
        "entry detail responses must never release a passkey private key"
    );
    assert_eq!(passkey.get("relyingParty").unwrap(), "example.com");
    assert_eq!(passkey.get("userHandle").unwrap(), "user-handle");
    assert_eq!(passkey.get("backupEligible").unwrap(), true);
    assert_eq!(passkey.get("backupState").unwrap(), false);
    let field_protection = object.get("fieldProtection").unwrap().as_object().unwrap();
    assert_eq!(field_protection.get("protectUsername").unwrap(), true);
    assert_eq!(field_protection.get("protectPassword").unwrap(), true);
    let custom_fields = object.get("customFields").unwrap().as_array().unwrap();
    assert_eq!(custom_fields[0].get("key").unwrap(), "RecoveryCode");
    assert_eq!(custom_fields[0].get("value").unwrap(), "one-time-code");
    assert_eq!(custom_fields[0].get("protected").unwrap(), true);
    let attachments = object.get("attachments").unwrap().as_array().unwrap();
    assert_eq!(attachments[0].get("name").unwrap(), "backup-codes.txt");
    assert_eq!(attachments[0].get("size").unwrap(), 128);
    assert_eq!(attachments[0].get("protectInMemory").unwrap(), true);

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_committed_entry_mutation_state() {
    let response = RuntimeResponse::EntryMutationResult(EntryMutationResultDto {
        commit: CommitStatusDto::Committed,
        publication: SaveVaultResultDto {
            status: SaveVaultStatusDto::SavedToCache,
            merge_summary: None,
            conflict_copy_path: None,
        },
        entry: None,
    });

    let value = serde_json::to_value(&response).expect("serialize committed entry mutation");
    assert_eq!(value["type"], "entry_mutation_result");
    assert_eq!(value["commit"], "committed");
    assert_eq!(value["publication"]["status"], "saved_to_cache");
    assert!(value.get("entry").is_none());
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(value).expect("deserialize committed mutation"),
        response
    );
}

#[test]
fn protocol_debug_redacts_master_credentials() {
    let secret = "master-password-must-not-appear-in-debug";
    let envelope = ProtocolEnvelope::new(RuntimeCommand::EnableQuickUnlockForCurrentVault {
        password: Some(secret.into()),
        key_file_path: None,
    });

    let debug = format!("{envelope:?}");

    assert!(
        !debug.contains(secret),
        "master credentials must be redacted from protocol Debug output"
    );
}

#[test]
fn protocol_debug_redacts_all_entry_secret_bearing_dtos() {
    let command = RuntimeCommand::CreateEntry {
        vault_id: "vault-1".into(),
        parent_group_id: "group-1".into(),
        entry_id: None,
        title: "title".into(),
        username: "username".into(),
        password: "command-password-secret".into(),
        url: "https://example.com".into(),
        notes: "notes".into(),
        totp_uri: None,
    };
    let plan = AutofillPersistPlanDto::Update {
        entry_id: "entry-1".into(),
        expected_fields: autofill_update_fields("expected-fields-secret"),
        desired_fields: autofill_update_fields("desired-fields-secret"),
    };
    let custom_field = vaultkern_runtime_protocol::EntryCustomFieldDto {
        key: "RecoveryCode".into(),
        value: "custom-field-secret".into(),
        protected: true,
    };
    let detail = EntryDetailDto {
        id: "entry-1".into(),
        title: "title".into(),
        username: "username".into(),
        password: "entry-detail-secret".into(),
        url: "https://example.com".into(),
        notes: "notes".into(),
        modified_at: 42,
        totp: Some("totp-code-secret".into()),
        totp_uri: None,
        passkey: None,
        field_protection: vaultkern_runtime_protocol::EntryFieldProtectionDto {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        },
        custom_fields: Vec::new(),
        attachments: Vec::new(),
    };
    let history = EntryHistoryDetailDto {
        entry_id: "entry-1".into(),
        history_index: 0,
        title: "title".into(),
        username: "username".into(),
        url: "https://example.com".into(),
        notes: "notes".into(),
        modified_at: 42,
        custom_fields: Vec::new(),
        attachments: Vec::new(),
    };
    let attachment = EntryAttachmentContentDto {
        name: "secret.txt".into(),
        data_base64: "attachment-content-secret".into(),
        protect_in_memory: true,
    };
    let passkey = EntryPasskeyDto {
        username: "alice@example.com".into(),
        credential_id: "passkey-credential-secret".into(),
        generated_user_id: Some("generated-user".into()),
        relying_party: "example.com".into(),
        user_handle: Some("user-handle".into()),
        backup_eligible: false,
        backup_state: false,
    };

    let debug_outputs = [
        format!("{command:?}"),
        format!("{plan:?}"),
        format!("{custom_field:?}"),
        format!("{detail:?}"),
        format!("{history:?}"),
        format!("{attachment:?}"),
        format!("{passkey:?}"),
    ];
    for debug in debug_outputs {
        for secret in [
            "command-password-secret",
            "expected-fields-secret",
            "desired-fields-secret",
            "custom-field-secret",
            "entry-detail-secret",
            "totp-code-secret",
            "history-detail-secret",
            "attachment-content-secret",
            "passkey-credential-secret",
        ] {
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
    }
}

#[test]
fn protocol_secret_dtos_explicitly_zeroize_owned_buffers() {
    use zeroize::Zeroize;

    fn fields(password: &str) -> EntryFieldsDto {
        EntryFieldsDto {
            title: "title".into(),
            username: "username".into(),
            password: password.into(),
            url: "https://example.com".into(),
            notes: "notes".into(),
            totp_uri: Some("otpauth://totp/Test?secret=SECRET".into()),
            custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
                key: "RecoveryCode".into(),
                value: "custom-secret".into(),
                protected: true,
            }],
        }
    }

    let mut nested_fields = fields("nested-secret");
    let mut detail = EntryDetailDto {
        id: "entry-1".into(),
        title: "title".into(),
        username: "username".into(),
        password: "detail-secret".into(),
        url: "https://example.com".into(),
        notes: "notes".into(),
        modified_at: 42,
        totp: Some("123456".into()),
        totp_uri: Some("otpauth://totp/Test?secret=SECRET".into()),
        passkey: None,
        field_protection: vaultkern_runtime_protocol::EntryFieldProtectionDto {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        },
        custom_fields: std::mem::take(&mut nested_fields.custom_fields),
        attachments: Vec::new(),
    };
    let mut history = EntryHistoryDetailDto {
        entry_id: "entry-1".into(),
        history_index: 0,
        title: "title".into(),
        username: "username".into(),
        url: "https://example.com".into(),
        notes: "notes".into(),
        modified_at: 42,
        custom_fields: Vec::new(),
        attachments: Vec::new(),
    };
    let mut attachment = EntryAttachmentContentDto {
        name: "secret.txt".into(),
        data_base64: "attachment-secret".into(),
        protect_in_memory: true,
    };
    let mut plan = AutofillPersistPlanDto::Update {
        entry_id: "entry-1".into(),
        expected_fields: autofill_update_fields("expected-secret"),
        desired_fields: autofill_update_fields("desired-secret"),
    };

    detail.zeroize();
    history.zeroize();
    attachment.zeroize();
    plan.zeroize();

    assert!(detail.password.is_empty());
    assert!(detail.totp.is_none());
    assert!(detail.totp_uri.is_none());
    assert!(detail.custom_fields.is_empty());
    assert!(history.custom_fields.is_empty());
    assert!(attachment.data_base64.is_empty());
    let AutofillPersistPlanDto::Update {
        expected_fields,
        desired_fields,
        ..
    } = &plan
    else {
        panic!("expected update plan");
    };
    assert!(expected_fields.password.is_empty());
    assert!(expected_fields.username.is_empty());
    assert!(expected_fields.url.is_empty());
    assert!(desired_fields.password.is_empty());
    assert!(desired_fields.username.is_empty());
    assert!(desired_fields.url.is_empty());
}

#[test]
fn protocol_secret_dtos_guarantee_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<EntryDetailDto>();
    assert_zeroize_on_drop::<EntryFieldsDto>();
    assert_zeroize_on_drop::<AutofillPersistPlanDto>();
    assert_zeroize_on_drop::<EntryHistoryDetailDto>();
    assert_zeroize_on_drop::<vaultkern_runtime_protocol::EntryCustomFieldDto>();
    assert_zeroize_on_drop::<EntryAttachmentContentDto>();
    assert_zeroize_on_drop::<RuntimeCommand>();
    assert_zeroize_on_drop::<RuntimeResponse>();
    assert_zeroize_on_drop::<vaultkern_runtime_protocol::SensitiveString>();
}

#[test]
fn passkey_metadata_update_rejects_private_key_material() {
    let request = serde_json::json!({
        "username": "alice@example.com",
        "credentialId": "credential-base64url",
        "generatedUserId": "generated-user",
        "privateKeyPem": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        "relyingParty": "example.com",
        "userHandle": "user-handle",
        "backupEligible": true,
        "backupState": false
    });

    assert!(serde_json::from_value::<EntryPasskeyUpdateDto>(request).is_err());
}

#[test]
fn protocol_roundtrips_entry_passkey_commands() {
    let passkey = EntryPasskeyUpdateDto {
        username: "alice@example.com".into(),
        credential_id: "credential-base64url".into(),
        generated_user_id: Some("generated-user".into()),
        relying_party: "example.com".into(),
        user_handle: Some("user-handle".into()),
        backup_eligible: true,
        backup_state: false,
    };
    assert_eq!(format!("{passkey:?}"), "EntryPasskeyUpdateDto([REDACTED])");
    let set = ProtocolEnvelope::new(RuntimeCommand::SetEntryPasskey {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        passkey,
    });
    let clear = ProtocolEnvelope::new(RuntimeCommand::ClearEntryPasskey {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });

    let set_json = serde_json::to_value(&set).unwrap();
    assert_eq!(
        set_json["command"]["type"],
        serde_json::json!("set_entry_passkey")
    );
    assert_eq!(
        set_json["command"]["passkey"]["credentialId"],
        serde_json::json!("credential-base64url")
    );

    let clear_json = serde_json::to_value(&clear).unwrap();
    assert_eq!(
        clear_json["command"]["type"],
        serde_json::json!("clear_entry_passkey")
    );

    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(set_json).unwrap(),
        set
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(clear_json).unwrap(),
        clear
    );
}

#[test]
fn protocol_roundtrips_fill_candidates_response_shape() {
    let response = RuntimeResponse::FillCandidates(FillCandidateListDto {
        entries: vec![EntrySummaryDto {
            id: "entry-1".into(),
            title: "Email".into(),
            username: "user@example.com".into(),
            url: "https://example.com".into(),
            group_id: "group-1".into(),
            has_totp: true,
        }],
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "fill_candidates");
    let entries = object.get("entries").unwrap().as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get("id").unwrap(), "entry-1");
    assert_eq!(entries[0].get("hasTotp").unwrap().as_bool(), Some(true));
    assert_eq!(entries[0].get("title").unwrap(), "Email");
    assert_eq!(entries[0].get("username").unwrap(), "user@example.com");
    assert_eq!(entries[0].get("url").unwrap(), "https://example.com");
    assert_eq!(entries[0].get("groupId").unwrap(), "group-1");

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_group_tree_response_shape() {
    let response = RuntimeResponse::GroupTree(GroupTreeDto {
        root: GroupNodeDto {
            id: "group-root".into(),
            title: "Archive".into(),
            entry_count: 0,
            child_count: 1,
            children: vec![GroupNodeDto {
                id: "group-child".into(),
                title: "General".into(),
                entry_count: 1,
                child_count: 0,
                children: vec![],
            }],
        },
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "group_tree");
    let root = object.get("root").unwrap().as_object().unwrap();
    assert_eq!(root.get("id").unwrap(), "group-root");
    assert_eq!(root.get("title").unwrap(), "Archive");
    assert_eq!(root.get("entryCount").unwrap(), 0);
    let children = root.get("children").unwrap().as_array().unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].get("id").unwrap(), "group-child");

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn session_state_dto_serializes_camel_case_keys() {
    let dto = SessionStateDto {
        unlocked: true,
        active_vault_id: Some("vault-1".into()),
        current_vault_ref_id: Some("vault-ref-1".into()),
        supports_biometric_unlock: true,
        source_status: None,
    };

    let json = serde_json::to_value(&dto).unwrap();
    let object = json.as_object().unwrap();

    assert!(object.contains_key("activeVaultId"));
    assert!(object.contains_key("currentVaultRefId"));
    assert!(object.contains_key("supportsBiometricUnlock"));
}

#[test]
fn protocol_roundtrips_unlock_command() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::UnlockWithPassword {
        vault_id: "vault-1".into(),
        password: "demo-password".into(),
    });

    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: ProtocolEnvelope = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, envelope);
}

#[test]
fn protocol_roundtrips_key_file_unlock_commands() {
    let current = ProtocolEnvelope::new(RuntimeCommand::UnlockCurrentVault {
        password: Some("demo-password".into()),
        key_file_path: Some("/tmp/demo.keyx".into()),
    });
    let selected = ProtocolEnvelope::new(RuntimeCommand::UnlockVault {
        vault_id: "vault-1".into(),
        password: None,
        key_file_path: Some("/tmp/demo.keyx".into()),
    });

    let current_json = serde_json::to_value(&current).unwrap();
    assert_eq!(current_json["command"]["type"], "unlock_current_vault");
    assert_eq!(current_json["command"]["password"], "demo-password");
    assert_eq!(current_json["command"]["key_file_path"], "/tmp/demo.keyx");

    let selected_json = serde_json::to_value(&selected).unwrap();
    assert_eq!(selected_json["command"]["type"], "unlock_vault");
    assert!(selected_json["command"]["password"].is_null());
    assert_eq!(selected_json["command"]["key_file_path"], "/tmp/demo.keyx");

    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(current_json).unwrap(),
        current
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(selected_json).unwrap(),
        selected
    );
}

#[test]
fn protocol_roundtrips_quick_unlock_commands() {
    let enable = ProtocolEnvelope::new(RuntimeCommand::EnableQuickUnlockForCurrentVault {
        password: Some("demo-password".into()),
        key_file_path: Some("/tmp/demo.keyx".into()),
    });
    let unlock = ProtocolEnvelope::new(RuntimeCommand::UnlockCurrentVaultWithQuickUnlock);
    let disable = ProtocolEnvelope::new(RuntimeCommand::DisableQuickUnlockForCurrentVault);

    let enable_json = serde_json::to_value(&enable).unwrap();
    assert_eq!(
        enable_json["command"]["type"],
        "enable_quick_unlock_for_current_vault"
    );
    assert_eq!(enable_json["command"]["password"], "demo-password");
    assert_eq!(enable_json["command"]["key_file_path"], "/tmp/demo.keyx");

    let unlock_json = serde_json::to_value(&unlock).unwrap();
    assert_eq!(
        unlock_json["command"]["type"],
        "unlock_current_vault_with_quick_unlock"
    );

    let disable_json = serde_json::to_value(&disable).unwrap();
    assert_eq!(
        disable_json["command"]["type"],
        "disable_quick_unlock_for_current_vault"
    );

    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(enable_json).unwrap(),
        enable
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(unlock_json).unwrap(),
        unlock
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(disable_json).unwrap(),
        disable
    );
}

#[test]
fn protocol_roundtrips_lock_session_command() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::LockSession);

    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: ProtocolEnvelope = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, envelope);
}

#[test]
fn protocol_roundtrips_list_groups_command() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::ListGroups {
        vault_id: "vault-1".into(),
    });

    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: ProtocolEnvelope = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded, envelope);
}

#[test]
fn protocol_roundtrips_entry_mutation_commands() {
    fn fields(password: &str) -> EntryFieldsDto {
        EntryFieldsDto {
            title: "Example".into(),
            username: "alice".into(),
            password: password.into(),
            url: "https://example.com".into(),
            notes: "demo".into(),
            totp_uri: None,
            custom_fields: vec![],
        }
    }
    let create = ProtocolEnvelope::new(RuntimeCommand::CreateEntry {
        vault_id: "vault-1".into(),
        parent_group_id: "group-root".into(),
        entry_id: Some("11111111-1111-4111-8111-111111111111".into()),
        title: "Example".into(),
        username: "alice".into(),
        password: "secret".into(),
        url: "https://example.com".into(),
        notes: "demo".into(),
        totp_uri: Some(
            "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test".into(),
        ),
    });
    let update = ProtocolEnvelope::new(RuntimeCommand::UpdateEntryFields {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        title: "Example 2".into(),
        username: "alice".into(),
        password: "secret-2".into(),
        url: "https://example.com/app".into(),
        notes: "updated".into(),
        totp_uri: None,
        custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
            key: "RecoveryCode".into(),
            value: "edited-code".into(),
            protected: true,
        }],
    });
    let compare_and_update = ProtocolEnvelope::new(RuntimeCommand::CompareAndUpdateEntryFields {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        expected_fields: fields("secret"),
        desired_fields: fields("secret-2"),
    });
    let clear_totp = ProtocolEnvelope::new(RuntimeCommand::ClearEntryTotp {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });
    let delete = ProtocolEnvelope::new(RuntimeCommand::DeleteEntry {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });

    for envelope in [create, update, compare_and_update, clear_totp, delete] {
        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: ProtocolEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, envelope);
    }
}

#[test]
fn protocol_roundtrips_scoped_browser_entry_mutations_without_receipt_identity() {
    let create = ProtocolEnvelope::new(RuntimeCommand::CreateAutofillEntry {
        vault_id: "vault-1".into(),
        parent_group_id: "group-root".into(),
        title: "Example".into(),
        username: "alice".into(),
        password: "secret".into(),
        url: "https://example.com/login".into(),
        notes: String::new().into(),
        totp_uri: None,
    });
    let update = ProtocolEnvelope::new(RuntimeCommand::UpdateAutofillEntryFields {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        expected_fields: autofill_update_fields("old-secret"),
        desired_fields: autofill_update_fields("new-secret"),
    });

    for envelope in [create, update] {
        let json = serde_json::to_value(&envelope).unwrap();
        assert!(json.get("operationId").is_none());
        assert!(json["command"].get("transaction_id").is_none());
        assert!(json["command"].get("operation_id").is_none());
        assert_eq!(
            serde_json::from_value::<ProtocolEnvelope>(json).unwrap(),
            envelope
        );
    }
}

#[test]
fn protocol_accepts_runtime_web_client_atomic_entry_field_shape() {
    let envelope: ProtocolEnvelope = serde_json::from_value(serde_json::json!({
        "version": 2,
        "command": {
            "type": "compare_and_update_entry_fields",
            "vault_id": "vault-1",
            "entry_id": "entry-1",
            "expected_fields": {
                "title": "Example",
                "username": "alice",
                "password": "old-secret",
                "url": "https://example.com/login",
                "notes": "",
                "totpUri": null,
                "customFields": []
            },
            "desired_fields": {
                "title": "Example",
                "username": "alice",
                "password": "new-secret",
                "url": "https://example.com/login",
                "notes": "",
                "totpUri": null,
                "customFields": []
            }
        }
    }))
    .expect("deserialize runtime web client envelope");

    let RuntimeCommand::CompareAndUpdateEntryFields {
        expected_fields,
        desired_fields,
        ..
    } = envelope.command
    else {
        panic!("expected atomic update command");
    };
    assert_eq!(expected_fields.password, "old-secret");
    assert_eq!(desired_fields.password, "new-secret");
}

#[test]
fn protocol_decodes_deprecated_autofill_persist_plans_for_compatibility() {
    fn fields(password: &str) -> EntryFieldsDto {
        EntryFieldsDto {
            title: "Example".into(),
            username: "alice".into(),
            password: password.into(),
            url: "https://example.com/login".into(),
            notes: String::new().into(),
            totp_uri: None,
            custom_fields: vec![],
        }
    }

    let update = ProtocolEnvelope::new(RuntimeCommand::PersistAutofillMutation {
        transaction_id: "transaction-1".into(),
        operation_id: "operation-1".into(),
        vault_id: "vault-1".into(),
        plan: AutofillPersistPlanDto::Update {
            entry_id: "entry-1".into(),
            expected_fields: autofill_update_fields("old-secret"),
            desired_fields: autofill_update_fields("new-secret"),
        },
    });
    let create = ProtocolEnvelope::new(RuntimeCommand::PersistAutofillMutation {
        transaction_id: "transaction-2".into(),
        operation_id: "operation-2".into(),
        vault_id: "vault-1".into(),
        plan: AutofillPersistPlanDto::Create {
            parent_group_id: "group-root".into(),
            planned_entry_id: "12345678-1234-4abc-8def-1234567890ab".into(),
            expected_matching_entry_ids: vec!["entry-existing".into()],
            desired_fields: fields("new-secret"),
        },
    });

    for envelope in [update, create] {
        let json = serde_json::to_value(&envelope).expect("serialize atomic persist plan");
        assert_eq!(json["command"]["type"], "persist_autofill_mutation");
        assert!(json["command"].get("transaction_id").is_some());
        assert!(json["command"].get("operation_id").is_some());
        assert!(json["command"].get("vault_id").is_some());
        assert!(json["command"]["plan"].get("desired_fields").is_some());
        assert!(json["command"].get("transactionId").is_none());
        assert_eq!(
            serde_json::from_value::<ProtocolEnvelope>(json).expect("roundtrip atomic plan"),
            envelope
        );
    }
}

#[test]
fn protocol_decodes_deprecated_autofill_results_for_compatibility() {
    for disposition in [
        AutofillPersistDispositionDto::Committed,
        AutofillPersistDispositionDto::Replayed,
    ] {
        let response = RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
            transaction_id: "transaction-1".into(),
            operation_id: "operation-1".into(),
            vault_id: "vault-1".into(),
            outcome: AutofillPersistOutcomeDto::Durable {
                disposition,
                entry_id: "entry-1".into(),
                durability: AutofillPersistDurabilityDto::Source,
                cache_state: AutofillCacheStateDto::Current,
                committed_fingerprint: AutofillCommittedFingerprintDto {
                    content_sha256:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                    size_bytes: 4096,
                },
                merge_summary: Some(MergeSummaryDto {
                    merged_entries: 2,
                    history_snapshots_added: 1,
                    meta_conflicts_resolved: 0,
                    icon_conflicts_resolved: 0,
                }),
                receipt_version: 1,
            },
        });

        let json = serde_json::to_value(&response).expect("serialize atomic durable response");
        assert_eq!(json["type"], "autofill_persist_result");
        assert_eq!(json["transactionId"], "transaction-1");
        assert_eq!(json["operationId"], "operation-1");
        assert_eq!(json["vaultId"], "vault-1");
        assert_eq!(json["outcome"], "durable");
        assert!(json.get("entryId").is_some());
        assert!(json.get("cacheState").is_some());
        assert!(json.get("committedFingerprint").is_some());
        assert!(json.get("receiptVersion").is_some());
        assert!(json.get("transaction_id").is_none());
        assert_eq!(
            serde_json::from_value::<RuntimeResponse>(json).expect("roundtrip durable response"),
            response
        );
    }
}

#[test]
fn protocol_preserves_deprecated_autofill_conflict_codes_for_compatibility() {
    let codes = [
        AutofillPersistConflictCodeDto::ActiveVaultMismatch,
        AutofillPersistConflictCodeDto::UpdatePreconditionFailed,
        AutofillPersistConflictCodeDto::CreateMatchingSetChanged,
        AutofillPersistConflictCodeDto::PlannedEntryIdCollision,
        AutofillPersistConflictCodeDto::OperationBindingMismatch,
        AutofillPersistConflictCodeDto::ConcurrentVaultChanges,
        AutofillPersistConflictCodeDto::SourceChangedRetryExhausted,
        AutofillPersistConflictCodeDto::LegacyCreateOutcomeAmbiguous,
    ];

    for code in codes {
        let response = RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
            transaction_id: "transaction-1".into(),
            operation_id: "operation-1".into(),
            vault_id: "vault-1".into(),
            outcome: AutofillPersistOutcomeDto::Conflict {
                code,
                retryable: matches!(
                    code,
                    AutofillPersistConflictCodeDto::ActiveVaultMismatch
                        | AutofillPersistConflictCodeDto::SourceChangedRetryExhausted
                ),
            },
        });
        let json = serde_json::to_value(&response).expect("serialize conflict response");
        assert_eq!(json["outcome"], "conflict");
        assert_eq!(
            serde_json::from_value::<RuntimeResponse>(json).expect("roundtrip conflict response"),
            response
        );
    }
}

#[test]
fn protocol_rejects_unknown_or_malformed_deprecated_autofill_results() {
    let unknown_outcome = serde_json::json!({
        "type": "autofill_persist_result",
        "transactionId": "transaction-1",
        "operationId": "operation-1",
        "vaultId": "vault-1",
        "outcome": "eventually_durable"
    });
    let unknown_conflict = serde_json::json!({
        "type": "autofill_persist_result",
        "transactionId": "transaction-1",
        "operationId": "operation-1",
        "vaultId": "vault-1",
        "outcome": "conflict",
        "code": "overwrite_anyway",
        "retryable": false
    });
    let missing_fingerprint = serde_json::json!({
        "type": "autofill_persist_result",
        "transactionId": "transaction-1",
        "operationId": "operation-1",
        "vaultId": "vault-1",
        "outcome": "durable",
        "disposition": "committed",
        "entryId": "entry-1",
        "durability": "source",
        "cacheState": "current",
        "mergeSummary": null,
        "receiptVersion": 1
    });

    for malformed in [unknown_outcome, unknown_conflict, missing_fingerprint] {
        assert!(serde_json::from_value::<RuntimeResponse>(malformed).is_err());
    }
}

#[test]
fn protocol_roundtrips_entry_attachment_commands() {
    let commands = vec![
        ProtocolEnvelope::new(RuntimeCommand::GetEntryAttachmentContent {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            name: "backup.txt".into(),
        }),
        ProtocolEnvelope::new(RuntimeCommand::AddEntryAttachment {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            name: "backup.txt".into(),
            data_base64: "aGVsbG8=".into(),
            protect_in_memory: true,
        }),
        ProtocolEnvelope::new(RuntimeCommand::UpdateEntryAttachmentMetadata {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            old_name: "backup.txt".into(),
            new_name: "backup-renamed.txt".into(),
            protect_in_memory: false,
        }),
        ProtocolEnvelope::new(RuntimeCommand::ReplaceEntryAttachmentContent {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            name: "backup-renamed.txt".into(),
            data_base64: "dXBkYXRlZA==".into(),
        }),
        ProtocolEnvelope::new(RuntimeCommand::DeleteEntryAttachment {
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            name: "backup-renamed.txt".into(),
        }),
    ];

    for command in commands {
        assert_eq!(
            serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&command).unwrap())
                .unwrap(),
            command
        );
    }
}

#[test]
fn protocol_roundtrips_passkey_assertion_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::CreatePasskeyAssertion {
        ceremony_token: "ceremony-token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        vault_id: "vault-1".into(),
        relying_party: "example.com".into(),
        origin: "https://example.com".into(),
        credential_id: Some("Y3JlZGVudGlhbC0x".into()),
        discoverable: true,
        user_presence_verified: true,
        related_origin_verified: false,
        client_data_json_base64url: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0".into(),
    });

    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("create_passkey_assertion")
    );
    assert_eq!(
        command_json["command"]["relying_party"],
        serde_json::json!("example.com")
    );
    assert_eq!(
        command_json["command"]["client_data_json_base64url"],
        serde_json::json!("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0")
    );
    assert_eq!(
        command_json["command"]["ceremony_token"],
        serde_json::json!("ceremony-token-1")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s4_completion_and_mutation")
    );
    assert_eq!(
        command_json["command"]["user_presence_verified"],
        serde_json::json!(true)
    );
    assert_eq!(
        command_json["command"]["discoverable"],
        serde_json::json!(true)
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let legacy_assertion_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "create_passkey_assertion",
            "ceremony_token": "ceremony-token-1",
            "expected_phase": "s4_completion_and_mutation",
            "vault_id": "vault-1",
            "relying_party": "example.com",
            "origin": "https://example.com",
            "credential_id": "Y3JlZGVudGlhbC0x",
            "user_presence_verified": true,
            "client_data_json_base64url": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"
        }
    });
    let legacy_assertion = serde_json::from_value::<ProtocolEnvelope>(legacy_assertion_json)
        .expect("legacy assertion command");
    let RuntimeCommand::CreatePasskeyAssertion { discoverable, .. } = legacy_assertion.command
    else {
        panic!("expected passkey assertion command");
    };
    assert!(!discoverable);

    let response = RuntimeResponse::PasskeyAssertion(PasskeyAssertionDto {
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        authenticator_data_base64url: "authenticator-data".into(),
        client_data_json_base64url: "client-data-json".into(),
        signature_base64url: "signature".into(),
        user_handle_base64url: Some("dXNlci0x".into()),
        backup_eligible: true,
        backup_state: false,
    });

    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_assertion")
    );
    assert_eq!(
        response_json["credentialId"],
        serde_json::json!("Y3JlZGVudGlhbC0x")
    );
    assert_eq!(
        response_json["userHandleBase64url"],
        serde_json::json!("dXNlci0x")
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );

    let missing_token_assertion_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "create_passkey_assertion",
            "vault_id": "vault-1",
            "relying_party": "example.com",
            "origin": "https://example.com",
            "credential_id": "Y3JlZGVudGlhbC0x",
            "user_presence_verified": true,
            "client_data_json_base64url": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"
        }
    });
    assert!(serde_json::from_value::<ProtocolEnvelope>(missing_token_assertion_json).is_err());
}

#[test]
fn protocol_roundtrips_passkey_registration_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::CreatePasskeyRegistration {
        ceremony_token: "ceremony-token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        vault_id: "vault-1".into(),
        relying_party: "example.com".into(),
        origin: "https://example.com".into(),
        user_name: "alice@example.com".into(),
        user_display_name: Some("Alice".into()),
        user_handle_base64url: "dXNlci0x".into(),
        public_key_algorithm: -7,
        related_origin_verified: false,
        client_data_json_base64url: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0".into(),
    });

    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("create_passkey_registration")
    );
    assert_eq!(
        command_json["command"]["user_name"],
        serde_json::json!("alice@example.com")
    );
    assert_eq!(
        command_json["command"]["ceremony_token"],
        serde_json::json!("ceremony-token-1")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s4_completion_and_mutation")
    );
    assert_eq!(
        command_json["command"]["public_key_algorithm"],
        serde_json::json!(-7)
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );
    let save = ProtocolEnvelope::new(RuntimeCommand::SavePasskeyRegistration {
        ceremony_token: "ceremony-token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        vault_id: "vault-1".into(),
    });
    let save_json = serde_json::to_value(&save).unwrap();
    assert_eq!(
        save_json["command"]["type"],
        serde_json::json!("save_passkey_registration")
    );
    assert_eq!(
        save_json["command"]["expected_phase"],
        serde_json::json!("s4_completion_and_mutation")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(save_json).unwrap(),
        save
    );

    let abort = ProtocolEnvelope::new(RuntimeCommand::AbortPasskeyRegistration {
        ceremony_token: "ceremony-token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        closed_phase: PasskeyCeremonyPhaseDto::ClosedFailed,
    });
    let abort_json = serde_json::to_value(&abort).unwrap();
    assert_eq!(
        abort_json["command"]["type"],
        serde_json::json!("abort_passkey_registration")
    );
    assert_eq!(
        abort_json["command"]["ceremony_token"],
        serde_json::json!("ceremony-token-1")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(abort_json).unwrap(),
        abort
    );
    let commit = ProtocolEnvelope::new(RuntimeCommand::CommitPasskeyRegistration {
        ceremony_token: "ceremony-token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
    });
    let commit_json = serde_json::to_value(&commit).unwrap();
    assert_eq!(
        commit_json["command"]["type"],
        serde_json::json!("commit_passkey_registration")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(commit_json).unwrap(),
        commit
    );
    let missing_token_commit_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "commit_passkey_registration",
            "vault_id": "vault-1",
            "entry_id": "entry-1",
            "credential_id": "Y3JlZGVudGlhbC0x"
        }
    });
    assert!(serde_json::from_value::<ProtocolEnvelope>(missing_token_commit_json).is_err());

    let missing_token_registration_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "create_passkey_registration",
            "vault_id": "vault-1",
            "relying_party": "example.com",
            "origin": "https://example.com",
            "user_name": "alice@example.com",
            "user_display_name": "Alice",
            "user_handle_base64url": "dXNlci0x",
            "client_data_json_base64url": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
        }
    });
    assert!(serde_json::from_value::<ProtocolEnvelope>(missing_token_registration_json).is_err());

    let response = RuntimeResponse::PasskeyRegistration(PasskeyRegistrationDto {
        entry_id: "entry-1".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        created: true,
        authenticator_data_base64url: "authenticator-data".into(),
        attestation_object_base64url: "attestation-object".into(),
        client_data_json_base64url: "client-data-json".into(),
        public_key_base64url: "public-key".into(),
        public_key_algorithm: -7,
        user_handle_base64url: "dXNlci0x".into(),
    });

    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_registration")
    );
    assert_eq!(
        response_json["credentialId"],
        serde_json::json!("Y3JlZGVudGlhbC0x")
    );
    assert_eq!(response_json["created"], serde_json::json!(true));
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_rejects_legacy_passkey_rollback_command() {
    let legacy_rollback_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "rollback_passkey_registration",
            "ceremony_token": "ceremony-token-1",
            "expected_phase": "s4_completion_and_mutation",
            "closed_phase": "closed_failed",
            "vault_id": "vault-1",
            "entry_id": "entry-1",
            "credential_id": "Y3JlZGVudGlhbC0x",
            "created": false
        }
    });

    assert!(serde_json::from_value::<ProtocolEnvelope>(legacy_rollback_json).is_err());
}

#[test]
fn protocol_roundtrips_passkey_credential_status_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::PasskeyCredentialStatus {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
        vault_id: "vault-1".into(),
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        relying_party: "example.com".into(),
    });

    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("passkey_credential_status")
    );
    assert_eq!(
        command_json["command"]["credential_id"],
        serde_json::json!("Y3JlZGVudGlhbC0x")
    );
    assert_eq!(
        command_json["command"]["ceremony_token"],
        serde_json::json!("token-1")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s3_credential_resolution")
    );
    assert_eq!(
        command_json["command"]["relying_party"],
        serde_json::json!("example.com")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let response = RuntimeResponse::PasskeyCredentialStatus(PasskeyCredentialStatusDto {
        credential_id: "Y3JlZGVudGlhbC0x".into(),
        exists: true,
    });

    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_credential_status")
    );
    assert_eq!(response_json["exists"], serde_json::json!(true));
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_roundtrips_passkey_credential_status_batch_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::PasskeyCredentialStatusBatch {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
        vault_id: "vault-1".into(),
        credential_ids: vec!["Y3JlZGVudGlhbC0x".into(), "Y3JlZGVudGlhbC0y".into()],
        relying_party: "example.com".into(),
    });

    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("passkey_credential_status_batch")
    );
    assert_eq!(
        command_json["command"]["credential_ids"],
        serde_json::json!(["Y3JlZGVudGlhbC0x", "Y3JlZGVudGlhbC0y"])
    );
    assert_eq!(
        command_json["command"]["ceremony_token"],
        serde_json::json!("token-1")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s3_credential_resolution")
    );
    assert_eq!(
        command_json["command"]["relying_party"],
        serde_json::json!("example.com")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let response = RuntimeResponse::PasskeyCredentialStatusBatch(PasskeyCredentialStatusBatchDto {
        statuses: vec![
            PasskeyCredentialStatusDto {
                credential_id: "Y3JlZGVudGlhbC0x".into(),
                exists: true,
            },
            PasskeyCredentialStatusDto {
                credential_id: "Y3JlZGVudGlhbC0y".into(),
                exists: false,
            },
        ],
    });

    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_credential_status_batch")
    );
    assert_eq!(
        response_json["statuses"][0]["exists"],
        serde_json::json!(true)
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_rejects_passkey_credential_status_without_relying_party() {
    let command_json = serde_json::json!({
        "version": 2,
        "command": {
            "type": "passkey_credential_status",
            "ceremony_token": "token-1",
            "expected_phase": "s3_credential_resolution",
            "vault_id": "vault-1",
            "credential_id": "Y3JlZGVudGlhbC0x"
        }
    });

    let error = serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap_err();
    assert!(error.to_string().contains("relying_party"));
}

#[test]
fn protocol_roundtrips_passkey_credential_list_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::ListPasskeyCredentials {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::CredentialResolution,
        vault_id: "vault-1".into(),
        relying_party: "example.com".into(),
    });

    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("list_passkey_credentials")
    );
    assert_eq!(
        command_json["command"]["relying_party"],
        serde_json::json!("example.com")
    );
    assert_eq!(
        command_json["command"]["ceremony_token"],
        serde_json::json!("token-1")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s3_credential_resolution")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let response = RuntimeResponse::PasskeyCredentialList(PasskeyCredentialListDto {
        credentials: vec![
            PasskeyCredentialCandidateDto {
                credential_id: "Y3JlZGVudGlhbC0x".into(),
                username: "alice@example.com".into(),
                user_handle: Some("dXNlci0x".into()),
            },
            PasskeyCredentialCandidateDto {
                credential_id: "Y3JlZGVudGlhbC0y".into(),
                username: "bob@example.com".into(),
                user_handle: None,
            },
        ],
    });

    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_credential_list")
    );
    assert_eq!(
        response_json["credentials"][0]["username"],
        "alice@example.com"
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_roundtrips_passkey_ceremony_ledger_commands_and_responses() {
    let register = ProtocolEnvelope::new(RuntimeCommand::RegisterPasskeyCeremony {
        ceremony_token: "token-1".into(),
        connection_id: "connection-1".into(),
        origin: "https://login.example.com".into(),
        top_origin: Some("https://login.example.com".into()),
        ancestor_origins: vec![],
        relying_party: "example.com".into(),
        ceremony: PasskeyCeremonyKindDto::Get,
        discoverable: true,
        user_verification: PasskeyUserVerificationRequirementDto::Required,
        challenge_base64url: "Y2hhbGxlbmdl".into(),
        request_id: -42,
        tab_id: 7,
        frame_id: 0,
        frame_kind: PasskeyFrameKindDto::Top,
        registered_at_epoch_ms: 1_000,
        expires_at_epoch_ms: 301_000,
    });
    let register_json = serde_json::to_value(&register).unwrap();
    assert_eq!(
        register_json["command"]["type"],
        serde_json::json!("register_passkey_ceremony")
    );
    assert_eq!(
        register_json["command"]["ceremony_token"],
        serde_json::json!("token-1")
    );
    assert_eq!(
        register_json["command"]["discoverable"],
        serde_json::json!(true)
    );
    assert_eq!(
        register_json["command"]["frame_kind"],
        serde_json::json!("top")
    );
    assert_eq!(
        register_json["command"]["request_id"],
        serde_json::json!(-42)
    );
    assert_eq!(
        register_json["command"]["user_verification"],
        serde_json::json!("required")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(register_json).unwrap(),
        register
    );

    let advance = ProtocolEnvelope::new(RuntimeCommand::AdvancePasskeyCeremonyPhase {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::PreAuthorization,
        next_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
        related_origin_verified: false,
    });
    let advance_json = serde_json::to_value(&advance).unwrap();
    assert_eq!(
        advance_json["command"]["type"],
        serde_json::json!("advance_passkey_ceremony_phase")
    );
    assert_eq!(
        advance_json["command"]["expected_phase"],
        serde_json::json!("s0_pre_authorization")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(advance_json).unwrap(),
        advance
    );

    let bind_vault = ProtocolEnvelope::new(RuntimeCommand::BindPasskeyCeremonyVault {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
        vault_id: "vault-1".into(),
    });
    let bind_vault_json = serde_json::to_value(&bind_vault).unwrap();
    assert_eq!(
        bind_vault_json["command"]["type"],
        serde_json::json!("bind_passkey_ceremony_vault")
    );
    assert_eq!(
        bind_vault_json["command"]["vault_id"],
        serde_json::json!("vault-1")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(bind_vault_json).unwrap(),
        bind_vault
    );

    let query = ProtocolEnvelope::new(RuntimeCommand::QueryPasskeyCeremonyLedger {
        ceremony_token: "token-1".into(),
    });
    let query_json = serde_json::to_value(&query).unwrap();
    assert_eq!(
        query_json["command"]["type"],
        serde_json::json!("query_passkey_ceremony_ledger")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(query_json).unwrap(),
        query
    );

    let reconcile = ProtocolEnvelope::new(RuntimeCommand::ReconcilePasskeyCeremonyLedger {
        active_connection_id: "connection-1".into(),
    });
    let reconcile_json = serde_json::to_value(&reconcile).unwrap();
    assert_eq!(
        reconcile_json["command"]["type"],
        serde_json::json!("reconcile_passkey_ceremony_ledger")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(reconcile_json).unwrap(),
        reconcile
    );

    let unknown_delivery =
        ProtocolEnvelope::new(RuntimeCommand::MarkPasskeyCeremonyUnknownDelivery {
            ceremony_token: "token-1".into(),
            expected_phase: PasskeyCeremonyPhaseDto::CompletionAndMutation,
        });
    let unknown_delivery_json = serde_json::to_value(&unknown_delivery).unwrap();
    assert_eq!(
        unknown_delivery_json["command"]["type"],
        serde_json::json!("mark_passkey_ceremony_unknown_delivery")
    );
    assert_eq!(
        unknown_delivery_json["command"]["expected_phase"],
        serde_json::json!("s4_completion_and_mutation")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(unknown_delivery_json).unwrap(),
        unknown_delivery
    );

    let registered = RuntimeResponse::PasskeyCeremonyRegistered(PasskeyCeremonyRegisteredDto {
        registered: true,
    });
    assert_eq!(
        serde_json::to_value(&registered).unwrap()["type"],
        serde_json::json!("passkey_ceremony_registered")
    );

    let advanced =
        RuntimeResponse::PasskeyCeremonyAdvanced(PasskeyCeremonyAdvancedDto { advanced: true });
    assert_eq!(
        serde_json::to_value(&advanced).unwrap()["type"],
        serde_json::json!("passkey_ceremony_advanced")
    );

    let unknown = RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
        known: false,
        phase: None,
        durable_state: None,
        delivery_state: None,
    });
    let unknown_json = serde_json::to_value(&unknown).unwrap();
    assert_eq!(
        unknown_json["type"],
        serde_json::json!("passkey_ceremony_ledger")
    );
    assert_eq!(unknown_json["known"], serde_json::json!(false));
    assert!(unknown_json.get("phase").is_none());

    let known = RuntimeResponse::PasskeyCeremonyLedger(PasskeyCeremonyLedgerDto {
        known: true,
        phase: Some(PasskeyCeremonyPhaseDto::CompletionAndMutation),
        durable_state: Some(PasskeyCeremonyDurableStateDto::Committed),
        delivery_state: Some(PasskeyCeremonyDeliveryStateDto::UnknownDelivery),
    });
    let known_json = serde_json::to_value(&known).unwrap();
    assert_eq!(known_json["known"], serde_json::json!(true));
    assert_eq!(
        known_json["deliveryState"],
        serde_json::json!("unknown_delivery")
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(known_json).unwrap(),
        known
    );

    let reconciliation =
        RuntimeResponse::PasskeyCeremonyReconciliation(PasskeyCeremonyReconciliationDto {
            reconciled: vec![PasskeyCeremonyReconciledDto {
                ceremony_token: "token-1".into(),
                delivery_state: PasskeyCeremonyDeliveryStateDto::UnknownDelivery,
            }],
        });
    let reconciliation_json = serde_json::to_value(&reconciliation).unwrap();
    assert_eq!(
        reconciliation_json["type"],
        serde_json::json!("passkey_ceremony_reconciliation")
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(reconciliation_json).unwrap(),
        reconciliation
    );
}

#[test]
fn protocol_roundtrips_passkey_user_verification_capability() {
    let command = ProtocolEnvelope::new(RuntimeCommand::GetPasskeyUserVerificationCapability);
    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("get_passkey_user_verification_capability")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let response =
        RuntimeResponse::PasskeyUserVerificationCapability(PasskeyUserVerificationCapabilityDto {
            available: true,
            methods: vec![
                PasskeyUserVerificationMethodDto::MasterPassword,
                PasskeyUserVerificationMethodDto::QuickUnlock,
            ],
        });
    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_user_verification_capability")
    );
    assert_eq!(response_json["available"], serde_json::json!(true));
    assert_eq!(
        response_json["methods"],
        serde_json::json!(["master_password", "quick_unlock"])
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_roundtrips_passkey_user_verification_command_and_response() {
    let command = ProtocolEnvelope::new(RuntimeCommand::VerifyPasskeyUser {
        ceremony_token: "token-1".into(),
        expected_phase: PasskeyCeremonyPhaseDto::UserAuthorization,
        vault_id: "vault-1".into(),
        method: PasskeyUserVerificationMethodDto::MasterPassword,
        password: Some("secret".into()),
    });
    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(
        command_json["command"]["type"],
        serde_json::json!("verify_passkey_user")
    );
    assert_eq!(
        command_json["command"]["expected_phase"],
        serde_json::json!("s1_user_authorization")
    );
    assert_eq!(
        command_json["command"]["method"],
        serde_json::json!("master_password")
    );
    assert_eq!(
        serde_json::from_value::<ProtocolEnvelope>(command_json).unwrap(),
        command
    );

    let response = RuntimeResponse::PasskeyUserVerified(PasskeyUserVerifiedDto {
        verified: true,
        method: PasskeyUserVerificationMethodDto::MasterPassword,
        verified_at_epoch_ms: 123,
    });
    let response_json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        response_json["type"],
        serde_json::json!("passkey_user_verified")
    );
    assert_eq!(response_json["verified"], serde_json::json!(true));
    assert_eq!(
        response_json["method"],
        serde_json::json!("master_password")
    );
    assert_eq!(response_json["verifiedAtEpochMs"], serde_json::json!(123));
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(response_json).unwrap(),
        response
    );
}

#[test]
fn protocol_roundtrips_entry_attachment_content_response_shape() {
    let response = RuntimeResponse::EntryAttachmentContent(EntryAttachmentContentDto {
        name: "backup.txt".into(),
        data_base64: "aGVsbG8=".into(),
        protect_in_memory: true,
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "entry_attachment_content");
    assert_eq!(object.get("name").unwrap(), "backup.txt");
    assert_eq!(object.get("dataBase64").unwrap(), "aGVsbG8=");
    assert_eq!(object.get("protectInMemory").unwrap(), true);

    let decoded: RuntimeResponse = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_entry_history_commands_and_responses() {
    let list = ProtocolEnvelope::new(RuntimeCommand::ListEntryHistory {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });
    let detail_command = ProtocolEnvelope::new(RuntimeCommand::GetEntryHistoryDetail {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
        history_index: 0,
    });

    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&list).unwrap()).unwrap(),
        list
    );
    assert_eq!(
        serde_json::from_str::<ProtocolEnvelope>(&serde_json::to_string(&detail_command).unwrap())
            .unwrap(),
        detail_command
    );

    let list_response = RuntimeResponse::EntryHistoryList(EntryHistoryListDto {
        items: vec![EntryHistoryItemDto {
            index: 0,
            title: "Old Example".into(),
            username: "alice".into(),
            modified_at: 42,
            attachment_count: 1,
            custom_field_count: 1,
        }],
    });
    let list_json = serde_json::to_value(&list_response).unwrap();
    let list_object = list_json.as_object().unwrap();
    let items = list_object.get("items").unwrap().as_array().unwrap();

    assert_eq!(list_object.get("type").unwrap(), "entry_history_list");
    assert_eq!(
        items[0]
            .get("historyIndex")
            .or_else(|| items[0].get("index"))
            .unwrap(),
        0
    );
    assert_eq!(items[0].get("modifiedAt").unwrap(), 42);
    assert_eq!(items[0].get("attachmentCount").unwrap(), 1);

    let detail_response = RuntimeResponse::EntryHistoryDetail(EntryHistoryDetailDto {
        entry_id: "entry-1".into(),
        history_index: 0,
        title: "Old Example".into(),
        username: "alice".into(),
        url: "https://example.com".into(),
        notes: "old note".into(),
        modified_at: 43,
        custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
            key: "RecoveryCode".into(),
            value: "".into(),
            protected: true,
        }],
        attachments: vec![vaultkern_runtime_protocol::EntryAttachmentDto {
            name: "backup.txt".into(),
            size: 5,
            protect_in_memory: true,
        }],
    });
    let detail_json = serde_json::to_value(&detail_response).unwrap();
    let detail_object = detail_json.as_object().unwrap();

    assert_eq!(detail_object.get("type").unwrap(), "entry_history_detail");
    assert_eq!(detail_object.get("entryId").unwrap(), "entry-1");
    assert_eq!(detail_object.get("historyIndex").unwrap(), 0);
    assert!(
        !detail_object.contains_key("password"),
        "history display responses must never serialize historical passwords"
    );
    let protected_field = &detail_object["customFields"].as_array().unwrap()[0];
    assert_eq!(protected_field["value"], "");
    assert_eq!(protected_field["protected"], true);
    assert_eq!(detail_object.get("modifiedAt").unwrap(), 43);

    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(list_json).unwrap(),
        list_response
    );
    assert_eq!(
        serde_json::from_value::<RuntimeResponse>(detail_json).unwrap(),
        detail_response
    );
}
