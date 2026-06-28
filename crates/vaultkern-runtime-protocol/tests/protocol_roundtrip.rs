use vaultkern_runtime_protocol::{
    DatabaseCredentialsUpdateDto, DatabaseEncryptionSettingsDto, DatabaseHistorySettingsDto,
    DatabaseKdfSettingsDto, DatabaseMetadataSettingsDto, DatabasePublicMetadataSettingsDto,
    DatabaseRecycleBinSettingsDto, DatabaseSettingsDto, DatabaseSettingsUpdateDto,
    EntryAttachmentContentDto, EntryDetailDto, EntryHistoryDetailDto, EntryHistoryItemDto,
    EntryHistoryListDto, EntrySummaryDto, FillCandidateListDto, GroupNodeDto, GroupTreeDto,
    MergeSummaryDto, OneDriveAuthSessionDto, OneDriveAuthStatusDto, OneDriveItemDto,
    OneDriveItemListDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse, SaveVaultResultDto,
    SaveVaultStatusDto, SessionStateDto, VaultHandleDto, VaultReferenceDto, VaultReferenceListDto,
    VaultSourceStatusDto,
};

#[test]
fn protocol_envelope_serializes_open_local_vault_command() {
    let envelope = ProtocolEnvelope::new(RuntimeCommand::OpenLocalVault {
        path: "/tmp/demo.kdbx".into(),
    });

    let json = serde_json::to_string(&envelope).unwrap();

    assert!(json.contains("\"version\":1"));
    assert!(json.contains("\"open_local_vault\""));
    assert!(json.contains("/tmp/demo.kdbx"));
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
            autosave_delay_seconds: Some(30),
        },
    });
    let response = RuntimeResponse::DatabaseSettings(DatabaseSettingsDto {
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
    });

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
        }),
    });

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["type"], "save_vault_result");
    assert_eq!(value["status"], "merged");
    assert_eq!(value["mergeSummary"]["mergedEntries"], 2);
    assert_eq!(value["mergeSummary"]["historySnapshotsAdded"], 1);

    let decoded: RuntimeResponse = serde_json::from_value(value).expect("deserialize response");
    assert_eq!(decoded, response);
}

#[test]
fn protocol_roundtrips_local_cache_save_result_response() {
    let response = RuntimeResponse::SaveVaultResult(SaveVaultResultDto {
        status: SaveVaultStatusDto::SavedToCache,
        merge_summary: None,
    });

    let value = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(value["type"], "save_vault_result");
    assert_eq!(value["status"], "saved_to_cache");
    assert!(value["mergeSummary"].is_null());

    let decoded: RuntimeResponse = serde_json::from_value(value).expect("deserialize response");
    assert_eq!(decoded, response);
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
    let complete = ProtocolEnvelope::new(RuntimeCommand::CompleteOneDriveLogin {
        code: "auth-code".into(),
        redirect_uri: "http://127.0.0.1:53121/callback".into(),
        code_verifier: "verifier".into(),
    });
    let complete_pending = ProtocolEnvelope::new(RuntimeCommand::CompletePendingOneDriveLogin);
    let list = ProtocolEnvelope::new(RuntimeCommand::ListOneDriveChildren {
        parent_item_id: Some("folder-1".into()),
    });
    let add = ProtocolEnvelope::new(RuntimeCommand::AddOneDriveVaultReference {
        drive_id: "drive-1".into(),
        item_id: "item-1".into(),
    });

    for envelope in [begin, complete, complete_pending, list, add] {
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
        code_verifier: "verifier".into(),
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
fn protocol_roundtrips_fill_candidates_response_shape() {
    let response = RuntimeResponse::FillCandidates(FillCandidateListDto {
        entries: vec![EntrySummaryDto {
            id: "entry-1".into(),
            title: "Email".into(),
            username: "user@example.com".into(),
            url: "https://example.com".into(),
            group_id: "group-1".into(),
        }],
    });

    let json = serde_json::to_value(&response).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.get("type").unwrap(), "fill_candidates");
    let entries = object.get("entries").unwrap().as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get("id").unwrap(), "entry-1");
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
    let create = ProtocolEnvelope::new(RuntimeCommand::CreateEntry {
        vault_id: "vault-1".into(),
        parent_group_id: "group-root".into(),
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
    let clear_totp = ProtocolEnvelope::new(RuntimeCommand::ClearEntryTotp {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });
    let delete = ProtocolEnvelope::new(RuntimeCommand::DeleteEntry {
        vault_id: "vault-1".into(),
        entry_id: "entry-1".into(),
    });

    for envelope in [create, update, clear_totp, delete] {
        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: ProtocolEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, envelope);
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
        password: "old-secret".into(),
        url: "https://example.com".into(),
        notes: "old note".into(),
        modified_at: 43,
        custom_fields: vec![vaultkern_runtime_protocol::EntryCustomFieldDto {
            key: "RecoveryCode".into(),
            value: "old-code".into(),
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
    assert_eq!(detail_object.get("password").unwrap(), "old-secret");
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
