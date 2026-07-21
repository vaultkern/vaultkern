use serde_json::{Value, json};
use vaultkern_core::{CompositeKey, EntryCreate, KeepassCore, SaveProfile, Vault};
use vaultkern_runtime::{
    PlatformPasskeyAssertionInput, PlatformPasskeyRegistrationInput,
    QuickUnlockReconciliationCredentials,
};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeResponse};
use vaultkern_windows::{RuntimeBridge, SettingsReconciliationRequest};

fn quick_unlock_bridge_with_current_vault(name: &str) -> (tempfile::TempDir, RuntimeBridge) {
    let scratch = tempfile::tempdir().unwrap();
    let database_path = scratch.path().join(format!("{name}.kdbx"));
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    std::fs::write(
        &database_path,
        KeepassCore::new()
            .save_kdbx(&Vault::empty(name), &key, SaveProfile::recommended())
            .unwrap(),
    )
    .unwrap();

    let bridge = RuntimeBridge::new_for_tests_with_quick_unlock();
    let reference = bridge.request(json!({
        "version": 1,
        "command": {
            "type": "add_local_vault_reference",
            "path": database_path.to_string_lossy()
        }
    }));
    assert_eq!(reference["type"], "vault_reference");
    (scratch, bridge)
}

trait RuntimeBridgeTestRequest {
    fn request(&self, message: Value) -> Value;
}

impl RuntimeBridgeTestRequest for RuntimeBridge {
    fn request(&self, message: Value) -> Value {
        let response = match serde_json::from_value::<ProtocolEnvelope>(message) {
            Ok(envelope) => self.request_envelope(envelope),
            Err(error) => RuntimeResponse::Error(ErrorDto {
                code: "invalid_request".into(),
                message: format!("invalid runtime request: {error}"),
            }),
        };
        serde_json::to_value(response).expect("serialize test runtime response")
    }
}

#[test]
fn windows_app_binary_declares_gui_subsystem() {
    let main_rs = include_str!("../src/main.rs");

    assert!(main_rs.contains(r#"#![cfg_attr(windows, windows_subsystem = "windows")]"#));
}

#[test]
fn native_registration_cancellation_boundary_precedes_the_durable_callback() {
    let native = include_str!("../native/passkey_plugin.cpp");
    let make_start = native
        .find("HRESULT STDMETHODCALLTYPE MakeCredential(")
        .expect("MakeCredential implementation");
    let get_start = native[make_start..]
        .find("HRESULT STDMETHODCALLTYPE GetAssertion(")
        .map(|offset| make_start + offset)
        .expect("GetAssertion implementation");
    let make = &native[make_start..get_start];
    let prepare_callback = make
        .find("callbacks_.make_credential")
        .expect("registration preparation callback");
    let durable_callback = make
        .find("callbacks_.commit_registration")
        .expect("durable registration callback");

    assert!(make[..prepare_callback].contains("operation.CheckCancelled()"));
    assert!(
        make[prepare_callback..durable_callback].contains("operation.CheckCancelled()"),
        "cancellation after preparation but before the durable commit must roll back"
    );
    assert!(
        !make[durable_callback..].contains("operation.CheckCancelled()"),
        "once the durable registration callback succeeds, late cancellation must not turn the committed ceremony into a failure"
    );
}

#[test]
fn native_operations_prepare_the_vault_only_after_authenticating_the_windows_request() {
    let native = include_str!("../native/passkey_plugin.cpp");
    let make_start = native
        .find("HRESULT STDMETHODCALLTYPE MakeCredential(")
        .expect("MakeCredential implementation");
    let get_start = native[make_start..]
        .find("HRESULT STDMETHODCALLTYPE GetAssertion(")
        .map(|offset| make_start + offset)
        .expect("GetAssertion implementation");
    let cancel_start = native[get_start..]
        .find("HRESULT STDMETHODCALLTYPE CancelOperation(")
        .map(|offset| get_start + offset)
        .expect("GetAssertion implementation end");

    for (name, implementation) in [
        ("MakeCredential", &native[make_start..get_start]),
        ("GetAssertion", &native[get_start..cancel_start]),
    ] {
        let verify = implementation
            .find("VerifyPlatformRequest(request)")
            .unwrap_or_else(|| panic!("{name} must authenticate the signed Windows request"));
        let prepare = implementation
            .find("callbacks_.prepare_operation")
            .unwrap_or_else(|| panic!("{name} must prepare or unlock the selected vault"));
        assert!(
            verify < prepare,
            "{name} must not accept a request-controlled parent HWND before authenticating the Windows request"
        );
        assert!(
            implementation[..prepare].contains("PluginOperation operation"),
            "{name} must establish the cancellable transaction before prompting for unlock"
        );
        assert!(
            !implementation[verify..prepare].contains("return NTE_NOT_FOUND"),
            "{name} must attempt Hello quick unlock instead of rejecting a cold provider process"
        );
    }
}

#[test]
fn native_com_objects_retain_the_rust_callback_context() {
    let native = include_str!("../native/passkey_plugin.cpp");
    let authenticator_start = native
        .find("class PluginAuthenticator final")
        .expect("PluginAuthenticator implementation");
    let factory_start = native[authenticator_start..]
        .find("class PluginFactory final")
        .map(|offset| authenticator_start + offset)
        .expect("PluginFactory implementation");
    let factory_end = native[factory_start..]
        .find("std::vector<BYTE> AuthenticatorInfo()")
        .map(|offset| factory_start + offset)
        .expect("PluginFactory implementation end");
    let authenticator = &native[authenticator_start..factory_start];
    let factory = &native[factory_start..factory_end];

    for (name, implementation) in [
        ("PluginAuthenticator", authenticator),
        ("PluginFactory", factory),
    ] {
        assert!(
            implementation.contains("callbacks_.retain_context(callbacks_.context)"),
            "{name} must retain the Rust callback context for its COM lifetime"
        );
        assert!(
            implementation.contains("callbacks_.release_context(callbacks_.context)"),
            "{name} must release the Rust callback context when its COM lifetime ends"
        );
    }
}

#[test]
fn native_metadata_reconciliation_prepares_first_and_never_runs_inline_after_registration() {
    let native = include_str!("../native/passkey_plugin.cpp");

    let bulk_start = native
        .find("vaultkern_plugin_sync_credentials(")
        .expect("bulk metadata reconciliation");
    let bulk_end = native[bulk_start..]
        .find("vaultkern_plugin_test_replaces_cached_account_credential")
        .map(|offset| bulk_start + offset)
        .expect("bulk metadata reconciliation end");
    let bulk = &native[bulk_start..bulk_end];
    assert!(
        bulk.find("PrepareCredentialCache")
            .expect("prepared replacement batch")
            < bulk
                .find("remove_all(kPluginClsid)")
                .expect("remove old metadata"),
        "the complete replacement must be validated before clearing OS metadata"
    );
    let remove = bulk.find("remove_all(kPluginClsid)").unwrap();
    assert!(
        bulk[..remove].contains("result = add("),
        "the desired metadata must be accepted before the destructive RemoveAll point"
    );
    assert!(
        bulk[remove..].matches("add(").count() >= 2,
        "a transient post-RemoveAll add failure must retry from the same desired snapshot"
    );
    assert!(
        bulk.contains("previous_cache")
            && bulk.contains("restore_details")
            && bulk[remove..].contains("restore_result = add("),
        "a persistent replacement failure must restore the previous OS metadata snapshot"
    );

    let make_start = native
        .find("HRESULT STDMETHODCALLTYPE MakeCredential(")
        .expect("MakeCredential implementation");
    let get_start = native[make_start..]
        .find("HRESULT STDMETHODCALLTYPE GetAssertion(")
        .map(|offset| make_start + offset)
        .expect("GetAssertion implementation");
    let make = &native[make_start..get_start];
    assert!(
        !make.contains("WebAuthNPluginAuthenticatorAddCredentials")
            && !make.contains("AddCredentialMetadata"),
        "credential metadata is desired-state reconciliation and must not run inline in registration"
    );
}

#[test]
fn bridge_forwards_native_parent_window_handle_without_using_the_runtime_protocol() {
    let bridge = RuntimeBridge::new_for_tests();

    bridge
        .set_parent_window_handle(Some(0x1234))
        .expect("set parent window");
    bridge
        .set_parent_window_handle(None)
        .expect("clear parent window");
}

#[test]
fn runtime_bridge_serves_protocol_envelopes_from_its_runtime_thread() {
    let bridge = RuntimeBridge::new_for_tests();

    let response = bridge.request(json!({
        "version": 1,
        "command": { "type": "get_session_state" }
    }));

    assert_eq!(response["type"], "session_state");
    assert_eq!(response["unlocked"], false);
    assert_eq!(response["supportsBiometricUnlock"], false);
}

#[test]
fn password_unlock_handoff_is_wiped_and_acknowledged_before_the_response_returns() {
    let (_scratch, bridge) = quick_unlock_bridge_with_current_vault("handoff-failure");
    let (reconciliation, reconciliation_requests) = std::sync::mpsc::sync_channel(1);
    bridge
        .set_reconciliation_notifier(reconciliation)
        .expect("install reconciliation notifier");
    let request_bridge = bridge.clone();
    let (response, response_receiver) = std::sync::mpsc::channel();
    let unlock = std::thread::spawn(move || {
        response
            .send(request_bridge.request(json!({
                "version": 1,
                "command": {
                    "type": "unlock_current_vault",
                    "password": "demo-password",
                    "key_file_path": null
                }
            })))
            .unwrap();
    });

    let SettingsReconciliationRequest {
        quick_unlock_credentials,
        quick_unlock_completion,
    } = reconciliation_requests
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("password unlock reconciliation handoff");
    let credentials = quick_unlock_credentials.expect("one-shot credentials");
    assert_eq!(credentials.password(), Some("demo-password"));
    assert!(response_receiver.try_recv().is_err());
    drop(credentials);
    quick_unlock_completion
        .expect("credential handoff completion")
        .send(Err("injected settings load failure".to_owned()))
        .unwrap();

    let session = response_receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("unlock response after reconciliation acknowledgement");
    unlock.join().unwrap();
    assert_eq!(session["type"], "session_state");
    assert_eq!(session["unlocked"], true);
}

#[test]
fn disconnected_reconciler_wipes_the_handoff_without_failing_password_unlock() {
    let (_scratch, bridge) = quick_unlock_bridge_with_current_vault("handoff-disconnected");
    let (reconciliation, reconciliation_requests) =
        std::sync::mpsc::sync_channel::<SettingsReconciliationRequest>(1);
    bridge
        .set_reconciliation_notifier(reconciliation)
        .expect("install reconciliation notifier");
    drop(reconciliation_requests);

    let session = bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));

    assert_eq!(session["type"], "session_state");
    assert_eq!(session["unlocked"], true);
}

#[test]
fn successful_password_handoff_enrolls_quick_unlock_before_returning() {
    let (_scratch, bridge) = quick_unlock_bridge_with_current_vault("handoff-success");
    let (reconciliation, reconciliation_requests) = std::sync::mpsc::sync_channel(1);
    bridge
        .set_reconciliation_notifier(reconciliation)
        .expect("install reconciliation notifier");
    let reconciliation_bridge = bridge.clone();
    let reconciliation = std::thread::spawn(move || {
        let SettingsReconciliationRequest {
            quick_unlock_credentials,
            quick_unlock_completion,
        } = reconciliation_requests.recv().unwrap();
        let result = reconciliation_bridge
            .reconcile_quick_unlock(true, quick_unlock_credentials)
            .map(|_| ());
        quick_unlock_completion.unwrap().send(result).unwrap();
    });

    let session = bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));
    reconciliation.join().unwrap();

    assert_eq!(session["unlocked"], true);
    assert_eq!(
        bridge.request(json!({
            "version": 1,
            "command": { "type": "list_recent_vaults" }
        }))["vaults"][0]["supportsQuickUnlock"],
        true
    );
}

#[test]
fn runtime_bridge_returns_a_protocol_error_for_invalid_envelopes() {
    let bridge = RuntimeBridge::new_for_tests();

    let response = bridge.request(json!({ "command": { "type": "not_a_command" } }));

    assert_eq!(response["type"], "error");
    assert_eq!(response["code"], "invalid_request");
}

#[test]
fn runtime_bridge_opens_edits_and_saves_a_real_local_vault() {
    let scratch = tempfile::tempdir().unwrap();
    let database_path = scratch.path().join("resident-slice.kdbx");
    let core = KeepassCore::new();
    let mut vault = Vault::empty("Resident Slice");
    let root_id = vault.root.id.to_string();
    let entry = core
        .add_entry(
            &mut vault,
            &root_id,
            EntryCreate {
                title: "Before Edit".into(),
                username: "alice".into(),
                password: "before-secret".into(),
                url: "https://example.com".into(),
                notes: "before".into(),
            },
        )
        .unwrap();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    std::fs::write(
        &database_path,
        core.save_kdbx(&vault, &key, SaveProfile::recommended())
            .unwrap(),
    )
    .unwrap();

    let bridge = RuntimeBridge::new_for_tests();
    let path = database_path.to_string_lossy().into_owned();
    let reference = bridge.request(json!({
        "version": 1,
        "command": { "type": "add_local_vault_reference", "path": path }
    }));
    assert_eq!(reference["type"], "vault_reference");

    let session = bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));
    assert_eq!(session["type"], "session_state");
    assert_eq!(session["unlocked"], true);
    let vault_id = session["activeVaultId"].as_str().unwrap();

    let entries = bridge.request(json!({
        "version": 1,
        "command": { "type": "list_entries", "vault_id": vault_id }
    }));
    assert_eq!(entries["entries"][0]["title"], "Before Edit");

    let updated = bridge.request(json!({
        "version": 1,
        "command": {
            "type": "update_entry_fields",
            "vault_id": vault_id,
            "entry_id": entry.id,
            "title": "After Edit",
            "username": "alice",
            "password": "after-secret",
            "url": "https://example.com/after",
            "notes": "after",
            "totp_uri": null,
            "custom_fields": []
        }
    }));
    assert_eq!(updated["type"], "entry_detail");
    assert_eq!(updated["title"], "After Edit");

    let saved = bridge.request(json!({
        "version": 1,
        "command": { "type": "save_vault", "vault_id": vault_id }
    }));
    assert_eq!(saved["type"], "save_vault_result");
    assert_eq!(saved["status"], "saved");

    let persisted = core
        .load_kdbx(&std::fs::read(&database_path).unwrap(), &key)
        .unwrap();
    let persisted_entry = persisted
        .root
        .entries
        .iter()
        .find(|candidate| candidate.title == "After Edit")
        .unwrap();
    assert_eq!(persisted_entry.title, "After Edit");
    assert_eq!(persisted_entry.password, "after-secret");
}

#[test]
fn runtime_bridge_runs_platform_passkeys_on_the_same_resident_runtime_thread() {
    const PLUGIN_AAGUID: [u8; 16] = [
        0xc8, 0xb2, 0xf4, 0xa1, 0x7d, 0x31, 0x4e, 0x59, 0x9a, 0x62, 0x0f, 0xd3, 0xb6, 0xe4, 0xc7,
        0x21,
    ];
    assert!(
        include_str!("../native/passkey_plugin.cpp").contains("C8B2F4A17D314E599A620FD3B6E4C721")
    );
    let scratch = tempfile::tempdir().unwrap();
    let database_path = scratch.path().join("resident-passkeys.kdbx");
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    std::fs::write(
        &database_path,
        core.save_kdbx(
            &Vault::empty("Resident Passkeys"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap(),
    )
    .unwrap();

    let bridge = RuntimeBridge::new_for_tests();
    let (reconciliation, reconciliation_requests) = std::sync::mpsc::sync_channel(1);
    bridge
        .set_reconciliation_notifier(reconciliation)
        .expect("install reconciliation notifier");
    let (reconciled, reconciled_requests) = std::sync::mpsc::channel();
    let reconciliation_worker = std::thread::spawn(move || {
        for _ in 0..2 {
            let SettingsReconciliationRequest {
                quick_unlock_credentials,
                quick_unlock_completion,
            } = reconciliation_requests.recv().unwrap();
            let carried_credentials = quick_unlock_credentials.is_some();
            drop(quick_unlock_credentials);
            if let Some(completion) = quick_unlock_completion {
                completion.send(Ok(())).unwrap();
            }
            reconciled.send(carried_credentials).unwrap();
        }
    });
    assert!(!bridge.platform_passkey_is_unlocked());
    let path = database_path.to_string_lossy().into_owned();
    bridge.request(json!({
        "version": 1,
        "command": { "type": "add_local_vault_reference", "path": path }
    }));
    bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));
    assert!(bridge.platform_passkey_is_unlocked());
    assert!(
        reconciled_requests
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("successful unlock must schedule reconciliation")
    );

    let registration_operation = vec![1; 16];
    bridge
        .prepare_platform_passkey_operation(registration_operation.clone(), None)
        .expect("prepare typed registration");
    let registration = bridge
        .register_platform_passkey(
            registration_operation.clone(),
            PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "example.com".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "alice@example.com".into(),
                user_handle: b"bridge-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            },
        )
        .expect("typed registration");
    bridge
        .commit_platform_passkey_registration(registration_operation.clone())
        .expect("durable typed registration");
    bridge.end_platform_passkey_operation(registration_operation);
    assert!(
        !reconciled_requests
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("durable platform registration must schedule reconciliation")
    );
    reconciliation_worker.join().unwrap();
    assert_eq!(&registration.authenticator_data[37..53], PLUGIN_AAGUID);
    let credentials = bridge
        .list_platform_passkey_credentials()
        .expect("typed credential list");
    assert_eq!(credentials, vec![registration.credential.clone()]);

    let abandoned_operation = vec![9; 16];
    bridge
        .prepare_platform_passkey_operation(abandoned_operation.clone(), None)
        .expect("prepare abandoned registration");
    bridge
        .register_platform_passkey(
            abandoned_operation.clone(),
            PlatformPasskeyRegistrationInput {
                relying_party: "example.net".into(),
                relying_party_name: "example.net".into(),
                user_name: "bob@example.net".into(),
                user_display_name: "bob@example.net".into(),
                user_handle: b"abandoned-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            },
        )
        .expect("prepare registration before native encode");
    bridge.end_platform_passkey_operation(abandoned_operation);
    assert_eq!(
        bridge
            .list_platform_passkey_credentials()
            .expect("credential list after abandoned registration"),
        vec![registration.credential.clone()],
        "ending an uncommitted registration must roll back its in-memory mutation"
    );

    let assertion_operation = vec![2; 16];
    bridge
        .prepare_platform_passkey_operation(assertion_operation.clone(), None)
        .expect("prepare typed assertion");
    let assertion = bridge
        .create_platform_passkey_assertion(
            assertion_operation.clone(),
            PlatformPasskeyAssertionInput {
                relying_party: "example.com".into(),
                allowed_credential_ids: vec![registration.credential.credential_id.clone()],
                client_data_hash: vec![0x61; 32],
                user_verified: true,
            },
        )
        .expect("typed assertion");
    bridge.end_platform_passkey_operation(assertion_operation);
    assert_eq!(
        assertion.credential_id,
        registration.credential.credential_id
    );
    assert_eq!(assertion.user_handle, b"bridge-user");
}

#[test]
fn locked_runtime_never_exposes_an_empty_passkey_sync_snapshot() {
    let bridge = RuntimeBridge::new_for_tests();

    assert!(!bridge.platform_passkey_is_unlocked());
    let error = bridge
        .list_platform_passkey_credentials()
        .expect_err("locked credential metadata must be skipped, not replaced with an empty list");
    assert!(error.contains("locked"), "unexpected error: {error}");
}

#[test]
fn runtime_bridge_reconciles_quick_unlock_from_desired_state_while_locked() {
    let scratch = tempfile::tempdir().unwrap();
    let database_path = scratch.path().join("reconcile-quick-unlock.kdbx");
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    std::fs::write(
        &database_path,
        core.save_kdbx(
            &Vault::empty("Quick Unlock"),
            &key,
            SaveProfile::recommended(),
        )
        .unwrap(),
    )
    .unwrap();

    let bridge = RuntimeBridge::new_for_tests_with_quick_unlock();
    bridge.request(json!({
        "version": 1,
        "command": {
            "type": "add_local_vault_reference",
            "path": database_path.to_string_lossy()
        }
    }));
    bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));

    assert!(
        bridge
            .reconcile_quick_unlock(
                true,
                Some(QuickUnlockReconciliationCredentials::from_protocol_input(
                    Some("demo-password".into()),
                    None,
                )),
            )
            .unwrap()
    );
    bridge.request(json!({
        "version": 1,
        "command": { "type": "lock_session" }
    }));
    assert!(
        bridge.request(json!({
            "version": 1,
            "command": { "type": "list_recent_vaults" }
        }))["vaults"][0]["supportsQuickUnlock"]
            .as_bool()
            .unwrap()
    );

    assert!(bridge.reconcile_quick_unlock(false, None).unwrap());
    assert!(
        !bridge.request(json!({
            "version": 1,
            "command": { "type": "list_recent_vaults" }
        }))["vaults"][0]["supportsQuickUnlock"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn cold_platform_operation_quick_unlocks_and_returns_the_authoritative_credential_snapshot() {
    let scratch = tempfile::tempdir().unwrap();
    let database_path = scratch.path().join("cold-platform-operation.kdbx");
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    std::fs::write(
        &database_path,
        KeepassCore::new()
            .save_kdbx(
                &Vault::empty("Cold Platform Operation"),
                &key,
                SaveProfile::recommended(),
            )
            .unwrap(),
    )
    .unwrap();

    let bridge = RuntimeBridge::new_for_tests_with_quick_unlock();
    bridge.request(json!({
        "version": 1,
        "command": {
            "type": "add_local_vault_reference",
            "path": database_path.to_string_lossy()
        }
    }));
    bridge.request(json!({
        "version": 1,
        "command": {
            "type": "unlock_current_vault",
            "password": "demo-password",
            "key_file_path": null
        }
    }));
    let registration_operation = vec![3; 16];
    bridge
        .prepare_platform_passkey_operation(registration_operation.clone(), None)
        .unwrap();
    let registration = bridge
        .register_platform_passkey(
            registration_operation.clone(),
            PlatformPasskeyRegistrationInput {
                relying_party: "example.com".into(),
                relying_party_name: "Example".into(),
                user_name: "alice@example.com".into(),
                user_display_name: "Alice".into(),
                user_handle: b"cold-user".to_vec(),
                public_key_algorithm: -7,
                user_verified: true,
            },
        )
        .unwrap();
    bridge
        .commit_platform_passkey_registration(registration_operation.clone())
        .unwrap();
    bridge.end_platform_passkey_operation(registration_operation);
    bridge
        .reconcile_quick_unlock(
            true,
            Some(QuickUnlockReconciliationCredentials::from_protocol_input(
                Some("demo-password".into()),
                None,
            )),
        )
        .unwrap();
    bridge.request(json!({
        "version": 1,
        "command": { "type": "lock_session" }
    }));

    let cold_operation = vec![4; 16];
    let (credentials, freshly_verified) = bridge
        .prepare_platform_passkey_operation(cold_operation.clone(), Some(0x1234))
        .expect("cold provider operation quick unlock");
    assert!(freshly_verified);
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials[0].credential_id,
        registration.credential.credential_id
    );
    bridge.end_platform_passkey_operation(cold_operation);
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(!bridge.platform_passkey_is_unlocked());

    bridge.request(json!({
        "version": 1,
        "command": { "type": "unlock_current_vault_with_quick_unlock" }
    }));
    let warm_operation = vec![5; 16];
    let (_, freshly_verified) = bridge
        .prepare_platform_passkey_operation(warm_operation.clone(), Some(0x1234))
        .expect("already-unlocked provider operation refresh");
    assert!(!freshly_verified);
    bridge.end_platform_passkey_operation(warm_operation);
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(bridge.platform_passkey_is_unlocked());
}
