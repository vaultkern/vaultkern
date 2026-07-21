use serde_json::json;
use vaultkern_core::{CompositeKey, EntryCreate, KeepassCore, SaveProfile, Vault};
use vaultkern_runtime::{PlatformPasskeyAssertionInput, PlatformPasskeyRegistrationInput};
use vaultkern_windows::RuntimeBridge;

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
    let durable_callback = make
        .find("callbacks_.make_credential")
        .expect("durable registration callback");

    assert!(make[..durable_callback].contains("operation.CheckCancelled()"));
    assert!(
        !make[durable_callback..].contains("operation.CheckCancelled()"),
        "once the durable registration callback succeeds, late cancellation must not turn the committed ceremony into a failure"
    );
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

    let registration = bridge
        .register_platform_passkey(PlatformPasskeyRegistrationInput {
            relying_party: "example.com".into(),
            relying_party_name: "example.com".into(),
            user_name: "alice@example.com".into(),
            user_display_name: "alice@example.com".into(),
            user_handle: b"bridge-user".to_vec(),
            public_key_algorithm: -7,
            user_verified: true,
        })
        .expect("typed registration");
    assert_eq!(&registration.authenticator_data[37..53], PLUGIN_AAGUID);
    let credentials = bridge
        .list_platform_passkey_credentials()
        .expect("typed credential list");
    assert_eq!(credentials, vec![registration.credential.clone()]);

    let assertion = bridge
        .create_platform_passkey_assertion(PlatformPasskeyAssertionInput {
            relying_party: "example.com".into(),
            allowed_credential_ids: vec![registration.credential.credential_id.clone()],
            client_data_hash: vec![0x61; 32],
            user_verified: true,
        })
        .expect("typed assertion");
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
