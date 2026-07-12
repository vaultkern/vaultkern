#![cfg(target_os = "macos")]

use serde_json::Value;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const HOST_NAME: &str = "com.vaultkern.runtime";
const EXTENSION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_EXTENSION_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DEVELOPER_ID_HASH: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
const DEVELOPER_ID_NAME: &str = "Developer ID Application: VaultKern Test (TEAMID1234)";
const APPLE_DEVELOPMENT_NAME: &str = "Apple Development: VaultKern Test (CERTUSER01)";
const SELF_SIGNED_NAME: &str = "VaultKern Self Signed";
const SPOOFED_DEVELOPER_ID_HASH: &str = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
const SPOOFED_DEVELOPER_ID_NAME: &str = "Developer ID Application: VaultKern Spoof (SPOOFTEAM1)";

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}

fn host_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-apple-darwin",
        "x86_64" => "x86_64-apple-darwin",
        arch => panic!("unsupported macOS test architecture: {arch}"),
    }
}

fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        arch => panic!("unsupported macOS test architecture: {arch}"),
    }
}

fn opposite_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "x86_64-apple-darwin",
        "x86_64" => "aarch64-apple-darwin",
        arch => panic!("unsupported macOS test architecture: {arch}"),
    }
}

fn script_command(name: &str) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(script(name))
        .env_remove("VAULTKERN_CODESIGN_IDENTITY")
        .env_remove("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID")
        .env_remove("VAULTKERN_MACOS_APP_DESTINATION")
        .env_remove("VAULTKERN_CHROME_NATIVE_HOST_MANIFEST");
    command
}

fn prebuilt_with_build_version(temp: &TempDir, name: &str, platform: &str, minos: &str) -> PathBuf {
    let source = temp.path().join(format!("{name}-source"));
    let output = temp.path().join(name);
    std::fs::copy(env!("CARGO_BIN_EXE_vaultkern-runtime"), &source).unwrap();
    let edit = Command::new("vtool")
        .args(["-set-build-version", platform, minos, "13.0", "-replace"])
        .arg("-output")
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert_success(edit, "edit prebuilt binary build version");
    output
}

fn valid_prebuilt(temp: &TempDir) -> PathBuf {
    prebuilt_with_build_version(temp, "vaultkern-runtime-macos-13", "macos", "13.0")
}

fn run_package(
    output_root: &Path,
    home: &Path,
    prebuilt_binary: &Path,
    extra_args: &[&str],
) -> Output {
    let mut command = script_command("package_macos.sh");
    command
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(prebuilt_binary)
        .args(extra_args)
        .env("HOME", home);
    command.output().unwrap()
}

fn run_install(home: &Path, app: &Path) -> Output {
    run_install_for_extension(home, app, EXTENSION_ID)
}

fn run_install_for_extension(home: &Path, app: &Path, extension_id: &str) -> Output {
    script_command("install_native_host_macos.sh")
        .arg(extension_id)
        .arg(app)
        .env("HOME", home)
        .output()
        .unwrap()
}

fn path_with_first(first: &Path) -> OsString {
    let inherited_path =
        std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    let mut search_paths = vec![first.to_path_buf()];
    search_paths.extend(std::env::split_paths(&inherited_path));
    std::env::join_paths(search_paths).unwrap()
}

fn write_executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn macos_bridge_source_contract_uses_secure_enclave_key_agreement() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");

    for required in [
        "SecureEnclave.P256.KeyAgreement.PrivateKey",
        ".privateKeyUsage",
        ".biometryCurrentSet",
        "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        "P256.KeyAgreement.PrivateKey(compactRepresentable: false)",
        "hkdfDerivedSymmetricKey",
        "SHA256.self",
        "outputByteCount: 32",
        "localizedReason",
        "NSUnderlyingErrorKey",
        "NSMultipleUnderlyingErrorsKey",
        "memset_s(pointer, length, 0, length)",
    ] {
        assert!(
            swift.contains(required),
            "Swift bridge is missing {required}"
        );
    }

    assert!(
        !swift.contains(".underlyingErrors"),
        "Swift bridge must read underlying NSError values through userInfo for SDK compatibility"
    );
}

#[test]
fn macos_local_authentication_is_transient_and_has_no_persisted_right_store() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source =
        std::fs::read_to_string(runtime.join("src/providers/macos_local_authentication.rs"))
            .expect("the macOS LocalAuthentication implementation must exist");
    let manifest = std::fs::read_to_string(runtime.join("Cargo.toml"))
        .expect("the runtime Cargo manifest must exist");

    for required in [
        "evaluatePolicy_localizedReason_reply",
        "DeviceOwnerAuthenticationWithBiometrics",
        "NSRunLoop::currentRunLoop()",
    ] {
        assert!(
            source.contains(required),
            "LocalAuthentication is missing {required}"
        );
    }

    assert!(
        !source.contains("#![allow(dead_code)]"),
        "LocalAuthentication must not suppress dead-code diagnostics"
    );

    for forbidden in [
        "LARight",
        "LARightStore",
        "LAPersistedRight",
        "LASecret",
        "LAAuthenticationRequirement",
    ] {
        assert!(
            !source.contains(forbidden),
            "LocalAuthentication still contains persisted API {forbidden}"
        );
        assert!(
            !manifest.contains(&format!("\"{forbidden}\"")),
            "the runtime still enables persisted API feature {forbidden}"
        );
    }
}

#[test]
fn macos_native_host_is_an_agent_app_without_a_dock_icon() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let plist = runtime.join("macos/Info.plist");

    assert_eq!(plist_value(&plist, "LSUIElement"), "true");
}

#[test]
fn macos_bridge_refreshes_wrapping_material_from_only_the_secure_enclave_public_key() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let refresh_start = swift
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_derive_for_refresh\")")
        .expect("the public-side refresh C ABI must exist");
    let restore_start = swift[refresh_start..]
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_restore_and_derive\")")
        .map(|offset| refresh_start + offset)
        .expect("the private-side restore C ABI must follow refresh");
    let refresh = &swift[refresh_start..restore_start];

    for required in [
        "context.interactionNotAllowed = true",
        "authenticationContext: context",
        "P256.KeyAgreement.PrivateKey(compactRepresentable: false)",
        "peerPrivateKey.sharedSecretFromKeyAgreement(with: secureEnclaveKey.publicKey)",
        "peerPrivateKey.publicKey.rawRepresentation",
    ] {
        assert!(refresh.contains(required), "refresh is missing {required}");
    }
    assert!(
        !refresh.contains("secureEnclaveKey.sharedSecretFromKeyAgreement"),
        "refresh must never perform a Secure Enclave private-key operation"
    );
}

#[test]
fn macos_secure_enclave_creation_uses_the_requested_touch_id_reason() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let create_start = swift
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_create\")")
        .expect("the create C ABI must exist");
    let refresh_start = swift[create_start..]
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_derive_for_refresh\")")
        .map(|offset| create_start + offset)
        .expect("the refresh C ABI must follow create");
    let create = &swift[create_start..refresh_start];

    assert!(create.contains("let reason = try copiedString("));
    assert!(create.contains("context.localizedReason = reason"));
    assert!(create.contains("authenticationContext: context"));
}

#[test]
fn macos_bridge_treats_biometry_unavailable_as_transient() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let classify_start = swift
        .find("private func classify(")
        .expect("error classifier must exist");
    let classify_end = swift[classify_start..]
        .find("private func diagnostic(")
        .map(|offset| classify_start + offset)
        .expect("diagnostic function must follow the classifier");
    let classify = &swift[classify_start..classify_end];
    let invalidation_start = classify
        .find("if invalidationEligible")
        .expect("invalidation branch must exist");
    let missing_start = classify[invalidation_start..]
        .find("if containsSecurityStatus(errSecItemNotFound")
        .map(|offset| invalidation_start + offset)
        .expect("missing-item branch must follow invalidation");
    let transient_branch = &classify[..invalidation_start];
    let invalidation_branch = &classify[invalidation_start..missing_start];

    assert!(
        transient_branch.contains("localAuthentication.contains(.biometryNotAvailable)"),
        "temporary biometric unavailability must map to interaction unavailability"
    );
    assert!(
        transient_branch.contains("return statusInteractionUnavailable"),
        "temporary biometric unavailability must use the transient bridge status"
    );
    assert!(
        !invalidation_branch.contains(".biometryNotAvailable"),
        "temporary biometric unavailability must never invalidate stored key material"
    );
    assert!(
        invalidation_branch.contains("localAuthentication.contains(.biometryNotEnrolled)"),
        "enrollment loss remains permanent invalidation evidence"
    );
}

#[test]
fn macos_bridge_treats_both_security_interaction_statuses_as_transient() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let classify_start = swift
        .find("private func classify(")
        .expect("error classifier must exist");
    let classify_end = swift[classify_start..]
        .find("private func diagnostic(")
        .map(|offset| classify_start + offset)
        .expect("diagnostic function must follow the classifier");
    let classify = &swift[classify_start..classify_end];
    let transient_end = classify
        .find("return statusInteractionUnavailable")
        .expect("the transient interaction branch must exist");
    let transient = &classify[..transient_end];

    for status in ["errSecInteractionNotAllowed", "errSecInteractionRequired"] {
        assert!(
            transient.contains(status),
            "{status} must map to InteractionUnavailable"
        );
    }
}

#[test]
fn macos_bridge_wipes_private_key_data_copies_on_every_exit() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    for required in [
        "private func wipeData(_ data: inout Data)",
        "data.withUnsafeMutableBytes",
        "memset_s(baseAddress, buffer.count, 0, buffer.count)",
    ] {
        assert!(
            swift.contains(required),
            "private-key Data wipe helper is missing {required}"
        );
    }

    let create_start = swift
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_create\")")
        .expect("create C ABI must exist");
    let restore_start = swift
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_restore_and_derive\")")
        .expect("restore C ABI must exist");
    let refresh_start = swift
        .find("@_cdecl(\"vaultkern_macos_secure_enclave_derive_for_refresh\")")
        .expect("refresh C ABI must exist");
    let free_start = swift
        .find("@_cdecl(\"vaultkern_macos_buffer_free\")")
        .expect("buffer free C ABI must follow restore");
    let create = &swift[create_start..refresh_start];
    let refresh = &swift[refresh_start..restore_start];
    let restore = &swift[restore_start..free_start];

    let create_copy = create
        .find("var privateKeyData = secureEnclaveKey.dataRepresentation")
        .expect("create must hold a mutable private-key representation");
    let create_defer = create
        .find("defer { wipeData(&privateKeyData) }")
        .expect("create must defer wiping its private-key representation");
    let create_publish = create
        .find("publish(\n            privateKeyData,")
        .expect("create must publish from the mutable private-key representation");
    assert!(
        create_copy < create_defer && create_defer < create_publish,
        "create must install the wipe defer before publishing private-key bytes"
    );
    assert!(
        !create.contains("publish(\n            secureEnclaveKey.dataRepresentation,"),
        "create must not publish an unwipeable temporary Data value"
    );

    let refresh_copy = refresh
        .find("var privateKeyData = try copiedData(")
        .expect("refresh must hold mutable private-key input Data");
    let refresh_defer = refresh
        .find("defer { wipeData(&privateKeyData) }")
        .expect("refresh must defer wiping its private-key input");
    let refresh_salt = refresh
        .find("let salt = try copiedData(")
        .expect("refresh salt parsing must follow private-key input");
    assert!(refresh_copy < refresh_defer && refresh_defer < refresh_salt);

    let restore_copy = restore
        .find("var privateKeyData = try copiedData(")
        .expect("restore must hold mutable private-key input Data");
    let restore_defer = restore
        .find("defer { wipeData(&privateKeyData) }")
        .expect("restore must defer wiping its private-key input Data");
    let next_throwing_copy = restore
        .find("let peerPublicKeyData = try copiedData(")
        .expect("peer public-key copy must follow private-key input");
    assert!(
        restore_copy < restore_defer && restore_defer < next_throwing_copy,
        "restore must install the wipe defer before any later throwing operation"
    );
}

#[test]
fn macos_quick_unlock_records_use_only_the_executable_bound_login_keychain() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let keychain_start = swift
        .find("// MARK: - Executable-bound Quick Unlock Keychain")
        .expect("the legacy login Keychain implementation must exist");
    let keychain_end = swift[keychain_start..]
        .find("// MARK: - Secure Enclave C ABI")
        .map(|offset| keychain_start + offset)
        .expect("the Secure Enclave bridge must follow the Keychain implementation");
    let keychain = &swift[keychain_start..keychain_end];

    for required in [
        "FileManager.default.homeDirectoryForCurrentUser",
        "Library/Keychains/login.keychain-db",
        "SecKeychainOpen(",
        "SecTrustedApplicationCreateFromPath(nil",
        "SecAccessCreate(",
        "kSecAttrAccess: access",
        "kSecUseKeychain: keychain",
        "kSecMatchSearchList: [keychain]",
        "SecItemAdd(",
        "SecItemCopyMatching(",
        "SecItemUpdate(",
        "SecItemDelete(",
        "vaultkern_macos_quick_unlock_record_store",
        "vaultkern_macos_quick_unlock_keychain_is_available",
        "vaultkern_macos_quick_unlock_record_contains",
        "vaultkern_macos_quick_unlock_record_load",
        "vaultkern_macos_quick_unlock_record_delete",
    ] {
        assert!(
            keychain.contains(required),
            "macOS Quick Unlock Keychain implementation is missing {required}"
        );
    }

    for forbidden in [
        "SecKeychainCopyDefault",
        "kSecUseDataProtectionKeychain",
        "kSecAttrSynchronizable",
        "kSecAttrAccessControl",
        "kSecAttrAccessible",
        "kSecAttrAccessGroup",
    ] {
        assert!(
            !keychain.contains(forbidden),
            "legacy Quick Unlock records must not use {forbidden}"
        );
    }
}

#[test]
fn macos_native_messaging_caller_accepts_only_the_top_level_chrome_identifier() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let caller_start = swift
        .find("// MARK: - Native Messaging Caller Verification")
        .expect("the native messaging caller verifier must exist");
    let caller_end = swift[caller_start..]
        .find("private func accessControl()")
        .map(|offset| caller_start + offset)
        .expect("Secure Enclave access control must follow caller verification");
    let caller = &swift[caller_start..caller_end];

    assert!(caller.contains("identifier == chromeBundleIdentifier"));
    assert!(!caller.contains("hasPrefix"));
    assert!(!caller.contains("com.google.Chrome.helper"));
}

#[test]
fn macos_quick_unlock_keychain_availability_probe_is_noninteractive_and_metadata_only() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let probe_start = swift
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_keychain_is_available\")")
        .expect("the login Keychain availability probe must exist");
    let store_start = swift[probe_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_store\")")
        .map(|offset| probe_start + offset)
        .expect("the record store C ABI must follow the availability probe");
    let probe = &swift[probe_start..store_start];

    for required in [
        "withKeychainUserInteractionDisabled {",
        "defaultLoginKeychain()",
        "return 1",
        "return 0",
    ] {
        assert!(
            probe.contains(required),
            "login Keychain availability probe is missing {required}"
        );
    }
    for forbidden in [
        "SecItem",
        "kSecReturnData",
        "publish(",
        "SecKeychainCreate",
        "SecKeychainSetDefault",
        "SecKeychainUnlock",
    ] {
        assert!(
            !probe.contains(forbidden),
            "login Keychain availability probe must not use {forbidden}"
        );
    }
}

#[test]
fn macos_quick_unlock_contains_never_requests_or_publishes_secret_data() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let contains_start = swift
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_contains\")")
        .expect("the record contains C ABI must exist");
    let load_start = swift[contains_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_load\")")
        .map(|offset| contains_start + offset)
        .expect("the record load C ABI must follow contains");
    let contains = &swift[contains_start..load_start];

    assert!(contains.contains("copyQuickUnlockRecordItem("));
    assert!(contains.contains("validateQuickUnlockRecordAccess(existingItem)"));
    assert!(
        !contains.contains("kSecReturnData"),
        "contains must never request the opaque record bytes"
    );
    assert!(
        !contains.contains("publish("),
        "contains must never return an allocated secret buffer"
    );
}

#[test]
fn macos_quick_unlock_acl_inspection_globally_suppresses_ui_under_a_lock() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let keychain_start = swift
        .find("// MARK: - Executable-bound Quick Unlock Keychain")
        .expect("the legacy login Keychain implementation must exist");
    let keychain_end = swift[keychain_start..]
        .find("// MARK: - Secure Enclave C ABI")
        .map(|offset| keychain_start + offset)
        .expect("the Secure Enclave bridge must follow the Keychain implementation");
    let keychain = &swift[keychain_start..keychain_end];

    for required in [
        "private let securityInteractionLock = NSRecursiveLock()",
        "SecKeychainGetUserInteractionAllowed(",
        "SecKeychainSetUserInteractionAllowed(false)",
        "let bodyResult: Result<T, Error>",
        "let restoreStatus = SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue)",
        "securityInteractionLock.lock()",
        "securityInteractionLock.unlock()",
    ] {
        assert!(
            keychain.contains(required),
            "Keychain guard is missing {required}"
        );
    }
    assert!(
        keychain
            .matches("withKeychainUserInteractionDisabled {")
            .count()
            >= 4,
        "every exported record operation must share the serialized global UI guard"
    );
}

#[test]
fn macos_secure_enclave_operations_share_the_global_keychain_interaction_lock() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    for (exported, next_exported) in [
        (
            "vaultkern_macos_secure_enclave_create",
            "vaultkern_macos_secure_enclave_derive_for_refresh",
        ),
        (
            "vaultkern_macos_secure_enclave_derive_for_refresh",
            "vaultkern_macos_secure_enclave_restore_and_derive",
        ),
        (
            "vaultkern_macos_secure_enclave_restore_and_derive",
            "vaultkern_macos_buffer_free",
        ),
    ] {
        let start = swift
            .find(&format!("@_cdecl(\"{exported}\")"))
            .unwrap_or_else(|| panic!("{exported} must exist"));
        let end = swift[start..]
            .find(&format!("@_cdecl(\"{next_exported}\")"))
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("{next_exported} must follow {exported}"));
        let body = &swift[start..end];
        assert!(
            body.contains("securityInteractionLock.lock()"),
            "{exported}"
        );
        assert!(
            body.contains("securityInteractionLock.unlock()"),
            "{exported}"
        );
    }
}

#[test]
fn macos_quick_unlock_acl_validation_covers_delete_controllers() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let validation_start = swift
        .find("private func validateQuickUnlockRecordAccess(")
        .expect("the ACL validator must exist");
    let store_start = swift[validation_start..]
        .find("private func storeQuickUnlockRecord(")
        .map(|offset| validation_start + offset)
        .expect("store helper must follow ACL validation");
    let validation = &swift[validation_start..store_start];

    for required in [
        "kSecACLAuthorizationDelete",
        "kSecACLAuthorizationKeychainItemDelete",
        "validateMutatingApplicationList(",
    ] {
        assert!(
            validation.contains(required),
            "ACL validation is missing {required}"
        );
    }
}

#[test]
fn macos_quick_unlock_load_validates_and_binds_the_item_before_requesting_secret_data() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let load_start = swift
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_load\")")
        .expect("the record load C ABI must exist");
    let delete_start = swift[load_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_delete\")")
        .map(|offset| load_start + offset)
        .expect("the record delete C ABI must follow load");
    let load = &swift[load_start..delete_start];

    let item_lookup = load
        .find("copyQuickUnlockRecordItem(")
        .expect("load must first fetch the item reference from the default Keychain");
    let acl_validation = load
        .find("try validateQuickUnlockRecordAccess(existingItem)")
        .expect("load must validate the existing item's full ACL");
    let stable_match = load
        .find("kSecMatchItemList: [existingItem]")
        .expect("load must bind its data request to the validated item reference");
    let return_data = load
        .find("kSecReturnData: true")
        .expect("load must explicitly request data only after validation");
    let data_fetch = load
        .find("SecItemCopyMatching(fetchQuery as CFDictionary, &result)")
        .expect("load must use the stable-reference fetch query");
    assert!(
        item_lookup < acl_validation
            && acl_validation < stable_match
            && stable_match < return_data
            && return_data < data_fetch,
        "lookup, ACL validation, stable binding, and data fetch must remain ordered"
    );
    assert!(
        load.contains("kSecUseAuthenticationUI: kSecUseAuthenticationUIFail"),
        "the stable-reference data fetch must suppress Keychain UI"
    );
    assert!(
        load[stable_match..data_fetch].contains("kSecMatchSearchList: [keychain]"),
        "the validated item fetch must remain scoped to the opened login Keychain"
    );
    for forbidden in ["kSecAttrService", "kSecAttrAccount"] {
        assert!(
            !load[stable_match..data_fetch].contains(forbidden),
            "the validated item fetch must not add {forbidden}"
        );
    }
}

#[test]
fn macos_quick_unlock_stable_item_queries_keep_class_and_login_keychain_scope() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");

    for (query_start, operation) in [
        ("let updateQuery: [CFString: Any] = [", "SecItemUpdate("),
        (
            "let fetchQuery: [CFString: Any] = [",
            "SecItemCopyMatching(fetchQuery",
        ),
        ("let deleteQuery: [CFString: Any] = [", "SecItemDelete("),
    ] {
        let start = swift
            .find(query_start)
            .unwrap_or_else(|| panic!("stable-reference query {query_start} must exist"));
        let end = swift[start..]
            .find(operation)
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("{operation} must follow {query_start}"));
        let query = &swift[start..end];

        assert!(
            query.contains("kSecClass: kSecClassGenericPassword"),
            "{query_start} must identify the validated item as a generic password"
        );
        assert!(
            query.contains("kSecMatchItemList: [existingItem]"),
            "{query_start} must stay bound to the validated item reference"
        );
        assert!(
            query.contains("kSecMatchSearchList: [keychain]"),
            "{query_start} must stay scoped to the opened login Keychain"
        );
    }
}

#[test]
fn macos_quick_unlock_store_wipes_its_copied_record_bytes_on_every_exit() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let store_start = swift
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_store\")")
        .expect("the record store C ABI must exist");
    let contains_start = swift[store_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_contains\")")
        .map(|offset| store_start + offset)
        .expect("the record contains C ABI must follow store");
    let store = &swift[store_start..contains_start];

    let record_copy = store
        .find("var recordData = try copiedData(")
        .expect("store must keep its copied record in mutable Data");
    let wipe = store
        .find("defer { wipeData(&recordData) }")
        .expect("store must defer wiping its copied record");
    let keychain = store
        .find("let keychain = try defaultLoginKeychain()")
        .expect("store must explicitly select the default login Keychain");
    assert!(
        record_copy < wipe && wipe < keychain,
        "store must install the record wipe before a later Keychain operation can fail"
    );
}

#[test]
fn macos_quick_unlock_store_updates_in_place_without_replacing_the_acl() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let helper_start = swift
        .find("private func storeQuickUnlockRecord(")
        .expect("the record storage helper must exist");
    let store_export_start = swift[helper_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_store\")")
        .map(|offset| helper_start + offset)
        .expect("the record store C ABI must follow its helper");
    let helper = &swift[helper_start..store_export_start];

    let update = helper
        .find("SecItemUpdate(")
        .expect("existing records must be updated in place");
    let add = helper
        .find("SecItemAdd(")
        .expect("a missing record must be added with its initial ACL");
    assert!(
        update < add,
        "store must try an in-place update before adding"
    );
    assert!(
        helper.contains("let replacement = [kSecValueData: recordData]"),
        "in-place updates must replace only the opaque record bytes"
    );
    assert!(
        !helper.contains("SecItemDelete("),
        "store must never delete an existing record before replacing it"
    );
    assert!(
        !helper.contains("kSecAttrAccess: access") || add > update,
        "the ACL belongs only to the missing-item add path"
    );
}

#[test]
fn macos_quick_unlock_keychain_operations_fail_instead_of_showing_keychain_ui() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let keychain_start = swift
        .find("// MARK: - Executable-bound Quick Unlock Keychain")
        .expect("the legacy login Keychain implementation must exist");
    let keychain_end = swift[keychain_start..]
        .find("// MARK: - Secure Enclave C ABI")
        .map(|offset| keychain_start + offset)
        .expect("the Secure Enclave bridge must follow the Keychain implementation");
    let keychain = &swift[keychain_start..keychain_end];

    let query_start = keychain
        .find("private func quickUnlockRecordQuery(")
        .expect("the shared query builder must exist");
    let record_id_start = keychain[query_start..]
        .find("private func quickUnlockRecordID(")
        .map(|offset| query_start + offset)
        .expect("the record ID parser must follow the query builder");
    let query = &keychain[query_start..record_id_start];
    assert!(
        query.contains("kSecUseAuthenticationUI: kSecUseAuthenticationUIFail"),
        "every lookup, update, and delete query must suppress Keychain UI"
    );

    let new_item_start = keychain
        .find("let newItem: [CFString: Any] = [")
        .expect("the missing-item add dictionary must exist");
    let add_start = keychain[new_item_start..]
        .find("let addStatus = SecItemAdd(")
        .map(|offset| new_item_start + offset)
        .expect("the add call must follow its dictionary");
    let new_item = &keychain[new_item_start..add_start];
    assert!(
        new_item.contains("kSecUseAuthenticationUI: kSecUseAuthenticationUIFail"),
        "adding a record must not permit a surprise login Keychain prompt"
    );

    for exported in [
        "vaultkern_macos_quick_unlock_record_contains",
        "vaultkern_macos_quick_unlock_record_load",
        "vaultkern_macos_quick_unlock_record_delete",
    ] {
        let exported_start = keychain
            .find(&format!("@_cdecl(\"{exported}\")"))
            .unwrap_or_else(|| panic!("{exported} C ABI must exist"));
        let body = &keychain[exported_start..];
        assert!(
            body.contains("copyQuickUnlockRecordItem("),
            "{exported} must use the UI-suppressing, Keychain-scoped item lookup"
        );
    }
}

#[test]
fn macos_quick_unlock_add_races_fail_closed_instead_of_adopting_an_unknown_acl() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let helper_start = swift
        .find("private func storeQuickUnlockRecord(")
        .expect("the record storage helper must exist");
    let store_export_start = swift[helper_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_store\")")
        .map(|offset| helper_start + offset)
        .expect("the record store C ABI must follow its helper");
    let helper = &swift[helper_start..store_export_start];

    assert_eq!(
        helper.matches("SecItemUpdate(").count(),
        1,
        "store must not update a duplicate created with an unverified ACL"
    );
    assert!(
        !helper.contains("addStatus == errSecDuplicateItem"),
        "an unexpected duplicate must fail closed"
    );
    assert!(
        helper.contains(
            "try checkSecurityStatus(addStatus, operation: \"add the Quick Unlock record\")"
        ),
        "the duplicate Security status must be preserved as a platform error"
    );
}

#[test]
fn macos_quick_unlock_validates_the_exact_existing_items_decrypt_acl_before_update() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let swift = std::fs::read_to_string(runtime.join("macos/SecureEnclaveBridge.swift"))
        .expect("the macOS Swift bridge source must exist");
    let keychain_start = swift
        .find("// MARK: - Executable-bound Quick Unlock Keychain")
        .expect("the legacy login Keychain implementation must exist");
    let keychain_end = swift[keychain_start..]
        .find("// MARK: - Secure Enclave C ABI")
        .map(|offset| keychain_start + offset)
        .expect("the Secure Enclave bridge must follow the Keychain implementation");
    let keychain = &swift[keychain_start..keychain_end];

    let item_start = keychain
        .find("private func copyQuickUnlockRecordItem(")
        .expect("updates must first copy the exact existing item reference");
    let validation_start = keychain[item_start..]
        .find("private func validateQuickUnlockRecordAccess(")
        .map(|offset| item_start + offset)
        .expect("the existing item's ACL validator must follow its lookup");
    let item_lookup = &keychain[item_start..validation_start];
    assert!(
        item_lookup.contains("kSecReturnRef"),
        "the lookup must return a stable item reference for validation and update"
    );
    assert!(
        !item_lookup.contains("kSecReturnData"),
        "ACL validation must not read the opaque record bytes"
    );
    assert!(
        item_lookup.contains("quickUnlockRecordQuery(recordID: recordID, keychain: keychain)"),
        "the item lookup must remain scoped to the explicit default Keychain with UI disabled"
    );

    let store_start = keychain[validation_start..]
        .find("private func storeQuickUnlockRecord(")
        .map(|offset| validation_start + offset)
        .expect("the record storage helper must follow ACL validation");
    let validation = &keychain[validation_start..store_start];
    for required in [
        "SecKeychainItemCopyAccess(",
        "SecAccessCopyACLList(",
        "SecACLGetTypeID()",
        "SecACLCopyAuthorizations(",
        "kSecACLAuthorizationDecrypt",
        "kSecACLAuthorizationAny",
        "kSecACLAuthorizationKeychainItemRead",
        "kSecACLAuthorizationChangeACL",
        "kSecACLAuthorizationChangeOwner",
        "kSecACLAuthorizationKeychainItemModify",
        "SecACLCopyContents(",
        "foundSecretReadingACL",
    ] {
        assert!(
            validation.contains(required),
            "existing-item ACL validation is missing {required}"
        );
    }
    assert!(
        keychain.contains("SecTrustedApplicationCopyData("),
        "trusted application identity comparisons must use Security framework identity data"
    );
    for required in [
        "SecTrustedApplicationGetTypeID()",
        "CFEqual(storedIdentity, currentIdentity)",
    ] {
        assert!(
            keychain.contains(required),
            "trusted application validation is missing {required}"
        );
    }
    assert!(
        !validation.contains("SecAccessCopyMatchingACLList"),
        "validation must enumerate the full ACL so Any and item-read entries cannot be missed"
    );
    for helper in [
        "validateSecretReadingApplicationList(",
        "validateMutatingApplicationList(",
    ] {
        assert!(
            keychain.contains(helper),
            "ACL validation must fail closed through {helper}"
        );
    }

    let store_export_start = keychain[store_start..]
        .find("@_cdecl(\"vaultkern_macos_quick_unlock_record_store\")")
        .map(|offset| store_start + offset)
        .expect("the record store C ABI must follow its helper");
    let store = &keychain[store_start..store_export_start];
    let validate_call = store
        .find("try validateQuickUnlockRecordAccess(")
        .expect("an existing item must be validated");
    let stable_match = store
        .find("kSecMatchItemList: [existingItem]")
        .expect("the update must stay bound to the validated item reference");
    let update_call = store
        .find("SecItemUpdate(")
        .expect("the validated item must be updated in place");
    assert!(
        validate_call < stable_match && stable_match < update_call,
        "ACL validation and stable item binding must both precede the in-place update"
    );
    let update_query_start = store[..update_call]
        .rfind("let updateQuery: [CFString: Any] = [")
        .expect("the stable-reference update query must be explicit");
    let update_query = &store[update_query_start..update_call];
    assert!(
        update_query.contains("kSecUseAuthenticationUI: kSecUseAuthenticationUIFail"),
        "the stable-reference update must keep Keychain UI disabled"
    );
    assert!(
        update_query.contains("kSecMatchSearchList: [keychain]"),
        "the validated item update must remain scoped to the opened login Keychain"
    );
    for forbidden in ["kSecAttrService", "kSecAttrAccount"] {
        assert!(
            !update_query.contains(forbidden),
            "the stable-reference update query must not add {forbidden}"
        );
    }
}

#[test]
fn macos_rust_bridge_exposes_zeroizing_quick_unlock_record_storage() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rust = std::fs::read_to_string(runtime.join("src/macos_secure_enclave.rs"))
        .expect("the private macOS bridge wrapper must exist");

    for required in [
        "fn vaultkern_macos_quick_unlock_record_store(",
        "fn vaultkern_macos_quick_unlock_record_contains(",
        "fn vaultkern_macos_quick_unlock_record_load(",
        "fn vaultkern_macos_quick_unlock_record_delete(",
        "pub(super) fn store_quick_unlock_record(",
        "pub(super) fn quick_unlock_record_exists(",
        "pub(super) fn load_quick_unlock_record(",
        "pub(super) fn delete_quick_unlock_record(",
        "Result<SensitiveBytes, BridgeError>",
    ] {
        assert!(
            rust.contains(required),
            "private Rust Keychain wrapper is missing {required}"
        );
    }

    let contains_start = rust
        .find("pub(super) fn quick_unlock_record_exists(")
        .expect("record existence wrapper must exist");
    let load_start = rust[contains_start..]
        .find("pub(super) fn load_quick_unlock_record(")
        .map(|offset| contains_start + offset)
        .expect("record load wrapper must follow existence");
    let contains = &rust[contains_start..load_start];
    assert!(
        contains.contains("STATUS_MISSING_ITEM => Ok(false)"),
        "the Rust existence API must distinguish a missing record"
    );

    let load_end = rust[load_start..]
        .find("pub(super) fn delete_quick_unlock_record(")
        .map(|offset| load_start + offset)
        .expect("record delete wrapper must follow load");
    let load = &rust[load_start..load_end];
    assert!(
        load.contains("SensitiveBytes(record.to_vec(\"Quick Unlock record\")?)"),
        "loaded opaque bytes must immediately enter a zeroizing Rust owner"
    );
}

#[test]
fn macos_envelope_moves_the_decoded_secure_enclave_blob_into_zeroizing_storage_first() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let provider = std::fs::read_to_string(runtime.join("src/providers/macos_quick_unlock.rs"))
        .expect("the macOS Quick Unlock provider source must exist");
    let decode_start = provider
        .find("fn decode_envelope(")
        .expect("the envelope decoder must exist");
    let decoder = &provider[decode_start..];
    let private_decode = decoder
        .find("let private_key = decode_base64(")
        .expect("the Secure Enclave representation must be decoded");
    let private_owner = decoder
        .find("let private_key = SensitiveBytes::new(private_key)")
        .expect("the decoded representation must enter a zeroizing owner");
    let peer_decode = decoder
        .find("let peer_public_key = decode_base64(")
        .expect("peer parsing must follow the private representation");
    assert!(private_decode < private_owner && private_owner < peer_decode);
}

#[test]
fn macos_runtime_zeroizes_serialized_and_decrypted_quick_unlock_credentials() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(runtime.join("src/runtime.rs"))
        .expect("the runtime source must exist");
    let manifest = std::fs::read_to_string(runtime.join("Cargo.toml"))
        .expect("the runtime Cargo manifest must exist");

    assert!(source.contains("use zeroize::{Zeroize, Zeroizing};"));
    assert!(source.matches("Zeroizing::new(").count() >= 4);
    let common_dependencies = manifest.find("[dependencies]").unwrap();
    let zeroize_dependency = manifest.find("zeroize.workspace = true").unwrap();
    let macos_dependencies = manifest
        .find("[target.'cfg(target_os = \"macos\")'.dependencies]")
        .unwrap();
    assert!(common_dependencies < zeroize_dependency);
    assert!(zeroize_dependency < macos_dependencies);
}

#[test]
fn macos_bridge_build_contract_resolves_the_selected_xcode_toolchain_with_xcrun() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR"));
    let build = std::fs::read_to_string(runtime.join("build.rs"))
        .expect("vaultkern-runtime build script must exist");

    for required in [
        "Command::new(\"/usr/bin/xcrun\")",
        "--find",
        "swiftc",
        "--show-sdk-path",
        "CARGO_CFG_TARGET_OS",
        "macos",
        "CARGO_CFG_TARGET_ARCH",
        "apple-macosx13.0",
        "-emit-library",
        "-static",
        "vaultkern_macos_bridge",
        "cargo:rustc-link-arg=-mmacosx-version-min=13.0",
    ] {
        assert!(
            build.contains(required),
            "build script is missing {required}"
        );
    }
    assert!(!build.contains("/Library/Developer/CommandLineTools"));
    assert!(!build.contains(".env(\"DEVELOPER_DIR\""));
}

#[test]
fn macos_bridge_final_test_binary_targets_macos_13() {
    let executable = std::env::current_exe().expect("test executable path must be available");
    let output = Command::new("vtool")
        .arg("-show-build")
        .arg(&executable)
        .output()
        .expect("vtool must inspect the test executable");
    assert!(
        output.status.success(),
        "vtool failed for {}: {}",
        executable.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let build_version = String::from_utf8(output.stdout).expect("vtool output must be UTF-8");

    assert!(
        build_version.contains("platform MACOS") && build_version.contains("minos 13.0"),
        "Swift-linked test executable must target macOS 13.0:\n{build_version}"
    );
}

fn fake_signing_tools(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let fake_bin = temp.path().join("fake-signing-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let security_log = temp.path().join("security.log");
    let codesign_log = temp.path().join("codesign.log");
    let codesign_display_log = temp.path().join("codesign-display.log");
    let codesign_verify_log = temp.path().join("codesign-verify.log");

    write_executable(
        &fake_bin.join("security"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VAULTKERN_TEST_SECURITY_LOG\"\ncat <<'EOF'\n  1) {DEVELOPER_ID_HASH} \"{DEVELOPER_ID_NAME}\"\n  2) 2222222222222222222222222222222222222222 \"{APPLE_DEVELOPMENT_NAME}\"\n  3) 3333333333333333333333333333333333333333 \"{SELF_SIGNED_NAME}\"\n  4) {SPOOFED_DEVELOPER_ID_HASH} \"{SPOOFED_DEVELOPER_ID_NAME}\"\n     4 valid identities found\nEOF\n"
        ),
    );
    write_executable(
        &fake_bin.join("codesign"),
        r#"#!/bin/sh
if [ "$1" = "--verify" ]; then
  : > "$VAULTKERN_TEST_CODESIGN_VERIFY_LOG"
  for argument in "$@"; do
    printf '%s\n' "$argument" >> "$VAULTKERN_TEST_CODESIGN_VERIFY_LOG"
  done
  if [ "${VAULTKERN_TEST_SIGNATURE_MODE:-valid}" = "spoofed" ]; then
    echo 'explicit Developer ID requirement failed' >&2
    exit 3
  fi
  exit 0
fi

if [ "$1" = "--display" ]; then
  printf 'call' >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  for argument in "$@"; do
    printf '\t%s' "$argument" >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  done
  printf '\n' >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  if [ "$2" = "--verbose=4" ]; then
    if [ "${VAULTKERN_TEST_SIGNATURE_MODE:-valid}" = "spoofed" ]; then
      cat >&2 <<'EOF'
Executable=/tmp/VaultKern Native.app/Contents/MacOS/vaultkern-runtime
Identifier=com.vaultkern.runtime
CodeDirectory v=20500 size=512 flags=0x10000(runtime) hashes=8+2 location=embedded
Authority=Developer ID Application: VaultKern Spoof (SPOOFTEAM1)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jul 11, 2026 at 12:00:00
TeamIdentifier=SPOOFTEAM1
EOF
    elif [ "${VAULTKERN_TEST_SIGNATURE_MODE:-valid}" = "apple-development" ]; then
      cat >&2 <<'EOF'
Executable=/tmp/VaultKern Native.app/Contents/MacOS/vaultkern-runtime
Identifier=com.vaultkern.runtime
CodeDirectory v=20500 size=512 flags=0x10000(runtime) hashes=8+2 location=embedded
Authority=Apple Development: VaultKern Test (CERTUSER01)
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=Jul 11, 2026 at 12:00:00
TeamIdentifier=TEAMID1234
EOF
    else
      cat >&2 <<'EOF'
Executable=/tmp/VaultKern Native.app/Contents/MacOS/vaultkern-runtime
Identifier=com.vaultkern.runtime
CodeDirectory v=20500 size=512 flags=0x10000(runtime) hashes=8+2 location=embedded
Authority=Developer ID Application: VaultKern Test (TEAMID1234)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jul 11, 2026 at 12:00:00
TeamIdentifier=TEAMID1234
EOF
    fi
    exit 0
  fi
  if [ "$2" = "--requirements" ]; then
    echo 'designated => identifier "com.vaultkern.runtime" and anchor apple generic' >&2
    exit 0
  fi
  exit 64
fi

: > "$VAULTKERN_TEST_CODESIGN_LOG"
for argument in "$@"; do
  printf '%s\n' "$argument" >> "$VAULTKERN_TEST_CODESIGN_LOG"
  bundle="$argument"
done
exec /usr/bin/codesign --force --sign - "$bundle"
"#,
    );

    (
        fake_bin,
        security_log,
        codesign_log,
        codesign_display_log,
        codesign_verify_log,
    )
}

fn fake_installer_codesign(temp: &TempDir) -> PathBuf {
    let fake_bin = temp.path().join("fake-installer-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("codesign"),
        r#"#!/bin/sh
for argument in "$@"; do
  bundle="$argument"
done

if [ "$1" = "--verify" ]; then
  exit 0
fi

if [ "$bundle" = "$VAULTKERN_TEST_EXISTING_APP" ]; then
  team="$VAULTKERN_TEST_EXISTING_TEAM"
  requirement="$VAULTKERN_TEST_EXISTING_REQUIREMENT"
else
  team="$VAULTKERN_TEST_INCOMING_TEAM"
  requirement="$VAULTKERN_TEST_INCOMING_REQUIREMENT"
fi

if [ "$1" = "--display" ] && [ "$2" = "--verbose=4" ]; then
  printf '%s\n' 'Identifier=com.vaultkern.runtime' "TeamIdentifier=$team" >&2
  exit 0
fi

if [ "$1" = "--display" ] && [ "$2" = "--requirements" ]; then
  printf 'designated => %s\n' "$requirement" >&2
  exit 0
fi

exit 64
"#,
    );
    fake_bin
}

fn assert_success(output: Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn plist_value(plist: &Path, key: &str) -> String {
    let output = Command::new("plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .unwrap();
    assert_success(output.clone(), &format!("read plist key {key}"));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn packages_signed_app_and_installs_chrome_native_host() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );

    let app = output_root.join(host_target()).join("VaultKern Native.app");
    let plist = app.join("Contents/Info.plist");
    let bundled_executable = app.join("Contents/MacOS/vaultkern-runtime");

    assert!(bundled_executable.is_file());
    assert_eq!(
        plist_value(&plist, "CFBundleIdentifier"),
        "com.vaultkern.runtime"
    );
    assert_eq!(
        plist_value(&plist, "CFBundleExecutable"),
        "vaultkern-runtime"
    );
    assert_eq!(plist_value(&plist, "CFBundlePackageType"), "APPL");
    assert_eq!(plist_value(&plist, "LSMinimumSystemVersion"), "13.0");
    assert_eq!(plist_value(&plist, "LSUIElement"), "true");

    let verify = Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&app)
        .output()
        .unwrap();
    assert_success(verify, "verify packaged app signature");

    let install = run_install(&home, &app);
    assert_success(install, "install macOS native host");

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    assert!(installed_executable.is_file());

    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(installed_manifest).unwrap()).unwrap();
    assert_eq!(manifest["name"], HOST_NAME);
    assert_eq!(
        manifest["path"],
        std::fs::canonicalize(&installed_executable)
            .unwrap()
            .to_str()
            .expect("temporary path is UTF-8")
    );
    assert_eq!(
        manifest["allowed_origins"],
        serde_json::json!([format!("chrome-extension://{EXTENSION_ID}/")])
    );
}

#[test]
fn package_rejects_prebuilt_for_the_opposite_architecture() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();

    let output = script_command("package_macos.sh")
        .arg(opposite_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .env("HOME", home)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "packaged the opposite architecture"
    );
    let expected = match host_architecture() {
        "arm64" => "expected thin x86_64 Mach-O",
        "x86_64" => "expected thin arm64 Mach-O",
        arch => panic!("unsupported test architecture: {arch}"),
    };
    assert!(String::from_utf8(output.stderr).unwrap().contains(expected));
}

#[test]
fn package_rejects_non_macho_prebuilt() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = temp.path().join("not-macho");
    write_executable(&prebuilt, "#!/bin/sh\nexit 0\n");
    std::fs::create_dir(&home).unwrap();

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .env("HOME", home)
        .output()
        .unwrap();

    assert!(!output.status.success(), "packaged a non-Mach-O file");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("not a thin Mach-O")
    );
}

#[test]
fn package_rejects_non_macos_platform_prebuilt() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = prebuilt_with_build_version(&temp, "ios-runtime", "ios", "13.0");
    std::fs::create_dir(&home).unwrap();

    let output = run_package(&output_root, &home, &prebuilt, &[]);

    assert!(!output.status.success(), "packaged a non-macOS Mach-O");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("expected macOS platform")
    );
}

#[test]
fn package_rejects_prebuilt_with_wrong_deployment_minimum() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = prebuilt_with_build_version(&temp, "macos-12-runtime", "macos", "12.0");
    std::fs::create_dir(&home).unwrap();

    let output = run_package(&output_root, &home, &prebuilt, &[]);

    assert!(!output.status.success(), "packaged a macOS 12 binary");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("minimum macOS version must be exactly 13.0")
    );
}

#[test]
fn package_copy_sign_or_publish_failure_preserves_existing_artifact() {
    for failing_tool in ["install", "codesign", "rmdir"] {
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let output_root = temp.path().join("packages");
        let prebuilt = valid_prebuilt(&temp);
        std::fs::create_dir(&home).unwrap();
        assert_success(
            run_package(&output_root, &home, &prebuilt, &[]),
            "package initial macOS app",
        );

        let app = output_root.join(host_target()).join("VaultKern Native.app");
        let marker = app.join("Contents/Resources/known-good");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"known-good").unwrap();
        assert_success(
            Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&app)
                .output()
                .unwrap(),
            "re-sign known-good app",
        );

        let fake_bin = temp.path().join("failing-package-bin");
        std::fs::create_dir(&fake_bin).unwrap();
        write_executable(&fake_bin.join(failing_tool), "#!/bin/sh\nexit 23\n");
        let failed_package = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .arg("--prebuilt-binary")
            .arg(&prebuilt)
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .output()
            .unwrap();

        assert!(
            !failed_package.status.success(),
            "{failing_tool} failure unexpectedly packaged an app"
        );
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"known-good",
            "{failing_tool} failure replaced the known-good artifact"
        );
        assert_success(
            Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(&app)
                .output()
                .unwrap(),
            &format!("verify artifact after {failing_tool} failure"),
        );
    }
}

#[test]
fn installer_rejects_invalid_or_changed_extension_id_without_replacing_state() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");

    for invalid_extension_id in [
        "test-extension-id".to_owned(),
        "A".repeat(32),
        "q".repeat(32),
        "é".repeat(32),
    ] {
        let invalid = script_command("install_native_host_macos.sh")
            .arg(&invalid_extension_id)
            .arg(&app)
            .env("HOME", &home)
            .env("LC_ALL", "en_US.UTF-8")
            .output()
            .unwrap();
        assert!(
            !invalid.status.success(),
            "accepted invalid extension ID {invalid_extension_id:?}"
        );
        assert!(
            String::from_utf8(invalid.stderr)
                .unwrap()
                .contains("32 lowercase characters in the range a-p")
        );
    }

    assert_success(run_install(&home, &app), "install initial app");
    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let expected_origin = format!("chrome-extension://{EXTENSION_ID}/");
    let mut origin_dictionary = serde_json::Map::new();
    origin_dictionary.insert(expected_origin, Value::String("not-a-string-origin".into()));
    let type_confusion_manifest = serde_json::to_vec(&serde_json::json!({
        "name": HOST_NAME,
        "description": "type confusion fixture",
        "path": "/stale/vaultkern-runtime",
        "type": "stdio",
        "allowed_origins": [Value::Object(origin_dictionary)],
    }))
    .unwrap();
    std::fs::write(&installed_manifest, &type_confusion_manifest).unwrap();

    let rejected_type_confusion = run_install(&home, &app);
    assert!(
        !rejected_type_confusion.status.success(),
        "accepted a non-string extension origin"
    );
    assert!(
        String::from_utf8(rejected_type_confusion.stderr)
            .unwrap()
            .contains("cannot read the existing native-host extension origin")
    );
    assert_eq!(
        std::fs::read(&installed_manifest).unwrap(),
        type_confusion_manifest
    );
    std::fs::write(&installed_manifest, &original_manifest).unwrap();

    let incoming_app = temp.path().join("Incoming Extension Drift.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "copy incoming extension-drift app",
    );
    let incoming_marker = incoming_app.join("Contents/Resources/incoming-marker");
    std::fs::create_dir_all(incoming_marker.parent().unwrap()).unwrap();
    std::fs::write(&incoming_marker, b"extension-drift").unwrap();
    assert_success(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "re-sign incoming extension-drift app",
    );

    let rejected = run_install_for_extension(&home, &incoming_app, OTHER_EXTENSION_ID);

    assert!(!rejected.status.success(), "accepted extension ID drift");
    assert!(
        String::from_utf8(rejected.stderr)
            .unwrap()
            .contains("extension origin drift")
    );
    assert_eq!(
        std::fs::read(&installed_manifest).unwrap(),
        original_manifest
    );
    assert!(
        !installed_app
            .join("Contents/Resources/incoming-marker")
            .exists(),
        "extension ID drift replaced the installed app"
    );
}

#[test]
fn failed_bundle_copy_preserves_existing_installation_and_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");

    assert_success(
        run_install(&home, &app),
        "install initial macOS native host",
    );

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let fake_bin = temp.path().join("fake-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let fake_ditto = fake_bin.join("ditto");
    std::fs::write(&fake_ditto, "#!/bin/sh\nexit 23\n").unwrap();
    std::fs::set_permissions(&fake_ditto, std::fs::Permissions::from_mode(0o755)).unwrap();
    let failed_install = script_command("install_native_host_macos.sh")
        .arg(EXTENSION_ID)
        .arg(&app)
        .env("HOME", &home)
        .env("PATH", path_with_first(&fake_bin))
        .output()
        .unwrap();

    assert!(!failed_install.status.success());
    let verify = Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&installed_app)
        .output()
        .unwrap();
    assert_success(verify, "verify preserved app signature");
    assert_eq!(
        std::fs::read(installed_manifest).unwrap(),
        original_manifest
    );
}

#[test]
fn failed_manifest_generation_restores_existing_installation_and_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    assert_success(
        run_install(&home, &app),
        "install initial macOS native host",
    );

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_executable = std::fs::read(&installed_executable).unwrap();
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let failing_app = temp.path().join("Manifest Failure.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&failing_app)
            .output()
            .unwrap(),
        "copy manifest-failure app",
    );
    std::fs::copy(
        "/usr/bin/false",
        failing_app.join("Contents/MacOS/vaultkern-runtime"),
    )
    .unwrap();
    assert_success(
        Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&failing_app)
            .output()
            .unwrap(),
        "sign manifest-failure app",
    );

    let failed_install = run_install(&home, &failing_app);
    assert!(!failed_install.status.success());
    assert_eq!(
        std::fs::read(&installed_executable).unwrap(),
        original_executable
    );
    assert_eq!(
        std::fs::read(&installed_manifest).unwrap(),
        original_manifest
    );
    assert_success(
        Command::new("codesign")
            .args(["--verify", "--strict"])
            .arg(&installed_app)
            .output()
            .unwrap(),
        "verify restored app signature",
    );
}

#[test]
fn first_install_manifest_failure_removes_new_app_and_preserves_stale_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    let failing_app = temp.path().join("First Install Failure.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&failing_app)
            .output()
            .unwrap(),
        "copy first-install failure app",
    );
    std::fs::copy(
        "/usr/bin/false",
        failing_app.join("Contents/MacOS/vaultkern-runtime"),
    )
    .unwrap();
    assert_success(
        Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&failing_app)
            .output()
            .unwrap(),
        "sign first-install failure app",
    );

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    std::fs::create_dir_all(installed_manifest.parent().unwrap()).unwrap();
    let stale_manifest = serde_json::to_vec(&serde_json::json!({
        "name": HOST_NAME,
        "description": "stale manifest",
        "path": "/stale/vaultkern-runtime",
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    }))
    .unwrap();
    std::fs::write(&installed_manifest, &stale_manifest).unwrap();

    let failed_install = run_install(&home, &failing_app);

    assert!(!failed_install.status.success());
    assert!(
        !installed_app.exists(),
        "failed first install left the new app"
    );
    assert_eq!(std::fs::read(installed_manifest).unwrap(), stale_manifest);
}

#[test]
fn adhoc_upgrade_is_rejected_before_it_can_strand_quick_unlock_records() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    assert_success(run_install(&home, &app), "install initial ad-hoc app");
    let installed_executable = home
        .join("Library/Application Support/VaultKern/VaultKern Native.app")
        .join("Contents/MacOS/vaultkern-runtime");
    let original_executable = std::fs::read(&installed_executable).unwrap();

    let upgrade = run_install(&home, &app);

    assert!(!upgrade.status.success());
    assert!(
        String::from_utf8(upgrade.stderr)
            .unwrap()
            .contains("refusing ad-hoc native host upgrade")
    );
    assert_eq!(
        std::fs::read(installed_executable).unwrap(),
        original_executable
    );
}

#[test]
fn installer_rejects_team_or_designated_requirement_drift_and_preserves_installation() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    assert_success(run_install(&home, &app), "install initial app");

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_app_canonical = std::fs::canonicalize(&installed_app).unwrap();
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_executable = std::fs::read(&installed_executable).unwrap();
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let incoming_app = temp.path().join("Incoming.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "copy incoming app",
    );
    let incoming_marker = incoming_app.join("Contents/Resources/incoming-marker");
    std::fs::create_dir_all(incoming_marker.parent().unwrap()).unwrap();
    std::fs::write(&incoming_marker, b"continuity-drift-fixture").unwrap();
    assert_success(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "re-sign incoming app",
    );

    let fake_bin = fake_installer_codesign(&temp);
    let stable_requirement = "identifier com.vaultkern.runtime and anchor apple generic";
    for (case, incoming_team, incoming_requirement, expected_error) in [
        (
            "ad-hoc",
            "not set",
            stable_requirement,
            "TeamIdentifier drift",
        ),
        (
            "team",
            "OTHERTEAM1",
            stable_requirement,
            "TeamIdentifier drift",
        ),
        (
            "requirement",
            "TEAMID1234",
            "identifier com.vaultkern.runtime and anchor apple generic and false",
            "designated requirement drift",
        ),
    ] {
        let rejected = script_command("install_native_host_macos.sh")
            .arg(EXTENSION_ID)
            .arg(&incoming_app)
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_TEST_EXISTING_APP", &installed_app_canonical)
            .env("VAULTKERN_TEST_EXISTING_TEAM", "TEAMID1234")
            .env("VAULTKERN_TEST_INCOMING_TEAM", incoming_team)
            .env("VAULTKERN_TEST_EXISTING_REQUIREMENT", stable_requirement)
            .env("VAULTKERN_TEST_INCOMING_REQUIREMENT", incoming_requirement)
            .output()
            .unwrap();

        assert!(!rejected.status.success(), "accepted {case} drift");
        assert!(
            String::from_utf8(rejected.stderr)
                .unwrap()
                .contains(expected_error)
        );
        assert_eq!(
            std::fs::read(&installed_executable).unwrap(),
            original_executable,
            "{case} drift replaced the existing app"
        );
        assert_eq!(
            std::fs::read(&installed_manifest).unwrap(),
            original_manifest,
            "{case} drift replaced the existing manifest"
        );
        assert!(
            !installed_app
                .join("Contents/Resources/incoming-marker")
                .exists(),
            "{case} drift installed the incoming bundle"
        );
    }
}

#[test]
fn release_signing_resolves_developer_id_name_and_sha1_hash() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, codesign_verify_log) =
        fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("name", DEVELOPER_ID_NAME.to_owned()),
        ("hash", DEVELOPER_ID_HASH.to_ascii_lowercase()),
    ] {
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .arg("--prebuilt-binary")
            .arg(&prebuilt)
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "TEAMID1234")
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
            .env("VAULTKERN_TEST_CODESIGN_VERIFY_LOG", &codesign_verify_log)
            .env("VAULTKERN_TEST_SIGNATURE_MODE", "valid")
            .output()
            .unwrap();
        assert_success(output, &format!("release sign by {case}"));

        assert!(
            security_log.is_file(),
            "release signing must query security"
        );
        let security_args = std::fs::read_to_string(&security_log).unwrap();
        assert_eq!(security_args, "find-identity\n-v\n-p\ncodesigning\n");
        let codesign_args = std::fs::read_to_string(&codesign_log).unwrap();
        for required in ["--force", "--options", "runtime", "--timestamp", "--sign"] {
            assert!(codesign_args.lines().any(|line| line == required));
        }
        assert!(codesign_args.lines().any(|line| line == DEVELOPER_ID_HASH));
        assert!(!codesign_args.lines().any(|line| line == "--deep"));
        let display_calls = std::fs::read_to_string(&codesign_display_log).unwrap();
        assert!(display_calls.contains("call\t--display\t--verbose=4"));
        assert!(display_calls.contains("call\t--display\t--requirements\t-"));
        let verify_args = std::fs::read_to_string(&codesign_verify_log).unwrap();
        assert!(verify_args.lines().any(|line| line == "--verify"));
        assert!(verify_args.lines().any(|line| line == "--strict"));
        let explicit_requirement = verify_args
            .lines()
            .find(|line| line.starts_with("-R="))
            .expect("codesign verify must receive an explicit requirement");
        for required in [
            "identifier \"com.vaultkern.runtime\"",
            "anchor apple generic",
            "certificate 1[field.1.2.840.113635.100.6.2.6] exists",
            "certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
            "certificate leaf[subject.OU] = \"TEAMID1234\"",
        ] {
            assert!(explicit_requirement.contains(required));
        }
    }
}

#[test]
fn development_signing_accepts_an_apple_development_identity_without_a_timestamp() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages-development");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, codesign_verify_log) =
        fake_signing_tools(&temp);

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--development-signing")
        .env("HOME", &home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", APPLE_DEVELOPMENT_NAME)
        .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "TEAMID1234")
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .env("VAULTKERN_TEST_CODESIGN_VERIFY_LOG", &codesign_verify_log)
        .env("VAULTKERN_TEST_SIGNATURE_MODE", "apple-development")
        .output()
        .unwrap();

    assert_success(output, "sign with Apple Development");
    let codesign_args = std::fs::read_to_string(codesign_log).unwrap();
    assert!(codesign_args.lines().any(|line| line == "--options"));
    assert!(codesign_args.lines().any(|line| line == "runtime"));
    assert!(codesign_args.lines().any(|line| line == "--sign"));
    assert!(
        codesign_args
            .lines()
            .any(|line| line == "2222222222222222222222222222222222222222")
    );
    assert!(!codesign_args.lines().any(|line| line == "--timestamp"));

    let display_calls = std::fs::read_to_string(codesign_display_log).unwrap();
    assert!(display_calls.contains("call\t--display\t--verbose=4"));
    let verify_args = std::fs::read_to_string(codesign_verify_log).unwrap();
    assert!(verify_args.lines().any(|line| line == "--strict"));
    assert!(verify_args.lines().any(|line| {
        line.starts_with("-R=")
            && line.contains("anchor apple generic")
            && line.contains("certificate leaf[subject.OU] = \"TEAMID1234\"")
    }));
}

#[test]
fn release_signing_requires_independent_expected_team_id() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", DEVELOPER_ID_NAME)
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID")
    );
    assert!(!codesign_log.exists());
}

#[test]
fn release_signing_rejects_selected_identity_from_unexpected_team() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", DEVELOPER_ID_NAME)
        .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "OTHERTEAM1")
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("does not match VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID")
    );
    assert!(!codesign_log.exists());
}

#[test]
fn release_signing_rejects_non_developer_id_identities() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("apple-development", APPLE_DEVELOPMENT_NAME),
        ("self-signed", SELF_SIGNED_NAME),
    ] {
        let _ = std::fs::remove_file(&codesign_log);
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .arg("--prebuilt-binary")
            .arg(&prebuilt)
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "TEAMID1234")
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
            .output()
            .unwrap();

        assert!(!output.status.success(), "accepted {case} identity");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Developer ID Application")
        );
        assert!(!codesign_log.exists(), "{case} identity reached codesign");
    }
}

#[test]
fn release_signing_rejects_spoofed_developer_id_after_signing() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, codesign_verify_log) =
        fake_signing_tools(&temp);
    let output_root = temp.path().join("packages-spoofed");

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", &home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", SPOOFED_DEVELOPER_ID_NAME)
        .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "SPOOFTEAM1")
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .env("VAULTKERN_TEST_CODESIGN_VERIFY_LOG", &codesign_verify_log)
        .env("VAULTKERN_TEST_SIGNATURE_MODE", "spoofed")
        .output()
        .unwrap();

    assert!(
        codesign_log.is_file(),
        "spoofed identity did not reach signing"
    );
    assert!(!output.status.success(), "accepted spoofed Developer ID");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("explicit Developer ID requirement")
    );
}

#[test]
fn release_signing_rejects_empty_identity() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", home)
        .env("VAULTKERN_CODESIGN_IDENTITY", "")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("VAULTKERN_CODESIGN_IDENTITY")
    );
}
