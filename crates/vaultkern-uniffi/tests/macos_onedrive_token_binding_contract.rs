use std::fs;
use std::path::Path;

#[test]
fn macos_onedrive_token_binding_uses_device_bound_data_protection_keychain_storage() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let adapter = fs::read_to_string(
        crate_root.join("bindings/swift/MacOSOneDriveTokenAdapter.swift"),
    )
    .unwrap();

    for required in [
        "kSecUseDataProtectionKeychain: true",
        "kSecAttrAccessGroup: accessGroup",
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "kSecAttrSynchronizable: false",
        "token.close()",
        "token.copyUTF8Data()",
        "VaultKernSensitiveString(utf8Data: bytes)",
        "bytes.resetBytes",
        "VaultKernMacOSOneDriveTokenAdapter([REDACTED])",
    ] {
        assert!(
            adapter.contains(required),
            "missing macOS OneDrive token binding token: {required}"
        );
    }
    assert!(
        !adapter.contains("token.reveal()"),
        "the Keychain adapter must not materialize the refresh token as a Swift String"
    );
    for banned in [
        "SecKeychain",
        "SecAccessCreate",
        "SecTrustedApplication",
        "kSecUseKeychain",
        "kSecMatchSearchList",
    ] {
        assert!(
            !adapter.contains(banned),
            "legacy Keychain API is banned: {banned}"
        );
    }
}
