use std::fs;
use std::path::Path;

#[test]
fn macos_unlock_blob_binding_keeps_the_002_and_d8_security_boundary() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let adapter =
        fs::read_to_string(crate_root.join("bindings/swift/MacOSUnlockBlobAdapter.swift")).unwrap();

    for required in [
        "kSecUseDataProtectionKeychain: true",
        "kSecAttrTokenIDSecureEnclave",
        ".privateKeyUsage",
        ".biometryCurrentSet",
        "touchIDAuthenticationAllowableReuseDuration = 0",
        "defer { context.invalidate() }",
        "PlatformAdapterError.Invalidated",
        "LAError.Code.userFallback.rawValue",
        "LAError.Code.notInteractive.rawValue",
        "value.close()",
    ] {
        assert!(
            adapter.contains(required),
            "missing macOS binding token: {required}"
        );
    }
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
