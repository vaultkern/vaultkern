use std::fs;
use std::path::Path;

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn generated_bindings_do_not_alias_secret_text_to_plain_strings() {
    let kotlin = fs::read_to_string(
        crate_root().join("bindings/kotlin/org/vaultkern/core/vaultkern_uniffi.kt"),
    )
    .unwrap();
    let swift =
        fs::read_to_string(crate_root().join("bindings/swift/VaultKernCore.swift")).unwrap();
    let kotlin_support = fs::read_to_string(
        crate_root().join("bindings/kotlin/org/vaultkern/core/SensitiveTypes.kt"),
    )
    .unwrap_or_default();
    let swift_support =
        fs::read_to_string(crate_root().join("bindings/swift/SensitiveTypes.swift"))
            .unwrap_or_default();

    assert!(!kotlin.contains("typealias SensitiveString = kotlin.String"));
    assert!(!swift.contains("typealias SensitiveString = String"));
    assert!(kotlin_support.contains("[REDACTED]"));
    assert!(swift_support.contains("[REDACTED]"));
}

#[test]
fn kotlin_generation_targets_android_instead_of_desktop_jvm() {
    let config = fs::read_to_string(crate_root().join("uniffi.toml")).unwrap();

    assert!(config.contains("android = true"));
}
