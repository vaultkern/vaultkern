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

#[test]
fn kotlin_sensitive_byte_converter_clears_every_temporary_copy() {
    let kotlin = fs::read_to_string(
        crate_root().join("bindings/kotlin/org/vaultkern/core/vaultkern_uniffi.kt"),
    )
    .unwrap();
    let converter = kotlin
        .split_once("public object FfiConverterTypeSensitiveBytes")
        .unwrap()
        .1
        .split_once("public typealias SensitiveString")
        .unwrap()
        .0;

    assert_eq!(converter.matches("builtinValue.fill(0)").count(), 3);
}

#[test]
fn kotlin_sensitive_string_converter_never_materializes_plain_strings() {
    let kotlin = fs::read_to_string(
        crate_root().join("bindings/kotlin/org/vaultkern/core/vaultkern_uniffi.kt"),
    )
    .unwrap();
    let converter = kotlin
        .split_once("public object FfiConverterTypeSensitiveString")
        .unwrap()
        .1;

    assert!(!converter.contains("FfiConverterString"));
    assert_eq!(converter.matches("value.copyUtf8Bytes()").count(), 3);
    assert_eq!(
        converter
            .matches("VaultKernSensitiveString.fromUtf8Bytes")
            .count(),
        2
    );
    assert_eq!(converter.matches("bytes.fill(0)").count(), 5);
}
