use std::process::Command;
use vaultkern_runtime::render_manifest;

#[test]
fn render_manifest_emits_expected_native_host_json() {
    let manifest = render_manifest(
        "/tmp/vaultkern-runtime",
        "chrome-extension://test-extension-id/",
    );

    assert_eq!(manifest, expected_manifest());
}

#[test]
fn cli_print_native_host_manifest_emits_only_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_vaultkern-runtime"))
        .args([
            "--print-native-host-manifest",
            "/tmp/vaultkern-runtime",
            "chrome-extension://test-extension-id/",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\n", expected_manifest())
    );
    assert!(String::from_utf8(output.stderr).unwrap().is_empty());
}

fn expected_manifest() -> String {
    let description = if cfg!(windows) {
        "VaultKern resident app IPC shim"
    } else {
        "VaultKern runtime native host"
    };
    format!(
        r#"{{"name":"com.vaultkern.runtime","description":"{description}","path":"/tmp/vaultkern-runtime","type":"stdio","allowed_origins":["chrome-extension://test-extension-id/"]}}"#
    )
}

#[test]
fn cli_rejects_unknown_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_vaultkern-runtime"))
        .arg("--print-native-host-manifest-typo")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("usage: vaultkern-runtime")
    );
}
