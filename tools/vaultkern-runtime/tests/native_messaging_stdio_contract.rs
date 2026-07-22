#![cfg(not(windows))]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use serde_json::json;
use vaultkern_runtime_protocol::PROTOCOL_VERSION;

#[test]
fn windows_native_messaging_shim_declares_gui_subsystem() {
    let runtime_main = include_str!("../src/main.rs");

    assert!(
        runtime_main.contains(r#"#![cfg_attr(windows, windows_subsystem = "windows")]"#),
        "the background native-messaging shim must not create a console window on Windows"
    );
}

#[test]
fn runtime_binary_serves_native_messaging_session_state_frame() {
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let mut child = spawn_isolated_runtime_native_host(&state_dir);

    let request = json!({
        "version": PROTOCOL_VERSION,
        "command": {
            "type": "get_session_state"
        }
    });
    write_native_message(
        child.stdin.as_mut().expect("runtime stdin"),
        &serde_json::to_vec(&request).expect("encode request"),
    );

    let response = read_native_message(child.stdout.as_mut().expect("runtime stdout"));
    child.kill().ok();
    child.wait().ok();

    assert_eq!(
        response.get("type").and_then(|value| value.as_str()),
        Some("session_state")
    );
    assert_eq!(
        response.get("unlocked").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(response.get("activeVaultId").is_some());
    assert!(response.get("currentVaultRefId").is_some());
    assert_eq!(
        response
            .get("supportsBiometricUnlock")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
}

#[test]
fn browser_native_host_cannot_open_or_manage_a_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("runtime-state");
    let home_dir = dir.path().join("runtime-home");
    let origin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut child = spawn_isolated_runtime_native_host_for_origin(&state_dir, &home_dir, origin);
    negotiate_browser_runtime(&mut child);

    let open = send_native_command(
        &mut child,
        json!({
            "version": PROTOCOL_VERSION,
            "command": {
                "type": "open_local_vault",
                "path": dir.path().join("forbidden.kdbx").to_str().expect("utf8 path")
            }
        }),
    );
    assert_eq!(
        open.get("type").and_then(|value| value.as_str()),
        Some("error")
    );
    assert_eq!(
        open.get("code").and_then(|value| value.as_str()),
        Some("browser_command_forbidden")
    );

    let unlock = send_native_command(
        &mut child,
        json!({
            "version": PROTOCOL_VERSION,
            "command": {
                "type": "unlock_with_password",
                "vault_id": "forbidden-vault",
                "password": "demo-password"
            }
        }),
    );
    assert_eq!(
        unlock.get("type").and_then(|value| value.as_str()),
        Some("error")
    );
    assert_eq!(
        unlock.get("code").and_then(|value| value.as_str()),
        Some("browser_command_forbidden")
    );

    child.kill().ok();
    child.wait().ok();
    assert!(
        !state_dir
            .join("vaultkern-runtime")
            .join("vault-references.json")
            .exists()
    );
}

fn spawn_isolated_runtime_native_host(state_dir: &tempfile::TempDir) -> std::process::Child {
    let home_dir = state_dir.path().join("home");
    spawn_isolated_runtime_native_host_at(state_dir.path(), &home_dir)
}

fn spawn_isolated_runtime_native_host_at(
    state_dir: &std::path::Path,
    home_dir: &std::path::Path,
) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_vaultkern-runtime"))
        .env("XDG_STATE_HOME", state_dir)
        .env("HOME", home_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runtime native host")
}

fn spawn_isolated_runtime_native_host_for_origin(
    state_dir: &std::path::Path,
    home_dir: &std::path::Path,
    origin: &str,
) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_vaultkern-runtime"))
        .arg(origin)
        .env("XDG_STATE_HOME", state_dir)
        .env("HOME", home_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runtime native host")
}

fn send_native_command(
    child: &mut std::process::Child,
    request: serde_json::Value,
) -> serde_json::Value {
    write_native_message(
        child.stdin.as_mut().expect("runtime stdin"),
        &serde_json::to_vec(&request).expect("encode request"),
    );
    read_native_message(child.stdout.as_mut().expect("runtime stdout"))
}

fn negotiate_browser_runtime(child: &mut std::process::Child) {
    let response = send_native_command(
        child,
        json!({
            "version": PROTOCOL_VERSION,
            "command": {
                "type": "handshake",
                "protocol_version": PROTOCOL_VERSION,
                "capabilities": ["runtime-core", "browser-extension"]
            }
        }),
    );
    assert_eq!(
        response.get("type").and_then(|value| value.as_str()),
        Some("handshake"),
        "unexpected browser-origin handshake response: {response}"
    );
}

fn write_native_message(writer: &mut impl Write, payload: &[u8]) {
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .expect("write native message length");
    writer
        .write_all(payload)
        .expect("write native message payload");
    writer.flush().expect("flush native message");
}

fn read_native_message(reader: &mut impl Read) -> serde_json::Value {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .expect("read native message length");
    let length = u32::from_le_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .expect("read native message payload");
    serde_json::from_slice(&payload).expect("decode native message response")
}
