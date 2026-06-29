use std::io::{Read, Write};
use std::process::{Command, Stdio};

use serde_json::json;
use vaultkern_core::{CompositeKey, KeepassCore, SaveProfile, Vault};

#[test]
fn runtime_binary_serves_native_messaging_session_state_frame() {
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let mut child = spawn_isolated_runtime_native_host(&state_dir);

    let request = json!({
        "version": 1,
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
fn runtime_binary_serves_browser_v0_native_messaging_loop() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("native-bridge"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create native bridge vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("native-bridge.kdbx");
    std::fs::write(&path, bytes).expect("write native bridge vault");
    let state_dir = dir.path().join("runtime-state");
    let home_dir = dir.path().join("runtime-home");

    let mut child = spawn_isolated_runtime_native_host_at(&state_dir, &home_dir);

    let open = send_native_command(
        &mut child,
        json!({
            "version": 1,
            "command": {
                "type": "open_local_vault",
                "path": path.to_str().expect("utf8 path")
            }
        }),
    );
    assert_eq!(
        open.get("type").and_then(|value| value.as_str()),
        Some("vault_opened")
    );
    let vault_id = open
        .get("vaultId")
        .and_then(|value| value.as_str())
        .expect("vault id")
        .to_owned();

    let unlock = send_native_command(
        &mut child,
        json!({
            "version": 1,
            "command": {
                "type": "unlock_with_password",
                "vault_id": vault_id,
                "password": "demo-password"
            }
        }),
    );
    assert_eq!(
        unlock.get("type").and_then(|value| value.as_str()),
        Some("session_state")
    );
    assert_eq!(
        unlock.get("unlocked").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        unlock.get("activeVaultId").and_then(|value| value.as_str()),
        Some(vault_id.as_str())
    );

    let groups = send_native_command(
        &mut child,
        json!({
            "version": 1,
            "command": {
                "type": "list_groups",
                "vault_id": vault_id
            }
        }),
    );
    assert_eq!(
        groups.get("type").and_then(|value| value.as_str()),
        Some("group_tree")
    );
    let root_id = groups
        .get("root")
        .and_then(|root| root.get("id"))
        .and_then(|value| value.as_str())
        .expect("root id")
        .to_owned();

    let created = send_native_command(
        &mut child,
        json!({
            "version": 1,
            "command": {
                "type": "create_entry",
                "vault_id": vault_id,
                "parent_group_id": root_id,
                "title": "Native Login",
                "username": "alice",
                "password": "secret",
                "url": "https://app.example.com/login",
                "notes": "native messaging contract",
                "totp_uri": null
            }
        }),
    );
    assert_eq!(
        created.get("type").and_then(|value| value.as_str()),
        Some("entry_detail")
    );
    let entry_id = created
        .get("id")
        .and_then(|value| value.as_str())
        .expect("entry id")
        .to_owned();

    let candidates = send_native_command(
        &mut child,
        json!({
            "version": 1,
            "command": {
                "type": "find_fill_candidates",
                "vault_id": vault_id,
                "url": "https://app.example.com/login?next=%2Fdashboard"
            }
        }),
    );
    child.kill().ok();
    child.wait().ok();

    assert_eq!(
        candidates.get("type").and_then(|value| value.as_str()),
        Some("fill_candidates")
    );
    let entries = candidates
        .get("entries")
        .and_then(|value| value.as_array())
        .expect("candidate entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("id").and_then(|value| value.as_str()),
        Some(entry_id.as_str())
    );
    assert_eq!(
        entries[0].get("title").and_then(|value| value.as_str()),
        Some("Native Login")
    );

    let store_path = state_dir
        .join("vaultkern-runtime")
        .join("vault-references.json");
    let store = std::fs::read_to_string(store_path).expect("isolated vault reference store");
    assert!(store.contains("native-bridge.kdbx"));
}

#[test]
fn browser_origin_native_hosts_do_not_share_recent_vaults() {
    let core = KeepassCore::new();
    let mut key = CompositeKey::default();
    key.add_password("demo-password");
    let bytes = core
        .save_kdbx(
            &Vault::empty("origin-isolation"),
            &key,
            SaveProfile::recommended(),
        )
        .expect("create origin isolation vault");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("origin-isolation.kdbx");
    std::fs::write(&path, bytes).expect("write origin isolation vault");
    let state_dir = dir.path().join("runtime-state");
    let home_dir = dir.path().join("runtime-home");
    let first_origin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";
    let second_origin = "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/";

    let mut first =
        spawn_isolated_runtime_native_host_for_origin(&state_dir, &home_dir, first_origin);
    let opened = send_native_command(
        &mut first,
        json!({
            "version": 1,
            "command": {
                "type": "open_local_vault",
                "path": path.to_str().expect("utf8 path")
            }
        }),
    );
    first.kill().ok();
    first.wait().ok();
    assert_eq!(
        opened.get("type").and_then(|value| value.as_str()),
        Some("vault_opened")
    );

    let mut second =
        spawn_isolated_runtime_native_host_for_origin(&state_dir, &home_dir, second_origin);
    let second_recent = send_native_command(
        &mut second,
        json!({
            "version": 1,
            "command": {
                "type": "list_recent_vaults"
            }
        }),
    );
    second.kill().ok();
    second.wait().ok();

    assert_eq!(
        second_recent.get("type").and_then(|value| value.as_str()),
        Some("vault_reference_list")
    );
    assert_eq!(
        second_recent
            .get("vaults")
            .and_then(|value| value.as_array())
            .map(Vec::len),
        Some(0)
    );

    let mut first_again =
        spawn_isolated_runtime_native_host_for_origin(&state_dir, &home_dir, first_origin);
    let first_recent = send_native_command(
        &mut first_again,
        json!({
            "version": 1,
            "command": {
                "type": "list_recent_vaults"
            }
        }),
    );
    first_again.kill().ok();
    first_again.wait().ok();

    assert_eq!(
        first_recent
            .get("vaults")
            .and_then(|value| value.as_array())
            .map(Vec::len),
        Some(1)
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
