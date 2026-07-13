use std::fs;

use vaultkern_runtime::Runtime;

#[test]
fn runtime_restores_current_vault_selection_from_persisted_store() {
    let dir = tempfile::tempdir().unwrap();
    let state_home = dir.path().join("state-home");
    let store_dir = state_home.join("vaultkern-runtime");
    let store_path = store_dir.join("vault-references.json");
    let current_vault_ref_id = "local-demo-vault";

    fs::create_dir_all(&store_dir).unwrap();
    fs::write(
        &store_path,
        format!(
            r#"{{
  "current_vault_ref_id": "{current_vault_ref_id}",
  "vaults": [
    {{
      "vault_ref_id": "{current_vault_ref_id}",
      "path": "/tmp/demo.kdbx",
      "display_name": "demo",
      "source_summary": "demo.kdbx",
      "last_used_at": 59
    }}
  ]
}}"#
        ),
    )
    .unwrap();

    let previous_state_home = std::env::var_os("XDG_STATE_HOME");
    let previous_local_app_data = std::env::var_os("LOCALAPPDATA");
    unsafe {
        std::env::set_var("XDG_STATE_HOME", &state_home);
        std::env::set_var("LOCALAPPDATA", &state_home);
    }

    let runtime = Runtime::new();

    match previous_state_home {
        Some(value) => unsafe {
            std::env::set_var("XDG_STATE_HOME", value);
        },
        None => unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        },
    }
    match previous_local_app_data {
        Some(value) => unsafe {
            std::env::set_var("LOCALAPPDATA", value);
        },
        None => unsafe {
            std::env::remove_var("LOCALAPPDATA");
        },
    }

    assert_eq!(
        runtime.session_state().current_vault_ref_id.as_deref(),
        Some(current_vault_ref_id)
    );
}
