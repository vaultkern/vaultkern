#[cfg(any(windows, test))]
mod plugin_operation_state;
mod runtime_bridge;

pub use runtime_bridge::RuntimeBridge;

pub fn launch_requests_visible_window(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| argument == "-PluginActivated")
}

pub fn should_refresh_platform_passkeys(
    command_type: Option<&str>,
    response: &serde_json::Value,
) -> bool {
    let response_type = response.get("type").and_then(serde_json::Value::as_str);
    if response_type == Some("error") {
        return false;
    }
    if response_type == Some("session_state")
        && response
            .get("unlocked")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    {
        return true;
    }

    matches!(
        command_type,
        Some(
            "retry_vault_source_sync"
                | "set_entry_passkey"
                | "clear_entry_passkey"
                | "save_passkey_registration"
                | "abort_passkey_registration"
                | "commit_passkey_registration"
                | "delete_entry"
                | "save_vault"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::{launch_requests_visible_window, should_refresh_platform_passkeys};
    use serde_json::json;

    #[test]
    fn passkey_cache_refreshes_after_unlock_and_passkey_metadata_mutations() {
        assert!(!should_refresh_platform_passkeys(
            Some("get_entry_detail"),
            &json!({ "type": "entry_detail" })
        ));
        assert!(should_refresh_platform_passkeys(
            Some("set_entry_passkey"),
            &json!({ "type": "entry_detail" })
        ));
        assert!(should_refresh_platform_passkeys(
            Some("retry_vault_source_sync"),
            &json!({ "type": "vault_source_status" })
        ));
        assert!(should_refresh_platform_passkeys(
            Some("get_entry_detail"),
            &json!({ "type": "session_state", "unlocked": true })
        ));
        assert!(!should_refresh_platform_passkeys(
            Some("set_entry_passkey"),
            &json!({ "type": "error" })
        ));
    }

    #[test]
    fn only_com_plugin_activation_starts_with_the_main_window_hidden() {
        assert!(!launch_requests_visible_window(&[
            "vaultkern-windows.exe".into(),
            "-PluginActivated".into(),
        ]));
        assert!(launch_requests_visible_window(&[
            "vaultkern-windows.exe".into(),
        ]));
        assert!(launch_requests_visible_window(&[
            "vaultkern-windows.exe".into(),
            "--webview-debug-port=9222".into(),
        ]));
    }
}

#[cfg(windows)]
mod passkey_plugin;
#[cfg(windows)]
pub use passkey_plugin::PasskeyPluginServer;
