#[cfg(any(windows, test))]
mod plugin_operation_state;
mod runtime_bridge;

pub use runtime_bridge::RuntimeBridge;

pub fn launch_requests_visible_window(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| argument == "-PluginActivated")
}

#[cfg(any(windows, test))]
pub(crate) fn plugin_callback_available(provider_enabled: bool, vault_unlocked: bool) -> bool {
    provider_enabled && vault_unlocked
}

pub fn should_refresh_platform_passkeys(
    command_type: Option<&str>,
    response: &serde_json::Value,
) -> bool {
    let command_may_change_credentials = matches!(
        command_type,
        Some(
            "add_local_vault_reference"
                | "add_onedrive_vault_reference"
                | "open_local_vault"
                | "set_current_vault"
                | "delete_vault_reference"
                | "unlock_current_vault_with_password"
                | "unlock_current_vault"
                | "unlock_current_vault_with_quick_unlock"
                | "unlock_with_password"
                | "unlock_vault"
                | "lock_session"
                | "retry_vault_source_sync"
                | "set_entry_passkey"
                | "clear_entry_passkey"
                | "save_passkey_registration"
                | "abort_passkey_registration"
                | "commit_passkey_registration"
                | "delete_entry"
                | "save_vault"
        )
    );
    let response_type = response.get("type").and_then(serde_json::Value::as_str);
    if response_type == Some("error") {
        return response.get("code").and_then(serde_json::Value::as_str)
            == Some("request_cancelled")
            && command_may_change_credentials;
    }
    if response_type == Some("session_state") {
        return true;
    }

    command_may_change_credentials
}

#[cfg(test)]
mod tests {
    use super::{
        launch_requests_visible_window, plugin_callback_available, should_refresh_platform_passkeys,
    };
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
        assert!(should_refresh_platform_passkeys(
            Some("lock_session"),
            &json!({ "type": "session_state", "unlocked": false })
        ));
        assert!(should_refresh_platform_passkeys(
            Some("delete_vault_reference"),
            &json!({ "type": "vault_reference_list", "vaults": [] })
        ));
        assert!(should_refresh_platform_passkeys(
            Some("add_local_vault_reference"),
            &json!({ "type": "vault_reference" })
        ));
        assert!(!should_refresh_platform_passkeys(
            Some("set_entry_passkey"),
            &json!({ "type": "error" })
        ));
    }

    #[test]
    fn cancelled_state_changes_reconcile_the_passkey_cache_after_runtime_completion() {
        for command in ["lock_session", "set_entry_passkey"] {
            assert!(should_refresh_platform_passkeys(
                Some(command),
                &json!({
                    "type": "error",
                    "code": "request_cancelled",
                    "message": "the runtime request was cancelled"
                })
            ));
        }

        assert!(!should_refresh_platform_passkeys(
            Some("set_entry_passkey"),
            &json!({ "type": "error", "code": "runtime_error" })
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

    #[test]
    fn provider_callbacks_require_both_the_preference_and_an_unlocked_vault() {
        assert!(plugin_callback_available(true, true));
        assert!(!plugin_callback_available(false, true));
        assert!(!plugin_callback_available(true, false));
        assert!(!plugin_callback_available(false, false));
    }
}

#[cfg(windows)]
mod passkey_plugin;
#[cfg(windows)]
pub use passkey_plugin::{PasskeyPluginHandle, PasskeyPluginServer};
