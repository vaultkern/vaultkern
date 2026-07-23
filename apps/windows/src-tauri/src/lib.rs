mod desktop_settings;
#[cfg(any(windows, test))]
mod plugin_operation_state;
mod runtime_bridge;

pub use desktop_settings::{
    DesktopDesiredState, DesktopSettingsStore, DesktopSettingsStoreError,
    SettingsReconciliationStatus,
};
pub use runtime_bridge::{RuntimeBridge, SettingsReconciliationRequest};

pub fn launch_requests_visible_window(arguments: &[String]) -> bool {
    !arguments
        .iter()
        .any(|argument| argument == "-PluginActivated" || argument == "-BrowserActivated")
}

#[cfg(any(windows, test))]
pub(crate) fn plugin_callback_available(provider_enabled: bool, vault_unlocked: bool) -> bool {
    provider_enabled && vault_unlocked
}

#[cfg(test)]
mod tests {
    use super::{launch_requests_visible_window, plugin_callback_available};

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
        assert!(!launch_requests_visible_window(&[
            "vaultkern-windows.exe".into(),
            "-BrowserActivated".into(),
        ]));
    }

    #[test]
    fn closing_the_main_window_hides_it_without_terminating_the_resident_app() {
        let main_source = include_str!("main.rs");

        assert!(main_source.contains(".on_window_event("));
        assert!(main_source.contains("api.prevent_close()"));
        assert!(main_source.contains("window.hide()"));
        assert!(main_source.contains("queue_parent_window_handle(None)"));
        assert!(
            main_source.find("window.hide()").unwrap()
                < main_source
                    .find("queue_parent_window_handle(None)")
                    .unwrap()
        );
    }

    #[test]
    fn provider_callbacks_require_both_the_preference_and_an_unlocked_vault() {
        assert!(plugin_callback_available(true, true));
        assert!(!plugin_callback_available(false, true));
        assert!(!plugin_callback_available(true, false));
        assert!(!plugin_callback_available(false, false));
    }

    #[test]
    fn main_window_capability_explicitly_allows_only_the_resident_app_commands() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        let identifiers = permissions
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();

        for command in [
            "allow-runtime-send",
            "allow-load-desktop-settings",
            "allow-load-desktop-reconciliation-error",
            "allow-save-desktop-settings",
            "allow-queue-quick-unlock-enrollment",
        ] {
            assert!(
                identifiers.contains(&command),
                "main capability does not allow {command}"
            );
        }
        assert!(!identifiers.contains(&"allow-reconcile-settings"));

        let build = include_str!("../build.rs");
        assert!(build.contains("\"queue_quick_unlock_enrollment\""));
        assert!(build.contains("\"load_desktop_reconciliation_error\""));
        assert!(!build.contains("\"reconcile_settings\""));
    }

    #[test]
    fn native_reconciliation_converges_side_effects_without_republishing_desired_state() {
        let main = include_str!("main.rs");
        let reconciliation_start = main
            .find("fn reconcile_desktop_settings(")
            .expect("desktop reconciliation entry point");
        let reconciliation_end = main[reconciliation_start..]
            .find("#[tauri::command]")
            .map(|offset| reconciliation_start + offset)
            .expect("next command after reconciliation");
        let reconciliation = &main[reconciliation_start..reconciliation_end];

        assert!(
            reconciliation.contains("reconcile_quick_unlock"),
            "native reconciliation must converge unlock-blob presence before the WebView starts"
        );
        assert!(
            !reconciliation.contains("set_browser_integration_settings")
                && !reconciliation.contains("set_quick_unlock_enabled")
                && !reconciliation.contains("apply_desired_state"),
            "a stale reconciliation snapshot must never overwrite desired-state gates or projections"
        );
        assert!(
            reconciliation.find("reconcile_quick_unlock").unwrap()
                < reconciliation
                    .find("passkey_plugin.reconcile_settings")
                    .unwrap(),
            "one-shot unlock credentials must be consumed before slower provider metadata work"
        );
        let desired_state_failure = reconciliation
            .find("Err(error) =>")
            .expect("desired-state load failure branch");
        let failure = &reconciliation[desired_state_failure..];
        assert!(
            failure.find("drop(quick_unlock_credentials)").unwrap()
                < failure.find("completion.send(Err(error.clone()))").unwrap(),
            "settings-load failure must wipe the credential handoff before acknowledging unlock"
        );
    }

    #[test]
    fn runtime_transport_never_runs_credential_reconciliation_inline() {
        let main = include_str!("main.rs");
        let send_start = main.find("async fn runtime_send(").expect("runtime_send");
        let send_end = main[send_start..]
            .find("#[tauri::command]")
            .map(|offset| send_start + offset)
            .expect("next command after runtime_send");
        let runtime_send = &main[send_start..send_end];

        assert!(
            !runtime_send.contains("sync_credentials"),
            "durable command responses must not wait on OS metadata reconciliation"
        );
    }

    #[test]
    fn provider_callbacks_recheck_desired_state_after_runtime_work() {
        let source = include_str!("passkey_plugin.rs");
        for (start, end, runtime_call) in [
            (
                "extern \"system\" fn prepare_operation_callback(",
                "extern \"system\" fn make_credential_callback(",
                "context.bridge.prepare_platform_passkey_operation",
            ),
            (
                "extern \"system\" fn make_credential_callback(",
                "extern \"system\" fn commit_registration_callback(",
                "context.bridge.register_platform_passkey",
            ),
            (
                "extern \"system\" fn get_assertion_callback(",
                "fn callback_available(",
                "context.bridge.create_platform_passkey_assertion",
            ),
        ] {
            let start = source.find(start).expect("provider callback start");
            let end = source[start..]
                .find(end)
                .map(|offset| start + offset)
                .expect("provider callback end");
            let callback = &source[start..end];
            let runtime_call = callback.find(runtime_call).expect("runtime callback call");
            assert!(
                callback[runtime_call..].contains("provider_disabled_after_runtime_work"),
                "provider desired state must be checked again before releasing callback output"
            );
        }
    }

    #[test]
    fn successful_settings_commit_schedules_the_single_reconciliation_entry_point() {
        let main = include_str!("main.rs");
        let save_start = main
            .find("fn save_desktop_settings(")
            .expect("save_desktop_settings");
        let save_end = main[save_start..]
            .find("fn main()")
            .map(|offset| save_start + offset)
            .expect("save_desktop_settings end");
        let save = &main[save_start..save_end];

        assert!(
            save.find(".save_and_publish(&desired").unwrap()
                < save.find("bridge.schedule_reconciliation()").unwrap(),
            "desired state must commit before reconciliation is scheduled"
        );
        assert!(
            save.find(".save_and_publish(&desired").unwrap()
                < save.find("passkey_plugin.apply_desired_state").unwrap(),
            "the committed provider preference must close the callback gate immediately"
        );
        assert!(
            save.find("passkey_plugin.apply_desired_state").unwrap()
                < save.find("bridge.schedule_reconciliation()").unwrap(),
            "OS registration reconciliation must run only after the callback gate reflects desired state"
        );
        assert!(
            save.find("bridge.set_quick_unlock_enabled").unwrap()
                < save.find("bridge.schedule_reconciliation()").unwrap(),
            "the committed quick-unlock preference must close its runtime gate before reconciliation"
        );
    }

    #[test]
    fn browser_activation_shows_the_resident_window_and_forwards_only_a_fixed_route() {
        let main = include_str!("main.rs");

        assert!(main.contains("set_resident_activation_notifier"));
        assert!(main.contains("vaultkern-open-route"));
        let activation_loop = main
            .find("while let Ok(route) = resident_activation_requests.recv()")
            .expect("resident activation loop");
        let activation = &main[activation_loop..];
        assert!(
            activation.find("show_main_window").unwrap()
                < activation.find("vaultkern-open-route").unwrap(),
            "the window must be visible before its fixed route is delivered"
        );
    }
}

#[cfg(windows)]
mod passkey_plugin;
#[cfg(windows)]
pub use passkey_plugin::PasskeyPluginServer;
