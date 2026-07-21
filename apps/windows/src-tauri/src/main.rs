#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
use serde_json::{Value, json};
#[cfg(windows)]
use tauri::{Manager, State};
#[cfg(windows)]
use vaultkern_windows::{
    PasskeyPluginServer, RuntimeBridge, launch_requests_visible_window,
    should_refresh_platform_passkeys,
};

#[cfg(windows)]
#[tauri::command]
async fn runtime_send(
    message: Value,
    bridge: State<'_, RuntimeBridge>,
    passkey_plugin: State<'_, PasskeyPluginServer>,
) -> Result<Value, String> {
    let command_type = message
        .pointer("/command/type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let bridge = bridge.inner().clone();
    let response = match tauri::async_runtime::spawn_blocking(move || bridge.request(message)).await
    {
        Ok(response) => response,
        Err(error) => json!({
            "type": "error",
            "code": "runtime_task_failed",
            "message": format!("runtime task failed: {error}")
        }),
    };
    if should_refresh_platform_passkeys(command_type.as_deref(), &response) {
        if let Err(error) = passkey_plugin.sync_credentials() {
            eprintln!("passkey credential cache refresh failed: {error}");
        }
    }
    Ok(response)
}

#[cfg(windows)]
#[tauri::command]
fn reconcile_settings(
    enabled: bool,
    vault_unlocked: bool,
    passkey_plugin: State<'_, PasskeyPluginServer>,
) -> Result<bool, String> {
    passkey_plugin.reconcile_settings(enabled, vault_unlocked)
}

#[cfg(windows)]
fn main() {
    #[cfg(debug_assertions)]
    configure_webview_debugging();
    let bridge = RuntimeBridge::new();
    let plugin_bridge = bridge.clone();
    let window_bridge = bridge.clone();
    let forwarded_bridge = bridge.clone();
    let resident_bridge = bridge.clone();
    let show_window_on_start =
        launch_requests_visible_window(&std::env::args().collect::<Vec<_>>());
    tauri::Builder::default()
        .manage(bridge)
        .plugin(tauri_plugin_single_instance::init(
            move |app, arguments, _cwd| {
                if launch_requests_visible_window(&arguments) {
                    if let Err(error) = show_main_window(app, &forwarded_bridge) {
                        eprintln!("failed to activate the existing VaultKern window: {error}");
                    }
                }
            },
        ))
        .setup(move |app| {
            if show_window_on_start {
                show_main_window(app.handle(), &window_bridge).map_err(std::io::Error::other)?;
            }
            let plugin = PasskeyPluginServer::start(plugin_bridge.clone());
            if let Some(error) = plugin.start_error() {
                eprintln!("passkey COM server unavailable: {error}");
            }
            app.manage(plugin);
            Ok(())
        })
        .on_window_event(move |window, event| {
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if let Err(error) = window.hide() {
                    eprintln!("failed to hide the resident VaultKern window: {error}");
                }
                if let Err(error) = resident_bridge.queue_parent_window_handle(None) {
                    eprintln!("failed to queue clearing the Windows Hello parent window: {error}");
                }
            }
        })
        .invoke_handler(tauri::generate_handler![runtime_send, reconcile_settings])
        .run(tauri::generate_context!())
        .expect("failed to run VaultKern");
}

#[cfg(windows)]
fn show_main_window(app: &tauri::AppHandle, bridge: &RuntimeBridge) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "VaultKern main window is unavailable".to_owned())?;
    window.show().map_err(|error| error.to_string())?;
    window.unminimize().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())?;
    let parent_window = window
        .hwnd()
        .map_err(|error| format!("failed to resolve VaultKern main window handle: {error}"))?
        .0 as usize;
    bridge
        .set_parent_window_handle(Some(parent_window))
        .map_err(|error| format!("failed to configure Windows Hello parent window: {error}"))
}

#[cfg(all(windows, debug_assertions))]
fn configure_webview_debugging() {
    const PREFIX: &str = "--webview-debug-port=";
    let Some(port) = std::env::args()
        .find_map(|argument| argument.strip_prefix(PREFIX).map(str::to_owned))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
    else {
        return;
    };
    unsafe {
        std::env::set_var(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            format!("--remote-debugging-port={port}"),
        );
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vaultkern-windows is available on Windows only");
}
