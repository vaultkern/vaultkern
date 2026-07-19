#[cfg(windows)]
use serde_json::{Value, json};
#[cfg(windows)]
use tauri::{Manager, State};
#[cfg(windows)]
use vaultkern_windows::{PasskeyPluginServer, RuntimeBridge};

#[cfg(windows)]
#[tauri::command]
async fn runtime_send(
    message: Value,
    bridge: State<'_, RuntimeBridge>,
    passkey_plugin: State<'_, PasskeyPluginServer>,
) -> Result<Value, String> {
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
    if response.get("type").and_then(Value::as_str) == Some("session_state")
        && response.get("unlocked").and_then(Value::as_bool) == Some(true)
    {
        if let Err(error) = passkey_plugin.sync_credentials() {
            eprintln!("passkey credential cache refresh failed: {error}");
        }
    }
    Ok(response)
}

#[cfg(windows)]
fn main() {
    #[cfg(debug_assertions)]
    configure_webview_debugging();
    let bridge = RuntimeBridge::new();
    let plugin_bridge = bridge.clone();
    let plugin_activated = std::env::args_os().any(|argument| argument == "-PluginActivated");
    tauri::Builder::default()
        .manage(bridge)
        .setup(move |app| {
            let plugin = PasskeyPluginServer::start(plugin_bridge.clone());
            if let Some(error) = plugin.start_error() {
                eprintln!("passkey COM server unavailable: {error}");
            } else {
                match plugin.ensure_registered() {
                    Ok(true) => {}
                    Ok(false) => eprintln!("passkey provider is registered but disabled"),
                    Err(error) => eprintln!("passkey provider registration failed: {error}"),
                }
            }
            app.manage(plugin);
            if plugin_activated {
                if let Some(window) = app.get_webview_window("main") {
                    if let Err(error) = window.hide() {
                        eprintln!("failed to hide plugin activation window: {error}");
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![runtime_send])
        .run(tauri::generate_context!())
        .expect("failed to run VaultKern");
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
