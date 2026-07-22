#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
use serde::Deserialize;
#[cfg(windows)]
use serde_json::Value;
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use tauri::{Manager, State};
#[cfg(windows)]
use vaultkern_runtime::QuickUnlockReconciliationCredentials;
#[cfg(windows)]
use vaultkern_runtime::resident_ipc::start_windows_resident_ipc_server;
#[cfg(windows)]
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeResponse, SensitiveString};
#[cfg(windows)]
use vaultkern_windows::{
    DesktopSettingsStore, PasskeyPluginServer, RuntimeBridge, SettingsReconciliationRequest,
    launch_requests_visible_window,
};

#[cfg(windows)]
#[tauri::command]
async fn runtime_send(
    message: ProtocolEnvelope,
    bridge: State<'_, RuntimeBridge>,
) -> Result<RuntimeResponse, String> {
    let bridge = bridge.inner().clone();
    let response = match tauri::async_runtime::spawn_blocking(move || {
        bridge.request_envelope(message)
    })
    .await
    {
        Ok(response) => response,
        Err(error) => RuntimeResponse::Error(ErrorDto {
            code: "runtime_task_failed".into(),
            message: format!("runtime task failed: {error}"),
        }),
    };
    Ok(response)
}

#[cfg(windows)]
fn reconcile_desktop_settings(
    settings: &DesktopSettingsStore,
    bridge: &RuntimeBridge,
    passkey_plugin: &PasskeyPluginServer,
    request: SettingsReconciliationRequest,
) -> Result<(), String> {
    let SettingsReconciliationRequest {
        quick_unlock_credentials,
        quick_unlock_completion,
    } = request;
    let desired = match settings.desired_state() {
        Ok(desired) => desired,
        Err(error) => {
            drop(quick_unlock_credentials);
            let error = error.to_string();
            if let Some(completion) = quick_unlock_completion {
                let _ = completion.send(Err(error.clone()));
            }
            return Err(error);
        }
    };
    let vault_unlocked = bridge.platform_passkey_is_unlocked();
    let mut failures = Vec::new();

    let quick_unlock_result = bridge
        .reconcile_quick_unlock(desired.quick_unlock_enabled, quick_unlock_credentials)
        .map(|_| ());
    if let Err(error) = &quick_unlock_result {
        failures.push(error.clone());
    }
    if let Some(completion) = quick_unlock_completion {
        let _ = completion.send(quick_unlock_result);
    }

    match passkey_plugin.reconcile_settings(desired.passkey_provider_enabled, vault_unlocked) {
        Ok(true) | Ok(false) if !desired.passkey_provider_enabled => {}
        Ok(true) => {}
        Ok(false) => failures
            .push("passkey provider is registered but disabled in Windows Settings".to_owned()),
        Err(error) => failures.push(error),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(windows)]
#[tauri::command]
fn load_desktop_settings(settings: State<'_, Arc<DesktopSettingsStore>>) -> Result<Value, String> {
    settings.load().map_err(|error| error.to_string())
}

#[cfg(windows)]
#[tauri::command]
fn save_desktop_settings(
    desired: Value,
    settings: State<'_, Arc<DesktopSettingsStore>>,
    bridge: State<'_, RuntimeBridge>,
) -> Result<(), String> {
    settings.save(&desired).map_err(|error| error.to_string())?;
    bridge.schedule_reconciliation();
    Ok(())
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuickUnlockEnrollmentCredentialsDto {
    #[serde(default)]
    password: Option<SensitiveString>,
    #[serde(default)]
    key_file_path: Option<String>,
}

#[cfg(windows)]
#[tauri::command]
fn queue_quick_unlock_enrollment(
    credentials: QuickUnlockEnrollmentCredentialsDto,
    bridge: State<'_, RuntimeBridge>,
) -> Result<(), String> {
    bridge.queue_quick_unlock_enrollment(QuickUnlockReconciliationCredentials::from_protocol_input(
        credentials.password,
        credentials.key_file_path,
    ))
}

#[cfg(windows)]
fn main() {
    vaultkern_runtime::install_redacted_panic_hook();
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
            configure_main_window_parent(app.handle(), &window_bridge)
                .map_err(std::io::Error::other)?;
            let settings_path = app
                .path()
                .app_data_dir()
                .map_err(std::io::Error::other)?
                .join("desktop-settings.json");
            let settings = Arc::new(DesktopSettingsStore::new(settings_path));
            let plugin = Arc::new(PasskeyPluginServer::start(plugin_bridge.clone()));
            if let Some(error) = plugin.start_error() {
                eprintln!("passkey COM server unavailable: {error}");
            }
            let (reconciliation, reconciliation_requests) = std::sync::mpsc::sync_channel(1);
            plugin_bridge
                .set_reconciliation_notifier(reconciliation)
                .map_err(std::io::Error::other)?;
            let reconciliation_settings = Arc::clone(&settings);
            let reconciliation_plugin = Arc::clone(&plugin);
            let reconciliation_bridge = plugin_bridge.clone();
            std::thread::Builder::new()
                .name("vaultkern-settings-reconciliation".to_owned())
                .spawn(move || {
                    while let Ok(request) = reconciliation_requests.recv() {
                        if let Err(error) = reconcile_desktop_settings(
                            &reconciliation_settings,
                            &reconciliation_bridge,
                            &reconciliation_plugin,
                            request,
                        ) {
                            eprintln!("post-commit settings reconciliation failed: {error}");
                        }
                    }
                })
                .map_err(std::io::Error::other)?;
            plugin_bridge.schedule_reconciliation();

            let ipc_bridge = plugin_bridge.clone();
            let ipc_handler = Arc::new(
                move |message, cancelled, execution_started, parent_window| {
                    ipc_bridge.request_browser_cancellable(
                        message,
                        cancelled,
                        execution_started,
                        parent_window,
                    )
                },
            );
            let ipc_server =
                start_windows_resident_ipc_server(ipc_handler).map_err(std::io::Error::other)?;

            app.manage(settings);
            app.manage(plugin);
            app.manage(ipc_server);
            if show_window_on_start {
                show_main_window(app.handle(), &window_bridge).map_err(std::io::Error::other)?;
            }
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
        .invoke_handler(tauri::generate_handler![
            runtime_send,
            load_desktop_settings,
            save_desktop_settings,
            queue_quick_unlock_enrollment
        ])
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
    configure_main_window_parent(app, bridge)
}

#[cfg(windows)]
fn configure_main_window_parent(
    app: &tauri::AppHandle,
    bridge: &RuntimeBridge,
) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "VaultKern main window is unavailable".to_owned())?;
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
