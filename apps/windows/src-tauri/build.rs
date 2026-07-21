#[cfg(windows)]
const APP_COMMANDS: &[&str] = &[
    "runtime_send",
    "load_desktop_settings",
    "save_desktop_settings",
    "queue_quick_unlock_enrollment",
];

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=tauri.conf.json");
        let mut native = cc::Build::new();
        native
            .cpp(true)
            .file("native/passkey_plugin.cpp")
            .include("native")
            .flag_if_supported("/std:c++20")
            .flag_if_supported("/EHsc");
        if std::env::var("PROFILE").as_deref() == Ok("debug") {
            native.define("VAULTKERN_PLUGIN_DIAGNOSTICS", None);
        }
        native.compile("vaultkern_passkey_plugin");
        println!("cargo:rerun-if-changed=native/passkey_plugin.cpp");
        println!("cargo:rerun-if-changed=native/passkey_plugin.h");
        tauri_build::try_build(
            tauri_build::Attributes::new()
                .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS)),
        )
        .expect("failed to build VaultKern's Tauri configuration");
    }
}
