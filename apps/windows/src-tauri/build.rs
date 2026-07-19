fn main() {
    #[cfg(windows)]
    {
        let mut native = cc::Build::new();
        native
            .cpp(true)
            .file("native/passkey_plugin.cpp")
            .include("native")
            .flag_if_supported("/std:c++20");
        if std::env::var("PROFILE").as_deref() == Ok("debug") {
            native.define("VAULTKERN_PLUGIN_DIAGNOSTICS", None);
        }
        native.compile("vaultkern_passkey_plugin");
        println!("cargo:rerun-if-changed=native/passkey_plugin.cpp");
        println!("cargo:rerun-if-changed=native/passkey_plugin.h");
        tauri_build::build();
    }
}
