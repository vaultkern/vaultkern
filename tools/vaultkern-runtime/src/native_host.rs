use serde::Serialize;

#[derive(Serialize)]
struct NativeHostManifest<'a> {
    name: &'static str,
    description: &'static str,
    path: &'a str,
    #[serde(rename = "type")]
    type_field: &'static str,
    allowed_origins: [&'a str; 1],
}

pub fn render_manifest(binary_path: &str, extension_origin: &str) -> String {
    let manifest = NativeHostManifest {
        name: "com.vaultkern.runtime",
        description: if cfg!(windows) {
            "VaultKern resident app IPC shim"
        } else {
            "VaultKern runtime native host"
        },
        path: binary_path,
        type_field: "stdio",
        allowed_origins: [extension_origin],
    };
    serde_json::to_string(&manifest).expect("native host manifest serialization is infallible")
}
