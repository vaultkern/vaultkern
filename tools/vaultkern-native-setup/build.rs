use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=windows/app.manifest");
    println!("cargo:rerun-if-changed=windows/app.rc");
    println!("cargo:rerun-if-env-changed=VAULTKERN_RUNTIME_PAYLOAD_PATH");

    let payload_output =
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("vaultkern-runtime.exe");
    if let Some(payload_path) = env::var_os("VAULTKERN_RUNTIME_PAYLOAD_PATH") {
        let payload_path = PathBuf::from(payload_path);
        println!("cargo:rerun-if-changed={}", payload_path.display());
        fs::copy(&payload_path, &payload_output).unwrap_or_else(|error| {
            panic!(
                "failed to copy runtime payload from {} to {}: {error}",
                payload_path.display(),
                payload_output.display()
            )
        });
    } else {
        fs::write(&payload_output, []).unwrap_or_else(|error| {
            panic!(
                "failed to write empty runtime payload at {}: {error}",
                payload_output.display()
            )
        });
    }

    let target = env::var("TARGET").unwrap_or_default();
    if target != "x86_64-pc-windows-gnu" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let windows_dir = manifest_dir.join("windows");
    let output =
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("vaultkern-native-setup-res.o");
    let windres = env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".to_string());

    let status = Command::new(&windres)
        .current_dir(&windows_dir)
        .arg("--input")
        .arg("app.rc")
        .arg("--output-format")
        .arg("coff")
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("failed to run {windres}: {error}"));

    if !status.success() {
        panic!("failed to compile Windows resources with {windres}");
    }

    println!(
        "cargo:rustc-link-arg-bin=vaultkern-native-setup={}",
        output.display()
    );
}
