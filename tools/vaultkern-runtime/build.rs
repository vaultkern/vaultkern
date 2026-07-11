use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMAND_LINE_TOOLS: &str = "/Library/Developer/CommandLineTools";
const SWIFTC: &str = "/Library/Developer/CommandLineTools/usr/bin/swiftc";
const MACOS_SDK: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let source = Path::new("macos/SecureEnclaveBridge.swift");
    println!("cargo:rerun-if-changed={}", source.display());
    require_path(Path::new(SWIFTC), "Command Line Tools swiftc");
    require_path(Path::new(MACOS_SDK), "Command Line Tools macOS SDK");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("Cargo did not provide CARGO_CFG_TARGET_ARCH to build.rs");
    let swift_target = match target_arch.as_str() {
        "aarch64" => "arm64-apple-macosx13.0",
        "x86_64" => "x86_64-apple-macosx13.0",
        other => panic!("unsupported macOS architecture for Swift bridge: {other}"),
    };

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not provide OUT_DIR"));
    let module_cache = out_dir.join("swift-module-cache");
    std::fs::create_dir_all(&module_cache).expect("failed to create Swift module cache");
    let archive = out_dir.join("libvaultkern_macos_bridge.a");

    let output = Command::new(SWIFTC)
        .env("DEVELOPER_DIR", COMMAND_LINE_TOOLS)
        .args([
            "-target",
            swift_target,
            "-sdk",
            MACOS_SDK,
            "-parse-as-library",
            "-module-name",
            "VaultKernMacOSBridge",
            "-module-cache-path",
        ])
        .arg(&module_cache)
        .args([
            "-O",
            "-warnings-as-errors",
            "-whole-module-optimization",
            "-emit-library",
            "-static",
        ])
        .arg(source)
        .arg("-o")
        .arg(&archive)
        .output()
        .expect("failed to invoke Command Line Tools swiftc");
    if !output.status.success() {
        panic!(
            "Swift bridge compilation failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+bundle=vaultkern_macos_bridge");
    println!("cargo:rustc-link-search=native={MACOS_SDK}/usr/lib/swift");
    println!("cargo:rustc-link-search=native={COMMAND_LINE_TOOLS}/usr/lib/swift/macosx");
    println!("cargo:rustc-link-search=framework={MACOS_SDK}/System/Library/Frameworks");
    for framework in ["Foundation", "CryptoKit", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-arg=-mmacosx-version-min=13.0");
}

fn require_path(path: &Path, label: &str) {
    assert!(path.exists(), "{label} was not found at {}", path.display());
}
