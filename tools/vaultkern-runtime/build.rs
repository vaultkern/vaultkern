use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let source = Path::new("macos/SecureEnclaveBridge.swift");
    println!("cargo:rerun-if-changed={}", source.display());
    let swiftc = xcrun(&["--find", "swiftc"], "Swift compiler");
    let macos_sdk = xcrun(&["--sdk", "macosx", "--show-sdk-path"], "macOS SDK");
    require_path(&swiftc, "selected Swift compiler");
    require_path(&macos_sdk, "selected macOS SDK");
    let swift_toolchain_usr = swiftc
        .parent()
        .and_then(Path::parent)
        .expect("selected Swift compiler is not under a toolchain usr/bin directory");
    let toolchain_swift_libraries = swift_toolchain_usr.join("lib/swift/macosx");
    let sdk_swift_libraries = macos_sdk.join("usr/lib/swift");

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

    let output = Command::new(&swiftc)
        .args(["-target", swift_target, "-sdk"])
        .arg(&macos_sdk)
        .args([
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
        .expect("failed to invoke selected swiftc");
    if !output.status.success() {
        panic!(
            "Swift bridge compilation failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+bundle=vaultkern_macos_bridge");
    println!(
        "cargo:rustc-link-search=native={}",
        sdk_swift_libraries.display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        toolchain_swift_libraries.display()
    );
    println!(
        "cargo:rustc-link-search=framework={}",
        macos_sdk.join("System/Library/Frameworks").display()
    );
    for framework in ["Foundation", "CryptoKit", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-arg=-mmacosx-version-min=13.0");
}

fn xcrun(arguments: &[&str], label: &str) -> PathBuf {
    let output = Command::new("/usr/bin/xcrun")
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("failed to invoke xcrun for {label}: {error}"));
    if !output.status.success() {
        panic!(
            "xcrun failed to resolve {label} ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let path = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("xcrun returned a non-UTF-8 path for {label}: {error}"));
    let path = path.trim();
    assert!(!path.is_empty(), "xcrun returned an empty path for {label}");
    PathBuf::from(path)
}

fn require_path(path: &Path, label: &str) {
    assert!(path.exists(), "{label} was not found at {}", path.display());
}
