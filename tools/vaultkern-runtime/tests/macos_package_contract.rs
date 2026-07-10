#![cfg(target_os = "macos")]

use serde_json::Value;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const HOST_NAME: &str = "com.vaultkern.runtime";
const EXTENSION_ID: &str = "test-extension-id";

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}

fn host_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-apple-darwin",
        "x86_64" => "x86_64-apple-darwin",
        arch => panic!("unsupported macOS test architecture: {arch}"),
    }
}

fn run_package(output_root: &Path, home: &Path, extra_args: &[&str]) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(script("package_macos.sh"))
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .args(["--prebuilt-binary", env!("CARGO_BIN_EXE_vaultkern-runtime")])
        .args(extra_args)
        .env("HOME", home);
    command.output().unwrap()
}

fn run_install(home: &Path, app: &Path) -> Output {
    Command::new("bash")
        .arg(script("install_native_host_macos.sh"))
        .arg(EXTENSION_ID)
        .arg(app)
        .env("HOME", home)
        .output()
        .unwrap()
}

fn assert_success(output: Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn plist_value(plist: &Path, key: &str) -> String {
    let output = Command::new("plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .unwrap();
    assert_success(output.clone(), &format!("read plist key {key}"));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn packages_signed_app_and_installs_chrome_native_host() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    assert_success(run_package(&output_root, &home, &[]), "package macOS app");

    let app = output_root.join(host_target()).join("VaultKern Native.app");
    let plist = app.join("Contents/Info.plist");
    let bundled_executable = app.join("Contents/MacOS/vaultkern-runtime");

    assert!(bundled_executable.is_file());
    assert_eq!(
        plist_value(&plist, "CFBundleIdentifier"),
        "com.vaultkern.runtime"
    );
    assert_eq!(
        plist_value(&plist, "CFBundleExecutable"),
        "vaultkern-runtime"
    );
    assert_eq!(plist_value(&plist, "CFBundlePackageType"), "APPL");
    assert_eq!(plist_value(&plist, "LSMinimumSystemVersion"), "13.0");

    let verify = Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&app)
        .output()
        .unwrap();
    assert_success(verify, "verify packaged app signature");

    let install = run_install(&home, &app);
    assert_success(install, "install macOS native host");

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    assert!(installed_executable.is_file());

    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(installed_manifest).unwrap()).unwrap();
    assert_eq!(manifest["name"], HOST_NAME);
    assert_eq!(
        manifest["path"],
        std::fs::canonicalize(&installed_executable)
            .unwrap()
            .to_str()
            .expect("temporary path is UTF-8")
    );
    assert_eq!(
        manifest["allowed_origins"],
        serde_json::json!(["chrome-extension://test-extension-id/"])
    );
}

#[test]
fn failed_bundle_copy_preserves_existing_installation_and_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    assert_success(run_package(&output_root, &home, &[]), "package macOS app");
    let app = output_root.join(host_target()).join("VaultKern Native.app");

    assert_success(
        run_install(&home, &app),
        "install initial macOS native host",
    );

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let fake_bin = temp.path().join("fake-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let fake_ditto = fake_bin.join("ditto");
    std::fs::write(&fake_ditto, "#!/bin/sh\nexit 23\n").unwrap();
    std::fs::set_permissions(&fake_ditto, std::fs::Permissions::from_mode(0o755)).unwrap();
    let inherited_path =
        std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    let mut search_paths = vec![fake_bin];
    search_paths.extend(std::env::split_paths(&inherited_path));

    let failed_install = Command::new("bash")
        .arg(script("install_native_host_macos.sh"))
        .arg(EXTENSION_ID)
        .arg(&app)
        .env("HOME", &home)
        .env("PATH", std::env::join_paths(search_paths).unwrap())
        .output()
        .unwrap();

    assert!(!failed_install.status.success());
    let verify = Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&installed_app)
        .output()
        .unwrap();
    assert_success(verify, "verify preserved app signature");
    assert_eq!(
        std::fs::read(installed_manifest).unwrap(),
        original_manifest
    );
}

#[test]
fn release_signing_rejects_empty_identity() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let output = Command::new("bash")
        .arg(script("package_macos.sh"))
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .args(["--prebuilt-binary", env!("CARGO_BIN_EXE_vaultkern-runtime")])
        .arg("--release-signing")
        .env("HOME", home)
        .env("VAULTKERN_CODESIGN_IDENTITY", "")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("VAULTKERN_CODESIGN_IDENTITY")
    );
}
