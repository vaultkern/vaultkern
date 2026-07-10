#![cfg(target_os = "macos")]

use serde_json::Value;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const HOST_NAME: &str = "com.vaultkern.runtime";
const EXTENSION_ID: &str = "test-extension-id";
const DEVELOPER_ID_HASH: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
const DEVELOPER_ID_NAME: &str = "Developer ID Application: VaultKern Test (TEAMID)";
const APPLE_DEVELOPMENT_NAME: &str = "Apple Development: VaultKern Test (TEAMID)";
const SELF_SIGNED_NAME: &str = "VaultKern Self Signed";

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

fn script_command(name: &str) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(script(name))
        .env_remove("VAULTKERN_CODESIGN_IDENTITY")
        .env_remove("VAULTKERN_MACOS_APP_DESTINATION")
        .env_remove("VAULTKERN_CHROME_NATIVE_HOST_MANIFEST");
    command
}

fn run_package(output_root: &Path, home: &Path, extra_args: &[&str]) -> Output {
    let mut command = script_command("package_macos.sh");
    command
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .args(["--prebuilt-binary", env!("CARGO_BIN_EXE_vaultkern-runtime")])
        .args(extra_args)
        .env("HOME", home);
    command.output().unwrap()
}

fn run_install(home: &Path, app: &Path) -> Output {
    script_command("install_native_host_macos.sh")
        .arg(EXTENSION_ID)
        .arg(app)
        .env("HOME", home)
        .output()
        .unwrap()
}

fn path_with_first(first: &Path) -> OsString {
    let inherited_path =
        std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    let mut search_paths = vec![first.to_path_buf()];
    search_paths.extend(std::env::split_paths(&inherited_path));
    std::env::join_paths(search_paths).unwrap()
}

fn write_executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn fake_signing_tools(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let fake_bin = temp.path().join("fake-signing-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let security_log = temp.path().join("security.log");
    let codesign_log = temp.path().join("codesign.log");

    write_executable(
        &fake_bin.join("security"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VAULTKERN_TEST_SECURITY_LOG\"\ncat <<'EOF'\n  1) {DEVELOPER_ID_HASH} \"{DEVELOPER_ID_NAME}\"\n  2) 2222222222222222222222222222222222222222 \"{APPLE_DEVELOPMENT_NAME}\"\n  3) 3333333333333333333333333333333333333333 \"{SELF_SIGNED_NAME}\"\n     3 valid identities found\nEOF\n"
        ),
    );
    write_executable(
        &fake_bin.join("codesign"),
        "#!/bin/sh\n: > \"$VAULTKERN_TEST_CODESIGN_LOG\"\nfor argument in \"$@\"; do\n  printf '%s\\n' \"$argument\" >> \"$VAULTKERN_TEST_CODESIGN_LOG\"\n  bundle=\"$argument\"\ndone\nexec /usr/bin/codesign --force --sign - \"$bundle\"\n",
    );

    (fake_bin, security_log, codesign_log)
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
    let failed_install = script_command("install_native_host_macos.sh")
        .arg(EXTENSION_ID)
        .arg(&app)
        .env("HOME", &home)
        .env("PATH", path_with_first(&fake_bin))
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
fn failed_manifest_generation_restores_existing_installation_and_manifest() {
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
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_executable = std::fs::read(&installed_executable).unwrap();
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let failing_app = temp.path().join("Manifest Failure.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&failing_app)
            .output()
            .unwrap(),
        "copy manifest-failure app",
    );
    std::fs::copy(
        "/usr/bin/false",
        failing_app.join("Contents/MacOS/vaultkern-runtime"),
    )
    .unwrap();
    assert_success(
        Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&failing_app)
            .output()
            .unwrap(),
        "sign manifest-failure app",
    );

    let failed_install = run_install(&home, &failing_app);
    assert!(!failed_install.status.success());
    assert_eq!(
        std::fs::read(&installed_executable).unwrap(),
        original_executable
    );
    assert_eq!(
        std::fs::read(&installed_manifest).unwrap(),
        original_manifest
    );
    assert_success(
        Command::new("codesign")
            .args(["--verify", "--strict"])
            .arg(&installed_app)
            .output()
            .unwrap(),
        "verify restored app signature",
    );
}

#[test]
fn release_signing_resolves_developer_id_name_and_sha1_hash() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log) = fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("name", DEVELOPER_ID_NAME.to_owned()),
        ("hash", DEVELOPER_ID_HASH.to_ascii_lowercase()),
    ] {
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .args(["--prebuilt-binary", env!("CARGO_BIN_EXE_vaultkern-runtime")])
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .output()
            .unwrap();
        assert_success(output, &format!("release sign by {case}"));

        assert!(
            security_log.is_file(),
            "release signing must query security"
        );
        let security_args = std::fs::read_to_string(&security_log).unwrap();
        assert_eq!(security_args, "find-identity\n-v\n-p\ncodesigning\n");
        let codesign_args = std::fs::read_to_string(&codesign_log).unwrap();
        for required in ["--force", "--options", "runtime", "--timestamp", "--sign"] {
            assert!(codesign_args.lines().any(|line| line == required));
        }
        assert!(codesign_args.lines().any(|line| line == DEVELOPER_ID_HASH));
        assert!(!codesign_args.lines().any(|line| line == "--deep"));
    }
}

#[test]
fn release_signing_rejects_non_developer_id_identities() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log) = fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("apple-development", APPLE_DEVELOPMENT_NAME),
        ("self-signed", SELF_SIGNED_NAME),
    ] {
        let _ = std::fs::remove_file(&codesign_log);
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .args(["--prebuilt-binary", env!("CARGO_BIN_EXE_vaultkern-runtime")])
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .output()
            .unwrap();

        assert!(!output.status.success(), "accepted {case} identity");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Developer ID Application")
        );
        assert!(!codesign_log.exists(), "{case} identity reached codesign");
    }
}

#[test]
fn release_signing_rejects_empty_identity() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let output = script_command("package_macos.sh")
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
