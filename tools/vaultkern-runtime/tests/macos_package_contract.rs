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
const DEVELOPER_ID_NAME: &str = "Developer ID Application: VaultKern Test (TEAMID1234)";
const APPLE_DEVELOPMENT_NAME: &str = "Apple Development: VaultKern Test (TEAMID1234)";
const SELF_SIGNED_NAME: &str = "VaultKern Self Signed";
const SPOOFED_DEVELOPER_ID_HASH: &str = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
const SPOOFED_DEVELOPER_ID_NAME: &str = "Developer ID Application: VaultKern Spoof (SPOOFTEAM1)";

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

fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        arch => panic!("unsupported macOS test architecture: {arch}"),
    }
}

fn opposite_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "x86_64-apple-darwin",
        "x86_64" => "aarch64-apple-darwin",
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

fn prebuilt_with_build_version(temp: &TempDir, name: &str, platform: &str, minos: &str) -> PathBuf {
    let source = temp.path().join(format!("{name}-source"));
    let output = temp.path().join(name);
    std::fs::copy(env!("CARGO_BIN_EXE_vaultkern-runtime"), &source).unwrap();
    let edit = Command::new("vtool")
        .args(["-set-build-version", platform, minos, "13.0", "-replace"])
        .arg("-output")
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert_success(edit, "edit prebuilt binary build version");
    output
}

fn valid_prebuilt(temp: &TempDir) -> PathBuf {
    prebuilt_with_build_version(temp, "vaultkern-runtime-macos-13", "macos", "13.0")
}

fn run_package(
    output_root: &Path,
    home: &Path,
    prebuilt_binary: &Path,
    extra_args: &[&str],
) -> Output {
    let mut command = script_command("package_macos.sh");
    command
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(prebuilt_binary)
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

fn fake_signing_tools(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let fake_bin = temp.path().join("fake-signing-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let security_log = temp.path().join("security.log");
    let codesign_log = temp.path().join("codesign.log");
    let codesign_display_log = temp.path().join("codesign-display.log");
    let codesign_verify_log = temp.path().join("codesign-verify.log");

    write_executable(
        &fake_bin.join("security"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$VAULTKERN_TEST_SECURITY_LOG\"\ncat <<'EOF'\n  1) {DEVELOPER_ID_HASH} \"{DEVELOPER_ID_NAME}\"\n  2) 2222222222222222222222222222222222222222 \"{APPLE_DEVELOPMENT_NAME}\"\n  3) 3333333333333333333333333333333333333333 \"{SELF_SIGNED_NAME}\"\n  4) {SPOOFED_DEVELOPER_ID_HASH} \"{SPOOFED_DEVELOPER_ID_NAME}\"\n     4 valid identities found\nEOF\n"
        ),
    );
    write_executable(
        &fake_bin.join("codesign"),
        r#"#!/bin/sh
if [ "$1" = "--verify" ]; then
  : > "$VAULTKERN_TEST_CODESIGN_VERIFY_LOG"
  for argument in "$@"; do
    printf '%s\n' "$argument" >> "$VAULTKERN_TEST_CODESIGN_VERIFY_LOG"
  done
  if [ "${VAULTKERN_TEST_SIGNATURE_MODE:-valid}" = "spoofed" ]; then
    echo 'explicit Developer ID requirement failed' >&2
    exit 3
  fi
  exit 0
fi

if [ "$1" = "--display" ]; then
  printf 'call' >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  for argument in "$@"; do
    printf '\t%s' "$argument" >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  done
  printf '\n' >> "$VAULTKERN_TEST_CODESIGN_DISPLAY_LOG"
  if [ "$2" = "--verbose=4" ]; then
    if [ "${VAULTKERN_TEST_SIGNATURE_MODE:-valid}" = "spoofed" ]; then
      cat >&2 <<'EOF'
Executable=/tmp/VaultKern Native.app/Contents/MacOS/vaultkern-runtime
Identifier=com.vaultkern.runtime
CodeDirectory v=20500 size=512 flags=0x10000(runtime) hashes=8+2 location=embedded
Authority=Developer ID Application: VaultKern Spoof (SPOOFTEAM1)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jul 11, 2026 at 12:00:00
TeamIdentifier=SPOOFTEAM1
EOF
    else
      cat >&2 <<'EOF'
Executable=/tmp/VaultKern Native.app/Contents/MacOS/vaultkern-runtime
Identifier=com.vaultkern.runtime
CodeDirectory v=20500 size=512 flags=0x10000(runtime) hashes=8+2 location=embedded
Authority=Developer ID Application: VaultKern Test (TEAMID1234)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jul 11, 2026 at 12:00:00
TeamIdentifier=TEAMID1234
EOF
    fi
    exit 0
  fi
  if [ "$2" = "--requirements" ]; then
    echo 'designated => identifier "com.vaultkern.runtime" and anchor apple generic' >&2
    exit 0
  fi
  exit 64
fi

: > "$VAULTKERN_TEST_CODESIGN_LOG"
for argument in "$@"; do
  printf '%s\n' "$argument" >> "$VAULTKERN_TEST_CODESIGN_LOG"
  bundle="$argument"
done
exec /usr/bin/codesign --force --sign - "$bundle"
"#,
    );

    (
        fake_bin,
        security_log,
        codesign_log,
        codesign_display_log,
        codesign_verify_log,
    )
}

fn fake_installer_codesign(temp: &TempDir) -> PathBuf {
    let fake_bin = temp.path().join("fake-installer-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("codesign"),
        r#"#!/bin/sh
for argument in "$@"; do
  bundle="$argument"
done

if [ "$1" = "--verify" ]; then
  exit 0
fi

if [ "$bundle" = "$VAULTKERN_TEST_EXISTING_APP" ]; then
  team="$VAULTKERN_TEST_EXISTING_TEAM"
  requirement="$VAULTKERN_TEST_EXISTING_REQUIREMENT"
else
  team="$VAULTKERN_TEST_INCOMING_TEAM"
  requirement="$VAULTKERN_TEST_INCOMING_REQUIREMENT"
fi

if [ "$1" = "--display" ] && [ "$2" = "--verbose=4" ]; then
  printf '%s\n' 'Identifier=com.vaultkern.runtime' "TeamIdentifier=$team" >&2
  exit 0
fi

if [ "$1" = "--display" ] && [ "$2" = "--requirements" ]; then
  printf 'designated => %s\n' "$requirement" >&2
  exit 0
fi

exit 64
"#,
    );
    fake_bin
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
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );

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
fn package_rejects_prebuilt_for_the_opposite_architecture() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();

    let output = script_command("package_macos.sh")
        .arg(opposite_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .env("HOME", home)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "packaged the opposite architecture"
    );
    let expected = match host_architecture() {
        "arm64" => "expected thin x86_64 Mach-O",
        "x86_64" => "expected thin arm64 Mach-O",
        arch => panic!("unsupported test architecture: {arch}"),
    };
    assert!(String::from_utf8(output.stderr).unwrap().contains(expected));
}

#[test]
fn package_rejects_non_macho_prebuilt() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = temp.path().join("not-macho");
    write_executable(&prebuilt, "#!/bin/sh\nexit 0\n");
    std::fs::create_dir(&home).unwrap();

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .env("HOME", home)
        .output()
        .unwrap();

    assert!(!output.status.success(), "packaged a non-Mach-O file");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("not a thin Mach-O")
    );
}

#[test]
fn package_rejects_non_macos_platform_prebuilt() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = prebuilt_with_build_version(&temp, "ios-runtime", "ios", "13.0");
    std::fs::create_dir(&home).unwrap();

    let output = run_package(&output_root, &home, &prebuilt, &[]);

    assert!(!output.status.success(), "packaged a non-macOS Mach-O");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("expected macOS platform")
    );
}

#[test]
fn package_rejects_prebuilt_with_wrong_deployment_minimum() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let output_root = temp.path().join("packages");
    let prebuilt = prebuilt_with_build_version(&temp, "macos-12-runtime", "macos", "12.0");
    std::fs::create_dir(&home).unwrap();

    let output = run_package(&output_root, &home, &prebuilt, &[]);

    assert!(!output.status.success(), "packaged a macOS 12 binary");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("minimum macOS version must be exactly 13.0")
    );
}

#[test]
fn failed_bundle_copy_preserves_existing_installation_and_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
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
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
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
fn first_install_manifest_failure_removes_new_app_and_preserves_stale_manifest() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    let failing_app = temp.path().join("First Install Failure.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&failing_app)
            .output()
            .unwrap(),
        "copy first-install failure app",
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
        "sign first-install failure app",
    );

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    std::fs::create_dir_all(installed_manifest.parent().unwrap()).unwrap();
    let stale_manifest = b"stale manifest bytes";
    std::fs::write(&installed_manifest, stale_manifest).unwrap();

    let failed_install = run_install(&home, &failing_app);

    assert!(!failed_install.status.success());
    assert!(
        !installed_app.exists(),
        "failed first install left the new app"
    );
    assert_eq!(std::fs::read(installed_manifest).unwrap(), stale_manifest);
}

#[test]
fn adhoc_upgrade_warns_that_persisted_right_continuity_is_not_guaranteed() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    assert_success(run_install(&home, &app), "install initial ad-hoc app");

    let upgrade = run_install(&home, &app);

    assert_success(upgrade.clone(), "upgrade ad-hoc app");
    assert!(
        String::from_utf8(upgrade.stderr)
            .unwrap()
            .contains("persisted Quick Unlock continuity is not guaranteed")
    );
}

#[test]
fn installer_rejects_team_or_designated_requirement_drift_and_preserves_installation() {
    let temp = TempDir::new().unwrap();
    let output_root = temp.path().join("packages");
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    assert_success(
        run_package(&output_root, &home, &prebuilt, &[]),
        "package macOS app",
    );
    let app = output_root.join(host_target()).join("VaultKern Native.app");
    assert_success(run_install(&home, &app), "install initial app");

    let installed_app = home
        .join("Library/Application Support/VaultKern")
        .join("VaultKern Native.app");
    let installed_app_canonical = std::fs::canonicalize(&installed_app).unwrap();
    let installed_executable = installed_app.join("Contents/MacOS/vaultkern-runtime");
    let installed_manifest = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let original_executable = std::fs::read(&installed_executable).unwrap();
    let original_manifest = std::fs::read(&installed_manifest).unwrap();

    let incoming_app = temp.path().join("Incoming.app");
    assert_success(
        Command::new("ditto")
            .arg(&app)
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "copy incoming app",
    );
    let incoming_marker = incoming_app.join("Contents/Resources/incoming-marker");
    std::fs::create_dir_all(incoming_marker.parent().unwrap()).unwrap();
    std::fs::write(&incoming_marker, b"continuity-drift-fixture").unwrap();
    assert_success(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&incoming_app)
            .output()
            .unwrap(),
        "re-sign incoming app",
    );

    let fake_bin = fake_installer_codesign(&temp);
    let stable_requirement = "identifier com.vaultkern.runtime and anchor apple generic";
    for (case, incoming_team, incoming_requirement, expected_error) in [
        (
            "ad-hoc",
            "not set",
            stable_requirement,
            "TeamIdentifier drift",
        ),
        (
            "team",
            "OTHERTEAM1",
            stable_requirement,
            "TeamIdentifier drift",
        ),
        (
            "requirement",
            "TEAMID1234",
            "identifier com.vaultkern.runtime and anchor apple generic and false",
            "designated requirement drift",
        ),
    ] {
        let rejected = script_command("install_native_host_macos.sh")
            .arg(EXTENSION_ID)
            .arg(&incoming_app)
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_TEST_EXISTING_APP", &installed_app_canonical)
            .env("VAULTKERN_TEST_EXISTING_TEAM", "TEAMID1234")
            .env("VAULTKERN_TEST_INCOMING_TEAM", incoming_team)
            .env("VAULTKERN_TEST_EXISTING_REQUIREMENT", stable_requirement)
            .env("VAULTKERN_TEST_INCOMING_REQUIREMENT", incoming_requirement)
            .output()
            .unwrap();

        assert!(!rejected.status.success(), "accepted {case} drift");
        assert!(
            String::from_utf8(rejected.stderr)
                .unwrap()
                .contains(expected_error)
        );
        assert_eq!(
            std::fs::read(&installed_executable).unwrap(),
            original_executable,
            "{case} drift replaced the existing app"
        );
        assert_eq!(
            std::fs::read(&installed_manifest).unwrap(),
            original_manifest,
            "{case} drift replaced the existing manifest"
        );
        assert!(
            !installed_app
                .join("Contents/Resources/incoming-marker")
                .exists(),
            "{case} drift installed the incoming bundle"
        );
    }
}

#[test]
fn release_signing_resolves_developer_id_name_and_sha1_hash() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, codesign_verify_log) =
        fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("name", DEVELOPER_ID_NAME.to_owned()),
        ("hash", DEVELOPER_ID_HASH.to_ascii_lowercase()),
    ] {
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .arg("--prebuilt-binary")
            .arg(&prebuilt)
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "TEAMID1234")
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
            .env("VAULTKERN_TEST_CODESIGN_VERIFY_LOG", &codesign_verify_log)
            .env("VAULTKERN_TEST_SIGNATURE_MODE", "valid")
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
        let display_calls = std::fs::read_to_string(&codesign_display_log).unwrap();
        assert!(display_calls.contains("call\t--display\t--verbose=4"));
        assert!(display_calls.contains("call\t--display\t--requirements\t-"));
        let verify_args = std::fs::read_to_string(&codesign_verify_log).unwrap();
        assert!(verify_args.lines().any(|line| line == "--verify"));
        assert!(verify_args.lines().any(|line| line == "--strict"));
        let explicit_requirement = verify_args
            .lines()
            .find(|line| line.starts_with("-R="))
            .expect("codesign verify must receive an explicit requirement");
        for required in [
            "identifier \"com.vaultkern.runtime\"",
            "anchor apple generic",
            "certificate 1[field.1.2.840.113635.100.6.2.6] exists",
            "certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
            "certificate leaf[subject.OU] = \"TEAMID1234\"",
        ] {
            assert!(explicit_requirement.contains(required));
        }
    }
}

#[test]
fn release_signing_requires_independent_expected_team_id() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", DEVELOPER_ID_NAME)
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID")
    );
    assert!(!codesign_log.exists());
}

#[test]
fn release_signing_rejects_selected_identity_from_unexpected_team() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", DEVELOPER_ID_NAME)
        .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "OTHERTEAM1")
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("does not match VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID")
    );
    assert!(!codesign_log.exists());
}

#[test]
fn release_signing_rejects_non_developer_id_identities() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, _) = fake_signing_tools(&temp);

    for (case, requested_identity) in [
        ("apple-development", APPLE_DEVELOPMENT_NAME),
        ("self-signed", SELF_SIGNED_NAME),
    ] {
        let _ = std::fs::remove_file(&codesign_log);
        let output_root = temp.path().join(format!("packages-{case}"));
        let output = script_command("package_macos.sh")
            .arg(host_target())
            .args(["--output-root", output_root.to_str().unwrap()])
            .arg("--prebuilt-binary")
            .arg(&prebuilt)
            .arg("--release-signing")
            .env("HOME", &home)
            .env("PATH", path_with_first(&fake_bin))
            .env("VAULTKERN_CODESIGN_IDENTITY", requested_identity)
            .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "TEAMID1234")
            .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
            .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
            .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
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
fn release_signing_rejects_spoofed_developer_id_after_signing() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let (fake_bin, security_log, codesign_log, codesign_display_log, codesign_verify_log) =
        fake_signing_tools(&temp);
    let output_root = temp.path().join("packages-spoofed");

    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", output_root.to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
        .arg("--release-signing")
        .env("HOME", &home)
        .env("PATH", path_with_first(&fake_bin))
        .env("VAULTKERN_CODESIGN_IDENTITY", SPOOFED_DEVELOPER_ID_NAME)
        .env("VAULTKERN_EXPECTED_DEVELOPER_TEAM_ID", "SPOOFTEAM1")
        .env("VAULTKERN_TEST_SECURITY_LOG", &security_log)
        .env("VAULTKERN_TEST_CODESIGN_LOG", &codesign_log)
        .env("VAULTKERN_TEST_CODESIGN_DISPLAY_LOG", &codesign_display_log)
        .env("VAULTKERN_TEST_CODESIGN_VERIFY_LOG", &codesign_verify_log)
        .env("VAULTKERN_TEST_SIGNATURE_MODE", "spoofed")
        .output()
        .unwrap();

    assert!(
        codesign_log.is_file(),
        "spoofed identity did not reach signing"
    );
    assert!(!output.status.success(), "accepted spoofed Developer ID");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("explicit Developer ID requirement")
    );
}

#[test]
fn release_signing_rejects_empty_identity() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let prebuilt = valid_prebuilt(&temp);
    std::fs::create_dir(&home).unwrap();
    let output = script_command("package_macos.sh")
        .arg(host_target())
        .args(["--output-root", temp.path().to_str().unwrap()])
        .arg("--prebuilt-binary")
        .arg(&prebuilt)
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
