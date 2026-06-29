use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const HOST_NAME: &str = "com.vaultkern.runtime";
const RUNTIME_DIR_NAME: &str = "vaultkern-runtime";
const RUNTIME_FILE_NAME: &str = "vaultkern-runtime.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Edge,
}

impl BrowserKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
        }
    }

    pub fn registry_key(self) -> &'static str {
        match self {
            Self::Chrome => {
                r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime"
            }
            Self::Edge => {
                r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultkern.runtime"
            }
        }
    }

    fn manifest_filename(self) -> &'static str {
        match self {
            Self::Chrome => "com.vaultkern.runtime.chrome.json",
            Self::Edge => "com.vaultkern.runtime.edge.json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSetupConfig {
    browser: BrowserKind,
    extension_id: String,
    runtime_path: PathBuf,
    local_app_data: PathBuf,
}

impl BrowserSetupConfig {
    pub fn new(
        browser: BrowserKind,
        extension_id: impl Into<String>,
        runtime_path: PathBuf,
        local_app_data: PathBuf,
    ) -> Self {
        Self {
            browser,
            extension_id: extension_id.into(),
            runtime_path,
            local_app_data,
        }
    }

    pub fn browser(&self) -> BrowserKind {
        self.browser
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    pub fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    pub fn registry_key(&self) -> &'static str {
        self.browser.registry_key()
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.local_app_data
            .join(RUNTIME_DIR_NAME)
            .join(self.browser.manifest_filename())
    }

    pub fn extension_origin(&self) -> String {
        format!("chrome-extension://{}/", self.extension_id)
    }

    pub fn expected_manifest(&self) -> String {
        render_native_host_manifest(
            &self.runtime_path.to_string_lossy(),
            &self.extension_origin(),
        )
    }

    pub fn diagnose(&self, probe: BrowserRegistrationProbe) -> RegistrationStatus {
        if !probe.browser_installed {
            return RegistrationStatus::BrowserMissing;
        }

        if let Some(content) = probe.manifest_content.as_deref() {
            let extension_origin = self.extension_origin_for_validation();
            if native_host_manifest_is_usable(content, extension_origin.as_deref())
                && probe.registered_runtime_exists != Some(false)
            {
                return RegistrationStatus::Registered;
            }
        }

        if probe.registry_manifest_path.is_none() {
            if probe.setup_runtime_exists {
                return RegistrationStatus::NotRegistered;
            }
            return RegistrationStatus::RuntimeMissing;
        }

        if !probe.setup_runtime_exists {
            return RegistrationStatus::RuntimeMissing;
        }

        RegistrationStatus::NeedsRepair
    }

    fn extension_origin_for_validation(&self) -> Option<String> {
        if self.extension_id.trim().is_empty() {
            None
        } else {
            Some(self.extension_origin())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRegistrationProbe {
    pub browser_installed: bool,
    pub registry_manifest_path: Option<PathBuf>,
    pub manifest_content: Option<String>,
    pub registered_runtime_exists: Option<bool>,
    pub setup_runtime_exists: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStatus {
    Registered,
    NotRegistered,
    NeedsRepair,
    BrowserMissing,
    RuntimeMissing,
}

#[derive(Debug, Clone)]
pub struct BrowserDiagnosis {
    pub config: BrowserSetupConfig,
    pub status: RegistrationStatus,
    pub browser_path: Option<PathBuf>,
    pub registry_manifest_path: Option<PathBuf>,
    pub manifest_path: PathBuf,
    pub runtime_path: PathBuf,
    pub detail: String,
}

impl BrowserDiagnosis {
    pub fn diagnostic_text(&self) -> String {
        let browser_path = self
            .browser_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not found".into());
        let registry_manifest_path = self
            .registry_manifest_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not registered".into());

        format!(
            "{}\nstatus: {}\nextension id: {}\nregistry: {}\nregistry manifest: {}\nexpected manifest: {}\nruntime: {}\nbrowser: {}\n{}",
            self.config.browser().label(),
            self.status.label(),
            self.config.extension_id(),
            self.config.registry_key(),
            registry_manifest_path,
            self.manifest_path.display(),
            self.runtime_path.display(),
            browser_path,
            self.detail
        )
    }
}

impl RegistrationStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Registered => "Registered",
            Self::NotRegistered => "Not registered",
            Self::NeedsRepair => "Needs repair",
            Self::BrowserMissing => "Browser not found",
            Self::RuntimeMissing => "Runtime missing",
        }
    }
}

#[derive(Serialize)]
struct NativeHostManifest<'a> {
    name: &'static str,
    description: &'static str,
    path: &'a str,
    #[serde(rename = "type")]
    type_field: &'static str,
    allowed_origins: [&'a str; 1],
}

#[derive(Deserialize)]
struct NativeHostManifestDocument {
    name: String,
    path: String,
    #[serde(rename = "type")]
    type_field: String,
    allowed_origins: Vec<String>,
}

pub fn render_native_host_manifest(runtime_path: &str, extension_origin: &str) -> String {
    let manifest = NativeHostManifest {
        name: HOST_NAME,
        description: "VaultKern runtime native host",
        path: runtime_path,
        type_field: "stdio",
        allowed_origins: [extension_origin],
    };
    serde_json::to_string(&manifest).expect("native host manifest serialization is infallible")
}

pub fn runtime_install_path(local_app_data: &Path) -> PathBuf {
    local_app_data
        .join(RUNTIME_DIR_NAME)
        .join(RUNTIME_FILE_NAME)
}

pub fn install_runtime_payload(local_app_data: &Path, payload: &[u8]) -> Result<PathBuf, String> {
    if payload.is_empty() {
        return Err("embedded runtime payload is missing".into());
    }

    let runtime_path = runtime_install_path(local_app_data);
    if let Some(parent) = runtime_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(&runtime_path, payload).map_err(|error| error.to_string())?;
    Ok(runtime_path)
}

fn native_host_manifest_is_usable(content: &str, expected_origin: Option<&str>) -> bool {
    let Ok(manifest) = serde_json::from_str::<NativeHostManifestDocument>(content) else {
        return false;
    };

    manifest.name == HOST_NAME
        && manifest.type_field == "stdio"
        && !manifest.path.trim().is_empty()
        && allowed_origins_match(&manifest.allowed_origins, expected_origin)
}

#[cfg(windows)]
fn native_host_manifest_runtime_path(content: &str) -> Option<PathBuf> {
    serde_json::from_str::<NativeHostManifestDocument>(content)
        .ok()
        .map(|manifest| PathBuf::from(manifest.path))
}

fn allowed_origins_match(allowed_origins: &[String], expected_origin: Option<&str>) -> bool {
    match expected_origin {
        Some(expected_origin) => allowed_origins
            .iter()
            .any(|origin| origin.eq_ignore_ascii_case(expected_origin)),
        None => allowed_origins
            .iter()
            .any(|origin| origin.starts_with("chrome-extension://") && origin.ends_with('/')),
    }
}

#[cfg(windows)]
pub mod windows_setup {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    use crate::{
        BrowserDiagnosis, BrowserKind, BrowserRegistrationProbe, BrowserSetupConfig,
        RegistrationStatus, install_runtime_payload, runtime_install_path,
    };

    const RUNTIME_PAYLOAD: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/vaultkern-runtime.exe"));

    pub fn local_app_data_dir() -> Result<PathBuf, String> {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is not set".to_string())
    }

    pub fn default_config(
        browser: BrowserKind,
        extension_id: &str,
    ) -> Result<BrowserSetupConfig, String> {
        let local_app_data = local_app_data_dir()?;
        let runtime_path = runtime_install_path(&local_app_data);
        Ok(BrowserSetupConfig::new(
            browser,
            extension_id,
            runtime_path,
            local_app_data,
        ))
    }

    pub fn diagnose_browser(
        browser: BrowserKind,
        extension_id: &str,
    ) -> Result<BrowserDiagnosis, String> {
        let config = default_config(browser, extension_id)?;
        let browser_path = detect_browser_path(browser);
        let registry_manifest_path = read_registry_manifest_path(browser)?;
        let manifest_content = registry_manifest_path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok());
        let registered_runtime_exists = manifest_content
            .as_deref()
            .and_then(super::native_host_manifest_runtime_path)
            .map(|path| path.is_file());
        let setup_runtime_exists = embedded_runtime_available() || config.runtime_path().is_file();

        let status = config.diagnose(BrowserRegistrationProbe {
            browser_installed: browser_path.is_some(),
            registry_manifest_path: registry_manifest_path.clone(),
            manifest_content,
            registered_runtime_exists,
            setup_runtime_exists,
        });
        let detail = detail_for_status(status);

        Ok(BrowserDiagnosis {
            manifest_path: config.manifest_path(),
            runtime_path: config.runtime_path().to_path_buf(),
            config,
            status,
            browser_path,
            registry_manifest_path,
            detail,
        })
    }

    pub fn register_browser(config: &BrowserSetupConfig) -> Result<(), String> {
        if config.extension_id().trim().is_empty() {
            return Err("extension id is required".into());
        }

        install_embedded_runtime(config)?;

        let manifest_path = config.manifest_path();
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::write(&manifest_path, config.expected_manifest()).map_err(|error| error.to_string())?;
        write_registry_manifest_path(config.browser(), &manifest_path)?;
        Ok(())
    }

    pub fn unregister_browser(browser: BrowserKind) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key_path = registry_subkey(browser);
        match hkcu.delete_subkey_all(key_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }?;

        if let Ok(local_app_data) = local_app_data_dir() {
            let manifest_path =
                BrowserSetupConfig::new(browser, "", PathBuf::new(), local_app_data)
                    .manifest_path();
            match fs::remove_file(&manifest_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }

        Ok(())
    }

    pub fn embedded_runtime_available() -> bool {
        !RUNTIME_PAYLOAD.is_empty()
    }

    fn install_embedded_runtime(config: &BrowserSetupConfig) -> Result<PathBuf, String> {
        let local_app_data = local_app_data_dir()?;
        let runtime_path = install_runtime_payload(&local_app_data, RUNTIME_PAYLOAD)?;
        if runtime_path != config.runtime_path() {
            return Err(format!(
                "runtime install path mismatch: {}",
                runtime_path.display()
            ));
        }
        Ok(runtime_path)
    }

    fn detect_browser_path(browser: BrowserKind) -> Option<PathBuf> {
        browser_install_candidates(browser)
            .into_iter()
            .find(|path| path.is_file())
    }

    fn browser_install_candidates(browser: BrowserKind) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let program_files = env::var_os("ProgramFiles").map(PathBuf::from);
        let program_files_x86 = env::var_os("ProgramFiles(x86)").map(PathBuf::from);

        match browser {
            BrowserKind::Chrome => {
                if let Some(root) = &program_files {
                    candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
                }
                if let Some(root) = &program_files_x86 {
                    candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
                }
            }
            BrowserKind::Edge => {
                if let Some(root) = &program_files {
                    candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
                }
                if let Some(root) = &program_files_x86 {
                    candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
                }
            }
        }

        candidates
    }

    fn read_registry_manifest_path(browser: BrowserKind) -> Result<Option<PathBuf>, String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(key) = hkcu.open_subkey(registry_subkey(browser)) else {
            return Ok(None);
        };
        let value: String = key.get_value("").map_err(|error| error.to_string())?;
        Ok(Some(PathBuf::from(value)))
    }

    fn write_registry_manifest_path(
        browser: BrowserKind,
        manifest_path: &Path,
    ) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(registry_subkey(browser))
            .map_err(|error| error.to_string())?;
        key.set_value("", &manifest_path.display().to_string())
            .map_err(|error| error.to_string())
    }

    fn registry_subkey(browser: BrowserKind) -> &'static str {
        match browser {
            BrowserKind::Chrome => {
                r"Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime"
            }
            BrowserKind::Edge => {
                r"Software\Microsoft\Edge\NativeMessagingHosts\com.vaultkern.runtime"
            }
        }
    }

    fn detail_for_status(status: RegistrationStatus) -> String {
        match status {
            RegistrationStatus::Registered => "Native host registration is ready.".into(),
            RegistrationStatus::NotRegistered => "Native host registry key is missing.".into(),
            RegistrationStatus::NeedsRepair => {
                "Registry or manifest exists but does not match the expected configuration.".into()
            }
            RegistrationStatus::BrowserMissing => "Browser executable was not found.".into(),
            RegistrationStatus::RuntimeMissing => {
                "Embedded runtime payload is missing from this setup executable.".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::{
        BrowserKind, BrowserRegistrationProbe, BrowserSetupConfig, RegistrationStatus,
        install_runtime_payload, render_native_host_manifest, runtime_install_path,
    };

    #[test]
    fn chrome_config_uses_hkcu_google_registry_and_browser_specific_manifest() {
        let config = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\VaultKern\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );

        assert_eq!(
            config.registry_key(),
            r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime"
        );
        assert_eq!(
            config.manifest_path(),
            PathBuf::from(
                "/home/alice/AppData/Local/vaultkern-runtime/com.vaultkern.runtime.chrome.json"
            )
        );
        assert_eq!(
            config.extension_origin(),
            "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"
        );
    }

    #[test]
    fn edge_config_uses_hkcu_edge_registry_and_browser_specific_manifest() {
        let config = BrowserSetupConfig::new(
            BrowserKind::Edge,
            "edgeextensionid",
            PathBuf::from(r"C:\VaultKern\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );

        assert_eq!(
            config.registry_key(),
            r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultkern.runtime"
        );
        assert_eq!(
            config.manifest_path(),
            PathBuf::from(
                "/home/alice/AppData/Local/vaultkern-runtime/com.vaultkern.runtime.edge.json"
            )
        );
    }

    #[test]
    fn manifest_uses_runtime_path_and_extension_origin() {
        let manifest = render_native_host_manifest(
            r"C:\VaultKern\vaultkern-runtime.exe",
            "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/",
        );

        assert_eq!(
            manifest,
            r#"{"name":"com.vaultkern.runtime","description":"VaultKern runtime native host","path":"C:\\VaultKern\\vaultkern-runtime.exe","type":"stdio","allowed_origins":["chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"]}"#
        );
    }

    #[test]
    fn runtime_installs_under_local_app_data_payload_directory() {
        assert_eq!(
            runtime_install_path(Path::new("/home/alice/AppData/Local")),
            PathBuf::from("/home/alice/AppData/Local/vaultkern-runtime/vaultkern-runtime.exe")
        );
    }

    #[test]
    fn install_runtime_payload_writes_embedded_runtime_bytes() {
        let temp_dir = tempfile::tempdir().unwrap();

        let runtime_path = install_runtime_payload(temp_dir.path(), b"runtime-bytes").unwrap();

        assert_eq!(
            runtime_path,
            temp_dir
                .path()
                .join("vaultkern-runtime/vaultkern-runtime.exe")
        );
        assert_eq!(fs::read(runtime_path).unwrap(), b"runtime-bytes");
    }

    #[test]
    fn install_runtime_payload_rejects_missing_payload() {
        let temp_dir = tempfile::tempdir().unwrap();

        assert!(install_runtime_payload(temp_dir.path(), b"").is_err());
    }

    #[test]
    fn diagnosis_reports_missing_and_repair_states() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\VaultKern\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: None,
                manifest_content: None,
                registered_runtime_exists: None,
                setup_runtime_exists: true,
            }),
            RegistrationStatus::NotRegistered
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(PathBuf::from(r"C:\other.json")),
                manifest_content: None,
                registered_runtime_exists: None,
                setup_runtime_exists: true,
            }),
            RegistrationStatus::NeedsRepair
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(expected.manifest_path()),
                manifest_content: Some(expected.expected_manifest()),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: true,
            }),
            RegistrationStatus::Registered
        );
    }

    #[test]
    fn diagnosis_accepts_existing_valid_manifest_outside_setup_path() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\Setup\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );
        let existing_manifest = render_native_host_manifest(
            r"C:\Existing\vaultkern-runtime.exe",
            "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/",
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(PathBuf::from(
                    r"C:\Users\alice\AppData\Local\vaultkern-runtime\com.vaultkern.runtime.json"
                )),
                manifest_content: Some(existing_manifest),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: true,
            }),
            RegistrationStatus::Registered
        );
    }

    #[test]
    fn diagnosis_accepts_existing_manifest_without_extension_id_when_origin_is_valid() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "",
            PathBuf::from(r"C:\Setup\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );
        let existing_manifest = render_native_host_manifest(
            r"C:\Existing\vaultkern-runtime.exe",
            "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/",
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(PathBuf::from(r"C:\other.json")),
                manifest_content: Some(existing_manifest),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: false,
            }),
            RegistrationStatus::Registered
        );
    }

    #[test]
    fn windows_application_manifest_declares_no_uac_elevation() {
        let manifest = read_package_file("windows/app.manifest");

        assert!(manifest.contains(r#"requestedExecutionLevel level="asInvoker""#));
        assert!(manifest.contains(r#"uiAccess="false""#));
    }

    #[test]
    fn windows_resource_script_embeds_application_manifest() {
        let resource_script = read_package_file("windows/app.rc");

        assert!(resource_script.contains(r#"1 24 "app.manifest""#));
    }

    #[test]
    fn windows_gui_binary_declares_windows_subsystem() {
        let main_rs = read_package_file("src/main.rs");

        assert!(main_rs.contains(r#"windows_subsystem = "windows""#));
    }

    #[test]
    fn windows_gui_uses_light_theme_and_collapsed_diagnostics() {
        let main_rs = read_package_file("src/main.rs");

        assert!(main_rs.contains("egui::Visuals::light()"));
        assert!(main_rs.contains(r#"C:\Windows\Fonts\segoeui.ttf"#));
        assert!(main_rs.contains(r#"C:\Windows\Fonts\msyh.ttc"#));
        assert!(main_rs.contains("CollapsingHeader::new(\"Details\")"));
        assert!(main_rs.contains(".id_salt((browser.label(), \"details\"))"));
        assert!(main_rs.contains("CollapsingHeader::new(\"Diagnostics\")"));
        assert!(main_rs.contains(".default_open(false)"));
    }

    #[test]
    fn package_script_outputs_single_setup_executable() {
        let script = read_package_file("scripts/package_windows.sh");

        assert!(script.contains("VAULTKERN_RUNTIME_PAYLOAD_PATH="));
        assert!(script.contains("VaultKernNativeSetup.exe"));
        assert!(!script.contains(r#""${output_dir}/vaultkern-runtime.exe""#));
    }

    fn read_package_file(path: &str) -> String {
        let package_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        fs::read_to_string(package_root.join(path)).expect("package file should be readable")
    }
}
