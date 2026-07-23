use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

const HOST_NAME: &str = "com.vaultkern.runtime";
const VENDOR_DIR_NAME: &str = "VaultKern";
const BROWSER_INTEGRATION_DIR_NAME: &str = "Browser Integration";
const RUNTIME_FILE_NAME: &str = "vaultkern-runtime.exe";
pub const DEFAULT_EXTENSION_ID_ENV: &str = "VAULTKERN_DEFAULT_EXTENSION_ID";
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn built_in_extension_id() -> Option<&'static str> {
    option_env!("VAULTKERN_DEFAULT_EXTENSION_ID").and_then(non_empty_trimmed)
}

pub fn resolve_extension_id(cli_arg: Option<&str>, env_value: Option<&str>) -> String {
    resolve_extension_id_with_default(built_in_extension_id(), cli_arg, env_value)
}

fn resolve_extension_id_with_default(
    built_in: Option<&str>,
    cli_arg: Option<&str>,
    env_value: Option<&str>,
) -> String {
    if let Some(extension_id) = built_in.and_then(non_empty_trimmed) {
        return extension_id.to_string();
    }
    if let Some(extension_id) = cli_arg.and_then(non_empty_trimmed) {
        return extension_id.to_string();
    }
    if let Some(extension_id) = env_value.and_then(non_empty_trimmed) {
        return extension_id.to_string();
    }
    String::new()
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

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
    install_root: PathBuf,
}

impl BrowserSetupConfig {
    pub fn new(
        browser: BrowserKind,
        extension_id: impl Into<String>,
        runtime_path: PathBuf,
        install_root: PathBuf,
    ) -> Self {
        Self {
            browser,
            extension_id: extension_id.into(),
            runtime_path,
            install_root,
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
        browser_integration_install_dir(&self.install_root).join(self.browser.manifest_filename())
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

        let registry_uses_setup_manifest = probe
            .registry_manifest_path
            .as_deref()
            .is_some_and(|path| paths_match(path, &self.manifest_path()));
        let manifest_matches_setup = probe.manifest_content.as_deref().is_some_and(|content| {
            native_host_manifest_matches_config(
                content,
                self.runtime_path(),
                self.extension_origin_for_validation().as_deref(),
            )
        });
        if registry_uses_setup_manifest
            && manifest_matches_setup
            && probe.registered_runtime_exists == Some(true)
            && probe.setup_runtime_exists
            && probe.registry_key_protected
        {
            return RegistrationStatus::Registered;
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
    pub registry_key_protected: bool,
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
        description: "VaultKern resident app IPC shim",
        path: runtime_path,
        type_field: "stdio",
        allowed_origins: [extension_origin],
    };
    serde_json::to_string(&manifest).expect("native host manifest serialization is infallible")
}

fn browser_integration_install_dir(install_root: &Path) -> PathBuf {
    install_root
        .join(VENDOR_DIR_NAME)
        .join(BROWSER_INTEGRATION_DIR_NAME)
}

pub fn runtime_install_path(install_root: &Path) -> PathBuf {
    browser_integration_install_dir(install_root).join(RUNTIME_FILE_NAME)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn browser_install_candidates_for_roots(
    browser: BrowserKind,
    program_files: Option<&Path>,
    program_files_x86: Option<&Path>,
    local_app_data: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    match browser {
        BrowserKind::Chrome => {
            if let Some(root) = program_files {
                candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
            }
            if let Some(root) = program_files_x86 {
                candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
            }
            if let Some(root) = local_app_data {
                candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
            }
        }
        BrowserKind::Edge => {
            if let Some(root) = program_files {
                candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
            }
            if let Some(root) = program_files_x86 {
                candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
            }
            if let Some(root) = local_app_data {
                candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
            }
        }
    }

    candidates
}

pub fn install_runtime_payload(install_root: &Path, payload: &[u8]) -> Result<PathBuf, String> {
    if payload.is_empty() {
        return Err("embedded runtime payload is missing".into());
    }

    let runtime_path = runtime_install_path(install_root);
    atomic_write_file(&runtime_path, payload).map_err(|error| error.to_string())?;
    Ok(runtime_path)
}

fn atomic_write_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_file_with_publish(path, contents, atomic_replace_file)
}

fn atomic_write_file_with_publish<F>(path: &Path, contents: &[u8], publish: F) -> io::Result<()>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target has no file name",
        )
    })?;

    let (temporary_path, mut temporary_file) = (0..128)
        .find_map(|_| {
            let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                ".{}.{}.{}.tmp",
                file_name.to_string_lossy(),
                std::process::id(),
                sequence
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => Some(Ok((candidate, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate an atomic write temporary file",
            )
        })?;

    let prepare_result = temporary_file
        .write_all(contents)
        .and_then(|()| temporary_file.sync_all());
    drop(temporary_file);
    if let Err(error) = prepare_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = publish(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    sync_parent_directory(parent)
}

#[cfg(not(windows))]
fn atomic_replace_file(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn atomic_replace_file(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    fs::File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

fn native_host_manifest_matches_config(
    content: &str,
    expected_runtime_path: &Path,
    expected_origin: Option<&str>,
) -> bool {
    let Ok(manifest) = serde_json::from_str::<NativeHostManifestDocument>(content) else {
        return false;
    };

    manifest.name == HOST_NAME
        && manifest.type_field == "stdio"
        && paths_match(Path::new(&manifest.path), expected_runtime_path)
        && allowed_origins_match(&manifest.allowed_origins, expected_origin)
}

fn paths_match(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(windows)]
fn native_host_manifest_runtime_path(content: &str) -> Option<PathBuf> {
    serde_json::from_str::<NativeHostManifestDocument>(content)
        .ok()
        .map(|manifest| PathBuf::from(manifest.path))
}

fn allowed_origins_match(allowed_origins: &[String], expected_origin: Option<&str>) -> bool {
    match expected_origin {
        Some(expected_origin) => {
            allowed_origins.len() == 1 && allowed_origins[0] == expected_origin
        }
        None => {
            allowed_origins.len() == 1
                && allowed_origins[0].starts_with("chrome-extension://")
                && allowed_origins[0].ends_with('/')
        }
    }
}

#[cfg(windows)]
pub mod windows_setup {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::slice;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Registry::{
        HKEY, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, RegCloseKey, RegCreateKeyExW,
        RegFlushKey, RegGetKeySecurity, RegSetKeySecurity, RegSetValueExW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};
    use winreg::RegKey;
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_USERS, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };

    use crate::{
        BrowserDiagnosis, BrowserKind, BrowserRegistrationProbe, BrowserSetupConfig,
        RegistrationStatus, atomic_write_file, browser_install_candidates_for_roots,
        built_in_extension_id, install_runtime_payload, paths_match, runtime_install_path,
    };

    const RUNTIME_PAYLOAD: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/vaultkern-runtime.exe"));
    const REGISTRY_VIEWS: [REG_SAM_FLAGS; 2] = [KEY_WOW64_32KEY, KEY_WOW64_64KEY];
    const PROTECTED_REGISTRATION_SDDL: &str = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0.cast());
                }
            }
        }
    }

    struct RegistryHandle(HKEY);

    impl Drop for RegistryHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    RegCloseKey(self.0);
                }
            }
        }
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub fn program_files_dir() -> Result<PathBuf, String> {
        known_folder_path(&FOLDERID_ProgramFiles, "Program Files")
    }

    pub fn default_config(
        browser: BrowserKind,
        extension_id: &str,
    ) -> Result<BrowserSetupConfig, String> {
        let program_files = program_files_dir()?;
        let runtime_path = runtime_install_path(&program_files);
        let extension_id = built_in_extension_id().unwrap_or(extension_id);
        Ok(BrowserSetupConfig::new(
            browser,
            extension_id,
            runtime_path,
            program_files,
        ))
    }

    pub fn diagnose_browser(
        browser: BrowserKind,
        extension_id: &str,
    ) -> Result<BrowserDiagnosis, String> {
        let config = default_config(browser, extension_id)?;
        let browser_path = detect_browser_path(browser);
        let (registry_manifest_path, registry_key_protected) =
            read_registry_manifest_path(browser)?;
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
            registry_key_protected,
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

    pub fn current_user_sid_string() -> Result<String, String> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let token = HandleGuard(token);
        let mut required = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
        }
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err("Windows did not return a valid user token".into());
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        let mut sid_string = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_string) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let mut length = 0;
        while unsafe { *sid_string.add(length) } != 0 {
            length += 1;
        }
        let result = String::from_utf16(unsafe { slice::from_raw_parts(sid_string, length) })
            .map_err(|error| error.to_string());
        unsafe {
            LocalFree(sid_string.cast());
        }
        result
    }

    pub fn register_browser_for_user(
        config: &BrowserSetupConfig,
        target_user_sid: &str,
    ) -> Result<(), String> {
        validate_target_user_sid(target_user_sid)?;
        if config.extension_id().len() != 32
            || !config
                .extension_id()
                .bytes()
                .all(|byte| (b'a'..=b'p').contains(&byte))
        {
            return Err(
                "extension id must contain exactly 32 lowercase letters from a through p".into(),
            );
        }
        if built_in_extension_id().is_some_and(|extension_id| extension_id != config.extension_id())
        {
            return Err("this signed package is pinned to a different extension id".into());
        }

        install_embedded_runtime(config)?;

        let manifest_path = config.manifest_path();
        atomic_write_file(&manifest_path, config.expected_manifest().as_bytes())
            .map_err(|error| error.to_string())?;
        write_registry_manifest_path_for_user(config.browser(), target_user_sid, &manifest_path)?;
        Ok(())
    }

    pub fn unregister_browser_for_user(
        browser: BrowserKind,
        target_user_sid: &str,
    ) -> Result<(), String> {
        validate_target_user_sid(target_user_sid)?;
        let users = RegKey::predef(HKEY_USERS);
        let key_path = user_registry_subkey(target_user_sid, browser);
        for view in REGISTRY_VIEWS {
            match users.delete_subkey_with_flags(&key_path, view) {
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
        let program_files = program_files_dir()?;
        let runtime_path = install_runtime_payload(&program_files, RUNTIME_PAYLOAD)?;
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
        let program_files = env::var_os("ProgramFiles").map(PathBuf::from);
        let program_files_x86 = env::var_os("ProgramFiles(x86)").map(PathBuf::from);
        let local_app_data = env::var_os("LOCALAPPDATA").map(PathBuf::from);

        browser_install_candidates_for_roots(
            browser,
            program_files.as_deref(),
            program_files_x86.as_deref(),
            local_app_data.as_deref(),
        )
    }

    fn read_registry_manifest_path(
        browser: BrowserKind,
    ) -> Result<(Option<PathBuf>, bool), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut registrations = Vec::new();
        for view in REGISTRY_VIEWS {
            let key = match hkcu.open_subkey_with_flags(registry_subkey(browser), KEY_READ | view) {
                Ok(key) => key,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            let value: String = match key.get_value("") {
                Ok(value) => value,
                Err(_) => {
                    registrations.push((PathBuf::new(), false));
                    continue;
                }
            };
            registrations.push((
                PathBuf::from(value),
                registration_key_has_expected_acl(&key)?,
            ));
        }

        let Some((first_path, _)) = registrations.first() else {
            return Ok((None, false));
        };
        let both_views_match = registrations.len() == REGISTRY_VIEWS.len()
            && registrations
                .iter()
                .all(|(path, protected)| paths_match(path, first_path) && *protected);
        Ok((Some(first_path.clone()), both_views_match))
    }

    fn write_registry_manifest_path_for_user(
        browser: BrowserKind,
        target_user_sid: &str,
        manifest_path: &Path,
    ) -> Result<(), String> {
        validate_target_user_sid(target_user_sid)?;
        let key_path = user_registry_subkey(target_user_sid, browser);
        let value = manifest_path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        for view in REGISTRY_VIEWS {
            let key = create_protected_registration_key(HKEY_USERS, &key_path, view)?;
            let result = unsafe {
                RegSetValueExW(
                    key.0,
                    ptr::null(),
                    0,
                    REG_SZ,
                    value.as_ptr().cast(),
                    (value.len() * size_of::<u16>()) as u32,
                )
            };
            win32_result(result)?;
            win32_result(unsafe { RegFlushKey(key.0) })?;
        }
        Ok(())
    }

    fn create_protected_registration_key(
        root: HKEY,
        path: &str,
        view: REG_SAM_FLAGS,
    ) -> Result<RegistryHandle, String> {
        let descriptor = protected_registration_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path = OsStr::new(path)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut key = ptr::null_mut();
        let mut disposition = 0;
        let result = unsafe {
            RegCreateKeyExW(
                root,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | view,
                &attributes,
                &mut key,
                &mut disposition,
            )
        };
        win32_result(result)?;
        let key = RegistryHandle(key);
        win32_result(unsafe {
            RegSetKeySecurity(
                key.0,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        })?;
        Ok(key)
    }

    fn protected_registration_descriptor() -> Result<LocalSecurityDescriptor, String> {
        let sddl = OsStr::new(PROTECTED_REGISTRATION_SDDL)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(LocalSecurityDescriptor(descriptor))
    }

    fn known_folder_path(
        folder_id: &windows_sys::core::GUID,
        label: &str,
    ) -> Result<PathBuf, String> {
        let mut raw_path = ptr::null_mut();
        let status = unsafe { SHGetKnownFolderPath(folder_id, 0, ptr::null_mut(), &mut raw_path) };
        if status < 0 {
            return Err(format!(
                "SHGetKnownFolderPath({label}) failed: {:#010x}",
                status as u32
            ));
        }
        if raw_path.is_null() {
            return Err(format!("SHGetKnownFolderPath({label}) returned no path"));
        }

        let length = unsafe {
            let mut length = 0;
            while *raw_path.add(length) != 0 {
                length += 1;
            }
            length
        };
        let path = PathBuf::from(OsString::from_wide(unsafe {
            slice::from_raw_parts(raw_path, length)
        }));
        unsafe {
            CoTaskMemFree(raw_path.cast());
        }
        Ok(path)
    }

    fn registration_key_has_expected_acl(key: &RegKey) -> Result<bool, String> {
        let mut descriptor_size = 0;
        let first = unsafe {
            RegGetKeySecurity(
                key.raw_handle(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                &mut descriptor_size,
            )
        };
        if first != ERROR_INSUFFICIENT_BUFFER {
            return win32_result(first).map(|()| false);
        }
        let word_count = (descriptor_size as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; word_count];
        let actual = storage.as_mut_ptr().cast();
        win32_result(unsafe {
            RegGetKeySecurity(
                key.raw_handle(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                actual,
                &mut descriptor_size,
            )
        })?;

        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(actual, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Ok(false);
        }

        let expected = protected_registration_descriptor()?;
        Ok(security_descriptor_owners_match(actual, expected.0)?
            && dacl_bytes(actual)? == dacl_bytes(expected.0)?)
    }

    fn security_descriptor_owners_match(
        actual: PSECURITY_DESCRIPTOR,
        expected: PSECURITY_DESCRIPTOR,
    ) -> Result<bool, String> {
        let mut actual_owner: PSID = ptr::null_mut();
        let mut expected_owner: PSID = ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(actual, &mut actual_owner, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        if unsafe { GetSecurityDescriptorOwner(expected, &mut expected_owner, &mut defaulted) } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if actual_owner.is_null() || expected_owner.is_null() {
            return Ok(false);
        }
        Ok(unsafe { EqualSid(actual_owner, expected_owner) } != 0)
    }

    fn dacl_bytes(descriptor: PSECURITY_DESCRIPTOR) -> Result<Vec<u8>, String> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if present == 0 || dacl.is_null() {
            return Ok(Vec::new());
        }
        let size = unsafe { (*dacl).AclSize as usize };
        Ok(unsafe { slice::from_raw_parts(dacl.cast(), size) }.to_vec())
    }

    fn win32_result(result: u32) -> Result<(), String> {
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result as i32).to_string())
        }
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

    fn user_registry_subkey(target_user_sid: &str, browser: BrowserKind) -> String {
        format!(r"{}\{}", target_user_sid, registry_subkey(browser))
    }

    fn validate_target_user_sid(target_user_sid: &str) -> Result<(), String> {
        if !target_user_sid.starts_with("S-1-")
            || target_user_sid.len() > 184
            || !target_user_sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
        {
            return Err("invalid target Windows user SID".into());
        }
        Ok(())
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
        BrowserKind, BrowserRegistrationProbe, BrowserSetupConfig, DEFAULT_EXTENSION_ID_ENV,
        RegistrationStatus, atomic_write_file_with_publish, browser_install_candidates_for_roots,
        built_in_extension_id, install_runtime_payload, render_native_host_manifest,
        resolve_extension_id, resolve_extension_id_with_default, runtime_install_path,
    };

    #[test]
    fn default_extension_id_is_compile_time_configured() {
        assert_eq!(DEFAULT_EXTENSION_ID_ENV, "VAULTKERN_DEFAULT_EXTENSION_ID");
        if let Some(default_id) = built_in_extension_id() {
            assert!(!default_id.trim().is_empty());
        }
    }

    #[test]
    fn signed_package_extension_id_cannot_be_overridden_at_runtime() {
        assert_eq!(
            resolve_extension_id_with_default(
                Some("pinned-extension"),
                Some("cli-extension"),
                Some("env-extension"),
            ),
            "pinned-extension"
        );
    }

    #[test]
    fn development_build_extension_id_prefers_cli_then_environment() {
        assert_eq!(
            resolve_extension_id_with_default(None, Some(" cli-extension "), Some("env-extension"),),
            "cli-extension"
        );
        assert_eq!(
            resolve_extension_id_with_default(None, Some("   "), Some(" env-extension ")),
            "env-extension"
        );
        assert_eq!(resolve_extension_id_with_default(None, None, Some("")), "");

        assert_eq!(
            resolve_extension_id(Some("cli-extension"), Some("env-extension")),
            built_in_extension_id().unwrap_or("cli-extension")
        );
    }

    #[test]
    fn chrome_config_uses_hkcu_google_registry_and_browser_specific_manifest() {
        let config = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\VaultKern\vaultkern-runtime.exe"),
            PathBuf::from("/Program Files"),
        );

        assert_eq!(
            config.registry_key(),
            r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vaultkern.runtime"
        );
        assert_eq!(
            config.manifest_path(),
            PathBuf::from(
                "/Program Files/VaultKern/Browser Integration/com.vaultkern.runtime.chrome.json"
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
            PathBuf::from("/Program Files"),
        );

        assert_eq!(
            config.registry_key(),
            r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.vaultkern.runtime"
        );
        assert_eq!(
            config.manifest_path(),
            PathBuf::from(
                "/Program Files/VaultKern/Browser Integration/com.vaultkern.runtime.edge.json"
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
            r#"{"name":"com.vaultkern.runtime","description":"VaultKern resident app IPC shim","path":"C:\\VaultKern\\vaultkern-runtime.exe","type":"stdio","allowed_origins":["chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"]}"#
        );
    }

    #[test]
    fn runtime_installs_under_the_machine_protected_payload_directory() {
        assert_eq!(
            runtime_install_path(Path::new("/Program Files")),
            PathBuf::from("/Program Files/VaultKern/Browser Integration/vaultkern-runtime.exe")
        );
    }

    #[test]
    fn production_runtime_and_manifests_share_a_machine_protected_install_directory() {
        let program_files = Path::new("/Program Files");
        let runtime_path = runtime_install_path(program_files);
        let config = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            runtime_path.clone(),
            program_files.to_path_buf(),
        );

        assert_eq!(
            runtime_path,
            PathBuf::from("/Program Files/VaultKern/Browser Integration/vaultkern-runtime.exe")
        );
        assert_eq!(
            config.manifest_path(),
            PathBuf::from(
                "/Program Files/VaultKern/Browser Integration/com.vaultkern.runtime.chrome.json"
            )
        );
    }

    #[test]
    fn native_setup_starts_as_the_interactive_user_before_requesting_elevation() {
        let manifest = include_str!("../windows/app.manifest");

        assert!(manifest.contains(r#"requestedExecutionLevel level="asInvoker""#));
        assert!(!manifest.contains(r#"requestedExecutionLevel level="requireAdministrator""#));
    }

    #[test]
    fn install_runtime_payload_writes_embedded_runtime_bytes() {
        let temp_dir = tempfile::tempdir().unwrap();

        let runtime_path = install_runtime_payload(temp_dir.path(), b"runtime-bytes").unwrap();

        assert_eq!(
            runtime_path,
            temp_dir
                .path()
                .join("VaultKern/Browser Integration/vaultkern-runtime.exe")
        );
        assert_eq!(fs::read(runtime_path).unwrap(), b"runtime-bytes");
    }

    #[test]
    fn install_runtime_payload_rejects_missing_payload() {
        let temp_dir = tempfile::tempdir().unwrap();

        assert!(install_runtime_payload(temp_dir.path(), b"").is_err());
    }

    #[test]
    fn failed_atomic_publish_preserves_the_installed_generation_and_cleans_up() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("vaultkern-runtime.exe");
        fs::write(&target, b"old-runtime").unwrap();

        let error =
            atomic_write_file_with_publish(&target, b"new-runtime", |_temporary, _target| {
                Err(std::io::Error::other("injected publish failure"))
            })
            .expect_err("publish failure must be surfaced");

        assert!(error.to_string().contains("injected publish failure"));
        assert_eq!(fs::read(&target).unwrap(), b"old-runtime");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn browser_install_candidates_include_local_app_data_user_installs() {
        let candidates = browser_install_candidates_for_roots(
            BrowserKind::Chrome,
            Some(Path::new("/Program Files")),
            Some(Path::new("/Program Files (x86)")),
            Some(Path::new("/Users/alice/AppData/Local")),
        );

        assert!(candidates.contains(&PathBuf::from(
            "/Users/alice/AppData/Local/Google/Chrome/Application/chrome.exe"
        )));
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
                registry_key_protected: true,
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
                registry_key_protected: true,
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
                registry_key_protected: true,
            }),
            RegistrationStatus::Registered
        );
    }

    #[test]
    fn diagnosis_requires_the_registry_to_point_at_the_setup_owned_manifest() {
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
                registry_key_protected: true,
            }),
            RegistrationStatus::NeedsRepair
        );
    }

    #[test]
    fn diagnosis_rejects_a_user_writable_native_host_registration() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\Program Files\VaultKern\Browser Integration\vaultkern-runtime.exe"),
            PathBuf::from(r"C:\Program Files"),
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(expected.manifest_path()),
                manifest_content: Some(expected.expected_manifest()),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: true,
                registry_key_protected: false,
            }),
            RegistrationStatus::NeedsRepair
        );
    }

    #[test]
    fn diagnosis_rejects_a_manifest_that_grants_an_extra_extension_origin() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\Setup\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );
        let manifest_with_extra_origin = format!(
            r#"{{"name":"com.vaultkern.runtime","path":"{}","type":"stdio","allowed_origins":["{}","chrome-extension://attacker/"]}}"#,
            expected.runtime_path().display(),
            expected.extension_origin()
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(expected.manifest_path()),
                manifest_content: Some(manifest_with_extra_origin),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: true,
                registry_key_protected: true,
            }),
            RegistrationStatus::NeedsRepair
        );
    }

    #[test]
    fn diagnosis_requires_the_exact_configured_extension_origin() {
        let expected = BrowserSetupConfig::new(
            BrowserKind::Chrome,
            "kblgblkjghklighdgmejjfondchkjcgf",
            PathBuf::from(r"C:\Setup\vaultkern-runtime.exe"),
            PathBuf::from("/home/alice/AppData/Local"),
        );
        let wrong_case_manifest = render_native_host_manifest(
            &expected.runtime_path().to_string_lossy(),
            "chrome-extension://KBLGBLKJGHKLIGHDGMEJJFONDCHKJCGF/",
        );

        assert_eq!(
            expected.diagnose(BrowserRegistrationProbe {
                browser_installed: true,
                registry_manifest_path: Some(expected.manifest_path()),
                manifest_content: Some(wrong_case_manifest),
                registered_runtime_exists: Some(true),
                setup_runtime_exists: true,
                registry_key_protected: true,
            }),
            RegistrationStatus::NeedsRepair
        );
    }

    #[test]
    fn diagnosis_without_an_extension_id_still_requires_the_setup_owned_paths() {
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
                registry_key_protected: true,
            }),
            RegistrationStatus::RuntimeMissing
        );
    }

    #[test]
    fn windows_application_manifest_preserves_the_launching_user_identity() {
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
        assert!(main_rs.contains("Current extension id"));
        assert!(main_rs.contains("Enter the current Chrome extension id before registering."));
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

    #[test]
    fn package_script_refuses_to_embed_an_unsigned_runtime() {
        let script = read_package_file("scripts/package_windows.sh");

        assert!(script.contains("VAULTKERN_WINDOWS_SIGNING_THUMBPRINT"));
        assert!(script.contains("VAULTKERN_SIGNTOOL"));
        assert!(script.contains(r#""${sign_tool}" sign"#));
        assert!(script.contains(r#""${sign_tool}" verify"#));
        assert!(script.contains("runtime signing certificate thumbprint is required"));
        assert!(script.contains("setup_sign_path"));
        assert!(script.contains(r#""${sign_tool}" sign"#));
        assert!(script.contains(r#""${sign_tool}" verify /pa /all "${setup_sign_path}""#));
    }

    #[test]
    fn windows_gui_elevates_only_the_machine_and_protected_registry_commit() {
        let main_rs = read_package_file("src/main.rs");
        let lib_rs = read_package_file("src/lib.rs");

        assert!(main_rs.contains("--elevated-register"));
        assert!(main_rs.contains("current_user_sid_string"));
        assert!(main_rs.contains("run_elevated_action"));
        assert!(lib_rs.contains("HKEY_USERS"));
        assert!(lib_rs.contains("register_browser_for_user"));
    }

    #[test]
    fn package_script_requires_a_pinned_chromium_extension_id() {
        let script = read_package_file("scripts/package_windows.sh");

        assert!(script.contains("VAULTKERN_DEFAULT_EXTENSION_ID"));
        assert!(script.contains("^[a-p]{32}$"));
        assert!(script.contains("extension id is required"));
        assert!(script.contains("export VAULTKERN_DEFAULT_EXTENSION_ID"));
    }

    #[test]
    fn build_script_tracks_runtime_payload_file_changes() {
        let build_rs = read_package_file("build.rs");

        assert!(build_rs.contains("VAULTKERN_DEFAULT_EXTENSION_ID"));
        assert!(build_rs.contains(r#"cargo:rerun-if-changed={}"#));
        assert!(build_rs.contains("payload_path.display()"));
    }

    fn read_package_file(path: &str) -> String {
        let package_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        fs::read_to_string(package_root.join(path)).expect("package file should be readable")
    }
}
