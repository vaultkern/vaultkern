use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{
    APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_AUTHENTICODE, CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS,
    CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
    CERT_SHA256_HASH_PROP_ID, CERT_X500_NAME_STR, CertFreeCertificateChain,
    CertGetCertificateChain, CertGetCertificateContextProperty, CertGetNameStringW, CertNameToStrW,
    CertVerifyCertificateChainPolicy, HCERTCHAINENGINE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::Win32::Storage::Packaging::Appx::{
    GetPackageFamilyName, GetPackageFullName, GetPackageId, PACKAGE_ID,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
};

const RESIDENT_EXECUTABLE_NAME: &str = "vaultkern-windows.exe";
const RESIDENT_PACKAGE_NAME: &str = "VaultKern.Windows";
const RESIDENT_PACKAGE_PUBLISHER: &str = "CN=VaultKern Development";
const RESIDENT_PACKAGE_PUBLISHER_ID: &str = "bf7at9bmb1e94";
const RESIDENT_PACKAGE_FAMILY_NAME: &str = "VaultKern.Windows_bf7at9bmb1e94";

#[derive(Clone, Debug)]
struct AuthenticodeIdentity {
    subject: String,
    organization: Option<String>,
    sha256_thumbprint: String,
    machine_chain_trusted: bool,
}

#[derive(Debug)]
struct ResidentServerIdentity {
    executable_name: String,
    package_name: Option<String>,
    package_publisher: Option<String>,
    package_publisher_id: Option<String>,
    package_family_name: Option<String>,
    package_signer: Option<AuthenticodeIdentity>,
    package_signature_kind: Option<i32>,
    package_is_development_mode: Option<bool>,
    package_install_root: Option<String>,
    executable_path: Option<String>,
}

#[derive(Debug)]
struct BrowserParentIdentity {
    executable_name: String,
    executable_path: String,
    signer: AuthenticodeIdentity,
}

#[derive(Debug)]
struct NativeShimIdentity {
    executable_path: String,
    signer: Option<AuthenticodeIdentity>,
}

#[derive(Debug)]
struct NativeMessagingChannelIdentity {
    stdin_client_process_id: u32,
    stdout_server_process_id: u32,
    actor: BrowserParentIdentity,
}

#[derive(Debug)]
struct ProcessPackageIdentity {
    name: String,
    publisher: String,
    publisher_id: String,
    family_name: String,
    full_name: String,
}

#[derive(Debug)]
struct RegisteredPackageEvidence {
    signature_kind: i32,
    is_development_mode: bool,
    install_root: String,
}

pub(super) fn authenticate_resident_server_process(process_id: u32) -> Result<()> {
    let identity = resident_server_identity_for_process(process_id)?;
    authenticate_resident_server_identity(&identity)?;
    let package_signer = identity
        .package_signer
        .as_ref()
        .context("resident IPC server package signer disappeared after validation")?;
    let shim_signer = authenticode_identity_for_file(
        &std::env::current_exe().context("resolve native shim executable path")?,
    )
    .context("verify native shim signature")?;
    authenticate_matching_signers(package_signer, &shim_signer)
}

pub(super) fn authenticate_native_shim_process(process_id: u32) -> Result<()> {
    let resident = resident_server_identity_for_process(unsafe { GetCurrentProcessId() })?;
    authenticate_resident_server_identity(&resident)?;
    let package_signer = resident
        .package_signer
        .as_ref()
        .context("resident package signer disappeared after validation")?;
    let expected_path = expected_native_shim_path()?;
    let expected_path = expected_path
        .to_str()
        .context("native shim install path is not valid UTF-8")?;
    let shim = native_shim_identity_for_process(process_id)?;
    authenticate_native_shim_identity(&shim, expected_path, &package_signer.subject)?;
    let shim_signer = shim
        .signer
        .as_ref()
        .context("native shim signer disappeared after validation")?;
    authenticate_matching_signers(package_signer, shim_signer)
}

pub(super) fn authenticate_native_messaging_channel() -> Result<()> {
    let stdin = std_handle(STD_INPUT_HANDLE, "stdin")?;
    let stdout = std_handle(STD_OUTPUT_HANDLE, "stdout")?;
    let (stdin_client_process_id, stdout_server_process_id) =
        native_messaging_stdio_peer_process_ids(stdin, stdout)?;
    let actor = browser_identity_for_process(stdin_client_process_id)
        .context("authenticate native-messaging channel actor")?;
    let identity = NativeMessagingChannelIdentity {
        stdin_client_process_id,
        stdout_server_process_id,
        actor,
    };
    let trusted_browser_paths = trusted_browser_executable_paths()?;
    authenticate_native_messaging_channel_identity(&identity, &trusted_browser_paths)
}

fn authenticate_resident_server_identity(identity: &ResidentServerIdentity) -> Result<()> {
    if !identity
        .executable_name
        .eq_ignore_ascii_case(RESIDENT_EXECUTABLE_NAME)
    {
        anyhow::bail!("resident IPC server executable name is not trusted");
    }
    if identity.package_name.as_deref() != Some(RESIDENT_PACKAGE_NAME)
        || identity.package_publisher.as_deref() != Some(RESIDENT_PACKAGE_PUBLISHER)
        || identity.package_publisher_id.as_deref() != Some(RESIDENT_PACKAGE_PUBLISHER_ID)
        || identity.package_family_name.as_deref() != Some(RESIDENT_PACKAGE_FAMILY_NAME)
    {
        anyhow::bail!("resident IPC server has no trusted package identity");
    }
    let package_signer = identity
        .package_signer
        .as_ref()
        .context("resident IPC server package has no valid package signature")?;
    if package_signer.subject != RESIDENT_PACKAGE_PUBLISHER
        || !valid_sha256_thumbprint(package_signer)
    {
        anyhow::bail!("resident IPC server package signature does not match its identity");
    }
    if identity.package_signature_kind.unwrap_or_default() == 0
        || identity.package_is_development_mode != Some(false)
    {
        anyhow::bail!("resident IPC server is not a signed installed package");
    }
    let install_root = identity
        .package_install_root
        .as_deref()
        .context("resident IPC server has no OS package install root")?;
    let executable_path = identity
        .executable_path
        .as_deref()
        .context("resident IPC server has no process image path")?;
    let expected_path = Path::new(install_root).join(RESIDENT_EXECUTABLE_NAME);
    let expected_path = expected_path
        .to_str()
        .context("resident IPC server package path is not valid UTF-8")?;
    if !executable_path.eq_ignore_ascii_case(expected_path) {
        anyhow::bail!("resident IPC server image is outside its OS package install root");
    }
    Ok(())
}

fn authenticate_native_shim_identity(
    identity: &NativeShimIdentity,
    expected_executable_path: &str,
    expected_package_publisher: &str,
) -> Result<()> {
    if !identity
        .executable_path
        .eq_ignore_ascii_case(expected_executable_path)
    {
        anyhow::bail!("resident IPC client executable path is not trusted");
    }
    let signer = identity
        .signer
        .as_ref()
        .context("resident IPC client has no valid Authenticode signature")?;
    if signer.subject != expected_package_publisher || !valid_sha256_thumbprint(signer) {
        anyhow::bail!("resident IPC client signature does not match the app publisher");
    }
    Ok(())
}

fn authenticate_native_messaging_channel_identity(
    identity: &NativeMessagingChannelIdentity,
    trusted_browser_paths: &[String],
) -> Result<()> {
    if identity.stdin_client_process_id == 0
        || identity.stdin_client_process_id != identity.stdout_server_process_id
    {
        anyhow::bail!("native-messaging stdin and stdout do not have one browser pipe peer");
    }
    authenticate_browser_identity(&identity.actor, trusted_browser_paths)
}

fn authenticate_browser_identity(
    browser: &BrowserParentIdentity,
    trusted_browser_paths: &[String],
) -> Result<()> {
    let expected_organization = if browser.executable_name.eq_ignore_ascii_case("chrome.exe") {
        "Google LLC"
    } else if browser.executable_name.eq_ignore_ascii_case("msedge.exe") {
        "Microsoft Corporation"
    } else {
        anyhow::bail!("resident IPC client parent is not an allowed browser executable");
    };
    if !trusted_browser_paths
        .iter()
        .any(|path| path.eq_ignore_ascii_case(&browser.executable_path))
    {
        anyhow::bail!("resident IPC browser install path is not trusted");
    }
    if browser.signer.organization.as_deref() != Some(expected_organization)
        || browser.signer.subject.is_empty()
        || !valid_sha256_thumbprint(&browser.signer)
    {
        anyhow::bail!("resident IPC browser publisher is not trusted");
    }
    if !browser.signer.machine_chain_trusted {
        anyhow::bail!("resident IPC browser signer is not trusted by LocalMachine");
    }
    Ok(())
}

fn authenticate_matching_signers(
    package_signer: &AuthenticodeIdentity,
    executable_signer: &AuthenticodeIdentity,
) -> Result<()> {
    if !valid_sha256_thumbprint(package_signer)
        || !valid_sha256_thumbprint(executable_signer)
        || package_signer.subject != executable_signer.subject
    {
        anyhow::bail!("resident IPC peer signer identity is incomplete or inconsistent");
    }
    if !package_signer
        .sha256_thumbprint
        .eq_ignore_ascii_case(&executable_signer.sha256_thumbprint)
    {
        anyhow::bail!("resident IPC peer signer certificate thumbprint does not match the package");
    }
    Ok(())
}

fn valid_sha256_thumbprint(identity: &AuthenticodeIdentity) -> bool {
    identity.sha256_thumbprint.len() == 64
        && identity
            .sha256_thumbprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn resident_server_identity_for_process(process_id: u32) -> Result<ResidentServerIdentity> {
    let process = open_process(process_id).context("open resident IPC server process")?;
    let executable_path =
        process_image_path(process.0).context("resolve resident IPC server executable path")?;
    let executable_name = Path::new(&executable_path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("resident IPC server executable has no valid file name")?
        .to_owned();
    let package = process_package_identity(process.0)
        .context("resolve resident IPC server package identity")?;
    let package_evidence = package
        .as_ref()
        .map(|package| registered_package_evidence(&package.full_name))
        .transpose()?;
    let package_signer = match package_evidence.as_ref() {
        Some(evidence) if evidence.signature_kind != 0 && !evidence.is_development_mode => Some(
            authenticode_identity_for_file(
                &Path::new(&evidence.install_root).join("AppxSignature.p7x"),
            )
            .context("verify resident IPC server package signature")?,
        ),
        _ => None,
    };

    Ok(ResidentServerIdentity {
        executable_name,
        package_name: package.as_ref().map(|package| package.name.clone()),
        package_publisher: package.as_ref().map(|package| package.publisher.clone()),
        package_publisher_id: package.as_ref().map(|package| package.publisher_id.clone()),
        package_family_name: package.map(|package| package.family_name),
        package_signer,
        package_signature_kind: package_evidence
            .as_ref()
            .map(|evidence| evidence.signature_kind),
        package_is_development_mode: package_evidence
            .as_ref()
            .map(|evidence| evidence.is_development_mode),
        package_install_root: package_evidence.map(|evidence| evidence.install_root),
        executable_path: Some(executable_path),
    })
}

fn native_shim_identity_for_process(process_id: u32) -> Result<NativeShimIdentity> {
    let process = open_process(process_id).context("open resident IPC client process")?;
    let executable_path =
        process_image_path(process.0).context("resolve native shim executable path")?;
    let executable_path = canonical_windows_path(&executable_path)
        .context("canonicalize native shim executable path")?;
    let signer = authenticode_identity_for_file(Path::new(&executable_path))
        .context("verify native shim Authenticode signature")?;

    Ok(NativeShimIdentity {
        executable_path,
        signer: Some(signer),
    })
}

fn browser_identity_for_process(process_id: u32) -> Result<BrowserParentIdentity> {
    let process = open_process(process_id).context("open native-messaging browser process")?;
    let browser_path = process_image_path(process.0).context("resolve browser executable path")?;
    let browser_path =
        canonical_windows_path(&browser_path).context("canonicalize browser executable path")?;
    let executable_name = Path::new(&browser_path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("browser executable has no valid file name")?
        .to_owned();
    let browser_signer = authenticode_identity_for_file(Path::new(&browser_path))
        .context("verify browser Authenticode signature")?;

    Ok(BrowserParentIdentity {
        executable_name,
        executable_path: browser_path,
        signer: browser_signer,
    })
}

fn trusted_browser_executable_paths() -> Result<Vec<String>> {
    let roots = [
        known_folder_path(&FOLDERID_ProgramFiles, "Program Files")?,
        known_folder_path(&FOLDERID_ProgramFilesX86, "Program Files (x86)")?,
        known_folder_path(&FOLDERID_LocalAppData, "Local AppData")?,
    ];
    let relative_paths = [
        Path::new("Google")
            .join("Chrome")
            .join("Application")
            .join("chrome.exe"),
        Path::new("Microsoft")
            .join("Edge")
            .join("Application")
            .join("msedge.exe"),
    ];
    let mut trusted = Vec::new();
    for root in roots {
        for relative_path in &relative_paths {
            let candidate = root.join(relative_path);
            if !candidate.is_file() {
                continue;
            }
            let candidate = canonical_windows_path(
                candidate
                    .to_str()
                    .context("trusted browser path is not valid UTF-8")?,
            )?;
            if !trusted
                .iter()
                .any(|path: &String| path.eq_ignore_ascii_case(&candidate))
            {
                trusted.push(candidate);
            }
        }
    }
    if trusted.is_empty() {
        anyhow::bail!("no trusted Chrome or Edge installation was found");
    }
    Ok(trusted)
}

fn known_folder_path(folder_id: &windows_sys::core::GUID, label: &str) -> Result<PathBuf> {
    let mut raw_path = null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder_id, 0, null_mut(), &mut raw_path) };
    if status < 0 {
        anyhow::bail!(
            "SHGetKnownFolderPath({label}) failed: {:#010x}",
            status as u32
        );
    }
    let decoded = wide_pointer_string(raw_path);
    unsafe {
        CoTaskMemFree(raw_path.cast());
    }
    decoded.map(PathBuf::from)
}

fn std_handle(kind: u32, label: &str) -> Result<HANDLE> {
    let handle = unsafe { GetStdHandle(kind) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("native-messaging {label} is not an inherited pipe handle");
    }
    Ok(handle)
}

fn native_messaging_stdio_peer_process_ids(stdin: HANDLE, stdout: HANDLE) -> Result<(u32, u32)> {
    let mut stdin_client_process_id = 0;
    check_win32(
        unsafe { GetNamedPipeClientProcessId(stdin, &mut stdin_client_process_id) },
        "GetNamedPipeClientProcessId(native-messaging stdin)",
    )?;
    let mut stdout_server_process_id = 0;
    check_win32(
        unsafe { GetNamedPipeServerProcessId(stdout, &mut stdout_server_process_id) },
        "GetNamedPipeServerProcessId(native-messaging stdout)",
    )?;
    Ok((stdin_client_process_id, stdout_server_process_id))
}

fn expected_native_shim_path() -> Result<std::path::PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .context("LOCALAPPDATA is unavailable for native shim authentication")?;
    let path = Path::new(&local_app_data)
        .join("vaultkern-runtime")
        .join("vaultkern-runtime.exe");
    let path = std::fs::canonicalize(&path).context("canonicalize installed native shim path")?;
    Ok(path)
}

fn canonical_windows_path(path: &str) -> Result<String> {
    std::fs::canonicalize(path)?
        .to_str()
        .map(str::to_owned)
        .context("canonical Windows path is not valid UTF-8")
}

fn process_package_identity(process: HANDLE) -> Result<Option<ProcessPackageIdentity>> {
    let mut required = 0;
    let status = unsafe { GetPackageId(process, &mut required, null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if status != ERROR_INSUFFICIENT_BUFFER || required < size_of::<PACKAGE_ID>() as u32 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("query resident IPC peer package ID size");
    }

    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let status = unsafe { GetPackageId(process, &mut required, storage.as_mut_ptr().cast::<u8>()) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("query resident IPC peer package ID");
    }
    let package = unsafe { &*storage.as_ptr().cast::<PACKAGE_ID>() };
    let name = wide_pointer_string(package.name).context("decode package name")?;
    let publisher = wide_pointer_string(package.publisher).context("decode package publisher")?;
    let publisher_id =
        wide_pointer_string(package.publisherId).context("decode package publisher ID")?;
    let family_name = process_package_string(process, GetPackageFamilyName, "package family")?;
    let full_name = process_package_string(process, GetPackageFullName, "package full name")?;

    Ok(Some(ProcessPackageIdentity {
        name,
        publisher,
        publisher_id,
        family_name,
        full_name,
    }))
}

fn process_package_string(
    process: HANDLE,
    query: unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32,
    label: &str,
) -> Result<String> {
    let mut required = 0;
    let status = unsafe { query(process, &mut required, null_mut()) };
    if status != ERROR_INSUFFICIENT_BUFFER || required <= 1 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("query resident IPC peer {label} size"));
    }
    let mut value = vec![0_u16; required as usize];
    let status = unsafe { query(process, &mut required, value.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("query resident IPC peer {label}"));
    }
    value.truncate(required.saturating_sub(1) as usize);
    String::from_utf16(&value).with_context(|| format!("{label} is not valid UTF-16"))
}

fn registered_package_evidence(package_full_name: &str) -> Result<RegisteredPackageEvidence> {
    use windows::Management::Deployment::PackageManager;
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize};
    use windows::core::HSTRING;

    let _apartment = match unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
        Ok(()) => WinRtApartment { initialized: true },
        Err(error) if error.code() == RPC_E_CHANGED_MODE => WinRtApartment { initialized: false },
        Err(error) => return Err(error).context("initialize WinRT for package authentication"),
    };
    let manager = PackageManager::new().context("activate Windows package manager")?;
    let package = manager
        .FindPackageByPackageFullName(&HSTRING::from(package_full_name))
        .context("find resident IPC peer package registration")?;
    if !package
        .Status()
        .and_then(|status| status.VerifyIsOK())
        .context("verify resident IPC peer package status")?
    {
        anyhow::bail!("resident IPC peer package status is not healthy");
    }
    let signature_kind = package
        .SignatureKind()
        .context("query resident IPC peer package signature kind")?
        .0;
    let is_development_mode = package
        .IsDevelopmentMode()
        .context("query resident IPC peer package development mode")?;
    let install_root = package
        .InstalledLocation()
        .and_then(|location| location.Path())
        .context("query resident IPC peer package install root")?
        .to_string_lossy();
    Ok(RegisteredPackageEvidence {
        signature_kind,
        is_development_mode,
        install_root,
    })
}

struct WinRtApartment {
    initialized: bool,
}

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                windows::Win32::System::WinRT::RoUninitialize();
            }
        }
    }
}

fn authenticode_identity_for_file(path: &Path) -> Result<AuthenticodeIdentity> {
    let path = path
        .to_str()
        .context("signed executable path is not valid UTF-8")?;
    let path = wide_nul(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: null_mut(),
        pgKnownSubject: null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 {
        close_wintrust_state(&mut trust_data, &mut action);
        anyhow::bail!(
            "WinVerifyTrust rejected the resident IPC peer: {:#010x}",
            status as u32
        );
    }

    let identity = unsafe { authenticode_identity_from_state(trust_data.hWVTStateData) };
    close_wintrust_state(&mut trust_data, &mut action);
    identity
}

fn close_wintrust_state(trust_data: &mut WINTRUST_DATA, action: &mut windows_sys::core::GUID) {
    if trust_data.hWVTStateData.is_null() {
        return;
    }
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            null_mut(),
            action,
            (trust_data as *mut WINTRUST_DATA).cast(),
        );
    }
    trust_data.hWVTStateData = null_mut();
}

unsafe fn authenticode_identity_from_state(state: HANDLE) -> Result<AuthenticodeIdentity> {
    let provider_data = unsafe { WTHelperProvDataFromStateData(state) };
    if provider_data.is_null() {
        anyhow::bail!("WinVerifyTrust returned no provider data");
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider_data, 0, 0, 0) };
    if signer.is_null() {
        anyhow::bail!("WinVerifyTrust returned no signer chain");
    }
    let provider_cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_cert.is_null() {
        anyhow::bail!("WinVerifyTrust returned no signer certificate");
    }
    let certificate = unsafe { (*provider_cert).pCert };
    if certificate.is_null() || unsafe { (*certificate).pCertInfo }.is_null() {
        anyhow::bail!("WinVerifyTrust returned an incomplete signer certificate");
    }

    let cert_info = unsafe { &*(*certificate).pCertInfo };
    let subject = certificate_subject(&cert_info.Subject)?;
    let organization = certificate_name_attribute(certificate, szOID_ORGANIZATION_NAME);
    let sha256_thumbprint = certificate_sha256_thumbprint(certificate)?;
    let machine_chain_trusted = certificate_has_local_machine_authenticode_chain(certificate)?;
    Ok(AuthenticodeIdentity {
        subject,
        organization,
        sha256_thumbprint,
        machine_chain_trusted,
    })
}

fn certificate_has_local_machine_authenticode_chain(
    certificate: *const CERT_CONTEXT,
) -> Result<bool> {
    const HCCE_LOCAL_MACHINE: HCERTCHAINENGINE = 1_usize as HCERTCHAINENGINE;

    let chain_parameters = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain = null_mut();
    check_win32(
        unsafe {
            CertGetCertificateChain(
                HCCE_LOCAL_MACHINE,
                certificate,
                null_mut(),
                (*certificate).hCertStore,
                &chain_parameters,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,
                null_mut(),
                &mut chain,
            )
        },
        "CertGetCertificateChain(LocalMachine)",
    )?;
    let chain = CertificateChainGuard(chain);
    let policy_parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        dwFlags: CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS,
        ..Default::default()
    };
    let mut policy_status = CERT_CHAIN_POLICY_STATUS {
        cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    check_win32(
        unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_AUTHENTICODE,
                chain.0,
                &policy_parameters,
                &mut policy_status,
            )
        },
        "CertVerifyCertificateChainPolicy(AuthentiCode, LocalMachine)",
    )?;
    Ok(policy_status.dwError == 0)
}

struct CertificateChainGuard(*mut windows_sys::Win32::Security::Cryptography::CERT_CHAIN_CONTEXT);

impl Drop for CertificateChainGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertFreeCertificateChain(self.0);
            }
        }
    }
}

fn certificate_subject(
    subject: &windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Result<String> {
    let encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    let required = unsafe { CertNameToStrW(encoding, subject, CERT_X500_NAME_STR, null_mut(), 0) };
    if required <= 1 {
        anyhow::bail!("signer certificate has no subject");
    }
    let mut value = vec![0_u16; required as usize];
    let written = unsafe {
        CertNameToStrW(
            encoding,
            subject,
            CERT_X500_NAME_STR,
            value.as_mut_ptr(),
            required,
        )
    };
    if written != required {
        anyhow::bail!("decode signer certificate subject failed");
    }
    value.truncate(written.saturating_sub(1) as usize);
    String::from_utf16(&value).context("signer certificate subject is not valid UTF-16")
}

fn certificate_name_attribute(
    certificate: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    attribute_oid: windows_sys::core::PCSTR,
) -> Option<String> {
    let required = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            attribute_oid.cast(),
            null_mut(),
            0,
        )
    };
    if required <= 1 {
        return None;
    }
    let mut value = vec![0_u16; required as usize];
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            attribute_oid.cast(),
            value.as_mut_ptr(),
            required,
        )
    };
    if written != required {
        return None;
    }
    value.truncate(written.saturating_sub(1) as usize);
    String::from_utf16(&value).ok()
}

fn certificate_sha256_thumbprint(
    certificate: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Result<String> {
    let mut required = 0;
    check_win32(
        unsafe {
            CertGetCertificateContextProperty(
                certificate,
                CERT_SHA256_HASH_PROP_ID,
                null_mut(),
                &mut required,
            )
        },
        "CertGetCertificateContextProperty(SHA256 size)",
    )?;
    if required != 32 {
        anyhow::bail!("signer certificate returned an invalid SHA-256 thumbprint length");
    }
    let mut hash = vec![0_u8; required as usize];
    check_win32(
        unsafe {
            CertGetCertificateContextProperty(
                certificate,
                CERT_SHA256_HASH_PROP_ID,
                hash.as_mut_ptr().cast(),
                &mut required,
            )
        },
        "CertGetCertificateContextProperty(SHA256)",
    )?;
    Ok(hash.iter().map(|byte| format!("{byte:02X}")).collect())
}

fn process_image_path(process: HANDLE) -> Result<String> {
    let mut path = vec![0_u16; 32_768];
    let mut length = path.len() as u32;
    check_win32(
        unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) },
        "QueryFullProcessImageNameW",
    )?;
    path.truncate(length as usize);
    String::from_utf16(&path).context("process image path is not valid UTF-16")
}

fn wide_pointer_string(value: *const u16) -> Result<String> {
    if value.is_null() {
        anyhow::bail!("Windows returned a null string pointer");
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .context("Windows string is not valid UTF-16")
}

fn open_process(process_id: u32) -> Result<HandleGuard> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(HandleGuard(process))
    }
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn check_win32(success: i32, operation: &str) -> Result<()> {
    if success == 0 {
        Err(std::io::Error::last_os_error()).with_context(|| format!("{operation} failed"))
    } else {
        Ok(())
    }
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    const TEST_CHROME_PATH: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const TEST_USER_CHROME_PATH: &str =
        r"C:\Users\alice\AppData\Local\Google\Chrome\Application\chrome.exe";

    fn trusted_test_browser_paths() -> Vec<String> {
        vec![TEST_CHROME_PATH.into(), TEST_USER_CHROME_PATH.into()]
    }

    fn google_browser(path: &str) -> BrowserParentIdentity {
        BrowserParentIdentity {
            executable_name: "chrome.exe".into(),
            executable_path: path.into(),
            signer: AuthenticodeIdentity {
                subject: "CN=Google LLC, O=Google LLC".into(),
                organization: Some("Google LLC".into()),
                sha256_thumbprint: "33".repeat(32),
                machine_chain_trusted: true,
            },
        }
    }

    fn signer(thumbprint_byte: &str) -> AuthenticodeIdentity {
        AuthenticodeIdentity {
            subject: RESIDENT_PACKAGE_PUBLISHER.into(),
            organization: Some("VaultKern Development".into()),
            sha256_thumbprint: thumbprint_byte.repeat(32),
            machine_chain_trusted: false,
        }
    }

    fn server_identity() -> ResidentServerIdentity {
        let root = r"C:\Program Files\WindowsApps\VaultKern.Windows_0.1.0.0_x64__bf7at9bmb1e94";
        ResidentServerIdentity {
            executable_name: RESIDENT_EXECUTABLE_NAME.into(),
            package_name: Some(RESIDENT_PACKAGE_NAME.into()),
            package_publisher: Some(RESIDENT_PACKAGE_PUBLISHER.into()),
            package_publisher_id: Some(RESIDENT_PACKAGE_PUBLISHER_ID.into()),
            package_family_name: Some(RESIDENT_PACKAGE_FAMILY_NAME.into()),
            package_signer: Some(signer("11")),
            package_signature_kind: Some(1),
            package_is_development_mode: Some(false),
            package_install_root: Some(root.into()),
            executable_path: Some(format!(r"{root}\{RESIDENT_EXECUTABLE_NAME}")),
        }
    }

    #[test]
    fn same_user_unpacked_process_cannot_impersonate_resident_server() {
        let mut peer = server_identity();
        peer.package_name = None;
        peer.package_publisher = None;
        peer.package_publisher_id = None;
        peer.package_family_name = None;

        let error = authenticate_resident_server_identity(&peer)
            .expect_err("an unpackaged same-user process must not authenticate as the app");
        assert!(error.to_string().contains("package identity"));
    }

    #[test]
    fn lookalike_package_cannot_impersonate_resident_server() {
        let mut peer = server_identity();
        peer.package_publisher = Some("CN=Attacker".into());
        peer.package_publisher_id = Some("attacker00000".into());
        peer.package_family_name = Some("VaultKern.Windows_attacker00000".into());

        authenticate_resident_server_identity(&peer)
            .expect_err("a package from a different publisher must not authenticate as the app");
    }

    #[test]
    fn loose_package_without_a_package_signature_is_rejected() {
        let mut peer = server_identity();
        peer.package_signer = None;
        peer.package_signature_kind = Some(0);
        peer.package_is_development_mode = Some(true);

        let error = authenticate_resident_server_identity(&peer)
            .expect_err("a loose package without AppxSignature.p7x must fail closed");
        assert!(error.to_string().contains("package signature"));
    }

    #[test]
    fn copied_package_signature_cannot_upgrade_a_loose_development_package() {
        let mut peer = server_identity();
        peer.package_signature_kind = Some(0);
        peer.package_is_development_mode = Some(true);

        let error = authenticate_resident_server_identity(&peer)
            .expect_err("a copied p7x must not authenticate a loose development package");
        assert!(error.to_string().contains("signed installed package"));
    }

    #[test]
    fn process_image_must_be_the_registered_package_executable() {
        let mut peer = server_identity();
        peer.executable_path = Some(r"C:\Users\alice\vaultkern-windows.exe".into());

        let error = authenticate_resident_server_identity(&peer)
            .expect_err("a copied executable outside the registered package root must fail");
        assert!(error.to_string().contains("install root"));
    }

    #[test]
    fn package_manager_identifies_the_current_loose_registration_as_development_only() {
        let Ok(evidence) =
            registered_package_evidence("VaultKern.Windows_0.1.0.0_x64__bf7at9bmb1e94")
        else {
            return;
        };

        assert_eq!(evidence.signature_kind, 0);
        assert!(evidence.is_development_mode);
    }

    #[test]
    fn matching_subjects_with_different_certificate_keys_are_rejected() {
        let error = authenticate_matching_signers(&signer("11"), &signer("22"))
            .expect_err("matching Subjects must not substitute for the same signing key");
        assert!(error.to_string().contains("thumbprint"));
    }

    #[test]
    fn wintrust_rejects_the_unsigned_test_binary() {
        let executable = std::env::current_exe().expect("current test executable");
        let error = authenticode_identity_for_file(&executable)
            .expect_err("the unsigned Rust test binary must fail WinVerifyTrust");
        assert!(error.to_string().contains("WinVerifyTrust"));
    }

    #[test]
    fn wintrust_extracts_the_signer_from_an_installed_package_signature() {
        let signature = Path::new(
            r"C:\Windows\SystemApps\Microsoft.Windows.FilePicker_cw5n1h2txyewy\AppxSignature.p7x",
        );
        if !signature.exists() {
            return;
        }

        let identity = authenticode_identity_for_file(signature)
            .expect("verify installed Windows package signature");

        assert!(!identity.subject.is_empty());
        assert!(valid_sha256_thumbprint(&identity));
    }

    #[test]
    fn wintrust_browser_publisher_evidence_matches_the_explicit_allowlist() {
        let trusted_paths = trusted_browser_executable_paths()
            .expect("resolve OS known-folder browser install paths");
        for (path, expected_organization) in [
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "Google LLC",
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                "Microsoft Corporation",
            ),
        ] {
            let path = Path::new(path);
            if !path.exists() {
                continue;
            }
            let identity = authenticode_identity_for_file(path)
                .expect("verify installed browser Authenticode signature");
            assert_eq!(
                identity.organization.as_deref(),
                Some(expected_organization)
            );
            assert!(valid_sha256_thumbprint(&identity));
            assert!(
                identity.machine_chain_trusted,
                "installed browser signer must chain to LocalMachine trust: {}",
                path.display()
            );
            let canonical_path = canonical_windows_path(
                path.to_str()
                    .expect("installed browser path is valid UTF-8"),
            )
            .expect("canonicalize installed browser path");
            let browser = BrowserParentIdentity {
                executable_name: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("browser executable name")
                    .into(),
                executable_path: canonical_path,
                signer: identity,
            };
            authenticate_browser_identity(&browser, &trusted_paths)
                .expect("installed browser satisfies native-messaging policy");
        }
    }

    #[test]
    fn production_server_identity_rejects_an_unpacked_process() {
        let peer = resident_server_identity_for_process(unsafe { GetCurrentProcessId() })
            .expect("inspect current test process");
        authenticate_resident_server_identity(&peer)
            .expect_err("the unpackaged test process must not authenticate as the app");
    }

    #[test]
    fn unsigned_same_user_process_cannot_impersonate_native_shim() {
        let path = r"C:\Users\alice\AppData\Local\vaultkern-runtime\vaultkern-runtime.exe";
        let peer = NativeShimIdentity {
            executable_path: path.into(),
            signer: None,
        };

        let error = authenticate_native_shim_identity(&peer, path, RESIDENT_PACKAGE_PUBLISHER)
            .expect_err("an unsigned direct client must not authenticate as the native shim");
        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn production_native_shim_identity_rejects_the_unsigned_test_process() {
        let error = native_shim_identity_for_process(unsafe { GetCurrentProcessId() })
            .expect_err("the unsigned test process must not authenticate as the native shim");

        assert!(
            error.to_string().contains("signature")
                || error.to_string().contains("executable path"),
            "unexpected authentication error: {error:#}"
        );
    }

    #[test]
    fn server_accepts_a_trusted_shim_without_rechecking_browser_parent_topology() {
        let path = r"C:\Users\alice\AppData\Local\vaultkern-runtime\vaultkern-runtime.exe";
        let peer = NativeShimIdentity {
            executable_path: path.into(),
            signer: Some(signer("11")),
        };

        authenticate_native_shim_identity(&peer, path, RESIDENT_PACKAGE_PUBLISHER)
            .expect("the signed shim self-authenticates stdio before connecting to the server");
    }

    #[test]
    fn trusted_but_non_browser_publisher_cannot_launch_the_native_shim() {
        let browser = BrowserParentIdentity {
            executable_name: "chrome.exe".into(),
            executable_path: TEST_CHROME_PATH.into(),
            signer: AuthenticodeIdentity {
                subject: "CN=Attacker, O=Attacker Ltd".into(),
                organization: Some("Attacker Ltd".into()),
                sha256_thumbprint: "33".repeat(32),
                machine_chain_trusted: true,
            },
        };

        let error = authenticate_browser_identity(&browser, &trusted_test_browser_paths())
            .expect_err("a trusted non-browser publisher must not impersonate Chrome");
        assert!(error.to_string().contains("browser publisher"));
    }

    #[test]
    fn per_user_browser_requires_a_local_machine_trusted_publisher_chain() {
        let mut browser = google_browser(TEST_USER_CHROME_PATH);
        browser.signer.machine_chain_trusted = false;

        let error = authenticate_browser_identity(&browser, &trusted_test_browser_paths())
            .expect_err("CurrentUser-only trust must not authenticate a per-user browser");
        assert!(error.to_string().contains("LocalMachine"));

        browser.signer.machine_chain_trusted = true;
        authenticate_browser_identity(&browser, &trusted_test_browser_paths())
            .expect("a machine-trusted per-user browser remains supported");
    }

    #[test]
    fn native_messaging_channel_requires_one_authenticated_pipe_actor() {
        let trusted_paths = trusted_test_browser_paths();
        let mismatched = NativeMessagingChannelIdentity {
            stdin_client_process_id: 101,
            stdout_server_process_id: 202,
            actor: google_browser(TEST_CHROME_PATH),
        };
        let error = authenticate_native_messaging_channel_identity(&mismatched, &trusted_paths)
            .expect_err("different stdin/stdout peers must not authenticate");
        assert!(error.to_string().contains("one browser pipe peer"));

        let matched = NativeMessagingChannelIdentity {
            stdin_client_process_id: 101,
            stdout_server_process_id: 101,
            actor: google_browser(TEST_CHROME_PATH),
        };
        authenticate_native_messaging_channel_identity(&matched, &trusted_paths)
            .expect("one trusted browser owning both pipe endpoints authenticates");
    }

    #[test]
    fn native_messaging_anonymous_pipe_child_reports_peer_pids() {
        if std::env::var_os("VAULTKERN_NATIVE_PIPE_TEST_CHILD").is_none() {
            return;
        }
        let stdin = std_handle(STD_INPUT_HANDLE, "test child stdin").expect("piped stdin");
        let stdout = std_handle(STD_OUTPUT_HANDLE, "test child stdout").expect("piped stdout");
        let (stdin_client, stdout_server) =
            native_messaging_stdio_peer_process_ids(stdin, stdout).expect("query pipe peer PIDs");
        eprintln!("VAULTKERN_NATIVE_PIPE_PEERS={stdin_client},{stdout_server}");
    }

    #[test]
    fn anonymous_native_messaging_pipes_identify_the_spawning_process() {
        let parent_process_id = unsafe { GetCurrentProcessId() };
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("native_messaging_anonymous_pipe_child_reports_peer_pids")
            .arg("--nocapture")
            .env("VAULTKERN_NATIVE_PIPE_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run anonymous-pipe child test");
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "VAULTKERN_NATIVE_PIPE_PEERS={parent_process_id},{parent_process_id}"
            )),
            "anonymous pipe peer evidence was missing: {stderr}"
        );
    }
}
