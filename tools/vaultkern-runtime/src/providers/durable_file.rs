use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::sync::{Arc, Mutex};

static UNIQUE_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static PROCESS_NONCE: LazyLock<String> = LazyLock::new(process_nonce);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableFaultPoint {
    BeforeTempPublishValidation,
    TempCreated,
    TempWritten,
    TempSynced,
    TempReadbackVerified,
    BackupPublished,
    BeforeTargetReplace,
    TargetReplaced,
    ParentSynced,
    Cleanup,
    GenerationTempCreated,
    GenerationTempWritten,
    GenerationTempSynced,
    GenerationReadbackVerified,
    BeforeGenerationPublish,
    GenerationPublished,
    GenerationParentSynced,
    ManifestTempCreated,
    ManifestTempWritten,
    ManifestTempSynced,
    ManifestReadbackVerified,
    BeforeManifestReplace,
    ManifestReplaced,
    ManifestParentSynced,
    CacheManifestDurable,
}

#[derive(Clone, Default)]
pub(crate) struct DurableFaultInjector {
    #[cfg(test)]
    action: Option<Arc<Mutex<Option<DurableFaultAction>>>>,
    #[cfg(test)]
    callback: Option<Arc<Mutex<Option<DurableFaultCallback>>>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum DurableFaultAction {
    Fail(DurableFaultPoint),
    Crash(DurableFaultPoint),
}

#[cfg(test)]
type DurableFaultCallback = (DurableFaultPoint, Arc<dyn Fn() + Send + Sync + 'static>);

impl std::fmt::Debug for DurableFaultInjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableFaultInjector")
            .finish_non_exhaustive()
    }
}

impl DurableFaultInjector {
    pub(crate) fn check(&self, point: DurableFaultPoint) -> io::Result<()> {
        #[cfg(test)]
        if let Some(action) = &self.action {
            let selected = {
                let mut action = action.lock().expect("durable fault lock");
                match *action {
                    Some(DurableFaultAction::Fail(selected))
                    | Some(DurableFaultAction::Crash(selected))
                        if selected == point =>
                    {
                        action.take()
                    }
                    _ => None,
                }
            };
            match selected {
                Some(DurableFaultAction::Fail(_)) => {
                    return Err(io::Error::other(format!(
                        "injected durable file failure at {point:?}"
                    )));
                }
                Some(DurableFaultAction::Crash(_)) => crash_process_now(),
                None => {}
            }
        }
        #[cfg(test)]
        if let Some(callback) = &self.callback {
            let selected = {
                let mut callback = callback.lock().expect("durable callback lock");
                if callback
                    .as_ref()
                    .is_some_and(|(selected, _)| *selected == point)
                {
                    callback.take().map(|(_, callback)| callback)
                } else {
                    None
                }
            };
            if let Some(callback) = selected {
                callback();
            }
        }
        let _ = point;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_once(point: DurableFaultPoint) -> Self {
        Self {
            action: Some(Arc::new(Mutex::new(Some(DurableFaultAction::Fail(point))))),
            callback: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn crash_once(point: DurableFaultPoint) -> Self {
        Self {
            action: Some(Arc::new(Mutex::new(Some(DurableFaultAction::Crash(point))))),
            callback: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn run_once(
        point: DurableFaultPoint,
        callback: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            action: None,
            callback: Some(Arc::new(Mutex::new(Some((point, Arc::new(callback)))))),
        }
    }
}

#[cfg(all(test, unix))]
fn crash_process_now() -> ! {
    unsafe {
        libc::raise(libc::SIGKILL);
        libc::_exit(86);
    }
}

#[cfg(all(test, windows))]
fn crash_process_now() -> ! {
    unsafe {
        windows_sys::Win32::System::Threading::TerminateProcess(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            86,
        );
    }
    std::process::abort()
}

#[cfg(all(test, not(any(unix, windows))))]
fn crash_process_now() -> ! {
    std::process::abort()
}

#[cfg(test)]
impl DurableFaultPoint {
    pub(crate) fn from_test_name(name: &str) -> Option<Self> {
        Some(match name {
            "BeforeTempPublishValidation" => Self::BeforeTempPublishValidation,
            "TempCreated" => Self::TempCreated,
            "TempWritten" => Self::TempWritten,
            "TempSynced" => Self::TempSynced,
            "TempReadbackVerified" => Self::TempReadbackVerified,
            "BackupPublished" => Self::BackupPublished,
            "BeforeTargetReplace" => Self::BeforeTargetReplace,
            "TargetReplaced" => Self::TargetReplaced,
            "ParentSynced" => Self::ParentSynced,
            "Cleanup" => Self::Cleanup,
            "GenerationTempCreated" => Self::GenerationTempCreated,
            "GenerationTempWritten" => Self::GenerationTempWritten,
            "GenerationTempSynced" => Self::GenerationTempSynced,
            "GenerationReadbackVerified" => Self::GenerationReadbackVerified,
            "BeforeGenerationPublish" => Self::BeforeGenerationPublish,
            "GenerationPublished" => Self::GenerationPublished,
            "GenerationParentSynced" => Self::GenerationParentSynced,
            "ManifestTempCreated" => Self::ManifestTempCreated,
            "ManifestTempWritten" => Self::ManifestTempWritten,
            "ManifestTempSynced" => Self::ManifestTempSynced,
            "ManifestReadbackVerified" => Self::ManifestReadbackVerified,
            "BeforeManifestReplace" => Self::BeforeManifestReplace,
            "ManifestReplaced" => Self::ManifestReplaced,
            "ManifestParentSynced" => Self::ManifestParentSynced,
            "CacheManifestDurable" => Self::CacheManifestDurable,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ExclusiveFileLock {
    file: File,
}

impl ExclusiveFileLock {
    pub(crate) fn acquire(path: &Path) -> io::Result<Self> {
        let file = open_validated_lock_file(path)?;
        file.lock()?;
        Ok(Self { file })
    }

    pub(crate) fn acquire_with_timeout(path: &Path, timeout: Duration) -> io::Result<Self> {
        let started = Instant::now();
        let file = open_validated_lock_file(path)?;
        let mut first_attempt = true;
        loop {
            if (!first_attempt || !timeout.is_zero()) && started.elapsed() >= timeout {
                return Err(lock_timeout_error(path));
            }
            first_attempt = false;
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(fs::TryLockError::WouldBlock) => {
                    let elapsed = started.elapsed();
                    if elapsed >= timeout {
                        return Err(lock_timeout_error(path));
                    }
                    std::thread::sleep(Duration::from_millis(10).min(timeout - elapsed));
                }
                Err(fs::TryLockError::Error(error)) => return Err(error),
            }
        }
    }
}

fn lock_timeout_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("timed out acquiring durable lock {}", path.display()),
    )
}

fn open_validated_lock_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable lock parent is not a real directory",
            ));
        }
        reject_reparse_point(&metadata)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.nlink() != 1
            || path_metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable lock path is not a private regular file",
            ));
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable lock path is owned by another user",
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(path)?;
        let information = windows_file_information(&file)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || information.nNumberOfLinks != 1
            || opened_file_identity(&file, &metadata)? != path_file_identity(path, &path_metadata)?
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable lock path is not a private regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable lock path is not a regular file",
            ));
        }
        Ok(file)
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TempWriteFaultPoints {
    pub created: DurableFaultPoint,
    pub written: DurableFaultPoint,
    pub synced: DurableFaultPoint,
    pub verified: DurableFaultPoint,
}

#[derive(Debug)]
pub(crate) struct PublishError {
    pub published: bool,
    pub target_conflict: bool,
    pub source: io::Error,
}

#[derive(Debug, Clone)]
pub(crate) enum TargetExpectation {
    Missing,
    Identity(DurableFileIdentity),
    IdentityAndContent {
        identity: DurableFileIdentity,
        content_sha256: String,
        size_bytes: u64,
        modified_at: Option<SystemTime>,
    },
}

#[derive(Debug)]
struct ReplaceError {
    published: bool,
    source: io::Error,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableFileIdentity {
    volume: u32,
    index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableFileIdentity {
    len: u64,
}

#[cfg(unix)]
pub(crate) fn opened_file_identity(
    _file: &File,
    metadata: &Metadata,
) -> io::Result<DurableFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Ok(DurableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
pub(crate) fn opened_file_identity(
    file: &File,
    _metadata: &Metadata,
) -> io::Result<DurableFileIdentity> {
    let information = windows_file_information(file)?;
    Ok(DurableFileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn opened_file_identity(
    _file: &File,
    metadata: &Metadata,
) -> io::Result<DurableFileIdentity> {
    Ok(DurableFileIdentity {
        len: metadata.len(),
    })
}

#[cfg(not(windows))]
pub(crate) fn path_file_identity(
    _path: &Path,
    metadata: &Metadata,
) -> io::Result<DurableFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DurableFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(any(unix, windows)))]
    Ok(DurableFileIdentity {
        len: metadata.len(),
    })
}

#[cfg(windows)]
pub(crate) fn path_file_identity(
    path: &Path,
    _metadata: &Metadata,
) -> io::Result<DurableFileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    opened_file_identity(&file, &file.metadata()?)
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(information)
    }
}

#[cfg(windows)]
fn reject_reparse_point(metadata: &Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable file is a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &Metadata) -> io::Result<()> {
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
pub(crate) fn durable_path(path: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let slash = b'\\' as u16;
    let alternate_slash = b'/' as u16;
    for value in &mut wide {
        if *value == alternate_slash {
            *value = slash;
        }
    }
    let verbatim_prefix = [slash, slash, b'?' as u16, slash];
    let device_prefix = [slash, slash, b'.' as u16, slash];
    if wide.starts_with(&verbatim_prefix) || wide.starts_with(&device_prefix) {
        return path.to_path_buf();
    }

    let prefixed = if wide.len() >= 3 && wide[1] == b':' as u16 && wide[2] == slash {
        verbatim_prefix.into_iter().chain(wide).collect::<Vec<_>>()
    } else if wide.starts_with(&[slash, slash]) {
        [
            slash,
            slash,
            b'?' as u16,
            slash,
            b'U' as u16,
            b'N' as u16,
            b'C' as u16,
            slash,
        ]
        .into_iter()
        .chain(wide.into_iter().skip(2))
        .collect::<Vec<_>>()
    } else {
        return path.to_path_buf();
    };
    PathBuf::from(OsString::from_wide(&prefixed))
}

#[cfg(not(windows))]
pub(crate) fn durable_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn process_nonce() -> String {
    let mut random = [0_u8; 16];
    if fill_random(&mut random).is_err() {
        let fallback = format!(
            "{}:{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos()),
            UNIQUE_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        random.copy_from_slice(&Sha256::digest(fallback.as_bytes())[..16]);
    }
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buffer)
}

#[cfg(windows)]
fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "BCryptGenRandom failed with status {status}"
        )))
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_random(_buffer: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no platform randomness source",
    ))
}

pub(crate) fn unique_sibling_path(target: &Path, marker: &str) -> io::Result<PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no parent"))?;
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?
        .to_string_lossy();
    for _ in 0..128 {
        let counter = UNIQUE_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.vaultkern.{marker}.{}.{}.{counter}",
            std::process::id(),
            PROCESS_NONCE.as_str(),
        ));
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => return Err(error),
            Ok(_) => continue,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique durable sidecar path",
    ))
}

#[derive(Debug)]
pub(crate) struct VerifiedTemp {
    path: PathBuf,
    file: Option<File>,
    identity: DurableFileIdentity,
    expected_sha256: String,
    expected_size: u64,
}

impl VerifiedTemp {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("verified temp file handle is available before publish")
    }

    pub(crate) fn discard(mut self) -> io::Result<()> {
        let path = self.path;
        drop(self.file.take());
        remove_if_exists(&path)
    }

    fn verify_for_publish(&mut self) -> io::Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable temp path is not a regular file",
            ));
        }
        reject_reparse_point(&path_metadata)?;
        if path_file_identity(&self.path, &path_metadata)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "durable temp path was replaced before publish",
            ));
        }

        self.verify_opened_contents()
    }

    fn verify_opened_contents(&mut self) -> io::Result<()> {
        let file = self.file.as_mut().ok_or_else(|| {
            io::Error::other("verified temp file handle is unavailable during verification")
        })?;
        file.sync_all()?;
        let before = file.metadata()?;
        if opened_file_identity(file, &before)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "durable temp handle identity changed",
            ));
        }
        file.rewind()?;
        let mut readback = Vec::with_capacity(self.expected_size as usize);
        file.read_to_end(&mut readback)?;
        let after = file.metadata()?;
        if opened_file_identity(file, &after)? != self.identity
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || readback.len() as u64 != self.expected_size
            || sha256_hex(&readback) != self.expected_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable temp changed after readback verification",
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn close_before_replace(&mut self) {
        drop(self.file.take());
    }

    #[cfg(windows)]
    fn reopen_published(&mut self, target: &Path) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        self.file = Some(options.open(target)?);
        Ok(())
    }
}

pub(crate) fn write_verified_temp(
    target: &Path,
    bytes: &[u8],
    faults: &DurableFaultInjector,
    points: TempWriteFaultPoints,
) -> io::Result<VerifiedTemp> {
    let mut opened = None;
    for _ in 0..128 {
        let path = unique_sibling_path(target, "tmp")?;
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                opened = Some((path, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (path, mut file) = opened.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique durable temp file",
        )
    })?;
    if let Err(error) = faults.check(points.created) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    let expected_sha256 = sha256_hex(bytes);
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        faults.check(points.written)?;
        file.sync_all()?;
        faults.check(points.synced)?;
        file.rewind()?;
        let mut readback = Vec::with_capacity(bytes.len());
        file.read_to_end(&mut readback)?;
        if readback.len() != bytes.len() || sha256_hex(&readback) != expected_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable temp readback did not match intended bytes",
            ));
        }
        faults.check(points.verified)
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    let verified_identity = (|| {
        let metadata = file.metadata()?;
        let identity = opened_file_identity(&file, &metadata)?;
        let path_metadata = fs::symlink_metadata(&path)?;
        if identity != path_file_identity(&path, &path_metadata)? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "durable temp path changed during initial verification",
            ));
        }
        Ok(identity)
    })();
    let identity = match verified_identity {
        Ok(identity) => identity,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
    };
    Ok(VerifiedTemp {
        path,
        file: Some(file),
        identity,
        expected_sha256,
        expected_size: bytes.len() as u64,
    })
}

pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    sync_directory(parent)
}

pub(crate) fn create_dir_all_durable(path: &Path) -> io::Result<()> {
    use std::path::Component;

    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private durable directory path is empty",
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private durable directory path cannot contain parent traversal",
                ));
            }
            Component::Normal(name) => current.push(name),
        }

        let mut created = false;
        let metadata = loop {
            match fs::symlink_metadata(&current) {
                Ok(metadata) => break metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let builder = fs::DirBuilder::new();
                    #[cfg(unix)]
                    let builder = {
                        let mut builder = builder;
                        use std::os::unix::fs::DirBuilderExt;
                        builder.mode(0o700);
                        builder
                    };
                    match builder.create(&current) {
                        Ok(()) => created = true,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private durable directory path contains a link or non-directory component",
            ));
        }
        reject_reparse_point(&metadata)?;
        validate_trusted_directory_component(&metadata)?;
        if created {
            sync_directory(&current)?;
            sync_parent(&current)?;
        }
    }

    validate_private_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_directory_component(metadata: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let owner = metadata.uid();
    let effective_user = unsafe { libc::geteuid() };
    if owner != effective_user && owner != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private durable directory ancestry is owned by an untrusted user",
        ));
    }
    let mode = metadata.mode();
    if mode & 0o022 != 0 && mode & libc::S_ISVTX == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private durable directory ancestry is writable without sticky protection",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_directory_component(_metadata: &Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private durable directory is owned by another user",
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private durable directory is group- or world-writable",
        ));
    }
    if mode != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        sync_directory(path)?;
        sync_parent(path)?;
    }
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.uid() != unsafe { libc::geteuid() }
        || final_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private durable directory permissions could not be enforced",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private durable directory is not a real directory",
        ));
    }
    reject_reparse_point(&metadata)
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
pub(crate) fn sync_directory(_path: &Path) -> io::Result<()> {
    // The published target is flushed explicitly. MoveFileExW also uses
    // WRITE_THROUGH when publishing to a previously missing target.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn publish_temp(
    mut temp: VerifiedTemp,
    target: &Path,
    target_expectation: TargetExpectation,
    backup: Option<&Path>,
    faults: &DurableFaultInjector,
    before_replace: DurableFaultPoint,
    after_replace: DurableFaultPoint,
    parent_sync: DurableFaultPoint,
) -> Result<(), PublishError> {
    if let Err(source) = faults
        .check(DurableFaultPoint::BeforeTempPublishValidation)
        .and_then(|_| temp.verify_for_publish())
    {
        let _ = temp.discard();
        return Err(PublishError {
            published: false,
            target_conflict: false,
            source,
        });
    }
    if let Err(source) = faults.check(before_replace) {
        let _ = temp.discard();
        return Err(PublishError {
            published: false,
            target_conflict: false,
            source,
        });
    }
    if let Err(source) = verify_target_expectation(target, target_expectation) {
        let _ = temp.discard();
        return Err(PublishError {
            published: false,
            target_conflict: true,
            source,
        });
    }
    // ReplaceFileW opens the replacement with no sharing mode, so its verified
    // handle must be closed for the duration of the path-based replacement.
    #[cfg(windows)]
    temp.close_before_replace();
    if let Err(error) = replace_file(temp.path(), target, backup) {
        if error.published {
            drop(temp);
        } else {
            let _ = temp.discard();
        }
        return Err(PublishError {
            published: error.published,
            target_conflict: false,
            source: error.source,
        });
    }
    let published_metadata = fs::symlink_metadata(target).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    reject_reparse_point(&published_metadata).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    if path_file_identity(target, &published_metadata).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })? != temp.identity
    {
        return Err(PublishError {
            published: true,
            target_conflict: false,
            source: io::Error::new(
                io::ErrorKind::WouldBlock,
                "published target is not the verified temp generation",
            ),
        });
    }
    #[cfg(windows)]
    temp.reopen_published(target)
        .map_err(|source| PublishError {
            published: true,
            target_conflict: false,
            source,
        })?;
    faults.check(after_replace).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    temp.verify_opened_contents()
        .map_err(|source| PublishError {
            published: true,
            target_conflict: false,
            source,
        })?;
    sync_published_target(target).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    faults.check(parent_sync).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    sync_parent(target).map_err(|source| PublishError {
        published: true,
        target_conflict: false,
        source,
    })?;
    Ok(())
}

fn verify_target_expectation(target: &Path, expectation: TargetExpectation) -> io::Result<()> {
    match expectation {
        TargetExpectation::Missing => match fs::symlink_metadata(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "durable publish target appeared after it was checked",
            )),
        },
        TargetExpectation::Identity(expected) => {
            let metadata = fs::symlink_metadata(target)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "durable publish target is not a regular file",
                ));
            }
            reject_reparse_point(&metadata)?;
            if path_file_identity(target, &metadata)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "durable publish target changed after its final CAS check",
                ));
            }
            Ok(())
        }
        TargetExpectation::IdentityAndContent {
            identity,
            content_sha256,
            size_bytes,
            modified_at,
        } => verify_target_content(target, identity, &content_sha256, size_bytes, modified_at),
    }
}

fn verify_target_content(
    target: &Path,
    expected_identity: DurableFileIdentity,
    expected_sha256: &str,
    expected_size: u64,
    expected_modified_at: Option<SystemTime>,
) -> io::Result<()> {
    let path_metadata = fs::symlink_metadata(target)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable CAS target is not a regular file",
        ));
    }
    reject_reparse_point(&path_metadata)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(target)?;
    let before = file.metadata()?;
    let opened_identity = opened_file_identity(&file, &before)?;
    if !before.is_file()
        || opened_identity != expected_identity
        || opened_identity != path_file_identity(target, &path_metadata)?
        || before.len() != expected_size
        || before.modified().ok() != expected_modified_at
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable CAS target metadata changed before publish",
        ));
    }

    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size.saturating_add(read as u64);
    }
    let actual_sha256: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let after = file.metadata()?;
    let final_path_metadata = fs::symlink_metadata(target)?;
    reject_reparse_point(&final_path_metadata)?;
    if size != expected_size
        || actual_sha256 != expected_sha256
        || opened_file_identity(&file, &after)? != expected_identity
        || path_file_identity(target, &final_path_metadata)? != expected_identity
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "durable CAS target content changed before publish",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temp: &Path, target: &Path, _backup: Option<&Path>) -> Result<(), ReplaceError> {
    fs::rename(temp, target).map_err(|source| ReplaceError {
        published: false,
        source,
    })
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsReplaceFileApi {
    MoveFileExWriteThrough,
    ReplaceFile,
}

#[cfg(windows)]
fn windows_replace_file_api(backup: Option<&Path>) -> WindowsReplaceFileApi {
    if backup.is_some() {
        WindowsReplaceFileApi::ReplaceFile
    } else {
        WindowsReplaceFileApi::MoveFileExWriteThrough
    }
}

#[cfg(windows)]
fn replace_file(temp: &Path, target: &Path, backup: Option<&Path>) -> Result<(), ReplaceError> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let target_wide = wide(target);
    let temp_wide = wide(temp);
    let backup_wide = backup.map(wide);
    let replacing_existing = target.exists();
    let result = unsafe {
        match windows_replace_file_api(backup) {
            WindowsReplaceFileApi::ReplaceFile => ReplaceFileW(
                target_wide.as_ptr(),
                temp_wide.as_ptr(),
                backup_wide
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                WINDOWS_REPLACE_FILE_FLAGS,
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            WindowsReplaceFileApi::MoveFileExWriteThrough => MoveFileExW(
                temp_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            ),
        }
    };
    if result == 0 {
        let source = io::Error::last_os_error();
        Err(ReplaceError {
            // Only the documented partial-failure states can have moved the
            // original or replacement. Preserve their recovery artifacts.
            published: windows_replace_failure_is_outcome_unknown(
                replacing_existing,
                backup.is_some(),
                source.raw_os_error(),
            ),
            source,
        })
    } else {
        Ok(())
    }
}

#[cfg(any(windows, test))]
const WINDOWS_REPLACE_FILE_FLAGS: u32 = 0;

#[cfg(any(windows, test))]
const WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT: i32 = 1176;
#[cfg(any(windows, test))]
const WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1177;

#[cfg(any(windows, test))]
fn windows_replace_failure_is_outcome_unknown(
    replacing_existing: bool,
    backup_supplied: bool,
    raw_os_error: Option<i32>,
) -> bool {
    replacing_existing
        && match raw_os_error {
            Some(WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT) => !backup_supplied,
            Some(WINDOWS_ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) => true,
            _ => false,
        }
}

#[cfg(not(windows))]
pub(crate) fn sync_published_target(_target: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn sync_published_target(target: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(target)?;
    let metadata = file.metadata()?;
    reject_reparse_point(&metadata)?;
    file.sync_all()
}

pub(crate) fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::{
        DurableFaultInjector, DurableFaultPoint, TempWriteFaultPoints, write_verified_temp,
    };
    use super::{ExclusiveFileLock, unique_sibling_path};
    use std::fs;
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn bounded_lock_times_out_under_contention_and_recovers_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("ledger.lock");
        let holder_path = lock_path.clone();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let held = ExclusiveFileLock::acquire(&holder_path).unwrap();
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(held);
        });
        acquired_rx.recv().unwrap();

        let started = Instant::now();
        let error = ExclusiveFileLock::acquire_with_timeout(&lock_path, Duration::from_millis(40))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_millis(250));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        ExclusiveFileLock::acquire_with_timeout(&lock_path, Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn bounded_lock_does_not_acquire_after_deadline_when_released_during_final_sleep() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("ledger.lock");
        let holder_path = lock_path.clone();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let (start_release_tx, start_release_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let held = ExclusiveFileLock::acquire(&holder_path).unwrap();
            acquired_tx.send(()).unwrap();
            start_release_rx.recv().unwrap();
            thread::sleep(Duration::from_millis(95));
            drop(held);
        });
        acquired_rx.recv().unwrap();

        let started = Instant::now();
        start_release_tx.send(()).unwrap();
        let error = ExclusiveFileLock::acquire_with_timeout(&lock_path, Duration::from_millis(100))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_millis(300));
        holder.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_lock_rejects_symlink_parent_like_blocking_acquisition() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        let linked_parent = dir.path().join("linked");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let lock_path = linked_parent.join("ledger.lock");

        let blocking = ExclusiveFileLock::acquire(&lock_path).unwrap_err();
        let bounded =
            ExclusiveFileLock::acquire_with_timeout(&lock_path, Duration::from_millis(40))
                .unwrap_err();

        assert_eq!(blocking.kind(), io::ErrorKind::Unsupported);
        assert_eq!(bounded.kind(), blocking.kind());
    }

    #[cfg(windows)]
    #[test]
    fn bounded_lock_rejects_reparse_parent_like_blocking_acquisition() {
        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        let linked_parent = dir.path().join("linked");
        fs::create_dir(&real_parent).unwrap();
        let status = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&linked_parent)
            .arg(&real_parent)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "could not create test directory junction");
        let lock_path = linked_parent.join("ledger.lock");

        let blocking = ExclusiveFileLock::acquire(&lock_path).unwrap_err();
        let bounded =
            ExclusiveFileLock::acquire_with_timeout(&lock_path, Duration::from_millis(40))
                .unwrap_err();

        assert_eq!(blocking.kind(), io::ErrorKind::Unsupported);
        assert_eq!(bounded.kind(), blocking.kind());
    }

    #[test]
    fn sidecar_names_use_a_process_nonce_and_skip_existing_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault.kdbx");
        fs::write(&target, b"target").unwrap();
        let first = unique_sibling_path(&target, "tmp").unwrap();
        fs::write(&first, b"orphan").unwrap();

        let second = unique_sibling_path(&target, "tmp").unwrap();

        assert_ne!(first, second);
        assert!(!second.exists());
        let name = second.file_name().unwrap().to_string_lossy();
        assert!(name.contains(&format!(".{}.", std::process::id())));
    }

    #[cfg(unix)]
    #[test]
    fn verified_temp_is_owner_only_before_metadata_is_copied() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault.kdbx");
        let temp = write_verified_temp(
            &target,
            b"candidate",
            &DurableFaultInjector::default(),
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .unwrap();

        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        temp.discard().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_publish_closes_and_reopens_the_verified_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ledger.json");
        fs::write(&target, b"old").unwrap();
        let metadata = fs::symlink_metadata(&target).unwrap();
        let identity = super::path_file_identity(&target, &metadata).unwrap();
        let temp = write_verified_temp(
            &target,
            b"new",
            &DurableFaultInjector::default(),
            TempWriteFaultPoints {
                created: DurableFaultPoint::TempCreated,
                written: DurableFaultPoint::TempWritten,
                synced: DurableFaultPoint::TempSynced,
                verified: DurableFaultPoint::TempReadbackVerified,
            },
        )
        .unwrap();

        super::publish_temp(
            temp,
            &target,
            super::TargetExpectation::Identity(identity),
            None,
            &DurableFaultInjector::default(),
            DurableFaultPoint::BeforeTargetReplace,
            DurableFaultPoint::TargetReplaced,
            DurableFaultPoint::ParentSynced,
        )
        .unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[cfg(windows)]
    #[test]
    fn windows_backup_free_publication_uses_write_through_move() {
        assert_eq!(
            super::windows_replace_file_api(None),
            super::WindowsReplaceFileApi::MoveFileExWriteThrough
        );
        assert_eq!(
            super::windows_replace_file_api(Some(std::path::Path::new("backup"))),
            super::WindowsReplaceFileApi::ReplaceFile
        );
    }

    #[test]
    fn windows_replace_failure_classification_preserves_only_partial_failure_artifacts() {
        assert_eq!(super::WINDOWS_REPLACE_FILE_FLAGS, 0);
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            false,
            false,
            Some(1176)
        ));
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            true,
            false,
            Some(5)
        ));
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            true,
            false,
            Some(32)
        ));
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            true,
            false,
            Some(1175)
        ));
        assert!(super::windows_replace_failure_is_outcome_unknown(
            true,
            false,
            Some(1176)
        ));
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            true,
            true,
            Some(1176)
        ));
        assert!(super::windows_replace_failure_is_outcome_unknown(
            true,
            false,
            Some(1177)
        ));
        assert!(super::windows_replace_failure_is_outcome_unknown(
            true,
            true,
            Some(1177)
        ));
        assert!(!super::windows_replace_failure_is_outcome_unknown(
            true, false, None
        ));
    }
}
