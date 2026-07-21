use std::error::Error;
use std::fmt;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

#[derive(Debug)]
pub struct DesktopSettingsStoreError {
    operation: &'static str,
    path: PathBuf,
    source: Box<dyn Error + Send + Sync>,
}

impl DesktopSettingsStoreError {
    fn new(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            operation,
            path: path.into(),
            source: Box::new(source),
        }
    }
}

impl fmt::Display for DesktopSettingsStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to {} desktop settings at {}: {}",
            self.operation,
            self.path.display(),
            self.source
        )
    }
}

impl Error for DesktopSettingsStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct DesktopSettingsStore {
    path: PathBuf,
}

impl DesktopSettingsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<Value, DesktopSettingsStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(json!({})),
            Err(error) => {
                return Err(DesktopSettingsStoreError::new("read", &self.path, error));
            }
        };
        serde_json::from_slice(&bytes)
            .map_err(|error| DesktopSettingsStoreError::new("parse", &self.path, error))
    }

    pub fn save(&self, settings: &Value) -> Result<(), DesktopSettingsStoreError> {
        let bytes = serde_json::to_vec(settings)
            .map_err(|error| DesktopSettingsStoreError::new("serialize", &self.path, error))?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            DesktopSettingsStoreError::new("create parent directory for", &self.path, error)
        })?;

        let temp = settings_temp_path(&self.path);
        match fs::symlink_metadata(&temp) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(&temp).map_err(|error| {
                    DesktopSettingsStoreError::new("remove stale temporary", &temp, error)
                })?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(DesktopSettingsStoreError::new(
                    "inspect temporary",
                    &temp,
                    error,
                ));
            }
        }

        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            publish_settings(&temp, &self.path)?;
            sync_settings_parent(parent)?;
            Ok::<_, io::Error>(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(DesktopSettingsStoreError::new("persist", &self.path, error));
        }
        Ok(())
    }

    pub fn passkey_provider_enabled(&self) -> Result<bool, DesktopSettingsStoreError> {
        Ok(self
            .load()?
            .get("passkeyProviderEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }
}

fn settings_temp_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => path.with_extension(format!("{extension}.tmp")),
        None => path.with_extension("tmp"),
    }
}

#[cfg(not(windows))]
fn publish_settings(temp: &Path, target: &Path) -> io::Result<()> {
    fs::rename(temp, target)
}

#[cfg(windows)]
fn publish_settings(temp: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temp = temp
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let status = unsafe {
        MoveFileExW(
            temp.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if status == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_settings_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_settings_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}
