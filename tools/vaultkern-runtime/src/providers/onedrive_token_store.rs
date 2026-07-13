use std::cell::RefCell;
use std::path::PathBuf;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::state_paths::{extension_state_dir, runtime_state_dir};

const TOKEN_FILE_NAME: &str = "onedrive-refresh-token.dpapi";

pub(crate) trait OneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn store(&self, token: &str) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

pub(crate) fn production_default() -> Box<dyn OneDriveRefreshTokenStore> {
    production_store(
        runtime_state_dir().join(TOKEN_FILE_NAME),
        "vaultkern-runtime/default",
    )
}

pub(crate) fn production_for_extension_id(
    extension_id: &str,
) -> Box<dyn OneDriveRefreshTokenStore> {
    production_store(
        extension_state_dir(extension_id).join(TOKEN_FILE_NAME),
        &format!("vaultkern-runtime/extension/{extension_id}"),
    )
}

fn production_store(path: PathBuf, scope: &str) -> Box<dyn OneDriveRefreshTokenStore> {
    Box::new(UnavailableOneDriveRefreshTokenStore {
        _path: path,
        _scope: scope.to_owned(),
    })
}

pub(crate) struct EphemeralOneDriveRefreshTokenStore {
    token: RefCell<Option<Zeroizing<String>>>,
}

impl Default for EphemeralOneDriveRefreshTokenStore {
    fn default() -> Self {
        Self {
            token: RefCell::new(None),
        }
    }
}

impl OneDriveRefreshTokenStore for EphemeralOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self.token.borrow().as_ref().cloned())
    }

    fn store(&self, token: &str) -> Result<()> {
        self.token.replace(Some(Zeroizing::new(token.to_owned())));
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        self.token.replace(None);
        Ok(())
    }
}

struct UnavailableOneDriveRefreshTokenStore {
    _path: PathBuf,
    _scope: String,
}

impl OneDriveRefreshTokenStore for UnavailableOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(None)
    }

    fn store(&self, _token: &str) -> Result<()> {
        anyhow::bail!(
            "persistent OneDrive refresh-token storage is unavailable on this platform; reauthenticate when the process restarts"
        )
    }

    fn delete(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemoryOneDriveRefreshTokenStore {
    token: std::sync::Arc<std::sync::Mutex<Option<Zeroizing<String>>>>,
}

#[cfg(test)]
impl OneDriveRefreshTokenStore for MemoryOneDriveRefreshTokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self.token.lock().expect("memory token store lock").clone())
    }

    fn store(&self, token: &str) -> Result<()> {
        *self.token.lock().expect("memory token store lock") =
            Some(Zeroizing::new(token.to_owned()));
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        *self.token.lock().expect("memory token store lock") = None;
        Ok(())
    }
}
