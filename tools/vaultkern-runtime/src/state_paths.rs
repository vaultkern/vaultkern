use std::env;
use std::path::PathBuf;

pub(crate) fn runtime_state_dir() -> PathBuf {
    if cfg!(windows) {
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("vaultkern-runtime");
        }
    }

    if let Ok(state_home) = env::var("XDG_STATE_HOME") {
        return PathBuf::from(state_home).join("vaultkern-runtime");
    }

    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("vaultkern-runtime");
    }

    env::temp_dir().join("vaultkern-runtime")
}

pub(crate) fn extension_state_dir(extension_id: &str) -> PathBuf {
    runtime_state_dir().join("extensions").join(extension_id)
}

pub(crate) fn extension_id_from_browser_origin(origin: &str) -> Option<&str> {
    let extension_id = origin.strip_prefix("chrome-extension://")?;
    let extension_id = extension_id.strip_suffix('/').unwrap_or(extension_id);

    if extension_id.is_empty()
        || !extension_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return None;
    }

    Some(extension_id)
}

#[cfg(test)]
mod tests {
    use super::extension_id_from_browser_origin;

    #[test]
    fn parses_extension_id_from_browser_origin() {
        assert_eq!(
            extension_id_from_browser_origin(
                "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/"
            ),
            Some("kblgblkjghklighdgmejjfondchkjcgf")
        );
        assert_eq!(
            extension_id_from_browser_origin("chrome-extension://kblgblkjghklighdgmejjfondchkjcgf"),
            Some("kblgblkjghklighdgmejjfondchkjcgf")
        );
    }

    #[test]
    fn rejects_non_extension_origins() {
        assert_eq!(
            extension_id_from_browser_origin("https://example.com/"),
            None
        );
        assert_eq!(
            extension_id_from_browser_origin("chrome-extension:///"),
            None
        );
        assert_eq!(
            extension_id_from_browser_origin("chrome-extension://UpperCase/"),
            None
        );
    }
}
