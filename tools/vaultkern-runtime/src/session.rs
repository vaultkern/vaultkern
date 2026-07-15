use std::collections::BTreeMap;

use url::form_urlencoded::byte_serialize;
use vaultkern_core::{SaveProfile, Vault};
use vaultkern_runtime_protocol::{SessionStateDto, VaultSourceStatusDto};

use crate::providers::local_file::VaultSourceFingerprint;

#[derive(Debug, Clone, Default)]
struct SessionState {
    unlocked: bool,
    active_vault_id: Option<String>,
    current_vault_ref_id: Option<String>,
}

impl SessionState {
    fn set_current_vault(&mut self, vault_ref_id: String) {
        self.current_vault_ref_id = Some(vault_ref_id);
        self.unlocked = false;
        self.active_vault_id = None;
    }

    fn unlock(&mut self, vault_id: String, current_vault_ref_id: Option<String>) {
        self.unlocked = true;
        self.active_vault_id = Some(vault_id);
        if let Some(vault_ref_id) = current_vault_ref_id {
            self.current_vault_ref_id = Some(vault_ref_id);
        }
    }

    fn lock(&mut self) {
        self.unlocked = false;
        self.active_vault_id = None;
    }

    fn clear_current_vault(&mut self) {
        self.lock();
        self.current_vault_ref_id = None;
    }

    fn current_vault_ref_id(&self) -> Option<&str> {
        self.current_vault_ref_id.as_deref()
    }

    fn active_vault_id(&self) -> Option<&str> {
        self.active_vault_id.as_deref()
    }

    fn to_dto(&self, supports_biometric_unlock: bool) -> SessionStateDto {
        SessionStateDto {
            unlocked: self.unlocked,
            active_vault_id: self.active_vault_id.clone(),
            current_vault_ref_id: self.current_vault_ref_id.clone(),
            supports_biometric_unlock,
            source_status: None,
        }
    }
}

pub(crate) struct LoadedVault {
    pub(crate) source: VaultSource,
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) baseline_fingerprint: VaultSourceFingerprint,
    pub(crate) password: Option<String>,
    pub(crate) key_file_path: Option<String>,
    pub(crate) save_profile: SaveProfile,
    pub(crate) autosave_delay_seconds: Option<u32>,
    pub(crate) vault: Option<Vault>,
    pub(crate) source_status: Option<VaultSourceStatusDto>,
    pub(crate) source_account_label: Option<String>,
    pub(crate) quick_unlock_refresh_pending: bool,
}

impl LoadedVault {
    fn clear_unlock_secrets(&mut self) {
        self.password = None;
        self.key_file_path = None;
        self.vault = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaultSource {
    LocalPath(String),
    OneDriveItem { drive_id: String, item_id: String },
}

pub(crate) fn onedrive_remote_id(drive_id: &str, item_id: &str) -> String {
    let encode = |value: &str| byte_serialize(value.as_bytes()).collect::<String>();
    format!("{}:{}", encode(drive_id), encode(item_id))
}

pub(crate) fn onedrive_vault_id(drive_id: &str, item_id: &str) -> String {
    format!("onedrive:{}", onedrive_remote_id(drive_id, item_id))
}

impl VaultSource {
    pub(crate) fn vault_id(&self) -> String {
        match self {
            Self::LocalPath(path) => path.clone(),
            Self::OneDriveItem { drive_id, item_id } => onedrive_vault_id(drive_id, item_id),
        }
    }
}

#[derive(Default)]
pub(crate) struct VaultSession {
    state: SessionState,
    loaded: BTreeMap<String, LoadedVault>,
}

impl VaultSession {
    pub(crate) fn set_current_vault(&mut self, vault_ref_id: String) {
        self.state.set_current_vault(vault_ref_id);
    }

    pub(crate) fn unlock(&mut self, vault_id: String, current_vault_ref_id: Option<String>) {
        self.state.unlock(vault_id, current_vault_ref_id);
    }

    pub(crate) fn lock_all(&mut self) {
        for loaded in self.loaded.values_mut() {
            loaded.clear_unlock_secrets();
        }
        self.state.lock();
    }

    pub(crate) fn clear_current_vault(&mut self) {
        self.state.clear_current_vault();
    }

    pub(crate) fn current_vault_ref_id(&self) -> Option<&str> {
        self.state.current_vault_ref_id()
    }

    pub(crate) fn active_vault_id(&self) -> Option<&str> {
        self.state.active_vault_id()
    }

    pub(crate) fn to_dto(&self, supports_biometric_unlock: bool) -> SessionStateDto {
        self.state.to_dto(supports_biometric_unlock)
    }

    pub(crate) fn insert_loaded(&mut self, vault_id: String, loaded: LoadedVault) {
        self.loaded.insert(vault_id, loaded);
    }

    pub(crate) fn contains_loaded(&self, vault_id: &str) -> bool {
        self.loaded.contains_key(vault_id)
    }

    pub(crate) fn find_loaded(&self, vault_id: &str) -> Option<&LoadedVault> {
        self.loaded.get(vault_id)
    }

    pub(crate) fn find_loaded_mut(&mut self, vault_id: &str) -> Option<&mut LoadedVault> {
        self.loaded.get_mut(vault_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{LoadedVault, VaultSession, VaultSource, onedrive_remote_id, onedrive_vault_id};
    use crate::providers::local_file::VaultSourceFingerprint;
    use vaultkern_core::{SaveProfile, Vault};
    use vaultkern_runtime_protocol::VaultSourceStatusDto;

    enum Transition {
        SetCurrent(&'static str),
        Unlock {
            vault_id: &'static str,
            current_vault_ref_id: Option<&'static str>,
        },
        Lock,
        ClearCurrent,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RetainedLoadedVaultState {
        source: VaultSource,
        name: String,
        bytes: Vec<u8>,
        baseline_fingerprint: VaultSourceFingerprint,
        save_profile: SaveProfile,
        autosave_delay_seconds: Option<u32>,
        source_status: Option<VaultSourceStatusDto>,
        source_account_label: Option<String>,
        quick_unlock_refresh_pending: bool,
    }

    fn retained_state(loaded: &LoadedVault) -> RetainedLoadedVaultState {
        let LoadedVault {
            source,
            name,
            bytes,
            baseline_fingerprint,
            password: _,
            key_file_path: _,
            save_profile,
            autosave_delay_seconds,
            vault: _,
            source_status,
            source_account_label,
            quick_unlock_refresh_pending,
        } = loaded;

        RetainedLoadedVaultState {
            source: source.clone(),
            name: name.clone(),
            bytes: bytes.clone(),
            baseline_fingerprint: baseline_fingerprint.clone(),
            save_profile: save_profile.clone(),
            autosave_delay_seconds: *autosave_delay_seconds,
            source_status: source_status.clone(),
            source_account_label: source_account_label.clone(),
            quick_unlock_refresh_pending: *quick_unlock_refresh_pending,
        }
    }

    #[test]
    fn onedrive_identity_encoding_is_shared_by_vault_and_remote_ids() {
        let drive_id = "drive:\u{79df}\u{6237}";
        let item_id = "item/id";
        let remote_id = onedrive_remote_id(drive_id, item_id);

        assert_eq!(remote_id, "drive%3A%E7%A7%9F%E6%88%B7:item%2Fid");
        assert_eq!(
            onedrive_vault_id(drive_id, item_id),
            format!("onedrive:{remote_id}")
        );
        assert_eq!(
            VaultSource::OneDriveItem {
                drive_id: drive_id.into(),
                item_id: item_id.into(),
            }
            .vault_id(),
            onedrive_vault_id(drive_id, item_id)
        );
    }

    #[test]
    fn session_transitions_preserve_the_existing_dto_contract() {
        let cases = [
            (
                Transition::SetCurrent("ref-a"),
                (false, None, Some("ref-a")),
            ),
            (
                Transition::Unlock {
                    vault_id: "vault-a",
                    current_vault_ref_id: None,
                },
                (true, Some("vault-a"), Some("ref-a")),
            ),
            (
                Transition::SetCurrent("ref-b"),
                (false, None, Some("ref-b")),
            ),
            (
                Transition::Unlock {
                    vault_id: "vault-b",
                    current_vault_ref_id: Some("ref-b"),
                },
                (true, Some("vault-b"), Some("ref-b")),
            ),
            (Transition::Lock, (false, None, Some("ref-b"))),
            (
                Transition::Unlock {
                    vault_id: "vault-b",
                    current_vault_ref_id: None,
                },
                (true, Some("vault-b"), Some("ref-b")),
            ),
            (Transition::ClearCurrent, (false, None, None)),
        ];
        let mut session = VaultSession::default();

        for (transition, expected) in cases {
            match transition {
                Transition::SetCurrent(vault_ref_id) => {
                    session.set_current_vault(vault_ref_id.to_owned());
                }
                Transition::Unlock {
                    vault_id,
                    current_vault_ref_id,
                } => session.unlock(
                    vault_id.to_owned(),
                    current_vault_ref_id.map(ToOwned::to_owned),
                ),
                Transition::Lock => session.lock_all(),
                Transition::ClearCurrent => session.clear_current_vault(),
            }

            let dto = session.to_dto(true);
            assert_eq!(dto.unlocked, expected.0);
            assert_eq!(dto.active_vault_id.as_deref(), expected.1);
            assert_eq!(dto.current_vault_ref_id.as_deref(), expected.2);
            assert!(dto.supports_biometric_unlock);
            assert!(dto.source_status.is_none());
        }
    }

    fn loaded_vault(name: &str, marker: u8) -> LoadedVault {
        LoadedVault {
            source: VaultSource::LocalPath(format!("/tmp/{name}.kdbx")),
            name: name.to_owned(),
            bytes: vec![marker, marker + 1],
            baseline_fingerprint: VaultSourceFingerprint {
                content_sha256: format!("fingerprint-{marker}"),
                size_bytes: 2,
                modified_at: Some(u64::from(marker)),
            },
            password: Some(format!("password-{marker}")),
            key_file_path: Some(format!("/tmp/key-{marker}")),
            save_profile: SaveProfile::recommended(),
            autosave_delay_seconds: Some(u32::from(marker)),
            vault: Some(Vault::empty(name)),
            source_status: Some(VaultSourceStatusDto {
                source_kind: "local".into(),
                remote_state: format!("state-{marker}"),
                last_sync_at: Some(i64::from(marker)),
                cached_at: None,
                last_error: None,
            }),
            source_account_label: Some(format!("account-{marker}")),
            quick_unlock_refresh_pending: true,
        }
    }

    #[test]
    fn vault_session_isolates_loaded_vaults_and_lock_clears_all_unlock_material() {
        let mut session = VaultSession::default();
        session.set_current_vault("ref-a".into());
        session.insert_loaded("vault-a".into(), loaded_vault("first", 1));
        session.insert_loaded("vault-b".into(), loaded_vault("second", 2));
        session.unlock("vault-a".into(), Some("ref-a".into()));

        assert_eq!(session.active_vault_id(), Some("vault-a"));
        assert_eq!(session.find_loaded("vault-a").unwrap().name, "first");
        assert_eq!(session.find_loaded("vault-b").unwrap().name, "second");

        session.set_current_vault("ref-b".into());
        session.unlock("vault-b".into(), Some("ref-b".into()));
        assert!(session.find_loaded("vault-a").unwrap().vault.is_some());
        assert!(session.find_loaded("vault-b").unwrap().vault.is_some());
        assert_eq!(
            session.find_loaded("vault-a").unwrap().password.as_deref(),
            Some("password-1")
        );
        assert_eq!(
            session.find_loaded("vault-b").unwrap().password.as_deref(),
            Some("password-2")
        );
        assert_eq!(
            session
                .find_loaded("vault-a")
                .unwrap()
                .key_file_path
                .as_deref(),
            Some("/tmp/key-1")
        );
        assert_eq!(
            session
                .find_loaded("vault-b")
                .unwrap()
                .key_file_path
                .as_deref(),
            Some("/tmp/key-2")
        );
        let retained = ["vault-a", "vault-b"].map(|vault_id| {
            (
                vault_id,
                retained_state(session.find_loaded(vault_id).unwrap()),
            )
        });
        session.lock_all();

        assert_eq!(session.active_vault_id(), None);
        assert_eq!(session.current_vault_ref_id(), Some("ref-b"));
        for (vault_id, expected) in retained {
            let loaded = session.find_loaded(vault_id).unwrap();
            assert_eq!(retained_state(loaded), expected);
            assert!(loaded.vault.is_none());
            assert!(loaded.password.is_none());
            assert!(loaded.key_file_path.is_none());
        }
    }
}
