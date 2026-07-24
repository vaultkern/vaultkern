//! Composition boundary for concrete storage adapters.
//!
//! VaultCore consumes [`Provider`] operations and opaque observations from this
//! directory. Local-file paths, OneDrive state tokens, revision encoding, and
//! adapter test controls stay on this side of the boundary.

use anyhow::Result;
use vaultkern_runtime_protocol::{
    OneDriveAuthSessionDto, OneDriveAuthStatusDto, OneDriveItemListDto,
};

use super::local_file::{LocalFileCommitError, LocalFileProvider, LocalFileVaultSourceProvider};
use super::onedrive::{
    OneDriveMemoryAccessCounts, OneDriveMemoryWriteBehavior, OneDriveMetadata, OneDriveProvider,
    OneDriveVaultSourceProvider, is_onedrive_item_not_found,
};
use super::onedrive_token_store::OneDriveRefreshTokenStore;
use super::provider::{ContentIdentity, Provider, ProviderCommit, ProviderError, ProviderRevision};

pub(crate) type LocalPublicationError = LocalFileCommitError;

pub(crate) struct ProviderCatalog {
    local_file: LocalFileVaultSourceProvider,
    one_drive: OneDriveVaultSourceProvider,
}

pub(crate) struct RemoteObservation {
    revision: ProviderRevision,
    display_name: String,
    size_bytes: Option<u64>,
    content_revision_marker: Option<u64>,
    cache_validation_token: Option<String>,
}

impl RemoteObservation {
    pub(crate) fn matches_identity(&self, identity: &ContentIdentity) -> bool {
        self.size_bytes == Some(identity.size_bytes)
            && self
                .content_revision_marker
                .is_some_and(|marker| identity.observation_marker == Some(marker))
    }

    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn revision(&self) -> &ProviderRevision {
        &self.revision
    }

    pub(crate) fn identity_for_bytes(&self, bytes: &[u8]) -> ContentIdentity {
        ContentIdentity::for_bytes(bytes, self.content_revision_marker)
    }

    pub(crate) fn cache_validation_token(&self) -> Option<&str> {
        self.cache_validation_token.as_deref()
    }
}

pub(crate) struct RemoteSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) fingerprint: ContentIdentity,
    pub(crate) revision: ProviderRevision,
    pub(crate) cache_validation_token: Option<String>,
    pub(crate) name: String,
    pub(crate) account_label: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderAccessCounts {
    pub remote_state_reads: usize,
    pub snapshot_reads: usize,
    pub snapshot_from_state_reads: usize,
    pub writes: usize,
}

pub(crate) enum ConditionalPublication {
    Committed { fingerprint: ContentIdentity },
    StaleRevision,
    OutcomeUnknown { message: String },
}

impl ProviderCatalog {
    pub(crate) fn new_from_env() -> Self {
        Self {
            local_file: LocalFileVaultSourceProvider::default(),
            one_drive: OneDriveVaultSourceProvider::new_from_env(),
        }
    }

    pub(crate) fn new_for_extension_id(extension_id: &str) -> Self {
        Self {
            local_file: LocalFileVaultSourceProvider::default(),
            one_drive: OneDriveVaultSourceProvider::new_from_env_for_extension_id(extension_id),
        }
    }

    pub(crate) fn new_with_platform_refresh_token_store(
        refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
    ) -> Self {
        Self {
            local_file: LocalFileVaultSourceProvider::default(),
            one_drive: OneDriveVaultSourceProvider::new_with_platform_refresh_token_store(
                refresh_token_store,
            ),
        }
    }

    pub(crate) fn new_in_memory() -> Self {
        Self {
            local_file: LocalFileVaultSourceProvider::default(),
            one_drive: OneDriveVaultSourceProvider::new_in_memory(),
        }
    }

    pub(crate) fn local(&self, path: impl Into<std::path::PathBuf>) -> LocalFileProvider {
        self.local_file.bind(path)
    }

    pub(crate) fn onedrive(
        &mut self,
        drive_id: impl Into<String>,
        item_id: impl Into<String>,
    ) -> impl Provider + '_ {
        self.one_drive.bind(drive_id, item_id)
    }

    pub(crate) fn pick_local_file(&self) -> Result<Option<String>> {
        self.local_file.pick()
    }

    pub(crate) fn begin_login(&mut self) -> Result<OneDriveAuthSessionDto> {
        self.one_drive.begin_login()
    }

    pub(crate) fn complete_pending_login(&mut self) -> Result<OneDriveAuthStatusDto> {
        self.one_drive.complete_pending_login()
    }

    pub(crate) fn list_children(
        &self,
        parent_item_id: Option<&str>,
    ) -> Result<OneDriveItemListDto> {
        self.one_drive.list_children(parent_item_id)
    }

    pub(crate) fn metadata(&self, drive_id: &str, item_id: &str) -> Result<OneDriveMetadata> {
        self.one_drive.metadata(drive_id, item_id)
    }

    pub(crate) fn remote_state(&self, drive_id: &str, item_id: &str) -> Result<RemoteObservation> {
        let state = self.one_drive.remote_state(drive_id, item_id)?;
        Ok(RemoteObservation {
            revision: OneDriveProvider::revision_for_state(&state)?,
            display_name: state.name.clone(),
            size_bytes: state.size,
            content_revision_marker: state.content_revision_marker(),
            cache_validation_token: state.cache_validation_token().map(str::to_owned),
        })
    }

    pub(crate) fn read_onedrive_observation(
        &mut self,
        drive_id: &str,
        item_id: &str,
        observation: &RemoteObservation,
    ) -> Result<RemoteSnapshot> {
        let mut state = OneDriveProvider::observed_state(observation.revision())?;
        state.name = observation.display_name.clone();
        state.size = observation.size_bytes;
        let snapshot = self
            .one_drive
            .bind(drive_id, item_id)
            .read_runtime_snapshot_from_state(&state)
            .map_err(anyhow::Error::from)?;
        Ok(RemoteSnapshot {
            bytes: snapshot.bytes,
            fingerprint: snapshot.fingerprint,
            revision: observation.revision.clone(),
            cache_validation_token: observation.cache_validation_token.clone(),
            name: snapshot.name,
            account_label: snapshot.account_label,
        })
    }

    pub(crate) fn publish_onedrive_observation(
        &mut self,
        drive_id: &str,
        item_id: &str,
        bytes: &[u8],
        observation: &RemoteObservation,
    ) -> Result<ConditionalPublication, ProviderError> {
        match self
            .one_drive
            .bind(drive_id, item_id)
            .publish(observation.revision(), bytes)
        {
            Ok(commit) => Self::committed_publication(commit),
            Err(ProviderError::StaleRevision { .. }) => Ok(ConditionalPublication::StaleRevision),
            Err(ProviderError::OutcomeUnknown { message }) => {
                Ok(ConditionalPublication::OutcomeUnknown { message })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn is_onedrive_not_found(error: &anyhow::Error) -> bool {
        is_onedrive_item_not_found(error)
    }

    fn committed_publication(
        commit: ProviderCommit,
    ) -> Result<ConditionalPublication, ProviderError> {
        Ok(ConditionalPublication::Committed {
            fingerprint: commit.identity,
        })
    }

    pub(crate) fn insert_memory_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) {
        self.one_drive
            .insert_memory_item(drive_id, item_id, name, account_label, bytes);
    }

    pub(crate) fn replace_memory_item(&mut self, drive_id: &str, item_id: &str, bytes: Vec<u8>) {
        self.one_drive.replace_memory_item(drive_id, item_id, bytes);
    }

    pub(crate) fn remove_memory_item(&mut self, drive_id: &str, item_id: &str) {
        self.one_drive.remove_memory_item(drive_id, item_id);
    }

    pub(crate) fn read_memory_item_bytes(&self, drive_id: &str, item_id: &str) -> Result<Vec<u8>> {
        self.one_drive.read_memory_item_bytes(drive_id, item_id)
    }

    pub(crate) fn memory_item_revision(&self, drive_id: &str, item_id: &str) -> Result<u64> {
        self.one_drive.memory_item_revision(drive_id, item_id)
    }

    pub(crate) fn set_memory_item_revision(
        &mut self,
        drive_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        self.one_drive
            .set_memory_item_revision(drive_id, item_id, revision)
    }

    pub(crate) fn reset_memory_access_counts(&self) {
        self.one_drive.reset_memory_access_counts();
    }

    pub(crate) fn memory_access_counts(&self) -> ProviderAccessCounts {
        let OneDriveMemoryAccessCounts {
            remote_state_reads,
            snapshot_reads,
            snapshot_from_state_reads,
            writes,
        } = self.one_drive.memory_access_counts();
        ProviderAccessCounts {
            remote_state_reads,
            snapshot_reads,
            snapshot_from_state_reads,
            writes,
        }
    }

    pub(crate) fn queue_precondition_failure(&mut self, replacement_bytes: Option<Vec<u8>>) {
        self.one_drive.queue_memory_write_behavior(
            OneDriveMemoryWriteBehavior::PreconditionFailed { replacement_bytes },
        );
    }

    pub(crate) fn queue_ambiguous_write(&mut self, committed: bool, readback_available: bool) {
        let behavior = match (committed, readback_available) {
            (true, true) => OneDriveMemoryWriteBehavior::OutcomeUnknownCommitted,
            (false, true) => OneDriveMemoryWriteBehavior::OutcomeUnknownNotCommitted,
            (true, false) => {
                OneDriveMemoryWriteBehavior::OutcomeUnknownCommittedReadbackUnavailable
            }
            (false, false) => {
                OneDriveMemoryWriteBehavior::OutcomeUnknownNotCommittedReadbackUnavailable
            }
        };
        self.one_drive.queue_memory_write_behavior(behavior);
    }

    pub(crate) fn fail_next_memory_conflict_copy(&self) {
        self.one_drive.fail_next_memory_conflict_copy();
    }

    pub(crate) fn fail_next_memory_remote_state(&self) {
        self.one_drive.fail_next_memory_remote_state();
    }

    #[cfg(test)]
    pub(crate) fn replace_local_file_with_write_faults(
        &mut self,
        faults: super::durable_file::DurableFaultInjector,
    ) {
        self.local_file = LocalFileVaultSourceProvider::with_write_faults(faults);
    }

    #[cfg(test)]
    pub(crate) fn replace_local_file_with_before_write_hook(
        &mut self,
        hook: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) {
        self.local_file = LocalFileVaultSourceProvider::with_before_write_hook(hook);
    }
}
