use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vaultkern_runtime_protocol::{
    OneDriveAuthSessionDto, OneDriveAuthStatusDto, OneDriveItemDto, OneDriveItemListDto,
};

use crate::providers::local_file::VaultSourceFingerprint;
use crate::providers::onedrive_token_store::{
    EphemeralOneDriveRefreshTokenStore, OneDriveRefreshTokenStore, is_unavailable_error,
    production_default, production_for_extension_id,
};
use zeroize::Zeroizing;

const MICROSOFT_AUTH_URL: &str =
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const MICROSOFT_GRAPH_ROOT: &str = "https://graph.microsoft.com/v1.0";
const ONEDRIVE_SCOPES: &str = "Files.ReadWrite offline_access User.Read";
const LOOPBACK_CALLBACK_ADDR: &str = "127.0.0.1:53121";
const CALLBACK_WAIT_SECONDS: u64 = 600;
const GRAPH_CHILDREN_SELECT: &str = "id,name,size,eTag,parentReference,folder,file";
const GRAPH_ITEM_SELECT: &str = "id,name,size,eTag,parentReference,@microsoft.graph.downloadUrl";
const GRAPH_CHILDREN_PAGE_SIZE: &str = "200";
const ACCESS_TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(120);
const MAX_AUTHORIZED_GET_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneDriveSnapshot {
    pub bytes: Vec<u8>,
    pub fingerprint: VaultSourceFingerprint,
    pub name: String,
    pub account_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneDriveMetadata {
    pub drive_id: String,
    pub item_id: String,
    pub name: String,
    pub account_label: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneDriveRemoteState {
    pub name: String,
    pub size: Option<u64>,
    pub e_tag: Option<String>,
    pub download_url: Option<String>,
    memory_revision: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OneDriveMemoryAccessCounts {
    pub remote_state_reads: usize,
    pub snapshot_reads: usize,
    pub snapshot_from_state_reads: usize,
    pub writes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneDriveConditionalWriteOutcome {
    Committed {
        fingerprint: VaultSourceFingerprint,
        e_tag: Option<String>,
    },
    PreconditionFailed,
    OutcomeUnknown {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneDriveConditionalWriteError {
    MissingEtag,
    InvalidMemoryRevision,
    Unavailable { message: String },
    Rejected { status: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneDriveMemoryWriteBehavior {
    PreconditionFailed { replacement_bytes: Option<Vec<u8>> },
    OutcomeUnknownCommitted,
    OutcomeUnknownNotCommitted,
}

impl fmt::Display for OneDriveConditionalWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEtag => write!(formatter, "current OneDrive item did not include an ETag"),
            Self::InvalidMemoryRevision => {
                write!(
                    formatter,
                    "current in-memory OneDrive item revision is unavailable"
                )
            }
            Self::Unavailable { message } => {
                write!(formatter, "OneDrive write unavailable: {message}")
            }
            Self::Rejected { status } => {
                write!(formatter, "OneDrive write was rejected with HTTP {status}")
            }
        }
    }
}

impl std::error::Error for OneDriveConditionalWriteError {}

impl OneDriveRemoteState {
    pub fn matches_fingerprint(&self, fingerprint: &VaultSourceFingerprint) -> bool {
        if self.size != Some(fingerprint.size_bytes) {
            return false;
        }
        if let Some(revision) = self.memory_revision {
            return fingerprint.modified_at == Some(revision);
        }
        self.e_tag
            .as_deref()
            .map(stable_u64_for_text)
            .is_some_and(|etag| fingerprint.modified_at == Some(etag))
    }

    pub(crate) fn memory_revision(&self) -> Option<u64> {
        self.memory_revision
    }
}

#[derive(Debug, Clone)]
struct MemoryOneDriveItem {
    drive_id: String,
    item_id: String,
    name: String,
    account_label: String,
    bytes: Vec<u8>,
    revision: u64,
}

pub struct OneDriveVaultSourceProvider {
    client_id: Option<String>,
    auth_url: String,
    token_url: String,
    graph_root: String,
    callback_addr: String,
    refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
    refresh_token_load_error: Option<String>,
    token_state: RefCell<Option<OneDriveTokenState>>,
    pending_login: Option<PendingOneDriveLogin>,
    test_code_verifier: Option<String>,
    memory_items: BTreeMap<(String, String), MemoryOneDriveItem>,
    memory_remote_state_reads: Cell<usize>,
    memory_snapshot_reads: Cell<usize>,
    memory_snapshot_from_state_reads: Cell<usize>,
    memory_writes: Cell<usize>,
    memory_write_behaviors: VecDeque<OneDriveMemoryWriteBehavior>,
}

struct PendingOneDriveLogin {
    redirect_uri: String,
    code_verifier: String,
    code_receiver: Receiver<Result<String, String>>,
}

struct OneDriveTokenState {
    access_token: Option<String>,
    access_expires_at: Option<Instant>,
    refresh_token: Zeroizing<String>,
    refresh_token_origin: RefreshTokenOrigin,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RefreshTokenOrigin {
    Environment,
    Store,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default, deserialize_with = "deserialize_optional_refresh_token")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphMeResponse {
    #[serde(default)]
    user_principal_name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphChildrenResponse {
    value: Vec<GraphDriveItem>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphDriveItem {
    id: String,
    name: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    e_tag: Option<String>,
    #[serde(default)]
    parent_reference: Option<GraphParentReference>,
    #[serde(default)]
    folder: Option<serde_json::Value>,
    #[serde(default, rename = "@microsoft.graph.downloadUrl")]
    download_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphWriteResponse {
    #[serde(default)]
    e_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphParentReference {
    #[serde(default)]
    drive_id: Option<String>,
}

impl OneDriveVaultSourceProvider {
    pub fn new_from_env() -> Self {
        Self::new_from_env_with_refresh_token_store(production_default())
    }

    pub fn new_from_env_for_extension_id(extension_id: &str) -> Self {
        Self::new_from_env_with_refresh_token_store(production_for_extension_id(extension_id))
    }

    fn new_from_env_with_refresh_token_store(
        refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
    ) -> Self {
        let environment_refresh_token = std::env::var("VAULTKERN_ONEDRIVE_REFRESH_TOKEN")
            .ok()
            .map(Zeroizing::new);
        let (token_state, refresh_token_load_error) = match environment_refresh_token {
            Some(refresh_token) => (
                Some(OneDriveTokenState {
                    access_token: None,
                    access_expires_at: None,
                    refresh_token,
                    refresh_token_origin: RefreshTokenOrigin::Environment,
                }),
                None,
            ),
            None => load_refresh_token_state(refresh_token_store.as_ref()),
        };
        Self {
            client_id: option_env!("VAULTKERN_ONEDRIVE_CLIENT_ID").map(str::to_owned),
            auth_url: std::env::var("VAULTKERN_ONEDRIVE_AUTH_URL")
                .unwrap_or_else(|_| MICROSOFT_AUTH_URL.into()),
            token_url: std::env::var("VAULTKERN_ONEDRIVE_TOKEN_URL")
                .unwrap_or_else(|_| MICROSOFT_TOKEN_URL.into()),
            graph_root: std::env::var("VAULTKERN_ONEDRIVE_GRAPH_ROOT")
                .unwrap_or_else(|_| MICROSOFT_GRAPH_ROOT.into()),
            callback_addr: LOOPBACK_CALLBACK_ADDR.into(),
            refresh_token_store,
            refresh_token_load_error,
            token_state: RefCell::new(token_state),
            pending_login: None,
            test_code_verifier: None,
            memory_items: BTreeMap::new(),
            memory_remote_state_reads: Cell::new(0),
            memory_snapshot_reads: Cell::new(0),
            memory_snapshot_from_state_reads: Cell::new(0),
            memory_writes: Cell::new(0),
            memory_write_behaviors: VecDeque::new(),
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            client_id: Some("test-client-id".into()),
            auth_url: MICROSOFT_AUTH_URL.into(),
            token_url: MICROSOFT_TOKEN_URL.into(),
            graph_root: MICROSOFT_GRAPH_ROOT.into(),
            callback_addr: LOOPBACK_CALLBACK_ADDR.into(),
            refresh_token_store: Box::new(EphemeralOneDriveRefreshTokenStore::default()),
            refresh_token_load_error: None,
            token_state: RefCell::new(None),
            pending_login: None,
            test_code_verifier: None,
            memory_items: BTreeMap::new(),
            memory_remote_state_reads: Cell::new(0),
            memory_snapshot_reads: Cell::new(0),
            memory_snapshot_from_state_reads: Cell::new(0),
            memory_writes: Cell::new(0),
            memory_write_behaviors: VecDeque::new(),
        }
    }

    #[cfg(test)]
    fn new_for_graph_tests(
        client_id: &str,
        auth_url: &str,
        token_url: &str,
        graph_root: &str,
    ) -> Self {
        Self::new_for_graph_tests_with_refresh_token_store(
            client_id,
            auth_url,
            token_url,
            graph_root,
            Box::new(
                crate::providers::onedrive_token_store::MemoryOneDriveRefreshTokenStore::default(),
            ),
        )
    }

    #[cfg(test)]
    fn new_for_graph_tests_with_refresh_token_store(
        client_id: &str,
        auth_url: &str,
        token_url: &str,
        graph_root: &str,
        refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
    ) -> Self {
        let (token_state, refresh_token_load_error) =
            load_refresh_token_state(refresh_token_store.as_ref());
        Self::new_for_graph_tests_with_refresh_token_state(
            client_id,
            auth_url,
            token_url,
            graph_root,
            refresh_token_store,
            token_state,
            refresh_token_load_error,
        )
    }

    #[cfg(all(test, not(windows)))]
    fn new_for_graph_tests_with_environment_refresh_token(
        client_id: &str,
        auth_url: &str,
        token_url: &str,
        graph_root: &str,
        refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
        refresh_token: &str,
    ) -> Self {
        Self::new_for_graph_tests_with_refresh_token_state(
            client_id,
            auth_url,
            token_url,
            graph_root,
            refresh_token_store,
            Some(OneDriveTokenState {
                access_token: None,
                access_expires_at: None,
                refresh_token: Zeroizing::new(refresh_token.to_owned()),
                refresh_token_origin: RefreshTokenOrigin::Environment,
            }),
            None,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_for_graph_tests_with_refresh_token_state(
        client_id: &str,
        auth_url: &str,
        token_url: &str,
        graph_root: &str,
        refresh_token_store: Box<dyn OneDriveRefreshTokenStore>,
        token_state: Option<OneDriveTokenState>,
        refresh_token_load_error: Option<String>,
    ) -> Self {
        Self {
            client_id: Some(client_id.into()),
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            graph_root: graph_root.trim_end_matches('/').into(),
            callback_addr: "127.0.0.1:0".into(),
            refresh_token_store,
            refresh_token_load_error,
            token_state: RefCell::new(token_state),
            pending_login: None,
            test_code_verifier: None,
            memory_items: BTreeMap::new(),
            memory_remote_state_reads: Cell::new(0),
            memory_snapshot_reads: Cell::new(0),
            memory_snapshot_from_state_reads: Cell::new(0),
            memory_writes: Cell::new(0),
            memory_write_behaviors: VecDeque::new(),
        }
    }

    #[cfg(test)]
    fn set_test_tokens(&mut self, access_token: &str, refresh_token: &str) {
        self.token_state.replace(Some(OneDriveTokenState {
            access_token: Some(access_token.into()),
            access_expires_at: Some(Instant::now() + Duration::from_secs(3600)),
            refresh_token: Zeroizing::new(refresh_token.into()),
            refresh_token_origin: RefreshTokenOrigin::Store,
        }));
    }

    #[cfg(test)]
    fn set_expired_test_tokens(&mut self, access_token: &str, refresh_token: &str) {
        self.token_state.replace(Some(OneDriveTokenState {
            access_token: Some(access_token.into()),
            access_expires_at: Some(Instant::now() - Duration::from_secs(1)),
            refresh_token: Zeroizing::new(refresh_token.into()),
            refresh_token_origin: RefreshTokenOrigin::Store,
        }));
    }

    #[cfg(test)]
    fn set_test_code_verifier(&mut self, code_verifier: &str) {
        self.test_code_verifier = Some(code_verifier.into());
    }

    pub fn insert_memory_item(
        &mut self,
        drive_id: &str,
        item_id: &str,
        name: &str,
        account_label: &str,
        bytes: Vec<u8>,
    ) {
        self.memory_items.insert(
            (drive_id.to_owned(), item_id.to_owned()),
            MemoryOneDriveItem {
                drive_id: drive_id.to_owned(),
                item_id: item_id.to_owned(),
                name: name.to_owned(),
                account_label: account_label.to_owned(),
                bytes,
                revision: 1,
            },
        );
    }

    pub fn replace_memory_item(&mut self, drive_id: &str, item_id: &str, bytes: Vec<u8>) {
        if let Some(item) = self
            .memory_items
            .get_mut(&(drive_id.to_owned(), item_id.to_owned()))
        {
            item.bytes = bytes;
            item.revision += 1;
        }
    }

    pub fn queue_memory_write_behavior(&mut self, behavior: OneDriveMemoryWriteBehavior) {
        self.memory_write_behaviors.push_back(behavior);
    }

    pub fn remove_memory_item(&mut self, drive_id: &str, item_id: &str) {
        self.memory_items
            .remove(&(drive_id.to_owned(), item_id.to_owned()));
    }

    pub fn read_memory_item_bytes(&self, drive_id: &str, item_id: &str) -> Result<Vec<u8>> {
        Ok(self.item(drive_id, item_id)?.bytes.clone())
    }

    pub fn memory_item_revision(&self, drive_id: &str, item_id: &str) -> Result<u64> {
        Ok(self.item(drive_id, item_id)?.revision)
    }

    pub fn set_memory_item_revision(
        &mut self,
        drive_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        let item = self
            .memory_items
            .get_mut(&(drive_id.to_owned(), item_id.to_owned()))
            .with_context(|| format!("OneDrive item not found: {drive_id}/{item_id}"))?;
        item.revision = revision;
        Ok(())
    }

    pub fn reset_memory_access_counts(&self) {
        self.memory_remote_state_reads.set(0);
        self.memory_snapshot_reads.set(0);
        self.memory_snapshot_from_state_reads.set(0);
        self.memory_writes.set(0);
    }

    pub fn memory_access_counts(&self) -> OneDriveMemoryAccessCounts {
        OneDriveMemoryAccessCounts {
            remote_state_reads: self.memory_remote_state_reads.get(),
            snapshot_reads: self.memory_snapshot_reads.get(),
            snapshot_from_state_reads: self.memory_snapshot_from_state_reads.get(),
            writes: self.memory_writes.get(),
        }
    }

    pub fn begin_login(&mut self) -> Result<OneDriveAuthSessionDto> {
        let client_id = self
            .client_id
            .as_deref()
            .context("VAULTKERN_ONEDRIVE_CLIENT_ID is not configured")?;
        let (code_receiver, redirect_uri) = start_loopback_callback_listener(&self.callback_addr)?;
        let code_verifier = self
            .test_code_verifier
            .clone()
            .unwrap_or_else(new_code_verifier);
        let challenge = code_challenge(&code_verifier);
        let auth_url = format!(
            "{auth_url}?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&code_challenge={challenge}&code_challenge_method=S256",
            auth_url = self.auth_url,
            client_id = encode_component(client_id),
            redirect_uri = encode_component(&redirect_uri),
            scope = encode_component(ONEDRIVE_SCOPES),
            challenge = encode_component(&challenge),
        );

        self.pending_login = Some(PendingOneDriveLogin {
            redirect_uri: redirect_uri.clone(),
            code_verifier: code_verifier.clone(),
            code_receiver,
        });

        Ok(OneDriveAuthSessionDto {
            auth_url,
            redirect_uri,
            code_verifier,
            expires_in_seconds: 600,
        })
    }

    pub fn complete_pending_login(&mut self) -> Result<OneDriveAuthStatusDto> {
        let pending = self
            .pending_login
            .take()
            .context("OneDrive login has not been started")?;
        let code = pending
            .code_receiver
            .recv_timeout(Duration::from_secs(CALLBACK_WAIT_SECONDS))
            .context("timed out waiting for OneDrive callback")?
            .map_err(anyhow::Error::msg)?;
        self.complete_login(&code, &pending.redirect_uri, &pending.code_verifier)
    }

    pub fn complete_login(
        &mut self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<OneDriveAuthStatusDto> {
        if !self.memory_items.is_empty() {
            let account_label = self
                .memory_items
                .values()
                .next()
                .map(|item| item.account_label.clone());
            return Ok(OneDriveAuthStatusDto {
                status: "authorized".into(),
                account_label,
            });
        }

        let client_id = self
            .client_id
            .as_deref()
            .context("VAULTKERN_ONEDRIVE_CLIENT_ID is not configured")?;
        let token = ureq::post(&self.token_url)
            .send_form(&[
                ("client_id", client_id),
                ("scope", ONEDRIVE_SCOPES),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", code_verifier),
            ])
            .context("failed to exchange OneDrive authorization code")?
            .into_json::<TokenResponse>()
            .context("failed to decode OneDrive token response")?;
        let expires_at = access_expires_at(&token);
        let refresh_token = token
            .refresh_token
            .context("OneDrive token response did not include refresh_token")?;
        self.store_refresh_token(&refresh_token)?;
        self.refresh_token_load_error = None;
        self.token_state.replace(Some(OneDriveTokenState {
            access_token: Some(token.access_token),
            access_expires_at: expires_at,
            refresh_token,
            refresh_token_origin: RefreshTokenOrigin::Store,
        }));
        Ok(OneDriveAuthStatusDto {
            status: "authorized".into(),
            account_label: Some(self.account_label()?),
        })
    }

    pub fn list_children(&self, parent_item_id: Option<&str>) -> Result<OneDriveItemListDto> {
        if !self.memory_items.is_empty() {
            return Ok(OneDriveItemListDto {
                items: self
                    .memory_items
                    .values()
                    .map(|item| OneDriveItemDto {
                        drive_id: item.drive_id.clone(),
                        item_id: item.item_id.clone(),
                        name: item.name.clone(),
                        folder: false,
                        size: Some(item.bytes.len() as u64),
                    })
                    .collect(),
            });
        }

        let path = if let Some(parent_item_id) = parent_item_id {
            format!(
                "/me/drive/items/{}/children",
                encode_component(parent_item_id)
            )
        } else {
            "/me/drive/root/children".into()
        };
        let mut url = self.graph_url_with_query(
            &path,
            &[
                ("$select", GRAPH_CHILDREN_SELECT),
                ("$top", GRAPH_CHILDREN_PAGE_SIZE),
            ],
        );
        let mut items = Vec::new();

        loop {
            let response = self
                .authorized_get(&url)?
                .into_json::<GraphChildrenResponse>()
                .context("failed to decode OneDrive children response")?;
            items.extend(response.value.into_iter().filter_map(|item| {
                let drive_id = item.parent_reference?.drive_id?;
                Some(OneDriveItemDto {
                    drive_id,
                    item_id: item.id,
                    name: item.name,
                    folder: item.folder.is_some(),
                    size: item.size,
                })
            }));

            let Some(next_link) = response.next_link else {
                break;
            };
            url = next_link;
        }

        Ok(OneDriveItemListDto { items })
    }

    pub fn metadata(&self, drive_id: &str, item_id: &str) -> Result<OneDriveMetadata> {
        if self.memory_items.is_empty() {
            let item = self.graph_item(drive_id, item_id)?;
            return Ok(OneDriveMetadata {
                drive_id: drive_id.to_owned(),
                item_id: item.id,
                name: item.name,
                account_label: "OneDrive".into(),
                size: item.size,
            });
        }

        let item = self.item(drive_id, item_id)?;
        Ok(OneDriveMetadata {
            drive_id: item.drive_id.clone(),
            item_id: item.item_id.clone(),
            name: item.name.clone(),
            account_label: item.account_label.clone(),
            size: Some(item.bytes.len() as u64),
        })
    }

    pub fn read_snapshot(&self, drive_id: &str, item_id: &str) -> Result<OneDriveSnapshot> {
        if self.memory_items.is_empty() {
            let item = self.graph_item(drive_id, item_id)?;
            return self.read_snapshot_from_state(drive_id, item_id, &remote_state_for_item(item));
        }

        self.memory_snapshot_reads
            .set(self.memory_snapshot_reads.get() + 1);
        let item = self.item(drive_id, item_id)?;
        Ok(OneDriveSnapshot {
            bytes: item.bytes.clone(),
            fingerprint: fingerprint_for_memory_item(item),
            name: item.name.clone(),
            account_label: item.account_label.clone(),
        })
    }

    pub fn remote_state(&self, drive_id: &str, item_id: &str) -> Result<OneDriveRemoteState> {
        if self.memory_items.is_empty() {
            return self
                .graph_item(drive_id, item_id)
                .map(remote_state_for_item);
        }

        self.memory_remote_state_reads
            .set(self.memory_remote_state_reads.get() + 1);
        let item = self.item(drive_id, item_id)?;
        Ok(OneDriveRemoteState {
            name: item.name.clone(),
            size: Some(item.bytes.len() as u64),
            e_tag: None,
            download_url: None,
            memory_revision: Some(item.revision),
        })
    }

    pub fn read_snapshot_from_state(
        &self,
        drive_id: &str,
        item_id: &str,
        state: &OneDriveRemoteState,
    ) -> Result<OneDriveSnapshot> {
        if !self.memory_items.is_empty() {
            self.memory_snapshot_from_state_reads
                .set(self.memory_snapshot_from_state_reads.get() + 1);
            return self.read_snapshot(drive_id, item_id);
        }

        let bytes = self.download_item_bytes(drive_id, item_id, state.download_url.as_deref())?;
        Ok(OneDriveSnapshot {
            fingerprint: fingerprint_for_graph_item(&bytes, state.e_tag.as_deref()),
            bytes,
            name: state.name.clone(),
            account_label: "OneDrive".into(),
        })
    }

    pub fn write_with_known_etag(
        &mut self,
        drive_id: &str,
        item_id: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<VaultSourceFingerprint> {
        if !self.memory_items.is_empty() {
            self.memory_writes.set(self.memory_writes.get() + 1);
            let item = self
                .memory_items
                .get_mut(&(drive_id.to_owned(), item_id.to_owned()))
                .with_context(|| format!("OneDrive item not found: {drive_id}/{item_id}"))?;
            item.bytes = bytes.to_vec();
            item.revision += 1;
            return Ok(fingerprint_for_memory_item(item));
        }

        let etag = if_match.context("current OneDrive item did not include an ETag")?;
        let request = self
            .authorized_request(
                "PUT",
                &self.graph_url(&format!(
                    "/drives/{}/items/{}/content",
                    encode_component(drive_id),
                    encode_component(item_id)
                )),
            )?
            .set("If-Match", etag);
        let response = request
            .send_bytes(bytes)
            .context("failed to upload OneDrive item content")?;
        let response_etag = response
            .into_json::<GraphWriteResponse>()
            .ok()
            .and_then(|body| body.e_tag);
        Ok(fingerprint_for_graph_item(
            bytes,
            response_etag.as_deref().or(if_match),
        ))
    }

    pub fn conditional_write(
        &mut self,
        drive_id: &str,
        item_id: &str,
        bytes: &[u8],
        observed: &OneDriveRemoteState,
    ) -> Result<OneDriveConditionalWriteOutcome, OneDriveConditionalWriteError> {
        if !self.memory_items.is_empty() {
            self.memory_writes.set(self.memory_writes.get() + 1);
            let expected_revision = observed
                .memory_revision
                .ok_or(OneDriveConditionalWriteError::InvalidMemoryRevision)?;
            let item = self
                .memory_items
                .get_mut(&(drive_id.to_owned(), item_id.to_owned()))
                .ok_or_else(|| OneDriveConditionalWriteError::Unavailable {
                    message: format!("OneDrive item not found: {drive_id}/{item_id}"),
                })?;
            if item.revision != expected_revision {
                return Ok(OneDriveConditionalWriteOutcome::PreconditionFailed);
            }
            if let Some(behavior) = self.memory_write_behaviors.pop_front() {
                match behavior {
                    OneDriveMemoryWriteBehavior::PreconditionFailed { replacement_bytes } => {
                        if let Some(replacement_bytes) = replacement_bytes {
                            item.bytes = replacement_bytes;
                            item.revision += 1;
                        }
                        return Ok(OneDriveConditionalWriteOutcome::PreconditionFailed);
                    }
                    OneDriveMemoryWriteBehavior::OutcomeUnknownCommitted => {
                        item.bytes = bytes.to_vec();
                        item.revision += 1;
                        return Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown {
                            message: "injected ambiguous committed write".into(),
                        });
                    }
                    OneDriveMemoryWriteBehavior::OutcomeUnknownNotCommitted => {
                        return Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown {
                            message: "injected ambiguous uncommitted write".into(),
                        });
                    }
                }
            }
            item.bytes = bytes.to_vec();
            item.revision += 1;
            return Ok(OneDriveConditionalWriteOutcome::Committed {
                fingerprint: fingerprint_for_memory_item(item),
                e_tag: None,
            });
        }

        let etag = observed
            .e_tag
            .as_deref()
            .ok_or(OneDriveConditionalWriteError::MissingEtag)?;
        let request = self
            .authorized_request(
                "PUT",
                &self.graph_url(&format!(
                    "/drives/{}/items/{}/content",
                    encode_component(drive_id),
                    encode_component(item_id)
                )),
            )
            .map_err(|error| OneDriveConditionalWriteError::Unavailable {
                message: format!("{error:#}"),
            })?
            .set("If-Match", etag);
        match request.send_bytes(bytes) {
            Ok(response) => {
                let response_etag = response
                    .into_json::<GraphWriteResponse>()
                    .ok()
                    .and_then(|body| body.e_tag);
                Ok(OneDriveConditionalWriteOutcome::Committed {
                    fingerprint: fingerprint_for_graph_item(bytes, response_etag.as_deref()),
                    e_tag: response_etag,
                })
            }
            Err(ureq::Error::Status(412, _)) => {
                Ok(OneDriveConditionalWriteOutcome::PreconditionFailed)
            }
            Err(ureq::Error::Status(status, _)) => {
                Err(OneDriveConditionalWriteError::Rejected { status })
            }
            Err(ureq::Error::Transport(error)) => {
                Ok(OneDriveConditionalWriteOutcome::OutcomeUnknown {
                    message: error.to_string(),
                })
            }
        }
    }

    fn item(&self, drive_id: &str, item_id: &str) -> Result<&MemoryOneDriveItem> {
        self.memory_items
            .get(&(drive_id.to_owned(), item_id.to_owned()))
            .with_context(|| format!("OneDrive item not found: {drive_id}/{item_id}"))
    }

    fn account_label(&self) -> Result<String> {
        let me = self
            .authorized_get(&self.graph_url("/me"))?
            .into_json::<GraphMeResponse>()
            .context("failed to decode OneDrive account response")?;
        Ok(me
            .user_principal_name
            .or(me.display_name)
            .unwrap_or_else(|| "OneDrive".into()))
    }

    fn graph_item(&self, drive_id: &str, item_id: &str) -> Result<GraphDriveItem> {
        let url = self.graph_url_with_query(
            &format!(
                "/drives/{}/items/{}",
                encode_component(drive_id),
                encode_component(item_id)
            ),
            &[("$select", GRAPH_ITEM_SELECT)],
        );
        self.authorized_get(&url)?
            .into_json::<GraphDriveItem>()
            .context("failed to decode OneDrive item metadata")
    }

    fn graph_url(&self, path: &str) -> String {
        format!("{}{}", self.graph_root.trim_end_matches('/'), path)
    }

    fn graph_url_with_query(&self, path: &str, query: &[(&str, &str)]) -> String {
        let mut url = self.graph_url(path);
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query.iter().copied())
            .finish();
        url.push('?');
        url.push_str(&encoded);
        url
    }

    fn download_item_bytes(
        &self,
        drive_id: &str,
        item_id: &str,
        download_url: Option<&str>,
    ) -> Result<Vec<u8>> {
        let response = if let Some(download_url) = download_url {
            ureq::get(download_url)
                .call()
                .map_err(anyhow::Error::from)?
        } else {
            self.authorized_get(&self.graph_url(&format!(
                "/drives/{}/items/{}/content",
                encode_component(drive_id),
                encode_component(item_id)
            )))?
        };

        let mut reader = response.into_reader();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .context("failed to read OneDrive item content")?;
        Ok(bytes)
    }

    fn authorized_get(&self, url: &str) -> Result<ureq::Response> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.authorized_request("GET", url)?.call() {
                Ok(response) => return Ok(response),
                Err(ureq::Error::Status(401, _)) if attempt == 1 => {
                    self.clear_access_token();
                    continue;
                }
                Err(ureq::Error::Status(status, response))
                    if is_retryable_graph_status(status)
                        && attempt < MAX_AUTHORIZED_GET_ATTEMPTS =>
                {
                    wait_for_retry_after(&response);
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn authorized_request(&self, method: &str, url: &str) -> Result<ureq::Request> {
        let access_token = self.access_token()?;
        Ok(ureq::request(method, url).set("Authorization", &format!("Bearer {access_token}")))
    }

    fn access_token(&self) -> Result<String> {
        if let Some(state) = self.token_state.borrow().as_ref() {
            if let Some(access_token) = state.access_token.clone() {
                let token_is_fresh = state.access_expires_at.is_some_and(|expires_at| {
                    expires_at > Instant::now() + ACCESS_TOKEN_EXPIRY_SKEW
                });
                if token_is_fresh {
                    return Ok(access_token);
                }
            }
        }
        self.refresh_access_token()
    }

    fn clear_access_token(&self) {
        if let Some(state) = self.token_state.borrow_mut().as_mut() {
            state.access_token = None;
            state.access_expires_at = None;
        }
    }

    fn refresh_access_token(&self) -> Result<String> {
        let client_id = self
            .client_id
            .as_deref()
            .context("VAULTKERN_ONEDRIVE_CLIENT_ID is not configured")?;
        let current_token = self
            .token_state
            .borrow()
            .as_ref()
            .map(|state| (state.refresh_token.clone(), state.refresh_token_origin))
            .or_else(|| {
                std::env::var("VAULTKERN_ONEDRIVE_REFRESH_TOKEN")
                    .ok()
                    .map(|token| (Zeroizing::new(token), RefreshTokenOrigin::Environment))
            });
        let Some((refresh_token, refresh_token_origin)) = current_token else {
            if let Some(error) = &self.refresh_token_load_error {
                anyhow::bail!("failed to load persisted OneDrive refresh token: {error}");
            }
            anyhow::bail!("OneDrive account is not connected");
        };
        let token = ureq::post(&self.token_url)
            .send_form(&[
                ("client_id", client_id),
                ("scope", ONEDRIVE_SCOPES),
                ("refresh_token", refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .context("failed to refresh OneDrive access token")?
            .into_json::<TokenResponse>()
            .context("failed to decode OneDrive refresh response")?;
        let expires_at = access_expires_at(&token);
        let (next_refresh, next_origin) = match token.refresh_token {
            Some(next_refresh) => {
                let next_origin = match self.store_refresh_token(&next_refresh) {
                    Ok(()) => RefreshTokenOrigin::Store,
                    Err(error)
                        if refresh_token_origin == RefreshTokenOrigin::Environment
                            && is_unavailable_error(&error) =>
                    {
                        RefreshTokenOrigin::Environment
                    }
                    Err(error) => return Err(error),
                };
                (next_refresh, next_origin)
            }
            None if refresh_token_origin == RefreshTokenOrigin::Store => {
                (refresh_token, RefreshTokenOrigin::Store)
            }
            None => {
                let next_origin = match self.store_refresh_token(&refresh_token) {
                    Ok(()) => RefreshTokenOrigin::Store,
                    Err(error) if is_unavailable_error(&error) => RefreshTokenOrigin::Environment,
                    Err(error) => return Err(error),
                };
                (refresh_token, next_origin)
            }
        };
        self.token_state.replace(Some(OneDriveTokenState {
            access_token: Some(token.access_token.clone()),
            access_expires_at: expires_at,
            refresh_token: next_refresh,
            refresh_token_origin: next_origin,
        }));
        Ok(token.access_token)
    }

    fn store_refresh_token(&self, refresh_token: &str) -> Result<()> {
        self.refresh_token_store.store(refresh_token)
    }
}

fn load_refresh_token_state(
    refresh_token_store: &dyn OneDriveRefreshTokenStore,
) -> (Option<OneDriveTokenState>, Option<String>) {
    match refresh_token_store.load() {
        Ok(Some(refresh_token)) => (
            Some(OneDriveTokenState {
                access_token: None,
                access_expires_at: None,
                refresh_token,
                refresh_token_origin: RefreshTokenOrigin::Store,
            }),
            None,
        ),
        Ok(None) => (None, None),
        Err(error) => (None, Some(format!("{error:#}"))),
    }
}

fn fingerprint_for_memory_item(item: &MemoryOneDriveItem) -> VaultSourceFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(&item.bytes);
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    VaultSourceFingerprint {
        content_sha256,
        size_bytes: item.bytes.len() as u64,
        modified_at: Some(item.revision),
    }
}

fn remote_state_for_item(item: GraphDriveItem) -> OneDriveRemoteState {
    OneDriveRemoteState {
        name: item.name,
        size: item.size,
        e_tag: item.e_tag,
        download_url: item.download_url,
        memory_revision: None,
    }
}

fn access_expires_at(token: &TokenResponse) -> Option<Instant> {
    token
        .expires_in
        .map(|seconds| Instant::now() + Duration::from_secs(seconds))
}

fn deserialize_optional_refresh_token<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|token| token.map(Zeroizing::new))
}

fn is_retryable_graph_status(status: u16) -> bool {
    matches!(status, 429 | 503)
}

fn wait_for_retry_after(response: &ureq::Response) {
    let Some(seconds) = response
        .header("Retry-After")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return;
    };
    std::thread::sleep(Duration::from_secs(seconds.min(5)));
}

fn start_loopback_callback_listener(
    callback_addr: &str,
) -> Result<(Receiver<Result<String, String>>, String)> {
    let listener = TcpListener::bind(callback_addr)
        .with_context(|| format!("failed to listen for OneDrive callback on {callback_addr}"))?;
    let local_addr = listener
        .local_addr()
        .context("failed to resolve OneDrive callback listener address")?;
    let redirect_uri = format!("http://{local_addr}/callback");
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let result = match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buffer = [0_u8; 8192];
                match stream.read(&mut buffer) {
                    Ok(len) => {
                        let request = String::from_utf8_lossy(&buffer[..len]);
                        let code_result = parse_callback_code(&request);
                        let response = if code_result.is_ok() {
                            callback_response(
                                "200 OK",
                                "OneDrive authorization complete. You can return to VaultKern.",
                            )
                        } else {
                            callback_response(
                                "400 Bad Request",
                                "OneDrive authorization failed. You can close this tab.",
                            )
                        };
                        let _ = stream.write_all(response.as_bytes());
                        code_result
                    }
                    Err(error) => Err(format!("failed to read OneDrive callback: {error}")),
                }
            }
            Err(error) => Err(format!("failed to accept OneDrive callback: {error}")),
        };
        let _ = sender.send(result);
    });

    Ok((receiver, redirect_uri))
}

fn parse_callback_code(request: &str) -> Result<String, String> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| "empty OneDrive callback request".to_owned())?;
    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing OneDrive callback method".to_owned())?;
    let path = parts
        .next()
        .ok_or_else(|| "missing OneDrive callback path".to_owned())?;
    if method != "GET" {
        return Err("OneDrive callback used an unsupported HTTP method".into());
    }

    let url = url::Url::parse(&format!("http://127.0.0.1{path}"))
        .map_err(|error| format!("invalid OneDrive callback URL: {error}"))?;
    if let Some(error) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "error").then(|| value.into_owned()))
    {
        return Err(format!("OneDrive authorization failed: {error}"));
    }
    url.query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .filter(|code| !code.trim().is_empty())
        .ok_or_else(|| "OneDrive callback did not include an authorization code".to_owned())
}

fn callback_response(status: &str, body: &str) -> String {
    let html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>VaultKern OneDrive</title><body>{body}</body>"
    );
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    )
}

fn fingerprint_for_graph_item(bytes: &[u8], etag: Option<&str>) -> VaultSourceFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    VaultSourceFingerprint {
        content_sha256,
        size_bytes: bytes.len() as u64,
        modified_at: etag.map(stable_u64_for_text),
    }
}

fn stable_u64_for_text(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

fn new_code_verifier() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        OneDriveConditionalWriteError, OneDriveConditionalWriteOutcome,
        OneDriveVaultSourceProvider, stable_u64_for_text,
    };
    use crate::providers::onedrive_token_store::{
        MemoryOneDriveRefreshTokenStore, OneDriveRefreshTokenStore,
    };
    use anyhow::Result;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use zeroize::Zeroizing;

    struct FailingRefreshTokenStore;

    struct LoadFailingRefreshTokenStore;

    struct FailOnStoreRefreshTokenStore {
        store_calls: Arc<AtomicUsize>,
    }

    impl OneDriveRefreshTokenStore for FailingRefreshTokenStore {
        fn load(&self) -> Result<Option<Zeroizing<String>>> {
            Ok(None)
        }

        fn store(&self, _token: &str) -> Result<()> {
            anyhow::bail!("simulated secure store failure")
        }

        fn delete(&self) -> Result<()> {
            Ok(())
        }
    }

    impl OneDriveRefreshTokenStore for LoadFailingRefreshTokenStore {
        fn load(&self) -> Result<Option<Zeroizing<String>>> {
            anyhow::bail!("simulated secure store load failure")
        }

        fn store(&self, _token: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&self) -> Result<()> {
            Ok(())
        }
    }

    impl OneDriveRefreshTokenStore for FailOnStoreRefreshTokenStore {
        fn load(&self) -> Result<Option<Zeroizing<String>>> {
            Ok(Some(Zeroizing::new("refresh-1".to_owned())))
        }

        fn store(&self, _token: &str) -> Result<()> {
            self.store_calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("store must not be called without token rotation")
        }

        fn delete(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn provider_uses_compile_time_public_client_id_for_pkce_login_when_configured() {
        let result = OneDriveVaultSourceProvider::new_from_env_with_refresh_token_store(Box::new(
            MemoryOneDriveRefreshTokenStore::default(),
        ))
        .begin_login();

        match option_env!("VAULTKERN_ONEDRIVE_CLIENT_ID") {
            Some(client_id) => {
                let session = result.expect("begin login with compiled public client id");
                assert!(session.auth_url.contains(&format!("client_id={client_id}")));
                let port = callback_port(&session.redirect_uri);
                let _ = send_callback(port, "code=ignored");
            }
            None => {
                let error = result.expect_err("missing compiled client id should fail");
                assert!(format!("{error:#}").contains("VAULTKERN_ONEDRIVE_CLIENT_ID"));
            }
        }
    }

    #[test]
    fn provider_uses_explicit_test_client_id_for_pkce_login() {
        let result = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-from-test",
            "https://login.example.test/authorize",
            "https://login.example.test/token",
            "https://graph.example.test",
        )
        .begin_login();

        let session = result.expect("begin login with explicit test client id");
        assert!(session.auth_url.contains("client_id=client-from-test"));
        let port = callback_port(&session.redirect_uri);
        let _ = send_callback(port, "code=ignored");
    }

    #[test]
    fn provider_receives_authorization_code_from_loopback_callback() {
        let mut server = mockito::Server::new();
        let token = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("code".into(), "auth-code".into()),
                mockito::Matcher::UrlEncoded("code_verifier".into(), "verifier".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#,
            )
            .create();
        let me = server
            .mock("GET", "/v1.0/me")
            .match_header("authorization", "Bearer access-1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"userPrincipalName":"alice@example.com"}"#)
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_code_verifier("verifier");
        let auth = provider.begin_login().unwrap();
        let port = callback_port(&auth.redirect_uri);
        let callback = std::thread::spawn(move || send_callback(port, "code=auth-code"));

        let status = provider.complete_pending_login().unwrap();

        assert_eq!(status.account_label.as_deref(), Some("alice@example.com"));
        assert!(
            callback
                .join()
                .unwrap()
                .contains("OneDrive authorization complete")
        );
        token.assert();
        me.assert();
    }

    #[test]
    fn graph_provider_completes_login_and_lists_children() {
        let mut server = mockito::Server::new();
        let token = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("code".into(), "auth-code".into()),
                mockito::Matcher::UrlEncoded("code_verifier".into(), "verifier".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#,
            )
            .create();
        let me = server
            .mock("GET", "/v1.0/me")
            .match_header("authorization", "Bearer access-1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"userPrincipalName":"alice@example.com"}"#)
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-1","name":"Vault.kdbx","size":42,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );

        let status = provider
            .complete_login("auth-code", "http://127.0.0.1/callback", "verifier")
            .unwrap();
        let items = provider.list_children(None).unwrap();

        assert_eq!(status.status, "authorized");
        assert_eq!(status.account_label.as_deref(), Some("alice@example.com"));
        assert_eq!(items.items.len(), 1);
        assert_eq!(items.items[0].drive_id, "drive-1");
        assert_eq!(items.items[0].item_id, "item-1");
        token.assert();
        me.assert();
        children.assert();
    }

    #[test]
    fn graph_provider_lists_children_with_minimal_fields_and_follows_next_link() {
        let mut server = mockito::Server::new();
        let first_page = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"value":[{{"id":"item-1","name":"First.kdbx","size":42,"parentReference":{{"driveId":"drive-1"}},"file":{{}}}}],"@odata.nextLink":"{}/v1.0/me/drive/root/children?$skiptoken=page-2"}}"#,
                server.url()
            ))
            .create();
        let second_page = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::UrlEncoded(
                "$skiptoken".into(),
                "page-2".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-2","name":"Second.kdbx","size":64,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");

        let items = provider.list_children(None).unwrap();

        assert_eq!(
            items
                .items
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["First.kdbx", "Second.kdbx"]
        );
        first_page.assert();
        second_page.assert();
    }

    #[test]
    fn graph_provider_reads_metadata_content_and_writes_with_etag() {
        let mut server = mockito::Server::new();
        let metadata = server
            .mock("GET", "/v1.0/drives/drive-1/items/item-1")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::UrlEncoded(
                "$select".into(),
                "id,name,size,eTag,parentReference,@microsoft.graph.downloadUrl".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"item-1","name":"Vault.kdbx","size":4,"eTag":"etag-1","parentReference":{"driveId":"drive-1"}}"#,
            )
            .expect(3)
            .create();
        let content = server
            .mock("GET", "/v1.0/drives/drive-1/items/item-1/content")
            .match_header("authorization", "Bearer access-1")
            .with_status(200)
            .with_body("kdbx")
            .create();
        let write = server
            .mock("PUT", "/v1.0/drives/drive-1/items/item-1/content")
            .match_header("authorization", "Bearer access-1")
            .match_header("if-match", "etag-1")
            .match_body("next")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"item-1"}"#)
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");

        let item_metadata = provider.metadata("drive-1", "item-1").unwrap();
        let state = provider.remote_state("drive-1", "item-1").unwrap();
        let snapshot = provider.read_snapshot("drive-1", "item-1").unwrap();
        provider
            .write_with_known_etag("drive-1", "item-1", b"next", state.e_tag.as_deref())
            .unwrap();

        assert_eq!(item_metadata.account_label, "OneDrive");
        assert_eq!(snapshot.bytes, b"kdbx");
        metadata.assert();
        content.assert();
        write.assert();
    }

    #[test]
    fn graph_provider_refreshes_before_using_expired_cached_access_token() {
        let mut server = mockito::Server::new();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "refresh-1".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"fresh-access","refresh_token":"refresh-2","expires_in":3600}"#,
            )
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer fresh-access")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-1","name":"Vault.kdbx","size":42,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_expired_test_tokens("expired-access", "refresh-1");

        let items = provider.list_children(None).unwrap();

        assert_eq!(items.items[0].name, "Vault.kdbx");
        refresh.assert();
        children.assert();
    }

    #[test]
    fn graph_provider_retries_get_after_retry_after_throttle() {
        let mut server = mockito::Server::new();
        let throttled_children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(429)
            .with_header("retry-after", "0")
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"code":"tooManyRequests"}}"#)
            .create();
        let fresh_children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-1","name":"Vault.kdbx","size":42,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");

        let items = provider.list_children(None).unwrap();

        assert_eq!(items.items[0].name, "Vault.kdbx");
        throttled_children.assert();
        fresh_children.assert();
    }

    #[test]
    fn graph_provider_writes_with_known_etag_without_fetching_metadata() {
        let mut server = mockito::Server::new();
        let write = server
            .mock("PUT", "/v1.0/drives/drive-1/items/item-1/content")
            .match_header("authorization", "Bearer access-1")
            .match_header("if-match", "etag-1")
            .match_body("next")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"eTag":"etag-2"}"#)
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");

        let fingerprint = provider
            .write_with_known_etag("drive-1", "item-1", b"next", Some("etag-1"))
            .unwrap();

        assert_eq!(fingerprint.size_bytes, 4);
        assert_eq!(fingerprint.modified_at, Some(stable_u64_for_text("etag-2")));
        write.assert();
    }

    #[test]
    fn graph_provider_rejects_write_when_known_etag_is_missing() {
        let mut server = mockito::Server::new();
        let write = server
            .mock("PUT", "/v1.0/drives/drive-1/items/item-1/content")
            .expect(0)
            .create();
        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");

        let error = provider
            .write_with_known_etag("drive-1", "item-1", b"next", None)
            .expect_err("missing Graph ETag must fail before PUT");

        assert!(error.to_string().contains("ETag"));
        write.assert();
    }

    #[test]
    fn graph_conditional_write_fails_closed_when_current_etag_is_missing() {
        let mut server = mockito::Server::new();
        let metadata = server
            .mock("GET", "/v1.0/drives/drive-1/items/item-1")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::UrlEncoded(
                "$select".into(),
                "id,name,size,eTag,parentReference,@microsoft.graph.downloadUrl".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"item-1","name":"Vault.kdbx","size":4,"parentReference":{"driveId":"drive-1"}}"#,
            )
            .create();
        let write = server
            .mock("PUT", "/v1.0/drives/drive-1/items/item-1/content")
            .expect(0)
            .create();
        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");
        let state = provider.remote_state("drive-1", "item-1").unwrap();

        let error = provider
            .conditional_write("drive-1", "item-1", b"next", &state)
            .expect_err("missing Graph ETag must fail closed");

        assert!(matches!(error, OneDriveConditionalWriteError::MissingEtag));
        metadata.assert();
        write.assert();
    }

    #[test]
    fn graph_conditional_write_returns_typed_precondition_failure_for_412() {
        let mut server = mockito::Server::new();
        let metadata = server
            .mock("GET", "/v1.0/drives/drive-1/items/item-1")
            .match_header("authorization", "Bearer access-1")
            .match_query(mockito::Matcher::UrlEncoded(
                "$select".into(),
                "id,name,size,eTag,parentReference,@microsoft.graph.downloadUrl".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"item-1","name":"Vault.kdbx","size":4,"eTag":"etag-1","parentReference":{"driveId":"drive-1"}}"#,
            )
            .create();
        let write = server
            .mock("PUT", "/v1.0/drives/drive-1/items/item-1/content")
            .match_header("authorization", "Bearer access-1")
            .match_header("if-match", "etag-1")
            .with_status(412)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"code":"preconditionFailed"}}"#)
            .create();
        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("access-1", "refresh-1");
        let state = provider.remote_state("drive-1", "item-1").unwrap();

        let outcome = provider
            .conditional_write("drive-1", "item-1", b"next", &state)
            .unwrap();

        assert!(matches!(
            outcome,
            OneDriveConditionalWriteOutcome::PreconditionFailed
        ));
        metadata.assert();
        write.assert();
    }

    #[test]
    fn memory_conditional_write_compares_the_observed_revision() {
        let mut provider = OneDriveVaultSourceProvider::new_in_memory();
        provider.insert_memory_item(
            "drive-1",
            "item-1",
            "Vault.kdbx",
            "alice@example.com",
            b"old".to_vec(),
        );
        let stale = provider.remote_state("drive-1", "item-1").unwrap();
        provider.replace_memory_item("drive-1", "item-1", b"external".to_vec());

        let outcome = provider
            .conditional_write("drive-1", "item-1", b"must-not-win", &stale)
            .unwrap();

        assert!(matches!(
            outcome,
            OneDriveConditionalWriteOutcome::PreconditionFailed
        ));
        assert_eq!(
            provider
                .read_memory_item_bytes("drive-1", "item-1")
                .unwrap(),
            b"external"
        );
    }

    #[test]
    fn graph_provider_refreshes_access_token_after_unauthorized_response() {
        let mut server = mockito::Server::new();
        let stale_children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer stale-access")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"code":"InvalidAuthenticationToken"}}"#)
            .create();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "refresh-1".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"fresh-access","refresh_token":"refresh-2","expires_in":3600}"#,
            )
            .create();
        let fresh_children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer fresh-access")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-1","name":"Vault.kdbx","size":42,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut provider = OneDriveVaultSourceProvider::new_for_graph_tests(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
        );
        provider.set_test_tokens("stale-access", "refresh-1");

        let items = provider.list_children(None).unwrap();

        assert_eq!(items.items.len(), 1);
        assert_eq!(items.items[0].name, "Vault.kdbx");
        stale_children.assert();
        refresh.assert();
        fresh_children.assert();
    }

    #[test]
    fn refresh_token_store_restores_token_after_provider_restart() {
        let store = MemoryOneDriveRefreshTokenStore::default();
        let mut server = mockito::Server::new();
        let login_token = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("code".into(), "auth-code".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#,
            )
            .create();
        let me = server
            .mock("GET", "/v1.0/me")
            .match_header("authorization", "Bearer access-1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"userPrincipalName":"alice@example.com"}"#)
            .create();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "client-1".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "refresh-1".into()),
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"access-2","expires_in":3600}"#)
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-2")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "$select".into(),
                    "id,name,size,eTag,parentReference,folder,file".into(),
                ),
                mockito::Matcher::UrlEncoded("$top".into(), "200".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"value":[{"id":"item-1","name":"Vault.kdbx","size":42,"parentReference":{"driveId":"drive-1"},"file":{}}]}"#,
            )
            .create();

        let mut first = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(store.clone()),
        );
        first
            .complete_login("auth-code", "http://127.0.0.1:53121/callback", "verifier")
            .unwrap();

        let second = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(store),
        );
        let items = second.list_children(None).unwrap();

        assert_eq!(items.items[0].name, "Vault.kdbx");
        login_token.assert();
        me.assert();
        refresh.assert();
        children.assert();
    }

    #[test]
    fn refresh_token_store_replaces_rotated_token() {
        let store = MemoryOneDriveRefreshTokenStore::default();
        store.store("refresh-1").unwrap();
        let mut server = mockito::Server::new();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "refresh_token".into(),
                "refresh-1".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}"#,
            )
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-2")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"value":[]}"#)
            .create();
        let provider = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(store.clone()),
        );

        provider.list_children(None).unwrap();

        assert_eq!(
            store.load().unwrap().as_deref().map(String::as_str),
            Some("refresh-2")
        );
        refresh.assert();
        children.assert();
    }

    #[test]
    fn refresh_without_rotated_token_does_not_rewrite_persisted_token() {
        let store_calls = Arc::new(AtomicUsize::new(0));
        let mut server = mockito::Server::new();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "refresh_token".into(),
                "refresh-1".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"access-2","expires_in":3600}"#)
            .expect(1)
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-2")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"value":[]}"#)
            .expect(1)
            .create();
        let provider = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(FailOnStoreRefreshTokenStore {
                store_calls: store_calls.clone(),
            }),
        );

        provider.list_children(None).unwrap();

        assert_eq!(store_calls.load(Ordering::SeqCst), 0);
        refresh.assert();
        children.assert();
    }

    #[test]
    fn refresh_token_store_failure_fails_oauth_completion() {
        let mut server = mockito::Server::new();
        let token = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-1","refresh_token":"sensitive-refresh-token","expires_in":3600}"#,
            )
            .create();
        let mut provider =
            OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
                "client-1",
                &format!("{}/authorize", server.url()),
                &format!("{}/token", server.url()),
                &format!("{}/v1.0", server.url()),
                Box::new(FailingRefreshTokenStore),
            );

        let error = provider
            .complete_login("auth-code", "http://127.0.0.1:53121/callback", "verifier")
            .expect_err("OAuth completion must fail when the refresh token cannot be stored");

        assert!(format!("{error:#}").contains("simulated secure store failure"));
        token.assert();
    }

    #[test]
    fn refresh_token_store_errors_do_not_include_token_values() {
        const TOKEN: &str = "sensitive-refresh-token-must-not-leak";
        let mut server = mockito::Server::new();
        let token = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"access_token":"access-1","refresh_token":"{TOKEN}","expires_in":3600}}"#
            ))
            .create();
        let mut provider =
            OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
                "client-1",
                &format!("{}/authorize", server.url()),
                &format!("{}/token", server.url()),
                &format!("{}/v1.0", server.url()),
                Box::new(FailingRefreshTokenStore),
            );

        let error = provider
            .complete_login("auth-code", "http://127.0.0.1:53121/callback", "verifier")
            .expect_err("store failure should be reported");

        assert!(!format!("{error:#}").contains(TOKEN));
        token.assert();
    }

    #[test]
    fn refresh_token_store_load_failure_remains_observable() {
        let mut server = mockito::Server::new();
        let token = server.mock("POST", "/token").expect(0).create();
        let provider = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(LoadFailingRefreshTokenStore),
        );

        let error = provider
            .list_children(None)
            .expect_err("secure-store load failure must not look like a disconnected account");

        assert!(format!("{error:#}").contains("simulated secure store load failure"));
        token.assert();
    }

    #[cfg(not(windows))]
    #[test]
    fn refresh_token_store_keeps_environment_token_ephemeral_when_backend_is_unavailable() {
        use crate::providers::onedrive_token_store::UnavailableOneDriveRefreshTokenStore;

        let mut server = mockito::Server::new();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "refresh_token".into(),
                "refresh-from-environment".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"access-2","refresh_token":"rotated-refresh","expires_in":3600}"#,
            )
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-2")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"value":[]}"#)
            .create();
        let provider =
            OneDriveVaultSourceProvider::new_for_graph_tests_with_environment_refresh_token(
                "client-1",
                &format!("{}/authorize", server.url()),
                &format!("{}/token", server.url()),
                &format!("{}/v1.0", server.url()),
                Box::new(UnavailableOneDriveRefreshTokenStore),
                "refresh-from-environment",
            );

        provider.list_children(None).unwrap();

        refresh.assert();
        children.assert();
    }

    #[cfg(windows)]
    #[test]
    fn refresh_token_store_state_directory_never_contains_plaintext() {
        use crate::providers::onedrive_token_store::WindowsOneDriveRefreshTokenStore;

        const INITIAL_TOKEN: &str = "initial-refresh-token-filesystem-regression";
        const ROTATED_TOKEN: &str = "rotated-refresh-token-filesystem-regression";
        let state_dir = tempfile::tempdir().unwrap();
        let token_path = state_dir.path().join("onedrive-refresh-token.dpapi");
        let mut server = mockito::Server::new();
        let login_token = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "grant_type".into(),
                "authorization_code".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"access_token":"access-1","refresh_token":"{INITIAL_TOKEN}","expires_in":3600}}"#
            ))
            .create();
        let me = server
            .mock("GET", "/v1.0/me")
            .match_header("authorization", "Bearer access-1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"userPrincipalName":"alice@example.com"}"#)
            .create();
        let refresh = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "refresh_token".into(),
                INITIAL_TOKEN.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"access_token":"access-2","refresh_token":"{ROTATED_TOKEN}","expires_in":3600}}"#
            ))
            .create();
        let children = server
            .mock("GET", "/v1.0/me/drive/root/children")
            .match_header("authorization", "Bearer access-2")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"value":[]}"#)
            .create();

        let mut first = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(WindowsOneDriveRefreshTokenStore::new(
                token_path.clone(),
                "test/default",
            )),
        );
        first
            .complete_login("auth-code", "http://127.0.0.1:53121/callback", "verifier")
            .unwrap();
        drop(first);

        let second = OneDriveVaultSourceProvider::new_for_graph_tests_with_refresh_token_store(
            "client-1",
            &format!("{}/authorize", server.url()),
            &format!("{}/token", server.url()),
            &format!("{}/v1.0", server.url()),
            Box::new(WindowsOneDriveRefreshTokenStore::new(
                token_path,
                "test/default",
            )),
        );
        second.list_children(None).unwrap();

        let mut pending = vec![state_dir.path().to_owned()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file() {
                    let bytes = std::fs::read(entry.path()).unwrap();
                    assert!(
                        !bytes
                            .windows(INITIAL_TOKEN.len())
                            .any(|window| { window == INITIAL_TOKEN.as_bytes() })
                    );
                    assert!(
                        !bytes
                            .windows(ROTATED_TOKEN.len())
                            .any(|window| { window == ROTATED_TOKEN.as_bytes() })
                    );
                }
            }
        }
        login_token.assert();
        me.assert();
        refresh.assert();
        children.assert();
    }

    fn callback_port(redirect_uri: &str) -> u16 {
        url::Url::parse(redirect_uri)
            .unwrap()
            .port()
            .expect("redirect uri should include port")
    }

    fn send_callback(port: u16, query: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(
                format!("GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes(),
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
}
