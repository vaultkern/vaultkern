#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vaultkern_runtime_protocol::{ProtocolEnvelope, RuntimeResponse};
use zeroize::Zeroizing;

use crate::command_loop::encode_zeroizing_json;
use crate::state_paths::extension_id_from_browser_origin;
use crate::{RuntimeProtocolDispatch, RuntimeProtocolSession};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    WindowsResidentIpcServer, run_windows_native_messaging_shim, start_windows_resident_ipc_server,
};

pub type ResidentIpcRequestHandler = Arc<
    dyn Fn(ProtocolEnvelope, Arc<AtomicBool>, Option<usize>) -> RuntimeResponse
        + Send
        + Sync
        + 'static,
>;

pub const RESIDENT_IPC_PROTOCOL_VERSION: u32 = 1;
pub const RESIDENT_IPC_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024 + 4 * 1024;
pub const RESIDENT_IPC_DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const RESIDENT_IPC_MAX_TIMEOUT_MS: u64 = 5 * 60_000;

const RESIDENT_IPC_CAPABILITIES: [&str; 2] = ["request_ids", "cancellation"];
const MAX_REQUEST_ID_BYTES: usize = 256;

#[derive(Clone, Default)]
pub(crate) struct PendingRequests {
    entries: Arc<Mutex<HashMap<String, Arc<PendingRequestState>>>>,
}

struct PendingRequestState {
    cancelled: Arc<AtomicBool>,
    phase: AtomicU8,
}

const REQUEST_PENDING: u8 = 0;
const REQUEST_EXECUTING: u8 = 1;
const REQUEST_RESPONDED: u8 = 2;

#[derive(Clone)]
pub(crate) struct PendingRequest {
    request_id: String,
    state: Arc<PendingRequestState>,
    entries: Arc<Mutex<HashMap<String, Arc<PendingRequestState>>>>,
}

impl PendingRequests {
    pub(crate) fn register(&self, request_id: &str) -> Result<PendingRequest> {
        let state = Arc::new(PendingRequestState {
            cancelled: Arc::new(AtomicBool::new(false)),
            phase: AtomicU8::new(REQUEST_PENDING),
        });
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries.contains_key(request_id) {
            anyhow::bail!("duplicate resident IPC request ID");
        }
        entries.insert(request_id.to_owned(), state.clone());
        Ok(PendingRequest {
            request_id: request_id.to_owned(),
            state,
            entries: self.entries.clone(),
        })
    }

    pub(crate) fn cancel(&self, request_id: &str) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let state = entries.get(request_id).cloned();
        let Some(state) = state else {
            return false;
        };
        state.cancelled.store(true, Ordering::Release);
        if state
            .phase
            .compare_exchange(
                REQUEST_PENDING,
                REQUEST_RESPONDED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        entries.remove(request_id);
        true
    }

    pub(crate) fn cancel_all(&self) {
        let entries = std::mem::take(
            &mut *self
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
        for state in entries.into_values() {
            state.cancelled.store(true, Ordering::Release);
            state.phase.store(REQUEST_RESPONDED, Ordering::Release);
        }
    }
}

impl PendingRequest {
    pub(crate) fn cancellation_token(&self) -> Arc<AtomicBool> {
        self.state.cancelled.clone()
    }

    pub(crate) fn begin_execution(&self) -> bool {
        self.state
            .phase
            .compare_exchange(
                REQUEST_PENDING,
                REQUEST_EXECUTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn claim_deadline_response(&self) -> Option<bool> {
        self.state.cancelled.store(true, Ordering::Release);
        loop {
            let phase = self.state.phase.load(Ordering::Acquire);
            if phase == REQUEST_RESPONDED {
                return None;
            }
            if self
                .state
                .phase
                .compare_exchange(
                    phase,
                    REQUEST_RESPONDED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.remove_from_registry();
                return Some(phase == REQUEST_EXECUTING);
            }
        }
    }

    pub(crate) fn response_claimed(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == REQUEST_RESPONDED
    }

    pub(crate) fn claim_response(&self) -> bool {
        loop {
            let phase = self.state.phase.load(Ordering::Acquire);
            if phase == REQUEST_RESPONDED {
                return false;
            }
            if self
                .state
                .phase
                .compare_exchange(
                    phase,
                    REQUEST_RESPONDED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.remove_from_registry();
                return true;
            }
        }
    }

    fn remove_from_registry(&self) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&self.request_id)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            entries.remove(&self.request_id);
        }
    }
}

pub(crate) fn request_deadline_error(
    execution_started: bool,
) -> vaultkern_runtime_protocol::ErrorDto {
    if execution_started {
        vaultkern_runtime_protocol::ErrorDto {
            code: "request_outcome_unknown".into(),
            message: "the resident IPC request deadline expired after execution started; refresh state before deciding whether to retry".into(),
        }
    } else {
        vaultkern_runtime_protocol::ErrorDto {
            code: "request_timeout".into(),
            message: "the resident IPC request timed out before execution".into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ClientHello {
    pub(crate) protocol_version: u32,
    pub(crate) capabilities: Vec<String>,
    pub(crate) client_origin: String,
    pub(crate) browser_process_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_window: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ServerHello {
    pub(crate) protocol_version: u32,
    pub(crate) capabilities: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ResidentIpcFrame {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Request {
        request_id: String,
        timeout_ms: u64,
        message: ProtocolEnvelope,
    },
    Cancel {
        request_id: String,
    },
    Response {
        request_id: String,
        message: RuntimeResponse,
    },
    Error {
        request_id: Option<String>,
        code: String,
        message: String,
    },
}

pub(crate) fn client_hello(
    client_origin: String,
    browser_process_id: u32,
    parent_window: Option<usize>,
) -> ClientHello {
    ClientHello {
        protocol_version: RESIDENT_IPC_PROTOCOL_VERSION,
        capabilities: resident_ipc_capabilities(),
        client_origin,
        browser_process_id,
        parent_window: parent_window.map(|value| value as u64),
    }
}

pub(crate) fn prepare_runtime_protocol_request(
    session: &mut RuntimeProtocolSession,
    envelope: ProtocolEnvelope,
) -> std::result::Result<ProtocolEnvelope, RuntimeResponse> {
    if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
        return Err(RuntimeResponse::Error(
            vaultkern_runtime_protocol::ErrorDto {
                code: "unsupported_version".into(),
                message: format!("unsupported runtime protocol version: {}", envelope.version),
            },
        ));
    }
    let request_id = envelope.request_id;
    match session.accept(envelope.command) {
        RuntimeProtocolDispatch::Respond(response) => Err(response),
        RuntimeProtocolDispatch::Dispatch(command) => Ok(ProtocolEnvelope {
            version: vaultkern_runtime_protocol::PROTOCOL_VERSION,
            request_id,
            command,
        }),
    }
}

pub(crate) fn negotiate_client_hello(hello: ClientHello) -> Result<ServerHello> {
    if hello.protocol_version != RESIDENT_IPC_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported resident IPC protocol version: {}",
            hello.protocol_version
        );
    }
    validate_capabilities(&hello.capabilities)?;
    validate_browser_origin(&hello.client_origin)?;
    if hello.browser_process_id == 0 {
        anyhow::bail!("resident IPC client did not identify its authenticated browser process");
    }

    Ok(ServerHello {
        protocol_version: RESIDENT_IPC_PROTOCOL_VERSION,
        capabilities: resident_ipc_capabilities(),
    })
}

pub(crate) fn validate_configured_browser_origin(browser_origin: &str) -> Result<()> {
    validate_browser_origin_for_extension(browser_origin, configured_extension_id())
}

fn validate_browser_origin(browser_origin: &str) -> Result<()> {
    if extension_id_from_browser_origin(browser_origin).is_none() {
        anyhow::bail!("invalid browser extension origin");
    }
    Ok(())
}

fn validate_browser_origin_for_extension(
    browser_origin: &str,
    expected_extension_id: Option<&str>,
) -> Result<()> {
    validate_browser_origin(browser_origin)?;
    let expected_extension_id = expected_extension_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("runtime has no build-time browser extension ID")?;
    if expected_extension_id.len() != 32
        || !expected_extension_id
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
    {
        anyhow::bail!("runtime build-time browser extension ID is invalid");
    }
    let expected_origin = format!("chrome-extension://{expected_extension_id}/");
    if browser_origin != expected_origin {
        anyhow::bail!("browser origin does not match the configured extension");
    }
    Ok(())
}

#[cfg(not(test))]
fn configured_extension_id() -> Option<&'static str> {
    option_env!("VAULTKERN_DEFAULT_EXTENSION_ID")
}

#[cfg(test)]
fn configured_extension_id() -> Option<&'static str> {
    Some("kblgblkjghklighdgmejjfondchkjcgf")
}

pub(crate) fn validate_server_hello(hello: &ServerHello) -> Result<()> {
    if hello.protocol_version != RESIDENT_IPC_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported resident IPC protocol version: {}",
            hello.protocol_version
        );
    }
    validate_capabilities(&hello.capabilities)
}

fn resident_ipc_capabilities() -> Vec<String> {
    RESIDENT_IPC_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn validate_capabilities(capabilities: &[String]) -> Result<()> {
    for required in RESIDENT_IPC_CAPABILITIES {
        if !capabilities.iter().any(|value| value == required) {
            anyhow::bail!("missing required resident IPC capability: {required}");
        }
    }
    Ok(())
}

pub(crate) fn validate_request(request_id: &str, timeout_ms: u64) -> Result<()> {
    if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_BYTES {
        anyhow::bail!("invalid resident IPC request ID");
    }
    if timeout_ms == 0 || timeout_ms > RESIDENT_IPC_MAX_TIMEOUT_MS {
        anyhow::bail!("invalid resident IPC request timeout: {timeout_ms}");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Option<ResidentIpcFrame>> {
    read_frame_with_limit(reader, RESIDENT_IPC_MAX_FRAME_BYTES)
}

#[cfg(test)]
pub(crate) fn read_frame_with_limit(
    reader: &mut impl Read,
    max_frame_bytes: usize,
) -> Result<Option<ResidentIpcFrame>> {
    let mut length = [0_u8; 4];
    let count = reader
        .read(&mut length[..1])
        .context("failed to read resident IPC frame length")?;
    if count == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut length[1..])
        .context("failed to read resident IPC frame length")?;

    let length = u32::from_le_bytes(length) as usize;
    if length > max_frame_bytes {
        anyhow::bail!("resident IPC frame exceeds maximum length: {length} > {max_frame_bytes}");
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(&mut payload)
        .context("failed to read resident IPC frame payload")?;
    serde_json::from_slice(&payload)
        .context("failed to decode resident IPC frame")
        .map(Some)
}

pub(crate) fn write_frame(writer: &mut impl Write, frame: &ResidentIpcFrame) -> Result<()> {
    let payload = encode_frame(frame)?;
    let length = u32::try_from(payload.len()).context("resident IPC frame length overflow")?;
    writer
        .write_all(&length.to_le_bytes())
        .context("failed to write resident IPC frame length")?;
    writer
        .write_all(&payload)
        .context("failed to write resident IPC frame payload")?;
    writer.flush().context("failed to flush resident IPC frame")
}

fn encode_frame(frame: &ResidentIpcFrame) -> Result<Zeroizing<Vec<u8>>> {
    let payload = encode_zeroizing_json(frame).context("failed to encode resident IPC frame")?;
    if payload.len() > RESIDENT_IPC_MAX_FRAME_BYTES {
        anyhow::bail!(
            "resident IPC frame exceeds maximum length: {} > {}",
            payload.len(),
            RESIDENT_IPC_MAX_FRAME_BYTES
        );
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use vaultkern_runtime_protocol::{ProtocolEnvelope, RuntimeCommand};
    use zeroize::Zeroizing;

    use super::{
        ClientHello, PendingRequests, RESIDENT_IPC_MAX_FRAME_BYTES, RESIDENT_IPC_PROTOCOL_VERSION,
        ResidentIpcFrame, encode_frame, negotiate_client_hello, read_frame_with_limit,
        request_deadline_error, validate_browser_origin_for_extension, write_frame,
    };

    const EXTENSION_ORIGIN: &str = "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/";

    fn valid_hello() -> ClientHello {
        ClientHello {
            protocol_version: RESIDENT_IPC_PROTOCOL_VERSION,
            capabilities: vec!["request_ids".into(), "cancellation".into()],
            client_origin: EXTENSION_ORIGIN.into(),
            browser_process_id: 41,
            parent_window: Some(0x1234),
        }
    }

    #[test]
    fn handshake_accepts_the_current_version_and_required_capabilities() {
        let response = negotiate_client_hello(valid_hello()).expect("negotiate client hello");

        assert_eq!(response.protocol_version, RESIDENT_IPC_PROTOCOL_VERSION);
        assert!(
            response
                .capabilities
                .iter()
                .any(|value| value == "request_ids")
        );
        assert!(
            response
                .capabilities
                .iter()
                .any(|value| value == "cancellation")
        );
    }

    #[test]
    fn handshake_rejects_version_capability_and_origin_mismatches() {
        let mut hello = valid_hello();
        hello.protocol_version += 1;
        assert!(
            negotiate_client_hello(hello)
                .unwrap_err()
                .to_string()
                .contains("unsupported resident IPC protocol version")
        );

        let mut hello = valid_hello();
        hello.capabilities.retain(|value| value != "cancellation");
        assert!(
            negotiate_client_hello(hello)
                .unwrap_err()
                .to_string()
                .contains("missing required resident IPC capability: cancellation")
        );

        let mut hello = valid_hello();
        hello.client_origin = "https://example.com/".into();
        assert!(
            negotiate_client_hello(hello)
                .unwrap_err()
                .to_string()
                .contains("invalid browser extension origin")
        );

        let mut hello = valid_hello();
        hello.browser_process_id = 0;
        assert!(
            negotiate_client_hello(hello)
                .unwrap_err()
                .to_string()
                .contains("authenticated browser process")
        );
    }

    #[test]
    fn handshake_accepts_a_valid_origin_from_the_authenticated_shim() {
        let mut hello = valid_hello();
        hello.client_origin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into();

        negotiate_client_hello(hello)
            .expect("the resident trusts the authenticated shim to pin the extension ID");
    }

    #[test]
    fn shim_rejects_a_valid_but_different_extension_origin() {
        let error = validate_browser_origin_for_extension(
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            Some("kblgblkjghklighdgmejjfondchkjcgf"),
        )
        .expect_err("a different valid extension ID must not authenticate");

        assert!(error.to_string().contains("configured extension"));
    }

    #[test]
    fn missing_build_time_extension_id_fails_closed() {
        let error = validate_browser_origin_for_extension(EXTENSION_ORIGIN, None)
            .expect_err("browser IPC must not run without a build-time extension ID");

        assert!(
            error
                .to_string()
                .contains("no build-time browser extension ID")
        );
    }

    #[test]
    fn invalid_build_time_extension_id_fails_closed() {
        let error = validate_browser_origin_for_extension(
            "chrome-extension://testextensionid/",
            Some("testextensionid"),
        )
        .expect_err("a malformed build-time extension ID must not authenticate");

        assert!(
            error
                .to_string()
                .contains("build-time browser extension ID is invalid")
        );
    }

    #[test]
    fn length_prefixed_frames_keep_secret_requests_in_typed_protocol_buffers() {
        let frame = ResidentIpcFrame::Request {
            request_id: "native-41".into(),
            timeout_ms: 30_000,
            message: ProtocolEnvelope::new(RuntimeCommand::UnlockCurrentVaultWithPassword {
                password: "native-secret".into(),
            }),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("encode frame");

        let decoded = read_frame_with_limit(&mut Cursor::new(bytes), 4096)
            .expect("decode frame")
            .expect("frame before EOF");

        match decoded {
            ResidentIpcFrame::Request {
                request_id,
                timeout_ms,
                message,
            } => {
                assert_eq!(request_id, "native-41");
                assert_eq!(timeout_ms, 30_000);
                match message.command {
                    RuntimeCommand::UnlockCurrentVaultWithPassword { password } => {
                        assert_eq!(password.as_str(), "native-secret");
                    }
                    _ => panic!("expected typed secret-bearing runtime command"),
                }
            }
            _ => panic!("expected request frame"),
        }
    }

    #[test]
    fn resident_frame_serialization_uses_a_zeroizing_payload_buffer() {
        let frame = ResidentIpcFrame::Request {
            request_id: "native-42".into(),
            timeout_ms: 30_000,
            message: ProtocolEnvelope::new(RuntimeCommand::UnlockCurrentVaultWithPassword {
                password: "serialized-secret".into(),
            }),
        };

        let payload: Zeroizing<Vec<u8>> = encode_frame(&frame).expect("encode frame payload");

        assert_eq!(
            payload.capacity(),
            payload.len(),
            "secret serialization must allocate its final buffer exactly once"
        );
        assert!(
            payload
                .windows("serialized-secret".len())
                .any(|window| window == b"serialized-secret")
        );
    }

    #[test]
    fn hello_frame_round_trips_as_a_single_flat_negotiation_object() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &ResidentIpcFrame::ClientHello(valid_hello()))
            .expect("encode hello frame");

        let decoded = read_frame_with_limit(&mut Cursor::new(bytes), 4096)
            .expect("decode hello frame")
            .expect("hello before EOF");

        match decoded {
            ResidentIpcFrame::ClientHello(hello) => {
                assert_eq!(hello.protocol_version, RESIDENT_IPC_PROTOCOL_VERSION);
                assert_eq!(hello.client_origin, EXTENSION_ORIGIN);
                assert_eq!(hello.browser_process_id, 41);
                assert_eq!(hello.parent_window, Some(0x1234));
            }
            _ => panic!("expected client hello frame"),
        }
    }

    #[test]
    fn frame_reader_rejects_lengths_over_the_hard_limit_before_allocating() {
        let mut bytes = Cursor::new(
            ((RESIDENT_IPC_MAX_FRAME_BYTES as u32) + 1)
                .to_le_bytes()
                .to_vec(),
        );

        let error = match read_frame_with_limit(&mut bytes, RESIDENT_IPC_MAX_FRAME_BYTES) {
            Ok(_) => panic!("oversized frame must fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("resident IPC frame exceeds maximum length")
        );
    }

    #[test]
    fn cancellation_claims_one_response_and_marks_the_runtime_token() {
        let pending = PendingRequests::default();
        let request = pending.register("native-7").expect("register request");

        assert!(pending.cancel("native-7"));
        assert!(request.cancelled());
        assert!(!request.claim_response());
        assert!(!pending.cancel("native-7"));
    }

    #[test]
    fn cancellation_after_runtime_dispatch_preserves_the_real_response() {
        let pending = PendingRequests::default();
        let request = pending
            .register("native-running")
            .expect("register request");
        assert!(request.begin_execution());

        assert!(!pending.cancel("native-running"));
        assert!(request.cancelled());
        assert!(request.claim_response());
    }

    #[test]
    fn deadline_and_execution_start_are_one_mutually_exclusive_transition() {
        let pending = PendingRequests::default();
        let request = pending
            .register("native-deadline-race")
            .expect("register request");

        assert_eq!(request.claim_deadline_response(), Some(false));
        assert!(
            !request.begin_execution(),
            "a request reported as timed out before execution must never start afterwards"
        );
    }

    #[test]
    fn an_expired_started_mutation_reports_unknown_outcome_instead_of_waiting_forever() {
        assert_eq!(request_deadline_error(false).code, "request_timeout");
        assert_eq!(request_deadline_error(true).code, "request_outcome_unknown");
    }

    #[test]
    fn request_ids_are_unique_until_the_response_is_claimed() {
        let pending = PendingRequests::default();
        let first = pending.register("native-9").expect("register request");

        assert!(pending.register("native-9").is_err());
        assert!(first.claim_response());
        assert!(pending.register("native-9").is_ok());
    }
}
